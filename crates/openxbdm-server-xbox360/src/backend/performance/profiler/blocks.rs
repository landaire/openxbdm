use core::cell::UnsafeCell;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::performance::profiler;
use openxbdm_server::commands::performance::profiler::BLOCK_SIZE;
use openxbdm_server::commands::performance::profiler::BufferLayout;
use openxbdm_server::commands::performance::profiler::BufferMemory;
use openxbdm_server::commands::performance::profiler::MAX_BLOCKS;
use openxbdm_server::commands::performance::profiler::ProfilerFlags;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AllocationType;
use xbox360_sys::xboxkrnl::InterlockedFlushSList;
use xbox360_sys::xboxkrnl::InterlockedPopEntrySList;
use xbox360_sys::xboxkrnl::MemoryRegion;
use xbox360_sys::xboxkrnl::PageProtection;

use super::super::COMMIT_RESERVE_LARGE;
use super::super::pmc::print;
use super::sampled;

const BLOCK_WORDS: usize = BLOCK_SIZE as usize / 4;

/// One sample block of big-endian record words.
pub(super) type Block = [u32; BLOCK_WORDS];

pub(super) static BLOCKS: AtomicU32 = AtomicU32::new(0);
/// Address of the sample buffer, 0 without one.
static BUFFER: AtomicU32 = AtomicU32::new(0);
static BUFFER_BYTES: AtomicU32 = AtomicU32::new(0);
/// [`MemoryRegion`] of the sample buffer.
static BUFFER_MEMORY: AtomicU32 = AtomicU32::new(0);
/// Where the writer gathers full blocks before writing them: `BLOCKS`
/// blocks at the end of the sample buffer, null without one.
pub(super) static STAGING: AtomicPtr<Block> = AtomicPtr::new(core::ptr::null_mut());

/// An interlocked singly linked list head: next entry in the high word,
/// depth and sequence in the low word.
#[repr(C, align(8))]
pub(super) struct ListHead(UnsafeCell<u64>);

#[repr(C, align(8))]
struct ListEntry(UnsafeCell<u64>);

impl ListHead {
    const fn new() -> Self {
        Self(UnsafeCell::new(0))
    }

    fn pop(&self) -> Option<u32> {
        // SAFETY: the head is an aligned static list of entries from one block set.
        match unsafe { InterlockedPopEntrySList(self.0.get()) } {
            0 => None,
            entry => Some(entry),
        }
    }

    fn flush(&self) {
        // SAFETY: as in `pop`.
        unsafe { InterlockedFlushSList(self.0.get()) };
    }

    pub(super) fn push(&self, entry: u32) {
        // SAFETY: `entry` is a list entry of the same block set.
        unsafe { push_entry(self.0.get(), entry) };
    }
}

/// Interlocked push (stock inlines it at 0x91f92f90).
#[unsafe(naked)]
unsafe extern "C" fn push_entry(head: *mut u64, entry: u32) {
    core::arch::naked_asm!(
        "2:",
        "mfmsr 9",
        // mtmsrd 13, 1: r13 holds the processor control region address,
        // whose external interrupt enable bit is clear.
        ".long 0x7da10164",
        // ldarx 6, 0, 3
        ".long 0x7cc018a8",
        // rldicl 7, 6, 32, 32: the current first entry.
        ".long 0x78c70022",
        "stw 7, 0(4)",
        "lwsync",
        "addis 8, 6, 1",
        "addi 6, 6, 1",
        "rlwimi 6, 8, 0, 0, 15",
        // rldimi 6, 4, 32, 0: the entry becomes the first.
        ".long 0x7886000e",
        // stdcx. 6, 0, 3
        ".long 0x7cc019ad",
        // mtmsrd 9, 1
        ".long 0x7d210164",
        "bne- 2b",
        "blr",
    )
}

/// Sampling state of a processor's blocks, shared with the writer.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ProfilerState {
    Idle = 0,
    Active = 1,
    /// The writer also flushes the partly filled blocks, then ends.
    Stopping = 2,
}

/// A [`ProfilerState`] in an atomic word.
pub(super) struct StateWord(AtomicU32);

impl StateWord {
    const fn new() -> Self {
        Self(AtomicU32::new(ProfilerState::Idle as u32))
    }

    pub(super) fn load(&self, order: Ordering) -> ProfilerState {
        // SAFETY: only `new` and `store` write the word, each with a
        // `ProfilerState` discriminant.
        unsafe { core::mem::transmute::<u32, ProfilerState>(self.0.load(order)) }
    }

    pub(super) fn store(&self, state: ProfilerState, order: Ordering) {
        self.0.store(state as u32, order);
    }
}

/// Sample blocks of one processor (stock 0x91fa9a08 + 0x148 * processor).
/// The block being filled is popped from `free` while a sample is copied
/// into it and pushed back after; full blocks go to `full`. Whoever popped
/// an entry owns its block until it pushes the entry.
#[repr(C, align(8))]
pub(super) struct ThreadBlocks {
    pub(super) free: ListHead,
    pub(super) full: ListHead,
    entries: [ListEntry; MAX_BLOCKS as usize],
    /// Bytes used in each block.
    fill: [AtomicU32; MAX_BLOCKS as usize],
    /// Blocks in the sample buffer; null when not assigned.
    blocks: [AtomicPtr<Block>; MAX_BLOCKS as usize],

    pub(super) state: StateWord,
}

// SAFETY: the list heads and entries change only through interlocked
// operations; the other fields are atomics.
unsafe impl Sync for ThreadBlocks {}

pub(super) static THREADS: [ThreadBlocks; HARDWARE_THREAD_COUNT] = [const {
    ThreadBlocks {
        free: ListHead::new(),
        full: ListHead::new(),
        entries: [const { ListEntry(UnsafeCell::new(0)) }; MAX_BLOCKS as usize],
        fill: [const { AtomicU32::new(0) }; MAX_BLOCKS as usize],
        blocks: [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_BLOCKS as usize],
        state: StateWord::new(),
    }
}; HARDWARE_THREAD_COUNT];

impl ThreadBlocks {
    pub(super) fn entry(&self, index: usize) -> u32 {
        self.entries[index].0.get() as usize as u32
    }

    fn index(&self, entry: u32) -> usize {
        (entry - self.entry(0)) as usize / 8
    }

    /// The block of entry `index`.
    ///
    /// # Safety
    ///
    /// The block must be assigned, and the caller must own it: it popped
    /// the entry, or no other code uses the block set. The result must be
    /// dropped before the entry is pushed.
    #[allow(clippy::mut_from_ref)]
    unsafe fn block(&self, index: usize) -> &mut Block {
        let block = self.blocks[index].load(Ordering::Relaxed);

        // SAFETY: an assigned block lies in the sample buffer, which stays
        // allocated while blocks are assigned; the caller owns the block.
        unsafe {
            core::hint::assert_unchecked(!block.is_null());
            &mut *block
        }
    }

    /// Empty both lists and queue every assigned block, zeroed (stock
    /// 0x91f90858).
    ///
    /// # Safety
    ///
    /// No other code may use the block set during the call: no processor
    /// samples into it and the writer does not drain it.
    pub(super) unsafe fn reset(&self) {
        self.free.flush();
        self.full.flush();

        for index in 0..MAX_BLOCKS as usize {
            if self.blocks[index].load(Ordering::Relaxed).is_null() {
                continue;
            }

            // SAFETY: the entry is in no list.
            unsafe { *self.entries[index].0.get() = 0 };
            self.free.push(self.entry(index));

            // SAFETY: the block is assigned, and nothing else uses the
            // block set by the contract, so nothing else pops its entry.
            unsafe { self.block(index) }.fill(0);
            self.fill[index].store(0, Ordering::Relaxed);
        }
    }

    /// Room for `size` bytes in the current block: the block's entry index
    /// and the room as words. A block without room is padded with zeros
    /// and queued as full (stock 0x91f908e8).
    ///
    /// # Safety
    ///
    /// The blocks of `self` must be assigned in an allocated sample buffer
    /// that stays allocated while the room lives. The caller owns the room
    /// until it pushes the returned entry back on `free`, and must drop the
    /// room before that push.
    pub(super) unsafe fn allocate(&self, size: u32) -> Option<(usize, &mut [u32])> {
        while let Some(entry) = self.free.pop() {
            let index = self.index(entry);
            let fill = self.fill[index].load(Ordering::Relaxed);

            // SAFETY: the entry was popped, and every entry on a list has an
            // assigned block. The room is returned before the caller pushes
            // the entry; the padded block before it is pushed here.
            let block = unsafe { self.block(index) };
            // SAFETY: the fill is a word multiple within the block: it grows
            // only by rooms that fit.
            let start = unsafe { block.as_mut_ptr().byte_add(fill as usize) };

            if fill + size <= BLOCK_SIZE {
                self.fill[index].store(fill + size, Ordering::Relaxed);
                // SAFETY: the `size` bytes from `start` end within the block,
                // checked above; `size` is a word multiple.
                return Some((index, unsafe {
                    core::slice::from_raw_parts_mut(start, size as usize / 4)
                }));
            }

            // SAFETY: the rest of the block from `start`.
            unsafe { core::ptr::write_bytes(start.cast::<u8>(), 0, (BLOCK_SIZE - fill) as usize) };
            self.fill[index].store(0, Ordering::Relaxed);
            self.full.push(entry);
        }

        None
    }

    /// Copy the used blocks of `from`, oldest first, to `destination`,
    /// zero them, and queue them on `to`; returns the end of the copy
    /// (stock 0x91f8f3f0).
    ///
    /// # Safety
    ///
    /// `destination` must have room for every used block of `from`, and
    /// only the caller may use it.
    pub(super) unsafe fn drain(
        &self,
        from: &ListHead,
        to: &ListHead,
        destination: *mut Block,
    ) -> *mut Block {
        let mut pending = [0u32; MAX_BLOCKS as usize];
        let mut count = 0;
        while let Some(entry) = from.pop() {
            pending[count] = entry;
            count += 1;
        }

        let mut destination = destination;
        for &entry in pending[..count].iter().rev() {
            // SAFETY: the entry was popped, and every entry on a list has an
            // assigned block; it is pushed after the last use.
            let block = unsafe { self.block(self.index(entry)) };
            if block[0] != 0 {
                // SAFETY: `destination` has room for the block by the
                // contract; staging and sample blocks do not overlap.
                unsafe {
                    core::ptr::copy_nonoverlapping(block, destination, 1);
                    destination = destination.add(1);
                }
            }
            block.fill(0);
            to.push(entry);
        }

        destination
    }
}

/// Allocate the sample buffers and assign each sampled processor its
/// blocks (stock 0x91f8f058).
pub(super) fn create_buffers(flags: ProfilerFlags) -> bool {
    let Ok(layout) = profiler::buffer_layout(flags) else {
        print(
            c"[LOP] Memory allocation failed! Invalid thread number of threads.\n",
            &[],
        );
        return false;
    };

    BLOCKS.store(layout.blocks, Ordering::Relaxed);

    let mut base = 0u32;
    let mut bytes = layout.bytes();
    let mut allocate = |region: MemoryRegion| {
        BUFFER_MEMORY.store(region as u32, Ordering::Relaxed);
        // SAFETY: `base` and `bytes` are live u32 values of the enclosing
        // function.
        let status = unsafe {
            xboxkrnl::NtAllocateVirtualMemory(
                &mut base,
                &mut bytes,
                COMMIT_RESERVE_LARGE,
                PageProtection::READWRITE,
                region,
            )
        };
        status.is_success()
    };

    let allocated = match layout.memory {
        BufferMemory::Title => allocate(MemoryRegion::TitleDebug) || allocate(MemoryRegion::Title),
        BufferMemory::System => allocate(MemoryRegion::System),
    };
    BUFFER_BYTES.store(bytes, Ordering::Relaxed);
    if !allocated {
        let message = match layout.memory {
            BufferMemory::Title => c"[LOP] Title Memory allocation failed! %d\n",
            BufferMemory::System => c"[LOP] System Memory allocation failed! %d\n",
        };
        print(message, &[u64::from(bytes)]);
        return false;
    }

    BUFFER.store(base, Ordering::Relaxed);

    // SAFETY: the kernel committed `bytes` bytes at `base` for this module,
    // which uses them only through the assigned blocks until
    // `free_buffers` releases them.
    let buffer = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::with_exposed_provenance_mut::<u8>(base as usize),
            bytes as usize,
        )
    };
    buffer.fill(0);
    assign_blocks(buffer, layout);
    true
}

/// Assign `layout.blocks` blocks of `buffer` to each sampled processor and
/// as many after them to the writer.
fn assign_blocks(buffer: &mut [u8], layout: BufferLayout) {
    // The kernel aligns the buffer to its 64 KiB pages.
    let first = buffer.as_mut_ptr().cast::<Block>();
    let mut assigned = 0;

    for (processor, blocks) in THREADS.iter().enumerate() {
        if !sampled(processor) {
            continue;
        }

        for index in 0..MAX_BLOCKS as usize {
            blocks.fill[index].store(0, Ordering::Relaxed);
            let block = if (index as u32) < layout.blocks {
                first.wrapping_add((layout.blocks * assigned + index as u32) as usize)
            } else {
                core::ptr::null_mut()
            };
            blocks.blocks[index].store(block, Ordering::Relaxed);
        }

        blocks.state.store(ProfilerState::Active, Ordering::Relaxed);
        // SAFETY: `initialize` assigns the blocks before it sets the profile
        // routine, and no writer runs.
        unsafe { blocks.reset() };
        assigned += 1;
    }

    if STAGING.load(Ordering::Relaxed).is_null() {
        STAGING.store(
            first.wrapping_add((layout.blocks * assigned) as usize),
            Ordering::Relaxed,
        );
    }
}

/// Stock 0x91f8f318.
pub(super) fn free_buffers() {
    for (processor, blocks) in THREADS.iter().enumerate() {
        if !sampled(processor) {
            continue;
        }

        for block in &blocks.blocks[..BLOCKS.load(Ordering::Relaxed) as usize] {
            block.store(core::ptr::null_mut(), Ordering::Relaxed);
        }
    }

    STAGING.store(core::ptr::null_mut(), Ordering::Relaxed);

    let mut base = BUFFER.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }

    let mut bytes = BUFFER_BYTES.load(Ordering::Relaxed);
    // SAFETY: `base` and `bytes` describe the allocation of
    // `create_buffers`, which no processor uses any more.
    unsafe {
        xboxkrnl::NtFreeVirtualMemory(
            &mut base,
            &mut bytes,
            AllocationType::RELEASE,
            BUFFER_MEMORY.load(Ordering::Relaxed),
        )
    };
    BUFFER.store(0, Ordering::Relaxed);
}
