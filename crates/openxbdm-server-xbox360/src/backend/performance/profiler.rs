//! CPU sampling profiler (stock 0x91f8eeb0..0x91f90bdf): `lopctrl` and
//! exports 149-151.
//!
//! A kernel interrupt hook (kernel exports 669-671) runs on every hardware
//! thread when the performance monitor interval timer expires. On a sampled
//! thread it records the interrupted call stack into 64 KiB blocks of that
//! thread; a writer thread moves full blocks to the capture file every
//! 250 ms. File layout: 0xc000 bytes of module snapshot (export 131), the
//! 0x200-byte header (rewritten with the final counters at the end), one
//! function table record per module, then the sample blocks.

use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::ptr::NonNull;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::NtStatus;
use openxbdm_server::Server;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::ObjectPath;
use openxbdm_server::commands::memory::PAGE_SIZE;
use openxbdm_server::commands::performance::CpuProfilerInfo;
use openxbdm_server::commands::performance::profiler;
use openxbdm_server::commands::performance::profiler::BLOCK_SIZE;
use openxbdm_server::commands::performance::profiler::BufferLayout;
use openxbdm_server::commands::performance::profiler::BufferMemory;
use openxbdm_server::commands::performance::profiler::MAX_BLOCKS;
use openxbdm_server::commands::performance::profiler::ProfilerError;
use openxbdm_server::commands::performance::profiler::ProfilerFlags;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::status::dos_error;
use xbox360::thread::current_object;
use xbox360::time::FileTime;
use xbox360::time::Timebase;
use xbox360::time::sleep;
use xbox360_sys::image::ImageDirectory;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::status::Win32ErrorCode;
use xbox360_sys::xam::GetCurrentThreadId;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::AllocationType;
use xbox360_sys::xboxkrnl::Boolean8;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::InterlockedFlushSList;
use xbox360_sys::xboxkrnl::InterlockedPopEntrySList;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::Kevent;
use xbox360_sys::xboxkrnl::KtrapFrame;
use xbox360_sys::xboxkrnl::MemoryRegion;
use xbox360_sys::xboxkrnl::MmStatistics;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::RtlImageDirectoryEntryToData;
use xbox360_sys::xboxkrnl::ShareAccess;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;

use super::COMMIT_RESERVE_LARGE;
use super::module_snapshot;
use super::pmc;
use super::pmc::Owner;
use super::pmc::print;
use crate::backend::Console;
use crate::backend::dispatcher;
use crate::backend::filesystem;
use crate::exports::export;
use crate::kernel;
use crate::kernel::LoaderLock;
use crate::net::XamNetwork;

/// Kernel exports of the profile interrupt: enable on a processor mask,
/// disable, and set the routine.
const ENABLE_PROFILE_INTERRUPT: Ordinal = Ordinal::new(669).unwrap();
const DISABLE_PROFILE_INTERRUPT: Ordinal = Ordinal::new(670).unwrap();
const SET_PROFILE_ROUTINE: Ordinal = Ordinal::new(671).unwrap();
/// Deepest call stack a sample records, the interrupted address included.
const MAX_FRAMES: usize = 500;
/// Words of a sample record before the frames.
const RECORD_HEADER_WORDS: usize = 10;
const RECORD_MAGIC: u32 = 0x0cdc_dce8;
/// Module snapshot at the start of the file; the header follows it.
const SNAPSHOT_SIZE: u32 = module_snapshot::SIZE;
const HEADER_VERSION: u32 = 0x201;
const TITLE: &[u8] = b"Microsoft CPU Profiler for Xbox";
const TITLE_WORD_COUNT: usize = TITLE.len().div_ceil(4);
/// `TITLE` as big-endian header words, NUL padded.
const TITLE_WORDS: [u32; TITLE_WORD_COUNT] = {
    let mut words = [0u32; TITLE_WORD_COUNT];
    let mut index = 0;
    while index < TITLE.len() {
        words[index / 4] |= (TITLE[index] as u32) << (24 - 8 * (index % 4));
        index += 1;
    }
    words
};
/// Function tables the file records at most.
const MODULE_CAPACITY: usize = 0x80;
const WRITER_STACK: u32 = 0x8000;
/// `ExCreateThread` flags of the writer before its processor is added.
const WRITER_FLAGS: ThreadCreationFlags = ThreadCreationFlags::SYSTEM_PROCESS
    .union(ThreadCreationFlags::PRIORITY_CLASS_13)
    .union(ThreadCreationFlags::RETURN_THREAD_OBJECT)
    .union(ThreadCreationFlags::NOT_DEBUGGABLE);
const POLL_INTERVAL_MS: u32 = 250;
const BLOCK_WORDS: usize = BLOCK_SIZE as usize / 4;

/// One sample block of big-endian record words.
type Block = [u32; BLOCK_WORDS];

xbox360_sys::flags! {
    /// Word 9 of a sample record: these flags and the number of the
    /// sampled processor in the low bits ([`SampleFlags::processor`]).
    pub struct SampleFlags(u32) {
        /// The sample came from a leaf function's epilogue.
        LEAF = 0x8000_0000,
    }
}

impl SampleFlags {
    /// The processor number field holding hardware thread `processor`,
    /// which is below `HARDWARE_THREAD_COUNT`.
    const fn processor(processor: usize) -> Self {
        Self::from_bits_retain(processor as u32)
    }
}

xbox360_sys::flags! {
    /// Interval timer control word
    /// ([`xboxkrnl::PrvRegister::INTERVAL_CONTROL`]).
    pub struct IntervalControl(u64) {
        /// Interrupt when the interval expires.
        INTERRUPT = 0x8000 << 32,
    }
}

/// A 64-bit header value as two words, high word first, each stored on its
/// own.
#[repr(C)]
struct DoubleWord([AtomicU32; 2]);

impl DoubleWord {
    const fn new() -> Self {
        Self([AtomicU32::new(0), AtomicU32::new(0)])
    }

    fn load(&self) -> u64 {
        u64::from(self.0[0].load(Ordering::Relaxed)) << 32
            | u64::from(self.0[1].load(Ordering::Relaxed))
    }

    fn store(&self, value: u64) {
        self.0[0].store((value >> 32) as u32, Ordering::Relaxed);
        self.0[1].store(value as u32, Ordering::Relaxed);
    }
}

/// One counter per hardware thread.
type PerProcessor = [AtomicU32; HARDWARE_THREAD_COUNT];

const fn per_processor() -> PerProcessor {
    [const { AtomicU32::new(0) }; HARDWARE_THREAD_COUNT]
}

/// The file header. The interrupt routine of each processor updates that
/// processor's counters while `info` reads them, so the words are atomics.
#[repr(C)]
struct ProfileHeader {
    version: AtomicU32,
    unknown_004: AtomicU32,
    write_errors: AtomicU32,
    _reserved_00c: AtomicU32,
    unknown_010: AtomicU32,
    processors: AtomicU32,
    start_time: DoubleWord,
    end_time: DoubleWord,
    /// Cleared with the counters; no known use.
    _unknown_028: PerProcessor,
    samples: PerProcessor,
    /// Stack walks that hit the depth limit or faulted.
    faulted: PerProcessor,
    record_header_size: AtomicU32,
    largest: PerProcessor,
    smallest: PerProcessor,
    bytes: PerProcessor,
    blocks: PerProcessor,
    stored: PerProcessor,
    dropped: PerProcessor,
    interrupts: PerProcessor,
    sampled: PerProcessor,
    /// Interrupts above dispatch level or in the idle thread.
    skipped: PerProcessor,
    /// Interrupts while the processor's previous sample was in progress.
    busy: PerProcessor,
    _reserved_164: [AtomicU32; 12],
    title: [AtomicU32; TITLE_WORD_COUNT],
    _reserved_1b4: [AtomicU32; 19],
}

const _: () = {
    assert!(offset_of!(ProfileHeader, version) == 0x00);
    assert!(offset_of!(ProfileHeader, unknown_004) == 0x04);
    assert!(offset_of!(ProfileHeader, write_errors) == 0x08);
    assert!(offset_of!(ProfileHeader, _reserved_00c) == 0x0c);
    assert!(offset_of!(ProfileHeader, unknown_010) == 0x10);
    assert!(offset_of!(ProfileHeader, processors) == 0x14);
    assert!(offset_of!(ProfileHeader, start_time) == 0x18);
    assert!(offset_of!(ProfileHeader, end_time) == 0x20);
    assert!(offset_of!(ProfileHeader, _unknown_028) == 0x28);
    assert!(offset_of!(ProfileHeader, samples) == 0x40);
    assert!(offset_of!(ProfileHeader, faulted) == 0x58);
    assert!(offset_of!(ProfileHeader, record_header_size) == 0x70);
    assert!(offset_of!(ProfileHeader, largest) == 0x74);
    assert!(offset_of!(ProfileHeader, smallest) == 0x8c);
    assert!(offset_of!(ProfileHeader, bytes) == 0xa4);
    assert!(offset_of!(ProfileHeader, blocks) == 0xbc);
    assert!(offset_of!(ProfileHeader, stored) == 0xd4);
    assert!(offset_of!(ProfileHeader, dropped) == 0xec);
    assert!(offset_of!(ProfileHeader, interrupts) == 0x104);
    assert!(offset_of!(ProfileHeader, sampled) == 0x11c);
    assert!(offset_of!(ProfileHeader, skipped) == 0x134);
    assert!(offset_of!(ProfileHeader, busy) == 0x14c);
    assert!(offset_of!(ProfileHeader, _reserved_164) == 0x164);
    assert!(offset_of!(ProfileHeader, title) == 0x194);
    assert!(offset_of!(ProfileHeader, _reserved_1b4) == 0x1b4);
    assert!(size_of::<ProfileHeader>() == 0x200);
    assert!(align_of::<ProfileHeader>() == 4);
};

impl ProfileHeader {
    const WORDS: usize = size_of::<Self>() / 4;
    /// Words cleared before the file is opened: the counters, up to the
    /// title.
    const CLEARED: core::ops::Range<usize> =
        offset_of!(ProfileHeader, _unknown_028) / 4..offset_of!(ProfileHeader, title) / 4;

    const fn new() -> Self {
        Self {
            version: AtomicU32::new(0),
            unknown_004: AtomicU32::new(0),
            write_errors: AtomicU32::new(0),
            _reserved_00c: AtomicU32::new(0),
            unknown_010: AtomicU32::new(0),
            processors: AtomicU32::new(0),
            start_time: DoubleWord::new(),
            end_time: DoubleWord::new(),
            _unknown_028: per_processor(),
            samples: per_processor(),
            faulted: per_processor(),
            record_header_size: AtomicU32::new(0),
            largest: per_processor(),
            smallest: per_processor(),
            bytes: per_processor(),
            blocks: per_processor(),
            stored: per_processor(),
            dropped: per_processor(),
            interrupts: per_processor(),
            sampled: per_processor(),
            skipped: per_processor(),
            busy: per_processor(),
            _reserved_164: [const { AtomicU32::new(0) }; 12],
            title: [const { AtomicU32::new(0) }; TITLE_WORD_COUNT],
            _reserved_1b4: [const { AtomicU32::new(0) }; 19],
        }
    }

    fn words(&self) -> &[AtomicU32; ProfileHeader::WORDS] {
        // SAFETY: the header consists of `AtomicU32` fields and arrays
        // without padding (offsets and size asserted above).
        unsafe { &*core::ptr::from_ref(self).cast() }
    }

    /// Write the header to the file at `offset` (see [`write`]). The kernel
    /// reads the words; sampling has stopped or not started, so no
    /// processor changes them meanwhile.
    #[inline(always)]
    fn write(&self, offset: Option<u64>) -> bool {
        // SAFETY: the header is `size_of::<Self>()` bytes that stay
        // allocated; only the kernel reads them during the call.
        unsafe {
            write_raw(
                core::ptr::from_ref(self).cast::<u8>(),
                size_of::<Self>() as u32,
                offset,
            )
        }
    }
}

static HEADER: ProfileHeader = ProfileHeader::new();

/// A per-processor counter of [`ProfileHeader`], as its byte offset.
#[repr(u32)]
#[derive(Clone, Copy)]
enum Counter {
    Samples = offset_of!(ProfileHeader, samples) as u32,
    Faulted = offset_of!(ProfileHeader, faulted) as u32,
    Stored = offset_of!(ProfileHeader, stored) as u32,
    Dropped = offset_of!(ProfileHeader, dropped) as u32,
    Interrupts = offset_of!(ProfileHeader, interrupts) as u32,
    Sampled = offset_of!(ProfileHeader, sampled) as u32,
    Skipped = offset_of!(ProfileHeader, skipped) as u32,
    Busy = offset_of!(ProfileHeader, busy) as u32,
}

/// Out of line, and the counter as an offset, so that each of the many
/// sites in the interrupt routine loads one constant.
#[inline(never)]
fn count(counter: Counter, processor: usize) {
    // SAFETY: each `Counter` is the offset of a `PerProcessor` field.
    let counters = unsafe {
        &*core::ptr::from_ref(&HEADER)
            .byte_add(counter as usize)
            .cast::<PerProcessor>()
    };
    counters[processor].fetch_add(1, Ordering::Relaxed);
}

static CONTROL: profiler::Control = profiler::Control::new();
static FLAGS: AtomicU32 = AtomicU32::new(0);
/// Samples are recorded (stock 0x91fa3b08).
static SAMPLING_ACTIVE: AtomicBool = AtomicBool::new(false);
/// The interrupt routine is set.
static HOOKED: AtomicBool = AtomicBool::new(false);
static INTERVAL: AtomicU32 = AtomicU32::new(0);
static START_TIMEBASE: DoubleWord = DoubleWord::new();
static BLOCKS: AtomicU32 = AtomicU32::new(0);
/// Address of the sample buffer, 0 without one.
static BUFFER: AtomicU32 = AtomicU32::new(0);
static BUFFER_BYTES: AtomicU32 = AtomicU32::new(0);
/// [`MemoryRegion`] of the sample buffer.
static BUFFER_MEMORY: AtomicU32 = AtomicU32::new(0);
/// Where the writer gathers full blocks before writing them: `BLOCKS`
/// blocks at the end of the sample buffer, null without one.
static STAGING: AtomicPtr<Block> = AtomicPtr::new(core::ptr::null_mut());
static FILE: AtomicU32 = AtomicU32::new(0);
static WRITER_FAILED: AtomicBool = AtomicBool::new(false);

fn processors() -> u32 {
    ProfilerFlags(FLAGS.load(Ordering::Relaxed)).processors()
}

fn sampled(processor: usize) -> bool {
    processors() & (1 << processor) != 0
}

/// Highest sampled processor; 0 without one.
fn last_processor() -> usize {
    let last = match processors() {
        0 => 0,
        mask => 31 - mask.leading_zeros() as usize,
    };
    // SAFETY: the processor mask has six bits.
    unsafe { core::hint::assert_unchecked(last < HARDWARE_THREAD_COUNT) };
    last
}

/// `words` as bytes in memory order.
fn word_bytes(words: &[u32]) -> &[u8] {
    // SAFETY: every byte of a `u32` is initialized and `u8` has no
    // alignment requirement.
    unsafe { core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), size_of_val(words)) }
}

/// A kernel notification event in static storage.
struct NotificationEvent(UnsafeCell<[u32; 4]>);

// SAFETY: the kernel synchronizes access to dispatcher objects.
unsafe impl Sync for NotificationEvent {}

impl NotificationEvent {
    fn pointer(&self) -> *mut Kevent {
        self.0.get().cast()
    }

    /// Unsignaled, with the wait list head pointing at itself.
    fn reset(&self) {
        let list = self.0.get().cast::<u32>().wrapping_add(2) as usize as u32;
        // SAFETY: called before the writer thread exists.
        unsafe { *self.0.get() = [0, 0, list, list] };
    }

    fn set(&self) {
        // SAFETY: the event lives in static storage initialized by `reset`.
        unsafe { xboxkrnl::KeSetEvent(self.pointer(), 1, false) };
    }

    fn wait(&self) -> bool {
        // SAFETY: the event lives in static storage initialized by `reset`.
        let status = unsafe {
            xboxkrnl::KeWaitForSingleObject(
                self.pointer().cast(),
                WaitReason::Executive,
                ProcessorMode::Kernel,
                false,
                core::ptr::null(),
            )
        };
        status.is_success()
    }
}

/// The writer opened the file (stock 0x91faaec4).
static WRITER_STARTED: NotificationEvent = NotificationEvent(UnsafeCell::new([0; 4]));
/// The writer closed the file (stock 0x91faaeb4).
static WRITER_FINISHED: NotificationEvent = NotificationEvent(UnsafeCell::new([0; 4]));

/// An interlocked singly linked list head: next entry in the high word,
/// depth and sequence in the low word.
#[repr(C, align(8))]
struct ListHead(UnsafeCell<u64>);

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

    fn push(&self, entry: u32) {
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
enum ProfilerState {
    Idle = 0,
    Active = 1,
    /// The writer also flushes the partly filled blocks, then ends.
    Stopping = 2,
}

/// A [`ProfilerState`] in an atomic word.
struct StateWord(AtomicU32);

impl StateWord {
    const fn new() -> Self {
        Self(AtomicU32::new(ProfilerState::Idle as u32))
    }

    fn load(&self, order: Ordering) -> ProfilerState {
        // SAFETY: only `new` and `store` write the word, each with a
        // `ProfilerState` discriminant.
        unsafe { core::mem::transmute::<u32, ProfilerState>(self.0.load(order)) }
    }

    fn store(&self, state: ProfilerState, order: Ordering) {
        self.0.store(state as u32, order);
    }
}

/// Sample blocks of one processor (stock 0x91fa9a08 + 0x148 * processor).
/// The block being filled is popped from `free` while a sample is copied
/// into it and pushed back after; full blocks go to `full`. Whoever popped
/// an entry owns its block until it pushes the entry.
#[repr(C, align(8))]
struct ThreadBlocks {
    free: ListHead,
    full: ListHead,
    entries: [ListEntry; MAX_BLOCKS as usize],
    /// Bytes used in each block.
    fill: [AtomicU32; MAX_BLOCKS as usize],
    /// Blocks in the sample buffer; null when not assigned.
    blocks: [AtomicPtr<Block>; MAX_BLOCKS as usize],
    state: StateWord,
}

// SAFETY: the list heads and entries change only through interlocked
// operations; the other fields are atomics.
unsafe impl Sync for ThreadBlocks {}

static THREADS: [ThreadBlocks; HARDWARE_THREAD_COUNT] = [const {
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
    fn entry(&self, index: usize) -> u32 {
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
    unsafe fn reset(&self) {
        self.free.flush();
        self.full.flush();
        for index in 0..MAX_BLOCKS as usize {
            if !self.blocks[index].load(Ordering::Relaxed).is_null() {
                // SAFETY: the entry is in no list.
                unsafe { *self.entries[index].0.get() = 0 };
                self.free.push(self.entry(index));
                // SAFETY: the block is assigned, and nothing else uses the
                // block set by the contract, so nothing else pops its entry.
                unsafe { self.block(index) }.fill(0);
                self.fill[index].store(0, Ordering::Relaxed);
            }
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
    unsafe fn allocate(&self, size: u32) -> Option<(usize, &mut [u32])> {
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
    unsafe fn drain(&self, from: &ListHead, to: &ListHead, destination: *mut Block) -> *mut Block {
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

/// Per-processor busy words of the sample in progress (stock 0x91fa3b10).
/// Stock builds each record in a static block next to its busy word; here
/// the stack is walked once for the size and again into the reserved
/// block space.
static BUSY: [AtomicU32; HARDWARE_THREAD_COUNT] =
    [const { AtomicU32::new(0) }; HARDWARE_THREAD_COUNT];

fn valid(address: u32) -> bool {
    xboxkrnl::MmIsAddressValid(address).get()
}

/// The interrupted code at `address` is a leaf epilogue: the instructions
/// up to `blr` (at most 13) only load, branch, or restore the link register
/// (stock 0x91f90030). The result is the record flag; `None` when the code
/// is unreadable, where stock catches the fault.
///
/// # Safety
///
/// The word at `address` must be readable. Later words are checked with
/// `MmIsAddressValid` where they start a page.
unsafe fn in_leaf_epilogue(address: u32) -> Option<SampleFlags> {
    const EPILOGUE_LIMIT: usize = 13;
    const PAGE_MASK: u32 = 0xfff;
    const BLR: u32 = 0x4e80_0020;
    const MTLR_R12: u32 = 0x7d88_03a6;
    // Primary opcodes of `ld`, `lwz`, `lfd`, `b`, and the X-form group.
    const LD: u32 = 0x3a;
    const LWZ: u32 = 0x20;
    const LFD: u32 = 0x32;
    const B: u32 = 0x12;
    const X_FORM: u32 = 0x1f;
    // Extended opcode field of an X-form instruction, and its `lvx` value.
    const EXTENDED_OPCODE: u32 = 0x7fe;
    const LVX: u32 = 0xce;
    let mut address = address;
    for _ in 0..EPILOGUE_LIMIT {
        if address & PAGE_MASK == 0 && !valid(address) {
            return None;
        }
        // SAFETY: the first word is readable by the contract; a later word
        // lies on the page of the previous one or on a page checked above.
        let instruction = unsafe { *core::ptr::with_exposed_provenance::<u32>(address as usize) };
        if instruction == BLR {
            return Some(SampleFlags::LEAF);
        }
        let opcode = instruction >> 26;
        let allowed = matches!(opcode, LD | LWZ | LFD | B)
            || (opcode == X_FORM && instruction & EXTENDED_OPCODE == LVX)
            || instruction == MTLR_R12;
        if !allowed {
            return Some(SampleFlags::empty());
        }
        address += 4;
    }
    Some(SampleFlags::LEAF)
}

/// Return addresses of the interrupted thread's stack, the interrupted
/// `address` first, stored in `frames` when given; `None` at `MAX_FRAMES`
/// (stock 0x91f900b8). Takes the two registers rather than the trap frame,
/// which the compiler would pass field by field.
///
/// # Safety
///
/// `stack` must be the r1 of the interrupted running thread, with the word
/// at it and the word 8 bytes below readable. `frames`, when given, must
/// hold `depth` words, where `depth` is the result of a walk over the same
/// unchanged stack.
unsafe fn walk_stack(
    mut stack: u32,
    address: u32,
    mut frames: Option<&mut [u32]>,
) -> Option<usize> {
    let mut store = |index: usize, value: u32| {
        if let Some(frames) = frames.as_deref_mut() {
            // SAFETY: `index` is below the depth of the walk, which `frames`
            // holds by the contract.
            unsafe { *frames.get_unchecked_mut(index) = value };
        }
    };
    store(0, address);
    let mut count = 1;
    loop {
        let thread = current_object().kthread();
        // SAFETY: the first back chain is at r1, readable by the contract;
        // later ones lie between the stack limits of the running thread.
        stack = unsafe { *core::ptr::with_exposed_provenance::<u32>(stack as usize) };
        if stack >= thread.stack_base.load(Ordering::Relaxed)
            || stack <= thread.stack_limit.load(Ordering::Relaxed)
        {
            return Some(count);
        }
        // SAFETY: the saved link register below a frame between the stack
        // limits of the running thread.
        store(count, unsafe {
            *core::ptr::with_exposed_provenance::<u32>((stack - 8) as usize)
        });
        count += 1;
        if count == MAX_FRAMES {
            return None;
        }
    }
}

/// Record one sample of `processor` (stock 0x91f90420, 0x91f8fe70,
/// 0x91f8f7f8). Stock reads the code and the stack under an exception
/// handler; an unreadable address counts as a faulted walk here.
///
/// # Safety
///
/// `frame` must be the trap frame of the thread that the profile interrupt
/// stopped on this processor, and `processor` the number of this
/// processor.
unsafe fn sample(frame: &KtrapFrame, processor: usize) {
    // SAFETY: guaranteed by the caller.
    unsafe { core::hint::assert_unchecked(processor < HARDWARE_THREAD_COUNT) };
    let stack = frame.gpr[1] as u32;
    let readable = valid(frame.iar) && valid(stack) && valid(stack.wrapping_sub(8));
    let walked = if readable {
        // SAFETY: the word at `iar` is valid, checked above.
        unsafe { in_leaf_epilogue(frame.iar) }.and_then(|leaf| {
            // SAFETY: r1 and the word 8 bytes below are valid, checked
            // above.
            unsafe { walk_stack(stack, frame.iar, None) }.map(|depth| (leaf, depth))
        })
    } else {
        None
    };
    let Some((leaf, depth)) = walked else {
        count(Counter::Faulted, processor);
        return;
    };
    count(Counter::Samples, processor);
    let size = ((depth + RECORD_HEADER_WORDS) * 4) as u32;
    let mut head = [
        RECORD_MAGIC,
        0,
        0,
        size,
        GetCurrentThreadId(),
        frame.lr,
        // SAFETY: valid, checked above.
        unsafe { *core::ptr::with_exposed_provenance::<u32>((stack - 8) as usize) },
        frame.gpr[12] as u32,
        // SAFETY: valid, checked above.
        unsafe { *core::ptr::with_exposed_provenance::<u32>(frame.iar as usize) },
        (SampleFlags::processor(processor) | leaf).bits(),
    ];
    HEADER.bytes[processor].fetch_add(size, Ordering::Relaxed);
    HEADER.largest[processor].fetch_max(size, Ordering::Relaxed);
    HEADER.smallest[processor].fetch_min(size, Ordering::Relaxed);
    let time = Timebase::now().ticks();
    head[1] = (time >> 32) as u32;
    head[2] = time as u32;
    let blocks = &THREADS[processor];
    // SAFETY: the interrupt routine runs only while the profiler is
    // initialized, so the blocks lie in the allocated sample buffer, which
    // `free_buffers` releases only after `unhook`. The record's last use is
    // the walk below, before the entry is pushed.
    match unsafe { blocks.allocate(size) } {
        Some((index, record)) => {
            count(Counter::Stored, processor);
            // SAFETY: the record holds `RECORD_HEADER_WORDS` words more than
            // `depth`.
            let (header, frames) = unsafe { record.split_at_mut_unchecked(RECORD_HEADER_WORDS) };
            header.copy_from_slice(&head);
            // SAFETY: `frames` holds the `depth` words of the walk above;
            // the stack does not change while its thread is interrupted.
            unsafe { walk_stack(stack, frame.iar, Some(frames)) };
            blocks.free.push(blocks.entry(index));
        }
        None => count(Counter::Dropped, processor),
    }
}

/// Profile interrupt routine (stock 0x91f90528): the last sampled
/// processor reloads the interval; samples are skipped above dispatch level
/// and in an idle thread without pending DPCs.
extern "C" fn profile_interrupt(frame: *const KtrapFrame, irql: Irql) {
    // SAFETY: the kernel passes the trap frame of the thread it interrupted
    // on this processor, unchanged until the routine returns.
    let frame = unsafe { &*frame };
    let pcr = Kpcr::current();
    let processor = pcr.processor_number().index();
    // SAFETY: the kernel keeps processor numbers below the hardware thread
    // count (`HardwareThread`).
    unsafe { core::hint::assert_unchecked(processor < HARDWARE_THREAD_COUNT) };
    if !sampled(processor) {
        return;
    }
    if processor == last_processor() {
        pmc::set_interval_reload(INTERVAL.load(Ordering::Relaxed).wrapping_neg());
        pmc::wait_interval_reload();
    }
    if !SAMPLING_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    count(Counter::Interrupts, processor);
    let prcb = &pcr.prcb;
    if irql > Irql::DISPATCH
        || (prcb.idle_thread.load(Ordering::Relaxed) == prcb.current_thread.load(Ordering::Relaxed)
            && prcb.dpc_active.load(Ordering::Relaxed) == 0)
    {
        count(Counter::Skipped, processor);
        return;
    }
    count(Counter::Sampled, processor);
    let busy = &BUSY[processor];
    if busy
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        // SAFETY: `frame` is the kernel's trap frame of the thread stopped
        // on this processor.
        unsafe { sample(frame, processor) };
        busy.store(0, Ordering::Release);
    } else {
        count(Counter::Busy, processor);
    }
}

// Kernel entry of `profile_interrupt`, preserving the full nonvolatile
// registers.
crate::exports::bridged!(profile_interrupt_entry, profile_interrupt);

/// Call profile interrupt export `ordinal` of the kernel (stock
/// 0x91f8eeb0, 0x91f8ef48, 0x91f8efd0).
fn call_kernel(ordinal: Ordinal, argument: u32) -> Result<u32, ProfilerError> {
    let kernel = SystemModule::Kernel
        .handle()
        .map_err(|_| ProfilerError::NoKernel)?;
    let function = resolve_export(kernel, ordinal).map_err(|_| ProfilerError::NoProfileExport)?;
    // SAFETY: the profile exports take one register argument.
    Ok(unsafe { kernel::call_export(function.raw(), argument, 0, 0, 0) })
}

fn set_profile_routine(routine: u32) -> Result<(), ProfilerError> {
    call_kernel(SET_PROFILE_ROUTINE, routine).map(|_| ())
}

fn enable_profile_interrupt(mask: u32) -> Result<(), ProfilerError> {
    if Boolean8(call_kernel(ENABLE_PROFILE_INTERRUPT, mask)?).get() {
        Ok(())
    } else {
        Err(ProfilerError::ProfileInterruptRefused)
    }
}

fn disable_profile_interrupt() {
    let _ = call_kernel(DISABLE_PROFILE_INTERRUPT, 1);
}

/// Allocate the sample buffers and assign each sampled processor its
/// blocks (stock 0x91f8f058).
fn create_buffers(flags: ProfilerFlags) -> bool {
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
fn free_buffers() {
    for (processor, blocks) in THREADS.iter().enumerate() {
        if sampled(processor) {
            for block in &blocks.blocks[..BLOCKS.load(Ordering::Relaxed) as usize] {
                block.store(core::ptr::null_mut(), Ordering::Relaxed);
            }
        }
    }
    STAGING.store(core::ptr::null_mut(), Ordering::Relaxed);
    let mut base = BUFFER.load(Ordering::Relaxed);
    if base != 0 {
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
}

/// Write `data`; true when all of it was written (stock 0x91f73af8).
/// `offset` is the file position, the current one when `None`.
#[inline(always)]
fn write(data: &[u8], offset: Option<u64>) -> bool {
    // SAFETY: `data` is a live slice.
    unsafe { write_raw(data.as_ptr(), data.len() as u32, offset) }
}

/// [`write`] of `length` bytes at `data`.
///
/// # Safety
///
/// `data` is readable for `length` bytes until the call returns.
unsafe fn write_raw(data: *const u8, length: u32, offset: Option<u64>) -> bool {
    let mut io_status = IoStatusBlock {
        status: NtStatus::SUCCESS,
        information: 0,
    };
    let offset_pointer = offset
        .as_ref()
        .map_or(core::ptr::null(), |offset| offset as *const u64);
    // SAFETY: FILE is the writer's open file; `io_status` and the offset
    // are live for the synchronous call, and the caller guarantees `data`.
    let status = unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(FILE.load(Ordering::Relaxed)),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            data,
            length,
            offset_pointer,
        )
    };
    status.is_success() && io_status.information == length
}

/// A module's exception directory copy (stock 0x91f32e90 entries).
#[derive(Clone, Copy, Default)]
struct FunctionTable {
    base: u32,
    image_size: u32,
    /// Bytes of `copy`; 0 without a directory.
    size: u32,
    /// Physical memory copy of the directory, owned by the table until
    /// freed; `None` without a directory.
    copy: Option<NonNull<u8>>,
}

/// Free a directory copy.
///
/// # Safety
///
/// `copy` must be a copy from `copy_function_tables` that is not used
/// afterwards.
#[inline(always)]
unsafe fn free_copy(copy: NonNull<u8>) {
    // SAFETY: a physical allocation in the region of
    // `copy_function_tables`, freed once by the contract.
    unsafe {
        xboxkrnl::MmFreePhysicalMemory(
            MemoryRegion::Title,
            copy.as_ptr().expose_provenance() as u32,
        )
    };
}

/// Copy the exception directories of the loaded modules into physical
/// memory (stock 0x91f32e90); `None` when a copy cannot be allocated.
fn copy_function_tables(tables: &mut [FunctionTable; MODULE_CAPACITY]) -> Option<usize> {
    // Copies may lie at any page aligned physical address.
    const LOWEST_ADDRESS: u32 = 0;
    const HIGHEST_ADDRESS: u32 = u32::MAX;
    const ALIGNMENT: u32 = PAGE_SIZE;
    let lock = LoaderLock::acquire();
    let mut count = 0;
    let mut result = Some(0);
    for record in lock.all_entries() {
        if count == MODULE_CAPACITY {
            break;
        }
        let base = record.dll_base;
        if base != 0 {
            let mut size = 0u32;
            // SAFETY: `base` is a loaded image on a list whose lock is
            // held; `size` is a live u32.
            let directory = unsafe {
                RtlImageDirectoryEntryToData(base, true, ImageDirectory::Exception, &mut size)
            };
            let mut table = FunctionTable {
                base,
                image_size: record.image_size,
                size: 0,
                copy: None,
            };
            if directory != 0 {
                // SAFETY: physical allocation of `size` bytes; the result is
                // checked below.
                let address = unsafe {
                    xboxkrnl::MmAllocatePhysicalMemoryEx(
                        MemoryRegion::Title,
                        size,
                        PageProtection::READWRITE,
                        LOWEST_ADDRESS,
                        HIGHEST_ADDRESS,
                        ALIGNMENT,
                    )
                };
                let Some(address) = NonNull::new(core::ptr::with_exposed_provenance_mut::<u8>(
                    address as usize,
                )) else {
                    // Stock also passes the null copies of modules without
                    // a directory to MmFreePhysicalMemory.
                    for table in &tables[..count] {
                        if let Some(copy) = table.copy {
                            // SAFETY: allocated above for an earlier table,
                            // and dropped with the tables.
                            unsafe { free_copy(copy) };
                        }
                    }
                    result = None;
                    break;
                };
                // SAFETY: the directory holds `size` bytes of an image on a
                // list whose lock is held; the new allocation holds `size`
                // bytes that nothing else uses.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        core::ptr::with_exposed_provenance::<u8>(directory as usize),
                        address.as_ptr(),
                        size as usize,
                    )
                };
                table.size = size;
                table.copy = Some(address);
            }
            tables[count] = table;
            count += 1;
        }
    }
    drop(lock);
    result.map(|_| count)
}

/// Executable path the module snapshot records, prepared on the server
/// thread for the writer.
struct WriterPaths(UnsafeCell<WriterPathData>);

struct WriterPathData {
    file: [u8; 0x104],
    file_length: usize,
    executable: [u8; module_snapshot::PATH_LIMIT + 2],
    executable_length: usize,
}

// SAFETY: written before the writer thread is created and read only by
// it while the starter waits.
unsafe impl Sync for WriterPaths {}

static WRITER_PATHS: WriterPaths = WriterPaths(UnsafeCell::new(WriterPathData {
    file: [0; 0x104],
    file_length: 0,
    executable: [0; module_snapshot::PATH_LIMIT + 2],
    executable_length: 0,
}));

fn report_fatal(message: &core::ffi::CStr) {
    print(message, &[]);
    print(c"[LOP] Please try to free up disk space or memory\n", &[]);
    xboxkrnl::DbgBreakPoint();
}

/// Write the module snapshot, the header, and the function tables (stock
/// 0x91f8f5c0).
fn write_prologue() -> bool {
    for word in &HEADER.words()[ProfileHeader::CLEARED] {
        word.store(0, Ordering::Relaxed);
    }
    HEADER.unknown_004.store(0, Ordering::Relaxed);
    HEADER.write_errors.store(0, Ordering::Relaxed);
    HEADER
        .record_header_size
        .store((RECORD_HEADER_WORDS * 4) as u32, Ordering::Relaxed);
    HEADER.unknown_010.store(0, Ordering::Relaxed);
    for processor in 0..HARDWARE_THREAD_COUNT {
        HEADER.blocks[processor].store(BLOCKS.load(Ordering::Relaxed), Ordering::Relaxed);
        HEADER.smallest[processor].store(u32::MAX, Ordering::Relaxed);
    }
    // SAFETY: see `WriterPaths`.
    let paths = unsafe { &*WRITER_PATHS.0.get() };
    let time = FileTime::now().intervals();
    let capture = module_snapshot::CaptureFields {
        start_time: time,
        previous_flags: 0,
    };
    let Some(snapshot) =
        module_snapshot::build(&paths.executable[..paths.executable_length], capture)
    else {
        // Stock passes a stale register as the number.
        print(c"[LOP] Failed to create common header! %d\n", &[0]);
        return false;
    };
    let mut tables = [FunctionTable::default(); MODULE_CAPACITY];
    // Sampling has not started: `start` sets `SAMPLING_ACTIVE` after the
    // prologue, so no processor counts.
    if !write(word_bytes(snapshot.words()), None) || !HEADER.write(None) {
        module_snapshot::free(snapshot);
        report_fatal(c"[LOP] Fatal error. Error writing file header!\n");
        return false;
    }
    // Stock keeps the snapshot when the copies fail.
    if copy_function_tables(&mut tables).is_none() {
        report_fatal(c"[LOP] Fatal error. Could not allocate memory for function table data!\n");
        return false;
    }
    // Tables past the copied ones are zero and fail the base check.
    let complete = tables
        .iter()
        .zip(snapshot.module_bases())
        .all(|(table, base)| {
            let record = [
                table.base.to_be(),
                table.image_size.to_be(),
                table.size.to_be(),
            ];
            base == table.base
                && write(word_bytes(&record), None)
                && (table.size == 0 || {
                    // SAFETY: `copy_function_tables` sets a nonzero size only
                    // with a copy of that many bytes, freed only below.
                    let (copy, bytes) = unsafe {
                        let copy = table.copy.unwrap_unchecked();
                        (
                            copy,
                            core::slice::from_raw_parts(copy.as_ptr(), table.size as usize),
                        )
                    };
                    let written = write(bytes, None);
                    if written {
                        // SAFETY: the copy is from `copy_function_tables` and
                        // is not used after it was written.
                        unsafe { free_copy(copy) };
                    }
                    written
                })
        });
    module_snapshot::free(snapshot);
    if !complete {
        report_fatal(c"[LOP] Fatal error. Error writing file header!\n");
        return false;
    }
    true
}

/// Move the full blocks of every sampled processor to the file; while
/// stopping, also the partly filled ones (stock 0x91f8f8b8, 0x91f8f4c8).
fn write_blocks() {
    let staging = STAGING.load(Ordering::Relaxed);
    for (processor, blocks) in THREADS.iter().enumerate() {
        if !sampled(processor) {
            continue;
        }
        // SAFETY: the staging area holds `BLOCKS` blocks of the sample
        // buffer, which stays allocated while the writer runs, and only the
        // writer uses it. A processor's lists link its `BLOCKS` assigned
        // blocks, each popped once per drain, and a block the first drain
        // copies is zeroed, so the second one, run after sampling stopped,
        // skips it: both together copy at most `BLOCKS` blocks.
        let mut end = unsafe { blocks.drain(&blocks.full, &blocks.free, staging) };
        if blocks.state.load(Ordering::Acquire) != ProfilerState::Active {
            // SAFETY: as above.
            end = unsafe { blocks.drain(&blocks.free, &blocks.free, end) };
        }
        if end != staging {
            // SAFETY: `drain` filled the blocks from `staging` to `end`.
            let filled = unsafe {
                core::slice::from_raw_parts(staging.cast::<u8>(), end.addr() - staging.addr())
            };
            if !write(filled, None) {
                HEADER.write_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Writer thread (stock 0x91f8fa68). When the file cannot be opened or the
/// prologue fails, stock returns without signaling its starter, which then
/// waits forever; here the starter learns of the failure.
extern "C" fn writer_thread(_context: u32) -> u32 {
    /// System time intervals (100 ns) per second.
    const FILETIME_PER_SECOND: u64 = 10_000_000;
    // SAFETY: see `WriterPaths`.
    let paths = unsafe { &*WRITER_PATHS.0.get() };
    let request = CreateRequest {
        access: AccessMask::GENERIC_WRITE.union(AccessMask::SYNCHRONIZE),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::READ,
        disposition: CreateDisposition::OverwriteIf,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    };
    let handle = match filesystem::create_file(&paths.file[..paths.file_length], &request) {
        Ok(handle) => handle,
        Err(error) => {
            print(
                c"[LOP] Error! %d\n",
                &[u64::from(Win32ErrorCode::from(dos_error(error)).0)],
            );
            return fail_writer();
        }
    };
    FILE.store(handle.0, Ordering::Relaxed);
    if !write_prologue() {
        // Stock passes a stale register as the number.
        print(c"[LOP] Error! %d\n", &[0]);
        // SAFETY: `handle` was opened above and is closed once.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
        return fail_writer();
    }
    WRITER_STARTED.set();
    let last = &THREADS[last_processor()];
    while last.state.load(Ordering::Acquire) != ProfilerState::Stopping {
        sleep(Duration::from_millis(u64::from(POLL_INTERVAL_MS)));
        write_blocks();
    }
    while THREADS.iter().enumerate().any(|(processor, blocks)| {
        sampled(processor) && blocks.state.load(Ordering::Acquire) != ProfilerState::Stopping
    }) {}
    write_blocks();
    let seconds = Timebase::now().ticks().wrapping_sub(START_TIMEBASE.load())
        / kernel::performance_frequency();
    HEADER
        .end_time
        .store(seconds * FILETIME_PER_SECOND + HEADER.start_time.load());
    // `stop` clears `SAMPLING_ACTIVE` and disables the profile interrupt
    // before it stops the writer, so no processor counts.
    if !HEADER.write(Some(u64::from(SNAPSHOT_SIZE))) {
        report_fatal(c"[LOP] Fatal error. Error updating header file!\n");
    }
    // SAFETY: `handle` was opened above and is closed once.
    if !unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) }.is_success() {
        print(c"[LOP] Close handle failed!\n", &[]);
    }
    WRITER_FINISHED.set();
    0
}

fn fail_writer() -> u32 {
    WRITER_FAILED.store(true, Ordering::Release);
    WRITER_STARTED.set();
    WRITER_FINISHED.set();
    0
}

// Kernel entry of `writer_thread`, preserving the full nonvolatile
// registers.
crate::exports::bridged!(writer_thread_entry, writer_thread);

/// Start the writer and wait until it has written the prologue (stock
/// 0x91f8fcc0). The thread handle stays open, as in stock.
fn start_writer() -> bool {
    for (processor, blocks) in THREADS.iter().enumerate() {
        if sampled(processor) {
            blocks.state.store(ProfilerState::Active, Ordering::Release);
        }
    }
    WRITER_STARTED.reset();
    WRITER_FINISHED.reset();
    WRITER_FAILED.store(false, Ordering::Relaxed);
    let writer_processor = ProfilerFlags(FLAGS.load(Ordering::Relaxed)).writer_processor();
    // Not `ThreadCreationFlags::processors`: the 3-bit field also selects
    // processors 6 and 7, whose bits stock passes on.
    let affinity = ThreadCreationFlags::from_bits_retain(
        ThreadCreationFlags::PROCESSOR0.bits() << writer_processor,
    );
    let mut handle = 0u32;
    // SAFETY: `handle` is a live u32; the writer takes no context and reads
    // only static state.
    let created = unsafe {
        xboxkrnl::ExCreateThread(
            &mut handle,
            WRITER_STACK,
            core::ptr::null_mut(),
            0,
            writer_thread_entry as *const () as usize as u32,
            0,
            WRITER_FLAGS.union(affinity),
        )
    };
    if !created.is_success() {
        return false;
    }
    if !WRITER_STARTED.wait() {
        print(c"[LOP] Wait for poll thread initialize failed\n", &[]);
    }
    !WRITER_FAILED.load(Ordering::Acquire)
}

/// Make the writer flush everything and wait for it (stock 0x91f8fc00).
fn stop_writer() {
    for (processor, blocks) in THREADS.iter().enumerate() {
        if sampled(processor) {
            blocks
                .state
                .store(ProfilerState::Stopping, Ordering::Release);
        }
    }
    if !WRITER_FINISHED.wait() {
        print(c"[LOP] Wait for poll thread shutdown failed\n", &[]);
    }
    for (processor, blocks) in THREADS.iter().enumerate() {
        if sampled(processor) {
            // SAFETY: the writer has finished, and no processor samples:
            // `stop` disables the profile interrupt first, and a failed
            // `start` never sets `SAMPLING_ACTIVE`. A failed wait (only
            // possible on a kernel error, as in stock) leaves the writer
            // unsynchronized.
            unsafe { blocks.reset() };
        }
    }
}

/// Program the interval timer and run the counters (stock 0x91f90138).
fn start_sampling(interval: u32) -> bool {
    if !pmc::stop(Owner::PROFILER) || !pmc::clear(Owner::PROFILER) {
        return false;
    }
    // Stock leaves the other bits of the control value uninitialized.
    pmc::set_interval_control(IntervalControl::INTERRUPT.bits());
    INTERVAL.store(interval, Ordering::Relaxed);
    pmc::set_interval(interval.wrapping_neg());
    pmc::start(Owner::PROFILER)
}

/// Undo the interrupt hook and release the counters and buffers.
fn unhook() {
    disable_profile_interrupt();
    let _ = set_profile_routine(0);
    HOOKED.store(false, Ordering::Release);
    pmc::release(Owner::PROFILER);
}

/// The sampling engine behind [`CONTROL`].
struct Sampler;

impl profiler::Engine for Sampler {
    /// Stock 0x91f90768. Stock also reads the memory statistics into a
    /// local it discards and seeds a random interval generator whose output
    /// it never uses; the latter is omitted.
    fn initialize(&mut self, flags: ProfilerFlags) -> Result<(), ProfilerError> {
        FLAGS.store(flags.0, Ordering::Relaxed);
        if !create_buffers(flags) {
            print(c"[LOP] CreateSharedBuffers Failed!!!\n", &[]);
            return Err(ProfilerError::NoBuffers);
        }
        for word in HEADER.words() {
            word.store(0, Ordering::Relaxed);
        }
        let mut statistics = MmStatistics::new();
        // SAFETY: `statistics` is a live block with its length set.
        unsafe { xboxkrnl::MmQueryStatistics(&mut statistics) };
        HEADER.version.store(HEADER_VERSION, Ordering::Relaxed);
        HEADER
            .processors
            .store(flags.processors(), Ordering::Relaxed);
        for (index, &word) in TITLE_WORDS.iter().enumerate() {
            HEADER.title[index].store(word, Ordering::Relaxed);
        }
        for busy in &BUSY {
            busy.store(0, Ordering::Relaxed);
        }
        if !pmc::acquire(Owner::PROFILER) {
            return Err(ProfilerError::NoCounters);
        }
        HOOKED.store(true, Ordering::Release);
        set_profile_routine(profile_interrupt_entry as *const () as usize as u32)?;
        enable_profile_interrupt(flags.processors())?;
        pmc::reset();
        Ok(())
    }

    /// Stock 0x91f90220.
    fn abandon(&mut self) {
        unhook();
        free_buffers();
    }

    /// Stock 0x91f64448.
    fn create_directories(&mut self, path: &[u8]) {
        let request = CreateRequest {
            access: AccessMask::SYNCHRONIZE.union(AccessMask::LIST_DIRECTORY),
            allocation_size: None,
            attributes: FileAttributes::NORMAL,
            share: ShareAccess::READ.union(ShareAccess::WRITE),
            disposition: CreateDisposition::Create,
            options: CreateOptions::DIRECTORY_FILE
                .union(CreateOptions::SYNCHRONOUS_IO_NONALERT)
                .union(CreateOptions::OPEN_FOR_BACKUP_INTENT),
        };
        for (index, _) in path
            .iter()
            .enumerate()
            .skip(1)
            .filter(|&(_, &byte)| byte == b'\\')
        {
            if let Ok(handle) = filesystem::create_file(&path[..index], &request) {
                // SAFETY: `handle` was just opened and is closed once.
                unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
            }
        }
    }

    /// Stock 0x91f90258.
    fn start(&mut self, path: Option<&[u8]>, interval: u32) -> Result<(), ProfilerError> {
        if SAMPLING_ACTIVE.load(Ordering::Acquire) {
            print(c"[LOP] Already started\n", &[]);
            return Err(ProfilerError::AlreadyRunning);
        }
        let started = path.is_some_and(|path| {
            // SAFETY: see `WriterPaths`; no writer runs.
            let paths = unsafe { &mut *WRITER_PATHS.0.get() };
            let length = path.len().min(paths.file.len());
            paths.file[..length].copy_from_slice(&path[..length]);
            paths.file_length = length;
            start_writer()
        });
        if !started {
            print(c"[LOP] Prologue Failed!!!\n", &[]);
            return Err(ProfilerError::PrologueFailed);
        }
        HEADER.start_time.store(FileTime::now().intervals());
        START_TIMEBASE.store(Timebase::now().ticks());
        if !start_sampling(interval) {
            stop_writer();
            return Err(ProfilerError::NoCounters);
        }
        SAMPLING_ACTIVE.store(true, Ordering::Release);
        Ok(())
    }

    /// Stock 0x91f90310, 0x91f901d0.
    fn stop(&mut self) -> Result<(), ProfilerError> {
        SAMPLING_ACTIVE.store(false, Ordering::Release);
        let result = if pmc::stop(Owner::PROFILER) {
            pmc::clear(Owner::PROFILER);
            INTERVAL.store(0, Ordering::Relaxed);
            Ok(())
        } else {
            Err(ProfilerError::NotCounterOwner)
        };
        unhook();
        stop_writer();
        free_buffers();
        result
    }

    /// Stock 0x91f90370.
    fn info(&mut self) -> CpuProfilerInfo {
        let elapsed = pmc::to_double(Timebase::now().ticks().wrapping_sub(START_TIMEBASE.load()))
            / pmc::to_double(kernel::performance_frequency());
        let last = last_processor();
        CpuProfilerInfo {
            elapsed_time: elapsed as i64 as u32,
            total_samples: HEADER.interrupts[last].load(Ordering::Relaxed),
            overhead_interrupts: HEADER.busy[last].load(Ordering::Relaxed),
        }
    }
}

/// Executable drive path of the module snapshot (stock 0x91f33c38, which
/// export 131 runs on the writer thread; here the starter prepares it).
fn store_executable_path(executable: &[u8]) {
    // SAFETY: see `WriterPaths`; no writer runs.
    let paths = unsafe { &mut *WRITER_PATHS.0.get() };
    let length = executable.len().min(paths.executable.len());
    paths.executable[..length].copy_from_slice(&executable[..length]);
    paths.executable_length = length;
}

/// `lopctrl start` and export 149: `path` is the object name of the
/// requested file, `executable` the drive path of the running executable.
pub(super) fn start(
    path: Option<&[u8]>,
    executable: &[u8],
    interval: u32,
    flags: ProfilerFlags,
) -> Result<(), ProfilerError> {
    if !CONTROL.running() {
        store_executable_path(executable);
    }
    CONTROL.start(&mut Sampler, path, interval, flags)
}

pub(super) fn stop() -> Result<(), ProfilerError> {
    CONTROL.stop(&mut Sampler)
}

pub(super) fn info() -> Result<CpuProfilerInfo, ProfilerError> {
    CONTROL.info(&mut Sampler)
}

/// Stock 0x91f32ff8.
pub(super) fn running() -> bool {
    CONTROL.running()
}

/// Profiler part of the title terminate notification (stock 0x91f33090).
pub(super) fn title_terminated() {
    CONTROL.title_terminated(&mut Sampler);
}

/// Remove the interrupt hook and stop the writer before the image unloads;
/// stock never unloads.
pub(super) fn shut_down() {
    if CONTROL.running() {
        let _ = CONTROL.stop(&mut Sampler);
    } else if HOOKED.load(Ordering::Acquire) {
        profiler::Engine::abandon(&mut Sampler);
    }
}

/// Request of [`translate_on_server`].
struct Translation<'a> {
    name: &'a [u8],
    path: Option<ObjectPath>,
    executable: [u8; module_snapshot::PATH_LIMIT + 2],
    executable_length: usize,
}

fn translate_on_server(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    request: &mut Translation<'_>,
) -> u32 {
    let drives = &server.state.filesystem.drives;
    request.path = drives.translate(console, request.name);
    request.executable_length = drives.object_path_to_drive_path(
        console,
        module_snapshot::ExecutableObjectPath::read().as_bytes(),
        &mut request.executable,
    );
    0
}

/// Export 149: start profiling into drive path `name`. The drive table is
/// read on the server thread; where that cannot wait, the name has no
/// object path.
extern "C" fn export_start(name: u32, interval: u32, flags: u32) -> u32 {
    /// Characters of the name `lopctrl` accepts at most.
    const NAME_LIMIT: usize = 0x140;
    let mut request = Translation {
        // SAFETY: the export takes a NUL-terminated drive path, not 0 (stock
        // reads it without a check; here 0 breaks the export contract),
        // that the caller keeps unchanged during the call.
        name: unsafe { kernel::bounded_c_string(name, NAME_LIMIT).unwrap_unchecked() },
        path: None,
        executable: [0; module_snapshot::PATH_LIMIT + 2],
        executable_length: 0,
    };
    if dispatcher::call_on_server_with(&mut request, translate_on_server).is_none() {
        request.executable_length =
            module_snapshot::copy_executable_object_path(&mut request.executable);
    }
    let path = request.path.as_ref().map(|path| path.as_bytes());
    crate::exports::export_result(start(
        path,
        &request.executable[..request.executable_length],
        interval,
        ProfilerFlags(flags),
    ))
    .0
}

/// Export 150.
extern "C" fn export_stop() -> u32 {
    crate::exports::export_result(stop()).0
}

/// Export 151: elapsed seconds, total samples, and overhead interrupts;
/// the outputs are written only on success.
extern "C" fn export_info(elapsed: *mut u32, samples: *mut u32, overhead: *mut u32) -> u32 {
    let result = info().map(|info| {
        // SAFETY: the export takes three writable u32 outputs.
        unsafe {
            *elapsed = info.elapsed_time;
            *samples = info.total_samples;
            *overhead = info.overhead_interrupts;
        }
    });
    crate::exports::export_result(result).0
}

export!(149, export_start);
export!(150, export_stop);
export!(151, export_info);
