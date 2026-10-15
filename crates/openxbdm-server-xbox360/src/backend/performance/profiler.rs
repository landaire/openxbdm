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
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_server::Server;
use openxbdm_server::commands::filesystem::CreateDisposition;
use openxbdm_server::commands::filesystem::CreateOptions;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::FileAccess;
use openxbdm_server::commands::filesystem::FileAttributes;
use openxbdm_server::commands::filesystem::ObjectPath;
use openxbdm_server::commands::filesystem::ShareAccess;
use openxbdm_server::commands::performance::CpuProfilerInfo;
use openxbdm_server::commands::performance::profiler;
use openxbdm_server::commands::performance::profiler::BLOCK_SIZE;
use openxbdm_server::commands::performance::profiler::BufferLayout;
use openxbdm_server::commands::performance::profiler::BufferMemory;
use openxbdm_server::commands::performance::profiler::MAX_BLOCKS;
use openxbdm_server::commands::performance::profiler::ProfilerFlags;

use super::module_snapshot;
use super::pmc;
use super::pmc::Owner;
use super::pmc::print;
use crate::backend::Console;
use crate::backend::dispatcher;
use crate::backend::filesystem;
use crate::backend::memory::RtlImageDirectoryEntryToData;
use crate::exports::export;
use crate::kernel;
use crate::kernel::IoStatusBlock;
use crate::kernel::LIB_KERNEL;
use crate::kernel::import_thunk;
use crate::net::XamNetwork;

use crate::kernel::GetCurrentThreadId;
import_thunk!(
    InterlockedPopEntrySList(header: *mut u64) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x2c
);
import_thunk!(
    InterlockedFlushSList(header: *mut u64) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x2b
);

/// Kernel exports of the profile interrupt: enable on a processor mask,
/// disable, and set the routine.
const ENABLE_PROFILE_INTERRUPT: u32 = 669;
const DISABLE_PROFILE_INTERRUPT: u32 = 670;
const SET_PROFILE_ROUTINE: u32 = 671;
const PROCESSORS: usize = 6;
/// Deepest call stack a sample records, the interrupted address included.
const MAX_FRAMES: usize = 500;
/// Words of a sample record before the frames.
const RECORD_HEADER_WORDS: usize = 10;
const RECORD_MAGIC: u32 = 0x0cdc_dce8;
/// The sample came from a leaf function's epilogue (record +0x24).
const LEAF: u32 = 0x8000_0000;
/// Module snapshot at the start of the file; the header follows it.
const SNAPSHOT_SIZE: u32 = module_snapshot::SIZE;
const HEADER_SIZE: usize = 0x200;
const HEADER_VERSION: u32 = 0x201;
const TITLE: &[u8] = b"Microsoft CPU Profiler for Xbox";
/// Function tables the file records at most.
const MODULE_CAPACITY: usize = 0x80;
const WRITER_STACK: u32 = 0x8000;
/// `ExCreateThread` flags of the writer; the processor goes in the top byte.
const WRITER_FLAGS: u32 = 0x4a2;
const POLL_INTERVAL_MS: u32 = 250;
const FILETIME_PER_SECOND: u64 = 10_000_000;
/// `NtAllocateVirtualMemory` type: commit, reserve, 64 KiB pages.
const ALLOCATION_TYPE: u32 = 0x2000_3000;
const PAGE_READWRITE: u32 = 4;
const MEM_RELEASE: u32 = 0x8000;
/// Memory options of the sample buffers.
const TITLE_MEMORY: u32 = 3;
const SYSTEM_FALLBACK_MEMORY: u32 = 1;
const SYSTEM_MEMORY: u32 = 2;
/// Physical memory of the function table copies.
const PHYSICAL_MEMORY: u32 = 1;
const IMAGE_DIRECTORY_EXCEPTION: u32 = 3;
/// Interval timer control: interrupt when the interval expires.
const INTERVAL_INTERRUPT: u64 = 0x8000 << 32;

const NO_KERNEL: Hresult = Hresult::error(0x03);
const NO_PROFILE_EXPORT: Hresult = Hresult::error(0x07);
const PROFILE_INTERRUPT_REFUSED: Hresult = Hresult::error(0x17);
const NO_BUFFERS: Hresult = Hresult::error(0x1c);
const NO_COUNTERS: Hresult = Hresult::error(0x2c);
const NOT_COUNTER_OWNER: Hresult = Hresult::error(0x2d);
/// Result of a started engine (stock 0x91f90258 returns 1).
const SAMPLING: Hresult = Hresult(1);

/// Header word offsets; per-processor arrays have six words.
mod header {
    pub(super) const VERSION: usize = 0x00;
    pub(super) const WRITE_ERRORS: usize = 0x08;
    pub(super) const PROCESSORS: usize = 0x14;
    pub(super) const START_TIME: usize = 0x18;
    pub(super) const END_TIME: usize = 0x20;
    /// Cleared before the file is opened, up to the title.
    pub(super) const COUNTERS: usize = 0x28;
    pub(super) const SAMPLES: usize = 0x40;
    /// Stack walks that hit the depth limit or faulted.
    pub(super) const FAULTED: usize = 0x58;
    pub(super) const RECORD_HEADER_SIZE: usize = 0x70;
    pub(super) const LARGEST: usize = 0x74;
    pub(super) const SMALLEST: usize = 0x8c;
    pub(super) const BYTES: usize = 0xa4;
    pub(super) const BLOCKS: usize = 0xbc;
    pub(super) const STORED: usize = 0xd4;
    pub(super) const DROPPED: usize = 0xec;
    pub(super) const INTERRUPTS: usize = 0x104;
    pub(super) const SAMPLED: usize = 0x11c;
    /// Interrupts above dispatch level or in the idle thread.
    pub(super) const SKIPPED: usize = 0x134;
    /// Interrupts while the processor's previous sample was in progress.
    pub(super) const BUSY: usize = 0x14c;
    pub(super) const TITLE: usize = 0x194;
}

static HEADER: [AtomicU32; HEADER_SIZE / 4] = [const { AtomicU32::new(0) }; HEADER_SIZE / 4];

fn header_word(offset: usize) -> &'static AtomicU32 {
    &HEADER[offset / 4]
}

fn processor_word(offset: usize, processor: usize) -> &'static AtomicU32 {
    header_word(offset + 4 * processor)
}

fn count(offset: usize, processor: usize) {
    processor_word(offset, processor).fetch_add(1, Ordering::Relaxed);
}

fn set_header_time(offset: usize, time: u64) {
    header_word(offset).store((time >> 32) as u32, Ordering::Relaxed);
    header_word(offset + 4).store(time as u32, Ordering::Relaxed);
}

fn header_time(offset: usize) -> u64 {
    u64::from(header_word(offset).load(Ordering::Relaxed)) << 32
        | u64::from(header_word(offset + 4).load(Ordering::Relaxed))
}

static CONTROL: profiler::Control = profiler::Control::new();
static FLAGS: AtomicU32 = AtomicU32::new(0);
/// Samples are recorded (stock 0x91fa3b08).
static SAMPLING_ACTIVE: AtomicBool = AtomicBool::new(false);
/// The interrupt routine is set.
static HOOKED: AtomicBool = AtomicBool::new(false);
static INTERVAL: AtomicU32 = AtomicU32::new(0);
static START_TIMEBASE: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
static BLOCKS: AtomicU32 = AtomicU32::new(0);
static BUFFER: AtomicU32 = AtomicU32::new(0);
static BUFFER_BYTES: AtomicU32 = AtomicU32::new(0);
static BUFFER_MEMORY: AtomicU32 = AtomicU32::new(0);
/// Where the writer gathers full blocks before writing them.
static STAGING: AtomicU32 = AtomicU32::new(0);
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
    match processors() {
        0 => 0,
        mask => 31 - mask.leading_zeros() as usize,
    }
}

fn start_timebase() -> u64 {
    u64::from(START_TIMEBASE[0].load(Ordering::Relaxed)) << 32
        | u64::from(START_TIMEBASE[1].load(Ordering::Relaxed))
}

fn read_u32(address: u32) -> u32 {
    // SAFETY: callers pass mapped addresses.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn pcr_word(offset: u32) -> u32 {
    read_u32(kernel::pcr() + offset)
}

/// A kernel notification event in static storage.
struct NotificationEvent(UnsafeCell<[u32; 4]>);

// SAFETY: the kernel synchronizes access to dispatcher objects.
unsafe impl Sync for NotificationEvent {}

impl NotificationEvent {
    fn pointer(&self) -> *mut u32 {
        self.0.get().cast()
    }

    /// Unsignaled, with the wait list head pointing at itself.
    fn reset(&self) {
        let list = self.pointer().wrapping_add(2) as usize as u32;
        // SAFETY: called before the writer thread exists.
        unsafe { *self.0.get() = [0, 0, list, list] };
    }

    fn set(&self) {
        kernel::KeSetEvent(self.pointer(), 1, 0);
    }

    fn wait(&self) -> bool {
        (kernel::KeWaitForSingleObject(self.pointer(), 0, 0, 0, core::ptr::null()) as i32) >= 0
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
        match InterlockedPopEntrySList(self.0.get()) {
            0 => None,
            entry => Some(entry),
        }
    }

    fn flush(&self) {
        InterlockedFlushSList(self.0.get());
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
        "bne- 2b",
        "blr",
    )
}

const ACTIVE: u32 = 1;
const STOPPING: u32 = 2;

/// Sample blocks of one processor (stock 0x91fa9a08 + 0x148 * processor).
/// The block being filled is popped from `free` while a sample is copied
/// into it and pushed back after; full blocks go to `full`.
#[repr(C, align(8))]
struct ThreadBlocks {
    free: ListHead,
    full: ListHead,
    entries: [ListEntry; MAX_BLOCKS as usize],
    fill: [AtomicU32; MAX_BLOCKS as usize],
    blocks: [AtomicU32; MAX_BLOCKS as usize],
    state: AtomicU32,
}

// SAFETY: the list heads and entries change only through interlocked
// operations; the other fields are atomics.
unsafe impl Sync for ThreadBlocks {}

static THREADS: [ThreadBlocks; PROCESSORS] = [const {
    ThreadBlocks {
        free: ListHead::new(),
        full: ListHead::new(),
        entries: [const { ListEntry(UnsafeCell::new(0)) }; MAX_BLOCKS as usize],
        fill: [const { AtomicU32::new(0) }; MAX_BLOCKS as usize],
        blocks: [const { AtomicU32::new(0) }; MAX_BLOCKS as usize],
        state: AtomicU32::new(0),
    }
}; PROCESSORS];

impl ThreadBlocks {
    fn entry(&self, index: usize) -> u32 {
        self.entries[index].0.get() as usize as u32
    }

    fn index(&self, entry: u32) -> usize {
        (entry - self.entry(0)) as usize / 8
    }

    /// Empty both lists and queue every assigned block, zeroed (stock
    /// 0x91f90858).
    fn reset(&self) {
        self.free.flush();
        self.full.flush();
        for index in 0..MAX_BLOCKS as usize {
            let block = self.blocks[index].load(Ordering::Relaxed);
            if block != 0 {
                // SAFETY: the entry is in no list.
                unsafe { *self.entries[index].0.get() = 0 };
                self.free.push(self.entry(index));
                zero(block, BLOCK_SIZE);
                self.fill[index].store(0, Ordering::Relaxed);
            }
        }
    }

    /// Room for `size` bytes in the current block: the block's entry index
    /// and the address. A block without room is padded with zeros and
    /// queued as full (stock 0x91f908e8).
    fn allocate(&self, size: u32) -> Option<(usize, u32)> {
        while let Some(entry) = self.free.pop() {
            let index = self.index(entry);
            let fill = self.fill[index].load(Ordering::Relaxed);
            let start = self.blocks[index].load(Ordering::Relaxed) + fill;
            let end = self.blocks[index].load(Ordering::Relaxed) + BLOCK_SIZE;
            if start + size <= end {
                self.fill[index].store(fill + size, Ordering::Relaxed);
                return Some((index, start));
            }
            zero(start, end - start);
            self.fill[index].store(0, Ordering::Relaxed);
            self.full.push(entry);
        }
        None
    }

    /// Copy the used blocks of `from`, oldest first, to `destination`, zero
    /// them, and queue them on `to`; returns the end of the copy (stock
    /// 0x91f8f3f0).
    fn drain(&self, from: &ListHead, to: &ListHead, destination: u32) -> u32 {
        let mut pending = [0u32; MAX_BLOCKS as usize];
        let mut count = 0;
        while let Some(entry) = from.pop() {
            pending[count] = entry;
            count += 1;
        }
        let mut destination = destination;
        for &entry in pending[..count].iter().rev() {
            let block = self.blocks[self.index(entry)].load(Ordering::Relaxed);
            if read_u32(block) != 0 {
                // SAFETY: the block and the staging area hold `BLOCK_SIZE`
                // bytes each and do not overlap.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        block as usize as *const u8,
                        destination as usize as *mut u8,
                        BLOCK_SIZE as usize,
                    )
                };
                destination += BLOCK_SIZE;
            }
            zero(block, BLOCK_SIZE);
            to.push(entry);
        }
        destination
    }
}

fn zero(address: u32, length: u32) {
    // SAFETY: callers pass memory of the sample buffer.
    unsafe { core::ptr::write_bytes(address as usize as *mut u8, 0, length as usize) };
}

/// A sample record: the header words, then the return addresses.
#[repr(C)]
struct Record {
    head: [u32; RECORD_HEADER_WORDS],
    frames: [u32; MAX_FRAMES],
}

/// Per-processor sample in progress (stock 0x91fa3b10): a busy word and
/// the record being built.
struct Samples {
    busy: [AtomicU32; PROCESSORS],
    records: UnsafeCell<[Record; PROCESSORS]>,
}

// SAFETY: a processor uses its record only while it holds its busy word.
unsafe impl Sync for Samples {}

static SAMPLES: Samples = Samples {
    busy: [const { AtomicU32::new(0) }; PROCESSORS],
    records: UnsafeCell::new(
        [const {
            Record {
                head: [0; RECORD_HEADER_WORDS],
                frames: [0; MAX_FRAMES],
            }
        }; PROCESSORS],
    ),
};

/// The interrupted state the kernel passes to the profile routine.
#[derive(Clone, Copy)]
struct TrapFrame(u32);

impl TrapFrame {
    /// Low word of saved register `register`.
    fn register(self, register: u32) -> u32 {
        read_u32(self.0 + 0x54 + register * 8)
    }

    fn link(self) -> u32 {
        read_u32(self.0 + 0x1a8)
    }

    fn address(self) -> u32 {
        read_u32(self.0 + 0x1ac)
    }
}

fn valid(address: u32) -> bool {
    kernel::MmIsAddressValid(address) != 0
}

/// The interrupted code is a leaf epilogue: the instructions up to `blr`
/// (at most 13) only load, branch, or restore the link register (stock
/// 0x91f90030). `None` when the code is unreadable; stock catches that
/// fault.
fn in_leaf_epilogue(frame: TrapFrame) -> Option<bool> {
    let mut address = frame.address();
    for _ in 0..13 {
        if address & 0xfff == 0 && !valid(address) {
            return None;
        }
        let instruction = read_u32(address);
        if instruction == 0x4e80_0020 {
            return Some(true);
        }
        let opcode = instruction >> 26;
        let allowed = matches!(opcode, 0x3a | 0x20 | 0x32 | 0x12)
            || (opcode == 0x1f && instruction & 0x7fe == 0xce)
            || instruction == 0x7d88_03a6;
        if !allowed {
            return Some(false);
        }
        address += 4;
    }
    Some(true)
}

/// Return addresses of the interrupted thread's stack, the interrupted
/// address first, into `frames`; `None` at `MAX_FRAMES` (stock 0x91f900b8).
fn walk_stack(frame: TrapFrame, frames: &mut [u32; MAX_FRAMES]) -> Option<usize> {
    frames[0] = frame.address();
    let mut count = 1;
    let mut stack = frame.register(1);
    loop {
        let thread = pcr_word(0x100);
        stack = read_u32(stack);
        if stack >= read_u32(thread + 0x5c) || stack <= read_u32(thread + 0x60) {
            return Some(count);
        }
        frames[count] = read_u32(stack - 8);
        count += 1;
        if count == MAX_FRAMES {
            return None;
        }
    }
}

/// Record one sample of `processor` (stock 0x91f90420, 0x91f8fe70,
/// 0x91f8f7f8). Stock reads the code and the stack under an exception
/// handler; an unreadable address counts as a faulted walk here.
fn sample(frame: TrapFrame, processor: usize) {
    let stack = frame.register(1);
    let readable = valid(frame.address()) && valid(stack) && valid(stack.wrapping_sub(8));
    // SAFETY: this processor holds its busy word.
    let record = unsafe { &mut (*SAMPLES.records.get())[processor] };
    let walked = if readable {
        in_leaf_epilogue(frame)
    } else {
        None
    }
    .and_then(|leaf| walk_stack(frame, &mut record.frames).map(|depth| (leaf, depth)));
    let Some((leaf, depth)) = walked else {
        count(header::FAULTED, processor);
        return;
    };
    count(header::SAMPLES, processor);
    let size = ((depth + RECORD_HEADER_WORDS) * 4) as u32;
    record.head = [
        RECORD_MAGIC,
        0,
        0,
        size,
        GetCurrentThreadId(),
        frame.link(),
        read_u32(stack - 8),
        frame.register(12),
        read_u32(frame.address()),
        processor as u32 | if leaf { LEAF } else { 0 },
    ];
    processor_word(header::BYTES, processor).fetch_add(size, Ordering::Relaxed);
    processor_word(header::LARGEST, processor).fetch_max(size, Ordering::Relaxed);
    processor_word(header::SMALLEST, processor).fetch_min(size, Ordering::Relaxed);
    let time = kernel::timebase();
    record.head[1] = (time >> 32) as u32;
    record.head[2] = time as u32;
    let blocks = &THREADS[processor];
    match blocks.allocate(size) {
        Some((index, address)) => {
            count(header::STORED, processor);
            // SAFETY: `allocate` reserved `size` bytes at `address`; the
            // record's words are contiguous.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (record as *const Record).cast::<u8>(),
                    address as usize as *mut u8,
                    size as usize,
                )
            };
            blocks.free.push(blocks.entry(index));
        }
        None => count(header::DROPPED, processor),
    }
}

/// Profile interrupt routine (stock 0x91f90528): the last sampled
/// processor reloads the interval; samples are skipped above dispatch level
/// and in an idle thread without pending DPCs.
extern "C" fn profile_interrupt(frame: u32, irql: u32) {
    let processor = usize::from(pmc::current_processor());
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
    count(header::INTERRUPTS, processor);
    let prcb = pcr_word(0x2a8);
    if irql & 0xff > 2 || (read_u32(prcb + 8) == pcr_word(0x100) && read_u32(prcb + 0x50) == 0) {
        count(header::SKIPPED, processor);
        return;
    }
    count(header::SAMPLED, processor);
    let busy = &SAMPLES.busy[processor];
    if busy
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        sample(TrapFrame(frame), processor);
        busy.store(0, Ordering::Release);
    } else {
        count(header::BUSY, processor);
    }
}

/// Kernel entry of [`profile_interrupt`], preserving the full nonvolatile
/// registers.
#[unsafe(naked)]
extern "C" fn profile_interrupt_entry() {
    core::arch::naked_asm!(
        "lis 12, {routine}@ha",
        "addi 12, 12, {routine}@l",
        "b {bridge}",
        routine = sym profile_interrupt,
        bridge = sym crate::exports::export_bridge,
    )
}

/// Call profile interrupt export `ordinal` of the kernel (stock
/// 0x91f8eeb0, 0x91f8ef48, 0x91f8efd0).
fn call_kernel(ordinal: u32, argument: u32) -> Result<u32, Hresult> {
    let kernel = kernel::module_handle(c"xboxkrnl.exe").map_err(|_| NO_KERNEL)?;
    let function = kernel::resolve_export(kernel, ordinal).map_err(|_| NO_PROFILE_EXPORT)?;
    // SAFETY: the profile exports take one register argument.
    Ok(unsafe { kernel::call_export(function, argument, 0, 0, 0) })
}

fn set_profile_routine(routine: u32) -> Hresult {
    call_kernel(SET_PROFILE_ROUTINE, routine).map_or_else(|result| result, |_| Hresult::OK)
}

fn enable_profile_interrupt(mask: u32) -> Hresult {
    match call_kernel(ENABLE_PROFILE_INTERRUPT, mask) {
        Ok(enabled) if enabled & 0xff != 0 => Hresult::OK,
        Ok(_) => PROFILE_INTERRUPT_REFUSED,
        Err(result) => result,
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
    let mut allocate = |memory| {
        BUFFER_MEMORY.store(memory, Ordering::Relaxed);
        (kernel::NtAllocateVirtualMemory(
            &mut base,
            &mut bytes,
            ALLOCATION_TYPE,
            PAGE_READWRITE,
            memory,
        ) as i32)
            >= 0
    };
    let allocated = match layout.memory {
        BufferMemory::Title => allocate(TITLE_MEMORY) || allocate(SYSTEM_FALLBACK_MEMORY),
        BufferMemory::System => allocate(SYSTEM_MEMORY),
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
    zero(base, bytes);
    assign_blocks(base, layout);
    true
}

fn assign_blocks(base: u32, layout: BufferLayout) {
    let mut assigned = 0;
    for (processor, blocks) in THREADS.iter().enumerate() {
        if !sampled(processor) {
            continue;
        }
        for index in 0..MAX_BLOCKS as usize {
            blocks.fill[index].store(0, Ordering::Relaxed);
            let block = if (index as u32) < layout.blocks {
                base + (layout.blocks * assigned + index as u32) * BLOCK_SIZE
            } else {
                0
            };
            blocks.blocks[index].store(block, Ordering::Relaxed);
        }
        blocks.state.store(ACTIVE, Ordering::Relaxed);
        blocks.reset();
        assigned += 1;
    }
    if STAGING.load(Ordering::Relaxed) == 0 {
        STAGING.store(
            base + layout.blocks * assigned * BLOCK_SIZE,
            Ordering::Relaxed,
        );
    }
}

/// Stock 0x91f8f318.
fn free_buffers() {
    for (processor, blocks) in THREADS.iter().enumerate() {
        if sampled(processor) {
            for block in &blocks.blocks[..BLOCKS.load(Ordering::Relaxed) as usize] {
                block.store(0, Ordering::Relaxed);
            }
        }
    }
    STAGING.store(0, Ordering::Relaxed);
    let mut base = BUFFER.load(Ordering::Relaxed);
    if base != 0 {
        let mut bytes = BUFFER_BYTES.load(Ordering::Relaxed);
        kernel::NtFreeVirtualMemory(
            &mut base,
            &mut bytes,
            MEM_RELEASE,
            BUFFER_MEMORY.load(Ordering::Relaxed),
        );
        BUFFER.store(0, Ordering::Relaxed);
    }
}

/// Write `length` bytes at `address`; true when all were written (stock
/// 0x91f73af8). `offset` is the file position, the current one when
/// `None`.
fn write(address: u32, length: u32, offset: Option<u64>) -> bool {
    let mut io_status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let offset_pointer = offset
        .as_ref()
        .map_or(core::ptr::null(), |offset| offset as *const u64);
    let status = kernel::NtWriteFile(
        FILE.load(Ordering::Relaxed),
        0,
        0,
        0,
        &mut io_status,
        address as usize as *const u8,
        length,
        offset_pointer,
    );
    (status as i32) >= 0 && io_status.information == length
}

/// A module's exception directory copy (stock 0x91f32e90 entries).
#[derive(Clone, Copy, Default)]
struct FunctionTable {
    base: u32,
    image_size: u32,
    size: u32,
    copy: u32,
}

/// Copy the exception directories of the loaded modules into physical
/// memory (stock 0x91f32e90); `None` when a copy cannot be allocated.
fn copy_function_tables(tables: &mut [FunctionTable; MODULE_CAPACITY]) -> Option<usize> {
    let data = kernel::debug_monitor_data();
    let lock = data.loader_lock() as usize as *mut u32;
    let irql = kernel::KfAcquireSpinLock(lock);
    let mut count = 0;
    let mut result = Some(0);
    'lists: for &head in &[data.module_list(), data.secondary_module_list()] {
        // Stock reads a missing list head without a check.
        if head == 0 {
            continue;
        }
        let mut entry = read_u32(head);
        while entry != head && count < MODULE_CAPACITY {
            let base = read_u32(entry + 0x18);
            if base != 0 {
                let mut size = 0u32;
                let directory =
                    RtlImageDirectoryEntryToData(base, 1, IMAGE_DIRECTORY_EXCEPTION, &mut size);
                let mut table = FunctionTable {
                    base,
                    image_size: read_u32(entry + 0x20),
                    size: 0,
                    copy: 0,
                };
                if directory != 0 {
                    table.copy = kernel::MmAllocatePhysicalMemoryEx(
                        PHYSICAL_MEMORY,
                        size,
                        PAGE_READWRITE,
                        0,
                        u32::MAX,
                        0x1000,
                    );
                    if table.copy == 0 {
                        // Stock also passes the null copies of modules
                        // without a directory to MmFreePhysicalMemory.
                        for table in &tables[..count] {
                            if table.copy != 0 {
                                kernel::MmFreePhysicalMemory(PHYSICAL_MEMORY, table.copy);
                            }
                        }
                        result = None;
                        break 'lists;
                    }
                    table.size = size;
                    // SAFETY: the directory and the copy hold `size` bytes.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            directory as usize as *const u8,
                            table.copy as usize as *mut u8,
                            size as usize,
                        )
                    };
                }
                tables[count] = table;
                count += 1;
            }
            entry = read_u32(entry);
        }
    }
    kernel::KfReleaseSpinLock(lock, irql);
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
    kernel::DbgBreakPoint();
}

/// Write the module snapshot, the header, and the function tables (stock
/// 0x91f8f5c0).
fn write_prologue() -> bool {
    for offset in (header::COUNTERS..header::TITLE).step_by(4) {
        header_word(offset).store(0, Ordering::Relaxed);
    }
    header_word(0x04).store(0, Ordering::Relaxed);
    header_word(header::WRITE_ERRORS).store(0, Ordering::Relaxed);
    header_word(header::RECORD_HEADER_SIZE)
        .store((RECORD_HEADER_WORDS * 4) as u32, Ordering::Relaxed);
    header_word(0x10).store(0, Ordering::Relaxed);
    for processor in 0..PROCESSORS {
        processor_word(header::BLOCKS, processor)
            .store(BLOCKS.load(Ordering::Relaxed), Ordering::Relaxed);
        processor_word(header::SMALLEST, processor).store(u32::MAX, Ordering::Relaxed);
    }
    // SAFETY: see `WriterPaths`.
    let paths = unsafe { &*WRITER_PATHS.0.get() };
    let time = kernel::system_time();
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
    if !write(snapshot.address(), SNAPSHOT_SIZE, None)
        || !write(HEADER.as_ptr() as usize as u32, HEADER_SIZE as u32, None)
    {
        module_snapshot::free(snapshot);
        report_fatal(c"[LOP] Fatal error. Error writing file header!\n");
        return false;
    }
    // Stock keeps the snapshot when the copies fail.
    if copy_function_tables(&mut tables).is_none() {
        report_fatal(c"[LOP] Fatal error. Could not allocate memory for function table data!\n");
        return false;
    }
    let modules = read_u32(snapshot.address() + 4) as usize;
    // Tables past the copied ones are zero and fail the base check.
    for (index, table) in tables.iter().enumerate().take(modules) {
        let record = [
            table.base.to_be(),
            table.image_size.to_be(),
            table.size.to_be(),
        ];
        let written = read_u32(snapshot.address() + 8 + index as u32 * 0x150) == table.base
            && write(record.as_ptr() as usize as u32, 12, None)
            && (table.size == 0 || {
                let written = write(table.copy, table.size, None);
                if written {
                    kernel::MmFreePhysicalMemory(PHYSICAL_MEMORY, table.copy);
                }
                written
            });
        if !written {
            module_snapshot::free(snapshot);
            report_fatal(c"[LOP] Fatal error. Error writing file header!\n");
            return false;
        }
    }
    module_snapshot::free(snapshot);
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
        let mut end = blocks.drain(&blocks.full, &blocks.free, staging);
        if blocks.state.load(Ordering::Acquire) != ACTIVE {
            end = blocks.drain(&blocks.free, &blocks.free, end);
        }
        if end != staging && !write(staging, end - staging, None) {
            header_word(header::WRITE_ERRORS).fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Writer thread (stock 0x91f8fa68). When the file cannot be opened or the
/// prologue fails, stock returns without signaling its starter, which then
/// waits forever; here the starter learns of the failure.
extern "C" fn writer_thread(_context: u32) -> u32 {
    // SAFETY: see `WriterPaths`.
    let paths = unsafe { &*WRITER_PATHS.0.get() };
    let request = CreateRequest {
        access: FileAccess(FileAccess::GENERIC_WRITE.0 | FileAccess::SYNCHRONIZE.0),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::READ,
        disposition: CreateDisposition::OverwriteIf,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    };
    let handle = match filesystem::create_file(&paths.file[..paths.file_length], &request) {
        Ok(handle) => handle,
        Err(status) => {
            print(
                c"[LOP] Error! %d\n",
                &[u64::from(kernel::RtlNtStatusToDosError(status.0))],
            );
            return fail_writer();
        }
    };
    FILE.store(handle.0, Ordering::Relaxed);
    if !write_prologue() {
        // Stock passes a stale register as the number.
        print(c"[LOP] Error! %d\n", &[0]);
        kernel::NtClose(handle.0);
        return fail_writer();
    }
    WRITER_STARTED.set();
    let last = &THREADS[last_processor()];
    while last.state.load(Ordering::Acquire) != STOPPING {
        kernel::sleep_milliseconds(POLL_INTERVAL_MS);
        write_blocks();
    }
    while THREADS.iter().enumerate().any(|(processor, blocks)| {
        sampled(processor) && blocks.state.load(Ordering::Acquire) != STOPPING
    }) {}
    write_blocks();
    let seconds =
        kernel::timebase().wrapping_sub(start_timebase()) / kernel::performance_frequency();
    set_header_time(
        header::END_TIME,
        seconds * FILETIME_PER_SECOND + header_time(header::START_TIME),
    );
    if !write(
        HEADER.as_ptr() as usize as u32,
        HEADER_SIZE as u32,
        Some(u64::from(SNAPSHOT_SIZE)),
    ) {
        report_fatal(c"[LOP] Fatal error. Error updating header file!\n");
    }
    if (kernel::NtClose(handle.0) as i32) < 0 {
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

/// Kernel entry of [`writer_thread`], preserving the full nonvolatile
/// registers.
#[unsafe(naked)]
extern "C" fn writer_thread_entry() {
    core::arch::naked_asm!(
        "lis 12, {routine}@ha",
        "addi 12, 12, {routine}@l",
        "b {bridge}",
        routine = sym writer_thread,
        bridge = sym crate::exports::export_bridge,
    )
}

/// Start the writer and wait until it has written the prologue (stock
/// 0x91f8fcc0). The thread handle stays open, as in stock.
fn start_writer() -> bool {
    for (processor, blocks) in THREADS.iter().enumerate() {
        if sampled(processor) {
            blocks.state.store(ACTIVE, Ordering::Release);
        }
    }
    WRITER_STARTED.reset();
    WRITER_FINISHED.reset();
    WRITER_FAILED.store(false, Ordering::Relaxed);
    let writer_processor = ProfilerFlags(FLAGS.load(Ordering::Relaxed)).writer_processor();
    let mut handle = 0u32;
    let created = kernel::ExCreateThread(
        &mut handle,
        WRITER_STACK,
        core::ptr::null_mut(),
        0,
        writer_thread_entry as *const () as usize as u32,
        0,
        (1u32 << writer_processor) << 24 | WRITER_FLAGS,
    );
    if (created as i32) < 0 {
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
            blocks.state.store(STOPPING, Ordering::Release);
        }
    }
    if !WRITER_FINISHED.wait() {
        print(c"[LOP] Wait for poll thread shutdown failed\n", &[]);
    }
    for (processor, blocks) in THREADS.iter().enumerate() {
        if sampled(processor) {
            blocks.reset();
        }
    }
}

/// Program the interval timer and run the counters (stock 0x91f90138).
fn start_sampling(interval: u32) -> bool {
    if !pmc::stop(Owner::PROFILER) || !pmc::clear(Owner::PROFILER) {
        return false;
    }
    // Stock leaves the other bits of the control value uninitialized.
    pmc::set_interval_control(INTERVAL_INTERRUPT);
    INTERVAL.store(interval, Ordering::Relaxed);
    pmc::set_interval(interval.wrapping_neg());
    pmc::start(Owner::PROFILER)
}

/// Undo the interrupt hook and release the counters and buffers.
fn unhook() {
    disable_profile_interrupt();
    set_profile_routine(0);
    HOOKED.store(false, Ordering::Release);
    pmc::release(Owner::PROFILER);
}

/// The sampling engine behind [`CONTROL`].
struct Sampler;

impl profiler::Engine for Sampler {
    /// Stock 0x91f90768. Stock also reads the memory statistics into a
    /// local it discards and seeds a random interval generator whose output
    /// it never uses; the latter is omitted.
    fn initialize(&mut self, flags: ProfilerFlags) -> Hresult {
        FLAGS.store(flags.0, Ordering::Relaxed);
        if !create_buffers(flags) {
            print(c"[LOP] CreateSharedBuffers Failed!!!\n", &[]);
            return NO_BUFFERS;
        }
        for word in &HEADER {
            word.store(0, Ordering::Relaxed);
        }
        let mut statistics = [0u32; 0x68 / 4];
        statistics[0] = 0x68;
        kernel::MmQueryStatistics(statistics.as_mut_ptr());
        header_word(header::VERSION).store(HEADER_VERSION, Ordering::Relaxed);
        header_word(header::PROCESSORS).store(flags.processors(), Ordering::Relaxed);
        for (index, chunk) in TITLE.chunks(4).enumerate() {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            header_word(header::TITLE + index * 4)
                .store(u32::from_be_bytes(word), Ordering::Relaxed);
        }
        for busy in &SAMPLES.busy {
            busy.store(0, Ordering::Relaxed);
        }
        if !pmc::acquire(Owner::PROFILER) {
            return NO_COUNTERS;
        }
        HOOKED.store(true, Ordering::Release);
        let result = set_profile_routine(profile_interrupt_entry as *const () as usize as u32);
        if result != Hresult::OK {
            return result;
        }
        let result = enable_profile_interrupt(flags.processors());
        if result == Hresult::OK {
            pmc::reset();
        }
        result
    }

    /// Stock 0x91f90220.
    fn abandon(&mut self) {
        unhook();
        free_buffers();
    }

    /// Stock 0x91f64448.
    fn create_directories(&mut self, path: &[u8]) {
        let request = CreateRequest {
            access: FileAccess(FileAccess::SYNCHRONIZE.0 | FileAccess::LIST_DIRECTORY.0),
            allocation_size: None,
            attributes: FileAttributes::NORMAL,
            share: ShareAccess::READ_WRITE,
            disposition: CreateDisposition::Create,
            options: CreateOptions(0x4021),
        };
        for (index, _) in path
            .iter()
            .enumerate()
            .skip(1)
            .filter(|&(_, &byte)| byte == b'\\')
        {
            if let Ok(handle) = filesystem::create_file(&path[..index], &request) {
                kernel::NtClose(handle.0);
            }
        }
    }

    /// Stock 0x91f90258.
    fn start(&mut self, path: Option<&[u8]>, interval: u32) -> Hresult {
        if SAMPLING_ACTIVE.load(Ordering::Acquire) {
            print(c"[LOP] Already started\n", &[]);
            return profiler::ALREADY_RUNNING;
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
            return profiler::PROLOGUE_FAILED;
        }
        set_header_time(header::START_TIME, kernel::system_time());
        let timebase = kernel::timebase();
        START_TIMEBASE[0].store((timebase >> 32) as u32, Ordering::Relaxed);
        START_TIMEBASE[1].store(timebase as u32, Ordering::Relaxed);
        if !start_sampling(interval) {
            stop_writer();
            return NO_COUNTERS;
        }
        SAMPLING_ACTIVE.store(true, Ordering::Release);
        SAMPLING
    }

    /// Stock 0x91f90310, 0x91f901d0.
    fn stop(&mut self) -> Hresult {
        SAMPLING_ACTIVE.store(false, Ordering::Release);
        let result = if pmc::stop(Owner::PROFILER) {
            pmc::clear(Owner::PROFILER);
            INTERVAL.store(0, Ordering::Relaxed);
            Hresult::OK
        } else {
            NOT_COUNTER_OWNER
        };
        unhook();
        stop_writer();
        free_buffers();
        result
    }

    /// Stock 0x91f90370.
    fn info(&mut self) -> CpuProfilerInfo {
        let elapsed = pmc::to_double(kernel::timebase().wrapping_sub(start_timebase()))
            / pmc::to_double(kernel::performance_frequency());
        let last = last_processor();
        CpuProfilerInfo {
            elapsed_time: elapsed as i64 as u32,
            total_samples: processor_word(header::INTERRUPTS, last).load(Ordering::Relaxed),
            overhead_interrupts: processor_word(header::BUSY, last).load(Ordering::Relaxed),
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
pub(super) fn start(path: Option<&[u8]>, executable: &[u8], interval: u32, flags: u32) -> Hresult {
    if !CONTROL.running() {
        store_executable_path(executable);
    }
    CONTROL.start(&mut Sampler, path, interval, ProfilerFlags(flags))
}

pub(super) fn stop() -> Hresult {
    CONTROL.stop(&mut Sampler)
}

pub(super) fn info() -> Result<CpuProfilerInfo, Hresult> {
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
    request: u32,
) -> u32 {
    // SAFETY: the poster waits in `call_on_server` while the request lives.
    let request = unsafe { &mut *(request as usize as *mut Translation<'_>) };
    let drives = &server.state.filesystem.drives;
    request.path = drives.translate(console, request.name);
    request.executable_length = drives.object_path_to_drive_path(
        console,
        module_snapshot::executable_object_path(),
        &mut request.executable,
    );
    0
}

/// Export 149: start profiling into drive path `name`. The drive table is
/// read on the server thread; where that cannot wait, the name has no
/// object path.
extern "C" fn export_start(name: u32, interval: u32, flags: u32) -> u32 {
    let mut request = Translation {
        // At most the 0x140 characters `lopctrl` accepts.
        name: super::c_string(name, 0x140),
        path: None,
        executable: [0; module_snapshot::PATH_LIMIT + 2],
        executable_length: 0,
    };
    if dispatcher::call_on_server(translate_on_server, &raw mut request as usize as u32).is_none() {
        let object = module_snapshot::executable_object_path();
        let length = object.len().min(request.executable.len());
        request.executable[..length].copy_from_slice(&object[..length]);
        request.executable_length = length;
    }
    let path = request.path.as_ref().map(|path| path.as_bytes());
    start(
        path,
        &request.executable[..request.executable_length],
        interval,
        flags,
    )
    .0
}

/// Export 150.
extern "C" fn export_stop() -> u32 {
    stop().0
}

/// Export 151: elapsed seconds, total samples, and overhead interrupts;
/// the outputs are written only on success.
extern "C" fn export_info(elapsed: *mut u32, samples: *mut u32, overhead: *mut u32) -> u32 {
    match info() {
        Ok(info) => {
            // SAFETY: the caller passes three writable u32.
            unsafe {
                core::ptr::write_volatile(elapsed, info.elapsed_time);
                core::ptr::write_volatile(samples, info.total_samples);
                core::ptr::write_volatile(overhead, info.overhead_interrupts);
            }
            Hresult::OK.0
        }
        Err(result) => result.0,
    }
}

export!(149, export_start);
export!(150, export_stop);
export!(151, export_info);
