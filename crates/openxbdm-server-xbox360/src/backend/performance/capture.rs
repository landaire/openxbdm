//! Fast-cap and call-cap capture engine (stock dmcap, 0x91f27bb8 to
//! 0x91f2a03c): per-processor record buffers, the record hooks that
//! instrumented modules import (exports 65, 66, 70, 71), and the control
//! entries of `capctrl` and titles (exports 73, 74, 84, 90, 146, 162).
//! The control sequences are in `openxbdm_server::commands::performance::
//! capture`; this module supplies the buffers, hooks, and file writer.
//!
//! Hooks run on any thread at any IRQL with interrupts disabled around
//! each record, on the block of the current processor, as stock does.

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::Server;
use openxbdm_server::commands::filesystem::DriveTable;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::filesystem::ObjectPath;
use openxbdm_server::commands::performance::capture;
use openxbdm_server::commands::performance::capture::BufferRequest;
use openxbdm_server::commands::performance::capture::CHUNK_RESERVE_WORDS;
use openxbdm_server::commands::performance::capture::CaptureError;
use openxbdm_server::commands::performance::capture::CaptureFlags;
use openxbdm_server::commands::performance::capture::ControlRecord;
use openxbdm_server::commands::performance::capture::CounterSetup;
use openxbdm_server::commands::performance::capture::CounterSource;
use openxbdm_server::commands::performance::capture::DrivePaths;
use openxbdm_server::commands::performance::capture::Instrumentation;
use openxbdm_server::commands::performance::capture::MAX_PROCESSORS;
use openxbdm_server::commands::performance::capture::Paths;
use openxbdm_server::commands::performance::capture::RecordKind;
use openxbdm_server::commands::performance::capture::Started;
use openxbdm_server::reply;
use openxbdm_server::reply::CommandError;
use openxbdm_server::reply::Reply;
use xbox360_sys::export_raw;
use xbox360_sys::image::XexHeaderKey;
use xbox360_sys::processor;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::KeIpiGenericCall;
use xbox360_sys::xboxkrnl::LdrDataTableEntry;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::RtlAssert;
use xbox360_sys::xboxkrnl::RtlImageXexHeaderField;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::counters;
use super::module_snapshot;
use super::pix;
use super::pmc;
use super::pmc::Owner;
use crate::backend::Console;
use crate::backend::dispatcher;
use crate::exports::export;
use crate::kernel;
use crate::net::XamNetwork;

/// Memory controller counter block (selectors 0x11 to 0x13).
const MEMORY_COUNTER_CONTROL: usize = 0x7fd2_0100;
const MEMORY_COUNTER_EVENT: usize = 0x7fd2_0104;
const MEMORY_COUNTER_VALUE: usize = 0x7fd2_010c;
const MEMORY_COUNTER_EVENT_2: usize = 0x7fd2_0110;
const MEMORY_COUNTER_VALUE_2: usize = 0x7fd2_0118;
const MEMORY_COUNTER_STOP: u32 = 0x0200_0000;
const MEMORY_COUNTER_START: u32 = 0x0100_0000;
/// Block flag: the processor does not record.
const STOPPED: u32 = 0x8000_0000;
/// Longest capture longer than the 29-bit record timestamps cover.
const TIMEBASE_LIMIT: u64 = 0x2000_0000;
/// Capture file name buffer (stock 0x91fae820).
const NAME_CAPACITY: usize = 0x104;
/// Longest name export 73 reads from the title.
const TITLE_NAME_LIMIT: usize = 0x140;
const TITLE_CAPTURE_POLL_MS: u32 = 60;
const TITLE_CAPTURE_TIMEOUT_MS: u32 = 15_000;
/// Physical memory type and allocation bounds of the buffers.
const MEMORY_TYPE: xboxkrnl::MemoryRegion = xboxkrnl::MemoryRegion::Title;
const PAGE_READWRITE: u32 = 4;
const BUFFER_PROTECT: u32 = 0x404;
const PAGE_SIZE: u32 = 0x1000;
/// Access of the capture file (stock 0x91f2eb68 callers).
const FILE_ACCESS: AccessMask = AccessMask::SYNCHRONIZE.union(AccessMask::GENERIC_WRITE);
/// Thread object: thread id.
const THREAD_ID: u32 = 0x14c;
const ASSERT_FILE: &[u8] =
    b"e:\\xenon\\xdksep13\\core\\private\\xdk\\tools\\debug\\xbdm\\core\\dmcap.c\0";
const ASSERT_PAGE_ALIGNED: &[u8] = b"((ULONG_PTR)bufstart % PAGE_SIZE) == 0\0";
const ASSERT_PAGE_ALIGNED_LINE: u32 = 0x7ec;

/// Recording state of one processor (stock 0x20-byte blocks at
/// 0x91fae804).
struct Block {
    /// Address of the last word written.
    cursor: AtomicU32,
    /// A record starts only while the cursor is below this address.
    limit: AtomicU32,
    /// End of the records once stopped; 0 while recording.
    end: AtomicU32,
    /// Chunk start and end address arrays in the chunk list.
    chunk_starts: AtomicU32,
    chunk_ends: AtomicU32,
    chunk_count: AtomicU32,
    /// Capture flags at start, with [`STOPPED`].
    flags: AtomicU32,
    enabled: AtomicBool,
}

impl Block {
    const fn new() -> Self {
        Self {
            cursor: AtomicU32::new(0),
            limit: AtomicU32::new(0),
            end: AtomicU32::new(0),
            chunk_starts: AtomicU32::new(0),
            chunk_ends: AtomicU32::new(0),
            chunk_count: AtomicU32::new(0),
            flags: AtomicU32::new(STOPPED),
            enabled: AtomicBool::new(false),
        }
    }

    /// Disable and stop (stock 0x91f28048).
    fn reset(&self) {
        self.enabled.store(false, Ordering::Relaxed);
        self.end.store(0, Ordering::Relaxed);
        self.chunk_count.store(0, Ordering::Relaxed);
        self.flags.store(STOPPED, Ordering::Relaxed);
        self.limit.store(0, Ordering::Relaxed);
    }

    fn chunk(&self, array: &AtomicU32, index: u32) -> u32 {
        read(array.load(Ordering::Relaxed) + index * 4)
    }
}

static BLOCKS: [Block; MAX_PROCESSORS] = [const { Block::new() }; MAX_PROCESSORS];
/// Stock 0x91f96078.
static FLAGS: AtomicU32 = AtomicU32::new(CaptureFlags::IDLE.0);
/// Chunk size in bytes and words (0x91f9607c, 0x91f96080).
static CHUNK_BYTES: AtomicU32 = AtomicU32::new(0x4_0000);
static CHUNK_WORDS: AtomicU32 = AtomicU32::new(0x1_0000);
/// The performance counters were released or programmed (0x91f96084).
static COUNTERS_READY: AtomicBool = AtomicBool::new(true);
/// Counter number per processor of the processor counter setup
/// (0x91fae488).
static COUNTER_NUMBERS: [AtomicU8; MAX_PROCESSORS] = [const { AtomicU8::new(0) }; MAX_PROCESSORS];
/// Time base at start (0x91fae490).
static START_TIMEBASE: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
/// Lowest recording processor (0x91fae498).
static FIRST_PROCESSOR: AtomicU32 = AtomicU32::new(0);
/// Start/stop interlock (0x91fae49c).
static LOCK: AtomicU32 = AtomicU32::new(0);
/// Record buffer: base, next free chunk, end, size (0x91fae4a0..0x91fae4ac).
static BUFFER: AtomicU32 = AtomicU32::new(0);
static NEXT_CHUNK: AtomicU32 = AtomicU32::new(0);
static BUFFER_END: AtomicU32 = AtomicU32::new(0);
static BUFFER_SIZE: AtomicU32 = AtomicU32::new(0);
/// Chunk start and end arrays of every processor (0x91fae4b0).
static CHUNK_LIST: AtomicU32 = AtomicU32::new(0);
static CHUNKS_PER_PROCESSOR: AtomicU32 = AtomicU32::new(0);
/// A title terminated since the last start (0x91fae7e8).
static TITLE_TERMINATED: AtomicBool = AtomicBool::new(false);
/// Thread switch routine replaced while recording (0x91fae7ec).
static PREVIOUS_SWAP_ROUTINE: AtomicU32 = AtomicU32::new(0);
/// System time of the last start (0x91fae7f8).
static START_TIME: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
/// Flags before the last stop (0x91fae800).
static PREVIOUS_FLAGS: AtomicU32 = AtomicU32::new(0);

/// Capture file name (0x91fae820); written and read under [`LOCK`].
struct FileName(UnsafeCell<[u8; NAME_CAPACITY]>);

// SAFETY: accessed only while `LOCK` is held.
unsafe impl Sync for FileName {}

static FILE_NAME: FileName = FileName(UnsafeCell::new([0; NAME_CAPACITY]));

fn read(address: u32) -> u32 {
    // SAFETY: callers pass addresses inside the record buffers, the chunk
    // list, or memory a title published.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn write(address: u32, value: u32) {
    // SAFETY: as `read`.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

fn current_thread_id() -> u32 {
    read(processor::current_thread() + THREAD_ID)
}

fn timebase_low() -> u32 {
    let value: u32;
    // SAFETY: reads the time base; no memory access.
    unsafe {
        core::arch::asm!("mftb {0}", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value
}

/// Clear the external interrupt enable bit and return the previous
/// machine state (stock 0x91f27b98).
fn disable_interrupts() -> u32 {
    let state: u32;
    // SAFETY: mtmsrd r13, 1 copies the interrupt enable bit of the PCR
    // address, which is clear.
    unsafe { core::arch::asm!("mfmsr {0}", ".long 0x7da10164", out(reg) state, options(nostack)) };
    state
}

/// Restore the interrupt enable bit (stock 0x91f27ba8).
fn restore_interrupts(state: u32) {
    // SAFETY: mtmsrd r11, 1 restores only the interrupt enable and
    // recoverable bits saved by `disable_interrupts`.
    unsafe { core::arch::asm!(".long 0x7d610164", in("r11") state, options(nostack)) };
}

fn processor_count() -> usize {
    (kernel::debug_monitor_data()
        .processor_count
        .load(Ordering::Relaxed) as usize)
        .min(MAX_PROCESSORS)
}

fn load_pair(pair: &[AtomicU32; 2]) -> u64 {
    u64::from(pair[0].load(Ordering::Relaxed)) << 32 | u64::from(pair[1].load(Ordering::Relaxed))
}

fn store_pair(pair: &[AtomicU32; 2], value: u64) {
    pair[0].store((value >> 32) as u32, Ordering::Relaxed);
    pair[1].store(value as u32, Ordering::Relaxed);
}

/// Address of the kernel's thread switch routine variable, if any.
fn swap_routine_slot() -> Option<u32> {
    match kernel::debug_monitor_data()
        .context_swap_notification
        .load(Ordering::Relaxed)
    {
        0 => None,
        slot => Some(slot),
    }
}

use core::time::Duration;

use xbox360::time::FileTime;
use xbox360::time::TickCount;
use xbox360::time::Timebase;
use xbox360::time::sleep;

use crate::exports::bridged;

/// Like `bridged!`, passing the caller's return address as the argument.
macro_rules! bridged_with_return_address {
    ($entry:ident, $target:path) => {
        #[unsafe(naked)]
        extern "C" fn $entry() {
            core::arch::naked_asm!(
                "mflr 3",
                "lis 12, {target}@ha",
                "addi 12, 12, {target}@l",
                "b {bridge}",
                target = sym $target,
                bridge = sym crate::exports::export_bridge,
            )
        }
    };
}

/// A chunk of the record buffer, or 0 when it is exhausted (stock
/// 0x91f27e20). A chunk is granted only while four chunks fit; with
/// discarded PIX output the buffer starts over at its base.
fn allocate_chunk() -> u32 {
    let size = CHUNK_BYTES.load(Ordering::Relaxed);
    let chunk = NEXT_CHUNK.fetch_add(size, Ordering::Relaxed);
    let reach = chunk.wrapping_add(size.wrapping_mul(4));
    let base = BUFFER.load(Ordering::Relaxed);
    if reach > base && reach <= BUFFER_END.load(Ordering::Relaxed) {
        return chunk;
    }
    if pix::discard_output() {
        NEXT_CHUNK.store(base, Ordering::Relaxed);
        return base;
    }
    0
}

/// Close the full chunk at `cursor` and continue in a new one; the new
/// cursor, or 0 when the processor stops recording (stock 0x91f28bd8).
fn next_chunk(cursor: u32, block: &Block) -> u32 {
    if block.flags.load(Ordering::Relaxed) & STOPPED != 0 {
        return 0;
    }
    let count = block.chunk_count.load(Ordering::Relaxed);
    write(
        block
            .chunk_ends
            .load(Ordering::Relaxed)
            .wrapping_add(count.wrapping_sub(1).wrapping_mul(4)),
        cursor + 4,
    );
    let chunk = allocate_chunk();
    if chunk == 0 {
        block.cursor.store(cursor, Ordering::Relaxed);
        block.limit.store(0, Ordering::Relaxed);
        block.flags.fetch_or(STOPPED, Ordering::Relaxed);
        return 0;
    }
    if pix::discard_output() {
        block.chunk_count.store(0, Ordering::Relaxed);
    }
    let count = block.chunk_count.load(Ordering::Relaxed);
    write(
        block.chunk_starts.load(Ordering::Relaxed) + count * 4,
        chunk,
    );
    block.chunk_count.store(count + 1, Ordering::Relaxed);
    let words = CHUNK_WORDS.load(Ordering::Relaxed);
    block.limit.store(
        chunk.wrapping_add(words.wrapping_sub(CHUNK_RESERVE_WORDS) * 4),
        Ordering::Relaxed,
    );
    chunk - 4
}

/// Counter value appended to records (stock 0x91f28cb8).
fn read_counter(flags: CaptureFlags, processor: usize) -> u32 {
    match flags.counter_source() {
        CounterSource::Processor(_) => pmc::counter(u32::from(
            COUNTER_NUMBERS[processor].load(Ordering::Relaxed),
        )),
        source => {
            let second = match source {
                CounterSource::Memory(capture::MemoryCounter::Combined) => {
                    read_le(MEMORY_COUNTER_VALUE_2)
                }
                _ => 0,
            };
            read_le(MEMORY_COUNTER_VALUE).wrapping_add(second)
        }
    }
}

fn read_le(register: usize) -> u32 {
    // SAFETY: memory controller counter register.
    u32::from_le(unsafe { core::ptr::read_volatile(register as *const u32) })
}

fn write_register(register: usize, value: u32) {
    // SAFETY: memory controller counter register; eieio orders the
    // device accesses.
    unsafe {
        core::ptr::write_volatile(register as *mut u32, value);
        core::arch::asm!("eieio", options(nostack, preserves_flags));
    }
}

/// Write one record into `processor`'s block. `checked` grows into a new
/// chunk at the limit (stock 0x91f28fa0 and the hooks); unchecked writes
/// rely on the chunk reserve (0x91f29048).
fn append(processor: usize, kind: RecordKind, first: u32, second: Option<u32>, checked: bool) {
    let Some(block) = BLOCKS.get(processor) else {
        return;
    };
    let state = disable_interrupts();
    let mut cursor = block.cursor.load(Ordering::Relaxed);
    let flags = CaptureFlags(block.flags.load(Ordering::Relaxed));
    if checked && cursor >= block.limit.load(Ordering::Relaxed) {
        cursor = next_chunk(cursor, block);
    }
    if cursor != 0 {
        cursor += 4;
        write(cursor, capture::record_header(kind, timebase_low()));
        cursor += 4;
        write(cursor, first);
        if let Some(second) = second {
            cursor += 4;
            write(cursor, second);
        }
        if flags.counters() {
            cursor += 4;
            write(cursor, read_counter(flags, processor));
        }
        block.cursor.store(cursor, Ordering::Relaxed);
    }
    restore_interrupts(state);
}

/// Record of an enabled processor's control event.
fn append_control(processor: usize, record: ControlRecord, value: u32, checked: bool) {
    if BLOCKS
        .get(processor)
        .is_some_and(|block| block.enabled.load(Ordering::Relaxed))
    {
        append(
            processor,
            RecordKind::Control,
            record as u32,
            Some(value),
            checked,
        );
    }
}

/// Export 65.
extern "C" fn record_pair(first: u32, second: u32) {
    append(
        usize::from(Kpcr::current().processor_number().get()),
        RecordKind::Pair,
        first,
        Some(second),
        true,
    );
}
export!(65, record_pair);

/// Export 66.
extern "C" fn record_single(value: u32) {
    append(
        usize::from(Kpcr::current().processor_number().get()),
        RecordKind::Single,
        value,
        None,
        true,
    );
}
export!(66, record_single);

extern "C" fn record_entry(return_address: u32) {
    append(
        usize::from(Kpcr::current().processor_number().get()),
        RecordKind::Entry,
        return_address,
        None,
        true,
    );
}
bridged_with_return_address!(entry_hook, record_entry);
export_raw!(70, entry_hook);

extern "C" fn record_exit(return_address: u32) {
    append(
        usize::from(Kpcr::current().processor_number().get()),
        RecordKind::Exit,
        return_address,
        None,
        true,
    );
}
bridged_with_return_address!(exit_hook, record_exit);
export_raw!(71, exit_hook);

/// Thread switch routine installed while recording (stock 0x91f290d0):
/// records the incoming thread, then runs the replaced routine.
extern "C" fn thread_switched(previous: u32, next: u32) {
    append_control(
        usize::from(Kpcr::current().processor_number().get()),
        ControlRecord::ThreadSwitch,
        read(next + THREAD_ID),
        true,
    );
    match PREVIOUS_SWAP_ROUTINE.load(Ordering::Relaxed) {
        0 => {}
        routine => {
            // SAFETY: the kernel's previous thread switch routine takes two
            // arguments.
            unsafe { crate::kernel::call_export(routine, previous, next, 0, 0) };
        }
    }
}
bridged!(thread_switch_entry, thread_switched);

/// Program the counters of `flags` on this processor (stock 0x91f27ce8).
fn program_counters(flags: CaptureFlags) {
    match flags.counter_source() {
        CounterSource::Processor(setup) => program_processor_counters(setup),
        CounterSource::Memory(counter) => {
            let (event, second) = counter.events();
            write_register(MEMORY_COUNTER_CONTROL, MEMORY_COUNTER_STOP);
            write_register(MEMORY_COUNTER_EVENT, event.to_le());
            write_register(MEMORY_COUNTER_EVENT_2, second.to_le());
            write_register(MEMORY_COUNTER_CONTROL, 0);
            write_register(MEMORY_COUNTER_CONTROL, MEMORY_COUNTER_START);
        }
        // Stock prints the message and traps on every processor; the
        // capture records without programming instead.
        CounterSource::Unsupported(selector) => {
            pmc::print(c"Invalid counter ID %u\n", &[u64::from(selector)]);
        }
    }
}

/// Processor counter setup (stock 0x91f27bb8): every processor selects
/// the events; the lowest recording processor also takes the counter
/// numbers, configures, clears, and starts the counters.
fn program_processor_counters(setup: CounterSetup) {
    pmc::set_print_flags(u32::MAX);
    let counters = setup.setup();
    pmc::select_events(Owner::CAPTURE, &counters);
    let flags = FLAGS.load(Ordering::Relaxed);
    let first = (0..MAX_PROCESSORS)
        .find(|&processor| flags & 1 << processor != 0)
        .unwrap_or(MAX_PROCESSORS);
    if first != usize::from(Kpcr::current().processor_number().get()) {
        return;
    }
    for (number, &value) in COUNTER_NUMBERS.iter().zip(&setup.counter_numbers()) {
        number.store(value, Ordering::Relaxed);
    }
    let ready = pmc::configure(Owner::CAPTURE, &counters)
        && pmc::stop(Owner::CAPTURE)
        && pmc::clear(Owner::CAPTURE)
        && pmc::start(Owner::CAPTURE);
    COUNTERS_READY.store(ready, Ordering::Relaxed);
}

/// Arguments of [`start_on_processor`]: first chunk per processor and the
/// chunk size in words.
#[repr(C)]
struct StartArguments {
    chunks: [u32; MAX_PROCESSORS],
    words: u32,
}

/// Start recording on this processor (stock 0x91f27eb8, IPI routine).
extern "C" fn start_on_processor(arguments: u32) -> u32 {
    // SAFETY: the initiator's arguments outlive the IPI.
    let arguments = unsafe { &*(arguments as usize as *const StartArguments) };
    let processor = usize::from(Kpcr::current().processor_number().get());
    let flags = CaptureFlags(FLAGS.load(Ordering::Relaxed));
    let state = disable_interrupts();
    if let Some(block) = BLOCKS
        .get(processor)
        .filter(|block| block.enabled.load(Ordering::Relaxed))
    {
        let chunk = arguments.chunks[processor];
        write(
            chunk,
            capture::record_header(RecordKind::Control, timebase_low()),
        );
        write(chunk + 4, ControlRecord::Start as u32);
        write(chunk + 8, current_thread_id());
        let mut last = chunk + 8;
        if flags.counters() {
            program_counters(flags);
            last += 4;
            write(last, read_counter(flags, processor));
        }
        write(block.chunk_starts.load(Ordering::Relaxed), chunk);
        block.cursor.store(last, Ordering::Relaxed);
        block.limit.store(
            chunk.wrapping_add(arguments.words.wrapping_sub(CHUNK_RESERVE_WORDS) * 4),
            Ordering::Relaxed,
        );
        block.chunk_count.store(1, Ordering::Relaxed);
        block.flags.store(flags.0, Ordering::Relaxed);
    }
    restore_interrupts(state);
    0
}
bridged!(start_on_processor_entry, start_on_processor);

/// Stop recording on this processor (stock 0x91f29160, IPI routine).
extern "C" fn stop_on_processor(_context: u32) -> u32 {
    let processor = usize::from(Kpcr::current().processor_number().get());
    let state = disable_interrupts();
    if let Some(block) = BLOCKS
        .get(processor)
        .filter(|block| block.enabled.load(Ordering::Relaxed))
    {
        append_control(processor, ControlRecord::Stop, current_thread_id(), false);
        let end = block.cursor.load(Ordering::Relaxed) + 4;
        block.end.store(end, Ordering::Relaxed);
        let count = block.chunk_count.load(Ordering::Relaxed);
        write(
            block
                .chunk_ends
                .load(Ordering::Relaxed)
                .wrapping_add(count.wrapping_sub(1).wrapping_mul(4)),
            end,
        );
        block.flags.store(STOPPED, Ordering::Relaxed);
        block.limit.store(0, Ordering::Relaxed);
    }
    restore_interrupts(state);
    0
}
bridged!(stop_on_processor_entry, stop_on_processor);

/// Disable this processor's block (stock 0x91f28048, IPI routine).
extern "C" fn reset_on_processor(_context: u32) -> u32 {
    let state = disable_interrupts();
    if let Some(block) = BLOCKS
        .get(usize::from(Kpcr::current().processor_number().get()))
        .filter(|block| block.enabled.load(Ordering::Relaxed))
    {
        block.reset();
    }
    restore_interrupts(state);
    0
}
bridged!(reset_on_processor_entry, reset_on_processor);

fn on_every_processor(routine: unsafe extern "C" fn(), context: u32) {
    // SAFETY: `routine` is a bridged IPI entry of this image that reads only
    // static state; `context` is passed through.
    unsafe { KeIpiGenericCall(routine as *const () as usize as u32, context) };
}

/// Buffers exist and the lowest recording processor has not stopped.
fn recording() -> bool {
    BUFFER.load(Ordering::Relaxed) != 0
        && BLOCKS
            .get(FIRST_PROCESSOR.load(Ordering::Relaxed) as usize)
            .is_some_and(|block| block.end.load(Ordering::Relaxed) == 0)
}

fn allocate(size: u32, protect: u32) -> u32 {
    // SAFETY: physical allocation of the requested size; callers check the result.
    unsafe {
        xboxkrnl::MmAllocatePhysicalMemoryEx(
            MEMORY_TYPE,
            size,
            PageProtection::from_bits_retain(protect),
            0,
            u32::MAX,
            PAGE_SIZE,
        )
    }
}

fn free(address: u32) {
    // SAFETY: callers pass a buffer from `allocate`, or 0, that is no longer used.
    unsafe { xboxkrnl::MmFreePhysicalMemory(MEMORY_TYPE, address) };
}

/// Restore the thread switch routine replaced at start.
fn restore_swap_routine() {
    if let Some(slot) = swap_routine_slot() {
        write(slot, PREVIOUS_SWAP_ROUTINE.load(Ordering::Relaxed));
    }
}

/// Free the buffers and disable every processor (end of stock 0x91f28540).
fn release_buffers() {
    free(BUFFER.load(Ordering::Relaxed));
    free(CHUNK_LIST.load(Ordering::Relaxed));
    BUFFER.store(0, Ordering::Relaxed);
    CHUNK_LIST.store(0, Ordering::Relaxed);
    FIRST_PROCESSOR.store(0, Ordering::Relaxed);
    NEXT_CHUNK.store(0, Ordering::Relaxed);
    BUFFER_END.store(0, Ordering::Relaxed);
    BUFFER_SIZE.store(0, Ordering::Relaxed);
    CHUNKS_PER_PROCESSOR.store(0, Ordering::Relaxed);
    store_pair(&START_TIMEBASE, 0);
    for block in BLOCKS.iter().take(processor_count()) {
        if block.enabled.load(Ordering::Relaxed) {
            block.flags.store(STOPPED, Ordering::Relaxed);
            block.limit.store(0, Ordering::Relaxed);
            block.enabled.store(false, Ordering::Relaxed);
            block.end.store(0, Ordering::Relaxed);
            block.chunk_count.store(0, Ordering::Relaxed);
        }
    }
}

fn file_attributes(name: &AnsiString) -> ObjectAttributes {
    ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    }
}

/// Create (overwrite) the capture file `path`.
fn create_file(path: &[u8]) -> Result<FileHandle, KernelError> {
    let name = kernel::ansi_string(path);
    let attributes = file_attributes(&name);
    let mut handle = 0u32;
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `handle`, `attributes`, the name it refers to, and `io_status`
    // are live for the call.
    let status = unsafe {
        xboxkrnl::NtCreateFile(
            (&raw mut handle).cast(),
            FILE_ACCESS,
            &attributes,
            &mut io_status,
            core::ptr::null(),
            FileAttributes::NORMAL,
            ShareAccess::READ,
            CreateDisposition::OverwriteIf,
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
        )
    };
    status.result()?;
    Ok(FileHandle(handle))
}

fn delete_file(path: &[u8]) {
    let name = kernel::ansi_string(path);
    // SAFETY: the attributes and the name they refer to are live for the call.
    unsafe { xboxkrnl::NtDeleteFile(&file_attributes(&name)) };
}

fn write_file(handle: FileHandle, address: u32, length: u32) -> Result<(), KernelError> {
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `handle` is the open capture file; `io_status` and the
    // `length` bytes at `address` are live for the synchronous call.
    let status = unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(handle.0),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            address as usize as *const u8,
            length,
            core::ptr::null(),
        )
    };
    status.result()
}

/// A recorded chunk of one processor, or `None` after printing `message`
/// when its bounds are invalid.
fn chunk_bounds(block: &Block, index: u32, message: &core::ffi::CStr) -> Option<(u32, u32)> {
    let start = block.chunk(&block.chunk_starts, index);
    let end = block.chunk(&block.chunk_ends, index);
    if start == 0 || end == 0 || end <= start {
        kernel::debug_print(message);
        return None;
    }
    Some((start, end))
}

/// Byte count of every recording processor at the file data sizes of
/// `snapshot`; `false` on invalid chunk bounds.
fn store_data_sizes(snapshot: u32) -> bool {
    for (index, block) in BLOCKS.iter().take(processor_count()).enumerate() {
        let slot = snapshot + capture::FILE_DATA_SIZES as u32 + index as u32 * 4;
        if !block.enabled.load(Ordering::Relaxed) {
            write(slot, 0);
            continue;
        }
        for chunk in 0..block.chunk_count.load(Ordering::Relaxed) {
            let Some((start, end)) =
                chunk_bounds(block, chunk, c"DmCapWrite: Invalid bufstart and bufend during fileheader->DataSize computation!\n")
            else {
                return false;
            };
            write(slot, read(slot).wrapping_sub(start).wrapping_add(end));
        }
    }
    true
}

/// Write the snapshot and every recorded chunk to `handle`.
fn write_capture(handle: FileHandle, snapshot: u32) -> Result<(), KernelError> {
    write_file(handle, snapshot, capture::FILE_HEADER_SIZE)?;
    let mut total = 0u32;
    for block in BLOCKS
        .iter()
        .take(processor_count())
        .filter(|block| block.enabled.load(Ordering::Relaxed))
    {
        for chunk in 0..block.chunk_count.load(Ordering::Relaxed) {
            let Some((start, end)) =
                chunk_bounds(block, chunk, c"DmCapWrite: Invalid bufstart and bufend!\n")
            else {
                return Err(KernelError::Unsuccessful);
            };
            total = total.wrapping_add(end - start);
            if start & (PAGE_SIZE - 1) != 0 {
                // SAFETY: the assertion strings are static and NUL-terminated.
                unsafe {
                    RtlAssert(
                        ASSERT_PAGE_ALIGNED.as_ptr(),
                        ASSERT_FILE.as_ptr(),
                        ASSERT_PAGE_ALIGNED_LINE,
                        core::ptr::null(),
                    )
                };
            }
            write_file(handle, start, end - start)?;
        }
    }
    let size = u64::from(total.wrapping_add(capture::FILE_HEADER_SIZE)).to_be_bytes();
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `handle` is the open capture file; `io_status` and the 8-byte
    // `size` are live.
    let status = unsafe {
        xboxkrnl::NtSetInformationFile(
            Handle::from_raw(handle.0),
            &mut io_status,
            size.as_ptr(),
            8,
            FileInformationClass::EndOfFile,
        )
    };
    status.result()?;
    // SAFETY: as above.
    let status = unsafe {
        xboxkrnl::NtSetInformationFile(
            Handle::from_raw(handle.0),
            &mut io_status,
            size.as_ptr(),
            8,
            FileInformationClass::Allocation,
        )
    };
    status.result()
}

/// The capture engine over this module's state.
struct Engine;

impl capture::Engine for Engine {
    /// Stock 0x91f28ae0: the first loader list only, under the loader lock.
    fn instrumented(&mut self, kind: Instrumentation) -> bool {
        let data = kernel::debug_monitor_data();
        let lock = data.loaded_module_list_lock.load(Ordering::Relaxed) as usize as *mut _;
        // SAFETY: the loader lock lives in the kernel debug monitor data.
        let irql = unsafe { xboxkrnl::KfAcquireSpinLock(lock) };
        let head = data.loaded_module_list.load(Ordering::Relaxed);
        let mut entry = read(head);
        let mut found = false;
        while entry != head {
            // SAFETY: `entry` is a loader entry on the module list, whose
            // lock is held.
            let loader_entry = unsafe {
                &*core::ptr::with_exposed_provenance::<LdrDataTableEntry>(entry as usize)
            };
            let header = loader_entry.xex_header_base;
            // SAFETY: `header` is the XEX header of a loaded module.
            if header != 0
                && unsafe { RtlImageXexHeaderField(header, XexHeaderKey(kind.header_field())) } != 0
            {
                found = true;
                break;
            }
            entry = read(entry);
        }
        // SAFETY: acquired above at `irql`.
        unsafe { xboxkrnl::KfReleaseSpinLock(lock, irql) };
        found
    }

    fn set_kernel_call_cap(&mut self, enable: bool) -> Result<(), KernelError> {
        // SAFETY: the service takes no pointers.
        let status = unsafe {
            xboxkrnl::ExDebugMonitorService(
                DebugMonitorService::KernelCallCapture,
                u32::from(enable),
                0,
                0,
            )
        };
        status.result()
    }

    fn set_title_terminated(&mut self, terminated: bool) {
        TITLE_TERMINATED.store(terminated, Ordering::Relaxed);
    }

    /// The title runs the capture: post the request in its control word
    /// and poll for its answer. The pointers are read again at every use,
    /// as stock does; a pointer the title cleared fails the request where
    /// stock dereferences null.
    fn request_title_capture(&mut self, megabytes: u8) -> Result<Started, CaptureError> {
        let request = counters::title_capture_request();
        let (Some(control), Some(_)) = (request.control, request.result) else {
            return Err(CaptureError::TitleCaptureFailed);
        };
        write(control, read(control) | u32::from(megabytes));
        let Some(control) = counters::title_capture_request().control else {
            return Err(CaptureError::TitleCaptureFailed);
        };
        write(control, read(control) | 0x100);
        let start = TickCount::now().milliseconds();
        loop {
            sleep(Duration::from_millis(u64::from(TITLE_CAPTURE_POLL_MS)));
            if TickCount::now().milliseconds().wrapping_sub(start) > TITLE_CAPTURE_TIMEOUT_MS {
                return Err(CaptureError::TitleCaptureFailed);
            }
            let request = counters::title_capture_request();
            let Some(control) = request.control else {
                return Err(CaptureError::TitleCaptureFailed);
            };
            if read(control) == 0 {
                return counters::title_capture_request()
                    .result
                    .map_or(Err(CaptureError::TitleCaptureFailed), |result| {
                        capture::title_result(Hresult(read(result)))
                    });
            }
        }
    }

    /// Stock 0x91f29210.
    fn begin(
        &mut self,
        name: &[u8],
        buffer_size: u32,
        exclusive: bool,
    ) -> Result<Started, CaptureError> {
        if LOCK
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(CaptureError::Busy);
        }
        let flags = CaptureFlags(FLAGS.load(Ordering::Relaxed))
            .for_start(Kpcr::current().processor_number().get());
        FLAGS.store(flags.0, Ordering::Relaxed);
        let continued = recording();
        if continued && exclusive {
            LOCK.store(0, Ordering::Release);
            return Err(CaptureError::AlreadyRunning);
        }
        // SAFETY: `LOCK` is held.
        let file_name = unsafe { &mut *FILE_NAME.0.get() };
        let length = name.len().min(NAME_CAPACITY);
        file_name[..length].copy_from_slice(&name[..length]);
        file_name[length..].fill(0);
        file_name[NAME_CAPACITY - 1] = 0;

        let previous_size = BUFFER_SIZE.load(Ordering::Relaxed);
        let processors = processor_count();
        let recording_processors =
            (0..processors).filter(|&processor| flags.0 & 1 << processor != 0);
        let count = recording_processors.clone().count() as u32;
        if let Some(first) = recording_processors.clone().next() {
            FIRST_PROCESSOR.store(first as u32, Ordering::Relaxed);
        }
        let size = match capture::requested_buffer_size(buffer_size) {
            Some(size) => size,
            None if BUFFER.load(Ordering::Relaxed) != 0 => previous_size,
            None => match capture::probe_megabytes(&mut |megabytes| match allocate(
                megabytes << 20,
                BUFFER_PROTECT,
            ) {
                0 => false,
                block => {
                    free(block);
                    true
                }
            }) {
                0 => {
                    BUFFER_SIZE.store(previous_size, Ordering::Relaxed);
                    LOCK.store(0, Ordering::Release);
                    return Err(CaptureError::NoBufferMemory);
                }
                megabytes => capture::default_buffer_size(megabytes),
            },
        };
        BUFFER_SIZE.store(size, Ordering::Relaxed);

        if flags.counters() && !pmc::acquire(Owner::CAPTURE) {
            BUFFER_SIZE.store(previous_size, Ordering::Relaxed);
            LOCK.store(0, Ordering::Release);
            return Err(CaptureError::CountersUnavailable);
        }
        let mut list = CHUNK_LIST.load(Ordering::Relaxed);
        if BUFFER.load(Ordering::Relaxed) != 0 {
            on_every_processor(reset_on_processor_entry, 0);
            let state = disable_interrupts();
            restore_swap_routine();
            restore_interrupts(state);
            if previous_size == size {
                NEXT_CHUNK.store(BUFFER.load(Ordering::Relaxed), Ordering::Relaxed);
            } else {
                free(BUFFER.swap(0, Ordering::Relaxed));
                free(list);
                list = 0;
                CHUNK_LIST.store(0, Ordering::Relaxed);
                NEXT_CHUNK.store(0, Ordering::Relaxed);
            }
        }
        let chunk = capture::chunk_size(size, count);
        CHUNK_BYTES.store(chunk, Ordering::Relaxed);
        let words = chunk >> 2;
        CHUNK_WORDS.store(words, Ordering::Relaxed);
        // Stock traps on a zero chunk size, which no buffer size yields.
        let chunks = size.checked_div(chunk).unwrap_or(0);
        CHUNKS_PER_PROCESSOR.store(chunks, Ordering::Relaxed);
        let mut allocated = true;
        if BUFFER.load(Ordering::Relaxed) == 0 {
            let buffer = allocate(size, BUFFER_PROTECT);
            BUFFER.store(buffer, Ordering::Relaxed);
            NEXT_CHUNK.store(buffer, Ordering::Relaxed);
            BUFFER_END.store(buffer.wrapping_add(size & !3), Ordering::Relaxed);
            list = allocate(
                chunks.wrapping_mul(processors as u32).wrapping_mul(8),
                PAGE_READWRITE,
            );
            CHUNK_LIST.store(list, Ordering::Relaxed);
            allocated = buffer != 0;
        }
        if !allocated || list == 0 {
            BUFFER_SIZE.store(previous_size, Ordering::Relaxed);
            if CaptureFlags(FLAGS.load(Ordering::Relaxed)).counters() {
                capture::Engine::release_counters(self);
            }
            LOCK.store(0, Ordering::Release);
            return Err(CaptureError::NoBufferMemory);
        }

        let state = disable_interrupts();
        if TITLE_TERMINATED.load(Ordering::Relaxed) {
            // Stock keeps the interlock until the next title terminates.
            restore_interrupts(state);
            return Err(CaptureError::TitleTerminated);
        }
        let mut arguments = StartArguments {
            chunks: [0; MAX_PROCESSORS],
            words,
        };
        let mut cursor = list;
        for (processor, block) in BLOCKS.iter().enumerate().take(processors) {
            let enabled = flags.0 & 1 << processor != 0;
            block.enabled.store(enabled, Ordering::Relaxed);
            block.flags.fetch_or(STOPPED, Ordering::Relaxed);
            if enabled {
                block.chunk_starts.store(cursor, Ordering::Relaxed);
                let ends = cursor + chunks * 4;
                block.chunk_ends.store(ends, Ordering::Relaxed);
                let next = NEXT_CHUNK.load(Ordering::Relaxed);
                arguments.chunks[processor] = next;
                NEXT_CHUNK.store(next.wrapping_add(words * 4), Ordering::Relaxed);
                cursor = ends + chunks * 4;
            } else {
                block.chunk_starts.store(0, Ordering::Relaxed);
                block.chunk_ends.store(0, Ordering::Relaxed);
                block.limit.store(0, Ordering::Relaxed);
            }
        }
        restore_interrupts(state);
        store_pair(&START_TIMEBASE, Timebase::now().ticks());
        on_every_processor(
            start_on_processor_entry,
            &raw const arguments as usize as u32,
        );
        if !continued {
            if let Some(slot) = swap_routine_slot() {
                // A title terminate leaves the routine installed; saving it
                // as its own predecessor makes stock recurse on every
                // thread switch.
                let current = read(slot);
                if current != thread_switch_entry as *const () as usize as u32 {
                    PREVIOUS_SWAP_ROUTINE.store(current, Ordering::Relaxed);
                }
                write(slot, thread_switch_entry as *const () as usize as u32);
            }
        }
        LOCK.store(0, Ordering::Release);
        if continued {
            Ok(Started::Continued)
        } else {
            Ok(Started::Recording)
        }
    }

    /// Stock 0x91f29830.
    fn end(&mut self) -> Result<(), CaptureError> {
        if LOCK
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(CaptureError::Busy);
        }
        if !recording() {
            LOCK.store(0, Ordering::Release);
            return Err(CaptureError::NoCapture);
        }
        if Timebase::now()
            .ticks()
            .wrapping_sub(load_pair(&START_TIMEBASE))
            > TIMEBASE_LIMIT
        {
            LOCK.store(0, Ordering::Release);
            return Err(CaptureError::TooLong);
        }
        let state = disable_interrupts();
        if let Some(slot) = swap_routine_slot() {
            write(slot, PREVIOUS_SWAP_ROUTINE.swap(0, Ordering::Relaxed));
        }
        let full = BLOCKS.iter().take(processor_count()).any(|block| {
            block.enabled.load(Ordering::Relaxed)
                && block.flags.load(Ordering::Relaxed) & STOPPED != 0
        });
        on_every_processor(stop_on_processor_entry, 0);
        restore_interrupts(state);
        LOCK.store(0, Ordering::Release);
        if full {
            Err(CaptureError::BufferFull)
        } else {
            Ok(())
        }
    }

    fn flags(&mut self) -> CaptureFlags {
        CaptureFlags(FLAGS.load(Ordering::Relaxed))
    }

    fn retire_flags(&mut self, previous: CaptureFlags) {
        FLAGS.store(CaptureFlags::IDLE.0, Ordering::Relaxed);
        PREVIOUS_FLAGS.store(previous.0, Ordering::Relaxed);
    }

    /// Stock 0x91f27db8.
    fn finish_counters(&mut self, flags: CaptureFlags) -> Result<(), CaptureError> {
        match flags.counter_source() {
            CounterSource::Processor(_) => {
                if pmc::stop(Owner::CAPTURE) {
                    Ok(())
                } else {
                    Err(CaptureError::CountersLost)
                }
            }
            _ => {
                write_register(MEMORY_COUNTER_CONTROL, MEMORY_COUNTER_STOP);
                Ok(())
            }
        }
    }

    fn release_counters(&mut self) {
        pmc::release(Owner::CAPTURE);
        COUNTERS_READY.store(true, Ordering::Relaxed);
    }

    fn counters_ready(&mut self) -> bool {
        COUNTERS_READY.load(Ordering::Relaxed)
    }

    fn try_lock(&mut self) -> bool {
        LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    fn unlock(&mut self) {
        LOCK.store(0, Ordering::Release);
    }

    /// Stock 0x91f28540; an open failure keeps the buffers.
    fn write(&mut self, paths: &mut dyn Paths) -> Result<(), KernelError> {
        // SAFETY: the caller holds `LOCK`.
        let file_name = unsafe { &*FILE_NAME.0.get() };
        let length = file_name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(NAME_CAPACITY);
        let path = paths
            .object_path(&file_name[..length])
            .ok_or(KernelError::NoSuchFile)?;
        let handle = create_file(path.as_bytes())?;
        let mut executable = [0u8; module_snapshot::PATH_LIMIT + 2];
        let executable_length = paths.executable_drive_path(&mut executable);
        let snapshot = module_snapshot::build(&executable[..executable_length], snapshot_fields());
        let written = match &snapshot {
            None => Err(KernelError::NoMemory),
            Some(snapshot) if !store_data_sizes(snapshot.address()) => {
                Err(KernelError::Unsuccessful)
            }
            Some(snapshot) => write_capture(handle, snapshot.address()),
        };
        // SAFETY: `handle` was opened by `create_file` above and is closed once.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
        if let Some(snapshot) = snapshot {
            module_snapshot::free(snapshot);
        }
        release_buffers();
        written
    }

    fn dos_error(&mut self, error: KernelError) -> Option<Win32Error> {
        xboxkrnl::RtlNtStatusToDosError(NtStatus::from(error)).error()
    }

    /// Stock 0x91f28a10 after the flags: the buffers are forgotten, not
    /// freed.
    fn discard(&mut self) {
        on_every_processor(reset_on_processor_entry, 0);
        LOCK.store(0, Ordering::Relaxed);
        BUFFER.store(0, Ordering::Relaxed);
        NEXT_CHUNK.store(0, Ordering::Relaxed);
        BUFFER_END.store(0, Ordering::Relaxed);
        BUFFER_SIZE.store(0, Ordering::Relaxed);
        CHUNK_LIST.store(0, Ordering::Relaxed);
        CHUNKS_PER_PROCESSOR.store(0, Ordering::Relaxed);
    }
}

/// [`Paths`] where the server's drive table cannot be read: no name
/// translates, and the executable keeps its object path, as for a path
/// outside every drive.
struct NoDriveTable;

impl Paths for NoDriveTable {
    fn object_path(&mut self, _name: &[u8]) -> Option<ObjectPath> {
        None
    }

    fn executable_drive_path(&mut self, output: &mut [u8]) -> usize {
        let object = module_snapshot::executable_object_path();
        let length = object.len().min(output.len().saturating_sub(1));
        output[..length].copy_from_slice(&object[..length]);
        length
    }
}

/// Capture values the module snapshot records.
pub(crate) fn snapshot_fields() -> module_snapshot::CaptureFields {
    module_snapshot::CaptureFields {
        start_time: load_pair(&START_TIME),
        previous_flags: PREVIOUS_FLAGS.load(Ordering::Relaxed),
    }
}

/// Capture buffers exist (stock 0x91f28bc0).
pub(crate) fn buffer_allocated() -> bool {
    BUFFER.load(Ordering::Relaxed) != 0
}

/// The result word of the capture exports.
fn export_result(result: Result<Reply, CaptureError>) -> u32 {
    reply::hresult(result.map_err(CommandError::from)).0
}

/// `capctrl start` after the server validated the file (stock 0x91f29d08).
pub(super) fn start(
    name: &[u8],
    path: &[u8],
    buffer: BufferRequest,
) -> Result<Started, CaptureError> {
    delete_file(path);
    store_pair(&START_TIME, FileTime::now().intervals());
    capture::start(&mut Engine, name, buffer, true)
}

/// Export 73 with `paths` (stock 0x91f29c00): a running capture continues
/// under the new name without touching the file.
fn start_for_title(
    paths: &mut dyn Paths,
    name: &[u8],
    buffer: BufferRequest,
) -> Result<Started, CaptureError> {
    if !recording() {
        let path = paths.object_path(name).ok_or(CaptureError::FileFailed)?;
        let handle = create_file(path.as_bytes()).map_err(|_| CaptureError::FileFailed)?;
        // SAFETY: `handle` was just opened by `create_file` and is closed once.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
        delete_file(path.as_bytes());
    }
    store_pair(&START_TIME, FileTime::now().intervals());
    capture::start(&mut Engine, name, buffer, false)
}

/// Export 73 request posted to the server thread.
struct TitleStart<'a> {
    name: &'a [u8],
    buffer: BufferRequest,
}

fn start_on_server(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    request: u32,
) -> u32 {
    // SAFETY: the poster waits in `call_on_server` while the request lives.
    let request = unsafe { &*(request as usize as *const TitleStart<'_>) };
    let mut paths = DrivePaths {
        drives: &server.state.filesystem.drives,
        backend: console,
    };
    export_result(start_for_title(&mut paths, request.name, request.buffer).map(Reply::from))
}

/// Export 73: start a capture into the drive path `name`. The drive table
/// is read on the server thread; the title waits for it.
extern "C" fn title_start(name: *const u8, buffer_size: u32) -> u32 {
    // At most `TITLE_NAME_LIMIT` bytes are read (stock copies the name
    // unbounded into a 0x141-byte stack buffer).
    let name = super::c_string(name as usize as u32, TITLE_NAME_LIMIT);
    let buffer = BufferRequest(buffer_size);
    let request = TitleStart { name, buffer };
    dispatcher::call_on_server(start_on_server, &raw const request as usize as u32).unwrap_or_else(
        || export_result(start_for_title(&mut NoDriveTable, name, buffer).map(Reply::from)),
    )
}
bridged!(title_start_entry, title_start);
export_raw!(73, title_start_entry);

/// `capctrl stop` on the server thread.
pub(super) fn stop(console: &mut Console, drives: &DriveTable) -> Result<(), CaptureError> {
    capture::stop(
        &mut Engine,
        &mut DrivePaths {
            drives,
            backend: console,
        },
    )
}

fn stop_on_server(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    _argument: u32,
) -> u32 {
    export_result(stop(console, &server.state.filesystem.drives).map(|()| Reply::Ok))
}

/// Export 74: stop and write the capture file; the drive table is read on
/// the server thread.
extern "C" fn title_stop() -> u32 {
    dispatcher::call_on_server(stop_on_server, 0).unwrap_or_else(|| {
        export_result(capture::stop(&mut Engine, &mut NoDriveTable).map(|()| Reply::Ok))
    })
}
bridged!(title_stop_entry, title_stop);
export_raw!(74, title_stop_entry);

pub(super) fn fast_cap_present() -> bool {
    capture::Engine::instrumented(&mut Engine, Instrumentation::FastCap)
}

pub(super) fn call_cap_present() -> bool {
    capture::Engine::instrumented(&mut Engine, Instrumentation::CallCap)
}

/// Export 84.
extern "C" fn fast_cap_result() -> u32 {
    export_result(capture::fast_cap_state(fast_cap_present()).map(Reply::Capture))
}
export!(84, fast_cap_result);

pub(super) fn set_flags(flags: CaptureFlags) {
    FLAGS.store(flags.0, Ordering::Relaxed);
}

/// Export 90.
extern "C" fn set_flags_export(value: u32) -> u32 {
    set_flags(CaptureFlags::from_request(value));
    Hresult::OK.0
}
export!(90, set_flags_export);

/// `capctrl profilingstatus` (stock 0x91f28940).
pub(super) fn status() -> Result<(), CaptureError> {
    if TITLE_TERMINATED.load(Ordering::Relaxed) {
        return Err(CaptureError::TitleTerminated);
    }
    if !recording() {
        return Err(CaptureError::NoCapture);
    }
    let full = BLOCKS.iter().take(processor_count()).any(|block| {
        block.enabled.load(Ordering::Relaxed)
            && block.end.load(Ordering::Relaxed) == 0
            && block.flags.load(Ordering::Relaxed) & STOPPED != 0
    });
    if full {
        Err(CaptureError::BufferFull)
    } else {
        Ok(())
    }
}

extern "C" fn status_export() -> u32 {
    export_result(status().map(|()| Reply::Ok))
}
export!(146, status_export);

/// `capctrl abort` (export 162).
pub(super) fn abort() -> Result<(), CaptureError> {
    capture::abort(&mut Engine)
}

extern "C" fn abort_export() -> u32 {
    export_result(abort().map(|()| Reply::Ok))
}
export!(162, abort_export);

/// Publish the title capture entries (stock 0x91f32628).
pub(super) fn initialize() {
    counters::set_capture_entries(
        title_start_entry as *const () as usize as u32,
        title_stop_entry as *const () as usize as u32,
    );
}

/// Stop a running capture (kernel call-cap, counters), restore the thread
/// switch routine, stop every processor, and free the buffers before the
/// image unloads; stock never unloads.
pub(super) fn shut_down() {
    if BUFFER.load(Ordering::Relaxed) != 0 {
        let _ = abort();
    }
    if let Some(slot) = swap_routine_slot()
        && read(slot) == thread_switch_entry as *const () as usize as u32
    {
        write(slot, PREVIOUS_SWAP_ROUTINE.swap(0, Ordering::Relaxed));
    }
    on_every_processor(reset_on_processor_entry, 0);
    if BUFFER.load(Ordering::Relaxed) != 0 {
        release_buffers();
    }
}

/// Capture part of the title terminate routine (stock 0x91f28a10).
pub(super) fn title_terminated() {
    capture::title_terminated(&mut Engine);
}
