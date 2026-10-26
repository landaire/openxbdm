//! Instruction trace engine (stock 0x91f65e50-0x91f67200, exports 133-137,
//! 177, 195): single-steps the thread that starts it and records every
//! instruction it executes into a trace file.
//!
//! The session memory holds five stream buffers after a 0x78-byte header
//! and the 64 KiB lookup cache of the encoder at the end. The trace
//! exception handler fills the current buffer and queues it when fewer
//! than eight words remain; a writer thread appends queued buffers to the
//! file in sequence order every 10 ms. Without a file name the buffers
//! stay in memory until export 137 writes them.

mod file;
mod handler;
mod writer;

use core::mem::size_of;
use core::num::NonZeroU32;
use core::ptr::null_mut;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::performance::xtrace;
use openxbdm_server::commands::performance::xtrace::AddressSpace;
use openxbdm_server::commands::performance::xtrace::Encoder;
use openxbdm_server::commands::performance::xtrace::Region;
use openxbdm_server::commands::performance::xtrace::Sink;
use xbox360::status::set_last_error;
use xbox360::time::Timebase;
use xbox360_sys::export_raw;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;
use xbox360_sys::processor::Msr;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::AllocationType;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::MemoryBasicInformation;
use xbox360_sys::xboxkrnl::MemoryRegion;
use xbox360_sys::xboxkrnl::MmQueryAddressProtect;
use xbox360_sys::xboxkrnl::MmQueryAllocationSize;
use xbox360_sys::xboxkrnl::NotificationRegistration;
use xbox360_sys::xboxkrnl::NtQueryVirtualMemory;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ShareAccess;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;

use self::file::create_request;
use self::file::create_trace_file;
use self::file::has_file_name;
use self::file::open;
use self::file::set_file_name;
use self::handler::SPOOFED;
use self::handler::hook;
use self::handler::resolve_spoofed_routines;
use self::handler::unhook;
use self::writer::WRITERS;
use self::writer::flush;
use self::writer::forget_writer;
use self::writer::track_writer;
use self::writer::writer;
use super::COMMIT_RESERVE_LARGE;
use super::load_pair;
use super::module_snapshot;
use super::store_pair;
use crate::exports::bridged;
use crate::exports::export;
use crate::kernel;

const BUFFER_COUNT: usize = 5;
const DEFAULT_SIZE_LIMIT: u32 = 0x40_0000;
const MINIMUM_SIZE_LIMIT: u32 = 0x10_0000;
/// A queued buffer leaves room for one record.
const RECORD_RESERVE: u32 = 8;
/// The last hardware thread.
const DEFAULT_WRITER_PROCESSOR: u32 = HARDWARE_THREAD_COUNT as u32 - 1;

/// Start of the session allocation, before the stream buffers. Stock
/// keeps its five 0x18-byte buffer descriptors here; this engine keeps
/// them in `BUFFERS`, and the block stays zero.
#[repr(C)]
struct SessionHeader {
    _descriptors: [[u32; 6]; BUFFER_COUNT],
}

impl SessionHeader {
    const ZERO: Self = Self {
        _descriptors: [[0; 6]; BUFFER_COUNT],
    };
}

const HEADER_SIZE: u32 = size_of::<SessionHeader>() as u32;

/// The encoder's lookup cache.
type Cache = [AtomicU32; xtrace::CACHE_WORDS];

const _: () = assert!(HEADER_SIZE == 0x78);

const _: () = assert!(module_snapshot::SIZE / 4 == xtrace::MODULE_WORDS);

/// One stream buffer (stock 0x18-byte descriptors).
struct Buffer {
    sequence: AtomicU32,
    /// Capacity and fill, in words.
    capacity: AtomicU32,
    used: AtomicU32,
    data: AtomicU32,
}

static BUFFERS: [Buffer; BUFFER_COUNT] = [const {
    Buffer {
        sequence: AtomicU32::new(0),
        capacity: AtomicU32::new(0),
        used: AtomicU32::new(0),
        data: AtomicU32::new(0),
    }
}; BUFFER_COUNT];
static CURRENT: AtomicPtr<Buffer> = AtomicPtr::new(null_mut());
static FREE: [AtomicPtr<Buffer>; BUFFER_COUNT] =
    [const { AtomicPtr::new(null_mut()) }; BUFFER_COUNT];
static FILLED: [AtomicPtr<Buffer>; BUFFER_COUNT] =
    [const { AtomicPtr::new(null_mut()) }; BUFFER_COUNT];
static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// Bytes of stream buffers requested (export 135); the session allocation
/// adds the cache.
static SIZE_LIMIT: AtomicU32 = AtomicU32::new(DEFAULT_SIZE_LIMIT);
/// [`MemoryRegion`] of the session allocation.
static MEMORY_OPTION: AtomicU32 = AtomicU32::new(MemoryRegion::TitleDebug as u32);
/// Hardware thread of the writer thread (export 195), below
/// `HARDWARE_THREAD_COUNT`.
static WRITER_PROCESSOR: AtomicU32 = AtomicU32::new(DEFAULT_WRITER_PROCESSOR);

/// Session memory: the first stream buffer's address (allocation + 0x78,
/// which stock also passes to the free); null while no session exists.
static BASE: AtomicU32 = AtomicU32::new(0);
/// The encoder's lookup cache at the end of the session allocation.
static CACHE: AtomicPtr<Cache> = AtomicPtr::new(null_mut());
/// Single-stepping is on for the traced thread.
static ARMED: AtomicBool = AtomicBool::new(false);
/// A recording, file, or allocation error happened.
static FAILED: AtomicBool = AtomicBool::new(false);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static WRITER_HANDLE: AtomicU32 = AtomicU32::new(0);
static WRITER_RUNNING: AtomicBool = AtomicBool::new(false);

static TERMINATE_REGISTERED: AtomicBool = AtomicBool::new(false);
static TITLE_TERMINATE: NotificationRegistration = NotificationRegistration::new();

/// State of the trace handlers, also used by the threads that start, stop,
/// and save the session. Stock shares it without synchronization: a stop
/// or save on another thread (control code 0x39, PIX, export 137), title
/// termination, and the handler of any other single-stepped thread race
/// the traced thread's handler, so every field is an atomic accessed with
/// relaxed loads and stores.
struct Session {
    encoder: Encoder,
    skip_instructions: AtomicU32,
    skip_returns: AtomicU32,
    /// Time base at arming, high word first.
    start_time: [AtomicU32; 2],
    /// Address whose record found no free buffer; 0 for none. A traced
    /// address is never 0: the handler reads the instruction there first.
    stop_address: AtomicU32,
}

static SESSION: Session = Session {
    encoder: Encoder::new(),
    skip_instructions: AtomicU32::new(0),
    skip_returns: AtomicU32::new(0),
    start_time: [const { AtomicU32::new(0) }; 2],
    stop_address: AtomicU32::new(0),
};

/// Encoded instruction count of the last progress line, as `i64` bits.
static PROGRESS_MARK: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];

/// Writes words at a cursor in session memory.
struct Cursor(u32);

impl Cursor {
    /// # Safety
    ///
    /// Every word at the cursor when `push` or `word` runs lies in
    /// writable, word-aligned memory that stays allocated while it is
    /// used, and that other threads access only as atomics or from outside
    /// Rust (the kernel's file writes).
    unsafe fn new(start: u32) -> Self {
        Self(start)
    }

    /// The word at the cursor.
    fn word(&self) -> &AtomicU32 {
        // SAFETY: guaranteed by the caller of `Cursor::new`.
        unsafe { kernel::object_at(self.0) }
    }
}

impl Sink for Cursor {
    fn push(&mut self, word: u32) {
        self.word().store(word, Ordering::Relaxed);
        self.0 += 4;
    }
}

/// Address space queries of the memory map record.
struct KernelSpace;

impl AddressSpace for KernelSpace {
    fn query(&mut self, address: u32) -> Option<Region> {
        let mut information = MemoryBasicInformation::default();
        // SAFETY: `information` is a live basic information block.
        let status =
            unsafe { NtQueryVirtualMemory(address, (&raw mut information).cast::<u32>(), 0) };
        if let Err(error) = status.result() {
            set_last_error(error);
            return None;
        }

        Some(Region {
            size: information.region_size,
            state: information.state.bits(),
            protect: information.protect.bits(),
        })
    }

    fn protect(&mut self, address: u32) -> u32 {
        MmQueryAddressProtect(address).bits()
    }

    fn allocation_size(&mut self, address: u32) -> u32 {
        // SAFETY: the kernel validates `address` against its pool and heap regions.
        unsafe { MmQueryAllocationSize(address) }
    }
}

/// The instruction word at `address`.
///
/// # Safety
///
/// `address` is a word of mapped code.
unsafe fn instruction_at(address: u32) -> u32 {
    // SAFETY: guaranteed by the caller.
    unsafe { (address as usize as *const u32).read() }
}

/// `OutputDebugString`: the debug print trap with the text and its length.
fn output_debug_string(text: &[u8]) {
    // SAFETY: the trap reads `text`; the kernel resumes after it.
    unsafe {
        core::arch::asm!("twi 31, 0, 0x14", in("r3") text.as_ptr(), in("r4") text.len(), options(nostack))
    };
}

/// Stock's assertion trap, handled by the debug routine.
fn break_trap() {
    // SAFETY: executes the breakpoint trap; the kernel resumes after it.
    unsafe { core::arch::asm!("twi 31, 0, 0x16", options(nostack)) };
}

/// Format `format` with up to four arguments, one per 8-byte va_list slot,
/// and print it with `OutputDebugString`. A message longer than the buffer
/// is cut, as stock's sprintf buffer would hold it.
#[inline(never)]
fn print(format: &core::ffi::CStr, arguments: &[u64]) {
    let mut slots = [0u64; 4];
    slots[..arguments.len()].copy_from_slice(arguments);

    let mut text = [0u8; 0x200];
    // SAFETY: `text` is a live buffer of the stated length; `format` is
    // NUL-terminated and `slots` holds every argument it consumes.
    let length = unsafe {
        xboxkrnl::_vsnprintf(
            text.as_mut_ptr(),
            text.len() as u32,
            format.as_ptr() as usize as u32,
            slots.as_ptr() as usize as u32,
        )
    };
    let length = usize::try_from(length).map_or(text.len(), |length| length.min(text.len()));

    output_debug_string(&text[..length]);
}

fn buffer_index(buffer: *mut Buffer) -> usize {
    // SAFETY: buffer slots hold null or an element of `BUFFERS`.
    unsafe { buffer.cast_const().offset_from(BUFFERS.as_ptr()) as usize }
}

/// Take the first free buffer as the current one.
fn take_free_buffer() -> *mut Buffer {
    for slot in &FREE {
        let buffer = slot.load(Ordering::Acquire);
        CURRENT.store(buffer, Ordering::Release);
        if !buffer.is_null() {
            slot.store(null_mut(), Ordering::Release);
            return buffer;
        }
    }

    null_mut()
}

/// Queue the current buffer for the writer (stock 0x91f660b0).
fn queue_current() {
    let buffer = CURRENT.load(Ordering::Acquire);
    // SAFETY: buffer slots hold null or an element of `BUFFERS`.
    let Some(reference) = (unsafe { buffer.as_ref() }) else {
        return;
    };

    reference.sequence.store(
        NEXT_SEQUENCE.fetch_add(1, Ordering::AcqRel),
        Ordering::Release,
    );
    FILLED[buffer_index(buffer)].store(buffer, Ordering::Release);
    CURRENT.store(null_mut(), Ordering::Release);
}

/// Empty the free and filled buffer slots.
fn clear_queues() {
    for slot in &FREE {
        slot.store(null_mut(), Ordering::Release);
    }

    for slot in &FILLED {
        slot.store(null_mut(), Ordering::Release);
    }
}

/// Allocate the session memory, shrinking the request while it fails.
/// Debug memory is tried first, then title memory.
fn allocate() -> bool {
    const CACHE_SIZE: u32 = size_of::<[u32; xtrace::CACHE_WORDS]>() as u32;
    const MAXIMUM_ALLOCATION: u32 = 0x8000_0000;

    loop {
        let mut limit = SIZE_LIMIT.load(Ordering::Relaxed);
        if limit.wrapping_add(CACHE_SIZE) > MAXIMUM_ALLOCATION {
            limit = MAXIMUM_ALLOCATION - CACHE_SIZE;
            SIZE_LIMIT.store(limit, Ordering::Relaxed);
        }

        MEMORY_OPTION.store(MemoryRegion::TitleDebug as u32, Ordering::Relaxed);
        let mut size = limit + CACHE_SIZE;
        // SAFETY: BASE and `size` are live u32 values.
        let mut status = unsafe {
            xboxkrnl::NtAllocateVirtualMemory(
                BASE.as_ptr(),
                &mut size,
                COMMIT_RESERVE_LARGE,
                PageProtection::READWRITE,
                MemoryRegion::TitleDebug,
            )
        };
        if !status.is_success() {
            BASE.store(0, Ordering::Relaxed);
            MEMORY_OPTION.store(MemoryRegion::Title as u32, Ordering::Relaxed);
            size = limit + CACHE_SIZE;
            // SAFETY: as above.
            status = unsafe {
                xboxkrnl::NtAllocateVirtualMemory(
                    BASE.as_ptr(),
                    &mut size,
                    COMMIT_RESERVE_LARGE,
                    PageProtection::READWRITE,
                    MemoryRegion::Title,
                )
            };

            if !status.is_success() {
                if limit <= MINIMUM_SIZE_LIMIT {
                    return BASE.load(Ordering::Relaxed) != 0;
                }

                SIZE_LIMIT.store((limit * 2 / 3).max(MINIMUM_SIZE_LIMIT), Ordering::Relaxed);
            }
        }

        if BASE.load(Ordering::Relaxed) != 0 {
            return true;
        }
    }
}

/// Prepare a session (stock 0x91f665e0); failures set `FAILED`.
fn initialize(name: Option<&[u8]>) {
    const WRITER_STACK: u32 = 0x8000;
    /// Instructions and returns skipped after arming: the way back out of
    /// the start function.
    const SKIP_INSTRUCTIONS: u32 = 0x28;
    const SKIP_RETURNS: u32 = 2;

    FAILED.store(false, Ordering::Release);
    STOP_REQUESTED.store(false, Ordering::Release);

    match name {
        Some(name) => {
            set_file_name(name);
            WRITER_RUNNING.store(true, Ordering::Release);
            let Some(handle) = create_trace_file(name) else {
                output_debug_string(b"Tracing: File open failed.\n");
                FAILED.store(true, Ordering::Release);
                return;
            };

            // SAFETY: `handle` was just opened and is closed once.
            unsafe { xboxkrnl::NtClose(Handle::from_raw(handle)) };

            // `set_writer_processor` keeps the number below
            // HARDWARE_THREAD_COUNT.
            let processor = WRITER_PROCESSOR.load(Ordering::Relaxed) as u8;
            // SAFETY: WRITER_HANDLE is a static u32; the writer takes no
            // context and reads only static state.
            let status = unsafe {
                xboxkrnl::ExCreateThread(
                    WRITER_HANDLE.as_ptr(),
                    WRITER_STACK,
                    core::ptr::null_mut(),
                    0,
                    writer as *const () as usize as u32,
                    0,
                    ThreadCreationFlags::processors(1 << processor),
                )
            };
            if !status.is_success() {
                output_debug_string(b"Tracing: Thread creation failed.\n");
                FAILED.store(true, Ordering::Release);
                return;
            }

            track_writer(WRITER_HANDLE.load(Ordering::Acquire));
        }
        None => {
            set_file_name(&[]);
            WRITER_HANDLE.store(0, Ordering::Release);
        }
    }

    SESSION.skip_returns.store(SKIP_RETURNS, Ordering::Relaxed);
    SESSION
        .skip_instructions
        .store(SKIP_INSTRUCTIONS, Ordering::Relaxed);

    if BASE.load(Ordering::Acquire) == 0 && !allocate() {
        output_debug_string(b"Tracing: Memory allocation failed.\n");
        FAILED.store(true, Ordering::Release);
        return;
    }

    let limit = SIZE_LIMIT.load(Ordering::Relaxed);
    let allocation = BASE.load(Ordering::Relaxed);
    let cache = core::ptr::with_exposed_provenance_mut::<Cache>((allocation + limit) as usize);
    CACHE.store(cache, Ordering::Relaxed);

    // Word stores where stock calls memset (deviation): the handler of
    // another single-stepped thread may use the cache meanwhile.
    // SAFETY: the allocation of `allocate` holds the header, the buffers,
    // and the cache after `limit` bytes. No other thread uses the header,
    // and the cache only atomically.
    unsafe {
        for word in &*cache {
            word.store(0, Ordering::Relaxed);
        }
        core::ptr::with_exposed_provenance_mut::<SessionHeader>(allocation as usize)
            .write(SessionHeader::ZERO);
    }

    let base = allocation + HEADER_SIZE;
    BASE.store(base, Ordering::Release);

    let size = ((limit - HEADER_SIZE) / BUFFER_COUNT as u32) & !3;
    for (index, ((buffer, free), filled)) in BUFFERS.iter().zip(&FREE).zip(&FILLED).enumerate() {
        buffer.sequence.store(0, Ordering::Relaxed);
        buffer.capacity.store(size / 4, Ordering::Relaxed);
        buffer.used.store(0, Ordering::Relaxed);
        buffer
            .data
            .store(base + index as u32 * size, Ordering::Relaxed);
        free.store(core::ptr::from_ref(buffer).cast_mut(), Ordering::Release);
        filled.store(null_mut(), Ordering::Release);
    }

    CURRENT.store(null_mut(), Ordering::Release);
    NEXT_SEQUENCE.store(0, Ordering::Relaxed);
    ARMED.store(false, Ordering::Release);
    SESSION.encoder.reset_depth();
}

/// Write the file header at `start` (stock 0x91f673e8); returns the end.
///
/// # Safety
///
/// `start` is the free part of a stream buffer of the session, which
/// nothing else uses.
unsafe fn write_header(start: u32) -> u32 {
    SESSION.encoder.begin();

    // SAFETY: guaranteed by the caller. The header fits in a stream buffer,
    // as in stock, which reports an overrun only after writing it.
    let mut cursor = unsafe { Cursor::new(start) };
    cursor.push(xtrace::TRACE_MAGIC);
    cursor.push(xtrace::TRACE_VERSION);

    let mut executable = [0u8; module_snapshot::PATH_LIMIT + 2];
    let length = module_snapshot::executable_drive_path(&mut executable);
    if let Some(snapshot) =
        module_snapshot::build(&executable[..length], super::capture::snapshot_fields())
    {
        cursor.push(xtrace::MODULE_MAGIC);
        cursor.push(xtrace::MODULE_WORDS);
        for &word in snapshot.words() {
            cursor.push(word);
        }
        module_snapshot::free(snapshot);
    }

    cursor.push(xtrace::MAP_MAGIC);
    // SAFETY: the word at the cursor, which the push below writes.
    let count = unsafe { Cursor::new(cursor.0) };
    cursor.push(0);
    xtrace::write_memory_map(&mut KernelSpace, &mut cursor);

    count
        .word()
        .store((cursor.0 - count.0 - 4) / 4, Ordering::Relaxed);

    cursor.0
}

/// Everything of a start before single-stepping is armed (stock
/// 0x91f66f50 up to 0x91f66138); false when no session started.
#[inline(never)]
fn prepare(name: Option<&[u8]>) -> bool {
    if BASE.load(Ordering::Acquire) != 0 {
        return false;
    }

    resolve_spoofed_routines();
    initialize(name);
    if FAILED.load(Ordering::Acquire) {
        return false;
    }

    let buffer = take_free_buffer();
    // SAFETY: buffer slots hold null or an element of `BUFFERS`; the
    // session just filled the free list.
    if let Some(buffer) = unsafe { buffer.as_ref() } {
        let start = buffer.data.load(Ordering::Relaxed) + 4 * buffer.used.load(Ordering::Relaxed);
        let used = buffer.used.load(Ordering::Relaxed);
        // SAFETY: `start` is the free part of the first stream buffer of the
        // session `initialize` just allocated.
        let end = unsafe { write_header(start) };
        let used = used + (end - start) / 4;
        buffer.used.store(used, Ordering::Release);
        if used + RECORD_RESERVE >= buffer.capacity.load(Ordering::Relaxed) {
            output_debug_string(
                b"Buffer overrun. Increase buffer size with XTraceSetBufferSize.\n",
            );
            break_trap();
        }
    }

    queue_current();
    hook();

    true
}

/// Turn on single-stepping for the calling thread (stock 0x91f66138).
/// Inlined into the start entry so that the skip counts cover exactly the
/// way back to its caller.
#[inline(always)]
fn arm() {
    if BASE.load(Ordering::Acquire) == 0 {
        return;
    }

    store_pair(&SESSION.start_time, Timebase::now().ticks());
    SESSION.encoder.arm();
    store_pair(&PROGRESS_MARK, 0);
    SESSION.stop_address.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Release);

    // SAFETY: sets MSR[SE] for the calling thread; the hooks are in place.
    unsafe {
        core::arch::asm!(
            "mfmsr {msr}",
            "ori {msr}, {msr}, {single_step}",
            "mtmsr {msr}",
            "nop",
            msr = out(reg) _,
            single_step = const Msr::SINGLE_STEP.bits(),
        )
    };
}

/// Stock 0x91f66f50. Inlined into each export so that the skip counts
/// cover exactly the way back to the caller of the export.
#[inline(always)]
fn start_body(name: u32) -> u32 {
    // SAFETY: exports 133 and 134 take null or the address of the caller's
    // NUL-terminated file name, which the caller keeps unchanged during the
    // call.
    let name = unsafe { kernel::c_string(name) };
    if !prepare(name) {
        return 0;
    }

    let result = u32::from(!FAILED.load(Ordering::Acquire));
    arm();

    result
}

/// Export 133: start recording the calling thread into the file `name`
/// (null keeps the stream in memory for export 137); 1 when recording.
extern "C" fn start_recording(name: u32) -> u32 {
    start_body(name)
}

bridged!(start_entry, start_recording);
export_raw!(133, start_entry);

/// Start through the export 133 entry, so recording resumes after this
/// call as it does after stock's internal calls of 0x91f66f50.
pub(crate) fn start(name: u32) -> u32 {
    // SAFETY: the entry follows the console convention, which a 32-bit
    // caller satisfies for 32-bit arguments.
    let entry: extern "C" fn(u32) -> u32 =
        unsafe { core::mem::transmute(start_entry as *const ()) };
    entry(name)
}

/// Export 134: as export 133, recording only from `start` onward, and
/// calls made from it only when `record_nested` is nonzero.
extern "C" fn start_recording_at(name: u32, start: u32, record_nested: u32) -> u32 {
    if BASE.load(Ordering::Acquire) != 0 {
        return 0;
    }

    SESSION
        .encoder
        .set_start(NonZeroU32::new(start), record_nested != 0);
    start_body(name)
}

export!(134, start_recording_at);

/// Export 135: the buffer size limit; a nonzero `size` replaces it, at
/// least 1 MiB.
extern "C" fn set_size_limit(size: u32) -> u32 {
    let previous = SIZE_LIMIT.load(Ordering::Relaxed);
    if size != 0 {
        SIZE_LIMIT.store(size.max(MINIMUM_SIZE_LIMIT), Ordering::Relaxed);
    }

    previous
}

export!(135, set_size_limit);

/// Part of the stop; see [`stop_recording`].
fn report_timing() {
    let encoder = &SESSION.encoder;
    if BASE.load(Ordering::Acquire) != 0 {
        let elapsed = Timebase::now()
            .ticks()
            .wrapping_sub(load_pair(&SESSION.start_time)) as i64;
        let frequency = kernel::performance_frequency() as i64;
        let deferred = i64::from(encoder.deferred());
        print(
            c"Tracing: %I64d ms to record %I64d instructions of %I64d.\n",
            &[
                (elapsed.wrapping_mul(1000) / frequency) as u64,
                encoder.recorded().wrapping_sub(deferred as u64),
                encoder.total().wrapping_sub(deferred as u64),
            ],
        );
    }

    if FAILED.load(Ordering::Acquire) {
        output_debug_string(b"Tracing: One or more trace recording errors occurred.\n");
    }

    FAILED.store(false, Ordering::Release);
}

/// Part of the stop; see [`stop_recording`].
fn report_mismatches() {
    let encoder = &SESSION.encoder;
    let (count, kept) = encoder.mismatches();
    if count != 0 {
        print(
            c"%d tracing error(s) detected. Please send the debug prints,\ntrace file, and executable to gameds@microsoft.com.\n",
            &[u64::from(count)],
        );
        for mismatch in kept {
            print(
                c"\tInstnum %I64d, expected address %08x, found address %08x\n",
                &[
                    mismatch.instruction,
                    u64::from(mismatch.expected),
                    u64::from(mismatch.found),
                ],
            );
        }
    }

    encoder.clear_mismatches();
}

/// Free the session memory (stock passes the buffer base, 0x78 past the
/// allocation, and the size limit variable).
fn free_memory() {
    // SAFETY: BASE and SIZE_LIMIT are static u32 values that describe the
    // session allocation, which no thread uses any more.
    unsafe {
        xboxkrnl::NtFreeVirtualMemory(
            BASE.as_ptr(),
            SIZE_LIMIT.as_ptr(),
            AllocationType::RELEASE,
            MEMORY_OPTION.load(Ordering::Relaxed),
        )
    };
}

/// Stock 0x91f668c0: a session with a file frees its memory; the hooks go.
/// Part of the stop; see [`stop_recording`].
fn release() {
    if has_file_name() {
        free_memory();
        clear_queues();
        BASE.store(0, Ordering::Release);
        SESSION.encoder.clear_start();
    }

    unhook();
}

/// Export 136: stop recording, write the rest of the file, and report;
/// 1 unless writing the file failed. On the traced thread the trace hooks
/// disarm before its entry runs. On another thread (control code 0x39,
/// PIX) the stop does not synchronize with the handler, which keeps
/// recording until it sees `STOP_REQUESTED`; the stop's use of the
/// session state races it, as in stock.
extern "C" fn stop_recording() -> u32 {
    if BASE.load(Ordering::Acquire) == 0 {
        return 0;
    }

    STOP_REQUESTED.store(true, Ordering::Release);
    report_timing();
    queue_current();

    let handle = WRITER_HANDLE.load(Ordering::Acquire);
    if handle != 0 {
        WRITER_RUNNING.store(false, Ordering::Release);
        // SAFETY: `handle` is the owned writer thread handle, closed once
        // after the wait.
        unsafe {
            xboxkrnl::NtWaitForSingleObjectEx(
                Handle::from_raw(handle),
                ProcessorMode::User,
                false,
                core::ptr::null(),
            );
            xboxkrnl::NtClose(Handle::from_raw(handle));
        }
        forget_writer(handle);
        WRITER_HANDLE.store(0, Ordering::Release);
    }

    report_mismatches();
    release();

    let stop_address = NonZeroU32::new(SESSION.stop_address.load(Ordering::Relaxed));
    SESSION.stop_address.store(0, Ordering::Relaxed);
    if let Some(address) = stop_address {
        print(
            c"Tracing stopped at IAR %08x because\n",
            &[u64::from(address.get())],
        );
        output_debug_string(
            b"the trace buffer filled up. Use XTraceSetBufferSize to increase the buffer\n",
        );
        print(
            c"size (currently %d).\n",
            &[u64::from(SIZE_LIMIT.load(Ordering::Relaxed))],
        );
    }

    super::pmc::print(
        c"Spoofed %d functions.\n",
        &[u64::from(SPOOFED.swap(0, Ordering::Relaxed))],
    );
    STOP_REQUESTED.store(false, Ordering::Release);

    u32::from(!FAILED.load(Ordering::Acquire))
}

// The trace hooks recognize calls to export 136 by this entry address and
// stop before tracing it.
bridged!(stop_entry, stop_recording);
export_raw!(136, stop_entry);

/// Export 137: write a session kept in memory to the file `name` and free
/// it; 1 when the file was written.
extern "C" fn save_recording(name: u32) -> u32 {
    if BASE.load(Ordering::Acquire) == 0 {
        return 0;
    }

    // SAFETY: export 137 takes the address of the caller's NUL-terminated
    // file name, not 0 (stock reads it without a check), which the caller
    // keeps unchanged during the call.
    let name = unsafe { kernel::c_string(name).unwrap_unchecked() };
    set_file_name(name);
    match create_trace_file(name) {
        Some(handle) => {
            // SAFETY: `handle` was just opened and is closed once.
            unsafe { xboxkrnl::NtClose(Handle::from_raw(handle)) };
        }
        None => {
            output_debug_string(b"Tracing: File open failed.\n");
            FAILED.store(true, Ordering::Release);
        }
    }

    flush();
    let result = u32::from(!FAILED.swap(false, Ordering::AcqRel));

    free_memory();
    BASE.store(0, Ordering::Release);
    SESSION.encoder.clear_start();

    result
}

export!(137, save_recording);

/// Whether a session exists (export 177).
pub(crate) fn is_recording() -> bool {
    BASE.load(Ordering::Acquire) != 0
}

extern "C" fn export_is_recording() -> u32 {
    u32::from(is_recording())
}

export!(177, export_is_recording);

/// Export 195: hardware thread of later writer threads, at most 5.
extern "C" fn set_writer_processor(processor: u32) -> u32 {
    const MAXIMUM_WRITER_PROCESSOR: u32 = HARDWARE_THREAD_COUNT as u32 - 1;

    let processor = processor.min(MAXIMUM_WRITER_PROCESSOR);
    WRITER_PROCESSOR.store(processor, Ordering::Relaxed);

    processor
}

export!(195, set_writer_processor);

/// Title termination while a session exists (stock 0x91f66388): the hooks
/// go and the session is forgotten; its memory and a running writer
/// thread are abandoned, as in stock.
extern "C" fn title_terminated() {
    unhook();
    SIZE_LIMIT.store(DEFAULT_SIZE_LIMIT, Ordering::Relaxed);
    BASE.store(0, Ordering::Release);
    SESSION.stop_address.store(0, Ordering::Relaxed);
    SPOOFED.store(0, Ordering::Relaxed);
    STOP_REQUESTED.store(false, Ordering::Release);
    FAILED.store(false, Ordering::Release);
    CURRENT.store(null_mut(), Ordering::Release);
    clear_queues();
    WRITER_HANDLE.store(0, Ordering::Release);
    set_file_name(&[]);
    SESSION.encoder.clear_start();
}

bridged!(title_terminated_entry, title_terminated);

/// Create `e:\pix` and start recording the calling thread to
/// `e:\pix\unnamed.pix2` (stock 0x91f3b610, also used by PIX).
pub(crate) fn start_default() -> u32 {
    const DEFAULT_DIRECTORY: &[u8] = b"e:\\pix";
    const DEFAULT_FILE: &core::ffi::CStr = c"e:\\pix\\unnamed.pix2";

    let request = create_request(
        AccessMask::LIST_DIRECTORY.union(AccessMask::SYNCHRONIZE),
        ShareAccess::empty(),
        CreateDisposition::Create,
        CreateOptions::DIRECTORY_FILE.union(CreateOptions::SYNCHRONOUS_IO_NONALERT),
    );

    if let Some(handle) = open(DEFAULT_DIRECTORY, &request) {
        // SAFETY: `handle` was just opened and is closed once.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(handle)) };
    }

    start(DEFAULT_FILE.as_ptr() as usize as u32)
}

/// Stop through the export 136 entry, which the trace hooks recognize, as
/// stock's internal callers branch to 0x91f66998.
pub(crate) fn stop() -> u32 {
    // SAFETY: the entry follows the console convention, which a 32-bit
    // caller satisfies.
    let entry: extern "C" fn() -> u32 = unsafe { core::mem::transmute(stop_entry as *const ()) };
    entry()
}

/// Control code 0x38.
pub(crate) fn service_start(_argument: u32) -> u32 {
    start_default()
}

/// Control code 0x39.
pub(crate) fn service_stop(_argument: u32) -> u32 {
    stop()
}

/// Control code 0x3a: low word of the traced instruction count while a
/// session exists.
pub(crate) fn service_instruction_count(_argument: u32) -> u32 {
    if BASE.load(Ordering::Acquire) == 0 {
        0
    } else {
        SESSION.encoder.total_low()
    }
}

/// Control code 0x3b: stop single-stepping at the next instruction.
pub(crate) fn service_request_stop(_argument: u32) -> u32 {
    STOP_REQUESTED.store(true, Ordering::Release);

    1
}

/// Module unload: remove the hooks and the title terminate registration
/// and wait for every writer thread.
pub(crate) fn shut_down() {
    ARMED.store(false, Ordering::Release);
    unhook();

    if TERMINATE_REGISTERED.swap(false, Ordering::AcqRel) {
        // SAFETY: TITLE_TERMINATE is the static registration added by `hook`.
        unsafe { xboxkrnl::ExRegisterTitleTerminateNotification(TITLE_TERMINATE.as_ptr(), false) };
    }

    WRITER_RUNNING.store(false, Ordering::Release);
    WRITER_HANDLE.store(0, Ordering::Release);

    for slot in &WRITERS {
        let handle = slot.swap(0, Ordering::AcqRel);
        if handle == 0 {
            continue;
        }

        // SAFETY: `handle` was taken out of its tracking slot and is closed
        // once after the wait.
        unsafe {
            xboxkrnl::NtWaitForSingleObjectEx(
                Handle::from_raw(handle),
                ProcessorMode::User,
                false,
                core::ptr::null(),
            );
            xboxkrnl::NtClose(Handle::from_raw(handle));
        }
    }
}
