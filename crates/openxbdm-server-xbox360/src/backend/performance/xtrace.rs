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

use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::sync::atomic::fence;

use openxbdm_server::Server;
use openxbdm_server::commands::filesystem::CreateDisposition;
use openxbdm_server::commands::filesystem::CreateOptions;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::FileAccess;
use openxbdm_server::commands::filesystem::FileAttributes;
use openxbdm_server::commands::filesystem::ObjectPath;
use openxbdm_server::commands::filesystem::ShareAccess;
use openxbdm_server::commands::performance::xtrace;
use openxbdm_server::commands::performance::xtrace::AddressSpace;
use openxbdm_server::commands::performance::xtrace::Encoder;
use openxbdm_server::commands::performance::xtrace::Region;
use openxbdm_server::commands::performance::xtrace::Sink;
use openxbdm_server::commands::performance::xtrace::Thread;
use xbox360_sys::export_raw;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AllocationType;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::MemoryRegion;
use xbox360_sys::xboxkrnl::MmQueryAddressProtect;
use xbox360_sys::xboxkrnl::MmQueryAllocationSize;
use xbox360_sys::xboxkrnl::NtQueryVirtualMemory;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;

use super::c_string;
use super::module_snapshot;
use crate::backend::Console;
use crate::backend::dispatcher;
use crate::backend::filesystem;
use crate::exports::export;
use crate::kernel;
use crate::net::XamNetwork;

const BUFFER_COUNT: usize = 5;
/// Session memory before the stream buffers.
const HEADER_SIZE: u32 = 0x78;
const CACHE_SIZE: u32 = (xtrace::CACHE_WORDS * 4) as u32;
const DEFAULT_SIZE_LIMIT: u32 = 0x40_0000;
const MINIMUM_SIZE_LIMIT: u32 = 0x10_0000;
const MAXIMUM_ALLOCATION: u32 = 0x8000_0000;
const MEM_COMMIT_RESERVE_LARGE: AllocationType = AllocationType::COMMIT
    .union(AllocationType::RESERVE)
    .union(AllocationType::LARGE_PAGES);
/// Memory options of the session allocation: debug memory, then title
/// memory when that fails.
const DEBUG_MEMORY: MemoryRegion = MemoryRegion::TitleDebug;
const TITLE_MEMORY: MemoryRegion = MemoryRegion::Title;
/// A queued buffer leaves room for one record.
const RECORD_RESERVE: u32 = 8;
/// Instructions and returns skipped after arming: the way back out of
/// the start function.
const SKIP_INSTRUCTIONS: u32 = 0x28;
const SKIP_RETURNS: u32 = 2;
const WRITER_STACK: u32 = 0x8000;
const WRITER_INTERVAL_MS: u32 = 10;
const DEFAULT_WRITER_PROCESSOR: u32 = 5;
const MAXIMUM_WRITER_PROCESSOR: u32 = 5;
const FILE_NAME_SIZE: usize = 0x100;
const STATUS_SINGLE_STEP: u32 = 0x8000_0004;
const STATUS_PENDING: u32 = 0x103;
const STATUS_WAIT_0: u32 = 0;
const MSR_SINGLE_STEP: u32 = 0x400;
/// Hardware flag that disables running the spin lock routines natively.
const HARDWARE_NO_SPOOF: u32 = 0x0200_0000;
const TITLE_TERMINATE_PRIORITY: u32 = 0x6f00_0000;
const PROGRESS_INTERVAL: i64 = 100_000;
/// Progress interval when the kernel has the fast trace hook.
const FAST_PROGRESS_INTERVAL: i64 = 500_000;
const NETWORK_OPEN_INFORMATION_SIZE: usize = 0x38;
const DEFAULT_DIRECTORY: &[u8] = b"e:\\pix";
const DEFAULT_FILE: &core::ffi::CStr = c"e:\\pix\\unnamed.pix2";

/// Kernel routines the handler runs natively instead of stepping through
/// them (their reservation loops never complete under single-step), and
/// whether the walk of the routine's body follows forward branches.
const SPOOFED_ROUTINES: [(Ordinal, bool); 5] = [
    (Ordinal::new(0x125).unwrap(), false), // RtlEnterCriticalSection
    (Ordinal::new(0x4d).unwrap(), false),  // KeAcquireSpinLockAtRaisedIrql
    (Ordinal::new(0xb1).unwrap(), false),  // KfAcquireSpinLock
    (Ordinal::new(0x10f).unwrap(), false), // ObReferenceObject
    (Ordinal::new(0x105).unwrap(), true),  // ObDereferenceObject
];

/// Trap frame offsets.
mod frame {
    pub const GPR: u32 = 0x50;
    pub const IAR: u32 = 0x1ac;
    pub const MSR: u32 = 0x1b4;
    pub const XER: u32 = 0x1b8;
    pub const SIZE: usize = 0x1c0;
}

/// Context offsets.
mod context {
    pub const MSR: u32 = 0x4;
    pub const IAR: u32 = 0x8;
    pub const GPR3: u32 = 0x30;
}

const RECORD_ADDRESS: u32 = 0xc;

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
static MEMORY_OPTION: AtomicU32 = AtomicU32::new(DEBUG_MEMORY as u32);
/// Hardware thread of the writer thread (export 195).
static WRITER_PROCESSOR: AtomicU32 = AtomicU32::new(DEFAULT_WRITER_PROCESSOR);
static SPOOF_ENABLED: AtomicBool = AtomicBool::new(true);
static SPOOF_RESOLVED: AtomicBool = AtomicBool::new(false);
static SPOOF_TARGETS: [AtomicU32; 5] = [const { AtomicU32::new(0) }; 5];
static SPOOFED: AtomicU32 = AtomicU32::new(0);

/// Session memory: the first stream buffer's address (allocation + 0x78,
/// which stock also passes to the free); null while no session exists.
static BASE: AtomicU32 = AtomicU32::new(0);
static CACHE: AtomicU32 = AtomicU32::new(0);
/// Single-stepping is on for the traced thread.
static ARMED: AtomicBool = AtomicBool::new(false);
/// A recording, file, or allocation error happened.
static FAILED: AtomicBool = AtomicBool::new(false);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static WRITER_HANDLE: AtomicU32 = AtomicU32::new(0);
static WRITER_RUNNING: AtomicBool = AtomicBool::new(false);
/// Handles of every writer thread not known to have ended. Title
/// termination abandons the running writer as stock does; it ends at the
/// next stop, and unload waits for all of them.
static WRITERS: [AtomicU32; WRITER_CAPACITY] = [const { AtomicU32::new(0) }; WRITER_CAPACITY];
const WRITER_CAPACITY: usize = 16;
/// Kernel debug routine variable this engine hooked, and its prior value.
static ROUTINE_SLOT: AtomicU32 = AtomicU32::new(0);
static PREVIOUS_ROUTINE: AtomicU32 = AtomicU32::new(0);
/// Kernel trace hook variable (debug monitor service 6).
static HOOK_SLOT: AtomicU32 = AtomicU32::new(0);
static TERMINATE_REGISTERED: AtomicBool = AtomicBool::new(false);

/// State of the traced thread's handler, also used by the threads that
/// start and stop the session.
struct Session {
    encoder: Encoder,
    skip_instructions: u32,
    skip_returns: u32,
    start_time: u64,
    stop_address: Option<u32>,
}

struct Shared<T>(UnsafeCell<T>);

// SAFETY: stock shares this state between the traced thread's exception
// handler and the threads that start and stop the session without
// synchronization; start and stop run while the handler is idle or
// disarmed. Values the writer thread reads are separate cells accessed
// with volatile operations.
unsafe impl<T> Sync for Shared<T> {}

static SESSION: Shared<Session> = Shared(UnsafeCell::new(Session {
    encoder: Encoder::new(),
    skip_instructions: 0,
    skip_returns: 0,
    start_time: 0,
    stop_address: None,
}));

#[allow(clippy::mut_from_ref)]
fn session() -> &'static mut Session {
    // SAFETY: see `Shared`.
    unsafe { &mut *SESSION.0.get() }
}

/// Encoded and recorded instruction counts, published after each change
/// for the writer thread and control code 0x3a.
static COUNTS: Shared<[u64; 2]> = Shared(UnsafeCell::new([0; 2]));
/// Encoded instruction count of the last progress line.
static PROGRESS_MARK: Shared<i64> = Shared(UnsafeCell::new(0));
static FILE_NAME: Shared<[u8; FILE_NAME_SIZE]> = Shared(UnsafeCell::new([0; FILE_NAME_SIZE]));

fn publish_counts() {
    let encoder = &session().encoder;
    // SAFETY: a plain cell; see `Shared`.
    unsafe { core::ptr::write_volatile(COUNTS.0.get(), [encoder.total(), encoder.recorded()]) };
}

/// Encoded and recorded instruction counts.
fn counts() -> (u64, u64) {
    // SAFETY: a plain cell; see `Shared`.
    let [total, recorded] = unsafe { core::ptr::read_volatile(COUNTS.0.get()) };
    (total, recorded)
}

fn progress_mark() -> i64 {
    // SAFETY: a plain cell; see `Shared`.
    unsafe { core::ptr::read_volatile(PROGRESS_MARK.0.get()) }
}

fn set_progress_mark(value: i64) {
    // SAFETY: a plain cell; see `Shared`.
    unsafe { core::ptr::write_volatile(PROGRESS_MARK.0.get(), value) }
}

/// Title terminate registration `{routine, priority, links}`.
static TITLE_TERMINATE: Shared<[u32; 4]> = Shared(UnsafeCell::new([0; 4]));

/// Scratch output of a record made while no buffer is free; two encodings
/// of at most eight words each.
static SCRATCH: Shared<[u32; 16]> = Shared(UnsafeCell::new([0; 16]));

use core::time::Duration;

use xbox360::console::hardware_flags;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::status::set_last_error;
use xbox360::time::Timebase;
use xbox360::time::sleep;

use crate::exports::bridged;

fn read_u32(address: u32) -> u32 {
    // SAFETY: callers pass addresses of kernel structures, code, or the
    // session memory.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn write_u32(address: u32, value: u32) {
    // SAFETY: as `read_u32`, for writable structures.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

fn read_u64(address: u32) -> u64 {
    (u64::from(read_u32(address)) << 32) | u64::from(read_u32(address + 4))
}

fn write_u64(address: u32, value: u64) {
    write_u32(address, (value >> 32) as u32);
    write_u32(address + 4, value as u32);
}

fn is_failure(status: u32) -> bool {
    (status as i32) < 0
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

/// The session file name.
fn file_name() -> ([u8; FILE_NAME_SIZE], usize) {
    let mut name = [0u8; FILE_NAME_SIZE];
    // SAFETY: a plain cell; see `Shared`.
    unsafe {
        core::ptr::copy_nonoverlapping(
            FILE_NAME.0.get().cast::<u8>(),
            name.as_mut_ptr(),
            FILE_NAME_SIZE,
        )
    };
    let length = name
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(FILE_NAME_SIZE);
    (name, length)
}

fn has_file_name() -> bool {
    // SAFETY: a plain cell; see `Shared`.
    unsafe { core::ptr::read_volatile(FILE_NAME.0.get().cast::<u8>()) != 0 }
}

/// Store the session file name as stock's bounded copy does: at most
/// 0xff bytes and a terminator.
#[inline(never)]
fn set_file_name(name: &[u8]) {
    let length = name.len().min(FILE_NAME_SIZE - 1);
    let stored = FILE_NAME.0.get().cast::<u8>();
    // SAFETY: a plain cell; see `Shared`.
    unsafe {
        core::ptr::copy_nonoverlapping(name.as_ptr(), stored, length);
        core::ptr::write_bytes(stored.add(length), 0, FILE_NAME_SIZE - length);
    }
}

/// Request of [`translate_on_server`].
struct Translation<'a> {
    name: &'a [u8],
    path: Option<ObjectPath>,
}

fn translate_on_server(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    request: &mut Translation<'_>,
) -> u32 {
    request.path = server
        .state
        .filesystem
        .drives
        .translate(console, request.name);
    0
}

/// Open a drive path (stock 0x91f2eb68). The drive table is server state,
/// so the name is translated on the server thread; a name that does not
/// translate fails, where stock would use an uninitialized handle.
fn open(name: &[u8], request: &CreateRequest) -> Option<u32> {
    let mut translation = Translation { name, path: None };
    dispatcher::call_on_server_with(&mut translation, translate_on_server)?;
    filesystem::create_file(translation.path?.as_bytes(), request)
        .ok()
        .map(|handle| handle.0)
}

fn create_request(
    access: FileAccess,
    share: ShareAccess,
    disposition: CreateDisposition,
    options: CreateOptions,
) -> CreateRequest {
    CreateRequest {
        access,
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share,
        disposition,
        options,
    }
}

/// The trace file opened for writing, replaced or created.
fn create_trace_file(name: &[u8]) -> Option<u32> {
    open(
        name,
        &create_request(
            FileAccess::GENERIC_WRITE.union(FileAccess::SYNCHRONIZE),
            ShareAccess::READ,
            CreateDisposition::OverwriteIf,
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
        ),
    )
}

/// Append `length` bytes at `data` to the trace file; true when all were
/// written.
fn append(name: &[u8], data: u32, length: u32) -> bool {
    let Some(handle) = open(
        name,
        &create_request(
            FileAccess::GENERIC_WRITE.union(FileAccess::SYNCHRONIZE),
            ShareAccess::READ,
            CreateDisposition::Open,
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
        ),
    ) else {
        return false;
    };
    let mut io_status = IoStatusBlock::default();
    let mut information = [0u8; NETWORK_OPEN_INFORMATION_SIZE];
    // SAFETY: `handle` was opened above; `io_status` and `information` are
    // live and sized as stated.
    let status = unsafe {
        xboxkrnl::NtQueryInformationFile(
            Handle::from_raw(handle),
            &mut io_status,
            information.as_mut_ptr(),
            NETWORK_OPEN_INFORMATION_SIZE as u32,
            FileInformationClass::NetworkOpen,
        )
    };
    // Stock seeks to the end; when that fails the write goes to the start.
    let offset = match status.result() {
        Err(error) => {
            set_last_error(error);
            0
        }
        Ok(()) => u64::from_be_bytes(information[0x28..0x30].try_into().unwrap_or([0; 8])),
    };
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `handle` was opened above; `io_status`, `offset`, and the
    // `length` bytes at `data` stay live until the write completes, which
    // the wait below ensures.
    let mut status = unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(handle),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            data as usize as *const u8,
            length,
            &offset,
        )
    };
    if status.0 == STATUS_PENDING {
        // SAFETY: `handle` was opened above.
        status = unsafe {
            xboxkrnl::NtWaitForSingleObjectEx(
                Handle::from_raw(handle),
                ProcessorMode::User,
                false,
                core::ptr::null(),
            )
        };
        if !is_failure(status.0) {
            status = io_status.status;
        }
    }
    let written = if !is_failure(status.0) || status.0 & 0xc000_0000 == 0x8000_0000 {
        io_status.information
    } else {
        0
    };
    if let Err(error) = status.result() {
        set_last_error(error);
    }
    // SAFETY: `handle` was opened above and is closed once.
    unsafe { xboxkrnl::NtClose(Handle::from_raw(handle)) };
    written == length
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

/// Writes words at a cursor in session memory.
struct Cursor(u32);

impl Sink for Cursor {
    fn push(&mut self, word: u32) {
        write_u32(self.0, word);
        self.0 += 4;
    }
}

/// The traced thread's registers in its trap frame.
struct TrapFrame(u32);

impl Thread for TrapFrame {
    fn instruction(&self, address: u32) -> u32 {
        read_u32(address)
    }

    fn gpr(&self, index: u32) -> u32 {
        read_u32(self.0 + frame::GPR + 8 * index + 4)
    }

    fn xer(&self) -> u32 {
        read_u32(self.0 + frame::XER)
    }
}

fn cache() -> &'static mut [u32; xtrace::CACHE_WORDS] {
    // SAFETY: the session allocation holds the cache at `CACHE`; only the
    // traced thread's handler uses it.
    unsafe { &mut *(CACHE.load(Ordering::Relaxed) as usize as *mut [u32; xtrace::CACHE_WORDS]) }
}

/// Record the instruction at `iar` (stock 0x91f66288); false when no
/// buffer was free, which ends the recording.
fn record(iar: u32, trap_frame: u32) -> bool {
    if BASE.load(Ordering::Acquire) == 0 {
        return false;
    }
    let mut buffer = CURRENT.load(Ordering::Acquire);
    if buffer.is_null() {
        buffer = take_free_buffer();
    }
    // SAFETY: buffer slots hold null or an element of `BUFFERS`.
    let start = match unsafe { buffer.as_ref() } {
        Some(buffer) => {
            buffer.data.load(Ordering::Relaxed) + 4 * buffer.used.load(Ordering::Relaxed)
        }
        None => SCRATCH.0.get() as usize as u32,
    };
    let mut cursor = Cursor(start);
    session()
        .encoder
        .record(iar, &TrapFrame(trap_frame), cache(), &mut cursor);
    publish_counts();
    // SAFETY: as above.
    let Some(buffer) = (unsafe { CURRENT.load(Ordering::Acquire).as_ref() }) else {
        session().stop_address = Some(iar);
        FAILED.store(true, Ordering::Release);
        return false;
    };
    let used = buffer.used.load(Ordering::Relaxed) + (cursor.0 - start) / 4;
    buffer.used.store(used, Ordering::Release);
    if buffer.capacity.load(Ordering::Relaxed).wrapping_sub(used) < RECORD_RESERVE {
        queue_current();
    }
    true
}

/// Skip the way out of the start function, then record; false ends the
/// recording.
fn skip_or_record(iar: u32, trap_frame: u32) -> bool {
    let session = session();
    if session.skip_returns != 0 && session.skip_instructions != 0 {
        session.skip_instructions -= 1;
        if read_u32(iar) == xtrace::BLR {
            session.skip_returns -= 1;
        }
        return true;
    }
    record(iar, trap_frame)
}

fn spoofed_routine(iar: u32) -> Option<usize> {
    SPOOF_TARGETS
        .iter()
        .rposition(|target| target.load(Ordering::Relaxed) == iar)
}

/// Call the console routine at `function` with r3 loaded from the 64-bit
/// value at `argument`, and store its 64-bit result. The CPU model of the
/// target has no 64-bit mnemonics, so `ld`/`std` are encoded directly.
#[unsafe(naked)]
extern "C" fn call_native(function: u32, argument: u32, result: *mut u64) {
    core::arch::naked_asm!(
        "stwu 1, -0x60(1)",
        "mflr 0",
        "stw 0, 0x64(1)",
        "stw 5, 0x58(1)",
        "mtctr 3",
        // ld 3, 0(4)
        ".long 0xe8640000",
        "bctrl",
        "lwz 5, 0x58(1)",
        // std 3, 0(5)
        ".long 0xf8650000",
        "lwz 0, 0x64(1)",
        "mtlr 0",
        "addi 1, 1, 0x60",
        "blr",
    )
}

/// Run a spoofed routine natively and record its body up to its `blr` as
/// if it had been stepped, with r4, r5, r11, and r31 set to plausible
/// values for the effective addresses. The thread resumes at the `blr`
/// with the routine's result.
fn spoof(entry: usize, trap_frame: u32, record_address: u32, context_address: u32) -> u32 {
    SPOOFED.fetch_add(1, Ordering::Relaxed);
    let function = SPOOF_TARGETS[entry].load(Ordering::Relaxed);
    let mut result = 0u64;
    call_native(function, trap_frame + frame::GPR + 8 * 3, &mut result);
    let mut saved = [0u8; frame::SIZE];
    // SAFETY: the trap frame holds `frame::SIZE` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            trap_frame as usize as *const u8,
            saved.as_mut_ptr(),
            frame::SIZE,
        )
    };
    let gpr = |index: u32| trap_frame + frame::GPR + 8 * index;
    let argument = read_u64(gpr(3));
    write_u64(gpr(5), 0x10);
    write_u64(gpr(11), argument.wrapping_sub(0x10));
    write_u64(gpr(4), argument);
    write_u64(gpr(31), argument.wrapping_sub(0x10));
    let follow_forward = SPOOFED_ROUTINES[entry].1;
    let mut address = function;
    loop {
        let word = read_u32(address);
        if word == xtrace::BLR {
            break;
        }
        write_u32(trap_frame + frame::IAR, address);
        write_u32(record_address + RECORD_ADDRESS, address);
        record(address, trap_frame);
        let forward_branch = word & 0xfc00_0000 == 0x4000_0000 && word & 0x8000 == 0;
        address = address.wrapping_add(if follow_forward && forward_branch {
            word & 0xfffc
        } else {
            4
        });
    }
    // SAFETY: as above.
    unsafe {
        core::ptr::copy_nonoverlapping(saved.as_ptr(), trap_frame as usize as *mut u8, frame::SIZE)
    };
    write_u32(context_address + context::IAR, address);
    write_u64(context_address + context::GPR3, result);
    write_u32(record_address + RECORD_ADDRESS, address);
    address
}

fn stop_entry_address() -> u32 {
    stop_entry as *const () as usize as u32
}

/// Kernel trace hook (stock 0x91f66ab0): handles trace exceptions before
/// the debug routine. Spoofed routines are left to the debug routine.
extern "C" fn trace_hook(trap_frame: u32, record_address: u32) -> u32 {
    if read_u32(record_address) != STATUS_SINGLE_STEP {
        return 0;
    }
    if ARMED.load(Ordering::Acquire) && !FAILED.load(Ordering::Acquire) {
        let iar = read_u32(record_address + RECORD_ADDRESS);
        let mut stop = iar == stop_entry_address() || STOP_REQUESTED.load(Ordering::Acquire);
        if SPOOF_ENABLED.load(Ordering::Relaxed) {
            let mut spoofed = spoofed_routine(iar).is_some();
            if hardware_flags().bits() & HARDWARE_NO_SPOOF != 0 {
                spoofed = false;
                SPOOF_ENABLED.store(false, Ordering::Relaxed);
            }
            if spoofed {
                return 0;
            }
        }
        if !stop {
            stop = !skip_or_record(iar, trap_frame);
        }
        if !(ARMED.load(Ordering::Acquire) && stop) {
            return 1;
        }
    } else if !ARMED.load(Ordering::Acquire) {
        return 1;
    }
    write_u32(
        trap_frame + frame::MSR,
        read_u32(trap_frame + frame::MSR) & !MSR_SINGLE_STEP,
    );
    ARMED.store(false, Ordering::Release);
    1
}

/// Debug routine (stock 0x91f66c30): trace exceptions while a session
/// exists; every other exception goes to the previous routine.
extern "C" fn debug_routine(
    trap_frame: u32,
    record_address: u32,
    context_address: u32,
    second_chance: u32,
) -> u32 {
    if read_u32(record_address) != STATUS_SINGLE_STEP {
        let previous = PREVIOUS_ROUTINE.load(Ordering::Acquire);
        // SAFETY: the kernel's debug routine variable held this routine.
        return unsafe {
            kernel::call_export(
                previous,
                trap_frame,
                record_address,
                context_address,
                second_chance,
            )
        };
    }
    if ARMED.load(Ordering::Acquire) && !FAILED.load(Ordering::Acquire) {
        let mut iar = read_u32(record_address + RECORD_ADDRESS);
        let mut stop = iar == stop_entry_address() || STOP_REQUESTED.load(Ordering::Acquire);
        if SPOOF_ENABLED.load(Ordering::Relaxed)
            && let Some(entry) = spoofed_routine(iar)
        {
            iar = spoof(entry, trap_frame, record_address, context_address);
        }
        if !stop {
            stop = !skip_or_record(iar, trap_frame);
        }
        if !(ARMED.load(Ordering::Acquire) && stop) {
            return 1;
        }
    } else if !ARMED.load(Ordering::Acquire) {
        return 1;
    }
    write_u32(
        context_address + context::MSR,
        read_u32(context_address + context::MSR) & !MSR_SINGLE_STEP,
    );
    ARMED.store(false, Ordering::Release);
    1
}

bridged!(trace_hook_entry, trace_hook);
bridged!(debug_routine_entry, debug_routine);

/// Resolve the spoofed kernel routines once (stock reads the targets of
/// its import thunks at the first start).
fn resolve_spoofed_routines() {
    if SPOOF_RESOLVED.swap(true, Ordering::AcqRel) {
        return;
    }
    let Ok(module) = SystemModule::Kernel.handle() else {
        return;
    };
    for (target, &(ordinal, _)) in SPOOF_TARGETS.iter().zip(&SPOOFED_ROUTINES) {
        if let Ok(address) = resolve_export(module, ordinal) {
            target.store(address.raw(), Ordering::Relaxed);
        }
    }
}

/// Install the hooks (stock 0x91f66e88).
fn hook() {
    if BASE.load(Ordering::Acquire) == 0 {
        return;
    }
    // Stock registers at every start; a session saved by export 137
    // without a stop keeps the registration, and registering it again
    // would corrupt the kernel's list.
    if !TERMINATE_REGISTERED.swap(true, Ordering::AcqRel) {
        // SAFETY: the registration is not linked while it is written.
        unsafe {
            *TITLE_TERMINATE.0.get() = [
                title_terminated_entry as *const () as usize as u32,
                TITLE_TERMINATE_PRIORITY,
                0,
                0,
            ]
        };
        // SAFETY: TITLE_TERMINATE is a static registration filled in above.
        unsafe {
            xboxkrnl::ExRegisterTitleTerminateNotification(TITLE_TERMINATE.0.get().cast(), true)
        };
    }
    let mut hook_slot = [0u32; 2];
    // SAFETY: `hook_slot` is a live two-word reply block.
    let status = unsafe {
        xboxkrnl::ExDebugMonitorService(
            DebugMonitorService::TraceHook,
            hook_slot.as_mut_ptr() as usize as u32,
            0,
            0,
        )
    };
    if !is_failure(status.0) {
        HOOK_SLOT.store(hook_slot[0], Ordering::Release);
        write_u32(hook_slot[0], trace_hook_entry as *const () as usize as u32);
    }
    let slot = kernel::debug_monitor_data()
        .debug_routine
        .load(Ordering::Relaxed);
    ROUTINE_SLOT.store(slot, Ordering::Release);
    let routine = debug_routine_entry as *const () as usize as u32;
    let previous = read_u32(slot);
    if previous == routine {
        // Stock asserts and then chains the routine to itself, which
        // recurses on the next exception; the chain is kept instead.
        break_trap();
    } else {
        PREVIOUS_ROUTINE.store(previous, Ordering::Release);
    }
    write_u32(slot, routine);
}

/// Remove the debug routine and the trace hook.
fn unhook() {
    let slot = ROUTINE_SLOT.swap(0, Ordering::AcqRel);
    if slot != 0 {
        write_u32(slot, PREVIOUS_ROUTINE.load(Ordering::Acquire));
        // SAFETY: TITLE_TERMINATE is the static registration added by `hook`.
        unsafe {
            xboxkrnl::ExRegisterTitleTerminateNotification(TITLE_TERMINATE.0.get().cast(), false)
        };
        TERMINATE_REGISTERED.store(false, Ordering::Release);
    }
    let hook_slot = HOOK_SLOT.load(Ordering::Acquire);
    if hook_slot != 0 {
        write_u32(hook_slot, 0);
    }
}

/// Write the queued buffers to the file in sequence order (stock
/// 0x91f65e50) and print the progress.
fn flush() {
    let mut collected = [null_mut::<Buffer>(); BUFFER_COUNT];
    let mut count = 0;
    let mut sequence = u32::MAX;
    for slot in &FILLED {
        let buffer = slot.swap(null_mut(), Ordering::AcqRel);
        // SAFETY: buffer slots hold null or an element of `BUFFERS`.
        if let Some(reference) = unsafe { buffer.as_ref() } {
            collected[count] = buffer;
            count += 1;
            sequence = sequence.min(reference.sequence.load(Ordering::Acquire));
        }
    }
    fence(Ordering::AcqRel);
    let mut written = 0;
    for _ in 0..count {
        for (position, slot) in collected.iter_mut().enumerate().take(count) {
            // SAFETY: as above.
            let Some(buffer) = (unsafe { slot.as_ref() }) else {
                continue;
            };
            if buffer.sequence.load(Ordering::Acquire) != sequence {
                continue;
            }
            written += 1;
            let (name, length) = file_name();
            if !FAILED.load(Ordering::Acquire)
                && !append(
                    &name[..length],
                    buffer.data.load(Ordering::Relaxed),
                    4 * buffer.used.load(Ordering::Relaxed),
                )
            {
                output_debug_string(b"Tracing: Error writing trace data to file.\n");
                FAILED.store(true, Ordering::Release);
            }
            buffer.used.store(0, Ordering::Release);
            // Free slots are refilled by position in the collected list,
            // as in stock.
            FREE[position].store(*slot, Ordering::Release);
            *slot = null_mut();
        }
        sequence = sequence.wrapping_add(1);
    }
    if written != count {
        break_trap();
    }
    let interval = if HOOK_SLOT.load(Ordering::Acquire) != 0 {
        FAST_PROGRESS_INTERVAL
    } else {
        PROGRESS_INTERVAL
    };
    loop {
        let (total, recorded) = counts();
        let (total, recorded) = (total as i64, recorded as i64);
        if progress_mark() + interval > total {
            break;
        }
        print(
            c"Tracing: %I64d K instructions recorded of %I64d K.\r\n",
            &[
                (recorded / interval * interval / 1000) as u64,
                (total / interval * interval / 1000) as u64,
            ],
        );
        set_progress_mark(progress_mark() + interval);
    }
}

/// Writer thread (stock 0x91f660f0).
extern "C" fn writer(_context: u32) -> u32 {
    while WRITER_RUNNING.load(Ordering::Acquire) {
        sleep(Duration::from_millis(u64::from(WRITER_INTERVAL_MS)));
        flush();
    }
    flush();
    0
}

/// Keep a new writer's handle for unload, after closing the handles of
/// writers that have ended. A seventeenth live writer is not tracked.
fn track_writer(handle: u32) {
    let now = 0i64;
    for slot in &WRITERS {
        let ended = slot.load(Ordering::Acquire);
        if ended == 0 {
            continue;
        }
        // SAFETY: `ended` is a tracked writer handle; `now` is a live zero
        // timeout.
        let wait = unsafe {
            xboxkrnl::NtWaitForSingleObjectEx(
                Handle::from_raw(ended),
                ProcessorMode::User,
                false,
                &now,
            )
        };
        if wait.0 == STATUS_WAIT_0 {
            // SAFETY: the writer has ended; its tracked handle is closed once.
            unsafe { xboxkrnl::NtClose(Handle::from_raw(ended)) };
            slot.store(0, Ordering::Release);
        }
    }
    if let Some(slot) = WRITERS
        .iter()
        .find(|slot| slot.load(Ordering::Acquire) == 0)
    {
        slot.store(handle, Ordering::Release);
    }
}

/// A writer handle the stop closed.
fn forget_writer(handle: u32) {
    for slot in &WRITERS {
        let _ = slot.compare_exchange(handle, 0, Ordering::AcqRel, Ordering::Relaxed);
    }
}

/// Allocate the session memory, shrinking the request while it fails.
fn allocate() -> bool {
    loop {
        let mut limit = SIZE_LIMIT.load(Ordering::Relaxed);
        if limit.wrapping_add(0x1_0000) > MAXIMUM_ALLOCATION {
            limit = MAXIMUM_ALLOCATION - 0x1_0000;
            SIZE_LIMIT.store(limit, Ordering::Relaxed);
        }
        MEMORY_OPTION.store(DEBUG_MEMORY as u32, Ordering::Relaxed);
        let mut size = limit + 0x1_0000;
        // SAFETY: BASE and `size` are live u32 values.
        let mut status = unsafe {
            xboxkrnl::NtAllocateVirtualMemory(
                BASE.as_ptr(),
                &mut size,
                MEM_COMMIT_RESERVE_LARGE,
                PageProtection::READWRITE,
                DEBUG_MEMORY,
            )
        };
        if is_failure(status.0) {
            BASE.store(0, Ordering::Relaxed);
            MEMORY_OPTION.store(TITLE_MEMORY as u32, Ordering::Relaxed);
            size = limit + 0x1_0000;
            // SAFETY: as above.
            status = unsafe {
                xboxkrnl::NtAllocateVirtualMemory(
                    BASE.as_ptr(),
                    &mut size,
                    MEM_COMMIT_RESERVE_LARGE,
                    PageProtection::READWRITE,
                    TITLE_MEMORY,
                )
            };
            if is_failure(status.0) {
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
            let processor = WRITER_PROCESSOR.load(Ordering::Relaxed) & 0x3f;
            let affinity = if processor < 32 { 1u32 << processor } else { 0 };
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
                    ThreadCreationFlags::from_bits_retain(affinity << 24),
                )
            };
            if is_failure(status.0) {
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
    let session = session();
    session.skip_returns = SKIP_RETURNS;
    session.skip_instructions = SKIP_INSTRUCTIONS;
    if BASE.load(Ordering::Acquire) == 0 && !allocate() {
        output_debug_string(b"Tracing: Memory allocation failed.\n");
        FAILED.store(true, Ordering::Release);
        return;
    }
    let limit = SIZE_LIMIT.load(Ordering::Relaxed);
    let allocation = BASE.load(Ordering::Relaxed);
    let cache = allocation + limit;
    CACHE.store(cache, Ordering::Relaxed);
    // SAFETY: the allocation holds the header, the buffers, and the cache.
    unsafe {
        core::ptr::write_bytes(cache as usize as *mut u8, 0, CACHE_SIZE as usize);
        core::ptr::write_bytes(allocation as usize as *mut u8, 0, HEADER_SIZE as usize);
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
    session.encoder.reset_depth();
}

/// Address space queries of the memory map record.
struct KernelSpace;

impl AddressSpace for KernelSpace {
    fn query(&mut self, address: u32) -> Option<Region> {
        let mut information = [0u32; 7];
        // SAFETY: `information` is a live seven-word basic information block.
        let status = unsafe { NtQueryVirtualMemory(address, information.as_mut_ptr(), 0) };
        if let Err(error) = status.result() {
            set_last_error(error);
            return None;
        }
        Some(Region {
            size: information[3],
            state: information[4],
            protect: information[5],
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

/// Write the file header at `start` (stock 0x91f673e8); returns the end.
fn write_header(start: u32) -> u32 {
    session().encoder.begin();
    publish_counts();
    let mut cursor = Cursor(start);
    cursor.push(xtrace::TRACE_MAGIC);
    cursor.push(xtrace::TRACE_VERSION);
    let mut executable = [0u8; module_snapshot::PATH_LIMIT + 2];
    let length = module_snapshot::executable_drive_path(&mut executable);
    if let Some(snapshot) =
        module_snapshot::build(&executable[..length], super::capture::snapshot_fields())
    {
        cursor.push(xtrace::MODULE_MAGIC);
        cursor.push(xtrace::MODULE_WORDS);
        for word in 0..xtrace::MODULE_WORDS {
            cursor.push(read_u32(snapshot.address() + 4 * word));
        }
        module_snapshot::free(snapshot);
    }
    cursor.push(xtrace::MAP_MAGIC);
    let count = cursor.0;
    cursor.push(0);
    xtrace::write_memory_map(&mut KernelSpace, &mut cursor);
    write_u32(count, (cursor.0 - count - 4) / 4);
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
        let used = buffer.used.load(Ordering::Relaxed) + (write_header(start) - start) / 4;
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
    let session = session();
    session.start_time = Timebase::now().ticks();
    session.encoder.arm();
    set_progress_mark(0);
    session.stop_address = None;
    publish_counts();
    ARMED.store(true, Ordering::Release);
    // SAFETY: sets MSR[SE] for the calling thread; the hooks are in place.
    unsafe {
        core::arch::asm!("mfmsr {msr}", "ori {msr}, {msr}, 0x400", "mtmsr {msr}", "nop", msr = out(reg) _)
    };
}

/// Stock 0x91f66f50. Inlined into each export so that the skip counts
/// cover exactly the way back to the caller of the export.
#[inline(always)]
fn start_body(name: u32) -> u32 {
    let name = (name != 0).then(|| c_string(name, usize::MAX));
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
    session()
        .encoder
        .set_start((start != 0).then_some(start), record_nested != 0);
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

fn report_timing() {
    let session = session();
    if BASE.load(Ordering::Acquire) != 0 {
        let elapsed = Timebase::now().ticks().wrapping_sub(session.start_time) as i64;
        let frequency = kernel::performance_frequency() as i64;
        let deferred = i64::from(session.encoder.deferred());
        print(
            c"Tracing: %I64d ms to record %I64d instructions of %I64d.\n",
            &[
                (elapsed.wrapping_mul(1000) / frequency) as u64,
                session.encoder.recorded().wrapping_sub(deferred as u64),
                session.encoder.total().wrapping_sub(deferred as u64),
            ],
        );
    }
    if FAILED.load(Ordering::Acquire) {
        output_debug_string(b"Tracing: One or more trace recording errors occurred.\n");
    }
    FAILED.store(false, Ordering::Release);
}

fn report_mismatches() {
    let encoder = &mut session().encoder;
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
fn release() {
    if has_file_name() {
        free_memory();
        clear_queues();
        BASE.store(0, Ordering::Release);
        session().encoder.clear_start();
    }
    unhook();
}

/// Export 136: stop recording, write the rest of the file, and report;
/// 1 unless writing the file failed.
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
    if let Some(address) = session().stop_address.take() {
        print(
            c"Tracing stopped at IAR %08x because\n",
            &[u64::from(address)],
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
    let name = c_string(name, usize::MAX);
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
    session().encoder.clear_start();
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
    session().stop_address = None;
    SPOOFED.store(0, Ordering::Relaxed);
    STOP_REQUESTED.store(false, Ordering::Release);
    FAILED.store(false, Ordering::Release);
    CURRENT.store(null_mut(), Ordering::Release);
    clear_queues();
    WRITER_HANDLE.store(0, Ordering::Release);
    set_file_name(&[]);
    session().encoder.clear_start();
}
bridged!(title_terminated_entry, title_terminated);

/// Create `e:\pix` and start recording the calling thread to
/// `e:\pix\unnamed.pix2` (stock 0x91f3b610, also used by PIX).
pub(crate) fn start_default() -> u32 {
    let request = create_request(
        FileAccess::LIST_DIRECTORY.union(FileAccess::SYNCHRONIZE),
        ShareAccess::NONE,
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
        counts().0 as u32
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
        unsafe {
            xboxkrnl::ExRegisterTitleTerminateNotification(TITLE_TERMINATE.0.get().cast(), false)
        };
    }
    WRITER_RUNNING.store(false, Ordering::Release);
    WRITER_HANDLE.store(0, Ordering::Release);
    for slot in &WRITERS {
        let handle = slot.swap(0, Ordering::AcqRel);
        if handle != 0 {
            // SAFETY: `handle` was taken out of its tracking slot and is
            // closed once after the wait.
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
}
