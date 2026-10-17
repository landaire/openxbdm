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

use core::mem::size_of;
use core::num::NonZeroU32;
use core::ptr::null_mut;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::sync::atomic::fence;
use core::time::Duration;

use openxbdm_server::Server;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::ObjectPath;
use openxbdm_server::commands::performance::xtrace;
use openxbdm_server::commands::performance::xtrace::AddressSpace;
use openxbdm_server::commands::performance::xtrace::Encoder;
use openxbdm_server::commands::performance::xtrace::Region;
use openxbdm_server::commands::performance::xtrace::Sink;
use openxbdm_server::commands::performance::xtrace::Thread;
use xbox360::console::hardware_flags;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::status::set_last_error;
use xbox360::time::Timebase;
use xbox360::time::sleep;
use xbox360_sys::export_raw;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;
use xbox360_sys::processor::Msr;
use xbox360_sys::status::NtStatus;
use xbox360_sys::status::Severity;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::AllocationType;
use xbox360_sys::xboxkrnl::Context;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::ExceptionRecord;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::KernelU32;
use xbox360_sys::xboxkrnl::KtrapFrame;
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

use super::COMMIT_RESERVE_LARGE;
use super::load_pair;
use super::module_snapshot;
use super::store_pair;
use crate::backend::Console;
use crate::backend::dispatcher;
use crate::backend::filesystem;
use crate::exports::bridged;
use crate::exports::export;
use crate::kernel;
use crate::kernel::RoutineVariable;
use crate::net::XamNetwork;

const BUFFER_COUNT: usize = 5;
const DEFAULT_SIZE_LIMIT: u32 = 0x40_0000;
const MINIMUM_SIZE_LIMIT: u32 = 0x10_0000;
/// A queued buffer leaves room for one record.
const RECORD_RESERVE: u32 = 8;
/// The last hardware thread.
const DEFAULT_WRITER_PROCESSOR: u32 = HARDWARE_THREAD_COUNT as u32 - 1;
const FILE_NAME_SIZE: usize = 0x100;

/// A kernel routine the handler runs natively instead of stepping through
/// it (its reservation loop never completes under single-step).
struct SpoofedRoutine {
    ordinal: Ordinal,
    /// The walk of the routine's body follows forward branches.
    follows_forward_branches: bool,
}

const SPOOFED_ROUTINES: [SpoofedRoutine; 5] = [
    // RtlEnterCriticalSection
    SpoofedRoutine {
        ordinal: Ordinal::new(0x125).unwrap(),
        follows_forward_branches: false,
    },
    // KeAcquireSpinLockAtRaisedIrql
    SpoofedRoutine {
        ordinal: Ordinal::new(0x4d).unwrap(),
        follows_forward_branches: false,
    },
    // KfAcquireSpinLock
    SpoofedRoutine {
        ordinal: Ordinal::new(0xb1).unwrap(),
        follows_forward_branches: false,
    },
    // ObReferenceObject
    SpoofedRoutine {
        ordinal: Ordinal::new(0x10f).unwrap(),
        follows_forward_branches: false,
    },
    // ObDereferenceObject
    SpoofedRoutine {
        ordinal: Ordinal::new(0x105).unwrap(),
        follows_forward_branches: true,
    },
];

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
static SPOOF_ENABLED: AtomicBool = AtomicBool::new(true);
static SPOOF_RESOLVED: AtomicBool = AtomicBool::new(false);
static SPOOF_TARGETS: [AtomicU32; SPOOFED_ROUTINES.len()] =
    [const { AtomicU32::new(0) }; SPOOFED_ROUTINES.len()];
static SPOOFED: AtomicU32 = AtomicU32::new(0);

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
/// Handles of every writer thread not known to have ended. Title
/// termination abandons the running writer as stock does; it ends at the
/// next stop, and unload waits for all of them.
static WRITERS: [AtomicU32; WRITER_CAPACITY] = [const { AtomicU32::new(0) }; WRITER_CAPACITY];
const WRITER_CAPACITY: usize = 16;
/// Address of the kernel debug routine variable this engine hooked, and
/// its prior value.
static ROUTINE_SLOT: AtomicU32 = AtomicU32::new(0);
static PREVIOUS_ROUTINE: AtomicU32 = AtomicU32::new(0);
/// Address of the kernel trace hook variable (debug monitor service 6).
static HOOK_SLOT: AtomicU32 = AtomicU32::new(0);
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
/// The session file name, NUL-padded.
static FILE_NAME: [AtomicU8; FILE_NAME_SIZE] = [const { AtomicU8::new(0) }; FILE_NAME_SIZE];

/// Scratch output of a record made while no buffer is free; two encodings
/// of at most eight words each.
static SCRATCH: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];

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

/// The session file name.
fn file_name() -> ([u8; FILE_NAME_SIZE], usize) {
    let mut name = [0u8; FILE_NAME_SIZE];
    for (byte, stored) in name.iter_mut().zip(&FILE_NAME) {
        *byte = stored.load(Ordering::Relaxed);
    }
    let length = name
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(FILE_NAME_SIZE);
    (name, length)
}

fn has_file_name() -> bool {
    FILE_NAME[0].load(Ordering::Relaxed) != 0
}

/// Store the session file name as stock's bounded copy does: at most
/// 0xff bytes and a terminator.
#[inline(never)]
fn set_file_name(name: &[u8]) {
    for (index, stored) in FILE_NAME.iter().enumerate() {
        let byte = match name.get(index) {
            Some(&byte) if index < FILE_NAME_SIZE - 1 => byte,
            _ => 0,
        };
        stored.store(byte, Ordering::Relaxed);
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
    access: AccessMask,
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
            AccessMask::GENERIC_WRITE.union(AccessMask::SYNCHRONIZE),
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
            AccessMask::GENERIC_WRITE.union(AccessMask::SYNCHRONIZE),
            ShareAccess::READ,
            CreateDisposition::Open,
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
        ),
    ) else {
        return false;
    };
    let mut io_status = IoStatusBlock::default();
    let mut information = xboxkrnl::FileNetworkOpenInformation::default();
    // SAFETY: `handle` was opened above; `io_status` and `information` are
    // live and sized as stated.
    let status = unsafe {
        xboxkrnl::NtQueryInformationFile(
            Handle::from_raw(handle),
            &mut io_status,
            (&raw mut information).cast::<u8>(),
            size_of::<xboxkrnl::FileNetworkOpenInformation>() as u32,
            FileInformationClass::NetworkOpen,
        )
    };
    // Stock seeks to the end; when that fails the write goes to the start.
    let offset = match status.result() {
        Err(error) => {
            set_last_error(error);
            0
        }
        Ok(()) => information.end_of_file,
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
    if status == NtStatus::PENDING {
        // SAFETY: `handle` was opened above.
        status = unsafe {
            xboxkrnl::NtWaitForSingleObjectEx(
                Handle::from_raw(handle),
                ProcessorMode::User,
                false,
                core::ptr::null(),
            )
        };
        if status.is_success() {
            status = io_status.status;
        }
    }
    // A warning status, such as a partial write, still reports the bytes
    // written.
    let written = if status.severity() != Severity::Error {
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

/// The traced thread at a trace exception: its trap frame and its code.
struct TracedThread<'a>(&'a KtrapFrame);

impl Thread for TracedThread<'_> {
    unsafe fn instruction(&self, address: u32) -> u32 {
        // SAFETY: the encoder reads the instruction the thread is about to
        // execute and the one after a system call or trap it executed:
        // code of the traced thread, which is mapped.
        unsafe { instruction_at(address) }
    }

    fn gpr(&self, index: u32) -> u32 {
        // Register fields are five bits; the mask keeps the index in
        // bounds without a check.
        self.0.gpr[(index & 0x1f) as usize] as u32
    }

    fn xer(&self) -> u32 {
        self.0.xer
    }
}

/// The encoder's lookup cache in the session allocation.
///
/// # Safety
///
/// `initialize` set CACHE, and the session allocation stays allocated
/// while the result is used.
unsafe fn cache<'a>() -> &'a Cache {
    // SAFETY: `initialize` set CACHE to the cache of the session
    // allocation, which the caller keeps allocated.
    unsafe { &*CACHE.load(Ordering::Relaxed) }
}

/// Record the instruction at `iar` (stock 0x91f66288); false when no
/// buffer was free, which ends the recording. Runs in the traced thread's
/// handler.
fn record(iar: u32, frame: &KtrapFrame) -> bool {
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
        None => kernel::address_of(&SCRATCH),
    };
    // SAFETY: `start` is the free part of the current stream buffer in the
    // session allocation, or the scratch block, which holds two encodings.
    // A buffer keeps only RECORD_RESERVE (8) words free, but a record after
    // a system call or trap is two encodings of up to 16 words: with 8 to
    // 15 words free it runs into the next buffer, which the kernel may be
    // writing to the file for the writer thread, or, past the last buffer,
    // into the start of the cache, as in stock. Both stay in the
    // allocation, and the cache is atomic. The allocation stays while the
    // handler runs, except under a stop or save on another thread, which
    // frees it without synchronizing with the handler, as in stock.
    let mut cursor = unsafe { Cursor::new(start) };
    // SAFETY: as above.
    let cache = unsafe { cache() };
    // SAFETY: `iar` is the traced thread's next instruction at this trace
    // exception. The encoder's skipped address is the word after a system
    // call or trap the thread executed: its return address, in the same code.
    unsafe {
        SESSION
            .encoder
            .record(iar, &TracedThread(frame), cache, &mut cursor)
    };
    // SAFETY: buffer slots hold null or an element of `BUFFERS`.
    let Some(buffer) = (unsafe { CURRENT.load(Ordering::Acquire).as_ref() }) else {
        SESSION.stop_address.store(iar, Ordering::Relaxed);
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
/// recording. Runs in the traced thread's handler.
fn skip_or_record(iar: u32, frame: &KtrapFrame) -> bool {
    let returns = SESSION.skip_returns.load(Ordering::Relaxed);
    let instructions = SESSION.skip_instructions.load(Ordering::Relaxed);
    if returns != 0 && instructions != 0 {
        SESSION
            .skip_instructions
            .store(instructions - 1, Ordering::Relaxed);
        // SAFETY: `iar` is the instruction the traced thread is about to
        // execute, which is mapped code.
        if unsafe { instruction_at(iar) } == xtrace::BLR {
            SESSION.skip_returns.store(returns - 1, Ordering::Relaxed);
        }
        return true;
    }
    record(iar, frame)
}

fn spoofed_routine(iar: u32) -> Option<usize> {
    SPOOF_TARGETS
        .iter()
        .rposition(|target| target.load(Ordering::Relaxed) == iar)
}

/// Call the console routine at `function` with r3 loaded from the 64-bit
/// value at `argument`, and store its 64-bit result. The CPU model of the
/// target has no 64-bit mnemonics, so `ld`/`std` are encoded directly.
///
/// # Safety
///
/// `function` is a console routine that takes one 64-bit argument in r3
/// and may run on the calling thread; `argument` is readable and `result`
/// writable, both 8-byte aligned.
#[unsafe(naked)]
unsafe extern "C" fn call_native(function: u32, argument: *const u64, result: *mut u64) {
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
fn spoof(
    entry: usize,
    frame: &mut KtrapFrame,
    exception: &mut ExceptionRecord,
    context: &mut Context,
) -> u32 {
    /// Distance below the argument of the plausible addresses.
    const STACK_OFFSET: u64 = 0x10;
    /// `bc`: a conditional branch, forward when the sign bit of its
    /// displacement is clear.
    const OPCODE: u32 = 0xfc00_0000;
    const BRANCH_CONDITIONAL: u32 = 0x4000_0000;
    const DISPLACEMENT_SIGN: u32 = 0x8000;
    const DISPLACEMENT: u32 = 0xfffc;
    const INSTRUCTION_SIZE: u32 = 4;

    SPOOFED.fetch_add(1, Ordering::Relaxed);
    let function = SPOOF_TARGETS[entry].load(Ordering::Relaxed);
    let mut result = 0u64;
    // SAFETY: `function` is a resolved kernel routine of SPOOFED_ROUTINES,
    // which takes the r3 of the trapped call; `argument` is that register in
    // the trap frame and `result` a live local.
    unsafe { call_native(function, &frame.gpr[3], &mut result) };
    let saved = *frame;
    let argument = frame.gpr[3];
    frame.gpr[5] = STACK_OFFSET;
    frame.gpr[11] = argument.wrapping_sub(STACK_OFFSET);
    frame.gpr[4] = argument;
    frame.gpr[31] = argument.wrapping_sub(STACK_OFFSET);
    let follow_forward = SPOOFED_ROUTINES[entry].follows_forward_branches;
    let mut address = function;
    loop {
        // SAFETY: `address` walks the body of a resolved kernel routine up
        // to its `blr`, which is mapped kernel code.
        let word = unsafe { instruction_at(address) };
        if word == xtrace::BLR {
            break;
        }
        frame.iar = address;
        exception.address = address;
        record(address, frame);
        let forward_branch = word & OPCODE == BRANCH_CONDITIONAL && word & DISPLACEMENT_SIGN == 0;
        address = address.wrapping_add(if follow_forward && forward_branch {
            word & DISPLACEMENT
        } else {
            INSTRUCTION_SIZE
        });
    }
    *frame = saved;
    context.iar = address;
    context.gpr[3] = result;
    exception.address = address;
    address
}

fn stop_entry_address() -> u32 {
    stop_entry as *const () as usize as u32
}

/// Kernel trace hook (stock 0x91f66ab0): handles trace exceptions before
/// the debug routine. Spoofed routines are left to the debug routine.
extern "C" fn trace_hook(trap_frame: u32, record_address: u32) -> u32 {
    // SAFETY: the kernel passes the exception record of the current
    // exception of this thread, which it does not change during the call.
    let exception = unsafe { crate::kernel::object_at::<ExceptionRecord>(record_address) };
    if exception.code != NtStatus::SINGLE_STEP {
        return 0;
    }
    // SAFETY: the kernel passes the trap frame of the current exception of
    // this thread; nothing else uses it during the call.
    let frame = unsafe { crate::kernel::object_at_mut::<KtrapFrame>(trap_frame) };
    if ARMED.load(Ordering::Acquire) && !FAILED.load(Ordering::Acquire) {
        let iar = exception.address;
        let mut stop = iar == stop_entry_address() || STOP_REQUESTED.load(Ordering::Acquire);
        if SPOOF_ENABLED.load(Ordering::Relaxed) {
            let mut spoofed = spoofed_routine(iar).is_some();
            // The spin lock routines do not run natively on a console with
            // this flag.
            if hardware_flags().contains(HardwareFlags::TEST_KIT) {
                spoofed = false;
                SPOOF_ENABLED.store(false, Ordering::Relaxed);
            }
            if spoofed {
                return 0;
            }
        }
        if !stop {
            stop = !skip_or_record(iar, frame);
        }
        if !(ARMED.load(Ordering::Acquire) && stop) {
            return 1;
        }
    } else if !ARMED.load(Ordering::Acquire) {
        return 1;
    }
    frame.msr.remove(Msr::SINGLE_STEP);
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
    // SAFETY: the kernel passes the exception record of the current
    // exception of this thread. The reference is not used after the
    // exception is passed on.
    let exception = unsafe { crate::kernel::object_at::<ExceptionRecord>(record_address) };
    if exception.code != NtStatus::SINGLE_STEP {
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
    // SAFETY: the kernel passes the trap frame, the exception record, and
    // the 16-byte aligned context of the current exception of this thread;
    // nothing else uses them during the call.
    let (frame, exception, context) = unsafe {
        (
            crate::kernel::object_at_mut::<KtrapFrame>(trap_frame),
            crate::kernel::object_at_mut::<ExceptionRecord>(record_address),
            crate::kernel::object_at_mut::<Context>(context_address),
        )
    };
    if ARMED.load(Ordering::Acquire) && !FAILED.load(Ordering::Acquire) {
        let mut iar = exception.address;
        let mut stop = iar == stop_entry_address() || STOP_REQUESTED.load(Ordering::Acquire);
        if SPOOF_ENABLED.load(Ordering::Relaxed)
            && let Some(entry) = spoofed_routine(iar)
        {
            iar = spoof(entry, frame, exception, context);
        }
        if !stop {
            stop = !skip_or_record(iar, frame);
        }
        if !(ARMED.load(Ordering::Acquire) && stop) {
            return 1;
        }
    } else if !ARMED.load(Ordering::Acquire) {
        return 1;
    }
    context.msr.remove(Msr::SINGLE_STEP);
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
    for (target, routine) in SPOOF_TARGETS.iter().zip(&SPOOFED_ROUTINES) {
        if let Ok(address) = resolve_export(module, routine.ordinal) {
            target.store(address.raw(), Ordering::Relaxed);
        }
    }
}

/// Install the hooks (stock 0x91f66e88).
fn hook() {
    const TITLE_TERMINATE_PRIORITY: u32 = 0x6f00_0000;

    if BASE.load(Ordering::Acquire) == 0 {
        return;
    }
    // Stock registers at every start; a session saved by export 137
    // without a stop keeps the registration, and registering it again
    // would corrupt the kernel's list.
    if !TERMINATE_REGISTERED.swap(true, Ordering::AcqRel) {
        // SAFETY: the record is not registered, so the kernel does not use
        // it while it is written. The routine stays loaded until `unhook`
        // or `shut_down` removes the record.
        unsafe {
            TITLE_TERMINATE.routine.store(
                title_terminated_entry as *const () as usize as u32,
                Ordering::Relaxed,
            );
            TITLE_TERMINATE
                .priority
                .store(TITLE_TERMINATE_PRIORITY, Ordering::Relaxed);
            TITLE_TERMINATE.link.flink.store(0, Ordering::Relaxed);
            TITLE_TERMINATE.link.blink.store(0, Ordering::Relaxed);
            xboxkrnl::ExRegisterTitleTerminateNotification(TITLE_TERMINATE.as_ptr(), true)
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
    if status.is_success() {
        HOOK_SLOT.store(hook_slot[0], Ordering::Release);
        // SAFETY: the service replies with the address of the kernel's
        // trace hook variable, kernel data that stays mapped.
        let slot = unsafe { kernel::object_at::<KernelU32>(hook_slot[0]) };
        // SAFETY: `trace_hook_entry` follows the kernel's trace hook
        // convention and stays loaded until `unhook` clears the variable.
        unsafe {
            slot.store(
                trace_hook_entry as *const () as usize as u32,
                Ordering::Relaxed,
            )
        };
    }
    // SAFETY: the monitor registered before any trace starts, so the query
    // service published the address of `KiDebugRoutine`; stock uses it
    // without a check.
    let slot = unsafe { kernel::routine_variable(RoutineVariable::Debug).unwrap_unchecked() };
    ROUTINE_SLOT.store(kernel::address_of(slot), Ordering::Release);
    let routine = debug_routine_entry as *const () as usize as u32;
    let previous = slot.load(Ordering::Relaxed);
    if previous == routine {
        // Stock asserts and then chains the routine to itself, which
        // recurses on the next exception; the chain is kept instead.
        break_trap();
    } else {
        PREVIOUS_ROUTINE.store(previous, Ordering::Release);
    }
    // SAFETY: `debug_routine_entry` follows the kernel's debug routine
    // convention and stays loaded until `unhook` restores the previous
    // routine.
    unsafe { slot.store(routine, Ordering::Relaxed) };
}

/// Remove the debug routine and the trace hook.
fn unhook() {
    let slot = ROUTINE_SLOT.swap(0, Ordering::AcqRel);
    if slot != 0 {
        // SAFETY: `hook` stored the address of the kernel's debug routine
        // variable, which stays mapped.
        let slot = unsafe { kernel::object_at::<KernelU32>(slot) };
        // SAFETY: restores the routine the kernel called before `hook`.
        unsafe { slot.store(PREVIOUS_ROUTINE.load(Ordering::Acquire), Ordering::Relaxed) };
        // SAFETY: TITLE_TERMINATE is the static registration added by `hook`.
        unsafe { xboxkrnl::ExRegisterTitleTerminateNotification(TITLE_TERMINATE.as_ptr(), false) };
        TERMINATE_REGISTERED.store(false, Ordering::Release);
    }
    let hook_slot = HOOK_SLOT.load(Ordering::Acquire);
    if hook_slot != 0 {
        // SAFETY: `hook` stored the address of the kernel's trace hook
        // variable, which stays mapped.
        let hook_slot = unsafe { kernel::object_at::<KernelU32>(hook_slot) };
        // SAFETY: a zero variable removes the hook.
        unsafe { hook_slot.store(0, Ordering::Relaxed) };
    }
}

/// Write the queued buffers to the file in sequence order (stock
/// 0x91f65e50) and print the progress.
fn flush() {
    const PROGRESS_INTERVAL: i64 = 100_000;
    /// Progress interval when the kernel has the fast trace hook.
    const FAST_PROGRESS_INTERVAL: i64 = 500_000;

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
        // Entries past `count` are null.
        for (position, slot) in collected.iter_mut().enumerate() {
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
        let total = SESSION.encoder.total() as i64;
        let recorded = SESSION.encoder.recorded() as i64;
        if load_pair(&PROGRESS_MARK) as i64 + interval > total {
            break;
        }
        print(
            c"Tracing: %I64d K instructions recorded of %I64d K.\r\n",
            &[
                (recorded / interval * interval / 1000) as u64,
                (total / interval * interval / 1000) as u64,
            ],
        );
        store_pair(
            &PROGRESS_MARK,
            (load_pair(&PROGRESS_MARK) as i64 + interval) as u64,
        );
    }
}

/// Writer thread (stock 0x91f660f0).
extern "C" fn writer(_context: u32) -> u32 {
    const INTERVAL: Duration = Duration::from_millis(10);

    while WRITER_RUNNING.load(Ordering::Acquire) {
        sleep(INTERVAL);
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
        if wait == NtStatus::WAIT_0 {
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
