//! Session services: the debug capture ring, server thread affinity, remote
//! calls, the `dmtelllog` log, file I/O events, and notification
//! texts posted by other threads.
//!
//! Monitor control codes reach the services here on arbitrary threads, so
//! the state they share with the commands is static and lock-protected.

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_server::Server;
use openxbdm_server::commands;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::session::DEBUG_CAPTURE_SIZE;
use openxbdm_server::commands::session::FastPipeBackend;
use openxbdm_server::commands::session::FileEventId;
use openxbdm_server::commands::session::LogEngineError;
use openxbdm_server::commands::session::ProcessorNumber;
use openxbdm_server::commands::session::RpcBackend;
use openxbdm_server::commands::session::RpcCall;
use openxbdm_server::commands::session::RpcContext;
use openxbdm_server::commands::session::RpcCreateError;
use openxbdm_server::commands::session::RpcThread;
use openxbdm_server::commands::session::TELL_LOG_LINE_LIMIT;
use openxbdm_server::commands::session::TellLogAreas;
use openxbdm_server::commands::session::TellLogBackend;
use openxbdm_server::commands::session::TellLogConfig;
use openxbdm_server::commands::session::TellLogCounters;
use openxbdm_server::commands::session::TellLogWriter;
use openxbdm_server::commands::session::WaitTrace;
use openxbdm_server::commands::session::WaitTraceLine;
use openxbdm_server::commands::session::format_wait_trace;
use openxbdm_server::notify::POSTED_TEXT_CAPACITY;
use openxbdm_server::notify::PostedTexts;
use xbox360::sync::SpinLock;
use xbox360_sys::processor;
use xbox360_sys::processor::current_thread;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::ExRegisterTitleTerminateNotification;
use xbox360_sys::xboxkrnl::FscGetCacheElementCount;
use xbox360_sys::xboxkrnl::FscSetCacheElementCount;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeResumeThread;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::RtlImageXexHeaderField;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;
use xbox360_sys::xboxkrnl::XexExecutableModuleHandle;

use super::Console;
use super::dispatcher;
use crate::net::XamNetwork;

mod file_events;
mod log_engine;
mod notifications;
mod processors;
mod swap;

pub(crate) use file_events::service_file_event_begin;
pub(crate) use file_events::service_file_event_end;

use log_engine::Engine;
use notifications::send_notification;
use notifications::unlink_title_notification_sessions;
pub(crate) use processors::poll_processor_calls;
pub(crate) use processors::release_processor_threads;
pub(crate) use processors::service_register_pix_processor;
pub(crate) use processors::service_register_processor;
pub(crate) use swap::register_swap_routine;
pub(crate) use swap::remove_unflagged_swap_routines;
pub(crate) use swap::unregister_swap_routine;

use core::time::Duration;

use xbox360::time::TickCount;
use xbox360::time::Timebase;
use xbox360::time::sleep;

use crate::kernel::CriticalSection;

/// Pool tag of the debug capture ring.
const DEBUG_CAPTURE_TAG: PoolTag = PoolTag::new(*b"mdbX");
/// Pool type the monitor allocates the ring from.
const DEBUG_CAPTURE_POOL: PoolType = PoolType::System;
/// Pseudo handle of the calling thread.
const CURRENT_THREAD: u32 = 0xffff_fffe;
/// File system cache the pipe engine resizes.
const PIPE_CACHE: u32 = 2;
/// `ExCreateThread` flags: create suspended, return the thread object.
const THREAD_SUSPENDED: u32 = 0x1;
const THREAD_OBJECT: u32 = 0x80;
/// Create the thread in the system process [INFERENCE: stock sets it for
/// `rpc system` and for a log started outside the title process].
const THREAD_SYSTEM_PROCESS: u32 = 0x2;
const STATUS_SUCCESS: u32 = 0;
/// `KeGetCurrentProcessType` of the title process.
const TITLE_PROCESS: u32 = 1;

/// Processor control region fields.
const PCR_STACK_BASE: u32 = 0x70;
const PCR_STACK_LIMIT: u32 = 0x74;
const PCR_CURRENT_PROCESSOR: u32 = 0x10c;
const PCR_LAST_ERROR_OVERRIDE: u32 = 0x150;
const PCR_WAIT_STATISTICS: u32 = 0x2d0;
/// Thread fields.
const THREAD_ID: u32 = 0x14c;
const THREAD_PROCESSOR: u32 = 0xbf;
const THREAD_LAST_ERROR: u32 = 0x160;
const THREAD_PROCESS_TYPE: u32 = 0x72;

/// Platform state of this domain owned by the server thread.
pub struct Data {
    /// Address of the debug capture ring.
    debug_capture: Option<u32>,
    processors: processors::Data,
}

impl Data {
    pub const fn new() -> Self {
        Self {
            debug_capture: None,
            processors: processors::Data::new(),
        }
    }
}

fn pcr_word(offset: u32) -> u32 {
    // SAFETY: the processor control region is always mapped.
    unsafe { core::ptr::read_volatile((processor::pcr() + offset) as usize as *const u32) }
}

fn pcr_byte(offset: u32) -> u8 {
    // SAFETY: the processor control region is always mapped.
    unsafe { core::ptr::read_volatile((processor::pcr() + offset) as usize as *const u8) }
}

fn passive() -> bool {
    processor::current_irql() == Irql::PASSIVE
}

fn read_u32(address: u32) -> u32 {
    // SAFETY: callers pass addresses of kernel or caller structures.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn read_u8(address: u32) -> u8 {
    // SAFETY: callers pass addresses of kernel or caller structures.
    unsafe { core::ptr::read_volatile(address as usize as *const u8) }
}

fn read_u64(address: u32) -> u64 {
    // SAFETY: callers pass addresses of kernel or caller structures.
    unsafe { core::ptr::read_unaligned(address as usize as *const u64) }
}

fn write_u32(address: u32, value: u32) {
    // SAFETY: callers pass addresses of structures they own.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

fn write_u64(address: u32, value: u64) {
    // SAFETY: callers pass addresses of structures they own.
    unsafe { core::ptr::write_unaligned(address as usize as *mut u64, value) }
}

/// Bytes of a NUL-terminated string, read for at most `limit` bytes.
fn c_string<'a>(address: u32, limit: usize) -> &'a [u8] {
    let mut length = 0;
    while length < limit && read_u8(address + length as u32) != 0 {
        length += 1;
    }
    // SAFETY: the bytes were just read.
    unsafe { core::slice::from_raw_parts(address as usize as *const u8, length) }
}

/// Title-terminate notification registration: routine, priority, links.
struct Registration(UnsafeCell<[u32; 4]>);

// SAFETY: written once by `initialize` before the kernel reads it.
unsafe impl Sync for Registration {}

static TITLE_TERMINATE: Registration = Registration(UnsafeCell::new([0; 4]));

/// Prepare the shared state; called once at module start, before the
/// control dispatcher is published.
pub(crate) fn initialize() {
    RPC_QUEUE_LOCK.initialize();
    processors::initialize();
    // Priority byte 0x78 as stock's registration (0x91f97434).
    // SAFETY: the registration is written once, before the kernel uses it.
    unsafe {
        *TITLE_TERMINATE.0.get() = [
            title_terminated_entry as *const () as usize as u32,
            0x7800_0000,
            0,
            0,
        ]
    };
    // SAFETY: TITLE_TERMINATE is static and holds the registration record.
    unsafe { ExRegisterTitleTerminateNotification(TITLE_TERMINATE.0.get().cast(), true) };
}

/// Undo the registration of [`initialize`] before the image unloads.
pub(crate) fn uninstall() {
    // SAFETY: written once by `initialize`; nonzero once registered.
    if unsafe { (*TITLE_TERMINATE.0.get())[0] } != 0 {
        // SAFETY: the static record registered by `initialize`.
        unsafe { ExRegisterTitleTerminateNotification(TITLE_TERMINATE.0.get().cast(), false) };
    }
}

// The kernel calls the routine with the console ABI.
crate::exports::bridged!(title_terminated_entry, title_terminated);

/// The server could not run its part of a title termination at once; it
/// runs it at its next pass.
static TITLE_TERMINATED: AtomicBool = AtomicBool::new(false);

/// Title termination (stock 0x91f32398): the server releases processors,
/// connections, and network state the title owned; the title's
/// notification sessions, frame counters, and file events go.
extern "C" fn title_terminated() {
    super::image_device::dismount_all();
    if dispatcher::call_on_server(release_title, 0).is_none() {
        TITLE_TERMINATED.store(true, Ordering::Release);
    }
    unlink_title_notification_sessions();
    super::performance::title_terminated();
    file_events::suppress_title(current_title_id());
    super::hardware::pgo::title_terminated();
}

fn release_title(
    server: &mut Server,
    console: &mut Console,
    network: &mut XamNetwork,
    _argument: u32,
) -> u32 {
    server.title_terminated(console, network);
    0
}

/// Whether a title terminated since the last call.
pub(crate) fn take_title_terminated() -> bool {
    TITLE_TERMINATED.swap(false, Ordering::AcqRel)
}

/// Title identifier of the running executable (stock 0x91f335c0).
fn current_title_id() -> u32 {
    let module = read_u32(XexExecutableModuleHandle.address());
    if module == 0 {
        return 0;
    }
    // SAFETY: +0x58 of a loaded module holds its XEX header address.
    match unsafe { RtlImageXexHeaderField(read_u32(module + 0x58), 0x40006) } {
        0 => 0,
        field => read_u32(field + 0xc),
    }
}

impl commands::session::Backend for Console {
    fn allocate_debug_capture(&mut self) -> bool {
        // SAFETY: the allocation takes only a size, tag and pool type.
        match unsafe {
            xboxkrnl::ExAllocatePoolTypeWithTag(
                DEBUG_CAPTURE_SIZE as u32,
                DEBUG_CAPTURE_TAG,
                DEBUG_CAPTURE_POOL,
            )
        } {
            0 => false,
            address => {
                self.session.debug_capture = Some(address);
                true
            }
        }
    }

    fn free_debug_capture(&mut self) {
        if let Some(address) = self.session.debug_capture.take() {
            // SAFETY: `address` is the ring allocated by `allocate_debug_capture`.
            unsafe { xboxkrnl::ExFreePool(address) };
        }
    }

    fn debug_capture(&mut self) -> Option<&mut [u8; DEBUG_CAPTURE_SIZE]> {
        let address = self.session.debug_capture?;
        // SAFETY: the pool block is DEBUG_CAPTURE_SIZE bytes, owned by this
        // backend until freed, and borrowed through `&mut self`.
        Some(unsafe { &mut *(address as usize as *mut [u8; DEBUG_CAPTURE_SIZE]) })
    }

    fn current_processor(&mut self) -> ProcessorNumber {
        ProcessorNumber(pcr_byte(PCR_CURRENT_PROCESSOR))
    }

    fn set_server_processor(&mut self, processor: ProcessorNumber) {
        let mut thread = 0u32;
        let object_type = xboxkrnl::ExThreadObjectType.address();
        // SAFETY: `thread` is a local word; the pseudo handle names the
        // calling thread.
        if (unsafe {
            xboxkrnl::ObReferenceObjectByHandle(
                Handle::from_raw(CURRENT_THREAD),
                object_type,
                &mut thread,
            )
        }
        .0 as i32)
            >= 0
        {
            let mut previous = 0u32;
            // SAFETY: `thread` is the referenced object of the calling
            // thread, released after use.
            unsafe {
                xboxkrnl::KeSetAffinityThread(
                    thread as usize as *mut xboxkrnl::Kthread,
                    1 << processor.0,
                    &mut previous,
                );
                xboxkrnl::ObDereferenceObject(thread);
            }
        }
    }

    fn flush_file(&mut self, handle: FileHandle) -> Result<(), KernelError> {
        let mut io_status = IoStatusBlock::default();
        // SAFETY: `io_status` is a live local.
        unsafe { xboxkrnl::NtFlushBuffersFile(Handle::from_raw(handle.0), &mut io_status) }.result()
    }

    fn switch_file_events(&mut self, enable: bool) -> FileEventId {
        file_events::switch(enable)
    }

    fn next_posted_notification(&mut self, text: &mut [u8; POSTED_TEXT_CAPACITY]) -> Option<usize> {
        POSTED.lock().pop(text)
    }

    fn notify_sessions(&mut self, event: &openxbdm_server::notify::Event<'_>) {
        notifications::notify_event(event);
    }
}

impl FastPipeBackend for Console {
    fn file_cache_elements(&mut self) -> u32 {
        // SAFETY: the query takes only a cache number.
        unsafe { FscGetCacheElementCount(PIPE_CACHE) }
    }

    fn set_file_cache_elements(&mut self, count: u32) {
        // SAFETY: the call takes only a cache number and count.
        unsafe { FscSetCacheElementCount(PIPE_CACHE, count) };
    }
}

/// Notification texts queued for the server thread.
static POSTED: SpinLock<PostedTexts> = SpinLock::new(PostedTexts::new());

/// Send a notification text to every notification channel. The server
/// thread sends it on its next pass; a text longer than a queue slot, or
/// one that finds the queue full, is sent by the server thread while the
/// caller waits. The server thread itself and the log worker (which the
/// server may be waiting for) cannot wait and lose such a text. Returns
/// whether the text was queued or sent.
pub(crate) fn post_notification(text: &[u8]) -> bool {
    if POSTED.lock().push(text) {
        return true;
    }
    let worker = TELL_LOG.worker.load(Ordering::Acquire);
    if worker != 0 && worker == read_u32(current_thread() + THREAD_ID) {
        return false;
    }
    let request = WaitingText {
        address: text.as_ptr() as usize as u32,
        length: text.len() as u32,
    };
    dispatcher::call_on_server(
        send_waiting_text,
        &request as *const WaitingText as usize as u32,
    )
    .is_some()
}

/// A text whose poster waits for the server thread to send it.
struct WaitingText {
    address: u32,
    length: u32,
}

/// Server-thread part of [`post_notification`]; queued texts go first.
fn send_waiting_text(
    server: &mut Server,
    console: &mut Console,
    network: &mut XamNetwork,
    argument: u32,
) -> u32 {
    server.drain_posted_notifications(console, network);
    // SAFETY: the poster waits in `call_on_server` while the request and
    // its text are alive.
    let text = unsafe {
        let request = &*(argument as usize as *const WaitingText);
        core::slice::from_raw_parts(
            request.address as usize as *const u8,
            request.length as usize,
        )
    };
    server.state.notifications.send_text(text, network);
    0
}

/// Monitor control code 0xa9 (stock case 0x91f3bb08): export 36 with the
/// caller's text; the result is dropped.
pub(crate) fn service_send_notification(text: u32) -> u32 {
    send_notification(text);
    0
}

/// Call block (stock 0x91f3e7c8, pool tag `drpc`): +0x00 queue link,
/// +0x04 abort flag, +0x08 system flag, +0x0c thread object, +0x10 buffer
/// size, +0x18 marker quadword, +0x20 thread name, +0x60 done flag, +0x64
/// release state, +0x68 the call buffer.
const CALL_TAG: PoolTag = PoolTag::new(*b"drpc");
const CALL_LINK: u32 = 0x00;
const CALL_ABORT: u32 = 0x04;
const CALL_SYSTEM: u32 = 0x08;
const CALL_THREAD: u32 = 0x0c;
const CALL_SIZE: u32 = 0x10;
const CALL_MARKER: u32 = 0x18;
const CALL_NAME: u32 = 0x20;
const CALL_NAME_CAPACITY: usize = 0x40;
const CALL_DONE: u32 = 0x60;
const CALL_RELEASE: u32 = 0x64;
const CALL_BUFFER: u32 = 0x68;
/// Release states: the runner finished, or the stream released the block.
const RUNNER_FINISHED: u32 = 1;
const STREAM_RELEASED: u32 = 2;
/// Call buffer fields.
const BUFFER_RESULT: u32 = 0x00;
const BUFFER_RETURN: u32 = 0x08;
const BUFFER_LAST_ERROR: u32 = 0x10;
const BUFFER_FLAGS: u32 = 0x18;
const BUFFER_INTEGERS: u32 = 0x20;
const BUFFER_DOUBLES: u32 = 0x28;
const BUFFER_MODULE: u32 = 0x30;
const BUFFER_TARGET: u32 = 0x38;
const BUFFER_ARGUMENTS: u32 = 0x40;
const MODULE_NOT_FOUND: u64 = 0xffff_ffff_8007_007e;
const PROCEDURE_NOT_FOUND: u64 = 0xffff_ffff_8007_007f;
/// Register slots: eight integers, then eight doubles.
const ARGUMENT_SLOTS: usize = 16;
/// Relative wait of the stream for an own-thread call: 100 ms.
const CALL_WAIT: i64 = -1_000_000;
const CALL_WAIT_MS: u32 = 100;
const CALL_POLL_MS: u32 = 10;

/// Head of the named-call queue (stock 0x91f9fda8), newest first.
static RPC_QUEUE: AtomicU32 = AtomicU32::new(0);
/// Lock of the named-call queue (stock 0x91f9766c).
static RPC_QUEUE_LOCK: CriticalSection = CriticalSection::new();

fn call_atomic(block: u32, offset: u32) -> &'static AtomicU32 {
    // SAFETY: the field is an aligned word of a live call block.
    unsafe { &*((block + offset) as usize as *const AtomicU32) }
}

fn push_call(block: u32) {
    RPC_QUEUE_LOCK.enter();
    write_u32(block + CALL_LINK, RPC_QUEUE.load(Ordering::Relaxed));
    RPC_QUEUE.store(block, Ordering::Relaxed);
    RPC_QUEUE_LOCK.leave();
}

/// Remove `block` from the queue; returns whether it was queued.
fn unlink_call(block: u32) -> bool {
    RPC_QUEUE_LOCK.enter();
    // The word that links the current call: the head, then a call's link.
    let mut link = &RPC_QUEUE;
    let mut found = false;
    loop {
        let current = link.load(Ordering::Relaxed);
        if current == 0 {
            break;
        }
        if current == block {
            link.store(read_u32(current + CALL_LINK), Ordering::Relaxed);
            found = true;
            break;
        }
        link = call_atomic(current, CALL_LINK);
    }
    RPC_QUEUE_LOCK.leave();
    found
}

/// Take the newest call queued for `name` (stock 0x91f3e208). A busy lock
/// reads as an empty queue.
fn take_call(name: &[u8]) -> Option<u32> {
    if !RPC_QUEUE_LOCK.try_enter() {
        return None;
    }
    let mut link = &RPC_QUEUE;
    let mut taken = None;
    loop {
        let current = link.load(Ordering::Relaxed);
        if current == 0 {
            break;
        }
        if c_string(current + CALL_NAME, CALL_NAME_CAPACITY) == name {
            link.store(read_u32(current + CALL_LINK), Ordering::Relaxed);
            write_u32(current + CALL_LINK, 0);
            taken = Some(current);
            break;
        }
        link = call_atomic(current, CALL_LINK);
    }
    RPC_QUEUE_LOCK.leave();
    taken
}

/// Monitor control code 0xa8 (export 372, stock 0x91f3ea50): run every
/// call queued for the calling thread's name, newest first.
pub(crate) fn service_rpc_drain(name: u32) -> u32 {
    if name == 0 {
        return 0;
    }
    let name = c_string(name, usize::MAX);
    while let Some(block) = take_call(name) {
        run_call(block);
    }
    0
}

/// Own-thread call start routine.
extern "C" fn call_thread(block: u32) -> u32 {
    if call_atomic(block, CALL_ABORT).load(Ordering::Acquire) != 0 {
        // SAFETY: an aborted block is owned by this thread and freed once.
        unsafe { xboxkrnl::ExFreePool(block) };
    } else {
        run_call(block);
    }
    // SAFETY: this thread was created for the call and holds no resources.
    unsafe { xboxkrnl::ExTerminateThread(0) }
}

/// Make the call described by the block's buffer (stock 0x91f3e630).
fn run_call(block: u32) {
    let buffer = block + CALL_BUFFER;
    let mut target = read_u64(buffer + BUFFER_TARGET) as u32;
    let module = read_u64(buffer + BUFFER_MODULE);
    let failure = if module != 0 {
        let mut handle = 0u32;
        // SAFETY: the client supplied the module name address; `handle` and
        // `target` are live locals.
        unsafe {
            if (xboxkrnl::XexGetModuleHandle(module as u32 as usize as *const u8, &mut handle).0
                as i32)
                < 0
            {
                Some(MODULE_NOT_FOUND)
            } else if (xboxkrnl::XexGetProcedureAddress(handle, target, &mut target).0 as i32) < 0 {
                Some(PROCEDURE_NOT_FOUND)
            } else {
                None
            }
        }
    } else {
        None
    };
    if let Some(failure) = failure {
        // Failures store the result before the done flag.
        write_u64(buffer + BUFFER_RESULT, failure);
        call_atomic(block, CALL_DONE).store(1, Ordering::Release);
        release_runner(block);
        return;
    }
    // The monitor copies the integers to slot 0 and the doubles to slot 8
    // of two adjacent eight-slot arrays without bounds; the copies are
    // limited to the arrays here.
    let mut slots = [0u64; ARGUMENT_SLOTS];
    let integers = (read_u64(buffer + BUFFER_INTEGERS) as u32 as usize).min(ARGUMENT_SLOTS);
    let doubles = (read_u64(buffer + BUFFER_DOUBLES) as u32 as usize).min(ARGUMENT_SLOTS / 2);
    for (index, slot) in slots.iter_mut().take(integers).enumerate() {
        *slot = read_u64(buffer + BUFFER_ARGUMENTS + 8 * index as u32);
    }
    let double_base = buffer + BUFFER_ARGUMENTS + 8 * integers as u32;
    for index in 0..doubles {
        slots[ARGUMENT_SLOTS / 2 + index] = read_u64(double_base + 8 * index as u32);
    }
    let mut registers = [0u64; 2];
    // SAFETY: the client supplied the target and its arguments; the call is
    // the purpose of the command.
    unsafe { invoke(target, slots.as_ptr(), registers.as_mut_ptr()) };
    let value = if read_u64(buffer + BUFFER_FLAGS) & 1 != 0 {
        registers[1]
    } else {
        registers[0]
    };
    write_u64(buffer + BUFFER_RETURN, value);
    if read_u64(buffer + BUFFER_LAST_ERROR) == 1 {
        write_u64(buffer + BUFFER_LAST_ERROR, u64::from(last_error()));
    }
    // The done flag is set before the success result is stored.
    call_atomic(block, CALL_DONE).store(1, Ordering::Release);
    write_u64(buffer + BUFFER_RESULT, 0);
    release_runner(block);
}

/// The runner is done with the block; free it when the stream already
/// released it.
fn release_runner(block: u32) {
    if call_atomic(block, CALL_RELEASE).swap(RUNNER_FINISHED, Ordering::AcqRel) == STREAM_RELEASED {
        // SAFETY: both owners released the block; this is the last use.
        unsafe { xboxkrnl::ExFreePool(block) };
    }
}

/// `GetLastError` of the calling thread (stock 0x91f72ba0).
fn last_error() -> u32 {
    if pcr_word(PCR_LAST_ERROR_OVERRIDE) != 0 {
        0
    } else {
        read_u32(current_thread() + THREAD_LAST_ERROR)
    }
}

/// Load r3..r10 from `slots[0..8]` and f1..f8 from `slots[8..16]`, call
/// `target` with a console frame, and store r3 (all 64 bits) and f1 in
/// `registers`.
#[unsafe(naked)]
unsafe extern "C" fn invoke(target: u32, slots: *const u64, registers: *mut u64) {
    core::arch::naked_asm!(
        "stwu 1, -0x80(1)",
        "mflr 0",
        "stw 0, 0x84(1)",
        "stw 31, 0x7c(1)",
        "mr 31, 5",
        "mtctr 3",
        "mr 11, 4",
        "lfd 1, 0x40(11)",
        "lfd 2, 0x48(11)",
        "lfd 3, 0x50(11)",
        "lfd 4, 0x58(11)",
        "lfd 5, 0x60(11)",
        "lfd 6, 0x68(11)",
        "lfd 7, 0x70(11)",
        "lfd 8, 0x78(11)",
        // ld 3..10, 0..0x38(11): the target CPU model has no 64-bit
        // mnemonics.
        ".long 0xe86b0000",
        ".long 0xe88b0008",
        ".long 0xe8ab0010",
        ".long 0xe8cb0018",
        ".long 0xe8eb0020",
        ".long 0xe90b0028",
        ".long 0xe92b0030",
        ".long 0xe94b0038",
        "bctrl",
        // std 3, 0(31)
        ".long 0xf87f0000",
        "stfd 1, 8(31)",
        "lwz 31, 0x7c(1)",
        "lwz 0, 0x84(1)",
        "mtlr 0",
        "addi 1, 1, 0x80",
        "blr",
    )
}

impl RpcBackend for Console {
    fn rpc_create(
        &mut self,
        size: u32,
        context: RpcContext,
        thread: RpcThread<'_>,
    ) -> Result<RpcCall, RpcCreateError> {
        // SAFETY: the allocation takes only a size and tag.
        let block =
            unsafe { xboxkrnl::ExAllocatePoolWithTag(size.wrapping_add(CALL_BUFFER), CALL_TAG) };
        if block == 0 {
            return Err(RpcCreateError::OutOfMemory);
        }
        let system = context == RpcContext::System;
        write_u32(block + CALL_LINK, 0);
        write_u32(block + CALL_ABORT, 0);
        write_u32(block + CALL_THREAD, 0);
        write_u32(block + CALL_DONE, 0);
        write_u32(block + CALL_RELEASE, 0);
        write_u32(block + CALL_SYSTEM, u32::from(system));
        write_u32(block + CALL_SIZE, size);
        write_u64(block + CALL_MARKER, 0x3e5);
        let name = match thread {
            RpcThread::Named(name) => &name[..name.len().min(CALL_NAME_CAPACITY - 1)],
            RpcThread::Own { .. } => &[],
        };
        // SAFETY: the name field holds CALL_NAME_CAPACITY bytes.
        unsafe {
            let field = (block + CALL_NAME) as usize as *mut u8;
            core::ptr::copy_nonoverlapping(name.as_ptr(), field, name.len());
            field.add(name.len()).write(0);
        }
        if let RpcThread::Own { processor } = thread {
            // Only the low six bits of the processor reach the shift.
            let processor = processor & 0x3f;
            let affinity = if processor < 32 {
                (1u32 << processor) << 24
            } else {
                0
            };
            let flags = if system { THREAD_SYSTEM_PROCESS } else { 0 }
                | affinity
                | THREAD_OBJECT
                | THREAD_SUSPENDED;
            let flags = ThreadCreationFlags::from_bits_retain(flags);
            let mut object = 0u32;
            // SAFETY: `object` is a local word; `call_thread` takes the block
            // as its context.
            let status = unsafe {
                xboxkrnl::ExCreateThread(
                    &mut object,
                    0,
                    core::ptr::null_mut(),
                    0,
                    call_thread as *const () as usize as u32,
                    block,
                    flags,
                )
            };
            if let Err(error) = status.result() {
                // SAFETY: the block was allocated above and no thread owns it.
                unsafe { xboxkrnl::ExFreePool(block) };
                return Err(RpcCreateError::Thread(error));
            }
            write_u32(block + CALL_THREAD, object);
        }
        Ok(RpcCall(block))
    }

    fn rpc_buffer_address(&mut self, call: RpcCall) -> u32 {
        call.0 + CALL_BUFFER
    }

    fn rpc_write(&mut self, call: RpcCall, offset: u32, data: &[u8]) {
        let destination = (call.0 + CALL_BUFFER + offset) as usize as *mut u8;
        // SAFETY: the upload never exceeds the buffer size it was sized for.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), destination, data.len()) };
    }

    fn rpc_start(&mut self, call: RpcCall) {
        match read_u32(call.0 + CALL_THREAD) {
            0 => push_call(call.0),
            thread => {
                // SAFETY: CALL_THREAD holds the referenced, suspended thread object.
                unsafe { KeResumeThread(thread as usize as *mut xboxkrnl::Kthread) };
            }
        }
    }

    fn rpc_abort(&mut self, call: RpcCall) {
        match read_u32(call.0 + CALL_THREAD) {
            0 => {
                unlink_call(call.0);
                // SAFETY: the unlinked block has no runner.
                unsafe { xboxkrnl::ExFreePool(call.0) };
            }
            thread => {
                // The thread sees the abort flag and frees the block.
                call_atomic(call.0, CALL_ABORT).store(1, Ordering::Release);
                // SAFETY: CALL_THREAD holds the referenced thread object;
                // the reference is dropped once here.
                unsafe {
                    KeResumeThread(thread as usize as *mut xboxkrnl::Kthread);
                    xboxkrnl::ObDereferenceObject(thread);
                }
            }
        }
    }

    fn rpc_wait(&mut self, call: RpcCall) -> bool {
        match read_u32(call.0 + CALL_THREAD) {
            0 => {
                let start = TickCount::now().milliseconds();
                loop {
                    if call_atomic(call.0, CALL_DONE).load(Ordering::Acquire) != 0 {
                        return true;
                    }
                    if TickCount::now().milliseconds().wrapping_sub(start) >= CALL_WAIT_MS {
                        return false;
                    }
                    sleep(Duration::from_millis(u64::from(CALL_POLL_MS)));
                }
            }
            thread => {
                let timeout = CALL_WAIT;
                // SAFETY: CALL_THREAD holds the referenced thread object;
                // `timeout` is a live local.
                unsafe {
                    xboxkrnl::KeWaitForSingleObject(
                        thread as usize as *mut xboxkrnl::DispatcherObject,
                        WaitReason::UserRequest,
                        ProcessorMode::Kernel,
                        false,
                        &timeout,
                    )
                }
                .0 == STATUS_SUCCESS
            }
        }
    }

    fn rpc_read(&mut self, call: RpcCall, offset: u32, output: &mut [u8]) {
        let source = (call.0 + CALL_BUFFER + offset) as usize as *const u8;
        // SAFETY: reads stay within the buffer size.
        unsafe { core::ptr::copy_nonoverlapping(source, output.as_mut_ptr(), output.len()) };
    }

    fn rpc_release(&mut self, call: RpcCall) {
        let thread = read_u32(call.0 + CALL_THREAD);
        if thread != 0 {
            // SAFETY: CALL_THREAD holds the reference ExCreateThread returned.
            unsafe { xboxkrnl::ObDereferenceObject(thread) };
        } else if unlink_call(call.0) {
            // Still queued: no runner exists.
            // SAFETY: the unlinked block has no runner.
            unsafe { xboxkrnl::ExFreePool(call.0) };
            return;
        }
        // The monitor frees the block at once; a runner still in the call
        // frees it when it finishes instead.
        if call_atomic(call.0, CALL_RELEASE).swap(STREAM_RELEASED, Ordering::AcqRel)
            == RUNNER_FINISHED
        {
            // SAFETY: the runner finished, so this is the last use.
            unsafe { xboxkrnl::ExFreePool(call.0) };
        }
    }
}

/// Open-log state (stock 0x91fa1fe4..0x91fa1ff4), read by the producers
/// and the engine writer on other threads.
struct TellLog {
    /// Engine address; 0 while no log is open.
    engine: AtomicU32,
    file: AtomicU32,
    /// The log is closing; producers leave it alone.
    closing: AtomicBool,
    area: AtomicU32,
    entry_size: AtomicU32,
    /// Thread id of the engine worker while the log is open; the server
    /// thread may be waiting for it.
    worker: AtomicU32,
    /// Producers inside the engine. Stock destroys the engine without
    /// waiting for them; the stop here waits so that none uses it after.
    producers: AtomicU32,
}

static TELL_LOG: TellLog = TellLog {
    engine: AtomicU32::new(0),
    file: AtomicU32::new(0),
    closing: AtomicBool::new(false),
    area: AtomicU32::new(0),
    entry_size: AtomicU32::new(0),
    worker: AtomicU32::new(0),
    producers: AtomicU32::new(0),
};

/// Writer results carry this bit on top of the write status.
const TELL_LOG_STATUS_FLAG: u32 = 0x1000_0000;

/// The writer's collection buffer; it outlives a log, as stock's static
/// buffer does.
struct WriterCell(UnsafeCell<TellLogWriter>);

// SAFETY: only the worker of the open log touches the writer.
unsafe impl Sync for WriterCell {}

static TELL_LOG_WRITER: WriterCell = WriterCell(UnsafeCell::new(TellLogWriter::new()));

fn tell_log_engine() -> Option<Engine> {
    Engine::new(TELL_LOG.engine.load(Ordering::SeqCst))
}

/// Engine callback of the log (stock 0x91f51938): collect the entry text
/// and write the collection to the log file. The state is static, so the
/// context is not read.
extern "C" fn tell_log_write(_context: u32, entry: u32, length: u32) -> u32 {
    // SAFETY: only the worker of the open log calls the writer.
    let writer = unsafe { &mut *TELL_LOG_WRITER.0.get() };
    // SAFETY: the worker passes an entry of `length` bytes.
    let entry =
        unsafe { core::slice::from_raw_parts(entry as usize as *const u8, length as usize) };
    let file = TELL_LOG.file.load(Ordering::Acquire);
    let closing = TELL_LOG.closing.load(Ordering::Acquire);
    let mut write = |bytes: &[u8]| write_log(file, bytes);
    match writer.process(entry, closing, &mut write) {
        Ok(()) => TELL_LOG_STATUS_FLAG,
        Err(error) => Hresult::from(error).0,
    }
}

fn write_log(file: u32, bytes: &[u8]) -> Result<(), KernelError> {
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `file` is the open log file and `bytes` is valid for its
    // length.
    let status = unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(file),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            bytes.as_ptr(),
            bytes.len() as u32,
            core::ptr::null(),
        )
    };
    status.result()
}

impl TellLogBackend for Console {
    fn tell_log_area(&mut self) -> Option<TellLogAreas> {
        tell_log_engine().map(|_| TellLogAreas(TELL_LOG.area.load(Ordering::Acquire)))
    }

    fn set_tell_log_area(&mut self, area: TellLogAreas) {
        TELL_LOG.area.store(area.0, Ordering::Release);
    }

    fn tell_log_start(
        &mut self,
        file: FileHandle,
        area: TellLogAreas,
        config: TellLogConfig,
    ) -> Result<(), LogEngineError> {
        TELL_LOG.file.store(file.0, Ordering::Release);
        let context = &TELL_LOG as *const TellLog as usize as u32;
        match log_engine::create_for_callback(
            context,
            tell_log_write as *const () as usize as u32,
            config,
        ) {
            Ok(engine) => {
                TELL_LOG
                    .entry_size
                    .store(config.entry_size, Ordering::Release);
                TELL_LOG.area.store(area.0, Ordering::Release);
                TELL_LOG
                    .worker
                    .store(log_engine::worker_id(engine), Ordering::Release);
                TELL_LOG.engine.store(engine.address(), Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                TELL_LOG.file.store(0, Ordering::Release);
                Err(error)
            }
        }
    }

    fn tell_log_close(&mut self) -> Option<TellLogCounters> {
        let engine = tell_log_engine()?;
        TELL_LOG.closing.store(true, Ordering::SeqCst);
        let record = 0u8;
        log_engine::write(engine, &record as *const u8 as usize as u32, 1);
        Some(log_engine::counters(engine))
    }

    fn tell_log_stop(&mut self) -> Option<FileHandle> {
        let engine = tell_log_engine()?;
        // Producers that entered before the closing flag finish first; the
        // running worker frees the entries they may wait for.
        while TELL_LOG.producers.load(Ordering::SeqCst) != 0 {
            sleep(Duration::from_millis(1));
        }
        log_engine::close_after_worker(engine);
        TELL_LOG.engine.store(0, Ordering::SeqCst);
        TELL_LOG.worker.store(0, Ordering::Release);
        TELL_LOG.area.store(0, Ordering::Release);
        TELL_LOG.closing.store(false, Ordering::SeqCst);
        Some(FileHandle(TELL_LOG.file.swap(0, Ordering::AcqRel)))
    }
}

/// Monitor control code 0x88 (stock 0x91f51d58): write a record `{u16
/// length, u16, u32 text}` to the open log through export 363.
pub(crate) fn service_tell_log_record(argument: u32) -> u32 {
    TELL_LOG.producers.fetch_add(1, Ordering::SeqCst);
    // The closing flag is read first: a stop clears the engine before the
    // flag.
    if !TELL_LOG.closing.load(Ordering::SeqCst)
        && let Some(engine) = tell_log_engine()
        && argument != 0
    {
        let length = read_u32(argument) >> 16;
        let text = read_u32(argument + 4);
        if length != 0 && text != 0 {
            log_engine::write(engine, text, length);
        }
    }
    TELL_LOG.producers.fetch_sub(1, Ordering::SeqCst);
    0
}

/// Monitor control code 0x89: entry size of the open log, else 0.
pub(crate) fn service_tell_log_entry_size(_argument: u32) -> u32 {
    tell_log_engine().map_or(0, |_| TELL_LOG.entry_size.load(Ordering::Acquire))
}

/// Monitor control code 0x8a: area bits of the open log, else 0.
pub(crate) fn service_tell_log_area(_argument: u32) -> u32 {
    tell_log_engine().map_or(0, |_| TELL_LOG.area.load(Ordering::Acquire))
}

/// Monitor control code 0x81 (stock 0x91f2b798): a thread starts waiting
/// for critical section `section`. `entry_stack` is the caller's stack
/// pointer at the dispatcher.
pub(crate) fn service_cs_trace_wait_begin(section: u32, entry_stack: u32) -> u32 {
    count_wait(0x18, 0x20);
    trace_wait(WaitTrace::Enter, section, entry_stack);
    0
}

/// Monitor control code 0x82 (stock 0x91f2b828): the thread acquired the
/// section after waiting.
pub(crate) fn service_cs_trace_wait_end(section: u32, entry_stack: u32) -> u32 {
    count_wait(0x1c, 0x24);
    trace_wait(WaitTrace::Leave, section, entry_stack);
    0
}

/// Count the wait in the processor's wait statistics when they are
/// enabled: `title` for title threads, `system` otherwise.
fn count_wait(title: u32, system: u32) {
    let statistics = pcr_word(PCR_WAIT_STATISTICS);
    if statistics == 0 || read_u32(statistics + 4) & 1 == 0 {
        return;
    }
    // SAFETY: re-enabled below; nothing in between waits or faults.
    unsafe { processor::disable_interrupts() };
    let counter = statistics
        + if xboxkrnl::KeGetCurrentProcessType().0 == TITLE_PROCESS {
            title
        } else {
            system
        };
    write_u32(counter, read_u32(counter).wrapping_add(1));
    // SAFETY: interrupts were disabled above.
    unsafe { processor::enable_interrupts() };
}

/// Title reboot (stock 0x91f2b410): on every processor with statistics
/// enabled, set the title wait-end count to the wait-begin count.
pub(crate) fn reset_title_wait_statistics() {
    // SAFETY: the bridged routine runs at IPI level and only touches the
    // processor's own statistics.
    unsafe {
        xboxkrnl::KeIpiGenericCall(
            reset_title_wait_counts_entry as *const () as usize as u32,
            0,
        )
    };
}

crate::exports::bridged!(reset_title_wait_counts_entry, reset_title_wait_counts);

/// Per-processor routine of [`reset_title_wait_statistics`] (stock
/// 0x91f2b3d8).
extern "C" fn reset_title_wait_counts(_context: u32) -> u32 {
    // SAFETY: re-enabled below; nothing in between waits or faults.
    unsafe { processor::disable_interrupts() };
    let statistics = pcr_word(PCR_WAIT_STATISTICS);
    if statistics != 0 && read_u32(statistics + 4) & 1 != 0 {
        write_u32(statistics + 0x1c, read_u32(statistics + 0x18));
    }
    // SAFETY: interrupts were disabled above.
    unsafe { processor::enable_interrupts() };
    0
}

/// Write an `E:` or `L:` line into the log when area bit 2 is set (stock
/// 0x91f2b680 and line writer 0x91f2b530).
fn trace_wait(trace: WaitTrace, section: u32, entry_stack: u32) {
    let open = TellLogAreas(dispatcher::dispatch(0x8a, 0));
    if !open.intersects(TellLogAreas::CRITICAL_SECTIONS) {
        return;
    }
    let thread = current_thread();
    let time_base = Timebase::now().ticks();
    let processor = pcr_byte(PCR_CURRENT_PROCESSOR);
    let title = xboxkrnl::KeGetCurrentProcessType().0 == TITLE_PROCESS;
    let (lock_count, recursion_count, owner) = if section == 0 {
        (0, 0, 0)
    } else {
        (
            read_u32(section + 0x10) as u16,
            read_u32(section + 0x14) as u16,
            read_u32(section + 0x18),
        )
    };
    let (owner_id, owner_processor) = if owner == 0 {
        (0, -1)
    } else {
        (
            read_u32(owner + THREAD_ID),
            i32::from(read_u8(owner + THREAD_PROCESSOR)),
        )
    };
    let line = WaitTraceLine {
        trace,
        title,
        time_base,
        section,
        thread_id: read_u32(thread + THREAD_ID),
        lock_count,
        recursion_count,
        processor,
        owner,
        owner_id,
        owner_processor,
        callers: callers(entry_stack),
    };
    let size = dispatcher::dispatch(0x89, 0);
    if size == 0 || dispatcher::dispatch(0x8a, 0) == 0 {
        return;
    }
    let mut text = [0u8; TELL_LOG_LINE_LIMIT as usize];
    let length = format_wait_trace(&line, size, &mut text);
    // Producer record: u16 length, u16 unused, u32 text.
    let record = [(length as u32) << 16, text.as_ptr() as usize as u32];
    dispatcher::dispatch(0x88, record.as_ptr() as usize as u32);
}

/// Return addresses three frames up from the dispatcher's caller (stock
/// 0x91f2b428 with skip 5 from the trace routine's frame): the frames are
/// followed through their back chains within the thread's stack, and a
/// console frame's return address is saved 8 bytes below it.
fn callers(entry_stack: u32) -> [u32; 3] {
    let base = pcr_word(PCR_STACK_BASE);
    let limit = pcr_word(PCR_STACK_LIMIT);
    let mut callers = [0u32; 3];
    let mut skip = 2;
    let mut found = 0;
    let mut frame = entry_stack;
    while frame != 0 && frame >= limit && frame < base && found < callers.len() {
        if skip != 0 {
            skip -= 1;
        } else {
            callers[found] = read_u32(frame - 8);
            found += 1;
        }
        frame = read_u32(frame);
    }
    callers
}
