//! Session services: the debug capture ring, server thread affinity, remote
//! calls, the `dmtelllog` log, file I/O events, and notification
//! texts posted by other threads.
//!
//! Monitor control codes reach the services here on arbitrary threads, so
//! the state they share with the commands is static and lock-protected.

use core::cell::UnsafeCell;
use core::num::NonZeroU32;
use core::ptr::NonNull;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
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
use xbox360::status::Win32ErrorCode;
use xbox360::sync::SpinLock;
use xbox360::thread::ThreadObject;
use xbox360::thread::current_object;
use xbox360::time::relative_interval;
use xbox360_sys::image::XexExecutionInfo;
use xbox360_sys::image::XexHeaderKey;
use xbox360_sys::processor;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::processor::WaitCounts;
use xbox360_sys::processor::WaitStatistics;
use xbox360_sys::processor::WaitStatisticsFlags;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::ExRegisterTitleTerminateNotification;
use xbox360_sys::xboxkrnl::FscGetCacheElementCount;
use xbox360_sys::xboxkrnl::FscSetCacheElementCount;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeResumeThread;
use xbox360_sys::xboxkrnl::LdrDataTableEntry;
use xbox360_sys::xboxkrnl::NotificationRegistration;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::RtlCriticalSection;
use xbox360_sys::xboxkrnl::RtlCriticalSectionFields;
use xbox360_sys::xboxkrnl::RtlImageXexHeaderField;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;
use xbox360_sys::xboxkrnl::XexExecutableModuleHandle;

use super::Console;
use super::dispatcher;
use super::dispatcher::ControlCode;
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

use crate::kernel;
use crate::kernel::CriticalSection;

/// Pool type the monitor allocates the ring from.
const DEBUG_CAPTURE_POOL: PoolType = PoolType::System;
/// File system cache the pipe engine resizes.
const PIPE_CACHE: u32 = 2;

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

fn passive() -> bool {
    processor::current_irql() == Irql::PASSIVE
}

/// `bytes` up to their first NUL.
fn until_nul(bytes: &[u8]) -> &[u8] {
    let length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..length]
}

/// Priority 0x78 in the high byte, as stock's registration (0x91f97434).
const TITLE_TERMINATE_PRIORITY: u32 = 0x7800_0000;

static TITLE_TERMINATE: NotificationRegistration = NotificationRegistration::new();

/// Prepare the shared state; called once at module start, before the
/// control dispatcher is published.
pub(crate) fn initialize() {
    RPC_QUEUE_LOCK.initialize();
    processors::initialize();
    // SAFETY: the record is not registered yet. The routine stays loaded
    // until `uninstall` removes the record.
    unsafe {
        TITLE_TERMINATE.routine.store(
            title_terminated_entry as *const () as usize as u32,
            Ordering::Relaxed,
        );
        TITLE_TERMINATE
            .priority
            .store(TITLE_TERMINATE_PRIORITY, Ordering::Relaxed);
        ExRegisterTitleTerminateNotification(TITLE_TERMINATE.as_ptr(), true);
    }
}

/// Undo the registration of [`initialize`] before the image unloads.
pub(crate) fn uninstall() {
    if TITLE_TERMINATE.routine.load(Ordering::Relaxed) != 0 {
        // SAFETY: the static record registered by `initialize`.
        unsafe { ExRegisterTitleTerminateNotification(TITLE_TERMINATE.as_ptr(), false) };
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
    if dispatcher::call_on_server_with(&mut (), release_title).is_none() {
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
    _request: &mut (),
) -> u32 {
    server.title_terminated(console, network);
    0
}

/// Whether a title terminated since the last call.
pub(crate) fn take_title_terminated() -> bool {
    TITLE_TERMINATED.swap(false, Ordering::AcqRel)
}

/// Title identifier of the running executable (stock 0x91f335c0); 0 when
/// none runs or its header has no execution information.
fn current_title_id() -> u32 {
    // SAFETY: `data_imports_resolved` held at module load.
    let module = unsafe { XexExecutableModuleHandle.get_unchecked() }.load(Ordering::Relaxed);
    if module == 0 {
        return 0;
    }
    // SAFETY: a nonzero executable module handle is the address of the
    // title's loader entry, which stays loaded while the title runs.
    let entry =
        unsafe { &*core::ptr::with_exposed_provenance::<LdrDataTableEntry>(module as usize) };
    // SAFETY: the loader entry holds the address of its XEX header.
    let field =
        unsafe { RtlImageXexHeaderField(entry.xex_header_base, XexHeaderKey::EXECUTION_INFO) };
    // SAFETY: the field is 0 or the address of the execution information in
    // the loaded header, which stays mapped while the title runs.
    match unsafe { core::ptr::with_exposed_provenance::<XexExecutionInfo>(field as usize).as_ref() }
    {
        None => 0,
        Some(info) => info.title_id,
    }
}

impl commands::session::Backend for Console {
    fn allocate_debug_capture(&mut self) -> bool {
        // SAFETY: the allocation takes only a size, tag and pool type.
        match unsafe {
            xboxkrnl::ExAllocatePoolTypeWithTag(
                DEBUG_CAPTURE_SIZE as u32,
                crate::kernel::pool_tag::BUFFER,
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
        ProcessorNumber(Kpcr::current().processor_number().get())
    }

    fn set_server_processor(&mut self, processor: ProcessorNumber) {
        let mut thread = 0u32;
        // SAFETY: `data_imports_resolved` held at module load.
        let object_type =
            core::ptr::from_ref(unsafe { xboxkrnl::ExThreadObjectType.get_unchecked() }).addr()
                as u32;
        // SAFETY: `thread` is a local word; the pseudo handle names the
        // calling thread.
        if unsafe {
            xboxkrnl::ObReferenceObjectByHandle(Handle::CURRENT_THREAD, object_type, &mut thread)
        }
        .is_success()
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
    if worker != 0 && worker == current_object().id().raw() {
        return false;
    }
    let mut request = WaitingText {
        address: text.as_ptr() as usize as u32,
        length: text.len() as u32,
    };
    dispatcher::call_on_server_with(&mut request, send_waiting_text).is_some()
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
    request: &mut WaitingText,
) -> u32 {
    server.drain_posted_notifications(console, network);
    // SAFETY: the poster waits in `call_on_server_with` while its text is
    // alive.
    let text = unsafe {
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
///
/// # Safety
///
/// `text` must be 0 or a NUL-terminated string the caller keeps unchanged
/// for the call.
pub(crate) unsafe fn service_send_notification(text: u32) -> u32 {
    send_notification(text);
    0
}

/// Pool tag of call blocks.
const CALL_TAG: PoolTag = PoolTag::new(*b"drpc");
const CALL_NAME_CAPACITY: usize = 0x40;
/// Register slots: eight integers, then eight doubles.
const ARGUMENT_SLOTS: usize = 16;
/// How long the stream waits for a call: 100 ms.
const CALL_WAIT_MS: u32 = 100;
const CALL_WAIT: i64 = relative_interval(Duration::from_millis(CALL_WAIT_MS as u64));
const CALL_POLL_MS: u32 = 10;

/// A quadword the stream and the runner share, accessed as two words, as
/// the monitor's 32-bit code does.
#[repr(C)]
struct Quad([AtomicU32; 2]);

impl Quad {
    #[inline(always)]
    fn get(&self) -> u64 {
        (u64::from(self.0[0].load(Ordering::Relaxed)) << 32)
            | u64::from(self.0[1].load(Ordering::Relaxed))
    }

    /// The low word alone, with one load.
    #[inline(always)]
    fn low(&self) -> u32 {
        self.0[1].load(Ordering::Relaxed)
    }

    #[inline(always)]
    fn set(&self, value: u64) {
        self.0[0].store((value >> 32) as u32, Ordering::Relaxed);
        self.0[1].store(value as u32, Ordering::Relaxed);
    }
}

/// Owner of a call block that released it last: the stream that created
/// it or the runner that makes the call.
#[repr(u32)]
#[derive(Clone, Copy)]
enum ReleaseState {
    Held = 0,
    RunnerFinished = 1,
    StreamReleased = 2,
}

/// Word of a [`ReleaseState`].
#[repr(transparent)]
struct ReleaseWord(AtomicU32);

impl ReleaseWord {
    /// Store `state`; whether the word held `previous` before.
    #[inline(always)]
    fn swap_from(&self, state: ReleaseState, previous: ReleaseState) -> bool {
        self.0.swap(state as u32, Ordering::AcqRel) == previous as u32
    }
}

/// Call block (stock 0x91f3e7c8), followed by the call buffer of the size
/// the client gives.
#[repr(C)]
struct CallBlock {
    /// Next queued call, under [`RPC_QUEUE_LOCK`]; 0 ends the queue.
    link: AtomicU32,
    /// Nonzero once the stream abandoned an own-thread call before it ran.
    abort: AtomicU32,
    /// Nonzero for a call in the system process.
    system: AtomicU32,
    /// Referenced, suspended thread object of an own-thread call; 0 for a
    /// call queued for a named thread.
    thread: AtomicU32,
    /// Size of the call buffer.
    size: AtomicU32,
    _reserved_14: AtomicU32,
    /// `ERROR_IO_PENDING` from the creation on; nothing reads it.
    marker: Quad,
    /// Name of the thread that runs a queued call, NUL-terminated.
    name: [u8; CALL_NAME_CAPACITY],
    /// Nonzero once the call finished.
    done: AtomicU32,
    release: ReleaseWord,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(CallBlock, abort) == 0x4);
    assert!(offset_of!(CallBlock, system) == 0x8);
    assert!(offset_of!(CallBlock, thread) == 0xc);
    assert!(offset_of!(CallBlock, size) == 0x10);
    assert!(offset_of!(CallBlock, marker) == 0x18);
    assert!(offset_of!(CallBlock, name) == 0x20);
    assert!(offset_of!(CallBlock, done) == 0x60);
    assert!(offset_of!(CallBlock, release) == 0x64);
    assert!(core::mem::size_of::<CallBlock>() == 0x68);
};

impl CallBlock {
    #[inline(always)]
    fn thread_object(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.thread.load(Ordering::Relaxed))
    }
}

xbox360_sys::flags! {
    /// Flags quadword of a call buffer.
    pub struct CallFlags(u64) {
        /// The return value is the double in f1.
        DOUBLE_RESULT = 0x1,
    }
}

/// Header of a call buffer, followed by the integer arguments, then the
/// doubles. The client fills it before the call; the runner stores the
/// results.
#[repr(C)]
struct CallBuffer {
    /// HRESULT, sign-extended.
    result: Quad,
    value: Quad,
    /// [`CallBuffer::LAST_ERROR_REQUESTED`] asks for the last error.
    last_error: Quad,
    flags: Quad,
    integer_count: Quad,
    double_count: Quad,
    /// Address of the module name, or 0 for a target address.
    module: Quad,
    /// Function address, or the export ordinal or name address in `module`.
    target: Quad,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(CallBuffer, value) == 0x8);
    assert!(offset_of!(CallBuffer, last_error) == 0x10);
    assert!(offset_of!(CallBuffer, flags) == 0x18);
    assert!(offset_of!(CallBuffer, integer_count) == 0x20);
    assert!(offset_of!(CallBuffer, double_count) == 0x28);
    assert!(offset_of!(CallBuffer, module) == 0x30);
    assert!(offset_of!(CallBuffer, target) == 0x38);
    assert!(core::mem::size_of::<CallBuffer>() == 0x40);
};

impl CallBuffer {
    const LAST_ERROR_REQUESTED: u64 = 1;
}

/// Why a call did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallError {
    ModuleNotFound,
    ProcedureNotFound,
}

impl From<CallError> for Hresult {
    fn from(error: CallError) -> Self {
        Hresult::from_win32(match error {
            CallError::ModuleNotFound => Win32Error::MOD_NOT_FOUND,
            CallError::ProcedureNotFound => Win32Error::PROC_NOT_FOUND,
        })
    }
}

impl core::fmt::Display for CallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ModuleNotFound => "module not found",
            Self::ProcedureNotFound => "procedure not found",
        })
    }
}

impl core::error::Error for CallError {}

/// The result quadword of a call buffer: the HRESULT sign-extended.
const fn result_quad(result: Hresult) -> u64 {
    result.0 as i32 as i64 as u64
}

/// A call block allocated by [`RpcBackend::rpc_create`], possibly freed.
#[derive(Clone, Copy, PartialEq, Eq)]
struct CallPointer(NonNull<CallBlock>);

impl CallPointer {
    /// `None` for 0.
    ///
    /// # Safety
    ///
    /// `address` must be 0 or the address of a call block.
    #[inline(always)]
    unsafe fn new(address: u32) -> Option<Self> {
        NonNull::new(core::ptr::with_exposed_provenance_mut(address as usize)).map(Self)
    }

    /// # Safety
    ///
    /// `address` must be the address of a call block.
    #[inline(always)]
    unsafe fn from_address(address: u32) -> Self {
        // SAFETY: the address of a call block is not 0.
        Self(unsafe {
            NonNull::new_unchecked(core::ptr::with_exposed_provenance_mut(address as usize))
        })
    }

    #[inline(always)]
    fn address(self) -> u32 {
        self.0.as_ptr().expose_provenance() as u32
    }

    /// # Safety
    ///
    /// The block must stay allocated while the reference is used: the
    /// caller is the stream before `rpc_release`, the runner before
    /// [`release_runner`], or holds [`RPC_QUEUE_LOCK`] while the block is
    /// queued.
    #[inline(always)]
    unsafe fn block<'a>(self) -> &'a CallBlock {
        // SAFETY: the caller guarantees the block for `'a`.
        unsafe { self.0.as_ref() }
    }

    /// The call buffer after the block.
    #[inline(always)]
    fn buffer(self) -> *mut CallBuffer {
        self.0.as_ptr().wrapping_add(1).cast()
    }

    /// # Safety
    ///
    /// The caller is the last owner of the block and does not use it after.
    #[inline(always)]
    unsafe fn free(self) {
        // SAFETY: the caller releases the last use of the pool block.
        unsafe { xboxkrnl::ExFreePool(self.address()) };
    }
}

/// Head of the named-call queue (stock 0x91f9fda8), newest first.
static RPC_QUEUE: AtomicU32 = AtomicU32::new(0);
/// Lock of the named-call queue (stock 0x91f9766c).
static RPC_QUEUE_LOCK: CriticalSection = CriticalSection::new();

fn push_call(call: CallPointer) {
    RPC_QUEUE_LOCK.enter();
    // SAFETY: the stream owns the block until it releases it.
    unsafe { call.block() }
        .link
        .store(RPC_QUEUE.load(Ordering::Relaxed), Ordering::Relaxed);
    RPC_QUEUE.store(call.address(), Ordering::Relaxed);
    RPC_QUEUE_LOCK.leave();
}

/// Remove `call` from the queue; returns whether it was queued.
fn unlink_call(call: CallPointer) -> bool {
    RPC_QUEUE_LOCK.enter();
    // The word that links the current call: the head, then a call's link.
    let mut link = &RPC_QUEUE;
    let mut found = false;
    // SAFETY: the queue links call blocks, which stay allocated while they
    // are queued and the lock is held.
    while let Some(current) = unsafe { CallPointer::new(link.load(Ordering::Relaxed)) } {
        // SAFETY: as above.
        let block = unsafe { current.block() };
        if current == call {
            link.store(block.link.load(Ordering::Relaxed), Ordering::Relaxed);
            found = true;
            break;
        }
        link = &block.link;
    }
    RPC_QUEUE_LOCK.leave();
    found
}

/// Take the newest call queued for `name` (stock 0x91f3e208). A busy lock
/// reads as an empty queue.
fn take_call(name: &[u8]) -> Option<CallPointer> {
    if !RPC_QUEUE_LOCK.try_enter() {
        return None;
    }
    let mut link = &RPC_QUEUE;
    let mut taken = None;
    // SAFETY: the queue links call blocks, which stay allocated while they
    // are queued and the lock is held.
    while let Some(current) = unsafe { CallPointer::new(link.load(Ordering::Relaxed)) } {
        // SAFETY: as above.
        let block = unsafe { current.block() };
        if until_nul(&block.name) == name {
            link.store(block.link.load(Ordering::Relaxed), Ordering::Relaxed);
            block.link.store(0, Ordering::Relaxed);
            taken = Some(current);
            break;
        }
        link = &block.link;
    }
    RPC_QUEUE_LOCK.leave();
    taken
}

/// Monitor control code 0xa8 (export 372, stock 0x91f3ea50): run every
/// call queued for the calling thread's name, newest first.
///
/// # Safety
///
/// `name` must be 0 or the NUL-terminated name of the calling thread,
/// unchanged for the call.
pub(crate) unsafe fn service_rpc_drain(name: u32) -> u32 {
    // SAFETY: the caller's contract.
    let Some(name) = (unsafe { kernel::c_string(name) }) else {
        return 0;
    };
    while let Some(call) = take_call(name) {
        // SAFETY: the taken call is unlinked, so this thread is its runner.
        unsafe { run_call(call) };
    }
    0
}

/// Own-thread call start routine.
extern "C" fn call_thread(context: u32) -> u32 {
    // SAFETY: `rpc_create` starts the thread with its call block as the
    // context; the thread is the block's runner.
    let call = unsafe { CallPointer::from_address(context) };
    // SAFETY: the runner's block stays allocated until it releases it.
    if unsafe { call.block() }.abort.load(Ordering::Acquire) != 0 {
        // SAFETY: an aborted block is owned by this thread and freed once.
        unsafe { call.free() };
    } else {
        // SAFETY: this thread is the runner of the block.
        unsafe { run_call(call) };
    }
    // SAFETY: this thread was created for the call and holds no resources.
    unsafe { xboxkrnl::ExTerminateThread(0) }
}

/// Make the call described by the block's buffer (stock 0x91f3e630).
///
/// # Safety
///
/// The caller must be the runner of `call`, which owns the block until
/// [`release_runner`].
unsafe fn run_call(call: CallPointer) {
    // SAFETY: the runner's block stays allocated until it releases it.
    let block = unsafe { call.block() };
    // SAFETY: the client sizes the buffer for the header and the arguments
    // it gives; as in stock, nothing checks the size.
    let buffer = unsafe { &*call.buffer() };
    let mut target = buffer.target.low();
    let module = buffer.module.get();
    let failure = if module != 0 {
        let mut handle = 0u32;
        // SAFETY: the client supplied the module name address; `handle` and
        // `target` are live locals.
        unsafe {
            if !xboxkrnl::XexGetModuleHandle(module as u32 as usize as *const u8, &mut handle)
                .is_success()
            {
                Some(CallError::ModuleNotFound)
            } else if !xboxkrnl::XexGetProcedureAddress(handle, target, &mut target).is_success() {
                Some(CallError::ProcedureNotFound)
            } else {
                None
            }
        }
    } else {
        None
    };
    if let Some(failure) = failure {
        // Failures store the result before the done flag.
        buffer.result.set(result_quad(Hresult::from(failure)));
        block.done.store(1, Ordering::Release);
        // SAFETY: this thread is the runner and does not use the block after.
        unsafe { release_runner(call) };
        return;
    }
    // The monitor copies the integers to slot 0 and the doubles to slot 8
    // of two adjacent eight-slot arrays without bounds; the copies are
    // limited to the arrays here.
    let mut slots = [0u64; ARGUMENT_SLOTS];
    let integers = (buffer.integer_count.low() as usize).min(ARGUMENT_SLOTS);
    let doubles = (buffer.double_count.low() as usize).min(ARGUMENT_SLOTS / 2);
    let first = call.buffer().wrapping_add(1).cast::<Quad>();
    // SAFETY: the arguments follow the header, integers first; the client
    // sizes the buffer for them as for the header.
    let (integer_arguments, double_arguments) = unsafe {
        (
            core::slice::from_raw_parts(first, integers),
            core::slice::from_raw_parts(first.add(integers), doubles),
        )
    };
    for (slot, argument) in slots.iter_mut().zip(integer_arguments) {
        *slot = argument.get();
    }
    for (slot, argument) in slots[ARGUMENT_SLOTS / 2..].iter_mut().zip(double_arguments) {
        *slot = argument.get();
    }
    let mut registers = [0u64; 2];
    // SAFETY: the client supplied the target and its arguments; the call is
    // the purpose of the command.
    unsafe { invoke(target, slots.as_ptr(), registers.as_mut_ptr()) };
    // The defined flag lies in the low word.
    let flags = CallFlags::from_bits_retain(u64::from(buffer.flags.low()));
    let value = if flags.contains(CallFlags::DOUBLE_RESULT) {
        registers[1]
    } else {
        registers[0]
    };
    buffer.value.set(value);
    if buffer.last_error.get() == CallBuffer::LAST_ERROR_REQUESTED {
        let code = Win32ErrorCode::from(xbox360::status::last_error());
        buffer.last_error.set(u64::from(code.0));
    }
    // The done flag is set before the success result is stored.
    block.done.store(1, Ordering::Release);
    buffer.result.set(result_quad(Hresult::SUCCESS));
    // SAFETY: this thread is the runner and does not use the block after.
    unsafe { release_runner(call) };
}

/// The runner is done with the block; free it when the stream already
/// released it.
///
/// # Safety
///
/// The caller must be the runner of `call` and must not use it after.
unsafe fn release_runner(call: CallPointer) {
    // SAFETY: the runner's block stays allocated until this release.
    if unsafe { call.block() }
        .release
        .swap_from(ReleaseState::RunnerFinished, ReleaseState::StreamReleased)
    {
        // SAFETY: both owners released the block; this is the last use.
        unsafe { call.free() };
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

/// The call block of `call`.
#[inline(always)]
fn call_pointer(call: RpcCall) -> CallPointer {
    // SAFETY: an `RpcCall` names a call block until it is aborted or
    // released (`RpcCall::from_raw`), after which no copy is used.
    unsafe { CallPointer::from_address(call.raw()) }
}

impl RpcBackend for Console {
    fn rpc_create(
        &mut self,
        size: u32,
        context: RpcContext,
        thread: RpcThread<'_>,
    ) -> Result<RpcCall, RpcCreateError> {
        // Stock adds without a carry, so a size near 4 GB gets a small block
        // its upload overruns; here that size fails as an allocation does.
        let total = size
            .checked_add(core::mem::size_of::<CallBlock>() as u32)
            .ok_or(RpcCreateError::OutOfMemory)?;
        // SAFETY: the allocation takes only a size and tag.
        let address = unsafe { xboxkrnl::ExAllocatePoolWithTag(total, CALL_TAG) };
        // SAFETY: the allocation is 0 or a new block sized for a call block
        // and its buffer.
        let Some(call) = (unsafe { CallPointer::new(address) }) else {
            return Err(RpcCreateError::OutOfMemory);
        };
        let name = match thread {
            RpcThread::Named(name) => &name[..name.len().min(CALL_NAME_CAPACITY - 1)],
            RpcThread::Own { .. } => &[],
        };
        // SAFETY: the new block is not shared; its name field holds
        // CALL_NAME_CAPACITY bytes.
        unsafe {
            let field = (&raw mut (*call.0.as_ptr()).name).cast::<u8>();
            core::ptr::copy_nonoverlapping(name.as_ptr(), field, name.len());
            field.add(name.len()).write(0);
        }
        // SAFETY: the stream owns the new block.
        let block = unsafe { call.block() };
        let system = context == RpcContext::System;
        block.link.store(0, Ordering::Relaxed);
        block.abort.store(0, Ordering::Relaxed);
        block.thread.store(0, Ordering::Relaxed);
        block.done.store(0, Ordering::Relaxed);
        block
            .release
            .0
            .store(ReleaseState::Held as u32, Ordering::Relaxed);
        block.system.store(u32::from(system), Ordering::Relaxed);
        block.size.store(size, Ordering::Relaxed);
        block.marker.set(u64::from(Win32Error::IO_PENDING.code()));
        if let RpcThread::Own { processor } = thread {
            // Only the low six bits of the processor reach the shift.
            // Numbers 6 and 7 set bits above PROCESSOR5, which pass on
            // unchanged as stock passes them.
            let processor = processor & 0x3f;
            let affinity = ThreadCreationFlags::from_bits_retain(if processor < 32 {
                (1u32 << processor) << 24
            } else {
                0
            });
            let mut flags = affinity
                | ThreadCreationFlags::RETURN_THREAD_OBJECT
                | ThreadCreationFlags::SUSPENDED;
            if system {
                flags |= ThreadCreationFlags::SYSTEM_PROCESS;
            }
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
                    call.address(),
                    flags,
                )
            };
            if let Err(error) = status.result() {
                // SAFETY: the block was allocated above and no thread owns it.
                unsafe { call.free() };
                return Err(RpcCreateError::Thread(error));
            }
            block.thread.store(object, Ordering::Relaxed);
        }
        // SAFETY: the block is new; it is freed only through `rpc_abort` or
        // `rpc_release`, whose contracts end the use of every copy.
        Ok(unsafe { RpcCall::from_raw(call.address()) })
    }

    fn rpc_buffer_address(&mut self, call: RpcCall) -> u32 {
        call.raw() + core::mem::size_of::<CallBlock>() as u32
    }

    unsafe fn rpc_write(&mut self, call: RpcCall, offset: u32, data: &[u8]) {
        let call = call_pointer(call);
        let destination = call.buffer().cast::<u8>().wrapping_add(offset as usize);
        // SAFETY: the bytes lie in the buffer the block was allocated with,
        // per the trait contract.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), destination, data.len()) };
    }

    fn rpc_start(&mut self, call: RpcCall) {
        let call = call_pointer(call);
        // SAFETY: the stream owns the block until it releases it.
        match unsafe { call.block() }.thread_object() {
            None => push_call(call),
            Some(thread) => {
                // SAFETY: the block holds the referenced, suspended thread object.
                unsafe { KeResumeThread(thread.get() as usize as *mut xboxkrnl::Kthread) };
            }
        }
    }

    unsafe fn rpc_abort(&mut self, call: RpcCall) {
        let call = call_pointer(call);
        // SAFETY: the stream owns the block until it releases it.
        let block = unsafe { call.block() };
        match block.thread_object() {
            None => {
                unlink_call(call);
                // SAFETY: the unlinked block has no runner.
                unsafe { call.free() };
            }
            Some(thread) => {
                // The thread sees the abort flag and frees the block.
                block.abort.store(1, Ordering::Release);
                // SAFETY: the block holds the referenced thread object; the
                // reference is dropped once here.
                unsafe {
                    KeResumeThread(thread.get() as usize as *mut xboxkrnl::Kthread);
                    xboxkrnl::ObDereferenceObject(thread.get());
                }
            }
        }
    }

    fn rpc_wait(&mut self, call: RpcCall) -> bool {
        let call = call_pointer(call);
        // SAFETY: the stream owns the block until it releases it.
        let block = unsafe { call.block() };
        match block.thread_object() {
            None => {
                let start = TickCount::now().milliseconds();
                loop {
                    if block.done.load(Ordering::Acquire) != 0 {
                        return true;
                    }
                    if TickCount::now().milliseconds().wrapping_sub(start) >= CALL_WAIT_MS {
                        return false;
                    }
                    sleep(Duration::from_millis(u64::from(CALL_POLL_MS)));
                }
            }
            Some(thread) => {
                let timeout = CALL_WAIT;
                // SAFETY: the block holds the referenced thread object;
                // `timeout` is a live local.
                let status = unsafe {
                    xboxkrnl::KeWaitForSingleObject(
                        thread.get() as usize as *mut xboxkrnl::DispatcherObject,
                        WaitReason::UserRequest,
                        ProcessorMode::Kernel,
                        false,
                        &timeout,
                    )
                };
                status == NtStatus::WAIT_0
            }
        }
    }

    unsafe fn rpc_read(&mut self, call: RpcCall, offset: u32, output: &mut [u8]) {
        let call = call_pointer(call);
        let source = call.buffer().cast::<u8>().wrapping_add(offset as usize);
        // SAFETY: the bytes lie in the buffer the block was allocated with,
        // per the trait contract.
        unsafe { core::ptr::copy_nonoverlapping(source, output.as_mut_ptr(), output.len()) };
    }

    unsafe fn rpc_release(&mut self, call: RpcCall) {
        let call = call_pointer(call);
        // SAFETY: the stream owns the block until it releases it here.
        let block = unsafe { call.block() };
        match block.thread_object() {
            Some(thread) => {
                // SAFETY: the block holds the reference ExCreateThread returned.
                unsafe { xboxkrnl::ObDereferenceObject(thread.get()) };
            }
            None => {
                if unlink_call(call) {
                    // Still queued: no runner exists.
                    // SAFETY: the unlinked block has no runner.
                    unsafe { call.free() };
                    return;
                }
            }
        }
        // The monitor frees the block at once; a runner still in the call
        // frees it when it finishes instead.
        if block
            .release
            .swap_from(ReleaseState::StreamReleased, ReleaseState::RunnerFinished)
        {
            // SAFETY: the runner finished, so this is the last use.
            unsafe { call.free() };
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

/// The writer's collection buffer; it outlives a log, as stock's static
/// buffer does.
struct WriterCell(UnsafeCell<TellLogWriter>);

// SAFETY: only the worker of the open log touches the writer.
unsafe impl Sync for WriterCell {}

static TELL_LOG_WRITER: WriterCell = WriterCell(UnsafeCell::new(TellLogWriter::new()));

fn tell_log_engine() -> Option<Engine> {
    // SAFETY: the word holds 0 or the engine of the open log. Only
    // `tell_log_stop` on the server thread destroys the engine, after
    // `tell_log_close` set the closing flag: it waits until no producer is
    // inside `service_tell_log_record`, closes the engine, and then clears
    // the word. Producers test the flag before they load the word, so none
    // uses the engine from that wait on; the other callers run on the
    // server thread or only test whether a log is open.
    unsafe { Engine::new(TELL_LOG.engine.load(Ordering::SeqCst)) }
}

/// Engine callback of the log (stock 0x91f51938): collect the entry text
/// and write the collection to the log file. The state is static, so the
/// context is not read. A success carries the NT status form.
extern "C" fn tell_log_write(_context: u32, entry: u32, length: u32) -> Hresult {
    // SAFETY: only the worker of the open log calls the writer.
    let writer = unsafe { &mut *TELL_LOG_WRITER.0.get() };
    // SAFETY: the worker passes an entry of `length` bytes.
    let entry =
        unsafe { core::slice::from_raw_parts(entry as usize as *const u8, length as usize) };
    let file = TELL_LOG.file.load(Ordering::Acquire);
    let closing = TELL_LOG.closing.load(Ordering::Acquire);
    let mut write = |bytes: &[u8]| write_log(file, bytes);
    match writer.process(entry, closing, &mut write) {
        Ok(()) => Hresult::from_nt(NtStatus::SUCCESS),
        Err(error) => Hresult::from(error),
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
        tell_log_engine()
            .map(|_| TellLogAreas::from_bits_retain(TELL_LOG.area.load(Ordering::Acquire)))
    }

    fn set_tell_log_area(&mut self, area: TellLogAreas) {
        TELL_LOG.area.store(area.bits(), Ordering::Release);
    }

    fn tell_log_start(
        &mut self,
        file: FileHandle,
        area: TellLogAreas,
        config: TellLogConfig,
    ) -> Result<(), LogEngineError> {
        TELL_LOG.file.store(file.0, Ordering::Release);
        let context = &TELL_LOG as *const TellLog as usize as u32;
        match log_engine::create_for_callback(context, tell_log_write, config) {
            Ok(engine) => {
                TELL_LOG
                    .entry_size
                    .store(config.entry_size, Ordering::Release);
                TELL_LOG.area.store(area.bits(), Ordering::Release);
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
        log_engine::write(engine, &[0]);
        Some(log_engine::counters(engine))
    }

    fn tell_log_stop(&mut self) -> Option<FileHandle> {
        let engine = tell_log_engine()?;
        // Producers that entered before the closing flag finish first; the
        // running worker frees the entries they may wait for.
        while TELL_LOG.producers.load(Ordering::SeqCst) != 0 {
            sleep(Duration::from_millis(1));
        }
        // SAFETY: producers have left and the closing flag keeps new ones
        // away from the engine word until it is cleared below, after the
        // close; nothing else uses the engine off the server thread.
        unsafe { log_engine::close_after_worker(engine) };
        TELL_LOG.engine.store(0, Ordering::SeqCst);
        TELL_LOG.worker.store(0, Ordering::Release);
        TELL_LOG.area.store(0, Ordering::Release);
        TELL_LOG.closing.store(false, Ordering::SeqCst);
        Some(FileHandle(TELL_LOG.file.swap(0, Ordering::AcqRel)))
    }
}

/// Producer record of monitor control code 0x88. The length is the high
/// half of the first word, read with one word load as stock reads it; the
/// load is atomic so that it is not narrowed to a halfword load.
#[repr(C)]
struct TellLogRecord {
    /// Text length in bits 16 to 31; bits 0 to 15 are unused.
    length_word: AtomicU32,
    /// Address of the text.
    text: u32,
}

impl TellLogRecord {
    const LENGTH_SHIFT: u32 = 16;

    #[inline(always)]
    fn new(length: u16, text: u32) -> Self {
        Self {
            length_word: AtomicU32::new(u32::from(length) << Self::LENGTH_SHIFT),
            text,
        }
    }

    #[inline(always)]
    fn length(&self) -> u32 {
        self.length_word.load(Ordering::Relaxed) >> Self::LENGTH_SHIFT
    }
}

/// Monitor control code 0x88 (stock 0x91f51d58): write a record to the
/// open log through export 363.
///
/// # Safety
///
/// `argument` must be 0 or the address of a [`TellLogRecord`] whose text
/// holds its length in readable bytes, both unchanged for the call.
pub(crate) unsafe fn service_tell_log_record(argument: u32) -> u32 {
    TELL_LOG.producers.fetch_add(1, Ordering::SeqCst);
    // The closing flag is read first: a stop clears the engine before the
    // flag.
    if !TELL_LOG.closing.load(Ordering::SeqCst)
        && let Some(engine) = tell_log_engine()
        // SAFETY: the caller's contract.
        && let Some(record) =
            unsafe { core::ptr::with_exposed_provenance::<TellLogRecord>(argument as usize).as_ref() }
    {
        let length = record.length();
        let text = record.text;
        if length != 0 && text != 0 {
            // SAFETY: the record's text holds `length` bytes.
            let text =
                unsafe { core::slice::from_raw_parts(text as usize as *const u8, length as usize) };
            log_engine::write(engine, text);
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

/// The section of control codes 0x81 and 0x82.
///
/// # Safety
///
/// `section` must be 0 or the address of an initialized critical section
/// that stays initialized while the calling thread waits for it.
#[inline(always)]
unsafe fn waited_section<'a>(section: u32) -> Option<&'a RtlCriticalSectionFields> {
    // SAFETY: the caller guarantees the section.
    unsafe { core::ptr::with_exposed_provenance::<RtlCriticalSection>(section as usize).as_ref() }
        .map(RtlCriticalSection::fields)
}

/// Monitor control code 0x81 (stock 0x91f2b798): a thread starts waiting
/// for critical section `section`. `entry_stack` is the caller's stack
/// pointer at the dispatcher.
///
/// # Safety
///
/// `section` must be 0 or the address of an initialized critical section
/// the calling thread waits for, whose owner stays allocated for the call
/// (see [`trace_wait`]). `entry_stack` must be the stack pointer of the
/// dispatcher's caller, with a valid back chain.
pub(crate) unsafe fn service_cs_trace_wait_begin(section: u32, entry_stack: u32) -> u32 {
    count_wait(WaitEdge::Begin);
    // SAFETY: the caller's contract.
    unsafe { trace_wait(WaitTrace::Enter, waited_section(section), entry_stack) };
    0
}

/// Monitor control code 0x82 (stock 0x91f2b828): the thread acquired the
/// section after waiting.
///
/// # Safety
///
/// As [`service_cs_trace_wait_begin`], for the section the calling thread
/// acquired.
pub(crate) unsafe fn service_cs_trace_wait_end(section: u32, entry_stack: u32) -> u32 {
    count_wait(WaitEdge::End);
    // SAFETY: the caller's contract.
    unsafe { trace_wait(WaitTrace::Leave, waited_section(section), entry_stack) };
    0
}

/// Which end of a critical section wait a count records.
#[derive(Clone, Copy)]
enum WaitEdge {
    Begin,
    End,
}

impl WaitEdge {
    #[inline(always)]
    fn counter(self, counts: &WaitCounts) -> &AtomicU32 {
        match self {
            WaitEdge::Begin => &counts.begins,
            WaitEdge::End => &counts.ends,
        }
    }
}

/// The wait statistics of the current processor while they are enabled.
#[inline(always)]
fn current_wait_statistics() -> Option<&'static WaitStatistics> {
    let address = Kpcr::current().wait_statistics.load(Ordering::Relaxed);
    // SAFETY: the kernel keeps 0 or the address of the processor's
    // statistics block, which stays mapped, in the PCR.
    let statistics =
        unsafe { core::ptr::with_exposed_provenance::<WaitStatistics>(address as usize).as_ref() }?;
    WaitStatisticsFlags::from_bits_retain(statistics.flags.load(Ordering::Relaxed))
        .contains(WaitStatisticsFlags::ENABLED)
        .then_some(statistics)
}

/// Count the wait in the processor's wait statistics when they are
/// enabled, under the counts of title or system threads.
fn count_wait(edge: WaitEdge) {
    let Some(statistics) = current_wait_statistics() else {
        return;
    };
    // SAFETY: re-enabled below; nothing in between waits or faults.
    unsafe { processor::disable_interrupts() };
    let counts = if xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE {
        &statistics.title
    } else {
        &statistics.system
    };
    let counter = edge.counter(counts);
    counter.store(
        counter.load(Ordering::Relaxed).wrapping_add(1),
        Ordering::Relaxed,
    );
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
    if let Some(statistics) = current_wait_statistics() {
        let title = &statistics.title;
        title
            .ends
            .store(title.begins.load(Ordering::Relaxed), Ordering::Relaxed);
    }
    // SAFETY: interrupts were disabled above.
    unsafe { processor::enable_interrupts() };
    0
}

/// Write an `E:` or `L:` line into the log when area bit 2 is set (stock
/// 0x91f2b680 and line writer 0x91f2b530).
///
/// # Safety
///
/// The thread object `section` names as its owner, if any, must stay
/// allocated for the call. Stock reads the owner's id and processor
/// without a reference, so an owner that releases the section and ends
/// after the owner word is read races with those reads; the trace keeps
/// that race.
unsafe fn trace_wait(
    trace: WaitTrace,
    section: Option<&RtlCriticalSectionFields>,
    entry_stack: u32,
) {
    // SAFETY: the code takes no argument.
    let open = TellLogAreas::from_bits_retain(unsafe {
        dispatcher::dispatch(ControlCode::TELL_LOG_AREAS, 0)
    });
    if !open.intersects(TellLogAreas::CRITICAL_SECTIONS) {
        return;
    }
    let thread = current_object();
    let time_base = Timebase::now().ticks();
    let processor = Kpcr::current().processor_number().get();
    let title = xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE;
    let (lock_count, recursion_count, owner) = match section {
        None => (0, 0, 0),
        Some(section) => (
            section.lock_count.load(Ordering::Relaxed) as u16,
            section.recursion_count.load(Ordering::Relaxed) as u16,
            section.owning_thread.load(Ordering::Relaxed),
        ),
    };
    let (owner_id, owner_processor) = match owner {
        0 => (0, -1),
        owner => {
            // SAFETY: the caller's contract.
            let owner = unsafe { ThreadObject::from_raw(owner) };
            (owner.id().raw(), i32::from(owner.hardware_thread().get()))
        }
    };
    let line = WaitTraceLine {
        trace,
        title,
        time_base,
        section: section.map_or(0, |section| {
            core::ptr::from_ref(section).expose_provenance() as u32
        }),
        thread_id: thread.id().raw(),
        lock_count,
        recursion_count,
        processor,
        owner,
        owner_id,
        owner_processor,
        callers: callers(entry_stack),
    };
    // SAFETY: the codes take no argument.
    let size = unsafe { dispatcher::dispatch(ControlCode::TELL_LOG_ENTRY_SIZE, 0) };
    if size == 0 || unsafe { dispatcher::dispatch(ControlCode::TELL_LOG_AREAS, 0) } == 0 {
        return;
    }
    let mut text = [0u8; TELL_LOG_LINE_LIMIT as usize];
    let length = format_wait_trace(&line, size, &mut text);
    let record = TellLogRecord::new(length as u16, text.as_ptr() as usize as u32);
    // SAFETY: `record` and its text are live locals; the length is the
    // formatted length within `text`.
    unsafe {
        dispatcher::dispatch(
            ControlCode::TELL_LOG_RECORD,
            &record as *const TellLogRecord as usize as u32,
        )
    };
}

/// Return addresses three frames up from the dispatcher's caller (stock
/// 0x91f2b428 with skip 5 from the trace routine's frame): the frames are
/// followed through their back chains within the thread's stack, and a
/// console frame's return address is saved 8 bytes below it.
fn callers(entry_stack: u32) -> [u32; 3] {
    let pcr = Kpcr::current();
    let base = pcr.stack_base.load(Ordering::Relaxed);
    let limit = pcr.stack_limit.load(Ordering::Relaxed);
    let mut callers = [0u32; 3];
    let mut skip = 2;
    let mut found = 0;
    let mut frame = entry_stack;
    while frame != 0 && frame >= limit && frame < base && found < callers.len() {
        let word = |address: u32| {
            // SAFETY: `frame` lies in the calling thread's stack between its
            // limit and base, which stays mapped; the save word 8 bytes
            // below a frame lies in the stack as well.
            unsafe { core::ptr::with_exposed_provenance::<u32>(address as usize).read() }
        };
        if skip != 0 {
            skip -= 1;
        } else {
            callers[found] = word(frame - 8);
            found += 1;
        }
        frame = word(frame);
    }
    callers
}
