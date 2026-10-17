//! Session services: the debug capture ring, server thread affinity, remote
//! calls, the `dmtelllog` log, file I/O events, and notification
//! texts posted by other threads.
//!
//! Monitor control codes reach the services here on arbitrary threads, so
//! the state they share with the commands is static and lock-protected.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use openxbdm_core::status::KernelError;
use openxbdm_server::Server;
use openxbdm_server::commands;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::session::DEBUG_CAPTURE_SIZE;
use openxbdm_server::commands::session::FastPipeBackend;
use openxbdm_server::commands::session::FileEventId;
use openxbdm_server::commands::session::ProcessorNumber;
use openxbdm_server::notify::POSTED_TEXT_CAPACITY;
use openxbdm_server::notify::PostedTexts;
use xbox360::sync::SpinLock;
use xbox360::thread::current_object;
use xbox360_sys::image::XexExecutionInfo;
use xbox360_sys::image::XexHeaderKey;
use xbox360_sys::processor;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::ExRegisterTitleTerminateNotification;
use xbox360_sys::xboxkrnl::FscGetCacheElementCount;
use xbox360_sys::xboxkrnl::FscSetCacheElementCount;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::LdrDataTableEntry;
use xbox360_sys::xboxkrnl::NotificationRegistration;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::RtlImageXexHeaderField;
use xbox360_sys::xboxkrnl::XexExecutableModuleHandle;

use self::notifications::send_notification;
use self::notifications::unlink_title_notification_sessions;
use super::Console;
use super::dispatcher;
use crate::net::XamNetwork;

pub(crate) use self::file_events::service_file_event_begin;
pub(crate) use self::file_events::service_file_event_end;
pub(crate) use self::processors::poll_processor_calls;
pub(crate) use self::processors::release_processor_threads;
pub(crate) use self::processors::service_register_pix_processor;
pub(crate) use self::processors::service_register_processor;
pub(crate) use self::rpc::service_rpc_drain;
pub(crate) use self::swap::register_swap_routine;
pub(crate) use self::swap::remove_unflagged_swap_routines;
pub(crate) use self::swap::unregister_swap_routine;
pub(crate) use self::tell_log::service_tell_log_area;
pub(crate) use self::tell_log::service_tell_log_entry_size;
pub(crate) use self::tell_log::service_tell_log_record;
pub(crate) use self::wait_trace::reset_title_wait_statistics;
pub(crate) use self::wait_trace::service_cs_trace_wait_begin;
pub(crate) use self::wait_trace::service_cs_trace_wait_end;

mod error;
mod file_events;
mod log_engine;
mod notifications;
mod processors;
mod rpc;
mod swap;
mod tell_log;
mod wait_trace;

/// File system cache the pipe engine resizes.
const PIPE_CACHE: u32 = 2;

static TITLE_TERMINATE: NotificationRegistration = NotificationRegistration::new();

/// The server could not run its part of a title termination at once; it
/// runs it at its next pass.
static TITLE_TERMINATED: AtomicBool = AtomicBool::new(false);

/// Notification texts queued for the server thread.
static POSTED: SpinLock<PostedTexts> = SpinLock::new(PostedTexts::new());

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

impl commands::session::Backend for Console {
    fn allocate_debug_capture(&mut self) -> bool {
        /// Pool type the monitor allocates the ring from.
        const DEBUG_CAPTURE_POOL: PoolType = PoolType::System;

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
        let referenced = unsafe {
            xboxkrnl::ObReferenceObjectByHandle(Handle::CURRENT_THREAD, object_type, &mut thread)
        }
        .is_success();
        if !referenced {
            return;
        }

        let mut previous = 0u32;
        // SAFETY: `thread` is the referenced object of the calling thread,
        // released after use.
        unsafe {
            xboxkrnl::KeSetAffinityThread(
                thread as usize as *mut xboxkrnl::Kthread,
                1 << processor.0,
                &mut previous,
            );
            xboxkrnl::ObDereferenceObject(thread);
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

/// A text whose poster waits for the server thread to send it.
struct WaitingText {
    address: u32,
    length: u32,
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

/// Prepare the shared state; called once at module start, before the
/// control dispatcher is published.
pub(crate) fn initialize() {
    /// Priority 0x78 in the high byte, as stock's registration (0x91f97434).
    const TITLE_TERMINATE_PRIORITY: u32 = 0x7800_0000;

    rpc::initialize();
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

    if tell_log::worker().is_some_and(|worker| worker.get() == current_object().id().raw()) {
        return false;
    }

    let mut request = WaitingText {
        address: text.as_ptr() as usize as u32,
        length: text.len() as u32,
    };

    dispatcher::call_on_server_with(&mut request, send_waiting_text).is_some()
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
