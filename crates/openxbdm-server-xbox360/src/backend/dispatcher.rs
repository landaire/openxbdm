//! Debug monitor control dispatcher (stock 0x91f3b4d0), published at debug
//! monitor data +0x18. The kernel, the system software, and this module
//! call it with a code and an argument on arbitrary threads, so every
//! handler uses static state; requests that need the server's state are
//! queued for the server thread.

use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::Hresult;
use openxbdm_server::Server;
use openxbdm_server::commands::debugger;
use xbox360::console::hardware_flags;
use xbox360::time::relative_interval;
use xbox360::time::sleep;
use xbox360_sys::processor;
use xbox360_sys::processor::current_thread;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::WaitReason;

use super::Console;
use super::console;
use super::debugger as monitor;
use super::filesystem;
use super::hardware;
use super::memory;
use super::network;
use super::session;
use super::system;
use crate::kernel;
use crate::net::XamNetwork;

/// Settings must be written (stock signals the server thread to run
/// WriteIniFile).
static SETTINGS_WRITE: AtomicBool = AtomicBool::new(false);
/// The kernel polled for a debugger break-in while threads were stopped.
static BREAK_IN: AtomicBool = AtomicBool::new(false);
/// Code 0x63 asked to apply the persisted kd lite flag.
static KD_LITE_REFRESH: AtomicBool = AtomicBool::new(false);
/// Code 0xa4 value: first-chance breakpoint and trace exceptions pass
/// through without the debugger.
static TRAP_PASSTHROUGH: AtomicU32 = AtomicU32::new(0);
/// Mirrors of server state read by handlers. Each word stands alone, as
/// stock's plain globals, so the accesses need no ordering.
static KERNEL_DEBUGGER: AtomicBool = AtomicBool::new(true);
static DEBUGGER_ATTACHED: AtomicU32 = AtomicU32::new(0);
static DEBUGGER_ADDRESS: AtomicU32 = AtomicU32::new(0);
static DEBUGGER_PORT: AtomicU32 = AtomicU32::new(0);
static THREADS_STOPPED: AtomicBool = AtomicBool::new(false);

/// Ask the server thread to write the settings file.
pub(crate) fn request_settings_write() {
    SETTINGS_WRITE.store(true, Ordering::Release);
}

/// The attached debugger as `debugger` recorded it (stock 0x91f9fef8: flag,
/// address word, port).
pub(crate) struct PublishedDebugger {
    pub(crate) attached: u32,
    pub(crate) address: u32,
    pub(crate) port: u32,
}

pub(crate) fn published_debugger() -> PublishedDebugger {
    PublishedDebugger {
        attached: DEBUGGER_ATTACHED.load(Ordering::Relaxed),
        address: DEBUGGER_ADDRESS.load(Ordering::Relaxed),
        port: DEBUGGER_PORT.load(Ordering::Relaxed),
    }
}

fn passive() -> bool {
    processor::current_irql() == Irql::PASSIVE
}

/// A service run on the server thread with the server's state and the
/// request its caller posted. The result is the export's or control code's
/// return word: services convert typed results to it as their last step.
pub(crate) type ServerService<T> = fn(&mut Server, &mut Console, &mut XamNetwork, &mut T) -> u32;

/// A [`ServerService`] whose return word is an HRESULT.
pub(crate) type HresultService<T> =
    fn(&mut Server, &mut Console, &mut XamNetwork, &mut T) -> Hresult;

/// [`ServerService`] with the request type erased, as the request slots
/// carry it. `&mut T` and `NonNull<()>` are ABI-compatible arguments for a
/// sized `T`, so a `ServerService<T>` may be called through this type with
/// a pointer to a live `T`.
type ErasedService = fn(&mut Server, &mut Console, &mut XamNetwork, NonNull<()>) -> u32;

/// Where a request that a thread hands to the server thread stands. The
/// poster claims a free request, fills it and posts it; the server takes
/// it and completes it; the poster reads the result and frees it.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum HandoffState {
    Free = 0,
    /// Claimed by a poster, which owns every other field.
    Filling = 1,
    Posted = 2,
    /// The server thread runs the request.
    Taken = 3,
    /// The server stored the result.
    Completed = 4,
}

/// A [`HandoffState`] shared by the poster and the server thread.
#[repr(transparent)]
pub(crate) struct Handoff(AtomicU32);

impl Handoff {
    pub(crate) const fn new() -> Self {
        Self(AtomicU32::new(HandoffState::Free as u32))
    }

    #[inline(always)]
    pub(crate) fn is(&self, state: HandoffState, order: Ordering) -> bool {
        self.0.load(order) == state as u32
    }

    #[inline(always)]
    pub(crate) fn store(&self, state: HandoffState, order: Ordering) {
        self.0.store(state as u32, order);
    }

    /// Move from `from` to `to`; false when the state was not `from`.
    #[inline(always)]
    pub(crate) fn transition(
        &self,
        from: HandoffState,
        to: HandoffState,
        success: Ordering,
    ) -> bool {
        self.0
            .compare_exchange(from as u32, to as u32, success, Ordering::Relaxed)
            .is_ok()
    }
}

const REQUEST_SLOTS: usize = 4;

/// Argument of control code 0x35: the thread to name and the address of
/// the name.
#[repr(C)]
struct NameThreadRequest {
    thread: u32,
    name: u32,
}

/// A dispatcher request waiting for the server thread.
struct Request {
    state: Handoff,
    /// An [`ErasedService`].
    service: AtomicPtr<()>,
    argument: AtomicPtr<()>,
    result: AtomicU32,
    done: kernel::KernelEvent,
}

static REQUESTS: [Request; REQUEST_SLOTS] = [const {
    Request {
        state: Handoff::new(),
        service: AtomicPtr::new(core::ptr::null_mut()),
        argument: AtomicPtr::new(core::ptr::null_mut()),
        result: AtomicU32::new(0),
        done: kernel::KernelEvent::new(),
    }
}; REQUEST_SLOTS];
/// Thread object of the server thread, recorded at its first pass.
static SERVER_THREAD: AtomicU32 = AtomicU32::new(0);
/// The server stopped serving requests (control code 0x02 or unload).
static STOPPED: AtomicBool = AtomicBool::new(false);
/// Threads inside `call_on_server`; unload waits for them to leave.
static CALLERS: AtomicU32 = AtomicU32::new(0);
/// Interval at which a waiting caller checks whether the server stopped.
const STOP_CHECK_INTERVAL: i64 = relative_interval(Duration::from_millis(100));

/// Server state before the command loop owns it. Stock runs export and
/// control-code work inline on the calling thread; until the loop starts,
/// openxbdm does the same under `STARTUP_LOCK`, so callers that load during
/// boot (system software that imports this module) never wait for a thread
/// that is still starting the network. The state is a static built at
/// compile time; the server thread's stack could not hold it.
struct StartupHost {
    /// Set by the server thread; callers before it see no state.
    created: UnsafeCell<bool>,
    server: UnsafeCell<Server>,
    console: UnsafeCell<Console>,
}

// SAFETY: accessed only with `STARTUP_LOCK` held, or by the server thread
// alone once `SERVING` is set.
unsafe impl Sync for StartupHost {}

static STARTUP_HOST: StartupHost = StartupHost {
    created: UnsafeCell::new(false),
    server: UnsafeCell::new(Server::new()),
    console: UnsafeCell::new(Console::new()),
};
static STARTUP_LOCK: kernel::CriticalSection = kernel::CriticalSection::new();
/// The command loop owns the server state; requests are queued to it.
static SERVING: AtomicBool = AtomicBool::new(false);
/// Longest wait of a caller for the startup lock, and its poll interval.
const STARTUP_WAIT_MS: u32 = 5000;
const STARTUP_POLL_MS: u32 = 10;

/// Called once at module start, before any thread can call in.
pub(crate) fn initialize_host() {
    STARTUP_LOCK.initialize();
}

/// Make the server state available to callers.
pub(crate) fn create_host() {
    STARTUP_LOCK.enter();
    // SAFETY: the lock is held.
    unsafe { *STARTUP_HOST.created.get() = true };
    STARTUP_LOCK.leave();
}

/// The server state once created.
///
/// # Safety
///
/// `STARTUP_LOCK` is held, or the caller is the server thread after it set
/// `SERVING`; the references must not outlive that exclusivity.
unsafe fn host() -> Option<(&'static mut Server, &'static mut Console)> {
    // SAFETY: exclusivity per the contract.
    unsafe {
        (*STARTUP_HOST.created.get()).then(|| {
            (
                &mut *STARTUP_HOST.server.get(),
                &mut *STARTUP_HOST.console.get(),
            )
        })
    }
}

/// Run `operation` on the server state during startup.
pub(crate) fn with_startup_host<R>(
    operation: impl FnOnce(&mut Server, &mut Console) -> R,
) -> Option<R> {
    STARTUP_LOCK.enter();
    // SAFETY: the lock is held and the loop does not own the state yet.
    let result = match unsafe { host() } {
        Some((server, console)) if !SERVING.load(Ordering::Acquire) => {
            Some(operation(server, console))
        }
        _ => None,
    };
    STARTUP_LOCK.leave();
    result
}

/// Hand the server state to the command loop.
pub(crate) fn begin_serving() -> Option<(&'static mut Server, &'static mut Console)> {
    STARTUP_LOCK.enter();
    // SAFETY: the lock is held; after `SERVING` is set only the server
    // thread touches the state, which lives as long as the module.
    let result = unsafe { host() };
    if result.is_some() {
        SERVING.store(true, Ordering::Release);
    }
    STARTUP_LOCK.leave();
    result
}

/// Run `service` with the server's state and `request` and return its
/// result: inline while the command loop has not started, otherwise on the
/// server thread. `None` on the server thread, above passive level, before
/// the state exists, when the startup lock stays busy, or once the server
/// stopped.
///
/// `T` is not bound by `Send`: requests carry raw addresses of caller
/// records (`*mut` and `NonNull` fields) that the service dereferences
/// under the poster's own contract. The poster waits in this call until
/// the service returned, so one thread at a time uses the request, and the
/// service is a plain `fn` that keeps nothing of it after the call. A
/// request type must not depend on the thread that uses it (no
/// thread-affine guards, no `Rc`).
#[inline(always)]
pub(crate) fn call_on_server_with<T>(request: &mut T, service: ServerService<T>) -> Option<u32> {
    // SAFETY: `ServerService<T>` and `ErasedService` differ only in the
    // request argument, which is ABI-compatible; the service is called with
    // the address of `request`, which outlives the call.
    let service = unsafe { core::mem::transmute::<ServerService<T>, ErasedService>(service) };
    call_on_server(service, NonNull::from(request).cast())
}

/// [`call_on_server_with`] for a service that returns an HRESULT; the
/// result word converts back to it here.
#[inline(always)]
pub(crate) fn call_hresult_service<T>(
    request: &mut T,
    service: HresultService<T>,
) -> Option<Hresult> {
    // SAFETY: `Hresult` is `#[repr(transparent)]` over `u32`, so the two
    // function types differ only in an ABI-compatible return type.
    let service = unsafe { core::mem::transmute::<HresultService<T>, ServerService<T>>(service) };
    call_on_server_with(request, service).map(Hresult)
}

fn call_on_server(service: ErasedService, argument: NonNull<()>) -> Option<u32> {
    CALLERS.fetch_add(1, Ordering::AcqRel);
    let result = call_on_server_counted(service, argument);
    CALLERS.fetch_sub(1, Ordering::AcqRel);
    result
}

fn call_on_server_counted(service: ErasedService, argument: NonNull<()>) -> Option<u32> {
    // The debugger backend records the server thread before startup work
    // (settings, extension loads) that may call in; this module's copy is
    // set only at the first pass.
    let thread = current_thread();
    let server = thread == SERVER_THREAD.load(Ordering::Acquire)
        || monitor::server_thread().is_some_and(|server| server.get() == thread);
    if !passive() || server || STOPPED.load(Ordering::Acquire) {
        return None;
    }
    if !SERVING.load(Ordering::Acquire) {
        let mut network = XamNetwork;
        let mut waited_ms = 0;
        // The server thread holds the lock while it loads the settings,
        // which can load images; a caller inside the loader would then
        // wait on the server while the server waits on the loader, so the
        // wait is bounded.
        loop {
            if STARTUP_LOCK.try_enter() {
                let serving = SERVING.load(Ordering::Acquire);
                // SAFETY: the lock is held; the loop owns the state only
                // once `SERVING` is set, which takes the lock.
                let result = match unsafe { host() } {
                    Some((server, console)) if !serving => {
                        Some(service(server, console, &mut network, argument))
                    }
                    _ => None,
                };
                STARTUP_LOCK.leave();
                if !serving {
                    return result;
                }
                break;
            }
            if SERVING.load(Ordering::Acquire) {
                break;
            }
            if waited_ms >= STARTUP_WAIT_MS {
                return None;
            }
            sleep(Duration::from_millis(u64::from(STARTUP_POLL_MS)));
            waited_ms += STARTUP_POLL_MS;
        }
    }
    let request = loop {
        if STOPPED.load(Ordering::Acquire) {
            return None;
        }
        if let Some(request) = REQUESTS.iter().find(|request| {
            request
                .state
                .transition(HandoffState::Free, HandoffState::Filling, Ordering::Acquire)
        }) {
            break request;
        }
        sleep(Duration::from_millis(1));
    };
    request.done.initialize();
    request.service.store(service as *mut (), Ordering::Relaxed);
    request.argument.store(argument.as_ptr(), Ordering::Relaxed);
    request.state.store(HandoffState::Posted, Ordering::Release);
    while !request.state.is(HandoffState::Completed, Ordering::Acquire) {
        // SAFETY: `done` was initialized above and lives in a static slot.
        unsafe {
            xboxkrnl::KeWaitForSingleObject(
                request.done.pointer().cast(),
                WaitReason::Executive,
                ProcessorMode::Kernel,
                false,
                &STOP_CHECK_INTERVAL,
            )
        };
        let released = STOPPED.load(Ordering::Acquire);
        if released
            && request
                .state
                .transition(HandoffState::Posted, HandoffState::Free, Ordering::AcqRel)
        {
            return None;
        }
    }
    let result = request.result.load(Ordering::Relaxed);
    request.state.store(HandoffState::Free, Ordering::Release);
    Some(result)
}

/// The server thread is about to exit; later requests fail.
pub(crate) fn stop_serving() {
    STOPPED.store(true, Ordering::Release);
}

/// Wait until no thread runs in `call_on_server`; call after
/// [`stop_serving`] before the image unloads.
pub(crate) fn wait_for_callers() {
    while CALLERS.load(Ordering::Acquire) != 0 {
        sleep(Duration::from_millis(10));
    }
}

fn serve_requests(server: &mut Server, console: &mut Console, network: &mut XamNetwork) {
    SERVER_THREAD.store(current_thread(), Ordering::Release);
    for request in &REQUESTS {
        if !request
            .state
            .transition(HandoffState::Posted, HandoffState::Taken, Ordering::AcqRel)
        {
            continue;
        }
        // SAFETY: the poster stored an `ErasedService` function pointer.
        let service = unsafe {
            core::mem::transmute::<*mut (), ErasedService>(request.service.load(Ordering::Relaxed))
        };
        // SAFETY: the poster stored a pointer to its request, which it keeps
        // alive and untouched until the state reads completed.
        let argument = unsafe { NonNull::new_unchecked(request.argument.load(Ordering::Relaxed)) };
        let result = service(server, console, network, argument);
        request.result.store(result, Ordering::Relaxed);
        request
            .state
            .store(HandoffState::Completed, Ordering::Release);
        request.done.set();
    }
}

/// A debug monitor control code. The set is open: this module serves the
/// codes named here and passes the others to
/// [`super::performance::service`].
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ControlCode(u32);

impl ControlCode {
    /// The kernel polls for a debugger break-in.
    pub(crate) const BREAK_IN_POLL: Self = Self(0x01);
    pub(crate) const PREPARE_REBOOT: Self = Self(0x02);
    pub(crate) const SET_DRIVE_MAPPING: Self = Self(0x03);
    pub(crate) const MEMTRACK_RECORD_ALLOC: Self = Self(0x08);
    pub(crate) const MEMTRACK_RECORD_FREE: Self = Self(0x09);
    pub(crate) const DEBUGGER_ATTACHED: Self = Self(0x0a);
    pub(crate) const APPLY_XNET_CONFIG: Self = Self(0x0b);
    pub(crate) const SET_STATIC_IP_ENABLE: Self = Self(0x0c);
    pub(crate) const GET_STATIC_IP_ENABLE: Self = Self(0x0d);
    pub(crate) const SET_STATIC_IP_ADDRESS: Self = Self(0x0e);
    pub(crate) const GET_STATIC_IP_ADDRESS: Self = Self(0x0f);
    pub(crate) const SET_SUBNET: Self = Self(0x10);
    pub(crate) const GET_SUBNET: Self = Self(0x11);
    pub(crate) const SET_GATEWAY: Self = Self(0x12);
    pub(crate) const GET_GATEWAY: Self = Self(0x13);
    pub(crate) const CONFIG_STATUS_1: Self = Self(0x14);
    pub(crate) const CONFIG_STATUS_2: Self = Self(0x15);
    pub(crate) const CONFIG_STATUS_3: Self = Self(0x16);
    pub(crate) const WIPE_SETTINGS: Self = Self(0x17);
    pub(crate) const GET_MODULE_PROC_ADDRESS: Self = Self(0x18);
    /// Whether a debug break may stop the caller: at passive level, or
    /// with the kernel debugger enabled.
    pub(crate) const BREAK_ALLOWED: Self = Self(0x19);
    pub(crate) const REGISTER_PIX_PROCESSOR: Self = Self(0x1c);
    pub(crate) const WRITE_SETTINGS_COPY: Self = Self(0x1d);
    pub(crate) const SET_SYSTEM_SETTINGS: Self = Self(0x1e);
    pub(crate) const GET_SYSTEM_SETTINGS: Self = Self(0x1f);
    pub(crate) const REGISTER_XAM_GLOBALS: Self = Self(0x20);
    pub(crate) const TITLE_REBOOT: Self = Self(0x21);
    pub(crate) const CAPTURE_SETTINGS: Self = Self(0x22);
    pub(crate) const REGISTER_PROCESSOR: Self = Self(0x32);
    pub(crate) const GET_DEBUG_NAME: Self = Self(0x33);
    pub(crate) const NAME_CURRENT_THREAD: Self = Self(0x34);
    pub(crate) const NAME_THREAD: Self = Self(0x35);
    pub(crate) const ODD_READ_START: Self = Self(0x46);
    pub(crate) const ODD_READ_COMPLETE: Self = Self(0x47);
    pub(crate) const ODD_MOUNT: Self = Self(0x48);
    pub(crate) const ODD_SPEED_CHANGE: Self = Self(0x49);
    pub(crate) const ODD_AUTH_STATE: Self = Self(0x4a);
    pub(crate) const REFRESH_KD_LITE: Self = Self(0x63);
    pub(crate) const FILE_EVENT_BEGIN: Self = Self(0x64);
    pub(crate) const FILE_EVENT_END: Self = Self(0x65);
    pub(crate) const LAUNCH_OVERRIDE: Self = Self(0x77);
    pub(crate) const AUTOMATION_GET_STATE: Self = Self(0x7a);
    pub(crate) const AUTOMATION_GET_STATUS: Self = Self(0x7b);
    pub(crate) const AUTOMATION_GET_CAPABILITIES: Self = Self(0x7c);
    pub(crate) const DVD_EMULATOR_STATE: Self = Self(0x7e);
    pub(crate) const CRITICAL_SECTION_WAIT_BEGIN: Self = Self(0x81);
    pub(crate) const CRITICAL_SECTION_WAIT_END: Self = Self(0x82);
    pub(crate) const ADJUST_MEMORY_STATISTICS: Self = Self(0x86);
    pub(crate) const TELL_LOG_RECORD: Self = Self(0x88);
    pub(crate) const TELL_LOG_ENTRY_SIZE: Self = Self(0x89);
    pub(crate) const TELL_LOG_AREAS: Self = Self(0x8a);
    pub(crate) const NUI_CAM_COMPLETE_RAW_DATA: Self = Self(0x96);
    pub(crate) const NUI_CAM_QUEUE_RAW_DATA: Self = Self(0x97);
    pub(crate) const NUI_CAM_FLUSH_RAW_DATA: Self = Self(0x98);
    pub(crate) const NUI_CAM_SET_CAPTURE_MODE: Self = Self(0xa1);
    pub(crate) const SET_TRAP_PASSTHROUGH: Self = Self(0xa4);
    pub(crate) const HTTP_PROXY_ACQUIRE: Self = Self(0xa5);
    pub(crate) const HTTP_PROXY_RELEASE: Self = Self(0xa6);
    pub(crate) const HTTP_PROXY_CERTIFICATE: Self = Self(0xa7);
    pub(crate) const RPC_DRAIN: Self = Self(0xa8);
    pub(crate) const SEND_NOTIFICATION: Self = Self(0xa9);
    pub(crate) const PIX_POST_TEXT: Self = Self(0x1b);
    pub(crate) const PIX_WRITE_DWORD: Self = Self(0x27);
    pub(crate) const PIX_FRAME: Self = Self(0x2e);
    pub(crate) const PIX_REGISTER_CALLBACK: Self = Self(0x2f);
    pub(crate) const PIX_UNREGISTER_CALLBACK: Self = Self(0x30);
    pub(crate) const XTRACE_START: Self = Self(0x38);
    pub(crate) const XTRACE_STOP: Self = Self(0x39);
    pub(crate) const XTRACE_INSTRUCTION_COUNT: Self = Self(0x3a);
    pub(crate) const XTRACE_REQUEST_STOP: Self = Self(0x3b);
    pub(crate) const PIX_THREAD_SLOT: Self = Self(0x3c);
    pub(crate) const PIX_SET_DISCARD_OUTPUT: Self = Self(0x3f);
    pub(crate) const PIX_UNREGISTER_CONSUMER: Self = Self(0x41);
    pub(crate) const PIX_REGISTER_CONSUMER: Self = Self(0x42);
    pub(crate) const PIX_WRITE_BLOCK: Self = Self(0x43);
    pub(crate) const PIX_STATE_FLAGS: Self = Self(0x44);
    pub(crate) const PIX_FILTER_CONTROL: Self = Self(0x45);
    pub(crate) const PIX_TIMING_REQUEST: Self = Self(0x50);
    pub(crate) const PIX_FRAME_BUFFER: Self = Self(0x51);
    pub(crate) const PIX_FRAME_RECORD: Self = Self(0x52);
    pub(crate) const PIX_OPEN_FOR_CAPTURE: Self = Self(0x53);
    pub(crate) const PIX_OPEN_FOR_START: Self = Self(0x54);
    pub(crate) const PIX_WRITE_CAPTURE_RECORD: Self = Self(0x55);
    pub(crate) const PIX_CONFIGURE: Self = Self(0x56);
    pub(crate) const PIX_QUEUE_MESSAGE: Self = Self(0x57);
    pub(crate) const PIX_REGISTER_PERSISTENT_CONSUMER: Self = Self(0x58);
    pub(crate) const PIX_ACQUIRE_OWNER: Self = Self(0x59);
    pub(crate) const PIX_RELEASE_OWNER: Self = Self(0x5a);
    pub(crate) const PIX_SAMPLES: Self = Self(0x5b);
    pub(crate) const PIX_COMMAND_BUFFERS: Self = Self(0x5c);
    pub(crate) const PIX_FENCE: Self = Self(0x5d);
    pub(crate) const PIX_WRITE_BLOCK_LIST: Self = Self(0x5e);
    pub(crate) const PIX_DISK_START: Self = Self(0x7f);
    pub(crate) const PIX_DISK_COMPLETE: Self = Self(0x80);
    pub(crate) const PIX_RESOURCE_BEGIN: Self = Self(0x83);
    pub(crate) const PIX_RESOURCE_RECORD: Self = Self(0x84);
    pub(crate) const PIX_RESOURCE_END: Self = Self(0x85);
    pub(crate) const PIX_RESOURCE_INFORMATION: Self = Self(0x87);
    pub(crate) const PIX_NUICAM_BEGIN: Self = Self(0x8d);
    pub(crate) const PIX_END: Self = Self(0x8e);
    pub(crate) const STUDIO_SET_DEVICE_STATUS: Self = Self(0x99);
    pub(crate) const STUDIO_SET_TEST_MODE: Self = Self(0x9f);

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

/// Run one control code from this module and pass the result through the
/// extension hook, as stock's calls through the data block do.
///
/// # Safety
///
/// `argument` must meet the contract of the service of `code`, as a
/// caller through the debug monitor data must.
pub(crate) unsafe fn dispatch(code: ControlCode, argument: u32) -> u32 {
    let stack: u32;
    // SAFETY: reads r1.
    unsafe { core::arch::asm!("mr {0}, 1", out(reg) stack) };
    // SAFETY: the caller's contract.
    unsafe { dispatch_with_stack(code.raw(), argument, stack) }
}

crate::exports::bridged!(dispatch_bridge, dispatch_with_stack);

/// Entry published to the kernel: passes the caller's stack pointer on,
/// for handlers that walk the caller's frames. The bridge passes r3-r10
/// through unchanged.
#[unsafe(naked)]
unsafe extern "C" fn dispatch_entry() {
    core::arch::naked_asm!("mr 5, 1", "b {target}", target = sym dispatch_bridge)
}

/// # Safety
///
/// As for [`dispatch`]; the kernel and titles call the published entry
/// under the same contract.
unsafe extern "C" fn dispatch_with_stack(code: u32, argument: u32, entry_stack: u32) -> u32 {
    use ControlCode as C;
    let code = ControlCode(code);
    let result = match code {
        C::BREAK_IN_POLL => {
            // When threads are stopped by the monitor the kernel debugger
            // takes over and the threads run again.
            if THREADS_STOPPED.load(Ordering::Relaxed) {
                BREAK_IN.store(true, Ordering::Release);
            }
            0
        }
        C::PREPARE_REBOOT => {
            // The server's copy of this flag is refreshed from it.
            TRAP_PASSTHROUGH.store(0, Ordering::Relaxed);
            system::service_prepare_reboot(argument)
        }
        C::SET_DRIVE_MAPPING => {
            let mut request = argument;
            call_on_server_with(&mut request, filesystem::service_set_drive_mapping).unwrap_or(0)
        }
        // SAFETY (each arm that calls an unsafe service): the caller's
        // contract gives `argument` the meaning the service of the code
        // requires.
        C::MEMTRACK_RECORD_ALLOC => unsafe { memory::service_memtrack_record_alloc(argument) },
        C::MEMTRACK_RECORD_FREE => unsafe { memory::service_memtrack_record_free(argument) },
        C::DEBUGGER_ATTACHED => DEBUGGER_ATTACHED.load(Ordering::Relaxed),
        C::APPLY_XNET_CONFIG => network::service_apply_xnet_config(argument),
        C::SET_STATIC_IP_ENABLE => network::service_set_static_ip_enable(argument),
        C::GET_STATIC_IP_ENABLE => network::service_get_static_ip_enable(argument),
        C::SET_STATIC_IP_ADDRESS => network::service_set_static_ip_address(argument),
        C::GET_STATIC_IP_ADDRESS => network::service_get_static_ip_address(argument),
        C::SET_SUBNET => network::service_set_subnet(argument),
        C::GET_SUBNET => network::service_get_subnet(argument),
        C::SET_GATEWAY => network::service_set_gateway(argument),
        C::GET_GATEWAY => network::service_get_gateway(argument),
        C::CONFIG_STATUS_1 => network::service_config_status_1(argument),
        C::CONFIG_STATUS_2 => network::service_config_status_2(argument),
        C::CONFIG_STATUS_3 => network::service_config_status_3(argument),
        C::WIPE_SETTINGS => system::service_wipe_settings(argument),
        C::GET_MODULE_PROC_ADDRESS => unsafe { memory::service_get_module_proc_address(argument) },
        C::BREAK_ALLOWED => {
            let kd = KERNEL_DEBUGGER.load(Ordering::Relaxed)
                && hardware_flags().contains(HardwareFlags::KERNEL_DEBUGGER);
            u32::from(passive() || kd)
        }
        C::REGISTER_PIX_PROCESSOR => unsafe { session::service_register_pix_processor(argument) },
        C::WRITE_SETTINGS_COPY => unsafe { system::service_write_settings_copy(argument) },
        C::SET_SYSTEM_SETTINGS => unsafe { console::service_set_system_settings(argument) },
        C::GET_SYSTEM_SETTINGS => unsafe { console::service_get_system_settings(argument) },
        C::REGISTER_XAM_GLOBALS => unsafe { system::service_register_xam_globals(argument) },
        C::TITLE_REBOOT => {
            hardware::service_automation_rebind(argument);
            unsafe { system::service_title_reboot(argument) }
        }
        C::CAPTURE_SETTINGS => unsafe { system::service_capture_settings(argument) },
        C::REGISTER_PROCESSOR => unsafe { session::service_register_processor(argument) },
        C::GET_DEBUG_NAME => unsafe { console::service_get_debug_name(argument) },
        C::NAME_CURRENT_THREAD => {
            unsafe { monitor::name_thread(None, argument) };
            0
        }
        C::NAME_THREAD => {
            // SAFETY: the caller passes the address of a `NameThreadRequest`
            // whose name is 0 or a NUL-terminated string, both valid for
            // the call.
            unsafe {
                let request = kernel::object_at::<NameThreadRequest>(argument);
                monitor::name_thread(Some(debugger::ThreadId(request.thread)), request.name);
            }
            0
        }
        C::ODD_READ_START => unsafe { hardware::service_odd_read_start(argument) },
        C::ODD_READ_COMPLETE => hardware::service_odd_read_complete(argument),
        C::ODD_MOUNT => unsafe { hardware::service_odd_mount(argument) },
        C::ODD_SPEED_CHANGE => unsafe { hardware::service_odd_speed_change(argument) },
        C::ODD_AUTH_STATE => hardware::service_odd_auth_state(argument),
        C::FILE_EVENT_BEGIN => unsafe { session::service_file_event_begin(argument) },
        C::FILE_EVENT_END => unsafe { session::service_file_event_end(argument) },
        C::CRITICAL_SECTION_WAIT_BEGIN => unsafe {
            session::service_cs_trace_wait_begin(argument, entry_stack)
        },
        C::CRITICAL_SECTION_WAIT_END => unsafe {
            session::service_cs_trace_wait_end(argument, entry_stack)
        },
        C::TELL_LOG_RECORD => unsafe { session::service_tell_log_record(argument) },
        C::TELL_LOG_ENTRY_SIZE => session::service_tell_log_entry_size(argument),
        C::TELL_LOG_AREAS => session::service_tell_log_area(argument),
        C::RPC_DRAIN => unsafe { session::service_rpc_drain(argument) },
        C::SEND_NOTIFICATION => unsafe { session::service_send_notification(argument) },
        C::REFRESH_KD_LITE => {
            if hardware_flags().contains(xboxkrnl::HardwareFlags::TEST_KIT) {
                KD_LITE_REFRESH.store(true, Ordering::Release);
            }
            0
        }
        C::LAUNCH_OVERRIDE => unsafe { system::service_launch_override(argument) },
        C::AUTOMATION_GET_STATE => unsafe { hardware::service_automation_get_state(argument) },
        C::AUTOMATION_GET_STATUS => unsafe { hardware::service_automation_get_status(argument) },
        C::AUTOMATION_GET_CAPABILITIES => unsafe {
            hardware::service_automation_get_capabilities(argument)
        },
        C::DVD_EMULATOR_STATE => match filesystem::service_dvd_emulator_state(argument) {
            0 => hardware::service_ignore_gdf_attributes(argument),
            emulator => emulator,
        },
        C::ADJUST_MEMORY_STATISTICS => unsafe {
            memory::service_adjust_memory_statistics(argument)
        },
        C::NUI_CAM_COMPLETE_RAW_DATA => unsafe {
            hardware::nuicam::service_complete_raw_data_request(argument)
        },
        C::NUI_CAM_QUEUE_RAW_DATA => unsafe {
            hardware::nuicam::service_queue_raw_data_request(argument)
        },
        C::NUI_CAM_FLUSH_RAW_DATA => hardware::nuicam::service_flush_raw_data_requests(argument),
        C::NUI_CAM_SET_CAPTURE_MODE => unsafe {
            hardware::nuicam::service_set_capture_mode(argument)
        },
        C::SET_TRAP_PASSTHROUGH => {
            TRAP_PASSTHROUGH.store(u32::from(argument != 0), Ordering::Relaxed);
            0
        }
        C::HTTP_PROXY_ACQUIRE => unsafe {
            network::xhttpproxy::service_http_proxy_acquire(argument)
        },
        C::HTTP_PROXY_RELEASE => unsafe {
            network::xhttpproxy::service_http_proxy_release(argument)
        },
        C::HTTP_PROXY_CERTIFICATE => unsafe {
            network::xhttpproxy::service_http_proxy_certificate(argument)
        },
        // 0x60 to 0x62 are empty routines; the remaining codes take the
        // monitor's default exit unless they are performance or PIX codes.
        _ => unsafe { super::performance::service(code, argument) }.unwrap_or(0),
    };
    monitor::tell_extension(code, argument, result)
}

/// Publish the dispatcher in the debug monitor data.
pub(crate) fn install() {
    // SAFETY: `dispatch_entry` enters `dispatch_with_stack` in the console
    // ABI with the code and argument in r3 and r4, and it is part of the
    // module, which outlives the published block.
    unsafe {
        kernel::publish_debug_monitor_dispatcher(dispatch_entry as *const () as usize as u32)
    };
}

/// Apply queued requests on the server thread and refresh the mirrors the
/// handlers read.
pub(crate) fn drain(server: &mut Server, console: &mut Console, network: &mut XamNetwork) {
    server.state.debugger.trap_passthrough = TRAP_PASSTHROUGH.load(Ordering::Relaxed) != 0;
    if KD_LITE_REFRESH.swap(false, Ordering::AcqRel) {
        debugger::refresh_kd_lite(&mut server.state, console);
    }
    if BREAK_IN.swap(false, Ordering::AcqRel) {
        let flags = &kernel::hardware_info().flags;
        // SAFETY: the monitor sets the kernel debugger bit on a break-in, as
        // stock does; the kernel only reads the word.
        unsafe {
            flags.store(
                flags.load(Ordering::Relaxed) | HardwareFlags::KERNEL_DEBUGGER.bits(),
                Ordering::Relaxed,
            )
        };
        debugger::break_in(&mut server.state, console, network);
    }
    // The server's timer pass writes dirty settings.
    if SETTINGS_WRITE.swap(false, Ordering::AcqRel) {
        server.state.settings_dirty = true;
    }
    if session::take_title_terminated() {
        server.title_terminated(console, network);
    }
    // Texts a requester posted before its request go out first.
    server.drain_posted_notifications(console, network);
    monitor::apply_pending_stop_on(&mut server.state);
    serve_requests(server, console, network);
    super::dvd_hotplug::drain(server, console);
    let state = &server.state.debugger;
    // Without a persisted setting the boot-time kernel debugger flag
    // applies, as the server's own default.
    let kd = state
        .kernel_debugger
        .unwrap_or(hardware_flags().contains(HardwareFlags::KERNEL_DEBUGGER_ENABLED));
    KERNEL_DEBUGGER.store(kd, Ordering::Relaxed);
    DEBUGGER_ADDRESS.store(state.debugger.address, Ordering::Relaxed);
    DEBUGGER_PORT.store(state.debugger.port, Ordering::Relaxed);
    DEBUGGER_ATTACHED.store(u32::from(state.debugger.attached), Ordering::Relaxed);
    THREADS_STOPPED.store(debugger::threads_stopped(&server.state), Ordering::Relaxed);
}
