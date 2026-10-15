//! Debug monitor control dispatcher (stock 0x91f3b4d0), published at debug
//! monitor data +0x18. The kernel, the system software, and this module
//! call it with a code and an argument on arbitrary threads, so every
//! handler uses static state; requests that need the server's state are
//! queued for the server thread.

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::Server;
use openxbdm_server::commands::debugger;

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
use crate::kernel::current_thread;
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
/// Mirrors of server state read by handlers.
static KERNEL_DEBUGGER: AtomicBool = AtomicBool::new(true);
static DEBUGGER_ATTACHED: AtomicU32 = AtomicU32::new(0);
static DEBUGGER_ADDRESS: AtomicU32 = AtomicU32::new(0);
static DEBUGGER_PORT: AtomicU32 = AtomicU32::new(0);
static THREADS_STOPPED: AtomicBool = AtomicBool::new(false);

/// Hardware flag set by a kernel debugger break-in.
const HARDWARE_KERNEL_DEBUGGER: u32 = 0x100;

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
        attached: DEBUGGER_ATTACHED.load(Ordering::Acquire),
        address: DEBUGGER_ADDRESS.load(Ordering::Acquire),
        port: DEBUGGER_PORT.load(Ordering::Acquire),
    }
}

fn passive() -> bool {
    kernel::current_irql() == 0
}

/// A service run on the server thread with the server's state.
pub(crate) type ServerService = fn(&mut Server, &mut Console, &mut XamNetwork, u32) -> u32;

const REQUEST_FREE: u32 = 0;
const REQUEST_FILLING: u32 = 1;
const REQUEST_POSTED: u32 = 2;
const REQUEST_TAKEN: u32 = 3;
const REQUEST_COMPLETED: u32 = 4;
const REQUEST_SLOTS: usize = 4;

/// A dispatcher request waiting for the server thread.
struct Request {
    state: AtomicU32,
    service: AtomicU32,
    argument: AtomicU32,
    result: AtomicU32,
    done: kernel::KernelEvent,
}

static REQUESTS: [Request; REQUEST_SLOTS] = [const {
    Request {
        state: AtomicU32::new(REQUEST_FREE),
        service: AtomicU32::new(0),
        argument: AtomicU32::new(0),
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
/// Interval at which a waiting caller checks whether the server stopped,
/// in 100 ns units (negative: relative).
const STOP_CHECK_INTERVAL: i64 = -100 * 10_000;

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

/// Run `service` with the server's state and return its result: inline
/// while the command loop has not started, otherwise on the server thread.
/// `None` on the server thread, above passive level, before the state
/// exists, when the startup lock stays busy, or once the server stopped.
pub(crate) fn call_on_server(service: ServerService, argument: u32) -> Option<u32> {
    CALLERS.fetch_add(1, Ordering::AcqRel);
    let result = call_on_server_counted(service, argument);
    CALLERS.fetch_sub(1, Ordering::AcqRel);
    result
}

fn call_on_server_counted(service: ServerService, argument: u32) -> Option<u32> {
    // The debugger backend records the server thread before startup work
    // (settings, extension loads) that may call in; this module's copy is
    // set only at the first pass.
    let thread = current_thread();
    let server =
        thread == SERVER_THREAD.load(Ordering::Acquire) || thread == monitor::server_thread();
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
            kernel::sleep_milliseconds(STARTUP_POLL_MS);
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
                .compare_exchange(
                    REQUEST_FREE,
                    REQUEST_FILLING,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
        }) {
            break request;
        }
        kernel::sleep_milliseconds(1);
    };
    request.done.initialize();
    request
        .service
        .store(service as usize as u32, Ordering::Relaxed);
    request.argument.store(argument, Ordering::Relaxed);
    request.state.store(REQUEST_POSTED, Ordering::Release);
    while request.state.load(Ordering::Acquire) != REQUEST_COMPLETED {
        kernel::KeWaitForSingleObject(request.done.pointer(), 0, 0, 0, &STOP_CHECK_INTERVAL);
        let released = STOPPED.load(Ordering::Acquire);
        if released
            && request
                .state
                .compare_exchange(
                    REQUEST_POSTED,
                    REQUEST_FREE,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            return None;
        }
    }
    let result = request.result.load(Ordering::Relaxed);
    request.state.store(REQUEST_FREE, Ordering::Release);
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
        kernel::sleep_milliseconds(10);
    }
}

fn serve_requests(server: &mut Server, console: &mut Console, network: &mut XamNetwork) {
    SERVER_THREAD.store(current_thread(), Ordering::Release);
    for request in &REQUESTS {
        if request
            .state
            .compare_exchange(
                REQUEST_POSTED,
                REQUEST_TAKEN,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            continue;
        }
        // SAFETY: the poster stored a `ServerService` function pointer.
        let service: ServerService =
            unsafe { core::mem::transmute(request.service.load(Ordering::Relaxed) as usize) };
        let result = service(
            server,
            console,
            network,
            request.argument.load(Ordering::Relaxed),
        );
        request.result.store(result, Ordering::Relaxed);
        request.state.store(REQUEST_COMPLETED, Ordering::Release);
        request.done.set();
    }
}

/// Run one control code from this module and pass the result through the
/// extension hook, as stock's calls through the data block do.
pub(crate) fn dispatch(code: u32, argument: u32) -> u32 {
    let stack: u32;
    // SAFETY: reads r1.
    unsafe { core::arch::asm!("mr {0}, 1", out(reg) stack) };
    dispatch_with_stack(code, argument, stack)
}

crate::exports::bridged!(dispatch_bridge, dispatch_with_stack);

/// Entry published to the kernel: passes the caller's stack pointer on,
/// for handlers that walk the caller's frames. The bridge passes r3-r10
/// through unchanged.
#[unsafe(naked)]
unsafe extern "C" fn dispatch_entry() {
    core::arch::naked_asm!("mr 5, 1", "b {target}", target = sym dispatch_bridge)
}

extern "C" fn dispatch_with_stack(code: u32, argument: u32, entry_stack: u32) -> u32 {
    let result = match code {
        0x01 => {
            // Break-in poll: when threads are stopped by the monitor the
            // kernel debugger takes over and the threads run again.
            if THREADS_STOPPED.load(Ordering::Acquire) {
                BREAK_IN.store(true, Ordering::Release);
            }
            0
        }
        0x02 => {
            // The server's copy of this flag is refreshed from it.
            TRAP_PASSTHROUGH.store(0, Ordering::Release);
            system::service_prepare_reboot(argument)
        }
        0x03 => call_on_server(filesystem::service_set_drive_mapping, argument).unwrap_or(0),
        0x08 => memory::service_memtrack_record_alloc(argument),
        0x09 => memory::service_memtrack_record_free(argument),
        0x0a => DEBUGGER_ATTACHED.load(Ordering::Acquire),
        0x0b => network::service_apply_xnet_config(argument),
        0x0c => network::service_set_static_ip_enable(argument),
        0x0d => network::service_get_static_ip_enable(argument),
        0x0e => network::service_set_static_ip_address(argument),
        0x0f => network::service_get_static_ip_address(argument),
        0x10 => network::service_set_subnet(argument),
        0x11 => network::service_get_subnet(argument),
        0x12 => network::service_set_gateway(argument),
        0x13 => network::service_get_gateway(argument),
        0x14 => network::service_config_status_1(argument),
        0x15 => network::service_config_status_2(argument),
        0x16 => network::service_config_status_3(argument),
        0x17 => system::service_wipe_settings(argument),
        0x18 => memory::service_get_module_proc_address(argument),
        0x19 => {
            let kd = KERNEL_DEBUGGER.load(Ordering::Acquire)
                && kernel::hardware_flags() & HARDWARE_KERNEL_DEBUGGER != 0;
            u32::from(passive() || kd)
        }
        0x1c => session::service_register_pix_processor(argument),
        0x1d => system::service_write_settings_copy(argument),
        0x1e => console::service_set_system_settings(argument),
        0x1f => console::service_get_system_settings(argument),
        0x20 => system::service_register_xam_globals(argument),
        0x21 => {
            hardware::service_automation_rebind(argument);
            system::service_title_reboot(argument)
        }
        0x22 => system::service_capture_settings(argument),
        0x32 => session::service_register_processor(argument),
        0x33 => console::service_get_debug_name(argument),
        0x34 => {
            monitor::name_thread(None, argument);
            0
        }
        0x35 => {
            // SAFETY: the caller passes `{thread id, name}`.
            let (thread, name) = unsafe {
                let words = argument as usize as *const u32;
                (
                    core::ptr::read_volatile(words),
                    core::ptr::read_volatile(words.add(1)),
                )
            };
            monitor::name_thread(Some(debugger::ThreadId(thread)), name);
            0
        }
        0x46 => hardware::service_odd_read_start(argument),
        0x47 => hardware::service_odd_read_complete(argument),
        0x48 => hardware::service_odd_mount(argument),
        0x49 => hardware::service_odd_speed_change(argument),
        0x4a => hardware::service_odd_auth_state(argument),
        0x64 => session::service_file_event_begin(argument),
        0x65 => session::service_file_event_end(argument),
        0x81 => session::service_cs_trace_wait_begin(argument, entry_stack),
        0x82 => session::service_cs_trace_wait_end(argument, entry_stack),
        0x88 => session::service_tell_log_record(argument),
        0x89 => session::service_tell_log_entry_size(argument),
        0x8a => session::service_tell_log_area(argument),
        0xa8 => session::service_rpc_drain(argument),
        0xa9 => session::service_send_notification(argument),
        0x63 => {
            if kernel::hardware_flags() & debugger::HARDWARE_KD_LITE != 0 {
                KD_LITE_REFRESH.store(true, Ordering::Release);
            }
            0
        }
        0x77 => system::service_launch_override(argument),
        0x7a => hardware::service_automation_get_state(argument),
        0x7b => hardware::service_automation_get_status(argument),
        0x7c => hardware::service_automation_get_capabilities(argument),
        0x7e => match filesystem::service_dvd_emulator_state(argument) {
            0 => hardware::service_ignore_gdf_attributes(argument),
            emulator => emulator,
        },
        0x86 => memory::service_adjust_memory_statistics(argument),
        0x96 => hardware::nuicam::service_complete_raw_data_request(argument),
        0x97 => hardware::nuicam::service_queue_raw_data_request(argument),
        0x98 => hardware::nuicam::service_flush_raw_data_requests(argument),
        0xa1 => hardware::nuicam::service_set_capture_mode(argument),
        0xa4 => {
            TRAP_PASSTHROUGH.store(u32::from(argument != 0), Ordering::Release);
            0
        }
        0xa5 => network::xhttpproxy::service_http_proxy_acquire(argument),
        0xa6 => network::xhttpproxy::service_http_proxy_release(argument),
        0xa7 => network::xhttpproxy::service_http_proxy_certificate(argument),
        // 0x60 to 0x62 are empty routines; the remaining codes take the
        // monitor's default exit unless they are performance or PIX codes.
        _ => super::performance::service(code, argument).unwrap_or(0),
    };
    monitor::tell_extension(code, argument, result)
}

/// Publish the dispatcher in the debug monitor data.
pub(crate) fn install() {
    kernel::publish_debug_monitor_dispatcher(dispatch_entry as *const () as usize as u32);
}

/// Apply queued requests on the server thread and refresh the mirrors the
/// handlers read.
pub(crate) fn drain(server: &mut Server, console: &mut Console, network: &mut XamNetwork) {
    server.state.debugger.trap_passthrough = TRAP_PASSTHROUGH.load(Ordering::Acquire) != 0;
    if KD_LITE_REFRESH.swap(false, Ordering::AcqRel) {
        debugger::refresh_kd_lite(&mut server.state, console);
    }
    if BREAK_IN.swap(false, Ordering::AcqRel) {
        kernel::set_hardware_flags(kernel::hardware_flags() | HARDWARE_KERNEL_DEBUGGER);
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
    let kd = state
        .kernel_debugger
        .unwrap_or(kernel::hardware_flags() & debugger::HARDWARE_KD_ENABLED != 0);
    KERNEL_DEBUGGER.store(kd, Ordering::Release);
    DEBUGGER_ADDRESS.store(state.debugger.address, Ordering::Release);
    DEBUGGER_PORT.store(state.debugger.port, Ordering::Release);
    DEBUGGER_ATTACHED.store(u32::from(state.debugger.attached), Ordering::Release);
    THREADS_STOPPED.store(debugger::threads_stopped(&server.state), Ordering::Release);
}
