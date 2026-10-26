mod error;

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;

use crate::kernel;
use crate::override_module::remove_override_module;
use crate::serve::run_server;

pub(crate) use self::error::ThreadCreationFailed;

/// Exit code of the server and recovery threads.
pub(crate) const THREAD_EXIT_CODE: u32 = 0;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
/// The server or recovery thread, or `Handle::NULL` when none runs.
static THREAD_HANDLE: AtomicU32 = AtomicU32::new(Handle::NULL.raw());

pub(crate) fn shutting_down() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Stop the server thread after its current pass (control code 0x02).
pub(crate) fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Take ownership of the running server or recovery thread handle.
pub(crate) fn take_thread_handle() -> Handle {
    Handle::from_raw(THREAD_HANDLE.swap(Handle::NULL.raw(), Ordering::SeqCst))
}

pub(crate) fn start_thread(entry: extern "C" fn(u32) -> u32) -> Result<(), ThreadCreationFailed> {
    /// Stack of stock's server thread (docs framework notes). The server
    /// state is static, and no frame on this thread may hold large buffers.
    const SERVER_STACK_SIZE: u32 = 0x8000;
    /// `ExCreateThread` flags of stock's server thread (docs framework
    /// notes). The server thread is not debuggable, so its own thread
    /// notifications never wait for it.
    const SERVER_THREAD_FLAGS: ThreadCreationFlags =
        kernel::SYSTEM_THREAD_FLAGS.union(ThreadCreationFlags::NOT_DEBUGGABLE);

    SHUTDOWN.store(false, Ordering::SeqCst);

    let mut handle = Handle::NULL.raw();
    let entry = entry as *const () as usize as u32;
    // SAFETY: `handle` is a live local and `entry` is a thread routine
    // with the start signature.
    let status = unsafe {
        xboxkrnl::ExCreateThread(
            &mut handle,
            SERVER_STACK_SIZE,
            core::ptr::null_mut(),
            0,
            entry,
            0,
            SERVER_THREAD_FLAGS,
        )
    };
    if status.result().is_err() {
        kernel::debug_print(c"openxbdm: server thread creation failed\n");
        return Err(ThreadCreationFailed);
    }

    THREAD_HANDLE.store(handle, Ordering::SeqCst);
    kernel::debug_print(c"openxbdm: server thread started\n");

    Ok(())
}

pub(crate) extern "C" fn server_thread(_context: u32) -> u32 {
    // Recorded first: debug prints and calls from this thread must
    // never wait for the server.
    crate::backend::debugger::set_server_thread();
    crate::backend::dispatcher::create_host();

    remove_override_module();
    if !shutting_down() {
        run_server();
    }

    stop_server_services();
    // SAFETY: called on the server thread, which owns no further state.
    unsafe { xboxkrnl::ExTerminateThread(THREAD_EXIT_CODE) }
}

/// Later calls and events take their default without waiting.
pub(crate) fn stop_server_services() {
    crate::backend::dispatcher::stop_serving();
    crate::backend::debugger::end_event_service();
}
