#[cfg(feature = "boot-guard")]
use core::sync::atomic::Ordering;

use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Boolean;
use xbox360_sys::xboxkrnl::DllEntryReason;
use xbox360_sys::xboxkrnl::ProcessorMode;

use crate::kernel;
#[cfg(feature = "boot-guard")]
use crate::override_module::Removal;
#[cfg(feature = "boot-guard")]
use crate::override_module::delete_file;
#[cfg(feature = "boot-guard")]
use crate::override_module::remove_override_module;
use crate::serve::close_listener;
#[cfg(feature = "boot-guard")]
use crate::thread::THREAD_EXIT_CODE;
use crate::thread::request_shutdown;
use crate::thread::server_thread;
use crate::thread::start_thread;
use crate::thread::stop_server_services;
use crate::thread::take_thread_handle;

/// Module entry point named by the linker script. The loader calls it
/// with the console ABI, so it runs `module_entry` behind the bridge.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn _start() {
    core::arch::naked_asm!(
        "lis 12, {target}@ha",
        "addi 12, 12, {target}@l",
        "b {bridge}",
        target = sym module_entry,
        bridge = sym xbox360_sys::entry_bridge,
    )
}

extern "C" fn module_entry(module: u32, reason: u32, _reserved: u32) -> Boolean {
    let succeeded = match DllEntryReason::from_raw(reason) {
        Some(DllEntryReason::ProcessDetach) => {
            unload();
            true
        }
        Some(DllEntryReason::ProcessAttach) => load(module),
        // Other reasons need no work.
        _ => true,
    };

    Boolean::from(succeeded)
}

#[inline(always)]
fn unload() {
    request_shutdown();
    close_listener();
    #[cfg(feature = "smb")]
    crate::smb::close_listener();

    let handle = take_thread_handle();
    if !handle.is_null() {
        // Commands on the server thread can arm engine hooks, so the
        // engines stop only after it has exited.
        // SAFETY: the handle came from `ExCreateThread` and the swap
        // in `take_thread_handle` makes this the only owner.
        unsafe {
            xboxkrnl::NtWaitForSingleObjectEx(
                handle,
                ProcessorMode::Kernel,
                false,
                core::ptr::null(),
            );
            xboxkrnl::NtClose(handle);
        }
    }

    stop_server_services();
    crate::backend::debugger::uninstall();
    crate::backend::session::uninstall();
    crate::backend::performance::shut_down();
    crate::backend::dispatcher::wait_for_callers();
    crate::backend::debugger::wait_for_event_waiters();
}

/// Whether the module stays loaded.
#[inline(always)]
fn load(module: u32) -> bool {
    #[cfg(feature = "boot-guard")]
    const BOOT_MARKER_PATH: &[u8] = br"\Device\Harddisk0\Partition1\DEVKIT\FlashEx\openxbdm.arm";

    // Every later read of these imports skips the check.
    if !kernel::data_imports_resolved() {
        kernel::debug_print(c"openxbdm: unresolved data import\n");
        return false;
    }

    // The recovery installs nothing, refuses every export, and never
    // waits on the loader thread.
    #[cfg(feature = "boot-guard")]
    if delete_file(BOOT_MARKER_PATH) != Removal::Removed {
        crate::exports::RECOVERY.store(1, Ordering::SeqCst);
        return start_thread(recovery_thread).is_ok();
    }

    crate::backend::dispatcher::initialize_host();
    if !kernel::register_debug_monitor(module) {
        kernel::debug_print(c"openxbdm: debug monitor registration failed\n");
        return false;
    }

    crate::backend::debugger::install();
    crate::backend::network::xhttpproxy::initialize();
    crate::backend::session::initialize();
    crate::backend::hardware::initialize();
    crate::backend::dispatcher::install();
    crate::backend::performance::initialize();
    crate::backend::memory::initialize();

    // The hooks above point into the image, so it stays loaded without
    // a server; calls and events take their defaults.
    if start_thread(server_thread).is_err() {
        stop_server_services();
    }

    true
}

/// Boot without the marker after a deployment: the previous boot of this
/// build armed the monitor and did not remove the override, so remove it
/// and restart into the flash monitor without installing any hook.
#[cfg(feature = "boot-guard")]
extern "C" fn recovery_thread(_context: u32) -> u32 {
    kernel::debug_print(c"openxbdm: boot marker absent, restoring the flash monitor\n");
    if remove_override_module() != Removal::Failed {
        // SAFETY: no hook is installed; the reboot ends the title.
        unsafe { xboxkrnl::HalReturnToFirmware(xboxkrnl::FirmwareRequest::RebootQuiesce) };
    }

    // SAFETY: called on the recovery thread, which owns no further state.
    unsafe { xboxkrnl::ExTerminateThread(THREAD_EXIT_CODE) }
}
