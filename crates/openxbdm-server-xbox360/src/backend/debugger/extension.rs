//! Calls into the loaded debugger extension.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::KernelError;
use openxbdm_server::commands::debugger::ExtensionHandle;
use xbox360::time::sleep;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::ImageFlags;
use xbox360_sys::xboxkrnl::ImageVersion;
use xbox360_sys::xboxkrnl::XexUnloadImage;

use crate::backend::dispatcher::ControlCode;
use crate::kernel;

/// Loaded extension exports read off the server thread.
static EXTENSION_TELL_DEBUGGER: AtomicU32 = AtomicU32::new(0);
static EXTENSION_PREPARE_TO_UNLOAD: AtomicU32 = AtomicU32::new(0);
static EXTENSION_CALLS: AtomicU32 = AtomicU32::new(0);

/// Call the loaded extension's OnTellDebugger export with a dispatcher
/// result (stock 0x91f2e2e8); its return replaces the result.
pub(crate) fn tell_extension(code: ControlCode, argument: u32, result: u32) -> u32 {
    EXTENSION_CALLS.fetch_add(1, Ordering::AcqRel);
    let routine = EXTENSION_TELL_DEBUGGER.load(Ordering::Acquire);
    let result = if routine == 0 {
        result
    } else {
        // SAFETY: the export was resolved from the loaded extension image
        // and takes three register arguments.
        unsafe { kernel::call_export(routine, code.raw(), argument, result, 0) }
    };
    EXTENSION_CALLS.fetch_sub(1, Ordering::AcqRel);

    result
}

pub(super) fn load_extension(path: &[u8]) -> Result<ExtensionHandle, KernelError> {
    let mut name = [0u8; 0x6c];
    let length = path.len().min(name.len() - 1);
    name[..length].copy_from_slice(&path[..length]);
    let mut handle = 0u32;
    // SAFETY: `name` is NUL-terminated and `handle` is a live local.
    let status = unsafe {
        xboxkrnl::XexLoadImage(
            name.as_ptr(),
            ImageFlags::SYSTEM_DEBUGGER | ImageFlags::DLL,
            ImageVersion::ANY,
            &mut handle,
        )
    };
    status.result()?;
    let export = |export_name: &core::ffi::CStr| {
        let mut address = 0u32;
        // Extensions export by name; the loader takes the name pointer
        // in place of an ordinal.
        // SAFETY: `handle` is the image loaded above, the name is
        // NUL-terminated, and `address` is a live local.
        unsafe {
            xboxkrnl::XexGetProcedureAddress(
                handle,
                export_name.as_ptr() as usize as u32,
                &mut address,
            )
        };
        address
    };
    let on_load = export(c"OnLoad");
    let tell_debugger = export(c"OnTellDebugger");
    EXTENSION_PREPARE_TO_UNLOAD.store(export(c"PrepareToUnload"), Ordering::Release);
    if on_load != 0 {
        // SAFETY: the export was resolved from the loaded image and
        // takes no arguments.
        unsafe { kernel::call_export(on_load, 0, 0, 0, 0) };
    }
    EXTENSION_TELL_DEBUGGER.store(tell_debugger, Ordering::Release);
    // SAFETY: `handle` is the image loaded above, and this call hands
    // out its only token.
    Ok(unsafe { ExtensionHandle::from_raw(handle) })
}

pub(super) fn unload_extension(handle: ExtensionHandle) -> Result<(), KernelError> {
    EXTENSION_TELL_DEBUGGER.store(0, Ordering::Release);

    while EXTENSION_CALLS.load(Ordering::Acquire) != 0 {
        sleep(Duration::from_millis(1));
    }

    let prepare = EXTENSION_PREPARE_TO_UNLOAD.swap(0, Ordering::AcqRel);
    if prepare != 0 {
        // SAFETY: the export was resolved from the loaded image and
        // takes no arguments.
        unsafe { kernel::call_export(prepare, 0, 0, 0, 0) };
    }
    // SAFETY: the token names the loaded extension image and is
    // consumed here.
    unsafe { XexUnloadImage(handle.raw()) }.result()
}
