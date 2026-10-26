//! Exports for file change counts, the devkit drive, and a kernel routine.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360_sys::status::Win32ErrorCode;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::ObCreateSymbolicLink;
use xbox360_sys::xboxkrnl::ProcessType;

use super::ansi;
use crate::exports::export;
use crate::kernel;

/// Closes of files commands may have changed (0x91f9feec).
pub(super) static FILE_CHANGES: AtomicU32 = AtomicU32::new(0);

/// The resolved routine (0x91f9f684); zero when absent.
static KERNEL_ROUTINE: AtomicU32 = AtomicU32::new(0);

/// Set by the first caller, which resolves the routine (0x91f9f688).
static KERNEL_ROUTINE_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Export 85 (stock 0x91f46fd8): store the file change counter.
extern "C" fn file_change_count(count: *mut u32) -> Hresult {
    // SAFETY: the caller passes a writable dword, as the image assumes.
    unsafe { count.write(FILE_CHANGES.load(Ordering::Relaxed)) };

    Hresult::OK
}
export!(85, file_change_count);

/// Export 141 (stock 0x91f33438): link `E:` and `DEVKIT:` to the devkit
/// directory in the caller's process namespace. Existing links count as
/// success; the result is the HRESULT of the DOS error.
extern "C" fn map_devkit_drive() -> Hresult {
    let (drive, devkit): (&[u8], &[u8]) =
        if xboxkrnl::KeGetCurrentProcessType() == ProcessType::SYSTEM {
            (b"\\system??\\E:", b"\\system??\\DEVKIT:")
        } else {
            (b"\\??\\E:", b"\\??\\DEVKIT:")
        };
    let target = ansi(b"\\Device\\Harddisk0\\Partition1\\DEVKIT");
    // SAFETY: both counted names refer to live bytes for the call.
    let link = |name: &[u8]| unsafe { ObCreateSymbolicLink(&ansi(name), &target) }.result();
    let linked = match link(drive) {
        Ok(()) | Err(KernelError::ObjectNameCollision) => match link(devkit) {
            Err(KernelError::ObjectNameCollision) => Ok(()),
            other => other,
        },
        Err(error) => Err(error),
    };
    match linked.err().and_then(xbox360::status::dos_error) {
        Some(error) => Hresult::from(error),
        // S_OK for ERROR_SUCCESS.
        None => Hresult::SUCCESS,
    }
}
export!(141, map_devkit_drive);

/// Export 144 (stock 0x91f334e8): call kernel export 0x273 as
/// `routine(0, a, b, c, d)` and return the DOS error of its status. A
/// caller that finds the routine claimed but not yet resolved, or a kernel
/// without it, gets ERROR_NOT_SUPPORTED.
extern "C" fn call_kernel_routine(a: u32, b: u32, c: u32, d: u32) -> Win32ErrorCode {
    /// Kernel export resolved on first use of export 144.
    const KERNEL_ROUTINE_ORDINAL: Ordinal = Ordinal::new(0x273).unwrap();

    let mut routine = KERNEL_ROUTINE.load(Ordering::Acquire);
    if routine == 0 && !KERNEL_ROUTINE_CLAIMED.swap(true, Ordering::AcqRel) {
        let mut address = 0u32;
        let resolved = SystemModule::Kernel.handle().is_ok_and(|module| {
            // SAFETY: `module` is a loaded module handle; `address` is a live local.
            unsafe {
                xboxkrnl::XexGetProcedureAddress(
                    module.raw(),
                    u32::from(KERNEL_ROUTINE_ORDINAL.get()),
                    &mut address,
                )
            }
            .is_success()
        });
        routine = if resolved { address } else { 0 };
        KERNEL_ROUTINE.store(routine, Ordering::Release);
    }
    if routine == 0 {
        return Win32ErrorCode::from(Some(Win32Error::NOT_SUPPORTED));
    }

    // SAFETY: the kernel export takes five register arguments.
    let status = unsafe { kernel::call_console(routine, 0, a, b, c, d, 0, 0) };

    xboxkrnl::RtlNtStatusToDosError(NtStatus(status))
}
export!(144, call_kernel_routine);
