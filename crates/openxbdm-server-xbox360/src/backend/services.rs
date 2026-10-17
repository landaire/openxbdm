//! Content integrity verification services: XAM exports 0x9bb..0x9c0 and
//! the kernel security detection exports, resolved at call time as stock
//! does. IPTV settings go through the console domain's configuration
//! store.

use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands;
use openxbdm_server::commands::services::CivProgress;
use openxbdm_server::commands::services::CivResult;
use openxbdm_server::commands::services::DetectionBit;
use openxbdm_server::commands::services::DetectionMask;
use openxbdm_server::commands::services::DetectionRoutine;
use openxbdm_server::commands::services::DetectionRoutineMissing;
use openxbdm_server::commands::services::DetectionUpdate;
use openxbdm_server::commands::services::LastError;
use openxbdm_server::commands::services::ThreadHandle;
use xbox360::module::ExportAddress;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::status::last_error;
use xbox360::status::set_last_error;
use xbox360_sys::xam;
use xbox360_sys::xam::MediaVerificationFailedBlocks;
use xbox360_sys::xam::UserIndex;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::FirmwareRequest;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;

use super::Console;
use crate::kernel;

/// Why a XAM export could not be called. The failure is stored as the
/// calling thread's last error, as stock stores it.
#[derive(Debug)]
enum Unresolved {
    /// xam.xex is not loaded.
    Module,
    /// The export is absent.
    Export,
}

impl core::fmt::Display for Unresolved {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Unresolved::Module => "xam.xex is not loaded",
            Unresolved::Export => "the XAM export is absent",
        })
    }
}

impl core::error::Error for Unresolved {}

/// The calling thread's last error.
fn stored_last_error() -> LastError {
    LastError::from_win32(last_error())
}

/// Resolve a XAM export; failures set the last error.
fn xam_export(ordinal: Ordinal) -> Result<u32, Unresolved> {
    let module = SystemModule::Xam.handle().map_err(|error| {
        set_last_error(error);
        Unresolved::Module
    })?;
    resolve_export(module, ordinal)
        .map(ExportAddress::raw)
        .map_err(|error| {
            set_last_error(error);
            Unresolved::Export
        })
}

/// Call a XAM export reporting a value: its return, or the last error
/// when xam.xex or the export is absent.
fn call_reporting(ordinal: Ordinal, a0: u32, a1: u32, a2: u32) -> CivResult {
    match xam_export(ordinal) {
        // SAFETY: the export takes at most three dword arguments.
        Ok(function) => CivResult::Returned(Hresult(unsafe {
            kernel::call_export(function, a0, a1, a2, 0)
        })),
        Err(Unresolved::Module) => CivResult::NoModule(stored_last_error()),
        Err(Unresolved::Export) => CivResult::NoExport(stored_last_error()),
    }
}

/// Start routine of the `civfail` thread; `context` is nonzero to reboot.
extern "C" fn failure_thread(context: u32) -> u32 {
    match xam_export(xam::ordinal::SHOW_BAD_DISC_ERROR_UI) {
        Err(Unresolved::Module) => return 0,
        // The meaning of the argument is unknown; stock passes the
        // any-user index, as to `XamShowDirtyDiscErrorUI`.
        // SAFETY: the export takes one dword argument.
        Ok(function) => unsafe {
            kernel::call_export(function, UserIndex::Any.raw(), 0, 0, 0);
        },
        Err(Unresolved::Export) => {}
    }
    if context != 0 {
        // SAFETY: the civfail thread reboots by request; no state survives.
        unsafe { xboxkrnl::HalReturnToFirmware(FirmwareRequest::Reboot) };
    }
    0
}

/// Resolve the detection exports in stock order.
fn detection_exports() -> Result<([u32; 4], NtStatus), DetectionRoutineMissing> {
    // The monitor holds the kernel handle from startup; the kernel is
    // always loaded.
    let kernel_module = SystemModule::Kernel
        .handle()
        .map_err(|error| DetectionRoutineMissing {
            routine: DetectionRoutine::SetDetected,
            error,
        })?;
    let mut addresses = [0u32; 4];
    let mut last_status = NtStatus::SUCCESS;
    for (address, routine) in addresses.iter_mut().zip(DetectionRoutine::ORDER) {
        // SAFETY: `address` is a live array element.
        let status = unsafe {
            xboxkrnl::XexGetProcedureAddress(kernel_module.raw(), routine.ordinal(), address)
        };
        status
            .result()
            .map_err(|error| DetectionRoutineMissing { routine, error })?;
        last_status = status;
    }
    Ok((addresses, last_status))
}

impl commands::services::Backend for Console {
    fn start_civ_failure_thread(&mut self, reboot: bool) -> Result<ThreadHandle, LastError> {
        /// Stock's creation flags of the thread.
        const FLAGS: ThreadCreationFlags = ThreadCreationFlags::PRIORITY_CLASS_13;
        let mut handle = 0u32;
        let mut thread_id = 0u32;
        // SAFETY: `handle` and `thread_id` are live locals; `failure_thread`
        // has the thread start signature.
        let status = unsafe {
            xboxkrnl::ExCreateThread(
                &mut handle,
                0,
                &mut thread_id,
                0,
                failure_thread as *const () as usize as u32,
                u32::from(reboot),
                FLAGS,
            )
        };
        // Thread creation does not set the last error; stock reports
        // whatever the thread held before.
        if !status.is_success() || handle == 0 {
            Err(stored_last_error())
        } else {
            Ok(ThreadHandle(handle))
        }
    }

    fn inject_civ_errors(&mut self, hash_errors: u32, read_errors: u32) {
        if let Ok(function) = xam_export(xam::ordinal::MEDIA_VERIFICATION_INJECT) {
            // SAFETY: the export takes two dword arguments.
            unsafe { kernel::call_export(function, hash_errors, read_errors, 0, 0) };
        }
    }

    fn update_civ_detection(
        &mut self,
        bit: Option<DetectionBit>,
    ) -> Result<DetectionUpdate, DetectionRoutineMissing> {
        let ([set, get, initialize, save], last_status) = detection_exports()?;
        // SAFETY: the detection exports take at most one dword argument.
        unsafe {
            let old_mask = DetectionMask(kernel::call_export(get, 0, 0, 0, 0));
            kernel::call_export(initialize, 0, 0, 0, 0);
            kernel::call_export(save, 0, 0, 0, 0);
            let status = bit.map_or(last_status, |bit| {
                NtStatus(kernel::call_export(set, bit.0, 0, 0, 0))
            });
            let new_mask = DetectionMask(kernel::call_export(get, 0, 0, 0, 0));
            Ok(DetectionUpdate {
                status,
                old_mask,
                new_mask,
            })
        }
    }

    fn create_civ_process(&mut self, thread_id: u32) -> CivResult {
        call_reporting(xam::ordinal::MEDIA_VERIFICATION_CREATE, thread_id, 0, 0)
    }

    fn close_civ_process(&mut self) {
        if let Ok(function) = xam_export(xam::ordinal::MEDIA_VERIFICATION_CLOSE) {
            // SAFETY: the export takes no arguments.
            unsafe { kernel::call_export(function, 0, 0, 0, 0) };
        }
    }

    fn verify_civ(&mut self, milliseconds: u32) -> CivResult {
        call_reporting(xam::ordinal::MEDIA_VERIFICATION_VERIFY, milliseconds, 0, 0)
    }

    fn civ_progress(&mut self) -> Result<CivProgress, CivResult> {
        let mut record = MediaVerificationFailedBlocks::new();
        match xam_export(xam::ordinal::MEDIA_VERIFICATION_FAILED_BLOCKS) {
            Ok(function) => {
                let address = core::ptr::from_mut(&mut record).expose_provenance() as u32;
                // SAFETY: the export fills the record it is given, which is a
                // live local of the size its first word states.
                let result = unsafe { kernel::call_export(function, address, 0, 0, 0) };
                if result != 0 {
                    return Err(CivResult::Returned(Hresult(result)));
                }
            }
            Err(Unresolved::Module) => return Err(CivResult::NoModule(stored_last_error())),
            Err(Unresolved::Export) => match stored_last_error() {
                // Without the export the verification counts as complete.
                LastError::ProcNotFound => record.completed = 1,
                error => return Err(CivResult::NoExport(error)),
            },
        }
        Ok(CivProgress {
            failed_reads: record.failed_reads,
            failed_hashes: record.failed_hashes,
            blocks_checked: record.blocks_checked,
            total_blocks: record.total_blocks,
            completed: record.completed != 0,
        })
    }
}
