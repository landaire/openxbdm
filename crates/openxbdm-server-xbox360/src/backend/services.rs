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
use xbox360::status::set_last_error;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::FirmwareRequest;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;

use super::Console;
use crate::kernel;

const XAM_CREATE_PROCESS: Ordinal = Ordinal::new(0x9bb).unwrap();
const XAM_CLOSE_PROCESS: Ordinal = Ordinal::new(0x9bc).unwrap();
const XAM_VERIFY: Ordinal = Ordinal::new(0x9bd).unwrap();
const XAM_FAILED_BLOCKS: Ordinal = Ordinal::new(0x9be).unwrap();
const XAM_INJECT: Ordinal = Ordinal::new(0x9bf).unwrap();
const XAM_FAILURE: Ordinal = Ordinal::new(0x9c0).unwrap();

/// Argument the failure thread passes to XAM 0x9c0.
const FAILURE_CODE: u32 = 0xff;
/// `ExCreateThread` creation flags of the failure thread.
const FAILURE_THREAD_FLAGS: ThreadCreationFlags = ThreadCreationFlags::from_bits_retain(0x20);
/// Size of the XAM 0x9be record, stored in its first dword.
const FAILED_BLOCKS_RECORD_SIZE: u32 = 0x18;

/// The calling thread's last-error value.
fn last_error() -> LastError {
    LastError::from_win32(xbox360::status::last_error())
}

/// Why a XAM export could not be called.
enum Unresolved {
    /// xam.xex is not loaded.
    Module,
    /// The export is absent.
    Export,
}

/// Resolve a XAM export; failures set the last error.
fn xam_export(ordinal: Ordinal) -> Result<u32, Unresolved> {
    let module = SystemModule::Xam.handle().map_err(|status| {
        set_last_error(status);
        Unresolved::Module
    })?;
    resolve_export(module, ordinal)
        .map(ExportAddress::raw)
        .map_err(|status| {
            set_last_error(status);
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
        Err(Unresolved::Module) => CivResult::NoModule(last_error()),
        Err(Unresolved::Export) => CivResult::NoExport(last_error()),
    }
}

/// Start routine of the `civfail` thread; `context` is nonzero to reboot.
extern "C" fn failure_thread(context: u32) -> u32 {
    match xam_export(XAM_FAILURE) {
        Err(Unresolved::Module) => return 0,
        // SAFETY: the export takes one dword argument.
        Ok(function) => unsafe {
            kernel::call_export(function, FAILURE_CODE, 0, 0, 0);
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
                FAILURE_THREAD_FLAGS,
            )
        };
        // Thread creation does not set the last error; stock reports
        // whatever the thread held before.
        if !status.is_success() || handle == 0 {
            Err(last_error())
        } else {
            Ok(ThreadHandle(handle))
        }
    }

    fn inject_civ_errors(&mut self, hash_errors: u32, read_errors: u32) {
        if let Ok(function) = xam_export(XAM_INJECT) {
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
        call_reporting(XAM_CREATE_PROCESS, thread_id, 0, 0)
    }

    fn close_civ_process(&mut self) {
        if let Ok(function) = xam_export(XAM_CLOSE_PROCESS) {
            // SAFETY: the export takes no arguments.
            unsafe { kernel::call_export(function, 0, 0, 0, 0) };
        }
    }

    fn verify_civ(&mut self, milliseconds: u32) -> CivResult {
        call_reporting(XAM_VERIFY, milliseconds, 0, 0)
    }

    fn civ_progress(&mut self) -> Result<CivProgress, CivResult> {
        let mut record = [0u32; FAILED_BLOCKS_RECORD_SIZE as usize / 4];
        record[0] = FAILED_BLOCKS_RECORD_SIZE;
        match xam_export(XAM_FAILED_BLOCKS) {
            Ok(function) => {
                // SAFETY: the export fills the 0x18-byte record it is given.
                let result = unsafe {
                    kernel::call_export(function, record.as_mut_ptr() as usize as u32, 0, 0, 0)
                };
                if result != 0 {
                    return Err(CivResult::Returned(Hresult(result)));
                }
            }
            Err(Unresolved::Module) => return Err(CivResult::NoModule(last_error())),
            Err(Unresolved::Export) => match last_error() {
                LastError::ProcNotFound => {
                    record = [0, 0, 0, 0, 0, 1];
                }
                error => return Err(CivResult::NoExport(error)),
            },
        }
        Ok(CivProgress {
            failed_reads: record[1],
            failed_hashes: record[2],
            blocks_checked: record[3],
            total_blocks: record[4],
            completed: record[5] != 0,
        })
    }
}
