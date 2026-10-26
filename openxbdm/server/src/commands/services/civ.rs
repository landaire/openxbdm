//! Content integrity verification (CIV) commands.

use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;

use super::LastError;
use crate::commands::util::required_dword;
use crate::invocation::Invocation;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// Value a CIV service call reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CivResult {
    /// The XAM service's return value, reported unchanged.
    Returned(Hresult),
    /// xam.xex is not loaded.
    NoModule(LastError),
    /// The service is not exported.
    NoExport(LastError),
}

impl CivResult {
    /// The value the reply text prints: the return value or the last
    /// error; an absent export with `ERROR_PROC_NOT_FOUND` reports 0.
    pub fn value(self) -> u32 {
        match self {
            Self::Returned(value) => value.0,
            Self::NoExport(LastError::ProcNotFound) => 0,
            Self::NoModule(error) | Self::NoExport(error) => error.code(),
        }
    }
}

/// Bit index into the kernel's 64-bit security detection mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionBit(pub u32);

/// Kernel exports `civsetbits` resolves, in resolution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionRoutine {
    SetDetected,
    GetDetected,
    Initialize,
    SaveSettings,
}

impl DetectionRoutine {
    pub const ORDER: [Self; 4] = [
        Self::SetDetected,
        Self::GetDetected,
        Self::Initialize,
        Self::SaveSettings,
    ];

    /// Kernel export ordinal.
    pub const fn ordinal(self) -> u32 {
        match self {
            Self::SetDetected => 0x295,
            Self::GetDetected => 0x296,
            Self::Initialize => 0x292,
            Self::SaveSettings => 0x294,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::SetDetected => "SET_DETECTED",
            Self::GetDetected => "GET_DETECTED",
            Self::Initialize => "INITIALIZE",
            Self::SaveSettings => "SAVE_SETTINGS",
        }
    }
}

/// The low 32 bits of the kernel's 64-bit security detection mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionMask(pub u32);

/// Outcome of a `civsetbits` update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionUpdate {
    /// Kernel status of the set request, or of the last export resolution
    /// when no bit was requested; reported unchanged.
    pub status: NtStatus,
    pub old_mask: DetectionMask,
    pub new_mask: DetectionMask,
}

/// Content verification counters reported by `civstatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CivProgress {
    pub failed_reads: u32,
    pub failed_hashes: u32,
    pub blocks_checked: u32,
    pub total_blocks: u32,
    pub completed: bool,
}

/// A dword parameter as the monitor's getter stores it: the parsed prefix
/// whenever the parameter is present, whether or not it is well formed.
/// Absent parameters write `missing <name>` into the reply text.
fn stored_dword(invocation: &mut Invocation<'_>, name: &str) -> Option<u32> {
    let value = invocation.line.param(name);
    if value.is_none_or(|value| value.dword().is_none()) {
        invocation.set_text(format_args!("missing {name}"));
    }

    value.map(|value| value.dword_prefix())
}

/// `civfail [reboot=<dword>]`. The thread handle is not closed.
pub(super) fn civ_fail(invocation: &mut Invocation<'_>) -> CommandResult {
    // The stack variable starts at zero.
    let reboot = stored_dword(invocation, "reboot").unwrap_or(0) != 0;

    match invocation.backend.start_civ_failure_thread(reboot) {
        Ok(handle) => {
            invocation.set_text(format_args!("Thread created: 0x{:08X}", handle.0));
        }
        Err(error) => {
            invocation.set_text(format_args!("CreateThread failed 0x{:x}", error.code()));
        }
    }

    Ok(Reply::Ok)
}

/// `civinject readerrors=<dword> hasherrors=<dword>`: absent counts are 0;
/// the text names the last missing parameter.
pub(super) fn civ_inject(invocation: &mut Invocation<'_>) -> CommandResult {
    let read_errors = required_dword(invocation, "readerrors").unwrap_or(0);
    let hash_errors = required_dword(invocation, "hasherrors").unwrap_or(0);
    invocation
        .backend
        .inject_civ_errors(hash_errors, read_errors);

    Ok(Reply::Ok)
}

/// `civsetbits on=<dword>`: `on` is a detection bit index; zero sets none.
pub(super) fn civ_set_bits(invocation: &mut Invocation<'_>) -> CommandResult {
    // Stock reads an uninitialized stack variable when `on` is absent; no
    // bit is set here.
    let bit = stored_dword(invocation, "on")
        .filter(|&on| on != 0)
        .map(DetectionBit);

    let update = match invocation.backend.update_civ_detection(bit) {
        Ok(update) => update,
        Err(missing) => {
            let status = NtStatus::from(missing.error);
            invocation.set_text(format_args!(
                "Cannot load ordinal {} ({}): 0x{:x}\n",
                missing.routine.ordinal(),
                missing.routine.name(),
                status.0
            ));
            invocation.backend.debug_print(invocation.text.as_bytes());

            DetectionUpdate {
                status,
                old_mask: DetectionMask(0xbaad_f00d),
                new_mask: DetectionMask(0xdead_beef),
            }
        }
    };

    invocation.set_text(format_args!(
        "Result 0x{:x}; old mask 0x{:x}, new mask 0x{:x}",
        update.status.0, update.old_mask.0, update.new_mask.0
    ));

    Ok(Reply::Ok)
}

/// `civstart threadid=<dword>`: the id is clamped to 5.
pub(super) fn civ_start(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Highest process slot `civstart` passes.
    const CIV_THREAD_ID_LIMIT: u32 = 5;

    let thread_id = stored_dword(invocation, "threadid")
        .unwrap_or(0)
        .min(CIV_THREAD_ID_LIMIT);

    let result = invocation.backend.create_civ_process(thread_id);
    invocation.set_text(format_args!(
        "XSecurityCreateProcess 0x{:x}",
        result.value()
    ));

    Ok(Reply::Ok)
}

pub(super) fn civ_status(invocation: &mut Invocation<'_>) -> CommandResult {
    match invocation.backend.civ_progress() {
        Ok(progress) => {
            invocation.set_text(format_args!(
                "Blocks Checked {}, Failed Reads {}, Failed Hashes {}, Total Blocks {}, {}.",
                progress.blocks_checked as i32,
                progress.failed_reads as i32,
                progress.failed_hashes as i32,
                progress.total_blocks as i32,
                if progress.completed {
                    "Completed"
                } else {
                    "In Progress"
                }
            ));
        }
        Err(error) => {
            invocation.set_text(format_args!(
                "XSecurityFailedBlocks returned 0x{:x}",
                error.value()
            ));
        }
    }

    Ok(Reply::Ok)
}

pub(super) fn civ_stop(invocation: &mut Invocation<'_>) -> CommandResult {
    invocation.backend.close_civ_process();
    invocation.text.set_bytes(b"XSecurityCloseProcess");

    Ok(Reply::Ok)
}

/// `civverify milliseconds=<dword>`: non-positive budgets other than -1
/// become 0x100.
pub(super) fn civ_verify(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Verification budget used for non-positive values other than -1.
    const CIV_DEFAULT_MILLISECONDS: u32 = 0x100;

    // Stock reads an uninitialized stack variable when the parameter is
    // absent; the default budget applies here.
    let requested = stored_dword(invocation, "milliseconds").unwrap_or(0) as i32;
    let milliseconds = if requested <= 0 && requested != -1 {
        CIV_DEFAULT_MILLISECONDS
    } else {
        requested as u32
    };

    let result = invocation.backend.verify_civ(milliseconds);
    invocation.set_text(format_args!("XSecurityVerify 0x{:x}", result.value()));

    Ok(Reply::Ok)
}
