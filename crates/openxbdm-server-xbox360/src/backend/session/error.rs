use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;

/// Why a remote call did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CallError {
    ModuleNotFound,
    ProcedureNotFound,
}

impl From<CallError> for Hresult {
    fn from(error: CallError) -> Self {
        Hresult::from_win32(match error {
            CallError::ModuleNotFound => Win32Error::MOD_NOT_FOUND,
            CallError::ProcedureNotFound => Win32Error::PROC_NOT_FOUND,
        })
    }
}

impl core::fmt::Display for CallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ModuleNotFound => "module not found",
            Self::ProcedureNotFound => "procedure not found",
        })
    }
}

impl core::error::Error for CallError {}

/// Why the log engine worker stopped early; its result word goes to the
/// engine's status field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkerError {
    /// The quit or done event is missing.
    MissingEvent,
    /// The log file could not be created.
    NoFile,
    /// The callback failed with this result.
    Callback(Hresult),
    /// The file write failed; the thread's last error, if any.
    Write(Option<Win32Error>),
    /// An entry could not be returned to the free queue.
    Requeue,
}

impl core::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingEvent => f.write_str("quit or done event missing"),
            Self::NoFile => f.write_str("log file not created"),
            Self::Callback(result) => write!(f, "callback failed with {:#x}", result.0),
            Self::Write(_) => f.write_str("log file write failed"),
            Self::Requeue => f.write_str("entry not returned to the free queue"),
        }
    }
}

impl core::error::Error for WorkerError {}

/// The engine status word of a worker failure.
impl From<WorkerError> for Hresult {
    fn from(error: WorkerError) -> Self {
        match error {
            WorkerError::MissingEvent => Self::INVALID_ARGUMENT,
            // Stock stores the NTSTATUS itself in the status word.
            WorkerError::NoFile => Self(KernelError::ObjectNameInvalid.status().0),
            WorkerError::Callback(result) => result,
            // Stock stores the conversion of a zero last error as is.
            WorkerError::Write(error) => error.map_or(Self::SUCCESS, Self::from),
            WorkerError::Requeue => Self::FAIL,
        }
    }
}

/// Why export 32 could not add a session processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AddProcessorError {
    NoFreeSlot,
    NameTooLong,
}

impl core::fmt::Display for AddProcessorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NoFreeSlot => "no free processor slot",
            Self::NameTooLong => "processor name too long",
        })
    }
}

impl core::error::Error for AddProcessorError {}

impl From<AddProcessorError> for Hresult {
    fn from(error: AddProcessorError) -> Self {
        match error {
            AddProcessorError::NoFreeSlot => ErrorCode::MaxConnectionsExceeded.hresult(),
            AddProcessorError::NameTooLong => Hresult::INVALID_ARGUMENT,
        }
    }
}

/// A notification text that names no kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MissingKind;
