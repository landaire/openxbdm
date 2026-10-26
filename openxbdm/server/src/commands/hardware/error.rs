use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::XbdmHresult;

use crate::reply::CommandError;

/// Failures of this domain without a status of the result table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareError {
    /// `424-`: no optical disc log is being written.
    NotLogging,
    /// `425-`: an optical disc log is being written.
    AlreadyLogging,
    /// `425-`: a PGO count block is allocated, so its settings are fixed.
    CountBlockAllocated,
    /// `437-`: a required `autoinput` parameter is missing.
    MissingParameter,
    /// `442-`: the virtual controller is absent or not connected.
    NotConnected,
    /// `400-` with no text: a monitor service call failed.
    ServiceFailed,
    /// A failed XAM call, passed through.
    Xam(XamError),
}

impl From<HardwareError> for Hresult {
    fn from(error: HardwareError) -> Self {
        match error {
            HardwareError::NotLogging => Hresult::NOT_STARTED,
            HardwareError::AlreadyLogging | HardwareError::CountBlockAllocated => {
                Hresult::ALREADY_STARTED
            }
            HardwareError::MissingParameter => Hresult::NO_SUCH_FIELD,
            HardwareError::NotConnected => Hresult::INVALID_STATE,
            HardwareError::ServiceFailed => Hresult::SERVICE_FAILED,
            HardwareError::Xam(error) => error.into(),
        }
    }
}

impl From<HardwareError> for CommandError {
    fn from(error: HardwareError) -> Self {
        Self::Hardware(error)
    }
}

/// A failed XAM or system service call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XamError {
    /// `E_FAIL`; also reported when the export is absent.
    Fail,
    InvalidArgument,
    Other(UnlistedXamResult),
}

impl XamError {
    /// `Ok` for a success result of a XAM call, the failure otherwise.
    pub fn check(result: Hresult) -> Result<(), Self> {
        match result {
            _ if !result.is_failure() => Ok(()),
            Hresult::FAIL => Err(Self::Fail),
            Hresult::INVALID_ARGUMENT => Err(Self::InvalidArgument),
            other => Err(Self::Other(UnlistedXamResult(other))),
        }
    }
}

impl From<XamError> for Hresult {
    fn from(error: XamError) -> Self {
        match error {
            XamError::Fail => Hresult::FAIL,
            XamError::InvalidArgument => Hresult::INVALID_ARGUMENT,
            XamError::Other(UnlistedXamResult(result)) => result,
        }
    }
}

impl From<XamError> for CommandError {
    fn from(error: XamError) -> Self {
        Self::Hardware(HardwareError::Xam(error))
    }
}

/// A failure result without an [`XamError`] variant. Only
/// [`XamError::check`] creates it, so equal errors have equal variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnlistedXamResult(Hresult);

/// Why an avatar hook could not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvatarError {
    /// The hook lookup failed.
    Lookup(XamError),
    /// The lookup returned no function.
    NoFunction,
    /// The hook failed.
    Hook(XamError),
}

impl From<AvatarError> for CommandError {
    fn from(error: AvatarError) -> Self {
        match error {
            AvatarError::Lookup(error) | AvatarError::Hook(error) => error.into(),
            AvatarError::NoFunction => Self::Status(ErrorCode::AccessDenied),
        }
    }
}

/// A kernel or system export the command needs is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportMissing;

/// Why the optical disc log did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OddLogStartError {
    /// A log is already being written.
    Busy,
    /// The log file or writer thread could not be created.
    Failed(KernelError),
}

impl From<OddLogStartError> for CommandError {
    fn from(error: OddLogStartError) -> Self {
        match error {
            OddLogStartError::Busy => HardwareError::AlreadyLogging.into(),
            OddLogStartError::Failed(error) => {
                Self::from_kernel(error, Self::Status(ErrorCode::FileCannotBeCreated))
            }
        }
    }
}

/// Result of the start service (export 147).
impl From<OddLogStartError> for Hresult {
    fn from(error: OddLogStartError) -> Self {
        CommandError::from(error).into()
    }
}

/// No optical disc log is being written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OddLogNotRunning;

impl From<OddLogNotRunning> for CommandError {
    fn from(OddLogNotRunning: OddLogNotRunning) -> Self {
        HardwareError::NotLogging.into()
    }
}

/// Result of the stop service (export 148).
impl From<OddLogNotRunning> for Hresult {
    fn from(error: OddLogNotRunning) -> Self {
        CommandError::from(error).into()
    }
}

/// Why a `pogoctrl` request or PGO export failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgoError {
    /// The module record is not registered.
    NoSuchModule,
    /// The module's count block is allocated; its settings are fixed.
    Busy,
}

impl From<PgoError> for CommandError {
    fn from(error: PgoError) -> Self {
        match error {
            PgoError::NoSuchModule => Self::Status(ErrorCode::BadParameter),
            PgoError::Busy => HardwareError::CountBlockAllocated.into(),
        }
    }
}

/// Result of the PGO exports 108 to 110.
impl From<PgoError> for Hresult {
    fn from(error: PgoError) -> Self {
        CommandError::from(error).into()
    }
}

/// Why a controller operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomationError {
    /// User slot out of range, or a malformed queue request.
    BadParameter,
    /// No controller in the slot, or it is not connected.
    NotConnected,
    OutOfMemory,
    /// The input system refused to bind or unbind the controller.
    Refused,
}

impl From<AutomationError> for CommandError {
    fn from(error: AutomationError) -> Self {
        match error {
            AutomationError::BadParameter => Self::Status(ErrorCode::BadParameter),
            AutomationError::NotConnected => HardwareError::NotConnected.into(),
            AutomationError::OutOfMemory => Self::Status(ErrorCode::OutOfMemory),
            AutomationError::Refused => Self::Status(ErrorCode::UnknownCommand),
        }
    }
}

/// Result of the automation exports 167 to 174.
impl From<AutomationError> for Hresult {
    fn from(error: AutomationError) -> Self {
        CommandError::from(error).into()
    }
}
