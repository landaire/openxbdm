use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::XbdmHresult;

use crate::reply::CommandError;

/// A thread lookup failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoSuchThread;

impl From<NoSuchThread> for CommandError {
    fn from(NoSuchThread: NoSuchThread) -> Self {
        ErrorCode::NoSuchThread.into()
    }
}

/// An operation on a thread stopped at a debug event failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoppedThreadError {
    NoSuchThread,
    /// The thread is not inside the monitor at a debug event.
    NotStopped,
}

impl From<NoSuchThread> for StoppedThreadError {
    fn from(NoSuchThread: NoSuchThread) -> Self {
        Self::NoSuchThread
    }
}

impl From<StoppedThreadError> for CommandError {
    fn from(error: StoppedThreadError) -> Self {
        match error {
            StoppedThreadError::NoSuchThread => ErrorCode::NoSuchThread.into(),
            StoppedThreadError::NotStopped => ErrorCode::NotStopped.into(),
        }
    }
}

/// No title launch is pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotPending;

impl From<NotPending> for CommandError {
    fn from(NotPending: NotPending) -> Self {
        Self::Fail
    }
}

/// Why a set did not take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetError {
    Misaligned,
    /// A block the entry needs could not be obtained from pool memory.
    NoBlock,
}

impl From<SetError> for CommandError {
    fn from(_: SetError) -> Self {
        Self::Fail
    }
}

/// No software breakpoint is set at the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoSuchBreakpoint;

impl From<NoSuchBreakpoint> for CommandError {
    fn from(NoSuchBreakpoint: NoSuchBreakpoint) -> Self {
        Self::Fail
    }
}

/// A data breakpoint request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataBreakpointError {
    /// The range crosses an 8-byte boundary.
    Unaligned,
    /// Another data breakpoint is set.
    InUse,
    /// The kind is not supported (execute).
    UnsupportedKind,
}

impl From<DataBreakpointError> for CommandError {
    fn from(error: DataBreakpointError) -> Self {
        match error {
            DataBreakpointError::Unaligned | DataBreakpointError::UnsupportedKind => {
                Self::InvalidArgument
            }
            DataBreakpointError::InUse => Self::OutOfMemory,
        }
    }
}

/// Why an execution state change was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionError {
    /// `426-`: a stop while stopped or while a title launch is pending.
    AlreadyStopped,
    /// A start while running.
    NotStopped,
    /// `400-`: a start while rebooting.
    Rebooting,
    /// The state machine has no transition from the current state.
    AccessDenied,
}

impl From<ExecutionError> for Hresult {
    fn from(error: ExecutionError) -> Self {
        match error {
            ExecutionError::AlreadyStopped => Hresult::ALREADY_STOPPED,
            ExecutionError::NotStopped => ErrorCode::NotStopped.hresult(),
            ExecutionError::Rebooting => ErrorCode::Undefined.hresult(),
            ExecutionError::AccessDenied => ErrorCode::AccessDenied.hresult(),
        }
    }
}

impl From<ExecutionError> for CommandError {
    fn from(error: ExecutionError) -> Self {
        Self::Execution(error)
    }
}

/// Why `kdnet set` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KdnetSetError {
    /// A parameter is malformed, or the settings are incomplete.
    BadParameter,
    /// The console MAC address for a default target address is unreadable.
    ConsoleAddress(KernelError),
    /// The settings record could not be written.
    Save(KernelError),
}

impl KdnetSetError {
    /// The error code the failure text prints.
    pub(super) fn code(self) -> Hresult {
        match self {
            Self::BadParameter => ErrorCode::BadParameter.hresult(),
            Self::ConsoleAddress(error) | Self::Save(error) => Hresult::from(error),
        }
    }
}

/// A debugger extension load or release failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionError {
    /// `443-`: another extension is loaded.
    OtherLoaded,
    /// The handle is not the loaded extension's.
    UnknownHandle,
    /// The loader or the unload failed.
    Kernel(KernelError),
}

impl From<ExtensionError> for Hresult {
    fn from(error: ExtensionError) -> Self {
        match error {
            ExtensionError::OtherLoaded => Hresult::EXTENSION_LOADED,
            ExtensionError::UnknownHandle => ErrorCode::BadParameter.hresult(),
            ExtensionError::Kernel(error) => {
                CommandError::from_kernel(error, CommandError::Fail).into()
            }
        }
    }
}

impl From<ExtensionError> for CommandError {
    fn from(error: ExtensionError) -> Self {
        Self::Extension(error)
    }
}
