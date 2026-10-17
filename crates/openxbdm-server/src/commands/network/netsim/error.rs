use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;

use crate::commands::network::NetworkError;
use crate::commands::network::WsaError;
use crate::commands::network::netsim::classifier;
use crate::commands::network::netsim::classifier::CompileError;
use crate::commands::network::netsim::classifier::ProgramError;
use crate::commands::network::netsim::classifier::SerializeError;
use crate::reply::CommandError;

/// Why a simulator operation failed. Titles receive the result value
/// through the simulator exports; commands report it as `err=` text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetsimError {
    NoInstance,
    /// The instance already exists (0x91f365e8).
    InstanceExists,
    /// The network stack lacks the frame transmit routine the instance
    /// forwards unchanged frames through.
    RoutineMissing,
    /// The Ethernet intercept is owned by another client (`WSAEALREADY`).
    InterceptBusy,
    /// Registering the Ethernet intercept failed.
    Intercept(WsaError),
    /// Malformed or rejected blob, or an index past the end.
    Invalid,
    /// The instance changed while it was being destroyed.
    InstanceChanged,
    OutOfMemory,
    /// A serialized blob does not fit its buffer.
    ShortBuffer,
    /// A program item holds a string, which the item encoder rejects.
    Unencodable,
    /// Classifier text of an export did not compile.
    Compile(CompileError),
    /// A reload is already running.
    Busy,
}

impl From<NetsimError> for Hresult {
    #[inline(never)]
    fn from(error: NetsimError) -> Self {
        match error {
            NetsimError::NoInstance => ErrorCode::FileNotFound.hresult(),
            NetsimError::InstanceExists => ErrorCode::NotStopped.hresult(),
            NetsimError::RoutineMissing => ErrorCode::AccessDenied.hresult(),
            NetsimError::InterceptBusy => ErrorCode::NotDebuggable.hresult(),
            NetsimError::Intercept(error) => Win32Error::from(error).into(),
            NetsimError::Invalid => ErrorCode::BadParameter.hresult(),
            NetsimError::InstanceChanged => Hresult::ALREADY_STOPPED,
            NetsimError::OutOfMemory => ErrorCode::OutOfMemory.hresult(),
            NetsimError::ShortBuffer => Hresult::BUFFER_FULL,
            // The library reports an unencodable item with its syntax error result.
            NetsimError::Unencodable => classifier::compile_result::SYNTAX,
            NetsimError::Compile(error) => error.into(),
            NetsimError::Busy => Hresult::IN_PROGRESS,
        }
    }
}

impl From<NetsimError> for NetworkError {
    fn from(error: NetsimError) -> Self {
        Self::Netsim(error)
    }
}

impl From<NetsimError> for CommandError {
    fn from(error: NetsimError) -> Self {
        NetworkError::Netsim(error).into()
    }
}

impl From<CompileError> for NetsimError {
    fn from(error: CompileError) -> Self {
        Self::Compile(error)
    }
}

impl From<ProgramError> for NetsimError {
    fn from(error: ProgramError) -> Self {
        match error {
            ProgramError::Invalid => Self::Invalid,
            ProgramError::OutOfMemory => Self::OutOfMemory,
        }
    }
}

/// The program encoder's failures as the blob builders report them
/// (0x91f847c0 within 0x91f8c058 and 0x91f8c418).
impl From<SerializeError> for NetsimError {
    fn from(error: SerializeError) -> Self {
        match error {
            SerializeError::TooLarge => Self::ShortBuffer,
            SerializeError::Unencodable => Self::Unencodable,
        }
    }
}

/// A rejected blob (0x82da0017).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidConfig;

impl From<InvalidConfig> for NetsimError {
    fn from(_: InvalidConfig) -> Self {
        Self::Invalid
    }
}
