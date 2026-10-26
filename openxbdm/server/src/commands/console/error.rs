//! Console domain errors.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;

use crate::reply::CommandError;

/// Console failures whose reply status is outside the result table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleError {
    /// `442-` with empty text: a network address query is pending.
    AddressPending,
}

impl From<ConsoleError> for Hresult {
    fn from(error: ConsoleError) -> Self {
        match error {
            ConsoleError::AddressPending => Hresult::INVALID_STATE,
        }
    }
}

impl From<ConsoleError> for CommandError {
    fn from(error: ConsoleError) -> Self {
        Self::Console(error)
    }
}

/// The output does not hold the whole value (stock exports 17 and 194).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall;

impl From<BufferTooSmall> for Hresult {
    fn from(_: BufferTooSmall) -> Self {
        Hresult::BUFFER_TOO_SMALL
    }
}

/// Why export 194 reports no response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationError {
    /// Waiting to register or a request is in progress.
    NotRegistered,
    Cleared,
    Failed,
    Rejected,
    ResponseTooLarge,
    /// The caller's buffer does not hold the response.
    BufferTooSmall,
}

impl From<RegistrationError> for Hresult {
    fn from(error: RegistrationError) -> Self {
        match error {
            RegistrationError::NotRegistered => Hresult::IN_PROGRESS,
            RegistrationError::Cleared => ErrorCode::FileNotFound.hresult(),
            RegistrationError::Failed => Hresult::REQUEST_FAILED,
            RegistrationError::Rejected => Hresult::SERVICE_FAILED,
            RegistrationError::ResponseTooLarge => ErrorCode::NoRoomOnDevice.hresult(),
            RegistrationError::BufferTooSmall => BufferTooSmall.into(),
        }
    }
}

/// A failed system network service request: the result the system
/// software returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkRaError(pub Hresult);
