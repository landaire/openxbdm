use openxbdm_core::status::ErrorCode;

use crate::reply::CommandError;

/// Why a new entry was not inserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    /// The certificate hex is malformed or longer than `certsize`.
    BadCertificate,
    OutOfMemory,
}

impl From<ProxyError> for CommandError {
    fn from(error: ProxyError) -> Self {
        match error {
            ProxyError::BadCertificate => ErrorCode::UnknownCommand.into(),
            ProxyError::OutOfMemory => ErrorCode::OutOfMemory.into(),
        }
    }
}
