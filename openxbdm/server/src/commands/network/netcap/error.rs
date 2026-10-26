use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;

use crate::commands::network::WsaError;
use crate::commands::network::netcap::capture_file::CaptureFileError;
use crate::commands::network::netcap::capture_result;
use crate::commands::network::netcap::intercept_result;

/// Why a capture did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    /// A capture runs.
    AlreadyCapturing,
    /// The Ethernet intercept callbacks are owned by another client.
    InterceptBusy,
    /// Installing the intercept callbacks failed.
    Intercept(WsaError),
    /// Creating the capture context or file failed.
    Open(CaptureFileError),
}

impl From<StartError> for Hresult {
    fn from(error: StartError) -> Self {
        match error {
            StartError::AlreadyCapturing => ErrorCode::NotStopped.hresult(),
            StartError::InterceptBusy => ErrorCode::NotDebuggable.hresult(),
            StartError::Intercept(error) => intercept_result(error),
            StartError::Open(error) => capture_result(error),
        }
    }
}
