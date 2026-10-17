use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::XbdmHresult;
use xbox360::status::Hresult;

/// Failures of the proxy control codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlError {
    NotFound,
    /// The caller asked for a forced entry and the entry is not forced.
    NotForced,
    BadRequest,
    /// The certificate upload has not finished.
    UploadPending,
    /// The caller's certificate callback failed.
    CallbackFailed,
}

impl core::fmt::Display for ControlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no matching proxy",
            Self::NotForced => "proxy is not forced",
            Self::BadRequest => "invalid proxy request",
            Self::UploadPending => "certificate upload pending",
            Self::CallbackFailed => "certificate callback failed",
        })
    }
}

impl core::error::Error for ControlError {}

impl From<ControlError> for Hresult {
    fn from(error: ControlError) -> Self {
        match error {
            ControlError::NotFound => ErrorCode::FileNotFound.hresult(),
            ControlError::NotForced => ErrorCode::FileAlreadyExists.hresult(),
            ControlError::BadRequest => ErrorCode::BadParameter.hresult(),
            ControlError::UploadPending => Hresult::IN_PROGRESS,
            ControlError::CallbackFailed => ErrorCode::NoSuchModule.hresult(),
        }
    }
}
