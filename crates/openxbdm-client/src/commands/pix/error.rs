use openxbdm_core::status::Hresult;

use crate::protocol::Response;

/// Typed error for both pixcmd and `PIX!{...}` interactions. Some
/// variants are shared; callers can discriminate with matches.
#[derive(Debug, thiserror::Error)]
pub enum PixError {
    /// xbdm / title replied with a non-2xx (or 2xx with unexpected shape).
    #[error("pix wire replied unexpectedly: {response:?}")]
    UnexpectedResponse { response: Response },
    /// Well-known "Cannot execute - previous command still pending" body.
    #[error("pix runtime reported busy: {message:?}")]
    Busy { message: String },
    /// xbmovie restricts visible filenames to 38 bytes.
    #[error("pix capture filename exceeds xbmovie's 38-byte visible-name limit")]
    CaptureNameTooLong,
    /// `PIX!{CaptureFileCreationEnded}` reported a failure result.
    #[error("capture file creation failed on the console with result {:#010x}", .result.0)]
    CaptureFileCreationFailed { result: Hresult },
    /// No `PIX!{CaptureFileCreationEnded}` arrived in time.
    #[error("no capture file creation result within {}s", .timeout.as_secs())]
    CaptureFileCreationTimedOut { timeout: core::time::Duration },
    /// The notification channel closed while a capture notification was
    /// awaited.
    #[error("notification channel closed")]
    NotificationChannelClosed,
}

#[derive(Debug, thiserror::Error)]
pub enum XbmError {
    #[error("not an .xbm file: expected magic 0x53A722B[4-6], got {got:#010x}")]
    BadMagic { got: u32 },
    #[error(
        "unsupported .xbm version {got:#010x}; only {expected:#010x} \
         (matching xbmovie + PIX_VERSION) is known"
    )]
    UnsupportedVersion { got: u32, expected: u32 },
    #[error("header size {got:#x} is not the expected {expected:#x}")]
    UnexpectedHeaderSize { got: u32, expected: u32 },
    #[error("frame record at {offset:#x} has implausible size {size}")]
    ImplausibleFrameSize { offset: u64, size: u32 },
}
