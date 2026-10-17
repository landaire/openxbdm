use openxbdm_core::status::Hresult;
use openxbdm_server::commands::console::BufferTooSmall;

/// Why stock export 17 failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DebugNameError {
    /// The buffer or size pointer is NULL.
    MissingBuffer,
    BufferTooSmall,
}

impl core::fmt::Display for DebugNameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::MissingBuffer => "missing buffer",
            Self::BufferTooSmall => "buffer too small",
        })
    }
}

impl core::error::Error for DebugNameError {}

impl From<BufferTooSmall> for DebugNameError {
    fn from(_: BufferTooSmall) -> Self {
        Self::BufferTooSmall
    }
}

impl From<DebugNameError> for Hresult {
    fn from(error: DebugNameError) -> Self {
        match error {
            DebugNameError::MissingBuffer => Hresult::INVALID_ARGUMENT,
            DebugNameError::BufferTooSmall => BufferTooSmall.into(),
        }
    }
}
