//! Errors of the capture operations.

/// Reason code 0x5c refuses command data buffers, stored as the fence
/// slot status.
#[derive(Clone, Copy)]
#[repr(u32)]
pub(super) enum CommandBufferError {
    /// Less time than the rate budget allows passed since the last
    /// allocation.
    RateLimited = 1,
    /// Too few capture buffers are free while the configuration waits for
    /// them.
    NoFreeBuffers = 2,
    TooLarge = 3,
    /// GPU capture is off.
    Off = 4,
}

/// Why a video operation ended early. The discriminants of the variants
/// without a field are their error numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum VideoError {
    /// The title's check routine returned `result`.
    Check { result: u32 } = 0,
    /// The title's submit routine returned `result`.
    Submit { result: u32 } = 1,
    /// The frame was captured without command data; the record's refusal
    /// status.
    Refused { status: u32 } = 2,
    /// The capture is too small for the read-ahead, or the request ring
    /// could not be allocated.
    NoBuffers = 3,
    /// No frame record at the start frame, or no part to replay.
    NothingToReplay = 4,
    /// The frame's command data holds no movie image.
    NoImage = 6,
    /// A movie data write failed.
    WriteFailed = 8,
}

impl VideoError {
    /// The error number of the `VideoOpError` status.
    pub(super) fn code(self) -> u32 {
        match self {
            Self::NoBuffers => 3,
            Self::NothingToReplay => 4,
            Self::NoImage => 6,
            Self::WriteFailed => 8,
            Self::Check { result } | Self::Submit { result } => result,
            Self::Refused { status } => status,
        }
    }
}
