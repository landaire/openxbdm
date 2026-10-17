//! Transport framing errors.

/// A transport header that the server does not accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The type byte is neither a session message nor a keep-alive.
    UnknownType { kind: u8 },
    /// The message is longer than the receive buffer.
    TooLong { length: usize, capacity: usize },
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownType { kind } => {
                write!(formatter, "unknown transport frame type {kind:#04x}")
            }
            Self::TooLong { length, capacity } => write!(
                formatter,
                "message of {length} bytes exceeds the {capacity}-byte receive buffer"
            ),
        }
    }
}

impl core::error::Error for FrameError {}
