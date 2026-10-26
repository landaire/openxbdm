//! Direct TCP transport framing (MS-SMB2 2.1): each message follows a
//! four-byte header holding a zero byte and the 24-bit big-endian message
//! length.

mod error;

pub use self::error::FrameError;

/// Bytes of the transport header.
pub const HEADER_LENGTH: usize = 4;
/// Longest message the header can describe.
pub const MAXIMUM_MESSAGE: usize = 0x00ff_ffff;

/// Type byte of a session message.
const SESSION_MESSAGE: u8 = 0x00;

/// What a transport header announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    /// A message of `length` bytes follows.
    Message { length: usize },
    /// A keep-alive with no message.
    KeepAlive,
}

/// Decode a transport header for a receive buffer of `capacity` bytes.
pub fn parse_header(header: [u8; HEADER_LENGTH], capacity: usize) -> Result<Frame, FrameError> {
    /// Type byte of a NetBIOS session keep-alive.
    const SESSION_KEEP_ALIVE: u8 = 0x85;

    let length =
        usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);

    match header[0] {
        SESSION_MESSAGE if length > capacity => Err(FrameError::TooLong { length, capacity }),
        SESSION_MESSAGE => Ok(Frame::Message { length }),
        SESSION_KEEP_ALIVE => Ok(Frame::KeepAlive),
        kind => Err(FrameError::UnknownType { kind }),
    }
}

/// Encode the header of a `length`-byte message.
pub const fn header(length: usize) -> [u8; HEADER_LENGTH] {
    [
        SESSION_MESSAGE,
        (length >> 16) as u8,
        (length >> 8) as u8,
        length as u8,
    ]
}
