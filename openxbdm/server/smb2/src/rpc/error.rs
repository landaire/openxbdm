//! Failures of pipe reads and writes. Failed RPC calls are not errors:
//! they are answered in-band with fault PDUs.

use super::CallId;
use super::DataFormat;
use super::PacketType;
use super::RpcVersion;
use crate::status::NtStatus;

/// A failed [`super::Pipe::read`] or [`super::Pipe::write`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeError {
    /// A read found no reply pending. The server cannot hold the read, so
    /// it answers as a nonblocking named pipe does (STATUS_PIPE_EMPTY).
    Empty,
    /// A read supplied no room for reply bytes; the reply stays pending
    /// (STATUS_BUFFER_TOO_SMALL).
    OutputEmpty,
    /// The share list changed while a reply was being read, so its
    /// remaining bytes no longer match those already read. The reply is
    /// discarded and the pipe stays bound (STATUS_PIPE_BROKEN).
    ReplyChanged,
    /// A write or transceive arrived before the pending reply was read
    /// (STATUS_PIPE_BUSY, MS-FSCC 2.3.47).
    Busy,
    /// The written bytes are not a valid PDU stream; the partial PDU is
    /// discarded (STATUS_INVALID_PARAMETER).
    MalformedPdu(PduError),
}

impl From<PduError> for PipeError {
    fn from(error: PduError) -> Self {
        Self::MalformedPdu(error)
    }
}

impl From<PipeError> for NtStatus {
    fn from(error: PipeError) -> Self {
        match error {
            PipeError::Empty => Self::PipeEmpty,
            PipeError::OutputEmpty => Self::BufferTooSmall,
            PipeError::ReplyChanged => Self::PipeBroken,
            PipeError::Busy => Self::PipeBusy,
            PipeError::MalformedPdu(_) => Self::InvalidParameter,
        }
    }
}

impl core::fmt::Display for PipeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("no reply pending on the pipe"),
            Self::OutputEmpty => formatter.write_str("pipe read with an empty buffer"),
            Self::ReplyChanged => {
                formatter.write_str("share list changed while the reply was read")
            }
            Self::Busy => formatter.write_str("pipe written before the pending reply was read"),
            Self::MalformedPdu(_) => formatter.write_str("malformed RPC PDU"),
        }
    }
}

impl core::error::Error for PipeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::MalformedPdu(error) => Some(error),
            _ => None,
        }
    }
}

/// What is wrong with a received PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduError {
    /// The protocol version is not 5.0 or 5.1.
    UnsupportedVersion { version: RpcVersion },
    /// The first data representation byte is not little-endian integers
    /// with ASCII characters (0x10).
    UnsupportedDataRepresentation { format: DataFormat },
    /// A packet type a client does not send.
    UnexpectedType { packet_type: PacketType },
    /// The fragment length is below the fixed part of its packet type.
    FragmentTooShort {
        packet_type: PacketType,
        length: u32,
        minimum: u32,
    },
    /// A request fragment without the first fragment flag that does not
    /// continue the request being received.
    UnexpectedContinuation { call_id: CallId },
}

impl core::fmt::Display for PduError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::UnsupportedVersion { version } => {
                write!(
                    formatter,
                    "unsupported RPC version {}.{}",
                    version.major, version.minor
                )
            }
            Self::UnsupportedDataRepresentation { format } => {
                write!(
                    formatter,
                    "unsupported data representation {:#04x}",
                    format.0
                )
            }
            Self::UnexpectedType { packet_type } => {
                write!(formatter, "unexpected packet type {}", packet_type.0)
            }
            Self::FragmentTooShort {
                packet_type,
                length,
                minimum,
            } => write!(
                formatter,
                "fragment of packet type {} has length {length}, minimum {minimum}",
                packet_type.0
            ),
            Self::UnexpectedContinuation { call_id } => {
                write!(
                    formatter,
                    "request fragment of call {} continues no request",
                    call_id.0
                )
            }
        }
    }
}

impl core::error::Error for PduError {}
