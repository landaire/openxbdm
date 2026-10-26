//! Codec errors.

use crate::file_io::FileIoApi;
use crate::packet::Checksum;
use crate::packet::PacketType;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("buffer holds {actual} bytes, {needed} required")]
    Truncated { needed: usize, actual: usize },
    #[error("datagram of {length} bytes is neither a beacon nor a packet")]
    UnrecognizedShortDatagram { length: usize },
    #[error("packet leader {leader:#010x} is not a data or control leader")]
    UnknownLeader { leader: u32 },
    #[error("control packet type {packet_type:?} is not acknowledge, resend or reset")]
    UnknownControlType { packet_type: PacketType },
    #[error("header declares {declared} payload bytes, maximum is {maximum}")]
    PayloadTooLarge { declared: usize, maximum: usize },
    #[error("header declares {declared} payload bytes, datagram carries {actual}")]
    PayloadLengthMismatch { declared: usize, actual: usize },
    #[error("checksum mismatch: header {expected:?}, computed {computed:?}")]
    ChecksumMismatch {
        expected: Checksum,
        computed: Checksum,
    },
    #[error("packet type {actual:?} where {expected:?} was required")]
    UnexpectedPacketType {
        expected: PacketType,
        actual: PacketType,
    },
    #[error("message header of {actual} bytes, {expected} required")]
    MessageHeaderLength { expected: usize, actual: usize },
    #[error("state change {state:#x} carries {actual} data bytes, header declares {declared}")]
    PathLengthMismatch {
        state: u32,
        declared: usize,
        actual: usize,
    },
    #[error("file path data of {length} bytes is not whole UTF-16 code units")]
    OddPathLength { length: usize },
    #[error("file path has no terminator")]
    UnterminatedPath,
    #[error("file request {api:?} names handle zero")]
    ZeroFileHandle { api: FileIoApi },
    #[error("file reply for unknown api {api:?}")]
    UnknownFileIoApi { api: FileIoApi },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("payload of {length} bytes exceeds the {maximum}-byte packet limit")]
    PayloadTooLarge { length: usize, maximum: usize },
    #[error("output buffer holds {actual} bytes, {needed} required")]
    BufferTooSmall { needed: usize, actual: usize },
    #[error("context range {offset:#x}+{length:#x} exceeds the {size:#x}-byte context")]
    ContextRange {
        offset: usize,
        length: usize,
        size: usize,
    },
}
