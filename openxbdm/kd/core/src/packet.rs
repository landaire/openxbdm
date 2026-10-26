//! Datagram framing: data packets, control packets, beacons, break-in.
//!
//! All header fields are little-endian.
//!
//! | Offset | Size | Field |
//! |-------:|-----:|-------|
//! | 0x00 | 4 | leader: `0x30303030` data, `0x69696969` control |
//! | 0x04 | 2 | packet type |
//! | 0x06 | 2 | payload byte count (0 for control packets) |
//! | 0x08 | 4 | packet id |
//! | 0x0c | 4 | checksum: byte sum of the payload (0 for control packets) |

use core::marker::PhantomData;
use core::net::Ipv4Addr;

use crate::DecodeError;
use crate::EncodeError;
use crate::wire;

pub const DATA_LEADER: u32 = 0x3030_3030;
pub const CONTROL_LEADER: u32 = 0x6969_6969;
pub const HEADER_LEN: usize = 16;
/// Largest payload either side accepts (kernel variable at 0x801cd7f4).
pub const MAX_PAYLOAD_LEN: usize = 0x580;
pub const MAX_DATAGRAM_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;
/// Length of the periodic target announcement.
pub const BEACON_LEN: usize = 12;
/// A datagram shorter than [`HEADER_LEN`] whose first byte is `b'b'`
/// requests a break-in when the kernel polls.
pub const BREAK_IN: [u8; 1] = *b"b";

/// Packet type field. Values other than the named constants are carried
/// through unchanged.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct PacketType(pub u16);

impl PacketType {
    pub const MANIPULATE: Self = Self(2);
    pub const DEBUG_IO: Self = Self(3);
    pub const ACKNOWLEDGE: Self = Self(4);
    pub const RESEND: Self = Self(5);
    pub const RESET: Self = Self(6);
    pub const STATE_CHANGE: Self = Self(7);
    /// Kernel-internal: the receive routine's break-in poll. Never on the wire.
    pub const POLL_BREAK_IN: Self = Self(8);
    /// Sent by the kernel with message 0x3330 only. Purpose not analyzed.
    pub const TYPE_9: Self = Self(9);
    pub const FILE_IO: Self = Self(0xb);

    fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::MANIPULATE => "Manipulate",
            Self::DEBUG_IO => "DebugIo",
            Self::ACKNOWLEDGE => "Acknowledge",
            Self::RESEND => "Resend",
            Self::RESET => "Reset",
            Self::STATE_CHANGE => "StateChange",
            Self::POLL_BREAK_IN => "PollBreakIn",
            Self::TYPE_9 => "Type9",
            Self::FILE_IO => "FileIo",
            _ => return None,
        })
    }
}

impl core::fmt::Debug for PacketType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name}"),
            None => write!(f, "PacketType({:#x})", self.0),
        }
    }
}

/// Packet id. Each side numbers its data packets independently and
/// advances by 2 per acknowledged packet; acknowledgements echo the id.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct PacketId(pub u32);

impl PacketId {
    /// Initial value of the kernel's expected receive id (0x801cdb84).
    pub const HOST_INITIAL: Self = Self(0x8000_0000);

    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(2))
    }
}

impl core::fmt::Debug for PacketId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PacketId({:#010x})", self.0)
    }
}

/// Wrapping 32-bit sum of the payload bytes.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Checksum(pub u32);

impl Checksum {
    pub fn from_parts(parts: &[&[u8]]) -> Self {
        let mut sum = 0u32;

        for part in parts {
            for &byte in *part {
                sum = sum.wrapping_add(u32::from(byte));
            }
        }

        Self(sum)
    }
}

impl core::fmt::Debug for Checksum {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Checksum({:#010x})", self.0)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub leader: u32,
    pub packet_type: PacketType,
    pub byte_count: u16,
    pub id: PacketId,
    pub checksum: Checksum,
}

impl PacketHeader {
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        wire::require(bytes, HEADER_LEN)?;

        Ok(Self {
            leader: wire::le32(bytes, 0)?,
            packet_type: PacketType(wire::le16(bytes, 4)?),
            byte_count: wire::le16(bytes, 6)?,
            id: PacketId(wire::le32(bytes, 8)?),
            checksum: Checksum(wire::le32(bytes, 0xc)?),
        })
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0u8; HEADER_LEN];
        wire::put_le32(&mut bytes, 0, self.leader);
        wire::put_le16(&mut bytes, 4, self.packet_type.0);
        wire::put_le16(&mut bytes, 6, self.byte_count);
        wire::put_le32(&mut bytes, 8, self.id.0);
        wire::put_le32(&mut bytes, 0xc, self.checksum.0);

        bytes
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ControlKind {
    Acknowledge,
    Resend,
    Reset,
}

impl ControlKind {
    pub const fn packet_type(self) -> PacketType {
        match self {
            Self::Acknowledge => PacketType::ACKNOWLEDGE,
            Self::Resend => PacketType::RESEND,
            Self::Reset => PacketType::RESET,
        }
    }

    fn from_packet_type(packet_type: PacketType) -> Option<Self> {
        match packet_type {
            PacketType::ACKNOWLEDGE => Some(Self::Acknowledge),
            PacketType::RESEND => Some(Self::Resend),
            PacketType::RESET => Some(Self::Reset),
            _ => None,
        }
    }
}

/// A control packet. `id` is the acknowledged id for
/// [`ControlKind::Acknowledge`], the sender's next data id for
/// [`ControlKind::Reset`], and zero for [`ControlKind::Resend`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ControlPacket {
    pub kind: ControlKind,
    pub id: PacketId,
}

impl ControlPacket {
    pub const fn new(kind: ControlKind, id: PacketId) -> Self {
        Self { kind, id }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        PacketHeader {
            leader: CONTROL_LEADER,
            packet_type: self.kind.packet_type(),
            byte_count: 0,
            id: self.id,
            checksum: Checksum(0),
        }
        .encode()
    }
}

/// Checksum state of a [`DataPacket`].
pub trait ChecksumState {}

/// The checksum has not been compared with the payload.
#[derive(Debug, Copy, Clone)]
pub enum Unverified {}

impl ChecksumState for Unverified {}

/// The checksum matched the payload.
#[derive(Debug, Copy, Clone)]
pub enum Verified {}

impl ChecksumState for Verified {}

#[derive(Debug, Copy, Clone)]
pub struct DataPacket<'a, S>
where
    S: ChecksumState,
{
    header: PacketHeader,
    payload: &'a [u8],
    state: PhantomData<S>,
}

impl<'a, S> DataPacket<'a, S>
where
    S: ChecksumState,
{
    pub fn header(&self) -> &PacketHeader {
        &self.header
    }

    pub fn packet_type(&self) -> PacketType {
        self.header.packet_type
    }

    pub fn id(&self) -> PacketId {
        self.header.id
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub fn computed_checksum(&self) -> Checksum {
        Checksum::from_parts(&[self.payload])
    }
}

impl<'a> DataPacket<'a, Unverified> {
    pub fn verify(self) -> Result<DataPacket<'a, Verified>, DecodeError> {
        let computed = self.computed_checksum();
        if computed != self.header.checksum {
            return Err(DecodeError::ChecksumMismatch {
                expected: self.header.checksum,
                computed,
            });
        }

        Ok(DataPacket {
            header: self.header,
            payload: self.payload,
            state: PhantomData,
        })
    }
}

/// Periodic 12-byte datagram the kernel sends to the host every 3 seconds
/// while idle (0x801ba418). Its source address is the target endpoint.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Beacon {
    /// Little-endian u64 copied from transport state +0x104 (0x80219664).
    /// No writer was found; observed zero.
    pub unidentified: u64,
    /// Host address from the kdnet settings, as the kernel stores it.
    pub host_address: Ipv4Addr,
}

impl Beacon {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            unidentified: wire::le64(bytes, 0)?,
            host_address: Ipv4Addr::from(wire::le32(bytes, 8)?),
        })
    }

    pub fn encode(&self) -> [u8; BEACON_LEN] {
        let mut bytes = [0u8; BEACON_LEN];
        wire::put_le64(&mut bytes, 0, self.unidentified);
        wire::put_le32(&mut bytes, 8, u32::from(self.host_address));

        bytes
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Datagram<'a> {
    Data(DataPacket<'a, Unverified>),
    Control(ControlPacket),
    Beacon(Beacon),
    /// Host to target only.
    BreakIn,
}

impl<'a> Datagram<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.len() < HEADER_LEN {
            if bytes.len() == BEACON_LEN {
                return Beacon::decode(bytes).map(Self::Beacon);
            }

            if bytes.first() == Some(&BREAK_IN[0]) {
                return Ok(Self::BreakIn);
            }

            return Err(DecodeError::UnrecognizedShortDatagram {
                length: bytes.len(),
            });
        }

        let header = PacketHeader::decode(bytes)?;

        match header.leader {
            CONTROL_LEADER => {
                let kind = ControlKind::from_packet_type(header.packet_type).ok_or(
                    DecodeError::UnknownControlType {
                        packet_type: header.packet_type,
                    },
                )?;

                Ok(Self::Control(ControlPacket {
                    kind,
                    id: header.id,
                }))
            }
            DATA_LEADER => {
                let declared = usize::from(header.byte_count);
                if declared > MAX_PAYLOAD_LEN {
                    return Err(DecodeError::PayloadTooLarge {
                        declared,
                        maximum: MAX_PAYLOAD_LEN,
                    });
                }

                let payload = &bytes[HEADER_LEN..];
                if payload.len() != declared {
                    return Err(DecodeError::PayloadLengthMismatch {
                        declared,
                        actual: payload.len(),
                    });
                }

                Ok(Self::Data(DataPacket {
                    header,
                    payload,
                    state: PhantomData,
                }))
            }
            leader => Err(DecodeError::UnknownLeader { leader }),
        }
    }
}

/// Encodes a data packet whose payload is the concatenation of `parts`.
/// Returns the datagram length written to `out`.
pub fn encode_data(
    out: &mut [u8],
    packet_type: PacketType,
    id: PacketId,
    parts: &[&[u8]],
) -> Result<usize, EncodeError> {
    let length: usize = parts.iter().map(|part| part.len()).sum();

    if length > MAX_PAYLOAD_LEN {
        return Err(EncodeError::PayloadTooLarge {
            length,
            maximum: MAX_PAYLOAD_LEN,
        });
    }

    let total = HEADER_LEN + length;
    if out.len() < total {
        return Err(EncodeError::BufferTooSmall {
            needed: total,
            actual: out.len(),
        });
    }

    let header = PacketHeader {
        leader: DATA_LEADER,
        packet_type,
        // Bounded by MAX_PAYLOAD_LEN above.
        byte_count: length as u16,
        id,
        checksum: Checksum::from_parts(parts),
    };
    out[..HEADER_LEN].copy_from_slice(&header.encode());

    let mut cursor = HEADER_LEN;
    for part in parts {
        out[cursor..cursor + part.len()].copy_from_slice(part);
        cursor += part.len();
    }

    Ok(total)
}
