//! Host side of the packet exchange.
//!
//! Kernel behavior this models (0x801ba588 receive, 0x801ba848 send):
//!
//! - Every data packet is answered with an acknowledgement echoing its id.
//!   A bad checksum, bad length, or unexpected type is answered with a
//!   resend request instead.
//! - A sender keeps one data packet outstanding and retransmits it until
//!   it is acknowledged. The kernel retries every 0.5 s.
//! - A reset sets the receiver's expected id to the reset's id; the kernel
//!   answers with a reset carrying its own next id and repeats its last
//!   state change.
//! - While waiting for an acknowledgement the kernel treats a data packet
//!   carrying its expected id as an implicit acknowledgement and requests
//!   a resend of it.
//!
//! The host mirrors this: one outstanding packet, duplicate suppression by
//! id, and a reset at the start of a session so the kernel's expected id
//! matches the host's numbering. Only an acknowledgement retires the
//! host's packet: a kernel data packet may predate it, as when the kernel
//! repeats its stop after a reset and answers the host's request with a
//! resend request.

mod error;

use crate::DecodeError;
use crate::packet::Beacon;
use crate::packet::ControlKind;
use crate::packet::ControlPacket;
use crate::packet::DataPacket;
use crate::packet::Datagram;
use crate::packet::HEADER_LEN;
use crate::packet::MAX_DATAGRAM_LEN;
use crate::packet::PacketId;
use crate::packet::PacketType;
use crate::packet::Verified;
use crate::packet::encode_data;

pub use self::error::SessionError;

#[derive(Debug, Clone)]
pub enum Event<'a> {
    /// A new data packet.
    Data(DataPacket<'a, Verified>),
    /// A retransmission of the last data packet.
    Duplicate(PacketId),
    /// A data packet that failed validation; a resend was requested.
    Corrupt(DecodeError),
    /// The outstanding packet was acknowledged.
    Acknowledged(PacketId),
    /// An acknowledgement for a packet that is not outstanding.
    UnmatchedAcknowledge(PacketId),
    /// The kernel asks for the outstanding packet again.
    ResendRequested,
    /// The kernel reset packet numbering; `target_next_id` is the id of
    /// its next data packet.
    Reset {
        target_next_id: PacketId,
    },
    Beacon(Beacon),
}

#[derive(Debug, Clone)]
pub struct Received<'a> {
    /// Control packet to transmit in response.
    pub reply: Option<[u8; HEADER_LEN]>,
    pub event: Event<'a>,
}

pub struct Session {
    next_send_id: PacketId,
    last_received: Option<PacketId>,

    outstanding: Option<PacketId>,
    outstanding_len: usize,
    outstanding_bytes: [u8; MAX_DATAGRAM_LEN],
}

impl Session {
    pub const fn new() -> Self {
        Self {
            next_send_id: PacketId::HOST_INITIAL,
            last_received: None,
            outstanding: None,
            outstanding_len: 0,
            outstanding_bytes: [0; MAX_DATAGRAM_LEN],
        }
    }

    pub fn outstanding(&self) -> Option<PacketId> {
        self.outstanding
    }

    /// Encodes a data packet and makes it the outstanding packet. Returns
    /// the datagram to transmit.
    pub fn send(
        &mut self,
        packet_type: PacketType,
        parts: &[&[u8]],
    ) -> Result<&[u8], SessionError> {
        if let Some(outstanding) = self.outstanding {
            return Err(SessionError::Outstanding { outstanding });
        }

        let id = self.next_send_id;
        let length = encode_data(&mut self.outstanding_bytes, packet_type, id, parts)?;

        self.next_send_id = id.next();
        self.outstanding = Some(id);
        self.outstanding_len = length;

        Ok(&self.outstanding_bytes[..length])
    }

    /// The outstanding datagram, for retransmission after a timeout or a
    /// resend request.
    pub fn retransmission(&self) -> Option<&[u8]> {
        self.outstanding
            .map(|_| &self.outstanding_bytes[..self.outstanding_len])
    }

    /// Forgets the outstanding packet without an acknowledgement.
    pub fn abandon(&mut self) {
        self.outstanding = None;
    }

    /// Starts renumbering. The kernel adopts the returned packet's id as
    /// its expected id.
    pub fn reset(&mut self) -> [u8; HEADER_LEN] {
        self.outstanding = None;
        self.last_received = None;

        ControlPacket::new(ControlKind::Reset, self.next_send_id).encode()
    }

    pub fn receive<'a>(&mut self, datagram: &'a [u8]) -> Result<Received<'a>, DecodeError> {
        let decoded = match Datagram::decode(datagram) {
            Ok(decoded) => decoded,
            Err(
                error @ (DecodeError::PayloadTooLarge { .. }
                | DecodeError::PayloadLengthMismatch { .. }),
            ) => {
                return Ok(self.corrupt(error));
            }
            Err(error) => return Err(error),
        };

        let received = match decoded {
            Datagram::Data(packet) => match packet.verify() {
                Err(error) => self.corrupt(error),
                Ok(packet) => {
                    let id = packet.id();
                    let reply = Some(ControlPacket::new(ControlKind::Acknowledge, id).encode());

                    let event = if self.last_received == Some(id) {
                        Event::Duplicate(id)
                    } else {
                        self.last_received = Some(id);
                        Event::Data(packet)
                    };

                    Received { reply, event }
                }
            },
            Datagram::Control(control) => {
                let event = match control.kind {
                    ControlKind::Acknowledge if self.outstanding == Some(control.id) => {
                        self.outstanding = None;
                        Event::Acknowledged(control.id)
                    }
                    ControlKind::Acknowledge => Event::UnmatchedAcknowledge(control.id),
                    ControlKind::Resend => Event::ResendRequested,
                    ControlKind::Reset => {
                        self.last_received = None;
                        Event::Reset {
                            target_next_id: control.id,
                        }
                    }
                };

                Received { reply: None, event }
            }
            Datagram::Beacon(beacon) => Received {
                reply: None,
                event: Event::Beacon(beacon),
            },
            Datagram::BreakIn => {
                return Err(DecodeError::UnrecognizedShortDatagram {
                    length: datagram.len(),
                });
            }
        };

        Ok(received)
    }

    fn corrupt<'a>(&self, error: DecodeError) -> Received<'a> {
        Received {
            reply: Some(ControlPacket::new(ControlKind::Resend, PacketId(0)).encode()),
            event: Event::Corrupt(error),
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}
