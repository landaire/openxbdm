//! Decoding of a data packet payload by packet type.

use crate::DecodeError;
use crate::debug_io::DebugIo;
use crate::file_io::FileIoRequest;
use crate::manipulate::Reply;
use crate::packet::ChecksumState;
use crate::packet::DataPacket;
use crate::packet::PacketType;
use crate::state_change::StateChange;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Message<'a> {
    Manipulate(Reply<'a>),
    StateChange(StateChange<'a>),
    DebugIo(DebugIo<'a>),
    FileIo(FileIoRequest<'a>),
    Other {
        packet_type: PacketType,
        payload: &'a [u8],
    },
}

impl<'a> Message<'a> {
    pub fn decode<S>(packet: &DataPacket<'a, S>) -> Result<Self, DecodeError>
    where
        S: ChecksumState,
    {
        let payload = packet.payload();

        let message = match packet.packet_type() {
            PacketType::MANIPULATE => Self::Manipulate(Reply::decode(payload)?),
            PacketType::STATE_CHANGE => Self::StateChange(StateChange::decode(payload)?),
            PacketType::DEBUG_IO => Self::DebugIo(DebugIo::decode(payload)?),
            PacketType::FILE_IO => Self::FileIo(FileIoRequest::decode(payload)?),
            packet_type => Self::Other {
                packet_type,
                payload,
            },
        };

        Ok(message)
    }
}
