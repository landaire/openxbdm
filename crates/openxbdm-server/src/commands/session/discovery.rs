//! The name discovery responder.

use crate::state::ServerState;

/// Receive buffer of a discovery request and size of the reply buffer.
pub const DISCOVERY_PACKET_CAPACITY: usize = 0x102;

xbox360_sys::flags! {
    /// Flag bits of a discovery request's kind byte.
    pub struct DiscoveryFlags(u8) {
        /// Send the reply to the broadcast address.
        BROADCAST = 0x80,
    }
}

xbox360_sys::value_enum! {
    /// Type of a name discovery datagram, without [`DiscoveryFlags::BROADCAST`].
    pub enum DiscoveryOpcode: u8 {
        /// Ask the console with the given debug name.
        Lookup = 1,
        Reply = 2,
        /// Ask every console for its name.
        Identify = 3,
    }
}

/// Where a discovery reply goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryDestination {
    /// The address and port the request came from.
    Sender,
    /// The broadcast address at the sender's port.
    Broadcast,
}

/// A discovery reply in the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryReply {
    pub length: usize,
    pub destination: DiscoveryDestination,
}

/// Answer a discovery datagram with the console's debug name.
pub fn answer_discovery(
    state: &ServerState,
    request: &[u8],
    reply: &mut [u8; DISCOVERY_PACKET_CAPACITY],
) -> Option<DiscoveryReply> {
    discovery_reply(state.console.debug_name.as_bytes(), request, reply)
}

/// Answer a name discovery datagram. Type 3 asks every console for its
/// name; type 1 asks the console whose debug name equals the given name,
/// ignoring ASCII case. The reply is type 2, a length byte, and the name.
/// Request bit 0x80 selects a broadcast reply. The monitor compares the
/// request name as a C string, so a name with a NUL matches by its text
/// before the NUL.
pub fn discovery_reply(
    name: &[u8],
    request: &[u8],
    reply: &mut [u8; DISCOVERY_PACKET_CAPACITY],
) -> Option<DiscoveryReply> {
    let (&kind, body) = request.split_first()?;
    let kind = DiscoveryFlags::from_bits_retain(kind);
    match DiscoveryOpcode::from_raw(kind.difference(DiscoveryFlags::BROADCAST).bits())? {
        // Every console answers.
        DiscoveryOpcode::Identify => {}
        DiscoveryOpcode::Lookup => {
            let (&length, requested) = body.split_first()?;
            let length = usize::from(length);
            if length == 0 || requested.len() != length {
                return None;
            }

            let text = requested
                .iter()
                .position(|&byte| byte == 0)
                .map_or(requested, |end| &requested[..end]);
            if !text.eq_ignore_ascii_case(name) {
                return None;
            }
        }
        DiscoveryOpcode::Reply => return None,
    }

    let length = name.len().min(usize::from(u8::MAX));
    reply[0] = DiscoveryOpcode::Reply.raw();
    reply[1] = length as u8;
    reply[2..2 + length].copy_from_slice(&name[..length]);

    let destination = if kind.intersects(DiscoveryFlags::BROADCAST) {
        DiscoveryDestination::Broadcast
    } else {
        DiscoveryDestination::Sender
    };

    Some(DiscoveryReply {
        length: 2 + length,
        destination,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_answers_identify_and_matching_lookup() {
        let mut reply = [0u8; DISCOVERY_PACKET_CAPACITY];
        let answer = discovery_reply(b"Kit", &[3], &mut reply).unwrap();
        assert_eq!(&reply[..answer.length], b"\x02\x03Kit");
        assert_eq!(answer.destination, DiscoveryDestination::Sender);
        let answer = discovery_reply(b"Kit", b"\x81\x03kIT", &mut reply).unwrap();
        assert_eq!(answer.destination, DiscoveryDestination::Broadcast);
        assert_eq!(discovery_reply(b"Kit", b"\x01\x02Ki", &mut reply), None);
        assert_eq!(discovery_reply(b"Kit", b"\x01\x03Kitx", &mut reply), None);
        assert_eq!(discovery_reply(b"Kit", b"\x02\x03Kit", &mut reply), None);
        assert_eq!(discovery_reply(b"", &[1, 0], &mut reply), None);
        let answer = discovery_reply(b"Kit", b"\x01\x05kit\0x", &mut reply).unwrap();
        assert_eq!(&reply[..answer.length], b"\x02\x03Kit");
        assert_eq!(discovery_reply(b"Kit", b"\x01\x04ki\0t", &mut reply), None);
    }
}
