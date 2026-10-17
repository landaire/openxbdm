//! Messages of the UDP tunnel between the console and the host, and the
//! IPv4 rewriting around them (stock hook 0x91f355e8, receive thread
//! 0x91f35798).

use core::ops::Range;
use core::time::Duration;

use xbox360_sys::xam::Protocol;

use crate::network::Endpoint;
use crate::network::Ipv4Address;

/// Largest tunnel message, and the receive buffer size.
pub const MESSAGE_LIMIT: usize = 0x5c0;
/// Receive timeout of the tunnel socket (`SO_RCVTIMEO`).
pub const RECEIVE_TIMEOUT: Duration = Duration::from_millis(5000);
/// Time without an outbound message after which a keepalive is sent.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(20_000);
/// The keepalive message.
pub const KEEPALIVE: [u8; 1] = [TunnelMessage::Keepalive.raw()];

xbox360_sys::value_enum! {
    /// Type byte of a tunnel message.
    pub enum TunnelMessage: u8 {
        Keepalive = 0x01,
        Tcp = 0x02,
        Udp = 0x03,
        /// UDP to the broadcast address.
        Broadcast = 0x04,
    }
}

const TCP_HEADER_LENGTH: usize = 5;
const UDP_HEADER_LENGTH: usize = 9;

/// Bytes of an IPv4 header without options.
pub const IPV4_HEADER_LENGTH: usize = 20;
/// Bytes of a UDP header.
pub const UDP_DATAGRAM_HEADER_LENGTH: usize = 8;
const PROTOCOL_TCP: u8 = Protocol::Tcp.raw() as u8;
const PROTOCOL_UDP: u8 = Protocol::Udp.raw() as u8;
/// Fragment offset and more-fragments bits of the IPv4 flags word.
const FRAGMENT_MASK: u16 = 0x3fff;
const BROADCAST: [u8; 4] = Ipv4Address::BROADCAST.octets();
const LOOPBACK: [u8; 4] = Ipv4Address::LOOPBACK.octets();
/// Time to live of injected packets.
const INJECTED_TTL: u8 = 1;

/// Endpoints of the tunnel socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tunnel {
    pub local: Endpoint,
    pub host: Endpoint,
}

/// An outbound packet rewritten in place into a UDP datagram to the host.
/// The datagram is the packet's IPv4 header, [`Self::udp`], the message
/// header, and the packet bytes in [`Self::payload`], in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    /// Bytes of the IPv4 header at the start of the packet.
    pub header_length: usize,
    pub udp: [u8; UDP_DATAGRAM_HEADER_LENGTH],
    message: [u8; UDP_HEADER_LENGTH],
    message_length: usize,
    /// The packet bytes carried after the message header.
    pub payload: Range<usize>,
}

impl Outbound {
    /// The tunnel message header.
    pub fn message(&self) -> &[u8] {
        &self.message[..self.message_length]
    }
}

/// Wrap an outbound IPv4 packet for the tunnel: TCP becomes `{0x02, dst
/// ip, segment}` and UDP `{0x03 or 0x04 (broadcast), dst ip, dst port, src
/// port, payload}`. The packet header becomes a UDP header from the local
/// endpoint to the host; its length and checksum fields are left as they
/// were. `None`: the packet is not tunneled (options, fragments, other
/// protocols, too large, or truncated).
///
/// The TCP checksum and urgent pointer are zeroed before the size check,
/// so a TCP packet too large for the tunnel leaves with them zeroed.
pub fn encapsulate(packet: &mut [u8], tunnel: &Tunnel) -> Option<Outbound> {
    let header_length = usize::from(*packet.first()? & 0x0f) * 4;
    if header_length > IPV4_HEADER_LENGTH || packet.len() < IPV4_HEADER_LENGTH {
        return None;
    }
    if u16::from_be_bytes([packet[6], packet[7]]) & FRAGMENT_MASK != 0 {
        return None;
    }
    let [d0, d1, d2, d3] = [packet[16], packet[17], packet[18], packet[19]];
    let (message, message_length, payload) = match packet[9] {
        PROTOCOL_TCP => {
            packet.get_mut(header_length..)?.get_mut(16..20)?.fill(0);
            (
                [TunnelMessage::Tcp.raw(), d0, d1, d2, d3, 0, 0, 0, 0],
                TCP_HEADER_LENGTH,
                header_length..packet.len(),
            )
        }
        PROTOCOL_UDP => {
            let ports = packet.get(header_length..header_length + UDP_DATAGRAM_HEADER_LENGTH)?;
            let kind = if [d0, d1, d2, d3] == BROADCAST {
                TunnelMessage::Broadcast
            } else {
                TunnelMessage::Udp
            };
            (
                [
                    kind.raw(),
                    d0,
                    d1,
                    d2,
                    d3,
                    ports[2],
                    ports[3],
                    ports[0],
                    ports[1],
                ],
                UDP_HEADER_LENGTH,
                header_length + UDP_DATAGRAM_HEADER_LENGTH..packet.len(),
            )
        }
        _ => return None,
    };
    let carried = message_length + payload.len();
    if carried > MESSAGE_LIMIT {
        return None;
    }
    packet[9] = PROTOCOL_UDP;
    packet[12..16].copy_from_slice(&tunnel.local.address.octets());
    packet[16..20].copy_from_slice(&tunnel.host.address.octets());
    let [s0, s1] = tunnel.local.port.to_be_bytes();
    let [h0, h1] = tunnel.host.port.to_be_bytes();
    let [l0, l1] = ((carried + UDP_DATAGRAM_HEADER_LENGTH) as u16).to_be_bytes();
    Some(Outbound {
        header_length,
        udp: [s0, s1, h0, h1, l0, l1, 0, 0],
        message,
        message_length,
        payload,
    })
}

/// A message received from the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound<'a> {
    Keepalive,
    Packet(Injected<'a>),
}

/// An IPv4 packet to inject into the console network stack: [`Self::ip`],
/// then [`Self::udp`] if present, then [`Self::payload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Injected<'a> {
    pub ip: [u8; IPV4_HEADER_LENGTH],
    pub udp: Option<[u8; UDP_DATAGRAM_HEADER_LENGTH]>,
    /// The TCP segment, or the UDP payload.
    pub payload: &'a [u8],
}

/// Decode a message from the host. TCP `{0x02, src ip, segment}` and UDP
/// `{0x03 or 0x04, src ip, src port, dst port, payload}` get a synthetic
/// IPv4 header (TTL 1, checksum 0) addressed to 127.0.0.1, or to
/// 255.255.255.255 for 0x04; the UDP header has checksum 0. `None`: the
/// message is ignored (unknown type or truncated).
pub fn decapsulate(message: &[u8]) -> Option<Inbound<'_>> {
    let (protocol, udp, payload, destination) = match TunnelMessage::from_raw(*message.first()?)? {
        TunnelMessage::Keepalive => return Some(Inbound::Keepalive),
        TunnelMessage::Tcp if message.len() >= TCP_HEADER_LENGTH => {
            (PROTOCOL_TCP, None, &message[TCP_HEADER_LENGTH..], LOOPBACK)
        }
        kind @ (TunnelMessage::Udp | TunnelMessage::Broadcast)
            if message.len() >= UDP_HEADER_LENGTH =>
        {
            let payload = &message[UDP_HEADER_LENGTH..];
            let [l0, l1] = ((payload.len() + UDP_DATAGRAM_HEADER_LENGTH) as u16).to_be_bytes();
            let udp = [message[5], message[6], message[7], message[8], l0, l1, 0, 0];
            let destination = if kind == TunnelMessage::Broadcast {
                BROADCAST
            } else {
                LOOPBACK
            };
            (PROTOCOL_UDP, Some(udp), payload, destination)
        }
        _ => return None,
    };
    let udp_length = if udp.is_some() {
        UDP_DATAGRAM_HEADER_LENGTH
    } else {
        0
    };
    let [t0, t1] = ((IPV4_HEADER_LENGTH + udp_length + payload.len()) as u16).to_be_bytes();
    let [s0, s1, s2, s3] = [message[1], message[2], message[3], message[4]];
    let [d0, d1, d2, d3] = destination;
    let ip = [
        0x45,
        0,
        t0,
        t1,
        0,
        0,
        0,
        0,
        INJECTED_TTL,
        protocol,
        0,
        0,
        s0,
        s1,
        s2,
        s3,
        d0,
        d1,
        d2,
        d3,
    ];
    Some(Inbound::Packet(Injected { ip, udp, payload }))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use super::*;
    use crate::network::Ipv4Address;

    const TUNNEL: Tunnel = Tunnel {
        local: Endpoint {
            address: Ipv4Address([10, 0, 0, 2]),
            port: 0xc001,
        },
        host: Endpoint {
            address: Ipv4Address([10, 0, 0, 9]),
            port: 0x1234,
        },
    };

    fn ipv4(protocol: u8, destination: [u8; 4], transport: &[u8]) -> Vec<u8> {
        let mut packet = vec![
            0x45,
            0,
            0,
            0,
            0xab,
            0xcd,
            0x40,
            0,
            64,
            protocol,
            0x5a,
            0x5a,
            10,
            0,
            0,
            2,
            destination[0],
            destination[1],
            destination[2],
            destination[3],
        ];
        let total = (packet.len() + transport.len()) as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(transport);
        packet
    }

    fn tcp_segment() -> Vec<u8> {
        let mut segment = vec![0x11; 20];
        segment.extend_from_slice(b"data");
        segment
    }

    #[test]
    fn tcp_packet_becomes_tunnel_datagram() {
        let mut packet = ipv4(PROTOCOL_TCP, [192, 168, 1, 7], &tcp_segment());
        let outbound = encapsulate(&mut packet, &TUNNEL).unwrap();
        assert_eq!(outbound.header_length, 20);
        assert_eq!(outbound.message(), [0x02, 192, 168, 1, 7]);
        assert_eq!(outbound.payload, 20..44);
        assert_eq!(outbound.udp, [0xc0, 0x01, 0x12, 0x34, 0x00, 0x25, 0, 0]);
        assert_eq!(
            packet[..20],
            [
                0x45, 0, 0, 44, 0xab, 0xcd, 0x40, 0, 64, 17, 0x5a, 0x5a, 10, 0, 0, 2, 10, 0, 0, 9
            ]
        );
        assert_eq!(packet[20..36], [0x11; 16]);
        assert_eq!(packet[36..40], [0; 4]);
    }

    #[test]
    fn udp_packet_carries_ports_remote_first() {
        let datagram = [
            0x04, 0xd2, 0x00, 0x35, 0x00, 0x0b, 0xee, 0xee, b'a', b'b', b'c',
        ];
        let mut packet = ipv4(PROTOCOL_UDP, [8, 8, 8, 8], &datagram);
        let outbound = encapsulate(&mut packet, &TUNNEL).unwrap();
        assert_eq!(
            outbound.message(),
            [0x03, 8, 8, 8, 8, 0x00, 0x35, 0x04, 0xd2]
        );
        assert_eq!(&packet[outbound.payload.clone()], b"abc");
        assert_eq!(outbound.udp, [0xc0, 0x01, 0x12, 0x34, 0x00, 0x14, 0, 0]);
    }

    #[test]
    fn udp_broadcast_uses_message_4() {
        let datagram = [0x00, 0x44, 0x00, 0x43, 0x00, 0x08, 0, 0];
        let mut packet = ipv4(PROTOCOL_UDP, BROADCAST, &datagram);
        let outbound = encapsulate(&mut packet, &TUNNEL).unwrap();
        assert_eq!(
            outbound.message(),
            [0x04, 0xff, 0xff, 0xff, 0xff, 0x00, 0x43, 0x00, 0x44]
        );
        assert!(outbound.payload.is_empty());
    }

    #[test]
    fn fragments_options_and_other_protocols_pass() {
        let mut fragment = ipv4(PROTOCOL_UDP, [8, 8, 8, 8], &[0; 8]);
        fragment[6] = 0x20;
        let mut options = ipv4(PROTOCOL_UDP, [8, 8, 8, 8], &[0; 12]);
        options[0] = 0x46;
        let mut icmp = ipv4(1, [8, 8, 8, 8], &[0; 8]);
        for packet in [&mut fragment, &mut options, &mut icmp] {
            let original = packet.clone();
            assert_eq!(encapsulate(packet, &TUNNEL), None);
            assert_eq!(*packet, original);
        }
    }

    #[test]
    fn oversized_tcp_passes_with_checksum_zeroed() {
        let mut segment = tcp_segment();
        segment.resize(MESSAGE_LIMIT - TCP_HEADER_LENGTH + 1, 0x22);
        let mut packet = ipv4(PROTOCOL_TCP, [192, 168, 1, 7], &segment);
        assert_eq!(encapsulate(&mut packet, &TUNNEL), None);
        assert_eq!(packet[9], PROTOCOL_TCP);
        assert_eq!(packet[16..20], [192, 168, 1, 7]);
        assert_eq!(packet[36..40], [0; 4]);
    }

    #[test]
    fn largest_udp_payload_fits() {
        let mut datagram = vec![0; UDP_DATAGRAM_HEADER_LENGTH + MESSAGE_LIMIT - UDP_HEADER_LENGTH];
        let mut packet = ipv4(PROTOCOL_UDP, [8, 8, 8, 8], &datagram);
        assert!(encapsulate(&mut packet, &TUNNEL).is_some());
        datagram.push(0);
        let mut packet = ipv4(PROTOCOL_UDP, [8, 8, 8, 8], &datagram);
        assert_eq!(encapsulate(&mut packet, &TUNNEL), None);
    }

    #[test]
    fn tcp_message_becomes_loopback_packet() {
        let message = [0x02, 192, 168, 1, 7, 0xaa, 0xbb, 0xcc];
        let Some(Inbound::Packet(packet)) = decapsulate(&message) else {
            panic!()
        };
        assert_eq!(
            packet.ip,
            [
                0x45, 0, 0, 23, 0, 0, 0, 0, 1, 6, 0, 0, 192, 168, 1, 7, 127, 0, 0, 1
            ]
        );
        assert_eq!(packet.udp, None);
        assert_eq!(packet.payload, [0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn udp_messages_become_udp_packets() {
        let message = [0x03, 8, 8, 4, 4, 0x00, 0x35, 0x04, 0xd2, b'x'];
        let Some(Inbound::Packet(packet)) = decapsulate(&message) else {
            panic!()
        };
        assert_eq!(
            packet.ip,
            [
                0x45, 0, 0, 29, 0, 0, 0, 0, 1, 17, 0, 0, 8, 8, 4, 4, 127, 0, 0, 1
            ]
        );
        assert_eq!(packet.udp, Some([0x00, 0x35, 0x04, 0xd2, 0x00, 0x09, 0, 0]));
        assert_eq!(packet.payload, b"x");

        let message = [0x04, 10, 0, 0, 9, 0x00, 0x43, 0x00, 0x44];
        let Some(Inbound::Packet(packet)) = decapsulate(&message) else {
            panic!()
        };
        assert_eq!(packet.ip[16..20], BROADCAST);
        assert_eq!(packet.ip[2..4], [0, 28]);
    }

    #[test]
    fn keepalive_short_and_unknown_messages() {
        assert_eq!(decapsulate(&KEEPALIVE), Some(Inbound::Keepalive));
        assert_eq!(decapsulate(&[0x01, 0xff]), Some(Inbound::Keepalive));
        assert_eq!(decapsulate(&[0x02, 1, 2, 3]), None);
        assert_eq!(decapsulate(&[0x03, 1, 2, 3, 4, 5, 6, 7]), None);
        assert_eq!(decapsulate(&[0x00, 1, 2, 3, 4, 5, 6, 7, 8]), None);
        assert_eq!(decapsulate(&[0x05, 1, 2, 3, 4, 5, 6, 7, 8]), None);
        assert_eq!(decapsulate(&[]), None);
    }
}
