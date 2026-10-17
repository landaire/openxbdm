//! Frame parsing (frame library 0x91f68320, the classification the
//! simulator's redirects and classifiers read) and address rewriting for
//! IPv4 redirects (0x91f8d008).

use xbox360_sys::xam::Protocol;

pub(super) const ETHERNET_HEADER: usize = 14;
const IPV4_HEADER: usize = 20;
const TCP_HEADER: usize = 20;
pub(super) const UDP_HEADER: usize = 8;
/// Largest transport segment stock checksums (its gather buffer at
/// 0x91fa30a8 holds 0x5ea bytes).
const GATHER_CAPACITY: usize = 0x5ea;

/// Ethernet header fields.
mod ethernet {
    pub(super) const TYPE: usize = 12;
    /// Largest IEEE 802.3 length; larger values are EtherTypes.
    pub(super) const MAXIMUM_LENGTH: u16 = 0x5dc;
    /// Group bit of the first destination byte.
    pub(super) const GROUP: u8 = 1;
    pub(super) const BROADCAST: [u8; 6] = [0xff; 6];
}

/// EtherTypes the parser recognizes.
mod ether_type {
    pub(super) const IPV4: u16 = 0x0800;
    pub(super) const ARP: u16 = 0x0806;
    pub(super) const PPPOE_DISCOVERY: u16 = 0x8863;
    pub(super) const PPPOE_SESSION: u16 = 0x8864;
    /// Types stock also counts as PPPoE.
    pub(super) const PPPOE_3C12: u16 = 0x3c12;
    pub(super) const PPPOE_3C13: u16 = 0x3c13;
    pub(super) const LLTD: u16 = 0x88d9;
}

/// IPv4 header fields and the address classes the parser rejects.
pub(super) mod ipv4 {
    pub(in super::super) const VERSION_LENGTH: usize = 0;
    pub(in super::super) const TOTAL_LENGTH: usize = 2;
    pub(in super::super) const IDENTIFICATION: usize = 4;
    pub(in super::super) const FRAGMENT: usize = 6;
    pub(in super::super) const TIME_TO_LIVE: usize = 8;
    pub(in super::super) const PROTOCOL: usize = 9;
    pub(in super::super) const CHECKSUM: usize = 10;
    pub(in super::super) const SOURCE: usize = 12;
    pub(in super::super) const DESTINATION: usize = 16;
    pub(super) const VERSION_MASK: u8 = 0xf0;
    pub(super) const VERSION_4: u8 = 0x40;
    /// Header length in words.
    pub(super) const LENGTH_MASK: u8 = 0xf;
    pub(super) const BROADCAST: u32 = u32::MAX;

    /// Class D: 224.0.0.0/4.
    #[inline(always)]
    pub(super) fn is_multicast(address: u32) -> bool {
        address & 0xf000_0000 == 0xe000_0000
    }

    /// 127.0.0.0/8.
    #[inline(always)]
    pub(super) fn is_loopback(address: u32) -> bool {
        address & 0xff00_0000 == 0x7f00_0000
    }
}

/// IPv4 protocol numbers.
mod ip_protocol {
    use super::Protocol;

    pub(super) const ICMP: u8 = 1;
    pub(super) const IGMP: u8 = 2;
    pub(super) const TCP: u8 = Protocol::Tcp.raw() as u8;
    pub(super) const UDP: u8 = Protocol::Udp.raw() as u8;
    pub(super) const ESP: u8 = 0x32;
}

/// Offsets shared by the TCP and UDP headers.
mod transport {
    pub(super) const SOURCE_PORT: usize = 0;
    pub(super) const DESTINATION_PORT: usize = 2;
}

mod tcp {
    pub(super) const SEQUENCE: usize = 4;
    /// End of the acknowledgment number.
    pub(super) const ACKNOWLEDGMENT_END: usize = 12;
    /// Data offset in words, in the high nibble.
    pub(super) const DATA_OFFSET: usize = 12;
    pub(super) const FLAGS: usize = 13;
    pub(super) const WINDOW: usize = 14;
    pub(super) const CHECKSUM: usize = 16;
}

pub(super) mod udp {
    pub(in super::super) const LENGTH: usize = 4;
    pub(in super::super) const CHECKSUM: usize = 6;
}

/// UDP ports the parser classifies.
mod port {
    pub(super) const DNS: u16 = 53;
    pub(super) const KERBEROS: u16 = 88;
    pub(super) const BOOTP_SERVER: u16 = 67;
    pub(super) const BOOTP_CLIENT: u16 = 68;
    pub(super) const NETBIOS_NAME: u16 = 137;
    pub(super) const NETBIOS_DATAGRAM: u16 = 138;
    pub(super) const NETBIOS_SESSION: u16 = 139;
    pub(super) const IKE: u16 = 500;
    /// Both XSP ports lie above this.
    pub(super) const XSP_MINIMUM: u16 = 0x400;
    /// Base of the XSP ports a header encodes in one byte.
    pub(super) const XSP_BASE: u16 = 1000;
}

/// BOOTP message fields and DHCP options.
mod dhcp {
    /// Fixed fields and the magic cookie.
    pub(super) const HEADER: usize = 0xf0;
    pub(super) const OPERATION: usize = 0;
    pub(super) const HARDWARE_TYPE: usize = 1;
    pub(super) const HARDWARE_LENGTH: usize = 2;
    pub(super) const TRANSACTION: usize = 4;
    pub(super) const SERVER_NAME: usize = 0x2c;
    pub(super) const SERVER_NAME_LENGTH: usize = 0x40;
    pub(super) const FILE: usize = 0x6c;
    pub(super) const FILE_LENGTH: usize = 0x80;
    pub(super) const COOKIE: usize = 0xec;
    pub(super) const MAGIC_COOKIE: u32 = 0x6382_5363;
    pub(super) const HARDWARE_ETHERNET: u8 = 1;
    pub(super) const ETHERNET_ADDRESS_LENGTH: u8 = 6;
    pub(super) const OPTION_PAD: u8 = 0;
    pub(super) const OPTION_END: u8 = 0xff;
    pub(super) const OPTION_OVERLOAD: u8 = 52;
    pub(super) const OPTION_MESSAGE_TYPE: u8 = 53;
    /// Overload option bits.
    pub(super) const OVERLOAD_FILE: u8 = 1;
    pub(super) const OVERLOAD_SERVER_NAME: u8 = 2;
}

/// ARP header fields and values.
pub(super) mod arp {
    pub(super) const HARDWARE_TYPE: usize = 0;
    pub(super) const PROTOCOL_TYPE: usize = 2;
    pub(super) const HARDWARE_LENGTH: usize = 4;
    pub(super) const PROTOCOL_LENGTH: usize = 5;
    pub(in super::super) const OPERATION: usize = 6;
    pub(super) const HEADER: usize = 8;
    /// Packet offsets of the addresses after the header.
    pub(in super::super) const SENDER_HARDWARE: usize = 8;
    pub(in super::super) const SENDER_PROTOCOL: usize = 14;
    pub(in super::super) const TARGET_HARDWARE: usize = 18;
    pub(in super::super) const TARGET_PROTOCOL: usize = 24;
    /// Address bytes after the header.
    pub(super) const BODY: usize = TARGET_PROTOCOL + 4 - HEADER;
    pub(super) const HARDWARE_ETHERNET: u16 = 1;
    pub(super) const HARDWARE_IEEE_802: u16 = 6;
    pub(super) const ETHERNET_ADDRESS_LENGTH: u8 = 6;
    pub(super) const IPV4_ADDRESS_LENGTH: u8 = 4;
    pub(super) const REQUEST: u16 = 1;
    pub(super) const REPLY: u16 = 2;
}

/// ICMP header fields, the message types the parser accepts, and the
/// number of codes of the types that limit them.
mod icmp {
    pub(super) const HEADER: usize = 8;
    pub(super) const TYPE: usize = 0;
    pub(super) const CODE: usize = 1;
    pub(super) const ECHO_REPLY: u8 = 0;
    pub(super) const DESTINATION_UNREACHABLE: u8 = 3;
    pub(super) const SOURCE_QUENCH: u8 = 4;
    pub(super) const REDIRECT: u8 = 5;
    pub(super) const ECHO: u8 = 8;
    pub(super) const ROUTER_ADVERTISEMENT: u8 = 9;
    pub(super) const ROUTER_SOLICITATION: u8 = 10;
    pub(super) const TIME_EXCEEDED: u8 = 11;
    pub(super) const PARAMETER_PROBLEM: u8 = 12;
    pub(super) const TIMESTAMP: u8 = 13;
    pub(super) const ADDRESS_MASK_REPLY: u8 = 18;
    pub(super) const DESTINATION_UNREACHABLE_CODES: u8 = 0xe;
    pub(super) const REDIRECT_CODES: u8 = 4;
    /// Codes of time exceeded and parameter problem.
    pub(super) const TIME_EXCEEDED_CODES: u8 = 2;
}

/// Base kinds of an XSP header word (low nibble of its first byte, less
/// the port form). Kinds 4 and 0xd have no known name.
mod xsp_kind {
    pub(super) const SECURE_MESSAGE: usize = 0;
    pub(super) const TCP_INFO: usize = 1;
    pub(super) const UNNAMED_4: usize = 4;
    pub(super) const VOICE_PAYLOAD: usize = 7;
    pub(super) const VOICE_ONLY_PAYLOAD: usize = 0xa;
    pub(super) const UNNAMED_D: usize = 0xd;
}

/// Key exchange packet kinds the parser accepts (first word after the
/// zero XSP header word).
mod key_exchange_kind {
    pub(super) const KEY_EX_XB_TO_XB_INIT: u16 = 0x58;
    pub(super) const KEY_EX_XB_TO_XB_RESP: u16 = 0x158;
    pub(super) const KEY_EX_XB_TO_SG_INIT: u16 = 0x258;
    pub(super) const KEY_EX_SG_TO_XB_RESP: u16 = 0x358;
    pub(super) const KEY_EX_NAT_OPEN_INIT: u16 = 0x458;
    pub(super) const KEY_EX_NAT_OPEN_RESP: u16 = 0x558;
    pub(super) const KEY_EX_QOS_INIT: u16 = 0x658;
    pub(super) const KEY_EX_QOS_RESP: u16 = 0x758;
    pub(super) const KEY_EX_XB_TO_XB_INIT2: u16 = 0xa58;
    pub(super) const KEY_EX_XB_TO_XB_RESP2: u16 = 0xb58;
    pub(super) const KEY_EX_NAT_OPEN2: u16 = 0xc58;
    pub(super) const KEY_EX_XB_TO_XB3_INIT: u16 = 0xe58;
    pub(super) const KEY_EX_XB_TO_XB_RESP3: u16 = 0xf58;
    pub(super) const KEY_EX_NAT_OPEN3: u16 = 0x1058;
    pub(super) const KEY_EX_QOS_INIT2: u16 = 0x1158;
}

/// Hash trailer of an XSP datagram.
const XSP_TRAILER: usize = 0xc;

/// XSP subtype: a nonzero value that fits the 5-bit field of
/// [`FrameFlags`]. Names follow the classifier fields; subtypes 3 and 6
/// have none and are named after header kinds 4 and 0xd, which set them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct XspSubtype(u8);

impl XspSubtype {
    const MAXIMUM: u8 = 0x1f;
    pub(super) const SECURE_MESSAGE: Self = Self::known(1);
    pub(super) const TCP_INFO: Self = Self::known(2);
    pub(super) const OF_UNNAMED_KIND_4: Self = Self::known(3);
    pub(super) const VOICE_PAYLOAD: Self = Self::known(4);
    pub(super) const VOICE_ONLY_PAYLOAD: Self = Self::known(5);
    pub(super) const OF_UNNAMED_KIND_D: Self = Self::known(6);
    pub(super) const KEY_EX_XB_TO_XB_INIT: Self = Self::known(7);
    pub(super) const KEY_EX_XB_TO_XB_RESP: Self = Self::known(8);
    pub(super) const KEY_EX_XB_TO_SG_INIT: Self = Self::known(9);
    pub(super) const KEY_EX_SG_TO_XB_RESP: Self = Self::known(0xa);
    pub(super) const KEY_EX_NAT_OPEN_INIT: Self = Self::known(0xb);
    pub(super) const KEY_EX_NAT_OPEN_RESP: Self = Self::known(0xc);
    pub(super) const KEY_EX_QOS_INIT: Self = Self::known(0xd);
    pub(super) const KEY_EX_QOS_RESP: Self = Self::known(0xe);
    pub(super) const KEY_EX_XB_TO_LSPSG_INIT: Self = Self::known(0xf);
    pub(super) const KEY_EX_LSPSG_TO_XB_RESP: Self = Self::known(0x10);
    pub(super) const KEY_EX_XB_TO_XB_INIT2: Self = Self::known(0x11);
    pub(super) const KEY_EX_XB_TO_XB_RESP2: Self = Self::known(0x12);
    pub(super) const KEY_EX_NAT_OPEN2: Self = Self::known(0x13);
    pub(super) const QOS_SETUP: Self = Self::known(0x14);
    pub(super) const KEY_EX_XB_TO_XB3_INIT: Self = Self::known(0x15);
    pub(super) const KEY_EX_XB_TO_XB_RESP3: Self = Self::known(0x16);
    pub(super) const KEY_EX_NAT_OPEN3: Self = Self::known(0x17);
    pub(super) const KEY_EX_QOS_INIT2: Self = Self::known(0x18);

    /// `None` for zero (no subtype) or a value wider than five bits.
    #[inline]
    pub(super) const fn new(value: u8) -> Option<Self> {
        if value != 0 && value <= Self::MAXIMUM {
            Some(Self(value))
        } else {
            None
        }
    }

    /// For constants: an out-of-range value fails compilation.
    const fn known(value: u8) -> Self {
        match Self::new(value) {
            Some(subtype) => subtype,
            None => panic!("XSP subtype out of range"),
        }
    }

    #[inline]
    pub(super) const fn get(self) -> u8 {
        self.0
    }
}

xbox360_sys::flags! {
    /// Parse flags (stock frame information +0x00). Bits 16..20 hold the
    /// [`XspSubtype`], reached through [`FrameFlags::xsp_subtype`].
    pub struct FrameFlags(u32) {
        ETHERNET = 0x1,
        IPV4 = 0x2,
        ARP = 0x4,
        PPPOE = 0x8,
        LLTD = 0x10,
        ICMP = 0x20,
        IGMP = 0x40,
        TCP = 0x80,
        UDP = 0x100,
        DNS = 0x200,
        DHCP = 0x400,
        ESP = 0x800,
        NETBIOS = 0x1000,
        IEEE_802_3 = 0x2000,
        IKE = 0x4000,
        KERBEROS = 0x20_0000,
        MALFORMED = 0x8000_0000,
    }
}

impl FrameFlags {
    const XSP_FIELD: u32 = 0x1f_0000;
    const XSP_SHIFT: u32 = 16;
    /// The bits redirect sessions keep: TCP or UDP.
    pub(super) const TRANSPORT: Self = Self(Self::TCP.0 | Self::UDP.0);

    #[inline]
    pub(super) const fn xsp_subtype(self) -> Option<XspSubtype> {
        XspSubtype::new(((self.0 & Self::XSP_FIELD) >> Self::XSP_SHIFT) as u8)
    }

    /// `self` with `subtype` added; the parser sets at most one subtype.
    #[inline]
    pub(super) const fn with_xsp(self, subtype: XspSubtype) -> Self {
        Self(self.0 | (subtype.0 as u32) << Self::XSP_SHIFT)
    }
}

xbox360_sys::flags! {
    /// TCP fields present in the information block.
    pub struct TcpFields(u8) {
        SEQUENCE = 0x1,
        ACKNOWLEDGMENT = 0x2,
        WINDOW = 0x4,
    }
}

/// Offsets of the frame information block.
pub(super) mod info {
    /// TCP or UDP ports.
    pub(in super::super) const SOURCE_PORT: u8 = 0x4;
    pub(in super::super) const DESTINATION_PORT: u8 = 0x6;
    pub(in super::super) const XSP_SOURCE_PORT: u8 = 0x8;
    pub(in super::super) const XSP_DESTINATION_PORT: u8 = 0xa;
    /// Frame offset after the XSP header word.
    pub(in super::super) const XSP_DATA: u8 = 0xc;
    /// XSP data size, or the key exchange size field.
    pub(in super::super) const DATA_SIZE: u8 = 0x10;
    pub(in super::super) const PAYLOAD_OFFSET: u8 = 0x14;
    pub(in super::super) const PAYLOAD_LENGTH: u8 = 0x18;
    /// DHCP transaction or key exchange identifier; the low three bytes of
    /// the XSP header word start one byte later.
    pub(in super::super) const IDENTIFIER: u8 = 0x1c;
    /// [`super::TcpFields`].
    pub(in super::super) const TCP_FIELDS: u8 = 0x27;
    pub(in super::super) const TCP_SEQUENCE: u8 = 0x28;
    pub(in super::super) const TCP_ACKNOWLEDGMENT: u8 = 0x2c;
    pub(in super::super) const TCP_WINDOW: u8 = 0x30;
    /// TCP flags; key exchanges set bit 0.
    pub(in super::super) const TCP_FLAGS: u8 = 0x32;
    pub(in super::super) const XSP_PORT_FORM: u8 = 0x33;
    /// ICMP type, BOOTP operation, or XSP hidden port bytes.
    pub(in super::super) const KIND: u8 = 0x34;
    /// ICMP code, DHCP message type, or XSP shown port bytes.
    pub(in super::super) const CODE: u8 = 0x35;
    /// Key exchange identifier (8 bytes).
    pub(in super::super) const KEY_IDENTIFIER: u8 = 0x36;
    pub(super) const SIZE: usize = 0x40;
}

/// A well-formed Ethernet IPv4 frame.
#[derive(Debug, Clone, Copy)]
pub(super) struct Ipv4Frame {
    /// IP header length in bytes.
    pub(super) header_length: usize,
    /// [`FrameFlags::TCP`], [`FrameFlags::UDP`], or empty.
    pub(super) protocol: FrameFlags,
}

fn word(frame: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([frame[offset], frame[offset + 1]])
}

/// A parsed frame: flags and the frame information block (stock 0x40
/// bytes, big-endian fields).
pub(super) struct Parsed {
    pub(super) flags: FrameFlags,
    pub(super) info: [u8; info::SIZE],
}

impl Parsed {
    fn put(&mut self, offset: u8, bytes: &[u8]) {
        let offset = usize::from(offset);
        self.info[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn put_u16(&mut self, offset: u8, value: u16) {
        self.put(offset, &value.to_be_bytes());
    }

    fn put_u32(&mut self, offset: u8, value: u32) {
        self.put(offset, &value.to_be_bytes());
    }

    fn set(&mut self, offset: u8, value: u8) {
        self.info[usize::from(offset)] = value;
    }

    fn set_bits(&mut self, offset: u8, bits: u8) {
        self.info[usize::from(offset)] |= bits;
    }

    fn u16_at(&self, offset: u8) -> u16 {
        let offset = usize::from(offset);
        u16::from_be_bytes([self.info[offset], self.info[offset + 1]])
    }

    /// The IPv4 view the redirects use: Ethernet and IPv4 parsed, TCP or
    /// UDP when their headers parsed.
    pub(super) fn ipv4(&self, frame: &[u8]) -> Option<Ipv4Frame> {
        if !self.flags.contains(FrameFlags::ETHERNET | FrameFlags::IPV4) {
            return None;
        }
        Some(Ipv4Frame {
            header_length: header_length(frame[ETHERNET_HEADER]),
            protocol: self.flags & FrameFlags::TRANSPORT,
        })
    }
}

/// IPv4 header length in bytes from the version and length byte.
pub(super) fn header_length(version_length: u8) -> usize {
    usize::from(version_length & ipv4::LENGTH_MASK) * 4
}

/// The frame library's reader (0x91f6a058): a position and the bytes it
/// may still read, which a protocol header can shorten.
#[derive(Clone, Copy)]
struct Reader<'a> {
    frame: &'a [u8],
    position: usize,
    remaining: usize,
}

impl<'a> Reader<'a> {
    fn read(&mut self, count: usize) -> Option<&'a [u8]> {
        if count > self.remaining {
            return None;
        }
        let bytes = &self.frame[self.position..self.position + count];
        self.position += count;
        self.remaining -= count;
        Some(bytes)
    }

    /// Bytes at `offset` past the position, without consuming (0x91f6a150).
    fn peek(&self, offset: usize, count: usize) -> Option<&'a [u8]> {
        let mut copy = *self;
        copy.read(offset)?;
        copy.read(count)
    }

    /// `read` of a fixed count, so indexing the bytes needs no checks.
    #[inline(always)]
    fn take<const N: usize>(&mut self) -> Option<&'a [u8; N]> {
        self.read(N)?.try_into().ok()
    }

    #[inline(always)]
    fn peek_array<const N: usize>(&self, offset: usize) -> Option<&'a [u8; N]> {
        self.peek(offset, N)?.try_into().ok()
    }
}

#[inline(always)]
fn be16<const N: usize>(bytes: &[u8; N], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

#[inline(always)]
fn be32<const N: usize>(bytes: &[u8; N], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Parse a frame (0x91f697a0 and the protocol parsers it calls).
pub(super) fn parse(frame: &[u8]) -> Parsed {
    let mut parsed = Parsed {
        flags: FrameFlags::empty(),
        info: [0; info::SIZE],
    };
    classify(frame, &mut parsed);
    parsed
}

/// Kept out of line: inlined, the optimizer spreads the information
/// block over registers and grows every path that writes it.
#[inline(never)]
fn classify(frame: &[u8], parsed: &mut Parsed) {
    let mut reader = Reader {
        frame,
        position: 0,
        remaining: frame.len(),
    };
    let Some(header) = reader.take::<ETHERNET_HEADER>() else {
        return;
    };
    parsed.flags |= FrameFlags::ETHERNET;
    match be16(header, ethernet::TYPE) {
        ether_type::IPV4 => ipv4(parsed, &mut reader, header),
        ether_type::ARP => arp(parsed, &mut reader),
        ether_type::PPPOE_3C12
        | ether_type::PPPOE_3C13
        | ether_type::PPPOE_DISCOVERY
        | ether_type::PPPOE_SESSION => parsed.flags |= FrameFlags::PPPOE,
        ether_type::LLTD => parsed.flags |= FrameFlags::LLTD,
        kind if kind > ethernet::MAXIMUM_LENGTH => payload(parsed, &reader),
        _ => parsed.flags |= FrameFlags::IEEE_802_3,
    }
}

fn payload(parsed: &mut Parsed, reader: &Reader<'_>) {
    parsed.put_u32(info::PAYLOAD_OFFSET, reader.position as u32);
    parsed.put_u32(info::PAYLOAD_LENGTH, reader.remaining as u32);
}

/// 0x91f69660.
fn ipv4(parsed: &mut Parsed, reader: &mut Reader<'_>, ethernet: &[u8; ETHERNET_HEADER]) {
    let Some(header) = reader.take::<IPV4_HEADER>() else {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    };
    let length = header_length(header[ipv4::VERSION_LENGTH]);
    let total = usize::from(be16(header, ipv4::TOTAL_LENGTH));
    let source = be32(header, ipv4::SOURCE);
    if header[ipv4::VERSION_LENGTH] & ipv4::VERSION_MASK != ipv4::VERSION_4
        || length < IPV4_HEADER
        || length > total
        || total - IPV4_HEADER > reader.remaining
    {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    }
    reader.remaining = total - IPV4_HEADER;
    if source == ipv4::BROADCAST || ipv4::is_multicast(source) {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    }
    if length != IPV4_HEADER {
        let _ = reader.read(length - IPV4_HEADER);
    }
    parsed.flags |= FrameFlags::IPV4;
    match header[ipv4::PROTOCOL] {
        ip_protocol::ICMP => icmp(parsed, reader),
        ip_protocol::IGMP => parsed.flags |= FrameFlags::IGMP,
        ip_protocol::TCP => tcp(parsed, reader),
        ip_protocol::UDP => udp(parsed, reader, ethernet, be32(header, ipv4::DESTINATION)),
        ip_protocol::ESP => parsed.flags |= FrameFlags::ESP,
        _ => payload(parsed, reader),
    }
}

/// 0x91f68918: types 0..0x12 with their code limits.
fn icmp(parsed: &mut Parsed, reader: &mut Reader<'_>) {
    let Some(header) = reader.take::<{ icmp::HEADER }>() else {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    };
    let (kind, code) = (header[icmp::TYPE], header[icmp::CODE]);
    let valid = match kind {
        icmp::ECHO_REPLY
        | icmp::SOURCE_QUENCH
        | icmp::ECHO
        | icmp::ROUTER_ADVERTISEMENT
        | icmp::ROUTER_SOLICITATION
        | icmp::TIMESTAMP..=icmp::ADDRESS_MASK_REPLY => true,
        icmp::DESTINATION_UNREACHABLE => code < icmp::DESTINATION_UNREACHABLE_CODES,
        icmp::REDIRECT => code < icmp::REDIRECT_CODES,
        icmp::TIME_EXCEEDED | icmp::PARAMETER_PROBLEM => code < icmp::TIME_EXCEEDED_CODES,
        _ => false,
    };
    if valid {
        parsed.flags |= FrameFlags::ICMP;
        parsed.set(info::KIND, kind);
        parsed.set(info::CODE, code);
    } else {
        parsed.flags |= FrameFlags::MALFORMED;
    }
}

/// 0x91f689e8.
fn tcp(parsed: &mut Parsed, reader: &mut Reader<'_>) {
    let Some(header) = reader.take::<TCP_HEADER>() else {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    };
    let offset = usize::from(header[tcp::DATA_OFFSET] >> 4) * 4;
    if offset < TCP_HEADER || reader.read(offset - TCP_HEADER).is_none() {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    }
    parsed.flags |= FrameFlags::TCP;
    parsed.put(
        info::SOURCE_PORT,
        &header[transport::SOURCE_PORT..tcp::SEQUENCE],
    );
    payload(parsed, reader);
    parsed.set_bits(info::TCP_FIELDS, TcpFields::all().bits());
    parsed.put(
        info::TCP_SEQUENCE,
        &header[tcp::SEQUENCE..tcp::ACKNOWLEDGMENT_END],
    );
    parsed.put(info::TCP_WINDOW, &header[tcp::WINDOW..tcp::CHECKSUM]);
    parsed.set(info::TCP_FLAGS, header[tcp::FLAGS]);
}

/// 0x91f69490.
fn udp(
    parsed: &mut Parsed,
    reader: &mut Reader<'_>,
    ethernet: &[u8; ETHERNET_HEADER],
    destination: u32,
) {
    let Some(header) = reader.take::<UDP_HEADER>() else {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    };
    let length = usize::from(be16(header, udp::LENGTH));
    if length < UDP_HEADER || length - UDP_HEADER > reader.remaining {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    }
    reader.remaining = length - UDP_HEADER;
    parsed.flags |= FrameFlags::UDP;
    parsed.put(
        info::SOURCE_PORT,
        &header[transport::SOURCE_PORT..udp::LENGTH],
    );
    payload(parsed, reader);
    let broadcast = ethernet[..6] == ethernet::BROADCAST;
    if ethernet[0] & ethernet::GROUP != 0 && !broadcast {
        return;
    }
    if ipv4::is_multicast(destination) && destination != ipv4::BROADCAST {
        return;
    }
    let (source_port, destination_port) = (
        be16(header, transport::SOURCE_PORT),
        be16(header, transport::DESTINATION_PORT),
    );
    let either = |port: u16| source_port == port || destination_port == port;
    if either(port::DNS) {
        parsed.flags |= FrameFlags::DNS;
    } else if (source_port, destination_port) == (port::BOOTP_SERVER, port::BOOTP_CLIENT)
        || (source_port, destination_port) == (port::BOOTP_CLIENT, port::BOOTP_SERVER)
    {
        dhcp(parsed, reader);
    } else if either(port::NETBIOS_NAME)
        || either(port::NETBIOS_DATAGRAM)
        || either(port::NETBIOS_SESSION)
    {
        parsed.flags |= FrameFlags::NETBIOS;
    } else if source_port == port::IKE && destination_port == port::IKE {
        parsed.flags |= FrameFlags::IKE;
    } else if either(port::KERBEROS) {
        parsed.flags |= FrameFlags::KERBEROS;
    } else if source_port > port::XSP_MINIMUM && destination_port > port::XSP_MINIMUM {
        xsp(parsed, reader);
    }
}

/// Search DHCP options for a one-byte option (0x91f686f0); the overload
/// option records its bits when `overload` is given.
fn dhcp_option(mut reader: Reader<'_>, code: u8, mut overload: Option<&mut u8>) -> Option<u8> {
    loop {
        let option = reader.read(1)?[0];
        if option == dhcp::OPTION_END {
            return None;
        }
        if option == dhcp::OPTION_PAD {
            continue;
        }
        let length = reader.read(1)?[0];
        if length == 0 {
            return None;
        }
        if option == dhcp::OPTION_OVERLOAD
            && length == 1
            && overload.as_deref().is_some_and(|value| *value == 0)
        {
            let value = reader.read(1)?[0];
            if let Some(slot) = overload.as_deref_mut() {
                *slot = value;
            }
            continue;
        }
        if option == code {
            return if length == 1 {
                Some(reader.read(1)?[0])
            } else {
                None
            };
        }
        reader.read(usize::from(length))?;
    }
}

/// 0x91f68e70: the DHCP message type, searched in the options, then the
/// file and server name fields when the overload option claims them.
fn dhcp(parsed: &mut Parsed, reader: &mut Reader<'_>) {
    let start = reader.position;
    let Some(bootp) = reader.take::<{ dhcp::HEADER }>() else {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    };
    if bootp[dhcp::HARDWARE_TYPE] != dhcp::HARDWARE_ETHERNET {
        return;
    }
    if bootp[dhcp::HARDWARE_LENGTH] != dhcp::ETHERNET_ADDRESS_LENGTH
        || be32(bootp, dhcp::COOKIE) != dhcp::MAGIC_COOKIE
    {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    }
    let mut overload = 0u8;
    let area = |offset: usize, length: usize| Reader {
        frame: reader.frame,
        position: start + offset,
        remaining: length,
    };
    let found = dhcp_option(*reader, dhcp::OPTION_MESSAGE_TYPE, Some(&mut overload))
        .or_else(|| {
            if overload & dhcp::OVERLOAD_FILE != 0 {
                dhcp_option(
                    area(dhcp::FILE, dhcp::FILE_LENGTH),
                    dhcp::OPTION_MESSAGE_TYPE,
                    None,
                )
            } else {
                None
            }
        })
        .or_else(|| {
            if overload & dhcp::OVERLOAD_SERVER_NAME != 0 {
                dhcp_option(
                    area(dhcp::SERVER_NAME, dhcp::SERVER_NAME_LENGTH),
                    dhcp::OPTION_MESSAGE_TYPE,
                    None,
                )
            } else {
                None
            }
        });
    match found {
        Some(kind) => {
            parsed.flags |= FrameFlags::DHCP;
            parsed.put(
                info::IDENTIFIER,
                &bootp[dhcp::TRANSACTION..dhcp::TRANSACTION + 4],
            );
            parsed.set(info::KIND, bootp[dhcp::OPERATION]);
            parsed.set(info::CODE, kind);
        }
        None => parsed.flags |= FrameFlags::MALFORMED,
    }
}

/// Key exchange packets of the secure protocol (0x91f68ac0). The packet
/// sizes and body offsets are the stock table.
fn key_exchange(parsed: &mut Parsed, reader: &mut Reader<'_>) -> Option<()> {
    use key_exchange_kind as kinds;

    let header = reader.peek_array::<4>(0)?;
    let kind = be16(header, 0);
    let size = be16(header, 2);
    let swapped = usize::from(size.swap_bytes());
    let remaining = reader.remaining;
    let mut size_field = 0u32;
    let subtype = match kind {
        kinds::KEY_EX_SG_TO_XB_RESP if size == 0x4000 => {
            let body = reader.take::<0x40>()?;
            parsed.put(info::IDENTIFIER, &body[8..16]);
            XspSubtype::KEY_EX_SG_TO_XB_RESP
        }
        kinds::KEY_EX_XB_TO_SG_INIT if remaining == 0x534 && size == 0x1800 => {
            let body = reader.take::<0x18>()?;
            parsed.put(info::IDENTIFIER, &body[8..12]);
            XspSubtype::KEY_EX_XB_TO_SG_INIT
        }
        kinds::KEY_EX_NAT_OPEN_INIT | kinds::KEY_EX_NAT_OPEN_RESP if size == 0x2e00 => {
            let body = reader.take::<0x2e>()?;
            if reader.remaining != 0 {
                return None;
            }
            parsed.put(info::KEY_IDENTIFIER, &body[8..16]);
            if be16(body, 6) & 0x200 != 0 {
                parsed.set_bits(info::TCP_FLAGS, 1);
            }
            if kind == kinds::KEY_EX_NAT_OPEN_INIT {
                XspSubtype::KEY_EX_NAT_OPEN_INIT
            } else {
                XspSubtype::KEY_EX_NAT_OPEN_RESP
            }
        }
        kinds::KEY_EX_QOS_INIT | kinds::KEY_EX_QOS_INIT2
            if size
                == if kind == kinds::KEY_EX_QOS_INIT {
                    0x4e00
                } else {
                    0x5600
                }
                && swapped == remaining =>
        {
            let body = reader.take::<0x1a>()?;
            parsed.put(info::KEY_IDENTIFIER, &body[0x12..0x1a]);
            if kind == kinds::KEY_EX_QOS_INIT {
                XspSubtype::KEY_EX_QOS_INIT
            } else {
                XspSubtype::KEY_EX_QOS_INIT2
            }
        }
        kinds::KEY_EX_QOS_RESP if size >= 0x2700 && swapped == remaining => {
            size_field = (remaining - 0x27) as u32;
            XspSubtype::KEY_EX_QOS_RESP
        }
        kinds::KEY_EX_NAT_OPEN2 | kinds::KEY_EX_NAT_OPEN3
            if size
                == if kind == kinds::KEY_EX_NAT_OPEN2 {
                    0x7600
                } else {
                    0x8600
                }
                && swapped == remaining =>
        {
            let body = reader.take::<0x22>()?;
            parsed.put(info::KEY_IDENTIFIER, &body[8..16]);
            if be16(body, 6) & 0x100 != 0 {
                parsed.set_bits(info::TCP_FLAGS, 1);
            } else {
                parsed.put(info::IDENTIFIER, &body[0x10..0x14]);
            }
            if kind == kinds::KEY_EX_NAT_OPEN2 {
                XspSubtype::KEY_EX_NAT_OPEN2
            } else {
                XspSubtype::KEY_EX_NAT_OPEN3
            }
        }
        kinds::KEY_EX_XB_TO_XB_INIT
        | kinds::KEY_EX_XB_TO_XB_RESP
        | kinds::KEY_EX_XB_TO_XB_INIT2
        | kinds::KEY_EX_XB_TO_XB_RESP2
        | kinds::KEY_EX_XB_TO_XB3_INIT
        | kinds::KEY_EX_XB_TO_XB_RESP3 => {
            let (expected, subtype) = match kind {
                kinds::KEY_EX_XB_TO_XB_INIT => (0x8000, XspSubtype::KEY_EX_XB_TO_XB_INIT),
                kinds::KEY_EX_XB_TO_XB_RESP => (0x8000, XspSubtype::KEY_EX_XB_TO_XB_RESP),
                kinds::KEY_EX_XB_TO_XB_INIT2 => (0x8200, XspSubtype::KEY_EX_XB_TO_XB_INIT2),
                kinds::KEY_EX_XB_TO_XB_RESP2 => (0x8000, XspSubtype::KEY_EX_XB_TO_XB_RESP2),
                kinds::KEY_EX_XB_TO_XB3_INIT => (0x9000, XspSubtype::KEY_EX_XB_TO_XB3_INIT),
                _ => (0x9000, XspSubtype::KEY_EX_XB_TO_XB_RESP3),
            };
            if size != expected {
                return None;
            }
            let body = reader.take::<0x80>()?;
            reader.read(swapped.checked_sub(0x80)?)?;
            parsed.put(info::KEY_IDENTIFIER, &body[8..16]);
            parsed.put(info::IDENTIFIER, &body[0x10..0x18]);
            subtype
        }
        _ => return None,
    };
    parsed.put_u32(info::DATA_SIZE, size_field);
    parsed.put_u32(info::PAYLOAD_LENGTH, 0);
    parsed.flags = parsed.flags.with_xsp(subtype);
    Some(())
}

/// Datagrams of the secure protocol between consoles (0x91f69068).
fn xsp(parsed: &mut Parsed, reader: &mut Reader<'_>) {
    /// Port of the secure protocol; a datagram that fails to parse is
    /// malformed only when it uses this port.
    const PORT: u16 = 0xc02;
    if xsp_header(parsed, reader).is_none()
        && (parsed.u16_at(info::SOURCE_PORT) == PORT
            || parsed.u16_at(info::DESTINATION_PORT) == PORT)
    {
        parsed.flags |= FrameFlags::MALFORMED;
    }
}

/// The XSP header word and trailer (0x91f69068).
fn xsp_header(parsed: &mut Parsed, reader: &mut Reader<'_>) -> Option<()> {
    let first = be32(reader.take::<4>()?, 0);
    if first == 0 {
        return key_exchange(parsed, reader);
    }
    let remaining = reader.remaining;
    let trailer_end = remaining.checked_sub(XSP_TRAILER)?;
    let byte = (first >> 24) as usize;
    let mut kind = byte & 0xf;
    let hidden = ((byte & 0x10) | (byte >> 4)) >> 1;
    // Kind 0 is a secure message; every other kind reduces to a base kind
    // that sets its subtype below.
    let mut subtype = XspSubtype::SECURE_MESSAGE;
    let mut port_form = 0usize;
    let mut ports = 0usize;
    let mut shown = 0usize;
    let mut data_size;
    let mut tail = 0usize;
    if kind == xsp_kind::SECURE_MESSAGE {
        data_size = trailer_end;
    } else {
        port_form = (kind - 1) % 3;
        kind -= port_form;
        ports = port_form * 2;
        if kind == xsp_kind::TCP_INFO {
            subtype = XspSubtype::TCP_INFO;
            ports += 0xc;
        }
        shown = hidden.min(ports);
        let missing = ports - shown;
        if remaining < missing + hidden + XSP_TRAILER {
            return None;
        }
        data_size = remaining - XSP_TRAILER - missing;
        match kind {
            xsp_kind::UNNAMED_4 => subtype = XspSubtype::OF_UNNAMED_KIND_4,
            xsp_kind::VOICE_PAYLOAD => {
                subtype = XspSubtype::VOICE_PAYLOAD;
                let pad = usize::from(reader.peek(trailer_end.checked_sub(1)?, 1)?[0]) << 3;
                if remaining < missing + pad + XSP_TRAILER + 1 {
                    return None;
                }
                tail = remaining - XSP_TRAILER - missing - pad;
                data_size = pad;
            }
            xsp_kind::VOICE_ONLY_PAYLOAD => {
                subtype = XspSubtype::VOICE_ONLY_PAYLOAD;
                tail = data_size;
                data_size = 0;
            }
            xsp_kind::UNNAMED_D => subtype = XspSubtype::OF_UNNAMED_KIND_D,
            _ => {}
        }
    }
    let declared = tail
        .wrapping_sub(shown)
        .wrapping_add(ports)
        .wrapping_add(data_size)
        .wrapping_add(XSP_TRAILER);
    if data_size & 7 != 0 || data_size < hidden || remaining != declared {
        return None;
    }
    if kind != xsp_kind::SECURE_MESSAGE {
        if port_form == 0 {
            parsed.put_u16(info::XSP_SOURCE_PORT, port::XSP_BASE);
            parsed.put_u16(info::XSP_DESTINATION_PORT, port::XSP_BASE);
        } else {
            let base = data_size - shown;
            if port_form == 1 {
                if shown == 0 {
                    parsed.put_u16(
                        info::XSP_SOURCE_PORT,
                        u16::from(reader.peek(base, 1)?[0]) + port::XSP_BASE,
                    );
                }
                if shown <= 1 {
                    parsed.put_u16(
                        info::XSP_DESTINATION_PORT,
                        u16::from(reader.peek(base + 1, 1)?[0]) + port::XSP_BASE,
                    );
                }
            } else {
                if shown == 0 {
                    parsed.put(info::XSP_SOURCE_PORT, reader.peek_array::<2>(base)?);
                }
                if shown <= 2 {
                    parsed.put(
                        info::XSP_DESTINATION_PORT,
                        reader.peek_array::<2>(base + 2)?,
                    );
                }
            }
        }
    }
    if subtype == XspSubtype::TCP_INFO {
        let segment = reader.peek_array::<0xc>(trailer_end.checked_sub(0xc)?)?;
        let offset = usize::from(segment[8] & 0xf0) >> 2;
        if offset < TCP_HEADER || offset > data_size - hidden + TCP_HEADER {
            return None;
        }
        let doubled = port_form * 2;
        if shown <= doubled {
            parsed.set_bits(info::TCP_FIELDS, TcpFields::SEQUENCE.bits());
            parsed.put(info::TCP_SEQUENCE, &segment[0..4]);
        }
        if shown <= (port_form + 2) * 2 {
            parsed.set_bits(info::TCP_FIELDS, TcpFields::ACKNOWLEDGMENT.bits());
            parsed.put(info::TCP_ACKNOWLEDGMENT, &segment[4..8]);
        }
        if shown <= doubled + 9 {
            parsed.set(info::TCP_FLAGS, segment[9]);
        }
        if shown <= (port_form + 5) * 2 {
            parsed.set_bits(info::TCP_FIELDS, TcpFields::WINDOW.bits());
            parsed.put(info::TCP_WINDOW, &segment[10..12]);
        }
    }
    parsed.flags = parsed.flags.with_xsp(subtype);
    parsed.put_u32(info::DATA_SIZE, (data_size - hidden) as u32);
    parsed.put_u32(info::XSP_DATA, reader.position as u32);
    if matches!(
        subtype,
        XspSubtype::VOICE_PAYLOAD | XspSubtype::VOICE_ONLY_PAYLOAD | XspSubtype::OF_UNNAMED_KIND_D
    ) {
        let payload = reader
            .position
            .wrapping_sub(shown)
            .wrapping_add(ports)
            .wrapping_add(data_size);
        parsed.put_u32(info::PAYLOAD_OFFSET, payload as u32);
        parsed.put_u32(
            info::PAYLOAD_LENGTH,
            tail.wrapping_sub(usize::from(kind == xsp_kind::VOICE_PAYLOAD)) as u32,
        );
    } else {
        parsed.put_u32(info::PAYLOAD_OFFSET, 0);
        parsed.put_u32(info::PAYLOAD_LENGTH, 0);
    }
    parsed.set(info::XSP_PORT_FORM, port_form as u8);
    parsed.set(info::KIND, hidden as u8);
    parsed.set(info::CODE, shown as u8);
    parsed.put(info::IDENTIFIER + 1, &first.to_be_bytes()[1..4]);
    Some(())
}

/// 0x91f68f48.
fn arp(parsed: &mut Parsed, reader: &mut Reader<'_>) {
    let Some(header) = reader.take::<{ arp::HEADER }>() else {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    };
    let hardware = be16(header, arp::HARDWARE_TYPE);
    if !matches!(hardware, arp::HARDWARE_ETHERNET | arp::HARDWARE_IEEE_802)
        || be16(header, arp::PROTOCOL_TYPE) != ether_type::IPV4
    {
        return;
    }
    if header[arp::HARDWARE_LENGTH] != arp::ETHERNET_ADDRESS_LENGTH
        || header[arp::PROTOCOL_LENGTH] != arp::IPV4_ADDRESS_LENGTH
    {
        parsed.flags |= FrameFlags::MALFORMED;
        return;
    }
    if !matches!(be16(header, arp::OPERATION), arp::REQUEST | arp::REPLY) {
        return;
    }
    let bad = |address: u32| {
        address == ipv4::BROADCAST || ipv4::is_multicast(address) || ipv4::is_loopback(address)
    };
    match reader.take::<{ arp::BODY }>() {
        Some(body)
            if body[arp::SENDER_HARDWARE - arp::HEADER] & ethernet::GROUP == 0
                && !bad(be32(body, arp::SENDER_PROTOCOL - arp::HEADER))
                && !bad(be32(body, arp::TARGET_PROTOCOL - arp::HEADER)) =>
        {
            parsed.flags |= FrameFlags::ARP;
        }
        _ => parsed.flags |= FrameFlags::MALFORMED,
    }
}

/// The port the redirects compare: destination when sending, source when
/// receiving.
pub(super) fn port(frame: &[u8], info: Ipv4Frame, transmit: bool) -> u16 {
    let transport = ETHERNET_HEADER + info.header_length;
    if transmit {
        word(frame, transport + transport::DESTINATION_PORT)
    } else {
        word(frame, transport + transport::SOURCE_PORT)
    }
}

/// Frame offset of the address the redirects compare: destination when
/// sending, source when receiving.
fn address_offset(transmit: bool) -> usize {
    ETHERNET_HEADER
        + if transmit {
            ipv4::DESTINATION
        } else {
            ipv4::SOURCE
        }
}

/// The address the redirects compare.
pub(super) fn address(frame: &[u8], transmit: bool) -> [u8; 4] {
    let offset = address_offset(transmit);
    [
        frame[offset],
        frame[offset + 1],
        frame[offset + 2],
        frame[offset + 3],
    ]
}

/// Ones' complement sum of big-endian words (0x91f68360).
fn sum(mut total: u32, bytes: &[u8]) -> u32 {
    let (pairs, rest) = bytes.as_chunks::<2>();
    for &pair in pairs {
        total += u32::from(u16::from_be_bytes(pair));
    }
    if let [last] = rest {
        total += u32::from(*last) << 8;
    }
    total
}

fn fold(mut total: u32) -> u16 {
    while total > 0xffff {
        total = (total & 0xffff) + (total >> 16);
    }
    total as u16
}

/// Recompute the IPv4 header checksum (0x91f67ef8).
fn ip_checksum(frame: &mut [u8]) {
    let ip = &mut frame[ETHERNET_HEADER..];
    let length = header_length(ip[ipv4::VERSION_LENGTH]);
    ip[ipv4::CHECKSUM] = 0;
    ip[ipv4::CHECKSUM + 1] = 0;
    let checksum = !fold(sum(0, &ip[..length]));
    ip[ipv4::CHECKSUM..ipv4::CHECKSUM + 2].copy_from_slice(&checksum.to_be_bytes());
}

/// Recompute a TCP or UDP checksum over a pseudo header and `length`
/// transport bytes (0x91f681a8, 0x91f68098). Stock sums a copy in its
/// 0x5ea-byte gather buffer (0x91fa30a8); the parser bounds `length` by the
/// frame, so summing the frame gives the same result. A segment that copy
/// cannot hold clears the frame headers instead, as stock does.
fn transport_checksum(
    frame: &mut [u8],
    protocol: u8,
    length: usize,
    checksum_offset: usize,
    cleared: usize,
) {
    ip_checksum(frame);
    let transport = ETHERNET_HEADER + IPV4_HEADER;
    frame[transport + checksum_offset] = 0;
    frame[transport + checksum_offset + 1] = 0;
    if length > GATHER_CAPACITY {
        frame[..cleared].fill(0);
        return;
    }
    // Source and destination addresses, zero, protocol, length.
    let mut pseudo = [0u8; 12];
    pseudo[..8].copy_from_slice(
        &frame[ETHERNET_HEADER + ipv4::SOURCE..ETHERNET_HEADER + ipv4::DESTINATION + 4],
    );
    pseudo[9] = protocol;
    pseudo[10..12].copy_from_slice(&(length as u16).to_be_bytes());
    let checksum = !fold(sum(sum(0, &pseudo), &frame[transport..transport + length]));
    // Zero means no checksum in UDP; both transports send all ones.
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    frame[transport + checksum_offset..transport + checksum_offset + 2]
        .copy_from_slice(&checksum.to_be_bytes());
}

/// Rewrite the compared address and port of a frame (0x91f8d008) and
/// recompute its checksums. Transport ports and checksums change only when
/// the IP header has no options; with options the transport checksums and
/// the IP checksum stay as they were.
pub(super) fn rewrite(
    frame: &mut [u8],
    info: Ipv4Frame,
    transmit: bool,
    address: [u8; 4],
    port: u16,
) {
    let offset = address_offset(transmit);
    frame[offset..offset + 4].copy_from_slice(&address);
    let transport = ETHERNET_HEADER + IPV4_HEADER;
    let port_offset = transport
        + if transmit {
            transport::DESTINATION_PORT
        } else {
            transport::SOURCE_PORT
        };
    match info.protocol {
        FrameFlags::TCP => {
            if info.header_length != IPV4_HEADER {
                return;
            }
            frame[port_offset..port_offset + 2].copy_from_slice(&port.to_be_bytes());
            let length = frame.len().saturating_sub(transport);
            transport_checksum(
                frame,
                ip_protocol::TCP,
                length,
                tcp::CHECKSUM,
                transport + TCP_HEADER,
            );
        }
        FrameFlags::UDP => {
            if info.header_length != IPV4_HEADER {
                return;
            }
            frame[port_offset..port_offset + 2].copy_from_slice(&port.to_be_bytes());
            let length = usize::from(word(frame, transport + udp::LENGTH));
            transport_checksum(
                frame,
                ip_protocol::UDP,
                length,
                udp::CHECKSUM,
                transport + UDP_HEADER,
            );
        }
        _ => ip_checksum(frame),
    }
}
