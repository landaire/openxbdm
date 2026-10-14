//! Frame parsing (frame library 0x91f68320, the classification the
//! simulator's redirects and classifiers read) and address rewriting for
//! IPv4 redirects (0x91f8d008).

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

pub(super) const ETHERNET_HEADER: usize = 14;
const IPV4_HEADER: usize = 20;
const ETHERTYPE_IPV4: u16 = 0x0800;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;
/// Largest transport segment the checksum gather buffer holds
/// (0x91f67e90).
const GATHER_CAPACITY: usize = 0x5ea;

/// Transport protocol bits of the frame classification, kept in redirect
/// sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Protocol(pub(super) u32);

impl Protocol {
    pub(super) const TCP: Self = Self(0x80);
    pub(super) const UDP: Self = Self(0x100);

    pub(super) fn is_transport(self) -> bool {
        self.0 != 0
    }
}

/// A well-formed Ethernet IPv4 frame.
#[derive(Debug, Clone, Copy)]
pub(super) struct Ipv4Frame {
    /// IP header length in bytes.
    pub(super) header_length: usize,
    pub(super) protocol: Protocol,
}

fn word(frame: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([frame[offset], frame[offset + 1]])
}

/// Parse flags (stock frame information +0x00).
pub(super) mod flags {
    pub(in super::super) const ETHERNET: u32 = 0x1;
    pub(in super::super) const IPV4: u32 = 0x2;
    pub(in super::super) const ARP: u32 = 0x4;
    pub(in super::super) const PPPOE: u32 = 0x8;
    pub(in super::super) const LLTD: u32 = 0x10;
    pub(in super::super) const ICMP: u32 = 0x20;
    pub(in super::super) const IGMP: u32 = 0x40;
    pub(in super::super) const TCP: u32 = 0x80;
    pub(in super::super) const UDP: u32 = 0x100;
    pub(in super::super) const DNS: u32 = 0x200;
    pub(in super::super) const DHCP: u32 = 0x400;
    pub(in super::super) const IPV6_IN_IPV4: u32 = 0x800;
    pub(in super::super) const NETBIOS: u32 = 0x1000;
    pub(in super::super) const IEEE_802_3: u32 = 0x2000;
    pub(in super::super) const IKE: u32 = 0x4000;
    pub(in super::super) const KERBEROS: u32 = 0x20_0000;
    pub(in super::super) const MALFORMED: u32 = 0x8000_0000;
}

/// A parsed frame: flags and the frame information block (stock 0x40
/// bytes, big-endian fields).
pub(super) struct Parsed {
    pub(super) flags: u32,
    pub(super) info: [u8; 0x40],
}

impl Parsed {
    fn put(&mut self, offset: usize, bytes: &[u8]) {
        self.info[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn put_u16(&mut self, offset: usize, value: u16) {
        self.put(offset, &value.to_be_bytes());
    }

    fn put_u32(&mut self, offset: usize, value: u32) {
        self.put(offset, &value.to_be_bytes());
    }

    fn u16_at(&self, offset: usize) -> u16 {
        u16::from_be_bytes([self.info[offset], self.info[offset + 1]])
    }

    /// The IPv4 view the redirects use: Ethernet and IPv4 parsed, TCP or
    /// UDP when their headers parsed.
    pub(super) fn ipv4(&self, frame: &[u8]) -> Option<Ipv4Frame> {
        if self.flags & (flags::ETHERNET | flags::IPV4) != flags::ETHERNET | flags::IPV4 {
            return None;
        }
        let protocol = Protocol(self.flags & (flags::TCP | flags::UDP));
        Some(Ipv4Frame {
            header_length: usize::from(frame[ETHERNET_HEADER] & 0xf) * 4,
            protocol,
        })
    }
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
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Parse a frame (0x91f697a0 and the protocol parsers it calls).
pub(super) fn parse(frame: &[u8]) -> Parsed {
    let mut parsed = Parsed {
        flags: 0,
        info: [0; 0x40],
    };
    let mut reader = Reader {
        frame,
        position: 0,
        remaining: frame.len(),
    };
    let Some(ethernet) = reader.read(ETHERNET_HEADER) else {
        return parsed;
    };
    parsed.flags |= flags::ETHERNET;
    match word(ethernet, 12) {
        ETHERTYPE_IPV4 => ipv4(&mut parsed, &mut reader, ethernet),
        0x0806 => arp(&mut parsed, &mut reader),
        0x3c12 | 0x3c13 | 0x8863 | 0x8864 => parsed.flags |= flags::PPPOE,
        0x88d9 => parsed.flags |= flags::LLTD,
        kind if kind > 0x5dc => payload(&mut parsed, &reader),
        _ => parsed.flags |= flags::IEEE_802_3,
    }
    parsed
}

fn payload(parsed: &mut Parsed, reader: &Reader<'_>) {
    parsed.put_u32(0x14, reader.position as u32);
    parsed.put_u32(0x18, reader.remaining as u32);
}

/// 0x91f69660.
fn ipv4(parsed: &mut Parsed, reader: &mut Reader<'_>, ethernet: &[u8]) {
    let Some(header) = reader.read(IPV4_HEADER) else {
        parsed.flags |= flags::MALFORMED;
        return;
    };
    let length = usize::from(header[0] & 0xf) * 4;
    let total = usize::from(word(header, 2));
    let source = be32(&header[12..16]);
    if header[0] & 0xf0 != 0x40
        || length < IPV4_HEADER
        || length > total
        || total - IPV4_HEADER > reader.remaining
    {
        parsed.flags |= flags::MALFORMED;
        return;
    }
    reader.remaining = total - IPV4_HEADER;
    if source == u32::MAX || source & 0xf000_0000 == 0xe000_0000 {
        parsed.flags |= flags::MALFORMED;
        return;
    }
    if length != IPV4_HEADER {
        let _ = reader.read(length - IPV4_HEADER);
    }
    parsed.flags |= flags::IPV4;
    match header[9] {
        1 => icmp(parsed, reader),
        2 => parsed.flags |= flags::IGMP,
        PROTOCOL_TCP => tcp(parsed, reader),
        PROTOCOL_UDP => udp(parsed, reader, ethernet, be32(&header[16..20])),
        0x32 => parsed.flags |= flags::IPV6_IN_IPV4,
        _ => payload(parsed, reader),
    }
}

/// 0x91f68918: types 0..0x12 with their code limits.
fn icmp(parsed: &mut Parsed, reader: &mut Reader<'_>) {
    let Some(header) = reader.read(8) else {
        parsed.flags |= flags::MALFORMED;
        return;
    };
    let (kind, code) = (header[0], header[1]);
    let valid = match kind {
        0 | 4 | 8 | 9 | 10 | 13..=18 => true,
        3 => code < 0xe,
        5 => code < 4,
        11 | 12 => code < 2,
        _ => false,
    };
    if valid {
        parsed.flags |= flags::ICMP;
        parsed.info[0x34] = kind;
        parsed.info[0x35] = code;
    } else {
        parsed.flags |= flags::MALFORMED;
    }
}

/// 0x91f689e8.
fn tcp(parsed: &mut Parsed, reader: &mut Reader<'_>) {
    let Some(header) = reader.read(20) else {
        parsed.flags |= flags::MALFORMED;
        return;
    };
    let offset = usize::from(header[12] >> 4) * 4;
    if offset < 20 || reader.read(offset - 20).is_none() {
        parsed.flags |= flags::MALFORMED;
        return;
    }
    parsed.flags |= flags::TCP;
    parsed.put(0x4, &header[0..4]);
    payload(parsed, reader);
    parsed.info[0x27] |= 7;
    parsed.put(0x28, &header[4..12]);
    parsed.put(0x30, &header[14..16]);
    parsed.info[0x32] = header[13];
}

/// 0x91f69490.
fn udp(parsed: &mut Parsed, reader: &mut Reader<'_>, ethernet: &[u8], destination: u32) {
    let Some(header) = reader.read(8) else {
        parsed.flags |= flags::MALFORMED;
        return;
    };
    let length = usize::from(word(header, 4));
    if length < 8 || length - 8 > reader.remaining {
        parsed.flags |= flags::MALFORMED;
        return;
    }
    reader.remaining = length - 8;
    parsed.flags |= flags::UDP;
    parsed.put(0x4, &header[0..4]);
    payload(parsed, reader);
    let broadcast = ethernet[..6] == [0xff; 6];
    if ethernet[0] & 1 != 0 && !broadcast {
        return;
    }
    if destination & 0xf000_0000 == 0xe000_0000 && destination != u32::MAX {
        return;
    }
    let (source_port, destination_port) = (word(header, 0), word(header, 2));
    let either = |port: u16| source_port == port || destination_port == port;
    if either(53) {
        parsed.flags |= flags::DNS;
    } else if (source_port, destination_port) == (67, 68)
        || (source_port, destination_port) == (68, 67)
    {
        dhcp(parsed, reader);
    } else if either(137) || either(138) || either(139) {
        parsed.flags |= flags::NETBIOS;
    } else if source_port == 500 && destination_port == 500 {
        parsed.flags |= flags::IKE;
    } else if either(88) {
        parsed.flags |= flags::KERBEROS;
    } else if source_port > 0x400 && destination_port > 0x400 {
        xsp(parsed, reader);
    }
}

/// Search DHCP options for a one-byte option (0x91f686f0); option 52
/// records the overload bits when `overload` is given.
fn dhcp_option(mut reader: Reader<'_>, code: u8, mut overload: Option<&mut u8>) -> Option<u8> {
    loop {
        let option = reader.read(1)?[0];
        if option == 0xff {
            return None;
        }
        if option == 0 {
            continue;
        }
        let length = reader.read(1)?[0];
        if length == 0 {
            return None;
        }
        if option == 52 && length == 1 && overload.as_deref().is_some_and(|value| *value == 0) {
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

/// 0x91f68e70: the DHCP message type (option 53), searched in the options,
/// then the file and server name fields when option 52 overloads them.
fn dhcp(parsed: &mut Parsed, reader: &mut Reader<'_>) {
    let start = reader.position;
    let Some(bootp) = reader.read(0xf0) else {
        parsed.flags |= flags::MALFORMED;
        return;
    };
    if bootp[1] != 1 {
        return;
    }
    if bootp[2] != 6 || be32(&bootp[0xec..0xf0]) != 0x6382_5363 {
        parsed.flags |= flags::MALFORMED;
        return;
    }
    let mut overload = 0u8;
    let area = |offset: usize, length: usize| Reader {
        frame: reader.frame,
        position: start + offset,
        remaining: length,
    };
    let found = dhcp_option(*reader, 53, Some(&mut overload))
        .or_else(|| {
            if overload & 1 != 0 {
                dhcp_option(area(0x6c, 0x80), 53, None)
            } else {
                None
            }
        })
        .or_else(|| {
            if overload & 2 != 0 {
                dhcp_option(area(0x2c, 0x40), 53, None)
            } else {
                None
            }
        });
    match found {
        Some(kind) => {
            parsed.flags |= flags::DHCP;
            parsed.put(0x1c, &bootp[4..8]);
            parsed.info[0x34] = bootp[0];
            parsed.info[0x35] = kind;
        }
        None => parsed.flags |= flags::MALFORMED,
    }
}

/// Key exchange packets of the secure protocol (0x91f68ac0).
fn key_exchange(parsed: &mut Parsed, reader: &mut Reader<'_>) -> Option<()> {
    let header = reader.peek(0, 4)?;
    let kind = word(header, 0);
    let size = word(header, 2);
    let swapped = usize::from(size.swap_bytes());
    let remaining = reader.remaining;
    let mut size_field = 0u32;
    let subtype = match kind {
        0x358 if size == 0x4000 => {
            let body = reader.read(0x40)?;
            parsed.put(0x1c, &body[8..16]);
            0xa_0000
        }
        0x258 if remaining == 0x534 && size == 0x1800 => {
            let body = reader.read(0x18)?;
            parsed.put(0x1c, &body[8..12]);
            0x9_0000
        }
        0x458 | 0x558 if size == 0x2e00 => {
            let body = reader.read(0x2e)?;
            if reader.remaining != 0 {
                return None;
            }
            parsed.put(0x36, &body[8..16]);
            if word(body, 6) & 0x200 != 0 {
                parsed.info[0x32] |= 1;
            }
            if kind == 0x458 { 0xb_0000 } else { 0xc_0000 }
        }
        0x658 | 0x1158
            if size == if kind == 0x658 { 0x4e00 } else { 0x5600 } && swapped == remaining =>
        {
            let body = reader.read(0x1a)?;
            parsed.put(0x36, &body[0x12..0x1a]);
            if kind == 0x658 { 0xd_0000 } else { 0x18_0000 }
        }
        0x758 if size >= 0x2700 && swapped == remaining => {
            size_field = (remaining - 0x27) as u32;
            0xe_0000
        }
        0xc58 | 0x1058
            if size == if kind == 0xc58 { 0x7600 } else { 0x8600 } && swapped == remaining =>
        {
            let body = reader.read(0x22)?;
            parsed.put(0x36, &body[8..16]);
            if word(body, 6) & 0x100 != 0 {
                parsed.info[0x32] |= 1;
            } else {
                parsed.put(0x1c, &body[0x10..0x14]);
            }
            if kind == 0xc58 { 0x13_0000 } else { 0x17_0000 }
        }
        0x58 | 0x158 | 0xa58 | 0xb58 | 0xe58 | 0xf58 => {
            let (expected, subtype) = match kind {
                0x58 => (0x8000, 0x7_0000),
                0x158 => (0x8000, 0x8_0000),
                0xa58 => (0x8200, 0x11_0000),
                0xb58 => (0x8000, 0x12_0000),
                0xe58 => (0x9000, 0x15_0000),
                _ => (0x9000, 0x16_0000),
            };
            if size != expected {
                return None;
            }
            let body = reader.read(0x80)?;
            reader.read(swapped.checked_sub(0x80)?)?;
            parsed.put(0x36, &body[8..16]);
            parsed.put(0x1c, &body[0x10..0x18]);
            subtype
        }
        _ => return None,
    };
    parsed.put_u32(0x10, size_field);
    parsed.put_u32(0x18, 0);
    parsed.flags |= subtype;
    Some(())
}

/// Datagrams of the secure protocol between consoles (0x91f69068).
fn xsp(parsed: &mut Parsed, reader: &mut Reader<'_>) {
    if xsp_header(parsed, reader).is_none()
        && (parsed.u16_at(0x4) == 0xc02 || parsed.u16_at(0x6) == 0xc02)
    {
        parsed.flags |= flags::MALFORMED;
    }
}

fn xsp_header(parsed: &mut Parsed, reader: &mut Reader<'_>) -> Option<()> {
    let first = be32(reader.read(4)?);
    if first == 0 {
        return key_exchange(parsed, reader);
    }
    let remaining = reader.remaining;
    let trailer_end = remaining.checked_sub(0xc)?;
    let byte = (first >> 24) as usize;
    let mut kind = byte & 0xf;
    let hidden = ((byte & 0x10) | (byte >> 4)) >> 1;
    let mut subtype = 0u32;
    let mut port_form = 0usize;
    let mut ports = 0usize;
    let mut shown = 0usize;
    let mut data_size;
    let mut tail = 0usize;
    if kind == 0 {
        subtype = 0x1_0000;
        data_size = trailer_end;
    } else {
        port_form = (kind - 1) % 3;
        kind -= port_form;
        ports = port_form * 2;
        if kind == 1 {
            subtype = 0x2_0000;
            ports += 0xc;
        }
        shown = hidden.min(ports);
        let missing = ports - shown;
        if remaining < missing + hidden + 0xc {
            return None;
        }
        data_size = remaining - 0xc - missing;
        match kind {
            4 => subtype = 0x3_0000,
            7 => {
                subtype = 0x4_0000;
                let pad = usize::from(reader.peek(trailer_end.checked_sub(1)?, 1)?[0]) << 3;
                if remaining < missing + pad + 0xd {
                    return None;
                }
                tail = remaining - 0xc - missing - pad;
                data_size = pad;
            }
            0xa => {
                subtype = 0x5_0000;
                tail = data_size;
                data_size = 0;
            }
            0xd => subtype = 0x6_0000,
            _ => {}
        }
    }
    let declared = tail
        .wrapping_sub(shown)
        .wrapping_add(ports)
        .wrapping_add(data_size)
        .wrapping_add(0xc);
    if data_size & 7 != 0 || data_size < hidden || remaining != declared {
        return None;
    }
    if kind != 0 {
        if port_form == 0 {
            parsed.put_u16(0x8, 0x3e8);
            parsed.put_u16(0xa, 0x3e8);
        } else {
            let base = data_size - shown;
            if port_form == 1 {
                if shown == 0 {
                    parsed.put_u16(0x8, u16::from(reader.peek(base, 1)?[0]) + 0x3e8);
                }
                if shown <= 1 {
                    parsed.put_u16(0xa, u16::from(reader.peek(base + 1, 1)?[0]) + 0x3e8);
                }
            } else {
                if shown == 0 {
                    parsed.put(0x8, reader.peek(base, 2)?);
                }
                if shown <= 2 {
                    parsed.put(0xa, reader.peek(base + 2, 2)?);
                }
            }
        }
    }
    if subtype == 0x2_0000 {
        let segment = reader.peek(trailer_end.checked_sub(0xc)?, 0xc)?;
        let offset = usize::from(segment[8] & 0xf0) >> 2;
        if offset < 0x14 || offset > data_size - hidden + 0x14 {
            return None;
        }
        let doubled = port_form * 2;
        if shown <= doubled {
            parsed.info[0x27] |= 1;
            parsed.put(0x28, &segment[0..4]);
        }
        if shown <= (port_form + 2) * 2 {
            parsed.info[0x27] |= 2;
            parsed.put(0x2c, &segment[4..8]);
        }
        if shown <= doubled + 9 {
            parsed.info[0x32] = segment[9];
        }
        if shown <= (port_form + 5) * 2 {
            parsed.info[0x27] |= 4;
            parsed.put(0x30, &segment[10..12]);
        }
    }
    parsed.flags |= subtype;
    parsed.put_u32(0x10, (data_size - hidden) as u32);
    parsed.put_u32(0xc, reader.position as u32);
    if matches!(subtype, 0x4_0000 | 0x5_0000 | 0x6_0000) {
        let payload = reader
            .position
            .wrapping_sub(shown)
            .wrapping_add(ports)
            .wrapping_add(data_size);
        parsed.put_u32(0x14, payload as u32);
        parsed.put_u32(0x18, tail.wrapping_sub(usize::from(kind == 7)) as u32);
    } else {
        parsed.put_u32(0x14, 0);
        parsed.put_u32(0x18, 0);
    }
    parsed.info[0x33] = port_form as u8;
    parsed.info[0x34] = hidden as u8;
    parsed.info[0x35] = shown as u8;
    parsed.put(0x1d, &first.to_be_bytes()[1..4]);
    Some(())
}

/// 0x91f68f48.
fn arp(parsed: &mut Parsed, reader: &mut Reader<'_>) {
    let Some(header) = reader.read(8) else {
        parsed.flags |= flags::MALFORMED;
        return;
    };
    let hardware = word(header, 0);
    if !matches!(hardware, 1 | 6) || word(header, 2) != 0x800 {
        return;
    }
    if header[4] != 6 || header[5] != 4 {
        parsed.flags |= flags::MALFORMED;
        return;
    }
    if !matches!(word(header, 6), 1 | 2) {
        return;
    }
    let bad = |address: u32| {
        address == u32::MAX
            || address & 0xf000_0000 == 0xe000_0000
            || address & 0xff00_0000 == 0x7f00_0000
    };
    match reader.read(20) {
        Some(body) if body[0] & 1 == 0 && !bad(be32(&body[6..10])) && !bad(be32(&body[16..20])) => {
            parsed.flags |= flags::ARP;
        }
        _ => parsed.flags |= flags::MALFORMED,
    }
}

/// The port the redirects compare: destination when sending, source when
/// receiving.
pub(super) fn port(frame: &[u8], info: Ipv4Frame, transmit: bool) -> u16 {
    let transport = ETHERNET_HEADER + info.header_length;
    if transmit {
        word(frame, transport + 2)
    } else {
        word(frame, transport)
    }
}

/// The address the redirects compare: destination when sending, source
/// when receiving.
pub(super) fn address(frame: &[u8], transmit: bool) -> [u8; 4] {
    let offset = ETHERNET_HEADER + if transmit { 16 } else { 12 };
    [
        frame[offset],
        frame[offset + 1],
        frame[offset + 2],
        frame[offset + 3],
    ]
}

/// Ones' complement sum of big-endian words (0x91f68360).
fn sum(mut total: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        total += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
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
    let length = usize::from(ip[0] & 0xf) * 4;
    ip[10] = 0;
    ip[11] = 0;
    let checksum = !fold(sum(0, &ip[..length]));
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
}

/// Gather buffer of the transport checksums (0x91fa30a8), shared by all
/// frames and guarded by a flag as stock does.
struct Gather {
    busy: AtomicBool,
    bytes: UnsafeCell<[u8; GATHER_CAPACITY]>,
}

// SAFETY: `bytes` is only touched while `busy` is held.
unsafe impl Sync for Gather {}

static GATHER: Gather = Gather {
    busy: AtomicBool::new(false),
    bytes: UnsafeCell::new([0; GATHER_CAPACITY]),
};

/// Recompute a TCP or UDP checksum over a pseudo header and `length`
/// transport bytes (0x91f681a8, 0x91f68098). The segment is copied into the
/// gather buffer first; a segment the buffer cannot hold clears the frame
/// headers instead, as stock does.
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
    while GATHER
        .busy
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: the flag is held.
    let gather = unsafe { &mut *GATHER.bytes.get() };
    let segment = &frame[transport..];
    let copied = segment.len().min(GATHER_CAPACITY);
    gather[..copied].copy_from_slice(&segment[..copied]);
    let mut pseudo = [0u8; 12];
    pseudo[..8].copy_from_slice(&frame[ETHERNET_HEADER + 12..ETHERNET_HEADER + 20]);
    pseudo[9] = protocol;
    pseudo[10..12].copy_from_slice(&(length as u16).to_be_bytes());
    let checksum = !fold(sum(sum(0, &pseudo), &gather[..length]));
    GATHER.busy.store(false, Ordering::Release);
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
    let offset = ETHERNET_HEADER + if transmit { 16 } else { 12 };
    frame[offset..offset + 4].copy_from_slice(&address);
    let transport = ETHERNET_HEADER + IPV4_HEADER;
    let port_offset = transport + if transmit { 2 } else { 0 };
    match info.protocol {
        Protocol::TCP => {
            if info.header_length != IPV4_HEADER {
                return;
            }
            frame[port_offset..port_offset + 2].copy_from_slice(&port.to_be_bytes());
            let length = frame.len().saturating_sub(transport);
            transport_checksum(frame, PROTOCOL_TCP, length, 16, 0x36);
        }
        Protocol::UDP => {
            if info.header_length != IPV4_HEADER {
                return;
            }
            frame[port_offset..port_offset + 2].copy_from_slice(&port.to_be_bytes());
            let length = usize::from(word(frame, transport + 4));
            transport_checksum(frame, PROTOCOL_UDP, length, 6, 0x2a);
        }
        _ => ip_checksum(frame),
    }
}
