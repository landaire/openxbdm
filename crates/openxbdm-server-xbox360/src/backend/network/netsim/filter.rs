//! Classifier evaluation (stock 0x91f8c988 driving 0x91f89310): a
//! program's expression over the fields of one parsed frame. Any failure
//! makes the frame pass the simulator untouched.

mod error;

use openxbdm_server::commands::network::netsim::classifier::Node;
use openxbdm_server::commands::network::netsim::classifier::Operator;
use openxbdm_server::commands::network::netsim::classifier::Program;
use openxbdm_server::commands::network::netsim::classifier::TEXT_CAPACITY;
use openxbdm_server::commands::network::netsim::classifier::Value;
use openxbdm_server::commands::network::netsim::classifier::variant;
use openxbdm_server::commands::network::netsim::classifier::variant::Text;
use openxbdm_server::commands::network::netsim::classifier::variant::Variant;

use super::frame::ETHERNET_HEADER;
use super::frame::FrameFlags;
use super::frame::Parsed;
use super::frame::UDP_HEADER;
use super::frame::XspSubtype;
use super::frame::arp;
use super::frame::header_length;
use super::frame::info;
use super::frame::ipv4;
use super::frame::udp;

pub(super) use self::error::EvaluationFailed;

type Result<T, E = EvaluationFailed> = core::result::Result<T, E>;

const ETHERNET: Presence = Presence::flag(FrameFlags::ETHERNET);
const IPV4: Presence = Presence::flag(FrameFlags::IPV4);
const ARP: Presence = Presence::flag(FrameFlags::ARP);
const ICMP: Presence = Presence::flag(FrameFlags::ICMP);
const TCP: Presence = Presence::flag(FrameFlags::TCP);
const UDP: Presence = Presence::flag(FrameFlags::UDP);
const DNS: Presence = Presence::flag(FrameFlags::DNS);
const DHCP: Presence = Presence::flag(FrameFlags::DHCP);
const XSP: Presence = Presence::ANY_XSP;

/// The frame field table (0x91f0ca48), by field number - 1.
const FIELDS: [Field; 0x55] = [
    present(ETHERNET),
    field(
        ETHERNET,
        Getter::Address(offset::ETHERNET_SOURCE),
        Kind::Mac,
    ),
    field(
        ETHERNET,
        Getter::Address(offset::ETHERNET_DESTINATION),
        Kind::Mac,
    ),
    field(ETHERNET, Getter::Frame(offset::ETHERNET_TYPE, 2), Kind::U16),
    present(IPV4),
    field(IPV4, Getter::Frame(offset::IPV4_TOTAL_LENGTH, 2), Kind::U16),
    field(
        IPV4,
        Getter::Frame(offset::IPV4_IDENTIFICATION, 2),
        Kind::U16,
    ),
    field(IPV4, Getter::Frame(offset::IPV4_FRAGMENT, 2), Kind::U16),
    field(IPV4, Getter::Frame(offset::IPV4_TIME_TO_LIVE, 1), Kind::U8),
    field(IPV4, Getter::Frame(offset::IPV4_PROTOCOL, 1), Kind::U8),
    field(IPV4, Getter::Address(offset::IPV4_SOURCE), Kind::Ipv4),
    field(IPV4, Getter::Address(offset::IPV4_DESTINATION), Kind::Ipv4),
    present(ARP),
    field(ARP, Getter::Frame(offset::ARP_OPERATION, 2), Kind::U16),
    field(ARP, Getter::Address(offset::ARP_SENDER_HARDWARE), Kind::Mac),
    field(
        ARP,
        Getter::Address(offset::ARP_SENDER_PROTOCOL),
        Kind::Ipv4,
    ),
    field(ARP, Getter::Address(offset::ARP_TARGET_HARDWARE), Kind::Mac),
    field(
        ARP,
        Getter::Address(offset::ARP_TARGET_PROTOCOL),
        Kind::Ipv4,
    ),
    present(Presence::flag(FrameFlags::LLTD)),
    present(ICMP),
    field(ICMP, Getter::Info(info::KIND, 1), Kind::U8),
    field(ICMP, Getter::Info(info::CODE, 1), Kind::U8),
    present(Presence::flag(FrameFlags::IGMP)),
    present(TCP),
    field(TCP, Getter::Info(info::SOURCE_PORT, 2), Kind::U16),
    field(TCP, Getter::Info(info::DESTINATION_PORT, 2), Kind::U16),
    field(TCP, Getter::Info(info::TCP_SEQUENCE, 4), Kind::U32),
    field(TCP, Getter::Info(info::TCP_ACKNOWLEDGMENT, 4), Kind::U32),
    field(TCP, Getter::Info(info::TCP_FLAGS, 1), Kind::U8),
    field(
        TCP,
        Getter::Bit(info::TCP_FLAGS, TcpFlags::URGENT),
        Kind::Bool,
    ),
    field(
        TCP,
        Getter::Bit(info::TCP_FLAGS, TcpFlags::ACKNOWLEDGE),
        Kind::Bool,
    ),
    field(
        TCP,
        Getter::Bit(info::TCP_FLAGS, TcpFlags::PUSH),
        Kind::Bool,
    ),
    field(
        TCP,
        Getter::Bit(info::TCP_FLAGS, TcpFlags::RESET),
        Kind::Bool,
    ),
    field(
        TCP,
        Getter::Bit(info::TCP_FLAGS, TcpFlags::SYNCHRONIZE),
        Kind::Bool,
    ),
    field(
        TCP,
        Getter::Bit(info::TCP_FLAGS, TcpFlags::FINISH),
        Kind::Bool,
    ),
    field(TCP, Getter::Info(info::TCP_WINDOW, 2), Kind::U16),
    present(UDP),
    field(UDP, Getter::Info(info::SOURCE_PORT, 2), Kind::U16),
    field(UDP, Getter::Info(info::DESTINATION_PORT, 2), Kind::U16),
    present(DNS),
    field(DNS, Getter::DnsFlags(DnsFlags::RESPONSE), Kind::Bool),
    field(DNS, Getter::DnsFlags(DnsFlags::OPCODE), Kind::U16),
    field(DNS, Getter::DnsFlags(DnsFlags::AUTHORITATIVE), Kind::Bool),
    field(DNS, Getter::DnsFlags(DnsFlags::TRUNCATED), Kind::Bool),
    field(
        DNS,
        Getter::DnsFlags(DnsFlags::RECURSION_DESIRED),
        Kind::Bool,
    ),
    field(
        DNS,
        Getter::DnsFlags(DnsFlags::RECURSION_AVAILABLE),
        Kind::Bool,
    ),
    field(DNS, Getter::DnsFlags(DnsFlags::AUTHENTIC_DATA), Kind::Bool),
    field(
        DNS,
        Getter::DnsFlags(DnsFlags::CHECKING_DISABLED),
        Kind::Bool,
    ),
    field(DNS, Getter::DnsFlags(DnsFlags::RESPONSE_CODE), Kind::U16),
    field(DNS, Getter::DnsCount(dns::QUESTIONS), Kind::U16),
    field(DNS, Getter::DnsCount(dns::ANSWERS), Kind::U16),
    field(DNS, Getter::DnsCount(dns::AUTHORITIES), Kind::U16),
    field(DNS, Getter::DnsCount(dns::ADDITIONAL), Kind::U16),
    field(DNS, Getter::DnsName, Kind::Str),
    present(DHCP),
    field(DHCP, Getter::Info(info::KIND, 1), Kind::U8),
    field(DHCP, Getter::Info(info::CODE, 1), Kind::U8),
    present(XSP),
    xsp(XspSubtype::KEY_EX_XB_TO_XB_INIT),
    xsp(XspSubtype::KEY_EX_XB_TO_XB_RESP),
    xsp(XspSubtype::KEY_EX_XB_TO_SG_INIT),
    xsp(XspSubtype::KEY_EX_SG_TO_XB_RESP),
    xsp(XspSubtype::KEY_EX_NAT_OPEN_INIT),
    xsp(XspSubtype::KEY_EX_NAT_OPEN_RESP),
    xsp(XspSubtype::KEY_EX_QOS_INIT),
    xsp(XspSubtype::KEY_EX_QOS_RESP),
    xsp(XspSubtype::KEY_EX_XB_TO_LSPSG_INIT),
    xsp(XspSubtype::KEY_EX_LSPSG_TO_XB_RESP),
    xsp(XspSubtype::KEY_EX_XB_TO_XB_INIT2),
    xsp(XspSubtype::KEY_EX_XB_TO_XB_RESP2),
    xsp(XspSubtype::KEY_EX_NAT_OPEN2),
    xsp(XspSubtype::QOS_SETUP),
    xsp(XspSubtype::KEY_EX_XB_TO_XB3_INIT),
    xsp(XspSubtype::KEY_EX_XB_TO_XB_RESP3),
    xsp(XspSubtype::KEY_EX_NAT_OPEN3),
    xsp(XspSubtype::KEY_EX_QOS_INIT2),
    field(XSP, Getter::Info(info::XSP_SOURCE_PORT, 2), Kind::U16),
    field(XSP, Getter::Info(info::XSP_DESTINATION_PORT, 2), Kind::U16),
    field(XSP, Getter::Info(info::DATA_SIZE, 4), Kind::U32),
    field(XSP, Getter::Info(info::PAYLOAD_LENGTH, 4), Kind::U32),
    xsp(XspSubtype::SECURE_MESSAGE),
    xsp(XspSubtype::TCP_INFO),
    xsp(XspSubtype::VOICE_PAYLOAD),
    xsp(XspSubtype::VOICE_ONLY_PAYLOAD),
    present(Presence::flag(FrameFlags::KERBEROS)),
];

/// Bytes of the DNS question name buffer (0x100 in stock).
const NAME_CAPACITY: usize = 0x100;

/// The decoded question name follows the program text in the evaluation
/// text, so that every string is a range of one buffer.
const NAME_START: usize = TEXT_CAPACITY;

/// How a field reads its value (getters of the table at 0x91f0ca48).
#[derive(Clone, Copy)]
enum Getter {
    /// Presence only: true.
    Present,
    /// Bytes at a frame offset (0x91f8c7c0).
    Frame(u8, u8),
    /// Bytes at a parse information offset (0x91f8c8b0).
    Info(u8, u8),
    /// A bit of a parse information byte (0x91f8c940).
    Bit(u8, TcpFlags),
    /// An address at a frame offset (0x91f8c850).
    Address(u8),
    /// A masked DNS flag field, shifted down by the mask's trailing zeros
    /// (0x91f8dc88).
    DnsFlags(DnsFlags),
    /// A DNS header count (0x91f8dd48).
    DnsCount(u8),
    /// The first DNS question name (0x91f8de00).
    DnsName,
}

xbox360_sys::flags! {
    /// TCP header flags (information byte [`info::TCP_FLAGS`]).
    pub struct TcpFlags(u8) {
        FINISH = 0x1,
        SYNCHRONIZE = 0x2,
        RESET = 0x4,
        PUSH = 0x8,
        ACKNOWLEDGE = 0x10,
        URGENT = 0x20,
    }
}

xbox360_sys::flags! {
    /// DNS header flag word; `OPCODE` and `RESPONSE_CODE` are fields.
    pub struct DnsFlags(u16) {
        RESPONSE = 0x8000,
        OPCODE = 0x7800,
        AUTHORITATIVE = 0x400,
        TRUNCATED = 0x200,
        RECURSION_DESIRED = 0x100,
        RECURSION_AVAILABLE = 0x80,
        AUTHENTIC_DATA = 0x20,
        CHECKING_DISABLED = 0x10,
        RESPONSE_CODE = 0xf,
    }
}

/// DNS header fields.
mod dns {
    pub(super) const FLAGS: usize = 2;
    pub(super) const QUESTIONS: u8 = 4;
    pub(super) const ANSWERS: u8 = 6;
    pub(super) const AUTHORITIES: u8 = 8;
    pub(super) const ADDITIONAL: u8 = 0xa;
    pub(super) const HEADER: usize = 0xc;
    /// Marks a compression pointer in a name; the other bits are the
    /// high bits of the offset.
    pub(super) const POINTER: u8 = 0xc0;
    /// Type and class after a question name.
    pub(super) const QUESTION_TRAILER: usize = 4;
}

/// Frame offsets of the fields the table reads.
mod offset {
    use super::ETHERNET_HEADER;
    use super::arp;
    use super::ipv4;

    /// Offset of a field of the packet after the Ethernet header.
    const fn ip(field: usize) -> u8 {
        (ETHERNET_HEADER + field) as u8
    }

    pub(super) const ETHERNET_DESTINATION: u8 = 0x0;
    pub(super) const ETHERNET_SOURCE: u8 = 0x6;
    pub(super) const ETHERNET_TYPE: u8 = 0xc;
    pub(super) const IPV4_TOTAL_LENGTH: u8 = ip(ipv4::TOTAL_LENGTH);
    pub(super) const IPV4_IDENTIFICATION: u8 = ip(ipv4::IDENTIFICATION);
    pub(super) const IPV4_FRAGMENT: u8 = ip(ipv4::FRAGMENT);
    pub(super) const IPV4_TIME_TO_LIVE: u8 = ip(ipv4::TIME_TO_LIVE);
    pub(super) const IPV4_PROTOCOL: u8 = ip(ipv4::PROTOCOL);
    pub(super) const IPV4_SOURCE: u8 = ip(ipv4::SOURCE);
    pub(super) const IPV4_DESTINATION: u8 = ip(ipv4::DESTINATION);
    pub(super) const ARP_OPERATION: u8 = ip(arp::OPERATION);
    pub(super) const ARP_SENDER_HARDWARE: u8 = ip(arp::SENDER_HARDWARE);
    pub(super) const ARP_SENDER_PROTOCOL: u8 = ip(arp::SENDER_PROTOCOL);
    pub(super) const ARP_TARGET_HARDWARE: u8 = ip(arp::TARGET_HARDWARE);
    pub(super) const ARP_TARGET_PROTOCOL: u8 = ip(arp::TARGET_PROTOCOL);
}

/// Value type of a field (variant type numbers).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bool,
    U8,
    U16,
    U32,
    Mac,
    Ipv4,
    Str,
}

/// Parse flags a field needs: one flag bit (`BIT` plus its number), one
/// XSP subtype (its value), or any XSP subtype (zero, which no subtype
/// has).
#[derive(Clone, Copy)]
struct Presence(u8);

impl Presence {
    const BIT: u8 = 0x20;
    const ANY_XSP: Self = Self(0);

    const fn flag(flag: FrameFlags) -> Self {
        assert!(flag.bits().is_power_of_two());
        Self(Self::BIT | flag.bits().trailing_zeros() as u8)
    }

    const fn xsp(subtype: XspSubtype) -> Self {
        Self(subtype.get())
    }

    fn test(self, flags: FrameFlags) -> bool {
        // Zero for no subtype, which matches only `ANY_XSP` below.
        let subtype = flags.xsp_subtype().map_or(0, XspSubtype::get);
        if self.0 & Self::BIT != 0 {
            (flags.bits() >> (self.0 & !Self::BIT)) & 1 != 0
        } else if self.0 == Self::ANY_XSP.0 {
            subtype != 0
        } else {
            subtype == self.0
        }
    }
}

#[derive(Clone, Copy)]
struct Field {
    presence: Presence,
    getter: Getter,
    kind: Kind,
}

/// One evaluation of a program against a frame.
pub(super) struct Evaluation<'a> {
    program: &'a Program,
    frame: &'a [u8],
    parsed: &'a Parsed,
    /// Item values once read.
    items: [Option<Variant>; 0x10],
    /// Operand node indices of every node.
    operands: [[u8; 5]; 0x20],
    /// The program text, then the question name.
    text: [u8; NAME_START + NAME_CAPACITY],
    name_len: Option<usize>,
}

impl Evaluation<'_> {
    fn operand(&mut self, node: usize, index: usize) -> Result<Variant> {
        self.evaluate(usize::from(self.operands[node][index]))
    }

    fn evaluate(&mut self, node: usize) -> Result<Variant> {
        match self.program.nodes()[node] {
            Node::Constant(value) => Ok(self.program.variant(value)),
            // Names resolve against named items, which netsim programs do
            // not have; stock creates an item without a field and fails.
            Node::Name(_) => Err(EvaluationFailed),
            Node::Item(index) => self.item(usize::from(index)),
            Node::Operator { operator, operands } => {
                self.operator(node, operator, usize::from(operands))
            }
        }
    }

    fn operator(&mut self, node: usize, operator: Operator, count: usize) -> Result<Variant> {
        /// Operator codes the server's `Operator` does not name.
        const AND: Operator = Operator(0x1a);
        const OR: Operator = Operator(0x1b);
        /// Binary operators `variant::apply` evaluates.
        const FIRST_BINARY: u8 = 0xa;
        const LAST_BINARY: u8 = 0x19;
        /// Functions from `Operator::STRING_LENGTH` on.
        const FIRST_FUNCTION: u8 = Operator::STRING_LENGTH.0;
        const LAST_FUNCTION: u8 = 0x24;

        match operator {
            AND | OR => self.logical(node, operator == AND),
            Operator::CONDITIONAL => {
                let condition = truth(&self.operand(node, 0)?)?;
                self.operand(node, if condition { 1 } else { 2 })
            }
            // Indexed names (`Operator::INDEX`) need named items.
            Operator::NEGATE
            | Operator::NOT
            | Operator::COMPLEMENT
            | Operator(FIRST_BINARY..=LAST_BINARY)
            | Operator(FIRST_FUNCTION..=LAST_FUNCTION) => {
                let mut arguments = [Variant::Null; 5];
                for (index, argument) in arguments.iter_mut().enumerate().take(count) {
                    *argument = self.operand(node, index)?;
                }

                variant::apply(&self.text, operator, &arguments[..count])
                    .map_err(|_| EvaluationFailed)
            }
            _ => Err(EvaluationFailed),
        }
    }

    /// And (0x1a) and or (0x1b): a literal right operand is converted with
    /// the left one (0x91f8a888); otherwise a deciding left operand skips
    /// the right one (0x91f85310).
    fn logical(&mut self, node: usize, and: bool) -> Result<Variant> {
        let left = truth(&self.operand(node, 0)?);
        let right_node = usize::from(self.operands[node][1]);

        if let Node::Constant(value) = self.program.nodes()[right_node] {
            let (left, right) = (left?, truth(&self.program.variant(value))?);
            return Ok(Variant::Bool(if and {
                left && right
            } else {
                left || right
            }));
        }

        let decided = left?;
        if decided != and {
            return Ok(Variant::Bool(decided));
        }

        Ok(Variant::Bool(truth(&self.evaluate(right_node)?)?))
    }

    fn item(&mut self, index: usize) -> Result<Variant> {
        if let Some(value) = self.items[index] {
            return Ok(value);
        }

        let item = self.program.items()[index];
        let value = match item.value {
            Value::Null => self.read_field(usize::from(item.field.0) - 1)?,
            declared => self.program.variant(declared),
        };

        self.items[index] = Some(value);

        Ok(value)
    }

    /// Read a field from the frame, or its default when the frame lacks
    /// the protocol.
    fn read_field(&mut self, index: usize) -> Result<Variant> {
        let field = FIELDS[index];
        let present = field.presence.test(self.parsed.flags);
        if !present {
            return Ok(match field.kind {
                Kind::Bool => Variant::Bool(false),
                Kind::U8 => Variant::U8(0),
                Kind::U16 => Variant::U16(0),
                Kind::U32 => Variant::U32(0),
                Kind::Mac => Variant::Mac([0; 6]),
                Kind::Ipv4 => Variant::Ipv4([0; 4]),
                Kind::Str => Variant::Str(Text {
                    start: NAME_START,
                    end: NAME_START,
                }),
            });
        }

        let number = |bytes: &[u8], kind: Kind| -> Variant {
            let value = bytes
                .iter()
                .fold(0u32, |value, &byte| (value << 8) | u32::from(byte));
            match kind {
                Kind::U8 => Variant::U8(value as u8),
                Kind::U16 => Variant::U16(value as u16),
                _ => Variant::U32(value),
            }
        };

        Ok(match field.getter {
            Getter::Present => Variant::Bool(true),
            // 0x91f8c7c0 copies `size` frame bytes in order and reads the
            // value from them.
            Getter::Frame(offset, size) => {
                let size = usize::from(size);
                number(
                    &bytes_at(self.frame, usize::from(offset), size)[..size],
                    field.kind,
                )
            }
            Getter::Info(offset, size) => {
                let offset = usize::from(offset);
                number(
                    &self.parsed.info[offset..offset + usize::from(size)],
                    field.kind,
                )
            }
            Getter::Bit(offset, mask) => {
                Variant::Bool(self.parsed.info[usize::from(offset)] & mask.bits() != 0)
            }
            Getter::Address(offset) => {
                let bytes = bytes_at(self.frame, usize::from(offset), 8);
                match field.kind {
                    Kind::Mac => {
                        Variant::Mac([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
                    }
                    _ => Variant::Ipv4([bytes[0], bytes[1], bytes[2], bytes[3]]),
                }
            }
            Getter::DnsFlags(mask) => {
                let mask = mask.bits();
                let value = self.dns_word(dns::FLAGS) & mask;
                if field.kind == Kind::Bool {
                    Variant::Bool(value != 0)
                } else {
                    Variant::U16(value >> mask.trailing_zeros())
                }
            }
            Getter::DnsCount(offset) => Variant::U16(self.dns_word(usize::from(offset))),
            Getter::DnsName => Variant::Str(Text {
                start: NAME_START,
                end: NAME_START + self.decode_name(),
            }),
        })
    }

    /// A DNS header word, zero without a DNS header.
    fn dns_word(&self, offset: usize) -> u16 {
        self.dns().map_or(0, |dns| {
            let bytes = bytes_at(self.frame, dns + offset, 2);
            u16::from_be_bytes([bytes[0], bytes[1]])
        })
    }

    /// Frame offset of the DNS header (0x91f8db88).
    fn dns(&self) -> Option<usize> {
        if !self
            .parsed
            .flags
            .contains(FrameFlags::ETHERNET | FrameFlags::IPV4 | FrameFlags::UDP)
        {
            return None;
        }

        let header = header_length(self.frame.get(ETHERNET_HEADER).copied().unwrap_or(0));

        Some(ETHERNET_HEADER + header + UDP_HEADER)
    }

    /// The first question name (0x91f68498 for question 0): labels joined
    /// by dots. Returns its length; a failed or root name reads as empty.
    fn decode_name(&mut self) -> usize {
        if let Some(length) = self.name_len {
            return length;
        }

        let length = self
            .dns()
            .and_then(|dns| {
                let header = header_length(self.frame.get(ETHERNET_HEADER).copied().unwrap_or(0));
                let udp_length = u16::from_be_bytes(
                    bytes_at(self.frame, ETHERNET_HEADER + header + udp::LENGTH, 2)[..2]
                        .try_into()
                        .ok()?,
                );
                let questions = u16::from_be_bytes(
                    bytes_at(self.frame, dns + usize::from(dns::QUESTIONS), 2)[..2]
                        .try_into()
                        .ok()?,
                );

                if questions == 0 {
                    return None;
                }

                let area_start = dns + dns::HEADER;
                let area_len = usize::from(udp_length).checked_sub(UDP_HEADER + dns::HEADER)?;
                let area = self
                    .frame
                    .get(area_start..(area_start + area_len).min(self.frame.len()))?;

                decode_question(area, area_len, &mut self.text[NAME_START..])
            })
            .unwrap_or(0);

        self.name_len = Some(length);

        length
    }
}

/// Whether the frame passes `program` (0x91f8c988).
pub(super) fn matches(
    program: &Program,
    frame: &[u8],
    parsed: &Parsed,
) -> core::result::Result<bool, EvaluationFailed> {
    let mut evaluation = Evaluation {
        program,
        frame,
        parsed,
        items: [None; 0x10],
        operands: [[0; 5]; 0x20],
        text: [0; NAME_START + NAME_CAPACITY],
        name_len: None,
    };

    let program_text = program.text();
    evaluation.text[..program_text.len()].copy_from_slice(program_text);

    let nodes = program.nodes();
    let mut stack = [0u8; 0x20];
    let mut depth = 0;

    for (index, node) in nodes.iter().enumerate() {
        let count = match *node {
            Node::Operator { operands, .. } => usize::from(operands),
            _ => 0,
        };
        depth -= count;
        evaluation.operands[index][..count].copy_from_slice(&stack[depth..depth + count]);
        stack[depth] = index as u8;
        depth += 1;
    }

    let root = evaluation.evaluate(nodes.len() - 1)?;

    // 0x91f84768: the result as a truth value.
    truth(&root)
}

/// Decode a question name into `output`; returns its length without the
/// trailing dot.
fn decode_question(area: &[u8], declared: usize, output: &mut [u8]) -> Option<usize> {
    let capacity = output.len();
    let mut position = 0usize;
    let mut limit = declared.min(area.len());
    let mut written = 0usize;

    loop {
        let byte = *area.get(position).filter(|_| position < limit)?;
        position += 1;

        if byte & dns::POINTER == dns::POINTER {
            let low = *area.get(position).filter(|_| position < limit)?;
            position += 1;

            let offset = (usize::from(byte & !dns::POINTER) << 8 | usize::from(low)) & 0x3fff;

            // Pointers count from the DNS header; `area` starts after it.
            if offset < dns::HEADER {
                return None;
            }

            let current = position - 2;
            let target = (offset - dns::HEADER) & 0xffff;
            if target + 1 >= current {
                return None;
            }

            limit = limit.min(current);
            position = target;
            continue;
        }

        if byte == 0 {
            if position + dns::QUESTION_TRAILER > limit {
                return None;
            }

            return written.checked_sub(1);
        }

        let label = usize::from(byte);
        let end = position + label;
        if end > limit {
            return None;
        }

        if written + label < capacity {
            output[written..written + label].copy_from_slice(&area[position..end]);
            output[written + label] = b'.';
        }

        written += label + 1;
        position = end;

        if written > capacity {
            return None;
        }
    }
}

fn truth(value: &Variant) -> Result<bool> {
    variant::to_bool(value).map_err(|_| EvaluationFailed)
}

/// Up to eight frame bytes; bytes past the frame read as zero.
fn bytes_at(frame: &[u8], offset: usize, size: usize) -> [u8; 8] {
    let mut bytes = [0u8; 8];

    for (index, byte) in bytes.iter_mut().enumerate().take(size) {
        *byte = frame.get(offset + index).copied().unwrap_or(0);
    }

    bytes
}

const fn field(presence: Presence, getter: Getter, kind: Kind) -> Field {
    Field {
        presence,
        getter,
        kind,
    }
}

const fn present(presence: Presence) -> Field {
    field(presence, Getter::Present, Kind::Bool)
}

const fn xsp(subtype: XspSubtype) -> Field {
    present(Presence::xsp(subtype))
}
