//! Classifier evaluation (stock 0x91f8c988 driving 0x91f89310): a
//! program's expression over the fields of one parsed frame. Any failure
//! makes the frame pass the simulator untouched.

use openxbdm_server::commands::network::netsim::classifier::Node;
use openxbdm_server::commands::network::netsim::classifier::Operator;
use openxbdm_server::commands::network::netsim::classifier::Program;
use openxbdm_server::commands::network::netsim::classifier::TEXT_CAPACITY;
use openxbdm_server::commands::network::netsim::classifier::Value;
use openxbdm_server::commands::network::netsim::classifier::variant;
use openxbdm_server::commands::network::netsim::classifier::variant::Text;
use openxbdm_server::commands::network::netsim::classifier::variant::Variant;

use super::frame::ETHERNET_HEADER;
use super::frame::Parsed;

/// Evaluation failed; the frame bypasses the simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EvaluationFailed;

type Result<T, E = EvaluationFailed> = core::result::Result<T, E>;

fn truth(value: &Variant) -> Result<bool> {
    variant::to_bool(value).map_err(|_| EvaluationFailed)
}

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
    Bit(u8, u8),
    /// An address at a frame offset (0x91f8c850).
    Address(u8),
    /// A masked DNS flag field, shifted down by the mask's trailing zeros
    /// (0x91f8dc88).
    DnsFlags(u16),
    /// A DNS header count (0x91f8dd48).
    DnsCount(u8),
    /// The first DNS question name (0x91f8de00).
    DnsName,
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

/// XSP subtype values of the parse flags (bits 16..20).
const XSP_MASK: u32 = 0x1f_0000;

/// Parse flags a field needs: one flag bit (`BIT` plus its number), one
/// XSP subtype, or any XSP subtype.
#[derive(Clone, Copy)]
struct Presence(u8);

impl Presence {
    const BIT: u8 = 0x20;
    const ANY_XSP: u8 = (XSP_MASK >> 16) as u8;

    /// From the stock table mask.
    const fn of(mask: u32) -> Self {
        if mask == XSP_MASK {
            Self(Self::ANY_XSP)
        } else if mask & XSP_MASK == 0 {
            assert!(mask.is_power_of_two());
            Self(Self::BIT | mask.trailing_zeros() as u8)
        } else {
            assert!(mask & !XSP_MASK == 0);
            Self((mask >> 16) as u8)
        }
    }

    fn test(self, flags: u32) -> bool {
        let subtype = (flags & XSP_MASK) >> 16;
        if self.0 & Self::BIT != 0 {
            (flags >> (self.0 & !Self::BIT)) & 1 != 0
        } else if self.0 == Self::ANY_XSP {
            subtype != 0
        } else {
            subtype == u32::from(self.0)
        }
    }
}

#[derive(Clone, Copy)]
struct Field {
    presence: Presence,
    getter: Getter,
    kind: Kind,
}

const fn field(mask: u32, getter: Getter, kind: Kind) -> Field {
    Field {
        presence: Presence::of(mask),
        getter,
        kind,
    }
}

const fn present(mask: u32) -> Field {
    field(mask, Getter::Present, Kind::Bool)
}

/// The frame field table (0x91f0ca48), by field number - 1.
const FIELDS: [Field; 0x55] = [
    present(0x1),
    field(0x1, Getter::Address(0x6), Kind::Mac),
    field(0x1, Getter::Address(0x0), Kind::Mac),
    field(0x1, Getter::Frame(0xc, 2), Kind::U16),
    present(0x2),
    field(0x2, Getter::Frame(0x10, 2), Kind::U16),
    field(0x2, Getter::Frame(0x12, 2), Kind::U16),
    field(0x2, Getter::Frame(0x14, 2), Kind::U16),
    field(0x2, Getter::Frame(0x16, 1), Kind::U8),
    field(0x2, Getter::Frame(0x17, 1), Kind::U8),
    field(0x2, Getter::Address(0x1a), Kind::Ipv4),
    field(0x2, Getter::Address(0x1e), Kind::Ipv4),
    present(0x4),
    field(0x4, Getter::Frame(0x14, 2), Kind::U16),
    field(0x4, Getter::Address(0x16), Kind::Mac),
    field(0x4, Getter::Address(0x1c), Kind::Ipv4),
    field(0x4, Getter::Address(0x20), Kind::Mac),
    field(0x4, Getter::Address(0x26), Kind::Ipv4),
    present(0x10),
    present(0x20),
    field(0x20, Getter::Info(0x34, 1), Kind::U8),
    field(0x20, Getter::Info(0x35, 1), Kind::U8),
    present(0x40),
    present(0x80),
    field(0x80, Getter::Info(0x4, 2), Kind::U16),
    field(0x80, Getter::Info(0x6, 2), Kind::U16),
    field(0x80, Getter::Info(0x28, 4), Kind::U32),
    field(0x80, Getter::Info(0x2c, 4), Kind::U32),
    field(0x80, Getter::Info(0x32, 1), Kind::U8),
    field(0x80, Getter::Bit(0x32, 0x20), Kind::Bool),
    field(0x80, Getter::Bit(0x32, 0x10), Kind::Bool),
    field(0x80, Getter::Bit(0x32, 0x8), Kind::Bool),
    field(0x80, Getter::Bit(0x32, 0x4), Kind::Bool),
    field(0x80, Getter::Bit(0x32, 0x2), Kind::Bool),
    field(0x80, Getter::Bit(0x32, 0x1), Kind::Bool),
    field(0x80, Getter::Info(0x30, 2), Kind::U16),
    present(0x100),
    field(0x100, Getter::Info(0x4, 2), Kind::U16),
    field(0x100, Getter::Info(0x6, 2), Kind::U16),
    present(0x200),
    field(0x200, Getter::DnsFlags(0x8000), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x7800), Kind::U16),
    field(0x200, Getter::DnsFlags(0x400), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x200), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x100), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x80), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x20), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x10), Kind::Bool),
    field(0x200, Getter::DnsFlags(0xf), Kind::U16),
    field(0x200, Getter::DnsCount(0x4), Kind::U16),
    field(0x200, Getter::DnsCount(0x6), Kind::U16),
    field(0x200, Getter::DnsCount(0x8), Kind::U16),
    field(0x200, Getter::DnsCount(0xa), Kind::U16),
    field(0x200, Getter::DnsName, Kind::Str),
    present(0x400),
    field(0x400, Getter::Info(0x34, 1), Kind::U8),
    field(0x400, Getter::Info(0x35, 1), Kind::U8),
    present(XSP_MASK),
    present(0x7_0000),
    present(0x8_0000),
    present(0x9_0000),
    present(0xa_0000),
    present(0xb_0000),
    present(0xc_0000),
    present(0xd_0000),
    present(0xe_0000),
    present(0xf_0000),
    present(0x10_0000),
    present(0x11_0000),
    present(0x12_0000),
    present(0x13_0000),
    present(0x14_0000),
    present(0x15_0000),
    present(0x16_0000),
    present(0x17_0000),
    present(0x18_0000),
    field(XSP_MASK, Getter::Info(0x8, 2), Kind::U16),
    field(XSP_MASK, Getter::Info(0xa, 2), Kind::U16),
    field(XSP_MASK, Getter::Info(0x10, 4), Kind::U32),
    field(XSP_MASK, Getter::Info(0x18, 4), Kind::U32),
    present(0x1_0000),
    present(0x2_0000),
    present(0x4_0000),
    present(0x5_0000),
    present(0x20_0000),
];

/// Bytes of the DNS question name buffer (0x100 in stock).
const NAME_CAPACITY: usize = 0x100;

/// The decoded question name follows the program text in the evaluation
/// text, so that every string is a range of one buffer.
const NAME_START: usize = TEXT_CAPACITY;

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
        match operator.0 {
            0x1a | 0x1b => self.logical(node, operator.0 == 0x1a),
            0x1c => {
                let condition = truth(&self.operand(node, 0)?)?;
                self.operand(node, if condition { 1 } else { 2 })
            }
            // Indexed names (op 3) need named items.
            6 | 8 | 9 | 0xa..=0x19 | 0x1e..=0x24 => {
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
                Variant::Bool(self.parsed.info[usize::from(offset)] & mask != 0)
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
                let value = self.dns_word(2) & mask;
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
        if self.parsed.flags & 0x103 != 0x103 {
            return None;
        }
        let header = usize::from(self.frame.get(ETHERNET_HEADER).copied().unwrap_or(0) & 0xf) * 4;
        Some(ETHERNET_HEADER + header + 8)
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
                let header =
                    usize::from(self.frame.get(ETHERNET_HEADER).copied().unwrap_or(0) & 0xf) * 4;
                let udp_length = u16::from_be_bytes(
                    bytes_at(self.frame, ETHERNET_HEADER + header + 4, 2)[..2]
                        .try_into()
                        .ok()?,
                );
                let questions =
                    u16::from_be_bytes(bytes_at(self.frame, dns + 4, 2)[..2].try_into().ok()?);
                if questions == 0 {
                    return None;
                }
                let area_start = dns + 0xc;
                let area_len = usize::from(udp_length).checked_sub(8 + 0xc)?;
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
        if byte & 0xc0 == 0xc0 {
            let low = *area.get(position).filter(|_| position < limit)?;
            position += 1;
            let offset = (usize::from(byte & 0x3f) << 8 | usize::from(low)) & 0x3fff;
            if offset < 0xc {
                return None;
            }
            let current = position - 2;
            let target = (offset - 0xc) & 0xffff;
            if target + 1 >= current {
                return None;
            }
            limit = limit.min(current);
            position = target;
            continue;
        }
        if byte == 0 {
            if position + 4 > limit {
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

/// Up to eight frame bytes; bytes past the frame read as zero.
fn bytes_at(frame: &[u8], offset: usize, size: usize) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    for (index, byte) in bytes.iter_mut().enumerate().take(size) {
        *byte = frame.get(offset + index).copied().unwrap_or(0);
    }
    bytes
}
