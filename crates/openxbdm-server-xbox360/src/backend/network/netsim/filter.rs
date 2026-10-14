//! Classifier evaluation (stock 0x91f8c988 driving 0x91f89310): a
//! program's expression over the fields of one parsed frame. Any failure
//! makes the frame pass the simulator untouched.

use openxbdm_server::commands::network::netsim::classifier::Node;
use openxbdm_server::commands::network::netsim::classifier::Operator;
use openxbdm_server::commands::network::netsim::classifier::Program;
use openxbdm_server::commands::network::netsim::classifier::Value;

use super::frame::ETHERNET_HEADER;
use super::frame::Parsed;

/// Evaluation failed; the frame bypasses the simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EvaluationFailed;

type Result<T, E = EvaluationFailed> = core::result::Result<T, E>;

/// Where a runtime string lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// A program string.
    Program(u8),
    /// The decoded DNS question name of the frame.
    Name,
}

/// A runtime string: bytes `start..end` of its base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Text {
    base: Base,
    start: u16,
    end: u16,
}

/// Runtime values (stock variant types 0..9, 0xf, 0x10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    Null,
    Bool(bool),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Mac([u8; 6]),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Opaque,
    Str(Text),
}

impl Variant {
    fn from_value(value: Value) -> Variant {
        match value {
            Value::Null => Variant::Null,
            Value::Bool(value) => Variant::Bool(value),
            Value::I8(value) => Variant::I8(value),
            Value::I16(value) => Variant::I16(value),
            Value::I32(value) => Variant::I32(value),
            Value::I64(value) => Variant::I64(value),
            Value::U8(value) => Variant::U8(value),
            Value::U16(value) => Variant::U16(value),
            Value::U32(value) => Variant::U32(value),
            Value::U64(value) => Variant::U64(value),
            Value::Mac(bytes) => Variant::Mac(bytes),
            Value::Ipv4(bytes) => Variant::Ipv4(bytes),
            Value::Ipv6(bytes) => Variant::Ipv6(bytes),
            Value::Opaque => Variant::Opaque,
            Value::Str(id) => Variant::Str(Text {
                base: Base::Program(id.0),
                start: 0,
                end: u16::MAX,
            }),
        }
    }

    /// Integer conversion source (0x91f8a0b8): the value widened to 64
    /// bits, and whether it is signed. Booleans count as unsigned.
    fn integer(self) -> Result<(u64, bool)> {
        Ok(match self {
            Variant::Bool(value) => (u64::from(value), false),
            Variant::I8(value) => (value as i64 as u64, true),
            Variant::I16(value) => (value as i64 as u64, true),
            Variant::I32(value) => (value as i64 as u64, true),
            Variant::I64(value) => (value as u64, true),
            Variant::U8(value) => (u64::from(value), false),
            Variant::U16(value) => (u64::from(value), false),
            Variant::U32(value) => (u64::from(value), false),
            Variant::U64(value) => (value, false),
            _ => return Err(EvaluationFailed),
        })
    }

    /// 0x91f89fe0.
    fn truth(self) -> Result<bool> {
        Ok(match self {
            Variant::Bool(value) => value,
            Variant::I8(_) | Variant::I16(_) | Variant::I32(_) | Variant::I64(_) => {
                self.integer()?.0 != 0
            }
            Variant::U8(_) | Variant::U16(_) | Variant::U32(_) | Variant::U64(_) => {
                self.integer()?.0 != 0
            }
            _ => return Err(EvaluationFailed),
        })
    }

    fn is_unsigned(self) -> bool {
        matches!(
            self,
            Variant::U8(_) | Variant::U16(_) | Variant::U32(_) | Variant::U64(_)
        )
    }
}

/// Conversion to `i32` (0x91f8a0b8 to type 4): sources wider than 32 bits
/// fail; narrower ones keep their bit pattern.
fn int32(value: Variant) -> Result<i32> {
    match value {
        Variant::Bool(value) => Ok(i32::from(value)),
        Variant::I8(value) => Ok(i32::from(value)),
        Variant::I16(value) => Ok(i32::from(value)),
        Variant::I32(value) => Ok(value),
        Variant::U8(value) => Ok(i32::from(value)),
        Variant::U16(value) => Ok(i32::from(value)),
        Variant::U32(value) => Ok(value as i32),
        _ => Err(EvaluationFailed),
    }
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
    /// A masked DNS flag field and its shift (0x91f8dc88).
    DnsFlags(u16, u8),
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

#[derive(Clone, Copy)]
struct Field {
    mask: u32,
    getter: Getter,
    kind: Kind,
}

const fn field(mask: u32, getter: Getter, kind: Kind) -> Field {
    Field { mask, getter, kind }
}

const fn present(mask: u32) -> Field {
    field(mask, Getter::Present, Kind::Bool)
}

/// XSP subtype values of the parse flags (bits 16..20).
const XSP_MASK: u32 = 0x1f_0000;

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
    field(0x200, Getter::DnsFlags(0x8000, 0xf), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x7800, 0xb), Kind::U16),
    field(0x200, Getter::DnsFlags(0x400, 0xa), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x200, 0x9), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x100, 0x8), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x80, 0x7), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x20, 0x5), Kind::Bool),
    field(0x200, Getter::DnsFlags(0x10, 0x4), Kind::Bool),
    field(0x200, Getter::DnsFlags(0xf, 0x0), Kind::U16),
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

/// One evaluation of a program against a frame.
pub(super) struct Evaluation<'a> {
    program: &'a Program,
    frame: &'a [u8],
    parsed: &'a Parsed,
    /// Item values once read.
    items: [Option<Variant>; 0x10],
    /// Operand node indices of every node.
    operands: [[u8; 5]; 0x20],
    name: [u8; NAME_CAPACITY],
    name_len: Option<u16>,
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
        name: [0; NAME_CAPACITY],
        name_len: None,
    };
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
    root.truth()
}

impl Evaluation<'_> {
    fn text<'s>(&'s self, text: Text) -> &'s [u8] {
        let bytes: &[u8] = match text.base {
            Base::Program(id) => self
                .program
                .string(openxbdm_server::commands::network::netsim::classifier::StringId(id)),
            Base::Name => &self.name[..usize::from(self.name_len.unwrap_or(0))],
        };
        let end = usize::from(text.end).min(bytes.len());
        &bytes[usize::from(text.start).min(end)..end]
    }

    fn operand(&mut self, node: usize, index: usize) -> Result<Variant> {
        self.evaluate(usize::from(self.operands[node][index]))
    }

    fn evaluate(&mut self, node: usize) -> Result<Variant> {
        match self.program.nodes()[node] {
            Node::Constant(value) => Ok(Variant::from_value(value)),
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
            // Indexed names (op 3) need named items.
            3 => Err(EvaluationFailed),
            6 => {
                let value = self.operand(node, 0)?;
                arithmetic(Variant::I32(-1), 2, value)
            }
            8 => Ok(Variant::Bool(!self.operand(node, 0)?.truth()?)),
            9 => complement(self.operand(node, 0)?),
            0xa..=0x10 | 0x17..=0x19 => {
                let left = self.operand(node, 0)?;
                let right = self.operand(node, 1)?;
                let op = match operator.0 {
                    0xa => 2,
                    0xb => 3,
                    0xc => 4,
                    0xd => 0,
                    0xe => 1,
                    0xf => 5,
                    0x10 => 6,
                    0x17 => 7,
                    0x18 => 8,
                    _ => 9,
                };
                arithmetic(left, op, right)
            }
            0x11..=0x16 => {
                let left = self.operand(node, 0)?;
                let right = self.operand(node, 1)?;
                self.compare(left, operator.0 - 0x11, right)
            }
            0x1a | 0x1b => self.logical(node, operator.0 == 0x1a),
            0x1c => {
                let condition = self.operand(node, 0)?.truth()?;
                self.operand(node, if condition { 1 } else { 2 })
            }
            0x1e => match self.operand(node, 0)? {
                Variant::Str(text) => Ok(Variant::I32(self.text(text).len() as i32)),
                _ => Err(EvaluationFailed),
            },
            0x1f..=0x24 => {
                let mut arguments = [Variant::Null; 5];
                for (index, argument) in arguments.iter_mut().enumerate().take(count) {
                    *argument = self.operand(node, index)?;
                }
                self.string_function(operator.0, &arguments[..count])
            }
            _ => Err(EvaluationFailed),
        }
    }

    /// And (0x1a) and or (0x1b): a literal right operand is converted with
    /// the left one (0x91f8a888); otherwise a deciding left operand skips
    /// the right one (0x91f85310).
    fn logical(&mut self, node: usize, and: bool) -> Result<Variant> {
        let left = self.operand(node, 0)?;
        let right_node = usize::from(self.operands[node][1]);
        if let Node::Constant(value) = self.program.nodes()[right_node] {
            let (left, right) = (left.truth()?, Variant::from_value(value).truth()?);
            return Ok(Variant::Bool(if and {
                left && right
            } else {
                left || right
            }));
        }
        let decided = left.truth()?;
        if decided != and {
            return Ok(Variant::Bool(decided));
        }
        let right = self.evaluate(right_node)?.truth()?;
        Ok(Variant::Bool(right))
    }

    /// 0x91f8b5e8: strings compare by signed bytes, addresses of one type
    /// by unsigned bytes, integers as unsigned 64-bit when either is
    /// unsigned and signed otherwise.
    fn compare(&self, left: Variant, op: u8, right: Variant) -> Result<Variant> {
        let byte_order = |a: &[u8], b: &[u8]| -> i32 {
            a.iter()
                .zip(b)
                .map(|(&x, &y)| i32::from(x) - i32::from(y))
                .find(|&difference| difference != 0)
                .unwrap_or(0)
        };
        let order = match (left, right) {
            (Variant::Str(a), Variant::Str(b)) => {
                compare_text(self.text(a), self.text(b), false, false)
            }
            (Variant::Mac(a), Variant::Mac(b)) => byte_order(&a, &b),
            (Variant::Ipv4(a), Variant::Ipv4(b)) => byte_order(&a, &b),
            (Variant::Ipv6(a), Variant::Ipv6(b)) => byte_order(&a, &b),
            (
                Variant::Mac(_) | Variant::Ipv4(_) | Variant::Ipv6(_),
                Variant::Mac(_) | Variant::Ipv4(_) | Variant::Ipv6(_),
            ) => {
                return Err(EvaluationFailed);
            }
            _ => {
                let unsigned = left.is_unsigned() || right.is_unsigned();
                let (a, _) = left.integer()?;
                let (b, _) = right.integer()?;
                let ordering = if unsigned {
                    a.cmp(&b)
                } else {
                    (a as i64).cmp(&(b as i64))
                };
                ordering as i32
            }
        };
        Ok(Variant::Bool(match op {
            0 => order < 0,
            1 => order > 0,
            2 => order <= 0,
            3 => order >= 0,
            4 => order == 0,
            _ => order != 0,
        }))
    }

    /// The string functions; every failure is an evaluation error.
    fn string_function(&self, function: u8, arguments: &[Variant]) -> Result<Variant> {
        let Variant::Str(haystack) = arguments[0] else {
            return Err(EvaluationFailed);
        };
        let text = self.text(haystack);
        let fold = |value: Option<&Variant>| -> Result<bool> {
            value.map_or(Ok(false), |value| value.truth())
        };
        let other = |value: Variant| -> Result<&[u8]> {
            match value {
                Variant::Str(other) => Ok(self.text(other)),
                _ => Err(EvaluationFailed),
            }
        };
        match function {
            // String.Compare(a, b[, ignorecase]) (0x91f8a938).
            0x1f => {
                let other = other(arguments[1])?;
                Ok(Variant::I32(compare_text(
                    text,
                    other,
                    fold(arguments.get(2))?,
                    false,
                )))
            }
            // String.IndexOf(s, t[, start][, count][, ignorecase]) and
            // String.Contains(s, t[, ignorecase]) (0x91f8a9f0). A boolean
            // in the last position is the case flag.
            0x20 | 0x21 => {
                let needle = other(arguments[1])?;
                let is_bool = |index: usize| matches!(arguments.get(index), Some(Variant::Bool(_)));
                let (start, count, case) = match (function, arguments.len()) {
                    (0x21, _) => (None, None, arguments.get(2)),
                    (_, 3) if is_bool(2) => (None, None, arguments.get(2)),
                    (_, 3) => (arguments.get(2), None, None),
                    (_, 4) if is_bool(3) => (arguments.get(2), None, arguments.get(3)),
                    (_, 4) => (arguments.get(2), arguments.get(3), None),
                    (_, 5) => (arguments.get(2), arguments.get(3), arguments.get(4)),
                    _ => (None, None, None),
                };
                let begin = match start {
                    Some(&start) => {
                        let start = int32(start)?;
                        if start < 0 || start as usize >= text.len() {
                            return Err(EvaluationFailed);
                        }
                        start as usize
                    }
                    None => 0,
                };
                let end = match count {
                    Some(&count) => {
                        let count = int32(count)?;
                        if count <= 0 || begin + count as usize > text.len() {
                            return Err(EvaluationFailed);
                        }
                        begin + count as usize
                    }
                    None => text.len(),
                };
                let found = search(&text[begin..end], needle, fold(case)?);
                Ok(match function {
                    0x21 => Variant::Bool(found >= 0),
                    _ if found < 0 => Variant::I32(found),
                    _ => Variant::I32(found + begin as i32),
                })
            }
            // String.StartsWith and String.EndsWith (0x91f8abb0, 0x91f8ac90).
            0x22 | 0x23 => {
                let affix = other(arguments[1])?;
                let fold = fold(arguments.get(2))?;
                if text.is_empty() || affix.is_empty() || text.len() < affix.len() {
                    return Ok(Variant::Bool(false));
                }
                Ok(Variant::Bool(if function == 0x22 {
                    compare_text(text, affix, fold, true) == 0
                } else {
                    compare_text(&text[text.len() - affix.len()..], affix, fold, false) == 0
                }))
            }
            // String.Substring(s, start[, length]) (0x91f8b0b0).
            _ => {
                let start = int32(arguments[1])?;
                if start < 0 || start as usize > text.len() {
                    return Err(EvaluationFailed);
                }
                let begin = start as usize;
                let end = match arguments.get(2) {
                    Some(&length) => {
                        let length = int32(length)?;
                        if length < 0 || begin + length as usize > text.len() {
                            return Err(EvaluationFailed);
                        }
                        begin + length as usize
                    }
                    None => text.len(),
                };
                let offset = haystack.start;
                Ok(Variant::Str(Text {
                    base: haystack.base,
                    start: offset + begin as u16,
                    end: offset + end as u16,
                }))
            }
        }
    }

    fn item(&mut self, index: usize) -> Result<Variant> {
        if let Some(value) = self.items[index] {
            return Ok(value);
        }
        let item = self.program.items()[index];
        let value = match Variant::from_value(item.value) {
            Variant::Null => self.read_field(usize::from(item.field.0) - 1)?,
            declared => declared,
        };
        self.items[index] = Some(value);
        Ok(value)
    }

    /// Read a field from the frame, or its default when the frame lacks
    /// the protocol.
    fn read_field(&mut self, index: usize) -> Result<Variant> {
        let field = FIELDS[index];
        let flags = self.parsed.flags;
        let present = if field.mask & XSP_MASK == 0 || field.mask == XSP_MASK {
            flags & field.mask != 0
        } else {
            flags & XSP_MASK == field.mask
        };
        if !present {
            return Ok(match field.kind {
                Kind::Bool => Variant::Bool(false),
                Kind::U8 => Variant::U8(0),
                Kind::U16 => Variant::U16(0),
                Kind::U32 => Variant::U32(0),
                Kind::Mac => Variant::Mac([0; 6]),
                Kind::Ipv4 => Variant::Ipv4([0; 4]),
                Kind::Str => Variant::Str(Text {
                    base: Base::Name,
                    start: 0,
                    end: 0,
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
            Getter::Frame(offset, size) => number(
                &bytes_at(self.frame, usize::from(offset), usize::from(size)),
                field.kind,
            ),
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
            Getter::DnsFlags(mask, shift) => {
                let word = self.dns().map_or(0, |dns| {
                    u16::from_be_bytes(
                        bytes_at(self.frame, dns + 2, 2)[..2]
                            .try_into()
                            .unwrap_or([0; 2]),
                    )
                });
                let value = word & mask;
                if field.kind == Kind::Bool {
                    Variant::Bool(value != 0)
                } else {
                    Variant::U16(value >> shift)
                }
            }
            Getter::DnsCount(offset) => {
                let value = self.dns().map_or([0; 8], |dns| {
                    bytes_at(self.frame, dns + usize::from(offset), 2)
                });
                Variant::U16(u16::from_be_bytes([value[0], value[1]]))
            }
            Getter::DnsName => {
                self.decode_name();
                Variant::Str(Text {
                    base: Base::Name,
                    start: 0,
                    end: u16::MAX,
                })
            }
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
    /// by dots; a failed or root name reads as empty.
    fn decode_name(&mut self) {
        if self.name_len.is_some() {
            return;
        }
        let length = self.dns().and_then(|dns| {
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
            decode_question(area, area_len, &mut self.name)
        });
        self.name_len = Some(length.unwrap_or(0) as u16);
    }
}

/// Decode a question name into `output`; returns its length without the
/// trailing dot.
fn decode_question(
    area: &[u8],
    declared: usize,
    output: &mut [u8; NAME_CAPACITY],
) -> Option<usize> {
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
        if written + label + 1 <= NAME_CAPACITY {
            output[written..written + label].copy_from_slice(&area[position..end]);
            output[written + label] = b'.';
        }
        written += label + 1;
        position = end;
        if written > NAME_CAPACITY {
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

/// 0x91f898e0 over plain strings: signed byte order, ASCII case folding,
/// and in prefix mode a match once `right` is used up.
fn compare_text(left: &[u8], right: &[u8], fold: bool, prefix: bool) -> i32 {
    let map = |byte: u8| -> i8 {
        (if fold {
            byte.to_ascii_lowercase()
        } else {
            byte
        }) as i8
    };
    for (index, &byte) in left.iter().enumerate() {
        let Some(&other) = right.get(index) else {
            return if prefix { 0 } else { 1 };
        };
        match map(byte).cmp(&map(other)) {
            core::cmp::Ordering::Less => return -1,
            core::cmp::Ordering::Greater => return 1,
            core::cmp::Ordering::Equal => {}
        }
    }
    if left.len() == right.len() { 0 } else { -1 }
}

/// 0x91f89a00: the first position where `needle` matches.
fn search(haystack: &[u8], needle: &[u8], fold: bool) -> i32 {
    if haystack.is_empty() || needle.is_empty() {
        return -1;
    }
    for start in 0..haystack.len() {
        if compare_text(&haystack[start..], needle, fold, true) == 0 {
            return start as i32;
        }
    }
    -1
}

/// 0x91f8a7b8: bitwise complement keeps the type; booleans become `i32`.
fn complement(value: Variant) -> Result<Variant> {
    Ok(match value {
        Variant::Bool(value) => Variant::I32(!i32::from(value)),
        Variant::I8(value) => Variant::I8(!value),
        Variant::I16(value) => Variant::I16(!value),
        Variant::I32(value) => Variant::I32(!value),
        Variant::I64(value) => Variant::I64(!value),
        Variant::U8(value) => Variant::U8(!value),
        Variant::U16(value) => Variant::U16(!value),
        Variant::U32(value) => Variant::U32(!value),
        Variant::U64(value) => Variant::U64(!value),
        _ => return Err(EvaluationFailed),
    })
}

/// 0x91f8b1c0: 64-bit arithmetic, unsigned when either operand is
/// unsigned; the result takes the type stock picks from the operand types.
fn arithmetic(left: Variant, op: u8, right: Variant) -> Result<Variant> {
    let unsigned = left.is_unsigned() || right.is_unsigned();
    let (a, _) = left.integer()?;
    let (b, _) = right.integer()?;
    let value = if unsigned {
        match op {
            0 => a.wrapping_add(b),
            1 => a.wrapping_sub(b),
            2 => a.wrapping_mul(b),
            3 => a.checked_div(b).ok_or(EvaluationFailed)?,
            4 => a.checked_rem(b).ok_or(EvaluationFailed)?,
            5 => {
                if b & 0x40 != 0 {
                    0
                } else {
                    a << (b & 0x3f)
                }
            }
            6 => {
                if b & 0x40 != 0 {
                    0
                } else {
                    a >> (b & 0x3f)
                }
            }
            7 => a & b,
            8 => a ^ b,
            _ => a | b,
        }
    } else {
        let (a, b) = (a as i64, b as i64);
        (match op {
            0 => a.wrapping_add(b),
            1 => a.wrapping_sub(b),
            2 => a.wrapping_mul(b),
            // Stock traps on i64::MIN / -1.
            3 => {
                if b == 0 || (a == i64::MIN && b == -1) {
                    return Err(EvaluationFailed);
                } else {
                    a / b
                }
            }
            4 => {
                if b == 0 || (a == i64::MIN && b == -1) {
                    return Err(EvaluationFailed);
                } else {
                    a % b
                }
            }
            5 => {
                if b < 0 {
                    return Err(EvaluationFailed);
                }
                if b & 0x40 != 0 { 0 } else { a << (b & 0x3f) }
            }
            6 => {
                if b < 0 {
                    return Err(EvaluationFailed);
                }
                if b & 0x40 != 0 {
                    a >> 63
                } else {
                    a >> (b & 0x3f)
                }
            }
            7 => a & b,
            8 => a ^ b,
            _ => a | b,
        }) as u64
    };
    let kinds = [left, right];
    let any = |test: fn(Variant) -> bool| kinds.iter().any(|&value| test(value));
    Ok(if unsigned {
        if any(|value| matches!(value, Variant::U64(_))) {
            Variant::U64(value)
        } else if any(|value| matches!(value, Variant::Bool(_) | Variant::U32(_))) {
            Variant::U32(value as u32)
        } else if any(|value| matches!(value, Variant::U16(_))) {
            Variant::U16(value as u16)
        } else if any(|value| matches!(value, Variant::U8(_))) {
            Variant::U8(value as u8)
        } else {
            Variant::U32(value as u32)
        }
    } else if any(|value| matches!(value, Variant::I64(_))) {
        Variant::I64(value as i64)
    } else if any(|value| matches!(value, Variant::Bool(_) | Variant::I32(_))) {
        Variant::I32(value as i32)
    } else if any(|value| matches!(value, Variant::I16(_))) {
        Variant::I16(value as i16)
    } else if any(|value| matches!(value, Variant::I8(_))) {
        Variant::I8(value as i8)
    } else {
        Variant::I32(value as i32)
    })
}
