//! Frame classifier programs: the bytes that follow a queue or redirect
//! blob (stock classifier library 0x91f84708..0x91f8b0b0, built by
//! 0x91f8bb08 with limits 0x80/0x20/0/0x40 and feature set 0xdd).
//!
//! A program declares items (frame fields, by index into the field table)
//! and an expression in postfix order over constants, item references,
//! names, and operators. The library keeps the parsed program and
//! re-serializes it in canonical form for `getq` and the settings file.

mod compile;
mod grammar;
mod variant;

pub use self::compile::Compiled;
pub use self::compile::compile_text;

/// Items a program may declare: the library allows 0x20 item objects and
/// the stored copy takes one per item.
pub const ITEM_LIMIT: usize = 0x10;
/// Expression nodes a program may hold (0x40 node objects, two per node).
pub const NODE_LIMIT: usize = 0x20;
/// Fields of the frame field table (0x91f0ca48).
pub const FIELD_COUNT: u8 = 0x55;
/// Bytes the program text of one blob can hold.
const TEXT_CAPACITY: usize = 0xdc;
/// Distinct strings while parsing: every reference takes at least two bytes
/// of the blob.
const STRING_LIMIT: usize = TEXT_CAPACITY / 2;
/// Parse-time limits: declared items, operators.
const PARSE_ITEM_LIMIT: u32 = 0x20;
const PARSE_NODE_LIMIT: u32 = 0x40;
/// Names must be shorter than this (the library's first limit, 0x80).
const NAME_LIMIT: usize = 0x80;

/// Why a program is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramError {
    /// Malformed or not allowed (0x82da0017).
    Invalid,
    /// The stored copy exceeds the item or node objects (0x82da001c).
    OutOfMemory,
}

/// Why a program cannot be serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializeError {
    /// The output does not fit (0x8007007a).
    TooLarge,
    /// An item holds a string, which the item encoder rejects
    /// (0x80070545).
    Unencodable,
}

/// Index of a field in the frame field table, 1..=0x55.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldId(pub u8);

/// Index of a distinct string of a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StringId(pub u8);

/// A typed value (stock variant types 0..9, 0xf, 0x10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Value {
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
    /// A MAC address (variant type 0xc).
    Mac([u8; 6]),
    /// An IPv4 address (variant type 0xd).
    Ipv4([u8; 4]),
    /// An IPv6 address (variant type 0xe).
    Ipv6([u8; 16]),
    /// Variant type 0xf, which carries no bytes.
    Opaque,
    Str(StringId),
}

impl Value {
    /// Wire type byte (0x91f89e18).
    fn wire_type(self) -> u8 {
        match self {
            Value::Null => 1,
            Value::Bool(false) => 2,
            Value::Bool(true) => 3,
            Value::I8(_) => 4,
            Value::I16(_) => 5,
            Value::I32(_) => 6,
            Value::I64(_) => 7,
            Value::U8(_) => 8,
            Value::U16(_) => 9,
            Value::U32(_) => 0xa,
            Value::U64(_) => 0xb,
            Value::Mac(_) => 0xe,
            Value::Ipv4(_) => 0xf,
            Value::Ipv6(_) => 0x10,
            Value::Opaque => 0x11,
            Value::Str(_) => 0x12,
        }
    }
}

/// A declared frame field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Item {
    pub field: FieldId,
    /// Initial value; its type is the declared type.
    pub value: Value,
    /// Item flag 4: the value is not replaced once set.
    pub fixed: bool,
    /// Item flag 2 value; 0xffffffffffffffff reads as absent.
    pub tag: Option<u64>,
}

/// Operator numbers (op byte - 0x20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Operator(pub u8);

impl Operator {
    /// `name[index]`: an element of an array item.
    pub const INDEX: Self = Self(3);
    pub const NEGATE: Self = Self(6);
    pub const NOT: Self = Self(8);
    pub const COMPLEMENT: Self = Self(9);
    pub const CONDITIONAL: Self = Self(0x1c);
    pub const STRING_LENGTH: Self = Self(0x1e);

    /// Operators written with an operand count.
    fn has_count(self) -> bool {
        matches!(self.0, 4 | 5 | 0x1f..=0x24)
    }

    /// Operand count range of the string functions (0x91f0c158).
    fn count_range(self) -> Option<(u32, u32)> {
        match self.0 {
            0x1e => Some((1, 1)),
            0x1f | 0x21..=0x24 => Some((2, 3)),
            0x20 => Some((2, 5)),
            _ => None,
        }
    }
}

/// An expression node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Node {
    Constant(Value),
    /// A reference by name (op 0x21).
    Name(StringId),
    /// A reference to an item (op 0x22).
    Item(u8),
    Operator {
        operator: Operator,
        operands: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
struct Span {
    start: u8,
    len: u8,
}

/// A parsed program.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Program {
    items: [Item; ITEM_LIMIT],
    item_count: u8,
    /// Postfix order.
    nodes: [Node; NODE_LIMIT],
    node_count: u8,
    /// Distinct strings in first-registration order.
    strings: [Span; STRING_LIMIT],
    string_count: u8,
    text: [u8; TEXT_CAPACITY],
    text_len: u8,
}

impl core::fmt::Debug for Program {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Program")
            .field("items", &self.items())
            .field("nodes", &self.nodes())
            .field("strings", &self.string_count)
            .finish()
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    little_endian: bool,
}

impl<'a> Input<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ProgramError> {
        if self.bytes.len() < count {
            return Err(ProgramError::Invalid);
        }
        let (head, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }

    /// An unsigned number of `width` bytes in the program's byte order
    /// (0x91f8a498 wire types 8..0xb).
    fn unsigned(&mut self, width: usize) -> Result<u64, ProgramError> {
        let bytes = self.take(width)?;
        let mut value = 0u64;
        for index in 0..width {
            let byte = if self.little_endian {
                bytes[width - 1 - index]
            } else {
                bytes[index]
            };
            value = (value << 8) | u64::from(byte);
        }
        Ok(value)
    }

    /// Big-endian header number; the header ignores the byte order flag.
    fn header(&mut self, width: usize) -> Result<u32, ProgramError> {
        let bytes = self.take(width)?;
        Ok(bytes
            .iter()
            .fold(0u32, |value, &byte| (value << 8) | u32::from(byte)))
    }
}

/// Bytes of a count or offset by the largest value it must hold.
fn width_for(limit: u64) -> usize {
    if limit <= 0xff {
        1
    } else if limit <= 0xffff {
        2
    } else {
        4
    }
}

struct Strings<'a> {
    /// The string table of the blob.
    table: &'a [u8],
    /// Declared longest string; length prefixes use its width.
    longest: u32,
}

impl Program {
    fn new() -> Self {
        Self {
            items: [Item {
                field: FieldId(0),
                value: Value::Null,
                fixed: false,
                tag: None,
            }; ITEM_LIMIT],
            item_count: 0,
            nodes: [Node::Constant(Value::Null); NODE_LIMIT],
            node_count: 0,
            strings: [Span::default(); STRING_LIMIT],
            string_count: 0,
            text: [0; TEXT_CAPACITY],
            text_len: 0,
        }
    }

    pub fn items(&self) -> &[Item] {
        &self.items[..usize::from(self.item_count)]
    }

    pub fn nodes(&self) -> &[Node] {
        &self.nodes[..usize::from(self.node_count)]
    }

    pub fn string(&self, id: StringId) -> &[u8] {
        let span = self.strings[usize::from(id.0)];
        &self.text[usize::from(span.start)..usize::from(span.start) + usize::from(span.len)]
    }

    /// Register a string, reusing an equal one (0x91f84938).
    fn intern(&mut self, bytes: &[u8]) -> Result<StringId, ProgramError> {
        for index in 0..usize::from(self.string_count) {
            if self.string(StringId(index as u8)) == bytes {
                return Ok(StringId(index as u8));
            }
        }
        let start = usize::from(self.text_len);
        if usize::from(self.string_count) == STRING_LIMIT || start + bytes.len() > TEXT_CAPACITY {
            return Err(ProgramError::Invalid);
        }
        self.text[start..start + bytes.len()].copy_from_slice(bytes);
        self.text_len = (start + bytes.len()) as u8;
        self.strings[usize::from(self.string_count)] = Span {
            start: start as u8,
            len: bytes.len() as u8,
        };
        self.string_count += 1;
        Ok(StringId(self.string_count - 1))
    }

    /// A string reference: an offset into the table, then at the offset a
    /// length prefix and the bytes (0x91f84bd0, 0x91f89aa8). The length must
    /// stay below `limit`.
    fn read_string(
        &mut self,
        input: &mut Input<'_>,
        strings: &Strings<'_>,
        limit: usize,
    ) -> Result<StringId, ProgramError> {
        let table_len = strings.table.len();
        let offset = input.unsigned(width_for(table_len as u64))?;
        if offset >= table_len as u64 {
            return Err(ProgramError::Invalid);
        }
        let mut entry = Input {
            bytes: &strings.table[offset as usize..],
            little_endian: input.little_endian,
        };
        let length = entry.unsigned(width_for(u64::from(strings.longest)))?;
        if length > u64::from(strings.longest) || length > entry.bytes.len() as u64 {
            return Err(ProgramError::Invalid);
        }
        let length = length as usize;
        if length >= limit {
            return Err(ProgramError::Invalid);
        }
        let bytes = &entry.bytes[..length];
        self.intern(bytes)
    }

    /// A value of wire type `kind` (0x91f8a498) as the netsim feature set
    /// allows it: no floating point or 0x13 values. Addresses are copied
    /// as they are, whatever the byte order flag.
    fn read_value(
        &mut self,
        kind: u8,
        input: &mut Input<'_>,
        strings: &Strings<'_>,
    ) -> Result<Value, ProgramError> {
        Ok(match kind {
            1 => Value::Null,
            2 => Value::Bool(false),
            3 => Value::Bool(true),
            4 => Value::I8(input.unsigned(1)? as u8 as i8),
            5 => Value::I16(input.unsigned(2)? as u16 as i16),
            6 => Value::I32(input.unsigned(4)? as u32 as i32),
            7 => Value::I64(input.unsigned(8)? as i64),
            8 => Value::U8(input.unsigned(1)? as u8),
            9 => Value::U16(input.unsigned(2)? as u16),
            0xa => Value::U32(input.unsigned(4)? as u32),
            0xb => Value::U64(input.unsigned(8)?),
            0xe => Value::Mac(
                input
                    .take(6)?
                    .try_into()
                    .map_err(|_| ProgramError::Invalid)?,
            ),
            0xf => Value::Ipv4(
                input
                    .take(4)?
                    .try_into()
                    .map_err(|_| ProgramError::Invalid)?,
            ),
            0x10 => Value::Ipv6(
                input
                    .take(16)?
                    .try_into()
                    .map_err(|_| ProgramError::Invalid)?,
            ),
            0x11 => Value::Opaque,
            0x12 => Value::Str(self.read_string(input, strings, usize::MAX)?),
            _ => return Err(ProgramError::Invalid),
        })
    }

    /// Parse and check a program (0x91f87a48 with the checks of 0x91f8bb08
    /// and the stored copy of 0x91f871f8).
    pub fn parse(blob: &[u8]) -> Result<Program, ProgramError> {
        let mut program = Program::new();
        let mut input = Input {
            bytes: blob,
            little_endian: false,
        };
        let version = input.byte()?;
        let flags = input.byte()?;
        if version & 0xf0 != 0x10 || flags & 1 != 0 {
            return Err(ProgramError::Invalid);
        }
        input.little_endian = flags & 2 != 0;
        let (table_len, longest) = match flags & 0xc {
            0x4 => (input.header(1)?, input.header(1)?),
            0x8 => (input.header(2)?, input.header(2)?),
            0xc => (input.header(4)?, input.header(4)?),
            _ => (0, 0),
        };
        let (item_count, node_count) = match flags & 0x30 {
            0x10 => (input.header(1)?, input.header(1)?),
            0x20 => (input.header(1)?, input.header(2)?),
            0x30 => (input.header(2)?, input.header(2)?),
            _ => (0, input.header(1)?),
        };
        let table_len = table_len as usize;
        if table_len > input.bytes.len() || longest as usize > table_len {
            return Err(ProgramError::Invalid);
        }
        let table = input.take(table_len)?;
        let strings = Strings { table, longest };
        let rest = input.bytes.len() as u32;
        if item_count > rest
            || node_count > rest - item_count
            || item_count > PARSE_ITEM_LIMIT
            || node_count > PARSE_NODE_LIMIT
        {
            return Err(ProgramError::Invalid);
        }
        let mut items = [Item {
            field: FieldId(0),
            value: Value::Null,
            fixed: false,
            tag: None,
        }; PARSE_ITEM_LIMIT as usize];
        let mut parsed_items = 0usize;
        let mut nodes = [Node::Constant(Value::Null); PARSE_NODE_LIMIT as usize];

        for _ in 0..item_count {
            let kind = input.byte()?;
            let item_flags = input.byte()?;
            // Named items parse but are refused for netsim.
            if item_flags & 1 != 0 {
                return Err(ProgramError::Invalid);
            }
            let tag = if item_flags & 2 != 0 {
                Some(input.unsigned(8)?)
            } else {
                None
            };
            let field = match item_flags & 0x38 {
                0x08 => input.unsigned(1)?,
                0x10 => input.unsigned(2)?,
                0x18 => input.unsigned(4)?,
                0x20 => input.unsigned(8)?,
                _ => return Err(ProgramError::Invalid),
            };
            if field == 0 || field > u64::from(FIELD_COUNT) {
                return Err(ProgramError::Invalid);
            }
            let value = program.read_value(kind, &mut input, &strings)?;
            items[parsed_items] = Item {
                field: FieldId(field as u8),
                value,
                fixed: item_flags & 4 != 0,
                tag: tag.filter(|&tag| tag != u64::MAX),
            };
            parsed_items += 1;
        }

        // Operand stack of node indices.
        let mut stack = [0u8; PARSE_NODE_LIMIT as usize];
        let mut depth = 0usize;
        let mut parsed_nodes = 0usize;
        for _ in 0..node_count {
            let op = input.byte()?;
            let (node, operands) = match op {
                1..=0xb | 0xe..=0x10 | 0x12 => (
                    Node::Constant(program.read_value(op, &mut input, &strings)?),
                    0,
                ),
                0x21 => (
                    Node::Name(program.read_string(&mut input, &strings, NAME_LIMIT)?),
                    0,
                ),
                0x22 => {
                    let index = input.unsigned(width_for(u64::from(item_count)))?;
                    if index >= u64::from(item_count) {
                        return Err(ProgramError::Invalid);
                    }
                    (Node::Item(index as u8), 0)
                }
                0x23..=0x26 | 0x28..=0x3c | 0x3e..=0x44 => {
                    let operator = Operator(op - 0x20);
                    let operands = match operator.0 {
                        4 | 5 => return Err(ProgramError::Invalid),
                        3 => {
                            // The indexed operand must be a reference.
                            let first = depth
                                .checked_sub(2)
                                .map(|index| nodes[usize::from(stack[index])]);
                            if !matches!(first, Some(Node::Name(_) | Node::Item(_))) {
                                return Err(ProgramError::Invalid);
                            }
                            2
                        }
                        6 | 8 | 9 | 0x1e => 1,
                        0x1c => 3,
                        _ => match operator.count_range() {
                            Some((minimum, maximum)) => {
                                let maximum = maximum.min(node_count);
                                let count = input.unsigned(2)? as u32;
                                if count < minimum || count > maximum {
                                    return Err(ProgramError::Invalid);
                                }
                                count
                            }
                            None => 2,
                        },
                    };
                    (
                        Node::Operator {
                            operator,
                            operands: operands as u16,
                        },
                        operands as usize,
                    )
                }
                _ => return Err(ProgramError::Invalid),
            };
            if depth < operands {
                return Err(ProgramError::Invalid);
            }
            depth -= operands;
            nodes[parsed_nodes] = node;
            stack[depth] = parsed_nodes as u8;
            depth += 1;
            parsed_nodes += 1;
        }
        // An empty expression makes stock dereference a null node.
        if !input.bytes.is_empty() || depth != 1 {
            return Err(ProgramError::Invalid);
        }
        // A constant result is refused by 0x91f8bb08.
        if matches!(nodes[usize::from(stack[0])], Node::Constant(_)) {
            return Err(ProgramError::Invalid);
        }
        if parsed_items > ITEM_LIMIT || parsed_nodes > NODE_LIMIT {
            return Err(ProgramError::OutOfMemory);
        }
        program.items[..parsed_items].copy_from_slice(&items[..parsed_items]);
        program.item_count = parsed_items as u8;
        program.nodes[..parsed_nodes].copy_from_slice(&nodes[..parsed_nodes]);
        program.node_count = parsed_nodes as u8;
        Ok(program)
    }

    /// Canonical form (0x91f87318). Returns the byte count.
    pub fn serialize(&self, output: &mut [u8]) -> Result<usize, SerializeError> {
        write_program(self.items(), self.nodes(), self, output)
    }
}

/// The program a blob carries: parsed from a blob or compiled from text.
#[derive(Clone, Copy)]
pub enum Source<'a> {
    Parsed(&'a Program),
    Compiled(&'a Compiled<'a>),
}

impl Source<'_> {
    /// Canonical form (0x91f87318). Returns the byte count.
    pub fn serialize(self, output: &mut [u8]) -> Result<usize, SerializeError> {
        match self {
            Source::Parsed(program) => program.serialize(output),
            Source::Compiled(program) => program.serialize(output),
        }
    }
}

impl StringTable for Program {
    fn count(&self) -> usize {
        usize::from(self.string_count)
    }

    fn bytes(&self, id: StringId) -> &[u8] {
        self.string(id)
    }
}

/// Distinct strings of a program in registration order.
trait StringTable {
    fn count(&self) -> usize;
    fn bytes(&self, id: StringId) -> &[u8];
}

/// Write a program in stock's canonical form (0x91f87318): big-endian,
/// minimal widths, the distinct strings last registered first.
fn write_program(
    items: &[Item],
    nodes: &[Node],
    table: &dyn StringTable,
    output: &mut [u8],
) -> Result<usize, SerializeError> {
    let mut writer = Writer {
        output,
        len: 0,
        overflow: false,
    };
    let strings = table.count();
    let length = |index: usize| table.bytes(StringId(index as u8)).len() as u32;
    let longest = (0..strings).map(length).max().unwrap_or(0);
    let prefix = width_for(u64::from(longest));
    let table_len: u32 = (0..strings)
        .map(|index| length(index) + prefix as u32)
        .sum();
    let mut flags = 0u8;
    let mut header = [0u8; 8];
    let mut header_len = 0;
    if strings != 0 {
        let width = if table_len <= 0xff && longest <= 0xff {
            flags |= 4;
            1
        } else if table_len > 0xffff || longest > 0xffff {
            flags |= 0xc;
            4
        } else {
            flags |= 8;
            2
        };
        header[..width].copy_from_slice(&table_len.to_be_bytes()[4 - width..]);
        header[width..2 * width].copy_from_slice(&longest.to_be_bytes()[4 - width..]);
        header_len = 2 * width;
    }
    let mut counts = [0u8; 2];
    let counts_len = if !items.is_empty() {
        flags |= 0x10;
        counts[0] = items.len() as u8;
        counts[1] = nodes.len() as u8;
        2
    } else {
        counts[0] = nodes.len() as u8;
        1
    };
    writer.put(&[0x10, flags]);
    writer.put(&header[..header_len]);
    writer.put(&counts[..counts_len]);
    // Strings, most recently registered first.
    for index in (0..strings).rev() {
        writer.put(&length(index).to_be_bytes()[4 - prefix..]);
        writer.put(table.bytes(StringId(index as u8)));
    }
    let offset_width = width_for(u64::from(table_len));
    let offset_of = |id: StringId| -> u32 {
        (usize::from(id.0) + 1..strings)
            .map(|index| length(index) + prefix as u32)
            .sum()
    };
    let put_string = |writer: &mut Writer<'_>, id: StringId| {
        writer.put(&offset_of(id).to_be_bytes()[4 - offset_width..]);
    };
    for item in items {
        let mut item_flags = 8u8;
        if item.tag.is_some() {
            item_flags |= 2;
        }
        if item.fixed {
            item_flags |= 4;
        }
        writer.put(&[item.value.wire_type(), item_flags]);
        if let Some(tag) = item.tag {
            writer.put(&tag.to_be_bytes());
        }
        writer.put(&[item.field.0]);
        if matches!(item.value, Value::Str(_)) {
            return Err(SerializeError::Unencodable);
        }
        writer.value(item.value);
    }
    for node in nodes {
        match *node {
            Node::Constant(Value::Str(id)) => {
                writer.put(&[0x12]);
                put_string(&mut writer, id);
            }
            Node::Constant(value) => {
                writer.put(&[value.wire_type()]);
                writer.value(value);
            }
            Node::Name(id) => {
                writer.put(&[0x21]);
                put_string(&mut writer, id);
            }
            Node::Item(index) => writer.put(&[0x22, index]),
            Node::Operator { operator, operands } => {
                writer.put(&[operator.0 + 0x20]);
                if operator.has_count() {
                    writer.put(&operands.to_be_bytes());
                }
            }
        }
    }
    if writer.overflow {
        Err(SerializeError::TooLarge)
    } else {
        Ok(writer.len)
    }
}

struct Writer<'a> {
    output: &'a mut [u8],
    len: usize,
    overflow: bool,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        if self.overflow || self.len + bytes.len() > self.output.len() {
            self.overflow = true;
            return;
        }
        self.output[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    /// Value bytes after the type (0x91f89ee8).
    fn value(&mut self, value: Value) {
        match value {
            Value::Null | Value::Bool(_) | Value::Opaque | Value::Str(_) => {}
            Value::I8(value) => self.put(&value.to_be_bytes()),
            Value::I16(value) => self.put(&value.to_be_bytes()),
            Value::I32(value) => self.put(&value.to_be_bytes()),
            Value::I64(value) => self.put(&value.to_be_bytes()),
            Value::U8(value) => self.put(&[value]),
            Value::U16(value) => self.put(&value.to_be_bytes()),
            Value::U32(value) => self.put(&value.to_be_bytes()),
            Value::U64(value) => self.put(&value.to_be_bytes()),
            Value::Mac(bytes) => self.put(&bytes),
            Value::Ipv4(bytes) => self.put(&bytes),
            Value::Ipv6(bytes) => self.put(&bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(text: &str) -> ([u8; TEXT_CAPACITY], usize) {
        let mut output = [0u8; TEXT_CAPACITY];
        let text = text.as_bytes();
        let digit = |byte: u8| char::from(byte).to_digit(16).unwrap() as u8;
        for index in 0..text.len() / 2 {
            output[index] = (digit(text[2 * index]) << 4) | digit(text[2 * index + 1]);
        }
        (output, text.len() / 2)
    }

    fn parse(text: &str) -> Result<Program, ProgramError> {
        let (input, length) = bytes(text);
        Program::parse(&input[..length])
    }

    fn assert_canonical(input: &str, expected: &str) {
        let program = parse(input).unwrap();
        let mut output = [0u8; TEXT_CAPACITY];
        let length = program.serialize(&mut output).unwrap();
        let (expected, expected_length) = bytes(expected);
        assert_eq!(&output[..length], &expected[..expected_length]);
    }

    /// `count` nodes: null constants joined by additions, then nots.
    fn chain(constants: usize, nots: usize) -> ([u8; TEXT_CAPACITY], usize) {
        let mut output = [0u8; TEXT_CAPACITY];
        let nodes = 2 * constants - 1 + nots;
        output[..3].copy_from_slice(&[0x10, 0, nodes as u8]);
        let mut length = 3;
        output[length] = 1;
        length += 1;
        for _ in 1..constants {
            output[length..length + 2].copy_from_slice(&[0x01, 0x2d]);
            length += 2;
        }
        for _ in 0..nots {
            output[length] = 0x28;
            length += 1;
        }
        (output, length)
    }

    #[test]
    fn field_comparison_round_trips() {
        assert_eq!(
            parse("10100103090827000022000900353500").map(|_| ()),
            Err(ProgramError::Invalid)
        );
        let program = parse("101001030908270000220009003535").unwrap();
        assert_eq!(
            program.items(),
            &[Item {
                field: FieldId(0x27),
                value: Value::U16(0),
                fixed: false,
                tag: None
            }]
        );
        assert_eq!(
            program.nodes(),
            &[
                Node::Item(0),
                Node::Constant(Value::U16(0x35)),
                Node::Operator {
                    operator: Operator(0x15),
                    operands: 2
                }
            ]
        );
        assert_canonical(
            "101001030908270000220009003535",
            "101001030908270000220009003535",
        );
        // IPv4.SourceAddress == 10.0.0.1.
        assert_canonical(
            "1010010301080b22000f0a00000135",
            "1010010301080b22000f0a00000135",
        );
    }

    #[test]
    fn little_endian_programs_serialize_big_endian() {
        assert_canonical("13060403020361626312003e", "10040403020361626312003e");
        assert_canonical(
            "13120103090aff00000000000000273500220009350035",
            "10100103090a00000000000000ff270035220009003535",
        );
    }

    #[test]
    fn strings_are_deduplicated_and_unreferenced_bytes_dropped() {
        assert_canonical(
            "10040b03030361626302787903616263120012073f0002",
            "100404030303616263120012003f0002",
        );
    }

    #[test]
    fn rejections() {
        let rejected = |text: &str| parse(text).map(|_| ());
        // A constant result, a named item, field 0x56.
        assert_eq!(rejected("10000102"), Err(ProgramError::Invalid));
        assert_eq!(
            rejected("1014020101010161010900012200"),
            Err(ProgramError::Invalid)
        );
        assert_eq!(rejected("101001010108562200"), Err(ProgramError::Invalid));
        // A floating point literal, an opaque literal, and a function call.
        assert_eq!(rejected("1000020c3f8000003e"), Err(ProgramError::Invalid));
        assert_eq!(rejected("100002113e"), Err(ProgramError::Invalid));
        assert_eq!(rejected("100003010124"), Err(ProgramError::Invalid));
        // The flags low bit, a bad version, an empty expression.
        assert_eq!(rejected("110100"), Err(ProgramError::Invalid));
        assert_eq!(rejected("200000"), Err(ProgramError::Invalid));
        assert_eq!(rejected("100000"), Err(ProgramError::Invalid));
        // Assignment needs a reference as its first operand.
        assert_eq!(rejected("100003010123"), Err(ProgramError::Invalid));
    }

    #[test]
    fn stored_copy_limits() {
        let (input, length) = chain(16, 1);
        assert!(Program::parse(&input[..length]).is_ok());
        let (input, length) = chain(17, 0);
        assert_eq!(
            Program::parse(&input[..length]).map(|_| ()),
            Err(ProgramError::OutOfMemory)
        );
    }

    #[test]
    fn string_items_do_not_serialize() {
        let program = parse("101402010101017a120801002200").unwrap();
        let mut output = [0u8; TEXT_CAPACITY];
        assert_eq!(
            program.serialize(&mut output),
            Err(SerializeError::Unencodable)
        );
    }
}
