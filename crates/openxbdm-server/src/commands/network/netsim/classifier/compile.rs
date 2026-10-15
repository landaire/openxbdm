//! Classifier text compiler (stock 0x91f8bdd0): a yacc parser (0x91f86688)
//! over a hand-written lexer (0x91f85af0) whose rules call the operator
//! builder (0x91f88668). The builder folds constant operands, declares the
//! names it meets as items, and the compiler then binds every item to an
//! entry of the frame field table.
//!
//! The library runs with feature set 0xdd and compile flags 0x27, which fix
//! the lexer and builder options: names are declared as items, no float
//! literals, no backslash escapes, `//` and `/* */` comments, `[` indexing,
//! string literals, address literals, the built-in string functions and no
//! other functions.

use openxbdm_core::status::Hresult;

use super::FieldId;
use super::Item as WireItem;
use super::Node as WireNode;
use super::Operator;
use super::SerializeError;
use super::StringId;
use super::StringTable;
use super::Value;
use super::grammar;
use super::variant;
use super::variant::Text;
use super::variant::Variant;
use super::write_program;

/// Node objects (library limit 0x40); freed nodes are reused.
const NODE_LIMIT: usize = 0x40;
/// Items (library limit 0x20); items are never freed during a compile.
const ITEM_LIMIT: usize = 0x20;
/// Names must be shorter than this (library limit 0x80).
const NAME_LIMIT: usize = 0x80;
/// String references: one per node, one per item name, and the result of
/// a fold.
const REFERENCE_LIMIT: usize = NODE_LIMIT + ITEM_LIMIT + 1;
/// Parser state stack entries (YYSTACKSIZE).
const STACK_DEPTH: usize = 500;

const SYNTAX_ERROR: Hresult = Hresult(0x8007_0545);
const STACK_OVERFLOW: Hresult = Hresult(0x8007_03e9);
const OUT_OF_MEMORY: Hresult = Hresult(0x8007_000e);
const INVALID_CHARACTER: Hresult = Hresult(0x8007_000d);
const UNTERMINATED_COMMENT: Hresult = Hresult(0x8007_0026);
const TRUNCATED_NUMBER: Hresult = Hresult(0x8007_044c);
const NUMBER_OVERFLOW: Hresult = Hresult(0x8007_0216);
const SUFFIX_OVERFLOW: Hresult = Hresult(0x8007_00ea);
const MISSING_OPERAND: Hresult = Hresult(0x8007_10d2);
const EMPTY_NAME: Hresult = Hresult(0x8007_007b);
const NAME_TOO_LONG: Hresult = Hresult(0x8007_009a);
const TOO_MANY_ITEMS: Hresult = Hresult(0x8007_0044);
const NOT_SCALAR: Hresult = Hresult(0x8007_0099);
const WRONG_ITEM_KIND: Hresult = Hresult(0x8007_048a);
const NEGATIVE_INDEX: Hresult = Hresult(0x8007_0083);
const INDEX_OUT_OF_RANGE: Hresult = Hresult(0x8007_0585);
const TOO_FEW_ARGUMENTS: Hresult = Hresult(0x8002_0004);
const TOO_MANY_ARGUMENTS: Hresult = Hresult(0x8002_000e);
/// The program is a constant false: it would match nothing.
const ALWAYS_FALSE: Hresult = Hresult(0x82da_0010);
/// A name that is not in the field table.
const UNKNOWN_FIELD: Hresult = Hresult(0x82da_0025);

const IDENTIFIER: i16 = 0x101;
const CONSTANT: i16 = 0x102;

/// Operators of the builder that the grammar does not name directly.
const COMMA: Operator = Operator(0x1d);
const STRING_COMPARE: Operator = Operator(0x1f);
const STRING_INDEX_OF: Operator = Operator(0x20);
const STRING_CONTAINS: Operator = Operator(0x21);
const STRING_STARTS_WITH: Operator = Operator(0x22);
const STRING_ENDS_WITH: Operator = Operator(0x23);
const STRING_SUBSTRING: Operator = Operator(0x24);

/// Keywords and their bool values (0x91f0c120).
const KEYWORDS: [(&[u8], bool); 4] = [
    (b"TRUE", true),
    (b"FALSE", false),
    (b"true", true),
    (b"false", false),
];

/// Built-in functions (0x91f0c158); [`Operator::count_range`] holds their
/// operand counts.
const FUNCTIONS: [(&[u8], Operator); 7] = [
    (b"String.Length", Operator::STRING_LENGTH),
    (b"String.Compare", STRING_COMPARE),
    (b"String.IndexOf", STRING_INDEX_OF),
    (b"String.Contains", STRING_CONTAINS),
    (b"String.StartsWith", STRING_STARTS_WITH),
    (b"String.EndsWith", STRING_ENDS_WITH),
    (b"String.Substring", STRING_SUBSTRING),
];

/// Frame field names (0x91f99660); a field's id is its position plus one.
/// Only [`FIELD_NAMES`] and [`FIELD_ENDS`] are stored.
const FIELDS: [&[u8]; super::FIELD_COUNT as usize] = [
    b"Ethernet",
    b"Ethernet.SourceAddress",
    b"Ethernet.DestinationAddress",
    b"Ethernet.EthernetType",
    b"IPv4",
    b"IPv4.TotalLength",
    b"IPv4.Identification",
    b"IPv4.FragmentFlags",
    b"IPv4.TimeToLive",
    b"IPv4.NextProtocol",
    b"IPv4.SourceAddress",
    b"IPv4.DestinationAddress",
    b"ARP",
    b"ARP.OpCode",
    b"ARP.SendersMacAddress",
    b"ARP.SendersIp4Address",
    b"ARP.TargetMacAddress",
    b"ARP.TargetIp4Address",
    b"LLTD",
    b"ICMP",
    b"ICMP.Type",
    b"ICMP.Code",
    b"IGMP",
    b"TCP",
    b"TCP.SrcPort",
    b"TCP.DstPort",
    b"TCP.SequenceNumber",
    b"TCP.AcknowledgementNumber",
    b"TCP.Flags",
    b"TCP.Flags.Urgent",
    b"TCP.Flags.Ack",
    b"TCP.Flags.Push",
    b"TCP.Flags.Reset",
    b"TCP.Flags.Syn",
    b"TCP.Flags.Fin",
    b"TCP.Window",
    b"UDP",
    b"UDP.SourcePort",
    b"UDP.DestinationPort",
    b"DNS",
    b"DNS.Flags.QR",
    b"DNS.Flags.Opcode",
    b"DNS.Flags.AA",
    b"DNS.Flags.TC",
    b"DNS.Flags.RD",
    b"DNS.Flags.RA",
    b"DNS.Flags.AuthenticatedData",
    b"DNS.Flags.CheckingDisabled",
    b"DNS.Flags.Rcode",
    b"DNS.QuestionCount",
    b"DNS.AnswerCount",
    b"DNS.NameServerCount",
    b"DNS.AdditionalCount",
    b"DNS.QRecord.QuestionName",
    b"DHCP",
    b"DHCP.OpCode",
    b"DHCP.MessageType.Value",
    b"XSP",
    b"XSP.KeyEx.KeyExXbToXbInit",
    b"XSP.KeyEx.KeyExXbToXbResp",
    b"XSP.KeyEx.KeyExXbToSgInit",
    b"XSP.KeyEx.KeyExSgToXbResp",
    b"XSP.KeyEx.KeyExNatOpenInit",
    b"XSP.KeyEx.KeyExNatOpenResp",
    b"XSP.KeyEx.KeyExQosInit",
    b"XSP.KeyEx.KeyExQosResp",
    b"XSP.KeyEx.KeyExXbToLSPSGInit",
    b"XSP.KeyEx.KeyExLSPSGToXbResp",
    b"XSP.KeyEx.KeyExXbToXbInit2",
    b"XSP.KeyEx.KeyExXbToXbResp2",
    b"XSP.KeyEx.KeyExNatOpen2",
    b"XSP.KeyEx.QoSSetup",
    b"XSP.KeyEx.KeyExXbToXb3Init",
    b"XSP.KeyEx.KeyExXbToXbResp3",
    b"XSP.KeyEx.KeyExNatOpen3",
    b"XSP.KeyEx.KeyExQosInit2",
    b"Property.XSPSourcePort",
    b"Property.XSPDestPort",
    b"Property.XSPDatSize",
    b"Property.XSPTvoSize",
    b"XSPENC.SecMsg",
    b"XSPENC.TCPInfo",
    b"XSPENC.VoicePayload",
    b"XSPENC.VoiceOnlyPayload",
    b"Kerberosv5",
];

/// The field names back to back.
const FIELD_NAMES: [u8; field_names_length()] = pack_field_names();
/// End of each name in [`FIELD_NAMES`]; a name starts where the previous
/// one ends.
const FIELD_ENDS: [u16; super::FIELD_COUNT as usize] = field_name_ends();

const fn field_names_length() -> usize {
    let mut length = 0;
    let mut field = 0;
    while field < FIELDS.len() {
        length += FIELDS[field].len();
        field += 1;
    }
    length
}

const fn pack_field_names() -> [u8; field_names_length()] {
    let mut names = [0u8; field_names_length()];
    let mut position = 0;
    let mut field = 0;
    while field < FIELDS.len() {
        let mut byte = 0;
        while byte < FIELDS[field].len() {
            names[position] = FIELDS[field][byte];
            position += 1;
            byte += 1;
        }
        field += 1;
    }
    names
}

const fn field_name_ends() -> [u16; super::FIELD_COUNT as usize] {
    let mut ends = [0u16; super::FIELD_COUNT as usize];
    let mut end = 0;
    let mut field = 0;
    while field < FIELDS.len() {
        end += FIELDS[field].len();
        ends[field] = end as u16;
        field += 1;
    }
    ends
}

/// The id of the field named `name` (0x91f75370: ASCII case-insensitive).
fn field_id(name: &[u8]) -> Option<FieldId> {
    let mut start = 0;
    for (position, &end) in FIELD_ENDS.iter().enumerate() {
        let end = usize::from(end);
        if name.eq_ignore_ascii_case(&FIELD_NAMES[start..end]) {
            return Some(FieldId(position as u8 + 1));
        }
        start = end;
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NodeId(u8);

/// Position of an item in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ItemIndex(u8);

#[derive(Debug, Clone, Copy)]
enum Kind {
    Constant(Variant),
    /// An undeclared name; the builder turns names into items.
    Name(Text),
    Item(ItemIndex),
    /// Builder operator 3..=0x24 over its operand list.
    Operator {
        operator: Operator,
        operands: Option<NodeId>,
    },
}

#[derive(Debug, Clone, Copy)]
struct Node {
    kind: Kind,
    /// The next node of the operand stack, an operand list or the free list.
    next: Option<NodeId>,
}

#[derive(Debug, Clone, Copy)]
struct Item {
    /// Cleared once the item is bound to its field.
    name: Option<Text>,
    /// Element index of an array element; none for a scalar or an array.
    index: Option<u64>,
    /// Declared by `name[...]` (variant type 0xf).
    array: bool,
}

/// The owner of a string reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Holder {
    Node(NodeId),
    Item(ItemIndex),
    /// The result of a fold before it is copied into its node.
    Fold,
}

/// A string reference (stock string reference, 0x14 bytes).
#[derive(Debug, Clone, Copy)]
struct Reference {
    holder: Holder,
    text: Text,
}

/// The pending token of the lexer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    Identifier,
    Number,
}

struct Compiler<'a> {
    text: &'a [u8],
    cursor: usize,
    /// First syntax error, or the latest lexer or builder error.
    status: Option<Hresult>,
    nodes: [Node; NODE_LIMIT],
    allocated: u8,
    free: Option<NodeId>,
    /// Operand stack, most recent first.
    stack: Option<NodeId>,
    items: [Item; ITEM_LIMIT],
    item_count: u8,
    /// Stock keeps one entry per distinct string, newest first, each with
    /// its first reference and the later ones newest first. Here: entries
    /// oldest first, each as a run of equal strings `[first, newest, ...,
    /// oldest]`. The serializer writes the entries newest first.
    references: [Reference; REFERENCE_LIMIT],
    reference_count: u8,
}

/// A program compiled from text: what the stock compiler hands to the
/// serializer (0x91f87318).
pub struct Compiled<'a> {
    compiler: Compiler<'a>,
    root: NodeId,
    /// Field of each item.
    fields: [FieldId; ITEM_LIMIT],
}

/// Compile classifier text (0x91f8bdd0). `Ok(None)` is a constant true
/// program, which classifies every frame.
pub fn compile_text(text: &[u8]) -> Result<Option<Compiled<'_>>, Hresult> {
    let mut compiler = Compiler::new(text);
    compiler.parse();
    if let Some(error) = compiler.status {
        return Err(error);
    }
    // An accepted program leaves exactly its root on the stack.
    let root = compiler.stack.ok_or(SYNTAX_ERROR)?;
    if let Kind::Constant(value) = compiler.node(root).kind {
        return if variant::to_bool(&value)? {
            Ok(None)
        } else {
            Err(ALWAYS_FALSE)
        };
    }
    // Every item carries a name until it is bound (stock skips unnamed
    // items, which this compiler never declares).
    let mut fields = [FieldId(0); ITEM_LIMIT];
    for (position, bound) in fields
        .iter_mut()
        .enumerate()
        .take(usize::from(compiler.item_count))
    {
        let Some(name) = compiler.items[position].name.take() else {
            continue;
        };
        *bound = field_id(&text[name.start..name.end]).ok_or(UNKNOWN_FIELD)?;
        compiler.release(Holder::Item(ItemIndex(position as u8)));
    }
    Ok(Some(Compiled {
        compiler,
        root,
        fields,
    }))
}

impl Compiled<'_> {
    /// Canonical form (0x91f87318). Returns the byte count.
    pub fn serialize(&self, output: &mut [u8]) -> Result<usize, SerializeError> {
        let compiler = &self.compiler;
        let mut items = [WireItem {
            field: FieldId(0),
            value: Value::Null,
            fixed: false,
            tag: None,
        }; ITEM_LIMIT];
        let count = usize::from(compiler.item_count);
        for ((wire, item), &field) in items
            .iter_mut()
            .zip(&compiler.items[..count])
            .zip(&self.fields)
        {
            *wire = WireItem {
                field,
                value: if item.array {
                    Value::Opaque
                } else {
                    Value::Null
                },
                fixed: false,
                tag: item.index,
            };
        }
        let mut nodes = [WireNode::Constant(Value::Null); NODE_LIMIT];
        let mut count = 0;
        compiler.postfix(self.root, &mut nodes, &mut count);
        write_program(
            &items[..usize::from(compiler.item_count)],
            &nodes[..count],
            compiler,
            output,
        )
    }
}

impl StringTable for Compiler<'_> {
    fn count(&self) -> usize {
        (0..usize::from(self.reference_count))
            .filter(|&position| self.starts_entry(position))
            .count()
    }

    fn bytes(&self, id: StringId) -> &[u8] {
        let text = (0..usize::from(self.reference_count))
            .filter(|&position| self.starts_entry(position))
            .nth(usize::from(id.0))
            .map_or(Text { start: 0, end: 0 }, |position| {
                self.references[position].text
            });
        &self.text[text.start..text.end]
    }
}

impl<'a> Compiler<'a> {
    fn new(text: &'a [u8]) -> Self {
        Self {
            text,
            cursor: 0,
            status: None,
            nodes: [Node {
                kind: Kind::Constant(Variant::Null),
                next: None,
            }; NODE_LIMIT],
            allocated: 0,
            free: None,
            stack: None,
            items: [Item {
                name: None,
                index: None,
                array: false,
            }; ITEM_LIMIT],
            item_count: 0,
            references: [Reference {
                holder: Holder::Fold,
                text: Text { start: 0, end: 0 },
            }; REFERENCE_LIMIT],
            reference_count: 0,
        }
    }

    fn node(&self, id: NodeId) -> &Node {
        &self.nodes[usize::from(id.0)]
    }

    fn node_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.nodes[usize::from(id.0)]
    }

    fn next(&self, id: NodeId) -> Option<NodeId> {
        self.node(id).next
    }

    fn equal(&self, left: Text, right: Text) -> bool {
        variant::compare_text(self.text, left, right, false) == 0
    }

    /// Whether the reference at `position` is the first of its entry.
    fn starts_entry(&self, position: usize) -> bool {
        position == 0
            || !self.equal(
                self.references[position - 1].text,
                self.references[position].text,
            )
    }

    fn reference_position(&self, holder: Holder) -> Option<usize> {
        self.references[..usize::from(self.reference_count)]
            .iter()
            .position(|reference| reference.holder == holder)
    }

    /// Register a reference to a string (0x91f84938): a new entry, or the
    /// newest reference of the equal string's entry, taking its bytes.
    fn intern(&mut self, holder: Holder, text: Text) -> Text {
        let count = usize::from(self.reference_count);
        let (position, text) =
            match (0..count).find(|&position| self.equal(self.references[position].text, text)) {
                Some(first) => (first + 1, self.references[first].text),
                None => (count, text),
            };
        self.references.copy_within(position..count, position + 1);
        self.references[position] = Reference { holder, text };
        self.reference_count += 1;
        text
    }

    /// Drop a reference (0x91f849f8). The next reference of the entry takes
    /// over the entry and its position; the last one removes the entry.
    fn release(&mut self, holder: Holder) {
        let count = usize::from(self.reference_count);
        if let Some(position) = self.reference_position(holder) {
            self.references.copy_within(position + 1..count, position);
            self.reference_count -= 1;
        }
    }

    /// Whether the stock reference of `holder` has a null link: the first
    /// reference of the oldest entry, or the oldest later reference.
    fn link_is_null(&self, holder: Holder) -> bool {
        let Some(position) = self.reference_position(holder) else {
            return false;
        };
        if self.starts_entry(position) {
            return position == 0;
        }
        let next = position + 1;
        next == usize::from(self.reference_count) || self.starts_entry(next)
    }

    /// A node from the free list, or a new one below the limit (0x91f85108).
    fn allocate(&mut self, kind: Kind) -> Option<NodeId> {
        let id = match self.free {
            Some(id) => {
                self.free = self.next(id);
                id
            }
            None if usize::from(self.allocated) < NODE_LIMIT => {
                self.allocated += 1;
                NodeId(self.allocated - 1)
            }
            None => return None,
        };
        *self.node_mut(id) = Node { kind, next: None };
        Some(id)
    }

    /// Free a node list with every operand below it (0x91f85188).
    fn free_list(&mut self, mut list: Option<NodeId>) {
        while let Some(id) = list {
            let node = *self.node(id);
            list = node.next;
            match node.kind {
                Kind::Constant(Variant::Str(_)) | Kind::Name(_) => self.release(Holder::Node(id)),
                Kind::Constant(_) | Kind::Item(_) => {}
                Kind::Operator { operands, .. } => self.free_list(operands),
            }
            *self.node_mut(id) = Node {
                kind: Kind::Constant(Variant::Null),
                next: self.free,
            };
            self.free = Some(id);
        }
    }

    fn push(&mut self, id: NodeId) {
        let stack = self.stack;
        self.node_mut(id).next = stack;
        self.stack = Some(id);
    }

    fn pop(&mut self) -> Option<NodeId> {
        let id = self.stack?;
        self.stack = self.next(id);
        self.node_mut(id).next = None;
        Some(id)
    }

    /// Push a new lexer node; a failed allocation is a lexer error. The
    /// node is allocated before its string is registered.
    fn push_new(&mut self, kind: Kind) -> Result<(), Hresult> {
        let id = self.allocate(kind).ok_or(OUT_OF_MEMORY)?;
        let kind = match kind {
            Kind::Constant(Variant::Str(text)) => {
                Kind::Constant(Variant::Str(self.intern(Holder::Node(id), text)))
            }
            Kind::Name(text) => Kind::Name(self.intern(Holder::Node(id), text)),
            other => other,
        };
        self.node_mut(id).kind = kind;
        self.push(id);
        Ok(())
    }

    /// The yacc driver (0x91f86688). The value stack is omitted: the rules
    /// work on the operand stack only.
    fn parse(&mut self) {
        let mut states = [0u8; STACK_DEPTH];
        let mut top = 0usize;
        let mut state = 0u8;
        let mut lookahead: Option<i16> = None;
        let mut recovering = 0u8;
        let row = |base: i16, symbol: i16| -> Option<usize> {
            let index = base.checked_add(symbol)?;
            (base != 0
                && (0..=grammar::TABLE_LAST).contains(&index)
                && grammar::CHECK[index as usize] == grammar::check_symbol(symbol))
            .then_some(index as usize)
        };
        loop {
            let mut rule = grammar::DEFAULT_REDUCTION[usize::from(state)];
            if rule == 0 {
                let token = match lookahead {
                    Some(token) => token,
                    None => *lookahead.insert(self.lex()),
                };
                if let Some(index) = row(grammar::SHIFT_BASE[usize::from(state)], token) {
                    if top >= STACK_DEPTH - 1 {
                        return self.syntax_error(STACK_OVERFLOW);
                    }
                    state = grammar::TABLE[index];
                    top += 1;
                    states[top] = state;
                    lookahead = None;
                    recovering = recovering.saturating_sub(1);
                    continue;
                }
                if let Some(index) = row(grammar::REDUCE_BASE[usize::from(state)], token) {
                    rule = grammar::TABLE[index];
                } else {
                    if recovering == 0 {
                        self.syntax_error(SYNTAX_ERROR);
                    }
                    if recovering == 3 {
                        if token == 0 {
                            return;
                        }
                        lookahead = None;
                        continue;
                    }
                    recovering = 3;
                    loop {
                        if let Some(index) = row(
                            grammar::SHIFT_BASE[usize::from(states[top])],
                            grammar::ERROR_TOKEN,
                        ) {
                            if top >= STACK_DEPTH - 1 {
                                return self.syntax_error(STACK_OVERFLOW);
                            }
                            state = grammar::TABLE[index];
                            top += 1;
                            states[top] = state;
                            break;
                        }
                        if top == 0 {
                            return;
                        }
                        top -= 1;
                    }
                    continue;
                }
            }
            let rule = usize::from(rule);
            if let Some(action) = grammar::ACTION[rule] {
                self.emit(action.operator, action.operands);
            }
            top -= usize::from(grammar::LENGTH[rule]);
            state = states[top];
            let symbol = grammar::LHS[rule];
            if state == 0 && symbol == 0 {
                state = grammar::FINAL_STATE;
                top += 1;
                states[top] = state;
                let token = match lookahead {
                    Some(token) => token,
                    None => *lookahead.insert(self.lex()),
                };
                if token == 0 {
                    return;
                }
                continue;
            }
            let symbol = symbol as usize;
            state = match row(grammar::GOTO_BASE[symbol], i16::from(state)) {
                Some(index) => grammar::TABLE[index],
                None => grammar::GOTO_DEFAULT[symbol],
            };
            if top >= STACK_DEPTH - 1 {
                return self.syntax_error(STACK_OVERFLOW);
            }
            top += 1;
            states[top] = state;
        }
    }

    /// The parser's error report (0x91f89238): only the first error is kept.
    fn syntax_error(&mut self, code: Hresult) {
        if self.status.is_none() {
            self.status = Some(code);
            self.cursor = self.text.len();
        }
    }

    /// A rule action (0x91f89260): a builder error replaces the status.
    fn emit(&mut self, operator: Operator, arity: u8) {
        if let Err(code) = self.apply(operator, arity) {
            self.status = Some(code);
            self.cursor = self.text.len();
        }
    }

    /// The next token (0x91f85af0); 0 at the end or after an error.
    fn lex(&mut self) -> i16 {
        match self.scan() {
            Ok((token, cursor)) => {
                self.cursor = cursor;
                token
            }
            Err(code) => {
                self.status = Some(code);
                self.cursor = self.text.len();
                0
            }
        }
    }

    fn scan(&mut self) -> Result<(i16, usize), Hresult> {
        let text = self.text;
        let end = text.len();
        let at = |position: usize| (position < end).then(|| text[position]);
        let mut p = self.cursor;
        let mut pending: Option<Pending> = None;
        let mut start = p;
        let mut base = 10u64;
        let mut value = 0u64;
        let mut suffix: Option<usize> = None;
        while p < end {
            let c = text[p];
            let simple = match c {
                b'(' => Some(0x10a),
                b')' => Some(0x10b),
                b'[' => Some(0x104),
                b']' => Some(0x105),
                b'~' => Some(0x112),
                b'+' => Some(0x10d),
                b'-' => Some(0x109),
                b'*' => Some(0x103),
                b'%' => Some(0x10c),
                b'^' => Some(0x114),
                b'?' => Some(0x10e),
                b',' => Some(0x107),
                _ => None,
            };
            if let Some(token) = simple {
                if pending.is_some() {
                    break;
                }
                return Ok((token, p + 1));
            }
            match c {
                b'<' | b'>' | b'=' | b'|' | b'&' | b'!' | b':' | b'/' | b'"' | b' ' | b'\t'
                | b'\r' | b'\n'
                    if pending.is_some() =>
                {
                    break;
                }
                b'<' => {
                    return Ok(match at(p + 1) {
                        Some(b'<') => (0x110, p + 2),
                        Some(b'=') => (0x117, p + 2),
                        _ => (0x116, p + 1),
                    });
                }
                b'>' => {
                    return Ok(match at(p + 1) {
                        Some(b'>') => (0x111, p + 2),
                        Some(b'=') => (0x119, p + 2),
                        _ => (0x118, p + 1),
                    });
                }
                b'=' => {
                    return match at(p + 1) {
                        Some(b'=') => Ok((0x11a, p + 2)),
                        _ => Err(INVALID_CHARACTER),
                    };
                }
                b'|' => {
                    return Ok(if at(p + 1) == Some(b'|') {
                        (0x11d, p + 2)
                    } else {
                        (0x115, p + 1)
                    });
                }
                b'&' => {
                    return Ok(if at(p + 1) == Some(b'&') {
                        (0x11c, p + 2)
                    } else {
                        (0x113, p + 1)
                    });
                }
                b'!' => {
                    return Ok(if at(p + 1) == Some(b'=') {
                        (0x11b, p + 2)
                    } else {
                        (0x108, p + 1)
                    });
                }
                b':' => return Ok((0x106, p + 1)),
                b'/' => match at(p + 1) {
                    Some(b'/') => {
                        p += 2;
                        while p < end && !matches!(text[p], b'\r' | b'\n') {
                            p += 1;
                        }
                        if p < end {
                            p += 1;
                        }
                    }
                    Some(b'*') => {
                        let mut q = p + 2;
                        loop {
                            if q >= end {
                                return Err(UNTERMINATED_COMMENT);
                            }
                            if text[q] == b'*' && at(q + 1) == Some(b'/') {
                                break;
                            }
                            q += 1;
                        }
                        p = q + 2;
                    }
                    _ => return Ok((0x10f, p + 1)),
                },
                b'"' => {
                    let open = p;
                    loop {
                        p += 1;
                        if p >= end {
                            return Err(INVALID_CHARACTER);
                        }
                        if text[p] == b'"' {
                            break;
                        }
                    }
                    p += 1;
                    self.push_new(Kind::Constant(Variant::Str(Text {
                        start: open + 1,
                        end: p - 1,
                    })))?;
                    return Ok((CONSTANT, p));
                }
                0 | b'\\' | b'\'' => return Err(INVALID_CHARACTER),
                b' ' | b'\t' | b'\r' | b'\n' => p += 1,
                _ => {
                    if pending.is_none() {
                        if let Some((address, cursor)) = address_literal(&text[p..]) {
                            self.push_new(Kind::Constant(address))?;
                            return Ok((CONSTANT, p + cursor));
                        }
                        pending = Some(match c {
                            b'0' if at(p + 1) == Some(b'x') => {
                                p += 2;
                                if p >= end {
                                    return Err(TRUNCATED_NUMBER);
                                }
                                base = 16;
                                Pending::Number
                            }
                            b'0'..=b'9' => Pending::Number,
                            b'.' => match at(p + 1) {
                                None => return Err(TRUNCATED_NUMBER),
                                Some(b'0'..=b'9') => Pending::Number,
                                Some(_) => return Err(INVALID_CHARACTER),
                            },
                            _ => Pending::Identifier,
                        });
                        start = p;
                    }
                    if pending == Some(Pending::Number) {
                        let c = text[p];
                        let digit = match c {
                            b'0'..=b'9' => Some(c - b'0'),
                            b'a'..=b'f' if base == 16 => Some(c - b'a' + 10),
                            b'A'..=b'F' if base == 16 => Some(c - b'A' + 10),
                            _ => None,
                        };
                        match (c, digit) {
                            (_, Some(_)) | (b'a'..=b'f' | b'A'..=b'F', None)
                                if suffix.is_some() =>
                            {
                                return Err(INVALID_CHARACTER);
                            }
                            (_, Some(digit)) => {
                                let product = value.wrapping_mul(base);
                                if value > product {
                                    return Err(NUMBER_OVERFLOW);
                                }
                                value = product.wrapping_add(u64::from(digit));
                            }
                            // `f` and `.` start a float literal, which netsim disables.
                            (b'f' | b'F' | b'.', None) => return Err(SYNTAX_ERROR),
                            (b'l' | b'L', None) => {
                                if !valid_long_suffix(text, suffix, p) {
                                    return Err(INVALID_CHARACTER);
                                }
                                suffix.get_or_insert(p);
                            }
                            (b'u' | b'U', None) if suffix.is_none() => suffix = Some(p),
                            _ => return Err(INVALID_CHARACTER),
                        }
                    }
                    p += 1;
                }
            }
        }
        match pending {
            None => Ok((0, p)),
            Some(Pending::Identifier) => {
                let bytes = &text[start..p];
                if let Some(&(_, truth)) = KEYWORDS.iter().find(|(keyword, _)| *keyword == bytes) {
                    self.push_new(Kind::Constant(Variant::Bool(truth)))?;
                    return Ok((CONSTANT, p));
                }
                self.push_new(Kind::Name(Text { start, end: p }))?;
                Ok((IDENTIFIER, p))
            }
            Some(Pending::Number) => {
                let number = number_value(text, start, p, suffix, base, value)?;
                self.push_new(Kind::Constant(number))?;
                Ok((CONSTANT, p))
            }
        }
    }

    /// The operator builder (0x91f88668): pops `arity` operands, folds
    /// constant ones or pushes an operator node over them.
    fn apply(&mut self, operator: Operator, arity: u8) -> Result<(), Hresult> {
        let mut list = None;
        let mut constant = true;
        for _ in 0..arity {
            let Some(id) = self.pop() else {
                self.free_list(list);
                return Err(MISSING_OPERAND);
            };
            constant &= matches!(self.node(id).kind, Kind::Constant(_));
            self.node_mut(id).next = list;
            list = Some(id);
        }
        let Some(first) = list else {
            return Ok(());
        };
        match self.build(operator, first, constant) {
            Ok(()) => Ok(()),
            Err((code, remaining)) => {
                self.free_list(remaining);
                Err(code)
            }
        }
    }

    /// Build one operator over the operand list starting at `first`. On
    /// failure returns the list that is still owned, to be freed.
    fn build(
        &mut self,
        operator: Operator,
        first: NodeId,
        constant: bool,
    ) -> Result<(), (Hresult, Option<NodeId>)> {
        let fail = |code| (code, Some(first));
        let second = self.next(first);
        let value = |compiler: &Self, id: Option<NodeId>| match id.map(|id| compiler.node(id).kind)
        {
            Some(Kind::Constant(value)) => value,
            _ => Variant::Null,
        };
        let result = match operator.0 {
            // Rule 1 (a constant) and unary plus.
            0 | 7 => {
                self.keep(first, second);
                return Ok(());
            }
            1 => return self.declare(first).map_err(fail),
            3 => return self.index(first, second.ok_or(fail(MISSING_OPERAND))?),
            4 => return self.call(first),
            // A constant left operand decides `&&` and `||` when it is false
            // and true respectively; otherwise the operator stays.
            0x1a | 0x1b if !constant => {
                let Kind::Constant(left) = self.node(first).kind else {
                    return self.generic(operator, first);
                };
                let truth = variant::to_bool(&left).map_err(fail)?;
                if truth == (operator.0 == 0x1a) {
                    return self.generic(operator, first);
                }
                Variant::Bool(truth)
            }
            0x1c => return self.select(first),
            _ if !constant => return self.generic(operator, first),
            6 | 8 | 9 | 0xa..=0x1b => {
                let operands = [value(self, Some(first)), value(self, second)];
                variant::apply(self.text, operator, &operands).map_err(fail)?
            }
            // Operator 5 and the comma are never folded.
            _ => return self.generic(operator, first),
        };
        self.fold(first, result);
        Ok(())
    }

    /// The ternary operator: a constant condition selects its branch.
    fn select(&mut self, first: NodeId) -> Result<(), (Hresult, Option<NodeId>)> {
        let Kind::Constant(condition) = self.node(first).kind else {
            return self.generic(Operator::CONDITIONAL, first);
        };
        let truth = variant::to_bool(&condition).map_err(|code| (code, Some(first)))?;
        let (Some(then), Some(otherwise)) = (
            self.next(first),
            self.next(first).and_then(|then| self.next(then)),
        ) else {
            return Err((MISSING_OPERAND, Some(first)));
        };
        let (chosen, other) = if truth {
            (then, otherwise)
        } else {
            (otherwise, then)
        };
        self.node_mut(first).next = None;
        self.node_mut(then).next = None;
        self.keep(chosen, None);
        self.free_list(Some(first));
        self.free_list(Some(other));
        Ok(())
    }

    /// Push `first` back as the result and free the other operands.
    fn keep(&mut self, first: NodeId, rest: Option<NodeId>) {
        self.node_mut(first).next = None;
        self.push(first);
        self.free_list(rest);
    }

    /// Store a folded value in the first operand (0x91f891a8). A string
    /// result is registered before the operand's own string is dropped.
    fn fold(&mut self, first: NodeId, result: Variant) {
        let result = match result {
            Variant::Str(text) => Variant::Str(self.intern(Holder::Fold, text)),
            other => other,
        };
        if let Kind::Constant(Variant::Str(_)) = self.node(first).kind {
            self.release(Holder::Node(first));
        }
        let result = match result {
            Variant::Str(text) => {
                let text = self.intern(Holder::Node(first), text);
                self.release(Holder::Fold);
                Variant::Str(text)
            }
            other => other,
        };
        let rest = self.next(first);
        self.node_mut(first).kind = Kind::Constant(result);
        self.keep(first, rest);
    }

    /// An operator node over the whole operand list (0x91f89114).
    fn generic(
        &mut self,
        operator: Operator,
        first: NodeId,
    ) -> Result<(), (Hresult, Option<NodeId>)> {
        let id = self
            .allocate(Kind::Operator {
                operator,
                operands: Some(first),
            })
            .ok_or((OUT_OF_MEMORY, Some(first)))?;
        self.push(id);
        Ok(())
    }

    fn find_item(&self, name: Text, index: Option<u64>) -> Option<ItemIndex> {
        self.items[..usize::from(self.item_count)]
            .iter()
            .position(|item| {
                item.name.is_some_and(|own| self.equal(own, name)) && item.index == index
            })
            .map(|position| ItemIndex(position as u8))
    }

    /// Declare an item (0x91f84f88).
    fn create_item(&mut self, name: Text, index: Option<u64>) -> Result<ItemIndex, Hresult> {
        let length = name.end - name.start;
        if length == 0 {
            return Err(EMPTY_NAME);
        }
        if length >= NAME_LIMIT {
            return Err(NAME_TOO_LONG);
        }
        let position = usize::from(self.item_count);
        if position >= ITEM_LIMIT {
            return Err(TOO_MANY_ITEMS);
        }
        let name = self.intern(Holder::Item(ItemIndex(position as u8)), name);
        self.items[position] = Item {
            name: Some(name),
            index,
            array: false,
        };
        self.item_count += 1;
        Ok(ItemIndex(position as u8))
    }

    /// Rule 3: a name becomes a reference to its item, declared on first
    /// use (builder operator 1).
    fn declare(&mut self, first: NodeId) -> Result<(), Hresult> {
        // Rule 3 always pops the node its own identifier pushed.
        let Kind::Name(name) = self.node(first).kind else {
            self.keep(first, None);
            return Ok(());
        };
        let item = match self.find_item(name, None) {
            Some(item) if self.items[usize::from(item.0)].array => return Err(NOT_SCALAR),
            Some(item) => item,
            None => self.create_item(name, None)?,
        };
        self.release(Holder::Node(first));
        self.node_mut(first).kind = Kind::Item(item);
        self.keep(first, None);
        Ok(())
    }

    /// Rule 4, `name[index]` (builder operator 3): declares the array item
    /// and, for a constant index, the element item.
    fn index(&mut self, first: NodeId, second: NodeId) -> Result<(), (Hresult, Option<NodeId>)> {
        let fail = |code| (code, Some(first));
        let array = match self.node(first).kind {
            Kind::Name(name) => {
                let array = match self.find_item(name, None) {
                    Some(item) if !self.items[usize::from(item.0)].array => {
                        return Err(fail(WRONG_ITEM_KIND));
                    }
                    Some(item) => item,
                    None => {
                        let item = self.create_item(name, None).map_err(fail)?;
                        self.items[usize::from(item.0)].array = true;
                        item
                    }
                };
                self.release(Holder::Node(first));
                self.node_mut(first).kind = Kind::Item(array);
                array
            }
            // After an earlier builder error the operand can be another node.
            // Stock takes the leading word of its value as an item position.
            Kind::Constant(value) => match self.value_word(first, value) {
                Some(word)
                    if word < u32::from(self.item_count) && self.items[word as usize].array =>
                {
                    ItemIndex(word as u8)
                }
                _ => return Err(fail(WRONG_ITEM_KIND)),
            },
            // Item references never name an array. An operator's word is a
            // pointer, which stock dereferences as an item and faults.
            Kind::Item(_) | Kind::Operator { .. } => return Err(fail(WRONG_ITEM_KIND)),
        };
        let Kind::Constant(index) = self.node(second).kind else {
            return self.generic(Operator::INDEX, first);
        };
        let index = match index {
            Variant::I8(_) | Variant::I16(_) | Variant::I32(_) | Variant::I64(_) => {
                // Signed values always convert.
                let index = variant::to_i64(&index).unwrap_or(0);
                u64::try_from(index).map_err(|_| fail(NEGATIVE_INDEX))?
            }
            _ => variant::to_u64(&index).map_err(fail)?,
        };
        if index == u64::MAX {
            return Err(fail(INDEX_OUT_OF_RANGE));
        }
        let array_name = self.items[usize::from(array.0)]
            .name
            .ok_or(fail(WRONG_ITEM_KIND))?;
        let element = match self.find_item(array_name, Some(index)) {
            Some(item) => item,
            None => self.create_item(array_name, Some(index)).map_err(fail)?,
        };
        // Stock drops the operand's value as a string reference; for any
        // other constant it follows the value bytes as links and faults.
        if let Kind::Constant(Variant::Str(_)) = self.node(first).kind {
            self.release(Holder::Node(first));
        }
        self.node_mut(first).kind = Kind::Item(element);
        self.keep(first, Some(second));
        Ok(())
    }

    /// The leading word of a constant's stock value storage, where it is
    /// defined: a string reference's link (only a null link is a valid item
    /// position) or the first four bytes of a value stored with at least
    /// that size. Narrower integers leave stale bytes in the word.
    fn value_word(&self, id: NodeId, value: Variant) -> Option<u32> {
        let bytes = |bytes: &[u8]| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        match value {
            Variant::Str(_) => self.link_is_null(Holder::Node(id)).then_some(0),
            Variant::Bool(value) => Some(u32::from(value)),
            Variant::I32(value) => Some(value as u32),
            Variant::U32(value) => Some(value),
            Variant::I64(value) => Some((value as u64 >> 32) as u32),
            Variant::U64(value) => Some((value >> 32) as u32),
            Variant::Mac(value) => Some(bytes(&value)),
            Variant::Ipv4(value) => Some(bytes(&value)),
            Variant::Ipv6(value) => Some(bytes(&value)),
            Variant::Null | Variant::I8(_) | Variant::I16(_) | Variant::U8(_) | Variant::U16(_) => {
                None
            }
        }
    }

    /// Rules 5 and 6, `name(arguments)` (builder operator 4): a built-in
    /// function over its flattened arguments.
    fn call(&mut self, first: NodeId) -> Result<(), (Hresult, Option<NodeId>)> {
        let fail = |code| (code, Some(first));
        // As in `index`, stock reads the item of any other node; such an
        // item is never a function.
        let Kind::Name(name) = self.node(first).kind else {
            return Err(fail(WRONG_ITEM_KIND));
        };
        if self.find_item(name, None).is_some() {
            return Err(fail(WRONG_ITEM_KIND));
        }
        let bytes = &self.text[name.start..name.end];
        let (_, function) = *FUNCTIONS
            .iter()
            .find(|(name, _)| *name == bytes)
            .ok_or(fail(SYNTAX_ERROR))?;
        let (minimum, maximum) = function.count_range().ok_or(fail(SYNTAX_ERROR))?;
        let mut count = 0u32;
        let mut constant = true;
        let mut previous = first;
        let mut current = self.next(first);
        while let Some(id) = current {
            let node = *self.node(id);
            if let Kind::Operator {
                operator: COMMA,
                operands,
            } = node.kind
            {
                let mut last = operands;
                while let Some(child) = last.and_then(|child| self.next(child)) {
                    last = Some(child);
                }
                if let Some(last) = last {
                    self.node_mut(last).next = node.next;
                }
                self.node_mut(id).kind = Kind::Operator {
                    operator: COMMA,
                    operands: None,
                };
                self.node_mut(id).next = None;
                self.node_mut(previous).next = operands;
                self.free_list(Some(id));
                current = operands;
                continue;
            }
            constant &= matches!(node.kind, Kind::Constant(_));
            previous = id;
            current = node.next;
            count += 1;
        }
        if count < minimum {
            return Err(fail(TOO_FEW_ARGUMENTS));
        }
        if count > maximum {
            return Err(fail(TOO_MANY_ARGUMENTS));
        }
        let Some(arguments) = self.next(first) else {
            return Err(fail(TOO_FEW_ARGUMENTS));
        };
        self.node_mut(first).next = None;
        self.free_list(Some(first));
        self.function(function, arguments, count, constant)
    }

    /// A built-in function over `count` arguments starting at `first`.
    fn function(
        &mut self,
        operator: Operator,
        first: NodeId,
        count: u32,
        constant: bool,
    ) -> Result<(), (Hresult, Option<NodeId>)> {
        if !constant {
            return self.generic(operator, first);
        }
        let mut values = [Variant::Null; 5];
        let mut id = Some(first);
        for slot in values.iter_mut().take(count as usize) {
            let Some(node) = id else { break };
            if let Kind::Constant(value) = self.node(node).kind {
                *slot = value;
            }
            id = self.next(node);
        }
        let result = variant::apply(self.text, operator, &values[..count as usize])
            .map_err(|code| (code, Some(first)))?;
        self.fold(first, result);
        Ok(())
    }

    /// Append the subtree of `id` in postfix order.
    fn postfix(&self, id: NodeId, nodes: &mut [WireNode; NODE_LIMIT], count: &mut usize) {
        let wire = match self.node(id).kind {
            Kind::Constant(value) => WireNode::Constant(self.wire_value(value)),
            Kind::Name(text) => WireNode::Name(self.string_id(text)),
            Kind::Item(item) => WireNode::Item(item.0),
            Kind::Operator { operator, operands } => {
                let mut operand_count = 0u16;
                let mut child = operands;
                while let Some(id) = child {
                    self.postfix(id, nodes, count);
                    operand_count += 1;
                    child = self.next(id);
                }
                WireNode::Operator {
                    operator,
                    operands: operand_count,
                }
            }
        };
        nodes[*count] = wire;
        *count += 1;
    }

    /// Position of the entry of `text` among the entries, oldest first.
    fn string_id(&self, text: Text) -> StringId {
        let count = (0..usize::from(self.reference_count))
            .take_while(|&position| !self.equal(self.references[position].text, text))
            .filter(|&position| self.starts_entry(position))
            .count();
        StringId(count as u8)
    }

    fn wire_value(&self, value: Variant) -> Value {
        match value {
            Variant::Null => Value::Null,
            Variant::Bool(value) => Value::Bool(value),
            Variant::I8(value) => Value::I8(value),
            Variant::I16(value) => Value::I16(value),
            Variant::I32(value) => Value::I32(value),
            Variant::I64(value) => Value::I64(value),
            Variant::U8(value) => Value::U8(value),
            Variant::U16(value) => Value::U16(value),
            Variant::U32(value) => Value::U32(value),
            Variant::U64(value) => Value::U64(value),
            Variant::Mac(bytes) => Value::Mac(bytes),
            Variant::Ipv4(bytes) => Value::Ipv4(bytes),
            Variant::Ipv6(bytes) => Value::Ipv6(bytes),
            Variant::Str(text) => Value::Str(self.string_id(text)),
        }
    }
}

/// Whether an `l` at `position` continues a valid integer suffix: the
/// first suffix character, or after `l` (at most two) or `u`.
fn valid_long_suffix(text: &[u8], suffix: Option<usize>, position: usize) -> bool {
    let Some(suffix) = suffix else {
        return true;
    };
    match text[position - 1] {
        b'l' | b'L' => {
            suffix >= position - 1
                || (suffix >= position - 2 && matches!(text[position - 2], b'u' | b'U'))
        }
        previous => matches!(previous, b'u' | b'U'),
    }
}

/// The constant of an integer literal: 32 bits unless the value, its digit
/// count or an `ll` suffix needs 64; `u` makes it unsigned.
fn number_value(
    text: &[u8],
    start: usize,
    end: usize,
    suffix: Option<usize>,
    base: u64,
    value: u64,
) -> Result<Variant, Hresult> {
    let wide = |digits: usize| {
        value > 0xffff_ffff || (base == 10 && digits > 10) || (base == 16 && digits > 8)
    };
    let Some(mut suffix) = suffix else {
        return Ok(if wide(end - start) {
            Variant::I64(value as i64)
        } else {
            Variant::I32(value as u32 as i32)
        });
    };
    let digits = suffix - start;
    let unsigned = matches!(text[suffix], b'u' | b'U');
    if unsigned {
        suffix += 1;
    }
    if suffix + 1 >= end {
        if wide(digits) {
            return Err(SUFFIX_OVERFLOW);
        }
        return Ok(if unsigned {
            Variant::U32(value as u32)
        } else {
            Variant::I32(value as u32 as i32)
        });
    }
    Ok(if unsigned {
        Variant::U64(value)
    } else {
        Variant::I64(value as i64)
    })
}

/// An address literal at the start of `text` (0x91f858e8): a MAC address
/// `xx-xx-xx-xx-xx-xx` (hex), an IPv4 address `d.d.d.d` (decimal) or an
/// IPv6 address of eight hex groups. Returns the value and the length
/// consumed. The last group may be empty; the literal ends at the first
/// character that is not a digit once every separator is seen.
fn address_literal(text: &[u8]) -> Option<(Variant, usize)> {
    if text.len() < 7 {
        return None;
    }
    let (separator, separators, base, maximum, group_bytes) = if text[2] == b'-' {
        (b'-', 5, 16, 0xff, 1)
    } else if text[1] == b'.' || text[2] == b'.' || text[3] == b'.' {
        (b'.', 3, 10, 0xff, 1)
    } else if text[4] == b':' {
        (b':', 7, 16, 0xffff, 2)
    } else {
        return None;
    };
    let mut bytes = [0u8; 16];
    let mut written = 0;
    let mut remaining = separators;
    let mut group_start = 0;
    let mut group = 0u32;
    let mut position = 0;
    while position < text.len() {
        let c = text[position];
        let digit = match c {
            b'0'..=b'9' => Some(u32::from(c - b'0')),
            b'a'..=b'f' => Some(u32::from(c - b'a' + 10)),
            b'A'..=b'F' => Some(u32::from(c - b'A' + 10)),
            _ => None,
        };
        match digit {
            Some(digit) => {
                if digit >= base {
                    return None;
                }
                group = group * base + digit;
                if group > maximum {
                    return None;
                }
            }
            None if remaining == 0 => break,
            None => {
                if c != separator || position <= group_start {
                    return None;
                }
                bytes[written..written + group_bytes]
                    .copy_from_slice(&group.to_be_bytes()[4 - group_bytes..]);
                written += group_bytes;
                group = 0;
                remaining -= 1;
                group_start = position + 1;
            }
        }
        position += 1;
    }
    if remaining != 0 {
        return None;
    }
    bytes[written..written + group_bytes].copy_from_slice(&group.to_be_bytes()[4 - group_bytes..]);
    let value = match separator {
        b'-' => Variant::Mac(bytes[..6].try_into().ok()?),
        b'.' => Variant::Ipv4(bytes[..4].try_into().ok()?),
        _ => Variant::Ipv6(bytes),
    };
    Some((value, position))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::network::netsim::classifier::Program;
    use crate::commands::network::netsim::classifier::ProgramError;

    // Expected values: stock 0x91f8bdd0 followed by the serializer 0x91f87318
    // (0xdc output bytes), run on the stock image in an instruction-level
    // PowerPC emulator. A differential run of 60000 generated texts against
    // the same emulation matched this port wherever stock does not fault.

    /// Texts and their serialized programs.
    const PROGRAMS: [(&str, &str); 45] = [
        ("UDP", "101001010108252200"),
        ("udp", "101001010108252200"),
        ("(UDP)", "101001010108252200"),
        (
            "IPv4.SourceAddress == 1.2.3.4",
            "1010010301080b22000f0102030435",
        ),
        (
            "UDP.DestinationPort == 3074",
            "1010010301082722000600000c0235",
        ),
        (
            "Ethernet.SourceAddress == 00-11-22-33-44-55",
            "1010010301080222000e00112233445535",
        ),
        (
            "UDP == fe80:0:0:0:0:0:0:1",
            "10100103010825220010fe80000000000000000000000000000135",
        ),
        (
            "TCP.DstPort == 0x0c02 && TCP",
            "1010020501081a01081822000600000c023522013a",
        ),
        ("-UDP", "10100102010825220026"),
        ("!UDP", "10100102010825220028"),
        ("~UDP", "10100102010825220029"),
        (
            "UDP ? TCP : ARP",
            "1010030401082501081801080d2200220122023c",
        ),
        ("1 ? UDP : TCP", "101002010108250108182200"),
        ("0 ? UDP : TCP", "101002010108250108182201"),
        ("1 && UDP", "10100103010825060000000122003a"),
        ("0 || UDP", "10100103010825060000000022003b"),
        ("UDP && 1", "10100103010825220006000000013a"),
        ("UDP[1]", "10100201110825010a0000000000000001252201"),
        (
            "UDP[1] == UDP[2]",
            "10100303110825010a000000000000000125010a0000000000000002252201220235",
        ),
        ("UDP[TCP]", "101002030108181108252201220023"),
        (
            "UDP[0] == 1 || UDP[0] == 2",
            "10100207110825010a000000000000000025220106000000013522010600000002353b",
        ),
        (
            "String.Length(\"abc\") == UDP",
            "101001030108250600000003220035",
        ),
        (
            "String.Compare(UDP, \"x\", true)",
            "101402010104017801082522001200033f0003",
        ),
        (
            "String.Substring(\"abcdef\", 2) == UDP",
            "10140504010304636465660108251200220035",
        ),
        (
            "String.IndexOf(\"abcabc\", \"c\", 3) == UDP",
            "101001030108250600000005220035",
        ),
        (
            "String.Contains(UDP, \"a\")",
            "101402010103016101082522001200410002",
        ),
        (
            "String.StartsWith(\"abc\", \"ab\") == UDP",
            "1010010301082503220035",
        ),
        ("\"abc\" == UDP", "101404030103036162630108251200220035"),
        ("UDP == \"abc\"", "101404030103036162630108252200120035"),
        (
            "UDP == \"a\" || TCP == \"b\" || ARP == \"a\"",
            "10140401030b0162016101082501081801080d220012023522011200353b22021202353b",
        ),
        (
            "String.Substring(\"abcdef\", 1) == UDP && \"bcdef\" == TCP",
            "101406050207056263646566010825010818120022003512002201353a",
        ),
        ("UDP == 1 + 2 * 3", "101001030108252200060000000735"),
        ("UDP == (1 << 40)", "101001030108252200060000000035"),
        ("UDP == 0xffffffffu", "1010010301082522000affffffff35"),
        (
            "UDP == 4294967296",
            "10100103010825220007000000010000000035",
        ),
        ("UDP == 1ull", "1010010301082522000b000000000000000135"),
        ("UDP == -5 / 2", "10100103010825220006fffffffe35"),
        ("UDP == 7 % 3", "101001030108252200060000000135"),
        ("UDP > 1u - 2", "1010010301082522000affffffff32"),
        ("UDP == ~true", "10100103010825220006fffffffe35"),
        ("UDP == 1.2.3.4 < 1.2.3.5", "1010010301082522000335"),
        (
            "TCP.Flags.Syn /* comment */ && !TCP.Flags.Ack // trailing",
            "1010020401082201081f22002201283a",
        ),
        (
            "Kerberosv5 != XSPENC.SecMsg",
            "101002030108550108512200220136",
        ),
        ("IPV4.SOURCEADDRESS", "1010010101080b2200"),
        ("UDP[1u - 2u]", "10100201110825010a00000000ffffffff252201"),
    ];

    /// Texts and the status the compile returns.
    const ERRORS: [(&str, u32); 42] = [
        ("UDP == 18446744073709551615u", 0x800700ea),
        ("", 0x80070545),
        ("  ", 0x80070545),
        ("UDP ==", 0x80070545),
        ("UDP = 1", 0x8007000d),
        ("UDP, TCP", 0x80070545),
        ("UDP(1)", 0x80070545),
        ("\"abc", 0x8007000d),
        ("/* open", 0x80070026),
        ("UDP \\ 1", 0x8007000d),
        ("'a'", 0x8007000d),
        ("1.5", 0x80070545),
        (".5", 0x80070545),
        ("1f", 0x80070545),
        ("UDP == 0x", 0x8007044c),
        (".", 0x8007044c),
        ("99999999999999999999", 0x80070216),
        ("4294967296u", 0x800700ea),
        ("1lll", 0x8007000d),
        ("foo", 0x82da0025),
        ("String.Length", 0x82da0025),
        ("0", 0x82da0010),
        ("1 == 2", 0x82da0010),
        ("false", 0x82da0010),
        ("UDP[-1]", 0x80070083),
        ("UDP[0xffffffffffffffff]", 0x80070083),
        ("UDP[\"a\"]", 0x80070545),
        ("UDP[1] == UDP", 0x800710d2),
        ("UDP == UDP[1]", 0x800710d2),
        ("String.Length()", 0x80020004),
        ("String.Length(1, 2)", 0x8002000e),
        ("String.Foo(1)", 0x80070545),
        ("String.Length(1) == UDP", 0x80070545),
        (
            "String.Length == 1 && String.Length(\"a\") == 1",
            0x800710d2,
        ),
        ("UDP == 1 / 0", 0x800710d2),
        ("UDP == \"a\" + 1", 0x800710d2),
        ("UDP == 1.2.3.4 + 1", 0x800710d2),
        ("\"x\"", 0x80070545),
        ("UDP == !\"x\"", 0x800710d2),
        ("String.IndexOf(\"abc\", \"b\", 5) == UDP", 0x80070585),
        ("String.Substring(\"abc\", 1, 5) == UDP", 0x80070018),
        ("A[0] == \"Q\" || B[\"Q\" * C[\"t\" - 1]]", 0x80070545),
    ];

    const CAPACITY: usize = 0xdc;

    fn hex(text: &str) -> ([u8; CAPACITY], usize) {
        let mut bytes = [0u8; CAPACITY];
        let digits = text.as_bytes();
        for (index, pair) in digits.chunks(2).enumerate() {
            let digit = |c: u8| (c as char).to_digit(16).unwrap() as u8;
            bytes[index] = digit(pair[0]) << 4 | digit(pair[1]);
        }
        (bytes, digits.len() / 2)
    }

    fn compile(text: &[u8]) -> Result<Option<([u8; CAPACITY], usize)>, Hresult> {
        compile_text(text).map(|program| {
            program.map(|program| {
                let mut output = [0u8; CAPACITY];
                let length = program.serialize(&mut output).unwrap();
                (output, length)
            })
        })
    }

    /// `prefix` repeated `count` times, then `middle`, then `suffix`
    /// repeated `count` times.
    fn nested<'a>(
        buffer: &'a mut [u8],
        prefix: &[u8],
        count: usize,
        middle: &[u8],
        suffix: &[u8],
    ) -> &'a [u8] {
        let mut length = 0;
        let mut put = |bytes: &[u8]| {
            buffer[length..length + bytes.len()].copy_from_slice(bytes);
            length += bytes.len();
        };
        (0..count).for_each(|_| put(prefix));
        put(middle);
        (0..count).for_each(|_| put(suffix));
        &buffer[..length]
    }

    #[test]
    fn programs() {
        for (text, expected) in PROGRAMS {
            let (output, length) = compile(text.as_bytes()).unwrap().unwrap();
            let (expected, expected_length) = hex(expected);
            assert_eq!(&output[..length], &expected[..expected_length], "{text}");
        }
    }

    #[test]
    fn constant_true_programs_have_no_classifier() {
        assert_eq!(compile(b"TRUE"), Ok(None));
        assert_eq!(compile(b"true && 1"), Ok(None));
    }

    #[test]
    fn errors() {
        for (text, code) in ERRORS {
            assert_eq!(compile(text.as_bytes()), Err(Hresult(code)), "{text}");
        }
    }

    #[test]
    fn programs_beyond_the_stored_copy_limits() {
        // 18 items and 39 nodes: stock compiles and serializes both, and its
        // blob parser later refuses them.
        let text =
            b"Ethernet || IPv4 || ARP || LLTD || ICMP || IGMP || TCP || UDP || DNS || DHCP || XSP || Kerberosv5 \
            || ARP.OpCode || ICMP.Type || ICMP.Code || TCP.Flags || TCP.Window || DNS.Flags.QR";
        let (output, length) = compile(text).unwrap().unwrap();
        let mut program = Program::EMPTY;
        let (expected, expected_length) = hex(
            "1010122301080101080501080d01081301081401081701081801082501082801083701083a01085501080e01081501081601081d010824010829220022013b22023b22033b22043b22053b22063b22073b22083b22093b220a3b220b3b220c3b220d3b220e3b220f3b22103b22113b",
        );
        assert_eq!(&output[..length], &expected[..expected_length]);
        assert_eq!(
            Program::parse(&output[..length], &mut program),
            Err(ProgramError::OutOfMemory)
        );

        let mut buffer = [0u8; 0x100];
        let text = nested(&mut buffer, b"UDP+", 19, b"UDP", b"");
        let (output, length) = compile(text).unwrap().unwrap();
        let (expected, expected_length) = hex(
            "10100127010825220022002d22002d22002d22002d22002d22002d22002d22002d22002d22002d22002d22002d22002d22002d22002d22002d22002d22002d22002d",
        );
        assert_eq!(&output[..length], &expected[..expected_length]);
        assert_eq!(
            Program::parse(&output[..length], &mut program),
            Err(ProgramError::OutOfMemory)
        );
    }

    #[test]
    fn serialization_overflow() {
        // 20 element items of 11 bytes each exceed the output.
        let mut buffer = [0u8; 0x100];
        let mut length = 0;
        for index in 0..19 {
            let mut item = [0u8; 16];
            let mut cursor = 0;
            for &byte in b"UDP[" {
                item[cursor] = byte;
                cursor += 1;
            }
            if index >= 10 {
                item[cursor] = b'1';
                cursor += 1;
            }
            item[cursor] = b'0' + (index % 10) as u8;
            item[cursor + 1] = b']';
            cursor += 2;
            if index != 18 {
                item[cursor..cursor + 4].copy_from_slice(b" || ");
                cursor += 4;
            }
            buffer[length..length + cursor].copy_from_slice(&item[..cursor]);
            length += cursor;
        }
        let program = compile_text(&buffer[..length]).unwrap().unwrap();
        let mut output = [0u8; CAPACITY];
        assert_eq!(
            program.serialize(&mut output),
            Err(SerializeError::TooLarge)
        );
    }

    #[test]
    fn resource_limits() {
        let mut buffer = [0u8; 0x400];
        // The parser stack holds 500 states.
        assert!(
            compile(nested(&mut buffer, b"(", 300, b"UDP", b")"))
                .unwrap()
                .is_some()
        );
        assert_eq!(
            compile(nested(&mut buffer, b"(", 499, b"UDP", b")")),
            Err(STACK_OVERFLOW)
        );
        assert_eq!(
            compile(nested(&mut buffer, b"-", 499, b"UDP", b"")),
            Err(STACK_OVERFLOW)
        );
        // 498 negations fit the stack but exhaust the node objects; the
        // freed operand then leaves the next negation without one.
        assert_eq!(
            compile(nested(&mut buffer, b"-", 498, b"UDP", b"")),
            Err(MISSING_OPERAND)
        );
        // 65 live nodes exceed the 0x40 node objects.
        assert_eq!(
            compile(nested(&mut buffer, b"UDP+", 32, b"UDP", b"")),
            Err(OUT_OF_MEMORY)
        );
        assert_eq!(
            compile(nested(&mut buffer, b"a", 0x80, b"", b"")),
            Err(NAME_TOO_LONG)
        );
    }
}
