//! Command-line parameter grammar as implemented by the stock monitor.
//!
//! A command line is the command word followed by tokens. Tokens are
//! separated by space, CR, or NUL. A double quote toggles quoting, and a
//! quoted region does not split tokens. Parameters are `KEY=VALUE` tokens;
//! keys compare case-insensitively and must match exactly. Flags are bare
//! tokens without `=`.

/// Maximum characters the monitor copies before parsing a numeric value.
const NUMBER_TEXT_LIMIT: usize = 0x1f;
/// Maximum characters the monitor copies before parsing a quadword value.
const QWORD_TEXT_LIMIT: usize = 0x1e;

fn is_separator(byte: u8) -> bool {
    matches!(byte, b' ' | b'\r' | 0)
}

/// A received command line, without the terminating LF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandLine<'a> {
    bytes: &'a [u8],
}

impl<'a> CommandLine<'a> {
    /// The line ends at the first NUL, as it does for the monitor.
    pub fn new(line: &'a [u8]) -> Self {
        let end = line
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(line.len());
        Self {
            bytes: &line[..end],
        }
    }

    fn at(&self, index: usize) -> u8 {
        self.bytes.get(index).copied().unwrap_or(0)
    }

    /// The whole line.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The command word: every byte before the first separator.
    pub fn command(&self) -> &'a [u8] {
        let end = (0..self.bytes.len())
            .find(|&index| is_separator(self.bytes[index]))
            .unwrap_or(self.bytes.len());
        &self.bytes[..end]
    }

    /// Whether the command word equals `name`, ignoring ASCII case.
    pub fn is_command(&self, name: &str) -> bool {
        self.command().eq_ignore_ascii_case(name.as_bytes())
    }

    /// Value of the `name=VALUE` parameter.
    pub fn param(&self, name: &str) -> Option<Value<'a>> {
        match self.find(name, true)? {
            Token::Value(start) => Some(Value { line: *self, start }),
            Token::Flag => None,
        }
    }

    /// Whether `name` appears as a bare flag or as a `name=VALUE` parameter.
    pub fn has(&self, name: &str) -> bool {
        self.find(name, false).is_some()
    }

    fn find(&self, name: &str, value_required: bool) -> Option<Token> {
        let name = name.as_bytes();
        let mut position = self.command().len();
        let mut quoted = false;
        loop {
            while position < self.bytes.len() && is_separator(self.at(position)) {
                position += 1;
            }
            if position >= self.bytes.len() {
                return None;
            }

            let key_start = position;
            let mut key_end = position;
            while !is_separator(self.at(key_end)) {
                if self.at(key_end) == b'=' {
                    if self.bytes[key_start..key_end].eq_ignore_ascii_case(name) {
                        return Some(Token::Value(key_end + 1));
                    }
                    break;
                }
                key_end += 1;
            }
            if !value_required
                && self.at(key_end) != b'='
                && self.bytes[key_start..key_end].eq_ignore_ascii_case(name)
            {
                return Some(Token::Flag);
            }

            position = key_end;
            loop {
                let byte = self.at(position);
                if byte == 0 || (is_separator(byte) && !quoted) {
                    break;
                }
                position += 1;
                if byte == b'"' {
                    quoted = !quoted;
                }
            }
        }
    }
}

enum Token {
    Value(usize),
    Flag,
}

/// The text of a parameter value as it appears on the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Value<'a> {
    line: CommandLine<'a>,
    start: usize,
}

impl<'a> Value<'a> {
    /// A value at a fixed offset of a line buffer, as handlers that read
    /// positional values do. `buffer` may extend past the line terminator;
    /// the value ends at the first NUL.
    pub fn at_offset(buffer: &'a [u8], offset: usize) -> Self {
        Self {
            line: CommandLine { bytes: buffer },
            start: offset,
        }
    }

    /// The line from the first value byte to the end of the line, without
    /// unquoting, for handlers that scan the value text in place.
    pub fn raw(&self) -> &'a [u8] {
        let end = self
            .line
            .bytes
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(self.line.bytes.len());
        &self.line.bytes[self.start.min(end)..end]
    }

    /// Unquoted value bytes, as the monitor copies them: quotes are removed,
    /// a doubled quote inside a quoted region yields one quote, and the value
    /// ends at a separator outside quotes.
    pub fn bytes(&self) -> Unquoted<'a> {
        Unquoted {
            line: self.line,
            position: self.start,
            quoted: false,
        }
    }

    /// Copy the unquoted value into `output`, truncated to `output.len() - 1`
    /// bytes as the monitor does, and return the copied bytes.
    pub fn copy_into<'b>(&self, output: &'b mut [u8]) -> &'b [u8] {
        let limit = output.len().saturating_sub(1);
        let mut length = 0;
        for byte in self.bytes().take(limit) {
            output[length] = byte;
            length += 1;
        }
        &output[..length]
    }

    /// The value parsed as a dword: C `strtol` base-0 rules (`0x` hex,
    /// leading `0` octal, optional `-`, decimal) over at most 31 copied
    /// characters. The number must be followed by space, CR, or the end of
    /// the copied text; otherwise the parameter counts as absent.
    pub fn dword(&self) -> Option<u32> {
        let mut buffer = [0u8; NUMBER_TEXT_LIMIT + 1];
        let text = self.copy_into(&mut buffer);
        let (value, consumed) = parse_number(text);
        let next = text.get(consumed).copied().unwrap_or(0);
        is_separator(next).then_some(value)
    }

    /// The number the monitor stores even when [`Self::dword`] reports the
    /// parameter absent: the parsed prefix of the copied text.
    pub fn dword_prefix(&self) -> u32 {
        let mut buffer = [0u8; NUMBER_TEXT_LIMIT + 1];
        parse_number(self.copy_into(&mut buffer)).0
    }

    /// The value parsed as a quadword: `0q` followed by hex digits. The
    /// last sixteen digits form the value; longer input is accepted up to
    /// the copy limit.
    pub fn qword(&self) -> Option<u64> {
        let mut buffer = [0u8; QWORD_TEXT_LIMIT + 1];
        let text = self.copy_into(&mut buffer);
        if text.len() < 2 || text[0] != b'0' || text[1] != b'q' {
            return None;
        }
        let mut count = 0;
        for &byte in &text[2..] {
            if is_separator(byte) {
                break;
            }
            if !byte.is_ascii_hexdigit() {
                return None;
            }
            count += 1;
        }
        if count == 0 {
            return None;
        }
        let digits = &text[2..2 + count];
        let keep = &digits[digits.len().saturating_sub(16)..];
        Some(keep.iter().fold(0u64, |value, &digit| {
            (value << 4) | u64::from(hex_value(digit))
        }))
    }
}

/// Iterator over the unquoted bytes of a parameter value.
#[derive(Debug, Clone)]
pub struct Unquoted<'a> {
    line: CommandLine<'a>,
    position: usize,
    quoted: bool,
}

impl Iterator for Unquoted<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        loop {
            let byte = self.line.at(self.position);
            if byte == 0 || (is_separator(byte) && !self.quoted) {
                return None;
            }
            if byte != b'"' {
                self.position += 1;
                return Some(byte);
            }
            if self.quoted && self.line.at(self.position + 1) == b'"' {
                self.position += 2;
                return Some(b'"');
            }
            self.quoted = !self.quoted;
            self.position += 1;
        }
    }
}

fn hex_value(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        _ => 0,
    }
}

/// C `strtol` base-0 subset used by the monitor. Returns the value and the
/// number of bytes consumed. Arithmetic wraps at 32 bits.
fn parse_number(text: &[u8]) -> (u32, usize) {
    let at = |index: usize| text.get(index).copied().unwrap_or(0);
    if at(0) != b'0' {
        let negative = at(0) == b'-';
        let mut index = usize::from(negative);
        let mut value = 0u32;
        while at(index).is_ascii_digit() {
            value = value
                .wrapping_mul(10)
                .wrapping_add(u32::from(at(index) - b'0'));
            index += 1;
        }
        return (
            if negative {
                value.wrapping_neg()
            } else {
                value
            },
            index,
        );
    }
    if matches!(at(1), b'x' | b'X') {
        let mut index = 2;
        let mut value = 0u32;
        while at(index).is_ascii_hexdigit() {
            value = (value << 4) | u32::from(hex_value(at(index)));
            index += 1;
        }
        return (value, index);
    }
    let mut index = 1;
    let mut value = 0u32;
    while matches!(at(index), b'0'..=b'7') {
        value = (value << 3).wrapping_add(u32::from(at(index) - b'0'));
        index += 1;
    }
    (value, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str) -> CommandLine<'_> {
        CommandLine::new(text.as_bytes())
    }

    #[test]
    fn command_word_ends_at_first_separator() {
        assert_eq!(line("getmem addr=0x10").command(), b"getmem");
        assert!(line("GETMEM addr=1").is_command("getmem"));
    }

    #[test]
    fn keys_match_case_insensitively_and_exactly() {
        let cmd = line("getmem ADDR=5 addrx=6 length=7");
        assert_eq!(cmd.param("addr").and_then(|v| v.dword()), Some(5));
        assert_eq!(cmd.param("addrx").and_then(|v| v.dword()), Some(6));
        assert!(cmd.param("add").is_none());
    }

    #[test]
    fn numbers_follow_strtol_base_zero() {
        let value = |text: &str| line(text).param("v").and_then(|v| v.dword());
        assert_eq!(value("x v=0x1F"), Some(0x1f));
        assert_eq!(value("x v=010"), Some(8));
        assert_eq!(value("x v=10"), Some(10));
        assert_eq!(value("x v=-1"), Some(u32::MAX));
        assert_eq!(value("x v=0"), Some(0));
        assert_eq!(value("x v=08"), None);
        assert_eq!(value("x v=12z"), None);
        assert_eq!(value("x v=+5"), None);
        assert_eq!(value("x v=\" 5\""), Some(0));
        assert_eq!(value("x v=\"12 34\""), Some(12));
    }

    #[test]
    fn quoted_values_are_unquoted_and_keep_spaces() {
        let cmd = line(r#"getfile name="e:\a b""c.txt" next=1"#);
        let mut buffer = [0u8; 64];
        assert_eq!(
            cmd.param("name").unwrap().copy_into(&mut buffer),
            br#"e:\a b"c.txt"#
        );
        assert_eq!(cmd.param("next").and_then(|v| v.dword()), Some(1));
    }

    #[test]
    fn quoted_spaces_do_not_create_tokens() {
        let cmd = line(r#"x name="a len=5" len=6"#);
        assert_eq!(cmd.param("len").and_then(|v| v.dword()), Some(6));
    }

    #[test]
    fn copy_truncates_to_buffer_size_minus_one() {
        let cmd = line("x name=abcdef");
        let mut buffer = [0u8; 4];
        assert_eq!(cmd.param("name").unwrap().copy_into(&mut buffer), b"abc");
    }

    #[test]
    fn flags_match_bare_tokens() {
        let cmd = line("reboot warm stop");
        assert!(cmd.has("WARM"));
        assert!(cmd.has("stop"));
        assert!(!cmd.has("wait"));
        assert!(cmd.param("warm").is_none());
    }

    #[test]
    fn qwords_take_the_last_sixteen_digits() {
        let value = |text: &str| line(text).param("q").and_then(|v| v.qword());
        assert_eq!(value("x q=0q1122334455667788"), Some(0x1122_3344_5566_7788));
        assert_eq!(value("x q=0qff"), Some(0xff));
        assert_eq!(
            value("x q=0qAA1122334455667788"),
            Some(0x1122_3344_5566_7788)
        );
        assert_eq!(value("x q=0Qff"), None);
        assert_eq!(value("x q=0q"), None);
        assert_eq!(value("x q=0qfg"), None);
    }

    #[test]
    fn line_ends_at_nul() {
        let cmd = CommandLine::new(b"x a=1\0 b=2");
        assert!(cmd.param("b").is_none());
    }

    #[test]
    fn malformed_numbers_keep_their_prefix() {
        let value = |text: &str| line(text).param("v").unwrap().dword_prefix();
        assert_eq!(value("x v=12z"), 12);
        assert_eq!(value("x v=0x1fq"), 0x1f);
        assert_eq!(value("x v=z"), 0);
    }

    #[test]
    fn positional_values_read_past_the_terminator() {
        let mut buffer = [0u8; 8];
        let value = Value::at_offset(b"ab\0\nc d", 3).copy_into(&mut buffer);
        assert_eq!(value, b"\nc");
    }
}
