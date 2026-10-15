//! Fixed-capacity text buffers for reply lines.

use core::fmt;

/// Capacity of the text after `NNN- ` in a handler reply.
pub const RESPONSE_TEXT_CAPACITY: usize = 0x1fb;
/// Capacity of one continuation line or continuation reply text.
pub const LINE_TEXT_CAPACITY: usize = 0x100;

/// ASCII text with a fixed capacity. Writes past the capacity are
/// truncated and reported as `fmt::Error`.
#[derive(Clone)]
pub struct Text<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Text<N> {
    pub const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Replace the content with `bytes`, truncated to the capacity.
    pub fn set_bytes(&mut self, bytes: &[u8]) {
        let count = bytes.len().min(N);
        self.bytes[..count].copy_from_slice(&bytes[..count]);
        self.len = count;
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> fmt::Result {
        self.cursor().push(bytes)
    }

    /// `value` as eight lowercase hex digits, as `{:08x}` writes it.
    pub fn push_hex32(&mut self, value: u32) -> fmt::Result {
        self.cursor().push_hex32(value)
    }

    /// `value` in decimal, as `{}` writes it.
    pub fn push_decimal(&mut self, value: u32) -> fmt::Result {
        self.cursor().push_decimal(value)
    }

    fn cursor(&mut self) -> Cursor<'_> {
        Cursor {
            bytes: &mut self.bytes,
            len: &mut self.len,
        }
    }
}

impl<const N: usize> Default for Text<N> {
    fn default() -> Self {
        Self::new()
    }
}

// Every capacity forwards to `Cursor`, so the writes are instantiated once.
impl<const N: usize> fmt::Write for Text<N> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.push_bytes(value.as_bytes())
    }

    fn write_char(&mut self, value: char) -> fmt::Result {
        self.cursor().write_char(value)
    }

    fn write_fmt(&mut self, arguments: fmt::Arguments<'_>) -> fmt::Result {
        self.cursor().write_fmt(arguments)
    }
}

/// The written length and storage of a `Text` of any capacity.
struct Cursor<'a> {
    bytes: &'a mut [u8],
    len: &'a mut usize,
}

impl Cursor<'_> {
    #[inline(never)]
    fn push(&mut self, bytes: &[u8]) -> fmt::Result {
        let available = self.bytes.len() - *self.len;
        let count = bytes.len().min(available);
        self.bytes[*self.len..*self.len + count].copy_from_slice(&bytes[..count]);
        *self.len += count;
        if count == bytes.len() {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }

    #[inline(never)]
    fn push_hex32(&mut self, value: u32) -> fmt::Result {
        let mut digits = [0u8; 8];
        for (index, digit) in digits.iter_mut().enumerate() {
            *digit = b"0123456789abcdef"[(value >> (28 - 4 * index)) as usize & 0xf];
        }
        self.push(&digits)
    }

    #[inline(never)]
    fn push_decimal(&mut self, mut value: u32) -> fmt::Result {
        let mut digits = [0u8; 10];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push(&digits[start..])
    }
}

impl fmt::Write for Cursor<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.push(value.as_bytes())
    }

    #[inline(never)]
    fn write_char(&mut self, value: char) -> fmt::Result {
        self.push(value.encode_utf8(&mut [0; 4]).as_bytes())
    }

    #[inline(never)]
    fn write_fmt(&mut self, arguments: fmt::Arguments<'_>) -> fmt::Result {
        fmt::write(self, arguments)
    }
}

impl<const N: usize> fmt::Debug for Text<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.as_bytes().escape_ascii())
    }
}

pub type ResponseText = Text<RESPONSE_TEXT_CAPACITY>;
pub type LineText = Text<LINE_TEXT_CAPACITY>;
