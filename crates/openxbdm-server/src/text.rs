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
        let available = N - self.len;
        let count = bytes.len().min(available);
        self.bytes[self.len..self.len + count].copy_from_slice(&bytes[..count]);
        self.len += count;
        if count == bytes.len() {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

impl<const N: usize> Default for Text<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Write for Text<N> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.push_bytes(value.as_bytes())
    }
}

impl<const N: usize> fmt::Debug for Text<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.as_bytes().escape_ascii())
    }
}

pub type ResponseText = Text<RESPONSE_TEXT_CAPACITY>;
pub type LineText = Text<LINE_TEXT_CAPACITY>;
