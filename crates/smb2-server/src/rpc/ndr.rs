//! NDR 2.0 in little-endian representation (C706 chapter 14).

use crate::crypto::Sha256;

const PADDING: [u8; 8] = [0; 8];
/// Bytes of a rendering digest: SHA-256 truncated to 128 bits.
pub(super) const DIGEST_LENGTH: usize = 16;

/// Serializes a byte stream and keeps only the bytes at stream positions
/// `start..start + output.len()`. With an empty output it only counts.
/// It also digests every byte, to tell whether two renderings match.
pub(super) struct Writer<'a> {
    output: &'a mut [u8],
    start: usize,
    position: usize,
    digest: Sha256,
}

impl<'a> Writer<'a> {
    pub fn counter() -> Writer<'static> {
        Writer::window(&mut [], 0)
    }

    pub fn window(output: &'a mut [u8], start: usize) -> Self {
        Self {
            output,
            start,
            position: 0,
            digest: Sha256::new(),
        }
    }

    /// Bytes serialized so far, including those outside the window.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Truncated SHA-256 of the bytes serialized.
    pub fn digest(self) -> [u8; DIGEST_LENGTH] {
        let digest = self.digest.finalize();
        let mut truncated = [0; DIGEST_LENGTH];
        truncated.copy_from_slice(&digest[..DIGEST_LENGTH]);
        truncated
    }

    pub fn bytes(&mut self, bytes: &[u8]) {
        self.digest.update(bytes);
        let begin = self.position;
        let end = begin + bytes.len();
        self.position = end;
        let window_end = self.start + self.output.len();
        let from = begin.max(self.start);
        let to = end.min(window_end);
        if from < to {
            self.output[from - self.start..to - self.start]
                .copy_from_slice(&bytes[from - begin..to - begin]);
        }
    }

    /// Zero padding up to a multiple of `alignment` (at most 8).
    pub fn align(&mut self, alignment: usize) {
        let padding = self.position.wrapping_neg() & (alignment - 1);
        self.bytes(&PADDING[..padding]);
    }

    pub fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    pub fn u16(&mut self, value: u16) {
        self.align(2);
        self.bytes(&value.to_le_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.align(4);
        self.bytes(&value.to_le_bytes());
    }

    /// A conformant varying `[string] wchar_t` array with its terminator.
    pub fn string(&mut self, text: Text<'_>) {
        let count = match text {
            Text::Units(units) => units.len(),
            Text::Ascii(ascii) => ascii.len(),
        } as u32
            + 1;
        self.u32(count);
        self.u32(0);
        self.u32(count);
        match text {
            Text::Units(units) => units.iter().for_each(|&unit| self.u16(unit)),
            Text::Ascii(ascii) => ascii.iter().for_each(|&byte| self.u16(u16::from(byte))),
        }
        self.u16(0);
    }
}

/// Text to marshal as a wide string.
#[derive(Clone, Copy)]
pub(super) enum Text<'a> {
    Units(&'a [u16]),
    Ascii(&'a [u8]),
}

/// A wide string in a request stub: byte offset and code units, without
/// the terminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StubString {
    pub start: u16,
    pub units: u16,
}

impl StubString {
    pub fn bytes(self, stub: &[u8]) -> &[u8] {
        let start = usize::from(self.start);
        &stub[start..start + 2 * usize::from(self.units)]
    }
}

/// Parses a request stub.
pub(super) struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub fn u32(&mut self) -> Option<u32> {
        let start = self.position.next_multiple_of(4);
        let bytes = self.data.get(start..start + 4)?;
        self.position = start + 4;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// A conformant varying `[string] wchar_t` array. The terminator is
    /// required.
    pub fn string(&mut self) -> Option<StubString> {
        let maximum = self.u32()?;
        let offset = self.u32()?;
        let actual = self.u32()?;
        if offset != 0 || actual == 0 || actual > maximum {
            return None;
        }
        let units = u16::try_from(actual - 1).ok()?;
        let start = self.position;
        let end = start.checked_add(2 * usize::from(units) + 2)?;
        let bytes = self.data.get(start..end)?;
        if bytes[bytes.len() - 2..] != [0, 0] {
            return None;
        }
        self.position = end;
        Some(StubString {
            start: u16::try_from(start).ok()?,
            units,
        })
    }

    /// A `[unique, string] wchar_t*` whose value the server does not use.
    pub fn skip_unique_string(&mut self) -> Option<()> {
        if self.u32()? != 0 {
            self.string()?;
        }
        Some(())
    }
}
