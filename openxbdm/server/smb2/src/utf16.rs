//! UTF-16LE strings as they appear on the wire.

/// A UTF-16LE string borrowed from a message. The byte length is even.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Utf16Le<'a>(&'a [u8]);

impl<'a> Utf16Le<'a> {
    pub const EMPTY: Utf16Le<'static> = Utf16Le(&[]);

    /// `None` when `bytes` has an odd length.
    pub const fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len().is_multiple_of(2) {
            Some(Self(bytes))
        } else {
            None
        }
    }

    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// Number of 16-bit code units.
    pub const fn len(self) -> usize {
        self.0.len() / 2
    }

    pub const fn is_empty(self) -> bool {
        self.0.is_empty()
    }

    pub fn units(self) -> impl DoubleEndedIterator<Item = u16> + ExactSizeIterator + Clone + 'a {
        self.0
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
    }

    pub fn unit(self, index: usize) -> Option<u16> {
        let start = index.checked_mul(2)?;
        let pair = self.0.get(start..start + 2)?;

        Some(u16::from_le_bytes([pair[0], pair[1]]))
    }

    /// Code units `start..end`.
    pub fn slice(self, start: usize, end: usize) -> Self {
        Self(&self.0[start * 2..end * 2])
    }

    /// Compare with an ASCII string, ignoring ASCII case.
    pub fn eq_ignore_ascii_case(self, ascii: &[u8]) -> bool {
        self.len() == ascii.len()
            && self
                .units()
                .zip(ascii)
                .all(|(unit, &byte)| fold_ascii(unit) == u16::from(byte.to_ascii_lowercase()))
    }

    /// Compare two strings, ignoring ASCII case.
    pub fn eq_ignore_ascii_case_utf16(self, other: Utf16Le<'_>) -> bool {
        self.len() == other.len()
            && self
                .units()
                .zip(other.units())
                .all(|(unit, other_unit)| fold_ascii(unit) == fold_ascii(other_unit))
    }
}

impl core::fmt::Debug for Utf16Le<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Write as _;

        formatter.write_char('"')?;

        for character in char::decode_utf16(self.units()) {
            // Debug output shows unpaired surrogates as the replacement character.
            let character = character.unwrap_or(char::REPLACEMENT_CHARACTER);
            for escaped in character.escape_debug() {
                formatter.write_char(escaped)?;
            }
        }

        formatter.write_char('"')
    }
}

/// Lower-case ASCII letters; other code units are unchanged.
pub const fn fold_ascii(unit: u16) -> u16 {
    if unit >= b'A' as u16 && unit <= b'Z' as u16 {
        unit + 0x20
    } else {
        unit
    }
}

/// Upper-case ASCII letters; other code units are unchanged.
pub const fn upper_ascii(unit: u16) -> u16 {
    if unit >= b'a' as u16 && unit <= b'z' as u16 {
        unit - 0x20
    } else {
        unit
    }
}

/// Write `units` as UTF-16LE into `output`; returns the bytes written, or
/// `None` when `output` is too small.
pub fn encode_units(units: impl IntoIterator<Item = u16>, output: &mut [u8]) -> Option<usize> {
    let mut written = 0;

    for unit in units {
        output
            .get_mut(written..written + 2)?
            .copy_from_slice(&unit.to_le_bytes());
        written += 2;
    }

    Some(written)
}

/// Write ASCII `text` as UTF-16LE into `output`.
pub fn encode_ascii(text: &[u8], output: &mut [u8]) -> Option<usize> {
    encode_units(text.iter().map(|&byte| u16::from(byte)), output)
}
