//! Capture log format used by [`super::RecordingTransport`] and consumed by
//! [`super::MockTransport`].
//!
//! A capture is an ordered list of frames. Each frame carries a direction
//! (server-to-client or client-to-server) and the raw bytes that crossed
//! the wire in that direction. Contiguous frames in the same direction are
//! coalesced when rendering to keep the on-disk form readable.
//!
//! Serialisation format (text, line-oriented):
//!
//! ```text
//! # xbdm capture v1
//! S> 201- connected\r\n
//! C> dbgname\r\n
//! S> 200- deanxbox\r\n
//! ```
//!
//! Direction tags: `S>` = server sent these bytes to us, `C>` = client
//! sent these bytes to the server. Non-printable bytes are escaped as
//! `\xHH`; `\r`, `\n`, `\t`, `\\` use their usual C-style escapes. A
//! capture line always ends in a real newline in the file, but the last
//! two characters before it may be the escape sequence `\r\n` denoting
//! a literal CRLF in the captured stream.

mod error;

use std::fmt::Write as _;

pub use error::CaptureParseError;

/// Which side of the connection the bytes travelled on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Server to client (things we read off the socket).
    ServerToClient,
    /// Client to server (things we write to the socket).
    ClientToServer,
}

impl Direction {
    pub fn tag(self) -> &'static str {
        match self {
            Self::ServerToClient => "S>",
            Self::ClientToServer => "C>",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "S>" => Some(Self::ServerToClient),
            "C>" => Some(Self::ClientToServer),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaptureEntry {
    pub direction: Direction,
    pub data: Vec<u8>,
}

impl CaptureEntry {
    pub fn new(direction: Direction, data: impl Into<Vec<u8>>) -> Self {
        Self {
            direction,
            data: data.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaptureLog {
    entries: Vec<CaptureEntry>,
}

impl CaptureLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Parse a capture log from its text form. Lines beginning with `#`
    /// are comments. Empty lines are skipped.
    pub fn from_text(input: &str) -> Result<Self, CaptureParseError> {
        let mut entries: Vec<CaptureEntry> = Vec::new();

        for (idx, raw_line) in input.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw_line.trim_end_matches('\n').trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let Some((tag, rest)) = line.split_once(' ') else {
                return Err(CaptureParseError::MissingTag { line_no });
            };
            let direction =
                Direction::from_tag(tag).ok_or(CaptureParseError::UnknownTag { line_no })?;
            let data = unescape(rest).ok_or(CaptureParseError::BadEscape { line_no })?;

            if let Some(last) = entries.last_mut()
                && last.direction == direction
            {
                last.data.extend_from_slice(&data);
                continue;
            }

            entries.push(CaptureEntry { direction, data });
        }

        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[CaptureEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn push(&mut self, direction: Direction, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        if let Some(last) = self.entries.last_mut()
            && last.direction == direction
        {
            last.data.extend_from_slice(bytes);
            return;
        }

        self.entries.push(CaptureEntry {
            direction,
            data: bytes.to_vec(),
        });
    }

    /// Render the capture to the canonical text format.
    pub fn to_text(&self) -> String {
        let mut out = String::from("# xbdm capture v1\n");

        for entry in &self.entries {
            let _ = writeln!(
                &mut out,
                "{} {}",
                entry.direction.tag(),
                escape(&entry.data)
            );
        }

        out
    }
}

impl Default for CaptureLog {
    fn default() -> Self {
        Self::new()
    }
}

fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());

    for &byte in bytes {
        match byte {
            b'\\' => out.push_str(r"\\"),
            b'\r' => out.push_str(r"\r"),
            b'\n' => out.push_str(r"\n"),
            b'\t' => out.push_str(r"\t"),
            0x20..=0x7e => out.push(byte as char),
            _ => {
                let _ = write!(out, r"\x{byte:02x}");
            }
        }
    }

    out
}

fn unescape(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;

    while idx < bytes.len() {
        if bytes[idx] != b'\\' {
            out.push(bytes[idx]);
            idx += 1;
            continue;
        }

        idx += 1;
        if idx >= bytes.len() {
            return None;
        }

        match bytes[idx] {
            b'\\' => out.push(b'\\'),
            b'r' => out.push(b'\r'),
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'x' => {
                if idx + 2 >= bytes.len() {
                    return None;
                }
                let hex = core::str::from_utf8(&bytes[idx + 1..idx + 3]).ok()?;
                let byte = u8::from_str_radix(hex, 16).ok()?;
                out.push(byte);
                idx += 2;
            }
            _ => return None,
        }
        idx += 1;
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_simple_session() {
        let mut log = CaptureLog::new();
        log.push(Direction::ServerToClient, b"201- connected\r\n");
        log.push(Direction::ClientToServer, b"dbgname\r\n");
        log.push(Direction::ServerToClient, b"200- deanxbox\r\n");
        let text = log.to_text();
        let parsed = CaptureLog::from_text(&text).unwrap();
        assert_eq!(parsed.entries.len(), log.entries.len());
        for (parsed_entry, original) in parsed.entries.iter().zip(log.entries.iter()) {
            assert_eq!(parsed_entry.direction, original.direction);
            assert_eq!(parsed_entry.data, original.data);
        }
    }

    #[test]
    fn escapes_non_printable_bytes() {
        let mut log = CaptureLog::new();
        log.push(Direction::ServerToClient, &[0x00, 0x1f, 0x80, b'a']);
        let text = log.to_text();
        assert!(text.contains(r"\x00"));
        assert!(text.contains(r"\x1f"));
        assert!(text.contains(r"\x80"));
        let round = CaptureLog::from_text(&text).unwrap();
        assert_eq!(round.entries[0].data, vec![0x00, 0x1f, 0x80, b'a']);
    }

    #[test]
    fn coalesces_adjacent_same_direction() {
        let mut log = CaptureLog::new();
        log.push(Direction::ClientToServer, b"dbg");
        log.push(Direction::ClientToServer, b"name\r\n");
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries[0].data, b"dbgname\r\n");
    }
}
