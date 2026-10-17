//! Typed argument values and a builder for constructing command lines.
//!
//! XBDM uses several distinct value formats on the wire. The newtypes
//! below enforce each representation at the type level so callers cannot
//! pass a hex-looking integer where a decimal is expected or forget
//! quoting on a path.
//!
//! Formats:
//!
//! - decimal: `123`, `%lu`, `%d` (counts, sizes, thread ids)
//! - hex: `0x00400000` (addresses, flags, handles)
//! - quadword: `0q08f1c0de08f1c0de` (64-bit hashes, box ids, XUIDs)
//! - quoted string: `"e:\foo.bar"` (filenames, arbitrary text)
//! - bare flag: `NOPERSIST` (presence-only markers)

use core::fmt::Write as _;

use crate::error::ArgumentError;

pub use openxbdm_core::value::Qword;

/// Builder for the right-hand side of an XBDM command line.
///
/// Each `arg_*` method appends a leading space and the formatted argument.
/// The builder starts with the command mnemonic and yields a `String` that
/// is ready to have `\r\n` appended by the transport layer.
#[derive(Debug, Clone)]
pub struct ArgBuilder {
    buf: String,
}

impl ArgBuilder {
    pub fn new(command: &str) -> Self {
        Self {
            buf: command.to_owned(),
        }
    }

    /// Append a bare sub-command token (e.g. `ADVISE`, `START`, `NOPERSIST`).
    pub fn flag(mut self, token: &str) -> Self {
        self.buf.push(' ');
        self.buf.push_str(token);
        self
    }

    /// Append `KEY=decimal`.
    pub fn dec(mut self, key: &str, value: impl Into<u64>) -> Self {
        let _ = write!(self.buf, " {key}={}", value.into());
        self
    }

    /// Append `KEY=signed-decimal`.
    pub fn int(mut self, key: &str, value: i64) -> Self {
        let _ = write!(self.buf, " {key}={value}");
        self
    }

    /// Append `KEY=0x<8 hex digits>`, the form used by most addresses,
    /// handles, and flag bitmasks.
    pub fn hex32(mut self, key: &str, value: u32) -> Self {
        let _ = write!(self.buf, " {key}=0x{value:08x}");
        self
    }

    /// Append `KEY=0x<lowercase hex>` without zero padding. Used by
    /// commands (e.g. `addtitlemem`, `SENDFILE LENGTH=0x%x`) that accept a
    /// plain hex literal rather than a fixed-width one.
    pub fn hex(mut self, key: &str, value: u64) -> Self {
        let _ = write!(self.buf, " {key}=0x{value:x}");
        self
    }

    /// Append `KEY=0q<quad>` (64-bit quadword).
    pub fn qword(mut self, key: &str, value: Qword) -> Self {
        let _ = write!(self.buf, " {key}={value}");
        self
    }

    /// Append `KEY="..."` with minimal quoting. Backslashes pass through
    /// unchanged (XBDM tokenises them literally); embedded double quotes
    /// and CR/LF are rejected.
    pub fn quoted(mut self, key: &str, value: &str) -> Result<Self, ArgumentError> {
        if value.contains('"') {
            return Err(ArgumentError::QuotedContainsDoubleQuote);
        }

        if value.contains(['\r', '\n']) {
            return Err(ArgumentError::QuotedContainsCrlf);
        }

        let _ = write!(self.buf, " {key}=\"{value}\"");

        Ok(self)
    }

    /// Consume the builder and return the completed line body (no `\r\n`).
    pub fn finish(self) -> String {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qword_formats_as_paired_halves() {
        let qword = Qword(0x1122_3344_5566_7788);
        assert_eq!(qword.to_string(), "0q1122334455667788");
    }

    #[test]
    fn builder_composes_systime_wire() {
        let line = ArgBuilder::new("setsystime")
            .hex32("clockhi", 0x01d4_c3e5)
            .hex32("clocklo", 0xd97b_cd80)
            .finish();
        assert_eq!(line, "setsystime clockhi=0x01d4c3e5 clocklo=0xd97bcd80");
    }

    #[test]
    fn builder_quotes_filenames() {
        let line = ArgBuilder::new("getfile")
            .quoted("NAME", r"e:\foo.bar")
            .unwrap()
            .finish();
        assert_eq!(line, r#"getfile NAME="e:\foo.bar""#);
    }

    #[test]
    fn builder_rejects_embedded_quote() {
        let err = ArgBuilder::new("delete").quoted("NAME", "bad\"name");
        assert!(matches!(err, Err(ArgumentError::QuotedContainsDoubleQuote)));
    }

    #[test]
    fn builder_rejects_embedded_newline() {
        let err = ArgBuilder::new("delete").quoted("NAME", "bad\nname");
        assert!(matches!(err, Err(ArgumentError::QuotedContainsCrlf)));
    }
}
