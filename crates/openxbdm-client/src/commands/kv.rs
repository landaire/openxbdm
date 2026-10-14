//! Parser for XBDM's `KEY=VALUE` response lines.
//!
//! Most informational commands return a single `200- key=val key=val` head
//! line or a multiline response whose body entries are themselves lists of
//! `KEY=VALUE` pairs. Values come in the same shapes documented on
//! [`crate::protocol::args`]:
//!
//! - plain decimal (`COUNT=42`)
//! - hex (`ADDR=0x80123456`)
//! - quad (`BOXID=0q08f1c0de08f1c0de`)
//! - quoted string (`NAME="e:\foo.bar"`)
//! - bare flag (`LOCKED`)
//!
//! Keys are stored as-is but lookups are case-insensitive.

use crate::error::ParseError;
use crate::protocol::parse::KvValue;
use crate::protocol::parse::kv_tokens;
use crate::protocol::parse::run_parse;

#[derive(Debug)]
pub struct KvLine<'a> {
    pairs: Vec<(&'a str, KvValue<'a>)>,
    flags: Vec<&'a str>,
}

pub type Value<'a> = KvValue<'a>;

impl<'a> KvLine<'a> {
    pub fn get(&self, key: &str) -> Option<Value<'a>> {
        self.pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| *v)
    }

    pub fn require(&self, key: &'static str) -> Result<Value<'a>, ParseError> {
        self.get(key).ok_or(ParseError::MissingKey { key })
    }

    pub fn has_flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f.eq_ignore_ascii_case(name))
    }

    pub fn pairs(&self) -> impl Iterator<Item = (&'a str, Value<'a>)> + '_ {
        self.pairs.iter().copied()
    }

    pub fn flags(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.flags.iter().copied()
    }
}

pub fn parse_kv_line(line: &str) -> KvLine<'_> {
    match run_parse(kv_tokens, line, ParseError::UnrecognizedShape) {
        Ok(tokens) => KvLine {
            pairs: tokens.pairs,
            flags: tokens.flags,
        },
        Err(_) => KvLine {
            pairs: Vec::new(),
            flags: Vec::new(),
        },
    }
}

/// Parse a `u32` from a bare or `0x`-prefixed value.
pub fn value_u32(value: Value<'_>, key: &'static str) -> Result<u32, ParseError> {
    let raw = value.as_str();
    if let Some(stripped) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u32::from_str_radix(stripped, 16).map_err(|_| ParseError::InvalidHexDigits { key })
    } else {
        raw.parse::<u32>()
            .map_err(|_| ParseError::InvalidDecimalU32 { key })
    }
}

/// Parse a `u64` from a bare or `0x`-prefixed value.
pub fn value_u64(value: Value<'_>, key: &'static str) -> Result<u64, ParseError> {
    let raw = value.as_str();
    if let Some(stripped) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(stripped, 16).map_err(|_| ParseError::InvalidHexDigits { key })
    } else {
        raw.parse::<u64>()
            .map_err(|_| ParseError::InvalidDecimalU64 { key })
    }
}

/// Parse a quadword value (`0q` + 16 hex digits).
pub fn value_qword(value: Value<'_>, key: &'static str) -> Result<u64, ParseError> {
    let raw = value.as_str();
    let stripped = raw
        .strip_prefix("0q")
        .or_else(|| raw.strip_prefix("0Q"))
        .ok_or(ParseError::MissingQuadwordPrefix { key })?;
    if stripped.len() != 16 {
        return Err(ParseError::QuadwordWrongLength { key });
    }
    u64::from_str_radix(stripped, 16).map_err(|_| ParseError::InvalidQuadwordHex { key })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_and_decimal() {
        let kv = parse_kv_line("addr=0x80123456 size=64");
        assert_eq!(
            value_u32(kv.require("addr").unwrap(), "addr").unwrap(),
            0x8012_3456
        );
        assert_eq!(value_u32(kv.require("size").unwrap(), "size").unwrap(), 64);
    }

    #[test]
    fn parses_quoted_names_and_flags() {
        let kv = parse_kv_line(r#"NAME="e:\xex.xbe" RUNNING protected"#);
        assert_eq!(kv.require("NAME").unwrap().as_str(), r"e:\xex.xbe");
        assert!(kv.has_flag("RUNNING"));
        assert!(kv.has_flag("protected"));
    }

    #[test]
    fn parses_qword() {
        let kv = parse_kv_line("boxid=0q0011223344556677 nonce=0q8899aabbccddeeff");
        assert_eq!(
            value_qword(kv.require("boxid").unwrap(), "boxid").unwrap(),
            0x0011_2233_4455_6677
        );
        assert_eq!(
            value_qword(kv.require("nonce").unwrap(), "nonce").unwrap(),
            0x8899_aabb_ccdd_eeff
        );
    }

    #[test]
    fn missing_key_errors_typed() {
        let kv = parse_kv_line("foo=1");
        let err = kv.require("bar").unwrap_err();
        assert!(matches!(err, ParseError::MissingKey { key: "bar" }));
    }
}
