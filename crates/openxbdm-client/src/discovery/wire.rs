//! Pure NAP wire encoder/decoder.

use std::net::SocketAddr;

use winnow::error::ContextError;
use winnow::error::ErrMode;
use winnow::prelude::*;
use winnow::token::any;
use winnow::token::take;

/// UDP port on which XBDM listens for name-resolution packets (730, same
/// as the command port but on UDP instead of TCP).
pub const NAP_PORT: u16 = crate::XBDM_PORT;

/// Maximum console name length supported by the protocol: `namelen` is a
/// single unsigned byte.
pub const MAX_NAME_LEN: usize = 255;

/// Request opcode. The low seven bits select the operation; with the high
/// bit (0x80) set the console sends its reply to the broadcast address
/// instead of the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOpcode {
    /// `0x01`: "do you have this name?" The console only replies when its
    /// own `dbgname` equals the supplied name.
    LookupName = 0x01,
    /// `0x03`: "what is your name?" Every console on the segment replies
    /// with its own `dbgname` regardless of the request body.
    WhatIsYourName = 0x03,
}

/// Response opcode emitted by XBDM. The parser rejects any other value.
pub const RESPONSE_OPCODE: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NapRequest {
    pub opcode: RequestOpcode,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NapResponse {
    pub name: String,
}

/// Result of a single observed reply: the console's name, and the UDP
/// socket address we received it from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredConsole {
    pub name: String,
    pub addr: SocketAddr,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum NapError {
    #[error("name is longer than {MAX_NAME_LEN} bytes and cannot fit in a NAP packet")]
    NameTooLong,
    #[error("name contains NUL, CR, or LF; the console compares names only up to a NUL")]
    NameContainsControlChar,
    #[error("response packet was empty")]
    EmptyPacket,
    #[error("response opcode was {got:#04x}; expected {expected:#04x}")]
    UnexpectedOpcode { expected: u8, got: u8 },
    #[error("response packet was truncated (header says {expected} name bytes, got {got})")]
    Truncated { expected: usize, got: usize },
    #[error("response name contained non-UTF-8 bytes")]
    NonUtf8Name,
}

impl RequestOpcode {
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

impl NapRequest {
    pub fn lookup(name: impl Into<String>) -> Self {
        Self {
            opcode: RequestOpcode::LookupName,
            name: name.into(),
        }
    }

    pub fn what_is_your_name() -> Self {
        Self {
            opcode: RequestOpcode::WhatIsYourName,
            name: String::new(),
        }
    }
}

pub fn encode_request(request: &NapRequest) -> Result<Vec<u8>, NapError> {
    let bytes = request.name.as_bytes();
    if bytes.len() > MAX_NAME_LEN {
        return Err(NapError::NameTooLong);
    }
    if bytes.iter().any(|&b| matches!(b, 0 | b'\r' | b'\n')) {
        return Err(NapError::NameContainsControlChar);
    }
    let mut buf = Vec::with_capacity(2 + bytes.len());
    buf.push(request.opcode.as_byte());
    buf.push(bytes.len() as u8);
    buf.extend_from_slice(bytes);
    Ok(buf)
}

pub fn parse_response(packet: &[u8]) -> Result<NapResponse, NapError> {
    let mut input = packet;
    parser_response
        .parse_next(&mut input)
        .map_err(|_| classify_parse_failure(packet))
}

fn classify_parse_failure(packet: &[u8]) -> NapError {
    if packet.is_empty() {
        return NapError::EmptyPacket;
    }
    if packet[0] != RESPONSE_OPCODE {
        return NapError::UnexpectedOpcode {
            expected: RESPONSE_OPCODE,
            got: packet[0],
        };
    }
    if packet.len() < 2 {
        return NapError::Truncated {
            expected: 0,
            got: 0,
        };
    }
    let expected = packet[1] as usize;
    let got = packet.len().saturating_sub(2);
    if got < expected {
        return NapError::Truncated { expected, got };
    }
    NapError::NonUtf8Name
}

fn parser_response(input: &mut &[u8]) -> Result<NapResponse, ErrMode<ContextError>> {
    any.verify(|b: &u8| *b == RESPONSE_OPCODE)
        .parse_next(input)?;
    let namelen = any.parse_next(input)? as usize;
    let raw = take(namelen).parse_next(input)?;
    let name = core::str::from_utf8(raw)
        .map(|s| s.to_owned())
        .map_err(|_| ErrMode::Backtrack(ContextError::new()))?;
    Ok(NapResponse { name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_lookup_request() {
        let req = NapRequest::lookup("deanxbox");
        let bytes = encode_request(&req).unwrap();
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 8);
        assert_eq!(&bytes[2..], b"deanxbox");
    }

    #[test]
    fn encodes_identify_request() {
        let req = NapRequest::what_is_your_name();
        let bytes = encode_request(&req).unwrap();
        assert_eq!(bytes, vec![0x03, 0x00]);
    }

    #[test]
    fn rejects_names_with_control_characters() {
        let req = NapRequest::lookup("bad\nname");
        assert_eq!(encode_request(&req), Err(NapError::NameContainsControlChar));
    }

    #[test]
    fn rejects_names_over_limit() {
        let req = NapRequest::lookup("a".repeat(MAX_NAME_LEN + 1));
        assert_eq!(encode_request(&req), Err(NapError::NameTooLong));
    }

    #[test]
    fn parses_valid_response() {
        let packet = [0x02, 0x08, b'd', b'e', b'a', b'n', b'x', b'b', b'o', b'x'];
        let parsed = parse_response(&packet).unwrap();
        assert_eq!(parsed.name, "deanxbox");
    }

    #[test]
    fn rejects_empty_response() {
        assert_eq!(parse_response(&[]), Err(NapError::EmptyPacket));
    }

    #[test]
    fn rejects_bad_opcode() {
        let err = parse_response(&[0x42, 0x00]).unwrap_err();
        assert!(matches!(err, NapError::UnexpectedOpcode { got: 0x42, .. }));
    }

    #[test]
    fn rejects_truncated_body() {
        let err = parse_response(&[0x02, 0x05, b'a']).unwrap_err();
        assert!(matches!(
            err,
            NapError::Truncated {
                expected: 5,
                got: 1
            }
        ));
    }
}
