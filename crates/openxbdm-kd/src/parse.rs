//! Parsers for command-line and interactive command values.

use std::net::IpAddr;
use std::net::SocketAddr;

use crate::error::ValueError;
use crate::transport::DEFAULT_PORT;

/// `IP` or `IP:PORT`; the port defaults to the stock kdnet port.
pub fn parse_target(text: &str) -> Result<SocketAddr, ValueError> {
    if let Ok(address) = text.parse::<SocketAddr>() {
        return Ok(address);
    }

    text.parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, DEFAULT_PORT))
        .map_err(|error| ValueError::Address {
            text: text.to_owned(),
            error,
        })
}

/// Hex with a `0x` prefix, or decimal.
pub fn parse_u64(text: &str) -> Result<u64, ValueError> {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };

    parsed.map_err(|error| ValueError::Integer {
        text: text.to_owned(),
        error,
    })
}

/// Bytes as pairs of hex digits.
pub(crate) fn parse_hex(text: &str) -> Result<Vec<u8>, ValueError> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return Err(ValueError::OddHexLength {
            text: text.to_owned(),
        });
    }

    (0..text.len())
        .step_by(2)
        .map(|idx| {
            text.get(idx..idx + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| ValueError::NotHex {
                    text: text.to_owned(),
                })
        })
        .collect()
}
