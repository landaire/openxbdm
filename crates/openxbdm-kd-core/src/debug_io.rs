//! Debug I/O messages (packet type 3): kernel debug output and prompts.
//!
//! Message header, little-endian (0x801b5de0):
//!
//! | Offset | Size | Field |
//! |-------:|-----:|-------|
//! | 0x00 | 4 | api: 0x3230 print, 0x3231 prompt |
//! | 0x04 | 2 | processor level (zero) |
//! | 0x06 | 2 | processor |
//! | 0x08 | 4 | text length |
//! | 0x0c | 4 | prompt only: capacity of the reply buffer |
//!
//! The text follows the header. A prompt (0x801b4b28) waits until the
//! host sends a prompt message back whose data is the reply text.

use crate::DecodeError;
use crate::manipulate::Processor;
use crate::wire;

pub const HEADER_LEN: usize = 0x10;
pub const PRINT: u32 = 0x3230;
pub const PROMPT: u32 = 0x3231;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DebugIo<'a> {
    Print {
        processor: Processor,
        text: &'a [u8],
    },
    Prompt {
        processor: Processor,
        text: &'a [u8],
        reply_capacity: u32,
    },
    Other {
        api: u32,
        data: &'a [u8],
    },
}

impl<'a> DebugIo<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self, DecodeError> {
        if payload.len() < HEADER_LEN {
            return Err(DecodeError::MessageHeaderLength {
                expected: HEADER_LEN,
                actual: payload.len(),
            });
        }
        let api = wire::le32(payload, 0)?;
        let processor = Processor(wire::le16(payload, 6)?);
        let text = &payload[HEADER_LEN..];
        Ok(match api {
            PRINT => Self::Print { processor, text },
            PROMPT => Self::Prompt {
                processor,
                text,
                reply_capacity: wire::le32(payload, 0xc)?,
            },
            api => Self::Other { api, data: text },
        })
    }
}

/// Header of the host's reply to a prompt; `reply_length` data bytes follow.
pub fn encode_prompt_reply(reply_length: u32) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    wire::put_le32(&mut out, 0, PROMPT);
    wire::put_le32(&mut out, 8, reply_length);
    out
}
