//! Fixed-offset field readers and writers.
//!
//! Callers check the buffer length before reading, so the readers report
//! a short buffer as [`DecodeError::Truncated`] only as a defensive path.

use winnow::Parser;
use winnow::binary::be_u32;
use winnow::binary::be_u64;
use winnow::binary::le_u16;
use winnow::binary::le_u32;
use winnow::binary::le_u64;
use winnow::error::ContextError;

use crate::DecodeError;

fn field<'a, O>(
    bytes: &'a [u8],
    offset: usize,
    width: usize,
    mut parser: impl Parser<&'a [u8], O, ContextError>,
) -> Result<O, DecodeError> {
    let truncated = DecodeError::Truncated {
        needed: offset + width,
        actual: bytes.len(),
    };
    let mut input = bytes.get(offset..offset + width).ok_or(truncated.clone())?;
    parser.parse_next(&mut input).map_err(|_| truncated)
}

pub(crate) fn le16(bytes: &[u8], offset: usize) -> Result<u16, DecodeError> {
    field(bytes, offset, 2, le_u16)
}

pub(crate) fn le32(bytes: &[u8], offset: usize) -> Result<u32, DecodeError> {
    field(bytes, offset, 4, le_u32)
}

pub(crate) fn le64(bytes: &[u8], offset: usize) -> Result<u64, DecodeError> {
    field(bytes, offset, 8, le_u64)
}

pub(crate) fn be32(bytes: &[u8], offset: usize) -> Result<u32, DecodeError> {
    field(bytes, offset, 4, be_u32)
}

pub(crate) fn be64(bytes: &[u8], offset: usize) -> Result<u64, DecodeError> {
    field(bytes, offset, 8, be_u64)
}

pub(crate) fn require(bytes: &[u8], needed: usize) -> Result<(), DecodeError> {
    if bytes.len() < needed {
        return Err(DecodeError::Truncated {
            needed,
            actual: bytes.len(),
        });
    }
    Ok(())
}

pub(crate) fn put_le16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_le32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_le64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
