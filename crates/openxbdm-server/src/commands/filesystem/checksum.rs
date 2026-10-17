//! `getsum` block checksums.

use openxbdm_core::status::ErrorCode;

use super::Continuation;
use super::begin;
use crate::commands::memory::PAGE_SIZE;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// `getsum` progress.
#[derive(Debug)]
pub struct Checksum {
    address: u32,
    block_size: u32,
    remaining: u32,
}

impl Checksum {
    pub(super) fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> CommandResult {
        /// Bytes of block checksums emitted per call.
        const GETSUM_CHUNK: u32 = 0x1000;

        if cx.aborted || self.remaining == 0 {
            return Err(CommandError::EndOfData);
        }

        let count = self.remaining.min(GETSUM_CHUNK);

        for slot in cx.binary[..count as usize].as_chunks_mut::<4>().0 {
            let value = block_checksum(cx.backend, self.address, self.block_size);
            slot.copy_from_slice(&value.to_be_bytes());
            self.address = self.address.wrapping_add(self.block_size);
        }

        self.remaining -= count;
        cx.binary_len = count as usize;

        Ok(Reply::Ok)
    }
}

/// `getsum ADDR=<dword> LENGTH=<dword> BLOCKSIZE=<dword>`: one CRC per
/// block of target memory, 0 for blocks touching an unreadable page.
pub(super) fn get_sum(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(address) = util::required_dword(invocation, "ADDR") else {
        return Err(util::MISSING);
    };

    let Some(length) = util::required_dword(invocation, "LENGTH") else {
        return Err(util::MISSING);
    };

    let Some(block_size) = util::required_dword(invocation, "BLOCKSIZE") else {
        return Err(util::MISSING);
    };

    if block_size == 0 {
        invocation.set_text(format_args!("Zero BLOCKSIZE not allowed."));
        return Err(ErrorCode::BadParameter.into());
    }

    let remaining = (length / block_size).wrapping_mul(4);
    if !begin(
        invocation,
        Continuation::Checksum(Checksum {
            address,
            block_size,
            remaining,
        }),
        None,
    ) {
        return Err(CommandError::Fail);
    }

    Ok(Reply::Binary)
}

fn block_checksum(backend: &mut dyn crate::backend::Backend, address: u32, size: u32) -> u32 {
    let last = address.wrapping_add(size - 1) & !(PAGE_SIZE - 1);
    let mut page = address & !(PAGE_SIZE - 1);

    loop {
        if !backend.is_readable(page) {
            return 0;
        }

        if page == last {
            break;
        }

        page = page.wrapping_add(PAGE_SIZE);
    }

    let mut crc = u32::MAX;
    let mut chunk = [0u8; 0x100];
    let mut offset = 0u32;

    while offset < size {
        let count = (size - offset).min(chunk.len() as u32) as usize;
        // SAFETY: the loop above accepted every page from `address` to the
        // last byte of the block.
        unsafe { backend.read_memory(address.wrapping_add(offset), &mut chunk[..count]) };

        // CRC-32/MPEG-2 (polynomial 0x04c11db7, most significant bit
        // first) computed bitwise as the image does, without a table.
        for &byte in &chunk[..count] {
            crc ^= u32::from(byte) << 24;

            for _ in 0..8 {
                crc = if crc & 0x8000_0000 != 0 {
                    (crc << 1) ^ 0x04c1_1db7
                } else {
                    crc << 1
                };
            }
        }

        offset += count as u32;
    }

    crc
}
