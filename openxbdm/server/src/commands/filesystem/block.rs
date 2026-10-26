//! Raw device block access: `dvdblk`, `gethddblk`, `sethddblk`, and `fmtfat`.

use openxbdm_core::status::ErrorCode;

use super::ACCESS_DENIED;
use super::Continuation;
use super::DeviceObject;
use super::PoolBuffer;
use super::PoolRange;
use super::TransferDirection;
use super::begin;
use super::send_pool_piece;
use super::string_param;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::notify::ExecutionState;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// Block device sector sizes.
const HDD_SECTOR: u32 = 0x200;
const HDD_MAX_BLOCKS: u32 = 0x100;

/// A raw device read sent as one 203 body.
#[derive(Debug)]
pub struct BlockRead {
    buffer: PoolBuffer,
    length: u32,
    sent: u32,
}

impl BlockRead {
    pub(super) fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> CommandResult {
        if cx.aborted || self.sent >= self.length {
            // SAFETY: the transfer ends with this result, so the server drops
            // the continuation, the only other holder.
            unsafe { cx.backend.free_pool(self.buffer) };
            return Err(CommandError::EndOfData);
        }

        send_pool_piece(cx, self.buffer, 0, self.length, &mut self.sent)
    }
}

/// `sethddblk` upload.
#[derive(Debug)]
pub struct BlockWrite {
    device: DeviceObject,
    buffer: PoolBuffer,
    block: u32,
    length: u32,
}

impl BlockWrite {
    pub(super) fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> CommandResult {
        let remaining = cx.session.receive_remaining.unwrap_or(0);
        if cx.received.is_empty() {
            // SAFETY: `receive_remaining` is 0, so the server drops the
            // continuation, the only other holder, after this result.
            unsafe { cx.backend.free_pool(self.buffer) };
            // SAFETY: `receive_remaining` is 0, so the server drops the
            // continuation, the only other holder, after this result.
            unsafe { cx.backend.dereference_device(self.device) };
            cx.session.receive_remaining = Some(0);
            return Err(CommandError::Fail);
        }

        let start = (self.length - remaining) as usize;
        let count = cx.received.len();
        cx.backend.pool(self.buffer)[start..start + count].copy_from_slice(cx.received);
        let remaining = remaining - count as u32;
        cx.session.receive_remaining = Some(remaining);
        if remaining != 0 {
            return Ok(Reply::Ok);
        }

        let range = PoolRange {
            buffer: self.buffer,
            offset: 0,
            length: self.length,
        };

        let offset = u64::from(self.block) * u64::from(HDD_SECTOR);
        let result =
            cx.backend
                .transfer_device(self.device, TransferDirection::Write, offset, range);
        // SAFETY: `receive_remaining` is 0, so the server drops the
        // continuation, the only other holder, after this result.
        unsafe { cx.backend.dereference_device(self.device) };
        // SAFETY: `receive_remaining` is 0, so the server drops the
        // continuation, the only other holder, after this result.
        unsafe { cx.backend.free_pool(self.buffer) };

        match result {
            Ok(()) => Ok(Reply::Ok),
            Err(_) => Err(CommandError::Unexpected),
        }
    }
}

/// Transfer length from the `count` parameter of the block commands. A
/// count that does not parse leaves the text `missing count` and uses its
/// parsed prefix as a byte length without the limit check.
fn block_length(invocation: &mut Invocation<'_>, limit: u32, sector: u32) -> Option<u32> {
    let value = invocation.line.param("count");

    match value.and_then(|value| value.dword()) {
        Some(count) if count > limit => {
            invocation.set_text(format_args!("Invalid block count: '{}'.", count as i32));
            None
        }
        Some(count) => Some(count * sector),
        None => {
            invocation.set_text(format_args!("missing count"));
            Some(value.map_or(0, |value| value.dword_prefix()))
        }
    }
}

fn read_blocks(
    invocation: &mut Invocation<'_>,
    device: &[u8],
    block: u32,
    length: u32,
    sector: u32,
) -> CommandResult {
    let backend = &mut *invocation.backend;
    let Ok(object) = backend.reference_device(device) else {
        return Err(CommandError::Fail);
    };

    let Some(buffer) = backend.allocate_pool(length) else {
        // SAFETY: the block is local to this command and not used after.
        unsafe { backend.dereference_device(object) };
        return Err(CommandError::Fail);
    };

    let range = PoolRange {
        buffer,
        offset: 0,
        length,
    };

    let offset = u64::from(block) * u64::from(sector);
    let result = backend.transfer_device(object, TransferDirection::Read, offset, range);
    // SAFETY: the block is local to this command and not used after.
    unsafe { backend.dereference_device(object) };
    if result.is_err() {
        // SAFETY: the block is local to this command and not used after.
        unsafe { backend.free_pool(buffer) };
        return Err(CommandError::Fail);
    }

    begin(
        invocation,
        Continuation::BlockRead(BlockRead {
            buffer,
            length,
            sent: 0,
        }),
        None,
    );

    Ok(Reply::Binary)
}

/// `dvdblk block=<dword> count=<dword>`: read 2048-byte optical sectors.
pub(super) fn dvd_block(invocation: &mut Invocation<'_>) -> CommandResult {
    const DVD_SECTOR: u32 = 0x800;
    const DVD_MAX_BLOCKS: u32 = 0x40;

    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let Some(block) = util::required_dword(invocation, "block") else {
        return Err(util::MISSING);
    };

    let Some(length) = block_length(invocation, DVD_MAX_BLOCKS, DVD_SECTOR) else {
        return Err(CommandError::Fail);
    };

    read_blocks(invocation, b"\\Device\\Cdrom0", block, length, DVD_SECTOR)
}

/// `gethddblk name=<device> block=<dword> count=<dword>`: read 512-byte
/// sectors of a named device.
pub(super) fn get_hdd_block(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let mut buffer = [0u8; 0x100];
    let Some(name) = string_param(invocation, "name", &mut buffer) else {
        return Err(CommandError::Fail);
    };

    let Some(block) = util::required_dword(invocation, "block") else {
        return Err(util::MISSING);
    };

    let Some(length) = block_length(invocation, HDD_MAX_BLOCKS, HDD_SECTOR) else {
        return Err(CommandError::Fail);
    };

    read_blocks(invocation, name, block, length, HDD_SECTOR)
}

/// `sethddblk name=<device> block=<dword> count=<dword>`, then the sector
/// data.
pub(super) fn set_hdd_block(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let mut buffer = [0u8; 0x100];
    let Some(name) = string_param(invocation, "name", &mut buffer) else {
        return Err(CommandError::Fail);
    };

    let Some(block) = util::required_dword(invocation, "block") else {
        return Err(util::MISSING);
    };

    let Some(length) = block_length(invocation, HDD_MAX_BLOCKS, HDD_SECTOR) else {
        return Err(CommandError::Fail);
    };

    let backend = &mut *invocation.backend;
    let Ok(device) = backend.reference_device(name) else {
        return Err(CommandError::Fail);
    };

    let Some(pool) = backend.allocate_pool(length) else {
        // SAFETY: the transfer was not started, so this command holds the only
        // copy.
        unsafe { backend.dereference_device(device) };
        return Err(CommandError::Fail);
    };

    begin(
        invocation,
        Continuation::BlockWrite(BlockWrite {
            device,
            buffer: pool,
            block,
            length,
        }),
        Some(length),
    );

    Ok(Reply::SendBinary)
}

/// `fmtfat partition=<1..5> [force=<dword>]`: format a hard disk
/// partition as XTAF.
pub(super) fn format_fat(invocation: &mut Invocation<'_>) -> CommandResult {
    /// XTAF cluster size.
    const FORMAT_CLUSTER_SIZE: u32 = 0x4000;

    let force_value = invocation.line.param("force");
    if force_value.and_then(|value| value.dword()).is_none() {
        invocation.set_text(format_args!("missing force"));
    }

    let force = force_value.map_or(0, |value| value.dword_prefix());
    if force == 0 && invocation.backend.execution_state() != ExecutionState::Pending {
        invocation.set_text(format_args!("not stopped"));
        return Err(ErrorCode::NotStopped.into());
    }

    let Some(partition) = util::required_dword(invocation, "partition") else {
        return Err(util::MISSING);
    };

    if !(1..=5).contains(&partition) {
        return Err(ErrorCode::FileNotFound.into());
    }

    let mut device = *b"\\Device\\Harddisk0\\Partition0";
    device[device.len() - 1] = b'0' + partition as u8;

    match invocation
        .backend
        .format_partition(&device, FORMAT_CLUSTER_SIZE)
    {
        Ok(()) => Ok(Reply::Ok),
        Err(_) => {
            invocation.set_text(format_args!("unable to format"));
            Err(ACCESS_DENIED)
        }
    }
}
