//! `getfile`: file downloads.

use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::ACCESS_DENIED;
use super::Continuation;
use super::CreateRequest;
use super::FileHandle;
use super::NAME_BUFFER;
use super::PoolBuffer;
use super::PoolRange;
use super::ReadTarget;
use super::SYNCHRONOUS;
use super::begin;
use super::drive::open_path;
use super::name_param;
use super::send_pool_piece;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::network::SendBufferSize;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// `getfile` reads this many bytes per chunk.
const GETFILE_CHUNK: u32 = 0x3000;

/// SO_SNDBUF for the duration of a `getfile` transfer.
const TRANSFER_SEND_BUFFER: u32 = 0x10000;

/// `getfile` transfer: a 4-byte little-endian length, then the data in
/// 0x3000-byte reads.
#[derive(Debug)]
pub struct GetFile {
    handle: FileHandle,
    buffer: PoolBuffer,
    length: u32,
    remaining: u32,
    header_sent: bool,
    chunk_sent: u32,
    chunk_length: u32,
    /// SO_SNDBUF before the transfer, restored when it ends.
    saved_send_buffer: Option<SendBufferSize>,
}

impl GetFile {
    /// A failed read sends zeros for its chunk.
    pub(super) fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> CommandResult {
        if !cx.aborted && !self.header_sent {
            self.header_sent = true;
            cx.binary[..4].copy_from_slice(&self.length.to_le_bytes());
            cx.binary_len = 4;

            // A failed query leaves the size unchanged; a saved size of 0
            // is not restored. A failed set is ignored.
            let socket = cx.session.socket;
            if let Ok(size) = cx.network.send_buffer_size(socket) {
                self.saved_send_buffer = Some(size).filter(|size| size.0 != 0);
                let _ = cx
                    .network
                    .set_send_buffer_size(socket, SendBufferSize(TRANSFER_SEND_BUFFER));
            }

            return Ok(Reply::Ok);
        }

        let refill = self.chunk_sent == self.chunk_length;
        if cx.aborted || refill && self.remaining == 0 {
            cx.backend.close_file(self.handle);
            // SAFETY: the transfer ends with this result, so the server drops
            // the continuation, the only other holder.
            unsafe { cx.backend.free_pool(self.buffer) };

            // A failed restore is ignored.
            if let Some(size) = self.saved_send_buffer {
                let _ = cx.network.set_send_buffer_size(cx.session.socket, size);
            }

            return Err(CommandError::EndOfData);
        }

        if refill {
            let count = self.remaining.min(GETFILE_CHUNK);
            let range = PoolRange {
                buffer: self.buffer,
                offset: 0,
                length: count,
            };

            if cx
                .backend
                .read_file(self.handle, None, ReadTarget::Pool(range))
                .is_err()
            {
                cx.backend.pool(self.buffer)[..count as usize].fill(0);
            }

            self.remaining -= count;
            self.chunk_length = count;
            self.chunk_sent = 0;
        }

        send_pool_piece(cx, self.buffer, 0, self.chunk_length, &mut self.chunk_sent)
    }
}

/// `getfile name=<path> [offset=<dword> size=<dword>]`.
pub(super) fn get_file(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return Err(util::MISSING);
    };

    let offset_value = invocation.line.param("offset");
    let offset = offset_value.map_or(0, |value| value.dword_prefix());
    let size = if offset_value.and_then(|value| value.dword()).is_some() {
        let Some(size) = util::required_dword(invocation, "size") else {
            return Err(util::MISSING);
        };

        size
    } else {
        0
    };

    let request = CreateRequest::open(
        AccessMask::GENERIC_READ.union(AccessMask::SYNCHRONIZE),
        ShareAccess::READ.union(ShareAccess::WRITE),
        SYNCHRONOUS,
    );
    let handle = match open_path(invocation.state, invocation.backend, name, &request) {
        Ok(handle) => handle,
        Err(error) => return Err(CommandError::from_kernel(error, ACCESS_DENIED)),
    };

    let backend = &mut *invocation.backend;
    let Ok(information) = backend.query_file_information(handle) else {
        backend.close_file(handle);
        return Err(CommandError::Unexpected);
    };

    if information.end_of_file >> 32 != 0 {
        backend.close_file(handle);
        invocation.set_text(format_args!("file is too big"));
        return Err(CommandError::Fail);
    }

    let end = information.end_of_file as u32;
    let available = if offset > end {
        0
    } else if offset == 0 {
        end
    } else {
        if let Err(error) = backend.set_file_position(handle, u64::from(offset)) {
            backend.close_file(handle);
            return Err(CommandError::from_kernel(error, ACCESS_DENIED));
        }

        end - offset
    };

    // A size of 0 sends the rest of the file.
    let length = if size != 0 {
        available.min(size)
    } else {
        available
    };

    let Some(pool) = backend.allocate_pool(GETFILE_CHUNK) else {
        backend.close_file(handle);
        return Err(CommandError::OutOfMemory);
    };

    if offset != 0 || size != 0 {
        invocation.set_text(format_args!("partial send"));
    }

    let transfer = GetFile {
        handle,
        buffer: pool,
        length,
        remaining: length,
        header_sent: false,
        chunk_sent: 0,
        chunk_length: 0,
        saved_send_buffer: None,
    };

    begin(invocation, Continuation::GetFile(transfer), None);

    Ok(Reply::Binary)
}
