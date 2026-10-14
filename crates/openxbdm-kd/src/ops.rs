//! Request construction and reply interpretation shared by the clients.

use openxbdm_kd_core::context::CONTEXT_LEN;
use openxbdm_kd_core::context::Context;
use openxbdm_kd_core::context::ContextChunk;
use openxbdm_kd_core::manipulate::ApiNumber;
use openxbdm_kd_core::manipulate::BreakpointHandle;
use openxbdm_kd_core::manipulate::MAX_TRANSFER_LEN;
use openxbdm_kd_core::manipulate::Reply;
use openxbdm_kd_core::manipulate::ReplyBody;
use openxbdm_kd_core::manipulate::Request;
use openxbdm_kd_core::manipulate::Version;

use crate::error::KdError;
use crate::link::OwnedReply;

pub(crate) fn check_status(reply: &Reply<'_>) -> Result<(), KdError> {
    if reply.status.is_error() {
        return Err(KdError::Status {
            api: reply.api,
            status: reply.status,
        });
    }
    Ok(())
}

fn unexpected(request: Request, reply: &Reply<'_>) -> KdError {
    KdError::UnexpectedReply {
        expected: request.api(),
        actual: reply.api,
    }
}

pub(crate) fn matching_reply(request: Request, reply: OwnedReply) -> Result<OwnedReply, KdError> {
    let actual = reply.reply().api;
    if actual != request.api() {
        return Err(KdError::UnexpectedReply {
            expected: request.api(),
            actual,
        });
    }
    Ok(reply)
}

pub(crate) fn version(reply: &OwnedReply) -> Result<Version, KdError> {
    let reply = reply.reply();
    check_status(&reply)?;
    match reply.body {
        ReplyBody::Version(version) => Ok(version),
        _ => Err(KdError::UnexpectedReply {
            expected: ApiNumber::GET_VERSION,
            actual: reply.api,
        }),
    }
}

/// The next read of a `total`-byte transfer of which `done` bytes are read.
pub(crate) fn read_memory_request(address: u64, total: usize, done: usize) -> Option<Request> {
    (done < total).then(|| Request::ReadVirtualMemory {
        address: address + done as u64,
        // Bounded by MAX_TRANSFER_LEN.
        length: (total - done).min(MAX_TRANSFER_LEN) as u32,
    })
}

pub(crate) fn copy_read_memory(
    reply: &OwnedReply,
    request: Request,
    out: &mut [u8],
) -> Result<usize, KdError> {
    let reply = reply.reply();
    let ReplyBody::ReadMemory { data, .. } = reply.body else {
        return Err(unexpected(request, &reply));
    };
    let copied = data.len().min(out.len());
    out[..copied].copy_from_slice(&data[..copied]);
    Ok(copied)
}

pub(crate) fn read_complete(request: Request, copied: usize) -> bool {
    match request {
        Request::ReadVirtualMemory { length, .. } => copied == length as usize,
        _ => false,
    }
}

pub(crate) fn write_memory_requests(
    address: u64,
    bytes: &[u8],
) -> impl Iterator<Item = (Request, &[u8])> {
    bytes
        .chunks(MAX_TRANSFER_LEN)
        .enumerate()
        .map(move |(index, chunk)| {
            let request = Request::WriteVirtualMemory {
                address: address + (index * MAX_TRANSFER_LEN) as u64,
                // Bounded by MAX_TRANSFER_LEN.
                length: chunk.len() as u32,
            };
            (request, chunk)
        })
}

pub(crate) fn check_write_memory(reply: &OwnedReply, requested: usize) -> Result<(), KdError> {
    let reply = reply.reply();
    let ReplyBody::WriteMemory { actual, .. } = reply.body else {
        return Err(KdError::UnexpectedReply {
            expected: ApiNumber::WRITE_VIRTUAL_MEMORY,
            actual: reply.api,
        });
    };
    if actual as usize != requested {
        return Err(KdError::ShortTransfer {
            api: reply.api,
            requested,
            actual: actual as usize,
        });
    }
    Ok(())
}

pub(crate) fn copy_context_range(
    reply: &OwnedReply,
    chunk: ContextChunk,
    out: &mut [u8; CONTEXT_LEN],
) -> Result<(), KdError> {
    let reply = reply.reply();
    check_status(&reply)?;
    let ReplyBody::ReadContextRange { data, .. } = reply.body else {
        return Err(KdError::UnexpectedReply {
            expected: ApiNumber::READ_CONTEXT_RANGE,
            actual: reply.api,
        });
    };
    let length = chunk.length as usize;
    if data.len() != length {
        return Err(KdError::ShortTransfer {
            api: reply.api,
            requested: length,
            actual: data.len(),
        });
    }
    let offset = chunk.offset as usize;
    out[offset..offset + length].copy_from_slice(data);
    Ok(())
}

pub(crate) fn write_context_request(context: &Context, chunk: ContextChunk) -> (Request, &[u8]) {
    let offset = chunk.offset as usize;
    let data = &context.as_bytes()[offset..offset + chunk.length as usize];
    (
        Request::WriteContextRange {
            offset: chunk.offset,
            length: chunk.length,
        },
        data,
    )
}

pub(crate) fn check_breakpoint_address(address: u64) -> Result<(), KdError> {
    if !address.is_multiple_of(4) {
        return Err(KdError::UnalignedBreakpoint { address });
    }
    Ok(())
}

pub(crate) fn breakpoint_handle(
    reply: &OwnedReply,
    address: u64,
) -> Result<BreakpointHandle, KdError> {
    let reply = reply.reply();
    match reply.body {
        ReplyBody::WriteBreakpoint {
            handle: Some(handle),
            ..
        } if !reply.status.is_error() => Ok(handle),
        _ => Err(KdError::BreakpointRejected { address }),
    }
}
