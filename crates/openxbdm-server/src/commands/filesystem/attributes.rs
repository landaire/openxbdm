//! File size and attributes: `fileeof`, `getfileattributes`, `getvfattr`, and
//! `setfileattributes`.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::KernelError;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::ACCESS_DENIED;
use super::BasicInformation;
use super::Continuation;
use super::CreateRequest;
use super::FileTime;
use super::NAME_BUFFER;
use super::PoolBuffer;
use super::SYNCHRONOUS;
use super::begin;
use super::close_changed;
use super::drive::is_device_path;
use super::drive::open_path;
use super::drive::open_translated;
use super::name_param;
use super::optional_dword;
use super::send_pool_piece;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// `getvfattr` receives each piece into a 0x141-byte area.
const VFATTR_RECEIVE_AREA: u32 = 0x141;

/// Bytes per `getvfattr` record.
const VFATTR_RECORD: u32 = 0x1c;

/// `getvfattr` progress.
#[derive(Debug)]
pub struct VirtualAttributes {
    buffer: Option<PoolBuffer>,
    count: u32,
    index: u32,
    phase: VirtualAttributesPhase,
}

impl VirtualAttributes {
    fn release(&mut self, backend: &mut dyn crate::backend::Backend) {
        if let Some(buffer) = self.buffer.take() {
            // SAFETY: the continuation held the only copy, taken out above;
            // `resume` checks for it before any further use.
            unsafe { backend.free_pool(buffer) };
        }
    }

    pub(super) fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> CommandResult {
        if let VirtualAttributesPhase::Send { sent } = &mut self.phase {
            let Some(buffer) = self.buffer else {
                return Err(CommandError::EndOfData);
            };

            let total = self.count.wrapping_mul(VFATTR_RECORD);
            if cx.aborted || *sent >= total {
                self.release(cx.backend);
                return Err(CommandError::EndOfData);
            }

            return send_pool_piece(cx, buffer, VFATTR_RECEIVE_AREA, total, sent);
        }

        let mut remaining = cx.session.receive_remaining.unwrap_or(0);
        if cx.received.is_empty() && remaining != 0 {
            self.release(cx.backend);
            return Err(CommandError::Fail);
        }

        let Some(buffer) = self.buffer else {
            return Ok(Reply::Ok);
        };

        if self.count == 0 {
            // The image frees the block on the first piece and keeps
            // receiving without ever completing.
            self.release(cx.backend);
            return Err(CommandError::EndOfData);
        }

        for piece in cx.received.chunks(VFATTR_RECEIVE_AREA as usize) {
            cx.backend.pool(buffer)[..piece.len()].copy_from_slice(piece);
        }

        remaining -= cx.received.len() as u32;
        cx.session.receive_remaining = Some(remaining);
        if remaining != 0 {
            return Ok(Reply::Ok);
        }

        match self.phase {
            VirtualAttributesPhase::Length => {
                let pool = cx.backend.pool(buffer);
                let length = u32::from_be_bytes([pool[0], pool[1], pool[2], pool[3]]);
                cx.session.receive_remaining = Some(length);
                self.phase = VirtualAttributesPhase::Name;

                if length == 0 {
                    self.release(cx.backend);
                }

                Ok(Reply::Ok)
            }
            VirtualAttributesPhase::Name => {
                let mut name = [0u8; VFATTR_RECEIVE_AREA as usize];
                name.copy_from_slice(&cx.backend.pool(buffer)[..VFATTR_RECEIVE_AREA as usize]);
                let length = name
                    .iter()
                    .position(|&byte| byte == 0)
                    .unwrap_or(name.len());
                let name = &name[..length];
                let result = if is_device_path(name) {
                    cx.backend
                        .query_full_attributes(&name[..name.len().min(0x140)])
                } else {
                    match cx.state.filesystem.drives.translate(cx.backend, name) {
                        Some(path) => cx.backend.query_full_attributes(path.as_bytes()),
                        None => Err(KernelError::NoSuchFile),
                    }
                };

                let record: [u32; 7] = match result {
                    Ok(information) => [
                        information.creation_time.high(),
                        information.creation_time.low(),
                        information.last_write_time.high(),
                        information.last_write_time.low(),
                        (information.end_of_file >> 32) as u32,
                        information.end_of_file as u32,
                        information.attributes.bits(),
                    ],
                    Err(_) => [0, 0, 0, 0, 0, 0, u32::MAX],
                };

                let start = (VFATTR_RECEIVE_AREA + self.index * VFATTR_RECORD) as usize;
                let pool = cx.backend.pool(buffer);
                let slot = &mut pool[start..start + VFATTR_RECORD as usize];

                for (index, value) in record.iter().enumerate() {
                    slot[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
                }

                self.index += 1;
                if self.index == self.count {
                    self.phase = VirtualAttributesPhase::Send { sent: 0 };
                    return Ok(Reply::Binary);
                }

                cx.session.receive_remaining = Some(4);
                self.phase = VirtualAttributesPhase::Length;

                Ok(Reply::Ok)
            }
            VirtualAttributesPhase::Send { .. } => Ok(Reply::Ok),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VirtualAttributesPhase {
    Length,
    Name,
    Send { sent: u32 },
}

/// `getfileattributes name=<path>`.
pub(super) fn get_file_attributes(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return Err(util::MISSING);
    };

    let result = if is_device_path(name) {
        invocation.backend.query_full_attributes(name)
    } else {
        let Some(path) = invocation
            .state
            .filesystem
            .drives
            .translate(invocation.backend, name)
        else {
            return Err(ErrorCode::Undefined.into());
        };

        invocation.backend.query_full_attributes(path.as_bytes())
    };

    match result {
        Err(error) => Err(CommandError::from_kernel(error, ACCESS_DENIED)),
        Ok(information) => {
            begin(
                invocation,
                Continuation::FileAttributes(Some(information)),
                None,
            );
            Ok(Reply::Multiline)
        }
    }
}

/// `getvfattr count=<dword>`, then `count` names, each a big-endian
/// length and the name bytes; replies with 0x1c-byte records.
pub(super) fn get_vfattr(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(count) = util::required_dword(invocation, "count") else {
        return Err(util::MISSING);
    };

    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let size = count
        .wrapping_mul(VFATTR_RECORD)
        .wrapping_add(VFATTR_RECEIVE_AREA);
    let Some(buffer) = invocation.backend.allocate_pool(size) else {
        return Err(CommandError::OutOfMemory);
    };

    let transfer = VirtualAttributes {
        buffer: Some(buffer),
        count,
        index: 0,
        phase: VirtualAttributesPhase::Length,
    };

    begin(
        invocation,
        Continuation::VirtualAttributes(transfer),
        Some(4),
    );

    Ok(Reply::SendBinary)
}

/// `setfileattributes name=<path> [readonly=] [hidden=] [createhi= createlo=]
/// [changehi= changelo=]`.
pub(super) fn set_file_attributes(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return Err(util::MISSING);
    };

    let request = CreateRequest::open(
        AccessMask::SYNCHRONIZE,
        ShareAccess::READ.union(ShareAccess::WRITE),
        SYNCHRONOUS,
    );
    let handle = match open_translated(invocation.state, invocation.backend, name, &request) {
        Ok(handle) => handle,
        Err(error) => return Err(CommandError::from_kernel(error, ACCESS_DENIED)),
    };

    let mut mask = 0;
    let mut value = 0;

    for (key, bit) in [
        ("readonly", FileAttributes::READONLY.bits()),
        ("hidden", FileAttributes::HIDDEN.bits()),
    ] {
        if let Some(flag) = invocation.line.dword(key) {
            mask |= bit;
            if flag != 0 {
                value |= bit;
            }
        }
    }

    let time = |high: &str, low: &str| {
        FileTime::from_parts(
            optional_dword(invocation, high, 0),
            optional_dword(invocation, low, 0),
        )
    };

    let creation_time = time("createhi", "createlo");
    let last_write_time = time("changehi", "changelo");
    let backend = &mut *invocation.backend;
    let result = backend
        .query_file_information(handle)
        .and_then(|information| {
            let attributes = match information.attributes.bits() & !mask | value & mask {
                0 => FileAttributes::NORMAL.bits(),
                attributes => attributes,
            };
            let basic = BasicInformation {
                creation_time,
                last_access_time: FileTime(0),
                last_write_time,
                change_time: FileTime(0),
                attributes: FileAttributes::from_bits_retain(attributes),
            };

            backend.set_basic_information(handle, &basic)
        });
    close_changed(invocation.backend, handle);

    match result {
        Ok(()) => Ok(Reply::Ok),
        Err(error) => Err(CommandError::from_kernel(error, CommandError::Fail)),
    }
}

/// `fileeof name=<path> size=<dword> [mustcreate|cancreate]`.
pub(super) fn file_eof(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return Err(util::MISSING);
    };

    let Some(size) = util::required_dword(invocation, "size") else {
        return Err(util::MISSING);
    };

    let disposition = if invocation.line.has("mustcreate") {
        CreateDisposition::Create
    } else if invocation.line.has("cancreate") {
        CreateDisposition::OverwriteIf
    } else {
        CreateDisposition::Open
    };

    let request = CreateRequest {
        access: AccessMask::GENERIC_WRITE
            .union(AccessMask::DELETE)
            .union(AccessMask::SYNCHRONIZE),
        allocation_size: Some(u64::from(size)),
        attributes: FileAttributes::empty(),
        share: ShareAccess::empty(),
        disposition,
        options: SYNCHRONOUS,
    };

    let handle = match open_path(invocation.state, invocation.backend, name, &request) {
        Ok(handle) => handle,
        Err(error) => return Err(CommandError::from_kernel(error, ACCESS_DENIED)),
    };

    let result = invocation.backend.set_end_of_file(handle, u64::from(size));
    close_changed(invocation.backend, handle);

    match result {
        Ok(()) => Ok(Reply::Ok),
        Err(error) => Err(CommandError::from_kernel(error, ACCESS_DENIED)),
    }
}
