//! Volume listing: `drivefreespace` and `drivelist`.

use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::ACCESS_DENIED;
use super::Continuation;
use super::CreateRequest;
use super::DIRECTORY;
use super::FileHandle;
use super::LINE_BUFFER;
use super::NAME_BUFFER;
use super::ObjectDirectory;
use super::PoolBuffer;
use super::SliceWriter;
use super::begin;
use super::drive::open_translated;
use super::name_param;
use super::send_pool_line;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// `drivelist` progress: drive letters from `\??`, then the drive table.
#[derive(Debug)]
pub enum DriveList {
    Objects {
        directory: ObjectDirectory,
        context: u32,
    },
    Table {
        index: usize,
    },
}

/// `drivefreespace name=<path>`.
pub(super) fn drive_free_space(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return Err(util::MISSING);
    };

    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let Some(line) = invocation.backend.allocate_pool(LINE_BUFFER) else {
        return Err(CommandError::Fail);
    };

    let request = CreateRequest::open(
        AccessMask::LIST_DIRECTORY.union(AccessMask::SYNCHRONIZE),
        ShareAccess::READ.union(ShareAccess::WRITE),
        DIRECTORY,
    );

    // The image keeps the line buffer allocated when the open fails.
    match open_translated(invocation.state, invocation.backend, name, &request) {
        Err(error) => Err(CommandError::from_kernel(error, ACCESS_DENIED)),
        Ok(handle) => {
            begin(
                invocation,
                Continuation::DriveFreeSpace {
                    handle,
                    first: true,
                    line,
                },
                None,
            );
            Ok(Reply::Multiline)
        }
    }
}

/// A failed query ends the transfer by closing the connection.
pub(super) fn drive_free_space_line(
    handle: FileHandle,
    first: &mut bool,
    line: PoolBuffer,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    if !core::mem::take(first) {
        cx.backend.close_file(handle);
        // SAFETY: the transfer ends with this result, so the server drops the
        // continuation, the only other holder.
        unsafe { cx.backend.free_pool(line) };
        return Err(CommandError::EndOfData);
    }

    let Ok(size) = cx.backend.query_volume_size(handle) else {
        cx.backend.close_file(handle);
        // SAFETY: the transfer ends with this result, so the server drops
        // the continuation, the only other holder.
        unsafe { cx.backend.free_pool(line) };
        return Err(CommandError::Fail);
    };

    let unit = u64::from(size.sectors_per_unit.wrapping_mul(size.bytes_per_sector));
    let total = size.total_units.wrapping_mul(unit);
    let free = size.available_units.wrapping_mul(unit);
    let pool = cx.backend.pool(line);
    let mut output = SliceWriter::new(&mut pool[..LINE_BUFFER as usize - 1]);
    output.push_hex(b"freetocallerlo=0x", free as u32, 8);
    output.push_hex(b" freetocallerhi=0x", (free >> 32) as u32, 8);
    output.push_hex(b" totalbyteslo=0x", total as u32, 8);
    output.push_hex(b" totalbyteshi=0x", (total >> 32) as u32, 8);
    output.push_hex(b" totalfreebyteslo=0x", free as u32, 8);
    output.push_hex(b" totalfreebyteshi=0x", (free >> 32) as u32, 8);
    let length = output.len;
    send_pool_line(&pool[..length], cx.binary, &mut cx.binary_len);

    Ok(Reply::Ok)
}

/// `drivelist`.
pub(super) fn drive_list(invocation: &mut Invocation<'_>) -> CommandResult {
    const DOS_DEVICES: &[u8] = b"\\??";

    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    match invocation.backend.open_object_directory(DOS_DEVICES) {
        Err(error) => Err(CommandError::from_kernel(error, CommandError::Fail)),
        Ok(directory) => {
            begin(
                invocation,
                Continuation::DriveList(DriveList::Objects {
                    directory,
                    context: 0,
                }),
                None,
            );
            Ok(Reply::Multiline)
        }
    }
}

/// `_strnicmp(a, b, count) == 0` over NUL-terminated views.
fn prefix_equal(a: &[u8], b: &[u8], count: usize) -> bool {
    for index in 0..count {
        let left = a.get(index).copied().unwrap_or(0);
        let right = b.get(index).copied().unwrap_or(0);
        if !left.eq_ignore_ascii_case(&right) {
            return false;
        }

        if left == 0 {
            return true;
        }
    }

    true
}

pub(super) fn drive_list_line(
    list: &mut DriveList,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    /// Name bytes the 0x10c-byte object directory query buffer holds.
    const OBJECT_NAME_CAPACITY: usize = 0x100;

    if let DriveList::Objects { directory, context } = list {
        let directory = *directory;

        loop {
            let mut name = [0u8; OBJECT_NAME_CAPACITY];
            let restart = *context == 0;
            let length = match cx
                .backend
                .query_object_directory(directory, restart, context, &mut name)
            {
                Ok(length) => length.min(OBJECT_NAME_CAPACITY),
                Err(_) => {
                    cx.backend.close_object_directory(directory);
                    *list = DriveList::Table { index: 0 };
                    break;
                }
            };

            let name = &name[..length];
            let Some(colon) = name.iter().position(|&byte| byte == b':') else {
                continue;
            };

            if length < 2
                || cx
                    .state
                    .filesystem
                    .drives
                    .drives()
                    .any(|drive| prefix_equal(drive.name.as_bytes(), name, length - 1))
            {
                continue;
            }

            let opened = cx.backend.open_relative(
                directory,
                &name[..=colon],
                AccessMask::SYNCHRONIZE,
                ShareAccess::all(),
                DIRECTORY,
            );
            if let Ok(handle) = opened {
                cx.backend.close_file(handle);
                cx.line.clear();
                return drive_name_line(cx, &name[..colon]);
            }
        }
    }

    let DriveList::Table { index } = list else {
        return Err(CommandError::EndOfData);
    };

    loop {
        let row = *index;
        let Some(Some(drive)) = cx.state.filesystem.drives.entries.get(row).copied() else {
            return Err(CommandError::EndOfData);
        };

        *index += 1;
        if !drive.enabled {
            continue;
        }

        let mut path = [0u8; 0x24];
        let length = drive.name.as_bytes().len().min(path.len() - 2);
        path[..length].copy_from_slice(&drive.name.as_bytes()[..length]);
        path[length..length + 2].copy_from_slice(b":\\");
        let request = CreateRequest::open(AccessMask::SYNCHRONIZE, ShareAccess::all(), DIRECTORY);
        match open_translated(cx.state, cx.backend, &path[..length + 2], &request) {
            Ok(handle) => {
                cx.backend.close_file(handle);
                return drive_name_line(cx, drive.name.as_bytes());
            }
            Err(_) if drive.name == b"F" || drive.name == b"SMB" => {
                if let Some(entry) = cx.state.filesystem.drives.entries[row].as_mut() {
                    entry.enabled = false;
                }
                super::publish_drives(cx.state, cx.backend);
            }
            // Other drives that fail to open are skipped.
            Err(_) => {}
        }
    }
}

fn drive_name_line(cx: &mut ContinuationContext<'_>, name: &[u8]) -> CommandResult {
    let _ = cx.line.push_bytes(b"drivename=\"");
    let _ = cx.line.push_bytes(name);
    let _ = cx.line.push_bytes(b"\"");

    Ok(Reply::Ok)
}
