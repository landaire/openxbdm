//! Directory and name commands: `delete`, `dirlist`, `mkdir`, and `rename`.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::KernelError;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::ACCESS_DENIED;
use super::CANNOT_CREATE;
use super::Continuation;
use super::CreateRequest;
use super::DIRECTORY;
use super::FileHandle;
use super::LINE_BUFFER;
use super::NAME_BUFFER;
use super::PoolBuffer;
use super::SYNCHRONOUS;
use super::SliceWriter;
use super::begin;
use super::close_changed;
use super::drive::open_path;
use super::drive::open_translated;
use super::name_param;
use super::send_pool_line;
use super::string_param;
use super::write_attributes;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// `delete name=<path> [dir]`.
pub(super) fn delete(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return Err(util::MISSING);
    };

    let directory = invocation.line.has("dir");
    let at = |index: usize| name.get(index).copied().unwrap_or(0);
    let base = usize::from(matches!(at(0), b'x' | b'X'));
    if at(base + 1) == b':' && at(base + 2) == b'\\' && at(base + 3) == 0 {
        return Err(ACCESS_DENIED);
    }

    let options = if directory {
        DIRECTORY
    } else {
        CreateOptions::NON_DIRECTORY_FILE.union(SYNCHRONOUS)
    };

    let request = CreateRequest::open(
        AccessMask::DELETE.union(AccessMask::SYNCHRONIZE),
        ShareAccess::empty(),
        options,
    );

    match open_path(invocation.state, invocation.backend, name, &request) {
        Err(KernelError::FileIsADirectory) => {
            invocation.set_text(format_args!("is a directory"));
            Err(ACCESS_DENIED)
        }
        Err(KernelError::NotADirectory) => {
            invocation.set_text(format_args!("not a directory"));
            Err(ACCESS_DENIED)
        }
        Err(error) => Err(CommandError::from_kernel(error, ACCESS_DENIED)),
        Ok(handle) => {
            let result = invocation.backend.set_delete_disposition(handle, true);
            close_changed(invocation.backend, handle);

            match result {
                Ok(()) => Ok(Reply::Ok),
                Err(error) => Err(CommandError::from_kernel(error, ACCESS_DENIED)),
            }
        }
    }
}

/// `dirlist name=<path>`: one line per directory entry.
pub(super) fn dirlist(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return Err(util::MISSING);
    };

    let Some(line) = invocation.backend.allocate_pool(LINE_BUFFER) else {
        return Err(CommandError::OutOfMemory);
    };

    let request = CreateRequest::open(
        AccessMask::LIST_DIRECTORY.union(AccessMask::SYNCHRONIZE),
        ShareAccess::READ.union(ShareAccess::WRITE),
        DIRECTORY,
    );

    match open_path(invocation.state, invocation.backend, name, &request) {
        Err(error) => {
            // SAFETY: the transfer was not started, so this command holds the
            // only copy.
            unsafe { invocation.backend.free_pool(line) };
            Err(CommandError::from_kernel(error, ACCESS_DENIED))
        }
        Ok(handle) => {
            begin(
                invocation,
                Continuation::DirectoryList {
                    handle,
                    count: 0,
                    line,
                },
                None,
            );
            Ok(Reply::Multiline)
        }
    }
}

/// Names are not escaped and are cut at 0x1ff bytes, the line buffer
/// size less one.
pub(super) fn directory_list_line(
    handle: FileHandle,
    count: &mut u32,
    line: PoolBuffer,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    /// Name bytes the 0x190-byte directory query buffer holds after the fixed
    /// 0x40-byte entry header.
    const DIRECTORY_NAME_CAPACITY: usize = 0x150;

    let mut name = [0u8; DIRECTORY_NAME_CAPACITY];
    let Ok(entry) = cx.backend.query_directory(handle, *count == 0, &mut name) else {
        cx.backend.close_file(handle);
        // SAFETY: the transfer ends with this result, so the server drops
        // the continuation, the only other holder.
        unsafe { cx.backend.free_pool(line) };
        return Err(CommandError::EndOfData);
    };

    *count += 1;

    let name = &name[..entry
        .name_length
        .min(DIRECTORY_NAME_CAPACITY)
        .min(LINE_BUFFER as usize - 1)];
    let pool = cx.backend.pool(line);
    let mut output = SliceWriter::new(&mut pool[..LINE_BUFFER as usize - 1]);
    output.push(b"name=\"");
    output.push(name);
    output.push(b"\" ");
    write_attributes(&mut output, &entry.information);
    let length = output.len;
    send_pool_line(&pool[..length], cx.binary, &mut cx.binary_len);

    Ok(Reply::Ok)
}

/// `mkdir name=<path>`.
pub(super) fn make_directory(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return Err(util::MISSING);
    };

    let request = CreateRequest {
        access: AccessMask::LIST_DIRECTORY.union(AccessMask::SYNCHRONIZE),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::empty(),
        disposition: CreateDisposition::Create,
        options: DIRECTORY,
    };

    match open_path(invocation.state, invocation.backend, name, &request) {
        Ok(handle) => {
            close_changed(invocation.backend, handle);
            Ok(Reply::Ok)
        }
        Err(error) => Err(CommandError::from_kernel(error, CANNOT_CREATE)),
    }
}

/// `rename name=<path> newname=<path>`.
pub(super) fn rename(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut new_buffer = [0u8; NAME_BUFFER];
    let Some(new_name) = string_param(invocation, "newname", &mut new_buffer) else {
        invocation.set_text(format_args!("missing new name"));
        return Err(CommandError::Fail);
    };

    let Some(target) = invocation
        .state
        .filesystem
        .drives
        .translate(invocation.backend, new_name)
    else {
        invocation.set_text(format_args!("new name does not exist"));
        return Err(ErrorCode::FileNotFound.into());
    };

    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return Err(util::MISSING);
    };

    let request = CreateRequest::open(
        AccessMask::GENERIC_WRITE.union(AccessMask::SYNCHRONIZE),
        ShareAccess::empty(),
        SYNCHRONOUS,
    );
    let Ok(handle) = open_translated(invocation.state, invocation.backend, name, &request) else {
        return Err(ACCESS_DENIED);
    };

    let result = invocation
        .backend
        .rename_file(handle, target.as_bytes(), false);
    close_changed(invocation.backend, handle);

    match result {
        Ok(()) => Ok(Reply::Ok),
        Err(KernelError::NotSameDevice) => Err(ErrorCode::FileMustBeCopied.into()),
        Err(error) => Err(CommandError::from_kernel(error, CANNOT_CREATE)),
    }
}
