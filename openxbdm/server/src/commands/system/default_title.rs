//! `deftitle`: the default title file.

use openxbdm_core::status::ErrorCode;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::title::TitlePath;
use super::title::string_param;
use super::title::translate_title_path;
use crate::commands::filesystem::BasicInformation;
use crate::commands::filesystem::CreateRequest;
use crate::commands::filesystem::FileData;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// `deftitle none` | `deftitle launcher` | `deftitle dir=<s> name=<s>`:
/// replace or delete the default title file `\SystemRoot\dashboard.xbx`.
pub(super) fn default_title(invocation: &mut Invocation<'_>) -> CommandResult {
    const DEFAULT_TITLE_PATH: &[u8] = b"\\SystemRoot\\dashboard.xbx";
    const LAUNCHER_PATH: &[u8] = b"\\SystemRoot\\xshell.xex";
    /// Size of the default-title file: `<directory>;<file>` padded with NUL.
    const DEFAULT_TITLE_SIZE: usize = 0x100;
    /// Buffer of the `dir` parameter.
    const DIRECTORY_BUFFER: usize = 0x104;

    let line = invocation.line;
    let backend = &mut *invocation.backend;
    let synchronous = CreateOptions::SYNCHRONOUS_IO_NONALERT;

    // Clear attributes such as read-only first; failures do not matter.
    let attributes = CreateRequest::open(
        AccessMask::WRITE_ATTRIBUTES.union(AccessMask::SYNCHRONIZE),
        ShareAccess::empty(),
        synchronous,
    );
    if let Ok(handle) = backend.create_file(DEFAULT_TITLE_PATH, &attributes) {
        let normal = BasicInformation {
            attributes: FileAttributes::NORMAL,
            ..BasicInformation::default()
        };
        let _ = backend.set_basic_information(handle, &normal);
        backend.close_file(handle);
    }

    if line.has("none") {
        let delete = CreateRequest::open(
            AccessMask::DELETE.union(AccessMask::SYNCHRONIZE),
            ShareAccess::empty(),
            synchronous,
        );
        let Ok(handle) = backend.create_file(DEFAULT_TITLE_PATH, &delete) else {
            return Ok(Reply::Ok);
        };

        let deleted = backend.set_delete_disposition(handle, true);
        backend.close_file(handle);

        return if deleted.is_ok() {
            Ok(Reply::Ok)
        } else {
            Err(CommandError::Unexpected)
        };
    }

    let mut content = [0u8; DEFAULT_TITLE_SIZE + 1];
    let file_start = if line.has("launcher") {
        content[..LAUNCHER_PATH.len()].copy_from_slice(LAUNCHER_PATH);
        LAUNCHER_PATH
            .iter()
            .rposition(|&byte| byte == b'\\')
            .map_or(0, |separator| separator + 1)
    } else {
        let mut dir_buffer = [0u8; DIRECTORY_BUFFER];
        let Some(dir) = string_param(line, "dir", &mut dir_buffer) else {
            invocation.set_text(format_args!("missing dir"));
            return Err(CommandError::Fail);
        };

        let mut translated = TitlePath::EMPTY;
        let Some(directory) =
            translate_title_path(invocation.state, invocation.backend, dir, &mut translated)
        else {
            return Err(ErrorCode::FileNotFound.into());
        };

        let mut length = directory.as_bytes().len();
        content[..length].copy_from_slice(directory.as_bytes());
        if length == 0 || content[length - 1] != b'\\' {
            content[length] = b'\\';
            length += 1;
        }

        let Some(name) = line.param("name") else {
            invocation.set_text(format_args!("missing name"));
            return Err(CommandError::Fail);
        };

        let end = DEFAULT_TITLE_SIZE.max(length);
        name.copy_into(&mut content[length..end]);

        length
    };

    let backend = &mut *invocation.backend;
    let path_end = content
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(DEFAULT_TITLE_SIZE);

    let check = CreateRequest::open(
        AccessMask::SYNCHRONIZE,
        ShareAccess::READ,
        synchronous.union(CreateOptions::NON_DIRECTORY_FILE),
    );
    let handle = match backend.create_file(&content[..path_end], &check) {
        Ok(handle) => handle,
        Err(error) => {
            return Err(CommandError::from_kernel(
                error,
                ErrorCode::AccessDenied.into(),
            ));
        }
    };
    backend.close_file(handle);

    content[file_start - 1] = b';';
    let create = CreateRequest {
        access: AccessMask::GENERIC_WRITE
            .union(AccessMask::DELETE)
            .union(AccessMask::SYNCHRONIZE),
        allocation_size: None,
        attributes: FileAttributes::empty(),
        share: ShareAccess::empty(),
        disposition: CreateDisposition::OverwriteIf,
        options: synchronous,
    };
    let Ok(handle) = backend.create_file(DEFAULT_TITLE_PATH, &create) else {
        return Err(CommandError::Fail);
    };

    let result = match backend.write_file(
        handle,
        None,
        FileData::Bytes(&content[..DEFAULT_TITLE_SIZE]),
    ) {
        Ok(()) => Ok(Reply::Ok),
        Err(_) => match backend.set_delete_disposition(handle, true) {
            Ok(()) => Ok(Reply::Ok),
            Err(_) => Err(CommandError::Unexpected),
        },
    };

    backend.close_file(handle);

    result
}
