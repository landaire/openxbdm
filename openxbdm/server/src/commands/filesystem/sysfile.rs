//! `sysfileupd`: system file updates.

use core::fmt::Write as _;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::BasicInformation;
use super::Continuation;
use super::CreateRequest;
use super::DIRECTORY;
use super::FileData;
use super::FileHandle;
use super::FileInformation;
use super::FileTime;
use super::PoolBuffer;
use super::PoolRange;
use super::ReadTarget;
use super::SYNCHRONOUS;
use super::SliceWriter;
use super::begin;
use super::error::UpdateError;
use super::string_param;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// `sysfileupd` data buffer and name area.
const SYSFILE_DATA: u32 = 0x4000;
const SYSFILE_NAME_BUFFER: usize = 0x200;

/// `sysfileupd` upload: data in [0, 0x4000), target name at 0x4000.
#[derive(Debug)]
pub struct SystemFileUpdate {
    buffer: PoolBuffer,
    handle: Option<FileHandle>,
    name_length: usize,
    time: FileTime,
    crc: u32,
    expected: u32,
    staged: u32,
}

impl SystemFileUpdate {
    fn fail(&mut self, cx: &mut ContinuationContext<'_>, error: KernelError) -> CommandResult {
        if let Some(handle) = self.handle.take() {
            let _ = cx.backend.set_delete_disposition(handle, true);
            cx.backend.close_file(handle);
        }

        let result = dos_result(cx.backend, error);
        cx.line.clear();
        let _ = write!(cx.line, "HRESULT 0x{:x}", crate::reply::hresult(result).0);

        result
    }

    /// Replace the target with the uploaded temporary file (0x91f64340).
    fn finalize(
        &mut self,
        cx: &mut ContinuationContext<'_>,
        handle: FileHandle,
    ) -> Result<(), KernelError> {
        let mut name = [0u8; SYSFILE_NAME_BUFFER];
        let start = SYSFILE_DATA as usize;
        name[..self.name_length]
            .copy_from_slice(&cx.backend.pool(self.buffer)[start..start + self.name_length]);
        let name = &name[..self.name_length];
        let request = CreateRequest::open(
            AccessMask::SYNCHRONIZE.union(AccessMask::WRITE_ATTRIBUTES),
            ShareAccess::all(),
            CreateOptions::OPEN_FOR_BACKUP_INTENT.union(SYNCHRONOUS),
        );
        if let Ok(existing) = cx.backend.create_file(name, &request) {
            let basic = BasicInformation {
                attributes: FileAttributes::NORMAL,
                ..BasicInformation::default()
            };

            let _ = cx.backend.set_basic_information(existing, &basic);
            cx.backend.close_file(existing);
        }

        let _ = cx.backend.rename_file(handle, name, true);
        let basic = BasicInformation {
            creation_time: self.time,
            last_access_time: self.time,
            last_write_time: self.time,
            change_time: self.time,
            attributes: FileAttributes::NORMAL,
        };

        cx.backend.set_basic_information(handle, &basic)
    }

    pub(super) fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> CommandResult {
        let mut remaining = cx.session.receive_remaining.unwrap_or(0);
        if cx.received.is_empty() && remaining != 0 {
            // SAFETY: `receive_remaining` is 0, so the server drops the
            // continuation, the only other holder, after this result.
            unsafe { cx.backend.free_pool(self.buffer) };
            // The image marks the temporary file for deletion but never
            // closes its handle, so the file stays until reboot.
            if let Some(handle) = self.handle {
                let _ = cx.backend.set_delete_disposition(handle, true);
            }

            cx.session.receive_remaining = Some(0);
            let error = CommandError::Unexpected;
            let _ = write!(cx.line, "HRESULT 0x{:x}", Hresult::from(error).0);
            return Err(error);
        }

        let mut data = cx.received;
        let mut result = Ok(Reply::Ok);

        loop {
            let count = ((SYSFILE_DATA - self.staged) as usize).min(data.len());
            let start = self.staged as usize;
            cx.backend.pool(self.buffer)[start..start + count].copy_from_slice(&data[..count]);
            self.staged += count as u32;
            remaining -= count as u32;
            data = &data[count..];
            if remaining == 0 || self.staged == SYSFILE_DATA {
                result = self.flush(cx, remaining);
            }

            if data.is_empty() {
                break;
            }
        }

        cx.session.receive_remaining = Some(remaining);
        if remaining == 0 {
            // SAFETY: `receive_remaining` is 0, so the server drops the
            // continuation, the only other holder, after this result.
            unsafe { cx.backend.free_pool(self.buffer) };
        }

        result
    }

    fn flush(&mut self, cx: &mut ContinuationContext<'_>, remaining: u32) -> CommandResult {
        let staged = self.staged;
        self.staged = 0;
        let pool = cx.backend.pool(self.buffer);
        self.crc = update_crc(self.crc, &pool[..staged as usize]);
        let range = PoolRange {
            buffer: self.buffer,
            offset: 0,
            length: staged,
        };

        // After a failure the image keeps writing through a null handle.
        let written = match self.handle {
            Some(handle) => cx.backend.write_file(handle, None, FileData::Pool(range)),
            None => Err(KernelError::InvalidHandle),
        };

        if let Err(error) = written {
            return self.fail(cx, error);
        }

        if remaining != 0 {
            return Ok(Reply::Ok);
        }

        if self.crc != self.expected {
            return self.fail(cx, KernelError::CrcError);
        }

        let Some(handle) = self.handle else {
            return Ok(Reply::Ok);
        };

        if let Err(error) = self.finalize(cx, handle) {
            return self.fail(cx, error);
        }

        self.handle = None;
        cx.backend.close_file(handle);

        Ok(Reply::Ok)
    }
}

/// The result of a failed kernel call through its Win32 error code.
/// `ERROR_SUCCESS` is result 0 ([`Reply::Sent`]).
fn dos_result(backend: &mut dyn crate::backend::Backend, error: KernelError) -> CommandResult {
    match backend.dos_error(error) {
        Some(code) => Err(CommandError::Win32(code)),
        None => Ok(Reply::Sent),
    }
}

/// Create each missing parent directory of `path` (0x91f64448).
fn create_parent_directories(backend: &mut dyn crate::backend::Backend, path: &[u8]) {
    let request = CreateRequest {
        access: AccessMask::LIST_DIRECTORY.union(AccessMask::SYNCHRONIZE),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::READ.union(ShareAccess::WRITE),
        disposition: CreateDisposition::Create,
        options: CreateOptions::OPEN_FOR_BACKUP_INTENT.union(DIRECTORY),
    };

    for index in 1..path.len() {
        if path[index] == b'\\'
            && let Ok(handle) = backend.create_file(&path[..index], &request)
        {
            backend.close_file(handle);
        }
    }
}

fn hresult_text(text: &mut crate::text::ResponseText, result: CommandResult) {
    text.clear();
    let _ = write!(text, "HRESULT 0x{:x}", crate::reply::hresult(result).0);
}

/// `sysfileupd name=<object path>` with `query=<nonzero>`, `localsrc=`, or
/// an upload of `size` bytes checked against `crc`.
pub(super) fn system_file_update(invocation: &mut Invocation<'_>) -> CommandResult {
    const SYSFILE_BLOCK: u32 = 0x4200;

    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let Some(buffer) = invocation.backend.allocate_pool(SYSFILE_BLOCK) else {
        hresult_text(invocation.text, Err(CommandError::OutOfMemory));
        return Err(CommandError::OutOfMemory);
    };

    let started = system_file_update_start(invocation, buffer);
    if !matches!(started, Ok(Reply::SendBinary)) {
        // SAFETY: the upload was not started, so no continuation holds a copy.
        unsafe { invocation.backend.free_pool(buffer) };
    }

    let result = match started {
        Ok(reply) => return Ok(reply),
        Err(UpdateError::Command(error)) => Err(error),
        Err(UpdateError::Kernel(error)) => dos_result(invocation.backend, error),
    };

    hresult_text(invocation.text, result);

    result
}

fn system_file_update_start(
    invocation: &mut Invocation<'_>,
    buffer: PoolBuffer,
) -> Result<Reply, UpdateError> {
    /// `ERROR_INVALID_NAME`: the target path has no room for the temporary
    /// file name.
    const INVALID_NAME: CommandError = CommandError::Win32(Win32Error::INVALID_NAME);

    let mut name = [0u8; SYSFILE_NAME_BUFFER];
    let name = string_param(invocation, "name", &mut name).ok_or(CommandError::InvalidArgument)?;
    if invocation
        .line
        .dword("query")
        .is_some_and(|value| value != 0)
    {
        let request = CreateRequest::open(
            AccessMask::GENERIC_READ.union(AccessMask::SYNCHRONIZE),
            ShareAccess::READ,
            CreateOptions::NON_DIRECTORY_FILE.union(CreateOptions::SYNCHRONOUS_IO_ALERT),
        );
        let backend = &mut *invocation.backend;
        let queried = backend.create_file(name, &request).and_then(|handle| {
            let information = backend.query_file_information(handle);
            backend.close_file(handle);
            information
        });
        let information = match queried {
            Ok(information) => information,
            Err(error) => match backend.dos_error(error) {
                Some(code) => return Err(CommandError::Win32(code).into()),
                // A failure without a Win32 error reports zero size and time.
                None => FileInformation::default(),
            },
        };

        invocation.set_text(format_args!(
            "0x{:x} 0x{:x}",
            information.end_of_file, information.last_write_time.0
        ));
        return Ok(Reply::Ok);
    }

    let time_high =
        util::required_dword(invocation, "ftimehi").ok_or(CommandError::InvalidArgument)?;
    let time_low =
        util::required_dword(invocation, "ftimelo").ok_or(CommandError::InvalidArgument)?;
    let time = FileTime::from_parts(time_high, time_low);
    let mut source = [0u8; SYSFILE_NAME_BUFFER];
    if let Some(source) = string_param(invocation, "localsrc", &mut source) {
        // The copy result does not reach the reply.
        copy_local_file(invocation.backend, source, name, time);
        return Ok(Reply::Ok);
    }

    let size = util::required_dword(invocation, "size").ok_or(CommandError::InvalidArgument)?;
    let expected = util::required_dword(invocation, "crc").ok_or(CommandError::InvalidArgument)?;
    invocation.text.clear();

    let mut temporary = [0u8; SYSFILE_NAME_BUFFER];
    let separator = name
        .iter()
        .rposition(|&byte| byte == b'\\')
        .ok_or(INVALID_NAME)?;
    if SYSFILE_NAME_BUFFER - 1 - separator < 0xe {
        return Err(INVALID_NAME.into());
    }

    temporary[..separator].copy_from_slice(&name[..separator]);
    let sequence = invocation.backend.update_sequence();
    let mut output = SliceWriter::new(&mut temporary[separator..]);
    output.push_hex(b"\\temp", u32::from(sequence), 4);
    output.push(b".tmp");
    let length = separator + output.len;
    let temporary = &temporary[..length];

    let backend = &mut *invocation.backend;
    create_parent_directories(backend, temporary);
    let request = CreateRequest {
        access: AccessMask::GENERIC_WRITE
            .union(AccessMask::DELETE)
            .union(AccessMask::SYNCHRONIZE),
        allocation_size: Some(u64::from(size)),
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::all(),
        disposition: CreateDisposition::Create,
        options: CreateOptions::OPEN_FOR_BACKUP_INTENT.union(SYNCHRONOUS),
    };

    let handle = backend
        .create_file(temporary, &request)
        .map_err(UpdateError::Kernel)?;
    if let Err(error) = backend.set_end_of_file(handle, u64::from(size)) {
        let _ = backend.set_delete_disposition(handle, true);
        backend.close_file(handle);
        return Err(UpdateError::Kernel(error));
    }

    let name_start = SYSFILE_DATA as usize;
    backend.pool(buffer)[name_start..name_start + name.len()].copy_from_slice(name);
    let update = SystemFileUpdate {
        buffer,
        handle: Some(handle),
        name_length: name.len(),
        time,
        crc: u32::MAX,
        expected,
        staged: 0,
    };

    begin(
        invocation,
        Continuation::SystemFileUpdate(update),
        Some(size),
    );

    Ok(Reply::SendBinary)
}

/// Copy `source` to `target` in 64 KiB pieces and set all four times to
/// `time` (0x91f64858).
fn copy_local_file(
    backend: &mut dyn crate::backend::Backend,
    source: &[u8],
    target: &[u8],
    time: FileTime,
) {
    create_parent_directories(backend, target);
    let Some(buffer) = backend.allocate_pool(0x1_0000) else {
        return;
    };

    let mut source_handle = None;
    let mut target_handle = None;
    let result = (|| {
        let read = CreateRequest::open(
            AccessMask::GENERIC_READ.union(AccessMask::SYNCHRONIZE),
            ShareAccess::READ,
            CreateOptions::NON_DIRECTORY_FILE.union(SYNCHRONOUS),
        );
        let input = *source_handle.insert(backend.create_file(source, &read)?);
        let information = backend.query_file_information(input)?;
        let write = CreateRequest {
            access: AccessMask::GENERIC_WRITE.union(AccessMask::SYNCHRONIZE),
            allocation_size: Some(information.end_of_file),
            attributes: FileAttributes::NORMAL,
            share: ShareAccess::empty(),
            disposition: CreateDisposition::OverwriteIf,
            options: CreateOptions::NON_DIRECTORY_FILE
                .union(SYNCHRONOUS)
                .union(CreateOptions::SEQUENTIAL_ONLY),
        };
        let output = *target_handle.insert(backend.create_file(target, &write)?);
        backend.set_end_of_file(output, information.end_of_file)?;

        let mut offset = 0u64;
        while offset < information.end_of_file {
            let range = PoolRange {
                buffer,
                offset: 0,
                length: 0x1_0000,
            };

            let count = backend.read_file(input, Some(offset), ReadTarget::Pool(range))?;
            backend.write_file(
                output,
                Some(offset),
                FileData::Pool(PoolRange {
                    length: count,
                    ..range
                }),
            )?;
            if count == 0 {
                break;
            }

            offset += u64::from(count);
        }

        let basic = BasicInformation {
            creation_time: time,
            last_access_time: time,
            last_write_time: time,
            change_time: time,
            attributes: information.attributes,
        };
        let _ = backend.set_basic_information(output, &basic);

        Ok::<(), KernelError>(())
    })();

    if let (Err(_), Some(output)) = (result, target_handle) {
        let _ = backend.set_delete_disposition(output, true);
    }

    // SAFETY: the block is local to this command and not used after.
    unsafe { backend.free_pool(buffer) };

    if let Some(input) = source_handle {
        backend.close_file(input);
    }

    if let Some(output) = target_handle {
        backend.close_file(output);
    }
}

/// Continue a reflected CRC-32 without final inversion.
pub fn update_crc(mut crc: u32, data: &[u8]) -> u32 {
    /// Reflected CRC-32 table (polynomial 0xedb88320) of the upload check.
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut index = 0;

        while index < 256 {
            let mut value = index as u32;
            let mut bit = 0;

            while bit < 8 {
                value = if value & 1 != 0 {
                    (value >> 1) ^ 0xedb8_8320
                } else {
                    value >> 1
                };

                bit += 1;
            }

            table[index] = value;
            index += 1;
        }

        table
    };

    for &byte in data {
        crc = TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }

    crc
}
