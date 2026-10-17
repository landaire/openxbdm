//! File uploads: `sendfile`, `writefile`, and `sendvfile`.

use core::fmt::Write as _;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::ACCESS_DENIED;
use super::BasicInformation;
use super::CANNOT_CREATE;
use super::Continuation;
use super::CreateRequest;
use super::FileData;
use super::FileHandle;
use super::FileTime;
use super::NAME_BUFFER;
use super::PoolBuffer;
use super::PoolRange;
use super::begin;
use super::close_changed;
use super::drive::open_path;
use super::name_param;
use super::send_pool_piece;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// Upload staging: two halves of this size.
const UPLOAD_HALF: u32 = 0x4000;

/// `sendvfile` header bytes.
const VFILE_HEADER: u32 = 0x20;

/// `sendvfile` result array offset in its pool block.
const VFILE_RESULTS: u32 = 0x8000;

/// Staging of uploaded file data into two 0x4000-byte halves, each
/// written when full or at the end of the upload (0x91f448d8).
#[derive(Debug)]
pub struct Writer {
    handle: Option<FileHandle>,
    buffer: PoolBuffer,
    staged: u32,
    half: u32,
    offset: u64,
    written: u32,
    failure: Option<KernelError>,
    /// Failed writes mark the file for deletion, except in write-at mode.
    delete_on_failure: bool,
}

impl Writer {
    fn new(handle: FileHandle, buffer: PoolBuffer, offset: u64, delete_on_failure: bool) -> Self {
        Self {
            handle: Some(handle),
            buffer,
            staged: 0,
            half: 0,
            offset,
            written: 0,
            failure: None,
            delete_on_failure,
        }
    }

    /// Stage `data`, decrementing `remaining`; the last byte flushes.
    fn receive(
        &mut self,
        backend: &mut dyn crate::backend::Backend,
        mut data: &[u8],
        remaining: &mut u32,
    ) {
        if data.is_empty() && *remaining == 0 {
            self.flush(backend);
            return;
        }

        while !data.is_empty() {
            let count = ((UPLOAD_HALF - self.staged) as usize).min(data.len());
            let start = (self.half + self.staged) as usize;
            backend.pool(self.buffer)[start..start + count].copy_from_slice(&data[..count]);
            self.staged += count as u32;
            *remaining -= count as u32;
            data = &data[count..];
            if self.staged == UPLOAD_HALF || *remaining == 0 {
                self.flush(backend);
            }
        }
    }

    fn flush(&mut self, backend: &mut dyn crate::backend::Backend) {
        if let Some(handle) = self.handle {
            let range = PoolRange {
                buffer: self.buffer,
                offset: self.half,
                length: self.staged,
            };

            match backend.write_file(handle, Some(self.offset), FileData::Pool(range)) {
                Ok(()) => {
                    self.offset += u64::from(self.staged);
                    self.written = self.written.wrapping_add(self.staged);
                }
                Err(error) => {
                    if self.delete_on_failure {
                        let _ = backend.set_delete_disposition(handle, true);
                    }

                    close_changed(backend, handle);
                    self.handle = None;
                    self.failure = Some(error);
                }
            }
        }

        self.staged = 0;
        self.half ^= UPLOAD_HALF;
    }

    /// The upload ended before all bytes arrived: write what is staged.
    fn abandon(&mut self, backend: &mut dyn crate::backend::Backend) {
        if let (Some(handle), true) = (self.handle, self.delete_on_failure) {
            let _ = backend.set_delete_disposition(handle, true);
        }

        self.flush(backend);

        if let Some(handle) = self.handle.take() {
            close_changed(backend, handle);
        }
    }
}

/// `sendfile` or `writefile` upload.
#[derive(Debug)]
pub struct Upload {
    writer: Writer,
    write_at: bool,
}

impl Upload {
    pub(super) fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> CommandResult {
        let mut remaining = cx.session.receive_remaining.unwrap_or(0);
        if cx.received.is_empty() && remaining != 0 {
            cx.session.receive_remaining = Some(0);
            self.writer.abandon(cx.backend);
            // SAFETY: `receive_remaining` is 0, so the server drops the
            // continuation, the only other holder, after this result.
            unsafe { cx.backend.free_pool(self.writer.buffer) };
            return Err(CommandError::Unexpected);
        }

        self.writer.receive(cx.backend, cx.received, &mut remaining);
        cx.session.receive_remaining = Some(remaining);
        if remaining != 0 {
            return Ok(Reply::Ok);
        }

        if let Some(handle) = self.writer.handle.take() {
            close_changed(cx.backend, handle);
        }

        // SAFETY: `receive_remaining` is 0, so the server drops the
        // continuation, the only other holder, after this result.
        unsafe { cx.backend.free_pool(self.writer.buffer) };
        if self.write_at {
            let _ = write!(cx.line, "{} bytes written", self.writer.written);
        }

        match self.writer.failure {
            Some(_) => Err(CommandError::Unexpected),
            None => Ok(Reply::Ok),
        }
    }
}

/// `sendvfile` progress.
#[derive(Debug)]
pub struct MultiUpload {
    buffer: Option<PoolBuffer>,
    total: u32,
    files_left: u32,
    staged: u32,
    header: VirtualFileHeader,
    phase: MultiUploadPhase,
}

impl MultiUpload {
    fn release(&mut self, backend: &mut dyn crate::backend::Backend) {
        self.abandon(backend);

        if let Some(buffer) = self.buffer.take() {
            // SAFETY: the continuation held the only copy outside its writer,
            // taken out above; `resume` returns before the writer is used
            // again.
            unsafe { backend.free_pool(buffer) };
        }
    }

    fn abandon(&mut self, backend: &mut dyn crate::backend::Backend) {
        if let MultiUploadPhase::Data(writer) = &mut self.phase {
            writer.abandon(backend);
        }
    }

    /// Store the current file's failure in the result table of the reply.
    fn set_result(&mut self, backend: &mut dyn crate::backend::Backend, error: CommandError) {
        let Some(buffer) = self.buffer else {
            return;
        };

        let start = (VFILE_RESULTS + (self.total - self.files_left) * 4) as usize;
        let result = Hresult::from(error);
        backend.pool(buffer)[start..start + 4].copy_from_slice(&result.0.to_be_bytes());
    }

    /// Stage header or name bytes after those already received.
    fn stage(
        &mut self,
        backend: &mut dyn crate::backend::Backend,
        buffer: PoolBuffer,
        data: &[u8],
    ) {
        let start = (self.staged as usize).min(UPLOAD_HALF as usize);
        let count = data.len().min(UPLOAD_HALF as usize - start);
        backend.pool(buffer)[start..start + count].copy_from_slice(&data[..count]);
        self.staged += data.len() as u32;
    }

    /// Set the times and attributes of a completed file and close it.
    fn complete(&mut self, backend: &mut dyn crate::backend::Backend, handle: FileHandle) {
        match backend.query_file_information(handle) {
            Ok(_) => {
                let basic = BasicInformation {
                    creation_time: self.header.creation_time,
                    last_access_time: FileTime(0),
                    last_write_time: self.header.last_write_time,
                    change_time: FileTime(0),
                    attributes: self.header.attributes,
                };

                let _ = backend.set_basic_information(handle, &basic);
            }
            Err(error) => self.set_result(backend, CommandError::from_kernel(error, CANNOT_CREATE)),
        }

        close_changed(backend, handle);
    }

    /// Advance to the next file header, or to the reply after the last.
    fn next_file(&mut self, remaining: &mut u32) -> CommandResult {
        self.files_left -= 1;
        self.staged = 0;
        if self.files_left == 0 {
            self.phase = MultiUploadPhase::Send { sent: 0 };
            return Ok(Reply::Binary);
        }

        self.phase = MultiUploadPhase::Header;
        *remaining = VFILE_HEADER;

        Ok(Reply::Ok)
    }

    fn open(
        &mut self,
        cx: &mut ContinuationContext<'_>,
        buffer: PoolBuffer,
        remaining: &mut u32,
    ) -> CommandResult {
        let mut name = [0u8; NAME_BUFFER];
        let staged = (self.staged as usize).min(UPLOAD_HALF as usize);
        let pool = cx.backend.pool(buffer);
        let length = pool[..staged]
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(staged)
            .min(NAME_BUFFER);
        name[..length].copy_from_slice(&pool[..length]);

        let request = CreateRequest {
            access: AccessMask::GENERIC_WRITE
                .union(AccessMask::DELETE)
                .union(AccessMask::SYNCHRONIZE),
            allocation_size: Some(self.header.size),
            attributes: FileAttributes::empty(),
            share: ShareAccess::empty(),
            disposition: CreateDisposition::OverwriteIf,
            options: CreateOptions::empty(),
        };

        let size = self.header.size;
        let opened = open_path(cx.state, cx.backend, &name[..length], &request);
        let opened = opened.and_then(|handle| {
            let Err(error) = cx.backend.set_end_of_file(handle, size) else {
                return Ok(handle);
            };

            let _ = cx.backend.set_delete_disposition(handle, true);
            close_changed(cx.backend, handle);

            Err(error)
        });

        self.staged = 0;
        *remaining = size as u32;

        match opened {
            Err(error) => {
                self.set_result(cx.backend, CommandError::from_kernel(error, CANNOT_CREATE));
                self.phase = MultiUploadPhase::Discard;
                if *remaining == 0 {
                    return self.next_file(remaining);
                }
            }
            Ok(handle) if *remaining == 0 => {
                self.complete(cx.backend, handle);
                return self.next_file(remaining);
            }
            Ok(handle) => {
                self.phase = MultiUploadPhase::Data(Writer::new(handle, buffer, 0, true));
            }
        }

        Ok(Reply::Ok)
    }

    /// Parse a completed file header and advance to its name, its data, or
    /// the next file.
    fn read_header(
        &mut self,
        cx: &mut ContinuationContext<'_>,
        buffer: PoolBuffer,
        remaining: &mut u32,
    ) -> CommandResult {
        let mut header = [0u8; VFILE_HEADER as usize];
        header.copy_from_slice(&cx.backend.pool(buffer)[..VFILE_HEADER as usize]);
        let dword = |offset: usize| {
            u32::from_be_bytes([
                header[offset],
                header[offset + 1],
                header[offset + 2],
                header[offset + 3],
            ])
        };
        let qword = |offset: usize| u64::from(dword(offset)) << 32 | u64::from(dword(offset + 4));

        let header_length = dword(0);
        self.header = VirtualFileHeader {
            creation_time: FileTime(qword(4)),
            last_write_time: FileTime(qword(0xc)),
            size: qword(0x14),
            attributes: FileAttributes::from_bits_retain(dword(0x1c)),
        };
        self.staged = 0;
        *remaining = header_length.wrapping_sub(VFILE_HEADER);

        if *remaining != 0 {
            self.phase = MultiUploadPhase::Name;
            return Ok(Reply::Ok);
        }

        if self.header.size == 0 {
            return self.next_file(remaining);
        }

        self.open(cx, buffer, remaining)
    }

    pub(super) fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> CommandResult {
        if let MultiUploadPhase::Send { sent } = &mut self.phase {
            let Some(buffer) = self.buffer else {
                return Err(CommandError::EndOfData);
            };

            let total = self.total * 4;
            if cx.aborted || *sent >= total {
                self.release(cx.backend);
                return Err(CommandError::EndOfData);
            }

            return send_pool_piece(cx, buffer, VFILE_RESULTS, total, sent);
        }

        let mut remaining = cx.session.receive_remaining.unwrap_or(0);
        if cx.received.is_empty() && remaining != 0 {
            // The image keeps the block allocated when the connection
            // drops.
            self.abandon(cx.backend);
            return Err(CommandError::Fail);
        }

        let Some(buffer) = self.buffer else {
            return Ok(Reply::Ok);
        };

        if self.total == 0 {
            // The image frees the block on the first piece and keeps
            // receiving without ever completing.
            self.release(cx.backend);
            return Err(CommandError::EndOfData);
        }

        let received = cx.received;
        let result = match &mut self.phase {
            MultiUploadPhase::Header => {
                self.stage(cx.backend, buffer, received);
                remaining -= received.len() as u32;
                if remaining != 0 {
                    Ok(Reply::Ok)
                } else {
                    self.read_header(cx, buffer, &mut remaining)
                }
            }
            MultiUploadPhase::Name => {
                self.stage(cx.backend, buffer, received);
                remaining -= received.len() as u32;
                if remaining != 0 {
                    Ok(Reply::Ok)
                } else {
                    self.open(cx, buffer, &mut remaining)
                }
            }
            MultiUploadPhase::Discard => {
                remaining -= received.len() as u32;
                if remaining != 0 {
                    Ok(Reply::Ok)
                } else {
                    self.next_file(&mut remaining)
                }
            }
            MultiUploadPhase::Data(writer) => {
                writer.receive(cx.backend, received, &mut remaining);
                if let Some(error) = writer.failure {
                    let error = CommandError::from_kernel(error, CommandError::Unexpected);
                    self.set_result(cx.backend, error);
                    self.phase = MultiUploadPhase::Discard;
                    if remaining != 0 {
                        Ok(Reply::Ok)
                    } else {
                        self.next_file(&mut remaining)
                    }
                } else if remaining != 0 {
                    Ok(Reply::Ok)
                } else {
                    let handle = writer.handle.take();
                    if let Some(handle) = handle {
                        self.complete(cx.backend, handle);
                    }

                    self.next_file(&mut remaining)
                }
            }
            MultiUploadPhase::Send { .. } => Ok(Reply::Ok),
        };

        cx.session.receive_remaining = Some(remaining);

        result
    }
}

/// Fields of one `sendvfile` header.
#[derive(Debug, Clone, Copy, Default)]
struct VirtualFileHeader {
    creation_time: FileTime,
    last_write_time: FileTime,
    size: u64,
    attributes: FileAttributes,
}

#[derive(Debug)]
enum MultiUploadPhase {
    Header,
    Name,
    /// The file could not be created; its data is discarded.
    Discard,
    Data(Writer),
    Send {
        sent: u32,
    },
}

/// `sendfile name=<path> length=<dword>`: create or replace a file.
pub(super) fn send_file(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return Err(util::MISSING);
    };

    let Some(length) = util::required_dword(invocation, "length") else {
        return Err(util::MISSING);
    };

    start_upload(invocation, name, None, length)
}

/// `writefile name=<path> offset=<dword> length=<dword>`: write into an
/// existing file.
pub(super) fn write_file(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return Err(util::MISSING);
    };

    let Some(offset) = util::required_dword(invocation, "offset") else {
        return Err(util::MISSING);
    };

    let Some(length) = util::required_dword(invocation, "length") else {
        return Err(util::MISSING);
    };

    start_upload(invocation, name, Some(offset), length)
}

/// Open `name` for an upload of `length` bytes: written at `write_at` in
/// an existing file, or into a file created with that size (`None`) that
/// a failed upload deletes.
fn start_upload(
    invocation: &mut Invocation<'_>,
    name: &[u8],
    write_at: Option<u32>,
    length: u32,
) -> CommandResult {
    let request = CreateRequest {
        access: match write_at {
            Some(_) => AccessMask::GENERIC_READ
                .union(AccessMask::GENERIC_WRITE)
                .union(AccessMask::SYNCHRONIZE),
            None => AccessMask::GENERIC_WRITE
                .union(AccessMask::DELETE)
                .union(AccessMask::SYNCHRONIZE),
        },
        allocation_size: Some(u64::from(length)),
        attributes: FileAttributes::empty(),
        share: ShareAccess::empty(),
        disposition: match write_at {
            Some(_) => CreateDisposition::Open,
            None => CreateDisposition::OverwriteIf,
        },
        options: CreateOptions::empty(),
    };
    let fallback = match write_at {
        Some(_) => ACCESS_DENIED,
        None => CANNOT_CREATE,
    };

    let handle = match open_path(invocation.state, invocation.backend, name, &request) {
        Ok(handle) => handle,
        Err(error) => return Err(CommandError::from_kernel(error, fallback)),
    };

    let backend = &mut *invocation.backend;
    let prepared = match write_at {
        Some(offset) => backend.set_file_position(handle, u64::from(offset)),
        None => backend.set_end_of_file(handle, u64::from(length)),
    }
    .and_then(|()| {
        backend
            .allocate_pool(2 * UPLOAD_HALF)
            .ok_or(KernelError::NoMemory)
    });
    let pool = match prepared {
        Ok(pool) => pool,
        Err(error) => {
            if write_at.is_none() {
                let _ = backend.set_delete_disposition(handle, true);
            }

            close_changed(backend, handle);
            return Err(CommandError::from_kernel(error, fallback));
        }
    };

    // A created file is written from its start.
    let offset = u64::from(write_at.unwrap_or(0));
    let upload = Upload {
        writer: Writer::new(handle, pool, offset, write_at.is_none()),
        write_at: write_at.is_some(),
    };

    begin(invocation, Continuation::Upload(upload), Some(length));

    Ok(Reply::SendBinary)
}

/// `sendvfile count=<dword>`, then per file a 0x20-byte big-endian
/// header, the name, and the data; replies with one HRESULT per file.
pub(super) fn send_vfile(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(count) = util::required_dword(invocation, "count") else {
        return Err(util::MISSING);
    };

    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let Some(buffer) = invocation
        .backend
        .allocate_pool(count.wrapping_add(0x2000).wrapping_mul(4))
    else {
        return Err(CommandError::OutOfMemory);
    };

    let results = VFILE_RESULTS as usize;
    invocation.backend.pool(buffer)[results..results + count as usize * 4].fill(0);
    let upload = MultiUpload {
        buffer: Some(buffer),
        total: count,
        files_left: count,
        staged: 0,
        header: VirtualFileHeader::default(),
        phase: MultiUploadPhase::Header,
    };

    begin(
        invocation,
        Continuation::MultiUpload(upload),
        Some(VFILE_HEADER),
    );

    Ok(Reply::SendBinary)
}
