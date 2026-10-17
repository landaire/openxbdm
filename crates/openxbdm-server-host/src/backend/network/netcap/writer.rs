//! Buffered writer of the capture file and its positional file access.

use openxbdm_core::status::KernelError;
use openxbdm_server::commands::filesystem;
use openxbdm_server::commands::filesystem::FileData;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::network::netcap::BufferSizes;
use openxbdm_server::commands::network::netcap::capture_file;
use openxbdm_server::commands::network::netcap::capture_file::CaptureFileError;
use openxbdm_server::commands::network::netcap::capture_file::CaptureIo;
use openxbdm_server::commands::network::netcap::capture_file::Recorder;

use crate::backend::MockBackend;

/// Buffered writer of the capture file. The simulated writer thread
/// drains the buffer as soon as it is woken.
#[derive(Debug)]
pub(super) struct Writer {
    handle: FileHandle,
    /// Object name the file was created with.
    name: Vec<u8>,

    /// Buffered bytes.
    buffer: Vec<u8>,
    size: u32,
    /// Buffered bytes that wake the writer thread.
    chunk: u32,

    /// File offset after the buffered bytes.
    position: u64,
    /// End of the last complete record; `None` after a record was cut
    /// short by a full buffer.
    record_end: Option<u64>,
    /// `record_end` as of the last buffer write.
    flushed_record_end: u64,

    /// The writer thread runs; it exits on its first write failure.
    running: bool,
}

impl Writer {
    /// A running writer whose next byte goes to file offset `start`.
    pub(super) fn new(handle: FileHandle, name: Vec<u8>, sizes: BufferSizes, start: u64) -> Self {
        Self {
            handle,
            name,
            buffer: Vec::with_capacity(sizes.buffer as usize),
            size: sizes.buffer,
            chunk: sizes.chunk,
            position: start,
            record_end: Some(start),
            flushed_record_end: start,
            running: true,
        }
    }

    pub(super) fn handle(&self) -> FileHandle {
        self.handle
    }

    /// Copy `data` into the buffer (0x91f6a730).
    pub(super) fn put(
        &mut self,
        backend: &mut MockBackend,
        data: &[u8],
        completes_record: bool,
    ) -> Result<(), CaptureFileError> {
        if self.record_end.is_none() {
            return Err(CaptureFileError::WriteFault);
        }

        let count = data.len().min(self.size as usize - self.buffer.len());
        self.buffer.extend_from_slice(&data[..count]);
        self.position += count as u64;

        let complete = count == data.len();
        if complete && completes_record {
            self.record_end = Some(self.position);
        }

        if self.buffer.len() >= self.chunk as usize
            && self.running
            && !backend.network.netcap.writer_stalled
            && self.drain(backend).is_err()
        {
            self.running = false;
        }

        if complete {
            return Ok(());
        }

        self.record_end = None;

        Err(CaptureFileError::WriteFault)
    }

    /// Write out the whole buffer (0x91f6a4e8).
    fn drain(&mut self, backend: &mut MockBackend) -> Result<(), CaptureFileError> {
        while !self.buffer.is_empty() {
            let count = self.buffer.len().min(capture_file::WRITE_LIMIT as usize);
            let offset = self.position - self.buffer.len() as u64;
            let committed = self.record_end;
            self.io(backend).write_at(offset, &self.buffer[..count])?;

            if let Some(end) = committed {
                self.flushed_record_end = end;
            }
            self.buffer.drain(..count);
        }

        Ok(())
    }

    /// Stop the thread, write the buffer, and finish the file (0x91f69d18).
    pub(super) fn finish(
        &mut self,
        backend: &mut MockBackend,
        recorder: &mut Recorder,
    ) -> Result<(), CaptureFileError> {
        self.running = false;
        self.drain(backend)?;

        let end = match self.record_end {
            None if recorder.frames() > 0 => self.flushed_record_end,
            _ => self.position,
        };

        recorder.finish(&mut self.io(backend), end)
    }

    pub(super) fn io<'a>(&'a self, backend: &'a mut MockBackend) -> FileIo<'a> {
        FileIo {
            backend,
            handle: self.handle,
            name: &self.name,
        }
    }
}

/// Positional access to the capture file through the simulated file system.
pub(super) struct FileIo<'a> {
    backend: &'a mut MockBackend,
    handle: FileHandle,
    name: &'a [u8],
}

impl CaptureIo for FileIo<'_> {
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), CaptureFileError> {
        let data = self
            .backend
            .filesystem
            .read(self.name)
            .ok_or(KernelError::ObjectNameNotFound)?;
        let Some(available) = data.get(offset as usize..).filter(|rest| !rest.is_empty()) else {
            return Err(KernelError::EndOfFile.into());
        };

        let bytes = available
            .get(..buffer.len())
            .ok_or(CaptureFileError::BadLength)?;
        buffer.copy_from_slice(bytes);

        Ok(())
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), CaptureFileError> {
        filesystem::Backend::write_file(
            self.backend,
            self.handle,
            Some(offset),
            FileData::Bytes(data),
        )
        .map_err(CaptureFileError::Kernel)
    }

    fn truncate(&mut self, length: u64) -> Result<(), CaptureFileError> {
        filesystem::Backend::set_end_of_file(self.backend, self.handle, length)
            .map_err(CaptureFileError::Kernel)
    }
}
