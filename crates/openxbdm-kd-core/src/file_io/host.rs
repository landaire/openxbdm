//! Host side of the file I/O exchange: the files the host offers and the
//! replies it sends for each request.

use crate::NtStatus;
use crate::file_io::FileIoReply;
use crate::file_io::FileIoRequest;
use crate::file_io::HostFileError;
use crate::file_io::HostFileHandle;
use crate::file_io::MAX_READ_LEN;
use crate::file_io::OpenRequest;
use crate::file_io::OpenedFile;

/// Files the host offers to the kernel.
pub trait HostFileSystem {
    fn open(&mut self, request: &OpenRequest<'_>) -> Result<OpenedFile, HostFileError>;

    /// Reads at `offset` into `buffer`. Returns 0 only at end of file.
    fn read(
        &mut self,
        handle: HostFileHandle,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, HostFileError>;

    fn close(&mut self, handle: HostFileHandle) -> Result<(), HostFileError>;
}

/// A request `respond` fails.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum RequestFailure {
    Host(HostFileError),
    /// A non-empty read at or past the end of the file.
    EndOfFile,
    UnknownApi,
}

impl RequestFailure {
    fn status(self) -> NtStatus {
        match self {
            // The kernel then opens the file from its own devices.
            Self::Host(HostFileError::NotMapped | HostFileError::OpenFailed) => {
                NtStatus::OBJECT_NAME_NOT_FOUND
            }
            Self::Host(HostFileError::UnknownHandle) => NtStatus::INVALID_HANDLE,
            Self::Host(HostFileError::ReadFailed) => NtStatus::UNSUCCESSFUL,
            Self::EndOfFile => NtStatus::END_OF_FILE,
            Self::UnknownApi => NtStatus::NOT_IMPLEMENTED,
        }
    }
}

/// Answers a request from `files`. Read data is placed in `data`; the
/// reply payload is the encoded header followed by `data[..length]`.
pub fn respond(
    request: &FileIoRequest<'_>,
    files: &mut impl HostFileSystem,
    data: &mut [u8; MAX_READ_LEN],
) -> (FileIoReply, usize) {
    let failed = |failure: RequestFailure| FileIoReply::Failed {
        api: request.api(),
        status: failure.status(),
    };

    match request {
        FileIoRequest::Open(open) => match files.open(open) {
            Ok(opened) => (FileIoReply::Opened(opened), 0),
            Err(error) => (failed(RequestFailure::Host(error)), 0),
        },
        FileIoRequest::Read(read) => {
            let length = (read.length as usize).min(MAX_READ_LEN);
            match files.read(read.handle, read.offset, &mut data[..length]) {
                // A successful empty reply makes the kernel repeat the
                // request forever (0x801b3a68 subtracts zero).
                Ok(0) if length != 0 => (failed(RequestFailure::EndOfFile), 0),
                Ok(count) => (FileIoReply::Read, count.min(length)),
                Err(error) => (failed(RequestFailure::Host(error)), 0),
            }
        }
        FileIoRequest::Close(close) => match files.close(close.handle) {
            Ok(()) => (FileIoReply::Closed, 0),
            Err(error) => (failed(RequestFailure::Host(error)), 0),
        },
        FileIoRequest::Other { .. } => (failed(RequestFailure::UnknownApi), 0),
    }
}
