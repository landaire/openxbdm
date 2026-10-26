use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;

/// Why a capture file operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFileError {
    /// A frame is longer than [`MAX_FRAME_LENGTH`], or a file transfer was
    /// short.
    ///
    /// [`MAX_FRAME_LENGTH`]: super::MAX_FRAME_LENGTH
    BadLength,
    /// The data limit is used up.
    DataLimitReached,
    /// The write buffer was full where the caller could not wait for it.
    WriteFault,
    /// A record header in the file is inconsistent.
    InvalidData,
    /// No memory for the context or the write buffer.
    OutOfMemory,
    /// A file operation failed.
    Kernel(KernelError),
}

impl From<CaptureFileError> for Hresult {
    fn from(error: CaptureFileError) -> Self {
        match error {
            CaptureFileError::BadLength => Win32Error::BAD_LENGTH.into(),
            CaptureFileError::DataLimitReached => Win32Error::BUFFER_OVERFLOW.into(),
            CaptureFileError::WriteFault => Win32Error::WRITE_FAULT.into(),
            CaptureFileError::InvalidData => Win32Error::INVALID_DATA.into(),
            CaptureFileError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            CaptureFileError::Kernel(error) => error.into(),
        }
    }
}

impl From<KernelError> for CaptureFileError {
    fn from(error: KernelError) -> Self {
        Self::Kernel(error)
    }
}
