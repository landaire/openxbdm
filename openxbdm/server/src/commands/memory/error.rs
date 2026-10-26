use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;
use xbox360_sys::status::Facility;

use crate::reply::CommandError;

/// The named module is not loaded or has no NT header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoSuchModule;

/// Why an XEX optional header field cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XexFieldError {
    NoSuchModule,
    /// The module's XEX header has no such field.
    FieldAbsent,
}

impl From<XexFieldError> for CommandError {
    fn from(error: XexFieldError) -> Self {
        match error {
            XexFieldError::NoSuchModule => ErrorCode::NoSuchModule.into(),
            XexFieldError::FieldAbsent => Self::Memory(MemoryError::NoSuchField),
        }
    }
}

/// Failures of this domain that no other [`CommandError`] form reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    /// 437: the XEX header has no such field.
    NoSuchField,
    /// 442: the detour engine is not running.
    DetourNotRunning,
    /// Saving the tracking records failed; the kernel's Win32 translation
    /// of the status.
    TrackingSave(Win32Error),
}

impl From<MemoryError> for Hresult {
    fn from(error: MemoryError) -> Self {
        match error {
            MemoryError::NoSuchField => Hresult::NO_SUCH_FIELD,
            MemoryError::DetourNotRunning => Hresult::INVALID_STATE,
            // Stock moves the code to the Win32 facility without the sign
            // test of HRESULT_FROM_WIN32.
            MemoryError::TrackingSave(error) => {
                Hresult::failure(Facility::WIN32, error.code() as u16)
            }
        }
    }
}

/// Why a detour engine request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetourError {
    /// The engine is not running.
    NotRunning,
    /// The entry id is out of range.
    BadEntry,
    /// Every entry is in use.
    NoFreeEntry,
}

impl From<DetourError> for CommandError {
    fn from(error: DetourError) -> Self {
        match error {
            DetourError::NotRunning => Self::Memory(MemoryError::DetourNotRunning),
            DetourError::BadEntry => ErrorCode::Undefined.into(),
            DetourError::NoFreeEntry => ErrorCode::OutOfMemory.into(),
        }
    }
}
