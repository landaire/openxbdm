use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;

/// A failed tracking hook call.
#[derive(Debug, Clone, Copy)]
pub(super) enum TrackingError {
    /// No type is tracked.
    Off,
    /// The type index is past the known types.
    UnknownType,
    /// The record could not be allocated.
    OutOfMemory,
    /// No record has the address.
    NotFound,
    /// The record has another type.
    TypeMismatch,
    /// The record has another size.
    SizeMismatch,
}

impl core::fmt::Display for TrackingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            TrackingError::Off => "allocation tracking is off",
            TrackingError::UnknownType => "unknown allocation type",
            TrackingError::OutOfMemory => "no memory for a tracking record",
            TrackingError::NotFound => "no tracking record has the address",
            TrackingError::TypeMismatch => "the tracking record has another type",
            TrackingError::SizeMismatch => "the tracking record has another size",
        })
    }
}

impl core::error::Error for TrackingError {}

impl From<TrackingError> for Hresult {
    fn from(error: TrackingError) -> Self {
        match error {
            TrackingError::Off => Hresult::from_win32(Win32Error::SERVICE_NOT_ACTIVE),
            TrackingError::UnknownType | TrackingError::TypeMismatch => Hresult::INVALID_ARGUMENT,
            TrackingError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            TrackingError::NotFound => Hresult::from_win32(Win32Error::NOT_FOUND),
            TrackingError::SizeMismatch => Hresult::from_win32(Win32Error::BAD_LENGTH),
        }
    }
}

/// Why a module walk returned no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModuleWalkError {
    /// A null walk or record pointer.
    InvalidArgument,
    /// The snapshot could not be allocated.
    OutOfMemory,
    /// Every module was returned.
    End,
}

impl core::fmt::Display for ModuleWalkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ModuleWalkError::InvalidArgument => "null walk or record pointer",
            ModuleWalkError::OutOfMemory => "no memory for the module snapshot",
            ModuleWalkError::End => "no more modules",
        })
    }
}

impl core::error::Error for ModuleWalkError {}

impl From<ModuleWalkError> for Hresult {
    fn from(error: ModuleWalkError) -> Self {
        match error {
            ModuleWalkError::InvalidArgument => Hresult::INVALID_ARGUMENT,
            ModuleWalkError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            ModuleWalkError::End => Hresult::END_OF_DATA,
        }
    }
}

/// Why export 52 could not take a section snapshot.
#[derive(Debug, Clone, Copy)]
pub(super) enum SectionSnapshotError {
    OutOfMemory,
    /// No loaded module with headers has the name.
    NoSuchModule,
}

impl core::fmt::Display for SectionSnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            SectionSnapshotError::OutOfMemory => "no memory for the section snapshot",
            SectionSnapshotError::NoSuchModule => "no loaded module has the name",
        })
    }
}

impl core::error::Error for SectionSnapshotError {}

impl From<SectionSnapshotError> for Hresult {
    fn from(error: SectionSnapshotError) -> Self {
        match error {
            SectionSnapshotError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            SectionSnapshotError::NoSuchModule => ErrorCode::NoSuchModule.hresult(),
        }
    }
}
