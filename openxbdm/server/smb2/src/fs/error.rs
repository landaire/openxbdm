//! File system operation errors.

use crate::status::NtStatus;

/// Why a file system operation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// The last component of the path does not exist.
    NotFound,
    /// A directory of the path does not exist.
    PathNotFound,
    /// The name exists and the operation does not replace it.
    NameCollision,
    /// The file system does not accept the name.
    NameInvalid,
    AccessDenied,
    /// Another open's share access excludes the requested access.
    SharingViolation,
    /// The operation needs a file and the path names a directory.
    IsADirectory,
    /// The operation needs a directory and the path names a file.
    NotADirectory,
    DirectoryNotEmpty,
    /// The file is read-only and may not be deleted.
    CannotDelete,
    /// The file is marked for deletion.
    DeletePending,
    DiskFull,
    /// The drive has no medium.
    NoMedia,
    /// A rename names another volume.
    NotSameDevice,
    /// The file system does not implement the operation.
    Unsupported,
    /// The file system rejects a value of the operation.
    InvalidValue,
    /// The handle names no open file of the backend.
    InvalidHandle,
    /// The backend cannot hold another open file.
    TooManyOpenFiles,
    /// The share's volume is no longer present.
    ShareRemoved,
    /// A failure with no variant here; the reply carries its status.
    Other(UnmappedStatus),
}

impl FsError {
    /// The error a file system status reports, for backends whose
    /// platform returns NT statuses.
    pub const fn from_status(status: NtStatus) -> Self {
        match status {
            NtStatus::ObjectNameNotFound => Self::NotFound,
            NtStatus::ObjectPathNotFound => Self::PathNotFound,
            NtStatus::ObjectNameCollision => Self::NameCollision,
            NtStatus::ObjectNameInvalid => Self::NameInvalid,
            NtStatus::AccessDenied => Self::AccessDenied,
            NtStatus::SharingViolation => Self::SharingViolation,
            NtStatus::FileIsADirectory => Self::IsADirectory,
            NtStatus::NotADirectory => Self::NotADirectory,
            NtStatus::DirectoryNotEmpty => Self::DirectoryNotEmpty,
            NtStatus::CannotDelete => Self::CannotDelete,
            NtStatus::DeletePending => Self::DeletePending,
            NtStatus::DiskFull => Self::DiskFull,
            NtStatus::NoMediaInDevice => Self::NoMedia,
            NtStatus::NotSameDevice => Self::NotSameDevice,
            NtStatus::NotSupported => Self::Unsupported,
            NtStatus::InvalidParameter => Self::InvalidValue,
            NtStatus::InvalidHandle => Self::InvalidHandle,
            NtStatus::InsufficientResources => Self::TooManyOpenFiles,
            NtStatus::NetworkNameDeleted => Self::ShareRemoved,
            status => Self::Other(UnmappedStatus(status)),
        }
    }
}

impl From<FsError> for NtStatus {
    fn from(error: FsError) -> Self {
        match error {
            FsError::NotFound => NtStatus::ObjectNameNotFound,
            FsError::PathNotFound => NtStatus::ObjectPathNotFound,
            FsError::NameCollision => NtStatus::ObjectNameCollision,
            FsError::NameInvalid => NtStatus::ObjectNameInvalid,
            FsError::AccessDenied => NtStatus::AccessDenied,
            FsError::SharingViolation => NtStatus::SharingViolation,
            FsError::IsADirectory => NtStatus::FileIsADirectory,
            FsError::NotADirectory => NtStatus::NotADirectory,
            FsError::DirectoryNotEmpty => NtStatus::DirectoryNotEmpty,
            FsError::CannotDelete => NtStatus::CannotDelete,
            FsError::DeletePending => NtStatus::DeletePending,
            FsError::DiskFull => NtStatus::DiskFull,
            FsError::NoMedia => NtStatus::NoMediaInDevice,
            FsError::NotSameDevice => NtStatus::NotSameDevice,
            FsError::Unsupported => NtStatus::NotSupported,
            FsError::InvalidValue => NtStatus::InvalidParameter,
            FsError::InvalidHandle => NtStatus::InvalidHandle,
            FsError::TooManyOpenFiles => NtStatus::InsufficientResources,
            FsError::ShareRemoved => NtStatus::NetworkNameDeleted,
            FsError::Other(status) => status.0,
        }
    }
}

impl core::fmt::Display for FsError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("file not found"),
            Self::PathNotFound => formatter.write_str("path not found"),
            Self::NameCollision => formatter.write_str("name exists"),
            Self::NameInvalid => formatter.write_str("name not valid"),
            Self::AccessDenied => formatter.write_str("access denied"),
            Self::SharingViolation => formatter.write_str("sharing violation"),
            Self::IsADirectory => formatter.write_str("file is a directory"),
            Self::NotADirectory => formatter.write_str("file is not a directory"),
            Self::DirectoryNotEmpty => formatter.write_str("directory not empty"),
            Self::CannotDelete => formatter.write_str("file cannot be deleted"),
            Self::DeletePending => formatter.write_str("delete pending"),
            Self::DiskFull => formatter.write_str("disk full"),
            Self::NoMedia => formatter.write_str("no medium"),
            Self::NotSameDevice => formatter.write_str("not the same volume"),
            Self::Unsupported => formatter.write_str("operation not supported"),
            Self::InvalidValue => formatter.write_str("value not valid"),
            Self::InvalidHandle => formatter.write_str("handle not valid"),
            Self::TooManyOpenFiles => formatter.write_str("too many open files"),
            Self::ShareRemoved => formatter.write_str("share removed"),
            Self::Other(status) => write!(formatter, "file system status {}", status.0),
        }
    }
}

impl core::error::Error for FsError {}

/// A status that no [`FsError`] variant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnmappedStatus(NtStatus);

impl UnmappedStatus {
    pub const fn status(self) -> NtStatus {
        self.0
    }
}
