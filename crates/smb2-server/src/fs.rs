//! File system values exchanged with the backend. The values follow the
//! NT I/O model that SMB 2 carries (MS-FSCC).

use crate::status::NtStatus;

/// A FILETIME: 100-nanosecond intervals since 1601-01-01 UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FileTime(pub u64);

/// File attribute bits (MS-FSCC 2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FileAttributes(pub u32);

impl FileAttributes {
    pub const READONLY: Self = Self(0x1);
    pub const HIDDEN: Self = Self(0x2);
    pub const SYSTEM: Self = Self(0x4);
    pub const DIRECTORY: Self = Self(0x10);
    pub const ARCHIVE: Self = Self(0x20);
    pub const NORMAL: Self = Self(0x80);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn is_directory(self) -> bool {
        self.contains(Self::DIRECTORY)
    }
}

/// An access mask (MS-SMB2 2.2.13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AccessMask(pub u32);

impl AccessMask {
    pub const READ_DATA: Self = Self(0x0000_0001);
    pub const WRITE_DATA: Self = Self(0x0000_0002);
    pub const APPEND_DATA: Self = Self(0x0000_0004);
    pub const READ_EA: Self = Self(0x0000_0008);
    pub const WRITE_EA: Self = Self(0x0000_0010);
    pub const EXECUTE: Self = Self(0x0000_0020);
    pub const DELETE_CHILD: Self = Self(0x0000_0040);
    pub const READ_ATTRIBUTES: Self = Self(0x0000_0080);
    pub const WRITE_ATTRIBUTES: Self = Self(0x0000_0100);
    pub const DELETE: Self = Self(0x0001_0000);
    pub const READ_CONTROL: Self = Self(0x0002_0000);
    pub const WRITE_DAC: Self = Self(0x0004_0000);
    pub const WRITE_OWNER: Self = Self(0x0008_0000);
    pub const SYNCHRONIZE: Self = Self(0x0010_0000);
    pub const ACCESS_SYSTEM_SECURITY: Self = Self(0x0100_0000);
    pub const MAXIMUM_ALLOWED: Self = Self(0x0200_0000);
    pub const GENERIC_ALL: Self = Self(0x1000_0000);
    pub const GENERIC_EXECUTE: Self = Self(0x2000_0000);
    pub const GENERIC_WRITE: Self = Self(0x4000_0000);
    pub const GENERIC_READ: Self = Self(0x8000_0000);
    /// Every specific and standard right of a file.
    pub const FILE_ALL_ACCESS: Self = Self(0x001f_01ff);
    /// Rights that modify a file or its directory entry.
    pub const MODIFY: Self = Self(
        Self::WRITE_DATA.0
            | Self::APPEND_DATA.0
            | Self::WRITE_EA.0
            | Self::DELETE_CHILD.0
            | Self::WRITE_ATTRIBUTES.0
            | Self::DELETE.0
            | Self::WRITE_DAC.0
            | Self::WRITE_OWNER.0,
    );

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Share access of an open (MS-SMB2 2.2.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ShareAccess(pub u32);

impl ShareAccess {
    pub const READ: Self = Self(0x1);
    pub const WRITE: Self = Self(0x2);
    pub const DELETE: Self = Self(0x4);
    pub const ALL: Self = Self(0x7);
}

/// What a create does when the file exists or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CreateDisposition {
    Supersede = 0,
    Open = 1,
    Create = 2,
    OpenIf = 3,
    Overwrite = 4,
    OverwriteIf = 5,
}

impl CreateDisposition {
    pub const fn from_wire(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Supersede,
            1 => Self::Open,
            2 => Self::Create,
            3 => Self::OpenIf,
            4 => Self::Overwrite,
            5 => Self::OverwriteIf,
            _ => return None,
        })
    }
}

/// Create options (MS-SMB2 2.2.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CreateOptions(pub u32);

impl CreateOptions {
    pub const DIRECTORY_FILE: Self = Self(0x0000_0001);
    pub const WRITE_THROUGH: Self = Self(0x0000_0002);
    pub const SEQUENTIAL_ONLY: Self = Self(0x0000_0004);
    pub const NO_INTERMEDIATE_BUFFERING: Self = Self(0x0000_0008);
    pub const SYNCHRONOUS_IO_ALERT: Self = Self(0x0000_0010);
    pub const SYNCHRONOUS_IO_NONALERT: Self = Self(0x0000_0020);
    pub const NON_DIRECTORY_FILE: Self = Self(0x0000_0040);
    pub const COMPLETE_IF_OPLOCKED: Self = Self(0x0000_0100);
    pub const NO_EA_KNOWLEDGE: Self = Self(0x0000_0200);
    pub const RANDOM_ACCESS: Self = Self(0x0000_0800);
    pub const DELETE_ON_CLOSE: Self = Self(0x0000_1000);
    pub const OPEN_BY_FILE_ID: Self = Self(0x0000_2000);
    pub const OPEN_FOR_BACKUP_INTENT: Self = Self(0x0000_4000);
    pub const NO_COMPRESSION: Self = Self(0x0000_8000);
    pub const OPEN_REPARSE_POINT: Self = Self(0x0020_0000);
    pub const OPEN_NO_RECALL: Self = Self(0x0040_0000);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

/// Result of a create (MS-SMB2 2.2.14 CreateAction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CreateAction {
    Superseded = 0,
    Opened = 1,
    Created = 2,
    Overwritten = 3,
}

/// A file system's identifier of a file (MS-FSCC FileInternalInformation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIndex(pub u64);

/// Size, times, and attributes of an open file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileInformation {
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub attributes: FileAttributes,
    /// `None` when the file system has no stable file identifiers.
    pub index: Option<FileIndex>,
}

/// Times and attributes to change; `None` leaves a value unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BasicInformation {
    pub creation_time: Option<FileTime>,
    pub last_access_time: Option<FileTime>,
    pub last_write_time: Option<FileTime>,
    pub change_time: Option<FileTime>,
    pub attributes: Option<FileAttributes>,
}

/// Capacity of a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeSize {
    pub total_units: u64,
    pub available_units: u64,
    pub sectors_per_unit: u32,
    pub bytes_per_sector: u32,
}

/// File system attribute bits (MS-FSCC 2.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FileSystemAttributes(pub u32);

impl FileSystemAttributes {
    pub const CASE_SENSITIVE_SEARCH: Self = Self(0x0000_0001);
    pub const CASE_PRESERVED_NAMES: Self = Self(0x0000_0002);
    pub const UNICODE_ON_DISK: Self = Self(0x0000_0004);
    pub const PERSISTENT_ACLS: Self = Self(0x0000_0008);
    pub const READ_ONLY_VOLUME: Self = Self(0x0008_0000);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Identity and capabilities of the file system behind a share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeInformation {
    pub size: VolumeSize,
    pub serial_number: u32,
    pub creation_time: FileTime,
    pub attributes: FileSystemAttributes,
    /// Longest file name component, in UTF-16 code units.
    pub maximum_component_length: u32,
    pub file_system_name: FileSystemName,
}

/// Bytes of a file system name.
pub const FILE_SYSTEM_NAME_CAPACITY: usize = 16;

/// A file system name in ASCII, such as `NTFS` or `FATX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSystemName {
    bytes: [u8; FILE_SYSTEM_NAME_CAPACITY],
    length: u8,
}

impl FileSystemName {
    /// `None` when `name` is longer than [`FILE_SYSTEM_NAME_CAPACITY`] or
    /// not ASCII.
    pub const fn new(name: &[u8]) -> Option<Self> {
        if name.len() > FILE_SYSTEM_NAME_CAPACITY || !name.is_ascii() {
            return None;
        }
        let mut bytes = [0; FILE_SYSTEM_NAME_CAPACITY];
        let mut index = 0;
        while index < name.len() {
            bytes[index] = name[index];
            index += 1;
        }
        Some(Self {
            bytes,
            length: name.len() as u8,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

/// Longest name component in UTF-16 code units that a directory entry
/// carries.
pub const NAME_CAPACITY: usize = 255;

/// One directory entry; the name is in the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub information: FileInformation,
    /// Code units of the name.
    pub name_length: usize,
}

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

/// A status that no [`FsError`] variant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnmappedStatus(NtStatus);

impl UnmappedStatus {
    pub const fn status(self) -> NtStatus {
        self.0
    }
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
