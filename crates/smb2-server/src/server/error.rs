//! Why a request fails, and the status each failure has on the wire.

use crate::auth::AuthError;
use crate::fs::FsError;
use crate::path::PathError;
use crate::rpc::PipeError;
use crate::server::shared::FileTableError;
use crate::status::NtStatus;

/// A request that fails with an error reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// A field or combination of fields is not valid for the request.
    InvalidRequest,
    /// The request names no valid session of the connection.
    SessionNotFound,
    /// The request names no tree connect of its session.
    TreeNotFound,
    /// The request names no open of its tree connect.
    OpenNotFound,
    /// No share has the requested name for the user.
    ShareNotFound,
    /// The user may not do what the request asks.
    AccessDenied,
    /// A table of the connection or server is full.
    TableFull,
    /// The server does not implement what the request asks.
    Unsupported,
    /// The information class is not one of the request's type.
    UnknownInformationClass,
    /// The output buffer cannot hold the fixed part of the information.
    InformationLengthMismatch,
    /// A read starts at or past the end of the file.
    EndOfFile,
    /// The operation does not apply to the open's kind of file.
    WrongFileKind,
    /// The impersonation level is above delegate.
    BadImpersonationLevel,
    /// The named pipe or previous version does not exist.
    NameNotFound,
    /// A name in the request is not valid.
    NameInvalid,
    /// The reply does not fit in the response buffer.
    ReplyOverflow,
    /// Extended attributes were requested.
    ExtendedAttributes,
    /// A later query of a directory scan found no more names.
    NoMoreFiles,
    /// The first query of a directory scan found no matching name.
    NoMatchingFile,
    /// A byte-range lock conflicts and the request may not wait.
    LockNotGranted,
    /// An unlock names a range the open does not hold.
    RangeNotLocked,
    /// The end of a lock range is past the largest offset.
    InvalidLockRange,
    /// A read or write overlaps another open's byte-range lock.
    LockConflict,
    /// The security information asks for the system ACL.
    PrivilegeNotHeld,
    /// Session binding is not supported for the dialect.
    BindingNotAccepted,
    /// DFS referrals are requested from a server without DFS.
    NoDfs,
    /// A reparse point is requested from a file that has none.
    NotAReparsePoint,
    /// The client offers no preauthentication hash the server supports.
    NoPreauthenticationHash,
    FileSystem(FsError),
    Path(PathError),
    Authentication(AuthError),
    Pipe(PipeError),
    FileTable(FileTableError),
}

impl From<RequestError> for NtStatus {
    fn from(error: RequestError) -> Self {
        match error {
            RequestError::InvalidRequest => NtStatus::InvalidParameter,
            RequestError::SessionNotFound => NtStatus::UserSessionDeleted,
            RequestError::TreeNotFound => NtStatus::NetworkNameDeleted,
            RequestError::OpenNotFound => NtStatus::FileClosed,
            RequestError::ShareNotFound => NtStatus::BadNetworkName,
            RequestError::AccessDenied => NtStatus::AccessDenied,
            RequestError::TableFull => NtStatus::InsufficientResources,
            RequestError::Unsupported => NtStatus::NotSupported,
            RequestError::UnknownInformationClass => NtStatus::InvalidInfoClass,
            RequestError::InformationLengthMismatch => NtStatus::InfoLengthMismatch,
            RequestError::EndOfFile => NtStatus::EndOfFile,
            RequestError::WrongFileKind => NtStatus::InvalidDeviceRequest,
            RequestError::BadImpersonationLevel => NtStatus::BadImpersonationLevel,
            RequestError::NameNotFound => NtStatus::ObjectNameNotFound,
            RequestError::NameInvalid => NtStatus::ObjectNameInvalid,
            RequestError::ReplyOverflow => NtStatus::BufferOverflow,
            RequestError::ExtendedAttributes => NtStatus::EasNotSupported,
            RequestError::NoMoreFiles => NtStatus::NoMoreFiles,
            RequestError::NoMatchingFile => NtStatus::NoSuchFile,
            RequestError::LockNotGranted => NtStatus::LockNotGranted,
            RequestError::RangeNotLocked => NtStatus::RangeNotLocked,
            RequestError::InvalidLockRange => NtStatus::InvalidLockRange,
            RequestError::LockConflict => NtStatus::FileLockConflict,
            RequestError::PrivilegeNotHeld => NtStatus::PrivilegeNotHeld,
            RequestError::BindingNotAccepted => NtStatus::RequestNotAccepted,
            RequestError::NoDfs => NtStatus::FsDriverRequired,
            RequestError::NotAReparsePoint => NtStatus::NotAReparsePoint,
            RequestError::NoPreauthenticationHash => NtStatus::NoPreauthIntegrityHashOverlap,
            RequestError::FileSystem(error) => error.into(),
            RequestError::Path(error) => error.into(),
            RequestError::Authentication(error) => error.into(),
            RequestError::Pipe(error) => error.into(),
            RequestError::FileTable(error) => error.into(),
        }
    }
}

impl From<FsError> for RequestError {
    fn from(error: FsError) -> Self {
        Self::FileSystem(error)
    }
}

impl From<PathError> for RequestError {
    fn from(error: PathError) -> Self {
        Self::Path(error)
    }
}

impl From<AuthError> for RequestError {
    fn from(error: AuthError) -> Self {
        Self::Authentication(error)
    }
}

impl From<PipeError> for RequestError {
    fn from(error: PipeError) -> Self {
        Self::Pipe(error)
    }
}

impl From<FileTableError> for RequestError {
    fn from(error: FileTableError) -> Self {
        Self::FileTable(error)
    }
}

/// A status of a reply with a regular body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    Success,
    /// The output buffer held only part of the data.
    BufferOverflow,
    /// The authentication exchange continues.
    MoreProcessingRequired,
    /// The changes of a watched directory were not kept; the client lists
    /// it again.
    NotifyEnumDirectory,
}

impl From<Completion> for NtStatus {
    fn from(completion: Completion) -> Self {
        match completion {
            Completion::Success => NtStatus::Success,
            Completion::BufferOverflow => NtStatus::BufferOverflow,
            Completion::MoreProcessingRequired => NtStatus::MoreProcessingRequired,
            Completion::NotifyEnumDirectory => NtStatus::NotifyEnumDir,
        }
    }
}
