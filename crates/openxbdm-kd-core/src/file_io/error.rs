//! Host file system errors.

/// A file request the host does not complete.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HostFileError {
    /// No host file serves the path.
    NotMapped,
    /// The host file serving the path cannot be opened.
    OpenFailed,
    /// The handle is not open.
    UnknownHandle,
    /// The host file cannot be read.
    ReadFailed,
}
