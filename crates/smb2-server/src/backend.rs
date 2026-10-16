//! Services the server requires from its host.
//!
//! The server calls the backend synchronously while it handles a message;
//! each call completes before the server continues.

use crate::fs::AccessMask;
use crate::fs::BasicInformation;
use crate::fs::CreateAction;
use crate::fs::CreateDisposition;
use crate::fs::CreateOptions;
use crate::fs::DirectoryEntry;
use crate::fs::FileAttributes;
use crate::fs::FileInformation;
use crate::fs::FileTime;
use crate::fs::FsError;
use crate::fs::NAME_CAPACITY;
use crate::fs::ShareAccess;
use crate::fs::VolumeInformation;
use crate::path::SharePath;
use crate::utf16::Utf16Le;

/// Bytes of the computer name, at most the 15 characters of a NetBIOS
/// name.
pub const COMPUTER_NAME_CAPACITY: usize = 15;
/// Code units of a share name.
pub const SHARE_NAME_CAPACITY: usize = 80;

/// Time, randomness, and the server's name.
pub trait Platform {
    /// Current time.
    fn system_time(&mut self) -> FileTime;
    /// Fill `output` with unpredictable bytes.
    fn random_bytes(&mut self, output: &mut [u8]);
    /// The server's NetBIOS computer name in ASCII; returns its length.
    fn computer_name(&mut self, output: &mut [u8; COMPUTER_NAME_CAPACITY]) -> usize;
}

/// NT one-way function of a password: MD4 of its UTF-16LE encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NtOwf(pub [u8; 16]);

impl core::fmt::Debug for NtOwf {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NtOwf(..)")
    }
}

/// How a session's user was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserKind {
    /// NTLMv2 authentication of a known account.
    Authenticated,
    /// User name without an account, admitted by the guest policy. A wrong
    /// password for an existing account fails the logon.
    Guest,
    /// Null session.
    Anonymous,
}

/// Account database and logon policy.
pub trait Accounts {
    /// Password of `user` in `domain`, or `None` when the account is
    /// unknown.
    fn password(&mut self, user: Utf16Le<'_>, domain: Utf16Le<'_>) -> Option<NtOwf>;
    /// Whether user names without an account log on as guest.
    fn allow_guest(&mut self) -> bool;
    /// Whether null sessions are allowed.
    fn allow_anonymous(&mut self) -> bool;
}

/// A disk share, as the backend identifies it. An identifier names the
/// same share for every connection of a [`crate::server::Server`]: open
/// files, byte-range locks, and change records are kept by share and path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShareId(pub u32);

/// A share that a user may connect to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Share {
    pub id: ShareId,
    /// Whether the user may modify files on the share.
    pub writable: bool,
}

/// Position of a share in the share list of a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShareIndex(pub u32);

/// Disk shares. The server provides `IPC$` itself.
pub trait Shares {
    /// Find the share named `name`, compared without case, for a user of
    /// `kind`. `None` when it does not exist or the user may not use it.
    fn find_share(&mut self, name: Utf16Le<'_>, kind: UserKind) -> Option<Share>;
    /// Name of the share at `index` in the share list for a user of `kind`;
    /// returns the code units written, or `None` past the end of the list.
    fn share_name(
        &mut self,
        index: ShareIndex,
        kind: UserKind,
        name: &mut [u16; SHARE_NAME_CAPACITY],
    ) -> Option<usize>;
}

/// An open file or directory, as the backend identifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileHandle(pub u32);

/// Arguments of an open or create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenRequest {
    pub access: AccessMask,
    pub share_access: ShareAccess,
    pub disposition: CreateDisposition,
    /// Only the options in [`OPEN_OPTIONS`] are passed through.
    pub options: CreateOptions,
    pub attributes: FileAttributes,
    pub allocation_size: Option<u64>,
}

/// Create options the server passes to [`FileSystem::open`].
pub const OPEN_OPTIONS: CreateOptions = CreateOptions(
    CreateOptions::DIRECTORY_FILE.0
        | CreateOptions::WRITE_THROUGH.0
        | CreateOptions::NON_DIRECTORY_FILE.0
        | CreateOptions::DELETE_ON_CLOSE.0,
);

/// A successful open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    pub handle: FileHandle,
    pub action: CreateAction,
    pub information: FileInformation,
}

/// File operations on disk shares, in NT semantics. Paths are relative to
/// the share root.
pub trait FileSystem {
    fn open(
        &mut self,
        share: ShareId,
        path: SharePath<'_>,
        request: &OpenRequest,
    ) -> Result<Opened, FsError>;
    /// Close the handle. A pending delete takes effect here.
    fn close(&mut self, handle: FileHandle);
    /// Read at `offset` into `output`; returns the bytes read, 0 at end of
    /// file.
    fn read(
        &mut self,
        handle: FileHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, FsError>;
    /// Write all of `data` at `offset`.
    fn write(&mut self, handle: FileHandle, offset: u64, data: &[u8]) -> Result<(), FsError>;
    fn flush(&mut self, handle: FileHandle) -> Result<(), FsError>;
    fn information(&mut self, handle: FileHandle) -> Result<FileInformation, FsError>;
    fn set_basic_information(
        &mut self,
        handle: FileHandle,
        information: &BasicInformation,
    ) -> Result<(), FsError>;
    fn set_end_of_file(&mut self, handle: FileHandle, size: u64) -> Result<(), FsError>;
    /// Mark the file for deletion when its last handle closes, or clear
    /// the mark.
    fn set_delete_pending(&mut self, handle: FileHandle, delete: bool) -> Result<(), FsError>;
    /// Move the file to `target` on the same share.
    fn rename(
        &mut self,
        handle: FileHandle,
        target: SharePath<'_>,
        replace: bool,
    ) -> Result<(), FsError>;
    /// Next entry of the directory, or the first after `restart`; `None`
    /// after the last. The name goes into `name`. The server lists `.`
    /// and `..` itself; the backend leaves them out.
    fn read_directory(
        &mut self,
        handle: FileHandle,
        restart: bool,
        name: &mut [u16; NAME_CAPACITY],
    ) -> Result<Option<DirectoryEntry>, FsError>;
    fn volume_information(&mut self, handle: FileHandle) -> Result<VolumeInformation, FsError>;
}

/// Everything the server requires.
pub trait Backend: Platform + Accounts + Shares + FileSystem {}

impl<T> Backend for T where T: Platform + Accounts + Shares + FileSystem {}
