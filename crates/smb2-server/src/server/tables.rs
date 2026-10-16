//! Sessions, tree connects, and opens of a connection.

use crate::backend::FileHandle;
use crate::backend::ShareId;
use crate::backend::UserKind;
use crate::fs::AccessMask;
use crate::fs::CreateOptions;
use crate::fs::FileTime;
use crate::fs::NAME_CAPACITY;
use crate::rpc::Pipe;
use crate::server::error::RequestError;
use crate::server::security::EncryptionKeys;
use crate::server::security::Nonce;
use crate::server::security::PreauthHash;
use crate::server::security::SigningKey;
use crate::server::shared::ByteRange;
use crate::server::shared::ChangeFilter;
use crate::server::shared::FileSlot;
use crate::server::shared::LockEpoch;
use crate::server::wire::AsyncId;
use crate::server::wire::CreditCharge;
use crate::server::wire::FileId;
use crate::server::wire::MessageId;
use crate::status::NtStatus;

/// Identifier of a session on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

/// Identifier of a tree connect on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TreeId(pub u32);

impl TreeId {
    /// The first identifier a connection assigns.
    pub const FIRST: Self = Self(1);
}

/// Index of a session slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSlot(pub u8);

/// Index of a tree connect slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeSlot(pub u8);

/// Index of an open slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenSlot(pub u8);

/// Index of a named pipe slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeIndex(pub u8);

/// Index of a search pattern slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternIndex(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Authentication has not finished.
    InProgress,
    Valid,
}

#[derive(Debug, Clone, Copy)]
pub struct Session {
    pub id: SessionId,
    pub state: SessionState,
    pub kind: UserKind,
    /// Signing key; `None` for guest and anonymous sessions.
    pub signing: Option<SigningKey>,
    /// Every message of the session is signed.
    pub signing_required: bool,
    /// Encryption keys when the dialect and client support encryption.
    pub encryption: Option<EncryptionKeys>,
    /// Every request of the session must be encrypted.
    pub encrypt_data: bool,
    /// Preauthentication integrity hash of the session's setup (SMB 3.1.1).
    pub preauth: PreauthHash,
    /// Nonce of the next message this session encrypts.
    pub next_nonce: Nonce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeKind {
    Disk {
        share: ShareId,
        writable: bool,
    },
    /// `IPC$`.
    Pipe,
}

#[derive(Debug, Clone, Copy)]
pub struct Tree {
    pub id: TreeId,
    pub session: SessionSlot,
    pub kind: TreeKind,
}

/// The search pattern of a directory open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    /// `*`: every name.
    All,
    /// A pattern in the connection's pattern slot.
    Stored(PatternIndex),
}

/// Enumeration state of a directory open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Search {
    pub pattern: Pattern,
    /// A query completed since the last restart.
    pub queried: bool,
    /// The backend's enumeration ended.
    pub exhausted: bool,
    /// How many of the `.` and `..` entries were returned.
    pub dots_listed: u8,
    /// The next backend read restarts the backend's enumeration.
    pub restart_backend: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileOpen {
    pub handle: FileHandle,
    pub directory: bool,
    /// `None` before the first directory query.
    pub search: Option<Search>,
    /// Byte offset for FilePositionInformation.
    pub position: u64,
    /// Mode bits for FileModeInformation.
    pub mode: CreateOptions,
    /// This open marked the file for deletion.
    pub delete_pending: bool,
    /// The file's entry in the server's file table.
    pub file: FileSlot,
    /// A change was recorded for data this open wrote.
    pub write_recorded: bool,
    /// Change notification state once a CHANGE_NOTIFY named the open.
    pub notify: Option<NotifyState>,
}

/// Change notification state of a directory open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyState {
    pub filter: ChangeFilter,
    /// Changes anywhere below the directory count.
    pub tree: bool,
    /// A change happened while no CHANGE_NOTIFY was pending, and was not
    /// kept.
    pub overflowed: bool,
    /// Digest of the directory contents at the last scan; `None` when the
    /// next scan only records a new baseline.
    pub digest: Option<ContentDigest>,
    /// When the directory was last scanned.
    pub scanned: FileTime,
}

/// A digest of directory contents for detecting changes made outside the
/// server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentDigest(pub [u8; 16]);

/// A request answered later (MS-SMB2 3.3.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending {
    pub message_id: MessageId,
    pub async_id: AsyncId,
    pub session: SessionSlot,
    pub open: OpenSlot,
    /// The request was signed, so the final reply is.
    pub signed: bool,
    /// The request was encrypted, so the final reply is.
    pub encrypted: bool,
    /// Credit charge of the request, echoed in the final reply.
    pub credit_charge: CreditCharge,
    pub kind: PendingKind,
    /// How the request ended, once known and not yet answered.
    pub ready: Option<PendingOutcome>,
}

/// How a request answered later ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingOutcome {
    /// The lock was granted, or the watched directory has change records.
    Completed,
    /// The watched directory changed in ways not recorded; the client
    /// lists it again.
    EnumerateDirectory,
    /// A CANCEL ended the request.
    Cancelled,
    /// The open the request waits on was closed.
    Closed,
    Failed(RequestError),
}

impl From<PendingOutcome> for NtStatus {
    fn from(outcome: PendingOutcome) -> Self {
        match outcome {
            PendingOutcome::Completed => NtStatus::Success,
            PendingOutcome::EnumerateDirectory => NtStatus::NotifyEnumDir,
            PendingOutcome::Cancelled => NtStatus::Cancelled,
            PendingOutcome::Closed => NtStatus::NotifyCleanup,
            PendingOutcome::Failed(error) => error.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    /// CHANGE_NOTIFY with the reply buffer size the client allows.
    Notify { output_length: u32 },
    /// A blocking byte-range lock, retried when the lock table's epoch
    /// changes.
    Lock {
        range: ByteRange,
        exclusive: bool,
        epoch: LockEpoch,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenKind {
    File(FileOpen),
    /// Index of the pipe slot.
    Pipe(PipeIndex),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Open {
    pub id: FileId,
    pub session: SessionSlot,
    pub tree: TreeSlot,
    pub access: AccessMask,
    pub kind: OpenKind,
}

/// Search pattern of a directory open, held per connection.
#[derive(Debug, Clone, Copy)]
pub struct PatternSlot {
    pub owner: Option<OpenSlot>,
    pub units: [u16; NAME_CAPACITY],
    pub length: u16,
}

impl PatternSlot {
    pub const fn new() -> Self {
        Self {
            owner: None,
            units: [0; NAME_CAPACITY],
            length: 0,
        }
    }

    pub fn units(&self) -> &[u16] {
        &self.units[..usize::from(self.length)]
    }
}

/// A directory entry read from the backend that did not fit in the reply
/// that read it.
#[derive(Debug, Clone, Copy)]
pub struct HeldEntry {
    pub owner: Option<OpenSlot>,
    pub entry: crate::fs::DirectoryEntry,
    pub name: [u16; NAME_CAPACITY],
}

impl HeldEntry {
    pub const fn new() -> Self {
        Self {
            owner: None,
            entry: crate::fs::DirectoryEntry {
                information: crate::fs::FileInformation {
                    creation_time: crate::fs::FileTime(0),
                    last_access_time: crate::fs::FileTime(0),
                    last_write_time: crate::fs::FileTime(0),
                    change_time: crate::fs::FileTime(0),
                    allocation_size: 0,
                    end_of_file: 0,
                    attributes: crate::fs::FileAttributes(0),
                    index: None,
                },
                name_length: 0,
            },
            name: [0; NAME_CAPACITY],
        }
    }
}

/// A named pipe slot.
pub struct PipeSlot {
    pub owner: Option<OpenSlot>,
    pub pipe: Pipe,
}

impl PipeSlot {
    pub const fn new() -> Self {
        Self {
            owner: None,
            pipe: Pipe::new(),
        }
    }
}
