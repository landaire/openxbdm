//! State shared by every connection of a server: the files that are open
//! with their paths, byte-range locks, and the log of changes that change
//! notifications report.

mod changes;
mod files;
mod locks;

use self::changes::ChangeLog;
use self::files::FileTable;
use self::locks::LockTable;
use crate::backend::UserKind;
use crate::server::ServerConfig;
use crate::server::tables::SessionId;

pub(crate) use self::changes::Change;
pub(crate) use self::changes::ChangeAction;
pub(crate) use self::changes::ChangeFilter;
pub(crate) use self::changes::ChangeSequence;
pub(crate) use self::files::FileSlot;
pub(crate) use self::locks::ByteRange;
pub(crate) use self::locks::LockEpoch;
pub(crate) use self::locks::LockOwner;
pub(crate) use self::locks::MAX_LOCKS;

/// Superseded sessions [`Server`] keeps until the platform takes them.
pub const SUPERSEDED_QUEUE: usize = 4;

/// Identifier the server gives a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u32);

impl ConnectionId {
    const FIRST: Self = Self(1);

    /// The identifier given after this one, skipping 0.
    fn next(self) -> Self {
        Self(self.0.wrapping_add(1).max(1))
    }
}

/// A session that a new logon replaced by naming it in PreviousSessionId
/// (MS-SMB2 3.3.5.5.3), held by a connection other than the one of the new
/// logon. The platform takes it with [`Server::take_superseded`] and passes
/// it to [`Connection::end_session`](crate::Connection::end_session) of
/// every other connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupersededSession {
    pub id: SessionId,
    /// The kind of the new session; only a session of the same kind ends.
    pub kind: UserKind,
}

/// Server-wide state: the configuration and the tables every connection
/// uses. One `Server` serves all connections; the platform passes it to
/// each [`Connection`](crate::Connection) call.
pub struct Server {
    config: Option<ServerConfig>,

    pub(crate) files: FileTable,
    pub(crate) locks: LockTable,
    pub(crate) changes: ChangeLog,

    next_connection: ConnectionId,
    /// Oldest first.
    superseded: [Option<SupersededSession>; SUPERSEDED_QUEUE],
}

impl Server {
    /// A server without configuration; connections are refused until
    /// [`Server::configure`].
    pub const fn new() -> Self {
        Self {
            config: None,
            files: FileTable::new(),
            locks: LockTable::new(),
            changes: ChangeLog::new(),
            next_connection: ConnectionId::FIRST,
            superseded: [None; SUPERSEDED_QUEUE],
        }
    }

    pub fn configure(&mut self, config: ServerConfig) {
        self.config = Some(config);
    }

    pub fn config(&self) -> Option<&ServerConfig> {
        self.config.as_ref()
    }

    /// The oldest superseded session not yet taken. The platform calls
    /// this after each [`Connection::handle`](crate::Connection::handle)
    /// until it returns `None`; a full queue drops its oldest entry.
    pub fn take_superseded(&mut self) -> Option<SupersededSession> {
        let first = self.superseded[0].take();
        self.superseded.rotate_left(1);

        first
    }

    pub(crate) fn supersede(&mut self, session: SupersededSession) {
        if self.superseded[SUPERSEDED_QUEUE - 1].is_some() {
            self.superseded[0] = None;
            self.superseded.rotate_left(1);
        }

        let free = self
            .superseded
            .iter()
            .position(Option::is_none)
            .expect("a full queue dropped its oldest entry");
        self.superseded[free] = Some(session);
    }

    pub(crate) fn attach(&mut self) -> ConnectionId {
        let id = self.next_connection;
        self.next_connection = id.next();

        id
    }
}

/// A run of code units in an arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    start: u16,
    length: u16,
}

impl Span {
    const fn end(self) -> usize {
        self.start as usize + self.length as usize
    }
}

/// Record a change of the file in `slot` in the server's change log.
pub(super) fn record_change(
    server: &mut Server,
    slot: FileSlot,
    action: ChangeAction,
    filter: ChangeFilter,
) {
    let share = server.files.share(slot);
    let path = server.files.path(slot);
    let (parent, name) = split_parent(path);
    server.changes.record(share, parent, name, action, filter);
}

/// A path's parent and last component.
pub(super) fn split_parent(path: &[u16]) -> (&[u16], &[u16]) {
    match path.iter().rposition(|&unit| unit == u16::from(b'\\')) {
        Some(index) => (&path[..index], &path[index + 1..]),
        None => (&[], path),
    }
}
