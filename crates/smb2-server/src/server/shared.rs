//! State shared by every connection of a server: the files that are open
//! with their paths, byte-range locks, and the log of changes that change
//! notifications report.

use crate::backend::ShareId;
use crate::backend::UserKind;
use crate::path::SharePath;
use crate::pattern::fold;
use crate::server::ServerConfig;
use crate::server::tables::SessionId;
use crate::server::wire::FileId;
use crate::status::NtStatus;
use crate::utf16::Utf16Le;

/// Files open at once across all connections.
pub const MAX_FILES: usize = 64;
/// Code units of path text the file table holds.
pub const PATH_ARENA: usize = 4096;
/// Byte-range locks held at once across all connections.
pub const MAX_LOCKS: usize = 64;
/// Change records the change log keeps.
pub const CHANGE_RECORDS: usize = 32;
/// Code units of path text the change log keeps.
pub const CHANGE_TEXT: usize = 2048;

const SEPARATOR: u16 = b'\\' as u16;

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

/// Index of a file table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FileSlot(pub u8);

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

/// Why the file table cannot take a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTableError {
    /// Every entry is in use.
    Full,
    /// The path is longer than the whole path arena.
    PathTooLong { length: usize },
    /// The paths of open files fill the arena.
    OutOfPathSpace,
}

impl From<FileTableError> for NtStatus {
    fn from(error: FileTableError) -> Self {
        match error {
            FileTableError::Full | FileTableError::OutOfPathSpace => {
                NtStatus::InsufficientResources
            }
            FileTableError::PathTooLong { .. } => NtStatus::ObjectNameInvalid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileEntry {
    share: ShareId,
    path: Span,
    /// Opens of this file across all connections.
    opens: u16,
    /// An open set the delete disposition or opened with delete on close.
    delete_pending: bool,
}

/// The files that are open, each with its path on its share. Opens of the
/// same path share an entry, which identifies the file for byte-range
/// locks and change notification.
#[derive(Debug)]
pub(crate) struct FileTable {
    entries: [Option<FileEntry>; MAX_FILES],
    arena: [u16; PATH_ARENA],
}

impl FileTable {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_FILES],
            arena: [0; PATH_ARENA],
        }
    }

    /// The entry of `path` on `share`, created when no open has it.
    pub(crate) fn acquire(
        &mut self,
        share: ShareId,
        path: SharePath<'_>,
    ) -> Result<FileSlot, FileTableError> {
        let units = path.as_utf16();
        if let Some(slot) = self.find(share, units) {
            let entry = self.entries[usize::from(slot.0)]
                .as_mut()
                .expect("found entry is occupied");
            entry.opens += 1;
            return Ok(slot);
        }
        let index = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(FileTableError::Full)?;
        let path = self.store(units)?;
        self.entries[index] = Some(FileEntry {
            share,
            path,
            opens: 1,
            delete_pending: false,
        });
        Ok(FileSlot(index as u8))
    }

    /// Drop one open of `slot`, removing the entry after the last.
    pub(crate) fn release(&mut self, slot: FileSlot) {
        let Some(entry) = self.entries[usize::from(slot.0)].as_mut() else {
            return;
        };
        entry.opens -= 1;
        if entry.opens == 0 {
            self.entries[usize::from(slot.0)] = None;
        }
    }

    /// Opens of the file across all connections.
    pub(crate) fn opens(&self, slot: FileSlot) -> u16 {
        self.entry(slot).opens
    }

    pub(crate) fn share(&self, slot: FileSlot) -> ShareId {
        self.entry(slot).share
    }

    pub(crate) fn path(&self, slot: FileSlot) -> &[u16] {
        let path = self.entry(slot).path;
        &self.arena[usize::from(path.start)..path.end()]
    }

    pub(crate) fn set_delete_pending(&mut self, slot: FileSlot, delete: bool) {
        if let Some(entry) = self.entries[usize::from(slot.0)].as_mut() {
            entry.delete_pending = delete;
        }
    }

    pub(crate) fn delete_pending(&self, slot: FileSlot) -> bool {
        self.entry(slot).delete_pending
    }

    /// Whether [`FileTable::rename`] of `slot` to `path` has room: the
    /// old path stays stored until the new one is.
    pub(crate) fn check_rename(&self, path: SharePath<'_>) -> Result<(), FileTableError> {
        let length = path.as_utf16().len();
        if length > PATH_ARENA {
            return Err(FileTableError::PathTooLong { length });
        }
        let used: usize = self
            .entries
            .iter()
            .flatten()
            .map(|entry| usize::from(entry.path.length))
            .sum();
        if used + length > PATH_ARENA {
            return Err(FileTableError::OutOfPathSpace);
        }
        Ok(())
    }

    /// Give the file of `slot` its path after a rename that
    /// [`FileTable::check_rename`] accepted.
    pub(crate) fn rename(&mut self, slot: FileSlot, path: SharePath<'_>) {
        let span = self
            .store(path.as_utf16())
            .expect("check_rename found room for the path");
        self.entries[usize::from(slot.0)]
            .as_mut()
            .expect("renamed entry is occupied")
            .path = span;
    }

    fn entry(&self, slot: FileSlot) -> &FileEntry {
        self.entries[usize::from(slot.0)]
            .as_ref()
            .expect("file slot of an open is occupied")
    }

    fn find(&self, share: ShareId, path: Utf16Le<'_>) -> Option<FileSlot> {
        self.entries
            .iter()
            .position(|entry| {
                entry.is_some_and(|entry| {
                    entry.share == share
                        && usize::from(entry.path.length) == path.len()
                        && self.arena[usize::from(entry.path.start)..entry.path.end()]
                            .iter()
                            .zip(path.units())
                            .all(|(&a, b)| fold(a) == fold(b))
                })
            })
            .map(|index| FileSlot(index as u8))
    }

    /// Copy `path` into the arena, compacting it when the free space at
    /// its end is too short.
    fn store(&mut self, path: Utf16Le<'_>) -> Result<Span, FileTableError> {
        let length = path.len();
        if length > PATH_ARENA {
            return Err(FileTableError::PathTooLong { length });
        }
        if length == 0 {
            // An empty path occupies nothing, so compaction never has to
            // move it.
            return Ok(Span {
                start: 0,
                length: 0,
            });
        }
        let mut end = self.used_end();
        if end + length > PATH_ARENA {
            self.compact();
            end = self.used_end();
            if end + length > PATH_ARENA {
                return Err(FileTableError::OutOfPathSpace);
            }
        }
        for (slot, unit) in self.arena[end..end + length].iter_mut().zip(path.units()) {
            *slot = unit;
        }
        Ok(Span {
            start: end as u16,
            length: length as u16,
        })
    }

    fn used_end(&self) -> usize {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| entry.path.length > 0)
            .map(|entry| entry.path.end())
            .max()
            .unwrap_or(0)
    }

    /// Move every path to the front of the arena, in arena order.
    fn compact(&mut self) {
        let mut next = 0usize;
        loop {
            // The entry with the lowest start at or after `next` that has
            // not been moved yet.
            let candidate = self
                .entries
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| entry.map(|entry| (index, entry.path)))
                .filter(|(_, path)| path.length > 0 && usize::from(path.start) >= next)
                .min_by_key(|(_, path)| path.start);
            let Some((index, path)) = candidate else {
                return;
            };
            let start = usize::from(path.start);
            self.arena.copy_within(start..path.end(), next);
            let entry = self.entries[index].as_mut().expect("candidate is occupied");
            entry.path.start = next as u16;
            next += usize::from(path.length);
        }
    }
}

/// The open that holds a byte-range lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LockOwner {
    pub connection: ConnectionId,
    pub open: FileId,
}

/// A byte range of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

impl ByteRange {
    /// Ranges overlap when they share a byte; empty ranges share none.
    fn overlaps(self, other: Self) -> bool {
        self.length != 0
            && other.length != 0
            && self.offset <= other.offset.saturating_add(other.length - 1)
            && other.offset <= self.offset.saturating_add(self.length - 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lock {
    file: FileSlot,
    owner: LockOwner,
    range: ByteRange,
    exclusive: bool,
}

/// Generation of the lock table: counts releases, so waiting lock requests
/// know when to retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LockEpoch(u32);

impl LockEpoch {
    fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

/// Byte-range locks (MS-FSA 2.1.5.7). Locks bind SMB opens only; the
/// backend's own file access does not see them.
#[derive(Debug)]
pub(crate) struct LockTable {
    locks: [Option<Lock>; MAX_LOCKS],
    epoch: LockEpoch,
}

/// Index of a lock table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LockSlot(u8);

const _: () = assert!(MAX_LOCKS <= u8::MAX as usize + 1);

/// Why a lock or an access is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockRefusal {
    /// Another lock covers part of the range.
    Conflict,
    /// The lock table is full.
    Exhausted,
}

impl LockTable {
    const fn new() -> Self {
        Self {
            locks: [None; MAX_LOCKS],
            epoch: LockEpoch(0),
        }
    }

    pub(crate) fn epoch(&self) -> LockEpoch {
        self.epoch
    }

    pub(crate) fn lock(
        &mut self,
        file: FileSlot,
        owner: LockOwner,
        range: ByteRange,
        exclusive: bool,
    ) -> Result<LockSlot, LockRefusal> {
        let conflict = self.locks.iter().flatten().any(|lock| {
            lock.file == file
                && lock.range.overlaps(range)
                // A shared lock may overlap an exclusive lock of the same
                // open; an exclusive lock overlaps nothing.
                && (exclusive || (lock.exclusive && lock.owner != owner))
        });
        if conflict {
            return Err(LockRefusal::Conflict);
        }
        let index = self
            .locks
            .iter()
            .position(Option::is_none)
            .ok_or(LockRefusal::Exhausted)?;
        self.locks[index] = Some(Lock {
            file,
            owner,
            range,
            exclusive,
        });
        Ok(LockSlot(index as u8))
    }

    /// Remove the lock in `slot`, which [`LockTable::lock`] returned.
    pub(crate) fn release(&mut self, slot: LockSlot) {
        if self.locks[usize::from(slot.0)].take().is_some() {
            self.epoch = self.epoch.next();
        }
    }

    /// Remove the lock of `owner` with exactly `range`; `false` when there
    /// is none.
    pub(crate) fn unlock(&mut self, file: FileSlot, owner: LockOwner, range: ByteRange) -> bool {
        let Some(slot) = self.locks.iter_mut().find(|lock| {
            lock.is_some_and(|lock| lock.file == file && lock.owner == owner && lock.range == range)
        }) else {
            return false;
        };
        *slot = None;
        self.epoch = self.epoch.next();
        true
    }

    /// Remove every lock of `owner`.
    pub(crate) fn release_owner(&mut self, owner: LockOwner) {
        let mut released = false;
        for slot in &mut self.locks {
            if slot.is_some_and(|lock| lock.owner == owner) {
                *slot = None;
                released = true;
            }
        }
        if released {
            self.epoch = self.epoch.next();
        }
    }

    /// Whether `owner` may read (`write` false) or write the range: reads
    /// conflict with exclusive locks of other opens, writes with any lock
    /// except an exclusive lock of the same open.
    pub(crate) fn check_access(
        &self,
        file: FileSlot,
        owner: LockOwner,
        range: ByteRange,
        write: bool,
    ) -> Result<(), LockRefusal> {
        let conflict = self.locks.iter().flatten().any(|lock| {
            lock.file == file
                && lock.range.overlaps(range)
                && if write {
                    !(lock.exclusive && lock.owner == owner)
                } else {
                    lock.exclusive && lock.owner != owner
                }
        });
        if conflict {
            Err(LockRefusal::Conflict)
        } else {
            Ok(())
        }
    }
}

/// Action of a change record (MS-FSCC 2.4.42 FILE_NOTIFY_INFORMATION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChangeAction {
    Added = 1,
    Removed = 2,
    Modified = 3,
    RenamedOldName = 4,
    RenamedNewName = 5,
}

/// Completion filter bits (MS-SMB2 2.2.35) a change matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChangeFilter(pub u32);

impl ChangeFilter {
    pub const FILE_NAME: Self = Self(0x001);
    pub const DIR_NAME: Self = Self(0x002);
    pub const ATTRIBUTES: Self = Self(0x004);
    pub const SIZE: Self = Self(0x008);
    pub const LAST_WRITE: Self = Self(0x010);
    pub const LAST_ACCESS: Self = Self(0x020);
    pub const CREATION: Self = Self(0x040);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn name(directory: bool) -> Self {
        if directory {
            Self::DIR_NAME
        } else {
            Self::FILE_NAME
        }
    }
}

/// Sequence number of a change record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ChangeSequence(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChangeRecord {
    sequence: ChangeSequence,
    share: ShareId,
    path: Span,
    action: ChangeAction,
    filter: ChangeFilter,
}

/// A change record as connections read it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Change<'a> {
    pub share: ShareId,
    /// Path of the changed file from the share root.
    pub path: &'a [u16],
    pub action: ChangeAction,
    pub filter: ChangeFilter,
}

/// The most recent changes made through the server, oldest dropped first.
#[derive(Debug)]
pub(crate) struct ChangeLog {
    records: [Option<ChangeRecord>; CHANGE_RECORDS],
    text: [u16; CHANGE_TEXT],
    /// Where the next record's text goes.
    cursor: u16,
    next: ChangeSequence,
}

impl ChangeLog {
    const fn new() -> Self {
        Self {
            records: [None; CHANGE_RECORDS],
            text: [0; CHANGE_TEXT],
            cursor: 0,
            next: ChangeSequence(1),
        }
    }

    /// The sequence number the next record gets.
    pub(crate) fn next(&self) -> ChangeSequence {
        self.next
    }

    /// Record a change of `path`, whose text is `parent` and, when not
    /// empty, a separator and `name`.
    pub(crate) fn record(
        &mut self,
        share: ShareId,
        parent: &[u16],
        name: &[u16],
        action: ChangeAction,
        filter: ChangeFilter,
    ) {
        let separator = usize::from(!parent.is_empty() && !name.is_empty());
        let length = parent.len() + separator + name.len();
        if length > CHANGE_TEXT {
            // Too long to keep: the record is dropped, which connections
            // see as a gap and report as an overflow.
            self.drop_oldest_through(self.next);
            self.next = ChangeSequence(self.next.0.wrapping_add(1));
            return;
        }
        let mut start = usize::from(self.cursor);
        if start + length > CHANGE_TEXT {
            start = 0;
        }
        let span = Span {
            start: start as u16,
            length: length as u16,
        };
        // Drop records whose text the new one overwrites; they are the
        // oldest because text is written in order.
        while let Some(index) = self.records.iter().position(|record| {
            record.is_some_and(|record| {
                record.path.length > 0
                    && usize::from(record.path.start) < span.end()
                    && usize::from(span.start) < record.path.end()
            })
        }) {
            let oldest = self.records[index].expect("matched record").sequence;
            self.drop_oldest_through(oldest);
        }
        let slot = match self.records.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => {
                let oldest = self
                    .records
                    .iter()
                    .flatten()
                    .map(|record| record.sequence)
                    .min()
                    .expect("a full log has records");
                self.drop_oldest_through(oldest);
                self.records
                    .iter()
                    .position(Option::is_none)
                    .expect("dropping frees a slot")
            }
        };
        let text = &mut self.text[start..start + length];
        text[..parent.len()].copy_from_slice(parent);
        if separator == 1 {
            text[parent.len()] = SEPARATOR;
        }
        text[parent.len() + separator..].copy_from_slice(name);
        self.records[slot] = Some(ChangeRecord {
            sequence: self.next,
            share,
            path: span,
            action,
            filter,
        });
        self.cursor = (start + length) as u16;
        self.next = ChangeSequence(self.next.0.wrapping_add(1));
    }

    /// Drop every record up to and including `sequence`.
    fn drop_oldest_through(&mut self, sequence: ChangeSequence) {
        for record in &mut self.records {
            if record.is_some_and(|record| record.sequence <= sequence) {
                *record = None;
            }
        }
    }

    /// The oldest sequence number still kept, or the next one when the log
    /// is empty.
    pub(crate) fn oldest(&self) -> ChangeSequence {
        self.records
            .iter()
            .flatten()
            .map(|record| record.sequence)
            .min()
            .unwrap_or(self.next)
    }

    /// The record with `sequence`, if kept.
    pub(crate) fn get(&self, sequence: ChangeSequence) -> Option<Change<'_>> {
        let record = self
            .records
            .iter()
            .flatten()
            .find(|record| record.sequence == sequence)?;
        Some(Change {
            share: record.share,
            path: &self.text[usize::from(record.path.start)..record.path.end()],
            action: record.action,
            filter: record.filter,
        })
    }
}

/// Superseded sessions [`Server`] keeps until the platform takes them.
pub const SUPERSEDED_QUEUE: usize = 4;

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
