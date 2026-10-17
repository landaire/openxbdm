//! Byte-range locks held across all connections.

use crate::server::error::LockRefusal;
use crate::server::shared::ConnectionId;
use crate::server::shared::FileSlot;
use crate::server::wire::FileId;

/// Byte-range locks held at once across all connections.
pub const MAX_LOCKS: usize = 64;

const _: () = assert!(MAX_LOCKS <= u8::MAX as usize + 1);

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

impl LockTable {
    pub(super) const fn new() -> Self {
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

/// Index of a lock table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LockSlot(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lock {
    file: FileSlot,
    owner: LockOwner,
    range: ByteRange,
    exclusive: bool,
}
