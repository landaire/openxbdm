//! The files that are open across all connections, with their paths.

use crate::backend::ShareId;
use crate::path::SharePath;
use crate::pattern::fold;
use crate::server::error::FileTableError;
use crate::server::shared::Span;
use crate::utf16::Utf16Le;

/// Files open at once across all connections.
pub const MAX_FILES: usize = 64;
/// Code units of path text the file table holds.
pub const PATH_ARENA: usize = 4096;

/// Index of a file table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FileSlot(pub u8);

/// The files that are open, each with its path on its share. Opens of the
/// same path share an entry, which identifies the file for byte-range
/// locks and change notification.
#[derive(Debug)]
pub(crate) struct FileTable {
    entries: [Option<FileEntry>; MAX_FILES],
    arena: [u16; PATH_ARENA],
}

impl FileTable {
    pub(super) const fn new() -> Self {
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
                            .all(|(&stored, unit)| fold(stored) == fold(unit))
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

        // An empty path occupies nothing, so compaction never has to move
        // it.
        if length == 0 {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileEntry {
    share: ShareId,
    path: Span,
    /// Opens of this file across all connections.
    opens: u16,
    /// An open set the delete disposition or opened with delete on close.
    delete_pending: bool,
}
