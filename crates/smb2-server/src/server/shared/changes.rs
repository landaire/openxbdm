//! The log of changes that change notifications report.

use crate::backend::ShareId;
use crate::server::shared::Span;

/// Change records the change log keeps.
pub const CHANGE_RECORDS: usize = 32;
/// Code units of path text the change log keeps.
pub const CHANGE_TEXT: usize = 2048;

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
    pub(super) const fn new() -> Self {
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
        const SEPARATOR: u16 = b'\\' as u16;

        let separator = usize::from(!parent.is_empty() && !name.is_empty());
        let length = parent.len() + separator + name.len();

        // Too long to keep: the record is dropped, which connections see as
        // a gap and report as an overflow.
        if length > CHANGE_TEXT {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChangeRecord {
    sequence: ChangeSequence,
    share: ShareId,
    path: Span,
    action: ChangeAction,
    filter: ChangeFilter,
}
