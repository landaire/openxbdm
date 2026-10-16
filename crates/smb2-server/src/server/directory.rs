//! QUERY_DIRECTORY (MS-SMB2 3.3.5.18) and the directory information
//! classes (MS-FSCC 2.4).

use crate::backend::Backend;
use crate::fs::AccessMask;
use crate::fs::DirectoryEntry;
use crate::fs::NAME_CAPACITY;
use crate::pattern;
use crate::server::Body;
use crate::server::Connection;
use crate::server::Exchange;
use crate::server::Failure;
use crate::server::Handled;
use crate::server::RequestError;
use crate::server::tables::OpenKind;
use crate::server::tables::OpenSlot;
use crate::server::tables::Pattern;
use crate::server::tables::PatternIndex;
use crate::server::tables::Search;
use crate::server::wire;
use crate::server::wire::FileId;
use crate::server::wire::HEADER_SIZE;
use crate::utf16::Utf16Le;

const REQUEST_FIXED: usize = 32;
const REPLY_FIXED: usize = 8;

/// Flags of a QUERY_DIRECTORY request (MS-SMB2 2.2.33).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueryFlags(u8);

impl QueryFlags {
    const RESTART_SCANS: Self = Self(0x01);
    const RETURN_SINGLE_ENTRY: Self = Self(0x02);
    const REOPEN: Self = Self(0x10);

    const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// A directory information class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Directory,
    FullDirectory,
    BothDirectory,
    Names,
    IdBothDirectory,
    IdFullDirectory,
}

impl Class {
    fn from_wire(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Directory,
            2 => Self::FullDirectory,
            3 => Self::BothDirectory,
            12 => Self::Names,
            37 => Self::IdBothDirectory,
            38 => Self::IdFullDirectory,
            _ => return None,
        })
    }

    /// Bytes before the name.
    const fn fixed(self) -> usize {
        match self {
            Self::Directory => 64,
            Self::FullDirectory => 68,
            Self::BothDirectory => 94,
            Self::Names => 12,
            Self::IdBothDirectory => 104,
            Self::IdFullDirectory => 80,
        }
    }
}

/// Bytes the largest entry of any class takes, alignment included.
const LARGEST_ENTRY: usize = wire::align8(104 + NAME_CAPACITY * 2);

impl Connection {
    pub(super) fn query_directory(
        &mut self,
        exchange: &Exchange<'_>,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        let body = exchange.fixed_body(33, REQUEST_FIXED)?;
        let class =
            Class::from_wire(wire::u8_at(body, 2)).ok_or(RequestError::UnknownInformationClass)?;
        let flags = QueryFlags(wire::u8_at(body, 3));
        let slot = self.find_open(exchange, FileId::read(body, 8))?;
        let expression = wire::buffer(
            exchange.message,
            REQUEST_FIXED,
            usize::from(wire::u16_at(body, 24)),
            usize::from(wire::u16_at(body, 26)),
        )
        .and_then(Utf16Le::new)
        .ok_or(RequestError::InvalidRequest)?;
        let open = *self.open(slot);
        let OpenKind::File(file) = open.kind else {
            return Err(Failure::Error(RequestError::InvalidRequest));
        };
        if !file.directory {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }
        if !open.access.contains(AccessMask::READ_DATA) {
            return Err(Failure::Error(RequestError::AccessDenied));
        }
        let limit = (wire::u32_at(body, 28) as usize)
            .min(exchange.config.max_io())
            .min(output.len().saturating_sub(REPLY_FIXED));
        let restart = flags.intersects(QueryFlags::RESTART_SCANS.union(QueryFlags::REOPEN))
            || file.search.is_none();
        let mut search = match file.search {
            Some(search) if !restart => search,
            _ => {
                // start_search frees the pattern of the old search before
                // it can fail; the open must not keep naming it.
                if let OpenKind::File(file) = &mut self.open_mut(slot).kind {
                    file.search = None;
                }
                self.start_search(slot, expression)?
            }
        };

        let entries = &mut output[REPLY_FIXED..REPLY_FIXED + limit];
        let mut written = 0;
        let mut previous: Option<usize> = None;
        let mut name = [0u16; NAME_CAPACITY];
        let mut failure: Option<RequestError> = None;
        loop {
            let entry = if self.held.owner == Some(slot) {
                self.held.owner = None;
                name = self.held.name;
                self.held.entry
            } else {
                if search.exhausted {
                    break;
                }
                let start = wire::align8(written);
                if previous.is_some() && start + LARGEST_ENTRY > limit {
                    break;
                }
                if previous.is_none() && start + LARGEST_ENTRY > limit && self.held.owner.is_some()
                {
                    failure = Some(RequestError::TableFull);
                    break;
                }
                if search.dots_listed < 2 {
                    // `.` and `..` lead every listing, with the directory's
                    // own information.
                    let information = match backend.information(file.handle) {
                        Ok(information) => information,
                        Err(error) => {
                            failure = Some(error.into());
                            break;
                        }
                    };
                    search.dots_listed += 1;
                    let length = usize::from(search.dots_listed);
                    name[..length].fill(u16::from(b'.'));
                    DirectoryEntry {
                        information,
                        name_length: length,
                    }
                } else {
                    match backend.read_directory(file.handle, search.restart_backend, &mut name) {
                        Ok(Some(entry)) => {
                            search.restart_backend = false;
                            entry
                        }
                        Ok(None) => {
                            search.restart_backend = false;
                            search.exhausted = true;
                            break;
                        }
                        Err(error) => {
                            failure = Some(error.into());
                            break;
                        }
                    }
                }
            };
            let name = &name[..entry.name_length.min(NAME_CAPACITY)];
            if !self.pattern_matches(search.pattern, name) {
                continue;
            }
            let start = wire::align8(written);
            let length = class.fixed() + name.len() * 2;
            if start + length > entries.len() {
                self.hold(slot, entry, name);
                if previous.is_none() {
                    failure = Some(RequestError::InformationLengthMismatch);
                }
                break;
            }
            entries[written..start].fill(0);
            encode_entry(class, &entry, name, &mut entries[start..start + length]);
            if let Some(previous) = previous {
                wire::put_u32(entries, previous, (start - previous) as u32);
            }
            previous = Some(start);
            written = start + length;
            if flags.intersects(QueryFlags::RETURN_SINGLE_ENTRY) {
                break;
            }
        }
        let first_query = !search.queried;
        search.queried = true;
        if let OpenKind::File(file) = &mut self.open_mut(slot).kind {
            file.search = Some(search);
        }
        // Entries already taken from the backend are returned; a failure
        // after them repeats on the next query.
        if let Some(error) = failure
            && previous.is_none()
        {
            return Err(Failure::Error(error));
        }
        if previous.is_none() {
            // The first query of a scan that finds nothing reports that no
            // file matches; later ones report the end of the scan.
            let error = if first_query {
                RequestError::NoMatchingFile
            } else {
                RequestError::NoMoreFiles
            };
            return Err(Failure::Error(error));
        }
        output[..REPLY_FIXED].fill(0);
        wire::put_u16(output, 0, 9);
        wire::put_u16(output, 2, (HEADER_SIZE + REPLY_FIXED) as u16);
        wire::put_u32(output, 4, written as u32);
        Ok(Body::success(REPLY_FIXED + written))
    }

    /// Begin a scan of the open in `slot` for `expression`.
    fn start_search(&mut self, slot: OpenSlot, expression: Utf16Le<'_>) -> Result<Search, Failure> {
        for stored in &mut self.patterns {
            if stored.owner == Some(slot) {
                stored.owner = None;
            }
        }
        if self.held.owner == Some(slot) {
            self.held.owner = None;
        }
        let pattern = if expression.is_empty() || expression.eq_ignore_ascii_case(b"*") {
            Pattern::All
        } else {
            if expression.len() > pattern::EXPRESSION_CAPACITY {
                return Err(Failure::Error(RequestError::NameInvalid));
            }
            let index = self
                .patterns
                .iter()
                .position(|stored| stored.owner.is_none())
                .ok_or(RequestError::TableFull)?;
            let stored = &mut self.patterns[index];
            stored.owner = Some(slot);
            for (unit, value) in stored.units.iter_mut().zip(expression.units()) {
                *unit = value;
            }
            stored.length = expression.len() as u16;
            Pattern::Stored(PatternIndex(index as u8))
        };
        Ok(Search {
            pattern,
            queried: false,
            exhausted: false,
            dots_listed: 0,
            restart_backend: true,
        })
    }

    fn pattern_matches(&self, pattern: Pattern, name: &[u16]) -> bool {
        match pattern {
            Pattern::All => true,
            Pattern::Stored(index) => {
                pattern::is_name_in_expression(self.patterns[usize::from(index.0)].units(), name)
            }
        }
    }

    /// Keep an entry that did not fit for the next query of the open.
    fn hold(&mut self, slot: OpenSlot, entry: DirectoryEntry, name: &[u16]) {
        self.held.owner = Some(slot);
        self.held.entry = entry;
        self.held.name[..name.len()].copy_from_slice(name);
    }
}

/// Write one entry of `class`; `output` is exactly the entry's length.
fn encode_entry(class: Class, entry: &DirectoryEntry, name: &[u16], output: &mut [u8]) {
    output.fill(0);
    let fixed = class.fixed();
    for (index, unit) in name.iter().enumerate() {
        wire::put_u16(output, fixed + index * 2, *unit);
    }
    let name_length = (name.len() * 2) as u32;
    if class == Class::Names {
        wire::put_u32(output, 8, name_length);
        return;
    }
    let information = &entry.information;
    wire::put_u64(output, 8, information.creation_time.0);
    wire::put_u64(output, 16, information.last_access_time.0);
    wire::put_u64(output, 24, information.last_write_time.0);
    wire::put_u64(output, 32, information.change_time.0);
    wire::put_u64(output, 40, information.end_of_file);
    wire::put_u64(output, 48, information.allocation_size);
    wire::put_u32(output, 56, information.attributes.0);
    wire::put_u32(output, 60, name_length);
    let file_id = information.index.map_or(0, |index| index.0);
    match class {
        Class::IdBothDirectory => wire::put_u64(output, 96, file_id),
        Class::IdFullDirectory => wire::put_u64(output, 72, file_id),
        _ => {}
    }
}
