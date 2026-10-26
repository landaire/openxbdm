//! Share names, the object directories they serve, and object names of
//! share paths.

use openxbdm_core::status::KernelError;
use smb2_server::backend::SHARE_NAME_CAPACITY;
use smb2_server::backend::ShareId;
use smb2_server::fs::FsError;
use smb2_server::path::SharePath;
use smb2_server::server::MAX_TREES;

use crate::commands::filesystem;
use crate::commands::filesystem::DriveName;
use crate::commands::filesystem::DriveTable;
use crate::commands::filesystem::DriveTarget;
use crate::commands::filesystem::OBJECT_PATH_LIMIT;

/// Shares in use at once across the service's connections.
const SHARE_BINDINGS: usize = 2 * MAX_TREES;

/// A drive name offered as a share and the object directory it serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Candidate<'a> {
    pub name: &'a [u8],
    pub target: DriveTarget,
}

/// Presence of the candidates during one message, each tested once.
#[derive(Debug, Default)]
pub(crate) struct Presence {
    tested: u128,
    present: u128,
}

impl Presence {
    /// Whether the candidate at list `position` exists; `probe` tests it.
    fn test(
        &mut self,
        position: usize,
        target: DriveTarget,
        probe: &mut dyn FnMut(DriveTarget) -> bool,
    ) -> bool {
        let Some(bit) = u32::try_from(position)
            .ok()
            .and_then(|position| 1u128.checked_shl(position))
        else {
            return probe(target);
        };

        if self.tested & bit == 0 {
            self.tested |= bit;
            if probe(target) {
                self.present |= bit;
            }
        }

        self.present & bit != 0
    }

    /// The existing share at `index` of the share list.
    pub(crate) fn nth<'a>(
        &mut self,
        drives: &'a DriveTable,
        index: usize,
        probe: &mut dyn FnMut(DriveTarget) -> bool,
    ) -> Option<Candidate<'a>> {
        candidates(drives)
            .enumerate()
            .filter(|&(position, candidate)| self.test(position, candidate.target, probe))
            .map(|(_, candidate)| candidate)
            .nth(index)
    }
}

/// Share identifiers of the service: an identifier is a slot that binds a
/// name to the target it had at a tree connect. The engine keys files,
/// locks, and changes by identifier across connections, so every
/// connection gets the same identifier for a share. The slot stays while
/// a tree of any connection uses it; when the name's target changes, the
/// share is gone for those trees.
#[derive(Debug)]
pub(crate) struct ShareBindings {
    slots: [Option<Binding>; SHARE_BINDINGS],
}

impl ShareBindings {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [None; SHARE_BINDINGS],
        }
    }

    /// The identifier of `candidate`: the slot that binds its name to its
    /// target, or a free slot. `None` when every slot is bound otherwise.
    pub(crate) fn bind(&mut self, candidate: Candidate<'_>) -> Option<ShareId> {
        let binding = Binding {
            name: DriveName::new(candidate.name),
            target: candidate.target,
        };

        let slot = match self.slots.iter().position(|slot| *slot == Some(binding)) {
            Some(slot) => slot,
            None => {
                let slot = self.slots.iter().position(Option::is_none)?;
                self.slots[slot] = Some(binding);
                slot
            }
        };

        Some(ShareId(slot as u32))
    }

    /// Free the slots that no identifier in `used` names.
    pub(crate) fn retain(&mut self, used: impl Iterator<Item = ShareId>) {
        let mut kept = [false; SHARE_BINDINGS];
        for ShareId(id) in used {
            if let Some(keep) = kept.get_mut(id as usize) {
                *keep = true;
            }
        }

        for (slot, keep) in self.slots.iter_mut().zip(kept) {
            if !keep {
                *slot = None;
            }
        }
    }

    /// The current target of the share `id`; [`FsError::ShareRemoved`]
    /// when its name is gone or now names another target.
    pub(crate) fn resolve(&self, drives: &DriveTable, id: ShareId) -> Result<DriveTarget, FsError> {
        let binding = self
            .slots
            .get(id.0 as usize)
            .copied()
            .flatten()
            .ok_or(FsError::ShareRemoved)?;

        match find(drives, binding.name.as_bytes()) {
            Some(candidate) if candidate.target == binding.target => Ok(binding.target),
            _ => Err(FsError::ShareRemoved),
        }
    }
}

/// The kernel object name of a path on a share: the share's target, `\`,
/// and the path with each UTF-16 code unit as one byte.
#[derive(Clone)]
pub(crate) struct ObjectName {
    bytes: [u8; OBJECT_PATH_LIMIT],
    len: usize,
}

impl ObjectName {
    /// Code units above 0xff and names longer than [`OBJECT_PATH_LIMIT`]
    /// fail with [`FsError::NameInvalid`].
    pub(crate) fn new(target: &[u8], path: SharePath<'_>) -> Result<Self, FsError> {
        let mut name = Self {
            bytes: [0; OBJECT_PATH_LIMIT],
            len: 0,
        };

        name.push(target)?;
        if !target.ends_with(b"\\") {
            name.push(b"\\")?;
        }

        for unit in path.as_utf16().units() {
            let byte = u8::try_from(unit).map_err(|_| FsError::NameInvalid)?;
            name.push(&[byte])?;
        }

        Ok(name)
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        let end = self.len + bytes.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(FsError::NameInvalid)?
            .copy_from_slice(bytes);
        self.len = end;

        Ok(())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl core::fmt::Debug for ObjectName {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "\"{}\"", self.as_bytes().escape_ascii())
    }
}

/// A share name and the target it had when a tree connected to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Binding {
    name: DriveName,
    target: DriveTarget,
}

/// Rows of the drive table, then the rows of the internal mapping.
fn rows(drives: &DriveTable) -> impl Iterator<Item = Candidate<'_>> {
    let internal = filesystem::internal_drives().map(|(name, target)| Candidate {
        name,
        target: DriveTarget::Object(target),
    });

    drives
        .drives()
        .map(|drive| Candidate {
            name: drive.name.as_bytes(),
            target: drive.target,
        })
        .chain(internal)
}

/// Every name that can be a share, in list order: the drive table and the
/// internal mapping, whether or not `drivelist` shows the drive. Names
/// that are not share names are skipped; a name already seen, compared
/// without case, is skipped.
pub(crate) fn candidates(drives: &DriveTable) -> impl Iterator<Item = Candidate<'_>> {
    rows(drives)
        .enumerate()
        .filter(move |&(position, row)| {
            is_share_name(row.name)
                && !rows(drives)
                    .take(position)
                    .any(|earlier| earlier.name.eq_ignore_ascii_case(row.name))
        })
        .map(|(_, row)| Candidate {
            name: row.name,
            target: fallback(row),
        })
}

/// A drive pointing at `\Badpath` serves the internal mapping's target of
/// its name.
fn fallback(row: Candidate<'_>) -> DriveTarget {
    match row.target {
        DriveTarget::Object(target) if target == filesystem::BADPATH => {
            filesystem::internal_drives()
                .find(|(name, _)| name.eq_ignore_ascii_case(row.name))
                .map_or(row.target, |(_, internal)| DriveTarget::Object(internal))
        }
        target => target,
    }
}

pub(crate) fn is_share_name(name: &[u8]) -> bool {
    // Characters share names exclude (MS-SRVS 2.2.4.102, `shi502_netname`).
    const EXCLUDED: &[u8] = b"\"/\\[]:|<>+=;,*?";

    !name.is_empty()
        && name.len() <= SHARE_NAME_CAPACITY
        && name
            .iter()
            .all(|&byte| (0x20..0x7f).contains(&byte) && !EXCLUDED.contains(&byte))
}

/// Whether a share exists, from the open of its root directory: a device
/// without a medium exists.
pub(crate) fn exists(root: Result<(), KernelError>) -> bool {
    matches!(root, Ok(()) | Err(KernelError::NoMediaInDevice))
}

/// The candidate named `name`, compared without case.
pub(crate) fn find<'a>(drives: &'a DriveTable, name: &[u8]) -> Option<Candidate<'a>> {
    candidates(drives).find(|candidate| candidate.name.eq_ignore_ascii_case(name))
}

/// Whether `target` names an optical drive or a directory on one.
pub(crate) fn is_optical(target: &[u8]) -> bool {
    // Optical drive devices, whose media are read-only.
    const OPTICAL_DEVICES: &[&[u8]] = &[
        b"\\Device\\Cdrom",
        b"\\Device\\HdDvdRom",
        b"\\Device\\HdDvdPlayer",
    ];

    OPTICAL_DEVICES.iter().any(|device| {
        target.len() >= device.len() && target[..device.len()].eq_ignore_ascii_case(device)
    })
}

/// Whether a mapped target fits an object name. A title's string longer
/// than [`OBJECT_PATH_LIMIT`] would be cut, so its share is absent.
pub(crate) fn fits(target: DriveTarget) -> bool {
    match target {
        DriveTarget::Mapped { length, .. } => length as usize <= OBJECT_PATH_LIMIT,
        DriveTarget::Object(_) | DriveTarget::NetworkShare => true,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    use std::string::String;
    use std::vec::Vec;

    use smb2_server::utf16::Utf16Le;

    use super::*;

    const DEVKIT: &[u8] = b"\\Device\\Harddisk0\\Partition1\\DEVKIT";
    const PARTITION: &[u8] = b"\\Device\\Harddisk0\\Partition1";
    const CDROM: &[u8] = b"\\Device\\Cdrom0";
    const FLASH: &[u8] = b"\\Device\\Flash";
    const TITLE: &[u8] = b"\\Device\\Harddisk0\\Partition1\\DEVKIT\\title";

    /// Open of a share root on a console with the development partition,
    /// flash, and an empty optical drive.
    fn open_root(target: DriveTarget) -> Result<(), KernelError> {
        match target {
            DriveTarget::Object(DEVKIT | PARTITION | FLASH | TITLE) => Ok(()),
            DriveTarget::Object(CDROM) => Err(KernelError::NoMediaInDevice),
            _ => Err(KernelError::ObjectNameNotFound),
        }
    }

    fn probe(target: DriveTarget) -> bool {
        exists(open_root(target))
    }

    fn render(candidate: Candidate<'_>) -> String {
        let target = match candidate.target {
            DriveTarget::Object(bytes) => format!("{}", bytes.escape_ascii()),
            other => format!("{other:?}"),
        };
        format!("{} -> {target}", candidate.name.escape_ascii())
    }

    fn share_list(drives: &DriveTable) -> String {
        let mut presence = Presence::default();
        let mut lines = Vec::new();
        while let Some(candidate) = presence.nth(drives, lines.len(), &mut probe) {
            lines.push(render(candidate));
        }
        lines.join("\n")
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn share_path(bytes: &[u8]) -> SharePath<'_> {
        SharePath::parse(Utf16Le::new(bytes).unwrap()).unwrap()
    }

    #[test]
    fn candidates_join_the_drive_table_and_the_internal_mapping() {
        let mut drives = DriveTable::new();
        drives.map(
            DriveName::new(b"GAME"),
            Some(DriveTarget::Object(TITLE)),
            true,
        );
        drives.map(
            DriveName::new(b"devkit"),
            Some(DriveTarget::Object(CDROM)),
            true,
        );
        drives.map(
            DriveName::new(b"BAD:NAME"),
            Some(DriveTarget::Object(DEVKIT)),
            true,
        );
        let names: Vec<String> = candidates(&drives).map(render).collect();
        insta::assert_snapshot!(names.join("\n"));
    }

    #[test]
    fn share_list_holds_existing_devices() {
        let mut drives = DriveTable::new();
        drives.map(
            DriveName::new(b"GAME"),
            Some(DriveTarget::Object(TITLE)),
            true,
        );
        insta::assert_snapshot!(share_list(&drives));
    }

    #[test]
    fn find_compares_without_case() {
        let drives = DriveTable::new();
        assert_eq!(
            find(&drives, b"flash"),
            Some(Candidate {
                name: b"FLASH",
                target: DriveTarget::Object(FLASH),
            })
        );
        assert_eq!(find(&drives, b"NOSUCH"), None);
        assert_eq!(find(&drives, b"\x01"), None);
    }

    #[test]
    fn presence_is_tested_once_per_candidate() {
        let drives = DriveTable::new();
        let mut presence = Presence::default();
        let opens = core::cell::Cell::new(0);
        let mut counting = |target| {
            opens.set(opens.get() + 1);
            probe(target)
        };
        presence.nth(&drives, 0, &mut counting);
        let first = opens.get();
        presence.nth(&drives, 0, &mut counting);
        assert_eq!(opens.get(), first);
        // `A` is the first candidate and exists without a medium.
        assert_eq!(first, 1);
    }

    #[test]
    fn optical_targets_are_read_only_devices() {
        let drives = DriveTable::new();
        let optical: Vec<&[u8]> = candidates(&drives)
            .filter_map(|candidate| match candidate.target {
                DriveTarget::Object(target) if is_optical(target) => Some(candidate.name),
                _ => None,
            })
            .collect();
        assert_eq!(optical, [&b"A"[..], b"DVD", b"HDDVD", b"HDDVDSYS"]);
        assert!(is_optical(b"\\device\\cdrom0\\video"));
        assert!(!is_optical(DEVKIT));
    }

    #[test]
    fn mapped_targets_longer_than_an_object_name_do_not_fit() {
        let mapped = |length| DriveTarget::Mapped {
            address: 0x8000_0000,
            length,
        };
        assert!(fits(mapped(OBJECT_PATH_LIMIT as u32)));
        assert!(!fits(mapped(OBJECT_PATH_LIMIT as u32 + 1)));
        assert!(fits(DriveTarget::Object(DEVKIT)));
    }

    #[test]
    fn bindings_last_while_a_tree_uses_them() {
        let mut drives = DriveTable::new();
        let mut bindings = ShareBindings::new();
        let devkit = bindings.bind(find(&drives, b"devkit").unwrap()).unwrap();
        assert_eq!(
            bindings.bind(find(&drives, b"DEVKIT").unwrap()),
            Some(devkit)
        );
        assert_eq!(
            bindings.resolve(&drives, devkit),
            Ok(DriveTarget::Object(DEVKIT))
        );
        let game = |address| DriveTarget::Mapped { address, length: 4 };
        drives.map(DriveName::new(b"GAME"), Some(game(0x1000)), true);
        let first = bindings.bind(find(&drives, b"GAME").unwrap()).unwrap();
        drives.map(DriveName::new(b"GAME"), Some(game(0x2000)), true);
        assert_eq!(bindings.resolve(&drives, first), Err(FsError::ShareRemoved));
        let second = bindings.bind(find(&drives, b"GAME").unwrap()).unwrap();
        assert_ne!(second, first);
        assert_eq!(bindings.resolve(&drives, second), Ok(game(0x2000)));
        drives.map(DriveName::new(b"GAME"), None, true);
        assert_eq!(
            bindings.resolve(&drives, second),
            Err(FsError::ShareRemoved)
        );
        bindings.retain([devkit].into_iter());
        assert_eq!(bindings.resolve(&drives, first), Err(FsError::ShareRemoved));
        assert_eq!(
            bindings.resolve(&drives, devkit),
            Ok(DriveTarget::Object(DEVKIT))
        );
        // Every other slot takes a target of GAME; a further target finds
        // no slot.
        for address in 1..SHARE_BINDINGS as u32 {
            drives.map(DriveName::new(b"GAME"), Some(game(address)), true);
            assert!(bindings.bind(find(&drives, b"GAME").unwrap()).is_some());
        }
        drives.map(DriveName::new(b"GAME"), Some(game(0)), true);
        assert_eq!(bindings.bind(find(&drives, b"GAME").unwrap()), None);
    }

    #[test]
    fn object_names_join_target_and_path() {
        let nested = utf16("dir\\caf\u{e9}.txt");
        let longest = "a".repeat(OBJECT_PATH_LIMIT - DEVKIT.len() - 1);
        let results = [
            ObjectName::new(DEVKIT, SharePath::ROOT),
            ObjectName::new(b"\\Device\\Cdrom0\\", SharePath::ROOT),
            ObjectName::new(DEVKIT, share_path(&nested)),
            ObjectName::new(DEVKIT, share_path(&utf16("\u{3042}"))),
            ObjectName::new(DEVKIT, share_path(&utf16(&format!("{longest}a")))),
        ];
        insta::assert_debug_snapshot!(results);
        let name = ObjectName::new(DEVKIT, share_path(&utf16(&longest))).unwrap();
        assert_eq!(name.as_bytes().len(), OBJECT_PATH_LIMIT);
    }
}
