//! The drive table and drive path translation.

use openxbdm_core::status::KernelError;

use super::CreateRequest;
use super::FileHandle;
use crate::commands::console;
use crate::commands::console::TraceMask;
use crate::commands::memory::PAGE_SIZE;
use crate::state::ServerState;

/// Translated object names are limited to this many bytes.
pub const OBJECT_PATH_LIMIT: usize = 0x141;

/// Rows of the drive table (0x91f96bf8..0x91f9735c, 0x2c-byte rows); the
/// last row stays the terminator.
const DRIVE_TABLE_CAPACITY: usize = 43;

/// Bytes of the name field of a drive table row, terminator included.
const DRIVE_NAME_SIZE: usize = 0x20;

pub(crate) const BADPATH: &[u8] = b"\\Badpath";

/// `\Network\Smb\` plus at most 0x3d server characters.
const NETWORK_SHARE_CAPACITY: usize = 0x50;

/// The drive table of the image, followed by the hidden `\x01` entry that
/// initialization maps to `\SystemRoot`.
const DEFAULT_DRIVES: [Option<Drive>; DRIVE_TABLE_CAPACITY] = [
    drive(b"A", b"\\Device\\Cdrom0", false),
    drive(b"DVD", b"\\Device\\Cdrom0", true),
    drive(b"E", b"\\Device\\Harddisk0\\Partition1\\DEVKIT", true),
    drive(b"DEVKIT", b"\\Device\\Harddisk0\\Partition1\\DEVKIT", true),
    drive(b"U", b"\\Network", false),
    drive(b"NET", b"\\Network", false),
    drive(b"MU0", b"\\Device\\Mu0", true),
    drive(b"MU1", b"\\Device\\Mu1", true),
    drive(b"HDD", b"\\Device\\Harddisk0\\Partition1", true),
    drive(b"MUINT", b"\\Device\\BuiltInMuSfc", true),
    drive(b"INTUSB", b"\\Device\\BuiltInMuUsb\\Storage", true),
    drive(
        b"USBMASS0MU",
        b"\\Device\\Mass0PartitionFile\\Storage",
        true,
    ),
    drive(
        b"USBMASS1MU",
        b"\\Device\\Mass1PartitionFile\\Storage",
        true,
    ),
    drive(b"F", BADPATH, false),
    drive(b"SMB", BADPATH, false),
    drive(b"Y", BADPATH, false),
    drive(b"Z", BADPATH, false),
    drive(b"FLASH", BADPATH, false),
    drive(b"MU0SYS", BADPATH, false),
    drive(b"MU1SYS", BADPATH, false),
    drive(b"USBMASS0", BADPATH, false),
    drive(b"USBMASS1", BADPATH, false),
    drive(b"USBMASS2", BADPATH, false),
    drive(b"MEDIA", BADPATH, false),
    drive(b"MUINTSYS", BADPATH, false),
    drive(b"HDDSYSEXT", BADPATH, false),
    drive(b"HDDSYSAUX", BADPATH, false),
    drive(b"INTUSBSYS", BADPATH, false),
    drive(b"INTUSBSYSEXT", BADPATH, false),
    drive(b"INTUSBSYSAUX", BADPATH, false),
    drive(b"INTMMC", BADPATH, false),
    drive(b"INTMMCSYS", BADPATH, false),
    drive(b"INTMMCSYSEXT", BADPATH, false),
    drive(b"INTMMCSYSAUX", BADPATH, false),
    drive(b"HDDVD", BADPATH, false),
    drive(b"HDDVDMU", BADPATH, false),
    drive(b"HDDVDSYS", BADPATH, false),
    drive(b"TRANSFERCABLE", BADPATH, false),
    drive(b"USBMASS0MUSYS", BADPATH, false),
    drive(b"USBMASS1MUSYS", BADPATH, false),
    drive(b"\x01", b"\\SystemRoot", false),
    None,
    None,
];

/// The mapping applied at startup when `drivemap internal` is nonzero
/// (0x91f2f0f8), in order.
const INTERNAL_DRIVES: &[(&[u8], &[u8], bool)] = &[
    (b"DEVICE", b"\\Device", false),
    (b"Y", b"\\Device\\Harddisk0\\SystemPartition", true),
    (b"Z", b"\\Device\\Harddisk0\\Partition1", true),
    (b"FLASH", b"\\Device\\Flash", true),
    (b"MU0SYS", b"\\Device\\Mu0System", false),
    (b"MU1SYS", b"\\Device\\Mu1System", false),
    (b"USBMASS0", b"\\Device\\Mass0", false),
    (b"USBMASS1", b"\\Device\\Mass1", false),
    (b"USBMASS2", b"\\Device\\Mass2", false),
    (b"MUINTSYS", b"\\Device\\BuiltInMuSfcSystem", false),
    (
        b"HDDSYSEXT",
        b"\\Device\\Harddisk0\\SystemExtPartition",
        false,
    ),
    (
        b"HDDSYSAUX",
        b"\\Device\\Harddisk0\\SystemAuxPartition",
        false,
    ),
    (b"INTUSB", b"\\Device\\BuiltInMuUsb\\Storage", true),
    (
        b"INTUSBSYS",
        b"\\Device\\BuiltInMuUsb\\StorageSystem",
        false,
    ),
    (
        b"INTUSBSYSEXT",
        b"\\Device\\BuiltInMuUsb\\SystemExtPartition",
        false,
    ),
    (
        b"INTUSBSYSAUX",
        b"\\Device\\BuiltInMuUsb\\SystemAuxPartition",
        false,
    ),
    (b"INTMMC", b"\\Device\\BuiltInMuMmc\\Storage", true),
    (
        b"INTMMCSYS",
        b"\\Device\\BuiltInMuMmc\\StorageSystem",
        false,
    ),
    (
        b"INTMMCSYSEXT",
        b"\\Device\\BuiltInMuMmc\\SystemExtPartition",
        false,
    ),
    (
        b"INTMMCSYSAUX",
        b"\\Device\\BuiltInMuMmc\\SystemAuxPartition",
        false,
    ),
    (b"HDDVD", b"\\Device\\HdDvdRom", false),
    (b"HDDVDMU", b"\\Device\\HdDvdStorage", false),
    (b"HDDVDSYS", b"\\Device\\HdDvdPlayer", false),
    (b"TRANSFERCABLE", b"\\Device\\TransferCable", false),
    (
        b"USBMASS0MU",
        b"\\Device\\Mass0PartitionFile\\Storage",
        true,
    ),
    (
        b"USBMASS1MU",
        b"\\Device\\Mass1PartitionFile\\Storage",
        true,
    ),
    (
        b"USBMASS0MUSYS",
        b"\\Device\\Mass0PartitionFile\\StorageSystem",
        false,
    ),
    (
        b"USBMASS1MUSYS",
        b"\\Device\\Mass1PartitionFile\\StorageSystem",
        false,
    ),
];

/// Where a drive name points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveTarget {
    Object(&'static [u8]),
    /// The network share in [`DriveTable::set_network_share`].
    NetworkShare,
    /// A string in title memory, read on every use, whose length was
    /// taken when the title mapped the drive (control code 0x03).
    Mapped {
        address: u32,
        length: u32,
    },
}

/// Name of a drive table row.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DriveName {
    bytes: [u8; DRIVE_NAME_SIZE],
    len: u8,
}

impl DriveName {
    /// The name cut to the row's field less its terminator.
    pub const fn new(name: &[u8]) -> Self {
        let mut bytes = [0; DRIVE_NAME_SIZE];
        let mut len = 0;

        while len < name.len() && len < DRIVE_NAME_SIZE - 1 {
            bytes[len] = name[len];
            len += 1;
        }

        Self {
            bytes,
            len: len as u8,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for DriveName {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_bytes() == other.as_slice()
    }
}

impl core::fmt::Debug for DriveName {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:?}", self.as_bytes().escape_ascii())
    }
}

/// One row of the drive table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drive {
    pub name: DriveName,
    pub target: DriveTarget,
    /// Enabled drives are listed by `drivelist`; translation ignores it.
    pub enabled: bool,
}

/// Drive names and the object directories they map to (0x91f96bf8).
#[derive(Debug, Clone)]
pub struct DriveTable {
    pub(super) entries: [Option<Drive>; DRIVE_TABLE_CAPACITY],
    network_share: [u8; NETWORK_SHARE_CAPACITY],
    network_share_len: usize,
}

impl DriveTable {
    pub const fn new() -> Self {
        Self {
            entries: DEFAULT_DRIVES,
            network_share: [0; NETWORK_SHARE_CAPACITY],
            network_share_len: 0,
        }
    }

    /// Rows in table order.
    pub fn drives(&self) -> impl Iterator<Item = &Drive> {
        self.entries.iter().map_while(Option::as_ref)
    }

    /// The bytes of `target`; `None` when a mapped string cannot be read.
    /// Mapped strings are read only up to `limit` bytes.
    pub(crate) fn target_bytes<'a>(
        &'a self,
        backend: &'a mut dyn crate::backend::Backend,
        target: DriveTarget,
        limit: usize,
    ) -> Option<&'a [u8]> {
        match target {
            DriveTarget::Object(bytes) => Some(bytes),
            DriveTarget::NetworkShare => Some(&self.network_share[..self.network_share_len]),
            DriveTarget::Mapped { address, length } => {
                backend.target_bytes(address, (length as usize).min(limit))
            }
        }
    }

    /// Point a drive at `target` or remove it (`None`), appending unknown
    /// names (0x91f2ef60). Names compare case-sensitively; a full table
    /// ignores new names. Removal moves the last row into the gap.
    pub fn map(&mut self, name: DriveName, target: Option<DriveTarget>, enabled: bool) {
        let count = self.drives().count();
        let index = self.entries[..count]
            .iter()
            .position(|entry| entry.is_some_and(|drive| drive.name == name));
        let index = match index {
            Some(index) => index,
            None if count + 1 < DRIVE_TABLE_CAPACITY => count,
            None => return,
        };

        match target {
            Some(target) => {
                self.entries[index] = Some(Drive {
                    name,
                    target,
                    enabled,
                })
            }
            None if index < count => {
                self.entries[index] = self.entries[count - 1];
                self.entries[count - 1] = None;
            }
            // A missing name has nothing to remove.
            None => {}
        }
    }

    /// Apply the internal drive mapping (0x91f2f0f8).
    pub fn map_internal_drives(&mut self) {
        for &(name, target, enabled) in INTERNAL_DRIVES {
            self.map(
                DriveName::new(name),
                Some(DriveTarget::Object(target)),
                enabled,
            );
        }
    }

    /// Point the first `F` or `SMB` drive at `\Network\Smb\<server>` and
    /// enable it, or at `\Badpath` disabled when `server` is `None`.
    pub fn set_network_share(&mut self, server: Option<&[u8]>) {
        const NETWORK_SHARE_PREFIX: &[u8] = b"\\Network\\Smb\\";

        let Some(entry) = self
            .entries
            .iter_mut()
            .map_while(Option::as_mut)
            .find(|drive| drive.name == b"F" || drive.name == b"SMB")
        else {
            return;
        };

        match server {
            Some(server) => {
                let server = &server[..server
                    .len()
                    .min(NETWORK_SHARE_CAPACITY - NETWORK_SHARE_PREFIX.len())];
                let prefix = NETWORK_SHARE_PREFIX.len();
                self.network_share[..prefix].copy_from_slice(NETWORK_SHARE_PREFIX);
                self.network_share[prefix..prefix + server.len()].copy_from_slice(server);
                self.network_share_len = prefix + server.len();
                entry.target = DriveTarget::NetworkShare;
                entry.enabled = true;
            }
            None => {
                entry.target = DriveTarget::Object(BADPATH);
                entry.enabled = false;
            }
        }
    }

    fn find(&self, drive: &[u8]) -> Option<&Drive> {
        self.drives()
            .find(|entry| entry.name.as_bytes().eq_ignore_ascii_case(drive))
    }

    /// Translate a drive path such as `E:\dir\file` to an object name
    /// (0x91f2e888). A leading `x` or `X` before a one-character drive is
    /// dropped. Drives missing from the table resolve through the `\??`
    /// symbolic link of the path, and to `\??\<path>` when that fails.
    pub fn translate(
        &self,
        backend: &mut dyn crate::backend::Backend,
        path: &[u8],
    ) -> Option<ObjectPath> {
        trace_path(
            backend,
            &[
                b"[xbdm] FFileNameToObName(sz='",
                console::c_string(path),
                b"',...)\n",
            ],
        );
        let translated = self.object_name(backend, path);
        match &translated {
            Some(output) => trace_path(
                backend,
                &[
                    b"[xbdm] FFileNameToObName succeeded, osz='",
                    console::c_string(output.as_bytes()),
                    b"'\n",
                ],
            ),
            None => trace_path(
                backend,
                &[b"[xbdm] FFileNameToObName - not a drive path - failing\n"],
            ),
        }

        translated
    }

    fn object_name(
        &self,
        backend: &mut dyn crate::backend::Backend,
        path: &[u8],
    ) -> Option<ObjectPath> {
        let input = match path {
            [b'x' | b'X', drive, b':', ..] if !matches!(drive, b':' | 0) => &path[1..],
            _ => path,
        };

        let colon = input.iter().position(|&byte| byte == b':')?;
        if input.get(colon + 1) != Some(&b'\\') {
            return None;
        }

        let drive = &input[..colon];
        let mut output = ObjectPath::new();
        if let Some(entry) = self.find(drive) {
            trace_path(
                backend,
                &[b"[xbdm] FFileNameToObName - drive name in conversion table\n"],
            );
            match entry.target {
                // The image copies the title's string up to its NUL on
                // every use; an unreadable page ends it (the image would
                // fault).
                DriveTarget::Mapped { address, .. } => {
                    let mut at = address;

                    while output.len < OBJECT_PATH_LIMIT {
                        let room = (PAGE_SIZE - (at & (PAGE_SIZE - 1))) as usize;
                        let Some(bytes) =
                            backend.target_bytes(at, room.min(OBJECT_PATH_LIMIT - output.len))
                        else {
                            break;
                        };

                        let end = bytes.iter().position(|&byte| byte == 0);
                        output.push(&bytes[..end.unwrap_or(bytes.len())]);
                        if end.is_some() || bytes.is_empty() {
                            break;
                        }

                        at = at.wrapping_add(bytes.len() as u32);
                    }
                }
                target => {
                    if let Some(target) = self.target_bytes(backend, target, OBJECT_PATH_LIMIT) {
                        output.push(target);
                    }
                }
            }

            output.push(&input[colon + 1..]);
            return Some(output);
        }

        // `_snprintf(buffer, 0x104, "%s%s", "\??\", path)`.
        let mut link = [0u8; 0x103];
        link[..4].copy_from_slice(b"\\??\\");
        let count = input.len().min(link.len() - 4);
        link[4..4 + count].copy_from_slice(&input[..count]);
        let link = &link[..4 + count];
        match backend.translate_symbolic_link(link, &mut output.bytes) {
            Ok(length) => {
                let mut length = length.min(OBJECT_PATH_LIMIT);
                if link.last() == Some(&b'\\')
                    && length > 0
                    && output.bytes[length - 1] != b'\\'
                    && length < OBJECT_PATH_LIMIT
                {
                    output.bytes[length] = b'\\';
                    length += 1;
                }

                output.len = length;
            }
            Err(_) => {
                output.push(b"\\??\\");
                let start = output.len;
                output.push(drive);
                output.bytes[start..output.len].make_ascii_uppercase();
                output.push(&input[colon..]);
            }
        }

        Some(output)
    }

    /// Convert an object name back to a drive path (0x91f2e750): the
    /// first drive whose target is a case-insensitive prefix of
    /// `object_path` gives `<drive>:<rest>`, otherwise the name is copied.
    /// The output holds at most `output.len() - 1` bytes; returns the
    /// length.
    pub fn object_path_to_drive_path(
        &self,
        backend: &mut dyn crate::backend::Backend,
        object_path: &[u8],
        output: &mut [u8],
    ) -> usize {
        let limit = output.len().saturating_sub(1);

        for entry in self.drives() {
            let length = match entry.target {
                DriveTarget::Mapped { length, .. } => length as usize,
                DriveTarget::Object(bytes) => bytes.len(),
                DriveTarget::NetworkShare => self.network_share_len,
            };

            if object_path.len() < length {
                continue;
            }

            let Some(target) = self.target_bytes(backend, entry.target, length) else {
                continue;
            };

            if target.len() == length && object_path[..length].eq_ignore_ascii_case(target) {
                let name = entry.name.as_bytes();
                let mut length = name.len().min(output.len());
                output[..length].copy_from_slice(&name[..length]);
                if length < output.len() {
                    output[length] = b':';
                    length += 1;
                }

                let room = limit.saturating_sub(length);
                let rest = &object_path[target.len()..];
                let count = rest.len().min(room);
                output[length..length + count].copy_from_slice(&rest[..count]);
                return length + count;
            }
        }

        let count = object_path.len().min(limit);
        output[..count].copy_from_slice(&object_path[..count]);

        count
    }
}

impl Default for DriveTable {
    fn default() -> Self {
        Self::new()
    }
}

/// A translated object name.
#[derive(Clone)]
pub struct ObjectPath {
    bytes: [u8; OBJECT_PATH_LIMIT],
    len: usize,
}

impl ObjectPath {
    const fn new() -> Self {
        Self {
            bytes: [0; OBJECT_PATH_LIMIT],
            len: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Append within the limit, dropping the excess as the translator does.
    fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.len >= OBJECT_PATH_LIMIT {
                return;
            }

            self.bytes[self.len] = byte;
            self.len += 1;
        }
    }
}

impl core::fmt::Debug for ObjectPath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:?}", self.as_bytes().escape_ascii())
    }
}

const fn drive(name: &'static [u8], target: &'static [u8], enabled: bool) -> Option<Drive> {
    Some(Drive {
        name: DriveName::new(name),
        target: DriveTarget::Object(target),
        enabled,
    })
}

/// Names and targets of the internal drive mapping, in order.
#[cfg(feature = "smb")]
pub(crate) fn internal_drives() -> impl Iterator<Item = (&'static [u8], &'static [u8])> {
    INTERNAL_DRIVES
        .iter()
        .map(|&(name, target, _)| (name, target))
}

/// A FFileNameToObName trace text of `parts`. The translation holds no
/// server state; the published mask follows every change of the server's.
#[inline(never)]
fn trace_path(backend: &mut dyn crate::backend::Backend, parts: &[&[u8]]) {
    let mask = console::Backend::trace_mask(backend);
    console::trace_text(mask, backend, TraceMask::PATHS, |message| {
        for part in parts {
            let _ = message.push_bytes(part);
        }
    });
}

/// Control code 0x03 (0x91f2ef60, enabled): map the drive named by a title
/// request `{name: [u8; 0x20], target: u32}` at `request` to the string at
/// `target`, or remove it when `target` is null. The table keeps the
/// title's pointer. `F` and `SMB` refresh the network share drive from the
/// configuration instead. Unreadable request memory, on which the image
/// would fault, leaves the table unchanged.
pub fn map_title_drive(
    state: &mut ServerState,
    backend: &mut dyn crate::backend::Backend,
    request: u32,
) {
    let Some(bytes) = backend.target_bytes(request, DRIVE_NAME_SIZE + 4) else {
        return;
    };

    let name_len = bytes[..DRIVE_NAME_SIZE]
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(DRIVE_NAME_SIZE);
    let name = DriveName::new(&bytes[..name_len]);
    let address = u32::from_be_bytes([
        bytes[DRIVE_NAME_SIZE],
        bytes[DRIVE_NAME_SIZE + 1],
        bytes[DRIVE_NAME_SIZE + 2],
        bytes[DRIVE_NAME_SIZE + 3],
    ]);
    if name == b"F" || name == b"SMB" {
        console::refresh_network_share(state, backend);
        return;
    }

    let target = match address {
        0 => None,
        _ => match mapped_length(backend, address) {
            Some(length) => Some(DriveTarget::Mapped { address, length }),
            None => return,
        },
    };

    state.filesystem.drives.map(name, target, true);
}

/// Length of the title string at `address`. Strings longer than any object
/// name count as `OBJECT_PATH_LIMIT + 1` bytes, which no translation or
/// prefix comparison can tell apart from their real length.
fn mapped_length(backend: &mut dyn crate::backend::Backend, address: u32) -> Option<u32> {
    let mut length = 0;

    while length <= OBJECT_PATH_LIMIT {
        let at = address.wrapping_add(length as u32);
        let page_room = (PAGE_SIZE - (at & (PAGE_SIZE - 1))) as usize;
        let count = page_room.min(OBJECT_PATH_LIMIT + 1 - length);
        let bytes = backend.target_bytes(at, count)?;
        if let Some(end) = bytes.iter().position(|&byte| byte == 0) {
            return Some((length + end) as u32);
        }

        length += count;
    }

    Some(length as u32)
}

/// Whether `name` starts with `\Device\`, ignoring case.
pub(super) fn is_device_path(name: &[u8]) -> bool {
    const DEVICE_PREFIX: &[u8] = b"\\Device\\";

    name.len() >= DEVICE_PREFIX.len()
        && name[..DEVICE_PREFIX.len()].eq_ignore_ascii_case(DEVICE_PREFIX)
}

/// Open a drive path (0x91f2eb68); a path that does not translate fails
/// with [`KernelError::NoSuchFile`].
pub fn open_translated(
    state: &ServerState,
    backend: &mut dyn crate::backend::Backend,
    name: &[u8],
    request: &CreateRequest,
) -> Result<FileHandle, KernelError> {
    let path = state
        .filesystem
        .drives
        .translate(backend, name)
        .ok_or(KernelError::NoSuchFile)?;
    backend.create_file(path.as_bytes(), request)
}

/// Open `\Device\` names as object names and translate the others.
pub fn open_path(
    state: &ServerState,
    backend: &mut dyn crate::backend::Backend,
    name: &[u8],
    request: &CreateRequest,
) -> Result<FileHandle, KernelError> {
    if is_device_path(name) {
        backend.create_file(name, request)
    } else {
        open_translated(state, backend, name, request)
    }
}
