//! The [`smb2_server::Backend`] of a connection over the monitor's state
//! and platform.

use openxbdm_core::status::KernelError;
use smb2_server::NtStatus;
use smb2_server::backend::Accounts;
use smb2_server::backend::COMPUTER_NAME_CAPACITY;
use smb2_server::backend::FileHandle;
use smb2_server::backend::FileSystem;
use smb2_server::backend::NtOwf;
use smb2_server::backend::OpenRequest;
use smb2_server::backend::Opened;
use smb2_server::backend::Platform;
use smb2_server::backend::SHARE_NAME_CAPACITY;
use smb2_server::backend::Share;
use smb2_server::backend::ShareId;
use smb2_server::backend::ShareIndex;
use smb2_server::backend::Shares;
use smb2_server::backend::UserKind;
use smb2_server::fs::BasicInformation;
use smb2_server::fs::CreateAction;
use smb2_server::fs::CreateDisposition;
use smb2_server::fs::DirectoryEntry;
use smb2_server::fs::FileAttributes;
use smb2_server::fs::FileInformation;
use smb2_server::fs::FileSystemAttributes;
use smb2_server::fs::FileSystemName;
use smb2_server::fs::FileTime;
use smb2_server::fs::FsError;
use smb2_server::fs::NAME_CAPACITY;
use smb2_server::fs::VolumeInformation;
use smb2_server::fs::VolumeSize;
use smb2_server::path::SharePath;
use smb2_server::server::MAX_HANDLES;
use smb2_server::utf16::Utf16Le;

use super::shares;
use super::shares::ObjectName;
use super::shares::Presence;
use super::shares::ShareBindings;
use crate::commands::filesystem;
use crate::commands::filesystem::DriveTable;
use crate::commands::filesystem::DriveTarget;
use crate::commands::filesystem::OBJECT_PATH_LIMIT;
use crate::commands::security;
use crate::state::ServerState;

/// NT one-way function of the empty password.
const EMPTY_PASSWORD: NtOwf = NtOwf([
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
]);
/// Computer name while the console has no debug name.
const DEFAULT_COMPUTER_NAME: &[u8] = b"XBOX360";
/// Volume information of a volume whose attribute query fails: FATX, the
/// file system of the console's writable volumes, with its 42-character
/// names.
const FALLBACK_FILE_SYSTEM: FileSystemName = match FileSystemName::new(b"FATX") {
    Some(name) => name,
    None => panic!("FATX is a file system name"),
};
const FALLBACK_ATTRIBUTES: FileSystemAttributes = FileSystemAttributes::CASE_PRESERVED_NAMES;
const FALLBACK_NAME_LIMIT: u32 = 42;

/// An open file of a connection.
#[derive(Debug, Clone, Copy)]
struct Open {
    handle: filesystem::FileHandle,
    share: ShareId,
    /// Counted as a file change when closed.
    changed: bool,
}

/// Backend files of a connection's opens and change scans; an SMB file
/// handle is a slot.
#[derive(Debug)]
pub(crate) struct Opens {
    slots: [Option<Open>; MAX_HANDLES],
}

impl Opens {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [None; MAX_HANDLES],
        }
    }

    fn get(&self, handle: FileHandle) -> Result<Open, FsError> {
        self.slots
            .get(handle.0 as usize)
            .copied()
            .flatten()
            .ok_or(FsError::InvalidHandle)
    }

    /// The backend handle of `handle`, marked changed when `changes`.
    fn use_handle(
        &mut self,
        handle: FileHandle,
        changes: bool,
    ) -> Result<filesystem::FileHandle, FsError> {
        let open = self
            .slots
            .get_mut(handle.0 as usize)
            .and_then(Option::as_mut)
            .ok_or(FsError::InvalidHandle)?;
        open.changed |= changes;
        Ok(open.handle)
    }
}

/// Per-connection state the adapter keeps between messages.
#[derive(Debug)]
pub(crate) struct ConnectionFiles {
    pub(crate) opens: Opens,
}

impl ConnectionFiles {
    pub(crate) const fn new() -> Self {
        Self {
            opens: Opens::new(),
        }
    }

    /// Close every open the engine left behind, leaving the state as new.
    pub(crate) fn reset(&mut self, backend: &mut dyn crate::backend::Backend) {
        for slot in &mut self.opens.slots {
            if let Some(open) = slot.take() {
                close(backend, open);
            }
        }
    }
}

fn close(backend: &mut dyn crate::backend::Backend, open: Open) {
    backend.close_file(open.handle);
    if open.changed {
        backend.count_file_change();
    }
}

/// The backend of one message.
pub(crate) struct Adapter<'a> {
    pub(crate) state: &'a ServerState,
    pub(crate) backend: &'a mut dyn crate::backend::Backend,
    pub(crate) files: &'a mut ConnectionFiles,
    /// Share identifiers of the service, shared by its connections.
    pub(crate) shares: &'a mut ShareBindings,
    /// Share presence, tested at most once per message.
    pub(crate) presence: Presence,
}

/// The SMB error of a failed kernel call; both carry NT statuses, so a
/// status without a variant passes through unchanged.
fn file_error(error: KernelError) -> FsError {
    FsError::from_status(NtStatus::from_raw(error.status().0))
}

fn time(time: filesystem::FileTime) -> FileTime {
    FileTime(time.0)
}

fn information(information: filesystem::FileInformation) -> FileInformation {
    FileInformation {
        creation_time: time(information.creation_time),
        last_access_time: time(information.last_access_time),
        last_write_time: time(information.last_write_time),
        change_time: time(information.change_time),
        allocation_size: information.allocation_size,
        end_of_file: information.end_of_file,
        // A file without attribute bits is reported as NORMAL, as NT file
        // systems do.
        attributes: match information.attributes.0 {
            0 => FileAttributes::NORMAL,
            bits => FileAttributes(bits),
        },
        // FATX has no file identifiers.
        index: None,
    }
}

fn disposition(disposition: CreateDisposition) -> filesystem::CreateDisposition {
    match disposition {
        CreateDisposition::Supersede => filesystem::CreateDisposition::Supersede,
        CreateDisposition::Open => filesystem::CreateDisposition::Open,
        CreateDisposition::Create => filesystem::CreateDisposition::Create,
        CreateDisposition::OpenIf => filesystem::CreateDisposition::OpenIf,
        CreateDisposition::Overwrite => filesystem::CreateDisposition::Overwrite,
        CreateDisposition::OverwriteIf => filesystem::CreateDisposition::OverwriteIf,
    }
}

/// The create action of a disposition, given whether the file existed.
fn action(disposition: CreateDisposition, existed: bool) -> CreateAction {
    match (disposition, existed) {
        (CreateDisposition::Create, _) | (_, false) => CreateAction::Created,
        (CreateDisposition::Open | CreateDisposition::OpenIf, true) => CreateAction::Opened,
        (CreateDisposition::Overwrite | CreateDisposition::OverwriteIf, true) => {
            CreateAction::Overwritten
        }
        (CreateDisposition::Supersede, true) => CreateAction::Superseded,
    }
}

/// The bytes of a share target; `None` when a title's string cannot be
/// read or would not fit an object name.
fn target_bytes<'b>(
    drives: &'b DriveTable,
    backend: &'b mut dyn crate::backend::Backend,
    target: DriveTarget,
) -> Option<&'b [u8]> {
    shares::fits(target)
        .then(|| drives.target_bytes(backend, target, OBJECT_PATH_LIMIT))
        .flatten()
}

/// Result of a share presence test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    Absent,
    Present { read_only: bool },
}

/// Open the root of a share target as a directory. Optical drives and
/// volumes that report themselves read-only are read-only shares.
fn probe(
    drives: &DriveTable,
    backend: &mut dyn crate::backend::Backend,
    target: DriveTarget,
) -> Probe {
    let Some(bytes) = target_bytes(drives, backend, target) else {
        return Probe::Absent;
    };
    let optical = shares::is_optical(bytes);
    let Ok(root) = ObjectName::new(bytes, SharePath::ROOT) else {
        return Probe::Absent;
    };
    let request = filesystem::CreateRequest::open(
        filesystem::FileAccess::READ_ATTRIBUTES.union(filesystem::FileAccess::SYNCHRONIZE),
        filesystem::ShareAccess::ALL,
        filesystem::CreateOptions::DIRECTORY_FILE,
    );
    let opened = backend.create_file(root.as_bytes(), &request);
    let read_only_volume = match opened {
        Ok(handle) => {
            let attributes = backend.query_volume_attributes(handle);
            backend.close_file(handle);
            attributes.is_ok_and(|attributes| {
                attributes
                    .flags
                    .contains(filesystem::FileSystemFlags::READ_ONLY_VOLUME)
            })
        }
        Err(_) => false,
    };
    if shares::exists(opened.map(|_| ())) {
        Probe::Present {
            read_only: optical || read_only_volume,
        }
    } else {
        Probe::Absent
    }
}

/// Share names are ASCII; other names match no share.
fn ascii_name<'b>(
    name: Utf16Le<'_>,
    buffer: &'b mut [u8; SHARE_NAME_CAPACITY],
) -> Option<&'b [u8]> {
    let length = name.len();
    let output = buffer.get_mut(..length)?;
    for (byte, unit) in output.iter_mut().zip(name.units()) {
        *byte = u8::try_from(unit).ok().filter(u8::is_ascii)?;
    }
    Some(output)
}

impl Adapter<'_> {
    /// Logons and shares are closed while the console is locked.
    fn locked(&self) -> bool {
        security::security_enabled(self.state)
    }

    /// The object name of `path` on `share`.
    fn object_name(&mut self, share: ShareId, path: SharePath<'_>) -> Result<ObjectName, FsError> {
        let drives = &self.state.filesystem.drives;
        let target = self.shares.resolve(drives, share)?;
        let target = target_bytes(drives, self.backend, target).ok_or(FsError::ShareRemoved)?;
        ObjectName::new(target, path)
    }

    /// Opens, renames, and deletes fail while the console is locked.
    fn check_unlocked(&self) -> Result<(), FsError> {
        if self.locked() {
            Err(FsError::AccessDenied)
        } else {
            Ok(())
        }
    }
}

impl Platform for Adapter<'_> {
    fn system_time(&mut self) -> FileTime {
        FileTime(crate::backend::Platform::system_time(self.backend))
    }

    fn random_bytes(&mut self, output: &mut [u8]) {
        crate::backend::Platform::random_bytes(self.backend, output);
    }

    /// The debug name in upper case, with characters NetBIOS names exclude
    /// replaced by `_`.
    fn computer_name(&mut self, output: &mut [u8; COMPUTER_NAME_CAPACITY]) -> usize {
        let name = self.state.console.debug_name;
        let name = match name.as_bytes() {
            [] => DEFAULT_COMPUTER_NAME,
            name => name,
        };
        let length = name.len().min(COMPUTER_NAME_CAPACITY);
        for (output, &byte) in output.iter_mut().zip(&name[..length]) {
            *output = match byte {
                b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' => byte.to_ascii_uppercase(),
                _ => b'_',
            };
        }
        length
    }
}

impl Accounts for Adapter<'_> {
    fn password(&mut self, _user: Utf16Le<'_>, _domain: Utf16Le<'_>) -> Option<NtOwf> {
        (!self.locked()).then_some(EMPTY_PASSWORD)
    }

    fn allow_guest(&mut self) -> bool {
        !self.locked()
    }

    fn allow_anonymous(&mut self) -> bool {
        !self.locked()
    }
}

impl Shares for Adapter<'_> {
    fn find_share(&mut self, name: Utf16Le<'_>, _kind: UserKind) -> Option<Share> {
        if self.locked() {
            return None;
        }
        let mut buffer = [0u8; SHARE_NAME_CAPACITY];
        let name = ascii_name(name, &mut buffer)?;
        let drives = &self.state.filesystem.drives;
        let candidate = shares::find(drives, name)?;
        let Probe::Present { read_only } = probe(drives, self.backend, candidate.target) else {
            return None;
        };
        let id = self.shares.bind(candidate)?;
        Some(Share {
            id,
            writable: !read_only,
        })
    }

    fn share_name(
        &mut self,
        index: ShareIndex,
        _kind: UserKind,
        name: &mut [u16; SHARE_NAME_CAPACITY],
    ) -> Option<usize> {
        if self.locked() {
            return None;
        }
        let drives = &self.state.filesystem.drives;
        let backend = &mut *self.backend;
        let candidate = self.presence.nth(drives, index.0 as usize, &mut |target| {
            probe(drives, backend, target) != Probe::Absent
        })?;
        for (unit, &byte) in name.iter_mut().zip(candidate.name) {
            *unit = u16::from(byte);
        }
        Some(candidate.name.len())
    }
}

impl FileSystem for Adapter<'_> {
    fn open(
        &mut self,
        share: ShareId,
        path: SharePath<'_>,
        request: &OpenRequest,
    ) -> Result<Opened, FsError> {
        self.check_unlocked()?;
        let name = self.object_name(share, path)?;
        let slot = self
            .files
            .opens
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(FsError::TooManyOpenFiles)?;
        // The backend reports no create action; it follows from whether
        // the file existed before.
        let existed = match request.disposition {
            CreateDisposition::Open | CreateDisposition::Create | CreateDisposition::Overwrite => {
                true
            }
            CreateDisposition::OpenIf
            | CreateDisposition::OverwriteIf
            | CreateDisposition::Supersede => {
                match self.backend.query_full_attributes(name.as_bytes()) {
                    Ok(_) => true,
                    Err(KernelError::ObjectNameNotFound | KernelError::ObjectPathNotFound) => false,
                    Err(error) => return Err(file_error(error)),
                }
            }
        };
        // Requests complete before the server continues, so the backend
        // performs synchronous I/O on the file.
        let create = filesystem::CreateRequest {
            access: filesystem::FileAccess(request.access.0)
                .union(filesystem::FileAccess::SYNCHRONIZE),
            allocation_size: request.allocation_size,
            attributes: filesystem::FileAttributes(request.attributes.0),
            share: filesystem::ShareAccess(request.share_access.0),
            disposition: disposition(request.disposition),
            options: filesystem::CreateOptions(request.options.0)
                .union(filesystem::CreateOptions::SYNCHRONOUS_IO_NONALERT),
        };
        let handle = self
            .backend
            .create_file(name.as_bytes(), &create)
            .map_err(file_error)?;
        let file = match self.backend.query_file_information(handle) {
            Ok(file) => file,
            Err(error) => {
                self.backend.close_file(handle);
                return Err(file_error(error));
            }
        };
        let action = action(request.disposition, existed);
        self.files.opens.slots[slot] = Some(Open {
            handle,
            share,
            changed: action != CreateAction::Opened,
        });
        Ok(Opened {
            handle: FileHandle(slot as u32),
            action,
            information: information(file),
        })
    }

    fn close(&mut self, handle: FileHandle) {
        if let Some(open) = self
            .files
            .opens
            .slots
            .get_mut(handle.0 as usize)
            .and_then(Option::take)
        {
            close(self.backend, open);
        }
    }

    fn read(
        &mut self,
        handle: FileHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, FsError> {
        let handle = self.files.opens.use_handle(handle, false)?;
        match self
            .backend
            .read_file(handle, Some(offset), filesystem::ReadTarget::Bytes(output))
        {
            Ok(count) => Ok(count as usize),
            Err(KernelError::EndOfFile) => Ok(0),
            Err(error) => Err(file_error(error)),
        }
    }

    fn write(&mut self, handle: FileHandle, offset: u64, data: &[u8]) -> Result<(), FsError> {
        let handle = self.files.opens.use_handle(handle, true)?;
        self.backend
            .write_file(handle, Some(offset), filesystem::FileData::Bytes(data))
            .map_err(file_error)
    }

    /// Writes complete into the file system before they return; the backend
    /// has no separate flush.
    fn flush(&mut self, handle: FileHandle) -> Result<(), FsError> {
        self.files.opens.get(handle).map(|_| ())
    }

    fn information(&mut self, handle: FileHandle) -> Result<FileInformation, FsError> {
        let handle = self.files.opens.use_handle(handle, false)?;
        self.backend
            .query_file_information(handle)
            .map(information)
            .map_err(file_error)
    }

    fn set_basic_information(
        &mut self,
        handle: FileHandle,
        information: &BasicInformation,
    ) -> Result<(), FsError> {
        let handle = self.files.opens.use_handle(handle, true)?;
        // Zero leaves a value unchanged.
        let time = |value: Option<FileTime>| filesystem::FileTime(value.map_or(0, |time| time.0));
        let basic = filesystem::BasicInformation {
            creation_time: time(information.creation_time),
            last_access_time: time(information.last_access_time),
            last_write_time: time(information.last_write_time),
            change_time: time(information.change_time),
            attributes: filesystem::FileAttributes(
                information.attributes.map_or(0, |attributes| attributes.0),
            ),
        };
        self.backend
            .set_basic_information(handle, &basic)
            .map_err(file_error)
    }

    fn set_end_of_file(&mut self, handle: FileHandle, size: u64) -> Result<(), FsError> {
        let handle = self.files.opens.use_handle(handle, true)?;
        self.backend
            .set_end_of_file(handle, size)
            .map_err(file_error)
    }

    fn set_delete_pending(&mut self, handle: FileHandle, delete: bool) -> Result<(), FsError> {
        self.check_unlocked()?;
        let handle = self.files.opens.use_handle(handle, true)?;
        self.backend
            .set_delete_disposition(handle, delete)
            .map_err(file_error)
    }

    fn rename(
        &mut self,
        handle: FileHandle,
        target: SharePath<'_>,
        replace: bool,
    ) -> Result<(), FsError> {
        self.check_unlocked()?;
        let share = self.files.opens.get(handle)?.share;
        let name = self.object_name(share, target)?;
        let handle = self.files.opens.use_handle(handle, true)?;
        self.backend
            .rename_file(handle, name.as_bytes(), replace)
            .map_err(file_error)
    }

    fn read_directory(
        &mut self,
        handle: FileHandle,
        restart: bool,
        name: &mut [u16; NAME_CAPACITY],
    ) -> Result<Option<DirectoryEntry>, FsError> {
        let handle = self.files.opens.use_handle(handle, false)?;
        let mut bytes = [0u8; NAME_CAPACITY];
        let mut restart = restart;
        loop {
            match self.backend.query_directory(handle, restart, &mut bytes) {
                // The server adds `.` and `..` itself.
                Ok(entry) if matches!(&bytes[..entry.name_length], b"." | b"..") => {
                    restart = false;
                }
                Ok(entry) => {
                    for (unit, &byte) in name.iter_mut().zip(&bytes[..entry.name_length]) {
                        *unit = u16::from(byte);
                    }
                    return Ok(Some(DirectoryEntry {
                        information: information(entry.information),
                        name_length: entry.name_length,
                    }));
                }
                // An empty directory reports NO_SUCH_FILE on its first query.
                Err(KernelError::NoMoreFiles | KernelError::NoSuchFile) => return Ok(None),
                Err(error) => return Err(file_error(error)),
            }
        }
    }

    /// Name, attributes, and component length come from the volume; when
    /// its attribute query fails they are FATX's. Console volumes have no
    /// serial number or creation time the backend reports.
    fn volume_information(&mut self, handle: FileHandle) -> Result<VolumeInformation, FsError> {
        let handle = self.files.opens.use_handle(handle, false)?;
        let size = self.backend.query_volume_size(handle).map_err(file_error)?;
        let (attributes, maximum_component_length, file_system_name) =
            match self.backend.query_volume_attributes(handle) {
                Ok(volume) => (
                    FileSystemAttributes(volume.flags.0),
                    volume.maximum_component_length,
                    FileSystemName::new(volume.name()).unwrap_or(FALLBACK_FILE_SYSTEM),
                ),
                Err(_) => (
                    FALLBACK_ATTRIBUTES,
                    FALLBACK_NAME_LIMIT,
                    FALLBACK_FILE_SYSTEM,
                ),
            };
        Ok(VolumeInformation {
            size: VolumeSize {
                total_units: size.total_units,
                available_units: size.available_units,
                sectors_per_unit: size.sectors_per_unit,
                bytes_per_sector: size.bytes_per_sector,
            },
            serial_number: 0,
            creation_time: FileTime(0),
            attributes,
            maximum_component_length,
            file_system_name,
        })
    }
}
