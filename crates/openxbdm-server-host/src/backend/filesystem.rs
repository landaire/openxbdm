//! Simulated object namespace, FATX volumes, and block devices.

use std::collections::HashMap;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use openxbdm_server::Platform;
use openxbdm_server::commands::filesystem;
use openxbdm_server::commands::filesystem::BasicInformation;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::DeviceObject;
use openxbdm_server::commands::filesystem::DirectoryEntry;
use openxbdm_server::commands::filesystem::DvdTrace;
use openxbdm_server::commands::filesystem::FileData;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::filesystem::FileInformation;
use openxbdm_server::commands::filesystem::FileTime;
use openxbdm_server::commands::filesystem::ObjectDirectory;
use openxbdm_server::commands::filesystem::PoolBuffer;
use openxbdm_server::commands::filesystem::PoolRange;
use openxbdm_server::commands::filesystem::ReadTarget;
use openxbdm_server::commands::filesystem::ScratchBlock;
use openxbdm_server::commands::filesystem::TransferDirection;
use openxbdm_server::commands::filesystem::VolumeSize;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FileSystemAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::MockBackend;
use super::POOL_LIMIT;

/// The development partition holding `E:` and `DEVKIT:`.
pub const PARTITION1: &str = "\\Device\\Harddisk0\\Partition1";
/// A system cache volume reachable only through `\??\SysCache0:`.
pub const CACHE0: &str = "\\Device\\Harddisk0\\Cache0";
/// The internal memory unit (`MUINT:`).
pub const MEMORY_UNIT: &str = "\\Device\\BuiltInMuSfc";
/// The system flash volume.
pub const SYSTEM_ROOT: &str = "\\SystemRoot";
/// The optical drive: a raw device without a recognized file system.
pub const CDROM: &str = "\\Device\\Cdrom0";
/// The whole hard disk as a raw device.
pub const HARDDISK: &str = "\\Device\\Harddisk0\\Partition0";

/// FATX names are at most 42 characters.
const MAX_NAME: usize = 42;
/// Rights that permit reading file data.
const READ_ACCESS: AccessMask = AccessMask::from_bits_retain(
    AccessMask::READ_DATA.bits()
        | AccessMask::MAXIMUM_ALLOWED.bits()
        | AccessMask::GENERIC_ALL.bits()
        | AccessMask::GENERIC_READ.bits(),
);
/// Rights that permit writing file data.
const WRITE_ACCESS: AccessMask = AccessMask::from_bits_retain(
    AccessMask::WRITE_DATA.bits()
        | AccessMask::APPEND_DATA.bits()
        | AccessMask::GENERIC_ALL.bits()
        | AccessMask::GENERIC_WRITE.bits(),
);
const CLUSTER: u64 = 0x4000;
const DVD_TRACE_SIZE: u32 = 0x20_0000;

/// One file or directory of a volume. `path` is relative to the volume
/// root and starts with a backslash.
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: Vec<u8>,
    pub directory: bool,
    pub data: Vec<u8>,
    pub attributes: FileAttributes,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
}

/// A mounted FATX volume.
#[derive(Debug, Clone)]
pub struct Volume {
    pub device: Vec<u8>,
    pub entries: Vec<Entry>,
    pub total_units: u64,
}

impl Volume {
    fn new(device: &str, total_units: u64) -> Self {
        Self {
            device: device.as_bytes().to_vec(),
            entries: Vec::new(),
            total_units,
        }
    }

    fn used_units(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| entry.data.len().div_ceil(CLUSTER as usize) as u64)
            .sum()
    }

    fn find(&self, path: &[u8]) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.path.eq_ignore_ascii_case(path))
    }
}

#[derive(Debug, Clone)]
struct OpenFile {
    volume: usize,
    /// `None` for the volume root.
    path: Option<Vec<u8>>,
    access: AccessMask,
    position: u64,
    delete_pending: bool,
    cursor: usize,
}

/// A block device addressed by object name.
#[derive(Debug, Clone)]
pub struct RawDevice {
    pub name: Vec<u8>,
    pub bytes: Vec<u8>,
}

/// Simulated state of this domain.
#[derive(Debug)]
pub struct Mock {
    pub volumes: Vec<Volume>,
    /// `\??` symbolic links: name (without `\??\`) and target.
    pub links: Vec<(Vec<u8>, Vec<u8>)>,
    pub devices: Vec<RawDevice>,
    /// Partition names formatted by `fmtfat`.
    pub formatted: Vec<Vec<u8>>,
    /// Values passed to the tray control.
    pub tray: Vec<u32>,
    pub update_sequence: u16,
    /// Writes ending past this file offset fail with a full disk.
    pub write_limit: Option<u64>,
    /// Every pool allocation fails.
    pub pool_exhausted: bool,
    /// Closes of files commands may have changed (export 85).
    pub file_changes: u32,
    handles: HashMap<u32, OpenFile>,
    next_handle: u32,
    pools: HashMap<u32, Vec<u8>>,
    next_pool: u32,
    dvd_trace: Option<(PoolBuffer, u32)>,
}

fn raw_image(sectors: usize, sector: usize, seed: u8) -> Vec<u8> {
    (0..sectors * sector)
        .map(|offset| (offset / sector) as u8 ^ (offset as u8).wrapping_mul(seed))
        .collect()
}

impl Default for Mock {
    fn default() -> Self {
        let mut partition = Volume::new(PARTITION1, 0x1000);
        partition.entries.push(Entry::directory(b"\\DEVKIT"));
        Self {
            volumes: vec![
                partition,
                Volume::new(CACHE0, 0x100),
                Volume::new(MEMORY_UNIT, 0x200),
                Volume::new(SYSTEM_ROOT, 0x40),
            ],
            links: vec![
                (b"D:".to_vec(), CDROM.as_bytes().to_vec()),
                (
                    b"E:".to_vec(),
                    b"\\Device\\Harddisk0\\Partition1\\DEVKIT".to_vec(),
                ),
                (b"SysCache0:".to_vec(), CACHE0.as_bytes().to_vec()),
                (
                    b"Q:".to_vec(),
                    b"\\Device\\Harddisk0\\Partition1\\DEVKIT".to_vec(),
                ),
                (b"CdRom0".to_vec(), CDROM.as_bytes().to_vec()),
            ],
            devices: vec![
                RawDevice {
                    name: CDROM.as_bytes().to_vec(),
                    bytes: raw_image(32, 0x800, 7),
                },
                RawDevice {
                    name: HARDDISK.as_bytes().to_vec(),
                    bytes: raw_image(0x200, 0x200, 13),
                },
            ],
            formatted: Vec::new(),
            tray: Vec::new(),
            update_sequence: 0x1234,
            write_limit: None,
            pool_exhausted: false,
            file_changes: 0,
            handles: HashMap::new(),
            next_handle: 1,
            pools: HashMap::new(),
            next_pool: 1,
            dvd_trace: None,
        }
    }
}

impl Entry {
    fn directory(path: &[u8]) -> Self {
        Self {
            path: path.to_vec(),
            directory: true,
            data: Vec::new(),
            attributes: FileAttributes::DIRECTORY,
            creation_time: FileTime(0),
            last_access_time: FileTime(0),
            last_write_time: FileTime(0),
            change_time: FileTime(0),
        }
    }

    fn information(&self) -> FileInformation {
        FileInformation {
            creation_time: self.creation_time,
            last_access_time: self.last_access_time,
            last_write_time: self.last_write_time,
            change_time: self.change_time,
            allocation_size: (self.data.len() as u64).div_ceil(CLUSTER) * CLUSTER,
            end_of_file: self.data.len() as u64,
            attributes: self.attributes,
        }
    }
}

fn root_information() -> FileInformation {
    FileInformation {
        attributes: FileAttributes::DIRECTORY,
        ..FileInformation::default()
    }
}

fn parent(path: &[u8]) -> &[u8] {
    &path[..path.iter().rposition(|&byte| byte == b'\\').unwrap_or(0)]
}

fn leaf(path: &[u8]) -> &[u8] {
    &path[path
        .iter()
        .rposition(|&byte| byte == b'\\')
        .map_or(0, |index| index + 1)..]
}

fn starts_with_ignore_case(text: &[u8], prefix: &[u8]) -> bool {
    text.len() >= prefix.len() && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// The rest of `path` after `prefix` when `prefix` names a whole
/// component.
fn strip_component<'a>(path: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if !starts_with_ignore_case(path, prefix) {
        return None;
    }
    let rest = &path[prefix.len()..];
    (rest.is_empty() || rest[0] == b'\\').then_some(rest)
}

impl Mock {
    /// Resolve an object name to a volume and a volume path; `None` path
    /// means the root.
    fn resolve(&self, path: &[u8]) -> Result<(usize, Option<Vec<u8>>), KernelError> {
        if let Some(rest) = strip_component(path, b"\\??") {
            let rest = rest.strip_prefix(b"\\").unwrap_or(rest);
            for (name, target) in &self.links {
                if let Some(tail) = strip_component(rest, name) {
                    let mut resolved = target.clone();
                    resolved.extend_from_slice(tail);
                    return self.resolve(&resolved);
                }
            }
            return Err(KernelError::ObjectPathNotFound);
        }
        for (index, volume) in self.volumes.iter().enumerate() {
            if let Some(rest) = strip_component(path, &volume.device) {
                let rest = rest.strip_suffix(b"\\").unwrap_or(rest);
                return Ok((index, (!rest.is_empty()).then(|| rest.to_vec())));
            }
        }
        if self
            .devices
            .iter()
            .any(|device| strip_component(path, &device.name).is_some())
        {
            return Err(KernelError::UnrecognizedVolume);
        }
        let components = path
            .split(|&byte| byte == b'\\')
            .filter(|part| !part.is_empty())
            .count();
        Err(if components > 2 {
            KernelError::ObjectPathNotFound
        } else {
            KernelError::ObjectNameNotFound
        })
    }

    fn file(&self, handle: FileHandle) -> Result<&OpenFile, KernelError> {
        self.handles
            .get(&handle.0)
            .ok_or(KernelError::InvalidHandle)
    }

    fn entry_of(&self, handle: FileHandle) -> Result<(usize, Option<usize>), KernelError> {
        let file = self.file(handle)?;
        let volume = &self.volumes[file.volume];
        match &file.path {
            None => Ok((file.volume, None)),
            Some(path) => volume
                .find(path)
                .map(|index| (file.volume, Some(index)))
                .ok_or(KernelError::InvalidHandle),
        }
    }

    fn insert_handle(&mut self, file: OpenFile) -> FileHandle {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(handle, file);
        FileHandle(handle)
    }

    /// Bytes of a file by object name.
    pub fn read(&self, path: &(impl AsRef<[u8]> + ?Sized)) -> Option<&[u8]> {
        let (volume, path) = self.resolve(path.as_ref()).ok()?;
        let index = self.volumes[volume].find(&path?)?;
        let entry = &self.volumes[volume].entries[index];
        (!entry.directory).then_some(entry.data.as_slice())
    }

    /// A file or directory by object name, for tests.
    pub fn entry(&self, path: &str) -> Option<&Entry> {
        let (volume, path) = self.resolve(path.as_bytes()).ok()?;
        let index = self.volumes[volume].find(&path?)?;
        Some(&self.volumes[volume].entries[index])
    }

    /// Create or replace a file and its missing parent directories.
    pub fn write(&mut self, path: &str, data: &[u8]) {
        let (volume, Some(path)) = self.resolve(path.as_bytes()).expect("path on a volume") else {
            panic!("the volume root is not a file");
        };
        let volume = &mut self.volumes[volume];
        for (index, &byte) in path.iter().enumerate().skip(1) {
            if byte == b'\\' && volume.find(&path[..index]).is_none() {
                volume.entries.push(Entry::directory(&path[..index]));
            }
        }
        match volume.find(&path) {
            Some(index) => volume.entries[index].data = data.to_vec(),
            None => volume.entries.push(Entry {
                path,
                directory: false,
                data: data.to_vec(),
                attributes: FileAttributes::empty(),
                creation_time: FileTime(0),
                last_access_time: FileTime(0),
                last_write_time: FileTime(0),
                change_time: FileTime(0),
            }),
        }
    }

    /// Set the attributes of a file or directory, for tests.
    pub fn set_attributes(&mut self, path: &str, attributes: FileAttributes) {
        let (volume, Some(path)) = self.resolve(path.as_bytes()).expect("path on a volume") else {
            panic!("the volume root has fixed attributes");
        };
        let index = self.volumes[volume].find(&path).expect("existing entry");
        self.volumes[volume].entries[index].attributes = attributes;
    }

    /// Open handles, for leak checks in tests.
    pub fn open_handles(&self) -> usize {
        self.handles.len()
    }

    /// Allocated pool blocks, for leak checks in tests.
    pub fn pool_blocks(&self) -> usize {
        self.pools.len()
    }

    /// Append one optical drive request to the active trace, as the
    /// optical driver does.
    pub fn record_dvd_request(
        &mut self,
        time: u64,
        lba: u32,
        blocks: u32,
        elapsed: u32,
        valid: bool,
    ) {
        let Some((buffer, length)) = self.dvd_trace.as_mut() else {
            return;
        };
        let word = (blocks << 25) | ((lba & 0xff_ffff) << 1) | u32::from(valid);
        let start = *length as usize;
        let pool = self.pools.get_mut(&buffer.raw()).expect("trace buffer");
        pool[start..start + 8].copy_from_slice(&time.to_be_bytes());
        pool[start + 8..start + 12].copy_from_slice(&word.to_be_bytes());
        pool[start + 12..start + 16].copy_from_slice(&elapsed.to_be_bytes());
        *length += 16;
    }

    /// Whether replacing `old_size` bytes of a file with `new_size` bytes
    /// fits the volume, counted in clusters as the free space is reported.
    fn check_capacity(
        &self,
        volume: usize,
        new_size: u64,
        old_size: u64,
    ) -> Result<(), KernelError> {
        let volume = &self.volumes[volume];
        let units = volume
            .used_units()
            .checked_sub(old_size.div_ceil(CLUSTER))
            .and_then(|units| units.checked_add(new_size.div_ceil(CLUSTER)))
            .ok_or(KernelError::DiskFull)?;
        if units > volume.total_units {
            Err(KernelError::DiskFull)
        } else {
            Ok(())
        }
    }

    fn pool_slice(&mut self, range: PoolRange) -> &mut [u8] {
        let pool = self
            .pools
            .get_mut(&range.buffer.raw())
            .expect("allocated pool block");
        &mut pool[range.offset as usize..(range.offset + range.length) as usize]
    }
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .iter()
            .all(|&byte| byte >= 0x20 && !b"\"*/:<>?|".contains(&byte))
}

impl filesystem::Backend for MockBackend {
    fn create_file(
        &mut self,
        path: &[u8],
        request: &CreateRequest,
    ) -> Result<FileHandle, KernelError> {
        let now = FileTime(self.system_time());
        let (volume, path) = self.filesystem.resolve(path)?;
        let state = &mut self.filesystem;
        let Some(path) = path else {
            if request.options.contains(CreateOptions::NON_DIRECTORY_FILE) {
                return Err(KernelError::FileIsADirectory);
            }
            if request.disposition == CreateDisposition::Create {
                return Err(KernelError::ObjectNameCollision);
            }
            let file = OpenFile {
                volume,
                path: None,
                access: request.access,
                position: 0,
                delete_pending: false,
                cursor: 0,
            };
            return Ok(state.insert_handle(file));
        };
        let disk = &mut state.volumes[volume];
        let parent_path = parent(&path);
        // Paths match without regard to case; entries keep their stored spelling.
        let stored_parent = if parent_path.is_empty() {
            Vec::new()
        } else {
            match disk.find(parent_path) {
                Some(index) if disk.entries[index].directory => disk.entries[index].path.clone(),
                _ => return Err(KernelError::ObjectPathNotFound),
            }
        };
        if !valid_name(leaf(&path)) {
            return Err(KernelError::ObjectNameInvalid);
        }
        let writes = request.access.intersects(WRITE_ACCESS);
        let path = match disk.find(&path) {
            Some(index) => {
                let entry = &mut disk.entries[index];
                if request.disposition == CreateDisposition::Create {
                    return Err(KernelError::ObjectNameCollision);
                }
                if request.options.contains(CreateOptions::DIRECTORY_FILE) && !entry.directory {
                    return Err(KernelError::NotADirectory);
                }
                if request.options.contains(CreateOptions::NON_DIRECTORY_FILE) && entry.directory {
                    return Err(KernelError::FileIsADirectory);
                }
                if writes && entry.attributes.contains(FileAttributes::READONLY) {
                    return Err(KernelError::AccessDenied);
                }
                if matches!(
                    request.disposition,
                    CreateDisposition::Overwrite
                        | CreateDisposition::OverwriteIf
                        | CreateDisposition::Supersede
                ) {
                    if entry.directory {
                        return Err(KernelError::FileIsADirectory);
                    }
                    entry.data.clear();
                    entry.last_write_time = now;
                }
                entry.path.clone()
            }
            None => {
                if matches!(
                    request.disposition,
                    CreateDisposition::Open | CreateDisposition::Overwrite
                ) {
                    return Err(KernelError::ObjectNameNotFound);
                }
                let directory = request.options.contains(CreateOptions::DIRECTORY_FILE);
                let mut attributes = request.attributes.bits() & !FileAttributes::NORMAL.bits();
                if directory {
                    attributes |= FileAttributes::DIRECTORY.bits();
                }
                if let Some(size) = request.allocation_size {
                    let free = disk.total_units.saturating_sub(disk.used_units()) * CLUSTER;
                    if size > free {
                        return Err(KernelError::DiskFull);
                    }
                }
                let mut stored = stored_parent;
                stored.extend_from_slice(&path[parent_path.len()..]);
                disk.entries.push(Entry {
                    path: stored.clone(),
                    directory,
                    data: Vec::new(),
                    attributes: FileAttributes::from_bits_retain(attributes),
                    creation_time: now,
                    last_access_time: now,
                    last_write_time: now,
                    change_time: now,
                });
                stored
            }
        };
        let file = OpenFile {
            volume,
            path: Some(path),
            access: request.access,
            position: 0,
            delete_pending: request.options.contains(CreateOptions::DELETE_ON_CLOSE),
            cursor: 0,
        };
        Ok(state.insert_handle(file))
    }

    fn open_relative(
        &mut self,
        root: ObjectDirectory,
        name: &[u8],
        access: AccessMask,
        share: ShareAccess,
        options: CreateOptions,
    ) -> Result<FileHandle, KernelError> {
        if root.0 != 1 {
            return Err(KernelError::InvalidHandle);
        }
        let mut path = b"\\??\\".to_vec();
        path.extend_from_slice(name);
        self.create_file(&path, &CreateRequest::open(access, share, options))
    }

    fn close_file(&mut self, handle: FileHandle) {
        let Some(file) = self.filesystem.handles.remove(&handle.0) else {
            return;
        };
        if let (true, Some(path)) = (file.delete_pending, file.path) {
            let volume = &mut self.filesystem.volumes[file.volume];
            if let Some(index) = volume.find(&path) {
                volume.entries.remove(index);
            }
        }
    }

    fn count_file_change(&mut self) {
        self.filesystem.file_changes = self.filesystem.file_changes.wrapping_add(1);
    }

    fn read_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        target: ReadTarget<'_>,
    ) -> Result<u32, KernelError> {
        let (volume, index) = self.filesystem.entry_of(handle)?;
        let index = index.ok_or(KernelError::InvalidParameter)?;
        let file = self.filesystem.file(handle)?;
        if !file.access.intersects(READ_ACCESS) {
            return Err(KernelError::AccessDenied);
        }
        let position = offset.unwrap_or(file.position);
        let data = &self.filesystem.volumes[volume].entries[index].data;
        if position >= data.len() as u64 {
            return Err(KernelError::EndOfFile);
        }
        let start = position as usize;
        let count = target.len().min(data.len() - start);
        let bytes = data[start..start + count].to_vec();
        let output = match target {
            ReadTarget::Bytes(bytes) => bytes,
            ReadTarget::Pool(range) => self.filesystem.pool_slice(range),
        };
        output[..count].copy_from_slice(&bytes);
        if let Some(file) = self.filesystem.handles.get_mut(&handle.0) {
            file.position = position + count as u64;
        }
        Ok(count as u32)
    }

    fn write_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        data: FileData<'_>,
    ) -> Result<(), KernelError> {
        let now = FileTime(self.system_time());
        let (volume, index) = self.filesystem.entry_of(handle)?;
        let index = index.ok_or(KernelError::InvalidParameter)?;
        let file = self.filesystem.file(handle)?;
        if !file.access.intersects(WRITE_ACCESS) {
            return Err(KernelError::AccessDenied);
        }
        let position = offset.unwrap_or(file.position);
        let bytes = match data {
            FileData::Bytes(bytes) => bytes.to_vec(),
            FileData::Pool(range) => self.filesystem.pool_slice(range).to_vec(),
        };
        let old = self.filesystem.volumes[volume].entries[index].data.len() as u64;
        let end = position
            .checked_add(bytes.len() as u64)
            .ok_or(KernelError::DiskFull)?;
        if self.filesystem.write_limit.is_some_and(|limit| end > limit) {
            return Err(KernelError::DiskFull);
        }
        self.filesystem.check_capacity(volume, end.max(old), old)?;
        let entry = &mut self.filesystem.volumes[volume].entries[index];
        if end as usize > entry.data.len() {
            entry.data.resize(end as usize, 0);
        }
        entry.data[position as usize..end as usize].copy_from_slice(&bytes);
        entry.last_write_time = now;
        if let Some(file) = self.filesystem.handles.get_mut(&handle.0) {
            file.position = end;
        }
        Ok(())
    }

    fn set_delete_disposition(
        &mut self,
        handle: FileHandle,
        delete: bool,
    ) -> Result<(), KernelError> {
        let (volume, index) = self.filesystem.entry_of(handle)?;
        let Some(index) = index else {
            return Err(KernelError::CannotDelete);
        };
        let disk = &self.filesystem.volumes[volume];
        let entry = &disk.entries[index];
        if delete {
            if entry.attributes.contains(FileAttributes::READONLY) {
                return Err(KernelError::CannotDelete);
            }
            if entry.directory
                && disk
                    .entries
                    .iter()
                    .any(|other| parent(&other.path).eq_ignore_ascii_case(&entry.path))
            {
                return Err(KernelError::DirectoryNotEmpty);
            }
        }
        if let Some(file) = self.filesystem.handles.get_mut(&handle.0) {
            file.delete_pending = delete;
        }
        Ok(())
    }

    fn set_end_of_file(&mut self, handle: FileHandle, size: u64) -> Result<(), KernelError> {
        let (volume, index) = self.filesystem.entry_of(handle)?;
        let index = index.ok_or(KernelError::InvalidParameter)?;
        if self.filesystem.volumes[volume].entries[index].directory {
            return Err(KernelError::InvalidParameter);
        }
        let old = self.filesystem.volumes[volume].entries[index].data.len() as u64;
        self.filesystem.check_capacity(volume, size, old)?;
        self.filesystem.volumes[volume].entries[index]
            .data
            .resize(size as usize, 0);
        Ok(())
    }

    fn set_file_position(&mut self, handle: FileHandle, position: u64) -> Result<(), KernelError> {
        let file = self
            .filesystem
            .handles
            .get_mut(&handle.0)
            .ok_or(KernelError::InvalidHandle)?;
        file.position = position;
        Ok(())
    }

    fn set_basic_information(
        &mut self,
        handle: FileHandle,
        information: &BasicInformation,
    ) -> Result<(), KernelError> {
        let (volume, index) = self.filesystem.entry_of(handle)?;
        let index = index.ok_or(KernelError::AccessDenied)?;
        let entry = &mut self.filesystem.volumes[volume].entries[index];
        for (target, value) in [
            (&mut entry.creation_time, information.creation_time),
            (&mut entry.last_access_time, information.last_access_time),
            (&mut entry.last_write_time, information.last_write_time),
            (&mut entry.change_time, information.change_time),
        ] {
            if value.0 != 0 {
                *target = value;
            }
        }
        if information.attributes.bits() != 0 {
            let kept = entry.attributes.bits() & FileAttributes::DIRECTORY.bits();
            entry.attributes = FileAttributes::from_bits_retain(
                information.attributes.bits()
                    & !FileAttributes::NORMAL.bits()
                    & !FileAttributes::DIRECTORY.bits()
                    | kept,
            );
        }
        Ok(())
    }

    fn rename_file(
        &mut self,
        handle: FileHandle,
        target: &[u8],
        replace: bool,
    ) -> Result<(), KernelError> {
        let (volume, index) = self.filesystem.entry_of(handle)?;
        let index = index.ok_or(KernelError::AccessDenied)?;
        let (target_volume, target) = self.filesystem.resolve(target)?;
        if target_volume != volume {
            return Err(KernelError::NotSameDevice);
        }
        let target = target.ok_or(KernelError::AccessDenied)?;
        let disk = &mut self.filesystem.volumes[volume];
        let parent_path = parent(&target);
        if !parent_path.is_empty()
            && !disk
                .find(parent_path)
                .is_some_and(|parent| disk.entries[parent].directory)
        {
            return Err(KernelError::ObjectPathNotFound);
        }
        if !valid_name(leaf(&target)) {
            return Err(KernelError::ObjectNameInvalid);
        }
        let old = disk.entries[index].path.clone();
        // A directory cannot move below itself.
        if target.len() > old.len()
            && starts_with_ignore_case(&target, &old)
            && target[old.len()] == b'\\'
        {
            return Err(KernelError::InvalidParameter);
        }
        let mut index = index;
        if let Some(existing) = disk.find(&target).filter(|&existing| existing != index) {
            if !replace || disk.entries[existing].directory {
                return Err(KernelError::ObjectNameCollision);
            }
            disk.entries.remove(existing);
            if existing < index {
                index -= 1;
            }
        }
        for entry in &mut disk.entries {
            if entry.path.len() > old.len()
                && starts_with_ignore_case(&entry.path, &old)
                && entry.path[old.len()] == b'\\'
            {
                let mut path = target.clone();
                path.extend_from_slice(&entry.path[old.len()..]);
                entry.path = path;
            }
        }
        disk.entries[index].path.clone_from(&target);
        if let Some(file) = self.filesystem.handles.get_mut(&handle.0) {
            file.path = Some(target);
        }
        Ok(())
    }

    fn query_file_information(
        &mut self,
        handle: FileHandle,
    ) -> Result<FileInformation, KernelError> {
        let (volume, index) = self.filesystem.entry_of(handle)?;
        Ok(index.map_or_else(root_information, |index| {
            self.filesystem.volumes[volume].entries[index].information()
        }))
    }

    fn query_full_attributes(&mut self, path: &[u8]) -> Result<FileInformation, KernelError> {
        let (volume, path) = self.filesystem.resolve(path)?;
        let Some(path) = path else {
            return Ok(root_information());
        };
        let disk = &self.filesystem.volumes[volume];
        match disk.find(&path) {
            Some(index) => Ok(disk.entries[index].information()),
            None if parent(&path).is_empty() || disk.find(parent(&path)).is_some() => {
                Err(KernelError::ObjectNameNotFound)
            }
            None => Err(KernelError::ObjectPathNotFound),
        }
    }

    fn query_directory(
        &mut self,
        handle: FileHandle,
        restart: bool,
        name: &mut [u8],
    ) -> Result<DirectoryEntry, KernelError> {
        let (volume, index) = self.filesystem.entry_of(handle)?;
        let directory = match index {
            Some(index) if !self.filesystem.volumes[volume].entries[index].directory => {
                return Err(KernelError::InvalidParameter);
            }
            Some(index) => self.filesystem.volumes[volume].entries[index].path.clone(),
            None => Vec::new(),
        };
        let file = self
            .filesystem
            .handles
            .get_mut(&handle.0)
            .ok_or(KernelError::InvalidHandle)?;
        if restart {
            file.cursor = 0;
        }
        let entry = self.filesystem.volumes[volume]
            .entries
            .iter()
            .filter(|entry| parent(&entry.path).eq_ignore_ascii_case(&directory))
            .nth(file.cursor)
            .ok_or(KernelError::NoMoreFiles)?;
        let leaf = leaf(&entry.path);
        if leaf.len() > name.len() {
            return Err(KernelError::BufferOverflow);
        }
        file.cursor += 1;
        name[..leaf.len()].copy_from_slice(leaf);
        Ok(DirectoryEntry {
            information: entry.information(),
            name_length: leaf.len(),
        })
    }

    fn query_volume_size(&mut self, handle: FileHandle) -> Result<VolumeSize, KernelError> {
        let volume = &self.filesystem.volumes[self.filesystem.file(handle)?.volume];
        Ok(VolumeSize {
            total_units: volume.total_units,
            available_units: volume.total_units.saturating_sub(volume.used_units()),
            sectors_per_unit: (CLUSTER / 0x200) as u32,
            bytes_per_sector: 0x200,
        })
    }

    /// Every simulated volume is FATX.
    #[cfg(feature = "smb")]
    fn query_volume_attributes(
        &mut self,
        handle: FileHandle,
    ) -> Result<filesystem::VolumeAttributes, KernelError> {
        self.filesystem.file(handle)?;
        let mut name = [0; filesystem::FILE_SYSTEM_NAME_CAPACITY];
        name[..4].copy_from_slice(b"FATX");
        Ok(filesystem::VolumeAttributes {
            flags: FileSystemAttributes::CASE_PRESERVED_NAMES,
            maximum_component_length: MAX_NAME as u32,
            name,
            name_length: 4,
        })
    }

    fn translate_symbolic_link(
        &mut self,
        link: &[u8],
        target: &mut [u8],
    ) -> Result<usize, KernelError> {
        let name = link
            .strip_prefix(b"\\??\\")
            .ok_or(KernelError::ObjectNameNotFound)?;
        let (_, resolved) = self
            .filesystem
            .links
            .iter()
            .find(|(link, _)| link.eq_ignore_ascii_case(name))
            .ok_or(KernelError::ObjectNameNotFound)?;
        let count = resolved.len().min(target.len());
        target[..count].copy_from_slice(&resolved[..count]);
        Ok(count)
    }

    fn open_object_directory(&mut self, path: &[u8]) -> Result<ObjectDirectory, KernelError> {
        if path == b"\\??" {
            Ok(ObjectDirectory(1))
        } else {
            Err(KernelError::ObjectNameNotFound)
        }
    }

    fn query_object_directory(
        &mut self,
        directory: ObjectDirectory,
        restart: bool,
        context: &mut u32,
        name: &mut [u8],
    ) -> Result<usize, KernelError> {
        if directory.0 != 1 {
            return Err(KernelError::InvalidHandle);
        }
        if restart {
            *context = 0;
        }
        let (link, _) = self
            .filesystem
            .links
            .get(*context as usize)
            .ok_or(KernelError::NoMoreFiles)?;
        if link.len() > name.len() {
            return Err(KernelError::BufferOverflow);
        }
        name[..link.len()].copy_from_slice(link);
        *context += 1;
        Ok(link.len())
    }

    fn close_object_directory(&mut self, _directory: ObjectDirectory) {}

    fn reference_device(&mut self, name: &[u8]) -> Result<DeviceObject, KernelError> {
        self.filesystem
            .devices
            .iter()
            .position(|device| device.name.eq_ignore_ascii_case(name))
            // SAFETY: the host checks device indices against `devices`;
            // dereferencing does nothing.
            .map(|index| unsafe { DeviceObject::from_raw(index as u32) })
            .ok_or(KernelError::ObjectNameNotFound)
    }

    unsafe fn dereference_device(&mut self, _device: DeviceObject) {}

    fn transfer_device(
        &mut self,
        device: DeviceObject,
        direction: TransferDirection,
        offset: u64,
        buffer: PoolRange,
    ) -> Result<(), KernelError> {
        let device = device.raw() as usize;
        let size = self.filesystem.devices[device].bytes.len() as u64;
        let end = offset + u64::from(buffer.length);
        if end > size {
            return Err(KernelError::InvalidParameter);
        }
        let range = offset as usize..end as usize;
        match direction {
            TransferDirection::Read => {
                let bytes = self.filesystem.devices[device].bytes[range].to_vec();
                self.filesystem.pool_slice(buffer).copy_from_slice(&bytes);
            }
            TransferDirection::Write => {
                let bytes = self.filesystem.pool_slice(buffer).to_vec();
                self.filesystem.devices[device].bytes[range].copy_from_slice(&bytes);
            }
        }
        Ok(())
    }

    fn allocate_pool(&mut self, size: u32) -> Option<PoolBuffer> {
        // Larger requests stand in for exhausted pool memory.
        if self.filesystem.pool_exhausted || size > POOL_LIMIT {
            return None;
        }
        let id = self.filesystem.next_pool;
        self.filesystem.next_pool += 1;
        self.filesystem.pools.insert(id, vec![0; size as usize]);
        // SAFETY: the id names the new entry of `pools`, removed only by
        // `free_pool`, after which no copy is used (the trait contract).
        Some(unsafe { PoolBuffer::from_raw(id) })
    }

    unsafe fn free_pool(&mut self, buffer: PoolBuffer) {
        self.filesystem.pools.remove(&buffer.raw());
    }

    fn pool(&mut self, buffer: PoolBuffer) -> &mut [u8] {
        self.filesystem
            .pools
            .get_mut(&buffer.raw())
            .expect("allocated pool block")
    }

    fn allocate_scratch(&mut self, size: u32) -> Option<ScratchBlock> {
        if self.filesystem.pool_exhausted || size > POOL_LIMIT {
            return None;
        }
        let block = Box::into_raw(vec![0; size as usize].into_boxed_slice());
        // SAFETY: the box is referenced only by the token; `free_scratch`
        // rebuilds and frees it.
        Some(unsafe { ScratchBlock::from_raw(&mut *block) })
    }

    fn free_scratch(&mut self, block: ScratchBlock) {
        // SAFETY: a `ScratchBlock` of this backend holds a box that
        // `allocate_scratch` released; the token is consumed here.
        drop(unsafe { Box::from_raw(block.into_raw() as *mut [u8]) });
    }

    fn open_close_tray(&mut self, value: u32) {
        self.filesystem.tray.push(value);
    }

    fn format_partition(&mut self, device: &[u8], _cluster_size: u32) -> Result<(), KernelError> {
        let volume = self
            .filesystem
            .volumes
            .iter_mut()
            .find(|volume| volume.device.eq_ignore_ascii_case(device))
            .ok_or(KernelError::ObjectNameNotFound)?;
        volume.entries.clear();
        self.filesystem.formatted.push(device.to_vec());
        Ok(())
    }

    fn update_sequence(&mut self) -> u16 {
        self.filesystem.update_sequence
    }

    fn dos_error(&mut self, error: KernelError) -> Option<Win32Error> {
        let code = match error {
            KernelError::ObjectNameNotFound => 2,
            KernelError::ObjectPathNotFound => 3,
            KernelError::AccessDenied => 5,
            KernelError::InvalidHandle => 6,
            KernelError::CrcError => 23,
            KernelError::DiskFull => 112,
            KernelError::ObjectNameInvalid => 123,
            KernelError::ObjectNameCollision => 183,
            _ => 317,
        };
        Win32Error::new(code)
    }

    fn start_dvd_trace(&mut self) {
        if let Some((buffer, _)) = self.filesystem.dvd_trace.take() {
            // SAFETY: the trace held the only copy, taken out here.
            unsafe { self.free_pool(buffer) };
        }
        if let Some(buffer) = self.allocate_pool(DVD_TRACE_SIZE) {
            self.filesystem.dvd_trace = Some((buffer, 0));
        }
    }

    fn stop_dvd_trace(&mut self) -> Option<DvdTrace> {
        self.filesystem
            .dvd_trace
            .take()
            .map(|(buffer, length)| DvdTrace { buffer, length })
    }

    fn dvd_trace_active(&mut self) -> bool {
        self.filesystem.dvd_trace.is_some()
    }
}
