//! In-memory backend with NT open semantics, a clock the tests set, and
//! counter-based random bytes.

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
use smb2_server::crypto::md4;
use smb2_server::fs::BasicInformation;
use smb2_server::fs::CreateAction;
use smb2_server::fs::CreateDisposition;
use smb2_server::fs::CreateOptions;
use smb2_server::fs::DirectoryEntry;
use smb2_server::fs::FileAttributes;
use smb2_server::fs::FileIndex;
use smb2_server::fs::FileInformation;
use smb2_server::fs::FileSystemAttributes;
use smb2_server::fs::FileSystemName;
use smb2_server::fs::FileTime;
use smb2_server::fs::FsError;
use smb2_server::fs::NAME_CAPACITY;
use smb2_server::fs::VolumeInformation;
use smb2_server::fs::VolumeSize;
use smb2_server::path::SharePath;
use smb2_server::status::NtStatus;
use smb2_server::utf16::Utf16Le;

pub const TIME: FileTime = FileTime(0x01d9_8f6d_1c2a_b000);
pub const COMPUTER_NAME: &[u8] = b"TESTSRV";
pub const USER: &str = "alice";
pub const PASSWORD: &str = "Secret1";
pub const DATA: ShareId = ShareId(1);
pub const PUBLIC: ShareId = ShareId(2);
const SHARES: [(&str, ShareId, bool); 2] = [("Data", DATA, true), ("Public", PUBLIC, false)];
const CLUSTER: u64 = 4096;
/// Largest file the backend holds.
const MAXIMUM_FILE: u64 = 1 << 24;
/// What the backend returns for a handle the server never opened.
const INVALID_HANDLE: FsError = FsError::from_status(NtStatus::InvalidHandle);

pub fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

struct Node {
    share: ShareId,
    /// Components separated by `\`; empty for the share root.
    path: String,
    directory: bool,
    data: Vec<u8>,
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    change_time: FileTime,
    attributes: FileAttributes,
    index: u64,
    delete_pending: bool,
    opens: usize,
}

impl Node {
    fn information(&self) -> FileInformation {
        let end_of_file = self.data.len() as u64;
        FileInformation {
            creation_time: self.creation_time,
            last_access_time: self.last_access_time,
            last_write_time: self.last_write_time,
            change_time: self.change_time,
            allocation_size: end_of_file.div_ceil(CLUSTER) * CLUSTER,
            end_of_file,
            attributes: self.attributes,
            index: Some(FileIndex(self.index)),
        }
    }

    fn name(&self) -> &str {
        self.path.rsplit('\\').next().unwrap_or("")
    }
}

struct Handle {
    node: usize,
    delete_on_close: bool,
    /// Names and nodes of a directory scan, taken at its start.
    listing: Option<Vec<(String, usize)>>,
    cursor: usize,
}

pub struct MemoryBackend {
    nodes: Vec<Option<Node>>,
    handles: Vec<Option<Handle>>,
    pub guest: bool,
    pub anonymous: bool,
    random: u8,
    /// What `system_time` returns.
    pub time: FileTime,
    /// Handles in the order the server closed them.
    pub closed: Vec<FileHandle>,
}

fn parent_of(path: &str) -> &str {
    path.rsplit_once('\\').map_or("", |(parent, _)| parent)
}

fn path_string(path: SharePath<'_>) -> String {
    String::from_utf16(&path.as_utf16().units().collect::<Vec<_>>()).unwrap()
}

impl MemoryBackend {
    pub fn new() -> Self {
        let mut backend = Self {
            nodes: Vec::new(),
            handles: Vec::new(),
            guest: false,
            anonymous: false,
            random: 0,
            time: TIME,
            closed: Vec::new(),
        };
        for (_, share, _) in SHARES {
            backend.insert(share, "", true, Vec::new());
        }
        backend
    }

    fn insert(&mut self, share: ShareId, path: &str, directory: bool, data: Vec<u8>) -> usize {
        let index = self.nodes.len();
        self.nodes.push(Some(Node {
            share,
            path: path.to_owned(),
            directory,
            data,
            creation_time: TIME,
            last_access_time: TIME,
            last_write_time: TIME,
            change_time: TIME,
            attributes: if directory {
                FileAttributes::DIRECTORY
            } else {
                FileAttributes::ARCHIVE
            },
            index: 0x100 + index as u64,
            delete_pending: false,
            opens: 0,
        }));
        index
    }

    pub fn add_file(&mut self, share: ShareId, path: &str, data: &[u8]) {
        self.insert(share, path, false, data.to_vec());
    }

    pub fn add_directory(&mut self, share: ShareId, path: &str) {
        self.insert(share, path, true, Vec::new());
    }

    fn find(&self, share: ShareId, path: &str) -> Option<usize> {
        self.nodes.iter().position(|node| {
            node.as_ref()
                .is_some_and(|node| node.share == share && node.path.eq_ignore_ascii_case(path))
        })
    }

    /// Contents of the file at `path`, or `None` when it does not exist.
    pub fn contents(&self, share: ShareId, path: &str) -> Option<&[u8]> {
        self.find(share, path)
            .map(|index| self.node(index).data.as_slice())
    }

    /// Remove the file at `path` as another program would, without the
    /// server.
    pub fn remove(&mut self, share: ShareId, path: &str) {
        let index = self.find(share, path).expect("file to remove exists");
        self.nodes[index] = None;
    }

    /// Move `source` and the entries below it to `target`.
    fn move_node(&mut self, share: ShareId, source: &str, target: &str) {
        let prefix = format!("{source}\\");
        for node in self.nodes.iter_mut().flatten() {
            if node.share != share {
                continue;
            }
            if node.path.eq_ignore_ascii_case(source) {
                node.path = target.to_owned();
            } else if node.path.len() > prefix.len()
                && node.path[..prefix.len()].eq_ignore_ascii_case(&prefix)
            {
                node.path = format!("{target}\\{}", &node.path[prefix.len()..]);
            }
        }
    }

    pub fn open_handles(&self) -> usize {
        self.handles.iter().flatten().count()
    }

    fn node(&self, index: usize) -> &Node {
        self.nodes[index].as_ref().expect("node exists")
    }

    fn node_mut(&mut self, index: usize) -> &mut Node {
        self.nodes[index].as_mut().expect("node exists")
    }

    fn handle(&mut self, handle: FileHandle) -> Result<&mut Handle, FsError> {
        self.handles
            .get_mut(handle.0 as usize)
            .and_then(Option::as_mut)
            .ok_or(INVALID_HANDLE)
    }

    fn handle_node(&mut self, handle: FileHandle) -> Result<usize, FsError> {
        Ok(self.handle(handle)?.node)
    }

    fn file_node(&mut self, handle: FileHandle) -> Result<&mut Node, FsError> {
        let index = self.handle_node(handle)?;
        let node = self.node_mut(index);
        if node.directory {
            return Err(FsError::IsADirectory);
        }
        Ok(node)
    }

    fn children(&self, directory: usize) -> Vec<(String, usize)> {
        let parent = self.node(directory);
        let mut children: Vec<(String, usize)> = self
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(index, node)| node.as_ref().map(|node| (index, node)))
            .filter(|(_, node)| {
                node.share == parent.share
                    && !node.path.is_empty()
                    && parent_of(&node.path).eq_ignore_ascii_case(&parent.path)
            })
            .map(|(index, node)| (node.name().to_owned(), index))
            .collect();
        children.sort();
        children
    }
}

impl Platform for MemoryBackend {
    fn system_time(&mut self) -> FileTime {
        self.time
    }

    fn random_bytes(&mut self, output: &mut [u8]) {
        for byte in output {
            self.random = self.random.wrapping_add(1);
            *byte = self.random;
        }
    }

    fn computer_name(&mut self, output: &mut [u8; COMPUTER_NAME_CAPACITY]) -> usize {
        output[..COMPUTER_NAME.len()].copy_from_slice(COMPUTER_NAME);
        COMPUTER_NAME.len()
    }
}

impl Accounts for MemoryBackend {
    fn password(&mut self, user: Utf16Le<'_>, _domain: Utf16Le<'_>) -> Option<NtOwf> {
        user.eq_ignore_ascii_case(USER.as_bytes())
            .then(|| NtOwf(md4(&utf16(PASSWORD))))
    }

    fn allow_guest(&mut self) -> bool {
        self.guest
    }

    fn allow_anonymous(&mut self) -> bool {
        self.anonymous
    }
}

impl Shares for MemoryBackend {
    fn find_share(&mut self, name: Utf16Le<'_>, _kind: UserKind) -> Option<Share> {
        SHARES
            .iter()
            .find(|(share, _, _)| name.eq_ignore_ascii_case(share.as_bytes()))
            .map(|&(_, id, writable)| Share { id, writable })
    }

    fn share_name(
        &mut self,
        index: ShareIndex,
        _kind: UserKind,
        name: &mut [u16; SHARE_NAME_CAPACITY],
    ) -> Option<usize> {
        let (share, _, _) = SHARES.get(index.0 as usize)?;
        let mut length = 0;
        for (unit, value) in name.iter_mut().zip(share.encode_utf16()) {
            *unit = value;
            length += 1;
        }
        Some(length)
    }
}

impl FileSystem for MemoryBackend {
    fn open(
        &mut self,
        share: ShareId,
        path: SharePath<'_>,
        request: &OpenRequest,
    ) -> Result<Opened, FsError> {
        let path = path_string(path);
        let wants_directory = request.options.contains(CreateOptions::DIRECTORY_FILE);
        let (index, action) = match self.find(share, &path) {
            Some(index) => {
                let node = self.node_mut(index);
                if node.delete_pending {
                    return Err(FsError::DeletePending);
                }
                if wants_directory && !node.directory {
                    return Err(FsError::NotADirectory);
                }
                if request.options.contains(CreateOptions::NON_DIRECTORY_FILE) && node.directory {
                    return Err(FsError::IsADirectory);
                }
                let action = match request.disposition {
                    CreateDisposition::Create => return Err(FsError::NameCollision),
                    CreateDisposition::Open | CreateDisposition::OpenIf => CreateAction::Opened,
                    _ if node.directory => return Err(FsError::InvalidValue),
                    CreateDisposition::Supersede => CreateAction::Superseded,
                    CreateDisposition::Overwrite | CreateDisposition::OverwriteIf => {
                        CreateAction::Overwritten
                    }
                };
                if action != CreateAction::Opened {
                    node.data.clear();
                }
                (index, action)
            }
            None => {
                if !self
                    .find(share, parent_of(&path))
                    .is_some_and(|parent| self.node(parent).directory)
                {
                    return Err(FsError::PathNotFound);
                }
                if matches!(
                    request.disposition,
                    CreateDisposition::Open | CreateDisposition::Overwrite
                ) {
                    return Err(FsError::NotFound);
                }
                let index = self.insert(share, &path, wants_directory, Vec::new());
                if request.attributes.0 != 0 && !wants_directory {
                    self.node_mut(index).attributes = request.attributes;
                }
                (index, CreateAction::Created)
            }
        };
        self.node_mut(index).opens += 1;
        let handle = Handle {
            node: index,
            delete_on_close: request.options.contains(CreateOptions::DELETE_ON_CLOSE),
            listing: None,
            cursor: 0,
        };
        let slot = match self.handles.iter().position(Option::is_none) {
            Some(slot) => {
                self.handles[slot] = Some(handle);
                slot
            }
            None => {
                self.handles.push(Some(handle));
                self.handles.len() - 1
            }
        };
        Ok(Opened {
            handle: FileHandle(slot as u32),
            action,
            information: self.node(index).information(),
        })
    }

    fn close(&mut self, handle: FileHandle) {
        let closed = self.handles[handle.0 as usize]
            .take()
            .expect("server closes an open handle once");
        self.closed.push(handle);
        let node = self.node_mut(closed.node);
        node.opens -= 1;
        node.delete_pending |= closed.delete_on_close;
        if node.opens == 0 && node.delete_pending {
            self.nodes[closed.node] = None;
        }
    }

    fn read(
        &mut self,
        handle: FileHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, FsError> {
        let data = &self.file_node(handle)?.data;
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let count = (data.len() - start).min(output.len());
        output[..count].copy_from_slice(&data[start..start + count]);
        Ok(count)
    }

    fn write(&mut self, handle: FileHandle, offset: u64, data: &[u8]) -> Result<(), FsError> {
        let node = self.file_node(handle)?;
        let end = offset
            .checked_add(data.len() as u64)
            .filter(|&end| end <= MAXIMUM_FILE)
            .ok_or(FsError::DiskFull)? as usize;
        let start = offset as usize;
        if node.data.len() < end {
            node.data.resize(end, 0);
        }
        node.data[start..end].copy_from_slice(data);
        Ok(())
    }

    fn flush(&mut self, handle: FileHandle) -> Result<(), FsError> {
        self.handle(handle).map(|_| ())
    }

    fn information(&mut self, handle: FileHandle) -> Result<FileInformation, FsError> {
        let index = self.handle_node(handle)?;
        Ok(self.node(index).information())
    }

    fn set_basic_information(
        &mut self,
        handle: FileHandle,
        information: &BasicInformation,
    ) -> Result<(), FsError> {
        let index = self.handle_node(handle)?;
        let node = self.node_mut(index);
        let times = [
            (&mut node.creation_time, information.creation_time),
            (&mut node.last_access_time, information.last_access_time),
            (&mut node.last_write_time, information.last_write_time),
            (&mut node.change_time, information.change_time),
        ];
        for (time, value) in times {
            if let Some(value) = value {
                *time = value;
            }
        }
        if let Some(attributes) = information.attributes {
            node.attributes = attributes;
        }
        Ok(())
    }

    fn set_end_of_file(&mut self, handle: FileHandle, size: u64) -> Result<(), FsError> {
        if size > MAXIMUM_FILE {
            return Err(FsError::DiskFull);
        }
        self.file_node(handle)?.data.resize(size as usize, 0);
        Ok(())
    }

    fn set_delete_pending(&mut self, handle: FileHandle, delete: bool) -> Result<(), FsError> {
        let index = self.handle_node(handle)?;
        if delete && self.node(index).directory && !self.children(index).is_empty() {
            return Err(FsError::DirectoryNotEmpty);
        }
        self.node_mut(index).delete_pending = delete;
        Ok(())
    }

    fn rename(
        &mut self,
        handle: FileHandle,
        target: SharePath<'_>,
        replace: bool,
    ) -> Result<(), FsError> {
        let index = self.handle_node(handle)?;
        let share = self.node(index).share;
        let target = path_string(target);
        if let Some(existing) = self
            .find(share, &target)
            .filter(|&existing| existing != index)
        {
            let existing_node = self.node(existing);
            if !replace {
                return Err(FsError::NameCollision);
            }
            if existing_node.directory || existing_node.opens != 0 {
                return Err(FsError::AccessDenied);
            }
            self.nodes[existing] = None;
        }
        if !self
            .find(share, parent_of(&target))
            .is_some_and(|parent| self.node(parent).directory)
        {
            return Err(FsError::PathNotFound);
        }
        let source = self.node(index).path.clone();
        self.move_node(share, &source, &target);
        Ok(())
    }

    fn read_directory(
        &mut self,
        handle: FileHandle,
        restart: bool,
        name: &mut [u16; NAME_CAPACITY],
    ) -> Result<Option<DirectoryEntry>, FsError> {
        let index = self.handle_node(handle)?;
        if !self.node(index).directory {
            return Err(FsError::NotADirectory);
        }
        if restart || self.handle(handle)?.listing.is_none() {
            let listing = self.children(index);
            let open = self.handle(handle)?;
            open.listing = Some(listing);
            open.cursor = 0;
        }
        let open = self.handle(handle)?;
        let listing = open.listing.as_ref().expect("listing taken above");
        let Some((entry_name, entry)) = listing.get(open.cursor).cloned() else {
            return Ok(None);
        };
        open.cursor += 1;
        let mut length = 0;
        for (unit, value) in name.iter_mut().zip(entry_name.encode_utf16()) {
            *unit = value;
            length += 1;
        }
        Ok(Some(DirectoryEntry {
            information: self.node(entry).information(),
            name_length: length,
        }))
    }

    fn volume_information(&mut self, _handle: FileHandle) -> Result<VolumeInformation, FsError> {
        Ok(VolumeInformation {
            size: VolumeSize {
                total_units: 0x0010_0000,
                available_units: 0x0004_0000,
                sectors_per_unit: 8,
                bytes_per_sector: 512,
            },
            serial_number: 0x1234_5678,
            creation_time: TIME,
            attributes: FileSystemAttributes::CASE_PRESERVED_NAMES
                .union(FileSystemAttributes::UNICODE_ON_DISK),
            maximum_component_length: 255,
            file_system_name: FileSystemName::new(b"NTFS")
                .expect("NTFS is a valid file system name"),
        })
    }
}
