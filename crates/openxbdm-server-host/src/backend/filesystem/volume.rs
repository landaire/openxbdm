//! Simulated FATX volumes and their entries.

use openxbdm_server::commands::filesystem::FileInformation;
use openxbdm_server::commands::filesystem::FileTime;
use xbox360_sys::xboxkrnl::FileAttributes;

/// Bytes of an allocation unit.
pub(super) const CLUSTER: u64 = 0x4000;
/// FATX names are at most 42 characters.
pub(super) const MAX_NAME: usize = 42;

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

impl Entry {
    pub(super) fn directory(path: &[u8]) -> Self {
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

    pub(super) fn information(&self) -> FileInformation {
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

/// A mounted FATX volume.
#[derive(Debug, Clone)]
pub struct Volume {
    pub device: Vec<u8>,
    pub entries: Vec<Entry>,
    pub total_units: u64,
}

impl Volume {
    pub(super) fn new(device: &str, total_units: u64) -> Self {
        Self {
            device: device.as_bytes().to_vec(),
            entries: Vec::new(),
            total_units,
        }
    }

    pub(super) fn used_units(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| entry.data.len().div_ceil(CLUSTER as usize) as u64)
            .sum()
    }

    pub(super) fn find(&self, path: &[u8]) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.path.eq_ignore_ascii_case(path))
    }
}

pub(super) fn root_information() -> FileInformation {
    FileInformation {
        attributes: FileAttributes::DIRECTORY,
        ..FileInformation::default()
    }
}

pub(super) fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .iter()
            .all(|&byte| byte >= 0x20 && !b"\"*/:<>?|".contains(&byte))
}
