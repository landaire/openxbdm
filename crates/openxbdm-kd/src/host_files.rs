//! Local files served to the kernel's host file requests.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::num::NonZeroU64;
use std::path::PathBuf;

use openxbdm_kd_core::NtStatus;
use openxbdm_kd_core::file_io::HostFileHandle;
use openxbdm_kd_core::file_io::HostFileSystem;
use openxbdm_kd_core::file_io::HostPath;
use openxbdm_kd_core::file_io::OpenRequest;
use openxbdm_kd_core::file_io::OpenedFile;

/// A console path, as the kernel requests it, served from a local file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMapping {
    pub console_path: String,
    pub local_path: PathBuf,
}

impl FileMapping {
    /// Compares case-insensitively. A path with an unpaired surrogate
    /// matches nothing.
    fn matches(&self, path: &HostPath<'_>) -> bool {
        let mut requested = path.chars();
        let mut mapped = self.console_path.chars();
        loop {
            match (requested.next(), mapped.next()) {
                (None, None) => return true,
                (Some(Ok(a)), Some(b)) if a.to_lowercase().eq(b.to_lowercase()) => {}
                _ => return false,
            }
        }
    }
}

struct OpenFile {
    file: File,
    /// The path as the kernel requested it.
    console_path: String,
    bytes_served: u64,
}

#[derive(Default)]
pub struct HostFiles {
    mappings: Vec<FileMapping>,
    open: HashMap<HostFileHandle, OpenFile>,
    last_handle: u64,
}

/// An open file, for reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedFile<'a> {
    pub console_path: &'a str,
    pub bytes_served: u64,
}

impl HostFiles {
    pub fn new(mappings: Vec<FileMapping>) -> Self {
        Self {
            mappings,
            ..Self::default()
        }
    }

    /// The mapping an open request for `path` uses.
    pub fn mapping(&self, path: &HostPath<'_>) -> Option<&FileMapping> {
        self.mappings.iter().find(|mapping| mapping.matches(path))
    }

    /// Details of an open handle, for reporting before it is closed.
    pub fn describe(&self, handle: HostFileHandle) -> Option<ServedFile<'_>> {
        let open = self.open.get(&handle)?;
        Some(ServedFile {
            console_path: &open.console_path,
            bytes_served: open.bytes_served,
        })
    }

    fn open_mapping(&mut self, mapping: usize, console_path: String) -> io::Result<OpenedFile> {
        let file = File::open(&self.mappings[mapping].local_path)?;
        let size = file.metadata()?.len();
        self.last_handle += 1;
        let Some(raw) = NonZeroU64::new(self.last_handle) else {
            unreachable!("incremented from zero or more")
        };
        let handle = HostFileHandle(raw);
        self.open.insert(
            handle,
            OpenFile {
                file,
                console_path,
                bytes_served: 0,
            },
        );
        Ok(OpenedFile { handle, size })
    }
}

fn read_at(file: &mut File, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
    file.seek(SeekFrom::Start(offset))?;
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

impl HostFileSystem for HostFiles {
    fn open(&mut self, request: &OpenRequest<'_>) -> Result<OpenedFile, NtStatus> {
        let mapping = self
            .mappings
            .iter()
            .position(|mapping| mapping.matches(&request.path))
            .ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;
        self.open_mapping(mapping, request.path.to_string()).map_err(|error| {
            tracing::warn!(%error, local = %self.mappings[mapping].local_path.display(), "host file open failed");
            // The kernel then opens the file from its own devices.
            NtStatus::OBJECT_NAME_NOT_FOUND
        })
    }

    fn read(
        &mut self,
        handle: HostFileHandle,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, NtStatus> {
        let open = self.open.get_mut(&handle).ok_or(NtStatus::INVALID_HANDLE)?;
        match read_at(&mut open.file, offset, buffer) {
            Ok(count) => {
                open.bytes_served += count as u64;
                Ok(count)
            }
            Err(error) => {
                tracing::warn!(%error, ?handle, offset, "host file read failed");
                Err(NtStatus::UNSUCCESSFUL)
            }
        }
    }

    fn close(&mut self, handle: HostFileHandle) -> Result<(), NtStatus> {
        self.open
            .remove(&handle)
            .map(drop)
            .ok_or(NtStatus::INVALID_HANDLE)
    }
}

#[cfg(test)]
mod tests {
    use openxbdm_kd_core::file_io::FileIoRequest;

    use super::*;

    fn open_request(path: &str) -> Vec<u8> {
        let mut payload = vec![0u8; 0x40];
        payload[..4].copy_from_slice(&0x3430u32.to_le_bytes());
        for unit in path.encode_utf16().chain([0]) {
            payload.extend_from_slice(&unit.to_le_bytes());
        }
        payload
    }

    #[test]
    fn mapping_match_ignores_case_and_requires_whole_path() {
        let mapping = FileMapping {
            console_path: r"host:\Device\Flash\xbdm.xex".to_owned(),
            local_path: PathBuf::new(),
        };
        let cases = [
            r"HOST:\DEVICE\FLASH\XBDM.XEX",
            r"host:\Device\Flash\xbdm.xex2",
            r"\Device\Flash\xbdm.xex",
        ];
        let results: Vec<bool> = cases
            .iter()
            .map(|path| {
                let payload = open_request(path);
                let Ok(FileIoRequest::Open(open)) = FileIoRequest::decode(&payload) else {
                    panic!("open request")
                };
                mapping.matches(&open.path)
            })
            .collect();
        assert_eq!(results, [true, false, false]);
    }
}
