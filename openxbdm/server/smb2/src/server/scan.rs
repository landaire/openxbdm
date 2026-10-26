//! Digests of directory contents, which find changes made outside the
//! server.

use crate::backend::Backend;
use crate::backend::FileHandle;
use crate::backend::OpenRequest;
use crate::backend::ShareId;
use crate::crypto::Sha256;
use crate::fs::AccessMask;
use crate::fs::CreateDisposition;
use crate::fs::CreateOptions;
use crate::fs::FileAttributes;
use crate::fs::FileTime;
use crate::fs::NAME_CAPACITY;
use crate::fs::ShareAccess;
use crate::path::SharePath;
use crate::server::tables::ContentDigest;
use crate::utf16::Utf16Le;
use crate::utf16::encode_units;

/// Directory levels below a tree watch that a scan visits.
const SCAN_DEPTH: usize = 4;
/// Directory handles a scan holds at once.
pub(super) const SCAN_HANDLES: usize = SCAN_DEPTH + 1;

/// Tag of a record a scan digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestRecord {
    Entry = 0,
    Failure = 1,
}

impl DigestRecord {
    const fn tag(self) -> [u8; 1] {
        [self as u8]
    }
}

/// A digest and scan time for a newly watched directory.
pub(super) fn baseline(
    backend: &mut dyn Backend,
    share: ShareId,
    path: &[u16],
    tree: bool,
    now: FileTime,
) -> (ContentDigest, FileTime) {
    (scan(backend, share, path, tree), now)
}

/// Digest of the contents of the directory `path` on `share`: names,
/// attributes, sizes, and last write times of its entries, and of the
/// directories below it up to [`SCAN_DEPTH`] levels for a tree watch. A
/// failure to read is part of the digest, so it differs from any listing.
#[inline(never)]
pub(super) fn scan(
    backend: &mut dyn Backend,
    share: ShareId,
    path: &[u16],
    tree: bool,
) -> ContentDigest {
    // Directory entries a scan reads at most; a tree with more is digested
    // up to this many entries in enumeration order.
    const SCAN_ENTRIES: u32 = 4096;
    // Bytes of the path buffer a tree scan builds subdirectory paths in.
    const SCAN_PATH: usize = 2 * 512;
    const SEPARATOR: u16 = b'\\' as u16;

    let mut hash = Sha256::new();
    let mut buffer = [0u8; SCAN_PATH];
    let Some(length) = encode_units(path.iter().copied(), &mut buffer) else {
        hash.update(&DigestRecord::Failure.tag());
        return finish(hash);
    };

    // One open directory per level; `lengths` holds the path length of
    // each level in `buffer`.
    let mut handles = [None; SCAN_HANDLES];
    let mut lengths = [0usize; SCAN_DEPTH + 1];
    let mut restart = [true; SCAN_DEPTH + 1];
    let mut depth = 0usize;
    let mut budget = SCAN_ENTRIES;
    let mut name = [0u16; NAME_CAPACITY];

    handles[0] = open_directory(backend, share, &buffer[..length]);
    if handles[0].is_none() {
        hash.update(&DigestRecord::Failure.tag());
    }
    lengths[0] = length;

    loop {
        let Some(handle) = handles[depth] else {
            if depth == 0 {
                break;
            }
            depth -= 1;
            continue;
        };

        let entry = if budget == 0 {
            Ok(None)
        } else {
            backend.read_directory(handle, restart[depth], &mut name)
        };
        restart[depth] = false;

        let entry = match entry {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                backend.close(handle);
                handles[depth] = None;
                continue;
            }
            Err(_) => {
                hash.update(&DigestRecord::Failure.tag());
                backend.close(handle);
                handles[depth] = None;
                continue;
            }
        };

        budget -= 1;
        let name = &name[..entry.name_length.min(NAME_CAPACITY)];
        hash.update(&DigestRecord::Entry.tag());
        hash.update(&(depth as u32).to_le_bytes());
        hash.update(&(name.len() as u32).to_le_bytes());
        for unit in name {
            hash.update(&unit.to_le_bytes());
        }
        let information = entry.information;
        hash.update(&information.attributes.0.to_le_bytes());
        hash.update(&information.end_of_file.to_le_bytes());
        hash.update(&information.last_write_time.0.to_le_bytes());

        let directory = information.attributes.contains(FileAttributes::DIRECTORY)
            && !matches!(name, [0x2e] | [0x2e, 0x2e]);
        if !tree || !directory || depth >= SCAN_DEPTH {
            continue;
        }

        let base = lengths[depth];
        let separator = usize::from(base > 0);
        let end = base + separator * 2 + name.len() * 2;
        if end > buffer.len() {
            continue;
        }

        if separator == 1 {
            buffer[base..base + 2].copy_from_slice(&SEPARATOR.to_le_bytes());
        }
        let _ = encode_units(name.iter().copied(), &mut buffer[base + separator * 2..end]);
        depth += 1;
        lengths[depth] = end;
        restart[depth] = true;
        handles[depth] = open_directory(backend, share, &buffer[..end]);
        if handles[depth].is_none() {
            hash.update(&DigestRecord::Failure.tag());
        }
    }

    finish(hash)
}

fn finish(hash: Sha256) -> ContentDigest {
    let digest = hash.finalize();
    let mut short = [0; 16];
    short.copy_from_slice(&digest[..16]);

    ContentDigest(short)
}

fn open_directory(backend: &mut dyn Backend, share: ShareId, path: &[u8]) -> Option<FileHandle> {
    let path = SharePath::parse(Utf16Le::new(path)?).ok()?;
    let request = OpenRequest {
        access: AccessMask::READ_DATA.union(AccessMask::SYNCHRONIZE),
        share_access: ShareAccess::ALL,
        disposition: CreateDisposition::Open,
        options: CreateOptions::DIRECTORY_FILE,
        attributes: FileAttributes::default(),
        allocation_size: None,
    };

    backend
        .open(share, path, &request)
        .ok()
        .map(|opened| opened.handle)
}
