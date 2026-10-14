//! Bridges the async XBDM [`Client`] to a synchronous [`fuser::Filesystem`].
//!
//! `fuser` dispatches one request at a time from a single worker thread by
//! default, and XBDM itself forbids issuing a command while a `getfile`/
//! `sendfile` transfer is in flight (see [`xeedee::commands::file`]), so a
//! plain [`Mutex`] around the client is exactly the right amount of
//! serialization -- no actor/channel is needed.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;

use fuser::BsdFileFlags;
use fuser::Errno;
use fuser::FileAttr;
use fuser::FileHandle;
use fuser::FileType;
use fuser::Filesystem;
use fuser::FopenFlags;
use fuser::Generation;
use fuser::INodeNo;
use fuser::KernelConfig;
use fuser::LockOwner;
use fuser::OpenAccMode;
use fuser::OpenFlags;
use fuser::RenameFlags;
use fuser::ReplyAttr;
use fuser::ReplyCreate;
use fuser::ReplyData;
use fuser::ReplyDirectory;
use fuser::ReplyEmpty;
use fuser::ReplyEntry;
use fuser::ReplyOpen;
use fuser::ReplyStatfs;
use fuser::ReplyWrite;
use fuser::Request;
use fuser::TimeOrNow;
use fuser::WriteFlags;

use xeedee::Client;
use xeedee::Connected;
use xeedee::Error;
use xeedee::ErrorCode;
use xeedee::commands::Delete;
use xeedee::commands::DirList;
use xeedee::commands::DriveFreeSpace;
use xeedee::commands::DriveList;
use xeedee::commands::FileAttributes;
use xeedee::commands::FileEof;
use xeedee::commands::FileUploadKind;
use xeedee::commands::GetFileAttributes;
use xeedee::commands::GetFileRange;
use xeedee::commands::MakeDirectory;
use xeedee::commands::Rename;
use xeedee::transport::tokio::Target;
use xeedee::transport::tokio::TokioTransport;
use xeedee::transport::tokio::connect_target_timeout;

const TTL: Duration = Duration::ZERO;
const BLOCK_SIZE: u32 = 4096;

/// Maps FUSE inode numbers to XBDM path strings for the lifetime of one
/// mount session. Single-session, in-memory, no eviction: correctness only
/// requires that a path already seen keeps resolving to the same ino.
struct InoTable {
    paths: HashMap<u64, String>,
    inos: HashMap<String, u64>,
    next_ino: u64,
}

impl InoTable {
    fn new() -> Self {
        let mut paths = HashMap::new();
        paths.insert(INodeNo::ROOT.0, String::new());
        Self {
            paths,
            inos: HashMap::new(),
            next_ino: 2,
        }
    }

    fn path_of(&self, ino: u64) -> Option<&str> {
        self.paths.get(&ino).map(String::as_str)
    }

    /// Get-or-insert: returns the existing ino for `path` if seen before,
    /// otherwise mints the next one and records both directions.
    fn ino_for(&mut self, path: String) -> u64 {
        if let Some(&ino) = self.inos.get(&path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.inos.insert(path.clone(), ino);
        self.paths.insert(ino, path);
        ino
    }

    /// Re-key a moved path onto its existing ino. Used by `rename`; does
    /// not attempt to rewrite descendants of a renamed directory (a stale
    /// child path just self-heals via a fresh `lookup` returning `ENOENT`).
    fn rekey(&mut self, from: &str, to: &str) {
        if let Some(ino) = self.inos.remove(from) {
            self.paths.insert(ino, to.to_owned());
            self.inos.insert(to.to_owned(), ino);
        }
    }
}

/// Build a child XBDM path from a parent path and a FUSE entry name.
///
/// Root's children are drive letters, stored as `"DEVKIT:"` (no trailing
/// backslash -- XBDM follows NT path semantics, where `"DEVKIT:"` alone
/// means "current directory on that drive" (rejected; there is no such
/// concept in an XBDM session) and `"DEVKIT:\"` means the drive's absolute
/// root. Confirmed against real hardware: both `getfileattributes` and
/// `dirlist` reject the bare form. Everything below a drive root joins
/// with a single backslash, e.g. `"DEVKIT:\subdir\file.bin"`.
fn child_path(parent_path: &str, name: &str) -> String {
    if parent_path.is_empty() {
        format!("{name}:\\")
    } else if parent_path.ends_with('\\') {
        format!("{parent_path}{name}")
    } else {
        format!("{parent_path}\\{name}")
    }
}

/// The drive-root path (`"DEVKIT:\"`) that `DriveFreeSpace` expects, for
/// whichever drive `path` lives under.
fn drive_of(path: &str) -> Option<String> {
    path.split_once(':').map(|(drive, _)| format!("{drive}:\\"))
}

/// True for a path that is a bare drive root (`"DEVKIT:\"`) as opposed to a
/// real file/directory under one (`"DEVKIT:\subdir"`). `child_path` never
/// produces a bare `"DEVKIT:"` (no trailing backslash) form. Kept as a
/// fast local check so `getattr`/`lookup`/`setattr` can synthesize a
/// directory attr for drive roots without a round trip -- XBDM has no
/// real attributes for a drive itself anyway.
fn is_drive_root(path: &str) -> bool {
    path.ends_with(":\\")
}

fn os_str_to_str(name: &OsStr) -> Result<&str, Errno> {
    name.to_str().ok_or(Errno::EINVAL)
}

/// `FileAttr` for a path XBDM actually told us about.
fn make_attr(ino: u64, attrs: &FileAttributes, uid: u32, gid: u32) -> FileAttr {
    let mtime = attrs.change_time.into_system_time();
    FileAttr {
        ino: INodeNo(ino),
        size: attrs.size,
        blocks: attrs.size.div_ceil(512),
        atime: mtime,
        mtime,
        ctime: mtime,
        crtime: attrs.create_time.into_system_time(),
        kind: if attrs.is_directory {
            FileType::Directory
        } else {
            FileType::RegularFile
        },
        perm: if attrs.is_directory { 0o755 } else { 0o644 },
        nlink: 1,
        uid,
        gid,
        rdev: 0,
        blksize: BLOCK_SIZE,
        flags: 0,
    }
}

/// `FileAttr` for an entry we just created/synthesized locally (root, a
/// freshly-`mkdir`'d directory, a freshly-`create`'d empty file, or a
/// drive-letter fallback) -- XBDM gives us no attributes for these.
fn synth_attr(ino: u64, is_directory: bool, uid: u32, gid: u32) -> FileAttr {
    FileAttr {
        ino: INodeNo(ino),
        size: 0,
        blocks: 0,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind: if is_directory {
            FileType::Directory
        } else {
            FileType::RegularFile
        },
        perm: if is_directory { 0o755 } else { 0o644 },
        nlink: if is_directory { 2 } else { 1 },
        uid,
        gid,
        rdev: 0,
        blksize: BLOCK_SIZE,
        flags: 0,
    }
}

fn map_error(report: &rootcause::Report<Error>) -> Errno {
    match report.current_context() {
        Error::Remote { code, .. } => match code {
            ErrorCode::FileNotFound => Errno::ENOENT,
            ErrorCode::AccessDenied => Errno::EACCES,
            ErrorCode::FileAlreadyExists => Errno::EEXIST,
            ErrorCode::DirectoryNotEmpty => Errno::ENOTEMPTY,
            ErrorCode::InvalidFilename | ErrorCode::BadFileName => Errno::EINVAL,
            ErrorCode::NoRoomOnDevice => Errno::ENOSPC,
            _ => Errno::EIO,
        },
        _ => Errno::EIO,
    }
}

/// A single bad response (e.g. a ranged `getfile` whose advertised length
/// doesn't match what was requested) desyncs the TCP byte stream for every
/// command after it -- there's no way to resynchronize an XBDM connection
/// in place, only to redial. `Remote` errors are the server cleanly
/// rejecting a request and don't indicate stream corruption; everything
/// else (I/O, a closed connection, framing) does.
fn is_connection_error(report: &rootcause::Report<Error>) -> bool {
    !matches!(report.current_context(), Error::Remote { .. })
}

pub struct XbdmFs {
    target: Target,
    timeout: Duration,
    client: Mutex<Client<TokioTransport, Connected>>,
    rt: tokio::runtime::Runtime,
    inodes: Mutex<InoTable>,
    read_only: bool,
}

impl XbdmFs {
    pub fn new(
        target: Target,
        timeout: Duration,
        client: Client<TokioTransport, Connected>,
        rt: tokio::runtime::Runtime,
        read_only: bool,
    ) -> Self {
        Self {
            target,
            timeout,
            client: Mutex::new(client),
            rt,
            inodes: Mutex::new(InoTable::new()),
            read_only,
        }
    }

    /// Run one XBDM call to completion, serialized against the single
    /// connection this filesystem owns. `f` is boxed (rather than plain
    /// `-> impl Future`) because the future it returns borrows the `&mut
    /// Client` passed in, and that borrow's lifetime is only known at the
    /// call site -- a bare associated `Fut` type can't vary per-call the
    /// way a boxed trait object with an elided lifetime can.
    ///
    /// On a connection-level error, redials before returning so the
    /// *next* call has a chance to succeed instead of every subsequent
    /// filesystem operation failing for the rest of the mount's life.
    fn xbdm<F, R>(&self, f: F) -> Result<R, Errno>
    where
        F: for<'a> FnOnce(
            &'a mut Client<TokioTransport, Connected>,
        ) -> Pin<
            Box<dyn Future<Output = Result<R, rootcause::Report<Error>>> + 'a>,
        >,
    {
        let mut client = self.client.lock().unwrap();
        let result = self.rt.block_on(f(&mut client));
        if let Err(report) = &result
            && is_connection_error(report)
        {
            tracing::warn!(error = ?report, "XBDM connection looks broken, reconnecting");
            match self.rt.block_on(async {
                Client::new(connect_target_timeout(&self.target, self.timeout).await?)
                    .read_banner()
                    .await
            }) {
                Ok(fresh) => *client = fresh,
                Err(reconnect_err) => {
                    tracing::error!(error = ?reconnect_err, "reconnect failed");
                }
            }
        }
        result.map_err(|e| map_error(&e))
    }

    fn path_of(&self, ino: u64) -> Option<String> {
        self.inodes.lock().unwrap().path_of(ino).map(str::to_owned)
    }

    fn ino_for(&self, path: String) -> u64 {
        self.inodes.lock().unwrap().ino_for(path)
    }
}

impl Filesystem for XbdmFs {
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> std::io::Result<()> {
        Ok(())
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.path_of(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Ok(name_str) = os_str_to_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let path = child_path(&parent_path, name_str);

        if parent.0 == INodeNo::ROOT.0 {
            // A direct child of root is a drive letter. XBDM's
            // `GetFileAttributes` doesn't accept bare drive paths, so
            // validate membership against `DriveList` and synthesize a
            // directory attr directly instead of ever calling it.
            match self.xbdm(move |c| Box::pin(async move { c.run(DriveList).await })) {
                Ok(drives) if drives.iter().any(|d| d.eq_ignore_ascii_case(name_str)) => {
                    let ino = self.ino_for(path);
                    reply.entry(
                        &TTL,
                        &synth_attr(ino, true, req.uid(), req.gid()),
                        Generation(0),
                    );
                }
                Ok(_) => reply.error(Errno::ENOENT),
                Err(e) => reply.error(e),
            }
            return;
        }

        let stat_path = path.clone();
        match self.xbdm(move |c| {
            Box::pin(async move { c.run(GetFileAttributes { path: stat_path }).await })
        }) {
            Ok(attrs) => {
                let ino = self.ino_for(path);
                reply.entry(
                    &TTL,
                    &make_attr(ino, &attrs, req.uid(), req.gid()),
                    Generation(0),
                );
            }
            Err(e) => reply.error(e),
        }
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino.0 == INodeNo::ROOT.0 {
            reply.attr(&TTL, &synth_attr(ino.0, true, req.uid(), req.gid()));
            return;
        }
        let Some(path) = self.path_of(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if is_drive_root(&path) {
            reply.attr(&TTL, &synth_attr(ino.0, true, req.uid(), req.gid()));
            return;
        }
        match self.xbdm(move |c| Box::pin(async move { c.run(GetFileAttributes { path }).await })) {
            Ok(attrs) => reply.attr(&TTL, &make_attr(ino.0, &attrs, req.uid(), req.gid())),
            Err(e) => reply.error(e),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if ino.0 == INodeNo::ROOT.0 {
            reply.attr(&TTL, &synth_attr(ino.0, true, req.uid(), req.gid()));
            return;
        }
        let Some(path) = self.path_of(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if is_drive_root(&path) {
            reply.attr(&TTL, &synth_attr(ino.0, true, req.uid(), req.gid()));
            return;
        }
        if let Some(new_size) = size {
            if self.read_only {
                reply.error(Errno::EROFS);
                return;
            }
            let truncate_path = path.clone();
            let result = self.xbdm(move |c| {
                Box::pin(async move {
                    c.run(FileEof {
                        path: truncate_path,
                        size: new_size,
                        create_if_missing: false,
                    })
                    .await
                })
            });
            if let Err(e) = result {
                reply.error(e);
                return;
            }
        }
        // No other settable attribute exists on XBDM (no mode/atime/mtime
        // bits) -- re-fetch and reply with whatever's current.
        match self.xbdm(move |c| Box::pin(async move { c.run(GetFileAttributes { path }).await })) {
            Ok(attrs) => reply.attr(&TTL, &make_attr(ino.0, &attrs, req.uid(), req.gid())),
            Err(e) => reply.error(e),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let Some(parent_path) = self.path_of(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Ok(name_str) = os_str_to_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let path = child_path(&parent_path, name_str);
        let mk_path = path.clone();
        match self
            .xbdm(move |c| Box::pin(async move { c.run(MakeDirectory { path: mk_path }).await }))
        {
            Ok(()) => {
                let ino = self.ino_for(path);
                reply.entry(
                    &TTL,
                    &synth_attr(ino, true, req.uid(), req.gid()),
                    Generation(0),
                );
            }
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let Some(parent_path) = self.path_of(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Ok(name_str) = os_str_to_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let path = child_path(&parent_path, name_str);
        match self.xbdm(move |c| {
            Box::pin(async move {
                c.run(Delete {
                    path,
                    is_directory: false,
                })
                .await
            })
        }) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let Some(parent_path) = self.path_of(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Ok(name_str) = os_str_to_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let path = child_path(&parent_path, name_str);
        match self.xbdm(move |c| {
            Box::pin(async move {
                c.run(Delete {
                    path,
                    is_directory: true,
                })
                .await
            })
        }) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let Some(parent_path) = self.path_of(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(newparent_path) = self.path_of(newparent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Ok(name_str) = os_str_to_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let Ok(newname_str) = os_str_to_str(newname) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let from = child_path(&parent_path, name_str);
        let to = child_path(&newparent_path, newname_str);
        let (rename_from, rename_to) = (from.clone(), to.clone());
        match self.xbdm(move |c| {
            Box::pin(async move {
                c.run(Rename {
                    from: rename_from,
                    to: rename_to,
                })
                .await
            })
        }) {
            Ok(()) => {
                self.inodes.lock().unwrap().rekey(&from, &to);
                reply.ok();
            }
            Err(e) => reply.error(e),
        }
    }

    fn open(&self, _req: &Request, _ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let wants_write = matches!(
            flags.acc_mode(),
            OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR
        );
        if self.read_only && wants_write {
            reply.error(Errno::EACCES);
            return;
        }
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let Some(path) = self.path_of(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        // The kernel's requested `size` is a read-ahead/buffer-size hint,
        // not a promise the file actually has that many bytes left --
        // `get_file`'s ranged form requires the server's advertised length
        // to exactly equal what we ask for, so asking for more than
        // remains (very common: kernel buffers are typically far larger
        // than a small file) would hard-error mid-transfer and leave the
        // connection desynced. Clamp to the real remaining size first.
        let stat_path = path.clone();
        let total_size = match self.xbdm(move |c| {
            Box::pin(async move { c.run(GetFileAttributes { path: stat_path }).await })
        }) {
            Ok(attrs) => attrs.size,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        let remaining = total_size.saturating_sub(offset);
        if remaining == 0 {
            reply.data(&[]);
            return;
        }
        let clamped_size = remaining.min(size as u64);

        // `Client::get_file`/`send_file` bypass `Client::run`'s own
        // send/recv tracing (they hold the transport directly mid-stream),
        // so log here -- otherwise transfers are invisible in `--log debug`.
        tracing::debug!(
            path,
            offset,
            requested = size,
            sending = clamped_size,
            "fuse read -> getfile"
        );
        let trace_path = path.clone();
        let result = self.xbdm(move |c| {
            Box::pin(async move {
                c.get_file(
                    &path,
                    GetFileRange::Range {
                        offset,
                        size: clamped_size,
                    },
                )
                .await?
                .into_vec()
                .await
            })
        });
        match &result {
            Ok(bytes) => tracing::debug!(path = trace_path, len = bytes.len(), "getfile ok"),
            Err(e) => tracing::warn!(path = trace_path, error = ?e, "getfile failed"),
        }
        match result {
            Ok(bytes) => reply.data(&bytes),
            Err(e) => reply.error(e),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let Some(path) = self.path_of(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        // Copy the kernel-owned buffer so the boxed future captures only
        // owned data alongside the borrowed `Client` -- a borrowed slice
        // tied to this call's stack frame can't satisfy the higher-ranked
        // lifetime the `xbdm` bridge needs.
        let payload = data.to_vec();
        let len = payload.len() as u32;
        tracing::debug!(path, offset, len, "fuse write -> writefile");
        let trace_path = path.clone();
        let result = self.xbdm(move |c| {
            Box::pin(async move {
                c.send_file(
                    &path,
                    FileUploadKind::WriteAt {
                        offset,
                        size: payload.len() as u64,
                    },
                )
                .await?
                .send_all(&payload)
                .await
            })
        });
        if let Err(e) = &result {
            tracing::warn!(path = trace_path, error = ?e, "writefile failed");
        }
        match result {
            Ok(()) => reply.written(len),
            Err(e) => reply.error(e),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.path_of(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino.0, FileType::Directory, ".".to_owned()),
            (ino.0, FileType::Directory, "..".to_owned()),
        ];

        if ino.0 == INodeNo::ROOT.0 {
            match self.xbdm(move |c| Box::pin(async move { c.run(DriveList).await })) {
                Ok(drives) => {
                    for drive in drives {
                        let child = child_path(&path, &drive);
                        let child_ino = self.ino_for(child);
                        entries.push((child_ino, FileType::Directory, drive));
                    }
                }
                Err(e) => {
                    reply.error(e);
                    return;
                }
            }
        } else {
            let list_path = path.clone();
            match self
                .xbdm(move |c| Box::pin(async move { c.run(DirList { path: list_path }).await }))
            {
                Ok(dir_entries) => {
                    for entry in dir_entries {
                        let child = child_path(&path, &entry.name);
                        let child_ino = self.ino_for(child);
                        let kind = if entry.is_directory {
                            FileType::Directory
                        } else {
                            FileType::RegularFile
                        };
                        entries.push((child_ino, kind, entry.name));
                    }
                }
                Err(e) => {
                    reply.error(e);
                    return;
                }
            }
        }

        for (idx, (child_ino, kind, name)) in entries.into_iter().enumerate() {
            let next_offset = (idx + 1) as u64;
            if next_offset <= offset {
                continue;
            }
            if reply.add(INodeNo(child_ino), next_offset, kind, &name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        let path = if ino.0 == INodeNo::ROOT.0 {
            None
        } else {
            self.path_of(ino.0)
        };
        let drive = path.as_deref().and_then(drive_of);
        let Some(drive) = drive else {
            // Root, or a path we don't recognize: no aggregate free-space
            // concept across drives, report harmless placeholder stats.
            reply.statfs(0, 0, 0, 0, 0, BLOCK_SIZE, 255, BLOCK_SIZE);
            return;
        };
        match self.xbdm(move |c| Box::pin(async move { c.run(DriveFreeSpace { drive }).await })) {
            Ok(space) => {
                let block = u64::from(BLOCK_SIZE);
                reply.statfs(
                    space.total_bytes / block,
                    space.total_free_bytes / block,
                    space.free_to_caller_bytes / block,
                    0,
                    0,
                    BLOCK_SIZE,
                    255,
                    BLOCK_SIZE,
                );
            }
            Err(e) => reply.error(e),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if self.read_only {
            reply.error(Errno::EROFS);
            return;
        }
        let Some(parent_path) = self.path_of(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Ok(name_str) = os_str_to_str(name) else {
            reply.error(Errno::EINVAL);
            return;
        };
        let path = child_path(&parent_path, name_str);
        // `fileeof ... CREATE` does not actually create a missing file on
        // real hardware (confirmed: cp got ENOENT). `sendfile` does --
        // it's the same verb `file put` already uses to upload brand-new
        // files -- so use a zero-length upload instead.
        let create_path = path.clone();
        let trace_path = path.clone();
        let result = self.xbdm(move |c| {
            Box::pin(async move {
                c.send_file(&create_path, FileUploadKind::Create { size: 0 })
                    .await?
                    .finish()
                    .await
            })
        });
        if let Err(e) = &result {
            tracing::warn!(path = trace_path, error = ?e, "sendfile create failed");
        }
        match result {
            Ok(()) => {
                let ino = self.ino_for(path);
                reply.created(
                    &TTL,
                    &synth_attr(ino, false, req.uid(), req.gid()),
                    Generation(0),
                    FileHandle(0),
                    FopenFlags::empty(),
                );
            }
            Err(e) => reply.error(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_path_joins_root_as_drive_letter_with_trailing_backslash() {
        assert_eq!(child_path("", "DEVKIT"), "DEVKIT:\\");
    }

    #[test]
    fn child_path_joins_nested_entries_with_backslash() {
        assert_eq!(child_path("DEVKIT:\\", "subdir"), "DEVKIT:\\subdir");
        assert_eq!(
            child_path("DEVKIT:\\subdir", "file.bin"),
            "DEVKIT:\\subdir\\file.bin"
        );
    }

    #[test]
    fn is_drive_root_distinguishes_bare_drives_from_nested_paths() {
        assert!(is_drive_root("DEVKIT:\\"));
        assert!(!is_drive_root("DEVKIT:\\subdir"));
        assert!(!is_drive_root("DEVKIT:\\subdir\\file.bin"));
        assert!(!is_drive_root(""));
    }

    #[test]
    fn drive_of_extracts_drive_root_with_trailing_backslash() {
        assert_eq!(
            drive_of("DEVKIT:\\subdir\\file.bin"),
            Some("DEVKIT:\\".to_owned())
        );
        assert_eq!(drive_of("DEVKIT:\\"), Some("DEVKIT:\\".to_owned()));
        assert_eq!(drive_of(""), None);
    }

    #[test]
    fn ino_table_reuses_ino_for_repeated_path() {
        let mut table = InoTable::new();
        let a = table.ino_for("DEVKIT:".to_owned());
        let b = table.ino_for("DEVKIT:".to_owned());
        assert_eq!(a, b);
        assert_eq!(table.path_of(a), Some("DEVKIT:"));
    }

    #[test]
    fn ino_table_root_is_ino_one_with_empty_path() {
        let table = InoTable::new();
        assert_eq!(table.path_of(1), Some(""));
    }

    #[test]
    fn ino_table_rekey_moves_ino_to_new_path() {
        let mut table = InoTable::new();
        let ino = table.ino_for("DEVKIT:\\old.txt".to_owned());
        table.rekey("DEVKIT:\\old.txt", "DEVKIT:\\new.txt");
        assert_eq!(table.path_of(ino), Some("DEVKIT:\\new.txt"));
        assert_eq!(table.ino_for("DEVKIT:\\new.txt".to_owned()), ino);
    }

    #[test]
    fn map_error_covers_every_error_code() {
        for code in [
            ErrorCode::UndefinedError,
            ErrorCode::MaxConnectionsExceeded,
            ErrorCode::FileNotFound,
            ErrorCode::NoSuchModule,
            ErrorCode::MemoryNotMapped,
            ErrorCode::NoSuchThread,
            ErrorCode::ClockNotSet,
            ErrorCode::UnknownCommand,
            ErrorCode::NotStopped,
            ErrorCode::FileCannotBeOpened,
            ErrorCode::InvalidFilename,
            ErrorCode::FileAlreadyExists,
            ErrorCode::DirectoryNotEmpty,
            ErrorCode::BadFileName,
            ErrorCode::FileCannotBeCreated,
            ErrorCode::AccessDenied,
            ErrorCode::NoRoomOnDevice,
            ErrorCode::NotDebuggable,
            ErrorCode::TypeInvalid,
            ErrorCode::DataNotAvailable,
            ErrorCode::OtherError,
        ] {
            let report = rootcause::Report::new(Error::Remote {
                code,
                message: String::new(),
            });
            let _ = map_error(&report);
        }
    }

    #[test]
    fn make_attr_maps_directory_flag_to_kind_and_perm() {
        let attrs = FileAttributes {
            size: 42,
            create_time: xeedee::FileTime::from_raw(0),
            change_time: xeedee::FileTime::from_raw(0),
            is_directory: true,
        };
        let attr = make_attr(7, &attrs, 1000, 1000);
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(attr.size, 42);
    }
}
