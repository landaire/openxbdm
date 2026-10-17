//! Serve host directories over SMB 2 and 3 from one thread: every
//! connection shares one `Server`, and each is polled for completed
//! change notifications and locks after any request, and on a timer for
//! the scans that find changes made outside the server.
//!
//! ```text
//! serve_directory --listen 127.0.0.1:1445 --share data=/tmp/data \
//!     --user alice --password secret [--guest] [--anonymous] [--encrypt]
//! smbclient //127.0.0.1/data -p 1445 -U alice%secret
//! ```
//!
//! File names compare with case on the host. Volume sizes are not
//! available through std, so every share reports 1 TiB free of 2 TiB.

use std::collections::hash_map::RandomState;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::hash::BuildHasher;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use smb2_server::Connection;
use smb2_server::NtStatus;
use smb2_server::Reply;
use smb2_server::ServerConfig;
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
use smb2_server::fs::CreateOptions;
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
use smb2_server::server::Guid;
use smb2_server::server::Server;
use smb2_server::transport;
use smb2_server::utf16::Utf16Le;

const BUFFER_SIZE: usize = 0x10400;
/// How often watched directories are scanned for outside changes.
const SCAN_INTERVAL: Duration = Duration::from_secs(5);
/// How long the loop sleeps when no connection had input.
const IDLE: Duration = Duration::from_millis(10);
/// 100-nanosecond intervals from 1601 to 1970.
const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;

struct Options {
    listen: String,
    shares: Vec<(String, PathBuf)>,
    user: Option<Account>,
    guest: bool,
    anonymous: bool,
    encrypt: bool,
}

/// Name and password of the one account the server accepts.
struct Account {
    name: String,
    password: String,
}

enum Node {
    File {
        file: File,
        path: PathBuf,
    },
    Directory {
        path: PathBuf,
        listing: Option<Vec<(String, PathBuf)>>,
        cursor: usize,
    },
}

struct Handle {
    share: ShareId,
    node: Node,
    delete_pending: bool,
}

struct Host {
    shares: Vec<(String, PathBuf)>,
    user: Option<(String, NtOwf)>,
    guest: bool,
    anonymous: bool,
    handles: Vec<Option<Handle>>,
    random: RandomState,
    counter: u64,
}

impl Host {
    fn path(&self, share: ShareId, path: SharePath<'_>) -> Result<PathBuf, FsError> {
        let mut host = self.shares[share.0 as usize].1.clone();

        for component in path.components() {
            host.push(host_name(component)?);
        }

        Ok(host)
    }

    fn handle(&mut self, handle: FileHandle) -> Result<&mut Handle, FsError> {
        self.handles
            .get_mut(handle.0 as usize)
            .and_then(Option::as_mut)
            .ok_or(FsError::from_status(NtStatus::InvalidHandle))
    }

    fn node_path(&mut self, handle: FileHandle) -> Result<PathBuf, FsError> {
        Ok(match &self.handle(handle)?.node {
            Node::File { path, .. } | Node::Directory { path, .. } => path.clone(),
        })
    }
}

impl Platform for Host {
    fn system_time(&mut self) -> FileTime {
        filetime(Ok(SystemTime::now()))
    }

    fn random_bytes(&mut self, output: &mut [u8]) {
        for chunk in output.chunks_mut(8) {
            self.counter += 1;

            let value = self.random.hash_one(self.counter).to_le_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
    }

    fn computer_name(&mut self, output: &mut [u8; COMPUTER_NAME_CAPACITY]) -> usize {
        let name = b"SMB2SERVER";

        output[..name.len()].copy_from_slice(name);

        name.len()
    }
}

impl Accounts for Host {
    fn password(&mut self, user: Utf16Le<'_>, _domain: Utf16Le<'_>) -> Option<NtOwf> {
        let (name, hash) = self.user.as_ref()?;

        let user = String::from_utf16(&user.units().collect::<Vec<_>>()).ok()?;

        user.eq_ignore_ascii_case(name).then_some(*hash)
    }

    fn allow_guest(&mut self) -> bool {
        self.guest
    }

    fn allow_anonymous(&mut self) -> bool {
        self.anonymous
    }
}

impl Shares for Host {
    fn find_share(&mut self, name: Utf16Le<'_>, _kind: UserKind) -> Option<Share> {
        let name = host_name(name).ok()?;

        let index = self
            .shares
            .iter()
            .position(|(share, _)| share.eq_ignore_ascii_case(&name))?;

        Some(Share {
            id: ShareId(index as u32),
            writable: true,
        })
    }

    fn share_name(
        &mut self,
        index: ShareIndex,
        _kind: UserKind,
        name: &mut [u16; SHARE_NAME_CAPACITY],
    ) -> Option<usize> {
        let (share, _) = self.shares.get(index.0 as usize)?;

        let mut length = 0;

        for (unit, value) in name.iter_mut().zip(share.encode_utf16()) {
            *unit = value;
            length += 1;
        }

        Some(length)
    }
}

impl FileSystem for Host {
    fn open(
        &mut self,
        share: ShareId,
        path: SharePath<'_>,
        request: &OpenRequest,
    ) -> Result<Opened, FsError> {
        let host = self.path(share, path)?;

        let exists = fs::symlink_metadata(&host).ok();
        let is_directory = exists.as_ref().is_some_and(fs::Metadata::is_dir);
        let wants_directory = request.options.contains(CreateOptions::DIRECTORY_FILE);

        if exists.is_some() {
            if wants_directory && !is_directory {
                return Err(FsError::NotADirectory);
            }

            if request.options.contains(CreateOptions::NON_DIRECTORY_FILE) && is_directory {
                return Err(FsError::IsADirectory);
            }
        }

        let action = match (request.disposition, exists.is_some()) {
            (CreateDisposition::Open | CreateDisposition::Overwrite, false) => {
                return Err(FsError::NotFound);
            }
            (CreateDisposition::Create, true) => return Err(FsError::NameCollision),
            (CreateDisposition::Open | CreateDisposition::OpenIf, true) => CreateAction::Opened,
            (CreateDisposition::Overwrite | CreateDisposition::OverwriteIf, true) => {
                CreateAction::Overwritten
            }
            (CreateDisposition::Supersede, true) => CreateAction::Superseded,
            (_, false) => CreateAction::Created,
        };

        if action == CreateAction::Created {
            if !host.parent().is_some_and(std::path::Path::is_dir) {
                return Err(FsError::PathNotFound);
            }

            if wants_directory {
                fs::create_dir(&host).map_err(fs_error)?;
            }
        }

        let node = if is_directory || (action == CreateAction::Created && wants_directory) {
            Node::Directory {
                path: host.clone(),
                listing: None,
                cursor: 0,
            }
        } else {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(action == CreateAction::Created)
                .truncate(matches!(
                    action,
                    CreateAction::Overwritten | CreateAction::Superseded
                ))
                .open(&host)
                .or_else(|_| File::open(&host))
                .map_err(fs_error)?;
            Node::File {
                file,
                path: host.clone(),
            }
        };

        let information = information(&host)?;

        let index = self
            .handles
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.handles.push(None);
                self.handles.len() - 1
            });

        self.handles[index] = Some(Handle {
            node,
            share,
            delete_pending: request.options.contains(CreateOptions::DELETE_ON_CLOSE),
        });

        Ok(Opened {
            handle: FileHandle(index as u32),
            action,
            information,
        })
    }

    fn close(&mut self, handle: FileHandle) {
        let Some(Some(closed)) = self.handles.get_mut(handle.0 as usize).map(Option::take) else {
            return;
        };

        if closed.delete_pending {
            // Close has no way to report failure; the file stays behind.
            let _ = match closed.node {
                Node::File { path, .. } => fs::remove_file(path),
                Node::Directory { path, .. } => fs::remove_dir(path),
            };
        }
    }

    fn read(
        &mut self,
        handle: FileHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, FsError> {
        let Node::File { file, .. } = &mut self.handle(handle)?.node else {
            return Err(FsError::IsADirectory);
        };

        file.seek(SeekFrom::Start(offset)).map_err(fs_error)?;

        let mut total = 0;

        while total < output.len() {
            match file.read(&mut output[total..]).map_err(fs_error)? {
                0 => break,
                count => total += count,
            }
        }

        Ok(total)
    }

    fn write(&mut self, handle: FileHandle, offset: u64, data: &[u8]) -> Result<(), FsError> {
        let Node::File { file, .. } = &mut self.handle(handle)?.node else {
            return Err(FsError::IsADirectory);
        };

        file.seek(SeekFrom::Start(offset)).map_err(fs_error)?;

        file.write_all(data).map_err(fs_error)
    }

    fn flush(&mut self, handle: FileHandle) -> Result<(), FsError> {
        if let Node::File { file, .. } = &mut self.handle(handle)?.node {
            file.sync_data().map_err(fs_error)?;
        }

        Ok(())
    }

    fn information(&mut self, handle: FileHandle) -> Result<FileInformation, FsError> {
        let path = self.node_path(handle)?;

        information(&path)
    }

    fn set_basic_information(
        &mut self,
        handle: FileHandle,
        basic: &BasicInformation,
    ) -> Result<(), FsError> {
        let Node::File { file, .. } = &mut self.handle(handle)?.node else {
            return Ok(());
        };

        if let Some(time) = basic.last_write_time
            && time.0 >= UNIX_EPOCH_FILETIME
        {
            let nanos = (time.0 - UNIX_EPOCH_FILETIME) * 100;
            file.set_modified(UNIX_EPOCH + Duration::from_nanos(nanos))
                .map_err(fs_error)?;
        }

        Ok(())
    }

    fn set_end_of_file(&mut self, handle: FileHandle, size: u64) -> Result<(), FsError> {
        let Node::File { file, .. } = &mut self.handle(handle)?.node else {
            return Err(FsError::IsADirectory);
        };

        file.set_len(size).map_err(fs_error)
    }

    fn set_delete_pending(&mut self, handle: FileHandle, delete: bool) -> Result<(), FsError> {
        let handle = self.handle(handle)?;

        if delete
            && let Node::Directory { path, .. } = &handle.node
            && fs::read_dir(path).map_err(fs_error)?.next().is_some()
        {
            return Err(FsError::DirectoryNotEmpty);
        }

        handle.delete_pending = delete;

        Ok(())
    }

    fn rename(
        &mut self,
        handle: FileHandle,
        target: SharePath<'_>,
        replace: bool,
    ) -> Result<(), FsError> {
        let share = self.handle(handle)?.share;
        let destination = self.path(share, target)?;
        let source = self.node_path(handle)?;

        if !replace && fs::symlink_metadata(&destination).is_ok() {
            return Err(FsError::NameCollision);
        }

        fs::rename(&source, &destination).map_err(fs_error)?;

        match &mut self.handle(handle)?.node {
            Node::File { path, .. } | Node::Directory { path, .. } => *path = destination,
        }

        Ok(())
    }

    fn read_directory(
        &mut self,
        handle: FileHandle,
        restart: bool,
        name: &mut [u16; NAME_CAPACITY],
    ) -> Result<Option<DirectoryEntry>, FsError> {
        let Node::Directory {
            path,
            listing,
            cursor,
        } = &mut self.handle(handle)?.node
        else {
            return Err(FsError::NotADirectory);
        };

        if restart || listing.is_none() {
            let mut entries = Vec::new();
            for entry in fs::read_dir(&*path).map_err(fs_error)? {
                let entry = entry.map_err(fs_error)?;
                entries.push((
                    entry.file_name().to_string_lossy().into_owned(),
                    entry.path(),
                ));
            }

            *listing = Some(entries);
            *cursor = 0;
        }

        let Some((entry_name, entry_path)) =
            listing.as_ref().and_then(|entries| entries.get(*cursor))
        else {
            return Ok(None);
        };

        *cursor += 1;

        let mut length = 0;

        for (unit, value) in name.iter_mut().zip(entry_name.encode_utf16()) {
            *unit = value;
            length += 1;
        }

        Ok(Some(DirectoryEntry {
            information: information(entry_path)?,
            name_length: length,
        }))
    }

    fn volume_information(&mut self, _handle: FileHandle) -> Result<VolumeInformation, FsError> {
        Ok(VolumeInformation {
            size: VolumeSize {
                total_units: 1 << 29,
                available_units: 1 << 28,
                sectors_per_unit: 8,
                bytes_per_sector: 512,
            },
            serial_number: 0x1234_5678,
            creation_time: FileTime(0),
            attributes: FileSystemAttributes::CASE_PRESERVED_NAMES
                .union(FileSystemAttributes::UNICODE_ON_DISK),
            maximum_component_length: 255,
            file_system_name: FileSystemName::new(b"NTFS")
                .expect("NTFS is a valid file system name"),
        })
    }
}

/// One transport connection and the bytes received but not yet handled.
struct Client {
    stream: TcpStream,
    connection: Box<Connection>,
    received: Vec<u8>,
}

impl Client {
    fn new(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_nonblocking(true)?;

        Ok(Self {
            stream,
            connection: Box::new(Connection::new()),
            received: Vec::new(),
        })
    }

    /// Read what has arrived; returns whether anything did.
    fn receive(&mut self) -> Result<bool, End> {
        let mut buffer = [0; 0x4000];
        let mut any = false;

        loop {
            match self.stream.read(&mut buffer) {
                Ok(0) => return Err(End::Closed),
                Ok(count) => {
                    self.received.extend_from_slice(&buffer[..count]);
                    any = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(any),
                Err(error) if error.kind() == ErrorKind::Interrupted => {
                    // Retry the read.
                }
                Err(error) => return Err(End::Failed(error)),
            }
        }
    }

    /// Handle every complete message received.
    fn handle_messages(
        &mut self,
        server: &mut Server,
        host: &mut Host,
        request: &mut [u8],
        response: &mut [u8],
    ) -> Result<(), End> {
        loop {
            let Some(header) = self.received.first_chunk::<{ transport::HEADER_LENGTH }>() else {
                return Ok(());
            };

            let length = match transport::parse_header(*header, request.len()) {
                Ok(transport::Frame::Message { length }) => length,
                Ok(transport::Frame::KeepAlive) => {
                    self.received.drain(..transport::HEADER_LENGTH);
                    continue;
                }
                Err(error) => return Err(End::Failed(std::io::Error::other(error))),
            };

            let end = transport::HEADER_LENGTH + length;

            if self.received.len() < end {
                return Ok(());
            }

            request[..length].copy_from_slice(&self.received[transport::HEADER_LENGTH..end]);
            self.received.drain(..end);

            let reply = self
                .connection
                .handle(server, host, &mut request[..length], response);

            self.send(reply, response)?;
        }
    }

    fn poll(
        &mut self,
        server: &mut Server,
        host: &mut Host,
        response: &mut [u8],
    ) -> Result<(), End> {
        let reply = self.connection.poll(server, host, response);

        self.send(reply, response)
    }

    fn send(&mut self, reply: Reply, response: &[u8]) -> Result<(), End> {
        match reply {
            Reply::Send { length } => {
                // Replies are written whole before the next request is read.
                self.stream.set_nonblocking(false).map_err(End::Failed)?;
                self.stream
                    .write_all(&response[..length])
                    .map_err(End::Failed)?;
                self.stream.set_nonblocking(true).map_err(End::Failed)
            }
            Reply::Nothing => Ok(()),
            Reply::Disconnect => Err(End::Closed),
        }
    }
}

/// Why a connection ends.
enum End {
    /// The peer closed it, or the server asked to.
    Closed,
    Failed(std::io::Error),
}

fn parse_options() -> Result<Options, String> {
    let mut options = Options {
        listen: "127.0.0.1:1445".into(),
        shares: Vec::new(),
        user: None,
        guest: false,
        anonymous: false,
        encrypt: false,
    };

    let mut user = None;
    let mut password = None;
    let mut arguments = std::env::args().skip(1);

    while let Some(argument) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or(format!("{argument} requires a value"))
        };
        match argument.as_str() {
            "--listen" => options.listen = value()?,
            "--share" => {
                let share = value()?;
                let (name, path) = share.split_once('=').ok_or("--share takes NAME=PATH")?;
                options.shares.push((name.into(), path.into()));
            }
            "--user" => user = Some(value()?),
            "--password" => password = Some(value()?),
            "--guest" => options.guest = true,
            "--anonymous" => options.anonymous = true,
            "--encrypt" => options.encrypt = true,
            _ => return Err(format!("unknown argument {argument}")),
        }
    }

    options.user = match (user, password) {
        (Some(name), Some(password)) => Some(Account { name, password }),
        (None, None) => None,
        _ => return Err("--user and --password go together".into()),
    };

    if options.shares.is_empty() {
        return Err("at least one --share is required".into());
    }

    Ok(options)
}

fn filetime(time: std::io::Result<SystemTime>) -> FileTime {
    let Ok(time) = time else { return FileTime(0) };

    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => FileTime(UNIX_EPOCH_FILETIME + duration.as_nanos() as u64 / 100),
        Err(_) => FileTime(0),
    }
}

fn information(path: &std::path::Path) -> Result<FileInformation, FsError> {
    let metadata = fs::metadata(path).map_err(fs_error)?;

    let attributes = if metadata.is_dir() {
        FileAttributes::DIRECTORY
    } else if metadata.permissions().readonly() {
        FileAttributes::READONLY
    } else {
        FileAttributes::ARCHIVE
    };

    let size = if metadata.is_dir() { 0 } else { metadata.len() };

    Ok(FileInformation {
        creation_time: filetime(metadata.created()),
        last_access_time: filetime(metadata.accessed()),
        last_write_time: filetime(metadata.modified()),
        change_time: filetime(metadata.modified()),
        allocation_size: size.div_ceil(4096) * 4096,
        end_of_file: size,
        attributes,
        index: None,
    })
}

fn fs_error(error: std::io::Error) -> FsError {
    match error.kind() {
        ErrorKind::NotFound => FsError::NotFound,
        ErrorKind::PermissionDenied => FsError::AccessDenied,
        ErrorKind::AlreadyExists => FsError::NameCollision,
        ErrorKind::DirectoryNotEmpty => FsError::DirectoryNotEmpty,
        ErrorKind::NotADirectory => FsError::NotADirectory,
        ErrorKind::IsADirectory => FsError::IsADirectory,
        ErrorKind::StorageFull => FsError::DiskFull,
        ErrorKind::CrossesDevices => FsError::NotSameDevice,
        ErrorKind::InvalidFilename => FsError::NameInvalid,
        _ => FsError::from_status(NtStatus::Unsuccessful),
    }
}

fn host_name(name: Utf16Le<'_>) -> Result<String, FsError> {
    char::decode_utf16(name.units())
        .collect::<Result<String, _>>()
        .map_err(|_| FsError::NameInvalid)
}

/// Serve connections until accepting one fails; returns that error.
fn serve(listener: &TcpListener, server: &mut Server, host: &mut Host) -> std::io::Error {
    if let Err(error) = listener.set_nonblocking(true) {
        return error;
    }

    let mut clients: Vec<Client> = Vec::new();
    let mut request = vec![0u8; BUFFER_SIZE];
    let mut response = vec![0u8; BUFFER_SIZE];
    let mut next_scan = Instant::now() + SCAN_INTERVAL;

    loop {
        loop {
            match listener.accept() {
                Ok((stream, _)) => match Client::new(stream) {
                    Ok(client) => clients.push(client),
                    Err(error) => eprintln!("connection refused: {error}"),
                },
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return error,
            }
        }

        let mut active = false;
        let mut ended: Vec<Option<End>> = clients.iter().map(|_| None).collect();

        for (index, client) in clients.iter_mut().enumerate() {
            let result = client.receive().and_then(|received| {
                active |= received;
                client.handle_messages(server, host, &mut request, &mut response)
            });
            if let Err(end) = result {
                ended[index] = Some(end);
            }
        }

        // A logon may name a session of another connection as its
        // previous one; that session ends.
        while let Some(superseded) = server.take_superseded() {
            for client in &mut clients {
                client.connection.end_session(server, host, superseded);
            }
        }

        // A request on one connection may complete requests waiting on
        // another; a due scan looks at every watched directory.
        let scan = Instant::now() >= next_scan;
        if scan {
            next_scan = Instant::now() + SCAN_INTERVAL;
        }

        for (index, client) in clients.iter_mut().enumerate() {
            if ended[index].is_none()
                && (scan || client.connection.wants_poll(server))
                && let Err(end) = client.poll(server, host, &mut response)
            {
                ended[index] = Some(end);
            }
        }

        for index in (0..clients.len()).rev() {
            let Some(end) = ended[index].take() else {
                continue;
            };

            let mut client = clients.swap_remove(index);
            client.connection.close(server, host);

            if let End::Failed(error) = end {
                eprintln!("connection ended: {error}");
            }
        }

        if !active {
            std::thread::sleep(IDLE);
        }
    }
}

fn main() -> std::process::ExitCode {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("serve_directory: {message}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let user = options.user.map(|Account { name, password }| {
        let mut encoded = Vec::new();
        for unit in password.encode_utf16() {
            encoded.extend_from_slice(&unit.to_le_bytes());
        }
        (name, NtOwf(smb2_server::crypto::md4(&encoded)))
    });

    let mut host = Host {
        shares: options.shares,
        user,
        guest: options.guest,
        anonymous: options.anonymous,
        handles: Vec::new(),
        random: RandomState::new(),
        counter: 0,
    };

    let mut guid = [0; 16];
    host.random_bytes(&mut guid);
    let mut server = Box::new(Server::new());

    server.configure(ServerConfig {
        guid: Guid(guid),
        start_time: host.system_time(),
        signing_required: false,
        buffer_size: BUFFER_SIZE,
        change_scan_interval: Some(SCAN_INTERVAL),
        encrypt_data: options.encrypt,
    });

    let listen = &options.listen;
    let listener = match TcpListener::bind(listen) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("serve_directory: cannot listen on {listen}: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    println!("listening on {listen}");

    let error = serve(&listener, &mut server, &mut host);
    eprintln!("serve_directory: {error}");

    std::process::ExitCode::FAILURE
}
