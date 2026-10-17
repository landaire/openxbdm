//! SMB service over loopback sockets: the test drives the service's
//! readiness events and the simulated console's clock.
#![cfg(feature = "smb")]

use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::time::Duration;

use openxbdm_server::SocketId;
use openxbdm_server::commands::filesystem;
use openxbdm_server::commands::filesystem::Backend as _;
use openxbdm_server::commands::filesystem::DriveName;
use openxbdm_server::commands::filesystem::DriveTarget;
use openxbdm_server::network::Network;
use openxbdm_server::smb::SmbService;
use openxbdm_server::state::LockMode;
use openxbdm_server_host::Host;
use openxbdm_server_host::backend::filesystem::Volume;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::ShareAccess;

const SECOND: u64 = 10_000_000;
const HEADER: usize = 64;
const DEVKIT: &[u8] = b"\\Device\\Harddisk0\\Partition1\\DEVKIT";

const STATUS_SUCCESS: u32 = 0;
const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_NOTIFY_ENUM_DIR: u32 = 0x0000_010c;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xc000_0016;
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
const STATUS_LOGON_FAILURE: u32 = 0xc000_006d;
const STATUS_NETWORK_NAME_DELETED: u32 = 0xc000_00c9;

mod command {
    pub const NEGOTIATE: u16 = 0x00;
    pub const SESSION_SETUP: u16 = 0x01;
    pub const TREE_CONNECT: u16 = 0x03;
    pub const CREATE: u16 = 0x05;
    pub const WRITE: u16 = 0x09;
    pub const CHANGE_NOTIFY: u16 = 0x0f;
    pub const QUERY_INFO: u16 = 0x10;
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const READ_ATTRIBUTES: u32 = 0x80;
const LIST_DIRECTORY: u32 = 0x1;
const OPEN: u32 = 1;
const OPEN_IF: u32 = 3;
const DIRECTORY_FILE: u32 = 0x1;
const NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x1;
const FILE_ACTION_ADDED: u32 = 1;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A reply: SMB 2 header and body.
struct Reply(Vec<u8>);

impl Reply {
    fn status(&self) -> u32 {
        u32_at(&self.0, 8)
    }

    fn body(&self) -> &[u8] {
        &self.0[HEADER..]
    }

    /// The file identifier of a CREATE reply.
    fn file_id(&self) -> [u8; 16] {
        self.body()[64..80].try_into().unwrap()
    }
}

/// The NTLMSSP NEGOTIATE of a client that offers a null session.
fn ntlm_negotiate() -> Vec<u8> {
    let mut message = b"NTLMSSP\0".to_vec();
    message.extend(1u32.to_le_bytes());
    // UNICODE, NTLM, ANONYMOUS, EXTENDED_SESSIONSECURITY.
    message.extend(0x0008_0a01u32.to_le_bytes());
    message.extend([0; 16]);
    message
}

/// An NTLMSSP AUTHENTICATE of a null session: every field empty.
fn ntlm_anonymous() -> Vec<u8> {
    let mut message = b"NTLMSSP\0".to_vec();
    message.extend(3u32.to_le_bytes());
    for _ in 0..6 {
        message.extend(0u16.to_le_bytes());
        message.extend(0u16.to_le_bytes());
        message.extend(64u32.to_le_bytes());
    }
    message.extend(0x0008_0a01u32.to_le_bytes());
    message
}

/// A host, an SMB service, and the client end of its connections.
struct Bench {
    host: Host,
    service: SmbService<2>,
    listener: TcpListener,
}

/// A client connection and the server's socket for it.
struct Peer {
    stream: TcpStream,
    socket: SocketId,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
}

impl Bench {
    fn new() -> Self {
        let mut host = Host::default();
        let mut service = SmbService::new();
        service.start(&mut host.backend);
        Self {
            host,
            service,
            listener: TcpListener::bind("127.0.0.1:0").unwrap(),
        }
    }

    fn connect(&mut self) -> Peer {
        let stream = TcpStream::connect(self.listener.local_addr().unwrap()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (accepted, _) = self.listener.accept().unwrap();
        let socket = self.host.network.insert(accepted);
        let Host {
            server,
            backend,
            network,
        } = &mut self.host;
        self.service.accept(socket, &server.state, backend, network);
        Peer {
            stream,
            socket,
            message_id: 0,
            session_id: 0,
            tree_id: 0,
        }
    }

    fn readable(&mut self, peer: &Peer) {
        let Host {
            server,
            backend,
            network,
        } = &mut self.host;
        self.service
            .on_readable(peer.socket, &server.state, backend, network);
    }

    fn poll_timers(&mut self) {
        let Host {
            server,
            backend,
            network,
        } = &mut self.host;
        self.service.poll_timers(&server.state, backend, network);
    }

    fn advance_clock(&mut self, units: u64) {
        self.host.backend.system.clock_adjustment += units;
    }

    /// Bytes the server has not yet received from `peer`.
    fn unread(&mut self, peer: &Peer) -> usize {
        self.host.network.pending_input(peer.socket).unwrap()
    }

    /// Send one request and return its reply.
    fn call(&mut self, peer: &mut Peer, command: u16, body: &[u8]) -> Reply {
        let mut message = vec![0u8; HEADER];
        message[..4].copy_from_slice(b"\xfeSMB");
        put_u16(&mut message, 4, HEADER as u16);
        put_u16(&mut message, 12, command);
        put_u16(&mut message, 14, 8);
        put_u64(&mut message, 24, peer.message_id);
        put_u32(&mut message, 36, peer.tree_id);
        put_u64(&mut message, 40, peer.session_id);
        message.extend_from_slice(body);
        peer.message_id += 1;
        let mut frame = (message.len() as u32).to_be_bytes().to_vec();
        frame.extend(message);
        peer.stream.write_all(&frame).unwrap();
        while !peer.has_input() {
            self.readable(peer);
        }
        let mut header = [0u8; 4];
        peer.stream.read_exact(&mut header).unwrap();
        let mut reply = vec![0u8; u32::from_be_bytes(header) as usize];
        peer.stream.read_exact(&mut reply).unwrap();
        Reply(reply)
    }

    fn negotiate(&mut self, peer: &mut Peer) {
        let mut body = vec![0u8; 36];
        put_u16(&mut body, 0, 36);
        put_u16(&mut body, 2, 2);
        body.extend(0x0202u16.to_le_bytes());
        body.extend(0x0210u16.to_le_bytes());
        assert_eq!(
            self.call(peer, command::NEGOTIATE, &body).status(),
            STATUS_SUCCESS
        );
    }

    fn session_setup(&mut self, peer: &mut Peer, token: &[u8]) -> Reply {
        let mut body = vec![0u8; 24];
        put_u16(&mut body, 0, 25);
        put_u16(&mut body, 12, (HEADER + 24) as u16);
        put_u16(&mut body, 14, token.len() as u16);
        body.extend_from_slice(token);
        let reply = self.call(peer, command::SESSION_SETUP, &body);
        peer.session_id = u64_at(&reply.0, 40);
        reply
    }

    /// Negotiate and log on with a null session; returns the final status.
    fn log_on(&mut self, peer: &mut Peer) -> u32 {
        self.negotiate(peer);
        let challenge = self.session_setup(peer, &ntlm_negotiate());
        assert_eq!(challenge.status(), STATUS_MORE_PROCESSING_REQUIRED);
        self.session_setup(peer, &ntlm_anonymous()).status()
    }

    fn tree_connect(&mut self, peer: &mut Peer, share: &str) -> u32 {
        let path = utf16(&format!("\\\\console\\{share}"));
        let mut body = vec![0u8; 8];
        put_u16(&mut body, 0, 9);
        put_u16(&mut body, 4, (HEADER + 8) as u16);
        put_u16(&mut body, 6, path.len() as u16);
        body.extend(path);
        let reply = self.call(peer, command::TREE_CONNECT, &body);
        if reply.status() == STATUS_SUCCESS {
            peer.tree_id = u32_at(&reply.0, 36);
        }
        reply.status()
    }

    fn create(&mut self, peer: &mut Peer, name: &str, access: u32) -> Reply {
        self.create_with(peer, name, access, OPEN_IF, NON_DIRECTORY_FILE)
    }

    fn create_with(
        &mut self,
        peer: &mut Peer,
        name: &str,
        access: u32,
        disposition: u32,
        options: u32,
    ) -> Reply {
        let name = utf16(name);
        let mut body = vec![0u8; 56];
        put_u16(&mut body, 0, 57);
        put_u32(&mut body, 4, 2);
        put_u32(&mut body, 24, access);
        put_u32(&mut body, 32, 7);
        put_u32(&mut body, 36, disposition);
        put_u32(&mut body, 40, options);
        put_u16(&mut body, 44, (HEADER + 56) as u16);
        put_u16(&mut body, 46, name.len() as u16);
        body.extend(name);
        self.call(peer, command::CREATE, &body)
    }

    /// Watch the directory `directory` for name changes.
    fn change_notify(&mut self, peer: &mut Peer, directory: [u8; 16]) -> Reply {
        let mut body = vec![0u8; 32];
        put_u16(&mut body, 0, 32);
        put_u32(&mut body, 4, 0x400);
        body[8..24].copy_from_slice(&directory);
        put_u32(&mut body, 24, FILE_NOTIFY_CHANGE_FILE_NAME);
        self.call(peer, command::CHANGE_NOTIFY, &body)
    }

    fn write(&mut self, peer: &mut Peer, file: [u8; 16], data: &[u8]) -> u32 {
        let mut body = vec![0u8; 48];
        put_u16(&mut body, 0, 49);
        put_u16(&mut body, 2, (HEADER + 48) as u16);
        put_u32(&mut body, 4, data.len() as u32);
        body[16..32].copy_from_slice(&file);
        body.extend_from_slice(data);
        self.call(peer, command::WRITE, &body).status()
    }

    /// FileFsAttributeInformation of the volume holding `file`.
    fn file_system(&mut self, peer: &mut Peer, file: [u8; 16]) -> (u32, u32, String) {
        let mut body = vec![0u8; 40];
        put_u16(&mut body, 0, 41);
        body[2] = 2;
        body[3] = 5;
        put_u32(&mut body, 4, 0x100);
        body[24..40].copy_from_slice(&file);
        body.push(0);
        let reply = self.call(peer, command::QUERY_INFO, &body);
        assert_eq!(reply.status(), STATUS_SUCCESS);
        let offset = usize::from(u16_at(reply.body(), 2));
        let output = &reply.0[offset..];
        let length = u32_at(output, 8) as usize;
        let name: Vec<u16> = output[12..12 + length]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .collect();
        (
            u32_at(output, 0),
            u32_at(output, 4),
            String::from_utf16(&name).unwrap(),
        )
    }
}

impl Peer {
    /// Whether a reply is waiting.
    fn has_input(&mut self) -> bool {
        self.stream.set_nonblocking(true).unwrap();
        let mut byte = [0u8; 1];
        let waiting = matches!(self.stream.peek(&mut byte), Ok(1..));
        self.stream.set_nonblocking(false).unwrap();
        waiting
    }

    /// Read a message the server sent without a request.
    fn receive(&mut self) -> Reply {
        let mut header = [0u8; 4];
        self.stream.read_exact(&mut header).unwrap();
        let mut reply = vec![0u8; u32::from_be_bytes(header) as usize];
        self.stream.read_exact(&mut reply).unwrap();
        Reply(reply)
    }

    /// Whether the server closed the connection.
    fn closed(&mut self) -> bool {
        self.stream.set_nonblocking(true).unwrap();
        let mut byte = [0u8; 1];
        let closed = match self.stream.read(&mut byte) {
            Ok(0) => true,
            Ok(_) => false,
            Err(error) => error.kind() != ErrorKind::WouldBlock,
        };
        self.stream.set_nonblocking(false).unwrap();
        closed
    }
}

#[test]
fn keep_alives_end_a_readiness_event() {
    let mut bench = Bench::new();
    let mut peer = bench.connect();
    peer.stream.write_all(&[0x85, 0, 0, 0].repeat(3)).unwrap();
    while bench.unread(&peer) != 12 {
        std::thread::yield_now();
    }
    bench.readable(&peer);
    assert_eq!(bench.unread(&peer), 8);
    bench.readable(&peer);
    bench.readable(&peer);
    assert_eq!(bench.unread(&peer), 0);
    bench.negotiate(&mut peer);
}

#[test]
fn connections_without_a_logon_close_after_30_seconds() {
    let mut bench = Bench::new();
    let mut waiting = bench.connect();
    let mut logged_on = bench.connect();
    assert_eq!(bench.log_on(&mut logged_on), STATUS_SUCCESS);
    bench.advance_clock(29 * SECOND);
    bench.poll_timers();
    assert!(bench.service.contains(waiting.socket));
    bench.advance_clock(SECOND);
    bench.poll_timers();
    assert!(!bench.service.contains(waiting.socket));
    assert!(waiting.closed());
    assert!(bench.service.contains(logged_on.socket));
}

#[test]
fn stalled_messages_close_after_30_seconds() {
    let mut bench = Bench::new();
    let mut peer = bench.connect();
    assert_eq!(bench.log_on(&mut peer), STATUS_SUCCESS);
    // A header announcing 100 bytes, then nothing.
    peer.stream.write_all(&[0, 0, 0, 100, 0xfe]).unwrap();
    while bench.unread(&peer) != 5 {
        std::thread::yield_now();
    }
    bench.readable(&peer);
    bench.advance_clock(30 * SECOND);
    bench.poll_timers();
    assert!(peer.closed());
}

#[test]
fn idle_connections_close_after_15_minutes_without_open_files() {
    let mut bench = Bench::new();
    let mut idle = bench.connect();
    let mut working = bench.connect();
    assert_eq!(bench.log_on(&mut idle), STATUS_SUCCESS);
    assert_eq!(bench.log_on(&mut working), STATUS_SUCCESS);
    assert_eq!(bench.tree_connect(&mut working, "DEVKIT"), STATUS_SUCCESS);
    let open = bench.create(&mut working, "open.txt", GENERIC_READ);
    assert_eq!(open.status(), STATUS_SUCCESS);
    bench.advance_clock(15 * 60 * SECOND);
    bench.poll_timers();
    assert!(idle.closed());
    assert!(bench.service.contains(working.socket));
}

#[test]
fn a_full_table_evicts_the_oldest_connection_without_a_session() {
    let mut bench = Bench::new();
    let mut first = bench.connect();
    bench.advance_clock(SECOND);
    let mut second = bench.connect();
    let mut third = bench.connect();
    assert!(first.closed());
    assert!(bench.service.contains(second.socket));
    assert!(bench.service.contains(third.socket));
    assert_eq!(bench.log_on(&mut second), STATUS_SUCCESS);
    assert_eq!(bench.log_on(&mut third), STATUS_SUCCESS);
    let mut refused = bench.connect();
    assert!(refused.closed());
    assert!(!second.closed() && !third.closed());
}

#[test]
fn a_locked_console_refuses_opens_but_finishes_open_files() {
    let mut bench = Bench::new();
    let mut peer = bench.connect();
    assert_eq!(bench.log_on(&mut peer), STATUS_SUCCESS);
    assert_eq!(bench.tree_connect(&mut peer, "DEVKIT"), STATUS_SUCCESS);
    let open = bench.create(&mut peer, "kept.txt", GENERIC_WRITE);
    assert_eq!(open.status(), STATUS_SUCCESS);
    bench.host.server.state.lock.mode = LockMode::Locked;
    assert_eq!(
        bench.create(&mut peer, "new.txt", GENERIC_WRITE).status(),
        STATUS_ACCESS_DENIED
    );
    assert_eq!(
        bench.write(&mut peer, open.file_id(), b"data"),
        STATUS_SUCCESS
    );
    let mut late = bench.connect();
    assert_eq!(bench.log_on(&mut late), STATUS_LOGON_FAILURE);
}

#[test]
fn optical_shares_are_read_only() {
    let mut bench = Bench::new();
    bench.host.backend.filesystem.volumes.push(Volume {
        device: b"\\Device\\Cdrom0".to_vec(),
        entries: Vec::new(),
        total_units: 0x100,
    });
    let mut peer = bench.connect();
    assert_eq!(bench.log_on(&mut peer), STATUS_SUCCESS);
    assert_eq!(bench.tree_connect(&mut peer, "DVD"), STATUS_SUCCESS);
    assert_eq!(
        bench.create(&mut peer, "disc.txt", GENERIC_WRITE).status(),
        STATUS_ACCESS_DENIED
    );
}

#[test]
fn volume_information_comes_from_the_volume() {
    let mut bench = Bench::new();
    let mut peer = bench.connect();
    assert_eq!(bench.log_on(&mut peer), STATUS_SUCCESS);
    assert_eq!(bench.tree_connect(&mut peer, "DEVKIT"), STATUS_SUCCESS);
    let open = bench.create(&mut peer, "file.txt", READ_ATTRIBUTES);
    assert_eq!(open.status(), STATUS_SUCCESS);
    assert_eq!(
        bench.file_system(&mut peer, open.file_id()),
        (0x2, 42, "FATX".to_owned())
    );
}

#[test]
fn a_remapped_drive_ends_its_tree_connects() {
    let mut bench = Bench::new();
    let drives = &mut bench.host.server.state.filesystem.drives;
    drives.map(
        DriveName::new(b"GAME"),
        Some(DriveTarget::Object(DEVKIT)),
        true,
    );
    let mut peer = bench.connect();
    assert_eq!(bench.log_on(&mut peer), STATUS_SUCCESS);
    assert_eq!(bench.tree_connect(&mut peer, "GAME"), STATUS_SUCCESS);
    assert_eq!(
        bench.create(&mut peer, "a.txt", GENERIC_WRITE).status(),
        STATUS_SUCCESS
    );
    bench.host.server.state.filesystem.drives.map(
        DriveName::new(b"GAME"),
        Some(DriveTarget::Object(b"\\Device\\Harddisk0\\Partition1")),
        true,
    );
    assert_eq!(
        bench.create(&mut peer, "a.txt", GENERIC_WRITE).status(),
        STATUS_NETWORK_NAME_DELETED
    );
}

#[test]
fn change_notifications_complete_when_the_service_polls() {
    let mut bench = Bench::new();
    let mut watcher = bench.connect();
    assert_eq!(bench.log_on(&mut watcher), STATUS_SUCCESS);
    assert_eq!(bench.tree_connect(&mut watcher, "DEVKIT"), STATUS_SUCCESS);
    let root = bench.create_with(&mut watcher, "", LIST_DIRECTORY, OPEN, DIRECTORY_FILE);
    assert_eq!(root.status(), STATUS_SUCCESS);
    assert_eq!(
        bench.change_notify(&mut watcher, root.file_id()).status(),
        STATUS_PENDING
    );

    // A file created over another connection completes the watch with its
    // name.
    let mut writer = bench.connect();
    assert_eq!(bench.log_on(&mut writer), STATUS_SUCCESS);
    assert_eq!(bench.tree_connect(&mut writer, "DEVKIT"), STATUS_SUCCESS);
    assert_eq!(
        bench
            .create(&mut writer, "added.txt", GENERIC_WRITE)
            .status(),
        STATUS_SUCCESS
    );
    assert!(!watcher.has_input());
    bench.poll_timers();
    let completed = watcher.receive();
    assert_eq!(completed.status(), STATUS_SUCCESS);
    let offset = usize::from(u16_at(completed.body(), 2));
    let record = &completed.0[offset..];
    assert_eq!(u32_at(record, 4), FILE_ACTION_ADDED);
    let length = u32_at(record, 8) as usize;
    assert_eq!(&record[12..12 + length], utf16("added.txt").as_slice());

    // A file created by XBDM is found by the next scan after the interval.
    assert_eq!(
        bench.change_notify(&mut watcher, root.file_id()).status(),
        STATUS_PENDING
    );
    let outside = filesystem::CreateRequest {
        disposition: CreateDisposition::Create,
        ..filesystem::CreateRequest::open(
            AccessMask::WRITE_DATA,
            ShareAccess::all(),
            CreateOptions::NON_DIRECTORY_FILE,
        )
    };
    let mut name = DEVKIT.to_vec();
    name.extend_from_slice(b"\\outside.txt");
    let handle = bench.host.backend.create_file(&name, &outside).unwrap();
    bench.host.backend.close_file(handle);
    bench.poll_timers();
    assert!(!watcher.has_input());
    bench.advance_clock(3 * SECOND);
    bench.poll_timers();
    assert_eq!(watcher.receive().status(), STATUS_NOTIFY_ENUM_DIR);
}

#[test]
fn connections_agree_on_share_identifiers() {
    let mut bench = Bench::new();
    let mut watcher = bench.connect();
    assert_eq!(bench.log_on(&mut watcher), STATUS_SUCCESS);
    assert_eq!(bench.tree_connect(&mut watcher, "DEVKIT"), STATUS_SUCCESS);
    let root = bench.create_with(&mut watcher, "", LIST_DIRECTORY, OPEN, DIRECTORY_FILE);
    assert_eq!(root.status(), STATUS_SUCCESS);
    assert_eq!(
        bench.change_notify(&mut watcher, root.file_id()).status(),
        STATUS_PENDING
    );

    // The writer connects another share first, so a share identifier
    // numbered per connection would name HDD for it and DEVKIT for the
    // watcher.
    let mut writer = bench.connect();
    assert_eq!(bench.log_on(&mut writer), STATUS_SUCCESS);
    assert_eq!(bench.tree_connect(&mut writer, "HDD"), STATUS_SUCCESS);
    assert_eq!(
        bench
            .create(&mut writer, "other.txt", GENERIC_WRITE)
            .status(),
        STATUS_SUCCESS
    );
    bench.poll_timers();
    assert!(!watcher.has_input());

    assert_eq!(bench.tree_connect(&mut writer, "DEVKIT"), STATUS_SUCCESS);
    assert_eq!(
        bench
            .create(&mut writer, "watched.txt", GENERIC_WRITE)
            .status(),
        STATUS_SUCCESS
    );
    bench.poll_timers();
    let completed = watcher.receive();
    assert_eq!(completed.status(), STATUS_SUCCESS);
    let offset = usize::from(u16_at(completed.body(), 2));
    let record = &completed.0[offset..];
    let length = u32_at(record, 8) as usize;
    assert_eq!(&record[12..12 + length], utf16("watched.txt").as_slice());
}
