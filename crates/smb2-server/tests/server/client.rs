//! SMB 2 and 3 client side of the tests: request layouts of MS-SMB2 2.2,
//! message identifiers and credits, negotiate contexts, and the SMB 3
//! preauthentication integrity hash, key derivation, signing, and
//! encryption. The cryptography follows MS-SMB2 3.1.4 and 3.2.5.3.1 with the
//! crate's primitives only, so it shares no protocol code with the server.

use std::mem;

use smb2_server::Connection;
use smb2_server::Reply;
use smb2_server::ServerConfig;
use smb2_server::crypto::HmacSha256;
use smb2_server::crypto::Sha512;
use smb2_server::crypto::aes_cmac;
use smb2_server::crypto::ccm_open;
use smb2_server::crypto::ccm_seal;
use smb2_server::crypto::gcm_open;
use smb2_server::crypto::gcm_seal;
use smb2_server::crypto::gmac;
use smb2_server::crypto::hmac_sha256;
use smb2_server::fs::FileTime;
use smb2_server::server::FileId;
use smb2_server::server::Guid;
use smb2_server::server::Server;
use smb2_server::status::NtStatus;
use smb2_server::transport;

use crate::backend::MemoryBackend;
use crate::backend::PASSWORD;
use crate::backend::USER;
use crate::backend::utf16;
use crate::ntlm;

/// Request and response buffer size, as the example server uses.
pub const BUFFER_SIZE: usize = 0x10400;
pub const SERVER_GUID: Guid = Guid([
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
]);
pub const START_TIME: FileTime = FileTime(0x01d9_0000_0000_0000);
pub const HEADER: usize = 64;
/// ClientGuid of every NEGOTIATE the tests send.
pub const CLIENT_GUID: [u8; 16] = *b"client-guid-0001";

pub mod command {
    pub const NEGOTIATE: u16 = 0x00;
    pub const SESSION_SETUP: u16 = 0x01;
    pub const LOGOFF: u16 = 0x02;
    pub const TREE_CONNECT: u16 = 0x03;
    pub const TREE_DISCONNECT: u16 = 0x04;
    pub const CREATE: u16 = 0x05;
    pub const CLOSE: u16 = 0x06;
    pub const FLUSH: u16 = 0x07;
    pub const READ: u16 = 0x08;
    pub const WRITE: u16 = 0x09;
    pub const LOCK: u16 = 0x0a;
    pub const IOCTL: u16 = 0x0b;
    pub const CANCEL: u16 = 0x0c;
    pub const ECHO: u16 = 0x0d;
    pub const QUERY_DIRECTORY: u16 = 0x0e;
    pub const CHANGE_NOTIFY: u16 = 0x0f;
    pub const QUERY_INFO: u16 = 0x10;
    pub const SET_INFO: u16 = 0x11;
}

pub mod flags {
    pub const SERVER_TO_REDIR: u32 = 0x1;
    pub const ASYNC_COMMAND: u32 = 0x2;
    pub const RELATED_OPERATIONS: u32 = 0x4;
    pub const SIGNED: u32 = 0x8;
}

pub mod dialect {
    pub const SMB_2_0_2: u16 = 0x0202;
    pub const SMB_2_1: u16 = 0x0210;
    pub const SMB_3_0: u16 = 0x0300;
    pub const SMB_3_0_2: u16 = 0x0302;
    pub const SMB_3_1_1: u16 = 0x0311;
}

/// Negotiate context types and the identifiers they list (MS-SMB2
/// 2.2.3.1).
pub mod context {
    pub const PREAUTH_INTEGRITY: u16 = 0x0001;
    pub const ENCRYPTION: u16 = 0x0002;
    pub const SIGNING: u16 = 0x0008;
    pub const SHA_512: u16 = 0x0001;
    pub const AES_128_CCM: u16 = 0x0001;
    pub const AES_128_GCM: u16 = 0x0002;
    pub const HMAC_SHA256: u16 = 0x0000;
    pub const AES_CMAC: u16 = 0x0001;
    pub const AES_GMAC: u16 = 0x0002;
}

pub mod access {
    pub const READ_DATA: u32 = 0x0000_0001;
    pub const WRITE_DATA: u32 = 0x0000_0002;
    pub const READ_ATTRIBUTES: u32 = 0x0000_0080;
    pub const DELETE: u32 = 0x0001_0000;
    pub const READ_CONTROL: u32 = 0x0002_0000;
    pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const READ: u32 = READ_DATA | READ_ATTRIBUTES | READ_CONTROL;
    pub const ALL: u32 = 0x001f_01ff;
}

pub mod disposition {
    pub const OPEN: u32 = 1;
    pub const CREATE: u32 = 2;
    pub const OPEN_IF: u32 = 3;
    pub const OVERWRITE_IF: u32 = 5;
}

pub mod options {
    pub const DIRECTORY_FILE: u32 = 0x1;
    pub const NON_DIRECTORY_FILE: u32 = 0x40;
    pub const DELETE_ON_CLOSE: u32 = 0x1000;
}

/// Flags of a LOCK element (MS-SMB2 2.2.26.1).
pub mod lock {
    pub const SHARED: u32 = 0x01;
    pub const EXCLUSIVE: u32 = 0x02;
    pub const UNLOCK: u32 = 0x04;
    pub const FAIL_IMMEDIATELY: u32 = 0x10;
}

/// SecurityMode of NEGOTIATE and SESSION_SETUP requests.
pub const SIGNING_ENABLED: u8 = 0x1;
pub const SIGNING_REQUIRED: u8 = 0x2;
/// SMB2_GLOBAL_CAP_ENCRYPTION.
pub const CAP_ENCRYPTION: u32 = 0x40;

pub const SESSION_FLAG_IS_GUEST: u16 = 0x1;
pub const SESSION_FLAG_IS_NULL: u16 = 0x2;
pub const SESSION_FLAG_ENCRYPT_DATA: u16 = 0x4;

/// Bytes of an SMB2 TRANSFORM_HEADER (MS-SMB2 2.2.41).
pub const TRANSFORM_HEADER: usize = 52;
const TRANSFORM_PROTOCOL_ID: &[u8; 4] = b"\xfdSMB";

pub fn config(signing_required: bool) -> ServerConfig {
    ServerConfig {
        guid: SERVER_GUID,
        start_time: START_TIME,
        signing_required,
        buffer_size: BUFFER_SIZE,
        change_scan_interval: None,
        encrypt_data: false,
    }
}

pub fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

pub fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    for (index, line) in bytes.chunks(16).enumerate() {
        write!(text, "{:04x}:", index * 16).unwrap();
        for byte in line {
            write!(text, " {byte:02x}").unwrap();
        }
        text.push('\n');
    }
    text
}

/// A signing algorithm (MS-SMB2 3.1.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signing {
    HmacSha256,
    AesCmac,
    AesGmac,
}

/// An encryption cipher (MS-SMB2 3.1.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes128Ccm,
    Aes128Gcm,
}

/// The client's encryption keys of a session.
#[derive(Debug, Clone, Copy)]
pub struct EncryptionKeys {
    /// Encrypts requests.
    pub encryption: [u8; 16],
    /// Decrypts replies.
    pub decryption: [u8; 16],
}

/// SP800-108 counter-mode KDF with HMAC-SHA256, one iteration and L = 128
/// (MS-SMB2 3.1.4.2). `label` includes its terminating NUL; a zero byte
/// separates it from `context`.
pub fn kdf(key: &[u8; 16], label: &[u8], context: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new(key);
    mac.update(&[0, 0, 0, 1]);
    mac.update(label);
    mac.update(&[0]);
    mac.update(context);
    mac.update(&[0, 0, 0, 0x80]);
    mac.finalize()[..16].try_into().unwrap()
}

/// SHA-512 of `hash` followed by `message` (MS-SMB2 3.2.5.2).
pub fn preauth_update(hash: &[u8; 64], message: &[u8]) -> [u8; 64] {
    let mut sha = Sha512::new();
    sha.update(hash);
    sha.update(message);
    sha.finalize()
}

/// Signature of a message (MS-SMB2 3.1.4.1) with the signature field taken
/// as zero.
pub fn sign_with(message: &[u8], key: &[u8; 16], signing: Signing) -> [u8; 16] {
    let mut copy = message.to_vec();
    copy[48..64].fill(0);
    match signing {
        Signing::HmacSha256 => hmac_sha256(key, &copy)[..16].try_into().unwrap(),
        Signing::AesCmac => aes_cmac(key, &[&copy]),
        Signing::AesGmac => {
            // MessageId, then a word with bit 0 for a reply and bit 1 for
            // a CANCEL.
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&copy[24..32]);
            let mut role = u32_at(&copy, 16) & flags::SERVER_TO_REDIR;
            if u16_at(&copy, 12) == command::CANCEL {
                role |= 2;
            }
            nonce[8..].copy_from_slice(&role.to_le_bytes());
            gmac(key, &nonce, &[&copy])
        }
    }
}

/// A TRANSFORM_HEADER and `plain` encrypted under `key` (MS-SMB2 3.1.4.3).
/// `nonce` is the 16-byte Nonce field; the cipher uses its first 11 or 12
/// bytes.
pub fn seal(
    plain: &[u8],
    key: &[u8; 16],
    cipher: Cipher,
    session_id: u64,
    nonce: [u8; 16],
) -> Vec<u8> {
    let mut header = vec![0u8; TRANSFORM_HEADER];
    header[..4].copy_from_slice(TRANSFORM_PROTOCOL_ID);
    header[20..36].copy_from_slice(&nonce);
    put_u32(&mut header, 36, plain.len() as u32);
    put_u16(&mut header, 42, 1);
    put_u64(&mut header, 44, session_id);
    let mut data = plain.to_vec();
    let aad = header[20..].to_vec();
    let tag = match cipher {
        Cipher::Aes128Ccm => ccm_seal(key, nonce[..11].try_into().unwrap(), &aad, &mut data),
        Cipher::Aes128Gcm => gcm_seal(key, nonce[..12].try_into().unwrap(), &aad, &mut data),
    }
    .unwrap();
    header[4..20].copy_from_slice(&tag);
    header.extend(data);
    header
}

/// The message inside an encrypted frame, or `None` when its tag is wrong.
pub fn unseal(frame: &[u8], key: &[u8; 16], cipher: Cipher) -> Option<Vec<u8>> {
    assert_eq!(&frame[..4], TRANSFORM_PROTOCOL_ID);
    assert_eq!(u16_at(frame, 42), 1, "transform flags");
    assert_eq!(u32_at(frame, 36) as usize, frame.len() - TRANSFORM_HEADER);
    let tag: [u8; 16] = frame[4..20].try_into().unwrap();
    let aad = &frame[20..TRANSFORM_HEADER];
    let mut data = frame[TRANSFORM_HEADER..].to_vec();
    let opened = match cipher {
        Cipher::Aes128Ccm => {
            assert_eq!(frame[31..36], [0; 5], "reserved nonce bytes");
            ccm_open(key, frame[20..31].try_into().unwrap(), aad, &mut data, &tag)
        }
        Cipher::Aes128Gcm => {
            assert_eq!(frame[32..36], [0; 4], "reserved nonce bytes");
            gcm_open(key, frame[20..32].try_into().unwrap(), aad, &mut data, &tag)
        }
    };
    opened.then_some(data)
}

/// One response: header and body, with the padding that precedes the next
/// response of a chain.
#[derive(Debug, Clone)]
pub struct Message(pub Vec<u8>);

impl Message {
    pub fn status(&self) -> NtStatus {
        NtStatus::from_raw(u32_at(&self.0, 8))
    }

    pub fn command(&self) -> u16 {
        u16_at(&self.0, 12)
    }

    pub fn credits(&self) -> u16 {
        u16_at(&self.0, 14)
    }

    pub fn flags(&self) -> u32 {
        u32_at(&self.0, 16)
    }

    pub fn next_command(&self) -> u32 {
        u32_at(&self.0, 20)
    }

    pub fn message_id(&self) -> u64 {
        u64_at(&self.0, 24)
    }

    /// AsyncId of a reply with SMB2_FLAGS_ASYNC_COMMAND.
    pub fn async_id(&self) -> u64 {
        assert_ne!(self.flags() & flags::ASYNC_COMMAND, 0, "asynchronous reply");
        u64_at(&self.0, 32)
    }

    pub fn tree_id(&self) -> u32 {
        u32_at(&self.0, 36)
    }

    pub fn session_id(&self) -> u64 {
        u64_at(&self.0, 40)
    }

    pub fn signed(&self) -> bool {
        self.flags() & flags::SIGNED != 0
    }

    pub fn body(&self) -> &[u8] {
        &self.0[HEADER..]
    }

    pub fn expect(&self, status: NtStatus) -> &Self {
        assert_eq!(
            self.status(),
            status,
            "status of command {:#04x}",
            self.command()
        );
        self
    }

    /// The buffer that a 16-bit offset at `offset_field` and a length at
    /// `length_field` of the body describe; the offset counts from the
    /// header.
    pub fn buffer16(&self, offset_field: usize, length_field: usize, length_bits: u32) -> &[u8] {
        let offset = usize::from(u16_at(self.body(), offset_field));
        let length = match length_bits {
            16 => usize::from(u16_at(self.body(), length_field)),
            _ => u32_at(self.body(), length_field) as usize,
        };
        &self.0[offset..offset + length]
    }

    /// FileId of a CREATE response.
    pub fn file_id(&self) -> FileId {
        self.expect(NtStatus::Success);
        FileId::read(self.body(), 64)
    }

    /// OutputBuffer of a QUERY_INFO, QUERY_DIRECTORY, or CHANGE_NOTIFY
    /// response.
    pub fn output(&self) -> &[u8] {
        self.buffer16(2, 4, 32)
    }

    /// Data of a READ response.
    pub fn data(&self) -> &[u8] {
        let offset = usize::from(self.body()[2]);
        let length = u32_at(self.body(), 4) as usize;
        &self.0[offset..offset + length]
    }

    /// Output of an IOCTL response.
    pub fn ioctl_output(&self) -> &[u8] {
        let offset = u32_at(self.body(), 32) as usize;
        let length = u32_at(self.body(), 36) as usize;
        &self.0[offset..offset + length]
    }

    /// ErrorData of an error response (MS-SMB2 2.2.2).
    pub fn error_data(&self) -> &[u8] {
        assert_eq!(u16_at(self.body(), 0), 9);
        let length = u32_at(self.body(), 4) as usize;
        &self.body()[8..8 + length]
    }

    /// The negotiate contexts of an SMB 3.1.1 NEGOTIATE response: type and
    /// data of each.
    pub fn negotiate_contexts(&self) -> Vec<(u16, Vec<u8>)> {
        let count = usize::from(u16_at(self.body(), 6));
        let mut offset = u32_at(self.body(), 60) as usize;
        let mut contexts = Vec::new();
        for _ in 0..count {
            assert_eq!(offset % 8, 0, "negotiate context alignment");
            let kind = u16_at(&self.0, offset);
            let length = usize::from(u16_at(&self.0, offset + 2));
            contexts.push((kind, self.0[offset + 8..offset + 8 + length].to_vec()));
            offset = (offset + 8 + length).next_multiple_of(8);
        }
        contexts
    }

    /// The single identifier a response negotiate context of `kind`
    /// selects, if the response has the context.
    pub fn negotiate_choice(&self, kind: u16) -> Option<u16> {
        let (_, data) = self
            .negotiate_contexts()
            .into_iter()
            .find(|(found, _)| *found == kind)?;
        assert_eq!(u16_at(&data, 0), 1, "one identifier in context {kind:#06x}");
        Some(u16_at(&data, 2))
    }
}

/// One transport frame of a reply.
#[derive(Debug)]
pub struct Frame {
    /// The responses of a chain.
    pub messages: Vec<Message>,
    /// The chain after the transport header, decrypted.
    pub bytes: Vec<u8>,
    /// Nonce of the transform header when the frame was encrypted.
    pub nonce: Option<u64>,
}

/// What the server did with a request.
#[derive(Debug)]
pub enum Outcome {
    Replies(Vec<Frame>),
    Nothing,
    Disconnect,
}

impl Outcome {
    pub fn frames(self) -> Vec<Frame> {
        match self {
            Self::Replies(frames) => frames,
            other => panic!("expected replies, got {other:?}"),
        }
    }

    /// The responses of every frame.
    pub fn replies(self) -> Vec<Message> {
        self.frames()
            .into_iter()
            .flat_map(|frame| frame.messages)
            .collect()
    }

    pub fn single(self) -> Message {
        let mut replies = self.replies();
        assert_eq!(replies.len(), 1);
        replies.remove(0)
    }

    pub fn is_disconnect(&self) -> bool {
        matches!(self, Self::Disconnect)
    }

    pub fn is_nothing(&self) -> bool {
        matches!(self, Self::Nothing)
    }

    /// The responses, or none when the server sent nothing.
    pub fn replies_or_none(self) -> Vec<Message> {
        match self {
            Self::Nothing => Vec::new(),
            other => other.replies(),
        }
    }
}

/// One request of a chain.
pub struct Request {
    pub command: u16,
    pub body: Vec<u8>,
    pub related: bool,
}

/// One element of a LOCK request.
#[derive(Debug, Clone, Copy)]
pub struct LockElement {
    pub offset: u64,
    pub length: u64,
    pub flags: u32,
}

pub struct Client {
    pub connection: Box<Connection>,
    pub server: Box<Server>,
    pub config: ServerConfig,
    pub backend: MemoryBackend,
    pub next_message_id: u64,
    /// One past the highest message identifier granted.
    pub credit_limit: u64,
    pub credit_request: u16,
    pub session_id: u64,
    pub tree_id: u32,
    /// Signing key of the session, once known.
    pub key: Option<[u8; 16]>,
    /// The algorithm of `key`.
    pub signing: Signing,
    /// Sign requests with `key`.
    pub sign: bool,
    /// SecurityMode of the NEGOTIATE reply has SIGNING_REQUIRED.
    pub server_requires_signing: bool,
    /// PreviousSessionId of SESSION_SETUP requests.
    pub previous_session_id: u64,
    /// DialectRevision of the NEGOTIATE reply; 0 before it.
    pub dialect: u16,
    /// The cipher the NEGOTIATE settled.
    pub cipher: Option<Cipher>,
    /// Preauthentication integrity hash of the NEGOTIATE (SMB 3.1.1).
    pub preauth: [u8; 64],
    /// Preauthentication integrity hash of the logon under way.
    pub session_preauth: Option<[u8; 64]>,
    /// Encryption keys of the session.
    pub encryption: Option<EncryptionKeys>,
    /// Encrypt requests with `encryption`.
    pub encrypt: bool,
    next_nonce: u64,
    /// Nonces of the encrypted frames received, in order.
    pub reply_nonces: Vec<u64>,
}

impl Client {
    pub fn new(backend: MemoryBackend, config: ServerConfig) -> Self {
        let mut server = Box::new(Server::new());
        server.configure(config);
        Self {
            connection: Box::new(Connection::new()),
            server,
            config,
            backend,
            next_message_id: 0,
            credit_limit: 1,
            credit_request: 8,
            session_id: 0,
            tree_id: 0,
            key: None,
            signing: Signing::HmacSha256,
            sign: false,
            server_requires_signing: false,
            previous_session_id: 0,
            dialect: 0,
            cipher: None,
            preauth: [0; 64],
            session_preauth: None,
            encryption: None,
            encrypt: false,
            next_nonce: 1,
            reply_nonces: Vec::new(),
        }
    }

    /// A client that negotiated dialect 2.1.
    pub fn negotiated(backend: MemoryBackend, config: ServerConfig) -> Self {
        let mut client = Self::new(backend, config);
        client.negotiate_2_1();
        client
    }

    fn negotiate_2_1(&mut self) {
        let reply = self.negotiate(&negotiate_body(&[dialect::SMB_2_0_2, dialect::SMB_2_1]));
        reply.expect(NtStatus::Success);
        assert_eq!(self.dialect, dialect::SMB_2_1);
    }

    /// A client logged on as the test account without signing.
    pub fn logged_on() -> Self {
        let mut client = Self::negotiated(MemoryBackend::new(), config(false));
        client
            .logon(USER, PASSWORD, false)
            .expect(NtStatus::Success);
        client
    }

    /// A logged-on client connected to `share`.
    pub fn connected(share: &str) -> Self {
        let mut client = Self::logged_on();
        client.tree_connect(share).expect(NtStatus::Success);
        client
    }

    /// A client that negotiated `dialect` alone, offering encryption and,
    /// for SMB 3.1.1, the SHA-512 preauthentication hash, `ciphers`, and
    /// `signing` algorithms, and logged on as the test account.
    pub fn smb3(config: ServerConfig, dialect: u16, ciphers: &[u16], signing: &[u16]) -> Self {
        let mut client = Self::new(MemoryBackend::new(), config);
        client
            .negotiate(&smb3_negotiate_body(dialect, ciphers, signing))
            .expect(NtStatus::Success);
        assert_eq!(client.dialect, dialect);
        client
            .logon(USER, PASSWORD, false)
            .expect(NtStatus::Success);
        client
    }

    /// A client on a second connection to this client's server and
    /// backend; [`Client::with_peer`] lends them to it.
    pub fn peer(&self) -> Self {
        Self::new(MemoryBackend::new(), self.config)
    }

    /// A peer that negotiated dialect 2.1, logged on, and connected to
    /// `share`.
    pub fn connected_peer(&mut self, share: &str) -> Self {
        let mut peer = self.peer();
        self.with_peer(&mut peer, |peer| {
            peer.negotiate_2_1();
            peer.logon(USER, PASSWORD, false).expect(NtStatus::Success);
            peer.tree_connect(share).expect(NtStatus::Success);
        });
        peer
    }

    /// Run `action` on `peer` with this client's server and backend.
    pub fn with_peer<R>(&mut self, peer: &mut Self, action: impl FnOnce(&mut Self) -> R) -> R {
        self.lend(peer);
        let result = action(peer);
        self.lend(peer);
        result
    }

    fn lend(&mut self, peer: &mut Self) {
        mem::swap(&mut self.server, &mut peer.server);
        mem::swap(&mut self.backend, &mut peer.backend);
    }

    /// Next message identifier, which a credit must cover.
    pub fn allocate_id(&mut self) -> u64 {
        assert!(
            self.next_message_id < self.credit_limit,
            "no credit for message {}",
            self.next_message_id
        );
        let id = self.next_message_id;
        self.next_message_id += 1;
        id
    }

    /// A request header with the client's session and tree.
    pub fn header(&self, command: u16, message_id: u64, flags: u32) -> Vec<u8> {
        let mut header = vec![0u8; HEADER];
        header[..4].copy_from_slice(b"\xfeSMB");
        put_u16(&mut header, 4, HEADER as u16);
        put_u16(&mut header, 6, 1);
        put_u16(&mut header, 12, command);
        put_u16(&mut header, 14, self.credit_request);
        put_u32(&mut header, 16, flags);
        put_u64(&mut header, 24, message_id);
        put_u32(&mut header, 32, 0xfeff);
        put_u32(&mut header, 36, self.tree_id);
        put_u64(&mut header, 40, self.session_id);
        header
    }

    /// Set the SIGNED flag and signature of `message` when the client signs
    /// and does not encrypt.
    pub fn sign_message(&self, message: &mut [u8]) {
        if let (true, false, Some(key)) = (self.sign, self.encrypt, self.key) {
            let flags = u32_at(message, 16) | flags::SIGNED;
            put_u32(message, 16, flags);
            let signature = sign_with(message, &key, self.signing);
            message[48..64].copy_from_slice(&signature);
        }
    }

    /// A complete request with the next message identifier.
    pub fn message(&mut self, command: u16, body: &[u8]) -> Vec<u8> {
        let id = self.allocate_id();
        let mut message = self.header(command, id, 0);
        message.extend_from_slice(body);
        self.sign_message(&mut message);
        message
    }

    /// `request` after a transform header, encrypted with the session's
    /// key and the next nonce.
    pub fn seal_request(&mut self, request: &[u8]) -> Vec<u8> {
        let keys = self.encryption.expect("session has encryption keys");
        let cipher = self.cipher.expect("connection has a cipher");
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&self.next_nonce.to_le_bytes());
        self.next_nonce += 1;
        seal(
            request,
            &keys.encryption,
            cipher,
            u64_at(request, 40),
            nonce,
        )
    }

    /// Hand `request` to the server, encrypted when the client encrypts;
    /// check the replies.
    pub fn transmit(&mut self, request: &[u8]) -> Outcome {
        let bytes = if self.encrypt {
            self.seal_request(request)
        } else {
            request.to_vec()
        };
        self.deliver(&bytes)
    }

    /// Hand `bytes` to the server as they are; check the framing, credits,
    /// signatures, and encryption of the replies.
    pub fn deliver(&mut self, bytes: &[u8]) -> Outcome {
        let mut request = bytes.to_vec();
        let mut response = vec![0u8; self.config.buffer_size];
        let reply = self.connection.handle(
            &mut self.server,
            &mut self.backend,
            &mut request,
            &mut response,
        );
        self.receive(reply, &response)
    }

    /// Collect the replies `Connection::poll` writes.
    pub fn poll(&mut self) -> Outcome {
        let mut response = vec![0u8; self.config.buffer_size];
        let reply = self
            .connection
            .poll(&mut self.server, &mut self.backend, &mut response);
        self.receive(reply, &response)
    }

    /// Whether the connection asks to be polled.
    pub fn wants_poll(&self) -> bool {
        self.connection.wants_poll(&self.server)
    }

    fn receive(&mut self, reply: Reply, response: &[u8]) -> Outcome {
        let length = match reply {
            Reply::Send { length } => length,
            Reply::Nothing => return Outcome::Nothing,
            Reply::Disconnect => return Outcome::Disconnect,
        };
        let mut frames = Vec::new();
        let mut at = 0;
        while at < length {
            let header: [u8; 4] = response[at..at + 4].try_into().unwrap();
            let Ok(transport::Frame::Message { length: frame }) =
                transport::parse_header(header, BUFFER_SIZE)
            else {
                panic!("transport header {header:?}");
            };
            frames.push(self.receive_frame(&response[at + 4..at + 4 + frame]));
            at += 4 + frame;
        }
        assert_eq!(at, length, "frames fill the reply");
        Outcome::Replies(frames)
    }

    fn receive_frame(&mut self, frame: &[u8]) -> Frame {
        let (bytes, nonce) = if frame[..4] == *TRANSFORM_PROTOCOL_ID {
            let keys = self.encryption.expect("encrypted reply without keys");
            let cipher = self.cipher.expect("encrypted reply without a cipher");
            let bytes = unseal(frame, &keys.decryption, cipher).expect("reply decrypts");
            assert_eq!(u64_at(frame, 44), u64_at(&bytes, 40), "transform session");
            let nonce = u64_at(frame, 20);
            self.reply_nonces.push(nonce);
            (bytes, Some(nonce))
        } else {
            (frame.to_vec(), None)
        };
        let messages = split_chain(&bytes);
        for message in &messages {
            assert_eq!(&message.0[..4], b"\xfeSMB");
            assert_ne!(message.flags() & flags::SERVER_TO_REDIR, 0);
            if message.signed() {
                assert!(nonce.is_none(), "encrypted reply is not signed");
                let key = self.key.expect("signed reply without a session key");
                assert_eq!(
                    sign_with(&message.0, &key, self.signing),
                    message.0[48..64],
                    "reply signature of command {:#04x}",
                    message.command()
                );
            }
            self.credit_limit += u64::from(message.credits());
            assert!(
                self.credit_limit - self.next_message_id <= 128,
                "more than 128 credits outstanding"
            );
        }
        Frame {
            messages,
            bytes,
            nonce,
        }
    }

    /// Send one request and return its single reply.
    pub fn call(&mut self, command: u16, body: &[u8]) -> Message {
        self.call_all(command, body).single()
    }

    /// Send one request and return every reply that came back.
    pub fn call_all(&mut self, command: u16, body: &[u8]) -> Outcome {
        let message = self.message(command, body);
        self.transmit(&message)
    }

    /// Send `requests` as one compound chain.
    pub fn compound(&mut self, requests: &[Request]) -> Outcome {
        let mut chain = Vec::new();
        let mut previous: Option<usize> = None;
        for request in requests {
            if let Some(previous) = previous {
                let start = chain.len().next_multiple_of(8);
                chain.resize(start, 0);
                put_u32(&mut chain, previous + 20, (start - previous) as u32);
            }
            let start = chain.len();
            let id = self.allocate_id();
            let flags = if request.related {
                flags::RELATED_OPERATIONS
            } else {
                0
            };
            chain.extend(self.header(request.command, id, flags));
            chain.extend_from_slice(&request.body);
            previous = Some(start);
        }
        let mut start = 0;
        loop {
            let next = u32_at(&chain, start + 20) as usize;
            let end = if next == 0 { chain.len() } else { start + next };
            self.sign_message(&mut chain[start..end]);
            if next == 0 {
                break;
            }
            start = end;
        }
        self.transmit(&chain)
    }

    /// Send a NEGOTIATE and record what it settled: dialect, signing
    /// algorithm, cipher, and for SMB 3.1.1 the preauthentication hash.
    pub fn negotiate(&mut self, body: &[u8]) -> Message {
        let request = self.message(command::NEGOTIATE, body);
        let reply = self.transmit(&request).single();
        if reply.status() != NtStatus::Success {
            return reply;
        }
        self.dialect = u16_at(reply.body(), 4);
        self.server_requires_signing = u16_at(reply.body(), 2) & u16::from(SIGNING_REQUIRED) != 0;
        let encryption_capable = u32_at(reply.body(), 24) & CAP_ENCRYPTION != 0;
        (self.signing, self.cipher) = match self.dialect {
            dialect::SMB_2_0_2 | dialect::SMB_2_1 => (Signing::HmacSha256, None),
            dialect::SMB_3_0 | dialect::SMB_3_0_2 => (
                Signing::AesCmac,
                encryption_capable.then_some(Cipher::Aes128Ccm),
            ),
            dialect::SMB_3_1_1 => {
                assert!(
                    !encryption_capable,
                    "3.1.1 negotiates its cipher in a context"
                );
                self.preauth = preauth_update(&preauth_update(&[0; 64], &request), &reply.0);
                let signing = match reply.negotiate_choice(context::SIGNING) {
                    None | Some(context::AES_CMAC) => Signing::AesCmac,
                    Some(context::AES_GMAC) => Signing::AesGmac,
                    Some(context::HMAC_SHA256) => Signing::HmacSha256,
                    Some(other) => panic!("signing algorithm {other:#06x}"),
                };
                let cipher = match reply.negotiate_choice(context::ENCRYPTION) {
                    None | Some(0) => None,
                    Some(context::AES_128_CCM) => Some(Cipher::Aes128Ccm),
                    Some(context::AES_128_GCM) => Some(Cipher::Aes128Gcm),
                    Some(other) => panic!("cipher {other:#06x}"),
                };
                (signing, cipher)
            }
            other => panic!("dialect {other:#06x}"),
        };
        reply
    }

    /// SESSION_SETUP body with the client's PreviousSessionId.
    fn setup_body(&self, token: &[u8], security_mode: u8) -> Vec<u8> {
        let mut body = session_setup_body(token, security_mode);
        put_u64(&mut body, 16, self.previous_session_id);
        body
    }

    pub fn session_setup(&mut self, token: &[u8], security_mode: u8) -> Message {
        let request = self.message(
            command::SESSION_SETUP,
            &self.setup_body(token, security_mode),
        );
        if let Some(hash) = &mut self.session_preauth {
            *hash = preauth_update(hash, &request);
        }
        let reply = self.transmit(&request).single();
        if reply.status() == NtStatus::MoreProcessingRequired
            && let Some(hash) = &mut self.session_preauth
        {
            *hash = preauth_update(hash, &reply.0);
        }
        reply
    }

    /// Raw NTLMSSP logon of a new session; returns the final SESSION_SETUP
    /// reply. The client keeps the keys of an authenticated account and
    /// signs when either side requires it.
    pub fn logon(&mut self, user: &str, password: &str, require_signing: bool) -> Message {
        let security_mode = if require_signing {
            SIGNING_ENABLED | SIGNING_REQUIRED
        } else {
            SIGNING_ENABLED
        };
        self.session_id = 0;
        self.encrypt = false;
        self.session_preauth = (self.dialect == dialect::SMB_3_1_1).then_some(self.preauth);
        let negotiate = ntlm::negotiate_message();
        let reply = self.session_setup(&negotiate, security_mode);
        reply.expect(NtStatus::MoreProcessingRequired);
        assert!(!reply.signed());
        self.session_id = reply.session_id();
        let challenge = reply.buffer16(4, 6, 16).to_vec();
        let authenticate =
            ntlm::authenticate_message(user, "WORKGROUP", password, &negotiate, &challenge);
        self.finish_logon(
            &authenticate.message,
            authenticate.session_key,
            security_mode,
        )
    }

    /// Send the final token; keeps the keys derived from `session_key`
    /// when the server authenticated the account.
    pub fn finish_logon(
        &mut self,
        token: &[u8],
        session_key: [u8; 16],
        security_mode: u8,
    ) -> Message {
        let request = self.message(
            command::SESSION_SETUP,
            &self.setup_body(token, security_mode),
        );
        if let Some(hash) = &mut self.session_preauth {
            *hash = preauth_update(hash, &request);
        }
        self.derive_keys(&session_key);
        let reply = self.transmit(&request).single();
        self.session_preauth = None;
        let session_flags = if reply.status() == NtStatus::Success {
            u16_at(reply.body(), 2)
        } else {
            0
        };
        let authenticated = reply.status() == NtStatus::Success
            && session_flags & (SESSION_FLAG_IS_GUEST | SESSION_FLAG_IS_NULL) == 0;
        if !authenticated {
            self.key = None;
            self.encryption = None;
        }
        self.encrypt = session_flags & SESSION_FLAG_ENCRYPT_DATA != 0;
        self.sign = authenticated
            && (security_mode & SIGNING_REQUIRED != 0 || self.server_requires_signing);
        reply
    }

    /// The signing and encryption keys of a session for the negotiated
    /// dialect (MS-SMB2 3.2.5.3.1).
    fn derive_keys(&mut self, session_key: &[u8; 16]) {
        match self.dialect {
            dialect::SMB_3_0 | dialect::SMB_3_0_2 => {
                self.key = Some(kdf(session_key, b"SMB2AESCMAC\0", b"SmbSign\0"));
                self.encryption = self.cipher.map(|_| EncryptionKeys {
                    encryption: kdf(session_key, b"SMB2AESCCM\0", b"ServerIn \0"),
                    decryption: kdf(session_key, b"SMB2AESCCM\0", b"ServerOut\0"),
                });
            }
            dialect::SMB_3_1_1 => {
                let hash = self.session_preauth.expect("logon hashes its messages");
                self.key = Some(kdf(session_key, b"SMBSigningKey\0", &hash));
                self.encryption = self.cipher.map(|_| EncryptionKeys {
                    encryption: kdf(session_key, b"SMBC2SCipherKey\0", &hash),
                    decryption: kdf(session_key, b"SMBS2CCipherKey\0", &hash),
                });
            }
            _ => self.key = Some(*session_key),
        }
    }

    /// Raw NTLMSSP re-authentication of the current session; the session
    /// keeps its key.
    pub fn reauthenticate(&mut self, user: &str, password: &str) -> Message {
        let negotiate = ntlm::negotiate_message();
        let reply = self.session_setup(&negotiate, SIGNING_ENABLED);
        reply.expect(NtStatus::MoreProcessingRequired);
        assert_eq!(reply.session_id(), self.session_id);
        let challenge = reply.buffer16(4, 6, 16).to_vec();
        let authenticate =
            ntlm::authenticate_message(user, "WORKGROUP", password, &negotiate, &challenge);
        self.session_setup(&authenticate.message, SIGNING_ENABLED)
    }

    pub fn tree_connect(&mut self, share: &str) -> Message {
        let reply = self.call(command::TREE_CONNECT, &tree_connect_body(share));
        if reply.status() == NtStatus::Success {
            self.tree_id = reply.tree_id();
        }
        reply
    }

    pub fn create(&mut self, name: &str, access: u32, disposition: u32, options: u32) -> Message {
        self.call(
            command::CREATE,
            &create_body(name, access, disposition, options, &[]),
        )
    }

    /// Open or create a file with every right; panics on failure.
    pub fn open(&mut self, name: &str, disposition: u32) -> FileId {
        self.create(name, access::ALL, disposition, options::NON_DIRECTORY_FILE)
            .file_id()
    }

    pub fn open_directory(&mut self, name: &str) -> FileId {
        self.create(
            name,
            access::READ,
            disposition::OPEN,
            options::DIRECTORY_FILE,
        )
        .file_id()
    }

    pub fn close(&mut self, file: FileId, flags: u16) -> Message {
        self.call(command::CLOSE, &close_body(file, flags))
    }

    pub fn read(&mut self, file: FileId, offset: u64, length: u32) -> Message {
        self.call(command::READ, &read_body(file, offset, length))
    }

    pub fn write(&mut self, file: FileId, offset: u64, data: &[u8]) -> Message {
        let mut body = vec![0u8; 48];
        put_u16(&mut body, 0, 49);
        put_u16(&mut body, 2, (HEADER + 48) as u16);
        put_u32(&mut body, 4, data.len() as u32);
        put_u64(&mut body, 8, offset);
        file.write(&mut body, 16);
        body.extend_from_slice(data);
        self.call(command::WRITE, &body)
    }

    pub fn flush(&mut self, file: FileId) -> Message {
        let mut body = vec![0u8; 24];
        put_u16(&mut body, 0, 24);
        file.write(&mut body, 8);
        self.call(command::FLUSH, &body)
    }

    pub fn lock(&mut self, file: FileId, elements: &[LockElement]) -> Message {
        self.call(command::LOCK, &lock_body(file, elements))
    }

    /// CHANGE_NOTIFY (MS-SMB2 2.2.35); returns every reply, the interim
    /// one first when the request waits.
    pub fn change_notify(&mut self, file: FileId, filter: u32, watch_tree: bool) -> Outcome {
        self.change_notify_sized(file, filter, watch_tree, 0x1000)
    }

    /// CHANGE_NOTIFY with an OutputBufferLength of `output_length`.
    pub fn change_notify_sized(
        &mut self,
        file: FileId,
        filter: u32,
        watch_tree: bool,
        output_length: u32,
    ) -> Outcome {
        let mut body = vec![0u8; 32];
        put_u16(&mut body, 0, 32);
        put_u16(&mut body, 2, u16::from(watch_tree));
        put_u32(&mut body, 4, output_length);
        file.write(&mut body, 8);
        put_u32(&mut body, 24, filter);
        self.call_all(command::CHANGE_NOTIFY, &body)
    }

    /// CANCEL of the asynchronous request `async_id`, which used the
    /// identifier `message_id`; returns what the server sent back.
    pub fn cancel(&mut self, message_id: u64, async_id: u64) -> Outcome {
        let mut message = self.header(command::CANCEL, message_id, flags::ASYNC_COMMAND);
        put_u64(&mut message, 32, async_id);
        message.extend(empty_body());
        self.sign_message(&mut message);
        self.transmit(&message)
    }

    pub fn query_directory(
        &mut self,
        file: FileId,
        class: u8,
        flags: u8,
        pattern: &str,
        output_length: u32,
    ) -> Message {
        let pattern = utf16(pattern);
        let mut body = vec![0u8; 32];
        put_u16(&mut body, 0, 33);
        body[2] = class;
        body[3] = flags;
        file.write(&mut body, 8);
        put_u16(&mut body, 24, (HEADER + 32) as u16);
        put_u16(&mut body, 26, pattern.len() as u16);
        put_u32(&mut body, 28, output_length);
        body.extend(pattern);
        self.call(command::QUERY_DIRECTORY, &body)
    }

    pub fn query_info(
        &mut self,
        file: FileId,
        info_type: u8,
        class: u8,
        additional: u32,
        output_length: u32,
    ) -> Message {
        self.call(
            command::QUERY_INFO,
            &query_info_body(file, info_type, class, additional, output_length),
        )
    }

    pub fn set_info(&mut self, file: FileId, info_type: u8, class: u8, data: &[u8]) -> Message {
        let mut body = vec![0u8; 32];
        put_u16(&mut body, 0, 33);
        body[2] = info_type;
        body[3] = class;
        put_u32(&mut body, 4, data.len() as u32);
        put_u16(&mut body, 8, (HEADER + 32) as u16);
        file.write(&mut body, 16);
        body.extend_from_slice(data);
        self.call(command::SET_INFO, &body)
    }

    pub fn ioctl(&mut self, file: FileId, code: u32, input: &[u8], max_output: u32) -> Message {
        self.call_all(command::IOCTL, &ioctl_body(file, code, input, max_output))
            .single()
    }

    pub fn echo(&mut self) -> Message {
        self.call(command::ECHO, &empty_body())
    }

    pub fn logoff(&mut self) -> Message {
        self.call(command::LOGOFF, &empty_body())
    }

    pub fn tree_disconnect(&mut self) -> Message {
        self.call(command::TREE_DISCONNECT, &empty_body())
    }
}

/// Split a chain of responses at their NextCommand offsets, checking that
/// each starts 8-byte aligned.
pub fn split_chain(bytes: &[u8]) -> Vec<Message> {
    let mut messages = Vec::new();
    let mut start = 0;
    loop {
        assert_eq!(start % 8, 0, "response at unaligned offset {start}");
        let next = u32_at(bytes, start + 20) as usize;
        let end = if next == 0 { bytes.len() } else { start + next };
        messages.push(Message(bytes[start..end].to_vec()));
        if next == 0 {
            return messages;
        }
        start = end;
    }
}

/// Body of LOGOFF, TREE_DISCONNECT, and ECHO requests.
pub fn empty_body() -> Vec<u8> {
    vec![4, 0, 0, 0]
}

/// NEGOTIATE request (MS-SMB2 2.2.3) offering `dialects`.
pub fn negotiate_body(dialects: &[u16]) -> Vec<u8> {
    let mut body = vec![0u8; 36];
    put_u16(&mut body, 0, 36);
    put_u16(&mut body, 2, dialects.len() as u16);
    put_u16(&mut body, 4, u16::from(SIGNING_ENABLED));
    body[12..28].copy_from_slice(&CLIENT_GUID);
    for dialect in dialects {
        body.extend(dialect.to_le_bytes());
    }
    body
}

/// NEGOTIATE request offering `dialects` with `capabilities`, followed by
/// `contexts` (type and data) 8-byte aligned (MS-SMB2 2.2.3.1).
pub fn negotiate_body_with(
    dialects: &[u16],
    capabilities: u32,
    contexts: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut body = negotiate_body(dialects);
    put_u32(&mut body, 8, capabilities);
    if contexts.is_empty() {
        return body;
    }
    body.resize((HEADER + body.len()).next_multiple_of(8) - HEADER, 0);
    let offset = (HEADER + body.len()) as u32;
    put_u32(&mut body, 28, offset);
    put_u16(&mut body, 32, contexts.len() as u16);
    for (index, (kind, data)) in contexts.iter().enumerate() {
        if index > 0 {
            body.resize((HEADER + body.len()).next_multiple_of(8) - HEADER, 0);
        }
        body.extend(kind.to_le_bytes());
        body.extend((data.len() as u16).to_le_bytes());
        body.extend([0; 4]);
        body.extend(data);
    }
    body
}

/// SMB2_PREAUTH_INTEGRITY_CAPABILITIES listing `algorithms` with a 32-byte
/// salt.
pub fn preauth_context(algorithms: &[u16]) -> (u16, Vec<u8>) {
    let mut data = Vec::new();
    data.extend((algorithms.len() as u16).to_le_bytes());
    data.extend(32u16.to_le_bytes());
    for algorithm in algorithms {
        data.extend(algorithm.to_le_bytes());
    }
    data.extend([0x5a; 32]);
    (context::PREAUTH_INTEGRITY, data)
}

/// A context of `kind` that lists `identifiers` after their count, as the
/// encryption and signing contexts do.
pub fn list_context(kind: u16, identifiers: &[u16]) -> (u16, Vec<u8>) {
    let mut data = Vec::new();
    data.extend((identifiers.len() as u16).to_le_bytes());
    for identifier in identifiers {
        data.extend(identifier.to_le_bytes());
    }
    (kind, data)
}

/// NEGOTIATE offering `dialect` alone with SMB2_GLOBAL_CAP_ENCRYPTION, and
/// for SMB 3.1.1 the SHA-512 preauthentication context and the encryption
/// and signing contexts of `ciphers` and `signing` when they are not
/// empty.
pub fn smb3_negotiate_body(dialect: u16, ciphers: &[u16], signing: &[u16]) -> Vec<u8> {
    let mut contexts = Vec::new();
    if dialect == dialect::SMB_3_1_1 {
        contexts.push(preauth_context(&[context::SHA_512]));
        if !ciphers.is_empty() {
            contexts.push(list_context(context::ENCRYPTION, ciphers));
        }
        if !signing.is_empty() {
            contexts.push(list_context(context::SIGNING, signing));
        }
    }
    negotiate_body_with(&[dialect], CAP_ENCRYPTION, &contexts)
}

/// TREE_CONNECT request (MS-SMB2 2.2.9) for `share` on the test server.
pub fn tree_connect_body(share: &str) -> Vec<u8> {
    let path = utf16(&format!("\\\\TESTSRV\\{share}"));
    let mut body = vec![0u8; 8];
    put_u16(&mut body, 0, 9);
    put_u16(&mut body, 4, (HEADER + 8) as u16);
    put_u16(&mut body, 6, path.len() as u16);
    body.extend(path);
    body
}

/// SESSION_SETUP request (MS-SMB2 2.2.5).
pub fn session_setup_body(token: &[u8], security_mode: u8) -> Vec<u8> {
    let mut body = vec![0u8; 24];
    put_u16(&mut body, 0, 25);
    body[3] = security_mode;
    put_u16(&mut body, 12, (HEADER + 24) as u16);
    put_u16(&mut body, 14, token.len() as u16);
    body.extend_from_slice(token);
    body
}

/// CREATE request (MS-SMB2 2.2.13) with impersonation level
/// Impersonation and share access read, write, and delete.
pub fn create_body(
    name: &str,
    access: u32,
    disposition: u32,
    options: u32,
    contexts: &[u8],
) -> Vec<u8> {
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
    body.extend(&name);
    if contexts.is_empty() {
        // The buffer holds at least one byte.
        if name.is_empty() {
            body.push(0);
        }
    } else {
        body.resize(body.len().next_multiple_of(8), 0);
        let offset = (HEADER + body.len()) as u32;
        put_u32(&mut body, 48, offset);
        put_u32(&mut body, 52, contexts.len() as u32);
        body.extend_from_slice(contexts);
    }
    body
}

/// A create context without data (MS-SMB2 2.2.13.2).
pub fn create_context(name: &[u8; 4]) -> Vec<u8> {
    let mut context = vec![0u8; 24];
    put_u16(&mut context, 4, 16);
    put_u16(&mut context, 6, 4);
    context[16..20].copy_from_slice(name);
    context
}

pub fn close_body(file: FileId, flags: u16) -> Vec<u8> {
    let mut body = vec![0u8; 24];
    put_u16(&mut body, 0, 24);
    put_u16(&mut body, 2, flags);
    file.write(&mut body, 8);
    body
}

/// READ request (MS-SMB2 2.2.19) with its one-byte buffer.
pub fn read_body(file: FileId, offset: u64, length: u32) -> Vec<u8> {
    let mut body = vec![0u8; 49];
    put_u16(&mut body, 0, 49);
    put_u32(&mut body, 4, length);
    put_u64(&mut body, 8, offset);
    file.write(&mut body, 16);
    body
}

pub fn query_info_body(
    file: FileId,
    info_type: u8,
    class: u8,
    additional: u32,
    output_length: u32,
) -> Vec<u8> {
    let mut body = vec![0u8; 40];
    put_u16(&mut body, 0, 41);
    body[2] = info_type;
    body[3] = class;
    put_u32(&mut body, 4, output_length);
    put_u32(&mut body, 16, additional);
    file.write(&mut body, 24);
    // The buffer holds at least one byte.
    body.push(0);
    body
}

/// LOCK request (MS-SMB2 2.2.26).
pub fn lock_body(file: FileId, elements: &[LockElement]) -> Vec<u8> {
    let mut body = vec![0u8; 24];
    put_u16(&mut body, 0, 48);
    put_u16(&mut body, 2, elements.len() as u16);
    file.write(&mut body, 8);
    for element in elements {
        let mut entry = [0u8; 24];
        put_u64(&mut entry, 0, element.offset);
        put_u64(&mut entry, 8, element.length);
        put_u32(&mut entry, 16, element.flags);
        body.extend(entry);
    }
    body
}

/// IOCTL request (MS-SMB2 2.2.31) of an FSCTL.
pub fn ioctl_body(file: FileId, code: u32, input: &[u8], max_output: u32) -> Vec<u8> {
    let mut body = vec![0u8; 56];
    put_u16(&mut body, 0, 57);
    put_u32(&mut body, 4, code);
    file.write(&mut body, 8);
    put_u32(&mut body, 24, (HEADER + 56) as u32);
    put_u32(&mut body, 28, input.len() as u32);
    put_u32(&mut body, 44, max_output);
    // SMB2_0_IOCTL_IS_FSCTL.
    put_u32(&mut body, 48, 1);
    body.extend_from_slice(input);
    body
}

/// FILE_NOTIFY_INFORMATION records (MS-FSCC 2.4.42): action and name of
/// each.
pub fn notify_records(output: &[u8]) -> Vec<(u32, String)> {
    let mut records = Vec::new();
    let mut at = 0;
    loop {
        let next = u32_at(output, at) as usize;
        let action = u32_at(output, at + 4);
        let length = u32_at(output, at + 8) as usize;
        let units: Vec<u16> = output[at + 12..at + 12 + length]
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        records.push((action, String::from_utf16(&units).unwrap()));
        if next == 0 {
            return records;
        }
        assert_eq!(next % 4, 0, "record alignment");
        at += next;
    }
}
