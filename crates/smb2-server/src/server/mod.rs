//! Connection state machine: one [`Connection`] per transport connection,
//! and one [`Server`] shared by them.
//!
//! [`Connection::handle`] takes one transport message, which holds a
//! request or a compound chain of requests, and writes the replies into
//! the platform's response buffer. [`Connection::poll`] writes replies to
//! requests that completed later: change notifications, byte-range locks
//! that waited, and requests ended by a cancel or a close.

mod create;
mod credits;
mod directory;
mod error;
mod info;
mod io;
mod lock;
mod negotiate;
mod notify;
mod pending;
mod security;
mod session;
mod shared;
mod tables;
mod tree;
mod wire;

use core::time::Duration;

use self::credits::CreditWindow;
use self::error::Completion;
use self::error::RequestError;
use self::negotiate::GlobalCapabilities;
use self::negotiate::Negotiated;
use self::negotiate::SecurityMode;
use self::security::PreauthHash;
use self::security::SigningKey;
use self::shared::ChangeSequence;
use self::shared::LockOwner;
use self::tables::HeldEntry;
use self::tables::Open;
use self::tables::OpenKind;
use self::tables::OpenSlot;
use self::tables::PatternSlot;
use self::tables::Pending;
use self::tables::PipeSlot;
use self::tables::Session;
use self::tables::SessionSlot;
use self::tables::SessionState;
use self::tables::Tree;
use self::tables::TreeId;
use self::tables::TreeSlot;
use self::wire::AsyncId;
use self::wire::Command;
use self::wire::CreditCharge;
use self::wire::Credits;
use self::wire::HEADER_SIZE;
use self::wire::HeaderFlags;
use self::wire::MessageId;
use self::wire::header;
use crate::auth::Authenticator;
use crate::backend::Backend;
use crate::backend::ShareId;
use crate::fs::FileTime;
use crate::status::NtStatus;
use crate::transport;

pub use self::shared::ConnectionId;
pub use self::shared::SUPERSEDED_QUEUE;
pub use self::shared::Server;
pub use self::shared::SupersededSession;
pub use self::tables::SessionId;
pub use self::wire::Dialect;
pub use self::wire::FileId;

/// Sessions per connection.
pub const MAX_SESSIONS: usize = 4;
/// Tree connects per connection.
pub const MAX_TREES: usize = 16;
/// Opens per connection.
pub const MAX_OPENS: usize = 32;
/// Backend handles a connection holds at most: its opens and the
/// directories a change scan reads.
pub const MAX_HANDLES: usize = MAX_OPENS + pending::SCAN_HANDLES;
/// Named pipe opens per connection.
pub const MAX_PIPES: usize = 2;
/// Directory opens per connection with a search pattern other than `*`.
pub const MAX_PATTERNS: usize = 4;
/// Requests per connection waiting for a later reply.
pub const MAX_PENDING: usize = 8;
/// Largest read, write, or transaction payload.
const MAX_IO: usize = 0x1_0000;
/// Response buffer room kept for the headers of a compound chain around a
/// read of [`MAX_IO`] bytes.
const COMPOUND_RESERVE: usize = 0x400;

/// A GUID in its wire layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Guid(pub [u8; 16]);

/// Settings shared by every connection of a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerConfig {
    pub guid: Guid,
    /// When the server started.
    pub start_time: FileTime,
    /// Require signed messages on every authenticated session.
    pub signing_required: bool,
    /// Capacity of each request and response buffer the platform passes
    /// to [`Connection::handle`] and [`Connection::poll`], transport header
    /// included.
    pub buffer_size: usize,
    /// How often a directory with a change notification is scanned for
    /// changes made outside the server; `None` reports only changes made
    /// through the server.
    pub change_scan_interval: Option<Duration>,
    /// Require encrypted messages on every authenticated session of an SMB
    /// 3 dialect whose client supports encryption.
    pub encrypt_data: bool,
}

impl ServerConfig {
    /// MaxTransactSize, MaxReadSize, and MaxWriteSize.
    pub const fn max_io(&self) -> usize {
        let room = self.buffer_size.saturating_sub(COMPOUND_RESERVE);
        if room < MAX_IO { room } else { MAX_IO }
    }
}

/// What the platform does after [`Connection::handle`] or
/// [`Connection::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Send the first `length` bytes of the response buffer; they hold one
    /// or more messages, each after its transport header.
    Send { length: usize },
    /// Send nothing.
    Nothing,
    /// Close the transport connection.
    Disconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Negotiation {
    Initial,
    /// A multi-protocol negotiate was answered with the wildcard dialect;
    /// an SMB 2 negotiate follows.
    Wildcard,
    Done(Dialect),
}

/// State of one transport connection: dialect, sessions, tree connects,
/// opens, and requests waiting for a reply.
pub struct Connection {
    id: Option<ConnectionId>,
    negotiation: Negotiation,
    client_guid: Guid,
    /// Capabilities and security mode of the client's NEGOTIATE.
    client_capabilities: GlobalCapabilities,
    client_security_mode: SecurityMode,
    /// Dialect, cipher, and signing algorithm of the connection.
    negotiated: Option<Negotiated>,
    /// Preauthentication integrity hash of the NEGOTIATE (SMB 3.1.1).
    preauth: PreauthHash,
    credits: CreditWindow,
    sessions: [Option<Session>; MAX_SESSIONS],
    /// Authentication exchange of the session in the same slot.
    auths: [Authenticator; MAX_SESSIONS],
    trees: [Option<Tree>; MAX_TREES],
    opens: [Option<Open>; MAX_OPENS],
    pipes: [PipeSlot; MAX_PIPES],
    patterns: [PatternSlot; MAX_PATTERNS],
    held: HeldEntry,
    pending: [Option<Pending>; MAX_PENDING],
    /// The first change record this connection has not examined.
    change_cursor: ChangeSequence,
    next_tree_id: TreeId,
    next_file_id: FileId,
    next_async: AsyncId,
}

/// The parsed header of a request.
#[derive(Debug, Clone, Copy)]
struct RequestHeader {
    command: Command,
    credit_charge: CreditCharge,
    credit_request: Credits,
    flags: HeaderFlags,
    message_id: MessageId,
    async_id: AsyncId,
    tree_id: TreeId,
    session_id: SessionId,
}

impl RequestHeader {
    fn parse(message: &[u8]) -> Self {
        Self {
            command: Command(wire::u16_at(message, header::COMMAND)),
            credit_charge: CreditCharge(wire::u16_at(message, header::CREDIT_CHARGE)),
            credit_request: Credits(wire::u16_at(message, header::CREDITS)),
            flags: HeaderFlags(wire::u32_at(message, header::FLAGS)),
            message_id: MessageId(wire::u64_at(message, header::MESSAGE_ID)),
            async_id: AsyncId(wire::u64_at(message, header::ASYNC_ID)),
            tree_id: TreeId(wire::u32_at(message, header::TREE_ID)),
            session_id: SessionId(wire::u64_at(message, header::SESSION_ID)),
        }
    }

    fn related(&self) -> bool {
        self.flags.contains(HeaderFlags::RELATED_OPERATIONS)
    }

    fn signed(&self) -> bool {
        self.flags.contains(HeaderFlags::SIGNED)
    }

    fn asynchronous(&self) -> bool {
        self.flags.contains(HeaderFlags::ASYNC_COMMAND)
    }
}

/// One request being handled.
struct Exchange<'a> {
    config: ServerConfig,
    /// The request: header and body.
    message: &'a [u8],
    header: RequestHeader,
    session: Option<SessionSlot>,
    tree: Option<TreeSlot>,
    /// In a related compound chain, the open of the preceding request.
    related_file: Option<Result<FileId, RequestError>>,
    /// The open the request named, once found.
    named_file: core::cell::Cell<Option<FileId>>,
    /// The request is the last of its chain, so it may complete later.
    last: bool,
    /// The request arrived encrypted.
    encrypted: bool,
}

impl Exchange<'_> {
    fn body(&self) -> &[u8] {
        &self.message[HEADER_SIZE..]
    }

    /// The body when it holds at least `fixed` bytes and declares
    /// `structure_size`.
    fn fixed_body(&self, structure_size: u16, fixed: usize) -> Result<&[u8], Failure> {
        let body = self.body();
        if body.len() < fixed || wire::u16_at(body, 0) != structure_size {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }
        Ok(body)
    }
}

/// A reply body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Body {
    completion: Completion,
    length: usize,
}

impl Body {
    const fn success(length: usize) -> Self {
        Self {
            completion: Completion::Success,
            length,
        }
    }
}

/// A request that ends without a regular body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// An error reply.
    Error(RequestError),
    /// The output buffer is smaller than the information; the error reply
    /// carries the required length.
    TooSmall { required: u32 },
    /// The request completes later; the reply now is an interim
    /// STATUS_PENDING with this async identifier.
    Pending { async_id: AsyncId },
    /// A protocol violation that ends the connection.
    Disconnect,
}

impl<E: Into<RequestError>> From<E> for Failure {
    fn from(error: E) -> Self {
        Self::Error(error.into())
    }
}

type Handled = Result<Body, Failure>;

/// Bytes of an error reply body.
const ERROR_BODY: usize = 9;
/// Reply room a request needs before it is handled: the largest fixed
/// reply, a CREATE reply with both create context replies (176 bytes).
/// Variable parts beyond it check their own room.
const REPLY_RESERVE: usize = 176;

/// A reply waiting for its signature until its length is final.
#[derive(Clone, Copy)]
struct Unsigned {
    start: usize,
    key: SigningKey,
}

impl Connection {
    pub const fn new() -> Self {
        Self {
            id: None,
            negotiation: Negotiation::Initial,
            client_guid: Guid([0; 16]),
            client_capabilities: GlobalCapabilities::NONE,
            client_security_mode: SecurityMode(0),
            negotiated: None,
            preauth: PreauthHash::ZERO,
            credits: CreditWindow::new(),
            sessions: [None; MAX_SESSIONS],
            auths: [const { Authenticator::new() }; MAX_SESSIONS],
            trees: [None; MAX_TREES],
            opens: [None; MAX_OPENS],
            pipes: [const { PipeSlot::new() }; MAX_PIPES],
            patterns: [const { PatternSlot::new() }; MAX_PATTERNS],
            held: HeldEntry::new(),
            pending: [None; MAX_PENDING],
            change_cursor: ChangeSequence(0),
            next_tree_id: TreeId::FIRST,
            next_file_id: FileId::FIRST,
            next_async: AsyncId::FIRST,
        }
    }

    /// The negotiated dialect.
    pub fn dialect(&self) -> Option<Dialect> {
        match self.negotiation {
            Negotiation::Done(dialect) => Some(dialect),
            Negotiation::Initial | Negotiation::Wildcard => None,
        }
    }

    /// Whether a session has completed authentication.
    pub fn has_sessions(&self) -> bool {
        self.sessions
            .iter()
            .any(|session| session.is_some_and(|session| session.state == SessionState::Valid))
    }

    /// Whether a file or pipe is open.
    pub fn has_opens(&self) -> bool {
        self.opens.iter().any(Option::is_some)
    }

    /// The share of each disk tree connect.
    pub fn shares(&self) -> impl Iterator<Item = ShareId> + '_ {
        self.trees
            .iter()
            .filter_map(|tree| match tree.as_ref()?.kind {
                tables::TreeKind::Disk { share, .. } => Some(share),
                tables::TreeKind::Pipe => None,
            })
    }

    /// Handle one message: `request` is a message without its transport
    /// header. The reply goes into `response`, transport header first.
    #[inline(never)]
    pub fn handle(
        &mut self,
        server: &mut Server,
        backend: &mut dyn Backend,
        request: &mut [u8],
        response: &mut [u8],
    ) -> Reply {
        let Some(config) = server.config().copied() else {
            return Reply::Disconnect;
        };
        if response.len() < transport::HEADER_LENGTH + HEADER_SIZE + ERROR_BODY {
            return Reply::Disconnect;
        }
        if self.id.is_none() {
            self.id = Some(server.attach());
            self.change_cursor = server.changes.next();
        }
        let end = match request.get(..4) {
            Some(id) if id == wire::SMB1_PROTOCOL_ID => {
                self.negotiate_multi_protocol(&config, backend, request, response)
            }
            Some(id) if id == wire::PROTOCOL_ID => self.handle_chain(
                server,
                config,
                backend,
                request,
                response,
                transport::HEADER_LENGTH,
                None,
            ),
            Some(id) if id == security::TRANSFORM_PROTOCOL_ID => {
                self.handle_encrypted(server, config, backend, request, response)
            }
            _ => None,
        };
        if let Some(end) = end
            && end > 0
        {
            let length = end - transport::HEADER_LENGTH;
            response[..transport::HEADER_LENGTH].copy_from_slice(&transport::header(length));
        }
        let Some(end) = end else {
            return Reply::Disconnect;
        };
        let end = self.write_ready(server, response, end);
        frame_reply(end)
    }

    /// Decrypt a message after a transform header (MS-SMB2 3.3.5.2.1.1),
    /// handle its chain, and encrypt the replies; returns their end.
    fn handle_encrypted(
        &mut self,
        server: &mut Server,
        config: ServerConfig,
        backend: &mut dyn Backend,
        request: &mut [u8],
        response: &mut [u8],
    ) -> Option<usize> {
        if request.len() < security::TRANSFORM_HEADER {
            return None;
        }
        let session_id = security::transform_session(request);
        let slot = self.find_session(session_id)?;
        let session = self.sessions[usize::from(slot.0)].as_mut()?;
        let keys = session.encryption?;
        let length = security::decrypt(request, &keys)?;
        // The reply's nonce is taken first: a LOGOFF in the chain removes
        // the session, and its reply is still encrypted.
        let nonce = session.next_nonce;
        session.next_nonce = nonce.next();
        let message = &request[security::TRANSFORM_HEADER..security::TRANSFORM_HEADER + length];
        if message.get(..4) != Some(&wire::PROTOCOL_ID[..]) {
            return None;
        }
        let base = transport::HEADER_LENGTH + security::TRANSFORM_HEADER;
        let end =
            self.handle_chain(server, config, backend, message, response, base, Some(slot))?;
        if end == 0 {
            return Some(0);
        }
        security::encrypt(
            &mut response[transport::HEADER_LENGTH..end],
            &keys,
            session_id,
            nonce,
        )?;
        Some(end)
    }

    /// Write replies to requests that completed since the last call:
    /// change notifications, granted locks, and scans for changes made
    /// outside the server when due. `response` is the same kind of
    /// buffer as for [`Connection::handle`].
    #[inline(never)]
    pub fn poll(
        &mut self,
        server: &mut Server,
        backend: &mut dyn Backend,
        response: &mut [u8],
    ) -> Reply {
        let Some(config) = server.config().copied() else {
            return Reply::Nothing;
        };
        if self.id.is_none() {
            return Reply::Nothing;
        }
        self.advance(server, &config, backend);
        let end = self.write_ready(server, response, 0);
        frame_reply(end)
    }

    /// Whether [`Connection::poll`] has work: changes not yet examined, a
    /// lock request that may be granted, or a reply ready to send. Scans
    /// for outside changes are not counted; the platform polls on a timer
    /// for them.
    pub fn wants_poll(&self, server: &Server) -> bool {
        self.id.is_some()
            && (self.change_cursor != server.changes.next()
                || self.pending.iter().flatten().any(|pending| {
                    pending.ready.is_some()
                        || matches!(pending.kind, tables::PendingKind::Lock { epoch, .. } if epoch != server.locks.epoch())
                }))
    }

    /// Release every open and session; the platform calls this when the
    /// transport connection ends. The connection is then in its initial
    /// state and may serve a new transport connection.
    pub fn close(&mut self, server: &mut Server, backend: &mut dyn Backend) {
        self.pending = [None; MAX_PENDING];
        for index in 0..MAX_OPENS {
            self.close_open(OpenSlot(index as u8), server, backend);
        }
        self.trees = [None; MAX_TREES];
        self.sessions = [None; MAX_SESSIONS];
        for auth in &mut self.auths {
            auth.reset();
        }
        self.id = None;
        self.negotiation = Negotiation::Initial;
        self.client_guid = Guid([0; 16]);
        self.client_capabilities = GlobalCapabilities::NONE;
        self.client_security_mode = SecurityMode(0);
        self.negotiated = None;
        self.preauth = PreauthHash::ZERO;
        self.credits = CreditWindow::new();
        self.next_tree_id = TreeId::FIRST;
        self.next_file_id = FileId::FIRST;
        self.next_async = AsyncId::FIRST;
    }

    /// Handle a chain of requests, writing replies from `base`; returns
    /// the end of the replies in `response`, 0 when there are none, or
    /// `None` to disconnect. `encrypted` names the session whose key
    /// decrypted the chain.
    #[allow(clippy::too_many_arguments)]
    fn handle_chain(
        &mut self,
        server: &mut Server,
        config: ServerConfig,
        backend: &mut dyn Backend,
        request: &[u8],
        response: &mut [u8],
        base: usize,
        encrypted: Option<SessionSlot>,
    ) -> Option<usize> {
        let mut offset = 0;
        let mut end = base;
        let mut previous_reply: Option<usize> = None;
        let mut unsigned: Option<Unsigned> = None;
        let mut previous_session = None;
        let mut previous_tree = None;
        let mut related_file: Option<Result<FileId, RequestError>> = None;
        loop {
            let rest = &request[offset..];
            if rest.len() < HEADER_SIZE
                || rest[..4] != wire::PROTOCOL_ID
                || wire::u16_at(rest, header::STRUCTURE_SIZE) != HEADER_SIZE as u16
            {
                return None;
            }
            let next = wire::u32_at(rest, header::NEXT_COMMAND) as usize;
            let length = match next {
                0 => rest.len(),
                next if next.is_multiple_of(8) && next >= HEADER_SIZE && next <= rest.len() => next,
                _ => return None,
            };
            let message = &rest[..length];
            let header = RequestHeader::parse(message);
            if header.command == Command::CANCEL {
                // A cancel has no reply of its own; the request it names
                // gets its final reply.
                self.cancel(&header, message, encrypted);
            } else {
                if header.asynchronous() || !self.credits.consume(header.message_id) {
                    return None;
                }
                let start = match previous_reply {
                    Some(previous) => {
                        // Replies align to 8 bytes from the first SMB 2
                        // header.
                        let start = base + wire::align8(end - base);
                        if start + HEADER_SIZE + ERROR_BODY > response.len() {
                            return None;
                        }
                        response[end..start].fill(0);
                        wire::put_u32(
                            response,
                            previous + header::NEXT_COMMAND,
                            (start - previous) as u32,
                        );
                        start
                    }
                    None => end,
                };
                if let Some(pending) = unsigned.take() {
                    security::sign(&mut response[pending.start..start], &pending.key);
                }
                let related = header.related();
                let (session_id, tree_id) = if related && previous_reply.is_some() {
                    (
                        previous_session.unwrap_or(header.session_id),
                        previous_tree.unwrap_or(header.tree_id),
                    )
                } else {
                    (header.session_id, header.tree_id)
                };
                let reply = self.handle_request(
                    server,
                    config,
                    backend,
                    message,
                    header,
                    RequestIds {
                        session: session_id,
                        tree: tree_id,
                        related_file: if related { related_file } else { None },
                        first: previous_reply.is_none(),
                        last: next == 0,
                        encrypted,
                    },
                    &mut response[start..],
                )?;
                let written = &response[start..start + reply.length];
                match header.command {
                    Command::NEGOTIATE => self.hash_negotiate(message, written),
                    Command::SESSION_SETUP if reply.more_processing => {
                        self.hash_setup_reply(reply.session_id, written);
                    }
                    _ => {}
                }
                previous_session = Some(reply.session_id);
                previous_tree = Some(reply.tree_id);
                if let Some(file) = reply.file {
                    related_file = Some(file);
                }
                end = start + reply.length;
                if let Some(key) = reply.sign_with {
                    unsigned = Some(Unsigned { start, key });
                }
                previous_reply = Some(start);
            }
            if next == 0 {
                break;
            }
            offset += next;
        }
        if let Some(pending) = unsigned {
            security::sign(&mut response[pending.start..end], &pending.key);
        }
        if previous_reply.is_none() {
            // A chain of cancels only: no frame was written.
            return Some(0);
        }
        Some(end)
    }

    /// Handle one request of a chain and write its reply at the start of
    /// `output`.
    #[allow(clippy::too_many_arguments)]
    fn handle_request(
        &mut self,
        server: &mut Server,
        config: ServerConfig,
        backend: &mut dyn Backend,
        message: &[u8],
        header: RequestHeader,
        ids: RequestIds,
        output: &mut [u8],
    ) -> Option<WrittenReply> {
        let mut exchange = Exchange {
            config,
            message,
            header,
            session: None,
            tree: None,
            related_file: ids.related_file,
            named_file: core::cell::Cell::new(None),
            last: ids.last,
            encrypted: ids.encrypted.is_some(),
        };
        let mut reply_session = ids.session;
        let mut reply_tree = ids.tree;
        let mut sign_with = None;
        let mut file = None;

        let result = (|| -> Handled {
            if header.related() && ids.first {
                return Err(Failure::Error(RequestError::InvalidRequest));
            }
            if output.len() < HEADER_SIZE + REPLY_RESERVE {
                return Err(Failure::Error(RequestError::TableFull));
            }
            match (self.negotiation, header.command) {
                (Negotiation::Done(_), Command::NEGOTIATE) => return Err(Failure::Disconnect),
                (_, Command::NEGOTIATE) => {
                    return self.negotiate(&exchange, backend, &mut output[HEADER_SIZE..]);
                }
                (Negotiation::Done(_), _) => {}
                _ => return Err(Failure::Disconnect),
            }
            // A message decrypted with one session's key names that session
            // (MS-SMB2 3.3.5.2.1.1).
            if let Some(decrypted) = ids.encrypted
                && self.find_session(ids.session) != Some(decrypted)
            {
                return Err(Failure::Disconnect);
            }
            if header.command == Command::ECHO {
                return echo(&exchange, &mut output[HEADER_SIZE..]);
            }
            if header.command == Command::SESSION_SETUP {
                let (handled, session) = self.session_setup(
                    &mut exchange,
                    ids.session,
                    server,
                    backend,
                    &mut output[HEADER_SIZE..],
                );
                if let Some((id, key)) = session {
                    reply_session = id;
                    sign_with = key.filter(|_| !exchange.encrypted);
                }
                return handled;
            }
            let session = self.verified_session(&exchange, ids.session)?;
            exchange.session = Some(session);
            // Replies to encrypted requests are encrypted instead of signed
            // (MS-SMB2 3.3.4.1.1).
            sign_with = self.sessions[usize::from(session.0)]
                .as_ref()
                .and_then(|session| {
                    session
                        .signing
                        .filter(|_| session.signing_required || header.signed())
                })
                .filter(|_| !exchange.encrypted);
            match header.command {
                Command::LOGOFF => {
                    return self.logoff(&exchange, server, backend, &mut output[HEADER_SIZE..]);
                }
                Command::TREE_CONNECT => {
                    let (body, id) =
                        self.tree_connect(&exchange, backend, &mut output[HEADER_SIZE..])?;
                    reply_tree = id;
                    return Ok(body);
                }
                _ => {}
            }
            let tree = self.find_tree(session, ids.tree)?;
            exchange.tree = Some(tree);
            let output = &mut output[HEADER_SIZE..];
            match header.command {
                Command::TREE_DISCONNECT => {
                    self.tree_disconnect(&exchange, server, backend, output)
                }
                Command::CREATE => {
                    let handled = self.create(&exchange, server, backend, output);
                    file = Some(handled.as_ref().map(|body| body.1).map_err(
                        |failure| match failure {
                            Failure::Error(error) => *error,
                            _ => RequestError::InvalidRequest,
                        },
                    ));
                    handled.map(|body| body.0)
                }
                Command::CLOSE => self.close_request(&exchange, server, backend, output),
                Command::FLUSH => self.flush(&exchange, backend, output),
                Command::READ => self.read(&exchange, server, backend, output),
                Command::WRITE => self.write(&exchange, server, backend, output),
                Command::LOCK => self.lock(&exchange, server, output),
                Command::IOCTL => self.ioctl(&exchange, backend, output),
                Command::QUERY_DIRECTORY => self.query_directory(&exchange, backend, output),
                Command::CHANGE_NOTIFY => self.change_notify(&exchange, server, backend, output),
                Command::QUERY_INFO => self.query_info(&exchange, server, backend, output),
                Command::SET_INFO => self.set_info(&exchange, server, backend, output),
                _ => Err(Failure::Error(RequestError::InvalidRequest)),
            }
        })();

        let mut flags = HeaderFlags::SERVER_TO_REDIR
            .union(header.flags.intersection(HeaderFlags::RELATED_OPERATIONS));
        let mut async_id = None;
        let more_processing =
            matches!(&result, Ok(body) if body.completion == Completion::MoreProcessingRequired);
        let (status, body_length): (NtStatus, usize) = match result {
            Ok(body) => (body.completion.into(), body.length),
            Err(Failure::Disconnect) => return None,
            Err(Failure::Error(error)) => (
                error.into(),
                write_error_body(&mut output[HEADER_SIZE..], None),
            ),
            Err(Failure::TooSmall { required }) => (
                NtStatus::BufferTooSmall,
                write_error_body(&mut output[HEADER_SIZE..], Some(required)),
            ),
            Err(Failure::Pending { async_id: id }) => {
                // Interim replies are not signed (MS-SMB2 3.3.4.1.1).
                sign_with = None;
                flags = flags.union(HeaderFlags::ASYNC_COMMAND);
                async_id = Some(id);
                (
                    NtStatus::Pending,
                    write_error_body(&mut output[HEADER_SIZE..], None),
                )
            }
        };
        if file.is_none() {
            // A request that names an open passes it on to the next
            // related request (MS-SMB2 3.3.5.2.7.2); a related request
            // that found none passes on what it received.
            file = match exchange.named_file.get() {
                Some(id) => Some(Ok(id)),
                None => exchange.related_file.filter(|_| header.related()),
            };
        }
        let granted = self.credits.grant(header.credit_request);
        if sign_with.is_some() {
            flags = flags.union(HeaderFlags::SIGNED);
        }
        output[..HEADER_SIZE].fill(0);
        output[..4].copy_from_slice(&wire::PROTOCOL_ID);
        wire::put_u16(output, header::STRUCTURE_SIZE, HEADER_SIZE as u16);
        wire::put_u16(output, header::CREDIT_CHARGE, header.credit_charge.0);
        wire::put_u32(output, header::STATUS, status.raw());
        wire::put_u16(output, header::COMMAND, header.command.0);
        wire::put_u16(output, header::CREDITS, granted.0);
        wire::put_u32(output, header::FLAGS, flags.0);
        wire::put_u64(output, header::MESSAGE_ID, header.message_id.0);
        match async_id {
            Some(id) => wire::put_u64(output, header::ASYNC_ID, id.0),
            None => wire::put_u32(output, header::TREE_ID, reply_tree.0),
        }
        wire::put_u64(output, header::SESSION_ID, reply_session.0);
        Some(WrittenReply {
            length: HEADER_SIZE + body_length,
            session_id: reply_session,
            tree_id: reply_tree,
            file,
            sign_with,
            more_processing,
        })
    }

    /// The valid session `id`, after the signature and encryption checks
    /// of the request.
    fn verified_session(
        &self,
        exchange: &Exchange<'_>,
        id: SessionId,
    ) -> Result<SessionSlot, Failure> {
        let slot = self.find_session(id).ok_or(RequestError::SessionNotFound)?;
        let session = self.sessions[usize::from(slot.0)]
            .as_ref()
            .ok_or(RequestError::SessionNotFound)?;
        if session.state != SessionState::Valid {
            return Err(Failure::Error(RequestError::SessionNotFound));
        }
        if !exchange.encrypted {
            if session.encrypt_data {
                return Err(Failure::Error(RequestError::AccessDenied));
            }
            check_signature(exchange, session)?;
        }
        Ok(slot)
    }

    fn find_session(&self, id: SessionId) -> Option<SessionSlot> {
        self.sessions
            .iter()
            .position(|session| session.is_some_and(|session| session.id == id))
            .map(|index| SessionSlot(index as u8))
    }

    fn find_tree(&self, session: SessionSlot, id: TreeId) -> Result<TreeSlot, Failure> {
        self.trees
            .iter()
            .position(|tree| tree.is_some_and(|tree| tree.id == id && tree.session == session))
            .map(|index| TreeSlot(index as u8))
            .ok_or(Failure::Error(RequestError::TreeNotFound))
    }

    fn tree(&self, slot: TreeSlot) -> &Tree {
        self.trees[usize::from(slot.0)]
            .as_ref()
            .expect("tree slot of a handled request is occupied")
    }

    /// The open a request names, resolving the related-compound file
    /// identifier.
    fn find_open(&self, exchange: &Exchange<'_>, id: FileId) -> Result<OpenSlot, Failure> {
        let id = if id == FileId::RELATED {
            match exchange.related_file {
                Some(Ok(id)) => id,
                Some(Err(status)) => return Err(Failure::Error(status)),
                None => return Err(Failure::Error(RequestError::OpenNotFound)),
            }
        } else {
            id
        };
        let slot = self
            .opens
            .iter()
            .position(|open| {
                open.is_some_and(|open| {
                    open.id == id
                        && Some(open.session) == exchange.session
                        && Some(open.tree) == exchange.tree
                })
            })
            .map(|index| OpenSlot(index as u8))
            .ok_or(Failure::Error(RequestError::OpenNotFound))?;
        exchange.named_file.set(Some(id));
        Ok(slot)
    }

    fn open(&self, slot: OpenSlot) -> &Open {
        self.opens[usize::from(slot.0)]
            .as_ref()
            .expect("open slot of a handled request is occupied")
    }

    fn open_mut(&mut self, slot: OpenSlot) -> &mut Open {
        self.opens[usize::from(slot.0)]
            .as_mut()
            .expect("open slot of a handled request is occupied")
    }

    /// The byte-range lock owner of the open `id` on this connection.
    fn lock_owner(&self, id: FileId) -> LockOwner {
        LockOwner {
            connection: self.id.expect("a handled request has a connection id"),
            open: id,
        }
    }

    /// Close the open in `slot` if there is one, releasing its pipe,
    /// pattern, held entry, locks, and file table entry, and ending the
    /// requests that wait on it.
    fn close_open(&mut self, slot: OpenSlot, server: &mut Server, backend: &mut dyn Backend) {
        let Some(open) = self.opens[usize::from(slot.0)].take() else {
            return;
        };
        for pending in self.pending.iter_mut().flatten() {
            if pending.open == slot && pending.ready.is_none() {
                pending.ready = Some(match pending.kind {
                    tables::PendingKind::Notify { .. } => tables::PendingOutcome::Closed,
                    tables::PendingKind::Lock { .. } => tables::PendingOutcome::Cancelled,
                });
            }
        }
        match open.kind {
            OpenKind::File(file) => {
                if let Some(connection) = self.id {
                    server.locks.release_owner(LockOwner {
                        connection,
                        open: open.id,
                    });
                }
                backend.close(file.handle);
                let last = server.files.opens(file.file) == 1;
                if last && server.files.delete_pending(file.file) {
                    // The last close of a file marked for deletion removes
                    // it.
                    record_change(
                        server,
                        file.file,
                        shared::ChangeAction::Removed,
                        shared::ChangeFilter::name(file.directory),
                    );
                }
                server.files.release(file.file);
            }
            OpenKind::Pipe(pipe) => {
                self.pipes[usize::from(pipe.0)] = PipeSlot::new();
            }
        }
        for pattern in &mut self.patterns {
            if pattern.owner == Some(slot) {
                pattern.owner = None;
            }
        }
        if self.held.owner == Some(slot) {
            self.held.owner = None;
        }
    }

    /// Close every open of a tree or session.
    fn close_opens_where(
        &mut self,
        server: &mut Server,
        backend: &mut dyn Backend,
        matches: impl Fn(&Open) -> bool,
    ) {
        for index in 0..MAX_OPENS {
            if self.opens[index].as_ref().is_some_and(&matches) {
                self.close_open(OpenSlot(index as u8), server, backend);
            }
        }
    }
}

/// Session and tree a request applies to, after compound resolution.
#[derive(Debug, Clone, Copy)]
struct RequestIds {
    session: SessionId,
    tree: TreeId,
    related_file: Option<Result<FileId, RequestError>>,
    /// First request of its chain.
    first: bool,
    /// Last request of its chain.
    last: bool,
    /// The session whose key decrypted the request.
    encrypted: Option<SessionSlot>,
}

/// A reply written at the start of the output.
struct WrittenReply {
    /// Header and body.
    length: usize,
    session_id: SessionId,
    tree_id: TreeId,
    /// The open the request created or named, for the next related
    /// request.
    file: Option<Result<FileId, RequestError>>,
    sign_with: Option<SigningKey>,
    /// The reply continues an authentication exchange.
    more_processing: bool,
}

/// What to send for replies that end at `end`.
fn frame_reply(end: usize) -> Reply {
    if end == 0 {
        return Reply::Nothing;
    }
    Reply::Send { length: end }
}

/// Record a change of the file in `slot` in the server's change log.
fn record_change(
    server: &mut Server,
    slot: shared::FileSlot,
    action: shared::ChangeAction,
    filter: shared::ChangeFilter,
) {
    let share = server.files.share(slot);
    let path = server.files.path(slot);
    let (parent, name) = split_parent(path);
    server.changes.record(share, parent, name, action, filter);
}

/// A path's parent and last component.
fn split_parent(path: &[u16]) -> (&[u16], &[u16]) {
    match path.iter().rposition(|&unit| unit == u16::from(b'\\')) {
        Some(index) => (&path[..index], &path[index + 1..]),
        None => (&[], path),
    }
}

/// Write an error body; returns its length.
fn write_error_body(output: &mut [u8], required: Option<u32>) -> usize {
    output[..ERROR_BODY].fill(0);
    wire::put_u16(output, 0, ERROR_BODY as u16);
    match required {
        Some(required) if output.len() >= 12 => {
            wire::put_u32(output, 4, 4);
            wire::put_u32(output, 8, required);
            12
        }
        _ => ERROR_BODY,
    }
}

/// ECHO (MS-SMB2 3.3.5.17).
fn echo(exchange: &Exchange<'_>, output: &mut [u8]) -> Handled {
    exchange.fixed_body(4, 4)?;
    Ok(Body::success(empty_body(output)))
}

/// Write the four-byte body of LOGOFF, TREE_DISCONNECT, FLUSH, LOCK, and
/// ECHO replies.
fn empty_body(output: &mut [u8]) -> usize {
    wire::put_u32(output, 0, 4);
    4
}

/// Check a request's signature against its session (MS-SMB2 3.3.5.2.4).
fn check_signature(exchange: &Exchange<'_>, session: &Session) -> Result<(), Failure> {
    if !exchange.header.signed() {
        if session.signing_required {
            return Err(Failure::Error(RequestError::AccessDenied));
        }
        return Ok(());
    }
    let Some(key) = session.signing else {
        return Err(Failure::Error(RequestError::AccessDenied));
    };
    if !security::verify(exchange.message, &key) {
        return Err(Failure::Error(RequestError::AccessDenied));
    }
    Ok(())
}
