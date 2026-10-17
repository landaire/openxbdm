//! SMB transport connections over the platform's sockets.

use core::time::Duration;

use smb2_server::Connection;
use smb2_server::Reply;
use smb2_server::ServerConfig;
use smb2_server::fs::FileTime;
use smb2_server::server::Guid;
use smb2_server::server::Server;
use smb2_server::transport;
use smb2_server::transport::Frame;
use smb2_server::transport::HEADER_LENGTH;

use super::adapter::Adapter;
use super::adapter::ConnectionFiles;
use super::limits;
use super::limits::Activity;
use super::limits::Usage;
use super::shares::Presence;
use super::shares::ShareBindings;
use crate::commands::filesystem::ScratchBlock;
use crate::network::NetError;
use crate::network::Network;
use crate::network::SocketId;
use crate::state::ServerState;

/// Bytes of each request and response buffer, transport header included:
/// a 64 KiB read or write and the headers around it.
pub const BUFFER_SIZE: usize = 0x1_0000 + 0x400;
/// How often a directory watched by a change notification is compared
/// with its last listing, to report changes made by titles and XBDM.
const CHANGE_SCAN_INTERVAL: Duration = Duration::from_secs(2);

/// Progress of the message being received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Receive {
    /// Bytes of the transport header received.
    Header(usize),
    /// Bytes received of a message of `length` bytes.
    Message { length: usize, received: usize },
}

/// A reply in the response buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sending {
    length: usize,
    sent: usize,
}

/// Pool blocks of a connection: the request, transport header first, and
/// the response.
struct Buffers {
    input: ScratchBlock,
    output: ScratchBlock,
}

/// The connection has ended.
struct Closed;

struct Slot {
    socket: Option<SocketId>,
    activity: Activity,
    connection: Connection,
    files: ConnectionFiles,
    buffers: Option<Buffers>,
    receive: Receive,
    sending: Option<Sending>,
}

impl Slot {
    fn usage(&self) -> Usage {
        Usage {
            session: self.connection.has_sessions(),
            opens: self.connection.has_opens(),
            in_transfer: self.receive != Receive::Header(0) || self.sending.is_some(),
        }
    }

    const fn new() -> Self {
        Self {
            socket: None,
            activity: Activity::new(FileTime(0)),
            connection: Connection::new(),
            files: ConnectionFiles::new(),
            buffers: None,
            receive: Receive::Header(0),
            sending: None,
        }
    }
}

/// Up to `N` SMB connections. The platform reports readiness of their
/// sockets: readable while [`SmbService::wants_write`] is false, writable
/// while it is true, and calls [`SmbService::poll_timers`] periodically.
/// Each connection holds two pool blocks of [`BUFFER_SIZE`] bytes.
///
/// A connection closes when it has no session 30 seconds after it was
/// accepted, when a message or reply in transfer makes no progress for 30
/// seconds, and when it sends no request for 15 minutes while it has no
/// open files. When every slot is in use, a new connection replaces the
/// earliest accepted one without a session, or else the one that sent no
/// request for the longest time if that is at least five minutes.
pub struct SmbService<const N: usize> {
    shared: Shared,
    slots: [Slot; N],
}

/// State the service's connections share.
struct Shared {
    server: Server,
    shares: ShareBindings,
}

impl<const N: usize> SmbService<N> {
    pub const fn new() -> Self {
        Self {
            shared: Shared {
                server: Server::new(),
                shares: ShareBindings::new(),
            },
            slots: [const { Slot::new() }; N],
        }
    }

    /// Free the share identifiers no tree of any connection uses.
    fn retain_shares(&mut self) {
        self.shared
            .shares
            .retain(self.slots.iter().flat_map(|slot| slot.connection.shares()));
    }

    /// Choose the server GUID and record the start time. Connections are
    /// accepted only after this.
    pub fn start(&mut self, backend: &mut dyn crate::backend::Backend) {
        let mut guid = [0u8; 16];
        backend.random_bytes(&mut guid);
        self.shared.server.configure(ServerConfig {
            guid: Guid(guid),
            start_time: FileTime(backend.system_time()),
            signing_required: false,
            buffer_size: BUFFER_SIZE,
            change_scan_interval: Some(CHANGE_SCAN_INTERVAL),
            encrypt_data: false,
        });
    }

    /// Open sockets and whether each waits to send.
    pub fn sockets(&self) -> impl Iterator<Item = (SocketId, bool)> + '_ {
        self.slots
            .iter()
            .filter_map(|slot| Some((slot.socket?, slot.sending.is_some())))
    }

    pub fn contains(&self, socket: SocketId) -> bool {
        self.position(socket).is_some()
    }

    /// Whether `socket` has a reply to send before it reads again.
    pub fn wants_write(&self, socket: SocketId) -> bool {
        self.position(socket)
            .is_some_and(|index| self.slots[index].sending.is_some())
    }

    fn position(&self, socket: SocketId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.socket == Some(socket))
    }

    /// Take a new connection, or close it when the service is not started
    /// or has no slot, socket mode, or pool memory.
    #[inline(never)]
    pub fn accept(
        &mut self,
        socket: SocketId,
        state: &ServerState,
        backend: &mut dyn crate::backend::Backend,
        network: &mut dyn Network,
    ) {
        let index = match self.shared.server.config() {
            Some(_) => self.free_slot(state, backend, network),
            None => None,
        };
        let Some(index) = index else {
            network.close(socket);
            return;
        };
        if network.set_blocking(socket, false).is_err() {
            network.close(socket);
            return;
        }
        let Some(input) = backend.allocate_scratch(BUFFER_SIZE as u32) else {
            network.close(socket);
            return;
        };
        let Some(output) = backend.allocate_scratch(BUFFER_SIZE as u32) else {
            backend.free_scratch(input);
            network.close(socket);
            return;
        };
        // Closing the slot's previous connection reset its state.
        let slot = &mut self.slots[index];
        slot.socket = Some(socket);
        slot.activity = Activity::new(FileTime(backend.system_time()));
        slot.buffers = Some(Buffers { input, output });
    }

    /// A slot without a connection, made when every slot is in use by
    /// closing the connection [`limits::eviction`] chooses.
    fn free_slot(
        &mut self,
        state: &ServerState,
        backend: &mut dyn crate::backend::Backend,
        network: &mut dyn Network,
    ) -> Option<usize> {
        if let Some(index) = self.slots.iter().position(|slot| slot.socket.is_none()) {
            return Some(index);
        }
        let now = FileTime(backend.system_time());
        let index = limits::eviction(
            self.slots
                .iter()
                .enumerate()
                .map(|(index, slot)| (index, slot.activity, slot.connection.has_sessions())),
            now,
        )?;
        close_slot(
            &mut self.slots[index],
            &mut self.shared,
            state,
            backend,
            network,
        );
        self.retain_shares();
        Some(index)
    }

    /// Close the connections that exceeded a time limit, and send the
    /// replies to requests that completed since: change notifications and
    /// byte-range locks.
    #[inline(never)]
    pub fn poll_timers(
        &mut self,
        state: &ServerState,
        backend: &mut dyn crate::backend::Backend,
        network: &mut dyn Network,
    ) {
        if self.slots.iter().all(|slot| slot.socket.is_none()) {
            return;
        }
        let now = FileTime(backend.system_time());
        for slot in &mut self.slots {
            if slot.socket.is_some() && slot.activity.expiry(slot.usage(), now).is_some() {
                close_slot(slot, &mut self.shared, state, backend, network);
            }
        }
        for slot in &mut self.slots {
            if complete(slot, &mut self.shared, state, backend, network, now).is_err() {
                close_slot(slot, &mut self.shared, state, backend, network);
            }
        }
        self.retain_shares();
    }

    /// Receive from `socket` and handle the message once it is complete.
    #[inline(never)]
    pub fn on_readable(
        &mut self,
        socket: SocketId,
        state: &ServerState,
        backend: &mut dyn crate::backend::Backend,
        network: &mut dyn Network,
    ) {
        let Some(index) = self.position(socket) else {
            return;
        };
        let slot = &mut self.slots[index];
        let now = FileTime(backend.system_time());
        if receive(slot, socket, &mut self.shared, state, backend, network, now).is_err() {
            close_slot(slot, &mut self.shared, state, backend, network);
        }
        self.end_superseded(state, backend);
        self.retain_shares();
    }

    /// End the sessions that logons replaced (MS-SMB2 PreviousSessionId),
    /// on whichever connection holds them.
    fn end_superseded(&mut self, state: &ServerState, backend: &mut dyn crate::backend::Backend) {
        while let Some(superseded) = self.shared.server.take_superseded() {
            for slot in &mut self.slots {
                let mut adapter = Adapter {
                    state,
                    backend: &mut *backend,
                    files: &mut slot.files,
                    shares: &mut self.shared.shares,
                    presence: Presence::default(),
                };
                slot.connection
                    .end_session(&mut self.shared.server, &mut adapter, superseded);
            }
        }
    }

    /// Continue sending the reply on `socket`.
    #[inline(never)]
    pub fn on_writable(
        &mut self,
        socket: SocketId,
        state: &ServerState,
        backend: &mut dyn crate::backend::Backend,
        network: &mut dyn Network,
    ) {
        let Some(index) = self.position(socket) else {
            return;
        };
        let slot = &mut self.slots[index];
        let now = FileTime(backend.system_time());
        if send(slot, socket, network, now).is_err() {
            close_slot(slot, &mut self.shared, state, backend, network);
        }
    }

    /// End the connection on `socket`, releasing its opens and buffers.
    pub fn close(
        &mut self,
        socket: SocketId,
        state: &ServerState,
        backend: &mut dyn crate::backend::Backend,
        network: &mut dyn Network,
    ) {
        if let Some(index) = self.position(socket) {
            close_slot(
                &mut self.slots[index],
                &mut self.shared,
                state,
                backend,
                network,
            );
        }
        self.retain_shares();
    }

    /// End every connection.
    pub fn close_all(
        &mut self,
        state: &ServerState,
        backend: &mut dyn crate::backend::Backend,
        network: &mut dyn Network,
    ) {
        for slot in &mut self.slots {
            close_slot(slot, &mut self.shared, state, backend, network);
        }
        self.retain_shares();
    }
}

/// Receive until a message or keep-alive is complete or no input is
/// waiting; a complete message is handled and its reply sent. One call
/// handles at most one message, so a peer cannot hold the caller.
fn receive(
    slot: &mut Slot,
    socket: SocketId,
    shared: &mut Shared,
    state: &ServerState,
    backend: &mut dyn crate::backend::Backend,
    network: &mut dyn Network,
    now: FileTime,
) -> Result<(), Closed> {
    let Some(buffers) = slot.buffers.as_mut() else {
        return Ok(());
    };
    if slot.sending.is_some() {
        return Ok(());
    }
    loop {
        let target = match slot.receive {
            Receive::Header(received) => &mut buffers.input[received..HEADER_LENGTH],
            Receive::Message { length, received } => {
                &mut buffers.input[HEADER_LENGTH + received..HEADER_LENGTH + length]
            }
        };
        let count = if target.is_empty() {
            0
        } else {
            match network.receive(socket, target) {
                Ok(0) => return Err(Closed),
                Ok(count) => count,
                Err(NetError::WouldBlock) => return Ok(()),
                Err(NetError::Closed | NetError::Exhausted) => return Err(Closed),
            }
        };
        slot.activity.progress = now;
        slot.receive = match slot.receive {
            Receive::Header(received) if received + count < HEADER_LENGTH => {
                Receive::Header(received + count)
            }
            Receive::Header(_) => {
                let mut header = [0u8; HEADER_LENGTH];
                header.copy_from_slice(&buffers.input[..HEADER_LENGTH]);
                match transport::parse_header(header, buffers.input.len() - HEADER_LENGTH) {
                    Ok(Frame::Message { length }) => Receive::Message {
                        length,
                        received: 0,
                    },
                    Ok(Frame::KeepAlive) => {
                        slot.receive = Receive::Header(0);
                        return Ok(());
                    }
                    Err(_) => return Err(Closed),
                }
            }
            Receive::Message { length, received } => Receive::Message {
                length,
                received: received + count,
            },
        };
        if let Receive::Message { length, received } = slot.receive
            && received == length
        {
            slot.receive = Receive::Header(0);
            slot.activity.request = now;
            let mut adapter = Adapter {
                state,
                backend,
                files: &mut slot.files,
                shares: &mut shared.shares,
                presence: Presence::default(),
            };
            let request = &mut buffers.input[HEADER_LENGTH..HEADER_LENGTH + length];
            let reply = slot.connection.handle(
                &mut shared.server,
                &mut adapter,
                request,
                &mut buffers.output,
            );
            return start_sending(slot, socket, reply, network, now);
        }
    }
}

/// Send the replies to the connection's requests that completed later,
/// when its response buffer is free.
fn complete(
    slot: &mut Slot,
    shared: &mut Shared,
    state: &ServerState,
    backend: &mut dyn crate::backend::Backend,
    network: &mut dyn Network,
    now: FileTime,
) -> Result<(), Closed> {
    let Some(socket) = slot.socket else {
        return Ok(());
    };
    let Some(buffers) = slot.buffers.as_mut() else {
        return Ok(());
    };
    if slot.sending.is_some() {
        return Ok(());
    }
    let mut adapter = Adapter {
        state,
        backend,
        files: &mut slot.files,
        shares: &mut shared.shares,
        presence: Presence::default(),
    };
    let reply = slot
        .connection
        .poll(&mut shared.server, &mut adapter, &mut buffers.output);
    start_sending(slot, socket, reply, network, now)
}

/// Begin sending what the engine wrote to the response buffer.
fn start_sending(
    slot: &mut Slot,
    socket: SocketId,
    reply: Reply,
    network: &mut dyn Network,
    now: FileTime,
) -> Result<(), Closed> {
    let capacity = slot
        .buffers
        .as_ref()
        .map_or(0, |buffers| buffers.output.len());
    match reply {
        Reply::Send { length } if length <= capacity => {
            slot.sending = Some(Sending { length, sent: 0 });
            send(slot, socket, network, now)
        }
        Reply::Send { .. } | Reply::Disconnect => Err(Closed),
        Reply::Nothing => Ok(()),
    }
}

/// Send what the socket accepts of the pending reply.
fn send(
    slot: &mut Slot,
    socket: SocketId,
    network: &mut dyn Network,
    now: FileTime,
) -> Result<(), Closed> {
    let (Some(buffers), Some(sending)) = (slot.buffers.as_ref(), slot.sending.as_mut()) else {
        return Ok(());
    };
    while sending.sent < sending.length {
        match network.send(socket, &buffers.output[sending.sent..sending.length]) {
            Ok(0) => return Err(Closed),
            Ok(count) => {
                sending.sent += count;
                slot.activity.progress = now;
            }
            Err(NetError::WouldBlock) => return Ok(()),
            Err(NetError::Closed | NetError::Exhausted) => return Err(Closed),
        }
    }
    slot.sending = None;
    Ok(())
}

fn close_slot(
    slot: &mut Slot,
    shared: &mut Shared,
    state: &ServerState,
    backend: &mut dyn crate::backend::Backend,
    network: &mut dyn Network,
) {
    let Some(socket) = slot.socket.take() else {
        return;
    };
    let mut adapter = Adapter {
        state,
        backend: &mut *backend,
        files: &mut slot.files,
        shares: &mut shared.shares,
        presence: Presence::default(),
    };
    // Closing returns the connection and its files to their initial state
    // for the slot's next connection.
    slot.connection.close(&mut shared.server, &mut adapter);
    slot.files.reset(backend);
    if let Some(Buffers { input, output }) = slot.buffers.take() {
        backend.free_scratch(input);
        backend.free_scratch(output);
    }
    slot.receive = Receive::Header(0);
    slot.sending = None;
    network.close(socket);
}
