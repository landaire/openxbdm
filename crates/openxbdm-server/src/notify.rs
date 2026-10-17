//! Notification channels and event delivery.
//!
//! Up to 16 notification sockets carry asynchronous event lines. Up to 16
//! targets record endpoints that receive notifications, either connected
//! outward by the console or attached by a `notify reconnectport=` peer.

mod event;
mod posted;

use self::event::EVENT_LINE_CAPACITY;
use crate::network::Endpoint;
use crate::network::NetError;
use crate::network::Network;
use crate::network::SocketId;
use crate::network::send_all;
use crate::network::send_line;
use crate::text::Text;

pub use self::event::DataAccess;
pub use self::event::Event;
pub use self::event::ExceptionDetail;
pub use self::event::ExecutionState;
pub use self::posted::POSTED_TEXT_CAPACITY;
pub use self::posted::POSTED_TEXT_SLOTS;
pub use self::posted::PostedTexts;

pub const MAX_NOTIFICATION_SOCKETS: usize = 16;
pub const MAX_NOTIFICATION_TARGETS: usize = 16;
/// Wait for a notification socket to become writable.
const SEND_TIMEOUT_MS: u32 = 60_000;

xbox360_sys::flags! {
    /// Target flags.
    pub struct TargetFlags(u32) {
        /// Debugger notifications (`debug`).
        DEBUG = 0x2,
        /// The peer connects to the console (`reverse`).
        REVERSE = 0x40000,
    }
}

/// A registered notification target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub endpoint: Endpoint,
    pub flags: TargetFlags,
    /// Notification socket slot bound to this target.
    pub socket_slot: Option<u8>,
}

/// Debugger attachment recorded when a `debug` target is registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebuggerTarget {
    pub endpoint: Endpoint,
}

/// Notification sockets and targets.
#[derive(Debug)]
pub struct Notifications {
    sockets: [Option<SocketId>; MAX_NOTIFICATION_SOCKETS],
    targets: [Option<Target>; MAX_NOTIFICATION_TARGETS],
    debugger: Option<DebuggerTarget>,
}

impl Notifications {
    pub const fn new() -> Self {
        Self {
            sockets: [None; MAX_NOTIFICATION_SOCKETS],
            targets: [None; MAX_NOTIFICATION_TARGETS],
            debugger: None,
        }
    }

    pub fn targets(&self) -> impl Iterator<Item = &Target> {
        self.targets.iter().flatten()
    }

    pub fn debugger(&self) -> Option<DebuggerTarget> {
        self.debugger
    }

    /// The target at `index`.
    pub fn target(&self, index: usize) -> Option<Target> {
        self.targets.get(index).copied().flatten()
    }

    /// Place `socket` in a free notification slot.
    pub fn add_socket(&mut self, socket: SocketId) -> Option<u8> {
        let slot = self.sockets.iter().position(Option::is_none)?;
        self.sockets[slot] = Some(socket);

        Some(slot as u8)
    }

    /// Place `socket` in a free notification slot and bind it to the target
    /// at `target`. When every slot is in use, a `null` line is sent on each
    /// channel, which closes channels that fail, and the search runs once
    /// more.
    pub fn attach_socket(
        &mut self,
        socket: SocketId,
        target: Option<usize>,
        network: &mut dyn Network,
    ) -> Option<u8> {
        let slot = match self.add_socket(socket) {
            Some(slot) => slot,
            None => {
                self.send_text(b"null", network);
                self.add_socket(socket)?
            }
        };

        if let Some(Some(entry)) = target.and_then(|index| self.targets.get_mut(index)) {
            entry.socket_slot = Some(slot);
        }

        Some(slot)
    }

    /// Register a target. A `socket` for a nonzero port binds to an existing
    /// target with the same endpoint that has no socket. Otherwise a new
    /// target is created; unless `reverse`, it is bound to `socket` or, without
    /// one, connected now and sent the `execution` line. A target that cannot
    /// be connected or attached is removed along with every target of its
    /// endpoint. Returns whether the target was registered.
    pub fn register_target(
        &mut self,
        endpoint: Endpoint,
        flags: TargetFlags,
        reverse: bool,
        socket: Option<SocketId>,
        execution: ExecutionState,
        network: &mut dyn Network,
    ) -> bool {
        if endpoint.address.is_unspecified() {
            return false;
        }

        if endpoint.port != 0
            && let Some(socket) = socket
            && let Some(index) = self.targets.iter().position(|target| {
                matches!(
                    target,
                    Some(target) if target.endpoint == endpoint && target.socket_slot.is_none()
                )
            })
        {
            let attached = self.attach_socket(socket, Some(index), network).is_some();
            if attached && flags.contains(TargetFlags::DEBUG) {
                self.debugger = Some(DebuggerTarget { endpoint });
            }

            return attached;
        }

        let Some(index) = self.targets.iter().position(Option::is_none) else {
            return false;
        };

        self.targets[index] = Some(Target {
            endpoint,
            flags,
            socket_slot: None,
        });

        if reverse {
            return true;
        }

        let connected = match socket {
            Some(socket) => Some(socket),
            None => connect_target(endpoint, execution, network),
        };
        let attached =
            connected.and_then(|connected| self.attach_socket(connected, Some(index), network));
        if attached.is_none() {
            self.targets[index] = None;
            if socket.is_none()
                && let Some(connected) = connected
            {
                network.close(connected);
            }

            self.drop_targets(endpoint, network);
            return false;
        }

        if flags.contains(TargetFlags::DEBUG) {
            self.debugger = Some(DebuggerTarget { endpoint });
        }

        true
    }

    /// Detach `socket` from its slot without closing it; targets bound to
    /// the slot are removed.
    pub fn detach_socket(&mut self, socket: SocketId) {
        let Some(slot) = self.sockets.iter().position(|entry| *entry == Some(socket)) else {
            return;
        };

        self.sockets[slot] = None;
        for target in &mut self.targets {
            if matches!(target, Some(entry) if entry.socket_slot == Some(slot as u8)) {
                *target = None;
            }
        }
    }

    /// Remove every target with `endpoint`, closing its socket.
    pub fn drop_targets(&mut self, endpoint: Endpoint, network: &mut dyn Network) {
        for index in 0..MAX_NOTIFICATION_TARGETS {
            if let Some(target) = self.targets[index]
                && target.endpoint == endpoint
            {
                self.targets[index] = None;

                if let Some(slot) = target.socket_slot {
                    self.close_slot(slot as usize, network);
                }
            }
        }
    }

    /// Remove the target at `index` without touching its socket.
    pub fn remove_target(&mut self, index: usize) {
        if let Some(target) = self.targets.get_mut(index) {
            *target = None;
        }
    }

    /// Close every notification socket. Targets stay registered and are
    /// unbound from their sockets.
    pub fn close_all(&mut self, network: &mut dyn Network) {
        for socket in self.sockets.iter_mut().filter_map(Option::take) {
            network.close(socket);
        }

        for target in self.targets.iter_mut().flatten() {
            target.socket_slot = None;
        }
    }

    fn close_slot(&mut self, slot: usize, network: &mut dyn Network) {
        if let Some(socket) = self.sockets[slot].take() {
            network.close(socket);
        }

        for target in &mut self.targets {
            if matches!(target, Some(entry) if entry.socket_slot == Some(slot as u8)) {
                *target = None;
            }
        }
    }

    /// Send `event` to every notification socket. A socket that fails is
    /// closed and its targets are removed. Returns whether any socket
    /// accepted the line; debug strings always report true.
    pub fn deliver(&mut self, event: &Event<'_>, network: &mut dyn Network) -> bool {
        match *event {
            Event::DebugString {
                thread,
                text,
                stopped,
            } => {
                self.deliver_string("debugstr", thread, text, stopped, network);

                true
            }
            Event::AssertString {
                thread,
                text,
                stopped,
            } => {
                self.deliver_string("assert", thread, text, stopped, network);

                true
            }
            _ => {
                let mut line = Text::<EVENT_LINE_CAPACITY>::new();
                event.write_line(&mut line);

                self.send_text(line.as_bytes(), network)
            }
        }
    }

    /// Send `text` as one line to every notification socket (stock
    /// 0x91f389e0): unread input is discarded first, then the socket is
    /// given 60 seconds to become writable. A socket that fails is closed
    /// and its targets are removed. Returns whether any socket accepted
    /// the line.
    pub fn send_text(&mut self, text: &[u8], network: &mut dyn Network) -> bool {
        let mut accepted = false;

        for slot in 0..MAX_NOTIFICATION_SOCKETS {
            let Some(socket) = self.sockets[slot] else {
                continue;
            };

            let sent = discard_input(network, socket)
                .and_then(|()| network.wait_writable(socket, SEND_TIMEOUT_MS))
                .and_then(|()| send_line(network, socket, text));
            if sent.is_err() {
                self.close_slot(slot, network);
            } else {
                accepted = true;
            }
        }

        accepted
    }

    /// Debug strings are split at CR, LF, LF CR, and every 0x800 bytes. Each
    /// piece is sent as `<kind> [stop ]thread=0x%08x <eol>string=<piece>`,
    /// where `<eol>` is `cr `, `lf `, `crlf `, or empty, naming the line end
    /// that ended the piece.
    fn deliver_string(
        &mut self,
        kind: &str,
        thread: u32,
        text: &[u8],
        stopped: bool,
        network: &mut dyn Network,
    ) {
        let mut prefix = Text::<0x40>::new();
        let _ = prefix.push_bytes(kind.as_bytes()).and_then(|()| {
            prefix.push_bytes(if stopped { b" stop " } else { b" " })?;
            prefix.push_bytes(b"thread=0x")?;
            prefix.push_hex32(thread)?;
            prefix.push_bytes(b" ")
        });

        for slot in 0..MAX_NOTIFICATION_SOCKETS {
            let Some(socket) = self.sockets[slot] else {
                continue;
            };

            if send_string_pieces(network, socket, prefix.as_bytes(), text).is_err() {
                self.close_slot(slot, network);
            }
        }
    }
}

/// Connect to a target and send the current execution state line.
fn connect_target(
    endpoint: Endpoint,
    execution: ExecutionState,
    network: &mut dyn Network,
) -> Option<SocketId> {
    let socket = network.connect(endpoint, true).ok()?;

    let mut line = Text::<EVENT_LINE_CAPACITY>::new();
    Event::Execution(execution).write_line(&mut line);

    if send_line(network, socket, line.as_bytes()).is_err() {
        network.close(socket);
        return None;
    }

    Some(socket)
}

fn send_string_pieces(
    network: &mut dyn Network,
    socket: SocketId,
    prefix: &[u8],
    text: &[u8],
) -> Result<(), NetError> {
    // Debug strings are split into chunks of at most this many bytes.
    const DEBUG_STRING_CHUNK: usize = 0x800;

    let mut offset = 0;
    while offset < text.len() {
        let limit = (offset + DEBUG_STRING_CHUNK).min(text.len());
        let end = text[offset..limit]
            .iter()
            .position(|&byte| byte == b'\n' || byte == b'\r')
            .map_or(limit, |position| offset + position);
        let (eol, skip): (&[u8], usize) = if end == limit {
            (b"", 0)
        } else if text[end] == b'\r' {
            (b"cr ", 1)
        } else if text.get(end + 1) == Some(&b'\r') {
            (b"crlf ", 2)
        } else {
            (b"lf ", 1)
        };

        network.wait_writable(socket, SEND_TIMEOUT_MS)?;
        send_all(network, socket, prefix)?;
        send_all(network, socket, eol)?;
        send_all(network, socket, b"string=")?;
        send_line(network, socket, &text[offset..end])?;
        offset = end + skip;
    }

    Ok(())
}

/// Read and drop the input waiting on a notification socket (stock
/// 0x91f388a8), in pieces of at most 0x40 bytes. The count shrinks by the
/// requested size, so input the socket returns short stays unread. Only a
/// failed pending-input query fails.
fn discard_input(network: &mut dyn Network, socket: SocketId) -> Result<(), NetError> {
    const PIECE: usize = 0x40;

    let mut remaining = network.pending_input(socket)?;
    let mut piece = [0u8; PIECE];

    while remaining != 0 {
        let size = remaining.min(PIECE);
        if !matches!(network.receive(socket, &mut piece[..size]), Ok(received) if received > 0) {
            break;
        }

        remaining -= size;
    }

    Ok(())
}
