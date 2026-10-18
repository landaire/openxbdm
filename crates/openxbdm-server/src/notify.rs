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
/// Wait for a notification socket to become writable before an event line.
const SEND_TIMEOUT_MS: u32 = 60_000;
/// Wait for a notification socket to become writable before each send of a
/// debug string piece.
const STRING_SEND_TIMEOUT_MS: u32 = 3_000;
/// Interval at which the input of every notification socket is discarded.
const INPUT_DRAIN_INTERVAL_MS: i32 = 120_000;

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

/// A target table entry (stock table 0x91fadb00). Freeing an entry clears
/// only its address word, so a free entry keeps the port and socket slot of
/// its last use. The table starts zeroed: port 0, socket slot 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetEntry {
    Used(Target),
    Free { port: u16, socket_slot: Option<u8> },
}

impl TargetEntry {
    const ZEROED: Self = Self::Free {
        port: 0,
        socket_slot: Some(0),
    };

    const fn used(&self) -> Option<&Target> {
        match self {
            Self::Used(target) => Some(target),
            Self::Free { .. } => None,
        }
    }

    fn free(&mut self) {
        if let Self::Used(target) = *self {
            *self = Self::Free {
                port: target.endpoint.port,
                socket_slot: target.socket_slot,
            };
        }
    }

    const fn socket_slot(&self) -> Option<u8> {
        match *self {
            Self::Used(target) => target.socket_slot,
            Self::Free { socket_slot, .. } => socket_slot,
        }
    }

    /// Whether a drop of `endpoint` takes this entry (stock 0x91f38b60);
    /// a free entry has address 0.
    fn matches(&self, endpoint: Endpoint) -> bool {
        match *self {
            Self::Used(target) => target.endpoint == endpoint,
            Self::Free { port, .. } => endpoint.address.is_unspecified() && port == endpoint.port,
        }
    }
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
    targets: [TargetEntry; MAX_NOTIFICATION_TARGETS],
    debugger: Option<DebuggerTarget>,
    /// Tick count of the last input drain.
    last_input_drain: Option<u32>,
}

impl Notifications {
    pub const fn new() -> Self {
        Self {
            sockets: [None; MAX_NOTIFICATION_SOCKETS],
            targets: [TargetEntry::ZEROED; MAX_NOTIFICATION_TARGETS],
            debugger: None,
            last_input_drain: None,
        }
    }

    pub fn targets(&self) -> impl Iterator<Item = &Target> {
        self.targets.iter().filter_map(TargetEntry::used)
    }

    pub fn debugger(&self) -> Option<DebuggerTarget> {
        self.debugger
    }

    /// The target at `index`.
    pub fn target(&self, index: usize) -> Option<Target> {
        self.targets.get(index).and_then(TargetEntry::used).copied()
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

        if let Some(TargetEntry::Used(entry)) = target.and_then(|index| self.targets.get_mut(index))
        {
            entry.socket_slot = Some(slot);
        }

        Some(slot)
    }

    /// Register a target. A `socket` for a nonzero port binds to an existing
    /// target with the same endpoint that has no socket. Otherwise the first
    /// free entry becomes the target; unless `reverse`, it is bound to
    /// `socket` or, without one, connected now and sent the `execution`
    /// line. A target that cannot be connected or attached is freed and its
    /// endpoint dropped. Returns whether the target was registered.
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
            && let Some(index) = self.targets.iter().position(|entry| {
                entry.used().is_some_and(|target| {
                    target.endpoint == endpoint && target.socket_slot.is_none()
                })
            })
        {
            let attached = self.attach_socket(socket, Some(index), network).is_some();
            if attached && flags.contains(TargetFlags::DEBUG) {
                self.debugger = Some(DebuggerTarget { endpoint });
            }

            return attached;
        }

        let Some(index) = self.targets.iter().position(|entry| entry.used().is_none()) else {
            return false;
        };

        self.targets[index] = TargetEntry::Used(Target {
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
            self.targets[index].free();
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
    /// the slot are freed.
    pub fn detach_socket(&mut self, socket: SocketId) {
        let Some(slot) = self.sockets.iter().position(|entry| *entry == Some(socket)) else {
            return;
        };

        self.sockets[slot] = None;
        self.free_slot_targets(slot);
    }

    /// `notifyat drop` (stock 0x91f38b60): free every entry of `endpoint`
    /// and close the socket of its slot. Address 0 also takes free entries
    /// by the port and slot they kept. Other targets bound to a closed slot
    /// keep it.
    pub fn drop_targets(&mut self, endpoint: Endpoint, network: &mut dyn Network) {
        for index in 0..MAX_NOTIFICATION_TARGETS {
            let entry = &mut self.targets[index];
            if !entry.matches(endpoint) {
                continue;
            }

            entry.free();
            if let Some(socket) = entry
                .socket_slot()
                .and_then(|slot| self.sockets[slot as usize].take())
            {
                network.close(socket);
            }
        }
    }

    /// Free the target at `index` without touching its socket.
    pub fn remove_target(&mut self, index: usize) {
        if let Some(entry) = self.targets.get_mut(index) {
            entry.free();
        }
    }

    /// Close every notification socket (stock 0x91f3b208). Targets stay
    /// registered and keep their socket slots.
    pub fn close_all(&mut self, network: &mut dyn Network) {
        for socket in self.sockets.iter_mut().filter_map(Option::take) {
            network.close(socket);
        }
    }

    /// Discard the input of every notification socket when 120 seconds
    /// have passed since the last time (stock 0x91f38940, run on every pass
    /// of the server loop). `now` is the millisecond tick count.
    pub fn drain_input(&mut self, now: u32, network: &mut dyn Network) {
        if let Some(last) = self.last_input_drain
            && (now.wrapping_sub(last) as i32) < INPUT_DRAIN_INTERVAL_MS
        {
            return;
        }

        self.last_input_drain = Some(now);
        for &socket in self.sockets.iter().flatten() {
            let _ = discard_input(network, socket);
        }
    }

    fn close_slot(&mut self, slot: usize, network: &mut dyn Network) {
        if let Some(socket) = self.sockets[slot].take() {
            network.close(socket);
        }

        self.free_slot_targets(slot);
    }

    fn free_slot_targets(&mut self, slot: usize) {
        for entry in &mut self.targets {
            if entry
                .used()
                .is_some_and(|target| target.socket_slot == Some(slot as u8))
            {
                entry.free();
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

    /// Debug strings (stock 0x91f38ce8) are split at CR, LF, LF CR, and every
    /// 0x800 bytes. Each piece is sent as `<kind> [stop ]thread=0x%08x
    /// <eol>string=<piece>`, where `<eol>` is `cr `, `lf `, `crlf `, or
    /// empty, naming the line end that ended the piece.
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

/// Send the pieces of a debug string to one socket. A socket that is not
/// writable in time gets no more of the string but stays open.
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

        let parts = [prefix, eol, b"string=", &text[offset..end], b"\r\n"];
        if send_gathered(network, socket, &parts)? == GatheredSend::TimedOut {
            return Ok(());
        }

        offset = end + skip;
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatheredSend {
    Sent,
    TimedOut,
}

/// Send `parts` back to back as the monitor's gathered send does. Each send
/// call is preceded by a wait of up to 3 seconds for the socket to become
/// writable and continues through the parts until one is accepted in part.
/// Only a wait that runs out ends the send; a failed wait still sends.
fn send_gathered(
    network: &mut dyn Network,
    socket: SocketId,
    parts: &[&[u8]],
) -> Result<GatheredSend, NetError> {
    let mut parts = parts.iter().copied().filter(|part| !part.is_empty());
    let Some(mut part) = parts.next() else {
        return Ok(GatheredSend::Sent);
    };

    loop {
        if network.wait_writable(socket, STRING_SEND_TIMEOUT_MS) == Err(NetError::WouldBlock) {
            return Ok(GatheredSend::TimedOut);
        }

        loop {
            let sent = network.send(socket, part)?;
            part = &part[sent.min(part.len())..];
            if !part.is_empty() {
                break;
            }

            match parts.next() {
                Some(next) => part = next,
                None => return Ok(GatheredSend::Sent),
            }
        }
    }
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

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::*;
    use crate::network::Ipv4Address;
    use crate::network::SendBufferSize;

    const SOCKETS: usize = 4;

    /// Sockets that accept bytes while they have room and report input that
    /// receives consume.
    #[derive(Default)]
    struct ScriptedNetwork {
        sent: [Vec<u8>; SOCKETS],
        /// Bytes a socket still accepts; `None` accepts any amount.
        room: [Option<usize>; SOCKETS],
        pending: [usize; SOCKETS],
        closed: Vec<SocketId>,
        waits: Vec<(SocketId, u32)>,
    }

    impl Network for ScriptedNetwork {
        fn receive(&mut self, socket: SocketId, buffer: &mut [u8]) -> Result<usize, NetError> {
            let pending = &mut self.pending[socket.0 as usize];
            let count = buffer.len().min(*pending);
            *pending -= count;

            Ok(count)
        }

        fn send(&mut self, socket: SocketId, data: &[u8]) -> Result<usize, NetError> {
            let index = socket.0 as usize;
            let count = self.room[index].map_or(data.len(), |room| room.min(data.len()));
            if let Some(room) = &mut self.room[index] {
                *room -= count;
            }
            self.sent[index].extend_from_slice(&data[..count]);

            Ok(count)
        }

        fn close(&mut self, socket: SocketId) {
            self.closed.push(socket);
        }

        fn peer(&mut self, _socket: SocketId) -> Result<Endpoint, NetError> {
            Err(NetError::Closed)
        }

        fn connect(&mut self, _endpoint: Endpoint, _blocking: bool) -> Result<SocketId, NetError> {
            Err(NetError::Exhausted)
        }

        fn wait_writable(&mut self, socket: SocketId, timeout_ms: u32) -> Result<(), NetError> {
            self.waits.push((socket, timeout_ms));
            match self.room[socket.0 as usize] {
                Some(0) => Err(NetError::WouldBlock),
                _ => Ok(()),
            }
        }

        fn set_blocking(&mut self, _socket: SocketId, _blocking: bool) -> Result<(), NetError> {
            Ok(())
        }

        fn pending_input(&mut self, socket: SocketId) -> Result<usize, NetError> {
            Ok(self.pending[socket.0 as usize])
        }

        fn send_buffer_size(&mut self, _socket: SocketId) -> Result<SendBufferSize, NetError> {
            Ok(SendBufferSize(0x2000))
        }

        fn set_send_buffer_size(
            &mut self,
            _socket: SocketId,
            _size: SendBufferSize,
        ) -> Result<(), NetError> {
            Ok(())
        }
    }

    fn endpoint(address: Ipv4Address, port: u16) -> Endpoint {
        Endpoint { address, port }
    }

    #[test]
    fn a_debug_string_skips_a_full_channel_and_an_event_line_closes_it() {
        const FIRST: &[u8] = b"debugstr thread=0x00000007 lf string=one\r\n";
        const SECOND: &[u8] = b"debugstr thread=0x00000007 string=two\r\n";

        let mut network = ScriptedNetwork::default();
        let mut notifications = Notifications::new();
        notifications.add_socket(SocketId(0));
        notifications.add_socket(SocketId(1));
        network.room[0] = Some(FIRST.len() + 5);

        let string = Event::DebugString {
            thread: 7,
            text: b"one\ntwo",
            stopped: false,
        };
        assert!(notifications.deliver(&string, &mut network));

        // The full channel got the first piece and part of the second; it
        // stays open.
        assert_eq!(network.sent[0], [FIRST, &SECOND[..5]].concat());
        assert_eq!(network.sent[1], [FIRST, SECOND].concat());
        assert!(network.closed.is_empty());
        assert!(
            network
                .waits
                .iter()
                .all(|&(_, timeout)| timeout == STRING_SEND_TIMEOUT_MS)
        );

        // An event line waits 60 seconds and closes the channel that is
        // still full.
        let execution = Event::Execution(ExecutionState::Stopped);
        assert!(notifications.deliver(&execution, &mut network));
        assert_eq!(network.closed, [SocketId(0)]);
        assert_eq!(network.waits.last(), Some(&(SocketId(1), SEND_TIMEOUT_MS)));
        assert!(network.sent[1].ends_with(b"execution stopped\r\n"));
    }

    #[test]
    fn a_drop_of_address_zero_takes_free_entries_by_their_kept_port_and_slot() {
        const TARGET: Endpoint = Endpoint {
            address: Ipv4Address([1, 0, 0, 127]),
            port: 731,
        };

        let mut network = ScriptedNetwork::default();
        let mut notifications = Notifications::new();

        // Entries never used hold port 0 and socket slot 0.
        assert_eq!(notifications.add_socket(SocketId(0)), Some(0));
        notifications.drop_targets(endpoint(Ipv4Address::UNSPECIFIED, 0), &mut network);
        assert_eq!(network.closed, [SocketId(0)]);

        // A dropped target keeps its port and slot; the slot's next socket
        // goes with the next drop of address 0 and that port.
        assert!(notifications.register_target(
            TARGET,
            TargetFlags::empty(),
            false,
            Some(SocketId(1)),
            ExecutionState::Started,
            &mut network,
        ));
        notifications.drop_targets(TARGET, &mut network);
        assert_eq!(network.closed, [SocketId(0), SocketId(1)]);
        assert_eq!(notifications.targets().count(), 0);

        assert_eq!(notifications.add_socket(SocketId(2)), Some(0));
        notifications.drop_targets(endpoint(Ipv4Address::UNSPECIFIED, 732), &mut network);
        assert_eq!(network.closed, [SocketId(0), SocketId(1)]);
        notifications.drop_targets(endpoint(Ipv4Address::UNSPECIFIED, 731), &mut network);
        assert_eq!(network.closed, [SocketId(0), SocketId(1), SocketId(2)]);
    }

    #[test]
    fn channel_input_is_discarded_every_120_seconds() {
        const START: u32 = 0xffff_0000;

        let mut network = ScriptedNetwork::default();
        let mut notifications = Notifications::new();
        notifications.add_socket(SocketId(0));

        network.pending[0] = 0x50;
        notifications.drain_input(START, &mut network);
        assert_eq!(network.pending[0], 0);

        network.pending[0] = 0x50;
        notifications.drain_input(START.wrapping_add(119_999), &mut network);
        assert_eq!(network.pending[0], 0x50);
        notifications.drain_input(START.wrapping_add(120_000), &mut network);
        assert_eq!(network.pending[0], 0);
    }
}
