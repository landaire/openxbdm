//! Notification channels and event delivery.
//!
//! Up to 16 notification sockets carry asynchronous event lines. Up to 16
//! targets record endpoints that receive notifications, either connected
//! outward by the console or attached by a `notify reconnectport=` peer.

use crate::commands::debugger::ModuleEvent;
use crate::commands::debugger::ModuleFlags;
use crate::network::Endpoint;
use crate::network::NetError;
use crate::network::Network;
use crate::network::SocketId;
use crate::network::send_all;
use crate::network::send_line;
use crate::text::Text;

pub const MAX_NOTIFICATION_SOCKETS: usize = 16;
pub const MAX_NOTIFICATION_TARGETS: usize = 16;
/// Debug strings are split into chunks of at most this many bytes.
const DEBUG_STRING_CHUNK: usize = 0x800;
/// Wait for a notification socket to become writable.
const SEND_TIMEOUT_MS: u32 = 60_000;
/// Capacity of a formatted notification line.
const EVENT_LINE_CAPACITY: usize = 0x230;

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

/// Execution state reported by `execution` lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionState {
    Stopped,
    Started,
    Rebooting,
    Pending,
    RebootTitle,
    PendingTitle,
}

impl ExecutionState {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Started => "started",
            Self::Rebooting => "rebooting",
            Self::Pending => "pending",
            Self::RebootTitle => "reboot_title",
            Self::PendingTitle => "pending_title",
        }
    }
}

/// Kind of a data breakpoint hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAccess {
    Write,
    Read,
    Execute,
}

impl DataAccess {
    const fn name(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Read => "read",
            Self::Execute => "execute",
        }
    }
}

/// Exception detail of an `exception` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionDetail {
    /// Access violation (code 0xc0000005): `write` or `read` and the address.
    AccessViolation {
        write: bool,
        address: u32,
    },
    Parameters {
        count: u32,
        address: u32,
    },
}

/// An asynchronous event. `stopped` marks events after which the thread is
/// stopped; their lines end in ` stop`.
#[derive(Clone, Copy)]
pub enum Event<'a> {
    Break {
        address: u32,
        thread: u32,
        stopped: bool,
    },
    DebugString {
        thread: u32,
        text: &'a [u8],
        stopped: bool,
    },
    AssertString {
        thread: u32,
        text: &'a [u8],
        stopped: bool,
    },
    Execution(ExecutionState),
    /// `execution` line of a thread that stops with the state change (the
    /// title launch waiting in pending_title).
    ExecutionStop(ExecutionState),
    SingleStep {
        address: u32,
        thread: u32,
        stopped: bool,
    },
    ModuleLoad {
        module: &'a ModuleEvent,
        thread: u32,
        stopped: bool,
    },
    ModuleUnload {
        name: &'a str,
        base: u32,
        size: u32,
    },
    ThreadCreate {
        thread: u32,
        start: u32,
        stopped: bool,
    },
    ThreadTerminate {
        thread: u32,
        stopped: bool,
    },
    Exception {
        code: u32,
        thread: u32,
        address: u32,
        detail: ExceptionDetail,
        first_chance: bool,
        noncontinuable: bool,
        stopped: bool,
    },
    Assert {
        thread: u32,
        string_address: u32,
        string_length: u32,
        stopped: bool,
    },
    Data {
        access: DataAccess,
        value: u32,
        address: u32,
        thread: u32,
        stopped: bool,
    },
    Rip {
        thread: u32,
        text: Option<&'a str>,
        stopped: bool,
    },
    SectionLoad {
        name: &'a str,
        base: u32,
        size: u32,
        index: u32,
        flags: u32,
    },
    SectionUnload {
        name: &'a str,
        base: u32,
        size: u32,
        index: u32,
        flags: u32,
    },
    StackTrace {
        thread: u32,
        text: Option<&'a str>,
        stopped: bool,
    },
    NtAssert {
        address: u32,
        thread: u32,
        stopped: bool,
    },
    PogoModuleStartup {
        name: &'a str,
        module: u32,
        thread: u32,
        stopped: bool,
    },
}

/// `label` followed by `value` in eight hex digits.
fn hex(out: &mut Text<EVENT_LINE_CAPACITY>, label: &[u8], value: u32) {
    put(out, label);
    let _ = out.push_hex32(value);
}

/// Append `bytes`. A full line takes no more bytes, so later appends
/// after a truncated one change nothing and need no check.
fn put(out: &mut Text<EVENT_LINE_CAPACITY>, bytes: &[u8]) {
    let _ = out.push_bytes(bytes);
}

fn decimal(out: &mut Text<EVENT_LINE_CAPACITY>, value: u32) {
    let _ = out.push_decimal(value);
}

/// Text of the `stopped` suffix.
fn stop(stopped: bool) -> &'static [u8] {
    if stopped { b" stop" } else { b"" }
}

/// `<kind> name="<name>" base=0x... size=0x... index=<n> flags=<n>`.
fn section_line(
    out: &mut Text<EVENT_LINE_CAPACITY>,
    kind: &[u8],
    name: &str,
    base: u32,
    size: u32,
    index: u32,
    flags: u32,
) {
    put(out, kind);
    put(out, b" name=\"");
    put(out, name.as_bytes());
    hex(out, b"\" base=0x", base);
    hex(out, b" size=0x", size);
    put(out, b" index=");
    decimal(out, index);
    put(out, b" flags=");
    decimal(out, flags);
}

/// `<kind><stop> thread=0x...`, then ` string=<text>` when present.
fn text_line(
    out: &mut Text<EVENT_LINE_CAPACITY>,
    kind: &[u8],
    thread: u32,
    text: Option<&str>,
    stopped: bool,
) {
    put(out, kind);
    put(out, stop(stopped));
    hex(out, b" thread=0x", thread);
    if let Some(text) = text {
        put(out, b" string=");
        put(out, text.as_bytes());
    }
}

impl Event<'_> {
    /// Write the notification line (without CR LF) for line-formatted events.
    fn write_line(&self, out: &mut Text<EVENT_LINE_CAPACITY>) {
        match *self {
            Self::Break {
                address,
                thread,
                stopped,
            } => {
                hex(out, b"break addr=0x", address);
                hex(out, b" thread=0x", thread);
                put(out, stop(stopped))
            }
            Self::Execution(state) => {
                put(out, b"execution ");
                put(out, state.name().as_bytes())
            }
            Self::ExecutionStop(state) => {
                put(out, b"execution ");
                put(out, state.name().as_bytes());
                put(out, stop(true))
            }
            Self::SingleStep {
                address,
                thread,
                stopped,
            } => {
                hex(out, b"singlestep addr=0x", address);
                hex(out, b" thread=0x", thread);
                put(out, stop(stopped));
            }
            Self::ModuleLoad {
                module,
                thread,
                stopped,
            } => {
                let flag = |bit: ModuleFlags, text: &'static [u8]| {
                    if module.flags.intersects(bit) {
                        text
                    } else {
                        b""
                    }
                };
                put(out, b"modload name=\"");
                put(out, &module.name[..module.name_length]);
                hex(out, b"\" base=0x", module.base);
                hex(out, b" size=0x", module.size);
                hex(out, b" check=0x", module.checksum);
                hex(out, b" timestamp=0x", module.timestamp);
                hex(out, b" pdata=0x", module.pdata);
                hex(out, b" psize=0x", module.pdata_size);
                put(out, flag(ModuleFlags::XBE, b" xbe"));
                put(out, flag(ModuleFlags::TLS, b" tls"));
                put(out, flag(ModuleFlags::DLL, b" dll"));
                hex(out, b" thread=0x", thread);
                hex(out, b" osize=0x", module.image_size);
                put(out, stop(stopped))
            }
            Self::ModuleUnload { name, base, size } => {
                put(out, b"modunload name=\"");
                put(out, name.as_bytes());
                hex(out, b"\" base=0x", base);
                hex(out, b" size=0x", size);
            }
            Self::ThreadCreate {
                thread,
                start,
                stopped,
            } => {
                hex(out, b"create thread=0x", thread);
                hex(out, b" start=0x", start);
                put(out, stop(stopped))
            }
            Self::ThreadTerminate { thread, stopped } => {
                hex(out, b"terminate thread=0x", thread);
                put(out, stop(stopped))
            }
            Self::Exception {
                code,
                thread,
                address,
                detail,
                first_chance,
                noncontinuable,
                stopped,
            } => {
                hex(out, b"exception code=0x", code);
                hex(out, b" thread=0x", thread);
                hex(out, b" address=0x", address);
                match detail {
                    ExceptionDetail::AccessViolation { write, address } => {
                        let label: &[u8] = if write { b" write=0x" } else { b" read=0x" };
                        hex(out, label, address);
                    }
                    ExceptionDetail::Parameters { count, address } => {
                        put(out, b" nparam=");
                        decimal(out, count);
                        hex(out, b" params=0x", address);
                    }
                }
                if first_chance {
                    put(out, b" first");
                }
                if noncontinuable {
                    put(out, b" noncont");
                }
                put(out, stop(stopped))
            }
            // The monitor's assert case appends the stop suffix and then
            // falls into the common suffix code, so stopped lines carry it
            // twice.
            Self::Assert {
                thread,
                string_address,
                string_length,
                stopped,
            } => {
                hex(out, b"assert thread=0x", thread);
                hex(out, b" straddr=0x", string_address);
                hex(out, b" strlen=0x", string_length);
                put(out, stop(stopped));
                put(out, stop(stopped))
            }
            Self::Data {
                access,
                value,
                address,
                thread,
                stopped,
            } => {
                put(out, b"data ");
                put(out, access.name().as_bytes());
                hex(out, b"=0x", value);
                hex(out, b" addr=0x", address);
                hex(out, b" thread=0x", thread);
                put(out, stop(stopped))
            }
            Self::Rip {
                thread,
                text,
                stopped,
            } => text_line(out, b"rip", thread, text, stopped),
            Self::SectionLoad {
                name,
                base,
                size,
                index,
                flags,
            } => section_line(out, b"sectload", name, base, size, index, flags),
            Self::SectionUnload {
                name,
                base,
                size,
                index,
                flags,
            } => section_line(out, b"sectunload", name, base, size, index, flags),
            Self::StackTrace {
                thread,
                text,
                stopped,
            } => text_line(out, b"stacktrace", thread, text, stopped),
            Self::NtAssert {
                address,
                thread,
                stopped,
            } => {
                hex(out, b"ntassert addr=0x", address);
                hex(out, b" thread=0x", thread);
                put(out, stop(stopped))
            }
            Self::PogoModuleStartup {
                name,
                module,
                thread,
                stopped,
            } => {
                put(out, b"pogomodstartup name=\"");
                put(out, name.as_bytes());
                hex(out, b"\" module=0x", module);
                hex(out, b" thread=0x", thread);
                put(out, stop(stopped));
            }
            Self::DebugString { .. } | Self::AssertString { .. } => {}
        }
    }
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
            && let Some(index) = self
                .targets
                .iter()
                .position(|target| matches!(target, Some(t) if t.endpoint == endpoint && t.socket_slot.is_none()))
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
        if let Some(slot) = self.sockets.iter().position(|s| *s == Some(socket)) {
            self.sockets[slot] = None;
            for target in &mut self.targets {
                if matches!(target, Some(t) if t.socket_slot == Some(slot as u8)) {
                    *target = None;
                }
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
            if matches!(target, Some(t) if t.socket_slot == Some(slot as u8)) {
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
    let mut offset = 0;
    while offset < text.len() {
        let limit = (offset + DEBUG_STRING_CHUNK).min(text.len());
        let end = text[offset..limit]
            .iter()
            .position(|&byte| byte == b'\n' || byte == b'\r')
            .map_or(limit, |p| offset + p);
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

/// Longest notification text a posted slot holds; a poster sends longer
/// texts through the server thread itself.
pub const POSTED_TEXT_CAPACITY: usize = 0x200;
/// Posted texts that can wait for the server thread.
pub const POSTED_TEXT_SLOTS: usize = 16;

/// Notification texts posted by threads other than the server thread,
/// oldest first. The monitor sends such texts in the posting thread; here
/// the server thread sends them on its next pass. Platforms keep the
/// queue under their own lock.
#[derive(Debug, Clone)]
pub struct PostedTexts {
    texts: [[u8; POSTED_TEXT_CAPACITY]; POSTED_TEXT_SLOTS],
    lengths: [u16; POSTED_TEXT_SLOTS],
    first: usize,
    count: usize,
}

impl Default for PostedTexts {
    fn default() -> Self {
        Self::new()
    }
}

impl PostedTexts {
    pub const fn new() -> Self {
        Self {
            texts: [[0; POSTED_TEXT_CAPACITY]; POSTED_TEXT_SLOTS],
            lengths: [0; POSTED_TEXT_SLOTS],
            first: 0,
            count: 0,
        }
    }

    pub const fn is_full(&self) -> bool {
        self.count == POSTED_TEXT_SLOTS
    }

    /// Queue `text`. `false` when the queue is full or `text` is longer
    /// than [`POSTED_TEXT_CAPACITY`].
    pub fn push(&mut self, text: &[u8]) -> bool {
        if self.is_full() || text.len() > POSTED_TEXT_CAPACITY {
            return false;
        }
        let slot = (self.first + self.count) % POSTED_TEXT_SLOTS;
        self.texts[slot][..text.len()].copy_from_slice(text);
        self.lengths[slot] = text.len() as u16;
        self.count += 1;
        true
    }

    /// Move the oldest text into `output`; returns its length.
    pub fn pop(&mut self, output: &mut [u8; POSTED_TEXT_CAPACITY]) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let length = self.lengths[self.first] as usize;
        output[..length].copy_from_slice(&self.texts[self.first][..length]);
        self.first = (self.first + 1) % POSTED_TEXT_SLOTS;
        self.count -= 1;
        Some(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(event: Event<'_>) -> Text<EVENT_LINE_CAPACITY> {
        let mut text = Text::new();
        event.write_line(&mut text);
        text
    }

    #[test]
    fn event_lines_follow_the_monitor_formats() {
        assert_eq!(
            line(Event::Break {
                address: 0x8201_0000,
                thread: 0xfb00_0018,
                stopped: true
            })
            .as_bytes(),
            b"break addr=0x82010000 thread=0xfb000018 stop"
        );
        assert_eq!(
            line(Event::Execution(ExecutionState::RebootTitle)).as_bytes(),
            b"execution reboot_title"
        );
        assert_eq!(
            line(Event::Exception {
                code: 0xc000_0005,
                thread: 1,
                address: 2,
                detail: ExceptionDetail::AccessViolation { write: true, address: 3 },
                first_chance: true,
                noncontinuable: false,
                stopped: true,
            })
            .as_bytes(),
            b"exception code=0xc0000005 thread=0x00000001 address=0x00000002 write=0x00000003 first stop"
        );
    }

    #[test]
    fn modload_names_keep_their_bytes() {
        let mut module = ModuleEvent {
            name: [0; crate::commands::debugger::MODULE_NAME_CAPACITY],
            name_length: 6,
            base: 0x8200_0000,
            size: 0x1000,
            checksum: 0,
            timestamp: 0,
            pdata: 0,
            pdata_size: 0,
            flags: ModuleFlags::DLL,
            image_size: 0x1000,
            has_header: false,
        };
        module.name[..6].copy_from_slice(b"m\xe9.xex");
        assert_eq!(
            line(Event::ModuleLoad { module: &module, thread: 1, stopped: false }).as_bytes(),
            b"modload name=\"m\xe9.xex\" base=0x82000000 size=0x00001000 check=0x00000000 timestamp=0x00000000 pdata=0x00000000 psize=0x00000000 dll thread=0x00000001 osize=0x00001000"
        );
    }

    #[test]
    fn every_event_line() {
        let module = ModuleEvent {
            name: [b'a'; crate::commands::debugger::MODULE_NAME_CAPACITY],
            name_length: 3,
            base: 0x8200_0000,
            size: 0xffff_ffff,
            checksum: 0x1234_abcd,
            timestamp: 7,
            pdata: 0x10,
            pdata_size: 0x20,
            flags: ModuleFlags::XBE | ModuleFlags::TLS | ModuleFlags::DLL,
            image_size: 0x30,
            has_header: true,
        };
        let events = [
            Event::Break {
                address: 1,
                thread: 2,
                stopped: false,
            },
            Event::ExecutionStop(ExecutionState::PendingTitle),
            Event::SingleStep {
                address: 0xdead_beef,
                thread: 0,
                stopped: true,
            },
            Event::ModuleLoad {
                module: &module,
                thread: 9,
                stopped: true,
            },
            Event::ModuleUnload {
                name: "x.xex",
                base: 0x8000_0000,
                size: 0x10,
            },
            Event::ModuleUnload {
                name: "",
                base: 0,
                size: 0,
            },
            Event::ThreadCreate {
                thread: 3,
                start: 0x8200_1000,
                stopped: false,
            },
            Event::ThreadTerminate {
                thread: 4,
                stopped: true,
            },
            Event::ThreadTerminate {
                thread: 4,
                stopped: false,
            },
            Event::Exception {
                code: 0x8000_0003,
                thread: 5,
                address: 6,
                detail: ExceptionDetail::Parameters {
                    count: 4_294_967_295,
                    address: 7,
                },
                first_chance: false,
                noncontinuable: true,
                stopped: false,
            },
            Event::Exception {
                code: 0xc000_0005,
                thread: 5,
                address: 6,
                detail: ExceptionDetail::AccessViolation {
                    write: false,
                    address: 8,
                },
                first_chance: true,
                noncontinuable: true,
                stopped: true,
            },
            Event::Assert {
                thread: 1,
                string_address: 2,
                string_length: 3,
                stopped: true,
            },
            Event::Assert {
                thread: 1,
                string_address: 2,
                string_length: 3,
                stopped: false,
            },
            Event::Data {
                access: DataAccess::Write,
                value: 0x11,
                address: 0x22,
                thread: 0x33,
                stopped: true,
            },
            Event::Rip {
                thread: 1,
                text: Some("message"),
                stopped: true,
            },
            Event::Rip {
                thread: 1,
                text: None,
                stopped: false,
            },
            Event::SectionLoad {
                name: ".text",
                base: 1,
                size: 2,
                index: 0,
                flags: 10,
            },
            Event::SectionUnload {
                name: ".data",
                base: 3,
                size: 4,
                index: 12345,
                flags: 0,
            },
            Event::StackTrace {
                thread: 2,
                text: Some(""),
                stopped: false,
            },
            Event::StackTrace {
                thread: 2,
                text: None,
                stopped: true,
            },
            Event::NtAssert {
                address: 0xffff_ffff,
                thread: 0x10,
                stopped: true,
            },
            Event::PogoModuleStartup {
                name: "pogo",
                module: 0x9000_0000,
                thread: 1,
                stopped: false,
            },
        ];
        extern crate std;
        let mut lines = std::string::String::new();
        for event in events {
            lines.push_str(core::str::from_utf8(line(event).as_bytes()).unwrap());
            lines.push('\n');
        }
        insta::assert_snapshot!(lines);
    }
}
