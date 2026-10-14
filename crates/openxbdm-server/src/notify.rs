//! Notification channels and event delivery.
//!
//! Up to 16 notification sockets carry asynchronous event lines. Up to 16
//! targets record endpoints that receive notifications, either connected
//! outward by the console or attached by a `notify reconnectport=` peer.

use core::fmt;
use core::fmt::Write as _;

use crate::commands::debugger::ModuleEvent;
use crate::commands::debugger::module_flags;
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

/// Target flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TargetFlags(u32);

impl TargetFlags {
    pub const NONE: Self = Self(0);
    /// Debugger notifications (`debug`).
    pub const DEBUG: Self = Self(0x2);
    /// The peer connects to the console (`reverse`).
    pub const REVERSE: Self = Self(0x40000);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
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

impl Event<'_> {
    /// Write the notification line (without CR LF) for line-formatted events.
    fn write_line(&self, out: &mut Text<EVENT_LINE_CAPACITY>) -> fmt::Result {
        let stop = |stopped: bool| if stopped { " stop" } else { "" };
        match *self {
            Self::Break {
                address,
                thread,
                stopped,
            } => {
                write!(
                    out,
                    "break addr=0x{address:08x} thread=0x{thread:08x}{}",
                    stop(stopped)
                )
            }
            Self::Execution(state) => write!(out, "execution {}", state.name()),
            Self::ExecutionStop(state) => write!(out, "execution {} stop", state.name()),
            Self::SingleStep {
                address,
                thread,
                stopped,
            } => {
                write!(
                    out,
                    "singlestep addr=0x{address:08x} thread=0x{thread:08x}{}",
                    stop(stopped)
                )
            }
            Self::ModuleLoad {
                module,
                thread,
                stopped,
            } => {
                let flag =
                    |bit: u32, text: &'static str| if module.flags & bit != 0 { text } else { "" };
                out.push_bytes(b"modload name=\"")?;
                out.push_bytes(&module.name[..module.name_length])?;
                write!(
                    out,
                    "\" base=0x{:08x} size=0x{:08x} check=0x{:08x} timestamp=0x{:08x} pdata=0x{:08x} psize=0x{:08x}{}{}{} thread=0x{thread:08x} osize=0x{:08x}{}",
                    module.base,
                    module.size,
                    module.checksum,
                    module.timestamp,
                    module.pdata,
                    module.pdata_size,
                    flag(module_flags::XBE, " xbe"),
                    flag(module_flags::TLS, " tls"),
                    flag(module_flags::DLL, " dll"),
                    module.image_size,
                    stop(stopped),
                )
            }
            Self::ModuleUnload { name, base, size } => {
                write!(
                    out,
                    "modunload name=\"{name}\" base=0x{base:08x} size=0x{size:08x}"
                )
            }
            Self::ThreadCreate {
                thread,
                start,
                stopped,
            } => {
                write!(
                    out,
                    "create thread=0x{thread:08x} start=0x{start:08x}{}",
                    stop(stopped)
                )
            }
            Self::ThreadTerminate { thread, stopped } => {
                write!(out, "terminate thread=0x{thread:08x}{}", stop(stopped))
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
                write!(
                    out,
                    "exception code=0x{code:08x} thread=0x{thread:08x} address=0x{address:08x}"
                )?;
                match detail {
                    ExceptionDetail::AccessViolation { write, address } => write!(
                        out,
                        " {}=0x{address:08x}",
                        if write { "write" } else { "read" }
                    )?,
                    ExceptionDetail::Parameters { count, address } => {
                        write!(out, " nparam={count} params=0x{address:08x}")?
                    }
                }
                if first_chance {
                    out.write_str(" first")?;
                }
                if noncontinuable {
                    out.write_str(" noncont")?;
                }
                out.write_str(stop(stopped))
            }
            // The monitor's assert case appends the stop suffix and then
            // falls into the common suffix code, so stopped lines carry it
            // twice.
            Self::Assert {
                thread,
                string_address,
                string_length,
                stopped,
            } => write!(
                out,
                "assert thread=0x{thread:08x} straddr=0x{string_address:08x} strlen=0x{string_length:08x}{}{}",
                stop(stopped),
                stop(stopped)
            ),
            Self::Data {
                access,
                value,
                address,
                thread,
                stopped,
            } => write!(
                out,
                "data {}=0x{value:08x} addr=0x{address:08x} thread=0x{thread:08x}{}",
                access.name(),
                stop(stopped)
            ),
            Self::Rip {
                thread,
                text,
                stopped,
            } => match text {
                Some(text) => write!(
                    out,
                    "rip{} thread=0x{thread:08x} string={text}",
                    stop(stopped)
                ),
                None => write!(out, "rip{} thread=0x{thread:08x}", stop(stopped)),
            },
            Self::SectionLoad {
                name,
                base,
                size,
                index,
                flags,
            } => write!(
                out,
                "sectload name=\"{name}\" base=0x{base:08x} size=0x{size:08x} index={index} flags={flags}"
            ),
            Self::SectionUnload {
                name,
                base,
                size,
                index,
                flags,
            } => write!(
                out,
                "sectunload name=\"{name}\" base=0x{base:08x} size=0x{size:08x} index={index} flags={flags}"
            ),
            Self::StackTrace {
                thread,
                text,
                stopped,
            } => match text {
                Some(text) => write!(
                    out,
                    "stacktrace{} thread=0x{thread:08x} string={text}",
                    stop(stopped)
                ),
                None => write!(out, "stacktrace{} thread=0x{thread:08x}", stop(stopped)),
            },
            Self::NtAssert {
                address,
                thread,
                stopped,
            } => {
                write!(
                    out,
                    "ntassert addr=0x{address:08x} thread=0x{thread:08x}{}",
                    stop(stopped)
                )
            }
            Self::PogoModuleStartup {
                name,
                module,
                thread,
                stopped,
            } => write!(
                out,
                "pogomodstartup name=\"{name}\" module=0x{module:08x} thread=0x{thread:08x}{}",
                stop(stopped)
            ),
            Self::DebugString { .. } | Self::AssertString { .. } => Ok(()),
        }
    }
}

/// Notification sockets and targets.
#[derive(Debug, Default)]
pub struct Notifications {
    sockets: [Option<SocketId>; MAX_NOTIFICATION_SOCKETS],
    targets: [Option<Target>; MAX_NOTIFICATION_TARGETS],
    debugger: Option<DebuggerTarget>,
}

impl Notifications {
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
                let _ = event.write_line(&mut line);
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
        let _ = write!(
            prefix,
            "{kind} {}thread=0x{thread:08x} ",
            if stopped { "stop " } else { "" }
        );
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
    let _ = Event::Execution(execution).write_line(&mut line);
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
        event.write_line(&mut text).unwrap();
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
            flags: module_flags::DLL,
            image_size: 0x1000,
            has_header: false,
        };
        module.name[..6].copy_from_slice(b"m\xe9.xex");
        assert_eq!(
            line(Event::ModuleLoad { module: &module, thread: 1, stopped: false }).as_bytes(),
            b"modload name=\"m\xe9.xex\" base=0x82000000 size=0x00001000 check=0x00000000 timestamp=0x00000000 pdata=0x00000000 psize=0x00000000 dll thread=0x00000001 osize=0x00001000"
        );
    }
}
