//! Session commands: connection lifetime, notification channels, command
//! processors, debug output capture, remote calls, the DEVKIT log, file
//! pipes, and the name discovery responder.

mod fastpipe;
mod fileevent;
mod notification;
mod rpc;
mod telllog;

pub use fastpipe::FastPipeBackend;
pub use fastpipe::FastPipes;
pub use fastpipe::PIPE_SLOTS;
pub use fastpipe::PipeGroup;
pub use fastpipe::on_readable as on_fast_pipe_readable;
pub use fileevent::EventPath;
pub use fileevent::FILE_EVENT_TEXT_LIMIT;
pub use fileevent::FLAG_BUFFERED;
pub use fileevent::FLAG_SCATTER_GATHER;
pub use fileevent::FLAG_SYNCHRONOUS;
pub use fileevent::FileEventBegin;
pub use fileevent::FileEventId;
pub use fileevent::FileEventText;
pub use fileevent::PseudoBegin;
pub use fileevent::PseudoBeginIo;
pub use fileevent::file_event_kind;
pub use fileevent::format_file_event_begin;
pub use fileevent::format_file_event_end;
pub use fileevent::format_file_event_switch;
pub use fileevent::format_mark_thread;
pub use fileevent::format_marker;
pub use fileevent::format_pseudo_begin;
pub use fileevent::format_pseudo_begin_io;
pub use fileevent::format_pseudo_end;
pub use fileevent::format_unmark_thread;
pub use notification::compare_names;
pub use notification::notification_kind_length;
pub use rpc::RpcBackend;
pub use rpc::RpcCall;
pub use rpc::RpcContext;
pub use rpc::RpcCreateError;
pub use rpc::RpcThread;
pub use rpc::RpcTransfer;
pub use telllog::LogEngineError;
pub use telllog::TELL_LOG_BUFFER_SIZE;
pub use telllog::TELL_LOG_LINE_LIMIT;
pub use telllog::TellLogAreas;
pub use telllog::TellLogBackend;
pub use telllog::TellLogConfig;
pub use telllog::TellLogCounters;
pub use telllog::TellLogFailed;
pub use telllog::TellLogReply;
pub use telllog::TellLogWriter;
pub use telllog::WaitTrace;
pub use telllog::WaitTraceLine;
pub use telllog::format_wait_trace;

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::KernelError;

use crate::access::Access;
use crate::backend::Backend as AnyBackend;
use crate::commands::filesystem::FileHandle;
use crate::commands::system;
use crate::commands::system::SettingsFile;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::DedicateTarget;
use crate::invocation::Invocation;
use crate::invocation::SessionRequest;
use crate::network::Endpoint;
use crate::network::Ipv4Address;
use crate::network::Network;
use crate::network::SocketId;
use crate::network::send_line;
use crate::notify::Event;
use crate::notify::ExecutionState;
use crate::notify::MAX_NOTIFICATION_TARGETS;
use crate::notify::POSTED_TEXT_CAPACITY;
use crate::notify::TargetFlags;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::text::Text;

/// Bytes of the debug capture ring.
pub const DEBUG_CAPTURE_SIZE: usize = 0x8000;
/// Longest message the capture producer stores.
const DEBUG_CAPTURE_MESSAGE: usize = 0x1ff;
/// A capture record ends after this many bytes when no LF ends it first;
/// the continuation buffer holds 0x100 bytes and the reader is given one
/// less, but stops only after copying one byte more.
const DEBUG_CAPTURE_RECORD: usize = 0x100;
/// Buffer the monitor copies `addr=` into.
const ADDRESS_TEXT_CAPACITY: usize = 0x14;
/// Buffer the monitor copies `handler=` into.
const HANDLER_NAME_CAPACITY: usize = 0x100;
/// Processors the server thread can be bound to.
const PROCESSOR_COUNT: u32 = 6;
/// `srvproc` binds to this processor when `num` is absent.
const DEFAULT_SERVER_PROCESSOR: u32 = 2;
/// Time persistent targets are given to connect, in FILETIME units.
const PERSISTENT_CONNECT_WINDOW: u64 = 30_000 * FILETIME_PER_MILLISECOND;
const FILETIME_PER_MILLISECOND: u64 = 10_000;

/// UDP port of the name discovery responder.
pub const DISCOVERY_PORT: u16 = 730;
/// Receive buffer of a discovery request and size of the reply buffer.
pub const DISCOVERY_PACKET_CAPACITY: usize = 0x102;
const DISCOVERY_LOOKUP: u8 = 1;
const DISCOVERY_REPLY: u8 = 2;
const DISCOVERY_IDENTIFY: u8 = 3;
/// Request flag: send the reply to the broadcast address.
const DISCOVERY_BROADCAST: u8 = 0x80;

pub(crate) const COMMANDS: &[CommandEntry] = &[
    CommandEntry::new(
        "bye",
        Access::NONE,
        Access::NONE,
        DispatchFlags::ANY_CONTEXT,
        bye,
    ),
    CommandEntry::new(
        "dbgprint",
        Access::READ,
        Access::NONE,
        DispatchFlags::DEVKIT_ONLY,
        debug_print,
    ),
    CommandEntry::new(
        "dedicate",
        Access::NONE,
        Access::NONE,
        DispatchFlags::ANY_CONTEXT,
        dedicate,
    ),
    CommandEntry::new(
        "dmtelllog",
        Access::CONTROL,
        Access::NONE,
        DispatchFlags::NONE,
        telllog::tell_log,
    ),
    CommandEntry::new(
        "fastpipe",
        Access::NONE,
        Access::NONE,
        DispatchFlags::NONE,
        fastpipe::fast_pipe,
    ),
    CommandEntry::new(
        "fileevent",
        Access::CONTROL,
        Access::NONE,
        DispatchFlags::NONE,
        file_event,
    ),
    CommandEntry::new(
        "notify",
        Access::CONTROL,
        Access::NONE,
        DispatchFlags::NONE,
        notify,
    ),
    CommandEntry::new(
        "notifyat",
        Access::CONTROL,
        Access::NONE,
        DispatchFlags::NONE,
        notify_at,
    ),
    CommandEntry::new(
        "notifyport",
        Access::CONTROL,
        Access::NONE,
        DispatchFlags::NONE,
        notify,
    ),
    CommandEntry::new(
        "spew",
        Access::READ,
        Access::NONE,
        DispatchFlags::DEVKIT_ONLY,
        spew,
    ),
    CommandEntry::new(
        "srvproc",
        Access::CONTROL,
        Access::NONE,
        DispatchFlags::NONE,
        server_processor,
    ),
    CommandEntry::new(
        "rpc",
        Access::CONTROL,
        Access::NONE,
        DispatchFlags::NONE,
        rpc::rpc,
    ),
];

/// A processor number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessorNumber(pub u8);

/// Write and read positions of the debug capture ring. The ring holds
/// messages back to back; a NUL follows the newest one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct DebugCapture {
    write: usize,
    /// Shared by every connection.
    read: usize,
}

/// Global state of this domain.
#[derive(Debug)]
pub struct State {
    capture: Option<DebugCapture>,
    /// FILETIME after which reverse persistent targets without a
    /// connection are dropped.
    reverse_deadline: Option<u64>,
    pub fast_pipes: FastPipes,
}

impl State {
    pub const fn new() -> Self {
        Self {
            capture: None,
            reverse_deadline: None,
            fast_pipes: FastPipes::new(),
        }
    }
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    /// `dbgprint` record stream.
    DebugPrint,
    Rpc(RpcTransfer),
}

/// Platform services this domain needs.
pub trait Backend: RpcBackend + FastPipeBackend + TellLogBackend {
    /// Allocate the debug capture ring; `false` when memory is exhausted.
    fn allocate_debug_capture(&mut self) -> bool;
    fn free_debug_capture(&mut self);
    /// The debug capture ring while it is allocated.
    fn debug_capture(&mut self) -> Option<&mut [u8; DEBUG_CAPTURE_SIZE]>;
    /// Processor executing the server thread.
    fn current_processor(&mut self) -> ProcessorNumber;
    /// Restrict the server thread to `processor`.
    fn set_server_processor(&mut self, processor: ProcessorNumber);
    /// Write a file's buffered data to its device.
    fn flush_file(&mut self, handle: FileHandle) -> Result<(), KernelError>;
    /// Switch file I/O event notifications and take the next event
    /// identifier, which the I/O events share.
    fn switch_file_events(&mut self, enable: bool) -> FileEventId;
    /// Take the oldest notification text another thread posted.
    fn next_posted_notification(&mut self, text: &mut [u8; POSTED_TEXT_CAPACITY]) -> Option<usize>;
    /// Run the in-process notification session handlers registered for
    /// `event` (stock 0x91f395c0), before its line goes to the channels.
    fn notify_sessions(&mut self, event: &Event<'_>);
}

/// Send the notification texts other threads have posted, in order.
pub fn send_posted_notifications(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) {
    let mut text = [0u8; POSTED_TEXT_CAPACITY];
    while let Some(length) = backend.next_posted_notification(&mut text) {
        state.notifications.send_text(&text[..length], network);
    }
}

pub(crate) fn resume(
    continuation: &mut Continuation,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    match continuation {
        Continuation::DebugPrint => debug_print_record(cx),
        Continuation::Rpc(transfer) => rpc::resume(transfer, cx),
    }
}

/// `bye`: reply `200- bye` and close the connection.
fn bye(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(session) = invocation.session.as_deref_mut() else {
        return Err(CommandError::InvalidArgument);
    };
    session.request(SessionRequest::Close);
    let _ = invocation.send_line(b"200- bye");
    Ok(Reply::Sent)
}

/// `notify` and `notifyport [reconnectport=<dword>] [debug] [reverse]`:
/// turn the connection into a notification channel. The channel receives
/// `205- now a notification channel` and the execution state line; no
/// status line follows.
fn notify(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(socket) = invocation
        .session
        .as_deref()
        .map(|session| session.socket())
    else {
        return Err(CommandError::Fail);
    };
    let (endpoint, persist) = match invocation.line.dword("reconnectport") {
        None => (
            Endpoint {
                address: Ipv4Address::UNSPECIFIED,
                port: 0,
            },
            false,
        ),
        Some(port) => match invocation.network.peer(socket) {
            // The monitor ends the command without any reply.
            Err(_) => return Ok(Reply::Sent),
            Ok(peer) => (
                Endpoint {
                    address: peer.address,
                    port: port as u16,
                },
                port != 0,
            ),
        },
    };
    let flags = target_flags(invocation);
    let execution = invocation.backend.execution_state();
    let notifications = &mut invocation.state.notifications;
    let registered = if endpoint.port == 0 {
        notifications
            .attach_socket(socket, None, invocation.network)
            .is_some()
    } else {
        notifications.register_target(
            endpoint,
            flags,
            false,
            Some(socket),
            execution,
            invocation.network,
        )
    };
    let announced = registered
        && send_line(
            invocation.network,
            socket,
            b"205- now a notification channel",
        )
        .is_ok()
        && send_execution_line(invocation.network, socket, execution);
    if !announced {
        // The socket stays with the connection, so the channel must not
        // keep it.
        if registered {
            invocation.state.notifications.detach_socket(socket);
        }
        invocation.text.set_bytes(b"notification limit exceeded");
        return Err(CommandError::Fail);
    }
    if let Some(session) = invocation.session.as_deref_mut() {
        session.request(SessionRequest::ReleaseSocket);
    }
    if persist {
        invocation.state.settings_dirty = true;
    }
    Ok(Reply::Sent)
}

fn send_execution_line(
    network: &mut dyn Network,
    socket: SocketId,
    execution: ExecutionState,
) -> bool {
    let mut line = Text::<0x20>::new();
    let _ = write!(line, "execution {}", execution.name());
    send_line(network, socket, line.as_bytes()).is_ok()
}

fn target_flags(invocation: &Invocation<'_>) -> TargetFlags {
    let mut flags = TargetFlags::NONE;
    if invocation.line.has("debug") {
        flags = flags.union(TargetFlags::DEBUG);
    }
    if invocation.line.has("reverse") {
        flags = flags.union(TargetFlags::REVERSE);
    }
    flags
}

/// `notifyat port=<dword> [addr=<a.b.c.d>] [drop] [debug] [reverse]`:
/// register a notification target (connected now unless `reverse`) or
/// drop every target with the endpoint.
fn notify_at(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(socket) = invocation
        .session
        .as_deref()
        .map(|session| session.socket())
    else {
        return Err(CommandError::Fail);
    };
    if !register_from_line(invocation, Some(socket), false) {
        return Err(CommandError::Fail);
    }
    invocation.state.settings_dirty = true;
    Ok(Reply::Ok)
}

/// A settings-file `notifyat` line: the target is recorded without a
/// connection and `addr=` is required.
pub(crate) fn ini_notifyat(invocation: &mut Invocation<'_>) {
    register_from_line(invocation, None, true);
}

/// The `notifyat` worker. `socket` supplies the default address.
fn register_from_line(
    invocation: &mut Invocation<'_>,
    socket: Option<SocketId>,
    reverse: bool,
) -> bool {
    let Some(port) = invocation.line.dword("port") else {
        return false;
    };
    let address = match invocation.line.param("addr") {
        Some(value) => {
            let mut buffer = [0u8; ADDRESS_TEXT_CAPACITY];
            parse_address(value.copy_into(&mut buffer))
        }
        None => match socket.map(|socket| invocation.network.peer(socket)) {
            Some(Ok(peer)) => peer.address,
            None | Some(Err(_)) => return false,
        },
    };
    let endpoint = Endpoint {
        address,
        port: port as u16,
    };
    if invocation.line.has("drop") {
        invocation
            .state
            .notifications
            .drop_targets(endpoint, invocation.network);
        return true;
    }
    let flags = target_flags(invocation);
    let reverse = reverse || flags.contains(TargetFlags::REVERSE);
    let execution = invocation.backend.execution_state();
    invocation.state.notifications.register_target(
        endpoint,
        flags,
        reverse,
        None,
        execution,
        invocation.network,
    )
}

/// Parse `a.b.c.d`: four groups of one to three decimal digits, each taken
/// modulo 256. The monitor stores the first group in the least significant
/// byte of a big-endian word that becomes `sin_addr` unchanged, so the
/// groups name the address bytes in reverse order. Malformed text gives the
/// unspecified address.
fn parse_address(text: &[u8]) -> Ipv4Address {
    let mut octets = [0u8; 4];
    let mut position = 0;
    for group in 0..4 {
        let mut value = 0u8;
        let mut digits = 0;
        while digits < 3 && text.get(position).is_some_and(u8::is_ascii_digit) {
            value = value.wrapping_mul(10).wrapping_add(text[position] - b'0');
            position += 1;
            digits += 1;
        }
        if digits == 0 {
            return Ipv4Address::UNSPECIFIED;
        }
        let separator = if group == 3 { None } else { Some(b'.') };
        if text.get(position).copied() != separator {
            return Ipv4Address::UNSPECIFIED;
        }
        position += 1;
        octets[3 - group] = value;
    }
    Ipv4Address(octets)
}

/// Settings-file lines for the notification targets.
pub(crate) fn notifyat_settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    for target in state.notifications.targets() {
        let [a, b, c, d] = target.endpoint.address.octets();
        let reverse = if target.flags.contains(TargetFlags::REVERSE) {
            " reverse"
        } else {
            ""
        };
        system::write_line(
            backend,
            file,
            format_args!(
                "notifyat addr={d}.{c}.{b}.{a} port={}{reverse}",
                target.endpoint.port
            ),
        );
    }
}

/// Connect the targets loaded from the settings file. Each non-reverse
/// target is connected and sent `hello`; reverse targets wait for a
/// `notify reconnectport=` connection. Targets get 30 seconds; the
/// remaining reverse wait is finished by [`expire_reverse_targets`].
pub fn connect_persistent_targets(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) {
    let deadline = backend
        .system_time()
        .saturating_add(PERSISTENT_CONNECT_WINDOW);
    let notifications = &mut state.notifications;
    let mut pending = [None::<SocketId>; MAX_NOTIFICATION_TARGETS];
    let mut reverse = false;
    for (index, socket) in pending.iter_mut().enumerate() {
        let Some(target) = notifications.target(index) else {
            continue;
        };
        if target.flags.contains(TargetFlags::REVERSE) {
            reverse = true;
        } else {
            match network.connect(target.endpoint, false) {
                Ok(connected) => *socket = Some(connected),
                Err(_) => notifications.remove_target(index),
            }
        }
    }
    let mut timed_out = false;
    for (index, socket) in pending.into_iter().enumerate() {
        let Some(socket) = socket else { continue };
        let now = backend.system_time();
        let ready = !timed_out
            && now < deadline
            && network
                .wait_writable(
                    socket,
                    (deadline - now).div_ceil(FILETIME_PER_MILLISECOND) as u32,
                )
                .is_ok();
        if !ready {
            // A timeout drops every target still connecting.
            timed_out = true;
            network.close(socket);
            notifications.remove_target(index);
            continue;
        }
        if network.set_blocking(socket, true).is_err() {
            // The monitor closes the socket but keeps the target.
            network.close(socket);
            continue;
        }
        if send_line(network, socket, b"hello").is_err()
            || notifications
                .attach_socket(socket, Some(index), network)
                .is_none()
        {
            network.close(socket);
            notifications.remove_target(index);
        }
    }
    if reverse {
        state.session.reverse_deadline = Some(deadline);
    } else {
        state.settings_dirty = true;
    }
    expire_reverse_targets(state, backend);
}

/// End the wait for reverse persistent targets once each has a connection
/// or the deadline has passed; targets still without one are dropped and
/// the settings file is rewritten.
pub fn expire_reverse_targets(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    let Some(deadline) = state.session.reverse_deadline else {
        return;
    };
    let waiting = |index: usize, state: &ServerState| {
        state
            .notifications
            .target(index)
            .is_some_and(|t| t.flags.contains(TargetFlags::REVERSE) && t.socket_slot.is_none())
    };
    let any_waiting = (0..MAX_NOTIFICATION_TARGETS).any(|index| waiting(index, state));
    if any_waiting && backend.system_time() < deadline {
        return;
    }
    for index in 0..MAX_NOTIFICATION_TARGETS {
        if waiting(index, state) {
            state.notifications.remove_target(index);
        }
    }
    state.session.reverse_deadline = None;
    state.settings_dirty = true;
}

/// `dedicate global` or `dedicate handler=<name>`: move the connection to
/// the main server context or to a command processor. Success sends only
/// `205- connection dedicated`.
fn dedicate(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::InvalidArgument);
    }
    let target = if invocation.line.has("global") {
        DedicateTarget::Main
    } else {
        let Some(value) = invocation.line.param("handler") else {
            invocation.text.set_bytes(b"missing handler");
            return Err(CommandError::Fail);
        };
        let mut buffer = [0u8; HANDLER_NAME_CAPACITY];
        let name = value.copy_into(&mut buffer);
        match invocation.backend.find_processor(name) {
            Some((index, _)) => DedicateTarget::Processor(index),
            None => return Err(ErrorCode::FileNotFound.into()),
        }
    };
    if let Some(session) = invocation.session.as_deref_mut() {
        session.request(SessionRequest::Dedicate(target));
    }
    Ok(Reply::Sent)
}

/// `dbgprint start=` | `stop=` | `[reset=]`: control the debug capture ring
/// or stream its records.
fn debug_print(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(ErrorCode::BadParameter.into());
    }
    let state = &mut invocation.state.session;
    if invocation.line.param("start").is_some() {
        if state.capture.is_some() {
            invocation.text.set_bytes(b"Debug capture already started");
            return Err(CommandError::Fail);
        }
        let result = if invocation.backend.allocate_debug_capture() {
            if let Some(ring) = invocation.backend.debug_capture() {
                ring[0] = 0;
            }
            state.capture = Some(DebugCapture::default());
            Ok(Reply::Ok)
        } else {
            Err(ErrorCode::OutOfMemory.into())
        };
        invocation
            .text
            .set_bytes(reply::hresult(result).default_message().as_bytes());
        return result;
    }
    if invocation.line.param("stop").is_some() {
        if state.capture.take().is_some() {
            invocation.backend.free_debug_capture();
        }
        invocation.text.set_bytes(b"OK");
        return Ok(Reply::Ok);
    }
    let Some(capture) = state.capture.as_mut() else {
        invocation
            .text
            .set_bytes(b"Debug capture not started (use 'start' option to start capture)");
        return Err(CommandError::Fail);
    };
    if invocation.line.param("reset").is_some() {
        capture.read = 0;
    }
    if let Some(session) = invocation.session.as_deref_mut() {
        session.continuation = AnyContinuation::Session(Continuation::DebugPrint);
    }
    invocation.text.set_bytes(b"Debug print strings follow");
    Ok(Reply::Multiline)
}

/// Send the next capture record without its trailing LF.
fn debug_print_record(cx: &mut ContinuationContext<'_>) -> CommandResult {
    let Some(capture) = cx.state.session.capture.as_mut() else {
        return Err(CommandError::EndOfData);
    };
    let Some(ring) = cx.backend.debug_capture() else {
        return Err(CommandError::EndOfData);
    };
    let Some((start, end)) = next_record(ring, capture) else {
        return Err(CommandError::EndOfData);
    };
    let record = &ring[start..end];
    let record = record.strip_suffix(b"\n").unwrap_or(record);
    cx.line.set_bytes(record);
    Ok(Reply::Ok)
}

/// Find the record at the read cursor: bytes up to and including an LF,
/// or `DEBUG_CAPTURE_RECORD` bytes, before a NUL or the ring end. Reaching
/// a NUL beyond the write position restarts once at the ring start. The
/// monitor loops forever when the restarted scan meets a NUL without an LF
/// before it; the stream ends there instead.
fn next_record(
    ring: &[u8; DEBUG_CAPTURE_SIZE],
    capture: &mut DebugCapture,
) -> Option<(usize, usize)> {
    let mut start = capture.read;
    let mut position = start;
    let mut restarted = false;
    loop {
        while position < DEBUG_CAPTURE_SIZE && ring[position] != 0 {
            position += 1;
            if ring[position - 1] == b'\n' || position - start >= DEBUG_CAPTURE_RECORD {
                capture.read = position;
                return Some((start, position));
            }
        }
        if position <= capture.write {
            capture.read = position;
            return None;
        }
        if restarted {
            capture.read = 0;
            return None;
        }
        restarted = true;
        start = 0;
        position = 0;
    }
}

/// Append a message to the debug capture ring when capture is active. The
/// message is cut to 0x1ff bytes and stored with a NUL that the next
/// message overwrites; a message that does not fit before the ring end is
/// stored at the ring start.
pub fn debug_capture_print(state: &mut ServerState, backend: &mut dyn AnyBackend, message: &[u8]) {
    let Some(capture) = state.session.capture.as_mut() else {
        return;
    };
    let Some(ring) = backend.debug_capture() else {
        return;
    };
    let length = message.len().min(DEBUG_CAPTURE_MESSAGE);
    let mut offset = capture.write;
    if offset + length + 1 >= DEBUG_CAPTURE_SIZE {
        offset = 0;
    }
    ring[offset..offset + length].copy_from_slice(&message[..length]);
    ring[offset + length] = 0;
    capture.write = offset + length;
}

/// `fileevent advise` | `fileevent unadvise`: switch file I/O event
/// notifications and announce `XBDMFE!Start` or `XBDMFE!Stop` with a new
/// sequence number on every notification channel.
fn file_event(invocation: &mut Invocation<'_>) -> CommandResult {
    let enable = if invocation.line.has("advise") {
        true
    } else if invocation.line.has("unadvise") {
        false
    } else {
        return Err(CommandError::Fail);
    };
    // Texts posted before the switch go out first, as the monitor sends
    // them in their threads.
    send_posted_notifications(invocation.state, invocation.backend, invocation.network);
    let sequence = invocation.backend.switch_file_events(enable);
    let line = format_file_event_switch(enable, sequence);
    invocation
        .state
        .notifications
        .send_text(line.as_bytes(), invocation.network);
    Ok(Reply::Ok)
}

/// `spew <text>`: write the command line to the debug output.
fn spew(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut output = Text::<{ crate::server::RECEIVE_CAPACITY + 8 }>::new();
    let _ = output.push_bytes(b"SPEW: ");
    let _ = output.push_bytes(invocation.line.as_bytes());
    let _ = output.push_bytes(b"\n");
    invocation.backend.debug_print(output.as_bytes());
    invocation.text.set_bytes(b"OK");
    Ok(Reply::Ok)
}

/// `srvproc [num=<dword>]`: report the processor running the server thread
/// and bind the thread to processor `num` (default 2).
fn server_processor(invocation: &mut Invocation<'_>) -> CommandResult {
    // An absent or malformed value selects the default.
    let number = invocation
        .line
        .dword("num")
        .unwrap_or(DEFAULT_SERVER_PROCESSOR);
    if number >= PROCESSOR_COUNT {
        return Err(ErrorCode::UnknownCommand.into());
    }
    let previous = invocation.backend.current_processor();
    invocation.set_text(format_args!("prev={}", previous.0));
    invocation
        .backend
        .set_server_processor(ProcessorNumber(number as u8));
    Ok(Reply::Ok)
}

/// Where a discovery reply goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryDestination {
    /// The address and port the request came from.
    Sender,
    /// The broadcast address at the sender's port.
    Broadcast,
}

/// A discovery reply in the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryReply {
    pub length: usize,
    pub destination: DiscoveryDestination,
}

/// Answer a discovery datagram with the console's debug name.
pub fn answer_discovery(
    state: &ServerState,
    request: &[u8],
    reply: &mut [u8; DISCOVERY_PACKET_CAPACITY],
) -> Option<DiscoveryReply> {
    discovery_reply(state.console.debug_name.as_bytes(), request, reply)
}

/// Answer a name discovery datagram. Type 3 asks every console for its
/// name; type 1 asks the console whose debug name equals the given name,
/// ignoring ASCII case. The reply is type 2, a length byte, and the name.
/// Request bit 0x80 selects a broadcast reply. A request name with an
/// embedded NUL is not matched.
pub fn discovery_reply(
    name: &[u8],
    request: &[u8],
    reply: &mut [u8; DISCOVERY_PACKET_CAPACITY],
) -> Option<DiscoveryReply> {
    let (&kind, body) = request.split_first()?;
    match kind & !DISCOVERY_BROADCAST {
        DISCOVERY_IDENTIFY => {}
        DISCOVERY_LOOKUP => {
            let (&length, requested) = body.split_first()?;
            let length = usize::from(length);
            if length == 0 || requested.len() != length || !requested.eq_ignore_ascii_case(name) {
                return None;
            }
        }
        _ => return None,
    }
    let length = name.len().min(usize::from(u8::MAX));
    reply[0] = DISCOVERY_REPLY;
    reply[1] = length as u8;
    reply[2..2 + length].copy_from_slice(&name[..length]);
    let destination = if kind & DISCOVERY_BROADCAST != 0 {
        DiscoveryDestination::Broadcast
    } else {
        DiscoveryDestination::Sender
    };
    Some(DiscoveryReply {
        length: 2 + length,
        destination,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_parse_in_reverse_group_order() {
        assert_eq!(parse_address(b"1.2.3.4"), Ipv4Address([4, 3, 2, 1]));
        assert_eq!(parse_address(b"300.0.0.1"), Ipv4Address([1, 0, 0, 44]));
        assert_eq!(parse_address(b"1.2.3"), Ipv4Address::UNSPECIFIED);
        assert_eq!(parse_address(b"1.2.3.4x"), Ipv4Address::UNSPECIFIED);
        assert_eq!(parse_address(b"1234.2.3.4"), Ipv4Address::UNSPECIFIED);
    }

    #[test]
    fn capture_records_split_at_lf_and_wrap_once() {
        let mut ring = [0u8; DEBUG_CAPTURE_SIZE];
        ring[..9].copy_from_slice(b"a\nbc\nde\n\0");
        let mut capture = DebugCapture { write: 8, read: 0 };
        assert_eq!(next_record(&ring, &mut capture), Some((0, 2)));
        assert_eq!(next_record(&ring, &mut capture), Some((2, 5)));
        assert_eq!(next_record(&ring, &mut capture), Some((5, 8)));
        assert_eq!(next_record(&ring, &mut capture), None);
        assert_eq!(capture.read, 8);

        // A NUL past the write position restarts the scan at the ring start.
        let mut capture = DebugCapture {
            write: 2,
            read: 0x7000,
        };
        assert_eq!(next_record(&ring, &mut capture), Some((0, 2)));
    }

    #[test]
    fn capture_records_without_lf_end_after_0x100_bytes() {
        let mut ring = [0u8; DEBUG_CAPTURE_SIZE];
        ring[..0x180].fill(b'x');
        let mut capture = DebugCapture {
            write: 0x180,
            read: 0,
        };
        assert_eq!(next_record(&ring, &mut capture), Some((0, 0x100)));
        assert_eq!(next_record(&ring, &mut capture), None);
    }

    #[test]
    fn discovery_answers_identify_and_matching_lookup() {
        let mut reply = [0u8; DISCOVERY_PACKET_CAPACITY];
        let answer = discovery_reply(b"Kit", &[3], &mut reply).unwrap();
        assert_eq!(&reply[..answer.length], b"\x02\x03Kit");
        assert_eq!(answer.destination, DiscoveryDestination::Sender);
        let answer = discovery_reply(b"Kit", b"\x81\x03kIT", &mut reply).unwrap();
        assert_eq!(answer.destination, DiscoveryDestination::Broadcast);
        assert_eq!(discovery_reply(b"Kit", b"\x01\x02Ki", &mut reply), None);
        assert_eq!(discovery_reply(b"Kit", b"\x01\x03Kitx", &mut reply), None);
        assert_eq!(discovery_reply(b"Kit", b"\x02\x03Kit", &mut reply), None);
        assert_eq!(discovery_reply(b"", &[1, 0], &mut reply), None);
    }
}
