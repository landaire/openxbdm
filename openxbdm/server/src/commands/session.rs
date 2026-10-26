//! Session commands: connection lifetime, notification channels, command
//! processors, debug output capture, remote calls, the DEVKIT log, file
//! pipes, and the name discovery responder.

mod capture;
mod discovery;
mod error;
mod fastpipe;
mod fileevent;
mod notification;
mod rpc;
mod telllog;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::KernelError;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;

use self::capture::DebugCapture;
use self::capture::debug_print;
use self::capture::debug_print_record;
use self::capture::spew;
use self::fileevent::file_event;
use self::notification::notify;
use self::notification::notify_at;
use crate::access::Access;
use crate::commands::filesystem::FileHandle;
use crate::continuation::ContinuationContext;
use crate::invocation::DedicateTarget;
use crate::invocation::Invocation;
use crate::invocation::SessionRequest;
use crate::notify::Event;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

pub use capture::DEBUG_CAPTURE_SIZE;
pub use capture::DebugCaptureRing;
pub use capture::ReservationEvent;
pub use discovery::DISCOVERY_PACKET_CAPACITY;
pub use discovery::DiscoveryDestination;
pub use discovery::DiscoveryFlags;
pub use discovery::DiscoveryOpcode;
pub use discovery::DiscoveryReply;
pub use discovery::answer_discovery;
pub use discovery::discovery_reply;
pub use error::LogEngineError;
pub use error::RpcCreateError;
pub use error::TellLogFailed;
pub use fastpipe::FastPipeBackend;
pub use fastpipe::FastPipes;
pub use fastpipe::PIPE_SLOTS;
pub use fastpipe::PipeGroup;
pub use fastpipe::on_readable as on_fast_pipe_readable;
pub use fileevent::EventPath;
pub use fileevent::FILE_EVENT_TEXT_LIMIT;
pub use fileevent::FileEventBegin;
pub use fileevent::FileEventFlags;
pub use fileevent::FileEventId;
pub use fileevent::FileEventText;
pub use fileevent::FileEventTitles;
pub use fileevent::FileOperationClass;
pub use fileevent::PseudoBegin;
pub use fileevent::PseudoBeginIo;
pub use fileevent::PseudoOptions;
pub use fileevent::file_event_kind;
pub use fileevent::file_mode_flags;
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
pub use notification::connect_persistent_targets;
pub use notification::expire_reverse_targets;
pub(crate) use notification::ini_notifyat;
pub use notification::notification_kind_length;
pub(crate) use notification::notifyat_settings_lines;
pub use notification::send_posted_notifications;
pub use rpc::RpcBackend;
pub use rpc::RpcCall;
pub use rpc::RpcContext;
pub use rpc::RpcThread;
pub use rpc::RpcTransfer;
pub use telllog::TELL_LOG_BUFFER_SIZE;
pub use telllog::TELL_LOG_LINE_LIMIT;
pub use telllog::TellLogAreas;
pub use telllog::TellLogBackend;
pub use telllog::TellLogConfig;
pub use telllog::TellLogCounters;
pub use telllog::TellLogReply;
pub use telllog::TellLogWriter;
pub use telllog::WaitTrace;
pub use telllog::WaitTraceLine;
pub use telllog::format_wait_trace;

pub(crate) const COMMANDS: &[CommandEntry] = &[
    CommandEntry::new(
        "bye",
        Access::empty(),
        Access::empty(),
        DispatchFlags::ANY_CONTEXT,
        bye,
    ),
    CommandEntry::new(
        "dbgprint",
        Access::READ,
        Access::empty(),
        DispatchFlags::DEVKIT_ONLY,
        debug_print,
    ),
    CommandEntry::new(
        "dedicate",
        Access::empty(),
        Access::empty(),
        DispatchFlags::ANY_CONTEXT,
        dedicate,
    ),
    CommandEntry::new(
        "dmtelllog",
        Access::CONTROL,
        Access::empty(),
        DispatchFlags::empty(),
        telllog::tell_log,
    ),
    CommandEntry::new(
        "fastpipe",
        Access::empty(),
        Access::empty(),
        DispatchFlags::empty(),
        fastpipe::fast_pipe,
    ),
    CommandEntry::new(
        "fileevent",
        Access::CONTROL,
        Access::empty(),
        DispatchFlags::empty(),
        file_event,
    ),
    CommandEntry::new(
        "notify",
        Access::CONTROL,
        Access::empty(),
        DispatchFlags::empty(),
        notify,
    ),
    CommandEntry::new(
        "notifyat",
        Access::CONTROL,
        Access::empty(),
        DispatchFlags::empty(),
        notify_at,
    ),
    CommandEntry::new(
        "notifyport",
        Access::CONTROL,
        Access::empty(),
        DispatchFlags::empty(),
        notify,
    ),
    CommandEntry::new(
        "spew",
        Access::READ,
        Access::empty(),
        DispatchFlags::DEVKIT_ONLY,
        spew,
    ),
    CommandEntry::new(
        "srvproc",
        Access::CONTROL,
        Access::empty(),
        DispatchFlags::empty(),
        server_processor,
    ),
    CommandEntry::new(
        "rpc",
        Access::CONTROL,
        Access::empty(),
        DispatchFlags::empty(),
        rpc::rpc,
    ),
];

/// A processor number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessorNumber(pub u8);

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
    /// Allocate the debug capture ring with its first byte and write offset
    /// cleared, then publish it to the producers; `false` when memory is
    /// exhausted.
    fn allocate_debug_capture(&mut self) -> bool;
    /// Withdraw the ring from the producers, wait for those still writing,
    /// free it and clear the write offset.
    fn free_debug_capture(&mut self);
    /// The debug capture ring while it is allocated.
    fn debug_capture(&mut self) -> Option<DebugCaptureRing<'_>>;
    /// Processor executing the server thread.
    fn current_processor(&mut self) -> ProcessorNumber;
    /// Restrict the server thread to `processor`.
    fn set_server_processor(&mut self, processor: ProcessorNumber);
    /// Write a file's buffered data to its device.
    fn flush_file(&mut self, handle: FileHandle) -> Result<(), KernelError>;
    /// Switch file I/O event notifications and take the next event
    /// identifier, which the I/O events share.
    fn switch_file_events(&mut self, enable: bool) -> FileEventId;
    /// Take the oldest notification text another thread posted and pass it
    /// to `send`; `false` when none is queued.
    fn send_next_posted_notification(&mut self, send: &mut dyn FnMut(&[u8])) -> bool;
    /// Run the in-process notification session handlers registered for
    /// `event` (stock 0x91f395c0), before its line goes to the channels.
    fn notify_sessions(&mut self, event: &Event<'_>);
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

/// `dedicate global` or `dedicate handler=<name>`: move the connection to
/// the main server context or to a command processor. Success sends only
/// `205- connection dedicated`.
fn dedicate(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Buffer the monitor copies `handler=` into.
    const HANDLER_NAME_CAPACITY: usize = 0x100;

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

/// `srvproc [num=<dword>]`: report the processor running the server thread
/// and bind the thread to processor `num` (default 2).
fn server_processor(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Processor bound when `num` is absent.
    const DEFAULT_SERVER_PROCESSOR: u32 = 2;

    // An absent or malformed value selects the default.
    let number = invocation
        .line
        .dword("num")
        .unwrap_or(DEFAULT_SERVER_PROCESSOR);
    if number >= HARDWARE_THREAD_COUNT as u32 {
        return Err(ErrorCode::UnknownCommand.into());
    }

    let previous = invocation.backend.current_processor();
    invocation.set_text(format_args!("prev={}", previous.0));

    invocation
        .backend
        .set_server_processor(ProcessorNumber(number as u8));

    Ok(Reply::Ok)
}
