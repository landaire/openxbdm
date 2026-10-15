//! Process, thread, breakpoint, and execution control commands, and the
//! processing of debug events reported by the platform.

mod breakpoints;
mod context;
mod direct;
mod events;
mod kd;

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;

pub use self::breakpoints::BREAKPOINT_BLOCKS;
pub use self::breakpoints::Breakpoints;
pub use self::breakpoints::DataBreakpoint;
pub use self::breakpoints::DataKind;
pub use self::breakpoints::TRAP_INSTRUCTION;
use self::context::CONTEXT_SIZE;
pub use self::context::Context;
pub use self::context::ContextFlags;
use self::context::ContextLine;
pub use self::context::MSR_SINGLE_STEP;
pub use self::direct::Delivery;
pub use self::direct::DirectException;
pub use self::direct::DirectNotice;
pub use self::direct::DirectOutcome;
pub use self::direct::DirectPolicy;
pub use self::direct::DirectRegisters;
pub use self::direct::DirectStep;
pub use self::direct::ThreadNameRequest;
pub use self::direct::dispatch_direct;
pub use self::events::StopReason;
pub use self::events::process_events;
pub use self::kd::KDNET_RECORD_OFFSET;
pub use self::kd::KDNET_RECORD_SIZE;
pub use self::kd::load_extension;
pub use self::kd::release_extension;
use crate::access::Access;
use crate::backend::Backend as AnyBackend;
use crate::commands::filesystem::PoolBuffer;
use crate::commands::system::SettingsFile;
use crate::commands::system::end_line;
use crate::commands::system::write_bytes;
use crate::commands::util;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::network::Network;
use crate::network::SocketId;
use crate::notify::Event;
use crate::notify::ExecutionState;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::server::MAX_CONNECTIONS;
use crate::state::ServerState;
use crate::text::LineText;
use crate::text::Text;

const fn entry(
    name: &'static str,
    flags: DispatchFlags,
    handler: fn(&mut Invocation<'_>) -> Hresult,
) -> CommandEntry {
    CommandEntry {
        name,
        any_of: Access::CONTROL,
        all_of: Access::NONE,
        flags,
        handler,
    }
}

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry("break", DispatchFlags::DEVKIT_ONLY, set_breakpoint),
    entry("continue", DispatchFlags::NONE, continue_thread),
    entry("crashdump", DispatchFlags::NONE, crash_dump),
    entry("dbgextld", DispatchFlags::NONE, kd::debugger_extension),
    entry("debugger", DispatchFlags::NONE, debugger_identity),
    entry("getcontext", DispatchFlags::NONE, get_context),
    entry("getpid", DispatchFlags::NONE, get_process_id),
    entry("go", DispatchFlags::NONE, go),
    entry("halt", DispatchFlags::DEVKIT_ONLY, halt),
    entry("isbreak", DispatchFlags::DEVKIT_ONLY, is_breakpoint),
    entry("isdebugger", DispatchFlags::NONE, is_debugger),
    entry("isstopped", DispatchFlags::NONE, is_stopped),
    entry("kd", DispatchFlags::DEVKIT_ONLY, kd::kernel_debugger),
    entry("kdlite", DispatchFlags::NONE, kd::kernel_debugger_lite),
    entry(
        "kdnet",
        DispatchFlags::DEVKIT_ONLY,
        kd::kernel_debugger_network,
    ),
    entry("nostopon", DispatchFlags::NONE, no_stop_on),
    entry("resume", DispatchFlags::DEVKIT_ONLY, resume_thread),
    entry("setcontext", DispatchFlags::DEVKIT_ONLY, set_context),
    entry("stop", DispatchFlags::DEVKIT_ONLY, stop),
    entry("stopon", DispatchFlags::NONE, stop_on),
    entry("suspend", DispatchFlags::DEVKIT_ONLY, suspend_thread),
    entry("threadinfo", DispatchFlags::NONE, thread_info),
    entry("threads", DispatchFlags::NONE, threads),
    entry("threadstat", DispatchFlags::NONE, thread_status),
];

/// Kernel thread identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadId(pub u32);

/// The two processes whose threads the monitor controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessKind {
    Title,
    System,
}

/// Events that stop the reporting thread when they occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StopOn(pub u32);

impl StopOn {
    pub const CREATE_THREAD: Self = Self(0x1);
    /// First-chance exceptions.
    pub const FIRST_CHANCE_EXCEPTION: Self = Self(0x2);
    pub const DEBUG_STRING: Self = Self(0x4);
    pub const STACK_TRACE: Self = Self(0x8);
    pub const MODULE_LOAD: Self = Self(0x10);
    pub const POGO_MODULE_START: Self = Self(0x40);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Hardware information flag: a kernel debugger is attached.
pub const HARDWARE_KERNEL_DEBUGGER: u32 = 0x100;
/// Hardware information flag: the kernel debugger is enabled at boot.
pub const HARDWARE_KD_ENABLED: u32 = 0x80;
/// Hardware information flag: the console supports kd lite.
pub const HARDWARE_KD_LITE: u32 = 0x0200_0000;

/// Scheduler and stack information of a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThreadInfo {
    /// Kernel suspend count (signed byte).
    pub suspend_count: i8,
    /// The monitor suspended the thread while stopping execution.
    pub monitor_suspended: bool,
    pub priority: u8,
    pub tls_base: u32,
    pub start_address: u32,
    pub stack_base: u32,
    pub stack_limit: u32,
    pub create_time: u64,
    /// Copy of the name set by the thread-name exception.
    pub name: Option<ThreadName>,
    pub processor: u8,
    pub last_error: u32,
}

/// Address and length (including the terminating NUL) of a thread name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadName {
    pub address: u32,
    pub length: u32,
}

/// Exception record of a thread that entered the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExceptionRecord {
    pub code: u32,
    pub flags: u32,
    pub address: u32,
    pub parameter_count: u32,
    /// The first parameters.
    pub parameters: [u32; 4],
    /// Target address of the record; `params=` reports the address of its
    /// parameter array.
    pub record_address: u32,
}

impl ExceptionRecord {
    pub const BREAKPOINT: u32 = 0x8000_0003;
    pub const SINGLE_STEP: u32 = 0x8000_0004;
    pub const ACCESS_VIOLATION: u32 = 0xc000_0005;
    pub const NT_ASSERT: u32 = 0xc000_0420;
    pub const THREAD_NAME: u32 = 0x406d_1388;
    /// Record flag: the exception cannot be continued.
    pub const NONCONTINUABLE: u32 = 0x1;

    /// Trap code of a breakpoint exception (low half of the first
    /// parameter).
    pub const fn trap_code(&self) -> u16 {
        self.parameters[0] as u16
    }

    /// Target address of the parameter array.
    pub const fn parameters_address(&self) -> u32 {
        self.record_address.wrapping_add(0x14)
    }
}

/// Trap codes of breakpoint exceptions.
pub mod trap {
    pub const DEBUG_STRING: u16 = 0x14;
    pub const BREAKPOINT: u16 = 0x16;
    pub const MODULE_LOAD: u16 = 0x17;
    pub const MODULE_UNLOAD: u16 = 0x18;
    pub const ASSERT_PROMPT: u16 = 0x1a;
    pub const RIP: u16 = 0x1b;
    pub const DEBUG_SERVICE: u16 = 0x1c;
}

/// Description of a module that was loaded or unloaded, as the loader
/// reports it with its trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleEvent {
    pub name: [u8; MODULE_NAME_CAPACITY],
    pub name_length: usize,
    pub base: u32,
    pub size: u32,
    /// Image checksum and time stamp; zero without an image header.
    pub checksum: u32,
    pub timestamp: u32,
    pub pdata: u32,
    pub pdata_size: u32,
    /// `ModuleFlags` bits.
    pub flags: u32,
    pub image_size: u32,
    /// The image header was found.
    pub has_header: bool,
}

impl Default for ModuleEvent {
    fn default() -> Self {
        Self {
            name: [0; MODULE_NAME_CAPACITY],
            name_length: 0,
            base: 0,
            size: 0,
            checksum: 0,
            timestamp: 0,
            pdata: 0,
            pdata_size: 0,
            flags: 0,
            image_size: 0,
            has_header: false,
        }
    }
}

/// Bytes of a module name the monitor keeps.
pub const MODULE_NAME_CAPACITY: usize = 0x100;
/// Bytes of a debug string or rip message a notification carries.
pub const NOTICE_TEXT_CAPACITY: usize = 0x800;

/// Module description flags.
pub mod module_flags {
    pub const TLS: u32 = 0x1;
    pub const XBE: u32 = 0x2;
    pub const DLL: u32 = 0x4;
}

/// What the platform reports to the monitor. The reporting thread waits
/// until [`Backend::complete_event`] is called for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugEvent {
    /// A thread at passive level raised an exception. Its context is
    /// readable and writable through the thread context services until
    /// completion.
    Exception {
        thread: ThreadId,
        process: ProcessKind,
        record: ExceptionRecord,
        second_chance: bool,
        /// The thread has a monitor record.
        has_record: bool,
        /// The monitor record has the debuggable flag.
        debuggable: bool,
    },
    /// A debuggable thread was created and runs its start notification.
    ThreadCreate {
        thread: ThreadId,
        process: ProcessKind,
        start: u32,
        /// First thread of the title image.
        title_entry: bool,
    },
    ThreadTerminate {
        thread: ThreadId,
        process: ProcessKind,
    },
    /// A profile-guided module registered while `stopon pogomodstart` is
    /// set: the thread stops with a `pogomodstartup` line. `name` is the
    /// address of the NUL-terminated module path, `module` the module's
    /// profile record.
    PogoModuleStart {
        thread: ThreadId,
        process: ProcessKind,
        name: u32,
        module: u32,
    },
    /// A thread asks for an execution state change (the monitor's state
    /// machine without its wait flag) and waits until it is applied. A
    /// pending_title request while stopped waits for the state to change.
    ExecutionRequest {
        thread: ThreadId,
        process: ProcessKind,
        target: ExecutionState,
        notify: bool,
    },
    /// The title launch stops its thread with `execution pending_title
    /// stop` until execution starts. After `timeout` milliseconds the wait
    /// ends and the thread starts execution itself. Completion reports in
    /// `handled` whether the thread was released before the timeout.
    PendingTitleStop {
        thread: ThreadId,
        process: ProcessKind,
        debuggable: bool,
        timeout: Option<u32>,
    },
    /// The kernel ran out of stack on a thread and bug checks after the
    /// event. `record_address` is the stop record the platform built
    /// (code 0xc00000fd, noncontinuable, faulting `address`); its context
    /// is the thread context. `can_stop` holds when the thread is
    /// debuggable and was at passive level. Completion reports in
    /// `handled` whether a debugger continued the thread, after which the
    /// platform reports the event again; `write_dump` asks for the crash
    /// dump before the bug check.
    StackOverflow {
        thread: ThreadId,
        process: ProcessKind,
        address: u32,
        record_address: u32,
        can_stop: bool,
    },
}

impl DebugEvent {
    pub const fn thread(&self) -> ThreadId {
        match *self {
            Self::Exception { thread, .. }
            | Self::ThreadCreate { thread, .. }
            | Self::ThreadTerminate { thread, .. }
            | Self::PogoModuleStart { thread, .. }
            | Self::ExecutionRequest { thread, .. }
            | Self::PendingTitleStop { thread, .. }
            | Self::StackOverflow { thread, .. } => thread,
        }
    }

    pub const fn process(&self) -> ProcessKind {
        match *self {
            Self::Exception { process, .. }
            | Self::ThreadCreate { process, .. }
            | Self::ThreadTerminate { process, .. }
            | Self::PogoModuleStart { process, .. }
            | Self::ExecutionRequest { process, .. }
            | Self::PendingTitleStop { process, .. }
            | Self::StackOverflow { process, .. } => process,
        }
    }
}

/// How the platform finishes a reported event on the reporting thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Disposition {
    /// The exception is handled; execution continues at the context.
    pub handled: bool,
    /// Write a crash dump of the exception first.
    pub write_dump: bool,
    /// Pass the exception to the previous kernel debugger routine, whose
    /// result replaces `handled`.
    pub chain_kernel_debugger: bool,
    /// Execute a breakpoint trap after the event (title entry break).
    pub break_after: bool,
}

/// A thread lookup failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoSuchThread;

/// Failure of a thread context write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetContextError {
    NoSuchThread,
    /// The thread is not inside the monitor at a debug event.
    NotStopped,
}

/// Handle of a loaded debugger extension module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionHandle(pub u32);

/// Platform services this domain needs.
pub trait Backend {
    /// Store the execution state reported by `Platform::execution_state`.
    fn set_execution_state(&mut self, state: ExecutionState);
    /// Suspend every debuggable thread of `process` other than the caller
    /// that is not inside the monitor, not exempt, and not already
    /// suspended by the monitor, and mark it suspended by the monitor.
    fn suspend_threads(&mut self, process: ProcessKind);
    /// Resume every thread of `process` the monitor suspended.
    fn resume_threads(&mut self, process: ProcessKind);
    /// Suspend `thread` for the monitor unless it already is.
    fn monitor_suspend(&mut self, thread: ThreadId);
    /// Debuggable thread identifiers, title process first. `None` when
    /// more than `ids.len()` exist.
    fn thread_ids(&mut self, ids: &mut [ThreadId]) -> Option<usize>;
    fn thread_info(&mut self, thread: ThreadId) -> Result<ThreadInfo, NoSuchThread>;
    /// Whether the thread has a monitor record.
    fn has_monitor_record(&mut self, thread: ThreadId) -> Result<bool, NoSuchThread>;
    fn suspend_thread(&mut self, thread: ThreadId) -> Result<(), NoSuchThread>;
    fn resume_thread(&mut self, thread: ThreadId) -> Result<(), NoSuchThread>;
    /// Read the groups in `context.flags`. A thread inside the monitor
    /// reports its exception context; another thread reports its switch
    /// frame (control and integer only, with the monitor's fill values).
    /// `context.flags` is replaced by the groups returned. Fails for
    /// unknown threads and threads without a monitor record.
    fn thread_context(
        &mut self,
        thread: ThreadId,
        context: &mut Context,
    ) -> Result<(), NoSuchThread>;
    /// Write the groups in `context.flags` to the exception context of a
    /// thread inside the monitor.
    fn set_thread_context(
        &mut self,
        thread: ThreadId,
        context: &Context,
    ) -> Result<(), SetContextError>;
    /// Copy the NUL-terminated name at `address` as the name of `thread`.
    fn set_thread_name(&mut self, thread: ThreadId, address: u32);
    /// Exit status of the thread behind a handle of the monitor process:
    /// `Ok(0x103)` while it runs. `Err` carries the Win32 error.
    fn thread_exit_status(&mut self, handle: u32) -> Result<u32, u32>;
    /// Replace the instruction word at `address` through a writable
    /// mapping, synchronizing the instruction cache. Returns the previous
    /// word, or `None` when the address cannot be mapped.
    fn replace_code_word(&mut self, address: u32, value: u32) -> Option<u32>;
    /// `length` bytes of target memory at `address`, or `None` when part
    /// of the range is not readable.
    fn target_bytes(&mut self, address: u32, length: usize) -> Option<&[u8]>;
    /// Program the data address breakpoint register on every processor.
    fn set_data_breakpoint_register(&mut self, value: u32);
    /// Describe the module of a load or unload trap from the loader's
    /// name string and module entry.
    fn module_event(
        &mut self,
        name_string: u32,
        entry: u32,
        thread: ThreadId,
    ) -> Option<ModuleEvent>;
    /// Take the next reported event.
    fn next_event(&mut self) -> Option<DebugEvent>;
    /// Release the thread of a reported event.
    fn complete_event(&mut self, thread: ThreadId, disposition: Disposition);
    /// Keep the state direct exceptions are dispatched with.
    fn publish_direct_policy(&mut self, policy: &DirectPolicy);
    /// Take the oldest notification queued by a direct exception, copying
    /// its captured text into `text`.
    fn next_direct_notification(
        &mut self,
        text: &mut [u8; NOTICE_TEXT_CAPACITY],
    ) -> Option<DirectNotification>;
    /// Wait 250 ms, then execute a breakpoint trap on the calling thread.
    /// Returns the trap as an exception event that is processed like a
    /// reported one: the thread's context at the trap stays readable and
    /// writable until the event is completed. `None` when the trap did not
    /// reach the monitor.
    fn break_now(&mut self) -> Option<DebugEvent>;
    /// Wait 200 ms, then write a crash dump of the calling thread.
    fn crash_dump(&mut self);
    /// Kernel build number.
    fn kernel_build(&mut self) -> u16;
    /// Load a debugger extension image.
    fn load_extension(&mut self, path: &[u8]) -> Result<ExtensionHandle, NtStatus>;
    /// Unload a debugger extension image, calling its unload export.
    fn unload_extension(&mut self, handle: ExtensionHandle) -> Result<(), NtStatus>;
}

/// A notification queued by a direct exception, with what the platform
/// captured on the raising thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectNotification {
    pub thread: ThreadId,
    pub iar: u32,
    pub record: ExceptionRecord,
    pub notice: DirectNotice,
    /// Description of the module of a load or unload notice.
    pub module: Option<ModuleEvent>,
    /// Bytes of target text copied for a debug string or rip message.
    pub text_length: usize,
}

/// The attached debugger as recorded by `debugger`.
#[derive(Debug, Clone)]
pub struct DebuggerRecord {
    pub attached: bool,
    /// Address word as the monitor stores it: `addr=` puts the first octet
    /// in the low byte, a peer address is the network-order word.
    pub address: u32,
    pub port: u32,
    pub name: Text<DEBUGGER_NAME_CAPACITY>,
    pub user: Text<DEBUGGER_USER_CAPACITY>,
}

impl DebuggerRecord {
    pub const EMPTY: Self = Self {
        attached: false,
        address: 0,
        port: 0,
        name: Text::new(),
        user: Text::new(),
    };
}

pub const DEBUGGER_NAME_CAPACITY: usize = 0x7f;
pub const DEBUGGER_USER_CAPACITY: usize = 0xf;

/// Global state of this domain.
#[derive(Debug)]
pub struct State {
    /// Per-boot process identifier, generated on first use.
    pub process_id: Option<u32>,
    pub breakpoints: Breakpoints,
    pub data_breakpoint: Option<DataBreakpoint>,
    pub stop_on: StopOn,
    /// Break when the title's first thread starts.
    pub break_at_title_entry: bool,
    /// State restored by `go` after `stop`.
    pub saved_execution: ExecutionState,
    /// Debug exceptions go to the kernel debugger. `None` until first
    /// read from the hardware flags.
    pub kernel_debugger: Option<bool>,
    /// Unhandled debug exceptions are passed to the kernel debugger.
    pub kd_lite: bool,
    pub debugger: DebuggerRecord,
    pub extension: Option<kd::Extension>,
    /// First-chance breakpoint and trace exceptions pass through without
    /// the debugger (control code 0xa4).
    pub trap_passthrough: bool,
    /// Reply of a `break now` held until its thread is continued.
    held_reply: Option<HeldReply>,
    /// Pool blocks of `getcontext` transfers in progress.
    snapshots: [Option<Snapshot>; MAX_CONNECTIONS],
    events: events::Events,
}

/// The pool copy of a context a `getcontext` transfer sends from.
#[derive(Debug, Clone, Copy)]
struct Snapshot {
    socket: SocketId,
    buffer: PoolBuffer,
    /// The connection closed before the transfer ended.
    closed: bool,
}

/// A command reply sent when `thread` stops waiting at its event.
#[derive(Debug)]
struct HeldReply {
    thread: ThreadId,
    socket: SocketId,
    result: Hresult,
    text: LineText,
}

impl State {
    pub const fn new() -> Self {
        Self {
            process_id: None,
            breakpoints: Breakpoints::new(),
            data_breakpoint: None,
            stop_on: StopOn(0),
            break_at_title_entry: false,
            saved_execution: ExecutionState::Stopped,
            kernel_debugger: None,
            kd_lite: true,
            debugger: DebuggerRecord::EMPTY,
            extension: None,
            trap_passthrough: false,
            held_reply: None,
            snapshots: [None; MAX_CONNECTIONS],
            events: events::Events::new(),
        }
    }
}

impl State {
    /// Original byte under an armed software breakpoint.
    pub fn shadow_read(&self, address: u32) -> Option<u8> {
        self.breakpoints.shadow_read(address)
    }

    /// Store a byte into the saved instruction of an armed breakpoint;
    /// true when the address is under one.
    pub fn shadow_write(&mut self, address: u32, value: u8) -> bool {
        self.breakpoints.shadow_write(address, value)
    }

    /// Copy the saved instruction bytes of every software breakpoint
    /// overlapping `data`, read from `start`, over it.
    pub fn restore_saved(&self, start: u32, data: &mut [u8]) {
        self.breakpoints.restore_saved(start, data);
    }
}

/// Whether debug exceptions are routed to the kernel debugger.
pub(crate) fn kernel_debugger_enabled(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
) -> bool {
    *state
        .debugger
        .kernel_debugger
        .get_or_insert_with(|| backend.hardware_flags() & HARDWARE_KD_ENABLED != 0)
}

/// Apply the persisted kd lite flag (control code 0x63): console
/// configuration (2, 6) bit 1.
pub fn refresh_kd_lite(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    let mut value = [0u8; 4];
    let persisted = backend
        .xconfig_get(
            crate::commands::console::ConfigSetting::new(2, 6),
            &mut value,
        )
        .is_ok()
        && u32::from_be_bytes(value) & 0x2 != 0;
    state.debugger.kd_lite = persisted;
}

/// A kernel debugger break-in while threads are stopped: exceptions go to
/// the kernel debugger and every stopped thread runs again.
pub fn break_in(state: &mut ServerState, backend: &mut dyn AnyBackend, network: &mut dyn Network) {
    state.debugger.kernel_debugger = Some(true);
    events::release_all(state, backend, network);
}

/// Whether any thread is stopped at a debug event.
pub fn threads_stopped(state: &ServerState) -> bool {
    state.debugger.events.any_pending()
}

/// Whether a thread stopped at an exception keeps the title from being
/// relaunched in place (stock 0x91f276d8).
pub(crate) fn threads_block_relaunch(state: &ServerState, backend: &mut dyn AnyBackend) -> bool {
    events::relaunch_blocked(state, backend)
}

/// Send the held `break now` reply once its thread no longer waits at the
/// trap.
fn send_held_reply(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) {
    let Some(held) = state.debugger.held_reply.as_ref() else {
        return;
    };
    if events::is_waiting(state, held.thread) {
        return;
    }
    if let Some(held) = state.debugger.held_reply.take() {
        let _ = crate::server::send_status(
            state,
            backend,
            network,
            held.socket,
            held.result,
            held.text.as_bytes(),
        );
    }
}

/// A connection closed: a reply held for it is dropped and its context
/// snapshot is freed at the next event pass.
pub(crate) fn connection_closed(state: &mut ServerState, socket: SocketId) {
    if state
        .debugger
        .held_reply
        .as_ref()
        .is_some_and(|held| held.socket == socket)
    {
        state.debugger.held_reply = None;
    }
    for snapshot in state
        .debugger
        .snapshots
        .iter_mut()
        .flatten()
        .filter(|snapshot| snapshot.socket == socket)
    {
        snapshot.closed = true;
    }
}

/// Free the snapshots of closed connections.
fn release_closed_snapshots(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    for slot in &mut state.debugger.snapshots {
        if let Some(snapshot) = slot.take_if(|snapshot| snapshot.closed) {
            backend.free_pool(snapshot.buffer);
        }
    }
}

/// Transfers started by this domain.
// The thread list is captured when the command runs, as the monitor's
// 0x400-byte list allocation is.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Continuation {
    Threads {
        ids: [ThreadId; THREAD_LIST_CAPACITY],
        remaining: usize,
    },
    ThreadInfo {
        line: Text<0x100>,
        sent: bool,
    },
    /// Lines of the context copied into `snapshot` when the command ran.
    Context {
        snapshot: PoolBuffer,
        position: usize,
    },
}

/// Thread identifiers `threads` can report.
pub const THREAD_LIST_CAPACITY: usize = 0x100;

pub(crate) fn resume(continuation: &mut Continuation, cx: &mut ContinuationContext<'_>) -> Hresult {
    match continuation {
        Continuation::Threads { ids, remaining } => thread_lines(ids, remaining, cx),
        Continuation::ThreadInfo { line, sent } => {
            if *sent {
                return Hresult::END_OF_DATA;
            }
            *sent = true;
            cx.line.set_bytes(line.as_bytes());
            Hresult::OK
        }
        Continuation::Context { snapshot, position } => context_lines(*snapshot, position, cx),
    }
}

fn start_transfer(invocation: &mut Invocation<'_>, continuation: Continuation) -> bool {
    match invocation.session.as_deref_mut() {
        Some(session) => {
            session.receive_remaining = None;
            session.continuation = AnyContinuation::Debugger(continuation);
            true
        }
        None => false,
    }
}

/// `getpid`: a nonzero identifier generated once per boot from the time
/// base and the system time.
fn get_process_id(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.backend.execution_state() == ExecutionState::Pending {
        return Hresult::from_error_code(ErrorCode::NO_SUCH_THREAD);
    }
    let process_id = match invocation.state.debugger.process_id {
        Some(process_id) => process_id,
        None => loop {
            let timebase = invocation.backend.timebase() as u32;
            let time = invocation.backend.system_time() as u32;
            let candidate = timebase.wrapping_add(time);
            if candidate != 0 {
                invocation.state.debugger.process_id = Some(candidate);
                break candidate;
            }
        },
    };
    invocation.set_text(format_args!("pid=0x{process_id:08x}"));
    Hresult::OK
}

/// `break`: `now`, `start`, `clearall`, `addr=` with optional `clear`, or a
/// data breakpoint `read=|write=|readwrite=|execute=` with `size=`. `now`
/// stops the command thread at a trap; the reply follows once a debugger
/// continues it.
fn set_breakpoint(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    let now = line.has("now");
    let stopped = if now { break_now(invocation) } else { None };
    let flagged = [
        "start",
        "clearall",
        "addr",
        "read",
        "write",
        "readwrite",
        "execute",
    ]
    .iter()
    .any(|key| line.has(key));
    let result = if now && !flagged {
        Hresult::OK
    } else {
        breakpoint_flags(invocation)
    };
    let (Some(thread), Some(session)) = (stopped, invocation.session.as_ref()) else {
        return result;
    };
    let mut text = LineText::new();
    text.set_bytes(invocation.text.as_bytes());
    let socket = session.socket();
    invocation.state.debugger.held_reply = Some(HeldReply {
        thread,
        socket,
        result,
        text,
    });
    send_held_reply(invocation.state, invocation.backend, invocation.network);
    Hresult::NO_REPLY
}

/// Trap on the command thread and process the trap as a debug event.
/// Returns the thread when it waits at the trap.
fn break_now(invocation: &mut Invocation<'_>) -> Option<ThreadId> {
    let event = invocation.backend.break_now()?;
    let thread = event.thread();
    events::handle(
        invocation.state,
        invocation.backend,
        invocation.network,
        event,
    );
    Some(thread)
}

fn breakpoint_flags(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    if line.has("start") {
        let result = break_at_title_start(invocation.state, invocation.backend);
        if result != Hresult::OK {
            invocation.set_text(format_args!("execution not pending"));
        }
        return result;
    }
    if line.has("clearall") {
        let debugger = &mut invocation.state.debugger;
        debugger.breakpoints.clear_all(invocation.backend);
        debugger.data_breakpoint = None;
        invocation.backend.set_data_breakpoint_register(0);
        return Hresult::OK;
    }
    let clear = line.has("clear");
    if let Some(address) = util::required_dword(invocation, "addr") {
        return if clear {
            clear_software_breakpoint(invocation.state, invocation.backend, address)
        } else {
            set_software_breakpoint(invocation.state, invocation.backend, address)
        };
    }
    let dword = |key: &str| line.param(key).and_then(|value| value.dword());
    let (address, kind) = if let Some(address) = dword("read") {
        (address, Some(DataKind::Read))
    } else if let Some(address) = dword("write") {
        (address, Some(DataKind::Write))
    } else if let Some(address) = dword("readwrite") {
        (address, Some(DataKind::ReadWrite))
    } else if let Some(address) = dword("execute") {
        (address, None)
    } else {
        return util::MISSING;
    };
    let size = if clear {
        0
    } else {
        match util::required_dword(invocation, "size") {
            Some(size) => size,
            None => return util::MISSING,
        }
    };
    invocation.text.clear();
    let target = if clear {
        DataTarget::Clear
    } else {
        DataTarget::Set(kind)
    };
    set_data_breakpoint(invocation.state, invocation.backend, address, size, target)
}

/// Break when the title's first thread starts (stock export 39,
/// 0x91f26728): only while a title launch is pending.
pub fn break_at_title_start(state: &mut ServerState, backend: &mut dyn AnyBackend) -> Hresult {
    if matches!(
        backend.execution_state(),
        ExecutionState::Pending | ExecutionState::PendingTitle
    ) {
        state.debugger.break_at_title_entry = true;
        Hresult::OK
    } else {
        Hresult::FAIL
    }
}

/// Set a software breakpoint at an aligned address (stock export 37,
/// 0x91f27140).
pub fn set_software_breakpoint(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    address: u32,
) -> Hresult {
    match state.debugger.breakpoints.set(address, backend) {
        Ok(()) => Hresult::OK,
        Err(_) => Hresult::FAIL,
    }
}

/// Remove a software breakpoint (stock export 34, 0x91f27258).
pub fn clear_software_breakpoint(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    address: u32,
) -> Hresult {
    if state.debugger.breakpoints.clear(address, backend) {
        Hresult::OK
    } else {
        Hresult::FAIL
    }
}

/// What a data breakpoint request does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataTarget {
    Clear,
    /// `None` is a kind the monitor rejects (execute).
    Set(Option<DataKind>),
}

impl DataTarget {
    /// The type argument of stock export 38: 0 clears.
    pub const fn from_type(kind: u32) -> Self {
        match kind {
            0 => Self::Clear,
            1 => Self::Set(Some(DataKind::Write)),
            2 => Self::Set(Some(DataKind::ReadWrite)),
            5 => Self::Set(Some(DataKind::Read)),
            _ => Self::Set(None),
        }
    }
}

/// Set or clear the data breakpoint (stock export 38, 0x91f27370). The
/// monitor keeps the address 0 as "no breakpoint", so a breakpoint at 0 is
/// replaced by the next set and a clear of 0 always reprograms.
pub fn set_data_breakpoint(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    address: u32,
    size: u32,
    target: DataTarget,
) -> Hresult {
    let debugger = &mut state.debugger;
    let kind = match target {
        DataTarget::Clear => {
            if debugger
                .data_breakpoint
                .map_or(0, |current| current.address)
                == address
            {
                debugger.data_breakpoint = None;
                backend.set_data_breakpoint_register(0);
            }
            return Hresult::OK;
        }
        DataTarget::Set(kind) => kind,
    };
    if (address & 7).wrapping_add(size) > 8 {
        return Hresult::INVALID_ARGUMENT;
    }
    if let Some(current) = debugger
        .data_breakpoint
        .filter(|current| current.address != 0)
    {
        if Some(current.kind) == kind && current.address == address && current.size == size {
            // The monitor reprograms the registers with 0 here.
            backend.set_data_breakpoint_register(0);
            return Hresult::OK;
        }
        return Hresult::OUT_OF_MEMORY;
    }
    let Some(kind) = kind else {
        return Hresult::INVALID_ARGUMENT;
    };
    let breakpoint = DataBreakpoint {
        address,
        size,
        kind,
    };
    debugger.data_breakpoint = Some(breakpoint);
    backend.set_data_breakpoint_register(breakpoint.register());
    Hresult::OK
}

/// Breakpoint kind at `address` (stock export 56, 0x91f257f8): 4 for a
/// software breakpoint, else the data breakpoint kind when the address is
/// its exact address, else 0.
pub fn breakpoint_kind(state: &ServerState, address: u32) -> u32 {
    let debugger = &state.debugger;
    if debugger.breakpoints.contains(address) {
        return 4;
    }
    match debugger.data_breakpoint {
        Some(data) if data.address == address => data.kind as u32,
        _ => 0,
    }
}

/// `isbreak addr=`.
fn is_breakpoint(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(address) = util::required_dword(invocation, "addr") else {
        return util::MISSING;
    };
    let kind = breakpoint_kind(invocation.state, address);
    invocation.set_text(format_args!("type={kind}"));
    Hresult::OK
}

/// Change the execution state for a command (callers of the monitor's
/// state machine that test the current state first): stopped, started,
/// reboot_title, or pending_title.
pub(crate) fn change_execution(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    target: ExecutionState,
) -> Hresult {
    match (target, backend.execution_state()) {
        (
            ExecutionState::Stopped,
            ExecutionState::Stopped | ExecutionState::Pending | ExecutionState::PendingTitle,
        ) => Hresult::error(0x1a),
        (
            ExecutionState::Started,
            ExecutionState::Started | ExecutionState::RebootTitle | ExecutionState::Pending,
        ) => Hresult::from_error_code(ErrorCode::NOT_STOPPED),
        (ExecutionState::Started, ExecutionState::Rebooting) => Hresult::error(0),
        _ if transition(state, backend, network, target, true) => Hresult::OK,
        _ => Hresult::from_error_code(ErrorCode::ACCESS_DENIED),
    }
}

/// The monitor's execution state machine (0x91f2da88) without its wait
/// flag: apply the transition to `target` and report whether one applied.
/// `notify` sends the `execution` line.
fn transition(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    target: ExecutionState,
    notify: bool,
) -> bool {
    let current = backend.execution_state();
    let mut suspend = [false; 2];
    let mut resume = [false; 2];
    let mut release = [false; 2];
    let new = match (target, current) {
        (
            ExecutionState::Stopped,
            ExecutionState::Started | ExecutionState::Rebooting | ExecutionState::RebootTitle,
        ) => {
            state.debugger.saved_execution = current;
            suspend = [true, true];
            ExecutionState::Stopped
        }
        (ExecutionState::Started, ExecutionState::Stopped) => {
            let saved = state.debugger.saved_execution;
            resume = [saved != ExecutionState::RebootTitle, true];
            saved
        }
        (ExecutionState::Started, ExecutionState::PendingTitle) => {
            release = [true, true];
            resume = [true, true];
            ExecutionState::Started
        }
        (
            ExecutionState::RebootTitle,
            ExecutionState::Stopped | ExecutionState::Started | ExecutionState::Pending,
        ) => {
            release = [false, true];
            resume = [false, true];
            ExecutionState::RebootTitle
        }
        (ExecutionState::PendingTitle, ExecutionState::RebootTitle) => ExecutionState::PendingTitle,
        _ => return false,
    };
    for (index, process) in [ProcessKind::Title, ProcessKind::System]
        .into_iter()
        .enumerate()
    {
        if release[index] {
            events::release_stopped(state, backend, network, process);
        }
        if suspend[index] {
            backend.suspend_threads(process);
        }
        if resume[index] {
            backend.resume_threads(process);
        }
    }
    backend.set_execution_state(new);
    if notify {
        events::notify(state, backend, network, &Event::Execution(new));
    }
    if new != ExecutionState::Stopped {
        events::process_deferred(state, backend, network);
    }
    true
}

/// Stop the title (stock 0x91f25be0): `Hresult::OK` when it was stopped by
/// this call, 0x82da001a when already stopped, else 0x82da000e.
pub fn stop_execution(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) -> Hresult {
    change_execution(state, backend, network, ExecutionState::Stopped)
}

/// Resume the title (stock 0x91f25b50).
pub fn go_execution(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) -> Hresult {
    let target = if backend.execution_state() == ExecutionState::Pending {
        ExecutionState::RebootTitle
    } else {
        ExecutionState::Started
    };
    change_execution(state, backend, network, target)
}

/// `stop`.
fn stop(invocation: &mut Invocation<'_>) -> Hresult {
    let result = stop_execution(invocation.state, invocation.backend, invocation.network);
    if result == Hresult::error(0x1a) {
        invocation.set_text(format_args!("already stopped"));
    }
    result
}

/// `go`.
fn go(invocation: &mut Invocation<'_>) -> Hresult {
    let result = go_execution(invocation.state, invocation.backend, invocation.network);
    if result == Hresult::from_error_code(ErrorCode::NOT_STOPPED) {
        invocation.set_text(format_args!("not stopped"));
    }
    result
}

/// `halt [thread=]`: the monitor's halt routine always fails.
fn halt(_invocation: &mut Invocation<'_>) -> Hresult {
    Hresult::error(0)
}

fn required_thread(invocation: &mut Invocation<'_>) -> Option<ThreadId> {
    util::required_dword(invocation, "thread").map(ThreadId)
}

/// Continue a stopped thread (stock export 8, 0x91f25c60); `pass_exception`
/// leaves a first-chance exception unhandled.
pub fn continue_stopped_thread(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    thread: ThreadId,
    pass_exception: bool,
) -> Hresult {
    events::continue_thread(state, backend, network, thread, pass_exception)
}

/// `continue thread= [exception]`.
fn continue_thread(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(thread) = required_thread(invocation) else {
        return util::MISSING;
    };
    let pass_exception = invocation.line.has("exception");
    continue_stopped_thread(
        invocation.state,
        invocation.backend,
        invocation.network,
        thread,
        pass_exception,
    )
}

/// `suspend thread=`.
fn suspend_thread(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(thread) = required_thread(invocation) else {
        return util::MISSING;
    };
    match invocation.backend.suspend_thread(thread) {
        Ok(()) => Hresult::OK,
        Err(NoSuchThread) => Hresult::from_error_code(ErrorCode::NO_SUCH_THREAD),
    }
}

/// `resume thread=`.
fn resume_thread(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(thread) = required_thread(invocation) else {
        return util::MISSING;
    };
    match invocation.backend.resume_thread(thread) {
        Ok(()) => Hresult::OK,
        Err(NoSuchThread) => Hresult::from_error_code(ErrorCode::NO_SUCH_THREAD),
    }
}

/// What a thread is stopped at (stock export 22, 0x91f26058).
pub fn stop_reason(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    thread: ThreadId,
) -> Result<StopReason, Hresult> {
    events::stop_reason(state, backend, thread)
}

/// `isstopped thread=`: the event the thread is stopped at.
fn is_stopped(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(thread) = required_thread(invocation) else {
        return util::MISSING;
    };
    let reason = match stop_reason(invocation.state, invocation.backend, thread) {
        Ok(reason) => reason,
        Err(result) => return result,
    };
    let mut line = Text::<0x230>::new();
    events::stop_description(invocation.backend, &reason, &mut line);
    invocation.text.set_bytes(line.as_bytes());
    Hresult::OK
}

/// `threads`: identifiers of the debuggable threads as signed decimal
/// lines, in reverse enumeration order.
fn threads(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let mut ids = [ThreadId(0); THREAD_LIST_CAPACITY];
    let count = if invocation.backend.execution_state() == ExecutionState::Pending {
        0
    } else {
        match invocation.backend.thread_ids(&mut ids) {
            Some(count) => count,
            None => return Hresult::UNEXPECTED,
        }
    };
    start_transfer(
        invocation,
        Continuation::Threads {
            ids,
            remaining: count,
        },
    );
    invocation.set_text(format_args!("thread list follows"));
    Hresult::MULTILINE
}

fn thread_lines(
    ids: &[ThreadId; THREAD_LIST_CAPACITY],
    remaining: &mut usize,
    cx: &mut ContinuationContext<'_>,
) -> Hresult {
    if *remaining == 0 {
        return Hresult::END_OF_DATA;
    }
    let mut out = BinaryWriter {
        buffer: cx.binary,
        len: 0,
    };
    // Leave room for one more line in the raw buffer.
    while *remaining > 0 && out.len + 16 <= out.buffer.len() {
        *remaining -= 1;
        let _ = write!(out, "{}\r\n", ids[*remaining].0 as i32);
    }
    cx.binary_len = out.len;
    Hresult::OK
}

struct BinaryWriter<'a> {
    buffer: &'a mut [u8],
    len: usize,
}

impl core::fmt::Write for BinaryWriter<'_> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let bytes = text.as_bytes();
        let end = self.len + bytes.len();
        if end > self.buffer.len() {
            return Err(core::fmt::Error);
        }
        self.buffer[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

/// Thread stack slack the monitor reports.
const THREAD_SLACK: u32 = 0x540;

/// `threadinfo thread=`.
fn thread_info(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::error(0);
    }
    let Some(thread) = required_thread(invocation) else {
        return util::MISSING;
    };
    let info = match invocation.backend.thread_info(thread) {
        Ok(info) => info,
        Err(NoSuchThread) => return Hresult::from_error_code(ErrorCode::NO_SUCH_THREAD),
    };
    let suspend = i32::from(info.suspend_count) - i32::from(info.monitor_suspended);
    let name = info.name.unwrap_or(ThreadName {
        address: 0,
        length: 0,
    });
    let mut line = Text::<0x100>::new();
    let _ = write!(
        line,
        "suspend={suspend} priority={} tlsbase=0x{:08x} start=0x{:08x} base=0x{:08x} limit=0x{:08x} slack=0x{THREAD_SLACK:08x} \
         createhi=0x{:08x} createlo=0x{:08x} nameaddr=0x{:08x} namelen=0x{:08x} proc=0x{:02X} lasterr=0x{:08x}",
        info.priority,
        info.tls_base,
        info.start_address,
        info.stack_base,
        info.stack_limit,
        (info.create_time >> 32) as u32,
        info.create_time as u32,
        name.address,
        name.length,
        info.processor,
        info.last_error,
    );
    start_transfer(invocation, Continuation::ThreadInfo { line, sent: false });
    invocation.set_text(format_args!("thread info follows"));
    Hresult::MULTILINE
}

/// `getcontext thread= [control] [int] [fp] [vr] [full]`.
fn get_context(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let Some(thread) = required_thread(invocation) else {
        return util::MISSING;
    };
    let line = invocation.line;
    let mut flags = ContextFlags::NONE;
    for (name, group) in [
        ("control", ContextFlags::CONTROL),
        ("int", ContextFlags::INTEGER),
        ("fp", ContextFlags::FLOATING_POINT),
        ("vr", ContextFlags::VECTOR),
        ("full", ContextFlags::FULL),
    ] {
        if line.has(name) {
            flags = flags.union(group);
        }
    }
    let mut context = Context::EMPTY;
    context.flags = flags;
    if invocation
        .backend
        .thread_context(thread, &mut context)
        .is_err()
    {
        return Hresult::from_error_code(ErrorCode::NO_SUCH_THREAD);
    }
    let Some(socket) = invocation.session.as_ref().map(|session| session.socket()) else {
        return Hresult::FAIL;
    };
    release_closed_snapshots(invocation.state, invocation.backend);
    let Some(buffer) = invocation.backend.allocate_pool(SNAPSHOT_POOL_SIZE) else {
        return Hresult::OUT_OF_MEMORY;
    };
    let Some(slot) = invocation
        .state
        .debugger
        .snapshots
        .iter_mut()
        .find(|slot| slot.is_none())
    else {
        invocation.backend.free_pool(buffer);
        return Hresult::OUT_OF_MEMORY;
    };
    *slot = Some(Snapshot {
        socket,
        buffer,
        closed: false,
    });
    if let Some(bytes) = snapshot_bytes(invocation.backend, buffer) {
        context.encode(bytes);
    }
    start_transfer(
        invocation,
        Continuation::Context {
            snapshot: buffer,
            position: 0,
        },
    );
    Hresult::MULTILINE
}

/// Pool bytes of a `getcontext` copy (stock 0x91f482b0 allocates 0xa50).
const SNAPSHOT_POOL_SIZE: u32 = 0xa50;

fn snapshot_bytes(
    backend: &mut dyn AnyBackend,
    buffer: PoolBuffer,
) -> Option<&mut [u8; CONTEXT_SIZE]> {
    backend
        .pool(buffer)
        .get_mut(..CONTEXT_SIZE)
        .and_then(|bytes| bytes.try_into().ok())
}

/// Emit context lines from the copy the command made; the last call frees
/// it.
fn context_lines(
    snapshot: PoolBuffer,
    position: &mut usize,
    cx: &mut ContinuationContext<'_>,
) -> Hresult {
    let context = snapshot_bytes(cx.backend, snapshot)
        .map(|bytes| Context::decode(bytes))
        .unwrap_or_default();
    if ContextLine::first_from(*position, context.flags).is_none() {
        cx.backend.free_pool(snapshot);
        if let Some(slot) = cx
            .state
            .debugger
            .snapshots
            .iter_mut()
            .find(|slot| slot.is_some_and(|entry| entry.buffer == snapshot))
        {
            *slot = None;
        }
        return Hresult::END_OF_DATA;
    }
    let mut out = BinaryWriter {
        buffer: cx.binary,
        len: 0,
    };
    let limit = out.buffer.len().saturating_sub(0x40);
    while out.len < limit {
        let Some((index, line)) = ContextLine::first_from(*position, context.flags) else {
            break;
        };
        let mut text = Text::<0x80>::new();
        line.write(&context, &mut text);
        let _ = text.push_bytes(b"\r\n");
        let end = out.len + text.as_bytes().len();
        out.buffer[out.len..end].copy_from_slice(text.as_bytes());
        out.len = end;
        *position = index + 1;
    }
    cx.binary_len = out.len;
    Hresult::OK
}

/// `setcontext thread= <Reg>=<value>...`.
fn set_context(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(thread) = required_thread(invocation) else {
        return util::MISSING;
    };
    let mut context = Context::EMPTY;
    context.flags = ContextFlags::FULL;
    if invocation
        .backend
        .thread_context(thread, &mut context)
        .is_err()
    {
        return Hresult::from_error_code(ErrorCode::NO_SUCH_THREAD);
    }
    context::apply_parameters(&invocation.line, &mut context);
    context.flags = ContextFlags::FULL;
    match invocation.backend.set_thread_context(thread, &context) {
        Ok(()) => Hresult::OK,
        Err(SetContextError::NoSuchThread) => Hresult::from_error_code(ErrorCode::NO_SUCH_THREAD),
        Err(SetContextError::NotStopped) => Hresult::from_error_code(ErrorCode::NOT_STOPPED),
    }
}

const STOP_ON_FLAGS: [(&str, StopOn); 6] = [
    ("fce", StopOn::FIRST_CHANCE_EXCEPTION),
    ("debugstr", StopOn::DEBUG_STRING),
    ("createthread", StopOn::CREATE_THREAD),
    ("stacktrace", StopOn::STACK_TRACE),
    ("modload", StopOn::MODULE_LOAD),
    ("pogomodstart", StopOn::POGO_MODULE_START),
];

fn stop_on_mask(invocation: &mut Invocation<'_>, all_text: &str) -> u32 {
    if invocation.line.has("all") {
        invocation.set_text(format_args!("{all_text}"));
        return u32::MAX;
    }
    STOP_ON_FLAGS
        .iter()
        .filter(|(name, _)| invocation.line.has(name))
        .fold(0, |mask, (_, flag)| mask | flag.0)
}

/// Set or clear stop-on flags (stock export 46, 0x91f26790).
pub fn change_stop_on(state: &mut ServerState, mask: StopOn, enable: bool) {
    let stop_on = &mut state.debugger.stop_on.0;
    if enable {
        *stop_on |= mask.0;
    } else {
        *stop_on &= !mask.0;
    }
}

/// `stopon`.
fn stop_on(invocation: &mut Invocation<'_>) -> Hresult {
    let mask = stop_on_mask(invocation, "stop on all");
    change_stop_on(invocation.state, StopOn(mask), true);
    Hresult::OK
}

/// `nostopon`.
fn no_stop_on(invocation: &mut Invocation<'_>) -> Hresult {
    let mask = stop_on_mask(invocation, "stop on none");
    change_stop_on(invocation.state, StopOn(mask), false);
    Hresult::OK
}

/// `crashdump`: reply first, then write a dump of the calling thread.
fn crash_dump(invocation: &mut Invocation<'_>) -> Hresult {
    let _ = invocation.send_line(b"200- OK");
    invocation.backend.crash_dump();
    Hresult::NO_REPLY
}

/// `threadstat handle=`.
fn thread_status(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    let Some(handle) = kd::flag_number(&line, invocation.buffer, "handle") else {
        return Hresult::from_error_code(ErrorCode::BAD_PARAMETER);
    };
    match invocation.backend.thread_exit_status(handle) {
        Ok(code) => invocation.set_text(format_args!("Exit Code 0x{code:x}")),
        Err(error) => invocation.set_text(format_args!("Error 0x{error:x}")),
    }
    Hresult::OK
}

/// Parse `a.b.c.d`: up to three decimal digits per octet, `.` after the
/// first three and the end after the fourth; the first octet lands in the
/// low byte. Malformed text yields 0.
fn parse_dotted_address(text: &[u8]) -> u32 {
    let mut bytes = [0u8; 4];
    let mut position = 0;
    for (octet, slot) in bytes.iter_mut().enumerate() {
        let mut value = 0u8;
        let mut digits = 0;
        while digits < 3 && text.get(position).is_some_and(u8::is_ascii_digit) {
            value = value.wrapping_mul(10).wrapping_add(text[position] - b'0');
            position += 1;
            digits += 1;
        }
        let expected = if octet < 3 { Some(&b'.') } else { None };
        if digits == 0 || text.get(position) != expected {
            return 0;
        }
        position += 1;
        *slot = value;
    }
    u32::from_le_bytes(bytes)
}

fn debugger_target_exists(state: &ServerState, address: u32, port: u32) -> bool {
    state.notifications.targets().any(|target| {
        u32::from_be_bytes(target.endpoint.address.octets()) == address
            && u32::from(target.endpoint.port) == port & 0xffff
    })
}

/// `debugger connect|disconnect|init [addr=] [port=] [name=] [user=]
/// [override]`.
fn debugger_identity(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    let address = match line.param("addr") {
        Some(value) => {
            let mut buffer = [0u8; 0x14];
            parse_dotted_address(value.copy_into(&mut buffer))
        }
        None => match invocation.session.as_ref() {
            Some(session) => {
                let socket = session.socket();
                invocation
                    .network
                    .peer(socket)
                    .map_or(0, |peer| u32::from_be_bytes(peer.address.octets()))
            }
            None => 0,
        },
    };
    let port = line.param("port").and_then(|value| value.dword());
    let override_existing = line.has("override");
    let state = &mut *invocation.state;
    if line.has("connect") {
        let record = &state.debugger.debugger;
        if record.attached
            && record.port != 0
            && debugger_target_exists(state, record.address, record.port)
            && !override_existing
        {
            return Hresult::from_error_code(ErrorCode::FILE_ALREADY_EXISTS);
        }
        let changed = apply_identity(state, &line, address, port, true);
        let record = &mut state.debugger.debugger;
        record.attached = true;
        state.debugger.kernel_debugger = Some(false);
        if changed {
            state.settings_dirty = true;
        }
        return Hresult::OK;
    }
    if line.has("disconnect") {
        let record = &state.debugger.debugger;
        if record.port != 0
            && !(port == Some(record.port) && address == record.address)
            && !override_existing
        {
            return Hresult::from_error_code(ErrorCode::ACCESS_DENIED);
        }
        state.debugger.debugger = DebuggerRecord::EMPTY;
        state.debugger.kernel_debugger = Some(true);
        state.settings_dirty = true;
        return Hresult::OK;
    }
    if line.has("init") {
        if apply_identity(state, &line, address, port, false) {
            state.settings_dirty = true;
        }
        return Hresult::OK;
    }
    invocation.set_text(format_args!("no command"));
    Hresult::FAIL
}

/// Store the given identity fields; returns whether the settings changed.
/// `connect` counts name and user as changes, `init` does not.
fn apply_identity(
    state: &mut ServerState,
    line: &openxbdm_core::line::CommandLine<'_>,
    address: u32,
    port: Option<u32>,
    count_names: bool,
) -> bool {
    let record = &mut state.debugger.debugger;
    let mut changed = false;
    if let Some(port) = port {
        record.address = address;
        record.port = port;
        changed = true;
    }
    if let Some(value) = line.param("name") {
        let mut buffer = [0u8; DEBUGGER_NAME_CAPACITY + 1];
        record.name.set_bytes(value.copy_into(&mut buffer));
        changed |= count_names;
    }
    if let Some(value) = line.param("user") {
        let mut buffer = [0u8; DEBUGGER_USER_CAPACITY + 1];
        record.user.set_bytes(value.copy_into(&mut buffer));
        changed |= count_names;
    }
    changed
}

/// `isdebugger`.
fn is_debugger(invocation: &mut Invocation<'_>) -> Hresult {
    let record = invocation.state.debugger.debugger.clone();
    if !record.attached {
        return Hresult::OK;
    }
    if record.address != 0 && !debugger_target_exists(invocation.state, record.address, record.port)
    {
        return Hresult::OK;
    }
    if record.name.is_empty() && record.user.is_empty() {
        return Hresult::from_error_code(ErrorCode::FILE_ALREADY_EXISTS);
    }
    invocation.text.clear();
    let text = &mut *invocation.text;
    if !record.name.is_empty() {
        let _ = text.push_bytes(b"name=\"");
        let _ = text.push_bytes(record.name.as_bytes());
        let _ = text.push_bytes(b"\" ");
    }
    if !record.user.is_empty() {
        let _ = text.push_bytes(b"user=");
        let _ = text.push_bytes(record.user.as_bytes());
    }
    Hresult::from_error_code(ErrorCode::FILE_ALREADY_EXISTS)
}

/// Settings line of the attached debugger (stock 0x91f3ce50), written
/// when a debugger is attached. The address prints low byte first.
pub(crate) fn settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let record = &state.debugger.debugger;
    if !record.attached {
        return;
    }
    let octets = record.address.to_le_bytes();
    let mut line = Text::<0x1ff>::new();
    let _ = write!(
        line,
        "debugger init addr={}.{}.{}.{} port=0x{:08x}",
        octets[0], octets[1], octets[2], octets[3], record.port
    );
    if !record.name.is_empty() {
        let _ = line.push_bytes(b" name=\"");
        let _ = line.push_bytes(record.name.as_bytes());
        let _ = line.push_bytes(b"\"");
    }
    if !record.user.is_empty() {
        let _ = line.push_bytes(b" user=");
        let _ = line.push_bytes(record.user.as_bytes());
    }
    write_bytes(backend, file, line.as_bytes());
    end_line(backend, file);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_address_puts_first_octet_low() {
        assert_eq!(parse_dotted_address(b"192.168.1.20"), 0x1401_a8c0);
        assert_eq!(parse_dotted_address(b"1.2.3"), 0);
        assert_eq!(parse_dotted_address(b"1.2.3.4x"), 0);
        assert_eq!(parse_dotted_address(b"300.1.1.1"), 0x0101_012c);
        assert_eq!(parse_dotted_address(b"1234.1.1.1"), 0);
    }
}
