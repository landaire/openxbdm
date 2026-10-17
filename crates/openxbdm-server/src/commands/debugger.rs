//! Process, thread, breakpoint, and execution control commands, and the
//! processing of debug events reported by the platform.

// Backend::module_event and Backend::set_thread_name take raw console addresses.
#![allow(unsafe_code)]

mod break_command;
mod breakpoints;
mod context;
mod direct;
mod error;
mod events;
mod execution;
mod identity;
mod kd;
mod stop_on;
mod thread_context;
mod threads;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;

use self::break_command::HeldReply;
// `events` reaches these through `super::`.
use self::break_command::send_held_reply;
use self::execution::transition;
use crate::access::Access;
use crate::backend::Backend as AnyBackend;
use crate::commands::console::ConfigSetting;
use crate::commands::console::ConsoleConfigFlags;
use crate::commands::services::ThreadHandle;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::network::Network;
use crate::notify::ExecutionState;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::transfer_blocks::TransferBlock;

pub use self::break_command::DataTarget;
pub use self::break_command::break_at_title_start;
pub use self::break_command::breakpoint_kind;
pub use self::break_command::clear_software_breakpoint;
pub(crate) use self::break_command::connection_closed;
pub use self::break_command::set_data_breakpoint;
pub use self::break_command::set_software_breakpoint;
pub use self::breakpoints::BREAKPOINT_BLOCKS;
pub use self::breakpoints::Breakpoints;
pub use self::breakpoints::DataBreakpoint;
pub use self::breakpoints::DataKind;
pub use self::breakpoints::TRAP_INSTRUCTION;
pub use self::context::Context;
pub use self::context::ContextFlags;
pub use self::direct::Delivery;
pub use self::direct::DirectException;
pub use self::direct::DirectNotice;
pub use self::direct::DirectOutcome;
pub use self::direct::DirectPolicy;
pub use self::direct::DirectRegisters;
pub use self::direct::DirectStep;
pub use self::direct::ThreadNameRequest;
pub use self::direct::dispatch_direct;
pub use self::error::DataBreakpointError;
pub use self::error::ExecutionError;
pub use self::error::ExtensionError;
pub use self::error::NoSuchBreakpoint;
pub use self::error::NoSuchThread;
pub use self::error::NotPending;
pub use self::error::SetError;
pub use self::error::StoppedThreadError;
pub use self::events::StopReason;
pub use self::events::process_events;
pub(crate) use self::execution::change_execution;
pub use self::execution::go_execution;
pub use self::execution::stop_execution;
pub use self::identity::DEBUGGER_NAME_CAPACITY;
pub use self::identity::DEBUGGER_USER_CAPACITY;
pub use self::identity::DebuggerRecord;
pub(crate) use self::identity::settings_lines;
pub use self::kd::KDNET_RECORD_OFFSET;
pub use self::kd::KDNET_RECORD_SIZE;
pub use self::kd::load_extension;
pub use self::kd::release_extension;
pub use self::stop_on::StopOn;
pub use self::stop_on::change_stop_on;
pub use self::threads::THREAD_LIST_CAPACITY;
pub use self::threads::continue_stopped_thread;
pub use self::threads::stop_reason;
// Field types of `Context` and `DirectException`.
pub use xbox360_sys::processor::Msr;
pub use xbox360_sys::xboxkrnl::HardwareFlags;

/// Bytes of a module name the monitor keeps.
pub const MODULE_NAME_CAPACITY: usize = 0x100;
/// Bytes of a debug string or rip message a notification carries.
pub const NOTICE_TEXT_CAPACITY: usize = 0x800;

/// The order the monitor visits the processes in.
static PROCESS_ORDER: [ProcessKind; 2] = [ProcessKind::Title, ProcessKind::System];

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry(
        "break",
        DispatchFlags::DEVKIT_ONLY,
        break_command::set_breakpoint,
    ),
    entry("continue", DispatchFlags::empty(), threads::continue_thread),
    entry("crashdump", DispatchFlags::empty(), threads::crash_dump),
    entry("dbgextld", DispatchFlags::empty(), kd::debugger_extension),
    entry(
        "debugger",
        DispatchFlags::empty(),
        identity::debugger_identity,
    ),
    entry(
        "getcontext",
        DispatchFlags::empty(),
        thread_context::get_context,
    ),
    entry("getpid", DispatchFlags::empty(), get_process_id),
    entry("go", DispatchFlags::empty(), execution::go),
    entry("halt", DispatchFlags::DEVKIT_ONLY, execution::halt),
    entry(
        "isbreak",
        DispatchFlags::DEVKIT_ONLY,
        break_command::is_breakpoint,
    ),
    entry("isdebugger", DispatchFlags::empty(), identity::is_debugger),
    entry("isstopped", DispatchFlags::empty(), threads::is_stopped),
    entry("kd", DispatchFlags::DEVKIT_ONLY, kd::kernel_debugger),
    entry("kdlite", DispatchFlags::empty(), kd::kernel_debugger_lite),
    entry(
        "kdnet",
        DispatchFlags::DEVKIT_ONLY,
        kd::kernel_debugger_network,
    ),
    entry("nostopon", DispatchFlags::empty(), stop_on::no_stop_on),
    entry("resume", DispatchFlags::DEVKIT_ONLY, threads::resume_thread),
    entry(
        "setcontext",
        DispatchFlags::DEVKIT_ONLY,
        thread_context::set_context,
    ),
    entry("stop", DispatchFlags::DEVKIT_ONLY, execution::stop),
    entry("stopon", DispatchFlags::empty(), stop_on::stop_on),
    entry(
        "suspend",
        DispatchFlags::DEVKIT_ONLY,
        threads::suspend_thread,
    ),
    entry("threadinfo", DispatchFlags::empty(), threads::thread_info),
    entry("threads", DispatchFlags::empty(), threads::threads),
    entry("threadstat", DispatchFlags::empty(), threads::thread_status),
];

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

/// Kernel thread identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadId(pub u32);

/// The two processes whose threads the monitor controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessKind {
    Title,
    System,
}

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

xbox360_sys::flags! {
    /// Flags of an exception record.
    pub struct ExceptionFlags(u32) {
        /// The exception cannot be continued.
        NONCONTINUABLE = 0x1,
    }
}

xbox360_sys::flags! {
    /// Flags word of an exception notification.
    pub struct ExceptionNotificationFlags(u32) {
        /// The exception cannot be continued.
        NONCONTINUABLE = 0x1,
        /// The debugger sees the exception before the handlers do.
        FIRST_CHANCE = 0x2,
    }
}

/// Exception record of a thread that entered the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionRecord {
    pub code: NtStatus,
    pub flags: ExceptionFlags,
    pub address: u32,
    pub parameter_count: u32,
    /// The first parameters.
    pub parameters: [u32; 4],
    /// Target address of the record; `params=` reports the address of its
    /// parameter array.
    pub record_address: u32,
}

impl ExceptionRecord {
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

impl Default for ExceptionRecord {
    fn default() -> Self {
        Self {
            code: NtStatus::SUCCESS,
            flags: ExceptionFlags::empty(),
            address: 0,
            parameter_count: 0,
            parameters: [0; 4],
            record_address: 0,
        }
    }
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
    pub flags: ModuleFlags,
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
            flags: ModuleFlags::empty(),
            image_size: 0,
            has_header: false,
        }
    }
}

xbox360_sys::flags! {
    /// Module description flags.
    pub struct ModuleFlags(u32) {
        TLS = 0x1,
        XBE = 0x2,
        DLL = 0x4,
    }
}

/// What the platform reports to the monitor. The reporting thread waits
/// until [`Backend::complete_event`] is called for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// The C layout keeps every variant's words aligned, so building an event
// stores fields directly instead of merging bytes.
#[repr(C)]
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

/// Exit status of a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus(pub u32);

impl ExitStatus {
    /// The status of a thread that has not exited.
    pub const STILL_ACTIVE: Self = Self(0x103);
}

/// Handle of a loaded debugger extension module, owned until it is passed
/// to [`Backend::unload_extension`].
#[derive(Debug)]
pub struct ExtensionHandle(u32);

impl ExtensionHandle {
    /// # Safety
    ///
    /// `value` must be the loader handle of a loaded debugger extension
    /// image that no other `ExtensionHandle` names.
    pub unsafe fn from_raw(value: u32) -> Self {
        Self(value)
    }

    pub fn raw(&self) -> u32 {
        self.0
    }
}

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
    ) -> Result<(), StoppedThreadError>;
    /// Copy the NUL-terminated name at `address` as the name of `thread`.
    ///
    /// # Safety
    ///
    /// `address` must be the name parameter of a thread-name exception
    /// (type 0x1000) raised by a thread that stays stopped in the monitor
    /// at that exception for the duration of the call. The raising code
    /// supplies it as a NUL-terminated string, readable through its
    /// terminator, or 0.
    unsafe fn set_thread_name(&mut self, thread: ThreadId, address: u32);
    /// Exit status of the thread behind a handle of the monitor process:
    /// [`ExitStatus::STILL_ACTIVE`] while it runs.
    fn thread_exit_status(&mut self, handle: ThreadHandle) -> Result<ExitStatus, KernelError>;
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
    ///
    /// # Safety
    ///
    /// `thread` must be stopped in the monitor at a module load or unload
    /// trap for the duration of the call, with `name_string` and `entry`
    /// its r3 and r4. The loader raises the trap with r3 addressing the
    /// module's counted name string (16-bit length, buffer address at +4,
    /// `length` readable bytes) and r4 its loader table entry (image base
    /// at +0, size at +0xc, of an image mapped at that base), or with 0.
    unsafe fn module_event(
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
    fn load_extension(&mut self, path: &[u8]) -> Result<ExtensionHandle, KernelError>;
    /// Unload a debugger extension image, calling its unload export.
    fn unload_extension(&mut self, handle: ExtensionHandle) -> Result<(), KernelError>;
}

/// A notification queued by a direct exception, with what the platform
/// captured on the raising thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Declaration order keeps the copies between the queue node and the
// caller word-aligned.
#[repr(C)]
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
    events: events::Events,
}

impl State {
    pub const fn new() -> Self {
        Self {
            process_id: None,
            breakpoints: Breakpoints::new(),
            data_breakpoint: None,
            stop_on: StopOn::empty(),
            break_at_title_entry: false,
            saved_execution: ExecutionState::Stopped,
            kernel_debugger: None,
            kd_lite: true,
            debugger: DebuggerRecord::EMPTY,
            extension: None,
            trap_passthrough: false,
            held_reply: None,
            events: events::Events::new(),
        }
    }

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

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    /// Thread identifiers captured when the command ran, in a block of
    /// stock's 0x400-byte list size.
    Threads {
        list: TransferBlock,
        remaining: u16,
    },
    ThreadInfo {
        info: ThreadInfo,
        sent: bool,
    },
    /// Lines of the context copied into `snapshot` when the command ran.
    Context {
        snapshot: TransferBlock,
        position: usize,
    },
}

const fn entry(
    name: &'static str,
    flags: DispatchFlags,
    handler: fn(&mut Invocation<'_>) -> CommandResult,
) -> CommandEntry {
    CommandEntry::new(name, Access::CONTROL, Access::empty(), flags, handler)
}

/// Whether debug exceptions are routed to the kernel debugger.
pub(crate) fn kernel_debugger_enabled(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
) -> bool {
    *state.debugger.kernel_debugger.get_or_insert_with(|| {
        backend
            .hardware_flags()
            .contains(HardwareFlags::KERNEL_DEBUGGER_ENABLED)
    })
}

/// Apply the persisted kd lite flag (control code 0x63): console
/// configuration (2, 6) bit 1.
pub fn refresh_kd_lite(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    let mut value = [0u8; 4];
    let persisted = backend
        .xconfig_get(ConfigSetting::CONSOLE_FLAGS, &mut value)
        .is_ok()
        && ConsoleConfigFlags::from_bits_retain(u32::from_be_bytes(value))
            .contains(ConsoleConfigFlags::KD_LITE);
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

pub(crate) fn resume(
    continuation: &mut Continuation,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    match continuation {
        Continuation::Threads { list, remaining } => threads::thread_lines(*list, remaining, cx),
        Continuation::ThreadInfo { info, sent } => threads::thread_info_lines(info, sent, cx),
        Continuation::Context { snapshot, position } => {
            thread_context::context_lines(*snapshot, position, cx)
        }
    }
}

fn start_transfer(invocation: &mut Invocation<'_>, continuation: Continuation) -> bool {
    let Some(session) = invocation.session.as_deref_mut() else {
        return false;
    };

    session.receive_remaining = None;
    session.continuation = AnyContinuation::Debugger(continuation);

    true
}

/// `getpid`: a nonzero identifier generated once per boot from the time
/// base and the system time.
fn get_process_id(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.backend.execution_state() == ExecutionState::Pending {
        return Err(NoSuchThread.into());
    }

    let process_id = match invocation.state.debugger.process_id {
        Some(process_id) => process_id,
        None => {
            let process_id = loop {
                let timebase = invocation.backend.timebase() as u32;
                let time = invocation.backend.system_time() as u32;
                let candidate = timebase.wrapping_add(time);
                if candidate != 0 {
                    break candidate;
                }
            };
            invocation.state.debugger.process_id = Some(process_id);
            process_id
        }
    };
    invocation.set_text(format_args!("pid=0x{process_id:08x}"));

    Ok(Reply::Ok)
}
