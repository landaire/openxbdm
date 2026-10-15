//! Debug event processing: the monitor's exception dispatch, thread
//! notifications, stops, and the release of stopped threads.
//!
//! The platform reports an event and holds the reporting thread until the
//! event is completed. An event that stops its thread stays pending until
//! `continue` (or a state change that releases stopped threads) supplies
//! what the monitor's exception path does after its wait returns.

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;

use super::Context;
use super::ContextFlags;
use super::DebugEvent;
use super::DirectNotice;
use super::DirectNotification;
use super::DirectPolicy;
use super::Disposition;
use super::ExceptionRecord;
use super::HARDWARE_KERNEL_DEBUGGER;
use super::MODULE_NAME_CAPACITY;
use super::MSR_SINGLE_STEP;
use super::ModuleEvent;
use super::NOTICE_TEXT_CAPACITY;
use super::NoSuchThread;
use super::ProcessKind;
use super::StopOn;
use super::TRAP_INSTRUCTION;
use super::ThreadId;
use super::breakpoints::Slot;
use super::change_execution;
use super::context::MSR_EXTERNAL_INTERRUPTS;
use super::kernel_debugger_enabled;
use super::transition;
use super::trap;
use crate::backend::Backend as AnyBackend;
use crate::commands::console::DumpMode;
use crate::network::Network;
use crate::notify::DataAccess;
use crate::notify::Event;
use crate::notify::ExceptionDetail;
use crate::notify::ExecutionState;
use crate::state::ServerState;
use crate::text::Text;

/// Threads that can be stopped at once.
const MAX_PENDING: usize = 16;
/// Events that can wait for the execution state to change.
const MAX_DEFERRED: usize = 16;
/// Value the monitor stores in r3 when an assertion prompt is answered by a
/// continue ("ignore").
pub(super) const ASSERT_IGNORE: u64 = 0x49;

/// Per-process step over a lifted breakpoint or the data breakpoint.
#[derive(Debug, Clone, Copy)]
struct Step {
    target: StepTarget,
    /// Trace was enabled before the step.
    saved_trace: bool,
}

#[derive(Debug, Clone, Copy)]
enum StepTarget {
    Breakpoint(Slot),
    DataBreakpoint,
}

/// What the exception path does once a stopped thread is released.
#[derive(Debug, Clone, Copy)]
enum Resolution {
    /// Breakpoint trap; `table` when the address is a software breakpoint.
    Break {
        table: bool,
    },
    /// Assertion prompt: answer "ignore" and step past the trap when the
    /// debugger left r3 and Iar unchanged.
    Assert {
        iar: u32,
        gpr3: u64,
    },
    /// Step past the trap when Iar is unchanged.
    Advance {
        iar: u32,
    },
    Exception {
        second_chance: bool,
    },
    SingleStep,
    DataBreakpoint,
    /// The event result is not used (debug strings, module loads).
    Final,
    /// The thread runs on; `break_after` executes the title entry break.
    Resume {
        break_after: bool,
    },
    /// Title launch wait: `timeout` milliseconds from tick `since`.
    PendingTitle {
        since: u32,
        timeout: Option<u32>,
    },
    StackOverflow,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    thread: ThreadId,
    process: ProcessKind,
    record: Option<ExceptionRecord>,
    /// The thread has the debuggable flag; only such threads are released
    /// by a state change.
    debuggable: bool,
    /// Reported as a stopping first-chance exception.
    first_chance: bool,
    /// `continue exception`.
    pass_exception: bool,
    /// Released by the kernel debugger without a debugger decision.
    released: bool,
    /// Write a crash dump when the event ends unhandled.
    dump: bool,
    resolution: Resolution,
}

impl Pending {
    fn new(thread: ThreadId, process: ProcessKind, resolution: Resolution) -> Self {
        Self {
            thread,
            process,
            record: None,
            debuggable: true,
            first_chance: false,
            pass_exception: false,
            released: false,
            dump: false,
            resolution,
        }
    }
}

/// Event processing state.
#[derive(Debug)]
pub(super) struct Events {
    pending: [Option<Pending>; MAX_PENDING],
    deferred: [Option<DebugEvent>; MAX_DEFERRED],
    steps: [Option<Step>; 2],
    /// A crash dump is being written; no further dumps are started.
    dump_in_progress: bool,
}

const fn process_index(process: ProcessKind) -> usize {
    match process {
        ProcessKind::Title => 0,
        ProcessKind::System => 1,
    }
}

impl Events {
    pub(super) const fn new() -> Self {
        Self {
            pending: [None; MAX_PENDING],
            deferred: [const { None }; MAX_DEFERRED],
            steps: [None; 2],
            dump_in_progress: false,
        }
    }

    pub(super) fn any_pending(&self) -> bool {
        self.pending.iter().any(Option::is_some)
    }

    fn pending_index(&self, thread: ThreadId) -> Option<usize> {
        self.pending
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.thread == thread))
    }
}

/// Process every event the platform has queued.
pub fn process_events(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) {
    super::release_closed_snapshots(state, backend);
    expire_title_stops(state, backend);
    let mut text = [0u8; NOTICE_TEXT_CAPACITY];
    while let Some(notification) = backend.next_direct_notification(&mut text) {
        let length = notification.text_length.min(NOTICE_TEXT_CAPACITY);
        deliver_direct(state, backend, network, &notification, &text[..length]);
    }
    while let Some(event) = backend.next_event() {
        // Texts the event's thread posted before it raised the event go
        // out first.
        crate::commands::session::send_posted_notifications(state, backend, network);
        handle(state, backend, network, event);
    }
    super::send_held_reply(state, backend, network);
    let policy = direct_policy(state, backend);
    backend.publish_direct_policy(&policy);
}

/// The state direct exceptions are dispatched with.
fn direct_policy(state: &mut ServerState, backend: &mut dyn AnyBackend) -> DirectPolicy {
    DirectPolicy {
        stop_on: state.debugger.stop_on,
        kd_lite: state.debugger.kd_lite,
        kernel_debugger: kernel_debugger_enabled(state, backend),
        trap_passthrough: state.debugger.trap_passthrough,
        dump_mode: state.console.dump_mode,
        dump_in_progress: state.debugger.events.dump_in_progress,
        attached: state.debugger.debugger.attached,
        defer_mask: state.console.event_defer.0,
        data_breakpoint: state.debugger.data_breakpoint,
    }
}

/// Send a notification a direct exception queued. A module unload removes
/// the module's breakpoints whether or not its line is sent.
fn deliver_direct(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    notification: &DirectNotification,
    text: &[u8],
) {
    let notice = match notification.notice {
        DirectNotice::DebugString { address, length } => Notice::DebugString { address, length },
        DirectNotice::ModuleLoad { .. } => match notification.module {
            Some(module) if module.has_header => Notice::ModuleLoad(module),
            _ => return,
        },
        DirectNotice::ModuleUnload { line, .. } => {
            let Some(module) = notification.module else {
                return;
            };
            state
                .debugger
                .breakpoints
                .remove_range(module.base, module.size, backend);
            if !line {
                return;
            }
            Notice::ModuleUnload(module)
        }
        DirectNotice::Assert { address, length } => Notice::Assert { address, length },
        DirectNotice::Rip { address, length } => Notice::Rip { address, length },
        DirectNotice::SingleStep => Notice::SingleStep,
        DirectNotice::Data { kind, address } => Notice::Data(kind, address),
        DirectNotice::Exception { first_chance } => Notice::Exception { first_chance },
    };
    let (record, thread, iar) = (notification.record, notification.thread, notification.iar);
    deliver_notice(
        state, backend, network, notice, &record, thread, iar, false, text,
    );
}

/// End title launch waits that ran out of time unreleased; the waiting
/// thread starts execution itself (stock 0x91f523a0).
fn expire_title_stops(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    let now = backend.tick_milliseconds();
    for index in 0..MAX_PENDING {
        let Some(entry) = state.debugger.events.pending[index] else {
            continue;
        };
        let Resolution::PendingTitle {
            since,
            timeout: Some(timeout),
        } = entry.resolution
        else {
            continue;
        };
        if now.wrapping_sub(since) < timeout {
            continue;
        }
        state.debugger.events.pending[index] = None;
        backend.complete_event(entry.thread, Disposition::default());
    }
}

/// Retry events that waited for the execution state to change.
pub(super) fn process_deferred(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) {
    for index in 0..MAX_DEFERRED {
        if let Some(event) = state.debugger.events.deferred[index].take() {
            handle(state, backend, network, event);
        }
    }
}

/// A stop requested while execution is stopped or pending waits for the
/// state to change, as the monitor's state machine does.
fn stop_must_wait(backend: &mut dyn AnyBackend) -> bool {
    matches!(
        backend.execution_state(),
        ExecutionState::Stopped | ExecutionState::Pending | ExecutionState::PendingTitle
    )
}

fn defer(state: &mut ServerState, backend: &mut dyn AnyBackend, event: DebugEvent) {
    match state
        .debugger
        .events
        .deferred
        .iter_mut()
        .find(|slot| slot.is_none())
    {
        Some(slot) => *slot = Some(event),
        // No room to wait: the thread continues without the debugger.
        None => backend.complete_event(event.thread(), Disposition::default()),
    }
}

pub(super) fn handle(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    event: DebugEvent,
) {
    match event {
        DebugEvent::Exception { .. } => exception(state, backend, network, event),
        DebugEvent::ThreadCreate {
            thread,
            process,
            start,
            title_entry,
        } => {
            let stop = state.debugger.stop_on.contains(StopOn::CREATE_THREAD);
            if stop && stop_must_wait(backend) {
                defer(state, backend, event);
                return;
            }
            let break_after =
                title_entry && core::mem::take(&mut state.debugger.break_at_title_entry);
            let resolution = Resolution::Resume { break_after };
            let line = Event::ThreadCreate {
                thread: thread.0,
                start,
                stopped: stop,
            };
            if stop {
                begin_stop(
                    state,
                    backend,
                    network,
                    Pending::new(thread, process, resolution),
                );
                notify(state, backend, network, &line);
            } else {
                notify(state, backend, network, &line);
                backend.complete_event(
                    thread,
                    Disposition {
                        handled: true,
                        break_after,
                        ..Disposition::default()
                    },
                );
            }
        }
        DebugEvent::ThreadTerminate { thread, .. } => {
            notify(
                state,
                backend,
                network,
                &Event::ThreadTerminate {
                    thread: thread.0,
                    stopped: false,
                },
            );
            backend.complete_event(
                thread,
                Disposition {
                    handled: true,
                    ..Disposition::default()
                },
            );
        }
        DebugEvent::PogoModuleStart {
            thread,
            process,
            name,
            module,
        } => {
            if stop_must_wait(backend) {
                defer(state, backend, event);
                return;
            }
            begin_stop(
                state,
                backend,
                network,
                Pending::new(thread, process, Resolution::Resume { break_after: false }),
            );
            let mut buffer = [0u8; MODULE_NAME_CAPACITY];
            let length = target_string(backend, name, &mut buffer);
            let name = core::str::from_utf8(&buffer[..length]).unwrap_or_default();
            notify(
                state,
                backend,
                network,
                &Event::PogoModuleStartup {
                    name,
                    module,
                    thread: thread.0,
                    stopped: true,
                },
            );
        }
        DebugEvent::ExecutionRequest {
            thread,
            target,
            notify: send_line,
            ..
        } => {
            // The monitor waits for the state to change and tries again.
            if target == ExecutionState::PendingTitle
                && backend.execution_state() == ExecutionState::Stopped
            {
                defer(state, backend, event);
                return;
            }
            transition(state, backend, network, target, send_line);
            backend.complete_event(
                thread,
                Disposition {
                    handled: true,
                    ..Disposition::default()
                },
            );
        }
        DebugEvent::PendingTitleStop {
            thread,
            process,
            debuggable,
            timeout,
        } => {
            notify(
                state,
                backend,
                network,
                &Event::ExecutionStop(ExecutionState::PendingTitle),
            );
            let since = backend.tick_milliseconds();
            let entry = Pending {
                debuggable,
                ..Pending::new(thread, process, Resolution::PendingTitle { since, timeout })
            };
            match state
                .debugger
                .events
                .pending
                .iter_mut()
                .find(|slot| slot.is_none())
            {
                Some(slot) => *slot = Some(entry),
                None => backend.complete_event(
                    thread,
                    Disposition {
                        handled: true,
                        ..Disposition::default()
                    },
                ),
            }
        }
        DebugEvent::StackOverflow {
            thread,
            process,
            address,
            record_address,
            can_stop,
        } => stack_overflow(
            state,
            backend,
            network,
            event,
            thread,
            process,
            address,
            record_address,
            can_stop,
        ),
    }
}

/// Stack overflow notification (stock 0x91f3aab0): stop with a
/// noncontinuable `exception code=0xc00000fd` line while a debugger keeps
/// continuing the thread, then ask for the crash dump.
#[allow(clippy::too_many_arguments)]
fn stack_overflow(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    event: DebugEvent,
    thread: ThreadId,
    process: ProcessKind,
    address: u32,
    record_address: u32,
    can_stop: bool,
) {
    const STACK_OVERFLOW: u32 = 0xc000_00fd;
    let hardware_kd = backend.hardware_flags() & HARDWARE_KERNEL_DEBUGGER != 0;
    if kernel_debugger_enabled(state, backend) && hardware_kd {
        backend.complete_event(thread, Disposition::default());
        return;
    }
    let dump_mode = state.console.dump_mode;
    let dump = dump_mode != DumpMode::Disabled;
    let can_stop = can_stop && (dump_mode != DumpMode::Enabled || state.debugger.debugger.attached);
    if !can_stop {
        backend.complete_event(
            thread,
            Disposition {
                write_dump: dump,
                ..Disposition::default()
            },
        );
        return;
    }
    if stop_must_wait(backend) {
        defer(state, backend, event);
        return;
    }
    let record = ExceptionRecord {
        code: STACK_OVERFLOW,
        flags: ExceptionRecord::NONCONTINUABLE,
        address,
        record_address,
        ..ExceptionRecord::default()
    };
    let entry = Pending {
        record: Some(record),
        dump,
        ..Pending::new(thread, process, Resolution::StackOverflow)
    };
    begin_stop(state, backend, network, entry);
    // The notification arguments carry no parameter array.
    let line = Event::Exception {
        code: STACK_OVERFLOW,
        thread: thread.0,
        address,
        detail: ExceptionDetail::Parameters {
            count: 0,
            address: 0,
        },
        first_chance: false,
        noncontinuable: true,
        stopped: true,
    };
    if !notify(state, backend, network, &line) && dump_mode == DumpMode::Enabled {
        if let Some(index) = state.debugger.events.pending_index(thread) {
            state.debugger.events.pending[index] = None;
        }
        change_execution(state, backend, network, ExecutionState::Started);
        backend.complete_event(
            thread,
            Disposition {
                write_dump: dump,
                ..Disposition::default()
            },
        );
    }
}

/// Registers of a thread in the monitor that the dispatch reads.
#[derive(Clone, Copy)]
struct Registers {
    msr: u32,
    iar: u32,
    gpr3: u64,
    gpr4: u64,
}

#[inline(never)]
fn registers(backend: &mut dyn AnyBackend, thread: ThreadId) -> Registers {
    let mut context = Context::EMPTY;
    context.flags = ContextFlags::CONTROL.union(ContextFlags::INTEGER);
    let _ = backend.thread_context(thread, &mut context);
    Registers {
        msr: context.msr,
        iar: context.iar,
        gpr3: context.gpr[3],
        gpr4: context.gpr[4],
    }
}

/// Read the control and integer registers of `thread`, let `change` edit
/// them, and write them back when it returns true. The context occupies
/// only this frame.
#[inline(never)]
fn edit_registers(
    backend: &mut dyn AnyBackend,
    thread: ThreadId,
    change: &mut dyn FnMut(&mut dyn AnyBackend, &mut Context) -> bool,
) {
    let mut context = Context::EMPTY;
    context.flags = ContextFlags::CONTROL.union(ContextFlags::INTEGER);
    let _ = backend.thread_context(thread, &mut context);
    if change(backend, &mut context) {
        context.flags = ContextFlags::CONTROL.union(ContextFlags::INTEGER);
        let _ = backend.set_thread_context(thread, &context);
    }
}

fn clear_single_step(backend: &mut dyn AnyBackend, thread: ThreadId) {
    edit_registers(backend, thread, &mut |_, context| {
        context.msr &= !MSR_SINGLE_STEP;
        true
    });
}

/// The monitor rewrites first-chance integer traps raised by trap
/// instructions into breakpoints, or into divide errors for the compiler's
/// overflow and divide-by-zero checks.
pub(super) fn rewrite_trap(record: &mut ExceptionRecord) {
    const INTEGER_DIVIDE_BY_ZERO: u32 = 0xc000_0094;
    const INTEGER_OVERFLOW: u32 = 0xc000_0095;
    const ILLEGAL_INSTRUCTION: u32 = 0xc000_008c;
    if !matches!(
        record.code,
        INTEGER_DIVIDE_BY_ZERO | INTEGER_OVERFLOW | ILLEGAL_INSTRUCTION
    ) {
        return;
    }
    let instruction = record.parameters[0];
    let immediate = match instruction >> 26 {
        2 | 3 => true,
        31 if matches!((instruction & 0x7fe) >> 1, 4 | 0x44) => false,
        _ => return,
    };
    record.code = ExceptionRecord::BREAKPOINT;
    if !immediate {
        return;
    }
    let condition = (instruction & 0x03e0_0000) >> 21;
    let value = instruction as u16 as i16;
    if condition == 5 && value == -1 {
        record.code = INTEGER_OVERFLOW;
    } else if (condition == 6 || condition == 7) && value == 0 {
        record.code = INTEGER_DIVIDE_BY_ZERO;
    }
}

fn exception(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    event: DebugEvent,
) {
    let DebugEvent::Exception {
        thread,
        process,
        mut record,
        second_chance,
        has_record,
        debuggable,
    } = event
    else {
        return;
    };
    if !second_chance {
        rewrite_trap(&mut record);
    }
    let hardware_kd = backend.hardware_flags() & HARDWARE_KERNEL_DEBUGGER != 0;
    if !second_chance && state.debugger.trap_passthrough && !hardware_kd {
        let passes = match record.code {
            ExceptionRecord::BREAKPOINT => record.trap_code() == trap::BREAKPOINT,
            ExceptionRecord::SINGLE_STEP => true,
            _ => false,
        };
        if passes {
            reprogram_data_breakpoint(state, backend);
            backend.complete_event(
                thread,
                Disposition {
                    handled: true,
                    ..Disposition::default()
                },
            );
            return;
        }
    }
    if state.debugger.events.dump_in_progress {
        // After a crash dump the monitor no longer dispatches exceptions.
        let entry = Pending {
            record: Some(record),
            ..Pending::new(thread, process, Resolution::Final)
        };
        finish(state, backend, network, entry, false);
        return;
    }
    let kd = kernel_debugger_enabled(state, backend) && hardware_kd;
    let dump_mode = state.console.dump_mode;
    let mut dump = !hardware_kd && dump_mode != DumpMode::Disabled;
    let context = registers(backend, thread);
    let mut can_stop = debuggable && context.msr & MSR_EXTERNAL_INTERRUPTS != 0;
    if dump_mode == DumpMode::Enabled {
        can_stop &= state.debugger.debugger.attached;
    }
    let iar = context.iar;
    let gpr3 = context.gpr3;
    let gpr4 = context.gpr4 as u16;
    let stop_on = state.debugger.stop_on;

    // Each arm yields the notification (if any), whether it stops, and the
    // resolution applied when the event ends.
    let plan: Plan = match record.code {
        ExceptionRecord::BREAKPOINT => match record.trap_code() {
            trap::DEBUG_STRING => {
                dump = false;
                let stop = stop_on.contains(StopOn::DEBUG_STRING) && can_stop;
                Plan::notify(
                    Notice::DebugString {
                        address: gpr3 as u32,
                        length: gpr4,
                    },
                    stop,
                    Resolution::Final,
                )
                .only_if(has_record)
            }
            trap::MODULE_LOAD => {
                dump = false;
                let stop = !kd && can_stop && stop_on.contains(StopOn::MODULE_LOAD);
                match backend.module_event(gpr3 as u32, context.gpr4 as u32, thread) {
                    Some(module) if module.has_header => {
                        Plan::notify(Notice::ModuleLoad(module), stop, Resolution::Final)
                    }
                    _ => Plan::silent(Resolution::Final),
                }
            }
            trap::MODULE_UNLOAD => {
                dump = false;
                if gpr3 == 0 {
                    Plan::silent(Resolution::Final)
                } else {
                    match backend.module_event(gpr3 as u32, context.gpr4 as u32, thread) {
                        Some(module) => {
                            state.debugger.breakpoints.remove_range(
                                module.base,
                                module.size,
                                backend,
                            );
                            crate::commands::memory::module_unloaded(
                                backend,
                                module.base,
                                module.size,
                            );
                            Plan::notify(Notice::ModuleUnload(module), false, Resolution::Final)
                        }
                        None => Plan::silent(Resolution::Final),
                    }
                }
            }
            trap::ASSERT_PROMPT => Plan::notify(
                Notice::Assert {
                    address: gpr3 as u32,
                    length: gpr4,
                },
                !kd && can_stop,
                Resolution::Assert { iar, gpr3 },
            ),
            trap::RIP => Plan::notify(
                Notice::Rip {
                    address: gpr3 as u32,
                    length: gpr4,
                },
                !kd && can_stop,
                Resolution::Advance { iar },
            ),
            trap::DEBUG_SERVICE => {
                dump = false;
                Plan::silent(Resolution::Final)
            }
            _ => {
                let table = state.debugger.breakpoints.contains(iar);
                if table {
                    dump = false;
                }
                Plan::notify(Notice::Break, true, Resolution::Break { table })
            }
        },
        ExceptionRecord::NT_ASSERT => {
            if !kd && can_stop {
                Plan::notify(Notice::NtAssert, true, Resolution::Advance { iar })
            } else {
                Plan::silent(Resolution::Final)
            }
        }
        ExceptionRecord::SINGLE_STEP if record.parameters[0] == 0 => {
            match state.debugger.data_breakpoint {
                Some(data) if data.overlaps(record.parameters[1], access_length(backend, iar)) => {
                    Plan::notify(
                        Notice::Data(data.kind as u32, data.address),
                        can_stop,
                        Resolution::DataBreakpoint,
                    )
                }
                Some(_) => Plan::handled(Resolution::DataBreakpoint),
                None => Plan::silent(Resolution::Final),
            }
        }
        ExceptionRecord::SINGLE_STEP => {
            if let Some(step) = state.debugger.events.steps[process_index(process)].take() {
                match step.target {
                    StepTarget::Breakpoint(slot) => state.debugger.breakpoints.rearm(slot, backend),
                    StepTarget::DataBreakpoint => {}
                }
                if !step.saved_trace {
                    clear_single_step(backend, thread);
                    reprogram_data_breakpoint(state, backend);
                    backend.complete_event(
                        thread,
                        Disposition {
                            handled: true,
                            ..Disposition::default()
                        },
                    );
                    return;
                }
            }
            clear_single_step(backend, thread);
            Plan::notify(Notice::SingleStep, !kd && can_stop, Resolution::SingleStep)
        }
        _ => {
            if record.code == ExceptionRecord::THREAD_NAME && record.parameters[0] == 0x1000 {
                let target = match record.parameters[2] {
                    u32::MAX => thread,
                    other => ThreadId(other),
                };
                backend.set_thread_name(target, record.parameters[1]);
            }
            dump &= second_chance;
            let stop = !kd
                && can_stop
                && (second_chance || stop_on.contains(StopOn::FIRST_CHANCE_EXCEPTION));
            Plan::notify(
                Notice::Exception {
                    first_chance: !second_chance,
                },
                stop,
                Resolution::Exception { second_chance },
            )
        }
    };

    if plan.stop && stop_must_wait(backend) {
        defer(state, backend, event);
        return;
    }
    let pending = Pending {
        record: Some(record),
        debuggable,
        first_chance: plan.stop && !second_chance,
        dump,
        ..Pending::new(thread, process, plan.resolution)
    };
    if plan.handled {
        finish(state, backend, network, pending, true);
        return;
    }
    let Some(notice) = plan.notice else {
        finish(state, backend, network, pending, false);
        return;
    };
    if plan.stop {
        begin_stop(state, backend, network, pending);
    }
    let mut buffer = [0u8; NOTICE_TEXT_CAPACITY];
    let text = notice_text(backend, &notice, &mut buffer);
    let delivered = deliver_notice(
        state, backend, network, notice, &record, thread, iar, plan.stop, text,
    );
    if !plan.stop {
        finish(state, backend, network, pending, false);
        return;
    }
    if !delivered && dump_mode == DumpMode::Enabled {
        // Nobody listens and dumps are enabled: run on and let the
        // exception end unhandled.
        if let Some(index) = state.debugger.events.pending_index(thread) {
            state.debugger.events.pending[index] = None;
        }
        change_execution(state, backend, network, ExecutionState::Started);
        finish(state, backend, network, pending, false);
    }
}

#[derive(Clone, Copy)]
enum Notice {
    Break,
    SingleStep,
    NtAssert,
    DebugString { address: u32, length: u16 },
    Assert { address: u32, length: u16 },
    Rip { address: u32, length: u16 },
    Data(u32, u32),
    ModuleLoad(ModuleEvent),
    ModuleUnload(ModuleEvent),
    Exception { first_chance: bool },
}

struct Plan {
    notice: Option<Notice>,
    stop: bool,
    /// The event ends handled without a notification.
    handled: bool,
    resolution: Resolution,
}

impl Plan {
    fn notify(notice: Notice, stop: bool, resolution: Resolution) -> Self {
        Self {
            notice: Some(notice),
            stop,
            handled: false,
            resolution,
        }
    }

    fn silent(resolution: Resolution) -> Self {
        Self {
            notice: None,
            stop: false,
            handled: false,
            resolution,
        }
    }

    fn handled(resolution: Resolution) -> Self {
        Self {
            notice: None,
            stop: false,
            handled: true,
            resolution,
        }
    }

    fn only_if(self, condition: bool) -> Self {
        if condition {
            self
        } else {
            Self::silent(self.resolution)
        }
    }
}

/// Mark the thread stopped, stop execution, and keep the event pending.
fn begin_stop(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    entry: Pending,
) {
    match state
        .debugger
        .events
        .pending
        .iter_mut()
        .find(|slot| slot.is_none())
    {
        Some(slot) => *slot = Some(entry),
        None => {
            backend.complete_event(
                entry.thread,
                Disposition {
                    handled: true,
                    ..Disposition::default()
                },
            );
            return;
        }
    }
    change_execution(state, backend, network, ExecutionState::Stopped);
}

/// Bytes the instruction at `iar` accesses, for the data breakpoint
/// overlap test; 8 when the instruction cannot be read.
fn access_length(backend: &mut dyn AnyBackend, iar: u32) -> u32 {
    backend
        .target_bytes(iar, 4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map_or(8, |word| {
            super::breakpoints::access_length(u32::from_be_bytes(word))
        })
}

/// Run the notification-session handlers for `event`, then send its line;
/// returns whether a channel accepted the line.
pub(super) fn notify(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    event: &Event<'_>,
) -> bool {
    backend.notify_sessions(event);
    state.notifications.deliver(event, network)
}

/// Copy the NUL-terminated string at `address` into `buffer` as far as it
/// is readable and fits; returns its length.
fn target_string(backend: &mut dyn AnyBackend, address: u32, buffer: &mut [u8]) -> usize {
    for (offset, slot) in buffer.iter_mut().enumerate() {
        match backend.target_bytes(address.wrapping_add(offset as u32), 1) {
            Some(&[byte]) if byte != 0 => *slot = byte,
            _ => return offset,
        }
    }
    buffer.len()
}

/// Copy of the target text at `address`, at most `length` bytes, as far as
/// it is readable.
fn target_text<'a>(
    backend: &mut dyn AnyBackend,
    address: u32,
    length: u16,
    buffer: &'a mut [u8; NOTICE_TEXT_CAPACITY],
) -> &'a [u8] {
    let length = usize::from(length).min(NOTICE_TEXT_CAPACITY);
    let Some(bytes) = backend.target_bytes(address, length) else {
        return &[];
    };
    let length = bytes.len();
    buffer[..length].copy_from_slice(bytes);
    &buffer[..length]
}

/// Copy of the debug string or rip message a notice names.
fn notice_text<'a>(
    backend: &mut dyn AnyBackend,
    notice: &Notice,
    buffer: &'a mut [u8; NOTICE_TEXT_CAPACITY],
) -> &'a [u8] {
    match *notice {
        Notice::DebugString { address, length } | Notice::Rip { address, length } => {
            target_text(backend, address, length, buffer)
        }
        _ => &[],
    }
}

/// Send the notification; returns whether a channel accepted it. `text` is
/// the debug string or rip message the notice names.
#[allow(clippy::too_many_arguments)]
fn deliver_notice(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    notice: Notice,
    record: &ExceptionRecord,
    thread: ThreadId,
    iar: u32,
    stopped: bool,
    text: &[u8],
) -> bool {
    let id = thread.0;
    let mut padded = Text::<0x200>::new();
    let event = match &notice {
        Notice::Break => Event::Break {
            address: iar,
            thread: id,
            stopped,
        },
        Notice::SingleStep => Event::SingleStep {
            address: iar,
            thread: id,
            stopped,
        },
        Notice::NtAssert => Event::NtAssert {
            address: iar,
            thread: id,
            stopped,
        },
        Notice::DebugString { .. } => Event::DebugString {
            thread: id,
            text,
            stopped,
        },
        &Notice::Assert { address, length } => Event::Assert {
            thread: id,
            string_address: address,
            string_length: u32::from(length),
            stopped,
        },
        &Notice::Rip { address, length } => Event::Rip {
            thread: id,
            text: (address != 0).then(|| pad_message(text, usize::from(length), &mut padded)),
            stopped,
        },
        &Notice::Data(kind, address) => {
            let access = match kind {
                1 => DataAccess::Write,
                2 => DataAccess::Read,
                // The monitor's formatter knows only kinds 1 to 3; others
                // produce no line.
                _ => return false,
            };
            Event::Data {
                access,
                value: address,
                address: iar,
                thread: id,
                stopped,
            }
        }
        Notice::ModuleLoad(module) => Event::ModuleLoad {
            module,
            thread: id,
            stopped,
        },
        Notice::ModuleUnload(module) => Event::ModuleUnload {
            name: core::str::from_utf8(&module.name[..module.name_length]).unwrap_or_default(),
            base: module.base,
            size: module.size,
        },
        &Notice::Exception { first_chance } => Event::Exception {
            code: record.code,
            thread: id,
            address: record.address,
            detail: if record.code == ExceptionRecord::ACCESS_VIOLATION {
                ExceptionDetail::AccessViolation {
                    write: record.parameters[0] != 0,
                    address: record.parameters[1],
                }
            } else {
                ExceptionDetail::Parameters {
                    count: record.parameter_count,
                    address: record.parameters_address(),
                }
            },
            first_chance,
            noncontinuable: record.flags & ExceptionRecord::NONCONTINUABLE != 0,
            stopped,
        },
    };
    notify(state, backend, network, &event)
}

/// `%-*.*s` with width and precision `length`: the text up to its NUL, cut
/// at `length` and padded with spaces to `length`.
fn pad_message<'a>(bytes: &[u8], length: usize, out: &'a mut Text<0x200>) -> &'a str {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len())
        .min(length);
    out.clear();
    let _ = out.push_bytes(&bytes[..end]);
    for _ in end..length {
        if out.push_bytes(b" ").is_err() {
            break;
        }
    }
    let text = out.as_bytes();
    match core::str::from_utf8(text) {
        Ok(text) => text,
        Err(error) => core::str::from_utf8(&text[..error.valid_up_to()]).unwrap_or_default(),
    }
}

/// Program the data breakpoint register with the current breakpoint.
fn reprogram_data_breakpoint(state: &ServerState, backend: &mut dyn AnyBackend) {
    if let Some(data) = state.debugger.data_breakpoint {
        backend.set_data_breakpoint_register(data.register());
    }
}

/// Step over a software breakpoint at Iar, or past an embedded trap.
/// Returns whether a table breakpoint was lifted.
fn step_over(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    thread: ThreadId,
    process: ProcessKind,
) -> bool {
    let mut lifted = false;
    edit_registers(backend, thread, &mut |backend, context| {
        if let Some(slot) = state.debugger.breakpoints.lift(context.iar, backend) {
            state.debugger.events.steps[process_index(process)] = Some(Step {
                target: StepTarget::Breakpoint(slot),
                saved_trace: context.msr & MSR_SINGLE_STEP != 0,
            });
            context.msr |= MSR_SINGLE_STEP;
            lifted = true;
            return true;
        }
        let word = backend
            .target_bytes(context.iar, 4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok());
        if word.map(u32::from_be_bytes) == Some(TRAP_INSTRUCTION) {
            context.iar = context.iar.wrapping_add(4);
            return true;
        }
        false
    });
    lifted
}

/// End an event: apply what the monitor does after its notification and
/// release the thread. `continued` is true when a debugger released a
/// stopped thread (or the event was handled outright).
fn finish(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    entry: Pending,
    continued: bool,
) {
    let thread = entry.thread;
    let process = entry.process;
    let mut handled = true;
    let mut advance = true;
    let mut resolved = continued && !entry.released;
    let mut disposition = Disposition::default();
    match entry.resolution {
        Resolution::Break { table } => {
            if table || resolved {
                step_over(state, backend, thread, process);
                if table {
                    resolved = true;
                }
            }
        }
        Resolution::Assert { iar, gpr3 } => {
            if resolved {
                edit_registers(backend, thread, &mut |_, context| {
                    if context.gpr[3] == gpr3 {
                        context.gpr[3] = ASSERT_IGNORE;
                    }
                    if context.iar == iar {
                        context.iar = iar.wrapping_add(4);
                    }
                    true
                });
            }
        }
        Resolution::Advance { iar } => {
            if resolved {
                edit_registers(backend, thread, &mut |_, context| {
                    let at_trap = context.iar == iar;
                    if at_trap {
                        context.iar = iar.wrapping_add(4);
                    }
                    at_trap
                });
            }
        }
        Resolution::Exception { second_chance } => {
            advance = false;
            handled = continued && (second_chance || !entry.pass_exception) && !entry.released;
            if continued && entry.released {
                handled = !entry.pass_exception;
            }
        }
        Resolution::SingleStep => {
            if resolved {
                let context = registers(backend, thread);
                if state.debugger.breakpoints.contains(context.iar) {
                    step_over(state, backend, thread, process);
                }
            } else {
                edit_registers(backend, thread, &mut |_, context| {
                    context.msr |= MSR_SINGLE_STEP;
                    true
                });
            }
        }
        Resolution::DataBreakpoint => {
            if resolved {
                backend.set_data_breakpoint_register(0);
                edit_registers(backend, thread, &mut |_, context| {
                    state.debugger.events.steps[process_index(process)] = Some(Step {
                        target: StepTarget::DataBreakpoint,
                        saved_trace: context.msr & MSR_SINGLE_STEP != 0,
                    });
                    context.msr |= MSR_SINGLE_STEP;
                    true
                });
            }
        }
        Resolution::Final => resolved = false,
        Resolution::Resume { break_after } => {
            backend.complete_event(
                thread,
                Disposition {
                    handled: true,
                    break_after,
                    ..Disposition::default()
                },
            );
            return;
        }
        Resolution::PendingTitle { .. } => {
            backend.complete_event(
                thread,
                Disposition {
                    handled: true,
                    ..Disposition::default()
                },
            );
            return;
        }
        Resolution::StackOverflow => {
            // A continued thread reports the overflow again; a released one
            // goes on to the crash dump unless the kernel debugger has it.
            let again = continued && !entry.released;
            let kd = kernel_debugger_enabled(state, backend)
                && backend.hardware_flags() & HARDWARE_KERNEL_DEBUGGER != 0;
            let write_dump = !again && entry.dump && !kd;
            state.debugger.events.dump_in_progress |= write_dump;
            backend.complete_event(
                thread,
                Disposition {
                    handled: again,
                    write_dump,
                    ..Disposition::default()
                },
            );
            return;
        }
    }
    if !resolved {
        if entry.dump {
            state.debugger.events.dump_in_progress = true;
            disposition.write_dump = true;
        }
        if state.debugger.kd_lite {
            disposition.chain_kernel_debugger = true;
        } else if advance {
            edit_registers(backend, thread, &mut |_, context| {
                context.gpr[3] = 0;
                context.iar = context.iar.wrapping_add(4);
                true
            });
            handled = true;
        }
    }
    reprogram_data_breakpoint(state, backend);
    disposition.handled = handled;
    backend.complete_event(thread, disposition);
    super::send_held_reply(state, backend, network);
}

/// `continue thread= [exception]` (stock 0x91f25c60).
pub(super) fn continue_thread(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    thread: ThreadId,
    pass_exception: bool,
) -> Hresult {
    let has_record = match backend.has_monitor_record(thread) {
        Ok(has_record) => has_record,
        Err(NoSuchThread) => return Hresult::from_error_code(ErrorCode::NO_SUCH_THREAD),
    };
    let execution = backend.execution_state();
    if matches!(
        execution,
        ExecutionState::Pending | ExecutionState::RebootTitle | ExecutionState::PendingTitle
    ) {
        return Hresult::from_error_code(ErrorCode::NO_SUCH_THREAD);
    }
    if !has_record {
        return Hresult::OK;
    }
    let Some(index) = state.debugger.events.pending_index(thread) else {
        return Hresult::from_error_code(ErrorCode::NOT_STOPPED);
    };
    let Some(mut entry) = state.debugger.events.pending[index].take() else {
        return Hresult::from_error_code(ErrorCode::NOT_STOPPED);
    };
    if execution == ExecutionState::Stopped {
        backend.monitor_suspend(thread);
    }
    entry.pass_exception = pass_exception;
    finish(state, backend, network, entry, true);
    Hresult::OK
}

/// Release every stopped thread of `process` as if continued without
/// `exception` (state machine release of waiting threads).
pub(super) fn release_stopped(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    process: ProcessKind,
) {
    for index in 0..MAX_PENDING {
        let Some(entry) = state.debugger.events.pending[index] else {
            continue;
        };
        if entry.process != process || !entry.debuggable {
            continue;
        }
        state.debugger.events.pending[index] = None;
        finish(state, backend, network, entry, true);
    }
}

/// Release every thread inside the monitor without a debugger decision,
/// resume monitor-suspended threads, and enter `started` (stock
/// 0x91f2de68, used when exceptions go to the kernel debugger).
pub(super) fn release_all(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) {
    for process in [ProcessKind::Title, ProcessKind::System] {
        for index in 0..MAX_PENDING {
            let Some(mut entry) = state.debugger.events.pending[index] else {
                continue;
            };
            if entry.process != process {
                continue;
            }
            state.debugger.events.pending[index] = None;
            entry.released = true;
            finish(state, backend, network, entry, true);
        }
        backend.resume_threads(process);
    }
    backend.set_execution_state(ExecutionState::Started);
    notify(
        state,
        backend,
        network,
        &Event::Execution(ExecutionState::Started),
    );
    process_deferred(state, backend, network);
}

/// Whether `thread` waits at an event, stopped or deferred.
pub(super) fn is_waiting(state: &ServerState, thread: ThreadId) -> bool {
    let events = &state.debugger.events;
    events.pending_index(thread).is_some()
        || events
            .deferred
            .iter()
            .flatten()
            .any(|event| event.thread() == thread)
}

/// Whether a thread stopped at an exception keeps the title from being
/// relaunched in place (stock 0x91f276d8). Title threads stopped in the
/// title image at a breakpoint trap or an assertion prompt do not.
pub(super) fn relaunch_blocked(state: &ServerState, backend: &mut dyn AnyBackend) -> bool {
    for process in [ProcessKind::Title, ProcessKind::System] {
        for entry in state
            .debugger
            .events
            .pending
            .iter()
            .flatten()
            .filter(|entry| entry.process == process)
        {
            let Some(record) = entry.record else { continue };
            if blocks_relaunch(state, backend, entry, &record) {
                return true;
            }
        }
    }
    false
}

fn blocks_relaunch(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    entry: &Pending,
    record: &ExceptionRecord,
) -> bool {
    let iar = registers(backend, entry.thread).iar;
    let outside_title_image = entry.process != ProcessKind::Title
        || !((0x8200_0000..=0x8bfe_ffff).contains(&iar)
            || (0x9200_0000..=0x9ffe_ffff).contains(&iar));
    match record.code {
        ExceptionRecord::SINGLE_STEP => false,
        ExceptionRecord::BREAKPOINT => match record.trap_code() {
            trap::DEBUG_STRING | trap::MODULE_LOAD => false,
            trap::BREAKPOINT => {
                if state.debugger.breakpoints.contains(iar) {
                    return false;
                }
                let word = backend
                    .target_bytes(iar, 4)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok());
                word.map(u32::from_be_bytes) == Some(TRAP_INSTRUCTION) && outside_title_image
            }
            0x19 | trap::ASSERT_PROMPT => outside_title_image,
            _ => true,
        },
        _ => !entry.first_chance,
    }
}

/// What a stopped thread is stopped at (the record of stock export 22,
/// 0x91f26058). The stock reason code of each variant is in its comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// 0: no exception record, or a trap the record does not describe.
    Unknown,
    /// 2.
    DebugString { thread: ThreadId },
    /// 1: a breakpoint trap at `address`.
    Breakpoint { address: u32, thread: ThreadId },
    /// 0xc: assertion prompt text at `address` (r3) of `length` (r4) bytes.
    Assert {
        thread: ThreadId,
        address: u32,
        length: u16,
    },
    /// 0xe: rip message, as for an assertion.
    Rip {
        thread: ThreadId,
        address: u32,
        length: u16,
    },
    /// 4.
    SingleStep { address: u32, thread: ThreadId },
    /// 0xd: a single step exception without a trace parameter; the record
    /// carries no access kind.
    DataBreakpoint { address: u32, thread: ThreadId },
    /// 0x15: exception code 0x15.
    NtAssert { address: u32, thread: ThreadId },
    /// 9.
    Exception {
        thread: ThreadId,
        record: ExceptionRecord,
        first_chance: bool,
    },
}

impl StopReason {
    /// The record words stock writes, in order; words past the count keep
    /// the caller's values.
    pub fn encode(&self) -> ([u32; 7], usize) {
        let mut words = [0u32; 7];
        let count = match *self {
            Self::Unknown => 1,
            Self::DebugString { thread } => {
                words[..4].copy_from_slice(&[2, thread.0, 0, 0]);
                4
            }
            Self::Breakpoint { address, thread } => {
                words[..3].copy_from_slice(&[1, address, thread.0]);
                3
            }
            Self::Assert {
                thread,
                address,
                length,
            } => {
                words[..4].copy_from_slice(&[0xc, thread.0, u32::from(length), address]);
                4
            }
            Self::Rip {
                thread,
                address,
                length,
            } => {
                words[..4].copy_from_slice(&[0xe, thread.0, u32::from(length), address]);
                4
            }
            Self::SingleStep { address, thread } => {
                words[..3].copy_from_slice(&[4, address, thread.0]);
                3
            }
            Self::DataBreakpoint { address, thread } => {
                words[..3].copy_from_slice(&[0xd, address, thread.0]);
                3
            }
            Self::NtAssert { address, thread } => {
                words[..3].copy_from_slice(&[0x15, address, thread.0]);
                3
            }
            Self::Exception {
                thread,
                record,
                first_chance,
            } => {
                let mut flags = record.flags & ExceptionRecord::NONCONTINUABLE;
                if first_chance {
                    flags |= 2;
                }
                let (first, second) = if record.code == ExceptionRecord::ACCESS_VIOLATION {
                    (record.parameters[0], record.parameters[1])
                } else {
                    (record.parameter_count, record.parameters_address())
                };
                words = [
                    9,
                    thread.0,
                    record.code,
                    record.address,
                    flags,
                    first,
                    second,
                ];
                7
            }
        };
        (words, count)
    }
}

/// The stop record of a thread (stock export 22, 0x91f26058).
pub(super) fn stop_reason(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    thread: ThreadId,
) -> Result<StopReason, Hresult> {
    let has_record = backend
        .has_monitor_record(thread)
        .map_err(|NoSuchThread| Hresult::from_error_code(ErrorCode::NO_SUCH_THREAD))?;
    let entry = state
        .debugger
        .events
        .pending_index(thread)
        .and_then(|index| state.debugger.events.pending[index]);
    let Some(entry) = entry.filter(|_| has_record) else {
        return Err(Hresult::from_error_code(ErrorCode::NOT_STOPPED));
    };
    let Some(record) = entry.record else {
        return Ok(StopReason::Unknown);
    };
    let context = registers(backend, thread);
    let iar = context.iar;
    let address = context.gpr3 as u32;
    let length = context.gpr4 as u16;
    Ok(match record.code {
        ExceptionRecord::BREAKPOINT => match record.trap_code() {
            trap::DEBUG_STRING => StopReason::DebugString { thread },
            trap::BREAKPOINT => StopReason::Breakpoint {
                address: iar,
                thread,
            },
            0x19 | trap::ASSERT_PROMPT => StopReason::Assert {
                thread,
                address,
                length,
            },
            trap::RIP => StopReason::Rip {
                thread,
                address,
                length,
            },
            _ => StopReason::Unknown,
        },
        ExceptionRecord::SINGLE_STEP if record.parameters[0] == 0 => StopReason::DataBreakpoint {
            address: iar,
            thread,
        },
        ExceptionRecord::SINGLE_STEP => StopReason::SingleStep {
            address: iar,
            thread,
        },
        // The builder tests code 0x15 for ntassert; the dispatch raises
        // 0xc0000420, which reports as an exception.
        0x15 => StopReason::NtAssert {
            address: iar,
            thread,
        },
        _ => StopReason::Exception {
            thread,
            record,
            first_chance: entry.first_chance,
        },
    })
}

/// `isstopped` text for a stop record (stock 0x91f48d90 and 0x91f391e0).
pub(super) fn stop_description<const N: usize>(
    backend: &mut dyn AnyBackend,
    reason: &StopReason,
    out: &mut Text<N>,
) {
    let _ = match *reason {
        StopReason::DebugString { thread } => {
            write!(out, "debugstr thread=0x{:08x} stop", thread.0)
        }
        StopReason::Breakpoint { address, thread } => {
            write!(out, "break addr=0x{address:08x} thread=0x{:08x}", thread.0)
        }
        StopReason::Assert {
            thread,
            address,
            length,
        } => {
            write!(
                out,
                "assert thread=0x{:08x} straddr=0x{address:08x} strlen=0x{:08x}",
                thread.0,
                u32::from(length)
            )
        }
        StopReason::Rip {
            thread, address: 0, ..
        } => write!(out, "rip thread=0x{:08x}", thread.0),
        StopReason::Rip {
            thread,
            address,
            length,
        } => {
            let mut buffer = [0u8; NOTICE_TEXT_CAPACITY];
            let mut padded = Text::<0x200>::new();
            let text = pad_message(
                target_text(backend, address, length, &mut buffer),
                usize::from(length),
                &mut padded,
            );
            write!(out, "rip thread=0x{:08x} string={text}", thread.0)
        }
        StopReason::SingleStep { address, thread } => write!(
            out,
            "singlestep addr=0x{address:08x} thread=0x{:08x}",
            thread.0
        ),
        StopReason::NtAssert { address, thread } => write!(
            out,
            "ntassert addr=0x{address:08x} thread=0x{:08x}",
            thread.0
        ),
        // The formatter reads the data breakpoint kind from a word the
        // record never sets; an unknown kind formats as `stopped`.
        StopReason::Unknown | StopReason::DataBreakpoint { .. } => out.write_str("stopped"),
        StopReason::Exception {
            thread,
            record,
            first_chance,
        } => {
            let code = record.code;
            let _ = write!(
                out,
                "exception code=0x{code:08x} thread=0x{:08x} address=0x{:08x}",
                thread.0, record.address
            );
            if code == ExceptionRecord::ACCESS_VIOLATION {
                let kind = if record.parameters[0] == 0 {
                    "read"
                } else {
                    "write"
                };
                let _ = write!(out, " {kind}=0x{:08x}", record.parameters[1]);
            } else {
                let _ = write!(
                    out,
                    " nparam={} params=0x{:08x}",
                    record.parameter_count,
                    record.parameters_address()
                );
            }
            if first_chance {
                let _ = out.write_str(" first");
            }
            if record.flags & ExceptionRecord::NONCONTINUABLE != 0 {
                let _ = out.write_str(" noncont");
            }
            Ok(())
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trap_rewrite_follows_instruction_form() {
        let mut record = ExceptionRecord {
            code: 0xc000_008c,
            parameters: [0x0ca0_ffff, 0, 0, 0],
            ..Default::default()
        };
        rewrite_trap(&mut record);
        assert_eq!(record.code, 0xc000_0095);
        let mut record = ExceptionRecord {
            code: 0xc000_0094,
            parameters: [0x0cc0_0000, 0, 0, 0],
            ..Default::default()
        };
        rewrite_trap(&mut record);
        assert_eq!(record.code, 0xc000_0094);
        let mut record = ExceptionRecord {
            code: 0xc000_0094,
            parameters: [0x0fe0_0016, 0, 0, 0],
            ..Default::default()
        };
        rewrite_trap(&mut record);
        assert_eq!(record.code, ExceptionRecord::BREAKPOINT);
        let mut record = ExceptionRecord {
            code: 0xc000_0094,
            parameters: [0x7c00_0008, 0, 0, 0],
            ..Default::default()
        };
        rewrite_trap(&mut record);
        assert_eq!(record.code, ExceptionRecord::BREAKPOINT);
    }

    #[test]
    fn rip_message_is_cut_and_padded() {
        let mut out = Text::<0x200>::new();
        assert_eq!(pad_message(b"abc\0def", 5, &mut out), "abc  ");
        assert_eq!(pad_message(b"abcdef", 4, &mut out), "abcd");
    }
}
