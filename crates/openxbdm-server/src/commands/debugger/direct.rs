//! Exceptions raised where the thread cannot wait for the server: above
//! passive level, or on the server thread itself. The monitor's dispatch
//! (stock 0x91f39fc0) cannot stop such a thread. Up to dispatch level its
//! notifications go to the deferred queue (stock 0x91f39768) when a
//! debugger is attached and `eventdefer` selects them; on the server
//! thread they go out unconditionally. Exceptions of a thread that
//! overflowed its stack take this path too and end unresolved.
//!
//! The platform runs [`dispatch_direct`] on the raising thread with the
//! [`DirectPolicy`] the server last published, applies the outcome, and
//! queues the notification for the server.

use openxbdm_core::status::NtStatus;
use xbox360_sys::processor::Msr;
use xbox360_sys::xboxkrnl::HardwareFlags;

use super::DataBreakpoint;
use super::Disposition;
use super::ExceptionRecord;
use super::ProcessKind;
use super::StopOn;
use super::ThreadId;
use super::breakpoints::BreakpointState;
use super::breakpoints::CodeWords;
use super::breakpoints::Slot;
use super::breakpoints::access_length;
use super::events::ASSERT_IGNORE;
use super::events::process_index;
use super::events::rewrite_trap;
use super::trap;
use crate::commands::console::DumpMode;
use crate::commands::console::EventDeferMask;

/// Monitor state the dispatch and the platform's event services read,
/// copied by the server for use on any thread.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectPolicy {
    /// Events that stop the reporting thread.
    pub stop_on: StopOn,
    /// Unresolved exceptions go to the previous kernel debug routine.
    pub kd_lite: bool,
    /// Debug exceptions are routed to the kernel debugger.
    pub kernel_debugger: bool,
    /// First-chance breakpoint and trace exceptions pass through.
    pub trap_passthrough: bool,
    pub dump_mode: DumpMode,
    /// A crash dump was written; exceptions are no longer dispatched.
    pub dump_in_progress: bool,
    /// A debugger is attached (`debugger connect` or a debug target).
    pub attached: bool,
    /// `eventdefer` mask: notifications queued above passive level.
    pub defer_mask: EventDeferMask,
    pub data_breakpoint: Option<DataBreakpoint>,
    /// Per process (title, system): a step over begun by a posted event
    /// is pending and its trace exception ends without a stop.
    pub quiet_step: [bool; 2],
}

/// Whether the monitor's dispatch (stock 0x91f39fc0) stops a thread that
/// can wait at this exception, as the server decides for a posted one
/// (`events.rs`). The platform asks on the raising thread while the server
/// waits for a dispatch flag 0x4 command thread: such a thread then waits
/// for the server as stock's would, and any other is dispatched in place.
/// `in_table` tells whether a software breakpoint is set at an address;
/// `module_has_header` whether the module of a load trap (r3, r4) has an
/// image header.
pub fn exception_stops(
    policy: &DirectPolicy,
    event: &DirectException,
    process: ProcessKind,
    context: &DirectRegisters,
    instruction: Option<u32>,
    in_table: &mut dyn FnMut(u32) -> bool,
    module_has_header: &mut dyn FnMut(u32, u32) -> bool,
) -> bool {
    let mut record = event.record;
    if !event.second_chance {
        rewrite_trap(&mut record);
    }

    let hardware_kd = event
        .hardware_flags
        .contains(HardwareFlags::KERNEL_DEBUGGER);
    if !event.second_chance && policy.trap_passthrough && !hardware_kd {
        let passes = match record.code {
            NtStatus::BREAKPOINT => record.trap_code() == trap::BREAKPOINT,
            NtStatus::SINGLE_STEP => true,
            _ => false,
        };
        if passes {
            return false;
        }
    }

    if policy.dump_in_progress {
        return false;
    }

    let kd = policy.kernel_debugger && hardware_kd;
    let can_stop = event.debuggable
        && context.msr.contains(Msr::EXTERNAL_INTERRUPT)
        && (policy.dump_mode != DumpMode::Enabled || policy.attached);
    match record.code {
        NtStatus::BREAKPOINT => match record.trap_code() {
            trap::DEBUG_STRING => can_stop && policy.stop_on.contains(StopOn::DEBUG_STRING),
            trap::MODULE_LOAD => {
                !kd && can_stop
                    && policy.stop_on.contains(StopOn::MODULE_LOAD)
                    && module_has_header(context.gpr3 as u32, context.gpr4 as u32)
            }
            trap::MODULE_UNLOAD | trap::DEBUG_SERVICE => false,
            trap::ASSERT_PROMPT | trap::RIP => !kd && can_stop,
            _ => can_stop && (!kd || in_table(context.iar)),
        },
        NtStatus::ASSERTION_FAILURE => !kd && can_stop,
        NtStatus::SINGLE_STEP if record.parameters[0] == 0 => {
            policy.data_breakpoint.is_some_and(|data| {
                data.overlaps(record.parameters[1], instruction.map_or(8, access_length))
            }) && can_stop
        }
        NtStatus::SINGLE_STEP => !policy.quiet_step[process_index(process)] && !kd && can_stop,
        _ => {
            !kd && can_stop
                && (event.second_chance || policy.stop_on.contains(StopOn::FIRST_CHANCE_EXCEPTION))
        }
    }
}

/// How notifications leave the raising thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The server thread at passive level, or a passive-level thread while
    /// the server thread waits for a command thread: every notification is
    /// sent.
    Inline,
    /// Above passive level up to dispatch level: the deferred queue.
    Deferred,
    /// Above dispatch level: nothing is sent.
    Discarded,
}

/// An exception the platform dispatches on the raising thread.
#[derive(Debug, Clone, Copy)]
pub struct DirectException {
    pub thread: ThreadId,
    pub record: ExceptionRecord,
    pub second_chance: bool,
    /// The thread has a monitor record.
    pub has_record: bool,
    /// The monitor record has the debuggable flag.
    pub debuggable: bool,
    /// The thread's monitor record is marked by a stack overflow: the
    /// exception ends unresolved (stock 0x91f3a0d8).
    pub stack_overflowed: bool,
    /// The thread waits in its slot at an earlier event (stock record
    /// +0xc set, 0x91f3a0e4).
    pub nested: bool,
    pub hardware_flags: HardwareFlags,
    pub delivery: Delivery,
}

/// Notification of a direct exception. The platform captures what the
/// variant names (target text, module descriptions) before queueing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectNotice {
    /// A table breakpoint of a thread that cannot stop, reported without a
    /// stop.
    Break,
    DebugString {
        address: u32,
        length: u16,
    },
    /// From the loader's name string and module entry; sent only when the
    /// module has an image header.
    ModuleLoad {
        name_string: u32,
        entry: u32,
    },
    /// The platform removes the module's breakpoints during the dispatch
    /// (stock 0x91f3a3dc), even when `line` is false.
    ModuleUnload {
        name_string: u32,
        entry: u32,
        line: bool,
    },
    Assert {
        address: u32,
        length: u16,
    },
    Rip {
        address: u32,
        length: u16,
    },
    SingleStep,
    Data {
        kind: u32,
        address: u32,
    },
    Exception {
        first_chance: bool,
    },
}

/// Step over begun in place (stock 0x91f27550 and the data breakpoint step
/// of 0x91f274d8), ended by the next single step (0x91f27630).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectStep {
    pub(crate) target: DirectStepTarget,
    /// Trace was enabled before the step.
    pub(crate) saved_trace: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectStepTarget {
    /// The lifted table breakpoint, re-armed after the step.
    Breakpoint(Slot),
    /// The data breakpoint register, reprogrammed after the step.
    DataBreakpoint,
}

/// What the platform does after [`dispatch_direct`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
// Declaration order keeps the record word-aligned for its copies.
#[repr(C)]
pub struct DirectOutcome {
    pub notice: Option<DirectNotice>,
    /// The exception record after the monitor's trap rewrite; notifications
    /// report it.
    pub record: ExceptionRecord,
    pub disposition: Disposition,
    /// Value to program into the data breakpoint register.
    pub data_breakpoint_register: Option<u32>,
    /// Thread-name exception: name this thread from the string address.
    pub thread_name: Option<ThreadNameRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadNameRequest {
    pub thread: ThreadId,
    pub address: u32,
}

/// The registers [`dispatch_direct`] reads and changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectRegisters {
    pub msr: Msr,
    pub iar: u32,
    pub gpr3: u64,
    pub gpr4: u64,
}

/// The monitor's dispatch for a thread that cannot stop (stock 0x91f39fc0
/// with "can stop" false, 0x91f3a110). `context` is updated in place;
/// `instruction` is the word at Iar. The platform holds its table lock
/// around the call, which reaches the breakpoint table and the in-place
/// step state through `shared`.
pub fn dispatch_direct(
    policy: &DirectPolicy,
    event: &DirectException,
    context: &mut DirectRegisters,
    instruction: Option<u32>,
    shared: &mut BreakpointState,
    code: &mut dyn CodeWords,
) -> DirectOutcome {
    let mut outcome = DirectOutcome::default();
    let mut record = event.record;
    if !event.second_chance {
        rewrite_trap(&mut record);
    }
    outcome.record = record;

    let hardware_kd = event
        .hardware_flags
        .contains(HardwareFlags::KERNEL_DEBUGGER);
    let reprogram = policy.data_breakpoint.map(DataBreakpoint::register);
    if !event.second_chance && policy.trap_passthrough && !hardware_kd {
        let passes = match record.code {
            NtStatus::BREAKPOINT => record.trap_code() == trap::BREAKPOINT,
            NtStatus::SINGLE_STEP => true,
            _ => false,
        };
        if passes {
            outcome.data_breakpoint_register = reprogram;
            outcome.disposition.handled = true;
            return outcome;
        }
    }

    let mut dump = !hardware_kd && policy.dump_mode != DumpMode::Disabled;
    let mut advance = true;
    if policy.dump_in_progress {
        dump = false;
    } else if event.stack_overflowed {
        // Ends unresolved below.
    } else if event.nested {
        // Stock 0x91f3a1b0: only a table breakpoint at Iar is resolved, by
        // restoring its instruction.
        if record.code == NtStatus::BREAKPOINT {
            match record.trap_code() {
                trap::BREAKPOINT if shared.table.disarm_at(context.iar, code) => {
                    outcome.disposition.handled = true;
                    return outcome;
                }
                trap::DEBUG_STRING | trap::DEBUG_SERVICE => dump = false,
                _ => {}
            }
        }
    } else {
        // Whether the notification goes out, and whether the deferred
        // queue took it (which resolves the event as a continue would).
        let sent = |defer_bit: Option<EventDeferMask>| match event.delivery {
            Delivery::Inline => true,
            Delivery::Deferred => {
                defer_bit.is_some_and(|bit| policy.attached && policy.defer_mask.intersects(bit))
            }
            Delivery::Discarded => false,
        };
        let queued = |defer_bit: EventDeferMask| {
            event.delivery == Delivery::Deferred && sent(Some(defer_bit))
        };

        let gpr3 = context.gpr3;
        let gpr4 = context.gpr4;
        match record.code {
            NtStatus::BREAKPOINT => match record.trap_code() {
                trap::DEBUG_STRING => {
                    dump = false;
                    if event.has_record && sent(Some(EventDeferMask::DEBUG_STRING)) {
                        outcome.notice = Some(DirectNotice::DebugString {
                            address: gpr3 as u32,
                            length: gpr4 as u16,
                        });
                    }
                }
                trap::MODULE_LOAD => {
                    dump = false;
                    if sent(None) {
                        outcome.notice = Some(DirectNotice::ModuleLoad {
                            name_string: gpr3 as u32,
                            entry: gpr4 as u32,
                        });
                    }
                }
                trap::MODULE_UNLOAD => {
                    dump = false;
                    if gpr3 != 0 {
                        outcome.notice = Some(DirectNotice::ModuleUnload {
                            name_string: gpr3 as u32,
                            entry: gpr4 as u32,
                            line: sent(None),
                        });
                    }
                }
                trap_code @ (trap::ASSERT_PROMPT | trap::RIP) => {
                    let (bit, notice) = if trap_code == trap::ASSERT_PROMPT {
                        (
                            EventDeferMask::ASSERT,
                            DirectNotice::Assert {
                                address: gpr3 as u32,
                                length: gpr4 as u16,
                            },
                        )
                    } else {
                        (
                            EventDeferMask::RIP,
                            DirectNotice::Rip {
                                address: gpr3 as u32,
                                length: gpr4 as u16,
                            },
                        )
                    };
                    if sent(Some(bit)) {
                        outcome.notice = Some(notice);
                    }

                    if queued(bit) {
                        if trap_code == trap::ASSERT_PROMPT {
                            context.gpr3 = ASSERT_IGNORE;
                        }
                        context.iar = context.iar.wrapping_add(4);
                        outcome.disposition.handled = true;
                        return outcome;
                    }
                }
                trap::DEBUG_SERVICE => dump = false,
                // Any other breakpoint that is not in the table ends
                // unresolved below (0x91f3a244).
                _ if shared.table.contains(context.iar) => {
                    // Reported without a stop, stepped over and handled
                    // (0x91f3a270, 0x91f3a2a0; the word tested at 0x91f3a2e0
                    // has no writer).
                    if event.debuggable && sent(Some(EventDeferMask::BREAK)) {
                        outcome.notice = Some(DirectNotice::Break);
                    }
                    step_over(shared, code, context);
                    outcome.disposition.handled = true;
                    return outcome;
                }
                _ => {}
            },
            NtStatus::ASSERTION_FAILURE => {
                // No notification; resolved by the common dump and continue below.
            }
            NtStatus::SINGLE_STEP if record.parameters[0] == 0 => {
                if let Some(data) = policy.data_breakpoint {
                    let length = instruction.map_or(8, access_length);
                    let overlap = data.overlaps(record.parameters[1], length);
                    if overlap && sent(Some(EventDeferMask::DATA_BREAK)) {
                        outcome.notice = Some(DirectNotice::Data {
                            kind: data.kind as u32,
                            address: data.address,
                        });
                    }

                    if !overlap || queued(EventDeferMask::DATA_BREAK) {
                        shared.direct_step = Some(DirectStep {
                            target: DirectStepTarget::DataBreakpoint,
                            saved_trace: context.msr.contains(Msr::SINGLE_STEP),
                        });
                        context.msr.insert(Msr::SINGLE_STEP);
                        outcome.data_breakpoint_register = Some(0);
                        outcome.disposition.handled = true;
                        return outcome;
                    }
                }
            }
            NtStatus::SINGLE_STEP => {
                // Stock 0x91f27630.
                if let Some(finished) = shared.direct_step.take() {
                    match finished.target {
                        DirectStepTarget::Breakpoint(slot) => shared.table.rearm(slot, code),
                        DirectStepTarget::DataBreakpoint => {
                            outcome.data_breakpoint_register = reprogram;
                        }
                    }
                    if !finished.saved_trace {
                        context.msr.remove(Msr::SINGLE_STEP);
                        outcome.disposition.handled = true;
                        return outcome;
                    }
                }

                context.msr.remove(Msr::SINGLE_STEP);
                if sent(Some(EventDeferMask::SINGLE_STEP)) {
                    outcome.notice = Some(DirectNotice::SingleStep);
                }

                if queued(EventDeferMask::SINGLE_STEP) {
                    // As a continue: step over a table breakpoint at the
                    // new Iar (0x91f3a68c).
                    if shared.table.contains(context.iar) {
                        step_over(shared, code, context);
                    }
                    outcome.disposition.handled = true;
                    return outcome;
                }

                context.msr.insert(Msr::SINGLE_STEP);
            }
            _ => {
                advance = false;
                if record.code == NtStatus::THREAD_NAME && record.parameters[0] == 0x1000 {
                    let thread = match record.parameters[2] {
                        u32::MAX => event.thread,
                        other => ThreadId(other),
                    };
                    outcome.thread_name = Some(ThreadNameRequest {
                        thread,
                        address: record.parameters[1],
                    });
                }

                dump &= event.second_chance;
                if sent(None) {
                    outcome.notice = Some(DirectNotice::Exception {
                        first_chance: !event.second_chance,
                    });
                }
            }
        }
    }

    outcome.disposition.write_dump = dump;
    if policy.kd_lite {
        outcome.disposition.chain_kernel_debugger = true;
    } else if advance {
        context.gpr3 = 0;
        context.iar = context.iar.wrapping_add(4);
        outcome.disposition.handled = true;
    }
    outcome.data_breakpoint_register = reprogram;

    outcome
}

/// Lift the table breakpoint at Iar for one traced instruction (stock
/// 0x91f27550), keeping its position for the re-arm.
fn step_over(
    shared: &mut BreakpointState,
    code: &mut dyn CodeWords,
    context: &mut DirectRegisters,
) {
    if let Some(slot) = shared.table.lift(context.iar, code) {
        shared.direct_step = Some(DirectStep {
            target: DirectStepTarget::Breakpoint(slot),
            saved_trace: context.msr.contains(Msr::SINGLE_STEP),
        });
        context.msr.insert(Msr::SINGLE_STEP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(code: NtStatus, trap_code: u16, debuggable: bool) -> DirectException {
        DirectException {
            thread: ThreadId(0xfb00_0058),
            record: ExceptionRecord {
                code,
                parameter_count: 1,
                parameters: [u32::from(trap_code), 0, 0, 0],
                ..ExceptionRecord::default()
            },
            second_chance: false,
            has_record: true,
            debuggable,
            stack_overflowed: false,
            nested: false,
            hardware_flags: HardwareFlags::empty(),
            delivery: Delivery::Inline,
        }
    }

    fn stops(policy: &DirectPolicy, event: &DirectException, msr: Msr) -> bool {
        let context = DirectRegisters {
            msr,
            iar: 0x8200_1000,
            gpr3: 0,
            gpr4: 0,
        };
        exception_stops(
            policy,
            event,
            ProcessKind::Title,
            &context,
            None,
            &mut |_| false,
            &mut |_, _| true,
        )
    }

    #[test]
    fn breakpoints_and_prompts_stop_a_thread_that_can_stop() {
        let policy = DirectPolicy::default();
        let enabled = Msr::EXTERNAL_INTERRUPT;
        for code in [trap::BREAKPOINT, trap::ASSERT_PROMPT, trap::RIP] {
            assert!(stops(
                &policy,
                &event(NtStatus::BREAKPOINT, code, true),
                enabled
            ));
            assert!(!stops(
                &policy,
                &event(NtStatus::BREAKPOINT, code, false),
                enabled
            ));
            assert!(!stops(
                &policy,
                &event(NtStatus::BREAKPOINT, code, true),
                Msr::empty()
            ));
        }
    }

    #[test]
    fn notifications_stop_only_when_stopon_selects_them() {
        let enabled = Msr::EXTERNAL_INTERRUPT;
        let debug_string = event(NtStatus::BREAKPOINT, trap::DEBUG_STRING, true);
        let module_load = event(NtStatus::BREAKPOINT, trap::MODULE_LOAD, true);
        let first_chance = event(NtStatus::ACCESS_VIOLATION, 0, true);
        let mut policy = DirectPolicy::default();
        assert!(!stops(&policy, &debug_string, enabled));
        assert!(!stops(&policy, &module_load, enabled));
        assert!(!stops(&policy, &first_chance, enabled));
        assert!(!stops(
            &policy,
            &event(NtStatus::BREAKPOINT, trap::MODULE_UNLOAD, true),
            enabled
        ));

        policy.stop_on =
            StopOn::DEBUG_STRING | StopOn::MODULE_LOAD | StopOn::FIRST_CHANCE_EXCEPTION;
        assert!(stops(&policy, &debug_string, enabled));
        assert!(stops(&policy, &module_load, enabled));
        assert!(stops(&policy, &first_chance, enabled));
    }

    #[test]
    fn step_over_trace_exception_does_not_stop() {
        let step = event(NtStatus::SINGLE_STEP, 1, true);
        let mut policy = DirectPolicy::default();
        assert!(stops(&policy, &step, Msr::EXTERNAL_INTERRUPT));
        policy.quiet_step = [true, false];
        assert!(!stops(&policy, &step, Msr::EXTERNAL_INTERRUPT));
    }
}
