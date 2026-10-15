//! Exceptions raised where the thread cannot wait for the server: above
//! passive level, or on the server thread itself. The monitor's dispatch
//! (stock 0x91f39fc0) cannot stop such a thread. Up to dispatch level its
//! notifications go to the deferred queue (stock 0x91f39768) when a
//! debugger is attached and `eventdefer` selects them; on the server
//! thread they go out unconditionally.
//!
//! The platform runs [`dispatch_direct`] on the raising thread with the
//! [`DirectPolicy`] the server last published, applies the outcome, and
//! queues the notification for the server.

use super::DataBreakpoint;
use super::Disposition;
use super::ExceptionRecord;
use super::HARDWARE_KERNEL_DEBUGGER;
use super::MSR_SINGLE_STEP;
use super::StopOn;
use super::ThreadId;
use super::breakpoints::access_length;
use super::events::ASSERT_IGNORE;
use super::events::rewrite_trap;
use super::trap;
use crate::commands::console::DumpMode;

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
    pub defer_mask: u32,
    pub data_breakpoint: Option<DataBreakpoint>,
}

impl DirectPolicy {
    const DEFER_DEBUG_STRING: u32 = 0x2;
    const DEFER_SINGLE_STEP: u32 = 0x4;
    const DEFER_ASSERT: u32 = 0x8;
    const DEFER_DATA_BREAK: u32 = 0x20;
    const DEFER_RIP: u32 = 0x40;
}

/// How notifications leave the raising thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The server thread at passive level: every notification is sent.
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
    pub hardware_flags: u32,
    pub delivery: Delivery,
}

/// Notification of a direct exception. The platform captures what the
/// variant names (target text, module descriptions) before queueing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectNotice {
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
    /// Breakpoints in the module are removed even when `line` is false.
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

/// Step over the data breakpoint begun by a direct exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectStep {
    /// Trace was enabled before the step.
    pub saved_trace: bool,
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
    pub msr: u32,
    pub iar: u32,
    pub gpr3: u64,
    pub gpr4: u64,
}

/// The monitor's dispatch for a thread that cannot stop. `context` is
/// updated in place; `instruction` is the word at Iar; `step` is the step
/// state of direct exceptions.
pub fn dispatch_direct(
    policy: &DirectPolicy,
    event: &DirectException,
    context: &mut DirectRegisters,
    instruction: Option<u32>,
    step: &mut Option<DirectStep>,
) -> DirectOutcome {
    let mut outcome = DirectOutcome::default();
    let mut record = event.record;
    if !event.second_chance {
        rewrite_trap(&mut record);
    }
    outcome.record = record;
    let hardware_kd = event.hardware_flags & HARDWARE_KERNEL_DEBUGGER != 0;
    let reprogram = policy.data_breakpoint.map(DataBreakpoint::register);
    if !event.second_chance && policy.trap_passthrough && !hardware_kd {
        let passes = match record.code {
            ExceptionRecord::BREAKPOINT => record.trap_code() == trap::BREAKPOINT,
            ExceptionRecord::SINGLE_STEP => true,
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
    } else {
        // Whether the notification goes out, and whether the deferred
        // queue took it (which resolves the event as a continue would).
        let sent = |defer_bit: Option<u32>| match event.delivery {
            Delivery::Inline => true,
            Delivery::Deferred => {
                defer_bit.is_some_and(|bit| policy.attached && policy.defer_mask & bit != 0)
            }
            Delivery::Discarded => false,
        };
        let queued = |defer_bit: u32| event.delivery == Delivery::Deferred && sent(Some(defer_bit));
        let gpr3 = context.gpr3;
        let gpr4 = context.gpr4;
        match record.code {
            ExceptionRecord::BREAKPOINT => match record.trap_code() {
                trap::DEBUG_STRING => {
                    dump = false;
                    if event.has_record && sent(Some(DirectPolicy::DEFER_DEBUG_STRING)) {
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
                code @ (trap::ASSERT_PROMPT | trap::RIP) => {
                    let (bit, notice) = if code == trap::ASSERT_PROMPT {
                        (
                            DirectPolicy::DEFER_ASSERT,
                            DirectNotice::Assert {
                                address: gpr3 as u32,
                                length: gpr4 as u16,
                            },
                        )
                    } else {
                        (
                            DirectPolicy::DEFER_RIP,
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
                        if code == trap::ASSERT_PROMPT {
                            context.gpr3 = ASSERT_IGNORE;
                        }
                        context.iar = context.iar.wrapping_add(4);
                        outcome.disposition.handled = true;
                        return outcome;
                    }
                }
                trap::DEBUG_SERVICE => dump = false,
                _ => {
                    // The monitor stops at every other trap, which a thread
                    // that cannot wait does not survive; the previous
                    // kernel debug routine takes the trap instead.
                    outcome.disposition.chain_kernel_debugger = true;
                    return outcome;
                }
            },
            ExceptionRecord::NT_ASSERT => {}
            ExceptionRecord::SINGLE_STEP if record.parameters[0] == 0 => {
                if let Some(data) = policy.data_breakpoint {
                    let length = instruction.map_or(8, access_length);
                    let overlap = data.overlaps(record.parameters[1], length);
                    if overlap && sent(Some(DirectPolicy::DEFER_DATA_BREAK)) {
                        outcome.notice = Some(DirectNotice::Data {
                            kind: data.kind as u32,
                            address: data.address,
                        });
                    }
                    if !overlap || queued(DirectPolicy::DEFER_DATA_BREAK) {
                        *step = Some(DirectStep {
                            saved_trace: context.msr & MSR_SINGLE_STEP != 0,
                        });
                        context.msr |= MSR_SINGLE_STEP;
                        outcome.data_breakpoint_register = Some(0);
                        outcome.disposition.handled = true;
                        return outcome;
                    }
                }
            }
            ExceptionRecord::SINGLE_STEP => {
                if let Some(finished) = step.take() {
                    outcome.data_breakpoint_register = reprogram;
                    if !finished.saved_trace {
                        context.msr &= !MSR_SINGLE_STEP;
                        outcome.disposition.handled = true;
                        return outcome;
                    }
                }
                context.msr &= !MSR_SINGLE_STEP;
                if sent(Some(DirectPolicy::DEFER_SINGLE_STEP)) {
                    outcome.notice = Some(DirectNotice::SingleStep);
                }
                if queued(DirectPolicy::DEFER_SINGLE_STEP) {
                    outcome.disposition.handled = true;
                    return outcome;
                }
                context.msr |= MSR_SINGLE_STEP;
            }
            _ => {
                advance = false;
                if record.code == ExceptionRecord::THREAD_NAME && record.parameters[0] == 0x1000 {
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
