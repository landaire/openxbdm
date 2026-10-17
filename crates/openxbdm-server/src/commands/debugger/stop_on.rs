//! `stopon` and `nostopon`: events that stop the reporting thread.

use crate::invocation::Invocation;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;

xbox360_sys::flags! {
    /// Events that stop the reporting thread when they occur.
    pub struct StopOn(u32) {
        CREATE_THREAD = 0x1,
        /// First-chance exceptions.
        FIRST_CHANCE_EXCEPTION = 0x2,
        DEBUG_STRING = 0x4,
        STACK_TRACE = 0x8,
        MODULE_LOAD = 0x10,
        /// Set only by `stopon all`: title reboots of reasons other than 0
        /// and 4.
        TITLE_REBOOT = 0x20,
        POGO_MODULE_START = 0x40,
    }
}

fn stop_on_mask(invocation: &mut Invocation<'_>, all_text: &str) -> StopOn {
    const STOP_ON_FLAGS: [(&str, StopOn); 6] = [
        ("fce", StopOn::FIRST_CHANCE_EXCEPTION),
        ("debugstr", StopOn::DEBUG_STRING),
        ("createthread", StopOn::CREATE_THREAD),
        ("stacktrace", StopOn::STACK_TRACE),
        ("modload", StopOn::MODULE_LOAD),
        ("pogomodstart", StopOn::POGO_MODULE_START),
    ];

    if invocation.line.has("all") {
        invocation.set_text(format_args!("{all_text}"));
        return StopOn::from_bits_retain(u32::MAX);
    }

    STOP_ON_FLAGS
        .iter()
        .filter(|(name, _)| invocation.line.has(name))
        .fold(StopOn::empty(), |mask, &(_, flag)| mask | flag)
}

/// Set or clear stop-on flags (stock export 46, 0x91f26790).
pub fn change_stop_on(state: &mut ServerState, mask: StopOn, enable: bool) {
    let stop_on = &mut state.debugger.stop_on;
    if enable {
        stop_on.insert(mask);
    } else {
        stop_on.remove(mask);
    }
}

/// `stopon`.
pub(super) fn stop_on(invocation: &mut Invocation<'_>) -> CommandResult {
    let mask = stop_on_mask(invocation, "stop on all");
    change_stop_on(invocation.state, mask, true);

    Ok(Reply::Ok)
}

/// `nostopon`.
pub(super) fn no_stop_on(invocation: &mut Invocation<'_>) -> CommandResult {
    let mask = stop_on_mask(invocation, "stop on none");
    change_stop_on(invocation.state, mask, false);

    Ok(Reply::Ok)
}
