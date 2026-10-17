//! Execution control: `stop`, `go`, `halt`, and the monitor's execution
//! state machine.

use openxbdm_core::status::ErrorCode;

use super::ExecutionError;
use super::PROCESS_ORDER;
use super::events;
use crate::backend::Backend as AnyBackend;
use crate::invocation::Invocation;
use crate::network::Network;
use crate::notify::Event;
use crate::notify::ExecutionState;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;

/// Thread actions of a transition per process, indexed like
/// [`PROCESS_ORDER`].
struct ProcessActions {
    release: [bool; 2],
    suspend: [bool; 2],
    resume: [bool; 2],
}

impl ProcessActions {
    const NONE: Self = Self {
        release: [false; 2],
        suspend: [false; 2],
        resume: [false; 2],
    };
}

/// Change the execution state for a command (callers of the monitor's
/// state machine that test the current state first): stopped, started,
/// reboot_title, or pending_title.
pub(crate) fn change_execution(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    target: ExecutionState,
) -> Result<(), ExecutionError> {
    match (target, backend.execution_state()) {
        (
            ExecutionState::Stopped,
            ExecutionState::Stopped | ExecutionState::Pending | ExecutionState::PendingTitle,
        ) => Err(ExecutionError::AlreadyStopped),
        (
            ExecutionState::Started,
            ExecutionState::Started | ExecutionState::RebootTitle | ExecutionState::Pending,
        ) => Err(ExecutionError::NotStopped),
        (ExecutionState::Started, ExecutionState::Rebooting) => Err(ExecutionError::Rebooting),
        _ if transition(state, backend, network, target, true) => Ok(()),
        _ => Err(ExecutionError::AccessDenied),
    }
}

/// The monitor's execution state machine (0x91f2da88) without its wait
/// flag: apply the transition to `target` and report whether one applied.
/// `notify` sends the `execution` line.
pub(super) fn transition(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    target: ExecutionState,
    notify: bool,
) -> bool {
    let current = backend.execution_state();
    let (new, actions) = match (target, current) {
        (
            ExecutionState::Stopped,
            ExecutionState::Started | ExecutionState::Rebooting | ExecutionState::RebootTitle,
        ) => {
            state.debugger.saved_execution = current;
            let actions = ProcessActions {
                suspend: [true, true],
                ..ProcessActions::NONE
            };
            (ExecutionState::Stopped, actions)
        }
        (ExecutionState::Started, ExecutionState::Stopped) => {
            let saved = state.debugger.saved_execution;
            let actions = ProcessActions {
                resume: [saved != ExecutionState::RebootTitle, true],
                ..ProcessActions::NONE
            };
            (saved, actions)
        }
        (ExecutionState::Started, ExecutionState::PendingTitle) => {
            let actions = ProcessActions {
                release: [true, true],
                resume: [true, true],
                ..ProcessActions::NONE
            };
            (ExecutionState::Started, actions)
        }
        (
            ExecutionState::RebootTitle,
            ExecutionState::Stopped | ExecutionState::Started | ExecutionState::Pending,
        ) => {
            let actions = ProcessActions {
                release: [false, true],
                resume: [false, true],
                ..ProcessActions::NONE
            };
            (ExecutionState::RebootTitle, actions)
        }
        (ExecutionState::PendingTitle, ExecutionState::RebootTitle) => {
            (ExecutionState::PendingTitle, ProcessActions::NONE)
        }
        _ => return false,
    };

    for (index, &process) in PROCESS_ORDER.iter().enumerate() {
        if actions.release[index] {
            events::release_stopped(state, backend, network, process);
        }
        if actions.suspend[index] {
            backend.suspend_threads(process);
        }
        if actions.resume[index] {
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

/// Stop the title (stock 0x91f25be0); fails unless this call stopped it.
pub fn stop_execution(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) -> Result<(), ExecutionError> {
    change_execution(state, backend, network, ExecutionState::Stopped)
}

/// Resume the title (stock 0x91f25b50).
pub fn go_execution(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) -> Result<(), ExecutionError> {
    let target = if backend.execution_state() == ExecutionState::Pending {
        ExecutionState::RebootTitle
    } else {
        ExecutionState::Started
    };

    change_execution(state, backend, network, target)
}

/// `stop`.
pub(super) fn stop(invocation: &mut Invocation<'_>) -> CommandResult {
    let result = stop_execution(invocation.state, invocation.backend, invocation.network);
    if result == Err(ExecutionError::AlreadyStopped) {
        invocation.set_text(format_args!("already stopped"));
    }

    result?;

    Ok(Reply::Ok)
}

/// `go`.
pub(super) fn go(invocation: &mut Invocation<'_>) -> CommandResult {
    let result = go_execution(invocation.state, invocation.backend, invocation.network);
    if result == Err(ExecutionError::NotStopped) {
        invocation.set_text(format_args!("not stopped"));
    }

    result?;

    Ok(Reply::Ok)
}

/// `halt [thread=]`: the monitor's halt routine always fails.
pub(super) fn halt(_invocation: &mut Invocation<'_>) -> CommandResult {
    Err(ErrorCode::Undefined.into())
}
