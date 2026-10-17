//! `break` and `isbreak`, and the breakpoint services behind the stock
//! exports.

use super::DataBreakpoint;
use super::DataBreakpointError;
use super::DataKind;
use super::NoSuchBreakpoint;
use super::NotPending;
use super::SetError;
use super::ThreadId;
use super::events;
use crate::backend::Backend as AnyBackend;
use crate::commands::util;
use crate::invocation::Invocation;
use crate::network::Network;
use crate::network::SocketId;
use crate::notify::ExecutionState;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::server::send_status;
use crate::state::ServerState;
use crate::text::LineText;

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

/// A command reply sent when `thread` stops waiting at its event.
#[derive(Debug)]
pub(super) struct HeldReply {
    thread: ThreadId,
    socket: SocketId,
    result: CommandResult,
    text: LineText,
}

/// `break`: `now`, `start`, `clearall`, `addr=` with optional `clear`, or a
/// data breakpoint `read=|write=|readwrite=|execute=` with `size=`. `now`
/// stops the command thread at a trap; the reply follows once a debugger
/// continues it.
pub(super) fn set_breakpoint(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Keys of `break` that request more than `now`.
    static BREAK_FLAGS: [&str; 7] = [
        "start",
        "clearall",
        "addr",
        "read",
        "write",
        "readwrite",
        "execute",
    ];

    let line = invocation.line;
    let now = line.has("now");
    let stopped = if now { break_now(invocation) } else { None };
    let result = if now && !BREAK_FLAGS.iter().any(|key| line.has(key)) {
        Ok(Reply::Ok)
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

    Ok(Reply::Sent)
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

fn breakpoint_flags(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line;
    if line.has("start") {
        if let Err(error) = break_at_title_start(invocation.state, invocation.backend) {
            invocation.set_text(format_args!("execution not pending"));
            return Err(error.into());
        }

        return Ok(Reply::Ok);
    }

    if line.has("clearall") {
        let debugger = &mut invocation.state.debugger;
        debugger.breakpoints.clear_all(invocation.backend);
        debugger.data_breakpoint = None;
        invocation.backend.set_data_breakpoint_register(0);
        return Ok(Reply::Ok);
    }

    let clear = line.has("clear");
    if let Some(address) = util::required_dword(invocation, "addr") {
        if clear {
            clear_software_breakpoint(invocation.state, invocation.backend, address)?;
        } else {
            set_software_breakpoint(invocation.state, invocation.backend, address)?;
        }

        return Ok(Reply::Ok);
    }

    let (address, kind) = if let Some(address) = line.dword("read") {
        (address, Some(DataKind::Read))
    } else if let Some(address) = line.dword("write") {
        (address, Some(DataKind::Write))
    } else if let Some(address) = line.dword("readwrite") {
        (address, Some(DataKind::ReadWrite))
    } else if let Some(address) = line.dword("execute") {
        (address, None)
    } else {
        return Err(util::MISSING);
    };

    let size = if clear {
        0
    } else {
        let Some(size) = util::required_dword(invocation, "size") else {
            return Err(util::MISSING);
        };
        size
    };

    invocation.text.clear();
    let target = if clear {
        DataTarget::Clear
    } else {
        DataTarget::Set(kind)
    };
    set_data_breakpoint(invocation.state, invocation.backend, address, size, target)?;

    Ok(Reply::Ok)
}

/// Break when the title's first thread starts (stock export 39,
/// 0x91f26728): only while a title launch is pending.
pub fn break_at_title_start(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
) -> Result<(), NotPending> {
    if !matches!(
        backend.execution_state(),
        ExecutionState::Pending | ExecutionState::PendingTitle
    ) {
        return Err(NotPending);
    }

    state.debugger.break_at_title_entry = true;

    Ok(())
}

/// Set a software breakpoint at an aligned address (stock export 37,
/// 0x91f27140).
pub fn set_software_breakpoint(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    address: u32,
) -> Result<(), SetError> {
    state.debugger.breakpoints.set(address, backend)
}

/// Remove a software breakpoint (stock export 34, 0x91f27258).
pub fn clear_software_breakpoint(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    address: u32,
) -> Result<(), NoSuchBreakpoint> {
    if !state.debugger.breakpoints.clear(address, backend) {
        return Err(NoSuchBreakpoint);
    }

    Ok(())
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
) -> Result<(), DataBreakpointError> {
    let debugger = &mut state.debugger;
    let kind = match target {
        DataTarget::Clear => {
            let current_address = debugger
                .data_breakpoint
                .map_or(0, |current| current.address);
            if current_address == address {
                debugger.data_breakpoint = None;
                backend.set_data_breakpoint_register(0);
            }

            return Ok(());
        }
        DataTarget::Set(kind) => kind,
    };

    if (address & 7).wrapping_add(size) > 8 {
        return Err(DataBreakpointError::Unaligned);
    }

    if let Some(current) = debugger
        .data_breakpoint
        .filter(|current| current.address != 0)
    {
        if Some(current.kind) == kind && current.address == address && current.size == size {
            // The monitor reprograms the registers with 0 here.
            backend.set_data_breakpoint_register(0);
            return Ok(());
        }

        return Err(DataBreakpointError::InUse);
    }

    let Some(kind) = kind else {
        return Err(DataBreakpointError::UnsupportedKind);
    };

    let breakpoint = DataBreakpoint {
        address,
        size,
        kind,
    };
    debugger.data_breakpoint = Some(breakpoint);
    backend.set_data_breakpoint_register(breakpoint.register());

    Ok(())
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
pub(super) fn is_breakpoint(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(address) = util::required_dword(invocation, "addr") else {
        return Err(util::MISSING);
    };

    let kind = breakpoint_kind(invocation.state, address);
    invocation.set_text(format_args!("type={kind}"));

    Ok(Reply::Ok)
}

/// Send the held `break now` reply once its thread no longer waits at the
/// trap.
pub(super) fn send_held_reply(
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
        let _ = send_status(
            state,
            backend,
            network,
            held.socket,
            held.result,
            held.text.as_bytes(),
        );
    }
}

/// A connection closed: a reply held for it is dropped.
pub(crate) fn connection_closed(state: &mut ServerState, socket: SocketId) {
    if state
        .debugger
        .held_reply
        .as_ref()
        .is_some_and(|held| held.socket == socket)
    {
        state.debugger.held_reply = None;
    }
}
