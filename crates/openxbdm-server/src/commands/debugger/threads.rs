//! Thread enumeration, information, and run control commands.

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Win32Error;

use super::Continuation;
use super::ExitStatus;
use super::StopReason;
use super::StoppedThreadError;
use super::ThreadId;
use super::ThreadInfo;
use super::ThreadName;
use super::events;
use super::kd;
use super::start_transfer;
use crate::backend::Backend as AnyBackend;
use crate::commands::filesystem::Backend as FilesystemBackend;
use crate::commands::services::ThreadHandle;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::network::Network;
use crate::notify::ExecutionState;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::text::LineText;
use crate::transfer_blocks::TransferBlock;

/// Thread identifiers `threads` can report.
pub const THREAD_LIST_CAPACITY: usize = 0x100;

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

pub(super) fn required_thread(invocation: &mut Invocation<'_>) -> Option<ThreadId> {
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
) -> Result<(), StoppedThreadError> {
    events::continue_thread(state, backend, network, thread, pass_exception)
}

/// `continue thread= [exception]`.
pub(super) fn continue_thread(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(thread) = required_thread(invocation) else {
        return Err(util::MISSING);
    };

    let pass_exception = invocation.line.has("exception");
    continue_stopped_thread(
        invocation.state,
        invocation.backend,
        invocation.network,
        thread,
        pass_exception,
    )?;

    Ok(Reply::Ok)
}

/// `suspend thread=`.
pub(super) fn suspend_thread(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(thread) = required_thread(invocation) else {
        return Err(util::MISSING);
    };

    invocation.backend.suspend_thread(thread)?;

    Ok(Reply::Ok)
}

/// `resume thread=`.
pub(super) fn resume_thread(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(thread) = required_thread(invocation) else {
        return Err(util::MISSING);
    };

    invocation.backend.resume_thread(thread)?;

    Ok(Reply::Ok)
}

/// What a thread is stopped at (stock export 22, 0x91f26058).
pub fn stop_reason(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    thread: ThreadId,
) -> Result<StopReason, StoppedThreadError> {
    events::stop_reason(state, backend, thread)
}

/// `isstopped thread=`: the event the thread is stopped at.
pub(super) fn is_stopped(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(thread) = required_thread(invocation) else {
        return Err(util::MISSING);
    };

    let reason = stop_reason(invocation.state, invocation.backend, thread)?;
    invocation.text.clear();
    events::stop_description(invocation.backend, &reason, invocation.text);

    Ok(Reply::Ok)
}

/// `threads`: identifiers of the debuggable threads as signed decimal
/// lines, in reverse enumeration order.
pub(super) fn threads(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(socket) = invocation.session.as_ref().map(|session| session.socket()) else {
        return Err(CommandError::Fail);
    };

    let Some(list) = invocation.state.transfer_blocks.acquire(
        invocation.backend,
        socket,
        THREAD_LIST_CAPACITY as u32 * 4,
    ) else {
        return Err(CommandError::OutOfMemory);
    };

    let mut ids = [ThreadId(0); THREAD_LIST_CAPACITY];
    let count = if invocation.backend.execution_state() == ExecutionState::Pending {
        0
    } else {
        let Some(count) = invocation.backend.thread_ids(&mut ids) else {
            // SAFETY: the transfer was not started, so this command holds
            // the only copy.
            unsafe {
                invocation
                    .state
                    .transfer_blocks
                    .release(invocation.backend, list)
            };
            return Err(CommandError::Unexpected);
        };
        count
    };

    let words = invocation
        .state
        .transfer_blocks
        .bytes(invocation.backend, list)
        .as_chunks_mut::<4>()
        .0;
    for (word, id) in words.iter_mut().zip(&ids[..count]) {
        *word = id.0.to_ne_bytes();
    }

    start_transfer(
        invocation,
        Continuation::Threads {
            list,
            remaining: count as u16,
        },
    );
    invocation.set_text(format_args!("thread list follows"));

    Ok(Reply::Multiline)
}

pub(super) fn thread_lines(
    list: TransferBlock,
    remaining: &mut u16,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    if *remaining == 0 {
        // SAFETY: the transfer ends with this result, so the server drops the
        // continuation, the only other holder.
        unsafe { cx.state.transfer_blocks.release(cx.backend, list) };
        return Err(CommandError::EndOfData);
    }

    let ids = cx
        .state
        .transfer_blocks
        .bytes(cx.backend, list)
        .as_chunks::<4>()
        .0;
    let mut output = BinaryWriter {
        buffer: cx.binary,
        len: 0,
    };

    // Leave room for one more line in the raw buffer.
    while *remaining > 0 && output.len + 16 <= output.buffer.len() {
        *remaining -= 1;
        let id = u32::from_ne_bytes(ids[usize::from(*remaining)]) as i32;
        let _ = write!(output, "{id}\r\n");
    }

    cx.binary_len = output.len;

    Ok(Reply::Ok)
}

/// `threadinfo thread=`.
pub(super) fn thread_info(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(ErrorCode::Undefined.into());
    }

    let Some(thread) = required_thread(invocation) else {
        return Err(util::MISSING);
    };

    let info = invocation.backend.thread_info(thread)?;
    start_transfer(invocation, Continuation::ThreadInfo { info, sent: false });
    invocation.set_text(format_args!("thread info follows"));

    Ok(Reply::Multiline)
}

/// Send the single `threadinfo` line.
pub(super) fn thread_info_lines(
    info: &ThreadInfo,
    sent: &mut bool,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    if *sent {
        return Err(CommandError::EndOfData);
    }

    *sent = true;
    thread_info_line(info, cx.line);

    Ok(Reply::Ok)
}

fn thread_info_line(info: &ThreadInfo, line: &mut LineText) {
    /// Thread stack slack the monitor reports.
    const THREAD_SLACK: u32 = 0x540;

    let suspend = i32::from(info.suspend_count) - i32::from(info.monitor_suspended);
    // An unnamed thread reports a name address and length of 0.
    let name = info.name.unwrap_or(ThreadName {
        address: 0,
        length: 0,
    });
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
}

/// `threadstat handle=`.
pub(super) fn thread_status(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line;
    let Some(handle) = kd::flag_number(&line, invocation.buffer, "handle") else {
        return Err(ErrorCode::BadParameter.into());
    };

    match invocation.backend.thread_exit_status(ThreadHandle(handle)) {
        Ok(ExitStatus(code)) => {
            invocation.set_text(format_args!("Exit Code 0x{code:x}"));
        }
        Err(error) => {
            // The kernel's translation; 0 (ERROR_SUCCESS) prints as is.
            let code =
                FilesystemBackend::dos_error(invocation.backend, error).map_or(0, Win32Error::code);
            invocation.set_text(format_args!("Error 0x{code:x}"));
        }
    }

    Ok(Reply::Ok)
}

/// `crashdump`: reply first, then write a dump of the calling thread.
pub(super) fn crash_dump(invocation: &mut Invocation<'_>) -> CommandResult {
    let _ = invocation.send_line(b"200- OK");
    invocation.backend.crash_dump();

    Ok(Reply::Sent)
}
