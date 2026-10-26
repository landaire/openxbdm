//! `getcontext` and `setcontext`.

use super::Context;
use super::ContextFlags;
use super::Continuation;
use super::context::CONTEXT_SIZE;
use super::context::ContextLine;
use super::context::apply_parameters;
use super::start_transfer;
use super::threads::required_thread;
use crate::backend::Backend as AnyBackend;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::text::Text;
use crate::transfer_blocks::TransferBlock;
use crate::transfer_blocks::TransferBlocks;

/// `getcontext thread= [control] [int] [fp] [vr] [full]`.
pub(super) fn get_context(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Pool bytes of a `getcontext` copy (stock 0x91f482b0 allocates 0xa50).
    const SNAPSHOT_POOL_SIZE: u32 = 0xa50;

    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let Some(thread) = required_thread(invocation) else {
        return Err(util::MISSING);
    };

    let line = invocation.line;
    let mut flags = ContextFlags::empty();
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

    // Not a struct update: one from this large constant leaves an unused
    // copy of it in the console image.
    let mut context = Context::EMPTY;
    context.flags = flags;
    invocation.backend.thread_context(thread, &mut context)?;

    let Some(socket) = invocation.session.as_ref().map(|session| session.socket()) else {
        return Err(CommandError::Fail);
    };

    let Some(snapshot) =
        invocation
            .state
            .transfer_blocks
            .acquire(invocation.backend, socket, SNAPSHOT_POOL_SIZE)
    else {
        return Err(CommandError::OutOfMemory);
    };

    if let Some(bytes) = snapshot_bytes(
        &mut invocation.state.transfer_blocks,
        invocation.backend,
        snapshot,
    ) {
        context.encode(bytes);
    }

    start_transfer(
        invocation,
        Continuation::Context {
            snapshot,
            position: 0,
        },
    );

    Ok(Reply::Multiline)
}

/// Emit context lines from the copy the command made; the last call frees
/// it.
pub(super) fn context_lines(
    snapshot: TransferBlock,
    position: &mut usize,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    // A missing copy reads as a context without groups, which ends the
    // transfer.
    let context = snapshot_bytes(&mut cx.state.transfer_blocks, cx.backend, snapshot)
        .map(|bytes| Context::decode(bytes))
        .unwrap_or_default();
    if ContextLine::first_from(*position, context.flags).is_none() {
        // SAFETY: the transfer ends with this result, so the server drops the
        // continuation, the only other holder.
        unsafe { cx.state.transfer_blocks.release(cx.backend, snapshot) };
        return Err(CommandError::EndOfData);
    }

    let output = &mut *cx.binary;
    let limit = output.len().saturating_sub(0x40);
    let mut length = 0;
    while length < limit {
        let Some((index, line)) = ContextLine::first_from(*position, context.flags) else {
            break;
        };

        let mut text = Text::<0x80>::new();
        line.write(&context, &mut text);
        let _ = text.push_bytes(b"\r\n");
        let end = length + text.as_bytes().len();
        output[length..end].copy_from_slice(text.as_bytes());
        length = end;
        *position = index + 1;
    }

    cx.binary_len = length;

    Ok(Reply::Ok)
}

/// `setcontext thread= <Reg>=<value>...`.
pub(super) fn set_context(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(thread) = required_thread(invocation) else {
        return Err(util::MISSING);
    };

    let mut context = Context::EMPTY;
    context.flags = ContextFlags::FULL;
    invocation.backend.thread_context(thread, &mut context)?;
    apply_parameters(&invocation.line, &mut context);

    // The read replaced the flags with the groups it returned.
    context.flags = ContextFlags::FULL;
    invocation.backend.set_thread_context(thread, &context)?;

    Ok(Reply::Ok)
}

fn snapshot_bytes<'a>(
    blocks: &'a mut TransferBlocks,
    backend: &'a mut dyn AnyBackend,
    snapshot: TransferBlock,
) -> Option<&'a mut [u8; CONTEXT_SIZE]> {
    blocks
        .bytes(backend, snapshot)
        .get_mut(..CONTEXT_SIZE)
        .and_then(|bytes| bytes.try_into().ok())
}
