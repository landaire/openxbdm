//! `rpc`: call a function on the console with arguments uploaded by the
//! client and stream back the call buffer.
//!
//! The call buffer, at the address reported in `204- buf_addr=`, is a
//! sequence of big-endian quadwords: +0x00 result HRESULT, +0x08 return
//! value, +0x10 last error (requested by 1), +0x18 flags (bit 0: the
//! return value is a double), +0x20 integer argument count, +0x28 double
//! argument count, +0x30 module name pointer or 0, +0x38 function address
//! or export ordinal, +0x40 the integer arguments then the doubles.

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;

use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;

use super::Continuation as SessionContinuation;

/// The only protocol version the monitor accepts.
const RPC_VERSION: u32 = 4;
/// Processor of the call thread when `processor` is absent.
const DEFAULT_PROCESSOR: u32 = 5;
/// Buffer the monitor copies `thread=` into.
const THREAD_NAME_CAPACITY: usize = 0x40;
/// Sent while the call has not finished: the quadword 0x3e5.
const PENDING_MARKER: [u8; 8] = [0, 0, 0, 0, 0, 0, 0x03, 0xe5];
/// Sent once when the call has finished, before the buffer.
const DONE_MARKER: [u8; 8] = [0; 8];

/// A call block owned by the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcCall(pub u32);

/// Thread context a call runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcContext {
    System,
    Title,
}

/// Where a call runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcThread<'a> {
    /// A new suspended thread with this affinity; the low six bits of the
    /// number select the processor bit.
    Own { processor: u32 },
    /// The title thread with this name runs the call when it drains the
    /// queue of named calls.
    Named(&'a [u8]),
}

/// Why a call block could not be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcCreateError {
    OutOfMemory,
    /// The call thread could not be created.
    Thread(NtStatus),
}

/// Platform services of `rpc`.
pub trait RpcBackend {
    /// Allocate a call block with a `size`-byte buffer and, for
    /// [`RpcThread::Own`], create its suspended thread.
    fn rpc_create(
        &mut self,
        size: u32,
        context: RpcContext,
        thread: RpcThread<'_>,
    ) -> Result<RpcCall, RpcCreateError>;
    /// Console address of the call buffer.
    fn rpc_buffer_address(&mut self, call: RpcCall) -> u32;
    /// Store uploaded bytes at `offset` in the call buffer.
    fn rpc_write(&mut self, call: RpcCall, offset: u32, data: &[u8]);
    /// The upload is complete: resume the call thread or queue the call
    /// for its named thread.
    fn rpc_start(&mut self, call: RpcCall);
    /// The upload was abandoned: the call is discarded without running.
    fn rpc_abort(&mut self, call: RpcCall);
    /// Wait up to 100 ms for the call to finish; returns whether it has.
    fn rpc_wait(&mut self, call: RpcCall) -> bool;
    /// Copy bytes of the call buffer at `offset` into `output`.
    fn rpc_read(&mut self, call: RpcCall, offset: u32, output: &mut [u8]);
    /// Release the call block. A call that is still running releases it
    /// when it finishes.
    fn rpc_release(&mut self, call: RpcCall);
}

/// Progress of an `rpc` transfer.
#[derive(Debug)]
pub enum RpcTransfer {
    /// 204 upload of the call buffer.
    Upload {
        call: RpcCall,
        size: u32,
        received: u32,
    },
    /// 203 stream: markers until the call finishes, then the buffer.
    Stream {
        call: RpcCall,
        size: u32,
        phase: StreamPhase,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPhase {
    /// Nothing finished has been reported yet.
    Waiting,
    /// The finished marker was sent; the buffer follows from `offset`.
    Buffer { offset: u32 },
    /// Everything was sent.
    Sent,
}

/// `rpc version=4 (system|title) buf_size=<dword> [processor=<dword>]
/// [thread=<name>]`.
pub(super) fn rpc(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(version) = invocation
        .line
        .param("version")
        .and_then(|value| value.dword())
    else {
        invocation.set_text(format_args!(
            "error=Version is not specified, expecting major version {RPC_VERSION}"
        ));
        return Hresult::OK;
    };
    if version != RPC_VERSION {
        invocation.set_text(format_args!(
            "error=Version mismatch, expected {RPC_VERSION} but got {}",
            version as i32
        ));
        return Hresult::OK;
    }
    let context = if invocation.line.has("system") {
        RpcContext::System
    } else if invocation.line.has("title") {
        RpcContext::Title
    } else {
        return Hresult::from_error_code(ErrorCode::BAD_PARAMETER);
    };
    let Some(size) = invocation
        .line
        .param("buf_size")
        .and_then(|value| value.dword())
    else {
        return Hresult::from_error_code(ErrorCode::BAD_PARAMETER);
    };
    // An absent or malformed value selects the default.
    let processor = invocation
        .line
        .param("processor")
        .and_then(|value| value.dword())
        .unwrap_or(DEFAULT_PROCESSOR);
    let mut name = [0u8; THREAD_NAME_CAPACITY];
    let name = match invocation.line.param("thread") {
        Some(value) => value.copy_into(&mut name),
        None => &[],
    };
    let thread = if name.is_empty() {
        RpcThread::Own { processor }
    } else {
        RpcThread::Named(name)
    };
    let call = match invocation.backend.rpc_create(size, context, thread) {
        Ok(call) => call,
        Err(RpcCreateError::OutOfMemory) => {
            return Hresult::from_error_code(ErrorCode::OUT_OF_MEMORY);
        }
        Err(RpcCreateError::Thread(status)) => return Hresult(status.0 | 0x1000_0000),
    };
    let address = invocation.backend.rpc_buffer_address(call);
    let Some(session) = invocation.session.as_deref_mut() else {
        invocation.backend.rpc_abort(call);
        return Hresult::FAIL;
    };
    session.receive_remaining = Some(size);
    session.continuation =
        AnyContinuation::Session(SessionContinuation::Rpc(RpcTransfer::Upload {
            call,
            size,
            received: 0,
        }));
    invocation.text.clear();
    let _ = write!(invocation.text, "buf_addr={address:08X}");
    Hresult::SEND_BINARY
}

pub(super) fn resume(transfer: &mut RpcTransfer, cx: &mut ContinuationContext<'_>) -> Hresult {
    match transfer {
        RpcTransfer::Upload {
            call,
            size,
            received,
        } => upload(*call, *size, received, cx),
        RpcTransfer::Stream { call, size, phase } => stream(*call, *size, phase, cx),
    }
}

fn upload(
    call: RpcCall,
    size: u32,
    received: &mut u32,
    cx: &mut ContinuationContext<'_>,
) -> Hresult {
    let remaining = cx.session.receive_remaining.unwrap_or(0);
    if cx.received.is_empty() && remaining != 0 {
        // The connection closed before the buffer arrived.
        cx.session.receive_remaining = Some(0);
        cx.backend.rpc_abort(call);
        return Hresult::OK;
    }
    cx.backend.rpc_write(call, *received, cx.received);
    let count = cx.received.len() as u32;
    *received += count;
    let remaining = remaining.saturating_sub(count);
    cx.session.receive_remaining = Some(remaining);
    if remaining != 0 {
        return Hresult::OK;
    }
    cx.backend.rpc_start(call);
    let next = RpcTransfer::Stream {
        call,
        size,
        phase: StreamPhase::Waiting,
    };
    cx.session.continuation = AnyContinuation::Session(SessionContinuation::Rpc(next));
    Hresult::BINARY
}

fn stream(
    call: RpcCall,
    size: u32,
    phase: &mut StreamPhase,
    cx: &mut ContinuationContext<'_>,
) -> Hresult {
    if cx.aborted {
        cx.backend.rpc_release(call);
        return Hresult::END_OF_DATA;
    }
    match *phase {
        StreamPhase::Waiting => {
            let marker = if cx.backend.rpc_wait(call) {
                *phase = if size == 0 {
                    StreamPhase::Sent
                } else {
                    StreamPhase::Buffer { offset: 0 }
                };
                DONE_MARKER
            } else {
                if size == 0 {
                    *phase = StreamPhase::Sent;
                }
                PENDING_MARKER
            };
            cx.binary[..8].copy_from_slice(&marker);
            cx.binary_len = 8;
            Hresult::OK
        }
        StreamPhase::Buffer { offset } => {
            // The monitor waits before sending the buffer; the call has
            // finished, so the wait returns at once.
            if offset == 0 {
                cx.backend.rpc_wait(call);
            }
            let count = (size - offset).min(cx.binary.len() as u32);
            cx.backend
                .rpc_read(call, offset, &mut cx.binary[..count as usize]);
            cx.binary_len = count as usize;
            *phase = if offset + count == size {
                StreamPhase::Sent
            } else {
                StreamPhase::Buffer {
                    offset: offset + count,
                }
            };
            Hresult::OK
        }
        StreamPhase::Sent => {
            cx.backend.rpc_release(call);
            Hresult::END_OF_DATA
        }
    }
}
