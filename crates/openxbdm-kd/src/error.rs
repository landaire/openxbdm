//! Client errors.

use openxbdm_kd_core::DecodeError;
use openxbdm_kd_core::NtStatus;
use openxbdm_kd_core::manipulate::ApiNumber;
use openxbdm_kd_core::session::SessionError;

#[derive(Debug, thiserror::Error)]
pub enum KdError {
    #[error("transport I/O failed")]
    Io(#[from] std::io::Error),
    #[error("malformed datagram")]
    Decode(#[from] DecodeError),
    #[error("packet session")]
    Session(#[from] SessionError),
    #[error("no {waiting_for} within {seconds} s")]
    Timeout {
        waiting_for: &'static str,
        seconds: u64,
    },
    #[error("{api:?} failed with status {status}")]
    Status { api: ApiNumber, status: NtStatus },
    #[error("reply for {actual:?} while waiting for {expected:?}")]
    UnexpectedReply {
        expected: ApiNumber,
        actual: ApiNumber,
    },
    #[error("the target is running; this request needs a stopped target")]
    NotStopped,
    #[error("{api:?} transferred {actual} of {requested} bytes")]
    ShortTransfer {
        api: ApiNumber,
        requested: usize,
        actual: usize,
    },
    #[error("breakpoint address {address:#x} is not 4-byte aligned")]
    UnalignedBreakpoint { address: u64 },
    #[error("the kernel rejected a breakpoint at {address:#x}")]
    BreakpointRejected { address: u64 },
}
