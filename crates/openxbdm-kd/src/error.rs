//! Client and command errors.

use std::net::AddrParseError;
use std::num::ParseIntError;
use std::num::TryFromIntError;

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
    #[error(
        "the kernel did not switch to processor {requested}; processor {stopped} reported the stop"
    )]
    SwitchRejected { requested: u16, stopped: u16 },
    #[error("the debugger named thread {thread}, which is no processor")]
    NoSuchProcessor { thread: usize },
    #[error("the kernel reports {reported} processors, outside 1 to 6")]
    ProcessorCount { reported: u32 },
}

/// A command-line or interactive command value that does not parse.
#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    #[error("{text:?} is not an address: {error}")]
    Address { text: String, error: AddrParseError },
    #[error("{text:?}: {error}")]
    Integer { text: String, error: ParseIntError },
    #[error("{error}")]
    Length { error: TryFromIntError },
    #[error("{text:?} is not an even number of hex digits")]
    OddHexLength { text: String },
    #[error("{text:?} is not hex")]
    NotHex { text: String },
    #[error("{text:?} is not CONSOLE_PATH=LOCAL_PATH")]
    NotFileMapping { text: String },
    #[error("{text:?} has an empty path")]
    EmptyMappingPath { text: String },
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("kernel debugger")]
    Kd(#[from] KdError),
    #[error("I/O")]
    Io(#[from] std::io::Error),
    #[error("the kernel did not stop within {seconds} s")]
    NoStop { seconds: u64 },
    #[error("GDB session failed: {message}")]
    Gdb { message: String },
    #[error(transparent)]
    InvalidValue(#[from] ValueError),
    #[error("unrecognized command {line:?}")]
    UnrecognizedCommand { line: String },
}
