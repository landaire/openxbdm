//! Codec and session state for the kernel debugger network transport
//! ("kdnet") of the Xbox 360 development kernel.
//!
//! The kernel exchanges UDP datagrams with one host. Data packets carry a
//! 16-byte little-endian header and a checksummed payload; control packets
//! acknowledge, request a resend, or reset packet numbering. See
//! `docs/re-notes/kd.md` for the wire layouts and kernel addresses.
//!
//! Everything here is allocation-free and performs no I/O.
#![no_std]
#![forbid(unsafe_code)]

pub mod context;
pub mod debug_io;
pub mod error;
pub mod file_io;
pub mod manipulate;
pub mod message;
pub mod packet;
pub mod session;
pub mod state_change;
pub mod status;
mod wire;

pub use self::error::DecodeError;
pub use self::error::EncodeError;
pub use self::status::NtStatus;
