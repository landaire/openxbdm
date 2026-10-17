//! XBDM wire-protocol definitions shared by the openxbdm client and server.
#![no_std]
#![forbid(unsafe_code)]

pub mod auth;
pub mod line;
pub mod status;
pub mod value;

/// TCP port of the command server and UDP port of name discovery.
pub const XBDM_PORT: u16 = 730;
