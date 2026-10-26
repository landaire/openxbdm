//! XBDM wire-protocol definitions shared by the openxbdm client and server.
#![no_std]
#![forbid(unsafe_code)]

pub mod auth;
pub mod line;
mod network;
pub mod status;
pub mod value;

pub use self::network::XBDM_PORT;
