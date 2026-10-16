//! Clean-room XBDM server: command dispatch, transfers, and notifications.
//!
//! The crate is `no_std` and allocation-free. A platform supplies a
//! [`Backend`] for console services and a [`Network`] for sockets, and
//! reports socket readiness to a [`Server`].
#![no_std]
#![forbid(unsafe_code)]
// State types are built by `const fn new()` so the platform can keep the
// server in a static; `Default` is implemented only where a caller needs it.
#![allow(clippy::new_without_default)]

pub mod access;
pub mod backend;
pub mod commands;
pub mod continuation;
pub mod invocation;
pub mod network;
pub mod notify;
pub mod processors;
pub mod registry;
pub mod reply;
pub mod server;
#[cfg(feature = "smb")]
pub mod smb;
pub mod state;
pub mod text;
pub mod transfer_blocks;

pub use access::Access;
pub use backend::Backend;
pub use backend::Platform;
pub use invocation::ConnectionIndex;
pub use network::Network;
pub use network::SocketId;
pub use server::Outcome;
pub use server::Server;
