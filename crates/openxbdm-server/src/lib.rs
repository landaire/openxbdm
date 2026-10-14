//! Clean-room XBDM server: command dispatch, transfers, and notifications.
//!
//! The crate is `no_std` and allocation-free. A platform supplies a
//! [`Backend`] for console services and a [`Network`] for sockets, and
//! reports socket readiness to a [`Server`].
#![no_std]
#![forbid(unsafe_code)]

pub mod access;
pub mod backend;
pub mod commands;
pub mod continuation;
pub mod invocation;
pub mod network;
pub mod notify;
pub mod processors;
pub mod registry;
pub mod server;
pub mod state;
pub mod text;

pub use access::Access;
pub use backend::Backend;
pub use backend::Platform;
pub use invocation::ConnectionIndex;
pub use network::Network;
pub use network::SocketId;
pub use server::Outcome;
pub use server::Server;
