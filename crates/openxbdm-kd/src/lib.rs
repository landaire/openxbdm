//! Kernel debugger client for the Xbox 360 kdnet transport, with a GDB
//! remote serial protocol server.

pub mod client;
pub mod describe;
pub mod error;
pub mod gdb;
pub mod host_files;
pub mod link;
mod ops;
pub mod step;
pub mod stop;
pub mod transport;

pub use client::KdClient;
pub use error::KdError;
pub use link::FileOpenAnswer;
pub use link::Notification;
pub use stop::StopReport;
