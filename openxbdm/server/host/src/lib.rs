//! Host XBDM server: the openxbdm server engine over std TCP sockets with a
//! simulated console.
//!
//! The engine is single-threaded; each connection has a thread that waits
//! for readability without holding the lock and then reports the event.
//! SMB connections take the SMB service's lock before the host's.

pub mod backend;
mod host;
pub mod network;

pub use self::host::Host;
pub use self::host::SharedHost;
