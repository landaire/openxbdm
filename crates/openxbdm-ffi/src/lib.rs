//! C/C++ FFI for the `openxbdm-client` crate via [diplomat].
//!
//! Exposes a synchronous XBDM client plus the wire-protocol helpers. The
//! async runtime is embedded; callers need not know tokio exists.
//!
//! The C++ wrappers are generated, not committed: `buck2 build
//! //bindings:cpp` runs `openxbdm-ffi-bindgen` on this crate. The release
//! archives hold them with the static and shared libraries.
//!
//! Each bridge module holds its diplomat types in an inline `ffi` module,
//! because diplomat only parses `#[diplomat::bridge]` on inline modules and
//! requires a type's impls to sit in the same module as the type.

mod blocking;
mod buffers;
mod client;
mod debugger;
mod discovery;
mod error;
mod filesystem;
mod memory;
mod network;
mod notification;
mod performance;
mod process;
mod protocol;
mod screenshot;
mod time;
