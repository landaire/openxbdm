//! SMB 2 and SMB 3 file server (MS-SMB2 dialects 2.0.2, 2.1, 3.0, 3.0.2,
//! and 3.1.1).
//!
//! The crate is `no_std`, allocation-free, and performs no I/O. A platform
//! reads each message with the framing of [`transport`], hands it to the
//! [`Connection`] of its transport connection together with the
//! [`server::Server`] its connections share, sends the reply, and supplies
//! a [`Backend`] for files, shares, accounts, time, and randomness.
//! Requests that complete later (change notifications and blocking
//! byte-range locks) are answered by [`Connection::poll`].
//! `examples/serve_directory.rs` serves host directories with blocking
//! sockets.
//!
//! ```text
//! server.configure(config)
//! loop {
//!     read 4 header bytes; transport::parse_header(header, buffer.len())
//!     read the message into request
//!     match connection.handle(&mut server, backend, &mut request[..length], &mut response) {
//!         Reply::Send { length } => send response[..length],
//!         Reply::Nothing => {}
//!         Reply::Disconnect => break,
//!     }
//!     on a timer or when connection.wants_poll(&server):
//!         connection.poll(&mut server, backend, &mut response), sent the same way
//! }
//! connection.close(&mut server, backend)
//! ```
//!
//! Supported:
//! - Negotiation from SMB 2 NEGOTIATE or an SMB 1 multi-protocol
//!   negotiate, SMB 3.1.1 negotiate contexts and preauthentication
//!   integrity, FSCTL_VALIDATE_NEGOTIATE_INFO, compound requests, and the
//!   credit window.
//! - NTLMv2 logon inside SPNEGO or as raw NTLMSSP, with key exchange,
//!   MIC, and mechListMIC; guest and anonymous logons by policy;
//!   re-authentication.
//! - Signing with HMAC-SHA256, AES-128-CMAC, or AES-128-GMAC, optional or
//!   required; encryption with AES-128-CCM or AES-128-GCM, on request of
//!   the client or required by the server.
//! - Disk shares with create, read, write, flush, directory queries with
//!   NT wildcards, file, file system and security information, rename,
//!   delete, and size changes; `IPC$` with the `srvsvc` pipe for share
//!   enumeration.
//! - Byte-range locks and change notification, kept by the server for the
//!   opens of its connections. Changes made outside the server are found
//!   by periodic directory scans and reported as STATUS_NOTIFY_ENUM_DIR.
//!
//! Not supported: AES-256 ciphers, compression, oplocks and leases,
//! durable handles, multichannel, DFS, extended attributes, named
//! streams, short names, and server-side copy. Requests for them fail
//! with the status a server without the feature returns.
#![no_std]
#![forbid(unsafe_code)]
#![allow(clippy::new_without_default)]

pub mod auth;
pub mod backend;
pub mod crypto;
pub mod fs;
pub mod path;
pub mod pattern;
pub mod rpc;
pub mod server;
pub mod status;
pub mod transport;
pub mod utf16;

pub use backend::Backend;
pub use server::Connection;
pub use server::Reply;
pub use server::ServerConfig;
pub use status::NtStatus;
