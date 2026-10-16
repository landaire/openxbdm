//! The server driven through its public API by an SMB 2 and 3 client over
//! an in-memory backend.

mod backend;
mod client;
mod ntlm;

mod compound;
mod directory;
mod files;
mod info;
mod ipc;
mod lifecycle;
mod locks;
mod malformed;
mod negotiate;
mod notify;
mod session;
mod smb3;
mod tree;
