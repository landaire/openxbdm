//! Connection state machine: one [`Connection`] per transport connection,
//! and one [`Server`] shared by them.
//!
//! [`Connection::handle`] takes one transport message, which holds a
//! request or a compound chain of requests, and writes the replies into
//! the platform's response buffer. [`Connection::poll`] writes replies to
//! requests that completed later: change notifications, byte-range locks
//! that waited, and requests ended by a cancel or a close.

mod config;
mod connection;
mod create;
mod credits;
mod directory;
mod error;
mod info;
mod io;
mod ioctl;
mod lock;
mod negotiate;
mod notify;
mod pending;
mod request;
mod scan;
mod security;
mod session;
mod shared;
mod tables;
mod tree;
mod wire;

pub use self::config::Guid;
pub use self::config::MAX_HANDLES;
pub use self::config::MAX_OPENS;
pub use self::config::MAX_PATTERNS;
pub use self::config::MAX_PENDING;
pub use self::config::MAX_PIPES;
pub use self::config::MAX_SESSIONS;
pub use self::config::MAX_TREES;
pub use self::config::ServerConfig;
pub use self::connection::Connection;
pub use self::connection::Reply;
pub use self::shared::ConnectionId;
pub use self::shared::SUPERSEDED_QUEUE;
pub use self::shared::Server;
pub use self::shared::SupersededSession;
pub use self::tables::SessionId;
pub use self::wire::Dialect;
pub use self::wire::FileId;
