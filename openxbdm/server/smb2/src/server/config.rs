//! Server settings and the table limits of a connection.

use core::time::Duration;

use crate::fs::FileTime;
use crate::server::scan::SCAN_HANDLES;

/// Sessions per connection.
pub const MAX_SESSIONS: usize = 4;
/// Tree connects per connection.
pub const MAX_TREES: usize = 16;
/// Opens per connection.
pub const MAX_OPENS: usize = 32;
/// Backend handles a connection holds at most: its opens and the
/// directories a change scan reads.
pub const MAX_HANDLES: usize = MAX_OPENS + SCAN_HANDLES;
/// Named pipe opens per connection.
pub const MAX_PIPES: usize = 2;
/// Directory opens per connection with a search pattern other than `*`.
pub const MAX_PATTERNS: usize = 4;
/// Requests per connection waiting for a later reply.
pub const MAX_PENDING: usize = 8;

/// A GUID in its wire layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Guid(pub [u8; 16]);

/// Settings shared by every connection of a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerConfig {
    pub guid: Guid,
    /// When the server started.
    pub start_time: FileTime,
    /// Require signed messages on every authenticated session.
    pub signing_required: bool,
    /// Capacity of each request and response buffer the platform passes
    /// to [`Connection::handle`](crate::Connection::handle) and
    /// [`Connection::poll`](crate::Connection::poll), transport header
    /// included.
    pub buffer_size: usize,
    /// How often a directory with a change notification is scanned for
    /// changes made outside the server; `None` reports only changes made
    /// through the server.
    pub change_scan_interval: Option<Duration>,
    /// Require encrypted messages on every authenticated session of an SMB
    /// 3 dialect whose client supports encryption.
    pub encrypt_data: bool,
}

impl ServerConfig {
    /// MaxTransactSize, MaxReadSize, and MaxWriteSize.
    pub const fn max_io(&self) -> usize {
        // Largest read, write, or transaction payload.
        const MAX_IO: usize = 0x1_0000;
        // Response buffer room kept for the headers of a compound chain
        // around a read of `MAX_IO` bytes.
        const COMPOUND_RESERVE: usize = 0x400;

        let room = self.buffer_size.saturating_sub(COMPOUND_RESERVE);
        if room < MAX_IO { room } else { MAX_IO }
    }
}
