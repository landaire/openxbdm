//! What a command handler receives.

use openxbdm_core::line::CommandLine;

use crate::access::Access;
use crate::backend::Backend;
use crate::commands::system::RebootKind;
use crate::continuation::Continuation;
use crate::network::NetError;
use crate::network::Network;
use crate::network::SocketId;
use crate::network::send_line;
use crate::state::ServerState;
use crate::text::ResponseText;

/// Index of a connection slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionIndex(pub u8);

/// Target of a `dedicate` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedicateTarget {
    /// Return the connection to the main server context.
    Main,
    /// Dedicate the connection to the command processor in this slot.
    Processor(u8),
}

/// A change to the connection that the server applies after the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRequest {
    /// Close the connection.
    Close,
    /// Release the connection slot without closing its socket; the socket
    /// now belongs to the notification subsystem.
    ReleaseSocket,
    /// Dedicate the connection; the server sends `205- connection dedicated`.
    Dedicate(DedicateTarget),
    /// Restart the console after writing settings, announcing
    /// `execution rebooting`, and closing every connection and channel.
    Reboot(RebootKind),
}

/// Per-connection state visible to handlers and continuations.
#[derive(Debug)]
pub struct Session {
    pub(crate) index: ConnectionIndex,
    pub(crate) socket: SocketId,
    /// Privileges of the connection.
    pub access: Access,
    /// Session key established by a completed `keyxchg`.
    pub session_key: Option<openxbdm_core::auth::SessionKey>,
    /// Lock-mode challenge sent in the banner.
    pub nonce: [u32; 2],
    /// Continuation of a 202, 203, or 204 transfer.
    pub continuation: Continuation,
    /// Bytes still expected in a 204 upload. The continuation decrements it.
    pub receive_remaining: Option<u32>,
    pub(crate) request: Option<SessionRequest>,
}

impl Session {
    pub(crate) fn new(
        index: ConnectionIndex,
        socket: SocketId,
        access: Access,
        nonce: [u32; 2],
    ) -> Self {
        Self {
            index,
            socket,
            access,
            session_key: None,
            nonce,
            continuation: Continuation::None,
            receive_remaining: None,
            request: None,
        }
    }

    pub fn index(&self) -> ConnectionIndex {
        self.index
    }

    pub fn socket(&self) -> SocketId {
        self.socket
    }

    pub fn request(&mut self, request: SessionRequest) {
        self.request = Some(request);
    }
}

/// A command being executed.
pub struct Invocation<'a> {
    /// The full command line, including the command word.
    pub line: CommandLine<'a>,
    /// The buffer holding the line: the line, a NUL in place of its CR, then
    /// the bytes that followed in the receive buffer (pipelined or stale).
    /// Handlers that read values at fixed offsets see these bytes.
    pub buffer: &'a [u8],
    /// Text sent after `NNN- `; empty means the default text for the result.
    pub text: &'a mut ResponseText,
    /// The connection, or `None` for settings-file lines.
    pub session: Option<&'a mut Session>,
    pub state: &'a mut ServerState,
    pub backend: &'a mut dyn Backend,
    pub network: &'a mut dyn Network,
}

impl Invocation<'_> {
    /// Privileges in effect: the connection's, or all for settings lines.
    pub fn access(&self) -> Access {
        self.session
            .as_ref()
            .map_or(Access::UNRESTRICTED, |session| session.access)
    }

    /// Write a line directly to the connection socket.
    pub fn send_line(&mut self, text: &[u8]) -> Result<(), NetError> {
        let socket = self
            .session
            .as_ref()
            .map(|session| session.socket)
            .ok_or(NetError::Closed)?;
        send_line(self.network, socket, text)
    }

    /// Replace the reply text with formatted output.
    pub fn set_text(&mut self, arguments: core::fmt::Arguments<'_>) {
        use core::fmt::Write as _;
        self.text.clear();
        let _ = self.text.write_fmt(arguments);
    }
}
