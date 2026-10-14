//! The [`Command`] trait connects a typed request to a typed response.
//!
//! A command is a value that knows (a) how to serialise itself to a wire
//! line via [`ArgBuilder`](crate::protocol::ArgBuilder) and (b) how to
//! turn a raw [`Response`](crate::protocol::Response) into its domain
//! result type. Keeping those two halves together lets the client expose
//! `conn.run(MyCommand { ... })` without surfacing the stringly-typed
//! protocol to callers.

use crate::error::Error;
use crate::protocol::response::Response;
use crate::protocol::status::ErrorCode;

/// Declared response shape of a command. Used by the connection layer to
/// decide how many binary bytes to collect or whether to expect a multi-line
/// body.
#[derive(Debug, Clone, Copy)]
pub enum ExpectedBody {
    /// A single-line response. The parsed head is handed to `parse`.
    Line,
    /// A 202 multi-line text body.
    Multiline,
    /// A 203 binary payload. The callee must return the known byte count
    /// from [`Command::binary_len`].
    Binary,
    /// A 204 "waiting for binary" handshake (outbound upload).
    UploadBinary,
}

pub trait Command {
    /// The typed result produced from a successful response.
    type Output;

    /// Build the wire line (no `\r\n` terminator).
    fn wire_line(&self) -> Result<String, rootcause::Report<Error>>;

    /// Response shape expected for this command.
    fn expected(&self) -> ExpectedBody;

    /// Known length of the binary payload, if the command declares
    /// [`ExpectedBody::Binary`]. Must return `Some` in that case.
    fn binary_len(&self) -> Option<usize> {
        None
    }

    /// Convert a successful response into the command's domain output.
    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>>;

    /// Optional hook letting a command translate a `4xx` remote error into
    /// a regular [`Output`] value. Returning `None` lets the error
    /// propagate; returning `Some(Ok(_))` treats the error as a typed
    /// success (used for commands like `isstopped` where "not stopped" is
    /// semantically part of the API). Returning `Some(Err(_))` lets the
    /// command rewrite the error type before it propagates.
    #[allow(unused_variables)]
    fn handle_remote(
        &self,
        code: ErrorCode,
        message: &str,
    ) -> Option<Result<Self::Output, rootcause::Report<Error>>> {
        None
    }
}
