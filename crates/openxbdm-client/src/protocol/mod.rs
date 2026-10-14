//! Wire-protocol primitives for XBDM.
//!
//! XBDM is a line-oriented ASCII protocol spoken over TCP/730. Commands are
//! case-insensitive mnemonics followed by zero or more `KEY=VALUE` arguments
//! (or bare flag tokens / sub-commands) and terminated by `\r\n`.
//!
//! Every response starts with a three-digit status code. The status numeric
//! range discriminates the semantic shape of the response:
//!
//! - 2xx: success
//! - 4xx: client/remote error
//!
//! Within the success range several sub-codes describe follow-up framing:
//!
//! - 200: single-line response terminating at the `\r\n` following the code
//! - 201: "connected" banner
//! - 202: multi-line text response, terminated by a bare `.\r\n`
//! - 203: a follow-up binary payload; commands determine its length
//! - 204: the server is ready to receive binary data from us
//!
//! Each command declares which shape(s) it expects; the response parser
//! converts well-known error statuses into [`crate::error::Error::Remote`]
//! before returning.

pub(crate) mod parse;

mod args;
mod command;
pub mod response;
mod status;

pub use args::ArgBuilder;
pub use args::Qword;
pub use args::QwordPair;
pub use command::Command;
pub use command::ExpectedBody;
pub use response::Response;
pub use response::ResponseHead;
pub use response::parse_response_head;
pub use status::Classified;
pub use status::ErrorCode;
pub use status::StatusCode;
pub use status::SuccessCode;
