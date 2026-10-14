#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms)]

pub mod commands;
pub mod discovery;
pub mod error;
pub mod protocol;
pub mod time;
pub mod transport;

mod client;

pub use client::Client;
pub use client::ClientEngine;
pub use client::ClientEvent;
pub use client::Connected;
pub use client::Fresh;
pub use client::SubmitError;
pub use error::ArgumentError;
pub use error::Error;
pub use error::ExpectedShape;
pub use error::FramingError;
pub use error::ParseError;
pub use error::Result;
pub use error::TransportError;
pub use protocol::ArgBuilder;
pub use protocol::Command;
pub use protocol::ErrorCode;
pub use protocol::ExpectedBody;
pub use protocol::Qword;
pub use protocol::QwordPair;
pub use protocol::Response;
pub use protocol::StatusCode;
pub use protocol::SuccessCode;
pub use time::FileTime;

pub const XBDM_PORT: u16 = 730;
