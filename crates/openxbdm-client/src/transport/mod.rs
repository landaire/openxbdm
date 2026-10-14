//! Async-agnostic transport for the XBDM wire protocol.
//!
//! The core library is written against [`futures_io::AsyncRead`] +
//! [`futures_io::AsyncWrite`] so callers may plug in any executor they
//! like. A convenience adapter for `tokio::net::TcpStream` is provided
//! behind the `tokio` feature flag; a [`MockTransport`] replays captured
//! conversations into tests without any network activity; a
//! [`RecordingTransport`] wraps any other transport and tees its traffic
//! into a [`CaptureLog`] for offline replay.

pub mod capture;
pub mod mock;
pub mod recording;

#[cfg(feature = "tokio")]
pub mod tokio;

pub use capture::CaptureEntry;
pub use capture::CaptureLog;
pub use capture::Direction;
pub use mock::MockTransport;
pub use recording::RecordingTransport;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;

/// A marker trait covering any full-duplex byte stream we can speak XBDM over.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> Transport for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
