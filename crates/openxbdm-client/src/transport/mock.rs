//! Mock transport that plays back a [`CaptureLog`] into tests.
//!
//! The mock walks the capture's frames one at a time. Frames tagged
//! [`Direction::ServerToClient`] become bytes returned from
//! [`AsyncRead::poll_read`]; frames tagged [`Direction::ClientToServer`]
//! are consumed by [`AsyncWrite::poll_write`] and verified against the
//! actual bytes written by the caller.
//!
//! A mismatch (client wrote unexpected bytes, or the script was exhausted
//! but the client wanted more data) is surfaced as an `io::Error` of kind
//! `InvalidData` so tests can capture it via their existing error paths.

use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;

use crate::transport::capture::CaptureEntry;
use crate::transport::capture::CaptureLog;
use crate::transport::capture::Direction;

#[derive(Debug)]
pub struct MockTransport {
    frames: Vec<CaptureEntry>,
    /// Index of the next frame to consume. We never pop; the index keeps
    /// debug output (which prints the whole script) meaningful.
    cursor: usize,
    /// Byte offset within the current frame when the client is only
    /// reading/writing a partial chunk.
    offset: usize,
    /// If true, unexpected client bytes are ignored instead of erroring.
    /// Useful when a test wants to drive a short command against a capture
    /// that only contains the server side.
    lax_writes: bool,
    /// If true, reads past the end of the script return `WouldBlock`
    /// (pending), simulating an idle socket, rather than EOF.
    reads_pend_on_end: bool,
}

impl MockTransport {
    pub fn from_log(log: CaptureLog) -> Self {
        Self {
            frames: log.entries().to_vec(),
            cursor: 0,
            offset: 0,
            lax_writes: false,
            reads_pend_on_end: false,
        }
    }

    /// Build a mock transport from a list of server-to-client responses
    /// without also asserting on the client's outgoing bytes.
    pub fn from_server_script<I, B>(chunks: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: Into<Vec<u8>>,
    {
        let mut log = CaptureLog::new();
        for chunk in chunks {
            log.push(Direction::ServerToClient, &chunk.into());
        }
        let mut mock = Self::from_log(log);
        mock.lax_writes = true;
        mock
    }

    pub fn with_lax_writes(mut self) -> Self {
        self.lax_writes = true;
        self
    }

    pub fn with_idle_after_end(mut self) -> Self {
        self.reads_pend_on_end = true;
        self
    }

    /// Returns true if the script has been fully consumed.
    pub fn is_exhausted(&self) -> bool {
        self.cursor >= self.frames.len()
    }

    fn current_frame(&self) -> Option<&CaptureEntry> {
        self.frames.get(self.cursor)
    }

    fn advance_frame(&mut self) {
        self.cursor += 1;
        self.offset = 0;
    }
}

impl AsyncRead for MockTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let Some((direction, remaining_in_frame, frame_total)) = self.frame_view() else {
                if self.reads_pend_on_end {
                    return Poll::Pending;
                }
                return Poll::Ready(Ok(0));
            };
            if direction != Direction::ServerToClient {
                if self.lax_writes {
                    self.advance_frame();
                    continue;
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mock transport: client attempted to read while the script expects client->server bytes",
                )));
            }
            if remaining_in_frame == 0 {
                self.advance_frame();
                continue;
            }
            let to_copy = remaining_in_frame.min(buf.len());
            {
                let frame = self.current_frame().expect("frame_view returned Some");
                buf[..to_copy].copy_from_slice(&frame.data[self.offset..self.offset + to_copy]);
            }
            self.offset += to_copy;
            if self.offset >= frame_total {
                self.advance_frame();
            }
            return Poll::Ready(Ok(to_copy));
        }
    }
}

impl MockTransport {
    fn frame_view(&self) -> Option<(Direction, usize, usize)> {
        let frame = self.frames.get(self.cursor)?;
        Some((
            frame.direction,
            frame.data.len().saturating_sub(self.offset),
            frame.data.len(),
        ))
    }
}

impl AsyncWrite for MockTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.lax_writes {
            return Poll::Ready(Ok(buf.len()));
        }
        let Some((direction, remaining, frame_total)) = self.frame_view() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mock transport: client wrote bytes past the end of the script",
            )));
        };
        if direction != Direction::ClientToServer {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mock transport: client wrote bytes when the script expected a server reply",
            )));
        }
        let to_check = remaining.min(buf.len());
        let cursor = self.cursor;
        let offset = self.offset;
        {
            let frame = self.current_frame().expect("frame_view returned Some");
            if frame.data[offset..offset + to_check] != buf[..to_check] {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "mock transport: client bytes diverged from script at frame {cursor} offset {offset}"
                    ),
                )));
            }
        }
        self.offset += to_check;
        if self.offset >= frame_total {
            self.advance_frame();
        }
        Poll::Ready(Ok(to_check))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::io::AsyncReadExt;
    use futures_util::io::AsyncWriteExt;

    fn log_of(frames: &[(Direction, &[u8])]) -> CaptureLog {
        let mut log = CaptureLog::new();
        for (dir, data) in frames {
            log.push(*dir, data);
        }
        log
    }

    #[test]
    fn returns_scripted_response_bytes() {
        let log = log_of(&[(Direction::ServerToClient, b"201- connected\r\n")]);
        let mut mock = MockTransport::from_log(log);
        let mut buf = [0u8; 64];
        let n = futures::executor::block_on(mock.read(&mut buf)).unwrap();
        assert_eq!(&buf[..n], b"201- connected\r\n");
    }

    #[test]
    fn strict_writes_detect_divergence() {
        let log = log_of(&[(Direction::ClientToServer, b"dbgname\r\n")]);
        let mut mock = MockTransport::from_log(log);
        let err = futures::executor::block_on(mock.write_all(b"different\r\n")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn lax_writes_accept_anything() {
        let mock = MockTransport::from_server_script(vec![b"200- OK\r\n".to_vec()]);
        let mut mock = mock;
        futures::executor::block_on(mock.write_all(b"anything\r\n")).unwrap();
    }
}
