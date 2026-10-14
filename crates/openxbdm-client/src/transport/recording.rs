//! Tee any transport's bytes into a [`CaptureLog`].
//!
//! Wrap a live transport (e.g. a tokio-backed TCP stream) with
//! [`RecordingTransport`]. Every byte read from the inner stream is
//! appended to the log as [`Direction::ServerToClient`]; every byte
//! written is appended as [`Direction::ClientToServer`]. The log is held
//! in an [`Arc<Mutex<_>>`] so it can be snapshotted to disk from a
//! different task (e.g. on `Ctrl+C`) while the connection is still live.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;

use crate::transport::capture::CaptureLog;
use crate::transport::capture::Direction;

#[derive(Debug)]
pub struct RecordingTransport<T> {
    inner: T,
    log: Arc<Mutex<CaptureLog>>,
}

impl<T> RecordingTransport<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            log: Arc::new(Mutex::new(CaptureLog::new())),
        }
    }

    /// Shared handle to the underlying log. Clone this out before the
    /// transport is consumed; the log itself implements `Clone` for
    /// snapshotting.
    pub fn log_handle(&self) -> Arc<Mutex<CaptureLog>> {
        self.log.clone()
    }

    /// Snapshot the log as of right now.
    pub fn snapshot(&self) -> CaptureLog {
        self.log.lock().expect("recording log poisoned").clone()
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for RecordingTransport<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll
            && *n > 0
            && let Ok(mut log) = this.log.lock()
        {
            log.push(Direction::ServerToClient, &buf[..*n]);
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for RecordingTransport<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll
            && *n > 0
            && let Ok(mut log) = this.log.lock()
        {
            log.push(Direction::ClientToServer, &buf[..*n]);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::io::AsyncReadExt;
    use futures_util::io::AsyncWriteExt;
    use futures_util::io::Cursor;

    #[test]
    fn captures_read_and_write_bytes() {
        let inner = Cursor::new(b"201- connected\r\n".to_vec());
        let mut recording = RecordingTransport::new(inner);
        let mut buf = [0u8; 64];

        let n = futures::executor::block_on(recording.read(&mut buf)).unwrap();
        assert_eq!(&buf[..n], b"201- connected\r\n");

        let inner_cursor: &mut Cursor<Vec<u8>> = &mut recording.inner;
        inner_cursor.set_position(0);
        inner_cursor.get_mut().clear();

        futures::executor::block_on(recording.write_all(b"dbgname\r\n")).unwrap();

        let log = recording.snapshot();
        assert_eq!(log.entries().len(), 2);
        assert_eq!(log.entries()[0].direction, Direction::ServerToClient);
        assert_eq!(log.entries()[0].data, b"201- connected\r\n".to_vec());
        assert_eq!(log.entries()[1].direction, Direction::ClientToServer);
        assert_eq!(log.entries()[1].data, b"dbgname\r\n".to_vec());
    }
}
