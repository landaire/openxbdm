//! Streaming file transfer.
//!
//! `getfile NAME="..." [OFFSET=n SIZE=m]` replies `203- binary response
//! follows` (`203- partial send` for a range), a 4-byte little-endian
//! length, then that many bytes. For a range the server sends the bytes
//! from `OFFSET` to the end of the file, clamped to `SIZE` when `SIZE` is
//! nonzero; an `OFFSET` past the end yields 0 bytes. Offsets and sizes are
//! 32-bit.
//!
//! After the 203 line we are mid-transfer on the same TCP stream; no other
//! commands can be issued until the payload is drained. That invariant is
//! enforced by [`FileDownload`] borrowing the transport mutably from the
//! client until it is fully consumed.

use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use bytes::BytesMut;
use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use futures_util::io::AsyncReadExt;
use futures_util::io::AsyncWriteExt;
use rootcause::prelude::*;

use crate::client::Client;
use crate::client::ClientEngine;
use crate::client::Connected;
use crate::error::Error;
use crate::error::FramingError;
use crate::protocol::ArgBuilder;
use crate::protocol::Response;
use crate::protocol::SuccessCode;

/// Maximum file size we'll consume in a single prefix-length getfile.
/// XBDM on-device caps payloads around ~5 MiB per range; this bound just
/// catches bogus length prefixes from corrupted streams.
pub const MAX_PREFIX_LENGTH: u64 = 1 << 32;

/// Active getfile transfer. Implements [`AsyncRead`] so callers can pipe it
/// into any [`AsyncWrite`] via `futures_util::io::copy`, or consume it
/// chunk-by-chunk by hand. Drops leave the underlying client in an
/// unreliable state if `remaining() > 0`; prefer one of the convenience
/// consumers unless you know you'll drain the stream yourself.
#[derive(Debug)]
pub struct FileDownload<'a, T> {
    transport: &'a mut T,
    engine: &'a mut ClientEngine,
    /// Body bytes captured by the same socket read that pulled in the
    /// 203 head, plus any additional bytes the length-prefix probe
    /// over-read. Drained before any transport read.
    leftover: BytesMut,
    total: u64,
    read_so_far: u64,
}

impl<'a, T> FileDownload<'a, T>
where
    T: AsyncRead + Unpin,
{
    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn remaining(&self) -> u64 {
        self.total - self.read_so_far
    }

    pub fn is_exhausted(&self) -> bool {
        self.remaining() == 0
    }

    /// Drain the rest of the payload into a `Vec`.
    pub async fn into_vec(mut self) -> Result<Vec<u8>, rootcause::Report<Error>> {
        let mut buf = Vec::with_capacity(self.total as usize);
        self.read_to_end(&mut buf)
            .await
            .map_err(Error::from)
            .into_report()
            .attach("draining getfile payload into memory")?;
        Ok(buf)
    }

    /// Drain the rest of the payload into any `AsyncWrite`. Returns the
    /// number of bytes written.
    pub async fn copy_into<W>(mut self, writer: &mut W) -> Result<u64, rootcause::Report<Error>>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = [0u8; 64 * 1024];
        let mut total = 0u64;
        while !self.is_exhausted() {
            let n = self
                .read(&mut buf)
                .await
                .map_err(Error::from)
                .into_report()
                .attach("reading getfile payload chunk")?;
            if n == 0 {
                break;
            }
            writer
                .write_all(&buf[..n])
                .await
                .map_err(Error::from)
                .into_report()
                .attach("writing getfile payload chunk to sink")?;
            total += n as u64;
        }
        writer
            .flush()
            .await
            .map_err(Error::from)
            .into_report()
            .attach("flushing getfile sink")?;
        Ok(total)
    }
}

impl<T> Drop for FileDownload<'_, T> {
    fn drop(&mut self) {
        let remaining = self.total.saturating_sub(self.read_so_far);
        if remaining > 0 {
            // Unread body bytes are still queued on the wire; the
            // connection can no longer be framed. Fail the engine
            // rather than hand back a reusable-looking client.
            self.engine.abort_stream(Some(remaining));
            return;
        }
        // Body fully consumed. `leftover` past the body belongs to the
        // next response, so hand it back to the engine.
        self.engine.end_stream(&self.leftover);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for FileDownload<'_, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let remaining = self.total.saturating_sub(self.read_so_far);
        if remaining == 0 {
            return Poll::Ready(Ok(0));
        }
        let cap = core::cmp::min(buf.len() as u64, remaining) as usize;
        let slice = &mut buf[..cap];

        let this = &mut *self;
        // Drain captured leftover bytes ahead of any new transport read.
        if !this.leftover.is_empty() {
            let take = core::cmp::min(this.leftover.len(), slice.len());
            slice[..take].copy_from_slice(&this.leftover[..take]);
            let _ = this.leftover.split_to(take);
            this.read_so_far += take as u64;
            return Poll::Ready(Ok(take));
        }
        let pinned = Pin::new(&mut *this.transport);
        match pinned.poll_read(cx, slice) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed mid-getfile payload",
            ))),
            Poll::Ready(Ok(n)) => {
                this.read_so_far += n as u64;
                Poll::Ready(Ok(n))
            }
        }
    }
}

/// Active sendfile/writefile transfer. Implements [`AsyncWrite`] so
/// callers can pipe any [`AsyncRead`] into it via `futures_util::io::copy`.
///
/// The upload is strict about byte counts: the caller must write exactly
/// `declared()` bytes and then call [`FileUpload::finish`] to drain the
/// server's success response. Dropping with bytes pending leaves the
/// connection in a broken state, so prefer the convenience consumers.
#[derive(Debug)]
pub struct FileUpload<'a, T> {
    client: &'a mut Client<T, Connected>,
    declared: u64,
    sent_so_far: u64,
}

impl<'a, T> FileUpload<'a, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn declared(&self) -> u64 {
        self.declared
    }

    pub fn sent(&self) -> u64 {
        self.sent_so_far
    }

    pub fn remaining(&self) -> u64 {
        self.declared - self.sent_so_far
    }

    /// Stream `reader`'s full contents into the upload (up to
    /// `declared()` bytes) and finalize.
    pub async fn copy_from<R>(mut self, reader: &mut R) -> Result<(), rootcause::Report<Error>>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 64 * 1024];
        while self.remaining() > 0 {
            let cap = core::cmp::min(buf.len() as u64, self.remaining()) as usize;
            let n = reader
                .read(&mut buf[..cap])
                .await
                .map_err(Error::from)
                .into_report()
                .attach("reading source for sendfile")?;
            if n == 0 {
                let msg = format!(
                    "source ran out after {} bytes but {} were declared",
                    self.sent_so_far, self.declared
                );
                return Err(rootcause::Report::new(Error::from(
                    FramingError::TrailingGarbageInHead,
                ))
                .attach(msg));
            }
            self.write_all(&buf[..n])
                .await
                .map_err(Error::from)
                .into_report()
                .attach("sending binary chunk to console")?;
        }
        self.finish().await
    }

    /// Upload an in-memory buffer and finalize. The buffer length must
    /// match `declared()`.
    pub async fn send_all(mut self, payload: &[u8]) -> Result<(), rootcause::Report<Error>> {
        if payload.len() as u64 != self.declared {
            let msg = format!(
                "payload length {} != declared {}",
                payload.len(),
                self.declared
            );
            return Err(
                rootcause::Report::new(Error::from(FramingError::TrailingGarbageInHead))
                    .attach(msg),
            );
        }
        self.write_all(payload)
            .await
            .map_err(Error::from)
            .into_report()
            .attach("writing send_all payload")?;
        self.finish().await
    }

    /// Drain any pending bytes on the wire and read the success response.
    /// Call after having pushed exactly `declared()` bytes via
    /// [`AsyncWrite`].
    pub async fn finish(self) -> Result<(), rootcause::Report<Error>> {
        if self.remaining() != 0 {
            let msg = format!(
                "upload finish called with {} bytes still to send",
                self.remaining()
            );
            return Err(
                rootcause::Report::new(Error::from(FramingError::TrailingGarbageInHead))
                    .attach(msg),
            );
        }
        let response = self.client.read_post_upload_response().await?;
        match response {
            Response::Line {
                code: SuccessCode::Ok,
                ..
            } => Ok(()),
            other => Err(
                rootcause::Report::new(Error::from(FramingError::HeadTooShort))
                    .attach(format!("expected 200 OK after upload, got {other:?}")),
            ),
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for FileUpload<'_, T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let remaining = this.declared - this.sent_so_far;
        if remaining == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "FileUpload declared length fully satisfied",
            )));
        }
        let cap = core::cmp::min(buf.len() as u64, remaining) as usize;
        let slice = &buf[..cap];
        let pinned = Pin::new(this.client.transport_mut());
        match pinned.poll_write(cx, slice) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => {
                this.sent_so_far += n as u64;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.client.transport_mut()).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.client.transport_mut()).poll_close(cx)
    }
}

/// Argument to [`Client::get_file`] describing whether to read the whole
/// file or a byte range. A range without a `size` reads to the end of the
/// file.
#[derive(Debug, Clone, Copy)]
pub enum GetFileRange {
    WholeFile,
    Range {
        offset: u32,
        size: Option<core::num::NonZeroU32>,
    },
}

impl<T> Client<T, Connected>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Start a getfile transfer. Returns an [`FileDownload`] that borrows
    /// the client's transport; callers must fully drain the download
    /// before issuing further commands on this connection.
    pub async fn get_file<'a>(
        &'a mut self,
        path: &str,
        range: GetFileRange,
    ) -> Result<FileDownload<'a, T>, rootcause::Report<Error>> {
        let mut line = ArgBuilder::new("getfile")
            .quoted("NAME", path)
            .map_err(|e| rootcause::Report::new(Error::from(e)))?;
        if let GetFileRange::Range { offset, size } = range {
            // The monitor reads to the end of the file for `SIZE=0`.
            let size = size.map_or(0, core::num::NonZeroU32::get);
            line = line
                .dec("OFFSET", u64::from(offset))
                .dec("SIZE", u64::from(size));
        }
        let wire = line.finish();

        // 203 head; engine parks in StreamingBody after this.
        let _head_text = self.submit_streaming(&wire).await?;
        let (transport, engine) = self.split_streaming();
        let mut leftover = engine.take_inbox();

        // The prefix gives the byte count actually sent, which for a range
        // is clamped to the bytes available.
        let advertised = match read_length_prefix(transport, &mut leftover).await {
            Ok(n) => n,
            Err(e) => {
                engine.end_stream(&[]);
                return Err(e);
            }
        };
        Ok(FileDownload {
            transport,
            engine,
            leftover,
            total: advertised,
            read_so_far: 0,
        })
    }
}

/// Mode for an outbound file upload. `Create` (sendfile) wipes any
/// existing file and writes the full `size` from offset 0. `WriteAt`
/// (writefile) writes exactly `size` bytes starting at `offset` within an
/// existing file. The server takes 32-bit offsets and sizes.
#[derive(Debug, Clone, Copy)]
pub enum FileUploadKind {
    Create { size: u32 },
    WriteAt { offset: u32, size: u32 },
}

impl FileUploadKind {
    pub fn size(&self) -> u32 {
        match self {
            FileUploadKind::Create { size } | FileUploadKind::WriteAt { size, .. } => *size,
        }
    }
}

impl<T> Client<T, Connected>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Begin a streaming upload to the console. The returned
    /// [`FileUpload`] is an `AsyncWrite` that accepts exactly `size` (or
    /// `size_at_offset`) bytes before being finalized via `.finish()`.
    pub async fn send_file<'a>(
        &'a mut self,
        path: &str,
        kind: FileUploadKind,
    ) -> Result<FileUpload<'a, T>, rootcause::Report<Error>> {
        let line = match kind {
            FileUploadKind::Create { size } => ArgBuilder::new("sendfile")
                .quoted("NAME", path)
                .map_err(|e| rootcause::Report::new(Error::from(e)))?
                .hex("LENGTH", u64::from(size))
                .finish(),
            FileUploadKind::WriteAt { offset, size } => ArgBuilder::new("writefile")
                .quoted("NAME", path)
                .map_err(|e| rootcause::Report::new(Error::from(e)))?
                .dec("OFFSET", u64::from(offset))
                .dec("LENGTH", u64::from(size))
                .finish(),
        };

        // 204 send-binary. Engine returns to Idle after this; the body
        // is then written raw to the transport, and the post-upload 200
        // is collected by `read_post_upload_response()` from `finish`.
        let response = self.send_raw(&line).await?;
        match response {
            Response::SendBinary { .. } => {}
            Response::Line {
                code: SuccessCode::Ok,
                head,
            } => {
                return Err(
                    rootcause::Report::new(Error::from(FramingError::HeadTooShort)).attach(
                        format!("expected 204 send-binary but got 200 OK ({head:?})"),
                    ),
                );
            }
            other => {
                return Err(
                    rootcause::Report::new(Error::from(FramingError::HeadTooShort))
                        .attach(format!("expected 204 send-binary, got {other:?}")),
                );
            }
        }

        Ok(FileUpload {
            client: self,
            declared: u64::from(kind.size()),
            sent_so_far: 0,
        })
    }
}

async fn read_length_prefix<R>(
    reader: &mut R,
    leftover: &mut BytesMut,
) -> Result<u64, rootcause::Report<Error>>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0u8; 4];
    let mut filled = 0usize;

    if !leftover.is_empty() {
        let take = core::cmp::min(leftover.len(), prefix.len());
        prefix[..take].copy_from_slice(&leftover[..take]);
        let _ = leftover.split_to(take);
        filled = take;
    }
    while filled < prefix.len() {
        let n = reader
            .read(&mut prefix[filled..])
            .await
            .map_err(Error::from)
            .into_report()
            .attach("reading getfile length prefix")?;
        if n == 0 {
            return Err(rootcause::Report::new(Error::ConnectionClosed));
        }
        filled += n;
    }
    let length = u32::from_le_bytes(prefix) as u64;
    if length > MAX_PREFIX_LENGTH {
        return Err(
            rootcause::Report::new(Error::from(FramingError::TrailingGarbageInHead))
                .attach(format!("refusing {length}-byte getfile payload")),
        );
    }
    Ok(length)
}
