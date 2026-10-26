//! Progress bars for streaming transfers.

use std::io::IsTerminal;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use indicatif::ProgressBar;
use indicatif::ProgressDrawTarget;
use indicatif::ProgressStyle;

/// Wrap an `AsyncWrite`, ticking a [`ProgressBar`] as bytes flow through.
pub struct ProgressWrite<W> {
    inner: W,
    bar: ProgressBar,
}

impl<W> ProgressWrite<W> {
    pub fn new(inner: W, bar: ProgressBar) -> Self {
        Self { inner, bar }
    }
}

impl<W> AsyncWrite for ProgressWrite<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = poll {
            this.bar.inc(written as u64);
        }

        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Wrap an `AsyncRead`, ticking a [`ProgressBar`] as bytes flow out.
pub struct ProgressRead<R> {
    inner: R,
    bar: ProgressBar,
}

impl<R> ProgressRead<R> {
    pub fn new(inner: R, bar: ProgressBar) -> Self {
        Self { inner, bar }
    }
}

impl<R> AsyncRead for ProgressRead<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(read)) = poll {
            this.bar.inc(read as u64);
        }

        poll
    }
}

/// Build a transfer progress bar. If `disabled` is true or stderr isn't a
/// TTY the bar is hidden and its `inc`/`finish` calls are no-ops.
pub fn transfer_bar(total: u64, label: &str, disabled: bool) -> ProgressBar {
    if disabled || !std::io::stderr().is_terminal() {
        return ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::hidden());
    }

    let bar = ProgressBar::new(total);
    bar.set_draw_target(ProgressDrawTarget::stderr());
    bar.set_style(
        ProgressStyle::with_template(
            "{prefix:.cyan.bold} [{bar:32.magenta/black}] {bytes:>9}/{total_bytes:<9}  {bytes_per_sec:>11}  eta {eta:>4}",
        )
        .expect("valid progress template")
        .progress_chars("##-"),
    );
    bar.enable_steady_tick(Duration::from_millis(120));
    bar.set_prefix(label.to_owned());

    bar
}
