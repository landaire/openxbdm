//! Typed connection layer.
//!
//! [`Client`] is parameterised over a marker type describing the current
//! protocol phase. Fresh clients wrapping a raw transport have not read
//! the banner yet; only after [`Client::read_banner`] succeeds does the
//! client transition to [`Connected`], where commands may be issued.
//!
//! Further states (dedicated handlers, debugger attach, notification
//! channels) can be layered on by moving the `Client<Connected>` through
//! additional transitions that consume it and return a new parameterisation.
//!
//! The async [`Client`] in this module is a thin driver over the sans-io
//! [`engine::ClientEngine`]: it pumps bytes between an
//! `AsyncRead`/`AsyncWrite` transport and the engine, surfacing typed
//! events as either parsed [`Response`]s or errors. Callers that don't
//! want to pull in tokio (or any async runtime) can use
//! [`engine::ClientEngine`] directly.

use futures_util::io::AsyncRead;
use futures_util::io::AsyncReadExt;
use futures_util::io::AsyncWrite;
use futures_util::io::AsyncWriteExt;
use rootcause::prelude::*;

use crate::error::Error;
use crate::error::FramingError;
use crate::error::TransportError;
use crate::protocol::Command;
use crate::protocol::ExpectedBody;
use crate::protocol::response::Response;

pub mod engine;
mod state;

pub use engine::ClientEngine;
pub use engine::ClientEvent;
pub use engine::SubmitError;
pub use state::Connected;
pub use state::Fresh;

/// Read-side scratch buffer used by [`Client::pump_until`] when copying
/// transport bytes into the engine. 8 KiB is plenty for line responses
/// while still being a small stack allocation per call.
const READ_CHUNK: usize = 8 * 1024;

/// A typed XBDM client.
///
/// `T` is the underlying transport (anything implementing both
/// `AsyncRead` and `AsyncWrite`); `S` is the protocol state marker.
#[derive(Debug)]
pub struct Client<T, S = Fresh> {
    transport: T,
    engine: ClientEngine,
    _state: core::marker::PhantomData<S>,
}

impl<T> Client<T, Fresh>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap a freshly opened transport. The caller still owes the banner
    /// read before commands may be issued.
    pub fn new(transport: T) -> Self {
        Self { transport, engine: ClientEngine::new(), _state: core::marker::PhantomData }
    }

    /// Read the initial `201 connected` banner and transition to
    /// [`Connected`]. Any non-201 response is reported as a framing
    /// error.
    pub async fn read_banner(mut self) -> Result<Client<T, Connected>, rootcause::Report<Error>> {
        let event = self.pump_until(|ev| matches!(ev, ClientEvent::Connected)).await?;
        match event {
            ClientEvent::Connected => {
                Ok(Client { transport: self.transport, engine: self.engine, _state: core::marker::PhantomData })
            }
            // pump_until guarantees the predicate matched or it returned Err.
            other => unreachable!("unexpected event after banner pump: {other:?}"),
        }
    }
}

impl<T> Client<T, Connected>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Execute a typed [`Command`], running it through the request/response
    /// pipeline and returning the command's parsed output.
    pub async fn run<C: Command>(&mut self, cmd: C) -> Result<C::Output, rootcause::Report<Error>> {
        let line = cmd.wire_line()?;
        tracing::debug!(wire = %line, "xbdm send");

        let binary_len = match cmd.expected() {
            ExpectedBody::Binary => Some(
                cmd.binary_len()
                    .ok_or_else(|| rootcause::Report::new(Error::from(TransportError::MissingBinaryLen)))?,
            ),
            _ => None,
        };

        self.engine.submit(&line, binary_len).map_err(|e| submit_to_report(e, &line))?;

        let event = match self
            .pump_until(|ev| matches!(ev, ClientEvent::Response(_) | ClientEvent::RemoteError { .. }))
            .await
        {
            Ok(ev) => ev,
            Err(report) => return Err(report),
        };

        match event {
            ClientEvent::Response(response) => {
                tracing::debug!(?response, "xbdm recv");
                cmd.parse(response)
            }
            ClientEvent::RemoteError { code, message } => {
                if let Some(mapped) = cmd.handle_remote(code, &message) {
                    return mapped;
                }
                Err(rootcause::Report::new(Error::Remote { code, message }))
            }
            other => unreachable!("unexpected event after run pump: {other:?}"),
        }
    }

    /// Send a raw command line. Useful for REPL-style exploration and
    /// commands we haven't modelled yet. Returns the raw parsed response
    /// so callers can decide what to do with it.
    pub async fn send_raw(&mut self, line: &str) -> Result<Response, rootcause::Report<Error>> {
        self.engine.submit(line, None).map_err(|e| submit_to_report(e, line))?;
        let event =
            self.pump_until(|ev| matches!(ev, ClientEvent::Response(_) | ClientEvent::RemoteError { .. })).await?;
        match event {
            ClientEvent::Response(response) => Ok(response),
            ClientEvent::RemoteError { code, message } => Err(rootcause::Report::new(Error::Remote { code, message })),
            other => unreachable!("unexpected event after send_raw pump: {other:?}"),
        }
    }

    /// Politely close the session with the XBDM `bye` command. The server
    /// replies with a status line and drops the socket.
    pub async fn bye(mut self) -> Result<(), rootcause::Report<Error>> {
        self.engine.submit("bye", None).map_err(|e| submit_to_report(e, "bye"))?;
        // Either a normal response or a clean close are both fine -- some
        // kits drop the socket before flushing the reply.
        let event = self
            .pump_until(|ev| {
                matches!(ev, ClientEvent::Response(_) | ClientEvent::RemoteError { .. } | ClientEvent::Closed)
            })
            .await;
        match event {
            Ok(_) => Ok(()),
            Err(report) if matches!(report.current_context(), Error::ConnectionClosed) => Ok(()),
            Err(report) => Err(report),
        }
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    /// Issue a binary streaming command and wait for the 203 head. The
    /// engine is left in `StreamingBody`; the caller drains
    /// [`ClientEngine::take_inbox`] for any prefix bytes captured with
    /// the head, reads the rest of the body off
    /// [`Self::transport_mut`], then calls [`Self::end_stream`] to
    /// release the engine.
    ///
    /// A 4xx remote error is reported as a typed `Error::Remote`; a
    /// non-203 success (line / multiline / 204) is reported as a
    /// framing error since the caller asked for a streaming body.
    pub(crate) async fn submit_streaming(&mut self, line: &str) -> Result<String, rootcause::Report<Error>> {
        self.engine.submit_streaming(line).map_err(|e| submit_to_report(e, line))?;
        let event = self
            .pump_until(|ev| {
                matches!(
                    ev,
                    ClientEvent::BinaryHead { .. } | ClientEvent::Response(_) | ClientEvent::RemoteError { .. }
                )
            })
            .await?;
        match event {
            ClientEvent::BinaryHead { head } => Ok(head),
            ClientEvent::RemoteError { code, message } => Err(rootcause::Report::new(Error::Remote { code, message })),
            ClientEvent::Response(response) => Err(rootcause::Report::new(Error::from(FramingError::HeadTooShort))
                .attach(format!("expected 203 streaming head, got {response:?}"))),
            other => unreachable!("unexpected event after streaming pump: {other:?}"),
        }
    }

    /// Disjoint mutable access to the transport and the engine. Used by
    /// streaming adapters that need both: the transport for raw body
    /// reads/writes, the engine to drain leftover inbox bytes and to
    /// finalise via [`ClientEngine::end_stream`] /
    /// [`ClientEngine::expect_response`].
    pub(crate) fn split_streaming(&mut self) -> (&mut T, &mut ClientEngine) {
        (&mut self.transport, &mut self.engine)
    }

    /// Raw transport access used by upload adapters that own a
    /// `&mut Client` and need to push body bytes after a 204 handshake.
    pub(crate) fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// After an out-of-band write (e.g. a `sendfile` upload body), arm
    /// the engine to read the kit's follow-up response and pump until
    /// it arrives. Returns the response or surfaces a remote 4xx.
    pub(crate) async fn read_post_upload_response(&mut self) -> Result<Response, rootcause::Report<Error>> {
        self.engine.expect_response().map_err(|e| submit_to_report(e, "<post-upload response>"))?;
        let event =
            self.pump_until(|ev| matches!(ev, ClientEvent::Response(_) | ClientEvent::RemoteError { .. })).await?;
        match event {
            ClientEvent::Response(response) => Ok(response),
            ClientEvent::RemoteError { code, message } => Err(rootcause::Report::new(Error::Remote { code, message })),
            other => unreachable!("unexpected event after upload response pump: {other:?}"),
        }
    }
}

impl<T, S> Client<T, S>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Drive the engine until `predicate` is satisfied by an event, or
    /// fail with the underlying transport / framing error. `Closed` and
    /// `Failed` are surfaced as `Err` unless the predicate explicitly
    /// accepts them (e.g. `bye` accepts `Closed` as success).
    async fn pump_until<F>(&mut self, mut predicate: F) -> Result<ClientEvent, rootcause::Report<Error>>
    where
        F: FnMut(&ClientEvent) -> bool,
    {
        let mut buf = [0u8; READ_CHUNK];
        loop {
            // Drain anything the engine has queued for transmission.
            while self.engine.pending_send() > 0 {
                let n = self.engine.send(&mut buf);
                self.transport
                    .write_all(&buf[..n])
                    .await
                    .map_err(Error::from)
                    .into_report()
                    .attach("flushing engine outbox")?;
            }
            self.transport.flush().await.map_err(Error::from).into_report().attach("flushing transport")?;

            // Surface any pending events.
            while let Some(ev) = self.engine.poll() {
                if predicate(&ev) {
                    return Ok(ev);
                }
                match ev {
                    ClientEvent::Failed(err) => return Err(rootcause::Report::new(*err)),
                    ClientEvent::Closed => {
                        return Err(rootcause::Report::new(Error::ConnectionClosed));
                    }
                    // Other events the predicate didn't want -- keep pumping.
                    _ => {}
                }
            }

            if self.engine.is_terminal() {
                return Err(rootcause::Report::new(Error::ConnectionClosed));
            }

            let n = self
                .transport
                .read(&mut buf)
                .await
                .map_err(Error::from)
                .into_report()
                .attach("reading from transport for engine pump")?;
            if n == 0 {
                self.engine.close_read();
                continue;
            }
            self.engine.recv(&buf[..n]);
        }
    }
}

fn submit_to_report(err: SubmitError, line: &str) -> rootcause::Report<Error> {
    // `Unusable` is the peer being gone; the rest are caller misuse and
    // keep their own variant so callers can tell them apart.
    let mapped = match err {
        SubmitError::Unusable => Error::ConnectionClosed,
        misuse => Error::EngineMisuse(misuse),
    };
    rootcause::Report::new(mapped).attach(format!("submit({line:?}) rejected"))
}
