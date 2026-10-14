//! Sans-io XBDM client state machine.
//!
//! [`ClientEngine`] models the protocol-level conversation with an XBDM
//! kit -- banner reading, line-by-line response framing, multiline (`.`-
//! terminated) bodies, and 203 binary payloads -- without owning a
//! socket. The caller drives I/O:
//!
//! - feed inbound bytes via [`ClientEngine::recv`] (or signal EOF via
//!   [`ClientEngine::close_read`]),
//! - drain outbound bytes via [`ClientEngine::send`] (or peek the queued
//!   length via [`ClientEngine::pending_send`]),
//! - submit a command line via [`ClientEngine::submit`] (eager modes) or
//!   [`ClientEngine::submit_streaming`] (caller-managed binary body),
//! - pull the next protocol event via [`ClientEngine::poll`].
//!
//! Because the engine has no I/O of its own, it works identically over
//! tokio TCP, blocking `std::net::TcpStream`, an in-memory test fixture,
//! or a WASM host's custom TCP interface. The async [`Client`] in the
//! parent module drives this engine under the hood.
//!
//! ## Streaming binary
//!
//! `getfile` payloads, screenshot framebuffers, and similar large 203
//! responses don't fit the "buffer the whole body" model. For those,
//! call [`ClientEngine::submit_streaming`]. When the head arrives the
//! engine emits a [`ClientEvent::BinaryHead`] and parks in a
//! `StreamingBody` state. The caller then:
//!
//! 1. drains any prefix bytes already buffered with
//!    [`ClientEngine::take_inbox`],
//! 2. reads the rest of the body straight from the transport,
//! 3. calls [`ClientEngine::end_stream`] to return to `Idle` (passing
//!    any over-read bytes that should be re-injected as new inbox).
//!
//! No further commands may be submitted until `end_stream` is called.
//!
//! ## Limitations
//!
//! - Pipelining is not supported: only one command may be outstanding at
//!   a time. Calling [`ClientEngine::submit`] before the prior command's
//!   response has been pulled returns
//!   [`SubmitError::CommandInFlight`].
//! - Asynchronous notifications arrive on a separate connection that
//!   has been turned into a notification channel with `notify`; see
//!   [`ClientEngine::enter_notification_mode`]. On a command connection,
//!   unsolicited bytes received while the engine is idle are buffered
//!   until the next command consumes them.
//!
//! [`Client`]: super::Client

use std::collections::VecDeque;

use bytes::BytesMut;
use memchr::memchr;

use crate::error::Error;
use crate::error::FramingError;
use crate::error::TransportError;
use crate::protocol::Classified;
use crate::protocol::ErrorCode;
use crate::protocol::SuccessCode;
use crate::protocol::response::Response;
use crate::protocol::response::parse_response_head;

/// Maximum length of a single protocol line we'll accept. XBDM text
/// lines are short in practice; anything longer is almost certainly a
/// desynced stream.
const MAX_LINE_LEN: usize = 16 * 1024;

/// Output of [`ClientEngine::poll`]. Each variant maps to a single
/// protocol-level event the I/O loop should react to.
#[derive(Debug)]
pub enum ClientEvent {
    /// Banner (`201 connected`) was successfully read. Fires once per
    /// session and unblocks [`ClientEngine::submit`].
    Connected,
    /// The most recently submitted command's response is complete.
    Response(Response),
    /// 203 head arrived for a streaming submit. The engine is now in
    /// `StreamingBody`: drain the inbox via [`ClientEngine::take_inbox`],
    /// read the rest of the body off the transport, then call
    /// [`ClientEngine::end_stream`] to return to `Idle`.
    BinaryHead {
        /// Text after the status code (typically `"binary response
        /// follows"`).
        head: String,
    },
    /// XBDM returned a 4xx remote error for the most recent command.
    /// The connection itself is still healthy: the engine returns to
    /// idle and another command can be submitted. Distinct from
    /// `Failed` so callers don't have to scrutinize the error variant
    /// to know whether the session survived.
    RemoteError {
        code: ErrorCode,
        /// Text after the status code (typically `"unknown command"`,
        /// `"file not found"`, etc.).
        message: String,
    },
    /// One line received on a notification channel.
    Notification(String),
    /// Peer closed the connection cleanly. No further commands can
    /// be submitted.
    Closed,
    /// Fatal protocol error (malformed head, oversize line, non-UTF-8
    /// in a text line, unexpected status code, etc.). Engine is now
    /// permanently failed; subsequent `submit`/`recv` are no-ops.
    Failed(Box<Error>),
}

/// Why [`ClientEngine::submit`] was rejected. Returned synchronously so
/// the caller learns the misuse without waiting for the next `poll`.
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    /// A previous command's response hasn't been pulled yet -- the
    /// engine doesn't pipeline.
    #[error("a command is already in flight; pull its response first")]
    CommandInFlight,
    /// Banner has not been read yet.
    #[error("banner not yet received; cannot submit commands")]
    NotConnected,
    /// Engine has terminally failed or the peer has closed.
    #[error("engine is no longer usable (closed or failed)")]
    Unusable,
    /// The connection is a notification channel and carries no commands.
    #[error("connection is a notification channel; commands are not accepted")]
    NotificationChannel,
}

/// Sans-io XBDM client. See module docs for the I/O loop pattern.
#[derive(Debug)]
pub struct ClientEngine {
    state: State,
    inbox: BytesMut,
    outbox: BytesMut,
    events: VecDeque<ClientEvent>,
    /// Text of the `201` banner after the status code.
    banner: Option<String>,
}

#[derive(Debug)]
enum State {
    /// Connection just opened; waiting for the `201 connected` banner.
    NeedBanner,
    /// No command in flight.
    Idle,
    /// Command line was submitted; head line not yet received.
    AwaitingHead(HeadExpect),
    /// Got `202 multiline`; accumulating body lines until we see `.`.
    ReadingMultiline { head: String, lines: Vec<String> },
    /// Got `203 binary follows`; collecting `remaining` more bytes.
    ReadingBinary {
        head: String,
        remaining: usize,
        data: Vec<u8>,
    },
    /// Streaming caller has been notified of a 203 head and now owns
    /// the body. The engine accepts no inbound bytes (recv is a no-op)
    /// and refuses new submits until [`ClientEngine::end_stream`] is
    /// called.
    StreamingBody,
    /// The connection is a notification channel; every line received is a
    /// notification.
    Notifications,
    /// Peer closed the connection.
    Closed,
    /// Hit a fatal protocol error; no further work possible.
    Failed,
}

/// What body shape the caller expects after submitting a command.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::enum_variant_names)]
enum HeadExpect {
    /// 200 / 201 / 202 / 204 only. A 203 here is a protocol error
    /// because the engine has no way to know where the body ends.
    NoBinary,
    /// 203 expected; engine eagerly buffers `usize` body bytes into a
    /// `Response::Binary` event.
    EagerBinary(usize),
    /// 203 expected; engine emits [`ClientEvent::BinaryHead`] and
    /// surrenders the body to the caller via streaming.
    StreamBinary,
}

impl Default for ClientEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientEngine {
    /// Construct a fresh engine. Initial state expects a `201` banner
    /// before any command may be submitted.
    pub fn new() -> Self {
        Self {
            state: State::NeedBanner,
            inbox: BytesMut::new(),
            outbox: BytesMut::new(),
            events: VecDeque::new(),
            banner: None,
        }
    }

    /// Text of the `201` banner after the status code: `connected`, or
    /// the box id and challenge of a locked console.
    pub fn banner(&self) -> Option<&str> {
        self.banner.as_deref()
    }

    /// Hand bytes received from the peer to the engine. Bytes are
    /// appended to an internal buffer and the state machine is
    /// advanced as far as possible. Calling with an empty slice is a
    /// no-op.
    ///
    /// While in `StreamingBody` the engine is not framing; the caller
    /// owns the wire. `recv` is a no-op there. Use
    /// [`Self::end_stream`] to push any over-read bytes back into the
    /// engine before calling `recv` again.
    pub fn recv(&mut self, bytes: &[u8]) {
        if matches!(
            self.state,
            State::Closed | State::Failed | State::StreamingBody
        ) {
            return;
        }
        if !bytes.is_empty() {
            self.inbox.extend_from_slice(bytes);
        }
        self.advance();
    }

    /// Drain up to `dst.len()` bytes of pending outbound data into
    /// `dst`. Returns the number of bytes written. The caller is
    /// expected to feed those bytes to the actual transport.
    pub fn send(&mut self, dst: &mut [u8]) -> usize {
        let n = self.outbox.len().min(dst.len());
        if n == 0 {
            return 0;
        }
        let chunk = self.outbox.split_to(n);
        dst[..n].copy_from_slice(&chunk);
        n
    }

    /// Number of bytes currently queued for outbound delivery. Useful
    /// when the I/O loop wants to know whether to schedule a write.
    pub fn pending_send(&self) -> usize {
        self.outbox.len()
    }

    /// Tell the engine the peer closed the read side. Subsequent
    /// `recv` calls are ignored. A `ClientEvent::Closed` is emitted
    /// (unless the engine had already failed).
    pub fn close_read(&mut self) {
        if matches!(self.state, State::Closed | State::Failed) {
            return;
        }
        self.state = State::Closed;
        self.events.push_back(ClientEvent::Closed);
    }

    /// Queue a command for transmission. The command line is framed
    /// with `\r\n` and pushed into the outbox; the engine transitions
    /// to "awaiting head" so the response of `line` is parsed when
    /// it arrives.
    ///
    /// `binary_len` should be `Some(N)` when the command's expected
    /// reply is `203 Binary` with `N` bytes of body. For other
    /// response shapes (line, multiline, upload-binary handshake)
    /// pass `None`; the engine reads them based on the wire status
    /// code. Use [`Self::submit_streaming`] for binary responses
    /// whose size isn't known up front (e.g. `getfile`, `screenshot`).
    pub fn submit(&mut self, line: &str, binary_len: Option<usize>) -> Result<(), SubmitError> {
        let expect = match binary_len {
            Some(n) => HeadExpect::EagerBinary(n),
            None => HeadExpect::NoBinary,
        };
        self.queue_submit(line, expect)
    }

    /// Submit a command whose 203 binary body the caller will stream
    /// itself. When the head arrives the engine emits
    /// [`ClientEvent::BinaryHead`] and parks in a `StreamingBody`
    /// state; the caller drains [`Self::take_inbox`], reads the rest
    /// of the body off the transport, and calls [`Self::end_stream`]
    /// to release the engine.
    ///
    /// A non-203 head (Line/Multiline/204/4xx) on a streaming submit
    /// flows through normally: the engine emits the corresponding
    /// `Response`/`RemoteError` event and transitions back to `Idle`.
    pub fn submit_streaming(&mut self, line: &str) -> Result<(), SubmitError> {
        self.queue_submit(line, HeadExpect::StreamBinary)
    }

    fn queue_submit(&mut self, line: &str, expect: HeadExpect) -> Result<(), SubmitError> {
        match self.state {
            State::NeedBanner => return Err(SubmitError::NotConnected),
            State::Idle => {}
            State::AwaitingHead(_)
            | State::ReadingMultiline { .. }
            | State::ReadingBinary { .. }
            | State::StreamingBody => return Err(SubmitError::CommandInFlight),
            State::Notifications => return Err(SubmitError::NotificationChannel),
            State::Closed | State::Failed => return Err(SubmitError::Unusable),
        }
        self.outbox.extend_from_slice(line.as_bytes());
        self.outbox.extend_from_slice(b"\r\n");
        self.state = State::AwaitingHead(expect);
        Ok(())
    }

    /// Drain any inbox bytes already buffered by the engine. Only
    /// meaningful right after a [`ClientEvent::BinaryHead`]: the
    /// returned bytes are the start of the streaming body, captured by
    /// the same read that pulled in the head line. In any other state
    /// returns whatever happens to be buffered (typically empty).
    pub fn take_inbox(&mut self) -> BytesMut {
        std::mem::take(&mut self.inbox)
    }

    /// Arm the engine to read the next response without sending any
    /// command line. Used after manual transport writes (e.g. an
    /// `sendfile` upload body) where the kit will respond with a
    /// status line that isn't tied to a normal `submit`. Transitions
    /// `Idle` -> `AwaitingHead(NoBinary)` so the next `recv` parses a
    /// fresh response head.
    pub fn expect_response(&mut self) -> Result<(), SubmitError> {
        self.arm_response(HeadExpect::NoBinary)
    }

    /// As [`Self::expect_response`], for a reply that is `203` with
    /// `len` bytes of body.
    pub fn expect_binary_response(&mut self, len: usize) -> Result<(), SubmitError> {
        self.arm_response(HeadExpect::EagerBinary(len))
    }

    fn arm_response(&mut self, expect: HeadExpect) -> Result<(), SubmitError> {
        match self.state {
            State::NeedBanner => Err(SubmitError::NotConnected),
            State::Idle => {
                self.state = State::AwaitingHead(expect);
                Ok(())
            }
            State::AwaitingHead(_)
            | State::ReadingMultiline { .. }
            | State::ReadingBinary { .. }
            | State::StreamingBody => Err(SubmitError::CommandInFlight),
            State::Notifications => Err(SubmitError::NotificationChannel),
            State::Closed | State::Failed => Err(SubmitError::Unusable),
        }
    }

    /// Treat every following line as a notification. Called after the
    /// console accepted `notify` with `205- now a notification channel`.
    pub fn enter_notification_mode(&mut self) -> Result<(), SubmitError> {
        match self.state {
            State::Idle => {
                self.state = State::Notifications;
                Ok(())
            }
            State::NeedBanner => Err(SubmitError::NotConnected),
            State::AwaitingHead(_)
            | State::ReadingMultiline { .. }
            | State::ReadingBinary { .. }
            | State::StreamingBody => Err(SubmitError::CommandInFlight),
            State::Notifications => Err(SubmitError::NotificationChannel),
            State::Closed | State::Failed => Err(SubmitError::Unusable),
        }
    }

    /// Return the engine to `Idle` after a streaming body has been
    /// fully read off the transport. Any bytes the caller over-read
    /// past the body end can be passed in `leftover`; they're folded
    /// back into the inbox so the next command's response can pick
    /// them up.
    ///
    /// No-op if the engine isn't in `StreamingBody`.
    pub fn end_stream(&mut self, leftover: &[u8]) {
        if !matches!(self.state, State::StreamingBody) {
            return;
        }
        self.state = State::Idle;
        if !leftover.is_empty() {
            self.inbox.extend_from_slice(leftover);
        }
    }

    /// Abandon a streaming body without having read it to the end.
    /// The unread bytes are still queued on the wire, so the framing
    /// position is lost: the engine is failed rather than returned to
    /// `Idle`, which would let the next command parse body bytes as a
    /// response head.
    pub fn abort_stream(&mut self, unread: Option<u64>) {
        if !matches!(self.state, State::StreamingBody) {
            return;
        }
        self.fail(Error::StreamAbandoned { unread });
    }

    /// Pull the next protocol event, advancing the state machine if
    /// needed. Returns `None` when no event is queued and the engine
    /// can't make further progress with the buffered input.
    pub fn poll(&mut self) -> Option<ClientEvent> {
        self.advance();
        self.events.pop_front()
    }

    /// Whether the engine is in a terminal state. Once true, no new
    /// commands can be submitted and no further events will fire.
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, State::Closed | State::Failed)
    }

    /// Drive the state machine forward until no more progress can be
    /// made on the current inbox / state. Idempotent.
    fn advance(&mut self) {
        while self.step() {}
    }

    /// One transition of the state machine. Returns `true` if
    /// something changed (so [`Self::advance`] should re-check) or
    /// `false` if we're stuck waiting for input.
    fn step(&mut self) -> bool {
        match &mut self.state {
            State::NeedBanner => {
                let Some(line) = self.try_take_line() else {
                    return false;
                };
                let head = match parse_response_head(&line) {
                    Ok(h) => h,
                    Err(e) => {
                        self.fail(e);
                        return true;
                    }
                };
                match head.code.try_classify() {
                    Classified::Success(SuccessCode::Connected) => {
                        self.state = State::Idle;
                        self.banner = Some(head.rest);
                        self.events.push_back(ClientEvent::Connected);
                        true
                    }
                    _ => {
                        self.fail(Error::Framing(FramingError::MissingBanner));
                        true
                    }
                }
            }
            State::Idle => {
                // Unsolicited bytes (e.g. async notifications) sit in
                // the inbox until the next command consumes them.
                false
            }
            State::AwaitingHead(expect) => {
                let expect = *expect;
                let Some(line) = self.try_take_line() else {
                    return false;
                };
                let head = match parse_response_head(&line) {
                    Ok(h) => h,
                    Err(e) => {
                        self.fail(e);
                        return true;
                    }
                };
                match head.code.try_classify() {
                    Classified::Error(code) => {
                        // 4xx is a per-command failure, not a session
                        // teardown: drop back to Idle so the caller can
                        // submit again.
                        self.events.push_back(ClientEvent::RemoteError {
                            code,
                            message: head.rest,
                        });
                        self.state = State::Idle;
                        true
                    }
                    Classified::Unknown(code) => {
                        self.fail(Error::UnknownStatusCode { raw: code.raw() });
                        true
                    }
                    Classified::Success(SuccessCode::MultilineFollows) => {
                        self.state = State::ReadingMultiline {
                            head: head.rest,
                            lines: Vec::new(),
                        };
                        true
                    }
                    Classified::Success(SuccessCode::BinaryFollows) => match expect {
                        HeadExpect::NoBinary => {
                            self.fail(Error::Transport(TransportError::MissingBinaryLen));
                            true
                        }
                        HeadExpect::EagerBinary(len) => {
                            self.state = State::ReadingBinary {
                                head: head.rest,
                                remaining: len,
                                data: Vec::with_capacity(len),
                            };
                            true
                        }
                        HeadExpect::StreamBinary => {
                            self.state = State::StreamingBody;
                            self.events
                                .push_back(ClientEvent::BinaryHead { head: head.rest });
                            true
                        }
                    },
                    Classified::Success(SuccessCode::SendBinary) => {
                        // 204 hands the conversation to the caller: it
                        // owns the upload bytes and pushes them into
                        // the outbox; the engine just returns to Idle.
                        self.events
                            .push_back(ClientEvent::Response(Response::SendBinary {
                                head: head.rest,
                            }));
                        self.state = State::Idle;
                        true
                    }
                    Classified::Success(
                        code @ (SuccessCode::Ok
                        | SuccessCode::Connected
                        | SuccessCode::Dedicated
                        | SuccessCode::Reserved206
                        | SuccessCode::FastPipe),
                    ) => {
                        self.events.push_back(ClientEvent::Response(Response::Line {
                            code,
                            head: head.rest,
                        }));
                        self.state = State::Idle;
                        true
                    }
                }
            }
            State::ReadingMultiline { .. } => {
                let Some(line) = self.try_take_line() else {
                    return false;
                };
                let State::ReadingMultiline { head, lines } = &mut self.state else {
                    unreachable!("we just matched ReadingMultiline");
                };
                if line == "." {
                    let head = std::mem::take(head);
                    let lines = std::mem::take(lines);
                    self.state = State::Idle;
                    self.events
                        .push_back(ClientEvent::Response(Response::Multiline { head, lines }));
                } else {
                    lines.push(line);
                }
                true
            }
            State::ReadingBinary {
                remaining, data, ..
            } => {
                if *remaining == 0 {
                    let State::ReadingBinary { head, data, .. } =
                        std::mem::replace(&mut self.state, State::Idle)
                    else {
                        unreachable!();
                    };
                    self.events
                        .push_back(ClientEvent::Response(Response::Binary { head, data }));
                    return true;
                }
                if self.inbox.is_empty() {
                    return false;
                }
                let take = (*remaining).min(self.inbox.len());
                let chunk = self.inbox.split_to(take);
                data.extend_from_slice(&chunk);
                *remaining -= take;
                true
            }
            State::Notifications => {
                let Some(line) = self.try_take_line() else {
                    return false;
                };
                self.events.push_back(ClientEvent::Notification(line));
                true
            }
            State::StreamingBody | State::Closed | State::Failed => false,
        }
    }

    /// Try to extract a single CRLF-terminated line from the inbox.
    /// Returns `None` if no full line is available yet. On a non-UTF-8
    /// or oversize line the engine transitions to Failed and `None`
    /// is returned so the outer loop notices via the queued event.
    fn try_take_line(&mut self) -> Option<String> {
        let Some(pos) = memchr(b'\n', &self.inbox) else {
            // An unterminated line must be capped here: without this the
            // peer can grow the inbox without bound by never sending LF.
            if self.inbox.len() > MAX_LINE_LEN {
                self.fail(Error::Framing(FramingError::LineTooLong));
            }
            return None;
        };
        let end = if pos > 0 && self.inbox[pos - 1] == b'\r' {
            pos - 1
        } else {
            pos
        };
        let take = pos + 1; // include the LF
        if end > MAX_LINE_LEN {
            self.fail(Error::Framing(FramingError::LineTooLong));
            return None;
        }
        let line_bytes = self.inbox.split_to(take);
        match std::str::from_utf8(&line_bytes[..end]) {
            Ok(s) => Some(s.to_owned()),
            Err(_) => {
                self.fail(Error::Framing(FramingError::NonUtf8Line));
                None
            }
        }
    }

    fn fail(&mut self, e: Error) {
        self.state = State::Failed;
        self.events.push_back(ClientEvent::Failed(Box::new(e)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive(engine: &mut ClientEngine) -> Vec<ClientEvent> {
        let mut out = Vec::new();
        while let Some(ev) = engine.poll() {
            out.push(ev);
        }
        out
    }

    fn drain_send(engine: &mut ClientEngine) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = engine.send(&mut buf);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    #[test]
    fn banner_yields_connected_and_unblocks_submit() {
        let mut e = ClientEngine::new();
        assert!(matches!(
            e.submit("ping", None),
            Err(SubmitError::NotConnected)
        ));
        e.recv(b"201- connected\r\n");
        let evs = drive(&mut e);
        assert_eq!(evs.len(), 1);
        assert!(matches!(evs[0], ClientEvent::Connected));
        // Now submit works.
        e.submit("ping", None).unwrap();
        assert_eq!(drain_send(&mut e), b"ping\r\n");
    }

    #[test]
    fn line_response_parses_into_response_line() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.submit("ping", None).unwrap();
        let _ = drain_send(&mut e);
        e.recv(b"200- pong\r\n");
        let evs = drive(&mut e);
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            ClientEvent::Response(Response::Line { code, head }) => {
                assert_eq!(*code, SuccessCode::Ok);
                assert_eq!(head, "pong");
            }
            other => panic!("got {other:?}"),
        }
        // Ready for another command.
        e.submit("ping", None).unwrap();
    }

    #[test]
    fn multiline_response_collects_lines_until_dot() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.submit("modules", None).unwrap();
        let _ = drain_send(&mut e);
        e.recv(b"202- multiline follows\r\nname=\"a\"\r\nname=\"b\"\r\n.\r\n");
        let evs = drive(&mut e);
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            ClientEvent::Response(Response::Multiline { head, lines }) => {
                assert_eq!(head, "multiline follows");
                assert_eq!(
                    lines,
                    &vec!["name=\"a\"".to_string(), "name=\"b\"".to_string()]
                );
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn binary_response_collects_exact_byte_count() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.submit("getmem", Some(8)).unwrap();
        let _ = drain_send(&mut e);
        e.recv(b"203- binary follows\r\n");
        e.recv(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let evs = drive(&mut e);
        match &evs[0] {
            ClientEvent::Response(Response::Binary { head, data }) => {
                assert_eq!(head, "binary follows");
                assert_eq!(data, &vec![1u8, 2, 3, 4, 5, 6, 7, 8]);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn binary_body_arriving_in_pieces_is_reassembled() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.submit("getmem", Some(6)).unwrap();
        let _ = drain_send(&mut e);
        e.recv(b"203- binary follows\r\n");
        e.recv(&[0xAA, 0xBB]);
        // Mid-stream poll yields nothing -- still waiting for bytes.
        assert!(e.poll().is_none());
        e.recv(&[0xCC, 0xDD, 0xEE]);
        assert!(e.poll().is_none());
        e.recv(&[0xFF]);
        match e.poll() {
            Some(ClientEvent::Response(Response::Binary { data, .. })) => {
                assert_eq!(data, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn remote_error_is_per_command_not_terminal() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.submit("badcmd", None).unwrap();
        let _ = drain_send(&mut e);
        e.recv(b"407- unknown command\r\n");
        let evs = drive(&mut e);
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            ClientEvent::RemoteError { code, message } => {
                assert_eq!(code.raw(), 407);
                assert_eq!(message, "unknown command");
            }
            other => panic!("got {other:?}"),
        }
        // Connection survives -- another command can still go through.
        assert!(!e.is_terminal());
        e.submit("ping", None).unwrap();
        let _ = drain_send(&mut e);
        e.recv(b"200- pong\r\n");
        assert!(matches!(
            e.poll(),
            Some(ClientEvent::Response(Response::Line { .. }))
        ));
    }

    #[test]
    fn submit_while_command_in_flight_is_rejected() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.submit("first", None).unwrap();
        // No response yet, so a second submit must be rejected.
        assert!(matches!(
            e.submit("second", None),
            Err(SubmitError::CommandInFlight)
        ));
    }

    #[test]
    fn close_read_emits_closed_event() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.close_read();
        let evs = drive(&mut e);
        assert_eq!(evs.len(), 1);
        assert!(matches!(evs[0], ClientEvent::Closed));
        assert!(matches!(e.submit("ping", None), Err(SubmitError::Unusable)));
    }

    #[test]
    fn non_201_banner_fails_engine() {
        let mut e = ClientEngine::new();
        e.recv(b"200- OK\r\n");
        let evs = drive(&mut e);
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            ClientEvent::Failed(err) => assert!(matches!(
                err.as_ref(),
                Error::Framing(FramingError::MissingBanner)
            )),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn malformed_head_fails_engine() {
        let mut e = ClientEngine::new();
        e.recv(b"abc bogus\r\n");
        let evs = drive(&mut e);
        assert_eq!(evs.len(), 1);
        assert!(matches!(evs[0], ClientEvent::Failed(_)));
    }

    #[test]
    fn binary_response_without_binary_len_fails_engine() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.submit("getmem", None).unwrap();
        let _ = drain_send(&mut e);
        e.recv(b"203- binary follows\r\n");
        let evs = drive(&mut e);
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            ClientEvent::Failed(err) => {
                assert!(matches!(
                    err.as_ref(),
                    Error::Transport(TransportError::MissingBinaryLen)
                ))
            }
            other => panic!("got {other:?}"),
        }
        assert!(e.is_terminal());
    }

    #[test]
    fn head_split_across_recv_calls_is_buffered() {
        let mut e = ClientEngine::new();
        e.recv(b"201-");
        assert!(e.poll().is_none());
        e.recv(b" connected\r");
        assert!(e.poll().is_none());
        e.recv(b"\n");
        assert!(matches!(e.poll(), Some(ClientEvent::Connected)));
    }

    #[test]
    fn lf_only_terminator_is_accepted() {
        // Some XBDM kits / proxies normalize line endings. The
        // framing layer should accept bare LF the same as CRLF.
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\n");
        assert!(matches!(e.poll(), Some(ClientEvent::Connected)));
    }

    #[test]
    fn streaming_submit_emits_binary_head_and_releases_inbox() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.submit_streaming("getfile NAME=\"x\"").unwrap();
        let _ = drain_send(&mut e);
        e.recv(b"203- binary response follows\r\n\x04\x00\x00\x00DATA");
        let evs = drive(&mut e);
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            ClientEvent::BinaryHead { head } => assert_eq!(head, "binary response follows"),
            other => panic!("got {other:?}"),
        }
        let leftover = e.take_inbox();
        assert_eq!(&leftover[..], b"\x04\x00\x00\x00DATA");
        // Submit must be rejected while streaming.
        assert!(matches!(
            e.submit("ping", None),
            Err(SubmitError::CommandInFlight)
        ));
        // Subsequent recv is ignored while streaming (caller owns the wire).
        e.recv(b"junk");
        assert!(e.take_inbox().is_empty());
        // Returning over-read bytes via end_stream re-arms the engine.
        e.end_stream(b"200- pong\r\n");
        e.submit("ping", None).unwrap();
        let _ = drain_send(&mut e);
        match e.poll() {
            Some(ClientEvent::Response(Response::Line { code, head })) => {
                assert_eq!(code, SuccessCode::Ok);
                assert_eq!(head, "pong");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn streaming_submit_handles_non_binary_head_normally() {
        // A streaming submit doesn't force 203: a 4xx should still flow
        // through as a RemoteError so the connection isn't tied up.
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.submit_streaming("getfile NAME=\"missing\"").unwrap();
        let _ = drain_send(&mut e);
        e.recv(b"402- file not found\r\n");
        let evs = drive(&mut e);
        match &evs[0] {
            ClientEvent::RemoteError { code, message } => {
                assert_eq!(code.raw(), 402);
                assert_eq!(message, "file not found");
            }
            other => panic!("got {other:?}"),
        }
        // Engine is back at Idle.
        e.submit("ping", None).unwrap();
    }

    #[test]
    fn expect_response_arms_engine_for_unprompted_reply() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        // 204 handshake on a sendfile-style command: the kit will reply
        // 200 OK after the body, which we read by calling
        // expect_response() and pumping again.
        e.submit("sendfile NAME=\"a\" LENGTH=0x4", None).unwrap();
        let _ = drain_send(&mut e);
        e.recv(b"204- send binary\r\n");
        let evs = drive(&mut e);
        assert!(matches!(
            evs[0],
            ClientEvent::Response(Response::SendBinary { .. })
        ));
        e.expect_response().unwrap();
        e.recv(b"200- ok\r\n");
        match e.poll() {
            Some(ClientEvent::Response(Response::Line {
                code: SuccessCode::Ok,
                ..
            })) => {}
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn unterminated_line_is_capped_before_a_terminator_arrives() {
        let mut engine = ClientEngine::new();
        engine.recv(b"201- connected\r\n");
        drive(&mut engine);
        engine.submit("dbgname", None).unwrap();

        // A peer that never sends LF must not grow the inbox forever.
        let chunk = vec![b'A'; 4096];
        let mut events = Vec::new();
        for _ in 0..8 {
            engine.recv(&chunk);
            events.extend(drive(&mut engine));
        }
        assert!(
            matches!(
                events.last(),
                Some(ClientEvent::Failed(e)) if matches!(**e, Error::Framing(FramingError::LineTooLong))
            ),
            "expected LineTooLong, got {events:?}"
        );
        assert!(engine.is_terminal());
    }

    #[test]
    fn close_read_mid_line_surfaces_closed() {
        let mut engine = ClientEngine::new();
        engine.recv(b"201- connected\r\n");
        drive(&mut engine);
        engine.submit("dbgname", None).unwrap();
        engine.recv(b"200- partial");
        assert!(drive(&mut engine).is_empty());

        engine.close_read();
        let events = drive(&mut engine);
        assert!(matches!(events.as_slice(), [ClientEvent::Closed]));
    }

    #[test]
    fn line_response_leaves_trailing_bytes_for_the_next_response() {
        let mut engine = ClientEngine::new();
        engine.recv(b"201- connected\r\n");
        drive(&mut engine);
        engine.submit("dbgname", None).unwrap();

        // Two responses arriving in one read: the second must survive.
        engine.recv(b"200- first\r\n200- second\r\n");
        let events = drive(&mut engine);
        assert_eq!(events.len(), 1);
        engine.submit("dbgname", None).unwrap();
        let events = drive(&mut engine);
        assert!(
            matches!(
                events.as_slice(),
                [ClientEvent::Response(Response::Line { head, .. })] if head == "second"
            ),
            "got {events:?}"
        );
    }

    #[test]
    fn abort_stream_fails_engine_instead_of_returning_to_idle() {
        let mut engine = ClientEngine::new();
        engine.recv(b"201- connected\r\n");
        drive(&mut engine);
        engine.submit_streaming("getfile").unwrap();
        engine.recv(b"203- binary response follows\r\n");
        drive(&mut engine);

        engine.abort_stream(Some(64));
        let events = drive(&mut engine);
        assert!(
            matches!(
                events.as_slice(),
                [ClientEvent::Failed(e)] if matches!(
                    **e,
                    Error::StreamAbandoned { unread: Some(64) }
                )
            ),
            "got {events:?}"
        );
        assert!(engine.is_terminal());
        // A failed engine must not accept another command.
        assert!(matches!(
            engine.submit("dbgname", None),
            Err(SubmitError::Unusable)
        ));
    }

    #[test]
    fn end_stream_outside_streaming_state_is_noop() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.end_stream(b"junk");
        // Idle with no leftovers absorbed: a fresh submit still works.
        e.submit("ping", None).unwrap();
    }

    #[test]
    fn send_drains_outbox_in_chunks() {
        let mut e = ClientEngine::new();
        e.recv(b"201- connected\r\n");
        let _ = drive(&mut e);
        e.submit("dbgname", None).unwrap();
        let mut buf = [0u8; 4];
        let n1 = e.send(&mut buf);
        assert_eq!(n1, 4);
        assert_eq!(&buf[..n1], b"dbgn");
        let n2 = e.send(&mut buf);
        assert_eq!(n2, 4);
        assert_eq!(&buf[..n2], b"ame\r");
        let n3 = e.send(&mut buf);
        assert_eq!(n3, 1);
        assert_eq!(&buf[..n3], b"\n");
        assert_eq!(e.send(&mut buf), 0);
    }
}
