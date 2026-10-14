//! Two distinct PIX wire protocols live on an Xbox 360 devkit. This
//! module exposes helpers for both.
//!
//! # 1. `pixcmd` - the PIX profiler (lives in xbdm itself)
//!
//! xbdm registers a first-party `pixcmd` command. Its handler
//! at `xbdm 0x91f56b88` is a first-letter switch over positional
//! `u32`-argument subcommands that drive the PIX performance profiler
//! (outputs `.pix2` trace files, emits `PIX!MovieData` / `PIX!Gpu` /
//! `PIX!Trace` style notifications). [`PixCmd`] is the thin wrapper
//! for this.
//!
//! # 2. `PIX!{Token}` - the xbmovie video capture (lives in the title)
//!
//! Any running title (dash.xex, xshell.xex, bootanim.xex, etc.) that
//! links the D3D runtime registers itself as the handler for the
//! `PIX!` command prefix. When a client sends `PIX!{BeginCapture}`
//! over xbdm, xbdm forwards it to the registered title process, which
//! runs the D3D capture hooks and writes the intermediate stream to
//! `\??\xbmovie:` on the console's HDD. xbmovie.exe and
//! [`CaptureSession`] both speak this protocol.
//!
//! The full token set we observed inside dash.xex / xshell.xex (all
//! clustered at offset `0xbc00..0xbe00` in the decrypted PE) is:
//!
//! ```text
//! {Connect}  {Version} <u32>  {Disconnect}
//! {LimitCaptureSize} <megabytes>
//! {BeginCaptureFileCreation} <remote_path>
//! {EndCaptureFileCreation}
//! {BeginCapture}
//! {EndCapture}
//! ```
//!
//! Single-line responses are `200- PIX!OK` on success and
//! `200- PIX!NO` on refusal. Two notification lines arrive on the
//! notify channel:
//!
//! ```text
//! PIX!{CaptureFileCreationEnded}<index>
//! PIX!{CaptureEnded}
//! ```
//!
//! # Prerequisite: a title must be running
//!
//! If no title is running (or the one that's running hasn't
//! registered a PIX handler) the commands still reach xbdm but there
//! is nobody to handle them; xbdm replies with an empty/ambiguous
//! response and nothing happens. On a fresh devkit the dashboard
//! (xshell.xex) normally registers itself and video capture Just
//! Works; on a halted or no-title state the session will appear to
//! succeed with zero segments emitted.

use core::fmt::Write as _;

use futures_util::io::AsyncRead;
use futures_util::io::AsyncWrite;

use crate::client::Client;
use crate::client::Connected;
use crate::error::Error;
use crate::protocol::Response;
use crate::protocol::SuccessCode;

/// Protocol version xbmovie sends on `{Version}`. Split low/high
/// halves give `major = 1`, `minor = 1`, encoded as `0x0001_0001`.
pub const PIX_VERSION: u32 = 0x0001_0001;

/// Typed error for both pixcmd and `PIX!{...}` interactions. Some
/// variants are shared; callers can discriminate with matches.
#[derive(Debug, thiserror::Error)]
pub enum PixError {
    /// xbdm / title replied with a non-2xx (or 2xx with unexpected shape).
    #[error("pix wire replied unexpectedly: {response:?}")]
    UnexpectedResponse { response: Response },
    /// Well-known "Cannot execute - previous command still pending" body.
    #[error("pix runtime reported busy: {message:?}")]
    Busy { message: String },
    /// xbmovie restricts visible filenames to 38 bytes.
    #[error("pix capture filename exceeds xbmovie's 38-byte visible-name limit")]
    CaptureNameTooLong,
}

/// One line off the notification channel, parsed into the PIX event
/// taxonomy we've catalogued. Both xbdm-emitted profiler notifications
/// and title-emitted capture notifications arrive via the same stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    // xbmovie / capture (emitted by the title).
    /// `PIX!{CaptureFileCreationEnded}<index>` -- segment done.
    CaptureFileCreationEnded { index: u32 },
    /// `PIX!{CaptureEnded}` -- whole session finished.
    CaptureEnded,

    // PIX profiler (emitted by xbdm's pixcmd subsystem).
    /// `PIX!MovieData ...`.
    MovieData(String),
    /// `PIX!Resource <name>`.
    Resource(String),
    /// `PIX!VideoOp <detail>` / `PIX!VideoOpError <detail>`.
    VideoOp { error: bool, detail: String },
    /// Any of the fixed status tokens: Trace / Pause / NoFrame / Gpu /
    /// BadD3dVersion / NO / Timing / StreamEngineOutOfMemory /
    /// CounterDataAvailable / NoHarddrive / Reboot / NotActive
    /// ResourceCapture / StartFailed ResourceCapture.
    Status(String),
    /// Any `PIX!...` line we haven't modelled.
    Other(String),
}

impl Notification {
    /// Parse one CRLF-stripped line. Returns `None` for lines that
    /// aren't `PIX!`-prefixed.
    pub fn parse(line: &str) -> Option<Self> {
        let body = line.strip_prefix("PIX!")?;
        // Capture notifications first -- they're brace-wrapped so they
        // can't collide with the profiler token names.
        if let Some(rest) = body.strip_prefix("{CaptureFileCreationEnded}") {
            let index: u32 = rest.trim().parse().unwrap_or(0);
            return Some(Notification::CaptureFileCreationEnded { index });
        }
        if body.starts_with("{CaptureEnded}") {
            return Some(Notification::CaptureEnded);
        }
        if let Some(rest) = body.strip_prefix("MovieData") {
            return Some(Notification::MovieData(rest.trim_start().to_owned()));
        }
        if let Some(rest) = body.strip_prefix("VideoOpError") {
            return Some(Notification::VideoOp { error: true, detail: rest.trim_start().to_owned() });
        }
        if let Some(rest) = body.strip_prefix("VideoOp") {
            return Some(Notification::VideoOp { error: false, detail: rest.trim_start().to_owned() });
        }
        if let Some(rest) = body.strip_prefix("Resource") {
            return Some(Notification::Resource(rest.trim_start().to_owned()));
        }
        const STATUS_TOKENS: &[&str] = &[
            "NotActive ResourceCapture",
            "StartFailed ResourceCapture",
            "Reboot",
            "NoHarddrive",
            "Trace",
            "Pause",
            "NoFrame",
            "Gpu",
            "BadD3dVersion",
            "NO",
            "Timing",
            "StreamEngineOutOfMemory",
            "CounterDataAvailable",
        ];
        for tok in STATUS_TOKENS {
            if body == *tok || body.starts_with(&format!("{tok} ")) {
                return Some(Notification::Status(body.to_owned()));
            }
        }
        Some(Notification::Other(body.to_owned()))
    }
}

/// Thin wrapper over `pixcmd <subcommand>` for driving the PIX
/// profiler. Subcommands take positional `u32` args. Call [`PixCmd::raw`]
/// with the tokens you want to send verbatim.
pub struct PixCmd<'a, T> {
    client: &'a mut Client<T, Connected>,
}

impl<'a, T> core::fmt::Debug for PixCmd<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PixCmd").finish_non_exhaustive()
    }
}

impl<'a, T> PixCmd<'a, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(client: &'a mut Client<T, Connected>) -> Self {
        Self { client }
    }

    /// Send `pixcmd <subcommand>` and return the raw response.
    pub async fn raw(&mut self, subcommand: &str) -> Result<Response, rootcause::Report<Error>> {
        let mut wire = String::with_capacity("pixcmd ".len() + subcommand.len());
        wire.push_str("pixcmd");
        if !subcommand.is_empty() {
            wire.push(' ');
            wire.push_str(subcommand);
        }
        self.client.send_raw(&wire).await
    }
}

/// Bound session around a connected client that drives the
/// `PIX!{Token}` capture protocol implemented by the running title.
pub struct CaptureSession<'a, T> {
    client: &'a mut Client<T, Connected>,
}

impl<'a, T> core::fmt::Debug for CaptureSession<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CaptureSession").finish_non_exhaustive()
    }
}

/// Outcome of [`CaptureSession::connect`]: a session plus whether the
/// `{Connect}` reply looked like a real PIX handler (`head` contained
/// `PIX`) or a plain xbdm no-op (`200- OK`). Callers can inspect
/// `handler_detected` and decide whether to proceed.
#[derive(Debug)]
pub struct ConnectOutcome<'a, T> {
    pub session: CaptureSession<'a, T>,
    pub handler_detected: bool,
}

impl<'a, T> CaptureSession<'a, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Perform the xbmovie handshake: `{Connect}` then
    /// `{Version} <ver>`.
    ///
    /// Returns a session regardless of whether a title was actually
    /// registered as the PIX handler.
    pub async fn connect(
        client: &'a mut Client<T, Connected>,
    ) -> Result<ConnectOutcome<'a, T>, rootcause::Report<Error>> {
        let mut session = CaptureSession { client };
        let resp = session.send_raw("{Connect}").await?;
        let handler_detected = matches!(
            &resp,
            Response::Line { head, .. } if head.contains("PIX")
        );
        session.send_raw(&format!("{{Version}} {}", PIX_VERSION)).await?;
        Ok(ConnectOutcome { session, handler_detected })
    }

    /// Cap the per-segment file size in megabytes. xbmovie's default
    /// is 512 MB.
    pub async fn limit_capture_size_mb(&mut self, megabytes: u32) -> Result<(), rootcause::Report<Error>> {
        self.send_ok(&format!("{{LimitCaptureSize}} {}", megabytes)).await
    }

    /// Pick the output file. Path is sent verbatim; xbmovie uses the
    /// full NT form `\Device\Harddisk0\Partition1\DEVKIT\<name>.xbm`.
    /// The capture is asynchronous -- success here only means the
    /// handler accepted the path; actual file-creation completion is
    /// signalled by a `PIX!{CaptureFileCreationEnded} <hresult>` on
    /// the notification channel and should be waited for before
    /// calling [`CaptureSession::begin_capture`].
    pub async fn begin_capture_file_creation(&mut self, path: &str) -> Result<(), rootcause::Report<Error>> {
        self.send_ok(&format!("{{BeginCaptureFileCreation}} {}", path)).await
    }

    pub async fn begin_capture(&mut self) -> Result<(), rootcause::Report<Error>> {
        self.send_ok("{BeginCapture}").await
    }

    pub async fn end_capture(&mut self) -> Result<(), rootcause::Report<Error>> {
        self.send_ok("{EndCapture}").await
    }

    pub async fn end_capture_file_creation(&mut self) -> Result<(), rootcause::Report<Error>> {
        self.send_ok("{EndCaptureFileCreation}").await
    }

    pub async fn disconnect(mut self) -> Result<(), rootcause::Report<Error>> {
        self.send_ok("{Disconnect}").await
    }

    /// Send a `PIX!<body>` line and expect a 200 single-line success.
    /// Logs at debug level whether the response looked like a real
    /// PIX handler reply (`head` starts with `PIX`) vs. a stock xbdm
    /// no-op (`OK`); this lets callers reason about whether the
    /// active title is actually processing PIX traffic.
    async fn send_ok(&mut self, body: &str) -> Result<(), rootcause::Report<Error>> {
        let response = self.send_raw(body).await?;
        match response {
            Response::Line { code: SuccessCode::Ok, head } => {
                if head.contains("Cannot execute") {
                    return Err(rootcause::Report::new(Error::from(PixError::Busy { message: head })));
                }
                if head.contains("PIX") {
                    tracing::debug!(target: "openxbdm_client::pix", command = %body, %head, "pix ok");
                } else {
                    tracing::debug!(target: "openxbdm_client::pix", command = %body, %head, "pix no-op (no title handler?)");
                }
                Ok(())
            }
            other => {
                let mut msg = String::new();
                let _ = write!(msg, "expected 200 PIX!OK, got {other:?}");
                Err(rootcause::Report::new(Error::from(PixError::UnexpectedResponse { response: other })).attach(msg))
            }
        }
    }

    /// Low-level helper: send `PIX!m <body>` verbatim and return the
    /// raw parsed response. The literal `m` and following space are
    /// part of the handler's expected prefix (captured from xbmovie
    /// wire traffic against the registered PIX handler); dropping
    /// either one silently falls through to a no-op `200- OK`.
    async fn send_raw(&mut self, body: &str) -> Result<Response, rootcause::Report<Error>> {
        let mut wire = String::with_capacity(body.len() + 6);
        wire.push_str("PIX!m ");
        wire.push_str(body);
        self.client.send_raw(&wire).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_segment_done_notification() {
        let ev = Notification::parse("PIX!{CaptureFileCreationEnded}3").unwrap();
        assert_eq!(ev, Notification::CaptureFileCreationEnded { index: 3 });
    }

    #[test]
    fn parses_capture_ended() {
        assert_eq!(Notification::parse("PIX!{CaptureEnded}"), Some(Notification::CaptureEnded));
    }

    #[test]
    fn parses_movie_data_bare() {
        assert_eq!(Notification::parse("PIX!MovieData"), Some(Notification::MovieData(String::new())));
    }

    #[test]
    fn parses_video_op_variants() {
        assert_eq!(
            Notification::parse("PIX!VideoOpError timeout"),
            Some(Notification::VideoOp { error: true, detail: "timeout".into() })
        );
        assert_eq!(
            Notification::parse("PIX!VideoOp paused"),
            Some(Notification::VideoOp { error: false, detail: "paused".into() })
        );
    }

    #[test]
    fn parses_status_tokens() {
        for tok in [
            "PIX!Trace",
            "PIX!Pause",
            "PIX!NoFrame",
            "PIX!Gpu",
            "PIX!BadD3dVersion",
            "PIX!NO",
            "PIX!Timing",
            "PIX!StreamEngineOutOfMemory",
            "PIX!CounterDataAvailable",
            "PIX!NoHarddrive",
            "PIX!Reboot",
            "PIX!NotActive ResourceCapture",
            "PIX!StartFailed ResourceCapture",
        ] {
            assert!(matches!(Notification::parse(tok), Some(Notification::Status(_))));
        }
    }

    #[test]
    fn rejects_non_pix_lines() {
        assert_eq!(Notification::parse("FOO!{Stuff}"), None);
    }
}
