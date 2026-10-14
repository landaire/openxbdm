//! PIX (Performance Investigator for Xbox) helpers.
//!
//! The devkit XBDM (xdk-main-nov11) exposes `pixcmd` and `pixpreview`
//! for the PIX *profiler* (produces `.pix2` trace files under
//! `E:\pix\`). These are NOT the video capture path that xbmovie
//! drives. xbmovie speaks a separate `PIX!{BeginCaptureFileCreation}`
//! / `{EndCapture}` dialect which, on xbdm, is registered by a
//! **loadable extension XEX** via `dbgextld`. The full xbdm command
//! name table at `0x91f05000..0x91f0589c` has no `video`/`movie`/
//! `capture` entries, confirming that the built-in kernel has no
//! first-party video capture command -- it's all extension-gated.
//!
//! This module therefore exposes two things:
//!
//! 1. [`session`] -- a raw wrapper around `pixcmd <subcommand>` for
//!    PIX-profiler experiments plus a parser for the PIX async
//!    notifications (`PIX!MovieData`, `PIX!Gpu`, etc.) observed in
//!    .rdata. Each pixcmd sub-handler takes POSITIONAL u32 args (not
//!    keywords), parsed via `xbdm 0x91f53fa0 :: ParseU32`.
//!
//! 2. [`profile`] -- host-side capture profile metadata (XML blobs
//!    xbmovie ships; used once we actually have an encoder to feed).
//!
//! If you want live movie capture on a console whose xbdm does have
//! the extension resident, the `PIX!{...}` wire shape still belongs
//! here eventually, but not until we observe it on a console that
//! accepts it.

pub mod profile;
pub mod session;
pub mod xbm;

pub use profile::CaptureProfile;
pub use profile::HdmiFrameRate;
pub use profile::Resolution;
pub use session::CaptureSession;
pub use session::ConnectOutcome;
pub use session::Notification;
pub use session::PIX_VERSION;
pub use session::PixCmd;
pub use session::PixError;
pub use xbm::FrameCursor;
pub use xbm::FrameHeader;
pub use xbm::FrameRef;
pub use xbm::MagicVariant;
pub use xbm::XbmError;
pub use xbm::XbmHeader;
pub use xbm::detile_frame;
