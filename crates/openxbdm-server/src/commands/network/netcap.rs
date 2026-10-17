//! `netcap`: Ethernet frame capture to a file.

pub mod capture_file;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;

use self::capture_file::CaptureFileError;
use super::NetworkError;
use super::WsaError;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// Size of the `file=` buffer, terminator included.
const FILE_PARAMETER_SIZE: usize = 0x104;
/// Size of the translated path buffer; the translator stops at this many
/// bytes.
const OBJECT_PATH_SIZE: usize = 0x104;

xbox360_sys::flags! {
    /// `start` flags (0x91f9f694).
    pub struct CaptureFlags(u32) {
        /// Put the adapter in promiscuous mode for the capture.
        PROMISCUOUS = 0x1,
        /// Skip received frames sent to the broadcast address.
        SKIP_BROADCAST = 0x2,
        /// Skip received frames sent to other group addresses.
        SKIP_MULTICAST = 0x4,
        /// Keep capturing when the title exits; also selects the smaller
        /// buffer defaults and the allocation pool that survives title
        /// termination.
        PERSISTENT = 0x8,
    }
}

impl CaptureFlags {
    /// Whether the receive callback leaves `frame` out of the capture
    /// (0x91f34e78). Received frames only; transmitted frames are always
    /// recorded.
    pub fn skips_received(self, frame: &[u8]) -> bool {
        if !self.intersects(Self::SKIP_BROADCAST.union(Self::SKIP_MULTICAST)) || frame.len() <= 6 {
            return false;
        }
        if frame[..6] == [0xff; 6] {
            self.contains(Self::SKIP_BROADCAST)
        } else {
            frame[0] & 1 != 0 && self.contains(Self::SKIP_MULTICAST)
        }
    }
}

/// Write buffer of the capture file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferSizes {
    /// Bytes of the write buffer.
    pub buffer: u32,
    /// Buffered bytes that wake the writer thread.
    pub chunk: u32,
}

impl BufferSizes {
    /// Sizes for the `buffersize` parameter (`None` when absent or 0).
    pub fn new(buffer: Option<u32>, flags: CaptureFlags) -> Self {
        match buffer {
            Some(buffer) => Self {
                buffer,
                chunk: (buffer / 2).min(0x4000),
            },
            None if flags.contains(CaptureFlags::PERSISTENT) => Self {
                buffer: 0x2000,
                chunk: 0x1000,
            },
            None => Self {
                buffer: 0x20000,
                chunk: 0x4000,
            },
        }
    }
}

/// Parameters of a new capture.
#[derive(Debug, Clone, Copy)]
pub struct CaptureRequest<'a> {
    /// Object name of the capture file, or the raw `file=` text when it is
    /// not a drive path.
    pub path: &'a [u8],
    /// Total frame bytes the capture accepts (`maxframedata`).
    pub data_limit: capture_file::DataLimit,
    pub sizes: BufferSizes,
    pub flags: CaptureFlags,
}

/// Result of finishing a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureClose {
    /// Result of writing the frame table and closing the file (0x91f69d18).
    pub result: Result<(), CaptureFileError>,
    /// Frames in the file.
    pub frames: u32,
}

/// Platform services `netcap` needs.
pub trait Backend {
    /// Create the capture context and the capture file (0x91f67f90,
    /// 0x91f69c10).
    fn open_capture(&mut self, request: &CaptureRequest<'_>) -> Result<(), CaptureFileError>;
    /// `XNetSetOpt(2, 0x1390, enable)`; true on success.
    fn set_promiscuous(&mut self, enable: bool) -> bool;
    /// Clear the frame callback error, then feed frames to the open capture
    /// with `flags`: chained into the network simulator when an instance
    /// exists, else through the Ethernet intercept callbacks, whose
    /// installation can fail.
    fn attach_capture(&mut self, flags: CaptureFlags) -> Result<(), WsaError>;
    /// Remove the callbacks `attach_capture` installed.
    fn detach_capture(&mut self);
    /// First failure a frame callback recorded (0x91f9f698).
    fn capture_error(&self) -> Option<CaptureFileError>;
    /// Finish and close the capture file, then free the context.
    fn close_capture(&mut self) -> CaptureClose;
}

/// Global state of `netcap`.
#[derive(Debug)]
pub struct State {
    /// Flags of the running capture (0x91f9f690 nonzero).
    capture: Option<CaptureFlags>,
}

impl State {
    pub const fn new() -> Self {
        Self { capture: None }
    }

    pub fn is_capturing(&self) -> bool {
        self.capture.is_some()
    }
}

/// `netcap start file=<name> [maxframedata=] [buffersize=] [flags=]` or
/// `netcap stop`.
pub(super) fn netcap(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.line.has("start") {
        start(invocation)
    } else if invocation.line.has("stop") {
        let text = stop(
            &mut invocation.state.network.netcap,
            &mut *invocation.backend,
        )?;
        invocation.set_text(format_args!("{text}"));
        text.status()?;
        Ok(Reply::Ok)
    } else {
        Err(ErrorCode::BadParameter.into())
    }
}

/// Title termination (0x91f38480): stop a capture without
/// [`CaptureFlags::PERSISTENT`].
pub(super) fn title_exited(state: &mut State, backend: &mut dyn crate::backend::Backend) {
    if state
        .capture
        .is_some_and(|flags| !flags.contains(CaptureFlags::PERSISTENT))
    {
        let _ = stop(state, backend);
    }
}

fn start(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line;
    // Absent and unparsable values read as 0, which selects the defaults.
    let dword = |name| line.dword(name).unwrap_or(0);
    let data_limit = dword("maxframedata");
    let buffer = dword("buffersize");
    let flags = CaptureFlags::from_bits_retain(dword("flags"));
    let Some(file) = line.param("file") else {
        return Err(ErrorCode::FilenameInvalid.into());
    };
    let mut name = [0u8; FILE_PARAMETER_SIZE];
    let name = file.copy_into(&mut name);

    match start_capture(
        invocation.state,
        invocation.backend,
        name,
        data_limit,
        buffer,
        flags,
    ) {
        Ok(()) => {
            invocation.set_text(format_args!("started"));
            Ok(Reply::Ok)
        }
        Err(error) => {
            invocation.set_text(format_args!("err=0x{:08x}", Hresult::from(error).0));
            Err(NetworkError::CaptureStart(error).into())
        }
    }
}

/// Why a capture did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    /// A capture runs.
    AlreadyCapturing,
    /// The Ethernet intercept callbacks are owned by another client.
    InterceptBusy,
    /// Installing the intercept callbacks failed.
    Intercept(WsaError),
    /// Creating the capture context or file failed.
    Open(CaptureFileError),
}

impl From<StartError> for Hresult {
    fn from(error: StartError) -> Self {
        match error {
            StartError::AlreadyCapturing => ErrorCode::NotStopped.hresult(),
            StartError::InterceptBusy => ErrorCode::NotDebuggable.hresult(),
            StartError::Intercept(error) => intercept_result(error),
            StartError::Open(error) => capture_result(error),
        }
    }
}

/// Open the capture and attach the callbacks (0x91f34f80).
pub fn start_capture(
    state: &mut crate::state::ServerState,
    backend: &mut dyn crate::backend::Backend,
    name: &[u8],
    data_limit: u32,
    buffer: u32,
    mut flags: CaptureFlags,
) -> Result<(), StartError> {
    if state.network.netcap.capture.is_some() {
        return Err(StartError::AlreadyCapturing);
    }
    let translated = state.filesystem.drives.translate(&mut *backend, name);
    let path = match &translated {
        Some(object) => {
            let bytes = object.as_bytes();
            &bytes[..bytes.len().min(OBJECT_PATH_SIZE)]
        }
        None => name,
    };
    let request = CaptureRequest {
        path,
        data_limit: capture_file::DataLimit(core::num::NonZeroU32::new(data_limit)),
        sizes: BufferSizes::new(
            core::num::NonZeroU32::new(buffer).map(core::num::NonZeroU32::get),
            flags,
        ),
        flags,
    };
    backend.open_capture(&request).map_err(StartError::Open)?;
    if flags.contains(CaptureFlags::PROMISCUOUS) && !backend.set_promiscuous(true) {
        flags.remove(CaptureFlags::PROMISCUOUS);
    }
    if let Err(error) = backend.attach_capture(flags) {
        // Stock leaves promiscuous mode on here.
        let _ = backend.close_capture();
        return Err(if error == WsaError::ALREADY {
            StartError::InterceptBusy
        } else {
            StartError::Intercept(error)
        });
    }
    state.network.netcap.capture = Some(flags);
    Ok(())
}

/// The result a failed capture reports: kernel failures map through the
/// status table (0x91f41f18), falling back to the NT-facility result.
fn capture_result(error: CaptureFileError) -> Hresult {
    match error {
        CaptureFileError::Kernel(error) => {
            CommandError::from_kernel(error, CommandError::Kernel(error)).into()
        }
        error => error.into(),
    }
}

/// An intercept failure as a result. Stock maps every failed start result
/// that carries the NT facility bit through the status table, so a
/// negative intercept value with that bit reads as a kernel status.
fn intercept_result(error: WsaError) -> Hresult {
    let result = Hresult::from(Win32Error::from(error));
    if result.is_failure()
        && result.0 & 0x1000_0000 != 0
        && let Some(status) = KernelError::from_status(NtStatus(result.0 & !0x1000_0000))
    {
        capture_result(CaptureFileError::Kernel(status))
    } else {
        result
    }
}

/// Reply of a stopped capture (0x91f351e0 text).
enum StopText {
    Stopped {
        frames: u32,
    },
    Failed {
        error: CaptureFileError,
        frames: u32,
    },
    /// Frames were lost to a full write buffer; the status reports it.
    FramesLost {
        frames: u32,
    },
}

impl StopText {
    /// Status of the stop.
    fn status(&self) -> Result<(), NetworkError> {
        match self {
            Self::FramesLost { .. } => Err(NetworkError::FramesLost),
            Self::Stopped { .. } | Self::Failed { .. } => Ok(()),
        }
    }
}

impl core::fmt::Display for StopText {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (error, frames) = match *self {
            Self::Stopped { frames } => return write!(formatter, "stopped frames={frames}"),
            Self::Failed { error, frames } => (capture_result(error), frames),
            Self::FramesLost { frames } => (NetworkError::FramesLost.into(), frames),
        };
        write!(formatter, "stopped err=0x{:08x} frames={frames}", error.0)
    }
}

/// Stop the capture (0x91f351e0).
pub fn stop_capture(
    state: &mut State,
    backend: &mut dyn crate::backend::Backend,
) -> Result<(), NetworkError> {
    stop(state, backend)?.status()
}

/// The first failure wins: a frame callback error, then the close result.
fn stop(
    state: &mut State,
    backend: &mut dyn crate::backend::Backend,
) -> Result<StopText, NetworkError> {
    let Some(flags) = state.capture.take() else {
        return Err(NetworkError::NotCapturing);
    };
    let callback_error = backend.capture_error();
    if flags.contains(CaptureFlags::PROMISCUOUS) {
        backend.set_promiscuous(false);
    }
    backend.detach_capture();
    let close = backend.close_capture();
    let frames = close.frames;
    Ok(match callback_error.or(close.result.err()) {
        Some(CaptureFileError::WriteFault) => StopText::FramesLost { frames },
        Some(error) => StopText::Failed { error, frames },
        None => StopText::Stopped { frames },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_sizes_follow_the_flags() {
        assert_eq!(
            BufferSizes::new(None, CaptureFlags::empty()),
            BufferSizes {
                buffer: 0x20000,
                chunk: 0x4000
            }
        );
        assert_eq!(
            BufferSizes::new(None, CaptureFlags::PERSISTENT),
            BufferSizes {
                buffer: 0x2000,
                chunk: 0x1000
            }
        );
        assert_eq!(
            BufferSizes::new(Some(0x3000), CaptureFlags::PERSISTENT),
            BufferSizes {
                buffer: 0x3000,
                chunk: 0x1800
            }
        );
        assert_eq!(
            BufferSizes::new(Some(0x10_0000), CaptureFlags::empty()),
            BufferSizes {
                buffer: 0x10_0000,
                chunk: 0x4000
            }
        );
        assert_eq!(
            BufferSizes::new(Some(1), CaptureFlags::empty()),
            BufferSizes {
                buffer: 1,
                chunk: 0
            }
        );
    }

    #[test]
    fn receive_filter_checks_the_destination() {
        let broadcast = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0];
        let multicast = [0x01, 0x00, 0x5e, 0, 0, 1, 0];
        let unicast = [0x00, 0x0d, 0x3a, 0, 0, 1, 0];
        let both = CaptureFlags::SKIP_BROADCAST | CaptureFlags::SKIP_MULTICAST;
        assert!(both.skips_received(&broadcast));
        assert!(both.skips_received(&multicast));
        assert!(!both.skips_received(&unicast));
        // Broadcast frames are not group frames for the multicast bit.
        assert!(!CaptureFlags::SKIP_MULTICAST.skips_received(&broadcast));
        assert!(!CaptureFlags::SKIP_BROADCAST.skips_received(&multicast));
        // Frames of six bytes or fewer are always kept.
        assert!(!both.skips_received(&broadcast[..6]));
    }

    #[test]
    fn kernel_failures_map_through_the_status_table() {
        assert_eq!(
            capture_result(CaptureFileError::Kernel(KernelError::ObjectNameCollision)),
            ErrorCode::FileAlreadyExists.hresult()
        );
        let unlisted = KernelError::from_status(NtStatus(0xc000_0010)).unwrap();
        assert_eq!(
            capture_result(CaptureFileError::Kernel(unlisted)),
            Hresult(0xd000_0010)
        );
        assert_eq!(
            capture_result(CaptureFileError::DataLimitReached),
            Hresult(0x8007_006f)
        );
    }
}
