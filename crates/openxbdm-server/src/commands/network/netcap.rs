//! `netcap`: Ethernet frame capture to a file.

pub mod capture_file;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;

use super::WsaError;
use crate::invocation::Invocation;

/// `start` while a capture runs.
const ALREADY_CAPTURING: Hresult = Hresult::error(0x08);
/// `stop` without a capture: status 435 with no default text.
const NOT_CAPTURING: Hresult = Hresult::error(0x23);
/// `stop` after frames were lost to a full write buffer.
const FRAMES_LOST: Hresult = Hresult::error(0x26);
/// Intercept callbacks owned by another client.
const INTERCEPT_BUSY: Hresult = Hresult::error(0x10);
/// Intercept result for callbacks that are already installed.
const WSAEALREADY: WsaError = WsaError(0x2735);
/// Result bit marking a kernel status carried as a result.
const NT_STATUS_BIT: u32 = 0x1000_0000;
/// Mask of the facility bits the `start` status keeps.
const FACILITY_MASK: u32 = 0x1fff_0000;
const FACILITY_XBDM: u32 = 0x02da_0000;
/// Size of the `file=` buffer, terminator included.
const FILE_PARAMETER_SIZE: usize = 0x104;
/// Size of the translated path buffer; the translator stops at this many
/// bytes.
const OBJECT_PATH_SIZE: usize = 0x104;

/// `start` flags (0x91f9f694).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaptureFlags(pub u32);

impl CaptureFlags {
    /// Put the adapter in promiscuous mode for the capture.
    pub const PROMISCUOUS: Self = Self(0x1);
    /// Skip received frames sent to the broadcast address.
    pub const SKIP_BROADCAST: Self = Self(0x2);
    /// Skip received frames sent to other group addresses.
    pub const SKIP_MULTICAST: Self = Self(0x4);
    /// Keep capturing when the title exits; also selects the smaller buffer
    /// defaults and the allocation pool that survives title termination.
    pub const PERSISTENT: Self = Self(0x8);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Whether the receive callback leaves `frame` out of the capture
    /// (0x91f34e78). Received frames only; transmitted frames are always
    /// recorded.
    pub fn skips_received(self, frame: &[u8]) -> bool {
        if self.0 & (Self::SKIP_BROADCAST.0 | Self::SKIP_MULTICAST.0) == 0 || frame.len() <= 6 {
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
    pub result: Result<(), Hresult>,
    /// Frames in the file.
    pub frames: u32,
}

/// Platform services `netcap` needs.
pub trait Backend {
    /// Create the capture context and the capture file (0x91f67f90,
    /// 0x91f69c10). Failures are raw results; kernel failures carry
    /// [`NT_STATUS_BIT`].
    fn open_capture(&mut self, request: &CaptureRequest<'_>) -> Result<(), Hresult>;
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
    fn capture_error(&self) -> Option<Hresult>;
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
pub(super) fn netcap(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.line.has("start") {
        start(invocation)
    } else if invocation.line.has("stop") {
        let (result, text) = stop(
            &mut invocation.state.network.netcap,
            &mut *invocation.backend,
        );
        if let Some(text) = text {
            invocation.set_text(format_args!("{text}"));
        }
        result
    } else {
        Hresult::from_error_code(ErrorCode::BAD_PARAMETER)
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

fn start(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    // Absent and unparsable values read as 0, which selects the defaults.
    let dword = |name| line.dword(name).unwrap_or(0);
    let data_limit = dword("maxframedata");
    let buffer = dword("buffersize");
    let flags = CaptureFlags(dword("flags"));
    let Some(file) = line.param("file") else {
        return Hresult::from_error_code(ErrorCode::FILENAME_INVALID);
    };
    let mut name = [0u8; FILE_PARAMETER_SIZE];
    let name = file.copy_into(&mut name);

    let result = match start_capture(
        invocation.state,
        invocation.backend,
        name,
        data_limit,
        buffer,
        flags,
    ) {
        Ok(()) => {
            invocation.set_text(format_args!("started"));
            return Hresult::OK;
        }
        Err(error) => error,
    };
    invocation.set_text(format_args!("err=0x{:08x}", result.0));
    if result.is_failure() && result.0 & FACILITY_MASK != FACILITY_XBDM {
        Hresult::error(0)
    } else {
        result
    }
}

/// Open the capture and attach the callbacks (0x91f34f80); failures that
/// carry a kernel status are mapped through the status table.
pub fn start_capture(
    state: &mut crate::state::ServerState,
    backend: &mut dyn crate::backend::Backend,
    name: &[u8],
    data_limit: u32,
    buffer: u32,
    flags: CaptureFlags,
) -> Result<(), Hresult> {
    open_and_attach(state, backend, name, data_limit, buffer, flags).map_err(map_nt_result)
}

fn open_and_attach(
    state: &mut crate::state::ServerState,
    backend: &mut dyn crate::backend::Backend,
    name: &[u8],
    data_limit: u32,
    buffer: u32,
    mut flags: CaptureFlags,
) -> Result<(), Hresult> {
    if state.network.netcap.capture.is_some() {
        return Err(ALREADY_CAPTURING);
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
    backend.open_capture(&request)?;
    if flags.contains(CaptureFlags::PROMISCUOUS) && !backend.set_promiscuous(true) {
        flags = flags.without(CaptureFlags::PROMISCUOUS);
    }
    if let Err(WsaError(error)) = backend.attach_capture(flags) {
        // Stock leaves promiscuous mode on here.
        let _ = backend.close_capture();
        return Err(if WsaError(error) == WSAEALREADY {
            INTERCEPT_BUSY
        } else if error <= 0 {
            Hresult(error as u32)
        } else {
            Hresult(0x8007_0000 | (error as u32 & 0xffff))
        });
    }
    state.network.netcap.capture = Some(flags);
    Ok(())
}

/// Reply of a stopped capture (0x91f351e0 text).
enum StopText {
    Stopped { frames: u32 },
    Failed { error: Hresult, frames: u32 },
}

impl core::fmt::Display for StopText {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Stopped { frames } => write!(formatter, "stopped frames={frames}"),
            Self::Failed { error, frames } => {
                write!(formatter, "stopped err=0x{:08x} frames={frames}", error.0)
            }
        }
    }
}

/// Stop the capture (0x91f351e0). The first failure wins: a frame callback
/// error, then the close result.
pub fn stop_capture(state: &mut State, backend: &mut dyn crate::backend::Backend) -> Hresult {
    stop(state, backend).0
}

fn stop(
    state: &mut State,
    backend: &mut dyn crate::backend::Backend,
) -> (Hresult, Option<StopText>) {
    let Some(flags) = state.capture.take() else {
        return (NOT_CAPTURING, None);
    };
    let callback_error = backend.capture_error();
    if flags.contains(CaptureFlags::PROMISCUOUS) {
        backend.set_promiscuous(false);
    }
    backend.detach_capture();
    let close = backend.close_capture();
    let frames = close.frames;
    match callback_error.or(close.result.err()) {
        Some(capture_file::WRITE_FAULT) => (
            FRAMES_LOST,
            Some(StopText::Failed {
                error: FRAMES_LOST,
                frames,
            }),
        ),
        Some(error) => {
            let error = map_nt_result(error);
            let text = if error.is_failure() {
                StopText::Failed { error, frames }
            } else {
                StopText::Stopped { frames }
            };
            (Hresult::OK, Some(text))
        }
        None => (Hresult::OK, Some(StopText::Stopped { frames })),
    }
}

/// Failures carrying a kernel status map through the status table
/// (0x91f41f18), falling back to the result itself.
fn map_nt_result(result: Hresult) -> Hresult {
    if result.is_failure() && result.0 & NT_STATUS_BIT != 0 {
        Hresult::from_nt_status(NtStatus(result.0 & !NT_STATUS_BIT), result)
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_sizes_follow_the_flags() {
        assert_eq!(
            BufferSizes::new(None, CaptureFlags(0)),
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
            BufferSizes::new(Some(0x10_0000), CaptureFlags(0)),
            BufferSizes {
                buffer: 0x10_0000,
                chunk: 0x4000
            }
        );
        assert_eq!(
            BufferSizes::new(Some(1), CaptureFlags(0)),
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
        let both = CaptureFlags(CaptureFlags::SKIP_BROADCAST.0 | CaptureFlags::SKIP_MULTICAST.0);
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
            map_nt_result(Hresult(0xd000_0035)),
            Hresult::from_error_code(ErrorCode::FILE_ALREADY_EXISTS)
        );
        assert_eq!(map_nt_result(Hresult(0xd000_0010)), Hresult(0xd000_0010));
        assert_eq!(map_nt_result(Hresult(0x8007_006f)), Hresult(0x8007_006f));
    }
}
