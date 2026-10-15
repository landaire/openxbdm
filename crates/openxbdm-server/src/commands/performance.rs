//! Performance counter, profiling, capture, and graphics commands.

pub mod capture;
pub mod counters;
pub mod pix;
pub mod pmc;
pub mod profiler;
pub mod studio;
pub mod xtrace;

use core::fmt::Write as _;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;

use crate::access::Access;
use crate::commands::console::ConfigSetting;
use crate::commands::debugger;
use crate::commands::filesystem::CreateDisposition;
use crate::commands::filesystem::CreateOptions;
use crate::commands::filesystem::CreateRequest;
use crate::commands::filesystem::DriveTable;
use crate::commands::filesystem::FileAccess;
use crate::commands::filesystem::FileAttributes;
use crate::commands::filesystem::ShareAccess;
use crate::commands::util;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::server::MAX_CONNECTIONS;
use crate::text::Text;

pub use counters::CounterSample;

const fn command(
    name: &'static str,
    any_of: Access,
    handler: crate::registry::Handler,
) -> CommandEntry {
    CommandEntry {
        name,
        any_of,
        all_of: Access::NONE,
        flags: DispatchFlags::NONE,
        handler,
    }
}

pub(crate) const COMMANDS: &[CommandEntry] = &[
    command("autoprof", Access::CONTROL, auto_profile),
    command("capctrl", Access::CONTROL, capture_control),
    command("gpucount", Access::CONTROL, gpu_count),
    command("lopctrl", Access::CONTROL, cpu_profiler_control),
    command("pclist", Access::CONTROL, counter_list),
    command("perfstat", Access::READ, performance_status),
    command("pixcmd", Access::CONTROL, pix::pix_command),
    command("pixpreview", Access::CONTROL, pix_preview),
    command("querypc", Access::CONTROL, query_counter),
    command("screenshot", Access::CONTROL, screenshot),
    command("vd", Access::READ.union(Access::WRITE), video_display),
    command("xstudio", Access::CONTROL, studio),
];

/// Hardware flag that enables the automatic sign-in profile settings.
const HARDWARE_AUTO_PROFILE: u32 = 0x10;
/// Console setting holding the automatic sign-in profile XUID.
const AUTO_PROFILE_SETTING: ConfigSetting = ConfigSetting::new(3, 8);
/// Kernel status codes become failures outside the monitor facility.
const NT_FAILURE_MARKER: u32 = 0x1000_0000;
/// Bytes of a counter name the enumeration copies.
pub const COUNTER_NAME_CAPACITY: usize = 0x100;
/// Path buffers of `capctrl` and `lopctrl`.
const PROFILE_NAME_CAPACITY: usize = 0x141;
/// `vd` command name buffer.
const VD_COMMAND_CAPACITY: usize = 0x20;
/// First register of the extended video encoder banks.
const VD_EXTENDED_FIRST: u32 = 0x100;
/// End of the video encoder register space.
const VD_REGISTER_END: u32 = 0x300;
/// Highest GPU register index `vd` accepts.
const VD_GPU_LAST: u32 = 0xfffc;
/// Bytes of one EDID block.
pub const EDID_BLOCK_SIZE: usize = 0x80;
/// Bytes of one framebuffer tile: 32 by 32 pixels of 4 bytes.
pub const TILE_SIZE: u32 = 0x1000;
/// Pixels along a tile edge.
const TILE_EDGE: u32 = 32;

const BAD_PARAMETER: Hresult = Hresult::error(0x17);
const UNKNOWN_COMMAND: Hresult = Hresult::error(0x07);
const MEMORY_NOT_MAPPED: Hresult = Hresult::error(0x04);
const EDID_FAILED: Hresult = Hresult::error(0x1d);
const CAPTURE_FILE_FAILED: Hresult = Hresult::error(0x0d);
const FAST_CAP_ENABLED: Hresult = Hresult::success(0x07);
const FAST_CAP_DISABLED: Hresult = Hresult::error(0x1b);
const CALL_CAP_ENABLED: Hresult = Hresult::success(0x08);
const CALL_CAP_DISABLED: Hresult = Hresult::error(0x21);
/// `capctrl` and `lopctrl` without a subcommand.
const NO_SUBCOMMAND: Hresult = Hresult::error(0);

/// Global state of this domain.
#[derive(Debug)]
pub struct State {
    /// D3D version and flags the title reported through `pixcmd q`.
    pub pix: PixVersion,
    /// Per-connection scratch area that `pclist` and `querypc` share:
    /// the enumeration context occupies the high half of `value`, and a
    /// query leaves fields it does not produce unchanged.
    pub scratch: [CounterSample; MAX_CONNECTIONS],
}

impl State {
    pub const fn new() -> Self {
        Self {
            pix: PixVersion {
                version: 0,
                flags: 0,
            },
            scratch: [CounterSample::ZERO; MAX_CONNECTIONS],
        }
    }
}

/// D3D version information stored by `pixcmd q`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PixVersion {
    pub version: u32,
    pub flags: u32,
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    CounterList,
    CounterData {
        sent: bool,
    },
    Screenshot(ScreenshotTransfer),
    Edid {
        block: [u8; EDID_BLOCK_SIZE],
        sent: bool,
    },
    Trace,
}

/// Current display mode as the video driver reports it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisplayInformation {
    /// Front buffer width in pixels; the pitch is derived from it.
    pub surface_width: u16,
    pub colorspace: u8,
    /// Displayed rectangle in front buffer pixels; right and bottom are
    /// exclusive.
    pub left: u32,
    pub top: u32,
    pub right: u32,
    pub bottom: u32,
    /// Scaled output size.
    pub scaled_width: u32,
    pub scaled_height: u32,
}

/// Front buffer state read for a screenshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisplayCapture {
    pub display: DisplayInformation,
    /// Display controller front buffer register (physical address plus
    /// 0x40000000).
    pub front_buffer: u32,
    /// The display controller applies gamma to the front buffer.
    pub gamma: bool,
}

/// Outcome of reading an EDID block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdidRead {
    /// The kernel lacks the EDID export.
    Unsupported,
    Failed,
    Read,
}

/// Counters reported by `lopctrl info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuProfilerInfo {
    pub elapsed_time: u32,
    pub total_samples: u32,
    pub overhead_interrupts: u32,
}

/// A message posted to the PIX engine: a code and up to 0x50 bytes of
/// big-endian words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixMessage {
    pub code: u32,
    words: [u32; 12],
    len: usize,
}

impl PixMessage {
    pub fn new(code: u32, payload: &[u32]) -> Self {
        let mut words = [0; 12];
        words[..payload.len()].copy_from_slice(payload);
        Self {
            code,
            words,
            len: payload.len(),
        }
    }

    pub fn payload(&self) -> &[u32] {
        &self.words[..self.len]
    }
}

/// Values `pixcmd h` posts for the D3D debug image.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PixDogma {
    pub handle: u32,
    pub procedure_1: u32,
    pub info: u32,
    pub procedure_3: u32,
}

/// Values `pixcmd k` stores before posting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureValue {
    First,
    Second,
}

/// A counter returned by enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterEntry {
    pub name_len: usize,
    pub counter_type: u16,
}

/// Platform services this domain needs.
pub trait Backend {
    fn performance_frequency(&mut self) -> u64;

    /// Next object of the counter directory after `context` (0 restarts).
    /// Fails with [`Hresult::END_OF_DATA`] at the end or without a
    /// directory, and with `0x82da0105` when the name does not fit.
    fn next_counter(
        &mut self,
        context: &mut u32,
        name: &mut [u8; COUNTER_NAME_CAPACITY],
    ) -> Result<CounterEntry, Hresult>;
    /// Open counter `name` and evaluate it with [`counters::query`].
    /// Fails with `0x82da0002` without a directory and `0x82da000e` when
    /// the counter cannot be opened.
    fn query_counter(&mut self, name: &[u8], query: u32, out: &mut CounterSample) -> Hresult;

    /// Wait up to 500 ms for the GPU to finish the pending flip, then read
    /// the front buffer registers and the display mode.
    fn capture_display(&mut self) -> DisplayCapture;
    /// Copy one 4 KiB framebuffer page at `address` (cache flushed before
    /// and after).
    fn read_framebuffer_page(&mut self, address: u32, page: &mut [u8]);

    /// Video encoder register below 0x300; 0x100 and up are the extended
    /// banks.
    fn read_video_encoder(&mut self, register: u32) -> u32;
    fn write_video_encoder(&mut self, register: u32, value: u32);
    /// Whether the extended banks exist (encoder register 0xfe >= 0x10000
    /// at startup).
    fn video_encoder_extended(&mut self) -> bool;
    /// Write one byte of an extended bank over I2C.
    fn write_video_encoder_extended(&mut self, register: u32, value: u8);
    fn read_gpu_register(&mut self, index: u32) -> u32;
    fn write_gpu_register(&mut self, index: u32, value: u32);
    fn read_edid(&mut self, block: u8, output: &mut [u8; EDID_BLOCK_SIZE]) -> EdidRead;

    /// Open a listener for the Xbox Studio service and return its port.
    fn dedicate_studio_socket(&mut self) -> Result<u16, Hresult>;

    /// Delete the validated capture file `path` (the object name of
    /// `name`), record the start time, and start a capture into `name`
    /// (stock 0x91f29d08).
    fn capture_start(&mut self, name: &[u8], path: &[u8], buffer_size: u32) -> Hresult;
    /// A loaded module carries fast-cap instrumentation.
    fn fast_cap_present(&mut self) -> bool;
    /// A loaded module carries call-cap instrumentation.
    fn call_cap_present(&mut self) -> bool;
    /// Stop and write the capture file, naming it through `drives`
    /// (export 74).
    fn capture_stop(&mut self, drives: &DriveTable) -> Hresult;
    fn capture_set_flags(&mut self, flags: capture::CaptureFlags);
    /// Export 146.
    fn capture_status(&mut self) -> Hresult;
    /// Export 162.
    fn capture_abort(&mut self) -> Hresult;

    /// Start the CPU sampling profiler (export 149, 0x91f32c90); `drives`
    /// translates the drive path `name`.
    fn cpu_profiler_start(
        &mut self,
        drives: &DriveTable,
        name: &[u8],
        interval: u32,
        flags: u32,
    ) -> Hresult;
    /// Stop sampling and write the capture file (export 150, 0x91f33010).
    fn cpu_profiler_stop(&mut self) -> Hresult;
    /// Export 151 (0x91f32e30).
    fn cpu_profiler_info(&mut self) -> Result<CpuProfilerInfo, Hresult>;

    /// Post a message to the PIX engine; false without a session or with a
    /// full queue. Code 0xc replaces the payload of a queued code 0xc.
    fn pix_post(&mut self, message: PixMessage) -> bool;
    /// Engine status for a title with D3D `version` and `flags`.
    fn pix_status(&mut self, version: u32, flags: u32) -> Option<[u32; 12]>;
    fn pix_frame_statistics(&mut self, frame: u32) -> Option<[u32; 3]>;
    /// Current PIX frame number.
    fn pix_frame_number(&mut self) -> i32;
    fn pix_signal_event(&mut self, event: u32);
    /// Enable or disable counter tracing: clears the counter bitmap,
    /// installs or removes the per-processor hook, allocates or frees the
    /// trace ring.
    fn pix_set_trace(&mut self, enabled: bool);
    /// Group 1 sets or clears bit `id` of the counter bitmap; groups 2 to 6
    /// call the registered group callback.
    fn pix_counter_control(&mut self, group: u32, id: u32, enabled: bool);
    fn pix_set_capture_value(&mut self, value: CaptureValue, data: u32);
    fn pix_set_capture_text(&mut self, text: &[u8]);
    fn pix_set_legacy_protocol(&mut self, legacy: bool);
    fn pix_set_gpu_capture(&mut self, enabled: bool);
    /// Handle and exports of the D3D debug image, loading it if needed.
    /// `None` when the image cannot be used.
    fn pix_dogma(&mut self) -> Option<PixDogma>;
    fn pix_boot_animation_loaded(&mut self) -> bool;
    fn pix_capture_ready(&mut self) -> bool;
    /// Sample the counters into the trace ring and return the queued byte
    /// count.
    fn pix_trace_snapshot(&mut self) -> u32;
    /// Copy queued trace bytes, advancing the read position. Zero at the
    /// end of the snapshot.
    fn pix_trace_read(&mut self, output: &mut [u8]) -> usize;
}

pub(crate) fn resume(continuation: &mut Continuation, cx: &mut ContinuationContext<'_>) -> Hresult {
    match continuation {
        Continuation::CounterList => next_counter_line(cx),
        Continuation::CounterData { sent } => {
            if *sent {
                return Hresult::END_OF_DATA;
            }
            *sent = true;
            let sample = cx.state.performance.scratch[usize::from(cx.session.index().0)];
            let _ = write!(
                cx.line,
                "type=0x{:08x} vallo=0x{:08x} valhi=0x{:08x} ratelo=0x{:08x} ratehi=0x{:08x}",
                sample.sample_type,
                sample.value as u32,
                (sample.value >> 32) as u32,
                sample.rate as u32,
                (sample.rate >> 32) as u32
            );
            Hresult::OK
        }
        Continuation::Screenshot(transfer) => transfer.resume(cx),
        Continuation::Edid { block, sent } => {
            if *sent || cx.aborted {
                return Hresult::END_OF_DATA;
            }
            *sent = true;
            cx.binary[..EDID_BLOCK_SIZE].copy_from_slice(block);
            cx.binary_len = EDID_BLOCK_SIZE;
            Hresult::OK
        }
        Continuation::Trace => {
            if cx.aborted {
                return Hresult::END_OF_DATA;
            }
            let count = cx.backend.pix_trace_read(cx.binary);
            if count == 0 {
                return Hresult::END_OF_DATA;
            }
            cx.binary_len = count;
            Hresult::OK
        }
    }
}

/// Map a failed kernel status the way the monitor reports it.
fn nt_failure(status: NtStatus) -> Hresult {
    Hresult(status.0 | NT_FAILURE_MARKER)
}

/// `autoprof [xuid=0q<hex>]`: read or set the automatic sign-in profile.
fn auto_profile(invocation: &mut Invocation<'_>) -> Hresult {
    let xuid = invocation
        .line
        .param("xuid")
        .and_then(|value| value.qword());
    if invocation.backend.hardware_flags() & HARDWARE_AUTO_PROFILE == 0 {
        return UNKNOWN_COMMAND;
    }
    match xuid {
        Some(xuid) => match invocation
            .backend
            .xconfig_set(AUTO_PROFILE_SETTING, &xuid.to_be_bytes())
        {
            Ok(()) => Hresult::OK,
            Err(status) => nt_failure(status),
        },
        None => {
            let mut value = [0u8; 8];
            match invocation
                .backend
                .xconfig_get(AUTO_PROFILE_SETTING, &mut value)
            {
                Ok(_) => {
                    invocation.set_text(format_args!("xuid==0q{:016x}", u64::from_be_bytes(value)));
                    Hresult::OK
                }
                Err(status) => nt_failure(status),
            }
        }
    }
}

/// Copy a required path parameter, or set `missing name`.
fn profile_name<'b>(
    invocation: &mut Invocation<'_>,
    output: &'b mut [u8; PROFILE_NAME_CAPACITY],
) -> Option<&'b [u8]> {
    match invocation.line.param("name") {
        Some(value) => Some(value.copy_into(output)),
        None => None,
    }
}

/// An optional dword parameter; a malformed value still stores its digits.
fn optional_dword(invocation: &Invocation<'_>, name: &str) -> u32 {
    invocation
        .line
        .param(name)
        .map_or(0, |value| value.dword_prefix())
}

/// `capctrl`: profiler capture control. Every reply is `HRESULT 0x%08x`.
fn capture_control(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    let result = if line.has("start") {
        let mut name = [0u8; PROFILE_NAME_CAPACITY];
        match profile_name(invocation, &mut name) {
            Some(name) => {
                let buffer_size = optional_dword(invocation, "buffersize");
                start_capture(invocation, name, buffer_size)
            }
            None => Hresult::INVALID_ARGUMENT,
        }
    } else if line.has("fastcapenabled") {
        if invocation.backend.fast_cap_present() {
            FAST_CAP_ENABLED
        } else {
            FAST_CAP_DISABLED
        }
    } else if line.has("callcapenabled") {
        if invocation.backend.call_cap_present() {
            CALL_CAP_ENABLED
        } else {
            CALL_CAP_DISABLED
        }
    } else if line.has("stop") {
        invocation
            .backend
            .capture_stop(&invocation.state.filesystem.drives)
    } else if let Some(flags) = line.param("flags").and_then(|value| value.dword()) {
        invocation
            .backend
            .capture_set_flags(capture::CaptureFlags::from_request(flags));
        Hresult::OK
    } else if line.has("profilingstatus") {
        invocation.backend.capture_status()
    } else if line.has("abort") {
        invocation.backend.capture_abort()
    } else {
        NO_SUBCOMMAND
    };
    invocation.set_text(format_args!("HRESULT 0x{:08x}", result.0));
    result
}

/// Create the capture file once to validate the path, then hand it to the
/// capture engine (stock 0x91f29d08).
fn start_capture(invocation: &mut Invocation<'_>, name: &[u8], buffer_size: u32) -> Hresult {
    let request = CreateRequest {
        access: FileAccess(FileAccess::GENERIC_WRITE.0 | FileAccess::SYNCHRONIZE.0),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::READ,
        disposition: CreateDisposition::OverwriteIf,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    };
    let Some(path) = invocation
        .state
        .filesystem
        .drives
        .translate(invocation.backend, name)
    else {
        return CAPTURE_FILE_FAILED;
    };
    match invocation.backend.create_file(path.as_bytes(), &request) {
        Ok(handle) => invocation.backend.close_file(handle),
        Err(_) => return CAPTURE_FILE_FAILED,
    }
    invocation
        .backend
        .capture_start(name, path.as_bytes(), buffer_size)
}

/// `gpucount enable|disable`: accepted without effect.
fn gpu_count(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.line.has("enable") || invocation.line.has("disable") {
        Hresult::OK
    } else {
        UNKNOWN_COMMAND
    }
}

/// `lopctrl start|stop|info`: CPU sampling profiler control.
fn cpu_profiler_control(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    let result = if line.has("start") {
        let mut name = [0u8; PROFILE_NAME_CAPACITY];
        match profile_name(invocation, &mut name) {
            Some(name) => {
                let interval = optional_dword(invocation, "interval");
                let flags = optional_dword(invocation, "flags");
                invocation.backend.cpu_profiler_start(
                    &invocation.state.filesystem.drives,
                    name,
                    interval,
                    flags,
                )
            }
            None => Hresult::INVALID_ARGUMENT,
        }
    } else if line.has("stop") {
        invocation.backend.cpu_profiler_stop()
    } else if line.has("info") {
        match invocation.backend.cpu_profiler_info() {
            Ok(info) => {
                invocation.set_text(format_args!(
                    "elapsedTime=0x{:08x} totalSamp=0x{:08x} overheadInt=0x{:08x}",
                    info.elapsed_time, info.total_samples, info.overhead_interrupts
                ));
                return Hresult::OK;
            }
            Err(result) => result,
        }
    } else {
        NO_SUBCOMMAND
    };
    invocation.set_text(format_args!("HRESULT 0x{:08x}", result.0));
    result
}

/// `pclist`: one line per object of the counter directory.
fn counter_list(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(session) = invocation.session.as_deref_mut() else {
        return Hresult::FAIL;
    };
    let scratch = &mut invocation.state.performance.scratch[usize::from(session.index().0)];
    scratch.value &= u64::from(u32::MAX);
    session.continuation = AnyContinuation::Performance(Continuation::CounterList);
    Hresult::MULTILINE
}

fn next_counter_line(cx: &mut ContinuationContext<'_>) -> Hresult {
    let scratch = &mut cx.state.performance.scratch[usize::from(cx.session.index().0)];
    let mut context = (scratch.value >> 32) as u32;
    let mut name = [0u8; COUNTER_NAME_CAPACITY];
    let result = cx.backend.next_counter(&mut context, &mut name);
    scratch.value = (u64::from(context) << 32) | (scratch.value & u64::from(u32::MAX));
    match result {
        Ok(entry) => {
            let _ = cx.line.push_bytes(b"name=\"");
            let _ = cx.line.push_bytes(&name[..entry.name_len]);
            let _ = write!(cx.line, "\" type=0x{:08x}", entry.counter_type);
            Hresult::OK
        }
        Err(result) => result,
    }
}

/// `perfstat`: the performance counter frequency.
fn performance_status(invocation: &mut Invocation<'_>) -> Hresult {
    let frequency = invocation.backend.performance_frequency();
    invocation.set_text(format_args!("PerfFreq=0x{frequency:X}"));
    Hresult::OK
}

/// `pixpreview`: always fails.
fn pix_preview(invocation: &mut Invocation<'_>) -> Hresult {
    invocation.set_text(format_args!("HRESULT 0x{:08x}", BAD_PARAMETER.0));
    BAD_PARAMETER
}

/// `querypc name=<counter> type=<dword>`.
fn query_counter(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(index) = invocation
        .session
        .as_ref()
        .map(|session| usize::from(session.index().0))
    else {
        return Hresult::FAIL;
    };
    let mut name = [0u8; COUNTER_NAME_CAPACITY];
    let Some(name) = invocation
        .line
        .param("name")
        .map(|value| value.copy_into(&mut name))
    else {
        invocation.set_text(format_args!("missing name"));
        return Hresult::FAIL;
    };
    let Some(query) = util::required_dword(invocation, "type") else {
        return util::MISSING;
    };
    let result = invocation.backend.query_counter(
        name,
        query,
        &mut invocation.state.performance.scratch[index],
    );
    if result.is_failure() {
        return result;
    }
    if let Some(session) = invocation.session.as_deref_mut() {
        session.continuation =
            AnyContinuation::Performance(Continuation::CounterData { sent: false });
    }
    invocation.set_text(format_args!("counter data follows"));
    Hresult::MULTILINE
}

const fn align_tile(value: u32) -> u32 {
    value.wrapping_add(TILE_EDGE - 1) & !(TILE_EDGE - 1)
}

/// Header and progress of a screenshot body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenshotTransfer {
    pitch: u32,
    width: u32,
    height: u32,
    format: u32,
    offset_x: u32,
    offset_y: u32,
    scaled_width: u32,
    scaled_height: u32,
    colorspace: u8,
    /// Framebuffer bytes not yet sent.
    remaining: u32,
    /// First tile of the current tile row.
    source: u32,
    header_sent: bool,
    /// This command stopped the title and resumes it at the end.
    stopped: bool,
}

impl ScreenshotTransfer {
    fn new(capture: &DisplayCapture, stopped: bool) -> Self {
        let display = capture.display;
        let pitch = align_tile(u32::from(display.surface_width)) * 4;
        let left = display.left & !(TILE_EDGE - 1);
        let top = display.top & !(TILE_EDGE - 1);
        let source = capture
            .front_buffer
            .wrapping_sub(0x4000_0000)
            .wrapping_add(top.wrapping_mul(pitch))
            .wrapping_add(display.left.wrapping_shl(7) & !(TILE_SIZE - 1));
        let rows = align_tile(display.bottom).wrapping_sub(top);
        let columns = align_tile(display.right).wrapping_sub(left);
        let format = if capture.gamma {
            0x1828_01b6
        } else {
            0x1828_0186
        };
        Self {
            pitch,
            width: display.right.wrapping_sub(display.left),
            height: display.bottom.wrapping_sub(display.top),
            format: 0x8000_0000 | format,
            offset_x: display.left & (TILE_EDGE - 1),
            offset_y: display.top & (TILE_EDGE - 1),
            scaled_width: display.scaled_width,
            scaled_height: display.scaled_height,
            colorspace: display.colorspace,
            remaining: rows.wrapping_mul(columns).wrapping_shl(2),
            source,
            header_sent: false,
            stopped,
        }
    }

    /// The header line first, then whole tiles in row-major order.
    fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> Hresult {
        if self.remaining == 0 || cx.aborted {
            if self.stopped {
                self.stopped = false;
                debugger::go_execution(cx.state, cx.backend, cx.network);
            }
            return Hresult::END_OF_DATA;
        }
        if !self.header_sent {
            self.header_sent = true;
            let mut header: Text<0x100> = Text::new();
            let _ = write!(
                header,
                "pitch=0x{:08x} width=0x{:08x} height=0x{:08x} format=0x{:08x} offsetx=0x{:08x} offsety=0x{:08x}, \
                 framebuffersize=0x{:08x} sw=0x{:08x} sh=0x{:08x} colorspace=0x{:x}\r\n",
                self.pitch,
                self.width,
                self.height,
                self.format,
                self.offset_x,
                self.offset_y,
                self.remaining,
                self.scaled_width,
                self.scaled_height,
                self.colorspace
            );
            let bytes = header.as_bytes();
            cx.binary[..bytes.len()].copy_from_slice(bytes);
            cx.binary_len = bytes.len();
            return Hresult::OK;
        }
        let chunk = self.remaining.min(cx.binary.len() as u32) & !(TILE_SIZE - 1);
        let tiles_per_row = self
            .offset_x
            .wrapping_add(self.width)
            .wrapping_add(TILE_EDGE - 1)
            >> 5;
        if chunk != 0 && tiles_per_row == 0 {
            // The monitor divides by the tile count and traps.
            return Hresult::UNEXPECTED;
        }
        let mut left = (self.remaining >> 12).wrapping_sub(1);
        for page in cx.binary[..chunk as usize]
            .as_chunks_mut::<{ TILE_SIZE as usize }>()
            .0
        {
            let column = tiles_per_row - 1 - left % tiles_per_row;
            cx.backend.read_framebuffer_page(
                self.source.wrapping_add(column.wrapping_mul(TILE_SIZE)),
                page,
            );
            if (column + 1).is_multiple_of(tiles_per_row) {
                self.source = self.source.wrapping_add(self.pitch.wrapping_mul(TILE_EDGE));
            }
            left = left.wrapping_sub(1);
        }
        cx.binary_len = chunk as usize;
        self.remaining -= chunk;
        Hresult::OK
    }
}

/// `screenshot`: stop the title and send the front buffer tiles.
fn screenshot(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let stop = debugger::stop_execution(invocation.state, invocation.backend, invocation.network);
    let capture = invocation.backend.capture_display();
    let transfer = ScreenshotTransfer::new(&capture, stop == Hresult::OK);
    if let Some(session) = invocation.session.as_deref_mut() {
        session.continuation = AnyContinuation::Performance(Continuation::Screenshot(transfer));
    }
    Hresult::BINARY
}

/// Fail with the result as `HRESULT 0x%x` text.
fn vd_failure(invocation: &mut Invocation<'_>, result: Hresult) -> Hresult {
    invocation.set_text(format_args!("HRESULT 0x{:x}", result.0));
    result
}

/// `vd cmd=<peek|poke|gpeek|gpoke|edid> ...`: video encoder, GPU register,
/// and EDID access.
fn video_display(invocation: &mut Invocation<'_>) -> Hresult {
    let mut buffer = [0u8; VD_COMMAND_CAPACITY];
    let Some(command) = invocation
        .line
        .param("cmd")
        .map(|value| value.copy_into(&mut buffer))
    else {
        return vd_failure(invocation, BAD_PARAMETER);
    };
    let line = invocation.line;
    let dword = |name: &str| line.param(name).and_then(|value| value.dword());
    if command.eq_ignore_ascii_case(b"peek") {
        let Some(register) = dword("addr").filter(|&register| register < VD_REGISTER_END) else {
            return vd_failure(invocation, BAD_PARAMETER);
        };
        if register < VD_EXTENDED_FIRST {
            let value = invocation.backend.read_video_encoder(register);
            invocation.set_text(format_args!("0x{value:08x}"));
        } else {
            if !invocation.backend.video_encoder_extended() {
                return vd_failure(invocation, MEMORY_NOT_MAPPED);
            }
            let value = invocation.backend.read_video_encoder(register) as u8;
            invocation.set_text(format_args!("0x{value:02x}"));
        }
    } else if command.eq_ignore_ascii_case(b"poke") {
        let Some(register) = dword("addr").filter(|&register| register < VD_REGISTER_END) else {
            return vd_failure(invocation, BAD_PARAMETER);
        };
        let Some(value) = dword("data") else {
            return vd_failure(invocation, BAD_PARAMETER);
        };
        if register > 0xff && value > 0xff {
            return vd_failure(invocation, BAD_PARAMETER);
        }
        if register < VD_EXTENDED_FIRST {
            invocation.backend.write_video_encoder(register, value);
        } else {
            if !invocation.backend.video_encoder_extended() {
                return vd_failure(invocation, MEMORY_NOT_MAPPED);
            }
            invocation
                .backend
                .write_video_encoder_extended(register, value as u8);
        }
    } else if command.eq_ignore_ascii_case(b"gpeek") {
        let Some(index) = dword("addr").filter(|&index| index <= VD_GPU_LAST) else {
            return vd_failure(invocation, BAD_PARAMETER);
        };
        let value = invocation.backend.read_gpu_register(index);
        invocation.set_text(format_args!("0x{value:08x}"));
    } else if command.eq_ignore_ascii_case(b"gpoke") {
        let Some(index) = dword("addr").filter(|&index| index <= VD_GPU_LAST) else {
            return vd_failure(invocation, BAD_PARAMETER);
        };
        let Some(value) = dword("data") else {
            return vd_failure(invocation, BAD_PARAMETER);
        };
        invocation.backend.write_gpu_register(index, value);
    } else if command.eq_ignore_ascii_case(b"edid") {
        let Some(block) = dword("block").filter(|&block| block <= 0xff) else {
            return vd_failure(invocation, BAD_PARAMETER);
        };
        let mut data = [0u8; EDID_BLOCK_SIZE];
        match invocation.backend.read_edid(block as u8, &mut data) {
            EdidRead::Unsupported => return vd_failure(invocation, UNKNOWN_COMMAND),
            EdidRead::Failed => return vd_failure(invocation, EDID_FAILED),
            EdidRead::Read => {}
        }
        let Some(session) = invocation.session.as_deref_mut() else {
            return Hresult::FAIL;
        };
        session.continuation = AnyContinuation::Performance(Continuation::Edid {
            block: data,
            sent: false,
        });
        return Hresult::BINARY;
    }
    Hresult::OK
}

/// `xstudio DedicateSocket`: open a listener for the Xbox Studio service.
fn studio(invocation: &mut Invocation<'_>) -> Hresult {
    let end = invocation
        .buffer
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(invocation.buffer.len());
    let line = &invocation.buffer[..end];
    let is_delimiter = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n');
    let after_word = line.iter().position(is_delimiter).unwrap_or(line.len());
    let rest = &line[after_word..];
    let start = rest
        .iter()
        .position(|byte| !is_delimiter(byte))
        .unwrap_or(rest.len());
    let rest = &rest[start..];
    let token = &rest[..rest.iter().position(is_delimiter).unwrap_or(rest.len())];
    if token != b"DedicateSocket" {
        invocation.text.set_bytes(b"NO");
        return Hresult::OK;
    }
    match invocation.backend.dedicate_studio_socket() {
        Ok(port) => invocation.set_text(format_args!("OK {port}")),
        Err(_) => invocation.text.set_bytes(b"NO"),
    }
    Hresult::OK
}
