//! Simulated performance counters, display, video encoder, and profiling
//! engines.

mod capture;
mod counters;
mod display;
mod pix;
mod profiler;
mod video;

use openxbdm_server::commands::filesystem;
use openxbdm_server::commands::filesystem::Backend as _;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::DriveTable;
use openxbdm_server::commands::performance;
use openxbdm_server::commands::performance::COUNTER_NAME_CAPACITY;
use openxbdm_server::commands::performance::CaptureValue;
use openxbdm_server::commands::performance::CounterEntry;
use openxbdm_server::commands::performance::CounterSample;
use openxbdm_server::commands::performance::CpuProfilerInfo;
use openxbdm_server::commands::performance::DisplayCapture;
use openxbdm_server::commands::performance::EDID_BLOCK_SIZE;
use openxbdm_server::commands::performance::EdidRead;
use openxbdm_server::commands::performance::PixDogma;
use openxbdm_server::commands::performance::PixMessage;
use openxbdm_server::commands::performance::TILE_SIZE;
use openxbdm_server::commands::performance::capture::BufferRequest;
use openxbdm_server::commands::performance::capture::CaptureError;
use openxbdm_server::commands::performance::capture::CaptureFlags;
use openxbdm_server::commands::performance::capture::DrivePaths;
use openxbdm_server::commands::performance::capture::Started;
use openxbdm_server::commands::performance::counters::CounterError;
use openxbdm_server::commands::performance::counters::CounterQuery;
use openxbdm_server::commands::performance::counters::Evaluation;
use openxbdm_server::commands::performance::profiler::ProfilerError;
use openxbdm_server::commands::performance::profiler::ProfilerFlags;
use openxbdm_server::commands::performance::studio::StudioError;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::ShareAccess;

use self::pix::GroupCall;
use super::MockBackend;

pub use self::capture::Capture;
pub use self::capture::CaptureSession;
pub use self::counters::Counter;
pub use self::counters::Counters;
pub use self::counters::GPU;
pub use self::counters::PAGES;
pub use self::counters::Source;
pub use self::counters::THREADS;
pub use self::display::Display;
pub use self::display::tiled_offset;
pub use self::pix::Pix;
pub use self::profiler::CpuProfiler;
pub use self::video::Video;

/// Simulated state of this domain.
#[derive(Debug)]
pub struct Mock {
    pub frequency: u64,
    pub counters: Counters,

    pub display: Display,
    pub video: Video,

    /// Port of the studio listener; `None` makes the listener fail.
    pub studio_port: Option<u16>,

    pub capture: Capture,

    pub cpu_profiler: CpuProfiler,
    /// Profiler state shared by `lopctrl` and the exports.
    pub cpu_profiler_control: performance::profiler::Control,

    pub pix: Pix,
}

impl Default for Mock {
    fn default() -> Self {
        Self {
            frequency: 50_000_000,
            counters: Counters::default(),
            display: Display::default(),
            video: Video::default(),
            studio_port: Some(0x8f12),
            capture: Capture::default(),
            cpu_profiler: CpuProfiler::default(),
            cpu_profiler_control: performance::profiler::Control::new(),
            pix: Pix::default(),
        }
    }
}

impl performance::Backend for MockBackend {
    fn performance_frequency(&mut self) -> u64 {
        self.performance.frequency
    }

    fn next_counter(
        &mut self,
        context: &mut u32,
        name: &mut [u8; COUNTER_NAME_CAPACITY],
    ) -> Result<CounterEntry, CounterError> {
        self.performance.counters.next(context, name)
    }

    fn query_counter(
        &mut self,
        name: &[u8],
        query: CounterQuery,
        out: &mut CounterSample,
    ) -> Result<Evaluation, CounterError> {
        self.performance.counters.query(name, query, out)
    }

    fn capture_display(&mut self) -> DisplayCapture {
        self.performance.display.capture
    }

    unsafe fn read_framebuffer_page(&mut self, address: u32, page: &mut [u8; TILE_SIZE as usize]) {
        self.performance.display.read_page(address, page);
    }

    fn read_video_encoder(&mut self, register: u32) -> u32 {
        self.performance.video.encoder[register as usize]
    }

    fn write_video_encoder(&mut self, register: u32, value: u32) {
        self.performance.video.encoder[register as usize] = value;
    }

    fn video_encoder_extended(&mut self) -> bool {
        self.performance.video.extended
    }

    fn write_video_encoder_extended(&mut self, register: u32, value: u8) {
        let video = &mut self.performance.video;
        video.extended_writes.push((register, value));
        video.encoder[register as usize] = u32::from(value);
    }

    fn read_gpu_register(&mut self, index: u32) -> u32 {
        // Registers never written read as zero.
        self.performance.video.gpu.get(&index).copied().unwrap_or(0)
    }

    fn write_gpu_register(&mut self, index: u32, value: u32) {
        self.performance.video.gpu.insert(index, value);
    }

    fn read_edid(&mut self, block: u8, output: &mut [u8; EDID_BLOCK_SIZE]) -> EdidRead {
        let Some(blocks) = &self.performance.video.edid else {
            return EdidRead::Unsupported;
        };

        let Some(data) = blocks.get(usize::from(block)) else {
            return EdidRead::Failed;
        };
        *output = *data;

        EdidRead::Read
    }

    fn dedicate_studio_socket(&mut self) -> Result<u16, StudioError> {
        self.performance.studio_port.ok_or(StudioError::Fail)
    }

    fn capture_start(
        &mut self,
        name: &[u8],
        path: &[u8],
        buffer: BufferRequest,
    ) -> Result<Started, CaptureError> {
        let request = CreateRequest::open(
            AccessMask::DELETE,
            ShareAccess::all(),
            CreateOptions::empty(),
        );
        if let Ok(handle) = filesystem::Backend::create_file(self, path, &request) {
            let _ = self.set_delete_disposition(handle, true);
            self.close_file(handle);
        }

        performance::capture::start(&mut self.performance.capture, name, buffer, true)
    }

    fn fast_cap_present(&mut self) -> bool {
        self.performance.capture.fast_cap
    }

    fn call_cap_present(&mut self) -> bool {
        self.performance.capture.call_cap
    }

    fn capture_stop(&mut self, drives: &DriveTable) -> Result<(), CaptureError> {
        let mut engine = std::mem::take(&mut self.performance.capture);

        let result = performance::capture::stop(
            &mut engine,
            &mut DrivePaths {
                drives,
                backend: self,
            },
        );
        self.performance.capture = engine;

        result
    }

    fn capture_set_flags(&mut self, flags: CaptureFlags) {
        self.performance.capture.flags = flags;
    }

    fn capture_status(&mut self) -> Result<(), CaptureError> {
        self.performance.capture.status()
    }

    fn capture_abort(&mut self) -> Result<(), CaptureError> {
        performance::capture::abort(&mut self.performance.capture)
    }

    fn cpu_profiler_start(
        &mut self,
        drives: &DriveTable,
        name: &[u8],
        interval: u32,
        flags: ProfilerFlags,
    ) -> Result<(), ProfilerError> {
        let path = drives.translate(self, name);

        let performance = &mut self.performance;
        performance.cpu_profiler_control.start(
            &mut performance.cpu_profiler,
            path.as_ref().map(|path| path.as_bytes()),
            interval,
            flags,
        )
    }

    fn cpu_profiler_stop(&mut self) -> Result<(), ProfilerError> {
        let performance = &mut self.performance;
        performance
            .cpu_profiler_control
            .stop(&mut performance.cpu_profiler)
    }

    fn cpu_profiler_info(&mut self) -> Result<CpuProfilerInfo, ProfilerError> {
        let performance = &mut self.performance;
        performance
            .cpu_profiler_control
            .info(&mut performance.cpu_profiler)
    }

    unsafe fn pix_post(&mut self, code: u32, payload: &[u32]) -> bool {
        let message = PixMessage::new(code, payload);
        self.performance.pix.post(message)
    }

    fn pix_status(&mut self, version: u32, flags: u32) -> Option<[u32; 12]> {
        let pix = &self.performance.pix;
        (version != 0 && flags & 3 != 0 && pix.session).then_some(pix.status)
    }

    fn pix_frame_statistics(&mut self, _frame: u32) -> Option<[u32; 3]> {
        let pix = &self.performance.pix;
        if pix.session {
            pix.frame_statistics
        } else {
            None
        }
    }

    fn pix_frame_number(&mut self) -> i32 {
        self.performance.pix.frame_number
    }

    fn pix_signal_event(&mut self, event: u32) {
        self.performance.pix.events.push(event);
    }

    fn pix_set_trace(&mut self, enabled: bool) {
        let pix = &mut self.performance.pix;
        pix.trace = enabled;
        pix.bitmap = [0; 2];
        if !enabled {
            pix.ring.clear();
        }
    }

    fn pix_counter_control(&mut self, group: u32, id: u32, enabled: bool) {
        let pix = &mut self.performance.pix;
        if group != 1 {
            pix.group_calls.push(GroupCall { group, id, enabled });
            return;
        }

        let Some(word) = pix.bitmap.get_mut((id / 32) as usize) else {
            return;
        };

        let bit = 1 << (id % 32);
        if enabled {
            *word |= bit;
        } else {
            *word &= !bit;
        }
    }

    fn pix_set_capture_value(&mut self, value: CaptureValue, data: u32) {
        let index = match value {
            CaptureValue::First => 0,
            CaptureValue::Second => 1,
        };
        self.performance.pix.capture_values[index] = data;
    }

    fn pix_set_capture_text(&mut self, text: &[u8]) {
        self.performance.pix.capture_text = text.to_vec();
    }

    fn pix_set_legacy_protocol(&mut self, legacy: bool) {
        self.performance.pix.legacy = legacy;
    }

    fn pix_set_gpu_capture(&mut self, enabled: bool) {
        self.performance.pix.gpu_capture = enabled;
    }

    fn pix_dogma(&mut self) -> Option<PixDogma> {
        self.performance.pix.dogma
    }

    fn pix_boot_animation_loaded(&mut self) -> bool {
        self.performance.pix.boot_animation
    }

    fn pix_capture_ready(&mut self) -> bool {
        self.performance.pix.capture_ready
    }

    fn pix_trace_snapshot(&mut self) -> u32 {
        self.performance.pix.take_snapshot()
    }

    fn pix_trace_read(&mut self, output: &mut [u8]) -> usize {
        self.performance.pix.read_snapshot(output)
    }
}
