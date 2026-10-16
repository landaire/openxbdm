//! Simulated performance counters, display, video encoder, and profiling
//! engines.

use std::collections::BTreeMap;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use openxbdm_server::commands::filesystem;
use openxbdm_server::commands::filesystem::Backend as _;
use openxbdm_server::commands::filesystem::CreateOptions;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::DriveTable;
use openxbdm_server::commands::filesystem::FileAccess;
use openxbdm_server::commands::filesystem::ShareAccess;
use openxbdm_server::commands::performance;
use openxbdm_server::commands::performance::COUNTER_NAME_CAPACITY;
use openxbdm_server::commands::performance::CaptureValue;
use openxbdm_server::commands::performance::CounterEntry;
use openxbdm_server::commands::performance::CounterSample;
use openxbdm_server::commands::performance::CpuProfilerInfo;
use openxbdm_server::commands::performance::DisplayCapture;
use openxbdm_server::commands::performance::DisplayInformation;
use openxbdm_server::commands::performance::EDID_BLOCK_SIZE;
use openxbdm_server::commands::performance::EdidRead;
use openxbdm_server::commands::performance::PixDogma;
use openxbdm_server::commands::performance::PixMessage;
use openxbdm_server::commands::performance::TILE_SIZE;
use openxbdm_server::commands::performance::capture;
use openxbdm_server::commands::performance::capture::CaptureError;
use openxbdm_server::commands::performance::capture::CaptureFlags;
use openxbdm_server::commands::performance::capture::Instrumentation;
use openxbdm_server::commands::performance::capture::Started;
use openxbdm_server::commands::performance::counters;
use openxbdm_server::commands::performance::counters::CounterError;
use openxbdm_server::commands::performance::counters::CounterObject;
use openxbdm_server::commands::performance::counters::CounterRegistration;
use openxbdm_server::commands::performance::counters::Evaluation;
use openxbdm_server::commands::performance::profiler;
use openxbdm_server::commands::performance::profiler::ProfilerError;
use openxbdm_server::commands::performance::studio::StudioError;

use super::MockBackend;

/// Header bytes simulated before each counter object.
const OBJECT_HEADER: usize = 0x10;
/// Number of sampler buckets.
const BUCKETS: u32 = 10;
/// Capacity of the PIX message queue.
const PIX_QUEUE_CAPACITY: usize = 8;
const ERROR_FILE_NOT_FOUND: u32 = 2;

/// Built-in counters in the order the counter directory enumerates them.
const BUILT_IN_COUNTERS: &[(&str, u32, Source)] = &[
    ("%Thread5 DPC", 0x0002_0021, Source::Words(THREADS + 2 * 16)),
    ("Debugger Pages", 0x0002_0001, Source::Words(7)),
    ("Contiguous Pages", 0x0002_0001, Source::Words(6)),
    ("%Thread3 ISR", 0x0002_0021, Source::Words(THREADS + 2 * 11)),
    ("% GPU Frontend", 0x0002_0021, Source::Words(GPU + 2)),
    ("%Thread2 DPC", 0x0002_0021, Source::Words(THREADS + 2 * 7)),
    ("VM Pages", 0x0002_0001, Source::Words(5)),
    ("Pool Pages", 0x0002_0001, Source::Words(3)),
    ("%Thread0 ISR", 0x0002_0021, Source::Words(THREADS + 2 * 2)),
    ("Frame Ticks", 0x0001_0001, Source::FrameTicks),
    ("Image Pages", 0x0002_0001, Source::Words(2)),
    ("%Thread4 ISR", 0x0002_0021, Source::Words(THREADS + 2 * 14)),
    ("Frames", 0x0001_0011, Source::Frames),
    ("%Thread1 ISR", 0x0002_0021, Source::Words(THREADS + 2 * 5)),
    ("%Thread0 DPC", 0x0002_0021, Source::Words(THREADS + 2)),
    ("Cache Pages", 0x0002_0001, Source::Words(1)),
    ("%Thread3 DPC", 0x0002_0021, Source::Words(THREADS + 2 * 10)),
    ("% GPU Backend", 0x0002_0021, Source::Words(GPU + 4)),
    ("Stack Pages", 0x0002_0001, Source::Words(4)),
    ("% GPU", 0x0002_0021, Source::Words(GPU)),
    ("%Thread2 ISR", 0x0002_0021, Source::Words(THREADS + 2 * 8)),
    ("%Thread5 ISR", 0x0002_0021, Source::Words(THREADS + 2 * 17)),
    ("%Thread4 DPC", 0x0002_0021, Source::Words(THREADS + 2 * 13)),
    ("%Thread2 Idle", 0x0002_0021, Source::Words(THREADS + 2 * 6)),
    ("%Thread1 Idle", 0x0002_0021, Source::Words(THREADS + 2 * 3)),
    ("% GPU Swap Stall", 0x0002_0021, Source::Words(GPU + 6)),
    ("Free Pages", 0x0002_0001, Source::Words(0)),
    (
        "%Thread5 Idle",
        0x0002_0021,
        Source::Words(THREADS + 2 * 15),
    ),
    (
        "%Thread4 Idle",
        0x0002_0021,
        Source::Words(THREADS + 2 * 12),
    ),
    ("%Thread3 Idle", 0x0002_0021, Source::Words(THREADS + 2 * 9)),
    ("%Thread1 DPC", 0x0002_0021, Source::Words(THREADS + 2 * 4)),
    ("%Thread0 Idle", 0x0002_0021, Source::Words(THREADS)),
];

/// Source word layout: eight page counts, then per-processor idle, DPC,
/// and ISR time pairs (time, tick count) directly after them, then the GPU
/// pairs.
pub const PAGES: usize = 0;
pub const THREADS: usize = 8;
pub const GPU: usize = THREADS + 36;
const SOURCE_WORDS: usize = GPU + 8;

/// Where a simulated counter reads its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A value and rate word pair starting at this source word.
    Words(usize),
    /// The title's frame counter.
    Frames,
    /// The title's frame tick counter.
    FrameTicks,
}

/// A simulated counter object.
#[derive(Debug, Clone)]
pub struct Counter {
    pub name: Vec<u8>,
    pub source: Source,
    image: [u8; OBJECT_HEADER + counters::OBJECT_SIZE],
    /// Sampler bucket of the next visit.
    bucket: Option<u32>,
}

impl Counter {
    pub fn registration(&self) -> CounterRegistration {
        CounterRegistration(u32::from_be_bytes(
            self.image[OBJECT_HEADER + 8..OBJECT_HEADER + 12]
                .try_into()
                .unwrap(),
        ))
    }
}

/// Simulated counter directory and its sources.
#[derive(Debug, Clone)]
pub struct Counters {
    /// The counter directory exists.
    pub directory: bool,
    /// Objects in directory order.
    pub objects: Vec<Counter>,
    /// Counters named here exist but cannot be opened.
    pub locked: Vec<Vec<u8>>,
    pub sources: [u32; SOURCE_WORDS],
    /// Frame counter registered by the title's graphics runtime.
    pub frame_counter: Option<u32>,
    pub frame_ticks: Option<u32>,
    bucket: u32,
}

impl Default for Counters {
    fn default() -> Self {
        let mut counters = Self {
            directory: true,
            objects: Vec::new(),
            locked: Vec::new(),
            sources: [0; SOURCE_WORDS],
            frame_counter: None,
            frame_ticks: None,
            bucket: 0,
        };
        for &(name, registration, source) in BUILT_IN_COUNTERS {
            counters.register(name.as_bytes(), CounterRegistration(registration), source);
        }
        counters
    }
}

impl Counters {
    /// Create a counter object; periods above ten are rejected.
    pub fn register(
        &mut self,
        name: &[u8],
        registration: CounterRegistration,
        source: Source,
    ) -> bool {
        let period = registration.period();
        if period > counters::MAX_PERIOD {
            return false;
        }
        let mut counter = Counter {
            name: name.to_vec(),
            source,
            image: [0; OBJECT_HEADER + counters::OBJECT_SIZE],
            bucket: (period != 0).then(|| (self.bucket + period) % BUCKETS),
        };
        counters::initialize(
            &mut View {
                counter: &mut counter,
                counters: &self.sources_view(),
            },
            registration,
        );
        self.objects.push(counter);
        true
    }

    fn sources_view(&self) -> Sources {
        Sources {
            words: self.sources,
            frame_counter: self.frame_counter,
            frame_ticks: self.frame_ticks,
        }
    }

    /// One sampler tick: visit the counters due in the current bucket.
    pub fn tick(&mut self, tick_count: u32) {
        let sources = self.sources_view();
        let frame_number = self.frame_counter.unwrap_or(0);
        for counter in &mut self.objects {
            if counter.bucket != Some(self.bucket) {
                continue;
            }
            let period = counter.registration().period();
            counters::sample(
                &mut View {
                    counter,
                    counters: &sources,
                },
                tick_count,
                frame_number,
            );
            counter.bucket = Some((self.bucket + period) % BUCKETS);
        }
        self.bucket = (self.bucket + 1) % BUCKETS;
    }
}

/// Snapshot of the counter sources for one evaluation.
#[derive(Clone, Copy)]
struct Sources {
    words: [u32; SOURCE_WORDS],
    frame_counter: Option<u32>,
    frame_ticks: Option<u32>,
}

struct View<'a> {
    counter: &'a mut Counter,
    counters: &'a Sources,
}

impl View<'_> {
    fn at(offset: i32) -> usize {
        (offset + OBJECT_HEADER as i32) as usize
    }
}

impl CounterObject for View<'_> {
    fn read_u32(&self, offset: i32) -> u32 {
        let start = Self::at(offset);
        u32::from_be_bytes(self.counter.image[start..start + 4].try_into().unwrap())
    }

    fn read_u64(&self, offset: i32) -> u64 {
        let start = Self::at(offset);
        u64::from_be_bytes(self.counter.image[start..start + 8].try_into().unwrap())
    }

    fn write_u32(&mut self, offset: i32, value: u32) {
        let start = Self::at(offset);
        self.counter.image[start..start + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn write_u64(&mut self, offset: i32, value: u64) {
        let start = Self::at(offset);
        self.counter.image[start..start + 8].copy_from_slice(&value.to_be_bytes());
    }

    fn source_u32(&self, offset: u32) -> u32 {
        match self.counter.source {
            Source::Words(index) => self
                .counters
                .words
                .get(index + offset as usize / 4)
                .copied()
                .unwrap_or(0),
            Source::Frames | Source::FrameTicks => 0,
        }
    }

    fn source_u64(&self, offset: u32) -> u64 {
        (u64::from(self.source_u32(offset)) << 32) | u64::from(self.source_u32(offset + 4))
    }

    fn call_reader(
        &mut self,
        value: &mut u64,
        _rate: Option<&mut u64>,
    ) -> Result<(), CounterError> {
        let reading = match self.counter.source {
            Source::Frames => self.counters.frame_counter,
            Source::FrameTicks => self.counters.frame_ticks,
            Source::Words(_) => None,
        };
        let reading = reading.ok_or(CounterError::DataNotAvailable)?;
        *value = u64::from(reading);
        Ok(())
    }

    fn call_handler(
        &mut self,
        _query: counters::CounterQuery,
        _out: &mut CounterSample,
    ) -> Result<Evaluation, CounterError> {
        Err(CounterError::Routine(Hresult::FAIL))
    }

    // The simulated sampler runs only between commands.
    fn exclude_sampler(&mut self) {}

    fn allow_sampler(&mut self) {}
}

/// Simulated front buffer: tiled memory at the address the display
/// controller register names.
#[derive(Debug, Clone, Default)]
pub struct Display {
    pub capture: DisplayCapture,
    pub memory: Vec<u8>,
    /// Pages read by screenshots, by address.
    pub reads: Vec<u32>,
}

impl Display {
    /// A front buffer of `display` geometry at physical `address` whose
    /// pixel at (x, y) holds `pixel(x, y)` in memory byte order.
    pub fn new(
        display: DisplayInformation,
        address: u32,
        pixel: impl Fn(u32, u32) -> [u8; 4],
    ) -> Self {
        let surface_width = (u32::from(display.surface_width) + 31) & !31;
        let rows = (display.bottom + 31) & !31;
        let mut memory = vec![0u8; (surface_width * rows * 4) as usize];
        for y in 0..rows {
            for x in 0..surface_width {
                let offset = tiled_offset(x, y, surface_width) as usize;
                memory[offset..offset + 4].copy_from_slice(&pixel(x, y));
            }
        }
        let capture = DisplayCapture {
            display,
            front_buffer: address.wrapping_add(0x4000_0000),
            gamma: false,
        };
        Self {
            capture,
            memory,
            reads: Vec::new(),
        }
    }
}

/// Byte offset of pixel (x, y) in a 32-bit tiled surface `width` pixels
/// wide: 32 by 32 pixel tiles of 4 KiB in row-major order.
pub fn tiled_offset(x: u32, y: u32, width: u32) -> u32 {
    let aligned_width = (width + 31) & !31;
    let macro_offset = ((x >> 5) + (y >> 5) * (aligned_width >> 5)) << 9;
    let micro = ((x & 7) + ((y & 6) << 2)) << 2;
    let offset =
        macro_offset + ((micro & !0xf) << 1) + (micro & 0xf) + ((y & 8) << 5) + ((y & 1) << 4);
    ((offset & !0x1ff) << 3)
        + ((y & 16) << 7)
        + ((offset & 0x1c0) << 2)
        + ((((y & 8) >> 2) + (x >> 3)) & 3) * 64
        + (offset & 0x3f)
}

/// Simulated video encoder and GPU registers.
#[derive(Debug, Clone)]
pub struct Video {
    pub encoder: Vec<u32>,
    pub extended: bool,
    /// Extended bank writes, in order.
    pub extended_writes: Vec<(u32, u8)>,
    pub gpu: BTreeMap<u32, u32>,
    /// EDID blocks; `None` when the kernel lacks the EDID export.
    pub edid: Option<Vec<[u8; EDID_BLOCK_SIZE]>>,
}

impl Default for Video {
    fn default() -> Self {
        Self {
            encoder: (0..0x300u32)
                .map(|register| register.wrapping_mul(0x0101_0101))
                .collect(),
            extended: true,
            extended_writes: Vec::new(),
            gpu: BTreeMap::new(),
            edid: Some(vec![std::array::from_fn(|index| index as u8 ^ 0xa5)]),
        }
    }
}

/// Simulated capture engine of instrumented titles; the control sequences
/// run through `capture::{start, stop, abort}`.
#[derive(Debug, Clone)]
pub struct Capture {
    pub fast_cap: bool,
    pub call_cap: bool,
    /// Calls of the kernel call-cap service (debug monitor service 2).
    pub kernel_call_cap: Vec<bool>,
    pub flags: CaptureFlags,
    pub previous_flags: CaptureFlags,
    /// Buffers of a running or stopped capture.
    pub session: Option<CaptureSession>,
    /// A processor buffer filled up.
    pub full: bool,
    pub title_terminated: bool,
    /// Result word of a capture handed to the title; `None` when the title
    /// published no control words.
    pub title_capture: Option<Hresult>,
    pub counters_ready: bool,
    /// Object names of written capture files.
    pub written: Vec<Vec<u8>>,
}

/// Buffers of a simulated capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSession {
    pub name: Vec<u8>,
    pub buffer_size: u32,
    pub recording: bool,
}

impl Default for Capture {
    fn default() -> Self {
        Self {
            fast_cap: false,
            call_cap: false,
            kernel_call_cap: Vec::new(),
            flags: CaptureFlags::IDLE,
            previous_flags: CaptureFlags(0),
            session: None,
            full: false,
            title_terminated: false,
            title_capture: None,
            counters_ready: true,
            written: Vec::new(),
        }
    }
}

impl Capture {
    fn status(&self) -> Result<(), CaptureError> {
        if self.title_terminated {
            return Err(CaptureError::TitleTerminated);
        }
        match &self.session {
            Some(session) if session.recording => {
                if self.full {
                    Err(CaptureError::BufferFull)
                } else {
                    Ok(())
                }
            }
            _ => Err(CaptureError::NoCapture),
        }
    }
}

impl capture::Engine for Capture {
    fn instrumented(&mut self, kind: Instrumentation) -> bool {
        match kind {
            Instrumentation::FastCap => self.fast_cap,
            Instrumentation::CallCap => self.call_cap,
        }
    }

    fn set_kernel_call_cap(&mut self, enable: bool) -> Result<(), KernelError> {
        self.kernel_call_cap.push(enable);
        Ok(())
    }

    fn set_title_terminated(&mut self, terminated: bool) {
        self.title_terminated = terminated;
    }

    fn request_title_capture(&mut self, _megabytes: u8) -> Result<Started, CaptureError> {
        self.title_capture
            .map_or(Err(CaptureError::TitleCaptureFailed), capture::title_result)
    }

    fn begin(
        &mut self,
        name: &[u8],
        buffer_size: u32,
        exclusive: bool,
    ) -> Result<Started, CaptureError> {
        if let Some(session) = self.session.as_mut().filter(|session| session.recording) {
            if exclusive {
                return Err(CaptureError::AlreadyRunning);
            }
            session.name = name.to_vec();
            return Ok(Started::Continued);
        }
        self.full = false;
        self.session = Some(CaptureSession {
            name: name.to_vec(),
            buffer_size,
            recording: true,
        });
        Ok(Started::Recording)
    }

    fn end(&mut self) -> Result<(), CaptureError> {
        match &mut self.session {
            Some(session) if session.recording => {
                session.recording = false;
                if self.full {
                    Err(CaptureError::BufferFull)
                } else {
                    Ok(())
                }
            }
            _ => Err(CaptureError::NoCapture),
        }
    }

    fn flags(&mut self) -> CaptureFlags {
        self.flags
    }

    fn retire_flags(&mut self, previous: CaptureFlags) {
        self.flags = CaptureFlags::IDLE;
        self.previous_flags = previous;
    }

    fn finish_counters(&mut self, _flags: CaptureFlags) -> Result<(), CaptureError> {
        Ok(())
    }

    fn release_counters(&mut self) {
        self.counters_ready = true;
    }

    fn counters_ready(&mut self) -> bool {
        self.counters_ready
    }

    fn try_lock(&mut self) -> bool {
        true
    }

    fn unlock(&mut self) {}

    /// An untranslatable name fails the open and keeps the buffers.
    fn write(&mut self, paths: &mut dyn capture::Paths) -> Result<(), KernelError> {
        let Some(session) = &self.session else {
            return Ok(());
        };
        let path = paths
            .object_path(&session.name)
            .ok_or(KernelError::NoSuchFile)?;
        self.written.push(path.as_bytes().to_vec());
        self.session = None;
        Ok(())
    }

    fn dos_error(&mut self, error: KernelError) -> Option<Win32Error> {
        match error {
            KernelError::NoSuchFile => Win32Error::new(ERROR_FILE_NOT_FOUND),
            _ => None,
        }
    }

    fn discard(&mut self) {
        self.session = None;
    }
}

/// Simulated CPU sampling profiler engine.
#[derive(Debug, Clone)]
pub struct CpuProfiler {
    pub initialize_result: Result<(), ProfilerError>,
    pub start_result: Result<(), ProfilerError>,
    pub stop_result: Result<(), ProfilerError>,
    pub initializations: Vec<profiler::ProfilerFlags>,
    pub abandons: u32,
    /// Paths whose parent directories were created.
    pub directories: Vec<Vec<u8>>,
    /// Object paths and intervals of each start.
    pub starts: Vec<(Vec<u8>, u32)>,
    pub stops: u32,
    pub info: CpuProfilerInfo,
}

impl Default for CpuProfiler {
    fn default() -> Self {
        Self {
            initialize_result: Ok(()),
            start_result: Ok(()),
            stop_result: Ok(()),
            initializations: Vec::new(),
            abandons: 0,
            directories: Vec::new(),
            starts: Vec::new(),
            stops: 0,
            info: CpuProfilerInfo::default(),
        }
    }
}

impl profiler::Engine for CpuProfiler {
    fn initialize(&mut self, flags: profiler::ProfilerFlags) -> Result<(), ProfilerError> {
        self.initializations.push(flags);
        self.initialize_result
    }

    fn abandon(&mut self) {
        self.abandons += 1;
    }

    fn create_directories(&mut self, path: &[u8]) {
        self.directories.push(path.to_vec());
    }

    /// A name without an object path fails as the console engine reports it.
    fn start(&mut self, path: Option<&[u8]>, interval: u32) -> Result<(), ProfilerError> {
        let Some(path) = path else {
            return Err(ProfilerError::PrologueFailed);
        };
        self.starts.push((path.to_vec(), interval));
        self.start_result
    }

    fn stop(&mut self) -> Result<(), ProfilerError> {
        self.stops += 1;
        self.stop_result
    }

    fn info(&mut self) -> CpuProfilerInfo {
        self.info
    }
}

/// Simulated PIX engine.
#[derive(Debug, Clone, Default)]
pub struct Pix {
    /// A PIX session exists; without one nothing can be posted.
    pub session: bool,
    pub queue: Vec<PixMessage>,
    pub status: [u32; 12],
    pub frame_statistics: Option<[u32; 3]>,
    pub frame_number: i32,
    pub events: Vec<u32>,
    pub trace: bool,
    pub bitmap: [u32; 2],
    pub group_calls: Vec<(u32, u32, bool)>,
    pub capture_values: [u32; 2],
    pub capture_text: Vec<u8>,
    pub legacy: bool,
    pub gpu_capture: bool,
    pub dogma: Option<PixDogma>,
    pub boot_animation: bool,
    pub capture_ready: bool,
    /// Bytes queued in the trace ring.
    pub ring: Vec<u8>,
    /// Bytes of the snapshot not yet read.
    snapshot: Vec<u8>,
}

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
    pub cpu_profiler_control: profiler::Control,
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
            cpu_profiler_control: profiler::Control::new(),
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
        let counters = &self.performance.counters;
        if !counters.directory {
            return Err(CounterError::End);
        }
        let Some(counter) = counters.objects.get(*context as usize) else {
            return Err(CounterError::End);
        };
        *context += 1;
        if counter.name.len() >= COUNTER_NAME_CAPACITY {
            return Err(CounterError::NameTooLong);
        }
        name[..counter.name.len()].copy_from_slice(&counter.name);
        Ok(CounterEntry {
            name_len: counter.name.len(),
            counter_type: counter.registration().counter_type(),
        })
    }

    fn query_counter(
        &mut self,
        name: &[u8],
        query: counters::CounterQuery,
        out: &mut CounterSample,
    ) -> Result<Evaluation, CounterError> {
        let counters = &mut self.performance.counters;
        if !counters.directory {
            return Err(CounterError::NoDirectory);
        }
        let sources = counters.sources_view();
        let locked = counters
            .locked
            .iter()
            .any(|locked| locked.eq_ignore_ascii_case(name));
        let Some(counter) = counters
            .objects
            .iter_mut()
            .find(|counter| counter.name.eq_ignore_ascii_case(name))
        else {
            return Err(CounterError::NotFound);
        };
        if locked {
            return Err(CounterError::NotFound);
        }
        counters::query(
            &mut View {
                counter,
                counters: &sources,
            },
            query,
            out,
        )
    }

    fn capture_display(&mut self) -> DisplayCapture {
        self.performance.display.capture
    }

    fn read_framebuffer_page(&mut self, address: u32, page: &mut [u8]) {
        let display = &mut self.performance.display;
        display.reads.push(address);
        let base = display.capture.front_buffer.wrapping_sub(0x4000_0000);
        let start = address.wrapping_sub(base) as usize;
        match display.memory.get(start..start + TILE_SIZE as usize) {
            Some(bytes) => page.copy_from_slice(bytes),
            None => page.fill(0),
        }
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
        self.performance.video.gpu.get(&index).copied().unwrap_or(0)
    }

    fn write_gpu_register(&mut self, index: u32, value: u32) {
        self.performance.video.gpu.insert(index, value);
    }

    fn read_edid(&mut self, block: u8, output: &mut [u8; EDID_BLOCK_SIZE]) -> EdidRead {
        match &self.performance.video.edid {
            None => EdidRead::Unsupported,
            Some(blocks) => match blocks.get(usize::from(block)) {
                Some(data) => {
                    *output = *data;
                    EdidRead::Read
                }
                None => EdidRead::Failed,
            },
        }
    }

    fn dedicate_studio_socket(&mut self) -> Result<u16, StudioError> {
        self.performance.studio_port.ok_or(StudioError::Fail)
    }

    fn capture_start(
        &mut self,
        name: &[u8],
        path: &[u8],
        buffer: capture::BufferRequest,
    ) -> Result<Started, CaptureError> {
        let request =
            CreateRequest::open(FileAccess::DELETE, ShareAccess::ALL, CreateOptions::NONE);
        if let Ok(handle) = filesystem::Backend::create_file(self, path, &request) {
            let _ = self.set_delete_disposition(handle, true);
            self.close_file(handle);
        }
        capture::start(&mut self.performance.capture, name, buffer, true)
    }

    fn fast_cap_present(&mut self) -> bool {
        self.performance.capture.fast_cap
    }

    fn call_cap_present(&mut self) -> bool {
        self.performance.capture.call_cap
    }

    fn capture_stop(&mut self, drives: &DriveTable) -> Result<(), CaptureError> {
        let mut engine = std::mem::take(&mut self.performance.capture);
        let result = capture::stop(
            &mut engine,
            &mut capture::DrivePaths {
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
        capture::abort(&mut self.performance.capture)
    }

    fn cpu_profiler_start(
        &mut self,
        drives: &DriveTable,
        name: &[u8],
        interval: u32,
        flags: profiler::ProfilerFlags,
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

    fn pix_post(&mut self, code: u32, payload: &[u32]) -> bool {
        let message = PixMessage::new(code, payload);
        let pix = &mut self.performance.pix;
        if !pix.session {
            return false;
        }
        if message.code == 0xc
            && let Some(queued) = pix.queue.iter_mut().find(|queued| queued.code == 0xc)
        {
            *queued = message;
            return true;
        }
        if pix.queue.len() >= PIX_QUEUE_CAPACITY {
            return false;
        }
        pix.queue.push(message);
        true
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
        if group == 1 {
            if let Some(word) = pix.bitmap.get_mut((id / 32) as usize) {
                if enabled {
                    *word |= 1 << (id % 32);
                } else {
                    *word &= !(1 << (id % 32));
                }
            }
        } else {
            pix.group_calls.push((group, id, enabled));
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
        let pix = &mut self.performance.pix;
        pix.snapshot = std::mem::take(&mut pix.ring);
        pix.snapshot.len() as u32 & !3
    }

    fn pix_trace_read(&mut self, output: &mut [u8]) -> usize {
        let pix = &mut self.performance.pix;
        let count = (pix.snapshot.len() & !3).min(output.len());
        output[..count].copy_from_slice(&pix.snapshot[..count]);
        pix.snapshot.drain(..count);
        count
    }
}
