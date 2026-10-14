//! Fast-cap and call-cap capture engine logic (`capctrl`, xbdm exports 65,
//! 66, 70, 71, 73, 74, 84, 90, 146, 162): the flag word, buffer sizing,
//! record encoding, and the control sequences of start (0x91f299c8), stop
//! (export 74), abort (export 162), and the title terminate part
//! (0x91f28a10). Platforms supply the buffers, hooks, and file writer
//! through [`Engine`].
//!
//! Capture file: the 0xc000-byte module snapshot of export 131 with the
//! per-processor data byte counts at +0xa91c, then for each processor in
//! order the chunks of its records from first to last.

use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;

use super::pmc::COUNTERS;
use super::pmc::Route;
use super::pmc::Setup;
use crate::backend::Backend;
use crate::commands::filesystem::DriveTable;
use crate::commands::filesystem::ObjectPath;

/// Start while a capture runs, from a title (export 73): the capture keeps
/// running.
pub const CONTINUED: Hresult = Hresult::success(0x06);
pub const ALREADY_RUNNING: Hresult = Hresult::error(0x19);
/// No capture buffers exist, or the capture is stopped.
pub const NO_CAPTURE: Hresult = Hresult::error(0x18);
pub const NO_BUFFER_MEMORY: Hresult = Hresult::error(0x1c);
pub const TITLE_CAPTURE_FAILED: Hresult = Hresult::error(0x1d);
pub const NOT_INSTRUMENTED: Hresult = Hresult::error(0x23);
pub const CALL_CAP_UNAVAILABLE: Hresult = Hresult::error(0x24);
/// A processor ran out of buffer space.
pub const BUFFER_FULL: Hresult = Hresult::error(0x26);
pub const TITLE_TERMINATED: Hresult = Hresult::error(0x27);
/// The capture ran longer than the 29-bit record timestamps cover.
pub const TOO_LONG: Hresult = Hresult::error(0x29);
pub const COUNTERS_UNAVAILABLE: Hresult = Hresult::error(0x2c);
pub const COUNTERS_LOST: Hresult = Hresult::error(0x2d);
/// Another start or stop holds the engine.
pub const BUSY: Hresult = Hresult(0x8007_00aa);

/// Kernel status of an unavailable call-cap service.
const CALL_CAP_SERVICE_UNAVAILABLE: u32 = 0xc000_0040;
/// Ceiling of a requested buffer size.
const BUFFER_SIZE_LIMIT: u32 = 0x1000_0000;
const PAGE_SIZE: u32 = 0x1000;
/// Probe range of the default buffer size, in MiB.
const PROBE_MEGABYTES: u32 = 0x100;
/// Ceiling of the chunk size when several processors record.
const CHUNK_SIZE_LIMIT: u32 = 0x4_0000;
/// Words kept free at the end of a chunk; records start below the limit.
pub const CHUNK_RESERVE_WORDS: u32 = 0x21;
/// Highest processor count of the flag word.
pub const MAX_PROCESSORS: usize = 6;
/// Byte offset of the per-processor data sizes in the capture file.
pub const FILE_DATA_SIZES: usize = 0xa91c;
/// Bytes of the module snapshot that opens the capture file.
pub const FILE_HEADER_SIZE: u32 = 0xc000;

/// The capture flag word (stock 0x91f96078).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureFlags(pub u32);

impl CaptureFlags {
    /// After initialization and every stop: record on the processor that
    /// starts the capture.
    pub const IDLE: Self = Self(0x2_0000);
    const PROCESSOR_MASK: u32 = 0x3f;
    const COUNTERS: u32 = 0x1_0000;
    /// Stored by a stop that saw a full buffer.
    pub const FULL_MARK: u32 = 0x8000_0000;

    /// Value of `capctrl flags=` and export 90.
    pub const fn from_request(value: u32) -> Self {
        Self(value & 0x7fff_ffff)
    }

    /// Recording processors.
    pub const fn processors(self) -> u32 {
        self.0 & Self::PROCESSOR_MASK
    }

    /// Records carry a performance counter value.
    pub const fn counters(self) -> bool {
        self.0 & Self::COUNTERS != 0
    }

    /// The flags a start uses: the idle bit or an empty mask selects the
    /// starting processor, which then stays selected.
    pub const fn for_start(self, processor: u8) -> Self {
        if self.0 & Self::IDLE.0 == 0 && self.processors() != 0 {
            self
        } else {
            Self(self.0 | 1 << processor | Self::IDLE.0)
        }
    }

    /// Counter sampled into each record.
    pub const fn counter_source(self) -> CounterSource {
        match (self.0 >> 6) & 0x1f {
            selector @ 0..=0x10 => CounterSource::Processor(CounterSetup(selector as u8)),
            0x11 => CounterSource::Memory(MemoryCounter::First),
            0x12 => CounterSource::Memory(MemoryCounter::Second),
            0x13 => CounterSource::Memory(MemoryCounter::Combined),
            selector => CounterSource::Unsupported(selector as u8),
        }
    }
}

/// Source of the counter value appended to records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterSource {
    /// Processor performance counter setup.
    Processor(CounterSetup),
    /// Memory controller counter block at 0x7fd20100.
    Memory(MemoryCounter),
    /// Selectors past 0x13: stock prints a message and traps.
    Unsupported(u8),
}

/// Memory controller counter programs of selectors 0x11 to 0x13.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryCounter {
    First,
    Second,
    /// Sum of both counters.
    Combined,
}

impl MemoryCounter {
    /// Event selections written to 0x7fd20104 and 0x7fd20110.
    pub const fn events(self) -> (u32, u32) {
        match self {
            Self::First => (0x0a, 0),
            Self::Second => (0x0c, 0),
            Self::Combined => (0x19, 0x1b),
        }
    }
}

/// Instrumentation kind a module carries in its XEX header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instrumentation {
    FastCap,
    CallCap,
}

impl Instrumentation {
    /// XEX header field key that marks the kind.
    pub const fn header_field(self) -> u32 {
        match self {
            Self::FastCap => 0x1_8200,
            Self::CallCap => 0x1_8102,
        }
    }
}

/// Record kinds; the kind occupies the top three bits of the first word,
/// the low 29 bits of the time base the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RecordKind {
    /// Export 65: two caller words.
    Pair = 0,
    /// Export 66: one caller word.
    Single = 1,
    /// Export 70: the return address of the call.
    Entry = 4,
    /// Export 71: the return address of the call.
    Exit = 5,
    /// Engine record: a [`ControlRecord`] code and a value.
    Control = 7,
}

/// Codes of [`RecordKind::Control`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ControlRecord {
    /// First record of a processor; the value is the current thread id.
    Start = 1,
    /// Last record of a processor; the value is the current thread id.
    Stop = 2,
    /// Thread switch; the value is the id of the incoming thread.
    ThreadSwitch = 5,
}

/// First word of a record.
pub const fn record_header(kind: RecordKind, timebase: u32) -> u32 {
    (kind as u32) << 29 | timebase & 0x1fff_ffff
}

/// Buffer size of `buffersize`: whole pages, at most 256 MiB; `None`
/// (zero, or a size that wraps to zero) selects the default size.
pub const fn requested_buffer_size(size: u32) -> Option<u32> {
    match size.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1) {
        0 => None,
        pages if pages > BUFFER_SIZE_LIMIT => Some(BUFFER_SIZE_LIMIT),
        pages => Some(pages),
    }
}

/// Largest whole MiB count below 256 that `fits` accepts, by bisection
/// (stock probes physical allocations); 0 when none fits.
pub fn probe_megabytes(fits: &mut dyn FnMut(u32) -> bool) -> u32 {
    let (mut low, mut high) = (0i32, PROBE_MEGABYTES as i32);
    let mut middle = high / 2;
    loop {
        if fits(middle as u32) {
            low = middle;
        } else {
            high = middle;
        }
        middle = (high + low) / 2;
        if high - low <= 1 {
            return middle as u32;
        }
    }
}

/// Default buffer size: 95 percent of the probed size, in whole pages.
pub const fn default_buffer_size(megabytes: u32) -> u32 {
    let size = megabytes << 20;
    let size = size - size / 100 * 5;
    size.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Index of a processor counter setup (stock table 0x91f96088, 0xa0 bytes
/// per setup); at most 0x10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterSetup(u8);

/// Event selections of the setups.
const COUNTER_SETUP_SELECTS: [u64; 17] = [
    0x0448_3a0d_0a56_2000,
    0x14a9_be0d_2a2f_8000,
    0x1499_bd8d_262f_6000,
    0x3459_bacd_166e_b000,
    0x3411_b88d_046e_2000,
    0x0318_18c0_c606_3000,
    0,
    0x0528_2941_4a0a_5000,
    0x0b58_5ac2_d616_b000,
    0x2631_3189_8c4c_6000,
    0x2739_39c9_ce4e_7000,
    0x4b5b_5ad2_d696_b000,
    0x4c63_6313_1898_c000,
    0x4d6b_6b53_5a9a_d000,
    0x4f7b_7bd3_de9e_f000,
    0x0948_4a42_5212_9000,
    0x0108_0840_4202_1000,
];
/// Counter routes (`source << 4 | lane`) of setups 0, 1 and 2, and 3 up.
const COUNTER_SETUP_ROUTES: [[u8; COUNTERS]; 3] = [
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x34, 0x35, 0x36, 0x37, 0x30, 0x31, 0x32,
        0x33,
    ],
    [
        0x3c, 0x32, 0x33, 0x34, 0x20, 0x21, 0x22, 0x23, 0x10, 0x11, 0x12, 0x13, 0x00, 0x01, 0x02,
        0x03,
    ],
    [
        0x3c, 0x32, 0x33, 0x34, 0x25, 0x21, 0x20, 0x20, 0x15, 0x11, 0x10, 0x10, 0x05, 0x01, 0x00,
        0x00,
    ],
];

impl CounterSetup {
    pub fn setup(self) -> Setup {
        let routes = &COUNTER_SETUP_ROUTES[match self.0 {
            0 => 0,
            1 | 2 => 1,
            _ => 2,
        }];
        Setup {
            select: COUNTER_SETUP_SELECTS[usize::from(self.0)],
            group: 0x1000_0000_0200_0000,
            trigger: 3,
            routes: core::array::from_fn(|counter| Route {
                source: u32::from(routes[counter] >> 4),
                lane: routes[counter] & 0xf,
            }),
        }
    }

    /// Counter each processor's records read (setup bytes +0x98..+0x9d).
    pub const fn counter_numbers(self) -> [u8; MAX_PROCESSORS] {
        match self.0 {
            0 => [0x0e, 0x0e, 0x0f, 0x0f, 0x08, 0x08],
            1 | 2 => [0x0d, 0x0f, 0x09, 0x0b, 0x05, 0x07],
            3 | 4 | 9..=14 => [0x0c, 0x0d, 0x08, 0x09, 0x04, 0x05],
            _ => [0x0d, 0x0c, 0x09, 0x08, 0x05, 0x04],
        }
    }
}

/// Chunk size: the whole buffer for one processor, else a 32nd of it up
/// to 256 KiB.
pub const fn chunk_size(buffer_size: u32, processors: u32) -> u32 {
    if processors == 1 {
        buffer_size
    } else if buffer_size >> 5 > CHUNK_SIZE_LIMIT {
        CHUNK_SIZE_LIMIT
    } else {
        buffer_size >> 5
    }
}

/// HRESULT of a Win32 error from the capture file writer.
pub const fn dos_result(error: u32) -> Hresult {
    if (error as i32) > 0 {
        Hresult(0x8007_0000 | error & 0xffff)
    } else {
        Hresult(error)
    }
}

/// Server state the capture file writer needs.
pub trait Paths {
    /// Object name of drive path `name` (stock 0x91f2e888).
    fn object_path(&mut self, name: &[u8]) -> Option<ObjectPath>;
    /// The running executable as a drive path (stock 0x91f33c38); returns
    /// the length.
    fn executable_drive_path(&mut self, output: &mut [u8]) -> usize;
}

/// [`Paths`] through the drive table.
pub struct DrivePaths<'a> {
    pub drives: &'a DriveTable,
    pub backend: &'a mut dyn Backend,
}

impl Paths for DrivePaths<'_> {
    fn object_path(&mut self, name: &[u8]) -> Option<ObjectPath> {
        self.drives.translate(self.backend, name)
    }

    fn executable_drive_path(&mut self, output: &mut [u8]) -> usize {
        let mut object_path = [0u8; 0x104];
        let length = self.backend.running_executable_path(&mut object_path);
        self.drives
            .object_path_to_drive_path(self.backend, &object_path[..length], output)
    }
}

/// Platform side of the engine; every method is a stock routine or global.
pub trait Engine {
    /// A loaded module carries `kind` (0x91f28ae0).
    fn instrumented(&mut self, kind: Instrumentation) -> bool;
    /// Kernel call-cap support (debug monitor service 2).
    fn set_kernel_call_cap(&mut self, enable: bool) -> NtStatus;
    /// The title-terminated mark (0x91fae7e8).
    fn set_title_terminated(&mut self, terminated: bool);
    /// Hand the capture to the title through its control words (buffer
    /// size bit 31).
    fn request_title_capture(&mut self, megabytes: u8) -> Hresult;
    /// Allocate the buffers and start recording (0x91f29210); `exclusive`
    /// rejects a running capture.
    fn begin(&mut self, name: &[u8], buffer_size: u32, exclusive: bool) -> Hresult;
    /// Stop recording (0x91f29830).
    fn end(&mut self) -> Hresult;
    fn flags(&mut self) -> CaptureFlags;
    /// Reset the flags to idle and keep `previous` (0x91fae800).
    fn retire_flags(&mut self, previous: u32);
    /// Stop the counters of `flags` (0x91f27db8).
    fn finish_counters(&mut self, flags: CaptureFlags) -> Hresult;
    /// Release the performance counters and mark them ready (0x91f96084).
    fn release_counters(&mut self);
    fn counters_ready(&mut self) -> bool;
    /// Take the start/stop interlock (0x91f9e49c).
    fn try_lock(&mut self) -> bool;
    fn unlock(&mut self);
    /// Write the capture file and free the buffers (0x91f28540).
    fn write(&mut self, paths: &mut dyn Paths) -> NtStatus;
    fn dos_error(&mut self, status: NtStatus) -> u32;
    /// Disable every processor and forget the buffers (title terminate).
    fn discard(&mut self);
}

/// Start after the file was validated (0x91f299c8, operation 1).
pub fn start(engine: &mut dyn Engine, name: &[u8], buffer_size: u32, exclusive: bool) -> Hresult {
    let fast_cap = engine.instrumented(Instrumentation::FastCap);
    let call_cap = engine.instrumented(Instrumentation::CallCap);
    engine.set_title_terminated(false);
    if !fast_cap && !call_cap {
        return NOT_INSTRUMENTED;
    }
    let size = buffer_size & 0x7fff_ffff;
    if buffer_size & 0x8000_0000 != 0 {
        return engine.request_title_capture((size >> 20) as u8);
    }
    if !fast_cap {
        let status = engine.set_kernel_call_cap(true);
        if !status.is_success() {
            return if status.0 == CALL_CAP_SERVICE_UNAVAILABLE {
                CALL_CAP_UNAVAILABLE
            } else {
                Hresult(status.0 | super::NT_FAILURE_MARKER)
            };
        }
    }
    engine.begin(name, size, exclusive)
}

/// Stop recording, release the counters, and retire the flags; returns
/// the result the caller continues with. Only a stop that writes the file
/// takes the counter result and marks a full buffer in the kept flags.
fn stop_recording(engine: &mut dyn Engine, writing: bool) -> Hresult {
    let stopped = engine.end();
    if !engine.instrumented(Instrumentation::FastCap)
        && engine.instrumented(Instrumentation::CallCap)
    {
        engine.set_kernel_call_cap(false);
    }
    let flags = engine.flags();
    let mut result = stopped;
    if flags.counters() {
        let finished = engine.finish_counters(flags);
        if writing && !stopped.is_failure() {
            result = if engine.counters_ready() {
                finished
            } else {
                COUNTERS_UNAVAILABLE
            };
        }
        engine.release_counters();
    }
    let flags = engine.flags();
    let full = writing && result == BUFFER_FULL;
    engine.retire_flags(if full {
        flags.0 | CaptureFlags::FULL_MARK
    } else {
        flags.0
    });
    result
}

/// Stop and write the capture file (export 74).
pub fn stop(engine: &mut dyn Engine, paths: &mut dyn Paths) -> Hresult {
    let mut result = stop_recording(engine, true);
    if result != BUFFER_FULL && result.is_failure() {
        return result;
    }
    if !engine.try_lock() {
        return BUSY;
    }
    let status = engine.write(paths);
    let error = engine.dos_error(status);
    if result != BUFFER_FULL {
        result = dos_result(error);
    }
    engine.unlock();
    if result.is_failure() {
        result
    } else {
        Hresult::OK
    }
}

/// Stop without writing the capture (export 162).
pub fn abort(engine: &mut dyn Engine) -> Hresult {
    let result = stop_recording(engine, false);
    if result == BUFFER_FULL || !result.is_failure() {
        Hresult::OK
    } else {
        result
    }
}

/// Capture part of the title terminate routine (0x91f28a10).
pub fn title_terminated(engine: &mut dyn Engine) {
    engine.set_title_terminated(true);
    let flags = engine.flags();
    if flags.counters() {
        engine.finish_counters(flags);
        engine.release_counters();
    }
    let flags = engine.flags();
    engine.retire_flags(flags.0);
    engine.discard();
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::*;

    #[test]
    fn flags_select_the_starting_processor_until_a_mask_is_set() {
        assert_eq!(CaptureFlags::IDLE.for_start(2), CaptureFlags(0x2_0004));
        assert_eq!(CaptureFlags(0x2_0004).for_start(3), CaptureFlags(0x2_000c));
        assert_eq!(CaptureFlags(0x10).for_start(3), CaptureFlags(0x10));
        assert_eq!(CaptureFlags(0x40).for_start(0), CaptureFlags(0x2_0041));
        assert_eq!(CaptureFlags::from_request(0x8000_0005), CaptureFlags(5));
    }

    #[test]
    fn counter_selector_occupies_bits_6_to_10() {
        assert_eq!(
            CaptureFlags(0x1_0000 | 0x10 << 6).counter_source(),
            CounterSource::Processor(CounterSetup(0x10))
        );
        assert_eq!(
            CaptureFlags(0x11 << 6).counter_source(),
            CounterSource::Memory(MemoryCounter::First)
        );
        assert_eq!(
            CaptureFlags(0x13 << 6).counter_source(),
            CounterSource::Memory(MemoryCounter::Combined)
        );
        assert_eq!(
            CaptureFlags(0x1f << 6).counter_source(),
            CounterSource::Unsupported(0x1f)
        );
    }

    #[test]
    fn record_headers_keep_29_timebase_bits() {
        assert_eq!(record_header(RecordKind::Pair, 0xffff_ffff), 0x1fff_ffff);
        assert_eq!(record_header(RecordKind::Single, 0x1234), 0x2000_1234);
        assert_eq!(record_header(RecordKind::Entry, 0xe000_0001), 0x8000_0001);
        assert_eq!(record_header(RecordKind::Exit, 0), 0xa000_0000);
        assert_eq!(record_header(RecordKind::Control, 5), 0xe000_0005);
    }

    #[test]
    fn requested_sizes_round_to_pages_and_clamp() {
        assert_eq!(requested_buffer_size(0), None);
        assert_eq!(requested_buffer_size(1), Some(0x1000));
        assert_eq!(requested_buffer_size(0x1000), Some(0x1000));
        assert_eq!(requested_buffer_size(0x1000_0001), Some(0x1000_0000));
        assert_eq!(requested_buffer_size(0xffff_f000), Some(0x1000_0000));
        assert_eq!(requested_buffer_size(0xffff_ffff), None);
    }

    #[test]
    fn probing_finds_the_largest_fitting_size() {
        assert_eq!(probe_megabytes(&mut |megabytes| megabytes <= 37), 37);
        assert_eq!(probe_megabytes(&mut |_| true), 0xff);
        assert_eq!(probe_megabytes(&mut |_| false), 0);
        assert_eq!(default_buffer_size(37), 0x0232_7000);
        assert_eq!(default_buffer_size(1), 0xf_4000);
    }

    #[test]
    fn chunks_split_the_buffer_between_processors() {
        assert_eq!(chunk_size(0x100_0000, 1), 0x100_0000);
        assert_eq!(chunk_size(0x100_0000, 2), 0x4_0000);
        assert_eq!(chunk_size(0x10_0000, 3), 0x8000);
    }

    #[test]
    fn writer_errors_become_win32_results() {
        assert_eq!(dos_result(0), Hresult(0));
        assert_eq!(dos_result(2), Hresult(0x8007_0002));
        assert_eq!(dos_result(0x1_0005), Hresult(0x8007_0005));
    }

    #[derive(Default)]
    struct Recorder {
        fast_cap: bool,
        call_cap: bool,
        kernel_call_cap: Vec<bool>,
        kernel_status: u32,
        title_terminated: Option<bool>,
        begun: Vec<(Vec<u8>, u32, bool)>,
        end: Option<Hresult>,
        flags: u32,
        previous: Option<u32>,
        finish: Option<Hresult>,
        ready: bool,
        released: bool,
        locked: bool,
        write: u32,
        discarded: bool,
    }

    impl Engine for Recorder {
        fn instrumented(&mut self, kind: Instrumentation) -> bool {
            match kind {
                Instrumentation::FastCap => self.fast_cap,
                Instrumentation::CallCap => self.call_cap,
            }
        }
        fn set_kernel_call_cap(&mut self, enable: bool) -> NtStatus {
            self.kernel_call_cap.push(enable);
            NtStatus(self.kernel_status)
        }
        fn set_title_terminated(&mut self, terminated: bool) {
            self.title_terminated = Some(terminated);
        }
        fn request_title_capture(&mut self, megabytes: u8) -> Hresult {
            Hresult(u32::from(megabytes))
        }
        fn begin(&mut self, name: &[u8], buffer_size: u32, exclusive: bool) -> Hresult {
            self.begun.push((name.to_vec(), buffer_size, exclusive));
            Hresult::OK
        }
        fn end(&mut self) -> Hresult {
            self.end.unwrap_or(NO_CAPTURE)
        }
        fn flags(&mut self) -> CaptureFlags {
            CaptureFlags(self.flags)
        }
        fn retire_flags(&mut self, previous: u32) {
            self.flags = CaptureFlags::IDLE.0;
            self.previous = Some(previous);
        }
        fn finish_counters(&mut self, _flags: CaptureFlags) -> Hresult {
            self.finish.unwrap_or(Hresult::OK)
        }
        fn release_counters(&mut self) {
            self.released = true;
            self.ready = true;
        }
        fn counters_ready(&mut self) -> bool {
            self.ready
        }
        fn try_lock(&mut self) -> bool {
            !core::mem::replace(&mut self.locked, true)
        }
        fn unlock(&mut self) {
            self.locked = false;
        }
        fn write(&mut self, _paths: &mut dyn Paths) -> NtStatus {
            NtStatus(self.write)
        }
        fn dos_error(&mut self, status: NtStatus) -> u32 {
            match status.0 {
                0 => 0,
                0xc000_000f => 2,
                other => other,
            }
        }
        fn discard(&mut self) {
            self.discarded = true;
        }
    }

    struct NoPaths;

    impl Paths for NoPaths {
        fn object_path(&mut self, _name: &[u8]) -> Option<ObjectPath> {
            None
        }
        fn executable_drive_path(&mut self, _output: &mut [u8]) -> usize {
            0
        }
    }

    #[test]
    fn start_requires_instrumentation_and_enables_call_cap_alone() {
        let mut engine = Recorder::default();
        assert_eq!(start(&mut engine, b"e:\\a", 0, true), NOT_INSTRUMENTED);
        assert_eq!(engine.title_terminated, Some(false));

        engine.call_cap = true;
        engine.kernel_status = 0xc000_0040;
        assert_eq!(start(&mut engine, b"e:\\a", 0, true), CALL_CAP_UNAVAILABLE);
        engine.kernel_status = 0xc000_0017;
        assert_eq!(start(&mut engine, b"e:\\a", 0, true), Hresult(0xd000_0017));
        engine.kernel_status = 0;
        assert_eq!(start(&mut engine, b"e:\\a", 0x1000, false), Hresult::OK);
        assert_eq!(engine.kernel_call_cap, [true, true, true]);

        engine.fast_cap = true;
        assert_eq!(start(&mut engine, b"e:\\b", 0x2000, true), Hresult::OK);
        assert_eq!(engine.kernel_call_cap.len(), 3);
        assert_eq!(
            engine.begun,
            [
                (b"e:\\a".to_vec(), 0x1000, false),
                (b"e:\\b".to_vec(), 0x2000, true)
            ]
        );
    }

    #[test]
    fn size_bit_31_hands_the_capture_to_the_title() {
        let mut engine = Recorder {
            call_cap: true,
            ..Recorder::default()
        };
        assert_eq!(
            start(&mut engine, b"e:\\a", 0x8350_0000, true),
            Hresult(0x35)
        );
        assert!(engine.kernel_call_cap.is_empty() && engine.begun.is_empty());
    }

    #[test]
    fn stop_writes_the_file_and_maps_the_writer_status() {
        let mut engine = Recorder {
            fast_cap: true,
            end: Some(Hresult::OK),
            flags: 0x2_0001,
            write: 0xc000_000f,
            ..Recorder::default()
        };
        assert_eq!(stop(&mut engine, &mut NoPaths), Hresult(0x8007_0002));
        assert_eq!(engine.previous, Some(0x2_0001));
        assert_eq!(engine.flags, CaptureFlags::IDLE.0);
        assert!(!engine.locked);

        engine.end = Some(BUFFER_FULL);
        engine.flags = 3;
        assert_eq!(stop(&mut engine, &mut NoPaths), BUFFER_FULL);
        assert_eq!(engine.previous, Some(0x8000_0003));

        engine.end = Some(Hresult::OK);
        engine.write = 0;
        engine.locked = true;
        assert_eq!(stop(&mut engine, &mut NoPaths), BUSY);
    }

    #[test]
    fn stop_failures_skip_the_file_and_only_call_cap_disables_the_service() {
        let mut engine = Recorder {
            call_cap: true,
            end: Some(TOO_LONG),
            ..Recorder::default()
        };
        assert_eq!(stop(&mut engine, &mut NoPaths), TOO_LONG);
        assert_eq!(engine.kernel_call_cap, [false]);
        engine.fast_cap = true;
        assert_eq!(abort(&mut engine), TOO_LONG);
        assert_eq!(engine.kernel_call_cap, [false]);
    }

    #[test]
    fn counter_mode_results() {
        let mut engine = Recorder {
            fast_cap: true,
            end: Some(Hresult::OK),
            flags: 0x1_0001,
            finish: Some(COUNTERS_LOST),
            ready: true,
            ..Recorder::default()
        };
        assert_eq!(stop(&mut engine, &mut NoPaths), COUNTERS_LOST);
        assert!(engine.released);

        engine.ready = false;
        engine.flags = 0x1_0001;
        engine.finish = Some(Hresult::OK);
        assert_eq!(stop(&mut engine, &mut NoPaths), COUNTERS_UNAVAILABLE);

        engine.ready = false;
        engine.flags = 0x1_0001;
        engine.finish = Some(COUNTERS_LOST);
        assert_eq!(abort(&mut engine), Hresult::OK);
        assert!(engine.ready);
    }

    #[test]
    fn abort_reports_stop_failures_except_a_full_buffer() {
        let mut engine = Recorder::default();
        assert_eq!(abort(&mut engine), NO_CAPTURE);
        engine.end = Some(BUFFER_FULL);
        engine.flags = 1;
        assert_eq!(abort(&mut engine), Hresult::OK);
        assert_eq!(engine.previous, Some(1));
    }

    #[test]
    fn title_termination_retires_the_capture() {
        let mut engine = Recorder {
            flags: 0x1_0002,
            ..Recorder::default()
        };
        title_terminated(&mut engine);
        assert_eq!(engine.title_terminated, Some(true));
        assert!(engine.released && engine.discarded);
        assert_eq!(engine.previous, Some(0x1_0002));
        assert_eq!(engine.flags, CaptureFlags::IDLE.0);
    }
}
