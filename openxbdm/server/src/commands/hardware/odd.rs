//! Optical disc log (`oddlog`, exports 147 and 148): drive events queue
//! records in a ring that the platform's writer formats into the log file.

use core::fmt::Write as _;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use xbox360_sys::status::Severity;

use super::OddLogNotRunning;
use super::OddLogStartError;
use crate::text::Text;

/// Record slots of the ring.
const RING: usize = 64;

/// Services of the platform that runs the log writer.
pub trait OddPlatform {
    /// An open log file.
    type File: Copy;

    /// Timebase count.
    fn timebase(&mut self) -> u64;

    /// Create or overwrite the log file at the object path `path`.
    fn create_file(&mut self, path: &[u8]) -> Result<Self::File, KernelError>;
    fn write_file(&mut self, file: Self::File, text: &[u8]) -> NtStatus;
    fn close_file(&mut self, file: Self::File);

    /// A writer is about to start; [`Self::join_writer`] waits from here
    /// until it finishes or [`Self::writer_absent`] is called.
    fn writer_starting(&mut self);
    /// Start the writer on `file`. Each time it is woken it calls
    /// [`OddLog::drain`]; once it finds the log stopped it closes `file`
    /// and finishes.
    fn start_writer(&mut self, file: Self::File) -> NtStatus;
    /// No writer runs.
    fn writer_absent(&mut self);
    /// Wake the writer of `log`.
    fn wake_writer(&mut self, log: &OddLog);
    /// Wait until the writer finishes.
    fn join_writer(&mut self);
}

/// Argument of monitor control 0x46.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadRequest {
    pub sector: u32,
    pub count: u32,
}

/// Leading words of the GDF volume descriptor fields monitor control 0x48
/// passes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountRequest {
    pub root_sector: u32,
    pub root_size: u32,
}

/// Spindle speed index of the drive.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpindleSpeed(pub u32);

impl SpindleSpeed {
    /// Name in `SSC ` records (0x91f3d098).
    pub const fn name(self) -> &'static str {
        match self.0 {
            1 => "2.4x",
            2 => "5x",
            3 => "8x",
            4 => "12x",
            _ => "Unknown",
        }
    }
}

/// Argument of monitor control 0x49.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeedChangeRequest {
    pub current: SpindleSpeed,
    pub target: SpindleSpeed,
    pub status: NtStatus,
}

/// A reserved log writer: [`OddLog::reserve`] succeeded and
/// [`OddLog::start`] must follow, or the log stays busy.
#[must_use]
#[derive(Debug)]
pub struct OddLogReservation(());

/// Record words of a slot, laid out per record kind; a timebase value
/// takes two words, high word first.
type Words = [u32; 7];

/// Kind of a record. The value is the slot state of a ready record.
#[derive(Debug, Clone, Copy)]
enum RecordKind {
    /// `{start, count, requested, completed, status}`.
    Read = 2,
    /// `{sector, size, time}`.
    Mount = 3,
    /// `{current, target, status, time}`.
    SpeedChange = 4,
}

#[derive(Clone, Copy)]
enum SlotState {
    Free,
    /// A drive event owns the slot.
    Writing,
    /// The writer owns the slot.
    Ready(RecordKind),
}

impl SlotState {
    const fn raw(self) -> u32 {
        match self {
            Self::Free => 0,
            Self::Writing => 1,
            Self::Ready(kind) => kind as u32,
        }
    }

    /// Slots hold only values of [`Self::raw`].
    const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Free,
            1 => Self::Writing,
            2 => Self::Ready(RecordKind::Read),
            3 => Self::Ready(RecordKind::Mount),
            _ => Self::Ready(RecordKind::SpeedChange),
        }
    }
}

/// The state orders the words: they are written before a release store
/// of a ready state and read after an acquire load of it.
#[derive(Debug)]
struct Slot {
    state: AtomicU32,
    words: [AtomicU32; 7],
}

/// The log: a ring filled by drive events and drained by the writer.
#[derive(Debug)]
pub struct OddLog {
    /// 1 while no log is being written; drive events are dropped.
    stopped: AtomicU32,
    /// A start owns the writer.
    busy: AtomicU32,

    allocate: AtomicU32,
    drops: AtomicU32,
    read: AtomicU32,
    slots: [Slot; RING],

    /// Read the drive started. Stock tests the time for zero: a start
    /// latched at timebase 0 reads as no start.
    pending_start: AtomicU32,
    pending_count: AtomicU32,
    pending_time_high: AtomicU32,
    pending_time_low: AtomicU32,
}

impl OddLog {
    pub const fn new() -> Self {
        Self {
            stopped: AtomicU32::new(1),
            busy: AtomicU32::new(0),
            allocate: AtomicU32::new(RING as u32 - 1),
            drops: AtomicU32::new(0),
            read: AtomicU32::new(0),
            slots: [const {
                Slot {
                    state: AtomicU32::new(SlotState::Free.raw()),
                    words: [const { AtomicU32::new(0) }; 7],
                }
            }; RING],
            pending_start: AtomicU32::new(0),
            pending_count: AtomicU32::new(0),
            pending_time_high: AtomicU32::new(0),
            pending_time_low: AtomicU32::new(0),
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire) == 1
    }

    /// Monitor control 0x46 (0x91f3d210): latch the read for its
    /// completion while a log is written. `timebase` is the time the
    /// control read.
    pub fn read_start(&self, request: ReadRequest, timebase: u64) {
        if self.is_stopped() {
            return;
        }

        self.pending_start.store(request.sector, Ordering::Relaxed);
        self.pending_count.store(request.count, Ordering::Relaxed);
        self.pending_time_high
            .store((timebase >> 32) as u32, Ordering::Relaxed);
        self.pending_time_low
            .store(timebase as u32, Ordering::Release);
    }

    /// Monitor control 0x47 (0x91f3d6e0): a `READ` record of the latched
    /// read. The latch is kept, so a later completion repeats its start.
    pub fn read_complete<P: OddPlatform>(&self, platform: &mut P, status: NtStatus, timebase: u64) {
        if self.is_stopped() {
            return;
        }

        let low = self.pending_time_low.load(Ordering::Acquire);
        let high = self.pending_time_high.load(Ordering::Relaxed);
        if high == 0 && low == 0 {
            return;
        }

        let words = [
            self.pending_start.load(Ordering::Relaxed),
            self.pending_count.load(Ordering::Relaxed),
            high,
            low,
            (timebase >> 32) as u32,
            timebase as u32,
            status.0,
        ];
        self.publish(platform, RecordKind::Read, |_| words);
    }

    /// Monitor control 0x48 (0x91f3d7a0): a `GMNT` record.
    pub fn mount<P: OddPlatform>(&self, platform: &mut P, request: MountRequest) {
        self.publish(platform, RecordKind::Mount, |platform| {
            let time = platform.timebase();
            [
                request.root_sector,
                request.root_size,
                (time >> 32) as u32,
                time as u32,
                0,
                0,
                0,
            ]
        });
    }

    /// Monitor control 0x49 (0x91f3d808): an `SSC ` record.
    pub fn speed_change<P: OddPlatform>(&self, platform: &mut P, request: SpeedChangeRequest) {
        self.publish(platform, RecordKind::SpeedChange, |platform| {
            let time = platform.timebase();
            [
                request.current.0,
                request.target.0,
                request.status.0,
                (time >> 32) as u32,
                time as u32,
                0,
                0,
            ]
        });
    }

    /// Queue a record and wake the writer (0x91f3d2c0, 0x91f3d330,
    /// 0x91f3d3b0). A slot the writer has not freed counts a drop. Stock
    /// reads the record time after taking the slot, so `words` runs then.
    fn publish<P: OddPlatform>(
        &self,
        platform: &mut P,
        kind: RecordKind,
        words: impl FnOnce(&mut P) -> Words,
    ) {
        if self.is_stopped() {
            return;
        }

        let next = self.allocate.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        let index = if next >= RING as u32 {
            let wrapped = next % RING as u32;
            let _ =
                self.allocate
                    .compare_exchange(next, wrapped, Ordering::AcqRel, Ordering::Relaxed);
            wrapped
        } else {
            next
        };

        let slot = &self.slots[index as usize];
        if slot
            .state
            .compare_exchange(
                SlotState::Free.raw(),
                SlotState::Writing.raw(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            self.drops.fetch_add(1, Ordering::AcqRel);
            return;
        }

        for (word, value) in slot.words.iter().zip(words(platform)) {
            word.store(value, Ordering::Relaxed);
        }
        slot.state
            .store(SlotState::Ready(kind).raw(), Ordering::Release);
        platform.wake_writer(self);
    }

    /// One pass of the writer (0x91f3d878): write and free the ready
    /// records in ring order, then a `DROP` record of the drops counted
    /// since the last pass.
    pub fn drain<P: OddPlatform>(&self, platform: &mut P, file: P::File) {
        loop {
            let index = self.read.load(Ordering::Relaxed);
            let slot = &self.slots[index as usize];
            let SlotState::Ready(kind) = SlotState::from_raw(slot.state.load(Ordering::Acquire))
            else {
                break;
            };

            let words = slot
                .words
                .each_ref()
                .map(|word| word.load(Ordering::Relaxed));
            write_record(platform, file, kind, words);

            slot.state.store(SlotState::Free.raw(), Ordering::Release);
            self.read
                .store((index + 1) % RING as u32, Ordering::Relaxed);
        }

        let drops = self.drops.swap(0, Ordering::AcqRel);
        if drops != 0 {
            let mut line = Text::<0x20>::new();
            let _ = write!(line, "DROP,0x{drops:08x}\r\n");
            platform.write_file(file, line.as_bytes());
        }
    }

    /// First half of export 147 (0x91f3dad0), before stock hands the name
    /// to its writer: take the writer and clear the ring. The caller
    /// translates the log path only after this succeeds.
    pub fn reserve<P: OddPlatform>(
        &self,
        platform: &mut P,
    ) -> Result<OddLogReservation, OddLogStartError> {
        if self
            .busy
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return Err(OddLogStartError::Busy);
        }

        for slot in &self.slots {
            slot.state.store(SlotState::Free.raw(), Ordering::Relaxed);
        }
        self.read.store(0, Ordering::Relaxed);
        self.drops.store(0, Ordering::Relaxed);
        self.allocate.store(RING as u32 - 1, Ordering::Relaxed);
        self.pending_time_low.store(0, Ordering::Relaxed);
        self.pending_time_high.store(0, Ordering::Relaxed);
        platform.writer_starting();
        self.stopped.store(0, Ordering::Release);

        Ok(OddLogReservation(()))
    }

    /// Start the reserved log at the object path `path`, or report the
    /// path translation failure as the file status.
    pub fn start<P: OddPlatform>(
        &self,
        platform: &mut P,
        reservation: OddLogReservation,
        path: Result<&[u8], KernelError>,
    ) -> Result<(), OddLogStartError> {
        const HEADER: &[u8] = b"# Optical Disc Log Created on Console\r\n\
# Log Format Information:\r\n\
# READ,<StartSector>,<SectorCount>,<RequestTime_100ns>,<CompleteTime_100ns>,<NTSTATUS>,;for each read operation\r\n\
# GMNT,<RootDirStartSector>,<RootDirSize_bytes>,<Time_100ns>,;when GDFX filesystem is mounted\r\n\
# SSC ,<CurrentSpeed>,<TargetSpeed>,<NTSTATUS>,<Time_100ns>,;for each spindle speed change\r\n\
# DROP,<DropCount>,;indicates dropped log entries\r\n";

        let OddLogReservation(()) = reservation;
        let failed = match path.and_then(|path| platform.create_file(path)) {
            Ok(file) => {
                let written = failure(platform.write_file(file, HEADER));
                // Stock leaves a stop waiting forever when the writer thread
                // is not created; here no writer runs, so the stop returns.
                match written.and_then(|()| failure(platform.start_writer(file))) {
                    Ok(()) => return Ok(()),
                    Err(error) => {
                        platform.close_file(file);
                        Some(error)
                    }
                }
            }
            Err(error) => failure(error.status()).err(),
        };

        // Stock's writer reports the open or header status and exits; only
        // statuses with error severity fail the start. The stop flag stays
        // clear, so a later stop succeeds.
        platform.writer_absent();
        if let Some(error) = failed {
            self.busy.store(0, Ordering::Release);
            return Err(OddLogStartError::Failed(error));
        }

        Ok(())
    }

    /// Stop the log and wait for its writer (export 148, 0x91f3d140).
    pub fn stop<P: OddPlatform>(&self, platform: &mut P) -> Result<(), OddLogNotRunning> {
        if self
            .stopped
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return Err(OddLogNotRunning);
        }

        platform.wake_writer(self);
        platform.join_writer();
        self.busy.store(0, Ordering::Release);

        Ok(())
    }
}

/// The failure of a status with error severity. Warnings do not fail the
/// log.
fn failure(status: NtStatus) -> Result<(), KernelError> {
    if status.severity() == Severity::Error {
        status.result()
    } else {
        Ok(())
    }
}

/// Timebase words in 100 ns units; stock divides the signed count.
fn hundred_ns(high: u32, low: u32) -> u64 {
    /// Timebase ticks per 100 ns unit.
    const TIMEBASE_PER_100NS: i64 = 5;

    let timebase = u64::from(high) << 32 | u64::from(low);

    (timebase as i64 / TIMEBASE_PER_100NS) as u64
}

/// Format a record line (0x91f3d410).
fn write_record<P: OddPlatform>(platform: &mut P, file: P::File, kind: RecordKind, words: Words) {
    let mut line = Text::<0x100>::new();
    let _ = match kind {
        RecordKind::Mount => {
            let [sector, size, high, low, ..] = words;
            let size = u64::from(size);
            let time = hundred_ns(high, low);
            write!(line, "GMNT,0x{sector:08x},0x{size:016x},0x{time:016x}\r\n")
        }
        RecordKind::Read => {
            let [
                start,
                count,
                requested_high,
                requested_low,
                high,
                low,
                status,
            ] = words;
            let requested = hundred_ns(requested_high, requested_low);
            let completed = hundred_ns(high, low);
            write!(
                line,
                "READ,0x{start:08x},0x{count:08x},0x{requested:016x},0x{completed:016x},0x{status:08x}\r\n"
            )
        }
        RecordKind::SpeedChange => {
            let [current, target, status, high, low, ..] = words;
            let current = SpindleSpeed(current).name();
            let target = SpindleSpeed(target).name();
            let time = hundred_ns(high, low);
            write!(
                line,
                "SSC ,{current},{target},0x{status:08X},0x{time:016x}\r\n"
            )
        }
    };

    platform.write_file(file, line.as_bytes());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    use std::string::String;
    use std::vec::Vec;

    use super::*;

    /// A platform whose writer runs only when a test drains it.
    #[derive(Default)]
    struct Platform {
        timebase: u64,
        content: Vec<u8>,
    }

    impl OddPlatform for Platform {
        type File = ();

        fn timebase(&mut self) -> u64 {
            self.timebase
        }

        fn create_file(&mut self, _path: &[u8]) -> Result<(), KernelError> {
            Ok(())
        }

        fn write_file(&mut self, (): (), text: &[u8]) -> NtStatus {
            self.content.extend_from_slice(text);
            NtStatus::SUCCESS
        }

        fn close_file(&mut self, (): ()) {}

        fn writer_starting(&mut self) {}

        fn start_writer(&mut self, (): ()) -> NtStatus {
            NtStatus::SUCCESS
        }

        fn writer_absent(&mut self) {}

        fn wake_writer(&mut self, _log: &OddLog) {}

        fn join_writer(&mut self) {}
    }

    /// Log text after the header.
    fn records(platform: &Platform) -> String {
        let text = String::from_utf8(platform.content.clone()).unwrap();
        text.lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| format!("{line}\n"))
            .collect()
    }

    fn mount(sector: u32) -> MountRequest {
        MountRequest {
            root_sector: sector,
            root_size: 0x800,
        }
    }

    fn started() -> (OddLog, Platform) {
        let log = OddLog::new();
        let mut platform = Platform::default();
        let reservation = log.reserve(&mut platform).unwrap();
        log.start(&mut platform, reservation, Ok(b"log")).unwrap();

        (log, platform)
    }

    /// A drop advances the allocator past the reader, so after the drain
    /// the writer waits at slot 0 while new records fill slot 1 onward;
    /// they are written once slot 0 is filled again.
    #[test]
    fn drop_leaves_records_behind_the_reader_until_the_ring_wraps() {
        let (log, mut platform) = started();
        let line =
            |sector: u32| format!("GMNT,0x{sector:08x},0x0000000000000800,0x0000000000000000\n");

        for sector in 0..65 {
            log.mount(&mut platform, mount(sector));
        }
        log.drain(&mut platform, ());

        let mut expected: String = (0..64).map(line).collect();
        expected.push_str("DROP,0x00000001\n");
        assert_eq!(records(&platform), expected);

        log.mount(&mut platform, mount(0x40));
        log.drain(&mut platform, ());
        assert_eq!(records(&platform), expected);

        for sector in 0x41..0x80 {
            log.mount(&mut platform, mount(sector));
        }
        log.drain(&mut platform, ());

        expected.push_str(&line(0x7f));
        expected.extend((0x40..0x7f).map(line));
        assert_eq!(records(&platform), expected);
    }

    #[test]
    fn times_are_signed_timebase_counts_over_five() {
        let (log, mut platform) = started();

        platform.timebase = 0xffff_ffff_ffff_fff6;
        log.speed_change(
            &mut platform,
            SpeedChangeRequest {
                current: SpindleSpeed(4),
                target: SpindleSpeed(5),
                status: NtStatus(0xc000_009c),
            },
        );
        log.drain(&mut platform, ());

        assert_eq!(
            records(&platform),
            "SSC ,12x,Unknown,0xC000009C,0xfffffffffffffffe\n"
        );
    }
}
