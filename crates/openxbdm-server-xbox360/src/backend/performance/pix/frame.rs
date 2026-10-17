//! Frame boundary (stock 0x91f57cf0, monitor control codes 0x2e and 0x52)
//! and the per-frame samplers it runs while the stream is active: the
//! processor time counters (0x91f56810) and the PIX performance counter
//! set (0x91f55620).

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands::performance::CounterSample;
use openxbdm_server::commands::performance::counters::CounterQuery;
use openxbdm_server::commands::performance::counters::Evaluation;
use xbox360::time::Timebase;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::processor::WaitStatistics;
use xbox360_sys::processor::WaitStatisticsFlags;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::MmStatistics;
use xbox360_sys::xboxkrnl::ProcessType;

use super::super::counters;
use super::super::pmc;
use super::RecordTag;
use super::events;
use super::events::CallbackOperation;
use super::ring;
use super::ring::PacketHeader;
use super::session::CaptureState;

/// Frames since the last `pixcmd r` and the last frame value (stock
/// 0x91fa2a5c and 0x91fa2a60).
static FRAME_COUNT: AtomicU32 = AtomicU32::new(0);
static FRAME: AtomicU32 = AtomicU32::new(0);
/// The title uses the old protocol (stock 0x91fa2a84): counter values are
/// also written as float records.
static LEGACY: AtomicBool = AtomicBool::new(false);
/// Old-protocol frame number record: value 2 of group 2.
const LEGACY_FRAME: u32 = PacketHeader::assignment(2, 2).raw();

pub(super) fn frame_number() -> u32 {
    FRAME.load(Ordering::Acquire)
}

pub(super) fn reset_frame_count() {
    FRAME_COUNT.store(0, Ordering::Release);
}

pub(super) fn set_legacy(legacy: bool) {
    LEGACY.store(legacy, Ordering::Release);
}

fn legacy() -> bool {
    LEGACY.load(Ordering::Acquire)
}

/// Monitor control code 0x2e: frame boundary with the frame value.
pub(crate) fn service_frame(frame: u32) -> u32 {
    // SAFETY: no record.
    unsafe { boundary(frame, 0) }
}

/// Monitor control code 0x52: frame boundary with a frame record whose
/// first dword is the frame value; a null record means frame 0.
///
/// # Safety
///
/// `record` must be 0 or the address of a title frame record as
/// [`super::capture::frame`] requires.
pub(crate) unsafe fn service_frame_record(record: u32) -> u32 {
    let frame = if record != 0 {
        // SAFETY: the caller's contract; the first word is the frame value.
        unsafe { crate::kernel::object_at::<AtomicU32>(record) }.load(Ordering::Relaxed)
    } else {
        0
    };
    // SAFETY: the caller's contract.
    unsafe { boundary(frame, record) }
}

fn write_float_record(id: u32, value: f32) {
    ring::write_block(&[id, value.to_bits()], true);
}

/// # Safety
///
/// `record` must be 0 or meet the contract of [`super::capture::frame`].
unsafe fn boundary(frame: u32, record: u32) -> u32 {
    FRAME_COUNT.fetch_add(1, Ordering::AcqRel);
    FRAME.store(frame, Ordering::Release);
    if super::stream_active() {
        sample_counters();
        sample_pmc();
        if xboxkrnl::KeGetCurrentProcessType() != ProcessType::SYSTEM {
            let d3d = events::callback(events::D3D_EVENT);
            if d3d != 0 {
                // SAFETY: a registered callback; registration requires it.
                unsafe { events::call(d3d, CallbackOperation::Frame, 0) };
                ring::write_frame_group(frame);
                if legacy() {
                    write_float_record(LEGACY_FRAME, frame as f32);
                }
            }
        }
        // The event types after the D3D type.
        for event in events::D3D_EVENT + 1..events::D3D_EVENT + events::TYPES as u32 {
            let callback = events::callback(event);
            if callback != 0 {
                // SAFETY: as above.
                unsafe { events::call(callback, CallbackOperation::Frame, 0) };
                ring::write_group(event as usize);
            }
        }
        ring::call_consumers(frame);
        ring::write_frame_marker(frame);
    }
    if xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE {
        if record != 0 {
            // SAFETY: the caller's contract.
            unsafe { super::capture::frame(record) };
        } else {
            super::capture::frame_without_record(1000);
        }
        if super::session::state_flags().contains(CaptureState::TIMING) {
            super::capture::module_records();
        }
    }
    1
}

/// One processor time counter of the sampler: counter name, history slot,
/// old-protocol record number, and the dword of the `XBDM` record with the
/// shift of its halfword.
struct TimeCounter {
    name: &'static [u8],
    slot: u8,
    record: u8,
    word: u8,
    shift: u8,
}

const fn counter(name: &'static [u8], slot: u8, record: u8, word: u8, high: bool) -> TimeCounter {
    TimeCounter {
        name,
        slot,
        record,
        word,
        shift: if high { 16 } else { 0 },
    }
}

/// Stock order of 0x91f56810; `word` is the dword of the `XBDM` record and
/// `high` its upper half.
const TIME_COUNTERS: [TimeCounter; 18] = [
    counter(b"%Thread0 Idle", 0, 0x09, 0x17, false),
    counter(b"%Thread1 Idle", 1, 0x0a, 0x17, true),
    counter(b"%Thread0 DPC", 2, 0x0b, 0x1d, false),
    counter(b"%Thread1 DPC", 3, 0x0c, 0x1d, true),
    counter(b"%Thread0 ISR", 0xc, 0x0d, 0x1a, false),
    counter(b"%Thread1 ISR", 0xd, 0x0e, 0x1a, true),
    counter(b"%Thread2 Idle", 4, 0x0f, 0x18, false),
    counter(b"%Thread3 Idle", 5, 0x10, 0x18, true),
    counter(b"%Thread4 Idle", 6, 0x11, 0x19, false),
    counter(b"%Thread5 Idle", 7, 0x12, 0x19, true),
    counter(b"%Thread2 DPC", 8, 0x13, 0x1e, false),
    counter(b"%Thread3 DPC", 9, 0x14, 0x1e, true),
    counter(b"%Thread4 DPC", 0xa, 0x15, 0x1f, false),
    counter(b"%Thread5 DPC", 0xb, 0x16, 0x1f, true),
    counter(b"%Thread2 ISR", 0xe, 0x17, 0x1b, false),
    counter(b"%Thread3 ISR", 0xf, 0x18, 0x1b, true),
    counter(b"%Thread4 ISR", 0x10, 0x19, 0x1c, false),
    counter(b"%Thread5 ISR", 0x11, 0x1a, 0x1c, true),
];
const SLOTS: usize = 0x12;
const PERCENT: f32 = 100.0;
/// 100 percent maps to 0xffff.
const HALFWORD_SCALE: f32 = 655.35;
/// `querypc` query of ratio class counters.
const COUNTER_QUERY: CounterQuery = CounterQuery(0x20);
/// Old-protocol time and memory records: values of group 1, by index.
const TIME_RECORD_BASE: u32 = PacketHeader::assignment(1, 0).raw();
/// First word of the `XBDM` record.
const XBDM_HEADER: u32 = 0x101;
/// `XBDM` record: 0x84 bytes.
const XBDM_WORDS: usize = 0x21;
/// Descriptor words of the `Cntn` record before the waits and before the
/// system count.
const CNTN_WAITS_DESCRIPTOR: u32 = 0x0103_0202;
const CNTN_SYSTEM_DESCRIPTOR: u32 = 0x0001_0104;

/// History of the time counters (stock 0x91fa2898 last percentages,
/// 0x91fa28e0 previous rates, 0x91fa2970 previous values); written only by
/// the frame boundary and `pixcmd r`/`b`, as in stock.
struct History {
    last: [f32; SLOTS],
    rate: [f64; SLOTS],
    value: [f64; SLOTS],
}

struct HistoryCell(UnsafeCell<History>);

// SAFETY: stock updates the history from the frame and `pixcmd` paths
// without a lock; the values are advisory percentages.
unsafe impl Sync for HistoryCell {}

static HISTORY: HistoryCell = HistoryCell(UnsafeCell::new(History {
    last: [-1.0; SLOTS],
    rate: [0.0; SLOTS],
    value: [0.0; SLOTS],
}));

fn history() -> &'static mut History {
    // SAFETY: see `HistoryCell`.
    unsafe { &mut *HISTORY.0.get() }
}

/// Reset the history (`pixcmd b`, stock 0x91f58034).
pub(super) fn reset_history() {
    let history = history();
    history.last = [-1.0; SLOTS];
    history.rate = [0.0; SLOTS];
    history.value = [0.0; SLOTS];
}

/// Percentage of slot `slot` from a cumulative value and rate (stock
/// 0x91f55450); `None` when no valid percentage is known.
fn percentage(slot: usize, value: f64, rate: f64) -> Option<f32> {
    let history = history();
    if value > rate {
        return None;
    }
    if !(rate > history.rate[slot]) {
        let last = history.last[slot];
        return (!(last < 0.0)).then_some(last);
    }
    let percent = ((value - history.value[slot]) / (rate - history.rate[slot])) as f32 * PERCENT;
    if percent > PERCENT || percent < 0.0 {
        return None;
    }
    history.value[slot] = value;
    history.rate[slot] = rate;
    history.last[slot] = percent;
    Some(percent)
}

fn query_counter(name: &[u8]) -> Option<CounterSample> {
    let handle = counters::open(name).ok()?;
    let mut sample = CounterSample::default();
    let result = counters::reference(handle).ok().map(|mut counter| {
        let result = counters::query(&mut counter, COUNTER_QUERY, &mut sample);
        counter.release();
        result
    });
    handle.close();
    let sampled = match result? {
        Ok(Evaluation::Sampled) => true,
        // A query routine's success counts only as exactly OK.
        Ok(Evaluation::Routine(result)) => result == Hresult::OK,
        Err(_) => false,
    };
    sampled.then_some(sample)
}

/// Sample the processor time counters, the processor statistics, and the
/// memory statistics into the stream (stock 0x91f56810).
pub(super) fn sample_counters() {
    let time = Timebase::now().ticks();
    let mut record = [0u32; XBDM_WORDS];
    record[0] = XBDM_HEADER;
    record[1] = (time >> 32) as u32;
    record[2] = time as u32;
    for counter in &TIME_COUNTERS {
        let Some(sample) = query_counter(counter.name) else {
            continue;
        };
        let Some(percent) = percentage(
            usize::from(counter.slot),
            sample.value as i64 as f64,
            sample.rate as i64 as f64,
        ) else {
            continue;
        };
        let halfword = (percent * HALFWORD_SCALE) as i64 as u16;
        record[usize::from(counter.word)] |= u32::from(halfword) << counter.shift;
        if legacy() {
            write_float_record(TIME_RECORD_BASE | u32::from(counter.record), percent);
        }
    }
    write_processor_statistics(time);
    write_memory_statistics(&mut record);
    super::write_tagged_words(RecordTag::XBDM.raw(), &record);
}

/// Sums of the per-processor statistics as `Cntn` and `Cnt2` records.
fn write_processor_statistics(time: u64) {
    let mut cycles = 0u64;
    let mut waits = 0u64;
    let mut begins = 0u32;
    let mut ends = 0u32;
    // SAFETY: the console kernel maps the control regions of all hardware
    // threads 4 KiB apart, ordered by number.
    for pcr in unsafe { Kpcr::all() } {
        cycles = cycles.wrapping_add(pcr.cycles());
        let address = pcr.wait_statistics.load(Ordering::Relaxed);
        if address == 0 {
            continue;
        }
        // SAFETY: a nonzero `wait_statistics` is the kernel's statistics
        // block of the processor; its words are only read here.
        let statistics = unsafe { crate::kernel::object_at::<WaitStatistics>(address) };
        if WaitStatisticsFlags::from_bits_retain(statistics.flags.load(Ordering::Relaxed))
            .contains(WaitStatisticsFlags::ENABLED)
        {
            waits = waits.wrapping_add(statistics.waits());
            begins = begins.wrapping_add(
                statistics
                    .system
                    .begins
                    .load(Ordering::Relaxed)
                    .wrapping_add(statistics.title.begins.load(Ordering::Relaxed)),
            );
            ends = ends.wrapping_add(
                statistics
                    .system
                    .ends
                    .load(Ordering::Relaxed)
                    .wrapping_add(statistics.title.ends.load(Ordering::Relaxed)),
            );
        }
    }
    let (time_high, time_low) = ((time >> 32) as u32, time as u32);
    super::write_tagged_words(
        RecordTag::CNTN.raw(),
        &[
            time_high,
            time_low,
            (cycles >> 32) as u32,
            cycles as u32,
            CNTN_WAITS_DESCRIPTOR,
            (waits >> 32) as u32,
            waits as u32,
            begins,
            CNTN_SYSTEM_DESCRIPTOR,
            ends,
        ],
    );
    super::write_tagged_words(
        RecordTag::CNT2.raw(),
        &[
            time_high,
            time_low,
            (waits >> 32) as u32,
            waits as u32,
            begins,
            ends,
        ],
    );
}

/// Statistics dwords copied into `XBDM` record words 3 on, with
/// old-protocol record numbers 0x20 on.
const MEMORY_FIELDS: [u8; 20] = [
    0x03, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18,
];
const FIRST_MEMORY_WORD: usize = 3;
const MEMORY_STATISTICS_LENGTH: u32 = core::mem::size_of::<MmStatistics>() as u32;
/// Reply length of `ExDebugMonitorService(MemoryStatistics)`.
const DEBUG_STATISTICS_LENGTH: u32 = 0x90;
/// Debug statistics word copied into `XBDM` record word 0x20.
const DEBUG_STATISTICS_FIELD: usize = 0x1b;
const DEBUG_MEMORY_WORD: usize = 0x20;
const LEGACY_MEMORY_RECORD: u32 = 0x20;

fn write_memory_statistics(record: &mut [u32; XBDM_WORDS]) {
    let mut statistics = [0u32; DEBUG_STATISTICS_LENGTH as usize / 4];
    statistics[0] = MEMORY_STATISTICS_LENGTH;
    // SAFETY: the buffer is 0x90 bytes, at least the `MmStatistics` size,
    // and its length word says 0x68.
    if unsafe { xboxkrnl::MmQueryStatistics(statistics.as_mut_ptr().cast()) }.is_success() {
        for (index, &field) in MEMORY_FIELDS.iter().enumerate() {
            let value = statistics[usize::from(field)];
            record[FIRST_MEMORY_WORD + index] = value;
            if legacy() {
                write_float_record(
                    TIME_RECORD_BASE | (LEGACY_MEMORY_RECORD + index as u32),
                    value as f32,
                );
            }
        }
    }
    statistics = [0; DEBUG_STATISTICS_LENGTH as usize / 4];
    statistics[0] = DEBUG_STATISTICS_LENGTH;
    statistics[1] = MEMORY_STATISTICS_LENGTH;
    // SAFETY: the buffer is 0x90 bytes, as its length word says.
    let status = unsafe {
        xboxkrnl::ExDebugMonitorService(
            DebugMonitorService::MemoryStatistics,
            statistics.as_mut_ptr() as usize as u32,
            0,
            0,
        )
    };
    record[DEBUG_MEMORY_WORD] = if status.is_success() && statistics[0] >= DEBUG_STATISTICS_LENGTH {
        statistics[DEBUG_STATISTICS_FIELD]
    } else {
        0
    };
}

/// PIX performance counter set (stock 0x91fa2ab4 active, 0x91fa2ab8 set
/// index, 0x91fa2648 slot cache).
static PMC_ACTIVE: AtomicBool = AtomicBool::new(false);
static PMC_SET: AtomicU32 = AtomicU32::new(0);
/// Counter setups cycled through, one per frame (stock 0x91f98f00).
const PMC_SETUPS: [u32; 7] = [0, 1, 2, 3, 4, 5, 0x2c];
/// Counter flags reported as their index in this table (stock 0x91f98f1c).
const PMC_FLAGS: [u32; 6] = [1, 2, 5, 0xb, 0x28, 0x2ad];
const PMC_COUNTERS: usize = 16;
const PMCP_TAG: RecordTag = RecordTag::new(*b"PMCP");
const PMC_UNCACHED: u8 = u8::MAX;
/// `PMC_FLAGS` index of each counter of each set; `PMC_UNCACHED` until found.
static PMC_CACHE: [[AtomicU8; PMC_COUNTERS]; PMC_SETUPS.len()] =
    [const { [const { AtomicU8::new(PMC_UNCACHED) }; PMC_COUNTERS] }; PMC_SETUPS.len()];

/// Index of counter `counter`'s flag in `PMC_FLAGS` for the current set,
/// cached once found (stock 0x91f55570).
fn pmc_flag_index(counter: usize) -> u32 {
    let slot = &PMC_CACHE[PMC_SET.load(Ordering::Acquire) as usize][counter];
    let cached = slot.load(Ordering::Acquire);
    if cached != PMC_UNCACHED {
        return u32::from(cached);
    }
    let flag = pmc::counter_flag(counter as u32);
    match PMC_FLAGS.iter().position(|&known| known == flag) {
        Some(index) => {
            slot.store(index as u8, Ordering::Release);
            index as u32
        }
        None => 0,
    }
}

/// Read the counters of the previous frame as a `PMCP` record and program
/// the next set (stock 0x91f55620).
fn sample_pmc() {
    /// First word of a `PMCP` record: the low byte of the setup from bit
    /// 16, and 1 in the low half (meaning unknown).
    const SETUP_SHIFT: u32 = 16;
    const LOW_HALF: u32 = 1;
    /// Counter value from bit 3 above its `PMC_FLAGS` index.
    const VALUE_SHIFT: u32 = 3;
    const FLAG_INDEX_MASK: u32 = 7;
    let time = Timebase::now().ticks();
    let set = PMC_SET.load(Ordering::Acquire);
    if PMC_ACTIVE.load(Ordering::Acquire) {
        let mut record = [0u32; 0x14];
        record[0] = (PMC_SETUPS[set as usize] & 0xff) << SETUP_SHIFT | LOW_HALF;
        record[1] = (time >> 32) as u32;
        record[2] = time as u32;
        let mut state = pmc::PmcState::new();
        if pmc::stop(pmc::Owner::PIX) && pmc::read_state(pmc::Owner::PIX, &mut state) {
            record[3] = state.interval as i64 as u32;
            for counter in 0..PMC_COUNTERS {
                record[4 + counter] = (state.counters[counter] as u32) << VALUE_SHIFT
                    | pmc_flag_index(counter) & FLAG_INDEX_MASK;
            }
            pmc::release(pmc::Owner::PIX);
        }
        PMC_ACTIVE.store(false, Ordering::Release);
        super::write_tagged_words(PMCP_TAG.raw(), &record);
    }
    let next = if (set as usize) < PMC_SETUPS.len() - 1 {
        set + 1
    } else {
        0
    };
    PMC_SET.store(next, Ordering::Release);
    if pmc::acquire(pmc::Owner::PIX)
        && pmc::install_on_all_processors(pmc::Owner::PIX, PMC_SETUPS[next as usize])
        && pmc::clear(pmc::Owner::PIX)
        && pmc::set_trigger_processor(
            pmc::Owner::PIX,
            u32::from(Kpcr::current().processor_number().get()) >> 1,
        )
        && pmc::start(pmc::Owner::PIX)
    {
        PMC_ACTIVE.store(true, Ordering::Release);
    }
}
