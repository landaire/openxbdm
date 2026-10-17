//! CPU sampling profiler (stock 0x91f8eeb0..0x91f90bdf): `lopctrl` and
//! exports 149-151.
//!
//! A kernel interrupt hook (kernel exports 669-671) runs on every hardware
//! thread when the performance monitor interval timer expires. On a sampled
//! thread it records the interrupted call stack into 64 KiB blocks of that
//! thread; a writer thread moves full blocks to the capture file every
//! 250 ms. File layout: 0xc000 bytes of module snapshot (export 131), the
//! 0x200-byte header (rewritten with the final counters at the end), one
//! function table record per module, then the sample blocks.

mod blocks;
mod exports;
mod sampling;
mod writer;

use core::mem::offset_of;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::performance::CpuProfilerInfo;
use openxbdm_server::commands::performance::profiler;
use openxbdm_server::commands::performance::profiler::ProfilerError;
use openxbdm_server::commands::performance::profiler::ProfilerFlags;
use xbox360::time::FileTime;
use xbox360::time::Timebase;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::MmStatistics;
use xbox360_sys::xboxkrnl::ShareAccess;

use self::blocks::create_buffers;
use self::blocks::free_buffers;
use self::sampling::BUSY;
use self::sampling::disable_profile_interrupt;
use self::sampling::enable_profile_interrupt;
use self::sampling::profile_interrupt_entry;
use self::sampling::set_profile_routine;
use self::writer::start_writer;
use self::writer::stop_writer;
use self::writer::store_executable_path;
use self::writer::store_file_path;
use self::writer::write_raw;
use super::pmc;
use super::pmc::Owner;
use super::pmc::print;
use crate::backend::filesystem;
use crate::kernel;

/// Words of a sample record before the frames.
const RECORD_HEADER_WORDS: usize = 10;

const TITLE: &[u8] = b"Microsoft CPU Profiler for Xbox";
const TITLE_WORD_COUNT: usize = TITLE.len().div_ceil(4);

xbox360_sys::flags! {
    /// Interval timer control word
    /// ([`xboxkrnl::PrvRegister::INTERVAL_CONTROL`]).
    pub struct IntervalControl(u64) {
        /// Interrupt when the interval expires.
        INTERRUPT = 0x8000 << 32,
    }
}

/// A 64-bit header value as two words, high word first, each stored on its
/// own.
#[repr(C)]
struct DoubleWord([AtomicU32; 2]);

impl DoubleWord {
    const fn new() -> Self {
        Self([AtomicU32::new(0), AtomicU32::new(0)])
    }

    fn load(&self) -> u64 {
        u64::from(self.0[0].load(Ordering::Relaxed)) << 32
            | u64::from(self.0[1].load(Ordering::Relaxed))
    }

    fn store(&self, value: u64) {
        self.0[0].store((value >> 32) as u32, Ordering::Relaxed);
        self.0[1].store(value as u32, Ordering::Relaxed);
    }
}

/// One counter per hardware thread.
type PerProcessor = [AtomicU32; HARDWARE_THREAD_COUNT];

const fn per_processor() -> PerProcessor {
    [const { AtomicU32::new(0) }; HARDWARE_THREAD_COUNT]
}

/// The file header. The interrupt routine of each processor updates that
/// processor's counters while `info` reads them, so the words are atomics.
#[repr(C)]
struct ProfileHeader {
    version: AtomicU32,
    unknown_004: AtomicU32,
    write_errors: AtomicU32,
    _reserved_00c: AtomicU32,
    unknown_010: AtomicU32,
    processors: AtomicU32,
    start_time: DoubleWord,
    end_time: DoubleWord,
    /// Cleared with the counters; no known use.
    _unknown_028: PerProcessor,
    samples: PerProcessor,
    /// Stack walks that hit the depth limit or faulted.
    faulted: PerProcessor,
    record_header_size: AtomicU32,
    largest: PerProcessor,
    smallest: PerProcessor,
    bytes: PerProcessor,
    blocks: PerProcessor,
    stored: PerProcessor,
    dropped: PerProcessor,
    interrupts: PerProcessor,
    sampled: PerProcessor,
    /// Interrupts above dispatch level or in the idle thread.
    skipped: PerProcessor,
    /// Interrupts while the processor's previous sample was in progress.
    busy: PerProcessor,
    _reserved_164: [AtomicU32; 12],
    title: [AtomicU32; TITLE_WORD_COUNT],
    _reserved_1b4: [AtomicU32; 19],
}

const _: () = {
    assert!(offset_of!(ProfileHeader, version) == 0x00);
    assert!(offset_of!(ProfileHeader, unknown_004) == 0x04);
    assert!(offset_of!(ProfileHeader, write_errors) == 0x08);
    assert!(offset_of!(ProfileHeader, _reserved_00c) == 0x0c);
    assert!(offset_of!(ProfileHeader, unknown_010) == 0x10);
    assert!(offset_of!(ProfileHeader, processors) == 0x14);
    assert!(offset_of!(ProfileHeader, start_time) == 0x18);
    assert!(offset_of!(ProfileHeader, end_time) == 0x20);
    assert!(offset_of!(ProfileHeader, _unknown_028) == 0x28);
    assert!(offset_of!(ProfileHeader, samples) == 0x40);
    assert!(offset_of!(ProfileHeader, faulted) == 0x58);
    assert!(offset_of!(ProfileHeader, record_header_size) == 0x70);
    assert!(offset_of!(ProfileHeader, largest) == 0x74);
    assert!(offset_of!(ProfileHeader, smallest) == 0x8c);
    assert!(offset_of!(ProfileHeader, bytes) == 0xa4);
    assert!(offset_of!(ProfileHeader, blocks) == 0xbc);
    assert!(offset_of!(ProfileHeader, stored) == 0xd4);
    assert!(offset_of!(ProfileHeader, dropped) == 0xec);
    assert!(offset_of!(ProfileHeader, interrupts) == 0x104);
    assert!(offset_of!(ProfileHeader, sampled) == 0x11c);
    assert!(offset_of!(ProfileHeader, skipped) == 0x134);
    assert!(offset_of!(ProfileHeader, busy) == 0x14c);
    assert!(offset_of!(ProfileHeader, _reserved_164) == 0x164);
    assert!(offset_of!(ProfileHeader, title) == 0x194);
    assert!(offset_of!(ProfileHeader, _reserved_1b4) == 0x1b4);
    assert!(size_of::<ProfileHeader>() == 0x200);
    assert!(align_of::<ProfileHeader>() == 4);
};

impl ProfileHeader {
    const WORDS: usize = size_of::<Self>() / 4;
    /// Words cleared before the file is opened: the counters, up to the
    /// title.
    const CLEARED: core::ops::Range<usize> =
        offset_of!(ProfileHeader, _unknown_028) / 4..offset_of!(ProfileHeader, title) / 4;

    const fn new() -> Self {
        Self {
            version: AtomicU32::new(0),
            unknown_004: AtomicU32::new(0),
            write_errors: AtomicU32::new(0),
            _reserved_00c: AtomicU32::new(0),
            unknown_010: AtomicU32::new(0),
            processors: AtomicU32::new(0),
            start_time: DoubleWord::new(),
            end_time: DoubleWord::new(),
            _unknown_028: per_processor(),
            samples: per_processor(),
            faulted: per_processor(),
            record_header_size: AtomicU32::new(0),
            largest: per_processor(),
            smallest: per_processor(),
            bytes: per_processor(),
            blocks: per_processor(),
            stored: per_processor(),
            dropped: per_processor(),
            interrupts: per_processor(),
            sampled: per_processor(),
            skipped: per_processor(),
            busy: per_processor(),
            _reserved_164: [const { AtomicU32::new(0) }; 12],
            title: [const { AtomicU32::new(0) }; TITLE_WORD_COUNT],
            _reserved_1b4: [const { AtomicU32::new(0) }; 19],
        }
    }

    fn words(&self) -> &[AtomicU32; ProfileHeader::WORDS] {
        // SAFETY: the header consists of `AtomicU32` fields and arrays
        // without padding (offsets and size asserted above).
        unsafe { &*core::ptr::from_ref(self).cast() }
    }

    /// Write the header to the file at `offset` (see `writer::write`). The kernel
    /// reads the words; sampling has stopped or not started, so no
    /// processor changes them meanwhile.
    #[inline(always)]
    fn write(&self, offset: Option<u64>) -> bool {
        // SAFETY: the header is `size_of::<Self>()` bytes that stay
        // allocated; only the kernel reads them during the call.
        unsafe {
            write_raw(
                core::ptr::from_ref(self).cast::<u8>(),
                size_of::<Self>() as u32,
                offset,
            )
        }
    }
}

/// A per-processor counter of [`ProfileHeader`], as its byte offset.
#[repr(u32)]
#[derive(Clone, Copy)]
enum Counter {
    Samples = offset_of!(ProfileHeader, samples) as u32,
    Faulted = offset_of!(ProfileHeader, faulted) as u32,
    Stored = offset_of!(ProfileHeader, stored) as u32,
    Dropped = offset_of!(ProfileHeader, dropped) as u32,
    Interrupts = offset_of!(ProfileHeader, interrupts) as u32,
    Sampled = offset_of!(ProfileHeader, sampled) as u32,
    Skipped = offset_of!(ProfileHeader, skipped) as u32,
    Busy = offset_of!(ProfileHeader, busy) as u32,
}

static HEADER: ProfileHeader = ProfileHeader::new();

static CONTROL: profiler::Control = profiler::Control::new();
static FLAGS: AtomicU32 = AtomicU32::new(0);
/// Samples are recorded (stock 0x91fa3b08).
static SAMPLING_ACTIVE: AtomicBool = AtomicBool::new(false);
/// The interrupt routine is set.
static HOOKED: AtomicBool = AtomicBool::new(false);
static INTERVAL: AtomicU32 = AtomicU32::new(0);
static START_TIMEBASE: DoubleWord = DoubleWord::new();

/// Out of line, and the counter as an offset, so that each of the many
/// sites in the interrupt routine loads one constant.
#[inline(never)]
fn count(counter: Counter, processor: usize) {
    // SAFETY: each `Counter` is the offset of a `PerProcessor` field.
    let counters = unsafe {
        &*core::ptr::from_ref(&HEADER)
            .byte_add(counter as usize)
            .cast::<PerProcessor>()
    };
    counters[processor].fetch_add(1, Ordering::Relaxed);
}

fn processors() -> u32 {
    ProfilerFlags(FLAGS.load(Ordering::Relaxed)).processors()
}

fn sampled(processor: usize) -> bool {
    processors() & (1 << processor) != 0
}

/// Highest sampled processor; 0 without one.
fn last_processor() -> usize {
    let last = match processors() {
        0 => 0,
        mask => 31 - mask.leading_zeros() as usize,
    };

    // SAFETY: the processor mask has six bits.
    unsafe { core::hint::assert_unchecked(last < HARDWARE_THREAD_COUNT) };
    last
}

/// `words` as bytes in memory order.
fn word_bytes(words: &[u32]) -> &[u8] {
    // SAFETY: every byte of a `u32` is initialized and `u8` has no
    // alignment requirement.
    unsafe { core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), size_of_val(words)) }
}

/// Program the interval timer and run the counters (stock 0x91f90138).
fn start_sampling(interval: u32) -> bool {
    if !pmc::stop(Owner::PROFILER) || !pmc::clear(Owner::PROFILER) {
        return false;
    }

    // Stock leaves the other bits of the control value uninitialized.
    pmc::set_interval_control(IntervalControl::INTERRUPT.bits());
    INTERVAL.store(interval, Ordering::Relaxed);
    pmc::set_interval(interval.wrapping_neg());
    pmc::start(Owner::PROFILER)
}

/// Undo the interrupt hook and release the counters and buffers.
fn unhook() {
    disable_profile_interrupt();
    let _ = set_profile_routine(0);
    HOOKED.store(false, Ordering::Release);
    pmc::release(Owner::PROFILER);
}

/// The sampling engine behind [`CONTROL`].
struct Sampler;

impl profiler::Engine for Sampler {
    /// Stock 0x91f90768. Stock also reads the memory statistics into a
    /// local it discards and seeds a random interval generator whose output
    /// it never uses; the latter is omitted.
    fn initialize(&mut self, flags: ProfilerFlags) -> Result<(), ProfilerError> {
        const HEADER_VERSION: u32 = 0x201;
        /// `TITLE` as big-endian header words, NUL padded.
        const TITLE_WORDS: [u32; TITLE_WORD_COUNT] = {
            let mut words = [0u32; TITLE_WORD_COUNT];
            let mut index = 0;
            while index < TITLE.len() {
                words[index / 4] |= (TITLE[index] as u32) << (24 - 8 * (index % 4));
                index += 1;
            }
            words
        };

        FLAGS.store(flags.0, Ordering::Relaxed);
        if !create_buffers(flags) {
            print(c"[LOP] CreateSharedBuffers Failed!!!\n", &[]);
            return Err(ProfilerError::NoBuffers);
        }

        for word in HEADER.words() {
            word.store(0, Ordering::Relaxed);
        }

        let mut statistics = MmStatistics::new();
        // SAFETY: `statistics` is a live block with its length set.
        unsafe { xboxkrnl::MmQueryStatistics(&mut statistics) };

        HEADER.version.store(HEADER_VERSION, Ordering::Relaxed);
        HEADER
            .processors
            .store(flags.processors(), Ordering::Relaxed);

        for (index, &word) in TITLE_WORDS.iter().enumerate() {
            HEADER.title[index].store(word, Ordering::Relaxed);
        }

        for busy in &BUSY {
            busy.store(0, Ordering::Relaxed);
        }

        if !pmc::acquire(Owner::PROFILER) {
            return Err(ProfilerError::NoCounters);
        }

        HOOKED.store(true, Ordering::Release);
        set_profile_routine(profile_interrupt_entry as *const () as usize as u32)?;
        enable_profile_interrupt(flags.processors())?;
        pmc::reset();
        Ok(())
    }

    /// Stock 0x91f90220.
    fn abandon(&mut self) {
        unhook();
        free_buffers();
    }

    /// Stock 0x91f64448.
    fn create_directories(&mut self, path: &[u8]) {
        let request = CreateRequest {
            access: AccessMask::SYNCHRONIZE.union(AccessMask::LIST_DIRECTORY),
            allocation_size: None,
            attributes: FileAttributes::NORMAL,
            share: ShareAccess::READ.union(ShareAccess::WRITE),
            disposition: CreateDisposition::Create,
            options: CreateOptions::DIRECTORY_FILE
                .union(CreateOptions::SYNCHRONOUS_IO_NONALERT)
                .union(CreateOptions::OPEN_FOR_BACKUP_INTENT),
        };

        for (index, _) in path
            .iter()
            .enumerate()
            .skip(1)
            .filter(|&(_, &byte)| byte == b'\\')
        {
            if let Ok(handle) = filesystem::create_file(&path[..index], &request) {
                // SAFETY: `handle` was just opened and is closed once.
                unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
            }
        }
    }

    /// Stock 0x91f90258.
    fn start(&mut self, path: Option<&[u8]>, interval: u32) -> Result<(), ProfilerError> {
        if SAMPLING_ACTIVE.load(Ordering::Acquire) {
            print(c"[LOP] Already started\n", &[]);
            return Err(ProfilerError::AlreadyRunning);
        }

        let started = path.is_some_and(|path| {
            store_file_path(path);
            start_writer()
        });
        if !started {
            print(c"[LOP] Prologue Failed!!!\n", &[]);
            return Err(ProfilerError::PrologueFailed);
        }

        HEADER.start_time.store(FileTime::now().intervals());
        START_TIMEBASE.store(Timebase::now().ticks());
        if !start_sampling(interval) {
            stop_writer();
            return Err(ProfilerError::NoCounters);
        }

        SAMPLING_ACTIVE.store(true, Ordering::Release);
        Ok(())
    }

    /// Stock 0x91f90310, 0x91f901d0.
    fn stop(&mut self) -> Result<(), ProfilerError> {
        SAMPLING_ACTIVE.store(false, Ordering::Release);

        let result = if pmc::stop(Owner::PROFILER) {
            pmc::clear(Owner::PROFILER);
            INTERVAL.store(0, Ordering::Relaxed);
            Ok(())
        } else {
            Err(ProfilerError::NotCounterOwner)
        };

        unhook();
        stop_writer();
        free_buffers();
        result
    }

    /// Stock 0x91f90370.
    fn info(&mut self) -> CpuProfilerInfo {
        let elapsed = pmc::to_double(Timebase::now().ticks().wrapping_sub(START_TIMEBASE.load()))
            / pmc::to_double(kernel::performance_frequency());
        let last = last_processor();

        CpuProfilerInfo {
            elapsed_time: elapsed as i64 as u32,
            total_samples: HEADER.interrupts[last].load(Ordering::Relaxed),
            overhead_interrupts: HEADER.busy[last].load(Ordering::Relaxed),
        }
    }
}

/// `lopctrl start` and export 149: `path` is the object name of the
/// requested file, `executable` the drive path of the running executable.
pub(super) fn start(
    path: Option<&[u8]>,
    executable: &[u8],
    interval: u32,
    flags: ProfilerFlags,
) -> Result<(), ProfilerError> {
    if !CONTROL.running() {
        store_executable_path(executable);
    }

    CONTROL.start(&mut Sampler, path, interval, flags)
}

pub(super) fn stop() -> Result<(), ProfilerError> {
    CONTROL.stop(&mut Sampler)
}

pub(super) fn info() -> Result<CpuProfilerInfo, ProfilerError> {
    CONTROL.info(&mut Sampler)
}

/// Stock 0x91f32ff8.
pub(super) fn running() -> bool {
    CONTROL.running()
}

/// Profiler part of the title terminate notification (stock 0x91f33090).
pub(super) fn title_terminated() {
    CONTROL.title_terminated(&mut Sampler);
}

/// Remove the interrupt hook and stop the writer before the image unloads;
/// stock never unloads.
pub(super) fn shut_down() {
    if CONTROL.running() {
        let _ = CONTROL.stop(&mut Sampler);
    } else if HOOKED.load(Ordering::Acquire) {
        profiler::Engine::abandon(&mut Sampler);
    }
}
