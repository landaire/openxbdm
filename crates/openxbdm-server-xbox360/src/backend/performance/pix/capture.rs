//! PIX frame capture engine (stock 0x91f58f10 to 0x91f62560): at each
//! title frame boundary it processes the session's messages, writes the
//! per-thread timing buffers, GPU command buffers and audio of the
//! configured parts to the `PixStream`/`PixDump` partition, and extracts
//! captured frames into PIX capture files.
//!
//! The engine keeps its state in the session block ([`PixSession`]). The
//! configuration selects the record stream (0 or 1, or off) of the
//! per-thread buffers (types 0-5), the second per-thread buffers (6-11),
//! the GPU buffers (0xd, 0xe) and the audio (0xc). Internal consistency
//! assertions of stock are not reproduced.

mod audio;
mod buffers;
mod engine;
mod gpu;
mod messages;
mod replay;
mod timing;
mod video;

use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU16;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use xbox360::time::Timebase;
use xbox360_sys::processor;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::KernelU32;

use super::session;
use super::session::EngineFlags;
use super::session::FrameRecord;
use super::session::FrameRecordFlags;
use super::session::Part;
use super::session::PixSession;

pub(crate) use audio::service_samples;
pub(crate) use timing::service_end;
pub(crate) use timing::service_nuicam_begin;
pub(super) use video::RenderClient;
pub(super) use video::VideoContext;

xbox360_sys::value_enum! {
    /// Identifiers of the data records in the per-thread buffers.
    pub enum TimingRecordId: u32 {
        /// Both threads' call stacks at a context swap.
        ContextSwap = 0x45,
        /// Thread identifiers of the processor table.
        Threads = 0x46,
        /// A loaded module.
        Module = 0x66,
        /// A module's debug directory.
        DebugDirectory = 0x67,
        /// The 100 ms marker.
        Marker = 0x6e,
    }
}

/// Hardware thread of the calling processor, below
/// [`processor::HARDWARE_THREAD_COUNT`], so per-thread arrays index it
/// without a check.
#[inline]
fn processor() -> usize {
    let index = Kpcr::current().processor_number().index();
    // SAFETY: the kernel numbers the hardware threads below the count.
    unsafe { core::hint::assert_unchecked(index < processor::HARDWARE_THREAD_COUNT) };
    index
}

fn timebase_low() -> u32 {
    Timebase::now().ticks() as u32
}

/// Active parts as `Ccap` and capture timing report them: per-thread data,
/// GPU, audio.
fn active_parts(s: &PixSession) -> u32 {
    let configuration = &s.configuration;
    u32::from(!configuration.part(Part::Thread).is_off())
        | u32::from(!configuration.part(Part::Gpu).is_off()) << 1
        | u32::from(!configuration.part(Part::Audio).is_off()) << 2
}

fn interrupts_off() {
    // SAFETY: interrupts_on follows every call; nothing in between waits or
    // faults.
    unsafe { processor::disable_interrupts() };
}

fn interrupts_on() {
    // SAFETY: follows interrupts_off.
    unsafe { processor::enable_interrupts() };
}

/// `lwsync`: orders a temporary block state word against the cursor
/// stores.
fn fence() {
    processor::lwsync();
}

fn sync() {
    // SAFETY: a full barrier; it changes no registers.
    unsafe { core::arch::asm!("sync", options(nostack)) };
}

/// Sign-extended 24-bit frame difference.
fn sign24(value: u32) -> i32 {
    ((value << 8) as i32) >> 8
}

/// Ring index after `next - 1`: `next`, or 0 at `count`.
fn wrap(next: u32, count: u32) -> u32 {
    if next < count { next } else { 0 }
}

/// Whether stream sequence `sequence` was overwritten by the stream at
/// sequence `current`: the generation in the top byte, the unit below
/// (stock 0x91f58f10, 0x91f5a310).
fn overwritten(sequence: u32, current: u32) -> bool {
    const GENERATION_SHIFT: u32 = 24;
    const UNIT_MASK: u32 = 0x00ff_ffff;
    let generation = sequence >> GENERATION_SHIFT;
    if generation == current >> GENERATION_SHIFT {
        return false;
    }
    if generation != (current >> GENERATION_SHIFT).wrapping_sub(1) & 0xff {
        return true;
    }
    sequence & UNIT_MASK <= current & UNIT_MASK
}

/// Cached view of physical capture memory at `address`; mappings from
/// 0xe0000000 lie 4 KiB into physical memory.
fn cached(address: u32) -> u32 {
    const PHYSICAL: u32 = 0x1fff_ffff;
    const CACHED_BASE: u32 = 0xc000_0000;
    let page_offset = ((address >> 20) + 0x200) & 0x1000;
    (address & PHYSICAL)
        .wrapping_add(page_offset)
        .wrapping_add(CACHED_BASE)
}

/// The least significant byte of `word`, which lies last in memory, for
/// the accesses stock makes to it alone.
///
/// # Safety
///
/// Byte and word accesses to `word` must not race while the view lives.
unsafe fn low_byte(word: &AtomicU32) -> &AtomicU8 {
    // SAFETY: the byte lies in the word and `AtomicU8` needs no alignment;
    // the caller excludes mixed-size races.
    unsafe { &*(&raw const *word).cast::<AtomicU8>().add(3) }
}

/// The least significant halfword of `word`, which lies last in memory,
/// for the accesses stock makes to it alone.
///
/// # Safety
///
/// As [`low_byte`].
unsafe fn low_half(word: &AtomicU32) -> &AtomicU16 {
    // SAFETY: the halfword lies in the word at an even offset; the caller
    // excludes mixed-size races.
    unsafe { &*(&raw const *word).cast::<AtomicU16>().add(1) }
}

/// Store a PIX buffer cursor, limit or flags word of a processor control
/// region.
///
/// # Safety
///
/// The kernel and titles write capture records on the processor from each
/// buffer's cursor up to its limit, and act on the flags. After the store,
/// that range must lie in a capture buffer or temporary block of the
/// session that stays allocated while it is installed, or be empty.
unsafe fn set_pcr_word(field: &KernelU32, value: u32) {
    // SAFETY: guaranteed by the caller.
    unsafe { field.store(value, Relaxed) };
}

/// Title part of the frame boundary (stock 0x91f622d8, code 0x52) with the
/// title's frame record at `record`, or 0.
///
/// # Safety
///
/// `record` must be 0 or the address of a title frame record the caller
/// keeps valid for the call: the short words and, with the full flag, the
/// extension after them.
pub(super) unsafe fn frame(record: u32) {
    let empty = FrameRecord::new();
    let (zero_short, zero_extension) = empty.parts();
    if record == 0 {
        frame_words(zero_short, zero_extension);
        return;
    }
    // SAFETY: the caller's contract.
    let short =
        unsafe { crate::kernel::object_at::<[AtomicU32; FrameRecord::SHORT_WORDS]>(record) };
    if is_full(short) {
        // SAFETY: as above; the extension follows the short words.
        let extension = unsafe {
            crate::kernel::object_at::<[AtomicU32; FrameRecord::EXTENSION_WORDS]>(
                record + size_of_val(short) as u32,
            )
        };
        frame_words(short, extension);
    } else {
        frame_words(short, zero_extension);
    }
}

fn is_full(short: &[AtomicU32; FrameRecord::SHORT_WORDS]) -> bool {
    FrameRecordFlags::from_bits_retain(short[3].load(Relaxed)).contains(FrameRecordFlags::FULL)
}

/// Frame boundary with a frame record: start capturing on the first
/// frame, process the messages, write the frame record, and report the
/// engine state in the record (`+0x20` version, `+0x24` revision, `+0x28`
/// flags, `+0x2c` with [`FrameRecordFlags::FULL`]). `extension` is zero
/// for a record without the full flag.
fn frame_words(
    short: &[AtomicU32; FrameRecord::SHORT_WORDS],
    extension: &[AtomicU32; FrameRecord::EXTENSION_WORDS],
) {
    let Some(locked) = session::lock() else {
        return;
    };
    let s = locked.session();
    if !s.engine_flags().contains(EngineFlags::RUNNING) {
        if s.allocation_attempted.load(Relaxed) == 0 {
            buffers::allocate_all(s);
        }
        engine::capture_record(s);
        engine::start(s);
        engine::frame_record(s, 0, None, 0);
    }
    timing::service_buffers(s);
    let full = is_full(short);
    let (copy_short, copy_extension) = s.frame_record.parts();
    for (word, source) in copy_short.iter().zip(short) {
        word.store(source.load(Relaxed), Relaxed);
    }
    for (word, source) in copy_extension.iter().zip(extension) {
        word.store(source.load(Relaxed), Relaxed);
    }
    let flags = s.engine_flags();
    s.frame_times[(flags.bits() >> EngineFlags::FRAME_SHIFT & 0x1f) as usize]
        .store(timebase_low(), Relaxed);
    s.set_engine_flags(s.engine_flags().next_frame());
    gpu::poll(s, false);
    gpu::flush_frame_buffers(s, s.frame_index().wrapping_sub(2));
    let mut state = FrameState::empty();
    messages::dispatch(s, short[3].load(Relaxed), &mut state);
    engine::frame_record(s, short[4].load(Relaxed), None, 0);
    let configuration = &s.configuration;
    if !configuration.part(Part::Thread).is_off() {
        state |= FrameState::TIMING;
        if s.entries[0xe].load(Relaxed) == 0 {
            state |= FrameState::NO_FRAME_BUFFER;
        }
    } else {
        state |= FrameState::NO_FRAME_BUFFER;
    }
    if !configuration.part(Part::Gpu).is_off() {
        state |= FrameState::GPU;
    }
    if s.message.is(session::EngineMessage::CaptureToFile) {
        state |= FrameState::CAPTURE_TO_FILE;
    }
    short[10].store(state.bits(), Relaxed);
    short[8].store(session::STATUS_VERSION, Relaxed);
    short[9].store(s.revision.load(Relaxed), Relaxed);
    if full {
        short[11].store(configuration.frame_word.load(Relaxed), Relaxed);
    }
    if s.capture_record_dropped.load(Relaxed) != 0 {
        engine::capture_record(s);
    }
}

xbox360_sys::flags! {
    /// Engine state reported in frame record `+0x28`.
    pub struct FrameState(u32) {
        /// Per-thread timing data is captured.
        TIMING = 0x1,
        /// A capture to file is in progress.
        CAPTURE_TO_FILE = 0x2,
        /// GPU data is captured.
        GPU = 0x4,
        /// No frame buffer is handed out.
        NO_FRAME_BUFFER = 0x10,
        /// Message 15: resource capture is active.
        RESOURCE_ACTIVE = 0x20,
        /// Message 15: resource capture is inactive.
        RESOURCE_INACTIVE = 0x40,
        /// Message 15: inactive, with a notification requested.
        RESOURCE_NOTIFY = 0x80,
    }
}

/// Frame boundary without a frame record (stock 0x91f62508): a record
/// with `milliseconds` in `+4` and the GPU idle wait as the stop routine.
pub(super) fn frame_without_record(milliseconds: u32) {
    let record = FrameRecord::new();
    record.milliseconds.store(milliseconds, Relaxed);
    record
        .stop_routine
        .store(wait_for_gpu as *const () as usize as u32, Relaxed);
    let (short, extension) = record.parts();
    frame_words(short, extension);
}

extern "C" fn wait_for_gpu(_argument: u32) {
    gpu::wait_for_idle();
}

/// Module records at the frame boundary (stock 0x91f55db8): the threads of
/// the debug monitor data's processor table, then each loaded module and
/// its debug directory; skipped while paused by message 13.
pub(super) fn module_records() {
    if session::session().is_some_and(|s| s.engine_flags().contains(EngineFlags::PAUSED)) {
        return;
    }
    let table = crate::kernel::debug_monitor_data()
        .processor_blocks
        .load(Relaxed);
    if table != 0 {
        // SAFETY: the kernel's table of the processor control blocks of
        // the six hardware threads.
        let blocks = unsafe {
            crate::kernel::object_at::<[AtomicU32; processor::HARDWARE_THREAD_COUNT]>(table)
        };
        // Stock leaves the identifiers of empty slots unset.
        let mut threads = [0u32; processor::HARDWARE_THREAD_COUNT];
        for (thread, block) in threads.iter_mut().zip(blocks) {
            let block = block.load(Relaxed);
            if block != 0 {
                // SAFETY: a processor control block starts with the address
                // of the thread it runs, which the kernel keeps allocated
                // while it is current. Another processor may switch the
                // thread out and the thread may end between the two reads;
                // stock has the same race and reads the identifier
                // unguarded.
                *thread = unsafe {
                    crate::kernel::thread_at(
                        crate::kernel::object_at::<AtomicU32>(block).load(Relaxed),
                    )
                }
                .id;
            }
        }
        timing::write_typed_record(TimingRecordId::Threads, &threads);
    }
    timing::write_record(TimingRecordId::Module, &[]);
    let mut walk = 0u32;
    let mut module = [0u32; crate::backend::memory::MODULE_RECORD_SHORT_SIZE / 4];
    let mut directory = [0u32; 0x118 / 4];
    while crate::backend::memory::next_module(&mut walk, &mut module).is_ok() {
        crate::backend::memory::module_debug_directory(module[0x104 / 4], &mut directory);
        timing::write_long_record(TimingRecordId::Module, &module[..0x49]);
        timing::write_long_record(TimingRecordId::DebugDirectory, &directory[..0x46]);
    }
    if walk != 0 {
        // SAFETY: the pool block `next_module` allocated for the walk.
        unsafe { xboxkrnl::ExFreePool(walk) };
    }
}

/// Title end part (stock 0x91f62100), from the title terminate routine.
pub(super) fn title_ended() {
    if let Some(locked) = session::lock() {
        messages::title_ended(locked.session());
    }
}

/// Server pass (stock 0x91f62228): replace the buffers a raised-level
/// writer switched away from.
pub(super) fn poll() {
    let Some(s) = session::session() else { return };
    if timing::take_pending_service(s)
        && let Some(locked) = session::lock()
    {
        timing::service_buffers(locked.session());
    }
}

/// Thread termination part (stock 0x91f5df80): wait for the thread's
/// partition writes.
pub(crate) fn thread_terminated() {
    if let Some(s) = session::session() {
        buffers::wait_for_thread(s);
    }
}

/// Stop capturing before the image is unloaded: the timer, the swap
/// routine and the per-thread buffers refer to it.
pub(super) fn shut_down() {
    if let Some(locked) = session::lock() {
        let s = locked.session();
        if s.engine_flags().contains(EngineFlags::RUNNING) {
            engine::stop(s, &FrameRecord::new(), true, false);
        }
        buffers::free(s);
    }
}

/// Monitor control code 0x50.
///
/// # Safety
///
/// As [`timing::timing_request`].
pub(crate) unsafe fn service_timing_request(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { timing::timing_request(argument) }
}

/// Monitor control code 0x51.
///
/// # Safety
///
/// As [`gpu::service_frame_buffer`].
pub(crate) unsafe fn service_frame_buffer(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { gpu::service_frame_buffer(argument) }
}

/// Monitor control code 0x56.
///
/// # Safety
///
/// As [`messages::configure`].
pub(crate) unsafe fn service_configure(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { messages::configure(argument) }
}

/// Monitor control code 0x5c.
///
/// # Safety
///
/// As [`gpu::service_command_buffers`].
pub(crate) unsafe fn service_command_buffers(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { gpu::service_command_buffers(argument) }
}

/// Monitor control code 0x5d.
///
/// # Safety
///
/// As [`gpu::service_fence`].
pub(crate) unsafe fn service_fence(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { gpu::service_fence(argument) }
}
