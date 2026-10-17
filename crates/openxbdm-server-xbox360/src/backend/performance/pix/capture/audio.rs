//! Audio capture (code 0x5b, stock 0x91f560d8 to 0x91f60328): the XAudio
//! render thread hands each rendered block of 0x600 float samples; they
//! are converted to 16-bit samples, staged in the session block, and
//! queued in buffers of 0x2000 samples (type 0xc).

use core::sync::atomic::AtomicU16;
use core::sync::atomic::Ordering::Relaxed;

use xbox360_sys::xam;
use xbox360_sys::xboxkrnl;

use super::super::session::AUDIO_BUFFER_SAMPLES;
use super::super::session::EngineFlags;
use super::super::session::Part;
use super::super::session::PixSession;
use super::buffers::BufferEntry;
use super::buffers::BufferInfo;
use super::buffers::BufferType;
use super::gpu::StreamRecordKind;

/// Samples of one XAudio render frame.
pub(super) const BLOCK_SAMPLES: usize = 0x600;

xbox360_sys::flags! {
    /// Flags word of a queued audio slot; bits 7 to 30 hold the frame.
    pub struct AudioSlotFlags(u32) {
        /// Write the slot's record with the buffer.
        RECORD = 0x8000_0000,
    }
}

impl AudioSlotFlags {
    /// Bits a queued slot keeps.
    const KEPT: u32 = 0x7f;

    pub(super) const fn frame(self) -> u32 {
        self.bits() >> 7 & 0x00ff_ffff
    }
}

/// Convert float samples of `source` to 16-bit samples in `output`
/// (stock 0x91f5d4b8): scaled by 32768, truncated and saturated; whole
/// groups of 32 only.
fn convert(output: &[AtomicU16], source: &[f32]) {
    let source = &source[..source.len() & !0x1f];
    for (output, &sample) in output.iter().zip(source) {
        // The cast truncates and saturates, as stock.
        output.store((sample * 32768.0) as i16 as u16, Relaxed);
    }
}

/// Take a ready audio buffer for stream `k` (stock 0x91f5d5d8).
fn ready_buffer(s: &PixSession, k: u32) -> Option<&BufferEntry> {
    let tail = s.audio_ready_tail.load(Relaxed);
    if s.audio_enabled.load(Relaxed) == 0 || s.audio_ready_head.load(Relaxed) == tail {
        return None;
    }
    let next = tail + 1;
    s.audio_ready_tail.store(
        if (next as usize) < s.audio_ready.len() {
            next
        } else {
            0
        },
        Relaxed,
    );
    // Ready ring indexes wrap at its length, a power of two.
    let word = &s.audio_ready[tail as usize % s.audio_ready.len()];
    // SAFETY: the ready ring holds entries `gpu::service` took from the
    // buffer table, or 0. As in stock, the table stays allocated while the
    // capture runs, which `service_samples` checked.
    let entry = unsafe { super::gpu::entry_at(word.load(Relaxed)) }?;
    entry.info.store(
        BufferInfo::new(k, BufferType::AUDIO, s.engine_flags(), entry.info()).0,
        Relaxed,
    );
    Some(entry)
}

/// Queue a filled audio buffer with its record (stock 0x91f5d670).
fn queue(s: &PixSession, entry: &BufferEntry, record: &[u32; 3]) {
    let index = s.audio_queue_head.load(Relaxed);
    // SAFETY: the session block is allocated zeroed, and only this function
    // (which wraps at the queue length) and the engine reset (which stores
    // 0) store the queue head.
    unsafe { core::hint::assert_unchecked((index as usize) < s.audio_queue.len()) };
    let slot = &s.audio_queue[index as usize];
    slot.entry.store(entry.address(), Relaxed);
    let flags = AudioSlotFlags::from_bits_retain(slot.flags.load(Relaxed) & AudioSlotFlags::KEPT)
        | AudioSlotFlags::RECORD;
    slot.flags.store(flags.bits(), Relaxed);
    for (slot, &word) in slot.record.iter().zip(record) {
        slot.store(word, Relaxed);
    }
    let next = index + 1;
    s.audio_queue_head.store(
        if (next as usize) < s.audio_queue.len() {
            next
        } else {
            0
        },
        Relaxed,
    );
}

/// Monitor control code 0x5b: one rendered block (1).
///
/// # Safety
///
/// `block` must be the address of a rendered block of `BLOCK_SAMPLES`
/// floats that the caller does not change during the call.
pub(crate) unsafe fn service_samples(block: u32) -> u32 {
    let Some(s) = super::super::session::session() else {
        return 1;
    };
    let k = s.configuration.part(Part::Audio);
    if !s.engine_flags().contains(EngineFlags::RUNNING) || k.is_off() {
        return 1;
    }
    // SAFETY: the caller's contract.
    let block: &[f32; BLOCK_SAMPLES] = unsafe { crate::kernel::object_at(block) };
    let stage = &s.audio_stage.0;
    let staged = s.staged.load(Relaxed) as usize;
    // SAFETY: the session block is allocated zeroed, and only this function
    // and the engine reset store the staged count: at most a full buffer
    // below, the rest of a block (under `BLOCK_SAMPLES`), or 0.
    unsafe { core::hint::assert_unchecked(staged <= AUDIO_BUFFER_SAMPLES) };
    if staged <= AUDIO_BUFFER_SAMPLES - BLOCK_SAMPLES {
        convert(&stage[staged..], block);
        s.staged.store((staged + BLOCK_SAMPLES) as u32, Relaxed);
        return 1;
    }
    // SAFETY: the audio spin lock lies in the session block.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(s.audio_lock.as_ptr()) };
    match ready_buffer(s, k.0) {
        None => s
            .dropped
            .store(s.dropped.load(Relaxed).wrapping_add(1), Relaxed),
        Some(entry) => {
            let mut counter = 0u64;
            // SAFETY: `counter` is a live local.
            unsafe { xam::QueryPerformanceCounter(&mut counter) };
            let record = [
                (s.dropped.load(Relaxed) << 16 | (staged as u32 & 0xffff)) << 3
                    | StreamRecordKind::Audio as u32,
                0,
                (counter >> 10) as u32,
            ];
            let data = core::ptr::with_exposed_provenance_mut::<AtomicU16>(entry.data() as usize);
            // SAFETY: a ready buffer's data is a capture buffer of
            // `AUDIO_BUFFER_SAMPLES` samples that only this thread
            // accesses until it is queued.
            let samples = unsafe { core::slice::from_raw_parts(data, AUDIO_BUFFER_SAMPLES) };
            // SAFETY: only the render thread accesses the stage, and the
            // copy stays within the stage and the buffer.
            unsafe { core::ptr::copy_nonoverlapping(stage.as_ptr(), data, staged) };
            let first = AUDIO_BUFFER_SAMPLES - staged;
            let rest = BLOCK_SAMPLES - first;
            let (head, tail) = block.split_at(first);
            convert(&samples[staged..], head);
            queue(s, entry, &record);
            convert(stage, tail);
            s.staged.store(rest as u32, Relaxed);
            s.dropped.store(0, Relaxed);
        }
    }
    // SAFETY: as above; the lock is held.
    unsafe { xboxkrnl::KfReleaseSpinLock(s.audio_lock.as_ptr(), irql) };
    service_from_render_thread(s);
    1
}

/// Service the queues from the render thread when both session locks can
/// be had within 25,000 ticks (stock 0x91f60288).
fn service_from_render_thread(s: &PixSession) {
    const WAIT_TICKS: u32 = 25_000;
    let start = super::timebase_low();
    let expired = || super::timebase_low().wrapping_sub(start) > WAIT_TICKS;
    let lock = s.lock.as_ptr();
    let engine_lock = s.engine_lock.as_ptr();
    // SAFETY: both critical sections lie in the session block and were
    // initialized by `session::create`.
    while !unsafe { xboxkrnl::RtlTryEnterCriticalSection(lock) }.get() {
        if expired() {
            return;
        }
    }
    // SAFETY: as above.
    while !unsafe { xboxkrnl::RtlTryEnterCriticalSection(engine_lock) }.get() {
        if expired() {
            // SAFETY: as above; `lock` is held.
            unsafe { xboxkrnl::RtlLeaveCriticalSection(lock) };
            return;
        }
    }
    super::gpu::service(s, true);
    // SAFETY: as above; both are held.
    unsafe {
        xboxkrnl::RtlLeaveCriticalSection(engine_lock);
        xboxkrnl::RtlLeaveCriticalSection(lock);
    }
}
