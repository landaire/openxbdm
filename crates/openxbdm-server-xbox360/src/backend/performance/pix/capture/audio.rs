//! Audio capture (code 0x5b, stock 0x91f560d8 to 0x91f60328): the XAudio
//! render thread hands each rendered block of 0x600 float samples; they
//! are converted to 16-bit samples, staged in the session block, and
//! queued in buffers of 0x2000 samples (type 0xc).

use xbox360_sys::xam;
use xbox360_sys::xboxkrnl;

use super::S;
use super::buffers;
use super::rd;
use super::wr;

const BLOCK_SAMPLES: u32 = 0x600;
const BUFFER_SAMPLES: u32 = 0x2000;
/// Staged samples and their count, and the blocks dropped while no buffer
/// was ready.
const STAGE: u32 = 0xe280;
const STAGED: u32 = 0x1_2280;
const DROPPED: u32 = 0x1_2284;

/// Convert `count` float samples at `source` to 16-bit samples at
/// `output` (stock 0x91f5d4b8): scaled by 32768, truncated and saturated.
fn convert(output: u32, source: u32, count: u32) {
    for index in 0..count & !0x1f {
        let sample = f32::from_bits(rd(source + index * 4)) * 32768.0;
        let value = (sample as i32).clamp(i16::MIN.into(), i16::MAX.into()) as i16;
        // SAFETY: the output holds `count` samples.
        unsafe { core::ptr::write_volatile((output + index * 2) as usize as *mut i16, value) };
    }
}

/// Take a ready audio buffer for stream `k` (stock 0x91f5d5d8).
fn ready_buffer(s: S, k: u32) -> Option<u32> {
    if s.word(0x1b0) == 0 || s.word(0x1c8) == s.word(0x1cc) {
        return None;
    }
    let index = s.word(0x1cc);
    s.set_word(0x1cc, if index + 1 < 4 { index + 1 } else { 0 });
    let entry = s.word(0x1b8 + index * 4);
    wr(
        entry + 4,
        (k << 5 | 0xc) << 25 | (s.word(super::FLAGS) >> 4 & 0x01ff_fffe) | (rd(entry + 4) & 1),
    );
    Some(entry)
}

/// Queue a filled audio buffer with its record (stock 0x91f5d670).
fn queue(s: S, entry: u32, record: &[u32; 3]) {
    let index = s.word(0x298);
    let slot = s.0 + 0x1d0 + index * 0x14;
    wr(slot, entry);
    wr(slot + 4, (rd(slot + 4) & 0x7f) | 0x8000_0000);
    for (offset, &word) in record.iter().enumerate() {
        wr(slot + 8 + offset as u32 * 4, word);
    }
    s.set_word(0x298, if index + 1 < 10 { index + 1 } else { 0 });
}

/// Monitor control code 0x5b: one rendered block (1).
pub(crate) fn service_samples(block: u32) -> u32 {
    let Some(s) = super::super::session::session() else {
        return 1;
    };
    let k = s.word(0xc);
    if s.word(super::FLAGS) & super::RUNNING == 0 || k == super::OFF {
        return 1;
    }
    let staged = s.word(STAGED);
    if staged <= BUFFER_SAMPLES - BLOCK_SAMPLES {
        convert(s.0 + STAGE + staged * 2, block, BLOCK_SAMPLES);
        s.set_word(STAGED, staged + BLOCK_SAMPLES);
        return 1;
    }
    // SAFETY: the spin lock word lies in the session block.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(s.at(0x1b4).cast()) };
    match ready_buffer(s, k) {
        None => s.set_word(DROPPED, s.word(DROPPED).wrapping_add(1)),
        Some(entry) => {
            let mut counter = 0u64;
            // SAFETY: `counter` is a live local.
            unsafe { xam::QueryPerformanceCounter(&mut counter) };
            let record = [
                (s.word(DROPPED) << 16 | (staged & 0xffff)) << 3 | 5,
                0,
                (counter >> 10) as u32,
            ];
            let data = buffers::data(entry);
            // SAFETY: the stage holds `staged` samples and the buffer room
            // for 0x2000.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (s.0 + STAGE) as usize as *const u8,
                    data as usize as *mut u8,
                    (staged * 2) as usize,
                )
            };
            let first = BUFFER_SAMPLES.wrapping_sub(staged);
            let rest = BLOCK_SAMPLES.wrapping_sub(first);
            convert(data + staged * 2, block, first);
            queue(s, entry, &record);
            convert(s.0 + STAGE, block + first * 4, rest);
            s.set_word(STAGED, rest);
            s.set_word(DROPPED, 0);
        }
    }
    // SAFETY: as above; the lock is held.
    unsafe { xboxkrnl::KfReleaseSpinLock(s.at(0x1b4).cast(), irql) };
    service_from_render_thread(s);
    1
}

/// Service the queues from the render thread when both session locks can
/// be had within 25,000 ticks (stock 0x91f60288).
fn service_from_render_thread(s: S) {
    let start = super::timebase_low();
    let expired = || super::timebase_low().wrapping_sub(start) > 0x61a8;
    let lock: *mut xboxkrnl::RtlCriticalSection = s.at(super::super::session::LOCK).cast();
    let engine_lock: *mut xboxkrnl::RtlCriticalSection =
        s.at(super::super::session::ENGINE_LOCK).cast();
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
