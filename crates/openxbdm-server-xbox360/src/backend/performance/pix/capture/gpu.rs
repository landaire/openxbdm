//! GPU command buffer capture: frame buffers of type 0xe (code 0x51,
//! stock 0x91f5ebb0), command data buffers of type 0xd handed out per
//! frame (code 0x5c, 0x91f604c8) and released when the GPU passes the
//! frame's fence (code 0x5d, 0x91f5d718; 0x91f5f838), and the queues
//! that order them in the streams (0x91f5f558, 0x91f5f6a0, 0x91f60060).

use super::S;
use super::buffers;
use super::rd;
use super::wr;
use crate::kernel;

/// Four fence slots `{flags | frame << 3, 0, count u16, id, data}`.
const SLOTS: u32 = 0x150;
const SLOT: u32 = 0x14;
const SLOT_COUNT: u32 = 4;
const SLOT_NEXT: u32 = 0x1a0;
const SLOT_DONE: u32 = 0x1a4;
const SLOT_READY: u32 = 0x1a8;
/// Last fence the GPU reported, and the last one serviced.
const FENCE: u32 = 0xe168;
const FENCE_SERVICED: u32 = 0xe16c;
/// Command data buffers outstanding, the pending frame record, and the
/// rate budget.
const OUTSTANDING: u32 = 0xe170;
const FRAME_WORDS: u32 = 0xe174;
const LAST_ALLOCATION: u32 = 0xe20c;
const BUDGET: u32 = 0xe214;
/// Current command data buffer and the bytes used in it.
const DATA_BUFFER: u32 = 0xfc;
const DATA_USED: u32 = 0x1ac;
/// GPU busy bit register.
const GPU_STATUS: u32 = 0x7fc8_1740;

fn sign24(value: u32) -> i32 {
    ((value << 8) as i32) >> 8
}

fn ring_push(s: S, ring: u32, head: u32, entry: u32, frame: u32) {
    let slot = s.word(ring) + s.word(head) * 8;
    wr(slot + 4, entry);
    wr(slot, u32::from(super::rd8(slot + 3)) | frame << 8);
    let next = s.word(head) + 1;
    s.set_word(head, if next < s.word(0x130) { next } else { 0 });
}

/// Queue a finished command data buffer (stock 0x91f5cbd8).
pub(super) fn push_finished(s: S, entry: u32, frame: u32) {
    ring_push(s, 0x13c, 0x148, entry, frame);
}

/// Close the frame buffer as full and queue it (stock 0x91f5cc60).
pub(super) fn close_frame_buffer(s: S) {
    let entry = s.word(0x100);
    if entry == 0 {
        return;
    }
    wr(buffers::data(entry), 0x000f_ff0e);
    ring_push(s, 0x138, 0x140, entry, super::frame_index(s));
    s.set_word(0x100, 0);
}

/// Wait up to 2000 ms while the GPU is busy (stock 0x91f5cf38).
pub(super) fn wait_for_idle() {
    let start = kernel::tick_count();
    while rd(GPU_STATUS) & 0x8000_0000 != 0 && kernel::tick_count().wrapping_sub(start) <= 2000 {
        // SAFETY: thread priority hints; no register changes.
        unsafe {
            core::arch::asm!(
                "mr 31, 31",
                "mr 31, 31",
                "mr 31, 31",
                "mr 31, 31",
                options(nomem, nostack)
            )
        };
    }
}

fn wrap(index: u32, count: u32) -> u32 {
    if index < count { index } else { 0 }
}

/// Write the frame buffers queued for `frame` and a record of them (stock
/// 0x91f5f558).
pub(super) fn flush_frame_buffers(s: S, frame: u32) {
    let k = s.word(0);
    let head = s.word(0x140);
    let mut tail = s.word(0x144);
    let sequence = s.word(buffers::stream(k) + buffers::STREAM_SEQUENCE);
    let mut count = 0;
    while tail != head {
        let slot = s.word(0x138) + tail * 8;
        if sign24((rd(slot) >> 8).wrapping_sub(frame)) != 0 {
            break;
        }
        buffers::submit(s, rd(slot + 4), rd(slot) >> 8);
        tail = wrap(tail + 1, s.word(0x130));
        count += 1;
    }
    if count != 0 {
        let paused = (!s.word(super::FLAGS) >> 26) & 8;
        let record = [
            paused | (frame << 4 & 0x0fff_fff0) | 3,
            sequence,
            count & 0xffff,
        ];
        buffers::append(s, k, record.as_ptr() as usize as u32, 0xc);
        s.set_word(super::FLAGS, s.word(super::FLAGS) & !super::PAUSED_OUTPUT);
    }
    s.set_word(0x144, tail);
}

/// Write the command data buffers of fence slot `record` and its record
/// (stock 0x91f5f6a0); `last` marks the end of the capture.
pub(super) fn write_frame(s: S, record: u32, last: bool) {
    let k = s.word(8);
    let frame = rd(record) >> 3 & 0x00ff_ffff;
    if k == super::OFF {
        return;
    }
    let head = s.word(0x148);
    let mut tail = s.word(0x14c);
    let sequence = s.word(buffers::stream(k) + buffers::STREAM_SEQUENCE);
    let mut count = 0u32;
    while tail != head {
        let slot = s.word(0x13c) + tail * 8;
        if sign24(frame.wrapping_sub(rd(slot) >> 8)) < 0 {
            break;
        }
        buffers::submit(s, rd(slot + 4), frame);
        tail = wrap(tail + 1, s.word(0x130));
        count += 1;
    }
    for index in 0..5 {
        s.set_word(FRAME_WORDS + index * 4, rd(record + index * 4));
    }
    let mut words = (s.word(FRAME_WORDS) & !0x0800_0000) | u32::from(last) << 27;
    s.set_word(FRAME_WORDS, words);
    s.set_word(FRAME_WORDS + 4, sequence);
    // SAFETY: an aligned halfword of the session block.
    unsafe {
        core::ptr::write_volatile((s.0 + FRAME_WORDS + 0xa) as usize as *mut u16, count as u16)
    };
    if last {
        words &= 0x0fff_ffff;
        s.set_word(FRAME_WORDS, words);
    }
    buffers::append(s, k, s.0 + FRAME_WORDS, 0x14);
    s.set_word(OUTSTANDING, s.word(OUTSTANDING).wrapping_sub(count));
    s.set_word(0x14c, tail);
}

/// Service the fences the GPU passed (stock 0x91f5f838); `check` stops
/// when no buffer is available.
pub(super) fn poll(s: S, check: bool) {
    let fence = s.word(FENCE);
    if fence == s.word(FENCE_SERVICED) || fence.wrapping_sub(super::frame_index(s)) << 8 == 0 {
        return;
    }
    if check && !buffers::available(s, 1) {
        return;
    }
    flush_frame_buffers(s, fence);
    while s.word(SLOT_DONE) != s.word(SLOT_READY) {
        let slot = s.0 + SLOTS + s.word(SLOT_DONE) * SLOT;
        if sign24(fence.wrapping_sub(rd(slot) >> 3)) < 0 {
            break;
        }
        if check && !buffers::available(s, 1) {
            return;
        }
        write_frame(s, slot, false);
        s.set_word(SLOT_DONE, wrap(s.word(SLOT_DONE) + 1, SLOT_COUNT));
    }
    s.set_word(FENCE_SERVICED, fence);
}

/// Write the queued audio buffers, close a command data buffer left open
/// for 5,000,000 ticks, and keep four audio buffers ready (stock
/// 0x91f60060); `check` stops when no buffer is available.
pub(super) fn service(s: S, check: bool) {
    if s.word(0x29c) != s.word(0x298) {
        poll(s, true);
        let entry = s.word(DATA_BUFFER);
        if super::timebase_low().wrapping_sub(s.word(LAST_ALLOCATION)) > 0x4c_4b40
            && entry != 0
            && s.word(OUTSTANDING) == 1
        {
            push_finished(s, entry, s.word(FRAME_WORDS) >> 3 & 0x00ff_ffff);
            write_frame(s, s.0 + FRAME_WORDS, true);
            s.set_word(DATA_BUFFER, 0);
        }
        loop {
            if check && !buffers::available(s, 1) {
                break;
            }
            let irql = kernel::KfAcquireSpinLock(s.at(0x1b4));
            let mut queued = None;
            if s.word(0x29c) != s.word(0x298) {
                let index = s.word(0x29c);
                let slot = s.0 + 0x1d0 + index * 0x14;
                let flags = rd(slot + 4);
                queued = Some((
                    rd(slot),
                    flags >> 31 != 0,
                    flags >> 7 & 0x00ff_ffff,
                    [rd(slot + 8), rd(slot + 0xc), rd(slot + 0x10)],
                ));
                s.set_word(0x29c, wrap(index + 1, 10));
            }
            kernel::KfReleaseSpinLock(s.at(0x1b4), irql);
            let Some((entry, with_record, frame, mut record)) =
                queued.filter(|queued| queued.0 != 0)
            else {
                break;
            };
            let k = buffers::entry_stream(entry);
            record[1] = s.word(buffers::stream(k) + buffers::STREAM_SEQUENCE);
            buffers::submit(s, entry, frame);
            if with_record {
                buffers::append(s, k, record.as_ptr() as usize as u32, 0xc);
            }
        }
    }
    if s.word(0x1b0) == 0 {
        return;
    }
    loop {
        if check && !buffers::available(s, 1) {
            return;
        }
        let index = s.word(0x1c8);
        let next = wrap(index + 1, 4);
        if next == s.word(0x1cc) {
            return;
        }
        let entry = buffers::take(s, 0x11, 0);
        let irql = kernel::KfAcquireSpinLock(s.at(0x1b4));
        s.set_word(0x1b8 + index * 4, entry);
        s.set_word(0x1c8, next);
        kernel::KfReleaseSpinLock(s.at(0x1b4), irql);
    }
}

/// Monitor control code 0x51 (stock 0x91f560a8 to 0x91f5ebb0): `{+0
/// unused, +4 close, +8 output}`. Closes the open frame buffer and hands
/// out a new one (its first data dword in `+8`); 0xfff when one was
/// handed out.
pub(super) fn service_frame_buffer(argument: u32) -> u32 {
    let close = rd(argument + 4);
    let output = rd(argument + 8);
    let Some(locked) = super::super::session::lock() else {
        return 0;
    };
    let s = locked.0;
    let k = s.word(0);
    if k == super::OFF {
        if output != 0 {
            wr(output, 0);
        }
        return 0;
    }
    if close != 0 {
        close_frame_buffer(s);
    }
    if output == 0 {
        return 0;
    }
    let mut used = s.word(0x140).wrapping_sub(s.word(0x144)) as i32;
    if used < 0 {
        used += s.word(0x130) as i32;
    }
    if (used as u32) + 1 >= s.word(0x130).wrapping_sub(s.word(0x134)) {
        s.set_word(super::FLAGS, s.word(super::FLAGS) | super::PAUSED_OUTPUT);
        wr(output, 0);
        return 0;
    }
    let entry = buffers::take(s, 0xe, k);
    s.set_word(0x100, entry);
    wr(output, buffers::data(entry) + 4);
    0xfff
}

/// Monitor control code 0x5c (stock 0x91f560b8 to 0x91f604c8): `{+0
/// status, +4 bytes, +8 alignment, +0xc offset out, +0x10 buffer address
/// array out, +0x14 buffer count out, +0x18 frame out}`. Hands out command
/// data buffers for `bytes` and opens a fence slot for the frame with the
/// status (nonzero refuses: 1 rate limit, 2 no free buffers, 3 too large,
/// 4 off). 1 when buffers were handed out.
pub(super) fn service_command_buffers(argument: u32) -> u32 {
    let mut status = rd(argument);
    let bytes = rd(argument + 4);
    let alignment = rd(argument + 8);
    let offset_out = argument + 0xc;
    let mut addresses = rd(argument + 0x10);
    let count_out = argument + 0x14;
    let frame_out = argument + 0x18;
    let Some(locked) = super::super::session::lock() else {
        return 0;
    };
    let s = locked.0;
    let k = s.word(8);
    let now = super::timebase_low();
    let mut elapsed = now.wrapping_sub(s.word(LAST_ALLOCATION)) as i32;
    if elapsed < 0 {
        elapsed = i32::MAX;
    }
    poll(s, false);
    let mut units = bytes.wrapping_add(0x3fff) >> 14;
    let mut used = 0u32;
    if status == 0 {
        let budget = s.word(BUDGET) as i32;
        if s.word(0x134).wrapping_add(bytes >> 14).wrapping_add(1) > s.word(0x130) {
            status = 3;
        } else if k == super::OFF {
            status = 4;
        } else if s.word(0x1c) != 0 && !buffers::available(s, (s.word(0x130) >> 2) + units) {
            status = 2;
        } else if elapsed < budget || elapsed < 0x4_3d11 {
            status = 1;
        } else {
            let remaining = budget.wrapping_sub(elapsed).wrapping_add(0x8_7a23);
            s.set_word(BUDGET, remaining.max(0) as u32);
            s.set_word(LAST_ALLOCATION, now);
            wr(count_out, units);
            wr(offset_out, 0);
            let current = s.word(DATA_BUFFER);
            if current != 0 {
                push_finished(s, current, super::frame_index(s));
                let offset = s.word(DATA_USED).wrapping_add(alignment).wrapping_sub(1)
                    & !alignment.wrapping_sub(1)
                    & 0x3fff;
                wr(offset_out, offset);
                if offset == 0 {
                    used = 0x4000;
                } else {
                    used = offset;
                    units = offset.wrapping_add(bytes).wrapping_sub(1) >> 14;
                    wr(count_out, units + 1);
                    wr(addresses, buffers::data(current));
                    addresses += 4;
                }
            }
            s.set_word(DATA_USED, used.wrapping_add(bytes));
            s.set_word(OUTSTANDING, s.word(OUTSTANDING).wrapping_add(units));
            // Stock loops about 2^32 times for a zero size.
            for _ in 1..units {
                let entry = buffers::take(s, 0xd, k);
                wr(addresses, buffers::data(entry));
                addresses += 4;
                push_finished(s, entry, super::frame_index(s));
            }
            let entry = buffers::take(s, 0xd, k);
            s.set_word(DATA_BUFFER, entry);
            wr(addresses, buffers::data(entry));
        }
    }
    wr(frame_out, super::frame_index(s));
    let index = s.word(SLOT_NEXT);
    let slot = s.0 + SLOTS + index * SLOT;
    wr(
        slot,
        4 | (s.word(super::FLAGS) >> 2 & 0x07ff_fff8) | (rd(slot) & 0x0800_0000) | status << 28,
    );
    wr(slot + 0xc, 0x0bad_f00d);
    wr(slot + 0x10, 0x0bad_f00d);
    // SAFETY: an aligned halfword of the session block.
    unsafe { core::ptr::write_volatile((slot + 8) as usize as *mut u16, used as u16) };
    s.set_word(SLOT_NEXT, wrap(index + 1, SLOT_COUNT));
    u32::from(status == 0)
}

/// Monitor control code 0x5d (stock 0x91f56100 to 0x91f5d718): `{+0 fence,
/// +4, +8}` completes the oldest open fence slot; the GPU reached `fence`.
pub(super) fn service_fence(argument: u32) -> u32 {
    // Stock dereferences the missing session.
    let Some(s) = super::super::session::session() else {
        return 1;
    };
    let fence = rd(argument);
    let index = s.word(SLOT_READY);
    let slot = s.0 + SLOTS + index * SLOT;
    wr(slot + 0xc, rd(argument + 4));
    wr(slot + 0x10, rd(argument + 8));
    super::sync();
    s.set_word(SLOT_READY, wrap(index + 1, SLOT_COUNT));
    super::sync();
    s.set_word(FENCE, fence);
    1
}
