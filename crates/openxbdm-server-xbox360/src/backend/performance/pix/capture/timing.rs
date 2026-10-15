//! Timing records in the per-hardware-thread capture buffers: the record
//! writers (stock 0x91f77b00, 0x91f77c78, 0x91f77e10, 0x91f78188), the
//! named event begin and end of codes 0x8d and 0x8e (0x91f78698,
//! 0x91f78760), the buffer request of code 0x50 (0x91f61f08) and its
//! raised-level path that switches to a temporary block (0x91f5ee68,
//! 0x91f5ed80), and the server-side buffer replacement (0x91f61cb8,
//! 0x91f61bc8).
//!
//! A record is `{time << 7 | kind, dwords << 24 | id, data}`; `kind` 1 is
//! a data record, 0x19 a formatted event, 0x1d a named begin, 0 an end.

use super::super::backend::EVENT_NAME_BYTES;
use super::S;
use super::buffers;
use super::engine::PCR_CURSOR;
use super::engine::PCR_LIMIT;
use super::rd;
use super::wr;
use crate::kernel::_vsnprintf;

const TEMPORARY_BYTES: u32 = 0x800;
/// Room a raised-level writer gets in the temporary block per request.
const TEMPORARY_RESERVE: u32 = 0xd4;
const PENDING_SERVICE: u32 = 0x1_22f4;
const LOST: u32 = 0x1_2298;
/// Temporary block state per buffer: 0 none, 1 in use, 2 data to merge.
const STATE: u32 = 0x876c;
const SAVED_CURSOR: u32 = 0x8738;
const TEMPORARY: u32 = 0x87a0;

/// Ask for buffer space through code 0x50 with `request` `{type, color,
/// text, arguments, extra}` (as stock calls the debug monitor routine);
/// whether space may be available.
fn request_space(request: &[u32; 5]) -> bool {
    super::service_timing_request(request.as_ptr() as usize as u32) != 0
}

/// With interrupts off, wait for `dwords` of buffer space, asking code
/// 0x50 for more; the processor control region and the cursor, or `None`
/// when no buffer is installed or the request fails (interrupts on again).
fn reserve(dwords: u32, request: &[u32; 5]) -> Option<(u32, u32)> {
    super::interrupts_off();
    loop {
        let pcr = super::pcr();
        let cursor = rd(pcr + PCR_CURSOR);
        let limit = rd(pcr + PCR_LIMIT);
        if cursor.wrapping_add(dwords.wrapping_mul(4)) < limit {
            return Some((pcr, cursor));
        }
        super::interrupts_on();
        if limit == 0 || !request_space(request) {
            return None;
        }
        super::interrupts_off();
    }
}

/// Data record `id` with `data` (stock 0x91f77b00, header kind 1).
pub(super) fn write_record(id: u32, data: &[u32]) {
    write(1, id, data, 0, [4, 0, 0, 0, 0]);
}

/// Data record `id` with up to 0xffc dwords; dwords past 0x33 must fit
/// before the limit (stock 0x91f77c78).
pub(super) fn write_long_record(id: u32, data: &[u32]) {
    let extra = (data.len() as u32).saturating_sub(0x33);
    write(1, id, data, extra, [5, 0, 0, 0, extra]);
}

/// Data record `id` with header kind 0x61 (stock 0x91f77e10).
pub(super) fn write_typed_record(id: u32, data: &[u32]) {
    write(0x61, id, data, 0, [4, 0, 0, 0, 0]);
}

fn write(kind: u32, id: u32, data: &[u32], extra: u32, request: [u32; 5]) {
    let Some((pcr, cursor)) = reserve(extra, &request) else {
        return;
    };
    let dwords = data.len() as u32 + 2;
    wr(cursor, super::timebase_low() << 7 | kind);
    wr(cursor + 4, (dwords << 24 & 0x7fff_ffff) | id);
    for (index, &word) in data.iter().enumerate() {
        wr(cursor + 8 + index as u32 * 4, word);
    }
    wr(pcr + PCR_CURSOR, cursor + dwords * 4);
    super::interrupts_on();
}

/// Code 0x8d (stock 0x91f56628): name the calling thread `NuiCam Driver`
/// and begin a timing event named `name`.
pub(crate) fn service_nuicam_begin(name: u32) -> u32 {
    crate::backend::debugger::name_thread(None, c"NuiCam Driver".as_ptr() as usize as u32);
    begin_named(0, name);
    0
}

/// Named event begin (stock 0x91f78698): a kind 0x1d record with the name
/// packed after the color; a full buffer falls back to the formatted
/// writer.
fn begin_named(color: u32, name: u32) {
    if rd(super::pcr() + PCR_LIMIT) == 0 {
        return;
    }
    super::interrupts_off();
    let pcr = super::pcr();
    let cursor = rd(pcr + PCR_CURSOR);
    if cursor < rd(pcr + PCR_LIMIT) {
        wr(cursor, super::timebase_low() << 7 | 0x1d);
        wr(cursor + 4, color);
        let end = pack(cursor + 8, name, cursor + 8 + 0x24, false);
        wr(pcr + PCR_CURSOR, end);
        super::interrupts_on();
        return;
    }
    super::interrupts_on();
    // Stock passes stale argument registers to the formatter here.
    formatted(0x19, 0, color, name, &[0; 8]);
}

/// Code 0x8e (stock 0x91f56668 to 0x91f78760): end the current timing
/// event.
pub(crate) fn service_end(_argument: u32) -> u32 {
    if let Some((pcr, cursor)) = reserve(0, &[1, 0, 0, 0, 0]) {
        wr(cursor, super::timebase_low() << 7);
        wr(pcr + PCR_CURSOR, cursor + 4);
        super::interrupts_on();
    }
    0
}

/// Pack the string at `source` into dwords from `output` (stock
/// 0x91f77f88; `wide` 0x91f78088 takes the low byte of each 16-bit
/// character). Words are written while they start before `limit`; a word
/// holding the terminator ends the string. Narrow characters of 0x80 and
/// up are sign-extended over the characters before them in the word, as
/// stock combines them.
fn pack(output: u32, source: u32, limit: u32, wide: bool) -> u32 {
    let mut cursor = output;
    let mut index = 0;
    while cursor < limit {
        let mut word = 0u32;
        let mut ended = false;
        for position in 0..4 {
            let byte = if wide {
                super::rd8(source + index * 2 + 1)
            } else {
                super::rd8(source + index)
            };
            index += 1;
            if byte == 0 {
                ended = true;
                break;
            }
            let value = if wide || position == 0 {
                u32::from(byte)
            } else {
                byte as i8 as i32 as u32
            };
            word |= value << (24 - position * 8);
        }
        wr(cursor, word);
        cursor += 4;
        if ended {
            break;
        }
    }
    cursor
}

/// Formatted event record (stock 0x91f78188): the arguments `format`
/// consumes (at most eight, 8-byte slots), the format text, and the
/// strings `%s`/`%S` arguments name, within 0x24 bytes.
fn formatted(kind: u32, extra: u32, color: u32, format: u32, arguments: &[u64; 8]) {
    if rd(super::pcr() + PCR_LIMIT) == 0 {
        return;
    }
    let mut cursor = format;
    let mut count = 0u32;
    let mut strings = [0u32; 8];
    let mut string_count = 0u32;
    let mut wide = 0u32;
    while super::rd8(cursor) != 0 {
        if super::rd8(cursor) != b'%' {
            cursor += 1;
            continue;
        }
        let mut offset = 1;
        let conversion = loop {
            let byte = super::rd8(cursor + offset);
            match byte {
                0 => break None,
                b'%' => break Some(0),
                b'X'
                | b'C'
                | b'E'
                | b'G'
                | b'S'
                | b's'
                | b'c'..=b'g'
                | b'i'
                | b'n'..=b'p'
                | b'u'
                | b'x' => break Some(byte),
                _ => offset += 1,
            }
        };
        match conversion {
            None => {
                cursor += offset;
                break;
            }
            Some(0) => cursor += offset + 1,
            Some(conversion) => {
                cursor += offset + 1;
                if count < 8 {
                    if conversion == b's' || conversion == b'S' {
                        strings[string_count as usize] = arguments[count as usize] as u32;
                        if conversion == b'S' {
                            wide |= 1 << string_count;
                        }
                        string_count += 1;
                    }
                    count += 1;
                }
            }
        }
    }
    let request = [extra, color, format, arguments.as_ptr() as usize as u32, 0];
    let Some((pcr, output)) = reserve(0, &request) else {
        return;
    };
    let misalignment = format & 3;
    wr(output, super::timebase_low() << 7 | (misalignment + kind));
    wr(output + 4, color);
    wr(output + 8, string_count << 16 | count);
    let mut position = output + 0xc;
    for argument in &arguments[..count as usize] {
        wr(position, (argument >> 32) as u32);
        wr(position + 4, *argument as u32);
        position += 8;
    }
    let limit = position + 0x24;
    let bytes = (cursor - format + 1 + misalignment).min(0x24);
    let start = format - misalignment;
    for word in 0..bytes.div_ceil(4) {
        wr(position, rd(start + word * 4));
        position += 4;
    }
    for (index, &string) in strings[..string_count as usize].iter().enumerate() {
        position = pack(position, string, limit, wide & 1 << index != 0);
    }
    wr(pcr + PCR_CURSOR, position);
    super::interrupts_on();
}

/// Raised-level buffer request (stock 0x91f5ee68): switch the processor to
/// its temporary block, or grant one more record in it; the server pass
/// replaces the full buffer. Whether a record may be written.
pub(super) fn request_at_raised_level(s: S) -> bool {
    let mut granted = true;
    let mut switched = false;
    super::interrupts_off();
    let pcr = super::pcr();
    if rd(pcr + PCR_LIMIT) == 0 {
        super::interrupts_on();
        return false;
    }
    let processor = super::processor();
    let base = s.word(TEMPORARY + processor * 4);
    match s.word(STATE + processor * 4) {
        0 => {
            s.set_word(SAVED_CURSOR + processor * 4, rd(pcr + PCR_CURSOR));
            wr(pcr + PCR_CURSOR, base);
            wr(pcr + PCR_LIMIT, base + 4);
            super::fence();
            s.set_word(STATE + processor * 4, 1);
            super::fence();
            switched = true;
        }
        1 => {
            let cursor = rd(pcr + PCR_CURSOR);
            if cursor + TEMPORARY_RESERVE <= base + TEMPORARY_BYTES {
                wr(pcr + PCR_LIMIT, cursor + 4);
            } else {
                granted = false;
            }
        }
        _ => merge(s),
    }
    super::interrupts_on();
    if switched {
        // SAFETY: an aligned word of the session block.
        let pending = unsafe { core::sync::atomic::AtomicU32::from_ptr(s.at(PENDING_SERVICE)) };
        pending.store(1, core::sync::atomic::Ordering::Release);
    }
    granted
}

/// Take the server pass request set by [`request_at_raised_level`].
pub(super) fn take_pending_service(s: S) -> bool {
    // SAFETY: an aligned word of the session block.
    let pending = unsafe { core::sync::atomic::AtomicU32::from_ptr(s.at(PENDING_SERVICE)) };
    pending.swap(0, core::sync::atomic::Ordering::AcqRel) != 0
}

/// Copy the temporary block's records into the processor's new buffer and
/// continue there (stock 0x91f5ed80), with interrupts off.
pub(super) fn merge(s: S) {
    let pcr = super::pcr();
    let processor = super::processor();
    let base = s.word(TEMPORARY + processor * 4);
    let dwords = rd(pcr + PCR_CURSOR).wrapping_sub(base) >> 2;
    let data = buffers::data(s.word(0xc8 + processor * 4));
    // SAFETY: the temporary block holds `dwords` dwords and the buffer has
    // room for them after its header.
    unsafe {
        core::ptr::copy_nonoverlapping(
            base as usize as *const u8,
            (data + 4) as usize as *mut u8,
            (dwords * 4) as usize,
        )
    };
    wr(pcr + PCR_CURSOR, data + 4 + dwords * 4);
    wr(pcr + PCR_LIMIT, data + 0x3f2c);
    if s.word(LOST + processor * 4) != 0 {
        s.set_word(LOST + processor * 4, 0);
        lost_records_marker();
    }
    super::fence();
    s.set_word(STATE + processor * 4, 0);
    super::fence();
}

/// Record noting that context swap records were lost (stock 0x91f5ed20).
fn lost_records_marker() {
    let pcr = super::pcr();
    let mut thread_id = rd(rd(pcr + 0x100) + super::THREAD_ID);
    if super::rd8(pcr + 0x19) != 0 && thread_id == 0 {
        thread_id = (-2i32) as u32;
    }
    let cursor = rd(pcr + PCR_CURSOR);
    wr(cursor, super::timebase_low() << 7 | 1);
    wr(cursor + 4, 0x0300_0045);
    wr(cursor + 8, thread_id);
    wr(pcr + PCR_CURSOR, cursor + 0xc);
}

/// Replace the calling processor's full buffer at passive level (stock
/// 0x91f61cb8); `dwords` is the size of the record being written.
fn replace_buffer(s: S, dwords: u32) {
    let kind = s.word(0);
    super::interrupts_off();
    let pcr = super::pcr();
    let processor = super::processor();
    let slot = 0xc8 + processor * 4;
    let mut full = 0;
    match s.word(STATE + processor * 4) {
        0 => {
            let cursor = rd(pcr + PCR_CURSOR);
            if cursor + dwords * 4 >= rd(pcr + PCR_LIMIT) {
                buffers::close(s.word(slot), processor, cursor);
                full = s.word(slot);
            }
        }
        1 => {
            buffers::close(
                s.word(slot),
                processor,
                s.word(SAVED_CURSOR + processor * 4),
            );
            full = s.word(slot);
        }
        _ => merge(s),
    }
    super::interrupts_on();
    if full != 0 {
        buffers::submit(s, full, super::frame_index(s));
        let entry = buffers::take(s, processor, kind);
        s.set_word(slot, entry);
        super::interrupts_off();
        if processor == super::processor() {
            if s.word(STATE + processor * 4) == 1 {
                merge(s);
            } else {
                let pcr = super::pcr();
                wr(pcr + PCR_CURSOR, buffers::data(entry) + 4);
                wr(pcr + PCR_LIMIT, buffers::data(entry) + 0x3f2c);
                super::fence();
                s.set_word(STATE + processor * 4, 0);
                super::fence();
            }
        } else {
            super::fence();
            s.set_word(STATE + processor * 4, 2);
            super::fence();
        }
        super::interrupts_on();
    }
    service_buffers(s);
}

/// Replace the buffers whose temporary blocks are in use and service the
/// GPU and audio queues (stock 0x91f61bc8), at passive level.
pub(super) fn service_buffers(s: S) {
    for index in 0..13u32 {
        if s.word(STATE + index * 4) != 1 {
            continue;
        }
        let slot = 0xc8 + index * 4;
        let entry = s.word(slot);
        buffers::close(entry, index, s.word(SAVED_CURSOR + index * 4));
        let k = buffers::entry_stream(entry);
        buffers::submit(s, entry, super::frame_index(s));
        s.set_word(slot, buffers::take(s, index, k));
        super::fence();
        s.set_word(STATE + index * 4, 2);
        super::fence();
    }
    super::gpu::service(s, false);
}

/// Event the owner callback learns for request type 0 to 2: 0xe0 on.
const OWNER_EVENT_BASE: u32 = 0xe0;

/// Monitor control code 0x50 (stock 0x91f56080 and 0x91f61f08): `{+0
/// type, +4, +8 text, +0xc arguments, +0x10 dwords (type 5)}`. The calling
/// processor's buffer is replaced; types 0 and 2 format the text for the
/// owner callback and the instruction trace. At raised level the request
/// is deferred to the server pass. 1 when the caller may write.
pub(super) fn timing_request(argument: u32) -> u32 {
    let kind = rd(argument);
    let text = rd(argument + 8);
    let arguments = rd(argument + 0xc);
    let dwords = if kind == 5 { rd(argument + 0x10) } else { 0 };
    let pcr = super::pcr();
    if super::rd8(pcr + 0x18) >= 2 || super::rd8(rd(pcr + 0x100) + 0x70) >= 0x12 {
        // Stock dereferences the missing session.
        let Some(s) = super::super::session::session() else {
            return 0;
        };
        if s.word(0x18) != 0 {
            return 0;
        }
        return u32::from(request_at_raised_level(s));
    }
    let Some(locked) = super::super::session::lock() else {
        return 0;
    };
    let s = locked.0;
    super::gpu::poll(s, false);
    if rd(super::pcr() + PCR_LIMIT) == 0 {
        return 0;
    }
    let tracing = s.word(0x18) != 0;
    if !tracing {
        replace_buffer(s, dwords);
    } else if kind != 3 {
        let mut name = [0u8; EVENT_NAME_BYTES];
        if (kind == 0 || kind == 2) && text != 0 {
            _vsnprintf(name.as_mut_ptr(), 0x23, text, arguments);
        }
        name[0x23] = 0;
        if kind < 3 && s.word(super::CURRENT_MESSAGE) == 5 {
            let event = OWNER_EVENT_BASE + kind;
            s.set_word(super::super::session::LOCK_OVERRIDE, 1);
            super::super::events::notify_owner(event, name.as_ptr() as usize as u32);
            s.set_word(super::super::session::LOCK_OVERRIDE, 0);
        }
        if s.word(super::CURRENT_MESSAGE) == 4 && super::messages::trace_event(kind, &name) {
            s.set_word(0x598, 1);
        }
    }
    drop(locked);
    u32::from(!tracing && rd(super::pcr() + PCR_LIMIT) != 0)
}
