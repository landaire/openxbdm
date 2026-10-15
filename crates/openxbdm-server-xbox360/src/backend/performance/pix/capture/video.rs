//! Video operations (stock 0x91f59bc8 to 0x91f5c2b0): replay captured
//! frames from the dump partition through the title's frame record
//! routines (`+0x30` check, `+0x34` completion, `+0x38` vertical position,
//! `+0x3c` submit), play the captured audio through a monitor XAudio
//! client while paused, or write frames and audio as movie data to a file.
//!
//! The context is the session block at 0xc83c; units are read ahead into
//! a ring of 0x24-byte requests `{kind << 4 | flags, unit u16, iosb,
//! record[5]}` (kinds 1 GPU frame, 2 frame without data, 3 audio, 4 end).

use super::S;
use super::buffers;
use super::rd;
use super::wr;
use crate::kernel;

const CONTEXT: u32 = 0xc83c;
const CLIENT: u32 = 0xc930;
const STATUS_PENDING: u32 = 0x103;
const REQUEST: u32 = 0x24;
/// Context flags: completion routine pending, GPU frames, audio.
const COMPLETION: u32 = 0x8000_0000;
const GPU: u32 = 0x4000_0000;
const AUDIO: u32 = 0x2000_0000;
const FRAME_RECORD: u32 = 0x5f4;
const POOL_TAG: u32 = 0x504d_4f56;
/// Ticks of the title's vertical position routine per frame.
const POSITION_LIMIT: i32 = 0xbebc;
const SAMPLES: u32 = 0x600;
const BUFFER_SAMPLES: u32 = 0x2000;

#[derive(Clone, Copy)]
struct V(u32);

impl V {
    fn w(self, offset: u32) -> u32 {
        rd(self.0 + offset)
    }

    fn set(self, offset: u32, value: u32) {
        wr(self.0 + offset, value);
    }

    fn s(self) -> S {
        S(self.w(0))
    }

    fn flags(self) -> u32 {
        self.w(4)
    }

    fn request(self, index: u32) -> u32 {
        self.w(0x9c) + index * REQUEST
    }

    fn advance(self, offset: u32) -> u32 {
        let next = self.w(offset) + 1;
        let next = if next < self.w(0xa4) { next } else { 0 };
        self.set(offset, next);
        next
    }

    /// Data of buffer `index` of the replay table.
    fn buffer(self, index: u32) -> u32 {
        rd(self.w(0xc4) + index * 8)
    }

    fn record_routine(self, offset: u32) -> u32 {
        self.s().word(FRAME_RECORD + offset)
    }

    fn record_argument(self) -> u32 {
        self.s().word(FRAME_RECORD + 0x1c)
    }
}

fn kind(word: u32) -> i32 {
    ((word << 24) as i32) >> 28
}

fn sign24(value: u32) -> i32 {
    ((value << 8) as i32) >> 8
}

fn set_kind(address: u32, kind: u32) {
    wr(address, (rd(address) & !0xf0) | kind << 4);
}

fn copy_request(target: u32, source: u32) {
    // SAFETY: requests are 0x24 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            source as usize as *const u8,
            target as usize as *mut u8,
            REQUEST as usize,
        )
    };
}

/// Mark `out` empty, with the end flag of the context (stock 0x91f59c38
/// tail).
fn empty(v: V, out: u32) {
    wr(out, (rd(out) & !0xf0) | (v.w(0xc0) & 0x40));
}

/// Busy-wait for every outstanding read (stock 0x91f59bc8).
fn wait_requests(v: V) {
    for index in 0..v.w(0xa4) {
        let request = v.request(index);
        if matches!(kind(rd(request)), 1 | 3) {
            while rd(request + 8) == STATUS_PENDING {}
        }
    }
}

/// Next GPU request into `out` (stock 0x91f59c38); `following` keeps
/// requests flagged as continued.
fn next_request(v: V, following: bool, out: u32) {
    while v.w(0xa8) != v.w(0xa0) {
        let request = v.request(v.w(0xa8));
        let flags = v.w(0xc0);
        if flags & 0x80 != 0 {
            if rd(request) & 0xf0 == 0x30 {
                v.set(0xd0, u32::from(super::rd16(request + 4)));
            }
            if rd(request) & 0xf0 == 0x10 {
                v.set(0xc0, flags & !0x80);
            }
        }
        let word = rd(request);
        match kind(word) {
            3 => {}
            1 if rd(request + 0x10) & 0x0800_0000 != 0 && !following => {}
            1 => {
                if rd(request + 8) == STATUS_PENDING {
                    if v.flags() & AUDIO == 0 {
                        v.set(0x1c, word >> 8);
                        v.set(0x3c, v.w(0x3c) + 1);
                    }
                    wr(out, rd(out) & !0xf0);
                    return;
                }
                if v.flags() & AUDIO == 0 {
                    v.set(0xb0, word >> 8);
                }
                copy_request(out, request);
                v.advance(0xa8);
                return;
            }
            _ => {
                copy_request(out, request);
                v.advance(0xa8);
                return;
            }
        }
        v.advance(0xa8);
    }
    empty(v, out);
}

/// Next audio request into `out` (stock 0x91f59dd8).
fn next_audio(v: V, out: u32) {
    while v.w(0xac) != v.w(0xa0) {
        let request = v.request(v.w(0xac));
        v.set(0xd4, u32::from(super::rd16(request + 4)));
        match kind(rd(request)) {
            1 | 2 => {
                v.advance(0xac);
                continue;
            }
            3 if rd(request + 8) == STATUS_PENDING => {
                wr(out, rd(out) & !0xf0);
                return;
            }
            _ => {}
        }
        v.set(0xb0, rd(request) >> 8);
        copy_request(out, request);
        v.advance(0xac);
        return;
    }
    empty(v, out);
}

/// Next request of either kind for movie data (stock 0x91f59f00).
fn current_request(v: V, out: u32) {
    let index = v.w(0xa8);
    if index == v.w(0xa0) {
        set_kind(out, 4);
        return;
    }
    let request = v.request(index);
    let flags = v.w(0xc0);
    if flags & 0x80 != 0 {
        match kind(rd(request)) {
            3 => v.set(0xd0, u32::from(super::rd16(request + 4))),
            1 => v.set(0xc0, flags & !0x80),
            _ => {}
        }
    }
    if rd(request + 8) == STATUS_PENDING {
        set_kind(out, 0);
        return;
    }
    copy_request(out, request);
    let next = if index + 1 < v.w(0xa4) { index + 1 } else { 0 };
    v.set(0xa8, next);
    v.set(0xac, next);
}

/// Note a consumed GPU request (stock 0x91f5a000).
fn note_request(v: V, request: u32) {
    if rd(request + 0x10) & 0x0800_0000 != 0 {
        v.set(0xc0, v.w(0xc0) | 0x80);
    } else {
        v.set(0xc0, v.w(0xc0) & !0x80);
        v.set(0xd0, u32::from(super::rd16(request + 4)));
    }
}

/// Set up the read-ahead buffers and the request ring (stock 0x91f5a058).
fn initialize(v: V) -> bool {
    let s = v.s();
    let count = s.word(0x130);
    if count << 14 < 0x8_0000 || (count.wrapping_sub(3) as i32) <= 0 {
        return false;
    }
    let table = s.word(0x12c);
    for index in 0..3 {
        v.set(0x68 + index * 0x10, rd(table + index * 8));
    }
    v.set(0xc4, table + 3 * 8);
    let buffers = count - 3;
    v.set(0xcc, buffers);
    let requests = buffers.max(1000);
    let ring = kernel::ExAllocatePoolTypeWithTag(requests * REQUEST, POOL_TAG, 2);
    if ring == 0 {
        return false;
    }
    for index in 0..requests {
        wr(ring + index * REQUEST + 8, 0);
    }
    v.set(0x9c, ring);
    v.set(0xa4, requests);
    for offset in (0x20..0x44).step_by(4) {
        v.set(offset, 0);
    }
    true
}

/// End the reads: kernel export 0x2b8 cancels the partition handle's
/// I/O, else wait for them (stock 0x91f5a138).
fn finish(v: V) {
    let routine = kernel::module_handle(c"xboxkrnl.exe")
        .and_then(|kernel| kernel::resolve_export(kernel, 0x2b8))
        .unwrap_or(0);
    if routine != 0 {
        let handle = buffers::stream_handle(v.s(), 0);
        // SAFETY: kernel export 0x2b8 takes one argument, a file handle.
        unsafe { kernel::call_export(routine, handle, 0, 0, 0) };
    } else {
        wait_requests(v);
    }
}

/// Read the next frame table unit into the next read-ahead slot (stock
/// 0x91f5a1a0).
fn prefetch(v: V) {
    let s = v.s();
    let slot_index = v.w(0x98);
    let stream = s.0 + buffers::stream(0);
    let index = v.w(0x54);
    let slot = v.0 + 0x64 + slot_index * 0x10;
    if index == rd(stream + buffers::STREAM_TABLE_INDEX) {
        wr(slot, rd(slot) & 0x7fff_ffff);
        wr(slot + 8, 0);
    } else {
        wr(slot, rd(slot) | 0x8000_0000);
        let offset =
            u64::from(rd(stream + buffers::STREAM_TABLE + index * 8 + 4) & 0x00ff_ffff) << 14;
        wr(slot + 8, STATUS_PENDING);
        kernel::NtReadFile(
            buffers::stream_handle(s, 0),
            0,
            0,
            0,
            (slot + 8) as usize as *mut kernel::IoStatusBlock,
            rd(slot + 4) as usize as *mut u8,
            buffers::BUFFER_BYTES,
            &offset,
        );
        v.set(
            0x54,
            if index + 1 < buffers::TABLE_ENTRIES {
                index + 1
            } else {
                0
            },
        );
    }
    v.set(
        0x98,
        if slot_index + 1 < 3 {
            slot_index + 1
        } else {
            0
        },
    );
}

/// Start reading ahead at table position `index` (stock 0x91f5a298).
fn start_prefetch(v: V, index: u32) {
    v.set(0x54, index);
    prefetch(v);
    prefetch(v);
    for slot in 0..2 {
        while v.w(0x6c + slot * 0x10) == STATUS_PENDING {}
    }
    v.set(0x58, 0);
    v.set(0x60, 0);
}

/// Whether sequence `sequence` of stream 0 was overwritten (stock
/// 0x91f5a310).
fn overwritten(s: S, sequence: u32) -> bool {
    let current = s.word(buffers::stream(0) + buffers::STREAM_SEQUENCE);
    let generation = sequence >> 24;
    if generation == current >> 24 {
        return false;
    }
    if generation != (current >> 24).wrapping_sub(1) & 0xff {
        return true;
    }
    sequence & 0x00ff_ffff <= current & 0x00ff_ffff
}

/// Buffers that may be read ahead (stock 0x91f5a358).
fn readable(v: V) -> u32 {
    let flags = v.flags();
    let distance = |offset: u32| {
        let mut distance = v.w(offset).wrapping_sub(v.w(0xc8)) as i32;
        if distance <= 0 {
            distance += v.w(0xcc) as i32;
        }
        distance
    };
    let gpu = if flags & GPU != 0 {
        distance(0xd0)
    } else {
        i32::MAX
    };
    let audio = if flags & AUDIO != 0 {
        distance(0xd4)
    } else {
        i32::MAX
    };
    let least = gpu.min(audio);
    (if least > 0 { least - 1 } else { least }) as u32
}

/// Whether the request ring is full (stock 0x91f5a3c8).
fn ring_full(v: V) -> bool {
    let next = v.w(0xa0) + 1;
    let next = if next < v.w(0xa4) { next } else { 0 };
    (v.flags() & GPU != 0 && next == v.w(0xa8)) || (v.flags() & AUDIO != 0 && next == v.w(0xac))
}

/// The title's check routine (stock 0x91f5a420); 0 lets it run once
/// more at the end.
fn check(v: V) -> u32 {
    // SAFETY: the title's frame record routine takes one argument.
    let result =
        unsafe { kernel::call_export(v.record_routine(0x30), v.record_argument(), 0, 0, 0) };
    if result == 0 {
        v.set(4, v.flags() | COMPLETION);
    }
    result
}

type CommandList = [u32; 0xca];

/// Part of a command list a request uses: first entry, entries, and the
/// byte offset in the first.
struct Commands {
    start: usize,
    count: usize,
    offset: u32,
}

/// Buffers of GPU request `first` up to request `next` into `list` (part
/// of stock 0x91f5a4e0 and 0x91f5bc78). An offset at the end of the first
/// buffer starts at the next one.
fn command_list(v: V, first: u32, next: u32, list: &mut CommandList) -> Commands {
    // Stock overruns its 0xca-entry list for larger counts.
    let count = u32::from(super::rd16(first + 0x1a)).min(0xc8);
    let mut index = u32::from(super::rd16(first + 4));
    for slot in list.iter_mut().take(count as usize) {
        *slot = v.buffer(index);
        index = if index + 1 < v.w(0xcc) { index + 1 } else { 0 };
    }
    list[count as usize] = v.buffer(u32::from(super::rd16(next + 4)));
    let offset = u32::from(super::rd16(first + 0x18));
    if offset == 0x4000 {
        Commands {
            start: 1,
            count: count as usize,
            offset: 0,
        }
    } else {
        Commands {
            start: 0,
            count: count as usize + 1,
            offset,
        }
    }
}

/// Submit one captured frame to the title (stock 0x91f5a4e0); the
/// routine's result, 0 on success.
fn replay_frame(v: V, first: u32, next: u32, extra: u32) -> u32 {
    let mut list = [0u32; 0xca];
    let commands = command_list(v, first, next, &mut list);
    // SAFETY: the title's submit routine takes seven arguments `(argument,
    // 0, buffers, count, offset, extra, 0x618)`.
    let result = unsafe {
        kernel::call_console(
            v.record_routine(0x3c),
            v.record_argument(),
            0,
            list[commands.start..].as_ptr() as usize as u32,
            commands.count as u32,
            commands.offset,
            extra,
            0x618,
        )
    };
    if result == 0 {
        v.set(0x20, v.w(0x20) + 1);
    }
    result
}

/// Tell the title the replay ended (submit routine with 1).
fn end_submissions(v: V) {
    // SAFETY: as in `replay_frame`.
    unsafe {
        kernel::call_console(
            v.record_routine(0x3c),
            v.record_argument(),
            1,
            0,
            0,
            0,
            0,
            0,
        )
    };
}

/// Statistics debug print (stock 0x91f5a5d8).
fn report(v: V, start: u32) {
    if v.flags() & GPU != 0 {
        let frames = v.w(0x20);
        let elapsed = kernel::tick_count().wrapping_sub(start).wrapping_add(1);
        let range = (v.w(0x10) >> 8).wrapping_sub(v.w(0xc) >> 8);
        // Stock traps on an empty range.
        let percent = (frames.wrapping_mul(100)).checked_div(range).unwrap_or(0);
        let rate = (frames as f32 * 1000.0) / elapsed as f32;
        let values = [
            u64::from(frames),
            u64::from(percent),
            f64::from(rate).to_bits(),
            u64::from(v.w(0x30)),
            u64::from(v.w(0x3c)),
            u64::from(v.w(0x28)),
            u64::from(v.w(0x38)),
        ];
        // SAFETY: the format consumes the seven arguments.
        unsafe {
            super::super::super::pmc::debug_print(
                c"Video: %i (%i%%) frames, %.2f fps, %i record-time drops, %i restarts, %i misses, %i index overruns\n".as_ptr().cast(),
                &values,
            )
        };
    }
    if v.flags() & AUDIO != 0 {
        let values = [
            u64::from(v.w(0x24)),
            u64::from(v.w(0x34)),
            u64::from(v.w(0x40)),
            u64::from(v.w(0x2c)),
            u64::from(v.w(0x38)),
            0,
            0,
        ];
        // SAFETY: the format consumes five arguments.
        unsafe {
            super::super::super::pmc::debug_print(
                c"Audio: %i frames, %i record-time drops, %i restarts, %i misses, %i index overruns\n".as_ptr().cast(),
                &values,
            )
        };
    }
    kernel::debug_print(c"\n");
}

/// Wait until the title's vertical position routine reaches `target`
/// (stock 0x91f5a6e0).
fn wait_position(v: V, target: u32) {
    let routine = v.record_routine(0x38);
    // SAFETY: the title's routine takes one argument and returns a signed
    // position.
    let position = |argument| unsafe { kernel::call_export(routine, argument, 0, 0, 0) } as i32;
    let target = target as i32;
    let mut previous = position(v.record_argument());
    let passed = i32::from(target < previous);
    let mut wraps = 0;
    let mut current = position(v.record_argument());
    while current <= POSITION_LIMIT {
        if wraps == passed && current >= target {
            break;
        }
        if wraps > passed {
            break;
        }
        if current < previous {
            wraps += 1;
        }
        previous = current;
        current = position(v.record_argument());
    }
}

/// Write movie data to the operation's file (stock 0x91f5a790).
fn emit(v: V, data: u32, bytes: u32) {
    let mut io_status = kernel::IoStatusBlock::default();
    if (kernel::NtWriteFile(
        v.w(0x14),
        0,
        0,
        0,
        &mut io_status,
        data as usize as *const u8,
        bytes,
        core::ptr::null(),
    ) as i32)
        < 0
    {
        v.set(0x18, 1);
    }
}

/// Convert 16-bit samples of capture buffer memory to floats (stock
/// 0x91f5a860).
fn to_float(output: u32, source: u32, count: u32) {
    let start = cached(source);
    for index in 0..count {
        let sample = f32::from(super::rd16(start + index * 2) as i16) * f32::from_bits(0x3800_0000);
        wr(output + index * 4, sample.to_bits());
    }
    buffers::flush(start, start + count * 2);
}

fn cached(address: u32) -> u32 {
    (address & 0x1fff_ffff)
        .wrapping_add(((address >> 20) + 0x200) & 0x1000)
        .wrapping_add(0xc000_0000)
}

fn record_size(record: u32) -> u32 {
    match rd(record) & 7 {
        0 | 1 => 0x28,
        2 => 8,
        3 | 5 => 0xc,
        4 => 0x14,
        _ => 0,
    }
}

/// Next record of the read-ahead buffers (stock 0x91f5a8f8).
fn next_record(v: V) -> u32 {
    if v.w(0x58) >= v.w(0x60) {
        prefetch(v);
        let slot = v.0 + 0x64 + v.w(0x94) * 0x10;
        if rd(slot) & 0x8000_0000 == 0 {
            return 0;
        }
        if rd(slot + 8) == STATUS_PENDING {
            v.set(0x38, v.w(0x38) + 1);
            while rd(slot + 8) == STATUS_PENDING {}
        }
        let data = rd(slot + 4);
        v.set(0x94, if v.w(0x94) + 1 < 3 { v.w(0x94) + 1 } else { 0 });
        v.set(0x58, data + 4);
        v.set(0x60, data + ((rd(data) >> 8) + 1) * 4);
    }
    let record = v.w(0x58);
    v.set(0x5c, record);
    v.set(0x58, record + record_size(record));
    record
}

/// Position the read-ahead at the frame record of `frame` (stock
/// 0x91f5aa50).
fn seek(v: V, frame: u32) -> u32 {
    let s = v.s();
    let stream = s.0 + buffers::stream(0);
    let mut index = rd(stream + buffers::STREAM_TABLE_INDEX);
    let mut found = false;
    for _ in 0..buffers::TABLE_ENTRIES {
        index = if index == 0 { 0x7ff } else { index - 1 };
        if overwritten(s, rd(stream + buffers::STREAM_TABLE + index * 8 + 4)) {
            index = if index + 1 < 0x800 { index + 1 } else { 0 };
            found = true;
            break;
        }
        if sign24(rd(stream + buffers::STREAM_TABLE + index * 8).wrapping_sub(frame)) < 0 {
            found = true;
            break;
        }
    }
    if !found {
        return 0;
    }
    start_prefetch(v, index);
    loop {
        let record = next_record(v);
        if record == 0 {
            return 0;
        }
        if rd(record) & 7 != 0 {
            continue;
        }
        let difference = sign24(rd(record + 4).wrapping_sub(frame));
        if difference < 0 {
            continue;
        }
        if difference != 0 {
            return 0;
        }
        return if overwritten(s, rd(record + 8)) {
            0
        } else {
            record
        };
    }
}

/// Next record that bounds the operation, 0 at its end (stock
/// 0x91f5ab60).
fn next_bound(v: V) -> u32 {
    let current = v.w(0x5c);
    if current != 0 {
        let word = rd(current);
        let frame = if v.flags() & GPU != 0 {
            (word & 7 == 4 && word & 0xf000_0000 == 0).then_some(word >> 3)
        } else {
            matches!(word & 7, 0 | 1).then(|| rd(current + 4))
        };
        if let Some(frame) = frame
            && sign24(frame.wrapping_sub(v.w(8) >> 8)) >= 0
        {
            return 0;
        }
    }
    loop {
        let record = next_record(v);
        if record == 0 {
            return 0;
        }
        let word = rd(record);
        let flags = v.flags();
        match word & 7 {
            0 => {
                if ((flags >> 20) ^ word) & 0x180 != 0 || ((flags >> 16) ^ word) & 0x600 != 0 {
                    return 0;
                }
                return record;
            }
            4 => {
                if sign24((word >> 3).wrapping_sub(flags >> 1)) >= 0 {
                    return record;
                }
            }
            _ => return record,
        }
    }
}

/// Queue reads of the next units into the request ring (stock
/// 0x91f5ac68).
fn fill_requests(v: V) {
    let s = v.s();
    let pending = v.0 + 0xb4;
    let units = (s.quad(buffers::stream(0) + buffers::STREAM_SIZE) as i64 / 0x4000) as u32;
    let mut budget = readable(v);
    if budget == 0 {
        return;
    }
    loop {
        if rd(pending) == 0 {
            loop {
                let request = v.request(v.w(0xa0));
                if ring_full(v) {
                    return;
                }
                if rd(pending + 0xc) & 0x40 != 0 {
                    end_marker(v, request);
                    return;
                }
                let record = next_bound(v);
                if record == 0 {
                    wr(pending + 0xc, rd(pending + 0xc) | 0x40);
                    end_marker(v, request);
                    return;
                }
                let word = rd(record);
                if word & 7 == 0 {
                    wr(
                        pending + 0xc,
                        rd(record + 4) << 8 | u32::from(super::rd8(pending + 0xf)),
                    );
                }
                if word & 7 == 5 && v.flags() & AUDIO != 0 {
                    wr(pending, 1);
                    wr(pending + 4, rd(record + 4));
                    set_kind(request, 3);
                    set_halfword(request + 4, v.w(0xc8));
                    for index in 0..3 {
                        wr(request + 0x10 + index * 4, rd(record + index * 4));
                    }
                    wr(
                        request,
                        (rd(pending + 0xc) & 0xffff_ff00) | (rd(request) & 0xff),
                    );
                    break;
                }
                if word & 7 == 4 && v.flags() & GPU != 0 {
                    set_halfword(request + 4, v.w(0xc8));
                    for index in 0..5 {
                        wr(request + 0x10 + index * 4, rd(record + index * 4));
                    }
                    wr(
                        request,
                        (word << 5 & 0xffff_ff00) | u32::from(super::rd8(request + 3)),
                    );
                    if word & 0xf000_0000 == 0 {
                        wr(pending, u32::from(super::rd16(record + 0xa)));
                        wr(pending + 4, rd(record + 4));
                        set_kind(request, 1);
                        break;
                    }
                    set_kind(request, 2);
                    v.advance(0xa0);
                    v.set(0x30, v.w(0x30) + 1);
                }
            }
        }
        let mut left = budget.min(rd(pending));
        while left != 0 {
            let request = v.request(v.w(0xa0));
            let chunk = left
                .min(8)
                .min(units.wrapping_sub(rd(pending + 4) & 0x00ff_ffff));
            let mut segments = [0u32; 8 * 4 + 1];
            for index in 0..chunk {
                let position = v.w(0xc8);
                let next = position + 1;
                v.set(0xc8, if next < v.w(0xcc) { next } else { 0 });
                let data = v.buffer(position);
                for page in 0..4 {
                    segments[(index * 4 + page) as usize] = data + page * 0x1000;
                }
            }
            let io_status = if rd(pending) == chunk {
                request + 8
            } else {
                v.0 + 0xec
            };
            wr(io_status, STATUS_PENDING);
            let offset = u64::from(rd(pending + 4) & 0x00ff_ffff) << 14;
            buffers::NtReadFileScatter(
                buffers::stream_handle(s, 0),
                0,
                0,
                0,
                io_status,
                segments.as_ptr(),
                chunk << 14,
                &offset,
            );
            left -= chunk;
            budget -= chunk;
            let position = rd(pending + 4);
            let mut next = (position & 0xff00_0000) | (position.wrapping_add(chunk) & 0x00ff_ffff);
            if next & 0x00ff_ffff >= units {
                next &= 0xff00_0000;
            }
            wr(pending + 4, next);
            wr(pending, rd(pending) - chunk);
            if rd(pending) == 0 {
                v.advance(0xa0);
            }
        }
        if budget == 0 {
            return;
        }
    }
}

fn set_halfword(address: u32, value: u32) {
    // SAFETY: an aligned halfword of a request.
    unsafe { core::ptr::write_volatile(address as usize as *mut u16, value as u16) };
}

fn end_marker(v: V, request: u32) {
    set_kind(request, 4);
    v.advance(0xa0);
}

/// Elapsed replay time against a record time (stock 0x91f5b018): true
/// when the frame is due; a frame far behind is recorded as a miss.
fn frame_due(v: V, record: u32) -> bool {
    if v.s().word(super::FLAGS) & super::PAUSED != 0 {
        return true;
    }
    let target = rd(record + 0xc).wrapping_sub(v.w(0x4c)) as i32;
    let elapsed = (performance_counter() as i32).wrapping_sub(v.w(0x50) as i32);
    if v.flags() & AUDIO == 0 && target > elapsed.wrapping_add(POSITION_LIMIT) {
        v.set(0x1c, rd(record) >> 3 & 0x00ff_ffff);
        v.set(0x3c, v.w(0x3c) + 1);
    }
    target < elapsed
}

/// Audio counterpart of [`frame_due`] (stock 0x91f5b0c0).
fn audio_due(v: V, record: u32) -> bool {
    let target = rd(record + 8).wrapping_sub(v.w(0x4c)) as i32;
    let mut elapsed = (performance_counter() as i32).wrapping_sub(v.w(0x50) as i32);
    if v.flags() & GPU != 0 {
        elapsed = elapsed.wrapping_add(0x82);
    }
    target < elapsed
}

fn performance_counter() -> u32 {
    let mut counter = 0u64;
    kernel::QueryPerformanceCounter(&mut counter);
    (counter as i64 >> 10) as u32
}

crate::exports::bridged!(render_entry, render);

/// Address of the audio client routine handed to XAudio.
pub(super) fn render_entry_address() -> u32 {
    render_entry as *const () as usize as u32
}

/// XAudio render client routine (stock 0x91f5b140): plays the captured
/// audio of the operation, 0x600 samples per call. The client state is
/// 0 idle, 1 starting, 2 playing, 3 stop requested, 4 underrun.
extern "C" fn render(context: u32) {
    let client = rd(context);
    let s = S(rd(client + 4));
    let v = V(rd(client + 8));
    let current = client + 0x14;
    let output = client + 0x38;
    match rd(client) {
        3 => {
            super::sync();
            wr(client, 0);
            super::sync();
            return;
        }
        1 => {
            if kind(rd(current)) == 0 {
                next_audio(v, current);
                if kind(rd(current)) == 0 {
                    return;
                }
            }
            if kind(rd(current)) == 4 {
                wr(client, 0);
                return;
            }
            if !audio_due(v, client + 0x24) {
                return;
            }
            wr(client + 0xc, rd(client + 0x24) >> 3 & 0xffff);
            wr(
                client + 0x10,
                v.buffer(u32::from(super::rd16(client + 0x18))),
            );
            super::sync();
            wr(client, 2);
            super::sync();
        }
        2 => {}
        _ => return,
    }
    let position = rd(client + 0xc);
    if position <= BUFFER_SAMPLES - SAMPLES {
        to_float(output, rd(client + 0x10) + position * 2, SAMPLES);
        wr(client + 0xc, position + SAMPLES);
        XAudioSubmitRenderDriverFrame(s.word(0x1_2290), output);
        v.set(0x24, v.w(0x24) + 1);
        return;
    }
    let repeat = rd(client + 0x24);
    if repeat >> 19 != 0 {
        wr(
            client + 0x24,
            (repeat & 0x7ffff) | ((repeat >> 19) - 1) << 19,
        );
        v.set(0x34, v.w(0x34) + 1);
        return;
    }
    let first = BUFFER_SAMPLES - position;
    let rest = SAMPLES - first;
    to_float(output, rd(client + 0x10) + position * 2, first);
    let mut next = [0u32; 9];
    let next_address = next.as_mut_ptr() as usize as u32;
    next_audio(v, next_address);
    let underrun = match kind(next[0]) {
        4 => {
            super::sync();
            wr(client, 0);
            super::sync();
            return;
        }
        0 => true,
        _ => {
            let lead = (v.w(0x50) as i32)
                .wrapping_sub(performance_counter() as i32)
                .wrapping_add(rd(client + 0x2c).wrapping_sub(v.w(0x4c)) as i32);
            lead > 0xa28 || ((next[4] >> 3 & 0xffff).wrapping_sub(rest)) % SAMPLES != 0
        }
    };
    if underrun {
        v.set(0x1c, (rd(current) >> 8) + 1);
        v.set(0x40, v.w(0x40) + 1);
        super::sync();
        wr(client, 4);
        super::sync();
        return;
    }
    let data = v.buffer(next[1] >> 16);
    wr(client + 0xc, rest);
    wr(client + 0x10, data);
    to_float(output + first * 4, data, rest);
    XAudioSubmitRenderDriverFrame(s.word(0x1_2290), output);
    v.set(0x24, v.w(0x24) + 1);
    copy_request(current, next_address);
}

/// Start an operation at the context's frame (stock 0x91f5b420): reset
/// the queues, find the frame record, and decide the parts. Nonzero
/// refuses (4 nothing to replay, or the title's check result).
fn begin(v: V, audio: bool, no_gpu: bool) -> u32 {
    let s = v.s();
    v.set(0x94, 0);
    v.set(0x98, 0);
    v.set(0xc8, 0);
    v.set(0xd0, 0);
    v.set(0xd4, 0);
    v.set(0xa0, 0);
    v.set(0xac, 0);
    v.set(0xa8, 0);
    v.set(0xb4, 0);
    v.set(0xb8, 0);
    v.set(0xbc, 0);
    v.set(0xc0, 0);
    v.set(0x58, 0);
    v.set(0x60, 0);
    v.set(
        0xc0,
        u32::from(super::rd8(v.0 + 0xc3)) | (v.flags() << 7 & 0xffff_ff00),
    );
    let record = seek(v, v.flags() >> 1 & 0x00ff_ffff);
    if record == 0 {
        return 4;
    }
    v.set(0x1c, u32::MAX);
    let word = rd(record);
    let mut flags = v.flags();
    flags = (flags & !0x1800_0000) | (word << 20 & 0x1800_0000);
    flags = (flags & !0x0600_0000) | (word << 16 & 0x0600_0000);
    flags = (flags & !GPU) | u32::from(word & 0x180 == 0) << 30;
    flags = (flags & !AUDIO) | u32::from(word & 0x600 == 0) << 29;
    if no_gpu {
        flags &= !GPU;
    }
    if !audio {
        flags &= !AUDIO;
    }
    let full_record = s.word(FRAME_RECORD + 0xc) & 4 != 0;
    if !full_record {
        flags &= !GPU;
    }
    if s.word(super::super::session::KERNEL_ROUTINE) == 0 {
        flags &= !AUDIO;
    }
    v.set(4, flags);
    if flags & (GPU | AUDIO) == 0 {
        return 4;
    }
    if flags & GPU != 0 && flags & COMPLETION == 0 {
        let result = check(v);
        if result != 0 {
            return result;
        }
    }
    fill_requests(v);
    wait_requests(v);
    0
}

/// `VideoOp` status with the operation's argument and the frames left
/// (stock 0x91f5b5d8 and 0x91f56438).
fn status(v: V, done: bool) {
    let mut frame = v.w(0xb0);
    if sign24(frame.wrapping_sub(v.w(0xc) >> 8)) < 0 {
        frame = v.w(0xc) >> 8;
    }
    if sign24(frame.wrapping_sub(v.w(0x10) >> 8)) >= 0 {
        frame = (v.w(0x10) >> 8).wrapping_sub(1);
    }
    let back = sign24((v.s().word(super::FLAGS) >> 5).wrapping_sub(frame));
    let current = super::super::frame::frame_number().wrapping_sub(back as u32) as i32;
    let mut text: openxbdm_server::text::Text<0x80> = openxbdm_server::text::Text::new();
    let label = if done { "Done" } else { "Update" };
    let _ = core::fmt::Write::write_fmt(
        &mut text,
        format_args!("{} {} {}\0", v.w(0x48) as i32, label, current),
    );
    super::super::status::post(
        super::super::status::Status::VideoOp,
        text.as_bytes().as_ptr() as usize as u32,
    );
}

/// Replay one frame (stock 0x91f5b630).
fn single(v: V) -> u32 {
    let mut result = begin(v, false, false);
    if result != 0 {
        return result;
    }
    if v.flags() & GPU != 0 {
        let mut first = [0u32; 9];
        let mut next = [0u32; 9];
        let mut extra = [0u32; 0x40];
        next_request(v, false, first.as_mut_ptr() as usize as u32);
        if kind(first[0]) == 2 {
            result = first[4] >> 28;
        } else {
            loop {
                next_request(v, true, next.as_mut_ptr() as usize as u32);
                if kind(next[0]) != 2 {
                    break;
                }
            }
            result = replay_frame(
                v,
                first.as_ptr() as usize as u32,
                next.as_ptr() as usize as u32,
                extra.as_mut_ptr() as usize as u32,
            );
        }
        if result != 0 {
            end_submissions(v);
        }
    }
    status(v, true);
    result
}

/// Align the replay clock with the first frame (stock 0x91f5b748).
fn start_clock(v: V, client: u32, out: u32) {
    if v.flags() & GPU != 0 {
        next_request(v, false, out);
        while kind(rd(out)) == 0 {
            fill_requests(v);
            next_audio(v, client + 0x14);
            next_request(v, false, out);
            wait_requests(v);
        }
        wait_position(v, rd(out + 0x1c).wrapping_sub(rd(out + 0x20)));
        v.set(0x50, performance_counter());
        v.set(0x4c, rd(out + 0x1c));
        if v.flags() & AUDIO != 0 {
            loop {
                next_audio(v, client + 0x14);
                if rd(client + 0x14) & 0xf0 != 0x30
                    || (v.w(0x4c).wrapping_sub(rd(client + 0x2c)) as i32) <= 0x82
                {
                    break;
                }
            }
        }
    } else {
        next_audio(v, client + 0x14);
        v.set(0x50, performance_counter());
        v.set(0x4c, rd(client + 0x2c));
    }
}

/// Replay a frame range in real time (stock 0x91f5b878) until its end, a
/// queued message, or a thread write; misses restart at the missed frame.
fn multiple(v: V) -> u32 {
    let mut s = v.s();
    let client = s.0 + CLIENT;
    let mut first = [0u32; 9];
    let mut next = [0u32; 9];
    let mut extra = [0u32; 0x40];
    let first_address = first.as_mut_ptr() as usize as u32;
    let next_address = next.as_mut_ptr() as usize as u32;
    let mut last_status = kernel::tick_count();
    let start = kernel::tick_count();
    let mut interrupted = false;
    let mut result = begin(v, true, false);
    if result != 0 {
        return result;
    }
    'restart: loop {
        start_clock(v, client, first_address);
        if v.flags() & AUDIO != 0 {
            super::sync();
            wr(client, 1);
            super::sync();
        }
        'frames: loop {
            let flags = v.flags();
            if flags & AUDIO != 0 && rd(client) == 0 {
                break 'frames;
            }
            if flags & GPU != 0 {
                let mut ready = kind(first[0]) == 1;
                if !ready {
                    next_request(v, false, first_address);
                    let kind_first = kind(first[0]);
                    if kind_first == 4 && v.flags() & AUDIO == 0 {
                        break 'frames;
                    }
                    ready = kind_first == 1;
                }
                if ready && frame_due(v, first_address + 0x10) {
                    next_request(v, true, next_address);
                    match kind(next[0]) {
                        4 => break 'frames,
                        1 => {
                            result = replay_frame(
                                v,
                                first_address,
                                next_address,
                                extra.as_mut_ptr() as usize as u32,
                            );
                            if result != 0 {
                                if v.w(0x20) == 0 {
                                    end_submissions(v);
                                }
                                break 'frames;
                            }
                            note_request(v, next_address);
                            if next[4] & 0x0800_0000 != 0 {
                                first[0] &= !0xf0;
                            } else {
                                first = next;
                            }
                            next[0] &= !0xf0;
                        }
                        0 => {
                            note_request(v, first_address);
                            v.set(0x28, v.w(0x28) + 1);
                            next[0] &= !0xf0;
                            first[0] &= !0xf0;
                        }
                        _ => {}
                    }
                }
            }
            if v.w(0x1c) != u32::MAX {
                break 'frames;
            }
            fill_requests(v);
            if kernel::tick_count().wrapping_sub(last_status) > 100 {
                last_status = kernel::tick_count();
                status(v, false);
            }
            super::super::session::leave(
                s.at(super::super::session::LOCK),
                s.word(super::super::session::LOCK_PRIORITY),
            );
            let saved = super::super::session::enter(s.at(super::super::session::LOCK));
            s.set_word(super::super::session::LOCK_PRIORITY, saved);
            s = v.s();
            if s.word(0x58c) > 0 && s.word(super::FLAGS) & super::PAUSED == 0 {
                interrupted = true;
                break 'frames;
            }
            if v.flags() & AUDIO != 0 && v.w(0x44) != s.word(0xe210) {
                break 'frames;
            }
        }
        let restart = v.w(0x1c);
        if restart != u32::MAX && restart < v.w(8) >> 8 {
            finish(v);
            v.set(4, (v.flags() & !0x01ff_fffe) | (restart << 1 & 0x01ff_fffe));
            result = begin(v, true, false);
            if result == 0 {
                continue 'restart;
            }
            return result;
        }
        break 'restart;
    }
    if v.flags() & AUDIO != 0 {
        if v.w(0x44) == s.word(0xe210) {
            super::sync();
            wr(client, 3);
            super::sync();
            while rd(client) != 0 {}
        } else {
            super::sync();
            wr(client, 0);
            super::sync();
        }
    }
    status(v, !interrupted);
    report(v, start);
    result
}

/// Movie data record header (stock 0x91f5bc08).
fn movie_record(v: V, id: u32, bytes: u32) {
    let dwords = bytes >> 2;
    if dwords < 0x7f {
        let header = [((dwords + 1) << 24 & 0x7fff_ffff) | id];
        emit(v, header.as_ptr() as usize as u32, 4);
    } else {
        let header = [id | 0x8000_0000, dwords + 2];
        emit(v, header.as_ptr() as usize as u32, 8);
    }
}

/// Movie frame: the `PixV` image the title stored in the frame's command
/// data (stock 0x91f5bc78); 6 when the data has no image.
fn movie_frame(v: V, first: u32, next: u32) -> u32 {
    let mut list = [0u32; 0xca];
    let Commands {
        start: mut index,
        mut count,
        offset,
    } = command_list(v, first, next, &mut list);
    let image = cached(list[index] + offset);
    if rd(image) != 0x5069_7856 || rd(image + 4) != 0 || rd(image + 8) > 2 {
        return 6;
    }
    let mut position = offset + 0x1000;
    if position >= 0x4000 {
        if position != 0x4000 {
            return 6;
        }
        position = 0;
        index += 1;
        count -= 1;
    }
    let header = [
        rd(first + 0x1c),
        rd(image + 0x10),
        rd(image + 0x14),
        rd(image + 0x20),
    ];
    movie_record(
        v,
        0x6b,
        ((count as u32) << 14).wrapping_sub(position) + 0x10,
    );
    emit(v, header.as_ptr() as usize as u32, 0x10);
    for &buffer in &list[index..index + count] {
        let data = buffer + position;
        let bytes = 0x4000 - position;
        emit(v, data, bytes);
        kernel::KeFlushCacheRange(data, bytes);
        position = 0;
    }
    0
}

/// Movie audio between two audio requests (stock 0x91f5be10).
fn movie_audio(v: V, previous: u32, current: u32) {
    let start = rd(previous + 0x10) >> 3 & 0xffff;
    let end = rd(current + 0x10) >> 3 & 0xffff;
    let header = [
        rd(previous + 0x18),
        (rd(previous + 0x10) >> 19) * SAMPLES,
        end + (BUFFER_SAMPLES - start),
    ];
    let first_bytes = (BUFFER_SAMPLES - start) * 2;
    let second_bytes = end * 2;
    let first = cached(v.buffer(u32::from(super::rd16(previous + 4)))) + start * 2;
    let second = cached(v.buffer(u32::from(super::rd16(current + 4))));
    movie_record(v, 0x6c, second_bytes + first_bytes + 0xc);
    emit(v, header.as_ptr() as usize as u32, 0xc);
    emit(v, first, first_bytes);
    emit(v, second, second_bytes);
    kernel::KeFlushCacheRange(first, first_bytes);
    kernel::KeFlushCacheRange(second, second_bytes);
}

/// Write the frame range as movie data (stock 0x91f5bf10).
fn movie(v: V, no_gpu: u32) -> u32 {
    movie_record(v, 0x69, 0);
    // Stock starts from uninitialized previous requests.
    let mut audio = [0u32; 9];
    let mut frame = [0u32; 9];
    let mut current = [0u32; 9];
    let current_address = current.as_mut_ptr() as usize as u32;
    'restart: loop {
        let result = begin(v, true, no_gpu != 0);
        if result != 0 {
            return result;
        }
        loop {
            fill_requests(v);
            current_request(v, current_address);
            match kind(current[0]) {
                0 => {}
                4 => {
                    movie_record(v, 0x18, 0);
                    return 0;
                }
                1 => {
                    if frame[0] & 0xf0 == 0x10 {
                        let result =
                            movie_frame(v, frame.as_ptr() as usize as u32, current_address);
                        if result != 0 {
                            movie_record(v, 0x18, 0);
                            return result;
                        }
                        note_request(v, current_address);
                    }
                    if current[4] & 0x0800_0000 != 0 {
                        frame[0] &= !0xf0;
                    } else {
                        frame = current;
                    }
                }
                3 => {
                    if audio[0] & 0xf0 == 0x30 {
                        let discontinuous = (current[6].wrapping_sub(audio[6]) as i32) > 0xa28
                            || ((current[4] >> 3 & 0xffff)
                                .wrapping_sub(audio[4] >> 3 & 0xffff)
                                .wrapping_add(BUFFER_SAMPLES))
                                % SAMPLES
                                != 0;
                        if discontinuous {
                            movie_record(v, 0x6d, 0);
                            finish(v);
                            let restart = ((current[0] >> 7) & 0x01ff_fffe).wrapping_add(2);
                            let flags = (restart & 0x01ff_fffe) | (v.flags() & !0x01ff_fffe);
                            v.set(4, flags);
                            if flags & 0x01ff_fffe < (v.w(8) >> 7) & 0x01ff_fffe {
                                audio[0] &= !0xf0;
                                frame[0] &= !0xf0;
                                continue 'restart;
                            }
                        }
                        movie_audio(v, audio.as_ptr() as usize as u32, current_address);
                        v.set(0xd4, current[1] >> 16);
                    }
                    audio = current;
                }
                _ => {}
            }
        }
    }
}

/// Context for frames `first` (frames back) and `count` frames.
fn setup(s: S, first: u32, count: u32) -> V {
    let v = V(s.0 + CONTEXT);
    let start = ((s.word(super::FLAGS) >> 4) & 0x0fff_fffe).wrapping_sub(first << 1);
    let flags = (start & 0x01ff_fffe) | (v.flags() & 0xfe00_0001);
    v.set(4, flags);
    v.set(0xb0, (flags & 0x01ff_fffe) >> 1);
    let end = ((flags & !1).wrapping_add(count << 1) & 0x01ff_fffe) << 7;
    v.set(8, end | u32::from(super::rd8(v.0 + 0xb)));
    v
}

/// Message 12: replay frames (stock 0x91f5c0e8); the error code, if any
/// (3 without buffers).
pub(super) fn run(s: S, first: u32, count: u32, argument: u32) -> Option<u32> {
    let v = V(s.0 + CONTEXT);
    if !initialize(v) {
        return Some(3);
    }
    let start_byte = u32::from(super::rd8(v.0 + 0xf));
    let end_byte = u32::from(super::rd8(v.0 + 0x13));
    v.set(0x48, argument);
    let v = setup(s, first, count);
    v.set(0xc, (v.flags() & 0x01ff_fffe) << 7 | start_byte);
    v.set(0x10, end_byte | (v.w(8) & 0xffff_ff00));
    let result = if count == 1 { single(v) } else { multiple(v) };
    finish(v);
    kernel::ExFreePool(v.w(0x9c));
    v.set(0x9c, 0);
    (result != 0).then_some(result)
}

/// Message 14 while paused: frames as movie data to `file` (stock
/// 0x91f5c1d8); 0, or 3 without buffers, 8 when a write failed.
pub(super) fn write(s: S, file: u32, no_gpu: u32, first: u32, count: u32) -> u32 {
    let v = V(s.0 + CONTEXT);
    if !initialize(v) {
        return 3;
    }
    v.set(0x14, file);
    v.set(0x18, 0);
    let v = setup(s, first, count);
    let mut result = movie(v, no_gpu);
    finish(v);
    kernel::ExFreePool(v.w(0x9c));
    v.set(0x9c, 0);
    if result == 0 && v.w(0x18) != 0 {
        result = 8;
    }
    result
}

crate::kernel::import_thunk!(
    XAudioSubmitRenderDriverFrame(client: u32, samples: u32) -> u32,
    lib = crate::kernel::LIB_KERNEL,
    ordinal = 0x1f5
);
