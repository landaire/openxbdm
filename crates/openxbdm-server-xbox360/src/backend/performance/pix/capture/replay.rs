//! Frame extraction from the dump partition (stock 0x91f594c8 and its
//! record walker 0x91f58f10 to 0x91f593a8): find the frame records of a
//! frame range in record stream 0 and hand the per-thread and frame
//! buffer data of those frames to a writer, by default the capture file
//! writer (0x91f5ea90 with 0x91f5e9a8 and 0x91f5d1b8).

use super::S;
use super::buffers;
use super::rd;
use super::wr;

/// Snapshot of stream `k`'s position and frame table (stock 0x91f5cfb0):
/// `{+0 k, +4 frame, +0x30 units, +0x34 sequence, +0x38 entries, +0x3c
/// table position, +0x40 table}`.
const HEADER: u32 = 0x87f4;
const HEADER_SIZE: usize = 0x4040;

pub(super) fn dump_header(s: S, k: u32) {
    let header = s.0 + HEADER;
    // SAFETY: the header area of the session block.
    unsafe { core::ptr::write_bytes(header as usize as *mut u8, 0, HEADER_SIZE) };
    let stream = buffers::stream(k);
    wr(header, k);
    wr(header + 4, super::frame_index(s));
    wr(
        header + 0x30,
        (s.quad(stream + buffers::STREAM_SIZE) as i64 / 0x4000) as u32,
    );
    wr(header + 0x34, s.word(stream + buffers::STREAM_SEQUENCE));
    wr(header + 0x38, buffers::TABLE_ENTRIES);
    wr(header + 0x3c, s.word(stream + buffers::STREAM_TABLE_INDEX));
    // SAFETY: the frame table and the header table are 0x4000 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (s.0 + stream + buffers::STREAM_TABLE) as usize as *const u8,
            (header + 0x40) as usize as *mut u8,
            0x4000,
        )
    };
}

/// Reader of 16 KiB units: `(context, unit, slot) -> data`.
type Read = extern "C" fn(u32, u32, u32) -> u32;

/// Walker over the record stream (stock layout of the 0x2c-byte state).
struct Walker {
    header: u32,
    read: u32,
    context: u32,
    write: u32,
    file: u32,
    previous: u32,
    current: u32,
    end: u32,
    index: u32,
    slot: u32,
    written: u32,
}

impl Walker {
    fn units(&self) -> u32 {
        rd(self.header + 0x30)
    }

    fn read(&self, unit: u32, slot: u32) -> u32 {
        // SAFETY: the reader routine of stock's interface.
        let read: Read = unsafe { core::mem::transmute(self.read as usize) };
        read(self.context, unit, slot)
    }

    /// Whether sequence `sequence` was overwritten since the snapshot
    /// (stock 0x91f58f10).
    fn overwritten(&self, sequence: u32) -> bool {
        let current = rd(self.header + 0x34);
        let generation = sequence >> 24;
        if generation == current >> 24 {
            return false;
        }
        if generation != (current >> 24).wrapping_sub(1) & 0xff {
            return true;
        }
        sequence & 0x00ff_ffff <= current & 0x00ff_ffff
    }

    /// Return the current record and advance; a buffer end loads the next
    /// buffer of the table (stock 0x91f59128).
    fn next(&mut self) -> u32 {
        let record = self.current;
        let mut next = match record {
            0 => 0,
            _ => match rd(record) & 7 {
                0 | 1 => record + 0x28,
                2 => record + 8,
                3 | 5 => record + 0xc,
                4 => record + 0x14,
                _ => 0,
            },
        };
        if next >= self.end {
            if self.index == rd(self.header + 0x3c) {
                next = 0;
            } else {
                let data = self.read(
                    rd(self.header + 0x44 + self.index * 8) & 0x00ff_ffff,
                    self.slot,
                );
                self.slot ^= 1;
                next = data + 4;
                self.index = if self.index + 1 < 0x800 {
                    self.index + 1
                } else {
                    0
                };
                self.end = data + ((rd(data) >> 8) + 1) * 4;
            }
        }
        self.current = next;
        self.previous = record;
        record
    }

    /// Position at the frame record of `frame` (stock 0x91f59278).
    fn seek(&mut self, frame: u32) -> u32 {
        let mut index = rd(self.header + 0x3c);
        let mut found = false;
        for _ in 0..0x800 {
            index = if index == 0 { 0x7ff } else { index - 1 };
            if self.overwritten(rd(self.header + 0x44 + index * 8)) {
                index = if index + 1 < 0x800 { index + 1 } else { 0 };
                found = true;
                break;
            }
            if sign24(rd(self.header + 0x40 + index * 8).wrapping_sub(frame)) < 0 {
                found = true;
                break;
            }
        }
        if !found {
            return 0;
        }
        self.index = index;
        self.previous = 0;
        self.current = 0;
        self.end = 0;
        self.next();
        loop {
            let record = self.next();
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
            let k = rd(self.header);
            return if self.overwritten(rd(record + (k + 2) * 4)) {
                0
            } else {
                record
            };
        }
    }

    /// Units a record covers: `(start, end)` (stock 0x91f58fe0).
    fn units_of(&self, record: u32) -> (u32, u32) {
        let (start, count) = match rd(record) & 7 {
            0 | 1 => (rd(record + (rd(self.header) + 2) * 4) & 0x00ff_ffff, 0),
            2 | 5 => (rd(record + 4) & 0x00ff_ffff, 1),
            3 | 4 => (
                rd(record + 4) & 0x00ff_ffff,
                u32::from(super::rd16(record + 0xa)),
            ),
            _ => (0, 0),
        };
        let mut end = start + count;
        if end >= self.units() {
            end -= self.units();
        }
        (start, end)
    }

    /// Units between the record just returned and the next frame or
    /// buffer record (stock 0x91f593a8); `None` at a capture break.
    fn span(&mut self, first: &mut u32) -> Option<(u32, u32)> {
        let previous = self.previous;
        *first = 0;
        let kind = rd(previous) & 7;
        if kind == 1 {
            *first = previous;
            return None;
        }
        let start = if kind == 0 {
            *first = previous;
            rd(previous + (rd(self.header) + 2) * 4) & 0x00ff_ffff
        } else {
            self.units_of(previous).1
        };
        while rd(self.current) & 7 == 2 {
            self.next();
        }
        let end = self.units_of(self.current).0;
        self.next();
        Some((start, end))
    }

    /// Hand dwords `first..last` of a buffer to the writer (stock
    /// 0x91f58f58).
    fn write(&mut self, buffer: u32, first: u32, last: u32) {
        let last = last.min(rd(buffer) >> 8);
        if first < last {
            // SAFETY: the writer routine of stock's interface takes four
            // arguments; it is this module's or the title's.
            unsafe { crate::kernel::call_export(self.write, self.file, buffer, first, last) };
            self.written += 1;
        }
    }
}

fn sign24(value: u32) -> i32 {
    ((value << 8) as i32) >> 8
}

/// Halfword slot `kind` of a frame record (stock 0x91f59080); 0xffff for
/// kinds without one.
fn slot(record: u32, kind: u32) -> u32 {
    let index = match kind {
        0..=5 => kind,
        0xe => 6,
        _ => return 0xffff,
    };
    u32::from(super::rd16(record + 0x18 + ((index << 1) ^ 2)))
}

fn clear_slot(record: &mut [u32; 10], kind: u32) {
    let index = if kind == 0xe { 6 } else { kind };
    let offset = 0x18 + ((index << 1) ^ 2);
    let word = &mut record[(offset / 4) as usize];
    *word &= if offset & 2 == 0 {
        0x0000_ffff
    } else {
        0xffff_0000
    };
}

fn copy_record(record: u32) -> [u32; 10] {
    core::array::from_fn(|index| rd(record + index as u32 * 4))
}

/// Extract frames `first` (frames back from the snapshot) to `first -
/// last` (stock 0x91f594c8). `per_thread` selects the buffers of types 0
/// to 5 and the frame buffers, else types 6 to 11. `begin(file, starting,
/// time, gpu)` brackets the output. True when anything was written.
#[expect(clippy::too_many_arguments, reason = "stock's interface")]
fn extract(
    read: u32,
    context: u32,
    begin: u32,
    write: u32,
    file: u32,
    header: u32,
    per_thread: bool,
    first: u32,
    last: u32,
) -> bool {
    let (low, high) = if per_thread { (0, 6) } else { (6, 12) };
    let start_frame = rd(header + 4).wrapping_sub(first);
    let end_frame = start_frame.wrapping_add(last);
    let mut walker = Walker {
        header,
        read,
        context,
        write,
        file,
        previous: 0,
        current: 0,
        end: 0,
        index: 0,
        slot: 0,
        written: 0,
    };
    let mut record = walker.seek(start_frame);
    if record == 0 {
        return false;
    }
    let mut first_record = copy_record(record);
    let mut last_record = [0u32; 10];
    loop {
        let kind = rd(record) & 7;
        let mut done = false;
        if kind == 1 {
            let difference = sign24(rd(record + 4).wrapping_sub(end_frame));
            if difference < 0 {
                return false;
            }
            if difference == 0 {
                last_record = copy_record(record);
            }
        }
        if kind == 0 && sign24(rd(record + 4).wrapping_sub(end_frame)) <= 0 {
            if (low..high).any(|index| slot(record, index) == 0xffff) {
                return false;
            }
            if per_thread && slot(record, 0xe) == 0xffff {
                return false;
            }
            if sign24(rd(record + 4).wrapping_sub(end_frame)) == 0 {
                last_record = copy_record(record);
                done = !per_thread;
            }
        }
        if !done && per_thread && kind == 3 {
            if rd(record) & 8 == 0 {
                return false;
            }
            done = sign24((rd(record) >> 4).wrapping_sub(end_frame)) >= 0;
        }
        if done {
            break;
        }
        record = walker.next();
        if record == 0 {
            return false;
        }
    }
    // SAFETY: the bracket routine of stock's interface takes four
    // arguments; it is this module's or the title's.
    unsafe { crate::kernel::call_export(begin, file, 1, first_record[4], first_record[5]) };
    walker.seek(start_frame);
    let mut frame = 0;
    let mut span = walker.span(&mut frame);
    while let Some((mut unit, end)) = span {
        if frame != 0 && sign24(rd(frame + 4).wrapping_sub(end_frame)) >= 0 {
            break;
        }
        while unit != end {
            let buffer = walker.read(unit, 2);
            let kind = rd(buffer) & 0xff;
            if !matches!(kind, 0xf..=0x11) {
                let first = slot(first_record.as_ptr() as usize as u32, kind);
                if per_thread {
                    if kind <= 5 {
                        walker.write(buffer, first, u32::MAX);
                        clear_slot(&mut first_record, kind);
                    }
                } else if (6..12).contains(&kind) {
                    walker.write(buffer, first, u32::MAX);
                }
            }
            unit = if unit + 1 < walker.units() {
                unit + 1
            } else {
                0
            };
        }
        span = walker.span(&mut frame);
    }
    if per_thread {
        let mut record = walker.seek(start_frame);
        let mut position = slot(first_record.as_ptr() as usize as u32, 0xe);
        while record != 0 {
            if rd(record) & 7 == 3 {
                let frame = rd(record) >> 4;
                if sign24(frame.wrapping_sub(start_frame)) >= 0 {
                    if sign24(frame.wrapping_sub(end_frame)) >= 0 {
                        clear_slot_value(&mut first_record, position);
                        let buffer = walker.read(rd(record + 4) & 0x00ff_ffff, 2);
                        walker.write(
                            buffer,
                            position,
                            slot(last_record.as_ptr() as usize as u32, 0xe),
                        );
                        break;
                    }
                    let (mut unit, end) = walker.units_of(record);
                    loop {
                        let buffer = walker.read(unit, 2);
                        walker.write(buffer, position, u32::MAX);
                        position = 0;
                        unit = if unit + 1 < walker.units() {
                            unit + 1
                        } else {
                            0
                        };
                        if unit == end {
                            break;
                        }
                    }
                }
            }
            record = walker.next();
            if record == 0 {
                clear_slot_value(&mut first_record, position);
            }
        }
    }
    let mut pending = 0u32;
    for index in low..high {
        if slot(last_record.as_ptr() as usize as u32, index) != 0 {
            pending |= 1 << index;
        }
    }
    let mut record = walker.seek(start_frame);
    while pending != 0 && record != 0 {
        let word = rd(record);
        if word & 7 == 2 && sign24((word >> 8).wrapping_sub(end_frame)) >= 0 {
            let kind = word >> 3 & 0x1f;
            let bit = 1u32.wrapping_shl(kind);
            if pending & bit != 0 {
                let (unit, _) = walker.units_of(record);
                let wanted = if per_thread {
                    kind <= 5 || kind == 0xe
                } else {
                    (6..12).contains(&kind)
                };
                if wanted {
                    let buffer = walker.read(unit, 2);
                    walker.write(
                        buffer,
                        slot(first_record.as_ptr() as usize as u32, kind),
                        slot(last_record.as_ptr() as usize as u32, kind),
                    );
                }
                pending &= !bit;
            }
        }
        record = walker.next();
    }
    // SAFETY: as above.
    unsafe { crate::kernel::call_export(begin, file, 0, first_record[4], first_record[5]) };
    walker.written != 0
}

/// Store `position` in the type 0xe slot of the first frame record.
fn clear_slot_value(record: &mut [u32; 10], position: u32) {
    clear_slot(record, 0xe);
    record[9] |= position & 0xffff;
}

/// Write frames `first`..`first - last` of stream 0 to `file` (stock
/// 0x91f5ea90).
pub(super) fn write_stream(s: S, file: u32, first: u32, last: u32) -> bool {
    dump_header(s, 0);
    extract(
        read_unit as *const () as usize as u32,
        s.0,
        begin_file as *const () as usize as u32,
        write_file as *const () as usize as u32,
        file,
        s.0 + HEADER,
        true,
        first,
        last,
    )
}

/// Message 8 (stock 0x91f614d0 part): the title's routines.
pub(super) fn replay(s: S, begin: u32, write: u32, context: u32, mode: u32, first: u32, last: u32) {
    dump_header(s, 0);
    extract(
        read_unit as *const () as usize as u32,
        s.0,
        begin,
        write,
        context,
        s.0 + HEADER,
        mode != 0,
        first,
        last,
    );
}

extern "C" fn read_unit(context: u32, unit: u32, slot: u32) -> u32 {
    buffers::read_unit(S(context), unit, slot)
}

/// Capture file bracket (stock 0x91f5e9a8): header, time base and GPU
/// read pointer, processor and timer frequency records at the start; the
/// thread names and the end record at the end.
extern "C" fn begin_file(file: u32, starting: u32, time: u32, gpu: u32) {
    let file = super::super::files::CaptureFile(file);
    if starting == 0 {
        thread_names(file);
        super::super::files::write_words(file, &[0x0100_0018]);
        return;
    }
    super::super::files::write_words(file, &[0x0100_0044]);
    super::super::files::write_words(file, &[0x0300_0060, time, gpu]);
    super::super::files::write_words(file, &[(super::processor() + 0x3e) | 0x0400_0000, 0, 0, 0]);
    super::super::files::write_words(file, &[0x8000_0019, 4, 0, 0x02fa_f080]);
}

/// Buffer data record `{0x8000005f, dwords, kind}` (stock 0x91f5d1b8).
extern "C" fn write_file(file: u32, buffer: u32, first: u32, last: u32) {
    let file = super::super::files::CaptureFile(file);
    super::super::files::write_words(
        file,
        &[
            0x8000_005f,
            last - first + 3,
            u32::from(super::rd8(buffer + 3)),
        ],
    );
    super::super::files::write(file, buffer + (first + 1) * 4, (last - first) * 4);
}

/// Thread name records of every debuggable thread, then of the server
/// thread (stock 0x91f5d110). Stock keeps the references it takes.
fn thread_names(file: super::super::files::CaptureFile) {
    let mut ids = [openxbdm_server::commands::debugger::ThreadId(0); 0x100];
    let Some(count) = crate::backend::debugger::debuggable_thread_ids(&mut ids) else {
        return;
    };
    for id in &ids[..count] {
        let mut thread = 0u32;
        if (crate::backend::debugger::ObLookupAnyThreadByThreadId(id.0, &mut thread) as i32) >= 0
            && !thread_name(file, thread)
        {
            return;
        }
    }
    thread_name(file, crate::backend::debugger::server_thread());
}

/// `{0x8000004a, dwords, thread id, name}` (stock 0x91f5d050); false when
/// the write fails.
fn thread_name(file: super::super::files::CaptureFile, thread: u32) -> bool {
    let Some(name) = (thread != 0)
        .then(|| crate::backend::debugger::thread_name(thread))
        .flatten()
    else {
        return true;
    };
    let mut length = 0;
    while super::rd8(name + length) != 0 {
        length += 1;
    }
    length += 1;
    if length > 0x3f4 {
        return true;
    }
    let mut record = [0u32; 3 + 0x3f4 / 4];
    let words = length.div_ceil(4) + 3;
    record[0] = 0x8000_004a;
    record[1] = words;
    record[2] = rd(thread + super::THREAD_ID);
    for index in 0..length {
        let word = &mut record[3 + (index / 4) as usize];
        *word |= u32::from(super::rd8(name + index)) << (24 - (index % 4) * 8);
    }
    (super::super::files::write(file, record.as_ptr() as usize as u32, words * 4) as i32) >= 0
}
