//! Frame extraction from the dump partition (stock 0x91f594c8 and its
//! record walker 0x91f58f10 to 0x91f593a8): find the frame records of a
//! frame range in record stream 0 and hand the per-thread and frame
//! buffer data of those frames to a writer, by default the capture file
//! writer (0x91f5ea90 with 0x91f5e9a8 and 0x91f5d1b8).

use core::ffi::CStr;
use core::num::NonZeroU8;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use xbox360::thread::ThreadObject;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Kthread;

use super::super::files;
use super::super::files::CaptureFile;
use super::super::files::RecordType;
use super::super::session::DumpHeader;
use super::super::session::PixSession;
use super::super::session::StreamId;
use super::super::session::TABLE_ENTRIES;
use super::super::session::TableEntry;
use super::buffers;
use super::buffers::BUFFER_BYTES;
use super::buffers::BufferType;
use super::gpu::StreamRecordKind;
use super::gpu::frame_buffers_header;
use super::sign24;

/// Capture file record without the type flag: its dword count, header
/// included, in bits 24 to 31 and its type below.
const fn short_record(dwords: u32, kind: u32) -> u32 {
    dwords << 24 | kind
}

pub(super) const END_RECORD: u32 = short_record(1, 0x18);
/// Start of the per-thread timing data of a capture to file.
pub(super) const TIMING_START_RECORD: u32 = short_record(1, 0x1b);

/// Words of a 16 KiB unit; the first is the buffer header.
const UNIT_WORDS: usize = BUFFER_BYTES as usize / 4;
const UNIT_DWORDS_SHIFT: u32 = buffers::HEADER_DWORDS_SHIFT;
/// Unit of a frame table sequence or a record (bits 0 to 23).
const UNIT_MASK: u32 = 0x00ff_ffff;

/// Words of a frame record.
const FRAME_RECORD_WORDS: usize = 10;

/// Record words by [`StreamRecordKind`] value; `None` for 6 and 7, which
/// end the walk.
const RECORD_WORDS: [Option<NonZeroU8>; StreamRecordKind::MASK as usize + 1] = {
    const BUFFER_RECORD_WORDS: usize = 2;
    const SHORT_RECORD_WORDS: usize = 3;
    const GPU_FRAME_RECORD_WORDS: usize = 5;

    let mut words = [None; StreamRecordKind::MASK as usize + 1];
    words[StreamRecordKind::Frame as usize] = NonZeroU8::new(FRAME_RECORD_WORDS as u8);
    words[StreamRecordKind::LastFrame as usize] = NonZeroU8::new(FRAME_RECORD_WORDS as u8);
    words[StreamRecordKind::Buffer as usize] = NonZeroU8::new(BUFFER_RECORD_WORDS as u8);
    words[StreamRecordKind::FrameBuffers as usize] = NonZeroU8::new(SHORT_RECORD_WORDS as u8);
    words[StreamRecordKind::GpuFrame as usize] = NonZeroU8::new(GPU_FRAME_RECORD_WORDS as u8);
    words[StreamRecordKind::Audio as usize] = NonZeroU8::new(SHORT_RECORD_WORDS as u8);
    words
};

/// Word indexes of a frame record (kinds 0 and 1): the frame, the
/// sequence of each stream, the time and GPU read pointer the capture
/// file starts with, and the halfword slots.
mod frame_word {
    pub(super) const FRAME: usize = 1;
    pub(super) const SEQUENCES: usize = 2;
    pub(super) const TIME: usize = 4;
    pub(super) const GPU: usize = 5;
    pub(super) const SLOTS: usize = 6;
}

/// Unit of the data of buffer, frame buffers, GPU frame and audio records.
const RECORD_UNIT: usize = 1;

/// Slot value of a buffer type without data in the frame.
const NO_SLOT: u32 = 0xffff;
/// Slot of the frame buffers, after the six per-thread types.
const FRAME_BUFFER_SLOT: u32 = 6;

/// `starting` argument of the bracket routine at the end.
const BRACKET_END: u32 = 0;

type Unit = [AtomicU32; UNIT_WORDS];

/// Reader of 16 KiB units: `(context, unit, slot) -> data`.
type Read = unsafe extern "C" fn(u32, u32, u32) -> u32;

/// A record of a unit the reader returned, by word index.
#[derive(Clone, Copy)]
struct Record<'a> {
    unit: &'a Unit,
    index: usize,
}

impl Record<'_> {
    /// Word `index` of the record. The unit's header bounds the records
    /// to the unit; the wrap only keeps a corrupt header inside it.
    fn word(self, index: usize) -> u32 {
        self.unit[(self.index + index) % UNIT_WORDS].load(Relaxed)
    }

    /// Low halfword of word `index`, read alone as stock reads it.
    fn low_half(self, index: usize) -> u16 {
        let word = &self.unit[(self.index + index) % UNIT_WORDS];

        // SAFETY: nothing stores a unit the reader returned while the walk
        // reads it, so the halfword read races no word store.
        unsafe { super::low_half(word) }.load(Relaxed)
    }

    /// Kind bits of the first word: a [`StreamRecordKind`] value, or 6 or
    /// 7 past the records.
    fn kind_bits(self) -> u32 {
        self.word(0) & StreamRecordKind::MASK
    }

    fn is(self, kind: StreamRecordKind) -> bool {
        self.kind_bits() == kind as u32
    }

    fn copy(self) -> [u32; FRAME_RECORD_WORDS] {
        core::array::from_fn(|index| self.word(index))
    }
}

/// Walker over the record stream (stock layout of the 0x2c-byte state).
struct Walker<'a> {
    header: &'a DumpHeader,
    read: Read,
    context: u32,
    write: u32,
    file: u32,
    previous: Option<Record<'a>>,
    current: Option<Record<'a>>,
    /// Word index after the records of the unit last read; 0 before the
    /// first unit, so the first `next` reads one (stock compares addresses).
    end: usize,
    index: u32,
    slot: u32,
    written: u32,
}

impl<'a> Walker<'a> {
    fn units(&self) -> u32 {
        self.header.units.load(Relaxed)
    }

    fn read(&self, unit: u32, slot: u32) -> &'a Unit {
        // SAFETY: `extract`'s contract covers the reader and its context.
        let data = unsafe { (self.read)(self.context, unit, slot) };

        // SAFETY: the reader returns the 16 KiB read buffer `slot` of the
        // session's buffer table, which stays allocated while the session
        // lock is held for the extraction; a later read into the slot
        // only replaces its contents.
        unsafe { crate::kernel::object_at::<Unit>(data) }
    }

    /// Frame table entry `index`; the wrap only matters for a corrupt
    /// snapshot index.
    fn entry(&self, index: u32) -> &'a TableEntry {
        &self.header.table[index as usize % TABLE_ENTRIES]
    }

    /// Sequence of the snapshot's stream in frame record `record`.
    fn sequence_of(&self, record: Record<'_>) -> u32 {
        record.word(frame_word::SEQUENCES + self.header.stream.load(Relaxed) as usize)
    }

    /// Whether sequence `sequence` was overwritten since the snapshot
    /// (stock 0x91f58f10).
    fn overwritten(&self, sequence: u32) -> bool {
        super::overwritten(sequence, self.header.sequence.load(Relaxed))
    }

    /// Return the current record and advance; a unit end loads the next
    /// unit of the table (stock 0x91f59128).
    fn next(&mut self) -> Option<Record<'a>> {
        let record = self.current;

        let following = record.and_then(|record| {
            let words = RECORD_WORDS[record.kind_bits() as usize]?;
            Some(Record {
                unit: record.unit,
                index: record.index + usize::from(words.get()),
            })
        });

        let next = if following.map_or(0, |following| following.index) < self.end {
            following
        } else if self.index == self.header.table_index.load(Relaxed) {
            None
        } else {
            let unit = self.read(
                self.entry(self.index).sequence.load(Relaxed) & UNIT_MASK,
                self.slot,
            );
            self.slot ^= 1;
            self.index = next_entry(self.index);
            self.end = (unit_header(unit) >> UNIT_DWORDS_SHIFT) as usize + 1;
            Some(Record { unit, index: 1 })
        };

        self.current = next;
        self.previous = record;

        record
    }

    /// Position at the frame record of `frame` (stock 0x91f59278).
    fn seek(&mut self, frame: u32) -> Option<Record<'a>> {
        let mut index = self.header.table_index.load(Relaxed);
        let mut found = false;

        for _ in 0..TABLE_ENTRIES {
            index = index.wrapping_sub(1) % TABLE_ENTRIES as u32;
            let entry = self.entry(index);
            if self.overwritten(entry.sequence.load(Relaxed)) {
                index = next_entry(index);
                found = true;
                break;
            }
            if sign24(entry.frame.load(Relaxed).wrapping_sub(frame)) < 0 {
                found = true;
                break;
            }
        }

        if !found {
            return None;
        }

        self.index = index;
        self.previous = None;
        self.current = None;
        self.end = 0;
        self.next();

        loop {
            let record = self.next()?;
            if !record.is(StreamRecordKind::Frame) {
                continue;
            }

            let difference = sign24(record.word(frame_word::FRAME).wrapping_sub(frame));
            if difference < 0 {
                continue;
            }
            if difference != 0 {
                return None;
            }

            return (!self.overwritten(self.sequence_of(record))).then_some(record);
        }
    }

    /// Units a record covers: `(start, end)` (stock 0x91f58fe0).
    fn units_of(&self, record: Record<'_>) -> (u32, u32) {
        const FRAME: u32 = StreamRecordKind::Frame as u32;
        const LAST_FRAME: u32 = StreamRecordKind::LastFrame as u32;
        const BUFFER: u32 = StreamRecordKind::Buffer as u32;
        const FRAME_BUFFERS: u32 = StreamRecordKind::FrameBuffers as u32;
        const GPU_FRAME: u32 = StreamRecordKind::GpuFrame as u32;
        const AUDIO: u32 = StreamRecordKind::Audio as u32;
        /// Frame buffers and GPU frame records: unit count in the low half.
        const RECORD_UNIT_COUNT: usize = 2;

        let kind = record.kind_bits();
        let (start, count) = match kind {
            FRAME | LAST_FRAME => (self.sequence_of(record) & UNIT_MASK, 0),
            BUFFER | AUDIO | FRAME_BUFFERS | GPU_FRAME => (
                record.word(RECORD_UNIT) & UNIT_MASK,
                if kind == BUFFER || kind == AUDIO {
                    1
                } else {
                    u32::from(record.low_half(RECORD_UNIT_COUNT))
                },
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
    /// buffer record (stock 0x91f593a8); `None` at a capture break, when
    /// the records run out, or when the span starts at a frame record of
    /// `end_frame` or later.
    fn span(&mut self, end_frame: u32) -> Option<(u32, u32)> {
        let previous = self.previous?;
        let kind = previous.kind_bits();
        if kind == StreamRecordKind::LastFrame as u32 {
            return None;
        }

        let frame = kind == StreamRecordKind::Frame as u32;
        let start = if frame {
            self.sequence_of(previous) & UNIT_MASK
        } else {
            self.units_of(previous).1
        };

        let end = loop {
            let current = self.current?;
            if !current.is(StreamRecordKind::Buffer) {
                break self.units_of(current).0;
            }
            self.next();
        };

        self.next();

        // Stock reads the frame word after the walk.
        if frame && sign24(previous.word(frame_word::FRAME).wrapping_sub(end_frame)) >= 0 {
            return None;
        }

        Some((start, end))
    }

    /// Hand dwords `first..last` of a unit to the writer, `last` limited
    /// to the unit's end (stock 0x91f58f58).
    fn write(&mut self, unit: &Unit, first: u32, last: u32) {
        let last = last.min(unit_header(unit) >> UNIT_DWORDS_SHIFT);
        if first >= last {
            return;
        }

        // SAFETY: `extract`'s contract covers the writer routine.
        unsafe {
            crate::kernel::call_export(
                self.write,
                self.file,
                crate::kernel::address_of(unit),
                first,
                last,
            )
        };
        self.written += 1;
    }

    fn next_unit(&self, unit: u32) -> u32 {
        if unit + 1 < self.units() { unit + 1 } else { 0 }
    }
}

/// Snapshot of stream `stream_id`'s position and frame table (stock
/// 0x91f5cfb0).
pub(super) fn dump_header(session: &PixSession, stream_id: StreamId) {
    let header = &session.dump_header;
    let stream = session.stream(stream_id);

    for word in &header.reserved {
        word.store(0, Relaxed);
    }

    header.stream.store(stream_id.raw(), Relaxed);
    header.frame.store(session.frame_index(), Relaxed);
    header.units.store(
        (stream.size.get() as i64 / i64::from(BUFFER_BYTES)) as u32,
        Relaxed,
    );
    header
        .sequence
        .store(stream.sequence.load(Relaxed), Relaxed);
    header.entries.store(TABLE_ENTRIES as u32, Relaxed);
    header
        .table_index
        .store(stream.table_index.load(Relaxed), Relaxed);

    for (target, source) in header.table.iter().zip(&stream.table) {
        target.frame.store(source.frame.load(Relaxed), Relaxed);
        target
            .sequence
            .store(source.sequence.load(Relaxed), Relaxed);
    }
}

/// Header word of `unit`.
fn unit_header(unit: &Unit) -> u32 {
    unit[0].load(Relaxed)
}

fn next_entry(index: u32) -> u32 {
    (index + 1) % TABLE_ENTRIES as u32
}

/// Word and shift of halfword slot `index`; each word holds the odd slot
/// in its high half.
fn slot_position(index: u32) -> (usize, u32) {
    (
        frame_word::SLOTS + (index / 2) as usize,
        if index & 1 == 0 { 0 } else { 16 },
    )
}

/// Halfword slot of buffer type `kind` in a frame record (stock
/// 0x91f59080): types 0 to 5 and the frame buffers have one.
#[inline(never)]
fn slot(record: &[u32; FRAME_RECORD_WORDS], kind: u32) -> u32 {
    /// Memory position of the low half within a word.
    const LOW_HALF: u32 = if cfg!(target_endian = "big") { 1 } else { 0 };

    let index = if kind < BufferType::SECOND_THREAD {
        kind
    } else if kind == BufferType::FRAME_BUFFER.0 {
        FRAME_BUFFER_SLOT
    } else {
        return NO_SLOT;
    };

    // SAFETY: the ten words hold twenty halfwords, which need no stricter
    // alignment.
    let halves = unsafe { &*core::ptr::from_ref(record).cast::<[u16; 2 * FRAME_RECORD_WORDS]>() };

    u32::from(halves[2 * frame_word::SLOTS + (index ^ LOW_HALF) as usize])
}

/// Clear the slot of per-thread type `kind` (0 to 5) or of the frame
/// buffers.
fn clear_slot(record: &mut [u32; FRAME_RECORD_WORDS], kind: u32) {
    let index = if kind == BufferType::FRAME_BUFFER.0 {
        FRAME_BUFFER_SLOT
    } else {
        kind
    };

    let (word, shift) = slot_position(index);
    record[word] &= !(0xffff << shift);
}

/// Store `position` in the frame buffer slot of the first frame record.
fn clear_slot_value(record: &mut [u32; FRAME_RECORD_WORDS], position: u32) {
    clear_slot(record, BufferType::FRAME_BUFFER.0);

    let (word, shift) = slot_position(FRAME_BUFFER_SLOT);
    record[word] |= (position & 0xffff) << shift;
}

/// Extract frames `first` (frames back from the snapshot) to `first -
/// last` (stock 0x91f594c8). `per_thread` selects the buffers of types 0
/// to 5 and the frame buffers, else types 6 to 11. `begin(file, starting,
/// time, gpu)` brackets the output. True when anything was written.
///
/// # Safety
///
/// `begin` and `write` must be loaded routines taking four arguments
/// `(file, ..)` as stock's interface passes them, and `read` must accept
/// `context`.
#[expect(clippy::too_many_arguments, reason = "stock's interface")]
unsafe fn extract(
    read: Read,
    context: u32,
    begin: u32,
    write: u32,
    file: u32,
    header: &DumpHeader,
    per_thread: bool,
    first: u32,
    last: u32,
) -> bool {
    /// Reader slot of data units; slots 0 and 1 alternate for record units.
    const DATA_SLOT: u32 = 2;
    /// Dword bound of [`Walker::write`] that keeps the unit's own end.
    const UNIT_END: u32 = u32::MAX;
    /// Buffer record: buffer type in bits 3 to 7, frame in bits 8 and up.
    const BUFFER_TYPE_SHIFT: u32 = 3;
    const BUFFER_TYPE_MASK: u32 = 0x1f;
    const BUFFER_FRAME_SHIFT: u32 = 8;
    /// `starting` argument of the bracket routine at the start.
    const BRACKET_START: u32 = 1;

    let second = BufferType::SECOND_THREAD;
    let (low, high) = if per_thread {
        (0, second)
    } else {
        (second, 2 * second)
    };
    let start_frame = header.frame.load(Relaxed).wrapping_sub(first);
    let end_frame = start_frame.wrapping_add(last);

    let mut walker = Walker {
        header,
        read,
        context,
        write,
        file,
        previous: None,
        current: None,
        end: 0,
        index: 0,
        slot: 0,
        written: 0,
    };
    let Some(mut record) = walker.seek(start_frame) else {
        return false;
    };

    let mut first_record = record.copy();
    let mut last_record = [0u32; FRAME_RECORD_WORDS];

    loop {
        let kind = record.kind_bits();
        let mut done = false;

        if kind == StreamRecordKind::LastFrame as u32 {
            let difference = sign24(record.word(frame_word::FRAME).wrapping_sub(end_frame));
            if difference < 0 {
                return false;
            }
            if difference == 0 {
                last_record = record.copy();
            }
        }

        if kind == StreamRecordKind::Frame as u32
            && sign24(record.word(frame_word::FRAME).wrapping_sub(end_frame)) <= 0
        {
            let frame_record = record.copy();
            if (low..high).any(|index| slot(&frame_record, index) == NO_SLOT) {
                return false;
            }
            if per_thread && slot(&frame_record, BufferType::FRAME_BUFFER.0) == NO_SLOT {
                return false;
            }
            if sign24(frame_record[frame_word::FRAME].wrapping_sub(end_frame)) == 0 {
                last_record = frame_record;
                done = !per_thread;
            }
        }

        if !done && per_thread && kind == StreamRecordKind::FrameBuffers as u32 {
            let word = record.word(0);
            if word & frame_buffers_header::OUTPUT_CONTINUES == 0 {
                return false;
            }
            done = sign24((word >> frame_buffers_header::FRAME_SHIFT).wrapping_sub(end_frame)) >= 0;
        }

        if done {
            break;
        }

        let Some(next) = walker.next() else {
            return false;
        };
        record = next;
    }

    // SAFETY: the caller's contract covers the bracket routine.
    unsafe {
        crate::kernel::call_export(
            begin,
            file,
            BRACKET_START,
            first_record[frame_word::TIME],
            first_record[frame_word::GPU],
        )
    };

    walker.seek(start_frame);

    while let Some((mut unit, end)) = walker.span(end_frame) {
        while unit != end {
            let data = walker.read(unit, DATA_SLOT);
            let kind = unit_header(data) & 0xff;
            if kind < BufferType::RECORDS.0 || kind > BufferType::FILLER.0 {
                let first = slot(&first_record, kind);
                if per_thread {
                    if kind < second {
                        walker.write(data, first, UNIT_END);
                        clear_slot(&mut first_record, kind);
                    }
                } else if (second..2 * second).contains(&kind) {
                    walker.write(data, first, UNIT_END);
                }
            }
            unit = walker.next_unit(unit);
        }
    }

    if per_thread {
        let mut record = walker.seek(start_frame);
        let mut position = slot(&first_record, BufferType::FRAME_BUFFER.0);

        while let Some(current) = record {
            if current.is(StreamRecordKind::FrameBuffers) {
                let frame = current.word(0) >> frame_buffers_header::FRAME_SHIFT;
                if sign24(frame.wrapping_sub(start_frame)) >= 0 {
                    if sign24(frame.wrapping_sub(end_frame)) >= 0 {
                        clear_slot_value(&mut first_record, position);
                        let data = walker.read(current.word(RECORD_UNIT) & UNIT_MASK, DATA_SLOT);
                        walker.write(
                            data,
                            position,
                            slot(&last_record, BufferType::FRAME_BUFFER.0),
                        );
                        break;
                    }

                    let (mut unit, end) = walker.units_of(current);
                    loop {
                        let data = walker.read(unit, DATA_SLOT);
                        walker.write(data, position, UNIT_END);
                        position = 0;
                        unit = walker.next_unit(unit);
                        if unit == end {
                            break;
                        }
                    }
                }
            }

            record = walker.next();
            if record.is_none() {
                clear_slot_value(&mut first_record, position);
            }
        }
    }

    let mut pending = 0u32;
    for index in low..high {
        if slot(&last_record, index) != 0 {
            pending |= 1 << index;
        }
    }

    let mut record = walker.seek(start_frame);

    while pending != 0 {
        let Some(current) = record else {
            break;
        };

        let word = current.word(0);
        if word & StreamRecordKind::MASK == StreamRecordKind::Buffer as u32
            && sign24((word >> BUFFER_FRAME_SHIFT).wrapping_sub(end_frame)) >= 0
        {
            let kind = word >> BUFFER_TYPE_SHIFT & BUFFER_TYPE_MASK;
            let bit = 1u32.wrapping_shl(kind);
            if pending & bit != 0 {
                let (unit, _) = walker.units_of(current);
                let wanted = if per_thread {
                    kind < second || kind == BufferType::FRAME_BUFFER.0
                } else {
                    (second..2 * second).contains(&kind)
                };
                if wanted {
                    let data = walker.read(unit, DATA_SLOT);
                    walker.write(data, slot(&first_record, kind), slot(&last_record, kind));
                }
                pending &= !bit;
            }
        }

        record = walker.next();
    }

    // SAFETY: as above.
    unsafe {
        crate::kernel::call_export(
            begin,
            file,
            BRACKET_END,
            first_record[frame_word::TIME],
            first_record[frame_word::GPU],
        )
    };

    walker.written != 0
}

/// Write frames `first`..`first - last` of stream 0 to `file` (stock
/// 0x91f5ea90).
pub(super) fn write_stream(session: &PixSession, file: u32, first: u32, last: u32) -> bool {
    dump_header(session, StreamId::First);

    // SAFETY: this module's routines with the session as reader context.
    unsafe {
        extract(
            read_unit,
            session.address(),
            begin_file as *const () as usize as u32,
            write_file as *const () as usize as u32,
            file,
            &session.dump_header,
            true,
            first,
            last,
        )
    }
}

/// Message 8 (stock 0x91f614d0 part): the title's routines.
///
/// # Safety
///
/// `begin` and `write` must meet the contract of [`extract`].
pub(super) unsafe fn replay(
    session: &PixSession,
    begin: u32,
    write: u32,
    context: u32,
    mode: u32,
    first: u32,
    last: u32,
) {
    dump_header(session, StreamId::First);

    // SAFETY: the caller's contract; the session is the reader context.
    unsafe {
        extract(
            read_unit,
            session.address(),
            begin,
            write,
            context,
            &session.dump_header,
            mode != 0,
            first,
            last,
        )
    };
}

/// # Safety
///
/// `context` must be the session address.
unsafe extern "C" fn read_unit(context: u32, unit: u32, slot: u32) -> u32 {
    // SAFETY: the caller's contract; the session block is never freed.
    let session = unsafe { crate::kernel::object_at::<PixSession>(context) };

    buffers::read_unit(session, unit, slot)
}

/// Capture file bracket (stock 0x91f5e9a8): header, time base and GPU
/// read pointer, processor and timer frequency records at the start; the
/// thread names and the end record at the end.
extern "C" fn begin_file(file: u32, starting: u32, time: u32, gpu: u32) {
    /// Capture file records: header, time base with the GPU read pointer,
    /// and processor (type plus the hardware thread).
    const HEADER_RECORD: u32 = short_record(1, 0x44);
    const TIME_BASE_RECORD: u32 = short_record(3, 0x60);
    const PROCESSOR_RECORD: u32 = short_record(4, 0x3e);
    /// Timer frequency record `{dwords, high, low}`.
    const FREQUENCY_RECORD: RecordType = RecordType::new(0x19);
    /// Timebase frequency the frequency record reports.
    const TIMEBASE_FREQUENCY: u32 = 50_000_000;

    let file = CaptureFile(file);
    if starting == BRACKET_END {
        thread_names(file);
        files::write_words(file, &[END_RECORD]);
        return;
    }

    files::write_words(file, &[HEADER_RECORD]);
    files::write_words(file, &[TIME_BASE_RECORD, time, gpu]);
    files::write_words(
        file,
        &[PROCESSOR_RECORD + super::processor() as u32, 0, 0, 0],
    );
    files::write_words(
        file,
        &const { [FREQUENCY_RECORD.raw(), 4, 0, TIMEBASE_FREQUENCY] },
    );
}

/// Buffer data record `{dwords, kind, data}` (stock 0x91f5d1b8).
///
/// # Safety
///
/// `unit` must be a unit the reader returned, holding words `first + 1`
/// to `last` after its header.
unsafe extern "C" fn write_file(file: u32, unit: u32, first: u32, last: u32) {
    const BUFFER_DATA_RECORD: RecordType = RecordType::new(0x5f);
    /// Words before the data.
    const HEADER_WORDS: u32 = 3;
    /// Memory position of the type byte, the low byte of the header word.
    const TYPE_BYTE: usize = if cfg!(target_endian = "big") { 3 } else { 0 };

    // SAFETY: the caller's contract.
    let header = unsafe { crate::kernel::object_at::<[AtomicU8; 4]>(unit) };
    let kind = header[TYPE_BYTE].load(Relaxed);

    let file = CaptureFile(file);
    files::write_words(
        file,
        &[
            BUFFER_DATA_RECORD.raw(),
            last - first + HEADER_WORDS,
            u32::from(kind),
        ],
    );

    // SAFETY: the caller's contract.
    unsafe { files::write(file, unit + (first + 1) * 4, (last - first) * 4) };
}

/// Thread name records of every debuggable thread, then of the server
/// thread (stock 0x91f5d110). Stock keeps the references it takes.
fn thread_names(file: CaptureFile) {
    let mut ids = [openxbdm_server::commands::debugger::ThreadId(0); 0x100];
    let Some(count) = crate::backend::debugger::debuggable_thread_ids(&mut ids) else {
        return;
    };

    for id in &ids[..count] {
        let mut thread: *mut Kthread = core::ptr::null_mut();
        // SAFETY: `thread` is a live local receiving the object address.
        let status = unsafe { xboxkrnl::ObLookupAnyThreadByThreadId(id.0, &mut thread) };
        if !status.is_success() {
            continue;
        }

        // SAFETY: the lookup referenced the object, and the reference is
        // kept, so it stays allocated.
        let thread = unsafe { ThreadObject::from_raw(thread.expose_provenance() as u32) };
        if !thread_name(file, thread) {
            return;
        }
    }

    if let Some(server) = crate::backend::debugger::server_thread() {
        // SAFETY: the server thread object stays allocated while the
        // monitor runs.
        thread_name(file, unsafe { ThreadObject::from_raw(server.get()) });
    }
}

/// `{dwords, thread id, name}` (stock 0x91f5d050); false when the write
/// fails.
fn thread_name(file: CaptureFile, thread: ThreadObject<'_>) -> bool {
    const THREAD_NAME_RECORD: RecordType = RecordType::new(0x4a);
    /// Name bytes a record holds, the terminator included.
    const NAME_BYTES: usize = 0x3f4;
    /// Words before the name.
    const HEADER_WORDS: usize = 3;

    // SAFETY: not guaranteed: a listed thread can end during the call, and
    // stock reads its monitor record here without the process lock; the
    // monitor keeps that race.
    let Some(name) = (unsafe { crate::backend::debugger::thread_name(thread.kthread()) }) else {
        return true;
    };

    // SAFETY: a thread name is a NUL-terminated string that stays
    // allocated while the thread has it.
    let name = unsafe { CStr::from_ptr(core::ptr::with_exposed_provenance(name as usize)) }
        .to_bytes_with_nul();
    if name.len() > NAME_BYTES {
        return true;
    }

    let mut record = [0u32; HEADER_WORDS + NAME_BYTES / 4];
    let words = (name.len().div_ceil(4) + HEADER_WORDS) as u32;
    record[0] = THREAD_NAME_RECORD.raw();
    record[1] = words;
    record[2] = thread.id().raw();

    const { assert!((HEADER_WORDS + NAME_BYTES / 4).is_power_of_two()) };
    for (index, &byte) in name.iter().enumerate() {
        // The word index stays below the record length, which the length
        // check above guarantees; the wrap only spares a bounds check.
        record[(HEADER_WORDS + index / 4) % record.len()] |=
            u32::from(byte) << (24 - (index % 4) * 8);
    }

    // SAFETY: the first `words` words of `record`.
    unsafe { files::write(file, record.as_ptr() as usize as u32, words * 4) }.is_success()
}
