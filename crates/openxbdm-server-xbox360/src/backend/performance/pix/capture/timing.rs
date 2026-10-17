//! Timing records in the per-hardware-thread capture buffers: the record
//! writers (stock 0x91f77b00, 0x91f77c78, 0x91f77e10, 0x91f78188), the
//! named event begin and end of codes 0x8d and 0x8e (0x91f78698,
//! 0x91f78760), the buffer request of code 0x50 (0x91f61f08) and its
//! raised-level path that switches to a temporary block (0x91f5ee68,
//! 0x91f5ed80), and the server-side buffer replacement (0x91f61cb8,
//! 0x91f61bc8).
//!
//! A record is `{time << 7 | kind, dwords << 24 | id, data}` with a
//! [`RecordKind`].

use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::AcqRel;
use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::Ordering::Release;

use xbox360::thread::current_object;
use xbox360_sys::processor;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::processor::PixBuffer;
use xbox360_sys::xboxkrnl::_vsnprintf;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::Kthread;

use super::super::backend::EVENT_NAME_BYTES;
use super::super::events;
use super::super::events::CallbackOperation;
use super::super::session;
use super::super::session::EngineMessage;
use super::super::session::Part;
use super::super::session::PixSession;
use super::super::session::TEMPORARY_BLOCKS;
use super::super::session::TEMPORARY_BYTES;
use super::super::session::TemporaryState;
use super::TimingRecordId;
use super::buffers;
use super::buffers::BufferEntry;
use super::buffers::BufferType;
use super::buffers::HEADER_BYTES;
use super::engine::THREAD_LIMIT;

/// Room for the record of a writer whose limit check passed: every limit
/// the engine installs leaves this many bytes of the buffer or temporary
/// block after the last cursor that passes the check, beyond the dwords
/// the check covered.
pub(super) const RECORD_RESERVE: u32 = 0xd4;
const _: () = assert!(buffers::BUFFER_BYTES - THREAD_LIMIT == RECORD_RESERVE);
/// Data dwords that fit in [`RECORD_RESERVE`] after the two header words.
const SHORT_RECORD_WORDS: u32 = RECORD_RESERVE / 4 - 2;
/// Bytes of the name, or of the format text and its strings, in an event
/// record.
const TEXT_BYTES: u32 = 0x24;
const TEXT_WORDS: usize = TEXT_BYTES as usize / 4;
/// Dwords of the longest formatted event record: three header words,
/// eight 8-byte arguments, the text.
const FORMATTED_RECORD_WORDS: usize = 3 + 2 * 8 + TEXT_WORDS;
const _: () = assert!(FORMATTED_RECORD_WORDS as u32 * 4 <= RECORD_RESERVE);
/// Identifier records give a thread with identifier 0 while PCR byte 0x19
/// is set (the idle thread).
const IDLE_THREAD_ID: u32 = -2i32 as u32;

/// Kind in the low seven bits of a record's first word, below the time.
#[derive(Clone, Copy)]
#[repr(u32)]
pub(super) enum RecordKind {
    /// Ends the current timing event.
    End = 0,
    /// Data record `{dwords << 24 | id, data}`.
    Data = 1,
    /// Formatted event; the format text's misalignment is added.
    Formatted = 0x19,
    /// Named event begin `{color, name}`.
    NamedBegin = 0x1d,
    /// Data record of [`write_typed_record`].
    Typed = 0x61,
}

impl RecordKind {
    /// First word of a record of this kind written now.
    #[inline(always)]
    pub(super) fn header(self) -> u32 {
        super::timebase_low() << 7 | self as u32
    }
}

/// Second word of a data record: `dwords` in bits 24 to 30 and `id`.
pub(super) fn id_word(id: TimingRecordId, dwords: u32) -> u32 {
    (dwords << 24 & 0x7fff_ffff) | id.raw()
}

/// Identifier records give `thread` on the processor of `pcr`.
pub(super) fn record_thread_id(pcr: &Kpcr, thread: &Kthread) -> u32 {
    let id = thread.id;
    if pcr.unknown_019.load(Relaxed) != 0 && id == 0 {
        IDLE_THREAD_ID
    } else {
        id
    }
}

/// Request types of code 0x50.
#[derive(Clone, Copy)]
#[repr(u32)]
enum RequestType {
    /// Timing event begin; the text names it.
    Begin = 0,
    /// Timing event end.
    End = 1,
    /// Marker; the text names it.
    Marker = 2,
    /// Not reported to the owner or the instruction trace.
    Untraced = 3,
    /// Space for a data record.
    Record = 4,
    /// Space for a data record with [`LongTimingRequest::dwords`] more
    /// dwords.
    LongRecord = 5,
}

/// Code 0x50 argument.
#[repr(C)]
struct TimingRequest {
    /// [`RequestType`].
    kind: AtomicU32,
    /// Event color; code 0x50 does not use it.
    color: AtomicU32,
    /// Format text of the event name and its `va_list` (8-byte slots).
    text: AtomicU32,
    arguments: AtomicU32,
}

/// Code 0x50 argument of a [`RequestType::LongRecord`] request. The
/// requests of this module always have this size, as stock's.
#[repr(C)]
struct LongTimingRequest {
    request: TimingRequest,
    dwords: AtomicU32,
}

impl LongTimingRequest {
    const fn new(kind: RequestType, color: u32, text: u32, arguments: u32, dwords: u32) -> Self {
        Self {
            request: TimingRequest {
                kind: AtomicU32::new(kind as u32),
                color: AtomicU32::new(color),
                text: AtomicU32::new(text),
                arguments: AtomicU32::new(arguments),
            },
            dwords: AtomicU32::new(dwords),
        }
    }
}

/// Ask for buffer space through code 0x50 (as stock calls the debug
/// monitor routine); whether space may be available.
fn request_space(request: &LongTimingRequest) -> bool {
    // SAFETY: `request` is a live long request built in this module, whose
    // text is 0 or a format string matching its argument array, as
    // `timing_request` requires.
    unsafe { super::service_timing_request(crate::kernel::address_of(request)) != 0 }
}

/// With interrupts off, wait for `dwords` of buffer space before the
/// limit, asking code 0x50 for more; the first capture buffer of the
/// processor and the cursor, or `None` when no buffer is installed or the
/// request fails (interrupts on again). From the cursor, `dwords * 4 +
/// RECORD_RESERVE` bytes of the buffer are free while interrupts stay
/// off.
fn reserve(dwords: u32, request: &LongTimingRequest) -> Option<(&'static PixBuffer, u32)> {
    super::interrupts_off();
    loop {
        let buffer = &Kpcr::current().pix_buffers[0];
        let cursor = buffer.cursor.load(Relaxed);
        let limit = buffer.limit.load(Relaxed);
        if cursor.wrapping_add(dwords.wrapping_mul(4)) < limit {
            return Some((buffer, cursor));
        }
        super::interrupts_on();
        if limit == 0 || !request_space(request) {
            return None;
        }
        super::interrupts_off();
    }
}

/// Request of the record writers without extra dwords; code 0x50 only
/// reads it.
static RECORD_REQUEST: LongTimingRequest = LongTimingRequest::new(RequestType::Record, 0, 0, 0, 0);

/// Data record `id` with `data` (stock 0x91f77b00).
pub(super) fn write_record(id: TimingRecordId, data: &[u32]) {
    write(RecordKind::Data, id, data, &RECORD_REQUEST);
}

/// Data record `id` with up to 0xffc dwords; dwords past
/// [`SHORT_RECORD_WORDS`] must fit before the limit (stock 0x91f77c78).
pub(super) fn write_long_record(id: TimingRecordId, data: &[u32]) {
    let extra = (data.len() as u32).saturating_sub(SHORT_RECORD_WORDS);
    write(
        RecordKind::Data,
        id,
        data,
        &LongTimingRequest::new(RequestType::LongRecord, 0, 0, 0, extra),
    );
}

/// Data record `id` of kind [`RecordKind::Typed`] (stock 0x91f77e10).
pub(super) fn write_typed_record(id: TimingRecordId, data: &[u32]) {
    write(RecordKind::Typed, id, data, &RECORD_REQUEST);
}

fn write(kind: RecordKind, id: TimingRecordId, data: &[u32], request: &LongTimingRequest) {
    let extra = (data.len() as u32).saturating_sub(SHORT_RECORD_WORDS);
    let Some((buffer, cursor)) = reserve(extra, request) else {
        return;
    };
    let dwords = data.len() as u32 + 2;
    // SAFETY: the record's dwords are at most `extra` plus the reserve,
    // which `reserve` leaves free at the cursor; only this processor
    // writes there, and interrupts stay off until the cursor moves on.
    let header = unsafe { crate::kernel::object_at::<[AtomicU32; 2]>(cursor) };
    header[0].store(kind.header(), Relaxed);
    header[1].store(id_word(id, dwords), Relaxed);
    // SAFETY: as above, for the data dwords after the header; `data` is
    // caller memory outside the buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            core::ptr::with_exposed_provenance_mut::<u32>((cursor + 8) as usize),
            data.len(),
        )
    };
    // SAFETY: the new cursor ends the record written inside the buffer.
    unsafe { super::set_pcr_word(&buffer.cursor, cursor + dwords * 4) };
    super::interrupts_on();
}

/// Code 0x8d (stock 0x91f56628): name the calling thread `NuiCam Driver`
/// and begin a timing event named `name`.
///
/// # Safety
///
/// `name` must meet the contract of `begin_named`, kept valid by the
/// caller for the call.
pub(crate) unsafe fn service_nuicam_begin(name: u32) -> u32 {
    // SAFETY: a static NUL-terminated name.
    unsafe {
        crate::backend::debugger::name_thread(None, c"NuiCam Driver".as_ptr() as usize as u32)
    };
    // SAFETY: the caller's contract.
    unsafe { begin_named(0, name) };
    0
}

/// Named event begin (stock 0x91f78698): a [`RecordKind::NamedBegin`]
/// record with the name packed after the color; a full buffer falls back
/// to the formatted writer.
///
/// # Safety
///
/// `name` must address a NUL-terminated string whose aligned words up to
/// the terminator are readable, without `%s` or `%S` conversions among
/// its first eight: the formatter reads their arguments, all 0 here, as
/// string addresses.
unsafe fn begin_named(color: u32, name: u32) {
    if Kpcr::current().pix_buffers[0].limit.load(Relaxed) == 0 {
        return;
    }
    super::interrupts_off();
    let buffer = &Kpcr::current().pix_buffers[0];
    let cursor = buffer.cursor.load(Relaxed);
    if cursor < buffer.limit.load(Relaxed) {
        // SAFETY: the cursor, read with interrupts off, is below the
        // limit, so the record of at most 11 dwords fits in the reserve
        // after it; only this processor writes there.
        let record = unsafe { crate::kernel::object_at::<[AtomicU32; 2 + TEXT_WORDS]>(cursor) };
        let (header, text) = record.split_at(2);
        header[0].store(RecordKind::NamedBegin.header(), Relaxed);
        header[1].store(color, Relaxed);
        // SAFETY: `name` is a NUL-terminated string, as the caller
        // guarantees.
        let rest = unsafe { pack(text, name, false) };
        let end = cursor + ((record.len() - rest.len()) * 4) as u32;
        // SAFETY: the new cursor ends the record written inside the buffer.
        unsafe { super::set_pcr_word(&buffer.cursor, end) };
        super::interrupts_on();
        return;
    }
    super::interrupts_on();
    // Stock passes stale argument registers to the formatter here.
    // SAFETY: `name` is readable in aligned words and has no string
    // conversions, as the caller guarantees.
    unsafe { formatted(color, name, &[0; 8]) };
}

/// Code 0x8e (stock 0x91f56668 to 0x91f78760): end the current timing
/// event.
pub(crate) fn service_end(_argument: u32) -> u32 {
    /// Request of an event end; code 0x50 only reads it.
    static END_REQUEST: LongTimingRequest = LongTimingRequest::new(RequestType::End, 0, 0, 0, 0);
    if let Some((buffer, cursor)) = reserve(0, &END_REQUEST) {
        // SAFETY: the one dword lies in the reserve `reserve` leaves at
        // the cursor; interrupts stay off until the cursor moves on.
        let record = unsafe { super::super::words_at(cursor, 1) };
        record[0].store(RecordKind::End.header(), Relaxed);
        // SAFETY: the new cursor ends the record written inside the buffer.
        unsafe { super::set_pcr_word(&buffer.cursor, cursor + 4) };
        super::interrupts_on();
    }
    0
}

/// Pack the string at `source` into the words of `slots` (stock
/// 0x91f77f88; `wide` 0x91f78088 takes the low byte of each 16-bit
/// character); the words after the string. A word holding the terminator
/// ends the string. Narrow characters of 0x80 and up are sign-extended
/// over the characters before them in the word, as stock combines them.
///
/// # Safety
///
/// `source` must address a NUL-terminated string (of 16-bit characters
/// with `wide`), readable up to its terminator.
unsafe fn pack(slots: &[AtomicU32], source: u32, wide: bool) -> &[AtomicU32] {
    let mut index = 0;
    let mut rest = slots;
    while let Some((slot, tail)) = rest.split_first() {
        rest = tail;
        let mut word = 0u32;
        let mut ended = false;
        for position in 0..4 {
            let address = if wide {
                source + index * 2 + 1
            } else {
                source + index
            };
            // SAFETY: a character of the string: reading stops at the
            // first zero byte, which the terminator holds.
            let byte = unsafe { crate::kernel::object_at::<AtomicU8>(address) }.load(Relaxed);
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
        slot.store(word, Relaxed);
        if ended {
            break;
        }
    }
    rest
}

/// Formatted event record (stock 0x91f78188) of a timing event begin: the
/// arguments `format` consumes (at most eight, 8-byte slots), the format
/// text, and the strings `%s`/`%S` arguments name, within
/// [`TEXT_BYTES`].
///
/// # Safety
///
/// `format` must address a NUL-terminated string whose aligned words up
/// to the terminator are readable. Each `%s` or `%S` argument among the
/// first eight conversions must address a NUL-terminated string (of
/// 16-bit characters for `%S`).
unsafe fn formatted(color: u32, format: u32, arguments: &[u64; 8]) {
    if Kpcr::current().pix_buffers[0].limit.load(Relaxed) == 0 {
        return;
    }
    // SAFETY: the scan below reads the format text up to its terminator.
    let byte =
        |address: u32| unsafe { crate::kernel::object_at::<AtomicU8>(address) }.load(Relaxed);
    let mut scan = format;
    let mut count = 0u32;
    let mut strings = [0u32; 8];
    let mut string_count = 0u32;
    let mut wide = 0u32;
    while byte(scan) != 0 {
        if byte(scan) != b'%' {
            scan += 1;
            continue;
        }
        let mut offset = 1;
        let conversion = loop {
            let character = byte(scan + offset);
            match character {
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
                | b'x' => break Some(character),
                _ => offset += 1,
            }
        };
        match conversion {
            None => {
                scan += offset;
                break;
            }
            Some(0) => scan += offset + 1,
            Some(conversion) => {
                scan += offset + 1;
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
    // SAFETY: the scan counts conversions only while fewer than eight were
    // counted, and a string conversion is counted with them.
    unsafe { core::hint::assert_unchecked(count <= 8 && string_count <= count) };
    let request = LongTimingRequest::new(
        RequestType::Begin,
        color,
        format,
        crate::kernel::address_of(arguments),
        0,
    );
    let Some((buffer, output)) = reserve(0, &request) else {
        return;
    };
    let misalignment = format & 3;
    // SAFETY: the record of at most 28 dwords fits in the reserve
    // `reserve` leaves at the cursor; interrupts stay off until the cursor
    // moves on.
    let record = unsafe { crate::kernel::object_at::<[AtomicU32; FORMATTED_RECORD_WORDS]>(output) };
    let (header, rest) = record.split_at(3);
    header[0].store(
        super::timebase_low() << 7 | (RecordKind::Formatted as u32 + misalignment),
        Relaxed,
    );
    header[1].store(color, Relaxed);
    header[2].store(string_count << 16 | count, Relaxed);
    let (values, rest) = rest.split_at(2 * count as usize);
    for (slots, argument) in values.chunks_exact(2).zip(arguments) {
        slots[0].store((argument >> 32) as u32, Relaxed);
        slots[1].store(*argument as u32, Relaxed);
    }
    let text = &rest[..TEXT_WORDS];
    let bytes = (scan - format + 1 + misalignment).min(TEXT_BYTES);
    let start = format - misalignment;
    let (copied, mut slots) = text.split_at(bytes.div_ceil(4) as usize);
    for (word, slot) in (0..).zip(copied) {
        // SAFETY: an aligned word holding format text up to the
        // terminator, readable as the caller guarantees.
        let value =
            unsafe { crate::kernel::object_at::<AtomicU32>(start + word * 4) }.load(Relaxed);
        slot.store(value, Relaxed);
    }
    for (index, &string) in strings[..string_count as usize].iter().enumerate() {
        // SAFETY: a `%s` or `%S` argument, a string as the caller
        // guarantees.
        slots = unsafe { pack(slots, string, wide & 1 << index != 0) };
    }
    let dwords = 3 + values.len() + TEXT_WORDS - slots.len();
    let end = output + (dwords * 4) as u32;
    // SAFETY: the new cursor ends the record written inside the buffer.
    unsafe { super::set_pcr_word(&buffer.cursor, end) };
    super::interrupts_on();
}

/// Raised-level buffer request (stock 0x91f5ee68): switch the processor to
/// its temporary block, or grant one more record in it; the server pass
/// replaces the full buffer. Whether a record may be written.
pub(super) fn request_at_raised_level(s: &PixSession) -> bool {
    let mut granted = true;
    let mut switched = false;
    super::interrupts_off();
    let buffer = &Kpcr::current().pix_buffers[0];
    if buffer.limit.load(Relaxed) == 0 {
        super::interrupts_on();
        return false;
    }
    let processor = super::processor();
    let base = s.temporary_blocks[processor].load(Relaxed);
    let state = s.temporary_state(processor);
    if state == TemporaryState::None {
        s.saved_cursors[processor].store(buffer.cursor.load(Relaxed), Relaxed);
        // SAFETY: the processor's temporary block in the session, with the
        // reserve after the cursor.
        unsafe {
            super::set_pcr_word(&buffer.cursor, base);
            super::set_pcr_word(&buffer.limit, base + 4);
        }
        super::fence();
        s.set_temporary_state(processor, TemporaryState::InUse);
        super::fence();
        switched = true;
    } else if state == TemporaryState::InUse {
        let cursor = buffer.cursor.load(Relaxed);
        if cursor + RECORD_RESERVE <= base + TEMPORARY_BYTES {
            // SAFETY: the reserve after the cursor remains in the block.
            unsafe { super::set_pcr_word(&buffer.limit, cursor + 4) };
        } else {
            granted = false;
        }
    } else {
        merge(s);
    }
    super::interrupts_on();
    if switched {
        s.pending_service.store(1, Release);
    }
    granted
}

/// Take the server pass request set by [`request_at_raised_level`].
pub(super) fn take_pending_service(s: &PixSession) -> bool {
    s.pending_service.swap(0, AcqRel) != 0
}

/// Copy the temporary block's records into the processor's new buffer and
/// continue there (stock 0x91f5ed80), with interrupts off.
pub(super) fn merge(s: &PixSession) {
    let buffer = &Kpcr::current().pix_buffers[0];
    let processor = super::processor();
    let base = s.temporary_blocks[processor].load(Relaxed);
    let dwords = buffer.cursor.load(Relaxed).wrapping_sub(base) >> 2;
    // SAFETY: a processor with records to merge has its new buffer entry
    // in the session.
    let data = unsafe { BufferEntry::at(s.entries[processor].load(Relaxed)) }.data();
    // SAFETY: the temporary block holds `dwords` dwords of records below
    // the cursor, and the new buffer has room for them after its header;
    // the two do not overlap, neither is installed elsewhere, and
    // interrupts are off, so nothing else accesses them.
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::with_exposed_provenance::<u32>(base as usize),
            core::ptr::with_exposed_provenance_mut::<u32>((data + HEADER_BYTES) as usize),
            dwords as usize,
        )
    };
    // SAFETY: the processor's buffer, past the records copied into it.
    unsafe {
        super::set_pcr_word(&buffer.cursor, data + HEADER_BYTES + dwords * 4);
        super::set_pcr_word(&buffer.limit, data + THREAD_LIMIT);
    }
    if s.lost[processor].load(Relaxed) != 0 {
        s.lost[processor].store(0, Relaxed);
        // SAFETY: interrupts are off, and the cursor just installed lies
        // below the limit.
        unsafe { lost_records_marker() };
    }
    super::fence();
    s.set_temporary_state(processor, TemporaryState::None);
    super::fence();
}

/// Record noting that context swap records were lost (stock 0x91f5ed20):
/// a context swap record with the current thread only.
///
/// # Safety
///
/// Interrupts must be off, and the processor's first buffer must have
/// room for the record's three dwords at its cursor.
unsafe fn lost_records_marker() {
    let pcr = Kpcr::current();
    let thread_id = record_thread_id(pcr, current_object().kthread());
    let buffer = &pcr.pix_buffers[0];
    let cursor = buffer.cursor.load(Relaxed);
    // SAFETY: guaranteed by the caller.
    let record = unsafe { super::super::words_at(cursor, 3) };
    record[0].store(RecordKind::Data.header(), Relaxed);
    record[1].store(id_word(TimingRecordId::ContextSwap, 3), Relaxed);
    record[2].store(thread_id, Relaxed);
    // SAFETY: the new cursor ends the record written inside the buffer.
    unsafe { super::set_pcr_word(&buffer.cursor, cursor + 0xc) };
}

/// Replace the calling processor's full buffer at passive level (stock
/// 0x91f61cb8); `dwords` is the size of the record being written.
fn replace_buffer(s: &PixSession, dwords: u32) {
    let part = s.configuration.part(Part::Thread);
    super::interrupts_off();
    let buffer = &Kpcr::current().pix_buffers[0];
    let processor = super::processor();
    let kind = BufferType(processor as u32);
    let slot = &s.entries[processor];
    let mut full = None;
    let state = s.temporary_state(processor);
    if state == TemporaryState::None {
        let cursor = buffer.cursor.load(Relaxed);
        if cursor + dwords * 4 >= buffer.limit.load(Relaxed) {
            // SAFETY: the processor's buffer is installed while its limit is
            // nonzero.
            let entry = unsafe { BufferEntry::at(slot.load(Relaxed)) };
            buffers::close(entry, kind, cursor);
            full = Some(entry);
        }
    } else if state == TemporaryState::InUse {
        // SAFETY: as above.
        let entry = unsafe { BufferEntry::at(slot.load(Relaxed)) };
        buffers::close(entry, kind, s.saved_cursors[processor].load(Relaxed));
        full = Some(entry);
    } else {
        merge(s);
    }
    super::interrupts_on();
    if let Some(full) = full {
        buffers::submit(s, full, s.frame_index());
        let entry = buffers::take(s, kind, part.0);
        slot.store(entry.address(), Relaxed);
        super::interrupts_off();
        if processor == super::processor() {
            if s.temporary_state(processor) == TemporaryState::InUse {
                merge(s);
            } else {
                let buffer = &Kpcr::current().pix_buffers[0];
                let data = entry.data();
                // SAFETY: the new buffer of this processor, taken above.
                unsafe {
                    super::set_pcr_word(&buffer.cursor, data + HEADER_BYTES);
                    super::set_pcr_word(&buffer.limit, data + THREAD_LIMIT);
                }
                super::fence();
                s.set_temporary_state(processor, TemporaryState::None);
                super::fence();
            }
        } else {
            super::fence();
            s.set_temporary_state(processor, TemporaryState::Merge);
            super::fence();
        }
        super::interrupts_on();
    }
    service_buffers(s);
}

/// Replace the buffers whose temporary blocks are in use and service the
/// GPU and audio queues (stock 0x91f61bc8), at passive level.
pub(super) fn service_buffers(s: &PixSession) {
    for index in 0..TEMPORARY_BLOCKS {
        if s.temporary_state(index) != TemporaryState::InUse {
            continue;
        }
        let slot = &s.entries[index];
        let kind = BufferType(index as u32);
        // SAFETY: a buffer whose temporary block is in use is installed.
        let entry = unsafe { BufferEntry::at(slot.load(Relaxed)) };
        buffers::close(entry, kind, s.saved_cursors[index].load(Relaxed));
        let k = entry.info().stream();
        buffers::submit(s, entry, s.frame_index());
        slot.store(buffers::take(s, kind, k).address(), Relaxed);
        super::fence();
        s.set_temporary_state(index, TemporaryState::Merge);
        super::fence();
    }
    super::gpu::service(s, false);
}

/// Monitor control code 0x50 (stock 0x91f56080 and 0x91f61f08). The
/// calling processor's buffer is replaced; types 0 and 2 format the text
/// for the owner callback and the instruction trace. At raised level the
/// request is deferred to the server pass. 1 when the caller may write.
///
/// # Safety
///
/// `argument` must be the address of a timing request, a long one for
/// the long record type, whose text is 0 or a format string matching its
/// argument list, all kept valid by the caller for the call.
pub(super) unsafe fn timing_request(argument: u32) -> u32 {
    /// Thread priority from which requests take the raised-level path.
    const RAISED_PRIORITY: u8 = 0x12;
    /// Characters of the formatted event name before its terminator.
    const NAME_LENGTH: usize = EVENT_NAME_BYTES - 1;

    // SAFETY: the caller's contract.
    let request = unsafe { crate::kernel::object_at::<TimingRequest>(argument) };
    let kind = request.kind.load(Relaxed);
    let text = request.text.load(Relaxed);
    let arguments = request.arguments.load(Relaxed);
    let dwords = if kind == RequestType::LongRecord as u32 {
        // SAFETY: a long record request carries its dword count.
        unsafe { crate::kernel::object_at::<LongTimingRequest>(argument) }
            .dwords
            .load(Relaxed)
    } else {
        0
    };
    if processor::current_irql() >= Irql::DISPATCH
        || current_object().kthread().priority.load(Relaxed) >= RAISED_PRIORITY
    {
        // Stock dereferences the missing session.
        let Some(s) = session::session() else {
            return 0;
        };
        if s.configuration.tracing.load(Relaxed) != 0 {
            return 0;
        }
        return u32::from(request_at_raised_level(s));
    }
    let Some(locked) = session::lock() else {
        return 0;
    };
    let s = locked.session();
    super::gpu::poll(s, false);
    if Kpcr::current().pix_buffers[0].limit.load(Relaxed) == 0 {
        return 0;
    }
    let tracing = s.configuration.tracing.load(Relaxed) != 0;
    if !tracing {
        replace_buffer(s, dwords);
    } else if kind != RequestType::Untraced as u32 {
        let mut name = [0u8; EVENT_NAME_BYTES];
        if (kind == RequestType::Begin as u32 || kind == RequestType::Marker as u32) && text != 0 {
            // SAFETY: `name` holds more than `NAME_LENGTH` bytes; `text`
            // and `arguments` are the caller's format string and argument
            // list.
            unsafe { _vsnprintf(name.as_mut_ptr(), NAME_LENGTH as u32, text, arguments) };
        }
        name[NAME_LENGTH] = 0;
        if let Some(operation) = CallbackOperation::timing(kind)
            && s.message.is(EngineMessage::CaptureToFile)
        {
            s.lock_override.store(1, Relaxed);
            events::notify_owner(operation, name.as_ptr().expose_provenance() as u32);
            s.lock_override.store(0, Relaxed);
        }
        if s.message.is(EngineMessage::TraceEvent) && super::messages::trace_event(kind, &name) {
            s.message.done.store(1, Relaxed);
        }
    }
    drop(locked);
    u32::from(!tracing && Kpcr::current().pix_buffers[0].limit.load(Relaxed) != 0)
}
