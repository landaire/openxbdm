//! Request ring and read-ahead of the captured stream.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_server::commands::memory::PAGE_SIZE;
use xbox360::module::ExportAddress;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;

use super::super::super::session::PixSession;
use super::super::super::session::StreamId;
use super::super::super::session::TABLE_ENTRIES;
use super::super::buffers;
use super::super::buffers::BufferEntry;
use super::super::buffers::UNIT_SHIFT;
use super::super::gpu::StreamRecordKind;
use super::super::gpu::fence_header;
use super::super::low_byte;
use super::super::low_half;
use super::super::sign24;
use super::super::wrap;
use super::Cursor;
use super::Operation;
use super::READ_SLOTS;
use super::ReadState;
use super::RequestKind;
use super::SlotState;
use super::VideoContext;
use super::VideoContextFlags;
use super::VideoRequest;
use super::audio_record;
use super::frame_header;
use super::gpu_record;
use crate::kernel;

/// A stream record in a read-ahead buffer: its kind and first word. The
/// record holds the words its kind gives.
#[derive(Clone, Copy)]
struct Record<'a> {
    kind: Option<StreamRecordKind>,
    header: &'a AtomicU32,
}

impl<'a> Record<'a> {
    /// The record at `address`.
    ///
    /// # Safety
    ///
    /// `address` must be the address of a stream record in a read-ahead
    /// buffer, which holds the bytes its kind gives, and the buffer must
    /// stay allocated for `'a`.
    #[inline(always)]
    unsafe fn at(address: u32) -> Self {
        // SAFETY: the first word lies in the record; guaranteed by the
        // caller.
        let header: &AtomicU32 = unsafe { kernel::object_at(address) };

        Self {
            kind: StreamRecordKind::of(header.load(Relaxed)),
            header,
        }
    }

    fn header(self) -> u32 {
        self.header.load(Relaxed)
    }

    /// Bytes of the record.
    fn bytes(self) -> u32 {
        match self.kind {
            Some(StreamRecordKind::Frame | StreamRecordKind::LastFrame) => 0x28,
            Some(StreamRecordKind::Buffer) => 8,
            Some(StreamRecordKind::FrameBuffers | StreamRecordKind::Audio) => 0xc,
            Some(StreamRecordKind::GpuFrame) => 0x14,
            None => 0,
        }
    }

    /// The first `N` words of the record.
    ///
    /// # Safety
    ///
    /// The record's kind must give at least `N` words.
    #[inline(always)]
    unsafe fn words<const N: usize>(self) -> &'a [AtomicU32; N] {
        // SAFETY: the words lie in the record (guaranteed by the caller),
        // which stays allocated for `'a` (the invariant of `Record`); the
        // view is rebuilt from the exposed address of the record.
        unsafe { kernel::object_at(kernel::address_of(self.header)) }
    }

    /// The words of a frame or last frame record.
    fn frame(self) -> Option<&'a [AtomicU32; 10]> {
        matches!(
            self.kind,
            Some(StreamRecordKind::Frame | StreamRecordKind::LastFrame)
        )
        // SAFETY: a frame record holds ten words.
        .then(|| unsafe { self.words() })
    }

    /// The words of a GPU frame record.
    fn gpu_frame(self) -> Option<&'a [AtomicU32; gpu_record::WORDS]> {
        (self.kind == Some(StreamRecordKind::GpuFrame))
            // SAFETY: a GPU frame record holds five words.
            .then(|| unsafe { self.words() })
    }

    /// The words of an audio record.
    fn audio(self) -> Option<&'a [AtomicU32; 3]> {
        (self.kind == Some(StreamRecordKind::Audio))
            // SAFETY: an audio record holds three words.
            .then(|| unsafe { self.words() })
    }
}

pub(super) fn count(counter: &AtomicU32) {
    counter.store(counter.load(Relaxed).wrapping_add(1), Relaxed);
}

/// Mark `out` empty, or ended with the end flag of the context (stock
/// 0x91f59c38 tail).
fn empty(operation: Operation<'_>, out: &VideoRequest) {
    out.set_kind(if operation.video.read_state().contains(ReadState::END) {
        RequestKind::End
    } else {
        RequestKind::Empty
    });
}

/// Busy-wait for every outstanding read (stock 0x91f59bc8).
pub(super) fn wait_requests(operation: Operation<'_>) {
    for request in operation.ring() {
        if matches!(request.kind(), Some(RequestKind::Gpu | RequestKind::Audio)) {
            while request.status.is_pending() {}
        }
    }
}

/// With [`ReadState::CONTINUED`], the GPU consumer follows the audio
/// requests until the next GPU request.
#[inline(always)]
fn follow(operation: Operation<'_>, request: &VideoRequest) {
    let video = operation.video;
    let state = video.read_state();
    if !state.contains(ReadState::CONTINUED) {
        return;
    }

    match request.kind() {
        Some(RequestKind::Audio) => video.gpu_buffer.store(request.unit() as u32, Relaxed),
        Some(RequestKind::Gpu) => video.set_read_state(state.difference(ReadState::CONTINUED)),
        // Other kinds leave the read state.
        _ => {}
    }
}

/// Next GPU request into `out` (stock 0x91f59c38); `following` keeps
/// requests that end the capture.
pub(super) fn next_request(operation: Operation<'_>, following: bool, out: &VideoRequest) {
    let video = operation.video;

    while video.gpu_index.load(Relaxed) != video.ring_tail.load(Relaxed) {
        let request = operation.request(Cursor::Gpu);
        follow(operation, request);

        match request.kind() {
            // Audio requests and, without `following`, the last fence are skipped.
            Some(RequestKind::Audio) => {}
            Some(RequestKind::Gpu)
                if request.record_word(gpu_record::HEADER) & fence_header::LAST != 0
                    && !following => {}
            Some(RequestKind::Gpu) => {
                if request.status.is_pending() {
                    if !video.flags().contains(VideoContextFlags::AUDIO) {
                        video.restart.store(request.frame(), Relaxed);
                        count(&video.statistics.restarts);
                    }
                    out.set_kind(RequestKind::Empty);
                    return;
                }

                if !video.flags().contains(VideoContextFlags::AUDIO) {
                    video.frame.store(request.frame(), Relaxed);
                }
                out.copy_from(request);
                operation.advance(Cursor::Gpu);
                return;
            }
            _ => {
                out.copy_from(request);
                operation.advance(Cursor::Gpu);
                return;
            }
        }

        operation.advance(Cursor::Gpu);
    }

    empty(operation, out);
}

/// Next audio request into `out` (stock 0x91f59dd8).
pub(super) fn next_audio(operation: Operation<'_>, out: &VideoRequest) {
    let video = operation.video;

    while video.audio_index.load(Relaxed) != video.ring_tail.load(Relaxed) {
        let request = operation.request(Cursor::Audio);
        video.audio_buffer.store(request.unit() as u32, Relaxed);

        match request.kind() {
            Some(RequestKind::Gpu | RequestKind::NoData) => {
                operation.advance(Cursor::Audio);
                continue;
            }
            Some(RequestKind::Audio) if request.status.is_pending() => {
                out.set_kind(RequestKind::Empty);
                return;
            }
            // Other requests are taken below.
            _ => {}
        }

        video.frame.store(request.frame(), Relaxed);
        out.copy_from(request);
        operation.advance(Cursor::Audio);
        return;
    }

    empty(operation, out);
}

/// Next request of either kind for movie data (stock 0x91f59f00).
pub(super) fn current_request(operation: Operation<'_>, out: &VideoRequest) {
    let video = operation.video;
    let index = video.gpu_index.load(Relaxed);
    if index == video.ring_tail.load(Relaxed) {
        out.set_kind(RequestKind::End);
        return;
    }

    // SAFETY: `index` is the GPU cursor.
    let request = unsafe { operation.request_at(index) };
    follow(operation, request);
    if request.status.is_pending() {
        out.set_kind(RequestKind::Empty);
        return;
    }

    out.copy_from(request);
    let next = operation.next_index(index);
    video.gpu_index.store(next, Relaxed);
    video.audio_index.store(next, Relaxed);
}

/// Note a consumed GPU request (stock 0x91f5a000).
pub(super) fn note_request(operation: Operation<'_>, request: &VideoRequest) {
    let video = operation.video;
    if request.record_word(gpu_record::HEADER) & fence_header::LAST != 0 {
        video.set_read_state(video.read_state() | ReadState::CONTINUED);
    } else {
        video.set_read_state(video.read_state().difference(ReadState::CONTINUED));
        video.gpu_buffer.store(request.unit() as u32, Relaxed);
    }
}

/// Set up the read-ahead buffers and the request ring of context `video` of
/// `session` (stock 0x91f5a058).
pub(super) fn initialize<'a>(
    session: &'a PixSession,
    video: &'a VideoContext,
) -> Option<Operation<'a>> {
    const POOL_TAG: PoolTag = PoolTag::new(*b"PMOV");
    /// Fewest entries of the request ring.
    const MINIMUM_REQUESTS: u32 = 1000;
    /// Smallest capture the operations replay.
    const MINIMUM_CAPTURE_BYTES: u32 = 0x8_0000;

    let session_buffers = session.buffer_count.load(Relaxed);
    if session_buffers << UNIT_SHIFT < MINIMUM_CAPTURE_BYTES
        || (session_buffers.wrapping_sub(READ_SLOTS) as i32) <= 0
    {
        return None;
    }

    let table = session.buffer_table.load(Relaxed);
    // SAFETY: the session's buffer table has `buffer_count` entries, more
    // than `READ_SLOTS` (checked above), while the session captures; the
    // operation runs under the session lock.
    let slot_entries: &[BufferEntry; READ_SLOTS as usize] = unsafe { kernel::object_at(table) };
    for (slot, entry) in video.slots.iter().zip(slot_entries) {
        slot.data.store(entry.data(), Relaxed);
    }

    let buffers = table + size_of_val(slot_entries) as u32;
    video.buffers.store(buffers, Relaxed);
    let buffer_count = session_buffers - READ_SLOTS;
    video.buffer_count.store(buffer_count, Relaxed);

    let requests = buffer_count.max(MINIMUM_REQUESTS);
    // SAFETY: allocates from the system pool; no pointer arguments.
    let ring = unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(
            requests * size_of::<VideoRequest>() as u32,
            POOL_TAG,
            PoolType::System,
        )
    };
    if ring == 0 {
        return None;
    }

    // SAFETY: `ring` is a new pool block of `requests` requests that only
    // this operation uses until `release` frees it; any contents are valid
    // atomics.
    let ring_requests: &[VideoRequest] = unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance(ring as usize),
            requests as usize,
        )
    };
    for request in ring_requests {
        request.status.status.store(0, Relaxed);
    }

    video.ring.store(ring, Relaxed);
    video.ring_count.store(requests, Relaxed);
    video.statistics.clear();

    Some(Operation { video })
}

/// End the reads: kernel export 0x2b8 cancels the partition handle's
/// I/O, else wait for them (stock 0x91f5a138).
pub(super) fn finish(operation: Operation<'_>) {
    /// Kernel export that cancels the I/O of a file handle.
    const CANCEL_IO_ROUTINE: Ordinal = Ordinal::new(0x2b8).unwrap();

    let routine = SystemModule::Kernel
        .handle()
        .and_then(|kernel| resolve_export(kernel, CANCEL_IO_ROUTINE))
        .map_or(0, ExportAddress::raw);

    if routine != 0 {
        let handle = buffers::stream_handle(operation.session(), StreamId::First);
        // SAFETY: kernel export 0x2b8 takes one argument, a file handle.
        unsafe { kernel::call_export(routine, handle, 0, 0, 0) };
    } else {
        wait_requests(operation);
    }
}

/// Read the next frame table unit into the next read-ahead slot (stock
/// 0x91f5a1a0).
fn prefetch(operation: Operation<'_>) {
    let video = operation.video;
    let session = operation.session();
    let stream = session.stream(StreamId::First);
    let slot_index = video.fill_slot.load(Relaxed);
    let index = video.table_position.load(Relaxed);
    // SAFETY: the fill slot is below `READ_SLOTS` (the invariant of
    // `Operation`).
    let slot = unsafe { video.slot(slot_index) };
    let state = slot.state();

    if index == stream.table_index.load(Relaxed) {
        slot.set_state(state.difference(SlotState::FILLED));
        slot.status.status.store(0, Relaxed);
    } else {
        slot.set_state(state | SlotState::FILLED);

        // The position wraps at the table size.
        let entry = &stream.table[index as usize % TABLE_ENTRIES];
        let offset = u64::from(entry.sequence.load(Relaxed) & 0x00ff_ffff) << UNIT_SHIFT;
        slot.status.set_pending();
        // SAFETY: the status block and the buffer belong to the slot, which
        // outlives the read (`finish` cancels or waits for it); `offset` is
        // read during the call.
        unsafe {
            xboxkrnl::NtReadFile(
                Handle::from_raw(buffers::stream_handle(session, StreamId::First)),
                Handle::NULL,
                0,
                0,
                slot.status.as_ptr(),
                core::ptr::with_exposed_provenance_mut(slot.data.load(Relaxed) as usize),
                buffers::BUFFER_BYTES,
                &offset,
            )
        };

        video
            .table_position
            .store(wrap(index + 1, TABLE_ENTRIES as u32), Relaxed);
    }

    video
        .fill_slot
        .store(wrap(slot_index + 1, READ_SLOTS), Relaxed);
}

/// Start reading ahead at table position `index` (stock 0x91f5a298).
fn start_prefetch(operation: Operation<'_>, index: u32) {
    let video = operation.video;
    video.table_position.store(index, Relaxed);
    prefetch(operation);
    prefetch(operation);

    for slot in &video.slots[..2] {
        while slot.status.is_pending() {}
    }

    video.record_cursor.store(0, Relaxed);
    video.record_end.store(0, Relaxed);
}

/// Whether sequence `sequence` of stream 0 was overwritten (stock
/// 0x91f5a310).
fn overwritten(session: &PixSession, sequence: u32) -> bool {
    super::super::overwritten(
        sequence,
        session.stream(StreamId::First).sequence.load(Relaxed),
    )
}

/// Buffers that may be read ahead (stock 0x91f5a358).
fn readable(operation: Operation<'_>) -> u32 {
    let video = operation.video;
    let flags = video.flags();
    let distance = |position: &AtomicU32| {
        let mut distance = position
            .load(Relaxed)
            .wrapping_sub(video.buffer_position.load(Relaxed)) as i32;
        if distance <= 0 {
            distance += video.buffer_count.load(Relaxed) as i32;
        }

        distance
    };

    let gpu = if flags.contains(VideoContextFlags::GPU) {
        distance(&video.gpu_buffer)
    } else {
        i32::MAX
    };
    let audio = if flags.contains(VideoContextFlags::AUDIO) {
        distance(&video.audio_buffer)
    } else {
        i32::MAX
    };
    let least = gpu.min(audio);

    (if least > 0 { least - 1 } else { least }) as u32
}

/// Whether the request ring is full (stock 0x91f5a3c8).
fn ring_full(operation: Operation<'_>) -> bool {
    let video = operation.video;
    let next = operation.next_index(video.ring_tail.load(Relaxed));

    (video.flags().contains(VideoContextFlags::GPU) && next == video.gpu_index.load(Relaxed))
        || (video.flags().contains(VideoContextFlags::AUDIO)
            && next == video.audio_index.load(Relaxed))
}

/// Next record of the read-ahead buffers (stock 0x91f5a8f8).
fn next_record<'a>(operation: Operation<'a>) -> Option<Record<'a>> {
    let video = operation.video;
    if video.record_cursor.load(Relaxed) >= video.record_end.load(Relaxed) {
        prefetch(operation);

        // SAFETY: the read slot is below `READ_SLOTS` (the invariant of
        // `Operation`).
        let slot = unsafe { video.slot(video.read_slot.load(Relaxed)) };
        if !slot.state().contains(SlotState::FILLED) {
            return None;
        }

        if slot.status.is_pending() {
            count(&video.statistics.overruns);
            while slot.status.is_pending() {}
        }

        let data = slot.data.load(Relaxed);
        video
            .read_slot
            .store(wrap(video.read_slot.load(Relaxed) + 1, READ_SLOTS), Relaxed);
        // SAFETY: the slot's read completed into `data`, a capture buffer
        // of the buffer table; its first word is the buffer header.
        let header = unsafe { kernel::object_at::<AtomicU32>(data) }.load(Relaxed);
        video
            .record_cursor
            .store(data + buffers::HEADER_BYTES, Relaxed);
        video.record_end.store(
            data + ((header >> buffers::HEADER_DWORDS_SHIFT) + 1) * 4,
            Relaxed,
        );
    }

    let address = video.record_cursor.load(Relaxed);
    video.current_record.store(address, Relaxed);
    // SAFETY: the cursor lies in the records of the buffer the last slot
    // read, which the engine wrote whole.
    let record = unsafe { Record::at(address) };
    video.record_cursor.store(address + record.bytes(), Relaxed);

    Some(record)
}

/// Position the read-ahead at the frame record of `frame` (stock
/// 0x91f5aa50); the words of that record.
pub(super) fn seek<'a>(operation: Operation<'a>, frame: u32) -> Option<&'a [AtomicU32; 10]> {
    let session = operation.session();
    let stream = session.stream(StreamId::First);
    let mut index = stream.table_index.load(Relaxed);

    let start = 'search: {
        for _ in 0..TABLE_ENTRIES {
            index = if index == 0 {
                TABLE_ENTRIES as u32 - 1
            } else {
                index - 1
            };

            // The index wraps at the table size.
            let entry = &stream.table[index as usize % TABLE_ENTRIES];
            if overwritten(session, entry.sequence.load(Relaxed)) {
                break 'search wrap(index + 1, TABLE_ENTRIES as u32);
            }
            if sign24(entry.frame.load(Relaxed).wrapping_sub(frame)) < 0 {
                break 'search index;
            }
        }

        return None;
    };

    start_prefetch(operation, start);

    loop {
        let record = next_record(operation)?;
        let (Some(StreamRecordKind::Frame), Some(words)) = (record.kind, record.frame()) else {
            continue;
        };

        let difference = sign24(words[1].load(Relaxed).wrapping_sub(frame));
        if difference < 0 {
            continue;
        }

        if difference != 0 || overwritten(session, words[2].load(Relaxed)) {
            return None;
        }

        return Some(words);
    }
}

/// Next record that bounds the operation, `None` at its end (stock
/// 0x91f5ab60).
fn next_bound<'a>(operation: Operation<'a>) -> Option<Record<'a>> {
    let video = operation.video;
    let current = video.current_record.load(Relaxed);
    if current != 0 {
        // SAFETY: a nonzero current record word holds the last record
        // `next_record` returned, in a read-ahead buffer of the table.
        let header: &AtomicU32 = unsafe { kernel::object_at(current) };
        let word = header.load(Relaxed);
        let kind = StreamRecordKind::of(word);

        let frame = if video.flags().contains(VideoContextFlags::GPU) {
            (kind == Some(StreamRecordKind::GpuFrame) && word & fence_header::STATUS_MASK == 0)
                .then_some(word >> fence_header::FRAME_SHIFT)
        } else if matches!(
            kind,
            Some(StreamRecordKind::Frame | StreamRecordKind::LastFrame)
        ) {
            // SAFETY: as above; a frame record holds more than two words.
            let words: &[AtomicU32; 2] = unsafe { kernel::object_at(current) };
            Some(words[1].load(Relaxed))
        } else {
            None
        };

        if let Some(frame) = frame
            && sign24(frame.wrapping_sub(video.end.load(Relaxed) >> 8)) >= 0
        {
            return None;
        }
    }

    loop {
        let record = next_record(operation)?;
        let word = record.header();
        let flags = video.flags().bits();

        match record.kind {
            Some(StreamRecordKind::Frame) => {
                if ((flags >> VideoContextFlags::GPU_STREAM_SHIFT) ^ word)
                    & frame_header::GPU_STREAM
                    != 0
                    || ((flags >> VideoContextFlags::AUDIO_STREAM_SHIFT) ^ word)
                        & frame_header::AUDIO_STREAM
                        != 0
                {
                    return None;
                }

                return Some(record);
            }
            Some(StreamRecordKind::GpuFrame) => {
                if sign24((word >> fence_header::FRAME_SHIFT).wrapping_sub(flags >> 1)) >= 0 {
                    return Some(record);
                }
            }
            _ => return Some(record),
        }
    }
}

/// Queue reads of the next units into the request ring (stock
/// 0x91f5ac68).
pub(super) fn fill_requests(operation: Operation<'_>) {
    /// Units read by one scatter read.
    const MAX_CHUNK_UNITS: u32 = 8;
    const PAGES_PER_UNIT: usize = (buffers::BUFFER_BYTES / PAGE_SIZE) as usize;

    let video = operation.video;
    let session = operation.session();
    let stream_units = (session.stream(StreamId::First).size.get() as i64
        / i64::from(buffers::BUFFER_BYTES)) as u32;
    let mut budget = readable(operation);
    if budget == 0 {
        return;
    }

    loop {
        if video.pending_units.load(Relaxed) == 0 {
            loop {
                let request = operation.request(Cursor::Tail);
                if ring_full(operation) {
                    return;
                }

                if video.read_state().contains(ReadState::END) {
                    end_marker(operation, request);
                    return;
                }

                let Some(record) = next_bound(operation) else {
                    video.set_read_state(video.read_state() | ReadState::END);
                    end_marker(operation, request);
                    return;
                };

                if record.kind == Some(StreamRecordKind::Frame)
                    && let Some(words) = record.frame()
                {
                    // SAFETY: only the operation's thread stores the
                    // context words, so the byte read races nothing.
                    let low = unsafe { low_byte(&video.read_state) };
                    video.read_state.store(
                        words[1].load(Relaxed) << 8 | u32::from(low.load(Relaxed)),
                        Relaxed,
                    );
                } else if let Some(words) = record.audio()
                    && video.flags().contains(VideoContextFlags::AUDIO)
                {
                    video.pending_units.store(1, Relaxed);
                    video
                        .pending_position
                        .store(words[audio_record::SEQUENCE].load(Relaxed), Relaxed);
                    request.set_kind(RequestKind::Audio);
                    request
                        .unit
                        .store(video.buffer_position.load(Relaxed) as u16, Relaxed);
                    copy_words(&request.record, words);
                    request.header.store(
                        (video.read_state.load(Relaxed) & ReadState::FRAME_MASK)
                            | (request.header.load(Relaxed) & 0xff),
                        Relaxed,
                    );
                    break;
                } else if let Some(words) = record.gpu_frame()
                    && video.flags().contains(VideoContextFlags::GPU)
                {
                    let word = words[gpu_record::HEADER].load(Relaxed);
                    request
                        .unit
                        .store(video.buffer_position.load(Relaxed) as u16, Relaxed);
                    copy_words(&request.record, words);

                    // SAFETY: only the operation's thread stores request
                    // headers, and nothing stores the records of completed
                    // reads, so the narrow reads race nothing.
                    let (low, command_units) = unsafe {
                        (
                            low_byte(&request.header),
                            low_half(&words[gpu_record::COMMANDS]),
                        )
                    };
                    request.header.store(
                        (word << 5 & 0xffff_ff00) | u32::from(low.load(Relaxed)),
                        Relaxed,
                    );

                    if word & fence_header::STATUS_MASK == 0 {
                        video
                            .pending_units
                            .store(u32::from(command_units.load(Relaxed)), Relaxed);
                        video
                            .pending_position
                            .store(words[gpu_record::SEQUENCE].load(Relaxed), Relaxed);
                        request.set_kind(RequestKind::Gpu);
                        break;
                    }

                    request.set_kind(RequestKind::NoData);
                    operation.advance(Cursor::Tail);
                    count(&video.statistics.dropped);
                }
            }
        }

        let mut remaining = budget.min(video.pending_units.load(Relaxed));

        while remaining != 0 {
            let request = operation.request(Cursor::Tail);
            let chunk = remaining
                .min(MAX_CHUNK_UNITS)
                .min(stream_units.wrapping_sub(video.pending_position.load(Relaxed) & 0x00ff_ffff));

            let mut segments = [0u32; MAX_CHUNK_UNITS as usize * PAGES_PER_UNIT + 1];
            // `chunk` is at most `MAX_CHUNK_UNITS`.
            for pages in
                segments[..chunk as usize * PAGES_PER_UNIT].chunks_exact_mut(PAGES_PER_UNIT)
            {
                let position = video.buffer_position.load(Relaxed);
                video.buffer_position.store(
                    wrap(position + 1, video.buffer_count.load(Relaxed)),
                    Relaxed,
                );
                let data = operation.buffer(position as usize);
                for (page, segment) in (0..).zip(pages) {
                    *segment = data + page * PAGE_SIZE;
                }
            }

            let io_status = if video.pending_units.load(Relaxed) == chunk {
                &request.status
            } else {
                &video.scatter_status
            };
            io_status.set_pending();
            let offset =
                u64::from(video.pending_position.load(Relaxed) & 0x00ff_ffff) << UNIT_SHIFT;
            // SAFETY: the status block lies in the ring or the context,
            // which outlive the read (`finish` cancels or waits for it);
            // `segments` and `offset` are read during the call.
            unsafe {
                xboxkrnl::NtReadFileScatter(
                    Handle::from_raw(buffers::stream_handle(session, StreamId::First)),
                    Handle::NULL,
                    0,
                    0,
                    io_status.as_ptr(),
                    segments.as_ptr(),
                    chunk << UNIT_SHIFT,
                    &offset,
                )
            };

            remaining -= chunk;
            budget -= chunk;

            let position = video.pending_position.load(Relaxed);
            let mut next = (position & 0xff00_0000) | (position.wrapping_add(chunk) & 0x00ff_ffff);
            if next & 0x00ff_ffff >= stream_units {
                next &= 0xff00_0000;
            }
            video.pending_position.store(next, Relaxed);
            video
                .pending_units
                .store(video.pending_units.load(Relaxed) - chunk, Relaxed);
            if video.pending_units.load(Relaxed) == 0 {
                operation.advance(Cursor::Tail);
            }
        }

        if budget == 0 {
            return;
        }
    }
}

/// Copy the words of a record into the words of a request.
#[inline(always)]
pub(super) fn copy_words(target: &[AtomicU32], source: &[AtomicU32]) {
    for (target, source) in target.iter().zip(source) {
        target.store(source.load(Relaxed), Relaxed);
    }
}

fn end_marker(operation: Operation<'_>, request: &VideoRequest) {
    request.set_kind(RequestKind::End);
    operation.advance(Cursor::Tail);
}
