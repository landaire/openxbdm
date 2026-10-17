//! Video operations (stock 0x91f59bc8 to 0x91f5c2b0): replay captured
//! frames from the dump partition through the title's frame record
//! routines (check, completion, vertical position, submit), play the
//! captured audio through a monitor XAudio client while paused, or write
//! frames and audio as movie data to a file.
//!
//! The state is the session's [`VideoContext`]; units are read ahead into
//! a ring of [`VideoRequest`]s.

mod movie;
mod read;
mod render;
mod replay;

use core::sync::atomic::AtomicU16;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use xbox360_sys::status::NtStatus;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::IoStatusBlock;

use self::movie::movie;
use self::read::copy_words;
use self::read::finish;
use self::read::initialize;
use self::replay::multiple;
use self::replay::single;
use super::super::session::AUDIO_BUFFER_SAMPLES;
use super::super::session::PixSession;
use super::buffers::BufferEntry;
use super::error::VideoError;
use super::low_byte;
use super::wrap;

pub(super) use self::render::render_entry_address;

/// Ticks of the title's vertical position routine per frame.
const POSITION_LIMIT: i32 = 0xbebc;
/// Samples of one XAudio render frame.
const BLOCK_SAMPLES: u32 = super::audio::BLOCK_SAMPLES as u32;
/// Samples of an audio capture buffer.
const BUFFER_SAMPLES: u32 = AUDIO_BUFFER_SAMPLES as u32;
/// Buffers the read-ahead slots take from the buffer table.
const READ_SLOTS: u32 = 3;
/// Performance counter ticks (counter / 1024) the audio runs ahead of
/// the GPU frames.
const AUDIO_LEAD: i32 = 0x82;
/// Largest gap between consecutive audio records that still plays as one
/// stream.
const AUDIO_GAP_LIMIT: i32 = 0xa28;

xbox360_sys::flags! {
    /// [`VideoContext::flags`]; the start frame is in bits 1 to 24 and the
    /// streams of the GPU and audio parts at the start frame in bits 27 and
    /// 28 and bits 25 and 26.
    pub struct VideoContextFlags(u32) {
        /// The frame record's completion routine is still to run.
        COMPLETION = 0x8000_0000,
        /// The operation replays GPU frames.
        GPU = 0x4000_0000,
        /// The operation plays audio.
        AUDIO = 0x2000_0000,
    }
}

impl VideoContextFlags {
    const FRAME_MASK: u32 = 0x01ff_fffe;
    /// Shifts from the stream bits of a frame record header.
    const GPU_STREAM_SHIFT: u32 = 20;
    const AUDIO_STREAM_SHIFT: u32 = 16;
    const STREAMS: u32 = frame_header::GPU_STREAM << Self::GPU_STREAM_SHIFT
        | frame_header::AUDIO_STREAM << Self::AUDIO_STREAM_SHIFT;

    const fn frame(self) -> u32 {
        self.0 >> 1 & 0x00ff_ffff
    }
}

xbox360_sys::flags! {
    /// Low byte of [`VideoContext::read_state`]; bits 8 to 31 hold the
    /// frame of the last frame record read.
    pub struct ReadState(u32) {
        /// The last GPU request ends the capture; the GPU consumer follows
        /// the audio requests.
        CONTINUED = 0x80,
        /// The frame range is read to its end.
        END = 0x40,
    }
}

impl ReadState {
    const FRAME_MASK: u32 = 0xffff_ff00;
}

xbox360_sys::flags! {
    /// [`ReadSlot::state`].
    pub struct SlotState(u32) {
        /// The slot holds a unit read from the table.
        FILLED = 0x8000_0000,
    }
}

/// Header of a frame record of the stream: the part streams in bits 3 to
/// 10.
mod frame_header {
    pub(super) const GPU_STREAM: u32 = 0x180;
    pub(super) const AUDIO_STREAM: u32 = 0x600;
}

/// Words of a GPU frame record (the fence slot it was written from); the
/// header is a [`fence_header`](super::gpu::fence_header).
mod gpu_record {
    pub(super) const HEADER: usize = 0;
    pub(super) const SEQUENCE: usize = 1;
    /// Byte offset in the first buffer (high half) and buffers (low half).
    pub(super) const COMMANDS: usize = 2;
    pub(super) const TIME: usize = 3;
    pub(super) const POSITION: usize = 4;
    pub(super) const WORDS: usize = 5;
}

/// Words of an audio record: the header holds the sample position in bits
/// 3 to 18 and the blocks the capture dropped from bit 19.
mod audio_record {
    pub(super) const HEADER: usize = 0;
    pub(super) const SEQUENCE: usize = 1;
    pub(super) const TIME: usize = 2;
    pub(super) const DROPPED_SHIFT: u32 = 19;

    pub(super) const fn position(header: u32) -> u32 {
        header >> 3 & 0xffff
    }
}

/// An I/O status block the kernel completes while the engine polls it.
#[repr(C)]
struct IoStatus {
    status: AtomicU32,
    information: AtomicU32,
}

impl IoStatus {
    fn is_pending(&self) -> bool {
        self.status.load(Relaxed) == NtStatus::PENDING.0
    }

    fn set_pending(&self) {
        self.status.store(NtStatus::PENDING.0, Relaxed);
    }

    fn as_ptr(&self) -> *mut IoStatusBlock {
        core::ptr::from_ref(self).cast_mut().cast()
    }
}

xbox360_sys::value_enum! {
    /// Kind of a [`VideoRequest`], bits 4 to 7 of its header.
    pub enum RequestKind: u32 {
        /// Not read yet, or none.
        Empty = 0,
        /// A GPU frame and its command data.
        Gpu = 1,
        /// A GPU frame captured without command data.
        NoData = 2,
        Audio = 3,
        /// The end of the frame range.
        End = 4,
    }
}

/// Request of the read-ahead ring (pool `PMOV`).
#[repr(C)]
struct VideoRequest {
    /// `frame << 8 | kind << 4 | flags`.
    header: AtomicU32,
    /// Buffer table index of the first unit.
    unit: AtomicU16,
    reserved_06: AtomicU16,
    /// Status of the read; [`NtStatus::PENDING`] until it completes.
    status: IoStatus,
    /// The stream record.
    record: [AtomicU32; gpu_record::WORDS],
}

impl VideoRequest {
    const KIND_SHIFT: u32 = 4;
    const KIND_MASK: u32 = 0xf0;

    /// Words of the status block and the record.
    const WORDS: usize = 2 + gpu_record::WORDS;

    const fn new() -> Self {
        // SAFETY: atomics are valid when zeroed.
        unsafe { core::mem::zeroed() }
    }

    fn kind(&self) -> Option<RequestKind> {
        RequestKind::from_raw((self.header.load(Relaxed) & Self::KIND_MASK) >> Self::KIND_SHIFT)
    }

    fn set_kind(&self, kind: RequestKind) {
        let header = self.header.load(Relaxed);
        self.header.store(
            (header & !Self::KIND_MASK) | kind.raw() << Self::KIND_SHIFT,
            Relaxed,
        );
    }

    fn frame(&self) -> u32 {
        self.header.load(Relaxed) >> 8
    }

    fn unit(&self) -> usize {
        usize::from(self.unit.load(Relaxed))
    }

    fn record_word(&self, index: usize) -> u32 {
        self.record[index].load(Relaxed)
    }

    /// The commands word of a GPU record as halfwords, read alone as
    /// stock reads them: the byte offset in the first buffer, then the
    /// buffers.
    fn command_halves(&self) -> &[AtomicU16; 2] {
        let word = &self.record[gpu_record::COMMANDS];

        // SAFETY: the halfwords lie in the word, which is 4-aligned. Only
        // the operation's thread stores and reads requests, so halfword
        // and word accesses never race.
        unsafe { &*(&raw const *word).cast::<[AtomicU16; 2]>() }
    }

    /// The status block and the record as one run of words.
    fn words(&self) -> &[AtomicU32; Self::WORDS] {
        let address = core::ptr::from_ref(self)
            .cast::<u8>()
            .wrapping_add(core::mem::offset_of!(Self, status));

        // SAFETY: the status block and the record are adjacent words that
        // end the request (asserted below).
        unsafe { &*address.cast() }
    }

    fn copy_from(&self, source: &Self) {
        self.header.store(source.header.load(Relaxed), Relaxed);
        self.unit.store(source.unit.load(Relaxed), Relaxed);
        self.reserved_06
            .store(source.reserved_06.load(Relaxed), Relaxed);
        copy_words(self.words(), source.words());
    }
}

/// Read-ahead slot of frame table units.
#[repr(C)]
struct ReadSlot {
    /// [`SlotState`].
    state: AtomicU32,
    /// Capture buffer the unit is read into.
    data: AtomicU32,
    status: IoStatus,
}

impl ReadSlot {
    fn state(&self) -> SlotState {
        SlotState::from_bits_retain(self.state.load(Relaxed))
    }

    fn set_state(&self, state: SlotState) {
        self.state.store(state.bits(), Relaxed);
    }
}

/// Counters of the statistics debug print.
#[repr(C)]
struct Statistics {
    /// GPU frames submitted.
    frames: AtomicU32,
    /// Audio frames submitted.
    audio_frames: AtomicU32,
    /// GPU frames due before their next request was read.
    misses: AtomicU32,
    /// Reported; no path counts it.
    audio_misses: AtomicU32,
    /// GPU frames captured without command data.
    dropped: AtomicU32,
    /// Audio blocks the capture dropped, played as repeats.
    audio_dropped: AtomicU32,
    /// Waits for a read-ahead unit.
    overruns: AtomicU32,
    /// GPU replays restarted at a late or unread frame.
    restarts: AtomicU32,
    /// Audio replays restarted after an underrun.
    audio_restarts: AtomicU32,
}

impl Statistics {
    fn clear(&self) {
        // SAFETY: `Statistics` is `repr(C)` and holds only `AtomicU32`s.
        let words: &[AtomicU32; size_of::<Self>() / 4] =
            unsafe { &*core::ptr::from_ref(self).cast() };

        for word in words {
            word.store(0, Relaxed);
        }
    }
}

/// State of a video operation, at session `+0xc83c`.
#[repr(C)]
pub(in super::super) struct VideoContext {
    /// Address of the session.
    pub(in super::super) session: AtomicU32,
    /// [`VideoContextFlags`].
    pub(in super::super) flags: AtomicU32,
    /// End frame in bits 8 to 31.
    end: AtomicU32,
    /// Frame range of the reports, in bits 8 to 31.
    report_start: AtomicU32,
    report_end: AtomicU32,
    /// Movie data file handle, and whether a write to it failed.
    file: AtomicU32,
    write_failed: AtomicU32,
    /// Frame to restart at; [`Self::NO_RESTART`] for none.
    restart: AtomicU32,
    statistics: Statistics,
    /// Thread writes of the session at the pause.
    pub(in super::super) writes_at_pause: AtomicU32,
    /// Argument of the operation's message, reported in the status.
    argument: AtomicU32,
    /// Record time and performance counter at the start of the replay
    /// clock.
    clock_record: AtomicU32,
    clock_start: AtomicU32,
    /// Next frame table entry to read ahead.
    table_position: AtomicU32,
    /// Next record, last record returned, and end of the records of the
    /// read-ahead buffer.
    record_cursor: AtomicU32,
    current_record: AtomicU32,
    record_end: AtomicU32,
    slots: [ReadSlot; READ_SLOTS as usize],
    /// Next slot to read records from and next slot to fill.
    read_slot: AtomicU32,
    fill_slot: AtomicU32,
    /// Request ring: address, next request to fill, entries, and the next
    /// request of the GPU and audio consumers.
    ring: AtomicU32,
    ring_tail: AtomicU32,
    ring_count: AtomicU32,
    gpu_index: AtomicU32,
    audio_index: AtomicU32,
    /// Frame the status reports.
    frame: AtomicU32,
    /// Units of the record being read, and the partition unit (generation
    /// in bits 24 to 31) of the next.
    pending_units: AtomicU32,
    pending_position: AtomicU32,
    pending_spare: AtomicU32,
    /// [`ReadState`].
    read_state: AtomicU32,
    /// Buffer table entries after the slots' buffers, their count, and the
    /// next one to read into.
    buffers: AtomicU32,
    buffer_position: AtomicU32,
    buffer_count: AtomicU32,
    /// Buffers the GPU and audio consumers hold; reads stop short of them.
    gpu_buffer: AtomicU32,
    audio_buffer: AtomicU32,
    _reserved_0d8: [AtomicU32; 5],
    /// Status of reads that end before their request does.
    scatter_status: IoStatus,
}

impl VideoContext {
    const NO_RESTART: u32 = u32::MAX;

    fn flags(&self) -> VideoContextFlags {
        VideoContextFlags::from_bits_retain(self.flags.load(Relaxed))
    }

    fn set_flags(&self, flags: VideoContextFlags) {
        self.flags.store(flags.bits(), Relaxed);
    }

    fn read_state(&self) -> ReadState {
        ReadState::from_bits_retain(self.read_state.load(Relaxed))
    }

    fn set_read_state(&self, state: ReadState) {
        self.read_state.store(state.bits(), Relaxed);
    }

    fn restart(&self) -> Option<u32> {
        let frame = self.restart.load(Relaxed);
        (frame != Self::NO_RESTART).then_some(frame)
    }

    /// Read-ahead slot `index`.
    ///
    /// # Safety
    ///
    /// `index` must be below [`READ_SLOTS`].
    unsafe fn slot(&self, index: u32) -> &ReadSlot {
        // SAFETY: guaranteed by the caller.
        unsafe { self.slots.get_unchecked(index as usize) }
    }
}

xbox360_sys::value_enum! {
    /// [`RenderClient::state`].
    pub enum ClientState: u32 {
        Idle = 0,
        Starting = 1,
        Playing = 2,
        StopRequested = 3,
        Underrun = 4,
    }
}

/// The XAudio render client of the pause, at session `+0xc930`.
#[repr(C)]
pub(in super::super) struct RenderClient {
    /// [`ClientState`].
    pub(in super::super) state: AtomicU32,
    /// Addresses of the session and of its video context.
    pub(in super::super) session: AtomicU32,
    pub(in super::super) video: AtomicU32,
    /// Sample position in the audio buffer, and the buffer.
    position: AtomicU32,
    data: AtomicU32,
    /// Audio request being played.
    current: VideoRequest,
    /// Float samples of the render frame.
    output: [AtomicU32; BLOCK_SAMPLES as usize],
}

impl RenderClient {
    fn set_state(&self, state: ClientState) {
        self.state.store(state.raw(), Relaxed);
    }

    /// A state change the render thread sees in order.
    fn publish_state(&self, state: ClientState) {
        super::sync();
        self.set_state(state);
        super::sync();
    }
}

/// A running operation: its video context. While an operation
/// exists, the context's ring and buffer words address `ring_count`
/// allocated requests and the last `buffer_count` entries of the session's
/// buffer table (only `initialize` and `release` store them). From the
/// first [`begin`](replay::begin), which every operation runs before it touches the ring
/// cursors or read-ahead slots, the cursors are below `ring_count` and the
/// read and fill slots below [`READ_SLOTS`] (`begin` stores 0, the rest
/// the next index wrapped at the count).
#[derive(Clone, Copy)]
struct Operation<'a> {
    video: &'a VideoContext,
}

impl<'a> Operation<'a> {
    /// The session of the context.
    fn session(self) -> &'a PixSession {
        // SAFETY: the context's session word holds the address of the
        // session block that contains it (stored when the block is set
        // up), which outlives the context.
        unsafe { crate::kernel::object_at(self.video.session.load(Relaxed)) }
    }

    fn ring(self) -> &'a [VideoRequest] {
        let video = self.video;

        // SAFETY: the invariant of `Operation`.
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::with_exposed_provenance(video.ring.load(Relaxed) as usize),
                video.ring_count.load(Relaxed) as usize,
            )
        }
    }

    fn cursor(self, cursor: Cursor) -> &'a AtomicU32 {
        let video = self.video;

        match cursor {
            Cursor::Tail => &video.ring_tail,
            Cursor::Gpu => &video.gpu_index,
            Cursor::Audio => &video.audio_index,
        }
    }

    /// Request `index` of the ring.
    ///
    /// # Safety
    ///
    /// `index` must be below `ring_count`.
    unsafe fn request_at(self, index: u32) -> &'a VideoRequest {
        let address = self.video.ring.load(Relaxed) + index * size_of::<VideoRequest>() as u32;

        // SAFETY: the request lies in the ring (the invariant of
        // `Operation`; guaranteed by the caller).
        unsafe { crate::kernel::object_at(address) }
    }

    /// The request at `cursor`.
    fn request(self, cursor: Cursor) -> &'a VideoRequest {
        // SAFETY: cursors are below `ring_count` (the invariant of
        // `Operation`).
        unsafe { self.request_at(self.cursor(cursor).load(Relaxed)) }
    }

    fn next_index(self, index: u32) -> u32 {
        wrap(index + 1, self.video.ring_count.load(Relaxed))
    }

    /// Move `cursor` to the next request.
    fn advance(self, cursor: Cursor) {
        let cursor = self.cursor(cursor);
        cursor.store(self.next_index(cursor.load(Relaxed)), Relaxed);
    }

    /// Data of replay buffer `index`; 0 for an index out of range (an end
    /// request has no unit; stock reads an unrelated word there).
    fn buffer(self, index: usize) -> u32 {
        let video = self.video;

        // SAFETY: the invariant of `Operation`.
        let buffers: &[BufferEntry] = unsafe {
            core::slice::from_raw_parts(
                core::ptr::with_exposed_provenance(video.buffers.load(Relaxed) as usize),
                video.buffer_count.load(Relaxed) as usize,
            )
        };

        if index < buffers.len() {
            buffers[index].data()
        } else {
            0
        }
    }

    fn routine_argument(self) -> u32 {
        self.session().frame_record.routine_argument.load(Relaxed)
    }
}

/// A position in the request ring.
#[derive(Clone, Copy)]
enum Cursor {
    /// Next request to fill.
    Tail,
    /// Next request of the GPU consumer.
    Gpu,
    /// Next request of the audio consumer.
    Audio,
}

const _: () = {
    use core::mem::offset_of;
    assert!(size_of::<IoStatus>() == size_of::<IoStatusBlock>());
    assert!(size_of::<VideoRequest>() == 0x24);
    assert!(offset_of!(VideoRequest, unit) == 4);
    assert!(offset_of!(VideoRequest, status) == 8);
    assert!(offset_of!(VideoRequest, record) == 0x10);
    assert!(
        offset_of!(VideoRequest, status) + VideoRequest::WORDS * 4 == size_of::<VideoRequest>()
    );
    assert!(size_of::<ReadSlot>() == 0x10);
    assert!(offset_of!(VideoContext, end) == 8);
    assert!(offset_of!(VideoContext, report_start) == 0xc);
    assert!(offset_of!(VideoContext, report_end) == 0x10);
    assert!(offset_of!(VideoContext, file) == 0x14);
    assert!(offset_of!(VideoContext, write_failed) == 0x18);
    assert!(offset_of!(VideoContext, restart) == 0x1c);
    assert!(offset_of!(VideoContext, statistics) == 0x20);
    assert!(offset_of!(VideoContext, writes_at_pause) == 0x44);
    assert!(offset_of!(VideoContext, argument) == 0x48);
    assert!(offset_of!(VideoContext, clock_record) == 0x4c);
    assert!(offset_of!(VideoContext, clock_start) == 0x50);
    assert!(offset_of!(VideoContext, table_position) == 0x54);
    assert!(offset_of!(VideoContext, record_cursor) == 0x58);
    assert!(offset_of!(VideoContext, current_record) == 0x5c);
    assert!(offset_of!(VideoContext, record_end) == 0x60);
    assert!(offset_of!(VideoContext, slots) == 0x64);
    assert!(offset_of!(VideoContext, read_slot) == 0x94);
    assert!(offset_of!(VideoContext, fill_slot) == 0x98);
    assert!(offset_of!(VideoContext, ring) == 0x9c);
    assert!(offset_of!(VideoContext, ring_tail) == 0xa0);
    assert!(offset_of!(VideoContext, ring_count) == 0xa4);
    assert!(offset_of!(VideoContext, gpu_index) == 0xa8);
    assert!(offset_of!(VideoContext, audio_index) == 0xac);
    assert!(offset_of!(VideoContext, frame) == 0xb0);
    assert!(offset_of!(VideoContext, pending_units) == 0xb4);
    assert!(offset_of!(VideoContext, pending_position) == 0xb8);
    assert!(offset_of!(VideoContext, pending_spare) == 0xbc);
    assert!(offset_of!(VideoContext, read_state) == 0xc0);
    assert!(offset_of!(VideoContext, buffers) == 0xc4);
    assert!(offset_of!(VideoContext, buffer_position) == 0xc8);
    assert!(offset_of!(VideoContext, buffer_count) == 0xcc);
    assert!(offset_of!(VideoContext, gpu_buffer) == 0xd0);
    assert!(offset_of!(VideoContext, audio_buffer) == 0xd4);
    assert!(offset_of!(VideoContext, scatter_status) == 0xec);
    assert!(size_of::<VideoContext>() == 0xf4);
    assert!(offset_of!(RenderClient, position) == 0xc);
    assert!(offset_of!(RenderClient, data) == 0x10);
    assert!(offset_of!(RenderClient, current) == 0x14);
    assert!(offset_of!(RenderClient, output) == 0x38);
    assert!(size_of::<RenderClient>() == 0x1838);
};

/// Context for frames `first` (frames back) and `count` frames.
fn setup(operation: Operation<'_>, first: u32, count: u32) {
    let video = operation.video;
    let mask = VideoContextFlags::FRAME_MASK;
    let start = (operation.session().frame_index() << 1).wrapping_sub(first << 1);
    let flags = (start & mask) | (video.flags().bits() & !mask);

    video.flags.store(flags, Relaxed);
    video.frame.store((flags & mask) >> 1, Relaxed);

    let end = ((flags & !1).wrapping_add(count << 1) & mask) << 7;
    // SAFETY: only the operation's thread stores the context words.
    let low = unsafe { low_byte(&video.end) };
    video.end.store(end | u32::from(low.load(Relaxed)), Relaxed);
}

/// Free the request ring of the operation.
///
/// # Safety
///
/// No copy of `operation` may be used afterwards.
#[inline(always)]
unsafe fn release(operation: Operation<'_>) {
    let ring = &operation.video.ring;

    // SAFETY: the request ring `initialize` allocated; no view of it
    // remains (guaranteed by the caller), and its word is cleared below.
    unsafe { xboxkrnl::ExFreePool(ring.load(Relaxed)) };
    ring.store(0, Relaxed);
}

/// Message 12: replay frames (stock 0x91f5c0e8).
pub(super) fn run(
    session: &PixSession,
    first: u32,
    count: u32,
    argument: u32,
) -> Result<(), VideoError> {
    let operation = initialize(session, &session.video).ok_or(VideoError::NoBuffers)?;
    let video = operation.video;

    // SAFETY: only the operation's thread stores the context words.
    let (start_low, end_low) =
        unsafe { (low_byte(&video.report_start), low_byte(&video.report_end)) };
    let start_byte = u32::from(start_low.load(Relaxed));
    let end_byte = u32::from(end_low.load(Relaxed));

    video.argument.store(argument, Relaxed);
    setup(operation, first, count);

    video.report_start.store(
        (video.flags().bits() & VideoContextFlags::FRAME_MASK) << 7 | start_byte,
        Relaxed,
    );
    video
        .report_end
        .store(end_byte | (video.end.load(Relaxed) & 0xffff_ff00), Relaxed);

    let result = if count == 1 {
        single(operation)
    } else {
        multiple(operation)
    };

    finish(operation);
    // SAFETY: the operation ends here.
    unsafe { release(operation) };

    result
}

/// Message 14 while paused: frames as movie data to `file` (stock
/// 0x91f5c1d8).
pub(super) fn write(
    session: &PixSession,
    file: u32,
    no_gpu: u32,
    first: u32,
    count: u32,
) -> Result<(), VideoError> {
    let operation = initialize(session, &session.video).ok_or(VideoError::NoBuffers)?;
    let video = operation.video;

    video.file.store(file, Relaxed);
    video.write_failed.store(0, Relaxed);
    setup(operation, first, count);

    let result = movie(operation, no_gpu != 0);

    finish(operation);
    // SAFETY: the operation ends here.
    unsafe { release(operation) };

    if result.is_ok() && video.write_failed.load(Relaxed) != 0 {
        return Err(VideoError::WriteFailed);
    }

    result
}
