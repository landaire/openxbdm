//! Video operations (stock 0x91f59bc8 to 0x91f5c2b0): replay captured
//! frames from the dump partition through the title's frame record
//! routines (check, completion, vertical position, submit), play the
//! captured audio through a monitor XAudio client while paused, or write
//! frames and audio as movie data to a file.
//!
//! The state is the session's [`VideoContext`]; units are read ahead into
//! a ring of [`VideoRequest`]s.

use core::sync::atomic::AtomicU16;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_server::commands::memory::PAGE_SIZE;
use xbox360::module::ExportAddress;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::time::TickCount;
use xbox360_sys::status::NtStatus;
use xbox360_sys::xam;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::XAudioSubmitRenderDriverFrame;

use super::super::files::RecordType;
use super::super::session::AUDIO_BUFFER_SAMPLES;
use super::super::session::EngineFlags;
use super::super::session::FrameRecordFlags;
use super::super::session::PixSession;
use super::super::session::StreamId;
use super::super::session::TABLE_ENTRIES;
use super::buffers;
use super::buffers::BufferEntry;
use super::buffers::UNIT_SHIFT;
use super::cached;
use super::gpu::StreamRecordKind;
use super::gpu::fence_header;
use super::low_byte;
use super::low_half;
use super::sign24;
use super::wrap;
use crate::kernel;

const POOL_TAG: PoolTag = PoolTag::new(*b"PMOV");
/// Ticks of the title's vertical position routine per frame.
const POSITION_LIMIT: i32 = 0xbebc;
/// Samples of one XAudio render frame.
const BLOCK_SAMPLES: u32 = super::audio::BLOCK_SAMPLES as u32;
/// Samples of an audio capture buffer.
const BUFFER_SAMPLES: u32 = AUDIO_BUFFER_SAMPLES as u32;
/// Buffers the read-ahead slots take from the buffer table.
const READ_SLOTS: u32 = 3;
/// Fewest entries of the request ring.
const MINIMUM_REQUESTS: u32 = 1000;
/// Smallest capture the operations replay.
const MINIMUM_CAPTURE_BYTES: u32 = 0x8_0000;
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
/// header is a [`fence_header`].
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

/// Why a video operation ended early. The discriminants of the variants
/// without a field are their error numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum VideoError {
    /// The title's check routine returned `result`.
    Check { result: u32 } = 0,
    /// The title's submit routine returned `result`.
    Submit { result: u32 } = 1,
    /// The frame was captured without command data; the record's refusal
    /// status.
    Refused { status: u32 } = 2,
    /// The capture is too small for the read-ahead, or the request ring
    /// could not be allocated.
    NoBuffers = 3,
    /// No frame record at the start frame, or no part to replay.
    NothingToReplay = 4,
    /// The frame's command data holds no movie image.
    NoImage = 6,
    /// A movie data write failed.
    WriteFailed = 8,
}

impl VideoError {
    /// The error number of the `VideoOpError` status.
    pub(super) fn code(self) -> u32 {
        match self {
            Self::NoBuffers => 3,
            Self::NothingToReplay => 4,
            Self::NoImage => 6,
            Self::WriteFailed => 8,
            Self::Check { result } | Self::Submit { result } => result,
            Self::Refused { status } => status,
        }
    }
}

/// A running operation: its video context. While an operation
/// exists, the context's ring and buffer words address `ring_count`
/// allocated requests and the last `buffer_count` entries of the session's
/// buffer table (only `initialize` and `release` store them). From the
/// first [`begin`], which every operation runs before it touches the ring
/// cursors or read-ahead slots, the cursors are below `ring_count` and the
/// read and fill slots below [`READ_SLOTS`] (`begin` stores 0, the rest
/// the next index wrapped at the count).
#[derive(Clone, Copy)]
struct Operation<'a> {
    video: &'a VideoContext,
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

impl<'a> Operation<'a> {
    /// The session of the context.
    fn s(self) -> &'a PixSession {
        // SAFETY: the context's session word holds the address of the
        // session block that contains it (stored when the block is set
        // up), which outlives the context.
        unsafe { crate::kernel::object_at(self.video.session.load(Relaxed)) }
    }

    fn ring(self) -> &'a [VideoRequest] {
        let v = self.video;
        // SAFETY: the invariant of `Operation`.
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::with_exposed_provenance(v.ring.load(Relaxed) as usize),
                v.ring_count.load(Relaxed) as usize,
            )
        }
    }

    fn cursor(self, cursor: Cursor) -> &'a AtomicU32 {
        let v = self.video;
        match cursor {
            Cursor::Tail => &v.ring_tail,
            Cursor::Gpu => &v.gpu_index,
            Cursor::Audio => &v.audio_index,
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
        let v = self.video;
        // SAFETY: the invariant of `Operation`.
        let buffers: &[BufferEntry] = unsafe {
            core::slice::from_raw_parts(
                core::ptr::with_exposed_provenance(v.buffers.load(Relaxed) as usize),
                v.buffer_count.load(Relaxed) as usize,
            )
        };
        if index < buffers.len() {
            buffers[index].data()
        } else {
            0
        }
    }

    fn routine_argument(self) -> u32 {
        self.s().frame_record.routine_argument.load(Relaxed)
    }
}

fn count(counter: &AtomicU32) {
    counter.store(counter.load(Relaxed).wrapping_add(1), Relaxed);
}

/// Mark `out` empty, or ended with the end flag of the context (stock
/// 0x91f59c38 tail).
fn empty(op: Operation<'_>, out: &VideoRequest) {
    out.set_kind(if op.video.read_state().contains(ReadState::END) {
        RequestKind::End
    } else {
        RequestKind::Empty
    });
}

/// Busy-wait for every outstanding read (stock 0x91f59bc8).
fn wait_requests(op: Operation<'_>) {
    for request in op.ring() {
        if matches!(request.kind(), Some(RequestKind::Gpu | RequestKind::Audio)) {
            while request.status.is_pending() {}
        }
    }
}

/// With [`ReadState::CONTINUED`], the GPU consumer follows the audio
/// requests until the next GPU request.
#[inline(always)]
fn follow(op: Operation<'_>, request: &VideoRequest) {
    let v = op.video;
    let state = v.read_state();
    if state.contains(ReadState::CONTINUED) {
        match request.kind() {
            Some(RequestKind::Audio) => v.gpu_buffer.store(request.unit() as u32, Relaxed),
            Some(RequestKind::Gpu) => v.set_read_state(state.difference(ReadState::CONTINUED)),
            _ => {}
        }
    }
}

/// Next GPU request into `out` (stock 0x91f59c38); `following` keeps
/// requests that end the capture.
fn next_request(op: Operation<'_>, following: bool, out: &VideoRequest) {
    let v = op.video;
    while v.gpu_index.load(Relaxed) != v.ring_tail.load(Relaxed) {
        let request = op.request(Cursor::Gpu);
        follow(op, request);
        match request.kind() {
            Some(RequestKind::Audio) => {}
            Some(RequestKind::Gpu)
                if request.record_word(gpu_record::HEADER) & fence_header::LAST != 0
                    && !following => {}
            Some(RequestKind::Gpu) => {
                if request.status.is_pending() {
                    if !v.flags().contains(VideoContextFlags::AUDIO) {
                        v.restart.store(request.frame(), Relaxed);
                        count(&v.statistics.restarts);
                    }
                    out.set_kind(RequestKind::Empty);
                    return;
                }
                if !v.flags().contains(VideoContextFlags::AUDIO) {
                    v.frame.store(request.frame(), Relaxed);
                }
                out.copy_from(request);
                op.advance(Cursor::Gpu);
                return;
            }
            _ => {
                out.copy_from(request);
                op.advance(Cursor::Gpu);
                return;
            }
        }
        op.advance(Cursor::Gpu);
    }
    empty(op, out);
}

/// Next audio request into `out` (stock 0x91f59dd8).
fn next_audio(op: Operation<'_>, out: &VideoRequest) {
    let v = op.video;
    while v.audio_index.load(Relaxed) != v.ring_tail.load(Relaxed) {
        let request = op.request(Cursor::Audio);
        v.audio_buffer.store(request.unit() as u32, Relaxed);
        match request.kind() {
            Some(RequestKind::Gpu | RequestKind::NoData) => {
                op.advance(Cursor::Audio);
                continue;
            }
            Some(RequestKind::Audio) if request.status.is_pending() => {
                out.set_kind(RequestKind::Empty);
                return;
            }
            _ => {}
        }
        v.frame.store(request.frame(), Relaxed);
        out.copy_from(request);
        op.advance(Cursor::Audio);
        return;
    }
    empty(op, out);
}

/// Next request of either kind for movie data (stock 0x91f59f00).
fn current_request(op: Operation<'_>, out: &VideoRequest) {
    let v = op.video;
    let index = v.gpu_index.load(Relaxed);
    if index == v.ring_tail.load(Relaxed) {
        out.set_kind(RequestKind::End);
        return;
    }
    // SAFETY: `index` is the GPU cursor.
    let request = unsafe { op.request_at(index) };
    follow(op, request);
    if request.status.is_pending() {
        out.set_kind(RequestKind::Empty);
        return;
    }
    out.copy_from(request);
    let next = op.next_index(index);
    v.gpu_index.store(next, Relaxed);
    v.audio_index.store(next, Relaxed);
}

/// Note a consumed GPU request (stock 0x91f5a000).
fn note_request(op: Operation<'_>, request: &VideoRequest) {
    let v = op.video;
    if request.record_word(gpu_record::HEADER) & fence_header::LAST != 0 {
        v.set_read_state(v.read_state() | ReadState::CONTINUED);
    } else {
        v.set_read_state(v.read_state().difference(ReadState::CONTINUED));
        v.gpu_buffer.store(request.unit() as u32, Relaxed);
    }
}

/// Set up the read-ahead buffers and the request ring of context `v` of
/// `s` (stock 0x91f5a058).
fn initialize<'a>(s: &'a PixSession, v: &'a VideoContext) -> Option<Operation<'a>> {
    let count = s.buffer_count.load(Relaxed);
    if count << UNIT_SHIFT < MINIMUM_CAPTURE_BYTES || (count.wrapping_sub(READ_SLOTS) as i32) <= 0 {
        return None;
    }
    let table = s.buffer_table.load(Relaxed);
    // SAFETY: the session's buffer table has `buffer_count` entries, more
    // than `READ_SLOTS` (checked above), while the session captures; the
    // operation runs under the session lock.
    let slot_entries: &[BufferEntry; READ_SLOTS as usize] =
        unsafe { crate::kernel::object_at(table) };
    for (slot, entry) in v.slots.iter().zip(slot_entries) {
        slot.data.store(entry.data(), Relaxed);
    }
    let buffers = table + size_of_val(slot_entries) as u32;
    v.buffers.store(buffers, Relaxed);
    let buffer_count = count - READ_SLOTS;
    v.buffer_count.store(buffer_count, Relaxed);
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
    v.ring.store(ring, Relaxed);
    v.ring_count.store(requests, Relaxed);
    v.statistics.clear();
    Some(Operation { video: v })
}

/// Kernel export that cancels the I/O of a file handle.
const CANCEL_IO_ROUTINE: Ordinal = Ordinal::new(0x2b8).unwrap();

/// End the reads: kernel export 0x2b8 cancels the partition handle's
/// I/O, else wait for them (stock 0x91f5a138).
fn finish(op: Operation<'_>) {
    let routine = SystemModule::Kernel
        .handle()
        .and_then(|kernel| resolve_export(kernel, CANCEL_IO_ROUTINE))
        .map_or(0, ExportAddress::raw);
    if routine != 0 {
        let handle = buffers::stream_handle(op.s(), StreamId::First);
        // SAFETY: kernel export 0x2b8 takes one argument, a file handle.
        unsafe { kernel::call_export(routine, handle, 0, 0, 0) };
    } else {
        wait_requests(op);
    }
}

/// Read the next frame table unit into the next read-ahead slot (stock
/// 0x91f5a1a0).
fn prefetch(op: Operation<'_>) {
    let v = op.video;
    let s = op.s();
    let stream = s.stream(StreamId::First);
    let slot_index = v.fill_slot.load(Relaxed);
    let index = v.table_position.load(Relaxed);
    // SAFETY: the fill slot is below `READ_SLOTS` (the invariant of
    // `Operation`).
    let slot = unsafe { v.slot(slot_index) };
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
                Handle::from_raw(buffers::stream_handle(s, StreamId::First)),
                Handle::NULL,
                0,
                0,
                slot.status.as_ptr(),
                core::ptr::with_exposed_provenance_mut(slot.data.load(Relaxed) as usize),
                buffers::BUFFER_BYTES,
                &offset,
            )
        };
        v.table_position
            .store(wrap(index + 1, TABLE_ENTRIES as u32), Relaxed);
    }
    v.fill_slot.store(wrap(slot_index + 1, READ_SLOTS), Relaxed);
}

/// Start reading ahead at table position `index` (stock 0x91f5a298).
fn start_prefetch(op: Operation<'_>, index: u32) {
    let v = op.video;
    v.table_position.store(index, Relaxed);
    prefetch(op);
    prefetch(op);
    for slot in &v.slots[..2] {
        while slot.status.is_pending() {}
    }
    v.record_cursor.store(0, Relaxed);
    v.record_end.store(0, Relaxed);
}

/// Whether sequence `sequence` of stream 0 was overwritten (stock
/// 0x91f5a310).
fn overwritten(s: &PixSession, sequence: u32) -> bool {
    super::overwritten(sequence, s.stream(StreamId::First).sequence.load(Relaxed))
}

/// Buffers that may be read ahead (stock 0x91f5a358).
fn readable(op: Operation<'_>) -> u32 {
    let v = op.video;
    let flags = v.flags();
    let distance = |position: &AtomicU32| {
        let mut distance = position
            .load(Relaxed)
            .wrapping_sub(v.buffer_position.load(Relaxed)) as i32;
        if distance <= 0 {
            distance += v.buffer_count.load(Relaxed) as i32;
        }
        distance
    };
    let gpu = if flags.contains(VideoContextFlags::GPU) {
        distance(&v.gpu_buffer)
    } else {
        i32::MAX
    };
    let audio = if flags.contains(VideoContextFlags::AUDIO) {
        distance(&v.audio_buffer)
    } else {
        i32::MAX
    };
    let least = gpu.min(audio);
    (if least > 0 { least - 1 } else { least }) as u32
}

/// Whether the request ring is full (stock 0x91f5a3c8).
fn ring_full(op: Operation<'_>) -> bool {
    let v = op.video;
    let next = op.next_index(v.ring_tail.load(Relaxed));
    (v.flags().contains(VideoContextFlags::GPU) && next == v.gpu_index.load(Relaxed))
        || (v.flags().contains(VideoContextFlags::AUDIO) && next == v.audio_index.load(Relaxed))
}

/// The title's check routine (stock 0x91f5a420); 0 lets it run once
/// more at the end.
fn check(op: Operation<'_>) -> u32 {
    let routine = op.s().frame_record.check_routine.load(Relaxed);
    // SAFETY: the title's frame record routine takes one argument.
    let result = unsafe { kernel::call_export(routine, op.routine_argument(), 0, 0, 0) };
    if result == 0 {
        op.video
            .set_flags(op.video.flags() | VideoContextFlags::COMPLETION);
    }
    result
}

/// Entries of a command list; stock overruns it for more than
/// [`MAX_COMMAND_BUFFERS`].
const COMMAND_LIST_ENTRIES: usize = 0xca;
const MAX_COMMAND_BUFFERS: u32 = 0xc8;
/// Words the title's submit routine may store.
const SUBMIT_EXTRA_WORDS: usize = 0x40;
/// Last argument of the title's submit routine.
const SUBMIT_MODE: u32 = 0x618;

type CommandList = [u32; COMMAND_LIST_ENTRIES];

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
fn command_list(
    op: Operation<'_>,
    first: &VideoRequest,
    next: &VideoRequest,
    list: &mut CommandList,
) -> Commands {
    let [offset, units] = first.command_halves();
    let count = u32::from(units.load(Relaxed)).min(MAX_COMMAND_BUFFERS);
    let mut index = first.unit() as u32;
    for slot in list.iter_mut().take(count as usize) {
        *slot = op.buffer(index as usize);
        index = wrap(index + 1, op.video.buffer_count.load(Relaxed));
    }
    list[count as usize] = op.buffer(next.unit());
    let offset = u32::from(offset.load(Relaxed));
    if offset == buffers::BUFFER_BYTES {
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

/// Submit one captured frame to the title (stock 0x91f5a4e0).
fn replay_frame(
    op: Operation<'_>,
    first: &VideoRequest,
    next: &VideoRequest,
    extra: &mut [u32; SUBMIT_EXTRA_WORDS],
) -> Result<(), VideoError> {
    let mut list = [0u32; COMMAND_LIST_ENTRIES];
    let commands = command_list(op, first, next, &mut list);
    // SAFETY: the title's submit routine takes seven arguments `(argument,
    // 0, buffers, count, offset, extra, mode)`.
    let result = unsafe {
        kernel::call_console(
            op.s().frame_record.submit_routine.load(Relaxed),
            op.routine_argument(),
            0,
            list[commands.start..].as_ptr() as usize as u32,
            commands.count as u32,
            commands.offset,
            extra.as_mut_ptr() as usize as u32,
            SUBMIT_MODE,
        )
    };
    if result != 0 {
        return Err(VideoError::Submit { result });
    }
    count(&op.video.statistics.frames);
    Ok(())
}

/// Tell the title the replay ended (submit routine with 1).
fn end_submissions(op: Operation<'_>) {
    // SAFETY: as in `replay_frame`.
    unsafe {
        kernel::call_console(
            op.s().frame_record.submit_routine.load(Relaxed),
            op.routine_argument(),
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
fn report(op: Operation<'_>, start: u32) {
    let v = op.video;
    let statistics = &v.statistics;
    if v.flags().contains(VideoContextFlags::GPU) {
        let frames = statistics.frames.load(Relaxed);
        let elapsed = TickCount::now()
            .milliseconds()
            .wrapping_sub(start)
            .wrapping_add(1);
        let range =
            (v.report_end.load(Relaxed) >> 8).wrapping_sub(v.report_start.load(Relaxed) >> 8);
        // Stock traps on an empty range.
        let percent = (frames.wrapping_mul(100)).checked_div(range).unwrap_or(0);
        let rate = (frames as f32 * 1000.0) / elapsed as f32;
        let values = [
            u64::from(frames),
            u64::from(percent),
            f64::from(rate).to_bits(),
            u64::from(statistics.dropped.load(Relaxed)),
            u64::from(statistics.restarts.load(Relaxed)),
            u64::from(statistics.misses.load(Relaxed)),
            u64::from(statistics.overruns.load(Relaxed)),
        ];
        // SAFETY: the format consumes the seven arguments.
        unsafe {
            super::super::super::pmc::debug_print(
                c"Video: %i (%i%%) frames, %.2f fps, %i record-time drops, %i restarts, %i misses, %i index overruns\n".as_ptr().cast(),
                &values,
            )
        };
    }
    if v.flags().contains(VideoContextFlags::AUDIO) {
        let values = [
            u64::from(statistics.audio_frames.load(Relaxed)),
            u64::from(statistics.audio_dropped.load(Relaxed)),
            u64::from(statistics.audio_restarts.load(Relaxed)),
            u64::from(statistics.audio_misses.load(Relaxed)),
            u64::from(statistics.overruns.load(Relaxed)),
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
fn wait_position(op: Operation<'_>, target: u32) {
    let routine = op.s().frame_record.position_routine.load(Relaxed);
    // SAFETY: the title's routine takes one argument and returns a signed
    // position.
    let position = |argument| unsafe { kernel::call_export(routine, argument, 0, 0, 0) } as i32;
    let target = target as i32;
    let mut previous = position(op.routine_argument());
    let passed = i32::from(target < previous);
    let mut wraps = 0;
    let mut current = position(op.routine_argument());
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
        current = position(op.routine_argument());
    }
}

/// Write movie data to the operation's file (stock 0x91f5a790).
///
/// # Safety
///
/// `bytes` bytes at `data` must be readable for the call.
unsafe fn emit(op: Operation<'_>, data: *const u8, bytes: u32) {
    let mut io_status = IoStatusBlock::default();
    // SAFETY: the operation's open file; guaranteed by the caller; the
    // write is synchronous.
    let status = unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(op.video.file.load(Relaxed)),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            data,
            bytes,
            core::ptr::null(),
        )
    };
    if !status.is_success() {
        op.video.write_failed.store(1, Relaxed);
    }
}

fn emit_words(op: Operation<'_>, words: &[u32]) {
    // SAFETY: `words` is live for the call.
    unsafe { emit(op, words.as_ptr().cast(), (words.len() * 4) as u32) };
}

/// Write capture buffer memory as movie data.
///
/// # Safety
///
/// `[data, data + bytes)` must lie in a capture buffer.
unsafe fn emit_buffer(op: Operation<'_>, data: u32, bytes: u32) {
    // SAFETY: guaranteed by the caller.
    unsafe { emit(op, core::ptr::with_exposed_provenance(data as usize), bytes) };
}

/// Convert the 16-bit samples at `source` to floats in `output` (stock
/// 0x91f5a860).
///
/// # Safety
///
/// `source` must address `output.len()` samples of a capture buffer.
unsafe fn to_float(output: &[AtomicU32], source: u32) {
    /// 2^-15.
    const SCALE: f32 = 1.0 / 32768.0;
    let start = cached(source);
    // SAFETY: guaranteed by the caller; `start` is the cached view of the
    // same memory.
    let samples: &[AtomicU16] = unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance(start as usize),
            output.len(),
        )
    };
    for (target, sample) in output.iter().zip(samples) {
        target.store(
            (f32::from(sample.load(Relaxed) as i16) * SCALE).to_bits(),
            Relaxed,
        );
    }
    buffers::flush(start, start + output.len() as u32 * 2);
}

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
        let header: &AtomicU32 = unsafe { crate::kernel::object_at(address) };
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
        unsafe { crate::kernel::object_at(crate::kernel::address_of(self.header)) }
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

/// Next record of the read-ahead buffers (stock 0x91f5a8f8).
fn next_record<'a>(op: Operation<'a>) -> Option<Record<'a>> {
    let v = op.video;
    if v.record_cursor.load(Relaxed) >= v.record_end.load(Relaxed) {
        prefetch(op);
        // SAFETY: the read slot is below `READ_SLOTS` (the invariant of
        // `Operation`).
        let slot = unsafe { v.slot(v.read_slot.load(Relaxed)) };
        if !slot.state().contains(SlotState::FILLED) {
            return None;
        }
        if slot.status.is_pending() {
            count(&v.statistics.overruns);
            while slot.status.is_pending() {}
        }
        let data = slot.data.load(Relaxed);
        v.read_slot
            .store(wrap(v.read_slot.load(Relaxed) + 1, READ_SLOTS), Relaxed);
        // SAFETY: the slot's read completed into `data`, a capture buffer
        // of the buffer table; its first word is the buffer header.
        let header = unsafe { crate::kernel::object_at::<AtomicU32>(data) }.load(Relaxed);
        v.record_cursor.store(data + buffers::HEADER_BYTES, Relaxed);
        v.record_end.store(
            data + ((header >> buffers::HEADER_DWORDS_SHIFT) + 1) * 4,
            Relaxed,
        );
    }
    let address = v.record_cursor.load(Relaxed);
    v.current_record.store(address, Relaxed);
    // SAFETY: the cursor lies in the records of the buffer the last slot
    // read, which the engine wrote whole.
    let record = unsafe { Record::at(address) };
    v.record_cursor.store(address + record.bytes(), Relaxed);
    Some(record)
}

/// Position the read-ahead at the frame record of `frame` (stock
/// 0x91f5aa50); the words of that record.
fn seek<'a>(op: Operation<'a>, frame: u32) -> Option<&'a [AtomicU32; 10]> {
    let s = op.s();
    let stream = s.stream(StreamId::First);
    let mut index = stream.table_index.load(Relaxed);
    let mut found = false;
    for _ in 0..TABLE_ENTRIES {
        index = if index == 0 {
            TABLE_ENTRIES as u32 - 1
        } else {
            index - 1
        };
        // The index wraps at the table size.
        let entry = &stream.table[index as usize % TABLE_ENTRIES];
        if overwritten(s, entry.sequence.load(Relaxed)) {
            index = wrap(index + 1, TABLE_ENTRIES as u32);
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
    start_prefetch(op, index);
    loop {
        let record = next_record(op)?;
        let (Some(StreamRecordKind::Frame), Some(words)) = (record.kind, record.frame()) else {
            continue;
        };
        let difference = sign24(words[1].load(Relaxed).wrapping_sub(frame));
        if difference < 0 {
            continue;
        }
        if difference != 0 || overwritten(s, words[2].load(Relaxed)) {
            return None;
        }
        return Some(words);
    }
}

/// Next record that bounds the operation, `None` at its end (stock
/// 0x91f5ab60).
fn next_bound<'a>(op: Operation<'a>) -> Option<Record<'a>> {
    let v = op.video;
    let current = v.current_record.load(Relaxed);
    if current != 0 {
        // SAFETY: a nonzero current record word holds the last record
        // `next_record` returned, in a read-ahead buffer of the table.
        let header: &AtomicU32 = unsafe { crate::kernel::object_at(current) };
        let word = header.load(Relaxed);
        let kind = StreamRecordKind::of(word);
        let frame = if v.flags().contains(VideoContextFlags::GPU) {
            (kind == Some(StreamRecordKind::GpuFrame) && word & fence_header::STATUS_MASK == 0)
                .then_some(word >> fence_header::FRAME_SHIFT)
        } else if matches!(
            kind,
            Some(StreamRecordKind::Frame | StreamRecordKind::LastFrame)
        ) {
            // SAFETY: as above; a frame record holds more than two words.
            let words: &[AtomicU32; 2] = unsafe { crate::kernel::object_at(current) };
            Some(words[1].load(Relaxed))
        } else {
            None
        };
        if let Some(frame) = frame
            && sign24(frame.wrapping_sub(v.end.load(Relaxed) >> 8)) >= 0
        {
            return None;
        }
    }
    loop {
        let record = next_record(op)?;
        let word = record.header();
        let flags = v.flags().bits();
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

/// Units read by one scatter read.
const MAX_CHUNK_UNITS: u32 = 8;
const PAGES_PER_UNIT: usize = (buffers::BUFFER_BYTES / PAGE_SIZE) as usize;

/// Queue reads of the next units into the request ring (stock
/// 0x91f5ac68).
fn fill_requests(op: Operation<'_>) {
    let v = op.video;
    let s = op.s();
    let units =
        (s.stream(StreamId::First).size.get() as i64 / i64::from(buffers::BUFFER_BYTES)) as u32;
    let mut budget = readable(op);
    if budget == 0 {
        return;
    }
    loop {
        if v.pending_units.load(Relaxed) == 0 {
            loop {
                let request = op.request(Cursor::Tail);
                if ring_full(op) {
                    return;
                }
                if v.read_state().contains(ReadState::END) {
                    end_marker(op, request);
                    return;
                }
                let Some(record) = next_bound(op) else {
                    v.set_read_state(v.read_state() | ReadState::END);
                    end_marker(op, request);
                    return;
                };
                if record.kind == Some(StreamRecordKind::Frame)
                    && let Some(words) = record.frame()
                {
                    // SAFETY: only the operation's thread stores the
                    // context words, so the byte read races nothing.
                    let low = unsafe { low_byte(&v.read_state) };
                    v.read_state.store(
                        words[1].load(Relaxed) << 8 | u32::from(low.load(Relaxed)),
                        Relaxed,
                    );
                } else if let Some(words) = record.audio()
                    && v.flags().contains(VideoContextFlags::AUDIO)
                {
                    v.pending_units.store(1, Relaxed);
                    v.pending_position
                        .store(words[audio_record::SEQUENCE].load(Relaxed), Relaxed);
                    request.set_kind(RequestKind::Audio);
                    request
                        .unit
                        .store(v.buffer_position.load(Relaxed) as u16, Relaxed);
                    copy_words(&request.record, words);
                    request.header.store(
                        (v.read_state.load(Relaxed) & ReadState::FRAME_MASK)
                            | (request.header.load(Relaxed) & 0xff),
                        Relaxed,
                    );
                    break;
                } else if let Some(words) = record.gpu_frame()
                    && v.flags().contains(VideoContextFlags::GPU)
                {
                    let word = words[gpu_record::HEADER].load(Relaxed);
                    request
                        .unit
                        .store(v.buffer_position.load(Relaxed) as u16, Relaxed);
                    copy_words(&request.record, words);
                    // SAFETY: only the operation's thread stores request
                    // headers, and nothing stores the records of completed
                    // reads, so the narrow reads race nothing.
                    let (low, units) = unsafe {
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
                        v.pending_units
                            .store(u32::from(units.load(Relaxed)), Relaxed);
                        v.pending_position
                            .store(words[gpu_record::SEQUENCE].load(Relaxed), Relaxed);
                        request.set_kind(RequestKind::Gpu);
                        break;
                    }
                    request.set_kind(RequestKind::NoData);
                    op.advance(Cursor::Tail);
                    count(&v.statistics.dropped);
                }
            }
        }
        let mut left = budget.min(v.pending_units.load(Relaxed));
        while left != 0 {
            let request = op.request(Cursor::Tail);
            let chunk = left
                .min(MAX_CHUNK_UNITS)
                .min(units.wrapping_sub(v.pending_position.load(Relaxed) & 0x00ff_ffff));
            let mut segments = [0u32; MAX_CHUNK_UNITS as usize * PAGES_PER_UNIT + 1];
            // `chunk` is at most `MAX_CHUNK_UNITS`.
            for pages in
                segments[..chunk as usize * PAGES_PER_UNIT].chunks_exact_mut(PAGES_PER_UNIT)
            {
                let position = v.buffer_position.load(Relaxed);
                v.buffer_position
                    .store(wrap(position + 1, v.buffer_count.load(Relaxed)), Relaxed);
                let data = op.buffer(position as usize);
                for (page, segment) in (0..).zip(pages) {
                    *segment = data + page * PAGE_SIZE;
                }
            }
            let io_status = if v.pending_units.load(Relaxed) == chunk {
                &request.status
            } else {
                &v.scatter_status
            };
            io_status.set_pending();
            let offset = u64::from(v.pending_position.load(Relaxed) & 0x00ff_ffff) << UNIT_SHIFT;
            // SAFETY: the status block lies in the ring or the context,
            // which outlive the read (`finish` cancels or waits for it);
            // `segments` and `offset` are read during the call.
            unsafe {
                xboxkrnl::NtReadFileScatter(
                    Handle::from_raw(buffers::stream_handle(s, StreamId::First)),
                    Handle::NULL,
                    0,
                    0,
                    io_status.as_ptr(),
                    segments.as_ptr(),
                    chunk << UNIT_SHIFT,
                    &offset,
                )
            };
            left -= chunk;
            budget -= chunk;
            let position = v.pending_position.load(Relaxed);
            let mut next = (position & 0xff00_0000) | (position.wrapping_add(chunk) & 0x00ff_ffff);
            if next & 0x00ff_ffff >= units {
                next &= 0xff00_0000;
            }
            v.pending_position.store(next, Relaxed);
            v.pending_units
                .store(v.pending_units.load(Relaxed) - chunk, Relaxed);
            if v.pending_units.load(Relaxed) == 0 {
                op.advance(Cursor::Tail);
            }
        }
        if budget == 0 {
            return;
        }
    }
}

/// Copy the words of a record into the words of a request.
#[inline(always)]
fn copy_words(target: &[AtomicU32], source: &[AtomicU32]) {
    for (target, source) in target.iter().zip(source) {
        target.store(source.load(Relaxed), Relaxed);
    }
}

fn end_marker(op: Operation<'_>, request: &VideoRequest) {
    request.set_kind(RequestKind::End);
    op.advance(Cursor::Tail);
}

/// Elapsed replay time against a record time (stock 0x91f5b018): true
/// when the frame is due; a frame far behind is recorded as a miss.
fn frame_due(op: Operation<'_>, request: &VideoRequest) -> bool {
    let v = op.video;
    if op.s().engine_flags().contains(EngineFlags::PAUSED) {
        return true;
    }
    let target = request
        .record_word(gpu_record::TIME)
        .wrapping_sub(v.clock_record.load(Relaxed)) as i32;
    let elapsed = (performance_counter() as i32).wrapping_sub(v.clock_start.load(Relaxed) as i32);
    if !v.flags().contains(VideoContextFlags::AUDIO)
        && target > elapsed.wrapping_add(POSITION_LIMIT)
    {
        v.restart.store(
            fence_header::frame(request.record_word(gpu_record::HEADER)),
            Relaxed,
        );
        count(&v.statistics.restarts);
    }
    target < elapsed
}

/// Audio counterpart of [`frame_due`] (stock 0x91f5b0c0).
fn audio_due(op: Operation<'_>, request: &VideoRequest) -> bool {
    let v = op.video;
    let target = request
        .record_word(audio_record::TIME)
        .wrapping_sub(v.clock_record.load(Relaxed)) as i32;
    let mut elapsed =
        (performance_counter() as i32).wrapping_sub(v.clock_start.load(Relaxed) as i32);
    if v.flags().contains(VideoContextFlags::GPU) {
        elapsed = elapsed.wrapping_add(AUDIO_LEAD);
    }
    target < elapsed
}

fn performance_counter() -> u32 {
    let mut counter = 0u64;
    // SAFETY: `counter` is a live local.
    unsafe { xam::QueryPerformanceCounter(&mut counter) };
    (counter as i64 >> 10) as u32
}

crate::exports::bridged!(render_entry, render);

/// Address of the audio client routine handed to XAudio.
pub(super) fn render_entry_address() -> u32 {
    render_entry as *const () as usize as u32
}

/// XAudio render client routine (stock 0x91f5b140): plays the captured
/// audio of the operation, [`BLOCK_SAMPLES`] samples per call.
extern "C" fn render(context: u32) {
    // SAFETY: XAudio passes the address of the word that holds the context
    // of the registration `pause_engine` made, the address of the session's
    // render client; the client's session and video words hold the
    // addresses of the session block that contains it and of the block's
    // video context. The block outlives the registration.
    let (client, s, video): (&RenderClient, &PixSession, &VideoContext) = unsafe {
        let client: &RenderClient =
            crate::kernel::object_at(crate::kernel::object_at::<AtomicU32>(context).load(Relaxed));
        (
            client,
            crate::kernel::object_at(client.session.load(Relaxed)),
            crate::kernel::object_at(client.video.load(Relaxed)),
        )
    };
    let current = &client.current;
    let state = ClientState::from_raw(client.state.load(Relaxed));
    match state {
        Some(ClientState::StopRequested) => {
            client.publish_state(ClientState::Idle);
            return;
        }
        Some(ClientState::Starting | ClientState::Playing) => {}
        _ => return,
    }
    // Only `multiple` sets the starting state, after `initialize`; it sets
    // the client idle or stopped before `release`, so the ring and buffer
    // words hold the operation's. `multiple` only waits for the client to
    // stop on the stop request; when it sets the client idle after a thread
    // write it does not wait, as stock, so a call that passed the state
    // check above can still use the ring after `release` frees it (a race
    // of stock).
    let op = Operation { video };
    let v = video;
    if state == Some(ClientState::Starting) {
        if current.kind() == Some(RequestKind::Empty) {
            next_audio(op, current);
            if current.kind() == Some(RequestKind::Empty) {
                return;
            }
        }
        if current.kind() == Some(RequestKind::End) {
            client.set_state(ClientState::Idle);
            return;
        }
        if !audio_due(op, current) {
            return;
        }
        client.position.store(
            audio_record::position(current.record_word(audio_record::HEADER)),
            Relaxed,
        );
        client.data.store(op.buffer(current.unit()), Relaxed);
        client.publish_state(ClientState::Playing);
    }
    let output_address = client.output.as_ptr().addr() as u32;
    let position = client.position.load(Relaxed);
    if position <= BUFFER_SAMPLES - BLOCK_SAMPLES {
        // SAFETY: the block lies in the audio buffer of `BUFFER_SAMPLES`
        // samples at `data`.
        unsafe { to_float(&client.output, client.data.load(Relaxed) + position * 2) };
        client.position.store(position + BLOCK_SAMPLES, Relaxed);
        // SAFETY: the client registered by `pause_engine`; `output` is its
        // sample buffer.
        unsafe { XAudioSubmitRenderDriverFrame(s.audio_client.load(Relaxed), output_address) };
        count(&v.statistics.audio_frames);
        return;
    }
    let repeat = current.record_word(audio_record::HEADER);
    let dropped = repeat >> audio_record::DROPPED_SHIFT;
    if dropped != 0 {
        current.record[audio_record::HEADER].store(
            (repeat & ((1 << audio_record::DROPPED_SHIFT) - 1))
                | (dropped - 1) << audio_record::DROPPED_SHIFT,
            Relaxed,
        );
        count(&v.statistics.audio_dropped);
        return;
    }
    let first = BUFFER_SAMPLES - position;
    let rest = BLOCK_SAMPLES - first;
    let (head, tail) = client.output.split_at(first as usize);
    // SAFETY: the samples from `position` to the end of the audio buffer at
    // `data`.
    unsafe { to_float(head, client.data.load(Relaxed) + position * 2) };
    let next = VideoRequest::new();
    next_audio(op, &next);
    let underrun = match next.kind() {
        Some(RequestKind::End) => {
            client.publish_state(ClientState::Idle);
            return;
        }
        Some(RequestKind::Empty) => true,
        _ => {
            let lead = (v.clock_start.load(Relaxed) as i32)
                .wrapping_sub(performance_counter() as i32)
                .wrapping_add(
                    current
                        .record_word(audio_record::TIME)
                        .wrapping_sub(v.clock_record.load(Relaxed)) as i32,
                );
            lead > AUDIO_GAP_LIMIT
                || (audio_record::position(next.record_word(audio_record::HEADER))
                    .wrapping_sub(rest))
                    % BLOCK_SAMPLES
                    != 0
        }
    };
    if underrun {
        v.restart.store(current.frame() + 1, Relaxed);
        count(&v.statistics.audio_restarts);
        client.publish_state(ClientState::Underrun);
        return;
    }
    let data = op.buffer(next.unit());
    client.position.store(rest, Relaxed);
    client.data.store(data, Relaxed);
    // SAFETY: the first `rest` samples of the next audio buffer.
    unsafe { to_float(tail, data) };
    // SAFETY: as above.
    unsafe { XAudioSubmitRenderDriverFrame(s.audio_client.load(Relaxed), output_address) };
    count(&v.statistics.audio_frames);
    current.copy_from(&next);
}

/// Start an operation at the context's frame (stock 0x91f5b420): reset
/// the queues, find the frame record, and decide the parts.
fn begin(op: Operation<'_>, audio: bool, no_gpu: bool) -> Result<(), VideoError> {
    let v = op.video;
    let s = op.s();
    v.read_slot.store(0, Relaxed);
    v.fill_slot.store(0, Relaxed);
    v.buffer_position.store(0, Relaxed);
    v.gpu_buffer.store(0, Relaxed);
    v.audio_buffer.store(0, Relaxed);
    v.ring_tail.store(0, Relaxed);
    v.audio_index.store(0, Relaxed);
    v.gpu_index.store(0, Relaxed);
    v.pending_units.store(0, Relaxed);
    v.pending_position.store(0, Relaxed);
    v.pending_spare.store(0, Relaxed);
    v.read_state.store(0, Relaxed);
    v.record_cursor.store(0, Relaxed);
    v.record_end.store(0, Relaxed);
    v.read_state
        .store(v.flags().bits() << 7 & ReadState::FRAME_MASK, Relaxed);
    let record = seek(op, v.flags().frame()).ok_or(VideoError::NothingToReplay)?;
    v.restart.store(VideoContext::NO_RESTART, Relaxed);
    let word = record[0].load(Relaxed);
    let streams = (word << VideoContextFlags::GPU_STREAM_SHIFT
        & frame_header::GPU_STREAM << VideoContextFlags::GPU_STREAM_SHIFT)
        | (word << VideoContextFlags::AUDIO_STREAM_SHIFT
            & frame_header::AUDIO_STREAM << VideoContextFlags::AUDIO_STREAM_SHIFT);
    let mut flags = VideoContextFlags::from_bits_retain(
        (v.flags().bits() & !VideoContextFlags::STREAMS) | streams,
    );
    flags.remove(VideoContextFlags::GPU | VideoContextFlags::AUDIO);
    if word & frame_header::GPU_STREAM == 0 {
        flags.insert(VideoContextFlags::GPU);
    }
    if word & frame_header::AUDIO_STREAM == 0 {
        flags.insert(VideoContextFlags::AUDIO);
    }
    if no_gpu {
        flags.remove(VideoContextFlags::GPU);
    }
    if !audio {
        flags.remove(VideoContextFlags::AUDIO);
    }
    let full_record = FrameRecordFlags::from_bits_retain(s.frame_record.flags.load(Relaxed))
        .contains(FrameRecordFlags::FULL);
    if !full_record {
        flags.remove(VideoContextFlags::GPU);
    }
    if s.kernel_routine.load(Relaxed) == 0 {
        flags.remove(VideoContextFlags::AUDIO);
    }
    v.set_flags(flags);
    if !flags.intersects(VideoContextFlags::GPU | VideoContextFlags::AUDIO) {
        return Err(VideoError::NothingToReplay);
    }
    if flags.contains(VideoContextFlags::GPU) && !flags.contains(VideoContextFlags::COMPLETION) {
        let result = check(op);
        if result != 0 {
            return Err(VideoError::Check { result });
        }
    }
    fill_requests(op);
    wait_requests(op);
    Ok(())
}

/// `VideoOp` status with the operation's argument and the frames left
/// (stock 0x91f5b5d8 and 0x91f56438).
fn status(op: Operation<'_>, done: bool) {
    let v = op.video;
    let start = v.report_start.load(Relaxed) >> 8;
    let end = v.report_end.load(Relaxed) >> 8;
    let mut frame = v.frame.load(Relaxed);
    if sign24(frame.wrapping_sub(start)) < 0 {
        frame = start;
    }
    if sign24(frame.wrapping_sub(end)) >= 0 {
        frame = end.wrapping_sub(1);
    }
    let back = sign24(op.s().frame_index().wrapping_sub(frame));
    let current = super::super::frame::frame_number().wrapping_sub(back as u32) as i32;
    let mut text: openxbdm_server::text::Text<0x80> = openxbdm_server::text::Text::new();
    let label = if done { "Done" } else { "Update" };
    let _ = core::fmt::Write::write_fmt(
        &mut text,
        format_args!(
            "{} {} {}\0",
            v.argument.load(Relaxed) as i32,
            label,
            current
        ),
    );
    // SAFETY: the three fields and the NUL fit in `text`, which outlives
    // the call.
    unsafe {
        super::super::status::post(
            super::super::status::Status::VideoOp,
            text.as_bytes().as_ptr() as usize as u32,
        )
    };
}

/// Replay one frame (stock 0x91f5b630).
fn single(op: Operation<'_>) -> Result<(), VideoError> {
    begin(op, false, false)?;
    let mut result = Ok(());
    if op.video.flags().contains(VideoContextFlags::GPU) {
        let first = VideoRequest::new();
        let next = VideoRequest::new();
        let mut extra = [0u32; SUBMIT_EXTRA_WORDS];
        next_request(op, false, &first);
        if first.kind() == Some(RequestKind::NoData) {
            let status = first.record_word(gpu_record::HEADER) >> fence_header::STATUS_SHIFT;
            if status != 0 {
                result = Err(VideoError::Refused { status });
            }
        } else {
            loop {
                next_request(op, true, &next);
                if next.kind() != Some(RequestKind::NoData) {
                    break;
                }
            }
            result = replay_frame(op, &first, &next, &mut extra);
        }
        if result.is_err() {
            end_submissions(op);
        }
    }
    status(op, true);
    result
}

/// Align the replay clock with the first frame (stock 0x91f5b748).
fn start_clock(op: Operation<'_>, out: &VideoRequest) {
    let v = op.video;
    let current = &op.s().render_client.current;
    if v.flags().contains(VideoContextFlags::GPU) {
        next_request(op, false, out);
        while out.kind() == Some(RequestKind::Empty) {
            fill_requests(op);
            next_audio(op, current);
            next_request(op, false, out);
            wait_requests(op);
        }
        wait_position(
            op,
            out.record_word(gpu_record::TIME)
                .wrapping_sub(out.record_word(gpu_record::POSITION)),
        );
        v.clock_start.store(performance_counter(), Relaxed);
        v.clock_record
            .store(out.record_word(gpu_record::TIME), Relaxed);
        if v.flags().contains(VideoContextFlags::AUDIO) {
            loop {
                next_audio(op, current);
                if current.kind() != Some(RequestKind::Audio)
                    || (v
                        .clock_record
                        .load(Relaxed)
                        .wrapping_sub(current.record_word(audio_record::TIME))
                        as i32)
                        <= AUDIO_LEAD
                {
                    break;
                }
            }
        }
    } else {
        next_audio(op, current);
        v.clock_start.store(performance_counter(), Relaxed);
        v.clock_record
            .store(current.record_word(audio_record::TIME), Relaxed);
    }
}

/// Milliseconds between `Update` statuses.
const STATUS_INTERVAL_MS: u32 = 100;

/// Replay a frame range in real time (stock 0x91f5b878) until its end, a
/// queued message, or a thread write; misses restart at the missed frame.
fn multiple(op: Operation<'_>) -> Result<(), VideoError> {
    let s = op.s();
    let v = op.video;
    let client = &s.render_client;
    let first = VideoRequest::new();
    let next = VideoRequest::new();
    let mut extra = [0u32; SUBMIT_EXTRA_WORDS];
    let mut last_status = TickCount::now().milliseconds();
    let start = TickCount::now().milliseconds();
    let mut interrupted = false;
    begin(op, true, false)?;
    let mut result = Ok(());
    'restart: loop {
        start_clock(op, &first);
        if v.flags().contains(VideoContextFlags::AUDIO) {
            client.publish_state(ClientState::Starting);
        }
        'frames: loop {
            let flags = v.flags();
            if flags.contains(VideoContextFlags::AUDIO)
                && client.state.load(Relaxed) == ClientState::Idle.raw()
            {
                break 'frames;
            }
            if flags.contains(VideoContextFlags::GPU) {
                let mut ready = first.kind() == Some(RequestKind::Gpu);
                if !ready {
                    next_request(op, false, &first);
                    let kind = first.kind();
                    if kind == Some(RequestKind::End)
                        && !v.flags().contains(VideoContextFlags::AUDIO)
                    {
                        break 'frames;
                    }
                    ready = kind == Some(RequestKind::Gpu);
                }
                if ready && frame_due(op, &first) {
                    next_request(op, true, &next);
                    match next.kind() {
                        Some(RequestKind::End) => break 'frames,
                        Some(RequestKind::Gpu) => {
                            result = replay_frame(op, &first, &next, &mut extra);
                            if result.is_err() {
                                if v.statistics.frames.load(Relaxed) == 0 {
                                    end_submissions(op);
                                }
                                break 'frames;
                            }
                            note_request(op, &next);
                            if next.record_word(gpu_record::HEADER) & fence_header::LAST != 0 {
                                first.set_kind(RequestKind::Empty);
                            } else {
                                first.copy_from(&next);
                            }
                            next.set_kind(RequestKind::Empty);
                        }
                        Some(RequestKind::Empty) => {
                            note_request(op, &first);
                            count(&v.statistics.misses);
                            next.set_kind(RequestKind::Empty);
                            first.set_kind(RequestKind::Empty);
                        }
                        _ => {}
                    }
                }
            }
            if v.restart().is_some() {
                break 'frames;
            }
            fill_requests(op);
            if TickCount::now().milliseconds().wrapping_sub(last_status) > STATUS_INTERVAL_MS {
                last_status = TickCount::now().milliseconds();
                status(op, false);
            }
            s.leave_lock();
            s.enter_lock();
            if s.queue_count.load(Relaxed) > 0 && !s.engine_flags().contains(EngineFlags::PAUSED) {
                interrupted = true;
                break 'frames;
            }
            if v.flags().contains(VideoContextFlags::AUDIO)
                && v.writes_at_pause.load(Relaxed) != s.thread_writes.load(Relaxed)
            {
                break 'frames;
            }
        }
        if let Some(restart) = v.restart()
            && restart < v.end.load(Relaxed) >> 8
        {
            finish(op);
            v.flags.store(
                (v.flags().bits() & !VideoContextFlags::FRAME_MASK)
                    | (restart << 1 & VideoContextFlags::FRAME_MASK),
                Relaxed,
            );
            begin(op, true, false)?;
            result = Ok(());
            continue 'restart;
        }
        break 'restart;
    }
    if v.flags().contains(VideoContextFlags::AUDIO) {
        if v.writes_at_pause.load(Relaxed) == s.thread_writes.load(Relaxed) {
            client.publish_state(ClientState::StopRequested);
            while client.state.load(Relaxed) != ClientState::Idle.raw() {}
        } else {
            client.publish_state(ClientState::Idle);
        }
    }
    status(op, !interrupted);
    report(op, start);
    result
}

/// Movie data record identifiers.
#[derive(Clone, Copy)]
#[repr(u32)]
enum MovieRecord {
    Start = 0x69,
    Frame = 0x6b,
    Audio = 0x6c,
    /// The audio stream has a gap; the movie restarts after it.
    Discontinuity = 0x6d,
    End = 0x18,
}

/// Records of fewer dwords have a one-word movie data header.
const SHORT_RECORD_DWORDS: u32 = 0x7f;

/// Movie data record header (stock 0x91f5bc08).
fn movie_record(op: Operation<'_>, id: MovieRecord, bytes: u32) {
    let id = id as u32;
    let dwords = bytes >> 2;
    if dwords < SHORT_RECORD_DWORDS {
        emit_words(op, &[((dwords + 1) << 24 & 0x7fff_ffff) | id]);
    } else {
        emit_words(op, &[RecordType::new(id).raw(), dwords + 2]);
    }
}

/// Header of the `PixV` image the title stores in a frame's command data.
#[repr(C)]
struct ImageHeader {
    magic: AtomicU32,
    /// 0.
    version: AtomicU32,
    /// At most [`ImageHeader::MAX_KIND`].
    kind: AtomicU32,
    _reserved_0c: AtomicU32,
    /// Copied into the movie frame record.
    frame_info: [AtomicU32; 2],
    _reserved_18: [AtomicU32; 2],
    /// Copied into the movie frame record.
    frame_format: AtomicU32,
}

impl ImageHeader {
    const MAGIC: u32 = u32::from_be_bytes(*b"PixV");
    const MAX_KIND: u32 = 2;
    /// Bytes from the header to the image data.
    const BYTES: u32 = PAGE_SIZE;
}

const _: () = assert!(core::mem::offset_of!(ImageHeader, frame_format) == 0x20);

/// Movie frame: the `PixV` image the title stored in the frame's command
/// data (stock 0x91f5bc78).
fn movie_frame(
    op: Operation<'_>,
    first: &VideoRequest,
    next: &VideoRequest,
) -> Result<(), VideoError> {
    let mut list = [0u32; COMMAND_LIST_ENTRIES];
    let Commands {
        start: mut index,
        mut count,
        offset,
    } = command_list(op, first, next, &mut list);
    // SAFETY: the title stores the image header at the start of the
    // frame's command data, in a capture buffer.
    let image: &ImageHeader = unsafe { crate::kernel::object_at(cached(list[index] + offset)) };
    if image.magic.load(Relaxed) != ImageHeader::MAGIC
        || image.version.load(Relaxed) != 0
        || image.kind.load(Relaxed) > ImageHeader::MAX_KIND
    {
        return Err(VideoError::NoImage);
    }
    let mut position = offset + ImageHeader::BYTES;
    if position >= buffers::BUFFER_BYTES {
        if position != buffers::BUFFER_BYTES {
            return Err(VideoError::NoImage);
        }
        position = 0;
        index += 1;
        count -= 1;
    }
    let header = [
        first.record_word(gpu_record::TIME),
        image.frame_info[0].load(Relaxed),
        image.frame_info[1].load(Relaxed),
        image.frame_format.load(Relaxed),
    ];
    movie_record(
        op,
        MovieRecord::Frame,
        ((count as u32) << UNIT_SHIFT).wrapping_sub(position) + 0x10,
    );
    emit_words(op, &header);
    for &buffer in &list[index..index + count] {
        let data = buffer + position;
        let bytes = buffers::BUFFER_BYTES - position;
        // SAFETY: `data` and `bytes` lie in a capture buffer.
        unsafe {
            emit_buffer(op, data, bytes);
            xboxkrnl::KeFlushCacheRange(data, bytes);
        }
        position = 0;
    }
    Ok(())
}

/// Movie audio between two audio requests (stock 0x91f5be10).
fn movie_audio(op: Operation<'_>, previous: &VideoRequest, current: &VideoRequest) {
    let previous_header = previous.record_word(audio_record::HEADER);
    let start = audio_record::position(previous_header);
    let end = audio_record::position(current.record_word(audio_record::HEADER));
    let header = [
        previous.record_word(audio_record::TIME),
        (previous_header >> audio_record::DROPPED_SHIFT) * BLOCK_SAMPLES,
        end + (BUFFER_SAMPLES - start),
    ];
    let first_bytes = (BUFFER_SAMPLES - start) * 2;
    let second_bytes = end * 2;
    let first = cached(op.buffer(previous.unit())) + start * 2;
    let second = cached(op.buffer(current.unit()));
    movie_record(op, MovieRecord::Audio, second_bytes + first_bytes + 0xc);
    emit_words(op, &header);
    // SAFETY: both ranges lie in the audio capture buffers of the requests.
    unsafe {
        emit_buffer(op, first, first_bytes);
        emit_buffer(op, second, second_bytes);
        xboxkrnl::KeFlushCacheRange(first, first_bytes);
        xboxkrnl::KeFlushCacheRange(second, second_bytes);
    }
}

/// Write the frame range as movie data (stock 0x91f5bf10).
fn movie(op: Operation<'_>, no_gpu: bool) -> Result<(), VideoError> {
    let v = op.video;
    movie_record(op, MovieRecord::Start, 0);
    // Stock starts from uninitialized previous requests.
    let audio = VideoRequest::new();
    let frame = VideoRequest::new();
    let current = VideoRequest::new();
    'restart: loop {
        begin(op, true, no_gpu)?;
        loop {
            fill_requests(op);
            current_request(op, &current);
            match current.kind() {
                Some(RequestKind::End) => {
                    movie_record(op, MovieRecord::End, 0);
                    return Ok(());
                }
                Some(RequestKind::Gpu) => {
                    if frame.kind() == Some(RequestKind::Gpu) {
                        if let Err(error) = movie_frame(op, &frame, &current) {
                            movie_record(op, MovieRecord::End, 0);
                            return Err(error);
                        }
                        note_request(op, &current);
                    }
                    if current.record_word(gpu_record::HEADER) & fence_header::LAST != 0 {
                        frame.set_kind(RequestKind::Empty);
                    } else {
                        frame.copy_from(&current);
                    }
                }
                Some(RequestKind::Audio) => {
                    if audio.kind() == Some(RequestKind::Audio) {
                        let discontinuous = (current
                            .record_word(audio_record::TIME)
                            .wrapping_sub(audio.record_word(audio_record::TIME))
                            as i32)
                            > AUDIO_GAP_LIMIT
                            || (audio_record::position(current.record_word(audio_record::HEADER))
                                .wrapping_sub(audio_record::position(
                                    audio.record_word(audio_record::HEADER),
                                ))
                                .wrapping_add(BUFFER_SAMPLES))
                                % BLOCK_SAMPLES
                                != 0;
                        if discontinuous {
                            movie_record(op, MovieRecord::Discontinuity, 0);
                            finish(op);
                            let mask = VideoContextFlags::FRAME_MASK;
                            let restart =
                                ((current.header.load(Relaxed) >> 7) & mask).wrapping_add(2);
                            let flags = (restart & mask) | (v.flags().bits() & !mask);
                            v.flags.store(flags, Relaxed);
                            if flags & mask < (v.end.load(Relaxed) >> 7) & mask {
                                audio.set_kind(RequestKind::Empty);
                                frame.set_kind(RequestKind::Empty);
                                continue 'restart;
                            }
                        }
                        movie_audio(op, &audio, &current);
                        v.audio_buffer.store(current.unit() as u32, Relaxed);
                    }
                    audio.copy_from(&current);
                }
                _ => {}
            }
        }
    }
}

/// Context for frames `first` (frames back) and `count` frames.
fn setup(op: Operation<'_>, first: u32, count: u32) {
    let v = op.video;
    let mask = VideoContextFlags::FRAME_MASK;
    let start = (op.s().frame_index() << 1).wrapping_sub(first << 1);
    let flags = (start & mask) | (v.flags().bits() & !mask);
    v.flags.store(flags, Relaxed);
    v.frame.store((flags & mask) >> 1, Relaxed);
    let end = ((flags & !1).wrapping_add(count << 1) & mask) << 7;
    // SAFETY: only the operation's thread stores the context words.
    let low = unsafe { low_byte(&v.end) };
    v.end.store(end | u32::from(low.load(Relaxed)), Relaxed);
}

/// Free the request ring of the operation.
///
/// # Safety
///
/// No copy of `op` may be used afterwards.
#[inline(always)]
unsafe fn release(op: Operation<'_>) {
    let ring = &op.video.ring;
    // SAFETY: the request ring `initialize` allocated; no view of it
    // remains (guaranteed by the caller), and its word is cleared below.
    unsafe { xboxkrnl::ExFreePool(ring.load(Relaxed)) };
    ring.store(0, Relaxed);
}

/// Message 12: replay frames (stock 0x91f5c0e8).
pub(super) fn run(s: &PixSession, first: u32, count: u32, argument: u32) -> Result<(), VideoError> {
    let op = initialize(s, &s.video).ok_or(VideoError::NoBuffers)?;
    let v = op.video;
    // SAFETY: only the operation's thread stores the context words.
    let (start_low, end_low) = unsafe { (low_byte(&v.report_start), low_byte(&v.report_end)) };
    let start_byte = u32::from(start_low.load(Relaxed));
    let end_byte = u32::from(end_low.load(Relaxed));
    v.argument.store(argument, Relaxed);
    setup(op, first, count);
    v.report_start.store(
        (v.flags().bits() & VideoContextFlags::FRAME_MASK) << 7 | start_byte,
        Relaxed,
    );
    v.report_end
        .store(end_byte | (v.end.load(Relaxed) & 0xffff_ff00), Relaxed);
    let result = if count == 1 { single(op) } else { multiple(op) };
    finish(op);
    // SAFETY: the operation ends here.
    unsafe { release(op) };
    result
}

/// Message 14 while paused: frames as movie data to `file` (stock
/// 0x91f5c1d8).
pub(super) fn write(
    s: &PixSession,
    file: u32,
    no_gpu: u32,
    first: u32,
    count: u32,
) -> Result<(), VideoError> {
    let op = initialize(s, &s.video).ok_or(VideoError::NoBuffers)?;
    let v = op.video;
    v.file.store(file, Relaxed);
    v.write_failed.store(0, Relaxed);
    setup(op, first, count);
    let result = movie(op, no_gpu != 0);
    finish(op);
    // SAFETY: the operation ends here.
    unsafe { release(op) };
    if result.is_ok() && v.write_failed.load(Relaxed) != 0 {
        return Err(VideoError::WriteFailed);
    }
    result
}
