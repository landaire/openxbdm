//! The PIX capture session (stock 0x91fab7cc): a 0x12380-byte pool block
//! created at initialization when XAM feature 0x22 is enabled (stock
//! 0x91f5c560). `pixcmd` and titles queue engine messages in it; the
//! capture engine (`super::capture`) processes them at frame boundaries.
//!
//! [`PixSession`] is the stock layout of the block. Title replay routines
//! receive its address, and the engine hands addresses of its fields to
//! the kernel, so the layout is fixed. Title threads, IPIs, DPCs and the
//! XAudio render thread share the block; every word is an `AtomicU32`
//! accessed with relaxed ordering, as stock accesses it with plain loads
//! and stores, and barriers are explicit where stock has them.
//!
//! Words that hold addresses (buffer entries, the request and buffer
//! tables, rings, queues, physical and temporary blocks) hold 0 or a
//! block the engine allocated and has not freed wherever a count, head
//! or tail makes them live. Only `super::capture` stores them, and only
//! such blocks; the safe accessors that dereference them rely on that.
//! Titles that write the block break this as they break stock.

use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU16;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use xbox360::module::ExportAddress;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::thread::current_object;
use xbox360_sys::xam;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::DeviceObject;
use xbox360_sys::xboxkrnl::DeviceObjectFlags;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FsInformationClass;
use xbox360_sys::xboxkrnl::FsSizeInformation;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::Kdpc;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::Kthread;
use xbox360_sys::xboxkrnl::Ktimer;
use xbox360_sys::xboxkrnl::MemoryRegion;
use xbox360_sys::xboxkrnl::NtStatus;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::RtlCriticalSection;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::capture::RenderClient;
use super::capture::VideoContext;
use super::events;
use super::events::CallbackOperation;
use crate::kernel;

/// Pool tag `PSTR` of the block and of capture allocations.
pub(super) const POOL_TAG: PoolTag = PoolTag::new(*b"PSTR");
/// XAM feature that enables PIX streaming.
const STREAMING_FEATURE: u32 = 0x22;
/// Engine status version, first word of `pixcmd q` and frame record
/// `+0x20`.
pub(super) const STATUS_VERSION: u32 = 0x5308;

xbox360_sys::flags! {
    /// Engine flags word: state bits, and the frame index in bits 5 to 28.
    pub struct EngineFlags(u32) {
        /// Capturing.
        RUNNING = 0x8000_0000,
        /// Module records paused by message 13.
        PAUSED = 0x4000_0000,
        /// Buffer output paused until the next buffer write.
        PAUSED_OUTPUT = 0x2000_0000,
    }
}

impl EngineFlags {
    /// Bits of the frame index.
    pub(super) const FRAME_MASK: u32 = 0x1fff_ffe0;
    pub(super) const FRAME_SHIFT: u32 = 5;

    /// Frame index (bits 5 to 28).
    pub(super) const fn frame_index(self) -> u32 {
        self.bits() >> Self::FRAME_SHIFT & 0x00ff_ffff
    }

    /// The flags with the frame index advanced by one.
    pub(super) const fn next_frame(self) -> Self {
        let bits = self.bits();
        Self::from_bits_retain(
            ((bits & !0x1f).wrapping_add(1 << Self::FRAME_SHIFT) & Self::FRAME_MASK)
                | (bits & !Self::FRAME_MASK),
        )
    }
}

xbox360_sys::value_enum! {
    /// Engine message codes of the session queue (`pixcmd` and code 0x57).
    pub enum EngineMessage: u32 {
        /// `{frames, notify, file}`: capture frames to a file.
        CaptureFrames = 1,
        /// Finish at the next frame.
        WaitFrame = 2,
        /// Instruction trace of one frame.
        TraceFrame = 3,
        /// Instruction trace of the event named by `pixcmd k`.
        TraceEvent = 4,
        /// Per-thread timing data to a capture file.
        CaptureToFile = 5,
        /// Store a requested configuration.
        RecordConfiguration = 6,
        /// Write frames of the dump partition to `unnamed.pix2`.
        WriteFrames = 7,
        /// Replay frames through the title's routines.
        ReplayFrames = 8,
        /// Snapshot of the stream position (only while paused).
        DumpHeader = 9,
        Pause = 10,
        Resume = 11,
        VideoOperation = 12,
        /// Set or clear [`EngineFlags::PAUSED`].
        PauseFlag = 13,
        /// Video operation into `unnamed.pix2` (only while paused).
        PausedVideo = 14,
        /// Resource capture state.
        ResourceState = 15,
    }
}

/// Capture part selected by a configuration word index.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub(super) enum Part {
    /// Per-thread buffers, types 0 to 5.
    Thread = 0,
    /// Second per-thread buffers, types 6 to 11.
    SecondThread = 1,
    /// GPU buffers, types 0xd and 0xe.
    Gpu = 2,
    /// Audio, type 0xc.
    Audio = 3,
}

/// Configuration word of a capture part: the record stream it writes (0
/// or 1), or [`PartStream::OFF`]. Titles may store other values, which
/// only affect the stream mask.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PartStream(pub(super) u32);

impl PartStream {
    pub(super) const OFF: Self = Self(2);

    pub(super) fn is_off(self) -> bool {
        self == Self::OFF
    }

    /// Bit of the stream in a stream mask (`slw`: 0 from 32 on).
    pub(super) fn bit(self) -> u32 {
        if self.0 & 0x20 == 0 {
            1 << (self.0 & 0x1f)
        } else {
            0
        }
    }
}

/// One of the two record streams.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub(super) enum StreamId {
    First = 0,
    Second = 1,
}

impl StreamId {
    /// Stream of a raw stream number. Only bit 0 selects: stock indexes
    /// past the two stream blocks for values above 1.
    pub(super) const fn from_raw(value: u32) -> Self {
        if value & 1 == 0 {
            Self::First
        } else {
            Self::Second
        }
    }

    pub(super) const fn raw(self) -> u32 {
        self as u32
    }
}

/// Memory a capture budget allocates from; the value is the physical
/// memory region of `MmAllocatePhysicalMemoryEx` ([`MemoryKind::region`]).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum MemoryKind {
    Title = 1,
    System = 2,
}

impl MemoryKind {
    pub(super) const fn index(self) -> usize {
        self as usize - 1
    }

    pub(super) const fn region(self) -> MemoryRegion {
        match self {
            Self::Title => MemoryRegion::Title,
            Self::System => MemoryRegion::System,
        }
    }
}

/// A 64-bit value, high word first. Stock reads and writes it as two
/// words.
#[repr(C, align(8))]
pub(super) struct Quad {
    high: AtomicU32,
    low: AtomicU32,
}

impl Quad {
    pub(super) fn get(&self) -> u64 {
        u64::from(self.high.load(Relaxed)) << 32 | u64::from(self.low.load(Relaxed))
    }

    pub(super) fn set(&self, value: u64) {
        self.high.store((value >> 32) as u32, Relaxed);
        self.low.store(value as u32, Relaxed);
    }

    /// The address kernel calls take.
    pub(super) fn as_ptr(&self) -> *mut u64 {
        // Both words are atomics, so the kernel may write through it.
        core::ptr::from_ref(self).cast_mut().cast()
    }
}

/// The ten configuration words, current at `+0` and requested at `+0x28`.
#[repr(C)]
pub(super) struct Configuration {
    /// [`PartStream`] of each [`Part`].
    pub(super) parts: [AtomicU32; 4],
    /// Hardware threads with second per-thread buffers (bit per thread).
    pub(super) second_threads: AtomicU32,
    /// PIX flags installed with the second buffers.
    pub(super) second_flags: AtomicU32,
    /// Instruction trace of a frame or an event; per-thread buffers stay
    /// off.
    pub(super) tracing: AtomicU32,
    /// Refuse GPU command buffers without spare capture buffers.
    pub(super) gpu_wait: AtomicU32,
    /// Reported in frame record `+0x2c`.
    pub(super) frame_word: AtomicU32,
    /// Title memory budget.
    pub(super) title_budget: AtomicU32,
}

impl Configuration {
    pub(super) fn part(&self, part: Part) -> PartStream {
        PartStream(self.parts[part as usize].load(Relaxed))
    }

    pub(super) fn set_part(&self, part: Part, value: PartStream) {
        self.parts[part as usize].store(value.0, Relaxed);
    }

    /// Turn every part off, one store each.
    #[inline(always)]
    pub(super) fn turn_off(&self) {
        let [thread, second_thread, gpu, audio] = &self.parts;
        thread.store(PartStream::OFF.0, Relaxed);
        second_thread.store(PartStream::OFF.0, Relaxed);
        gpu.store(PartStream::OFF.0, Relaxed);
        audio.store(PartStream::OFF.0, Relaxed);
    }

    pub(super) fn words(&self) -> &[AtomicU32; 10] {
        // SAFETY: `Configuration` is ten `AtomicU32` in `repr(C)`, the
        // layout of the array.
        unsafe { &*core::ptr::from_ref(self).cast() }
    }
}

/// An engine message: the queue entries and the message being processed.
#[repr(C)]
pub(super) struct QueueEntry {
    /// [`EngineMessage`] code; 0 for none.
    pub(super) code: AtomicU32,
    /// 0 when queued; the trace sets it when the traced event ended.
    pub(super) done: AtomicU32,
    pub(super) payload: [AtomicU32; MESSAGE_PAYLOAD_SIZE / 4],
}

impl QueueEntry {
    pub(super) fn message(&self) -> Option<EngineMessage> {
        EngineMessage::from_raw(self.code.load(Relaxed))
    }

    /// Whether the entry holds `message`.
    #[inline(always)]
    pub(super) fn is(&self, message: EngineMessage) -> bool {
        self.code.load(Relaxed) == message.raw()
    }

    pub(super) fn copy_from(&self, source: &Self) {
        self.code.store(source.code.load(Relaxed), Relaxed);
        self.done.store(source.done.load(Relaxed), Relaxed);
        for (target, source) in self.payload.iter().zip(&source.payload) {
            target.store(source.load(Relaxed), Relaxed);
        }
    }
}

pub(super) const MESSAGE_PAYLOAD_SIZE: usize = 0x50;
const QUEUE_ENTRIES: u32 = 8;

xbox360_sys::flags! {
    /// Frame record `+0xc` flags.
    pub struct FrameRecordFlags(u32) {
        /// The record has the words from `+0x30` and reports `+0x2c`.
        FULL = 0x4,
    }
}

/// A title's frame record (code 0x52) and the session's copy. Routines are
/// title addresses taking one argument, [`FrameRecord::routine_argument`].
#[repr(C)]
pub(super) struct FrameRecord {
    pub(super) unknown_00: AtomicU32,
    /// Milliseconds of the frame.
    pub(super) milliseconds: AtomicU32,
    pub(super) unknown_08: AtomicU32,
    /// [`FrameRecordFlags`] and the title's frame state bits.
    pub(super) flags: AtomicU32,
    /// GPU write cursor of the frame buffer.
    pub(super) gpu_cursor: AtomicU32,
    pub(super) unknown_14: AtomicU32,
    /// Waits until the GPU is idle; stop and pause call it.
    pub(super) stop_routine: AtomicU32,
    pub(super) routine_argument: AtomicU32,
    /// Engine state reported to the title.
    pub(super) status_version: AtomicU32,
    pub(super) revision: AtomicU32,
    pub(super) state: AtomicU32,
    pub(super) configuration_word: AtomicU32,
    /// Replay routines of video operations.
    pub(super) check_routine: AtomicU32,
    pub(super) completion_routine: AtomicU32,
    pub(super) position_routine: AtomicU32,
    pub(super) submit_routine: AtomicU32,
}

impl FrameRecord {
    /// Words before the ones a record without [`FrameRecordFlags::FULL`]
    /// may lack.
    pub(super) const SHORT_WORDS: usize = 12;
    pub(super) const EXTENSION_WORDS: usize = 4;

    pub(super) const fn new() -> Self {
        // SAFETY: atomics are valid when zeroed.
        unsafe { core::mem::zeroed() }
    }

    pub(super) fn words(&self) -> &[AtomicU32; 16] {
        // SAFETY: `FrameRecord` is sixteen `AtomicU32` in `repr(C)`.
        unsafe { &*core::ptr::from_ref(self).cast() }
    }

    /// The short words and the extension.
    pub(super) fn parts(
        &self,
    ) -> (
        &[AtomicU32; Self::SHORT_WORDS],
        &[AtomicU32; Self::EXTENSION_WORDS],
    ) {
        let (short, extension) = self.words().split_at(Self::SHORT_WORDS);
        (
            short.try_into().unwrap_or_else(|_| unreachable!()),
            extension.try_into().unwrap_or_else(|_| unreachable!()),
        )
    }
}

/// Entry of a stream's frame table: the frame index (bits 0 to 23) and
/// the sequence of the buffer that starts it.
#[repr(C)]
pub(super) struct TableEntry {
    pub(super) frame: AtomicU32,
    pub(super) sequence: AtomicU32,
}

impl TableEntry {
    /// The generation byte of the sequence.
    pub(super) fn generation(&self) -> &AtomicU8 {
        generation_byte(&self.sequence)
    }
}

/// The generation byte of a sequence word: its high byte, the first byte
/// in memory. Stock stores it alone.
fn generation_byte(sequence: &AtomicU32) -> &AtomicU8 {
    // SAFETY: the byte lies in the word and `AtomicU8` needs no alignment.
    // Byte and word accesses to a sequence happen under the session lock,
    // so they never race.
    unsafe { &*sequence.as_ptr().cast::<AtomicU8>() }
}

pub(super) const TABLE_ENTRIES: usize = 0x800;

/// A record stream: the partition it writes, its write queue, the buffers
/// waiting for the next gather write and the frame table.
#[repr(C)]
pub(super) struct Stream {
    /// Partition handle of the system process.
    pub(super) handle: AtomicU32,
    /// Partition handle the title opened.
    pub(super) title_handle: AtomicU32,
    /// Bytes of the partition the stream uses.
    pub(super) size: Quad,
    /// Sequence of the next buffer: generation in bits 24 to 31.
    pub(super) sequence: AtomicU32,
    /// Word after the sequence; code 0x3f adds 2 to the quadword of the
    /// two in stream 0.
    pub(super) sequence_low: AtomicU32,
    /// Partition offset of the next gather write.
    pub(super) offset: Quad,
    /// Ring of request addresses, its tail and its head.
    pub(super) queue: AtomicU32,
    pub(super) tail: AtomicU32,
    pub(super) head: AtomicU32,
    /// Entries of the next gather write.
    pub(super) pending: [AtomicU32; 8],
    pub(super) pending_count: AtomicU32,
    pub(super) table: [TableEntry; TABLE_ENTRIES],
    pub(super) table_index: AtomicU32,
    /// Copy of the last record appended, and its key.
    pub(super) last_record: [AtomicU32; 10],
    pub(super) last_key: AtomicU32,
}

/// Fence slot of the GPU command buffers, and the pending frame record of
/// the same layout.
#[repr(C)]
pub(super) struct FenceSlot {
    /// `flags | frame << 3`, refusal status in bits 28 to 30.
    pub(super) header: AtomicU32,
    pub(super) sequence: AtomicU32,
    /// Bytes used in the first buffer (`+8`), and buffers written (`+0xa`).
    pub(super) used: AtomicU16,
    pub(super) count: AtomicU16,
    pub(super) id: AtomicU32,
    pub(super) data: AtomicU32,
}

/// Queued audio buffer.
#[repr(C)]
pub(super) struct AudioSlot {
    pub(super) entry: AtomicU32,
    /// Bit 31: write the record; bits 7 to 30: frame.
    pub(super) flags: AtomicU32,
    pub(super) record: [AtomicU32; 3],
}

/// Ring of buffer entries: its address in the session, head and tail.
#[repr(C)]
pub(super) struct RingPosition {
    pub(super) head: AtomicU32,
    pub(super) tail: AtomicU32,
}

/// Snapshot of a stream's position and frame table (stock 0x91f5cfb0),
/// which replay routines read.
#[repr(C)]
pub(super) struct DumpHeader {
    pub(super) stream: AtomicU32,
    pub(super) frame: AtomicU32,
    pub(super) reserved: [AtomicU32; 10],
    pub(super) units: AtomicU32,
    pub(super) sequence: AtomicU32,
    pub(super) entries: AtomicU32,
    pub(super) table_index: AtomicU32,
    pub(super) table: [TableEntry; TABLE_ENTRIES],
}

/// Audio samples staged until a buffer is ready. Only code 0x5b writes and
/// reads them, which the XAudio render thread calls.
#[repr(C)]
pub(super) struct AudioStage(pub(super) [AtomicU16; AUDIO_BUFFER_SAMPLES]);

pub(super) const AUDIO_BUFFER_SAMPLES: usize = 0x2000;

/// Temporary block state of a per-thread buffer.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum TemporaryState {
    None = 0,
    /// A raised-level writer switched to the temporary block.
    InUse = 1,
    /// A new buffer is ready; the block's records are still to be merged.
    Merge = 2,
}

impl TemporaryState {
    /// State of a raw word; values above 2 merge, as stock.
    pub(super) const fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::InUse,
            _ => Self::Merge,
        }
    }
}

/// Per-thread buffer types with a temporary block.
pub(super) const TEMPORARY_BLOCKS: usize = 13;
/// Bytes of a temporary block.
pub(super) const TEMPORARY_BYTES: u32 = 0x800;

/// Memory budget switches and overrides of code 0x56.
#[repr(C)]
pub(super) struct Budget {
    pub(super) enabled: AtomicU32,
    pub(super) title_enabled: AtomicU32,
    pub(super) override_title: AtomicU32,
    pub(super) title_size: AtomicU32,
    pub(super) override_system: AtomicU32,
    pub(super) system_size: AtomicU32,
}

/// The session block.
#[repr(C)]
pub(super) struct PixSession {
    pub(super) configuration: Configuration,
    pub(super) requested: Configuration,
    /// [`EngineFlags`].
    pub(super) flags: AtomicU32,
    /// Protocol revision reported by `pixcmd q`.
    pub(super) revision: AtomicU32,
    pub(super) lock: RtlCriticalSection,
    pub(super) engine_lock: RtlCriticalSection,
    /// Saved base priority increments of the two locks.
    pub(super) lock_priority: AtomicU32,
    pub(super) engine_lock_priority: AtomicU32,
    /// Addresses of the PCR cursors of each hardware thread's two buffers.
    pub(super) cursors: [AtomicU32; 6],
    pub(super) second_cursors: [AtomicU32; 6],
    /// Current buffer entry of each buffer type 0 to 0xe.
    pub(super) entries: [AtomicU32; 15],
    /// Record buffer entry, cursor and end of each stream.
    pub(super) record_entries: [AtomicU32; 2],
    pub(super) unknown_10c: AtomicU32,
    pub(super) record_cursors: [AtomicU32; 2],
    pub(super) record_ends: [AtomicU32; 2],
    /// Write request table, its size, and the next request.
    pub(super) requests: AtomicU32,
    pub(super) request_count: AtomicU32,
    pub(super) next_request: AtomicU32,
    /// Buffer entry table and its size, and the buffers the configuration
    /// needs.
    pub(super) buffer_table: AtomicU32,
    pub(super) buffer_count: AtomicU32,
    pub(super) needed_buffers: AtomicU32,
    /// Rings of finished frame buffers and command data buffers.
    pub(super) rings: [AtomicU32; 2],
    pub(super) ring_positions: [RingPosition; 2],
    pub(super) fence_slots: [FenceSlot; 4],
    pub(super) fence_next: AtomicU32,
    pub(super) fence_done: AtomicU32,
    pub(super) fence_ready: AtomicU32,
    /// Bytes used in the current command data buffer.
    pub(super) data_used: AtomicU32,
    /// Audio buffers are handed out.
    pub(super) audio_enabled: AtomicU32,
    /// Guards the audio rings.
    pub(super) audio_lock: KspinLock,
    pub(super) audio_ready: [AtomicU32; 4],
    pub(super) audio_ready_head: AtomicU32,
    pub(super) audio_ready_tail: AtomicU32,
    pub(super) audio_queue: [AudioSlot; 10],
    pub(super) audio_queue_head: AtomicU32,
    pub(super) audio_queue_tail: AtomicU32,
    /// Buffers taken from the table, and the completed request whose
    /// buffers are reused with the next index.
    pub(super) buffers_used: AtomicU32,
    pub(super) completed_request: AtomicU32,
    pub(super) completed_index: AtomicU32,
    /// Per [`MemoryKind`]: physical block, budget, bytes used, physical
    /// block size.
    pub(super) physical_blocks: [AtomicU32; 2],
    pub(super) budgets: [AtomicU32; 2],
    pub(super) used: [AtomicU32; 2],
    pub(super) physical_sizes: [AtomicU32; 2],
    pub(super) queue: [QueueEntry; QUEUE_ENTRIES as usize],
    pub(super) queue_count: AtomicU32,
    pub(super) queue_head: AtomicU32,
    pub(super) message: QueueEntry,
    /// Frames the current message has been processed for.
    pub(super) step: AtomicU32,
    /// Mask of the streams the configuration writes.
    pub(super) streams_mask: AtomicU32,
    pub(super) frame_record: FrameRecord,
    /// XAM export 0x1f0, the capture size routine.
    pub(super) capture_size_routine: AtomicU32,
    pub(super) streams: [Stream; 2],
    /// Per-thread buffer state while a raised-level writer uses the
    /// temporary block: the saved cursor, the [`TemporaryState`] and the
    /// block.
    pub(super) saved_cursors: [AtomicU32; TEMPORARY_BLOCKS],
    pub(super) temporary_states: [AtomicU32; TEMPORARY_BLOCKS],
    pub(super) temporary_blocks: [AtomicU32; TEMPORARY_BLOCKS],
    pub(super) swap_routine_registered: AtomicU32,
    pub(super) allocation_attempted: AtomicU32,
    pub(super) budget: Budget,
    pub(super) dump_header: DumpHeader,
    /// Lock recursion override used while the engine calls out.
    pub(super) lock_override: AtomicU32,
    pub(super) paused: AtomicU32,
    pub(super) video: VideoContext,
    pub(super) render_client: RenderClient,
    /// Last fence the GPU reported, and the last one serviced.
    pub(super) fence: AtomicU32,
    pub(super) fence_serviced: AtomicU32,
    /// Command data buffers outstanding.
    pub(super) outstanding: AtomicU32,
    pub(super) pending_frame: FenceSlot,
    /// Frame start times, indexed by the low five bits of the frame index.
    pub(super) frame_times: [AtomicU32; FRAME_TIME_SLOTS],
    /// The `Ccap` record was dropped and is retried.
    pub(super) capture_record_dropped: AtomicU32,
    /// Time of the last command data allocation, threads ending, and the
    /// command data rate budget.
    pub(super) last_allocation: AtomicU32,
    pub(super) thread_writes: AtomicU32,
    pub(super) allocation_budget: AtomicU32,
    _reserved_e218: [AtomicU32; 0x1a],
    pub(super) audio_stage: AudioStage,
    pub(super) staged: AtomicU32,
    pub(super) dropped: AtomicU32,
    /// Monitor record flags saved by the pause.
    pub(super) caller_flags: AtomicU32,
    pub(super) audio_thread_flags: AtomicU32,
    /// XAudio client of the pause.
    pub(super) audio_client: AtomicU32,
    /// Kernel export 0x2d4.
    pub(super) kernel_routine: AtomicU32,
    /// Context swap records lost per hardware thread.
    pub(super) lost: [AtomicU32; 6],
    pub(super) marker_timer: Ktimer,
    pub(super) marker_dpc: Kdpc,
    /// A raised-level writer wants the server pass to replace buffers.
    pub(super) pending_service: AtomicU32,
    _reserved_122f8: [AtomicU32; 0x22],
}

pub(super) const FRAME_TIME_SLOTS: usize = 32;

const _: () = {
    use core::mem::offset_of;
    use core::mem::size_of;
    assert!(size_of::<Configuration>() == 0x28);
    assert!(size_of::<QueueEntry>() == 0x58);
    assert!(size_of::<FrameRecord>() == 0x40);
    assert!(size_of::<FenceSlot>() == 0x14);
    assert!(size_of::<AudioSlot>() == 0x14);
    assert!(size_of::<Stream>() == 0x4080);
    assert!(offset_of!(Stream, size) == 8);
    assert!(offset_of!(Stream, sequence) == 0x10);
    assert!(offset_of!(Stream, offset) == 0x18);
    assert!(offset_of!(Stream, queue) == 0x20);
    assert!(offset_of!(Stream, pending) == 0x2c);
    assert!(offset_of!(Stream, pending_count) == 0x4c);
    assert!(offset_of!(Stream, table) == 0x50);
    assert!(offset_of!(Stream, table_index) == 0x4050);
    assert!(offset_of!(Stream, last_record) == 0x4054);
    assert!(offset_of!(Stream, last_key) == 0x407c);
    assert!(size_of::<DumpHeader>() == 0x4040);
    assert!(offset_of!(DumpHeader, units) == 0x30);
    assert!(offset_of!(DumpHeader, table) == 0x40);
    assert!(offset_of!(PixSession, requested) == 0x28);
    assert!(offset_of!(PixSession, flags) == 0x50);
    assert!(offset_of!(PixSession, revision) == 0x54);
    assert!(offset_of!(PixSession, lock) == 0x58);
    assert!(offset_of!(PixSession, engine_lock) == 0x74);
    assert!(offset_of!(PixSession, lock_priority) == 0x90);
    assert!(offset_of!(PixSession, engine_lock_priority) == 0x94);
    assert!(offset_of!(PixSession, cursors) == 0x98);
    assert!(offset_of!(PixSession, second_cursors) == 0xb0);
    assert!(offset_of!(PixSession, entries) == 0xc8);
    assert!(offset_of!(PixSession, record_entries) == 0x104);
    assert!(offset_of!(PixSession, record_cursors) == 0x110);
    assert!(offset_of!(PixSession, record_ends) == 0x118);
    assert!(offset_of!(PixSession, requests) == 0x120);
    assert!(offset_of!(PixSession, buffer_table) == 0x12c);
    assert!(offset_of!(PixSession, needed_buffers) == 0x134);
    assert!(offset_of!(PixSession, rings) == 0x138);
    assert!(offset_of!(PixSession, ring_positions) == 0x140);
    assert!(offset_of!(PixSession, fence_slots) == 0x150);
    assert!(offset_of!(PixSession, fence_next) == 0x1a0);
    assert!(offset_of!(PixSession, data_used) == 0x1ac);
    assert!(offset_of!(PixSession, audio_enabled) == 0x1b0);
    assert!(offset_of!(PixSession, audio_lock) == 0x1b4);
    assert!(offset_of!(PixSession, audio_ready) == 0x1b8);
    assert!(offset_of!(PixSession, audio_ready_head) == 0x1c8);
    assert!(offset_of!(PixSession, audio_queue) == 0x1d0);
    assert!(offset_of!(PixSession, audio_queue_head) == 0x298);
    assert!(offset_of!(PixSession, buffers_used) == 0x2a0);
    assert!(offset_of!(PixSession, physical_blocks) == 0x2ac);
    assert!(offset_of!(PixSession, budgets) == 0x2b4);
    assert!(offset_of!(PixSession, used) == 0x2bc);
    assert!(offset_of!(PixSession, physical_sizes) == 0x2c4);
    assert!(offset_of!(PixSession, queue) == 0x2cc);
    assert!(offset_of!(PixSession, queue_count) == 0x58c);
    assert!(offset_of!(PixSession, queue_head) == 0x590);
    assert!(offset_of!(PixSession, message) == 0x594);
    assert!(offset_of!(PixSession, step) == 0x5ec);
    assert!(offset_of!(PixSession, streams_mask) == 0x5f0);
    assert!(offset_of!(PixSession, frame_record) == 0x5f4);
    assert!(offset_of!(PixSession, capture_size_routine) == 0x634);
    assert!(offset_of!(PixSession, streams) == 0x638);
    assert!(offset_of!(PixSession, saved_cursors) == 0x8738);
    assert!(offset_of!(PixSession, temporary_states) == 0x876c);
    assert!(offset_of!(PixSession, temporary_blocks) == 0x87a0);
    assert!(offset_of!(PixSession, swap_routine_registered) == 0x87d4);
    assert!(offset_of!(PixSession, allocation_attempted) == 0x87d8);
    assert!(offset_of!(PixSession, budget) == 0x87dc);
    assert!(offset_of!(PixSession, dump_header) == 0x87f4);
    assert!(offset_of!(PixSession, lock_override) == 0xc834);
    assert!(offset_of!(PixSession, paused) == 0xc838);
    assert!(offset_of!(PixSession, video) == 0xc83c);
    assert!(offset_of!(PixSession, render_client) == 0xc930);
    assert!(offset_of!(PixSession, fence) == 0xe168);
    assert!(offset_of!(PixSession, outstanding) == 0xe170);
    assert!(offset_of!(PixSession, pending_frame) == 0xe174);
    assert!(offset_of!(PixSession, frame_times) == 0xe188);
    assert!(offset_of!(PixSession, capture_record_dropped) == 0xe208);
    assert!(offset_of!(PixSession, last_allocation) == 0xe20c);
    assert!(offset_of!(PixSession, thread_writes) == 0xe210);
    assert!(offset_of!(PixSession, allocation_budget) == 0xe214);
    assert!(offset_of!(PixSession, audio_stage) == 0xe280);
    assert!(offset_of!(PixSession, staged) == 0x1_2280);
    assert!(offset_of!(PixSession, caller_flags) == 0x1_2288);
    assert!(offset_of!(PixSession, audio_client) == 0x1_2290);
    assert!(offset_of!(PixSession, kernel_routine) == 0x1_2294);
    assert!(offset_of!(PixSession, lost) == 0x1_2298);
    assert!(offset_of!(PixSession, marker_timer) == 0x1_22b0);
    assert!(offset_of!(PixSession, marker_dpc) == 0x1_22d8);
    assert!(offset_of!(PixSession, pending_service) == 0x1_22f4);
    assert!(size_of::<PixSession>() == 0x1_2380);
};

impl PixSession {
    /// Address of the block, as title routines receive it.
    pub(super) fn address(&self) -> u32 {
        crate::kernel::address_of(self)
    }

    pub(super) fn engine_flags(&self) -> EngineFlags {
        EngineFlags::from_bits_retain(self.flags.load(Relaxed))
    }

    pub(super) fn set_engine_flags(&self, flags: EngineFlags) {
        self.flags.store(flags.bits(), Relaxed);
    }

    pub(super) fn frame_index(&self) -> u32 {
        self.engine_flags().frame_index()
    }

    pub(super) fn stream(&self, id: StreamId) -> &Stream {
        &self.streams[id as usize]
    }

    #[inline(always)]
    pub(super) fn temporary_state(&self, index: usize) -> TemporaryState {
        TemporaryState::from_raw(self.temporary_states[index].load(Relaxed))
    }

    #[inline(always)]
    pub(super) fn set_temporary_state(&self, index: usize, state: TemporaryState) {
        self.temporary_states[index].store(state as u32, Relaxed);
    }

    /// Take the block lock (stock 0x91f5c2b0) and save the priority.
    #[inline(always)]
    pub(super) fn enter_lock(&self) {
        enter(&self.lock, &self.lock_priority);
    }

    /// Release the block lock and restore the priority (stock 0x91f5c350).
    #[inline(always)]
    pub(super) fn leave_lock(&self) {
        leave(&self.lock, &self.lock_priority);
    }

    #[inline(always)]
    pub(super) fn enter_engine_lock(&self) {
        enter(&self.engine_lock, &self.engine_lock_priority);
    }

    #[inline(always)]
    pub(super) fn leave_engine_lock(&self) {
        leave(&self.engine_lock, &self.engine_lock_priority);
    }
}

/// The session block, or 0.
static SESSION: AtomicU32 = AtomicU32::new(0);

/// The session, when one was created.
pub(super) fn session() -> Option<&'static PixSession> {
    let block = SESSION.load(core::sync::atomic::Ordering::Acquire);
    if block == 0 {
        return None;
    }
    // SAFETY: `create` publishes a zeroed, initialized pool block of the
    // session's size and alignment that is never freed, and the session
    // is only reached through atomics and kernel objects.
    Some(unsafe { crate::kernel::object_at::<PixSession>(block) })
}

/// XAM builds with the feature query: `FEATURE_FIRST..FEATURE_END`, and
/// from `FEATURE_CURRENT` on.
const FEATURE_FIRST: u32 = 0x2029_dc00;
const FEATURE_END: u32 = 0x202a_f701;
const FEATURE_CURRENT: u32 = 0x202f_f100;

/// Whether XAM feature `feature` is enabled (stock 0x91f521a8). Other XAM
/// builds have every feature; these ask XAM export 0x200.
pub(super) fn xam_feature_enabled(feature: u32) -> bool {
    const FEATURE_QUERY: Ordinal = Ordinal::new(0x200).unwrap();
    static QUERY: AtomicU32 = AtomicU32::new(0);
    let version = xam::XamGetSystemVersion();
    if !(FEATURE_FIRST..FEATURE_END).contains(&version) && version < FEATURE_CURRENT {
        return true;
    }
    let mut query = QUERY.load(core::sync::atomic::Ordering::Acquire);
    if query == 0 {
        let Ok(address) = SystemModule::Xam
            .handle()
            .and_then(|xam| resolve_export(xam, FEATURE_QUERY))
        else {
            return true;
        };
        query = address.raw();
        QUERY.store(query, core::sync::atomic::Ordering::Release);
    }
    // SAFETY: XAM export 0x200 takes one argument, a feature number.
    (unsafe { kernel::call_export(query, feature, 0, 0, 0) }) != 0
}

/// D3D build of the running XAM, as `pixcmd q` reports it.
#[inline(always)]
pub(super) fn xam_build() -> u32 {
    (xam::XamGetSystemVersion() & 0x1fff_ff00) >> 8
}

/// Capture buffer size the title's D3D version calls for (stock
/// 0x91f5c4e0); `pixcmd q` reports it.
pub(super) fn capture_buffer_size() -> u32 {
    const FEATURE_QUERY_BUILD: u32 = 0x2f7d;
    let build = xam_build();
    // Stock queries the feature for these builds although every build
    // from 0x211f gets the same size.
    if build >= FEATURE_QUERY_BUILD {
        xam_feature_enabled(STREAMING_FEATURE);
    }
    if build >= 0x211f {
        0x6_0000
    } else if build >= 0x19fa {
        0x1c_0000
    } else if build >= 0x1676 {
        0x2c_0000
    } else {
        0
    }
}

const PIX_STREAM: &[u8] = b"\\Device\\Harddisk0\\PixStream";
const PIX_DUMP: &[u8] = b"\\Device\\Harddisk0\\PixDump";
/// Dump partitions are used in 128 KiB units.
const DUMP_UNIT: i64 = 0x2_0000;
/// Critical section spin count of the two locks.
const LOCK_SPIN_COUNT: u32 = 10;
/// Generation byte of the frame table sequences of an empty stream.
pub(super) const EMPTY_GENERATION: u8 = 0xcc;
/// XAM export of the capture size routine.
const CAPTURE_SIZE_EXPORT: Ordinal = Ordinal::new(0x1f0).unwrap();
/// Kernel export of the engine's kernel routine.
const KERNEL_ROUTINE_EXPORT: Ordinal = Ordinal::new(0x2d4).unwrap();
/// Protocol revisions with and without the kernel routine.
const REVISION_KERNEL_ROUTINE: u32 = 0x5d;
const REVISION: u32 = 0x55;

/// Create the session (stock 0x91f5c560); `false` when streaming is
/// disabled or the block cannot be allocated.
pub(super) fn create() -> bool {
    if !xam_feature_enabled(STREAMING_FEATURE) {
        return false;
    }
    // SAFETY: allocates from the system pool; no pointer arguments.
    let block = unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(
            size_of::<PixSession>() as u32,
            POOL_TAG,
            PoolType::System,
        )
    };
    if block == 0 {
        return false;
    }
    let pointer = core::ptr::with_exposed_provenance_mut::<PixSession>(block as usize);
    // SAFETY: a fresh pool block of the session's size, aligned for it
    // (pool blocks are 16-byte aligned), not yet shared; zero is a valid
    // session.
    let session = unsafe {
        pointer.write_bytes(0, 1);
        &*pointer
    };
    // SAFETY: both sections lie in the fresh, zeroed block, which is never
    // freed.
    unsafe {
        xboxkrnl::RtlInitializeCriticalSectionAndSpinCount(session.lock.as_ptr(), LOCK_SPIN_COUNT);
        xboxkrnl::RtlInitializeCriticalSectionAndSpinCount(
            session.engine_lock.as_ptr(),
            LOCK_SPIN_COUNT,
        );
    }
    let mut path = PIX_STREAM;
    let mut device = reference_device(path);
    if device.is_none() {
        path = PIX_DUMP;
        device = reference_device(path);
    }
    if let Some(device) = device {
        /// Device flag the monitor sets on the device of the dump
        /// partition.
        const DUMP: DeviceObjectFlags = DeviceObjectFlags::from_bits_retain(0x1);
        // SAFETY: `device` is the device object referenced above; its
        // flags change under the device object lock, which is released
        // before the reference is dropped.
        unsafe {
            let irql = xboxkrnl::IoAcquireDeviceObjectLock();
            (*device).flags.insert(DUMP);
            xboxkrnl::IoReleaseDeviceObjectLock(irql);
            xboxkrnl::ObDereferenceObject(device.addr() as u32);
        }
    }
    if let Some(handle) = open_device(path) {
        let stream = &session.streams[0];
        stream.handle.store(handle, Relaxed);
        let mut io_status = IoStatusBlock::default();
        let mut size = FsSizeInformation::default();
        // SAFETY: `handle` is the open partition; `size` is the output
        // buffer of the passed length.
        unsafe {
            xboxkrnl::NtQueryVolumeInformationFile(
                Handle::from_raw(handle),
                &mut io_status,
                core::ptr::from_mut(&mut size).cast(),
                size_of::<FsSizeInformation>() as u32,
                FsInformationClass::Size,
            )
        };
        // Stock multiplies the units by the sector size alone.
        let bytes = size
            .total_allocation_units
            .wrapping_mul(u64::from(size.bytes_per_sector)) as i64;
        stream.size.set((bytes / DUMP_UNIT * DUMP_UNIT) as u64);
    }
    session.message.code.store(0, Relaxed);
    session
        .render_client
        .video
        .store(crate::kernel::address_of(&session.video), Relaxed);
    session.configuration.turn_off();
    session.requested.turn_off();
    session.video.session.store(block, Relaxed);
    session.render_client.session.store(block, Relaxed);
    for entry in &session.streams[0].table {
        entry.generation().store(EMPTY_GENERATION, Relaxed);
    }
    if capture_buffer_size() != 0 {
        let routine = SystemModule::Xam
            .handle()
            .and_then(|xam| resolve_export(xam, CAPTURE_SIZE_EXPORT))
            .map_or(0, ExportAddress::raw);
        session.capture_size_routine.store(routine, Relaxed);
    }
    let routine = SystemModule::Kernel
        .handle()
        .and_then(|kernel| resolve_export(kernel, KERNEL_ROUTINE_EXPORT))
        .map_or(0, ExportAddress::raw);
    session.kernel_routine.store(routine, Relaxed);
    session.revision.store(
        if routine != 0 {
            REVISION_KERNEL_ROUTINE
        } else {
            REVISION
        },
        Relaxed,
    );
    reset_budget(session);
    SESSION.store(block, core::sync::atomic::Ordering::Release);
    true
}

/// Memory budget switches and overrides of code 0x56 at their defaults.
#[inline(always)]
pub(super) fn reset_budget(session: &PixSession) {
    session.budget.reset();
}

impl Budget {
    #[inline(never)]
    fn reset(&self) {
        self.override_title.store(0, Relaxed);
        self.enabled.store(1, Relaxed);
        self.title_enabled.store(1, Relaxed);
        self.title_size.store(0, Relaxed);
        self.override_system.store(0, Relaxed);
        self.system_size.store(0, Relaxed);
    }
}

/// Reference the device object `path` names; `None` when the lookup
/// fails.
fn reference_device(path: &[u8]) -> Option<*mut DeviceObject> {
    let mut device = 0u32;
    // SAFETY: `data_imports_resolved` held at module load.
    let object_type = unsafe { xboxkrnl::IoDeviceObjectType.get_unchecked() };
    // SAFETY: the name string and `device` are live for the call.
    let status = unsafe {
        xboxkrnl::ObReferenceObjectByName(
            &kernel::ansi_string(path),
            ObjectAttributeFlags::CASE_INSENSITIVE,
            crate::kernel::address_of(object_type),
            0,
            &mut device,
        )
    };
    status
        .is_success()
        .then(|| core::ptr::with_exposed_provenance_mut(device as usize))
}

/// Open the partition device `path` for capture writes; the handle.
fn open_device(path: &[u8]) -> Option<u32> {
    let name = kernel::ansi_string(path);
    let attributes = ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: &name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    let mut io_status = IoStatusBlock::default();
    let mut handle = Handle::NULL;
    // SAFETY: all pointers refer to live locals.
    let status: NtStatus = unsafe {
        xboxkrnl::NtCreateFile(
            &mut handle,
            AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE | AccessMask::SYNCHRONIZE,
            &attributes,
            &mut io_status,
            core::ptr::null(),
            FileAttributes::SYSTEM,
            ShareAccess::READ | ShareAccess::WRITE,
            CreateDisposition::Open,
            CreateOptions::NO_INTERMEDIATE_BUFFERING,
        )
    };
    status.is_success().then(|| handle.raw())
}

/// Open a title handle to the dump partition (stock 0x91f5cb08):
/// `PixStream`, else `PixDump`.
pub(super) fn open_partition() -> Option<u32> {
    open_device(PIX_STREAM).or_else(|| open_device(PIX_DUMP))
}

/// Priority increment while holding a session lock.
const LOCK_INCREMENT: u32 = 0xf;
/// Priorities at which the lock leaves the thread's priority alone.
const HIGH_PRIORITY: u8 = 0x12;
const HIGH_BASE_PRIORITY: u8 = 0x11;
/// Stored increment of a lock taken without a priority change.
const PRIORITY_UNCHANGED: u32 = 0x8000_0000;

/// Raised priority of a lock holder: the increment to restore, `None` when
/// the lock left the priority alone. Stored in the lock's priority word.
fn encode_priority(saved: Option<u32>) -> u32 {
    saved.unwrap_or(PRIORITY_UNCHANGED)
}

fn decode_priority(word: u32) -> Option<u32> {
    (word != PRIORITY_UNCHANGED).then_some(word)
}

fn thread_pointer(thread: &Kthread) -> *mut Kthread {
    core::ptr::from_ref(thread).cast_mut()
}

/// Raise the caller's base priority unless it is already high, then
/// enter `section` and store the increment to restore in `priority`
/// (stock 0x91f5c2b0).
fn enter(section: &RtlCriticalSection, priority: &AtomicU32) {
    let thread = current_object().kthread();
    // SAFETY: pairs with the `KeLeaveCriticalRegion` of `leave`.
    unsafe { xboxkrnl::KeEnterCriticalRegion() };
    let saved = (thread.priority.load(Relaxed) < HIGH_PRIORITY
        && thread.base_priority.load(Relaxed) < HIGH_BASE_PRIORITY
        && thread.saturation.load(Relaxed) == 0)
        .then(|| {
            // SAFETY: the current thread object.
            unsafe { xboxkrnl::KeSetBasePriorityThread(thread_pointer(thread), LOCK_INCREMENT) }
        });
    // SAFETY: an initialized critical section of the session block.
    unsafe { xboxkrnl::RtlEnterCriticalSection(section.as_ptr()) };
    priority.store(encode_priority(saved), Relaxed);
}

/// Leave `section` and restore the priority [`enter`] stored in
/// `priority` (stock 0x91f5c350); a priority changed meanwhile is put
/// back.
fn leave(section: &RtlCriticalSection, priority: &AtomicU32) {
    let saved = decode_priority(priority.load(Relaxed));
    let thread = current_object().kthread();
    // SAFETY: the session critical section [`enter`] took.
    unsafe { xboxkrnl::RtlLeaveCriticalSection(section.as_ptr()) };
    if let Some(saved) = saved {
        let base = u32::from(thread.process_priority.load(Relaxed));
        let expected = (base + LOCK_INCREMENT).min(u32::from(thread.priority_limit.load(Relaxed)));
        if u32::from(thread.base_priority.load(Relaxed)) == expected
            && thread.priority_boost.load(Relaxed) == 0
        {
            // SAFETY: the current thread object.
            let previous =
                unsafe { xboxkrnl::KeSetBasePriorityThread(thread_pointer(thread), saved) };
            if previous != expected - u32::from(thread.process_priority.load(Relaxed)) {
                kernel::debug_print(c"WRN[PIX]: Undoing thread base priority restore.\n");
                // SAFETY: as above.
                unsafe { xboxkrnl::KeSetBasePriorityThread(thread_pointer(thread), previous) };
            }
        }
    }
    // SAFETY: pairs with the `KeEnterCriticalRegion` of [`enter`].
    unsafe { xboxkrnl::KeLeaveCriticalRegion() };
}

/// The locked session (stock 0x91f5a7f0); unlocks on drop (0x91f5c350).
/// Only [`lock`] builds one.
pub(super) struct Locked(&'static PixSession);

impl Locked {
    pub(super) fn session(&self) -> &'static PixSession {
        self.0
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        self.0.leave_lock();
    }
}

pub(super) fn lock() -> Option<Locked> {
    let session = session()?;
    session.enter_lock();
    Some(Locked(session))
}

/// Queue engine message `code` with `payload` (stock 0x91f5f000). A
/// frame range message replaces the payload of a queued one. `false`
/// without a session or with a full queue.
pub(super) fn post(code: u32, payload: &[u32]) -> bool {
    let Some(locked) = lock() else { return false };
    let session = locked.0;
    let count = session.queue_count.load(Relaxed);
    let head = session.queue_head.load(Relaxed);
    let entry = |index: u32| &session.queue[((head + index) % QUEUE_ENTRIES) as usize];
    let write_payload = |entry: &QueueEntry| {
        for (target, &word) in entry.payload.iter().zip(payload) {
            target.store(word, Relaxed);
        }
    };
    if code == EngineMessage::VideoOperation.raw()
        && let Some(queued) = (0..count)
            .map(entry)
            .find(|queued| queued.is(EngineMessage::VideoOperation))
    {
        write_payload(queued);
        return true;
    }
    if count >= QUEUE_ENTRIES {
        return false;
    }
    let free = entry(count);
    free.code.store(code, Relaxed);
    free.done.store(0, Relaxed);
    write_payload(free);
    session.queue_count.store(count + 1, Relaxed);
    true
}

/// Take the oldest queued message (stock 0x91f5d3f0).
pub(super) fn next_message(session: &PixSession) -> Option<&QueueEntry> {
    let count = session.queue_count.load(Relaxed);
    if count == 0 {
        return None;
    }
    let head = session.queue_head.load(Relaxed);
    session.queue_count.store(count - 1, Relaxed);
    session.queue_head.store(
        if head + 1 < QUEUE_ENTRIES {
            head + 1
        } else {
            0
        },
        Relaxed,
    );
    Some(&session.queue[head as usize % QUEUE_ENTRIES as usize])
}

/// Put the message [`next_message`] took back at the queue head (stock
/// 0x91f617b0 on resuming).
pub(super) fn requeue_message(session: &PixSession) {
    session
        .queue_count
        .store(session.queue_count.load(Relaxed) + 1, Relaxed);
    let head = session.queue_head.load(Relaxed);
    session.queue_head.store(
        if head == 0 {
            QUEUE_ENTRIES - 1
        } else {
            head - 1
        },
        Relaxed,
    );
}

/// Status flags of `pixcmd q` that select the status words.
const MIN_STATUS_FLAGS: u32 = 3;

/// Engine status for `pixcmd q`/`p`/`u` (stock 0x91f5f130).
pub(super) fn status(version: u32, flags: u32) -> Option<[u32; 12]> {
    if version == 0 || flags & MIN_STATUS_FLAGS == 0 {
        return None;
    }
    let locked = lock()?;
    let session = locked.0;
    let dump = session.streams[0].size.get() as i64;
    let record = &session.frame_record;
    Some([
        STATUS_VERSION,
        session.revision.load(Relaxed),
        record.milliseconds.load(Relaxed),
        record.flags.load(Relaxed),
        record.unknown_08.load(Relaxed),
        xam_build(),
        capture_buffer_size(),
        (dump / 0x10_0000) as u32,
        u32::from(session.engine_flags().contains(EngineFlags::RUNNING)),
        session.streams_mask.load(Relaxed),
        session.budgets[MemoryKind::Title.index()].load(Relaxed),
        session.paused.load(Relaxed),
    ])
}

/// Frame rate statistics of `pixcmd m` (stock 0x91f5f230): the owner
/// callback reports two percentages and a count for `frame`, scaled by the
/// measured frame rate over the last 31 frames (at most 90).
pub(super) fn frame_statistics(frame: u32) -> Option<[u32; 3]> {
    const TICK_SECONDS: f32 = f32::from_bits(0x32ab_cc77);
    const MEASURED_FRAMES: f32 = 31.0;
    const MAX_RATE: f32 = 90.0;
    const RATE_SCALE: f32 = f32::from_bits(0x3c88_8889);
    const COUNT_SCALE: f32 = f32::from_bits(0x3655_5555);
    const PERCENT: f32 = 100.0;
    let locked = lock()?;
    let session = locked.0;
    let index = session.flags.load(Relaxed) >> EngineFlags::FRAME_SHIFT;
    let slot = |index: u32| session.frame_times[index as usize % FRAME_TIME_SLOTS].load(Relaxed);
    let ticks = slot(index.wrapping_sub(1)).wrapping_sub(slot(index));
    let rate = (MEASURED_FRAMES / (ticks as f32 * TICK_SECONDS)).min(MAX_RATE);
    let mut query = [frame, 0, 0, 0];
    events::notify_owner(
        CallbackOperation::FrameStatistics,
        query.as_mut_ptr() as usize as u32,
    );
    #[inline(never)]
    fn truncate(value: f32) -> u32 {
        value as i64 as u32
    }
    let mut out = [0u32; 3];
    if query[3] != 0 {
        let scale = rate * RATE_SCALE;
        out[0] = truncate(scale * f32::from_bits(query[1]) * PERCENT);
        out[1] = truncate(scale * f32::from_bits(query[2]) * PERCENT);
        out[2] = truncate(query[3] as f32 * scale * COUNT_SCALE * PERCENT);
    }
    Some(out)
}

xbox360_sys::flags! {
    /// Capture state bits of monitor control code 0x44.
    pub struct CaptureState(u32) {
        /// Per-thread timing capture, or an event trace message.
        TIMING = 0x1,
        /// A capture to file message.
        CAPTURE_TO_FILE = 0x2,
        /// An instruction trace records.
        INSTRUCTION_TRACE = 0x4,
        /// The performance capture buffer is allocated.
        CAPTURE_BUFFER = 0x8,
        PROFILER = 0x10,
        /// The stream ring is allocated.
        STREAM = 0x20,
        GPU = 0x40,
        AUDIO = 0x80,
    }
}

/// Monitor control code 0x44 (stock 0x91f5f3b8): capture state bits.
pub(super) fn state_flags() -> CaptureState {
    let mut flags = CaptureState::empty();
    if let Some(locked) = lock() {
        let configuration = &locked.0.configuration;
        if !configuration.part(Part::Thread).is_off() {
            flags |= CaptureState::TIMING;
        }
        if !configuration.part(Part::Gpu).is_off() {
            flags |= CaptureState::GPU;
        }
        if !configuration.part(Part::Audio).is_off() {
            flags |= CaptureState::AUDIO;
        }
        const TRACE_EVENT: u32 = EngineMessage::TraceEvent.raw();
        const CAPTURE_TO_FILE: u32 = EngineMessage::CaptureToFile.raw();
        match locked.0.message.code.load(Relaxed) {
            TRACE_EVENT => flags |= CaptureState::TIMING,
            CAPTURE_TO_FILE => flags |= CaptureState::CAPTURE_TO_FILE,
            _ => {}
        }
    }
    if super::super::xtrace::is_recording() {
        flags |= CaptureState::INSTRUCTION_TRACE;
    }
    if super::super::capture::buffer_allocated() {
        flags |= CaptureState::CAPTURE_BUFFER;
    }
    if super::super::profiler::running() {
        flags |= CaptureState::PROFILER;
    }
    if super::stream_active() {
        flags |= CaptureState::STREAM;
    }
    flags
}

/// Monitor control code 0x3f (stock 0x91f5f4b0): clearing the discard flag
/// adds two to the quadword at stream 0's sequence and to the generation
/// of stream 1.
pub(super) fn set_discard(discard: bool) {
    if super::discard_output()
        && !discard
        && let Some(locked) = lock()
    {
        let first = &locked.0.streams[0];
        let value = (u64::from(first.sequence.load(Relaxed)) << 32
            | u64::from(first.sequence_low.load(Relaxed)))
        .wrapping_add(2);
        first.sequence.store((value >> 32) as u32, Relaxed);
        first.sequence_low.store(value as u32, Relaxed);
        let generation = generation_byte(&locked.0.streams[1].sequence);
        generation.store(generation.load(Relaxed).wrapping_add(2), Relaxed);
    }
}
