//! GPU command buffer capture: frame buffers of type 0xe (code 0x51,
//! stock 0x91f5ebb0), command data buffers of type 0xd handed out per
//! frame (code 0x5c, 0x91f604c8) and released when the GPU passes the
//! frame's fence (code 0x5d, 0x91f5d718; 0x91f5f838), and the queues
//! that order them in the streams (0x91f5f558, 0x91f5f6a0, 0x91f60060).

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use xbox360::time::TickCount;
use xbox360_sys::mmio::GpuRegisters;
use xbox360_sys::mmio::GpuStatus;
use xbox360_sys::xboxkrnl;

use super::super::session::EngineFlags;
use super::super::session::FenceSlot;
use super::super::session::Part;
use super::super::session::PartStream;
use super::super::session::PixSession;
use super::super::session::RingPosition;
use super::super::session::StreamId;
use super::audio::AudioSlotFlags;
use super::buffers;
use super::buffers::BufferEntry;
use super::buffers::BufferType;
use super::buffers::HEADER_BYTES;
use super::buffers::UNIT_SHIFT;
use super::sign24;
use super::wrap;

/// Kind of a stream record, in bits 0 to 2 of its first word.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum StreamRecordKind {
    /// Frame record.
    Frame = 0,
    /// Frame record that ends a capture.
    LastFrame = 1,
    /// Buffer record.
    Buffer = 2,
    /// Frame buffers written for a frame.
    FrameBuffers = 3,
    /// Command data buffers of a GPU frame.
    GpuFrame = 4,
    /// Audio buffer.
    Audio = 5,
}

impl StreamRecordKind {
    pub(super) const MASK: u32 = 7;

    /// Kind of the record whose first word is `word`; `None` for 6 and 7.
    pub(super) const fn of(word: u32) -> Option<Self> {
        match word & Self::MASK {
            0 => Some(Self::Frame),
            1 => Some(Self::LastFrame),
            2 => Some(Self::Buffer),
            3 => Some(Self::FrameBuffers),
            4 => Some(Self::GpuFrame),
            5 => Some(Self::Audio),
            _ => None,
        }
    }
}

/// Header word of a fence slot and of the GPU frame record it becomes:
/// [`StreamRecordKind::GpuFrame`], frame in bits 3 to 26, the capture end
/// bit, and the refusal status in bits 28 to 31.
pub(super) mod fence_header {
    pub(crate) const FRAME_SHIFT: u32 = 3;
    /// Frame field in place.
    pub(crate) const FRAME_FIELD: u32 = 0x07ff_fff8;
    pub(crate) const LAST: u32 = 0x0800_0000;
    pub(crate) const STATUS_SHIFT: u32 = 28;
    pub(crate) const STATUS_MASK: u32 = 0xf000_0000;

    pub(crate) const fn frame(header: u32) -> u32 {
        header >> FRAME_SHIFT & 0x00ff_ffff
    }
}

/// Header word of a [`StreamRecordKind::FrameBuffers`] record: the bit
/// set when buffer output was not paused before it, and the frame from
/// bit 4.
pub(super) mod frame_buffers_header {
    pub(crate) const OUTPUT_CONTINUES: u32 = 8;
    pub(crate) const FRAME_SHIFT: u32 = 4;
    /// Frame field in place.
    pub(crate) const FRAME_FIELD: u32 = 0x0fff_fff0;
}

/// Reason code 0x5c refuses command data buffers, stored as the fence
/// slot status.
#[derive(Clone, Copy)]
#[repr(u32)]
pub(super) enum CommandBufferError {
    /// Less time than the rate budget allows passed since the last
    /// allocation.
    RateLimited = 1,
    /// Too few capture buffers are free while the configuration waits for
    /// them.
    NoFreeBuffers = 2,
    TooLarge = 3,
    /// GPU capture is off.
    Off = 4,
}

/// Index of the frame buffer ring in `rings` and `ring_positions`.
const FRAME_BUFFERS: usize = 0;
/// Index of the command data ring.
const COMMAND_DATA: usize = 1;
/// Fence slot words for an id and data the GPU did not report yet.
const UNREPORTED: u32 = 0x0bad_f00d;
/// Data dwords of a full frame buffer.
const FRAME_BUFFER_DWORDS: u32 = (buffers::BUFFER_BYTES - HEADER_BYTES) / 4;
/// Rate budget of command data allocations, in timebase ticks: the minimum
/// interval and the budget each allocation adds.
const MIN_INTERVAL: i32 = 0x4_3d11;
const BUDGET_REFILL: i32 = 0x8_7a23;
/// A command data buffer left open this many ticks is closed.
const IDLE_CLOSE_TICKS: u32 = 5_000_000;

/// Finished buffer ring entry: frame in bits 8 to 31 above a byte that is
/// kept, and the buffer entry.
#[repr(C)]
struct FinishedBuffer {
    tag: AtomicU32,
    entry: AtomicU32,
}

const _: () = assert!(size_of::<FinishedBuffer>() == 8);

impl FinishedBuffer {
    fn frame(&self) -> u32 {
        self.tag.load(Relaxed) >> 8
    }

    /// The buffer entry of the slot.
    ///
    /// # Safety
    ///
    /// `ring_push` must have written the slot since the ring was
    /// allocated, and the buffer table must not have been released since.
    unsafe fn entry(&self) -> &BufferEntry {
        // SAFETY: `ring_push` stores the address of a buffer table entry;
        // `buffers::free` releases the table and the rings together, so
        // the entry lives as long as the ring borrow.
        unsafe { BufferEntry::at(self.entry.load(Relaxed)) }
    }
}

/// Finished buffer ring held in the session word `ring`; empty while no
/// ring is allocated.
#[inline]
fn finished_ring<'a>(s: &PixSession, ring: &'a AtomicU32) -> &'a [FinishedBuffer] {
    let address = ring.load(Relaxed);
    if address == 0 {
        return &[];
    }
    let count = s.buffer_count.load(Relaxed);
    // SAFETY: a nonzero ring word is a pool block that
    // `buffers::try_allocate` allocated with room for `buffer_count`
    // 8-byte entries. Callers hold the session lock, under which
    // `buffers::free` releases the block and clears the word, so it stays
    // allocated while they use it; the entries are only accessed
    // atomically.
    unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance::<FinishedBuffer>(address as usize),
            count as usize,
        )
    }
}

/// The five words of a fence slot or the pending frame record, laid out as
/// the frame record it becomes.
fn slot_words(slot: &FenceSlot) -> &[AtomicU32; 5] {
    const _: () = assert!(size_of::<FenceSlot>() == size_of::<[AtomicU32; 5]>());
    // SAFETY: `FenceSlot` is `#[repr(C)]`, 4-aligned and holds only
    // atomics, two halfwords in its third word. Its halfwords are accessed
    // only by threads holding the session lock, as are these word views,
    // so the word and halfword accesses never race.
    unsafe { &*(&raw const *slot).cast::<[AtomicU32; 5]>() }
}

/// The buffer entry a session word holds; `None` for 0.
///
/// # Safety
///
/// `word` is 0 or the address of a buffer table entry that stays
/// allocated for `'a`.
pub(super) unsafe fn entry_at<'a>(word: u32) -> Option<&'a BufferEntry> {
    // SAFETY: guaranteed by the caller.
    (word != 0).then(|| unsafe { BufferEntry::at(word) })
}

fn ring_push(
    s: &PixSession,
    ring: &AtomicU32,
    position: &RingPosition,
    entry: &BufferEntry,
    frame: u32,
) {
    let head = position.head.load(Relaxed);
    let ring = finished_ring(s, ring);
    let slot = &ring[head as usize];
    slot.entry.store(entry.address(), Relaxed);
    // SAFETY: ring slots are accessed only under the session lock, so the
    // byte read races no word store.
    let kept = unsafe { super::low_byte(&slot.tag) }.load(Relaxed);
    slot.tag.store(u32::from(kept) | frame << 8, Relaxed);
    position
        .head
        .store(wrap(head + 1, ring.len() as u32), Relaxed);
}

/// Queue a finished command data buffer (stock 0x91f5cbd8).
#[inline(always)]
pub(super) fn push_finished(s: &PixSession, entry: &BufferEntry, frame: u32) {
    ring_push(
        s,
        &s.rings[COMMAND_DATA],
        &s.ring_positions[COMMAND_DATA],
        entry,
        frame,
    );
}

/// Close the frame buffer as full and queue it (stock 0x91f5cc60).
pub(super) fn close_frame_buffer(s: &PixSession) {
    let word = &s.entries[BufferType::FRAME_BUFFER.0 as usize];
    // SAFETY: the frame buffer word holds 0 or the entry `buffers::take`
    // returned; the session lock keeps the buffer table allocated.
    let Some(entry) = (unsafe { entry_at(word.load(Relaxed)) }) else {
        return;
    };
    /// Header of a full frame buffer: the type, and the data dwords from
    /// bit 8 (the layout `buffers::close` stores).
    const FULL_HEADER: u32 =
        BufferType::FRAME_BUFFER.0 | FRAME_BUFFER_DWORDS << buffers::HEADER_DWORDS_SHIFT;
    // SAFETY: the data of a buffer table entry is a 16 KiB block the
    // engine owns while the entry is out of the queues.
    let header = unsafe { super::super::words_at(entry.data(), 1) };
    header[0].store(FULL_HEADER, Relaxed);
    ring_push(
        s,
        &s.rings[FRAME_BUFFERS],
        &s.ring_positions[FRAME_BUFFERS],
        entry,
        s.frame_index(),
    );
    s.entries[BufferType::FRAME_BUFFER.0 as usize].store(0, Relaxed);
}

/// Wait up to 2000 ms while the GPU is busy (stock 0x91f5cf38).
pub(super) fn wait_for_idle() {
    const TIMEOUT_MS: u32 = 2000;
    let start = TickCount::now().milliseconds();
    while GpuRegisters::get()
        .status()
        .read()
        .contains(GpuStatus::BUSY)
        && TickCount::now().milliseconds().wrapping_sub(start) <= TIMEOUT_MS
    {
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

/// Write the frame buffers queued for `frame` and a record of them (stock
/// 0x91f5f558).
pub(super) fn flush_frame_buffers(s: &PixSession, frame: u32) {
    use frame_buffers_header::FRAME_FIELD;
    use frame_buffers_header::FRAME_SHIFT;
    use frame_buffers_header::OUTPUT_CONTINUES;
    let k = StreamId::from_raw(s.configuration.part(Part::Thread).0);
    let position = &s.ring_positions[FRAME_BUFFERS];
    let head = position.head.load(Relaxed);
    let mut tail = position.tail.load(Relaxed);
    let sequence = s.stream(k).sequence.load(Relaxed);
    let mut count = 0;
    while tail != head {
        let slot = &finished_ring(s, &s.rings[FRAME_BUFFERS])[tail as usize];
        let slot_frame = slot.frame();
        if sign24(slot_frame.wrapping_sub(frame)) != 0 {
            break;
        }
        // SAFETY: slots from the tail to the head were written by
        // `ring_push`; the session lock keeps the table allocated.
        buffers::submit(s, unsafe { slot.entry() }, slot_frame);
        tail = wrap(tail + 1, s.buffer_count.load(Relaxed));
        count += 1;
    }
    if count != 0 {
        let continues = if s.engine_flags().contains(EngineFlags::PAUSED_OUTPUT) {
            0
        } else {
            OUTPUT_CONTINUES
        };
        let record = [
            continues
                | (frame << FRAME_SHIFT & FRAME_FIELD)
                | StreamRecordKind::FrameBuffers as u32,
            sequence,
            count & 0xffff,
        ];
        buffers::append(s, k, &record);
        s.set_engine_flags(s.engine_flags().difference(EngineFlags::PAUSED_OUTPUT));
    }
    position.tail.store(tail, Relaxed);
}

/// Write the command data buffers of the fence slot `record` and the
/// record (stock 0x91f5f6a0); `last` marks the end of the capture.
pub(super) fn write_frame(s: &PixSession, mut record: [u32; 5], last: bool) {
    // SAFETY: `record` is a local array of the same layout.
    write_slot(
        s,
        unsafe { &*(&raw mut record).cast::<[AtomicU32; 5]>() },
        last,
    );
}

/// [`write_frame`] for the session's pending frame record, read in place.
pub(super) fn write_pending_frame(s: &PixSession, last: bool) {
    write_slot(s, slot_words(&s.pending_frame), last);
}

/// [`write_frame`] for the five words of a fence slot or of the pending
/// record itself, read in place. Kept out of line so that the callers of
/// [`write_frame`] share one copy.
#[inline(never)]
fn write_slot(s: &PixSession, record: &[AtomicU32; 5], last: bool) {
    let k = s.configuration.part(Part::Gpu);
    if k.is_off() {
        return;
    }
    let k = StreamId::from_raw(k.0);
    let frame = fence_header::frame(record[0].load(Relaxed));
    let position = &s.ring_positions[COMMAND_DATA];
    let head = position.head.load(Relaxed);
    let mut tail = position.tail.load(Relaxed);
    let sequence = s.stream(k).sequence.load(Relaxed);
    let mut count = 0u32;
    while tail != head {
        let slot = &finished_ring(s, &s.rings[COMMAND_DATA])[tail as usize];
        if sign24(frame.wrapping_sub(slot.frame())) < 0 {
            break;
        }
        // SAFETY: as in `flush_frame_buffers`.
        buffers::submit(s, unsafe { slot.entry() }, frame);
        tail = wrap(tail + 1, s.buffer_count.load(Relaxed));
        count += 1;
    }
    let pending = slot_words(&s.pending_frame);
    for (word, value) in pending.iter().zip(record) {
        word.store(value.load(Relaxed), Relaxed);
    }
    let mut header = (pending[0].load(Relaxed) & !fence_header::LAST)
        | if last { fence_header::LAST } else { 0 };
    pending[0].store(header, Relaxed);
    pending[1].store(sequence, Relaxed);
    s.pending_frame.count.store(count as u16, Relaxed);
    if last {
        header &= !fence_header::STATUS_MASK;
        pending[0].store(header, Relaxed);
    }
    // SAFETY: the words are atomics of the same layout, and nothing writes
    // the pending record during `append`, which only the session lock
    // holder calls.
    buffers::append(s, k, unsafe { &*(&raw const *pending).cast::<[u32; 5]>() });
    s.outstanding
        .store(s.outstanding.load(Relaxed).wrapping_sub(count), Relaxed);
    position.tail.store(tail, Relaxed);
}

/// Service the fences the GPU passed (stock 0x91f5f838); `check` stops
/// when no buffer is available.
pub(super) fn poll(s: &PixSession, check: bool) {
    let fence = s.fence.load(Relaxed);
    if fence == s.fence_serviced.load(Relaxed) || fence.wrapping_sub(s.frame_index()) << 8 == 0 {
        return;
    }
    if check && !buffers::available(s, 1) {
        return;
    }
    flush_frame_buffers(s, fence);
    loop {
        let done = s.fence_done.load(Relaxed);
        if done == s.fence_ready.load(Relaxed) {
            break;
        }
        // Slot indexes wrap at the slot count, a power of two.
        let slot = &s.fence_slots[done as usize % s.fence_slots.len()];
        if sign24(fence.wrapping_sub(fence_header::frame(slot.header.load(Relaxed)))) < 0 {
            break;
        }
        if check && !buffers::available(s, 1) {
            return;
        }
        write_slot(s, slot_words(slot), false);
        s.fence_done.store(
            wrap(s.fence_done.load(Relaxed) + 1, s.fence_slots.len() as u32),
            Relaxed,
        );
    }
    s.fence_serviced.store(fence, Relaxed);
}

/// Write the queued audio buffers, close a command data buffer left open
/// for 5,000,000 ticks, and keep four audio buffers ready (stock
/// 0x91f60060); `check` stops when no buffer is available.
pub(super) fn service(s: &PixSession, check: bool) {
    if s.audio_queue_tail.load(Relaxed) != s.audio_queue_head.load(Relaxed) {
        poll(s, true);
        let data_buffer = &s.entries[BufferType::COMMAND_DATA.0 as usize];
        if super::timebase_low().wrapping_sub(s.last_allocation.load(Relaxed)) > IDLE_CLOSE_TICKS
            // SAFETY: the command data word holds 0 or the entry
            // `buffers::take` returned; the session lock keeps the buffer
            // table allocated.
            && let Some(entry) = unsafe { entry_at(data_buffer.load(Relaxed)) }
            && s.outstanding.load(Relaxed) == 1
        {
            push_finished(
                s,
                entry,
                fence_header::frame(s.pending_frame.header.load(Relaxed)),
            );
            write_slot(s, slot_words(&s.pending_frame), true);
            data_buffer.store(0, Relaxed);
        }
        loop {
            if check && !buffers::available(s, 1) {
                break;
            }
            // SAFETY: the audio spin lock lies in the session block.
            let irql = unsafe { xboxkrnl::KfAcquireSpinLock(s.audio_lock.as_ptr()) };
            let mut queued = None;
            let tail = s.audio_queue_tail.load(Relaxed);
            // The queue indexes wrap at the queue length; an index out of
            // range reads as an empty queue.
            if tail != s.audio_queue_head.load(Relaxed)
                && let Some(slot) = s.audio_queue.get(tail as usize)
            {
                queued = Some((
                    slot.entry.load(Relaxed),
                    AudioSlotFlags::from_bits_retain(slot.flags.load(Relaxed)),
                    [
                        slot.record[0].load(Relaxed),
                        slot.record[1].load(Relaxed),
                        slot.record[2].load(Relaxed),
                    ],
                ));
                s.audio_queue_tail
                    .store(wrap(tail + 1, s.audio_queue.len() as u32), Relaxed);
            }
            // SAFETY: as above; the lock is held.
            unsafe { xboxkrnl::KfReleaseSpinLock(s.audio_lock.as_ptr(), irql) };
            let Some((Some(entry), flags, mut record)) =
                // SAFETY: `audio::queue` stores entries `gpu::service` took
                // from the buffer table, or the slot holds 0; the session
                // lock keeps the table allocated.
                queued.map(|(word, flags, record)| (unsafe { entry_at(word) }, flags, record))
            else {
                break;
            };
            let k = StreamId::from_raw(entry.info().stream());
            record[1] = s.stream(k).sequence.load(Relaxed);
            buffers::submit(s, entry, flags.frame());
            if flags.contains(AudioSlotFlags::RECORD) {
                buffers::append(s, k, &record);
            }
        }
    }
    if s.audio_enabled.load(Relaxed) == 0 {
        return;
    }
    loop {
        if check && !buffers::available(s, 1) {
            return;
        }
        let index = s.audio_ready_head.load(Relaxed);
        let next = wrap(index + 1, s.audio_ready.len() as u32);
        if next == s.audio_ready_tail.load(Relaxed) {
            return;
        }
        let entry = buffers::take(s, BufferType::FILLER, 0);
        // SAFETY: the audio spin lock lies in the session block.
        let irql = unsafe { xboxkrnl::KfAcquireSpinLock(s.audio_lock.as_ptr()) };
        // Ready ring indexes wrap at its length, a power of two.
        s.audio_ready[index as usize % s.audio_ready.len()].store(entry.address(), Relaxed);
        s.audio_ready_head.store(next, Relaxed);
        // SAFETY: as above; the lock is held.
        unsafe { xboxkrnl::KfReleaseSpinLock(s.audio_lock.as_ptr(), irql) };
    }
}

/// Argument of monitor control code 0x51.
#[repr(C)]
struct FrameBufferArgument {
    _unused: AtomicU32,
    close: AtomicU32,
    /// Address of the dword that receives the first data dword of the new
    /// frame buffer, or 0.
    output: AtomicU32,
}

/// Monitor control code 0x51 (stock 0x91f560a8 to 0x91f5ebb0). Closes the
/// open frame buffer and hands out a new one; 0xfff when one was handed
/// out.
///
/// # Safety
///
/// `argument` must be the address of a frame buffer argument whose output
/// word is 0 or the address of a writable dword, both kept valid by the
/// caller for the call.
pub(super) unsafe fn service_frame_buffer(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let argument: &FrameBufferArgument = unsafe { crate::kernel::object_at(argument) };
    let close = argument.close.load(Relaxed);
    let output = argument.output.load(Relaxed);
    // SAFETY: the caller's contract.
    let output = (output != 0).then(|| unsafe { crate::kernel::object_at::<AtomicU32>(output) });
    let Some(locked) = super::super::session::lock() else {
        return 0;
    };
    let s = locked.session();
    let k = s.configuration.part(Part::Thread);
    if k.is_off() {
        if let Some(output) = output {
            output.store(0, Relaxed);
        }
        return 0;
    }
    if close != 0 {
        close_frame_buffer(s);
    }
    let Some(output) = output else {
        return 0;
    };
    let position = &s.ring_positions[FRAME_BUFFERS];
    let count = s.buffer_count.load(Relaxed);
    let mut used = position
        .head
        .load(Relaxed)
        .wrapping_sub(position.tail.load(Relaxed)) as i32;
    if used < 0 {
        used += count as i32;
    }
    if (used as u32) + 1 >= count.wrapping_sub(s.needed_buffers.load(Relaxed)) {
        s.set_engine_flags(s.engine_flags().union(EngineFlags::PAUSED_OUTPUT));
        output.store(0, Relaxed);
        return 0;
    }
    let entry = buffers::take(s, BufferType::FRAME_BUFFER, k.0);
    s.entries[BufferType::FRAME_BUFFER.0 as usize].store(entry.address(), Relaxed);
    output.store(entry.data() + HEADER_BYTES, Relaxed);
    FRAME_BUFFER_DWORDS
}

/// Argument of monitor control code 0x5c.
#[repr(C)]
struct CommandBufferArgument {
    /// Nonzero refuses the buffers and is stored as the slot status.
    status: AtomicU32,
    bytes: AtomicU32,
    alignment: AtomicU32,
    /// Out: offset of the data in the first buffer.
    offset: AtomicU32,
    /// Address of the array that receives the buffer data addresses.
    addresses: AtomicU32,
    /// Out: buffers handed out.
    count: AtomicU32,
    /// Out: frame index.
    frame: AtomicU32,
}

/// Monitor control code 0x5c (stock 0x91f560b8 to 0x91f604c8). Hands out
/// command data buffers for `bytes` and opens a fence slot for the frame
/// with the status. 1 when buffers were handed out.
///
/// # Safety
///
/// `argument` must be the address of a command buffer argument whose
/// address array has room for an address per buffer handed out, both kept
/// valid by the caller for the call.
pub(super) unsafe fn service_command_buffers(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let argument: &CommandBufferArgument = unsafe { crate::kernel::object_at(argument) };
    let requested = argument.status.load(Relaxed);
    let Some(locked) = super::super::session::lock() else {
        return 0;
    };
    let s = locked.session();
    let now = super::timebase_low();
    let mut elapsed = now.wrapping_sub(s.last_allocation.load(Relaxed)) as i32;
    if elapsed < 0 {
        elapsed = i32::MAX;
    }
    poll(s, false);
    let (used, status) = if requested != 0 {
        (0, requested)
    } else {
        match allocate(s, argument, now, elapsed) {
            Ok(used) => (used, 0),
            Err(error) => (0, error as u32),
        }
    };
    argument.frame.store(s.frame_index(), Relaxed);
    let index = s.fence_next.load(Relaxed);
    let slot = &s.fence_slots[index as usize % s.fence_slots.len()];
    slot.header.store(
        StreamRecordKind::GpuFrame as u32
            | s.frame_index() << fence_header::FRAME_SHIFT
            | (slot.header.load(Relaxed) & fence_header::LAST)
            | status << fence_header::STATUS_SHIFT,
        Relaxed,
    );
    slot.id.store(UNREPORTED, Relaxed);
    slot.data.store(UNREPORTED, Relaxed);
    slot.used.store(used as u16, Relaxed);
    s.fence_next
        .store(wrap(index + 1, s.fence_slots.len() as u32), Relaxed);
    u32::from(status == 0)
}

/// Hand out the command data buffers of code 0x5c; the bytes used in the
/// first buffer.
fn allocate(
    s: &PixSession,
    argument: &CommandBufferArgument,
    now: u32,
    elapsed: i32,
) -> Result<u32, CommandBufferError> {
    let bytes = argument.bytes.load(Relaxed);
    let alignment = argument.alignment.load(Relaxed);
    let k = s.configuration.part(Part::Gpu);
    let count = s.buffer_count.load(Relaxed);
    let budget = s.allocation_budget.load(Relaxed) as i32;
    let mut units = bytes.wrapping_add(buffers::BUFFER_BYTES - 1) >> UNIT_SHIFT;
    if s.needed_buffers
        .load(Relaxed)
        .wrapping_add(bytes >> UNIT_SHIFT)
        .wrapping_add(1)
        > count
    {
        return Err(CommandBufferError::TooLarge);
    }
    if k == PartStream::OFF {
        return Err(CommandBufferError::Off);
    }
    if s.configuration.gpu_wait.load(Relaxed) != 0 && !buffers::available(s, (count >> 2) + units) {
        return Err(CommandBufferError::NoFreeBuffers);
    }
    if elapsed < budget || elapsed < MIN_INTERVAL {
        return Err(CommandBufferError::RateLimited);
    }
    let remaining = budget.wrapping_sub(elapsed).wrapping_add(BUDGET_REFILL);
    s.allocation_budget.store(remaining.max(0) as u32, Relaxed);
    s.last_allocation.store(now, Relaxed);
    argument.count.store(units, Relaxed);
    argument.offset.store(0, Relaxed);
    let data_buffer = &s.entries[BufferType::COMMAND_DATA.0 as usize];
    let mut used = 0u32;
    let mut addresses = argument.addresses.load(Relaxed);
    // SAFETY: as in `service`.
    if let Some(current) = unsafe { entry_at(data_buffer.load(Relaxed)) } {
        push_finished(s, current, s.frame_index());
        let offset = s
            .data_used
            .load(Relaxed)
            .wrapping_add(alignment)
            .wrapping_sub(1)
            & !alignment.wrapping_sub(1)
            & (buffers::BUFFER_BYTES - 1);
        argument.offset.store(offset, Relaxed);
        if offset == 0 {
            used = buffers::BUFFER_BYTES;
        } else {
            used = offset;
            units = offset.wrapping_add(bytes).wrapping_sub(1) >> UNIT_SHIFT;
            argument.count.store(units + 1, Relaxed);
            // SAFETY: code 0x5c passes the address of an array with room
            // for an address per buffer handed out.
            unsafe { crate::kernel::object_at::<AtomicU32>(addresses) }
                .store(current.data(), Relaxed);
            addresses = addresses.wrapping_add(4);
        }
    }
    s.data_used.store(used.wrapping_add(bytes), Relaxed);
    s.outstanding
        .store(s.outstanding.load(Relaxed).wrapping_add(units), Relaxed);
    // Stock loops about 2^32 times for a zero size; here a zero size takes
    // one buffer.
    for _ in 1..units {
        let entry = buffers::take(s, BufferType::COMMAND_DATA, k.0);
        // SAFETY: as above; `units` is below `buffer_count`.
        unsafe { crate::kernel::object_at::<AtomicU32>(addresses) }.store(entry.data(), Relaxed);
        addresses = addresses.wrapping_add(4);
        push_finished(s, entry, s.frame_index());
    }
    let entry = buffers::take(s, BufferType::COMMAND_DATA, k.0);
    data_buffer.store(entry.address(), Relaxed);
    // SAFETY: as above.
    unsafe { crate::kernel::object_at::<AtomicU32>(addresses) }.store(entry.data(), Relaxed);
    Ok(used)
}

/// Argument of monitor control code 0x5d.
#[repr(C)]
struct FenceArgument {
    /// Fence the GPU reached.
    fence: AtomicU32,
    id: AtomicU32,
    data: AtomicU32,
}

/// Monitor control code 0x5d (stock 0x91f56100 to 0x91f5d718): completes
/// the oldest open fence slot.
///
/// # Safety
///
/// `argument` must be the address of a fence argument the caller keeps
/// valid for the call.
pub(super) unsafe fn service_fence(argument: u32) -> u32 {
    // Stock dereferences the missing session.
    let Some(s) = super::super::session::session() else {
        return 1;
    };
    // SAFETY: the caller's contract.
    let argument: &FenceArgument = unsafe { crate::kernel::object_at(argument) };
    let fence = argument.fence.load(Relaxed);
    let index = s.fence_ready.load(Relaxed);
    let slot = &s.fence_slots[index as usize % s.fence_slots.len()];
    slot.id.store(argument.id.load(Relaxed), Relaxed);
    slot.data.store(argument.data.load(Relaxed), Relaxed);
    super::sync();
    s.fence_ready
        .store(wrap(index + 1, s.fence_slots.len() as u32), Relaxed);
    super::sync();
    s.fence.store(fence, Relaxed);
    1
}
