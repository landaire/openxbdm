//! Capture memory and the dump partition writer: the pool and physical
//! memory budget (stock 0x91f5c418, 0x91f5da20, 0x91f5d828), 16 KiB data
//! buffers with their record headers (0x91f5e360, 0x91f5e418), and the
//! asynchronous gather writes of eight buffers per request to the
//! `PixStream`/`PixDump` partition (0x91f5e090, 0x91f5de90, 0x91f5c9b0).
//!
//! A buffer entry is 8 bytes `{data, info}`; `info` holds the stream in
//! bits 30-31, the buffer type in bits 25-29 and the frame index in bits
//! 1-24. The first dword of the data is the header `type | dwords << 8`.

use core::num::NonZeroU32;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_server::commands::memory::PAGE_SIZE;
use xbox360::time::Timebase;
use xbox360_sys::processor;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::EventType;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::NtStatus;
use xbox360_sys::xboxkrnl::NtWriteFileGather;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::WaitType;

use super::super::RecordTag;
use super::super::session;
use super::super::session::EngineFlags;
use super::super::session::MemoryKind;
use super::super::session::POOL_TAG;
use super::super::session::Part;
use super::super::session::PartStream;
use super::super::session::PixSession;
use super::super::session::Stream;
use super::super::session::StreamId;
use super::super::session::TABLE_ENTRIES;
use super::super::session::TEMPORARY_BYTES;
use super::cached;
use super::gpu::StreamRecordKind;
use super::wrap;

/// Type of a capture buffer, in its header and its entry's info word.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct BufferType(pub(super) u32);

impl BufferType {
    /// Second per-thread buffers follow the six per-thread types.
    pub(super) const SECOND_THREAD: u32 = 6;
    pub(super) const AUDIO: Self = Self(0xc);
    pub(super) const COMMAND_DATA: Self = Self(0xd);
    pub(super) const FRAME_BUFFER: Self = Self(0xe);
    /// Record buffers of stream 0; stream 1's is the next type.
    pub(super) const RECORDS: Self = Self(0xf);
    /// Untyped buffer: the empty buffer that completes a gather write at
    /// stop, and the buffers `gpu::service` takes for the audio ready ring
    /// before `audio::ready_buffer` types them.
    pub(super) const FILLER: Self = Self(0x11);

    /// Record buffer type of stream `k`.
    pub(super) const fn records(k: StreamId) -> Self {
        Self(Self::RECORDS.0 + k.raw())
    }
}

/// Info word of a buffer entry: stream in bits 30 and 31, buffer type in
/// bits 25 to 29, frame index in bits 1 to 24; bit 0 is kept.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct BufferInfo(pub(super) u32);

impl BufferInfo {
    /// Info of a buffer of `kind` on stream `k` taken at the frame of
    /// `flags`, keeping bit 0 of `previous`.
    pub(super) const fn new(k: u32, kind: BufferType, flags: EngineFlags, previous: Self) -> Self {
        Self((k << 5 | kind.0) << 25 | (flags.bits() >> 4 & 0x01ff_fffe) | (previous.0 & 1))
    }

    /// Stream (arithmetic shift, as stock).
    pub(super) const fn stream(self) -> u32 {
        ((self.0 as i32) >> 30) as u32
    }

    pub(super) const fn kind(self) -> BufferType {
        BufferType(self.0 >> 25 & 0x1f)
    }

    pub(super) const fn frame(self) -> u32 {
        self.0 >> 1 & 0x00ff_ffff
    }
}

/// A buffer entry of the session's buffer table: the 16 KiB data block
/// and its [`BufferInfo`]. Session words, rings and requests hold entries
/// by address.
#[repr(C)]
pub(super) struct BufferEntry {
    pub(super) data: AtomicU32,
    pub(super) info: AtomicU32,
}

impl BufferEntry {
    /// The entry at `address`.
    ///
    /// # Safety
    ///
    /// `address` must be the address of an entry of the session's buffer
    /// table, which stays allocated for `'a`.
    pub(super) unsafe fn at<'a>(address: u32) -> &'a Self {
        // SAFETY: guaranteed by the caller.
        unsafe { crate::kernel::object_at::<Self>(address) }
    }

    /// The address session words and rings hold.
    pub(super) fn address(&self) -> u32 {
        crate::kernel::address_of(self)
    }

    pub(super) fn data(&self) -> u32 {
        self.data.load(Relaxed)
    }

    pub(super) fn info(&self) -> BufferInfo {
        BufferInfo(self.info.load(Relaxed))
    }
}

/// A gather write or read request of the request table: its I/O status
/// block, event, whether a title waits on the event, the thread that
/// issued it, and the entries of the eight buffers it writes.
#[repr(C)]
pub(super) struct WriteRequest {
    /// [`IoStatusBlock`] status; the kernel stores the result.
    pub(super) status: AtomicU32,
    pub(super) information: AtomicU32,
    pub(super) event: AtomicU32,
    pub(super) has_event: AtomicU32,
    pub(super) thread: AtomicU32,
    pub(super) buffers: [AtomicU32; REQUEST_BUFFERS as usize],
}

const _: () = assert!(size_of::<BufferEntry>() == 8);
const _: () = assert!(size_of::<WriteRequest>() == 0x34);

impl WriteRequest {
    /// The request at `address`.
    ///
    /// # Safety
    ///
    /// `address` must be the address of a request of the session's request
    /// table, which stays allocated for `'a`.
    unsafe fn at<'a>(address: u32) -> &'a Self {
        // SAFETY: guaranteed by the caller.
        unsafe { crate::kernel::object_at::<Self>(address) }
    }

    /// The address the stream queues hold.
    fn address(&self) -> u32 {
        crate::kernel::address_of(self)
    }

    /// Whether the kernel has not completed the request.
    fn pending(&self) -> bool {
        self.status.load(Relaxed) == NtStatus::PENDING.0
    }

    /// The I/O status block the kernel completes: the status and
    /// information words.
    fn status_block(&self) -> *mut IoStatusBlock {
        // Both words are atomics, so the kernel may write through it.
        core::ptr::from_ref(self).cast_mut().cast()
    }
}

pub(super) const BUFFER_BYTES: u32 = 0x4000;
/// Header word at the start of a buffer's data, `type | dwords << 8` with
/// the data dwords after it; records follow it.
pub(super) const HEADER_BYTES: u32 = 4;
pub(super) const HEADER_DWORDS_SHIFT: u32 = 8;
/// Partition offsets and command data sizes are in units of one buffer.
pub(super) const UNIT_SHIFT: u32 = BUFFER_BYTES.trailing_zeros();
const REQUEST_SIZE: u32 = size_of::<WriteRequest>() as u32;
const REQUEST_BUFFERS: u32 = 8;
/// Large page size; physical blocks start on a large page.
const LARGE_PAGE: u32 = 0x1_0000;

/// `bytes` rounded up to a large page.
const fn round_up(bytes: u32) -> u32 {
    bytes.wrapping_add(LARGE_PAGE - 1) & !(LARGE_PAGE - 1)
}

/// Requests for `buffers` buffers: one per eight, and one more.
const fn requests_for(buffers: u32) -> u32 {
    ((buffers + REQUEST_BUFFERS - 1) / REQUEST_BUFFERS) + 1
}

/// The request table.
fn request_table(s: &PixSession) -> &[WriteRequest] {
    let table = s.requests.load(Relaxed);
    if table == 0 {
        return &[];
    }
    // SAFETY: the nonzero `requests` word.
    unsafe { requests_at(s, table) }
}

/// The request table at `table`.
///
/// # Safety
///
/// `table` must be the nonzero `requests` word of `s`.
unsafe fn requests_at(s: &PixSession, table: u32) -> &[WriteRequest] {
    // SAFETY: a nonzero `requests` is the table `try_allocate` allocated
    // for `request_count` requests; `free` releases it only after the
    // engine stopped using it.
    unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance::<WriteRequest>(table as usize),
            s.request_count.load(Relaxed) as usize,
        )
    }
}

/// Entry `index` of the buffer table.
///
/// # Safety
///
/// `index` must be below `buffer_count`.
unsafe fn entry_at(s: &PixSession, index: u32) -> &BufferEntry {
    let address = s
        .buffer_table
        .load(Relaxed)
        .wrapping_add(index * size_of::<BufferEntry>() as u32);
    // SAFETY: entries below a nonzero `buffer_count` lie in the table
    // `try_allocate` allocated; `free` releases it after the engine
    // stopped using its entries.
    unsafe { BufferEntry::at(address) }
}

/// Slot `index` of `stream`'s queue of request addresses.
fn queue_slot(stream: &Stream, index: u32) -> &AtomicU32 {
    // SAFETY: `try_allocate` sizes each queue for at least `request_count`
    // addresses, and queue indexes wrap below `request_count`; the queue
    // stays allocated until `free`, which runs with the queues drained.
    unsafe {
        crate::kernel::object_at::<AtomicU32>(stream.queue.load(Relaxed).wrapping_add(index * 4))
    }
}

/// The request queued at `index` of `stream`'s queue.
fn queued(stream: &Stream, index: u32) -> &WriteRequest {
    // SAFETY: `submit` stores only request table addresses in the queue
    // slots between head and tail.
    unsafe { WriteRequest::at(queue_slot(stream, index).load(Relaxed)) }
}

/// Store the header of `entry`'s data: `kind` and the dwords before
/// `cursor`.
pub(super) fn close(entry: &BufferEntry, kind: BufferType, cursor: u32) {
    let data = entry.data();
    // SAFETY: the data of a buffer table entry is a 16 KiB block the engine
    // owns while the entry is out of the queues.
    let header = unsafe { super::super::words_at(data, 1) };
    let dwords = (cursor.wrapping_sub(data).wrapping_sub(HEADER_BYTES) as i32) >> 2;
    header[0].store(kind.0 | (dwords as u32) << HEADER_DWORDS_SHIFT, Relaxed);
}

/// Allocate `size` zeroed bytes against the system budget, else the title
/// budget (stock 0x91f5c418).
pub(super) fn allocate(s: &PixSession, size: u32) -> u32 {
    for &(kind, pool_type) in &[
        (MemoryKind::System, PoolType::System),
        (MemoryKind::Title, PoolType::Title),
    ] {
        let used = &s.used[kind.index()];
        if used.load(Relaxed).wrapping_add(size) <= s.budgets[kind.index()].load(Relaxed) {
            // SAFETY: allocates from the pool; no pointer arguments.
            let block = unsafe { xboxkrnl::ExAllocatePoolTypeWithTag(size, POOL_TAG, pool_type) };
            if block != 0 {
                // SAFETY: a fresh pool block of `size` bytes, not yet shared.
                unsafe {
                    core::ptr::write_bytes(
                        core::ptr::with_exposed_provenance_mut::<u8>(block as usize),
                        0,
                        size as usize,
                    )
                };
                used.store(used.load(Relaxed).wrapping_add(size), Relaxed);
                return block;
            }
        }
    }
    0
}

/// [`allocate`] into `slot`; `None` when it failed.
fn allocate_into(s: &PixSession, slot: &AtomicU32, size: u32) -> Option<NonZeroU32> {
    let block = allocate(s, size);
    slot.store(block, Relaxed);
    NonZeroU32::new(block)
}

/// Buffers the configuration needs (stock 0x91f5c820).
fn needed(s: &PixSession) -> u32 {
    /// Buffers each part needs, in [`Part`] order.
    const PART_BUFFERS: [u32; 4] = [7, 6, 0x11, 3];
    /// Bits of the two streams in a stream mask.
    const STREAMS: u32 = 0b11;
    let mut count = 0;
    let mut streams = 0u32;
    for (part, &extra) in s.configuration.parts.iter().zip(&PART_BUFFERS) {
        let k = PartStream(part.load(Relaxed));
        if !k.is_off() {
            count += extra;
            streams |= k.bit();
        }
    }
    // Each stream may hold the eight buffers of its next gather write.
    count + REQUEST_BUFFERS * (streams & STREAMS).count_ones()
}

/// Write back the data cache lines of `[start, end)` (stock 0x91f5d778).
pub(super) fn flush(start: u32, end: u32) {
    const LINE: u32 = 0x80;
    let mut line = start & !(LINE - 1);
    while line < (end.wrapping_add(LINE - 1) & !(LINE - 1)) {
        // SAFETY: flushes one cache line of memory the engine owns.
        unsafe { core::arch::asm!("dcbf 0, {0}", in(reg) line, options(nostack)) };
        line += LINE;
    }
    super::sync();
}

/// Release every capture allocation (stock 0x91f5d828).
pub(super) fn free(s: &PixSession) {
    for &kind in &[MemoryKind::System, MemoryKind::Title] {
        let index = kind.index();
        let address = s.physical_blocks[index].load(Relaxed);
        if address != 0 {
            let start = cached(address);
            flush(
                start,
                start.wrapping_add(s.physical_sizes[index].load(Relaxed)),
            );
            // SAFETY: the physical block of this kind that `try_allocate`
            // allocated; its slot is cleared below.
            unsafe { xboxkrnl::MmFreePhysicalMemory(kind.region(), address) };
            s.physical_blocks[index].store(0, Relaxed);
            s.physical_sizes[index].store(0, Relaxed);
        }
        s.budgets[index].store(0, Relaxed);
        s.used[index].store(0, Relaxed);
    }
    let release = |slot: &AtomicU32| {
        let block = slot.load(Relaxed);
        if block != 0 {
            // SAFETY: a pool block from `allocate`; its slot is cleared
            // below.
            unsafe { xboxkrnl::ExFreePool(block) };
            slot.store(0, Relaxed);
            true
        } else {
            false
        }
    };
    for block in &s.temporary_blocks {
        release(block);
    }
    if release(&s.buffer_table) {
        s.buffer_count.store(0, Relaxed);
    }
    for stream in &s.streams {
        release(&stream.queue);
    }
    for (ring, position) in s.rings.iter().zip(&s.ring_positions) {
        if release(ring) {
            position.head.store(0, Relaxed);
            position.tail.store(0, Relaxed);
        }
    }
    let requests = s.requests.load(Relaxed);
    if requests != 0 {
        if xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE {
            // SAFETY: the nonzero `requests` word.
            for request in unsafe { requests_at(s, requests) } {
                let event = request.event.load(Relaxed);
                if event != 0 {
                    // SAFETY: an event this title created for the request.
                    unsafe { xboxkrnl::NtClose(Handle::from_raw(event)) };
                }
            }
        }
        // SAFETY: the request table from `allocate`; its slot is cleared
        // below.
        unsafe { xboxkrnl::ExFreePool(requests) };
        s.requests.store(0, Relaxed);
        s.request_count.store(0, Relaxed);
        s.next_request.store(0, Relaxed);
    }
    s.allocation_attempted.store(0, Relaxed);
}

/// Allocate the buffers, queues and requests the configuration needs
/// (stock 0x91f5da20); on failure the configuration is turned off and
/// everything is released.
pub(super) fn allocate_all(s: &PixSession) {
    s.allocation_attempted.store(1, Relaxed);
    if !try_allocate(s) {
        let configuration = &s.configuration;
        configuration.set_part(Part::Audio, PartStream::OFF);
        configuration.set_part(Part::Gpu, PartStream::OFF);
        configuration.set_part(Part::SecondThread, PartStream::OFF);
        configuration.set_part(Part::Thread, PartStream::OFF);
        free(s);
    }
}

fn try_allocate(s: &PixSession) -> bool {
    /// Temporary per-thread blocks allocated, one per type of the first
    /// per-thread buffers.
    const TEMPORARY_ALLOCATED: usize = 6;
    /// Stock's estimate of the pool bytes of each buffer.
    const POOL_BYTES_PER_BUFFER: u32 = 0x14;
    /// Physical bytes needed beyond the buffers.
    const PHYSICAL_EXTRA: u32 = 2 * LARGE_PAGE;
    /// System budget kept for the pool allocations when the budget has
    /// room for it.
    const SYSTEM_RESERVED: u32 = LARGE_PAGE;
    /// Bytes of a frame buffer or command data ring entry.
    const RING_ENTRY_BYTES: u32 = 8;
    const QUEUE_ENTRY_BYTES: u32 = 4;
    if s.budget.enabled.load(Relaxed) == 0 || s.stream(StreamId::First).handle.load(Relaxed) == 0 {
        return false;
    }
    let count = needed(s);
    if count == 0 {
        free(s);
        return true;
    }
    s.needed_buffers.store(count, Relaxed);
    let need = round_up(count * BUFFER_BYTES + PHYSICAL_EXTRA).wrapping_add(round_up(
        requests_for(count) * REQUEST_SIZE
            + count * POOL_BYTES_PER_BUFFER
            + TEMPORARY_ALLOCATED as u32 * TEMPORARY_BYTES,
    ));
    let routine = s.capture_size_routine.load(Relaxed);
    let system = if routine != 0 {
        // SAFETY: XAM export 0x1f0 takes no arguments and returns a size.
        unsafe { crate::kernel::call_export(routine, 0, 0, 0, 0) }
    } else {
        session::capture_buffer_size()
    };
    let title_budget = &s.budgets[MemoryKind::Title.index()];
    let system_budget = &s.budgets[MemoryKind::System.index()];
    let title_used = &s.used[MemoryKind::Title.index()];
    let system_used = &s.used[MemoryKind::System.index()];
    let title_size = &s.physical_sizes[MemoryKind::Title.index()];
    let system_size = &s.physical_sizes[MemoryKind::System.index()];
    let budget = &s.budget;
    system_budget.store(system, Relaxed);
    title_budget.store(s.configuration.title_budget.load(Relaxed), Relaxed);
    if budget.override_title.load(Relaxed) != 0 {
        title_budget.store(budget.title_size.load(Relaxed), Relaxed);
    }
    if budget.override_system.load(Relaxed) != 0 {
        system_budget.store(budget.system_size.load(Relaxed), Relaxed);
    }
    if budget.title_enabled.load(Relaxed) == 0 {
        title_budget.store(0, Relaxed);
    }
    if system_budget
        .load(Relaxed)
        .wrapping_add(title_budget.load(Relaxed))
        < need
    {
        title_budget.store(need.wrapping_sub(system_budget.load(Relaxed)), Relaxed);
    }
    system_used.store(
        if system_budget.load(Relaxed) >= SYSTEM_RESERVED {
            SYSTEM_RESERVED
        } else {
            0
        },
        Relaxed,
    );
    title_used.store(0, Relaxed);
    system_size.store(0, Relaxed);
    title_size.store(0, Relaxed);
    for block in &s.temporary_blocks[..TEMPORARY_ALLOCATED] {
        if allocate_into(s, block, TEMPORARY_BYTES).is_none() {
            return false;
        }
    }
    let total = (title_budget.load(Relaxed) - title_used.load(Relaxed)) / BUFFER_BYTES
        + (system_budget.load(Relaxed) - system_used.load(Relaxed)) / BUFFER_BYTES;
    let Some(table) = allocate_into(s, &s.buffer_table, total * size_of::<BufferEntry>() as u32)
    else {
        return false;
    };
    if allocate_into(
        s,
        &s.stream(StreamId::First).queue,
        total * QUEUE_ENTRY_BYTES,
    )
    .is_none()
        || allocate_into(
            s,
            &s.stream(StreamId::Second).queue,
            total * QUEUE_ENTRY_BYTES,
        )
        .is_none()
        || allocate_into(s, &s.rings[0], total * RING_ENTRY_BYTES).is_none()
        || allocate_into(s, &s.rings[1], total * RING_ENTRY_BYTES).is_none()
    {
        return false;
    }
    let requests = requests_for(total);
    s.request_count.store(requests, Relaxed);
    let Some(request_table) = allocate_into(s, &s.requests, requests * REQUEST_SIZE) else {
        return false;
    };
    // Physical memory after the pool allocations of each budget, system
    // first.
    for index in (MemoryKind::Title.index()..=MemoryKind::System.index()).rev() {
        let kind = if index == MemoryKind::Title.index() {
            MemoryKind::Title
        } else {
            MemoryKind::System
        };
        let used = &s.used[index];
        let size = &s.physical_sizes[index];
        let start = round_up(used.load(Relaxed));
        used.store(start, Relaxed);
        let limit = s.budgets[index].load(Relaxed);
        if limit > start {
            let bytes = limit - start;
            size.store(bytes, Relaxed);
            // SAFETY: no pointer arguments.
            let address = unsafe {
                xboxkrnl::MmAllocatePhysicalMemoryEx(
                    kind.region(),
                    bytes,
                    PageProtection::READWRITE
                        | PageProtection::WRITECOMBINE
                        | PageProtection::LARGE_PAGES,
                    0,
                    u32::MAX,
                    0,
                )
            };
            s.physical_blocks[index].store(address, Relaxed);
            if address == 0 {
                size.store(0, Relaxed);
                if kind == MemoryKind::Title {
                    super::super::status::post_without_text(
                        super::super::status::Status::StreamEngineOutOfMemory,
                    );
                }
            }
        } else {
            size.store(0, Relaxed);
        }
    }
    let system = system_size.load(Relaxed) / BUFFER_BYTES;
    let title = title_size.load(Relaxed) / BUFFER_BYTES;
    s.needed_buffers.store(count, Relaxed);
    s.configuration
        .title_budget
        .store(title_size.load(Relaxed) + title_used.load(Relaxed), Relaxed);
    if system + title < count {
        return false;
    }
    // At most `total`: the physical blocks come from the same budgets less
    // the pool allocations made since.
    let entries = system + title;
    s.buffer_count.store(entries, Relaxed);
    // SAFETY: the buffer table allocated above for `total` entries.
    let table = unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance::<BufferEntry>(table.get() as usize),
            entries as usize,
        )
    };
    // Title blocks first, then system blocks; the system base is offset so
    // that the entry index keeps counting past the title entries.
    let title_data = s.physical_blocks[MemoryKind::Title.index()].load(Relaxed);
    let system_data = s.physical_blocks[MemoryKind::System.index()]
        .load(Relaxed)
        .wrapping_sub(title * BUFFER_BYTES);
    for (index, entry) in (0u32..).zip(table) {
        let data = if index < title {
            title_data
        } else {
            system_data
        };
        entry
            .data
            .store(data.wrapping_add(index * BUFFER_BYTES), Relaxed);
    }
    // SAFETY: the `requests` word stored above.
    for request in unsafe { requests_at(s, request_table.get()) } {
        request.status.store(NtStatus::SUCCESS.0, Relaxed);
        // SAFETY: the handle slot lies in the request table allocated above.
        let status = unsafe {
            xboxkrnl::NtCreateEvent(
                request.event.as_ptr().cast::<Handle>(),
                core::ptr::null(),
                EventType::Notification,
                true,
            )
        };
        if !status.is_success() {
            return false;
        }
    }
    true
}

/// Whether `need` buffers can be had: unused ones plus eight for each
/// completed request (stock 0x91f5c8b8).
pub(super) fn available(s: &PixSession, need: u32) -> bool {
    let mut free = s
        .buffer_count
        .load(Relaxed)
        .wrapping_sub(s.buffers_used.load(Relaxed));
    if s.completed_request.load(Relaxed) != 0 {
        free = free
            .wrapping_sub(s.completed_index.load(Relaxed))
            .wrapping_add(REQUEST_BUFFERS);
    }
    if free >= need {
        return true;
    }
    for stream in &s.streams {
        let tail = stream.tail.load(Relaxed);
        let mut index = stream.head.load(Relaxed);
        while index != tail {
            if queued(stream, index).pending() {
                break;
            }
            free = free.wrapping_add(REQUEST_BUFFERS);
            if free >= need {
                return true;
            }
            index = wrap(index + 1, s.request_count.load(Relaxed));
        }
    }
    false
}

/// `STRE` stream record marking a wait for the writer (stock 0x91f5c968).
fn stream_wait_record(waiting: bool) {
    let time = Timebase::now().ticks();
    super::super::write_tagged_words(
        RecordTag::STRE.raw(),
        &[(time >> 32) as u32, time as u32, u32::from(waiting)],
    );
}

/// Wait until a queued request completes (stock 0x91f5c9b0): titles wait
/// on the request events, the system process polls every 100 us.
fn wait_for_request(s: &PixSession) {
    let mut events = [0u32; 2];
    // One slot per stream, so a slot is free for each event.
    let mut slots = events.iter_mut();
    let mut wait = xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE;
    for stream in &s.streams {
        let head = stream.head.load(Relaxed);
        if head != stream.tail.load(Relaxed) {
            let request = queued(stream, head);
            if request.has_event.load(Relaxed) != 0 {
                if let Some(slot) = slots.next() {
                    *slot = request.event.load(Relaxed);
                }
            } else {
                wait = false;
            }
        }
    }
    let count = 2 - slots.len();
    if wait {
        // SAFETY: `events` holds `count` request event handles.
        unsafe {
            xboxkrnl::NtWaitForMultipleObjectsEx(
                count as u32,
                events.as_ptr().cast(),
                WaitType::Any,
                ProcessorMode::Kernel,
                false,
                core::ptr::null(),
            )
        };
        return;
    }
    loop {
        delay();
        for stream in &s.streams {
            let head = stream.head.load(Relaxed);
            if head != stream.tail.load(Relaxed) && !queued(stream, head).pending() {
                return;
            }
        }
    }
}

/// `KeDelayExecutionThread` for 100 us.
pub(super) fn delay() {
    /// Relative interval in 100 ns units.
    const INTERVAL: i64 = -1000;
    // SAFETY: the interval is a live constant.
    unsafe { xboxkrnl::KeDelayExecutionThread(ProcessorMode::Kernel, false, &INTERVAL) };
}

/// Partition handle of `stream` for the calling process (stock
/// 0x91f5cb08): titles open their own handle to the partition once. The
/// null handle when that fails, which the kernel calls reject.
fn handle(stream: &Stream) -> Handle {
    let title = xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE;
    if title && stream.title_handle.load(Relaxed) == 0 {
        let Some(handle) = session::open_partition() else {
            return Handle::NULL;
        };
        stream.title_handle.store(handle, Relaxed);
    }
    Handle::from_raw(if title {
        stream.title_handle.load(Relaxed)
    } else {
        stream.handle.load(Relaxed)
    })
}

/// Partition handle of stream `k` for the calling process.
pub(super) fn stream_handle(s: &PixSession, k: StreamId) -> u32 {
    handle(s.stream(k)).raw()
}

/// Take the next buffer of a completed request (stock 0x91f5de90). With
/// completions on both streams the first one's buffers are lost, as in
/// stock.
fn next_completed(s: &PixSession) -> Option<&BufferEntry> {
    let mut address = s.completed_request.load(Relaxed);
    if address == 0 {
        s.enter_engine_lock();
        for stream in &s.streams {
            let head = stream.head.load(Relaxed);
            if head != stream.tail.load(Relaxed) {
                let candidate = queued(stream, head);
                if !candidate.pending() {
                    address = candidate.address();
                    stream
                        .head
                        .store(wrap(head + 1, s.request_count.load(Relaxed)), Relaxed);
                }
            }
        }
        s.leave_engine_lock();
        if address == 0 {
            return None;
        }
        s.completed_request.store(address, Relaxed);
        s.completed_index.store(0, Relaxed);
    }
    // SAFETY: `completed_request` holds a request taken from a queue.
    let request = unsafe { WriteRequest::at(address) };
    // Below `REQUEST_BUFFERS` while `completed_request` is set; the mask
    // only drops the bounds check.
    let index = s.completed_index.load(Relaxed) % REQUEST_BUFFERS;
    let entry = request.buffers[index as usize].load(Relaxed);
    s.completed_index.store(index + 1, Relaxed);
    if index + 1 >= REQUEST_BUFFERS {
        s.completed_request.store(0, Relaxed);
    }
    // SAFETY: `submit` stores buffer table entries in a request before it
    // can complete.
    Some(unsafe { BufferEntry::at(entry) })
}

/// Next free buffer entry for `kind` on stream `k` (stock 0x91f5e360);
/// waits for the writer when none is free.
pub(super) fn take(s: &PixSession, kind: BufferType, k: u32) -> &BufferEntry {
    let used = s.buffers_used.load(Relaxed);
    let entry = if used < s.buffer_count.load(Relaxed) {
        s.buffers_used.store(used + 1, Relaxed);
        // SAFETY: checked against `buffer_count`.
        unsafe { entry_at(s, used) }
    } else {
        // Stock retries once after the wait and then writes through a null
        // entry; this waits until a request completes.
        loop {
            if let Some(entry) = next_completed(s) {
                break entry;
            }
            stream_wait_record(true);
            wait_for_request(s);
            stream_wait_record(false);
        }
    };
    entry.info.store(
        BufferInfo::new(k, kind, s.engine_flags(), entry.info()).0,
        Relaxed,
    );
    entry
}

/// Queue `entry` for writing (stock 0x91f5e090); every eighth buffer of a
/// stream starts a gather write of the eight.
pub(super) fn submit(s: &PixSession, entry: &BufferEntry, frame: u32) {
    /// Bytes one request writes (eight buffers).
    const REQUEST_BYTES: u64 = REQUEST_BUFFERS as u64 * BUFFER_BYTES as u64;
    /// Generation bits of a stream sequence; the rest counts buffers.
    const GENERATION_MASK: u32 = 0xff00_0000;
    const GENERATION_ONE: u32 = 0x0100_0000;
    const SEQUENCE_MASK: u32 = 0x00ff_ffff;
    const PAGES: usize = (BUFFER_BYTES / PAGE_SIZE) as usize;
    /// Frame index bits of a frame table entry.
    const FRAME_BITS: u32 = 0x00ff_ffff;
    let info = entry.info();
    let k = StreamId::from_raw(info.stream());
    let stream = s.stream(k);
    let sequence = stream.sequence.load(Relaxed);
    let mut next = (sequence & GENERATION_MASK) | (sequence.wrapping_add(1) & SEQUENCE_MASK);
    // `pending_count` wraps below `REQUEST_BUFFERS`; the mask only drops the
    // bounds check.
    let slot = stream.pending_count.load(Relaxed) % REQUEST_BUFFERS;
    stream.pending[slot as usize].store(entry.address(), Relaxed);
    if slot + 1 < REQUEST_BUFFERS {
        stream.pending_count.store(slot + 1, Relaxed);
    } else {
        stream.pending_count.store(0, Relaxed);
        let index = s.next_request.load(Relaxed);
        s.next_request
            .store(wrap(index + 1, s.request_count.load(Relaxed)), Relaxed);
        // SAFETY: `next_request` wraps below `request_count`, so this is a
        // request of the table `try_allocate` allocated; buffers are
        // submitted only while it is allocated.
        let request = unsafe {
            WriteRequest::at(s.requests.load(Relaxed).wrapping_add(index * REQUEST_SIZE))
        };
        request.status.store(NtStatus::PENDING.0, Relaxed);
        s.enter_engine_lock();
        let tail = stream.tail.load(Relaxed);
        queue_slot(stream, tail).store(request.address(), Relaxed);
        stream
            .tail
            .store(wrap(tail + 1, s.request_count.load(Relaxed)), Relaxed);
        s.leave_engine_lock();
        // Stock's segment array has one more, unused element.
        let mut segments = [0u32; REQUEST_BUFFERS as usize * PAGES + 1];
        for ((pending, buffer), pages) in stream
            .pending
            .iter()
            .zip(&request.buffers)
            .zip(segments.chunks_exact_mut(PAGES))
        {
            let pending = pending.load(Relaxed);
            buffer.store(pending, Relaxed);
            // SAFETY: `pending` holds the entries submitted to this stream.
            let data = unsafe { BufferEntry::at(pending) }.data();
            for (page, segment) in (0u32..).zip(pages) {
                *segment = data + page * PAGE_SIZE;
            }
        }
        if super::super::discard_output() {
            request.status.store(NtStatus::SUCCESS.0, Relaxed);
        } else if k == StreamId::First {
            let title = xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE;
            let event = if title {
                request.event.load(Relaxed)
            } else {
                0
            };
            // SAFETY: the status block and the stream offset lie in session
            // memory that outlives the request; `segments` is read during
            // the call.
            unsafe {
                NtWriteFileGather(
                    handle(stream),
                    Handle::from_raw(event),
                    0,
                    0,
                    request.status_block(),
                    segments.as_ptr(),
                    REQUEST_BYTES as u32,
                    stream.offset.as_ptr(),
                )
            };
            request.has_event.store(u32::from(title), Relaxed);
            request.thread.store(processor::current_thread(), Relaxed);
        }
        let offset = stream.offset.get() + REQUEST_BYTES;
        stream.offset.set(offset);
        if offset as i64 >= stream.size.get() as i64 {
            stream.offset.set(0);
            next = (next & GENERATION_MASK).wrapping_add(GENERATION_ONE);
        }
    }
    stream.sequence.store(next, Relaxed);
    let kind = info.kind();
    if kind.0 < BufferType::COMMAND_DATA.0 {
        if info.frame() != frame {
            append(
                s,
                k,
                &[
                    StreamRecordKind::Buffer as u32 | kind.0 << 3 | frame << 8,
                    sequence,
                ],
            );
        }
    } else if kind == BufferType::records(StreamId::First)
        || kind == BufferType::records(StreamId::Second)
    {
        // `table_index` wraps below `TABLE_ENTRIES`; the mask only drops the
        // bounds check.
        let index = stream.table_index.load(Relaxed) % TABLE_ENTRIES as u32;
        let slot = &stream.table[index as usize];
        slot.frame.store(
            (slot.frame.load(Relaxed) & !FRAME_BITS) | info.frame(),
            Relaxed,
        );
        slot.sequence.store(sequence, Relaxed);
        stream.table_index.store(
            if (index + 1) < TABLE_ENTRIES as u32 {
                index + 1
            } else {
                0
            },
            Relaxed,
        );
    }
}

/// Append `record` to record stream `k` (stock 0x91f5e418); a full buffer
/// is queued and replaced.
pub(super) fn append(s: &PixSession, k: StreamId, record: &[u32]) {
    let bytes = record.len() as u32 * 4;
    let cursor_slot = &s.record_cursors[k as usize];
    let end_slot = &s.record_ends[k as usize];
    let entry_slot = &s.record_entries[k as usize];
    let kind = BufferType::records(k);
    if k == StreamId::First {
        const LAST_FRAME: u32 = StreamRecordKind::LastFrame as u32;
        const AUDIO: u32 = StreamRecordKind::Audio as u32;
        let stream = s.stream(StreamId::First);
        // Frame records keep their key in the third word, the other kinds
        // in the second. A record too short for its key has none; stock
        // reads past it.
        let key_word = match record.first().map(|word| word & StreamRecordKind::MASK) {
            Some(..=LAST_FRAME) => Some(2),
            Some(..=AUDIO) => Some(1),
            _ => None,
        };
        let key = key_word.and_then(|index| record.get(index));
        stream.last_key.store(key.copied().unwrap_or(0), Relaxed);
        // Stock copies ten words from the record's address whatever its
        // size: stack bytes, or the session's frame times after the
        // pending GPU frame. The words past a short record are zero here.
        for (target, index) in stream.last_record.iter().zip(0..) {
            target.store(record.get(index).copied().unwrap_or(0), Relaxed);
        }
    }
    let mut cursor = cursor_slot.load(Relaxed);
    if cursor + bytes > end_slot.load(Relaxed) {
        // SAFETY: the record entry of a running stream is a buffer table
        // entry `start` or this function took.
        let full = unsafe { BufferEntry::at(entry_slot.load(Relaxed)) };
        close(full, kind, cursor);
        submit(s, full, s.frame_index());
        let entry = take(s, kind, k.raw());
        entry_slot.store(entry.address(), Relaxed);
        end_slot.store(entry.data() + BUFFER_BYTES, Relaxed);
        cursor = entry.data() + HEADER_BYTES;
    }
    // SAFETY: the record fits in the current buffer before its end; the
    // engine alone writes the buffer past the cursor.
    unsafe {
        core::ptr::copy_nonoverlapping(
            record.as_ptr(),
            core::ptr::with_exposed_provenance_mut::<u32>(cursor as usize),
            record.len(),
        )
    };
    cursor_slot.store(cursor + bytes, Relaxed);
}

/// Wait for the calling thread's writes before it ends (stock 0x91f5df80,
/// from the thread notification).
pub(super) fn wait_for_thread(s: &PixSession) {
    s.thread_writes
        .store(s.thread_writes.load(Relaxed).wrapping_add(1), Relaxed);
    s.enter_engine_lock();
    let thread = processor::current_thread();
    for stream in &s.streams {
        let tail = stream.tail.load(Relaxed);
        let mut index = stream.head.load(Relaxed);
        while index != tail {
            let request = queued(stream, index);
            if request.thread.load(Relaxed) == thread && request.pending() {
                if xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE {
                    // SAFETY: the request's event, created by this title.
                    unsafe {
                        xboxkrnl::NtWaitForSingleObjectEx(
                            Handle::from_raw(request.event.load(Relaxed)),
                            ProcessorMode::Kernel,
                            false,
                            core::ptr::null(),
                        )
                    };
                } else {
                    while request.pending() {
                        delay();
                    }
                }
            }
            index = wrap(index + 1, s.request_count.load(Relaxed));
        }
    }
    s.leave_engine_lock();
}

/// Wait until no request is pending, then empty the queues (end of stock
/// 0x91f60800).
pub(super) fn drain(s: &PixSession) {
    for request in request_table(s) {
        while request.pending() {
            delay();
        }
    }
    s.enter_engine_lock();
    for stream in &s.streams {
        stream.head.store(0, Relaxed);
        stream.tail.store(0, Relaxed);
    }
    s.leave_engine_lock();
}

/// Read the 16 KiB at partition unit `unit` into buffer `position` and
/// wait for it (stock 0x91f5e8c0); the address of the data.
pub(super) fn read_unit(s: &PixSession, unit: u32, position: u32) -> u32 {
    // Both bounds panic where stock reads through an unallocated or too
    // small table (`pixcmd d` without buffers); neither implies the other
    // for a single buffer.
    let request = &request_table(s)[position as usize];
    assert!(position < s.buffer_count.load(Relaxed));
    // SAFETY: checked against `buffer_count`.
    let address = unsafe { entry_at(s, position) }.data();
    request.status.store(NtStatus::PENDING.0, Relaxed);
    let offset = u64::from(unit) * u64::from(BUFFER_BYTES);
    // SAFETY: the status block, buffer and event belong to request
    // `position` and buffer `position` of the session; `offset` is live
    // until the wait below completes the read.
    unsafe {
        xboxkrnl::NtReadFile(
            handle(s.stream(StreamId::First)),
            Handle::from_raw(request.event.load(Relaxed)),
            0,
            0,
            request.status_block(),
            core::ptr::with_exposed_provenance_mut::<u8>(address as usize),
            BUFFER_BYTES,
            &offset,
        )
    };
    let start = cached(address);
    flush(start, start + BUFFER_BYTES);
    // SAFETY: the request's event.
    unsafe {
        xboxkrnl::NtWaitForSingleObjectEx(
            Handle::from_raw(request.event.load(Relaxed)),
            ProcessorMode::Kernel,
            false,
            core::ptr::null(),
        )
    };
    start
}
