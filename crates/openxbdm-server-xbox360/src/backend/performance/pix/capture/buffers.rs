//! Capture memory and the dump partition writer: the pool and physical
//! memory budget (stock 0x91f5c418, 0x91f5da20, 0x91f5d828), 16 KiB data
//! buffers with their record headers (0x91f5e360, 0x91f5e418), and the
//! asynchronous gather writes of eight buffers per request to the
//! `PixStream`/`PixDump` partition (0x91f5e090, 0x91f5de90, 0x91f5c9b0).
//!
//! A buffer entry is 8 bytes `{data, info}`; `info` holds the stream in
//! bits 30-31, the buffer type in bits 25-29 and the frame index in bits
//! 1-24. The first dword of the data is the header `type | dwords << 8`.

use xbox360::time::Timebase;
use xbox360_sys::processor;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::EventType;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::NtWriteFileGather;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::WaitType;

use super::S;
use super::rd;
use super::wr;

const STATUS_PENDING: u32 = 0x103;
pub(super) const BUFFER_BYTES: u32 = 0x4000;
/// Request records `{iosb[2], event, has_event, thread, buffers[8]}`.
const REQUEST: u32 = 0x34;
const REQUEST_BUFFERS: u32 = 8;
/// Bytes one request writes (eight buffers).
const REQUEST_BYTES: u64 = 0x2_0000;
const POOL_TAG: PoolTag = PoolTag::new(*b"PSTR");
/// Temporary per-thread blocks used while a capture buffer is replaced.
pub(super) const TEMPORARY_BLOCKS: u32 = 13;
const TEMPORARY_BYTES: u32 = 0x800;

/// Stream `k` (0 or 1): handles, partition size, sequence, request queue,
/// pending buffers and the frame table.
pub(super) fn stream(k: u32) -> u32 {
    0x638u32.wrapping_add(k.wrapping_mul(0x4080))
}

pub(super) const STREAM_SIZE: u32 = 8;
pub(super) const STREAM_SEQUENCE: u32 = 0x10;
const STREAM_OFFSET: u32 = 0x18;
const STREAM_QUEUE: u32 = 0x20;
const STREAM_TAIL: u32 = 0x24;
const STREAM_HEAD: u32 = 0x28;
const STREAM_PENDING: u32 = 0x2c;
pub(super) const STREAM_PENDING_COUNT: u32 = 0x4c;
pub(super) const STREAM_TABLE: u32 = 0x50;
pub(super) const STREAM_TABLE_INDEX: u32 = 0x4050;
const STREAM_LAST_RECORD: u32 = 0x4054;
const STREAM_LAST_KEY: u32 = 0x407c;
pub(super) const TABLE_ENTRIES: u32 = 0x800;

pub(super) fn data(entry: u32) -> u32 {
    rd(entry)
}

pub(super) fn info(entry: u32) -> u32 {
    rd(entry + 4)
}

/// Stream of a buffer entry (arithmetic shift as stock).
pub(super) fn entry_stream(entry: u32) -> u32 {
    ((info(entry) as i32) >> 30) as u32
}

/// Store the header of `entry`'s data: `kind` and the dwords before
/// `cursor`.
pub(super) fn close(entry: u32, kind: u32, cursor: u32) {
    let data = data(entry);
    wr(
        data,
        kind | (((cursor.wrapping_sub(data).wrapping_sub(4) as i32) >> 2) as u32) << 8,
    );
}

/// Words of pool type `kind` (2 system, 1 title): budget and bytes used
/// at +0x2b4/+0x2bc (title) and +0x2b8/+0x2c0 (system), physical block
/// and its size at +0x2ac/+0x2c4 and +0x2b0/+0x2c8.
fn budget(kind: u32) -> u32 {
    0x2b0 + kind * 4
}

fn used(kind: u32) -> u32 {
    0x2b8 + kind * 4
}

fn physical_block(kind: u32) -> u32 {
    0x2a8 + kind * 4
}

fn physical_size(kind: u32) -> u32 {
    0x2c0 + kind * 4
}

/// Allocate `size` zeroed bytes against the system budget, else the title
/// budget (stock 0x91f5c418).
pub(super) fn allocate(s: S, size: u32) -> u32 {
    for (kind, pool_type) in [(2, PoolType::System), (1, PoolType::Title)] {
        if s.word(used(kind)).wrapping_add(size) <= s.word(budget(kind)) {
            // SAFETY: allocates from the pool; no pointer arguments.
            let block = unsafe { xboxkrnl::ExAllocatePoolTypeWithTag(size, POOL_TAG, pool_type) };
            if block != 0 {
                // SAFETY: a fresh pool block of `size` bytes.
                unsafe { core::ptr::write_bytes(block as usize as *mut u8, 0, size as usize) };
                s.set_word(used(kind), s.word(used(kind)).wrapping_add(size));
                return block;
            }
        }
    }
    0
}

/// [`allocate`] into session word `offset`; false when it failed.
fn allocate_at(s: S, offset: u32, size: u32) -> bool {
    let block = allocate(s, size);
    s.set_word(offset, block);
    block != 0
}

/// Buffers each part needs, in configuration word order.
const PART_BUFFERS: [u32; 4] = [7, 6, 0x11, 3];

/// Buffers the configuration needs (stock 0x91f5c820).
fn needed(s: S) -> u32 {
    let mut count = 0;
    let mut streams = 0u32;
    for (index, &extra) in PART_BUFFERS.iter().enumerate() {
        let k = s.word(index as u32 * 4);
        if k != super::OFF {
            count += extra;
            streams |= super::stream_bit(k);
        }
    }
    count + 8 * (streams & 3).count_ones()
}

/// Cached view of a physical allocation, as the free path flushes it.
fn cached(address: u32) -> u32 {
    (address & 0x1fff_ffff)
        .wrapping_add(((address >> 20) + 0x200) & 0x1000)
        .wrapping_add(0xc000_0000)
}

/// Write back the data cache lines of `[start, end)` (stock 0x91f5d778).
pub(super) fn flush(start: u32, end: u32) {
    let mut line = start & !0x7f;
    while line < (end.wrapping_add(0x7f) & !0x7f) {
        // SAFETY: flushes one cache line of memory the engine owns.
        unsafe { core::arch::asm!("dcbf 0, {0}", in(reg) line, options(nostack)) };
        line += 0x80;
    }
    // SAFETY: orders the flushes.
    unsafe { core::arch::asm!("sync", options(nostack)) };
}

/// Release every capture allocation (stock 0x91f5d828).
pub(super) fn free(s: S) {
    for kind in (1..3).rev() {
        let address = s.word(physical_block(kind));
        if address != 0 {
            let start = cached(address);
            flush(start, start.wrapping_add(s.word(physical_size(kind))));
            // SAFETY: the physical block of this kind that `try_allocate`
            // allocated; its slot is cleared below.
            unsafe { xboxkrnl::MmFreePhysicalMemory(kind, address) };
            s.set_word(physical_block(kind), 0);
            s.set_word(physical_size(kind), 0);
        }
        s.set_word(budget(kind), 0);
        s.set_word(used(kind), 0);
    }
    let release = |offset: u32| {
        let block = s.word(offset);
        if block != 0 {
            // SAFETY: a pool block from `allocate`; its slot is cleared
            // below.
            unsafe { xboxkrnl::ExFreePool(block) };
            s.set_word(offset, 0);
            true
        } else {
            false
        }
    };
    for index in 0..TEMPORARY_BLOCKS {
        release(0x87a0 + index * 4);
    }
    if release(0x12c) {
        s.set_word(0x130, 0);
    }
    for k in 0..2 {
        release(stream(k) + STREAM_QUEUE);
    }
    for index in 0..2 {
        if release(0x138 + index * 4) {
            s.set_word(0x140 + index * 8, 0);
            s.set_word(0x144 + index * 8, 0);
        }
    }
    let requests = s.word(0x120);
    if requests != 0 {
        if xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE {
            for index in 0..s.word(0x124) {
                let event = rd(requests + index * REQUEST + 8);
                if event != 0 {
                    // SAFETY: an event this title created for the request.
                    unsafe { xboxkrnl::NtClose(Handle::from_raw(event)) };
                }
            }
        }
        // SAFETY: the request table from `allocate`; its slot is cleared
        // below.
        unsafe { xboxkrnl::ExFreePool(requests) };
        s.set_word(0x120, 0);
        s.set_word(0x124, 0);
        s.set_word(0x128, 0);
    }
    s.set_word(0x87d8, 0);
}

/// Allocate the buffers, queues and requests the configuration needs
/// (stock 0x91f5da20); on failure the configuration is turned off and
/// everything is released.
pub(super) fn allocate_all(s: S) {
    s.set_word(0x87d8, 1);
    if !try_allocate(s) {
        s.set_word(0xc, super::OFF);
        s.set_word(8, super::OFF);
        s.set_word(4, super::OFF);
        s.set_word(0, super::OFF);
        free(s);
    }
}

fn try_allocate(s: S) -> bool {
    if s.word(0x87dc) == 0 || s.word(super::super::session::DUMP_FILE) == 0 {
        return false;
    }
    let count = needed(s);
    if count == 0 {
        free(s);
        return true;
    }
    s.set_word(0x134, count);
    let need = ((count << 14).wrapping_add(0x2_ffff) & !0xffff)
        .wrapping_add((((count + 7) >> 3) * REQUEST + count * 0x14 + 0x1_3033) & !0xffff);
    let routine = s.word(super::super::session::CAPTURE_SIZE_ROUTINE);
    let system = if routine != 0 {
        // SAFETY: XAM export 0x1f0 takes no arguments and returns a size.
        unsafe { crate::kernel::call_export(routine, 0, 0, 0, 0) }
    } else {
        super::super::session::capture_buffer_size()
    };
    s.set_word(0x2b8, system);
    s.set_word(0x2b4, s.word(0x24));
    if s.word(0x87e4) != 0 {
        s.set_word(0x2b4, s.word(0x87e8));
    }
    if s.word(0x87ec) != 0 {
        s.set_word(0x2b8, s.word(0x87f0));
    }
    if s.word(0x87e0) == 0 {
        s.set_word(0x2b4, 0);
    }
    if s.word(0x2b8).wrapping_add(s.word(0x2b4)) < need {
        s.set_word(0x2b4, need.wrapping_sub(s.word(0x2b8)));
    }
    s.set_word(
        0x2c0,
        if s.word(0x2b8) >= 0x1_0000 {
            0x1_0000
        } else {
            0
        },
    );
    s.set_word(0x2bc, 0);
    s.set_word(0x2c8, 0);
    s.set_word(0x2c4, 0);
    for index in 0..6 {
        if !allocate_at(s, 0x87a0 + index * 4, TEMPORARY_BYTES) {
            return false;
        }
    }
    let total = ((s.word(0x2b4) - s.word(0x2bc)) >> 14) + ((s.word(0x2b8) - s.word(0x2c0)) >> 14);
    if !(allocate_at(s, 0x12c, total * 8)
        && allocate_at(s, stream(0) + STREAM_QUEUE, total * 4)
        && allocate_at(s, stream(1) + STREAM_QUEUE, total * 4)
        && allocate_at(s, 0x138, total * 8)
        && allocate_at(s, 0x13c, total * 8))
    {
        return false;
    }
    let requests = ((total + 7) >> 3) + 1;
    s.set_word(0x124, requests);
    if !allocate_at(s, 0x120, requests * REQUEST) {
        return false;
    }
    let table = s.word(0x120);
    // Physical memory after the pool allocations of each budget.
    for kind in (1..3).rev() {
        let start = s.word(used(kind)).wrapping_add(0xffff) & !0xffff;
        s.set_word(used(kind), start);
        let limit = s.word(budget(kind));
        if limit > start {
            let bytes = limit - start;
            s.set_word(physical_size(kind), bytes);
            // SAFETY: no pointer arguments.
            let address = unsafe {
                xboxkrnl::MmAllocatePhysicalMemoryEx(
                    kind,
                    bytes,
                    PageProtection::READWRITE
                        | PageProtection::WRITECOMBINE
                        | PageProtection::LARGE_PAGES,
                    0,
                    u32::MAX,
                    0,
                )
            };
            s.set_word(physical_block(kind), address);
            if address == 0 {
                s.set_word(physical_size(kind), 0);
                if kind == 1 {
                    super::super::status::post(
                        super::super::status::Status::StreamEngineOutOfMemory,
                        0,
                    );
                }
            }
        } else {
            s.set_word(physical_size(kind), 0);
        }
    }
    let system = s.word(0x2c8) >> 14;
    let title = s.word(0x2c4) >> 14;
    s.set_word(0x134, count);
    s.set_word(0x24, s.word(0x2c4) + s.word(0x2bc));
    if system + title < count {
        return false;
    }
    s.set_word(0x130, system + title);
    let mut entry = s.word(0x12c);
    for kind in 1..3 {
        let number = if kind == 1 { title } else { system };
        for index in 0..number {
            wr(entry, s.word(physical_block(kind)) + index * BUFFER_BYTES);
            entry += 8;
        }
    }
    for index in 0..requests {
        let request = table + index * REQUEST;
        wr(request, 0);
        // SAFETY: the handle slot lies in the request table allocated above.
        if (unsafe {
            xboxkrnl::NtCreateEvent(
                (request + 8) as usize as *mut Handle,
                core::ptr::null(),
                EventType::Notification,
                true,
            )
        }
        .0 as i32)
            < 0
        {
            return false;
        }
    }
    true
}

/// Whether `need` buffers can be had: unused ones plus eight for each
/// completed request (stock 0x91f5c8b8).
pub(super) fn available(s: S, need: u32) -> bool {
    let mut free = s.word(0x130).wrapping_sub(s.word(0x2a0));
    if s.word(0x2a4) != 0 {
        free = free.wrapping_sub(s.word(0x2a8)).wrapping_add(8);
    }
    if free >= need {
        return true;
    }
    for k in 0..2 {
        let base = s.0 + stream(k);
        let tail = rd(base + STREAM_TAIL);
        let mut index = rd(base + STREAM_HEAD);
        while index != tail {
            if rd(rd(rd(base + STREAM_QUEUE) + index * 4)) == STATUS_PENDING {
                break;
            }
            free = free.wrapping_add(8);
            if free >= need {
                return true;
            }
            index = wrap(index + 1, s.word(0x124));
        }
    }
    false
}

fn wrap(index: u32, count: u32) -> u32 {
    if index < count { index } else { 0 }
}

/// `STRE` stream record marking a wait for the writer (stock 0x91f5c968).
fn stream_wait_record(waiting: u32) {
    let time = Timebase::now().ticks();
    super::super::write_tagged_words(0x5354_5245, &[(time >> 32) as u32, time as u32, waiting]);
}

/// Wait until a queued request completes (stock 0x91f5c9b0): titles wait
/// on the request events, the system process polls every 100 us.
fn wait_for_request(s: S) {
    let mut events = [0u32; 2];
    let mut count = 0;
    let mut wait = xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE;
    for k in 0..2 {
        let base = s.0 + stream(k);
        let head = rd(base + STREAM_HEAD);
        if head != rd(base + STREAM_TAIL) {
            let request = rd(rd(base + STREAM_QUEUE) + head * 4);
            if rd(request + 0xc) != 0 {
                events[count] = rd(request + 8);
                count += 1;
            } else {
                wait = false;
            }
        }
    }
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
        for k in 0..2 {
            let base = s.0 + stream(k);
            let head = rd(base + STREAM_HEAD);
            if head != rd(base + STREAM_TAIL)
                && rd(rd(rd(base + STREAM_QUEUE) + head * 4)) != STATUS_PENDING
            {
                return;
            }
        }
    }
}

/// `KeDelayExecutionThread` for 100 us.
pub(super) fn delay() {
    let interval: i64 = -1000;
    // SAFETY: `interval` is a live local.
    unsafe { xboxkrnl::KeDelayExecutionThread(ProcessorMode::Kernel, false, &interval) };
}

/// Handle of stream `base` for the calling process (stock 0x91f5cb08):
/// titles open their own handle to the partition once.
fn handle(s: S, base: u32) -> u32 {
    if xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE && s.word(base + 4) == 0 {
        let mut handle = 0u32;
        if !super::super::session::open_partition(&mut handle) {
            return 0;
        }
        s.set_word(base + 4, handle);
    }
    if xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE {
        s.word(base + 4)
    } else {
        s.word(base)
    }
}

/// Partition handle of stream `k` for the calling process.
pub(super) fn stream_handle(s: S, k: u32) -> u32 {
    handle(s, s.0 + stream(k))
}

/// Take the next buffer of a completed request (stock 0x91f5de90). With
/// completions on both streams the first one's buffers are lost, as in
/// stock.
fn next_completed(s: S) -> u32 {
    let mut request = s.word(0x2a4);
    if request == 0 {
        let saved = super::super::session::enter(s.at(super::super::session::ENGINE_LOCK));
        s.set_word(super::super::session::ENGINE_LOCK_PRIORITY, saved);
        for k in 0..2 {
            let base = s.0 + stream(k);
            let head = rd(base + STREAM_HEAD);
            if head != rd(base + STREAM_TAIL) {
                let candidate = rd(rd(base + STREAM_QUEUE) + head * 4);
                if rd(candidate) != STATUS_PENDING {
                    request = candidate;
                    wr(base + STREAM_HEAD, wrap(head + 1, s.word(0x124)));
                }
            }
        }
        super::super::session::leave(
            s.at(super::super::session::ENGINE_LOCK),
            s.word(super::super::session::ENGINE_LOCK_PRIORITY),
        );
        if request == 0 {
            return 0;
        }
        s.set_word(0x2a4, request);
        s.set_word(0x2a8, 0);
    }
    let index = s.word(0x2a8);
    let entry = rd(request + 0x14 + index * 4);
    s.set_word(0x2a8, index + 1);
    if index + 1 >= REQUEST_BUFFERS {
        s.set_word(0x2a4, 0);
    }
    entry
}

/// Next free buffer entry for `kind` on stream `k` (stock 0x91f5e360);
/// waits for the writer when none is free.
pub(super) fn take(s: S, kind: u32, k: u32) -> u32 {
    let used = s.word(0x2a0);
    let entry = if used < s.word(0x130) {
        s.set_word(0x2a0, used + 1);
        s.word(0x12c) + used * 8
    } else {
        let mut entry = next_completed(s);
        if entry == 0 {
            stream_wait_record(1);
            wait_for_request(s);
            stream_wait_record(0);
            entry = next_completed(s);
        }
        entry
    };
    wr(
        entry + 4,
        (k << 5 | kind) << 25 | (s.word(super::FLAGS) >> 4 & 0x01ff_fffe) | (info(entry) & 1),
    );
    entry
}

/// Queue `entry` for writing (stock 0x91f5e090); every eighth buffer of a
/// stream starts a gather write of the eight.
pub(super) fn submit(s: S, entry: u32, frame: u32) {
    let k = entry_stream(entry);
    let base = s.0 + stream(k);
    let sequence = rd(base + STREAM_SEQUENCE);
    let mut next = (sequence & 0xff00_0000) | (sequence.wrapping_add(1) & 0x00ff_ffff);
    let slot = rd(base + STREAM_PENDING_COUNT);
    wr(base + STREAM_PENDING + slot * 4, entry);
    if slot + 1 < REQUEST_BUFFERS {
        wr(base + STREAM_PENDING_COUNT, slot + 1);
    } else {
        wr(base + STREAM_PENDING_COUNT, 0);
        let index = s.word(0x128);
        s.set_word(0x128, wrap(index + 1, s.word(0x124)));
        let request = s.word(0x120) + index * REQUEST;
        wr(request, STATUS_PENDING);
        let saved = super::super::session::enter(s.at(super::super::session::ENGINE_LOCK));
        s.set_word(super::super::session::ENGINE_LOCK_PRIORITY, saved);
        let tail = rd(base + STREAM_TAIL);
        wr(rd(base + STREAM_QUEUE) + tail * 4, request);
        wr(base + STREAM_TAIL, wrap(tail + 1, s.word(0x124)));
        super::super::session::leave(
            s.at(super::super::session::ENGINE_LOCK),
            s.word(super::super::session::ENGINE_LOCK_PRIORITY),
        );
        let mut segments = [0u32; (REQUEST_BUFFERS * 4 + 1) as usize];
        for index in 0..REQUEST_BUFFERS {
            let pending = rd(base + STREAM_PENDING + index * 4);
            wr(request + 0x14 + index * 4, pending);
            for page in 0..4 {
                segments[(index * 4 + page) as usize] = data(pending) + page * 0x1000;
            }
        }
        if super::super::discard_output() {
            wr(request, 0);
        } else if k == 0 {
            let title = xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE;
            let event = if title { rd(request + 8) } else { 0 };
            // SAFETY: the status block and the stream offset lie in session
            // memory that outlives the request; `segments` is read during
            // the call.
            unsafe {
                NtWriteFileGather(
                    Handle::from_raw(handle(s, base)),
                    Handle::from_raw(event),
                    0,
                    0,
                    request as usize as *mut IoStatusBlock,
                    segments.as_ptr(),
                    REQUEST_BYTES as u32,
                    (base + STREAM_OFFSET) as usize as *const u64,
                )
            };
            wr(request + 0xc, u32::from(title));
            wr(request + 0x10, processor::current_thread());
        }
        let offset = s.quad(stream(k) + STREAM_OFFSET) + REQUEST_BYTES;
        s.set_quad(stream(k) + STREAM_OFFSET, offset);
        if offset as i64 >= s.quad(stream(k) + STREAM_SIZE) as i64 {
            s.set_quad(stream(k) + STREAM_OFFSET, 0);
            next = (next & 0xff00_0000).wrapping_add(0x0100_0000);
        }
    }
    wr(base + STREAM_SEQUENCE, next);
    let info = info(entry);
    let kind = info >> 25 & 0x1f;
    if kind < 0xd {
        if info >> 1 & 0x00ff_ffff != frame {
            // Stock's record area past the two words is stale stack.
            let mut record = [0u32; 10];
            record[0] = 2 | kind << 3 | frame << 8;
            record[1] = sequence;
            append(s, k, record.as_ptr() as usize as u32, 8);
        }
    } else if kind == 0xf || kind == 0x10 {
        let index = rd(base + STREAM_TABLE_INDEX);
        let slot = base + STREAM_TABLE + index * 8;
        wr(slot, (rd(slot) & 0xff00_0000) | (info >> 1 & 0x00ff_ffff));
        wr(slot + 4, sequence);
        wr(
            base + STREAM_TABLE_INDEX,
            if index + 1 < TABLE_ENTRIES {
                index + 1
            } else {
                0
            },
        );
    }
}

/// Append a `bytes`-byte record to record stream `k` (stock 0x91f5e418);
/// a full buffer is queued and replaced.
pub(super) fn append(s: S, k: u32, record: u32, bytes: u32) {
    let cursor_slot = 0x110 + k * 4;
    let end_slot = 0x118 + k * 4;
    let entry_slot = 0x104 + k * 4;
    let kind = k + 0xf;
    if k == 0 {
        let base = s.0 + stream(0);
        let key = match rd(record) & 7 {
            0 | 1 => rd(record + 8),
            2..=5 => rd(record + 4),
            _ => 0,
        };
        wr(base + STREAM_LAST_KEY, key);
        // SAFETY: records are at least 0x28 bytes where stock copies them;
        // the source and the stream are distinct memory.
        unsafe {
            core::ptr::copy_nonoverlapping(
                record as usize as *const u8,
                (base + STREAM_LAST_RECORD) as usize as *mut u8,
                0x28,
            )
        };
    }
    let mut cursor = s.word(cursor_slot);
    if cursor + bytes > s.word(end_slot) {
        close(s.word(entry_slot), kind, cursor);
        submit(s, s.word(entry_slot), super::frame_index(s));
        let entry = take(s, kind, k);
        s.set_word(entry_slot, entry);
        s.set_word(end_slot, data(entry) + BUFFER_BYTES);
        cursor = data(entry) + 4;
    }
    // SAFETY: the record fits before the buffer end.
    unsafe {
        core::ptr::copy_nonoverlapping(
            record as usize as *const u8,
            cursor as usize as *mut u8,
            bytes as usize,
        )
    };
    s.set_word(cursor_slot, cursor + bytes);
}

/// Wait for the calling thread's writes before it ends (stock 0x91f5df80,
/// from the thread notification).
pub(super) fn wait_for_thread(s: S) {
    s.set_word(0xe210, s.word(0xe210).wrapping_add(1));
    let saved = super::super::session::enter(s.at(super::super::session::ENGINE_LOCK));
    s.set_word(super::super::session::ENGINE_LOCK_PRIORITY, saved);
    let thread = processor::current_thread();
    for k in 0..2 {
        let base = s.0 + stream(k);
        let tail = rd(base + STREAM_TAIL);
        let mut index = rd(base + STREAM_HEAD);
        while index != tail {
            let request = rd(rd(base + STREAM_QUEUE) + index * 4);
            if rd(request + 0x10) == thread && rd(request) == STATUS_PENDING {
                if xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE {
                    // SAFETY: the request's event, created by this title.
                    unsafe {
                        xboxkrnl::NtWaitForSingleObjectEx(
                            Handle::from_raw(rd(request + 8)),
                            ProcessorMode::Kernel,
                            false,
                            core::ptr::null(),
                        )
                    };
                } else {
                    while rd(request) == STATUS_PENDING {
                        delay();
                    }
                }
            }
            index = wrap(index + 1, s.word(0x124));
        }
    }
    super::super::session::leave(
        s.at(super::super::session::ENGINE_LOCK),
        s.word(super::super::session::ENGINE_LOCK_PRIORITY),
    );
}

/// Wait until no request is pending, then empty the queues (end of stock
/// 0x91f60800).
pub(super) fn drain(s: S) {
    let requests = s.word(0x120);
    for index in 0..s.word(0x124) {
        while rd(requests + index * REQUEST) == STATUS_PENDING {
            delay();
        }
    }
    let saved = super::super::session::enter(s.at(super::super::session::ENGINE_LOCK));
    s.set_word(super::super::session::ENGINE_LOCK_PRIORITY, saved);
    for k in 0..2 {
        wr(s.0 + stream(k) + STREAM_HEAD, 0);
        wr(s.0 + stream(k) + STREAM_TAIL, 0);
    }
    super::super::session::leave(
        s.at(super::super::session::ENGINE_LOCK),
        s.word(super::super::session::ENGINE_LOCK_PRIORITY),
    );
}

/// Read the 16 KiB at partition unit `unit` into buffer `position` and
/// wait for it (stock 0x91f5e8c0); the address of the data.
pub(super) fn read_unit(s: S, unit: u32, position: u32) -> u32 {
    let request = s.word(0x120) + position * REQUEST;
    let address = data(s.word(0x12c) + position * 8);
    wr(request, STATUS_PENDING);
    let offset = u64::from(unit) << 14 & 0x3fff_ffff_c000;
    // SAFETY: the status block, buffer and event belong to request
    // `position` of the session block; `offset` is live until the wait
    // below completes the read.
    unsafe {
        xboxkrnl::NtReadFile(
            Handle::from_raw(handle(s, s.0 + stream(0))),
            Handle::from_raw(rd(request + 8)),
            0,
            0,
            request as usize as *mut xboxkrnl::IoStatusBlock,
            address as usize as *mut u8,
            BUFFER_BYTES,
            &offset,
        )
    };
    let start = cached(address);
    flush(start, start + BUFFER_BYTES);
    // SAFETY: the request's event.
    unsafe {
        xboxkrnl::NtWaitForSingleObjectEx(
            Handle::from_raw(rd(request + 8)),
            ProcessorMode::Kernel,
            false,
            core::ptr::null(),
        )
    };
    start
}
