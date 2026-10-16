//! PIX stream ring (stock 0x91fa2af0): a 64 KiB pool ring that `pixcmd b`
//! allocates and `pixcmd e` frees. Titles append records through monitor
//! control codes, the monitor appends its own records, and `pixcmd r`
//! sends the queued bytes. A record that does not fit is dropped; its tag
//! is remembered and the ring refuses writes until the drop record is
//! written at the end of the next `r` transfer.

use core::cell::UnsafeCell;

use openxbdm_core::status::Hresult;

use crate::backend::dispatcher;
use crate::kernel;
use crate::kernel::KeAcquireSpinLockAtRaisedIrql;
use crate::kernel::KeInsertQueueDpc;
use crate::kernel::KeRaiseIrqlToDpcLevel;
use crate::kernel::KeReleaseSpinLockFromRaisedIrql;
use crate::kernel::KeTryToAcquireSpinLockAtRaisedIrql;

use super::pcr;
use super::status;

/// Ring size and pool tag `PIXs`.
const RING_BYTES: u32 = 0x1_0000;
const RING_TAG: u32 = 0x5049_5873;
/// Queued bytes that make the ring report `CounterDataAvailable`.
const NOTIFY_BYTES: u32 = 0x8000;
/// Dropped tags kept for the drop record; the last slot becomes `....`
/// when more tags are dropped.
const DROPPED_TAGS: usize = 16;
const DROPPED_OVERFLOW: u32 = 0x2e2e_2e2e;
/// Packet type bits of the first dword of a record.
const KIND_MASK: u32 = 0xff_ffff;
const KIND_TAGGED: u32 = 0x62;
/// Header flag: the packet assigns values of a value group.
const ASSIGNS_VALUE: u32 = 0x20_0000;
/// Packet kind that starts collecting dwords for a capture record.
const KIND_CAPTURE_START: u32 = 0x16;
/// Dwords a capture record collects.
const CAPTURED_DWORDS: usize = 8;
/// Stream consumers (stock 0x91fa2b20).
const CONSUMERS: usize = 5;
/// Context swap routine flag when `pixcmd b` registers the ring's routine.
const SWAP_ROUTINE_FLAG: u32 = 1;
/// `CxSw` record tag.
const CONTEXT_SWITCH_TAG: u32 = 0x4378_5377;

/// A value group: values that packets with `ASSIGNS_VALUE` set and the
/// frame boundary writes as one tagged record. `first` is the group's
/// first slot in [`Ring::group_values`].
#[derive(Clone, Copy)]
pub(super) struct Group {
    tag: u32,
    count: usize,
    first: usize,
}

/// Groups 0 to 4; 0 and 1 hold no values (group 0 index 0 starts a
/// capture record instead).
const GROUPS: [Group; 5] = [
    Group {
        tag: 0,
        count: 0,
        first: 0,
    },
    Group {
        tag: 0,
        count: 0,
        first: 0,
    },
    Group {
        tag: 0x4433_645f,
        count: 0x13,
        first: 0,
    },
    Group {
        tag: 0x5841_4d5f,
        count: 7,
        first: 0x13,
    },
    Group {
        tag: 0x5841_755f,
        count: 7,
        first: 0x1a,
    },
];
/// Values of every group.
const GROUP_VALUES: usize = 0x21;
/// Group 2 value index that the frame boundary sets to the frame number.
const FRAME_VALUE: usize = 2;
/// Group the frame boundary writes after storing the frame number.
pub(super) const FRAME_GROUP: usize = 2;

/// Where the next dword of a packet is stored.
#[derive(Clone, Copy)]
enum ValueTarget {
    Captured,
    /// Slot of [`Ring::group_values`].
    Group(usize),
}

#[derive(Clone, Copy)]
struct Consumer {
    callback: u32,
    context: u32,
    /// Registered through code 0x58; code 0x42 with a null argument keeps
    /// these.
    persistent: bool,
}

const NO_CONSUMER: Consumer = Consumer {
    callback: 0,
    context: 0,
    persistent: false,
};

/// Ring state; every field is guarded by the ring lock.
pub(super) struct Ring {
    /// Pool block; `None` when tracing is off.
    buffer: Option<u32>,
    /// Address of the last dword of the block.
    last: u32,
    read: u32,
    /// Write position of the record being written.
    write: u32,
    /// End of the last complete record.
    committed: u32,
    /// `pixcmd r` transfer: next byte to send and end of the snapshot.
    snapshot: u32,
    snapshot_end: u32,
    consumers: [Consumer; CONSUMERS],
    /// `CounterDataAvailable` was reported and not yet answered by `r`.
    notified: bool,
    /// The DPC ran and the server thread has not checked the ring yet.
    dpc_fired: bool,
    dpc_queued: bool,
    dropped: [u32; DROPPED_TAGS],
    dropped_count: usize,
    first_drop_time: u64,
    accepting: bool,
    /// GPU capture timing written ahead of the drop record (stock
    /// 0x91f632e8): start and end time base and the frame count.
    capture_start: u64,
    capture_end: u64,
    capture_frames: u32,
    value_target: Option<ValueTarget>,
    group_values: [u32; GROUP_VALUES],
    capturing: bool,
    /// Dwords left in the current packet after its first dword.
    packet_left: u32,
    captured_value: u32,
    /// Next dword of `captured`; `None` until a capture packet starts.
    captured_index: Option<usize>,
    captured: [u32; CAPTURED_DWORDS],
    flush_capture: bool,
    /// The title uses the old D3D protocol (`pixcmd q`).
    legacy: bool,
    /// Code 0x27 packet: owning processor control region, dwords left, and
    /// whether every dword so far was stored.
    dword_owner: u32,
    dword_left: u32,
    dword_ok: bool,
}

#[repr(C, align(8))]
struct Dpc(UnsafeCell<[u8; 0x20]>);

struct Locked {
    lock: UnsafeCell<u32>,
    irql: UnsafeCell<u32>,
    dpc: Dpc,
    ring: UnsafeCell<Ring>,
}

// SAFETY: `ring` and `irql` are only accessed while `lock` is held; the DPC
// object is used through kernel calls.
unsafe impl Sync for Locked {}

static RING: Locked = Locked {
    lock: UnsafeCell::new(0),
    irql: UnsafeCell::new(0),
    dpc: Dpc(UnsafeCell::new([0; 0x20])),
    ring: UnsafeCell::new(Ring {
        buffer: None,
        last: 0,
        read: 0,
        write: 0,
        committed: 0,
        snapshot: 0,
        snapshot_end: 0,
        consumers: [NO_CONSUMER; CONSUMERS],
        notified: false,
        dpc_fired: false,
        dpc_queued: false,
        dropped: [0; DROPPED_TAGS],
        dropped_count: 0,
        first_drop_time: 0,
        accepting: false,
        capture_start: 0,
        capture_end: 0,
        capture_frames: 0,
        value_target: None,
        group_values: [0; GROUP_VALUES],
        capturing: false,
        packet_left: 0,
        captured_value: 0,
        captured_index: None,
        captured: [0; CAPTURED_DWORDS],
        flush_capture: false,
        legacy: false,
        dword_owner: 0,
        dword_left: 0,
        dword_ok: false,
    }),
};

/// Raise to DISPATCH and take the ring lock (stock 0x91f625c8).
fn acquire() {
    let irql = KeRaiseIrqlToDpcLevel();
    KeAcquireSpinLockAtRaisedIrql(RING.lock.get());
    // SAFETY: the lock is held.
    unsafe { *RING.irql.get() = irql };
}

/// Like [`acquire`] but give up when another processor holds the lock.
fn try_acquire() -> bool {
    let irql = KeRaiseIrqlToDpcLevel();
    if KeTryToAcquireSpinLockAtRaisedIrql(RING.lock.get()) & 0xff == 0 {
        kernel::KfLowerIrql(irql);
        return false;
    }
    // SAFETY: the lock is held.
    unsafe { *RING.irql.get() = irql };
    true
}

/// Release the lock and return to the saved IRQL (stock 0x91f62618).
fn release() {
    // SAFETY: the lock is held.
    let irql = unsafe { *RING.irql.get() };
    KeReleaseSpinLockFromRaisedIrql(RING.lock.get());
    kernel::KfLowerIrql(irql);
}

/// The ring while the lock is held.
///
/// # Safety
/// The caller holds the ring lock and keeps no other reference.
unsafe fn ring() -> &'static mut Ring {
    // SAFETY: guaranteed by the caller.
    unsafe { &mut *RING.ring.get() }
}

/// Run `f` with the ring locked.
pub(super) fn with<R>(f: impl FnOnce(&mut Ring) -> R) -> R {
    acquire();
    // SAFETY: the lock is held for the call.
    let result = f(unsafe { ring() });
    release();
    result
}

fn copy_words(source: u32, destination: u32, bytes: u32) {
    // SAFETY: the source is caller data of `bytes` bytes and the
    // destination lies in the ring block.
    unsafe {
        core::ptr::copy(
            source as usize as *const u8,
            destination as usize as *mut u8,
            bytes as usize,
        )
    };
}

impl Ring {
    fn base(&self) -> u32 {
        self.buffer.unwrap_or(0)
    }

    /// Copy `bytes` (a multiple of 4) to the write position without
    /// committing (stock 0x91f62668); the write position after them. The
    /// ring never fills completely.
    fn place(&self, source: u32, bytes: u32) -> Option<u32> {
        let base = self.buffer?;
        if !self.accepting {
            return None;
        }
        let dwords = bytes >> 2;
        let to_end = (self.last.wrapping_sub(self.write).wrapping_add(4) as i32 >> 2) as u32;
        if to_end > dwords {
            if self.read > self.write && self.read <= self.write.wrapping_add(dwords << 2) {
                return None;
            }
            copy_words(source, self.write, bytes);
            Some(self.write.wrapping_add(dwords << 2))
        } else {
            if self.read > self.write {
                return None;
            }
            let rest = (dwords - to_end) << 2;
            if self.read <= base.wrapping_add(rest) {
                return None;
            }
            copy_words(source, self.write, to_end << 2);
            copy_words(source + (to_end << 2), base, rest);
            Some(base.wrapping_add(rest))
        }
    }

    fn advance(&mut self, placed: Option<u32>) -> bool {
        if let Some(write) = placed {
            self.write = write;
        }
        placed.is_some()
    }

    fn put(&mut self, source: u32, bytes: u32) -> bool {
        let placed = self.place(source, bytes);
        self.advance(placed)
    }

    fn put_words(&mut self, words: &[u32]) -> bool {
        self.put(words.as_ptr() as usize as u32, (words.len() * 4) as u32)
    }

    /// [`Self::place`] for words of the ring state itself.
    fn place_own(&self, words: &[u32]) -> Option<u32> {
        self.place(words.as_ptr() as usize as u32, (words.len() * 4) as u32)
    }

    fn commit(&mut self) {
        self.committed = self.write;
    }

    fn discard(&mut self) {
        self.write = self.committed;
    }

    /// Remember a dropped record's tag (stock 0x91f627a0); the first drop
    /// stops further writes.
    fn drop_tag(&mut self, tag: u32) {
        if self.dropped[..self.dropped_count].contains(&tag) {
            return;
        }
        if self.dropped_count == 0 {
            self.first_drop_time = kernel::timebase();
            self.accepting = false;
        }
        if self.dropped_count < DROPPED_TAGS {
            self.dropped[self.dropped_count] = tag;
            self.dropped_count += 1;
        } else {
            self.dropped[DROPPED_TAGS - 1] = DROPPED_OVERFLOW;
        }
    }

    /// Bytes between the read position and the last complete record.
    fn queued(&self) -> u32 {
        let bytes = if self.committed < self.read {
            ((self.last.wrapping_sub(self.read).wrapping_add(4) as i32 >> 2) << 2) as u32
                - self.base()
                + self.committed
        } else {
            self.committed - self.read
        };
        ((bytes as i32 >> 2) << 2) as u32
    }

    /// Queue the DPC that reports `CounterDataAvailable` once enough data
    /// is queued (stock 0x91f62870).
    fn kick(&mut self) {
        if self.notified || self.dpc_fired || self.dpc_queued || self.queued() < NOTIFY_BYTES {
            return;
        }
        self.dpc_queued = true;
        KeInsertQueueDpc(RING.dpc.0.get().cast(), 0, 0);
    }

    /// Feed one dword of a packet to the value and capture state (stock
    /// 0x91f62c90).
    fn parse(&mut self, word: u32) {
        if let Some(target) = self.value_target.take() {
            match target {
                ValueTarget::Captured => self.captured_value = word,
                ValueTarget::Group(slot) => self.group_values[slot] = word,
            }
        }
        if self.capturing
            && let Some(index) = self.captured_index
        {
            // Stock keeps storing past the eighth dword into the fields
            // after the array; the extra dwords are not stored.
            if let Some(slot) = self.captured.get_mut(index) {
                *slot = word;
            }
            self.captured_index = Some(index + 1);
            if index + 1 >= CAPTURED_DWORDS || self.packet_left == 1 {
                self.flush_capture = true;
            }
        }
        if self.packet_left != 0 {
            self.packet_left -= 1;
            return;
        }
        self.packet_left = ((word & 0x7f00_0000) >> 24).wrapping_sub(1);
        if word & 0xf_ffff == KIND_CAPTURE_START && self.capturing {
            self.captured_index = Some(0);
        }
        if word & ASSIGNS_VALUE == 0 {
            return;
        }
        let group = ((word >> 16) & 0xf) as usize;
        let index = (word & 0xffff) as usize;
        if group == 0 && index == 0 {
            self.capturing = true;
            self.value_target = Some(ValueTarget::Captured);
            self.captured_index = None;
            return;
        }
        if let Some(&Group { count, first, .. }) = GROUPS.get(group)
            && index < count
        {
            self.value_target = Some(ValueTarget::Group(first + index));
        }
    }

    /// Write the capture record and end the capture (stock 0x91f63718).
    fn write_capture(&mut self) {
        let time = kernel::timebase();
        let count = self.captured_index.map_or(u32::MAX, |index| index as u32);
        let header = (count.wrapping_add(4) << 24) & 0x7fff_ff9a | 0x65;
        let stored = self.captured_index.unwrap_or(0).min(CAPTURED_DWORDS);
        let written = self.put_words(&[
            header,
            (time >> 32) as u32,
            time as u32,
            self.captured_value,
        ]) && {
            let placed = self.place_own(&self.captured[..stored]);
            self.advance(placed)
        };
        if written {
            self.commit()
        } else {
            self.discard()
        }
        self.flush_capture = false;
        self.capturing = false;
        self.captured_index = None;
    }

    /// Write the timing and drop records that end an `r` transfer and
    /// accept writes again (stock 0x91f62ee0).
    fn write_drop_record(&mut self) {
        let time = kernel::timebase();
        if self.capture_start != 0 && self.capture_end == 0 {
            return;
        }
        self.accepting = true;
        if self.dropped_count == 0 {
            self.first_drop_time = time;
        }
        let mut written = true;
        if self.capture_start != 0 {
            let start = self.capture_start;
            let end = self.capture_end;
            written = self.put_words(&[0x0400_0061, 1, (start >> 32) as u32, start as u32])
                && self.put_words(&[
                    0x0500_0061,
                    2,
                    (end >> 32) as u32,
                    end as u32,
                    self.capture_frames,
                ]);
        }
        let header = ((self.dropped_count as u32 + 5) << 24) & 0x7fff_ff9b | 0x64;
        let first = self.first_drop_time;
        if written
            && self.put_words(&[
                header,
                (first >> 32) as u32,
                first as u32,
                (time >> 32) as u32,
                time as u32,
            ])
            && {
                let placed = self.place_own(&self.dropped[..self.dropped_count]);
                self.advance(placed)
            }
        {
            self.dropped_count = 0;
            self.capture_start = 0;
            self.capture_end = 0;
            self.capture_frames = 0;
            self.commit();
        } else {
            self.accepting = false;
            self.discard();
        }
    }

    /// Append a record of `dwords` words at `words` and commit it (stock
    /// 0x91f63808 after locking).
    fn write_block(&mut self, words: u32, dwords: u32) {
        if self.put(words, dwords << 2) {
            self.commit();
        } else {
            if dwords >= 2 && super::read_u32(words) & KIND_MASK == KIND_TAGGED {
                self.drop_tag(super::read_u32(words + 4));
            }
            self.discard();
        }
        if dwords >= 1 && super::read_u32(words) & ASSIGNS_VALUE == ASSIGNS_VALUE {
            for index in 0..dwords {
                self.parse(super::read_u32(words + index * 4));
            }
            if self.flush_capture {
                self.write_capture();
            }
        }
        self.kick();
    }

    /// A `0x5e` record carrying a consumer's data block (stock 0x91f630a0).
    fn write_consumer_block(&mut self, tag: u32, data: u32, length: u32, extra: u32) {
        let header = ((((length + 3) >> 2) + 4) << 24) & 0x7fff_ffa1 | 0x5e;
        if self.put_words(&[header, extra, tag, length]) && self.put(data, length) {
            self.commit();
        } else {
            self.drop_tag(tag);
            self.discard();
        }
    }

    /// Write value group `group` as a tagged record (stock 0x91f63570).
    fn write_group(&mut self, group: usize) {
        let Some(&Group { tag, count, first }) = GROUPS.get(group) else {
            return;
        };
        if self.legacy || count == 0 {
            return;
        }
        let time = kernel::timebase();
        let header = ((count as u32 + 5) << 24) & 0x7fff_ff9d | KIND_TAGGED;
        if self.put_words(&[
            header,
            tag,
            (count as u32 + 2) << 2,
            (time >> 32) as u32,
            time as u32,
        ]) && {
            let placed = self.place_own(&self.group_values[first..first + count]);
            self.advance(placed)
        } {
            self.commit();
        } else {
            self.drop_tag(tag);
            self.discard();
        }
    }
}

/// Whether the ring exists, i.e. tracing is on (stock 0x91f62758).
pub(crate) fn stream_active() -> bool {
    with(|ring| ring.buffer.is_some())
}

/// Most payload dwords a tagged record carries; stock asserts below 0x7d.
const TAGGED_PAYLOAD_DWORDS: usize = 0x7c;

type TaggedRecord = [u32; TAGGED_PAYLOAD_DWORDS + 3];

/// Write a tagged record `{header, tag, length, payload}` through the
/// monitor control codes so a debugger extension sees it: code 0x5e with a
/// block list, then code 0x43 with one block when 0x5e reports nothing
/// (stock 0x91f788b8); whether it was written. Padding bytes after the
/// payload are zero.
pub(crate) fn write_tagged_record(tag: u32, payload: &[u8]) -> bool {
    if payload.len().div_ceil(4) > TAGGED_PAYLOAD_DWORDS {
        return false;
    }
    let mut record = [0u32; TAGGED_PAYLOAD_DWORDS + 3];
    for (index, chunk) in payload.chunks(4).enumerate() {
        let mut bytes = [0u8; 4];
        bytes[..chunk.len()].copy_from_slice(chunk);
        record[3 + index] = u32::from_be_bytes(bytes);
    }
    send_tagged_record(&mut record, tag, payload.len() as u32)
}

/// [`write_tagged_record`] with a payload of dwords.
pub(crate) fn write_tagged_words(tag: u32, words: &[u32]) -> bool {
    if words.len() > TAGGED_PAYLOAD_DWORDS {
        return false;
    }
    let mut record = [0u32; TAGGED_PAYLOAD_DWORDS + 3];
    record[3..3 + words.len()].copy_from_slice(words);
    send_tagged_record(&mut record, tag, (words.len() * 4) as u32)
}

/// Fill the header of `record`, whose payload of `length` bytes is in
/// place, and write it.
fn send_tagged_record(record: &mut TaggedRecord, tag: u32, length: u32) -> bool {
    let dwords = length.div_ceil(4);
    record[0] = ((dwords + 3) << 24) & 0x7fff_ff9d | KIND_TAGGED;
    record[1] = tag;
    record[2] = length;
    let address = record.as_ptr() as usize as u32;
    let list = [address, 3, address + 12, dwords, 0];
    match dispatcher::dispatch(0x5e, list.as_ptr() as usize as u32) as i32 {
        0 => {
            let block = [address, dwords + 3];
            dispatcher::dispatch(0x43, block.as_ptr() as usize as u32) != 0
        }
        result => result > 0,
    }
}

/// Allocate the ring and register the context switch record routine
/// (stock 0x91f63ba8, `pixcmd b`).
pub(super) fn start() {
    acquire();
    // SAFETY: the lock is held.
    let ring = unsafe { ring() };
    let fresh = ring.buffer.is_none();
    if fresh {
        let block = kernel::ExAllocatePoolTypeWithTag(RING_BYTES, RING_TAG, 2);
        ring.buffer = (block != 0).then_some(block);
    }
    if let Some(base) = ring.buffer {
        ring.read = base;
        ring.write = base;
        ring.committed = base;
        ring.notified = false;
        ring.last = base + RING_BYTES - 4;
        ring.accepting = true;
        ring.first_drop_time = 0;
        ring.capture_start = 0;
        ring.capture_end = 0;
        ring.capture_frames = 0;
        ring.dropped_count = 0;
        ring.capturing = false;
        ring.packet_left = 0;
        ring.captured_index = None;
        ring.flush_capture = false;
        if fresh {
            crate::backend::session::register_swap_routine(
                context_switch as *const () as usize as u32,
                SWAP_ROUTINE_FLAG,
            );
        }
    }
    release();
}

/// Free the ring and remove the context switch routine (stock 0x91f63c90,
/// `pixcmd e`).
pub(super) fn stop() {
    acquire();
    // SAFETY: the lock is held.
    let ring = unsafe { ring() };
    let block = ring.buffer.take();
    ring.last = 0;
    ring.read = 0;
    ring.write = 0;
    ring.committed = 0;
    if block.is_some() {
        crate::backend::session::unregister_swap_routine(
            context_switch as *const () as usize as u32,
        );
    }
    release();
    if let Some(block) = block {
        kernel::ExFreePool(block);
    }
}

/// Context swap routine: a `CxSw` record with the time and the processor
/// (stock 0x91f63b40). Skipped when another processor holds the ring.
extern "C" fn context_switch(_old: u32, _frame: u32, _new: u32) {
    let time = kernel::timebase();
    let processor = super::read_u8(pcr() + 0x10c);
    let record = [
        0x0600_0062,
        CONTEXT_SWITCH_TAG,
        0xc,
        (time >> 32) as u32,
        time as u32,
        u32::from(processor),
    ];
    write_block(record.as_ptr() as usize as u32, 6, false);
}

/// Append a record and commit it (stock 0x91f63808); `wait` false gives up
/// when the lock is busy.
pub(super) fn write_block(words: u32, dwords: u32, wait: bool) {
    if wait {
        acquire();
    } else if !try_acquire() {
        return;
    }
    // SAFETY: the lock is held.
    unsafe { ring() }.write_block(words, dwords);
    release();
}

/// Frame marker `{0x04000063, frame, time}` (stock 0x91f63af0).
pub(super) fn write_frame_marker(frame: u32) {
    let time = kernel::timebase();
    let record = [0x0400_0063, frame, (time >> 32) as u32, time as u32];
    write_block(record.as_ptr() as usize as u32, 4, true);
}

/// Write value group `group` (stock 0x91f63680).
pub(super) fn write_group(group: usize) {
    with(|ring| ring.write_group(group));
}

/// Store the frame number in group 2 and write the group (stock
/// 0x91f636c8).
pub(super) fn write_frame_group(frame: u32) {
    with(|ring| {
        ring.group_values[GROUPS[FRAME_GROUP].first + FRAME_VALUE] = frame;
        ring.write_group(FRAME_GROUP);
    });
}

/// Call every consumer with the frame number and the block writer, with
/// the ring locked (stock 0x91f63a90).
pub(super) fn call_consumers(frame: u32) {
    acquire();
    // SAFETY: the lock is held; consumers write through `consumer_write`,
    // which relies on this lock.
    let consumers = unsafe { ring() }.consumers;
    for consumer in consumers.iter().filter(|consumer| consumer.callback != 0) {
        // SAFETY: a title registered `callback` taking three arguments
        // `(context, writer, frame)`.
        unsafe {
            crate::kernel::call_export(
                consumer.callback,
                consumer.context,
                consumer_write_entry as *const () as usize as u32,
                frame,
                0,
            )
        };
    }
    release();
}

crate::exports::bridged!(consumer_write_entry, consumer_write);

/// Writer passed to consumers (stock 0x91f63378): `(tag, data, length,
/// extra)`. Runs inside [`call_consumers`] with the ring locked.
extern "C" fn consumer_write(tag: u32, data: u32, length: u32, extra: u32) {
    const D3D_COUNTERS: u32 = 0x4433_6463;
    const XAM_COUNTERS: u32 = 0x5841_4d20;
    const COUNTER_BLOCK: u32 = 0x28;
    // SAFETY: called by a consumer while `call_consumers` holds the lock.
    let ring = unsafe { ring() };
    if !ring.legacy {
        if length == COUNTER_BLOCK && tag == D3D_COUNTERS {
            // The current protocol adds the time base and marks version 1.
            let time = kernel::timebase();
            let mut block = [0u32; 0xc];
            for (index, word) in block[..10].iter_mut().enumerate() {
                *word = super::read_u32(data + index as u32 * 4);
            }
            block[0] = block[0] & 0xffff_ff0f | 0x10;
            block[10] = (time >> 32) as u32;
            block[11] = time as u32;
            ring.write_consumer_block(tag, block.as_ptr() as usize as u32, 0x30, extra);
        } else {
            ring.write_consumer_block(tag, data, length, extra);
        }
        return;
    }
    if length != COUNTER_BLOCK {
        return;
    }
    if tag == XAM_COUNTERS {
        let mut record = [0u32; 14];
        for (index, pair) in record.chunks_exact_mut(2).enumerate() {
            pair[0] = 0x0223_0000 + index as u32;
            pair[1] = (super::read_u32(data + 12 + index as u32 * 4) as f32).to_bits();
        }
        if ring.put_words(&record) {
            ring.commit()
        } else {
            ring.discard()
        }
    } else if tag == D3D_COUNTERS {
        ring.write_consumer_block(tag, data, COUNTER_BLOCK, extra);
    }
}

/// Monitor control code 0x27 (stock 0x91f63938): one dword of a packet
/// whose first dword carries the dword count in bits 24 to 30. The ring
/// stays locked by the writing processor until the packet is complete.
pub(crate) fn service_write_dword(word: u32) -> u32 {
    let processor = pcr();
    // SAFETY: the owner field is only written by the processor that holds
    // the lock; another processor reading a stale value only takes the
    // lock.
    if unsafe { ring() }.dword_owner != processor {
        acquire();
        // SAFETY: the lock is held.
        let ring = unsafe { ring() };
        ring.dword_owner = processor;
        ring.dword_left = word >> 24;
        ring.dword_ok = true;
    }
    // SAFETY: this processor holds the lock until the packet ends.
    let ring = unsafe { ring() };
    ring.parse(word);
    let stored = ring.dword_ok && ring.accepting && ring.buffer.is_some() && {
        let next = if ring.write == ring.last {
            ring.base()
        } else {
            ring.write + 4
        };
        let full = ring.read.wrapping_sub(ring.write) & !3 == 4
            || (ring.read == ring.base() && ring.write == ring.last);
        if !full {
            super::write_u32(ring.write, word);
            ring.write = next;
        }
        !full
    };
    ring.dword_ok = stored;
    ring.dword_left = ring.dword_left.wrapping_sub(1);
    if ring.dword_left == 0 {
        if stored {
            ring.commit()
        } else {
            ring.discard()
        }
        ring.dword_owner = 0;
        if ring.flush_capture {
            ring.write_capture();
        }
        release();
    }
    u32::from(stored)
}

/// Monitor control code 0x43 (stock 0x91f63808 with `{+0 address, +4
/// dwords}`); stock returns a stale register, this returns 0.
pub(crate) fn service_write_block(argument: u32) -> u32 {
    write_block(
        super::read_u32(argument),
        super::read_u32(argument + 4),
        true,
    );
    0
}

/// Monitor control code 0x5e (stock 0x91f62998): a list of `{address,
/// dwords}` pairs ending with a null address, written as one record. 1
/// when written, `0xffffffff` when dropped.
pub(crate) fn service_write_block_list(argument: u32) -> u32 {
    with(|ring| {
        let mut written = true;
        let mut entry = argument;
        while super::read_u32(entry) != 0 {
            if written {
                written = ring.put(super::read_u32(entry), super::read_u32(entry + 4) << 2);
            }
            entry += 8;
        }
        if written {
            ring.commit();
        } else {
            let first = super::read_u32(argument);
            if first != 0
                && super::read_u32(argument + 4) >= 2
                && super::read_u32(first) & KIND_MASK == KIND_TAGGED
            {
                ring.drop_tag(super::read_u32(first + 4));
            }
            ring.discard();
        }
        ring.kick();
        if written { 1 } else { u32::MAX }
    })
}

/// Monitor control codes 0x42 (`persistent` false) and 0x58: register a
/// consumer in the first free slot (stock 0x91f62af8); no free slot drops
/// the request. Stock returns a stale register; this returns 0.
pub(crate) fn register_consumer(argument: u32, persistent: bool) -> u32 {
    let callback = super::read_u32(argument);
    let context = super::read_u32(argument + 4);
    with(|ring| {
        if let Some(slot) = ring.consumers.iter_mut().find(|slot| slot.callback == 0) {
            *slot = Consumer {
                callback,
                context,
                persistent,
            };
        }
    });
    0
}

/// Monitor control code 0x42 with a null argument (stock 0x91f62a98):
/// remove the consumers registered through 0x42.
pub(super) fn clear_consumers() {
    with(|ring| {
        for slot in ring
            .consumers
            .iter_mut()
            .filter(|slot| slot.callback != 0 && !slot.persistent)
        {
            *slot = NO_CONSUMER;
        }
    });
}

/// Monitor control code 0x41 (stock 0x91f62b78): remove the consumer with
/// this callback and context.
pub(crate) fn service_unregister_consumer(argument: u32) -> u32 {
    let callback = super::read_u32(argument);
    let context = super::read_u32(argument + 4);
    with(|ring| {
        if let Some(slot) = ring
            .consumers
            .iter_mut()
            .find(|slot| slot.callback == callback && slot.context == context)
        {
            *slot = NO_CONSUMER;
        }
    });
    1
}

/// Replay group `group`'s state to a newly registered event callback:
/// `callback(0, 0)`, then `callback(0x11, index)` for every value (stock
/// 0x91f62c08), with the ring locked.
pub(super) fn replay_group(group: usize, callback: u32) {
    if callback == 0 {
        return;
    }
    let Some(&Group { count, .. }) = GROUPS.get(group) else {
        return;
    };
    acquire();
    // SAFETY: an event callback taking two arguments `(op, id)`.
    unsafe { crate::kernel::call_export(callback, 0, 0, 0, 0) };
    for index in 0..count as u32 {
        // SAFETY: as above.
        unsafe { crate::kernel::call_export(callback, 0x11, index, 0, 0) };
    }
    release();
}

/// Record the old-protocol flag of `pixcmd q` (stock 0x91f62da0).
pub(super) fn set_legacy(legacy: bool) {
    with(|ring| ring.legacy = legacy);
}

/// GPU capture timing written ahead of the next drop record (stock
/// 0x91f632e8): phase 1 starts, phase 2 ends with `frames` frames.
pub(super) fn capture_timing(phase: u32, frames: u32, time: u64) {
    with(|ring| {
        if phase == 1 {
            ring.accepting = false;
            if ring.capture_start == 0 {
                ring.capture_start = time;
            }
            ring.capture_end = 0;
            ring.capture_frames = 0;
        } else if phase == 2 && ring.capture_start != 0 {
            ring.capture_end = time;
            ring.capture_frames = frames;
            ring.write_drop_record();
        }
    });
}

/// Snapshot the queued bytes for `pixcmd r` (stock 0x91f63248).
pub(super) fn snapshot() -> u32 {
    with(|ring| {
        ring.snapshot_end = ring.committed;
        ring.snapshot = ring.read;
        ring.queued()
    })
}

/// Copy the next snapshot bytes into `output` (stock 0x91f63168). Data
/// sent by the previous call is released first. At the end of the
/// snapshot the drop record is written and 0 is returned.
pub(super) fn read_snapshot(output: &mut [u8]) -> usize {
    with(|ring| {
        // Stock keeps sending from the freed block after `pixcmd e`.
        if ring.buffer.is_none() {
            return 0;
        }
        ring.read = ring.snapshot;
        if ring.snapshot == ring.snapshot_end {
            ring.notified = false;
            ring.write_drop_record();
            return 0;
        }
        let end = if ring.snapshot_end > ring.snapshot {
            ring.snapshot_end
        } else {
            ring.last + 4
        };
        let count = ((end - ring.snapshot) as usize).min(output.len());
        // SAFETY: the bytes lie in the ring block between the read position
        // and the snapshot end, which writers do not overwrite.
        let source =
            unsafe { core::slice::from_raw_parts(ring.snapshot as usize as *const u8, count) };
        output[..count].copy_from_slice(source);
        ring.snapshot += count as u32;
        if ring.snapshot > ring.last {
            ring.snapshot = ring.base();
        }
        count
    })
}

/// Fill a title's transfer context for `pixcmd r` run through code 0x45
/// (stock 0x91f63248): `+0` continuation, `+0xc` and `+0x14` the snapshot
/// size, `+8` and `+0x10` cleared.
pub(super) fn begin_title_transfer(context: u32) {
    let size = with(|ring| {
        let end = ring.snapshot_end;
        let start = ring.snapshot;
        if end < start {
            ((ring.last.wrapping_sub(start).wrapping_add(4) as i32 >> 2) << 2) as u32 - ring.base()
                + end
        } else {
            end - start
        }
    });
    super::write_u32(context, title_transfer_entry as *const () as usize as u32);
    super::write_u32(context + 8, 0);
    super::write_u32(context + 0xc, size);
    super::write_u32(context + 0x10, 0);
    super::write_u32(context + 0x14, size);
}

crate::exports::bridged!(title_transfer_entry, title_transfer);

/// Transfer continuation of a title's `pixcmd r` (stock 0x91f63168):
/// each call releases the bytes of the previous call and points `+8`/`+4`
/// at the next contiguous run; `+0x14` is the length after a wrap.
extern "C" fn title_transfer(context: u32) -> u32 {
    with(|ring| {
        if ring.buffer.is_none() {
            return Hresult::END_OF_DATA.0;
        }
        ring.read = ring.snapshot;
        if ring.snapshot == ring.snapshot_end {
            ring.notified = false;
            ring.write_drop_record();
            return Hresult::END_OF_DATA.0;
        }
        super::write_u32(context + 8, ring.snapshot);
        if ring.snapshot_end > ring.snapshot {
            super::write_u32(context + 0x14, 0);
            super::write_u32(
                context + 4,
                (((ring.snapshot_end - ring.snapshot) as i32 >> 2) << 2) as u32,
            );
            ring.snapshot = ring.snapshot_end;
        } else {
            super::write_u32(
                context + 4,
                ((ring.last.wrapping_sub(ring.snapshot).wrapping_add(4) as i32 >> 2) << 2) as u32,
            );
            super::write_u32(
                context + 0x14,
                (((ring.snapshot_end - ring.base()) as i32 >> 2) << 2) as u32,
            );
            ring.snapshot = ring.base();
        }
        Hresult::OK.0
    })
}

crate::exports::bridged!(data_available_entry, data_available_dpc);

/// DPC queued once enough data is in the ring (stock 0x91f62828): the
/// server thread reports it.
extern "C" fn data_available_dpc(_dpc: u32, _context: u32, _argument1: u32, _argument2: u32) {
    with(|ring| {
        ring.dpc_queued = false;
        ring.dpc_fired = true;
    });
}

/// Server-thread part of the ring DPC (stock 0x91f62e88 and 0x91f628f8):
/// report `CounterDataAvailable` once per `r` transfer.
pub(super) fn poll() {
    if !with(|ring| core::mem::take(&mut ring.dpc_fired)) {
        return;
    }
    let notify = with(|ring| {
        if ring.notified || ring.queued() < NOTIFY_BYTES {
            return false;
        }
        ring.notified = true;
        true
    });
    if notify {
        status::post(status::Status::CounterDataAvailable, 0);
    }
}

/// Initialize the lock, the value groups, and the DPC (stock 0x91f62dd8).
pub(super) fn initialize() {
    // SAFETY: runs before any other ring user.
    unsafe { *RING.lock.get() = 0 };
    kernel::KeInitializeDpc(
        RING.dpc.0.get().cast(),
        data_available_entry as *const () as usize,
        0,
    );
}

/// Remove the DPC and the context switch routine and free the ring.
pub(super) fn shut_down() {
    kernel::KeRemoveQueueDpc(RING.dpc.0.get().cast());
    stop();
}
