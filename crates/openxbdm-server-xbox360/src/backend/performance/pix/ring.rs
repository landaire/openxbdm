//! PIX stream ring (stock 0x91fa2af0): a 64 KiB pool ring that `pixcmd b`
//! allocates and `pixcmd e` frees. Titles append records through monitor
//! control codes, the monitor appends its own records, and `pixcmd r`
//! sends the queued bytes. A record that does not fit is dropped; its tag
//! is remembered and the ring refuses writes until the drop record is
//! written at the end of the next `r` transfer.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::num::NonZeroU32;
use core::num::NonZeroU64;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use xbox360::time::Timebase;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeAcquireSpinLockAtRaisedIrql;
use xbox360_sys::xboxkrnl::KeInsertQueueDpc;
use xbox360_sys::xboxkrnl::KeRaiseIrqlToDpcLevel;
use xbox360_sys::xboxkrnl::KeReleaseSpinLockFromRaisedIrql;
use xbox360_sys::xboxkrnl::KeTryToAcquireSpinLockAtRaisedIrql;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;

use super::RecordTag;
use super::events::CallbackOperation;
use super::status;
use crate::backend::dispatcher;
use crate::backend::dispatcher::ControlCode;

/// Ring size.
const RING_BYTES: u32 = 0x1_0000;
const RING_WORDS: usize = (RING_BYTES / 4) as usize;
/// Queued bytes that make the ring report `CounterDataAvailable`.
const NOTIFY_BYTES: u32 = 0x8000;
/// Dropped tags kept for the drop record.
const DROPPED_TAGS: usize = 16;
/// Dwords a capture record collects.
const CAPTURED_DWORDS: usize = 8;
/// Stream consumers (stock 0x91fa2b20).
const CONSUMERS: usize = 5;
/// Groups 0 to 4; 0 and 1 hold no values (group 0 index 0 starts a
/// capture record instead).
const GROUPS: [Option<Group>; 5] = [
    None,
    None,
    Some(Group {
        tag: RecordTag::new(*b"D3d_"),
        count: 0x13,
        first: 0,
    }),
    Some(Group {
        tag: RecordTag::new(*b"XAM_"),
        count: 7,
        first: 0x13,
    }),
    Some(Group {
        tag: RecordTag::new(*b"XAu_"),
        count: 7,
        first: 0x1a,
    }),
];

/// Values of every group.
const GROUP_VALUES: usize = 0x21;

/// Header, tag, and length of a tagged record.
const TAGGED_HEADER_DWORDS: usize = 3;
/// Most payload dwords a tagged record carries; stock asserts below 0x7d.
const TAGGED_PAYLOAD_DWORDS: usize = 0x7c;

type TaggedRecord = [u32; TAGGED_HEADER_DWORDS + TAGGED_PAYLOAD_DWORDS];

static RING: Locked = Locked {
    lock: KspinLock::new(),
    irql: UnsafeCell::new(Irql::PASSIVE),
    dpc: Dpc(UnsafeCell::new([0; 0x20])),
    dword_owner: AtomicU32::new(0),
    ring: UnsafeCell::new(Ring {
        buffer: None,
        last: 0,
        read: 0,
        write: 0,
        committed: 0,
        snapshot: 0,
        snapshot_end: 0,
        consumers: [Consumer {
            callback: None,
            context: 0,
            persistent: false,
        }; CONSUMERS],
        notified: false,
        dpc_fired: false,
        dpc_queued: false,
        dropped: [0; DROPPED_TAGS],
        dropped_count: 0,
        first_drop_time: 0,
        accepting: false,
        capture_start: None,
        capture_end: None,
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
        dword_left: 0,
        dword_ok: false,
    }),
};

xbox360_sys::value_enum! {
    /// Packet kinds in the low bits of a packet header.
    pub enum PacketKind: u32 {
        /// Starts collecting dwords for a capture record.
        CaptureStart = 0x16,
        /// A consumer's data block.
        ConsumerBlock = 0x5e,
        /// GPU capture start or end time.
        CaptureTiming = 0x61,
        /// `{header, tag, length, payload}`.
        Tagged = 0x62,
        FrameMarker = 0x63,
        /// Tags of dropped records.
        Drops = 0x64,
        Capture = 0x65,
    }
}

/// First dword of a packet: the dword count in bits 24 to 30, flags, and
/// the packet kind or a value assignment.
#[derive(Clone, Copy)]
pub(super) struct PacketHeader(u32);

impl PacketHeader {
    const DWORDS_SHIFT: u32 = 24;
    const DWORDS_MASK: u32 = 0x7f00_0000;
    /// Bits compared with [`PacketKind::Tagged`].
    const KIND_MASK: u32 = 0xff_ffff;
    /// Bits compared with [`PacketKind::CaptureStart`].
    const CODE_MASK: u32 = 0xf_ffff;
    /// The packet assigns a value of a value group.
    const ASSIGNS_VALUE: u32 = 0x20_0000;
    const GROUP_SHIFT: u32 = 16;
    const GROUP_MASK: u32 = 0xf;
    const INDEX_MASK: u32 = 0xffff;

    const fn new(kind: PacketKind, dwords: u32) -> Self {
        Self((dwords << Self::DWORDS_SHIFT) & Self::DWORDS_MASK | kind.raw())
    }

    /// A two-dword packet assigning value `index` of group `group`.
    pub(super) const fn assignment(group: u32, index: u32) -> Self {
        Self(2 << Self::DWORDS_SHIFT | Self::ASSIGNS_VALUE | group << Self::GROUP_SHIFT | index)
    }

    pub(super) const fn raw(self) -> u32 {
        self.0
    }

    fn dwords(self) -> u32 {
        (self.0 & Self::DWORDS_MASK) >> Self::DWORDS_SHIFT
    }

    fn is_tagged(self) -> bool {
        self.0 & Self::KIND_MASK == PacketKind::Tagged.raw()
    }

    fn starts_capture(self) -> bool {
        self.0 & Self::CODE_MASK == PacketKind::CaptureStart.raw()
    }

    fn assigns_value(self) -> bool {
        self.0 & Self::ASSIGNS_VALUE != 0
    }

    fn group(self) -> usize {
        ((self.0 >> Self::GROUP_SHIFT) & Self::GROUP_MASK) as usize
    }

    fn index(self) -> usize {
        (self.0 & Self::INDEX_MASK) as usize
    }
}

xbox360_sys::value_enum! {
    /// GPU capture phase of [`capture_timing`] and of the timing records.
    pub enum CapturePhase: u32 {
        Start = 1,
        End = 2,
    }
}

/// A value group: values that packets with
/// [`PacketHeader::ASSIGNS_VALUE`] set and the frame boundary writes as one
/// tagged record. `first` is the group's first slot in
/// [`Ring::group_values`].
#[derive(Clone, Copy)]
struct Group {
    tag: RecordTag,
    count: usize,
    first: usize,
}

/// Where the next dword of a packet is stored.
#[derive(Clone, Copy)]
enum ValueTarget {
    Captured,
    /// Slot of [`Ring::group_values`].
    Group(usize),
}

/// A consumer slot; free while `callback` is `None`.
#[derive(Clone, Copy)]
struct Consumer {
    callback: Option<NonZeroU32>,
    context: u32,
    /// Registered through code 0x58; code 0x42 with a null argument keeps
    /// these.
    persistent: bool,
}

/// Ring state; every field is guarded by the ring lock.
struct Ring {
    /// Pool block; `None` when tracing is off. `stop` takes it out under
    /// the lock before freeing it, so views of it are only used while the
    /// lock is held. While it is `Some`, it holds `RING_WORDS` words,
    /// `last` is its last dword, and `write` and `committed` are dword
    /// positions in it; `place_bytes` and `put_dword` rely on this.
    buffer: Option<&'static [AtomicU32]>,
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
    /// A time base of 0 counts as none, as in stock.
    capture_start: Option<NonZeroU64>,
    capture_end: Option<NonZeroU64>,
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
    /// Code 0x27 packet: dwords left, and whether every dword so far was
    /// stored.
    dword_left: u32,
    dword_ok: bool,
}

impl Ring {
    /// Address of the block; 0 without one, when every position is 0 too.
    fn base(&self) -> u32 {
        self.buffer.map_or(0, address)
    }

    /// Copy `bytes` to the write position without committing (stock
    /// 0x91f62668); the write position after their whole dwords. The ring
    /// never fills completely.
    fn place_bytes(&self, bytes: &[u8]) -> Option<u32> {
        let block = self.buffer?;
        if !self.accepting {
            return None;
        }

        let base = address(block);
        let dwords = (bytes.len() >> 2) as u32;
        let to_end = (self.last.wrapping_sub(self.write).wrapping_add(4) as i32 >> 2) as u32;
        let offset = self.write.wrapping_sub(base);

        if to_end > dwords {
            if self.read > self.write && self.read <= self.write.wrapping_add(dwords << 2) {
                return None;
            }

            // Stock copies the trailing partial dword too, past the new
            // write position.
            // SAFETY: `write` is a dword position in the block and `last`
            // its last dword (`Ring::buffer`), so `to_end` dwords are left;
            // `bytes` is shorter than `dwords + 1 <= to_end` dwords.
            unsafe { copy_to(block, offset, bytes) };

            Some(self.write.wrapping_add(dwords << 2))
        } else {
            if self.read > self.write {
                return None;
            }

            let rest = (dwords - to_end) << 2;
            // `read` stays in the block, so the first test bounds `rest`;
            // the second keeps the copy below inside the block on its own,
            // as the unchecked split relies on it.
            if self.read <= base.wrapping_add(rest) || rest > RING_BYTES - 4 {
                return None;
            }

            // Across the end stock copies whole dwords only.
            let split = (to_end << 2) as usize;
            // SAFETY: `bytes` holds `to_end` dwords and then `rest` bytes of
            // its remaining `dwords - to_end` dwords.
            let (head, tail) = unsafe {
                (
                    bytes.get_unchecked(..split),
                    bytes.get_unchecked(split..split + rest as usize),
                )
            };
            // SAFETY: `head` is the `to_end` dwords from `write` to the end
            // of the block (`Ring::buffer`); `tail`, `rest` bytes, fits in
            // the `RING_BYTES` block as tested above.
            unsafe {
                copy_to(block, offset, head);
                copy_to(block, 0, tail);
            }

            Some(base.wrapping_add(rest))
        }
    }

    /// [`Self::place_bytes`] for words.
    fn place(&self, words: &[u32]) -> Option<u32> {
        self.place_bytes(word_bytes(words))
    }

    fn advance(&mut self, placed: Option<u32>) -> bool {
        if let Some(write) = placed {
            self.write = write;
        }

        placed.is_some()
    }

    fn put_bytes(&mut self, bytes: &[u8]) -> bool {
        let placed = self.place_bytes(bytes);
        self.advance(placed)
    }

    fn put(&mut self, words: &[u32]) -> bool {
        self.put_bytes(word_bytes(words))
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
        /// Last tag slot once more tags are dropped than fit.
        const DROPPED_OVERFLOW: RecordTag = RecordTag::new(*b"....");

        if self.dropped[..self.dropped_count].contains(&tag) {
            return;
        }

        if self.dropped_count == 0 {
            self.first_drop_time = Timebase::now().ticks();
            self.accepting = false;
        }

        if self.dropped_count < DROPPED_TAGS {
            self.dropped[self.dropped_count] = tag;
            self.dropped_count += 1;
        } else {
            self.dropped[DROPPED_TAGS - 1] = DROPPED_OVERFLOW.raw();
        }
    }

    /// Bytes from ring position `start` to `end`, across the end of the
    /// block when `end` is before `start`.
    #[inline(always)]
    fn span(&self, start: u32, end: u32) -> u32 {
        if end < start {
            ((self.last.wrapping_sub(start).wrapping_add(4) as i32 >> 2) << 2) as u32 - self.base()
                + end
        } else {
            end - start
        }
    }

    /// Bytes between the read position and the last complete record.
    fn queued(&self) -> u32 {
        ((self.span(self.read, self.committed) as i32 >> 2) << 2) as u32
    }

    /// Queue the DPC that reports `CounterDataAvailable` once enough data
    /// is queued (stock 0x91f62870).
    fn kick(&mut self) {
        if self.notified || self.dpc_fired || self.dpc_queued || self.queued() < NOTIFY_BYTES {
            return;
        }

        self.dpc_queued = true;
        // SAFETY: the static DPC object `initialize` set up.
        unsafe { KeInsertQueueDpc(RING.dpc.0.get().cast(), 0, 0) };
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

        let header = PacketHeader(word);
        self.packet_left = header.dwords().wrapping_sub(1);
        if header.starts_capture() && self.capturing {
            self.captured_index = Some(0);
        }

        if !header.assigns_value() {
            return;
        }

        let group = header.group();
        let index = header.index();
        if group == 0 && index == 0 {
            self.capturing = true;
            self.value_target = Some(ValueTarget::Captured);
            self.captured_index = None;
            return;
        }

        if let Some(&Some(Group { count, first, .. })) = GROUPS.get(group)
            && index < count
        {
            self.value_target = Some(ValueTarget::Group(first + index));
        }
    }

    /// Write the capture record and end the capture (stock 0x91f63718).
    fn write_capture(&mut self) {
        /// Header, time base, and the captured value.
        const FIXED_DWORDS: u32 = 4;

        let time = Timebase::now().ticks();
        let count = self.captured_index.map_or(u32::MAX, |index| index as u32);
        let header = PacketHeader::new(PacketKind::Capture, count.wrapping_add(FIXED_DWORDS));
        let stored = self.captured_index.unwrap_or(0).min(CAPTURED_DWORDS);
        let written = self.put(&[
            header.raw(),
            (time >> 32) as u32,
            time as u32,
            self.captured_value,
        ]) && {
            let placed = self.place(&self.captured[..stored]);
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
        /// Header and two time base values.
        const FIXED_DWORDS: u32 = 5;

        let time = Timebase::now().ticks();
        if self.capture_start.is_some() && self.capture_end.is_none() {
            return;
        }

        self.accepting = true;
        if self.dropped_count == 0 {
            self.first_drop_time = time;
        }

        let written = match (self.capture_start, self.capture_end) {
            (Some(start), Some(end)) => {
                let start = start.get();
                let end = end.get();
                self.put(&[
                    PacketHeader::new(PacketKind::CaptureTiming, 4).raw(),
                    CapturePhase::Start.raw(),
                    (start >> 32) as u32,
                    start as u32,
                ]) && self.put(&[
                    PacketHeader::new(PacketKind::CaptureTiming, 5).raw(),
                    CapturePhase::End.raw(),
                    (end >> 32) as u32,
                    end as u32,
                    self.capture_frames,
                ])
            }
            _ => true,
        };

        let header = PacketHeader::new(PacketKind::Drops, self.dropped_count as u32 + FIXED_DWORDS);
        let first = self.first_drop_time;
        if written
            && self.put(&[
                header.raw(),
                (first >> 32) as u32,
                first as u32,
                (time >> 32) as u32,
                time as u32,
            ])
            && {
                let placed = self.place(&self.dropped[..self.dropped_count]);
                self.advance(placed)
            }
        {
            self.dropped_count = 0;
            self.capture_start = None;
            self.capture_end = None;
            self.capture_frames = 0;
            self.commit();
        } else {
            self.accepting = false;
            self.discard();
        }
    }

    /// Append a record and commit it (stock 0x91f63808 after locking).
    fn write_block(&mut self, words: &[u32]) {
        if self.put(words) {
            self.commit();
        } else {
            if let [header, tag, ..] = *words
                && PacketHeader(header).is_tagged()
            {
                self.drop_tag(tag);
            }
            self.discard();
        }

        if let Some(&header) = words.first()
            && PacketHeader(header).assigns_value()
        {
            for &word in words {
                self.parse(word);
            }
            if self.flush_capture {
                self.write_capture();
            }
        }

        self.kick();
    }

    /// A consumer block record carrying `data` (stock 0x91f630a0).
    fn write_consumer_block(&mut self, tag: u32, data: &[u8], extra: u32) {
        /// Header, `extra`, tag, and length.
        const FIXED_DWORDS: u32 = 4;

        let length = data.len() as u32;
        let header = PacketHeader::new(
            PacketKind::ConsumerBlock,
            (length.wrapping_add(3) >> 2) + FIXED_DWORDS,
        );

        if self.put(&[header.raw(), extra, tag, length]) && self.put_bytes(data) {
            self.commit();
        } else {
            self.drop_tag(tag);
            self.discard();
        }
    }

    /// Write value group `group` as a tagged record (stock 0x91f63570).
    fn write_group(&mut self, group: usize) {
        /// Header, tag, length, and the time base.
        const FIXED_DWORDS: u32 = 5;

        let Some(&Some(Group { tag, count, first })) = GROUPS.get(group) else {
            return;
        };

        if self.legacy {
            return;
        }

        let time = Timebase::now().ticks();
        let header = PacketHeader::new(PacketKind::Tagged, count as u32 + FIXED_DWORDS);

        if self.put(&[
            header.raw(),
            tag.raw(),
            (count as u32 + 2) << 2,
            (time >> 32) as u32,
            time as u32,
        ]) && {
            let placed = self.place(&self.group_values[first..first + count]);
            self.advance(placed)
        } {
            self.commit();
        } else {
            self.drop_tag(tag.raw());
            self.discard();
        }
    }

    /// Store one dword of a code 0x27 packet in `block`, the ring block,
    /// unless the ring is full.
    fn put_dword(&mut self, block: &[AtomicU32], word: u32) -> bool {
        let base = address(block);
        let next = if self.write == self.last {
            base
        } else {
            self.write + 4
        };

        let full = self.read.wrapping_sub(self.write) & !3 == 4
            || (self.read == base && self.write == self.last);
        if !full {
            // SAFETY: `write` is a dword position in the block
            // (`Ring::buffer`).
            unsafe {
                &*block
                    .as_ptr()
                    .byte_add(self.write.wrapping_sub(base) as usize)
            }
            .store(word, Relaxed);
            self.write = next;
        }

        !full
    }
}

#[repr(C, align(8))]
struct Dpc(UnsafeCell<[u8; 0x20]>);

struct Locked {
    lock: KspinLock,
    irql: UnsafeCell<Irql>,
    dpc: Dpc,
    /// Processor control region of the processor writing a code 0x27
    /// packet, 0 for none. Read without the lock.
    dword_owner: AtomicU32,
    ring: UnsafeCell<Ring>,
}

// SAFETY: `ring` and `irql` are only accessed while `lock` is held; the DPC
// object is used through kernel calls.
unsafe impl Sync for Locked {}

/// A block of a code 0x43 argument and of a code 0x5e list.
#[repr(C)]
struct BlockEntry {
    address: AtomicU32,
    dwords: AtomicU32,
}

/// Records of a code 0x5e block list, up to its null address.
#[derive(Clone)]
struct BlockList<'a> {
    entry: u32,
    records: PhantomData<&'a [u8]>,
}

impl BlockList<'_> {
    /// # Safety
    /// `list` holds 4-byte aligned [`BlockEntry`] values up to a null
    /// address word, each naming `dwords` readable words of any alignment,
    /// all kept for the lifetime of the list.
    unsafe fn new(list: u32) -> Self {
        Self {
            entry: list,
            records: PhantomData,
        }
    }
}

impl<'a> Iterator for BlockList<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        // SAFETY: the entry address lies in the list up to and including
        // its null address word (`BlockList::new`).
        let address = unsafe { crate::kernel::object_at::<AtomicU32>(self.entry) }.load(Relaxed);
        if address == 0 {
            return None;
        }

        // SAFETY: a full entry precedes the null address word, and it names
        // a record of `dwords` words (`BlockList::new`) at the nonzero
        // `address`, a valid pointer for an empty record too. The byte count
        // wraps as in stock.
        let record = unsafe {
            let entry = crate::kernel::object_at::<BlockEntry>(self.entry);
            core::slice::from_raw_parts(
                core::ptr::with_exposed_provenance(address as usize),
                (entry.dwords.load(Relaxed) << 2) as usize,
            )
        };
        self.entry += size_of::<BlockEntry>() as u32;

        Some(record)
    }
}

/// Code 0x41, 0x42, and 0x58 argument.
#[repr(C)]
struct ConsumerArgument {
    callback: AtomicU32,
    context: AtomicU32,
}

/// Transfer context of a title's `pixcmd r` run through code 0x45.
#[repr(C)]
struct TitleTransfer {
    /// Routine the title calls for each run.
    continuation: AtomicU32,
    /// Bytes of the current run.
    length: AtomicU32,
    /// Address of the current run.
    data: AtomicU32,
    /// Snapshot size.
    size: AtomicU32,
    reserved: AtomicU32,
    /// Snapshot size, then the bytes after the end of the block.
    wrapped: AtomicU32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(TitleTransfer, length) == 4);
    assert!(offset_of!(TitleTransfer, data) == 8);
    assert!(offset_of!(TitleTransfer, size) == 0xc);
    assert!(offset_of!(TitleTransfer, reserved) == 0x10);
    assert!(offset_of!(TitleTransfer, wrapped) == 0x14);
};

/// Raise to DISPATCH and take the ring lock (stock 0x91f625c8).
fn acquire() {
    // SAFETY: `RING.lock` is a static spin lock word; the IRQL is restored
    // in `release`.
    let irql = unsafe {
        let irql = KeRaiseIrqlToDpcLevel();
        KeAcquireSpinLockAtRaisedIrql(RING.lock.as_ptr());
        irql
    };

    // SAFETY: the lock is held.
    unsafe { *RING.irql.get() = irql };
}

/// Like [`acquire`] but give up when another processor holds the lock.
fn try_acquire() -> bool {
    // SAFETY: `RING.lock` is a static spin lock word; the IRQL is lowered
    // on failure and in `release` otherwise.
    let irql = unsafe { KeRaiseIrqlToDpcLevel() };
    if !unsafe { KeTryToAcquireSpinLockAtRaisedIrql(RING.lock.as_ptr()) }.get() {
        // SAFETY: returns to the IRQL raised from above.
        unsafe { xboxkrnl::KfLowerIrql(irql) };
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
    // SAFETY: the lock is held by this processor at the raised IRQL.
    unsafe {
        KeReleaseSpinLockFromRaisedIrql(RING.lock.as_ptr());
        xboxkrnl::KfLowerIrql(irql);
    }
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
fn with<R>(f: impl FnOnce(&mut Ring) -> R) -> R {
    acquire();
    // SAFETY: the lock is held for the call.
    let result = f(unsafe { ring() });
    release();

    result
}

/// The caller's `dwords` words at `address`; empty for no words.
///
/// # Safety
/// For a nonzero `dwords`, `address` must be 4-byte aligned and the words
/// valid for reads and unchanged for `'a`, as the record a control code
/// passes.
unsafe fn caller_words<'a>(address: u32, dwords: u32) -> &'a [u32] {
    if dwords == 0 {
        return &[];
    }

    // SAFETY: guaranteed by the caller.
    unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance(address as usize),
            dwords as usize,
        )
    }
}

/// The caller's `length` bytes at `address`, any alignment; empty for no
/// bytes.
///
/// # Safety
/// For a nonzero `length`, the bytes must be valid for reads and unchanged
/// for `'a`, as the data a control code or a consumer passes.
unsafe fn caller_bytes<'a>(address: u32, length: usize) -> &'a [u8] {
    if length == 0 {
        return &[];
    }

    // SAFETY: guaranteed by the caller.
    unsafe {
        core::slice::from_raw_parts(core::ptr::with_exposed_provenance(address as usize), length)
    }
}

/// The bytes of `words` in memory order.
fn word_bytes(words: &[u32]) -> &[u8] {
    // SAFETY: every byte of the initialized words is initialized, and `u8`
    // has no alignment requirement.
    unsafe { core::slice::from_raw_parts(words.as_ptr().cast(), words.len() * 4) }
}

/// Address of the ring block.
fn address(block: &[AtomicU32]) -> u32 {
    crate::kernel::address_of(block)
}

/// Copy `source` to byte `offset` of `block`; a trailing partial word
/// replaces only the leading bytes of its word, as a byte copy does.
///
/// # Safety
/// `offset + source.len()` is at most the byte size of `block`, and the ring
/// lock is held.
#[inline]
unsafe fn copy_to(block: &[AtomicU32], offset: u32, source: &[u8]) {
    // SAFETY: the destination bytes lie in `block` (guaranteed by the
    // caller), whose words may be stored through a shared reference; every
    // ring write holds the ring lock, and no reader of `block` reads the
    // free bytes stored here. `copy` allows the caller's bytes to be
    // anywhere, any alignment.
    unsafe {
        core::ptr::copy(
            source.as_ptr(),
            block.as_ptr().cast::<u8>().cast_mut().add(offset as usize),
            source.len(),
        )
    };
}

/// Whether the ring exists, i.e. tracing is on (stock 0x91f62758).
pub(crate) fn stream_active() -> bool {
    with(|ring| ring.buffer.is_some())
}

/// Write a tagged record `{header, tag, length, payload}` through the
/// monitor control codes so a debugger extension sees it: code 0x5e with a
/// block list, then code 0x43 with one block when 0x5e reports nothing
/// (stock 0x91f788b8); whether it was written. Padding bytes after the
/// payload are zero.
pub(crate) fn write_tagged_record(tag: u32, payload: &[u8]) -> bool {
    if payload.len().div_ceil(4) > TAGGED_PAYLOAD_DWORDS {
        return false;
    }

    let mut record: TaggedRecord = [0; TAGGED_HEADER_DWORDS + TAGGED_PAYLOAD_DWORDS];
    for (word, chunk) in record[TAGGED_HEADER_DWORDS..]
        .iter_mut()
        .zip(payload.chunks(4))
    {
        let mut bytes = [0u8; 4];
        bytes[..chunk.len()].copy_from_slice(chunk);
        *word = u32::from_be_bytes(bytes);
    }

    send_tagged_record(&mut record, tag, payload.len() as u32)
}

/// [`write_tagged_record`] with a payload of dwords.
pub(crate) fn write_tagged_words(tag: u32, words: &[u32]) -> bool {
    if words.len() > TAGGED_PAYLOAD_DWORDS {
        return false;
    }

    let mut record: TaggedRecord = [0; TAGGED_HEADER_DWORDS + TAGGED_PAYLOAD_DWORDS];
    record[TAGGED_HEADER_DWORDS..TAGGED_HEADER_DWORDS + words.len()].copy_from_slice(words);
    send_tagged_record(&mut record, tag, (words.len() * 4) as u32)
}

/// Fill the header of `record`, whose payload of `length` bytes is in
/// place, and write it.
fn send_tagged_record(record: &mut TaggedRecord, tag: u32, length: u32) -> bool {
    let header_dwords = TAGGED_HEADER_DWORDS as u32;
    let dwords = length.div_ceil(4);
    record[0] = PacketHeader::new(PacketKind::Tagged, dwords + header_dwords).raw();
    record[1] = tag;
    record[2] = length;

    let address = record.as_ptr() as usize as u32;
    // Header and payload entries, then the null address that ends the list.
    let list = [
        address,
        header_dwords,
        address + header_dwords * 4,
        dwords,
        0,
    ];
    // SAFETY: `list` is a block list of two entries naming words of
    // `record`, ended by a null address, all live for the call.
    let listed = unsafe {
        dispatcher::dispatch(
            ControlCode::PIX_WRITE_BLOCK_LIST,
            list.as_ptr() as usize as u32,
        )
    };

    match listed as i32 {
        0 => {
            let block = [address, dwords + header_dwords];
            // SAFETY: `block` names the `dwords + header_dwords` words of
            // `record`, both live for the call.
            let written = unsafe {
                dispatcher::dispatch(ControlCode::PIX_WRITE_BLOCK, block.as_ptr() as usize as u32)
            };
            written != 0
        }
        result => result > 0,
    }
}

/// Allocate the ring and register the context switch record routine
/// (stock 0x91f63ba8, `pixcmd b`).
pub(super) fn start() {
    /// Pool tag `PIXs` of the ring block.
    const RING_TAG: PoolTag = PoolTag::new(*b"PIXs");

    acquire();

    // SAFETY: the lock is held.
    let ring = unsafe { ring() };
    let fresh = ring.buffer.is_none();
    if fresh {
        // SAFETY: allocates from the system pool; no pointer arguments.
        let block =
            unsafe { xboxkrnl::ExAllocatePoolTypeWithTag(RING_BYTES, RING_TAG, PoolType::System) };
        // SAFETY: a nonzero result is a fresh pool block of `RING_BYTES`
        // bytes, 4-byte aligned, that only the ring uses until `stop`
        // takes it out of `buffer` and frees it.
        ring.buffer = (block != 0).then(|| unsafe { super::words_at(block, RING_WORDS) });
    }

    if let Some(block) = ring.buffer {
        let base = address(block);
        ring.read = base;
        ring.write = base;
        ring.committed = base;
        ring.notified = false;
        ring.last = base + RING_BYTES - 4;
        ring.accepting = true;
        ring.first_drop_time = 0;
        ring.capture_start = None;
        ring.capture_end = None;
        ring.capture_frames = 0;
        ring.dropped_count = 0;
        ring.capturing = false;
        ring.packet_left = 0;
        ring.captured_index = None;
        ring.flush_capture = false;
        if fresh {
            // Stock keeps the snapshot positions of a freed block, and a
            // later `pixcmd r` reads through them; an empty snapshot keeps
            // the transfer inside the new block.
            ring.snapshot = base;
            ring.snapshot_end = base;
            crate::backend::session::register_swap_routine(context_switch, true);
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
    let block = ring.buffer.take().map(address);
    ring.last = 0;
    ring.read = 0;
    ring.write = 0;
    ring.committed = 0;
    if block.is_some() {
        crate::backend::session::unregister_swap_routine(context_switch);
    }

    release();

    if let Some(block) = block {
        // SAFETY: the ring block from `start`, detached from the ring under
        // the lock.
        unsafe { xboxkrnl::ExFreePool(block) };
    }
}

/// Context swap routine: a `CxSw` record with the time and the processor
/// (stock 0x91f63b40). Skipped when another processor holds the ring.
extern "C" fn context_switch(_old: u32, _frame: u32, _new: u32) {
    let time = Timebase::now().ticks();
    let processor = Kpcr::current().processor_number().get();
    let record = [
        PacketHeader::new(PacketKind::Tagged, 6).raw(),
        RecordTag::CXSW.raw(),
        0xc,
        (time >> 32) as u32,
        time as u32,
        u32::from(processor),
    ];
    write_block(&record, false);
}

/// Append a record and commit it (stock 0x91f63808); `wait` false gives up
/// when the lock is busy.
pub(super) fn write_block(record: &[u32], wait: bool) {
    if wait {
        acquire();
    } else if !try_acquire() {
        return;
    }

    // SAFETY: the lock is held.
    unsafe { ring() }.write_block(record);
    release();
}

/// Frame marker `{header, frame, time}` (stock 0x91f63af0).
pub(super) fn write_frame_marker(frame: u32) {
    let time = Timebase::now().ticks();
    let record = [
        PacketHeader::new(PacketKind::FrameMarker, 4).raw(),
        frame,
        (time >> 32) as u32,
        time as u32,
    ];
    write_block(&record, true);
}

/// Write value group `group` (stock 0x91f63680).
pub(super) fn write_group(group: usize) {
    with(|ring| ring.write_group(group));
}

/// Store the frame number in group 2 and write the group (stock
/// 0x91f636c8).
pub(super) fn write_frame_group(frame: u32) {
    /// Group the frame boundary writes after storing the frame number.
    const FRAME_GROUP: usize = 2;
    /// Group 2 value index that the frame boundary sets to the frame number.
    const FRAME_VALUE: usize = 2;

    with(|ring| {
        if let Some(group) = GROUPS[FRAME_GROUP] {
            ring.group_values[group.first + FRAME_VALUE] = frame;
        }
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

    for consumer in &consumers {
        let Some(callback) = consumer.callback else {
            continue;
        };
        // SAFETY: a title registered `callback` taking three arguments
        // `(context, writer, frame)`.
        unsafe {
            crate::kernel::call_export(
                callback.get(),
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
///
/// # Safety
///
/// The caller must be a consumer called by [`call_consumers`], passing
/// `length` readable bytes at `data` that it keeps for the call.
unsafe extern "C" fn consumer_write(tag: u32, data: u32, length: u32, extra: u32) {
    const D3D_COUNTERS: RecordTag = RecordTag::new(*b"D3dc");
    const XAM_COUNTERS: RecordTag = RecordTag::new(*b"XAM ");
    /// Bytes of a counter block.
    const COUNTER_BLOCK: u32 = 0x28;
    /// Bytes of a counter block with the time base appended.
    const TIMED_COUNTER_BLOCK: u32 = 0x30;
    /// Version bits of the first word of a counter block.
    const VERSION_MASK: u32 = 0xf0;
    const VERSION_1: u32 = 0x10;
    /// Dword of an XAM counter block holding the first XAM group value.
    const XAM_FIRST_VALUE: usize = 3;
    /// Group of the XAM counters an old-protocol consumer block carries.
    const XAM_GROUP: u32 = 3;

    /// The counter block as words, as stock reads it.
    ///
    /// # Safety
    /// `data` is a consumer's aligned block of `COUNTER_BLOCK` bytes.
    unsafe fn counters<'a>(data: u32) -> &'a [u32] {
        // SAFETY: guaranteed by the caller.
        unsafe { caller_words(data, COUNTER_BLOCK >> 2) }
    }

    // SAFETY: the caller's contract: `call_consumers` holds the lock.
    let ring = unsafe { ring() };
    if !ring.legacy {
        if length == COUNTER_BLOCK && tag == D3D_COUNTERS.raw() {
            // SAFETY: a D3D counter block, read by words as in stock.
            let data = unsafe { counters(data) };
            // The current protocol adds the time base and marks version 1.
            let time = Timebase::now().ticks();
            let mut block = [0u32; (TIMED_COUNTER_BLOCK / 4) as usize];
            for (word, &value) in block.iter_mut().zip(data) {
                *word = value;
            }
            block[0] = block[0] & !VERSION_MASK | VERSION_1;
            block[10] = (time >> 32) as u32;
            block[11] = time as u32;
            ring.write_consumer_block(tag, word_bytes(&block), extra);
        } else {
            // SAFETY: the caller's contract; stock copies the bytes
            // bytewise.
            ring.write_consumer_block(tag, unsafe { caller_bytes(data, length as usize) }, extra);
        }

        return;
    }

    if length != COUNTER_BLOCK {
        return;
    }

    if tag == XAM_COUNTERS.raw() {
        // SAFETY: an XAM counter block, read by words as in stock.
        let data = unsafe { counters(data) };
        let mut record = [0u32; 14];
        for ((index, pair), &value) in record
            .chunks_exact_mut(2)
            .enumerate()
            .zip(data.iter().skip(XAM_FIRST_VALUE))
        {
            pair[0] = PacketHeader::assignment(XAM_GROUP, index as u32).raw();
            pair[1] = (value as f32).to_bits();
        }

        if ring.put(&record) {
            ring.commit()
        } else {
            ring.discard()
        }
    } else if tag == D3D_COUNTERS.raw() {
        // SAFETY: the caller's contract.
        ring.write_consumer_block(tag, unsafe { caller_bytes(data, length as usize) }, extra);
    }
}

/// Monitor control code 0x27 (stock 0x91f63938): one dword of a packet
/// whose first dword carries the dword count in bits 24 to 30. The ring
/// stays locked by the writing processor until the packet is complete.
pub(crate) fn service_write_dword(word: u32) -> u32 {
    let processor = crate::kernel::address_of(Kpcr::current());
    // Only the processor holding the lock stores its own address here;
    // another processor reading a stale value only takes the lock.
    if RING.dword_owner.load(Relaxed) != processor {
        acquire();
        RING.dword_owner.store(processor, Relaxed);
        // SAFETY: the lock is held.
        let ring = unsafe { ring() };
        // Stock takes the whole top byte here, bit 31 included.
        ring.dword_left = word >> PacketHeader::DWORDS_SHIFT;
        ring.dword_ok = true;
    }

    // SAFETY: this processor holds the lock until the packet ends.
    let ring = unsafe { ring() };
    ring.parse(word);
    let stored = match ring.buffer {
        Some(block) if ring.dword_ok & ring.accepting => ring.put_dword(block, word),
        _ => false,
    };
    ring.dword_ok = stored;
    ring.dword_left = ring.dword_left.wrapping_sub(1);

    if ring.dword_left == 0 {
        if stored {
            ring.commit()
        } else {
            ring.discard()
        }
        RING.dword_owner.store(0, Relaxed);
        if ring.flush_capture {
            ring.write_capture();
        }
        release();
    }

    u32::from(stored)
}

/// Monitor control code 0x43 (stock 0x91f63808 with `{+0 address, +4
/// dwords}`); stock returns a stale register, this returns 0.
///
/// # Safety
///
/// `argument` must be the address of a block entry naming a record of
/// `dwords` words, both kept valid and unchanged by the caller for the
/// call.
pub(crate) unsafe fn service_write_block(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let record = unsafe {
        let entry = crate::kernel::object_at::<BlockEntry>(argument);
        caller_words(entry.address.load(Relaxed), entry.dwords.load(Relaxed))
    };
    write_block(record, true);

    0
}

/// Monitor control code 0x5e (stock 0x91f62998): a list of `{address,
/// dwords}` pairs ending with a null address, written as one record. 1
/// when written, `0xffffffff` when dropped.
///
/// # Safety
///
/// `argument` must be a block list as [`BlockList::new`] requires, kept
/// by the caller for the call.
pub(crate) unsafe fn service_write_block_list(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let blocks = unsafe { BlockList::new(argument) };

    with(|ring| {
        let written = blocks.clone().all(|record| ring.put_bytes(record));
        if written {
            ring.commit();
        } else {
            // SAFETY: a failed write means the list starts with a full
            // entry (`BlockList::new`).
            let first = unsafe { crate::kernel::object_at::<BlockEntry>(argument) };
            let address = first.address.load(Relaxed);
            if address != 0
                && first.dwords.load(Relaxed) >= 2
                // SAFETY: the first record has at least two words, which
                // stock reads by words.
                && let [header, tag] = *unsafe { caller_words(address, 2) }
                && PacketHeader(header).is_tagged()
            {
                ring.drop_tag(tag);
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
///
/// # Safety
///
/// `argument` must be the address of a consumer argument the caller keeps
/// valid for the call, whose nonzero callback takes `(context, writer,
/// frame)` and stays loaded while registered.
pub(crate) unsafe fn register_consumer(argument: u32, persistent: bool) -> u32 {
    // SAFETY: the caller's contract.
    let argument = unsafe { crate::kernel::object_at::<ConsumerArgument>(argument) };
    let callback = argument.callback.load(Relaxed);
    let context = argument.context.load(Relaxed);

    with(|ring| {
        if let Some(slot) = ring
            .consumers
            .iter_mut()
            .find(|slot| slot.callback.is_none())
        {
            // A null callback leaves the slot free, as in stock.
            *slot = Consumer {
                callback: NonZeroU32::new(callback),
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
        for slot in &mut ring.consumers {
            if slot.callback.is_some() && !slot.persistent {
                slot.callback = None;
            }
        }
    });
}

/// Monitor control code 0x41 (stock 0x91f62b78): remove the consumer with
/// this callback and context.
///
/// # Safety
///
/// `argument` must be the address of a consumer argument the caller keeps
/// valid for the call.
pub(crate) unsafe fn service_unregister_consumer(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let argument = unsafe { crate::kernel::object_at::<ConsumerArgument>(argument) };
    let callback = argument.callback.load(Relaxed);
    let context = argument.context.load(Relaxed);

    with(|ring| {
        if let Some(slot) = ring.consumers.iter_mut().find(|slot| {
            // A free slot matches a null callback, as in stock; freeing it
            // again changes nothing.
            slot.callback.map_or(0, NonZeroU32::get) == callback && slot.context == context
        }) {
            slot.callback = None;
        }
    });

    1
}

/// Replay group `group`'s state to a newly registered event callback:
/// `callback(0, 0)`, then `callback(CounterEnabled, index)` for every
/// value (stock 0x91f62c08), with the ring locked.
///
/// # Safety
///
/// `callback` must be 0 or a loaded routine taking `(operation, value)`.
pub(super) unsafe fn replay_group(group: usize, callback: u32) {
    if callback == 0 {
        return;
    }

    let Some(group) = GROUPS.get(group) else {
        return;
    };

    let count = group.map_or(0, |group| group.count);

    acquire();

    // SAFETY: the caller's contract.
    unsafe { super::events::call(callback, CallbackOperation::ReplayStart, 0) };
    for index in 0..count as u32 {
        // SAFETY: the caller's contract.
        unsafe { super::events::call(callback, CallbackOperation::CounterEnabled, index) };
    }

    release();
}

/// Record the old-protocol flag of `pixcmd q` (stock 0x91f62da0).
pub(super) fn set_legacy(legacy: bool) {
    with(|ring| ring.legacy = legacy);
}

/// GPU capture timing written ahead of the next drop record (stock
/// 0x91f632e8): [`CapturePhase::Start`] starts, [`CapturePhase::End`] ends
/// with `frames` frames.
pub(super) fn capture_timing(phase: u32, frames: u32, time: u64) {
    with(|ring| {
        if phase == CapturePhase::Start.raw() {
            ring.accepting = false;
            if ring.capture_start.is_none() {
                ring.capture_start = NonZeroU64::new(time);
            }
            ring.capture_end = None;
            ring.capture_frames = 0;
        } else if phase == CapturePhase::End.raw() && ring.capture_start.is_some() {
            ring.capture_end = NonZeroU64::new(time);
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
        let Some(block) = ring.buffer else {
            return 0;
        };
        let base = address(block);
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

        // SAFETY: the bytes lie in the block between the snapshot position
        // and the snapshot end or the end of the block; every ring write
        // holds the lock held here.
        let source = unsafe {
            core::slice::from_raw_parts(
                block
                    .as_ptr()
                    .cast::<u8>()
                    .add((ring.snapshot - base) as usize),
                count,
            )
        };
        output[..count].copy_from_slice(source);

        ring.snapshot += count as u32;
        if ring.snapshot > ring.last {
            ring.snapshot = base;
        }

        count
    })
}

/// Fill a title's transfer context for `pixcmd r` run through code 0x45
/// (stock 0x91f63248): the continuation, the snapshot size, and cleared
/// run fields.
///
/// # Safety
///
/// `context` must be the address of a transfer context the title keeps
/// for the transfer.
pub(super) unsafe fn begin_title_transfer(context: u32) {
    let size = with(|ring| ring.span(ring.snapshot, ring.snapshot_end));

    // SAFETY: the caller's contract.
    let transfer = unsafe { crate::kernel::object_at::<TitleTransfer>(context) };
    transfer
        .continuation
        .store(title_transfer_entry as *const () as usize as u32, Relaxed);
    transfer.data.store(0, Relaxed);
    transfer.size.store(size, Relaxed);
    transfer.reserved.store(0, Relaxed);
    transfer.wrapped.store(size, Relaxed);
}

crate::exports::bridged!(title_transfer_entry, title_transfer);

/// Transfer continuation of a title's `pixcmd r` (stock 0x91f63168):
/// each call releases the bytes of the previous call and points the run
/// at the next contiguous bytes; `wrapped` is the length after a wrap.
///
/// # Safety
///
/// `context` must be the transfer context `begin_title_transfer` filled.
unsafe extern "C" fn title_transfer(context: u32) -> u32 {
    // SAFETY: the caller's contract.
    let transfer = unsafe { crate::kernel::object_at::<TitleTransfer>(context) };

    with(|ring| {
        let Some(block) = ring.buffer else {
            return Hresult::END_OF_DATA.0;
        };

        let base = address(block);
        ring.read = ring.snapshot;
        if ring.snapshot == ring.snapshot_end {
            ring.notified = false;
            ring.write_drop_record();
            return Hresult::END_OF_DATA.0;
        }

        transfer.data.store(ring.snapshot, Relaxed);
        if ring.snapshot_end > ring.snapshot {
            transfer.wrapped.store(0, Relaxed);
            transfer.length.store(
                (((ring.snapshot_end - ring.snapshot) as i32 >> 2) << 2) as u32,
                Relaxed,
            );
            ring.snapshot = ring.snapshot_end;
        } else {
            transfer.length.store(
                ((ring.last.wrapping_sub(ring.snapshot).wrapping_add(4) as i32 >> 2) << 2) as u32,
                Relaxed,
            );
            transfer.wrapped.store(
                (((ring.snapshot_end - base) as i32 >> 2) << 2) as u32,
                Relaxed,
            );
            ring.snapshot = base;
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
        status::post_without_text(status::Status::CounterDataAvailable);
    }
}

/// Initialize the lock, the value groups, and the DPC (stock 0x91f62dd8).
pub(super) fn initialize() {
    // SAFETY: runs before any other ring user.
    unsafe { RING.lock.as_ptr().cast::<u32>().write(0) };

    // SAFETY: the static DPC storage, 0x20 bytes, not yet queued.
    unsafe {
        xboxkrnl::KeInitializeDpc(
            RING.dpc.0.get().cast(),
            data_available_entry as *const () as usize,
            0,
        )
    };
}

/// Remove the DPC and the context switch routine and free the ring.
pub(super) fn shut_down() {
    // SAFETY: the static DPC object `initialize` set up.
    unsafe { xboxkrnl::KeRemoveQueueDpc(RING.dpc.0.get().cast()) };

    stop();
}
