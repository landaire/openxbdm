//! Lock pool 'LfPl' (exports 340-351): reader/writer locks whose waiters
//! block on shared wait entries, and a free list of lock records.

use core::mem::offset_of;
use core::num::NonZeroU32;
use core::ptr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_core::status::Hresult;
use xbox360::atomic::Interlocked32;
use xbox360_sys::processor::lwsync;
use xbox360_sys::xam::CreateEventA;
use xbox360_sys::xam::GetCurrentThreadId;
use xbox360_sys::xboxkrnl::Handle;

use super::AllocatorRecord;
use super::Backoff;
use super::DoubleWord;
use super::Error;
use super::NodeAddress;
use super::NodeCounts;
use super::NodeWord;
use super::OutputWord;
use super::Routine;
use super::Signature;
use super::Tagged;
use super::TaggedList;
use super::Timeout;
use super::Wait;
use super::WaitObject;
use super::claim;
use super::close_handle;
use super::container;
use super::create_semaphore;
use super::release_semaphore;
use super::set_event;
use crate::exports::export;

/// Pool object (caller-visible, 0x100 bytes, then the allocator record and
/// the attributes).
#[repr(C, align(8))]
struct Pool {
    /// Free wait entries, linked through their link word.
    free_entries: TaggedList,
    signature: AtomicU32,
    /// Lock record kind ([`Kind::encode`]).
    kind: AtomicU32,
    /// Address of the entry table, and the entry count under
    /// [`Pool::COUNT_MASK`]. Slot 0 stays empty.
    table: DoubleWord,
    /// Free lock records, linked through their holders word.
    records: TaggedList,
    /// Record blocks, linked through their trailers.
    blocks: TaggedList,
    /// Bytes requested from the allocator.
    memory: AtomicU32,
    /// Lock records allocated.
    total: AtomicU32,
    per_block: AtomicU32,
    /// Entry tables made by growth, by log2 of the count at growth.
    grown_tables: [AtomicU32; 15],
    initial_table: [AtomicU32; 32],
    /// Base of the allocation that holds the pool.
    allocation: AtomicU32,
    /// Address of the allocator record after the pool.
    allocator: AtomicU32,
    /// Address of the kept attributes after the allocator record, or 0.
    attributes: AtomicU32,
    _reserved_fc: AtomicU32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(Pool, signature) == 0x08);
    assert!(offset_of!(Pool, kind) == 0x0c);
    assert!(offset_of!(Pool, table) == 0x10);
    assert!(offset_of!(Pool, records) == 0x18);
    assert!(offset_of!(Pool, blocks) == 0x20);
    assert!(offset_of!(Pool, memory) == 0x28);
    assert!(offset_of!(Pool, total) == 0x2c);
    assert!(offset_of!(Pool, per_block) == 0x30);
    assert!(offset_of!(Pool, grown_tables) == 0x34);
    assert!(offset_of!(Pool, initial_table) == 0x70);
    assert!(offset_of!(Pool, allocation) == 0xf0);
    assert!(offset_of!(Pool, allocator) == 0xf4);
    assert!(offset_of!(Pool, attributes) == 0xf8);
    assert!(size_of::<Pool>() == 0x100);
};

xbox360_sys::flags! {
    /// Flags of the pool attributes. Stock tests no other bit: bit 0x8 and
    /// those above 0x20 have no known meaning, and kept attributes keep
    /// them as the caller passed them.
    pub struct PoolFlags(u32) {
        /// The owner may acquire again, counted in the record.
        RECURSIVE = 0x1,
        /// The owner is recorded; it may not acquire again.
        OWNED = 0x2,
        /// Operations may wait.
        MAY_WAIT = 0x4,
        /// Acquirers ask waiters to spin before they block.
        SPIN = 0x10,
        /// Waiters block in alertable waits.
        ALERTABLE = 0x20,
    }
}

impl PoolFlags {
    /// Flags that make the pool keep its attributes.
    const KEPT: Self = Self::MAY_WAIT.union(Self::SPIN).union(Self::ALERTABLE);
}

/// Pool attributes (caller record, 0x18 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct PoolAttributes {
    flags: PoolFlags,
    per_block: u32,
    wait_context: u32,
    timeout: Timeout,
    /// `routine(context, object, timeout, alertable)` replacing the wait.
    wait_routine: Option<Routine>,
    /// [`PoolAttributes::SIZE`].
    size: u32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(PoolAttributes, timeout) == 0xc);
    assert!(offset_of!(PoolAttributes, wait_routine) == 0x10);
    assert!(offset_of!(PoolAttributes, size) == 0x14);
};

impl PoolAttributes {
    const SIZE: u32 = size_of::<Self>() as u32;

    /// The attributes at `address`, or none for 0.
    ///
    /// # Safety
    ///
    /// `address` is 0 or the address of pool attributes (export contract),
    /// whose routine field holds a console routine.
    unsafe fn read(address: u32) -> Result<Option<Self>, Error> {
        let attributes = ptr::with_exposed_provenance::<Self>(address as usize);
        if attributes.is_null() {
            return Ok(None);
        }
        // Stock reads the size before the rest of the record.
        // SAFETY: the caller guarantees the record.
        if unsafe { ptr::read(&raw const (*attributes).size) } != Self::SIZE {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: as above.
        Ok(Some(unsafe { attributes.read() }))
    }
}

/// Wait entry (0x10 bytes).
#[repr(C)]
struct WaitEntry {
    /// Semaphore handle that shared waiters block on.
    semaphore: AtomicU32,
    /// Auto-reset event handle that exclusive and upgrading waiters block
    /// on.
    event: AtomicU32,
    /// Slot of the entry in the entry table.
    index: AtomicU32,
    /// Link on the free entry list.
    _link: AtomicU32,
}

const _: () = assert!(core::mem::offset_of!(WaitEntry, _link) == NodeWord::Word3 as usize);

impl WaitEntry {
    fn semaphore(&self) -> Handle {
        Handle::from_raw(self.semaphore.load(Relaxed))
    }

    fn event(&self) -> Handle {
        Handle::from_raw(self.event.load(Relaxed))
    }

    fn address(&self) -> NodeAddress {
        // SAFETY: a reference is not null.
        unsafe { NodeAddress::new_unchecked(ptr::from_ref(self).expose_provenance() as u32) }
    }
}

/// Lock record: the holders word and the waiters word, changed as one
/// doubleword. Records of owned and recursive pools are
/// [`OwnedLockRecord`]s.
#[repr(C, align(8))]
struct LockRecord {
    state: DoubleWord,
}

impl LockRecord {
    /// Alignment bits a record address leaves clear, as `ldarx` requires.
    const ALIGNMENT_MASK: u32 = align_of::<Self>() as u32 - 1;
}

/// Lock record of an owned or recursive pool.
#[repr(C, align(8))]
struct OwnedLockRecord {
    record: LockRecord,
    ownership: Ownership,
}

/// Owner fields of a lock record of an owned or recursive pool.
#[repr(C)]
struct Ownership {
    /// Thread id of the exclusive owner, or 0.
    owner: AtomicU32,
    recursion: AtomicU32,
}

const _: () = {
    assert!(size_of::<LockRecord>() == 0x8);
    assert!(offset_of!(OwnedLockRecord, ownership) == 0x8);
    assert!(size_of::<OwnedLockRecord>() == 0x10);
};

/// Holders word of a lock record: the shared holder count, the upgrade and
/// exclusive bits, and above them the count of exclusive and upgrading
/// waiters.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Holders(u32);

impl Holders {
    /// Shared holder count.
    const SHARED: u32 = 0x7fff;
    /// An upgrade waits for the shared holders to leave.
    const UPGRADING: u32 = 0x8000;
    const EXCLUSIVE: u32 = 0x1_0000;
    /// One exclusive or upgrading waiter.
    const WAITER: u32 = 0x2_0000;
    /// Exclusive and upgrading waiter count.
    const WAITERS: u32 = !(Self::WAITER - 1);

    const NONE: Self = Self(0);

    fn has_shared(self) -> bool {
        self.0 & Self::SHARED != 0
    }

    fn is_upgrading(self) -> bool {
        self.0 & Self::UPGRADING != 0
    }

    fn is_exclusive(self) -> bool {
        self.0 & Self::EXCLUSIVE != 0
    }

    fn has_waiters(self) -> bool {
        self.0 & Self::WAITERS != 0
    }

    /// The waiter count bits in place.
    fn waiter_field(self) -> u32 {
        self.0 & Self::WAITERS
    }

    /// An exclusive holder or waiters.
    fn is_held(self) -> bool {
        self.0 & (Self::EXCLUSIVE | Self::WAITERS) != 0
    }

    /// A shared or exclusive holder.
    fn has_holder(self) -> bool {
        self.0 & (Self::EXCLUSIVE | Self::SHARED) != 0
    }

    /// A holder or a pending upgrade, either of which keeps an exclusive
    /// acquirer out.
    fn has_holder_or_upgrade(self) -> bool {
        self.0 & (Self::EXCLUSIVE | Self::UPGRADING | Self::SHARED) != 0
    }

    fn add_shared(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    fn remove_shared(self) -> Self {
        Self(self.0.wrapping_sub(1))
    }

    fn add_waiter(self) -> Self {
        Self(self.0.wrapping_add(Self::WAITER))
    }

    fn remove_waiter(self) -> Self {
        Self(self.0.wrapping_sub(Self::WAITER))
    }

    fn with_exclusive(self) -> Self {
        Self(self.0 | Self::EXCLUSIVE)
    }

    fn without_exclusive(self) -> Self {
        Self(self.0 & !Self::EXCLUSIVE)
    }

    fn with_upgrading(self) -> Self {
        Self(self.0 | Self::UPGRADING)
    }

    fn without_upgrading(self) -> Self {
        Self(self.0 & !Self::UPGRADING)
    }
}

/// Waiters word of a lock record: the shared waiter count, the spin and
/// caller record bits, and above them the table slot of the wait entry
/// that the waiters share.
#[derive(Clone, Copy)]
struct Waiters(u32);

impl Waiters {
    /// Shared waiter count.
    const SHARED: u32 = 0x7fff;
    /// Waiters spin before blocking.
    const SPIN: u32 = 0x8000;
    /// The caller initialized the record (export 348).
    const CALLER_RECORD: u32 = 0x1_0000;
    const INDEX_SHIFT: u32 = 17;
    /// Wait entry slot; 0 for none.
    const INDEX: u32 = u32::MAX << Self::INDEX_SHIFT;

    /// Shared waiter count.
    fn shared(self) -> u32 {
        self.0 & Self::SHARED
    }

    fn spins(self) -> bool {
        self.0 & Self::SPIN != 0
    }

    fn with_spin(self) -> Self {
        Self(self.0 | Self::SPIN)
    }

    fn without_spin(self) -> Self {
        Self(self.0 & !Self::SPIN)
    }

    /// The spin bit set from an acquirer's flag.
    fn spin_as(self, spin: bool) -> Self {
        Self((self.0 & !Self::SPIN) | if spin { Self::SPIN } else { 0 })
    }

    fn with_caller_record(self) -> Self {
        Self(self.0 | Self::CALLER_RECORD)
    }

    /// Table slot of the wait entry.
    fn index(self) -> u32 {
        self.0 >> Self::INDEX_SHIFT
    }

    fn has_entry(self) -> bool {
        self.0 & Self::INDEX != 0
    }

    /// The word with the entry at slot `index` added; the word names no
    /// entry.
    fn with_entry(self, index: u32) -> Self {
        Self(self.0.wrapping_add(index << Self::INDEX_SHIFT))
    }

    fn without_entry(self) -> Self {
        Self(self.0 & !Self::INDEX)
    }

    fn add_shared(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    fn remove_shared(self) -> Self {
        Self(self.0.wrapping_sub(1))
    }
}

/// A failed lock operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockError {
    Container(Error),
    /// Export 351 with a mode other than shared or exclusive.
    BadMode,
    NotHeld,
    UpgradePending,
    ExclusiveWaiting,
    NotRecursive,
}

/// Stock keeps its internal codes of the lock failures and wait routine
/// results in one status word, so a wait result equal to a code reports as
/// that code.
impl From<Error> for LockError {
    fn from(error: Error) -> Self {
        const NOT_HELD: u32 = 0xe000_0001;
        const UPGRADE_PENDING: u32 = 0xe000_0002;
        const EXCLUSIVE_WAITING: u32 = 0xe000_0003;
        const NOT_RECURSIVE: u32 = 0xe000_0004;
        match error {
            Error::Wait(status) => match status.code() {
                NOT_HELD => Self::NotHeld,
                UPGRADE_PENDING => Self::UpgradePending,
                EXCLUSIVE_WAITING => Self::ExclusiveWaiting,
                NOT_RECURSIVE => Self::NotRecursive,
                _ => Self::Container(error),
            },
            error => Self::Container(error),
        }
    }
}

impl From<LockError> for Hresult {
    fn from(error: LockError) -> Self {
        let code = match error {
            LockError::Container(error) => return error.into(),
            LockError::BadMode => 3,
            LockError::NotHeld => 4,
            LockError::UpgradePending => 5,
            LockError::ExclusiveWaiting => 6,
            LockError::NotRecursive => 7,
        };
        Self::failure(Error::FACILITY, code)
    }
}

impl core::fmt::Display for LockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Container(error) => error.fmt(f),
            Self::BadMode => f.write_str("release mode is neither shared nor exclusive"),
            Self::NotHeld => f.write_str("lock not held"),
            Self::UpgradePending => f.write_str("another upgrade is pending"),
            Self::ExclusiveWaiting => f.write_str("an exclusive acquirer waits"),
            Self::NotRecursive => f.write_str("lock is not recursive"),
        }
    }
}

impl core::error::Error for LockError {}

fn lock_result(result: Result<(), LockError>) -> Hresult {
    match result {
        Ok(()) => Hresult::SUCCESS,
        Err(error) => error.into(),
    }
}

/// Lock record kind of a pool.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// 8-byte records without an owner.
    Plain,
    /// The owner is recorded; it may not acquire again.
    Owned,
    /// The owner may acquire again, counted in the record.
    Recursive,
}

impl Kind {
    fn from_flags(flags: PoolFlags) -> Self {
        if flags.contains(PoolFlags::RECURSIVE) {
            Self::Recursive
        } else if flags.contains(PoolFlags::OWNED) {
            Self::Owned
        } else {
            Self::Plain
        }
    }

    /// Pool word: -1, 0 or 1.
    fn encode(self) -> u32 {
        match self {
            Self::Plain => -1i32 as u32,
            Self::Owned => 0,
            Self::Recursive => 1,
        }
    }

    /// Pool word: negative, 0 or positive.
    fn decode(word: u32) -> Self {
        match word as i32 {
            kind if kind < 0 => Self::Plain,
            0 => Self::Owned,
            _ => Self::Recursive,
        }
    }

    fn record_size(self) -> u32 {
        if self == Self::Plain {
            size_of::<LockRecord>() as u32
        } else {
            size_of::<OwnedLockRecord>() as u32
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FirstRecord {
    Keep,
    Free,
}

impl Pool {
    const SIZE: u32 = size_of::<Self>() as u32;
    /// Entry count bits of the table count word.
    const COUNT_MASK: u32 = 0x7fff_ffff;
    /// Entry count that marks the table full.
    const ENTRY_LIMIT: u32 = 0x8000;
    const INITIAL_CAPACITY: u32 = 32;
    /// Entry count of a new pool: slot 0 stays empty.
    const INITIAL_COUNT: u32 = 1;
    /// Bound on the entry count at which the table grows, so that the
    /// bytes of the doubled table stay a positive `i32`.
    const MAX_GROWTH_COUNT: u32 = 0x0fff_ffff;
    /// Bound on the records that export 347 adds to an owned or recursive
    /// pool, so that their bytes stay a positive `i32`.
    const MAX_RESERVED_RECORDS: u32 = 0x07ff_ffff;
    /// Lock records per block without attributes.
    const DEFAULT_PER_BLOCK: u32 = 16;

    /// The pool at `handle`.
    ///
    /// # Safety
    ///
    /// `handle` is 0 or the address of a pool (export contract) that stays
    /// allocated for `'a`.
    unsafe fn from_handle<'a>(handle: u32) -> Option<&'a Self> {
        // SAFETY: the caller guarantees the pool.
        unsafe { container(handle, Signature::POOL, offset_of!(Self, signature)) }
    }

    fn kind(&self) -> Kind {
        Kind::decode(self.kind.load(Relaxed))
    }

    fn allocator(&self) -> &AllocatorRecord {
        // SAFETY: the allocator word of a live pool (module invariants).
        unsafe { AllocatorRecord::at(&self.allocator) }
    }

    fn attributes(&self) -> Option<&PoolAttributes> {
        let address = self.attributes.load(Relaxed);
        // SAFETY: a nonzero attributes word holds the address of the
        // attributes creation copied after the allocator record.
        unsafe { ptr::with_exposed_provenance::<PoolAttributes>(address as usize).as_ref() }
    }

    /// Slot `index` of the entry table at `table`.
    ///
    /// # Safety
    ///
    /// `table` is an entry table of this pool with more than `index`
    /// slots.
    unsafe fn slot(&self, table: u32, index: u32) -> &AtomicU32 {
        let address = table.wrapping_add(4 * index);
        // SAFETY: the caller guarantees the slot.
        unsafe { &*ptr::with_exposed_provenance(address as usize) }
    }

    /// The entry an installed slot `index` of the current table holds.
    ///
    /// # Safety
    ///
    /// `index` is below the entry count, and the current table has more
    /// than `index` slots.
    unsafe fn entry(&self, index: u32) -> Option<&WaitEntry> {
        // SAFETY: the caller guarantees the slot.
        let entry = unsafe { self.slot(self.table.high.load(Relaxed), index) }.load(Relaxed);
        // SAFETY: table slots hold 0 or entries this pool allocated, which
        // stay until destroy.
        NodeAddress::new(entry).map(|entry| unsafe { entry.get(self) })
    }

    /// The entry a waiters word names.
    ///
    /// # Safety
    ///
    /// `waiters` was read from a lock record of this pool (export 340 and
    /// 351 contract) while it named an entry: the slot of an installed
    /// entry, which install placed in the current table or copied into it.
    unsafe fn entry_of(&self, waiters: Waiters) -> &WaitEntry {
        let index = waiters.index();
        // SAFETY: the caller guarantees the slot.
        unsafe {
            let entry = self
                .slot(self.table.high.load(Relaxed), index)
                .load(Relaxed);
            NodeAddress::new_unchecked(entry).get(self)
        }
    }

    fn free_entry(&self, entry: &WaitEntry) {
        // SAFETY: an entry of this pool, on no list.
        unsafe { self.free_entries.push(entry.address(), NodeWord::Word3) };
    }

    fn take_entry(&self) -> Option<&WaitEntry> {
        // SAFETY: the free entry list holds entries of this pool, which stay
        // until destroy.
        unsafe { self.free_entries.pop(NodeWord::Word3) }
            // SAFETY: as above.
            .map(|entry| unsafe { entry.get(self) })
            .or_else(|| self.create_entry())
    }

    /// Allocate a wait entry with its semaphore and event and give it a
    /// table slot; any failure marks the table full.
    fn create_entry(&self) -> Option<&WaitEntry> {
        if self.table.low.load(Relaxed) & Self::COUNT_MASK == Self::ENTRY_LIMIT {
            return None;
        }
        let allocator = self.allocator();
        if let Some(address) = allocator.allocate(size_of::<WaitEntry>() as u32, &self.memory) {
            // SAFETY: a new allocation of an entry.
            let entry = unsafe { NodeAddress(address).get::<WaitEntry, _>(self) };
            let semaphore = create_semaphore();
            entry
                .semaphore
                .store(semaphore.map_or(0, Handle::raw), Relaxed);
            if let Some(semaphore) = semaphore {
                // SAFETY: a null name creates an unnamed auto-reset event.
                let event = unsafe { CreateEventA(0, false, false, ptr::null()) };
                entry.event.store(event.raw(), Relaxed);
                if !event.is_null() {
                    if self.install(entry) {
                        return Some(entry);
                    }
                    close_handle(event);
                }
                close_handle(semaphore);
            }
            allocator.free(address.get());
        }
        loop {
            let current = self.table.load();
            if current.low() & Self::COUNT_MASK == Self::ENTRY_LIMIT
                || self
                    .table
                    .compare_exchange(current, Tagged::new(current.high(), Self::ENTRY_LIMIT))
            {
                return None;
            }
        }
    }

    /// Store `entry` at the next table slot, doubling the table when a
    /// power-of-two count of at least 32 fills it.
    fn install(&self, entry: &WaitEntry) -> bool {
        let address = entry.address().raw();
        loop {
            let current = self.table.load();
            let count = current.low() & Self::COUNT_MASK;
            if count == Self::ENTRY_LIMIT {
                return false;
            }
            let table = current.high();
            if count >= Self::INITIAL_CAPACITY && count.is_power_of_two() {
                if count >= Self::MAX_GROWTH_COUNT {
                    return false;
                }
                let allocator = self.allocator();
                // The doubled table: twice the slots of the current one.
                let size = count * (2 * size_of::<AtomicU32>() as u32);
                let Some(grown) = allocator.allocate(size, &self.memory) else {
                    return false;
                };
                let slots = ptr::with_exposed_provenance_mut::<u32>(grown.get() as usize);
                let count_slots = count as usize;
                for index in 0..count {
                    // SAFETY: the current table holds `count` slots.
                    let value = unsafe { self.slot(table, index) }.load(Relaxed);
                    // SAFETY: the new allocation holds 2 * `count` slots and
                    // no other thread sees it yet.
                    unsafe { slots.add(index as usize).write(value) };
                }
                // SAFETY: as above.
                unsafe {
                    slots.add(count_slots).write(address);
                    slots.add(count_slots + 1).write_bytes(0, count_slots - 1);
                }
                if self
                    .table
                    .compare_exchange(current, Tagged::new(grown.get(), count + 1))
                {
                    entry.index.store(count, Relaxed);
                    if let Some(slot) = self.grown_tables.get(count.trailing_zeros() as usize) {
                        slot.swap_relaxed(grown.get());
                    }
                    return true;
                }
                allocator.free(grown.get());
                continue;
            }
            // SAFETY: a count below 32 is within the initial table, and any
            // other count lies below twice the count the current table grew
            // at.
            let claimed = unsafe { self.slot(table, count) }
                .compare_exchange_release(0, address)
                .is_ok();
            if claimed {
                entry.index.store(count, Relaxed);
            }
            self.table
                .compare_exchange(current, Tagged::new(table, count + 1));
            if claimed {
                return true;
            }
        }
    }

    /// Slots of the current entry table: the initial table or the newest
    /// grown one.
    fn capacity(&self, table: u32) -> Option<u32> {
        if table == ptr::from_ref(&self.initial_table).expose_provenance() as u32 {
            return Some(Self::INITIAL_CAPACITY);
        }
        (0..self.grown_tables.len())
            .find(|&order| self.grown_tables[order].load(Relaxed) == table)
            .map(|order| 2 << order)
    }

    /// Allocate `count` lock records and put them on the free list, or all
    /// but the first, which is returned, with [`FirstRecord::Keep`].
    fn add_records(&self, count: u32, first: FirstRecord) -> Option<NodeAddress> {
        let record_size = self.kind().record_size();
        let size = count.wrapping_mul(record_size);
        // SAFETY: the block list of this pool.
        let block = unsafe {
            self.allocator()
                .allocate_block(&self.blocks, size, &self.memory)
        }?;
        self.total.fetch_add_relaxed(count);
        let mut record = block.raw().wrapping_add(size);
        for _ in u32::from(first == FirstRecord::Keep)..count {
            record = record.wrapping_sub(self.kind().record_size());
            // SAFETY: a record inside the new block, on no list.
            unsafe {
                self.records
                    .push(NodeAddress::new_unchecked(record), NodeWord::Word0)
            };
        }
        Some(block)
    }

    fn pop_record(&self) -> Option<NodeAddress> {
        // SAFETY: the free record list holds records of this pool's blocks
        // or records callers returned with export 345.
        unsafe { self.records.pop(NodeWord::Word0) }
    }

    fn create(attributes: Option<&PoolAttributes>) -> Result<&'static Self, Error> {
        let (flags, per_block) = attributes.map_or(
            (PoolFlags::empty(), Self::DEFAULT_PER_BLOCK),
            |attributes| {
                (
                    attributes.flags,
                    NodeCounts::clamp_per_block(attributes.per_block),
                )
            },
        );
        let kept = attributes.filter(|_| flags.intersects(PoolFlags::KEPT));
        let allocator = AllocatorRecord::default_routines();
        let memory = AtomicU32::new(0);
        let size = Self::SIZE + AllocatorRecord::SIZE + kept.map_or(0, |_| PoolAttributes::SIZE);
        let allocation = allocator
            .allocate_aligned(size, &memory)
            .ok_or(Error::NotEnoughMemory)?;
        let object = ptr::with_exposed_provenance_mut::<Self>(allocation.aligned.get() as usize);
        // SAFETY: the new allocation holds the pool, the allocator record and
        // the kept attributes, aligned to 128 bytes; zero bytes are a valid
        // pool.
        let pool = unsafe {
            object.write_bytes(0, 1);
            &*object
        };
        pool.allocation.store(allocation.base, Relaxed);
        pool.memory.store(memory.load(Relaxed), Relaxed);
        let record = object.wrapping_add(1).cast::<AllocatorRecord>();
        pool.allocator
            .store(record.expose_provenance() as u32, Relaxed);
        // SAFETY: the record and the attributes follow the pool inside the
        // allocation.
        unsafe {
            record.write(allocator);
            if let Some(kept) = kept {
                let copy = record.wrapping_add(1).cast::<PoolAttributes>();
                pool.attributes
                    .store(copy.expose_provenance() as u32, Relaxed);
                copy.write(*kept);
            }
        }
        pool.kind.store(Kind::from_flags(flags).encode(), Relaxed);
        pool.per_block.store(per_block, Relaxed);
        pool.table.high.store(
            ptr::from_ref(&pool.initial_table).expose_provenance() as u32,
            Relaxed,
        );
        pool.table.low.store(Self::INITIAL_COUNT, Relaxed);
        pool.signature.store(Signature::POOL.0, Relaxed);
        lwsync();
        Ok(pool)
    }

    /// Clear the signature of the pool at `handle` and free it with its
    /// entries; whether it was a pool.
    ///
    /// # Safety
    ///
    /// `handle` is 0 or the address of a pool (export contract) on which no
    /// other operation runs, now or later.
    unsafe fn destroy(handle: u32) -> bool {
        // SAFETY: the caller guarantees the pool. The reference is not used
        // once the pool is freed.
        let Some(pool) =
            (unsafe { claim::<Self>(handle, Signature::POOL, offset_of!(Self, signature)) })
        else {
            return false;
        };
        let allocator = *pool.allocator();
        let table = pool.table.high.load(Relaxed);
        let count = pool.table.low.load(Relaxed) & Self::COUNT_MASK;
        // Stock walks to the count even when a failure set it to the full
        // mark past the end of the table; the walk stays within the table
        // here, and a table of unknown origin is not walked.
        let slots = pool
            .capacity(table)
            .map_or(0, |capacity| count.min(capacity));
        for index in (0..slots).rev() {
            // SAFETY: below both the count and the table's capacity.
            if let Some(entry) = unsafe { pool.entry(index) } {
                close_handle(entry.semaphore());
                close_handle(entry.event());
                allocator.free(entry.address().raw());
            }
        }
        for grown in &pool.grown_tables {
            let grown = grown.load(Relaxed);
            if grown != 0 {
                allocator.free(grown);
            }
        }
        // SAFETY: the block list of the pool, which no operation uses
        // anymore.
        unsafe { allocator.free_blocks(&pool.blocks) };
        allocator.free(pool.allocation.load(Relaxed));
        lwsync();
        true
    }
}

/// Holders and waiters words of a lock record, read in one access.
#[derive(Clone, Copy)]
struct State {
    holders: Holders,
    waiters: Waiters,
}

impl State {
    fn of(word: Tagged) -> Self {
        Self {
            holders: Holders(word.high()),
            waiters: Waiters(word.low()),
        }
    }

    fn word(self) -> Tagged {
        Tagged::new(self.holders.0, self.waiters.0)
    }

    /// The waiters word less the entry index once nobody waits.
    fn idle_waiters(self) -> Waiters {
        if self.holders.waiter_field() | self.waiters.shared() == 0 {
            self.waiters.without_entry()
        } else {
            self.waiters
        }
    }

    /// A shared take of the waiters word: unless spinning is asked, waiters
    /// stop spinning; a spinning acquirer turns spinning on only for an
    /// unheld lock.
    fn shared_spin(self, spin: bool) -> Waiters {
        if !spin {
            self.waiters.without_spin()
        } else if !self.holders.has_shared() {
            self.waiters.with_spin()
        } else {
            self.waiters
        }
    }
}

/// Who finished a take after waiting.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Taker {
    Shared,
    Exclusive,
    /// The exclusive take while spinning, the only one stock follows with a
    /// barrier.
    SpinningExclusive,
}

/// Whether an upgrade may pass exclusive waiters.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Precedence {
    /// Exclusive waiters fail the upgrade.
    Behind,
    Ahead,
}

/// One attempt to take a lock after waiting.
enum Take {
    /// Taken; the waiters word stored.
    Taken(Waiters),
    /// Still held.
    Busy(State),
    /// Another thread changed the record; the waiters word computed.
    Lost(Waiters),
}

/// One operation on a lock record.
struct Request<'a> {
    pool: &'a Pool,
    kind: Kind,
    lock: &'a LockRecord,
    /// Owner fields; none in a plain pool.
    ownership: Option<&'a Ownership>,
    wait: Wait,
    /// Fail rather than wait.
    immediate: bool,
    /// Wait entry this operation holds.
    entry: Option<&'a WaitEntry>,
    backoff: Backoff,
    /// Calling thread, read when the pool records owners.
    owner: Option<u32>,
}

impl<'a> Request<'a> {
    /// A request on the record at `lock`.
    ///
    /// # Safety
    ///
    /// `lock` is the address of a lock record of `pool` (export 340 and 351
    /// contract): 8-byte aligned, as `ldarx` requires, an
    /// [`OwnedLockRecord`] in owned and recursive pools, and valid for
    /// `'a`.
    unsafe fn new(pool: &'a Pool, lock: NonZeroU32) -> Self {
        let address = lock.get() as usize;
        let kind = pool.kind();
        // SAFETY: the caller guarantees the record.
        let record = unsafe { &*ptr::with_exposed_provenance::<LockRecord>(address) };
        let ownership = (kind != Kind::Plain).then(|| {
            // SAFETY: as above.
            unsafe { &(*ptr::with_exposed_provenance::<OwnedLockRecord>(address)).ownership }
        });
        Self {
            pool,
            kind,
            lock: record,
            ownership,
            wait: Wait::NONE,
            immediate: true,
            entry: None,
            backoff: Backoff::new(),
            owner: None,
        }
    }

    fn read(&self) -> State {
        State::of(self.lock.state.load())
    }

    fn swap(&self, old: State, new: State) -> bool {
        self.lock.state.compare_exchange(old.word(), new.word())
    }

    /// Whether the caller owns the record; the thread id is kept to record
    /// as owner later. Plain records have no owner.
    fn owned_by_caller(&mut self) -> bool {
        let Some(ownership) = self.ownership else {
            return false;
        };
        let thread = GetCurrentThreadId();
        self.owner = Some(thread);
        ownership.owner.load(Relaxed) == thread
    }

    fn record_owner(&self) {
        if let (Some(thread), Some(ownership)) = (self.owner, self.ownership) {
            ownership.owner.store(thread, Relaxed);
        }
    }

    fn release_entry(&mut self) {
        if let Some(entry) = self.entry.take() {
            self.pool.free_entry(entry);
        }
    }

    fn may_wait(&self, waiters: Waiters) -> bool {
        !self.immediate && (waiters.spins() || self.wait.timeout != Timeout::IMMEDIATE)
    }

    /// Give the waiters word an entry index, taking an entry when it has
    /// none.
    fn attach(&mut self, waiters: Waiters) -> Result<Waiters, Error> {
        if waiters.has_entry() {
            return Ok(waiters);
        }
        let entry = match self.entry {
            Some(entry) => entry,
            None => self.pool.take_entry().ok_or(Error::NotEnoughMemory)?,
        };
        self.entry = Some(entry);
        Ok(waiters.with_entry(entry.index.load(Relaxed)))
    }

    /// Use the entry the stored waiters word names.
    fn adopt(&mut self, waiters: Waiters) -> &'a WaitEntry {
        let index = waiters.index();
        match self.entry {
            Some(entry) if entry.index.load(Relaxed) == index => entry,
            _ => {
                self.release_entry();
                // SAFETY: the stored waiters word names the entry.
                let entry = unsafe { self.pool.entry_of(waiters) };
                self.entry = Some(entry);
                entry
            }
        }
    }

    /// Spin up to [`Backoff::SPIN_ATTEMPTS`] times while the record asks
    /// waiters to spin.
    fn spin(&mut self, waiters: Waiters, mut take: impl FnMut(&Self) -> Take) -> Option<Waiters> {
        if !waiters.spins() {
            return None;
        }
        for _ in 0..Backoff::SPIN_ATTEMPTS {
            self.backoff.pause();
            match take(self) {
                Take::Taken(stored) => return Some(stored),
                Take::Busy(State { waiters, .. }) | Take::Lost(waiters) => {
                    if !waiters.spins() {
                        break;
                    }
                }
            }
        }
        None
    }

    /// Finish a take after waiting: the entry returns to the free list once
    /// the record names none.
    fn taken(&mut self, stored: Waiters, taker: Taker) -> Result<(), LockError> {
        if !stored.has_entry() {
            self.release_entry();
        }
        if taker != Taker::Shared {
            self.record_owner();
        }
        if taker == Taker::SpinningExclusive {
            lwsync();
        }
        Ok(())
    }

    fn block(&self, handle: Handle) -> Result<(), LockError> {
        self.wait
            .block(WaitObject::Handle(handle))
            .map_err(LockError::from)
    }

    fn take_shared(&self) -> Take {
        let old = self.read();
        if old.holders.is_held() {
            return Take::Busy(old);
        }
        let holders = old.holders.add_shared();
        let waiters = State {
            holders,
            waiters: old.shared_spin(self.wait.spin).remove_shared(),
        }
        .idle_waiters();
        if self.swap(old, State { holders, waiters }) {
            Take::Taken(waiters)
        } else {
            Take::Lost(waiters)
        }
    }

    fn shared(&mut self) -> Result<(), LockError> {
        if self.owned_by_caller() {
            if self.kind == Kind::Owned {
                return Err(LockError::NotRecursive);
            }
            loop {
                let old = self.read();
                let waiters = old.shared_spin(self.wait.spin);
                if self.swap(
                    old,
                    State {
                        holders: old.holders.add_shared(),
                        waiters,
                    },
                ) {
                    return Ok(());
                }
            }
        }
        let registered = loop {
            let old = self.read();
            let (holders, waiters) = (old.holders, old.waiters);
            if !holders.is_held() {
                if self.swap(
                    old,
                    State {
                        holders: holders.add_shared(),
                        waiters: old.shared_spin(self.wait.spin),
                    },
                ) {
                    self.release_entry();
                    return Ok(());
                }
                continue;
            }
            if !self.may_wait(waiters) {
                self.release_entry();
                return Err(Error::Timeout.into());
            }
            let waiters = match self.attach(waiters) {
                Ok(waiters) => waiters.add_shared(),
                Err(error) => return Err(error.into()),
            };
            if self.swap(old, State { holders, waiters }) {
                break waiters;
            }
        };
        let entry = self.adopt(registered);
        if let Some(stored) = self.spin(registered, Self::take_shared) {
            return self.taken(stored, Taker::Shared);
        }
        loop {
            if let Err(error) = self.block(entry.semaphore()) {
                let stored = loop {
                    let old = self.read();
                    let waiters = State {
                        holders: old.holders,
                        waiters: old.waiters.remove_shared(),
                    }
                    .idle_waiters();
                    if self.swap(
                        old,
                        State {
                            holders: old.holders,
                            waiters,
                        },
                    ) {
                        break waiters;
                    }
                };
                if !stored.has_entry() {
                    self.release_entry();
                }
                return Err(error);
            }
            loop {
                match self.take_shared() {
                    Take::Taken(stored) => return self.taken(stored, Taker::Shared),
                    Take::Busy(..) => break,
                    Take::Lost(_) => {}
                }
            }
        }
    }

    fn take_exclusive(&self) -> Take {
        let old = self.read();
        let (holders, waiters) = (old.holders, old.waiters);
        if holders.has_holder_or_upgrade() {
            return Take::Busy(old);
        }
        let holders = holders.with_exclusive().remove_waiter();
        let waiters = State {
            holders,
            waiters: waiters.spin_as(self.wait.spin),
        }
        .idle_waiters();
        if self.swap(old, State { holders, waiters }) {
            Take::Taken(waiters)
        } else {
            Take::Lost(waiters)
        }
    }

    /// Leave the waiters after a failed wait. `holders` gives the holders
    /// word to store; shared waiters run when no exclusive holder or waiter
    /// remains.
    fn abandon(
        &mut self,
        entry: &WaitEntry,
        error: LockError,
        holders: impl Fn(Holders) -> Holders,
    ) -> Result<(), LockError> {
        let (holders, waiters) = loop {
            let old = self.read();
            let holders = holders(old.holders);
            let waiters = State {
                holders,
                waiters: old.waiters,
            }
            .idle_waiters();
            if self.swap(old, State { holders, waiters }) {
                break (holders, waiters);
            }
        };
        if !waiters.has_entry() {
            self.release_entry();
        }
        if !holders.is_held() && waiters.shared() != 0 {
            release_semaphore(entry.semaphore(), waiters.shared());
        }
        Err(error)
    }

    fn exclusive(&mut self) -> Result<(), LockError> {
        if self.owned_by_caller()
            && let Some(ownership) = self.ownership
        {
            if self.kind == Kind::Owned {
                return Err(LockError::NotRecursive);
            }
            let recursion = &ownership.recursion;
            recursion.store(recursion.load(Relaxed).wrapping_add(1), Relaxed);
            // Stock passes the compare and exchange values of this update
            // swapped and spins until another thread clears the bit; the
            // bit is cleared here.
            if !self.wait.spin && Waiters(self.lock.state.low.load(Relaxed)).spins() {
                loop {
                    let old = self.read();
                    if self.swap(
                        old,
                        State {
                            holders: old.holders,
                            waiters: old.waiters.without_spin(),
                        },
                    ) {
                        break;
                    }
                }
            }
            lwsync();
            return Ok(());
        }
        let registered = loop {
            let old = self.read();
            let (holders, waiters) = (old.holders, old.waiters);
            if holders == Holders::NONE || (waiters.spins() && !holders.has_holder_or_upgrade()) {
                if self.swap(
                    old,
                    State {
                        holders: holders.with_exclusive(),
                        waiters: waiters.spin_as(self.wait.spin),
                    },
                ) {
                    self.release_entry();
                    self.record_owner();
                    return Ok(());
                }
                continue;
            }
            if !self.may_wait(waiters) {
                self.release_entry();
                return Err(Error::Timeout.into());
            }
            let waiters = match self.attach(waiters) {
                Ok(waiters) => waiters,
                Err(error) => return Err(error.into()),
            };
            if self.swap(
                old,
                State {
                    holders: holders.add_waiter(),
                    waiters,
                },
            ) {
                break waiters;
            }
        };
        let entry = self.adopt(registered);
        if let Some(stored) = self.spin(registered, Self::take_exclusive) {
            return self.taken(stored, Taker::SpinningExclusive);
        }
        loop {
            if let Err(error) = self.block(entry.event()) {
                return self.abandon(entry, error, |holders| holders.remove_waiter());
            }
            loop {
                match self.take_exclusive() {
                    Take::Taken(stored) => return self.taken(stored, Taker::Exclusive),
                    Take::Busy(State { holders, .. }) => {
                        // Pass the wake on to the upgrading thread.
                        if holders.is_upgrading() {
                            set_event(entry.event());
                        }
                        break;
                    }
                    Take::Lost(_) => {}
                }
            }
        }
    }

    /// Exclusive to shared; a recursive owner gives up one recursion level.
    fn downgrade(&mut self) -> Result<(), LockError> {
        if let Some(ownership) = self.ownership {
            if ownership.owner.load(Relaxed) != GetCurrentThreadId() {
                return Err(LockError::NotHeld);
            }
            if ownership.recursion.load(Relaxed) == 0 {
                ownership.owner.store(0, Relaxed);
            }
        }
        let (holders, waiters) = loop {
            let old = self.read();
            let mut holders = old.holders;
            if self
                .ownership
                .is_none_or(|ownership| ownership.recursion.load(Relaxed) == 0)
            {
                if !holders.is_exclusive() {
                    return Err(LockError::NotHeld);
                }
                holders = holders.without_exclusive();
            }
            let holders = holders.add_shared();
            let waiters = old.waiters.spin_as(self.wait.spin);
            if self.swap(old, State { holders, waiters }) {
                break (holders, waiters);
            }
        };
        if let Some(ownership) = self.ownership {
            let recursion = &ownership.recursion;
            if recursion.load(Relaxed) != 0 {
                recursion.store(recursion.load(Relaxed).wrapping_sub(1), Relaxed);
                return Ok(());
            }
        }
        if !holders.has_waiters() && waiters.shared() != 0 {
            // SAFETY: shared waiters attached an entry to the waiters word.
            let entry = unsafe { self.pool.entry_of(waiters) };
            release_semaphore(entry.semaphore(), waiters.shared());
        }
        Ok(())
    }

    fn take_upgrade(&self) -> Take {
        let old = self.read();
        let (holders, waiters) = (old.holders, old.waiters);
        if holders.has_holder() {
            return Take::Busy(old);
        }
        let holders = holders.with_exclusive().remove_waiter().without_upgrading();
        let waiters = State {
            holders,
            waiters: waiters.spin_as(self.wait.spin),
        }
        .idle_waiters();
        if self.swap(old, State { holders, waiters }) {
            Take::Taken(waiters)
        } else {
            Take::Lost(waiters)
        }
    }

    /// Shared to exclusive.
    fn upgrade(&mut self, precedence: Precedence) -> Result<(), LockError> {
        if self.owned_by_caller()
            && let Some(ownership) = self.ownership
        {
            loop {
                let old = self.read();
                if !old.holders.has_shared() {
                    return Err(Error::InvalidArgument.into());
                }
                let waiters = if self.wait.spin {
                    old.waiters
                } else {
                    old.waiters.without_spin()
                };
                if self.swap(
                    old,
                    State {
                        holders: old.holders.remove_shared(),
                        waiters,
                    },
                ) {
                    break;
                }
            }
            let recursion = &ownership.recursion;
            recursion.store(recursion.load(Relaxed).wrapping_add(1), Relaxed);
            return Ok(());
        }
        let registered = loop {
            let old = self.read();
            let (holders, waiters) = (old.holders, old.waiters);
            let error = if !holders.has_shared() {
                Some(LockError::Container(Error::InvalidArgument))
            } else if holders.is_upgrading() {
                Some(LockError::UpgradePending)
            } else if holders.has_waiters() && precedence == Precedence::Behind {
                Some(LockError::ExclusiveWaiting)
            } else {
                None
            };
            if let Some(error) = error {
                self.release_entry();
                return Err(error);
            }
            let remaining = holders.remove_shared();
            if !remaining.has_holder() {
                if self.swap(
                    old,
                    State {
                        holders: remaining.with_exclusive(),
                        waiters: waiters.spin_as(self.wait.spin),
                    },
                ) {
                    self.release_entry();
                    self.record_owner();
                    return Ok(());
                }
                continue;
            }
            if !self.may_wait(waiters) {
                self.release_entry();
                return Err(Error::Timeout.into());
            }
            let waiters = match self.attach(waiters) {
                Ok(waiters) => waiters,
                Err(error) => return Err(error.into()),
            };
            if self.swap(
                old,
                State {
                    holders: remaining.with_upgrading().add_waiter(),
                    waiters,
                },
            ) {
                break waiters;
            }
        };
        let entry = self.adopt(registered);
        if let Some(stored) = self.spin(registered, Self::take_upgrade) {
            return self.taken(stored, Taker::Exclusive);
        }
        loop {
            if let Err(error) = self.block(entry.event()) {
                return self.abandon(entry, error, |holders| {
                    holders.remove_waiter().without_upgrading().add_shared()
                });
            }
            loop {
                match self.take_upgrade() {
                    Take::Taken(stored) => return self.taken(stored, Taker::Exclusive),
                    Take::Busy(..) => break,
                    Take::Lost(_) => {}
                }
            }
        }
    }

    fn release_shared(&mut self) -> Result<(), LockError> {
        let (holders, waiters) = loop {
            let old = self.read();
            if !old.holders.has_shared() {
                return Err(LockError::NotHeld);
            }
            let holders = old.holders.remove_shared();
            if self.swap(
                old,
                State {
                    holders,
                    waiters: old.waiters,
                },
            ) {
                break (holders, old.waiters);
            }
        };
        // Waiters but no holder, tested on the word: the method form compiles
        // to a longer sequence here.
        if holders.0 & (Holders::EXCLUSIVE | Holders::SHARED) == 0
            && holders.0 & Holders::WAITERS != 0
        {
            // SAFETY: exclusive waiters attached an entry to the waiters word.
            set_event(unsafe { self.pool.entry_of(waiters) }.event());
        }
        Ok(())
    }

    fn release_exclusive(&mut self) -> Result<(), LockError> {
        if let Some(ownership) = self.ownership {
            if ownership.owner.load(Relaxed) != GetCurrentThreadId() {
                return Err(LockError::NotHeld);
            }
            let recursion = &ownership.recursion;
            let depth = recursion.load(Relaxed);
            if depth != 0 {
                recursion.store(depth.wrapping_sub(1), Relaxed);
                return Ok(());
            }
            ownership.owner.store(0, Relaxed);
        }
        let (holders, waiters) = loop {
            let old = self.read();
            if !old.holders.is_exclusive() {
                return Err(LockError::NotHeld);
            }
            let holders = old.holders.without_exclusive();
            if self.swap(
                old,
                State {
                    holders,
                    waiters: old.waiters,
                },
            ) {
                break (holders, old.waiters);
            }
        };
        if holders.has_waiters() {
            if !holders.has_shared() {
                // SAFETY: exclusive waiters attached an entry to the waiters
                // word.
                set_event(unsafe { self.pool.entry_of(waiters) }.event());
            }
        } else if waiters.shared() != 0 {
            // SAFETY: shared waiters attached an entry to the waiters word.
            let entry = unsafe { self.pool.entry_of(waiters) };
            release_semaphore(entry.semaphore(), waiters.shared());
        }
        Ok(())
    }
}

/// Lock record operations of export 340.
#[derive(Clone, Copy)]
enum Operation {
    Shared,
    Exclusive,
    Downgrade,
    Upgrade,
    UpgradeAhead,
}

/// Operation word of export 340: the operation, and a bit that fails the
/// operation rather than wait.
#[derive(Clone, Copy)]
struct OperationWord(u32);

impl OperationWord {
    const IMMEDIATE: u32 = 0x8;

    fn immediate(self) -> bool {
        self.0 & Self::IMMEDIATE != 0
    }

    fn operation(self) -> Option<Operation> {
        Some(match self.0 & !Self::IMMEDIATE {
            0 => Operation::Shared,
            1 => Operation::Exclusive,
            2 => Operation::Downgrade,
            3 => Operation::Upgrade,
            4 => Operation::UpgradeAhead,
            _ => return None,
        })
    }
}

/// The pool and record address of export 340 or 351: none for an invalid
/// pool, a null record or one that is not 4-byte aligned, the checks stock
/// makes. `ldarx` needs the 8-byte alignment that the export contract
/// requires of a lock record; stock faults on a record that is only 4-byte
/// aligned.
///
/// # Safety
///
/// `pool` is 0 or a pool of export 342 that stays valid for `'a`.
unsafe fn request_target<'a>(pool: u32, lock: u32) -> Option<(&'a Pool, NonZeroU32)> {
    /// Alignment bits stock checks.
    const CHECKED_ALIGNMENT_MASK: u32 = 3;
    // SAFETY: the caller guarantees the pool.
    let pool = unsafe { Pool::from_handle(pool) }?;
    let lock = NonZeroU32::new(lock).filter(|lock| lock.get() & CHECKED_ALIGNMENT_MASK == 0)?;
    Some((pool, lock))
}

extern "C" fn operate(pool: u32, operation: u32, lock: u32) -> Hresult {
    // SAFETY: export 340 contract: `pool` is 0 or a pool of export 342.
    let Some((pool, lock)) = (unsafe { request_target(pool, lock) }) else {
        return Hresult::INVALID_ARGUMENT;
    };
    let operation = OperationWord(operation);
    let Some(kind) = operation.operation() else {
        return Error::InvalidArgument.into();
    };
    // SAFETY: export 340 contract: `lock` is a lock record of the pool,
    // 8-byte aligned.
    let mut request = unsafe { Request::new(pool, lock) };
    if let Some(attributes) = request.pool.attributes() {
        let flags = attributes.flags;
        request.wait = Wait {
            context: attributes.wait_context,
            routine: attributes.wait_routine,
            spin: flags.contains(PoolFlags::SPIN),
            timeout: attributes.timeout,
            alertable: flags.contains(PoolFlags::ALERTABLE),
        };
        request.immediate = !flags.contains(PoolFlags::MAY_WAIT);
    }
    request.immediate |= operation.immediate();
    let outcome = match kind {
        Operation::Shared => request.shared(),
        Operation::Exclusive => request.exclusive(),
        Operation::Downgrade => request.downgrade(),
        Operation::Upgrade => request.upgrade(Precedence::Behind),
        Operation::UpgradeAhead => request.upgrade(Precedence::Ahead),
    };
    lock_result(outcome)
}
export!(340, operate);

/// A pool word that stock reports as E_FAIL when it reads -1.
fn count_result(value: Option<u32>, output_word: Option<OutputWord<'_>>) -> Hresult {
    let (Some(value), Some(output_word)) = (value, output_word) else {
        return Hresult::INVALID_ARGUMENT;
    };
    if value == u32::MAX {
        return Hresult::FAIL;
    }
    output_word.store(value);
    Hresult::SUCCESS
}

extern "C" fn memory(pool: u32, output_word: u32) -> Hresult {
    // SAFETY: export 341 contract: `pool` is 0 or a pool of export 342 and
    // `output_word` 0 or a writable word.
    let (pool, output_word) = unsafe { (Pool::from_handle(pool), OutputWord::new(output_word)) };
    count_result(pool.map(|pool| pool.memory.load(Relaxed)), output_word)
}
export!(341, memory);

/// `attributes` is optional; `output_word` receives the pool.
extern "C" fn create(attributes: u32, output_word: u32) -> Hresult {
    // SAFETY: export 342 contract: `output_word` is 0 or a writable word.
    let Some(output_word) = (unsafe { OutputWord::new(output_word) }) else {
        return Hresult::INVALID_ARGUMENT;
    };
    output_word.store(0);
    // SAFETY: export 342 contract: `attributes` is 0 or pool attributes.
    let created = unsafe { PoolAttributes::read(attributes) }
        .and_then(|attributes| Pool::create(attributes.as_ref()));
    match created {
        Ok(pool) => {
            output_word.store(ptr::from_ref(pool).expose_provenance() as u32);
            Hresult::SUCCESS
        }
        Err(error) => error.into(),
    }
}
export!(342, create);

/// Take a free lock record, growing the free list by a block when empty.
extern "C" fn allocate_lock(pool: u32, output_word: u32) -> Hresult {
    // SAFETY: export 343 contract: `pool` is 0 or a pool of export 342 and
    // `output_word` 0 or a writable word.
    let (pool, output_word) = unsafe { (Pool::from_handle(pool), OutputWord::new(output_word)) };
    let (Some(pool), Some(output_word)) = (pool, output_word) else {
        return Hresult::INVALID_ARGUMENT;
    };
    let Some(record) = pool
        .pop_record()
        .or_else(|| pool.add_records(pool.per_block.load(Relaxed), FirstRecord::Keep))
    else {
        output_word.store(0);
        return Error::NotEnoughMemory.into();
    };
    // SAFETY: a record of this pool's blocks or one returned through export
    // 345, an `OwnedLockRecord` in owned and recursive pools by its
    // contract.
    unsafe {
        record.get::<LockRecord, _>(pool).state.store(Tagged(0));
        if pool.kind() != Kind::Plain {
            let ownership = &record.get::<OwnedLockRecord, _>(pool).ownership;
            ownership.recursion.store(0, Relaxed);
            ownership.owner.store(0, Relaxed);
        }
    }
    lwsync();
    output_word.store(record.raw());
    Hresult::SUCCESS
}
export!(343, allocate_lock);

/// 1 after destroying, 0 for an invalid pool.
extern "C" fn destroy(pool: u32) -> u32 {
    // SAFETY: export 344 contract: `pool` is 0 or a pool of export 342 on
    // which no other operation runs.
    u32::from(unsafe { Pool::destroy(pool) })
}
export!(344, destroy);

/// Return an idle lock record from 343 to the free list.
extern "C" fn free_lock(pool: u32, lock: u32) -> Hresult {
    // SAFETY: export 345 contract: `pool` is 0 or a pool of export 342.
    let Some(pool) = (unsafe { Pool::from_handle(pool) }) else {
        return Hresult::INVALID_ARGUMENT;
    };
    // Stock also requires records of owned and recursive pools to be
    // aligned to their size.
    let alignment_mask = pool.kind().record_size() - 1;
    let Some(record) = NodeAddress::new(lock).filter(|_| lock & LockRecord::ALIGNMENT_MASK == 0)
    else {
        return Hresult::INVALID_ARGUMENT;
    };
    // SAFETY: export 345 contract: `lock` is a lock record of the pool.
    let state = &unsafe { record.get::<LockRecord, _>(pool) }.state;
    let waiters = Waiters(state.low.load(Relaxed));
    let holders = Holders(state.high.load(Relaxed));
    if waiters.without_spin().0 | holders.0 != 0 || lock & alignment_mask != 0 {
        return Hresult::INVALID_ARGUMENT;
    }
    // SAFETY: as above; an idle record is on no list.
    unsafe { pool.records.push(record, NodeWord::Word0) };
    Hresult::SUCCESS
}
export!(345, free_lock);

/// Create `count` wait entries ahead of use; E_FAIL when fewer were made.
extern "C" fn reserve_entries(pool: u32, count: u32) -> Hresult {
    // SAFETY: export 346 contract: `pool` is 0 or a pool of export 342.
    let Some(pool) = (unsafe { Pool::from_handle(pool) }).filter(|_| count as i32 >= 0) else {
        return Hresult::INVALID_ARGUMENT;
    };
    let mut created = 0;
    while created < count {
        let Some(entry) = pool.create_entry() else {
            break;
        };
        pool.free_entry(entry);
        created += 1;
    }
    if created == count {
        Hresult::SUCCESS
    } else {
        Hresult::FAIL
    }
}
export!(346, reserve_entries);

/// Add `count` free lock records; a plain pool adds one block whatever the
/// count. E_FAIL when the records were not added.
extern "C" fn reserve_locks(pool: u32, count: u32) -> Hresult {
    // SAFETY: export 347 contract: `pool` is 0 or a pool of export 342.
    let Some(pool) = (unsafe { Pool::from_handle(pool) }) else {
        return Hresult::INVALID_ARGUMENT;
    };
    let added = if pool.kind() == Kind::Plain {
        pool.add_records(pool.per_block.load(Relaxed), FirstRecord::Free)
            .map_or(0, |_| count)
    } else if count as i32 > 0 && count < Pool::MAX_RESERVED_RECORDS {
        pool.add_records(count, FirstRecord::Free)
            .map_or(0, |_| count)
    } else {
        0
    };
    if added == count {
        Hresult::SUCCESS
    } else {
        Hresult::FAIL
    }
}
export!(347, reserve_locks);

/// Prepare caller memory as a lock record.
extern "C" fn initialize_lock(pool: u32, lock: u32) -> Hresult {
    // SAFETY: export 348 contract: `pool` is 0 or a pool of export 342.
    let pool = unsafe { Pool::from_handle(pool) };
    let (Some(pool), Some(record)) = (
        pool,
        NodeAddress::new(lock).filter(|_| lock & LockRecord::ALIGNMENT_MASK == 0),
    ) else {
        return Hresult::INVALID_ARGUMENT;
    };
    // SAFETY: export 348 contract: `lock` is caller memory for a lock record
    // of the pool, an `OwnedLockRecord` in owned and recursive pools.
    unsafe {
        let state = &record.get::<LockRecord, _>(pool).state;
        state.store(Tagged(0));
        let waiters = Waiters(state.low.load(Relaxed));
        state.low.store(waiters.with_caller_record().0, Relaxed);
        if pool.kind() != Kind::Plain {
            let ownership = &record.get::<OwnedLockRecord, _>(pool).ownership;
            ownership.owner.store(0, Relaxed);
            ownership.recursion.store(0, Relaxed);
        }
    }
    lwsync();
    Hresult::SUCCESS
}
export!(348, initialize_lock);

/// Wait entries created.
extern "C" fn entry_count(pool: u32, output_word: u32) -> Hresult {
    // SAFETY: export 349 contract: as for export 341.
    let (pool, output_word) = unsafe { (Pool::from_handle(pool), OutputWord::new(output_word)) };
    let value = pool.map(|pool| (pool.table.low.load(Relaxed) & Pool::COUNT_MASK).wrapping_sub(1));
    count_result(value, output_word)
}
export!(349, entry_count);

extern "C" fn record_total(pool: u32, output_word: u32) -> Hresult {
    // SAFETY: export 350 contract: as for export 341.
    let (pool, output_word) = unsafe { (Pool::from_handle(pool), OutputWord::new(output_word)) };
    count_result(pool.map(|pool| pool.total.load(Relaxed)), output_word)
}
export!(350, record_total);

/// Release a lock record held shared (`mode` 0) or exclusive (1).
extern "C" fn release(pool: u32, mode: u32, lock: u32) -> Hresult {
    // SAFETY: export 351 contract: `pool` is 0 or a pool of export 342.
    let Some((pool, lock)) = (unsafe { request_target(pool, lock) }) else {
        return Hresult::INVALID_ARGUMENT;
    };
    let release = match mode {
        0 => Request::release_shared,
        1 => Request::release_exclusive,
        _ => return LockError::BadMode.into(),
    };
    // SAFETY: export 351 contract: `lock` is a lock record of the pool.
    let mut request = unsafe { Request::new(pool, lock) };
    lock_result(release(&mut request))
}
export!(351, release);
