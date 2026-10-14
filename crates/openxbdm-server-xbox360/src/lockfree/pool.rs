//! Lock pool 'LfPl' (exports 340-351): reader/writer locks whose waiters
//! block on shared wait entries, and a free list of lock records.
//!
//! Pool (0x100 bytes, then the allocator record and the attributes):
//! +0x00 free wait entries (tagged, linked through entry +0xc), +0x08
//! signature, +0x0c lock kind (-1 plain, 0 owned, 1 recursive), +0x10
//! entry table with +0x14 its count (one quadword; slot 0 stays empty),
//! +0x18 free lock records (tagged), +0x20 record blocks (tagged), +0x28
//! bytes allocated, +0x2c record total, +0x30 records per block, +0x34
//! entry tables made by growth (15 words, by log2 of the count at growth),
//! +0x70 initial entry table (32 slots), +0xf0 allocation base, +0xf4
//! allocator record, +0xf8 attributes.
//!
//! Attributes (0x18 bytes): +0 flags (0x1 recursive, 0x2 owned, 0x4
//! operations may wait, 0x10 spin, 0x20 alertable), +4 records per block,
//! +8 wait context, +0xc timeout, +0x10 wait routine, +0x14 size. The pool
//! keeps them only when a flag of 0x34 is set.
//!
//! Wait entry (0x10 bytes): +0 semaphore handle (shared waiters), +4 auto
//! reset event handle (exclusive and upgrading waiters), +8 table index,
//! +0xc free list link.
//!
//! Lock record (8 bytes, 16 for owned and recursive pools): +0 holders
//! word, +4 waiters word, +8 owner thread id, +0xc recursion count.
//! Holders word: 0x7fff shared holders, 0x8000 upgrade pending, 0x10000
//! exclusive holder, upper bits exclusive and upgrading waiters in units of
//! 0x20000. Waiters word: 0x7fff shared waiters, 0x8000 waiters spin before
//! blocking, 0x10000 caller-initialized record, upper bits the wait entry
//! index.

use core::num::NonZeroU32;

use openxbdm_core::status::Hresult;

use super::Allocator;
use super::Backoff;
use super::CREATE_FAILED;
use super::SPIN_ATTEMPTS;
use super::SUCCESS;
use super::Status;
use super::Tagged;
use super::Timeout;
use super::Wait;
use super::WaitObject;
use super::close_handle;
use super::compare_exchange;
use super::copy;
use super::create_semaphore;
use super::default_record;
use super::exchange;
use super::fetch_add;
use super::load;
use super::load_tagged;
use super::lwsync;
use super::pop;
use super::push;
use super::release_semaphore;
use super::set_event;
use super::store;
use super::store_quad;
use super::swap_tagged;
use super::win32_result;
use super::zero;
use crate::exports::export;
use crate::kernel::CreateEventA;
use crate::kernel::GetCurrentThreadId;

const LFPL: u32 = u32::from_be_bytes(*b"LfPl");
const ENTRIES: usize = 0x00;
const SIGNATURE: usize = 0x08;
const KIND: usize = 0x0c;
const TABLE: usize = 0x10;
const TABLE_COUNT: usize = 0x14;
const RECORDS: usize = 0x18;
const BLOCKS: usize = 0x20;
const MEMORY: usize = 0x28;
const TOTAL: usize = 0x2c;
const GROW: usize = 0x30;
const GROWN_TABLES: usize = 0x34;
const GROWN_TABLE_COUNT: usize = 15;
/// Entry count bits of the table count word.
const COUNT_MASK: u32 = 0x7fff_ffff;
const INITIAL_TABLE: usize = 0x70;
const INITIAL_CAPACITY: u32 = 32;
const BASE: usize = 0xf0;
const ALLOCATOR: usize = 0xf4;
const ATTRIBUTES: usize = 0xf8;
/// Bytes of the pool before the allocator record.
const OBJECT_SIZE: u32 = 0x100;
const ATTRIBUTES_SIZE: u32 = 0x18;
/// Attribute flags.
const RECURSIVE: u32 = 0x1;
const OWNED: u32 = 0x2;
const MAY_WAIT: u32 = 0x4;
const SPIN_FLAG: u32 = 0x10;
const ALERTABLE: u32 = 0x20;
const KEPT_FLAGS: u32 = 0x34;
/// Entry count that marks the table full.
const ENTRY_LIMIT: u32 = 0x8000;
/// Fields of a wait entry.
const ENTRY_SIZE: u32 = 0x10;
const ENTRY_EVENT: usize = 4;
const ENTRY_INDEX: usize = 8;
const ENTRY_LINK: usize = 0xc;
/// Fields of a lock record.
const OWNER: usize = 8;
const RECURSION: usize = 0xc;

/// Holders and waiters word fields.
const SHARED: u32 = 0x7fff;
const UPGRADING: u32 = 0x8000;
const EXCLUSIVE: u32 = 0x1_0000;
const WAITER: u32 = 0x2_0000;
const WAITERS: u32 = 0xfffe_0000;
const HELD: u32 = 0xffff_0000;
const SPIN: u32 = 0x8000;
const CALLER_RECORD: u32 = 0x1_0000;
const INDEX_SHIFT: u32 = 17;
const INDEX: u32 = 0xfffe_0000;

/// Internal results that [`result`] maps to facility 0x31 HRESULTs.
const NOT_HELD: Status = Status(0xe000_0001);
const UPGRADE_PENDING: Status = Status(0xe000_0002);
const EXCLUSIVE_WAITING: Status = Status(0xe000_0003);
const NOT_RECURSIVE: Status = Status(0xe000_0004);
/// 351 with a mode other than shared or exclusive.
const BAD_MODE: Hresult = Hresult(0x8031_0003);
const NOT_HELD_RESULT: Hresult = Hresult(0x8031_0004);
const UPGRADE_PENDING_RESULT: Hresult = Hresult(0x8031_0005);
const EXCLUSIVE_WAITING_RESULT: Hresult = Hresult(0x8031_0006);
const NOT_RECURSIVE_RESULT: Hresult = Hresult(0x8031_0007);

fn result(status: Status) -> Hresult {
    match status {
        Status::SUCCESS => SUCCESS,
        NOT_HELD => NOT_HELD_RESULT,
        UPGRADE_PENDING => UPGRADE_PENDING_RESULT,
        EXCLUSIVE_WAITING => EXCLUSIVE_WAITING_RESULT,
        NOT_RECURSIVE => NOT_RECURSIVE_RESULT,
        Status(code) => win32_result(code),
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
    fn from_flags(flags: u32) -> Self {
        if flags & RECURSIVE != 0 {
            Self::Recursive
        } else if flags & OWNED != 0 {
            Self::Owned
        } else {
            Self::Plain
        }
    }

    /// Pool field value: -1, 0 or 1.
    fn encode(self) -> u32 {
        match self {
            Self::Plain => -1i32 as u32,
            Self::Owned => 0,
            Self::Recursive => 1,
        }
    }
}

/// Holders and waiters words of a lock record, read in one access.
#[derive(Clone, Copy)]
struct State {
    holders: u32,
    waiters: u32,
}

impl State {
    fn word(self) -> Tagged {
        Tagged::new(self.holders, self.waiters)
    }

    /// The waiters word less the entry index once nobody waits.
    fn idle_waiters(self) -> u32 {
        if (self.holders & WAITERS) | (self.waiters & SHARED) == 0 {
            self.waiters & !INDEX
        } else {
            self.waiters
        }
    }
}

/// A shared take of the waiters word: unless spinning is asked, waiters
/// stop spinning; a spinning acquirer turns spinning on only for an unheld
/// lock.
fn shared_spin(old: State, spin: bool) -> u32 {
    if !spin {
        old.waiters & !SPIN
    } else if old.holders & SHARED == 0 {
        old.waiters | SPIN
    } else {
        old.waiters
    }
}

/// An exclusive take sets the spin bit from the acquirer's flag.
fn exclusive_spin(waiters: u32, spin: bool) -> u32 {
    (waiters & !SPIN) | if spin { SPIN } else { 0 }
}

#[derive(Clone, Copy)]
struct Entry(u32);

impl Entry {
    fn semaphore(self) -> u32 {
        load(self.0 as usize)
    }

    fn event(self) -> u32 {
        load(self.0 as usize + ENTRY_EVENT)
    }

    fn index(self) -> u32 {
        load(self.0 as usize + ENTRY_INDEX)
    }
}

#[derive(Clone, Copy)]
struct Pool(usize);

impl Pool {
    fn validate(address: u32) -> Option<Self> {
        (address != 0 && load(address as usize + SIGNATURE) == LFPL)
            .then_some(Self(address as usize))
    }

    fn kind(self) -> Kind {
        match load(self.0 + KIND) as i32 {
            kind if kind < 0 => Kind::Plain,
            0 => Kind::Owned,
            _ => Kind::Recursive,
        }
    }

    fn allocator(self) -> Allocator {
        Allocator(load(self.0 + ALLOCATOR) as usize)
    }

    /// Entry at table slot `index`.
    fn entry(self, index: u32) -> Entry {
        Entry(load(load(self.0 + TABLE) as usize + 4 * index as usize))
    }

    /// Entry a waiters word names.
    fn entry_of(self, waiters: u32) -> Entry {
        self.entry(waiters >> INDEX_SHIFT)
    }

    fn free_entry(self, entry: Entry) {
        push(self.0 + ENTRIES, entry.0, ENTRY_LINK);
    }

    fn take_entry(self) -> Option<Entry> {
        pop(self.0 + ENTRIES, ENTRY_LINK)
            .map(Entry)
            .or_else(|| self.create_entry())
    }

    /// Allocate a wait entry with its semaphore and event and give it a
    /// table slot; any failure marks the table full.
    fn create_entry(self) -> Option<Entry> {
        if load(self.0 + TABLE_COUNT) & COUNT_MASK == ENTRY_LIMIT {
            return None;
        }
        let allocator = self.allocator();
        let entry = allocator.allocate(ENTRY_SIZE, self.0 + MEMORY);
        if entry != 0 {
            let semaphore = create_semaphore();
            store(entry as usize, semaphore);
            if semaphore != 0 {
                let event = CreateEventA(0, 0, 0, core::ptr::null());
                store(entry as usize + ENTRY_EVENT, event);
                if event != 0 {
                    if self.install(entry) {
                        return Some(Entry(entry));
                    }
                    close_handle(event);
                }
                close_handle(semaphore);
            }
            allocator.free(entry);
        }
        loop {
            let current = load_tagged(self.0 + TABLE);
            if current.low() & COUNT_MASK == ENTRY_LIMIT
                || swap_tagged(
                    self.0 + TABLE,
                    current,
                    Tagged::new(current.address(), ENTRY_LIMIT),
                )
            {
                return None;
            }
        }
    }

    /// Store `entry` at the next table slot, doubling the table when a
    /// power-of-two count of at least 32 fills it.
    fn install(self, entry: u32) -> bool {
        let list = self.0 + TABLE;
        loop {
            let current = load_tagged(list);
            let count = current.low() & COUNT_MASK;
            if count == ENTRY_LIMIT {
                return false;
            }
            let table = current.address();
            if count >= INITIAL_CAPACITY && count.is_power_of_two() {
                if count >= 0x0fff_ffff {
                    return false;
                }
                let allocator = self.allocator();
                let grown = allocator.allocate(count * 8, self.0 + MEMORY);
                if grown == 0 {
                    return false;
                }
                let slot = grown as usize + 4 * count as usize;
                copy(grown as usize, table as usize, 4 * count as usize);
                store(slot, entry);
                zero(slot + 4, 4 * (count as usize - 1));
                if swap_tagged(list, current, Tagged::new(grown, count + 1)) {
                    store(entry as usize + ENTRY_INDEX, count);
                    exchange(
                        self.0 + GROWN_TABLES + 4 * count.trailing_zeros() as usize,
                        grown,
                    );
                    return true;
                }
                allocator.free(grown);
                continue;
            }
            let claimed = compare_exchange(table as usize + 4 * count as usize, 0, entry) == 0;
            if claimed {
                store(entry as usize + ENTRY_INDEX, count);
            }
            swap_tagged(list, current, Tagged::new(table, count + 1));
            if claimed {
                return true;
            }
        }
    }

    /// Slots of the current entry table: the initial table or the newest
    /// grown one.
    fn capacity(self, table: u32) -> Option<u32> {
        if table as usize == self.0 + INITIAL_TABLE {
            return Some(INITIAL_CAPACITY);
        }
        (0..GROWN_TABLE_COUNT)
            .find(|&order| load(self.0 + GROWN_TABLES + 4 * order) == table)
            .map(|order| 2 << order)
    }

    fn record_size(self) -> u32 {
        if self.kind() == Kind::Plain { 8 } else { 16 }
    }

    /// Allocate `count` lock records and put them on the free list, or all
    /// but the first, which is returned, with [`FirstRecord::Keep`].
    fn add_records(self, count: u32, first: FirstRecord) -> Option<u32> {
        let size = count.wrapping_mul(self.record_size());
        let block = self
            .allocator()
            .allocate_block(self.0 + BLOCKS, size, self.0 + MEMORY)?;
        fetch_add(self.0 + TOTAL, count);
        let mut record = block.wrapping_add(size);
        for _ in u32::from(first == FirstRecord::Keep)..count {
            record = record.wrapping_sub(self.record_size());
            push(self.0 + RECORDS, record, 0);
        }
        Some(block)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FirstRecord {
    Keep,
    Free,
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

/// One operation on a lock record.
struct Request {
    pool: Pool,
    lock: usize,
    wait: Wait,
    /// Fail rather than wait.
    immediate: bool,
    /// Wait entry this operation holds.
    entry: Option<Entry>,
    backoff: Backoff,
    /// Calling thread, read when the pool records owners.
    owner: Option<u32>,
}

/// One attempt to take a lock after waiting.
enum Take {
    /// Taken; the waiters word stored.
    Taken(u32),
    /// Still held.
    Busy(State),
    /// Another thread changed the record; the waiters word computed.
    Lost(u32),
}

impl Request {
    fn read(&self) -> State {
        let word = load_tagged(self.lock);
        State {
            holders: word.address(),
            waiters: word.low(),
        }
    }

    fn swap(&self, old: State, new: State) -> bool {
        swap_tagged(self.lock, old.word(), new.word())
    }

    fn owner_field(&self) -> usize {
        self.lock + OWNER
    }

    fn recursion_field(&self) -> usize {
        self.lock + RECURSION
    }

    /// Whether the caller owns the record; the thread id is kept to record
    /// as owner later. Plain records have no owner.
    fn owned_by_caller(&mut self) -> bool {
        if self.pool.kind() == Kind::Plain {
            return false;
        }
        let thread = GetCurrentThreadId();
        self.owner = Some(thread);
        load(self.owner_field()) == thread
    }

    fn record_owner(&self) {
        if let Some(thread) = self.owner {
            store(self.owner_field(), thread);
        }
    }

    fn release_entry(&mut self) {
        if let Some(entry) = self.entry.take() {
            self.pool.free_entry(entry);
        }
    }

    fn may_wait(&self, waiters: u32) -> bool {
        !self.immediate && (waiters & SPIN != 0 || self.wait.timeout.0 != 0)
    }

    /// Give the waiters word an entry index, taking an entry when it has
    /// none.
    fn attach(&mut self, waiters: u32) -> Result<u32, Status> {
        if waiters & INDEX != 0 {
            return Ok(waiters);
        }
        let entry = match self.entry {
            Some(entry) => entry,
            None => self.pool.take_entry().ok_or(Status::NOT_ENOUGH_MEMORY)?,
        };
        self.entry = Some(entry);
        Ok(waiters.wrapping_add(entry.index() << INDEX_SHIFT))
    }

    /// Use the entry the stored waiters word names.
    fn adopt(&mut self, waiters: u32) -> Entry {
        let index = waiters >> INDEX_SHIFT;
        match self.entry {
            Some(entry) if entry.index() == index => entry,
            _ => {
                self.release_entry();
                let entry = self.pool.entry(index);
                self.entry = Some(entry);
                entry
            }
        }
    }

    /// Spin up to [`SPIN_ATTEMPTS`] times while the record asks waiters to
    /// spin.
    fn spin(&mut self, waiters: u32, mut take: impl FnMut(&Self) -> Take) -> Option<u32> {
        if waiters & SPIN == 0 {
            return None;
        }
        for _ in 0..SPIN_ATTEMPTS {
            self.backoff.pause();
            match take(self) {
                Take::Taken(stored) => return Some(stored),
                Take::Busy(State { waiters, .. }) | Take::Lost(waiters) => {
                    if waiters & SPIN == 0 {
                        break;
                    }
                }
            }
        }
        None
    }

    /// Finish a take after waiting: the entry returns to the free list once
    /// the record names none.
    fn taken(&mut self, stored: u32, taker: Taker) -> Status {
        if stored & INDEX == 0 {
            self.release_entry();
        }
        if taker != Taker::Shared {
            self.record_owner();
        }
        if taker == Taker::SpinningExclusive {
            lwsync();
        }
        Status::SUCCESS
    }

    fn block(&self, handle: u32) -> Status {
        self.wait.block(WaitObject::handle(handle))
    }

    fn take_shared(&self) -> Take {
        let old = self.read();
        if old.holders & HELD != 0 {
            return Take::Busy(old);
        }
        let holders = old.holders.wrapping_add(1);
        let waiters = State {
            holders,
            waiters: shared_spin(old, self.wait.spin).wrapping_sub(1),
        }
        .idle_waiters();
        if self.swap(old, State { holders, waiters }) {
            Take::Taken(waiters)
        } else {
            Take::Lost(waiters)
        }
    }

    fn shared(&mut self) -> Status {
        if self.owned_by_caller() {
            if self.pool.kind() == Kind::Owned {
                return NOT_RECURSIVE;
            }
            loop {
                let old = self.read();
                let waiters = shared_spin(old, self.wait.spin);
                if self.swap(
                    old,
                    State {
                        holders: old.holders.wrapping_add(1),
                        waiters,
                    },
                ) {
                    return Status::SUCCESS;
                }
            }
        }
        let registered = loop {
            let old = self.read();
            let (holders, waiters) = (old.holders, old.waiters);
            if holders & HELD == 0 {
                if self.swap(
                    old,
                    State {
                        holders: holders.wrapping_add(1),
                        waiters: shared_spin(old, self.wait.spin),
                    },
                ) {
                    self.release_entry();
                    return Status::SUCCESS;
                }
                continue;
            }
            if !self.may_wait(waiters) {
                self.release_entry();
                return Status::TIMEOUT;
            }
            let waiters = match self.attach(waiters) {
                Ok(waiters) => waiters.wrapping_add(1),
                Err(status) => return status,
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
            let status = self.block(entry.semaphore());
            if status != Status::SUCCESS {
                let stored = loop {
                    let old = self.read();
                    let waiters = State {
                        holders: old.holders,
                        waiters: old.waiters.wrapping_sub(1),
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
                if stored & INDEX == 0 {
                    self.release_entry();
                }
                return status;
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
        if holders & (EXCLUSIVE | UPGRADING | SHARED) != 0 {
            return Take::Busy(old);
        }
        let holders = (holders | EXCLUSIVE).wrapping_sub(WAITER);
        let waiters = State {
            holders,
            waiters: exclusive_spin(waiters, self.wait.spin),
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
    fn abandon(&mut self, entry: Entry, status: Status, holders: impl Fn(u32) -> u32) -> Status {
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
        if waiters & INDEX == 0 {
            self.release_entry();
        }
        if holders & HELD == 0 && waiters & SHARED != 0 {
            release_semaphore(entry.semaphore(), waiters & SHARED);
        }
        status
    }

    fn exclusive(&mut self) -> Status {
        if self.owned_by_caller() {
            if self.pool.kind() == Kind::Owned {
                return NOT_RECURSIVE;
            }
            let recursion = self.recursion_field();
            store(recursion, load(recursion).wrapping_add(1));
            // Stock passes the compare and exchange values of this update
            // swapped and spins until another thread clears the bit; the
            // bit is cleared here.
            if !self.wait.spin && load(self.lock + 4) & SPIN != 0 {
                loop {
                    let old = self.read();
                    if self.swap(
                        old,
                        State {
                            holders: old.holders,
                            waiters: old.waiters & !SPIN,
                        },
                    ) {
                        break;
                    }
                }
            }
            lwsync();
            return Status::SUCCESS;
        }
        let registered = loop {
            let old = self.read();
            let (holders, waiters) = (old.holders, old.waiters);
            if holders == 0
                || (waiters & SPIN != 0 && holders & (EXCLUSIVE | UPGRADING | SHARED) == 0)
            {
                if self.swap(
                    old,
                    State {
                        holders: holders | EXCLUSIVE,
                        waiters: exclusive_spin(waiters, self.wait.spin),
                    },
                ) {
                    self.release_entry();
                    self.record_owner();
                    return Status::SUCCESS;
                }
                continue;
            }
            if !self.may_wait(waiters) {
                self.release_entry();
                return Status::TIMEOUT;
            }
            let waiters = match self.attach(waiters) {
                Ok(waiters) => waiters,
                Err(status) => return status,
            };
            if self.swap(
                old,
                State {
                    holders: holders.wrapping_add(WAITER),
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
            let status = self.block(entry.event());
            if status != Status::SUCCESS {
                return self.abandon(entry, status, |holders| holders.wrapping_sub(WAITER));
            }
            loop {
                match self.take_exclusive() {
                    Take::Taken(stored) => return self.taken(stored, Taker::Exclusive),
                    Take::Busy(State { holders, .. }) => {
                        // Pass the wake on to the upgrading thread.
                        if holders & UPGRADING != 0 {
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
    fn downgrade(&mut self) -> Status {
        let kind = self.pool.kind();
        let recursion = self.recursion_field();
        if kind != Kind::Plain {
            if load(self.owner_field()) != GetCurrentThreadId() {
                return NOT_HELD;
            }
            if load(recursion) == 0 {
                store(self.owner_field(), 0);
            }
        }
        let (holders, waiters) = loop {
            let old = self.read();
            let mut holders = old.holders;
            if kind == Kind::Plain || load(recursion) == 0 {
                if holders & EXCLUSIVE == 0 {
                    return NOT_HELD;
                }
                holders &= !EXCLUSIVE;
            }
            let holders = holders.wrapping_add(1);
            let waiters = exclusive_spin(old.waiters, self.wait.spin);
            if self.swap(old, State { holders, waiters }) {
                break (holders, waiters);
            }
        };
        if kind != Kind::Plain && load(recursion) != 0 {
            store(recursion, load(recursion).wrapping_sub(1));
            return Status::SUCCESS;
        }
        if holders & WAITERS == 0 && waiters & SHARED != 0 {
            release_semaphore(self.pool.entry_of(waiters).semaphore(), waiters & SHARED);
        }
        Status::SUCCESS
    }

    fn take_upgrade(&self) -> Take {
        let old = self.read();
        let (holders, waiters) = (old.holders, old.waiters);
        if holders & (EXCLUSIVE | SHARED) != 0 {
            return Take::Busy(old);
        }
        let holders = (holders | EXCLUSIVE).wrapping_sub(WAITER) & !UPGRADING;
        let waiters = State {
            holders,
            waiters: exclusive_spin(waiters, self.wait.spin),
        }
        .idle_waiters();
        if self.swap(old, State { holders, waiters }) {
            Take::Taken(waiters)
        } else {
            Take::Lost(waiters)
        }
    }

    /// Shared to exclusive.
    fn upgrade(&mut self, precedence: Precedence) -> Status {
        if self.owned_by_caller() {
            loop {
                let old = self.read();
                if old.holders & SHARED == 0 {
                    return Status::INVALID_PARAMETER;
                }
                let waiters = if self.wait.spin {
                    old.waiters
                } else {
                    old.waiters & !SPIN
                };
                if self.swap(
                    old,
                    State {
                        holders: old.holders.wrapping_sub(1),
                        waiters,
                    },
                ) {
                    break;
                }
            }
            let recursion = self.recursion_field();
            store(recursion, load(recursion).wrapping_add(1));
            return Status::SUCCESS;
        }
        let registered = loop {
            let old = self.read();
            let (holders, waiters) = (old.holders, old.waiters);
            let failure = if holders & SHARED == 0 {
                Some(Status::INVALID_PARAMETER)
            } else if holders & UPGRADING != 0 {
                Some(UPGRADE_PENDING)
            } else if holders & WAITERS != 0 && precedence == Precedence::Behind {
                Some(EXCLUSIVE_WAITING)
            } else {
                None
            };
            if let Some(status) = failure {
                self.release_entry();
                return status;
            }
            let remaining = holders.wrapping_sub(1);
            if remaining & (EXCLUSIVE | SHARED) == 0 {
                if self.swap(
                    old,
                    State {
                        holders: remaining | EXCLUSIVE,
                        waiters: exclusive_spin(waiters, self.wait.spin),
                    },
                ) {
                    self.release_entry();
                    self.record_owner();
                    return Status::SUCCESS;
                }
                continue;
            }
            if !self.may_wait(waiters) {
                self.release_entry();
                return Status::TIMEOUT;
            }
            let waiters = match self.attach(waiters) {
                Ok(waiters) => waiters,
                Err(status) => return status,
            };
            if self.swap(
                old,
                State {
                    holders: (remaining | UPGRADING).wrapping_add(WAITER),
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
            let status = self.block(entry.event());
            if status != Status::SUCCESS {
                return self.abandon(entry, status, |holders| {
                    (holders.wrapping_sub(WAITER) & !UPGRADING).wrapping_add(1)
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

    fn release_shared(&mut self) -> Status {
        let (holders, waiters) = loop {
            let old = self.read();
            if old.holders & SHARED == 0 {
                return NOT_HELD;
            }
            let holders = old.holders.wrapping_sub(1);
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
        if holders & (EXCLUSIVE | SHARED) == 0 && holders & WAITERS != 0 {
            set_event(self.pool.entry_of(waiters).event());
        }
        Status::SUCCESS
    }

    fn release_exclusive(&mut self) -> Status {
        if self.pool.kind() != Kind::Plain {
            if load(self.owner_field()) != GetCurrentThreadId() {
                return NOT_HELD;
            }
            let recursion = self.recursion_field();
            let depth = load(recursion);
            if depth != 0 {
                store(recursion, depth.wrapping_sub(1));
                return Status::SUCCESS;
            }
            store(self.owner_field(), 0);
        }
        let (holders, waiters) = loop {
            let old = self.read();
            if old.holders & EXCLUSIVE == 0 {
                return NOT_HELD;
            }
            let holders = old.holders & !EXCLUSIVE;
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
        if holders & WAITERS != 0 {
            if holders & SHARED == 0 {
                set_event(self.pool.entry_of(waiters).event());
            }
        } else if waiters & SHARED != 0 {
            release_semaphore(self.pool.entry_of(waiters).semaphore(), waiters & SHARED);
        }
        Status::SUCCESS
    }
}

/// Lock record operations of export 340; bit 0x8 fails rather than waits.
#[derive(Clone, Copy)]
enum Operation {
    Shared,
    Exclusive,
    Downgrade,
    Upgrade,
    UpgradeAhead,
}

const IMMEDIATE: u32 = 0x8;

impl Operation {
    fn decode(operation: u32) -> Option<Self> {
        Some(match operation & !IMMEDIATE {
            0 => Self::Shared,
            1 => Self::Exclusive,
            2 => Self::Downgrade,
            3 => Self::Upgrade,
            4 => Self::UpgradeAhead,
            _ => return None,
        })
    }
}

/// A validated pool and a 4-byte aligned lock record.
fn request(pool: u32, lock: u32) -> Option<Request> {
    let pool = Pool::validate(pool)?;
    (lock != 0 && lock & 3 == 0).then_some(Request {
        pool,
        lock: lock as usize,
        wait: Wait::NONE,
        immediate: true,
        entry: None,
        backoff: Backoff(0),
        owner: None,
    })
}

extern "C" fn operate(pool: u32, operation: u32, lock: u32) -> u32 {
    let Some(mut request) = request(pool, lock) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let attributes = load(request.pool.0 + ATTRIBUTES) as usize;
    if attributes != 0 {
        let flags = load(attributes);
        request.wait = Wait {
            context: load(attributes + 8),
            routine: NonZeroU32::new(load(attributes + 0x10)),
            spin: flags & SPIN_FLAG != 0,
            timeout: Timeout(load(attributes + 0xc)),
            alertable: flags & ALERTABLE != 0,
        };
        request.immediate = flags & MAY_WAIT == 0;
    }
    request.immediate |= operation & IMMEDIATE != 0;
    let status = match Operation::decode(operation) {
        Some(Operation::Shared) => request.shared(),
        Some(Operation::Exclusive) => request.exclusive(),
        Some(Operation::Downgrade) => request.downgrade(),
        Some(Operation::Upgrade) => request.upgrade(Precedence::Behind),
        Some(Operation::UpgradeAhead) => request.upgrade(Precedence::Ahead),
        None => Status::INVALID_PARAMETER,
    };
    result(status).0
}
export!(340, operate);

/// A pool word that stock reports as E_FAIL when it reads -1.
fn read_count(pool: u32, output: u32, value: impl FnOnce(Pool) -> u32) -> u32 {
    let Some(pool) = Pool::validate(pool).filter(|_| output != 0) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let value = value(pool);
    if value == u32::MAX {
        return Hresult::FAIL.0;
    }
    store(output as usize, value);
    SUCCESS.0
}

extern "C" fn memory(pool: u32, output: u32) -> u32 {
    read_count(pool, output, |pool| load(pool.0 + MEMORY))
}
export!(341, memory);

/// `attributes` is optional; `output` receives the pool.
extern "C" fn create(attributes: u32, output: u32) -> u32 {
    if output == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    store(output as usize, 0);
    let attributes = attributes as usize;
    let (flags, per_block) = if attributes == 0 {
        (0, 16)
    } else {
        if load(attributes + 0x14) != ATTRIBUTES_SIZE {
            return Hresult::INVALID_ARGUMENT.0;
        }
        (
            load(attributes),
            (load(attributes + 4) as i32).clamp(16, 0x100_0000) as u32,
        )
    };
    let keep = attributes != 0 && flags & KEPT_FLAGS != 0;
    let record = default_record();
    let mut counter = 0u32;
    let size = OBJECT_SIZE + super::ALLOCATOR_SIZE + if keep { ATTRIBUTES_SIZE } else { 0 };
    let Some((pool, raw)) =
        Allocator::of(&record).allocate_aligned(size, &raw mut counter as usize)
    else {
        return CREATE_FAILED.0;
    };
    let base = pool as usize;
    zero(base, OBJECT_SIZE as usize);
    store(base + BASE, raw);
    store(base + MEMORY, counter);
    let allocator = base + OBJECT_SIZE as usize;
    store(base + ALLOCATOR, allocator as u32);
    copy(
        allocator,
        record.as_ptr() as usize,
        super::ALLOCATOR_SIZE as usize,
    );
    if keep {
        let kept = allocator + super::ALLOCATOR_SIZE as usize;
        store(base + ATTRIBUTES, kept as u32);
        copy(kept, attributes, ATTRIBUTES_SIZE as usize);
    }
    store(base + KIND, Kind::from_flags(flags).encode());
    store(base + GROW, per_block);
    store(base + TABLE, (base + INITIAL_TABLE) as u32);
    store(base + TABLE_COUNT, 1);
    store(base + SIGNATURE, LFPL);
    lwsync();
    store(output as usize, pool);
    SUCCESS.0
}
export!(342, create);

/// Take a free lock record, growing the free list by a block when empty.
extern "C" fn allocate_lock(pool: u32, output: u32) -> u32 {
    let Some(pool) = Pool::validate(pool).filter(|_| output != 0) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let Some(record) = pop(pool.0 + RECORDS, 0)
        .or_else(|| pool.add_records(load(pool.0 + GROW), FirstRecord::Keep))
    else {
        store(output as usize, 0);
        return CREATE_FAILED.0;
    };
    let address = record as usize;
    store_quad(address, 0);
    if pool.kind() != Kind::Plain {
        store(address + RECURSION, 0);
        store(address + OWNER, 0);
    }
    lwsync();
    store(output as usize, record);
    SUCCESS.0
}
export!(343, allocate_lock);

/// 1 after destroying, 0 for an invalid pool.
extern "C" fn destroy(pool: u32) -> u32 {
    if pool == 0 || exchange(pool as usize + SIGNATURE, 0) != LFPL {
        return 0;
    }
    let pool = Pool(pool as usize);
    let allocator = pool.allocator();
    let table = load(pool.0 + TABLE);
    let count = load(pool.0 + TABLE_COUNT) & COUNT_MASK;
    // Stock walks to the count even when a failure set it to the full mark
    // past the end of the table; the walk stays within the table here, and
    // a table of unknown origin is not walked.
    let slots = pool
        .capacity(table)
        .map_or(0, |capacity| count.min(capacity));
    for index in (0..slots).rev() {
        let entry = pool.entry(index);
        if entry.0 != 0 {
            close_handle(entry.semaphore());
            close_handle(entry.event());
            allocator.free(entry.0);
        }
    }
    for order in 0..GROWN_TABLE_COUNT {
        let grown = load(pool.0 + GROWN_TABLES + 4 * order);
        if grown != 0 {
            allocator.free(grown);
        }
    }
    allocator.free_blocks(pool.0 + BLOCKS);
    allocator.free(load(pool.0 + BASE));
    lwsync();
    1
}
export!(344, destroy);

/// Return an idle lock record from 343 to the free list.
extern "C" fn free_lock(pool: u32, lock: u32) -> u32 {
    let Some(pool) = Pool::validate(pool) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let address = lock as usize;
    let alignment = if pool.kind() == Kind::Plain { 7 } else { 15 };
    if lock == 0
        || lock & 7 != 0
        || (load(address + 4) & !SPIN) | load(address) != 0
        || lock & alignment != 0
    {
        return Hresult::INVALID_ARGUMENT.0;
    }
    push(pool.0 + RECORDS, lock, 0);
    SUCCESS.0
}
export!(345, free_lock);

/// Create `count` wait entries ahead of use; E_FAIL when fewer were made.
extern "C" fn reserve_entries(pool: u32, count: u32) -> u32 {
    let Some(pool) = Pool::validate(pool).filter(|_| count as i32 >= 0) else {
        return Hresult::INVALID_ARGUMENT.0;
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
        SUCCESS.0
    } else {
        Hresult::FAIL.0
    }
}
export!(346, reserve_entries);

/// Add `count` free lock records; a plain pool adds one block whatever the
/// count. E_FAIL when the records were not added.
extern "C" fn reserve_locks(pool: u32, count: u32) -> u32 {
    let Some(pool) = Pool::validate(pool) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let added = if pool.kind() == Kind::Plain {
        pool.add_records(load(pool.0 + GROW), FirstRecord::Free)
            .map_or(0, |_| count)
    } else if count as i32 > 0 && count < 0x07ff_ffff {
        pool.add_records(count, FirstRecord::Free)
            .map_or(0, |_| count)
    } else {
        0
    };
    if added == count {
        SUCCESS.0
    } else {
        Hresult::FAIL.0
    }
}
export!(347, reserve_locks);

/// Prepare caller memory as a lock record.
extern "C" fn initialize_lock(pool: u32, lock: u32) -> u32 {
    let Some(pool) = Pool::validate(pool).filter(|_| lock != 0 && lock & 7 == 0) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let address = lock as usize;
    store_quad(address, 0);
    store(address + 4, load(address + 4) | CALLER_RECORD);
    if pool.kind() != Kind::Plain {
        store(address + OWNER, 0);
        store(address + RECURSION, 0);
    }
    lwsync();
    SUCCESS.0
}
export!(348, initialize_lock);

/// Wait entries created.
extern "C" fn entry_count(pool: u32, output: u32) -> u32 {
    read_count(pool, output, |pool| {
        (load(pool.0 + TABLE_COUNT) & COUNT_MASK).wrapping_sub(1)
    })
}
export!(349, entry_count);

extern "C" fn record_total(pool: u32, output: u32) -> u32 {
    read_count(pool, output, |pool| load(pool.0 + TOTAL))
}
export!(350, record_total);

/// Release a lock record held shared (`mode` 0) or exclusive (1).
extern "C" fn release(pool: u32, mode: u32, lock: u32) -> u32 {
    let Some(mut request) = request(pool, lock) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    match mode {
        0 => result(request.release_shared()).0,
        1 => result(request.release_exclusive()).0,
        _ => BAD_MODE.0,
    }
}
export!(351, release);
