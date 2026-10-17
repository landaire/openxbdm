//! Function detour engine (stock `dmdetours.c`): the hook entry table, the
//! record log, the logger the trampolines enter, and deferred completion of
//! overlapped requests.
//!
//! Every field is atomic so that one instance can be shared by the server
//! thread, the writer and completion workers, and title threads that enter
//! through a trampoline. Entry list changes happen on the server thread
//! only; the logger reads entries without a lock, as stock does.
// `Platform` reads and writes title memory by address.
#![allow(unsafe_code)]

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::sync::atomic::fence;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;

/// Hook entries, and trampolines (0x91f9f510).
pub const ENTRY_COUNT: u32 = 0x2e8;
/// Bytes per trampoline: `li r12, id`, a branch to the entry stub, then
/// the scribble area.
pub const TRAMPOLINE_SIZE: u32 = 0x58;
/// Offset of the scribble area, which the host fills with the relocated
/// start of the detoured function.
pub const SCRIBBLE_OFFSET: u32 = 8;
pub const SCRIBBLE_SIZE: u32 = 0x50;
/// Bytes of one log record.
pub const RECORD_SIZE: usize = 0x70;
const RECORD_WORDS: usize = RECORD_SIZE / 4;
/// Records in the pool (0x91f9f328).
pub const RECORD_COUNT: usize = 0x40;
/// Bytes of title memory one parameter record carries.
pub const BLOCK_SIZE: usize = 0x68;
const COMPLETION_SLOTS: usize = 0x40;
/// Interval at which the completion worker rechecks delayed completions.
pub const COMPLETION_POLL_MILLISECONDS: u32 = 200;

/// The word a hooked title function returns: the original's result, or
/// the configured value of a discarded call. A discarded overlapped call
/// stores the configured value as the request status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReturnValue(pub u32);

impl ReturnValue {
    /// `ERROR_IO_PENDING`: the result of a discarded call that completes
    /// its overlapped request later.
    pub const IO_PENDING: Self = Self(Win32Error::IO_PENDING.code());
}

/// Why an engine request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetourError {
    /// The engine is not running.
    NotRunning,
    /// The entry id is out of range.
    BadEntry,
    /// Every entry is in use.
    NoFreeEntry,
}

/// Index of a hook entry and its trampoline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryId(pub u32);

impl EntryId {
    fn index(self) -> Option<usize> {
        (self.0 < ENTRY_COUNT).then_some(self.0 as usize)
    }
}

/// Engine state (0x91f9f500).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    Stopped,
    Starting,
    Running,
    Stopping,
}

impl EngineState {
    pub const fn code(self) -> u32 {
        match self {
            Self::Stopped => 0,
            Self::Starting => 1,
            Self::Running => 2,
            Self::Stopping => 3,
        }
    }

    const fn from_code(code: u32) -> Self {
        match code {
            1 => Self::Starting,
            2 => Self::Running,
            3 => Self::Stopping,
            _ => Self::Stopped,
        }
    }
}

xbox360_sys::flags! {
    /// Hook flags: set per entry by `setinfo`; the logger derives the flags
    /// of one call from them.
    pub struct HookFlags(u32) {
        /// Log register, stack, floating-point, and vector parameter
        /// records.
        LOG_PARAMETERS = 0x1,
        /// Log a return record.
        LOG_RETURN = 0x2,
        /// Entry: never discard a call. Call: the original function runs.
        CALL_ORIGINAL = 0x4,
        /// Call: the original function is skipped and the configured return
        /// value is returned.
        DISCARDED = 0x8,
        REGISTERS = 0x10,
        FLOATING_POINT = 0x20,
        VECTOR = 0x40,
        STACK = 0x80,
        SLEEP_BEFORE = 0x100,
        SLEEP_AFTER = 0x200,
        /// A discarded call completes an overlapped request.
        OVERLAPPED = 0x400,
        /// The overlapped offset is an argument register index rather than
        /// a stack offset.
        OVERLAPPED_IN_REGISTER = 0x800,
        /// Call: the call record was logged.
        LOGGED = 0x1000,
    }
}

/// `entry setinfo` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HookSettings {
    pub address: u32,
    pub param_size: u32,
    pub flags: HookFlags,
    pub return_value: ReturnValue,
    pub sleep_milliseconds: u32,
    pub discard_frequency: u32,
    pub overlapped_offset: u32,
    /// Win32 error a discarded overlapped call completes with; `None`
    /// for `ERROR_SUCCESS`.
    pub extended_error: Option<Win32Error>,
}

/// What `entry query` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trampoline {
    pub enter: u32,
    pub scribble: u32,
    pub scribble_size: u32,
}

/// A link of the entry lists: entry index + 1, or 0 for none.
fn load_link(link: &AtomicU32) -> Option<usize> {
    link.load(Ordering::Relaxed)
        .checked_sub(1)
        .map(|index| index as usize)
}

fn store_link(link: &AtomicU32, index: Option<usize>) {
    link.store(index.map_or(0, |index| index as u32 + 1), Ordering::Relaxed);
}

/// One 0x34-byte hook entry.
struct Entry {
    address: AtomicU32,
    param_size: AtomicU32,
    return_value: AtomicU32,
    flags: AtomicU32,
    sleep_milliseconds: AtomicU32,
    discard_frequency: AtomicU32,
    calls: AtomicU32,
    overlapped_offset: AtomicU32,
    extended_error: AtomicU32,
    previous: AtomicU32,
    next: AtomicU32,
}

impl Entry {
    const fn new() -> Self {
        Self {
            address: AtomicU32::new(0),
            param_size: AtomicU32::new(0),
            return_value: AtomicU32::new(0),
            flags: AtomicU32::new(0),
            sleep_milliseconds: AtomicU32::new(0),
            discard_frequency: AtomicU32::new(0),
            calls: AtomicU32::new(0),
            overlapped_offset: AtomicU32::new(0),
            extended_error: AtomicU32::new(0),
            previous: AtomicU32::new(0),
            next: AtomicU32::new(0),
        }
    }

    fn flags(&self) -> HookFlags {
        HookFlags::from_bits_retain(self.flags.load(Ordering::Relaxed))
    }

    fn get(field: &AtomicU32) -> u32 {
        field.load(Ordering::Relaxed)
    }

    fn return_value(&self) -> ReturnValue {
        ReturnValue(Self::get(&self.return_value))
    }
}

/// The stored and logged word of an extended error.
fn win32_code(error: Option<Win32Error>) -> u32 {
    error.map_or(0, Win32Error::code)
}

/// Hook entries on a free list and an in-use list (0x91f9f508,
/// 0x91f9f50c). The list operations reproduce stock's pointer updates,
/// including their effect when an entry that is not in use is released.
struct EntryTable {
    entries: [Entry; ENTRY_COUNT as usize],
    free: AtomicU32,
    used: AtomicU32,
}

impl EntryTable {
    const fn new() -> Self {
        Self {
            entries: [const { Entry::new() }; ENTRY_COUNT as usize],
            free: AtomicU32::new(0),
            used: AtomicU32::new(0),
        }
    }

    /// Put every entry on the free list in id order (0x91f2c458).
    fn initialize(&self) {
        for (index, entry) in self.entries.iter().enumerate() {
            store_link(&entry.previous, index.checked_sub(1));
            store_link(
                &entry.next,
                Some(index + 1).filter(|&next| next < self.entries.len()),
            );
        }
        store_link(&self.free, Some(0));
        store_link(&self.used, None);
    }

    /// Move the first free entry to the head of the in-use list and clear
    /// its flags, sleep, discard frequency, and call count (0x91f2b9e0).
    fn acquire(&self) -> Option<usize> {
        let index = load_link(&self.free)?;
        let entry = &self.entries[index];
        let next = load_link(&entry.next);
        store_link(&self.free, next);
        if let Some(next) = next {
            store_link(&self.entries[next].previous, None);
        }
        let used = load_link(&self.used);
        store_link(&entry.next, used);
        if let Some(used) = used {
            store_link(&self.entries[used].previous, Some(index));
        }
        store_link(&self.used, Some(index));
        for field in [
            &entry.flags,
            &entry.sleep_milliseconds,
            &entry.discard_frequency,
            &entry.calls,
        ] {
            field.store(0, Ordering::Relaxed);
        }
        Some(index)
    }

    /// Unlink an entry and push it on the free list (0x91f2ba48).
    fn release(&self, index: usize) {
        let entry = &self.entries[index];
        let next = load_link(&entry.next);
        let previous = load_link(&entry.previous);
        if let Some(next) = next {
            store_link(&self.entries[next].previous, previous);
        }
        if let Some(previous) = previous {
            store_link(&self.entries[previous].next, next);
        }
        if load_link(&self.used) == Some(index) {
            store_link(&self.used, load_link(&entry.next));
        }
        if let Some(free) = load_link(&self.free) {
            store_link(&self.entries[free].previous, Some(index));
        }
        store_link(&entry.next, load_link(&self.free));
        store_link(&entry.previous, None);
        store_link(&self.free, Some(index));
        entry.flags.store(0, Ordering::Relaxed);
    }
}

/// Index of a record in the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecordIndex(usize);

struct QueueCell {
    sequence: AtomicU32,
    value: AtomicU32,
}

/// Bounded multi-producer, multi-consumer FIFO of record indices; stock
/// uses its lock-free queue exports for the free and filled lists.
struct RecordQueue {
    cells: [QueueCell; RECORD_COUNT],
    head: AtomicU32,
    tail: AtomicU32,
}

impl RecordQueue {
    const MASK: u32 = RECORD_COUNT as u32 - 1;

    const fn new() -> Self {
        Self {
            cells: [const {
                QueueCell {
                    sequence: AtomicU32::new(0),
                    value: AtomicU32::new(0),
                }
            }; RECORD_COUNT],
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
        }
    }

    fn reset(&self) {
        for (index, cell) in self.cells.iter().enumerate() {
            cell.sequence.store(index as u32, Ordering::Relaxed);
        }
        self.head.store(0, Ordering::Relaxed);
        self.tail.store(0, Ordering::Release);
    }

    fn push(&self, record: RecordIndex) -> bool {
        loop {
            let position = self.tail.load(Ordering::Relaxed);
            let cell = &self.cells[(position & Self::MASK) as usize];
            let lag = cell.sequence.load(Ordering::Acquire).wrapping_sub(position) as i32;
            if lag < 0 {
                return false;
            }
            if lag == 0
                && self
                    .tail
                    .compare_exchange_weak(
                        position,
                        position.wrapping_add(1),
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                cell.value.store(record.0 as u32, Ordering::Relaxed);
                cell.sequence
                    .store(position.wrapping_add(1), Ordering::Release);
                return true;
            }
        }
    }

    fn pop(&self) -> Option<RecordIndex> {
        loop {
            let position = self.head.load(Ordering::Relaxed);
            let cell = &self.cells[(position & Self::MASK) as usize];
            let lag = cell
                .sequence
                .load(Ordering::Acquire)
                .wrapping_sub(position.wrapping_add(1)) as i32;
            if lag < 0 {
                return None;
            }
            if lag == 0
                && self
                    .head
                    .compare_exchange_weak(
                        position,
                        position.wrapping_add(1),
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                let value = cell.value.load(Ordering::Relaxed) as usize;
                cell.sequence
                    .store(position.wrapping_add(Self::MASK + 1), Ordering::Release);
                return Some(RecordIndex(value));
            }
        }
    }
}

/// Record types (the dword at +0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordType {
    Call = 0,
    Return = 1,
    FloatingPoint = 2,
    Vector = 3,
    Stack = 4,
    SetInfo = 5,
    Release = 6,
    Completion = 7,
}

/// A record taken from the pool and its words in the record storage.
#[derive(Clone, Copy)]
struct Record {
    index: RecordIndex,
    words: &'static [AtomicU32],
}

/// Words of the record storage the platform provides.
pub const RECORD_STORAGE_WORDS: usize = RECORD_COUNT * RECORD_WORDS;

/// The free and filled queues of the record pool, and the log counters
/// (0x91f9f328..0x91f9f450). Records are reused without clearing, so a
/// field a record type does not write keeps the value of an earlier use of
/// the same record.
struct RecordLog {
    free: RecordQueue,
    filled: RecordQueue,
    /// Records may be allocated (0x91f9f330 == 2).
    accepting: AtomicBool,
    /// Producers between allocation and submission, plus the writer while
    /// it holds a record (0x91f9f33c).
    users: AtomicU32,
    written: AtomicU32,
    read: AtomicU32,
}

impl RecordLog {
    const fn new() -> Self {
        Self {
            free: RecordQueue::new(),
            filled: RecordQueue::new(),
            accepting: AtomicBool::new(false),
            users: AtomicU32::new(0),
            written: AtomicU32::new(0),
            read: AtomicU32::new(0),
        }
    }

    fn set_u32(&self, record: Record, offset: usize, value: u32) {
        record.words[offset / 4].store(value, Ordering::Relaxed);
    }

    fn set_u64(&self, record: Record, offset: usize, value: u64) {
        self.set_u32(record, offset, (value >> 32) as u32);
        self.set_u32(record, offset + 4, value as u32);
    }

    fn set_bytes(&self, record: Record, offset: usize, bytes: &[u8]) {
        for (index, word) in bytes.as_chunks::<4>().0.iter().enumerate() {
            self.set_u32(record, offset + index * 4, u32::from_be_bytes(*word));
        }
    }

    fn bytes(&self, record: Record) -> [u8; RECORD_SIZE] {
        let mut bytes = [0u8; RECORD_SIZE];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(record.words) {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_be_bytes());
        }
        bytes
    }
}

/// The words of record `index` in `storage`.
fn record_in(storage: &'static [AtomicU32], index: RecordIndex) -> Record {
    Record {
        index,
        words: &storage[index.0 * RECORD_WORDS..][..RECORD_WORDS],
    }
}

/// Services the engine needs from the platform. Implementations are
/// callable from any thread.
///
/// The title memory the engine passes to the access methods is the stub
/// locals, stack parameters and register save areas of a hooked call
/// while that call is in the logger, and the XOVERLAPPED of a discarded
/// overlapped call, which the title keeps until its completion is
/// written. Stock does not align these accesses.
pub trait Platform {
    /// Address of trampoline 0.
    fn trampolines(&self) -> u32;
    fn timebase(&self) -> u64;
    fn system_time(&self) -> u64;
    /// Milliseconds since boot.
    fn tick_count(&self) -> u32;
    fn sleep(&self, milliseconds: u32);
    /// Record pool storage of [`RECORD_STORAGE_WORDS`] words; `None` until
    /// [`Platform::allocate_records`] succeeded.
    fn records(&self) -> Option<&'static [AtomicU32]>;
    /// Obtain the record pool storage from pool memory unless it is held.
    /// Stock allocates it at every start and frees it at stop; here it is
    /// kept once obtained. False when pool memory is short.
    fn allocate_records(&self) -> bool;
    /// The record pool is empty; wait briefly for the writer to free one.
    fn wait_for_record(&self);
    /// A record was queued for the writer.
    fn record_queued(&self);
    /// The writer returned a record to the pool.
    fn record_freed(&self);
    /// # Safety
    ///
    /// The 4 bytes at `address` are title memory that stays readable for
    /// the call.
    unsafe fn read_u32(&self, address: u32) -> u32;
    /// # Safety
    ///
    /// The 8 bytes at `address` are title memory that stays readable for
    /// the call.
    unsafe fn read_u64(&self, address: u32) -> u64;
    /// # Safety
    ///
    /// The [`BLOCK_SIZE`] bytes at `address` are title memory that stays
    /// readable for the call.
    unsafe fn read_block(&self, address: u32, output: &mut [u8; BLOCK_SIZE]);
    /// Store a word that title threads may read concurrently.
    ///
    /// # Safety
    ///
    /// `address` is an aligned word of title memory that stays writable
    /// for the call.
    unsafe fn write_u32(&self, address: u32, value: u32);
    /// `ObReferenceObjectByHandle` with any object type.
    fn reference_event(&self, handle: u32) -> Option<u32>;
    /// # Safety
    ///
    /// `event` is an event object [`Platform::reference_event`] returned
    /// whose reference is still held.
    unsafe fn signal_event(&self, event: u32);
    /// Serialize completion slot changes (stock critical section at
    /// 0x91f9e4e8).
    fn lock_completions(&self);
    fn unlock_completions(&self);
    /// Wake the completion worker.
    fn completion_queued(&self);
    /// No completion is pending; the worker may sleep until the next one
    /// is queued.
    fn completions_idle(&self);
}

/// The stub's per-call locals (0x70 bytes at the stub frame + 0x50).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CallContext {
    /// Address of the locals in title memory. An overlapped register
    /// index past r10 reads relative to it, as stock does.
    pub address: u32,
    /// Entry id the trampoline loaded into r12.
    pub hook: u32,
    pub sequence: u32,
    pub flags: HookFlags,
    pub param_size: u32,
    /// Function the stub calls with the saved arguments; `None` when the
    /// call is discarded.
    pub function: Option<u32>,
    pub return_value: ReturnValue,
    /// r3 through r10 on entry.
    pub registers: [u64; 8],
    pub overlapped: Option<u32>,
}

impl CallContext {
    /// Offsets of the fields within the locals.
    pub const HOOK: u32 = 0;
    pub const SEQUENCE: u32 = 4;
    pub const FLAGS: u32 = 8;
    pub const PARAM_SIZE: u32 = 0xc;
    pub const FUNCTION: u32 = 0x10;
    pub const RETURN_VALUE: u32 = 0x14;
    pub const REGISTERS: u32 = 0x18;
    pub const OVERLAPPED: u32 = 0x58;
}

/// A deferred overlapped completion (0x38-byte slot).
struct CompletionSlot {
    in_use: AtomicBool,
    sequence: AtomicU32,
    hook: AtomicU32,
    flags: AtomicU32,
    overlapped: AtomicU32,
    status: AtomicU32,
    due: AtomicU32,
    extended_error: AtomicU32,
    event: AtomicU32,
    next: AtomicU32,
}

/// Completion slots on a free list (0x91f9e504, head at 0x91f9f304).
/// Callers hold the platform's completion lock.
struct Completions {
    slots: [CompletionSlot; COMPLETION_SLOTS],
    free: AtomicU32,
}

impl Completions {
    const fn new() -> Self {
        Self {
            slots: [const {
                CompletionSlot {
                    in_use: AtomicBool::new(false),
                    sequence: AtomicU32::new(0),
                    hook: AtomicU32::new(0),
                    flags: AtomicU32::new(0),
                    overlapped: AtomicU32::new(0),
                    status: AtomicU32::new(0),
                    due: AtomicU32::new(0),
                    extended_error: AtomicU32::new(0),
                    event: AtomicU32::new(0),
                    next: AtomicU32::new(0),
                }
            }; COMPLETION_SLOTS],
            free: AtomicU32::new(0),
        }
    }

    /// Clear every slot and chain them in index order (0x91f2c150).
    /// Pending completions are dropped without completing.
    fn reset(&self) {
        for (index, slot) in self.slots.iter().enumerate() {
            slot.in_use.store(false, Ordering::Relaxed);
            for field in [
                &slot.sequence,
                &slot.hook,
                &slot.flags,
                &slot.overlapped,
                &slot.status,
                &slot.due,
                &slot.extended_error,
                &slot.event,
            ] {
                field.store(0, Ordering::Relaxed);
            }
            store_link(
                &slot.next,
                Some(index + 1).filter(|&next| next < COMPLETION_SLOTS),
            );
        }
        store_link(&self.free, Some(0));
    }
}

/// A completion the logger defers.
struct PendingCompletion {
    sequence: u32,
    hook: u32,
    flags: HookFlags,
    overlapped: u32,
    event: Option<u32>,
    delay_milliseconds: u32,
    status: ReturnValue,
    extended_error: Option<Win32Error>,
}

/// The detour engine.
pub struct Engine {
    table: EntryTable,
    log: RecordLog,
    completions: Completions,
    state: AtomicU32,
    /// Status of the last failed log open (0x91f9f4f8); 0 when the last
    /// open succeeded or none ran since `start`.
    status: AtomicU32,
    /// Sequence number of the last call (0x91f9f504); never reset.
    sequence: AtomicU32,
}

impl Default for Engine {
    fn default() -> Self {
        let engine = Self::new();
        engine.initialize();
        engine
    }
}

impl Engine {
    /// An engine whose lists are empty until [`Engine::initialize`].
    pub const fn new() -> Self {
        Self {
            table: EntryTable::new(),
            log: RecordLog::new(),
            completions: Completions::new(),
            state: AtomicU32::new(0),
            status: AtomicU32::new(0),
            sequence: AtomicU32::new(0),
        }
    }

    /// Link the entry table and the completion slots (module init).
    pub fn initialize(&self) {
        self.table.initialize();
        self.completions.reset();
    }

    pub fn state(&self) -> EngineState {
        EngineState::from_code(self.state.load(Ordering::Acquire))
    }

    /// The error of the last log open.
    pub fn log_error(&self) -> Option<KernelError> {
        KernelError::from_status(NtStatus(self.status.load(Ordering::Relaxed)))
    }

    fn running(&self) -> bool {
        self.state() == EngineState::Running
    }

    fn transition(&self, from: EngineState, to: EngineState) -> bool {
        self.state
            .compare_exchange(from.code(), to.code(), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn checked_entry(&self, id: EntryId) -> Result<usize, DetourError> {
        if !self.running() {
            return Err(DetourError::NotRunning);
        }
        // Stock accepts an id equal to the entry count and then reads past
        // the table.
        id.index().ok_or(DetourError::BadEntry)
    }

    /// `log available` (0x91f2bc40): records written but not yet read.
    pub fn available(&self) -> Result<u32, DetourError> {
        if !self.running() {
            return Err(DetourError::NotRunning);
        }
        Ok(self
            .log
            .written
            .load(Ordering::Acquire)
            .wrapping_sub(self.log.read.load(Ordering::Relaxed)))
    }

    /// Whether the log holds a record `log getentries` has not read.
    pub fn has_unread(&self) -> bool {
        self.log.read.load(Ordering::Relaxed) < self.log.written.load(Ordering::Acquire)
    }

    /// Count a record `log getentries` read.
    pub fn note_read(&self) {
        self.log.read.fetch_add(1, Ordering::Relaxed);
    }

    /// `entry acquire` (0x91f2bac0).
    pub fn acquire(&self) -> Result<EntryId, DetourError> {
        if !self.running() {
            return Err(DetourError::NotRunning);
        }
        self.table
            .acquire()
            .map(|index| EntryId(index as u32))
            .ok_or(DetourError::NoFreeEntry)
    }

    /// `entry release` (0x91f2ce68): log a release record and free the
    /// entry.
    pub fn release(&self, platform: &dyn Platform, id: EntryId) -> Result<(), DetourError> {
        let index = self.checked_entry(id)?;
        if let Some(record) = self.allocate(platform) {
            self.log.set_u32(record, 4, 0);
            self.log.set_u32(record, 0, RecordType::Release as u32);
            self.log.set_u64(record, 8, timestamp(platform));
            self.log.set_u32(record, 0x18, id.0);
            self.submit(platform, record);
        }
        self.table.release(index);
        Ok(())
    }

    /// `entry query` (0x91f2bb30).
    pub fn query(&self, platform: &dyn Platform, id: EntryId) -> Result<Trampoline, DetourError> {
        self.checked_entry(id)?;
        let enter = platform.trampolines().wrapping_add(id.0 * TRAMPOLINE_SIZE);
        Ok(Trampoline {
            enter,
            scribble: enter.wrapping_add(SCRIBBLE_OFFSET),
            scribble_size: SCRIBBLE_SIZE,
        })
    }

    /// `entry setinfo` (0x91f2cf30): log a setinfo record and configure the
    /// entry.
    ///
    /// # Safety
    ///
    /// `settings` describes the parameters of the function hooked at `id`:
    /// for each call of it, the memory [`Engine::enter`] requires from the
    /// overlapped offset and parameter size is readable, and an overlapped
    /// parameter is 0 or the call's XOVERLAPPED, whose event handle names an
    /// event. Stock trusts the debugger client for this.
    pub unsafe fn configure(
        &self,
        platform: &dyn Platform,
        id: EntryId,
        settings: &HookSettings,
    ) -> Result<(), DetourError> {
        let index = self.checked_entry(id)?;
        if let Some(record) = self.allocate(platform) {
            self.log.set_u32(record, 0x1c, settings.flags.bits());
            self.log.set_u32(record, 0x18, id.0);
            self.log.set_u32(record, 0, RecordType::SetInfo as u32);
            self.log.set_u32(record, 4, 0);
            self.log.set_u64(record, 8, timestamp(platform));
            self.log.set_u32(record, 0x20, settings.address);
            self.log.set_u32(record, 0x24, settings.param_size);
            self.log.set_u32(record, 0x28, settings.return_value.0);
            self.log.set_u64(record, 0x10, platform.system_time());
            self.submit(platform, record);
        }
        let entry = &self.table.entries[index];
        entry.address.store(settings.address, Ordering::Relaxed);
        entry
            .param_size
            .store(settings.param_size, Ordering::Relaxed);
        entry
            .return_value
            .store(settings.return_value.0, Ordering::Relaxed);
        entry.flags.store(settings.flags.bits(), Ordering::Relaxed);
        entry
            .sleep_milliseconds
            .store(settings.sleep_milliseconds, Ordering::Relaxed);
        entry
            .discard_frequency
            .store(settings.discard_frequency, Ordering::Relaxed);
        entry
            .extended_error
            .store(win32_code(settings.extended_error), Ordering::Relaxed);
        entry
            .overlapped_offset
            .store(settings.overlapped_offset, Ordering::Relaxed);
        Ok(())
    }

    /// Release every in-use entry whose address lies in `[base, base +
    /// size)`, logging a release record with the system time for each
    /// (0x91f2c608, module unload).
    pub fn release_range(&self, platform: &dyn Platform, base: u32, size: u32) {
        let end = base.wrapping_add(size);
        let mut cursor = load_link(&self.table.used);
        // Stock follows the list without a bound; a list corrupted by
        // releasing a free entry would loop forever.
        for _ in 0..ENTRY_COUNT {
            let Some(index) = cursor else {
                break;
            };
            let entry = &self.table.entries[index];
            cursor = load_link(&entry.next);
            let address = Entry::get(&entry.address);
            if address < base || address >= end {
                continue;
            }
            if let Some(record) = self.allocate(platform) {
                self.log.set_u32(record, 4, 0);
                self.log.set_u32(record, 0, RecordType::Release as u32);
                self.log.set_u64(record, 8, timestamp(platform));
                self.log.set_u64(record, 0x10, platform.system_time());
                self.log.set_u32(record, 0x18, index as u32);
                self.submit(platform, record);
            }
            self.table.release(index);
        }
    }

    /// Move from stopped to starting (`start`, 0x91f2d330).
    /// The status of the previous run is cleared once the engine is taken.
    pub fn begin_start(&self) -> bool {
        let started = self.transition(EngineState::Stopped, EngineState::Starting);
        if started {
            self.status.store(0, Ordering::Relaxed);
        }
        started
    }

    /// Return to stopped after the workers could not be created.
    pub fn cancel_start(&self) {
        self.state
            .store(EngineState::Stopped.code(), Ordering::Release);
    }

    /// Reset the counters and the record pool before the log files open
    /// (0x91f2cb28). Fresh records read as zero. False when the record
    /// storage cannot be obtained.
    pub fn prepare_log(&self, platform: &dyn Platform) -> bool {
        let log = &self.log;
        self.status.store(0, Ordering::Relaxed);
        log.written.store(0, Ordering::Relaxed);
        log.read.store(0, Ordering::Relaxed);
        log.users.store(0, Ordering::Relaxed);
        if !platform.allocate_records() {
            return false;
        }
        let Some(storage) = platform.records() else {
            return false;
        };
        for word in storage {
            word.store(0, Ordering::Relaxed);
        }
        log.free.reset();
        log.filled.reset();
        for index in 0..RECORD_COUNT {
            log.free.push(RecordIndex(index));
        }
        true
    }

    /// Record the result of a log file open.
    pub fn set_log_result(&self, result: Result<(), KernelError>) {
        let status = match result {
            Ok(()) => 0,
            Err(error) => NtStatus::from(error).0,
        };
        self.status.store(status, Ordering::Relaxed);
    }

    /// The log files are open: accept records and move from starting to
    /// running (0x91f2d040).
    pub fn mark_running(&self) {
        self.log.accepting.store(true, Ordering::Release);
        self.transition(EngineState::Starting, EngineState::Running);
    }

    /// A log file failed to open: move from starting to stopped.
    pub fn abort_start(&self) {
        self.transition(EngineState::Starting, EngineState::Stopped);
    }

    /// `stop` (0x91f2cd08): refuse new records and move from running to
    /// stopping. Records are refused even when the transition fails.
    pub fn begin_stop(&self) -> bool {
        self.log.accepting.store(false, Ordering::Release);
        fence(Ordering::SeqCst);
        self.transition(EngineState::Running, EngineState::Stopping)
    }

    /// The writer keeps writing while this holds.
    pub fn writing(&self) -> bool {
        self.running()
    }

    /// Write every queued record (0x91f2bd60, 0x91f2bf58). `write` stores
    /// one record in the log file and reports success.
    pub fn write_queued(
        &self,
        platform: &dyn Platform,
        write: &mut dyn FnMut(&[u8; RECORD_SIZE]) -> bool,
    ) {
        let log = &self.log;
        let Some(storage) = platform.records() else {
            return;
        };
        loop {
            log.users.fetch_add(1, Ordering::AcqRel);
            if !log.accepting.load(Ordering::Acquire) {
                log.users.fetch_sub(1, Ordering::AcqRel);
                return;
            }
            let Some(record) = log.filled.pop() else {
                log.users.fetch_sub(1, Ordering::AcqRel);
                return;
            };
            if write(&log.bytes(record_in(storage, record))) {
                log.written.fetch_add(1, Ordering::AcqRel);
            }
            if log.free.push(record) {
                log.users.fetch_sub(1, Ordering::AcqRel);
                platform.record_freed();
            }
        }
    }

    /// Return queued records to the pool unwritten; `false` once no
    /// producer holds a record (0x91f2d0a4 stop path).
    pub fn discard_queued(&self, platform: &dyn Platform) -> bool {
        let log = &self.log;
        if log.users.load(Ordering::Acquire) == 0 {
            return false;
        }
        while let Some(record) = log.filled.pop() {
            log.free.push(record);
            platform.record_freed();
        }
        true
    }

    /// Drop pending completions and return to stopped (end of `stop`).
    pub fn finish_stop(&self, platform: &dyn Platform) {
        platform.lock_completions();
        self.completions.reset();
        platform.unlock_completions();
        self.state
            .store(EngineState::Stopped.code(), Ordering::Release);
    }

    /// Take a record from the pool, waiting while it is empty (0x91f2be68).
    /// `None` while records are refused.
    fn allocate(&self, platform: &dyn Platform) -> Option<Record> {
        let log = &self.log;
        log.users.fetch_add(1, Ordering::AcqRel);
        // Records are accepted only after the storage was obtained.
        let storage = platform
            .records()
            .filter(|_| log.accepting.load(Ordering::Acquire));
        let Some(storage) = storage else {
            log.users.fetch_sub(1, Ordering::AcqRel);
            return None;
        };
        loop {
            if let Some(record) = log.free.pop() {
                return Some(record_in(storage, record));
            }
            platform.wait_for_record();
        }
    }

    /// Queue a record for the writer (0x91f2c038).
    fn submit(&self, platform: &dyn Platform, record: Record) {
        if self.log.filled.push(record.index) {
            self.log.users.fetch_sub(1, Ordering::AcqRel);
            platform.record_queued();
        }
    }

    /// Log `BLOCK_SIZE` bytes of title memory at `source` (0x91f2c0f8).
    ///
    /// # Safety
    ///
    /// As [`Platform::read_block`] for `source`.
    unsafe fn log_block(
        &self,
        platform: &dyn Platform,
        sequence: u32,
        kind: RecordType,
        source: u32,
    ) {
        let Some(record) = self.allocate(platform) else {
            return;
        };
        self.log.set_u32(record, 4, sequence);
        self.log.set_u32(record, 0, kind as u32);
        let mut block = [0u8; BLOCK_SIZE];
        // SAFETY: the caller's contract.
        unsafe { platform.read_block(source, &mut block) };
        self.log.set_bytes(record, 8, &block);
        self.submit(platform, record);
    }

    fn entry_of(&self, call: &CallContext) -> Option<&Entry> {
        EntryId(call.hook)
            .index()
            .map(|index| &self.table.entries[index])
    }

    /// Notification 0, before the call (0x91f2c8fc). `frame` is the entry
    /// stack pointer + 0x10, where stack parameters start.
    ///
    /// # Safety
    ///
    /// `call.address` is the stub locals and `frame` the stack parameters
    /// of a hooked call in the logger. The memory the entry of `call.hook`
    /// describes is readable for the call: with an overlapped offset, the
    /// 8 bytes at `frame` + offset, or at `call.address` + (offset + 3) * 8
    /// for a register index past r10; with stack logging, [`BLOCK_SIZE`]
    /// bytes at each multiple of [`BLOCK_SIZE`] from `frame` below the
    /// parameter size, and at least the first.
    pub unsafe fn enter(&self, platform: &dyn Platform, call: &mut CallContext, frame: u32) {
        // Stock asserts on a bad id and then indexes past the table.
        let Some(entry) = self.entry_of(call) else {
            return;
        };
        let calls = entry.calls.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let discard = if entry.flags().contains(HookFlags::CALL_ORIGINAL) {
            false
        } else {
            match Entry::get(&entry.discard_frequency) {
                0 => true,
                frequency => calls % frequency == 0,
            }
        };
        call.param_size = Entry::get(&entry.param_size);
        call.flags = entry.flags();
        let enter = platform
            .trampolines()
            .wrapping_add(call.hook.wrapping_mul(TRAMPOLINE_SIZE));
        call.function = Some(enter.wrapping_add(SCRIBBLE_OFFSET));
        call.return_value = entry.return_value();
        call.sequence = self
            .sequence
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);

        let flags = entry.flags();
        let overlapped = if flags.contains(HookFlags::OVERLAPPED) {
            let offset = Entry::get(&entry.overlapped_offset);
            let value = if flags.contains(HookFlags::OVERLAPPED_IN_REGISTER) {
                match call.registers.get(offset as usize) {
                    Some(&register) => register,
                    // SAFETY: the caller's contract for a register index
                    // past r10.
                    None => unsafe {
                        platform.read_u64(
                            call.address
                                .wrapping_add(offset.wrapping_add(3).wrapping_shl(3)),
                        )
                    },
                }
            } else {
                // SAFETY: the caller's contract for the overlapped offset.
                unsafe { platform.read_u64(frame.wrapping_add(offset)) }
            };
            value as u32
        } else {
            0
        };
        call.overlapped = (overlapped != 0).then_some(overlapped);
        if call.overlapped.is_none() {
            call.flags = call.flags.difference(HookFlags::OVERLAPPED);
        }
        if discard {
            call.function = None;
            call.flags = call.flags.union(HookFlags::DISCARDED);
        } else {
            call.flags = call
                .flags
                .difference(HookFlags::DISCARDED)
                .union(HookFlags::CALL_ORIGINAL);
        }

        match self.allocate(platform) {
            Some(record) => {
                self.log.set_u32(record, 0, RecordType::Call as u32);
                self.log.set_u32(record, 4, call.sequence);
                self.log.set_u32(record, 0x1c, call.flags.bits());
                self.log.set_u32(record, 0x18, call.hook);
                self.log.set_u64(record, 8, timestamp(platform));
                self.log.set_u64(record, 0x10, platform.system_time());
                if entry.flags().contains(HookFlags::SLEEP_BEFORE) {
                    self.log
                        .set_u32(record, 0x60, Entry::get(&entry.sleep_milliseconds));
                }
                let parameters = entry.flags().contains(HookFlags::LOG_PARAMETERS);
                if call.flags.contains(HookFlags::REGISTERS) && parameters {
                    for (index, register) in call.registers.iter().enumerate() {
                        self.log.set_u64(record, 0x20 + index * 8, *register);
                    }
                }
                self.submit(platform, record);
                if call.flags.contains(HookFlags::STACK)
                    && entry.flags().contains(HookFlags::LOG_PARAMETERS)
                {
                    let mut offset = 0u32;
                    loop {
                        // SAFETY: a block of the stack parameters the
                        // caller's contract covers.
                        unsafe {
                            self.log_block(
                                platform,
                                call.sequence,
                                RecordType::Stack,
                                frame.wrapping_add(offset),
                            )
                        };
                        offset = offset.wrapping_add(BLOCK_SIZE as u32);
                        if offset >= call.param_size {
                            break;
                        }
                    }
                }
                call.flags = call.flags.union(HookFlags::LOGGED);
            }
            None => call.flags = call.flags.difference(HookFlags::LOGGED),
        }
        if entry.flags().contains(HookFlags::SLEEP_BEFORE) {
            platform.sleep(Entry::get(&entry.sleep_milliseconds));
        }
    }

    fn logs_parameters(&self, call: &CallContext, entry: &Entry) -> bool {
        call.flags.contains(HookFlags::LOGGED) && entry.flags().contains(HookFlags::LOG_PARAMETERS)
    }

    /// Notification 1: log f1-f13, saved at `area` (0x91f2c8d0).
    ///
    /// # Safety
    ///
    /// `area` is the floating point save area of the hooked call in the
    /// logger: [`BLOCK_SIZE`] readable bytes.
    pub unsafe fn floating_point(&self, platform: &dyn Platform, call: &CallContext, area: u32) {
        if let Some(entry) = self.entry_of(call)
            && self.logs_parameters(call, entry)
        {
            // SAFETY: the caller's contract.
            unsafe { self.log_block(platform, call.sequence, RecordType::FloatingPoint, area) };
        }
    }

    /// Notification 2: log the vector save area at `area` as two records
    /// (0x91f2c89c).
    ///
    /// # Safety
    ///
    /// `area` is the vector save area of the hooked call in the logger:
    /// twice [`BLOCK_SIZE`] readable bytes.
    pub unsafe fn vector(&self, platform: &dyn Platform, call: &CallContext, area: u32) {
        if let Some(entry) = self.entry_of(call)
            && self.logs_parameters(call, entry)
        {
            // SAFETY: both blocks lie in the save area of the caller's
            // contract.
            unsafe {
                self.log_block(platform, call.sequence, RecordType::Vector, area);
                self.log_block(
                    platform,
                    call.sequence,
                    RecordType::Vector,
                    area.wrapping_add(BLOCK_SIZE as u32),
                );
            }
        }
    }

    /// Notification 3, after the call (0x91f2c768). `call.return_value`
    /// holds the original's result when it ran.
    ///
    /// # Safety
    ///
    /// `call` is the context [`Engine::enter`] produced for a hooked call
    /// in the logger. A set `call.overlapped` of a discarded call is the
    /// call's XOVERLAPPED: the words at +0 and +0xc are aligned, writable
    /// and readable now, and the words at +0, +4 and +0x18 stay writable
    /// until [`Engine::service_completions`] has completed the request. Its
    /// event handle at +0xc is 0 or names an event.
    pub unsafe fn exit(&self, platform: &dyn Platform, call: &mut CallContext) {
        let Some(entry) = self.entry_of(call) else {
            return;
        };
        if call.flags.contains(HookFlags::DISCARDED) {
            match call.overlapped {
                Some(overlapped) => {
                    let delay = if entry.flags().contains(HookFlags::SLEEP_AFTER) {
                        Entry::get(&entry.sleep_milliseconds)
                    } else {
                        0
                    };
                    call.return_value = ReturnValue::IO_PENDING;
                    // SAFETY: words of the XOVERLAPPED of the caller's
                    // contract.
                    let handle = unsafe {
                        platform.write_u32(overlapped, ReturnValue::IO_PENDING.0);
                        platform.read_u32(overlapped.wrapping_add(0xc))
                    };
                    let event = if handle != 0 {
                        platform.reference_event(handle)
                    } else {
                        None
                    };
                    self.defer_completion(
                        platform,
                        PendingCompletion {
                            sequence: call.sequence,
                            hook: call.hook,
                            flags: call.flags,
                            overlapped,
                            event,
                            delay_milliseconds: delay,
                            status: entry.return_value(),
                            extended_error: Win32Error::new(Entry::get(&entry.extended_error)),
                        },
                    );
                }
                None => call.return_value = entry.return_value(),
            }
        }
        if entry.flags().contains(HookFlags::SLEEP_AFTER) && call.overlapped.is_none() {
            platform.sleep(Entry::get(&entry.sleep_milliseconds));
        }
        if !entry.flags().contains(HookFlags::LOG_RETURN) || !call.flags.contains(HookFlags::LOGGED)
        {
            return;
        }
        let Some(record) = self.allocate(platform) else {
            return;
        };
        self.log.set_u32(record, 0, RecordType::Return as u32);
        self.log.set_u32(record, 4, call.sequence);
        self.log.set_u32(record, 0x14, call.flags.bits());
        self.log.set_u32(record, 0x10, call.hook);
        self.log.set_u32(record, 0x18, call.return_value.0);
        self.log.set_u64(record, 8, timestamp(platform));
        if entry.flags().contains(HookFlags::SLEEP_AFTER) {
            self.log
                .set_u32(record, 0x1c, Entry::get(&entry.sleep_milliseconds));
        }
        self.submit(platform, record);
    }

    /// Queue a completion for the worker (0x91f2c238). With every slot
    /// taken the request stays pending forever.
    fn defer_completion(&self, platform: &dyn Platform, pending: PendingCompletion) {
        let completions = &self.completions;
        platform.lock_completions();
        if let Some(index) = load_link(&completions.free) {
            let slot = &completions.slots[index];
            store_link(&completions.free, load_link(&slot.next));
            slot.in_use.store(true, Ordering::Relaxed);
            slot.overlapped.store(pending.overlapped, Ordering::Relaxed);
            slot.extended_error
                .store(win32_code(pending.extended_error), Ordering::Relaxed);
            slot.status.store(pending.status.0, Ordering::Relaxed);
            slot.due.store(
                platform
                    .tick_count()
                    .wrapping_add(pending.delay_milliseconds),
                Ordering::Relaxed,
            );
            slot.event
                .store(pending.event.unwrap_or(0), Ordering::Relaxed);
            slot.sequence.store(pending.sequence, Ordering::Relaxed);
            slot.hook.store(pending.hook, Ordering::Relaxed);
            slot.flags.store(pending.flags.bits(), Ordering::Relaxed);
            platform.completion_queued();
        }
        platform.unlock_completions();
    }

    /// One pass of the completion worker (0x91f2c2f8): complete every due
    /// request in slot order, logging a completion record for logged
    /// calls. Returns whether delayed completions remain.
    pub fn service_completions(&self, platform: &dyn Platform) -> bool {
        let now = platform.tick_count();
        let completions = &self.completions;
        platform.lock_completions();
        let mut pending = 0u32;
        for (index, slot) in completions.slots.iter().enumerate() {
            if !slot.in_use.load(Ordering::Relaxed) {
                continue;
            }
            if slot.due.load(Ordering::Relaxed) > now {
                pending += 1;
                continue;
            }
            let overlapped = slot.overlapped.load(Ordering::Relaxed);
            let status = slot.status.load(Ordering::Relaxed);
            let extended_error = slot.extended_error.load(Ordering::Relaxed);
            // 0x91f2b8b8: the extended error and InternalHigh first, the
            // status last, then the event.
            // SAFETY: only `exit` queues completions; its contract keeps
            // these words of the XOVERLAPPED writable until this pass
            // completes the request, and `event` is a reference it took
            // with `reference_event` of the XOVERLAPPED's event handle,
            // which that contract makes an event, and still holds.
            unsafe {
                platform.write_u32(overlapped.wrapping_add(0x18), extended_error);
                platform.write_u32(overlapped.wrapping_add(4), 0);
                fence(Ordering::SeqCst);
                platform.write_u32(overlapped, status);
                let event = slot.event.load(Ordering::Relaxed);
                if event != 0 {
                    platform.signal_event(event);
                }
            }
            // Stock reuses the previous record of this pass for an unlogged
            // call and queues it a second time; no record is written here.
            if HookFlags::from_bits_retain(slot.flags.load(Ordering::Relaxed))
                .contains(HookFlags::LOGGED)
                && let Some(record) = self.allocate(platform)
            {
                self.log.set_u32(record, 0, RecordType::Completion as u32);
                self.log
                    .set_u32(record, 4, slot.sequence.load(Ordering::Relaxed));
                self.log
                    .set_u32(record, 0x14, slot.flags.load(Ordering::Relaxed));
                self.log
                    .set_u32(record, 0x10, slot.hook.load(Ordering::Relaxed));
                self.log.set_u32(record, 0x18, status);
                self.log.set_u32(record, 0x1c, extended_error);
                self.log.set_u64(record, 8, timestamp(platform));
                self.log.set_u64(record, 0x20, platform.system_time());
                self.submit(platform, record);
            }
            slot.in_use.store(false, Ordering::Relaxed);
            slot.next
                .store(completions.free.load(Ordering::Relaxed), Ordering::Relaxed);
            store_link(&completions.free, Some(index));
        }
        if pending == 0 {
            platform.completions_idle();
        }
        platform.unlock_completions();
        pending != 0
    }
}

/// The time base as the logger stores it: read again when its low word is
/// zero.
fn timestamp(platform: &dyn Platform) -> u64 {
    let time = platform.timebase();
    if time as u32 == 0 {
        platform.timebase()
    } else {
        time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releasing_the_free_head_loses_the_rest_of_the_free_list() {
        let table = EntryTable::new();
        table.initialize();
        assert_eq!(table.acquire(), Some(0));
        table.release(1);
        assert_eq!(table.acquire(), Some(1));
        assert_eq!(table.acquire(), Some(1));
        assert_eq!(table.acquire(), Some(0));
    }

    #[test]
    fn released_entries_are_reused_first() {
        let table = EntryTable::new();
        table.initialize();
        for expected in 0..3 {
            assert_eq!(table.acquire(), Some(expected));
        }
        table.release(1);
        table.release(0);
        assert_eq!(table.acquire(), Some(0));
        assert_eq!(table.acquire(), Some(1));
        assert_eq!(table.acquire(), Some(3));
    }

    #[test]
    fn record_queue_is_first_in_first_out() {
        let queue = RecordQueue::new();
        queue.reset();
        for index in 0..RECORD_COUNT {
            assert!(queue.push(RecordIndex(index)));
        }
        assert!(!queue.push(RecordIndex(0)));
        for index in 0..RECORD_COUNT {
            assert_eq!(queue.pop(), Some(RecordIndex(index)));
        }
        assert_eq!(queue.pop(), None);
        assert!(queue.push(RecordIndex(5)));
        assert_eq!(queue.pop(), Some(RecordIndex(5)));
    }
}
