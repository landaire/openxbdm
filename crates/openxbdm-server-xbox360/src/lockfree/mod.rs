//! Lock-free containers of stock exports 300-351: queue 'LfQu' (302-309),
//! stack 'LfSt' (310-317), priority queue 'LFPQ' (320-328), hash table
//! 'LFHT' (330-338) and lock pool 'LfPl' (340-351), with the pool memory
//! routines 300 and 301.
//!
//! Lists link through tagged doublewords ([`DoubleWord`]): the node address
//! in the high word and a 31-bit change count in the low word, whose top
//! bit marks a deleted node of a sorted list. Every interlocked sequence
//! runs with external interrupts disabled across the reservation, and every
//! compare-exchange follows an `lwsync`. Containers draw fixed-size nodes
//! from a free list that grows in batches from blocks of the creation
//! allocator. Stock duplicates the node routines for each container layout;
//! [`Nodes`] carries the layout instead, so one copy serves all of them.
//!
//! Container memory is caller-visible. Each export turns its container
//! argument into a reference once (`from_handle` of the container type)
//! under the export contract: the caller passes 0 or a container that the
//! matching create export made and that no destroy frees while the call
//! runs. The containers keep these invariants from creation on:
//! - every node address in a list word, head, tail or bucket names a node
//!   in a block of the same container, of the container's node type;
//! - node blocks stay allocated until destroy;
//! - the allocator, options and semaphore words hold what creation stored;
//! - the allocator record, options and attributes after the container hold
//!   what creation copied there. Their routine fields ([`Routine`]) hold
//!   nonzero addresses of console routines: the routines of this crate, or
//!   those of the caller records, which the export contract requires to be
//!   console routines.

mod hash;
mod pool;
mod priority;
mod queue;
mod stack;

use core::marker::PhantomData;
use core::num::NonZeroU32;
use core::ptr;
use core::ptr::NonNull;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;
use core::time::Duration;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use xbox360::atomic::Interlocked32;
use xbox360::status::set_last_error;
use xbox360::status::set_last_error_value;
use xbox360::time::relative_interval;
use xbox360_sys::interlocked;
use xbox360_sys::processor;
use xbox360_sys::status::Facility;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DispatcherObject;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeReleaseSemaphore;
use xbox360_sys::xboxkrnl::Ksemaphore;
use xbox360_sys::xboxkrnl::NtCreateSemaphore;
use xbox360_sys::xboxkrnl::NtReleaseSemaphore;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::WaitReason;

use crate::exports::export;
use crate::kernel;
use crate::kernel::pool_tag;

pub(crate) use queue::Queue;

/// Failure of a container operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    /// A container, record or argument is not valid.
    InvalidArgument,
    /// The allocator returned no memory.
    NotEnoughMemory,
    /// No node or item in time, or a wait that timed out.
    Timeout,
    /// A sorted container with unique keys already holds the key.
    DuplicateKey,
    /// Another wait status or caller wait routine result.
    Wait(Win32Error),
    /// The first nonzero result of an enumeration callback.
    Callback(Win32Error),
}

impl Error {
    /// Facility of the container result codes.
    const FACILITY: Facility = Facility::new(0x31);
    /// An insertion found no free node in time, or its unique key present.
    const INSERT_TIMEOUT: Hresult = Hresult::failure(Self::FACILITY, 1);
    /// A removal found no item in time.
    const REMOVE_TIMEOUT: Hresult = Hresult::failure(Self::FACILITY, 2);

    /// Outcome of a wait status or caller wait routine result; stock
    /// treats both as Win32 codes.
    fn of_wait(status: u32) -> Result<(), Self> {
        match Win32Error::new(status) {
            None => Ok(()),
            Some(error) if error == Win32Error::WAIT_TIMEOUT => Err(Self::Timeout),
            Some(error) => Err(Self::Wait(error)),
        }
    }

    /// Export result of a failed insertion.
    pub(crate) fn insert_result(self) -> Hresult {
        match self {
            Self::Timeout | Self::DuplicateKey => Self::INSERT_TIMEOUT,
            error => error.into(),
        }
    }

    /// Export result of a failed removal.
    fn remove_result(self) -> Hresult {
        match self {
            Self::Timeout => Self::REMOVE_TIMEOUT,
            error => error.into(),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidArgument => f.write_str("invalid container or argument"),
            Self::NotEnoughMemory => f.write_str("not enough memory"),
            Self::Timeout => f.write_str("timed out"),
            Self::DuplicateKey => f.write_str("key already present"),
            Self::Wait(error) => write!(f, "wait failed with {:#x}", error.code()),
            Self::Callback(error) => write!(f, "callback failed with {:#x}", error.code()),
        }
    }
}

impl core::error::Error for Error {}

/// HRESULT of an operation without a timeout result of its own.
impl From<Error> for Hresult {
    fn from(error: Error) -> Self {
        match error {
            // Equal to HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER).
            Error::InvalidArgument => Self::INVALID_ARGUMENT,
            Error::NotEnoughMemory => Win32Error::NOT_ENOUGH_MEMORY.into(),
            Error::Timeout => Win32Error::WAIT_TIMEOUT.into(),
            Error::DuplicateKey => Error::INSERT_TIMEOUT,
            Error::Wait(error) | Error::Callback(error) => error.into(),
        }
    }
}

/// Result of an operation without a timeout result of its own.
fn success_result(result: Result<(), Error>) -> Hresult {
    match result {
        Ok(()) => Hresult::SUCCESS,
        Err(error) => error.into(),
    }
}

fn insert_result(result: Result<(), Error>) -> Hresult {
    match result {
        Ok(()) => Hresult::SUCCESS,
        Err(error) => error.insert_result(),
    }
}

/// A caller's output word. No reference to it exists before
/// [`OutputWord::store`], so none lives across the waits and caller
/// routines of an operation.
pub(crate) struct OutputWord<'a>(NonNull<u32>, PhantomData<&'a mut u32>);

impl<'a> OutputWord<'a> {
    /// The output word at `address`, or nothing for a null address.
    ///
    /// # Safety
    ///
    /// `address` is 0 or the address of an aligned word that the export
    /// may write for `'a`.
    pub(crate) unsafe fn new(address: u32) -> Option<Self> {
        NonNull::new(ptr::with_exposed_provenance_mut(address as usize))
            .map(|word| Self(word, PhantomData))
    }

    pub(crate) fn store(&self, value: u32) {
        // SAFETY: an aligned word the export may write (`OutputWord::new`).
        unsafe { self.0.write(value) }
    }
}

/// Store `value` through `output`: E_INVALIDARG without a container or an
/// output word.
fn report(value: Option<u32>, output: Option<OutputWord<'_>>) -> Hresult {
    match (value, output) {
        (Some(value), Some(output)) => {
            output.store(value);
            Hresult::SUCCESS
        }
        _ => Hresult::INVALID_ARGUMENT,
    }
}

/// Export result of a removal: the value goes through `output` when the
/// caller passed one.
fn removed(result: Result<u32, Error>, output: Option<OutputWord<'_>>) -> Hresult {
    match result {
        Ok(value) => {
            if let Some(output) = output {
                output.store(value);
            }
            Hresult::SUCCESS
        }
        Err(error) => error.remove_result(),
    }
}

/// Address of a console routine that takes up to four register arguments
/// and returns in r3: from a caller record, or one of this crate's. Caller
/// records hold one in caller-visible memory under the module invariants.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Routine(NonZeroU32);

impl Routine {
    /// The routine at `address`; nothing for 0.
    ///
    /// # Safety
    ///
    /// `address` is 0 or a console routine that takes up to four register
    /// arguments, as the export contract requires of caller routines.
    pub(crate) unsafe fn new(address: u32) -> Option<Self> {
        NonZeroU32::new(address).map(Self)
    }

    pub(crate) fn raw(self) -> u32 {
        self.0.get()
    }

    pub(crate) fn call(self, a0: u32, a1: u32, a2: u32, a3: u32) -> u32 {
        // SAFETY: a `Routine` is a console routine of up to four register
        // arguments (`Routine::new`, or a function of this crate).
        unsafe { kernel::call_export(self.0.get(), a0, a1, a2, a3) }
    }

    fn of_function(address: usize) -> Self {
        // SAFETY: function addresses are not zero.
        Self(unsafe { NonZeroU32::new_unchecked(address as u32) })
    }
}

impl From<extern "C" fn(u32, u32) -> u32> for Routine {
    fn from(function: extern "C" fn(u32, u32) -> u32) -> Self {
        Self::of_function(function as usize)
    }
}

impl From<extern "C" fn(u32, u32, u32) -> Hresult> for Routine {
    fn from(function: extern "C" fn(u32, u32, u32) -> Hresult) -> Self {
        Self::of_function(function as usize)
    }
}

impl From<extern "C" fn(u32, u32, u32, u32) -> NtStatus> for Routine {
    fn from(function: extern "C" fn(u32, u32, u32, u32) -> NtStatus) -> Self {
        Self::of_function(function as usize)
    }
}

/// Wait time in milliseconds as the caller gives it.
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Timeout(u32);

impl Timeout {
    /// Fail at once.
    pub(crate) const IMMEDIATE: Self = Self(0);
    /// Wait without limit.
    pub(crate) const INFINITE: Self = Self(u32::MAX);

    pub(crate) const fn from_raw(milliseconds: u32) -> Self {
        Self(milliseconds)
    }

    /// Relative interval in 100 ns units, or nothing for no limit.
    pub(crate) fn interval(self) -> Option<i64> {
        (self != Self::INFINITE).then(|| relative_interval(Duration::from_millis(self.0 as u64)))
    }
}

xbox360_sys::flags! {
    /// Flags of an options record. Stock tests no other bit: bits 0x1, 0x2
    /// and those above 0x100 have no known meaning, and a kept record
    /// keeps them as the caller passed them.
    pub struct OptionFlags(u32) {
        /// Insertions wait for free nodes; creation makes the free node
        /// semaphore when the node count is limited.
        INSERT_WAITS = 0x4,
        /// Removals wait for items; creation makes the item semaphore.
        REMOVE_WAITS = 0x8,
        /// Waiting insertions spin before they block.
        INSERT_SPIN = 0x10,
        /// Waiting removals spin before they block.
        REMOVE_SPIN = 0x20,
        /// Insertions block in alertable waits.
        INSERT_ALERTABLE = 0x40,
        /// Removals block in alertable waits.
        REMOVE_ALERTABLE = 0x80,
        /// Keys of a sorted container are unique.
        UNIQUE_KEYS = 0x100,
    }
}

impl OptionFlags {
    /// Flags that make a queue or stack keep its options record.
    const KEPT: Self = Self::INSERT_SPIN
        .union(Self::REMOVE_SPIN)
        .union(Self::INSERT_ALERTABLE)
        .union(Self::REMOVE_ALERTABLE)
        .union(Self::UNIQUE_KEYS);
}

/// Side of a container operation.
#[derive(Clone, Copy)]
enum Side {
    Insert,
    Remove,
}

/// Options record (caller record, 0x1c bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct OptionsRecord {
    pub(crate) flags: OptionFlags,
    pub(crate) insert_context: u32,
    pub(crate) remove_context: u32,
    pub(crate) insert_timeout: Timeout,
    pub(crate) remove_timeout: Timeout,
    /// `routine(context, object, timeout, alertable)` replacing the
    /// semaphore wait of insertions.
    pub(crate) insert_routine: Option<Routine>,
    pub(crate) remove_routine: Option<Routine>,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(OptionsRecord, insert_context) == 0x4);
    assert!(offset_of!(OptionsRecord, remove_timeout) == 0x10);
    assert!(offset_of!(OptionsRecord, insert_routine) == 0x14);
    assert!(size_of::<OptionsRecord>() == 0x1c);
};

impl OptionsRecord {
    /// Wait behavior of `side`; nothing unless the side may wait.
    fn wait(&self, side: Side) -> Option<Wait> {
        self.wait_with(self.flags, side)
    }

    /// [`OptionsRecord::wait`] with the flags word already read.
    fn wait_with(&self, flags: OptionFlags, side: Side) -> Option<Wait> {
        let (waits, spin, alertable, context, timeout, routine) = match side {
            Side::Insert => (
                OptionFlags::INSERT_WAITS,
                OptionFlags::INSERT_SPIN,
                OptionFlags::INSERT_ALERTABLE,
                &self.insert_context,
                &self.insert_timeout,
                &self.insert_routine,
            ),
            Side::Remove => (
                OptionFlags::REMOVE_WAITS,
                OptionFlags::REMOVE_SPIN,
                OptionFlags::REMOVE_ALERTABLE,
                &self.remove_context,
                &self.remove_timeout,
                &self.remove_routine,
            ),
        };
        flags.contains(waits).then(|| Wait {
            context: *context,
            routine: *routine,
            spin: flags.contains(spin),
            timeout: *timeout,
            alertable: flags.contains(alertable),
        })
    }

    /// Whether a queue or stack keeps the record: a kept flag or any wait
    /// field is set.
    fn is_kept(&self) -> bool {
        self.flags.intersects(OptionFlags::KEPT)
            || self.insert_context != 0
            || self.remove_context != 0
            || self.insert_timeout != Timeout::IMMEDIATE
            || self.remove_timeout != Timeout::IMMEDIATE
            || self.insert_routine.is_some()
            || self.remove_routine.is_some()
    }
}

/// Wait behavior of one operation, from the container options.
#[derive(Clone, Copy)]
struct Wait {
    context: u32,
    /// `routine(context, object, timeout, alertable)` replacing the
    /// semaphore wait.
    routine: Option<Routine>,
    spin: bool,
    timeout: Timeout,
    alertable: bool,
}

impl Wait {
    /// No spinning and no waiting.
    const NONE: Self = Self {
        context: 0,
        routine: None,
        spin: false,
        timeout: Timeout::IMMEDIATE,
        alertable: false,
    };

    fn block(&self, object: WaitObject<'_>) -> Result<(), Error> {
        match self.routine {
            Some(routine) => Error::of_wait(routine.call(
                self.context,
                object.raw(),
                self.timeout.0,
                u32::from(self.alertable),
            )),
            None if self.timeout == Timeout::IMMEDIATE => Err(Error::Timeout),
            None => object.wait(self.timeout, self.alertable),
        }
    }
}

/// Spin delay between attempts: `count + 1` low-priority pauses, the count
/// doubling plus one up to [`Backoff::MAX_COUNT`].
struct Backoff(u32);

impl Backoff {
    /// Attempts of a spinning operation before it blocks.
    const SPIN_ATTEMPTS: u32 = 1000;
    const MAX_COUNT: u32 = 1023;

    const fn new() -> Self {
        Self(0)
    }

    fn pause(&mut self) {
        for _ in 0..=self.0 {
            processor::low_priority_hint();
        }
        if self.0 <= Self::MAX_COUNT / 2 {
            self.0 = 2 * self.0 + 1;
        }
    }
}

/// Two words that stock reads and changes as one doubleword or one word at
/// a time: a list link (node address, change count), a sorted item (value,
/// key) or a lock state (holders, waiters).
#[repr(C, align(8))]
struct DoubleWord {
    high: AtomicU32,
    low: AtomicU32,
}

impl DoubleWord {
    fn as_ptr(&self) -> *mut u64 {
        ptr::from_ref(self).cast_mut().cast()
    }

    /// One doubleword load, no barrier.
    fn load(&self) -> Tagged {
        // SAFETY: `self` is 8 aligned bytes of atomics. Aligned word and
        // doubleword accesses are single-copy atomic on Xenon, so this access
        // and the word accesses stock mixes with it on the same bytes do not
        // tear.
        Tagged(unsafe { interlocked::load64(self.as_ptr()) })
    }

    /// One doubleword store, no barrier.
    fn store(&self, value: Tagged) {
        // SAFETY: as for `load`.
        unsafe { interlocked::store64(self.as_ptr(), value.0) }
    }

    /// Store `new` when the doubleword equals `expected`: a leading
    /// `lwsync`, no barrier after.
    fn compare_exchange(&self, expected: Tagged, new: Tagged) -> bool {
        // SAFETY: as for `load`.
        unsafe { interlocked::compare_exchange64(self.as_ptr(), expected.0, new.0) == expected.0 }
    }
}

/// Value of a [`DoubleWord`].
#[derive(Clone, Copy, PartialEq, Eq)]
struct Tagged(u64);

impl Tagged {
    /// Top bit of a link's low word: the node it links to is deleted.
    const DELETED: u32 = 0x8000_0000;

    const fn new(high: u32, low: u32) -> Self {
        Self(((high as u64) << 32) | low as u64)
    }

    const fn high(self) -> u32 {
        (self.0 >> 32) as u32
    }

    const fn low(self) -> u32 {
        self.0 as u32
    }

    /// The node a link names.
    fn address(self) -> Option<NodeAddress> {
        NodeAddress::new(self.high())
    }

    const fn is_deleted(self) -> bool {
        self.low() & Self::DELETED != 0
    }

    /// The link to `address` (0 for none) with the next change count; the
    /// deletion mark is clear.
    const fn successor(self, address: u32) -> Self {
        Self::new(address, self.low().wrapping_add(1) & !Self::DELETED)
    }
}

/// Word of a node by position; the byte offset is four times the number.
#[derive(Clone, Copy)]
enum NodeWord {
    /// Link of stack nodes, block trailers and lock records; next address
    /// of queue and sorted nodes.
    Word0 = 0,
    /// Value of a stack node.
    Word1 = 4,
    /// Value of a queue or sorted node, which also links it on the free
    /// list.
    Word2 = 8,
    /// Link of a wait entry.
    Word3 = 12,
}

/// Address of a node, block trailer, wait entry or lock record.
#[derive(Clone, Copy, PartialEq, Eq)]
struct NodeAddress(NonZeroU32);

impl NodeAddress {
    const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    /// # Safety
    ///
    /// `raw` is not 0.
    const unsafe fn new_unchecked(raw: u32) -> Self {
        // SAFETY: the caller guarantees a nonzero address.
        Self(unsafe { NonZeroU32::new_unchecked(raw) })
    }

    const fn raw(self) -> u32 {
        self.0.get()
    }

    /// The node at this address, for as long as `_owner` is borrowed.
    ///
    /// # Safety
    ///
    /// The address names a live `N` that stays allocated while `_owner` is
    /// borrowed: a node of the container `_owner` belongs to (module
    /// invariants), or a new allocation.
    #[inline(always)]
    unsafe fn get<'a, N, O: ?Sized>(self, _owner: &'a O) -> &'a N {
        // SAFETY: the caller guarantees the node.
        unsafe { &*ptr::with_exposed_provenance(self.0.get() as usize) }
    }

    /// Word `word` of the node at this address.
    ///
    /// # Safety
    ///
    /// The address names a live node of at least `word + 4` bytes that
    /// stays allocated for `'a`.
    #[inline(always)]
    unsafe fn word<'a>(self, word: NodeWord) -> &'a AtomicU32 {
        let address = self.0.get().wrapping_add(word as u32);
        // SAFETY: the caller guarantees the node.
        unsafe { &*ptr::with_exposed_provenance(address as usize) }
    }
}

/// Head of a tagged list.
#[repr(transparent)]
struct TaggedList(DoubleWord);

impl TaggedList {
    /// Link `node` in front through its word `link`.
    ///
    /// # Safety
    ///
    /// `node` names a live node of at least `link + 4` bytes that is not on
    /// a list.
    unsafe fn push(&self, node: NodeAddress, link: NodeWord) {
        // SAFETY: the caller guarantees the node.
        let word = unsafe { node.word(link) };
        loop {
            let head = self.0.load();
            word.store(head.high(), Relaxed);
            if self.0.compare_exchange(head, head.successor(node.raw())) {
                return;
            }
        }
    }

    /// Unlink the first node.
    ///
    /// # Safety
    ///
    /// Every node on the list is live, with its link at `link`, and stays
    /// allocated after it leaves the list (no node is freed before the
    /// container is destroyed).
    unsafe fn pop(&self, link: NodeWord) -> Option<NodeAddress> {
        loop {
            let head = self.0.load();
            let node = head.address()?;
            // SAFETY: the caller guarantees the nodes of the list.
            let next = unsafe { node.word(link) }.load(Relaxed);
            if self.0.compare_exchange(head, head.successor(next)) {
                return Some(node);
            }
        }
    }

    /// Address word of the head, one word load as stock reads it.
    fn first(&self) -> u32 {
        self.0.high.load(Relaxed)
    }
}

/// Container signature, read as a big-endian word.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Signature(u32);

impl Signature {
    const QUEUE: Self = Self(u32::from_be_bytes(*b"LfQu"));
    const STACK: Self = Self(u32::from_be_bytes(*b"LfSt"));
    const PRIORITY_QUEUE: Self = Self(u32::from_be_bytes(*b"LFPQ"));
    const HASH_TABLE: Self = Self(u32::from_be_bytes(*b"LFHT"));
    const POOL: Self = Self(u32::from_be_bytes(*b"LfPl"));

    fn is_in(self, word: &AtomicU32) -> bool {
        word.load(Relaxed) == self.0
    }

    /// Clear `word` and report whether it held this signature.
    fn take_from(self, word: &AtomicU32) -> bool {
        word.swap_relaxed(0) == self.0
    }
}

/// The container at `handle`, when its signature word at `offset` holds
/// `signature`.
///
/// # Safety
///
/// `handle` is 0 or the address of a container of this library (export
/// contract) whose word at `offset` is readable, and that is a `T` valid
/// for `'a` when the word holds `signature`.
unsafe fn container<'a, T>(handle: u32, signature: Signature, offset: usize) -> Option<&'a T> {
    let container = ptr::with_exposed_provenance::<T>(handle as usize);
    if container.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the word, and the type once it matches.
    unsafe {
        let word = &*container.byte_add(offset).cast::<AtomicU32>();
        signature.is_in(word).then(|| &*container)
    }
}

/// The container at `handle` with its signature cleared, when the
/// signature word at `offset` held `signature`.
///
/// # Safety
///
/// As for [`container`]; in addition no other operation uses the
/// container, now or later, and the caller does not use the reference
/// once it frees the container.
unsafe fn claim<'a, T>(handle: u32, signature: Signature, offset: usize) -> Option<&'a T> {
    let container = ptr::with_exposed_provenance::<T>(handle as usize);
    if container.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the word, and the type once it held the
    // signature.
    unsafe {
        let word = &*container.byte_add(offset).cast::<AtomicU32>();
        signature.take_from(word).then(|| &*container)
    }
}

/// How a container holds its semaphores. Stock waits on every handle with
/// the routine for kernel objects and releases some with it, which faults
/// on a handle; this code uses the handle services instead and keeps the
/// IRQL check of the kernel release.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SemaphoreKind {
    /// Address of a KSEMAPHORE inside the container.
    Object,
    /// Handle that stock releases with NtReleaseSemaphore.
    Handle,
    /// Handle that stock releases with KeReleaseSemaphore, which it skips
    /// above DISPATCH_LEVEL.
    GatedHandle,
}

/// A semaphore or event that operations block on.
#[derive(Clone, Copy)]
enum WaitObject<'a> {
    Object(&'a Ksemaphore),
    Handle(Handle),
    GatedHandle(Handle),
}

impl WaitObject<'_> {
    /// Count limit of every semaphore the library creates.
    const SEMAPHORE_LIMIT: u32 = 0x7fff_ffff;

    /// The word a caller wait routine receives.
    fn raw(self) -> u32 {
        match self {
            Self::Object(semaphore) => semaphore.as_ptr().expose_provenance() as u32,
            Self::Handle(handle) | Self::GatedHandle(handle) => handle.raw(),
        }
    }

    /// Release a semaphore by `count`.
    fn release(self, count: u32) {
        match self {
            Self::Object(semaphore) => {
                if processor::current_irql() <= Irql::DISPATCH {
                    // SAFETY: the semaphore is initialized and lies in a
                    // live queue.
                    unsafe { KeReleaseSemaphore(semaphore.as_ptr(), 1, count, false) };
                }
            }
            Self::Handle(handle) => release_semaphore(handle, count),
            Self::GatedHandle(handle) => {
                if processor::current_irql() <= Irql::DISPATCH {
                    release_semaphore(handle, count);
                }
            }
        }
    }

    fn wait(self, timeout: Timeout, alertable: bool) -> Result<(), Error> {
        let interval = timeout.interval();
        let pointer = interval.as_ref().map_or(ptr::null(), ptr::from_ref);
        Error::of_wait(match self {
            // SAFETY: the semaphore is initialized and lies in a live queue;
            // `pointer` is null or a live local.
            Self::Object(semaphore) => unsafe {
                xboxkrnl::KeWaitForSingleObject(
                    semaphore.as_ptr().cast::<DispatcherObject>(),
                    WaitReason::UserRequest,
                    ProcessorMode::Kernel,
                    alertable,
                    pointer,
                )
                .0
            },
            // SAFETY: the handle is a semaphore handle the container owns;
            // `pointer` is null or a live local.
            Self::Handle(handle) | Self::GatedHandle(handle) => unsafe {
                xboxkrnl::NtWaitForSingleObjectEx(handle, ProcessorMode::Kernel, alertable, pointer)
                    .0
            },
        })
    }
}

/// Unnamed semaphore at count 0. Records the outcome as the thread's last
/// error, as stock does.
fn create_semaphore() -> Option<Handle> {
    let mut handle = Handle::NULL;
    // SAFETY: `handle` is a live local; null attributes create an unnamed
    // semaphore.
    let status =
        unsafe { NtCreateSemaphore(&mut handle, ptr::null(), 0, WaitObject::SEMAPHORE_LIMIT) };
    if let Err(error) = status.result() {
        set_last_error(error);
        return None;
    }
    // Stock records ERROR_SUCCESS, the conversion of STATUS_SUCCESS.
    set_last_error_value(None);
    Some(handle)
}

/// Record a failed kernel call as the thread's last error.
fn record_failure(status: NtStatus) {
    if let Err(error) = status.result() {
        set_last_error(error);
    }
}

fn release_semaphore(handle: Handle, count: u32) {
    // SAFETY: callers pass a semaphore handle their container owns; a null
    // previous-count pointer is allowed.
    record_failure(unsafe { NtReleaseSemaphore(handle, count, ptr::null_mut()) });
}

fn close_handle(handle: Handle) {
    // SAFETY: callers pass a handle their container owns and close it once.
    record_failure(unsafe { xboxkrnl::NtClose(handle) });
}

/// Close the semaphore whose handle `word` holds, if any.
fn close_semaphore(word: &AtomicU32) {
    let handle = word.load(Relaxed);
    if handle != 0 {
        close_handle(Handle::from_raw(handle));
    }
}

fn set_event(handle: Handle) {
    // SAFETY: callers pass an event handle their pool owns; a null
    // previous-state pointer is allowed.
    record_failure(unsafe { xboxkrnl::NtSetEvent(handle, ptr::null_mut()) });
}

extern "C" fn default_allocate(_context: u32, size: u32) -> u32 {
    pool_allocate(size).map_or(0, NonZeroU32::get)
}

/// Tail-calls ExFreePool with `address`, as stock does, so its r3 passes
/// through.
#[unsafe(naked)]
extern "C" fn default_free(_context: u32, _address: u32) -> u32 {
    core::arch::naked_asm!("mr 3, 4", "b {free}", free = sym xboxkrnl::ExFreePool)
}

/// Allocator record (caller-visible, 0x10 bytes), copied after each
/// container.
#[repr(C)]
#[derive(Clone, Copy)]
struct AllocatorRecord {
    /// Alignment that the allocate routine guarantees.
    alignment: u32,
    context: u32,
    /// `allocate(context, size)`.
    allocate: Routine,
    /// `free(context, address)`.
    free: Routine,
}

const _: () = assert!(size_of::<AllocatorRecord>() == 0x10);

/// An allocation aligned inside the block the allocator returned.
struct Allocation {
    aligned: NonZeroU32,
    /// Address to free.
    base: u32,
}

impl AllocatorRecord {
    /// Alignment every stock allocator record states.
    const DEFAULT_ALIGNMENT: u32 = 16;
    const SIZE: u32 = size_of::<Self>() as u32;

    /// The routines stock uses when the caller supplies none.
    fn default_routines() -> Self {
        Self {
            alignment: Self::DEFAULT_ALIGNMENT,
            context: 0,
            allocate: Routine::from(default_allocate as extern "C" fn(u32, u32) -> u32),
            free: Routine::from(default_free as extern "C" fn(u32, u32) -> u32),
        }
    }

    /// The record at `address`.
    ///
    /// # Safety
    ///
    /// `address` is the allocator word of a live container, which holds the
    /// address of the record creation wrote after it; the record keeps the
    /// routines creation copied (module invariants).
    unsafe fn at<'a>(address: &'a AtomicU32) -> &'a Self {
        // SAFETY: the caller guarantees the record.
        unsafe { &*ptr::with_exposed_provenance(address.load(Relaxed) as usize) }
    }

    /// Allocate `size` bytes and add the request to `memory`.
    fn allocate(&self, size: u32, memory: &AtomicU32) -> Option<NonZeroU32> {
        if size as i32 <= 0 {
            return None;
        }
        let address = self.allocate.call(self.context, size, 0, 0);
        memory.fetch_add_relaxed(size);
        NonZeroU32::new(address)
    }

    fn free(&self, address: u32) {
        self.free.call(self.context, address, 0, 0);
    }

    /// Allocate `size` bytes aligned to the next power of two up to 64, or
    /// to 128 above that, unless the record guarantees that alignment.
    fn allocate_aligned(&self, size: u32, memory: &AtomicU32) -> Option<Allocation> {
        if size as i32 <= 0 {
            return None;
        }
        let mut alignment = 128;
        if size <= 64 {
            let mut half = 64;
            loop {
                alignment = half;
                half >>= 1;
                if size > half {
                    break;
                }
            }
        }
        if alignment <= self.alignment {
            alignment = 1;
        }
        let total = alignment.wrapping_add(size);
        if total as i32 <= 1 {
            return None;
        }
        let base = self.allocate(total - 1, memory)?.get();
        let aligned = base.wrapping_add(alignment.wrapping_sub(base) & (alignment - 1));
        Some(Allocation {
            aligned: NonZeroU32::new(aligned)?,
            base,
        })
    }

    /// Allocate a `size`-byte block followed by a trailer that links it on
    /// `blocks` and keeps the allocation base.
    ///
    /// # Safety
    ///
    /// `blocks` is the block list of a live container, which holds only
    /// block trailers.
    unsafe fn allocate_block(
        &self,
        blocks: &TaggedList,
        size: u32,
        memory: &AtomicU32,
    ) -> Option<NodeAddress> {
        let padded = size.wrapping_add(size_of::<BlockTrailer>() as u32);
        if size as i32 <= 0 || padded == 0 || (padded as i32) < size as i32 {
            return None;
        }
        let block = self.allocate_aligned(padded, memory)?;
        // SAFETY: the trailer is the 8 bytes after the block, inside the new
        // allocation.
        let trailer = unsafe { NodeAddress::new_unchecked(block.aligned.get().wrapping_add(size)) };
        // SAFETY: as above.
        unsafe { trailer.get::<BlockTrailer, _>(blocks) }
            .base
            .store(block.base, Relaxed);
        // SAFETY: as above; the caller guarantees the list, which links
        // trailers through word 0.
        unsafe { blocks.push(trailer, NodeWord::Word0) };
        Some(NodeAddress(block.aligned))
    }

    /// Free every block on `blocks`.
    ///
    /// # Safety
    ///
    /// `blocks` is the block list of a container, which holds only trailers
    /// of [`AllocatorRecord::allocate_block`] for blocks of this allocator,
    /// and no other operation uses the container.
    unsafe fn free_blocks(&self, blocks: &TaggedList) {
        // SAFETY: the caller guarantees the list; each trailer lies in its
        // block, which stays allocated until freed here.
        while let Some(trailer) = unsafe { blocks.pop(NodeWord::Word0) } {
            // SAFETY: as above.
            let base = unsafe { trailer.get::<BlockTrailer, _>(blocks) }
                .base
                .load(Relaxed);
            self.free(base);
        }
    }
}

/// Trailer after each node block.
#[repr(C)]
struct BlockTrailer {
    /// Link on the container's block list.
    link: AtomicU32,
    /// Allocation base of the block.
    base: AtomicU32,
}

/// Node of a queue, priority queue or hash table (0x10 bytes).
#[repr(C, align(8))]
struct ListNode {
    /// Link to the next node; a sorted list marks it once the node is
    /// deleted.
    next: DoubleWord,
    /// Value in the high word, which also links a free node; the key of a
    /// sorted node, or 0, in the low word.
    item: DoubleWord,
}

const _: () = assert!(core::mem::offset_of!(ListNode, item) == NodeWord::Word2 as usize);

/// Creation descriptor (caller record, 0x34 bytes) of the queue, stack,
/// priority queue and hash table.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct CreationDescriptor {
    pub(crate) options: OptionsRecord,
    /// [`CreationDescriptor::SIZE`].
    pub(crate) size: u32,
    pub(crate) per_block: u32,
    /// Node limit; zero or less is unlimited.
    pub(crate) node_limit: u32,
    /// Allocate routine; the free routine must come with it.
    pub(crate) allocate: Option<Routine>,
    pub(crate) free: Option<Routine>,
    /// Context of both routines.
    pub(crate) context: u32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(CreationDescriptor, size) == 0x1c);
    assert!(offset_of!(CreationDescriptor, per_block) == 0x20);
    assert!(offset_of!(CreationDescriptor, node_limit) == 0x24);
    assert!(offset_of!(CreationDescriptor, allocate) == 0x28);
    assert!(offset_of!(CreationDescriptor, context) == 0x30);
    assert!(size_of::<CreationDescriptor>() == 0x34);
};

impl CreationDescriptor {
    pub(crate) const SIZE: u32 = size_of::<Self>() as u32;
}

/// A validated creation descriptor.
pub(crate) struct Creation<'a> {
    /// The caller's descriptor; nothing when it passed none.
    descriptor: Option<&'a CreationDescriptor>,
    allocator: AllocatorRecord,
}

impl<'a> Creation<'a> {
    pub(crate) fn new(descriptor: Option<&'a CreationDescriptor>) -> Result<Self, Error> {
        let mut allocator = AllocatorRecord::default_routines();
        if let Some(descriptor) = descriptor {
            if descriptor.size != CreationDescriptor::SIZE {
                return Err(Error::InvalidArgument);
            }
            if let Some(allocate) = descriptor.allocate {
                let Some(free) = descriptor.free else {
                    return Err(Error::InvalidArgument);
                };
                allocator = AllocatorRecord {
                    alignment: AllocatorRecord::DEFAULT_ALIGNMENT,
                    context: descriptor.context,
                    allocate,
                    free,
                };
            }
        }
        Ok(Self {
            descriptor,
            allocator,
        })
    }

    /// The descriptor at `address`, or none for 0.
    ///
    /// # Safety
    ///
    /// `address` is 0 or the address of a creation descriptor (export
    /// contract) that stays unchanged for `'a`, whose routine fields hold
    /// console routines.
    unsafe fn read(address: u32) -> Result<Self, Error> {
        // SAFETY: the caller guarantees the record.
        Self::new(unsafe {
            ptr::with_exposed_provenance::<CreationDescriptor>(address as usize).as_ref()
        })
    }

    fn flags(&self) -> OptionFlags {
        self.descriptor
            .map_or(OptionFlags::empty(), |descriptor| descriptor.options.flags)
    }

    /// The options a queue or stack keeps, when any is set.
    fn kept_options(&self) -> Option<&'a OptionsRecord> {
        self.descriptor
            .map(|descriptor| &descriptor.options)
            .filter(|options| options.is_kept())
    }

    /// The options record of the descriptor, zero without one.
    fn options(&self) -> OptionsRecord {
        self.descriptor
            .map_or(OptionsRecord::default(), |descriptor| descriptor.options)
    }

    fn counts(&self, node_size: u32) -> NodeCounts {
        let (per_block, limit) = self.descriptor.map_or((0, 0), |descriptor| {
            (descriptor.per_block, descriptor.node_limit)
        });
        NodeCounts::new(per_block, limit, node_size)
    }

    /// Creation flag: removals wait, so creation makes the item semaphore.
    fn item_wait(&self) -> bool {
        self.flags().contains(OptionFlags::REMOVE_WAITS)
    }

    /// Creation flag: insertions wait, so a limited container makes the
    /// free node semaphore.
    fn free_wait(&self) -> bool {
        self.flags().contains(OptionFlags::INSERT_WAITS)
    }
}

/// Node counts of a creation.
struct NodeCounts {
    per_block: u32,
    /// Node limit; nothing when unlimited.
    limit: Option<u32>,
}

impl NodeCounts {
    const MIN_PER_BLOCK: i32 = 16;
    const MAX_PER_BLOCK: i32 = 0x100_0000;
    /// Bound on the bytes of the node limit, so that they stay a positive
    /// `i32`.
    const MAX_BYTES: u32 = i32::MAX as u32;

    /// Nodes per block clamped to 16..=0x100_0000.
    fn clamp_per_block(per_block: u32) -> u32 {
        (per_block as i32).clamp(Self::MIN_PER_BLOCK, Self::MAX_PER_BLOCK) as u32
    }

    /// The node limit stays below [`NodeCounts::MAX_BYTES`] / `node_size`;
    /// a limit of zero or less is unlimited.
    fn new(per_block: u32, limit: u32, node_size: u32) -> Self {
        let per_block = Self::clamp_per_block(per_block);
        let ceiling = (Self::MAX_BYTES / node_size) as i32;
        let limit = if limit as i32 >= ceiling {
            ceiling - 1
        } else {
            limit as i32
        };
        if limit <= 0 {
            return Self {
                per_block,
                limit: None,
            };
        }
        Self {
            per_block: per_block.min(limit as u32),
            limit: Some(limit as u32),
        }
    }
}

/// Nodes the limit still allows (caller-visible word).
#[repr(transparent)]
struct Remaining(AtomicU32);

impl Remaining {
    /// Stock encoding of an unlimited count; any negative value reads as
    /// unlimited.
    const UNLIMITED: u32 = u32::MAX;

    fn set(&self, limit: Option<u32>) {
        self.0.store(limit.unwrap_or(Self::UNLIMITED), Relaxed);
    }

    fn is_exhausted(&self) -> bool {
        self.0.load(Relaxed) == 0
    }

    /// End growth after a failed allocation.
    fn exhaust(&self) {
        self.0.store(0, Relaxed);
    }

    /// Claim up to `wanted` nodes; nothing once the limit is reached.
    fn claim(&self, wanted: u32) -> Option<u32> {
        let mut nodes = wanted;
        loop {
            let left = self.0.load(Relaxed);
            if (left as i32) < 0 {
                return Some(nodes);
            }
            if left == 0 {
                return None;
            }
            if nodes as i32 > left as i32 {
                nodes = left;
            }
            if self
                .0
                .compare_exchange_release(left, left.wrapping_sub(nodes))
                .is_ok()
            {
                return Some(nodes);
            }
        }
    }

    /// Claim up to `wanted` but at least `minimum` nodes.
    fn claim_at_least(&self, wanted: u32, minimum: u32) -> Option<u32> {
        let mut nodes = wanted;
        loop {
            let left = self.0.load(Relaxed);
            if (left as i32) < 0 {
                return Some(nodes);
            }
            if left == 0 {
                return None;
            }
            if nodes as i32 > left as i32 {
                nodes = left;
            }
            if (nodes as i32) < minimum as i32 {
                return None;
            }
            if self
                .0
                .compare_exchange_release(left, left.wrapping_sub(nodes))
                .is_ok()
            {
                return Some(nodes);
            }
        }
    }
}

/// Node supply and item accounting, the same run of fields in every node
/// container: +0x18 in a queue, +0x10 in a stack or hash table.
#[repr(C, align(8))]
struct Supply {
    /// Free node credits; below zero, insertions wait.
    credits: AtomicU32,
    /// Free node semaphore ([`SemaphoreKind`]); 0 when insertions do not
    /// wait.
    free_semaphore: AtomicU32,
    /// Removers blocked on the item semaphore.
    waiters: AtomicU32,
    /// Item semaphore and item count, in the order of [`ItemOrder`].
    items: [AtomicU32; 2],
    _reserved: AtomicU32,
    /// Node blocks, linked through their trailers.
    blocks: TaggedList,
    per_block: AtomicU32,
    remaining: Remaining,
    /// Nodes allocated.
    total: AtomicU32,
    /// Bytes requested from the allocator.
    memory: AtomicU32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(Supply, items) == 0xc);
    assert!(offset_of!(Supply, blocks) == 0x18);
    assert!(offset_of!(Supply, remaining) == 0x24);
    assert!(offset_of!(Supply, memory) == 0x2c);
    assert!(size_of::<Supply>() == 0x30);
};

/// Order of the item words of a [`Supply`].
#[derive(Clone, Copy)]
enum ItemOrder {
    /// Item semaphore, then item count (queue, stack).
    SemaphoreFirst,
    /// Item count, then item semaphore (hash table).
    CountFirst,
}

/// Node layout of a container type.
struct Layout {
    node_size: u32,
    /// Free list link of a node.
    link: NodeWord,
    semaphores: SemaphoreKind,
    items: ItemOrder,
}

mod nodes {
    use core::ptr;
    use core::sync::atomic::AtomicU32;
    use core::sync::atomic::Ordering::Relaxed;

    use xbox360_sys::xboxkrnl::Handle;

    use super::AllocatorRecord;
    use super::ItemOrder;
    use super::Layout;
    use super::NodeAddress;
    use super::SemaphoreKind;
    use super::Supply;
    use super::TaggedList;
    use super::WaitObject;

    /// The node supply of one container, for the routines every container
    /// layout shares. The fields are private to this module, so a `Nodes`
    /// always comes from [`Nodes::new`].
    #[derive(Clone, Copy)]
    pub(super) struct Nodes<'a> {
        /// Free nodes, at +0 of every container.
        free: &'a TaggedList,
        supply: &'a Supply,
        /// Allocator word of the container.
        allocator: &'a AtomicU32,
        layout: &'static Layout,
    }

    impl<'a> Nodes<'a> {
        /// # Safety
        ///
        /// `free`, `supply` and `allocator` are the free list, the supply
        /// fields and the allocator word of one container that creation set
        /// up, whose nodes have `layout`, and that stays allocated for `'a`.
        pub(super) const unsafe fn new(
            free: &'a TaggedList,
            supply: &'a Supply,
            allocator: &'a AtomicU32,
            layout: &'static Layout,
        ) -> Self {
            Self {
                free,
                supply,
                allocator,
                layout,
            }
        }

        pub(super) fn free(&self) -> &'a TaggedList {
            self.free
        }

        pub(super) fn supply(&self) -> &'a Supply {
            self.supply
        }

        pub(super) fn layout(&self) -> &'static Layout {
            self.layout
        }

        pub(super) fn allocator(&self) -> &'a AllocatorRecord {
            // SAFETY: the allocator word of the container (`Nodes::new`).
            unsafe { AllocatorRecord::at(self.allocator) }
        }

        fn wait_object(&self, word: &'a AtomicU32) -> Option<WaitObject<'a>> {
            let raw = word.load(Relaxed);
            if raw == 0 {
                return None;
            }
            Some(match self.layout.semaphores {
                // SAFETY: an object-kind container stores the address of its
                // own initialized KSEMAPHORE in its semaphore words.
                SemaphoreKind::Object => {
                    WaitObject::Object(unsafe { &*ptr::with_exposed_provenance(raw as usize) })
                }
                SemaphoreKind::Handle => WaitObject::Handle(Handle::from_raw(raw)),
                SemaphoreKind::GatedHandle => WaitObject::GatedHandle(Handle::from_raw(raw)),
            })
        }

        /// The item semaphore word and the item count.
        pub(super) fn item_words(&self) -> (&'a AtomicU32, &'a AtomicU32) {
            let [first, second] = &self.supply.items;
            match self.layout.items {
                ItemOrder::SemaphoreFirst => (first, second),
                ItemOrder::CountFirst => (second, first),
            }
        }

        pub(super) fn free_semaphore(&self) -> Option<WaitObject<'a>> {
            self.wait_object(&self.supply.free_semaphore)
        }

        pub(super) fn item_semaphore(&self) -> Option<WaitObject<'a>> {
            self.wait_object(self.item_words().0)
        }

        pub(super) fn pop_free(&self) -> Option<NodeAddress> {
            // SAFETY: the free list holds nodes of the container's blocks,
            // linked at the layout's link (module invariants).
            unsafe { self.free.pop(self.layout.link) }
        }

        /// # Safety
        ///
        /// `node` is a node of this container that no list holds.
        pub(super) unsafe fn push_free(&self, node: NodeAddress) {
            // SAFETY: the caller guarantees the node; nodes of the layout
            // hold its link word.
            unsafe { self.free.push(node, self.layout.link) };
        }

        /// Allocate a block of `size` bytes for nodes.
        pub(super) fn allocate_block(&self, size: u32) -> Option<NodeAddress> {
            // SAFETY: the block list of the container.
            unsafe {
                self.allocator()
                    .allocate_block(&self.supply.blocks, size, &self.supply.memory)
            }
        }
    }
}

use nodes::Nodes;

impl<'a> Nodes<'a> {
    fn count(&self) -> &'a AtomicU32 {
        self.item_words().1
    }

    fn count_added(&self) {
        self.count().fetch_add_relaxed(1);
    }

    fn count_removed(&self) {
        self.count().fetch_add_relaxed(1_u32.wrapping_neg());
    }

    /// Return a node to the free list and wake an insertion waiting for one.
    ///
    /// # Safety
    ///
    /// `node` is a node of this container that no list holds.
    unsafe fn release_node(&self, node: NodeAddress) {
        // SAFETY: the caller guarantees the node.
        unsafe { self.push_free(node) };
        if let Some(semaphore) = self.free_semaphore()
            && (self.supply().credits.fetch_add_relaxed(1) as i32).wrapping_add(1) <= 0
        {
            semaphore.release(1);
        }
    }

    /// Wake a remover blocked on the item semaphore.
    fn signal_item(&self) {
        if let Some(semaphore) = self.item_semaphore()
            && self.supply().waiters.load(Relaxed) as i32 > 0
        {
            semaphore.release(1);
        }
    }

    /// Take a block of nodes within the limit: all but the first go to the
    /// free list and the first is returned.
    fn grow(&self) -> Option<NodeAddress> {
        let supply = self.supply();
        let nodes = supply.remaining.claim(supply.per_block.load(Relaxed))?;
        self.populate(nodes)
    }

    /// Allocate `nodes` nodes, free all but the first and pass the new
    /// credits to waiting insertions; a failed allocation ends growth.
    fn populate(&self, nodes: u32) -> Option<NodeAddress> {
        let node_size = self.layout().node_size;
        let size = nodes.wrapping_mul(node_size);
        let Some(block) = self.allocate_block(size) else {
            self.supply().remaining.exhaust();
            return None;
        };
        self.supply().total.fetch_add_relaxed(nodes);
        let mut node = block.raw().wrapping_add(size);
        for _ in 1..nodes {
            node = node.wrapping_sub(node_size);
            // SAFETY: a node inside the new block, which holds `nodes` nodes.
            unsafe { self.push_free(NodeAddress::new_unchecked(node)) };
        }
        if let Some(semaphore) = self.free_semaphore() {
            let previous = self.supply().credits.fetch_add_relaxed(nodes) as i32;
            let spare = (nodes as i32).wrapping_sub(1);
            if previous < -1 && spare > 0 {
                semaphore.release((!previous).min(spare) as u32);
            }
        }
        Some(block)
    }

    /// Take a node for an insertion; with a node limit, wait per `wait`.
    fn acquire_node(&self, wait: &Wait) -> Result<NodeAddress, Error> {
        let Some(semaphore) = self.free_semaphore() else {
            if let Some(node) = self.pop_free() {
                return Ok(node);
            }
            if self.supply().remaining.is_exhausted() {
                return Err(Error::Timeout);
            }
            return self.grow().ok_or(Error::Timeout);
        };
        let credits = &self.supply().credits;
        let mut node = None;
        if (credits.fetch_add_relaxed(1_u32.wrapping_neg()) as i32).wrapping_sub(1) >= 0 {
            node = self.pop_free();
        }
        if node.is_none() && !self.supply().remaining.is_exhausted() {
            node = self.grow();
        }
        let mut backoff = Backoff::new();
        if wait.spin {
            for _ in 0..Backoff::SPIN_ATTEMPTS {
                if node.is_some() {
                    break;
                }
                backoff.pause();
                node = self.pop_free();
            }
        }
        loop {
            if let Some(node) = node {
                return Ok(node);
            }
            if wait.spin {
                backoff.pause();
            }
            if let Err(error) = wait.block(semaphore) {
                credits.fetch_add_relaxed(1);
                return Err(error);
            }
            node = self.pop_free();
        }
    }

    /// Run `attempt` until it yields an item: at once, then spinning when
    /// asked, then counted among the waiters and blocking on `semaphore`
    /// between attempts.
    fn remove_waiting<T>(
        &self,
        semaphore: WaitObject<'_>,
        wait: &Wait,
        mut attempt: impl FnMut() -> Option<T>,
    ) -> Result<T, Error> {
        if let Some(item) = attempt() {
            return Ok(item);
        }
        let mut backoff = Backoff::new();
        if wait.spin {
            for _ in 0..Backoff::SPIN_ATTEMPTS {
                backoff.pause();
                if let Some(item) = attempt() {
                    return Ok(item);
                }
            }
        }
        let waiters = &self.supply().waiters;
        waiters.fetch_add_relaxed(1);
        loop {
            if let Some(item) = attempt() {
                waiters.fetch_add_relaxed(1_u32.wrapping_neg());
                return Ok(item);
            }
            if wait.spin {
                backoff.pause();
            }
            if let Err(error) = wait.block(semaphore) {
                waiters.fetch_add_relaxed(1_u32.wrapping_neg());
                return Err(error);
            }
        }
    }
}

/// Call `callback(context, value, node)` for each node from `first`,
/// following the address word at +0, until a callback returns nonzero.
///
/// # Safety
///
/// Every node from `first` is a live node of a container borrowed for the
/// call, with its value at `value`.
unsafe fn walk(first: u32, value: NodeWord, context: u32, callback: Routine) -> Result<(), Error> {
    let mut node = NodeAddress::new(first);
    while let Some(address) = node {
        // SAFETY: the caller guarantees the nodes.
        let item = unsafe { address.word(value) }.load(Relaxed);
        let result = callback.call(context, item, address.raw(), 0);
        if let Some(result) = Win32Error::new(result) {
            return Err(Error::Callback(result));
        }
        // SAFETY: as above.
        node = NodeAddress::new(unsafe { address.word(NodeWord::Word0) }.load(Relaxed));
    }
    Ok(())
}

/// Pool allocation of the library; nothing when the pool has no memory.
pub(crate) fn pool_allocate(size: u32) -> Option<NonZeroU32> {
    // SAFETY: pool allocation of any size is valid; failure is null.
    NonZeroU32::new(unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(size, pool_tag::DETOUR, PoolType::Default)
    })
}

/// Free a block of [`pool_allocate`].
///
/// # Safety
///
/// `address` is a block of [`pool_allocate`] that is not used after.
pub(crate) unsafe fn pool_free(address: NonZeroU32) {
    // SAFETY: the caller guarantees the block.
    unsafe { xboxkrnl::ExFreePool(address.get()) }
}

extern "C" fn allocate(size: u32) -> u32 {
    pool_allocate(size).map_or(0, NonZeroU32::get)
}
export!(300, allocate);

crate::kernel::forward!(
    /// Stock tail-calls ExFreePool, so its r3 passes through.
    fn free(u32) -> u32 => xboxkrnl::ExFreePool
);
export!(301, free);
