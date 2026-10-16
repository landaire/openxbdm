//! Lock-free containers of stock exports 300-351: queue 'LfQu' (302-309),
//! stack 'LfSt' (310-317), priority queue 'LFPQ' (320-328), hash table
//! 'LFHT' (330-338) and lock pool 'LfPl' (340-351), with the pool memory
//! helpers 300 and 301.
//!
//! Lists link through tagged quadwords: the node address in the high word
//! and a 31-bit change count in the low word, whose top bit marks a deleted
//! node of a sorted list. Every interlocked sequence runs with external
//! interrupts disabled across the reservation, and every compare-exchange
//! follows an `lwsync`. Containers draw fixed-size nodes from a free list
//! that grows in batches from blocks of the creation allocator. Stock
//! duplicates the node routines for each container layout; [`Shape`]
//! carries the layout instead.
//!
//! Container memory is caller-visible and every address below comes from
//! the caller or from a container the caller passed, as in stock: the
//! validity of each access rests on the caller's contract with the export.

mod hash;
mod pool;
mod priority;
pub(crate) mod queue;
mod stack;

use core::num::NonZeroU32;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use xbox360::status::set_last_error;
use xbox360::status::set_last_error_value;
use xbox360_sys::interlocked::compare_exchange32;
use xbox360_sys::interlocked::compare_exchange64;
use xbox360_sys::interlocked::exchange32;
use xbox360_sys::interlocked::fetch_add32;
use xbox360_sys::interlocked::load64;
use xbox360_sys::interlocked::store64;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DispatcherObject;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::KeReleaseSemaphore;
use xbox360_sys::xboxkrnl::Ksemaphore;
use xbox360_sys::xboxkrnl::NtCreateSemaphore;
use xbox360_sys::xboxkrnl::NtReleaseSemaphore;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::WaitReason;

use crate::exports::export;
use crate::kernel;

/// Pool tag of library allocations.
const POOL_TAG: PoolTag = PoolTag::new(*b"Detr");
/// Successful export result.
const SUCCESS: Hresult = Hresult(0);
/// HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY): a creation or allocation
/// found no memory.
const CREATE_FAILED: Hresult = Hresult(0x8007_0008);
/// An insertion found no free node in time.
const INSERT_TIMEOUT: Hresult = Hresult(0x8031_0001);
/// A removal found no item in time.
const REMOVE_TIMEOUT: Hresult = Hresult(0x8031_0002);
/// Top bit of a tagged low word: the node it links to is deleted.
const MARK: u32 = 0x8000_0000;
/// Attempts of a spinning operation before it blocks.
const SPIN_ATTEMPTS: u32 = 1000;
/// Count limit of every semaphore the library creates.
const SEMAPHORE_LIMIT: u32 = 0x7fff_ffff;
/// Stock encoding of an unlimited node count.
const UNLIMITED: u32 = u32::MAX;
/// Highest IRQL at which a kernel semaphore is released.
const DISPATCH_LEVEL: u8 = 2;

fn load(address: usize) -> u32 {
    // SAFETY: see the module documentation.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

fn store(address: usize, value: u32) {
    // SAFETY: see the module documentation.
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}

fn fetch_add(address: usize, delta: u32) -> u32 {
    // SAFETY: see the module documentation.
    unsafe { fetch_add32(address as *mut u32, delta) }
}

fn fetch_sub(address: usize, delta: u32) -> u32 {
    fetch_add(address, delta.wrapping_neg())
}

fn compare_exchange(address: usize, expected: u32, new: u32) -> u32 {
    // SAFETY: see the module documentation.
    unsafe { compare_exchange32(address as *mut u32, expected, new) }
}

fn exchange(address: usize, value: u32) -> u32 {
    // SAFETY: see the module documentation.
    unsafe { exchange32(address as *mut u32, value) }
}

fn load_quad(address: usize) -> u64 {
    // SAFETY: see the module documentation.
    unsafe { load64(address as *const u64) }
}

fn store_quad(address: usize, value: u64) {
    // SAFETY: see the module documentation.
    unsafe { store64(address as *mut u64, value) }
}

/// Store `new` when the quadword at `address` equals `expected`.
fn swap_quad(address: usize, expected: u64, new: u64) -> bool {
    // SAFETY: see the module documentation.
    unsafe { compare_exchange64(address as *mut u64, expected, new) == expected }
}

fn copy(destination: usize, source: usize, length: usize) {
    // SAFETY: see the module documentation.
    unsafe { core::ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, length) }
}

fn zero(address: usize, length: usize) {
    // SAFETY: see the module documentation.
    unsafe { core::ptr::write_bytes(address as *mut u8, 0, length) }
}

fn lwsync() {
    // SAFETY: a memory barrier.
    unsafe { core::arch::asm!("lwsync", options(nostack, preserves_flags)) }
}

/// Current IRQL from the processor control region (r13 +0x18).
fn irql() -> u8 {
    let level: u8;
    // SAFETY: the console keeps r13 pointing at the processor control
    // region, which the compiler leaves alone under the SVR4 ABI.
    unsafe {
        core::arch::asm!("lbz {0}, 24(13)", out(reg) level, options(nostack, readonly, preserves_flags))
    };
    level
}

/// Call a caller-supplied console routine.
fn call(routine: u32, a0: u32, a1: u32, a2: u32, a3: u32) -> u32 {
    // SAFETY: the routine comes from the caller's descriptor, as in stock.
    unsafe { kernel::call_export(routine, a0, a1, a2, a3) }
}

/// A tagged list word: node address in the high word, change count in the
/// low word.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Tagged(u64);

impl Tagged {
    const fn new(address: u32, low: u32) -> Self {
        Self(((address as u64) << 32) | low as u64)
    }

    const fn address(self) -> u32 {
        (self.0 >> 32) as u32
    }

    const fn low(self) -> u32 {
        self.0 as u32
    }

    /// The word linking `address` with the next change count; the mark is
    /// clear.
    const fn successor(self, address: u32) -> Self {
        Self::new(address, self.low().wrapping_add(1) & !MARK)
    }
}

fn load_tagged(address: usize) -> Tagged {
    Tagged(load_quad(address))
}

fn swap_tagged(address: usize, expected: Tagged, new: Tagged) -> bool {
    swap_quad(address, expected.0, new.0)
}

/// Push `node` onto the tagged list at `list`, linking through `link`.
fn push(list: usize, node: u32, link: usize) {
    loop {
        let head = load_tagged(list);
        store(node as usize + link, head.address());
        if swap_tagged(list, head, head.successor(node)) {
            return;
        }
    }
}

/// Pop the first node of the tagged list at `list`.
fn pop(list: usize, link: usize) -> Option<u32> {
    loop {
        let head = load_tagged(list);
        let node = head.address();
        if node == 0 {
            return None;
        }
        if swap_tagged(list, head, head.successor(load(node as usize + link))) {
            return Some(node);
        }
    }
}

/// Spin delay between attempts: `count + 1` low-priority pauses, the count
/// doubling plus one up to 1023.
struct Backoff(u32);

impl Backoff {
    fn pause(&mut self) {
        for _ in 0..=self.0 {
            // SAFETY: `or 31, 31, 31` only lowers the hardware thread
            // priority.
            unsafe { core::arch::asm!("or 31, 31, 31", options(nomem, nostack, preserves_flags)) };
        }
        if self.0 <= 511 {
            self.0 = 2 * self.0 + 1;
        }
    }
}

const ERROR_NOT_ENOUGH_MEMORY: Win32Error = Win32Error::new(8).unwrap();
const ERROR_INVALID_PARAMETER: Win32Error = Win32Error::new(87).unwrap();
/// WAIT_TIMEOUT, equal to STATUS_TIMEOUT.
const WAIT_TIMEOUT: Win32Error = Win32Error::new(258).unwrap();

/// A failed container routine.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    NotEnoughMemory,
    InvalidParameter,
    /// No node or item in time, or a wait that timed out.
    Timeout,
    /// Another wait status or caller wait routine result.
    Wait(Win32Error),
    /// The first nonzero result of an enumeration callback.
    Callback(Win32Error),
}

impl Failure {
    /// Outcome of a wait or of a caller wait routine; stock treats both
    /// as Win32 codes.
    fn of_wait(status: u32) -> Result<(), Self> {
        match Win32Error::new(status) {
            None => Ok(()),
            Some(error) if error == WAIT_TIMEOUT => Err(Self::Timeout),
            Some(error) => Err(Self::Wait(error)),
        }
    }
}

/// HRESULT_FROM_WIN32 of the failure's code.
impl From<Failure> for Hresult {
    fn from(failure: Failure) -> Self {
        Self::from(match failure {
            Failure::NotEnoughMemory => ERROR_NOT_ENOUGH_MEMORY,
            Failure::InvalidParameter => ERROR_INVALID_PARAMETER,
            Failure::Timeout => WAIT_TIMEOUT,
            Failure::Wait(error) | Failure::Callback(error) => error,
        })
    }
}

/// A malformed caller record.
struct InvalidArgument;

impl From<InvalidArgument> for Hresult {
    fn from(_: InvalidArgument) -> Self {
        Self::INVALID_ARGUMENT
    }
}

/// Export result of an operation without a timeout result of its own.
fn export_result(result: Result<(), Failure>) -> u32 {
    match result {
        Ok(()) => SUCCESS.0,
        Err(failure) => Hresult::from(failure).0,
    }
}

fn insert_result(result: Result<(), Failure>) -> u32 {
    match result {
        Err(Failure::Timeout) => INSERT_TIMEOUT.0,
        result => export_result(result),
    }
}

fn remove_result(failure: Failure) -> u32 {
    match failure {
        Failure::Timeout => REMOVE_TIMEOUT.0,
        failure => Hresult::from(failure).0,
    }
}

/// Wait time in milliseconds as the caller gave it: 0 fails at once and
/// `u32::MAX` waits without limit.
#[derive(Clone, Copy)]
struct Timeout(u32);

impl Timeout {
    /// Relative interval in 100 ns units, or nothing for no limit.
    fn interval(self) -> Option<i64> {
        (self.0 != u32::MAX).then(|| -(i64::from(self.0) * 10_000))
    }
}

/// How a container holds its semaphores.
/// Stock waits on every handle with the routine for kernel objects and
/// releases some with it, which faults on a handle; this code uses the
/// handle services instead and keeps the IRQL check of the kernel release.
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
struct WaitObject {
    raw: u32,
    kind: SemaphoreKind,
}

impl WaitObject {
    fn handle(raw: u32) -> Self {
        Self {
            raw,
            kind: SemaphoreKind::Handle,
        }
    }

    /// Release a semaphore by `count`.
    fn release(self, count: u32) {
        match self.kind {
            SemaphoreKind::Object => {
                if irql() <= DISPATCH_LEVEL {
                    // SAFETY: an object-kind `raw` is the address of an
                    // initialized semaphore inside a live queue object.
                    unsafe {
                        KeReleaseSemaphore(self.raw as usize as *mut Ksemaphore, 1, count, false)
                    };
                }
            }
            SemaphoreKind::Handle => release_semaphore(self.raw, count),
            SemaphoreKind::GatedHandle => {
                if irql() <= DISPATCH_LEVEL {
                    release_semaphore(self.raw, count);
                }
            }
        }
    }

    fn wait(self, timeout: Timeout, alertable: bool) -> Result<(), Failure> {
        let interval = timeout.interval();
        let pointer = interval
            .as_ref()
            .map_or(core::ptr::null(), |value| value as *const i64);
        Failure::of_wait(match self.kind {
            // SAFETY: an object-kind `raw` is the address of an initialized
            // semaphore inside a live queue object; `pointer` is null or a
            // live local.
            SemaphoreKind::Object => unsafe {
                xboxkrnl::KeWaitForSingleObject(
                    self.raw as usize as *mut DispatcherObject,
                    WaitReason::UserRequest,
                    ProcessorMode::Kernel,
                    alertable,
                    pointer,
                )
                .0
            },
            // SAFETY: a handle-kind `raw` is a semaphore handle owned by the
            // queue; `pointer` is null or a live local.
            SemaphoreKind::Handle | SemaphoreKind::GatedHandle => unsafe {
                xboxkrnl::NtWaitForSingleObjectEx(
                    Handle::from_raw(self.raw),
                    ProcessorMode::Kernel,
                    alertable,
                    pointer,
                )
                .0
            },
        })
    }
}

/// Unnamed semaphore at count 0; failures set the thread's last error.
fn create_semaphore() -> u32 {
    let mut handle = Handle::NULL;
    // SAFETY: `handle` is a live local; null attributes create an unnamed
    // semaphore.
    if let Err(error) =
        unsafe { NtCreateSemaphore(&mut handle, core::ptr::null(), 0, SEMAPHORE_LIMIT) }.result()
    {
        set_last_error(error);
        return 0;
    }
    // Stock records ERROR_SUCCESS, the conversion of STATUS_SUCCESS.
    set_last_error_value(None);
    handle.raw()
}

/// Record a failed kernel call as the thread's last error.
fn record_failure(status: NtStatus) {
    if let Err(error) = status.result() {
        set_last_error(error);
    }
}

fn release_semaphore(handle: u32, count: u32) {
    // SAFETY: callers pass a semaphore handle owned by the queue; a null
    // previous-count pointer is allowed.
    record_failure(unsafe {
        NtReleaseSemaphore(Handle::from_raw(handle), count, core::ptr::null_mut())
    });
}

fn close_handle(handle: u32) {
    // SAFETY: callers pass a handle owned by the queue and close it once.
    record_failure(unsafe { xboxkrnl::NtClose(Handle::from_raw(handle)) });
}

fn set_event(handle: u32) {
    // SAFETY: callers pass an event handle owned by the queue; a null
    // previous-state pointer is allowed.
    record_failure(unsafe {
        xboxkrnl::NtSetEvent(Handle::from_raw(handle), core::ptr::null_mut())
    });
}

/// Wait behavior of one operation, from the container options.
#[derive(Clone, Copy)]
struct Wait {
    context: u32,
    /// `routine(context, object, timeout, alertable)` replacing the
    /// semaphore wait.
    routine: Option<NonZeroU32>,
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
        timeout: Timeout(0),
        alertable: false,
    };

    fn block(&self, object: WaitObject) -> Result<(), Failure> {
        match self.routine {
            Some(routine) => Failure::of_wait(call(
                routine.get(),
                self.context,
                object.raw,
                self.timeout.0,
                u32::from(self.alertable),
            )),
            None if self.timeout.0 == 0 => Err(Failure::Timeout),
            None => object.wait(self.timeout, self.alertable),
        }
    }
}

/// Side of a container operation; remove-side option bits are the
/// insert-side bits shifted left by one.
#[derive(Clone, Copy)]
enum Side {
    Insert = 0,
    Remove = 1,
}

/// Option flag: insertions wait for free nodes (creation makes the free
/// node semaphore). The remove-side flag waits for items.
const WAIT_FLAG: u32 = 0x4;
const SPIN_FLAG: u32 = 0x10;
const ALERTABLE_FLAG: u32 = 0x40;
/// Option flag of the sorted containers: keys are unique.
const UNIQUE_FLAG: u32 = 0x100;
/// Option bits that make a queue or stack keep its options.
const OPTION_BITS: u32 = 0x1f0;

/// Wait behavior of `side` from an options record (caller-visible, 0x1c
/// bytes): +0 flags, +4/+8 insert/remove wait context, +0xc/+0x10
/// timeouts, +0x14/+0x18 wait routines. Nothing unless the side may wait.
fn options_wait(options: usize, side: Side) -> Option<Wait> {
    options_wait_with(options, load(options), side)
}

/// [`options_wait`] with the flags word already read.
fn options_wait_with(options: usize, flags: u32, side: Side) -> Option<Wait> {
    let shift = side as u32;
    let word = 4 * side as usize;
    (flags & (WAIT_FLAG << shift) != 0).then(|| Wait {
        context: load(options + 4 + word),
        routine: NonZeroU32::new(load(options + 0x14 + word)),
        spin: flags & (SPIN_FLAG << shift) != 0,
        timeout: Timeout(load(options + 0xc + word)),
        alertable: flags & (ALERTABLE_FLAG << shift) != 0,
    })
}

/// Allocator record (caller-visible, 0x10 bytes): +0 alignment the routine
/// guarantees, +4 context, +8 allocate(context, size), +0xc free(context,
/// address).
#[derive(Clone, Copy)]
struct Allocator(usize);

const ALLOCATOR_SIZE: u32 = 0x10;
/// Alignment every stock allocator record states.
const ALLOCATOR_ALIGNMENT: u32 = 16;

extern "C" fn default_allocate(_context: u32, size: u32) -> u32 {
    // SAFETY: pool allocation of any size is valid; failure is null.
    unsafe { xboxkrnl::ExAllocatePoolTypeWithTag(size, POOL_TAG, PoolType::Default) }
}

/// Tail-calls ExFreePool with `address`, as stock does, so its r3 passes
/// through.
#[unsafe(naked)]
extern "C" fn default_free(_context: u32, _address: u32) -> u32 {
    core::arch::naked_asm!("mr 3, 4", "b {free}", free = sym xboxkrnl::ExFreePool)
}

/// Address of a two-argument routine for a caller-visible record.
fn routine(function: extern "C" fn(u32, u32) -> u32) -> u32 {
    function as usize as u32
}

/// Record of the routines stock uses when the caller supplies none.
fn default_record() -> [u32; 4] {
    [
        ALLOCATOR_ALIGNMENT,
        0,
        routine(default_allocate),
        routine(default_free),
    ]
}

impl Allocator {
    fn of(record: &[u32; 4]) -> Self {
        Self(record.as_ptr() as usize)
    }

    /// Allocate `size` bytes and add the request to the word at `counter`.
    fn allocate(self, size: u32, counter: usize) -> u32 {
        if size as i32 <= 0 {
            return 0;
        }
        let address = call(load(self.0 + 8), load(self.0 + 4), size, 0, 0);
        fetch_add(counter, size);
        address
    }

    fn free(self, address: u32) {
        call(load(self.0 + 0xc), load(self.0 + 4), address, 0, 0);
    }

    /// Allocate `size` bytes aligned to the next power of two up to 64, or
    /// to 128 above that, unless the record guarantees that alignment;
    /// returns the aligned address and the allocation base.
    fn allocate_aligned(self, size: u32, counter: usize) -> Option<(u32, u32)> {
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
        if alignment <= load(self.0) {
            alignment = 1;
        }
        let total = alignment.wrapping_add(size);
        if total as i32 <= 1 {
            return None;
        }
        let base = self.allocate(total - 1, counter);
        let aligned = base.wrapping_add(alignment.wrapping_sub(base) & (alignment - 1));
        (aligned != 0).then_some((aligned, base))
    }

    /// Allocate a `size`-byte block followed by an 8-byte trailer that
    /// links it on the tagged list `list` and keeps the allocation base.
    fn allocate_block(self, list: usize, size: u32, counter: usize) -> Option<u32> {
        let padded = size.wrapping_add(8);
        if size as i32 <= 0 || padded == 0 || (padded as i32) < size as i32 {
            return None;
        }
        let (block, base) = self.allocate_aligned(padded, counter)?;
        let trailer = block.wrapping_add(size);
        store(trailer as usize + 4, base);
        push(list, trailer, 0);
        Some(block)
    }

    fn free_blocks(self, list: usize) {
        while let Some(trailer) = pop(list, 0) {
            self.free(load(trailer as usize + 4));
        }
    }
}

/// Creation descriptor of the queue, stack, priority queue and hash table
/// (0x34 bytes): the options record, +0x1c size, +0x20 nodes per block,
/// +0x24 node limit, +0x28/+0x2c allocate/free routines, +0x30 their
/// context.
const DESCRIPTOR_SIZE: u32 = 0x34;
/// Bytes of the options record.
const OPTIONS_SIZE: u32 = 0x1c;

/// A validated creation descriptor, zero when the caller passed none.
struct Creation {
    descriptor: usize,
    flags: u32,
    initial: u32,
    limit: u32,
    allocator: [u32; 4],
}

impl Creation {
    fn read(descriptor: u32) -> Result<Self, InvalidArgument> {
        let descriptor = descriptor as usize;
        let mut creation = Self {
            descriptor,
            flags: 0,
            initial: 0,
            limit: 0,
            allocator: default_record(),
        };
        if descriptor == 0 {
            return Ok(creation);
        }
        if load(descriptor + 0x1c) != DESCRIPTOR_SIZE {
            return Err(InvalidArgument);
        }
        let allocate = load(descriptor + 0x28);
        if allocate != 0 {
            let free = load(descriptor + 0x2c);
            if free == 0 {
                return Err(InvalidArgument);
            }
            creation.allocator = [ALLOCATOR_ALIGNMENT, load(descriptor + 0x30), allocate, free];
        }
        creation.flags = load(descriptor);
        creation.initial = load(descriptor + 0x20);
        creation.limit = load(descriptor + 0x24);
        Ok(creation)
    }

    /// Whether a queue or stack keeps its options: any option bit or wait
    /// field is set.
    fn keeps_options(&self) -> bool {
        self.descriptor != 0
            && (self.flags & OPTION_BITS != 0
                || (4..OPTIONS_SIZE as usize)
                    .step_by(4)
                    .any(|offset| load(self.descriptor + offset) != 0))
    }

    fn item_wait(&self) -> bool {
        self.flags & (WAIT_FLAG << Side::Remove as u32) != 0
    }

    fn free_wait(&self) -> bool {
        self.flags & WAIT_FLAG != 0
    }
}

/// Clamp the nodes per block to 16..=0x100_0000 and the node limit below
/// 0x7fff_ffff / `node_size`; a limit of zero or less is unlimited.
fn counts(initial: u32, limit: u32, node_size: u32) -> (u32, Option<u32>) {
    let initial = (initial as i32).clamp(16, 0x100_0000);
    let ceiling = (0x7fff_ffff / node_size) as i32;
    let limit = if limit as i32 >= ceiling {
        ceiling - 1
    } else {
        limit as i32
    };
    if limit <= 0 {
        return (initial as u32, None);
    }
    (initial.min(limit) as u32, Some(limit as u32))
}

/// Field offsets of a container. The free node list is at +0.
struct Shape {
    signature: u32,
    tag: u8,
    /// Free node credits; below zero, insertions wait.
    credits: u8,
    free_semaphore: u8,
    /// Removers blocked on the item semaphore.
    waiters: u8,
    item_semaphore: u8,
    count: u8,
    /// Tagged list of node blocks.
    blocks: u8,
    /// Nodes per block.
    grow: u8,
    /// Nodes the limit still allows; negative when unlimited.
    remaining: u8,
    total: u8,
    /// Bytes requested from the allocator.
    memory: u8,
    allocator: u8,
    options: u8,
    node_size: u8,
    /// Free list link within a node.
    link: u8,
    semaphores: SemaphoreKind,
}

#[derive(Clone, Copy)]
struct Object {
    base: usize,
    shape: &'static Shape,
}

impl Object {
    fn validate(address: u32, shape: &'static Shape) -> Option<Self> {
        let base = address as usize;
        (base != 0 && load(base + usize::from(shape.tag)) == shape.signature)
            .then_some(Self { base, shape })
    }

    fn field(self, offset: u8) -> usize {
        self.base + usize::from(offset)
    }

    fn wait_object(self, offset: u8) -> Option<WaitObject> {
        let raw = load(self.field(offset));
        (raw != 0).then_some(WaitObject {
            raw,
            kind: self.shape.semaphores,
        })
    }

    fn free_semaphore(self) -> Option<WaitObject> {
        self.wait_object(self.shape.free_semaphore)
    }

    fn item_semaphore(self) -> Option<WaitObject> {
        self.wait_object(self.shape.item_semaphore)
    }

    fn allocator(self) -> Allocator {
        Allocator(load(self.field(self.shape.allocator)) as usize)
    }

    fn options(self) -> usize {
        load(self.field(self.shape.options)) as usize
    }

    fn count_added(self) {
        fetch_add(self.field(self.shape.count), 1);
    }

    fn count_removed(self) {
        fetch_sub(self.field(self.shape.count), 1);
    }

    fn pop_node(self) -> Option<u32> {
        pop(self.base, usize::from(self.shape.link))
    }

    fn push_node(self, node: u32) {
        push(self.base, node, usize::from(self.shape.link));
    }

    /// Return a node to the free list and wake an insertion waiting for one.
    fn release_node(self, node: u32) {
        self.push_node(node);
        if let Some(semaphore) = self.free_semaphore()
            && (fetch_add(self.field(self.shape.credits), 1) as i32).wrapping_add(1) <= 0
        {
            semaphore.release(1);
        }
    }

    /// Wake a remover blocked on the item semaphore.
    fn signal_item(self) {
        if let Some(semaphore) = self.item_semaphore()
            && load(self.field(self.shape.waiters)) as i32 > 0
        {
            semaphore.release(1);
        }
    }

    /// Take a block of nodes within the limit: all but the first go to the
    /// free list and the first is returned.
    fn grow(self) -> Option<u32> {
        let remaining = self.field(self.shape.remaining);
        let mut nodes = load(self.field(self.shape.grow));
        loop {
            let left = load(remaining);
            if (left as i32) < 0 {
                break;
            }
            if left == 0 {
                return None;
            }
            if nodes as i32 > left as i32 {
                nodes = left;
            }
            if compare_exchange(remaining, left, left.wrapping_sub(nodes)) == left {
                break;
            }
        }
        self.populate(nodes)
    }

    /// Allocate `nodes` nodes, free all but the first and pass the new
    /// credits to waiting insertions; a failed allocation ends growth.
    fn populate(self, nodes: u32) -> Option<u32> {
        let shape = self.shape;
        let node_size = u32::from(shape.node_size);
        let size = nodes.wrapping_mul(node_size);
        let Some(block) = self.allocator().allocate_block(
            self.field(shape.blocks),
            size,
            self.field(shape.memory),
        ) else {
            store(self.field(shape.remaining), 0);
            return None;
        };
        fetch_add(self.field(shape.total), nodes);
        let mut node = block.wrapping_add(size);
        for _ in 1..nodes {
            node = node.wrapping_sub(node_size);
            self.push_node(node);
        }
        if let Some(semaphore) = self.free_semaphore() {
            let previous = fetch_add(self.field(shape.credits), nodes) as i32;
            let spare = (nodes as i32).wrapping_sub(1);
            if previous < -1 && spare > 0 {
                semaphore.release((!previous).min(spare) as u32);
            }
        }
        Some(block)
    }

    /// Take a node for an insertion; with a node limit, wait per `wait`.
    fn acquire_node(self, wait: &Wait) -> Result<u32, Failure> {
        let shape = self.shape;
        let Some(semaphore) = self.free_semaphore() else {
            if let Some(node) = self.pop_node() {
                return Ok(node);
            }
            if load(self.field(shape.remaining)) == 0 {
                return Err(Failure::Timeout);
            }
            return self.grow().ok_or(Failure::Timeout);
        };
        let credits = self.field(shape.credits);
        let mut node = None;
        if (fetch_sub(credits, 1) as i32).wrapping_sub(1) >= 0 {
            node = self.pop_node();
        }
        if node.is_none() && load(self.field(shape.remaining)) != 0 {
            node = self.grow();
        }
        let mut backoff = Backoff(0);
        if wait.spin {
            for _ in 0..SPIN_ATTEMPTS {
                if node.is_some() {
                    break;
                }
                backoff.pause();
                node = self.pop_node();
            }
        }
        loop {
            if let Some(node) = node {
                return Ok(node);
            }
            if wait.spin {
                backoff.pause();
            }
            if let Err(failure) = wait.block(semaphore) {
                fetch_add(credits, 1);
                return Err(failure);
            }
            node = self.pop_node();
        }
    }

    /// Free the node blocks, then the allocations at `bases`.
    fn free_storage(self, bases: &[u8]) {
        let allocator = self.allocator();
        allocator.free_blocks(self.field(self.shape.blocks));
        for &base in bases {
            allocator.free(load(self.field(base)));
        }
        lwsync();
    }
}

/// Run `attempt` until it yields an item: at once, then spinning when
/// asked, then counted among the waiters and blocking on `semaphore`
/// between attempts.
fn remove_waiting<T>(
    object: Object,
    semaphore: WaitObject,
    wait: &Wait,
    mut attempt: impl FnMut() -> Option<T>,
) -> Result<T, Failure> {
    if let Some(item) = attempt() {
        return Ok(item);
    }
    let mut backoff = Backoff(0);
    if wait.spin {
        for _ in 0..SPIN_ATTEMPTS {
            backoff.pause();
            if let Some(item) = attempt() {
                return Ok(item);
            }
        }
    }
    let waiters = object.field(object.shape.waiters);
    fetch_add(waiters, 1);
    loop {
        if let Some(item) = attempt() {
            fetch_sub(waiters, 1);
            return Ok(item);
        }
        if wait.spin {
            backoff.pause();
        }
        if let Err(failure) = wait.block(semaphore) {
            fetch_sub(waiters, 1);
            return Err(failure);
        }
    }
}

/// Call `callback(context, value, node)` for each node from `first`,
/// following the link at +0, until a callback returns nonzero.
fn walk(first: u32, value: usize, context: u32, callback: u32) -> Result<(), Failure> {
    let mut node = first;
    while node != 0 {
        let result = call(callback, context, load(node as usize + value), node, 0);
        if let Some(result) = Win32Error::new(result) {
            return Err(Failure::Callback(result));
        }
        node = load(node as usize);
    }
    Ok(())
}

/// Store a word of a validated container through `output`.
fn read_field(object: u32, shape: &'static Shape, offset: u8, output: u32) -> u32 {
    match Object::validate(object, shape) {
        Some(object) if output != 0 => {
            store(output as usize, load(object.field(offset)));
            SUCCESS.0
        }
        _ => Hresult::INVALID_ARGUMENT.0,
    }
}

pub(crate) extern "C" fn allocate(size: u32) -> u32 {
    // SAFETY: pool allocation of any size is valid; failure is null.
    unsafe { xboxkrnl::ExAllocatePoolTypeWithTag(size, POOL_TAG, PoolType::Default) }
}
export!(300, allocate);

crate::kernel::forward!(
    /// Stock tail-calls ExFreePool, so its r3 passes through.
    pub(crate) fn free(u32) -> u32 => xboxkrnl::ExFreePool
);
export!(301, free);
