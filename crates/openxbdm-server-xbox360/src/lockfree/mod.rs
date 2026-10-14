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

use crate::exports::export;
use crate::kernel;
use crate::kernel::LIB_KERNEL;
use crate::kernel::import_thunk;

import_thunk!(
    KeInitializeSemaphore(semaphore: u32, count: u32, limit: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x74
);
import_thunk!(
    KeReleaseSemaphore(semaphore: u32, increment: u32, adjustment: u32, wait: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x88
);
import_thunk!(
    NtCreateSemaphore(handle: *mut u32, attributes: u32, count: u32, limit: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xd5
);
import_thunk!(
    NtReleaseSemaphore(handle: u32, count: u32, previous: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xf3
);

/// Pool tag of library allocations.
const POOL_TAG: u32 = u32::from_be_bytes(*b"Detr");
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
/// Wait reason and processor mode of every library wait.
const USER_REQUEST: u32 = 3;
const KERNEL_MODE: u32 = 0;

/// Compare the quadword at `target` with `expected` and store `new` on a
/// match; returns the observed quadword. A mismatch stores the observed
/// value back to end the reservation, as stock does.
#[unsafe(naked)]
unsafe extern "C" fn compare_exchange64(target: usize, expected: u64, new: u64) -> u64 {
    core::arch::naked_asm!(
        "lwsync",
        // rldimi 6, 5, 32, 0 and rldimi 8, 7, 32, 0: join the word pairs.
        ".long 0x78a6000e",
        ".long 0x78e8000e",
        "1:",
        "mfmsr 9",
        // mtmsrd 13, 1: r13 holds the processor control region address,
        // whose external interrupt enable bit is clear.
        ".long 0x7da10164",
        // ldarx 10, 0, 3
        ".long 0x7d4018a8",
        // cmpd 10, 6
        ".long 0x7c2a3000",
        "bne 2f",
        // stdcx. 8, 0, 3
        ".long 0x7d0019ad",
        // mtmsrd 9, 1
        ".long 0x7d210164",
        "bne 1b",
        "b 3f",
        "2:",
        // stdcx. 10, 0, 3
        ".long 0x7d4019ad",
        ".long 0x7d210164",
        "3:",
        // rldicl 3, 10, 32, 32: the high word into r3.
        ".long 0x79430022",
        "mr 4, 10",
        "blr",
    )
}

/// Compare the word at `target` with `expected` and store `new` on a
/// match; returns the observed word.
#[unsafe(naked)]
unsafe extern "C" fn compare_exchange32(target: usize, expected: u32, new: u32) -> u32 {
    core::arch::naked_asm!(
        "lwsync",
        "1:",
        "mfmsr 9",
        ".long 0x7da10164",
        "lwarx 10, 0, 3",
        "cmpw 10, 4",
        "bne 2f",
        "stwcx. 5, 0, 3",
        ".long 0x7d210164",
        "bne 1b",
        "b 3f",
        "2:",
        "stwcx. 10, 0, 3",
        ".long 0x7d210164",
        "3:",
        "mr 3, 10",
        "blr",
    )
}

/// Add `delta` to the word at `target`; returns the previous value.
#[unsafe(naked)]
unsafe extern "C" fn fetch_add32(target: usize, delta: u32) -> u32 {
    core::arch::naked_asm!(
        "1:",
        "mfmsr 9",
        ".long 0x7da10164",
        "lwarx 10, 0, 3",
        "add 11, 10, 4",
        "stwcx. 11, 0, 3",
        ".long 0x7d210164",
        "bne 1b",
        "mr 3, 10",
        "blr",
    )
}

/// Store `value` at `target`; returns the previous value.
#[unsafe(naked)]
unsafe extern "C" fn exchange32(target: usize, value: u32) -> u32 {
    core::arch::naked_asm!(
        "1:",
        "mfmsr 9",
        ".long 0x7da10164",
        "lwarx 10, 0, 3",
        "stwcx. 4, 0, 3",
        ".long 0x7d210164",
        "bne 1b",
        "mr 3, 10",
        "blr",
    )
}

/// Load the quadword at `address` in one access.
#[unsafe(naked)]
unsafe extern "C" fn load64(address: usize) -> u64 {
    core::arch::naked_asm!(
        // ld 4, 0(3)
        ".long 0xe8830000",
        // rldicl 3, 4, 32, 32
        ".long 0x78830022",
        "blr",
    )
}

/// Store `value` at `address` in one access.
#[unsafe(naked)]
unsafe extern "C" fn store64(address: usize, value: u64) {
    core::arch::naked_asm!(
        // rldimi 6, 5, 32, 0
        ".long 0x78a6000e",
        // std 6, 0(3)
        ".long 0xf8c30000",
        "blr",
    )
}

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
    unsafe { fetch_add32(address, delta) }
}

fn fetch_sub(address: usize, delta: u32) -> u32 {
    fetch_add(address, delta.wrapping_neg())
}

fn compare_exchange(address: usize, expected: u32, new: u32) -> u32 {
    // SAFETY: see the module documentation.
    unsafe { compare_exchange32(address, expected, new) }
}

fn exchange(address: usize, value: u32) -> u32 {
    // SAFETY: see the module documentation.
    unsafe { exchange32(address, value) }
}

fn load_quad(address: usize) -> u64 {
    // SAFETY: see the module documentation.
    unsafe { load64(address) }
}

fn store_quad(address: usize, value: u64) {
    // SAFETY: see the module documentation.
    unsafe { store64(address, value) }
}

/// Store `new` when the quadword at `address` equals `expected`.
fn swap_quad(address: usize, expected: u64, new: u64) -> bool {
    // SAFETY: see the module documentation.
    unsafe { compare_exchange64(address, expected, new) == expected }
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

/// Status of an internal routine: 0, a Win32 error, a wait status or a
/// result of a caller wait routine.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Status(u32);

impl Status {
    const SUCCESS: Self = Self(0);
    const NOT_ENOUGH_MEMORY: Self = Self(8);
    const INVALID_PARAMETER: Self = Self(87);
    const TIMEOUT: Self = Self(258);
}

/// HRESULT_FROM_WIN32 for positive codes; other values pass through.
const fn win32_result(code: u32) -> Hresult {
    if code as i32 > 0 {
        Hresult(0x8007_0000 | (code & 0xffff))
    } else {
        Hresult(code)
    }
}

fn insert_result(status: Status) -> u32 {
    match status {
        Status::SUCCESS => SUCCESS.0,
        Status::TIMEOUT => INSERT_TIMEOUT.0,
        Status(code) => win32_result(code).0,
    }
}

fn remove_result(status: Status) -> u32 {
    match status {
        Status::SUCCESS => SUCCESS.0,
        Status::TIMEOUT => REMOVE_TIMEOUT.0,
        Status(code) => win32_result(code).0,
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
                    KeReleaseSemaphore(self.raw, 1, count, 0);
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

    fn wait(self, timeout: Timeout, alertable: bool) -> Status {
        let interval = timeout.interval();
        let pointer = interval
            .as_ref()
            .map_or(core::ptr::null(), |value| value as *const i64);
        Status(match self.kind {
            SemaphoreKind::Object => kernel::KeWaitForSingleObject(
                self.raw as usize as *mut u32,
                USER_REQUEST,
                KERNEL_MODE,
                u32::from(alertable),
                pointer,
            ),
            SemaphoreKind::Handle | SemaphoreKind::GatedHandle => kernel::NtWaitForSingleObjectEx(
                self.raw,
                KERNEL_MODE,
                u32::from(alertable),
                pointer,
            ),
        })
    }
}

/// Unnamed semaphore at count 0; failures set the thread's last error.
fn create_semaphore() -> u32 {
    let mut handle = 0;
    let status = NtCreateSemaphore(&mut handle, 0, 0, SEMAPHORE_LIMIT);
    if (status as i32) < 0 {
        kernel::set_last_error(status);
        return 0;
    }
    // Stock records ERROR_SUCCESS, the conversion of STATUS_SUCCESS.
    kernel::set_last_error(0);
    handle
}

fn release_semaphore(handle: u32, count: u32) {
    let status = NtReleaseSemaphore(handle, count, 0);
    if (status as i32) < 0 {
        kernel::set_last_error(status);
    }
}

fn close_handle(handle: u32) {
    let status = kernel::NtClose(handle);
    if (status as i32) < 0 {
        kernel::set_last_error(status);
    }
}

fn set_event(handle: u32) {
    let status = kernel::NtSetEvent(handle, core::ptr::null_mut());
    if (status as i32) < 0 {
        kernel::set_last_error(status);
    }
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

    fn block(&self, object: WaitObject) -> Status {
        match self.routine {
            Some(routine) => Status(call(
                routine.get(),
                self.context,
                object.raw,
                self.timeout.0,
                u32::from(self.alertable),
            )),
            None if self.timeout.0 == 0 => Status::TIMEOUT,
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
    kernel::ExAllocatePoolTypeWithTag(size, POOL_TAG, 0)
}

extern "C" fn default_free(_context: u32, address: u32) -> u32 {
    kernel::ExFreePool(address)
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
    fn read(descriptor: u32) -> Result<Self, Hresult> {
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
            return Err(Hresult::INVALID_ARGUMENT);
        }
        let allocate = load(descriptor + 0x28);
        if allocate != 0 {
            let free = load(descriptor + 0x2c);
            if free == 0 {
                return Err(Hresult::INVALID_ARGUMENT);
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
    fn acquire_node(self, wait: &Wait) -> Result<u32, Status> {
        let shape = self.shape;
        let Some(semaphore) = self.free_semaphore() else {
            if let Some(node) = self.pop_node() {
                return Ok(node);
            }
            if load(self.field(shape.remaining)) == 0 {
                return Err(Status::TIMEOUT);
            }
            return self.grow().ok_or(Status::TIMEOUT);
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
            let status = wait.block(semaphore);
            if status != Status::SUCCESS {
                fetch_add(credits, 1);
                return Err(status);
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
) -> Result<T, Status> {
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
        let status = wait.block(semaphore);
        if status != Status::SUCCESS {
            fetch_sub(waiters, 1);
            return Err(status);
        }
    }
}

/// Call `callback(context, value, node)` for each node from `first`,
/// following the link at +0, until a callback returns nonzero.
fn walk(first: u32, value: usize, context: u32, callback: u32) -> u32 {
    let mut node = first;
    while node != 0 {
        let result = call(callback, context, load(node as usize + value), node, 0);
        if result != 0 {
            return result;
        }
        node = load(node as usize);
    }
    0
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
    kernel::ExAllocatePoolTypeWithTag(size, POOL_TAG, 0)
}
export!(300, allocate);

/// Stock tail-calls ExFreePool, so its result passes through.
pub(crate) extern "C" fn free(address: u32) -> u32 {
    kernel::ExFreePool(address)
}
export!(301, free);
