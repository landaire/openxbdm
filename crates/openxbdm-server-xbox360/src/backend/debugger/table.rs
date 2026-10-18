//! The breakpoint table under its lock, shared by the server thread, the
//! breakpoint exports, and threads dispatched in place.

use core::cell::UnsafeCell;

use openxbdm_server::commands::debugger::BreakpointState;
use openxbdm_server::commands::debugger::CodeWords;
use openxbdm_server::commands::debugger::SetError;
use openxbdm_server::commands::debugger::SpareBlock;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;

use super::memory;
use crate::kernel::CriticalSection;

/// The level stock raises to before taking the table lock (0x91f25480,
/// 0x91f26fc8): no interrupt reaches the processor while it is held.
const TABLE_IRQL: Irql = Irql::new(0x7c);

/// Stock spin lock 0x91fae9c0 with the state it guards.
struct Table {
    lock: KspinLock,
    state: UnsafeCell<BreakpointState>,
}

// SAFETY: `state` is reached only by `with_breakpoints`, which holds `lock`.
unsafe impl Sync for Table {}

static TABLE: Table = Table {
    lock: KspinLock::new(),
    state: UnsafeCell::new(BreakpointState::new()),
};

/// Serializes sets, which allocate the spare outside the spin lock (stock
/// critical section 0x91fae960).
static SET_SECTION: CriticalSection = CriticalSection::new();

/// Code memory written through debugger mappings.
struct KernelCode;

impl CodeWords for KernelCode {
    fn replace_code_word(&mut self, address: u32, value: u32) -> Option<u32> {
        memory::replace_code_word(address, value)
    }
}

/// Prepare the set lock; called once before the exports and the server run.
pub(super) fn initialize() {
    SET_SECTION.initialize();
}

/// Run `access` on the breakpoint state with the table lock held at IRQL
/// 0x7c. `access` must not allocate or wait. A thread that takes a debug
/// exception while it holds the lock does not get it again, as in stock.
pub(super) fn with_breakpoints<R>(
    access: impl FnOnce(&mut BreakpointState, &mut dyn CodeWords) -> R,
) -> R {
    // SAFETY: the IRQL is lowered back below, after the lock is released.
    let irql = unsafe { xboxkrnl::KfRaiseIrql(TABLE_IRQL) };
    // SAFETY: the lock is a static spin lock taken at raised IRQL and
    // released below.
    unsafe { xboxkrnl::KeAcquireSpinLockAtRaisedIrql(TABLE.lock.as_ptr()) };

    // SAFETY: the lock is held, so no other reference to the state exists.
    let result = access(unsafe { &mut *TABLE.state.get() }, &mut KernelCode);

    // SAFETY: taken above on this processor.
    unsafe {
        xboxkrnl::KeReleaseSpinLockFromRaisedIrql(TABLE.lock.as_ptr());
        xboxkrnl::KfLowerIrql(irql);
    }

    result
}

/// Set a software breakpoint on the calling thread (stock 0x91f26fc8): the
/// spare block is allocated before the table lock is taken.
pub(crate) fn set_breakpoint(address: u32) -> Result<(), SetError> {
    if address & 3 != 0 {
        return Err(SetError::Misaligned);
    }

    SET_SECTION.enter();
    if with_breakpoints(|state, _| state.needs_spare())
        && let Some(spare) = allocate_block()
    {
        with_breakpoints(|state, _| state.provide_spare(spare));
    }
    let result = with_breakpoints(|state, code| state.set(address, code));
    SET_SECTION.leave();

    result
}

/// Remove a software breakpoint (stock 0x91f27178); whether it existed.
pub(crate) fn clear_breakpoint(address: u32) -> bool {
    with_breakpoints(|state, code| state.clear(address, code))
}

/// Original byte under an armed breakpoint (stock 0x91f26bc8), on the
/// calling thread.
pub(crate) fn shadow_read(address: u32) -> Option<u8> {
    with_breakpoints(|state, _| state.shadow_read(address))
}

/// Store a byte into the saved instruction of an armed breakpoint (stock
/// 0x91f26cb8), on the calling thread; whether the address is covered.
pub(crate) fn shadow_write(address: u32, value: u8) -> bool {
    with_breakpoints(|state, _| state.shadow_write(address, value))
}

/// A table block from the pool as stock allocates it (0x488 bytes, tag
/// `Xbdm`, system pool, 0x91f2700c); blocks are never freed.
fn allocate_block() -> Option<SpareBlock> {
    // SAFETY: pool allocation has no pointer arguments.
    let address = unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(
            SpareBlock::SIZE,
            PoolTag::new(*b"Xbdm"),
            PoolType::System,
        )
    };
    if address == 0 {
        return None;
    }

    // SAFETY: the block holds `SIZE` bytes, is never freed, and nothing
    // else refers to it.
    let memory = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::with_exposed_provenance_mut::<u8>(address as usize),
            SpareBlock::SIZE as usize,
        )
    };

    SpareBlock::from_pool(memory)
}
