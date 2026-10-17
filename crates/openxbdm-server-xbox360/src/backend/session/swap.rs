//! Context-swap routine chain (stock 0x91f641d8 register, 0x91f64290
//! unregister, 0x91f64128 title cleanup, dispatcher 0x91f64088): up to
//! eight routines run on every thread switch while any is registered. The
//! dispatcher replaces the kernel's swap routine (debug monitor data +0x1c)
//! and does not call the routine it replaced.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use xbox360::sync::SpinLock;
use xbox360_sys::xboxkrnl::KernelU32;

use crate::kernel;

const SWAP_SLOTS: usize = 8;

/// A routine run on every thread switch with the outgoing thread object,
/// the dispatcher's frame, and the incoming thread object.
pub(crate) type SwapRoutine = extern "C" fn(old: u32, frame: u32, new: u32);

/// Routine addresses, 0 for a free slot. Read by the dispatcher without
/// the lock, as stock does.
static ROUTINES: [AtomicU32; SWAP_SLOTS] = [const { AtomicU32::new(0) }; SWAP_SLOTS];
static CHAIN: SpinLock<Chain> = SpinLock::new(Chain {
    persistent: [false; SWAP_SLOTS],
    installed: false,
    replaced: 0,
});

struct Chain {
    /// The routine stays registered when the title ends.
    persistent: [bool; SWAP_SLOTS],
    installed: bool,
    /// Kernel swap routine replaced by the dispatcher.
    replaced: u32,
}

/// `KiContextSwapNotification`, the routine variable the kernel calls on
/// each thread switch.
///
/// # Safety
///
/// The query service must have published the address of the variable,
/// which it does at registration. Stock uses the word without a check.
unsafe fn kernel_swap_routine() -> &'static KernelU32 {
    // SAFETY: the caller's contract.
    unsafe { kernel::routine_variable(kernel::RoutineVariable::ContextSwap).unwrap_unchecked() }
}

fn routine_address(routine: SwapRoutine) -> u32 {
    routine as usize as u32
}

impl Chain {
    /// # Safety
    ///
    /// As for [`kernel_swap_routine`].
    unsafe fn install(&mut self) {
        // SAFETY: the caller's contract.
        let kernel_slot = unsafe { kernel_swap_routine() };
        self.replaced = kernel_slot.load(Ordering::Relaxed);
        // SAFETY: the dispatcher entry takes the kernel's swap routine
        // arguments and stays loaded while installed.
        unsafe {
            kernel_slot.store(
                dispatch_entry as *const () as usize as u32,
                Ordering::Relaxed,
            )
        };
        self.installed = true;
    }
}

/// Add `routine` in the first free slot (nothing when all are taken) and
/// install the dispatcher. A `persistent` routine stays registered when
/// the title ends.
pub(crate) fn register_swap_routine(routine: SwapRoutine, persistent: bool) {
    let mut chain = CHAIN.lock();
    if let Some(slot) = ROUTINES
        .iter()
        .position(|slot| slot.load(Ordering::Relaxed) == 0)
    {
        ROUTINES[slot].store(routine_address(routine), Ordering::Release);
        chain.persistent[slot] = persistent;
    }
    if !chain.installed {
        // SAFETY: the monitor registered with the kernel before any routine
        // registers, so the variable is published, as stock assumes.
        unsafe { chain.install() };
    }
}

/// Remove every slot holding `routine`; with no routine left the kernel's
/// own swap routine is restored.
pub(crate) fn unregister_swap_routine(routine: SwapRoutine) {
    let routine = routine_address(routine);
    let mut chain = CHAIN.lock();
    let mut remaining = 0;
    for (slot, persistent) in ROUTINES.iter().zip(&mut chain.persistent) {
        match slot.load(Ordering::Relaxed) {
            0 => {}
            current if current == routine => {
                slot.store(0, Ordering::Release);
                *persistent = false;
            }
            _ => remaining += 1,
        }
    }
    if remaining == 0 && chain.installed {
        // SAFETY: `install` found the variable; the routine the dispatcher
        // replaced is the kernel's own.
        unsafe { kernel_swap_routine().store(chain.replaced, Ordering::Relaxed) };
        chain.installed = false;
    }
}

/// Title termination part (stock 0x91f64128, from 0x91f566f0): remove the
/// routines registered as not persistent. With routines left the
/// dispatcher is installed again, replacing whatever the kernel slot holds
/// then (possibly the dispatcher itself); with none left it stays in the
/// kernel slot with an empty chain.
pub(crate) fn remove_unflagged_swap_routines() {
    let mut chain = CHAIN.lock();
    let mut remaining = 0;
    for (slot, persistent) in ROUTINES.iter().zip(&mut chain.persistent) {
        if slot.load(Ordering::Relaxed) == 0 {
            continue;
        }
        if *persistent {
            remaining += 1;
        } else {
            slot.store(0, Ordering::Release);
        }
    }
    if remaining > 0 {
        // SAFETY: as in `register_swap_routine`.
        unsafe { chain.install() };
    } else {
        chain.installed = false;
    }
}

/// Kernel swap routine. Like stock, it saves its return address below the
/// kernel's frame and hands the routines its own frame, whose back chain
/// is the kernel's; routines walk the call stack from there.
#[unsafe(naked)]
unsafe extern "C" fn dispatch_entry() {
    core::arch::naked_asm!(
        "mflr 12",
        "stw 12, -8(1)",
        "stwu 1, -0x10(1)",
        "mr 5, 1",
        "lis 12, {target}@ha",
        "addi 12, 12, {target}@l",
        "bl {bridge}",
        "addi 1, 1, 0x10",
        "lwz 12, -8(1)",
        "mtlr 12",
        "blr",
        target = sym dispatch,
        bridge = sym crate::exports::export_bridge,
    )
}

/// Run every registered routine with the outgoing thread, the entry's
/// frame, and the incoming thread.
extern "C" fn dispatch(old: u32, new: u32, frame: u32) {
    for slot in &ROUTINES {
        let routine = slot.load(Ordering::Acquire);
        if routine != 0 {
            // SAFETY: nonzero slots hold only `SwapRoutine` addresses stored
            // by `register_swap_routine`.
            let routine: SwapRoutine = unsafe { core::mem::transmute(routine as usize) };
            routine(old, frame, new);
        }
    }
}
