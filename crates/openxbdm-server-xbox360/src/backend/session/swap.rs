//! Context-swap routine chain (stock 0x91f641d8 register, 0x91f64290
//! unregister, 0x91f64128 title cleanup, dispatcher 0x91f64088): up to
//! eight routines run on every thread switch while any is registered. The
//! dispatcher replaces the kernel's swap routine (debug monitor data +0x1c)
//! and does not call the routine it replaced.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use xbox360::sync::SpinLock;

use super::read_u32;
use super::write_u32;
use crate::kernel;

const SWAP_SLOTS: usize = 8;
/// Debug monitor data word holding the address of the kernel's swap
/// routine slot.
const SWAP_SLOT_WORD: usize = 0x1c / 4;

/// Read by the dispatcher without the lock, as stock does.
static ROUTINES: [AtomicU32; SWAP_SLOTS] = [const { AtomicU32::new(0) }; SWAP_SLOTS];
static CHAIN: SpinLock<Chain> = SpinLock::new(Chain {
    flags: [0; SWAP_SLOTS],
    installed: false,
    replaced: 0,
});

struct Chain {
    /// Nonzero: the routine stays registered when the title ends.
    flags: [u32; SWAP_SLOTS],
    installed: bool,
    /// Kernel swap routine replaced by the dispatcher.
    replaced: u32,
}

impl Chain {
    fn install(&mut self) {
        let kernel_slot = kernel::debug_monitor_data().words[SWAP_SLOT_WORD];
        self.replaced = read_u32(kernel_slot);
        write_u32(kernel_slot, dispatch_entry as *const () as usize as u32);
        self.installed = true;
    }
}

/// Add `routine(old_thread, frame, new_thread)` in the first free slot
/// (nothing when all are taken) and install the dispatcher.
pub(crate) fn register_swap_routine(routine: u32, flag: u32) {
    let mut chain = CHAIN.lock();
    if let Some(slot) = ROUTINES
        .iter()
        .position(|slot| slot.load(Ordering::Relaxed) == 0)
    {
        ROUTINES[slot].store(routine, Ordering::Release);
        chain.flags[slot] = flag;
    }
    if !chain.installed {
        chain.install();
    }
}

/// Remove every slot holding `routine`; with no routine left the kernel's
/// own swap routine is restored.
pub(crate) fn unregister_swap_routine(routine: u32) {
    let mut chain = CHAIN.lock();
    let mut remaining = 0;
    for (slot, flag) in ROUTINES.iter().zip(&mut chain.flags) {
        match slot.load(Ordering::Relaxed) {
            0 => {}
            current if current == routine => {
                slot.store(0, Ordering::Release);
                *flag = 0;
            }
            _ => remaining += 1,
        }
    }
    if remaining == 0 && chain.installed {
        write_u32(
            kernel::debug_monitor_data().words[SWAP_SLOT_WORD],
            chain.replaced,
        );
        chain.installed = false;
    }
}

/// Title termination part (stock 0x91f64128, from 0x91f566f0): remove the
/// routines registered with a zero flag. With routines left the
/// dispatcher is installed again, replacing whatever the kernel slot holds
/// then (possibly the dispatcher itself); with none left it stays in the
/// kernel slot with an empty chain.
pub(crate) fn remove_unflagged_swap_routines() {
    let mut chain = CHAIN.lock();
    let mut remaining = 0;
    for (slot, flag) in ROUTINES.iter().zip(&mut chain.flags) {
        if slot.load(Ordering::Relaxed) == 0 {
            continue;
        }
        if *flag != 0 {
            remaining += 1;
        } else {
            slot.store(0, Ordering::Release);
        }
    }
    if remaining > 0 {
        chain.install();
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
            // SAFETY: registrants pass `(old, frame, new)` routines of this
            // module.
            let routine: extern "C" fn(u32, u32, u32) -> u32 =
                unsafe { core::mem::transmute(routine as usize) };
            routine(old, frame, new);
        }
    }
}
