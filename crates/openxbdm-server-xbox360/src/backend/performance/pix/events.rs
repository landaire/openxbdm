//! Title event callbacks (stock 0x91fa2a38 owner, 0x91fa2a3c callbacks for
//! event types 2 to 6), the counter enable bitmap of `pixcmd n`/`y`, and
//! the per-hardware-thread slots of code 0x3c.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use super::plugin;
use super::ring;
use crate::kernel;

/// Event types with a callback slot.
const FIRST_TYPE: u32 = 2;
const TYPES: usize = 5;
/// Callback operations: counter disabled and enabled.
const COUNTER_DISABLED: u32 = 0x10;
const COUNTER_ENABLED: u32 = 0x11;
/// Bitmap group of `pixcmd n`/`y`.
const BITMAP_GROUP: u32 = 1;
const BITMAP_WORDS: usize = 2;
/// Hardware threads with a slot.
const HARDWARE_THREADS: usize = 6;

static OWNER: AtomicU32 = AtomicU32::new(0);
static CALLBACKS: [AtomicU32; TYPES] = [const { AtomicU32::new(0) }; TYPES];
static BITMAP: [AtomicU32; BITMAP_WORDS] = [const { AtomicU32::new(0) }; BITMAP_WORDS];
/// Flags word the slots point at (stock 0x91fa282c); titles write it.
static THREAD_FLAGS: AtomicU32 = AtomicU32::new(0);
/// Slots of 16 bytes per hardware thread (stock 0x91fa2838); `+0` points
/// at `THREAD_FLAGS`, the rest belongs to the title.
static SLOTS: [[AtomicU32; 4]; HARDWARE_THREADS] =
    [const { [const { AtomicU32::new(0) }; 4] }; HARDWARE_THREADS];

/// Call a title callback with the stock ABI `(operation, value)`.
fn call(callback: u32, operation: u32, value: u32) {
    // SAFETY: titles register callbacks taking two arguments.
    unsafe { crate::kernel::call_export(callback, operation, value, 0, 0) };
}

/// The callback of event type `event`, 0 when none.
pub(super) fn callback(event: u32) -> u32 {
    event
        .checked_sub(FIRST_TYPE)
        .and_then(|index| CALLBACKS.get(index as usize))
        .map_or(0, |slot| slot.load(Ordering::Acquire))
}

/// Tell the owner, else the type 2 callback, about `operation` (stock
/// pattern in 0x91f55b48, 0x91f55cb0, 0x91f559d8, 0x91f58e90).
pub(super) fn notify_owner(operation: u32, value: u32) {
    let owner = OWNER.load(Ordering::Acquire);
    let target = if owner != 0 {
        owner
    } else {
        CALLBACKS[0].load(Ordering::Acquire)
    };
    if target != 0 {
        call(target, operation, value);
    }
}

/// Monitor control code 0x2f (stock 0x91f55eb8): `{+0 type, +4
/// callback}`; types 2 to 4 get their value group replayed, type 2 starts
/// the counter plugin.
pub(crate) fn service_register_callback(argument: u32) -> u32 {
    let event = super::read_u32(argument);
    let callback = super::read_u32(argument + 4);
    if (FIRST_TYPE..FIRST_TYPE + TYPES as u32).contains(&event) {
        CALLBACKS[(event - FIRST_TYPE) as usize].store(callback, Ordering::Release);
        ring::replay_group(event as usize, callback);
        if event == FIRST_TYPE {
            plugin::start();
        }
    }
    1
}

/// Monitor control code 0x30 (stock 0x91f55f28): type 2 stops the counter
/// plugin first.
pub(crate) fn service_unregister_callback(event: u32) -> u32 {
    if (FIRST_TYPE..FIRST_TYPE + TYPES as u32).contains(&event) {
        if event == FIRST_TYPE {
            plugin::stop();
        }
        CALLBACKS[(event - FIRST_TYPE) as usize].store(0, Ordering::Release);
    }
    1
}

/// Monitor control code 0x59 (stock 0x91f55f88): 1 when `callback`
/// becomes the single owner, 0 when another owner holds it.
pub(crate) fn service_acquire_owner(callback: u32) -> u32 {
    if OWNER
        .compare_exchange(0, callback, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return 0;
    }
    plugin::start();
    1
}

/// Monitor control code 0x5a (stock 0x91f55fc8).
pub(crate) fn service_release_owner(callback: u32) -> u32 {
    if OWNER.load(Ordering::Acquire) != callback {
        return 0;
    }
    OWNER.store(0, Ordering::Release);
    plugin::stop();
    1
}

/// Monitor control code 0x3c (stock 0x91f56010): the slot of the calling
/// hardware thread, with `+0` pointing at the shared flags word.
pub(crate) fn service_thread_slot(_argument: u32) -> u32 {
    let thread = kernel::current_thread();
    let hardware_thread = usize::from(super::read_u8(thread + 0xbf));
    // Stock asserts and indexes past the table for other values; the
    // kernel only runs six hardware threads.
    let Some(slot) = SLOTS.get(hardware_thread) else {
        return 0;
    };
    slot[0].store(
        core::ptr::from_ref(&THREAD_FLAGS) as usize as u32,
        Ordering::Release,
    );
    slot.as_ptr() as usize as u32
}

/// `pixcmd n`/`y` (stock 0x91f58aa0 and 0x91f58a10): group 1 clears or
/// sets bit `id` of the bitmap; groups 2 to 6 tell their callback.
pub(super) fn counter_control(group: u32, id: u32, enabled: bool) {
    if group == BITMAP_GROUP {
        // Stock indexes the bitmap without a bound and overwrites the
        // owner and callbacks for identifiers of 64 and up.
        let Some(word) = BITMAP.get((id >> 5) as usize) else {
            return;
        };
        let bit = 1 << (id & 31);
        if enabled {
            word.fetch_or(bit, Ordering::AcqRel);
        } else {
            word.fetch_and(!bit, Ordering::AcqRel);
        }
        return;
    }
    let target = callback(group);
    if target != 0 {
        call(
            target,
            if enabled {
                COUNTER_ENABLED
            } else {
                COUNTER_DISABLED
            },
            id,
        );
    }
}

/// Clear the bitmap (`pixcmd b`/`e`).
pub(super) fn clear_bitmap() {
    for word in &BITMAP {
        word.store(0, Ordering::Release);
    }
}

/// Drop every callback but type 3's, the owner, and the 0x42 consumers
/// (stock 0x91f552b0).
pub(super) fn forget_title() {
    for (index, slot) in CALLBACKS.iter().enumerate() {
        if index != 1 {
            slot.store(0, Ordering::Release);
        }
    }
    OWNER.store(0, Ordering::Release);
    ring::clear_consumers();
}

/// Clear the low bits of the thread flags word (stock 0x91f566f0).
pub(super) fn clear_thread_flags() {
    THREAD_FLAGS.fetch_and(!7, Ordering::AcqRel);
}
