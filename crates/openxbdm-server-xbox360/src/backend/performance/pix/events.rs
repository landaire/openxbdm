//! Title event callbacks (stock 0x91fa2a38 owner, 0x91fa2a3c callbacks for
//! event types 2 to 6), the counter enable bitmap of `pixcmd n`/`y`, and
//! the per-hardware-thread slots of code 0x3c.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use xbox360::thread::current_object;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;

use super::plugin;
use super::ring;

/// Event types with a callback slot, from the D3D type on.
pub(super) const D3D_EVENT: u32 = 2;
pub(super) const TYPES: usize = 5;
/// Bitmap group of `pixcmd n`/`y`.
const BITMAP_GROUP: u32 = 1;
const BITMAP_WORDS: usize = 2;
/// Thread flags the title terminate notification clears.
const TITLE_THREAD_FLAGS: u32 = 7;

xbox360_sys::value_enum! {
    /// Operation passed to a title callback `(operation, value)`.
    pub enum CallbackOperation: u32 {
        /// A replay of the enabled counters follows.
        ReplayStart = 0,
        /// `pixcmd n`: counter `value` disabled.
        CounterDisabled = 0x10,
        /// `pixcmd y`: counter `value` enabled.
        CounterEnabled = 0x11,
        /// The plugin's submit hook or capture context in `value`; 0
        /// removes it.
        SubmitHook = 0x22,
        /// Timing requests of types 0 to 2 with the formatted name in
        /// `value`: begin, end, and a marker.
        TimingBegin = 0xe0,
        TimingEnd = 0xe1,
        TimingMarker = 0xe2,
        /// `pixcmd m`: `value` is `{frame, out percent, out percent, out
        /// count}`.
        FrameStatistics = 0xe3,
        /// The frame boundary.
        Frame = 0xff,
    }
}

impl CallbackOperation {
    /// Operation of timing request `kind`, for kinds 0 to 2.
    pub(super) const fn timing(kind: u32) -> Option<Self> {
        match kind {
            0 => Some(Self::TimingBegin),
            1 => Some(Self::TimingEnd),
            2 => Some(Self::TimingMarker),
            _ => None,
        }
    }
}

static OWNER: AtomicU32 = AtomicU32::new(0);
static CALLBACKS: [AtomicU32; TYPES] = [const { AtomicU32::new(0) }; TYPES];
static BITMAP: [AtomicU32; BITMAP_WORDS] = [const { AtomicU32::new(0) }; BITMAP_WORDS];
/// Flags word the slots point at (stock 0x91fa282c); titles write it.
static THREAD_FLAGS: AtomicU32 = AtomicU32::new(0);
/// Slots of 16 bytes per hardware thread (stock 0x91fa2838); `+0` points
/// at `THREAD_FLAGS`, the rest belongs to the title.
static SLOTS: [[AtomicU32; 4]; HARDWARE_THREAD_COUNT] =
    [const { [const { AtomicU32::new(0) }; 4] }; HARDWARE_THREAD_COUNT];

/// Call a title callback with the stock ABI `(operation, value)`.
///
/// # Safety
///
/// `callback` must be a loaded routine taking `(operation, value)`, as
/// the registrations of codes 0x2f and 0x59 require.
pub(super) unsafe fn call(callback: u32, operation: CallbackOperation, value: u32) {
    // SAFETY: the caller's contract.
    unsafe { crate::kernel::call_export(callback, operation.raw(), value, 0, 0) };
}

/// The callback of event type `event`, 0 when none.
pub(super) fn callback(event: u32) -> u32 {
    event
        .checked_sub(D3D_EVENT)
        .and_then(|index| CALLBACKS.get(index as usize))
        .map_or(0, |slot| slot.load(Ordering::Acquire))
}

/// Tell the owner, else the type 2 callback, about `operation` (stock
/// pattern in 0x91f55b48, 0x91f55cb0, 0x91f559d8, 0x91f58e90).
pub(super) fn notify_owner(operation: CallbackOperation, value: u32) {
    let owner = OWNER.load(Ordering::Acquire);
    let target = if owner != 0 {
        owner
    } else {
        CALLBACKS[0].load(Ordering::Acquire)
    };
    if target != 0 {
        // SAFETY: a registered callback; registration requires it.
        unsafe { call(target, operation, value) };
    }
}

/// Code 0x2f argument.
#[repr(C)]
struct Registration {
    event: AtomicU32,
    callback: AtomicU32,
}

/// Monitor control code 0x2f (stock 0x91f55eb8): `{+0 type, +4
/// callback}`; types 2 to 4 get their value group replayed, type 2 starts
/// the counter plugin.
///
/// # Safety
///
/// `argument` must be the address of a registration record the caller
/// keeps valid for the call. Its callback must be 0 or a routine that
/// takes `(operation, value)` and stays loaded until code 0x30 removes it.
pub(crate) unsafe fn service_register_callback(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let registration = unsafe { crate::kernel::object_at::<Registration>(argument) };
    let event = registration.event.load(Ordering::Relaxed);
    let callback = registration.callback.load(Ordering::Relaxed);
    if (D3D_EVENT..D3D_EVENT + TYPES as u32).contains(&event) {
        CALLBACKS[(event - D3D_EVENT) as usize].store(callback, Ordering::Release);
        // SAFETY: the caller's contract covers the callback.
        unsafe { ring::replay_group(event as usize, callback) };
        if event == D3D_EVENT {
            plugin::start();
        }
    }
    1
}

/// Monitor control code 0x30 (stock 0x91f55f28): type 2 stops the counter
/// plugin first.
pub(crate) fn service_unregister_callback(event: u32) -> u32 {
    if (D3D_EVENT..D3D_EVENT + TYPES as u32).contains(&event) {
        if event == D3D_EVENT {
            plugin::stop();
        }
        CALLBACKS[(event - D3D_EVENT) as usize].store(0, Ordering::Release);
    }
    1
}

/// Monitor control code 0x59 (stock 0x91f55f88): 1 when `callback`
/// becomes the single owner, 0 when another owner holds it.
///
/// # Safety
///
/// `callback` must be a routine that takes `(operation, value)` and stays
/// loaded until code 0x5a releases it; [`notify_owner`] calls it.
pub(crate) unsafe fn service_acquire_owner(callback: u32) -> u32 {
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
    // Stock asserts and indexes past the table for other values; the
    // kernel only runs six hardware threads.
    let Some(slot) = SLOTS.get(current_object().hardware_thread().index()) else {
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
        let operation = if enabled {
            CallbackOperation::CounterEnabled
        } else {
            CallbackOperation::CounterDisabled
        };
        // SAFETY: a registered callback; registration requires it.
        unsafe { call(target, operation, id) };
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
    THREAD_FLAGS.fetch_and(!TITLE_THREAD_FLAGS, Ordering::AcqRel);
}
