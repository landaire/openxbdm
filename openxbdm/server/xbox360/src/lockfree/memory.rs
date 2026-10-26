//! Pool memory routines of the library (exports 300 and 301).

use core::num::NonZeroU32;

use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::PoolType;

use crate::exports::export;
use crate::kernel::pool_tag;

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
