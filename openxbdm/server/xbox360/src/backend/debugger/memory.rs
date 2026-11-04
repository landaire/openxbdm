//! Target memory reads checked against the kernel mappings.

use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;

use crate::kernel;

/// Size of a PowerPC instruction.
pub(super) const INSTRUCTION_SIZE: u32 = 4;

/// A byte of target memory.
///
/// # Safety
///
/// `address` must be mapped readable, as [`readable`] checks.
#[inline(always)]
pub(super) unsafe fn target_u8(address: u32) -> u8 {
    // SAFETY: the caller guarantees a readable byte; other threads may
    // write it, so it is read atomically.
    unsafe { AtomicU8::from_ptr(core::ptr::with_exposed_provenance_mut(address as usize)) }
        .load(Ordering::Relaxed)
}

/// Bytes of `length` at `address` that can be read without a fault.
pub(super) fn readable_length(address: u32, length: usize) -> usize {
    (0..length)
        .find(|&offset| {
            let byte = address.wrapping_add(offset as u32);
            (offset == 0 || byte & 0xfff == 0) && !readable(byte)
        })
        .unwrap_or(length)
}

pub(super) fn readable(address: u32) -> bool {
    kernel::debug_readable(address)
}

pub(super) fn replace_code_word(address: u32, value: u32) -> Option<u32> {
    kernel::replace_code_word(address, value)
}
