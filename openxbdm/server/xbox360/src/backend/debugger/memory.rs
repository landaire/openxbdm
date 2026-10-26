//! Target memory reads checked against the kernel mappings.

use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use xbox360_sys::xboxkrnl;

/// Size of a PowerPC instruction.
pub(super) const INSTRUCTION_SIZE: u32 = 4;

/// An inclusive range of addresses.
struct AddressRange {
    first: u32,
    last: u32,
}

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

fn is_excluded(address: u32) -> bool {
    /// Address ranges the debugger never maps (memory-mapped devices).
    const EXCLUDED_RANGES: &[AddressRange] = &[
        AddressRange {
            first: 0x7fc8_0000,
            last: 0x7fc9_ffff,
        },
        AddressRange {
            first: 0x7fd0_0000,
            last: 0x7fdf_ffff,
        },
        AddressRange {
            first: 0x7fea_0000,
            last: 0x7fea_ffff,
        },
        AddressRange {
            first: 0x7fed_0000,
            last: 0x7fed_ffff,
        },
        AddressRange {
            first: 0x8fff_0000,
            last: 0x8fff_0fff,
        },
        AddressRange {
            first: 0x8fff_1000,
            last: 0x8fff_1fff,
        },
    ];

    EXCLUDED_RANGES
        .iter()
        .any(|range| (range.first..=range.last).contains(&address))
}

pub(super) fn readable(address: u32) -> bool {
    // SAFETY: the kernel validates the address before it maps it.
    let mapped = unsafe { xboxkrnl::MmDbgReadCheck(address) };

    mapped != 0 && !is_excluded(mapped)
}

pub(super) fn replace_code_word(address: u32, value: u32) -> Option<u32> {
    let mut mapping = [0u32; 14];
    // SAFETY: `mapping` is a live local of the size the kernel fills.
    let mapped = unsafe { xboxkrnl::MmDbgWriteCheck(address, mapping.as_mut_ptr()) };
    if mapped == 0 {
        return None;
    }

    if is_excluded(mapped) {
        // SAFETY: `mapped` and `mapping` come from `MmDbgWriteCheck` above.
        unsafe { xboxkrnl::MmDbgReleaseAddress(mapped, mapping.as_mut_ptr()) };
        return None;
    }

    // SAFETY: `MmDbgWriteCheck` mapped the word-aligned code word
    // writable at `mapped` until the release below.
    let word =
        unsafe { AtomicU32::from_ptr(core::ptr::with_exposed_provenance_mut(mapped as usize)) };
    let previous = word.load(Ordering::Relaxed);
    word.store(value, Ordering::Relaxed);
    // SAFETY: `mapped` is the writable word mapped above; `mapped` and
    // `mapping` come from `MmDbgWriteCheck`.
    unsafe {
        xboxkrnl::KeSweepIcacheRange(
            core::ptr::with_exposed_provenance_mut(mapped as usize),
            INSTRUCTION_SIZE,
        );
        xboxkrnl::MmDbgReleaseAddress(mapped, mapping.as_mut_ptr());
    }

    Some(previous)
}
