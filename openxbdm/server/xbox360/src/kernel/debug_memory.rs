//! Debugger memory access with retail-safe executable writes.

use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::memory::is_device_address;
use xbox360_sys::xboxkrnl;

#[cfg(not(feature = "retail-dashlaunch"))]
const WRITE_CONTEXT_WORDS: usize = 14;
const INSTRUCTION_SIZE: u32 = 4;

struct WritableMapping {
    address: u32,
    #[cfg(not(feature = "retail-dashlaunch"))]
    context: [u32; WRITE_CONTEXT_WORDS],
}

impl WritableMapping {
    fn new(address: u32) -> Option<Self> {
        #[cfg(feature = "retail-dashlaunch")]
        {
            if is_device_address(address) || !xboxkrnl::MmIsAddressValid(address).get() {
                return None;
            }

            Some(Self { address })
        }

        #[cfg(not(feature = "retail-dashlaunch"))]
        {
            let mut context = [0u32; WRITE_CONTEXT_WORDS];
            // SAFETY: `context` is live storage of the size the kernel fills.
            let mapped = unsafe { xboxkrnl::MmDbgWriteCheck(address, context.as_mut_ptr()) };
            if mapped == 0 || is_device_address(mapped) {
                if mapped != 0 {
                    // SAFETY: `mapped` and `context` came from `MmDbgWriteCheck`.
                    unsafe { xboxkrnl::MmDbgReleaseAddress(mapped, context.as_mut_ptr()) };
                }
                return None;
            }

            Some(Self {
                address: mapped,
                context,
            })
        }
    }

    fn byte(&self) -> *mut u8 {
        core::ptr::with_exposed_provenance_mut(self.address as usize)
    }

    fn word(&self) -> *mut u32 {
        core::ptr::with_exposed_provenance_mut(self.address as usize)
    }
}

impl Drop for WritableMapping {
    fn drop(&mut self) {
        #[cfg(not(feature = "retail-dashlaunch"))]
        {
            // SAFETY: this mapping and context came from `MmDbgWriteCheck`.
            unsafe { xboxkrnl::MmDbgReleaseAddress(self.address, self.context.as_mut_ptr()) };
        }
    }
}

/// Whether the debugger may read the page containing `address`.
pub fn readable(address: u32) -> bool {
    #[cfg(feature = "retail-dashlaunch")]
    {
        !is_device_address(address) && xboxkrnl::MmIsAddressValid(address).get()
    }

    #[cfg(not(feature = "retail-dashlaunch"))]
    {
        // SAFETY: the kernel validates the address before it maps it.
        let mapped = unsafe { xboxkrnl::MmDbgReadCheck(address) };

        mapped != 0 && !is_device_address(mapped)
    }
}

/// Write a debugger-visible byte and invalidate the corresponding instruction cache range.
pub fn write_byte(address: u32, value: u8) -> bool {
    let Some(mapping) = WritableMapping::new(address) else {
        return false;
    };

    // SAFETY: the mapping is writable for this byte and remains live through the cache sweep.
    unsafe {
        AtomicU8::from_ptr(mapping.byte()).store(value, Ordering::Relaxed);
        xboxkrnl::KeSweepIcacheRange(mapping.byte(), 1);
    }

    true
}

/// Replace an aligned executable word and return its prior value.
pub fn replace_code_word(address: u32, value: u32) -> Option<u32> {
    let mapping = WritableMapping::new(address)?;

    // SAFETY: the mapping is writable for this aligned word and remains live through the cache sweep.
    let word = unsafe { AtomicU32::from_ptr(mapping.word()) };
    let previous = word.load(Ordering::Relaxed);
    word.store(value, Ordering::Relaxed);
    // SAFETY: the mapped word remains live through this call.
    unsafe { xboxkrnl::KeSweepIcacheRange(mapping.byte(), INSTRUCTION_SIZE) };

    Some(previous)
}

/// Write an aligned executable word without reading it first.
pub fn write_code_word(address: u32, value: u32) -> bool {
    let Some(mapping) = WritableMapping::new(address) else {
        return false;
    };

    // SAFETY: the mapping is writable for this aligned word and remains live through the cache sweep.
    unsafe {
        AtomicU32::from_ptr(mapping.word()).store(value, Ordering::Relaxed);
        xboxkrnl::KeSweepIcacheRange(mapping.byte(), INSTRUCTION_SIZE);
    }

    true
}
