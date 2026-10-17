//! Module descriptions for load and unload traps.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::debugger::MODULE_NAME_CAPACITY;
use openxbdm_server::commands::debugger::ModuleEvent;
use openxbdm_server::commands::debugger::ModuleFlags;
use xbox360_sys::image::ImageCharacteristics;
use xbox360_sys::image::ImageDirectory;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::RtlImageDirectoryEntryToData;
use xbox360_sys::xboxkrnl::RtlImageNtHeader;

use crate::kernel::object_at;

/// Module entry of a load or unload trap.
#[repr(C)]
struct TrapModuleEntry {
    base: u32,
    _reserved_04: [u32; 2],
    size: u32,
}

const _: () = assert!(core::mem::offset_of!(TrapModuleEntry, size) == 0xc);

/// The length of an `ANSI_STRING`, read as stock reads it: one word load
/// of the first word, whose high half (big-endian) holds the length. The
/// load is atomic so that it is not narrowed to a halfword load.
#[inline(always)]
pub(crate) fn ansi_string_length(string: &AnsiString) -> u16 {
    // SAFETY: the string starts with the two halfwords of an aligned word
    // that nothing writes while the reference lives.
    let word = unsafe { AtomicU32::from_ptr(core::ptr::from_ref(string).cast::<u32>().cast_mut()) };

    (word.load(Ordering::Relaxed) >> 16) as u16
}

/// Describe the module of a load or unload trap from the loader's name
/// string and module entry.
///
/// # Safety
///
/// `name_string` and `entry` must each be 0 or the loader's live name
/// string and module entry of the trap, and the image must stay mapped for
/// the call.
pub(super) unsafe fn describe_module(name_string: u32, entry: u32) -> Option<ModuleEvent> {
    if name_string == 0 || entry == 0 {
        return None;
    }

    // SAFETY: the caller guarantees both objects.
    let (name, entry) = unsafe {
        (
            object_at::<AnsiString>(name_string),
            object_at::<TrapModuleEntry>(entry),
        )
    };
    let mut module = ModuleEvent::default();
    let length = usize::from(ansi_string_length(name)).min(MODULE_NAME_CAPACITY - 1);
    // SAFETY: the loader's name buffer holds `length` bytes.
    module.name[..length]
        .copy_from_slice(unsafe { core::slice::from_raw_parts(name.buffer, length) });
    module.name_length = length;
    module.base = entry.base;
    module.size = entry.size;
    // SAFETY: `module.base` is the image base from the loader's module entry.
    let header = unsafe { RtlImageNtHeader(module.base) };
    // SAFETY: a non-null result is the NT headers of the mapped image, which
    // the loader keeps mapped across the load or unload trap.
    if let Some(header) = unsafe { header.as_ref() } {
        module.has_header = true;
        module.checksum = header.optional_header.check_sum.get();
        module.timestamp = header.file_header.time_date_stamp.get();
        module.image_size = header.optional_header.size_of_image.get();
        if header
            .file_header
            .characteristics()
            .contains(ImageCharacteristics::DLL)
        {
            module.flags |= ModuleFlags::DLL;
        }
        let mut size = 0u32;
        // SAFETY: the image has the NT header found above; `size` is a live local.
        module.pdata = unsafe {
            RtlImageDirectoryEntryToData(module.base, true, ImageDirectory::Exception, &mut size)
        };
        module.pdata_size = size;
    }

    Some(module)
}
