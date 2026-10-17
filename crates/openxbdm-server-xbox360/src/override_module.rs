use openxbdm_core::status::KernelError;
use xbox360::time::sleep;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;

use crate::kernel;
use crate::serve::RETRY_DELAY;
use crate::thread::shutting_down;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Removal {
    Removed,
    Absent,
    Failed,
}

pub(crate) fn delete_file(path: &[u8]) -> Removal {
    let name = kernel::ansi_string(path);
    let attributes = ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: &name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };

    // SAFETY: `attributes` and the name it points at are live locals.
    match unsafe { xboxkrnl::NtDeleteFile(&attributes) }.result() {
        Ok(()) => Removal::Removed,
        Err(
            KernelError::NoSuchFile
            | KernelError::ObjectNameNotFound
            | KernelError::ObjectPathNotFound,
        ) => Removal::Absent,
        Err(_) => Removal::Failed,
    }
}

/// Remove the override, retrying while the file system is not ready.
#[inline(never)]
pub(crate) fn remove_override_module() -> Removal {
    // XAM loads xbdm.xex with the system-root-only flag. The kernel still
    // searches \FlashEx\ before \SystemRoot\ and accepts a module there whose
    // bounding path names that file, so this file replaces the flash XBDM
    // until it is removed.
    const OVERRIDE_MODULE_PATH: &[u8] = br"\Device\Harddisk0\Partition1\DEVKIT\FlashEx\xbdm.xex";
    const OVERRIDE_REMOVAL_ATTEMPTS: u32 = 30;

    let mut removal = delete_file(OVERRIDE_MODULE_PATH);
    for _ in 1..OVERRIDE_REMOVAL_ATTEMPTS {
        if removal != Removal::Failed || shutting_down() {
            break;
        }

        sleep(RETRY_DELAY);
        removal = delete_file(OVERRIDE_MODULE_PATH);
    }

    kernel::debug_print(match removal {
        Removal::Removed => c"openxbdm: removed FlashEx override module\n",
        Removal::Absent => c"openxbdm: FlashEx override module is absent\n",
        Removal::Failed => c"openxbdm: failed to remove FlashEx override module\n",
    });

    removal
}
