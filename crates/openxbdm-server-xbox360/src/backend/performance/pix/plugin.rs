//! The flash counter plugin `catma.xex` (stock 0x91f55b48, 0x91f55cb0)
//! and the D3D debug image of `pixcmd h` (`dogma.xex`). Both export the
//! submit hook titles install: ordinal 4 when every D3D library linked into
//! the running executable is version 0x2028 or later, else ordinal 2
//! (stock 0x91f54f98).

use core::fmt::Write as _;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::KernelError;
use openxbdm_server::commands::performance::PixDogma;
use openxbdm_server::text::Text;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::ImageFlags;
use xbox360_sys::xboxkrnl::ImageVersion;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::events;
use super::files;
use crate::backend::memory;
use crate::backend::memory::ModuleWalkError;
use crate::kernel;

const CATMA: &[u8] = b"\\Device\\Flash\\catma.xex\0";
const DOGMA: &[u8] = b"\\Device\\Flash\\dogma.xex\0";
/// `XexLoadImage` flags of the two images.
const CATMA_LOAD_FLAGS: ImageFlags = ImageFlags::TITLE.union(ImageFlags::DLL);
/// Owner and type 2 callback operation that carries the submit hook.
const SUBMIT_HOOK: u32 = 0x22;
/// Plugin exports 5 to 10: start, stop, the two-routine pair, and the
/// callback installer and its counterpart.
const FIRST_PROCEDURE: u32 = 5;
const PROCEDURES: usize = 6;
const START: usize = 0;
const STOP: usize = 1;
const HAS_CALLBACKS: usize = 2;
const RELEASE: usize = 3;
const INSTALL_CALLBACKS: usize = 4;
const UNINSTALL: usize = 5;
/// Pool tag `PIXd` of plugin allocations.
const PLUGIN_TAG: PoolTag = PoolTag::new(*b"PIXd");
/// Flag of DLL module records.
const MODULE_DLL: u32 = 4;
const RECORD_SIZE: usize = memory::MODULE_RECORD_SHORT_SIZE;
const RECORD_FLAGS: usize = 0x114;
/// XEX header field of the linked static libraries: 16-byte entries
/// `{name[8], major, minor, build, qfe}` after a size word.
const XEX_LIBRARIES: u32 = 0x2_00ff;
const SUBMIT_RETURNS_BUILD: u16 = 0x2028;
const ORDINAL_SUBMIT_RETURNS: u32 = 4;
const ORDINAL_SUBMIT: u32 = 2;
/// Loader entry field holding the XEX header.
const ENTRY_XEX_HEADER: u32 = 0x58;

/// `catma.xex` exists (stock 0x91fa2aac, probed at initialization).
static PRESENT: AtomicBool = AtomicBool::new(false);
/// Loaded plugin image (stock 0x91fa2aa8); `pixcmd h` reuses it.
static HANDLE: AtomicU32 = AtomicU32::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static PROCEDURE: [AtomicU32; PROCEDURES] = [const { AtomicU32::new(0) }; PROCEDURES];
static HOOK: AtomicU32 = AtomicU32::new(0);

fn debug_print(arguments: core::fmt::Arguments<'_>) {
    let mut text: Text<0x100> = Text::new();
    let _ = text.write_fmt(arguments);
    let _ = text.push_bytes(b"\0");
    if let Ok(text) = core::ffi::CStr::from_bytes_until_nul(text.as_bytes()) {
        kernel::debug_print(text);
    }
}

/// Probe for the plugin image (stock 0x91f55a60).
pub(super) fn initialize() {
    let name = kernel::ansi_string(&CATMA[..CATMA.len() - 1]);
    let attributes = ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: &name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    let mut handle = Handle::NULL;
    let mut io_status = IoStatusBlock::default();
    // SAFETY: all pointers refer to live locals; the open is synchronous.
    unsafe {
        xboxkrnl::NtOpenFile(
            &mut handle,
            AccessMask::GENERIC_READ,
            &attributes,
            &mut io_status,
            ShareAccess::READ,
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
        )
    };
    PRESENT.store(!handle.is_null(), Ordering::Release);
    if !handle.is_null() {
        // SAFETY: the handle was just opened and is not used again.
        unsafe { xboxkrnl::NtClose(handle) };
    }
}

/// Call plugin export `5 + index` when the plugin has it.
fn call(index: usize) {
    let procedure = PROCEDURE[index].load(Ordering::Acquire);
    if procedure != 0 {
        // SAFETY: a plugin export without arguments.
        unsafe { kernel::call_export(procedure, 0, 0, 0, 0) };
    }
}

/// Load the plugin once (stock 0x91f55ad8).
fn load() {
    if HANDLE.load(Ordering::Acquire) != 0 || !PRESENT.load(Ordering::Acquire) {
        return;
    }
    let mut handle = 0u32;
    // SAFETY: `CATMA` is NUL-terminated and `handle` is a live local.
    if (unsafe {
        xboxkrnl::XexLoadImage(
            CATMA.as_ptr(),
            CATMA_LOAD_FLAGS,
            ImageVersion::ANY,
            &mut handle,
        )
    }
    .0 as i32)
        < 0
    {
        handle = 0;
    }
    HANDLE.store(handle, Ordering::Release);
}

/// Look up the plugin's exports and submit hook (stock 0x91f55b48 and
/// 0x91f57bd0 after the active check); a start also runs the plugin's
/// start routine and installs the capture callbacks. The owner learns the
/// hook.
fn attach(starting: bool) {
    let handle = HANDLE.load(Ordering::Acquire);
    if handle == 0 {
        return;
    }
    let mut hook = 0u32;
    let _ = submit_hook(handle, &mut hook);
    HOOK.store(hook, Ordering::Release);
    for (index, slot) in PROCEDURE.iter().enumerate() {
        let mut address = 0u32;
        // SAFETY: `handle` is the loaded plugin image; `address` is a live
        // local.
        unsafe {
            xboxkrnl::XexGetProcedureAddress(handle, FIRST_PROCEDURE + index as u32, &mut address)
        };
        slot.store(address, Ordering::Release);
    }
    if starting {
        call(START);
        // Stock calls the installer whenever export 7 exists, even without
        // an installer; a missing installer is skipped here.
        let install = PROCEDURE[INSTALL_CALLBACKS].load(Ordering::Acquire);
        if PROCEDURE[HAS_CALLBACKS].load(Ordering::Acquire) != 0 && install != 0 {
            install_callbacks(install);
        }
    }
    events::notify_owner(SUBMIT_HOOK, hook);
}

/// Give a plugin installer the capture file writer, the allocator, and the
/// free routine.
pub(super) fn install_callbacks(install: u32) {
    // SAFETY: plugin installers take three arguments, the routines.
    unsafe {
        kernel::call_export(
            install,
            plugin_write_entry as *const () as usize as u32,
            allocate_entry as *const () as usize as u32,
            free_entry as *const () as usize as u32,
            0,
        )
    };
}

crate::exports::bridged!(plugin_write_entry, files::plugin_write);
crate::exports::bridged!(allocate_entry, allocate);
crate::exports::bridged!(free_entry, free);

/// Plugin allocator (stock 0x91f559c8).
extern "C" fn allocate(size: u32) -> u32 {
    // SAFETY: allocates from the system pool; no pointer arguments.
    unsafe { xboxkrnl::ExAllocatePoolTypeWithTag(size, PLUGIN_TAG, PoolType::System) }
}

crate::kernel::forward!(
    /// Tail-calls ExFreePool, so its r3 passes through.
    fn free(u32) -> u32 => xboxkrnl::ExFreePool
);

/// Stock 0x91f55b48: start once, in a title.
pub(super) fn start() {
    if ACTIVE.load(Ordering::Acquire) || xboxkrnl::KeGetCurrentProcessType() == ProcessType::SYSTEM
    {
        return;
    }
    load();
    ACTIVE.store(true, Ordering::Release);
    attach(true);
}

/// Restart after a capture start (stock 0x91f57bd0): the plugin is loaded
/// and attached again without the title check.
pub(super) fn restart() {
    if !PRESENT.load(Ordering::Acquire) {
        return;
    }
    load();
    ACTIVE.store(true, Ordering::Release);
    attach(false);
}

/// Stock 0x91f55cb0: stop the plugin and forget its image (it stays
/// loaded).
pub(super) fn stop() {
    if !ACTIVE.swap(false, Ordering::AcqRel) {
        return;
    }
    if xboxkrnl::KeGetCurrentProcessType() != ProcessType::SYSTEM {
        call(STOP);
    }
    call(RELEASE);
    call(UNINSTALL);
    events::notify_owner(SUBMIT_HOOK, 0);
    for slot in &PROCEDURE {
        slot.store(0, Ordering::Release);
    }
    HOOK.store(0, Ordering::Release);
    HANDLE.store(0, Ordering::Release);
}

/// Plugin export `5 + index`, 0 when absent; exports 7 and 8 start and
/// stop a resource capture.
pub(super) fn procedure(index: usize) -> u32 {
    PROCEDURE[index].load(Ordering::Acquire)
}

/// The loaded plugin image, if any.
pub(super) fn handle() -> Option<u32> {
    Some(HANDLE.load(Ordering::Acquire)).filter(|&handle| handle != 0)
}

fn name_is(record: &[u8], name: &[u8]) -> bool {
    let end = record
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(record.len());
    record[..end].eq_ignore_ascii_case(name)
}

/// Look up the submit hook of `image` for the running executable (stock
/// 0x91f54f98).
fn submit_hook(image: u32, hook: &mut u32) -> Result<(), KernelError> {
    let mut returns = true;
    let mut walk = 0u32;
    let mut words = [0u32; RECORD_SIZE / 4];
    // Stock keeps walking after failures other than the end of the list,
    // with the record of the last module.
    while !matches!(
        memory::next_module(&mut walk, &mut words),
        Err(ModuleWalkError::End)
    ) {
        let mut record = [0u8; RECORD_SIZE];
        for (bytes, word) in record.as_chunks_mut::<4>().0.iter_mut().zip(&words) {
            *bytes = word.to_ne_bytes();
        }
        let flags = u32::from_be_bytes(
            record[RECORD_FLAGS..RECORD_FLAGS + 4]
                .try_into()
                .unwrap_or_default(),
        );
        if flags & MODULE_DLL == 0 && !name_is(&record, b"xboxkrnl.exe") {
            let end = record
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(record.len());
            let name = &record[..end];
            debug_print(format_args!(
                "Catma: Executable is {} \n",
                core::str::from_utf8(name).unwrap_or_default()
            ));
            let libraries = memory::loader_entry(name).map_or(0, |entry| {
                // SAFETY: the loader entry of a loaded module holds its XEX
                // header address.
                unsafe {
                    xboxkrnl::RtlImageXexHeaderField(
                        super::read_u32(entry + ENTRY_XEX_HEADER),
                        XEX_LIBRARIES,
                    )
                }
            });
            if libraries != 0 {
                let end = libraries + super::read_u32(libraries);
                let mut library = libraries + 4;
                while library < end {
                    // SAFETY: entries lie in the image's XEX header.
                    let entry =
                        unsafe { core::slice::from_raw_parts(library as usize as *const u8, 0x10) };
                    if &entry[..4] == b"d3d9" {
                        let half =
                            |offset: usize| u16::from_be_bytes([entry[offset], entry[offset + 1]]);
                        let qfe = half(0xe);
                        debug_print(format_args!(
                            "Catma: d3d version {}.{}.{}.{}, {}\n",
                            half(8),
                            half(0xa),
                            half(0xc),
                            qfe & 0xff,
                            if qfe & 0x8000 != 0 { "DEBUG" } else { "RETAIL" }
                        ));
                        returns &= half(0xc) >= SUBMIT_RETURNS_BUILD;
                    }
                    library += 0x10;
                }
            }
        }
    }
    if walk != 0 {
        // SAFETY: the pool block `next_module` allocated for the walk.
        unsafe { xboxkrnl::ExFreePool(walk) };
    }
    let ordinal = if returns {
        kernel::debug_print(c"Catma: Use Submit hook with returns\n");
        ORDINAL_SUBMIT_RETURNS
    } else {
        kernel::debug_print(c"Catma: Use Submit hook NO returns\n");
        ORDINAL_SUBMIT
    };
    // SAFETY: `image` is a loaded image handle; `hook` is a live reference.
    unsafe { xboxkrnl::XexGetProcedureAddress(image, ordinal, hook) }.result()
}

/// `pixcmd h` (stock 0x91f58b20): the plugin image, or `dogma.xex` loaded
/// for the request, with its exports 1 and 3 and the submit hook. `None`
/// unloads a freshly loaded image.
pub(super) fn dogma() -> Option<PixDogma> {
    let cached = handle();
    let image = match cached {
        Some(image) => image,
        None => {
            let mut image = 0u32;
            // SAFETY: `DOGMA` is NUL-terminated and `image` is a live local.
            if (unsafe {
                xboxkrnl::XexLoadImage(
                    DOGMA.as_ptr(),
                    ImageFlags::DLL,
                    ImageVersion::ANY,
                    &mut image,
                )
            }
            .0 as i32)
                < 0
            {
                return None;
            }
            image
        }
    };
    let mut dogma = PixDogma {
        handle: image,
        ..PixDogma::default()
    };
    // SAFETY: `image` is a loaded image handle; the outputs are fields of
    // the live `dogma`.
    let found = submit_hook(image, &mut dogma.info).is_ok()
        && unsafe { xboxkrnl::XexGetProcedureAddress(image, 1, &mut dogma.procedure_1) }
            .is_success()
        && unsafe { xboxkrnl::XexGetProcedureAddress(image, 3, &mut dogma.procedure_3) }
            .is_success();
    if found || cached.is_some() {
        return Some(dogma);
    }
    // SAFETY: `image` was loaded above and nothing refers to it.
    unsafe { xboxkrnl::XexUnloadImage(image) };
    None
}
