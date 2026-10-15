//! The flash counter plugin `catma.xex` (stock 0x91f55b48, 0x91f55cb0)
//! and the D3D debug image of `pixcmd h` (`dogma.xex`). Both export the
//! submit hook titles install: ordinal 4 when every D3D library linked into
//! the running executable is version 0x2028 or later, else ordinal 2
//! (stock 0x91f54f98).

use core::fmt::Write as _;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::performance::PixDogma;
use openxbdm_server::text::Text;

use super::events;
use super::files;
use crate::backend::memory;
use crate::kernel;
use crate::kernel::AnsiString;
use crate::kernel::IoStatusBlock;
use crate::kernel::ObjectAttributes;

const CATMA: &[u8] = b"\\Device\\Flash\\catma.xex\0";
const DOGMA: &[u8] = b"\\Device\\Flash\\dogma.xex\0";
/// `XexLoadImage` flags of the two images.
const CATMA_LOAD_FLAGS: u32 = 9;
const DOGMA_LOAD_FLAGS: u32 = 8;
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
const PLUGIN_TAG: u32 = 0x5049_5864;
/// Module walk end and the flag of DLL records.
const END_OF_LIST: u32 = 0x82da_0104;
const MODULE_DLL: u32 = 4;
const RECORD_SIZE: usize = 0x124;
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
    let name = AnsiString::new(&CATMA[..CATMA.len() - 1]);
    let attributes = ObjectAttributes {
        root_directory: 0,
        object_name: &name,
        attributes: kernel::OBJ_CASE_INSENSITIVE,
    };
    let mut handle = 0u32;
    let mut io_status = IoStatusBlock::default();
    kernel::NtOpenFile(
        &mut handle,
        0x8000_0000,
        &attributes,
        &mut io_status,
        1,
        0x20,
    );
    PRESENT.store(handle != 0, Ordering::Release);
    if handle != 0 {
        kernel::NtClose(handle);
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
    if (kernel::XexLoadImage(CATMA.as_ptr(), CATMA_LOAD_FLAGS, 0, &mut handle) as i32) < 0 {
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
    submit_hook(handle, &mut hook);
    HOOK.store(hook, Ordering::Release);
    for (index, slot) in PROCEDURE.iter().enumerate() {
        let mut address = 0u32;
        kernel::XexGetProcedureAddress(handle, FIRST_PROCEDURE + index as u32, &mut address);
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
    kernel::ExAllocatePoolTypeWithTag(size, PLUGIN_TAG, 2)
}

extern "C" fn free(block: u32) -> u32 {
    kernel::ExFreePool(block)
}

/// Stock 0x91f55b48: start once, in a title.
pub(super) fn start() {
    if ACTIVE.load(Ordering::Acquire) || kernel::KeGetCurrentProcessType() == SYSTEM_PROCESS {
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

const SYSTEM_PROCESS: u32 = 2;

/// Stock 0x91f55cb0: stop the plugin and forget its image (it stays
/// loaded).
pub(super) fn stop() {
    if !ACTIVE.swap(false, Ordering::AcqRel) {
        return;
    }
    if kernel::KeGetCurrentProcessType() != SYSTEM_PROCESS {
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
/// 0x91f54f98); returns the lookup status.
fn submit_hook(image: u32, hook: &mut u32) -> u32 {
    let mut returns = true;
    let mut walk = 0u32;
    let mut record = [0u8; RECORD_SIZE];
    let record_address = record.as_mut_ptr() as usize as u32;
    let mut status = memory::walk_modules(
        core::ptr::from_mut(&mut walk) as usize as u32,
        record_address,
    );
    while status != END_OF_LIST {
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
                memory::RtlImageXexHeaderField(
                    super::read_u32(entry + ENTRY_XEX_HEADER),
                    XEX_LIBRARIES,
                )
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
        status = memory::walk_modules(
            core::ptr::from_mut(&mut walk) as usize as u32,
            record_address,
        );
    }
    if walk != 0 {
        kernel::ExFreePool(walk);
    }
    let ordinal = if returns {
        kernel::debug_print(c"Catma: Use Submit hook with returns\n");
        ORDINAL_SUBMIT_RETURNS
    } else {
        kernel::debug_print(c"Catma: Use Submit hook NO returns\n");
        ORDINAL_SUBMIT
    };
    kernel::XexGetProcedureAddress(image, ordinal, hook)
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
            if (kernel::XexLoadImage(DOGMA.as_ptr(), DOGMA_LOAD_FLAGS, 0, &mut image) as i32) < 0 {
                return None;
            }
            image
        }
    };
    let mut dogma = PixDogma {
        handle: image,
        ..PixDogma::default()
    };
    let found = (submit_hook(image, &mut dogma.info) as i32) >= 0
        && (kernel::XexGetProcedureAddress(image, 1, &mut dogma.procedure_1) as i32) >= 0
        && (kernel::XexGetProcedureAddress(image, 3, &mut dogma.procedure_3) as i32) >= 0;
    if found || cached.is_some() {
        return Some(dogma);
    }
    kernel::XexUnloadImage(image);
    None
}
