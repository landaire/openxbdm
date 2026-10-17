//! Memory, module, and allocation tracking exports. They run on the
//! importer's thread; the ones that need the server's breakpoint or drive
//! tables run their server part through the dispatcher's server requests.

use core::ffi::CStr;
use core::ffi::c_char;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands::console;
use openxbdm_server::commands::console::ConsoleMemory;
use openxbdm_server::commands::memory;
use openxbdm_server::commands::memory::Backend as _;
use openxbdm_server::commands::memory::PAGE_SIZE;
use openxbdm_server::commands::memory::TrackingFlags;
use openxbdm_server::reply;
use openxbdm_server::reply::CommandResult;
use openxbdm_server::reply::Reply;
use xbox360_sys::image::ImageCharacteristics;
use xbox360_sys::image::ImageDirectory;
use xbox360_sys::image::ImageNtHeaders;
use xbox360_sys::image::ImageSectionHeader;
use xbox360_sys::image::XexHeaderKey;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DebugMemoryStatistics;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::LdrDataTableEntry;
use xbox360_sys::xboxkrnl::MmStatistics;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::RtlImageDirectoryEntryToData;
use xbox360_sys::xboxkrnl::RtlImageXexHeaderField;

use super::REGISTERED_TYPE_NAMES;
use super::TRACKING;
use super::TRACKING_TYPE_COUNT;
use super::TrackingError;
use super::Untracked;
use super::code_view_of;
use super::entry_name_units;
use super::find_entry;
use super::is_reported;
use super::nt_header;
use super::read_debug_byte;
use super::section_info;
use super::track_allocation;
use super::tracking_hresult;
use super::tracking_type_name_bytes;
use super::untrack_allocation;
use super::write_debug_byte;
use crate::backend::dispatcher;
use crate::exports::export;
use crate::exports::export_result;
use crate::kernel;
use crate::kernel::LoaderLock;
use crate::kernel::pool_tag;

/// Result of an export whose server part could not run (on the server
/// thread or above passive level).
const SERVER_UNAVAILABLE: Hresult = Hresult::FAIL;
const BAD_PARAMETER: Hresult = ErrorCode::BadParameter.hresult();
const NO_SUCH_MODULE: Hresult = ErrorCode::NoSuchModule.hresult();
/// Export 78's result once 0x10000 type names exist.
const TOO_MANY_NAMES: Hresult = Hresult::from_win32(Win32Error::NO_LOG_SPACE);
/// Export 51's record: the export 142 record without its size dword.
pub(crate) const MODULE_RECORD_SHORT_SIZE: usize = size_of::<ShortModuleRecord>();
const MODULE_SNAPSHOT_TAG: PoolTag = PoolTag::new(*b"dmwm");
const MODULE_SNAPSHOT_CAPACITY: u32 = 10;
const SECTION_SNAPSHOT_TAG: PoolTag = PoolTag::new(*b"dmws");
const SECTION_SNAPSHOT_CAPACITY: u16 = 5;
/// Export 123 starts no region at or above this address.
const WALK_LIMIT: u32 = 0xa000_0000;
/// Bytes of a module name in a module record, including the terminator.
const MODULE_NAME_CAPACITY: usize = 0x104;
/// Bytes of a section name in a section record.
const SECTION_NAME_CAPACITY: usize = 0x104;
/// Bytes of the drive path in a DM_XBE.
const XBE_PATH_CAPACITY: usize = 0x105;

xbox360_sys::flags! {
    /// `DMN_MODFLAG_*` flags of a module record.
    pub struct DmnModuleFlags(u32) {
        /// The image is a DLL.
        DLL = 0x4,
    }
}

/// `strncpy`: copy up to `count` bytes of `source` and pad the rest of
/// `count` with zeros.
///
/// # Safety
///
/// `destination` is writable for `count` bytes.
unsafe fn copy_string(destination: *mut u8, source: &[u8], count: u32) {
    for index in 0..count as usize {
        // Zero past the end of `source` is the strncpy padding.
        let byte = source.get(index).copied().unwrap_or(0);
        // SAFETY: per the caller.
        unsafe { destination.add(index).write(byte) };
    }
}

/// A memory copy of exports 10 and 40, passed to the server thread by
/// address. Built only by those exports from their arguments.
struct Transfer {
    address: u32,
    length: u32,
    /// The caller's buffer of `length` bytes.
    buffer: NonNull<u8>,
    /// The caller's count dword, at any alignment, or null.
    count: *mut u32,
}

/// The byte loop of exports 10 and 40: pages are checked when the loop
/// enters a new page, and an invalid page or a byte that fails ends the
/// copy before the next byte. Without a count pointer, stock reports
/// 0x82da0004 whenever its down counter did not end at zero, which
/// includes every complete copy.
fn copy_bytes(request: &mut Transfer, mut step: impl FnMut(u32, u32) -> bool) -> CommandResult {
    let mut remaining = request.length;
    let mut valid = true;
    let mut page = request.address.wrapping_add(PAGE_SIZE);
    let mut current = request.address;
    let mut count = 0u32;
    loop {
        let more = remaining != 0;
        remaining = remaining.wrapping_sub(1);
        if !more || !valid {
            break;
        }
        if (page ^ current) & !(PAGE_SIZE - 1) != 0 {
            page = current & !(PAGE_SIZE - 1);
            valid = xboxkrnl::MmIsAddressValid(current).get();
        }
        if valid {
            valid = step(current, count);
            if valid {
                count += 1;
            }
        }
        current = current.wrapping_add(1);
    }
    if !request.count.is_null() {
        // SAFETY: exports 10 and 40 take a writable count dword or null;
        // stock does not align it.
        unsafe { request.count.write_unaligned(count) };
        return Ok(Reply::Ok);
    }
    if remaining != 0 {
        Err(ErrorCode::MemoryNotMapped.into())
    } else {
        Ok(Reply::Ok)
    }
}

/// Stock export 10 (0x91f33730): `(address, length, buffer, count) ->
/// HRESULT`; read through the debugger with breakpoint bytes shown as
/// their saved originals.
extern "C" fn get_memory(
    address: u32,
    length: u32,
    buffer: Option<NonNull<u8>>,
    count: *mut u32,
) -> Hresult {
    let Some(buffer) = buffer else {
        return Hresult::INVALID_ARGUMENT;
    };
    let mut request = Transfer {
        address,
        length,
        buffer,
        count,
    };
    dispatcher::call_on_server_with(
        &mut request,
        |server, _console, _network, request: &mut Transfer| {
            let buffer = request.buffer;
            reply::hresult(copy_bytes(request, |current, index| {
                match server
                    .state
                    .debugger
                    .shadow_read(current)
                    .or_else(|| read_debug_byte(current))
                {
                    Some(byte) => {
                        // SAFETY: export 10 takes a writable buffer of
                        // `length` bytes, and `index` is below `length`.
                        unsafe { buffer.add(index as usize).write(byte) };
                        true
                    }
                    None => false,
                }
            }))
            .0
        },
    )
    .map_or(SERVER_UNAVAILABLE, Hresult)
}
export!(10, get_memory);

/// Stock export 40 (0x91f337f8): `(address, length, buffer, count) ->
/// HRESULT`; write through the debugger, updating the saved original of a
/// byte under a breakpoint.
extern "C" fn set_memory(
    address: u32,
    length: u32,
    buffer: Option<NonNull<u8>>,
    count: *mut u32,
) -> Hresult {
    let Some(buffer) = buffer else {
        return Hresult::INVALID_ARGUMENT;
    };
    let mut request = Transfer {
        address,
        length,
        buffer,
        count,
    };
    dispatcher::call_on_server_with(
        &mut request,
        |server, _console, _network, request: &mut Transfer| {
            let buffer = request.buffer;
            reply::hresult(copy_bytes(request, |current, index| {
                // SAFETY: export 40 takes a readable buffer of `length`
                // bytes, and `index` is below `length`.
                let byte = unsafe { buffer.add(index as usize).read() };
                server.state.debugger.shadow_write(current, byte) || write_debug_byte(current, byte)
            }))
            .0
        },
    )
    .map_or(SERVER_UNAVAILABLE, Hresult)
}
export!(40, set_memory);

/// Stock export 12 (0x91f33ce0): `(module, ordinal, address) -> HRESULT`.
extern "C" fn get_proc_address(module: u32, ordinal: u32, address: *mut u32) -> Hresult {
    if ordinal == 0 || address.is_null() {
        return Hresult::INVALID_ARGUMENT;
    }
    // SAFETY: the caller supplies a writable dword at `address`, which the
    // check above requires to be non-null.
    let status = unsafe { xboxkrnl::XexGetProcedureAddress(module, ordinal, address) };
    if !status.is_success() {
        return ErrorCode::FileNotFound.hresult();
    }
    Hresult::OK
}
export!(12, get_proc_address);

/// DM_XBE: the record of export 16.
#[repr(C)]
struct XbeInfo {
    /// NUL-terminated drive path.
    path: [u8; XBE_PATH_CAPACITY],
    time_stamp: u32,
    checksum: u32,
    stack_size: u32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(XbeInfo, time_stamp) == 0x108);
    assert!(offset_of!(XbeInfo, checksum) == 0x10c);
    assert!(offset_of!(XbeInfo, stack_size) == 0x110);
};

/// Stock export 16 (0x91f34448 -> 0x91f33c38 with flags 0): `(name, info)
/// -> HRESULT`; the running executable's drive path, whatever the name,
/// with zero timestamp, checksum, and stack size.
extern "C" fn get_xbe_info(_name: u32, mut info: *mut XbeInfo) -> Hresult {
    if info.is_null() {
        return Hresult::INVALID_ARGUMENT;
    }
    dispatcher::call_on_server_with(
        &mut info,
        |server, console, _network, info: &mut *mut XbeInfo| {
            let info = *info;
            let mut object = [0u8; memory::EXECUTABLE_PATH_CAPACITY];
            let length = console.running_executable_path(&mut object);
            let mut path = [0u8; XBE_PATH_CAPACITY];
            let length = server.state.filesystem.drives.object_path_to_drive_path(
                console,
                &object[..length],
                &mut path,
            );
            // SAFETY: export 16 takes a writable DM_XBE, checked non-null
            // above, which stock does not align; the path is a byte array.
            unsafe {
                let slots = &mut *(&raw mut (*info).path);
                // The conversion leaves at least one zero after the path,
                // which terminates the copy.
                for (slot, &byte) in slots.iter_mut().zip(&path[..=length]) {
                    *slot = byte;
                }
                (&raw mut (*info).time_stamp).write_unaligned(0);
                (&raw mut (*info).checksum).write_unaligned(0);
                (&raw mut (*info).stack_size).write_unaligned(0);
            }
            Hresult::OK.0
        },
    )
    .map_or(SERVER_UNAVAILABLE, Hresult)
}
export!(16, get_xbe_info);

/// DMN_MODLOAD_EX without its size dword: the record of export 51.
#[repr(C)]
struct ShortModuleRecord {
    /// Low bytes of the base name units, NUL-terminated.
    name: [u8; MODULE_NAME_CAPACITY],
    base: u32,
    /// Size of the loaded image, from the loader entry.
    size: u32,
    time_stamp: u32,
    checksum: u32,
    flags: DmnModuleFlags,
    pdata: u32,
    pdata_size: u32,
    /// Never written.
    unknown_124: u32,
}

/// DMN_MODLOAD_EX: the record of export 142.
#[repr(C)]
struct ModuleRecord {
    /// Bytes of the record.
    size: u32,
    short: ShortModuleRecord,
    /// `SizeOfImage` of the image's optional header.
    image_size: u32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(ModuleRecord, short) == 4);
    assert!(offset_of!(ModuleRecord, short) + offset_of!(ShortModuleRecord, base) == 0x108);
    assert!(offset_of!(ModuleRecord, short) + offset_of!(ShortModuleRecord, flags) == 0x118);
    assert!(offset_of!(ModuleRecord, short) + offset_of!(ShortModuleRecord, unknown_124) == 0x124);
    assert!(offset_of!(ModuleRecord, image_size) == 0x128);
    assert!(size_of::<ModuleRecord>() == 0x12c);
    assert!(size_of::<ShortModuleRecord>() == 0x124);
};

impl ModuleRecord {
    /// A zero record with its size set.
    const fn new() -> Self {
        Self {
            size: size_of::<Self>() as u32,
            short: ShortModuleRecord {
                name: [0; MODULE_NAME_CAPACITY],
                base: 0,
                size: 0,
                time_stamp: 0,
                checksum: 0,
                flags: DmnModuleFlags::empty(),
                pdata: 0,
                pdata_size: 0,
                unknown_124: 0,
            },
            image_size: 0,
        }
    }
}

/// Pool block of export 142's module snapshot: the record count, the next
/// index, then the records.
#[repr(C)]
struct ModuleSnapshot {
    count: u32,
    next: u32,
    records: [ModuleRecord; 0],
}

const _: () = assert!(core::mem::offset_of!(ModuleSnapshot, records) == 8);

impl ModuleSnapshot {
    /// Record `index` of the snapshot at `block`.
    ///
    /// # Safety
    ///
    /// `block` is a snapshot block with room for record `index`.
    unsafe fn record(block: NonNull<Self>, index: u32) -> *mut ModuleRecord {
        // SAFETY: per the caller.
        unsafe {
            (&raw mut (*block.as_ptr()).records)
                .cast::<ModuleRecord>()
                .add(index as usize)
        }
    }
}

/// Fill a module snapshot record for a loader entry (zero before).
fn fill_module_record(
    record: &mut ModuleRecord,
    lock: &LoaderLock,
    entry: &LdrDataTableEntry,
    header: &ImageNtHeaders,
) {
    record.size = size_of::<ModuleRecord>() as u32;
    // 0x91f485b8: the low byte of each name unit; the zeroed record
    // terminates the name.
    let name = &mut record.short.name;
    for (slot, unit) in name
        .iter_mut()
        .zip(entry_name_units(lock, entry).take(MODULE_NAME_CAPACITY - 1))
    {
        *slot = unit as u8;
    }
    let base = entry.dll_base;
    record.short.base = base;
    record.short.size = entry.image_size;
    record.short.checksum = header.optional_header.check_sum.get();
    record.short.time_stamp = header.file_header.time_date_stamp.get();
    record.image_size = header.optional_header.size_of_image.get();
    let mut pdata_size = 0u32;
    // SAFETY: `base` is the image of a loaded entry, held by `lock`.
    let pdata = unsafe {
        RtlImageDirectoryEntryToData(base, true, ImageDirectory::Exception, &mut pdata_size)
    };
    record.short.pdata = pdata;
    record.short.pdata_size = pdata_size;
    let dll = header
        .file_header
        .characteristics()
        .contains(ImageCharacteristics::DLL);
    record.short.flags = if dll {
        DmnModuleFlags::DLL
    } else {
        DmnModuleFlags::empty()
    };
}

/// Allocate and fill a module snapshot, growing it until every reported
/// module fits.
fn module_snapshot() -> Option<NonNull<ModuleSnapshot>> {
    let mut capacity = MODULE_SNAPSHOT_CAPACITY;
    let mut previous: Option<NonNull<ModuleSnapshot>> = None;
    loop {
        if let Some(block) = previous {
            // SAFETY: the block allocated and filled on the previous pass;
            // nothing else refers to it.
            unsafe {
                capacity = (*block.as_ptr()).count;
                xboxkrnl::ExFreePool(block.as_ptr().addr() as u32);
            }
        }
        let size = capacity
            .wrapping_mul(size_of::<ModuleRecord>() as u32)
            .wrapping_add(size_of::<ModuleSnapshot>() as u32);
        // SAFETY: pool allocation has no pointer arguments.
        let address = unsafe { xboxkrnl::ExAllocatePoolWithTag(size, MODULE_SNAPSHOT_TAG) };
        let block = NonNull::new(core::ptr::with_exposed_provenance_mut::<ModuleSnapshot>(
            address as usize,
        ))?;
        // SAFETY: the new pool block holds `size` bytes.
        unsafe { core::ptr::write_bytes(block.as_ptr().cast::<u8>(), 0, size as usize) };
        {
            let lock = LoaderLock::acquire();
            for entry in lock.all_entries() {
                if !is_reported(entry) {
                    continue;
                }
                let Some(header) = nt_header(entry) else {
                    continue;
                };
                // SAFETY: the block allocated above, which holds `capacity`
                // records and which nothing else refers to.
                unsafe {
                    let count = (*block.as_ptr()).count;
                    if count < capacity {
                        let record = &mut *ModuleSnapshot::record(block, count);
                        fill_module_record(record, &lock, entry, header);
                    }
                    (*block.as_ptr()).count = count + 1;
                }
            }
        }
        // SAFETY: as above.
        if capacity >= unsafe { (*block.as_ptr()).count } {
            return Some(block);
        }
        previous = Some(block);
    }
}

/// Why a module walk returned no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModuleWalkError {
    /// A null walk or record pointer.
    InvalidArgument,
    /// The snapshot could not be allocated.
    OutOfMemory,
    /// Every module was returned.
    End,
}

impl core::fmt::Display for ModuleWalkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ModuleWalkError::InvalidArgument => "null walk or record pointer",
            ModuleWalkError::OutOfMemory => "no memory for the module snapshot",
            ModuleWalkError::End => "no more modules",
        })
    }
}

impl core::error::Error for ModuleWalkError {}

impl From<ModuleWalkError> for Hresult {
    fn from(error: ModuleWalkError) -> Self {
        match error {
            ModuleWalkError::InvalidArgument => Hresult::INVALID_ARGUMENT,
            ModuleWalkError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            ModuleWalkError::End => Hresult::END_OF_DATA,
        }
    }
}

/// The next module of a snapshot taken on the first call. `record` starts
/// with its size, at most 0x12c bytes are copied, and the size is replaced
/// by the copied length.
///
/// # Safety
///
/// `walk` is null or a dword holding 0 or a handle this function stored,
/// and `record` is null or a writable record whose first dword holds its
/// size in bytes; neither needs alignment.
unsafe fn next_loaded_module(walk: *mut u32, record: *mut u32) -> Result<(), ModuleWalkError> {
    if walk.is_null() || record.is_null() {
        return Err(ModuleWalkError::InvalidArgument);
    }
    // SAFETY: per the caller.
    let handle = unsafe { walk.read_unaligned() };
    let snapshot = match NonNull::new(core::ptr::with_exposed_provenance_mut::<ModuleSnapshot>(
        handle as usize,
    )) {
        Some(snapshot) => snapshot,
        None => {
            let snapshot = module_snapshot().ok_or(ModuleWalkError::OutOfMemory)?;
            // SAFETY: per the caller.
            unsafe { walk.write_unaligned(snapshot.as_ptr().addr() as u32) };
            snapshot
        }
    };
    // SAFETY: a nonzero walk handle is a snapshot stored above, which stays
    // allocated until the caller closes the walk.
    let (count, index) = unsafe { ((*snapshot.as_ptr()).count, (*snapshot.as_ptr()).next) };
    if index == count {
        return Err(ModuleWalkError::End);
    }
    // SAFETY: per the caller.
    let size = unsafe { record.read_unaligned() }.min(size_of::<ModuleRecord>() as u32);
    // SAFETY: `index` is below the count, which the snapshot's capacity
    // covers; the caller's record holds `size` bytes.
    unsafe {
        (*snapshot.as_ptr()).next = index + 1;
        core::ptr::copy(
            ModuleSnapshot::record(snapshot, index).cast::<u8>(),
            record.cast::<u8>(),
            size as usize,
        );
        record.write_unaligned(size);
    }
    Ok(())
}

/// Stock export 142 (0x91f338c0): `(walk, record) -> HRESULT`;
/// [`next_loaded_module`].
extern "C" fn walk_loaded_modules(walk: *mut u32, record: *mut u32) -> Hresult {
    // SAFETY: export 142 takes the caller's walk handle and a record that
    // starts with its size, or nulls.
    export_result(unsafe { next_loaded_module(walk, record) })
}
export!(142, walk_loaded_modules);

/// [`next_loaded_module`] with a 0x124-byte record that has no size dword.
///
/// # Safety
///
/// `walk` is as for [`next_loaded_module`]; `record` is writable for a
/// [`ShortModuleRecord`] at any alignment.
unsafe fn next_short_module(
    walk: *mut u32,
    record: *mut ShortModuleRecord,
) -> Result<(), ModuleWalkError> {
    let mut full = ModuleRecord::new();
    // SAFETY: `full` is a live record whose first dword holds its size;
    // `walk` per the caller.
    unsafe { next_loaded_module(walk, (&raw mut full).cast::<u32>())? };
    // SAFETY: per the caller.
    unsafe { record.write_unaligned(full.short) };
    Ok(())
}

/// The next module of the walk `walk` (0 before the first call), as export
/// 51 returns it.
pub(crate) fn next_module(
    walk: &mut u32,
    record: &mut [u32; MODULE_RECORD_SHORT_SIZE / 4],
) -> Result<(), ModuleWalkError> {
    // SAFETY: `walk` is only passed to this walk; `record` is a live buffer
    // of the short record size.
    unsafe { next_short_module(walk, core::ptr::from_mut(record).cast()) }
}

/// Stock export 51 (0x91f33af8): `(walk, record) -> HRESULT`;
/// [`next_short_module`].
extern "C" fn walk_modules(walk: *mut u32, record: *mut ShortModuleRecord) -> Hresult {
    // SAFETY: export 51 takes the caller's walk handle and a writable
    // record, which stock does not check.
    export_result(unsafe { next_short_module(walk, record) })
}
export!(51, walk_modules);

/// DMN_SECTIONLOAD: the record of export 52.
#[repr(C)]
struct SectionRecord {
    /// NUL-padded section name.
    name: [u8; SECTION_NAME_CAPACITY],
    address: u32,
    size: u32,
    /// One-based index of the section.
    index: u16,
    flags: u16,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(SectionRecord, address) == 0x104);
    assert!(offset_of!(SectionRecord, index) == 0x10c);
    assert!(offset_of!(SectionRecord, flags) == 0x10e);
    assert!(size_of::<SectionRecord>() == 0x110);
};

/// Pool block of export 52's section snapshot: the record count, the next
/// index, then the records.
#[repr(C)]
struct SectionSnapshot {
    count: u16,
    next: u16,
    records: [SectionRecord; 0],
}

const _: () = assert!(core::mem::offset_of!(SectionSnapshot, records) == 4);

impl SectionSnapshot {
    /// Record `index` of the snapshot at `block`.
    ///
    /// # Safety
    ///
    /// `block` is a snapshot block with room for record `index`.
    unsafe fn record(block: NonNull<Self>, index: u16) -> *mut SectionRecord {
        // SAFETY: per the caller.
        unsafe {
            (&raw mut (*block.as_ptr()).records)
                .cast::<SectionRecord>()
                .add(usize::from(index))
        }
    }
}

/// Why export 52 could not take a section snapshot.
#[derive(Debug, Clone, Copy)]
enum SectionSnapshotError {
    OutOfMemory,
    /// No loaded module with headers has the name.
    NoSuchModule,
}

impl core::fmt::Display for SectionSnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            SectionSnapshotError::OutOfMemory => "no memory for the section snapshot",
            SectionSnapshotError::NoSuchModule => "no loaded module has the name",
        })
    }
}

impl core::error::Error for SectionSnapshotError {}

impl From<SectionSnapshotError> for Hresult {
    fn from(error: SectionSnapshotError) -> Self {
        match error {
            SectionSnapshotError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            SectionSnapshotError::NoSuchModule => NO_SUCH_MODULE,
        }
    }
}

/// Fill one export 52 record from a section header (0x91f33b88).
fn fill_section_record(record: &mut SectionRecord, section: &ImageSectionHeader, base: u32) {
    let info = section_info(section, base);
    record.name[..info.name.len()].copy_from_slice(&info.name);
    record.address = info.address;
    record.size = info.size;
    record.flags = info.flags() as u16;
}

/// Allocate and fill a snapshot of the section table of the module named
/// `name`, growing it until every section fits.
fn section_snapshot(name: &[u8]) -> Result<NonNull<SectionSnapshot>, SectionSnapshotError> {
    let mut capacity = SECTION_SNAPSHOT_CAPACITY;
    let mut previous: Option<NonNull<SectionSnapshot>> = None;
    loop {
        if let Some(block) = previous {
            // SAFETY: the block allocated and filled on the previous pass;
            // nothing else refers to it.
            unsafe {
                capacity = (*block.as_ptr()).count;
                xboxkrnl::ExFreePool(block.as_ptr().addr() as u32);
            }
        }
        let size = u32::from(capacity) * size_of::<SectionRecord>() as u32
            + size_of::<SectionSnapshot>() as u32;
        // SAFETY: pool allocation has no pointer arguments.
        let address = unsafe { xboxkrnl::ExAllocatePoolWithTag(size, SECTION_SNAPSHOT_TAG) };
        let block = NonNull::new(core::ptr::with_exposed_provenance_mut::<SectionSnapshot>(
            address as usize,
        ))
        .ok_or(SectionSnapshotError::OutOfMemory)?;
        // SAFETY: the new pool block holds `size` bytes.
        unsafe { core::ptr::write_bytes(block.as_ptr().cast::<u8>(), 0, size as usize) };
        let mut found = false;
        {
            let lock = LoaderLock::acquire();
            if let Some(entry) = find_entry(&lock, name) {
                let base = entry.dll_base;
                if let Some(header) = nt_header(entry) {
                    let count = header.file_header.number_of_sections.get();
                    found = true;
                    // SAFETY: the block allocated above, which holds
                    // `capacity` records and which nothing else refers to.
                    unsafe { (*block.as_ptr()).count = count };
                    if count <= capacity {
                        // SAFETY: the headers of a loaded image, mapped
                        // under the loader lock; the linker emits an
                        // optional header whose size is a multiple of 4,
                        // so the section table is aligned.
                        let sections = unsafe { header.sections() };
                        for (index, section) in (0..count).zip(sections) {
                            // SAFETY: `index` is below `count`, which fits
                            // the capacity.
                            let record = unsafe { &mut *SectionSnapshot::record(block, index) };
                            fill_section_record(record, section, base);
                            record.index = index + 1;
                        }
                    }
                }
            }
        }
        if !found {
            // SAFETY: `block` was allocated above and is not returned.
            unsafe { xboxkrnl::ExFreePool(block.as_ptr().addr() as u32) };
            return Err(SectionSnapshotError::NoSuchModule);
        }
        // SAFETY: as above.
        if unsafe { (*block.as_ptr()).count } <= capacity {
            return Ok(block);
        }
        previous = Some(block);
    }
}

/// Stock export 52 (0x91f340d0): `(walk, module name, record) ->
/// HRESULT`; the next section of a snapshot of the named module's section
/// table.
extern "C" fn walk_module_sections(
    walk: *mut u32,
    name: *const c_char,
    record: *mut SectionRecord,
) -> Hresult {
    if walk.is_null() {
        return Hresult::INVALID_ARGUMENT;
    }
    // SAFETY: export 52 takes a walk dword, checked non-null above, which
    // stock does not align.
    let handle = unsafe { walk.read_unaligned() };
    let snapshot = match NonNull::new(core::ptr::with_exposed_provenance_mut::<SectionSnapshot>(
        handle as usize,
    )) {
        Some(snapshot) => {
            if record.is_null() {
                return Hresult::INVALID_ARGUMENT;
            }
            snapshot
        }
        None => {
            if name.is_null() {
                return Hresult::INVALID_ARGUMENT;
            }
            // SAFETY: export 52 takes a NUL-terminated module name.
            let name = unsafe { CStr::from_ptr(name) }.to_bytes();
            let snapshot = match section_snapshot(name) {
                Ok(snapshot) => snapshot,
                Err(error) => return error.into(),
            };
            // SAFETY: as above.
            unsafe { walk.write_unaligned(snapshot.as_ptr().addr() as u32) };
            if record.is_null() {
                return Hresult::OK;
            }
            snapshot
        }
    };
    // SAFETY: a nonzero walk handle is a snapshot this export stored, which
    // stays allocated until the caller closes the walk.
    let (count, index) = unsafe { ((*snapshot.as_ptr()).count, (*snapshot.as_ptr()).next) };
    if index == count {
        return Hresult::END_OF_DATA;
    }
    // SAFETY: `index` is below the count, which the snapshot's capacity
    // covers; export 52 takes a writable record, checked non-null above.
    unsafe {
        (*snapshot.as_ptr()).next = index + 1;
        core::ptr::copy_nonoverlapping(
            SectionSnapshot::record(snapshot, index).cast::<u8>(),
            record.cast::<u8>(),
            size_of::<SectionRecord>(),
        );
    }
    Hresult::OK
}
export!(52, walk_module_sections);

/// Stock export 75 (0x91f331c8): `(statistics) -> HRESULT`.
extern "C" fn query_memory_statistics(statistics: *mut u32) -> Hresult {
    let mut block = [0u32; 12];
    // SAFETY: the importer passes a writable 0x30-byte statistics block,
    // which stock neither checks for null nor aligns.
    block[0] = unsafe { statistics.read_unaligned() };
    let result = crate::backend::performance::memory_statistics(&mut block);
    if result.is_ok() {
        // The length word keeps the caller's value, as stock leaves it.
        let [_, words @ ..] = block;
        // SAFETY: as above.
        unsafe { statistics.add(1).cast::<[u32; 11]>().write_unaligned(words) };
    }
    export_result(result)
}
export!(75, query_memory_statistics);

/// DM_MEMORY_STATISTICS: page counts by use, as exports 75 and 165 fill
/// them.
#[repr(C)]
struct MonitorMemoryStatistics {
    /// Bytes of the block, which the caller sets.
    length: u32,
    total_pages: u32,
    available_pages: u32,
    stack_pages: u32,
    virtual_page_table_pages: u32,
    system_page_table_pages: u32,
    pool_pages: u32,
    virtual_mapped_pages: u32,
    image_pages: u32,
    file_cache_pages: u32,
    contiguous_pages: u32,
    debugger_pages: u32,
}

const _: () = assert!(size_of::<MonitorMemoryStatistics>() == 0x30);

/// The kernel's memory statistics through the debug monitor service, or
/// `MmQueryStatistics` when the service fails or replies short. `output`
/// holds zero statistics with the length set.
fn kernel_memory_statistics(output: &mut MmStatistics) -> Result<(), KernelError> {
    let mut reply = DebugMemoryStatistics::new();
    // SAFETY: `reply` is a live block whose length fields give its size.
    let status = unsafe {
        xboxkrnl::ExDebugMonitorService(
            DebugMonitorService::MemoryStatistics,
            &raw mut reply as usize as u32,
            0,
            0,
        )
    };
    if status.is_success() && reply.is_complete() {
        *output = reply.statistics;
        return status.result();
    }
    // SAFETY: `output` is a live statistics block whose length field holds
    // its size.
    unsafe { xboxkrnl::MmQueryStatistics(output) }.result()
}

/// Stock export 165 (0x91f33318): `(statistics) -> HRESULT`; page counts
/// by use, with the total as their sum.
extern "C" fn query_memory_usage(statistics: *mut MonitorMemoryStatistics) -> Hresult {
    // SAFETY: export 165 takes a writable statistics block, which stock
    // neither checks for null nor aligns.
    let length = unsafe { (&raw const (*statistics).length).read_unaligned() };
    if length != size_of::<MonitorMemoryStatistics>() as u32 {
        return Hresult::INVALID_ARGUMENT;
    }
    let mut kernel = MmStatistics::new();
    if let Err(error) = kernel_memory_statistics(&mut kernel) {
        return error.into();
    }
    let title = &kernel.title;
    let total_pages = [
        title.physical_pages,
        title.pool_pages,
        title.stack_pages,
        title.image_pages,
        title.heap_pages,
        title.virtual_pages,
        title.page_table_pages,
        title.cache_pages,
    ]
    .iter()
    .fold(title.available_pages, |sum, &value| sum.wrapping_add(value));
    // SAFETY: as above.
    unsafe {
        (&raw mut (*statistics).total_pages).write_unaligned(total_pages);
        (&raw mut (*statistics).available_pages).write_unaligned(title.available_pages);
        (&raw mut (*statistics).stack_pages).write_unaligned(title.stack_pages);
        (&raw mut (*statistics).virtual_page_table_pages).write_unaligned(title.page_table_pages);
        (&raw mut (*statistics).system_page_table_pages).write_unaligned(0);
        (&raw mut (*statistics).pool_pages).write_unaligned(title.pool_pages);
        (&raw mut (*statistics).virtual_mapped_pages)
            .write_unaligned(title.heap_pages.wrapping_add(title.virtual_pages));
        (&raw mut (*statistics).image_pages).write_unaligned(title.image_pages);
        (&raw mut (*statistics).file_cache_pages).write_unaligned(title.cache_pages);
        (&raw mut (*statistics).contiguous_pages).write_unaligned(title.physical_pages);
        (&raw mut (*statistics).debugger_pages).write_unaligned(0);
    }
    Hresult::OK
}
export!(165, query_memory_usage);

/// Stock export 77 (0x91f234b8): `(type, buffer, size) -> HRESULT`; the
/// name of an allocation type, truncated to the buffer; S_FALSE when
/// truncated.
extern "C" fn get_tracking_type_name(kind: u32, buffer: *mut u8, size: u32) -> Hresult {
    let kind = kind as u16;
    if u32::from(kind) >= TRACKING_TYPE_COUNT.load(Ordering::Acquire) {
        return Hresult::INVALID_ARGUMENT;
    }
    let name = tracking_type_name_bytes(kind);
    // SAFETY: export 77 takes a writable buffer of `size` bytes; stock
    // terminates it at `size - 1` without checking for a zero size.
    unsafe {
        copy_string(buffer, name, size);
        buffer.wrapping_add(size as usize).wrapping_sub(1).write(0);
    }
    if name.len() as u32 + 1 > size {
        Hresult::FALSE
    } else {
        Hresult::OK
    }
}
export!(77, get_tracking_type_name);

/// Stock export 78 (0x91f23a30): `(name, type) -> HRESULT`; register an
/// allocation type name and store its index through `type` (u16).
extern "C" fn register_tracking_type(name: *const c_char, kind: *mut u16) -> Hresult {
    if !TrackingFlags::from_bits_retain(TRACKING.flags.load(Ordering::Relaxed)).is_active() {
        return TrackingError::Off.into();
    }
    if TRACKING_TYPE_COUNT.load(Ordering::Acquire) > u32::from(u16::MAX) {
        return TOO_MANY_NAMES;
    }
    // SAFETY: export 78 takes a NUL-terminated name.
    let source = unsafe { CStr::from_ptr(name) }.to_bytes();
    let length = source.len() as u32 + 1;
    // SAFETY: pool allocation has no pointer arguments.
    let copy = unsafe { xboxkrnl::ExAllocatePoolWithTag(length, pool_tag::MONITOR) };
    if copy == 0 {
        return Hresult::OUT_OF_MEMORY;
    }
    // SAFETY: the new pool block holds `length` bytes.
    unsafe {
        copy_string(
            core::ptr::with_exposed_provenance_mut::<u8>(copy as usize),
            source,
            length,
        )
    };
    let index = TRACKING_TYPE_COUNT.fetch_add(1, Ordering::AcqRel);
    match REGISTERED_TYPE_NAMES.get(index as usize - memory::TRACKING_TYPE_NAMES.len()) {
        Some(slot) => slot.store(copy, Ordering::Release),
        None => {
            // The registered table is full: undo the registration.
            TRACKING_TYPE_COUNT.fetch_sub(1, Ordering::AcqRel);
            // SAFETY: `copy` was allocated above and was not published.
            unsafe { xboxkrnl::ExFreePool(copy) };
            return TOO_MANY_NAMES;
        }
    }
    // SAFETY: export 78 takes a writable type word, which stock neither
    // checks nor aligns.
    unsafe { kind.write_unaligned(index as u16) };
    Hresult::OK
}
export!(78, register_tracking_type);

/// Stock export 79 (0x91f23df0): `(address, size, type) -> HRESULT`; track
/// an allocation of a registered type.
extern "C" fn track_registered_allocation(address: u32, size: u32, kind: u32) -> Hresult {
    let kind = kind as u16;
    if usize::from(kind) < memory::TRACKING_TYPE_NAMES.len() {
        return Hresult::INVALID_ARGUMENT;
    }
    tracking_hresult(track_allocation(address, size, kind))
}
export!(79, track_registered_allocation);

/// Stock export 80 (0x91f23e20): `(address, size, type) -> HRESULT`.
extern "C" fn untrack_registered_allocation(address: u32, size: u32, kind: u32) -> Hresult {
    let kind = kind as u16;
    if usize::from(kind) < memory::TRACKING_TYPE_NAMES.len() {
        return Hresult::INVALID_ARGUMENT;
    }
    match untrack_allocation(address, size, kind) {
        Untracked::Skipped(result) | Untracked::Lookup(result) => tracking_hresult(result),
    }
}
export!(80, untrack_registered_allocation);

/// The region record of export 123.
#[repr(C)]
struct MemoryRegion {
    base: u32,
    size: u32,
    protection: PageProtection,
}

/// Stock export 123 (0x91f33e48): `(cursor, region) -> HRESULT`; the next
/// valid range at or after `*cursor` below 0xa0000000 as base, size, and
/// protection, advancing the cursor past the page that ended it.
extern "C" fn walk_committed_memory(cursor: *mut u32, region: *mut MemoryRegion) -> Hresult {
    /// Stock reports these pages as executable and the others as
    /// read-write.
    const EXECUTABLE_RANGE: core::ops::RangeInclusive<u32> = 0x8000_0000..=0x9fff_ffff;
    if region.is_null() {
        return BAD_PARAMETER;
    }
    loop {
        // SAFETY: export 123 takes a writable cursor dword, which stock
        // neither checks for null nor aligns.
        let start = unsafe { cursor.read_unaligned() };
        if start >= WALK_LIMIT {
            return Hresult::END_OF_DATA;
        }
        let mut end = start;
        if xboxkrnl::MmIsAddressValid(start).get() {
            loop {
                if memory::is_device_address(end) {
                    break;
                }
                end = memory::next_page(end);
                if !xboxkrnl::MmIsAddressValid(end).get() {
                    break;
                }
            }
        }
        // SAFETY: as above.
        unsafe { cursor.write_unaligned(memory::next_page(end)) };
        if end > start {
            let protection = if EXECUTABLE_RANGE.contains(&start) {
                PageProtection::EXECUTE_READWRITE
            } else {
                PageProtection::READWRITE
            };
            // SAFETY: export 123 takes a writable region record, checked
            // non-null above, which stock does not align.
            unsafe {
                (&raw mut (*region).base).write_unaligned(start);
                (&raw mut (*region).size).write_unaligned(end - start);
                (&raw mut (*region).protection).write_unaligned(protection);
            }
            return Hresult::OK;
        }
    }
}
export!(123, walk_committed_memory);

/// Stock export 143 (0x91f342f0): `(module, key, buffer, buffer size,
/// size) -> HRESULT`; copy an XEX header field of a loaded module. `size`
/// receives the field size; a short buffer gets a truncated copy and
/// 0x82da0105.
extern "C" fn get_xex_header_field(
    module: *const c_char,
    key: u32,
    buffer: *mut u8,
    buffer_size: u32,
    size: *mut u32,
) -> Hresult {
    /// Low byte of a key: the field size in dwords, or this value for data
    /// that starts with its size.
    const SIZE_PREFIXED: u32 = 0xff;
    if size.is_null() || module.is_null() || (buffer.is_null() && buffer_size != 0) {
        return Hresult::INVALID_ARGUMENT;
    }
    // SAFETY: export 143 takes a writable size dword, checked non-null
    // above, which stock does not align.
    unsafe { size.write_unaligned(0) };
    let lock = LoaderLock::acquire();
    // SAFETY: export 143 takes a NUL-terminated module name.
    let module = unsafe { CStr::from_ptr(module) }.to_bytes();
    let Some(entry) = find_entry(&lock, module) else {
        return NO_SUCH_MODULE;
    };
    let key = XexHeaderKey(key);
    // SAFETY: the entry's XEX header stays mapped under the loader lock.
    let field = unsafe { RtlImageXexHeaderField(entry.xex_header_base, key) };
    if field == 0 {
        return Hresult::NO_SUCH_FIELD;
    }
    let mut truncated = false;
    let length = match key.0 & SIZE_PREFIXED {
        // SAFETY: the data of a size-prefixed field starts with its size,
        // in the XEX header mapped under the loader lock.
        SIZE_PREFIXED => unsafe {
            core::ptr::with_exposed_provenance::<u32>(field as usize).read()
        },
        words => words << 2,
    };
    // SAFETY: the size dword, as at entry.
    unsafe { size.write_unaligned(length) };
    if length != 0 && !buffer.is_null() {
        let count = if length > buffer_size {
            truncated = true;
            buffer_size
        } else {
            length
        };
        // SAFETY: the field data lies in the mapped XEX header; the buffer
        // holds `buffer_size` bytes.
        unsafe {
            core::ptr::copy(
                core::ptr::with_exposed_provenance::<u8>(field as usize),
                buffer,
                count as usize,
            )
        };
    } else if key == XexHeaderKey::ENTRY_POINT {
        // SAFETY: the size dword, as at entry.
        unsafe { size.write_unaligned(4) };
        if !buffer.is_null() {
            if buffer_size < 4 {
                truncated = true;
            } else {
                // SAFETY: the buffer holds `buffer_size` bytes, at least a
                // dword; stock does not align it.
                unsafe { buffer.cast::<u32>().write_unaligned(field) };
            }
        }
    }
    if truncated {
        Hresult::BUFFER_TOO_SMALL
    } else {
        Hresult::OK
    }
}
export!(143, get_xex_header_field);

/// The record of export 145: the CodeView GUID and age, then the PDB path.
#[repr(C)]
struct DebugDirectoryRecord {
    guid: [u8; 16],
    age: [u8; 4],
    /// NUL-terminated PDB path.
    path: [u8; memory::PDB_PATH_CAPACITY],
}

const _: () = {
    assert!(core::mem::offset_of!(DebugDirectoryRecord, path) == 0x14);
    assert!(size_of::<DebugDirectoryRecord>() == 0x118);
};

/// GUID, age, and PDB path of the module loaded at `base`, as export 145
/// writes them.
#[inline(never)]
fn debug_directory(base: u32, record: &mut DebugDirectoryRecord) -> Hresult {
    let Some(code_view) = code_view_of(base) else {
        return Hresult::from_win32(Win32Error::NOT_FOUND);
    };
    record.guid = code_view.guid;
    record.age = code_view.age;
    // `strncpy` of the path: zeros pad the rest of the field.
    let path = code_view
        .path()
        .iter()
        .copied()
        .chain(core::iter::repeat(0));
    for (slot, byte) in record.path.iter_mut().zip(path) {
        *slot = byte;
    }
    record.path[memory::PDB_PATH_CAPACITY - 1] = 0;
    Hresult::OK
}

/// Export 145 for callers inside the monitor: the same writes and results
/// into a word buffer of the record's size.
pub(crate) fn module_debug_directory(base: u32, record: &mut [u32; 0x118 / 4]) -> Hresult {
    // SAFETY: the record is byte arrays of the buffer's size, so any bytes
    // are valid and the word alignment exceeds its own.
    debug_directory(base, unsafe {
        &mut *core::ptr::from_mut(record).cast::<DebugDirectoryRecord>()
    })
}

/// Stock export 145 (0x91f282a8): `(base, record) -> HRESULT`.
extern "C" fn get_module_debug_directory(base: u32, record: u32) -> Hresult {
    // SAFETY: export 145 takes a record writable for 0x118 bytes, which has
    // no alignment requirement.
    debug_directory(base, unsafe {
        kernel::object_at_mut::<DebugDirectoryRecord>(record)
    })
}
export!(145, get_module_debug_directory);

/// Stock export 212 (0x91f51538): `(size) -> HRESULT`; the running title's
/// additional title memory while the console runs its extra memory, else 0.
extern "C" fn get_title_workspace_size(mut size: *mut u32) -> Hresult {
    if size.is_null() {
        return BAD_PARAMETER;
    }
    // SAFETY: export 212 takes a writable size dword, checked non-null
    // above, which stock does not align.
    unsafe { size.write_unaligned(0) };
    dispatcher::call_on_server_with(
        &mut size,
        |_server, console, _network, size: &mut *mut u32| {
            if console::console_memory(console) != ConsoleMemory::ExtraMemoryInUse {
                return Hresult::OK.0;
            }
            match console
                .title_xex_dword(memory::XexFieldKey(XexHeaderKey::ADDITIONAL_TITLE_MEMORY.0))
            {
                Ok(Some(value)) => {
                    // SAFETY: the caller's size dword, as at entry.
                    unsafe { size.write_unaligned(value) };
                    Hresult::OK.0
                }
                Ok(None) => Hresult::OK.0,
                Err(memory::NoSuchModule) => NO_SUCH_MODULE.0,
            }
        },
    )
    .map_or(SERVER_UNAVAILABLE, Hresult)
}
export!(212, get_title_workspace_size);
