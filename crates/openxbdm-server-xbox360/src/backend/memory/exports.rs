//! Memory, module, and allocation tracking exports. They run on the
//! importer's thread; the ones that need the server's breakpoint or drive
//! tables run their server part through the dispatcher's server requests.

use core::ffi::CStr;
use core::ffi::c_char;
use core::sync::atomic::Ordering;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands::console;
use openxbdm_server::commands::memory;
use openxbdm_server::commands::memory::Backend as _;
use openxbdm_server::reply;
use openxbdm_server::reply::CommandResult;
use openxbdm_server::reply::Reply;
use xbox360_sys::image::ImageCharacteristics;
use xbox360_sys::image::ImageDirectory;
use xbox360_sys::image::ImageNtHeaders;
use xbox360_sys::image::ImageSectionHeader;
use xbox360_sys::image::XexHeaderKey;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::LdrDataTableEntry;
use xbox360_sys::xboxkrnl::MmStatistics;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::RtlImageDirectoryEntryToData;
use xbox360_sys::xboxkrnl::RtlImageXexHeaderField;

use super::LoaderLock;
use super::REGISTERED_TYPE_NAMES;
use super::TRACKING;
use super::TRACKING_TYPE_COUNT;
use super::TrackingError;
use super::Untracked;
use super::all_entries;
use super::code_view_of;
use super::find_entry;
use super::is_reported;
use super::nt_header;
use super::read_debug_byte;
use super::read_u16;
use super::read_u32;
use super::section_info;
use super::track_allocation;
use super::tracking_hresult;
use super::tracking_type_name_bytes;
use super::untrack_allocation;
use super::write_debug_byte;
use crate::backend::dispatcher;
use crate::exports::export;
use crate::exports::export_result;

/// Result of an export whose server part could not run (on the server
/// thread or above passive level).
const SERVER_UNAVAILABLE: Hresult = Hresult::FAIL;
const BAD_PARAMETER: Hresult = ErrorCode::BadParameter.hresult();
const NO_SUCH_MODULE: Hresult = ErrorCode::NoSuchModule.hresult();
/// HRESULT_FROM_WIN32(ERROR_NOT_FOUND).
const NOT_FOUND: u32 = 0x8007_0490;
/// HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION)-style limit of 0x10000 names.
const TOO_MANY_NAMES: u32 = 0x8007_03fb;
/// Module snapshot record of export 142 (DMN_MODLOAD_EX).
const MODULE_RECORD_SIZE: u32 = 0x12c;
/// Export 51's record: the export 142 record without its size dword.
pub(crate) const MODULE_RECORD_SHORT_SIZE: usize = 0x124;
const MODULE_SNAPSHOT_TAG: PoolTag = PoolTag::new(*b"dmwm");
const MODULE_SNAPSHOT_CAPACITY: u32 = 10;
/// Section snapshot record of export 52 (DMN_SECTIONLOAD).
const SECTION_RECORD_SIZE: u32 = 0x110;
const SECTION_SNAPSHOT_TAG: PoolTag = PoolTag::new(*b"dmws");
const SECTION_SNAPSHOT_CAPACITY: u16 = 5;
const MODULE_FLAG_DLL: u32 = 4;
const WALK_LIMIT: u32 = 0xa000_0000;
const MEMORY_STATISTICS_LENGTH: u32 = 0x68;
const MEMORY_STATISTICS_REPLY_LENGTH: u32 = 0x90;
const MONITOR_STATISTICS_LENGTH: u32 = 0x30;

fn write_u32(address: u32, value: u32) {
    // SAFETY: the importer passed a writable dword.
    unsafe { core::ptr::write_unaligned(address as usize as *mut u32, value) }
}

fn write_u16(address: u32, value: u16) {
    // SAFETY: the importer passed a writable word.
    unsafe { core::ptr::write_unaligned(address as usize as *mut u16, value) }
}

fn write_u8(address: u32, value: u8) {
    // SAFETY: the importer passed a writable byte.
    unsafe { core::ptr::write_volatile(address as usize as *mut u8, value) }
}

fn read_u8(address: u32) -> u8 {
    // SAFETY: the importer or the loader supplied a readable byte.
    unsafe { core::ptr::read_volatile(address as usize as *const u8) }
}

/// `strncpy`: copy up to `count` bytes of a NUL-terminated string and pad
/// the rest of `count` with zeros.
fn copy_string(destination: u32, source: &[u8], count: u32) {
    for index in 0..count {
        write_u8(
            destination + index,
            source.get(index as usize).copied().unwrap_or(0),
        );
    }
}

fn caller_string<'a>(address: u32) -> &'a [u8] {
    // SAFETY: the importer passes a NUL-terminated string.
    unsafe { CStr::from_ptr(address as usize as *const c_char) }.to_bytes()
}

/// A memory copy of exports 10 and 40, passed to the server thread by
/// address.
#[repr(C)]
struct Transfer {
    address: u32,
    length: u32,
    buffer: u32,
    count: u32,
}

/// The byte loop of exports 10 and 40: pages are checked when the loop
/// enters a new page, and an invalid page or a byte that fails ends the
/// copy before the next byte. Without a count pointer, stock reports
/// 0x82da0004 whenever its down counter did not end at zero, which
/// includes every complete copy.
fn copy_bytes(request: &Transfer, mut step: impl FnMut(u32, u32) -> bool) -> CommandResult {
    let mut remaining = request.length;
    let mut valid = true;
    let mut page = request.address.wrapping_add(0x1000);
    let mut current = request.address;
    let mut count = 0u32;
    loop {
        let more = remaining != 0;
        remaining = remaining.wrapping_sub(1);
        if !more || !valid {
            break;
        }
        if (page ^ current) & !0xfff != 0 {
            page = current & !0xfff;
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
    if request.count != 0 {
        write_u32(request.count, count);
    }
    if remaining != 0 && request.count == 0 {
        Err(ErrorCode::MemoryNotMapped.into())
    } else {
        Ok(Reply::Ok)
    }
}

/// Stock export 10 (0x91f33730): `(address, length, buffer, count) ->
/// HRESULT`; read through the debugger with breakpoint bytes shown as
/// their saved originals.
extern "C" fn get_memory(address: u32, length: u32, buffer: u32, count: u32) -> u32 {
    if buffer == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let mut request = Transfer {
        address,
        length,
        buffer,
        count,
    };
    dispatcher::call_on_server_with(
        &mut request,
        |server, _console, _network, request: &mut Transfer| {
            reply::hresult(copy_bytes(request, |current, index| {
                match server
                    .state
                    .debugger
                    .shadow_read(current)
                    .or_else(|| read_debug_byte(current))
                {
                    Some(byte) => {
                        write_u8(request.buffer + index, byte);
                        true
                    }
                    None => false,
                }
            }))
            .0
        },
    )
    .unwrap_or(SERVER_UNAVAILABLE.0)
}
export!(10, get_memory);

/// Stock export 40 (0x91f337f8): `(address, length, buffer, count) ->
/// HRESULT`; write through the debugger, updating the saved original of a
/// byte under a breakpoint.
extern "C" fn set_memory(address: u32, length: u32, buffer: u32, count: u32) -> u32 {
    if buffer == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let mut request = Transfer {
        address,
        length,
        buffer,
        count,
    };
    dispatcher::call_on_server_with(
        &mut request,
        |server, _console, _network, request: &mut Transfer| {
            reply::hresult(copy_bytes(request, |current, index| {
                let byte = read_u8(request.buffer + index);
                server.state.debugger.shadow_write(current, byte) || write_debug_byte(current, byte)
            }))
            .0
        },
    )
    .unwrap_or(SERVER_UNAVAILABLE.0)
}
export!(40, set_memory);

/// Stock export 12 (0x91f33ce0): `(module, ordinal, address) -> HRESULT`.
extern "C" fn get_proc_address(module: u32, ordinal: u32, address: u32) -> u32 {
    if ordinal == 0 || address == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    // SAFETY: the caller supplies a writable dword at `address`, which the
    // check above requires to be nonzero.
    let status =
        unsafe { xboxkrnl::XexGetProcedureAddress(module, ordinal, address as usize as *mut u32) };
    if (status.0 as i32) < 0 {
        return ErrorCode::FileNotFound.hresult().0;
    }
    Hresult::OK.0
}
export!(12, get_proc_address);

/// Bytes of the drive path in a DM_XBE.
const XBE_PATH_CAPACITY: usize = 0x105;

/// Stock export 16 (0x91f34448 -> 0x91f33c38 with flags 0): `(name, info)
/// -> HRESULT`; the running executable's drive path, whatever the name,
/// with zero timestamp, checksum, and stack size.
extern "C" fn get_xbe_info(_name: u32, info: u32) -> u32 {
    if info == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let mut info = info;
    dispatcher::call_on_server_with(&mut info, |server, console, _network, info: &mut u32| {
        let info = *info;
        let mut object = [0u8; memory::EXECUTABLE_PATH_CAPACITY];
        let length = console.running_executable_path(&mut object);
        let mut path = [0u8; XBE_PATH_CAPACITY];
        let length = server.state.filesystem.drives.object_path_to_drive_path(
            console,
            &object[..length],
            &mut path,
        );
        for (offset, byte) in path[..length].iter().chain(&[0]).enumerate() {
            write_u8(info + offset as u32, *byte);
        }
        for offset in [0x108, 0x10c, 0x110] {
            write_u32(info + offset, 0);
        }
        Hresult::OK.0
    })
    .unwrap_or(SERVER_UNAVAILABLE.0)
}
export!(16, get_xbe_info);

/// Fill the export 142 record at `record` for a loader entry.
fn fill_module_record(record: u32, entry: &LdrDataTableEntry, header: &ImageNtHeaders) {
    write_u32(record, MODULE_RECORD_SIZE);
    // 0x91f485b8: the low byte of each name unit, at most 0x103 bytes.
    let units = u32::from(entry.base_dll_name.length >> 1);
    let buffer = entry.base_dll_name.buffer;
    let mut length = 0;
    while length < units && length < 0x103 {
        write_u8(record + 4 + length, read_u16(buffer + length * 2) as u8);
        length += 1;
    }
    write_u8(record + 4 + length, 0);
    let base = entry.dll_base;
    write_u32(record + 0x108, base);
    write_u32(record + 0x10c, entry.image_size);
    write_u32(record + 0x114, header.optional_header.check_sum.get());
    write_u32(record + 0x110, header.file_header.time_date_stamp.get());
    write_u32(record + 0x128, header.optional_header.size_of_image.get());
    let mut pdata_size = 0u32;
    // SAFETY: `base` is the image of a loaded entry, held by the caller's
    // loader lock.
    let pdata = unsafe {
        RtlImageDirectoryEntryToData(base, true, ImageDirectory::Exception, &mut pdata_size)
    };
    write_u32(record + 0x11c, pdata);
    write_u32(record + 0x120, pdata_size);
    let dll = header
        .file_header
        .characteristics()
        .contains(ImageCharacteristics::DLL);
    write_u32(record + 0x118, if dll { MODULE_FLAG_DLL } else { 0 });
}

/// Allocate and fill a module snapshot, growing it until every reported
/// module fits. Layout: count, next index, then records.
fn module_snapshot() -> Option<u32> {
    let mut capacity = MODULE_SNAPSHOT_CAPACITY;
    let mut snapshot = 0u32;
    loop {
        if snapshot != 0 {
            capacity = read_u32(snapshot);
            // SAFETY: `snapshot` is the pool block allocated on the previous pass.
            unsafe { xboxkrnl::ExFreePool(snapshot) };
        }
        let size = capacity.wrapping_mul(MODULE_RECORD_SIZE).wrapping_add(8);
        // SAFETY: pool allocation has no pointer arguments.
        snapshot = unsafe { xboxkrnl::ExAllocatePoolWithTag(size, MODULE_SNAPSHOT_TAG) };
        if snapshot == 0 {
            return None;
        }
        // SAFETY: the pool block holds `size` bytes.
        unsafe { core::ptr::write_bytes(snapshot as usize as *mut u8, 0, size as usize) };
        {
            let lock = LoaderLock::acquire();
            for entry in all_entries(&lock) {
                if !is_reported(entry) {
                    continue;
                }
                let Some(header) = nt_header(entry) else {
                    continue;
                };
                let count = read_u32(snapshot);
                if count < capacity {
                    fill_module_record(snapshot + 8 + count * MODULE_RECORD_SIZE, entry, header);
                }
                write_u32(snapshot, count + 1);
            }
        }
        if capacity >= read_u32(snapshot) {
            return Some(snapshot);
        }
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
fn next_loaded_module(walk: u32, record: u32) -> Result<(), ModuleWalkError> {
    if walk == 0 || record == 0 {
        return Err(ModuleWalkError::InvalidArgument);
    }
    let mut snapshot = read_u32(walk);
    if snapshot == 0 {
        snapshot = module_snapshot().ok_or(ModuleWalkError::OutOfMemory)?;
        write_u32(walk, snapshot);
    }
    let count = read_u32(snapshot);
    let index = read_u32(snapshot + 4);
    if index == count {
        return Err(ModuleWalkError::End);
    }
    let size = read_u32(record).min(MODULE_RECORD_SIZE);
    write_u32(snapshot + 4, index + 1);
    // SAFETY: the record lies in the snapshot; the caller's record holds
    // the size it declared.
    unsafe {
        core::ptr::copy(
            (snapshot + 8 + index * MODULE_RECORD_SIZE) as usize as *const u8,
            record as usize as *mut u8,
            size as usize,
        )
    };
    write_u32(record, size);
    Ok(())
}

/// Stock export 142 (0x91f338c0): `(walk, record) -> HRESULT`;
/// [`next_loaded_module`].
extern "C" fn walk_loaded_modules(walk: u32, record: u32) -> u32 {
    export_result(next_loaded_module(walk, record)).0
}
export!(142, walk_loaded_modules);

/// [`next_loaded_module`] with a 0x124-byte record that has no size dword.
fn next_short_module(walk: u32, record: u32) -> Result<(), ModuleWalkError> {
    let mut full = [0u32; MODULE_RECORD_SIZE as usize / 4];
    full[0] = MODULE_RECORD_SIZE;
    next_loaded_module(walk, full.as_mut_ptr() as usize as u32)?;
    // SAFETY: the caller's record holds 0x124 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            full.as_ptr().cast::<u8>().add(4),
            record as usize as *mut u8,
            MODULE_RECORD_SHORT_SIZE,
        )
    };
    Ok(())
}

/// The next module of the walk `walk` (0 before the first call), as export
/// 51 returns it.
pub(crate) fn next_module(
    walk: &mut u32,
    record: &mut [u32; MODULE_RECORD_SHORT_SIZE / 4],
) -> Result<(), ModuleWalkError> {
    next_short_module(
        core::ptr::from_mut(walk) as usize as u32,
        record.as_mut_ptr() as usize as u32,
    )
}

/// Stock export 51 (0x91f33af8): `(walk, record) -> HRESULT`;
/// [`next_short_module`].
extern "C" fn walk_modules(walk: u32, record: u32) -> u32 {
    export_result(next_short_module(walk, record)).0
}
export!(51, walk_modules);

/// Fill one export 52 record from a section header (0x91f33b88).
fn fill_section_record(record: u32, section: &ImageSectionHeader, base: u32) {
    let info = section_info(section, base);
    for (offset, &byte) in info.name.iter().enumerate() {
        write_u8(record + offset as u32, byte);
    }
    write_u32(record + 0x104, info.address);
    write_u32(record + 0x108, info.size);
    write_u16(record + 0x10e, info.flags() as u16);
}

/// Stock export 52 (0x91f340d0): `(walk, module name, record) ->
/// HRESULT`; the next section of a snapshot of the named module's section
/// table. Layout: u16 count, u16 next index, then records.
extern "C" fn walk_module_sections(walk: u32, name: u32, record: u32) -> u32 {
    if walk == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let mut snapshot = read_u32(walk);
    if snapshot != 0 {
        if record == 0 {
            return Hresult::INVALID_ARGUMENT.0;
        }
    } else {
        if name == 0 {
            return Hresult::INVALID_ARGUMENT.0;
        }
        let name = caller_string(name);
        let mut capacity = SECTION_SNAPSHOT_CAPACITY;
        loop {
            let mut found = false;
            if snapshot != 0 {
                capacity = read_u16(snapshot);
                // SAFETY: `snapshot` is the pool block allocated on the previous pass.
                unsafe { xboxkrnl::ExFreePool(snapshot) };
            }
            let size = u32::from(capacity) * SECTION_RECORD_SIZE + 4;
            // SAFETY: pool allocation has no pointer arguments.
            snapshot = unsafe { xboxkrnl::ExAllocatePoolWithTag(size, SECTION_SNAPSHOT_TAG) };
            if snapshot == 0 {
                return Hresult::OUT_OF_MEMORY.0;
            }
            // SAFETY: the pool block holds `size` bytes.
            unsafe { core::ptr::write_bytes(snapshot as usize as *mut u8, 0, size as usize) };
            {
                let lock = LoaderLock::acquire();
                if let Some(entry) = find_entry(&lock, name) {
                    let base = entry.dll_base;
                    if let Some(header) = nt_header(entry) {
                        let count = header.file_header.number_of_sections.get();
                        found = true;
                        write_u16(snapshot, count);
                        if count <= capacity {
                            // SAFETY: the headers of a loaded image, mapped
                            // under the loader lock.
                            let sections = unsafe { header.sections() };
                            for (index, section) in (0..count).zip(sections) {
                                let entry_record =
                                    snapshot + 4 + u32::from(index) * SECTION_RECORD_SIZE;
                                fill_section_record(entry_record, section, base);
                                write_u16(entry_record + 0x10c, index + 1);
                            }
                        }
                    }
                }
            }
            if !found {
                // SAFETY: `snapshot` was allocated above and is not returned.
                unsafe { xboxkrnl::ExFreePool(snapshot) };
                return NO_SUCH_MODULE.0;
            }
            if read_u16(snapshot) <= capacity {
                break;
            }
        }
        write_u32(walk, snapshot);
        if record == 0 {
            return Hresult::OK.0;
        }
    }
    let count = read_u16(snapshot);
    let index = read_u16(snapshot + 2);
    if index == count {
        return Hresult::END_OF_DATA.0;
    }
    write_u16(snapshot + 2, index + 1);
    // SAFETY: the record lies in the snapshot; the caller's record holds
    // 0x110 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (snapshot + 4 + u32::from(index) * SECTION_RECORD_SIZE) as usize as *const u8,
            record as usize as *mut u8,
            SECTION_RECORD_SIZE as usize,
        )
    };
    Hresult::OK.0
}
export!(52, walk_module_sections);

/// Stock export 75 (0x91f331c8): `(statistics) -> HRESULT`.
extern "C" fn query_memory_statistics(statistics: u32) -> u32 {
    // SAFETY: the importer passes a 0x30-byte statistics block.
    let block = unsafe { &mut *(statistics as usize as *mut [u32; 12]) };
    match crate::backend::performance::memory_statistics(block) {
        Ok(()) => Hresult::OK.0,
        Err(error) => Hresult::from(error).0,
    }
}
export!(75, query_memory_statistics);

/// The kernel's memory statistics through the debug monitor service, or
/// `MmQueryStatistics` when the service fails or replies short.
fn kernel_memory_statistics(
    output: &mut [u32; MEMORY_STATISTICS_LENGTH as usize / 4],
) -> Result<(), KernelError> {
    let mut reply = [0u32; MEMORY_STATISTICS_REPLY_LENGTH as usize / 4];
    reply[0] = MEMORY_STATISTICS_REPLY_LENGTH;
    reply[1] = MEMORY_STATISTICS_LENGTH;
    // SAFETY: `reply` is a live local of the length stored in its first word.
    let status = unsafe {
        xboxkrnl::ExDebugMonitorService(
            DebugMonitorService::MemoryStatistics,
            reply.as_mut_ptr() as usize as u32,
            0,
            0,
        )
    };
    if (status.0 as i32) >= 0 && reply[0] >= MEMORY_STATISTICS_REPLY_LENGTH {
        let length = output.len();
        output.copy_from_slice(&reply[1..1 + length]);
        return status.result();
    }
    output[0] = MEMORY_STATISTICS_LENGTH;
    // SAFETY: `output` is a live statistics block whose first word holds its length.
    unsafe { xboxkrnl::MmQueryStatistics(output.as_mut_ptr().cast::<MmStatistics>()) }.result()
}

/// Stock export 165 (0x91f33318): `(statistics) -> HRESULT`; page counts
/// by use, with the total as their sum.
extern "C" fn query_memory_usage(statistics: u32) -> u32 {
    if read_u32(statistics) != MONITOR_STATISTICS_LENGTH {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let mut s = [0u32; MEMORY_STATISTICS_LENGTH as usize / 4];
    if let Err(error) = kernel_memory_statistics(&mut s) {
        return Hresult::from(error).0;
    }
    let total = s[6..14]
        .iter()
        .fold(s[3], |sum, &value| sum.wrapping_add(value));
    let word = |index: u32, value: u32| write_u32(statistics + index * 4, value);
    word(1, total);
    word(2, s[3]);
    word(3, s[8]);
    word(4, s[12]);
    word(5, 0);
    word(6, s[7]);
    word(7, s[10].wrapping_add(s[11]));
    word(8, s[9]);
    word(9, s[13]);
    word(10, s[6]);
    word(11, 0);
    Hresult::OK.0
}
export!(165, query_memory_usage);

/// Stock export 77 (0x91f234b8): `(type, buffer, size) -> HRESULT`; the
/// name of an allocation type, truncated to the buffer; 1 when truncated.
extern "C" fn get_tracking_type_name(kind: u32, buffer: u32, size: u32) -> u32 {
    let kind = kind as u16;
    if u32::from(kind) >= TRACKING_TYPE_COUNT.load(Ordering::Acquire) {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let name = tracking_type_name_bytes(kind);
    copy_string(buffer, name, size);
    write_u8(buffer.wrapping_add(size).wrapping_sub(1), 0);
    if name.len() as u32 + 1 > size {
        1
    } else {
        Hresult::OK.0
    }
}
export!(77, get_tracking_type_name);

/// Stock export 78 (0x91f23a30): `(name, type) -> HRESULT`; register an
/// allocation type name and store its index through `type` (u16).
extern "C" fn register_tracking_type(name: u32, kind: u32) -> u32 {
    if !memory::TrackingFlags::from_bits_retain(TRACKING.flags.load(Ordering::Relaxed))
        .intersects(memory::TrackingFlags::TYPE_MASK)
    {
        return tracking_hresult(Err(TrackingError::Off)).0;
    }
    if TRACKING_TYPE_COUNT.load(Ordering::Acquire) > 0xffff {
        return TOO_MANY_NAMES;
    }
    let source = caller_string(name);
    let length = source.len() as u32 + 1;
    // SAFETY: pool allocation has no pointer arguments.
    let copy = unsafe { xboxkrnl::ExAllocatePoolWithTag(length, PoolTag::new(*b"xbdm")) };
    if copy == 0 {
        return Hresult::OUT_OF_MEMORY.0;
    }
    copy_string(copy, source, length);
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
    write_u16(kind, index as u16);
    Hresult::OK.0
}
export!(78, register_tracking_type);

/// Stock export 79 (0x91f23df0): `(address, size, type) -> HRESULT`; track
/// an allocation of a registered type.
extern "C" fn track_registered_allocation(address: u32, size: u32, kind: u32) -> u32 {
    let kind = kind as u16;
    if usize::from(kind) < memory::TRACKING_TYPE_NAMES.len() {
        return Hresult::INVALID_ARGUMENT.0;
    }
    tracking_hresult(track_allocation(address, size, kind)).0
}
export!(79, track_registered_allocation);

/// Stock export 80 (0x91f23e20): `(address, size, type) -> HRESULT`.
extern "C" fn untrack_registered_allocation(address: u32, size: u32, kind: u32) -> u32 {
    let kind = kind as u16;
    if usize::from(kind) < memory::TRACKING_TYPE_NAMES.len() {
        return Hresult::INVALID_ARGUMENT.0;
    }
    match untrack_allocation(address, size, kind) {
        Untracked::Skipped(result) | Untracked::Lookup(result) => tracking_hresult(result).0,
    }
}
export!(80, untrack_registered_allocation);

/// Stock export 123 (0x91f33e48): `(cursor, region) -> HRESULT`; the next
/// valid range at or after `*cursor` below 0xa0000000 as base, size, and
/// protection, advancing the cursor past the page that ended it.
extern "C" fn walk_committed_memory(cursor: u32, region: u32) -> u32 {
    if region == 0 {
        return BAD_PARAMETER.0;
    }
    loop {
        let start = read_u32(cursor);
        if start >= WALK_LIMIT {
            return Hresult::END_OF_DATA.0;
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
        write_u32(cursor, memory::next_page(end));
        if end > start {
            let protect = if (0x8000_0000..=0x9fff_ffff).contains(&start) {
                0x40
            } else {
                4
            };
            write_u32(region, start);
            write_u32(region + 4, end - start);
            write_u32(region + 8, protect);
            return Hresult::OK.0;
        }
    }
}
export!(123, walk_committed_memory);

/// Stock export 143 (0x91f342f0): `(module, key, buffer, buffer size,
/// size) -> HRESULT`; copy an XEX header field of a loaded module. `size`
/// receives the field size; a short buffer gets a truncated copy and
/// 0x82da0105.
extern "C" fn get_xex_header_field(
    module: u32,
    key: u32,
    buffer: u32,
    buffer_size: u32,
    size: u32,
) -> u32 {
    if module == 0 || size == 0 || (buffer == 0 && buffer_size != 0) {
        return Hresult::INVALID_ARGUMENT.0;
    }
    write_u32(size, 0);
    let lock = LoaderLock::acquire();
    let Some(entry) = find_entry(&lock, caller_string(module)) else {
        return NO_SUCH_MODULE.0;
    };
    // SAFETY: the entry's XEX header stays mapped under the loader lock.
    let field = unsafe { RtlImageXexHeaderField(entry.xex_header_base, XexHeaderKey(key)) };
    if field == 0 {
        return Hresult::NO_SUCH_FIELD.0;
    }
    let mut truncated = false;
    match key & 0xff {
        0 => {}
        1 => write_u32(size, 4),
        0xff => write_u32(size, read_u32(field)),
        words => write_u32(size, words << 2),
    }
    let length = read_u32(size);
    if length != 0 && buffer != 0 {
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
                field as usize as *const u8,
                buffer as usize as *mut u8,
                count as usize,
            )
        };
    } else if key == XexHeaderKey::ENTRY_POINT.0 {
        write_u32(size, 4);
        if buffer != 0 {
            if buffer_size < 4 {
                truncated = true;
            } else {
                write_u32(buffer, field);
            }
        }
    }
    if truncated {
        Hresult::BUFFER_TOO_SMALL.0
    } else {
        Hresult::OK.0
    }
}
export!(143, get_xex_header_field);

/// Stock export 145 (0x91f282a8): `(base, record) -> HRESULT`; GUID, age,
/// and PDB path of the module loaded at `base`.
pub(crate) extern "C" fn get_module_debug_directory(base: u32, record: u32) -> u32 {
    let Some(code_view) = code_view_of(base) else {
        return NOT_FOUND;
    };
    for (offset, byte) in code_view.guid.iter().chain(&code_view.age).enumerate() {
        write_u8(record + offset as u32, *byte);
    }
    copy_string(
        record + 0x14,
        code_view.path(),
        memory::PDB_PATH_CAPACITY as u32,
    );
    write_u8(record + 0x117, 0);
    Hresult::OK.0
}
export!(145, get_module_debug_directory);

/// Stock export 212 (0x91f51538): `(size) -> HRESULT`; the running title's
/// additional title memory while the console runs its extra memory, else 0.
extern "C" fn get_title_workspace_size(size: u32) -> u32 {
    if size == 0 {
        return BAD_PARAMETER.0;
    }
    write_u32(size, 0);
    let mut size = size;
    dispatcher::call_on_server_with(&mut size, |_server, console, _network, size: &mut u32| {
        let size = *size;
        if console::console_memory(console).value() & 2 == 0 {
            return Hresult::OK.0;
        }
        match console.title_xex_dword(memory::XexFieldKey(XexHeaderKey::ADDITIONAL_TITLE_MEMORY.0))
        {
            Ok(Some(value)) => {
                write_u32(size, value);
                Hresult::OK.0
            }
            Ok(None) => Hresult::OK.0,
            Err(memory::NoSuchModule) => NO_SUCH_MODULE.0,
        }
    })
    .unwrap_or(SERVER_UNAVAILABLE.0)
}
export!(212, get_title_workspace_size);
