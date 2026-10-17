//! Module snapshot block (stock export 131, 0x91f282b0; export 132 frees
//! it): the loaded modules and console facts that capture and trace files
//! embed.

use core::sync::atomic::Ordering;

use openxbdm_server::Server;
use xbox360_sys::image::CodeViewRsds;
use xbox360_sys::image::DebugType;
use xbox360_sys::image::ImageDebugDirectory;
use xbox360_sys::image::ImageDirectory;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::ExLoadedImageName;
use xbox360_sys::xboxkrnl::LdrDataTableEntry;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::RtlImageDirectoryEntryToData;

use crate::backend::Console;
use crate::backend::console;
use crate::backend::dispatcher;
use crate::exports::export;
use crate::kernel;
use crate::net::XamNetwork;

/// Bytes of the block.
pub(crate) const SIZE: u32 = 0xc000;
/// Physical memory type of the block (`MmFreePhysicalMemory` takes it too).
const MEMORY_TYPE: xboxkrnl::MemoryRegion = xboxkrnl::MemoryRegion::Title;
const VERSION: u32 = 0xa;
const MODULE_CAPACITY: u32 = 0x80;
/// Module records start at +8.
const RECORDS: u32 = 8;
const RECORD_SIZE: u32 = 0x150;
/// Longest module name, in characters, that a record holds.
const NAME_LIMIT: u32 = 0x2a;
/// Longest executable and debug file path kept, in bytes.
pub(crate) const PATH_LIMIT: usize = 0x103;
const CAPTURE_START_TIME: u32 = 0xa808;
const XBOX_NAME: u32 = 0xa814;
const XBOX_NAME_SIZE: usize = 0x100;
const PROCESSOR_COUNT: u32 = 0xa914;
const CAPTURE_PREVIOUS_FLAGS: u32 = 0xa918;
const EXECUTABLE: u32 = 0xa934;
const MAGIC: u32 = 0xaa38;
const MAGIC_VALUE: u32 = 0x5308;
const PERFORMANCE_FREQUENCY: u32 = 0xaa3c;

/// Capture state the block records.
#[derive(Clone, Copy)]
pub(crate) struct CaptureFields {
    /// System time of the last capture start (stock 0x91fae7f8).
    pub start_time: u64,
    /// Capture flags before the last capture stop (stock 0x91fae800).
    pub previous_flags: u32,
}

/// An allocated snapshot block.
pub(crate) struct Snapshot(u32);

impl Snapshot {
    pub(crate) fn address(&self) -> u32 {
        self.0
    }
}

fn read_u32(address: u32) -> u32 {
    // SAFETY: callers pass addresses of loaded images, loader entries, or
    // the block.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn read_u16(address: u32) -> u16 {
    // SAFETY: as `read_u32`.
    unsafe { core::ptr::read_volatile(address as usize as *const u16) }
}

fn read_u8(address: u32) -> u8 {
    // SAFETY: as `read_u32`.
    unsafe { core::ptr::read_volatile(address as usize as *const u8) }
}

fn write_u32(address: u32, value: u32) {
    // SAFETY: callers pass addresses inside the block.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

fn write_u8(address: u32, value: u8) {
    // SAFETY: callers pass addresses inside the block.
    unsafe { core::ptr::write_volatile(address as usize as *mut u8, value) }
}

fn write_bytes(address: u32, bytes: &[u8]) {
    for (offset, &byte) in bytes.iter().enumerate() {
        write_u8(address + offset as u32, byte);
    }
}

/// Copy a NUL-terminated string of at most `limit` bytes.
fn copy_string(destination: u32, source: u32, limit: u32) {
    for offset in 0..limit {
        let byte = read_u8(source + offset);
        if byte == 0 {
            return;
        }
        write_u8(destination + offset, byte);
    }
}

/// The loader entry at `entry`.
///
/// # Safety
///
/// `entry` must be linked into a loader module list of the debug monitor
/// data while the caller holds the loader lock.
unsafe fn loader_entry<'a>(entry: u32) -> &'a LdrDataTableEntry {
    // SAFETY: guaranteed by the caller.
    unsafe { &*core::ptr::with_exposed_provenance::<LdrDataTableEntry>(entry as usize) }
}

fn contains(head: u32, base: u32) -> bool {
    if head == 0 {
        return false;
    }
    let mut entry = read_u32(head);
    while entry != head {
        // SAFETY: `entry` is on the list at `head`; the caller holds the
        // loader lock.
        let current = unsafe { loader_entry(entry) };
        if current.dll_base == base {
            return true;
        }
        entry = current.in_load_order_links.flink.load(Ordering::Relaxed);
    }
    false
}

/// Debug directory of a loaded image, looked up as stock 0x91f280d8 does
/// with the loader lock already held.
fn debug_directory(base: u32, lists: [u32; 2]) -> Option<&'static [ImageDebugDirectory]> {
    let mut size = 0u32;
    for list in lists {
        if contains(list, base) {
            // SAFETY: `base` is a loaded image on a list whose lock the
            // caller holds; `size` is a live u32.
            let directory = unsafe {
                RtlImageDirectoryEntryToData(base, true, ImageDirectory::Debug, &mut size)
            };
            if directory != 0 && size != 0 {
                // SAFETY: the debug directory of a mapped image holds `size`
                // bytes and stays mapped under the loader lock.
                return Some(unsafe {
                    core::slice::from_raw_parts(
                        core::ptr::with_exposed_provenance::<ImageDebugDirectory>(
                            directory as usize,
                        ),
                        size as usize / core::mem::size_of::<ImageDebugDirectory>(),
                    )
                });
            }
        }
    }
    None
}

/// Store the CodeView age, GUID, and debug file path of `base` in
/// `record`; any CodeView entry selects the record named by the first
/// entry, as in stock 0x91f280d8.
fn store_code_view(record: u32, base: u32, lists: [u32; 2]) {
    let Some(entries) = debug_directory(base, lists) else {
        return;
    };
    if !entries
        .iter()
        .any(|entry| entry.debug_type() == DebugType::CODEVIEW)
    {
        return;
    }
    let Some(first) = entries.first() else {
        return;
    };
    let code_view = base.wrapping_add(first.address_of_raw_data.get());
    if code_view == 0 {
        return;
    }
    // SAFETY: the debug data of a mapped image lies in the image.
    let rsds = unsafe { &*core::ptr::with_exposed_provenance::<CodeViewRsds>(code_view as usize) };
    if rsds.signature != CodeViewRsds::SIGNATURE {
        return;
    }
    write_u32(record + 0x38, u32::from_ne_bytes(rsds.age.bytes()));
    for (word, bytes) in rsds.guid.chunks_exact(4).enumerate() {
        write_u32(
            record + 0x3c + 4 * word as u32,
            u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        );
    }
    copy_string(
        record + 0x4c,
        code_view + core::mem::offset_of!(CodeViewRsds, path) as u32,
        PATH_LIMIT as u32,
    );
}

/// Write one module record; false when the name does not fit.
fn store_module(record: u32, entry: &LdrDataTableEntry, lists: [u32; 2]) -> bool {
    let base = entry.dll_base;
    write_u32(record, base);
    write_u32(record + 8, entry.time_date_stamp.swap_bytes());
    write_u32(record + 4, entry.image_size);
    let characters = u32::from(entry.base_dll_name.length) >> 1;
    if characters > NAME_LIMIT {
        super::pmc::print(
            c"PERF: ignore module \"%wZ\" because the name is too long.\n",
            &[core::ptr::from_ref(&entry.base_dll_name).addr() as u64],
        );
        return false;
    }
    let name = entry.base_dll_name.buffer;
    for index in 0..characters {
        write_u8(record + 0xc + index, read_u16(name + 2 * index) as u8);
    }
    store_code_view(record, base, lists);
    true
}

/// Allocate and fill a snapshot block. `executable` is the drive path of
/// the running executable (stock converts the object path through the
/// drive table, 0x91f33c38).
pub(crate) fn build(executable: &[u8], capture: CaptureFields) -> Option<Snapshot> {
    // SAFETY: physical allocation of SIZE bytes; the result is checked below.
    let block = unsafe {
        xboxkrnl::MmAllocatePhysicalMemoryEx(
            MEMORY_TYPE,
            SIZE,
            PageProtection::READWRITE,
            0,
            u32::MAX,
            0x1000,
        )
    };
    if block == 0 {
        return None;
    }
    // SAFETY: the allocation holds `SIZE` bytes.
    unsafe { core::ptr::write_bytes(block as usize as *mut u8, 0, SIZE as usize) };
    let data = kernel::debug_monitor_data();
    let lists = [
        data.loaded_module_list.load(Ordering::Relaxed),
        data.loaded_usermode_module_list.load(Ordering::Relaxed),
    ];
    write_u32(block, VERSION);
    write_u32(
        block + PROCESSOR_COUNT,
        data.processor_count.load(Ordering::Relaxed),
    );
    write_u32(block + MAGIC, MAGIC_VALUE);
    write_u32(block + CAPTURE_PREVIOUS_FLAGS, capture.previous_flags);
    let frequency = kernel::performance_frequency();
    write_u32(block + PERFORMANCE_FREQUENCY, (frequency >> 32) as u32);
    write_u32(block + PERFORMANCE_FREQUENCY + 4, frequency as u32);
    write_bytes(
        block + EXECUTABLE,
        &executable[..executable.len().min(PATH_LIMIT)],
    );

    let lock = data.loaded_module_list_lock.load(Ordering::Relaxed) as usize as *mut _;
    // SAFETY: the loader lock lives in the kernel debug monitor data.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(lock) };
    let mut count = 0;
    'lists: for head in lists {
        // Stock reads the second list head without a null check.
        if head == 0 {
            continue;
        }
        let mut entry = read_u32(head);
        while entry != head {
            if count >= MODULE_CAPACITY {
                break 'lists;
            }
            // SAFETY: `entry` is on a loader list of the debug monitor data,
            // under the loader lock acquired above.
            let current = unsafe { loader_entry(entry) };
            if current.dll_base != 0
                && store_module(block + RECORDS + count * RECORD_SIZE, current, lists)
            {
                count += 1;
            }
            entry = current.in_load_order_links.flink.load(Ordering::Relaxed);
        }
    }
    // SAFETY: acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(lock, irql) };

    write_u32(block + 4, count);
    write_u32(
        block + CAPTURE_START_TIME,
        (capture.start_time >> 32) as u32,
    );
    write_u32(block + CAPTURE_START_TIME + 4, capture.start_time as u32);
    let name = console::debug_name();
    let name = &name.as_bytes()[..name.as_bytes().len().min(XBOX_NAME_SIZE - 1)];
    write_bytes(block + XBOX_NAME, name);
    Some(Snapshot(block))
}

pub(crate) fn free(snapshot: Snapshot) {
    // SAFETY: the snapshot owns a block from `build`, consumed here.
    unsafe { xboxkrnl::MmFreePhysicalMemory(MEMORY_TYPE, snapshot.0) };
}

/// Object path of the running executable.
pub(crate) fn executable_object_path() -> &'static [u8] {
    // SAFETY: `data_imports_resolved` held at module load.
    let path =
        core::ptr::from_ref(unsafe { ExLoadedImageName.get_unchecked() }).expose_provenance() as u32;
    let mut length = 0;
    while read_u8(path + length) != 0 {
        length += 1;
    }
    // SAFETY: the export is a NUL-terminated string the kernel owns.
    unsafe { core::slice::from_raw_parts(path as usize as *const u8, length as usize) }
}

/// Request of [`drive_path_on_server`].
struct DrivePath<'a> {
    object: &'a [u8],
    output: &'a mut [u8],
    length: usize,
}

fn drive_path_on_server(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    request: &mut DrivePath<'_>,
) -> u32 {
    request.length = server.state.filesystem.drives.object_path_to_drive_path(
        console,
        request.object,
        request.output,
    );
    0
}

/// Drive path of the running executable from a thread other than the
/// server's. Off the server, where the drive table cannot be read, the
/// object path is kept, which is what the conversion yields for a path
/// outside every drive.
pub(crate) fn executable_drive_path(output: &mut [u8; PATH_LIMIT + 2]) -> usize {
    let object = executable_object_path();
    let mut request = DrivePath {
        object,
        output,
        length: 0,
    };
    if dispatcher::call_on_server_with(&mut request, drive_path_on_server).is_some() {
        return request.length;
    }
    let length = object.len().min(PATH_LIMIT + 1);
    request.output[..length].copy_from_slice(&object[..length]);
    length
}

/// Export 131: a snapshot block, or null when it cannot be allocated.
extern "C" fn export_build() -> u32 {
    let mut executable = [0u8; PATH_LIMIT + 2];
    let length = executable_drive_path(&mut executable);
    build(&executable[..length], super::capture::snapshot_fields()).map_or(0, |snapshot| snapshot.0)
}
export!(131, export_build);

/// Export 132: free a block from export 131; null is ignored and returns 0.
/// Tail-calls MmFreePhysicalMemory, so its r3 passes through.
#[unsafe(naked)]
extern "C" fn export_free(_address: u32) -> u32 {
    core::arch::naked_asm!(
        "cmpwi 3, 0",
        "bne 1f",
        "blr",
        "1:",
        "mr 4, 3",
        "li 3, {kind}",
        "b {free}",
        kind = const MEMORY_TYPE as u32,
        free = sym xboxkrnl::MmFreePhysicalMemory,
    )
}
export!(132, export_free);
