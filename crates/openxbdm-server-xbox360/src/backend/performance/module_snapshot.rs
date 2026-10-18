//! Module snapshot block (stock export 131, 0x91f282b0; export 132 frees
//! it): the loaded modules and console facts that capture and trace files
//! embed.

use core::mem::offset_of;
use core::mem::size_of;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::memory::PAGE_SIZE;
use openxbdm_server::commands::performance::capture;
use openxbdm_server::commands::performance::capture::MAX_PROCESSORS;
use xbox360_sys::image::CodeViewRsds;
use xbox360_sys::image::DebugType;
use xbox360_sys::image::ImageDebugDirectory;
use xbox360_sys::image::ImageDirectory;
use xbox360_sys::image::Le32;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::ExLoadedImageName;
use xbox360_sys::xboxkrnl::LdrDataTableEntry;
use xbox360_sys::xboxkrnl::MemoryRegion;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::RtlImageDirectoryEntryToData;

use crate::backend::console;
use crate::backend::filesystem;
use crate::exports::export;
use crate::kernel;
use crate::kernel::LoaderLock;
use crate::kernel::ModuleList;

/// Bytes of the block.
pub(crate) const SIZE: u32 = 0xc000;
/// Longest executable and debug file path kept, in bytes.
pub(crate) const PATH_LIMIT: usize = 0x103;
const MODULE_CAPACITY: usize = 0x80;
/// Longest module name, in characters, that a record holds.
const NAME_LIMIT: u32 = 0x2a;

/// One loaded module of the block.
#[repr(C)]
struct ModuleRecord {
    base: u32,
    size: u32,
    /// PE timestamp of the image, byte-reversed.
    time_date_stamp: u32,
    /// Base name, the low byte of each UTF-16 code unit.
    name: [u8; 0x2c],
    /// CodeView age, GUID, and debug file path, as the image stores them.
    age: Le32,
    guid: [u8; 16],
    debug_path: [u8; PATH_LIMIT + 1],
}

/// The block (stock layout). Every field is a word or a byte array, so the
/// block has no padding and reads as words.
#[repr(C)]
struct ModuleSnapshot {
    version: u32,
    count: u32,
    records: [ModuleRecord; MODULE_CAPACITY],
    /// System time of the last capture start, high word first.
    capture_start_time: [u32; 2],
    _reserved_a810: u32,
    xbox_name: [u8; 0x100],
    processor_count: u32,
    capture_previous_flags: u32,
    /// Capture file bytes of each processor, stored by the capture writer.
    data_sizes: [u32; MAX_PROCESSORS],
    executable: [u8; PATH_LIMIT + 1],
    magic: u32,
    /// High word first.
    performance_frequency: [u32; 2],
    _reserved_aa44: [u8; 0x15bc],
}

impl ModuleSnapshot {
    const VERSION: u32 = 0xa;
    const MAGIC: u32 = 0x5308;
}

const _: () = {
    assert!(offset_of!(ModuleRecord, time_date_stamp) == 8);
    assert!(offset_of!(ModuleRecord, name) == 0xc);
    assert!(offset_of!(ModuleRecord, age) == 0x38);
    assert!(offset_of!(ModuleRecord, guid) == 0x3c);
    assert!(offset_of!(ModuleRecord, debug_path) == 0x4c);
    assert!(size_of::<ModuleRecord>() == 0x150);
    assert!(NAME_LIMIT < 0x2c);
    assert!(offset_of!(ModuleSnapshot, count) == 4);
    assert!(offset_of!(ModuleSnapshot, records) == 8);
    assert!(offset_of!(ModuleSnapshot, capture_start_time) == 0xa808);
    assert!(offset_of!(ModuleSnapshot, xbox_name) == 0xa814);
    assert!(offset_of!(ModuleSnapshot, processor_count) == 0xa914);
    assert!(offset_of!(ModuleSnapshot, capture_previous_flags) == 0xa918);
    assert!(offset_of!(ModuleSnapshot, data_sizes) == capture::FILE_DATA_SIZES);
    assert!(offset_of!(ModuleSnapshot, executable) == 0xa934);
    assert!(offset_of!(ModuleSnapshot, magic) == 0xaa38);
    assert!(offset_of!(ModuleSnapshot, performance_frequency) == 0xaa3c);
    assert!(size_of::<ModuleSnapshot>() == SIZE as usize);
    assert!(SIZE == capture::FILE_HEADER_SIZE);
};

/// Capture state the block records.
#[derive(Clone, Copy)]
pub(crate) struct CaptureFields {
    /// System time of the last capture start (stock 0x91fae7f8).
    pub start_time: u64,
    /// Capture flags before the last capture stop (stock 0x91fae800).
    pub previous_flags: u32,
}

/// An allocated snapshot block, owned until [`free`].
pub(crate) struct Snapshot(NonNull<ModuleSnapshot>);

impl Snapshot {
    pub(crate) fn address(&self) -> u32 {
        self.0.as_ptr().expose_provenance() as u32
    }

    /// The block as words.
    pub(crate) fn words(&self) -> &[u32; SIZE as usize / 4] {
        // SAFETY: the block is `SIZE` bytes, word aligned, without padding,
        // and initialized by `build`; `self` owns it.
        unsafe { self.0.cast().as_ref() }
    }

    /// Base address of each recorded module, in record order.
    pub(crate) fn module_bases(&self) -> impl Iterator<Item = u32> + '_ {
        // SAFETY: `self` owns the block that `build` initialized.
        let block = unsafe { self.0.as_ref() };
        block
            .records
            .iter()
            .take(block.count as usize)
            .map(|record| record.base)
    }

    /// Capture file bytes of each processor.
    pub(crate) fn data_sizes(&mut self) -> &mut [u32; MAX_PROCESSORS] {
        // SAFETY: `self` owns the initialized block.
        unsafe { &mut self.0.as_mut().data_sizes }
    }
}

/// Copy of the object path of the running executable. The kernel rewrites
/// the path when it starts a title, so it is copied before use.
pub(crate) struct ExecutableObjectPath {
    bytes: [u8; Self::CAPACITY],
    length: usize,
}

impl ExecutableObjectPath {
    /// Bytes of the kernel's `ExLoadedImageName` buffer, terminator
    /// included (K15574 symbols).
    const CAPACITY: usize = 0x100;

    #[inline(never)]
    pub(crate) fn read() -> Self {
        let mut path = Self {
            bytes: [0; Self::CAPACITY],
            length: 0,
        };
        path.length = copy_executable_object_path(&mut path.bytes);
        path
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

fn contains(lock: &LoaderLock, list: ModuleList, base: u32) -> bool {
    lock.entries(list).any(|entry| entry.dll_base == base)
}

/// Debug directory of a loaded image, looked up as stock 0x91f280d8 does
/// with the loader lock already held.
fn debug_directory(lock: &LoaderLock, base: u32) -> Option<&[ImageDebugDirectory]> {
    let mut size = 0u32;

    // Iterated by reference: the by-value array iterator is not inlined.
    for &list in &[ModuleList::Loaded, ModuleList::Usermode] {
        if !contains(lock, list, base) {
            continue;
        }

        // SAFETY: `base` is a loaded image on a list whose lock `lock`
        // holds; `size` is a live u32.
        let directory =
            unsafe { RtlImageDirectoryEntryToData(base, true, ImageDirectory::Debug, &mut size) };
        if directory != 0 && size != 0 {
            // SAFETY: the debug directory of a mapped image holds `size`
            // bytes and stays mapped under the loader lock.
            return Some(unsafe {
                core::slice::from_raw_parts(
                    core::ptr::with_exposed_provenance::<ImageDebugDirectory>(directory as usize),
                    size as usize / size_of::<ImageDebugDirectory>(),
                )
            });
        }
    }

    None
}

/// Store the CodeView age, GUID, and debug file path of `base` in
/// `record`; any CodeView entry selects the record named by the first
/// entry, as in stock 0x91f280d8.
fn store_code_view(record: &mut ModuleRecord, lock: &LoaderLock, base: u32) {
    let Some(entries) = debug_directory(lock, base) else {
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

    let code_view = core::ptr::with_exposed_provenance::<CodeViewRsds>(code_view as usize);
    // SAFETY: the debug data of a mapped image lies in the image, which
    // the loader lock keeps mapped.
    let header = unsafe { &*code_view };
    if header.signature != CodeViewRsds::SIGNATURE {
        return;
    }

    record.age = header.age;
    record.guid = header.guid;

    let path = code_view
        .cast::<u8>()
        .wrapping_add(offset_of!(CodeViewRsds, path));

    for index in 0..PATH_LIMIT {
        // SAFETY: the record's path is NUL-terminated in the image; the
        // loop stops at the NUL.
        let byte = unsafe { path.add(index).read() };
        if byte == 0 {
            return;
        }

        record.debug_path[index] = byte;
    }
}

/// Write one module record; false when the name does not fit.
fn store_module(record: &mut ModuleRecord, entry: &LdrDataTableEntry, lock: &LoaderLock) -> bool {
    let base = entry.dll_base;
    record.base = base;
    record.time_date_stamp = entry.time_date_stamp.swap_bytes();
    record.size = entry.image_size;

    let characters = u32::from(entry.base_dll_name.length) >> 1;
    if characters > NAME_LIMIT {
        super::pmc::print(
            c"PERF: ignore module \"%wZ\" because the name is too long.\n",
            &[core::ptr::from_ref(&entry.base_dll_name).addr() as u64],
        );
        return false;
    }

    let name = core::ptr::with_exposed_provenance::<u16>(entry.base_dll_name.buffer as usize);
    // Index loops: the slice iterator adapters here are not inlined.
    for index in 0..characters as usize {
        // SAFETY: the name buffer of a loader entry holds `characters` code
        // units and stays mapped under the loader lock.
        record.name[index] = unsafe { name.add(index).read() } as u8;
    }

    store_code_view(record, lock, base);

    true
}

/// Allocate and fill a snapshot block. `executable` is the drive path of
/// the running executable (stock converts the object path through the
/// drive table, 0x91f33c38).
pub(crate) fn build(executable: &[u8], capture: CaptureFields) -> Option<Snapshot> {
    // SAFETY: physical allocation of SIZE bytes; the result is checked below.
    let block = unsafe {
        xboxkrnl::MmAllocatePhysicalMemoryEx(
            MemoryRegion::Title,
            SIZE,
            PageProtection::READWRITE,
            0,
            u32::MAX,
            PAGE_SIZE,
        )
    };

    let mut block = NonNull::new(core::ptr::with_exposed_provenance_mut::<ModuleSnapshot>(
        block as usize,
    ))?;

    // SAFETY: the allocation holds `SIZE` bytes, page aligned, owned here
    // until it is returned; zero bytes are a valid `ModuleSnapshot`.
    let snapshot = unsafe {
        block.write_bytes(0, 1);
        block.as_mut()
    };

    let data = kernel::debug_monitor_data();
    snapshot.version = ModuleSnapshot::VERSION;
    snapshot.processor_count = data.processor_count.load(Ordering::Relaxed);
    snapshot.magic = ModuleSnapshot::MAGIC;
    snapshot.capture_previous_flags = capture.previous_flags;

    let frequency = kernel::performance_frequency();
    snapshot.performance_frequency = [(frequency >> 32) as u32, frequency as u32];

    let length = executable.len().min(PATH_LIMIT);
    snapshot.executable[..length].copy_from_slice(&executable[..length]);

    let count = {
        let lock = LoaderLock::acquire();
        let mut count = 0;
        for entry in lock.all_entries() {
            if count >= MODULE_CAPACITY {
                break;
            }

            if entry.dll_base != 0 && store_module(&mut snapshot.records[count], entry, &lock) {
                count += 1;
            }
        }

        count
    };

    snapshot.count = count as u32;
    snapshot.capture_start_time = [(capture.start_time >> 32) as u32, capture.start_time as u32];

    let name = console::debug_name();
    let name = &name.as_bytes()[..name.as_bytes().len().min(snapshot.xbox_name.len() - 1)];
    snapshot.xbox_name[..name.len()].copy_from_slice(name);

    Some(Snapshot(block))
}

/// Inlined: the call of [`free_title_memory`] is the whole body.
#[inline(always)]
pub(crate) fn free(snapshot: Snapshot) {
    // SAFETY: the snapshot owns a block from `build`, consumed here.
    unsafe { free_title_memory(snapshot.address()) };
}

/// Free physical title memory; the snapshot and the capture buffers share
/// this one copy.
///
/// # Safety
///
/// `address` must be 0 or a block from `MmAllocatePhysicalMemoryEx` in
/// [`MemoryRegion::Title`] that nothing uses any more.
#[inline(never)]
pub(super) unsafe fn free_title_memory(address: u32) {
    // SAFETY: guaranteed by the caller.
    unsafe { xboxkrnl::MmFreePhysicalMemory(MemoryRegion::Title, address) };
}

/// Copy the object path of the running executable into `output`, up to its
/// terminator or the end of `output`; returns the bytes copied.
#[inline(always)]
pub(crate) fn copy_executable_object_path(output: &mut [u8]) -> usize {
    // SAFETY: `data_imports_resolved` held at module load.
    unsafe { ExLoadedImageName.get_unchecked() }.copy_to(output)
}

/// Drive path of the running executable, translated on the caller's
/// thread (stock 0x91f33c38).
pub(crate) fn executable_drive_path(output: &mut [u8; PATH_LIMIT + 2]) -> usize {
    filesystem::drive_path(ExecutableObjectPath::read().as_bytes(), output)
}

/// Export 131: a snapshot block, or null when it cannot be allocated.
extern "C" fn export_build() -> u32 {
    let mut executable = [0u8; PATH_LIMIT + 2];
    let length = executable_drive_path(&mut executable);

    build(&executable[..length], super::capture::snapshot_fields())
        .map_or(0, |snapshot| snapshot.address())
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
        kind = const MemoryRegion::Title as u32,
        free = sym xboxkrnl::MmFreePhysicalMemory,
    )
}
export!(132, export_free);
