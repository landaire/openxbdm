//! Virtual memory, loaded modules, raw flash, import tracing, and
//! allocation tracking.

use core::fmt::Write as _;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::filesystem;
use openxbdm_server::commands::filesystem::Backend as _;
use openxbdm_server::commands::memory;
use openxbdm_server::commands::memory::CodeView;
use openxbdm_server::commands::memory::ModuleIndex;
use openxbdm_server::commands::memory::ModuleInfo;
use openxbdm_server::commands::memory::ModuleName;
use openxbdm_server::commands::memory::NoSuchModule;
use openxbdm_server::commands::memory::SectionIndex;
use openxbdm_server::commands::memory::SectionInfo;
use openxbdm_server::commands::memory::TrackingFlags;
use openxbdm_server::commands::memory::XexFieldError;
use openxbdm_server::commands::memory::XexFieldKey;
use openxbdm_server::text::Text;

use super::Console;
use crate::kernel;
use crate::kernel::LIB_KERNEL;
use crate::kernel::import_thunk;
use crate::kernel::import_variable;

mod detour;
mod exports;

pub(crate) use exports::get_module_debug_directory;
pub(crate) use exports::walk_modules;

import_thunk!(pub RtlImageNtHeader(base: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x1a9);
import_thunk!(
    pub RtlImageDirectoryEntryToData(base: u32, mapped: u32, directory: u32, size: *mut u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x1a8
);
import_thunk!(pub(crate) RtlImageXexHeaderField(header: u32, key: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x12b);
import_thunk!(
    pub(crate) RtlAssert(message: *const u8, file: *const u8, line: u32, extra: *const u8) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x118
);
import_variable!(
    /// The running executable's module handle.
    EXECUTABLE_MODULE_HANDLE,
    lib = LIB_KERNEL,
    ordinal = 403
);
import_variable!(
    /// NUL-terminated object path of the running executable.
    pub(crate) EXECUTABLE_PATH, lib = LIB_KERNEL, ordinal = 431
);

/// Debugger context the kernel fills for a writable mapping.
const WRITE_CONTEXT_WORDS: usize = 14;

/// Loader data table entry offsets.
const ENTRY_BASE: usize = 0x18;
const ENTRY_SIZE: usize = 0x20;
const ENTRY_NAME_LENGTH: usize = 0x2c;
const ENTRY_NAME_BUFFER: usize = 0x30;
const ENTRY_FLAGS: usize = 0x34;
const ENTRY_XEX_HEADER: usize = 0x58;
/// Loader flag of modules `modules` reports.
const ENTRY_FLAG_REPORTED: u32 = 0x10_0000;

const IMAGE_DIRECTORY_EXCEPTION: u32 = 3;
const IMAGE_DIRECTORY_DEBUG: u32 = 6;
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
const IMAGE_FILE_DLL: u16 = 0x2000;
const DEBUG_DIRECTORY_ENTRY_SIZE: u32 = 0x1c;
const SECTION_HEADER_SIZE: u32 = 0x28;
const CODEVIEW_RSDS: u32 = u32::from_be_bytes(*b"RSDS");

/// `ExDebugMonitorService` 8: debug-adjusted memory statistics.
const DEBUG_MONITOR_MEMORY_STATISTICS: u32 = 8;
/// Words of the service 8 reply, including its size and length header.
const MEMORY_STATISTICS_REPLY_WORDS: usize = 0x90 / 4;
/// Length of an `MmQueryStatistics` block.
const MEMORY_STATISTICS_LENGTH: u32 = 0x68;

/// Kernel export that configures import tracing for a module name.
const TRACE_IMPORTS_ORDINAL: u32 = 0x2cf;

/// Pool tag of allocation tracking records ('xmem').
const TRACKING_POOL_TAG: u32 = 0x6d65_6d78;
const TRACKING_ASSERT_FILE: &core::ffi::CStr =
    c"e:\\xenon\\xdksep13\\core\\private\\xdk\\tools\\debug\\xbdm\\core\\alloctrk.c";
const TRACKING_ASSERT_LINE: u32 = 0x73;
/// Tracking flag that turns diagnostics into assertions.
const TRACKING_ASSERT: u32 = 0x100;
const TRACK_ASSERT_LINE: u32 = 0xac;
const UNTRACK_ASSERT_LINE: u32 = 0xef;

/// Stock asserts a null allocation pointer whatever the tracking flags.
fn assert_allocation_pointer(line: u32) {
    RtlAssert(
        c"AllocPtr != NULL".as_ptr().cast(),
        TRACKING_ASSERT_FILE.as_ptr().cast(),
        line,
        core::ptr::null(),
    );
}

/// HRESULT of tracking calls while no type is tracked.
const TRACKING_OFF: u32 = 0x8007_0426;

fn read_u32(address: u32) -> u32 {
    // SAFETY: callers pass addresses of kernel structures that stay mapped
    // while the loader lock is held or that the kernel owns permanently.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn read_u16(address: u32) -> u16 {
    // SAFETY: as `read_u32`.
    unsafe { core::ptr::read_volatile(address as usize as *const u16) }
}

/// A little-endian PE field.
fn read_le32(address: u32) -> u32 {
    read_u32(address).swap_bytes()
}

fn read_le16(address: u32) -> u16 {
    read_u16(address).swap_bytes()
}

/// Module init of this domain: the detour trampolines and engine.
pub(crate) fn initialize() {
    detour::initialize();
}

/// Holds the loader spin lock for its lifetime.
struct LoaderLock {
    lock: u32,
    irql: u32,
}

impl LoaderLock {
    fn acquire() -> Self {
        let lock = kernel::debug_monitor_data().loader_lock();
        let irql = kernel::KfAcquireSpinLock(lock as usize as *mut u32);
        Self { lock, irql }
    }
}

impl Drop for LoaderLock {
    fn drop(&mut self) {
        kernel::KfReleaseSpinLock(self.lock as usize as *mut u32, self.irql);
    }
}

/// Loader data table entries of each list in `heads`, one list after the
/// other; a zero head is an empty list. One iterator for both lists keeps
/// the walks from being instantiated once per list.
struct LoaderEntries {
    heads: [u32; 2],
    list: usize,
    entry: u32,
}

impl LoaderEntries {
    fn new(heads: [u32; 2]) -> Self {
        Self {
            heads,
            list: 0,
            entry: first_entry(heads[0]),
        }
    }
}

fn first_entry(head: u32) -> u32 {
    if head == 0 { 0 } else { read_u32(head) }
}

impl Iterator for LoaderEntries {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        loop {
            let head = *self.heads.get(self.list)?;
            if head != 0 && self.entry != head {
                let current = self.entry;
                self.entry = read_u32(current);
                return Some(current);
            }
            self.list += 1;
            self.entry = self
                .heads
                .get(self.list)
                .map_or(0, |&head| first_entry(head));
        }
    }
}

/// Entries of both loader lists, in the order the monitor walks them.
fn all_entries() -> LoaderEntries {
    let data = kernel::debug_monitor_data();
    LoaderEntries::new([data.module_list(), data.secondary_module_list()])
}

fn entry_name_units(entry: u32) -> impl Iterator<Item = u16> {
    let length = u32::from(read_u16(entry + ENTRY_NAME_LENGTH as u32) >> 1);
    let buffer = read_u32(entry + ENTRY_NAME_BUFFER as u32);
    (0..length).map(move |index| read_u16(buffer + index * 2))
}

/// The entry whose base name exactly matches `name`, searching the first
/// list and then the second. Callers hold the loader lock.
fn find_entry(name: &[u8]) -> Option<u32> {
    all_entries().find(|&entry| memory::module_name_matches(entry_name_units(entry), name, true))
}

/// The loader entry of the module whose base name exactly matches `name`
/// (stock 0x91f33fb0 with exact matching), looked up under the loader lock.
pub(crate) fn loader_entry(name: &[u8]) -> Option<u32> {
    let _lock = LoaderLock::acquire();
    find_entry(name)
}

fn nt_header(entry: u32) -> Option<u32> {
    let base = read_u32(entry + ENTRY_BASE as u32);
    if base == 0 {
        return None;
    }
    Some(RtlImageNtHeader(base)).filter(|&header| header != 0)
}

/// Address of the section table after the NT header `header`.
fn section_table(header: u32) -> u32 {
    header + 0x18 + u32::from(read_le16(header + 0x14))
}

/// The section header at `section` of the module loaded at `base`
/// (also the export 52 record, 0x91f33b88).
#[inline(never)]
fn section_info(section: u32, base: u32) -> SectionInfo {
    let mut name = [0u8; memory::SECTION_NAME_LENGTH];
    for (offset, byte) in name.iter_mut().enumerate() {
        // SAFETY: section headers are part of the mapped image header.
        *byte = unsafe { core::ptr::read_volatile((section as usize + offset) as *const u8) };
    }
    // Stock copies the name with strncpy: bytes after a NUL are zero.
    if let Some(end) = name.iter().position(|&byte| byte == 0) {
        name[end..].fill(0);
    }
    SectionInfo {
        name,
        address: read_le32(section + 0xc).wrapping_add(base),
        size: read_le32(section + 8),
        characteristics: read_le32(section + 0x24),
    }
}

/// Characters of a tracking diagnostic; stock formats it into a 0x200-byte
/// buffer that keeps its terminator.
const TRACKING_MESSAGE_LIMIT: usize = 0x1ff;

/// Format a tracking diagnostic and report it as stock does: an assertion
/// when the flags request it, else `DbgPrint("DM: %s\n", message)`.
fn tracking_diagnostic(arguments: core::fmt::Arguments<'_>) {
    let mut text = Text::<TRACKING_MESSAGE_LIMIT>::new();
    let _ = text.write_fmt(arguments);
    let mut message = [0u8; TRACKING_MESSAGE_LIMIT + 1];
    message[..text.as_bytes().len()].copy_from_slice(text.as_bytes());
    if TRACKING.flags.load(Ordering::Relaxed) & TRACKING_ASSERT != 0 {
        RtlAssert(
            message.as_ptr(),
            TRACKING_ASSERT_FILE.as_ptr().cast(),
            TRACKING_ASSERT_LINE,
            core::ptr::null(),
        );
    } else {
        // The message pointer goes in the first variadic argument slot, as
        // `kernel::debug_print` passes it.
        kernel::DbgPrint(
            c"DM: %s\n".as_ptr().cast(),
            message.as_ptr() as usize as u32,
            core::ptr::null(),
        );
    }
}

/// Allocation tracking state shared with the debug service dispatcher.
struct Tracking {
    /// Flags in effect.
    flags: AtomicU32,
    /// Spin lock guarding the record list.
    lock: AtomicU32,
    /// Newest record; each record starts with the address of the next.
    head: AtomicU32,
    count: AtomicU32,
}

static TRACKING: Tracking = Tracking {
    flags: AtomicU32::new(0),
    lock: AtomicU32::new(0),
    head: AtomicU32::new(0),
    count: AtomicU32::new(0),
};

/// Record layout: next (+0), type (+4, u16), size (+6), address (+0xa),
/// then the captured return addresses.
const RECORD_TYPE: u32 = 4;
const RECORD_SIZE: u32 = 6;
const RECORD_ADDRESS: u32 = 0xa;
const RECORD_STACK: u32 = 0xe;

fn record_length() -> u32 {
    memory::ACTIVE_STACK_DEPTH
        .0
        .wrapping_sub(1)
        .wrapping_shl(2)
        .wrapping_add(0x12)
}

fn tracking_type_enabled(kind: u16, flags: u32) -> bool {
    match kind {
        0 => flags & 1 != 0,
        1 => flags & 2 != 0,
        2..=13 => true,
        _ => flags & 0x80 != 0,
    }
}

/// Allocation type names: the built-in names, then names titles register
/// through export 78 (0x91f96038 counts both).
static TRACKING_TYPE_COUNT: AtomicU32 = AtomicU32::new(memory::TRACKING_TYPE_NAMES.len() as u32);
/// Registered names (pool copies). Stock stores them through a table
/// pointer that is never allocated and faults; this table holds
/// `REGISTERED_TYPE_CAPACITY` names.
static REGISTERED_TYPE_NAMES: [AtomicU32; REGISTERED_TYPE_CAPACITY] =
    [const { AtomicU32::new(0) }; REGISTERED_TYPE_CAPACITY];
const REGISTERED_TYPE_CAPACITY: usize = 0x100;

/// The NUL-terminated name of allocation type `kind`, below the type count.
fn tracking_type_name_bytes(kind: u16) -> &'static [u8] {
    match memory::TRACKING_TYPE_NAMES.get(usize::from(kind)) {
        Some(name) => name.as_bytes(),
        None => {
            let index = usize::from(kind) - memory::TRACKING_TYPE_NAMES.len();
            let name = REGISTERED_TYPE_NAMES
                .get(index)
                .map_or(0, |slot| slot.load(Ordering::Acquire));
            if name == 0 {
                return b"";
            }
            // SAFETY: registered names are NUL-terminated pool copies that
            // are never freed.
            unsafe { core::ffi::CStr::from_ptr(name as usize as *const core::ffi::c_char) }
                .to_bytes()
        }
    }
}

fn tracking_type_name(kind: u16) -> &'static str {
    core::str::from_utf8(tracking_type_name_bytes(kind)).unwrap_or_default()
}

fn tracking_type_count() -> u32 {
    TRACKING_TYPE_COUNT.load(Ordering::Acquire)
}

fn write_unaligned_u32(address: u32, value: u32) {
    // SAFETY: the record was allocated with `record_length` bytes.
    unsafe { core::ptr::write_unaligned(address as usize as *mut u32, value) }
}

fn read_unaligned_u32(address: u32) -> u32 {
    // SAFETY: records are live while the tracking lock is held.
    unsafe { core::ptr::read_unaligned(address as usize as *const u32) }
}

/// Debug monitor control code 8 (stock 0x91f3b73c -> 0x91f23598): track an
/// allocation. `arguments` points at the address, size, and type dwords.
/// The stock return value is residual.
pub(crate) fn service_memtrack_record_alloc(arguments: u32) -> u32 {
    track_allocation(
        read_u32(arguments),
        read_u32(arguments + 4),
        u16::from(read_u32(arguments + 8) as u8),
    );
    0
}

/// 0x91f23598: 0x80070426 while tracking is off, E_INVALIDARG for an
/// unknown type, 1 for a type not tracked, E_OUTOFMEMORY, or 0.
fn track_allocation(address: u32, size: u32, kind: u16) -> u32 {
    if address == 0 {
        assert_allocation_pointer(TRACK_ASSERT_LINE);
    }
    let flags = TRACKING.flags.load(Ordering::Relaxed);
    if flags & TrackingFlags::TYPE_MASK == 0 {
        return TRACKING_OFF;
    }
    if u32::from(kind) >= tracking_type_count() {
        return Hresult::INVALID_ARGUMENT.0;
    }
    if !tracking_type_enabled(kind, flags) {
        return 1;
    }
    let length = record_length();
    let record = kernel::ExAllocatePoolWithTag(length, TRACKING_POOL_TAG);
    if record == 0 {
        tracking_diagnostic(format_args!(
            "unable to allocate buffer for allocation tracking"
        ));
        return Hresult::OUT_OF_MEMORY.0;
    }
    write_unaligned_u32(record + RECORD_ADDRESS, address);
    write_unaligned_u32(record + RECORD_SIZE, size);
    // SAFETY: the record holds at least RECORD_STACK bytes.
    unsafe { core::ptr::write_unaligned((record + RECORD_TYPE) as usize as *mut u16, kind) };
    let stack = memory::ACTIVE_STACK_DEPTH.0 << 2;
    if stack != 0 {
        // SAFETY: the record holds the stack area after RECORD_STACK.
        unsafe {
            core::ptr::write_bytes(
                (record + RECORD_STACK) as usize as *mut u8,
                0,
                stack as usize,
            )
        };
    }
    let lock = TRACKING.lock.as_ptr();
    let irql = kernel::KfAcquireSpinLock(lock);
    write_unaligned_u32(record, TRACKING.head.load(Ordering::Relaxed));
    TRACKING.head.store(record, Ordering::Relaxed);
    TRACKING.count.fetch_add(1, Ordering::Relaxed);
    kernel::KfReleaseSpinLock(lock, irql);
    0
}

/// Debug monitor control code 9 (stock 0x91f3b754 -> 0x91f236d8): stop
/// tracking an allocation. A size of 0 matches any recorded size. Returns
/// the lookup HRESULT when the type is tracked; the stock value is residual
/// otherwise.
pub(crate) fn service_memtrack_record_free(arguments: u32) -> u32 {
    match untrack_allocation(
        read_u32(arguments),
        read_u32(arguments + 4),
        u16::from(read_u32(arguments + 8) as u8),
    ) {
        Untracked::Lookup(result) => result,
        Untracked::Skipped(_) => 0,
    }
}

/// Outcome of 0x91f236d8.
enum Untracked {
    /// Tracking is off, the type is unknown, or it is not tracked.
    Skipped(u32),
    /// The record lookup ran.
    Lookup(u32),
}

fn untrack_allocation(address: u32, size: u32, kind: u16) -> Untracked {
    if address == 0 {
        assert_allocation_pointer(UNTRACK_ASSERT_LINE);
    }
    let flags = TRACKING.flags.load(Ordering::Relaxed);
    if flags & TrackingFlags::TYPE_MASK == 0 {
        return Untracked::Skipped(TRACKING_OFF);
    }
    if u32::from(kind) >= tracking_type_count() {
        return Untracked::Skipped(Hresult::INVALID_ARGUMENT.0);
    }
    if !tracking_type_enabled(kind, flags) {
        return Untracked::Skipped(1);
    }
    let lock = TRACKING.lock.as_ptr();
    let irql = kernel::KfAcquireSpinLock(lock);
    let mut previous = None;
    let mut record = TRACKING.head.load(Ordering::Relaxed);
    while record != 0 && read_unaligned_u32(record + RECORD_ADDRESS) != address {
        previous = Some(record);
        record = read_unaligned_u32(record);
    }
    let mut release = false;
    let result = if record == 0 {
        tracking_diagnostic(format_args!(
            "no history tracking found freeing {} @ {:08X} size {}",
            tracking_type_name(kind),
            address,
            size as i32
        ));
        0x8007_0490
    } else {
        // SAFETY: the record is live under the lock.
        let recorded_kind =
            unsafe { core::ptr::read_unaligned((record + RECORD_TYPE) as usize as *const u16) };
        if recorded_kind != kind {
            tracking_diagnostic(format_args!(
                "mismatch allocator @ {:08X} (was {}, expected {})",
                address,
                tracking_type_name(recorded_kind),
                tracking_type_name(kind)
            ));
            0x8007_0057
        } else if size == 0 || size == read_unaligned_u32(record + RECORD_SIZE) {
            let next = read_unaligned_u32(record);
            match previous {
                Some(previous) => write_unaligned_u32(previous, next),
                None => TRACKING.head.store(next, Ordering::Relaxed),
            }
            TRACKING.count.fetch_sub(1, Ordering::Relaxed);
            release = true;
            0
        } else {
            tracking_diagnostic(format_args!(
                "invalid size freeing {} @ {:08X}",
                tracking_type_name(kind),
                address
            ));
            0x8007_0018
        }
    };
    kernel::KfReleaseSpinLock(lock, irql);
    if release {
        kernel::ExFreePool(record);
    }
    Untracked::Lookup(result)
}

/// Debug monitor control code 0x18 (stock 0x91f3b804 -> 0x91f33d38): the
/// address of export `ordinal` of a loaded module, or 0. `argument` points
/// at the module name pointer and the ordinal.
pub(crate) fn service_get_module_proc_address(argument: u32) -> u32 {
    let name = read_u32(argument) as usize as *const u8;
    let mut module = 0u32;
    if (kernel::XexGetModuleHandle(name, &mut module) as i32) < 0 {
        return 0;
    }
    let mut address = 0u32;
    if (kernel::XexGetProcedureAddress(module, read_u32(argument + 4), &mut address) as i32) < 0 {
        0
    } else {
        address
    }
}

/// Debug monitor control code 0x86 (stock 0x91f3ba40 -> 0x91f330f0):
/// replace the `MmQueryStatistics` result at `argument` with the debug
/// monitor's statistics when the lengths match, then correct the available
/// page count and the total page count for debug memory.
pub(crate) fn service_adjust_memory_statistics(argument: u32) -> u32 {
    let mut reply = [0u32; MEMORY_STATISTICS_REPLY_WORDS];
    reply[0] = (MEMORY_STATISTICS_REPLY_WORDS * 4) as u32;
    reply[1] = MEMORY_STATISTICS_LENGTH;
    let status = kernel::ExDebugMonitorService(
        DEBUG_MONITOR_MEMORY_STATISTICS,
        reply.as_mut_ptr() as usize as u32,
        0,
        0,
    );
    if (status as i32) < 0 || reply[0] < (MEMORY_STATISTICS_REPLY_WORDS * 4) as u32 {
        return 0;
    }
    let length = read_u32(argument);
    let word = |offset: usize| reply[offset / 4];
    if word(4) != length || word(0x84) == 0 {
        return 0;
    }
    // SAFETY: the caller's statistics block holds `length` bytes, which
    // equals the length the kernel reported.
    unsafe {
        core::ptr::copy_nonoverlapping(
            reply.as_ptr().cast::<u8>().add(4),
            argument as usize as *mut u8,
            length as usize,
        )
    };
    let free = word(0x10).wrapping_sub(word(0x6c));
    let limit = word(0x80).wrapping_sub(word(0x28)).wrapping_sub(word(0x1c));
    write_unaligned_u32(argument + 0xc, free.min(limit));
    write_unaligned_u32(argument + 4, word(0x88).wrapping_add(word(0x80)));
    0
}

/// Whether the debugger may read the page of `address`.
fn debug_readable(address: u32) -> bool {
    let mapped = kernel::MmDbgReadCheck(address);
    mapped != 0 && !memory::is_device_address(mapped)
}

/// Read a byte the debugger may read (0x91f26bc8 without breakpoints).
fn read_debug_byte(address: u32) -> Option<u8> {
    if !debug_readable(address) {
        return None;
    }
    // SAFETY: the kernel reported the address readable by the debugger.
    Some(unsafe { core::ptr::read_volatile(address as usize as *const u8) })
}

/// Write a byte through a writable debugger mapping and flush the
/// instruction cache for it (0x91f26cb8 without breakpoints).
fn write_debug_byte(address: u32, value: u8) -> bool {
    let mut context = [0u32; WRITE_CONTEXT_WORDS];
    let mapped = kernel::MmDbgWriteCheck(address, context.as_mut_ptr());
    if mapped == 0 {
        return false;
    }
    if memory::is_device_address(mapped) {
        kernel::MmDbgReleaseAddress(mapped, context.as_mut_ptr());
        return false;
    }
    let pointer = mapped as usize as *mut u8;
    // SAFETY: the kernel mapped the address writable for the debugger.
    unsafe { core::ptr::write_volatile(pointer, value) };
    kernel::KeSweepIcacheRange(pointer, 1);
    kernel::MmDbgReleaseAddress(mapped, context.as_mut_ptr());
    true
}

/// Whether the loader list at `head` has an entry for the module loaded at
/// `base`.
fn list_has_base(head: u32, base: u32) -> bool {
    if head == 0 {
        return false;
    }
    let mut entry = read_u32(head);
    while entry != head {
        if read_u32(entry + ENTRY_BASE as u32) == base {
            return true;
        }
        entry = read_u32(entry);
    }
    false
}

/// The CodeView record of the module loaded at `base` (0x91f280d8).
fn code_view_of(base: u32) -> Option<CodeView> {
    let _lock = LoaderLock::acquire();
    let data = kernel::debug_monitor_data();
    let mut directory = 0u32;
    let mut size = 0u32;
    if list_has_base(data.module_list(), base) {
        directory = RtlImageDirectoryEntryToData(base, 1, IMAGE_DIRECTORY_DEBUG, &mut size);
    }
    if directory == 0 || size == 0 {
        directory = 0;
        if list_has_base(data.secondary_module_list(), base) {
            directory = RtlImageDirectoryEntryToData(base, 1, IMAGE_DIRECTORY_DEBUG, &mut size);
        }
    }
    if directory == 0 || size == 0 {
        return None;
    }
    // Any CodeView entry selects the record named by the first entry.
    let count = size / DEBUG_DIRECTORY_ENTRY_SIZE;
    let has_code_view = (0..count).any(|index| {
        read_le32(directory + index * DEBUG_DIRECTORY_ENTRY_SIZE + 0xc) == IMAGE_DEBUG_TYPE_CODEVIEW
    });
    if !has_code_view {
        return None;
    }
    let record = base.wrapping_add(read_le32(directory + 0x14));
    if read_u32(record) != CODEVIEW_RSDS {
        return None;
    }
    let mut guid = [0u8; 16];
    let mut age = [0u8; 4];
    // SAFETY: the CodeView record lies in the mapped image.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (record + 4) as usize as *const u8,
            guid.as_mut_ptr(),
            guid.len(),
        );
        core::ptr::copy_nonoverlapping(
            (record + 0x14) as usize as *const u8,
            age.as_mut_ptr(),
            age.len(),
        );
    }
    Some(CodeView::read(guid, age, |offset| {
        // SAFETY: as above; the path is NUL-terminated.
        unsafe { core::ptr::read_volatile((record as usize + 0x18 + offset) as *const u8) }
    }))
}

impl memory::Backend for Console {
    fn is_address_valid(&mut self, address: u32) -> bool {
        kernel::MmIsAddressValid(address) != 0
    }

    fn read_byte(&mut self, address: u32) -> Option<u8> {
        read_debug_byte(address)
    }

    fn write_byte(&mut self, address: u32, value: u8) -> bool {
        write_debug_byte(address, value)
    }

    fn is_readable(&mut self, address: u32) -> bool {
        debug_readable(address)
    }

    fn read_memory(&mut self, address: u32, output: &mut [u8]) {
        // A range that wraps past 0xffffffff continues at address 0.
        let before_wrap =
            (u64::from(u32::MAX) + 1 - u64::from(address)).min(output.len() as u64) as usize;
        let (head, tail) = output.split_at_mut(before_wrap);
        // SAFETY: the caller checked every page of the range with
        // `is_readable`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                address as usize as *const u8,
                head.as_mut_ptr(),
                head.len(),
            );
            for (offset, byte) in tail.iter_mut().enumerate() {
                *byte = core::ptr::read_volatile(core::ptr::with_exposed_provenance::<u8>(offset));
            }
        }
    }

    fn module(&mut self, index: ModuleIndex) -> Option<ModuleInfo> {
        let _lock = LoaderLock::acquire();
        let (entry, header) = all_entries()
            .filter(|&entry| read_u32(entry + ENTRY_FLAGS as u32) & ENTRY_FLAG_REPORTED != 0)
            .filter_map(|entry| nt_header(entry).map(|header| (entry, header)))
            .nth(index.0 as usize)?;
        let base = read_u32(entry + ENTRY_BASE as u32);
        let mut pdata_size = 0u32;
        let pdata =
            RtlImageDirectoryEntryToData(base, 1, IMAGE_DIRECTORY_EXCEPTION, &mut pdata_size);
        Some(ModuleInfo {
            name: ModuleName::from_units(entry_name_units(entry)),
            base,
            size: read_u32(entry + ENTRY_SIZE as u32),
            checksum: read_le32(header + 0x58),
            timestamp: read_le32(header + 8),
            pdata,
            pdata_size,
            dll: read_le16(header + 0x16) & IMAGE_FILE_DLL != 0,
            image_size: read_le32(header + 0x50),
        })
    }

    fn module_section(
        &mut self,
        name: &[u8],
        index: SectionIndex,
    ) -> Result<Option<SectionInfo>, NoSuchModule> {
        let _lock = LoaderLock::acquire();
        let entry = find_entry(name).ok_or(NoSuchModule)?;
        let header = nt_header(entry).ok_or(NoSuchModule)?;
        let base = read_u32(entry + ENTRY_BASE as u32);
        let count = read_le16(header + 6);
        if index.0 == 0 || index.0 > count {
            return Ok(None);
        }
        let section = section_table(header) + u32::from(index.0 - 1) * SECTION_HEADER_SIZE;
        Ok(Some(section_info(section, base)))
    }

    fn code_view(&mut self, base: u32) -> Option<CodeView> {
        code_view_of(base)
    }

    fn xex_header_field(
        &mut self,
        module: &[u8],
        field: XexFieldKey,
    ) -> Result<u32, XexFieldError> {
        let _lock = LoaderLock::acquire();
        let entry = find_entry(module).ok_or(XexFieldError::NoSuchModule)?;
        match RtlImageXexHeaderField(read_u32(entry + ENTRY_XEX_HEADER as u32), field.0) {
            0 => Err(XexFieldError::FieldAbsent),
            value => Ok(value),
        }
    }

    fn read_xex_header_field(
        &mut self,
        module: &[u8],
        field: XexFieldKey,
        offset: u32,
        output: &mut [u8],
    ) -> Result<(), XexFieldError> {
        let _lock = LoaderLock::acquire();
        let entry = find_entry(module).ok_or(XexFieldError::NoSuchModule)?;
        let data = match RtlImageXexHeaderField(read_u32(entry + ENTRY_XEX_HEADER as u32), field.0)
        {
            0 => return Err(XexFieldError::FieldAbsent),
            data => data,
        };
        // SAFETY: XEX headers stay mapped while the module is loaded, which
        // the loader lock guarantees.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (data + offset) as usize as *const u8,
                output.as_mut_ptr(),
                output.len(),
            )
        };
        Ok(())
    }

    fn title_xex_dword(&mut self, field: XexFieldKey) -> Result<Option<u32>, NoSuchModule> {
        let module = read_u32(EXECUTABLE_MODULE_HANDLE.load(Ordering::Relaxed));
        if module == 0 {
            return Err(NoSuchModule);
        }
        match RtlImageXexHeaderField(read_u32(module + ENTRY_XEX_HEADER as u32), field.0) {
            0 => Ok(None),
            data => Ok(Some(read_u32(data))),
        }
    }

    fn running_executable_path(&mut self, output: &mut [u8]) -> usize {
        let path = EXECUTABLE_PATH.load(Ordering::Relaxed);
        let mut length = 0;
        while length < output.len() {
            // SAFETY: the export is a NUL-terminated string the kernel owns.
            let byte = unsafe { core::ptr::read_volatile((path as usize + length) as *const u8) };
            if byte == 0 {
                break;
            }
            output[length] = byte;
            length += 1;
        }
        length
    }

    fn read_flash(&mut self, offset: u32, output: &mut [u8]) -> Result<(), NtStatus> {
        super::system::flash::device_read(offset, output.as_mut_ptr(), output.len() as u32)
    }

    fn write_flash(&mut self, offset: u32, data: &[u8]) -> Result<(), NtStatus> {
        super::system::flash::device_write(offset, data.as_ptr(), data.len() as u32)
    }

    fn trace_imports(&mut self, module: &[u8], enable: bool) -> bool {
        let Ok(kernel_module) = kernel::module_handle(c"xboxkrnl.exe") else {
            return false;
        };
        let Ok(function) = kernel::resolve_export(kernel_module, TRACE_IMPORTS_ORDINAL) else {
            return false;
        };
        let mut name = [0u8; 0x104];
        let count = module.len().min(name.len() - 1);
        name[..count].copy_from_slice(&module[..count]);
        // SAFETY: the export takes a module name and an enable flag.
        unsafe {
            kernel::call_export(
                function,
                name.as_ptr() as usize as u32,
                u32::from(enable),
                0,
                0,
            ) != 0
        }
    }

    fn tracking_flags(&mut self) -> TrackingFlags {
        TrackingFlags(TRACKING.flags.load(Ordering::Relaxed))
    }

    fn set_tracking_flags(&mut self, flags: TrackingFlags) {
        TRACKING.flags.store(flags.0, Ordering::Relaxed);
    }

    fn write_tracking_records(&mut self, file: filesystem::FileHandle) -> NtStatus {
        let length = record_length() as usize;
        let mut record = TRACKING.head.load(Ordering::Relaxed);
        while record != 0 {
            // SAFETY: records stay allocated while tracked; the title is
            // stopped during the save.
            let bytes =
                unsafe { core::slice::from_raw_parts(record as usize as *const u8, length) };
            if let Err(status) = self.write_file(file, None, filesystem::FileData::Bytes(bytes)) {
                return status;
            }
            record = read_unaligned_u32(record);
        }
        NtStatus::SUCCESS
    }

    fn dos_error_from_nt_status(&mut self, status: NtStatus) -> u32 {
        kernel::RtlNtStatusToDosError(status.0)
    }

    fn detour(
        &mut self,
        operation: &mut dyn FnMut(&memory::detour::Engine, &dyn memory::detour::Platform),
    ) {
        detour::with_engine(operation);
    }

    fn start_detour_log(&mut self, log: Option<&[u8]>) -> NtStatus {
        detour::start(log)
    }

    fn stop_detour_log(&mut self, log: Option<&[u8]>) {
        detour::stop(log);
    }

    fn read_detour_record(&mut self, output: &mut [u8; memory::detour::RECORD_SIZE]) -> bool {
        detour::read_record(output)
    }
}
