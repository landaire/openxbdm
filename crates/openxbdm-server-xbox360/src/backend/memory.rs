//! Virtual memory, loaded modules, raw flash, import tracing, and
//! allocation tracking.

use core::fmt::Write as _;
use core::marker::PhantomData;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
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
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360_sys::image::CodeViewRsds;
use xbox360_sys::image::DebugType;
use xbox360_sys::image::ImageCharacteristics;
use xbox360_sys::image::ImageDebugDirectory;
use xbox360_sys::image::ImageDirectory;
use xbox360_sys::image::ImageNtHeaders;
use xbox360_sys::image::ImageSectionHeader;
use xbox360_sys::image::XexHeaderKey;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::ExLoadedImageName;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::LdrDataTableEntry;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::RtlAssert;
use xbox360_sys::xboxkrnl::RtlImageDirectoryEntryToData;
use xbox360_sys::xboxkrnl::RtlImageNtHeader;
use xbox360_sys::xboxkrnl::RtlImageXexHeaderField;
use xbox360_sys::xboxkrnl::XexExecutableModuleHandle;

use super::Console;
use crate::kernel;

mod detour;
mod exports;

pub(crate) use exports::MODULE_RECORD_SHORT_SIZE;
pub(crate) use exports::ModuleWalkError;
pub(crate) use exports::get_module_debug_directory;
pub(crate) use exports::next_module;

/// Debugger context the kernel fills for a writable mapping.
const WRITE_CONTEXT_WORDS: usize = 14;

/// Words of the service 8 reply, including its size and length header.
const MEMORY_STATISTICS_REPLY_WORDS: usize = 0x90 / 4;
/// Length of an `MmQueryStatistics` block.
const MEMORY_STATISTICS_LENGTH: u32 = 0x68;

/// Kernel export that configures import tracing for a module name.
const TRACE_IMPORTS_ORDINAL: Ordinal = Ordinal::new(0x2cf).unwrap();

/// Pool tag of allocation tracking records ('xmem').
const TRACKING_POOL_TAG: PoolTag = PoolTag::new(*b"memx");
const TRACKING_ASSERT_FILE: &core::ffi::CStr =
    c"e:\\xenon\\xdksep13\\core\\private\\xdk\\tools\\debug\\xbdm\\core\\alloctrk.c";
const TRACKING_ASSERT_LINE: u32 = 0x73;
/// Tracking flag that turns diagnostics into assertions.
const TRACKING_ASSERT: u32 = 0x100;
const TRACK_ASSERT_LINE: u32 = 0xac;
const UNTRACK_ASSERT_LINE: u32 = 0xef;

/// Stock asserts a null allocation pointer whatever the tracking flags.
fn assert_allocation_pointer(line: u32) {
    // SAFETY: both strings are static NUL-terminated literals.
    unsafe {
        RtlAssert(
            c"AllocPtr != NULL".as_ptr().cast(),
            TRACKING_ASSERT_FILE.as_ptr().cast(),
            line,
            core::ptr::null(),
        )
    };
}

/// A tracking hook call that did not fail.
#[derive(Clone, Copy)]
enum Tracked {
    /// The record was added or removed.
    Done,
    /// The type is not tracked.
    TypeNotTracked,
}

/// A failed tracking hook call.
#[derive(Clone, Copy)]
enum TrackingError {
    /// No type is tracked.
    Off,
    /// The type index is past the known types.
    UnknownType,
    /// The record could not be allocated.
    OutOfMemory,
    /// No record has the address.
    NotFound,
    /// The record has another type.
    TypeMismatch,
    /// The record has another size.
    SizeMismatch,
}

type TrackingResult = Result<Tracked, TrackingError>;

/// The HRESULT a tracking hook returns to the kernel or the title.
fn tracking_hresult(result: TrackingResult) -> Hresult {
    match result {
        // S_OK.
        Ok(Tracked::Done) => Hresult(0),
        // S_FALSE.
        Ok(Tracked::TypeNotTracked) => Hresult(1),
        // HRESULT_FROM_WIN32(ERROR_SERVICE_NOT_ACTIVE).
        Err(TrackingError::Off) => Hresult(0x8007_0426),
        Err(TrackingError::UnknownType | TrackingError::TypeMismatch) => Hresult::INVALID_ARGUMENT,
        Err(TrackingError::OutOfMemory) => Hresult::OUT_OF_MEMORY,
        // HRESULT_FROM_WIN32(ERROR_NOT_FOUND).
        Err(TrackingError::NotFound) => Hresult(0x8007_0490),
        // HRESULT_FROM_WIN32(ERROR_BAD_LENGTH).
        Err(TrackingError::SizeMismatch) => Hresult(0x8007_0018),
    }
}

fn read_u32(address: u32) -> u32 {
    // SAFETY: callers pass addresses of kernel structures that stay mapped
    // while the loader lock is held or that the kernel owns permanently.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn read_u16(address: u32) -> u16 {
    // SAFETY: as `read_u32`.
    unsafe { core::ptr::read_volatile(address as usize as *const u16) }
}

/// Module init of this domain: the detour trampolines and engine.
pub(crate) fn initialize() {
    detour::initialize();
}

/// Holds the loader spin lock for its lifetime.
struct LoaderLock {
    lock: u32,
    irql: Irql,
}

impl LoaderLock {
    fn acquire() -> Self {
        let lock = kernel::debug_monitor_data()
            .loaded_module_list_lock
            .load(Ordering::Relaxed);
        // SAFETY: the debug monitor data holds the address of the kernel
        // loader spin lock.
        let irql = unsafe { xboxkrnl::KfAcquireSpinLock(lock as usize as *mut KspinLock) };
        Self { lock, irql }
    }
}

impl Drop for LoaderLock {
    fn drop(&mut self) {
        // SAFETY: `acquire` took this lock at `self.irql`.
        unsafe { xboxkrnl::KfReleaseSpinLock(self.lock as usize as *mut KspinLock, self.irql) };
    }
}

/// Loader data table entries of each list in `heads`, one list after the
/// other; a zero head is an empty list. One iterator for both lists keeps
/// the walks from being instantiated once per list.
struct LoaderEntries<'a> {
    heads: [u32; 2],
    list: usize,
    entry: u32,
    _lock: PhantomData<&'a LoaderLock>,
}

impl LoaderEntries<'_> {
    fn new(heads: [u32; 2]) -> Self {
        Self {
            heads,
            list: 0,
            entry: first_entry(heads[0]),
            _lock: PhantomData,
        }
    }
}

fn first_entry(head: u32) -> u32 {
    if head == 0 { 0 } else { read_u32(head) }
}

impl<'a> Iterator for LoaderEntries<'a> {
    type Item = &'a LdrDataTableEntry;

    fn next(&mut self) -> Option<&'a LdrDataTableEntry> {
        loop {
            let head = *self.heads.get(self.list)?;
            if head != 0 && self.entry != head {
                // SAFETY: `self.entry` is linked into a loader module list of
                // the debug monitor data; callers hold the loader lock, which
                // keeps the entry linked and mapped.
                let current = unsafe {
                    &*core::ptr::with_exposed_provenance::<LdrDataTableEntry>(self.entry as usize)
                };
                self.entry = current.in_load_order_links.flink.load(Ordering::Relaxed);
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

/// Entries of both loader lists, in the order the monitor walks them,
/// valid while `_lock` is held.
fn all_entries(_lock: &LoaderLock) -> LoaderEntries<'_> {
    let data = kernel::debug_monitor_data();
    LoaderEntries::new([
        data.loaded_module_list.load(Ordering::Relaxed),
        data.loaded_usermode_module_list.load(Ordering::Relaxed),
    ])
}

xbox360_sys::flags! {
    /// Bits of a loader entry's flags word that the monitor reads; their
    /// kernel meaning is not known.
    pub struct LoaderEntryFlags(u32) {
        /// The monitor lists the module.
        REPORTED = 0x10_0000,
    }
}

fn is_reported(entry: &LdrDataTableEntry) -> bool {
    LoaderEntryFlags::from_bits_retain(entry.flags.load(Ordering::Relaxed))
        .contains(LoaderEntryFlags::REPORTED)
}

fn entry_name_units(entry: &LdrDataTableEntry) -> impl Iterator<Item = u16> {
    let length = u32::from(entry.base_dll_name.length >> 1);
    let buffer = entry.base_dll_name.buffer;
    (0..length).map(move |index| read_u16(buffer + index * 2))
}

/// The entry whose base name exactly matches `name`, searching the first
/// list and then the second. Callers hold the loader lock.
fn find_entry<'a>(lock: &'a LoaderLock, name: &[u8]) -> Option<&'a LdrDataTableEntry> {
    all_entries(lock).find(|entry| memory::module_name_matches(entry_name_units(entry), name, true))
}

/// The loader entry of the module whose base name exactly matches `name`
/// (stock 0x91f33fb0 with exact matching), looked up under the loader lock.
pub(crate) fn loader_entry(name: &[u8]) -> Option<u32> {
    let lock = LoaderLock::acquire();
    find_entry(&lock, name).map(|entry| core::ptr::from_ref(entry).expose_provenance() as u32)
}

fn nt_header(entry: &LdrDataTableEntry) -> Option<&ImageNtHeaders> {
    let base = entry.dll_base;
    if base == 0 {
        return None;
    }
    // SAFETY: `base` is the image base of a loaded module entry.
    let header = unsafe { RtlImageNtHeader(base) };
    // SAFETY: a non-null result is the NT headers of the mapped image, which
    // stays mapped while the caller holds the loader lock.
    unsafe { header.as_ref() }
}

/// The section header `section` of the module loaded at `base`
/// (also the export 52 record, 0x91f33b88).
#[inline(never)]
fn section_info(section: &ImageSectionHeader, base: u32) -> SectionInfo {
    let mut name = section.name;
    // Stock copies the name with strncpy: bytes after a NUL are zero.
    if let Some(end) = name.iter().position(|&byte| byte == 0) {
        name[end..].fill(0);
    }
    SectionInfo {
        name,
        address: section.virtual_address.get().wrapping_add(base),
        size: section.virtual_size.get(),
        characteristics: section.characteristics.get(),
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
        // SAFETY: `message` is NUL-terminated and the file name is a static literal.
        unsafe {
            RtlAssert(
                message.as_ptr(),
                TRACKING_ASSERT_FILE.as_ptr().cast(),
                TRACKING_ASSERT_LINE,
                core::ptr::null(),
            )
        };
    } else {
        // The message pointer goes in the first variadic argument slot, as
        // `kernel::debug_print` passes it.
        // SAFETY: the format is a static literal whose one `%s` takes the
        // NUL-terminated `message`.
        unsafe {
            kernel::DbgPrint(
                c"DM: %s\n".as_ptr().cast(),
                message.as_ptr() as usize as u32,
                core::ptr::null(),
            )
        };
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
    let _ = track_allocation(
        read_u32(arguments),
        read_u32(arguments + 4),
        u16::from(read_u32(arguments + 8) as u8),
    );
    0
}

/// 0x91f23598.
fn track_allocation(address: u32, size: u32, kind: u16) -> TrackingResult {
    if address == 0 {
        assert_allocation_pointer(TRACK_ASSERT_LINE);
    }
    let flags = TRACKING.flags.load(Ordering::Relaxed);
    if flags & TrackingFlags::TYPE_MASK == 0 {
        return Err(TrackingError::Off);
    }
    if u32::from(kind) >= tracking_type_count() {
        return Err(TrackingError::UnknownType);
    }
    if !tracking_type_enabled(kind, flags) {
        return Ok(Tracked::TypeNotTracked);
    }
    let length = record_length();
    // SAFETY: pool allocation has no pointer arguments.
    let record = unsafe { xboxkrnl::ExAllocatePoolWithTag(length, TRACKING_POOL_TAG) };
    if record == 0 {
        tracking_diagnostic(format_args!(
            "unable to allocate buffer for allocation tracking"
        ));
        return Err(TrackingError::OutOfMemory);
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
    // SAFETY: `lock` is the static tracking spin lock.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(lock.cast()) };
    write_unaligned_u32(record, TRACKING.head.load(Ordering::Relaxed));
    TRACKING.head.store(record, Ordering::Relaxed);
    TRACKING.count.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the lock was acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(lock.cast(), irql) };
    Ok(Tracked::Done)
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
        Untracked::Lookup(result) => tracking_hresult(result).0,
        Untracked::Skipped(_) => 0,
    }
}

/// Outcome of 0x91f236d8.
enum Untracked {
    /// Tracking is off, the type is unknown, or it is not tracked.
    Skipped(TrackingResult),
    /// The record lookup ran.
    Lookup(TrackingResult),
}

fn untrack_allocation(address: u32, size: u32, kind: u16) -> Untracked {
    if address == 0 {
        assert_allocation_pointer(UNTRACK_ASSERT_LINE);
    }
    let flags = TRACKING.flags.load(Ordering::Relaxed);
    if flags & TrackingFlags::TYPE_MASK == 0 {
        return Untracked::Skipped(Err(TrackingError::Off));
    }
    if u32::from(kind) >= tracking_type_count() {
        return Untracked::Skipped(Err(TrackingError::UnknownType));
    }
    if !tracking_type_enabled(kind, flags) {
        return Untracked::Skipped(Ok(Tracked::TypeNotTracked));
    }
    let lock = TRACKING.lock.as_ptr();
    // SAFETY: `lock` is the static tracking spin lock.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(lock.cast()) };
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
        Err(TrackingError::NotFound)
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
            Err(TrackingError::TypeMismatch)
        } else if size == 0 || size == read_unaligned_u32(record + RECORD_SIZE) {
            let next = read_unaligned_u32(record);
            match previous {
                Some(previous) => write_unaligned_u32(previous, next),
                None => TRACKING.head.store(next, Ordering::Relaxed),
            }
            TRACKING.count.fetch_sub(1, Ordering::Relaxed);
            release = true;
            Ok(Tracked::Done)
        } else {
            tracking_diagnostic(format_args!(
                "invalid size freeing {} @ {:08X}",
                tracking_type_name(kind),
                address
            ));
            Err(TrackingError::SizeMismatch)
        }
    };
    // SAFETY: the lock was acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(lock.cast(), irql) };
    if release {
        // SAFETY: the record is a pool block unlinked from the list above.
        unsafe { xboxkrnl::ExFreePool(record) };
    }
    Untracked::Lookup(result)
}

/// Debug monitor control code 0x18 (stock 0x91f3b804 -> 0x91f33d38): the
/// address of export `ordinal` of a loaded module, or 0. `argument` points
/// at the module name pointer and the ordinal.
pub(crate) fn service_get_module_proc_address(argument: u32) -> u32 {
    let name = read_u32(argument) as usize as *const u8;
    let mut module = 0u32;
    // SAFETY: the caller passes a NUL-terminated module name; `module` is a
    // live local.
    if (unsafe { xboxkrnl::XexGetModuleHandle(name, &mut module) }.0 as i32) < 0 {
        return 0;
    }
    let mut address = 0u32;
    // SAFETY: `module` was returned by the kernel; `address` is a live local.
    let status =
        unsafe { xboxkrnl::XexGetProcedureAddress(module, read_u32(argument + 4), &mut address) };
    if (status.0 as i32) < 0 { 0 } else { address }
}

/// Debug monitor control code 0x86 (stock 0x91f3ba40 -> 0x91f330f0):
/// replace the `MmQueryStatistics` result at `argument` with the debug
/// monitor's statistics when the lengths match, then correct the available
/// page count and the total page count for debug memory.
pub(crate) fn service_adjust_memory_statistics(argument: u32) -> u32 {
    let mut reply = [0u32; MEMORY_STATISTICS_REPLY_WORDS];
    reply[0] = (MEMORY_STATISTICS_REPLY_WORDS * 4) as u32;
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
    if (status.0 as i32) < 0 || reply[0] < (MEMORY_STATISTICS_REPLY_WORDS * 4) as u32 {
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
    // SAFETY: the kernel validates the address before it maps it.
    let mapped = unsafe { xboxkrnl::MmDbgReadCheck(address) };
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
    // SAFETY: `context` is a live local of the size the kernel fills.
    let mapped = unsafe { xboxkrnl::MmDbgWriteCheck(address, context.as_mut_ptr()) };
    if mapped == 0 {
        return false;
    }
    if memory::is_device_address(mapped) {
        // SAFETY: `mapped` and `context` come from `MmDbgWriteCheck` above.
        unsafe { xboxkrnl::MmDbgReleaseAddress(mapped, context.as_mut_ptr()) };
        return false;
    }
    let pointer = mapped as usize as *mut u8;
    // SAFETY: the kernel mapped the address writable for the debugger;
    // `mapped` and `context` come from `MmDbgWriteCheck` above.
    unsafe {
        core::ptr::write_volatile(pointer, value);
        xboxkrnl::KeSweepIcacheRange(pointer, 1);
        xboxkrnl::MmDbgReleaseAddress(mapped, context.as_mut_ptr());
    }
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
        // SAFETY: `entry` is linked into a loader module list of the debug
        // monitor data; the caller holds the loader lock.
        let current =
            unsafe { &*core::ptr::with_exposed_provenance::<LdrDataTableEntry>(entry as usize) };
        if current.dll_base == base {
            return true;
        }
        entry = current.in_load_order_links.flink.load(Ordering::Relaxed);
    }
    false
}

/// The CodeView record of the module loaded at `base` (0x91f280d8).
fn code_view_of(base: u32) -> Option<CodeView> {
    let _lock = LoaderLock::acquire();
    let data = kernel::debug_monitor_data();
    let mut directory = 0u32;
    let mut size = 0u32;
    if list_has_base(data.loaded_module_list.load(Ordering::Relaxed), base) {
        // SAFETY: `base` is a module in the loader list, held by the loader lock.
        directory =
            unsafe { RtlImageDirectoryEntryToData(base, true, ImageDirectory::Debug, &mut size) };
    }
    if directory == 0 || size == 0 {
        directory = 0;
        if list_has_base(
            data.loaded_usermode_module_list.load(Ordering::Relaxed),
            base,
        ) {
            // SAFETY: `base` is a module in the loader list, held by the loader lock.
            directory = unsafe {
                RtlImageDirectoryEntryToData(base, true, ImageDirectory::Debug, &mut size)
            };
        }
    }
    if directory == 0 || size == 0 {
        return None;
    }
    let count = size as usize / core::mem::size_of::<ImageDebugDirectory>();
    // SAFETY: the debug directory of a mapped image holds `size` bytes and
    // stays mapped under the loader lock.
    let entries = unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance::<ImageDebugDirectory>(directory as usize),
            count,
        )
    };
    // Any CodeView entry selects the record named by the first entry.
    if !entries
        .iter()
        .any(|entry| entry.debug_type() == DebugType::CODEVIEW)
    {
        return None;
    }
    let record = base.wrapping_add(entries.first()?.address_of_raw_data.get());
    // SAFETY: the debug data of a mapped image lies in the image.
    let record = unsafe { &*core::ptr::with_exposed_provenance::<CodeViewRsds>(record as usize) };
    if record.signature != CodeViewRsds::SIGNATURE {
        return None;
    }
    let path = core::ptr::from_ref(&record.path).addr();
    Some(CodeView::read(record.guid, record.age.bytes(), |offset| {
        // SAFETY: the path is NUL-terminated in the mapped image.
        unsafe { core::ptr::read_volatile(core::ptr::with_exposed_provenance::<u8>(path + offset)) }
    }))
}

impl memory::Backend for Console {
    fn is_address_valid(&mut self, address: u32) -> bool {
        xboxkrnl::MmIsAddressValid(address).get()
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
        let lock = LoaderLock::acquire();
        let (entry, header) = all_entries(&lock)
            .filter(|entry| is_reported(entry))
            .filter_map(|entry| nt_header(entry).map(|header| (entry, header)))
            .nth(index.0 as usize)?;
        let base = entry.dll_base;
        let mut pdata_size = 0u32;
        // SAFETY: `base` is a module image with an NT header, held by the loader lock.
        let pdata = unsafe {
            RtlImageDirectoryEntryToData(base, true, ImageDirectory::Exception, &mut pdata_size)
        };
        Some(ModuleInfo {
            name: ModuleName::from_units(entry_name_units(entry)),
            base,
            size: entry.image_size,
            checksum: header.optional_header.check_sum.get(),
            timestamp: header.file_header.time_date_stamp.get(),
            pdata,
            pdata_size,
            dll: header
                .file_header
                .characteristics()
                .contains(ImageCharacteristics::DLL),
            image_size: header.optional_header.size_of_image.get(),
        })
    }

    fn module_section(
        &mut self,
        name: &[u8],
        index: SectionIndex,
    ) -> Result<Option<SectionInfo>, NoSuchModule> {
        let lock = LoaderLock::acquire();
        let entry = find_entry(&lock, name).ok_or(NoSuchModule)?;
        let header = nt_header(entry).ok_or(NoSuchModule)?;
        let Some(slot) = index.0.checked_sub(1) else {
            return Ok(None);
        };
        // SAFETY: the headers of a loaded image, mapped under the loader lock.
        let sections = unsafe { header.sections() };
        Ok(sections
            .get(usize::from(slot))
            .map(|section| section_info(section, entry.dll_base)))
    }

    fn code_view(&mut self, base: u32) -> Option<CodeView> {
        code_view_of(base)
    }

    fn xex_header_field(
        &mut self,
        module: &[u8],
        field: XexFieldKey,
    ) -> Result<u32, XexFieldError> {
        let lock = LoaderLock::acquire();
        let entry = find_entry(&lock, module).ok_or(XexFieldError::NoSuchModule)?;
        // SAFETY: the entry's XEX header stays mapped under the loader lock.
        let value = unsafe { RtlImageXexHeaderField(entry.xex_header_base, XexHeaderKey(field.0)) };
        match value {
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
        let lock = LoaderLock::acquire();
        let entry = find_entry(&lock, module).ok_or(XexFieldError::NoSuchModule)?;
        // SAFETY: the entry's XEX header stays mapped under the loader lock.
        let data = unsafe { RtlImageXexHeaderField(entry.xex_header_base, XexHeaderKey(field.0)) };
        let data = match data {
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
        let module = kernel::resolved(&XexExecutableModuleHandle).load(Ordering::Relaxed);
        if module == 0 {
            return Err(NoSuchModule);
        }
        // SAFETY: the executable module handle is the loader entry of the
        // running executable, which stays loaded while it runs.
        let entry =
            unsafe { &*core::ptr::with_exposed_provenance::<LdrDataTableEntry>(module as usize) };
        // SAFETY: the running executable's XEX header stays mapped while it runs.
        let value = unsafe { RtlImageXexHeaderField(entry.xex_header_base, XexHeaderKey(field.0)) };
        match value {
            0 => Ok(None),
            data => Ok(Some(read_u32(data))),
        }
    }

    fn running_executable_path(&mut self, output: &mut [u8]) -> usize {
        kernel::resolved(&ExLoadedImageName).copy_to(output)
    }

    fn read_flash(&mut self, offset: u32, output: &mut [u8]) -> Result<(), KernelError> {
        super::system::flash::device_read(offset, output.as_mut_ptr(), output.len() as u32)
    }

    fn write_flash(&mut self, offset: u32, data: &[u8]) -> Result<(), KernelError> {
        super::system::flash::device_write(offset, data.as_ptr(), data.len() as u32)
    }

    fn trace_imports(&mut self, module: &[u8], enable: bool) -> bool {
        let Ok(kernel_module) = SystemModule::Kernel.handle() else {
            return false;
        };
        let Ok(function) = resolve_export(kernel_module, TRACE_IMPORTS_ORDINAL) else {
            return false;
        };
        let mut name = [0u8; 0x104];
        let count = module.len().min(name.len() - 1);
        name[..count].copy_from_slice(&module[..count]);
        // SAFETY: the export takes a module name and an enable flag.
        unsafe {
            kernel::call_export(
                function.raw(),
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

    fn write_tracking_records(&mut self, file: filesystem::FileHandle) -> Result<(), KernelError> {
        let length = record_length() as usize;
        let mut record = TRACKING.head.load(Ordering::Relaxed);
        while record != 0 {
            // SAFETY: records stay allocated while tracked; the title is
            // stopped during the save.
            let bytes =
                unsafe { core::slice::from_raw_parts(record as usize as *const u8, length) };
            self.write_file(file, None, filesystem::FileData::Bytes(bytes))?;
            record = read_unaligned_u32(record);
        }
        Ok(())
    }

    fn dos_error_from_nt_status(&mut self, error: KernelError) -> Option<Win32Error> {
        xboxkrnl::RtlNtStatusToDosError(NtStatus::from(error)).error()
    }

    fn detour(
        &mut self,
        operation: &mut dyn FnMut(&memory::detour::Engine, &dyn memory::detour::Platform),
    ) {
        detour::with_engine(operation);
    }

    fn start_detour_log(&mut self, log: Option<&[u8]>) -> Result<(), KernelError> {
        detour::start(log)
    }

    fn stop_detour_log(&mut self, log: Option<&[u8]>) {
        detour::stop(log);
    }

    fn read_detour_record(&mut self, output: &mut [u8; memory::detour::RECORD_SIZE]) -> bool {
        detour::read_record(output)
    }
}
