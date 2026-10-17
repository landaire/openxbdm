//! Virtual memory, loaded modules, raw flash, import tracing, and
//! allocation tracking.

use core::fmt::Write as _;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
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
use xbox360_sys::xboxkrnl::DebugMemoryStatistics;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::ExLoadedImageName;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::LdrDataTableEntry;
use xbox360_sys::xboxkrnl::MmStatistics;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::RtlAssert;
use xbox360_sys::xboxkrnl::RtlImageDirectoryEntryToData;
use xbox360_sys::xboxkrnl::RtlImageNtHeader;
use xbox360_sys::xboxkrnl::RtlImageXexHeaderField;
use xbox360_sys::xboxkrnl::XexExecutableModuleHandle;

use super::Console;
use crate::kernel;
use crate::kernel::LoaderLock;
use crate::kernel::ModuleList;

mod detour;
mod exports;

pub(crate) use exports::MODULE_RECORD_SHORT_SIZE;
pub(crate) use exports::ModuleWalkError;
pub(crate) use exports::module_debug_directory;
pub(crate) use exports::next_module;

/// Debugger context the kernel fills for a writable mapping.
const WRITE_CONTEXT_WORDS: usize = 14;

/// Kernel export that configures import tracing for a module name.
const TRACE_IMPORTS_ORDINAL: Ordinal = Ordinal::new(0x2cf).unwrap();

/// Pool tag of allocation tracking records ('xmem').
const TRACKING_POOL_TAG: PoolTag = PoolTag::new(*b"memx");
const TRACKING_ASSERT_FILE: &core::ffi::CStr =
    c"e:\\xenon\\xdksep13\\core\\private\\xdk\\tools\\debug\\xbdm\\core\\alloctrk.c";
const TRACKING_ASSERT_LINE: u32 = 0x73;
const TRACK_ASSERT_LINE: u32 = 0xac;
const UNTRACK_ASSERT_LINE: u32 = 0xef;

xbox360_sys::flags! {
    /// Bits of the allocation tracking flags word that select types and
    /// diagnostics.
    pub struct TrackingOptions(u32) {
        /// Track type 0 (heap).
        HEAP = 0x1,
        /// Track type 1 (virtual-mapped memory).
        VIRTUAL_MAPPED = 0x2,
        /// Track the types titles register.
        REGISTERED = 0x80,
        /// Report diagnostics as assertions.
        ASSERT = 0x100,
    }
}

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
#[derive(Debug, Clone, Copy)]
enum Tracked {
    /// The record was added or removed.
    Done,
    /// The type is not tracked.
    TypeNotTracked,
}

impl From<Tracked> for Hresult {
    fn from(tracked: Tracked) -> Self {
        match tracked {
            Tracked::Done => Hresult::SUCCESS,
            Tracked::TypeNotTracked => Hresult::FALSE,
        }
    }
}

/// A failed tracking hook call.
#[derive(Debug, Clone, Copy)]
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

impl core::fmt::Display for TrackingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            TrackingError::Off => "allocation tracking is off",
            TrackingError::UnknownType => "unknown allocation type",
            TrackingError::OutOfMemory => "no memory for a tracking record",
            TrackingError::NotFound => "no tracking record has the address",
            TrackingError::TypeMismatch => "the tracking record has another type",
            TrackingError::SizeMismatch => "the tracking record has another size",
        })
    }
}

impl core::error::Error for TrackingError {}

impl From<TrackingError> for Hresult {
    fn from(error: TrackingError) -> Self {
        match error {
            TrackingError::Off => Hresult::from_win32(Win32Error::SERVICE_NOT_ACTIVE),
            TrackingError::UnknownType | TrackingError::TypeMismatch => Hresult::INVALID_ARGUMENT,
            TrackingError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            TrackingError::NotFound => Hresult::from_win32(Win32Error::NOT_FOUND),
            TrackingError::SizeMismatch => Hresult::from_win32(Win32Error::BAD_LENGTH),
        }
    }
}

type TrackingResult = Result<Tracked, TrackingError>;

/// The HRESULT a tracking hook returns to the kernel or the title.
fn tracking_hresult(result: TrackingResult) -> Hresult {
    match result {
        Ok(tracked) => tracked.into(),
        Err(error) => error.into(),
    }
}

/// Module init of this domain: the detour trampolines and engine.
pub(crate) fn initialize() {
    detour::initialize();
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

/// The base name units of an entry from [`LoaderEntries`].
fn entry_name_units<'a>(
    _lock: &'a LoaderLock,
    entry: &'a LdrDataTableEntry,
) -> impl Iterator<Item = u16> + 'a {
    let length = usize::from(entry.base_dll_name.length >> 1);
    let buffer = core::ptr::with_exposed_provenance::<u16>(entry.base_dll_name.buffer as usize);
    // SAFETY: the name buffer of a linked loader entry holds `length` units
    // and stays mapped while `_lock` is held.
    (0..length).map(move |index| unsafe { buffer.add(index).read() })
}

/// The entry whose base name exactly matches `name`, searching the first
/// list and then the second.
fn find_entry<'a>(lock: &'a LoaderLock, name: &[u8]) -> Option<&'a LdrDataTableEntry> {
    lock.all_entries()
        .find(|entry| memory::module_name_matches(entry_name_units(lock, entry), name, true))
}

/// The loader entry of the module whose base name exactly matches `name`
/// (stock 0x91f33fb0 with exact matching), looked up under the loader lock.
pub(crate) fn loader_entry(name: &[u8]) -> Option<u32> {
    let lock = LoaderLock::acquire();
    find_entry(&lock, name).map(kernel::address_of)
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
    if TrackingOptions::from_bits_retain(TRACKING.flags.load(Ordering::Relaxed))
        .contains(TrackingOptions::ASSERT)
    {
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
    /// [`TrackingFlags`] in effect.
    flags: AtomicU32,
    /// Spin lock guarding the record list.
    lock: KspinLock,
    /// Address of the newest [`TrackingRecord`], or 0.
    head: AtomicU32,
    count: AtomicU32,
}

static TRACKING: Tracking = Tracking {
    flags: AtomicU32::new(0),
    lock: KspinLock::new(),
    head: AtomicU32::new(0),
    count: AtomicU32::new(0),
};

/// Holds the tracking spin lock for its lifetime.
struct TrackingLock(Irql);

impl TrackingLock {
    fn acquire() -> Self {
        // SAFETY: the static tracking spin lock.
        Self(unsafe { xboxkrnl::KfAcquireSpinLock(TRACKING.lock.as_ptr()) })
    }
}

impl Drop for TrackingLock {
    fn drop(&mut self) {
        // SAFETY: `acquire` took the tracking lock at `self.0`.
        unsafe { xboxkrnl::KfReleaseSpinLock(TRACKING.lock.as_ptr(), self.0) };
    }
}

/// An allocation tracking record: a pool block of [`record_length`]
/// bytes, this header followed by the captured return addresses. The
/// `save` file holds the records as stored.
#[repr(C, packed)]
struct TrackingRecord {
    /// Address of the next older record, or 0.
    next: u32,
    kind: u16,
    size: u32,
    address: u32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(TrackingRecord, kind) == 4);
    assert!(offset_of!(TrackingRecord, size) == 6);
    assert!(offset_of!(TrackingRecord, address) == 0xa);
    assert!(core::mem::size_of::<TrackingRecord>() == 0xe);
};

/// The record at `address`, or `None` for 0.
///
/// # Safety
///
/// `address` is 0 or a record linked into [`TRACKING`], the caller holds
/// the tracking lock or otherwise keeps the list from changing for `'a`,
/// and no other reference to the record exists for `'a`.
unsafe fn linked_record<'a>(address: u32) -> Option<&'a mut TrackingRecord> {
    // SAFETY: per the caller; records are pool blocks of this module.
    unsafe { core::ptr::with_exposed_provenance_mut::<TrackingRecord>(address as usize).as_mut() }
}

fn record_length() -> u32 {
    (core::mem::size_of::<TrackingRecord>() as u32)
        .wrapping_add(memory::ACTIVE_STACK_DEPTH.0.wrapping_shl(2))
}

fn tracking_type_enabled(kind: u16, flags: TrackingOptions) -> bool {
    match kind {
        0 => flags.contains(TrackingOptions::HEAP),
        1 => flags.contains(TrackingOptions::VIRTUAL_MAPPED),
        kind if usize::from(kind) < memory::TRACKING_TYPE_NAMES.len() => true,
        _ => flags.contains(TrackingOptions::REGISTERED),
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

/// Argument block of control codes 8 and 9.
#[repr(C)]
struct TrackingRequest {
    address: u32,
    size: u32,
    /// The type index is the low byte.
    kind: u32,
}

impl TrackingRequest {
    fn kind(&self) -> u16 {
        u16::from(self.kind as u8)
    }
}

/// Debug monitor control code 8 (stock 0x91f3b73c -> 0x91f23598): track an
/// allocation. The stock return value is residual.
///
/// # Safety
///
/// `arguments` must be the address of a `TrackingRequest` (the address,
/// size, and type dwords) the caller keeps unchanged for the call.
pub(crate) unsafe fn service_memtrack_record_alloc(arguments: u32) -> u32 {
    // SAFETY: the caller's contract.
    let request = unsafe { kernel::object_at::<TrackingRequest>(arguments) };
    let _ = track_allocation(request.address, request.size, request.kind());
    0
}

/// 0x91f23598.
fn track_allocation(address: u32, size: u32, kind: u16) -> TrackingResult {
    if address == 0 {
        assert_allocation_pointer(TRACK_ASSERT_LINE);
    }
    let flags = TRACKING.flags.load(Ordering::Relaxed);
    if !TrackingFlags::from_bits_retain(flags).is_active() {
        return Err(TrackingError::Off);
    }
    if u32::from(kind) >= tracking_type_count() {
        return Err(TrackingError::UnknownType);
    }
    if !tracking_type_enabled(kind, TrackingOptions::from_bits_retain(flags)) {
        return Ok(Tracked::TypeNotTracked);
    }
    let length = record_length();
    // SAFETY: pool allocation has no pointer arguments.
    let block = unsafe { xboxkrnl::ExAllocatePoolWithTag(length, TRACKING_POOL_TAG) };
    let record = core::ptr::with_exposed_provenance_mut::<TrackingRecord>(block as usize);
    if record.is_null() {
        tracking_diagnostic(format_args!(
            "unable to allocate buffer for allocation tracking"
        ));
        return Err(TrackingError::OutOfMemory);
    }
    let stack = memory::ACTIVE_STACK_DEPTH.0 << 2;
    // SAFETY: the new pool block holds `length` bytes: the header and the
    // stack area after it. It is not linked yet.
    unsafe {
        (*record).address = address;
        (*record).size = size;
        (*record).kind = kind;
        if stack != 0 {
            core::ptr::write_bytes(record.add(1).cast::<u8>(), 0, stack as usize);
        }
    }
    let lock = TrackingLock::acquire();
    // SAFETY: the record is the block filled above; the lock guards the list.
    unsafe { (*record).next = TRACKING.head.load(Ordering::Relaxed) };
    TRACKING.head.store(block, Ordering::Relaxed);
    TRACKING.count.fetch_add(1, Ordering::Relaxed);
    drop(lock);
    Ok(Tracked::Done)
}

/// Debug monitor control code 9 (stock 0x91f3b754 -> 0x91f236d8): stop
/// tracking an allocation. A size of 0 matches any recorded size. Returns
/// the lookup HRESULT when the type is tracked; the stock value is residual
/// otherwise.
///
/// # Safety
///
/// `arguments` must be the address of a `TrackingRequest` the caller
/// keeps unchanged for the call.
pub(crate) unsafe fn service_memtrack_record_free(arguments: u32) -> u32 {
    // SAFETY: the caller's contract.
    let request = unsafe { kernel::object_at::<TrackingRequest>(arguments) };
    match untrack_allocation(request.address, request.size, request.kind()) {
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
    if !TrackingFlags::from_bits_retain(flags).is_active() {
        return Untracked::Skipped(Err(TrackingError::Off));
    }
    if u32::from(kind) >= tracking_type_count() {
        return Untracked::Skipped(Err(TrackingError::UnknownType));
    }
    if !tracking_type_enabled(kind, TrackingOptions::from_bits_retain(flags)) {
        return Untracked::Skipped(Ok(Tracked::TypeNotTracked));
    }
    let lock = TrackingLock::acquire();
    let mut previous: Option<&mut TrackingRecord> = None;
    // SAFETY: the head is 0 or a linked record; `lock` is held and this
    // walk holds the only references, one per record.
    let mut current = unsafe { linked_record(TRACKING.head.load(Ordering::Relaxed)) };
    let found = loop {
        let Some(record) = current else {
            break None;
        };
        if record.address == address {
            break Some(record);
        }
        let next = record.next;
        previous = Some(record);
        // SAFETY: as above; `next` links a record after `record`.
        current = unsafe { linked_record(next) };
    };
    let mut release = None;
    let result = match found {
        None => {
            tracking_diagnostic(format_args!(
                "no history tracking found freeing {} @ {:08X} size {}",
                tracking_type_name(kind),
                address,
                size as i32
            ));
            Err(TrackingError::NotFound)
        }
        Some(record) => {
            let recorded_kind = record.kind;
            if recorded_kind != kind {
                tracking_diagnostic(format_args!(
                    "mismatch allocator @ {:08X} (was {}, expected {})",
                    address,
                    tracking_type_name(recorded_kind),
                    tracking_type_name(kind)
                ));
                Err(TrackingError::TypeMismatch)
            } else if size == 0 || size == record.size {
                let next = record.next;
                match previous {
                    Some(previous) => previous.next = next,
                    None => TRACKING.head.store(next, Ordering::Relaxed),
                }
                TRACKING.count.fetch_sub(1, Ordering::Relaxed);
                release = Some(core::ptr::from_mut(record).addr() as u32);
                Ok(Tracked::Done)
            } else {
                tracking_diagnostic(format_args!(
                    "invalid size freeing {} @ {:08X}",
                    tracking_type_name(kind),
                    address
                ));
                Err(TrackingError::SizeMismatch)
            }
        }
    };
    drop(lock);
    if let Some(record) = release {
        // SAFETY: the record is a pool block unlinked from the list above.
        unsafe { xboxkrnl::ExFreePool(record) };
    }
    Untracked::Lookup(result)
}

/// Argument block of control code 0x18.
#[repr(C)]
struct ProcAddressRequest {
    /// Address of the NUL-terminated module name.
    name: u32,
    ordinal: u32,
}

/// Debug monitor control code 0x18 (stock 0x91f3b804 -> 0x91f33d38): the
/// address of export `ordinal` of a loaded module, or 0.
///
/// # Safety
///
/// `argument` must be the address of a `ProcAddressRequest` whose name is a
/// NUL-terminated string, both unchanged for the call.
pub(crate) unsafe fn service_get_module_proc_address(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let request = unsafe { kernel::object_at::<ProcAddressRequest>(argument) };
    let mut module = 0u32;
    // SAFETY: the caller's contract for the name; `module` is a live local.
    let status = unsafe {
        xboxkrnl::XexGetModuleHandle(
            core::ptr::with_exposed_provenance(request.name as usize),
            &mut module,
        )
    };
    if !status.is_success() {
        return 0;
    }
    let mut address = 0u32;
    // SAFETY: `module` was returned by the kernel; `address` is a live local.
    let status = unsafe { xboxkrnl::XexGetProcedureAddress(module, request.ordinal, &mut address) };
    if status.is_success() { address } else { 0 }
}

/// Debug monitor control code 0x86 (stock 0x91f3ba40 -> 0x91f330f0):
/// replace the `MmQueryStatistics` result at `argument` with the debug
/// monitor's statistics when the lengths match, then correct the available
/// page count and the total page count for debug memory.
///
/// # Safety
///
/// `argument` must be the address of the caller's `MmQueryStatistics`
/// block, aligned or not, whose length field the caller set and which holds
/// that many writable bytes, not otherwise accessed for the call.
pub(crate) unsafe fn service_adjust_memory_statistics(argument: u32) -> u32 {
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
    if !status.is_success() || !reply.is_complete() {
        return 0;
    }
    // Stock stores to the caller's block without assuming alignment.
    let statistics = core::ptr::with_exposed_provenance_mut::<MmStatistics>(argument as usize);
    // SAFETY: the caller's contract.
    let length = unsafe { (&raw const (*statistics).length).read_unaligned() };
    if reply.statistics.length != length || reply.unknown_084 == 0 {
        return 0;
    }
    let title = &reply.statistics.title;
    let free = title.available_pages.wrapping_sub(reply.unknown_06c);
    let limit = reply
        .unknown_080
        .wrapping_sub(title.image_pages)
        .wrapping_sub(title.physical_pages);
    // SAFETY: the caller's contract; the length equals the one the service
    // reported for the `MmStatistics` it filled.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (&raw const reply.statistics).cast::<u8>(),
            statistics.cast::<u8>(),
            length as usize,
        );
        (&raw mut (*statistics).title.available_pages).write_unaligned(free.min(limit));
        (&raw mut (*statistics).total_physical_pages)
            .write_unaligned(reply.unknown_088.wrapping_add(reply.unknown_080));
    }
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
    // SAFETY: the kernel reported the address readable by the debugger and
    // not a device; other threads may write it, so it is read atomically.
    let byte =
        unsafe { AtomicU8::from_ptr(core::ptr::with_exposed_provenance_mut(address as usize)) };
    Some(byte.load(Ordering::Relaxed))
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
    let pointer = core::ptr::with_exposed_provenance_mut::<u8>(mapped as usize);
    // SAFETY: the kernel mapped the address writable for the debugger and
    // it is not a device; other threads may access it, so it is written
    // atomically. `mapped` and `context` come from `MmDbgWriteCheck` above.
    unsafe {
        AtomicU8::from_ptr(pointer).store(value, Ordering::Relaxed);
        xboxkrnl::KeSweepIcacheRange(pointer, 1);
        xboxkrnl::MmDbgReleaseAddress(mapped, context.as_mut_ptr());
    }
    true
}

/// Whether the loader list `list` has an entry for the module loaded at
/// `base`.
fn list_has_base(lock: &LoaderLock, list: ModuleList, base: u32) -> bool {
    lock.entries(list).any(|entry| entry.dll_base == base)
}

/// The CodeView record of the module loaded at `base` (0x91f280d8).
fn code_view_of(base: u32) -> Option<CodeView> {
    let lock = LoaderLock::acquire();
    let mut directory = 0u32;
    let mut size = 0u32;
    if list_has_base(&lock, ModuleList::Loaded, base) {
        // SAFETY: `base` is a module in the loader list, held by the loader lock.
        directory =
            unsafe { RtlImageDirectoryEntryToData(base, true, ImageDirectory::Debug, &mut size) };
    }
    if directory == 0 || size == 0 {
        directory = 0;
        if list_has_base(&lock, ModuleList::Usermode, base) {
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
    let record = unsafe { kernel::object_at::<CodeViewRsds>(record) };
    if record.signature != CodeViewRsds::SIGNATURE {
        return None;
    }
    let path = kernel::address_of(&record.path) as usize;
    Some(CodeView::read(record.guid, record.age.bytes(), |offset| {
        // SAFETY: the path is NUL-terminated in the image, which stays
        // mapped under the loader lock.
        unsafe { core::ptr::with_exposed_provenance::<u8>(path + offset).read() }
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
        let (entry, header) = lock
            .all_entries()
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
            name: ModuleName::from_units(entry_name_units(&lock, entry)),
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
        // SAFETY: the headers of a loaded image, mapped under the loader
        // lock; the linker emits an optional header whose size is a multiple
        // of 4, so the section table is aligned.
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
        // SAFETY: `data_imports_resolved` held at module load.
        let module = unsafe { XexExecutableModuleHandle.get_unchecked() }.load(Ordering::Relaxed);
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
            // SAFETY: a nonzero result addresses the field's dword in the
            // XEX header, which stays mapped while the executable runs.
            data => Ok(Some(unsafe {
                core::ptr::with_exposed_provenance::<u32>(data as usize).read()
            })),
        }
    }

    fn running_executable_path(&mut self, output: &mut [u8]) -> usize {
        // SAFETY: `data_imports_resolved` held at module load.
        unsafe { ExLoadedImageName.get_unchecked() }.copy_to(output)
    }

    fn read_flash(&mut self, offset: u32, output: &mut [u8]) -> Result<(), KernelError> {
        super::system::flash::device_read(offset, output)
    }

    fn write_flash(&mut self, offset: u32, data: &[u8]) -> Result<(), KernelError> {
        super::system::flash::device_write(offset, data)
    }

    fn trace_imports(&mut self, module: &[u8], enable: bool) -> bool {
        let Ok(kernel_module) = SystemModule::Kernel.handle() else {
            return false;
        };
        let Ok(function) = resolve_export(kernel_module, TRACE_IMPORTS_ORDINAL) else {
            return false;
        };
        const NAME_CAPACITY: usize = 0x104;
        let mut name = [0u8; NAME_CAPACITY];
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
        TrackingFlags::from_bits_retain(TRACKING.flags.load(Ordering::Relaxed))
    }

    fn set_tracking_flags(&mut self, flags: TrackingFlags) {
        TRACKING.flags.store(flags.bits(), Ordering::Relaxed);
    }

    fn write_tracking_records(&mut self, file: filesystem::FileHandle) -> Result<(), KernelError> {
        let length = record_length() as usize;
        let mut record = TRACKING.head.load(Ordering::Relaxed);
        while record != 0 {
            let block = core::ptr::with_exposed_provenance::<u8>(record as usize);
            // SAFETY: linked records are pool blocks of `length` bytes that
            // stay allocated while linked; the title is stopped during the
            // save, so the list does not change.
            let bytes = unsafe { core::slice::from_raw_parts(block, length) };
            self.write_file(file, None, filesystem::FileData::Bytes(bytes))?;
            // SAFETY: as above.
            record = unsafe { (*block.cast::<TrackingRecord>()).next };
        }
        Ok(())
    }

    fn dos_error_from_nt_status(&mut self, error: KernelError) -> Option<Win32Error> {
        xbox360::status::dos_error(error)
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
