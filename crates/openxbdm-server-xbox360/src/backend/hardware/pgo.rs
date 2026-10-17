//! PGO instrumentation runtime (stock 0x91f6b900..0x91f71600): the
//! instrumented-module list, count blocks, the value probes instrumented
//! code calls (exports 181-193), profile files, and the controls behind
//! exports 106-115 and `pogoctrl`. Records, count blocks, and thread
//! records live in the title's memory and the title's code shares them;
//! the `#[repr(C)]` views below reach them from the address an export, a
//! kernel call, or an allocation supplies. See `docs/re-notes/pgo.md`.

use core::cell::UnsafeCell;
use core::ffi::CStr;
use core::ffi::c_char;
use core::mem::ManuallyDrop;
use core::mem::offset_of;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU16;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::sync::atomic::fence;

use openxbdm_core::status::NtStatus;
use openxbdm_server::Server;
use openxbdm_server::commands::filesystem::CreateDisposition;
use openxbdm_server::commands::filesystem::CreateOptions;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::FileAccess;
use openxbdm_server::commands::filesystem::FileAttributes;
use openxbdm_server::commands::filesystem::ShareAccess;
use openxbdm_server::commands::hardware::PgoError;
use openxbdm_server::commands::hardware::PgoModule;
use openxbdm_server::commands::hardware::pgo;
use openxbdm_server::commands::hardware::pgo::BadModulePath;
use openxbdm_server::commands::hardware::pgo::BlockFormat;
use openxbdm_server::commands::hardware::pgo::CountBlockHeader;
use openxbdm_server::commands::hardware::pgo::Fatal;
use openxbdm_server::commands::hardware::pgo::IniDirective;
use openxbdm_server::commands::hardware::pgo::ListHead;
use openxbdm_server::commands::hardware::pgo::ModuleShape;
use openxbdm_server::commands::hardware::pgo::PATH_UNITS;
use openxbdm_server::commands::hardware::pgo::PgoOption;
use openxbdm_server::commands::hardware::pgo::ProfileName;
use openxbdm_server::commands::hardware::pgo::RangeTable;
use openxbdm_server::commands::hardware::pgo::SweepKind;
use openxbdm_server::commands::hardware::pgo::TreeDescriptor;
use openxbdm_server::commands::hardware::pgo::WidePath;
use openxbdm_server::commands::hardware::pgo::WriteWarning;
use openxbdm_server::commands::hardware::pgo::block;
use openxbdm_server::commands::memory::PAGE_SIZE;
use xbox360::atomic::AtomicU64;
use xbox360::status::last_error;
use xbox360::status::set_last_error;
use xbox360::status::set_last_error_value;
use xbox360::time::FileTime;
use xbox360_sys::export_raw;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::status::KernelError;
use xbox360_sys::xam;
use xbox360_sys::xam::DuplicateHandle;
use xbox360_sys::xam::DuplicateOptions;
use xbox360_sys::xam::GetCurrentThreadId;
use xbox360_sys::xam::GetProcessHeap;
use xbox360_sys::xam::HeapFlags;
use xbox360_sys::xam::ResetEvent;
use xbox360_sys::xam::RtlAllocateHeap;
use xbox360_sys::xam::RtlFreeHeap;
use xbox360_sys::xam::WaitResult;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::AllocationType;
use xbox360_sys::xboxkrnl::BugCheckCode;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::KeBugCheck;
use xbox360_sys::xboxkrnl::KeTlsAlloc;
use xbox360_sys::xboxkrnl::KeTlsGetValue;
use xbox360_sys::xboxkrnl::KeTlsSetValue;
use xbox360_sys::xboxkrnl::MemoryRegion;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::TlsIndex;
use xbox360_sys::xboxkrnl::XexPcToFileHeader;

use super::super::Console;
use super::super::debugger;
use super::super::dispatcher;
use super::super::filesystem;
use crate::exports::export;
use crate::kernel;
use crate::kernel::CriticalSection;
use crate::kernel::address_of;
use crate::kernel::object_at;
use crate::net::XamNetwork;

/// Entries of a module's probe dispatch table.
const DISPATCH_ENTRIES: usize = 24;
/// Words of a [`ModuleInterface`] that export 112 loads.
const INTERFACE_WORDS: usize = 10;

/// Address of the processor control region, the outside-probe mark.
fn processor_region() -> u32 {
    address_of(Kpcr::current())
}

fn load_units(source: &[AtomicU16], target: &mut [u16]) {
    for (unit, source) in target.iter_mut().zip(source) {
        *unit = source.load(Ordering::Relaxed);
    }
}

fn store_units(target: &[AtomicU16], units: &[u16]) {
    for (target, &unit) in target.iter().zip(units) {
        target.store(unit, Ordering::Relaxed);
    }
}

/// Instrumented-module record (0x6d0 bytes from the title's heap, zeroed).
/// Export 112 links it before filling it, and probes, exports, and the
/// server thread use it concurrently, so the fields written after linking
/// are atomics.
#[repr(C)]
struct ModuleRecord {
    /// Address of the older record; set before linking.
    next: u32,
    /// Address of the module's probe dispatch table; set before linking.
    table: u32,
    /// Dispatch table contents while counting.
    counting: [AtomicU32; DISPATCH_ENTRIES],
    /// Address inside the module, its identity; set before linking.
    module: u32,
    allocation_scale: AtomicU32,
    title_memory: AtomicU32,
    module_word: AtomicU32,
    _reserved_078: u32,
    /// Address of the [`CountBlock`], 0 before one exists.
    block: AtomicU32,
    /// Nonzero: writing the dispatch table faulted; start and stop skip it.
    dead: AtomicU8,
    /// Nonzero: counting requested.
    enabled: AtomicU8,
    _reserved_082: [u8; 2],
    /// Nonzero: profile names carry the phase.
    phase_set: AtomicU32,
    base_path: [AtomicU16; PATH_UNITS],
    phase: [AtomicU16; PATH_UNITS],
    module_name: [AtomicU16; PATH_UNITS],
    has_callers: AtomicU32,
    count_slots: AtomicU32,
    tree_count: AtomicU32,
    list_count: AtomicU32,
    word_count: AtomicU32,
    /// Address of the module header's [`CallTree`] descriptors.
    descriptors: AtomicU32,
    /// Stub routines the dispatch table holds while stopped.
    stubs: [AtomicU32; 3],
    /// Zero from the allocation.
    scratch: u32,
    scale_bonus: AtomicU8,
    extended: AtomicU8,
    fill_counters: AtomicU8,
    /// Set with release once create_block wrote the count block; a byte
    /// stock leaves zero.
    block_written: AtomicU8,
    /// Address of the [`ModuleInterface`] of the first registration.
    interface: AtomicU32,
}

impl ModuleRecord {
    /// The record at `address`, `None` for 0.
    ///
    /// # Safety
    ///
    /// `address` is 0 or a record export 112 allocated. Records stay
    /// allocated until the title ends.
    unsafe fn from_address(address: u32) -> Option<&'static Self> {
        // SAFETY: the caller guarantees the record.
        (address != 0).then(|| unsafe { object_at(address) })
    }

    /// The newest record.
    fn first() -> Option<&'static Self> {
        // SAFETY: MODULES holds 0 or a record of export 112.
        unsafe { Self::from_address(MODULES.load(Ordering::Acquire)) }
    }

    fn next(&self) -> Option<&'static Self> {
        // SAFETY: export 112 sets `next` to the list head it replaces.
        unsafe { Self::from_address(self.next) }
    }

    fn address(&self) -> u32 {
        address_of(self)
    }

    fn has_block(&self) -> bool {
        self.block.load(Ordering::Relaxed) != 0
    }

    /// The count block once create_block wrote it. The acquire load of
    /// `block_written` pairs with its release store there, so the block is
    /// complete for any thread that gets it; stock reads the address alone
    /// (deviation, see `count_block`).
    fn block(&self) -> Option<&'static CountBlock> {
        if self.block_written.load(Ordering::Acquire) == 0 {
            return None;
        }
        // SAFETY: with `block_written` set, `block` holds the count block
        // create_block allocated and wrote for the record, which stays
        // allocated.
        Some(unsafe { CountBlock::from_address(self.block.load(Ordering::Relaxed)) })
    }

    /// The count block, which registration creates before any other use.
    /// A record has none only while export 112 on another thread is still
    /// registering it; stock then reads the header through the null block
    /// address and faults, or reads a block being written. Safe code can
    /// do neither, so the console stops with the `BlockLookup` message
    /// instead (deviation).
    fn count_block(&self) -> &'static CountBlock {
        self.block().unwrap_or_else(|| fatal(Fatal::BlockLookup))
    }

    fn base_path(&self) -> WidePath {
        let mut path = WidePath::default();
        load_units(&self.base_path, &mut path.0);
        path
    }

    fn set_base_path(&self, path: &WidePath) {
        store_units(&self.base_path, &path.0);
    }
}

/// Per-thread record (0x10 bytes from the title's heap). Its thread
/// creates and links it; a sweep unlinks and frees it after the thread
/// ended.
#[repr(C)]
struct ThreadRecord {
    /// The record's own address inside a probe, the processor region
    /// address outside one.
    state: AtomicU32,
    /// Duplicated handle of the thread.
    handle: Handle,
    /// Address of the next record of [`THREADS`].
    next: AtomicU32,
    id: u32,
}

impl ThreadRecord {
    /// The record at `address`, `None` for 0.
    ///
    /// # Safety
    ///
    /// `address` is 0, the calling thread's record, or a record linked in
    /// [`THREADS`] that no sweep frees meanwhile.
    unsafe fn from_address(address: u32) -> Option<&'static Self> {
        // SAFETY: the caller guarantees the record.
        (address != 0).then(|| unsafe { object_at(address) })
    }

    fn address(&self) -> u32 {
        address_of(self)
    }

    /// Mark the thread inside a probe.
    fn enter(&self) {
        self.state.store(self.address(), Ordering::Relaxed);
    }

    /// Mark the thread outside a probe.
    fn leave(&self) {
        self.state.store(processor_region(), Ordering::Relaxed);
    }
}

/// Probe context of exports 182, 185, 188, 191, and 193, on the stack of
/// the instrumented caller, which reads it after the probe returns.
#[repr(C)]
struct ProbeContext {
    /// Call tree key; the caller sets it.
    key: u32,
    /// Address of the caller's [`ThreadRecord`], 0 without one.
    thread: u32,
    /// Address of the [`CountBlock`].
    block: u32,
    /// Sweep generation of the payload, 0 after a failure.
    generation: u32,
    /// Address of the call tree entry's slots; the block's scratch word
    /// after a failure.
    payload: u32,
    /// Address of the [`CallTree`].
    descriptor: u32,
}

impl ProbeContext {
    /// # Safety
    ///
    /// `address` is the caller's context, which nothing else uses for `'a`.
    unsafe fn from_address<'a>(address: u32) -> &'a mut Self {
        // SAFETY: the caller guarantees the context.
        unsafe { &mut *core::ptr::with_exposed_provenance_mut::<Self>(address as usize) }
    }
}

/// Module interface of export 112's seventh argument, in the module.
#[repr(C)]
struct ModuleInterface {
    /// Routines the counting dispatch table takes; the extended format
    /// loads all but word 2 from export 112's eighth argument.
    words: [AtomicU32; INTERFACE_WORDS],
    _reserved_028: [u32; 3],
    /// Address of the module's word for its count block address.
    block_slot: u32,
    /// Address of the module's word for its counter array address.
    counts_slot: u32,
    /// Address of the module's word for the first probe.
    first_probe_slot: u32,
    _reserved_040: u32,
    /// Addresses of the module's words for the other probes.
    probe_slots: [u32; 6],
}

xbox360_sys::flags! {
    /// Flags word of a [`PogoHeader`].
    pub struct PogoHeaderFlags(u32) {
        /// Three more allocation scale steps in the standard format.
        SCALE_BONUS = 0x0800_0000,
    }
}

/// Module header of export 113 (`'POGO'`), in the module.
#[repr(C)]
struct PogoHeader {
    /// [`block::MAGIC_VALUE`], as the count block has it.
    magic: u32,
    version: u32,
    module_word: u32,
    _reserved_00c: u32,
    flags: PogoHeaderFlags,
    tree_count: u32,
    count_slots: u32,
    list_count: u32,
    _reserved_020: [u32; 14],
    word_count: u32,
    _reserved_05c: u32,
    /// `tree_count` call tree descriptors.
    descriptors: [CallTree; 0],
}

impl PogoHeader {
    const VERSION: u32 = 0x2b;

    /// The header at `address`, `None` for 0.
    ///
    /// # Safety
    ///
    /// `address` is 0 or a module header that stays mapped for `'a`.
    unsafe fn from_address<'a>(address: u32) -> Option<&'a Self> {
        // SAFETY: the caller guarantees the header.
        (address != 0).then(|| unsafe { object_at(address) })
    }
}

/// Count block header ([`block`] offsets). This module allocates the
/// block and instrumented code counts in it, so the words probes and
/// sweeps change are atomics. Entries and regions follow at the offsets
/// the header and the entry links hold.
#[repr(C)]
struct CountBlock {
    _magic: u32,
    version: u32,
    _module_word: u32,
    /// Bytes in use from the block start.
    used: AtomicU32,
    /// Creation or reset time, high word first.
    time: [AtomicU32; 2],
    count_slots: u32,
    counts: u32,
    list_count: u32,
    lists: u32,
    wide_entries: AtomicU32,
    tree_count: u32,
    trees: u32,
    path_entries: AtomicU32,
    word_count: u32,
    words: u32,
    _reserved_040: [u32; 4],
    _present: u8,
    _has_callers: u8,
    _reserved_052: [u8; 2],
    committed: AtomicU32,
    reserved: u32,
    state: BlockState,
    threads: AtomicU32,
    _reserved_068: u32,
    /// Sweep generation; changes when a full-buffer sweep clears entries.
    generation: AtomicU32,
    /// Probes running on threads without a thread record.
    untracked: AtomicU32,
    /// Extended only: written to contexts whose probe failed.
    scratch: u32,
}

/// Count block +0x5c..+0x64, laid out by format.
#[repr(C)]
union BlockState {
    standard: ManuallyDrop<StandardState>,
    extended: ManuallyDrop<ExtendedState>,
}

#[repr(C)]
struct StandardState {
    /// Dword 1.
    _sweep_kind: u32,
    /// Dword 1 until the shutdown profile.
    live: AtomicU32,
}

#[repr(C)]
struct ExtendedState {
    /// [`SweepKind`] of the profile being written.
    sweep_kind: AtomicU8,
    /// 1 until the shutdown profile.
    live: AtomicU8,
    /// Counts are reset after the profile being written.
    resetting: AtomicU8,
    /// Set while a full-buffer profile is written.
    full_buffer: [AtomicU8; 2],
    /// A probe dropped data.
    lost: AtomicU8,
    _reserved_062: [u8; 2],
}

impl CountBlock {
    /// # Safety
    ///
    /// `address` is a count block create_block allocated, which stays
    /// allocated. Its links and regions hold the offsets this runtime and
    /// the layout gave them.
    unsafe fn from_address(address: u32) -> &'static Self {
        // SAFETY: the caller guarantees the block.
        unsafe { object_at(address) }
    }

    fn address(&self) -> u32 {
        address_of(self)
    }

    fn format(&self) -> BlockFormat {
        BlockFormat::from_version(self.version)
    }

    fn extended_state(&self) -> &ExtendedState {
        // SAFETY: both views are integers and atomic integers, which
        // every bit pattern makes valid.
        unsafe { &self.state.extended }
    }

    fn standard_state(&self) -> &StandardState {
        // SAFETY: as in `extended_state`.
        unsafe { &self.state.standard }
    }

    fn lose(&self) {
        self.extended_state().lost.store(1, Ordering::Relaxed);
    }

    fn set_time(&self, time: u64) {
        self.time[0].store((time >> 32) as u32, Ordering::Relaxed);
        self.time[1].store(time as u32, Ordering::Relaxed);
    }

    /// The `T` at `offset` from the block start.
    ///
    /// # Safety
    ///
    /// `offset` locates a `T` in the committed part of the block: a
    /// region of the header, an offset from a link of the right kind, or
    /// an allocation of [`allocate`] for a `T`.
    unsafe fn at<T>(&self, offset: u32) -> &T {
        // SAFETY: the caller guarantees the location.
        unsafe { object_at(self.address() + offset) }
    }

    /// The descriptors of the tree region; entry 0 is unused.
    fn trees(&self) -> &[CallTree] {
        let first = core::ptr::with_exposed_provenance((self.address() + self.trees) as usize);
        // SAFETY: the tree region holds `tree_count` descriptors
        // (`from_address`).
        unsafe { core::slice::from_raw_parts(first, self.tree_count as usize) }
    }

    /// Clear `length` bytes at `offset`, one word at a time where stock
    /// calls memset (deviation): probes that were already running when
    /// counting stopped may still update the words, atomically.
    ///
    /// # Safety
    ///
    /// `offset..offset + length` lies in the committed part of the block;
    /// `offset` and `length` are multiples of 4. Other threads access the
    /// range only with 32-bit atomics or from instrumented code.
    #[inline(never)]
    unsafe fn zero(&self, offset: u32, length: u32) {
        let first =
            core::ptr::with_exposed_provenance::<AtomicU32>((self.address() + offset) as usize);
        // SAFETY: guaranteed by the caller.
        let words = unsafe { core::slice::from_raw_parts(first, length as usize / 4) };
        for word in words {
            word.store(0, Ordering::Relaxed);
        }
    }
}

/// Call tree entry (exports 181, 182, 193): the links, then the counter
/// slots and value list heads its [`CallTree`] counts.
#[repr(C)]
struct TreeEntry {
    /// [`pgo::tree_key`] of the key.
    key: AtomicU32,
    /// Offset of the subtree of lower keys.
    lower: AtomicU32,
    /// Offset of the subtree of higher keys.
    higher: AtomicU32,
    _reserved_00c: u32,
}

impl TreeEntry {
    /// Address of the slots after the links.
    fn slots(&self) -> u32 {
        address_of(self) + size_of::<Self>() as u32
    }

    /// The first counter of an extended entry.
    ///
    /// # Safety
    ///
    /// The entry's tree has a counter.
    unsafe fn word_count(&self) -> &AtomicU32 {
        // SAFETY: the caller guarantees the counter.
        unsafe { object_at(self.slots()) }
    }

    /// The first counter of a standard entry.
    ///
    /// # Safety
    ///
    /// The entry's tree has a counter and the entry is 8-byte aligned, as
    /// standard entries are.
    unsafe fn wide_count(&self) -> &AtomicU64 {
        // SAFETY: the caller guarantees the counter.
        unsafe { object_at(self.slots()) }
    }
}

/// Value list entry with a 32-bit value (exports 184, 185, 187, 188).
#[repr(C)]
struct WordEntry {
    value: AtomicU32,
    count: AtomicU32,
    /// Offset of the next entry.
    next: AtomicU32,
}

/// Value list entry with a 64-bit value (exports 183, 186).
#[repr(C)]
struct WideEntry {
    /// High word first.
    value: [AtomicU32; 2],
    count: AtomicU64,
    /// Offset of the next entry.
    next: AtomicU32,
    _reserved_014: u32,
}

impl WideEntry {
    fn value(&self) -> u64 {
        u64::from(self.value[0].load(Ordering::Relaxed)) << 32
            | u64::from(self.value[1].load(Ordering::Relaxed))
    }

    fn set_value(&self, value: u64) {
        self.value[0].store((value >> 32) as u32, Ordering::Relaxed);
        self.value[1].store(value as u32, Ordering::Relaxed);
    }
}

/// Value list head of the standard format (exports 183, 186). The
/// extended head is one [`ListHead`] word.
#[repr(C)]
struct WideListHead {
    /// Entries inserted, for [`pgo::LIST_LIMIT`].
    count: AtomicU32,
    /// Offset of the first entry.
    first: AtomicU32,
}

/// Bytes of a value list head in `format`.
const fn list_head_size(format: BlockFormat) -> u32 {
    match format {
        BlockFormat::Extended => size_of::<AtomicU32>() as u32,
        BlockFormat::Standard => size_of::<WideListHead>() as u32,
    }
}

/// Call tree descriptor, in the module header and in the count block's
/// tree region.
#[repr(C)]
struct CallTree {
    counters: u16,
    lists: u16,
    /// Offset of the root entry, in the count block.
    root: AtomicU32,
}

impl CallTree {
    fn descriptor(&self) -> TreeDescriptor {
        TreeDescriptor {
            counters: self.counters,
            lists: self.lists,
        }
    }
}

/// Range table of exports 189-191; sorted entries of 4 or 8 bytes follow.
#[repr(C)]
struct RangeTableHeader {
    _reserved_000: u32,
    count: u16,
    flags: u16,
}

const _: () = {
    assert!(offset_of!(ModuleRecord, next) == 0x00);
    assert!(offset_of!(ModuleRecord, table) == 0x04);
    assert!(offset_of!(ModuleRecord, counting) == 0x08);
    assert!(offset_of!(ModuleRecord, module) == 0x68);
    assert!(offset_of!(ModuleRecord, allocation_scale) == 0x6c);
    assert!(offset_of!(ModuleRecord, title_memory) == 0x70);
    assert!(offset_of!(ModuleRecord, module_word) == 0x74);
    assert!(offset_of!(ModuleRecord, block) == 0x7c);
    assert!(offset_of!(ModuleRecord, dead) == 0x80);
    assert!(offset_of!(ModuleRecord, enabled) == 0x81);
    assert!(offset_of!(ModuleRecord, phase_set) == 0x84);
    assert!(offset_of!(ModuleRecord, base_path) == 0x88);
    assert!(offset_of!(ModuleRecord, phase) == 0x290);
    assert!(offset_of!(ModuleRecord, module_name) == 0x498);
    assert!(offset_of!(ModuleRecord, has_callers) == 0x6a0);
    assert!(offset_of!(ModuleRecord, count_slots) == 0x6a4);
    assert!(offset_of!(ModuleRecord, tree_count) == 0x6a8);
    assert!(offset_of!(ModuleRecord, list_count) == 0x6ac);
    assert!(offset_of!(ModuleRecord, word_count) == 0x6b0);
    assert!(offset_of!(ModuleRecord, descriptors) == 0x6b4);
    assert!(offset_of!(ModuleRecord, stubs) == 0x6b8);
    assert!(offset_of!(ModuleRecord, scratch) == 0x6c4);
    assert!(offset_of!(ModuleRecord, scale_bonus) == 0x6c8);
    assert!(offset_of!(ModuleRecord, extended) == 0x6c9);
    assert!(offset_of!(ModuleRecord, fill_counters) == 0x6ca);
    assert!(offset_of!(ModuleRecord, block_written) == 0x6cb);
    assert!(offset_of!(ModuleRecord, interface) == 0x6cc);
    assert!(size_of::<ModuleRecord>() == 0x6d0);

    assert!(offset_of!(ThreadRecord, state) == 0x0);
    assert!(offset_of!(ThreadRecord, handle) == 0x4);
    assert!(offset_of!(ThreadRecord, next) == 0x8);
    assert!(offset_of!(ThreadRecord, id) == 0xc);
    assert!(size_of::<ThreadRecord>() == 0x10);

    assert!(offset_of!(ProbeContext, key) == 0x00);
    assert!(offset_of!(ProbeContext, thread) == 0x04);
    assert!(offset_of!(ProbeContext, block) == 0x08);
    assert!(offset_of!(ProbeContext, generation) == 0x0c);
    assert!(offset_of!(ProbeContext, payload) == 0x10);
    assert!(offset_of!(ProbeContext, descriptor) == 0x14);
    assert!(size_of::<ProbeContext>() == 0x18);

    assert!(offset_of!(ModuleInterface, words) == 0x00);
    assert!(offset_of!(ModuleInterface, block_slot) == 0x34);
    assert!(offset_of!(ModuleInterface, counts_slot) == 0x38);
    assert!(offset_of!(ModuleInterface, first_probe_slot) == 0x3c);
    assert!(offset_of!(ModuleInterface, probe_slots) == 0x44);
    assert!(size_of::<ModuleInterface>() == 0x5c);

    assert!(offset_of!(PogoHeader, magic) == 0x00);
    assert!(offset_of!(PogoHeader, version) == 0x04);
    assert!(offset_of!(PogoHeader, module_word) == 0x08);
    assert!(offset_of!(PogoHeader, flags) == 0x10);
    assert!(offset_of!(PogoHeader, tree_count) == 0x14);
    assert!(offset_of!(PogoHeader, count_slots) == 0x18);
    assert!(offset_of!(PogoHeader, list_count) == 0x1c);
    assert!(offset_of!(PogoHeader, word_count) == 0x58);
    assert!(offset_of!(PogoHeader, descriptors) == 0x60);

    assert!(offset_of!(CountBlock, _magic) == block::MAGIC as usize);
    assert!(offset_of!(CountBlock, version) == block::VERSION as usize);
    assert!(offset_of!(CountBlock, _module_word) == block::MODULE_WORD as usize);
    assert!(offset_of!(CountBlock, used) == block::USED as usize);
    assert!(offset_of!(CountBlock, time) == block::TIME as usize);
    assert!(offset_of!(CountBlock, count_slots) == block::COUNT_SLOTS as usize);
    assert!(offset_of!(CountBlock, counts) == block::COUNTS as usize);
    assert!(offset_of!(CountBlock, list_count) == block::LIST_COUNT as usize);
    assert!(offset_of!(CountBlock, lists) == block::LISTS as usize);
    assert!(offset_of!(CountBlock, wide_entries) == block::WIDE_ENTRIES as usize);
    assert!(offset_of!(CountBlock, tree_count) == block::TREE_COUNT as usize);
    assert!(offset_of!(CountBlock, trees) == block::TREES as usize);
    assert!(offset_of!(CountBlock, path_entries) == block::PATH_ENTRIES as usize);
    assert!(offset_of!(CountBlock, word_count) == block::WORD_COUNT as usize);
    assert!(offset_of!(CountBlock, words) == block::WORDS as usize);
    assert!(offset_of!(CountBlock, _present) == block::PRESENT as usize);
    assert!(offset_of!(CountBlock, _has_callers) == block::HAS_CALLERS as usize);
    assert!(offset_of!(CountBlock, committed) == block::COMMITTED as usize);
    assert!(offset_of!(CountBlock, reserved) == block::RESERVED as usize);
    assert!(offset_of!(CountBlock, state) == block::SWEEP_KIND as usize);
    assert!(offset_of!(CountBlock, threads) == block::THREADS as usize);
    assert!(offset_of!(CountBlock, generation) == block::GENERATION as usize);
    assert!(offset_of!(CountBlock, untracked) == block::UNTRACKED as usize);
    assert!(offset_of!(CountBlock, scratch) == block::SCRATCH as usize);
    assert!(size_of::<CountBlock>() == BlockFormat::Extended.header_size() as usize);
    assert!(BlockFormat::Extended.header_size() <= BlockFormat::Standard.header_size());
    assert!(size_of::<BlockState>() == 8);
    assert!(
        block::SWEEP_KIND as usize + offset_of!(StandardState, live)
            == block::FULL_BUFFER_OR_LIVE as usize
    );
    assert!(
        block::SWEEP_KIND as usize + offset_of!(ExtendedState, sweep_kind)
            == block::SWEEP_KIND as usize
    );
    assert!(block::SWEEP_KIND as usize + offset_of!(ExtendedState, live) == block::LIVE as usize);
    assert!(
        block::SWEEP_KIND as usize + offset_of!(ExtendedState, resetting)
            == block::RESETTING as usize
    );
    assert!(
        block::SWEEP_KIND as usize + offset_of!(ExtendedState, full_buffer)
            == block::FULL_BUFFER as usize
    );
    assert!(block::FULL_BUFFER as usize + 1 == block::FULL_BUFFER_OR_LIVE as usize);
    assert!(block::SWEEP_KIND as usize + offset_of!(ExtendedState, lost) == block::LOST as usize);

    assert!(offset_of!(TreeEntry, key) == 0x0);
    assert!(offset_of!(TreeEntry, lower) == 0x4);
    assert!(offset_of!(TreeEntry, higher) == 0x8);
    assert!(size_of::<TreeEntry>() == 0x10);

    assert!(offset_of!(WordEntry, value) == 0x0);
    assert!(offset_of!(WordEntry, count) == 0x4);
    assert!(offset_of!(WordEntry, next) == 0x8);
    assert!(size_of::<WordEntry>() == 0xc);
    assert!(size_of::<WordEntry>() == BlockFormat::Extended.word_entry_size() as usize);

    assert!(offset_of!(WideEntry, value) == 0x00);
    assert!(offset_of!(WideEntry, count) == 0x08);
    assert!(offset_of!(WideEntry, next) == 0x10);
    assert!(size_of::<WideEntry>() == pgo::WIDE_ENTRY_SIZE as usize);

    assert!(offset_of!(WideListHead, count) == 0x0);
    assert!(offset_of!(WideListHead, first) == 0x4);
    assert!(size_of::<WideListHead>() == 0x8);

    assert!(offset_of!(CallTree, counters) == 0x0);
    assert!(offset_of!(CallTree, lists) == 0x2);
    assert!(offset_of!(CallTree, root) == 0x4);
    assert!(size_of::<CallTree>() == 0x8);

    assert!(offset_of!(RangeTableHeader, count) == 0x4);
    assert!(offset_of!(RangeTableHeader, flags) == 0x6);
    assert!(size_of::<RangeTableHeader>() == 0x8);
};

/// Whether the calling thread belongs to the title process (stock
/// 0x91f713b8); other threads get no record.
fn title_thread() -> bool {
    xbox360::thread::current_object().process_type() == ProcessType::TITLE
}

/// Print a failure and stop the console (0x91f74280, then KeBugCheck).
fn fatal(failure: Fatal) -> ! {
    kernel::debug_print_bytes(failure.text().as_bytes());
    KeBugCheck(BugCheckCode::KMODE_EXCEPTION_NOT_HANDLED)
}

fn warn(warning: WriteWarning) {
    kernel::debug_print_bytes(warning.text().as_bytes());
}

fn report_illegal(decoded: pgo::Decoded) {
    for _ in 0..decoded.illegal {
        kernel::debug_print_bytes(pgo::ILLEGAL_UTF8_WARNING.as_bytes());
    }
}

/// The registration lock (0x91fa3ac0).
static SECTION: CriticalSection = CriticalSection::new();

/// Base profile name from export 113 (0x91fa36a8).
struct BaseName(UnsafeCell<[u16; PATH_UNITS]>);

// SAFETY: export 113 writes the name before the module registers; stock
// shares the buffer the same way.
unsafe impl Sync for BaseName {}

static BASE_NAME: BaseName = BaseName(UnsafeCell::new([0; PATH_UNITS]));
/// 0x91fa3ae1: a full-buffer sweep runs; probes wait on [`SWEEP_EVENT`].
static SWEEPING: AtomicBool = AtomicBool::new(false);
/// 0x91fa38b4: address of the newest [`ModuleRecord`].
static MODULES: AtomicU32 = AtomicU32::new(0);
/// 0x91fa3ae4: address of the newest [`ThreadRecord`].
static THREADS: AtomicU32 = AtomicU32::new(0);
/// 0x91fa3ae8: manual-reset event, signaled while no sweep runs.
static SWEEP_EVENT: AtomicU32 = AtomicU32::new(0);
/// 0x91f9904c.
static TLS_INDEX: AtomicU32 = AtomicU32::new(TlsIndex::OUT_OF_INDEXES.0);
/// 0x91fa3adc and 0x91fa38b0 from export 113: addresses of the module
/// header and the module's word table.
static HEADER: AtomicU32 = AtomicU32::new(0);
static WORDS: AtomicU32 = AtomicU32::new(0);
/// `ValidateVPLE`, `ValidateEPLH`, `ValidateVPLH` (0x91fa36a0..2).
static VALIDATE_VPLE: AtomicBool = AtomicBool::new(false);
static VALIDATE_EPLH: AtomicBool = AtomicBool::new(false);
static VALIDATE_VPLH: AtomicBool = AtomicBool::new(false);
/// `EnableSweepOnOverflow`, `EnableSweepFullBuffer` (0x91f99050, 0x91f99051).
static SWEEP_ON_OVERFLOW: AtomicBool = AtomicBool::new(true);
static SWEEP_FULL_BUFFER: AtomicBool = AtomicBool::new(true);

fn modules() -> impl Iterator<Item = &'static ModuleRecord> {
    core::iter::successors(ModuleRecord::first(), |record| record.next())
}

fn find_record(address: u32) -> Option<&'static ModuleRecord> {
    modules().find(|record| record.address() == address)
}

fn record_of_block(block: u32) -> Option<&'static ModuleRecord> {
    modules().find(|record| record.block.load(Ordering::Relaxed) == block)
}

/// Lookup under the registration lock (0x91f6bab0).
fn locked_record_of_block(block: u32) -> &'static ModuleRecord {
    SECTION.enter();
    let record = record_of_block(block);
    SECTION.leave();
    record.unwrap_or_else(|| fatal(Fatal::BlockLookup))
}

/// Store one dispatch table entry. Stock writes under an exception
/// handler that marks the record dead on a fault; an unmapped entry is
/// treated as that fault.
fn store_entry(record: &ModuleRecord, index: usize, value: u32) -> bool {
    let address = record.table.wrapping_add(4 * index as u32);
    if !xboxkrnl::MmIsAddressValid(address).get() {
        record.dead.store(1, Ordering::Relaxed);
        return false;
    }
    // SAFETY: export 112 registered `table` as the module's dispatch
    // table of aligned words, and the word is mapped (checked above).
    let entry = unsafe { object_at::<AtomicU32>(address) };
    entry.swap(value, Ordering::AcqRel);
    true
}

/// Point the dispatch table at the counting routines (0x91f6c090).
fn start_counting(record: &ModuleRecord) {
    for (index, routine) in record.counting.iter().enumerate() {
        if !store_entry(record, index, routine.load(Ordering::Relaxed)) {
            return;
        }
    }
}

/// Point the dispatch table at the stubs (0x91f6c140): stub 0 for entries
/// 0-5 and 21-23, stub 1 for 6-8 and 12-17, stub 2 for 9-11; 18-20 keep
/// their routine.
fn stop_counting(record: &ModuleRecord) {
    for index in 0..DISPATCH_ENTRIES {
        let stub = match index {
            0..=5 | 21..=23 => 0,
            6..=8 | 12..=17 => 1,
            9..=11 => 2,
            _ => continue,
        };
        if !store_entry(record, index, record.stubs[stub].load(Ordering::Relaxed)) {
            return;
        }
    }
}

fn sleep_zero() {
    let interval = 0i64;
    // SAFETY: `interval` is a live local.
    unsafe { xboxkrnl::KeDelayExecutionThread(ProcessorMode::User, false, &interval) };
}

/// Close a handle; a failure sets the last error.
fn close_handle(handle: Handle) -> Result<(), KernelError> {
    // SAFETY: callers pass a handle they own and close once.
    let result = unsafe { xboxkrnl::NtClose(handle) }.result();
    result.inspect_err(|&error| set_last_error(error))
}

fn wait_for_sweep() {
    // SAFETY: SWEEP_EVENT holds the event created at startup.
    unsafe {
        xam::WaitForSingleObject(
            Handle::from_raw(SWEEP_EVENT.load(Ordering::Acquire)),
            xam::INFINITE,
        )
    };
}

/// Enter a probe (0x91f6c690): mark the thread inside, or count it
/// without a record, then wait out a sweep. A thread without a record
/// cannot wait and fails; its count stays raised, as in the image.
fn enter_probe(block: &CountBlock, record: Option<&ThreadRecord>) -> bool {
    match record {
        Some(record) => {
            record.enter();
            fence(Ordering::Release);
        }
        None => {
            block.untracked.fetch_add(1, Ordering::AcqRel);
        }
    }
    while SWEEPING.load(Ordering::Acquire) {
        let Some(record) = record else {
            return false;
        };
        record.leave();
        wait_for_sweep();
        record.enter();
        fence(Ordering::Release);
    }
    true
}

fn leave_probe(block: &CountBlock, record: Option<&ThreadRecord>) {
    match record {
        Some(record) => record.leave(),
        None => {
            block.untracked.fetch_add(u32::MAX, Ordering::AcqRel);
        }
    }
}

/// The calling thread's record, if it has one.
fn own_record() -> Option<&'static ThreadRecord> {
    let index = TlsIndex(TLS_INDEX.load(Ordering::Acquire));
    // SAFETY: the slot holds 0 or the calling thread's record.
    unsafe { ThreadRecord::from_address(KeTlsGetValue(index)) }
}

/// The calling thread's record, created on first use (0x91f6c728).
fn thread_record(block: &CountBlock) -> Option<&'static ThreadRecord> {
    if !title_thread() {
        return None;
    }
    let index = TlsIndex(TLS_INDEX.load(Ordering::Acquire));
    // SAFETY: the slot holds 0 or the calling thread's record.
    if let Some(existing) = unsafe { ThreadRecord::from_address(KeTlsGetValue(index)) } {
        return Some(existing);
    }
    // SAFETY: the process heap takes a size only.
    let address = unsafe {
        RtlAllocateHeap(
            GetProcessHeap(),
            HeapFlags::empty(),
            size_of::<ThreadRecord>() as u32,
        )
    };
    if address == 0 {
        fatal(Fatal::ThreadListAllocation);
    }
    let pointer = core::ptr::with_exposed_provenance_mut::<ThreadRecord>(address as usize);
    // SAFETY: a new heap block of the record's size and alignment, which
    // only this thread reaches until it is linked below.
    unsafe {
        (&raw mut (*pointer).state).write(AtomicU32::new(0));
        (&raw mut (*pointer).id).write(GetCurrentThreadId());
    }
    let mut handle = Handle::NULL;
    // SAFETY: `handle` is a local handle slot.
    if !unsafe {
        DuplicateHandle(
            Handle::NULL,
            Handle::CURRENT_THREAD,
            Handle::NULL,
            &mut handle,
            AccessMask::empty(),
            false,
            DuplicateOptions::SAME_ACCESS,
        )
    }
    .get()
    {
        fatal(Fatal::ThreadHandle);
    }
    // SAFETY: as above.
    unsafe { (&raw mut (*pointer).handle).write(handle) };
    block.threads.fetch_add(1, Ordering::AcqRel);
    loop {
        let head = THREADS.load(Ordering::Acquire);
        // SAFETY: as above; the record is not linked yet.
        unsafe { (&raw mut (*pointer).next).write(AtomicU32::new(head)) };
        if THREADS
            .compare_exchange(head, address, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }
    // SAFETY: every field is written; the record stays allocated while its
    // thread runs.
    let record = unsafe { &*pointer };
    // SAFETY: `index` is the slot allocated at startup.
    unsafe { KeTlsSetValue(index, address) };
    Some(record)
}

fn acquire(block: &CountBlock) -> (Option<&'static ThreadRecord>, bool) {
    let record = thread_record(block);
    (record, enter_probe(block, record))
}

/// Leave the probe ahead of a sweep (0x91f6c618).
fn release_for_sweep(block: &CountBlock) -> Option<&'static ThreadRecord> {
    let record = if title_thread() { own_record() } else { None };
    leave_probe(block, record);
    record
}

/// Stop probes for a sweep (0x91f6c8d8, extended blocks only): optionally
/// start a new generation, then wait until no other thread is inside a
/// probe, freeing the records of threads that ended. Runs under the
/// registration lock.
fn begin_sweep(block: &CountBlock, new_generation: bool) {
    if block.format() != BlockFormat::Extended {
        return;
    }
    // SAFETY: SWEEP_EVENT holds the event created at startup.
    unsafe { ResetEvent(Handle::from_raw(SWEEP_EVENT.load(Ordering::Acquire))) };
    fence(Ordering::Release);
    SWEEPING.store(true, Ordering::Release);
    if new_generation {
        fence(Ordering::Release);
        block.generation.store(
            block.generation.load(Ordering::Relaxed).wrapping_add(1),
            Ordering::Relaxed,
        );
    }
    fence(Ordering::SeqCst);
    let own = if title_thread() {
        KeTlsGetValue(TlsIndex(TLS_INDEX.load(Ordering::Acquire)))
    } else {
        0
    };
    loop {
        let mut link = &THREADS;
        let mut busy = block.untracked.load(Ordering::Relaxed);
        let mut current = link.load(Ordering::Relaxed);
        // SAFETY: THREADS links records of thread_record; only this
        // function frees them, under the registration lock.
        while let Some(record) = unsafe { ThreadRecord::from_address(current) } {
            if current != own {
                // SAFETY: a record holds the duplicated handle of its thread.
                if unsafe { xam::WaitForSingleObject(record.handle, 0) } == WaitResult::OBJECT_0
                    && link
                        .compare_exchange(
                            current,
                            record.next.load(Ordering::Relaxed),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                {
                    let _ = close_handle(record.handle);
                    // SAFETY: the record was unlinked above and came from the
                    // process heap; its thread ended.
                    unsafe { RtlFreeHeap(GetProcessHeap(), HeapFlags::empty(), current) };
                    current = link.load(Ordering::Relaxed);
                    continue;
                }
                if record.state.load(Ordering::Relaxed) == current {
                    busy = busy.wrapping_add(1);
                }
            }
            link = &record.next;
            current = link.load(Ordering::Relaxed);
        }
        if busy == 0 {
            return;
        }
        sleep_zero();
    }
}

fn end_sweep() {
    fence(Ordering::SeqCst);
    SWEEPING.store(false, Ordering::Release);
    // SAFETY: SWEEP_EVENT holds the event created at startup.
    let status = unsafe {
        xboxkrnl::NtSetEvent(
            Handle::from_raw(SWEEP_EVENT.load(Ordering::Acquire)),
            core::ptr::null_mut(),
        )
    };
    if let Err(error) = status.result() {
        set_last_error(error);
    }
}

/// Count block time: GetSystemTime through SystemTimeToFileTime keeps
/// whole milliseconds.
fn block_time() -> u64 {
    FileTime::now().intervals() / 10_000 * 10_000
}

/// Raise the committed size to cover `offset` (0x91f6bc18); past the
/// reservation the console stops.
fn grow(block: &CountBlock, offset: u32) {
    let committed = pgo::align_up(offset.wrapping_add(PAGE_SIZE), PAGE_SIZE);
    if committed > block.reserved {
        locked_record_of_block(block.address());
        fatal(Fatal::ReservationExhausted);
    }
    block.committed.swap(committed, Ordering::AcqRel);
}

/// Allocate `size` bytes of a count block for an entry, sweeping a full
/// extended block when `EnableSweepFullBuffer` is set. Returns the
/// entry's offset; `None` when the thread cannot take part in the sweep.
fn allocate(block: &CountBlock, size: u32) -> Option<u32> {
    let mut offset = block.used.fetch_add(size, Ordering::AcqRel);
    loop {
        let end = offset.wrapping_add(size);
        if end <= block.committed.load(Ordering::Relaxed) {
            return (offset != 0).then_some(offset);
        }
        if block.format() == BlockFormat::Extended
            && SWEEP_FULL_BUFFER.load(Ordering::Relaxed)
            && end > block.reserved
        {
            // Without a record the image would use the offset past the
            // reservation; the entry is dropped instead.
            let record = record_of_block(block.address())?;
            let Some(thread) = release_for_sweep(block) else {
                block.lose();
                return None;
            };
            SECTION.enter();
            if block.used.load(Ordering::Relaxed).wrapping_add(size) > block.reserved {
                full_buffer_sweep(record, block);
            }
            SECTION.leave();
            enter_probe(block, Some(thread));
            offset = block.used.fetch_add(size, Ordering::AcqRel);
            continue;
        }
        grow(block, offset);
        return (offset != 0).then_some(offset);
    }
}

fn full_buffer_sweep(record: &ModuleRecord, block: &CountBlock) {
    begin_sweep(block, true);
    stop_counting(record);
    let state = block.extended_state();
    state.resetting.store(1, Ordering::Relaxed);
    state
        .sweep_kind
        .store(SweepKind::FullBuffer as u8, Ordering::Relaxed);
    state.full_buffer[0].store(1, Ordering::Relaxed);
    state.full_buffer[1].store(1, Ordering::Relaxed);
    write_profile(record);
    state.sweep_kind.store(0, Ordering::Relaxed);
    state.resetting.store(0, Ordering::Relaxed);
    block.set_time(block_time());
    clear_block(block);
    block.committed.store(
        pgo::align_up(block.used.load(Ordering::Relaxed), PAGE_SIZE),
        Ordering::Relaxed,
    );
    start_counting(record);
    end_sweep();
}

/// Clear every count and free every entry (0x91f70f88). Extended blocks
/// only, from a full-buffer sweep.
fn clear_block(block: &CountBlock) {
    let width = block.format().width();
    // SAFETY: the counts and list regions hold `count_slots` counters and
    // `list_count` heads (create_block) at word-aligned offsets; only
    // instrumented code writes the counts, and the sweep stopped the
    // probes. The image clears 4 bytes per head in both formats.
    unsafe {
        block.zero(block.counts, width.wrapping_mul(block.count_slots));
        block.zero(block.lists, block.list_count.wrapping_mul(4));
    }
    for tree in block.trees().iter().skip(1) {
        tree.root.store(0, Ordering::Relaxed);
    }
    let used = pgo::align_up(
        block.word_count.wrapping_mul(4).wrapping_add(block.words),
        size_of::<u32>() as u32,
    );
    block.used.store(used, Ordering::Relaxed);
    // SAFETY: the entry area lies between the word table and the committed
    // end, both word-aligned; the sweep stopped the probes.
    unsafe {
        block.zero(
            used,
            block.committed.load(Ordering::Relaxed).wrapping_sub(used),
        )
    };
}

/// Clear counts and keep entries (0x91f70e40).
fn reset_counts(block: &CountBlock) {
    let format = block.format();
    // SAFETY: the counts region holds `count_slots` counters at a
    // word-aligned offset, which only instrumented code writes.
    unsafe { block.zero(block.counts, format.width().wrapping_mul(block.count_slots)) };
    for index in 0..block.list_count {
        // SAFETY: the list region holds `list_count` heads.
        unsafe { reset_list(block, format, block.lists + list_head_size(format) * index) };
    }
    for tree in block.trees().iter().skip(1) {
        // SAFETY: the root link of a descriptor of the block.
        unsafe { reset_tree(block, format, tree, tree.root.load(Ordering::Relaxed)) };
    }
}

/// Clear the counts of one value list.
///
/// # Safety
///
/// `slot` is the offset of a value list head of `block` in `format`.
unsafe fn reset_list(block: &CountBlock, format: BlockFormat, slot: u32) {
    match format {
        BlockFormat::Extended => {
            // SAFETY: the caller guarantees the head.
            let head: &AtomicU32 = unsafe { block.at(slot) };
            let mut offset = ListHead(head.load(Ordering::Relaxed)).offset();
            while offset != 0 {
                // SAFETY: list links hold offsets of word entries.
                let entry: &WordEntry = unsafe { block.at(offset) };
                offset = entry.next.load(Ordering::Relaxed);
                entry.count.store(0, Ordering::Relaxed);
            }
        }
        BlockFormat::Standard => {
            // SAFETY: the caller guarantees the head.
            let head: &WideListHead = unsafe { block.at(slot) };
            let mut offset = head.first.load(Ordering::Relaxed);
            while offset != 0 {
                // SAFETY: list links hold offsets of wide entries.
                let entry: &WideEntry = unsafe { block.at(offset) };
                offset = entry.next.load(Ordering::Relaxed);
                entry.count.store_relaxed(0);
            }
        }
    }
}

/// Clear the counts of a call tree (0x91f70cf0).
///
/// # Safety
///
/// `offset` is 0 or the offset of an entry of `tree`, a descriptor of
/// `block`.
unsafe fn reset_tree(block: &CountBlock, format: BlockFormat, tree: &CallTree, mut offset: u32) {
    let width = format.width();
    while offset != 0 {
        // SAFETY: the caller guarantees the entry; links of an entry lead
        // to entries of the same tree.
        let entry: &TreeEntry = unsafe { block.at(offset) };
        let counters = u32::from(tree.counters);
        let lists = u32::from(tree.lists);
        let slots = offset + size_of::<TreeEntry>() as u32;
        match format {
            // SAFETY: the word-aligned entry holds `counters` word counters
            // after its links.
            BlockFormat::Extended => unsafe { block.zero(slots, width * counters) },
            // Probes update these counters as doublewords, so they are
            // cleared as doublewords where stock calls memset (deviation).
            BlockFormat::Standard => {
                for index in 0..counters {
                    // SAFETY: the 8-byte aligned entry holds `counters`
                    // doubleword counters after its links.
                    let counter: &AtomicU64 = unsafe { block.at(slots + width * index) };
                    counter.store_relaxed(0);
                }
            }
        }
        let heads = slots + width * counters;
        for index in 0..lists {
            // SAFETY: the entry holds `lists` heads after its counters.
            unsafe { reset_list(block, format, heads + list_head_size(format) * index) };
        }
        // SAFETY: as above.
        unsafe { reset_tree(block, format, tree, entry.lower.load(Ordering::Relaxed)) };
        offset = entry.higher.load(Ordering::Relaxed);
    }
}

/// `ValidateEPLH` (0x91f6c278): `descriptor` is the address of a call
/// tree descriptor of the block.
fn check_tree_descriptor(block: &CountBlock, descriptor: u32) {
    if !VALIDATE_EPLH.load(Ordering::Relaxed) {
        return;
    }
    let stride = size_of::<CallTree>() as u32;
    let trees = block.address().wrapping_add(block.trees);
    if descriptor < trees
        || descriptor & (stride - 1) != 0
        || descriptor
            > (block.tree_count.wrapping_mul(stride))
                .wrapping_add(trees)
                .wrapping_sub(stride)
    {
        fatal(Fatal::InvalidTreeHead);
    }
}

/// `ValidateVPLH` (0x91f6c3f8): a value list head of the block or of one
/// of its call tree entries, at address `head`.
fn check_list_head(block: &CountBlock, head: u32, alignment: u32) {
    if !VALIDATE_VPLH.load(Ordering::Relaxed) {
        return;
    }
    let lists = block.address().wrapping_add(block.lists);
    if head < lists || head & (alignment - 1) != 0 {
        fatal(Fatal::InvalidValueListHead);
    }
    if head
        <= block
            .list_count
            .wrapping_sub(1)
            .wrapping_mul(alignment)
            .wrapping_add(lists)
    {
        return;
    }
    for tree in block.trees() {
        let root = tree.root.load(Ordering::Relaxed);
        // SAFETY: the root link of a descriptor of the block.
        if tree.lists != 0
            && root != 0
            && unsafe { head_in_tree(block, tree, root, head, alignment) }
        {
            return;
        }
    }
    fatal(Fatal::InvalidValueListHead);
}

/// # Safety
///
/// As [`reset_tree`].
unsafe fn head_in_tree(
    block: &CountBlock,
    tree: &CallTree,
    mut offset: u32,
    head: u32,
    alignment: u32,
) -> bool {
    while offset != 0 {
        let entry_address = block.address() + offset;
        let start = block.format().width() * u32::from(tree.counters)
            + entry_address
            + size_of::<TreeEntry>() as u32;
        let last = (u32::from(tree.lists).wrapping_sub(1))
            .wrapping_mul(alignment)
            .wrapping_add(start);
        if head >= start && head <= last {
            return true;
        }
        // SAFETY: the caller guarantees the entry; links of an entry lead
        // to entries of the same tree.
        let entry: &TreeEntry = unsafe { block.at(offset) };
        // SAFETY: as above.
        if unsafe {
            head_in_tree(
                block,
                tree,
                entry.lower.load(Ordering::Relaxed),
                head,
                alignment,
            )
        } {
            return true;
        }
        offset = entry.higher.load(Ordering::Relaxed);
    }
    false
}

/// `ValidateVPLE` (0x91f6c520): every entry of a list lies in the
/// allocated area.
///
/// # Safety
///
/// `head` is the address of a value list head of `block`.
unsafe fn check_list_entries(block: &CountBlock, head: u32) {
    if !VALIDATE_VPLE.load(Ordering::Relaxed) {
        return;
    }
    let extended = block.format() == BlockFormat::Extended;
    let mut offset = if extended {
        // SAFETY: the caller guarantees the head.
        ListHead(unsafe { object_at::<AtomicU32>(head) }.load(Ordering::Relaxed)).offset()
    } else {
        // SAFETY: the caller guarantees the head.
        unsafe { object_at::<WideListHead>(head) }
            .first
            .load(Ordering::Relaxed)
    };
    while offset != 0 {
        let entry = block.address() + offset;
        let first = block
            .word_count
            .wrapping_mul(4)
            .wrapping_add(block.words)
            .wrapping_add(block.address());
        let entry_size = if extended {
            size_of::<WordEntry>()
        } else {
            size_of::<WideEntry>()
        };
        let last = block
            .address()
            .wrapping_sub(entry_size as u32)
            .wrapping_add(block.used.load(Ordering::Relaxed));
        if entry < first || entry > last {
            fatal(Fatal::InvalidValueListEntry);
        }
        offset = if extended {
            // SAFETY: the entry lies in the allocated area (checked above).
            unsafe { block.at::<WordEntry>(offset) }
                .next
                .load(Ordering::Relaxed)
        } else {
            // SAFETY: as above.
            unsafe { block.at::<WideEntry>(offset) }
                .next
                .load(Ordering::Relaxed)
        };
    }
}

/// Whether a 64-bit argument is a zero- or sign-extended 32-bit value.
fn fits32(value: u64) -> bool {
    value == u64::from(value as u32) || value == value as u32 as i32 as i64 as u64
}

/// Export 181 (stock 0x91f6f7d0): find or insert `key` in a path tree
/// and count it in the first 8-byte slot; returns the entry's slots.
extern "C" fn probe_path(block: u32, tree: u32, key: u32) -> u32 {
    // SAFETY: instrumented code passes the standard count block that
    // export 112 published to it.
    let block = unsafe { CountBlock::from_address(block) };
    check_tree_descriptor(block, tree);
    // SAFETY: instrumented code passes one of the block's call tree
    // descriptors.
    let tree = unsafe { object_at::<CallTree>(tree) };
    let key = pgo::tree_key(key);
    let mut link = &tree.root;
    let mut allocated = None;
    let entry = loop {
        let offset = link.load(Ordering::Relaxed);
        if offset != 0 {
            // SAFETY: tree links hold offsets of entries of the tree.
            let entry: &TreeEntry = unsafe { block.at(offset) };
            let existing = entry.key.load(Ordering::Relaxed);
            if existing == key {
                break Some(entry);
            }
            link = if existing > key {
                &entry.lower
            } else {
                &entry.higher
            };
            continue;
        }
        let offset = match allocated {
            Some(offset) => offset,
            None => match allocate(block, block.format().path_entry_size(tree.descriptor())) {
                Some(offset) => *allocated.insert(offset),
                None => break None,
            },
        };
        // SAFETY: `allocate` returned room for an entry of the tree.
        let entry: &TreeEntry = unsafe { block.at(offset) };
        entry.key.store(key, Ordering::Relaxed);
        entry.lower.store(0, Ordering::Relaxed);
        entry.higher.store(0, Ordering::Relaxed);
        if link
            .compare_exchange(0, offset, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            block.path_entries.fetch_add(1, Ordering::AcqRel);
            break Some(entry);
        }
    };
    match entry {
        Some(entry) => {
            if tree.counters != 0 {
                // SAFETY: the tree has a counter; standard entries are
                // 8-byte aligned.
                unsafe { entry.wide_count() }.fetch_add_relaxed(1);
            }
            entry.slots()
        }
        // The image increments at address 0x10 when the tree has counters.
        None => size_of::<TreeEntry>() as u32,
    }
}

/// Find or insert `key` in a call tree: exports 182 and 193 share it.
/// `None` when no entry could be allocated.
///
/// # Safety
///
/// `tree` is the address of a call tree descriptor of `block`.
unsafe fn tree_entry(block: &CountBlock, tree: u32, key: u32) -> Option<&TreeEntry> {
    check_tree_descriptor(block, tree);
    // SAFETY: the caller guarantees the descriptor.
    let tree = unsafe { object_at::<CallTree>(tree) };
    let key = pgo::tree_key(key);
    let mut allocated: Option<u32> = None;
    'restart: loop {
        let mut link = &tree.root;
        loop {
            let offset = link.load(Ordering::Relaxed);
            if offset != 0 {
                // SAFETY: tree links hold offsets of entries of the tree.
                let entry: &TreeEntry = unsafe { block.at(offset) };
                let existing = entry.key.load(Ordering::Relaxed);
                if existing == key {
                    return Some(entry);
                }
                link = if existing > key {
                    &entry.lower
                } else {
                    &entry.higher
                };
                continue;
            }
            let offset = match allocated {
                Some(offset) => offset,
                None => {
                    let generation = block.generation.load(Ordering::Relaxed);
                    let offset =
                        allocate(block, block.format().tree_entry_size(tree.descriptor()))?;
                    allocated = Some(offset);
                    if block.generation.load(Ordering::Relaxed) != generation {
                        continue 'restart;
                    }
                    offset
                }
            };
            // SAFETY: `allocate` returned room for an entry of the tree.
            let entry: &TreeEntry = unsafe { block.at(offset) };
            entry.key.store(key, Ordering::Relaxed);
            entry.lower.store(0, Ordering::Relaxed);
            entry.higher.store(0, Ordering::Relaxed);
            if link
                .compare_exchange(0, offset, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(entry);
            }
        }
    }
}

/// Export 182 (stock 0x91f6fb18): count `key` in a call tree and fill
/// the caller's context for the value probes of the entry.
extern "C" fn probe_call(block: u32, tree: u32, key: u32, frame: u32) {
    // SAFETY: instrumented code passes the extended count block that
    // export 112 published to it and its probe context on its stack.
    let (block, frame) = unsafe {
        (
            CountBlock::from_address(block),
            ProbeContext::from_address(frame),
        )
    };
    let (record, entered) = acquire(block);
    let thread = record.map_or(0, ThreadRecord::address);
    let fail = |frame: &mut ProbeContext| {
        frame.block = block.address();
        frame.generation = 0;
        frame.thread = thread;
        frame.payload = block.scratch;
        frame.descriptor = tree;
    };
    if !entered {
        fail(frame);
        block.lose();
        return;
    }
    // SAFETY: instrumented code passes one of the block's call tree
    // descriptors.
    match unsafe { tree_entry(block, tree, key) } {
        Some(entry) => {
            let payload = entry.slots();
            // SAFETY: as above.
            if unsafe { object_at::<CallTree>(tree) }.counters != 0 {
                // SAFETY: the tree has a counter.
                let count = unsafe { entry.word_count() };
                // Stock's overflow test (`addic.` then `ble` toward 0x91f70920)
                // judges the 64-bit sum of a zero-extended word, which is
                // never <= 0, so the count wraps.
                loop {
                    let current = count.load(Ordering::Relaxed);
                    if count
                        .compare_exchange(
                            current,
                            current.wrapping_add(1),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
            }
            frame.block = block.address();
            frame.thread = thread;
            frame.generation = block.generation.load(Ordering::Relaxed);
            frame.payload = payload;
            frame.descriptor = tree;
            if SWEEPING.load(Ordering::Acquire) {
                // SAFETY: the context was filled above.
                unsafe { refresh(frame) };
            }
        }
        None => fail(frame),
    }
    leave_probe(block, record);
}

/// Export 193 (stock 0x91f6d940): 1 when the context refers to its entry
/// again, 0 on failure.
extern "C" fn export_lookup(frame: u32) -> u32 {
    // SAFETY: instrumented code passes the probe context export 182
    // filled, on its stack.
    let frame = unsafe { ProbeContext::from_address(frame) };
    // SAFETY: as above.
    u32::from(unsafe { refresh(frame) })
}

/// Refresh a context after a sweep: wait out the sweep, then find or
/// insert its key again. On failure the payload is the block's scratch
/// word.
///
/// # Safety
///
/// Export 182 filled `frame`: its block, thread, and descriptor words
/// name a count block, the calling thread's record or 0, and a call tree
/// descriptor of the block.
unsafe fn refresh(frame: &mut ProbeContext) -> bool {
    loop {
        // SAFETY: the caller guarantees the context's block.
        let block = unsafe { CountBlock::from_address(frame.block) };
        if SWEEPING.load(Ordering::Acquire) {
            if frame.thread == 0 {
                block.lose();
                frame.generation = 0;
                frame.payload = block.scratch;
                return false;
            }
            loop {
                // SAFETY: the caller guarantees the context's thread record.
                leave_probe(block, unsafe { ThreadRecord::from_address(frame.thread) });
                wait_for_sweep();
                // SAFETY: as above.
                enter_probe(block, unsafe { ThreadRecord::from_address(frame.thread) });
                if !SWEEPING.load(Ordering::Acquire) {
                    break;
                }
            }
        }
        // SAFETY: the caller guarantees the context's descriptor.
        let Some(entry) = (unsafe { tree_entry(block, frame.descriptor, frame.key) }) else {
            frame.generation = 0;
            frame.payload = block.scratch;
            return false;
        };
        frame.payload = entry.slots();
        frame.generation = block.generation.load(Ordering::Relaxed);
        if !SWEEPING.load(Ordering::Acquire) {
            return true;
        }
    }
}

/// Insert or count `value` in a sorted list of [`WideEntry`] headed by
/// `list` (exports 183 and 186). `limit` redirects new values past
/// [`pgo::LIST_LIMIT`] to the overflow entry and counts entries in the
/// head.
fn count_wide(block: &CountBlock, list: &WideListHead, mut value: u64, limit: bool) {
    let mut allocated: Option<u32> = None;
    'restart: loop {
        check_list_head(block, address_of(list), size_of::<WideListHead>() as u32);
        // SAFETY: `list` is a value list head of the block.
        unsafe { check_list_entries(block, address_of(list)) };
        let mut link = &list.first;
        'search: loop {
            let mut current = link.load(Ordering::Relaxed);
            while current != 0 {
                // SAFETY: list links hold offsets of wide entries.
                let entry: &WideEntry = unsafe { block.at(current) };
                let existing = entry.value();
                if existing == value {
                    entry.count.fetch_add_relaxed(1);
                    return;
                }
                if existing > value {
                    break;
                }
                link = &entry.next;
                current = link.load(Ordering::Relaxed);
            }
            let offset = match allocated {
                Some(offset) => offset,
                None => {
                    if limit
                        && list.count.load(Ordering::Relaxed) >= pgo::LIST_LIMIT
                        && value != pgo::OVERFLOW_VALUE
                    {
                        value = pgo::OVERFLOW_VALUE;
                        continue 'restart;
                    }
                    // The image increments at address 8 when allocation fails.
                    let Some(offset) = allocate(block, pgo::WIDE_ENTRY_SIZE) else {
                        return;
                    };
                    *allocated.insert(offset)
                }
            };
            // SAFETY: `allocate` returned room for a wide entry.
            let entry: &WideEntry = unsafe { block.at(offset) };
            entry.set_value(value);
            entry
                .next
                .store(link.load(Ordering::Relaxed), Ordering::Relaxed);
            if link
                .compare_exchange(current, offset, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue 'search;
            }
            block.wide_entries.fetch_add(1, Ordering::AcqRel);
            if limit {
                list.count.store(
                    list.count.load(Ordering::Relaxed).wrapping_add(1),
                    Ordering::Relaxed,
                );
            }
            entry.count.fetch_add_relaxed(1);
            return;
        }
    }
}

/// Insert or count `value` in a sorted list of [`WordEntry`] with a
/// [`ListHead`] `list` (exports 184, 185, 187, 188). `limit` applies
/// [`pgo::LIST_LIMIT`] by the head's counter. `frame` is the context of a
/// probe that rebases `list` onto a refreshed call tree entry after a
/// sweep.
///
/// # Safety
///
/// `frame`, when given, satisfies [`refresh`], and `list` lies in the
/// slots of its entry.
unsafe fn count_word(
    block: &CountBlock,
    mut list: &AtomicU32,
    mut value: u64,
    limit: bool,
    mut frame: Option<&mut ProbeContext>,
) {
    let mut allocated: Option<u32> = None;
    'restart: loop {
        check_list_head(block, address_of(list), size_of::<AtomicU32>() as u32);
        // SAFETY: `list` is a value list head of the block.
        unsafe { check_list_entries(block, address_of(list)) };
        let mut previous: Option<&AtomicU32> = None;
        let mut head = list.load(Ordering::Relaxed);
        let mut current = ListHead(head).offset();
        loop {
            let mut found = None;
            while current != 0 {
                // SAFETY: list links hold offsets of word entries.
                let entry: &WordEntry = unsafe { block.at(current) };
                let existing = entry.value.load(Ordering::Relaxed);
                if existing == value as u32 {
                    found = Some(entry);
                    break;
                }
                if existing > value as u32 {
                    break;
                }
                previous = Some(&entry.next);
                current = entry.next.load(Ordering::Relaxed);
            }
            if let Some(entry) = found {
                entry.count.fetch_add(1, Ordering::AcqRel);
                return;
            }
            let offset = match allocated {
                Some(offset) => offset,
                None => {
                    if limit
                        && ListHead(list.load(Ordering::Relaxed)).counter() >= pgo::LIST_LIMIT
                        && value != pgo::OVERFLOW_VALUE
                    {
                        value = pgo::OVERFLOW_VALUE;
                        continue 'restart;
                    }
                    let generation = block.generation.load(Ordering::Relaxed);
                    let Some(offset) = allocate(block, block.format().word_entry_size()) else {
                        return;
                    };
                    allocated = Some(offset);
                    if block.generation.load(Ordering::Relaxed) != generation {
                        if let Some(frame) = frame.as_deref_mut() {
                            let delta = address_of(list).wrapping_sub(frame.payload);
                            // SAFETY: the caller guarantees the context.
                            if !unsafe { refresh(frame) } {
                                return;
                            }
                            // SAFETY: the list keeps its place in the slots of
                            // the refreshed entry.
                            list = unsafe { object_at(frame.payload.wrapping_add(delta)) };
                        }
                        continue 'restart;
                    }
                    offset
                }
            };
            // SAFETY: `allocate` returned room for a word entry.
            let entry: &WordEntry = unsafe { block.at(offset) };
            entry.value.store(value as u32, Ordering::Relaxed);
            match previous {
                None => {
                    entry.next.store(ListHead(head).offset(), Ordering::Relaxed);
                    match list.compare_exchange(
                        head,
                        ListHead(head).advanced(offset).0,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            entry.count.fetch_add(1, Ordering::AcqRel);
                            return;
                        }
                        Err(replaced) => {
                            // The search resumes at the entry it last compared.
                            if current == 0 {
                                current = ListHead(replaced).offset();
                                if current == 0 {
                                    fatal(Fatal::InvalidValueListHead);
                                }
                            }
                            head = replaced;
                        }
                    }
                }
                Some(link) => {
                    entry
                        .next
                        .store(link.load(Ordering::Relaxed), Ordering::Relaxed);
                    if link
                        .compare_exchange(current, offset, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        if limit {
                            let mut expected = head;
                            while let Err(replaced) = list.compare_exchange(
                                expected,
                                ListHead(expected).advanced(ListHead(expected).offset()).0,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            ) {
                                expected = replaced;
                            }
                        }
                        entry.count.fetch_add(1, Ordering::AcqRel);
                        return;
                    }
                    current = link.load(Ordering::Relaxed);
                }
            }
        }
    }
}

/// Exports 184 and 187: count a 32-bit value on the calling thread.
fn word_probe(block: &CountBlock, list: &AtomicU32, value: u64, limit: bool) {
    if !fits32(value) {
        block.lose();
        return;
    }
    let (record, entered) = acquire(block);
    if !entered {
        block.lose();
        return;
    }
    // SAFETY: no context.
    unsafe { count_word(block, list, value, limit, None) };
    leave_probe(block, record);
}

/// Exports 185 and 188: count a 32-bit value of the call tree entry the
/// context refers to, refreshing the context after a sweep.
///
/// # Safety
///
/// As [`count_word`] with `frame`.
unsafe fn tracked_word_probe(
    block: &CountBlock,
    list: &AtomicU32,
    value: u64,
    frame: &mut ProbeContext,
    limit: bool,
) {
    if !fits32(value) {
        block.lose();
        return;
    }
    // SAFETY: the caller guarantees the context's block and thread record.
    let (owner, record) = unsafe {
        (
            CountBlock::from_address(frame.block),
            ThreadRecord::from_address(frame.thread),
        )
    };
    if !enter_probe(owner, record) {
        owner.lose();
        return;
    }
    // SAFETY: the caller guarantees the context and the list.
    if frame.generation == block.generation.load(Ordering::Relaxed) || unsafe { refresh(frame) } {
        // SAFETY: as above.
        unsafe { count_word(block, list, value, limit, Some(&mut *frame)) };
    }
    // SAFETY: the caller guarantees the context's block and thread record.
    let (owner, record) = unsafe {
        (
            CountBlock::from_address(frame.block),
            ThreadRecord::from_address(frame.thread),
        )
    };
    leave_probe(owner, record);
}

/// Export 183 (stock 0x91f6dd18): count a 64-bit value.
extern "C" fn probe_wide(block: u32, list: u32, value: u64) {
    // SAFETY: instrumented code passes the standard count block that
    // export 112 published to it and one of its value list heads.
    let (block, list) = unsafe {
        (
            CountBlock::from_address(block),
            object_at::<WideListHead>(list),
        )
    };
    count_wide(block, list, value, false);
}

/// Export 184 (stock 0x91f6e030).
extern "C" fn probe_word(block: u32, list: u32, value: u64) {
    // SAFETY: instrumented code passes the extended count block that
    // export 112 published to it and one of its value list heads.
    let (block, list) = unsafe {
        (
            CountBlock::from_address(block),
            object_at::<AtomicU32>(list),
        )
    };
    word_probe(block, list, value, false);
}

/// Export 185 (stock 0x91f6e448).
extern "C" fn probe_tracked_word(block: u32, list: u32, value: u64, frame: u32) {
    // SAFETY: instrumented code passes its extended count block, a value
    // list head in the slots of the entry its context refers to, and that
    // context, which export 182 filled, on its stack.
    unsafe {
        tracked_word_probe(
            CountBlock::from_address(block),
            object_at::<AtomicU32>(list),
            value,
            ProbeContext::from_address(frame),
            false,
        )
    };
}

/// Export 186 (stock 0x91f6e8f8): count a 64-bit value, at most ten
/// distinct ones.
extern "C" fn probe_limited_wide(block: u32, list: u32, value: u64) {
    // SAFETY: as in `probe_wide`.
    let (block, list) = unsafe {
        (
            CountBlock::from_address(block),
            object_at::<WideListHead>(list),
        )
    };
    count_wide(block, list, value, true);
}

/// Export 187 (stock 0x91f6ec48).
extern "C" fn probe_limited_word(block: u32, list: u32, value: u64) {
    // SAFETY: as in `probe_word`.
    let (block, list) = unsafe {
        (
            CountBlock::from_address(block),
            object_at::<AtomicU32>(list),
        )
    };
    word_probe(block, list, value, true);
}

/// Export 188 (stock 0x91f6f148).
extern "C" fn probe_limited_tracked_word(block: u32, list: u32, value: u64, frame: u32) {
    // SAFETY: as in `probe_tracked_word`.
    unsafe {
        tracked_word_probe(
            CountBlock::from_address(block),
            object_at::<AtomicU32>(list),
            value,
            ProbeContext::from_address(frame),
            true,
        )
    };
}

/// The bucket of `value` in a range table.
///
/// # Safety
///
/// `table` is the address of a range table with at least one entry, and
/// `count` entries when `count` is nonzero.
unsafe fn range_bucket(value: u64, table: u32) -> u64 {
    // SAFETY: the caller guarantees the table.
    let header = unsafe { object_at::<RangeTableHeader>(table) };
    let range = RangeTable {
        count: header.count,
        flags: header.flags,
    };
    let entries = table + size_of::<RangeTableHeader>() as u32;
    let bucket = range.bucket(value, |index| {
        if range.wide() {
            // SAFETY: the search reads entries the caller guarantees.
            let entry = unsafe { object_at::<[u32; 2]>(entries + 8 * index) };
            u64::from(entry[0]) << 32 | u64::from(entry[1])
        } else {
            // SAFETY: as above.
            u64::from(*unsafe { object_at::<u32>(entries + 4 * index) })
        }
    });
    u64::from(bucket)
}

/// Export 189 (stock 0x91f6f6f0): count the range of a value as export 183.
extern "C" fn probe_wide_range(block: u32, list: u32, value: u64, table: u32) {
    // SAFETY: instrumented code passes the range table of the probe site.
    probe_wide(block, list, unsafe { range_bucket(value, table) });
}

/// Export 190 (stock 0x91f6f740): as export 184.
extern "C" fn probe_word_range(block: u32, list: u32, value: u64, table: u32) {
    // SAFETY: as in `probe_wide_range`.
    probe_word(block, list, unsafe { range_bucket(value, table) });
}

/// Export 191 (stock 0x91f6f790): as export 185.
extern "C" fn probe_tracked_word_range(block: u32, list: u32, value: u64, table: u32, frame: u32) {
    // SAFETY: as in `probe_wide_range`.
    probe_tracked_word(block, list, unsafe { range_bucket(value, table) }, frame);
}

/// Export 192 (stock 0x91f70920): a 31-bit call counter is about to
/// overflow: write a profile and reset, or stop the console.
extern "C" fn export_overflow(block: u32) {
    if !SWEEP_ON_OVERFLOW.load(Ordering::Relaxed) {
        fatal(Fatal::CounterOverflow);
    }
    if let Some(record) = record_of_block(block) {
        snapshot(record, None, true, SweepKind::Overflow);
    }
}

/// Probe entries: the console passes a 64-bit value in one register; the
/// 32-bit routines take it as a register pair, so later arguments move up
/// one register (rldicl 5,5,32,32 puts the high word in r5).
macro_rules! probe_entry {
    ($entry:ident, $target:path, [$($adapt:literal),*]) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $entry() {
            core::arch::naked_asm!(
                $($adapt,)*
                "lis 12, {target}@ha",
                "addi 12, 12, {target}@l",
                "b {bridge}",
                target = sym $target,
                bridge = sym crate::exports::export_bridge,
            )
        }
    };
}

probe_entry!(entry_181, probe_path, []);
probe_entry!(entry_182, probe_call, []);
probe_entry!(entry_183, probe_wide, ["mr 6, 5", ".long 0x78a50022"]);
probe_entry!(entry_184, probe_word, ["mr 6, 5", ".long 0x78a50022"]);
probe_entry!(
    entry_185,
    probe_tracked_word,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_186,
    probe_limited_wide,
    ["mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_187,
    probe_limited_word,
    ["mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_188,
    probe_limited_tracked_word,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_189,
    probe_wide_range,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_190,
    probe_word_range,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_191,
    probe_tracked_word_range,
    ["mr 8, 7", "mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);

export_raw!(181, entry_181);
export_raw!(182, entry_182);
export_raw!(183, entry_183);
export_raw!(184, entry_184);
export_raw!(185, entry_185);
export_raw!(186, entry_186);
export_raw!(187, entry_187);
export_raw!(188, entry_188);
export_raw!(189, entry_189);
export_raw!(190, entry_190);
export_raw!(191, entry_191);
export!(192, export_overflow);
export!(193, export_lookup);

/// What the image stores in a probe slot: it loads 8 bytes at the export's
/// entry and stores the low word, the entry's second instruction.
fn probe_slot_word(entry: unsafe extern "C" fn()) -> u32 {
    // SAFETY: every probe entry is a routine of this module longer than
    // two instructions.
    unsafe { (entry as *const ()).cast::<u32>().add(1).read() }
}

/// Publish the count block and probes to the module (0x91f6ff58) and
/// load the counting entries of the dispatch table from the interface.
///
/// # Safety
///
/// The slot words of `interface` hold addresses of aligned words of the
/// module that the module keeps. For an extended count block, `values` is
/// the address of the module's [`INTERFACE_WORDS`] interface words.
unsafe fn connect_interface(record: &ModuleRecord, interface: &ModuleInterface, values: u32) {
    let block = record.count_block();
    // SAFETY: the caller guarantees the slots.
    unsafe {
        object_at::<AtomicU32>(interface.block_slot).store(block.address(), Ordering::Relaxed);
        object_at::<AtomicU32>(interface.counts_slot)
            .store(block.counts + block.address(), Ordering::Relaxed);
    }
    let probes: [unsafe extern "C" fn(); 7] = if block.format() == BlockFormat::Extended {
        // SAFETY: the caller guarantees the words of an extended block.
        let values = unsafe { object_at::<[u32; INTERFACE_WORDS]>(values) };
        for (index, (word, &value)) in interface.words.iter().zip(values).enumerate() {
            if index != 2 {
                word.store(value, Ordering::Relaxed);
            }
        }
        [
            entry_182, entry_184, entry_190, entry_187, entry_185, entry_191, entry_188,
        ]
    } else {
        [
            entry_181, entry_183, entry_189, entry_186, entry_183, entry_189, entry_186,
        ]
    };
    let slots = core::iter::once(&interface.first_probe_slot).chain(&interface.probe_slots);
    for (&slot, entry) in slots.zip(probes) {
        // SAFETY: the caller guarantees the slots.
        unsafe { object_at::<AtomicU32>(slot) }.store(probe_slot_word(entry), Ordering::Relaxed);
    }
    // Dispatch entries 0-13 take interface words 0-9 in order with every
    // third entry from 2 left empty; 14-23 are empty.
    let mut words = interface.words.iter();
    for (index, routine) in record.counting.iter().enumerate() {
        let source = if index < 14 && index % 3 != 2 {
            words.next()
        } else {
            None
        };
        routine.store(
            source.map_or(0, |word| word.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
    }
}

/// Copy the module header of export 113 into the record and build the
/// profile base path (0x91f6d8a0).
fn load_header(record: &ModuleRecord) {
    // SAFETY: export 113 stored 0 or the module header of the title,
    // which stays mapped while the title runs.
    let header = unsafe { PogoHeader::from_address(HEADER.load(Ordering::Acquire)) };
    // A missing header would fault the image.
    let Some(header) = header.filter(|header| header.magic == block::MAGIC_VALUE) else {
        fatal(Fatal::InvalidSignature);
    };
    if header.version != PogoHeader::VERSION {
        fatal(Fatal::InvalidVersion);
    }
    record
        .descriptors
        .store(address_of(&header.descriptors), Ordering::Relaxed);
    record.has_callers.store(1, Ordering::Relaxed);
    record
        .module_word
        .store(header.module_word, Ordering::Relaxed);
    record
        .count_slots
        .store(header.count_slots, Ordering::Relaxed);
    record
        .tree_count
        .store(header.tree_count, Ordering::Relaxed);
    record
        .list_count
        .store(header.list_count, Ordering::Relaxed);
    record
        .word_count
        .store(header.word_count, Ordering::Relaxed);
    record.scale_bonus.store(
        u8::from(header.flags.contains(PogoHeaderFlags::SCALE_BONUS)),
        Ordering::Relaxed,
    );
    let module = module_file_name(record.module);
    // SAFETY: export 113 completed before the module registered.
    let base_name = unsafe { &*BASE_NAME.0.get() };
    match pgo::base_path(base_name, module.units()) {
        Ok(path) => record.set_base_path(&path),
        Err(failure) => fatal(failure),
    }
}

/// The full name of the module containing `address` (GetModuleFileName,
/// 0x91f71128 and 0x91f71150).
struct ModuleFileName {
    units: [u16; PATH_UNITS + 1],
    length: usize,
}

impl ModuleFileName {
    fn units(&self) -> &[u16] {
        &self.units[..self.length]
    }

    /// The image also requires the copy to be terminated, which the copy
    /// guarantees below this length.
    fn fits(&self) -> bool {
        self.length < PATH_UNITS
    }
}

fn module_file_name(address: u32) -> ModuleFileName {
    let mut name = ModuleFileName {
        units: [0; PATH_UNITS + 1],
        length: 0,
    };
    let mut entry = 0u32;
    // SAFETY: `entry` is a local word.
    unsafe { XexPcToFileHeader(address, &mut entry) };
    // An address outside every module leaves the image with an unset
    // entry; the name is taken as empty.
    if entry == 0 {
        return name;
    }
    // SAFETY: the loader returned the entry of the module containing
    // `address`, which stays loaded while the module registers.
    let entry = unsafe { object_at::<xboxkrnl::LdrDataTableEntry>(entry) };
    let bytes = usize::from(entry.full_dll_name.length).min(2 * PATH_UNITS);
    name.length = bytes / 2;
    // An empty name may come with a null buffer, which a slice cannot hold.
    if name.length == 0 {
        return name;
    }
    // SAFETY: the loader's name buffer holds `length` bytes of UTF-16.
    let units = unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance::<u16>(entry.full_dll_name.buffer as usize),
            name.length,
        )
    };
    name.units[..name.length].copy_from_slice(units);
    name
}

/// Lay out and allocate the count block (0x91f6cbd8).
fn create_block(record: &ModuleRecord) {
    /// `TestCounterOverflow` fill: counters start close to overflowing.
    const OVERFLOW_FILL: u8 = 0x7f;
    let format = if record.extended.load(Ordering::Relaxed) != 0 {
        BlockFormat::Extended
    } else {
        BlockFormat::Standard
    };
    let descriptors = record.descriptors.load(Ordering::Relaxed);
    let tree_count = record.tree_count.load(Ordering::Relaxed);
    // SAFETY: load_header stored the address of the module header's
    // `tree_count` descriptors, which the module keeps.
    let trees: &[CallTree] = unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance(descriptors as usize),
            tree_count as usize,
        )
    };
    let shape = ModuleShape {
        format,
        module_word: record.module_word.load(Ordering::Relaxed),
        has_callers: record.has_callers.load(Ordering::Relaxed) != 0,
        count_slots: record.count_slots.load(Ordering::Relaxed),
        list_count: record.list_count.load(Ordering::Relaxed),
        tree_count,
        word_count: record.word_count.load(Ordering::Relaxed),
        scratch: record.scratch,
        title_memory: record.title_memory.load(Ordering::Relaxed),
        scale_bonus: record.scale_bonus.load(Ordering::Relaxed) != 0,
        allocation_scale: record.allocation_scale.load(Ordering::Relaxed),
        descriptors: trees.iter().map(CallTree::descriptor),
    };
    let header = CountBlockHeader::new(&shape);
    let mut bytes = [0u8; BlockFormat::Standard.header_size() as usize];
    header.encode(block_time(), &mut bytes);
    let mut base = 0u32;
    let mut size = header.reserved;
    // SAFETY: `base` and `size` are live locals.
    let status = unsafe {
        xboxkrnl::NtAllocateVirtualMemory(
            &mut base,
            &mut size,
            AllocationType::COMMIT,
            PageProtection::READWRITE,
            MemoryRegion::CurrentProcess,
        )
    };
    if let Err(error) = status.result() {
        set_last_error(error);
        base = 0;
    }
    record.block.store(base, Ordering::Relaxed);
    if base == 0 {
        fatal(Fatal::BlockAllocation);
    }
    let block = core::ptr::with_exposed_provenance_mut::<u8>(base as usize);
    // SAFETY: the new allocation spans `header.reserved` bytes, which hold
    // the header and the regions the layout placed; no other thread reads
    // it before `block_written` is set below. The header fits `bytes`. The
    // descriptors and the word table are the module's (export 113).
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), block, format.header_size() as usize);
        if record.fill_counters.load(Ordering::Relaxed) != 0 {
            core::ptr::write_bytes(
                block.add(header.counts.offset as usize),
                OVERFLOW_FILL,
                format
                    .width()
                    .wrapping_mul(record.count_slots.load(Ordering::Relaxed))
                    as usize,
            );
        }
        core::ptr::copy(
            trees.as_ptr().cast::<u8>(),
            block.add(header.trees.offset as usize + size_of::<CallTree>()),
            tree_count.wrapping_mul(size_of::<CallTree>() as u32) as usize,
        );
        core::ptr::copy(
            core::ptr::with_exposed_provenance::<u8>(WORDS.load(Ordering::Acquire) as usize),
            block.add(header.words.offset as usize),
            record.word_count.load(Ordering::Relaxed).wrapping_mul(4) as usize,
        );
    }
    record.block_written.store(1, Ordering::Release);
}

/// A `pogo.ini` request for the server thread.
struct IniRequest<'a> {
    path: &'a [u8],
    record: Option<&'a ModuleRecord>,
    /// Unchanged when the server cannot take the request.
    result: Result<(), BadModulePath>,
}

/// Apply `pogo.ini` to a record, then raise `pogomodstartup` when
/// `stopon pogomodstart` is set. The drive table belongs to the server, so
/// the file is read on its thread; when the server cannot take the
/// request the file is not read.
fn load_ini(path: &CStr, record: Option<&ModuleRecord>) -> Result<(), BadModulePath> {
    /// Longest module path the request takes, in bytes.
    const PATH_LIMIT: usize = 0x140;
    let bytes = path.to_bytes();
    if bytes.len() >= PATH_LIMIT {
        return Err(BadModulePath);
    }
    let mut request = IniRequest {
        path: bytes,
        record,
        result: Ok(()),
    };
    dispatcher::call_on_server_with(&mut request, service_load_ini);
    request.result?;
    debugger::report_pogo_module_start(
        path.as_ptr().addr() as u32,
        record.map_or(0, ModuleRecord::address),
    );
    Ok(())
}

/// Export 107 (stock 0x91f3e038).
extern "C" fn export_load_ini(path: *const c_char, record: u32) -> u32 {
    // SAFETY: the caller passes a NUL-terminated module path and 0 or a
    // record of export 112, as export 106 returns it.
    let (path, record) = unsafe { (CStr::from_ptr(path), ModuleRecord::from_address(record)) };
    crate::exports::export_result(load_ini(path, record)).0
}

fn service_load_ini(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    request: &mut IniRequest<'_>,
) -> u32 {
    let record = request.record;
    let module = PgoModule::Record(record.map_or(0, ModuleRecord::address));
    // The results of the settings are not reported.
    let result = pgo::load_ini(
        &server.state,
        console,
        request.path,
        &mut |_, _, directive| match directive {
            IniDirective::AllocScale(scale) => {
                let _ = set_allocation_scale(module, scale);
            }
            IniDirective::OutputPath(directory) => {
                // Export 107 may pass record 0; stock then reads the base
                // path at address 0x88 and faults, which safe code cannot do,
                // so the directive is skipped (deviation).
                if let Some(record) = record {
                    let mut path = record.base_path();
                    report_illegal(pgo::output_path(&mut path, directory));
                    record.set_base_path(&path);
                }
            }
            IniDirective::DisableDataCollection => {
                let _ = stop_modules(module);
            }
            IniDirective::Option { option, value } => {
                let _ = set_option(module, option, value);
            }
        },
    );
    request.result = result;
    0
}

/// Set up a new record (0x91f70250).
///
/// # Safety
///
/// As [`connect_interface`].
unsafe fn initialize_module(
    record: &ModuleRecord,
    name: &ModuleFileName,
    interface: &ModuleInterface,
    values: u32,
) {
    /// `MAX_PATH`: the UTF-8 module path for `pogo.ini`.
    const PATH_BYTES: usize = 0x104;
    load_header(record);
    if name.length >= PATH_UNITS {
        fatal(Fatal::BinaryPathTooLong);
    }
    store_units(&record.module_name, &name.units[..=name.length]);
    let mut path = [0u8; PATH_BYTES];
    // A name longer than the buffer in UTF-8 keeps the bytes that fit.
    let _ = pgo::encode_utf8(&name.units[..=name.length], &mut path[..PATH_BYTES - 1]);
    record.allocation_scale.store(1, Ordering::Relaxed);
    record.block.store(0, Ordering::Relaxed);
    record.extended.store(1, Ordering::Relaxed);
    record.fill_counters.store(0, Ordering::Relaxed);
    // SAFETY: the last byte of `path` stays 0.
    let _ = load_ini(
        unsafe { CStr::from_ptr(path.as_ptr().cast()) },
        Some(record),
    );
    create_block(record);
    // SAFETY: the caller guarantees the interface.
    unsafe { connect_interface(record, interface, values) };
    if SWEEP_EVENT.load(Ordering::Acquire) == 0 {
        // SAFETY: the event is unnamed, so no name pointer is read.
        let event = unsafe { xam::CreateEventA(0, true, true, core::ptr::null()) };
        SWEEP_EVENT.store(event.raw(), Ordering::Release);
        if event == Handle::NULL {
            fatal(Fatal::EventCreation);
        }
    }
    let index = KeTlsAlloc();
    TLS_INDEX.store(index.0, Ordering::Release);
    if index == TlsIndex::OUT_OF_INDEXES {
        let _ = close_handle(Handle::from_raw(SWEEP_EVENT.swap(0, Ordering::AcqRel)));
        fatal(Fatal::TlsAllocation);
    }
}

/// The record of `address` whose module has file name `name` (0x91f6bb40);
/// records at the address with another name are marked dead.
fn find_module(address: u32, name: Option<&[u16]>) -> Option<&'static ModuleRecord> {
    for record in modules() {
        if record.dead.load(Ordering::Relaxed) != 0 || record.module != address {
            continue;
        }
        let Some(name) = name else {
            continue;
        };
        let mut existing = [0u16; PATH_UNITS];
        load_units(&record.module_name, &mut existing);
        if existing[..pgo::wide_len(&existing)] == name[..pgo::wide_len(name)] {
            return Some(record);
        }
        record.dead.store(1, Ordering::Relaxed);
    }
    None
}

/// Export 112 (stock 0x91f703f8): register or re-register an instrumented
/// module and start or stop its counting.
extern "C" fn export_register(
    table: u32,
    address: u32,
    stub_a: u32,
    stub_b: u32,
    stub_c: u32,
    _reserved: u32,
    module_interface: u32,
    values: u32,
) {
    // The table starts out stopped through a stack record.
    // SAFETY: integers and atomic integers are valid when zero.
    let mut scratch: ModuleRecord = unsafe { core::mem::zeroed() };
    scratch.table = table;
    scratch.stubs = [
        AtomicU32::new(stub_a),
        AtomicU32::new(stub_b),
        AtomicU32::new(stub_c),
    ];
    stop_counting(&scratch);
    let error = last_error();
    SECTION.enter();
    let name = module_file_name(address);
    // The units past the name are zero, so the slice is terminated.
    let record = match find_module(address, Some(&name.units[..])) {
        Some(record) => {
            record.dead.store(0, Ordering::Relaxed);
            // SAFETY: the record keeps the module interface of its first
            // registration; the eighth argument is the module's interface
            // words.
            unsafe {
                connect_interface(
                    record,
                    object_at(record.interface.load(Ordering::Relaxed)),
                    values,
                )
            };
            record
        }
        None => {
            if name.length == 0 {
                SECTION.leave();
                fatal(Fatal::ModuleNameFailed);
            }
            if !name.fits() {
                SECTION.leave();
                fatal(Fatal::ModuleNameTooLong);
            }
            // SAFETY: the process heap takes a size only.
            let allocation = unsafe {
                RtlAllocateHeap(
                    GetProcessHeap(),
                    HeapFlags::ZERO_MEMORY,
                    size_of::<ModuleRecord>() as u32,
                )
            };
            if allocation == 0 {
                fatal(Fatal::NodeAllocation);
            }
            let pointer =
                core::ptr::with_exposed_provenance_mut::<ModuleRecord>(allocation as usize);
            {
                // SAFETY: a zeroed heap block of the record's size and
                // alignment, unreachable to others until linked below.
                let new = unsafe { &mut *pointer };
                new.table = table;
                new.module = address;
                new.next = MODULES.load(Ordering::Acquire);
            }
            MODULES.store(allocation, Ordering::Release);
            // SAFETY: linked records are shared and stay allocated until the
            // title ends.
            let record: &'static ModuleRecord = unsafe { &*pointer };
            record.stubs[0].store(stub_a, Ordering::Relaxed);
            record.stubs[1].store(stub_b, Ordering::Relaxed);
            record.stubs[2].store(stub_c, Ordering::Relaxed);
            record.enabled.store(1, Ordering::Relaxed);
            record.interface.store(module_interface, Ordering::Relaxed);
            // SAFETY: the seventh argument is the module's interface and the
            // eighth its interface words.
            unsafe { initialize_module(record, &name, object_at(module_interface), values) };
            record.phase_set.store(0, Ordering::Relaxed);
            record.phase[0].store(0, Ordering::Relaxed);
            record
        }
    };
    if record.enabled.load(Ordering::Relaxed) != 0 {
        start_counting(record);
    } else {
        stop_counting(record);
    }
    SECTION.leave();
    set_last_error_value(error);
}

/// Export 106 (stock 0x91f70628): look a module up without a name, which
/// never matches.
extern "C" fn export_find_module(address: u32) -> u32 {
    find_module(address, None).map_or(0, ModuleRecord::address)
}

fn select(module: PgoModule) -> impl Iterator<Item = &'static ModuleRecord> {
    modules().filter(move |record| match module {
        PgoModule::All => true,
        PgoModule::Record(address) => record.address() == address,
    })
}

fn module_result(module: PgoModule, matched: bool) -> Result<(), PgoError> {
    if module != PgoModule::All && !matched {
        Err(PgoError::NoSuchModule)
    } else {
        Ok(())
    }
}

/// Export 108 (stock 0x91f70630): request counting for one module or all.
fn start_modules(module: PgoModule) -> Result<(), PgoError> {
    let mut matched = false;
    for record in select(module) {
        matched = true;
        record.enabled.store(1, Ordering::Relaxed);
        if record.dead.load(Ordering::Relaxed) == 0 {
            start_counting(record);
        }
    }
    module_result(module, matched)
}

/// Export 109 (stock 0x91f706d0).
fn stop_modules(module: PgoModule) -> Result<(), PgoError> {
    let mut matched = false;
    for record in select(module) {
        matched = true;
        record.enabled.store(0, Ordering::Relaxed);
        if record.dead.load(Ordering::Relaxed) == 0 {
            stop_counting(record);
        }
    }
    module_result(module, matched)
}

/// Write a profile of one module and optionally reset its counts
/// (0x91f70770). Counting restarts afterwards even for a stopped module.
fn snapshot(record: &ModuleRecord, phase: Option<&[u8]>, reset: bool, kind: SweepKind) {
    stop_counting(record);
    match phase {
        Some(phase) => {
            let mut converted = [0u16; PATH_UNITS];
            report_illegal(pgo::decode_utf8(phase, &mut converted));
            record.phase_set.store(1, Ordering::Relaxed);
            store_units(&record.phase, &WidePath::copy_from(&converted).0);
        }
        None => record.phase[0].store(0, Ordering::Relaxed),
    }
    let block = record.count_block();
    let extended = block.format() == BlockFormat::Extended;
    if extended {
        let state = block.extended_state();
        state.sweep_kind.store(kind as u8, Ordering::Relaxed);
        state.resetting.store(u8::from(reset), Ordering::Relaxed);
    }
    write_profile(record);
    if extended {
        let state = block.extended_state();
        state.sweep_kind.store(0, Ordering::Relaxed);
        state.resetting.store(0, Ordering::Relaxed);
    }
    if reset {
        block.set_time(block_time());
        reset_counts(block);
    }
    start_counting(record);
}

/// Export 110 and `pogoctrl snapshot` (0x91f70880).
fn snapshot_modules(
    phase: Option<&[u8]>,
    reset: bool,
    module: PgoModule,
    kind: SweepKind,
) -> Result<(), PgoError> {
    let mut matched = false;
    for record in select(module) {
        matched = true;
        snapshot(record, phase, reset, kind);
    }
    module_result(module, matched)
}

/// The record `module` selects; every module is not a record.
fn selected_record(module: PgoModule) -> Result<&'static ModuleRecord, PgoError> {
    match module {
        PgoModule::All => None,
        PgoModule::Record(address) => find_record(address),
    }
    .ok_or(PgoError::NoSuchModule)
}

/// `AllocScale` (0x91f70978).
fn set_allocation_scale(module: PgoModule, scale: u32) -> Result<(), PgoError> {
    let record = selected_record(module)?;
    if record.has_block() {
        return Err(PgoError::Busy);
    }
    record.allocation_scale.store(scale, Ordering::Relaxed);
    Ok(())
}

/// `pogo.ini` options (0x91f709e0); the validation and sweep options are
/// global but still need a record without a count block.
fn set_option(module: PgoModule, option: PgoOption, value: u32) -> Result<(), PgoError> {
    let record = selected_record(module)?;
    if record.has_block() {
        return Err(PgoError::Busy);
    }
    let set = value != 0;
    match option {
        PgoOption::StandardPgc => record.extended.store(u8::from(!set), Ordering::Relaxed),
        PgoOption::TestCounterOverflow => {
            record.fill_counters.store(u8::from(set), Ordering::Relaxed)
        }
        PgoOption::MaxTitleMemory => record.title_memory.store(value, Ordering::Relaxed),
        PgoOption::ValidateEplh => VALIDATE_EPLH.store(set, Ordering::Relaxed),
        PgoOption::ValidateVplh => VALIDATE_VPLH.store(set, Ordering::Relaxed),
        PgoOption::ValidateVple => VALIDATE_VPLE.store(set, Ordering::Relaxed),
        PgoOption::EnableSweepOnOverflow => SWEEP_ON_OVERFLOW.store(set, Ordering::Relaxed),
        PgoOption::EnableSweepFullBuffer => SWEEP_FULL_BUFFER.store(set, Ordering::Relaxed),
    }
    Ok(())
}

fn profile_request(access: FileAccess, disposition: CreateDisposition) -> CreateRequest {
    CreateRequest {
        access: access
            .union(FileAccess::SYNCHRONIZE)
            .union(FileAccess::READ_ATTRIBUTES),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::NONE,
        disposition,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    }
}

/// Create the first free profile `<name>!<n>.pgc` from 1 (0x91f6d038).
/// The image also scans the directory for existing numbers but compares
/// the character after the name, which is always `!`, so the scan never
/// raises the start. `None` when a name can neither be created nor opened.
fn create_profile(name: &ProfileName) -> Option<Handle> {
    let mut number = 1u32;
    loop {
        let mut bytes = [0u8; pgo::FILE_NAME_BYTES];
        let length = name.file_name(number, &mut bytes);
        let path = &bytes[..length];
        if let Ok(handle) = filesystem::create_file(
            path,
            &profile_request(FileAccess::GENERIC_WRITE, CreateDisposition::Create),
        ) {
            return Some(Handle::from_raw(handle.0));
        }
        let handle = filesystem::create_file(
            path,
            &profile_request(FileAccess::GENERIC_READ, CreateDisposition::Open),
        )
        .ok()?;
        // SAFETY: `handle` was opened above and is closed once.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
        number = number.wrapping_add(1);
    }
}

/// Write `length` bytes at `buffer` to a file; a failure sets the last
/// error.
///
/// # Safety
///
/// `buffer` is valid for reads of `length` bytes until the call returns.
unsafe fn write_file(handle: Handle, buffer: *const u8, length: u32) -> Result<(), KernelError> {
    let mut io_status = IoStatusBlock::default();
    // SAFETY: the caller guarantees the buffer; `io_status` outlives the
    // request, which is waited for below when pending.
    let mut status = unsafe {
        xboxkrnl::NtWriteFile(
            handle,
            Handle::NULL,
            0,
            0,
            &mut io_status,
            buffer,
            length,
            core::ptr::null(),
        )
    };
    if status == NtStatus::PENDING {
        // SAFETY: `handle` is the open profile file.
        unsafe {
            xboxkrnl::NtWaitForSingleObjectEx(handle, ProcessorMode::User, false, core::ptr::null())
        };
        // The kernel completed the request before it signaled the file.
        status = io_status.status;
    }
    status.result().inspect_err(|&error| set_last_error(error))
}

/// Write the count block to a new profile file (0x91f6d420), from the
/// module's directory or the devkit directory, then mark it complete.
fn write_profile(record: &ModuleRecord) {
    let base = record.base_path();
    let mut phase = [0u16; PATH_UNITS];
    let mut continuation = [0u16; PATH_UNITS];
    let phase_set = record.phase_set.load(Ordering::Relaxed) != 0;
    if phase_set {
        load_units(&record.phase, &mut phase);
        load_units(&record.module_name, &mut continuation);
    }
    let phase = phase_set.then_some((&phase, &continuation[..]));
    let open = |path: &WidePath| {
        create_profile(&ProfileName::new(path, phase).unwrap_or_else(|failure| fatal(failure)))
    };
    let handle = open(&base)
        .or_else(|| open(&pgo::fallback_path(&base)))
        .unwrap_or_else(|| fatal(Fatal::WriteFailed));
    let block = record.count_block();
    let length = block
        .used
        .load(Ordering::Relaxed)
        .min(block.committed.load(Ordering::Relaxed));
    let start = core::ptr::with_exposed_provenance::<u8>(block.address() as usize);
    // SAFETY: the block's first `committed` bytes are committed.
    if unsafe { write_file(handle, start, length) }.is_err() {
        warn(WriteWarning::Write);
    }
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `handle` is the open profile file; `io_status` is a live local.
    let status = unsafe { xboxkrnl::NtFlushBuffersFile(handle, &mut io_status) };
    if let Err(error) = status.result() {
        set_last_error(error);
        warn(WriteWarning::Flush);
    }
    // The image reports a seek only when the new position is 0.
    let position = pgo::COMPLETION_OFFSET.to_be_bytes();
    // SAFETY: `position` holds the 8-byte position information.
    let status = unsafe {
        xboxkrnl::NtSetInformationFile(
            handle,
            &mut io_status,
            position.as_ptr(),
            8,
            FileInformationClass::Position,
        )
    };
    if let Err(error) = status.result() {
        set_last_error(error);
    }
    let complete = 1u8;
    // SAFETY: `complete` is a live local byte.
    if unsafe { write_file(handle, &complete, 1) }.is_err() {
        warn(WriteWarning::Write);
    }
    if close_handle(handle).is_err() {
        warn(WriteWarning::Close);
    }
}

/// The shutdown profile of one module (0x91f6d740).
fn shutdown_profile(record: &ModuleRecord, block: &CountBlock) {
    stop_counting(record);
    record.phase_set.store(0, Ordering::Relaxed);
    if block.format() == BlockFormat::Extended {
        let state = block.extended_state();
        state.live.store(0, Ordering::Relaxed);
        state
            .sweep_kind
            .store(SweepKind::Shutdown as u8, Ordering::Relaxed);
    } else {
        block.standard_state().live.store(0, Ordering::Relaxed);
    }
    write_profile(record);
}

/// Title termination (0x91f6d7f8, last step of 0x91f32398): write a
/// profile of every module with a count block and forget the modules,
/// thread records, sweep event, and TLS slot.
pub(crate) fn title_terminated() {
    for record in modules() {
        if let Some(block) = record.block() {
            shutdown_profile(record, block);
        }
    }
    MODULES.store(0, Ordering::Release);
    SWEEPING.store(false, Ordering::Release);
    THREADS.store(0, Ordering::Release);
    SWEEP_EVENT.store(0, Ordering::Release);
    TLS_INDEX.store(TlsIndex::OUT_OF_INDEXES.0, Ordering::Release);
}

/// Prepare the registration lock; called once at module start, before
/// export 112 is reachable.
pub(super) fn initialize() {
    SECTION.initialize();
}

/// Export 108.
extern "C" fn export_start(module: u32) -> u32 {
    crate::exports::export_result(start_modules(PgoModule::from_value(module))).0
}

/// Export 109.
extern "C" fn export_stop(module: u32) -> u32 {
    crate::exports::export_result(stop_modules(PgoModule::from_value(module))).0
}

/// Export 110 (stock 0x91f70918): profile one module or all; `phase` may
/// be null.
extern "C" fn export_snapshot(phase: *const c_char, reset: u32, module: u32) -> u32 {
    let phase = (!phase.is_null()).then(|| {
        // SAFETY: the caller passes a NUL-terminated phase name.
        unsafe { CStr::from_ptr(phase) }.to_bytes_with_nul()
    });
    crate::exports::export_result(snapshot_modules(
        phase,
        reset != 0,
        PgoModule::from_value(module),
        SweepKind::Export,
    ))
    .0
}

/// Export 111 (stock 0x91f6cba8).
extern "C" fn export_abort() {
    fatal(Fatal::ClientAbort);
}

/// Export 113 (stock 0x91f6b900): the base profile name (UTF-8), the
/// module header, and the module's word table for later registrations.
extern "C" fn export_set_module_info(name: *const c_char, module_header: u32, words: u32) {
    // A null name would fault the image; it is taken as unreadable.
    if name.is_null() {
        fatal(Fatal::BaseNameUnreadable);
    }
    // SAFETY: the caller passes a NUL-terminated name.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes_with_nul();
    // SAFETY: registrations read the name after this call returns.
    let base_name = unsafe { &mut *BASE_NAME.0.get() };
    let decoded = pgo::decode_utf8(name, base_name);
    report_illegal(decoded);
    if !matches!(decoded.units, Ok(units) if units > 0) {
        fatal(Fatal::BaseNameUnreadable);
    }
    HEADER.store(module_header, Ordering::Release);
    WORDS.store(words, Ordering::Release);
}

/// Export 114 (stock 0x91f6d5d0): profile a module under a wide phase
/// name. The lookup runs without a name and never matches.
extern "C" fn export_phase_snapshot(address: u32, _phase: *const u16) {
    find_module(address, None);
}

/// Export 115 (stock 0x91f6d6c0): as export 114 with an ANSI phase,
/// which must convert into 0x104 units.
extern "C" fn export_ansi_phase_snapshot(address: u32, phase: *const c_char) {
    // A null phase would fault the image; it converts as empty.
    let length = if phase.is_null() {
        0
    } else {
        // SAFETY: the caller passes a NUL-terminated phase name.
        unsafe { CStr::from_ptr(phase) }.to_bytes().len()
    };
    if length + 1 > PATH_UNITS {
        fatal(Fatal::PhaseUnconvertible);
    }
    find_module(address, None);
}

export!(106, export_find_module);
export!(107, export_load_ini);
export!(108, export_start);
export!(109, export_stop);
export!(110, export_snapshot);
export!(111, export_abort);
export!(112, export_register);
export!(113, export_set_module_info);
export!(114, export_phase_snapshot);
export!(115, export_ansi_phase_snapshot);

/// `pogoctrl start`.
pub(super) fn control_start(module: PgoModule) -> Result<(), PgoError> {
    start_modules(module)
}

/// `pogoctrl stop`.
pub(super) fn control_stop(module: PgoModule) -> Result<(), PgoError> {
    stop_modules(module)
}

/// `pogoctrl snapshot`: the phase is always set, empty when absent.
pub(super) fn control_snapshot(
    phase: &[u8],
    reset: bool,
    module: PgoModule,
) -> Result<(), PgoError> {
    snapshot_modules(Some(phase), reset, module, SweepKind::Control)
}

/// `pogoctrl allocscale`.
pub(super) fn control_allocation_scale(module: PgoModule, scale: u32) -> Result<(), PgoError> {
    set_allocation_scale(module, scale)
}
