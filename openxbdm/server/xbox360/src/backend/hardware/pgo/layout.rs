//! `#[repr(C)]` views of the PGO records and count blocks in title memory.

use core::mem::ManuallyDrop;
use core::mem::offset_of;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU16;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::hardware::pgo;
use openxbdm_server::commands::hardware::pgo::BlockFormat;
use openxbdm_server::commands::hardware::pgo::Fatal;
use openxbdm_server::commands::hardware::pgo::PATH_UNITS;
use openxbdm_server::commands::hardware::pgo::TreeDescriptor;
use openxbdm_server::commands::hardware::pgo::WidePath;
use openxbdm_server::commands::hardware::pgo::block;
use xbox360::atomic::AtomicU64;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::xboxkrnl::Handle;

use super::MODULES;
use super::fatal;
use crate::kernel::address_of;
use crate::kernel::object_at;

/// Entries of a module's probe dispatch table.
pub(super) const DISPATCH_ENTRIES: usize = 24;
/// Words of a [`ModuleInterface`] that export 112 loads.
pub(super) const INTERFACE_WORDS: usize = 10;

/// Instrumented-module record (0x6d0 bytes from the title's heap, zeroed).
/// Export 112 links it before filling it, and probes, exports, and the
/// server thread use it concurrently, so the fields written after linking
/// are atomics.
#[repr(C)]
pub(super) struct ModuleRecord {
    /// Address of the older record; set before linking.
    pub(super) next: u32,
    /// Address of the module's probe dispatch table; set before linking.
    pub(super) table: u32,
    /// Dispatch table contents while counting.
    pub(super) counting: [AtomicU32; DISPATCH_ENTRIES],
    /// Address inside the module, its identity; set before linking.
    pub(super) module: u32,
    pub(super) allocation_scale: AtomicU32,
    pub(super) title_memory: AtomicU32,
    pub(super) module_word: AtomicU32,
    _reserved_078: u32,
    /// Address of the [`CountBlock`], 0 before one exists.
    pub(super) block: AtomicU32,
    /// Nonzero: writing the dispatch table faulted; start and stop skip it.
    pub(super) dead: AtomicU8,
    /// Nonzero: counting requested.
    pub(super) enabled: AtomicU8,
    _reserved_082: [u8; 2],
    /// Nonzero: profile names carry the phase.
    pub(super) phase_set: AtomicU32,
    pub(super) base_path: [AtomicU16; PATH_UNITS],
    pub(super) phase: [AtomicU16; PATH_UNITS],
    pub(super) module_name: [AtomicU16; PATH_UNITS],
    pub(super) has_callers: AtomicU32,
    pub(super) count_slots: AtomicU32,
    pub(super) tree_count: AtomicU32,
    pub(super) list_count: AtomicU32,
    pub(super) word_count: AtomicU32,
    /// Address of the module header's [`CallTree`] descriptors.
    pub(super) descriptors: AtomicU32,
    /// Stub routines the dispatch table holds while stopped.
    pub(super) stubs: [AtomicU32; 3],
    /// Zero from the allocation.
    pub(super) scratch: u32,
    pub(super) scale_bonus: AtomicU8,
    pub(super) extended: AtomicU8,
    pub(super) fill_counters: AtomicU8,
    /// Set with release once create_block wrote the count block; a byte
    /// stock leaves zero.
    pub(super) block_written: AtomicU8,
    /// Address of the [`ModuleInterface`] of the first registration.
    pub(super) interface: AtomicU32,
}

impl ModuleRecord {
    /// The record at `address`, `None` for 0.
    ///
    /// # Safety
    ///
    /// `address` is 0 or a record export 112 allocated. Records stay
    /// allocated until the title ends.
    pub(super) unsafe fn from_address(address: u32) -> Option<&'static Self> {
        // SAFETY: the caller guarantees the record.
        (address != 0).then(|| unsafe { object_at(address) })
    }

    /// The newest record.
    pub(super) fn first() -> Option<&'static Self> {
        // SAFETY: MODULES holds 0 or a record of export 112.
        unsafe { Self::from_address(MODULES.load(Ordering::Acquire)) }
    }

    pub(super) fn next(&self) -> Option<&'static Self> {
        // SAFETY: export 112 sets `next` to the list head it replaces.
        unsafe { Self::from_address(self.next) }
    }

    pub(super) fn address(&self) -> u32 {
        address_of(self)
    }

    pub(super) fn has_block(&self) -> bool {
        self.block.load(Ordering::Relaxed) != 0
    }

    /// The count block once create_block wrote it. The acquire load of
    /// `block_written` pairs with its release store there, so the block is
    /// complete for any thread that gets it; stock reads the address alone
    /// (deviation, see `count_block`).
    pub(super) fn block(&self) -> Option<&'static CountBlock> {
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
    pub(super) fn count_block(&self) -> &'static CountBlock {
        self.block().unwrap_or_else(|| fatal(Fatal::BlockLookup))
    }

    pub(super) fn base_path(&self) -> WidePath {
        let mut path = WidePath::default();
        load_units(&self.base_path, &mut path.0);

        path
    }

    pub(super) fn set_base_path(&self, path: &WidePath) {
        store_units(&self.base_path, &path.0);
    }
}

/// Per-thread record (0x10 bytes from the title's heap). Its thread
/// creates and links it; a sweep unlinks and frees it after the thread
/// ended.
#[repr(C)]
pub(super) struct ThreadRecord {
    /// The record's own address inside a probe, the processor region
    /// address outside one.
    pub(super) state: AtomicU32,
    /// Duplicated handle of the thread.
    pub(super) handle: Handle,
    /// Address of the next record of [`super::THREADS`].
    pub(super) next: AtomicU32,
    pub(super) id: u32,
}

impl ThreadRecord {
    /// The record at `address`, `None` for 0.
    ///
    /// # Safety
    ///
    /// `address` is 0, the calling thread's record, or a record linked in
    /// [`super::THREADS`] that no sweep frees meanwhile.
    pub(super) unsafe fn from_address(address: u32) -> Option<&'static Self> {
        // SAFETY: the caller guarantees the record.
        (address != 0).then(|| unsafe { object_at(address) })
    }

    pub(super) fn address(&self) -> u32 {
        address_of(self)
    }

    /// Mark the thread inside a probe.
    pub(super) fn enter(&self) {
        self.state.store(self.address(), Ordering::Relaxed);
    }

    /// Mark the thread outside a probe.
    pub(super) fn leave(&self) {
        self.state.store(processor_region(), Ordering::Relaxed);
    }
}

/// Probe context of exports 182, 185, 188, 191, and 193, on the stack of
/// the instrumented caller, which reads it after the probe returns.
#[repr(C)]
pub(super) struct ProbeContext {
    /// Call tree key; the caller sets it.
    pub(super) key: u32,
    /// Address of the caller's [`ThreadRecord`], 0 without one.
    pub(super) thread: u32,
    /// Address of the [`CountBlock`].
    pub(super) block: u32,
    /// Sweep generation of the payload, 0 after a failure.
    pub(super) generation: u32,
    /// Address of the call tree entry's slots; the block's scratch word
    /// after a failure.
    pub(super) payload: u32,
    /// Address of the [`CallTree`].
    pub(super) descriptor: u32,
}

impl ProbeContext {
    /// # Safety
    ///
    /// `address` is the caller's context, which nothing else uses for `'a`.
    pub(super) unsafe fn from_address<'a>(address: u32) -> &'a mut Self {
        // SAFETY: the caller guarantees the context.
        unsafe { &mut *core::ptr::with_exposed_provenance_mut::<Self>(address as usize) }
    }
}

/// Module interface of export 112's seventh argument, in the module.
#[repr(C)]
pub(super) struct ModuleInterface {
    /// Routines the counting dispatch table takes; the extended format
    /// loads all but word 2 from export 112's eighth argument.
    pub(super) words: [AtomicU32; INTERFACE_WORDS],
    _reserved_028: [u32; 3],
    /// Address of the module's word for its count block address.
    pub(super) block_slot: u32,
    /// Address of the module's word for its counter array address.
    pub(super) counts_slot: u32,
    /// Address of the module's word for the first probe.
    pub(super) first_probe_slot: u32,
    _reserved_040: u32,
    /// Addresses of the module's words for the other probes.
    pub(super) probe_slots: [u32; 6],
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
pub(super) struct PogoHeader {
    /// [`block::MAGIC_VALUE`], as the count block has it.
    pub(super) magic: u32,
    pub(super) version: u32,
    pub(super) module_word: u32,
    _reserved_00c: u32,
    pub(super) flags: PogoHeaderFlags,
    pub(super) tree_count: u32,
    pub(super) count_slots: u32,
    pub(super) list_count: u32,
    _reserved_020: [u32; 14],
    pub(super) word_count: u32,
    _reserved_05c: u32,
    /// `tree_count` call tree descriptors.
    pub(super) descriptors: [CallTree; 0],
}

impl PogoHeader {
    pub(super) const VERSION: u32 = 0x2b;

    /// The header at `address`, `None` for 0.
    ///
    /// # Safety
    ///
    /// `address` is 0 or a module header that stays mapped for `'a`.
    pub(super) unsafe fn from_address<'a>(address: u32) -> Option<&'a Self> {
        // SAFETY: the caller guarantees the header.
        (address != 0).then(|| unsafe { object_at(address) })
    }
}

/// Count block header ([`block`] offsets). This module allocates the
/// block and instrumented code counts in it, so the words probes and
/// sweeps change are atomics. Entries and regions follow at the offsets
/// the header and the entry links hold.
#[repr(C)]
pub(super) struct CountBlock {
    _magic: u32,
    version: u32,
    _module_word: u32,
    /// Bytes in use from the block start.
    pub(super) used: AtomicU32,
    /// Creation or reset time, high word first.
    time: [AtomicU32; 2],
    pub(super) count_slots: u32,
    pub(super) counts: u32,
    pub(super) list_count: u32,
    pub(super) lists: u32,
    pub(super) wide_entries: AtomicU32,
    pub(super) tree_count: u32,
    pub(super) trees: u32,
    pub(super) path_entries: AtomicU32,
    pub(super) word_count: u32,
    pub(super) words: u32,
    _reserved_040: [u32; 4],
    _present: u8,
    _has_callers: u8,
    _reserved_052: [u8; 2],
    pub(super) committed: AtomicU32,
    pub(super) reserved: u32,
    state: BlockState,
    pub(super) threads: AtomicU32,
    _reserved_068: u32,
    /// Sweep generation; changes when a full-buffer sweep clears entries.
    pub(super) generation: AtomicU32,
    /// Probes running on threads without a thread record.
    pub(super) untracked: AtomicU32,
    /// Extended only: written to contexts whose probe failed.
    pub(super) scratch: u32,
}

impl CountBlock {
    /// # Safety
    ///
    /// `address` is a count block create_block allocated, which stays
    /// allocated. Its links and regions hold the offsets this runtime and
    /// the layout gave them.
    pub(super) unsafe fn from_address(address: u32) -> &'static Self {
        // SAFETY: the caller guarantees the block.
        unsafe { object_at(address) }
    }

    pub(super) fn address(&self) -> u32 {
        address_of(self)
    }

    pub(super) fn format(&self) -> BlockFormat {
        BlockFormat::from_version(self.version)
    }

    pub(super) fn extended_state(&self) -> &ExtendedState {
        // SAFETY: both views are integers and atomic integers, which
        // every bit pattern makes valid.
        unsafe { &self.state.extended }
    }

    pub(super) fn standard_state(&self) -> &StandardState {
        // SAFETY: as in `extended_state`.
        unsafe { &self.state.standard }
    }

    pub(super) fn lose(&self) {
        self.extended_state().lost.store(1, Ordering::Relaxed);
    }

    pub(super) fn set_time(&self, time: u64) {
        self.time[0].store((time >> 32) as u32, Ordering::Relaxed);
        self.time[1].store(time as u32, Ordering::Relaxed);
    }

    /// The `T` at `offset` from the block start.
    ///
    /// # Safety
    ///
    /// `offset` locates a `T` in the committed part of the block: a
    /// region of the header, an offset from a link of the right kind, or
    /// an allocation of [`super::sweep::allocate`] for a `T`.
    pub(super) unsafe fn at<T>(&self, offset: u32) -> &T {
        // SAFETY: the caller guarantees the location.
        unsafe { object_at(self.address() + offset) }
    }

    /// The descriptors of the tree region; entry 0 is unused.
    pub(super) fn trees(&self) -> &[CallTree] {
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
    pub(super) unsafe fn zero(&self, offset: u32, length: u32) {
        let first =
            core::ptr::with_exposed_provenance::<AtomicU32>((self.address() + offset) as usize);

        // SAFETY: guaranteed by the caller.
        let words = unsafe { core::slice::from_raw_parts(first, length as usize / 4) };

        for word in words {
            word.store(0, Ordering::Relaxed);
        }
    }
}

/// Count block +0x5c..+0x64, laid out by format.
#[repr(C)]
union BlockState {
    standard: ManuallyDrop<StandardState>,
    extended: ManuallyDrop<ExtendedState>,
}

#[repr(C)]
pub(super) struct StandardState {
    /// Dword 1.
    _sweep_kind: u32,
    /// Dword 1 until the shutdown profile.
    pub(super) live: AtomicU32,
}

#[repr(C)]
pub(super) struct ExtendedState {
    /// [`pgo::SweepKind`] of the profile being written.
    pub(super) sweep_kind: AtomicU8,
    /// 1 until the shutdown profile.
    pub(super) live: AtomicU8,
    /// Counts are reset after the profile being written.
    pub(super) resetting: AtomicU8,
    /// Set while a full-buffer profile is written.
    pub(super) full_buffer: [AtomicU8; 2],
    /// A probe dropped data.
    lost: AtomicU8,
    _reserved_062: [u8; 2],
}

/// Call tree entry (exports 181, 182, 193): the links, then the counter
/// slots and value list heads its [`CallTree`] counts.
#[repr(C)]
pub(super) struct TreeEntry {
    /// [`pgo::tree_key`] of the key.
    pub(super) key: AtomicU32,
    /// Offset of the subtree of lower keys.
    pub(super) lower: AtomicU32,
    /// Offset of the subtree of higher keys.
    pub(super) higher: AtomicU32,
    _reserved_00c: u32,
}

impl TreeEntry {
    /// Address of the slots after the links.
    pub(super) fn slots(&self) -> u32 {
        address_of(self) + size_of::<Self>() as u32
    }

    /// The first counter of an extended entry.
    ///
    /// # Safety
    ///
    /// The entry's tree has a counter.
    pub(super) unsafe fn word_count(&self) -> &AtomicU32 {
        // SAFETY: the caller guarantees the counter.
        unsafe { object_at(self.slots()) }
    }

    /// The first counter of a standard entry.
    ///
    /// # Safety
    ///
    /// The entry's tree has a counter and the entry is 8-byte aligned, as
    /// standard entries are.
    pub(super) unsafe fn wide_count(&self) -> &AtomicU64 {
        // SAFETY: the caller guarantees the counter.
        unsafe { object_at(self.slots()) }
    }
}

/// Value list entry with a 32-bit value (exports 184, 185, 187, 188).
#[repr(C)]
pub(super) struct WordEntry {
    pub(super) value: AtomicU32,
    pub(super) count: AtomicU32,
    /// Offset of the next entry.
    pub(super) next: AtomicU32,
}

/// Value list entry with a 64-bit value (exports 183, 186).
#[repr(C)]
pub(super) struct WideEntry {
    /// High word first.
    pub(super) value: [AtomicU32; 2],
    pub(super) count: AtomicU64,
    /// Offset of the next entry.
    pub(super) next: AtomicU32,
    _reserved_014: u32,
}

impl WideEntry {
    pub(super) fn value(&self) -> u64 {
        u64::from(self.value[0].load(Ordering::Relaxed)) << 32
            | u64::from(self.value[1].load(Ordering::Relaxed))
    }

    pub(super) fn set_value(&self, value: u64) {
        self.value[0].store((value >> 32) as u32, Ordering::Relaxed);
        self.value[1].store(value as u32, Ordering::Relaxed);
    }
}

/// Value list head of the standard format (exports 183, 186). The
/// extended head is one [`pgo::ListHead`] word.
#[repr(C)]
pub(super) struct WideListHead {
    /// Entries inserted, for [`pgo::LIST_LIMIT`].
    pub(super) count: AtomicU32,
    /// Offset of the first entry.
    pub(super) first: AtomicU32,
}

/// Call tree descriptor, in the module header and in the count block's
/// tree region.
#[repr(C)]
pub(super) struct CallTree {
    pub(super) counters: u16,
    pub(super) lists: u16,
    /// Offset of the root entry, in the count block.
    pub(super) root: AtomicU32,
}

impl CallTree {
    pub(super) fn descriptor(&self) -> TreeDescriptor {
        TreeDescriptor {
            counters: self.counters,
            lists: self.lists,
        }
    }
}

/// Range table of exports 189-191; sorted entries of 4 or 8 bytes follow.
#[repr(C)]
pub(super) struct RangeTableHeader {
    _reserved_000: u32,
    pub(super) count: u16,
    pub(super) flags: u16,
}

/// Address of the processor control region, the outside-probe mark.
fn processor_region() -> u32 {
    address_of(Kpcr::current())
}

pub(super) fn load_units(source: &[AtomicU16], target: &mut [u16]) {
    for (unit, source) in target.iter_mut().zip(source) {
        *unit = source.load(Ordering::Relaxed);
    }
}

pub(super) fn store_units(target: &[AtomicU16], units: &[u16]) {
    for (target, &unit) in target.iter().zip(units) {
        target.store(unit, Ordering::Relaxed);
    }
}

/// Bytes of a value list head in `format`.
pub(super) const fn list_head_size(format: BlockFormat) -> u32 {
    match format {
        BlockFormat::Extended => size_of::<AtomicU32>() as u32,
        BlockFormat::Standard => size_of::<WideListHead>() as u32,
    }
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
