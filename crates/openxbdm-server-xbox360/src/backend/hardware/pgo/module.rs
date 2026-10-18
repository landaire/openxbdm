//! Module registration, module headers, INI files, and per-module controls.

use core::ffi::CStr;
use core::ffi::c_char;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::hardware::PgoError;
use openxbdm_server::commands::hardware::PgoModule;
use openxbdm_server::commands::hardware::pgo;
use openxbdm_server::commands::hardware::pgo::BadModulePath;
use openxbdm_server::commands::hardware::pgo::BlockFormat;
use openxbdm_server::commands::hardware::pgo::CountBlockHeader;
use openxbdm_server::commands::hardware::pgo::Fatal;
use openxbdm_server::commands::hardware::pgo::IniDirective;
use openxbdm_server::commands::hardware::pgo::ModuleShape;
use openxbdm_server::commands::hardware::pgo::PATH_UNITS;
use openxbdm_server::commands::hardware::pgo::PgoOption;
use openxbdm_server::commands::hardware::pgo::SweepKind;
use openxbdm_server::commands::hardware::pgo::WidePath;
use openxbdm_server::commands::hardware::pgo::block;
use xbox360::status::last_error;
use xbox360::status::set_last_error;
use xbox360::status::set_last_error_value;
use xbox360_sys::xam;
use xbox360_sys::xam::GetProcessHeap;
use xbox360_sys::xam::HeapFlags;
use xbox360_sys::xam::RtlAllocateHeap;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AllocationType;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::KeTlsAlloc;
use xbox360_sys::xboxkrnl::MemoryRegion;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::TlsIndex;
use xbox360_sys::xboxkrnl::XexPcToFileHeader;

use super::BASE_NAME;
use super::HEADER;
use super::MODULES;
use super::SECTION;
use super::SWEEP_EVENT;
use super::SWEEP_FULL_BUFFER;
use super::SWEEP_ON_OVERFLOW;
use super::TLS_INDEX;
use super::VALIDATE_EPLH;
use super::VALIDATE_VPLE;
use super::VALIDATE_VPLH;
use super::WORDS;
use super::fatal;
use super::find_record;
use super::layout::CallTree;
use super::layout::INTERFACE_WORDS;
use super::layout::ModuleInterface;
use super::layout::ModuleRecord;
use super::layout::PogoHeader;
use super::layout::PogoHeaderFlags;
use super::layout::load_units;
use super::layout::store_units;
use super::modules;
use super::probe::entry_181;
use super::probe::entry_182;
use super::probe::entry_183;
use super::probe::entry_184;
use super::probe::entry_185;
use super::probe::entry_186;
use super::probe::entry_187;
use super::probe::entry_188;
use super::probe::entry_189;
use super::probe::entry_190;
use super::probe::entry_191;
use super::profile::write_profile;
use super::report_illegal;
use super::start_counting;
use super::stop_counting;
use super::sweep::block_time;
use super::sweep::close_handle;
use super::sweep::reset_counts;
use crate::backend::debugger;
use crate::backend::filesystem;
use crate::backend::filesystem::CallerPaths;
use crate::exports::export_result;
use crate::kernel::address_of;
use crate::kernel::object_at;

/// The full name of the module containing an address (GetModuleFileName,
/// 0x91f71128 and 0x91f71150).
struct ModuleFileName {
    units: [u16; PATH_UNITS + 1],
    length: usize,
}

impl ModuleFileName {
    fn from_address(address: u32) -> Self {
        let mut name = Self {
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

    fn units(&self) -> &[u16] {
        &self.units[..self.length]
    }

    /// The image also requires the copy to be terminated, which the copy
    /// guarantees below this length.
    fn fits(&self) -> bool {
        self.length < PATH_UNITS
    }
}

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

    let module = ModuleFileName::from_address(record.module);
    // SAFETY: export 113 completed before the module registered.
    let base_name = unsafe { &*BASE_NAME.0.get() };
    match pgo::base_path(base_name, module.units()) {
        Ok(path) => record.set_base_path(&path),
        Err(failure) => fatal(failure),
    }
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
    let base = if let Err(error) = status.result() {
        set_last_error(error);
        0
    } else {
        base
    };
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

/// Apply `pogo.ini` to a record, then raise `pogomodstartup` when
/// `stopon pogomodstart` is set. The file is read on the caller's thread
/// with the published drive table.
fn load_ini(path: &CStr, record: Option<&ModuleRecord>) -> Result<(), BadModulePath> {
    let module = PgoModule::Record(record.map_or(0, ModuleRecord::address));

    // The results of the settings are not reported.
    pgo::load_ini(
        &filesystem::published_drives(),
        &mut CallerPaths::new(),
        path.to_bytes(),
        &mut |directive| match directive {
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
    )?;

    debugger::report_pogo_module_start(
        path.as_ptr().addr() as u32,
        record.map_or(0, ModuleRecord::address),
    );

    Ok(())
}

/// Export 107 (stock 0x91f3e038).
pub(super) extern "C" fn export_load_ini(path: *const c_char, record: u32) -> u32 {
    // SAFETY: the caller passes a NUL-terminated module path and 0 or a
    // record of export 112, as export 106 returns it.
    let (path, record) = unsafe { (CStr::from_ptr(path), ModuleRecord::from_address(record)) };

    export_result(load_ini(path, record)).0
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
    let path = unsafe { CStr::from_ptr(path.as_ptr().cast()) };
    let _ = load_ini(path, Some(record));
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
pub(super) fn find_module(address: u32, name: Option<&[u16]>) -> Option<&'static ModuleRecord> {
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
pub(super) extern "C" fn export_register(
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
    let name = ModuleFileName::from_address(address);
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
pub(super) extern "C" fn export_find_module(address: u32) -> u32 {
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
pub(super) fn start_modules(module: PgoModule) -> Result<(), PgoError> {
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
pub(super) fn stop_modules(module: PgoModule) -> Result<(), PgoError> {
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
pub(super) fn snapshot(record: &ModuleRecord, phase: Option<&[u8]>, reset: bool, kind: SweepKind) {
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
pub(super) fn snapshot_modules(
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
pub(super) fn set_allocation_scale(module: PgoModule, scale: u32) -> Result<(), PgoError> {
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
