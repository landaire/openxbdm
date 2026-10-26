//! PGO instrumentation runtime (stock 0x91f6b900..0x91f71600): the
//! instrumented-module list, count blocks, the value probes instrumented
//! code calls (exports 181-193), profile files, and the controls behind
//! exports 106-115 and `pogoctrl`. Records, count blocks, and thread
//! records live in the title's memory and the title's code shares them;
//! the `#[repr(C)]` views below reach them from the address an export, a
//! kernel call, or an allocation supplies. See `docs/re-notes/pgo.md`.

mod layout;
mod module;
mod probe;
mod profile;
mod sweep;
mod validate;

use core::cell::UnsafeCell;
use core::ffi::CStr;
use core::ffi::c_char;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::hardware::PgoError;
use openxbdm_server::commands::hardware::PgoModule;
use openxbdm_server::commands::hardware::pgo;
use openxbdm_server::commands::hardware::pgo::Fatal;
use openxbdm_server::commands::hardware::pgo::PATH_UNITS;
use openxbdm_server::commands::hardware::pgo::SweepKind;
use openxbdm_server::commands::hardware::pgo::WriteWarning;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::BugCheckCode;
use xbox360_sys::xboxkrnl::KeBugCheck;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::TlsIndex;

use self::layout::DISPATCH_ENTRIES;
use self::layout::ModuleRecord;
use self::module::export_find_module;
use self::module::export_load_ini;
use self::module::export_register;
use self::module::find_module;
use self::module::set_allocation_scale;
use self::module::snapshot_modules;
use self::module::start_modules;
use self::module::stop_modules;
use self::profile::shutdown_profile;
use crate::exports::export;
use crate::exports::export_result;
use crate::kernel;
use crate::kernel::CriticalSection;
use crate::kernel::object_at;

/// The registration lock (0x91fa3ac0).
static SECTION: CriticalSection = CriticalSection::new();

/// Base profile name from export 113 (0x91fa36a8).
static BASE_NAME: BaseName = BaseName(UnsafeCell::new([0; PATH_UNITS]));

/// 0x91fa3ae1: a full-buffer sweep runs; probes wait on [`SWEEP_EVENT`].
static SWEEPING: AtomicBool = AtomicBool::new(false);

/// 0x91fa38b4: address of the newest [`ModuleRecord`].
static MODULES: AtomicU32 = AtomicU32::new(0);

/// 0x91fa3ae4: address of the newest [`layout::ThreadRecord`].
static THREADS: AtomicU32 = AtomicU32::new(0);

/// 0x91fa3ae8: manual-reset event, signaled while no sweep runs.
static SWEEP_EVENT: AtomicU32 = AtomicU32::new(0);

/// 0x91f9904c.
static TLS_INDEX: AtomicU32 = AtomicU32::new(TlsIndex::OUT_OF_INDEXES.0);

/// 0x91fa3adc, from export 113: address of the module header.
static HEADER: AtomicU32 = AtomicU32::new(0);

/// 0x91fa38b0, from export 113: address of the module's word table.
static WORDS: AtomicU32 = AtomicU32::new(0);

/// `ValidateVPLE` (0x91fa36a0).
static VALIDATE_VPLE: AtomicBool = AtomicBool::new(false);

/// `ValidateEPLH` (0x91fa36a1).
static VALIDATE_EPLH: AtomicBool = AtomicBool::new(false);

/// `ValidateVPLH` (0x91fa36a2).
static VALIDATE_VPLH: AtomicBool = AtomicBool::new(false);

/// `EnableSweepOnOverflow` (0x91f99050).
static SWEEP_ON_OVERFLOW: AtomicBool = AtomicBool::new(true);

/// `EnableSweepFullBuffer` (0x91f99051).
static SWEEP_FULL_BUFFER: AtomicBool = AtomicBool::new(true);

/// Storage of [`BASE_NAME`].
struct BaseName(UnsafeCell<[u16; PATH_UNITS]>);

// SAFETY: export 113 writes the name before the module registers; stock
// shares the buffer the same way.
unsafe impl Sync for BaseName {}

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
    export_result(start_modules(PgoModule::from_value(module))).0
}

/// Export 109.
extern "C" fn export_stop(module: u32) -> u32 {
    export_result(stop_modules(PgoModule::from_value(module))).0
}

/// Export 110 (stock 0x91f70918): profile one module or all; `phase` may
/// be null.
extern "C" fn export_snapshot(phase: *const c_char, reset: u32, module: u32) -> u32 {
    let phase = (!phase.is_null()).then(|| {
        // SAFETY: the caller passes a NUL-terminated phase name.
        unsafe { CStr::from_ptr(phase) }.to_bytes_with_nul()
    });
    let module = PgoModule::from_value(module);

    export_result(snapshot_modules(
        phase,
        reset != 0,
        module,
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
