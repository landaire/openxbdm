//! Performance monitor counters (stock 0x91f913f0..0x91f92e58): ownership
//! by priority, the counter hardware, setups, the statistics printouts, and
//! exports 196-211.
//!
//! The owner, trigger processor, and run timestamps change under the
//! monitor's spin lock; the counter controls, print flags, current setup,
//! and measured clock are read without it, as in stock.

mod error;
mod exports;
mod registers;
mod report;

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::performance::pmc;
use openxbdm_server::commands::performance::pmc::COUNTERS;
use openxbdm_server::commands::performance::pmc::CounterControl;
use openxbdm_server::commands::performance::pmc::Counting;
use openxbdm_server::commands::performance::pmc::Event;
use openxbdm_server::commands::performance::pmc::EventName;
use openxbdm_server::commands::performance::pmc::Setup;
use xbox360::time::Timebase;
use xbox360_sys::processor;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeEnablePPUPerformanceMonitor;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::PmwRegister;
use xbox360_sys::xboxkrnl::PrvRegister;
use xbox360_sys::xboxkrnl::SpecialPurposeRegister;

use self::registers::BusWidth;
use self::registers::LiveRegisters;
use self::registers::MonitorControl;
use self::registers::MonitorRegisters;
use self::registers::RunControl;
use self::registers::TriggerMode;
use self::registers::monitor_control;
use self::registers::set_monitor_control;
use self::registers::set_pmw_value;
use self::registers::set_prv_value;
use self::registers::set_spr_value;
use self::report::pointer;
use crate::kernel;

pub(super) use self::report::debug_print;
pub(super) use self::report::print;

/// Trigger selection of processors 0..2.
const TRIGGERS: [u32; 3] = [0x0842_2108, 0x39ce_8420, 0x6b5a_e738];

xbox360_sys::flags! {
    /// Printout options (export 208 flags and the stored print flags). Any
    /// stored flag also suppresses the routing and counting notes.
    pub struct PrintFlags(u32) {
        /// Omit the L2 ECC counts.
        NO_ECC = 0x1,
        /// Omit the frame rate.
        NO_FRAME_RATE = 0x2,
        /// Omit the time, frame rate, and setup line.
        NO_TIME = 0x4,
    }
}

impl PrintFlags {
    /// Print flags the setup installers store: every bit but the time and
    /// the frame rate. Bits above `NO_TIME` select nothing in the
    /// printouts; stock sets them.
    const QUIET: Self = Self(!(Self::NO_FRAME_RATE.0 | Self::NO_TIME.0));
}

/// A counter owner; a higher priority preempts a lower one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Owner(pub(super) i32);

impl Owner {
    /// Stops at title termination after releasing every owner.
    pub(super) const NONE: Self = Self(0);
    pub(super) const PIX: Self = Self(5);
    pub(super) const EXPORTS: Self = Self(0x19);
    pub(super) const CAPTURE: Self = Self(0x63);
    pub(super) const PROFILER: Self = Self(0x64);
    pub(super) const TITLE_TERMINATION: Self = Self(0x3e8);
}

/// Counter state as stock export 205 fills it (0xa0 bytes).
#[repr(C)]
pub(super) struct PmcState {
    pub(super) counters: [u64; COUNTERS],
    /// Time base ticks the counters ran.
    pub(super) ticks: u64,
    /// Interval timer count.
    pub(super) interval: f64,
    pub(super) status: u64,
    /// Doubled count of the last instruction counter.
    pub(super) instructions: u64,
}

impl PmcState {
    pub(super) const fn new() -> Self {
        Self {
            counters: [0; COUNTERS],
            ticks: 0,
            interval: 0.0,
            status: 0,
            instructions: 0,
        }
    }
}

struct Hardware {
    owner: Owner,
    trigger: TriggerMode,
    started: u64,
    stopped: u64,
}

struct Monitor {
    lock: KspinLock,
    hardware: UnsafeCell<Hardware>,
}

// SAFETY: `hardware` is only accessed while `lock` is held.
unsafe impl Sync for Monitor {}

static MONITOR: Monitor = Monitor {
    lock: KspinLock::new(),
    hardware: UnsafeCell::new(Hardware {
        owner: Owner::NONE,
        trigger: TriggerMode::INITIAL,
        started: 0,
        stopped: 0,
    }),
};
static CONTROLS: [AtomicU32; COUNTERS] = [const { AtomicU32::new(0) }; COUNTERS];
static PRINT_FLAGS: AtomicU32 = AtomicU32::new(0);
/// Setup index plus one; 0 when the last installed setup was not built in.
static CURRENT_SETUP: AtomicU32 = AtomicU32::new(0);

/// An `f64` read and written only with single 8-byte floating-point loads
/// and stores, which are single-copy atomic on this processor, so threads
/// share it without a lock.
#[repr(C, align(8))]
struct SharedF64(UnsafeCell<f64>);

// SAFETY: every access is one aligned `lfd` or `stfd`.
unsafe impl Sync for SharedF64 {}

const _: () = assert!(align_of::<SharedF64>() == 8);

impl SharedF64 {
    #[inline(always)]
    fn load(&self) -> f64 {
        let value: f64;
        // SAFETY: the cell is an 8-byte aligned f64 that only these
        // single-instruction accesses touch.
        unsafe {
            core::arch::asm!(
                "lfd {value}, 0({address})",
                value = out(freg) value,
                address = in(reg_nonzero) self.0.get(),
                options(nostack, readonly, preserves_flags),
            )
        };
        value
    }

    #[inline(always)]
    fn store(&self, value: f64) {
        // SAFETY: as for `load`.
        unsafe {
            core::arch::asm!(
                "stfd {value}, 0({address})",
                value = in(freg) value,
                address = in(reg_nonzero) self.0.get(),
                options(nostack, preserves_flags),
            )
        };
    }
}

/// Measured processor clock in Hz (stock 0x91f9b168).
static CLOCK: SharedF64 = SharedF64(UnsafeCell::new(3.2e9));

/// L2 event names stock formats into a static buffer (0x91faaee8).
struct NameBuffer(UnsafeCell<[u8; 0x40]>);

// SAFETY: stock writes the buffer from any thread without a lock; readers
// see a complete NUL-terminated name of the same table.
unsafe impl Sync for NameBuffer {}

static NAME_BUFFER: NameBuffer = NameBuffer(UnsafeCell::new([0; 0x40]));

/// The monitor lock, taken without lowering an IRQL above dispatch level.
struct Locked {
    irql: Option<Irql>,
}

impl Locked {
    fn take() -> Self {
        if processor::current_irql() >= Irql::DISPATCH {
            // SAFETY: MONITOR.lock is a static spin lock word; the IRQL is
            // already at or above dispatch level.
            unsafe { xboxkrnl::KeAcquireSpinLockAtRaisedIrql(MONITOR.lock.as_ptr()) };
            Self { irql: None }
        } else {
            Self {
                // SAFETY: MONITOR.lock is a static spin lock word.
                irql: Some(unsafe { xboxkrnl::KfAcquireSpinLock(MONITOR.lock.as_ptr()) }),
            }
        }
    }

    fn hardware(&mut self) -> &mut Hardware {
        // SAFETY: the lock is held for the lifetime of `self`.
        unsafe { &mut *MONITOR.hardware.get() }
    }

    /// A higher owner holds the counters (stock 0x91f91400).
    fn preempted(&mut self, owner: Owner) -> bool {
        let current = self.hardware().owner;
        current.0 > 0 && current.0 > owner.0
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        // SAFETY: `take` acquired MONITOR.lock in the matching way.
        unsafe {
            match self.irql {
                Some(irql) => xboxkrnl::KfReleaseSpinLock(MONITOR.lock.as_ptr(), irql),
                None => xboxkrnl::KeReleaseSpinLockFromRaisedIrql(MONITOR.lock.as_ptr()),
            }
        };
    }
}

/// u64 to double by truncating the mantissa (stock 0x91f28f78).
pub(super) fn to_double(value: u64) -> f64 {
    if value == 0 {
        return 0.0;
    }

    let zeros = value.leading_zeros();
    let mantissa = (value << zeros >> 11) & ((1 << 52) - 1);
    f64::from_bits(u64::from(0x43e - zeros) << 52 | mantissa)
}

fn frequency() -> f64 {
    to_double(kernel::performance_frequency())
}

fn control(counter: usize) -> CounterControl {
    CounterControl(CONTROLS[counter].load(Ordering::Relaxed))
}

fn set_control(counter: usize, control: CounterControl) {
    CONTROLS[counter].store(control.0, Ordering::Relaxed);
}

fn print_flags() -> PrintFlags {
    PrintFlags::from_bits_retain(PRINT_FLAGS.load(Ordering::Relaxed))
}

/// The event of `counter` (stock 0x91f910f8), formatting L2 names into the
/// static buffer as stock does.
fn event(counter: usize) -> Event {
    let event = pmc::event(counter, control(counter), &mut LiveRegisters);
    if let EventName::Formatted(name) = event.name {
        let text = name.text();
        // SAFETY: see `NameBuffer`; every L2 name fits the buffer.
        unsafe { (&mut *NAME_BUFFER.0.get())[..text.len()].copy_from_slice(text) };
    }

    event
}

/// Address of an event's name.
fn name_address(name: EventName) -> u64 {
    match name {
        EventName::Table(name) => pointer(name.text()),
        EventName::Formatted(_) => u64::from(NAME_BUFFER.0.get() as usize as u32),
    }
}

/// Take the counters for `owner` (stock 0x91f91428); a preempted current
/// owner's counters stop.
pub(super) fn acquire(owner: Owner) -> bool {
    let mut locked = Locked::take();
    if locked.preempted(owner) {
        return false;
    }

    if locked.hardware().owner.0 > 0 {
        set_prv_value(PrvRegister::RUN, 0);
    }

    locked.hardware().owner = owner;
    true
}

/// Give the counters up unless a higher owner holds them (stock
/// 0x91f914c0).
pub(super) fn release(owner: Owner) {
    let mut locked = Locked::take();
    if !locked.preempted(owner) {
        locked.hardware().owner = Owner::NONE;
    }
}

/// Run the counters (stock 0x91f91540).
pub(super) fn start(owner: Owner) -> bool {
    let mut locked = Locked::take();
    if locked.preempted(owner) {
        return false;
    }

    let control = monitor_control().difference(MonitorControl::FREEZE | MonitorControl::ENABLE);
    set_monitor_control(control);
    set_prv_value(
        PrvRegister::RUN,
        u64::from(RunControl::running(locked.hardware().trigger).bits()) << 32,
    );
    set_monitor_control(control | MonitorControl::ENABLE);
    locked.hardware().started = Timebase::now().ticks();
    true
}

/// Freeze the counters; only the current owner may (stock 0x91f91638).
pub(super) fn stop(owner: Owner) -> bool {
    let mut locked = Locked::take();
    if locked.hardware().owner != owner {
        return false;
    }

    locked.hardware().stopped = Timebase::now().ticks();
    set_monitor_control(monitor_control() | MonitorControl::FREEZE);
    set_prv_value(PrvRegister::RUN, 0);
    true
}

/// Count the events of processor `processor` (stock 0x91f91718, export 201).
pub(super) fn set_trigger_processor(owner: Owner, processor: u32) -> bool {
    let mut locked = Locked::take();
    if locked.preempted(owner) {
        return false;
    }

    let trigger = match TRIGGERS.get(processor as usize) {
        Some(&trigger) => trigger,
        None => {
            // Stock passes a stale register as the number.
            print(
                c"PMCSetTriggerProcessor - %d is not a physical processor\n",
                &[u64::from(processor)],
            );
            0
        }
    };

    set_prv_value(PrvRegister::TRIGGER, u64::from(trigger) << 32);
    true
}

/// Enable the monitor and reset the event selection, trigger, and counter
/// controls (stock 0x91f91800).
pub(super) fn reset() {
    set_spr_value(SpecialPurposeRegister::EVENT_SELECT, 0);
    // SAFETY: enables the monitor of the current processor; no memory is involved.
    unsafe { KeEnablePPUPerformanceMonitor() };

    set_prv_value(PrvRegister::TRIGGER, u64::from(TRIGGERS[0]) << 32);
    set_monitor_control(monitor_control().with_bus_width(BusWidth::RESET));

    for counter in 0..COUNTERS {
        set_control(counter, CounterControl::RESET);
    }
}

/// Zero the counters and the interval timer (stock 0x91f91bd0).
fn clear_locked(locked: &mut Locked, owner: Owner) -> bool {
    if locked.preempted(owner) {
        return false;
    }

    for counter in 0..COUNTERS as u8 {
        set_prv_value(PrvRegister::counter_value(counter), 0);
    }

    set_prv_value(PrvRegister::INTERVAL, 0);
    set_prv_value(PrvRegister::INTERVAL_RELOAD, 0);
    set_prv_value(PrvRegister::INTERVAL_CONTROL, 0);
    true
}

/// Stock 0x91f92770.
pub(super) fn clear(owner: Owner) -> bool {
    clear_locked(&mut Locked::take(), owner)
}

fn fill_state(locked: &mut Locked, state: &mut PmcState) {
    let registers = MonitorRegisters::get();
    for (index, counter) in state.counters.iter_mut().enumerate() {
        *counter = registers.counter_value(index);
    }

    let hardware = locked.hardware();
    state.ticks = hardware.stopped.wrapping_sub(hardware.started);
    state.interval = registers.interval_count() as i64 as f64;
    state.status = registers.status().0;
}

/// Read the counters (stock 0x91f918a8).
pub(super) fn read_state(owner: Owner, state: &mut PmcState) -> bool {
    let mut locked = Locked::take();
    if locked.preempted(owner) {
        return false;
    }

    fill_state(&mut locked, state);
    true
}

/// Read the counters as stock export 205 reports them (0x91f921a8).
fn read_reported(owner: Owner, state: &mut PmcState) -> bool {
    let mut locked = Locked::take();
    if locked.preempted(owner) {
        return false;
    }

    fill_state(&mut locked, state);
    state.instructions = 0;
    for counter in 0..COUNTERS {
        let name = event(counter).name;
        let value = pmc::reported(name, state.counters[counter]);
        if pmc::counts_instructions(name) {
            state.instructions = value;
        }
        state.counters[counter] = value;
    }

    true
}

/// Count of counter `index`, 0 past the last (stock 0x91f919a0).
pub(super) fn counter(index: u32) -> u32 {
    if index as usize >= COUNTERS {
        0
    } else {
        MonitorRegisters::get().counter_value(index as usize) as u32
    }
}

/// Stock 0x91f920e8.
pub(super) fn set_print_flags(flags: u32) {
    PRINT_FLAGS.store(flags, Ordering::Relaxed);
}

/// Select the events of a setup on the calling processor (stock 0x91f92918).
fn select_events_locked(locked: &mut Locked, owner: Owner, setup: &Setup) -> bool {
    if locked.preempted(owner) {
        return false;
    }

    reset();
    set_spr_value(SpecialPurposeRegister::EVENT_SELECT, setup.select);
    true
}

/// Stock 0x91f929f0.
pub(super) fn select_events(owner: Owner, setup: &Setup) -> bool {
    select_events_locked(&mut Locked::take(), owner, setup)
}

/// Route the counters, the bus, and the counting mode of a setup, then
/// clear the counters (stock 0x91f92970).
fn configure_locked(locked: &mut Locked, owner: Owner, setup: &Setup) -> bool {
    /// Unit number of the L2 in `pmc::bus_selection`.
    const L2_UNIT: u32 = 5;

    if locked.preempted(owner) {
        return false;
    }

    for (counter, route) in setup.routes.iter().enumerate() {
        route_counter(route.source, route.lane, counter);
    }

    for (register, value) in pmc::bus_selection(L2_UNIT) {
        set_pmw_value(PmwRegister(register.0), value);
    }

    locked.hardware().trigger = TriggerMode::from_setup(setup.trigger);
    set_pmw_value(PmwRegister::L2_GROUP, setup.group);
    write_controls();
    clear_locked(locked, owner)
}

/// Stock 0x91f92a68.
pub(super) fn configure(owner: Owner, setup: &Setup) -> bool {
    configure_locked(&mut Locked::take(), owner, setup)
}

/// Stock 0x91f91f20.
fn route_counter(source: u32, lane: u8, counter: usize) {
    match pmc::route(source, lane, counter) {
        Some(input) => {
            if print_flags().is_empty() {
                print(
                    c"PMCAssignBusToPMC: assigning counter %d to input %d\n",
                    &[counter as u64, u64::from(input)],
                );
            }
            set_control(counter, control(counter).routed(input));
        }
        None => print(
            c"\nPMCAssignBusToPMC: ERROR - Failed to route source %d bitlane %d to counter %d\n",
            &[u64::from(source), u64::from(lane), counter as u64],
        ),
    }
}

/// Make each counter count cycles or edges as its event requires and load
/// the controls (stock 0x91f91c78).
fn write_controls() {
    for counter in 0..COUNTERS {
        let event = event(counter);
        let mut control = control(counter);
        let quiet = !print_flags().is_empty();
        match event.name.name().counting() {
            Counting::Cycles => {
                if !control.counts_cycles() && !quiet {
                    print(
                        c"PMCSetCounterControl: WARNING ctr %d set to count edges but should count cycles.  Changing to cycles\n",
                        &[counter as u64],
                    );
                }
                control = control.with_cycles(true);
            }
            Counting::Edges => {
                if control.counts_cycles() && !quiet {
                    print(
                        c"PMCSetCounterControl: WARNING ctr %d set to count cycles but should count edges.  Changing to edges\n",
                        &[counter as u64],
                    );
                }
                control = control.with_cycles(false);
            }
            Counting::Unknown => print(
                c"PMCSetCounterControl: WARNING counter %d (%s) may be cycle or edge or invalid\n",
                &[counter as u64, name_address(event.name)],
            ),
        }

        set_control(counter, control);
        set_prv_value(
            PrvRegister::counter_control(counter as u8),
            u64::from(control.0) << 32,
        );
    }
}

/// Built-in setup `index`, recorded as the current setup (stock
/// 0x91f92ae0/0x91f92c58). Stock applies whatever lies past the table for
/// an index out of range; here that installs nothing.
fn current_setup(index: u32) -> Option<Setup> {
    let setup = pmc::setup(index);
    CURRENT_SETUP.store(
        if setup.is_some() { index + 1 } else { 0 },
        Ordering::Relaxed,
    );
    set_print_flags(PrintFlags::QUIET.bits());
    setup
}

/// Run the calling thread on processor `processor` (stock 0x91f78a68).
fn set_processor(processor: u8) {
    let mut thread = 0u32;

    // SAFETY: `data_imports_resolved` held at module load.
    let object_type =
        crate::kernel::address_of(unsafe { xboxkrnl::ExThreadObjectType.get_unchecked() });
    // SAFETY: `Handle::CURRENT_THREAD` is the pseudo-handle of the calling
    // thread, `object_type` the kernel thread type, and `thread` a live u32.
    let status = unsafe {
        xboxkrnl::ObReferenceObjectByHandle(Handle::CURRENT_THREAD, object_type, &mut thread)
    };

    if status.is_success() {
        let mut previous = 0u32;
        // SAFETY: `thread` is the referenced calling thread, released here;
        // `previous` is a live u32.
        unsafe {
            xboxkrnl::KeSetAffinityThread(thread as usize as *mut _, 1 << processor, &mut previous);
            xboxkrnl::ObDereferenceObject(thread);
        }
    }
}

/// Install built-in setup `index`, selecting its events on each core by
/// moving the calling thread (stock 0x91f92ae0).
pub(super) fn install(owner: Owner, index: u32) -> bool {
    const CORES: u8 = (processor::HARDWARE_THREAD_COUNT / 2) as u8;

    let processor = Kpcr::current().processor_number().get();
    if Locked::take().preempted(owner) {
        return false;
    }

    let Some(setup) = current_setup(index) else {
        return false;
    };

    for core in 0..CORES {
        set_processor(core * 2);
        select_events(owner, &setup);
    }

    set_processor(processor);
    configure(owner, &setup)
}

/// Context of [`select_on_processor`].
struct SelectRequest<'a> {
    owner: Owner,
    setup: &'a Setup,
}

/// Per-processor routine of [`install_on_all_processors`] (stock
/// 0x91f92c00): the first thread of each core selects the events.
extern "C" fn select_on_processor(request: &SelectRequest<'_>) -> u32 {
    if Kpcr::current().processor_number().get() & 1 != 0 {
        return 1;
    }

    u32::from(select_events(request.owner, request.setup))
}

// Kernel entry of `select_on_processor`, preserving the full nonvolatile
// registers.
crate::exports::bridged!(select_on_processor_entry, select_on_processor);

/// Install built-in setup `index` on every core at once (stock 0x91f92c58).
pub(super) fn install_on_all_processors(owner: Owner, index: u32) -> bool {
    if Locked::take().preempted(owner) {
        return false;
    }

    let Some(setup) = current_setup(index) else {
        return false;
    };

    let request = SelectRequest {
        owner,
        setup: &setup,
    };
    // SAFETY: the kernel passes the context to `select_on_processor` as its
    // `&SelectRequest`, and `request` outlives the call because the kernel
    // returns only after every processor ran the routine.
    unsafe {
        xboxkrnl::KeIpiGenericCall(
            select_on_processor_entry as *const () as usize as u32,
            core::ptr::from_ref(&request) as usize as u32,
        )
    };

    configure(owner, &setup)
}

/// Program the interval timer control (stock 0x91f920f8).
pub(super) fn set_interval_control(value: u64) {
    set_prv_value(PrvRegister::INTERVAL_CONTROL, value);
}

/// Load the interval timer and its reload value with `ticks` before the
/// next interrupt (stock 0x91f92108, 0x91f92138); the count is in the high
/// word, the low word stock leaves uninitialized is 0.
pub(super) fn set_interval(ticks: u32) {
    set_prv_value(PrvRegister::INTERVAL, u64::from(ticks) << 32);
    set_prv_value(PrvRegister::INTERVAL_RELOAD, u64::from(ticks) << 32);
}

/// Load the interval reload value (stock 0x91f92138).
pub(super) fn set_interval_reload(ticks: u32) {
    set_prv_value(PrvRegister::INTERVAL_RELOAD, u64::from(ticks) << 32);
}

/// Wait until a pending interval reload completes; false when none is
/// pending (stock 0x91f92168).
pub(super) fn wait_interval_reload() -> bool {
    let pending = || MonitorRegisters::get().status().interval_overflow();
    if !pending() {
        return false;
    }

    while pending() {}

    true
}

/// Table flag of counter `index`, 0 past the last (stock 0x91f912d8).
pub(super) fn counter_flag(index: u32) -> u32 {
    if index as usize >= COUNTERS {
        0
    } else {
        event(index as usize).flag
    }
}

/// PMC part of the title terminate notification (stock 0x91f64e68).
pub(super) fn title_terminated() {
    release(Owner::TITLE_TERMINATION);
    stop(Owner::NONE);
    clear(Owner::NONE);
}
