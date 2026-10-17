//! Performance monitor counters (stock 0x91f913f0..0x91f92e58): ownership
//! by priority, the counter hardware, setups, the statistics printouts, and
//! exports 196-211.
//!
//! The owner, trigger processor, and run timestamps change under the
//! monitor's spin lock; the counter controls, print flags, current setup,
//! and measured clock are read without it, as in stock.

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands::performance::pmc;
use openxbdm_server::commands::performance::pmc::BusRegister;
use openxbdm_server::commands::performance::pmc::COUNTERS;
use openxbdm_server::commands::performance::pmc::CounterControl;
use openxbdm_server::commands::performance::pmc::Counting;
use openxbdm_server::commands::performance::pmc::Event;
use openxbdm_server::commands::performance::pmc::EventName;
use openxbdm_server::commands::performance::pmc::Setup;
use xbox360::time::TickCount;
use xbox360::time::Timebase;
use xbox360_sys::export_raw;
use xbox360_sys::processor;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeEnablePPUPerformanceMonitor;
use xbox360_sys::xboxkrnl::KeGetPMWRegister;
use xbox360_sys::xboxkrnl::KeGetSpecialPurposeRegister;
use xbox360_sys::xboxkrnl::KeSetPMWRegister;
use xbox360_sys::xboxkrnl::KeSetPRVRegister;
use xbox360_sys::xboxkrnl::PmwRegister;
use xbox360_sys::xboxkrnl::PrvRegister;
use xbox360_sys::xboxkrnl::SpecialPurposeRegister;

use crate::exports::export;
use crate::kernel;

/// Counter values: one register per counter, the count in the high word.
const COUNTER_VALUES: u32 = 0x8fff_1200;
const INTERVAL_COUNT: u32 = 0x8fff_11e0;
/// Status: bit 47 marks an interval overflow, bits 63 down to 48 counter
/// overflows.
const STATUS: u32 = 0x8fff_11c8;
/// Trigger selection of processors 0..2.
const TRIGGERS: [u32; 3] = [0x0842_2108, 0x39ce_8420, 0x6b5a_e738];
/// Print flags the setup installers store: suppress the routing and
/// counting notes, the frame rate, and the ECC counts.
const QUIET: u32 = 0xffff_fff9;
/// Handle of the calling thread.
const CURRENT_THREAD: u32 = 0xffff_fffe;

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
    trigger: u32,
    started: u64,
    stopped: u64,
}

struct Monitor {
    lock: UnsafeCell<u32>,
    hardware: UnsafeCell<Hardware>,
}

// SAFETY: `hardware` is only accessed while `lock` is held.
unsafe impl Sync for Monitor {}

static MONITOR: Monitor = Monitor {
    lock: UnsafeCell::new(0),
    hardware: UnsafeCell::new(Hardware {
        owner: Owner::NONE,
        trigger: 3,
        started: 0,
        stopped: 0,
    }),
};
static CONTROLS: [AtomicU32; COUNTERS] = [const { AtomicU32::new(0) }; COUNTERS];
static PRINT_FLAGS: AtomicU32 = AtomicU32::new(0);
/// Setup index plus one; 0 when the last installed setup was not built in.
static CURRENT_SETUP: AtomicU32 = AtomicU32::new(0);

/// Measured processor clock in Hz (stock 0x91f9b168); stock reads and
/// writes it with single 8-byte accesses.
struct Clock(UnsafeCell<f64>);

// SAFETY: aligned 8-byte floating-point loads and stores are single
// accesses on this processor, which is how stock shares the value.
unsafe impl Sync for Clock {}

static CLOCK: Clock = Clock(UnsafeCell::new(3.2e9));

impl Clock {
    fn get(&self) -> f64 {
        // SAFETY: see the `Sync` implementation.
        unsafe { core::ptr::read_volatile(self.0.get()) }
    }

    fn set(&self, value: f64) {
        // SAFETY: see the `Sync` implementation.
        unsafe { core::ptr::write_volatile(self.0.get(), value) }
    }
}

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
            unsafe { xboxkrnl::KeAcquireSpinLockAtRaisedIrql(MONITOR.lock.get().cast()) };
            Self { irql: None }
        } else {
            Self {
                // SAFETY: MONITOR.lock is a static spin lock word.
                irql: Some(unsafe { xboxkrnl::KfAcquireSpinLock(MONITOR.lock.get().cast()) }),
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
                Some(irql) => xboxkrnl::KfReleaseSpinLock(MONITOR.lock.get().cast(), irql),
                None => xboxkrnl::KeReleaseSpinLockFromRaisedIrql(MONITOR.lock.get().cast()),
            }
        };
    }
}

/// `KeGetSpecialPurposeRegister`, splitting the 64-bit result into r3:r4.
#[unsafe(naked)]
extern "C" fn get_spr(register: SpecialPurposeRegister) -> u64 {
    core::arch::naked_asm!(
        "stwu 1, -0x20(1)",
        "mflr 0",
        "stw 0, 0x24(1)",
        "bl {get}",
        "mr 4, 3",
        // rldicl 3, 3, 32, 32: the high word into the low half of r3.
        ".long 0x78630022",
        "lwz 0, 0x24(1)",
        "mtlr 0",
        "addi 1, 1, 0x20",
        "blr",
        get = sym KeGetSpecialPurposeRegister,
    )
}

/// `KeGetPMWRegister`, splitting the 64-bit result into r3:r4.
#[unsafe(naked)]
extern "C" fn get_pmw(register: PmwRegister) -> u64 {
    core::arch::naked_asm!(
        "stwu 1, -0x20(1)",
        "mflr 0",
        "stw 0, 0x24(1)",
        "bl {get}",
        "mr 4, 3",
        ".long 0x78630022",
        "lwz 0, 0x24(1)",
        "mtlr 0",
        "addi 1, 1, 0x20",
        "blr",
        get = sym KeGetPMWRegister,
    )
}

/// One 64-bit load of a monitor register; the halves come back in r3:r4.
#[unsafe(naked)]
extern "C" fn read_register(address: u32) -> u64 {
    core::arch::naked_asm!(
        // ld 5, 0(3)
        ".long 0xe8a30000",
        "mr 4, 5",
        // rldicl 3, 5, 32, 32
        ".long 0x78a30022",
        "blr",
    )
}

/// `DbgPrint(format, arguments...)` with each argument in one 64-bit
/// register, as the console passes variadic arguments.
#[unsafe(naked)]
pub(super) unsafe extern "C" fn debug_print(format: *const u8, arguments: *const [u64; 7]) -> u32 {
    core::arch::naked_asm!(
        "mr 11, 4",
        ".irp reg, 4,5,6,7,8,9,10",
        // ld \reg, 8 * (\reg - 4)(r11)
        ".long (58 << 26) | (\\reg << 21) | (11 << 16) | (8 * (\\reg - 4))",
        ".endr",
        "b {print}",
        print = sym kernel::DbgPrint,
    )
}

/// Print `format` with up to seven arguments.
pub(super) fn print(format: &core::ffi::CStr, arguments: &[u64]) {
    let mut slots = [0u64; 7];
    slots[..arguments.len()].copy_from_slice(arguments);
    // SAFETY: `format` is NUL-terminated and `slots` holds every argument
    // it consumes.
    unsafe { debug_print(format.as_ptr().cast(), &slots) };
}

fn pointer(text: &[u8]) -> u64 {
    u64::from(text.as_ptr() as usize as u32)
}

fn set_prv_value(register: PrvRegister, value: u64) {
    // SAFETY: PRV register writes reach only the performance monitor.
    unsafe { KeSetPRVRegister(register, value) };
}

fn set_spr_value(register: SpecialPurposeRegister, value: u64) {
    // SAFETY: the callers write only the monitor control and event select
    // registers.
    unsafe { xboxkrnl::KeSetSpecialPurposeRegister(register, value) };
}

fn set_pmw_value(register: PmwRegister, value: u64) {
    // SAFETY: PMW register writes reach only the event bus selection.
    unsafe { KeSetPMWRegister(register, value) };
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

fn counter_value(index: usize) -> u64 {
    read_register(COUNTER_VALUES + index as u32 * 8) >> 32
}

fn control(counter: usize) -> CounterControl {
    CounterControl(CONTROLS[counter].load(Ordering::Relaxed))
}

fn set_control(counter: usize, control: CounterControl) {
    CONTROLS[counter].store(control.0, Ordering::Relaxed);
}

fn print_flags() -> u32 {
    PRINT_FLAGS.load(Ordering::Relaxed)
}

/// The registers the event decoding reads.
struct LiveRegisters;

impl pmc::Registers for LiveRegisters {
    fn select(&mut self) -> u64 {
        get_spr(SpecialPurposeRegister::EVENT_SELECT)
    }

    fn bus(&mut self, register: BusRegister) -> u64 {
        get_pmw(PmwRegister(register.0))
    }
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
    let control = get_spr(SpecialPurposeRegister::MONITOR_CONTROL) & !6;
    set_spr_value(SpecialPurposeRegister::MONITOR_CONTROL, control);
    set_prv_value(
        PrvRegister::RUN,
        u64::from(0x8000_0000 | (locked.hardware().trigger & 3) << 26) << 32,
    );
    set_spr_value(SpecialPurposeRegister::MONITOR_CONTROL, control | 4);
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
    set_spr_value(
        SpecialPurposeRegister::MONITOR_CONTROL,
        get_spr(SpecialPurposeRegister::MONITOR_CONTROL) | 2,
    );
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
    drop(locked);
    true
}

/// Enable the monitor and reset the event selection, trigger, and counter
/// controls (stock 0x91f91800).
pub(super) fn reset() {
    set_spr_value(SpecialPurposeRegister::EVENT_SELECT, 0);
    // SAFETY: enables the monitor of the current processor; no memory is involved.
    unsafe { KeEnablePPUPerformanceMonitor() };
    set_prv_value(PrvRegister::TRIGGER, u64::from(TRIGGERS[0]) << 32);
    set_spr_value(
        SpecialPurposeRegister::MONITOR_CONTROL,
        get_spr(SpecialPurposeRegister::MONITOR_CONTROL) & !0xfc00 | 5 << 11,
    );
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
    for (index, counter) in state.counters.iter_mut().enumerate() {
        *counter = counter_value(index);
    }
    let hardware = locked.hardware();
    state.ticks = hardware.stopped.wrapping_sub(hardware.started);
    state.interval = (read_register(INTERVAL_COUNT) >> 32) as i64 as f64;
    state.status = read_register(STATUS);
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
        counter_value(index as usize) as u32
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
    if locked.preempted(owner) {
        return false;
    }
    for (counter, route) in setup.routes.iter().enumerate() {
        route_counter(route.source, route.lane, counter);
    }
    for (register, value) in pmc::bus_selection(5) {
        set_pmw_value(PmwRegister(register.0), value);
    }
    locked.hardware().trigger = setup.trigger & 3;
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
            if print_flags() == 0 {
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
        let quiet = print_flags() != 0;
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
    set_print_flags(QUIET);
    setup
}

/// Run the calling thread on processor `processor` (stock 0x91f78a68).
fn set_processor(processor: u8) {
    let mut thread = 0u32;
    // SAFETY: `data_imports_resolved` held at module load.
    let object_type =
        core::ptr::from_ref(unsafe { xboxkrnl::ExThreadObjectType.get_unchecked() }).addr() as u32;
    // SAFETY: CURRENT_THREAD is the pseudo-handle of the calling thread,
    // `object_type` the kernel thread type, and `thread` a live u32.
    let status = unsafe {
        xboxkrnl::ObReferenceObjectByHandle(
            Handle::from_raw(CURRENT_THREAD),
            object_type,
            &mut thread,
        )
    };
    if (status.0 as i32) >= 0 {
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
    let processor = Kpcr::current().processor_number().get();
    if Locked::take().preempted(owner) {
        return false;
    }
    let Some(setup) = current_setup(index) else {
        return false;
    };
    for core in 0..3 {
        set_processor(core * 2);
        select_events(owner, &setup);
    }
    set_processor(processor);
    configure(owner, &setup)
}

/// Context of [`select_on_processor`].
#[repr(C)]
struct SelectRequest {
    owner: Owner,
    setup: *const Setup,
}

/// Per-processor routine of [`install_on_all_processors`] (stock
/// 0x91f92c00): the first thread of each core selects the events.
extern "C" fn select_on_processor(request: u32) -> u32 {
    if Kpcr::current().processor_number().get() & 1 != 0 {
        return 1;
    }
    // SAFETY: the requester waits in `KeIpiGenericCall` while the request
    // and its setup are alive.
    let request = unsafe { &*(request as usize as *const SelectRequest) };
    // SAFETY: as above.
    u32::from(select_events(request.owner, unsafe { &*request.setup }))
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
    // SAFETY: `select_on_processor_entry` reads `request`, which outlives
    // the call because the kernel returns only after every processor ran it.
    unsafe {
        xboxkrnl::KeIpiGenericCall(
            select_on_processor_entry as *const () as usize as u32,
            &request as *const SelectRequest as usize as u32,
        )
    };
    configure(owner, &setup)
}

/// Acquire, install setup `index`, and run the counters (stock 0x91f92d68).
fn begin(owner: Owner, index: u32) -> bool {
    acquire(owner)
        && install(owner, index)
        && clear(owner)
        && set_trigger_processor(
            owner,
            u32::from(Kpcr::current().processor_number().get() >> 1),
        )
        && start(owner)
}

/// Stop the counters, release them, and print the statistics (stock
/// 0x91f92df0).
fn end(owner: Owner) -> bool {
    let mut state = PmcState::new();
    if !stop(owner) || !read_reported(owner, &mut state) {
        return false;
    }
    release(owner);
    print_statistics(&mut state, 1);
    true
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
    let pending = || (read_register(STATUS) >> 32) as u32 & 0x8000 != 0;
    if !pending() {
        return false;
    }
    while pending() {}
    true
}

/// Print a counter state (stock export 207, 0x91f919c8).
fn print_state(state: &PmcState) {
    let ticks = state.ticks as i64 as f64;
    let rate = ticks / frequency();
    // Stock passes the interval's bit pattern for `%u`.
    print(
        c"CPU ticks %I64d interval %u frequency %.1f\n",
        &[
            state.ticks,
            state.interval.to_bits(),
            (state.interval / rate).to_bits(),
        ],
    );
    for (index, &value) in state.counters.iter().enumerate() {
        print(c"pmc[%d] = %I64u\n", &[index as u64, value]);
    }
}

/// Percentages of one counter (stock 0x91f91a60).
fn print_rates(counter: usize, state: &PmcState) {
    let event = event(counter);
    let value = to_double(state.counters[counter]);
    if pmc::counts_instructions(event.name) {
        print(c"(%6.2f%%)", &[(value / state.interval * 100.0).to_bits()]);
        if state.status & (1 << 63 >> counter) == 0 {
            print(c" IPC=|%.3f|", &[(value / state.interval).to_bits()]);
        }
        return;
    }
    let flag = f64::from(event.flag as i32);
    print(
        c"(%6.2f%%)",
        &[(flag / state.interval * value * 100.0).to_bits()],
    );
    if state.instructions != 0 {
        print(
            c"[%6.2f%%]",
            &[(value * 100.0 / state.instructions as i64 as f64).to_bits()],
        );
    }
}

/// Print the statistics of a counter state (stock export 208, 0x91f92438).
fn print_statistics(state: &mut PmcState, flags: u32) {
    const THREADS: [&core::ffi::CStr; 4] = [c"T0", c"T1", c"EE", c""];
    static SPACE: [u16; 2] = [0x20, 0];
    let ticks = state.ticks as i64 as f64;
    let rate = ticks / frequency();
    print(
        c"\n\nCPU ticks=|%I64d| interval=|%.0f| frequency=|%.1f|\n",
        &[
            state.ticks,
            state.interval.to_bits(),
            (state.interval / rate).to_bits(),
        ],
    );
    let print_flags = print_flags();
    if print_flags & 4 == 0 {
        let time = ticks / frequency();
        print(c"time=|%.3f| ", &[time.to_bits()]);
        if print_flags & 2 == 0 {
            print(c"FPS=|%7.2f|", &[(1.0 / time).to_bits()]);
        }
        match CURRENT_SETUP.load(Ordering::Relaxed).checked_sub(1) {
            Some(setup) => print(c" using setup %2d", &[u64::from(setup)]),
            None => print(c"               ", &[]),
        }
        print(
            c"%12ls( /cycle)[ /inst ]\n",
            &[u64::from(SPACE.as_ptr() as usize as u32)],
        );
    }
    if (state.status >> 32) as u32 & 0x8000 != 0 {
        let time = ticks / frequency();
        let clock = CLOCK.get();
        let interval = time * clock;
        print(
            c"Interval overflow, using ticks (freq is %.2fGhz) = |%.0f|\n",
            &[(clock * 1e-9).to_bits(), interval.to_bits()],
        );
        state.interval = interval;
        state.status &= !(0x8000 << 32);
    }
    // Stock advances the overflow bit only for routed counters.
    let mut overflow = 1u64 << 63;
    for counter in 0..COUNTERS {
        let Some(input) = control(counter).input() else {
            continue;
        };
        let thread = pmc::thread(counter, control(counter), &mut LiveRegisters);
        let label = pmc::source_label(counter, input);
        let value = state.counters[counter];
        let name = name_address(event(counter).name) + 1;
        print(
            c"[%2d]%s%2s(%29s)=%10I64u ",
            &[
                counter as u64,
                pointer(label.to_bytes()),
                pointer(THREADS[usize::from(thread)].to_bytes()),
                name,
                value,
            ],
        );
        if state.status & overflow != 0 {
            print(c" OVERFLOW\n", &[]);
        } else {
            print_rates(counter, state);
            print(c"\n", &[]);
        }
        overflow >>= 1;
    }
    if flags & 1 == 0 && print_flags & 1 == 0 {
        print_ecc_counts();
    }
}

/// Stock 0x91f92020: one line per field, A0Q0 in the top byte.
fn print_ecc_counts() {
    let counts = get_pmw(PmwRegister::L2_ECC);
    print(c"L2 ECC ERROR COUNTS\n", &[]);
    let words = [(counts >> 32) as u32, counts as u32];
    for index in 0..8u32 {
        let word = words[(index >> 2) as usize];
        let field = word >> (24 - 8 * (index & 3)) & 0x3f;
        print(
            c"A%dQ%d = %d\n",
            &[
                u64::from(index & 1),
                u64::from(index >> 1),
                u64::from(field),
            ],
        );
    }
}

/// Measure the processor clock over 100 ms of the interval counter (stock
/// export 211, 0x91f927e0); 0 when the counters are unavailable. A failed
/// step keeps the counters acquired, as in stock.
fn measure_clock() -> u64 {
    let begun = TickCount::now().milliseconds();
    let clock = if acquire(Owner::EXPORTS)
        && {
            reset();
            clear(Owner::EXPORTS)
        }
        && start(Owner::EXPORTS)
    {
        // Stock compares the zero-extended tick counts, which never ends
        // when the count wraps during the wait.
        while TickCount::now().milliseconds().wrapping_sub(begun) < 100 {}
        if stop(Owner::EXPORTS) {
            let interval = (read_register(INTERVAL_COUNT) >> 32) as i64 as f64;
            let ticks = {
                let mut locked = Locked::take();
                let hardware = locked.hardware();
                hardware.stopped.wrapping_sub(hardware.started)
            };
            release(Owner::EXPORTS);
            let seconds = ticks as i64 as f64 / frequency();
            ((interval / seconds) as i64 / 100_000) as f64 * 100_000.0
        } else {
            0.0
        }
    } else {
        0.0
    };
    CLOCK.set(clock);
    clock as i64 as u64
}

fn result(succeeded: bool, failure: Hresult) -> u32 {
    if succeeded { Hresult::OK.0 } else { failure.0 }
}

/// Export 196: acquire, install setup `index`, and run the counters.
extern "C" fn export_begin(index: u32) -> u32 {
    result(begin(Owner::EXPORTS, index), Hresult::NOT_ACQUIRED)
}

/// Export 197: stop, release, and print the statistics.
extern "C" fn export_end() -> u32 {
    result(end(Owner::EXPORTS), Hresult::NOT_OWNER)
}

/// Export 198: acquire and install setup `index`.
extern "C" fn export_install(index: u32) -> u32 {
    result(
        acquire(Owner::EXPORTS) && install(Owner::EXPORTS, index),
        Hresult::NOT_ACQUIRED,
    )
}

/// Export 199: stop and release.
extern "C" fn export_stop_and_release() {
    stop(Owner::EXPORTS);
    release(Owner::EXPORTS);
}

/// Export 200.
extern "C" fn export_clear() -> u32 {
    result(clear(Owner::EXPORTS), Hresult::NOT_OWNER)
}

/// Export 201.
extern "C" fn export_set_trigger_processor(processor: u32) -> u32 {
    result(
        set_trigger_processor(Owner::EXPORTS, processor),
        Hresult::NOT_OWNER,
    )
}

/// Export 202.
extern "C" fn export_start() -> u32 {
    result(start(Owner::EXPORTS), Hresult::NOT_OWNER)
}

/// Export 203.
extern "C" fn export_stop() -> u32 {
    result(stop(Owner::EXPORTS), Hresult::NOT_OWNER)
}

/// Export 204 (stock 0x91f92378): count of counter `index` into `value`;
/// 0 while a higher owner holds the counters.
extern "C" fn export_query_counter(index: u32, value: *mut u32) -> u32 {
    let mut locked = Locked::take();
    let (count, succeeded) = if locked.preempted(Owner::EXPORTS) {
        (0, false)
    } else {
        (counter(index), true)
    };
    drop(locked);
    // SAFETY: the caller passes a writable u32.
    unsafe { core::ptr::write_volatile(value, count) };
    result(succeeded, Hresult::NOT_OWNER)
}

/// Export 205.
extern "C" fn export_read_state(state: *mut PmcState) -> u32 {
    // SAFETY: the caller passes a writable 0xa0-byte state.
    result(
        read_reported(Owner::EXPORTS, unsafe { &mut *state }),
        Hresult::NOT_OWNER,
    )
}

/// Export 206 (stock 0x91f91290): event name of counter `counter` without
/// its counting kind.
extern "C" fn export_counter_name(counter: i32) -> u32 {
    match usize::try_from(counter) {
        Ok(counter) if counter < COUNTERS => name_address(event(counter).name) as u32 + 1,
        _ => pmc::BAD_COUNTER.text().as_ptr() as usize as u32,
    }
}

/// Export 207.
extern "C" fn export_print_state(state: *const PmcState) {
    // SAFETY: the caller passes a 0xa0-byte state.
    print_state(unsafe { &*state });
}

/// Export 208.
extern "C" fn export_print_statistics(state: *mut PmcState, flags: u32) {
    // SAFETY: the caller passes a writable 0xa0-byte state.
    print_statistics(unsafe { &mut *state }, flags);
}

/// Table flag of counter `index`, 0 past the last (stock 0x91f912d8).
pub(super) fn counter_flag(index: u32) -> u32 {
    if index as usize >= COUNTERS {
        0
    } else {
        event(index as usize).flag
    }
}

/// Export 209: the counter number is signed, so negative numbers are past
/// the last as unsigned values.
extern "C" fn export_counter_flag(counter: i32) -> u32 {
    counter_flag(counter as u32)
}

/// Export 210 (stock 0x91f91320): source class of counter `counter`. Stock
/// does not check the number and reads past the controls; here other
/// numbers report an unrouted counter.
extern "C" fn export_counter_source(counter: i32) -> u32 {
    match usize::try_from(counter) {
        Ok(counter) if counter < COUNTERS => {
            pmc::source_class(counter, control(counter), &mut LiveRegisters)
        }
        _ => 7,
    }
}

/// Export 211: the measured clock, returned in one 64-bit register.
#[unsafe(naked)]
unsafe extern "C" fn export_measure_clock() {
    core::arch::naked_asm!(
        "stwu 1, -0x10(1)",
        "mflr 0",
        "stw 0, 0x8(1)",
        "lis 12, {measure}@ha",
        "addi 12, 12, {measure}@l",
        "bl {bridge}",
        // rldimi 4, 3, 32, 0: join r3:r4 into r4.
        ".long 0x7864000e",
        "mr 3, 4",
        "lwz 0, 0x8(1)",
        "mtlr 0",
        "addi 1, 1, 0x10",
        "blr",
        measure = sym measure_clock_entry,
        bridge = sym crate::exports::export_bridge,
    )
}

extern "C" fn measure_clock_entry() -> u64 {
    measure_clock()
}

export!(196, export_begin);
export!(197, export_end);
export!(198, export_install);
export!(199, export_stop_and_release);
export!(200, export_clear);
export!(201, export_set_trigger_processor);
export!(202, export_start);
export!(203, export_stop);
export!(204, export_query_counter);
export!(205, export_read_state);
export!(206, export_counter_name);
export!(207, export_print_state);
export!(208, export_print_statistics);
export!(209, export_counter_flag);
export!(210, export_counter_source);
export_raw!(211, export_measure_clock);

/// PMC part of the title terminate notification (stock 0x91f64e68).
pub(super) fn title_terminated() {
    release(Owner::TITLE_TERMINATION);
    stop(Owner::NONE);
    clear(Owner::NONE);
}
