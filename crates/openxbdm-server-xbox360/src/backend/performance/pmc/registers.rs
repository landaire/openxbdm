//! Monitor register layout, register words, and the kernel register
//! accessors.

use core::mem::offset_of;

use openxbdm_server::commands::performance::pmc;
use openxbdm_server::commands::performance::pmc::BusRegister;
use openxbdm_server::commands::performance::pmc::COUNTERS;
use xbox360_sys::mmio::Register;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::KeGetPMWRegister;
use xbox360_sys::xboxkrnl::KeGetSpecialPurposeRegister;
use xbox360_sys::xboxkrnl::KeSetPMWRegister;
use xbox360_sys::xboxkrnl::KeSetPRVRegister;
use xbox360_sys::xboxkrnl::PmwRegister;
use xbox360_sys::xboxkrnl::PrvRegister;
use xbox360_sys::xboxkrnl::SpecialPurposeRegister;

/// Memory mapping of the monitor registers the counters read back, each
/// with one 64-bit load.
#[repr(C)]
pub(super) struct MonitorRegisters {
    status: Register<u64>,
    _reserved_08: [Register<u64>; 2],
    /// Interval timer count in the high word.
    interval_count: Register<u64>,
    _reserved_20: [Register<u64>; 3],
    /// One register per counter, the count in the high word.
    counter_values: [Register<u64>; COUNTERS],
}

const _: () = {
    assert!(offset_of!(MonitorRegisters, interval_count) == 0x18);
    assert!(offset_of!(MonitorRegisters, counter_values) == 0x38);
    assert!(size_of::<MonitorRegisters>() == 0xb8);
};

impl MonitorRegisters {
    const ADDRESS: usize = 0x8fff_11c8;

    #[inline(always)]
    pub(super) fn get() -> &'static Self {
        // SAFETY: `ADDRESS` maps the monitor registers in this layout for
        // the life of the system, 8-byte aligned; loads read them without
        // side effects.
        unsafe { &*(Self::ADDRESS as *const Self) }
    }

    #[inline(always)]
    pub(super) fn status(&self) -> PmcStatus {
        PmcStatus(self.status.read())
    }

    /// The interval timer count, zero-extended.
    #[inline(always)]
    pub(super) fn interval_count(&self) -> u64 {
        self.interval_count.read() >> 32
    }

    /// Count of counter `counter`, which callers keep below `COUNTERS`; the
    /// wrap only spares a bounds check.
    pub(super) fn counter_value(&self, counter: usize) -> u64 {
        self.counter_values[counter % COUNTERS].read() >> 32
    }
}

/// Monitor status word, as export 205 reports it in `PmcState::status`.
#[derive(Clone, Copy)]
pub(super) struct PmcStatus(pub(super) u64);

impl PmcStatus {
    /// Interval timer overflow; also set while an interval reload is
    /// pending.
    pub(super) const INTERVAL_OVERFLOW: u64 = 1 << 47;
    /// Overflow of the first counter; each further counter is one bit
    /// lower, down to bit 48.
    pub(super) const FIRST_COUNTER_OVERFLOW: u64 = 1 << 63;

    pub(super) fn interval_overflow(self) -> bool {
        self.0 & Self::INTERVAL_OVERFLOW != 0
    }

    pub(super) fn counter_overflow(self, counter: usize) -> bool {
        self.0 & (Self::FIRST_COUNTER_OVERFLOW >> counter) != 0
    }
}

xbox360_sys::flags! {
    /// Value of `SpecialPurposeRegister::MONITOR_CONTROL`.
    pub struct MonitorControl(u64) {
        FREEZE = 0x2,
        ENABLE = 0x4,
    }
}

impl MonitorControl {
    /// Event bus width field, bits 10 to 15.
    const BUS_WIDTH_SHIFT: u32 = 10;
    const BUS_WIDTH_MASK: u64 = 0x3f;

    /// The control word with event bus width `width`.
    #[inline(always)]
    pub(super) fn with_bus_width(self, width: BusWidth) -> Self {
        Self(
            self.0 & !(Self::BUS_WIDTH_MASK << Self::BUS_WIDTH_SHIFT)
                | u64::from(width.0) << Self::BUS_WIDTH_SHIFT,
        )
    }
}

/// Event bus width field of [`MonitorControl`].
#[derive(Clone, Copy)]
pub(super) struct BusWidth(u8);

impl BusWidth {
    /// Width of a reset.
    pub(super) const RESET: Self = Self(0xa);
}

xbox360_sys::flags! {
    /// High word of `PrvRegister::RUN`; bits 26 and 27 hold the
    /// [`TriggerMode`].
    pub struct RunControl(u32) {
        RUN = 0x8000_0000,
    }
}

impl RunControl {
    const TRIGGER_SHIFT: u32 = 26;

    /// Running in trigger mode `trigger`.
    #[inline(always)]
    pub(super) fn running(trigger: TriggerMode) -> Self {
        Self(Self::RUN.0 | trigger.0 << Self::TRIGGER_SHIFT)
    }
}

/// Trigger mode field of [`RunControl`] (`Setup::trigger`).
#[derive(Clone, Copy)]
pub(super) struct TriggerMode(u32);

impl TriggerMode {
    /// Mode before any setup.
    pub(super) const INITIAL: Self = Self(3);

    /// The mode of setup value `trigger`, of which the field keeps two bits.
    pub(super) fn from_setup(trigger: u32) -> Self {
        Self(trigger & 3)
    }
}

/// The registers the event decoding reads.
pub(super) struct LiveRegisters;

impl pmc::Registers for LiveRegisters {
    fn select(&mut self) -> u64 {
        get_spr(SpecialPurposeRegister::EVENT_SELECT)
    }

    fn bus(&mut self, register: BusRegister) -> u64 {
        get_pmw(PmwRegister(register.0))
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
pub(super) extern "C" fn get_pmw(register: PmwRegister) -> u64 {
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

pub(super) fn set_prv_value(register: PrvRegister, value: u64) {
    // SAFETY: PRV register writes reach only the performance monitor.
    unsafe { KeSetPRVRegister(register, value) };
}

pub(super) fn set_spr_value(register: SpecialPurposeRegister, value: u64) {
    // SAFETY: the callers write only the monitor control and event select
    // registers.
    unsafe { xboxkrnl::KeSetSpecialPurposeRegister(register, value) };
}

#[inline(always)]
pub(super) fn monitor_control() -> MonitorControl {
    MonitorControl::from_bits_retain(get_spr(SpecialPurposeRegister::MONITOR_CONTROL))
}

#[inline(always)]
pub(super) fn set_monitor_control(control: MonitorControl) {
    set_spr_value(SpecialPurposeRegister::MONITOR_CONTROL, control.bits());
}

pub(super) fn set_pmw_value(register: PmwRegister, value: u64) {
    // SAFETY: PMW register writes reach only the event bus selection.
    unsafe { KeSetPMWRegister(register, value) };
}
