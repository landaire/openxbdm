//! Runtime access to DashLaunch exception-hook state.

use core::num::NonZeroU32;

use xbox360::module::Ordinal;
use xbox360::module::module_handle;
use xbox360::module::resolve_export;

use crate::kernel;

mod offset {
    pub const ID: u32 = 0x00;
    pub const TARGET_KERNEL: u32 = 0x214;
    pub const DEBUG_ROUTINE: u32 = 0x21c;
    pub const DEBUG_STEP_PATCH: u32 = 0x220;
}

const LAUNCH_DATA_ID: u32 = u32::from_be_bytes(*b"DL30");
const NO_OPERATION: u32 = 0x6000_0000;
const LAUNCH_DATA: Ordinal = match Ordinal::new(1) {
    Some(ordinal) => ordinal,
    None => panic!("ordinal 0"),
};

fn read_u32(address: u32) -> u32 {
    // SAFETY: callers pass fields of `ldata`, which DashLaunch keeps mapped.
    unsafe { core::ptr::with_exposed_provenance::<u32>(address as usize).read_volatile() }
}

fn read_u16(address: u32) -> u16 {
    // SAFETY: callers pass fields of `ldata`, which DashLaunch keeps mapped.
    unsafe { core::ptr::with_exposed_provenance::<u16>(address as usize).read_volatile() }
}

/// Resolve `launch.xex` export 1 after validating its layout and target kernel.
fn launch_data() -> Option<u32> {
    // SAFETY: DashLaunch keeps `launch.xex` loaded while this plugin runs.
    let module = unsafe { module_handle(c"launch.xex") }.ok()?;
    let address = resolve_export(module, LAUNCH_DATA).ok()?.raw();

    (read_u32(address + offset::ID) == LAUNCH_DATA_ID
        && read_u16(address + offset::TARGET_KERNEL) == xbox360::console::kernel_version().build)
        .then_some(address)
}

/// Address of the kernel `KiDebugRoutine` pointer resolved by DashLaunch.
pub fn debug_routine_variable() -> Option<NonZeroU32> {
    NonZeroU32::new(read_u32(launch_data()? + offset::DEBUG_ROUTINE))
}

/// An instruction replaced to enable single-step exceptions.
pub struct SingleStepPatch {
    address: u32,
    previous: u32,
}

impl SingleStepPatch {
    /// Restore the kernel instruction replaced by [`enable_single_step`].
    pub fn restore(self) {
        kernel::write_code_word(self.address, self.previous);
    }
}

/// Enable single-step exceptions through DashLaunch's kernel-build-specific patch address.
pub fn enable_single_step() -> Option<SingleStepPatch> {
    let data = launch_data()?;
    let address = NonZeroU32::new(read_u32(data + offset::DEBUG_STEP_PATCH))?.get();
    let previous = kernel::replace_code_word(address, NO_OPERATION)?;

    Some(SingleStepPatch { address, previous })
}
