//! Runtime access to DashLaunch exception-hook state.

use core::num::NonZeroU32;

use xbox360::dashlaunch::LaunchData;

use crate::kernel;

const NO_OPERATION: u32 = 0x6000_0000;

/// Address of the kernel `KiDebugRoutine` pointer resolved by DashLaunch.
pub fn debug_routine_variable() -> Option<NonZeroU32> {
    LaunchData::current()?.debug_routine_variable()
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
    let address = LaunchData::current()?.single_step_patch()?.get();
    let previous = kernel::replace_code_word(address, NO_OPERATION)?;

    Some(SingleStepPatch { address, previous })
}
