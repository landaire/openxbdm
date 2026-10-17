//! The debug monitor data block and the data imports the module reads.

use core::sync::atomic::Ordering;

use xbox360::console::KernelVersion;
use xbox360_sys::xboxkrnl::DebugMonitorData;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::ExDebugMonitorService;
use xbox360_sys::xboxkrnl::ExLoadedImageName;
use xbox360_sys::xboxkrnl::ExThreadObjectType;
use xbox360_sys::xboxkrnl::HardwareInfo;
use xbox360_sys::xboxkrnl::IoDeviceObjectType;
use xbox360_sys::xboxkrnl::KeDebugMonitorData;
use xbox360_sys::xboxkrnl::KeTimeStampBundle;
use xbox360_sys::xboxkrnl::KernelU32;
use xbox360_sys::xboxkrnl::XboxHardwareInfo;
use xbox360_sys::xboxkrnl::XboxKrnlBaseVersion;
use xbox360_sys::xboxkrnl::XexExecutableModuleHandle;

static DEBUG_MONITOR_DATA: DebugMonitorData = DebugMonitorData::new();

/// A kernel routine variable whose address the query service stores in
/// the debug monitor data.
#[derive(Clone, Copy)]
pub enum RoutineVariable {
    /// `KiDebugRoutine`.
    Debug,
    /// `KiStackOverflowNotification`.
    StackOverflow,
    /// `KiContextSwapNotification`, called on each thread switch.
    ContextSwap,
    /// The kernel callback routine variable.
    Callback,
}

/// Register `module` as the debug monitor and keep the debug monitor data.
/// Fails when either service fails, as stock module initialization does.
pub fn register_debug_monitor(module: u32) -> bool {
    // SAFETY: the register service takes the module handle as a scalar.
    if !unsafe { ExDebugMonitorService(DebugMonitorService::Register, module, 0, 0) }.is_success() {
        return false;
    }

    // SAFETY: the service fills the 0x68-byte block, whose fields are
    // atomics, before any other thread reads it.
    unsafe {
        ExDebugMonitorService(
            DebugMonitorService::Query,
            core::ptr::from_ref(&DEBUG_MONITOR_DATA).expose_provenance() as u32,
            0,
            0,
        )
    }
    .is_success()
}

/// Debug monitor data stored by [`register_debug_monitor`].
pub fn debug_monitor_data() -> &'static DebugMonitorData {
    &DEBUG_MONITOR_DATA
}

/// Store the control dispatcher in the data block and publish the block to
/// the kernel, as stock initialization does.
///
/// # Safety
///
/// `dispatcher` must be the address of a routine in the console ABI that
/// takes a debug monitor control code and its argument and returns a word,
/// and it must stay loaded while the block is published. The kernel calls
/// it from any thread once the block is published.
pub unsafe fn publish_debug_monitor_dispatcher(dispatcher: u32) {
    // SAFETY: the caller guarantees the routine the kernel calls.
    unsafe {
        DEBUG_MONITOR_DATA
            .control_routine
            .store(dispatcher, Ordering::Release)
    };

    let block = core::ptr::from_ref(&DEBUG_MONITOR_DATA).expose_provenance() as u32;
    // SAFETY: `data_imports_resolved` held at module load. The block is a
    // static that lives as long as the module, and its routine fields hold
    // the kernel's values or this module's entries.
    unsafe {
        KeDebugMonitorData
            .get_unchecked()
            .store(block, Ordering::Relaxed)
    };
}

/// Whether the loader resolved every data import that the module reads
/// with `get_unchecked`. Module load checks it once, before other module
/// code runs, and fails when it does not hold; stock reads its data
/// imports without a check. Each `get_unchecked` read in the module names
/// an import of this list.
pub fn data_imports_resolved() -> bool {
    KeDebugMonitorData.get().is_some()
        && XboxHardwareInfo.get().is_some()
        && XboxKrnlBaseVersion.get().is_some()
        && ExLoadedImageName.get().is_some()
        && ExThreadObjectType.get().is_some()
        && IoDeviceObjectType.get().is_some()
        && KeTimeStampBundle.get().is_some()
        && XexExecutableModuleHandle.get().is_some()
}

/// The debug monitor data block that the kernel reads, if one is
/// published.
pub fn published_debug_monitor_data() -> Option<&'static DebugMonitorData> {
    // SAFETY: `data_imports_resolved` held at module load.
    let block = unsafe { KeDebugMonitorData.get_unchecked() }.load(Ordering::Relaxed);

    // SAFETY: a nonzero value is the address of a published debug monitor
    // block, which stays mapped while its module runs.
    (block != 0).then(|| unsafe {
        &*core::ptr::with_exposed_provenance::<DebugMonitorData>(block as usize)
    })
}

/// The hardware information export.
pub fn hardware_info() -> &'static HardwareInfo {
    // SAFETY: `data_imports_resolved` held at module load.
    unsafe { XboxHardwareInfo.get_unchecked() }
}

/// The version parts in export order.
pub const fn version_words(version: KernelVersion) -> [u16; 4] {
    [version.major, version.minor, version.build, version.qfe]
}

/// `XboxKrnlBaseVersion`, which stock reads without a check.
pub fn base_kernel_version() -> KernelVersion {
    // SAFETY: `data_imports_resolved` held at module load.
    *unsafe { XboxKrnlBaseVersion.get_unchecked() }
}

/// The kernel variable `variable`, once the query service published its
/// address.
pub fn routine_variable(variable: RoutineVariable) -> Option<&'static KernelU32> {
    let data = debug_monitor_data();
    let address = match variable {
        RoutineVariable::Debug => &data.debug_routine,
        RoutineVariable::StackOverflow => &data.stack_overflow_notification,
        RoutineVariable::ContextSwap => &data.context_swap_notification,
        RoutineVariable::Callback => &data.callback_routine,
    }
    .load(Ordering::Relaxed);

    // SAFETY: the query service stores the address of the kernel's
    // word-aligned variable, which lives as long as the kernel, or leaves
    // 0.
    unsafe { core::ptr::with_exposed_provenance::<KernelU32>(address as usize).as_ref() }
}
