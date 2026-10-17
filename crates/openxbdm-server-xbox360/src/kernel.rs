//! Kernel helpers over the `xbox360_sys` imports, and the imports whose
//! signature is specific to the module.

use core::sync::atomic::Ordering;

use xbox360::console::KernelVersion;
use xbox360_sys::ImportedVariable;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::DebugMonitorData;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::ExDebugMonitorService;
use xbox360_sys::xboxkrnl::HardwareInfo;
use xbox360_sys::xboxkrnl::KeDebugMonitorData;
use xbox360_sys::xboxkrnl::KeEnterCriticalRegion;
use xbox360_sys::xboxkrnl::KeLeaveCriticalRegion;
use xbox360_sys::xboxkrnl::KeQueryPerformanceFrequency;
use xbox360_sys::xboxkrnl::KeResetEvent;
use xbox360_sys::xboxkrnl::KeSetEvent;
use xbox360_sys::xboxkrnl::KeWaitForSingleObject;
use xbox360_sys::xboxkrnl::Kevent;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::RtlCriticalSection;
use xbox360_sys::xboxkrnl::RtlEnterCriticalSection;
use xbox360_sys::xboxkrnl::RtlInitializeCriticalSection;
use xbox360_sys::xboxkrnl::RtlLeaveCriticalSection;
use xbox360_sys::xboxkrnl::RtlTryEnterCriticalSection;
use xbox360_sys::xboxkrnl::WaitReason;
use xbox360_sys::xboxkrnl::XboxHardwareInfo;
use xbox360_sys::xboxkrnl::XboxKrnlBaseVersion;

/// A counted string over `bytes`. The length is truncated to 16 bits; the
/// names and paths the module passes are far shorter.
pub const fn ansi_string(bytes: &[u8]) -> AnsiString {
    AnsiString {
        length: bytes.len() as u16,
        maximum_length: bytes.len() as u16,
        buffer: bytes.as_ptr(),
    }
}

/// Call a resolved export with up to four arguments through a frame that
/// reserves the console home area, as the import thunks do.
///
/// # Safety
/// `function` must be the address of a console function taking at most
/// four register arguments.
#[unsafe(naked)]
pub unsafe extern "C" fn call_export(function: u32, a0: u32, a1: u32, a2: u32, a3: u32) -> u32 {
    core::arch::naked_asm!(
        "stwu 1, -0x50(1)",
        "mflr 0",
        "stw 0, 0x54(1)",
        "mtctr 3",
        "mr 3, 4",
        "mr 4, 5",
        "mr 5, 6",
        "mr 6, 7",
        "bctrl",
        "lwz 0, 0x54(1)",
        "mtlr 0",
        "addi 1, 1, 0x50",
        "blr",
    )
}

/// [`call_export`] for console functions taking up to seven register
/// arguments; unused arguments may be passed as zero.
///
/// # Safety
/// `function` must be the address of a console function taking at most
/// seven register arguments.
#[unsafe(naked)]
pub unsafe extern "C" fn call_console(
    function: u32,
    a0: u32,
    a1: u32,
    a2: u32,
    a3: u32,
    a4: u32,
    a5: u32,
    a6: u32,
) -> u32 {
    core::arch::naked_asm!(
        "stwu 1, -0x50(1)",
        "mflr 0",
        "stw 0, 0x54(1)",
        "mtctr 3",
        "mr 3, 4",
        "mr 4, 5",
        "mr 5, 6",
        "mr 6, 7",
        "mr 7, 8",
        "mr 8, 9",
        "mr 9, 10",
        "bctrl",
        "lwz 0, 0x54(1)",
        "mtlr 0",
        "addi 1, 1, 0x50",
        "blr",
    )
}

/// A kernel critical section in static storage; waits at passive level.
pub struct CriticalSection(core::cell::UnsafeCell<[u32; 8]>);

// SAFETY: the kernel synchronizes the critical section.
unsafe impl Sync for CriticalSection {}

impl CriticalSection {
    pub const fn new() -> Self {
        Self(core::cell::UnsafeCell::new([0; 8]))
    }

    pub fn pointer(&self) -> *mut RtlCriticalSection {
        self.0.get().cast()
    }

    /// Called once before any thread enters.
    pub fn initialize(&self) {
        // SAFETY: the storage is a static critical section of 0x20 bytes.
        unsafe { RtlInitializeCriticalSection(self.pointer()) };
    }

    pub fn enter(&self) {
        // SAFETY: the section was initialized by `initialize`; `leave`
        // undoes the critical region.
        unsafe {
            KeEnterCriticalRegion();
            RtlEnterCriticalSection(self.pointer());
        }
    }

    /// Enters without waiting; returns whether the section is now held.
    pub fn try_enter(&self) -> bool {
        // SAFETY: the section was initialized by `initialize`; the critical
        // region is left here on failure and by `leave` on success.
        unsafe {
            KeEnterCriticalRegion();
            if RtlTryEnterCriticalSection(self.pointer()).get() {
                return true;
            }
            KeLeaveCriticalRegion();
        }
        false
    }

    pub fn leave(&self) {
        // SAFETY: the calling thread holds the section and the critical
        // region entered with it.
        unsafe {
            RtlLeaveCriticalSection(self.pointer());
            KeLeaveCriticalRegion();
        }
    }
}

/// A kernel synchronization event in static storage.
pub struct KernelEvent(core::cell::UnsafeCell<[u32; 4]>);

// SAFETY: the kernel synchronizes access to dispatcher objects.
unsafe impl Sync for KernelEvent {}

impl KernelEvent {
    pub const fn new() -> Self {
        Self(core::cell::UnsafeCell::new([0; 4]))
    }

    pub fn pointer(&self) -> *mut u32 {
        self.0.get().cast()
    }

    /// Initialize as an unsignaled synchronization event; the wait list
    /// head at +8 points at itself.
    pub fn initialize(&self) {
        let list = self.pointer().wrapping_add(2) as usize as u32;
        // SAFETY: called before any waiter or signaler uses the event.
        unsafe { *self.0.get() = [0x0100_0000, 0, list, list] };
    }

    /// Initialize as a notification event, signaled or not.
    pub fn initialize_notification(&self, signaled: bool) {
        let list = self.pointer().wrapping_add(2) as usize as u32;
        // SAFETY: called before any waiter or signaler uses the event.
        unsafe { *self.0.get() = [0, u32::from(signaled), list, list] };
    }

    fn object(&self) -> *mut Kevent {
        self.0.get().cast()
    }

    pub fn reset(&self) {
        // SAFETY: the storage holds an initialized event.
        unsafe { KeResetEvent(self.object()) };
    }

    pub fn set(&self) {
        // SAFETY: the storage holds an initialized event.
        unsafe { KeSetEvent(self.object(), 1, false) };
    }

    /// Wait without a timeout (executive reason, kernel mode).
    pub fn wait(&self) -> u32 {
        // SAFETY: the storage holds an initialized event.
        let status = unsafe {
            KeWaitForSingleObject(
                self.object().cast(),
                WaitReason::Executive,
                ProcessorMode::Kernel,
                false,
                core::ptr::null(),
            )
        };
        status.0
    }
}

/// `KeQueryPerformanceFrequency`. The console returns the quadword in one
/// 64-bit register; this splits it into the r3:r4 pair the 32-bit ABI
/// expects. The CPU model of the target has no 64-bit mnemonics, so the
/// shift is encoded directly.
#[unsafe(naked)]
pub extern "C" fn performance_frequency() -> u64 {
    core::arch::naked_asm!(
        "stwu 1, -0x20(1)",
        "mflr 0",
        "stw 0, 0x24(1)",
        "bl {query}",
        "mr 4, 3",
        // rldicl 3, 3, 32, 32: the high word into the low half of r3.
        ".long 0x78630022",
        "lwz 0, 0x24(1)",
        "mtlr 0",
        "addi 1, 1, 0x20",
        "blr",
        query = sym KeQueryPerformanceFrequency,
    )
}

xbox360_sys::import_thunk!(
    /// Variadic; callers pass at most the two arguments `%.*s` takes.
    #[allow(non_snake_case)]
    pub DbgPrint(format: *const u8, length: u32, text: *const u8) -> u32,
    lib = xbox360_sys::lib_index::XBOXKRNL,
    ordinal = 3
);

/// Define `$name` as a branch to `$target`: the arguments reach it in
/// r3-r10 unchanged and its r3 comes back unchanged. Stock passes some
/// values that the typed imports do not model (the r3 of a VOID call, a raw
/// user number, a stale register), and a forward keeps them exact. The
/// forward is `unsafe` with the contract of `$target`.
macro_rules! forward {
    ($(#[$meta:meta])* $vis:vis fn $name:ident($($argty:ty),* $(,)?) -> $ret:ty => $target:path) => {
        $(#[$meta])*
        #[unsafe(naked)]
        $vis unsafe extern "C" fn $name($(_: $argty),*) -> $ret {
            core::arch::naked_asm!("b {target}", target = sym $target)
        }
    };
}
pub(crate) use forward;

static DEBUG_MONITOR_DATA: DebugMonitorData = DebugMonitorData::new();

/// Register `module` as the debug monitor and keep the debug monitor data.
/// Fails when either service fails, as stock module initialization does.
pub fn register_debug_monitor(module: u32) -> bool {
    // SAFETY: service 1 and 2 take scalar arguments or a 0x68-byte buffer.
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
pub fn publish_debug_monitor_dispatcher(dispatcher: u32) {
    // SAFETY: the dispatcher is the module's control routine entry, which
    // the kernel may call once the block is published.
    unsafe {
        DEBUG_MONITOR_DATA
            .control_routine
            .store(dispatcher, Ordering::Release)
    };
    let block = core::ptr::from_ref(&DEBUG_MONITOR_DATA).expose_provenance() as u32;
    // SAFETY: the block is a static that lives as long as the module, and
    // its routine fields hold the kernel's values or this module's entries.
    unsafe { resolved(&KeDebugMonitorData).store(block, Ordering::Relaxed) };
}

/// The export of a data import. Stock uses its data imports without a
/// check; a slot that the loader left unresolved stops the module.
pub fn resolved<T: Sync>(variable: &ImportedVariable<T>) -> &'static T {
    match variable.get() {
        Some(export) => export,
        None => unresolved_import(),
    }
}

/// One shared copy keeps the stop out of every caller.
#[cold]
#[inline(never)]
fn unresolved_import() -> ! {
    panic!("unresolved data import")
}

/// The debug monitor data block that the kernel reads, if one is
/// published.
pub fn published_debug_monitor_data() -> Option<&'static DebugMonitorData> {
    let block = resolved(&KeDebugMonitorData).load(Ordering::Relaxed);
    // SAFETY: a nonzero value is the address of a published debug monitor
    // block, which stays mapped while its module runs.
    (block != 0).then(|| unsafe {
        &*core::ptr::with_exposed_provenance::<DebugMonitorData>(block as usize)
    })
}

/// The hardware information export.
pub fn hardware_info() -> &'static HardwareInfo {
    resolved(&XboxHardwareInfo)
}

/// The version parts in export order.
pub const fn version_words(version: KernelVersion) -> [u16; 4] {
    [version.major, version.minor, version.build, version.qfe]
}

/// `XboxKrnlBaseVersion`, which stock reads without a check.
pub fn base_kernel_version() -> KernelVersion {
    *resolved(&XboxKrnlBaseVersion)
}

/// Write a NUL-terminated message to the debug output.
pub fn debug_print(message: &core::ffi::CStr) {
    // SAFETY: the format and `message` are NUL-terminated.
    unsafe {
        DbgPrint(
            c"%s".as_ptr().cast(),
            message.as_ptr() as u32,
            core::ptr::null(),
        )
    };
}

/// Write `text` to the debug output as the argument of `%.*s`, so it is
/// printed literally and the kernel applies the same length limit as to a
/// formatted message.
pub fn debug_print_bytes(text: &[u8]) {
    // SAFETY: `text` is valid for its length, which `%.*s` bounds.
    unsafe { DbgPrint(c"%.*s".as_ptr().cast(), text.len() as u32, text.as_ptr()) };
}
