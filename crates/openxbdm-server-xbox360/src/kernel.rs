//! Kernel helpers over the `xbox360_sys` imports, and the imports whose
//! signature is specific to the module.

use xbox360::console::KernelVersion;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::ExDebugMonitorService;
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

pub const DEBUG_MONITOR_DATA_WORDS: usize = 0x68 / 4;

static DEBUG_MONITOR_DATA: [core::sync::atomic::AtomicU32; DEBUG_MONITOR_DATA_WORDS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; DEBUG_MONITOR_DATA_WORDS];

/// The 0x68-byte block returned by debug monitor service 1, as big-endian
/// words (word `n` is at byte offset `n * 4`).
#[derive(Clone, Copy)]
pub struct DebugMonitorData {
    pub words: [u32; DEBUG_MONITOR_DATA_WORDS],
}

impl DebugMonitorData {
    /// Head of the loaded module list (+0x04).
    pub fn module_list(&self) -> u32 {
        self.words[1]
    }

    /// Spin lock guarding both module lists (+0x08).
    pub fn loader_lock(&self) -> u32 {
        self.words[2]
    }

    /// Processor count (+0x4c).
    pub fn processor_count(&self) -> u32 {
        self.words[0x13]
    }

    /// Head of the second loaded module list (+0x64); may be null.
    pub fn secondary_module_list(&self) -> u32 {
        self.words[0x19]
    }
}

/// Register `module` as the debug monitor and keep the debug monitor data.
/// Fails when either service fails, as stock module initialization does.
pub fn register_debug_monitor(module: u32) -> bool {
    // SAFETY: service 1 and 2 take scalar arguments or a 0x68-byte buffer.
    if (unsafe { ExDebugMonitorService(DebugMonitorService::Register, module, 0, 0) }.0 as i32) < 0
    {
        return false;
    }
    let mut words = [0u32; DEBUG_MONITOR_DATA_WORDS];
    // SAFETY: `words` is a live 0x68-byte buffer.
    if (unsafe {
        ExDebugMonitorService(
            DebugMonitorService::Query,
            words.as_mut_ptr() as usize as u32,
            0,
            0,
        )
    }
    .0 as i32)
        < 0
    {
        return false;
    }
    for (slot, word) in DEBUG_MONITOR_DATA.iter().zip(words) {
        slot.store(word, core::sync::atomic::Ordering::Relaxed);
    }
    true
}

/// Debug monitor data stored by [`register_debug_monitor`].
pub fn debug_monitor_data() -> DebugMonitorData {
    DebugMonitorData {
        words: core::array::from_fn(|index| {
            DEBUG_MONITOR_DATA[index].load(core::sync::atomic::Ordering::Relaxed)
        }),
    }
}

/// Store the control dispatcher at +0x18 of the data block and publish the
/// block to the kernel, as stock initialization does.
pub fn publish_debug_monitor_dispatcher(dispatcher: u32) {
    DEBUG_MONITOR_DATA[0x18 / 4].store(dispatcher, core::sync::atomic::Ordering::Release);
    let variable = KeDebugMonitorData.address();
    // SAFETY: the loader stored the address of the kernel export; the block
    // is a static that lives as long as the module.
    unsafe {
        core::ptr::write_volatile(
            variable as usize as *mut u32,
            DEBUG_MONITOR_DATA.as_ptr() as usize as u32,
        )
    };
}

/// Store a monitor-owned field of the published data block at byte
/// `offset`.
pub fn set_debug_monitor_word(offset: usize, value: u32) {
    DEBUG_MONITOR_DATA[offset / 4].store(value, core::sync::atomic::Ordering::Release);
}

/// Replace the first dword of the hardware information export (the
/// monitor sets the kernel debugger bit on a break-in).
pub fn set_hardware_flags(flags: u32) {
    let address = XboxHardwareInfo.address();
    // SAFETY: the loader stored the address of the writable kernel export.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, flags) }
}

/// The halfword at +0xe of the hardware information export; bit 0x400 is
/// set when the console booted from disc.
pub fn hardware_boot_flags() -> u16 {
    let address = XboxHardwareInfo.address();
    // SAFETY: the loader stored the address of the kernel export.
    unsafe { core::ptr::read_volatile((address as usize + 0xe) as *const u16) }
}

/// The version parts in export order.
pub const fn version_words(version: KernelVersion) -> [u16; 4] {
    [version.major, version.minor, version.build, version.qfe]
}

/// `XboxKrnlBaseVersion`, read unconditionally as stock does.
pub fn base_kernel_version() -> KernelVersion {
    let address = XboxKrnlBaseVersion.address() as usize as *const u16;
    // SAFETY: the loader stored the address of a four-u16 kernel export.
    let part = |index| unsafe { core::ptr::read_volatile(address.add(index)) };
    KernelVersion {
        major: part(0),
        minor: part(1),
        build: part(2),
        qfe: part(3),
    }
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
