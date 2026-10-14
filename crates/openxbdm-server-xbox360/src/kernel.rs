//! Kernel and XAM imports and shared kernel structures.
//!
//! Library indices: 0 `xboxkrnl.exe`, 1 `xam.xex`, 2 `xbdm.xex`. Ordinals are
//! those of the development kernel the module runs on; take each ordinal
//! from the import record stock XBDM uses for the same purpose.

/// Declare an import. Console callees home r3-r10 into the caller frame at
/// sp+0x10..sp+0x50. SysV frames do not reserve that area, so each import is
/// called through a stub that allocates it. Stack-passed arguments are not
/// forwarded, so an import takes at most eight arguments.
macro_rules! import_thunk {
    ($(#[$meta:meta])* $vis:vis $name:ident($($arg:ident: $argty:ty),* $(,)?) -> $ret:ty, lib = $lib:expr, ordinal = $ordinal:expr) => {
        const _: () = assert!(<[&str]>::len(&[$(stringify!($arg)),*]) <= 8);

        $(#[$meta])*
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        $vis extern "C" fn $name($(_: $argty),*) -> $ret {
            core::arch::naked_asm!(
                "stwu 1, -0x50(1)",
                "mflr 0",
                "stw 0, 0x54(1)",
                "bl 2f",
                "lwz 0, 0x54(1)",
                "mtlr 0",
                "addi 1, 1, 0x50",
                "blr",
                ".pushsection .xthunks, \"ax\"",
                ".balign 4",
                "2:",
                ".long {record}",
                ".long 0x60000000",
                ".long 0x60000000",
                ".long 0x4e800020",
                ".popsection",
                record = const (1u32 << 24) | (($lib as u32) << 16) | ($ordinal as u32),
            )
        }
    };
}
pub(crate) use import_thunk;

/// Declare an import that takes nine or ten arguments. SysV passes them on
/// the stack at sp+8 and sp+0xc; the console callee reads them from the
/// 8-byte parameter slots at sp+0x50 and sp+0x58 of its caller frame.
macro_rules! import_thunk_stack {
    ($(#[$meta:meta])* $vis:vis $name:ident($($arg:ident: $argty:ty),* $(,)?) -> $ret:ty, lib = $lib:expr, ordinal = $ordinal:expr) => {
        const _: () = assert!(matches!(<[&str]>::len(&[$(stringify!($arg)),*]), 9 | 10));

        $(#[$meta])*
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        $vis extern "C" fn $name($(_: $argty),*) -> $ret {
            core::arch::naked_asm!(
                "stwu 1, -0x70(1)",
                "mflr 0",
                "stw 0, 0x74(1)",
                "li 12, 0",
                "lwz 11, 0x78(1)",
                "stw 12, 0x50(1)",
                "stw 11, 0x54(1)",
                "lwz 11, 0x7c(1)",
                "stw 12, 0x58(1)",
                "stw 11, 0x5c(1)",
                "bl 2f",
                "lwz 0, 0x74(1)",
                "mtlr 0",
                "addi 1, 1, 0x70",
                "blr",
                ".pushsection .xthunks, \"ax\"",
                ".balign 4",
                "2:",
                ".long {record}",
                ".long 0x60000000",
                ".long 0x60000000",
                ".long 0x4e800020",
                ".popsection",
                record = const (1u32 << 24) | (($lib as u32) << 16) | ($ordinal as u32),
            )
        }
    };
}
pub(crate) use import_thunk_stack;

/// Declare a data import: a slot that the loader replaces with the address
/// of the export. Interior mutability keeps the compiler from folding the
/// initial record value into reads.
macro_rules! import_variable {
    ($(#[$meta:meta])* $vis:vis $name:ident, lib = $lib:expr, ordinal = $ordinal:expr) => {
        $(#[$meta])*
        #[used]
        #[unsafe(link_section = ".xvars")]
        $vis static $name: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new((($lib as u32) << 16) | ($ordinal as u32));
    };
}
pub(crate) use import_variable;

pub const LIB_KERNEL: u32 = 0;
pub const LIB_XAM: u32 = 1;

pub const OBJ_CASE_INSENSITIVE: u32 = 0x40;

import_thunk!(pub XamGetSystemVersion() -> u32, lib = LIB_XAM, ordinal = 0x282);
import_thunk!(pub XexGetModuleHandle(name: *const u8, handle: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 0x195);
import_thunk!(
    pub XexLoadImage(name: *const u8, flags: u32, version: u32, handle: *mut u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x199
);
import_thunk!(
    pub XexGetProcedureAddress(module: u32, ordinal: u32, address: *mut u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x197
);
import_thunk!(pub XexUnloadImage(handle: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x1a1);
import_thunk!(pub RtlNtStatusToDosError(status: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x135);

/// Address of the current thread's last-error field (KTHREAD +0x160), or
/// `None` while a DPC runs (PCR +0x150), as stock 0x91f72ba0/0x91f72b58.
fn last_error_slot() -> Option<*mut u32> {
    let region: usize;
    // SAFETY: reads r13, which the console keeps pointing at the PCR; the
    // compiler reserves r13 under the SVR4 ABI.
    unsafe {
        core::arch::asm!("mr {0}, 13", out(reg) region, options(nomem, nostack, preserves_flags))
    };
    // SAFETY: PCR +0x150 is the DPC-active flag and +0x100 the current
    // thread; both stay valid for the life of the processor.
    unsafe {
        if core::ptr::read_volatile((region + 0x150) as *const u32) != 0 {
            return None;
        }
        let thread = core::ptr::read_volatile((region + 0x100) as *const u32) as usize;
        Some((thread + 0x160) as *mut u32)
    }
}

/// The calling thread's Win32 last-error value; 0 during a DPC.
pub fn last_error() -> u32 {
    // SAFETY: the slot is a field of the current thread object.
    last_error_slot().map_or(0, |slot| unsafe { core::ptr::read_volatile(slot) })
}

/// Record a failure status as the calling thread's last error.
pub fn set_last_error(status: u32) {
    let error = RtlNtStatusToDosError(status);
    if let Some(slot) = last_error_slot() {
        // SAFETY: the slot is a field of the current thread object.
        unsafe { core::ptr::write_volatile(slot, error) };
    }
}

/// Store a Win32 error as the calling thread's last error (stock
/// 0x91f72b30).
pub fn set_last_error_value(error: u32) {
    if let Some(slot) = last_error_slot() {
        // SAFETY: the slot is a field of the current thread object.
        unsafe { core::ptr::write_volatile(slot, error) };
    }
}

/// Status for an export whose address is the module entry point.
pub const STATUS_DRIVER_ENTRYPOINT_NOT_FOUND: u32 = 0xc000_0263;

/// Handle of a loaded module, or the failure status.
pub fn module_handle(name: &core::ffi::CStr) -> Result<u32, u32> {
    let mut handle = 0u32;
    let status = XexGetModuleHandle(name.as_ptr().cast(), &mut handle);
    if (status as i32) < 0 {
        Err(status)
    } else {
        Ok(handle)
    }
}

/// Address of an export by ordinal, or the failure status. As stock
/// 0x91f729d8, an address equal to the module's entry point (handle
/// +0x18) counts as absent.
pub fn resolve_export(module: u32, ordinal: u32) -> Result<u32, u32> {
    let mut address = 0u32;
    let status = XexGetProcedureAddress(module, ordinal, &mut address);
    if (status as i32) < 0 {
        return Err(status);
    }
    // SAFETY: a module handle points at the loader's data table entry.
    let entry = unsafe { core::ptr::read_volatile((module as usize + 0x18) as *const u32) };
    if address == entry {
        Err(STATUS_DRIVER_ENTRYPOINT_NOT_FOUND)
    } else {
        Ok(address)
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
import_thunk!(pub ExAllocatePoolTypeWithTag(size: u32, tag: u32, pool_type: u32) -> u32, lib = LIB_KERNEL, ordinal = 11);
import_thunk!(pub ExFreePool(address: u32) -> u32, lib = LIB_KERNEL, ordinal = 15);
import_thunk!(pub ExAllocatePoolWithTag(size: u32, tag: u32) -> u32, lib = LIB_KERNEL, ordinal = 0xa);
import_thunk!(pub KfAcquireSpinLock(lock: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 0xb1);
import_thunk!(pub KfReleaseSpinLock(lock: *mut u32, irql: u32) -> u32, lib = LIB_KERNEL, ordinal = 0xb4);
import_thunk!(pub KeEnterCriticalRegion() -> u32, lib = LIB_KERNEL, ordinal = 0x5f);
import_thunk!(pub KeLeaveCriticalRegion() -> u32, lib = LIB_KERNEL, ordinal = 0x7d);
import_thunk!(pub RtlInitializeCriticalSection(section: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 0x12e);
import_thunk!(pub RtlEnterCriticalSection(section: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 0x125);
import_thunk!(pub RtlLeaveCriticalSection(section: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 0x130);
import_thunk!(pub RtlTryEnterCriticalSection(section: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 321);
import_thunk!(
    pub ObReferenceObjectByHandle(handle: u32, object_type: u32, object: *mut u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 272
);
import_thunk!(pub ObDereferenceObject(object: u32) -> u32, lib = LIB_KERNEL, ordinal = 261);
import_thunk!(
    pub ObOpenObjectByName(attributes: *const ObjectAttributes, object_type: u32, parse_context: u32, handle: *mut u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x10d
);
import_thunk!(
    pub NtQueryDirectoryObject(handle: u32, buffer: *mut u8, length: u32, restart: u32, context: *mut u32, return_length: *mut u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xe5
);
import_thunk!(
    pub NtCreateDirectoryObject(handle: *mut u32, attributes: *const ObjectAttributes) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xd0
);
import_thunk!(
    pub NtOpenDirectoryObject(handle: *mut u32, attributes: *const ObjectAttributes) -> u32,
    lib = LIB_KERNEL,
    ordinal = 222
);
import_thunk!(
    /// `object_type` is the address of an object type descriptor.
    pub ObCreateObject(object_type: u32, attributes: *const ObjectAttributes, body_size: u32, object: *mut u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x102
);
import_thunk!(
    pub ObInsertObject(object: u32, attributes: *const ObjectAttributes, pointer_bias: u32, handle: *mut u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x108
);
import_thunk!(pub ObMakeTemporaryObject(object: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x10c);
import_thunk!(pub KeInitializeTimerEx(timer: *mut u8, kind: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x75);
import_thunk!(pub KeInitializeDpc(dpc: *mut u8, routine: usize, context: usize) -> u32, lib = LIB_KERNEL, ordinal = 0x6f);
import_thunk!(
    /// The due time is one 64-bit register on the console; callers join the
    /// halves in a naked wrapper.
    pub KeSetTimerEx(timer: *mut u8, due: u32, period: u32, dpc: *mut u8) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xa7
);
import_thunk!(pub KeCancelTimer(timer: *mut u8) -> u32, lib = LIB_KERNEL, ordinal = 0x54);
import_thunk!(pub KeRemoveQueueDpc(dpc: *mut u8) -> u32, lib = LIB_KERNEL, ordinal = 0x8e);
import_thunk!(
    /// `registration` is `{routine, priority, 0, 0}` and must stay valid
    /// while registered.
    pub ExRegisterTitleTerminateNotification(registration: *mut u32, register: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 21
);
import_thunk!(pub KeSetAffinityThread(thread: u32, affinity: u32, previous: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 151);
import_thunk!(
    /// The value is one 64-bit register on the console; 64-bit values need a
    /// naked wrapper that joins the halves.
    pub KeSetSpecialPurposeRegister(register: u32, value: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xa5
);
import_variable!(
    /// Object type of thread objects.
    pub EX_THREAD_OBJECT_TYPE, lib = LIB_KERNEL, ordinal = 27
);
import_thunk!(pub KfRaiseIrql(irql: u32) -> u32, lib = LIB_KERNEL, ordinal = 0xb2);
import_thunk!(pub KfLowerIrql(irql: u32) -> u32, lib = LIB_KERNEL, ordinal = 0xb3);
import_thunk!(pub KeFlushCacheRange(address: u32, length: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x61);
import_thunk!(pub KeInsertQueueDpc(dpc: *mut u8, argument1: u32, argument2: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x7b);
import_thunk!(pub KeStallExecutionProcessor(microseconds: u32) -> u32, lib = LIB_KERNEL, ordinal = 0xa8);
import_thunk!(pub DbgBreakPoint() -> u32, lib = LIB_KERNEL, ordinal = 1);
import_thunk!(pub HalIsExecutingPowerDownDpc() -> u32, lib = LIB_KERNEL, ordinal = 0x267);
import_thunk!(
    /// `registration` is `{routine, priority, 0, 0}` and must stay valid
    /// while registered.
    pub HalRegisterSMCNotification(registration: *mut u32, register: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x27
);
import_thunk!(pub IoAllocateIrp(stack_size: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x2f);
import_thunk!(pub IoCompleteRequest(irp: u32, priority_boost: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x35);
import_thunk!(pub IoStartPacket(device: u32, irp: u32, key: *const u32) -> u32, lib = LIB_KERNEL, ordinal = 0x4a);
import_thunk!(pub IoStartNextPacket(device: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x48);
import_thunk!(
    /// Returns the IRQL `IoReleaseDeviceObjectLock` restores.
    pub IoAcquireDeviceObjectLock() -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x2e
);
import_thunk!(pub IoReleaseDeviceObjectLock(irql: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x44);
import_thunk!(
    pub IoSynchronousDeviceIoControlRequest(
        code: u32,
        device: u32,
        input: *const u8,
        input_length: u32,
        output: *mut u8,
        output_length: u32,
        returned: *mut u32,
        internal: u32,
    ) -> u32,
    lib = LIB_KERNEL,
    ordinal = 75
);
import_thunk!(
    pub ObReferenceObjectByName(name: *const AnsiString, attributes: u32, object_type: u32, parse_context: u32, object: *mut u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 273
);
import_thunk!(
    pub NtQueryVolumeInformationFile(handle: u32, io_status: *mut IoStatusBlock, information: *mut u8, length: u32, class: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 239
);
import_variable!(
    /// The device object type.
    pub IO_DEVICE_OBJECT_TYPE, lib = LIB_KERNEL, ordinal = 58
);
import_thunk!(pub RtlInitializeCriticalSectionAndSpinCount(section: *mut u32, spin_count: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x12f);
import_thunk!(pub KeSetBasePriorityThread(thread: u32, increment: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x99);
import_thunk!(pub XAudioGetRenderDriverThread() -> u32, lib = LIB_KERNEL, ordinal = 0x1fe);
import_variable!(
    /// Kernel time stamp bundle; the dword at +0x10 is the tick count in
    /// milliseconds.
    pub KE_TIME_STAMP_BUNDLE, lib = LIB_KERNEL, ordinal = 0xad
);

/// Milliseconds since boot from the time stamp bundle.
pub fn tick_count() -> u32 {
    let address = KE_TIME_STAMP_BUNDLE.load(core::sync::atomic::Ordering::Relaxed);
    // SAFETY: the loader stored the address of the kernel export.
    unsafe { core::ptr::read_volatile((address as usize + 0x10) as *const u32) }
}

import_thunk!(pub KeSetEvent(event: *mut u32, increment: u32, wait: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x9d);
import_thunk!(pub KeResetEvent(event: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 0x8f);
import_thunk!(
    pub KeWaitForSingleObject(object: *mut u32, reason: u32, mode: u32, alertable: u32, timeout: *const i64) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xb0
);
import_thunk!(
    pub KeWaitForMultipleObjects(
        count: u32,
        objects: *const u32,
        wait_type: u32,
        reason: u32,
        mode: u32,
        alertable: u32,
        timeout: *const i64,
        wait_blocks: *mut u32,
    ) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xaf
);

/// A kernel spin lock around `T`, for state shared with other threads.
pub struct SpinLocked<T> {
    lock: core::cell::UnsafeCell<u32>,
    value: core::cell::UnsafeCell<T>,
}

// SAFETY: every access to `value` holds the spin lock.
unsafe impl<T: Send> Sync for SpinLocked<T> {}

impl<T> SpinLocked<T> {
    pub const fn new(value: T) -> Self {
        Self {
            lock: core::cell::UnsafeCell::new(0),
            value: core::cell::UnsafeCell::new(value),
        }
    }

    pub fn with<R>(&self, operation: impl FnOnce(&mut T) -> R) -> R {
        let irql = KfAcquireSpinLock(self.lock.get());
        // SAFETY: the spin lock is held.
        let result = operation(unsafe { &mut *self.value.get() });
        KfReleaseSpinLock(self.lock.get(), irql);
        result
    }
}

/// A kernel critical section in static storage; waits at passive level.
pub struct CriticalSection(core::cell::UnsafeCell<[u32; 8]>);

// SAFETY: the kernel synchronizes the critical section.
unsafe impl Sync for CriticalSection {}

impl CriticalSection {
    pub const fn new() -> Self {
        Self(core::cell::UnsafeCell::new([0; 8]))
    }

    pub fn pointer(&self) -> *mut u32 {
        self.0.get().cast()
    }

    /// Called once before any thread enters.
    pub fn initialize(&self) {
        RtlInitializeCriticalSection(self.pointer());
    }

    pub fn enter(&self) {
        KeEnterCriticalRegion();
        RtlEnterCriticalSection(self.pointer());
    }

    /// Enters without waiting; returns whether the section is now held.
    pub fn try_enter(&self) -> bool {
        KeEnterCriticalRegion();
        if RtlTryEnterCriticalSection(self.pointer()) != 0 {
            return true;
        }
        KeLeaveCriticalRegion();
        false
    }

    pub fn leave(&self) {
        RtlLeaveCriticalSection(self.pointer());
        KeLeaveCriticalRegion();
    }
}

/// Processor control region, held in r13.
pub fn pcr() -> u32 {
    let value: u32;
    // SAFETY: reads r13.
    unsafe { core::arch::asm!("mr {0}, 13", out(reg) value) };
    value
}

pub fn current_irql() -> u8 {
    // SAFETY: the processor control region is always mapped.
    unsafe { core::ptr::read_volatile((pcr() + 0x18) as usize as *const u8) }
}

/// The current thread object.
pub fn current_thread() -> u32 {
    // SAFETY: the processor control region is always mapped.
    unsafe { core::ptr::read_volatile((pcr() + 0x100) as usize as *const u32) }
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

    pub fn reset(&self) {
        KeResetEvent(self.pointer());
    }

    pub fn set(&self) {
        KeSetEvent(self.pointer(), 1, 0);
    }

    /// Wait without a timeout (executive reason, kernel mode).
    pub fn wait(&self) -> u32 {
        KeWaitForSingleObject(self.pointer(), 0, 0, 0, core::ptr::null())
    }
}

import_thunk!(pub KeGetCurrentProcessType() -> u32, lib = LIB_KERNEL, ordinal = 0x66);
import_thunk!(
    /// Fills eight u16 fields: year, month, day of week, day, hour, minute,
    /// second, millisecond.
    pub GetLocalTime(time: *mut u16) -> u32, lib = LIB_XAM, ordinal = 0x444
);

import_thunk!(
    /// Returns a 64-bit value in r3; call [`performance_frequency`].
    pub KeQueryPerformanceFrequency() -> u32, lib = LIB_KERNEL, ordinal = 0x83
);

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

import_thunk!(pub QueryPerformanceCounter(counter: *mut u64) -> u32, lib = LIB_XAM, ordinal = 0x42f);
import_thunk!(pub QueryPerformanceFrequency(frequency: *mut u64) -> u32, lib = LIB_XAM, ordinal = 0x430);
import_thunk!(pub GetCurrentThreadId() -> u32, lib = LIB_XAM, ordinal = 0x410);

/// Kernel I/O status block.
#[repr(C)]
#[derive(Default)]
pub struct IoStatusBlock {
    pub status: u32,
    pub information: u32,
}

import_thunk_stack!(
    pub NtCreateFile(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatusBlock,
        allocation_size: *const u64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
    ) -> u32,
    lib = LIB_KERNEL,
    ordinal = 210
);
import_thunk!(
    pub NtOpenFile(
        handle: *mut u32,
        access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatusBlock,
        share: u32,
        options: u32,
    ) -> u32,
    lib = LIB_KERNEL,
    ordinal = 223
);
import_thunk!(
    pub NtReadFile(
        handle: u32,
        event: u32,
        apc_routine: u32,
        apc_context: u32,
        io_status: *mut IoStatusBlock,
        buffer: *mut u8,
        length: u32,
        byte_offset: *const u64,
    ) -> u32,
    lib = LIB_KERNEL,
    ordinal = 240
);
import_thunk!(
    pub NtWriteFile(
        handle: u32,
        event: u32,
        apc_routine: u32,
        apc_context: u32,
        io_status: *mut IoStatusBlock,
        buffer: *const u8,
        length: u32,
        byte_offset: *const u64,
    ) -> u32,
    lib = LIB_KERNEL,
    ordinal = 255
);
import_thunk!(
    pub NtSetInformationFile(
        handle: u32,
        io_status: *mut IoStatusBlock,
        information: *const u8,
        length: u32,
        class: u32,
    ) -> u32,
    lib = LIB_KERNEL,
    ordinal = 247
);
import_thunk!(
    pub NtQueryInformationFile(
        handle: u32,
        io_status: *mut IoStatusBlock,
        information: *mut u8,
        length: u32,
        class: u32,
    ) -> u32,
    lib = LIB_KERNEL,
    ordinal = 232
);
import_thunk!(pub NtFlushBuffersFile(handle: u32, io_status: *mut IoStatusBlock) -> u32, lib = LIB_KERNEL, ordinal = 219);
import_thunk!(
    pub NtQueryFullAttributesFile(attributes: *const ObjectAttributes, information: *mut u8) -> u32,
    lib = LIB_KERNEL,
    ordinal = 231
);
import_thunk!(
    pub NtCreateEvent(handle: *mut u32, attributes: *const ObjectAttributes, kind: u32, initial_state: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 209
);
import_thunk!(
    pub NtWaitForSingleObjectEx(handle: u32, mode: u32, alertable: u32, timeout: *const i64) -> u32,
    lib = LIB_KERNEL,
    ordinal = 253
);
import_thunk!(pub NtClearEvent(handle: u32) -> u32, lib = LIB_KERNEL, ordinal = 206);
import_thunk!(pub NtSetEvent(handle: u32, previous_state: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 0xf6);
import_thunk!(
    pub NtWaitForMultipleObjectsEx(count: u32, handles: *const u32, wait_type: u32, mode: u32, alertable: u32, timeout: *const i64) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xfe
);
import_thunk!(pub KeAcquireSpinLockAtRaisedIrql(lock: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 0x4d);
import_thunk!(pub KeReleaseSpinLockFromRaisedIrql(lock: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 0x89);
import_thunk!(pub KeRaiseIrqlToDpcLevel() -> u32, lib = LIB_KERNEL, ordinal = 0x85);
import_thunk!(pub KeTryToAcquireSpinLockAtRaisedIrql(lock: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 0xae);
import_thunk!(
    pub CreateEventA(attributes: u32, manual_reset: u32, initial_state: u32, name: *const u8) -> u32,
    lib = LIB_XAM,
    ordinal = 0x446
);
import_thunk!(pub ResumeThread(thread: u32) -> u32, lib = LIB_XAM, ordinal = 0x43d);
import_thunk!(pub WaitForSingleObject(handle: u32, milliseconds: u32) -> u32, lib = LIB_XAM, ordinal = 0x425);

import_thunk!(
    /// Variadic; callers pass at most the two arguments `%.*s` takes.
    pub DbgPrint(format: *const u8, length: u32, text: *const u8) -> u32, lib = LIB_KERNEL, ordinal = 3
);
import_thunk!(
    /// `arguments` is a console va_list: 8-byte slots, 32-bit values in the
    /// low word.
    pub _vsnprintf(buffer: *mut u8, count: u32, format: u32, arguments: u32) -> i32,
    lib = LIB_KERNEL,
    ordinal = 0x14d
);
import_thunk!(
    pub ExCreateThread(
        handle_out: *mut u32,
        stack_size: u32,
        thread_id_out: *mut u32,
        xapi_thread_startup: u32,
        start_address: u32,
        start_context: u32,
        creation_flags: u32,
    ) -> u32,
    lib = LIB_KERNEL,
    ordinal = 13
);
import_thunk!(pub ExTerminateThread(exit_code: u32) -> u32, lib = LIB_KERNEL, ordinal = 25);
import_thunk!(pub KeDelayExecutionThread(mode: u32, alertable: u32, interval: *const i64) -> u32, lib = LIB_KERNEL, ordinal = 90);
import_thunk!(pub KeQuerySystemTime(time: *mut u64) -> u32, lib = LIB_KERNEL, ordinal = 132);
import_thunk!(pub NtClose(handle: u32) -> u32, lib = LIB_KERNEL, ordinal = 207);
import_thunk!(pub NtDeleteFile(object_attributes: *const ObjectAttributes) -> u32, lib = LIB_KERNEL, ordinal = 216);
import_thunk!(pub KeSweepIcacheRange(address: *mut u8, length: u32) -> u32, lib = LIB_KERNEL, ordinal = 171);
import_thunk!(pub HalReturnToFirmware(routine: u32) -> u32, lib = LIB_KERNEL, ordinal = 40);

/// `HalReturnToFirmware` routine that restarts the system software.
pub const FIRMWARE_REBOOT: u32 = 6;
/// `HalReturnToFirmware` routine that resets through the SMC.
pub const FIRMWARE_SMC_RESET: u32 = 4;
import_thunk!(pub MmIsAddressValid(address: u32) -> u32, lib = LIB_KERNEL, ordinal = 191);
import_thunk!(
    /// Returns the address when the debugger may read it, else null.
    pub MmDbgReadCheck(address: u32) -> u32, lib = LIB_KERNEL, ordinal = 427
);
import_thunk!(pub MmDbgReleaseAddress(address: u32, context: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 428);
import_thunk!(
    /// Maps `address` writable and returns the mapped address, else null.
    pub MmDbgWriteCheck(address: u32, context: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 429
);
import_thunk!(
    pub ExGetXConfigSetting(category: u32, setting: u32, buffer: *mut u8, size: u32, size_out: *mut u16) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x10
);
import_thunk!(
    pub ExSetXConfigSetting(category: u32, setting: u32, buffer: *const u8, size: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x18
);
import_thunk!(pub ExDebugMonitorService(service: u32, a: u32, b: u32, c: u32) -> u32, lib = LIB_KERNEL, ordinal = 0x1aa);
import_thunk!(pub MmQueryStatistics(statistics: *mut u32) -> u32, lib = LIB_KERNEL, ordinal = 0xc6);

/// `ExDebugMonitorService` 0: register the module as the debug monitor.
const DEBUG_MONITOR_REGISTER: u32 = 0;
/// `ExDebugMonitorService` 1: copy the kernel's debug monitor data.
const DEBUG_MONITOR_QUERY: u32 = 1;
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
    if (ExDebugMonitorService(DEBUG_MONITOR_REGISTER, module, 0, 0) as i32) < 0 {
        return false;
    }
    let mut words = [0u32; DEBUG_MONITOR_DATA_WORDS];
    if (ExDebugMonitorService(
        DEBUG_MONITOR_QUERY,
        words.as_mut_ptr() as usize as u32,
        0,
        0,
    ) as i32)
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

import_variable!(
    /// `KeDebugMonitorData`: the kernel reads the debug monitor's copy of
    /// the data block through it.
    pub KE_DEBUG_MONITOR_DATA, lib = LIB_KERNEL, ordinal = 89
);

/// Store the control dispatcher at +0x18 of the data block and publish the
/// block to the kernel, as stock initialization does.
pub fn publish_debug_monitor_dispatcher(dispatcher: u32) {
    DEBUG_MONITOR_DATA[0x18 / 4].store(dispatcher, core::sync::atomic::Ordering::Release);
    let variable = KE_DEBUG_MONITOR_DATA.load(core::sync::atomic::Ordering::Relaxed);
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

import_thunk!(
    pub XMsgStartIORequest(app: u32, message: u32, overlapped: u32, buffer: *mut u8, size: u32) -> u32,
    lib = LIB_XAM,
    ordinal = 0x1f7
);
import_thunk!(pub NetDll_XNetGetTitleXnAddr(caller: u32, address: *mut u8) -> u32, lib = LIB_XAM, ordinal = 0x49);
import_thunk!(pub NetDll_XNetGetDebugXnAddr(caller: u32, address: *mut u8) -> u32, lib = LIB_XAM, ordinal = 0x4a);

import_variable!(
    /// Console hardware flags; the first dword is the flags word.
    pub HARDWARE_INFO, lib = LIB_KERNEL, ordinal = 342
);

/// The first dword of the hardware information export.
pub fn hardware_flags() -> u32 {
    let address = HARDWARE_INFO.load(core::sync::atomic::Ordering::Relaxed);
    // SAFETY: the loader stored the address of the kernel export.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

/// Replace the first dword of the hardware information export (the
/// monitor sets the kernel debugger bit on a break-in).
pub fn set_hardware_flags(flags: u32) {
    let address = HARDWARE_INFO.load(core::sync::atomic::Ordering::Relaxed);
    // SAFETY: the loader stored the address of the writable kernel export.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, flags) }
}

/// The halfword at +0xe of the hardware information export; bit 0x400 is
/// set when the console booted from disc.
pub fn hardware_boot_flags() -> u16 {
    let address = HARDWARE_INFO.load(core::sync::atomic::Ordering::Relaxed);
    // SAFETY: the loader stored the address of the kernel export.
    unsafe { core::ptr::read_volatile((address as usize + 0xe) as *const u16) }
}

import_thunk!(
    pub KeBugCheckEx(code: u32, parameter1: u32, parameter2: u32, parameter3: u32, parameter4: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x53
);
import_thunk!(pub NtSetSystemTime(new_time: *const u64, previous_time: *mut u64) -> u32, lib = LIB_KERNEL, ordinal = 0xf9);
import_thunk!(pub NetDll_XnpNoteSystemTime(caller: u32) -> u32, lib = LIB_XAM, ordinal = 0x7b);

import_thunk!(
    /// Send a 16-byte SMC message and receive the 16-byte reply.
    pub HalSendSMCMessage(message: *const u8, reply: *mut u8) -> u32, lib = LIB_KERNEL, ordinal = 0x29
);
import_variable!(
    /// Version of the running kernel: four u16 (major, minor, build, qfe).
    pub KERNEL_VERSION, lib = LIB_KERNEL, ordinal = 0x158
);
import_variable!(
    /// Version of the base kernel: four u16 (major, minor, build, qfe).
    pub BASE_KERNEL_VERSION, lib = LIB_KERNEL, ordinal = 0x157
);

fn read_version(slot: &core::sync::atomic::AtomicU32) -> [u16; 4] {
    let address = slot.load(core::sync::atomic::Ordering::Relaxed) as usize as *const u16;
    // SAFETY: the loader stored the address of a four-u16 kernel export.
    core::array::from_fn(|index| unsafe { core::ptr::read_volatile(address.add(index)) })
}

/// `XboxKrnlVersion`.
pub fn kernel_version() -> [u16; 4] {
    read_version(&KERNEL_VERSION)
}

/// `XboxKrnlBaseVersion`.
pub fn base_kernel_version() -> [u16; 4] {
    read_version(&BASE_KERNEL_VERSION)
}

/// Counted ANSI string.
#[repr(C)]
pub struct AnsiString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u8,
}

impl AnsiString {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            length: bytes.len() as u16,
            maximum_length: bytes.len() as u16,
            buffer: bytes.as_ptr(),
        }
    }
}

/// Object attributes; the console layout has no length or security fields.
#[repr(C)]
pub struct ObjectAttributes {
    pub root_directory: u32,
    pub object_name: *const AnsiString,
    pub attributes: u32,
}

/// Write a NUL-terminated message to the debug output.
pub fn debug_print(message: &core::ffi::CStr) {
    debug_print_bytes(message.to_bytes());
}

/// Write `text` to the debug output as the argument of `%.*s`, so it is
/// printed literally and the kernel applies the same length limit as to a
/// formatted message.
pub fn debug_print_bytes(text: &[u8]) {
    DbgPrint(c"%.*s".as_ptr().cast(), text.len() as u32, text.as_ptr());
}

/// Read the 64-bit time base.
pub fn timebase() -> u64 {
    let (mut upper, mut lower, mut check): (u32, u32, u32);
    loop {
        // SAFETY: reads time base registers; no memory access.
        unsafe {
            core::arch::asm!("mftbu {0}", "mftb {1}", "mftbu {2}", out(reg) upper, out(reg) lower, out(reg) check);
        }
        if upper == check {
            return (u64::from(upper) << 32) | u64::from(lower);
        }
    }
}

/// System time as a FILETIME.
pub fn system_time() -> u64 {
    let mut time = 0u64;
    KeQuerySystemTime(&mut time);
    time
}

/// Suspend the calling thread.
pub fn sleep_milliseconds(milliseconds: u32) {
    let interval = -(i64::from(milliseconds) * 10_000);
    KeDelayExecutionThread(1, 0, &interval);
}

import_thunk!(
    pub NtAllocateVirtualMemory(base: *mut u32, size: *mut u32, allocation_type: u32, protect: u32, options: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xcc
);
import_thunk!(
    pub NtFreeVirtualMemory(base: *mut u32, size: *mut u32, free_type: u32, options: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xdc
);
import_thunk!(pub MmAllocatePhysicalMemory(kind: u32, size: u32, protect: u32) -> u32, lib = LIB_KERNEL, ordinal = 0xb9);
import_thunk!(
    pub MmAllocatePhysicalMemoryEx(kind: u32, size: u32, protect: u32, lowest: u32, highest: u32, alignment: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xba
);
import_thunk!(pub MmFreePhysicalMemory(kind: u32, address: u32) -> u32, lib = LIB_KERNEL, ordinal = 0xbd);
import_thunk!(
    /// Stock passes `flags` zeroed and treats a nonzero value on return as failure.
    pub XeKeysSaveBootLoader(flags: *mut u32, size: *mut u32, buffer: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x23d
);
import_thunk_stack!(
    pub NtDeviceIoControlFile(
        handle: u32,
        event: u32,
        apc_routine: u32,
        apc_context: u32,
        io_status: *mut IoStatusBlock,
        control_code: u32,
        input: *const u8,
        input_length: u32,
        output: *mut u8,
        output_length: u32,
    ) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0xd9
);
