//! Kernel helpers over the `xbox360_sys` imports, and the imports whose
//! signature is specific to the module.

use core::marker::PhantomData;
use core::num::NonZeroU32;
use core::sync::atomic::Ordering;

use xbox360::console::KernelVersion;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::DebugMonitorData;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::EVENT_INCREMENT;
use xbox360_sys::xboxkrnl::EventType;
use xbox360_sys::xboxkrnl::ExDebugMonitorService;
use xbox360_sys::xboxkrnl::ExLoadedImageName;
use xbox360_sys::xboxkrnl::ExThreadObjectType;
use xbox360_sys::xboxkrnl::HardwareInfo;
use xbox360_sys::xboxkrnl::IoDeviceObjectType;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeDebugMonitorData;
use xbox360_sys::xboxkrnl::KeEnterCriticalRegion;
use xbox360_sys::xboxkrnl::KeLeaveCriticalRegion;
use xbox360_sys::xboxkrnl::KeQueryPerformanceFrequency;
use xbox360_sys::xboxkrnl::KeResetEvent;
use xbox360_sys::xboxkrnl::KeSetEvent;
use xbox360_sys::xboxkrnl::KeTimeStampBundle;
use xbox360_sys::xboxkrnl::KeWaitForSingleObject;
use xbox360_sys::xboxkrnl::KernelU32;
use xbox360_sys::xboxkrnl::Kevent;
use xbox360_sys::xboxkrnl::KfAcquireSpinLock;
use xbox360_sys::xboxkrnl::KfReleaseSpinLock;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::Kthread;
use xbox360_sys::xboxkrnl::LdrDataTableEntry;
use xbox360_sys::xboxkrnl::ListEntry;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::RtlCriticalSection;
use xbox360_sys::xboxkrnl::RtlEnterCriticalSection;
use xbox360_sys::xboxkrnl::RtlInitializeCriticalSection;
use xbox360_sys::xboxkrnl::RtlLeaveCriticalSection;
use xbox360_sys::xboxkrnl::RtlTryEnterCriticalSection;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;
use xbox360_sys::xboxkrnl::XboxHardwareInfo;
use xbox360_sys::xboxkrnl::XboxKrnlBaseVersion;
use xbox360_sys::xboxkrnl::XexExecutableModuleHandle;

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

/// A kernel event in static storage.
pub struct KernelEvent(core::cell::UnsafeCell<[u32; 4]>);

// SAFETY: the kernel synchronizes access to dispatcher objects.
unsafe impl Sync for KernelEvent {}

impl KernelEvent {
    pub const fn new() -> Self {
        Self(core::cell::UnsafeCell::new([0; 4]))
    }

    /// The `KEVENT` for kernel calls that take one.
    pub fn pointer(&self) -> *mut Kevent {
        self.0.get().cast()
    }

    /// Write the dispatcher header: the type in the first byte, the signal
    /// state, and a wait list head at +8 that points at itself.
    #[inline(always)]
    fn initialize_header(&self, kind: EventType, signaled: bool) {
        let list = self.0.get().cast::<u32>().wrapping_add(2) as usize as u32;
        // SAFETY: called before any waiter or signaler uses the event.
        unsafe { *self.0.get() = [kind.raw() << 24, u32::from(signaled), list, list] };
    }

    /// Initialize as an unsignaled synchronization event.
    pub fn initialize(&self) {
        self.initialize_header(EventType::Synchronization, false);
    }

    /// Initialize as a notification event, signaled or not.
    pub fn initialize_notification(&self, signaled: bool) {
        self.initialize_header(EventType::Notification, signaled);
    }

    pub fn reset(&self) {
        // SAFETY: the storage holds an initialized event.
        unsafe { KeResetEvent(self.pointer()) };
    }

    pub fn set(&self) {
        // SAFETY: the storage holds an initialized event.
        unsafe { KeSetEvent(self.pointer(), EVENT_INCREMENT, false) };
    }

    /// Wait without a timeout (executive reason, kernel mode). A wait
    /// without a timeout or alert ends only when the event is signaled.
    pub fn wait(&self) {
        // SAFETY: the storage holds an initialized event.
        unsafe {
            KeWaitForSingleObject(
                self.pointer().cast(),
                WaitReason::Executive,
                ProcessorMode::Kernel,
                false,
                core::ptr::null(),
            )
        };
    }
}

/// `ExCreateThread` flags that stock gives each of its system threads: the
/// system process, a thread object result, hardware thread 2, priority
/// class 13, and bit 0x4, which the kernel does not test. Each thread adds
/// whether the monitor may stop or debug it.
pub const SYSTEM_THREAD_FLAGS: ThreadCreationFlags = ThreadCreationFlags::SYSTEM_PROCESS
    .union(ThreadCreationFlags::RETURN_THREAD_OBJECT)
    .union(ThreadCreationFlags::PROCESSOR2)
    .union(ThreadCreationFlags::PRIORITY_CLASS_13)
    .union(ThreadCreationFlags::from_bits_retain(0x4));

/// Pool tags shared by several services.
pub mod pool_tag {
    use xbox360_sys::xboxkrnl::PoolTag;

    /// Monitor allocations of the generic pool exports and of copies made
    /// for callers.
    pub const MONITOR: PoolTag = PoolTag::new(*b"xbdm");
    /// Settings text, debug capture buffers and flash images.
    pub const BUFFER: PoolTag = PoolTag::new(*b"mdbX");
    /// Detour log records and lockfree containers.
    pub const DETOUR: PoolTag = PoolTag::new(*b"Detr");
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

/// The address of `value`, as kernel calls and caller-visible words take
/// it. The provenance is exposed so that [`object_at`] can return to it.
#[inline(always)]
pub fn address_of<T: ?Sized>(value: &T) -> u32 {
    core::ptr::from_ref(value).cast::<u8>().expose_provenance() as u32
}

/// The `T` at `address`.
///
/// # Safety
///
/// `address` must hold an initialized, aligned `T` that stays allocated
/// and is not written through another path except by interior mutability
/// for `'a`.
#[inline(always)]
pub unsafe fn object_at<'a, T>(address: u32) -> &'a T {
    // SAFETY: the caller guarantees the object for `'a`.
    unsafe { &*core::ptr::with_exposed_provenance::<T>(address as usize) }
}

/// The `T` at `address`, for writing.
///
/// # Safety
///
/// As [`object_at`], and no other reference to the object is used for
/// `'a`.
#[inline(always)]
pub unsafe fn object_at_mut<'a, T>(address: u32) -> &'a mut T {
    // SAFETY: the caller guarantees exclusive access for `'a`.
    unsafe { &mut *core::ptr::with_exposed_provenance_mut::<T>(address as usize) }
}

/// The thread object at `address`.
///
/// # Safety
///
/// `address` must be a thread object that stays allocated for `'a`.
#[inline(always)]
pub unsafe fn thread_at<'a>(address: u32) -> &'a Kthread {
    // SAFETY: the caller guarantees the object for `'a`.
    unsafe { xbox360::thread::ThreadObject::from_raw(address) }.kthread()
}

/// Bytes before the NUL of the string at `address`; none for 0.
///
/// # Safety
///
/// `address` must be 0 or the address of a NUL-terminated string that
/// stays unchanged for `'a`.
pub unsafe fn c_string<'a>(address: u32) -> Option<&'a [u8]> {
    let start = core::ptr::with_exposed_provenance::<core::ffi::c_char>(address as usize);
    // SAFETY: guaranteed by the caller.
    (!start.is_null()).then(|| unsafe { core::ffi::CStr::from_ptr(start) }.to_bytes())
}

/// Bytes before the NUL of the string at `address`, at most `limit`; none
/// for 0.
///
/// # Safety
///
/// `address` must be 0, or readable up to its NUL or `limit` bytes,
/// whichever comes first, and the bytes must stay unchanged for `'a`.
#[inline(never)]
pub unsafe fn bounded_c_string<'a>(address: u32, limit: usize) -> Option<&'a [u8]> {
    let start = core::ptr::with_exposed_provenance::<u8>(address as usize);
    if start.is_null() {
        return None;
    }
    let mut length = 0;
    // SAFETY: the caller guarantees the bytes up to the NUL or the limit.
    while length < limit && unsafe { start.add(length).read() } != 0 {
        length += 1;
    }
    // SAFETY: the `length` bytes were just read.
    Some(unsafe { core::slice::from_raw_parts(start, length) })
}

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

/// A loader module list of the debug monitor data.
#[derive(Clone, Copy)]
pub enum ModuleList {
    Loaded,
    Usermode,
}

impl ModuleList {
    /// The list head, if the kernel has the list.
    fn head(self) -> Option<NonZeroU32> {
        let data = debug_monitor_data();
        NonZeroU32::new(
            match self {
                ModuleList::Loaded => &data.loaded_module_list,
                ModuleList::Usermode => &data.loaded_usermode_module_list,
            }
            .load(Ordering::Relaxed),
        )
    }
}

/// Holds the kernel loader spin lock, which guards both module lists, for
/// its lifetime.
pub struct LoaderLock {
    lock: *mut KspinLock,
    irql: Irql,
}

impl LoaderLock {
    /// Inlined: two loads and the import call cost less than a call.
    #[inline(always)]
    pub fn acquire() -> Self {
        let lock = core::ptr::with_exposed_provenance_mut::<KspinLock>(
            debug_monitor_data()
                .loaded_module_list_lock
                .load(Ordering::Relaxed) as usize,
        );
        // SAFETY: the debug monitor data holds the address of the kernel
        // loader spin lock; Drop releases it at the returned IRQL.
        let irql = unsafe { KfAcquireSpinLock(lock) };
        Self { lock, irql }
    }

    /// Entries of `list` in load order.
    pub fn entries(&self, list: ModuleList) -> LoaderEntries<'_> {
        LoaderEntries {
            heads: [list.head(), None],
            list: 0,
            link: None,
            _lock: PhantomData,
        }
    }

    /// Entries of the loaded list, then of the user-mode list, in the
    /// order the monitor walks them. One iterator for both lists keeps
    /// the walks from being instantiated once per list.
    pub fn all_entries(&self) -> LoaderEntries<'_> {
        LoaderEntries {
            heads: [ModuleList::Loaded.head(), ModuleList::Usermode.head()],
            list: 0,
            link: None,
            _lock: PhantomData,
        }
    }
}

impl Drop for LoaderLock {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: `acquire` took this lock at `self.irql`.
        unsafe { KfReleaseSpinLock(self.lock, self.irql) };
    }
}

/// Loader data table entries of up to two lists, one after the other;
/// built only by [`LoaderLock`], whose borrow keeps the entries linked.
pub struct LoaderEntries<'a> {
    /// Heads of the lists; none for a list the kernel does not have.
    heads: [Option<NonZeroU32>; 2],
    list: usize,
    /// The head or the last entry returned of the current list; none
    /// before its first entry.
    link: Option<NonZeroU32>,
    _lock: PhantomData<&'a LoaderLock>,
}

impl<'a> Iterator for LoaderEntries<'a> {
    type Item = &'a LdrDataTableEntry;

    fn next(&mut self) -> Option<&'a LdrDataTableEntry> {
        loop {
            if let Some(head) = *self.heads.get(self.list)? {
                let link = *self.link.get_or_insert(head);
                // SAFETY: `link` is the kernel's list head, which lives as
                // long as the system, or an entry linked into its list; the
                // loader lock borrowed for `'a` keeps the links unchanged and
                // the entries mapped.
                let entry = unsafe { object_at::<ListEntry>(link.get()) }
                    .flink
                    .load(Ordering::Relaxed);
                if entry != head.get() {
                    // SAFETY: the link of a circular kernel list holds the
                    // address of a mapped link, which is not 0.
                    self.link = Some(unsafe { NonZeroU32::new_unchecked(entry) });
                    // SAFETY: `entry` is linked into the list, as above; a
                    // loader entry starts with its load order link.
                    return Some(unsafe { object_at(entry) });
                }
            }
            self.list += 1;
            self.link = None;
        }
    }
}
