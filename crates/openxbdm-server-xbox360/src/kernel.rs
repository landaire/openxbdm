//! Kernel helpers over the `xbox360_sys` imports.

mod address;
mod call;
mod debug_output;
mod loader;
mod monitor;
mod sync;

use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;

pub use self::address::address_of;
pub use self::address::bounded_c_string;
pub use self::address::c_string;
pub use self::address::object_at;
pub use self::address::object_at_mut;
pub use self::address::thread_at;
pub use self::call::DbgPrint;
pub use self::call::call_console;
pub use self::call::call_export;
pub(crate) use self::call::forward;
pub use self::call::performance_frequency;
pub use self::debug_output::debug_print;
pub use self::debug_output::debug_print_bytes;
pub use self::loader::LoaderLock;
pub use self::loader::ModuleList;
pub use self::monitor::RoutineVariable;
pub use self::monitor::base_kernel_version;
pub use self::monitor::data_imports_resolved;
pub use self::monitor::debug_monitor_data;
pub use self::monitor::hardware_info;
pub use self::monitor::publish_debug_monitor_dispatcher;
pub use self::monitor::published_debug_monitor_data;
pub use self::monitor::register_debug_monitor;
pub use self::monitor::routine_variable;
pub use self::monitor::version_words;
pub use self::sync::CriticalSection;
pub use self::sync::KernelEvent;

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

/// A counted string over `bytes`. The length is truncated to 16 bits; the
/// names and paths the module passes are far shorter.
pub const fn ansi_string(bytes: &[u8]) -> AnsiString {
    AnsiString {
        length: bytes.len() as u16,
        maximum_length: bytes.len() as u16,
        buffer: bytes.as_ptr(),
    }
}
