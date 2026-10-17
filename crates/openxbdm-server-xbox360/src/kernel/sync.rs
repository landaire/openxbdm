//! Kernel synchronization objects in static storage.

use core::cell::UnsafeCell;

use xbox360_sys::xboxkrnl::EVENT_INCREMENT;
use xbox360_sys::xboxkrnl::EventType;
use xbox360_sys::xboxkrnl::KeEnterCriticalRegion;
use xbox360_sys::xboxkrnl::KeLeaveCriticalRegion;
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

/// A kernel critical section in static storage; waits at passive level.
pub struct CriticalSection(UnsafeCell<[u32; 8]>);

// SAFETY: the kernel synchronizes the critical section.
unsafe impl Sync for CriticalSection {}

impl CriticalSection {
    pub const fn new() -> Self {
        Self(UnsafeCell::new([0; 8]))
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
pub struct KernelEvent(UnsafeCell<[u32; 4]>);

// SAFETY: the kernel synchronizes access to dispatcher objects.
unsafe impl Sync for KernelEvent {}

impl KernelEvent {
    pub const fn new() -> Self {
        Self(UnsafeCell::new([0; 4]))
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
