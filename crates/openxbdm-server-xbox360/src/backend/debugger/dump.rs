//! Crash dump requests.

use core::sync::atomic::Ordering;

use xbox360_sys::xboxkrnl::Context as KernelContext;
use xbox360_sys::xboxkrnl::ContextFlags as KernelContextFlags;
use xbox360_sys::xboxkrnl::DebugMonitorFlags;
use xbox360_sys::xboxkrnl::DumpWriteDump;
use xbox360_sys::xboxkrnl::ExceptionRecord as KernelExceptionRecord;
use xbox360_sys::xboxkrnl::RtlCaptureContext;

use super::context::ContextStorage;
use crate::kernel;
use crate::kernel::address_of;

/// `DumpWriteDump` flags (K16547 0x801af818). Without
/// [`DumpKind::Return`] the kernel restarts the console after writing
/// (`HalReturnToFirmware(2)`, 0x801afad8); the call returns only when a dump
/// was already written or is in progress (0x116) or the dump disk cannot be
/// opened (its status).
#[repr(u32)]
#[derive(Clone, Copy)]
pub(crate) enum DumpKind {
    Default = 0,
    /// The kind stock passes for an exception once the kernel's bug check
    /// flag ([`DebugMonitorFlags::BUG_CHECK`]) is set: the dump header
    /// records `KiBugCheckData` (K15574 0x801ad748).
    BugCheck = 1,
    /// Return to the caller after writing instead of restarting
    /// (0x801afa88).
    Return = 2,
}

/// Mark the data block as writing a crash dump, as stock does before each
/// dump; returns the updated flags.
pub(super) fn mark_dump() -> DebugMonitorFlags {
    let data = kernel::debug_monitor_data();
    let flags = DebugMonitorFlags::from_bits_retain(data.flags.load(Ordering::Relaxed))
        | DebugMonitorFlags::DUMP;
    data.flags.store(flags.bits(), Ordering::Release);

    flags
}

/// Write a crash dump of an exception; the kernel's bug check flag selects
/// the dump kind.
pub(super) fn write_dump(record: &KernelExceptionRecord, context: &KernelContext) {
    let kind = if mark_dump().contains(DebugMonitorFlags::BUG_CHECK) {
        DumpKind::BugCheck
    } else {
        DumpKind::Default
    };
    // SAFETY: both are the live exception record and context of the
    // exception.
    unsafe { DumpWriteDump(address_of(record), address_of(context), kind as u32) };
}

/// Capture the calling thread's context and write a crash dump of it
/// (`crashdump`, stock export 83) with dump kind `kind`.
pub(crate) fn dump_calling_thread(kind: DumpKind) {
    let mut context = ContextStorage::new(KernelContextFlags::empty());
    // SAFETY: `context` is a live local of the size the kernel writes.
    unsafe {
        RtlCaptureContext(context.as_mut_ptr());
        DumpWriteDump(0, address_of(&context.context), kind as u32);
    }
}
