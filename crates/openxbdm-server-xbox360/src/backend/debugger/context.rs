//! Thread context transfer between kernel and server forms.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::debugger::Context;
use openxbdm_server::commands::debugger::ContextFlags;
use openxbdm_server::commands::debugger::NoSuchThread;
use openxbdm_server::commands::debugger::StoppedThreadError;
use openxbdm_server::commands::debugger::ThreadId;
use xbox360_sys::processor::Msr;
use xbox360_sys::xboxkrnl::Context as KernelContext;
use xbox360_sys::xboxkrnl::ContextFlags as KernelContextFlags;
use xbox360_sys::xboxkrnl::KswitchFrame;
use xbox360_sys::xboxkrnl::Kthread;

use super::hook::BREAK_NOW;
use super::hook::BREAK_NOW_STOPPED;
use super::slot::SLOTS;
use super::slot::SlotEventKind;
use super::thread::ThreadListLock;
use super::thread::ThreadRef;
use super::thread::has_record;
use super::thread::is_server;
use super::thread::owning_process;

/// Bytes `RtlCaptureContext` and `KeContextFromKframes` may write: the
/// kernel context and 0x10 more.
const CONTEXT_STORAGE_SIZE: usize = 0xa50;

/// Context block the kernel fills.
#[repr(C, align(16))]
pub(super) struct ContextStorage {
    pub(super) context: KernelContext,
    _tail: [u8; CONTEXT_STORAGE_SIZE - core::mem::size_of::<KernelContext>()],
}

const _: () = assert!(core::mem::size_of::<ContextStorage>() == CONTEXT_STORAGE_SIZE);

impl ContextStorage {
    pub(super) const fn new(flags: KernelContextFlags) -> Self {
        Self {
            context: KernelContext::new(flags),
            _tail: [0; CONTEXT_STORAGE_SIZE - core::mem::size_of::<KernelContext>()],
        }
    }

    #[inline(always)]
    pub(super) fn as_mut_ptr(&mut self) -> *mut u8 {
        core::ptr::from_mut(self).cast()
    }
}

/// Copy the groups in `flags` from a kernel context to a [`Context`].
///
/// The context is reached through field pointers, not a reference: a
/// caller's CONTEXT is only known to have the 8-byte alignment of its
/// widest scalar field, not the 16 bytes of [`KernelContext`].
///
/// # Safety
///
/// `source` must be valid for reads of a kernel context, aligned to 8
/// bytes, and not written during the call.
unsafe fn read_context(source: *const KernelContext, flags: ContextFlags, out: &mut Context) {
    // SAFETY: the caller's contract; no field needs more than 8-byte
    // alignment.
    unsafe {
        if flags.contains(ContextFlags::CONTROL) {
            out.msr = (&raw const (*source).msr).read();
            out.iar = (&raw const (*source).iar).read();
            out.lr = (&raw const (*source).lr).read();
            out.ctr = (&raw const (*source).ctr).read();
        }
        if flags.contains(ContextFlags::INTEGER) {
            out.gpr = (&raw const (*source).gpr).read();
            out.cr = (&raw const (*source).cr).read();
            out.xer = (&raw const (*source).xer).read();
        }
        if flags.contains(ContextFlags::FLOATING_POINT) {
            out.fpscr = (&raw const (*source).fpscr).read();
            out.fpr = (&raw const (*source).fpr).read();
        }
        if flags.contains(ContextFlags::VECTOR) {
            out.vscr = (&raw const (*source).vscr).read();
            out.vr = (&raw const (*source).vr).read();
        }
    }
}

/// Copy the groups in `source.flags` from a [`Context`] to a kernel
/// context, through field pointers as [`read_context`] reads.
///
/// # Safety
///
/// `target` must be valid for writes of a kernel context, aligned to 8
/// bytes, and not accessed by anything else during the call.
unsafe fn write_context(target: *mut KernelContext, source: &Context) {
    let flags = source.flags;
    // SAFETY: the caller's contract; no field needs more than 8-byte
    // alignment.
    unsafe {
        if flags.contains(ContextFlags::CONTROL) {
            (&raw mut (*target).msr).write(source.msr);
            (&raw mut (*target).iar).write(source.iar);
            (&raw mut (*target).lr).write(source.lr);
            (&raw mut (*target).ctr).write(source.ctr);
        }
        if flags.contains(ContextFlags::INTEGER) {
            (&raw mut (*target).gpr).write(source.gpr);
            (&raw mut (*target).cr).write(source.cr);
            (&raw mut (*target).xer).write(source.xer);
        }
        if flags.contains(ContextFlags::FLOATING_POINT) {
            (&raw mut (*target).fpscr).write(source.fpscr);
            (&raw mut (*target).fpr).write(source.fpr);
        }
        if flags.contains(ContextFlags::VECTOR) {
            (&raw mut (*target).vscr).write(source.vscr);
            (&raw mut (*target).vr).write(source.vr);
        }
    }
}

/// Exception context of a thread stopped at an event: a thread waiting in
/// a slot, or the command thread at the `break now` trap. `lock` is the
/// lock of the thread's process.
fn slot_context(lock: &ThreadListLock<'_>, thread: &Kthread) -> Option<*mut KernelContext> {
    if is_server(thread) {
        return BREAK_NOW_STOPPED
            .load(Ordering::Acquire)
            .then(|| BREAK_NOW.context.get());
    }
    let slot = lock.record(thread)?.slot.load(Ordering::Relaxed);
    if slot == 0 {
        return None;
    }

    let slot = &SLOTS[slot as usize - 1];
    matches!(
        slot.kind(),
        Some(SlotEventKind::Exception | SlotEventKind::StackOverflow)
    )
    .then(|| core::ptr::with_exposed_provenance_mut(slot.context.load(Ordering::Relaxed) as usize))
}

/// Read the groups in `out.flags` of a thread with a monitor record (stock
/// export 13, 0x91f26260); `out.flags` becomes the groups read. A thread
/// stopped in the monitor reports its exception context, another its
/// switch frame with the monitor's fill values.
pub(crate) fn read_thread_context(thread: ThreadId, out: &mut Context) -> Result<(), NoSuchThread> {
    let reference = ThreadRef::lookup(thread)?;
    let thread = reference.thread();
    let lock = ThreadListLock::acquire(owning_process(thread));
    let requested = out.flags & ContextFlags::FULL;
    if !has_record(thread) {
        return Err(NoSuchThread);
    }

    if let Some(context) = slot_context(&lock, thread) {
        // SAFETY: the context of a thread waiting in a slot is the kernel's
        // aligned context, which stays live and unchanged while the process
        // lock keeps the thread from leaving the slot; the `break now`
        // capture is only touched by the server thread.
        unsafe { read_context(context, requested, out) };
        out.flags = requested;
        return Ok(());
    }

    // Switch frame: only the nonvolatile state is meaningful. The thread may
    // run and overwrite the frame meanwhile, so each word is read with one
    // relaxed load.
    let frame_address = thread.switch_frame.load(Ordering::Relaxed);
    let frame = core::ptr::with_exposed_provenance_mut::<KswitchFrame>(frame_address as usize);
    // SAFETY: the switch frame lies on the stack of the referenced thread,
    // which stays allocated while the reference is held; the words are
    // aligned and only read atomically here.
    let word = |address: *mut u32| unsafe { AtomicU32::from_ptr(address) }.load(Ordering::Relaxed);
    let mut flags = ContextFlags::empty();
    if requested.contains(ContextFlags::INTEGER) {
        flags = flags.union(ContextFlags::INTEGER);
        out.gpr = [u64::MAX; 32];
        // SAFETY: field pointers within the frame described above.
        let gpr = unsafe { &raw mut (*frame).gpr }.cast::<u32>();

        for (index, register) in out.gpr[14..].iter_mut().enumerate() {
            // SAFETY: both words lie within the frame's register array.
            let (high, low) = unsafe { (gpr.add(2 * index), gpr.add(2 * index + 1)) };
            *register = (u64::from(word(high)) << 32) | u64::from(word(low));
        }

        out.gpr[1] = u64::from(frame_address);
        // SAFETY: as above.
        out.cr = word(unsafe { &raw mut (*frame).cr });
        out.xer = u32::MAX;
    }
    if requested.contains(ContextFlags::CONTROL) {
        flags = flags.union(ContextFlags::CONTROL);
        out.msr = Msr::from_bits_retain(u32::MAX);
        // SAFETY: as above.
        out.iar = word(unsafe { &raw mut (*frame).iar });
        // SAFETY: as above.
        out.lr = word(unsafe { &raw mut (*frame).lr });
        out.ctr = u64::MAX;
    }
    out.flags = flags;

    Ok(())
}

/// Write the groups in `source.flags` to the exception context of a thread
/// stopped in the monitor (stock export 41, 0x91f26468).
pub(crate) fn write_thread_context(
    thread: ThreadId,
    source: &Context,
) -> Result<(), StoppedThreadError> {
    let reference = ThreadRef::lookup(thread)?;
    let thread = reference.thread();
    let lock = ThreadListLock::acquire(owning_process(thread));
    if !has_record(thread) {
        return Err(StoppedThreadError::NoSuchThread);
    }

    let context = slot_context(&lock, thread).ok_or(StoppedThreadError::NotStopped)?;
    // SAFETY: as in `read_thread_context`; the stopped thread does not
    // touch its context while it waits.
    unsafe { write_context(context, source) };

    Ok(())
}

/// The groups in `flags` of a kernel context.
///
/// # Safety
///
/// As [`read_context`].
pub(crate) unsafe fn context_from_memory(
    source: *const KernelContext,
    flags: ContextFlags,
) -> Context {
    let mut context = Context {
        flags,
        ..Context::default()
    };
    // SAFETY: the caller's contract.
    unsafe { read_context(source, flags, &mut context) };

    context
}

/// Store the groups in `source.flags` into a kernel context.
///
/// # Safety
///
/// As [`write_context`].
pub(crate) unsafe fn context_to_memory(target: *mut KernelContext, source: &Context) {
    // SAFETY: the caller's contract.
    unsafe { write_context(target, source) };
}
