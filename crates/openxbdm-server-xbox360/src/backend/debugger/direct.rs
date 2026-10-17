//! Queue of direct notifications captured at raised level.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::debugger::DirectNotice;
use openxbdm_server::commands::debugger::DirectNotification;
use openxbdm_server::commands::debugger::ExceptionRecord;
use openxbdm_server::commands::debugger::NOTICE_TEXT_CAPACITY;
use openxbdm_server::commands::debugger::ThreadId;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;

use super::memory::readable_length;
use super::memory::target_u8;
use super::module::describe_module;
use crate::kernel::object_at;

static DIRECT_LOCK: KspinLock = KspinLock::new();

static DIRECT_HEAD: AtomicU32 = AtomicU32::new(0);

static DIRECT_TAIL: AtomicU32 = AtomicU32::new(0);

/// A queued direct notification; the captured text follows it.
#[repr(C)]
struct DirectNode {
    /// Address of the next node, or 0; guarded by `DIRECT_LOCK`.
    next: AtomicU32,
    notification: DirectNotification,
}

/// Capture what a direct notice names and queue it for the server (stock
/// 0x91f39768 allocates the same way at raised level).
pub(super) fn queue_direct(
    thread: ThreadId,
    iar: u32,
    record: ExceptionRecord,
    notice: DirectNotice,
) {
    /// Pool tag of queued direct notifications ('Ddfn').
    const DIRECT_TAG: PoolTag = PoolTag::new(*b"nfdD");

    let (text_address, text_length) = match notice {
        DirectNotice::DebugString { address, length } | DirectNotice::Rip { address, length } => (
            address,
            readable_length(address, usize::from(length).min(NOTICE_TEXT_CAPACITY)),
        ),
        _ => (0, 0),
    };
    let module = match notice {
        DirectNotice::ModuleLoad { name_string, entry }
        | DirectNotice::ModuleUnload {
            name_string, entry, ..
        } => {
            // SAFETY: the notice carries the loader's name string and module
            // entry from the parameters of the trap the calling thread
            // raised, live while the debug routine runs.
            unsafe { describe_module(name_string, entry) }
        }
        _ => None,
    };
    let header = core::mem::size_of::<DirectNode>();
    // SAFETY: pool allocation has no pointer arguments.
    let node = unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(
            (header + text_length) as u32,
            DIRECT_TAG,
            PoolType::System,
        )
    };
    if node == 0 {
        return;
    }

    let notification = DirectNotification {
        thread,
        iar,
        record,
        notice,
        module,
        text_length,
    };
    let node_pointer = core::ptr::with_exposed_provenance_mut::<DirectNode>(node as usize);
    // SAFETY: the pool block holds the node and `text_length` bytes and
    // only this call reaches it until it is linked; `readable_length`
    // found the text readable.
    unsafe {
        node_pointer.write(DirectNode {
            next: AtomicU32::new(0),
            notification,
        });
        let text = node_pointer.cast::<u8>().add(header);

        for offset in 0..text_length {
            text.add(offset)
                .write(target_u8(text_address + offset as u32));
        }
    }
    let lock = DIRECT_LOCK.as_ptr();
    // SAFETY: `lock` is the static direct notification spin lock.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(lock) };
    match DIRECT_TAIL.swap(node, Ordering::Relaxed) {
        0 => DIRECT_HEAD.store(node, Ordering::Relaxed),
        // SAFETY: under the lock the tail is a queued node that
        // `next_direct_notification` has not freed.
        tail => unsafe { object_at::<DirectNode>(tail) }
            .next
            .store(node, Ordering::Relaxed),
    }
    // SAFETY: the lock was acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(lock, irql) };
}

pub(super) fn next_direct_notification(
    text: &mut [u8; NOTICE_TEXT_CAPACITY],
) -> Option<DirectNotification> {
    let lock = DIRECT_LOCK.as_ptr();
    // SAFETY: `lock` is the static direct notification spin lock.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(lock) };
    let node = DIRECT_HEAD.load(Ordering::Relaxed);
    if node != 0 {
        // SAFETY: under the lock the head is a queued node.
        let next = unsafe { object_at::<DirectNode>(node) }
            .next
            .load(Ordering::Relaxed);
        DIRECT_HEAD.store(next, Ordering::Relaxed);
        if next == 0 {
            DIRECT_TAIL.store(0, Ordering::Relaxed);
        }
    }
    // SAFETY: the lock was acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(lock, irql) };
    if node == 0 {
        return None;
    }

    // SAFETY: `queue_direct` wrote the node and its text; this call
    // unlinked it, so nothing else reaches it.
    let node_ref = unsafe { object_at::<DirectNode>(node) };
    let mut notification = node_ref.notification;
    let length = notification.text_length.min(NOTICE_TEXT_CAPACITY);
    // SAFETY: the node is followed by `text_length` bytes of text.
    let source = unsafe {
        core::slice::from_raw_parts(
            core::ptr::from_ref(node_ref)
                .cast::<u8>()
                .add(core::mem::size_of::<DirectNode>()),
            length,
        )
    };
    text[..length].copy_from_slice(source);
    notification.text_length = length;
    // SAFETY: the node is a pool block `queue_direct` allocated and this
    // call unlinked.
    unsafe { xboxkrnl::ExFreePool(node) };

    Some(notification)
}
