//! NuiCam raw data requests (stock 0x91fab760): requesters queue nodes,
//! the camera driver completes the oldest one with each raw data block.
//! The capture switch is the kernel's NuiCam control routine (kernel
//! ordinal 0x30d), resolved at startup.

use core::mem::offset_of;
use core::ptr::NonNull;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU16;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::sync::SpinLock;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Kevent;

use crate::kernel;

static REQUESTS: SpinLock<Requests> = SpinLock::new(Requests {
    control: None,
    missed: false,
    mode: CaptureMode::OFF,
});

/// Head of the queued nodes; changed with the `REQUESTS` lock held, or
/// before the dispatcher is published.
static LIST: Link = Link {
    next: AtomicPtr::new(core::ptr::null_mut()),
    previous: AtomicPtr::new(core::ptr::null_mut()),
};

/// Code of a NuiCam control routine request.
#[repr(u32)]
#[derive(Clone, Copy)]
enum NuiCamControl {
    /// Switch raw data capture to the request's value.
    RawCapture = 0xa,
}

/// Argument of the NuiCam control routine.
#[repr(C)]
struct ControlRequest {
    code: NuiCamControl,
    value: CaptureMode,
}

const _: () = assert!(offset_of!(ControlRequest, value) == 4);
const _: () = assert!(size_of::<ControlRequest>() == 8);

/// Capture mode: the value the control routine switches capture to.
/// Requesters may store any value.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct CaptureMode(u32);

impl CaptureMode {
    const OFF: Self = Self(0);
    /// Set by a queued request and by `CaptureOperation::Exchange`.
    const CAPTURING: Self = Self(1);
}

/// Operation of a monitor control 0xa1 request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CaptureOperation {
    /// Op 0: store the value and switch capture to it.
    Apply,
    /// Op 1: return the old mode, select capture, and switch it off.
    Exchange,
    /// Other ops: store the value and switch capture off.
    Store,
}

impl CaptureOperation {
    fn from_raw(operation: u32) -> Self {
        match operation {
            0 => Self::Apply,
            1 => Self::Exchange,
            _ => Self::Store,
        }
    }
}

/// Monitor control 0xa1 request (caller memory).
#[repr(C)]
struct CaptureModeRequest {
    operation: u32,
    value: CaptureMode,
}

const _: () = assert!(offset_of!(CaptureModeRequest, value) == 4);

/// Link of the request list: the next and the previous link. The list
/// head and the first field of every queued node.
#[repr(C)]
struct Link {
    next: AtomicPtr<Link>,
    previous: AtomicPtr<Link>,
}

impl Link {
    fn as_ptr(&self) -> *mut Link {
        core::ptr::from_ref(self).cast_mut()
    }

    /// Empty the list, forgetting every queued node.
    fn reset(&self) {
        let head = self.as_ptr();
        self.next.store(head, Ordering::Relaxed);
        self.previous.store(head, Ordering::Relaxed);
    }

    /// Append `node` to the list headed by `self`.
    ///
    /// # Safety
    ///
    /// The list is reset. Until `node` and every queued node are completed
    /// or flushed, each stays valid and only this list touches its links,
    /// its `buffer` holds `size` writable bytes, and its `event`, when
    /// present, is an initialized event.
    unsafe fn push_back(&self, node: NonNull<RawDataNode>) {
        let head = self.as_ptr();
        let last = self.previous.load(Ordering::Relaxed);
        let link = node.cast::<Link>().as_ptr();

        // SAFETY: `node` and `last` (a queued node or the head) are valid
        // links per the caller contract.
        unsafe {
            (*link).next.store(head, Ordering::Relaxed);
            (*link).previous.store(last, Ordering::Relaxed);
            (*last).next.store(link, Ordering::Relaxed);
        }

        self.previous.store(link, Ordering::Relaxed);
    }

    /// Unlink the first node of the list headed by `self`.
    ///
    /// # Safety
    ///
    /// As [`Link::push_back`].
    unsafe fn pop_front(&self) -> Option<NonNull<RawDataNode>> {
        let first = self.next.load(Ordering::Relaxed);
        if first == self.as_ptr() {
            return None;
        }

        // SAFETY: `first` and its neighbors are queued nodes or the head,
        // valid per the caller contract.
        unsafe {
            let next = (*first).next.load(Ordering::Relaxed);
            let previous = (*first).previous.load(Ordering::Relaxed);
            (*previous).next.store(next, Ordering::Relaxed);
            (*next).previous.store(previous, Ordering::Relaxed);
            Some(NonNull::new_unchecked(first).cast())
        }
    }
}

/// Requester node (caller memory): queued by monitor control 0x97,
/// completed by 0x96 with a copy of the raw data block.
#[repr(C)]
struct RawDataNode {
    link: Link,
    /// Signaled on completion when present.
    event: Option<NonNull<Kevent>>,
    buffer: *mut u8,
    /// Size of `buffer`.
    size: u32,
    /// Length of the block's data, which may exceed `size`.
    received: AtomicU32,
    _reserved: u32,
    tag: AtomicU16,
    kind: AtomicU8,
    /// Nonzero when a completion found no request before this one.
    missed: AtomicU8,
}

const _: () = {
    assert!(offset_of!(RawDataNode, link) == 0);
    assert!(offset_of!(RawDataNode, event) == 8);
    assert!(offset_of!(RawDataNode, buffer) == 0xc);
    assert!(offset_of!(RawDataNode, size) == 0x10);
    assert!(offset_of!(RawDataNode, received) == 0x14);
    assert!(offset_of!(RawDataNode, tag) == 0x1c);
    assert!(offset_of!(RawDataNode, kind) == 0x1e);
    assert!(offset_of!(RawDataNode, missed) == 0x1f);
    assert!(size_of::<RawDataNode>() == 0x20);
};

/// Raw data block from the camera driver (monitor control 0x96).
#[repr(C)]
struct RawDataBlock {
    _flag: u32,
    tag: u16,
    kind: u8,
    _pad: u8,
    data: *const u8,
    length: u32,
}

const _: () = {
    assert!(offset_of!(RawDataBlock, tag) == 4);
    assert!(offset_of!(RawDataBlock, kind) == 6);
    assert!(offset_of!(RawDataBlock, data) == 8);
    assert!(offset_of!(RawDataBlock, length) == 0xc);
    assert!(size_of::<RawDataBlock>() == 0x10);
};

struct Requests {
    /// The control routine; requests are accepted only once it resolved.
    control: Option<u32>,
    /// The last completion found no request.
    missed: bool,
    mode: CaptureMode,
}

impl Requests {
    /// Queue `node`; the control routine when this request turns capture
    /// on.
    ///
    /// # Safety
    ///
    /// Once the control routine is resolved, `node` is nonnull and meets
    /// the contract of [`Link::push_back`].
    unsafe fn queue(&mut self, node: *mut RawDataNode) -> Option<u32> {
        let control = self.control?;

        // SAFETY: forwarded to the caller.
        unsafe { LIST.push_back(NonNull::new_unchecked(node)) };

        if self.mode != CaptureMode::OFF {
            return None;
        }

        self.mode = CaptureMode::CAPTURING;

        Some(control)
    }

    /// Complete the oldest request with the raw data `block`.
    ///
    /// # Safety
    ///
    /// `block.data` points to `block.length` readable bytes for the call,
    /// not overlapping a node buffer.
    unsafe fn complete(&mut self, block: &RawDataBlock) {
        // SAFETY: the `REQUESTS` lock is held, and every queued node meets
        // the contract of `Link::push_back` until it is completed or
        // flushed (the caller contract of monitor control 0x97).
        let Some(node) = (unsafe { LIST.pop_front() }) else {
            self.missed = true;
            return;
        };

        // SAFETY: as above; the node was queued until now.
        let node = unsafe { node.as_ref() };
        let length = block.length;
        let copied = node.size.min(length);

        // SAFETY: the block holds `length` readable bytes (caller
        // contract) and the node's buffer `size` writable bytes (queue
        // contract).
        unsafe { core::ptr::copy_nonoverlapping(block.data, node.buffer, copied as usize) };

        node.received.store(length, Ordering::Relaxed);
        node.tag.store(block.tag, Ordering::Relaxed);
        node.kind.store(block.kind, Ordering::Relaxed);
        node.missed.store(u8::from(self.missed), Ordering::Relaxed);

        if let Some(event) = node.event {
            // SAFETY: a present event is initialized (queue contract).
            unsafe { xboxkrnl::KeSetEvent(event.as_ptr(), xboxkrnl::EVENT_INCREMENT, false) };
        }

        self.missed = false;
    }

    /// Apply `operation` of `request`; the control routine once it
    /// resolved.
    fn set_mode(
        &mut self,
        operation: CaptureOperation,
        request: &mut CaptureModeRequest,
    ) -> Option<u32> {
        let control = self.control?;

        if operation == CaptureOperation::Exchange {
            request.value = self.mode;
            self.mode = CaptureMode::CAPTURING;
        } else {
            self.mode = request.value;
        }

        Some(control)
    }
}

/// Startup (stock 0x91f652b8).
pub(super) fn initialize() {
    /// Kernel export: NuiCam control routine `(&ControlRequest)`.
    const NUICAM_CONTROL: Ordinal = Ordinal::new(0x30d).unwrap();

    LIST.reset();

    let Ok(module) = SystemModule::Kernel.handle() else {
        return;
    };

    let mut address = 0u32;
    // SAFETY: `module` is the loaded kernel image and `address` a local word.
    if unsafe {
        xboxkrnl::XexGetProcedureAddress(
            module.raw(),
            u32::from(NUICAM_CONTROL.get()),
            &mut address,
        )
    }
    .is_success()
    {
        REQUESTS.lock().control = Some(address);
    }
}

fn switch_capture(control: u32, value: CaptureMode) {
    let request = ControlRequest {
        code: NuiCamControl::RawCapture,
        value,
    };
    // SAFETY: the control routine takes a pointer to a `ControlRequest`.
    unsafe { kernel::call_export(control, kernel::address_of(&request), 0, 0, 0) };
}

/// Monitor control 0x97: queue a raw data request node; the first request
/// turns capture on.
///
/// # Safety
///
/// `argument` must be the nonnull address of a requester node that, until
/// it is completed or flushed, stays valid and is touched only by this
/// module, whose `buffer` holds `size` writable bytes, and whose `event`,
/// when present, is an initialized event.
pub(crate) unsafe fn service_queue_raw_data_request(argument: u32) -> u32 {
    let node = core::ptr::with_exposed_provenance_mut::<RawDataNode>(argument as usize);

    // SAFETY: left below on the same thread.
    unsafe { xboxkrnl::KeEnterCriticalRegion() };

    // SAFETY: the caller's contract for `node`. `initialize` reset the list
    // before the control routine resolved, and `queue` queues only after
    // that.
    let enable = unsafe { REQUESTS.lock().queue(node) };
    if let Some(control) = enable {
        switch_capture(control, CaptureMode::CAPTURING);
    }

    // SAFETY: entered above on the same thread.
    unsafe { xboxkrnl::KeLeaveCriticalRegion() };

    0
}

/// Monitor control 0x96: complete the oldest request with a raw data
/// block.
///
/// # Safety
///
/// `argument` must be the address of the driver's raw data block, valid
/// and unchanged for the call, whose `data` points to `length` readable
/// bytes outside every requester buffer.
pub(crate) unsafe fn service_complete_raw_data_request(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let block = unsafe { kernel::object_at::<RawDataBlock>(argument) };

    // SAFETY: see `block`.
    unsafe { REQUESTS.lock().complete(block) };

    0
}

/// Monitor control 0x98: forget every queued request without completing
/// it.
pub(crate) fn service_flush_raw_data_requests(_argument: u32) -> u32 {
    flush();

    0
}

fn flush() {
    let requests = REQUESTS.lock();

    if requests.control.is_some() {
        LIST.reset();
    }
}

/// Monitor control 0xa1: apply a `CaptureModeRequest`. Pending requests
/// are dropped and capture is switched as the operation says.
///
/// # Safety
///
/// `argument` must be the address of the caller's `CaptureModeRequest`,
/// readable and writable and not otherwise accessed for the call.
pub(crate) unsafe fn service_set_capture_mode(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let request = unsafe { kernel::object_at_mut::<CaptureModeRequest>(argument) };

    // SAFETY: left below on the same thread.
    unsafe { xboxkrnl::KeEnterCriticalRegion() };

    let operation = CaptureOperation::from_raw(request.operation);
    let control = REQUESTS.lock().set_mode(operation, request);
    if let Some(control) = control {
        flush();

        let mode = if operation == CaptureOperation::Apply {
            request.value
        } else {
            CaptureMode::OFF
        };
        switch_capture(control, mode);
    }

    // SAFETY: entered above on the same thread.
    unsafe { xboxkrnl::KeLeaveCriticalRegion() };

    0
}

/// Second title terminate routine's last step (stock 0x91f32418 calls
/// 0x91f653d0).
pub(crate) fn title_ended() {
    flush();
}
