//! NuiCam raw data requests (stock 0x91fab760): requesters queue nodes,
//! the camera driver completes the oldest one with each raw data block.
//! The capture switch is the kernel's NuiCam control routine (kernel
//! ordinal 0x30d), resolved at startup.

use core::cell::UnsafeCell;

use xbox360::module::SystemModule;
use xbox360::sync::SpinLock;
use xbox360_sys::xboxkrnl;

use super::read_word;
use super::write_word;
use crate::kernel;

/// Kernel ordinal: NuiCam control routine `(&{u32 code, u32 value})`.
const KERNEL_NUICAM_CONTROL: u32 = 0x30d;
/// Control routine code that switches raw data capture.
const CONTROL_RAW_CAPTURE: u32 = 0xa;

/// Capture mode set by a queued request and by the `op == 1` mode change.
const MODE_CAPTURING: u32 = 1;

/// Request node offsets (caller memory): links, event, buffer, size,
/// received length, then the block's u16, u8 and the missed flag.
const NODE_EVENT: u32 = 8;
const NODE_BUFFER: u32 = 0xc;
const NODE_SIZE: u32 = 0x10;
const NODE_LENGTH: u32 = 0x14;
const NODE_TAG: u32 = 0x1c;
const NODE_KIND: u32 = 0x1e;
const NODE_MISSED: u32 = 0x1f;

struct Requests {
    /// The control routine; requests are accepted only once it resolved.
    control: Option<u32>,
    /// The last completion found no request.
    missed: bool,
    mode: u32,
}

static REQUESTS: SpinLock<Requests> = SpinLock::new(Requests {
    control: None,
    missed: false,
    mode: 0,
});

impl Requests {
    /// Queue `node`; the control routine when this request turns capture
    /// on.
    fn queue(&mut self, node: u32) -> Option<u32> {
        let control = self.control?;
        LIST.push_back(node);
        if self.mode != 0 {
            return None;
        }
        self.mode = MODE_CAPTURING;
        Some(control)
    }

    /// Complete the oldest request with the raw data `block`.
    fn complete(&mut self, block: u32) {
        let Some(node) = LIST.first() else {
            self.missed = true;
            return;
        };
        unlink(node);
        let length = read_word(block + 0xc);
        let copied = read_word(node + NODE_SIZE).min(length);
        // SAFETY: the driver's block holds `length` bytes and the node's
        // buffer `size` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                read_word(block + 8) as usize as *const u8,
                read_word(node + NODE_BUFFER) as usize as *mut u8,
                copied as usize,
            );
        }
        write_word(node + NODE_LENGTH, length);
        // SAFETY: the node and block layouts hold these fields.
        unsafe {
            let tag = core::ptr::read_volatile((block + 4) as usize as *const u16);
            core::ptr::write_volatile((node + NODE_TAG) as usize as *mut u16, tag);
            let kind = core::ptr::read_volatile((block + 6) as usize as *const u8);
            core::ptr::write_volatile((node + NODE_KIND) as usize as *mut u8, kind);
            core::ptr::write_volatile(
                (node + NODE_MISSED) as usize as *mut u8,
                u8::from(self.missed),
            );
        }
        let event = read_word(node + NODE_EVENT);
        if event != 0 {
            // SAFETY: the requester stores an initialized event in its node.
            unsafe { xboxkrnl::KeSetEvent(event as usize as *mut xboxkrnl::Kevent, 1, false) };
        }
        self.missed = false;
    }

    /// Apply capture mode `operation` of `request`; the control routine
    /// once it resolved.
    fn set_mode(&mut self, operation: u32, request: u32) -> Option<u32> {
        let control = self.control?;
        if operation == 1 {
            write_word(request + 4, self.mode);
            self.mode = MODE_CAPTURING;
        } else {
            self.mode = read_word(request + 4);
        }
        Some(control)
    }
}

/// List head of the queued nodes; guarded by the `REQUESTS` lock.
struct ListHead(UnsafeCell<[u32; 2]>);

// SAFETY: accessed only with the `REQUESTS` lock held, or before the
// dispatcher is published.
unsafe impl Sync for ListHead {}

static LIST: ListHead = ListHead(UnsafeCell::new([0; 2]));

impl ListHead {
    fn address(&self) -> u32 {
        self.0.get() as usize as u32
    }

    fn reset(&self) {
        let head = self.address();
        write_word(head, head);
        write_word(head + 4, head);
    }

    fn first(&self) -> Option<u32> {
        let first = read_word(self.address());
        (first != self.address()).then_some(first)
    }

    fn push_back(&self, node: u32) {
        let head = self.address();
        let last = read_word(head + 4);
        write_word(node, head);
        write_word(node + 4, last);
        write_word(last, node);
        write_word(head + 4, node);
    }
}

fn unlink(node: u32) {
    let next = read_word(node);
    let previous = read_word(node + 4);
    write_word(previous, next);
    write_word(next + 4, previous);
}

/// Startup (stock 0x91f652b8).
pub(super) fn initialize() {
    LIST.reset();
    let Ok(module) = SystemModule::Kernel.handle() else {
        return;
    };
    let mut address = 0u32;
    // SAFETY: `module` is the loaded kernel image and `address` a local word.
    if (unsafe {
        xboxkrnl::XexGetProcedureAddress(module.raw(), KERNEL_NUICAM_CONTROL, &mut address)
    }
    .0 as i32)
        >= 0
    {
        REQUESTS.lock().control = Some(address);
    }
}

fn switch_capture(control: u32, value: u32) {
    let request = [CONTROL_RAW_CAPTURE, value];
    // SAFETY: the control routine takes a pointer to `{code, value}`.
    unsafe { kernel::call_export(control, request.as_ptr() as usize as u32, 0, 0, 0) };
}

/// Monitor control 0x97: queue a raw data request node; the first request
/// turns capture on.
pub(crate) fn service_queue_raw_data_request(node: u32) -> u32 {
    // SAFETY: left below on the same thread.
    unsafe { xboxkrnl::KeEnterCriticalRegion() };
    let enable = REQUESTS.lock().queue(node);
    if let Some(control) = enable {
        switch_capture(control, 1);
    }
    // SAFETY: entered above on the same thread.
    unsafe { xboxkrnl::KeLeaveCriticalRegion() };
    0
}

/// Monitor control 0x96: complete the oldest request with a raw data
/// block `{u32 flag, u16 tag, u8 kind, u8 pad, u32 data, u32 length}`.
pub(crate) fn service_complete_raw_data_request(block: u32) -> u32 {
    REQUESTS.lock().complete(block);
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

/// Monitor control 0xa1: `request` is `{u32 op, u32 value}`. Op 1 returns
/// the old mode in `value` and selects capture; other ops store `value`.
/// Pending requests are dropped and capture is switched to `value` for op
/// 0, off otherwise.
pub(crate) fn service_set_capture_mode(request: u32) -> u32 {
    // SAFETY: left below on the same thread.
    unsafe { xboxkrnl::KeEnterCriticalRegion() };
    let operation = read_word(request);
    let control = REQUESTS.lock().set_mode(operation, request);
    if let Some(control) = control {
        flush();
        switch_capture(
            control,
            if operation == 0 {
                read_word(request + 4)
            } else {
                0
            },
        );
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
