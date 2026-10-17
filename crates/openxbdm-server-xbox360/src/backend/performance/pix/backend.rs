//! Backend part of `pixcmd`.

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::performance::CaptureValue;
use openxbdm_server::commands::performance::PixDogma;

use super::GPU_CAPTURE;
use super::events;
use super::files;
use super::frame;
use super::plugin;
use super::ring;
use super::session;
use super::status;

/// Event name buffer of a timing request.
pub(super) const EVENT_NAME_BYTES: usize = 0x24;
const CAPTURE_TEXT_CAPACITY: usize = EVENT_NAME_BYTES + 2;
/// Capture thread value of no thread.
const NO_CAPTURE_THREAD: u32 = u32::MAX;

/// Capture values of `pixcmd k` (stock 0x91f98ef8 and 0x91fa2a7c) and
/// its text (0x91fa280c, counter 0x91fa2808).
static CAPTURE_VALUES: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];

/// Text of `pixcmd k` (stock 0x91fa280c, unbounded copy there). It is
/// only compared with event names of at most `EVENT_NAME_BYTES` bytes,
/// which a longer text never matches; one more byte and the NUL keep
/// that outcome.
static CAPTURE_TEXT: CaptureText = CaptureText(UnsafeCell::new([0; CAPTURE_TEXT_CAPACITY]));

struct CaptureText(UnsafeCell<[u8; CAPTURE_TEXT_CAPACITY]>);

// SAFETY: written only by the server thread's `pixcmd k`.
unsafe impl Sync for CaptureText {}

impl CaptureText {
    fn with(&self, text: &[u8]) {
        // SAFETY: see the `Sync` impl.
        let buffer = unsafe { &mut *self.0.get() };
        let count = text.len().min(CAPTURE_TEXT_CAPACITY - 1);
        buffer[..count].copy_from_slice(&text[..count]);
        buffer[count] = 0;
    }
}

/// # Safety
///
/// As `performance::Backend::pix_post`.
pub(crate) unsafe fn post(code: u32, payload: &[u32]) -> bool {
    session::post(code, payload)
}

pub(crate) fn status(version: u32, flags: u32) -> Option<[u32; 12]> {
    session::status(version, flags)
}

pub(crate) fn frame_statistics(frame: u32) -> Option<[u32; 3]> {
    session::frame_statistics(frame)
}

pub(crate) fn frame_number() -> i32 {
    frame::frame_number() as i32
}

pub(crate) fn signal_event(event: u32) {
    if let Some(status) = status::Status::from_code(event) {
        status::post_without_text(status);
    }
}

pub(crate) fn counter_control(group: u32, id: u32, enabled: bool) {
    events::counter_control(group, id, enabled);
}

pub(crate) fn set_capture_value(value: CaptureValue, data: u32) {
    let index = match value {
        CaptureValue::First => 0,
        CaptureValue::Second => 1,
    };
    CAPTURE_VALUES[index].store(data, Ordering::Release);
}

pub(crate) fn set_capture_text(text: &[u8]) {
    CAPTURE_TEXT.with(text);
}

/// Text of the event a trace capture waits for (`pixcmd k`).
pub(super) fn capture_text() -> &'static [u8; CAPTURE_TEXT_CAPACITY] {
    // SAFETY: see the `Sync` impl; readers see the last `pixcmd k`.
    unsafe { &*CAPTURE_TEXT.0.get() }
}

/// Hardware thread whose events a trace capture follows; `None` after
/// the traced event ended.
pub(super) fn capture_thread() -> Option<u32> {
    let thread = CAPTURE_VALUES[0].load(Ordering::Acquire);
    (thread != NO_CAPTURE_THREAD).then_some(thread)
}

pub(super) fn clear_capture_thread() {
    CAPTURE_VALUES[0].store(NO_CAPTURE_THREAD, Ordering::Release);
}

/// Count down the occurrences before the traced one (stock
/// 0x91fa2a7c); true when this occurrence is traced.
pub(super) fn count_down_capture() -> bool {
    let count = CAPTURE_VALUES[1].load(Ordering::Acquire).wrapping_sub(1);
    CAPTURE_VALUES[1].store(count, Ordering::Release);

    count == 0
}

pub(crate) fn set_legacy_protocol(legacy: bool) {
    frame::set_legacy(legacy);
    ring::set_legacy(legacy);
}

pub(crate) fn set_gpu_capture(enabled: bool) {
    GPU_CAPTURE.store(enabled, Ordering::Release);
}

pub(crate) fn dogma() -> Option<PixDogma> {
    plugin::dogma()
}

pub(crate) fn capture_ready() -> bool {
    files::resource_capture_flagged()
}

pub(crate) fn trace_snapshot() -> u32 {
    frame::reset_frame_count();
    frame::sample_counters();
    ring::snapshot()
}

pub(crate) fn trace_read(output: &mut [u8]) -> usize {
    ring::read_snapshot(output)
}
