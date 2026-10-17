//! PIX status notifications (stock 0x91f63f28): a title may install a
//! filter that takes a status first; otherwise the status is sent to the
//! notification channels as a `PIX!` text.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;

use crate::backend::session;
use crate::kernel;

/// Status filter a title installs through code 0x45 (stock 0x91fa2cec);
/// 0 when none. Stock guards it with a spin lock that only serializes the
/// word access.
static FILTER: AtomicU32 = AtomicU32::new(0);

/// Status codes of the PIX engine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub(crate) enum Status {
    CounterDataAvailable = 0,
    StreamEngineOutOfMemory = 1,
    Timing = 2,
    No = 3,
    BadD3dVersion = 4,
    Gpu = 5,
    NoFrame = 6,
    Trace = 7,
    Pause = 8,
    /// The argument is the complete text (code 0x1b).
    Text = 9,
    NoHarddrive = 10,
    VideoOp = 11,
    VideoOpError = 12,
    MovieData = 13,
    Resource = 14,
    Reboot = 15,
}

impl Status {
    /// The status with stock code `code`; stock rejects codes above 15.
    pub(crate) fn from_code(code: u32) -> Option<Self> {
        const ALL: [Status; 16] = [
            Status::CounterDataAvailable,
            Status::StreamEngineOutOfMemory,
            Status::Timing,
            Status::No,
            Status::BadD3dVersion,
            Status::Gpu,
            Status::NoFrame,
            Status::Trace,
            Status::Pause,
            Status::Text,
            Status::NoHarddrive,
            Status::VideoOp,
            Status::VideoOpError,
            Status::MovieData,
            Status::Resource,
            Status::Reboot,
        ];
        ALL.get(code as usize).copied()
    }
}

/// Code 0x45 argument record.
#[repr(C)]
struct FilterControl {
    _size: AtomicU32,
    operation: AtomicU32,
    data: AtomicU32,
}

/// Data record of filter control operation 1.
#[repr(C)]
struct InstallFilter {
    _size: AtomicU32,
    filter: AtomicU32,
    previous: AtomicU32,
}

/// Install `filter` and return the previous one (stock 0x91f63d10).
///
/// # Safety
///
/// `filter` must be 0 or a routine that takes `(status, argument)` and
/// stays loaded while installed; [`post`] calls it.
pub(super) unsafe fn set_filter(filter: u32) -> u32 {
    FILTER.swap(filter, Ordering::AcqRel)
}

/// Offer `status` with `argument` (a text address or 0) to the filter, and
/// send it when the filter is absent or declines (stock 0x91f63f28).
///
/// # Safety
///
/// `argument` must be 0 or a NUL-terminated string that stays unchanged
/// for the call.
pub(crate) unsafe fn post(status: Status, argument: u32) {
    let filter = FILTER.load(Ordering::Acquire);

    if filter != 0 {
        // SAFETY: the title installed a filter taking two arguments
        // `(status, argument) -> taken`.
        if unsafe { crate::kernel::call_export(filter, status as u32, argument, 0, 0) } != 0 {
            return;
        }
    }

    // SAFETY: the caller's contract.
    unsafe { send(status, argument) };
}

/// [`post`] without text. Inlined so that callers pass the 0 directly.
#[inline(always)]
pub(crate) fn post_without_text(status: Status) {
    // SAFETY: no text.
    unsafe { post(status, 0) }
}

/// Format and send the text of `status` (stock 0x91f63dd8).
///
/// # Safety
///
/// As [`post`].
unsafe fn send(status: Status, argument: u32) {
    /// Text of each status by code: NUL-terminated, or for `VideoOp`,
    /// `VideoOpError` and `Resource` the prefix of the argument text. `Text`
    /// sends the argument itself.
    const TEXTS: [&[u8]; 16] = [
        b"PIX!CounterDataAvailable\0",
        b"PIX!StreamEngineOutOfMemory\0",
        b"PIX!Timing\0",
        b"PIX!NO\0",
        b"PIX!BadD3dVersion\0",
        b"PIX!Gpu\0",
        b"PIX!NoFrame\0",
        b"PIX!Trace\0",
        b"PIX!Pause\0",
        b"",
        b"PIX!NoHarddrive\0",
        b"PIX!VideoOp ",
        b"PIX!VideoOpError ",
        b"PIX!MovieData\0",
        b"PIX!Resource ",
        b"PIX!Reboot\0",
    ];

    let fixed = TEXTS[status as usize];

    let text = match status {
        Status::Text => argument,
        Status::VideoOp | Status::VideoOpError | Status::Resource => {
            // Stock formats into a 0x90-byte stack buffer; longer
            // arguments overflow it, here they are cut.
            let mut text = [0u8; 0x90];
            text[..fixed.len()].copy_from_slice(fixed);
            // The last byte stays the terminator; the prefixes are shorter,
            // so `space` always exists.
            if let Some(space) = text.get_mut(fixed.len()..0x8f)
                // SAFETY: the caller's contract.
                && let Some(argument) = unsafe { kernel::c_string(argument) }
            {
                let count = argument.len().min(space.len());
                space[..count].copy_from_slice(&argument[..count]);
            }
            // SAFETY: `text` is NUL-terminated in its last byte.
            unsafe { session::service_send_notification(text.as_ptr() as usize as u32) };
            return;
        }
        _ => fixed.as_ptr() as usize as u32,
    };

    // SAFETY: the caller's text or a static NUL-terminated text.
    unsafe { session::service_send_notification(text) };
}

/// Monitor control code 0x1b (stock 0x91f3b6b0): post status 9 with the
/// caller's text; 1 as stock's send path reports.
///
/// # Safety
///
/// As [`post`] for `text`.
pub(crate) unsafe fn service_post_text(text: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { post(Status::Text, text) };

    1
}

/// Monitor control code 0x45 (stock 0x91f64058): `{+0 0xc, +4 operation,
/// +8 data}`. Operation 1 installs a status filter `{0xc, filter, previous
/// out}`; operation 0 runs a `pixcmd` line `{0x14, line, response, size,
/// context}` and returns its status; others fail with 0x8000ffff.
///
/// # Safety
///
/// `argument` must be the address of a filter control record whose data
/// is the record of its operation, both kept valid by the caller for the
/// call; an installed filter takes `(status, argument)` and stays loaded
/// while installed.
pub(crate) unsafe fn service_filter_control(argument: u32) -> u32 {
    /// Operations of code 0x45.
    const RUN_COMMAND_LINE: u32 = 0;
    const INSTALL_FILTER: u32 = 1;

    // SAFETY: the caller's contract.
    let argument = unsafe { crate::kernel::object_at::<FilterControl>(argument) };
    let data = argument.data.load(Ordering::Relaxed);

    match argument.operation.load(Ordering::Relaxed) {
        // SAFETY: the caller's contract.
        RUN_COMMAND_LINE => unsafe { super::run_command_line(data) },
        INSTALL_FILTER => {
            // SAFETY: the caller's contract.
            let data = unsafe { crate::kernel::object_at::<InstallFilter>(data) };
            // SAFETY: the caller's contract covers the filter routine.
            let previous = unsafe { set_filter(data.filter.load(Ordering::Relaxed)) };
            data.previous.store(previous, Ordering::Relaxed);

            0
        }
        _ => Hresult::UNEXPECTED.0,
    }
}
