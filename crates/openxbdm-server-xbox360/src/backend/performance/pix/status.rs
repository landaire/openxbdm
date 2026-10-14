//! PIX status notifications (stock 0x91f63f28): a title may install a
//! filter that takes a status first; otherwise the status is sent to the
//! notification channels as a `PIX!` text.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use crate::backend::session;

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

/// Status filter a title installs through code 0x45 (stock 0x91fa2cec);
/// 0 when none. Stock guards it with a spin lock that only serializes the
/// word access.
static FILTER: AtomicU32 = AtomicU32::new(0);

/// Install `filter` and return the previous one (stock 0x91f63d10).
pub(super) fn set_filter(filter: u32) -> u32 {
    FILTER.swap(filter, Ordering::AcqRel)
}

/// Offer `status` with `argument` (a text address or 0) to the filter, and
/// send it when the filter is absent or declines (stock 0x91f63f28).
pub(crate) fn post(status: Status, argument: u32) {
    let filter = FILTER.load(Ordering::Acquire);
    if filter != 0 {
        // SAFETY: the title installed a filter taking two arguments
        // `(status, argument) -> taken`.
        if unsafe { crate::kernel::call_export(filter, status as u32, argument, 0, 0) } != 0 {
            return;
        }
    }
    send(status, argument);
}

/// Format and send the text of `status` (stock 0x91f63dd8).
fn send(status: Status, argument: u32) {
    let fixed: &[u8] = match status {
        Status::CounterDataAvailable => b"PIX!CounterDataAvailable\0",
        Status::StreamEngineOutOfMemory => b"PIX!StreamEngineOutOfMemory\0",
        Status::Timing => b"PIX!Timing\0",
        Status::No => b"PIX!NO\0",
        Status::BadD3dVersion => b"PIX!BadD3dVersion\0",
        Status::Gpu => b"PIX!Gpu\0",
        Status::NoFrame => b"PIX!NoFrame\0",
        Status::Trace => b"PIX!Trace\0",
        Status::Pause => b"PIX!Pause\0",
        Status::NoHarddrive => b"PIX!NoHarddrive\0",
        Status::MovieData => b"PIX!MovieData\0",
        Status::Reboot => b"PIX!Reboot\0",
        Status::Text => {
            session::service_send_notification(argument);
            return;
        }
        Status::VideoOp | Status::VideoOpError | Status::Resource => {
            let prefix: &[u8] = match status {
                Status::VideoOp => b"PIX!VideoOp ",
                Status::VideoOpError => b"PIX!VideoOpError ",
                _ => b"PIX!Resource ",
            };
            // Stock formats into a 0x90-byte stack buffer; longer
            // arguments overflow it, here they are cut.
            let mut text = [0u8; 0x90];
            text[..prefix.len()].copy_from_slice(prefix);
            let mut length = prefix.len();
            let mut address = argument;
            while address != 0 && length < text.len() - 1 {
                let byte = super::read_u8(address);
                if byte == 0 {
                    break;
                }
                text[length] = byte;
                length += 1;
                address += 1;
            }
            session::service_send_notification(text.as_ptr() as usize as u32);
            return;
        }
    };
    session::service_send_notification(fixed.as_ptr() as usize as u32);
}

/// Monitor control code 0x1b (stock 0x91f3b6b0): post status 9 with the
/// caller's text; 1 as stock's send path reports.
pub(crate) fn service_post_text(text: u32) -> u32 {
    post(Status::Text, text);
    1
}

/// Monitor control code 0x45 (stock 0x91f64058): `{+0 0xc, +4 operation,
/// +8 data}`. Operation 1 installs a status filter `{0xc, filter, previous
/// out}`; operation 0 runs a `pixcmd` line `{0x14, line, response, size,
/// context}` and returns its status; others fail with 0x8000ffff.
pub(crate) fn service_filter_control(argument: u32) -> u32 {
    let data = super::read_u32(argument + 8);
    match super::read_u32(argument + 4) {
        0 => super::run_command_line(data),
        1 => {
            let previous = set_filter(super::read_u32(data + 4));
            super::write_u32(data + 8, previous);
            0
        }
        _ => 0x8000_ffff,
    }
}
