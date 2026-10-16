//! File I/O event notifications (`XBDMFE!`): the switch that `fileevent`
//! and exports 152/153 share, the file services' events (monitor control
//! codes 0x64 and 0x65), and the events titles report through exports 154
//! to 160.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands::session::EventPath;
use openxbdm_server::commands::session::FILE_EVENT_TEXT_LIMIT;
use openxbdm_server::commands::session::FLAG_BUFFERED;
use openxbdm_server::commands::session::FLAG_SCATTER_GATHER;
use openxbdm_server::commands::session::FLAG_SYNCHRONOUS;
use openxbdm_server::commands::session::FileEventBegin;
use openxbdm_server::commands::session::FileEventId;
use openxbdm_server::commands::session::FileEventText;
use openxbdm_server::commands::session::PseudoBegin;
use openxbdm_server::commands::session::PseudoBeginIo;
use openxbdm_server::commands::session::file_event_kind;
use openxbdm_server::commands::session::format_file_event_begin;
use openxbdm_server::commands::session::format_file_event_end;
use openxbdm_server::commands::session::format_file_event_switch;
use openxbdm_server::commands::session::format_mark_thread;
use openxbdm_server::commands::session::format_marker;
use openxbdm_server::commands::session::format_pseudo_begin;
use openxbdm_server::commands::session::format_pseudo_begin_io;
use openxbdm_server::commands::session::format_pseudo_end;
use openxbdm_server::commands::session::format_unmark_thread;
use xbox360::sync::SpinLock;
use xbox360::time::Timebase;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;

use super::THREAD_ID;
use super::c_string;
use super::current_thread;
use super::current_title_id;
use super::notifications::notification_result;
use super::notifications::send_notification_text;
use super::read_u32;
use super::read_u64;
use super::write_u32;
use crate::exports::export;

export!(152, start);
export!(153, stop);
export!(154, marker);
export!(155, pseudo_begin);
export!(156, pseudo_end);
export!(157, pseudo_begin_io);
export!(158, pseudo_end_result);
export!(159, mark_thread);
export!(160, unmark_thread);

/// Identifier and title state under the monitor's critical section
/// 0x91fae520 (stock 0x91f9735c identifier, 0x91f9f62c/0x91f9f630
/// suppressed title).
struct FileEvents {
    last_id: FileEventId,
    /// Title whose events are suppressed after it terminated.
    suppressed: Option<u32>,
}

impl FileEvents {
    fn next_id(&mut self) -> FileEventId {
        self.last_id = self.last_id.next();
        self.last_id
    }

    /// Whether the running title reports events; a different title ends
    /// the suppression.
    fn reports(&mut self) -> bool {
        let title = current_title_id();
        // The dashboard and this system title never report.
        if title == 0xfffe_07d1 || title == 0xfffe_07ff || self.suppressed == Some(title) {
            return false;
        }
        self.suppressed = None;
        true
    }
}

static FILE_EVENTS: SpinLock<FileEvents> = SpinLock::new(FileEvents {
    last_id: FileEventId(0),
    suppressed: None,
});
/// Enable flag (stock 0x91f9f628): set under the lock, read without it, as
/// stock does.
static ENABLED: AtomicBool = AtomicBool::new(false);

const BAD_PARAMETER: Hresult = ErrorCode::BadParameter.hresult();

fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// Switch the notifications and take the next identifier (exports 152 and
/// 153 before their text).
pub(super) fn switch(enable: bool) -> FileEventId {
    let mut events = FILE_EVENTS.lock();
    ENABLED.store(enable, Ordering::Release);
    events.next_id()
}

/// The title-terminate routine suppresses the ending title's events.
pub(super) fn suppress_title(title: u32) {
    FILE_EVENTS.lock().suppressed = Some(title);
}

/// Take the next identifier and store it at `output` under the lock.
fn assign_id(output: u32) -> FileEventId {
    let mut events = FILE_EVENTS.lock();
    let id = events.next_id();
    write_u32(output, id.0);
    id
}

/// Send `text`; the export result word.
fn send(text: &FileEventText) -> u32 {
    notification_result(send_notification_text(text.as_bytes()))
}

fn event_time() -> u64 {
    // A zero low word is read again.
    match Timebase::now().ticks() {
        time if time as u32 == 0 => Timebase::now().ticks(),
        time => time,
    }
}

fn current_thread_id() -> u32 {
    read_u32(current_thread() + THREAD_ID)
}

/// Path text of an optional ANSI_STRING (+0 u16 Length, +4 Buffer); none
/// without a buffer.
fn ansi_path<'a>(string: u32) -> Option<EventPath<'a>> {
    if string == 0 {
        return None;
    }
    let buffer = read_u32(string + 4);
    if buffer == 0 {
        return None;
    }
    let length = (read_u32(string) >> 16) as u16;
    Some(EventPath {
        length,
        text: c_string(buffer, usize::from(length)),
    })
}

fn string<'a>(address: u32) -> &'a [u8] {
    c_string(address, FILE_EVENT_TEXT_LIMIT)
}

fn announce_switch(enable: bool) -> u32 {
    let text = format_file_event_switch(enable, switch(enable));
    notification_result(send_notification_text(text.as_bytes()))
}

/// Export 152 (stock 0x91f2f428): enable the notifications and announce
/// `XBDMFE!Start`; the result of export 36.
extern "C" fn start() -> u32 {
    announce_switch(true)
}

/// Export 153 (stock 0x91f2f4c0): disable them and announce `XBDMFE!Stop`.
extern "C" fn stop() -> u32 {
    announce_switch(false)
}

/// Export 154 (stock 0x91f2f558): `(message) -> HRESULT`.
extern "C" fn marker(message: u32) -> u32 {
    if message == 0 {
        return BAD_PARAMETER.0;
    }
    if !enabled() {
        return Hresult::OK.0;
    }
    send(&format_marker(string(message)))
}

/// Export 155 (stock 0x91f2fa50): `(library, path, options, id) -> HRESULT`;
/// `path` is an optional ANSI_STRING, `id` receives the event identifier.
extern "C" fn pseudo_begin(library: u32, path: u32, options: u32, id: u32) -> u32 {
    if id == 0 || library == 0 {
        return BAD_PARAMETER.0;
    }
    if !enabled() {
        return Hresult::OK.0;
    }
    let id = assign_id(id);
    let thread_id = current_thread_id();
    let event = PseudoBegin {
        id,
        library: string(library),
        time_base: event_time(),
        thread_id,
        options,
        path: ansi_path(path),
    };
    send(&format_pseudo_begin(&event))
}

/// Export 156 (stock 0x91f2fbf0): `(handle, result, id) -> HRESULT`.
extern "C" fn pseudo_end(handle: u32, result: u32, id: u32) -> u32 {
    if !enabled() {
        return Hresult::OK.0;
    }
    send(&format_pseudo_end(
        FileEventId(id),
        event_time(),
        Some(handle),
        Hresult(result),
    ))
}

/// Export 157 (stock 0x91f2fc70): `(library, handle, operation, event,
/// bytes, offset, options, id) -> HRESULT`; `event` (a string) and `offset`
/// (a 64-bit value) are optional, `id` receives the event identifier.
#[expect(clippy::too_many_arguments, reason = "the export's ABI")]
extern "C" fn pseudo_begin_io(
    library: u32,
    handle: u32,
    operation: u32,
    event: u32,
    bytes: u32,
    offset: u32,
    options: u32,
    id: u32,
) -> u32 {
    if id == 0 || library == 0 {
        return BAD_PARAMETER.0;
    }
    if !enabled() {
        return Hresult::OK.0;
    }
    let id = assign_id(id);
    let offset = if offset == 0 { 0 } else { read_u64(offset) };
    let thread_id = current_thread_id();
    let event = PseudoBeginIo {
        id,
        library: string(library),
        time_base: event_time(),
        operation,
        event: if event == 0 { b"" } else { string(event) },
        thread_id,
        handle,
        offset,
        bytes,
        options,
    };
    send(&format_pseudo_begin_io(&event))
}

/// Export 158 (stock 0x91f2fe48): `(result, id) -> HRESULT`.
extern "C" fn pseudo_end_result(result: u32, id: u32) -> u32 {
    if !enabled() {
        return Hresult::OK.0;
    }
    send(&format_pseudo_end(
        FileEventId(id),
        event_time(),
        None,
        Hresult(result),
    ))
}

/// Export 159 (stock 0x91f2fec8): `(library) -> HRESULT`.
extern "C" fn mark_thread(library: u32) -> u32 {
    if library == 0 {
        return BAD_PARAMETER.0;
    }
    if !enabled() {
        return Hresult::OK.0;
    }
    send(&format_mark_thread(string(library), current_thread_id()))
}

/// Export 160 (stock 0x91f2ff40).
extern "C" fn unmark_thread() -> u32 {
    if !enabled() {
        return Hresult::OK.0;
    }
    send(&format_unmark_thread(current_thread_id()))
}

/// Kernel file event record (0x28 bytes).
const EVENT_ID: u32 = 0x0;
const EVENT_OPERATION: u32 = 0x4;
const EVENT_HANDLE: u32 = 0x8;
const EVENT_ATTRIBUTES: u32 = 0xc;
const EVENT_STATUS: u32 = 0x10;
const EVENT_LENGTH: u32 = 0x14;
const EVENT_OFFSET: u32 = 0x18;
const EVENT_OPTIONS: u32 = 0x24;
/// File mode and create option bits.
const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x8;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;

/// Monitor control code 0x64 (stock 0x91f2f5c8): a file service is about
/// to run. Assigns the record its event identifier and announces
/// `XBDMFE!Begin`. The service always runs.
pub(crate) fn service_file_event_begin(record: u32) -> u32 {
    if record == 0 || !enabled() {
        return 0;
    }
    let id = {
        let mut events = FILE_EVENTS.lock();
        if events.reports() {
            let id = events.next_id();
            write_u32(record + EVENT_ID, id.0);
            Some(id)
        } else {
            None
        }
    };
    let Some(id) = id else { return 0 };
    let operation = read_u32(record + EVENT_OPERATION);
    let handle = read_u32(record + EVENT_HANDLE);
    let mut offset = 0u64;
    let mut flags = 0u32;
    match operation {
        3..=6 => {
            let pointer = read_u32(record + EVENT_OFFSET);
            let requested = if pointer == 0 { 0 } else { read_u64(pointer) };
            if requested != 0 {
                offset = requested;
            } else {
                let mut position = 0u64;
                let mut io_status = IoStatusBlock::default();
                // SAFETY: `position` holds the 8-byte result; the handle is
                // the caller's file in its I/O request.
                let status = unsafe {
                    xboxkrnl::NtQueryInformationFile(
                        Handle::from_raw(handle),
                        &mut io_status,
                        (&raw mut position).cast(),
                        8,
                        FileInformationClass::Position,
                    )
                };
                if (status.0 as i32) >= 0 {
                    offset = position;
                }
            }
            let mut mode = 0u32;
            let mut io_status = IoStatusBlock::default();
            // SAFETY: `mode` holds the 4-byte result.
            let status = unsafe {
                xboxkrnl::NtQueryInformationFile(
                    Handle::from_raw(handle),
                    &mut io_status,
                    (&raw mut mode).cast(),
                    4,
                    FileInformationClass::Mode,
                )
            };
            if (status.0 as i32) >= 0 {
                flags = mode_flags(mode);
            }
            if matches!(operation, 5 | 6) {
                flags |= FLAG_SCATTER_GATHER;
            }
        }
        0 | 1 => flags = mode_flags(read_u32(record + EVENT_OPTIONS)),
        _ => {}
    }
    let thread_id = current_thread_id();
    let time_base = event_time();
    let path = if matches!(operation, 0 | 1) {
        match read_u32(record + EVENT_ATTRIBUTES) {
            0 => None,
            attributes => ansi_path(read_u32(attributes + 4)),
        }
    } else {
        None
    };
    let event = FileEventBegin {
        id,
        time_base,
        kind: file_event_kind(operation),
        thread_id,
        handle,
        offset,
        bytes: read_u32(record + EVENT_LENGTH),
        flags,
        path,
    };
    send(&format_file_event_begin(&event));
    0
}

/// Begin flags from file mode or create option bits.
fn mode_flags(mode: u32) -> u32 {
    let mut flags = 0;
    if mode & FILE_SYNCHRONOUS_IO_NONALERT != 0 {
        flags |= FLAG_SYNCHRONOUS;
    }
    if mode & FILE_NO_INTERMEDIATE_BUFFERING == 0 {
        flags |= FLAG_BUFFERED;
    }
    flags
}

/// Monitor control code 0x65 (stock 0x91f2f930): a file service finished;
/// announces `XBDMFE!End` for a record that got an identifier.
pub(crate) fn service_file_event_end(record: u32) -> u32 {
    if record == 0 {
        return 0;
    }
    let id = read_u32(record + EVENT_ID);
    if id == 0 || !enabled() {
        return 0;
    }
    let time_base = event_time();
    if !FileEvents::reports(&mut FILE_EVENTS.lock()) {
        return 0;
    }
    let text = format_file_event_end(
        FileEventId(id),
        time_base,
        read_u32(record + EVENT_HANDLE),
        NtStatus(read_u32(record + EVENT_STATUS)),
    );
    send(&text);
    0
}
