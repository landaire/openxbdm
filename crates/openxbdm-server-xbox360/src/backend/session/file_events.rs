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
use openxbdm_server::commands::session::FileEventBegin;
use openxbdm_server::commands::session::FileEventFlags;
use openxbdm_server::commands::session::FileEventId;
use openxbdm_server::commands::session::FileEventText;
use openxbdm_server::commands::session::PseudoBegin;
use openxbdm_server::commands::session::PseudoBeginIo;
use openxbdm_server::commands::session::PseudoOptions;
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
use xbox360::thread::current_object;
use xbox360::time::Timebase;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::ObjectAttributes;

use super::current_title_id;
use super::notifications::notification_result;
use super::notifications::send_notification_text;
use crate::backend::debugger::ansi_string_length;
use crate::exports::export;
use crate::kernel;

const BAD_PARAMETER: Hresult = ErrorCode::BadParameter.hresult();

static FILE_EVENTS: SpinLock<FileEvents> = SpinLock::new(FileEvents {
    last_id: FileEventId(0),
    suppressed: None,
});
/// Enable flag (stock 0x91f9f628): set under the lock, read without it, as
/// stock does.
static ENABLED: AtomicBool = AtomicBool::new(false);

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
    /// The dashboard and this system title never report.
    const DASHBOARD_TITLE: u32 = 0xfffe_07d1;
    const SYSTEM_TITLE: u32 = 0xfffe_07ff;

    fn next_id(&mut self) -> FileEventId {
        self.last_id = self.last_id.next();
        self.last_id
    }

    /// Whether the running title reports events; a different title ends
    /// the suppression.
    fn reports(&mut self) -> bool {
        let title = current_title_id();
        if title == Self::DASHBOARD_TITLE
            || title == Self::SYSTEM_TITLE
            || self.suppressed == Some(title)
        {
            return false;
        }

        self.suppressed = None;

        true
    }
}

/// Event record a kernel file service passes with control codes 0x64 and
/// 0x65; the service waits for the code to return.
#[repr(C)]
struct FileEventRecord {
    /// Event identifier the begin code assigns; 0 for none.
    id: u32,
    operation: u32,
    handle: u32,
    /// Object attributes of an open, or 0.
    attributes: u32,
    status: NtStatus,
    length: u32,
    /// Address of the 64-bit byte offset of a transfer, or 0.
    offset: u32,
    _reserved_1c: [u32; 2],
    /// Create options of an open.
    options: CreateOptions,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(FileEventRecord, operation) == 0x4);
    assert!(offset_of!(FileEventRecord, handle) == 0x8);
    assert!(offset_of!(FileEventRecord, attributes) == 0xc);
    assert!(offset_of!(FileEventRecord, status) == 0x10);
    assert!(offset_of!(FileEventRecord, length) == 0x14);
    assert!(offset_of!(FileEventRecord, offset) == 0x18);
    assert!(offset_of!(FileEventRecord, options) == 0x24);
    assert!(core::mem::size_of::<FileEventRecord>() == 0x28);
};

/// What a record's operation number tells the begin event.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OperationClass {
    /// Operations 0 and 1 open a file by path, with create options.
    Open,
    /// Operations 3 to 6 transfer data at a byte offset; 5 and 6 are
    /// scatter/gather transfers.
    Transfer {
        scatter_gather: bool,
    },
    Other,
}

impl OperationClass {
    #[inline(always)]
    const fn of(operation: u32) -> Self {
        match operation {
            0 | 1 => Self::Open,
            3 | 4 => Self::Transfer {
                scatter_gather: false,
            },
            5 | 6 => Self::Transfer {
                scatter_gather: true,
            },
            _ => Self::Other,
        }
    }
}

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

/// Take the next identifier and store it in `output` under the lock.
fn assign_id(output: &mut u32) -> FileEventId {
    let mut events = FILE_EVENTS.lock();
    let id = events.next_id();
    *output = id.0;

    id
}

/// The identifier word an export receives the event identifier in.
///
/// # Safety
///
/// `address` must be the nonzero address of a writable word that nothing
/// else uses during the call.
#[inline(always)]
unsafe fn id_word<'a>(address: u32) -> &'a mut u32 {
    // SAFETY: the caller guarantees the word.
    unsafe { &mut *core::ptr::with_exposed_provenance_mut::<u32>(address as usize) }
}

/// Send `text`; the export result.
fn send(text: &FileEventText) -> Hresult {
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
    current_object().id().raw()
}

/// Path text of an optional ANSI_STRING; none without a buffer.
///
/// # Safety
///
/// `string` must be null or point to an ANSI_STRING whose buffer is null
/// or readable up to its NUL or `length` bytes, for `'a`.
unsafe fn ansi_path<'a>(string: *const AnsiString) -> Option<EventPath<'a>> {
    // SAFETY: the caller guarantees the string.
    let string = unsafe { string.as_ref() }?;
    let length = ansi_string_length(string);

    // SAFETY: the caller guarantees the buffer.
    let text =
        unsafe { kernel::bounded_c_string(string.buffer as usize as u32, usize::from(length)) }?;

    Some(EventPath { length, text })
}

/// A string an export receives, read for at most the event text limit.
///
/// # Safety
///
/// `address` must not be 0 (stock reads it without a check), and as for
/// [`kernel::bounded_c_string`] with that limit.
unsafe fn string<'a>(address: u32) -> &'a [u8] {
    // SAFETY: the caller guarantees a string at a nonzero address.
    unsafe { kernel::bounded_c_string(address, FILE_EVENT_TEXT_LIMIT).unwrap_unchecked() }
}

fn announce_switch(enable: bool) -> Hresult {
    let text = format_file_event_switch(enable, switch(enable));

    notification_result(send_notification_text(text.as_bytes()))
}

/// Export 152 (stock 0x91f2f428): enable the notifications and announce
/// `XBDMFE!Start`; the result of export 36.
extern "C" fn start() -> Hresult {
    announce_switch(true)
}

/// Export 153 (stock 0x91f2f4c0): disable them and announce `XBDMFE!Stop`.
extern "C" fn stop() -> Hresult {
    announce_switch(false)
}

/// Export 154 (stock 0x91f2f558): `(message) -> HRESULT`.
extern "C" fn marker(message: u32) -> Hresult {
    if message == 0 {
        return BAD_PARAMETER;
    }

    if !enabled() {
        return Hresult::OK;
    }

    // SAFETY: callers pass a NUL-terminated message.
    send(&format_marker(unsafe { string(message) }))
}

/// Export 155 (stock 0x91f2fa50): `(library, path, options, id) -> HRESULT`;
/// `path` is an optional ANSI_STRING, `id` receives the event identifier.
extern "C" fn pseudo_begin(library: u32, path: u32, options: u32, id: u32) -> Hresult {
    if id == 0 || library == 0 {
        return BAD_PARAMETER;
    }

    if !enabled() {
        return Hresult::OK;
    }

    // SAFETY: callers pass a writable identifier word.
    let id = assign_id(unsafe { id_word(id) });
    let thread_id = current_thread_id();
    let event = PseudoBegin {
        id,
        // SAFETY: callers pass a NUL-terminated library name.
        library: unsafe { string(library) },
        time_base: event_time(),
        thread_id,
        options: PseudoOptions::from_bits_retain(options),
        // SAFETY: callers pass 0 or an ANSI_STRING.
        path: unsafe { ansi_path(core::ptr::with_exposed_provenance(path as usize)) },
    };

    send(&format_pseudo_begin(&event))
}

/// Export 156 (stock 0x91f2fbf0): `(handle, result, id) -> HRESULT`.
extern "C" fn pseudo_end(handle: u32, result: Hresult, id: u32) -> Hresult {
    if !enabled() {
        return Hresult::OK;
    }

    send(&format_pseudo_end(
        FileEventId(id),
        event_time(),
        Some(handle),
        result,
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
) -> Hresult {
    if id == 0 || library == 0 {
        return BAD_PARAMETER;
    }

    if !enabled() {
        return Hresult::OK;
    }

    // SAFETY: callers pass a writable identifier word.
    let id = assign_id(unsafe { id_word(id) });
    let offset = if offset == 0 {
        0
    } else {
        // SAFETY: callers pass 0 or the address of a 64-bit offset, which
        // stock reads without alignment.
        unsafe { core::ptr::with_exposed_provenance::<u64>(offset as usize).read_unaligned() }
    };
    let thread_id = current_thread_id();
    let event = PseudoBeginIo {
        id,
        // SAFETY: callers pass a NUL-terminated library name.
        library: unsafe { string(library) },
        time_base: event_time(),
        operation,
        // SAFETY: callers pass 0 or a NUL-terminated event name.
        event: if event == 0 {
            b""
        } else {
            unsafe { string(event) }
        },
        thread_id,
        handle,
        offset,
        bytes,
        options: PseudoOptions::from_bits_retain(options),
    };

    send(&format_pseudo_begin_io(&event))
}

/// Export 158 (stock 0x91f2fe48): `(result, id) -> HRESULT`.
extern "C" fn pseudo_end_result(result: Hresult, id: u32) -> Hresult {
    if !enabled() {
        return Hresult::OK;
    }

    send(&format_pseudo_end(
        FileEventId(id),
        event_time(),
        None,
        result,
    ))
}

/// Export 159 (stock 0x91f2fec8): `(library) -> HRESULT`.
extern "C" fn mark_thread(library: u32) -> Hresult {
    if library == 0 {
        return BAD_PARAMETER;
    }

    if !enabled() {
        return Hresult::OK;
    }

    // SAFETY: callers pass a NUL-terminated library name.
    send(&format_mark_thread(
        unsafe { string(library) },
        current_thread_id(),
    ))
}

/// Export 160 (stock 0x91f2ff40).
extern "C" fn unmark_thread() -> Hresult {
    if !enabled() {
        return Hresult::OK;
    }

    send(&format_unmark_thread(current_thread_id()))
}

/// Monitor control code 0x64 (stock 0x91f2f5c8): a file service is about
/// to run. Assigns the record its event identifier and announces
/// `XBDMFE!Begin`. The service always runs.
///
/// # Safety
///
/// `record` must be 0 or the address of the file service's event record,
/// which the service leaves alone until the code returns.
pub(crate) unsafe fn service_file_event_begin(record: u32) -> u32 {
    // SAFETY: the caller's contract.
    let Some(record) = (unsafe {
        core::ptr::with_exposed_provenance_mut::<FileEventRecord>(record as usize).as_mut()
    }) else {
        return 0;
    };

    if !enabled() {
        return 0;
    }

    let id = {
        let mut events = FILE_EVENTS.lock();
        if events.reports() {
            let id = events.next_id();
            record.id = id.0;
            Some(id)
        } else {
            None
        }
    };
    let Some(id) = id else {
        return 0;
    };

    let operation = record.operation;
    let class = OperationClass::of(operation);
    let handle = record.handle;
    let (offset, flags) = match class {
        OperationClass::Transfer { scatter_gather } => {
            let requested = if record.offset == 0 {
                0
            } else {
                // SAFETY: a transfer record holds 0 or the address of the
                // caller's byte offset, which stock reads without alignment.
                unsafe {
                    core::ptr::with_exposed_provenance::<u64>(record.offset as usize)
                        .read_unaligned()
                }
            };
            let offset = if requested != 0 {
                requested
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
                        core::mem::size_of::<u64>() as u32,
                        FileInformationClass::Position,
                    )
                };
                if status.is_success() { position } else { 0 }
            };

            let mut mode = CreateOptions::empty();
            let mut io_status = IoStatusBlock::default();
            // SAFETY: `mode` holds the 4-byte result.
            let status = unsafe {
                xboxkrnl::NtQueryInformationFile(
                    Handle::from_raw(handle),
                    &mut io_status,
                    (&raw mut mode).cast(),
                    core::mem::size_of::<CreateOptions>() as u32,
                    FileInformationClass::Mode,
                )
            };
            let mut flags = if status.is_success() {
                mode_flags(mode)
            } else {
                FileEventFlags::empty()
            };
            if scatter_gather {
                flags |= FileEventFlags::SCATTER_GATHER;
            }

            (offset, flags)
        }
        OperationClass::Open => (0, mode_flags(record.options)),
        OperationClass::Other => (0, FileEventFlags::empty()),
    };

    let thread_id = current_thread_id();
    let time_base = event_time();
    let path = if class == OperationClass::Open {
        // SAFETY: an open record holds 0 or the address of the caller's
        // object attributes, whose name is 0 or an ANSI_STRING.
        unsafe {
            core::ptr::with_exposed_provenance::<ObjectAttributes>(record.attributes as usize)
                .as_ref()
                .and_then(|attributes| ansi_path(attributes.object_name))
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
        bytes: record.length,
        flags,
        path,
    };
    send(&format_file_event_begin(&event));

    0
}

/// Begin flags from file mode or create option bits.
fn mode_flags(mode: CreateOptions) -> FileEventFlags {
    let mut flags = FileEventFlags::empty();

    if mode.contains(CreateOptions::SYNCHRONOUS_IO_NONALERT) {
        flags |= FileEventFlags::SYNCHRONOUS;
    }

    if !mode.contains(CreateOptions::NO_INTERMEDIATE_BUFFERING) {
        flags |= FileEventFlags::BUFFERED;
    }

    flags
}

/// Monitor control code 0x65 (stock 0x91f2f930): a file service finished;
/// announces `XBDMFE!End` for a record that got an identifier.
///
/// # Safety
///
/// As for [`service_file_event_begin`].
pub(crate) unsafe fn service_file_event_end(record: u32) -> u32 {
    // SAFETY: the caller's contract.
    let Some(record) = (unsafe {
        core::ptr::with_exposed_provenance::<FileEventRecord>(record as usize).as_ref()
    }) else {
        return 0;
    };

    let id = record.id;
    if id == 0 || !enabled() {
        return 0;
    }

    let time_base = event_time();
    if !FileEvents::reports(&mut FILE_EVENTS.lock()) {
        return 0;
    }

    let text = format_file_event_end(FileEventId(id), time_base, record.handle, record.status);
    send(&text);

    0
}
