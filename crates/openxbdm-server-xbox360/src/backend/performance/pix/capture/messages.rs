//! Session message processing at each frame (stock 0x91f619d8) and the
//! handlers. A handler returning `false` keeps its message for the next
//! frame with the step count advanced; `true` finishes it.
//!
//! Codes: 1 capture frames (`pixcmd c`, code 0x53), 3 and 4 instruction
//! trace (`t`, `k`), 5 capture to file (`a`, `h`, code 0x54), 6 record
//! configuration (`o`), 7 write frames (`d`), 8 write frames with title
//! routines, 10 pause (`p`), 11 resume (`g`), 12 video operation (`v`), 13
//! pause flag, 15 resource capture state (`u`); 9 and 14 (`w`) are
//! refused.

use core::fmt::Write as _;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_server::text::Text;
use xbox360::thread::current_object;
use xbox360::time::TickCount;
use xbox360::time::Timebase;
use xbox360_sys::status::Hresult;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::XAudioRegisterRenderDriverClient;
use xbox360_sys::xboxkrnl::XAudioUnregisterRenderDriverClient;

use super::super::backend::EVENT_NAME_BYTES;
use super::super::events;
use super::super::events::CallbackOperation;
use super::super::files;
use super::super::files::CaptureFile;
use super::super::plugin;
use super::super::plugin::PluginProcedure;
use super::super::ring;
use super::super::session;
use super::super::session::EngineFlags;
use super::super::session::EngineMessage;
use super::super::session::FrameRecord;
use super::super::session::MESSAGE_PAYLOAD_SIZE;
use super::super::session::MemoryKind;
use super::super::session::Part;
use super::super::session::PartStream;
use super::super::session::PixSession;
use super::super::session::StreamId;
use super::super::status::Status;
use super::super::status::post_without_text as post_status;
use super::FrameState;
use super::buffers;
use super::buffers::BUFFER_BYTES;
use super::engine;
use super::replay;
use super::video;
use super::video::VideoContextFlags;
use crate::backend::debugger::MonitorRecordFlags;
use crate::kernel;

const UNNAMED: &core::ffi::CStr = c"unnamed.pix2";
/// Configuration word of a part writing stream 0.
const FIRST_STREAM: PartStream = PartStream(StreamId::First.raw());

xbox360_sys::flags! {
    /// Capture support the title reports in its frame record flags word.
    pub struct FrameSupport(u32) {
        /// Per-thread timing capture (message 1).
        TIMING_CAPTURE = 0x1,
        /// Capture to file (message 5).
        FILE_CAPTURE = 0x2,
    }
}

/// Monitor record flags the pause replaces, and their value while paused.
const PAUSE_MASK: MonitorRecordFlags = MonitorRecordFlags::EXEMPT
    .union(MonitorRecordFlags::DEBUGGABLE)
    .union(MonitorRecordFlags::CAPTURE_PAUSE);
const PAUSED: MonitorRecordFlags =
    MonitorRecordFlags::EXEMPT.union(MonitorRecordFlags::CAPTURE_PAUSE);

/// Payload words of an engine message.
type Payload = [AtomicU32; MESSAGE_PAYLOAD_SIZE / 4];

/// Fields of a message payload.
///
/// # Safety
///
/// The implementer is `#[repr(C)]` and has only `AtomicU32` fields or
/// arrays of them.
unsafe trait PayloadFields: Sized {
    fn of(payload: &Payload) -> &Self {
        const { assert!(size_of::<Self>() <= size_of::<Payload>()) };
        // SAFETY: the implementer consists of words, as the payload, and
        // is no larger.
        unsafe { &*core::ptr::from_ref(payload).cast::<Self>() }
    }
}

/// Message 1.
#[repr(C)]
struct CaptureFramesPayload {
    frames: AtomicU32,
    notify: AtomicU32,
    /// Capture file; 0 opens `unnamed.pix2` and stores its handle.
    file: AtomicU32,
}

/// Messages 3 and 4.
#[repr(C)]
struct TracePayload {
    /// Milliseconds at the first step.
    started: AtomicU32,
}

/// Message 5.
#[repr(C)]
struct CaptureToFilePayload {
    notify: AtomicU32,
    /// Capture file; 0 opens `unnamed.pix2` and stores its handle.
    file: AtomicU32,
    /// The plugin captures; it reports busy through `poll`.
    plugin: AtomicU32,
    /// Image `dogma` loaded for the capture.
    image: AtomicU32,
    /// Plugin installer of the capture callbacks.
    installer: AtomicU32,
    /// Submit hook value for the owner.
    information: AtomicU32,
    poll: AtomicU32,
}

/// Message 6.
#[repr(C)]
struct ConfigurationPayload {
    _unknown_00: AtomicU32,
    /// Parts, second threads and second flags: the leading words of
    /// [`session::Configuration`] in its layout.
    threads: [AtomicU32; 6],
    _unknown_1c: AtomicU32,
    title_budget: AtomicU32,
    /// Size of stream 1 in 16 KiB units.
    units: AtomicU32,
    gpu_wait: AtomicU32,
    frame_word: AtomicU32,
}

/// Message 7.
#[repr(C)]
struct WriteFramesPayload {
    first: AtomicU32,
    last: AtomicU32,
    /// Stock traps when 0.
    required: AtomicU32,
}

/// Message 8.
#[repr(C)]
struct ReplayFramesPayload {
    first: AtomicU32,
    last: AtomicU32,
    begin: AtomicU32,
    write: AtomicU32,
    context: AtomicU32,
    mode: AtomicU32,
}

/// Message 12.
#[repr(C)]
struct VideoOperationPayload {
    first: AtomicU32,
    last: AtomicU32,
    operation: AtomicU32,
    argument: AtomicU32,
}

/// Message 13: bit 0 sets [`EngineFlags::PAUSED`].
#[repr(C)]
struct PauseFlagPayload {
    paused: AtomicU32,
}

/// Message 14.
#[repr(C)]
struct PausedVideoPayload {
    first: AtomicU32,
    last: AtomicU32,
    no_gpu: AtomicU32,
}

/// Message 15.
#[repr(C)]
struct ResourceStatePayload {
    active: AtomicU32,
    notify: AtomicU32,
    /// Start or stop the capture through the plugin, else report.
    request: AtomicU32,
    information: [AtomicU32; 3],
}

// SAFETY: each is `#[repr(C)]` of `AtomicU32` words.
unsafe impl PayloadFields for CaptureFramesPayload {}
// SAFETY: as above.
unsafe impl PayloadFields for TracePayload {}
// SAFETY: as above.
unsafe impl PayloadFields for CaptureToFilePayload {}
// SAFETY: as above.
unsafe impl PayloadFields for ConfigurationPayload {}
// SAFETY: as above.
unsafe impl PayloadFields for WriteFramesPayload {}
// SAFETY: as above.
unsafe impl PayloadFields for ReplayFramesPayload {}
// SAFETY: as above.
unsafe impl PayloadFields for VideoOperationPayload {}
// SAFETY: as above.
unsafe impl PayloadFields for PauseFlagPayload {}
// SAFETY: as above.
unsafe impl PayloadFields for PausedVideoPayload {}
// SAFETY: as above.
unsafe impl PayloadFields for ResourceStatePayload {}

fn open_unnamed() -> Option<CaptureFile> {
    // SAFETY: a static NUL-terminated name.
    unsafe { files::open(UNNAMED.as_ptr() as usize as u32, true) }
}

fn running(s: &PixSession) -> bool {
    s.engine_flags().contains(EngineFlags::RUNNING)
}

#[inline(never)]
fn stop(s: &PixSession) {
    engine::stop(s, &s.frame_record, false, false);
}

/// Whether the capture buffers are reallocated: the title budget changed,
/// or there are none and `parts_on`.
fn reallocation_needed(s: &PixSession, parts_on: bool) -> bool {
    s.configuration.title_budget.load(Relaxed) != s.budgets[MemoryKind::Title.index()].load(Relaxed)
        || (s.buffer_count.load(Relaxed) == 0 && parts_on)
}

/// Process queued messages (stock 0x91f619d8). `flags` is the frame
/// record's flags word; message 15 reports into `out`.
pub(super) fn dispatch(s: &PixSession, flags: u32, out: &mut FrameState) {
    let support = FrameSupport::from_bits_retain(flags);
    let message = &s.message;
    let mut processed = false;
    loop {
        if message.code.load(Relaxed) == 0 {
            let Some(entry) = session::next_message(s) else {
                break;
            };
            message.copy_from(entry);
            s.step.store(0, Relaxed);
        }
        processed = true;
        let step = s.step.load(Relaxed);
        let payload = &message.payload;
        let done = match message.message() {
            Some(EngineMessage::CaptureFrames) => capture_frames(s, support, step, payload),
            Some(EngineMessage::WaitFrame) => step != 0,
            Some(EngineMessage::TraceFrame) => trace(s, step, payload, false),
            Some(EngineMessage::TraceEvent) => trace(s, step, payload, true),
            Some(EngineMessage::CaptureToFile) => capture_to_file(s, support, step, payload),
            Some(EngineMessage::RecordConfiguration) => {
                record_configuration(s, payload, true);
                processed = false;
                true
            }
            Some(EngineMessage::WriteFrames) => write_frames(s, payload),
            Some(EngineMessage::ReplayFrames) => write_frames_with(s, payload),
            Some(EngineMessage::Pause) => pause(s),
            Some(EngineMessage::VideoOperation) => video_operation(s, payload),
            Some(EngineMessage::PauseFlag) => {
                let paused = PauseFlagPayload::of(payload).paused.load(Relaxed) & 1 != 0;
                let mut flags = s.engine_flags();
                flags.remove(EngineFlags::PAUSED);
                if paused {
                    flags.insert(EngineFlags::PAUSED);
                }
                s.set_engine_flags(flags);
                true
            }
            Some(EngineMessage::ResourceState) => resource_state(payload, out),
            // Resume finishes at once; stock traps on 9, 14 and unknown
            // codes.
            Some(
                EngineMessage::DumpHeader | EngineMessage::Resume | EngineMessage::PausedVideo,
            )
            | None => true,
        };
        if !done {
            s.step.store(step + 1, Relaxed);
            return;
        }
        message.code.store(0, Relaxed);
    }
    if processed
        && s.configuration
            .words()
            .iter()
            .zip(s.requested.words())
            .any(|(current, requested)| current.load(Relaxed) != requested.load(Relaxed))
    {
        apply_requested(s, true);
    }
}

/// Stop, set the per-thread parts, reallocate when needed, and start
/// (stock 0x91f60d50).
fn reconfigure(s: &PixSession, thread: PartStream, second: PartStream, tracing: bool) {
    stop(s);
    let configuration = &s.configuration;
    configuration.set_part(Part::Gpu, PartStream::OFF);
    configuration.set_part(Part::Audio, PartStream::OFF);
    configuration.set_part(Part::Thread, thread);
    configuration.set_part(Part::SecondThread, second);
    configuration.tracing.store(u32::from(tracing), Relaxed);
    if reallocation_needed(s, !thread.is_off() || !second.is_off()) {
        buffers::free(s);
        buffers::allocate_all(s);
    }
    engine::start(s);
}

/// Make the requested configuration current (stock 0x91f60de0), with a
/// stop and start around it when `restart`.
pub(super) fn apply_requested(s: &PixSession, restart: bool) {
    if restart {
        stop(s);
    }
    for (current, requested) in s.configuration.words().iter().zip(s.requested.words()) {
        current.store(requested.load(Relaxed), Relaxed);
    }
    let parts_on = s
        .configuration
        .parts
        .iter()
        .any(|part| !PartStream(part.load(Relaxed)).is_off());
    if reallocation_needed(s, parts_on) {
        buffers::free(s);
        buffers::allocate_all(s);
    }
    if restart {
        engine::start(s);
    }
}

/// Message 1 (stock 0x91f60ea8): capture the next frames, then write them
/// to the file (status 2, or 3 when nothing was written).
fn capture_frames(s: &PixSession, support: FrameSupport, step: u32, payload: &Payload) -> bool {
    let fields = CaptureFramesPayload::of(payload);
    let frames = fields.frames.load(Relaxed);
    if step < frames {
        if !support.contains(FrameSupport::TIMING_CAPTURE) {
            if fields.notify.load(Relaxed) != 0 {
                post_status(Status::BadD3dVersion);
            }
            return true;
        }
        if step == 0 && frames != 0 {
            reconfigure(s, FIRST_STREAM, PartStream::OFF, false);
        }
        return false;
    }
    stop(s);
    let mut written = false;
    let file = match fields.file.load(Relaxed) {
        0 => open_unnamed().map(|file| file.0),
        file => Some(file),
    };
    if let Some(file) = file {
        fields.file.store(file, Relaxed);
        written = replay::write_stream(s, file, frames, frames);
        // SAFETY: the capture file handle, not used after the write.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(file)) };
    }
    engine::start(s);
    if fields.notify.load(Relaxed) != 0 {
        post_status(if written { Status::Timing } else { Status::No });
    }
    true
}

/// Messages 3 and 4 (stock 0x91f61140): record an instruction trace of
/// the frame thread. 3 traces one frame; 4 traces the event named by
/// `pixcmd k`, giving up after 10 s.
fn trace(s: &PixSession, step: u32, payload: &Payload, by_event: bool) -> bool {
    const TIMEOUT_MILLISECONDS: u32 = 10_000;
    let fields = TracePayload::of(payload);
    if step == 0 {
        fields
            .started
            .store(TickCount::now().milliseconds(), Relaxed);
        reconfigure(s, PartStream::OFF, PartStream::OFF, by_event);
        if !by_event {
            super::super::super::xtrace::start_default();
        }
        return false;
    }
    if !by_event {
        super::super::super::xtrace::stop();
        post_status(Status::Trace);
        return true;
    }
    let now = TickCount::now().milliseconds();
    if s.message.done.load(Relaxed) != 0 {
        post_status(Status::Trace);
        return true;
    }
    if now.wrapping_sub(fields.started.load(Relaxed)) >= TIMEOUT_MILLISECONDS {
        stop_event_trace();
        post_status(Status::No);
        return true;
    }
    false
}

/// Nesting depth of the traced event (stock 0x91fa2808).
static EVENT_DEPTH: AtomicU32 = AtomicU32::new(0);

/// Begin of a named event on the trace capture thread (stock 0x91f557c0):
/// the event `pixcmd k` names starts the trace once its countdown ends.
fn trace_event_begin(name: &[u8; EVENT_NAME_BYTES]) {
    if !on_capture_thread() {
        return;
    }
    let depth = EVENT_DEPTH.load(Ordering::Acquire);
    if depth != 0 {
        EVENT_DEPTH.store(depth + 1, Ordering::Release);
        return;
    }
    let text = super::super::backend::capture_text();
    let end = name
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(name.len());
    let text_end = text
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(text.len());
    if name[..end] != text[..text_end] {
        return;
    }
    if super::super::backend::count_down_capture() {
        EVENT_DEPTH.store(1, Ordering::Release);
        super::super::super::xtrace::start_default();
    }
}

fn on_capture_thread() -> bool {
    super::super::backend::capture_thread()
        == Some(u32::from(current_object().hardware_thread().get()))
}

/// Timing request on the trace capture path (stock 0x91f558e0): type 0
/// begins an event, type 1 ends one; true when the traced event ended.
pub(super) fn trace_event(kind: u32, name: &[u8; EVENT_NAME_BYTES]) -> bool {
    const BEGIN: u32 = 0;
    const END: u32 = 1;
    match kind {
        BEGIN => trace_event_begin(name),
        END if on_capture_thread() => {
            let depth = EVENT_DEPTH.load(Ordering::Acquire);
            if depth != 0 {
                EVENT_DEPTH.store(depth - 1, Ordering::Release);
                if depth == 1 {
                    super::super::backend::clear_capture_thread();
                    super::super::super::xtrace::stop();
                    return true;
                }
            }
        }
        _ => {}
    }
    false
}

/// Stock 0x91f558b0.
fn stop_event_trace() {
    super::super::super::xtrace::stop();
    EVENT_DEPTH.store(0, Ordering::Release);
}

/// Message 5 (stock 0x91f60fb0): write per-thread timing data to the
/// capture file until the next frame, or while the plugin reports busy.
fn capture_to_file(s: &PixSession, support: FrameSupport, step: u32, payload: &Payload) -> bool {
    let fields = CaptureToFilePayload::of(payload);
    let plugin = fields.plugin.load(Relaxed) != 0;
    if step >= 1 {
        if plugin && !plugin_finished(fields.poll.load(Relaxed)) {
            return false;
        }
        files::set_capture_file(None);
        let file = CaptureFile(fields.file.load(Relaxed));
        files::write_words(file, &[replay::END_RECORD]);
        // SAFETY: the capture file handle, detached above.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(file.0)) };
        if fields.notify.load(Relaxed) != 0 {
            post_status(Status::Gpu);
        }
        // Stock unloads the image here and once more for plugin captures.
        if plugin::handle().is_none() && fields.image.load(Relaxed) != 0 {
            // SAFETY: the image `dogma` loaded for this capture; its slot
            // is cleared below.
            unsafe { xboxkrnl::XexUnloadImage(fields.image.load(Relaxed)) };
            fields.image.store(0, Relaxed);
        }
        return true;
    }
    if !support.contains(FrameSupport::FILE_CAPTURE) && !plugin {
        if fields.notify.load(Relaxed) != 0 {
            post_status(Status::BadD3dVersion);
        }
        return true;
    }
    reconfigure(s, PartStream::OFF, PartStream::OFF, true);
    if fields.file.load(Relaxed) == 0
        && let Some(file) = open_unnamed()
    {
        fields.file.store(file.0, Relaxed);
    }
    let file = CaptureFile(fields.file.load(Relaxed));
    files::set_capture_file(Some(file));
    files::write_words(file, &[replay::TIMING_START_RECORD]);
    if plugin {
        plugin::install_callbacks(fields.installer.load(Relaxed));
        events::notify_owner(
            CallbackOperation::SubmitHook,
            fields.information.load(Relaxed),
        );
    }
    false
}

/// Poll the plugin's capture routine (stock 0x91f58e90): finished unless
/// it reports `E_PENDING`; the owner then forgets the hook and the plugin
/// is attached again.
fn plugin_finished(poll: u32) -> bool {
    // SAFETY: the plugin's export without arguments.
    let result = Hresult(unsafe { kernel::call_export(poll, 0, 0, 0, 0) });
    if result == Hresult::PENDING {
        return false;
    }
    events::notify_owner(CallbackOperation::SubmitHook, 0);
    plugin::restart();
    true
}

/// Message 6 (stock 0x91f61330): store a requested configuration, reset
/// stream 1, and apply it.
fn record_configuration(s: &PixSession, payload: &Payload, restart: bool) {
    let fields = ConfigurationPayload::of(payload);
    if restart {
        stop(s);
    }
    let requested = &s.requested;
    for word in requested.words() {
        word.store(0, Relaxed);
    }
    const {
        assert!(
            core::mem::offset_of!(session::Configuration, second_flags)
                == 5 * size_of::<AtomicU32>()
        );
    };
    for (target, source) in requested.words().iter().zip(&fields.threads) {
        target.store(source.load(Relaxed), Relaxed);
    }
    requested
        .title_budget
        .store(fields.title_budget.load(Relaxed), Relaxed);
    requested
        .gpu_wait
        .store(fields.gpu_wait.load(Relaxed), Relaxed);
    requested
        .frame_word
        .store(fields.frame_word.load(Relaxed), Relaxed);
    let stream = s.stream(StreamId::Second);
    for entry in &stream.table {
        entry.generation().store(session::EMPTY_GENERATION, Relaxed);
    }
    stream.offset.set(0);
    stream.sequence.store(0, Relaxed);
    stream
        .size
        .set(u64::from(fields.units.load(Relaxed)) * u64::from(BUFFER_BYTES));
    apply_requested(s, false);
    if restart {
        engine::capture_record(s);
    }
    let first = requested.part(Part::Thread);
    if first != s.configuration.part(Part::Thread)
        && first == FIRST_STREAM
        && s.stream(StreamId::First).handle.load(Relaxed) == 0
    {
        post_status(Status::NoHarddrive);
    }
    if restart {
        engine::start(s);
    }
}

/// Message 7 (stock 0x91f5eb00): write frames of the dump partition to
/// `unnamed.pix2` (status 2, else 6).
fn write_frames(s: &PixSession, payload: &Payload) -> bool {
    let fields = WriteFramesPayload::of(payload);
    if fields.required.load(Relaxed) == 0 {
        return true;
    }
    let mut written = false;
    if !running(s)
        && let Some(file) = open_unnamed()
    {
        written = replay::write_stream(
            s,
            file.0,
            fields.first.load(Relaxed),
            fields.last.load(Relaxed),
        );
        // SAFETY: the file opened above, not used after the write.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(file.0)) };
    }
    post_status(if written {
        Status::Timing
    } else {
        Status::NoFrame
    });
    true
}

/// Message 8 (stock 0x91f614d0): replay the dump partition through the
/// title's routines.
fn write_frames_with(s: &PixSession, payload: &Payload) -> bool {
    let fields = ReplayFramesPayload::of(payload);
    let running = running(s);
    if running {
        stop(s);
    }
    // SAFETY: only code 0x57 queues message 8 (the server's `pixcmd`
    // never posts it), and its contract covers the routines.
    unsafe {
        replay::replay(
            s,
            fields.begin.load(Relaxed),
            fields.write.load(Relaxed),
            fields.context.load(Relaxed),
            fields.mode.load(Relaxed),
            fields.first.load(Relaxed),
            fields.last.load(Relaxed),
        )
    };
    if running {
        engine::start(s);
    }
    true
}

/// Message 12 (stock 0x91f61568): run a video operation over captured
/// frames; a failure is reported as `VideoOpError <code>`.
fn video_operation(s: &PixSession, payload: &Payload) -> bool {
    let fields = VideoOperationPayload::of(payload);
    if fields.operation.load(Relaxed) == 0 {
        return true;
    }
    let running = running(s);
    if running {
        stop(s);
    }
    let result = video::run(
        s,
        fields.first.load(Relaxed),
        fields.last.load(Relaxed),
        fields.argument.load(Relaxed),
    );
    if running {
        end_video(s);
        engine::start(s);
    }
    if let Err(error) = result {
        let mut text: Text<0x40> = Text::new();
        let _ = write!(text, "{}\0", error.code() as i32);
        // SAFETY: the code and the NUL fit in `text`, which outlives the
        // call.
        unsafe {
            super::super::status::post(
                Status::VideoOpError,
                text.as_bytes().as_ptr() as usize as u32,
            )
        };
    }
    true
}

/// End of a video operation (stock 0x91f5a488): the frame record's
/// completion routine runs once.
pub(super) fn end_video(s: &PixSession) {
    let flags = &s.video.flags;
    if VideoContextFlags::from_bits_retain(flags.load(Relaxed))
        .contains(VideoContextFlags::COMPLETION)
    {
        let record = &s.frame_record;
        // SAFETY: the title's frame record names a routine taking one
        // argument.
        unsafe {
            kernel::call_export(
                record.completion_routine.load(Relaxed),
                record.routine_argument.load(Relaxed),
                0,
                0,
                0,
            )
        };
        flags.store(
            VideoContextFlags::from_bits_retain(flags.load(Relaxed))
                .difference(VideoContextFlags::COMPLETION)
                .bits(),
            Relaxed,
        );
    }
}

/// Message 15 (stock 0x91f5d270): report the resource capture state into
/// the frame flags, or start or stop it through the plugin.
fn resource_state(payload: &Payload, out: &mut FrameState) -> bool {
    let fields = ResourceStatePayload::of(payload);
    let active = fields.active.load(Relaxed) != 0;
    if fields.request.load(Relaxed) == 0 {
        if active {
            *out |= FrameState::RESOURCE_ACTIVE;
        } else {
            *out |= FrameState::RESOURCE_INACTIVE;
            if fields.notify.load(Relaxed) != 0 {
                *out |= FrameState::RESOURCE_NOTIFY;
            }
        }
    } else {
        let (procedure, refusal) = if active {
            (
                plugin::procedure(PluginProcedure::StartResourceCapture),
                c"PIX!StartFailed ResourceCapture",
            )
        } else {
            (
                plugin::procedure(PluginProcedure::StopResourceCapture),
                c"PIX!NotActive ResourceCapture",
            )
        };
        if let Some(procedure) = procedure {
            // SAFETY: the plugin's resource capture routines take two
            // arguments, the message payload and the frame state, which
            // they may update.
            unsafe {
                kernel::call_export(
                    procedure,
                    crate::kernel::address_of(payload),
                    core::ptr::from_mut(out).expose_provenance() as u32,
                    0,
                    0,
                )
            };
        } else {
            // SAFETY: `refusal` is a static NUL-terminated string.
            unsafe {
                crate::backend::session::service_send_notification(refusal.as_ptr() as usize as u32)
            };
        }
    }
    super::super::set_resource_information(&fields.information);
    true
}

/// Message 10 (stock 0x91f617b0): pause the title until a resume message.
/// The frame thread services messages while paused; a message other than
/// 11 resumes and is handled at the next frame.
fn pause(s: &PixSession) -> bool {
    /// Phases of [`ring::capture_timing`].
    const TIMING_START: u32 = 1;
    const TIMING_END: u32 = 2;
    ring::capture_timing(
        TIMING_START,
        super::active_parts(s),
        Timebase::now().ticks(),
    );
    let record = &s.frame_record;
    if record.stop_routine.load(Relaxed) != 0 {
        s.leave_lock();
        // SAFETY: the title's frame record names a routine taking one
        // argument.
        unsafe {
            kernel::call_export(
                record.stop_routine.load(Relaxed),
                record.routine_argument.load(Relaxed),
                0,
                0,
                0,
            )
        };
        s.enter_lock();
    }
    pause_engine(s);
    post_status(Status::Pause);
    let resumed = loop {
        s.leave_lock();
        s.enter_lock();
        let Some(entry) = session::next_message(s) else {
            continue;
        };
        let payload = &entry.payload;
        match entry.message() {
            Some(EngineMessage::TraceFrame | EngineMessage::TraceEvent) => {
                post_status(Status::No);
            }
            Some(EngineMessage::RecordConfiguration) => record_configuration(s, payload, false),
            Some(EngineMessage::WriteFrames) => {
                write_frames(s, payload);
            }
            Some(EngineMessage::ReplayFrames) => {
                write_frames_with(s, payload);
            }
            Some(EngineMessage::DumpHeader) => replay::dump_header(s, StreamId::Second),
            Some(EngineMessage::Pause) => {}
            Some(EngineMessage::VideoOperation) => {
                video_operation(s, payload);
            }
            Some(EngineMessage::PausedVideo) => paused_video(s, payload),
            _ => break entry,
        }
    };
    resume_engine(s);
    ring::capture_timing(TIMING_END, super::active_parts(s), Timebase::now().ticks());
    if resumed.is(EngineMessage::Resume) {
        return true;
    }
    session::requeue_message(s);
    false
}

/// Message 14 while paused (stock 0x91f5d360): video operation into
/// `unnamed.pix2` (status 13, else 6).
fn paused_video(s: &PixSession, payload: &Payload) {
    let fields = PausedVideoPayload::of(payload);
    let written = open_unnamed().is_some_and(|file| {
        let result = video::write(
            s,
            file.0,
            fields.no_gpu.load(Relaxed),
            fields.first.load(Relaxed),
            fields.last.load(Relaxed),
        );
        // SAFETY: the file opened above, not used after the write.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(file.0)) };
        result.is_ok()
    });
    post_status(if written {
        Status::MovieData
    } else {
        Status::NoFrame
    });
}

/// Stop for the pause (stock 0x91f61610): exempt the frame thread and
/// the audio render thread from execution stops, render silence through
/// a monitor audio client, stop with an execution state notification, and
/// stop controller vibration.
fn pause_engine(s: &PixSession) {
    const CONTROLLER_PORTS: u32 = 4;
    // SAFETY: `resume_engine` leaves the region.
    unsafe { xboxkrnl::KeEnterCriticalRegion() };
    s.video
        .writes_at_pause
        .store(s.thread_writes.load(Relaxed), Relaxed);
    let routine = s.kernel_routine.load(Relaxed);
    if routine != 0 {
        let client = [
            video::render_entry_address(),
            crate::kernel::address_of(&s.render_client),
        ];
        // SAFETY: `client` is live for the call; the handle slot lies in
        // the session block.
        unsafe { XAudioRegisterRenderDriverClient(client.as_ptr(), s.audio_client.as_ptr()) };
        call_kernel_routine(routine, s.audio_client.load(Relaxed), true);
        // SAFETY: takes no arguments. Stock dereferences the result without
        // a check; the pause relies on XAudio having a render driver thread
        // while its kernel routine is set, as stock does.
        let thread = unsafe { &*xboxkrnl::XAudioGetRenderDriverThread() };
        // SAFETY: the render driver thread runs while XAudio keeps it, which
        // the pause relies on above.
        if let Some(previous) =
            unsafe { crate::backend::debugger::exchange_record_flags(thread, PAUSE_MASK, PAUSED) }
        {
            s.audio_thread_flags.store(previous.bits(), Relaxed);
        }
    }
    // SAFETY: the calling thread does not end during the call.
    if let Some(previous) = unsafe {
        crate::backend::debugger::exchange_record_flags(
            current_object().kthread(),
            PAUSE_MASK,
            PAUSED,
        )
    } {
        s.caller_flags.store(previous.bits(), Relaxed);
    }
    engine::stop(s, &s.frame_record, false, true);
    for port in 0..CONTROLLER_PORTS {
        stop_vibration(port);
    }
    s.paused.store(1, Relaxed);
}

/// Resume (stock 0x91f5ff30).
fn resume_engine(s: &PixSession) {
    end_video(s);
    engine::start(s);
    let target = if crate::backend::debugger::execution_state()
        == openxbdm_server::notify::ExecutionState::Pending
    {
        openxbdm_server::notify::ExecutionState::RebootTitle
    } else {
        openxbdm_server::notify::ExecutionState::Started
    };
    crate::backend::debugger::request_execution(target, true);
    // SAFETY: as in `pause_engine`.
    unsafe {
        crate::backend::debugger::exchange_record_flags(
            current_object().kthread(),
            PAUSE_MASK,
            MonitorRecordFlags::from_bits_retain(s.caller_flags.load(Relaxed)),
        )
    };
    let routine = s.kernel_routine.load(Relaxed);
    if routine != 0 {
        // SAFETY: takes no arguments; dereferenced without a check as in
        // `pause_engine`.
        let audio = unsafe { &*xboxkrnl::XAudioGetRenderDriverThread() };
        // SAFETY: as in `pause_engine`.
        unsafe {
            crate::backend::debugger::exchange_record_flags(
                audio,
                PAUSE_MASK,
                MonitorRecordFlags::from_bits_retain(s.audio_thread_flags.load(Relaxed)),
            )
        };
        call_kernel_routine(routine, s.audio_client.load(Relaxed), false);
        // SAFETY: the client `pause_engine` registered.
        unsafe { XAudioUnregisterRenderDriverClient(s.audio_client.load(Relaxed)) };
        s.audio_client.store(0, Relaxed);
    }
    // SAFETY: pairs with the `KeEnterCriticalRegion` of `pause_engine`.
    unsafe { xboxkrnl::KeLeaveCriticalRegion() };
    s.paused.store(0, Relaxed);
}

#[inline(always)]
fn call_kernel_routine(routine: u32, client: u32, enable: bool) {
    // SAFETY: kernel export 0x2d4 takes two arguments, the audio client
    // and a flag.
    unsafe { kernel::call_export(routine, client, u32::from(enable), 0, 0) };
}

/// Stop the vibration of controller `port` (stock 0x91f78b20 with zero
/// motor speeds; its capability query only decides whether to swap the
/// two speeds).
fn stop_vibration(port: u32) {
    let vibration = [0u16; 2];
    // SAFETY: `vibration` is live for the synchronous call.
    unsafe { XamInputSetState(port, 0, vibration.as_ptr(), 0, 0, 0) };
}

/// Title end part (stock 0x91f62100, from the title terminate routine):
/// stop, forget the title's partition handles and every allocation, and
/// finish a capture to file.
pub(super) fn title_ended(s: &PixSession) {
    let record = FrameRecord::new();
    s.swap_routine_registered.store(0, Relaxed);
    if running(s) {
        engine::stop(s, &record, true, false);
    }
    let frame_record = &s.frame_record;
    frame_record.milliseconds.store(0, Relaxed);
    frame_record.flags.store(0, Relaxed);
    frame_record.unknown_08.store(0, Relaxed);
    for stream in &s.streams {
        stream.title_handle.store(0, Relaxed);
    }
    buffers::free(s);
    session::reset_budget(s);
    if s.message.is(EngineMessage::CaptureToFile) {
        files::set_capture_file(None);
        if CaptureToFilePayload::of(&s.message.payload)
            .notify
            .load(Relaxed)
            != 0
        {
            post_status(Status::No);
        }
        s.message.code.store(0, Relaxed);
        s.step.store(0, Relaxed);
    }
}

/// Argument of monitor control code 0x56: its size, then the budget
/// switches.
#[repr(C)]
struct BudgetArgument {
    size: AtomicU32,
    enabled: AtomicU32,
    title_enabled: AtomicU32,
}

/// Code 0x56 argument with the budget overrides.
#[repr(C)]
struct BudgetOverrideArgument {
    _switches: BudgetArgument,
    override_title: AtomicU32,
    title_size: AtomicU32,
    override_system: AtomicU32,
    system_size: AtomicU32,
}

/// Monitor control code 0x56 (stock 0x91f56420 and 0x91f61228) sets the
/// memory budget switches and, with the larger argument, the overrides; a
/// running capture restarts with them.
///
/// # Safety
///
/// `argument` must be the address of a record that starts with its size
/// in bytes and is as large as that size says, kept valid by the caller
/// for the call.
pub(super) unsafe fn configure(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let size = unsafe { crate::kernel::object_at::<AtomicU32>(argument) };
    if size.load(Relaxed) < size_of::<BudgetArgument>() as u32 {
        return 0;
    }
    // SAFETY: the record is as large as its size word says.
    let switches = unsafe { crate::kernel::object_at::<BudgetArgument>(argument) };
    let Some(locked) = session::lock() else {
        return 1;
    };
    let s = locked.session();
    let running = running(s);
    if running {
        stop(s);
    }
    let budget = &s.budget;
    budget
        .enabled
        .store(switches.enabled.load(Relaxed), Relaxed);
    budget
        .title_enabled
        .store(switches.title_enabled.load(Relaxed), Relaxed);
    if switches.size.load(Relaxed) >= size_of::<BudgetOverrideArgument>() as u32 {
        // SAFETY: as above.
        let overrides = unsafe { crate::kernel::object_at::<BudgetOverrideArgument>(argument) };
        budget
            .override_title
            .store(overrides.override_title.load(Relaxed), Relaxed);
        budget
            .title_size
            .store(overrides.title_size.load(Relaxed), Relaxed);
        budget
            .override_system
            .store(overrides.override_system.load(Relaxed), Relaxed);
        budget
            .system_size
            .store(overrides.system_size.load(Relaxed), Relaxed);
    }
    if running {
        buffers::free(s);
        buffers::allocate_all(s);
        engine::start(s);
    }
    1
}

// Xenia names xam 0x190 XamInputGetCapabilities; the ordinal follows the
// stock import.
xbox360_sys::import_thunk!(
    #[allow(non_snake_case)]
    XamInputSetState(
        user: u32,
        flags: u32,
        vibration: *const u16,
        overlapped: u32,
        completion: u32,
        context: u32,
    ) -> u32,
    lib = xbox360_sys::lib_index::XAM,
    ordinal = 0x190
);
