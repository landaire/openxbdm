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

use super::super::backend::EVENT_NAME_BYTES;
use super::super::status::Status;
use super::super::status::post as post_status;
use super::S;
use super::buffers;
use super::engine;
use super::rd;
use super::wr;
use crate::kernel;
use openxbdm_server::text::Text;

const MESSAGE: u32 = super::CURRENT_MESSAGE;
const MESSAGE_WORD: u32 = 0x598;
const PAYLOAD: u32 = 0x59c;
const STEP: u32 = 0x5ec;
const FRAME_RECORD: u32 = 0x5f4;
/// Pause state: paused flag, thread write count at the pause, XAudio
/// client and the saved monitor record flags.
const PAUSED: u32 = 0xc838;
const VIDEO_FLAGS: u32 = 0xc840;
const AUDIO_CLIENT: u32 = 0x1_2290;
const AUDIO_THREAD_FLAGS: u32 = 0x1_228c;
const CALLER_FLAGS: u32 = 0x1_2288;
/// Monitor record flags exchanged while paused: exempt from stops, not
/// debuggable, and 0x1000.
const RECORD_PAUSE_MASK: u32 = 0x0200_3000;
const UNNAMED: &core::ffi::CStr = c"unnamed.pix2";

fn payload(s: S) -> u32 {
    s.0 + PAYLOAD
}

fn open_unnamed() -> Option<super::super::files::CaptureFile> {
    super::super::files::open(UNNAMED.as_ptr() as usize as u32, true)
}

/// Process queued messages (stock 0x91f619d8). `flags` is the frame
/// record's flags word; message 15 reports into `out`.
pub(super) fn dispatch(s: S, flags: u32, out: &mut u32) {
    let mut processed = false;
    loop {
        if s.word(MESSAGE) == 0 {
            let Some(entry) = super::super::session::next_message(s) else {
                break;
            };
            // SAFETY: a queue entry and the current message are 0x58 bytes
            // of the session block.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    entry as usize as *const u8,
                    s.at(MESSAGE).cast::<u8>(),
                    0x58,
                )
            };
            s.set_word(STEP, 0);
        }
        processed = true;
        let step = s.word(STEP);
        let done = match s.word(MESSAGE) {
            1 => capture_frames(s, flags, step, payload(s)),
            2 => step != 0,
            3 => trace(s, step, payload(s), false),
            4 => trace(s, step, payload(s), true),
            5 => capture_to_file(s, flags, step, payload(s)),
            6 => {
                record_configuration(s, payload(s), true);
                processed = false;
                true
            }
            7 => write_frames(s, payload(s)),
            8 => write_frames_with(s, payload(s)),
            10 => pause(s),
            12 => video_operation(s, payload(s)),
            13 => {
                let flag = rd(payload(s)) & 1;
                s.set_word(
                    super::FLAGS,
                    (s.word(super::FLAGS) & !super::PAUSED) | flag << 30,
                );
                true
            }
            15 => resource_state(payload(s), out),
            // 11 finishes at once; stock traps on 9, 14 and unknown codes.
            _ => true,
        };
        if !done {
            s.set_word(STEP, step + 1);
            return;
        }
        s.set_word(MESSAGE, 0);
    }
    // SAFETY: the current and requested configurations are 0x28 bytes.
    let differs = (0..10).any(|index| {
        s.word(index * 4) != s.word(super::super::session::REQUESTED_CONFIGURATION + index * 4)
    });
    if processed && differs {
        apply_requested(s, true);
    }
}

/// Stop, set the per-thread parts, reallocate when needed, and start
/// (stock 0x91f60d50).
fn reconfigure(s: S, first: u32, second: u32, tracing: u32) {
    engine::stop(s, s.0 + FRAME_RECORD, false, false);
    s.set_word(8, super::OFF);
    s.set_word(0xc, super::OFF);
    s.set_word(0, first);
    s.set_word(4, second);
    s.set_word(0x18, tracing);
    if s.word(0x24) != s.word(0x2b4)
        || (s.word(0x130) == 0 && (first != super::OFF || second != super::OFF))
    {
        buffers::free(s);
        buffers::allocate_all(s);
    }
    engine::start(s);
}

/// Make the requested configuration current (stock 0x91f60de0), with a
/// stop and start around it when `restart`.
pub(super) fn apply_requested(s: S, restart: bool) {
    if restart {
        engine::stop(s, s.0 + FRAME_RECORD, false, false);
    }
    for index in 0..10 {
        s.set_word(
            index * 4,
            s.word(super::super::session::REQUESTED_CONFIGURATION + index * 4),
        );
    }
    let any = (0..4).any(|index| s.word(index * 4) != super::OFF);
    if s.word(0x24) != s.word(0x2b4) || (s.word(0x130) == 0 && any) {
        buffers::free(s);
        buffers::allocate_all(s);
    }
    if restart {
        engine::start(s);
    }
}

/// Message 1 `{frames, notify, file}` (stock 0x91f60ea8): capture the
/// next frames, then write them to the file (status 2, or 3 when nothing
/// was written).
fn capture_frames(s: S, flags: u32, step: u32, payload: u32) -> bool {
    let frames = rd(payload);
    if step < frames {
        if flags & 1 == 0 {
            if rd(payload + 4) != 0 {
                post_status(Status::BadD3dVersion, 0);
            }
            return true;
        }
        if step == 0 && frames != 0 {
            reconfigure(s, 0, super::OFF, 0);
        }
        return false;
    }
    engine::stop(s, s.0 + FRAME_RECORD, false, false);
    let mut written = false;
    let file = match rd(payload + 8) {
        0 => open_unnamed().map(|file| file.0),
        file => Some(file),
    };
    if let Some(file) = file {
        wr(payload + 8, file);
        written = super::replay::write_stream(s, file, frames, frames);
        kernel::NtClose(file);
    }
    engine::start(s);
    if rd(payload + 4) != 0 {
        post_status(if written { Status::Timing } else { Status::No }, 0);
    }
    true
}

/// Messages 3 and 4 (stock 0x91f61140): record an instruction trace of
/// the frame thread. 3 traces one frame; 4 traces the event named by
/// `pixcmd k`, giving up after 10 s.
fn trace(s: S, step: u32, payload: u32, by_event: bool) -> bool {
    if step == 0 {
        wr(payload, kernel::tick_count());
        reconfigure(s, super::OFF, super::OFF, u32::from(by_event));
        if !by_event {
            super::super::super::xtrace::start_default();
        }
        return false;
    }
    if !by_event {
        super::super::super::xtrace::stop();
        post_status(Status::Trace, 0);
        return true;
    }
    let now = kernel::tick_count();
    if s.word(MESSAGE_WORD) != 0 {
        post_status(Status::Trace, 0);
        return true;
    }
    if now.wrapping_sub(rd(payload)) >= 10_000 {
        stop_event_trace();
        post_status(Status::No, 0);
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
    let thread = kernel::current_thread();
    super::super::backend::capture_thread() == u32::from(super::rd8(thread + 0xbf))
}

/// Timing request on the trace capture path (stock 0x91f558e0): type 0
/// begins an event, type 1 ends one; true when the traced event ended.
pub(super) fn trace_event(kind: u32, name: &[u8; EVENT_NAME_BYTES]) -> bool {
    match kind {
        0 => trace_event_begin(name),
        1 if on_capture_thread() => {
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

/// Message 5 `{notify, file, plugin, image, installer, information,
/// poll}` (stock 0x91f60fb0): write per-thread timing data to the capture
/// file until the next frame, or while the plugin reports busy.
fn capture_to_file(s: S, flags: u32, step: u32, payload: u32) -> bool {
    let plugin = rd(payload + 8) != 0;
    if step >= 1 {
        if plugin && !plugin_finished(rd(payload + 0x18)) {
            return false;
        }
        super::super::files::set_capture_file(None);
        let file = super::super::files::CaptureFile(rd(payload + 4));
        super::super::files::write_words(file, &[0x0100_0018]);
        kernel::NtClose(file.0);
        if rd(payload) != 0 {
            post_status(Status::Gpu, 0);
        }
        // Stock unloads the image here and once more for plugin captures.
        if super::super::plugin::handle().is_none() && rd(payload + 0xc) != 0 {
            kernel::XexUnloadImage(rd(payload + 0xc));
            wr(payload + 0xc, 0);
        }
        return true;
    }
    if flags & 2 == 0 && !plugin {
        if rd(payload) != 0 {
            post_status(Status::BadD3dVersion, 0);
        }
        return true;
    }
    reconfigure(s, super::OFF, super::OFF, 1);
    if rd(payload + 4) == 0
        && let Some(file) = open_unnamed()
    {
        wr(payload + 4, file.0);
    }
    let file = super::super::files::CaptureFile(rd(payload + 4));
    super::super::files::set_capture_file(Some(file));
    super::super::files::write_words(file, &[0x0100_001b]);
    if plugin {
        super::super::plugin::install_callbacks(rd(payload + 0x10));
        super::super::events::notify_owner(0x22, rd(payload + 0x14));
    }
    false
}

/// Poll the plugin's capture routine (stock 0x91f58e90): finished unless
/// it reports 0x8000000a; the owner then forgets the hook and the plugin
/// is attached again.
fn plugin_finished(poll: u32) -> bool {
    // SAFETY: the plugin's export without arguments.
    if unsafe { kernel::call_export(poll, 0, 0, 0, 0) } == 0x8000_000a {
        return false;
    }
    super::super::events::notify_owner(0x22, 0);
    super::super::plugin::restart();
    true
}

/// Message 6 (stock 0x91f61330): store a requested configuration
/// `{+4 parts[4], +0x14, +0x18, +0x20 size, +0x24 units, +0x28, +0x2c}`,
/// reset stream 1, and apply it.
pub(super) fn record_configuration(s: S, payload: u32, restart: bool) {
    if restart {
        engine::stop(s, s.0 + FRAME_RECORD, false, false);
    }
    let requested = super::super::session::REQUESTED_CONFIGURATION;
    for index in 0..10 {
        s.set_word(requested + index * 4, 0);
    }
    for index in 0..6 {
        s.set_word(requested + index * 4, rd(payload + 4 + index * 4));
    }
    s.set_word(requested + 0x24, rd(payload + 0x20));
    s.set_word(requested + 0x1c, rd(payload + 0x28));
    s.set_word(requested + 0x20, rd(payload + 0x2c));
    let stream = buffers::stream(1);
    for index in 0..buffers::TABLE_ENTRIES {
        super::wr8(s.0 + stream + buffers::STREAM_TABLE + index * 8 + 4, 0xcc);
    }
    s.set_quad(stream + 0x18, 0);
    s.set_word(stream + buffers::STREAM_SEQUENCE, 0);
    s.set_quad(
        stream + buffers::STREAM_SIZE,
        u64::from(rd(payload + 0x24)) << 14,
    );
    apply_requested(s, false);
    if restart {
        engine::capture_record(s);
    }
    let first = s.word(requested);
    if first != s.word(0) && first == 0 && s.word(super::super::session::DUMP_FILE) == 0 {
        post_status(Status::NoHarddrive, 0);
    }
    if restart {
        engine::start(s);
    }
}

/// Message 7 `{first, last, ...}` (stock 0x91f5eb00): write frames of the
/// dump partition to `unnamed.pix2` (status 2, else 6).
fn write_frames(s: S, payload: u32) -> bool {
    // Stock traps without a third word.
    if rd(payload + 8) == 0 {
        return true;
    }
    let mut written = false;
    if s.word(super::FLAGS) & super::RUNNING == 0
        && let Some(file) = open_unnamed()
    {
        written = super::replay::write_stream(s, file.0, rd(payload), rd(payload + 4));
        kernel::NtClose(file.0);
    }
    post_status(
        if written {
            Status::Timing
        } else {
            Status::NoFrame
        },
        0,
    );
    true
}

/// Message 8 `{first, last, begin, write, context, mode}` (stock
/// 0x91f614d0): replay the dump partition through the title's routines.
fn write_frames_with(s: S, payload: u32) -> bool {
    let running = s.word(super::FLAGS) & super::RUNNING != 0;
    if running {
        engine::stop(s, s.0 + FRAME_RECORD, false, false);
    }
    super::replay::replay(
        s,
        rd(payload + 8),
        rd(payload + 0xc),
        rd(payload + 0x10),
        rd(payload + 0x14),
        rd(payload),
        rd(payload + 4),
    );
    if running {
        engine::start(s);
    }
    true
}

/// Message 12 `{first, last, operation, argument}` (stock 0x91f61568):
/// run a video operation over captured frames; a failure is reported as
/// `VideoOpError <code>`.
fn video_operation(s: S, payload: u32) -> bool {
    if rd(payload + 8) == 0 {
        return true;
    }
    let running = s.word(super::FLAGS) & super::RUNNING != 0;
    if running {
        engine::stop(s, s.0 + FRAME_RECORD, false, false);
    }
    let error = super::video::run(s, rd(payload), rd(payload + 4), rd(payload + 0xc));
    if running {
        end_video(s);
        engine::start(s);
    }
    if let Some(error) = error {
        let mut text: Text<0x40> = Text::new();
        let _ = write!(text, "{}\0", error as i32);
        post_status(
            Status::VideoOpError,
            text.as_bytes().as_ptr() as usize as u32,
        );
    }
    true
}

/// End of a video operation (stock 0x91f5a488): the frame record's
/// completion routine runs once.
pub(super) fn end_video(s: S) {
    if s.word(VIDEO_FLAGS) & 0x8000_0000 != 0 {
        // SAFETY: the title's frame record names a routine taking one
        // argument.
        unsafe {
            kernel::call_export(
                s.word(FRAME_RECORD + 0x34),
                s.word(FRAME_RECORD + 0x1c),
                0,
                0,
                0,
            )
        };
        s.set_word(VIDEO_FLAGS, s.word(VIDEO_FLAGS) & !0x8000_0000);
    }
}

/// Message 15 `{active, notify, request, information[3]}` (stock
/// 0x91f5d270): report the resource capture state into the frame flags,
/// or start or stop it through the plugin.
fn resource_state(payload: u32, out: &mut u32) -> bool {
    let active = rd(payload) != 0;
    if rd(payload + 8) == 0 {
        if active {
            *out |= 0x20;
        } else {
            *out |= 0x40;
            if rd(payload + 4) != 0 {
                *out |= 0x80;
            }
        }
    } else {
        let (procedure, refusal): (u32, &core::ffi::CStr) = if active {
            (
                super::super::plugin::procedure(2),
                c"PIX!StartFailed ResourceCapture",
            )
        } else {
            (
                super::super::plugin::procedure(3),
                c"PIX!NotActive ResourceCapture",
            )
        };
        if procedure != 0 {
            // SAFETY: the plugin's resource capture routines take two
            // arguments, the message payload and the frame flags.
            unsafe {
                kernel::call_export(procedure, payload, out as *mut u32 as usize as u32, 0, 0)
            };
        } else {
            crate::backend::session::service_send_notification(refusal.as_ptr() as usize as u32);
        }
    }
    super::super::set_resource_information(payload + 0xc);
    true
}

/// Message 10 (stock 0x91f617b0): pause the title until a resume message.
/// The frame thread services messages while paused; a message other than
/// 11 resumes and is handled at the next frame.
fn pause(s: S) -> bool {
    super::super::ring::capture_timing(1, super::active_parts(s), kernel::timebase());
    if s.word(FRAME_RECORD + 0x18) != 0 {
        relock(s, || {
            // SAFETY: the title's frame record names a routine taking one
            // argument.
            unsafe {
                kernel::call_export(
                    s.word(FRAME_RECORD + 0x18),
                    s.word(FRAME_RECORD + 0x1c),
                    0,
                    0,
                    0,
                )
            };
        });
    }
    pause_engine(s);
    post_status(Status::Pause, 0);
    let resumed = loop {
        relock(s, || {});
        let Some(entry) = super::super::session::next_message(s) else {
            continue;
        };
        let message = entry + 8;
        match rd(entry) {
            3 | 4 => post_status(Status::No, 0),
            6 => record_configuration(s, message, false),
            7 => {
                write_frames(s, message);
            }
            8 => {
                write_frames_with(s, message);
            }
            9 => super::replay::dump_header(s, 1),
            10 => {}
            12 => {
                video_operation(s, message);
            }
            14 => paused_video(s, message),
            _ => break entry,
        }
    };
    resume_engine(s);
    super::super::ring::capture_timing(2, super::active_parts(s), kernel::timebase());
    if rd(resumed) == 11 {
        return true;
    }
    super::super::session::requeue_message(s);
    false
}

/// Release the session lock around `f` and take it again.
fn relock(s: S, f: impl FnOnce()) {
    super::super::session::leave(
        s.at(super::super::session::LOCK),
        s.word(super::super::session::LOCK_PRIORITY),
    );
    f();
    let saved = super::super::session::enter(s.at(super::super::session::LOCK));
    s.set_word(super::super::session::LOCK_PRIORITY, saved);
}

/// Message 14 while paused (stock 0x91f5d360): video operation into
/// `unnamed.pix2` (status 13, else 6).
fn paused_video(s: S, payload: u32) {
    let written = open_unnamed().is_some_and(|file| {
        let error = super::video::write(s, file.0, rd(payload + 8), rd(payload), rd(payload + 4));
        kernel::NtClose(file.0);
        error == 0
    });
    post_status(
        if written {
            Status::MovieData
        } else {
            Status::NoFrame
        },
        0,
    );
}

/// Stop for the pause (stock 0x91f61610): exempt the frame thread and
/// the audio render thread from execution stops, render silence through
/// a monitor audio client, stop with an execution state notification, and
/// stop controller vibration.
fn pause_engine(s: S) {
    kernel::KeEnterCriticalRegion();
    s.set_word(0xc880, s.word(0xe210));
    let routine = s.word(super::super::session::KERNEL_ROUTINE);
    if routine != 0 {
        let client = [super::video::render_entry_address(), s.0 + 0xc930];
        XAudioRegisterRenderDriverClient(client.as_ptr(), s.at(AUDIO_CLIENT));
        call_kernel_routine(routine, s.word(AUDIO_CLIENT), 1);
        let thread = kernel::XAudioGetRenderDriverThread();
        if let Some(previous) =
            crate::backend::debugger::exchange_record_flags(thread, RECORD_PAUSE_MASK, 0x0200_1000)
        {
            s.set_word(AUDIO_THREAD_FLAGS, previous);
        }
    }
    let thread = kernel::current_thread();
    if let Some(previous) =
        crate::backend::debugger::exchange_record_flags(thread, RECORD_PAUSE_MASK, 0x0200_1000)
    {
        s.set_word(CALLER_FLAGS, previous);
    }
    engine::stop(s, s.0 + FRAME_RECORD, false, true);
    for port in 0..4 {
        stop_vibration(port);
    }
    s.set_word(PAUSED, 1);
}

/// Resume (stock 0x91f5ff30).
fn resume_engine(s: S) {
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
    let thread = kernel::current_thread();
    crate::backend::debugger::exchange_record_flags(
        thread,
        RECORD_PAUSE_MASK,
        s.word(CALLER_FLAGS),
    );
    let routine = s.word(super::super::session::KERNEL_ROUTINE);
    if routine != 0 {
        let audio = kernel::XAudioGetRenderDriverThread();
        crate::backend::debugger::exchange_record_flags(
            audio,
            RECORD_PAUSE_MASK,
            s.word(AUDIO_THREAD_FLAGS),
        );
        call_kernel_routine(routine, s.word(AUDIO_CLIENT), 0);
        XAudioUnregisterRenderDriverClient(s.word(AUDIO_CLIENT));
        s.set_word(AUDIO_CLIENT, 0);
    }
    kernel::KeLeaveCriticalRegion();
    s.set_word(PAUSED, 0);
}

fn call_kernel_routine(routine: u32, client: u32, enable: u32) {
    // SAFETY: kernel export 0x2d4 takes two arguments, the audio client
    // and a flag.
    unsafe { kernel::call_export(routine, client, enable, 0, 0) };
}

/// Stop the vibration of controller `port` (stock 0x91f78b20 with zero
/// motor speeds; its capability query only decides whether to swap the
/// two speeds).
fn stop_vibration(port: u32) {
    let vibration = [0u16; 2];
    XamInputSetState(port, 0, vibration.as_ptr(), 0, 0, 0);
}

/// Title end part (stock 0x91f62100, from the title terminate routine):
/// stop, forget the title's partition handles and every allocation, and
/// finish a capture to file.
pub(super) fn title_ended(s: S) {
    let record = [0u32; 0x10];
    s.set_word(0x87d4, 0);
    if s.word(super::FLAGS) & super::RUNNING != 0 {
        engine::stop(s, record.as_ptr() as usize as u32, true, false);
    }
    s.set_word(0x5f8, 0);
    s.set_word(0x600, 0);
    s.set_word(0x5fc, 0);
    for k in 0..2 {
        s.set_word(buffers::stream(k) + 4, 0);
    }
    buffers::free(s);
    super::super::session::reset_budget(s);
    if s.word(MESSAGE) == 5 {
        super::super::files::set_capture_file(None);
        if rd(payload(s)) != 0 {
            post_status(Status::No, 0);
        }
        s.set_word(MESSAGE, 0);
        s.set_word(STEP, 0);
    }
}

/// Monitor control code 0x56 (stock 0x91f56420 and 0x91f61228): `{+0
/// size, +4, +8, +0xc..+0x18 with size 0x1c}` sets the memory budget
/// switches and overrides; a running capture restarts with them.
pub(super) fn configure(argument: u32) -> u32 {
    if rd(argument) < 0xc {
        return 0;
    }
    let Some(locked) = super::super::session::lock() else {
        return 1;
    };
    let s = locked.0;
    let running = s.word(super::FLAGS) & super::RUNNING != 0;
    if running {
        engine::stop(s, s.0 + FRAME_RECORD, false, false);
    }
    s.set_word(0x87dc, rd(argument + 4));
    s.set_word(0x87e0, rd(argument + 8));
    if rd(argument) >= 0x1c {
        for index in 0..4 {
            s.set_word(0x87e4 + index * 4, rd(argument + 0xc + index * 4));
        }
    }
    if running {
        buffers::free(s);
        buffers::allocate_all(s);
        engine::start(s);
    }
    1
}

crate::kernel::import_thunk!(
    XAudioRegisterRenderDriverClient(client: *const u32, handle: *mut u32) -> u32,
    lib = crate::kernel::LIB_KERNEL,
    ordinal = 0x1f3
);
crate::kernel::import_thunk!(
    XAudioUnregisterRenderDriverClient(handle: u32) -> u32,
    lib = crate::kernel::LIB_KERNEL,
    ordinal = 0x1f4
);
crate::kernel::import_thunk!(
    XamInputSetState(
        user: u32,
        flags: u32,
        vibration: *const u16,
        overlapped: u32,
        completion: u32,
        context: u32,
    ) -> u32,
    lib = crate::kernel::LIB_XAM,
    ordinal = 0x190
);
