//! PIX engine: the stream ring, status notifications, title event
//! callbacks, the frame boundary, capture files, and the capture session.
//! Titles and the kernel reach it through monitor control codes; `pixcmd`
//! reaches it through the domain backend.
//!
//! The control code services receive the caller's argument as an address
//! and make it a typed view with [`kernel::object_at`] or [`words_at`]
//! where they first use it.

mod capture;
mod events;
mod files;
mod frame;
mod plugin;
mod ring;
mod session;
mod status;

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_server::Server;
use openxbdm_server::commands::performance::pix;
use openxbdm_server::reply;
use openxbdm_server::reply::Reply;
use openxbdm_server::text::ResponseText;
use xbox360::time::Timebase;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::processor::WaitStatistics;
use xbox360_sys::xboxkrnl;

use crate::backend::Console;
use crate::backend::dispatcher;
use crate::kernel;
use crate::net::XamNetwork;

pub(crate) use ring::stream_active;
pub(crate) use ring::write_tagged_record;
pub(crate) use ring::write_tagged_words;

/// Code 0x3f flag (stock 0x91fa2a50): capture file writes are discarded
/// and the capture buffer wraps.
static DISCARD_OUTPUT: AtomicBool = AtomicBool::new(false);

/// Whether capture output is discarded (code 0x3f); any IRQL.
pub(crate) fn discard_output() -> bool {
    DISCARD_OUTPUT.load(Ordering::Acquire)
}

/// The `count` words at `address`; empty for no words, whatever the
/// address.
///
/// # Safety
///
/// For a nonzero `count`, `address` must be 4-byte aligned and the words
/// valid for reads and writes for `'a`. Other code may only access them
/// atomically meanwhile.
unsafe fn words_at<'a>(address: u32, count: usize) -> &'a [AtomicU32] {
    if count == 0 {
        return &[];
    }
    // SAFETY: guaranteed by the caller.
    unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance::<AtomicU32>(address as usize),
            count,
        )
    }
}

/// Four-character tag of a stream ring record, first character in the
/// high byte.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RecordTag(u32);

impl RecordTag {
    /// Disk transfers (codes 0x7f and 0x80).
    pub(super) const HDD: Self = Self::new(*b"HDD ");
    /// Monitor counters of the frame boundary.
    pub(super) const XBDM: Self = Self::new(*b"XBDM");
    /// Processor statistics.
    pub(super) const CNTN: Self = Self::new(*b"Cntn");
    pub(super) const CNT2: Self = Self::new(*b"Cnt2");
    /// Context switches.
    pub(super) const CXSW: Self = Self::new(*b"CxSw");
    /// Active capture parts.
    pub(super) const CCAP: Self = Self::new(*b"Ccap");
    /// Waits for the partition writer.
    pub(super) const STRE: Self = Self::new(*b"STRE");

    pub(super) const fn new(characters: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(characters))
    }

    pub(super) const fn raw(self) -> u32 {
        self.0
    }
}

/// Code 0x7f argument: a starting disk transfer.
#[repr(C)]
struct DiskTransfer {
    is_write: AtomicU32,
    start: AtomicU32,
    sectors: AtomicU32,
}

/// Monitor control code 0x7f (stock 0x91f56560): a starting disk transfer
/// as an `HDD ` record with time bit 0 clear.
///
/// # Safety
///
/// `argument` must be the address of a disk transfer record the caller
/// keeps valid for the call.
pub(crate) unsafe fn service_disk_start(argument: u32) -> u32 {
    let time = Timebase::now().ticks();
    if stream_active() {
        // SAFETY: the caller's contract.
        let transfer = unsafe { kernel::object_at::<DiskTransfer>(argument) };
        write_tagged_words(
            RecordTag::HDD.raw(),
            &[
                (time >> 32) as u32,
                time as u32 & !1,
                transfer.is_write.load(Relaxed),
                transfer.start.load(Relaxed),
                transfer.sectors.load(Relaxed),
            ],
        );
    }
    0
}

/// Monitor control code 0x80 (stock 0x91f565c0): completion status of a
/// disk transfer, as an `HDD ` record with time bit 0 set.
pub(crate) fn service_disk_complete(status: u32) -> u32 {
    let time = Timebase::now().ticks();
    if stream_active() {
        write_tagged_words(
            RecordTag::HDD.raw(),
            &[(time >> 32) as u32, time as u32 | 1, status],
        );
    }
    0
}

/// Monitor control code 0x42 (stock 0x91f3b670): register a consumer, or
/// with a null argument remove the consumers registered this way (1).
///
/// # Safety
///
/// `argument` must be 0 or meet the contract of [`ring::register_consumer`].
pub(crate) unsafe fn service_register_consumer(argument: u32) -> u32 {
    if argument == 0 {
        ring::clear_consumers();
        return 1;
    }
    // SAFETY: the caller's contract.
    unsafe { ring::register_consumer(argument, false) }
}

/// Monitor control code 0x58 (stock 0x91f3b5e4): register a consumer that
/// code 0x42 does not remove.
///
/// # Safety
///
/// As [`ring::register_consumer`].
pub(crate) unsafe fn service_register_persistent_consumer(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { ring::register_consumer(argument, true) }
}

/// A title's `pixcmd` line of code 0x45 operation 0.
#[repr(C)]
struct TitleCommand {
    _size: u32,
    line: u32,
    response: u32,
    response_size: u32,
    context: u32,
}

/// Monitor control code 0x45 operation 0: run the title's `pixcmd` line
/// `{0x14, line, response, size, context}` on the server thread.
///
/// # Safety
///
/// `request` must be the address of a title command whose line is
/// NUL-terminated and readable for at least `TITLE_LINE_MINIMUM` bytes
/// and whose response buffer holds its size, all kept by the title until
/// the call returns, and whose context is a transfer context the title
/// keeps for a `pixcmd r` transfer.
unsafe fn run_command_line(request: u32) -> u32 {
    // SAFETY: the caller's contract, which `TitleRequest` carries.
    let mut request = TitleRequest(unsafe { kernel::object_at::<TitleCommand>(request) });
    dispatcher::call_on_server_with(&mut request, title_command).unwrap_or(0)
}

/// A title command that meets the contract of [`run_command_line`].
struct TitleRequest<'a>(&'a TitleCommand);

/// Bytes of the title's line buffer the parser may read: the line, its
/// NUL, and the eight selector characters at offset 9.
const TITLE_LINE_MINIMUM: usize = 0x11;

fn title_command(
    server: &mut Server,
    console: &mut Console,
    network: &mut XamNetwork,
    request: &mut TitleRequest<'_>,
) -> u32 {
    let request = request.0;
    // SAFETY: a `TitleRequest` line is NUL-terminated and readable for
    // `TITLE_LINE_MINIMUM` bytes; stock reads the same bytes past short
    // lines.
    let buffer = unsafe {
        let line = core::ptr::with_exposed_provenance::<u8>(request.line as usize);
        let length = core::ffi::CStr::from_ptr(line.cast()).count_bytes();
        core::slice::from_raw_parts(line, (length + 1).max(TITLE_LINE_MINIMUM))
    };
    let mut text = ResponseText::new();
    let result = pix::run_title_command(&mut server.state, console, network, buffer, &mut text);
    let size = request.response_size as usize;
    if size != 0 {
        let count = text.as_bytes().len().min(size - 1);
        // SAFETY: a `TitleRequest` response buffer holds `size` bytes.
        let output = unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::with_exposed_provenance_mut::<u8>(request.response as usize),
                count + 1,
            )
        };
        output[..count].copy_from_slice(&text.as_bytes()[..count]);
        output[count] = 0;
    }
    if result == Ok(Reply::Binary) {
        // SAFETY: a `TitleRequest` context is the title's transfer context.
        unsafe { ring::begin_title_transfer(request.context) };
    }
    reply::hresult(result).0
}

pub(crate) use capture::service_command_buffers;
pub(crate) use capture::service_configure;
pub(crate) use capture::service_end;
pub(crate) use capture::service_fence;
pub(crate) use capture::service_frame_buffer;
pub(crate) use capture::service_nuicam_begin;
pub(crate) use capture::service_samples;
pub(crate) use capture::service_timing_request;
pub(crate) use capture::thread_terminated;
pub(crate) use events::service_acquire_owner;
pub(crate) use events::service_register_callback;
pub(crate) use events::service_release_owner;
pub(crate) use events::service_thread_slot;
pub(crate) use events::service_unregister_callback;
pub(crate) use files::service_open_for_capture;
pub(crate) use files::service_open_for_start;
pub(crate) use files::service_resource_begin;
pub(crate) use files::service_resource_end;
pub(crate) use files::service_resource_record;
pub(crate) use files::service_write_capture_record;
pub(crate) use frame::service_frame;
pub(crate) use frame::service_frame_record;
pub(crate) use ring::service_unregister_consumer;
pub(crate) use ring::service_write_block;
pub(crate) use ring::service_write_block_list;
pub(crate) use ring::service_write_dword;
pub(crate) use status::service_filter_control;
pub(crate) use status::service_post_text;

/// Monitor control code 0x3f (stock 0x91f5f4b0).
pub(crate) fn service_set_discard_output(discard: u32) -> u32 {
    session::set_discard(discard != 0);
    DISCARD_OUTPUT.store(discard != 0, Ordering::Release);
    1
}

/// Monitor control code 0x44 (stock 0x91f5f3b8).
pub(crate) fn service_state_flags(_argument: u32) -> u32 {
    session::state_flags().bits()
}

/// Code 0x57 argument: an engine message.
#[repr(C)]
struct QueuedMessage {
    code: AtomicU32,
    payload: AtomicU32,
    bytes: AtomicU32,
}

/// Monitor control code 0x57 (stock 0x91f564a0): queue `{+0 code, +4
/// payload, +8 bytes}`. Stock returns a stale register; this returns 0.
///
/// # Safety
///
/// `argument` must be the address of a message record whose payload
/// holds its byte count, rounded up to whole words, both kept valid for
/// the call. The routines of a message 8 payload must meet the contract
/// of `replay::replay` until the message completes.
pub(crate) unsafe fn service_queue_message(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let message = unsafe { kernel::object_at::<QueuedMessage>(argument) };
    let code = message.code.load(Relaxed);
    let bytes = (message.bytes.load(Relaxed) as usize).min(session::MESSAGE_PAYLOAD_SIZE);
    let count = bytes.div_ceil(4);
    // SAFETY: the record's payload holds `bytes` bytes, rounded up to
    // whole words as stock reads them.
    let payload = unsafe { words_at(message.payload.load(Relaxed), count) };
    let mut words = [0u32; session::MESSAGE_PAYLOAD_SIZE / 4];
    for (word, source) in words.iter_mut().zip(payload) {
        *word = source.load(Relaxed);
    }
    session::post(code, &words[..count]);
    0
}

/// Resource capture information of code 0x87 (stock 0x91fa2adc), set by
/// session message 15.
static RESOURCE_INFORMATION: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];

/// Store the three words of a resource capture message.
fn set_resource_information(source: &[AtomicU32]) {
    for (slot, word) in RESOURCE_INFORMATION.iter().zip(source) {
        slot.store(word.load(Relaxed), Ordering::Release);
    }
}

/// Monitor control code 0x87 (stock 0x91f563e0).
///
/// # Safety
///
/// `output` must be 0 or the address of three writable words the caller
/// keeps valid for the call.
pub(crate) unsafe fn service_resource_information(output: u32) -> u32 {
    if output == 0 {
        return 0;
    }
    // SAFETY: the caller's contract.
    let output = unsafe { kernel::object_at::<[AtomicU32; 3]>(output) };
    for (target, word) in output.iter().zip(&RESOURCE_INFORMATION) {
        target.store(word.load(Ordering::Acquire), Relaxed);
    }
    1
}

/// `pixcmd u` GPU capture flag (stock 0x91fa2aa4).
static GPU_CAPTURE: AtomicBool = AtomicBool::new(false);

fn gpu_capture_requested() -> bool {
    GPU_CAPTURE.load(Ordering::Acquire)
}

/// Module initialization part (stock 0x91f56758).
pub(crate) fn initialize() {
    // SAFETY: takes no arguments; returns the thread object or null.
    let audio = unsafe { xboxkrnl::XAudioGetRenderDriverThread() };
    if !audio.is_null() {
        // SAFETY: the render driver thread object, which XAudio keeps
        // while it runs.
        let id = openxbdm_server::commands::debugger::ThreadId(unsafe { (*audio).id });
        // SAFETY: a static NUL-terminated name; the render driver thread
        // runs while XAudio keeps it.
        unsafe {
            crate::backend::debugger::name_thread(
                Some(id),
                c"Audio Driver".as_ptr() as usize as u32,
            )
        };
    }
    plugin::initialize();
    frame::reset_frame_count();
    ring::initialize();
    if !session::create() {
        kernel::debug_print(c"Pix streaming disabled\n");
    }
}

/// Remove everything that calls into this image.
pub(crate) fn shut_down() {
    capture::shut_down();
    ring::shut_down();
}

/// Server-thread pass (stock server loop 0x91f510e4 calling 0x91f62e88
/// and 0x91f62228).
pub(crate) fn poll() {
    ring::poll();
    capture::poll();
}

/// PIX part of the second title terminate routine (stock 0x91f32418).
pub(crate) fn title_ended() {
    capture::title_ended();
}

/// PIX part of the title terminate notification (stock 0x91f566f0).
pub(crate) fn title_terminated() {
    crate::backend::session::remove_unflagged_swap_routines();
    events::forget_title();
    plugin::stop();
    files::title_terminated();
    events::clear_thread_flags();
    status::post_without_text(status::Status::Reboot);
}

/// `pixcmd b`/`e` (stock 0x91f58034, 0x91f580c4): reset the bitmap, set the
/// per-processor trace flags through an IPI, and allocate or free the
/// ring.
pub(crate) fn set_trace(enabled: bool) {
    events::clear_bitmap();
    if enabled {
        frame::reset_history();
    }
    // SAFETY: `trace_hook` is an IPI routine that only touches the PCR of
    // its processor and its wait statistics.
    unsafe {
        xboxkrnl::KeIpiGenericCall(trace_hook as *const () as usize as u32, u32::from(enabled))
    };
    if enabled { ring::start() } else { ring::stop() }
}

/// IPI routine of `pixcmd b`/`e` (stock 0x91f56670): with interrupts off,
/// bit 0 of the PCR PIX flags and the low three bits of the wait
/// statistics flags become the enable value.
#[unsafe(naked)]
extern "C" fn trace_hook(_enable: u32) -> u32 {
    core::arch::naked_asm!(
        "mr 10, 13",
        "li 9, 0",
        "li 8, 0",
        "cmpwi 6, 3, 0",
        "beq 6, 1f",
        "li 9, 1",
        "li 8, 1",
        "1:",
        "lwz 11, {statistics}(10)",
        // mtmsrd r13, 1: interrupts off (r13 has the enable bit clear).
        ".long 0x7da10164",
        "lwz 7, {pix_flags}(10)",
        "cmplwi 6, 11, 0",
        "rlwimi 7, 9, 0, 31, 31",
        "stw 7, {pix_flags}(10)",
        "beq 6, 2f",
        "lwz 10, {statistics_flags}(11)",
        "rlwimi 10, 8, 0, 29, 31",
        "stw 10, {statistics_flags}(11)",
        "2:",
        "lis 11, 0",
        "ori 11, 11, 0x8000",
        // mtmsrd r11, 1: interrupts on.
        ".long 0x7d610164",
        "li 3, 0",
        "blr",
        statistics = const core::mem::offset_of!(Kpcr, wait_statistics),
        pix_flags = const core::mem::offset_of!(Kpcr, pix_flags),
        statistics_flags = const core::mem::offset_of!(WaitStatistics, flags),
    )
}

/// Backend part of `pixcmd`.
pub(crate) mod backend {
    use openxbdm_server::commands::performance::CaptureValue;
    use openxbdm_server::commands::performance::PixDogma;

    use super::*;

    /// Capture values of `pixcmd k` (stock 0x91f98ef8 and 0x91fa2a7c) and
    /// its text (0x91fa280c, counter 0x91fa2808).
    static CAPTURE_VALUES: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
    /// Capture thread value of no thread.
    const NO_CAPTURE_THREAD: u32 = u32::MAX;

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

    /// Text of `pixcmd k` (stock 0x91fa280c, unbounded copy there). It is
    /// only compared with event names of at most `EVENT_NAME_BYTES` bytes,
    /// which a longer text never matches; one more byte and the NUL keep
    /// that outcome.
    static CAPTURE_TEXT: CaptureText =
        CaptureText(core::cell::UnsafeCell::new([0; CAPTURE_TEXT_CAPACITY]));
    const CAPTURE_TEXT_CAPACITY: usize = EVENT_NAME_BYTES + 2;
    /// Event name buffer of a timing request.
    pub(super) const EVENT_NAME_BYTES: usize = 0x24;

    struct CaptureText(core::cell::UnsafeCell<[u8; CAPTURE_TEXT_CAPACITY]>);

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
}
