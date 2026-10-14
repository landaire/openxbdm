//! System control commands: time, reboot, titles, flash, and the settings
//! file.

use core::fmt;
use core::fmt::Write as _;

use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;

use crate::access::Access;
use crate::backend::Backend as AnyBackend;
use crate::commands;
use crate::commands::console::ConfigSetting;
use crate::commands::console::TraceMask;
use crate::commands::console::trace;
use crate::commands::console::trace_text;
use crate::commands::filesystem::BasicInformation;
use crate::commands::filesystem::CreateDisposition;
use crate::commands::filesystem::CreateOptions;
use crate::commands::filesystem::CreateRequest;
use crate::commands::filesystem::FileAccess;
use crate::commands::filesystem::FileAttributes;
use crate::commands::filesystem::FileData;
use crate::commands::filesystem::ShareAccess;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::invocation::SessionRequest;
use crate::network::Network;
use crate::notify::Event;
use crate::notify::ExecutionState;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::server::Server;
use crate::state::ServerState;

/// Delay between the `200- OK` of a reboot and the reboot.
const REBOOT_REPLY_DELAY_MS: u32 = 200;
/// Line terminator of the settings file.
const LINE_END: &[u8] = b"\r\n";
/// Read buffer of the settings loader; a line that fills it is cut.
const SETTINGS_READ_CAPACITY: usize = 0x4000;

const fn entry(
    name: &'static str,
    any_of: Access,
    flags: DispatchFlags,
    handler: fn(&mut Invocation<'_>) -> Hresult,
) -> CommandEntry {
    CommandEntry {
        name,
        any_of,
        all_of: Access::NONE,
        flags,
        handler,
    }
}

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry(
        "deftitle",
        Access::CONTROL,
        DispatchFlags::NONE,
        default_title,
    ),
    entry("flash", Access::CONFIG, DispatchFlags::NONE, flash),
    entry(
        "magicboot",
        Access::CONTROL,
        DispatchFlags::NONE,
        magic_boot,
    ),
    entry("reboot", Access::CONTROL, DispatchFlags::NONE, reboot),
    entry("recovery", Access::CONFIG, DispatchFlags::NONE, recovery),
    entry(
        "setdiscboot",
        Access::CONTROL,
        DispatchFlags::DEVKIT_ONLY,
        set_disc_boot,
    ),
    entry("setreset", Access::NONE, DispatchFlags::NONE, set_reset),
    entry(
        "setsystime",
        Access::CONFIG,
        DispatchFlags::NONE,
        set_system_time,
    ),
    entry("systime", Access::NONE, DispatchFlags::NONE, system_time),
    entry("title", Access::CONTROL, DispatchFlags::NONE, title),
];

/// What the console does at the next boot before the title runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootWait {
    /// Wait for a debugger connection.
    Wait,
    /// Stop at the title entry point.
    Stop,
    /// Wait for a debugger at every boot; set only from the settings file.
    Forever,
}

/// How the console restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootKind {
    /// Return to firmware and restart the system software.
    Normal,
    /// Reset through the system management controller.
    SmcReset,
}

/// Capacity of a title string: the monitor keeps each in a 0x100-byte
/// buffer with a forced terminator.
pub const TITLE_TEXT_CAPACITY: usize = 0xff;

/// A title image path, drive path, or command line.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TitleText {
    bytes: [u8; TITLE_TEXT_CAPACITY],
    len: u8,
}

impl TitleText {
    pub const EMPTY: Self = Self {
        bytes: [0; TITLE_TEXT_CAPACITY],
        len: 0,
    };

    /// `bytes` up to the first NUL, truncated to the capacity.
    pub fn new(bytes: &[u8]) -> Self {
        let end = bytes
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(bytes.len())
            .min(TITLE_TEXT_CAPACITY);
        let mut text = Self::EMPTY;
        text.bytes[..end].copy_from_slice(&bytes[..end]);
        text.len = end as u8;
        text
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for TitleText {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl fmt::Debug for TitleText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "\"{}\"", self.as_bytes().escape_ascii())
    }
}

/// A title to launch: image object path, drive object path, and command
/// line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LaunchTitle {
    pub image: TitleText,
    pub drive: TitleText,
    pub command_line: TitleText,
}

/// Global state of this domain.
#[derive(Debug, Default)]
pub struct State {
    /// Boot-wait mode for the next boot.
    pub boot_wait: Option<BootWait>,
    /// Set once the saved settings file has been executed; the settings
    /// file is not written before.
    pub settings_loaded: bool,
    /// Set by `setsystime`; `systime` fails until then.
    pub clock_set: bool,
    /// A `recovery` command requested a recovery boot; the settings file
    /// then carries a `recovery` line.
    pub recovery_requested: bool,
    /// A settings-file `recovery` line requested a boot to recovery.
    pub recovery_boot: bool,
    /// Title for the next launch (stock 0x91fa2020).
    pub title: LaunchTitle,
    /// Default title kept across launches (stock 0x91fa232c).
    pub persistent_title: LaunchTitle,
    /// Flags of the last launch request (stock 0x91fa2324).
    pub boot_flags: BootFlags,
    /// `drivemap internal=` from the settings file (stock 0x91f9f678).
    pub internal_drive_map: bool,
    /// A launch fell back to a hardware reboot (stock 0x91fa2328); the
    /// launch title then stays for the settings file of the next boot.
    pub hard_reboot_pending: bool,
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    /// Receiving a `flash` image.
    Flash(FlashUpload),
}

/// A `flash` image being received.
#[derive(Debug, Clone, Copy)]
pub struct FlashUpload {
    /// Bytes received so far.
    received: u32,
    options: FlashOptions,
}

/// Options of a flash write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashOptions {
    /// Skip the image hardware check.
    pub ignore_version_checking: bool,
    pub stock_image: bool,
}

/// A Win32 error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32Error(pub core::num::NonZeroU32);

/// An open settings file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsFile(pub u32);

/// Settings files read at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsSource {
    /// `\SystemRoot\xbdm.ini` when it exists, else the file the monitor
    /// writes, `\SystemRoot\MobileJ.dat`.
    Saved,
    /// `\SystemRoot\recint.ini`, executed after [`SettingsSource::Saved`].
    Recint,
}

/// A copy of the settings text requested by the system software, besides
/// the saved file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsCopy {
    /// Written to the caller's open file through a 0x1000-byte buffer;
    /// with `pad`, the last write is a whole buffer.
    File { handle: u32, pad: bool },
    /// Stored in the caller's memory.
    Memory { address: u32, capacity: u32 },
}

/// Why the settings file could not be created for writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateSettingsError {
    /// The write buffer could not be allocated.
    NoBuffer,
    /// The file could not be created.
    Create(NtStatus),
}

/// Platform services this domain needs.
pub trait Backend {
    /// Create or truncate the settings file for writing.
    fn create_settings(&mut self) -> Result<SettingsFile, CreateSettingsError>;
    /// The console booted from disc; the settings file is not written.
    fn booted_from_disc(&mut self) -> bool;
    /// The settings write or wipe in progress was requested by a thread of
    /// the title process, which stock hands to the server thread.
    fn title_process_caller(&mut self) -> bool;
    /// Low dword of the size of a settings file opened for reading.
    fn settings_file_size(&mut self, file: SettingsFile) -> Result<u32, NtStatus>;
    /// Start a copy of the settings text; `None` when its buffer cannot be
    /// allocated. Bytes go through [`Backend::write_settings`].
    fn begin_settings_copy(&mut self, copy: SettingsCopy) -> Option<SettingsFile>;
    /// Finish a copy: write out what is buffered and return the length of
    /// the text, without padding.
    fn end_settings_copy(&mut self, file: SettingsFile) -> u32;
    /// Open a settings file for reading.
    fn open_settings(&mut self, source: SettingsSource) -> Option<SettingsFile>;
    /// Append bytes to a settings file opened by
    /// [`Backend::create_settings`].
    fn write_settings(&mut self, file: SettingsFile, bytes: &[u8]);
    /// Read the next bytes of a settings file; `None` at the end or on
    /// failure.
    fn read_settings(&mut self, file: SettingsFile, buffer: &mut [u8]) -> Option<usize>;
    fn close_settings(&mut self, file: SettingsFile);
    fn sleep_milliseconds(&mut self, milliseconds: u32);
    /// Restart the console. On a console this does not return.
    fn reboot(&mut self, kind: RebootKind);
    /// Set the system clock (FILETIME) and tell the network stack the
    /// clock changed.
    fn set_system_time(&mut self, file_time: u64);
    /// The first dword of the kernel hardware information.
    fn hardware_flags(&mut self) -> u32;
    /// The system registered a title launch routine that supports a
    /// relaunch (stock 0x91fa200c nonzero).
    fn title_launch_registered(&mut self) -> bool;
    /// Call the registered title launch routine.
    fn launch_title(&mut self);
    /// Allocate the buffer of a `flash` image; false when out of memory.
    fn flash_begin(&mut self, rounded_size: u32) -> bool;
    /// Store received image bytes at `offset`.
    fn flash_write(&mut self, offset: u32, bytes: &[u8]);
    /// Zero the buffer from `length` to its end, program the flash with the
    /// whole buffer, and release it.
    fn flash_commit(&mut self, length: u32, options: FlashOptions) -> Result<(), Win32Error>;
    /// Release the image buffer without programming.
    fn flash_abort(&mut self);
}

pub(crate) fn resume(continuation: &mut Continuation, cx: &mut ContinuationContext<'_>) -> Hresult {
    match continuation {
        Continuation::Flash(upload) => resume_flash(upload, cx),
    }
}

/// Append formatted text and the line terminator to a settings file
/// (stock WriteIniSz 0x91f31a50).
pub(crate) fn write_line(
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
    arguments: fmt::Arguments<'_>,
) {
    write_text(backend, file, arguments);
    end_line(backend, file);
}

/// Append formatted text to a settings file as one text (stock
/// WriteIniSzNoCRLF 0x91f319c8).
pub(crate) fn write_text(
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
    arguments: fmt::Arguments<'_>,
) {
    echo(backend, |message| {
        let _ = message.write_fmt(arguments);
    });
    let _ = SettingsWriter { backend, file }.write_fmt(arguments);
}

/// Append raw bytes to a settings file as one text (stock
/// WriteIniSzNoCRLF 0x91f319c8).
pub(crate) fn write_bytes(backend: &mut dyn AnyBackend, file: SettingsFile, bytes: &[u8]) {
    echo(backend, |message| {
        let _ = message.push_bytes(bytes);
    });
    backend.write_settings(file, bytes);
}

/// Append the line terminator to a settings file. It is not echoed.
pub(crate) fn end_line(backend: &mut dyn AnyBackend, file: SettingsFile) {
    backend.write_settings(file, LINE_END);
}

/// Append the line terminator as stock WriteIniSz with a null text does:
/// the null text is echoed.
fn end_null_line(backend: &mut dyn AnyBackend, file: SettingsFile) {
    echo_null(backend);
    end_line(backend, file);
}

/// Echo of a null text; the kernel formatter prints a null `%s` as
/// `(null)`, as the `flash` reply shows for the same formatter.
fn echo_null(backend: &mut dyn AnyBackend) {
    echo(backend, |message| {
        let _ = message.write_str("(null)");
    });
}

/// Trace bit 4 echo of each text written to a settings file.
fn echo(backend: &mut dyn AnyBackend, text: impl FnOnce(&mut commands::console::MessageText)) {
    let mask = commands::console::Backend::trace_mask(backend);
    trace_text(mask, backend, TraceMask::SETTINGS, |message| {
        let _ = message.write_str("XBDM: WriteIniSzNoCRLF: '");
        text(message);
        let _ = message.write_str("'\n");
    });
}

struct SettingsWriter<'a> {
    backend: &'a mut dyn AnyBackend,
    file: SettingsFile,
}

impl fmt::Write for SettingsWriter<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.backend.write_settings(self.file, text.as_bytes());
        Ok(())
    }
}

/// Write the settings file from the current state (stock WriteIniFile
/// 0x91f31e48). Nothing is written on a disc boot or before the saved
/// settings have been loaded. The wipe gate of stock never applies: its
/// flag 0x91f9f664 has no writer.
pub(crate) fn save_settings(state: &ServerState, backend: &mut dyn AnyBackend) {
    if backend.booted_from_disc() {
        trace(
            state,
            backend,
            TraceMask::SETTINGS,
            format_args!("XBDM: Cannot write xbdm.ini: CD boot\n"),
        );
        return;
    }
    if !state.system.settings_loaded {
        trace(
            state,
            backend,
            TraceMask::SETTINGS,
            format_args!("XBDM: WriteIniFile - not finished loading\n"),
        );
        return;
    }
    if backend.title_process_caller() {
        let text = format_args!("XBDM: WriteIniFile - called from title process - signal server\n");
        trace(state, backend, TraceMask::SETTINGS, text);
    }
    write_settings_file(state, backend, SettingsContent::Text);
}

/// What [`write_settings_file`] leaves in the file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsContent {
    Text,
    Empty,
}

/// Stock WriteIniFileImpl 0x91f31d28: create the saved settings file and
/// write the settings text, or leave it empty for a wipe.
fn write_settings_file(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    content: SettingsContent,
) {
    trace(
        state,
        backend,
        TraceMask::SETTINGS,
        format_args!("XBDM: WriteIniFileImpl - entry\n"),
    );
    let file = match backend.create_settings() {
        Ok(file) => file,
        Err(CreateSettingsError::NoBuffer) => return,
        Err(CreateSettingsError::Create(NtStatus(status))) => {
            let text = format_args!("XBDM: WriteIniFileImpl - Failed Create: 0x{status:08x}\n");
            trace(state, backend, TraceMask::SETTINGS, text);
            return;
        }
    };
    if content == SettingsContent::Text {
        settings_text(state, backend, file);
    }
    backend.close_settings(file);
    trace(
        state,
        backend,
        TraceMask::SETTINGS,
        format_args!("XBDM: WriteIniFileImpl - Done writing ini file...\n"),
    );
}

/// The lines of the settings file (stock 0x91f31a90).
fn settings_text(state: &ServerState, backend: &mut dyn AnyBackend, file: SettingsFile) {
    write_line(backend, file, format_args!("[xbdm]"));
    commands::console::verbose_settings_lines(state, backend, file);
    boot_wait_settings_lines(state, backend, file);
    title_settings_lines(state, backend, file);
    commands::console::debug_name_settings_lines(state, backend, file);
    commands::network::address_settings_lines(state, backend, file);
    commands::filesystem::dvdperf_settings_lines(state, backend, file);
    commands::memory::memtrack_settings_lines(state, backend, file);
    commands::session::notifyat_settings_lines(state, backend, file);
    commands::security::settings_lines(state, backend, file);
    commands::console::dump_settings_lines(state, backend, file);
    commands::console::dump_mode_settings_lines(state, backend, file);
    commands::debugger::settings_lines(state, backend, file);
    commands::console::httpreg_settings_lines(state, backend, file);
    commands::network::xhttpproxy_settings_lines(state, backend, file);
    if state.system.recovery_requested {
        write_line(backend, file, format_args!("recovery"));
    }
}

/// Control code 0x17 (stock WipeIniFile 0x91f321d8, WriteIniFileImpl
/// 0x91f31d28 with its wipe argument): truncate the saved settings file.
/// Neither the disc boot nor the load gate of [`save_settings`] applies;
/// the `already wiped` gate never does, as its flag has no writer.
pub fn wipe_settings(state: &ServerState, backend: &mut dyn AnyBackend) {
    if backend.title_process_caller() {
        let text = format_args!("XBDM: WipeIniFile - signaling system thread to wipe ini file.\n");
        trace(state, backend, TraceMask::SETTINGS, text);
    }
    write_settings_file(state, backend, SettingsContent::Empty);
}

/// Control codes 0x1d and 0x22 (stock WriteAltIniFile 0x91f32110 and
/// CaptureIniFile 0x91f32080, text 0x91f31fb0): the settings text, a
/// `sysset` line, and an unconditional `recovery` line. Returns the text
/// length; `None` when the copy buffer cannot be allocated.
pub fn copy_settings(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    copy: SettingsCopy,
) -> Option<u32> {
    let name = match copy {
        SettingsCopy::File { .. } => "WriteAltIniFile",
        SettingsCopy::Memory { .. } => "CaptureIniFile",
    };
    trace(
        state,
        backend,
        TraceMask::SETTINGS,
        format_args!("XBDM: {name} - start\n"),
    );
    let file = backend.begin_settings_copy(copy)?;
    settings_text(state, backend, file);
    commands::console::sysset_settings_lines(state, backend, file);
    // Stock ends the sysset line with an inlined WriteIniSz of a null text.
    echo_null(backend);
    write_line(backend, file, format_args!("recovery"));
    let length = backend.end_settings_copy(file);
    trace(
        state,
        backend,
        TraceMask::SETTINGS,
        format_args!("XBDM: {name} - end\n"),
    );
    Some(length)
}

/// Control code 0x02 (stock 0x91f3b208): the system is about to restart.
/// Exceptions go to the kernel debugger, trap pass-through ends, the
/// settings file is written, `execution rebooting` is announced, every
/// connection is closed, and no further connection is accepted.
pub fn prepare_reboot(
    server: &mut Server,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) {
    let state = &mut server.state;
    state.debugger.kernel_debugger = Some(true);
    state.debugger.trap_passthrough = false;
    state.settings_dirty = false;
    save_settings(state, backend);
    state
        .notifications
        .deliver(&Event::Execution(ExecutionState::Rebooting), network);
    for index in 0..crate::server::MAX_CONNECTIONS {
        server.close(crate::ConnectionIndex(index as u8), network);
    }
    server.shut_down();
}

/// Reason of a title launch: the first dword of the system software's
/// launch information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchReason(pub u32);

impl LaunchReason {
    /// Reasons that fall back to the persistent title.
    fn takes_persistent_title(self) -> bool {
        matches!(self.0, 0 | 4)
    }
}

/// What a title reboot does with the launching thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TitleRebootStop {
    /// Execution starts at once.
    Run,
    /// The thread stops at `execution pending_title` until resumed; the
    /// stop ends after 15 seconds unless `forever`.
    Stop { forever: bool },
}

/// Stop-on bit set only by `stopon all`; it stops title reboots of
/// reasons other than 0 and 4.
const STOP_ON_TITLE_REBOOT: u32 = 0x20;

/// Control code 0x21 (stock DmpTitleReboot 0x91f523a0) on entry with
/// launch information: the reason and the launch flags.
pub fn trace_title_reboot(state: &ServerState, backend: &mut dyn AnyBackend, reason: LaunchReason) {
    let text = format_args!(
        "[xbdm] DmpTitleReboot: Reason={}, g_XamGlobals.Flags=0x{:08x}\n",
        reason.0 as i32, state.system.boot_flags.0
    );
    trace(state, backend, TraceMask::TITLE_LAUNCH, text);
}

/// Control code 0x21 (stock 0x91f523a0): whether the launching thread
/// stops. Reason 0 never stops; reason 4 stops for the `wait` and `stop`
/// launch flags and consumes `stop`; other reasons stop after
/// `stopon all`.
pub fn title_reboot_stop(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    reason: LaunchReason,
) -> TitleRebootStop {
    let stop = match reason.0 {
        0 => {
            trace(
                state,
                backend,
                TraceMask::TITLE_LAUNCH,
                format_args!("[xbdm] DmpTitleReboot: not stopping\n"),
            );
            return TitleRebootStop::Run;
        }
        4 => {
            let flags = &mut state.system.boot_flags;
            let stop = flags.0 & (BootFlags::WAIT.0 | BootFlags::STOP.0) != 0;
            flags.0 &= !BootFlags::STOP.0;
            stop
        }
        _ => state.debugger.stop_on.0 & STOP_ON_TITLE_REBOOT != 0,
    };
    if !stop {
        return TitleRebootStop::Run;
    }
    trace(
        state,
        backend,
        TraceMask::TITLE_LAUNCH,
        format_args!("[xbdm] DmpTitleReboot: stopping\n"),
    );
    TitleRebootStop::Stop {
        forever: state.system.boot_flags.contains(BootFlags::STOP),
    }
}

/// Control code 0x77 (stock 0x91f52260): the title to launch instead of
/// the system software's choice. The launch title applies unless a
/// hardware reboot is pending; reasons 0 and 4 otherwise take the
/// persistent title.
pub fn launch_override(state: &ServerState, reason: LaunchReason) -> Option<LaunchTitle> {
    let system = &state.system;
    if !system.title.image.is_empty() && !system.hard_reboot_pending {
        return Some(system.title);
    }
    (reason.takes_persistent_title() && !system.persistent_title.image.is_empty())
        .then_some(system.persistent_title)
}

/// Control code 0x21 (stock 0x91f523a0) after the stop: as
/// [`launch_override`], but a launch title is used up and the settings
/// file rewritten.
pub fn title_reboot_launch(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    reason: LaunchReason,
) -> Option<LaunchTitle> {
    let consumed = !state.system.title.image.is_empty() && !state.system.hard_reboot_pending;
    let title = launch_override(state, reason)?;
    let kind = if consumed { "" } else { "[default] " };
    let mask = state.console.trace_mask;
    trace_text(mask, backend, TraceMask::TITLE_LAUNCH, |message| {
        let _ = write!(
            message,
            "[xbdm] DmpTitleReboot: updating {kind}launch info\n  ImageName='"
        );
        let _ = message.push_bytes(title.image.as_bytes());
        let _ = message.write_str("'\n   DDrive='");
        let _ = message.push_bytes(title.drive.as_bytes());
        let _ = message.write_str("'\n   CommandLine='");
        let _ = message.push_bytes(title.command_line.as_bytes());
        let _ = message.write_str("'\n");
    });
    if consumed {
        state.system.title = LaunchTitle::default();
        save_settings(state, backend);
    }
    Some(title)
}

/// Stock FTitleExists 0x91f447c8 after boot: the image opens, disc images
/// included.
pub fn launch_image_exists(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    image: &[u8],
) -> bool {
    title_exists(state, backend, image, TitleCheck::PostBoot)
}

fn boot_wait_settings_lines(state: &ServerState, backend: &mut dyn AnyBackend, file: SettingsFile) {
    let line = match state.system.boot_wait {
        None => return,
        Some(BootWait::Wait) => "wait",
        Some(BootWait::Stop) => "wait stop",
        Some(BootWait::Forever) => "wait forever",
    };
    write_line(backend, file, format_args!("{line}"));
}

/// Title lines (stock 0x91f51ed0). The command line of the persistent
/// title is quoted but reloads with its quotes, since `cmdline` takes the
/// rest of the line.
fn title_settings_lines(state: &ServerState, backend: &mut dyn AnyBackend, file: SettingsFile) {
    let persistent = &state.system.persistent_title;
    if !persistent.image.is_empty() {
        write_text(backend, file, format_args!("title persist name=\""));
        write_bytes(backend, file, persistent.image.as_bytes());
        if !persistent.drive.is_empty() {
            write_text(backend, file, format_args!("\" dir=\""));
            write_bytes(backend, file, persistent.drive.as_bytes());
        }
        if !persistent.command_line.is_empty() {
            write_text(backend, file, format_args!("\" cmdline=\""));
            write_bytes(backend, file, persistent.command_line.as_bytes());
        }
        write_line(backend, file, format_args!("\""));
    }
    let current = &state.system.title;
    if !current.image.is_empty() {
        write_text(backend, file, format_args!("title"));
        if state.system.boot_flags.0 != 0 {
            write_text(
                backend,
                file,
                format_args!(" flags=0x{:08x}", state.system.boot_flags.0),
            );
        }
        write_text(backend, file, format_args!(" name=\""));
        write_bytes(backend, file, current.image.as_bytes());
        if !current.drive.is_empty() {
            write_text(backend, file, format_args!("\" dir=\""));
            write_bytes(backend, file, current.drive.as_bytes());
        }
        write_text(backend, file, format_args!("\""));
        if !current.command_line.is_empty() {
            write_text(backend, file, format_args!(" cmdline="));
            write_bytes(backend, file, current.command_line.as_bytes());
        }
        end_null_line(backend, file);
    }
}

/// Startup: execute the saved settings file and then `recint.ini` (stock
/// LoadIniFile 0x91f316b8), apply the settings that act at boot, and
/// consume a one-time boot-wait mode.
pub fn load_settings(server: &mut Server, backend: &mut dyn AnyBackend, network: &mut dyn Network) {
    commands::console::initialize(&mut server.state, backend);
    let mut buffer = [0u8; SETTINGS_READ_CAPACITY];
    if let Some(file) = backend.open_settings(SettingsSource::Saved) {
        if server
            .state
            .console
            .trace_mask
            .contains(TraceMask::SETTINGS)
        {
            trace_settings_file(&server.state, backend, file);
        }
        execute_settings_file(server, backend, network, file, &mut buffer);
        backend.close_settings(file);
    }
    let text = format_args!("XBDM: g_fFinishedLoadingIniFile = TRUE\n");
    trace(&server.state, backend, TraceMask::SETTINGS, text);
    server.state.system.settings_loaded = true;
    if let Some(file) = backend.open_settings(SettingsSource::Recint) {
        execute_settings_file(server, backend, network, file, &mut buffer);
        trace(
            &server.state,
            backend,
            TraceMask::SETTINGS,
            format_args!("XBDM: Finished loading recint.ini\n"),
        );
        backend.close_settings(file);
    }
    if server.state.system.internal_drive_map {
        server.state.filesystem.drives.map_internal_drives();
    } else {
        commands::console::check_settings_block(&mut server.state, backend);
    }
    commands::session::connect_persistent_targets(&mut server.state, backend, network);
    let system = &mut server.state.system;
    if matches!(system.boot_wait, Some(BootWait::Wait | BootWait::Stop)) {
        system.boot_wait = None;
        save_settings(&server.state, backend);
    }
}

/// The saved settings file before it is executed (stock 0x91f31758 and
/// 0x91f31538).
fn trace_settings_file(state: &ServerState, backend: &mut dyn AnyBackend, file: SettingsFile) {
    trace(
        state,
        backend,
        TraceMask::SETTINGS,
        format_args!("XBDM: LoadIniFile\n"),
    );
    let SettingsFile(handle) = file;
    match backend.settings_file_size(file) {
        Ok(size) => {
            let text = format_args!("XBDM: Handle: 0x{handle:08x}, File Size: {}\n", size as i32);
            trace(state, backend, TraceMask::SETTINGS, text);
        }
        Err(NtStatus(status)) => {
            let text = format_args!("XBDM: NtQueryInformationFile Failed: 0x{status:08x}\n");
            trace(state, backend, TraceMask::SETTINGS, text);
        }
    }
}

/// Execute each line of a settings file (stock 0x91f315a0). Lines end at
/// CR or LF. A line that starts with NUL ends the file, and text that
/// reaches the end of the buffer without a terminator loses its last byte.
fn execute_settings_file(
    server: &mut Server,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    file: SettingsFile,
    buffer: &mut [u8; SETTINGS_READ_CAPACITY],
) {
    let mut count = 0;
    loop {
        if count != 0 {
            let mut start = 0;
            for position in 0..count {
                if matches!(buffer[position], b'\n' | b'\r') {
                    buffer[position] = 0;
                    server.execute_settings_line(&buffer[start..position], backend, network);
                    start = position + 1;
                }
            }
            // Stock tests the byte at the remainder start, which lies past
            // the data when the buffer ends in a terminator; that byte is
            // taken as nonzero.
            if start < count && buffer[start] == 0 {
                return;
            }
            if start != 0 {
                buffer.copy_within(start..count, 0);
                count -= start;
            } else {
                buffer[count - 1] = 0;
                server.execute_settings_line(&buffer[..count - 1], backend, network);
                count = 0;
            }
        }
        if let Some(read) = backend.read_settings(file, &mut buffer[count..]) {
            count += read;
        }
        if count == 0 {
            return;
        }
    }
}

/// Settings-file keywords handled before the command table (stock
/// DoIniLine 0x91f311b8). Returns whether the line was consumed.
pub(crate) fn settings_keyword(invocation: &mut Invocation<'_>) -> bool {
    let word = invocation.line.command();
    let is = |keyword: &str| word.eq_ignore_ascii_case(keyword.as_bytes());
    if word.is_empty() {
        return false;
    }
    if is("wait") {
        invocation.state.system.boot_wait = Some(if invocation.line.has("forever") {
            BootWait::Forever
        } else if invocation.line.has("stop") {
            BootWait::Stop
        } else {
            BootWait::Wait
        });
    } else if is("notify") {
        // Notification channels need a connection; the line is ignored.
    } else if is("notifyat") {
        commands::session::ini_notifyat(invocation);
    } else if is("staticip") {
        commands::network::ini_staticip(invocation);
    } else if is("gateway") {
        commands::network::ini_gateway(invocation);
    } else if is("subnet") {
        commands::network::ini_subnet(invocation);
    } else if is("memtrack") {
        commands::memory::ini_memtrack(invocation);
    } else if is("drivemap") {
        if let Some(internal) = invocation
            .line
            .param("internal")
            .and_then(|value| value.dword())
        {
            invocation.state.system.internal_drive_map = internal != 0;
        }
    } else if is("sysset") {
        commands::console::ini_sysset(invocation);
    } else if is("httpreg") {
        commands::console::ini_httpreg(invocation);
    } else if is("netsim") {
        commands::network::ini_netsim(invocation);
    } else if is("xhttpproxy") {
        commands::network::ini_xhttpproxy(invocation);
    } else {
        return false;
    }
    true
}

/// Restart without a connection to report to: write settings, announce
/// `execution rebooting`, close the notification channels, and reboot.
fn reboot_from_settings(invocation: &mut Invocation<'_>, kind: RebootKind) {
    save_settings(invocation.state, invocation.backend);
    invocation.state.notifications.deliver(
        &Event::Execution(ExecutionState::Rebooting),
        invocation.network,
    );
    invocation.state.notifications.close_all(invocation.network);
    invocation.backend.reboot(kind);
}

/// `reboot [stop] [wait] [smcreset]`: reply, then restart. The server
/// writes the settings file, sends `execution rebooting`, and closes every
/// connection and notification channel before the restart.
fn reboot(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(session) = invocation.session.as_deref_mut() else {
        return Hresult::NO_REPLY;
    };
    let kind = if invocation.line.has("smcreset") {
        RebootKind::SmcReset
    } else {
        RebootKind::Normal
    };
    session.request(SessionRequest::Reboot(kind));
    let _ = invocation.send_line(b"200- OK");
    invocation.backend.sleep_milliseconds(REBOOT_REPLY_DELAY_MS);
    let system = &mut invocation.state.system;
    if system.boot_wait.is_none() {
        if invocation.line.has("stop") {
            system.boot_wait = Some(BootWait::Stop);
        } else if invocation.line.has("wait") {
            system.boot_wait = Some(BootWait::Wait);
        }
    }
    invocation.state.settings_dirty = true;
    Hresult::NO_REPLY
}

/// `recovery`: request a recovery boot and restart. From the settings file
/// the line only records the request.
fn recovery(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        invocation.state.system.recovery_boot = true;
        return Hresult::FAIL;
    }
    invocation.state.system.recovery_requested = true;
    launch(invocation, BootFlags::COLD, None)
}

/// Flags of a title launch (stock 0x91fa2324).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BootFlags(pub u32);

impl BootFlags {
    pub const WAIT: Self = Self(0x1);
    pub const COLD: Self = Self(0x4);
    pub const STOP: Self = Self(0x8);
    /// Export 125: the paths are object paths and are not translated.
    pub const OBJECT_PATHS: Self = Self(0x10);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// The hardware reboot of stock 0x91f278a8: reply, wait, record the
/// boot-wait mode, then restart through the session or directly.
fn hard_reboot(invocation: &mut Invocation<'_>, flags: BootFlags) {
    if invocation.session.is_some() {
        let _ = invocation.send_line(b"200- OK");
        invocation.backend.sleep_milliseconds(REBOOT_REPLY_DELAY_MS);
    }
    record_hard_reboot(&mut invocation.state.system, flags);
    match invocation.session.as_deref_mut() {
        Some(session) => {
            session.request(SessionRequest::Reboot(RebootKind::Normal));
            invocation.state.settings_dirty = true;
        }
        None => reboot_from_settings(invocation, RebootKind::Normal),
    }
}

/// Mark the launch title for the next boot and record the boot-wait mode
/// the flags ask for, unless one is set.
fn record_hard_reboot(system: &mut State, flags: BootFlags) {
    system.hard_reboot_pending = true;
    if system.boot_wait.is_none() {
        if flags.contains(BootFlags::STOP) {
            system.boot_wait = Some(BootWait::Stop);
        } else if flags.contains(BootFlags::WAIT) {
            system.boot_wait = Some(BootWait::Wait);
        }
    }
}

/// `systime`: the system clock as FILETIME halves, once `setsystime` has
/// run.
fn system_time(invocation: &mut Invocation<'_>) -> Hresult {
    if !invocation.state.system.clock_set {
        return Hresult::from_error_code(ErrorCode::CLOCK_NOT_SET);
    }
    let time = invocation.backend.system_time();
    invocation.set_text(format_args!(
        "high=0x{:x} low=0x{:x}",
        (time >> 32) as u32,
        time as u32
    ));
    Hresult::OK
}

/// `setsystime clockhi=<dword> clocklo=<dword> [tz=<dword>]`: set the
/// clock; with `tz`, fill in a default time zone when none is configured.
fn set_system_time(invocation: &mut Invocation<'_>) -> Hresult {
    let dword = |name: &str| invocation.line.param(name).and_then(|value| value.dword());
    let (Some(high), Some(low)) = (dword("clockhi"), dword("clocklo")) else {
        return Hresult::from_error_code(ErrorCode::CLOCK_NOT_SET);
    };
    let has_zone = dword("tz").is_some();
    let backend = &mut *invocation.backend;
    backend.set_system_time(u64::from(high) << 32 | u64::from(low));
    invocation.state.system.clock_set = true;
    if !has_zone {
        return Hresult::OK;
    }
    let mut standard_name = [0u8; 4];
    if backend
        .xconfig_get(ConfigSetting::new(3, 2), &mut standard_name)
        .is_err()
    {
        return Hresult::OK;
    }
    if standard_name[0] == 0 {
        const DEFAULT_ZONE: [(u16, [u8; 4]); 7] = [
            (1, 0x1e0u32.to_be_bytes()),
            (2, *b"PST\0"),
            (3, *b"PDT\0"),
            (6, 0u32.to_be_bytes()),
            (7, 0xffff_ffc4u32.to_be_bytes()),
            (4, [0x0a, 0x05, 0x00, 0x00]),
            (5, [0x04, 0x01, 0x00, 0x00]),
        ];
        for (index, value) in DEFAULT_ZONE {
            if backend
                .xconfig_set(ConfigSetting::new(3, index), &value)
                .is_err()
            {
                return Hresult::from_error_code(ErrorCode::CLOCK_NOT_SET);
            }
        }
    }
    // A failed read leaves the value zero, as in stock.
    let mut enabled = [0u8; 4];
    let _ = backend.xconfig_get(ConfigSetting::new(3, 9), &mut enabled);
    if enabled != [0; 4] {
        return Hresult::OK;
    }
    match backend.xconfig_set(ConfigSetting::new(3, 9), &1u32.to_be_bytes()) {
        Ok(()) => Hresult::OK,
        Err(_) => Hresult::from_error_code(ErrorCode::CLOCK_NOT_SET),
    }
}

/// `setdiscboot enable=<0|1>`: select the boot device bits of
/// configuration setting (3, 0xc) through the kernel modify export.
fn set_disc_boot(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(enable) = util::required_dword(invocation, "enable") else {
        return util::MISSING;
    };
    let or_mask = match enable {
        0 => 0x80,
        1 => 0x2000,
        _ => return Hresult::FAIL,
    };
    match invocation.backend.xconfig_modify(
        ConfigSetting::new(3, 0xc),
        !or_mask & 0xfffd_d77f,
        or_mask,
    ) {
        Ok(()) => Hresult::OK,
        Err(NtStatus(status)) => {
            invocation.set_text(format_args!("Modify failed: 0x{status:08x}"));
            Hresult::FAIL
        }
    }
}

/// Size of the reset chord configuration setting (2, 5).
const RESET_CHORD_SIZE: usize = 5;

/// `setreset [chord=<string>]`: store the reset button chord (up to four
/// characters), or report the stored one.
fn set_reset(invocation: &mut Invocation<'_>) -> Hresult {
    let setting = ConfigSetting::new(2, 5);
    let mut chord = [0u8; RESET_CHORD_SIZE];
    let result = match invocation.line.param("chord") {
        Some(value) => {
            // Stock leaves the bytes after the terminator uninitialized;
            // they are stored as zero.
            value.copy_into(&mut chord);
            invocation
                .backend
                .xconfig_set(setting, &chord)
                .map(|()| None)
        }
        None => invocation
            .backend
            .xconfig_get(setting, &mut chord)
            .map(Some),
    };
    match result {
        Ok(None) => Hresult::OK,
        Ok(Some(length)) => {
            let stored = &chord[..length.min(RESET_CHORD_SIZE)];
            let end = stored
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(stored.len());
            invocation.text.set_bytes(&stored[..end]);
            Hresult::OK
        }
        Err(_) => {
            invocation.set_text(format_args!("Could not change reset key"));
            Hresult::FAIL
        }
    }
}

/// Object path buffer of the title commands.
const TITLE_PATH_CAPACITY: usize = 0x100;
/// Buffer of a string parameter of the title commands.
const TITLE_PARAMETER_BUFFER: usize = 0x100;
/// Launch flags that rule out a relaunch without a hardware reboot.
const HARD_REBOOT_FLAGS: u32 = 0x6;
/// Images under this prefix are launched without an existence check.
const DISC_IMAGE_PREFIX: &[u8] = b"\\device\\cdrom0";
const DEFAULT_TITLE_PATH: &[u8] = b"\\SystemRoot\\dashboard.xbx";
const LAUNCHER_PATH: &[u8] = b"\\SystemRoot\\xshell.xex";
/// Size of the default-title file: `<directory>;<file>` padded with NUL.
const DEFAULT_TITLE_SIZE: usize = 0x100;
/// Buffer of the `deftitle` `dir` parameter.
const DEFAULT_TITLE_DIRECTORY_BUFFER: usize = 0x104;
/// Flash images are programmed in whole 0x4000-byte blocks.
const FLASH_BLOCK: u32 = 0x4000;

/// An object path of at most [`TITLE_PATH_CAPACITY`] bytes.
#[derive(Clone, Copy)]
struct TitlePath {
    bytes: [u8; TITLE_PATH_CAPACITY],
    len: usize,
}

impl TitlePath {
    const EMPTY: Self = Self {
        bytes: [0; TITLE_PATH_CAPACITY],
        len: 0,
    };

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Append, dropping what does not fit.
    fn push(&mut self, bytes: &[u8]) {
        let count = bytes.len().min(TITLE_PATH_CAPACITY - self.len);
        self.bytes[self.len..self.len + count].copy_from_slice(&bytes[..count]);
        self.len += count;
    }
}

/// A string parameter copied into a buffer the size stock uses.
fn string_param<'b>(line: CommandLine<'_>, name: &str, buffer: &'b mut [u8]) -> Option<&'b [u8]> {
    Some(line.param(name)?.copy_into(buffer))
}

/// Translate a drive path to an object path, limited as stock's
/// 0x100-byte destination buffers limit it.
fn translate_title_path(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    path: &[u8],
) -> Option<TitlePath> {
    let object = state.filesystem.drives.translate(backend, path)?;
    let mut translated = TitlePath::EMPTY;
    translated.push(object.as_bytes());
    Some(translated)
}

/// When stock FTitleExists 0x91f447c8 runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TitleCheck {
    /// Before a launch: disc images count as present.
    PreBoot,
    /// At the launch: every image must open.
    PostBoot,
}

fn title_exists(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    image: &[u8],
    check: TitleCheck,
) -> bool {
    let post_boot = if check == TitleCheck::PostBoot {
        "TRUE"
    } else {
        "FALSE"
    };
    trace_text(
        state.console.trace_mask,
        backend,
        TraceMask::PATHS,
        |message| {
            let _ = message.write_str("[xbdm] FTitleExists(oszImage='");
            let _ = message.push_bytes(image);
            let _ = writeln!(message, "',fPostBoot={post_boot})");
        },
    );
    if check == TitleCheck::PreBoot
        && image.len() >= DISC_IMAGE_PREFIX.len()
        && image[..DISC_IMAGE_PREFIX.len()].eq_ignore_ascii_case(DISC_IMAGE_PREFIX)
    {
        return true;
    }
    let request = CreateRequest::open(
        FileAccess::SYNCHRONIZE,
        ShareAccess::READ,
        CreateOptions::SYNCHRONOUS_IO_NONALERT.union(CreateOptions::NON_DIRECTORY_FILE),
    );
    let exists = match backend.create_file(image, &request) {
        Ok(handle) => {
            backend.close_file(handle);
            true
        }
        Err(_) => false,
    };
    let result = if exists { "TRUE" } else { "FALSE" };
    trace(
        state,
        backend,
        TraceMask::PATHS,
        format_args!("[xbdm] FTitleExists() returning {result}\n"),
    );
    exists
}

/// Stock FGetImageAndDrive 0x91f44608: with a nonempty `dir`, the drive is
/// the translated directory and the image is the drive, a backslash, and
/// `name`; otherwise the image is the translated `name`.
fn image_and_drive(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    name: &[u8],
    dir: Option<&[u8]>,
) -> Option<(TitlePath, TitlePath)> {
    trace_text(
        state.console.trace_mask,
        backend,
        TraceMask::PATHS,
        |message| {
            let _ = message.write_str("[xbdm] FGetImageAndDrive(\n   szTitle='");
            let _ = message.push_bytes(name);
            let _ = message.write_str("',\n   szDir='");
            let _ = message.push_bytes(dir.unwrap_or(b"(null)"));
            let _ = message.write_str("',\n   ...)\n");
        },
    );
    let paths = join_image_and_drive(state, backend, name, dir);
    trace_text(
        state.console.trace_mask,
        backend,
        TraceMask::PATHS,
        |message| match &paths {
            Some((image, drive)) => {
                let _ = message.write_str("[xbdm] FGetImageAndDrive succeeded:\n   oszImage='");
                let _ = message.push_bytes(image.as_bytes());
                let _ = message.write_str("'\n   oszDrive='");
                let _ = message.push_bytes(drive.as_bytes());
                let _ = message.write_str("'\n");
            }
            None => {
                let _ = message.write_str("[xbdm] FGetImageAndDrive failed:\n");
            }
        },
    );
    paths
}

fn join_image_and_drive(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    name: &[u8],
    dir: Option<&[u8]>,
) -> Option<(TitlePath, TitlePath)> {
    let Some(dir) = dir.filter(|dir| !dir.is_empty()) else {
        return Some((
            translate_title_path(state, backend, name)?,
            TitlePath::EMPTY,
        ));
    };
    let drive = translate_title_path(state, backend, dir)?;
    let overflow = |state: &ServerState, backend: &mut dyn AnyBackend, what: &str| {
        trace(
            state,
            backend,
            TraceMask::PATHS,
            format_args!("[xbdm] FGetImageAndDrive buffer overflow {what}\n"),
        );
    };
    // The copy needs room for its terminator, and a missing separator for
    // one more byte.
    if drive.len == TITLE_PATH_CAPACITY {
        overflow(state, backend, "copying path");
        return None;
    }
    let mut image = drive;
    if image.as_bytes().last() != Some(&b'\\') {
        if image.len + 1 == TITLE_PATH_CAPACITY {
            overflow(state, backend, "appending '\\'");
            return None;
        }
        image.push(b"\\");
    }
    // A name that leaves no room for the terminator is cut and still
    // succeeds.
    if image.len + name.len() >= TITLE_PATH_CAPACITY {
        overflow(state, backend, "appending title");
    }
    image.push(name);
    Some((image, drive))
}

/// Stock 0x91f46ff0: check the image, then store the launch title and,
/// with `persist`, the default title, and write the settings file.
fn set_title(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    image: &[u8],
    drive: Option<&[u8]>,
    command_line: Option<&[u8]>,
    persist: bool,
) -> Hresult {
    if !title_exists(state, backend, image, TitleCheck::PreBoot) {
        return Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND);
    }
    let title = LaunchTitle {
        image: TitleText::new(image),
        drive: drive.map(TitleText::new).unwrap_or_default(),
        command_line: command_line.map(TitleText::new).unwrap_or_default(),
    };
    if persist {
        state.system.persistent_title = title;
    }
    state.system.title = title;
    save_settings(state, backend);
    Hresult::OK
}

/// Flags of export 81.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TitleFlags(pub u32);

impl TitleFlags {
    /// The title also becomes the persistent title.
    pub const PERSIST: Self = Self(0x1);
    /// Clear the persistent title first.
    pub const CLEAR_PERSISTENT: Self = Self(0x2);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Export 81 (stock 0x91f47140), and export 42 with no flags: set the
/// launch title from the drive paths `dir` and `name`. With
/// [`TitleFlags::CLEAR_PERSISTENT`] and no `name`, only the persistent
/// title is cleared.
pub fn set_title_from_paths(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    dir: Option<&[u8]>,
    name: Option<&[u8]>,
    command_line: Option<&[u8]>,
    flags: TitleFlags,
) -> Hresult {
    if flags.contains(TitleFlags::CLEAR_PERSISTENT) {
        state.system.persistent_title = LaunchTitle::default();
        if name.is_none() {
            save_settings(state, backend);
            return Hresult::OK;
        }
    }
    let Some(name) = name else {
        return Hresult::INVALID_ARGUMENT;
    };
    let Some((image, drive)) = image_and_drive(state, backend, name, dir) else {
        return Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND);
    };
    set_title(
        state,
        backend,
        image.as_bytes(),
        Some(drive.as_bytes()),
        command_line,
        flags.contains(TitleFlags::PERSIST),
    )
}

/// `title nopersist` | `title name=<s> [dir=<s>] [persist] [cmdline=<rest>]`:
/// set the title for the next launch. From the settings file `flags=` is
/// honored and `name`/`dir` are object paths taken as given; from a
/// connection they are drive paths, as for export 81. The settings file
/// is written again after the title is set.
fn title(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    let loading = invocation.session.is_none();
    if loading && let Some(flags) = line.param("flags").and_then(|value| value.dword()) {
        invocation.state.system.boot_flags = BootFlags(flags);
    }
    if line.has("nopersist") {
        invocation.state.system.persistent_title = LaunchTitle::default();
        // Stock writes the settings file twice here.
        save_settings(invocation.state, invocation.backend);
        save_settings(invocation.state, invocation.backend);
        return Hresult::OK;
    }
    let mut dir_buffer = [0u8; TITLE_PARAMETER_BUFFER];
    let dir = string_param(line, "dir", &mut dir_buffer);
    let mut name_buffer = [0u8; TITLE_PARAMETER_BUFFER];
    let Some(name) = string_param(line, "name", &mut name_buffer) else {
        invocation.set_text(format_args!("missing name"));
        return Hresult::FAIL;
    };
    let persist = line.has("persist");
    let command_line = line.param("cmdline").map(|value| value.raw());
    let result = if loading {
        set_title(
            invocation.state,
            invocation.backend,
            name,
            dir,
            command_line,
            persist,
        )
    } else {
        let flags = if persist {
            TitleFlags::PERSIST
        } else {
            TitleFlags::default()
        };
        set_title_from_paths(
            invocation.state,
            invocation.backend,
            dir,
            Some(name),
            command_line,
            flags,
        )
    };
    save_settings(invocation.state, invocation.backend);
    result
}

/// Title strings of a launch request.
#[derive(Debug, Clone, Copy)]
pub struct LaunchRequest<'a> {
    pub image: &'a [u8],
    pub drive: Option<&'a [u8]>,
    pub command_line: Option<&'a [u8]>,
}

/// How a launch continues after [`begin_launch`].
enum LaunchOutcome {
    Done(Hresult),
    /// Restart the console with these flags.
    HardReboot(BootFlags),
}

/// Stock 0x91f278a8 up to the hardware reboot: record the launch, then
/// relaunch the title in place when the flags and console allow it.
fn begin_launch(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    flags: BootFlags,
    request: Option<LaunchRequest<'_>>,
) -> LaunchOutcome {
    if let Some(request) = &request
        && !title_exists(state, backend, request.image, TitleCheck::PreBoot)
    {
        return LaunchOutcome::Done(Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND));
    }
    let execution = backend.execution_state();
    let system = &mut state.system;
    system.boot_flags = flags;
    if let Some(request) = request {
        system.title = LaunchTitle {
            image: TitleText::new(request.image),
            drive: request.drive.map(TitleText::new).unwrap_or_default(),
            command_line: request.command_line.map(TitleText::new).unwrap_or_default(),
        };
    }
    let mut effective = flags;
    if !state.system.internal_drive_map
        && commands::console::trinity_or_later(backend.hardware_flags())
        && !backend.is_test_kit()
        && !commands::console::settings_block_readable(backend)
    {
        effective = BootFlags(effective.0 | BootFlags::COLD.0);
    }
    if effective.0 & HARD_REBOOT_FLAGS == 0 {
        if execution == ExecutionState::RebootTitle {
            return LaunchOutcome::Done(Hresult::OK);
        }
        if backend.title_launch_registered()
            && !commands::debugger::threads_block_relaunch(state, backend)
        {
            let _ = commands::debugger::change_execution(
                state,
                backend,
                network,
                ExecutionState::RebootTitle,
            );
            state.system.boot_flags = effective;
            backend.launch_title();
            return LaunchOutcome::Done(Hresult::OK);
        }
    }
    LaunchOutcome::HardReboot(effective)
}

/// Stock 0x91f278a8 for a command: the hardware reboot replies first.
fn launch(
    invocation: &mut Invocation<'_>,
    flags: BootFlags,
    request: Option<LaunchRequest<'_>>,
) -> Hresult {
    match begin_launch(
        invocation.state,
        invocation.backend,
        invocation.network,
        flags,
        request,
    ) {
        LaunchOutcome::Done(result) => result,
        LaunchOutcome::HardReboot(effective) => {
            hard_reboot(invocation, effective);
            Hresult::NO_REPLY
        }
    }
}

/// Exports 28 and 125 (stock 0x91f278a8 with no connection): launch a
/// title, relaunching in place when possible; otherwise prepare the
/// restart as control code 0x02 does and restart, which on a console
/// does not return.
pub fn launch_without_connection(
    server: &mut Server,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    flags: BootFlags,
    request: Option<LaunchRequest<'_>>,
) -> Hresult {
    match begin_launch(&mut server.state, backend, network, flags, request) {
        LaunchOutcome::Done(result) => result,
        LaunchOutcome::HardReboot(effective) => {
            record_hard_reboot(&mut server.state.system, effective);
            prepare_reboot(server, backend, network);
            backend.reboot(RebootKind::Normal);
            Hresult::NO_REPLY
        }
    }
}

/// Export 125 (stock 0x91f27ab8): launch with drive paths, or with object
/// paths when `flags` has [`BootFlags::OBJECT_PATHS`]. Without an image,
/// a drive or command line is an invalid argument.
pub fn launch_from_paths(
    server: &mut Server,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    flags: BootFlags,
    image: Option<&[u8]>,
    drive: Option<&[u8]>,
    command_line: Option<&[u8]>,
) -> Hresult {
    let Some(image) = image else {
        if drive.is_some() || command_line.is_some() {
            return Hresult::INVALID_ARGUMENT;
        }
        return launch_without_connection(server, backend, network, flags, None);
    };
    if flags.contains(BootFlags::OBJECT_PATHS) {
        let request = LaunchRequest {
            image,
            drive,
            command_line,
        };
        return launch_without_connection(server, backend, network, flags, Some(request));
    }
    let Some(image) = translate_title_path(&mut server.state, backend, image) else {
        return Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND);
    };
    let drive = match drive {
        Some(drive) => match translate_title_path(&mut server.state, backend, drive) {
            Some(drive) => Some(drive),
            None => return Hresult::from_error_code(ErrorCode::PATH_NOT_FOUND),
        },
        None => None,
    };
    let request = LaunchRequest {
        image: image.as_bytes(),
        drive: drive.as_ref().map(TitlePath::as_bytes),
        command_line,
    };
    launch_without_connection(server, backend, network, flags, Some(request))
}

/// `magicboot [warm] [cold] [wait] [stop] [title=<s>] [directory=<s>]
/// [cmdline=<s>]`: launch a title, relaunching in place when possible.
fn magic_boot(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    let mut flags = 0;
    for (name, bit) in [
        ("warm", BootFlags::COLD),
        ("cold", BootFlags::COLD),
        ("wait", BootFlags::WAIT),
        ("stop", BootFlags::STOP),
    ] {
        if line.has(name) {
            flags |= bit.0;
        }
    }
    let mut buffer = [0u8; TITLE_PARAMETER_BUFFER];
    let image = match string_param(line, "title", &mut buffer) {
        Some(title) => match translate_title_path(invocation.state, invocation.backend, title) {
            Some(image) => Some(image),
            None => return Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND),
        },
        None => None,
    };
    let directory = match string_param(line, "directory", &mut buffer) {
        Some(directory) => {
            match translate_title_path(invocation.state, invocation.backend, directory) {
                Some(drive) => Some(drive),
                None => return Hresult::from_error_code(ErrorCode::PATH_NOT_FOUND),
            }
        }
        None => None,
    };
    let mut command_line_buffer = [0u8; TITLE_PARAMETER_BUFFER];
    let command_line = string_param(line, "cmdline", &mut command_line_buffer);
    let request = image.as_ref().map(|image| LaunchRequest {
        image: image.as_bytes(),
        drive: directory.as_ref().map(TitlePath::as_bytes),
        command_line,
    });
    launch(invocation, BootFlags(flags), request)
}

/// `deftitle none` | `deftitle launcher` | `deftitle dir=<s> name=<s>`:
/// replace or delete the default title file `\SystemRoot\dashboard.xbx`.
fn default_title(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    let backend = &mut *invocation.backend;
    let synchronous = CreateOptions::SYNCHRONOUS_IO_NONALERT;
    // Clear attributes such as read-only first; failures do not matter.
    let attributes = CreateRequest::open(
        FileAccess::WRITE_ATTRIBUTES.union(FileAccess::SYNCHRONIZE),
        ShareAccess::NONE,
        synchronous,
    );
    if let Ok(handle) = backend.create_file(DEFAULT_TITLE_PATH, &attributes) {
        let normal = BasicInformation {
            attributes: FileAttributes::NORMAL,
            ..BasicInformation::default()
        };
        let _ = backend.set_basic_information(handle, &normal);
        backend.close_file(handle);
    }
    if line.has("none") {
        let delete = CreateRequest::open(
            FileAccess::DELETE.union(FileAccess::SYNCHRONIZE),
            ShareAccess::NONE,
            synchronous,
        );
        let Ok(handle) = backend.create_file(DEFAULT_TITLE_PATH, &delete) else {
            return Hresult::OK;
        };
        let deleted = backend.set_delete_disposition(handle, true);
        backend.close_file(handle);
        return if deleted.is_ok() {
            Hresult::OK
        } else {
            Hresult::UNEXPECTED
        };
    }

    let mut content = [0u8; DEFAULT_TITLE_SIZE + 1];
    let file_start = if line.has("launcher") {
        content[..LAUNCHER_PATH.len()].copy_from_slice(LAUNCHER_PATH);
        LAUNCHER_PATH
            .iter()
            .rposition(|&byte| byte == b'\\')
            .map_or(0, |separator| separator + 1)
    } else {
        let mut dir_buffer = [0u8; DEFAULT_TITLE_DIRECTORY_BUFFER];
        let Some(dir) = string_param(line, "dir", &mut dir_buffer) else {
            invocation.set_text(format_args!("missing dir"));
            return Hresult::FAIL;
        };
        let Some(directory) = translate_title_path(invocation.state, invocation.backend, dir)
        else {
            return Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND);
        };
        let mut length = directory.len;
        content[..length].copy_from_slice(directory.as_bytes());
        if length == 0 || content[length - 1] != b'\\' {
            content[length] = b'\\';
            length += 1;
        }
        let Some(name) = line.param("name") else {
            invocation.set_text(format_args!("missing name"));
            return Hresult::FAIL;
        };
        let end = DEFAULT_TITLE_SIZE.max(length);
        name.copy_into(&mut content[length..end]);
        length
    };

    let backend = &mut *invocation.backend;
    let path_end = content
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(DEFAULT_TITLE_SIZE);
    let check = CreateRequest::open(
        FileAccess::SYNCHRONIZE,
        ShareAccess::READ,
        synchronous.union(CreateOptions::NON_DIRECTORY_FILE),
    );
    match backend.create_file(&content[..path_end], &check) {
        Ok(handle) => backend.close_file(handle),
        Err(status) => {
            return Hresult::from_nt_status(
                status,
                Hresult::from_error_code(ErrorCode::ACCESS_DENIED),
            );
        }
    }
    content[file_start - 1] = b';';
    let create = CreateRequest {
        access: FileAccess::GENERIC_WRITE
            .union(FileAccess::DELETE)
            .union(FileAccess::SYNCHRONIZE),
        allocation_size: None,
        attributes: FileAttributes::NONE,
        share: ShareAccess::NONE,
        disposition: CreateDisposition::OverwriteIf,
        options: synchronous,
    };
    let Ok(handle) = backend.create_file(DEFAULT_TITLE_PATH, &create) else {
        return Hresult::FAIL;
    };
    let result = match backend.write_file(
        handle,
        None,
        FileData::Bytes(&content[..DEFAULT_TITLE_SIZE]),
    ) {
        Ok(()) => Hresult::OK,
        Err(_) => match backend.set_delete_disposition(handle, true) {
            Ok(()) => Hresult::OK,
            Err(_) => Hresult::UNEXPECTED,
        },
    };
    backend.close_file(handle);
    result
}

/// Hardware selector values (kernel hardware flags & 0xff000003), the size
/// parameter each requires, and the suffix reported for it.
const FLASH_HARDWARE: [(u32, &str, &str); 16] = [
    (0x0000_0003, "size_w2", "w2"),
    (0x0200_0003, "size_tw2", "tw2"),
    (0x1000_0003, "size_z", "z"),
    (0x1200_0003, "size_zt", "zt"),
    (0x2000_0003, "size_f", "f"),
    (0x2200_0003, "size_ft", "ft"),
    (0x3000_0003, "size_j", "j"),
    (0x3200_0003, "size_jt", "jt"),
    (0x4000_0003, "size_t", "t"),
    (0x4200_0003, "size_tt", "tt"),
    (0x5000_0003, "size_c", "c"),
    (0x5200_0003, "size_ct", "ct"),
    (0x6000_0003, "size_wi", "wi"),
    (0x6200_0003, "size_wit", "wit"),
    (0x8000_0003, "size_r", "r"),
    (0x8200_0003, "size_rt", "rt"),
];
const FLASH_HARDWARE_MASK: u32 = 0xff00_0003;

/// `flash size_<hw>=<dword> [ignoreversionchecking=<dword>] [stockimage]`:
/// receive a system flash image for this hardware and program it.
fn flash(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let line = invocation.line;
    let selector = invocation.backend.hardware_flags() & FLASH_HARDWARE_MASK;
    let Some(&(_, parameter, suffix)) = FLASH_HARDWARE
        .iter()
        .find(|(value, _, _)| *value == selector)
    else {
        // Stock formats a null suffix, which the CRT prints as `(null)`.
        invocation.set_text(format_args!("unsupported hardware type, requires (null)"));
        return Hresult::FAIL;
    };
    let Some(size) = line.param(parameter).and_then(|value| value.dword()) else {
        invocation.set_text(format_args!("unsupported hardware type, requires {suffix}"));
        return Hresult::FAIL;
    };
    // Stock reads this with the required-parameter getter; its `missing`
    // text is always replaced below.
    let ignore_version_checking = line
        .param("ignoreversionchecking")
        .is_some_and(|value| value.dword_prefix() != 0);
    let options = FlashOptions {
        ignore_version_checking,
        stock_image: line.has("stockimage"),
    };
    let rounded = size.wrapping_add(FLASH_BLOCK - 1) & !(FLASH_BLOCK - 1);
    if !invocation.backend.flash_begin(rounded) {
        invocation.set_text(format_args!("Not enough memory"));
        return Hresult::error(0);
    }
    invocation.set_text(format_args!("send={suffix}"));
    if let Some(session) = invocation.session.as_deref_mut() {
        session.receive_remaining = Some(size);
        session.continuation =
            crate::continuation::Continuation::System(Continuation::Flash(FlashUpload {
                received: 0,
                options,
            }));
    }
    Hresult::SEND_BINARY
}

fn resume_flash(upload: &mut FlashUpload, cx: &mut ContinuationContext<'_>) -> Hresult {
    if cx.received.is_empty() {
        cx.backend.flash_abort();
        return Hresult::UNEXPECTED;
    }
    cx.backend.flash_write(upload.received, cx.received);
    let count = cx.received.len() as u32;
    upload.received += count;
    let remaining = cx
        .session
        .receive_remaining
        .unwrap_or(0)
        .saturating_sub(count);
    cx.session.receive_remaining = Some(remaining);
    if remaining != 0 {
        return Hresult::OK;
    }
    match cx.backend.flash_commit(upload.received, upload.options) {
        Ok(()) => {
            let _ = cx.line.write_str("Done, new image flashed");
            Hresult::OK
        }
        Err(Win32Error(error)) => {
            let result = Hresult(0x8007_0000 | (error.get() & 0xffff));
            let _ = write!(cx.line, "Flash failed with HRESULT 0x{:x}", result.0);
            result
        }
    }
}
