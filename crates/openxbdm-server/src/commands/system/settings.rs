//! Settings file: writing, wiping, copying, and loading at startup.

use core::fmt;
use core::fmt::Write as _;

use super::BootWait;
use super::RebootKind;
use super::error::CreateSettingsError;
use super::title::TitleText;
use crate::backend::Backend as AnyBackend;
use crate::commands;
use crate::commands::console::TraceMask;
use crate::commands::console::trace;
use crate::commands::console::trace_text;
use crate::invocation::Invocation;
use crate::network::Network;
use crate::notify::Event;
use crate::notify::ExecutionState;
use crate::server::Server;
use crate::state::ServerState;

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

/// Text of a settings file write.
enum Echo<'a> {
    Bytes(&'a [u8]),
    Format(fmt::Arguments<'a>),
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

/// What [`write_settings_file`] leaves in the file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsContent {
    Text,
    Empty,
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
    echo(backend, Echo::Format(arguments));
    let _ = SettingsWriter { backend, file }.write_fmt(arguments);
}

/// Append raw bytes to a settings file as one text (stock
/// WriteIniSzNoCRLF 0x91f319c8).
pub(crate) fn write_bytes(backend: &mut dyn AnyBackend, file: SettingsFile, bytes: &[u8]) {
    echo(backend, Echo::Bytes(bytes));
    backend.write_settings(file, bytes);
}

/// [`write_bytes`] followed by the line terminator.
fn write_bytes_line(backend: &mut dyn AnyBackend, file: SettingsFile, bytes: &[u8]) {
    write_bytes(backend, file, bytes);
    end_line(backend, file);
}

/// Append the line terminator to a settings file. It is not echoed.
pub(crate) fn end_line(backend: &mut dyn AnyBackend, file: SettingsFile) {
    backend.write_settings(file, b"\r\n");
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
    echo(backend, Echo::Bytes(b"(null)"));
}

/// Trace bit 4 echo of each text written to a settings file.
fn echo(backend: &mut dyn AnyBackend, text: Echo<'_>) {
    let mask = commands::console::Backend::trace_mask(backend);
    trace_text(mask, backend, TraceMask::SETTINGS, |message| {
        let _ = message.write_str("XBDM: WriteIniSzNoCRLF: '");
        let _ = match text {
            Echo::Bytes(bytes) => message.push_bytes(bytes),
            Echo::Format(arguments) => message.write_fmt(arguments),
        };

        let _ = message.write_str("'\n");
    });
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
        Err(CreateSettingsError::Create(error)) => {
            let status = error.status().0;
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
    write_bytes_line(backend, file, b"[xbdm]");
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
        write_bytes_line(backend, file, b"recovery");
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
    write_bytes_line(backend, file, b"recovery");
    let length = backend.end_settings_copy(file);
    trace(
        state,
        backend,
        TraceMask::SETTINGS,
        format_args!("XBDM: {name} - end\n"),
    );

    Some(length)
}

fn boot_wait_settings_lines(state: &ServerState, backend: &mut dyn AnyBackend, file: SettingsFile) {
    let line: &[u8] = match state.system.boot_wait {
        None => return,
        Some(BootWait::Wait) => b"wait",
        Some(BootWait::Stop) => b"wait stop",
        Some(BootWait::Forever) => b"wait forever",
    };

    write_bytes_line(backend, file, line);
}

/// `label` and `value` when `value` is not empty.
fn write_title_field(
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
    label: &[u8],
    value: &TitleText,
) {
    if !value.is_empty() {
        write_bytes(backend, file, label);
        write_bytes(backend, file, value.as_bytes());
    }
}

/// Title lines (stock 0x91f51ed0). The command line of the persistent
/// title is quoted but reloads with its quotes, since `cmdline` takes the
/// rest of the line.
fn title_settings_lines(state: &ServerState, backend: &mut dyn AnyBackend, file: SettingsFile) {
    let persistent = &state.system.persistent_title;
    if !persistent.image.is_empty() {
        write_bytes(backend, file, b"title persist name=\"");
        write_bytes(backend, file, persistent.image.as_bytes());
        write_title_field(backend, file, b"\" dir=\"", &persistent.drive);
        write_title_field(backend, file, b"\" cmdline=\"", &persistent.command_line);
        write_bytes_line(backend, file, b"\"");
    }

    let current = &state.system.title;

    if !current.image.is_empty() {
        write_bytes(backend, file, b"title");
        if !state.system.boot_flags.is_empty() {
            write_text(
                backend,
                file,
                format_args!(" flags=0x{:08x}", state.system.boot_flags.bits()),
            );
        }

        write_bytes(backend, file, b" name=\"");
        write_bytes(backend, file, current.image.as_bytes());
        write_title_field(backend, file, b"\" dir=\"", &current.drive);
        write_bytes(backend, file, b"\"");
        write_title_field(backend, file, b" cmdline=", &current.command_line);
        end_null_line(backend, file);
    }
}

/// Startup: execute the saved settings file and then `recint.ini` (stock
/// LoadIniFile 0x91f316b8), apply the settings that act at boot, and
/// consume a one-time boot-wait mode.
pub fn load_settings(server: &mut Server, backend: &mut dyn AnyBackend, network: &mut dyn Network) {
    commands::console::initialize(&mut server.state, backend);
    load_settings_files(server, backend, network);
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

/// Stock LoadIniFile allocates its 0x4000-byte read buffer from pool
/// memory first and does nothing at all when that fails: no file is read,
/// nothing is traced, and the settings stay marked as not loaded.
fn load_settings_files(
    server: &mut Server,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) {
    /// Read buffer of the settings loader; a line that fills it is cut.
    const SETTINGS_READ_CAPACITY: usize = 0x4000;

    let Some(mut buffer) = backend.allocate_scratch(SETTINGS_READ_CAPACITY as u32) else {
        return;
    };

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

    backend.free_scratch(buffer);
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
        Err(error) => {
            let status = error.status().0;
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
    buffer: &mut [u8],
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
        if let Some(internal) = invocation.line.dword("internal") {
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
pub(super) fn reboot_from_settings(invocation: &mut Invocation<'_>, kind: RebootKind) {
    save_settings(invocation.state, invocation.backend);
    invocation.state.notifications.deliver(
        &Event::Execution(ExecutionState::Rebooting),
        invocation.network,
    );
    invocation.state.notifications.close_all(invocation.network);
    invocation.backend.reboot(kind);
}
