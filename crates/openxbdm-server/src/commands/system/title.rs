//! Title launch and title paths.

use core::fmt;

use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::BootFlags;
use super::RebootKind;
use super::hard_reboot;
use super::prepare_reboot;
use super::record_hard_reboot;
use super::settings::save_settings;
use crate::backend::Backend as AnyBackend;
use crate::commands;
use crate::commands::console::TraceMask;
use crate::commands::console::c_string;
use crate::commands::console::trace;
use crate::commands::console::trace_text;
use crate::commands::debugger::StopOn;
use crate::commands::filesystem::CreateRequest;
use crate::invocation::Invocation;
use crate::network::Network;
use crate::notify::ExecutionState;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::server::Server;
use crate::state::ServerState;

/// Capacity of a title string: the monitor keeps each in a 0x100-byte
/// buffer with a forced terminator.
pub const TITLE_TEXT_CAPACITY: usize = 0xff;

/// Object path buffer of the title commands.
const TITLE_PATH_CAPACITY: usize = 0x100;

/// Buffer of a string parameter of the title commands.
const TITLE_PARAMETER_BUFFER: usize = 0x100;

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

    /// Replace the text with `bytes` up to the first NUL, truncated to the
    /// capacity.
    pub fn set(&mut self, bytes: &[u8]) {
        let end = c_string(bytes).len().min(TITLE_TEXT_CAPACITY);
        self.bytes[..end].copy_from_slice(&bytes[..end]);
        // Bytes past the length are zero, as equality compares them.
        self.bytes[end..].fill(0);
        self.len = end as u8;
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

impl LaunchTitle {
    pub const EMPTY: Self = Self {
        image: TitleText::EMPTY,
        drive: TitleText::EMPTY,
        command_line: TitleText::EMPTY,
    };

    /// Replace the strings; an absent drive or command line is empty.
    fn set(&mut self, image: &[u8], drive: Option<&[u8]>, command_line: Option<&[u8]>) {
        self.image.set(image);
        self.drive.set(drive.unwrap_or_default());
        self.command_line.set(command_line.unwrap_or_default());
    }
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

xbox360_sys::flags! {
    /// Flags of export 81.
    pub struct TitleFlags(u32) {
        /// The title also becomes the persistent title.
        PERSIST = 0x1,
        /// Clear the persistent title first.
        CLEAR_PERSISTENT = 0x2,
    }
}

/// Title strings of a launch request.
#[derive(Debug, Clone, Copy)]
pub struct LaunchRequest<'a> {
    pub image: &'a [u8],
    pub drive: Option<&'a [u8]>,
    pub command_line: Option<&'a [u8]>,
}

/// An object path of at most [`TITLE_PATH_CAPACITY`] bytes.
#[derive(Clone, Copy)]
pub(super) struct TitlePath {
    bytes: [u8; TITLE_PATH_CAPACITY],
    len: usize,
}

impl TitlePath {
    pub(super) const EMPTY: Self = Self {
        bytes: [0; TITLE_PATH_CAPACITY],
        len: 0,
    };

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Append, dropping what does not fit.
    fn push(&mut self, bytes: &[u8]) {
        let count = bytes.len().min(TITLE_PATH_CAPACITY - self.len);
        self.bytes[self.len..self.len + count].copy_from_slice(&bytes[..count]);
        self.len += count;
    }
}

/// When stock FTitleExists 0x91f447c8 runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TitleCheck {
    /// Before a launch: disc images count as present.
    PreBoot,
    /// At the launch: every image must open.
    PostBoot,
}

/// Image and drive object paths of a title.
struct TitlePaths {
    image: TitlePath,
    drive: TitlePath,
}

impl TitlePaths {
    const EMPTY: Self = Self {
        image: TitlePath::EMPTY,
        drive: TitlePath::EMPTY,
    };
}

/// How a launch continues after [`begin_launch`].
enum LaunchOutcome {
    Done(CommandResult),
    /// Restart the console with these flags.
    HardReboot(BootFlags),
}

/// Control code 0x21 (stock DmpTitleReboot 0x91f523a0) on entry with
/// launch information: the reason and the launch flags.
pub fn trace_title_reboot(state: &ServerState, backend: &mut dyn AnyBackend, reason: LaunchReason) {
    let text = format_args!(
        "[xbdm] DmpTitleReboot: Reason={}, g_XamGlobals.Flags=0x{:08x}\n",
        reason.0 as i32,
        state.system.boot_flags.bits()
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
            let stop = flags.intersects(BootFlags::WAIT | BootFlags::STOP);
            flags.remove(BootFlags::STOP);
            stop
        }
        _ => state.debugger.stop_on.contains(StopOn::TITLE_REBOOT),
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
    let kind: &[u8] = if consumed { b"" } else { b"[default] " };
    trace_pieces(
        state,
        backend,
        TraceMask::TITLE_LAUNCH,
        &[
            b"[xbdm] DmpTitleReboot: updating ",
            kind,
            b"launch info\n  ImageName='",
            title.image.as_bytes(),
            b"'\n   DDrive='",
            title.drive.as_bytes(),
            b"'\n   CommandLine='",
            title.command_line.as_bytes(),
            b"'\n",
        ],
    );

    if consumed {
        state.system.title = LaunchTitle::default();
        save_settings(state, backend);
    }

    Some(title)
}

/// DbgPrint the concatenated `pieces` when `bits` are set in the trace
/// mask.
#[inline(never)]
fn trace_pieces(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    bits: TraceMask,
    pieces: &[&[u8]],
) {
    trace_text(state.console.trace_mask, backend, bits, |message| {
        for piece in pieces {
            let _ = message.push_bytes(piece);
        }
    });
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

/// A string parameter copied into a buffer the size stock uses.
pub(super) fn string_param<'b>(
    line: CommandLine<'_>,
    name: &str,
    buffer: &'b mut [u8],
) -> Option<&'b [u8]> {
    Some(line.param(name)?.copy_into(buffer))
}

/// Translate a drive path into `translated`, limited as stock's 0x100-byte
/// destination buffers limit it.
pub(super) fn translate_title_path<'p>(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    path: &[u8],
    translated: &'p mut TitlePath,
) -> Option<&'p TitlePath> {
    let object = state.filesystem.drives.translate(backend, path)?;
    translated.len = 0;
    translated.push(object.as_bytes());

    Some(translated)
}

fn title_exists(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    image: &[u8],
    check: TitleCheck,
) -> bool {
    /// Images under this prefix are launched without an existence check.
    const DISC_IMAGE_PREFIX: &[u8] = b"\\device\\cdrom0";

    let post_boot: &[u8] = if check == TitleCheck::PostBoot {
        b"TRUE"
    } else {
        b"FALSE"
    };

    trace_pieces(
        state,
        backend,
        TraceMask::PATHS,
        &[
            b"[xbdm] FTitleExists(oszImage='",
            image,
            b"',fPostBoot=",
            post_boot,
            b")\n",
        ],
    );

    if check == TitleCheck::PreBoot
        && image.len() >= DISC_IMAGE_PREFIX.len()
        && image[..DISC_IMAGE_PREFIX.len()].eq_ignore_ascii_case(DISC_IMAGE_PREFIX)
    {
        return true;
    }

    let request = CreateRequest::open(
        AccessMask::SYNCHRONIZE,
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
/// `name`; otherwise the image is the translated `name`. Returns whether
/// `paths` were filled.
fn image_and_drive(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    name: &[u8],
    dir: Option<&[u8]>,
    paths: &mut TitlePaths,
) -> bool {
    trace_pieces(
        state,
        backend,
        TraceMask::PATHS,
        &[
            b"[xbdm] FGetImageAndDrive(\n   szTitle='",
            name,
            b"',\n   szDir='",
            dir.unwrap_or(b"(null)"),
            b"',\n   ...)\n",
        ],
    );

    let joined = join_image_and_drive(state, backend, name, dir, paths);
    if joined {
        trace_pieces(
            state,
            backend,
            TraceMask::PATHS,
            &[
                b"[xbdm] FGetImageAndDrive succeeded:\n   oszImage='",
                paths.image.as_bytes(),
                b"'\n   oszDrive='",
                paths.drive.as_bytes(),
                b"'\n",
            ],
        );
    } else {
        trace(
            state,
            backend,
            TraceMask::PATHS,
            format_args!("[xbdm] FGetImageAndDrive failed:\n"),
        );
    }

    joined
}

fn join_image_and_drive(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    name: &[u8],
    dir: Option<&[u8]>,
    paths: &mut TitlePaths,
) -> bool {
    let Some(dir) = dir.filter(|dir| !dir.is_empty()) else {
        paths.drive.len = 0;
        return translate_title_path(state, backend, name, &mut paths.image).is_some();
    };

    if translate_title_path(state, backend, dir, &mut paths.drive).is_none() {
        return false;
    }

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
    if paths.drive.len == TITLE_PATH_CAPACITY {
        overflow(state, backend, "copying path");
        return false;
    }

    paths.image = paths.drive;
    let image = &mut paths.image;
    if image.as_bytes().last() != Some(&b'\\') {
        if image.len + 1 == TITLE_PATH_CAPACITY {
            overflow(state, backend, "appending '\\'");
            return false;
        }

        image.push(b"\\");
    }

    // A name that leaves no room for the terminator is cut and still
    // succeeds.
    if image.len + name.len() >= TITLE_PATH_CAPACITY {
        overflow(state, backend, "appending title");
    }

    image.push(name);

    true
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
) -> CommandResult {
    if !title_exists(state, backend, image, TitleCheck::PreBoot) {
        return Err(ErrorCode::FileNotFound.into());
    }

    let system = &mut state.system;
    system.title.set(image, drive, command_line);
    if persist {
        system.persistent_title = system.title;
    }

    save_settings(state, backend);

    Ok(Reply::Ok)
}

/// Export 81 (stock 0x91f47140), and export 42 with no flags: set the
/// launch title from the drive paths `dir` and `name`. With
/// [`TitleFlags::CLEAR_PERSISTENT`] and no `name`, only the persistent
/// title is cleared. The exports return the result as an HRESULT.
pub fn set_title_from_paths(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    dir: Option<&[u8]>,
    name: Option<&[u8]>,
    command_line: Option<&[u8]>,
    flags: TitleFlags,
) -> CommandResult {
    if flags.contains(TitleFlags::CLEAR_PERSISTENT) {
        state.system.persistent_title = LaunchTitle::default();
        if name.is_none() {
            save_settings(state, backend);
            return Ok(Reply::Ok);
        }
    }

    let Some(name) = name else {
        return Err(CommandError::InvalidArgument);
    };

    let mut paths = TitlePaths::EMPTY;
    if !image_and_drive(state, backend, name, dir, &mut paths) {
        return Err(ErrorCode::FileNotFound.into());
    }

    set_title(
        state,
        backend,
        paths.image.as_bytes(),
        Some(paths.drive.as_bytes()),
        command_line,
        flags.contains(TitleFlags::PERSIST),
    )
}

/// `title nopersist` | `title name=<s> [dir=<s>] [persist] [cmdline=<rest>]`:
/// set the title for the next launch. From the settings file `flags=` is
/// honored and `name`/`dir` are object paths taken as given; from a
/// connection they are drive paths, as for export 81. The settings file
/// is written again after the title is set.
pub(super) fn title(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line;
    let loading = invocation.session.is_none();
    if loading && let Some(flags) = line.dword("flags") {
        invocation.state.system.boot_flags = BootFlags::from_bits_retain(flags);
    }

    if line.has("nopersist") {
        invocation.state.system.persistent_title = LaunchTitle::default();
        // Stock writes the settings file twice here.
        save_settings(invocation.state, invocation.backend);
        save_settings(invocation.state, invocation.backend);
        return Ok(Reply::Ok);
    }

    let mut dir_buffer = [0u8; TITLE_PARAMETER_BUFFER];
    let dir = string_param(line, "dir", &mut dir_buffer);
    let mut name_buffer = [0u8; TITLE_PARAMETER_BUFFER];
    let Some(name) = string_param(line, "name", &mut name_buffer) else {
        invocation.set_text(format_args!("missing name"));
        return Err(CommandError::Fail);
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

/// Stock 0x91f278a8 up to the hardware reboot: record the launch, then
/// relaunch the title in place when the flags and console allow it.
fn begin_launch(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    flags: BootFlags,
    request: Option<LaunchRequest<'_>>,
) -> LaunchOutcome {
    /// Launch flags that rule out a relaunch without a hardware reboot. The
    /// meaning of bit 1 is not known.
    const HARD_REBOOT_FLAGS: BootFlags = BootFlags::COLD.union(BootFlags::from_bits_retain(0x2));

    if let Some(request) = &request
        && !title_exists(state, backend, request.image, TitleCheck::PreBoot)
    {
        return LaunchOutcome::Done(Err(ErrorCode::FileNotFound.into()));
    }

    let execution = backend.execution_state();

    let system = &mut state.system;
    system.boot_flags = flags;
    if let Some(request) = request {
        system
            .title
            .set(request.image, request.drive, request.command_line);
    }

    let mut effective = flags;
    if !state.system.internal_drive_map
        && commands::console::trinity_or_later(backend.hardware_flags())
        && !backend.is_test_kit()
        && !commands::console::settings_block_readable(backend)
    {
        effective.insert(BootFlags::COLD);
    }

    if !effective.intersects(HARD_REBOOT_FLAGS) {
        if execution == ExecutionState::RebootTitle {
            return LaunchOutcome::Done(Ok(Reply::Ok));
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
            return LaunchOutcome::Done(Ok(Reply::Ok));
        }
    }

    LaunchOutcome::HardReboot(effective)
}

/// Stock 0x91f278a8 for a command: the hardware reboot replies first.
pub(super) fn launch(
    invocation: &mut Invocation<'_>,
    flags: BootFlags,
    request: Option<LaunchRequest<'_>>,
) -> CommandResult {
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
            Ok(Reply::Sent)
        }
    }
}

/// Exports 28 and 125 (stock 0x91f278a8 with no connection): launch a
/// title, relaunching in place when possible; otherwise prepare the
/// restart as control code 0x02 does and restart, which on a console
/// does not return. The exports return the result as an HRESULT.
pub fn launch_without_connection(
    server: &mut Server,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    flags: BootFlags,
    request: Option<LaunchRequest<'_>>,
) -> CommandResult {
    match begin_launch(&mut server.state, backend, network, flags, request) {
        LaunchOutcome::Done(result) => result,
        LaunchOutcome::HardReboot(effective) => {
            record_hard_reboot(&mut server.state.system, effective);
            prepare_reboot(server, backend, network);
            backend.reboot(RebootKind::Normal);
            Ok(Reply::Sent)
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
) -> CommandResult {
    let Some(image) = image else {
        if drive.is_some() || command_line.is_some() {
            return Err(CommandError::InvalidArgument);
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

    let mut paths = TitlePaths::EMPTY;
    let Some(image) = translate_title_path(&mut server.state, backend, image, &mut paths.image)
    else {
        return Err(ErrorCode::FileNotFound.into());
    };

    let drive = translate_optional_path(
        &mut server.state,
        backend,
        drive,
        &mut paths.drive,
        ErrorCode::PathNotFound,
    )?;

    let request = LaunchRequest {
        image: image.as_bytes(),
        drive,
        command_line,
    };

    launch_without_connection(server, backend, network, flags, Some(request))
}

/// Translate `path` when present; the error reply when it does not
/// translate.
fn translate_optional_path<'p>(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    path: Option<&[u8]>,
    translated: &'p mut TitlePath,
    error: ErrorCode,
) -> Result<Option<&'p [u8]>, CommandError> {
    let Some(path) = path else {
        return Ok(None);
    };

    match translate_title_path(state, backend, path, translated) {
        Some(translated) => Ok(Some(translated.as_bytes())),
        None => Err(error.into()),
    }
}

/// `magicboot [warm] [cold] [wait] [stop] [title=<s>] [directory=<s>]
/// [cmdline=<s>]`: launch a title, relaunching in place when possible.
pub(super) fn magic_boot(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line;

    let mut flags = BootFlags::empty();

    for (name, bit) in [
        ("warm", BootFlags::COLD),
        ("cold", BootFlags::COLD),
        ("wait", BootFlags::WAIT),
        ("stop", BootFlags::STOP),
    ] {
        if line.has(name) {
            flags.insert(bit);
        }
    }

    let mut paths = TitlePaths::EMPTY;
    let mut buffer = [0u8; TITLE_PARAMETER_BUFFER];
    let image = translate_optional_path(
        invocation.state,
        invocation.backend,
        string_param(line, "title", &mut buffer),
        &mut paths.image,
        ErrorCode::FileNotFound,
    )?;
    let drive = translate_optional_path(
        invocation.state,
        invocation.backend,
        string_param(line, "directory", &mut buffer),
        &mut paths.drive,
        ErrorCode::PathNotFound,
    )?;

    let mut command_line_buffer = [0u8; TITLE_PARAMETER_BUFFER];
    let command_line = string_param(line, "cmdline", &mut command_line_buffer);
    let request = image.map(|image| LaunchRequest {
        image,
        drive,
        command_line,
    });

    launch(invocation, flags, request)
}
