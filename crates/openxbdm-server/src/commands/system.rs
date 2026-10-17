//! System control commands: time, reboot, titles, flash, and the settings
//! file.

mod default_title;
mod error;
mod flash;
mod settings;
mod title;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use xbox360_sys::xboxkrnl::HardwareFlags;

use self::default_title::default_title;
use self::flash::flash;
use self::flash::resume_flash;
use self::settings::reboot_from_settings;
use self::title::launch;
use self::title::magic_boot;
use self::title::title;
use crate::access::Access;
use crate::backend::Backend as AnyBackend;
use crate::commands::console::ConfigFlags;
use crate::commands::console::ConfigSetting;
use crate::commands::console::RetailFlags;
use crate::commands::console::c_string;
use crate::commands::util;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::invocation::SessionRequest;
use crate::network::Network;
use crate::notify::Event;
use crate::notify::ExecutionState;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::server::Server;

pub use self::error::CreateSettingsError;
pub use self::error::FlashFailed;
pub use self::flash::FlashOptions;
pub use self::flash::FlashUpload;
pub use self::settings::SettingsCopy;
pub use self::settings::SettingsFile;
pub use self::settings::SettingsSource;
pub use self::settings::copy_settings;
pub(crate) use self::settings::end_line;
pub use self::settings::load_settings;
pub(crate) use self::settings::save_settings;
pub(crate) use self::settings::settings_keyword;
pub use self::settings::wipe_settings;
pub(crate) use self::settings::write_bytes;
pub(crate) use self::settings::write_line;
pub(crate) use self::settings::write_text;
pub use self::title::LaunchReason;
pub use self::title::LaunchRequest;
pub use self::title::LaunchTitle;
pub use self::title::TITLE_TEXT_CAPACITY;
pub use self::title::TitleFlags;
pub use self::title::TitleRebootStop;
pub use self::title::TitleText;
pub use self::title::launch_from_paths;
pub use self::title::launch_image_exists;
pub use self::title::launch_override;
pub use self::title::launch_without_connection;
pub use self::title::set_title_from_paths;
pub use self::title::title_reboot_launch;
pub use self::title::title_reboot_stop;
pub use self::title::trace_title_reboot;

/// Delay between the `200- OK` of a reboot and the reboot.
const REBOOT_REPLY_DELAY_MS: u32 = 200;

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry(
        "deftitle",
        Access::CONTROL,
        DispatchFlags::empty(),
        default_title,
    ),
    entry("flash", Access::CONFIG, DispatchFlags::empty(), flash),
    entry(
        "magicboot",
        Access::CONTROL,
        DispatchFlags::empty(),
        magic_boot,
    ),
    entry("reboot", Access::CONTROL, DispatchFlags::empty(), reboot),
    entry("recovery", Access::CONFIG, DispatchFlags::empty(), recovery),
    entry(
        "setdiscboot",
        Access::CONTROL,
        DispatchFlags::DEVKIT_ONLY,
        set_disc_boot,
    ),
    entry(
        "setreset",
        Access::empty(),
        DispatchFlags::empty(),
        set_reset,
    ),
    entry(
        "setsystime",
        Access::CONFIG,
        DispatchFlags::empty(),
        set_system_time,
    ),
    entry(
        "systime",
        Access::empty(),
        DispatchFlags::empty(),
        system_time,
    ),
    entry("title", Access::CONTROL, DispatchFlags::empty(), title),
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

/// Global state of this domain.
#[derive(Debug)]
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

impl State {
    pub const fn new() -> Self {
        Self {
            boot_wait: None,
            settings_loaded: false,
            clock_set: false,
            recovery_requested: false,
            recovery_boot: false,
            title: LaunchTitle::EMPTY,
            persistent_title: LaunchTitle::EMPTY,
            boot_flags: BootFlags::empty(),
            internal_drive_map: false,
            hard_reboot_pending: false,
        }
    }
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    /// Receiving a `flash` image.
    Flash(FlashUpload),
}

xbox360_sys::flags! {
    /// Flags of a title launch (stock 0x91fa2324).
    pub struct BootFlags(u32) {
        WAIT = 0x1,
        COLD = 0x4,
        STOP = 0x8,
        /// Export 125: the paths are object paths and are not translated.
        OBJECT_PATHS = 0x10,
    }
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
    fn settings_file_size(&mut self, file: SettingsFile) -> Result<u32, KernelError>;
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
    fn hardware_flags(&mut self) -> HardwareFlags;
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

const fn entry(
    name: &'static str,
    any_of: Access,
    flags: DispatchFlags,
    handler: fn(&mut Invocation<'_>) -> CommandResult,
) -> CommandEntry {
    CommandEntry::new(name, any_of, Access::empty(), flags, handler)
}

pub(crate) fn resume(
    continuation: &mut Continuation,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    match continuation {
        Continuation::Flash(upload) => resume_flash(upload, cx),
    }
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

/// `reboot [stop] [wait] [smcreset]`: reply, then restart. The server
/// writes the settings file, sends `execution rebooting`, and closes every
/// connection and notification channel before the restart.
fn reboot(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(session) = invocation.session.as_deref_mut() else {
        return Ok(Reply::Sent);
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
        system.boot_wait = if invocation.line.has("stop") {
            Some(BootWait::Stop)
        } else if invocation.line.has("wait") {
            Some(BootWait::Wait)
        } else {
            None
        };
    }

    invocation.state.settings_dirty = true;

    Ok(Reply::Sent)
}

/// `recovery`: request a recovery boot and restart. From the settings file
/// the line only records the request.
fn recovery(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        invocation.state.system.recovery_boot = true;
        return Err(CommandError::Fail);
    }

    invocation.state.system.recovery_requested = true;

    launch(invocation, BootFlags::COLD, None)
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
        system.boot_wait = if flags.contains(BootFlags::STOP) {
            Some(BootWait::Stop)
        } else if flags.contains(BootFlags::WAIT) {
            Some(BootWait::Wait)
        } else {
            None
        };
    }
}

/// `systime`: the system clock as FILETIME halves, once `setsystime` has
/// run.
fn system_time(invocation: &mut Invocation<'_>) -> CommandResult {
    if !invocation.state.system.clock_set {
        return Err(ErrorCode::ClockNotSet.into());
    }

    let time = invocation.backend.system_time();
    invocation.set_text(format_args!(
        "high=0x{:x} low=0x{:x}",
        (time >> 32) as u32,
        time as u32
    ));

    Ok(Reply::Ok)
}

/// `setsystime clockhi=<dword> clocklo=<dword> [tz=<dword>]`: set the
/// clock; with `tz`, fill in a default time zone when none is configured.
fn set_system_time(invocation: &mut Invocation<'_>) -> CommandResult {
    let dword = |name: &str| invocation.line.dword(name);
    let (Some(high), Some(low)) = (dword("clockhi"), dword("clocklo")) else {
        return Err(ErrorCode::ClockNotSet.into());
    };

    let has_zone = dword("tz").is_some();
    let backend = &mut *invocation.backend;
    backend.set_system_time(u64::from(high) << 32 | u64::from(low));
    invocation.state.system.clock_set = true;
    if !has_zone {
        return Ok(Reply::Ok);
    }

    let mut standard_name = [0u8; 4];
    if backend
        .xconfig_get(ConfigSetting::new(3, 2), &mut standard_name)
        .is_err()
    {
        return Ok(Reply::Ok);
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
                return Err(ErrorCode::ClockNotSet.into());
            }
        }
    }

    // A failed read leaves the value zero, as in stock.
    let mut enabled = [0u8; 4];
    let _ = backend.xconfig_get(ConfigSetting::new(3, 9), &mut enabled);
    if enabled != [0; 4] {
        return Ok(Reply::Ok);
    }

    match backend.xconfig_set(ConfigSetting::new(3, 9), &1u32.to_be_bytes()) {
        Ok(()) => Ok(Reply::Ok),
        Err(_) => Err(ErrorCode::ClockNotSet.into()),
    }
}

/// `setdiscboot enable=<0|1>`: select the boot device bits of
/// configuration setting (3, 0xc) through the kernel modify export.
fn set_disc_boot(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(enable) = util::required_dword(invocation, "enable") else {
        return Err(util::MISSING);
    };

    let selected = match enable {
        0 => RetailFlags::DISC_BOOT_DISABLED,
        1 => RetailFlags::DISC_BOOT_ENABLED,
        _ => return Err(CommandError::Fail),
    };

    let (selected, field) = (selected.bits(), RetailFlags::BOOT_DEVICE.bits());
    match invocation
        .backend
        .xconfig_modify(RetailFlags::SETTING, !selected & !field, selected)
    {
        Ok(()) => Ok(Reply::Ok),
        Err(error) => {
            let status = error.status().0;
            invocation.set_text(format_args!("Modify failed: 0x{status:08x}"));
            Err(CommandError::Fail)
        }
    }
}

/// `setreset [chord=<string>]`: store the reset button chord (up to four
/// characters), or report the stored one.
fn set_reset(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Size of the reset chord configuration setting (2, 5).
    const RESET_CHORD_SIZE: usize = 5;

    let setting = ConfigSetting::RESET_CHORD;
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
        Ok(None) => Ok(Reply::Ok),
        Ok(Some(length)) => {
            let stored = &chord[..length.min(RESET_CHORD_SIZE)];
            invocation.text.set_bytes(c_string(stored));
            Ok(Reply::Ok)
        }
        Err(_) => {
            invocation.set_text(format_args!("Could not change reset key"));
            Err(CommandError::Fail)
        }
    }
}
