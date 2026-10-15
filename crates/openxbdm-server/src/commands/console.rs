//! Console identity and configuration commands.

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;

use crate::access::Access;
use crate::backend::Backend as AnyBackend;
use crate::commands::system::RebootKind;
use crate::commands::system::SettingsFile;
use crate::commands::system::end_line;
use crate::commands::system::write_bytes;
use crate::commands::system::write_line;
use crate::commands::system::write_text;
use crate::commands::util;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::state::ServerState;
use crate::text::LineText;

/// Monitor version reported by `dmversion`.
pub const MONITOR_VERSION: &str = "2.0.21256.0";
/// Bytes of a stored debug name, including the terminator.
pub const DEBUG_NAME_CAPACITY: usize = 0x15;
/// Bytes of the SMC I2C settings block that holds the debug name.
pub const SETTINGS_BLOCK_SIZE: usize = 0x20;
/// Bytes of a network address record (`XNADDR`).
pub const NETWORK_ADDRESS_SIZE: usize = 0x24;
/// Characters of a console identifier string.
pub const CONSOLE_ID_LENGTH: usize = 12;

/// Status the kernel returns when an export is absent.
pub const STATUS_PROCEDURE_NOT_FOUND: NtStatus = NtStatus(0xc000_0138);

/// `442-` with empty text.
const NOT_AVAILABLE: Hresult = Hresult::error(0x2a);
const BAD_PARAMETER: Hresult = Hresult::from_error_code(ErrorCode::BAD_PARAMETER);
const ACCESS_DENIED: Hresult = Hresult::from_error_code(ErrorCode::ACCESS_DENIED);
const UNKNOWN_COMMAND: Hresult = Hresult::from_error_code(ErrorCode::UNKNOWN_COMMAND);
const FILENAME_INVALID: Hresult = Hresult::from_error_code(ErrorCode::FILENAME_INVALID);

/// Configuration settings written by this domain.
const SETTING_AUTO_SHUTOFF: ConfigSetting = ConfigSetting::new(7, 2);
const SETTING_DISCOVERABLE: ConfigSetting = ConfigSetting::new(7, 0xf);
const SETTING_KIOSK_ID: ConfigSetting = ConfigSetting::new(0xb, 3);
const SETTING_RETAIL_FLAGS: ConfigSetting = ConfigSetting::new(3, 0xc);
const SETTING_NETWORK_SHARE: ConfigSetting = ConfigSetting::new(3, 0x10);
/// Index of the category-3 user flags dword.
const USER_FLAGS_INDEX: u16 = 0xd;
/// Index of the category-3 retail flags dword.
const RETAIL_FLAGS_INDEX: u16 = 0xc;

const USER_FLAG_LIVE_SIGNIN_REQUIRED: u32 = 0x08;
const USER_FLAG_KIOSK: u32 = 0x40;
const USER_FLAG_DATA_CENTER: u32 = 0x400;
const RETAIL_FLAG_WELCOME_HIDE: u32 = 0x0400_0000;
const RETAIL_FLAG_WELCOME_DEFAULT: u32 = 0x0800_0000;

/// Value buffer of the on/off string parameters.
const SWITCH_BUFFER: usize = 10;
/// Value buffer of the `kiosk enabled=` parameter.
const KIOSK_SWITCH_BUFFER: usize = 0x20;
/// Value buffer of the `dumpsettings` selectors.
const DUMP_SELECTOR_BUFFER: usize = 0x3f;
/// Characters kept of a crash dump path.
const DUMP_PATH_CAPACITY: usize = 0x102;
/// Characters kept of the server and object of `httpreg`.
const REGISTRATION_TEXT_CAPACITY: usize = 0xff;
/// Bytes kept of a registration response body.
pub const REGISTRATION_RESPONSE_CAPACITY: usize = 0x400;
/// Bytes of the registration request path and query.
const REGISTRATION_PATH_CAPACITY: usize = 0x3ff;
/// User agent of the registration request.
pub const REGISTRATION_USER_AGENT: &str = "Xbox Debugger/2.0.21256.0";
/// Address check period of the registration task.
const REGISTRATION_PERIOD_MS: u32 = 30_000;
/// Task period while no registration is configured.
const REGISTRATION_IDLE_MS: u32 = 3_600_000;
/// Task period while a request or the network address is pending.
const REGISTRATION_RETRY_MS: u32 = 1;
/// System software version from which the title need not be running.
const REGISTRATION_ANY_STATE_VERSION: u32 = 0x2016_5400;
/// Bytes of the network share setting.
const NETWORK_SHARE_SIZE: usize = 0x100;
/// Longest network share server name the drive refresh accepts.
const NETWORK_SHARE_NAME_LIMIT: usize = 0x3d;
/// XDK version reported by `systeminfo`.
pub const XDK_VERSION: Version = Version([2, 0, 21256, 0]);

const VE_FAILURE: &str =
    "confignetra: failed to getting VE device config! Are you not running in DC mode?";
const VE_HEADER: &str = "[Current VE configurations]";
const VE_USAGE: &str =
    "Usage: xbsetcfg /confignetra {relaxheartbeat=[on|off]} {customubootaddr=<address>}";

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
        "altaddr",
        Access::CONTROL,
        DispatchFlags::NONE,
        alternate_address,
    ),
    entry(
        "autoshutoff",
        Access::CONTROL,
        DispatchFlags::DEVKIT_ONLY,
        auto_shutoff,
    ),
    entry(
        "confignetra",
        Access::CONTROL,
        DispatchFlags::DEVKIT_ONLY,
        configure_network_ra,
    ),
    entry(
        "consolefeatures",
        Access::CONTROL,
        DispatchFlags::NONE,
        console_features,
    ),
    entry(
        "consolemem",
        Access::CONTROL,
        DispatchFlags::NONE,
        console_memory_command,
    ),
    entry(
        "consoletype",
        Access::CONTROL,
        DispatchFlags::NONE,
        console_type,
    ),
    entry(
        "datacentermode",
        Access::CONTROL,
        DispatchFlags::NONE,
        data_center_mode,
    ),
    entry("dbgname", Access::NONE, DispatchFlags::NONE, debug_name),
    entry(
        "debugmemsize",
        Access::CONTROL,
        DispatchFlags::NONE,
        debug_memory_size,
    ),
    entry("debugmode", Access::NONE, DispatchFlags::NONE, debug_mode),
    entry(
        "discoverable",
        Access::CONTROL,
        DispatchFlags::NONE,
        discoverable,
    ),
    entry(
        "dmversion",
        Access::CONTROL,
        DispatchFlags::NONE,
        monitor_version,
    ),
    entry("dumpmode", Access::CONFIG, DispatchFlags::NONE, dump_mode),
    entry(
        "dumpsettings",
        Access::CONFIG,
        DispatchFlags::NONE,
        dump_settings,
    ),
    entry(
        "eventdefer",
        Access::CONFIG,
        DispatchFlags::NONE,
        event_defer,
    ),
    entry("feature", Access::CONTROL, DispatchFlags::NONE, feature),
    entry(
        "getconsoleid",
        Access::CONTROL,
        DispatchFlags::NONE,
        console_id,
    ),
    entry(
        "getnetaddrs",
        Access::READ,
        DispatchFlags::NONE,
        network_addresses,
    ),
    entry(
        "httpreg",
        Access::MANAGE,
        DispatchFlags::NONE,
        http_registration,
    ),
    entry("kiosk", Access::CONTROL, DispatchFlags::DEVKIT_ONLY, kiosk),
    entry(
        "livesigninrequired",
        Access::CONTROL,
        DispatchFlags::NONE,
        live_signin_required,
    ),
    entry(
        "resetnetra",
        Access::CONTROL,
        DispatchFlags::DEVKIT_ONLY,
        reset_network_ra,
    ),
    entry("setconfig", Access::CONFIG, DispatchFlags::NONE, set_config),
    entry(
        "setretail",
        Access::WRITE,
        DispatchFlags::DEVKIT_ONLY,
        set_retail,
    ),
    entry("setserver", Access::MANAGE, DispatchFlags::NONE, set_server),
    entry("systeminfo", Access::READ, DispatchFlags::NONE, system_info),
    entry("verbose", Access::CONFIG, DispatchFlags::NONE, verbose),
    entry(
        "welcomedefault",
        Access::CONTROL,
        DispatchFlags::NONE,
        welcome_default,
    ),
    entry(
        "welcomehide",
        Access::CONTROL,
        DispatchFlags::NONE,
        welcome_hide,
    ),
];

/// Console debug name: at most 20 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugName {
    bytes: [u8; DEBUG_NAME_CAPACITY - 1],
    len: u8,
}

impl DebugName {
    pub const EMPTY: Self = Self {
        bytes: [0; DEBUG_NAME_CAPACITY - 1],
        len: 0,
    };

    /// The name, truncated to 20 bytes.
    pub fn new(name: &[u8]) -> Self {
        let mut stored = Self::EMPTY;
        let length = name.len().min(stored.bytes.len());
        stored.bytes[..length].copy_from_slice(&name[..length]);
        stored.len = length as u8;
        stored
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// The name does not fit the caller's buffer (stock export 17).
pub const BUFFER_TOO_SMALL: Hresult = Hresult::error(0x105);

/// Stock export 17 (control code 0x33): copy the debug name and a
/// terminator into `output`, cut to fit; a cut name fails with
/// [`BUFFER_TOO_SMALL`]. Stock underflows the size of an empty buffer and
/// copies the whole name past it; here nothing is written.
pub fn copy_debug_name(name: &DebugName, output: &mut [u8]) -> Hresult {
    let Some(room) = output.len().checked_sub(1) else {
        return if name.as_bytes().is_empty() {
            Hresult::OK
        } else {
            BUFFER_TOO_SMALL
        };
    };
    let name = name.as_bytes();
    let length = name.len().min(room);
    output[..length].copy_from_slice(&name[..length]);
    output[length] = 0;
    if length == name.len() {
        Hresult::OK
    } else {
        BUFFER_TOO_SMALL
    }
}

/// Diagnostic trace mask set by `verbose` (stock 0x91f9fef4); each bit
/// enables the monitor's DbgPrint texts of one area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TraceMask(pub u32);

impl TraceMask {
    /// Command lines, status lines, title command processor thread.
    pub const REPLIES: Self = Self(0x1);
    /// 204 binary receive.
    pub const BINARY_RECEIVE: Self = Self(0x2);
    /// Settings file reads and writes.
    pub const SETTINGS: Self = Self(0x4);
    /// Drive path and title image resolution.
    pub const PATHS: Self = Self(0x8);
    /// Title launch control codes.
    pub const TITLE_LAUNCH: Self = Self(0x10);
    /// CD-ROM driver setup at startup.
    pub const CDROM: Self = Self(0x20);

    pub fn contains(self, bits: Self) -> bool {
        self.0 & bits.0 != 0
    }
}

/// DbgPrint `arguments` when `bits` are set in the trace mask.
pub(crate) fn trace(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    bits: TraceMask,
    arguments: core::fmt::Arguments<'_>,
) {
    if state.console.trace_mask.contains(bits) {
        print(backend, arguments);
    }
}

/// DbgPrint the text `build` writes when `bits` are set in `mask`. For
/// texts with byte strings, and for callers that hold only a backend
/// (`mask` is then [`Backend::trace_mask`]).
pub(crate) fn trace_text(
    mask: TraceMask,
    backend: &mut dyn AnyBackend,
    bits: TraceMask,
    build: impl FnOnce(&mut MessageText),
) {
    if mask.contains(bits) {
        let mut message = MessageText::new();
        build(&mut message);
        backend.debug_print(message.as_bytes());
    }
}

/// Bytes before the first NUL, as a `%s` argument prints them.
pub(crate) fn c_string(bytes: &[u8]) -> &[u8] {
    bytes.split(|&byte| byte == 0).next().unwrap_or_default()
}

/// Crash dump mode set by `dumpmode` and export 118 (stock 0x91f9f660).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DumpMode {
    #[default]
    Smart,
    Enabled,
    Disabled,
    /// A value only export 118 stores; it acts and reads as `smart` but
    /// export 117 returns it unchanged.
    Other(u32),
}

impl DumpMode {
    const ALL: [Self; 3] = [Self::Smart, Self::Enabled, Self::Disabled];

    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Smart,
            1 => Self::Enabled,
            2 => Self::Disabled,
            other => Self::Other(other),
        }
    }

    pub const fn raw(self) -> u32 {
        match self {
            Self::Smart => 0,
            Self::Enabled => 1,
            Self::Disabled => 2,
            Self::Other(raw) => raw,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Smart | Self::Other(_) => "smart",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

/// Bytes of the crash dump settings block of exports 119 and 120.
pub const DUMP_SETTINGS_SIZE: usize = 0x108;
/// Bytes of the path in that block.
const DUMP_SETTINGS_PATH_SIZE: usize = DUMP_SETTINGS_SIZE - 4;

/// Selector names in stock's table order (0x91f96bd0): reports,
/// destinations, formats, then a NULL entry the kernel formatter prints as
/// `(null)`. The summary indexes past a group as stock does.
const DUMP_NAMES: [&str; 10] = [
    "prompt", "always", "never", "local", "remote", "full", "partial", "noheap", "retail", "(null)",
];

/// A 4-bit field of the crash dump flags.
#[derive(Clone, Copy)]
struct DumpField {
    shift: u32,
    /// Index of the field's first name in [`DUMP_NAMES`].
    first: usize,
    /// Names `dumpsettings` accepts.
    count: usize,
    /// Largest value the summary shows; larger values show as 0.
    shown: u32,
}

const DUMP_REPORT: DumpField = DumpField {
    shift: 0,
    first: 0,
    count: 3,
    shown: 3,
};
const DUMP_DESTINATION: DumpField = DumpField {
    shift: 4,
    first: 3,
    count: 2,
    shown: 2,
};
const DUMP_FORMAT: DumpField = DumpField {
    shift: 8,
    first: 5,
    count: 4,
    shown: 4,
};

/// Crash dump settings set by `dumpsettings` and export 120 (stock
/// 0x91f9f520): flags with the report in bits 0-3, the destination in
/// bits 4-7 and the format in bits 8-11, and the dump directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DumpSettings {
    flags: u32,
    path: [u8; DUMP_SETTINGS_PATH_SIZE],
    path_len: u16,
}

impl DumpSettings {
    pub const fn new() -> Self {
        Self {
            flags: 0,
            path: [0; DUMP_SETTINGS_PATH_SIZE],
            path_len: 0,
        }
    }

    /// The dump directory; empty when unset.
    pub fn path(&self) -> &[u8] {
        &self.path[..usize::from(self.path_len)]
    }

    fn set_path(&mut self, path: &[u8]) {
        let length = path.len().min(DUMP_SETTINGS_PATH_SIZE);
        self.path = [0; DUMP_SETTINGS_PATH_SIZE];
        self.path[..length].copy_from_slice(&path[..length]);
        self.path_len = length as u16;
    }

    fn set(&mut self, field: DumpField, value: u32) {
        self.flags = (self.flags & !(0xf << field.shift)) | value << field.shift;
    }

    fn name(&self, field: DumpField) -> &'static str {
        let value = (self.flags >> field.shift) & 0xf;
        let value = if value > field.shown { 0 } else { value };
        DUMP_NAMES[field.first + value as usize]
    }

    /// The block of export 119: big-endian flags, then the path. A path
    /// that fills its room has no terminator, as in stock.
    pub fn to_block(&self) -> [u8; DUMP_SETTINGS_SIZE] {
        let mut block = [0u8; DUMP_SETTINGS_SIZE];
        block[..4].copy_from_slice(&self.flags.to_be_bytes());
        block[4..].copy_from_slice(&self.path);
        block
    }

    /// The settings of an export 120 block; the path ends at its first NUL.
    pub fn from_block(block: &[u8; DUMP_SETTINGS_SIZE]) -> Self {
        let mut settings = Self {
            flags: u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
            ..Self::new()
        };
        let path = &block[4..];
        settings.set_path(
            &path[..path
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(path.len())],
        );
        settings
    }

    /// `rpt=%s dst=%s fmt=%s[ path=%s]`.
    fn write_summary(&self, output: &mut dyn FnMut(&[u8])) {
        output(b"rpt=");
        output(self.name(DUMP_REPORT).as_bytes());
        output(b" dst=");
        output(self.name(DUMP_DESTINATION).as_bytes());
        output(b" fmt=");
        output(self.name(DUMP_FORMAT).as_bytes());
        if self.path_len != 0 {
            output(b" path=");
            output(self.path());
        }
    }
}

/// Notifications queued to the server thread rather than delivered inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventDeferMask(pub u32);

impl EventDeferMask {
    const NAMES: [&'static str; 7] = [
        "break",
        "debugstring",
        "singlestep",
        "assert",
        "ntassert",
        "databreak",
        "rip",
    ];

    fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .iter()
            .enumerate()
            .filter(move |(bit, _)| self.0 & (1 << bit) != 0)
            .map(|(_, name)| *name)
    }

    /// break, debugstring, singlestep, databreak.
    pub const DEFAULT: Self = Self(0x27);
}

/// State of the HTTP registration with a lab server (stock 0x91f9f638).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegistrationState {
    /// Waiting to register (stock state 0).
    #[default]
    Pending,
    /// A request is in progress (stock states 1 to 7).
    InProgress,
    /// `httpreg clear`, or no object to register (stock state 8).
    Cleared,
    /// The server accepted the registration (stock state 9).
    Registered,
    /// The last `httpreg` was rejected or the request failed (stock
    /// state 10).
    Failed,
    /// The server answered with a status other than 200 (stock state 11).
    Rejected,
    /// The response body exceeded 0x400 bytes (stock state 12).
    ResponseTooLarge,
}

/// Address check of the registration task: the debug address registered
/// and the tick of the last check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationCheck {
    pub address: [u8; NETWORK_ADDRESS_SIZE],
    pub tick: u32,
}

impl RegistrationCheck {
    pub const EMPTY: Self = Self {
        address: [0; NETWORK_ADDRESS_SIZE],
        tick: 0,
    };
}

/// Lab server registration set by `httpreg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpRegistration {
    pub state: RegistrationState,
    server: [u8; REGISTRATION_TEXT_CAPACITY],
    server_len: u8,
    object: [u8; REGISTRATION_TEXT_CAPACITY],
    object_len: u8,
    pub port: u16,
    /// Random identifier sent with the request; 0 when none was sent.
    pub transaction: u64,
    response: [u8; REGISTRATION_RESPONSE_CAPACITY],
    response_len: u16,
}

impl HttpRegistration {
    pub const EMPTY: Self = Self {
        state: RegistrationState::Pending,
        server: [0; REGISTRATION_TEXT_CAPACITY],
        server_len: 0,
        object: [0; REGISTRATION_TEXT_CAPACITY],
        object_len: 0,
        port: 0,
        transaction: 0,
        response: [0; REGISTRATION_RESPONSE_CAPACITY],
        response_len: 0,
    };

    pub fn server(&self) -> &[u8] {
        &self.server[..usize::from(self.server_len)]
    }

    pub fn object(&self) -> &[u8] {
        &self.object[..usize::from(self.object_len)]
    }

    /// Body of the last accepted registration response.
    pub fn response(&self) -> &[u8] {
        &self.response[..usize::from(self.response_len)]
    }

    /// The part export 194 reads.
    pub const fn result(&self) -> RegistrationResult {
        RegistrationResult {
            state: self.state,
            transaction: self.transaction,
            response: self.response,
            response_len: self.response_len,
        }
    }
}

/// State, transaction, and response of a registration, as export 194
/// reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationResult {
    pub state: RegistrationState,
    pub transaction: u64,
    response: [u8; REGISTRATION_RESPONSE_CAPACITY],
    response_len: u16,
}

impl RegistrationResult {
    pub const EMPTY: Self = HttpRegistration::EMPTY.result();

    /// Export 194 (stock 0x91f30b48) after its argument checks: copy the
    /// response of a registered console into `output`, the caller's buffer
    /// (`None` without a size pointer).
    pub fn export_response(&self, output: Option<&mut [u8]>) -> RegistrationResponse {
        let none = |result| RegistrationResponse {
            result,
            transaction: 0,
            length: 0,
        };
        match self.state {
            RegistrationState::Pending | RegistrationState::InProgress => {
                none(Hresult::error(0x150))
            }
            RegistrationState::Cleared => none(Hresult::error(0x2)),
            RegistrationState::Failed => none(Hresult::error(0x100)),
            RegistrationState::Rejected => none(Hresult::error(0x10a)),
            RegistrationState::ResponseTooLarge => none(Hresult::error(0xf)),
            RegistrationState::Registered => {
                let response = &self.response[..usize::from(self.response_len)];
                let result = match output {
                    Some(output) if output.len() >= response.len() => {
                        output[..response.len()].copy_from_slice(response);
                        Hresult::OK
                    }
                    Some(_) => BUFFER_TOO_SMALL,
                    // Without a size pointer nothing is copied, yet stock reports success.
                    None => Hresult::OK,
                };
                RegistrationResponse {
                    result,
                    transaction: self.transaction,
                    length: response.len() as u32,
                }
            }
        }
    }
}

/// What export 194 stores and returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationResponse {
    pub result: Hresult,
    pub transaction: u64,
    pub length: u32,
}

/// Global state of this domain.
#[derive(Debug)]
pub struct State {
    /// Loaded at startup only from the settings file.
    pub debug_name: DebugName,
    pub trace_mask: TraceMask,
    pub dump_mode: DumpMode,
    pub dump_settings: DumpSettings,
    pub event_defer: EventDeferMask,
    pub http_registration: HttpRegistration,
    /// Kept across `httpreg` commands, as stock 0x91fae2e0 and 0x91f9f64c.
    pub registration_check: RegistrationCheck,
}

impl State {
    pub const fn new() -> Self {
        Self {
            debug_name: DebugName::EMPTY,
            trace_mask: TraceMask(0),
            dump_mode: DumpMode::Smart,
            dump_settings: DumpSettings::new(),
            event_defer: EventDeferMask::DEFAULT,
            http_registration: HttpRegistration::EMPTY,
            registration_check: RegistrationCheck::EMPTY,
        }
    }
}

/// Lines of the `systeminfo` reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemInfoLine {
    Disk,
    KitType,
    Hardware,
    Versions,
    End,
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    SystemInfo {
        next: SystemInfoLine,
        info: SystemInformation,
        test_kit: bool,
    },
}

/// Hardware capabilities reported by `consolefeatures`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KitFeatures {
    pub debugging: bool,
    pub secondary_nic: bool,
    pub one_gigabyte_ram: bool,
}

impl KitFeatures {
    /// Export 220 bits (stock 0x91f4cd60).
    pub fn mask(self) -> u32 {
        u32::from(self.debugging)
            | u32::from(self.secondary_nic) << 1
            | u32::from(self.one_gigabyte_ram) << 2
    }
}

/// Address of a console configuration setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConfigSetting {
    pub category: u16,
    pub index: u16,
}

impl ConfigSetting {
    pub const fn new(category: u16, index: u16) -> Self {
        Self { category, index }
    }
}

/// Fields of the kernel memory statistics (debug monitor service 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryStatistics {
    /// Reply offset 0x08: physical pages managed by the kernel.
    pub physical_pages: u32,
    /// Reply offset 0x70; bits 8..20 are the debug memory size.
    pub debug_memory: u32,
    /// Reply offset 0x7c: the page count of the base memory configuration.
    pub page_threshold: u32,
}

impl MemoryStatistics {
    /// `debugmemsize` and export 213: bits 8..20 of offset 0x70.
    pub fn debug_memory_size(&self) -> u32 {
        (self.debug_memory >> 8) & 0xfff
    }
}

/// Memory configuration reported by `consolemem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleMemory {
    /// The console has no additional memory.
    Standard = 0,
    /// Additional memory is installed but the kernel does not use it.
    ExtraMemoryUnused = 1,
    /// The kernel manages more pages than the base configuration.
    ExtraMemoryInUse = 2,
}

impl ConsoleMemory {
    pub const fn value(self) -> u32 {
        self as u32
    }
}

/// Result code of a system message request; negative values are failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XamStatus(pub u32);

impl XamStatus {
    pub const fn is_failure(self) -> bool {
        (self.0 as i32) < 0
    }
}

/// Data-center network configuration record exchanged with the system
/// network service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkRaRecord {
    pub flags: u32,
    pub custom_boot_address: u32,
}

impl NetworkRaRecord {
    pub const RELAX_HEARTBEAT: u32 = 0x8000_0000;
    pub const CUSTOM_BOOT_ADDRESS: u32 = 0x4000_0000;
}

/// A request to the system network service (message 0x00a00004).
#[derive(Debug)]
pub enum NetworkRaRequest<'a> {
    /// Fill the record with the current configuration.
    Get(&'a mut NetworkRaRecord),
    /// Store the record.
    Set(&'a mut NetworkRaRecord),
    Reset,
}

/// A four-part version number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Version(pub [u16; 4]);

/// Kernel versions and hardware flags for `systeminfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SystemInformation {
    pub base_kernel: Version,
    pub kernel: Version,
    /// First dword of the kernel hardware information export.
    pub hardware_flags: u32,
}

/// A network address record and the status of the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkAddress {
    /// Address query flags; 0 means pending.
    pub status: u32,
    pub record: [u8; NETWORK_ADDRESS_SIZE],
}

/// Console identifier text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleId(pub [u8; CONSOLE_ID_LENGTH]);

/// Bytes of the settings block of control codes 0x1e and 0x1f.
pub const SYSTEM_SETTINGS_SIZE: usize = 0xc;
/// [`SystemSettings`] flag: the video standard is set.
const SYSTEM_SETTINGS_VIDEO_STANDARD: u32 = 1;

/// Settings block of control codes 0x1e and 0x1f (stock 0x91fade20),
/// big-endian: +0 size given by the last writer, +4 flags, +8 video
/// standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SystemSettings(pub [u8; SYSTEM_SETTINGS_SIZE]);

impl SystemSettings {
    fn word(&self, offset: usize) -> u32 {
        let bytes = &self.0;
        u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    /// The video standard, when its flag is set.
    pub fn video_standard(&self) -> Option<u32> {
        (self.word(4) & SYSTEM_SETTINGS_VIDEO_STANDARD != 0).then(|| self.word(8))
    }

    /// Settings-file `sysset videostd=`; the other flags are kept.
    pub fn set_video_standard(&mut self, value: u32) {
        let flags = self.word(4) | SYSTEM_SETTINGS_VIDEO_STANDARD;
        self.0[4..8].copy_from_slice(&flags.to_be_bytes());
        self.0[8..12].copy_from_slice(&value.to_be_bytes());
    }

    /// Stock export 92 (code 0x1e): `block` is the caller's block cut to
    /// its size field and [`SYSTEM_SETTINGS_SIZE`]. Only the video standard
    /// flag is kept.
    pub fn store(&mut self, block: &[u8]) {
        let length = block.len().min(SYSTEM_SETTINGS_SIZE);
        self.0[..length].copy_from_slice(&block[..length]);
        let flags = self.word(4) & SYSTEM_SETTINGS_VIDEO_STANDARD;
        self.0[4..8].copy_from_slice(&flags.to_be_bytes());
    }
}

/// A registration request: `GET <path>` to `server` on `port` (0 for the
/// default port).
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest<'a> {
    pub server: &'a [u8],
    pub port: u16,
    pub path: &'a [u8],
}

/// Step of starting a request that failed (stock 0x91f300e0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpStartStage {
    Startup,
    Session,
    Connection,
    Request,
    Send,
}

/// A failed request start and the last error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpStartFailure {
    pub stage: HttpStartStage,
    pub error: u32,
}

/// How an in-progress request failed. Errors are last error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFailure {
    Work {
        error: u32,
    },
    Receive {
        error: u32,
    },
    StatusQuery {
        error: u32,
    },
    /// The server answered with a status other than 200.
    Status {
        code: u32,
    },
    ContentLength {
        error: u32,
    },
    /// The announced body exceeds [`REGISTRATION_RESPONSE_CAPACITY`].
    TooLarge {
        length: u32,
    },
    Read {
        error: u32,
    },
    /// The request failed in stock state `state` (1 sending, 3 receiving
    /// headers, 5 reading).
    Request {
        state: u32,
        error: u32,
    },
    /// The connection ended with `expected` body bytes outstanding.
    Truncated {
        received: u32,
        expected: u32,
    },
}

/// Progress of an in-progress request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpProgress {
    Pending,
    /// The status was 200 and this many body bytes were stored.
    Complete(usize),
    Failed(HttpFailure),
}

/// Platform services this domain needs.
pub trait Backend {
    fn kit_features(&mut self) -> KitFeatures;
    /// Read a configuration setting into `output`; returns the stored length.
    fn xconfig_get(&mut self, setting: ConfigSetting, output: &mut [u8])
    -> Result<usize, NtStatus>;
    fn xconfig_set(&mut self, setting: ConfigSetting, value: &[u8]) -> Result<(), NtStatus>;
    /// Kernel export 700: replace a 4-byte setting with
    /// `(old & and_mask) | or_mask`. [`STATUS_PROCEDURE_NOT_FOUND`] when
    /// the export is absent.
    fn xconfig_modify(
        &mut self,
        setting: ConfigSetting,
        and_mask: u32,
        or_mask: u32,
    ) -> Result<(), NtStatus>;
    /// Read the SMC I2C settings block; `None` when the read fails.
    fn read_settings_block(&mut self) -> Option<[u8; SETTINGS_BLOCK_SIZE]>;
    /// Write the SMC I2C settings block; false when the write fails.
    fn write_settings_block(&mut self, block: &[u8; SETTINGS_BLOCK_SIZE]) -> bool;
    /// Kernel memory statistics; `None` when the query fails.
    fn memory_statistics(&mut self) -> Option<MemoryStatistics>;
    fn system_information(&mut self) -> SystemInformation;
    fn console_id(&mut self) -> Result<ConsoleId, NtStatus>;
    fn debug_network_address(&mut self) -> NetworkAddress;
    fn title_network_address(&mut self) -> NetworkAddress;
    /// Apply the inactivity auto-shutoff configuration.
    fn apply_inactivity_time(&mut self);
    fn network_ra_request(&mut self, request: NetworkRaRequest<'_>) -> XamStatus;
    /// Whether the system UI library exports its feature switch (ordinal 515).
    fn feature_switch_present(&mut self) -> bool;
    fn set_feature(&mut self, enable: u32, feature: u32);
    /// Load the network file system client; the status of the image load.
    fn load_network_client(&mut self) -> NtStatus;
    /// Millisecond tick count.
    fn tick_milliseconds(&mut self) -> u32;
    /// Version of the system software (XAM).
    fn xam_version(&mut self) -> u32;
    /// Start a registration request.
    fn http_begin(&mut self, request: &HttpRequest<'_>) -> Result<(), HttpStartFailure>;
    /// Advance the request; on completion the body is in `body`.
    fn http_poll(&mut self, body: &mut [u8; REGISTRATION_RESPONSE_CAPACITY]) -> HttpProgress;
    /// Release the request and the HTTP client.
    fn http_close(&mut self);
    /// Make server state readable by other threads (control codes 0x0b
    /// and 0x33, the monitor exports).
    fn publish(&mut self, value: Published<'_>);
    /// The settings block of control codes 0x1e and 0x1f.
    fn system_settings(&mut self) -> SystemSettings;
    fn set_system_settings(&mut self, settings: SystemSettings);
    /// Report this console as a test kit from now on (stock 0x91f9f680).
    fn mark_test_kit(&mut self);
    /// Thread object of the caller, for the trace texts (stock PCR +0x100).
    fn current_thread(&mut self) -> u32;
    /// The published trace mask, for code that holds no server state.
    fn trace_mask(&mut self) -> TraceMask;
}

/// Stock 0x91f4d350: set or clear `mask` in the 4-byte setting (3, `index`)
/// through kernel export 700, or read, modify and write the setting when
/// that export is absent. Failures map with fallback 0x8000ffff.
pub fn modify_config_flag(
    backend: &mut dyn AnyBackend,
    index: u16,
    mask: u32,
    set: bool,
) -> Hresult {
    let setting = ConfigSetting::new(3, index);
    let or_mask = if set { mask } else { 0 };
    let status = match backend.xconfig_modify(setting, !mask, or_mask) {
        Err(STATUS_PROCEDURE_NOT_FOUND) => {
            let mut value = [0u8; 4];
            match backend.xconfig_get(setting, &mut value) {
                Ok(_) => {
                    let old = u32::from_be_bytes(value);
                    let new = if set { old | mask } else { old & !mask };
                    backend.xconfig_set(setting, &new.to_be_bytes())
                }
                Err(status) => Err(status),
            }
        }
        other => other,
    };
    Hresult::from_nt_status(
        status.err().unwrap_or(NtStatus::SUCCESS),
        Hresult::UNEXPECTED,
    )
}

/// Stock 0x91f50088 (export 214), shared with `consolemem` and
/// `addtitlemem`.
pub fn console_memory(backend: &mut dyn AnyBackend) -> ConsoleMemory {
    ConsoleMemory::of(backend.kit_features(), || backend.memory_statistics())
}

impl ConsoleMemory {
    /// The statistics are queried only for a 1 GB console.
    pub fn of(
        features: KitFeatures,
        statistics: impl FnOnce() -> Option<MemoryStatistics>,
    ) -> Self {
        if !features.one_gigabyte_ram {
            return Self::Standard;
        }
        match statistics() {
            None => Self::Standard,
            Some(statistics) if statistics.page_threshold < statistics.physical_pages => {
                Self::ExtraMemoryInUse
            }
            Some(_) => Self::ExtraMemoryUnused,
        }
    }
}

/// Startup work of this domain, before the settings file is read: a test
/// kit starts with crash dumps enabled (stock 0x91f32628), and the network
/// share drive follows the stored server setting.
pub(crate) fn initialize(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    if backend.is_test_kit() {
        state.console.dump_mode = DumpMode::Enabled;
        backend.publish(Published::DumpMode(DumpMode::Enabled));
    }
    refresh_network_share(state, backend);
}

/// Hardware flags field of the console generation; Trinity is 4.
const HARDWARE_GENERATION_MASK: u32 = 0xf000_0000;
const HARDWARE_GENERATION_TRINITY: u32 = 0x4000_0000;
/// Reads of the settings block before it counts as unreadable.
const SETTINGS_BLOCK_READS: usize = 3;
/// Flash block startup inspects, and the dword in it that it clears.
const FLASH_BLOCK_OFFSET: u32 = 0x80;
const FLASH_BLOCK_SIZE: usize = 0x80;
const FLASH_BLOCK_CLEARED: core::ops::Range<usize> = 0x10..0x14;

/// Stock 0x91f4e648: whether the I2C settings block can be read.
pub(crate) fn settings_block_readable(backend: &mut dyn AnyBackend) -> bool {
    (0..SETTINGS_BLOCK_READS).any(|_| backend.read_settings_block().is_some())
}

/// Whether hardware `flags` describe a console from Trinity on.
pub(crate) fn trinity_or_later(flags: u32) -> bool {
    flags & HARDWARE_GENERATION_MASK >= HARDWARE_GENERATION_TRINITY
}

/// Stock 0x91f329f0, after the settings files when `drivemap internal` is
/// off: a console from Trinity on whose I2C settings block cannot be read
/// is a test kit. When the dword at +0x10 of the flash block at 0x80 is
/// nonzero, it is cleared and the console restarts.
pub(crate) fn check_settings_block(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    if settings_block_readable(backend) || !trinity_or_later(backend.hardware_flags()) {
        return;
    }
    backend.mark_test_kit();
    if state.console.dump_mode == DumpMode::Smart {
        state.console.dump_mode = DumpMode::Enabled;
        backend.publish(Published::DumpMode(DumpMode::Enabled));
    }
    let mut block = [0u8; FLASH_BLOCK_SIZE];
    if backend.read_flash(FLASH_BLOCK_OFFSET, &mut block).is_err()
        || block[FLASH_BLOCK_CLEARED] == [0; 4]
    {
        return;
    }
    block[FLASH_BLOCK_CLEARED].fill(0);
    // Stock ignores the write result and restarts regardless.
    let _ = backend.write_flash(FLASH_BLOCK_OFFSET, &block);
    backend.reboot(RebootKind::Normal);
}

/// Stock 0x91f30998, run when the title ends: before system software
/// 0x20165400 a registration request in progress is abandoned and started
/// again.
pub(crate) fn title_terminated(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    let registration = &mut state.console.http_registration;
    if backend.xam_version() < REGISTRATION_ANY_STATE_VERSION
        && registration.state == RegistrationState::InProgress
    {
        backend.http_close();
        registration.state = RegistrationState::Pending;
        backend.publish(Published::Registration(registration));
    }
}

/// Settings-file `sysset videostd=<dword>` (stock DoIniLine 0x91f311b8).
pub(crate) fn ini_sysset(invocation: &mut Invocation<'_>) {
    if let Some(value) = invocation
        .line
        .param("videostd")
        .and_then(|value| value.dword())
    {
        let mut settings = invocation.backend.system_settings();
        settings.set_video_standard(value);
        invocation.backend.set_system_settings(settings);
    }
}

/// `sysset[ videostd=0x%08x]` of the alternate settings writer (stock
/// 0x91f31fb0).
pub(crate) fn sysset_settings_lines(
    _state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    write_text(backend, file, format_args!("sysset"));
    if let Some(standard) = backend.system_settings().video_standard() {
        write_text(backend, file, format_args!(" videostd=0x{standard:08x}"));
    }
    end_line(backend, file);
}

/// Stock 0x91f2ec88: point the network share drive at the server named by
/// configuration setting (3, 0x10), or disable it when the name is empty or
/// too long. A failed setting read or client load leaves the drive as is.
pub(crate) fn refresh_network_share(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    let mut setting = [0u8; NETWORK_SHARE_SIZE];
    if backend
        .xconfig_get(SETTING_NETWORK_SHARE, &mut setting)
        .is_err()
    {
        return;
    }
    let mut length = 0;
    if setting[0] != 0 {
        let mut index = 0;
        while index <= NETWORK_SHARE_NAME_LIMIT {
            if setting[index] == b'\t' {
                setting[index] = 0;
                break;
            }
            index += 1;
            length = index;
            if setting[index] == 0 {
                break;
            }
        }
    }
    if length == 0 || length > NETWORK_SHARE_NAME_LIMIT || setting[0] == 0 {
        state.filesystem.drives.set_network_share(None);
    } else if backend.load_network_client().is_success() {
        state
            .filesystem
            .drives
            .set_network_share(Some(&setting[..length]));
    }
}

pub(crate) fn resume(continuation: &mut Continuation, cx: &mut ContinuationContext<'_>) -> Hresult {
    match continuation {
        Continuation::SystemInfo {
            next,
            info,
            test_kit,
        } => system_info_line(next, info, *test_kit, cx.line),
    }
}

fn string_param<'b>(
    invocation: &Invocation<'_>,
    name: &str,
    buffer: &'b mut [u8],
) -> Option<&'b [u8]> {
    invocation
        .line
        .param(name)
        .map(|value| value.copy_into(buffer))
}

fn equals_any(value: &[u8], words: &[&str]) -> bool {
    words
        .iter()
        .any(|word| value.eq_ignore_ascii_case(word.as_bytes()))
}

/// `altaddr`: the title IPv4 address; fails while the address is pending.
fn alternate_address(invocation: &mut Invocation<'_>) -> Hresult {
    let address = invocation.backend.title_network_address();
    if address.status <= 1 {
        return Hresult::FAIL;
    }
    let [a, b, c, d, ..] = address.record;
    invocation.set_text(format_args!(
        "addr=0x{:08x}",
        u32::from_be_bytes([a, b, c, d])
    ));
    Hresult::OK
}

/// `autoshutoff timeout=<hours>`: 0, 1 or 6 hours; stored in minutes with
/// bit 15 set.
fn auto_shutoff(invocation: &mut Invocation<'_>) -> Hresult {
    let value = invocation.line.param("timeout");
    let hours = value.map_or(0, |value| value.dword_prefix());
    let result = match value.and_then(|value| value.dword()) {
        None => Hresult::error(0),
        Some(0 | 1 | 6) => {
            let minutes = ((hours * 60) as u16) | 0x8000;
            if invocation
                .backend
                .xconfig_set(SETTING_AUTO_SHUTOFF, &minutes.to_be_bytes())
                .is_ok()
            {
                invocation.backend.apply_inactivity_time();
                Hresult::OK
            } else {
                Hresult::error(0)
            }
        }
        Some(_) => BAD_PARAMETER,
    };
    let mut message = LineText::new();
    let _ = writeln!(
        message,
        "[xbdm] AutoShutoff, timeout={hours} hr:0x{:08X}",
        result.0
    );
    invocation.backend.debug_print(message.as_bytes());
    result
}

fn network_ra_failure(invocation: &mut Invocation<'_>, status: XamStatus) -> Hresult {
    invocation.set_text(format_args!(
        "\x1e{VE_FAILURE} (err 0x{:08X})\x1e",
        status.0
    ));
    Hresult::UNEXPECTED
}

/// Stock 0x91f46560: query and print the configuration.
fn show_network_ra(invocation: &mut Invocation<'_>, record: &mut NetworkRaRecord) -> Hresult {
    record.flags = 0;
    let status = invocation
        .backend
        .network_ra_request(NetworkRaRequest::Get(record));
    if status.is_failure() {
        return network_ra_failure(invocation, status);
    }
    let relax = if record.flags & NetworkRaRecord::RELAX_HEARTBEAT != 0 {
        "on"
    } else {
        "off"
    };
    invocation.set_text(format_args!(
        "\x1e{VE_HEADER}\x1erelaxheartbeat={relax} customubootaddr=0x{:08X}\x1e",
        record.custom_boot_address
    ));
    Hresult::OK
}

/// `confignetra [show] [relaxheartbeat=on|off] [customubootaddr=<dword>]`.
fn configure_network_ra(invocation: &mut Invocation<'_>) -> Hresult {
    let mut record = NetworkRaRecord::default();
    if invocation.line.has("show") {
        return show_network_ra(invocation, &mut record);
    }
    let status = invocation
        .backend
        .network_ra_request(NetworkRaRequest::Get(&mut record));
    if status.is_failure() {
        return network_ra_failure(invocation, status);
    }
    let mut changes = 0;
    if invocation.line.has("relaxheartbeat") {
        let mut buffer = [0u8; SWITCH_BUFFER];
        if let Some(value) = string_param(invocation, "relaxheartbeat", &mut buffer) {
            record.flags &= !NetworkRaRecord::RELAX_HEARTBEAT;
            if value.eq_ignore_ascii_case(b"on") {
                record.flags |= NetworkRaRecord::RELAX_HEARTBEAT;
            }
            changes += 1;
        }
    }
    if invocation.line.has("customubootaddr")
        && let Some(address) = invocation
            .line
            .param("customubootaddr")
            .and_then(|value| value.dword())
    {
        record.custom_boot_address = address;
        record.flags &= !NetworkRaRecord::CUSTOM_BOOT_ADDRESS;
        if address != 0 {
            record.flags |= NetworkRaRecord::CUSTOM_BOOT_ADDRESS;
        }
        changes += 1;
    }
    if changes == 0 {
        invocation.set_text(format_args!("\x1e{VE_USAGE}\x1e"));
        return UNKNOWN_COMMAND;
    }
    let status = invocation
        .backend
        .network_ra_request(NetworkRaRequest::Set(&mut record));
    if status.is_failure() {
        return network_ra_failure(invocation, status);
    }
    show_network_ra(invocation, &mut record)
}

/// `consolefeatures`: each feature name is appended with a leading space.
fn console_features(invocation: &mut Invocation<'_>) -> Hresult {
    let features = invocation.backend.kit_features();
    invocation.text.clear();
    for (present, name) in [
        (features.debugging, " DEBUGGING"),
        (features.secondary_nic, " SECONDARY_NIC"),
        (features.one_gigabyte_ram, " 1GB_RAM"),
    ] {
        if present {
            let _ = invocation.text.push_bytes(name.as_bytes());
        }
    }
    Hresult::OK
}

fn console_memory_command(invocation: &mut Invocation<'_>) -> Hresult {
    let memory = console_memory(invocation.backend);
    invocation.set_text(format_args!("consolemem=0x{:x}", memory.value()));
    Hresult::OK
}

/// `consoletype`: stock reports only these two kit types.
fn console_type(invocation: &mut Invocation<'_>) -> Hresult {
    let kind: &[u8] = if invocation.backend.is_test_kit() {
        b"testkit"
    } else {
        b"devkit"
    };
    invocation.text.set_bytes(kind);
    Hresult::OK
}

/// `datacentermode [enabled=on|true]`: any other value, or none, disables.
fn data_center_mode(invocation: &mut Invocation<'_>) -> Hresult {
    let mut buffer = [0u8; SWITCH_BUFFER];
    let enable = string_param(invocation, "enabled", &mut buffer)
        .is_some_and(|value| equals_any(value, &["on", "true"]));
    let _ = modify_config_flag(
        invocation.backend,
        USER_FLAGS_INDEX,
        USER_FLAG_DATA_CENTER,
        enable,
    );
    Hresult::OK
}

/// Stock 0x91f4e6b0: store the name in the SMC I2C settings block when it
/// differs. Block layout: +0 version (2), +1 size (0x20), +0xa name length,
/// +0xb name (20 bytes, zero padded).
fn persist_debug_name(backend: &mut dyn AnyBackend, name: &[u8]) {
    let Some(mut block) = backend.read_settings_block() else {
        return;
    };
    let mut changed = false;
    if block[0] < 2 || block[0] == 0xff {
        block[0] = 2;
        block[1] = SETTINGS_BLOCK_SIZE as u8;
        changed = true;
    }
    let length = name.len();
    if usize::from(block[0xa]) != length || block[0xb..0xb + length] != *name {
        changed = true;
    }
    if !changed {
        return;
    }
    block[0xa] = length as u8;
    block[0xb..0xb + length].copy_from_slice(name);
    block[0xb + length..0xb + DEBUG_NAME_CAPACITY - 1].fill(0);
    if !backend.write_settings_block(&block) {
        backend.debug_print(b"dm: I2C write failed.\n");
    }
}

/// `dbgname [name=<string>]`: report or set the debug name. Setting it
/// requires the config privilege and also rewrites the settings file.
fn debug_name(invocation: &mut Invocation<'_>) -> Hresult {
    let mut buffer = [0u8; DEBUG_NAME_CAPACITY];
    let Some(value) = string_param(invocation, "name", &mut buffer) else {
        let name = invocation.state.console.debug_name;
        invocation.text.set_bytes(name.as_bytes());
        return Hresult::OK;
    };
    if !invocation.access().intersects(Access::CONFIG) {
        return ACCESS_DENIED;
    }
    let name = DebugName::new(value);
    invocation.state.console.debug_name = name;
    invocation.backend.publish(Published::DebugName(&name));
    persist_debug_name(invocation.backend, name.as_bytes());
    crate::commands::system::save_settings(invocation.state, invocation.backend);
    Hresult::OK
}

/// `debugmemsize`: bits 8..20 of debug monitor memory statistic 0x70.
fn debug_memory_size(invocation: &mut Invocation<'_>) -> Hresult {
    // A failed query reports 0, as stock does.
    let size = invocation
        .backend
        .memory_statistics()
        .map_or(0, |statistics| statistics.debug_memory_size());
    invocation.set_text(format_args!("debugmemsize=0x{size:x}"));
    Hresult::OK
}

/// `debugmode`: gated by a stock global (0x91fab9a8) that nothing sets, so
/// the command is always unknown.
fn debug_mode(_invocation: &mut Invocation<'_>) -> Hresult {
    UNKNOWN_COMMAND
}

/// `discoverable enabled=on|true|off|false`; the write result is ignored.
fn discoverable(invocation: &mut Invocation<'_>) -> Hresult {
    let mut buffer = [0u8; SWITCH_BUFFER];
    let value = match string_param(invocation, "enabled", &mut buffer) {
        Some(value) if equals_any(value, &["on", "true"]) => 1u8,
        Some(value) if equals_any(value, &["off", "false"]) => 0,
        _ => return BAD_PARAMETER,
    };
    let _ = invocation
        .backend
        .xconfig_set(SETTING_DISCOVERABLE, &[value]);
    Hresult::OK
}

/// `dumpmode [smart|enabled|disabled]`: the first present flag is stored
/// through export 118. Replies with the current mode.
fn dump_mode(invocation: &mut Invocation<'_>) -> Hresult {
    if let Some(mode) = DumpMode::ALL
        .into_iter()
        .find(|mode| invocation.line.has(mode.name()))
    {
        set_dump_mode(invocation.state, invocation.backend, mode);
        crate::commands::system::save_settings(invocation.state, invocation.backend);
    }
    invocation
        .text
        .set_bytes(invocation.state.console.dump_mode.name().as_bytes());
    Hresult::OK
}

/// Stock export 118, also behind `dumpmode`: a test kit stores `enabled`
/// for `smart`.
fn set_dump_mode(state: &mut ServerState, backend: &mut dyn AnyBackend, mode: DumpMode) {
    let mode = if mode == DumpMode::Smart && backend.is_test_kit() {
        backend.debug_print(b"Reset Dump mode to ENABLED for the TEST KIT!\n");
        DumpMode::Enabled
    } else {
        mode
    };
    state.console.dump_mode = mode;
    backend.publish(Published::DumpMode(mode));
}

/// The index of the name a `dumpsettings` selector gives for `field`.
fn dump_selector(invocation: &Invocation<'_>, name: &str, field: DumpField) -> Option<u32> {
    let mut buffer = [0u8; DUMP_SELECTOR_BUFFER];
    let value = string_param(invocation, name, &mut buffer)?;
    let names = &DUMP_NAMES[field.first..field.first + field.count];
    names
        .iter()
        .position(|word| value.eq_ignore_ascii_case(word.as_bytes()))
        .map(|index| index as u32)
}

/// `dumpsettings [rpt=] [dst=] [fmt=] [path=]`: unrecognized values are
/// ignored; replies with the current settings.
fn dump_settings(invocation: &mut Invocation<'_>) -> Hresult {
    let mut settings = invocation.state.console.dump_settings;
    let mut changed = false;
    for (name, field) in [
        ("rpt", DUMP_REPORT),
        ("dst", DUMP_DESTINATION),
        ("fmt", DUMP_FORMAT),
    ] {
        if let Some(value) = dump_selector(invocation, name, field) {
            settings.set(field, value);
            changed = true;
        }
    }
    if let Some(value) = invocation.line.param("path") {
        let mut buffer = [0u8; DUMP_PATH_CAPACITY + 1];
        settings.set_path(value.copy_into(&mut buffer));
        changed = true;
    }
    if changed {
        invocation.state.console.dump_settings = settings;
        invocation
            .backend
            .publish(Published::DumpSettings(&settings));
        crate::commands::system::save_settings(invocation.state, invocation.backend);
    }
    let text = &mut *invocation.text;
    text.clear();
    settings.write_summary(&mut |bytes| {
        let _ = text.push_bytes(bytes);
    });
    Hresult::OK
}

/// `eventdefer [set [break] [debugstring] ...]`: `set` replaces the mask
/// with the named events. Replies with a leading space before each name.
fn event_defer(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.line.has("set") {
        let mut mask = 0;
        for (bit, name) in EventDeferMask::NAMES.iter().enumerate() {
            if invocation.line.has(name) {
                mask |= 1 << bit;
            }
        }
        invocation.state.console.event_defer = EventDeferMask(mask);
        invocation
            .backend
            .publish(Published::EventDefer(EventDeferMask(mask)));
        crate::commands::system::save_settings(invocation.state, invocation.backend);
    }
    invocation.text.clear();
    for name in invocation.state.console.event_defer.names() {
        let _ = invocation.text.push_bytes(b" ");
        let _ = invocation.text.push_bytes(name.as_bytes());
    }
    Hresult::OK
}

/// Server state other threads read through the monitor exports and
/// control codes.
#[derive(Debug, Clone, Copy)]
pub enum Published<'a> {
    DebugName(&'a DebugName),
    DumpMode(DumpMode),
    DumpSettings(&'a DumpSettings),
    EventDefer(EventDeferMask),
    TraceMask(TraceMask),
    /// Export 194 reads the state, transaction and response.
    Registration(&'a HttpRegistration),
}

/// A setting a monitor export changes on another thread; the platform
/// applies it on the server thread.
// A value lives only on the stack of the export waiting for the server.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy)]
pub enum ExportedSetting {
    /// Export 43.
    DebugName(DebugName),
    /// Export 118.
    DumpMode(u32),
    /// Export 120.
    DumpSettings([u8; DUMP_SETTINGS_SIZE]),
    /// Export 122.
    EventDefer(u32),
}

/// Store a setting changed by a monitor export and write the settings file
/// (stock WriteIniFile, synchronous in each export). Export 43 then writes
/// the name to the SMC I2C settings block.
pub fn apply_exported_setting(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    setting: ExportedSetting,
) {
    match setting {
        ExportedSetting::DebugName(name) => {
            state.console.debug_name = name;
            backend.publish(Published::DebugName(&name));
        }
        ExportedSetting::DumpMode(raw) => set_dump_mode(state, backend, DumpMode::from_raw(raw)),
        ExportedSetting::DumpSettings(block) => {
            let settings = DumpSettings::from_block(&block);
            state.console.dump_settings = settings;
            backend.publish(Published::DumpSettings(&settings));
        }
        ExportedSetting::EventDefer(mask) => {
            state.console.event_defer = EventDeferMask(mask);
            backend.publish(Published::EventDefer(EventDeferMask(mask)));
        }
    }
    crate::commands::system::save_settings(state, backend);
    if let ExportedSetting::DebugName(name) = setting {
        persist_debug_name(backend, name.as_bytes());
    }
}

/// `feature enable=<dword> feature=<dword>`: forwarded to the system UI
/// library; without that export the command does nothing.
fn feature(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return BAD_PARAMETER;
    }
    if !invocation.backend.feature_switch_present() {
        return Hresult::OK;
    }
    let Some(enable) = invocation
        .line
        .param("enable")
        .and_then(|value| value.dword())
    else {
        invocation.text.set_bytes(b"'enable' not specified");
        return BAD_PARAMETER;
    };
    let Some(feature) = invocation
        .line
        .param("feature")
        .and_then(|value| value.dword())
    else {
        invocation.text.set_bytes(b"'feature' not specified");
        return BAD_PARAMETER;
    };
    invocation.backend.set_feature(enable, feature);
    Hresult::OK
}

/// `getconsoleid`: a failed read returns the status with bit 28 set.
fn console_id(invocation: &mut Invocation<'_>) -> Hresult {
    match invocation.backend.console_id() {
        Ok(ConsoleId(id)) => {
            let length = id.iter().position(|&byte| byte == 0).unwrap_or(id.len());
            invocation.text.clear();
            let _ = invocation.text.push_bytes(b"consoleid=");
            let _ = invocation.text.push_bytes(&id[..length]);
            Hresult::OK
        }
        Err(status) => Hresult(status.0 | 0x1000_0000),
    }
}

fn push_hex(invocation: &mut Invocation<'_>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in bytes {
        let _ = invocation.text.push_bytes(&[
            DIGITS[usize::from(byte >> 4)],
            DIGITS[usize::from(byte & 0xf)],
        ]);
    }
}

/// `getnetaddrs`: debug name and both address records in hex.
fn network_addresses(invocation: &mut Invocation<'_>) -> Hresult {
    let debug = invocation.backend.debug_network_address();
    let title = invocation.backend.title_network_address();
    if debug.status == 0 || title.status == 0 {
        invocation.set_text(format_args!(
            "debugstatus=0x{:08x} titlestatus=0x{:08x}",
            debug.status, title.status
        ));
        return NOT_AVAILABLE;
    }
    let name = invocation.state.console.debug_name;
    invocation.text.clear();
    let _ = invocation.text.push_bytes(b"name=");
    let _ = invocation.text.push_bytes(name.as_bytes());
    let _ = invocation.text.push_bytes(b" debug=");
    push_hex(invocation, &debug.record);
    let _ = invocation.text.push_bytes(b" title=");
    push_hex(invocation, &title.record);
    Hresult::OK
}

/// `httpreg clear` | `httpreg server=<s> object=</path> [port=<dword>]`.
/// Every call clears the previous registration and rewrites the settings
/// file.
fn http_registration(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.state.console.http_registration.state == RegistrationState::InProgress {
        invocation.backend.http_close();
    }
    let registration = &mut invocation.state.console.http_registration;
    *registration = HttpRegistration::EMPTY;
    let result = if invocation.line.has("clear") {
        registration.state = RegistrationState::Cleared;
        Hresult::OK
    } else {
        let mut buffer = [0u8; REGISTRATION_TEXT_CAPACITY + 1];
        let server = invocation
            .line
            .param("server")
            .map(|value| value.copy_into(&mut buffer).len());
        if let Some(length) = server {
            registration.server[..length].copy_from_slice(&buffer[..length]);
            registration.server_len = length as u8;
        }
        let object = server
            .and(invocation.line.param("object"))
            .map(|value| value.copy_into(&mut buffer).len());
        if let Some(length) = object {
            registration.object[..length].copy_from_slice(&buffer[..length]);
            registration.object_len = length as u8;
        }
        if object.is_none() {
            registration.state = RegistrationState::Failed;
            BAD_PARAMETER
        } else if registration.object().first() != Some(&b'/') {
            registration.state = RegistrationState::Failed;
            FILENAME_INVALID
        } else {
            registration.port = invocation
                .line
                .param("port")
                .and_then(|value| value.dword())
                .map_or(0, |port| port as u16);
            registration.state = RegistrationState::Pending;
            Hresult::OK
        }
    };
    invocation.backend.publish(Published::Registration(
        &invocation.state.console.http_registration,
    ));
    crate::commands::system::save_settings(invocation.state, invocation.backend);
    result
}

/// Settings-file `httpreg` line (stock DoIniLine calls the handler).
pub(crate) fn ini_httpreg(invocation: &mut Invocation<'_>) {
    let _ = http_registration(invocation);
}

/// Diagnostic message; holds the longest registration message (a 0x3ff-byte
/// path plus the server).
pub(crate) type MessageText = crate::text::Text<0x600>;

fn print(backend: &mut dyn AnyBackend, arguments: core::fmt::Arguments<'_>) {
    let mut message = MessageText::new();
    let _ = message.write_fmt(arguments);
    backend.debug_print(message.as_bytes());
}

/// The registration request path: object, then the query of stock
/// 0x91f300e0, truncated as `_snprintf` with a 0x400-byte buffer.
fn registration_path(
    state: &ServerState,
    test_kit: bool,
    kernel: Version,
    buffer: &mut [u8; REGISTRATION_PATH_CAPACITY],
) -> usize {
    struct Path<'a> {
        buffer: &'a mut [u8; REGISTRATION_PATH_CAPACITY],
        len: usize,
    }
    impl Path<'_> {
        fn push(&mut self, bytes: &[u8]) {
            let count = bytes.len().min(self.buffer.len() - self.len);
            self.buffer[self.len..self.len + count].copy_from_slice(&bytes[..count]);
            self.len += count;
        }
    }
    impl core::fmt::Write for Path<'_> {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            self.push(text.as_bytes());
            Ok(())
        }
    }
    let console = &state.console;
    let registration = &console.http_registration;
    let address = &console.registration_check.address;
    let Version(version) = kernel;
    let mut path = Path { buffer, len: 0 };
    path.push(registration.object());
    path.push(b"?name=");
    path.push(console.debug_name.as_bytes());
    let _ = write!(
        path,
        "&dbgmac={:02X}{:02X}{:02X}{:02X}{:02X}{:02X}&dbgip={}.{}.{}.{}&verflash={}.{}.{}.{}&verxdk={MONITOR_VERSION}\
         &type={}&locked={}&transaction={:016X}",
        address[10],
        address[11],
        address[12],
        address[13],
        address[14],
        address[15],
        address[0],
        address[1],
        address[2],
        address[3],
        version[0],
        version[1],
        version[2],
        version[3] & 0x7fff,
        u32::from(test_kit),
        i32::from(state.lock.is_locked()),
        registration.transaction,
    );
    path.len
}

/// Stock 0x91f300e0: build the request and start it.
fn start_registration(state: &mut ServerState, backend: &mut dyn AnyBackend) -> Result<(), u32> {
    let mut transaction = [0u8; 8];
    backend.random_bytes(&mut transaction);
    state.console.http_registration.transaction = u64::from_be_bytes(transaction);
    state.console.http_registration.response_len = 0;
    let test_kit = backend.is_test_kit();
    let kernel = backend.system_information().kernel;
    let mut path = [0u8; REGISTRATION_PATH_CAPACITY];
    let length = registration_path(state, test_kit, kernel, &mut path);
    let registration = &state.console.http_registration;
    let request = HttpRequest {
        server: registration.server(),
        port: registration.port,
        path: &path[..length],
    };
    if let Err(failure) = backend.http_begin(&request) {
        let stage = match failure.stage {
            HttpStartStage::Startup => "starting up XHttp",
            HttpStartStage::Session => "creating XHttp session object",
            HttpStartStage::Connection => "creating XHttp connection object",
            HttpStartStage::Request => "creating XHttp request object",
            HttpStartStage::Send => "starting HTTP request",
        };
        print(
            backend,
            format_args!("XBDM: Failed {stage} (err = {})!\n", failure.error),
        );
        state.console.http_registration.transaction = 0;
        return Err(failure.error);
    }
    let mut message = MessageText::new();
    let _ = message.write_str("XBDM: Attempting to register at [http://");
    let _ = message.push_bytes(request.server);
    if request.port != 0 {
        let _ = write!(message, ":{}", request.port);
    }
    let _ = message.push_bytes(request.path);
    let _ = message.write_str("]...\n");
    backend.debug_print(message.as_bytes());
    state.console.http_registration.state = RegistrationState::InProgress;
    Ok(())
}

/// Advance an in-progress request (stock 0x91f30580 states 1 to 7).
fn advance_registration(state: &mut ServerState, backend: &mut dyn AnyBackend) -> u32 {
    let registration = &mut state.console.http_registration;
    let failure = match backend.http_poll(&mut registration.response) {
        HttpProgress::Pending => return REGISTRATION_RETRY_MS,
        HttpProgress::Complete(length) => {
            registration.response_len = length as u16;
            print(
                backend,
                format_args!("XBDM: Received {length} byte HTTP registration response.\n"),
            );
            registration.state = RegistrationState::Registered;
            backend.http_close();
            return REGISTRATION_PERIOD_MS;
        }
        HttpProgress::Failed(failure) => failure,
    };
    let next = match failure {
        HttpFailure::Status { .. } => RegistrationState::Rejected,
        HttpFailure::TooLarge { .. } => RegistrationState::ResponseTooLarge,
        _ => RegistrationState::Failed,
    };
    match failure {
        HttpFailure::Work { error } => print(
            backend,
            format_args!("XBDM: Failed doing XHttp work (err = {error})!\n"),
        ),
        HttpFailure::Receive { error } => print(
            backend,
            format_args!("XBDM: Failed starting to receive HTTP response (err = {error})!\n"),
        ),
        HttpFailure::StatusQuery { error } => print(
            backend,
            format_args!("XBDM: Failed retrieving HTTP status code (err = {error})!\n"),
        ),
        HttpFailure::Status { code } => print(
            backend,
            format_args!("XBDM: HTTP server returned status code other than OK ({code})!\n"),
        ),
        HttpFailure::ContentLength { error } => print(
            backend,
            format_args!("XBDM: Failed retrieving content length (err = {error})!\n"),
        ),
        HttpFailure::TooLarge { length } => print(
            backend,
            format_args!(
                "XBDM: HTTP registration response too large ({length} > {REGISTRATION_RESPONSE_CAPACITY})!\n"
            ),
        ),
        HttpFailure::Read { error } => print(
            backend,
            format_args!("XBDM: Failed reading XHttp data (err = {error})!\n"),
        ),
        HttpFailure::Request { state, error } => print(
            backend,
            format_args!("XBDM: HTTP registration failed (state {state}, err = {error})!\n"),
        ),
        HttpFailure::Truncated { received, expected } => print(
            backend,
            format_args!(
                "XBDM: HTTP registration response truncated (received {received} bytes, expecting {expected} more)!\n"
            ),
        ),
    }
    backend.http_close();
    state.console.http_registration.state = next;
    REGISTRATION_PERIOD_MS
}

/// Stock 0x91f30580, run on every pass of the server loop: drive the lab
/// server registration and return the milliseconds until it needs to run
/// again. A registered or failed console registers again when its debug
/// address changes.
pub(crate) fn poll_registration(state: &mut ServerState, backend: &mut dyn AnyBackend) -> u32 {
    let registration = &state.console.http_registration;
    let before = (registration.state, registration.transaction);
    let wait = run_registration(state, backend);
    let registration = &state.console.http_registration;
    if (registration.state, registration.transaction) != before {
        backend.publish(Published::Registration(registration));
    }
    wait
}

fn run_registration(state: &mut ServerState, backend: &mut dyn AnyBackend) -> u32 {
    let now = backend.tick_milliseconds();
    match state.console.http_registration.state {
        RegistrationState::Cleared => return REGISTRATION_IDLE_MS,
        RegistrationState::InProgress => return advance_registration(state, backend),
        RegistrationState::Pending => {}
        RegistrationState::Registered
        | RegistrationState::Failed
        | RegistrationState::Rejected
        | RegistrationState::ResponseTooLarge => {
            let elapsed = now.wrapping_sub(state.console.registration_check.tick);
            if elapsed < REGISTRATION_PERIOD_MS {
                return REGISTRATION_PERIOD_MS - elapsed;
            }
            let address = backend.debug_network_address();
            if address.status == 0 {
                return REGISTRATION_RETRY_MS;
            }
            if address.record == state.console.registration_check.address {
                state.console.registration_check.tick = now;
                return REGISTRATION_PERIOD_MS;
            }
            state.console.http_registration.state = RegistrationState::Pending;
        }
    }
    let address = backend.debug_network_address();
    if address.status == 0 {
        return REGISTRATION_RETRY_MS;
    }
    if backend.xam_version() < REGISTRATION_ANY_STATE_VERSION
        && backend.execution_state() != crate::notify::ExecutionState::Started
    {
        return REGISTRATION_RETRY_MS;
    }
    state.console.registration_check = RegistrationCheck {
        address: address.record,
        tick: now,
    };
    if state.console.http_registration.object().is_empty() {
        state.console.http_registration.state = RegistrationState::Cleared;
        return REGISTRATION_IDLE_MS;
    }
    if address.record[..4] == [0; 4] {
        state.console.http_registration.state = RegistrationState::Failed;
        return REGISTRATION_PERIOD_MS;
    }
    match start_registration(state, backend) {
        Ok(()) => advance_registration(state, backend),
        Err(error) => {
            print(
                backend,
                format_args!("XBDM: Failed starting up HTTP registration task (err = {error})!\n"),
            );
            state.console.http_registration.state = RegistrationState::Failed;
            REGISTRATION_PERIOD_MS
        }
    }
}

/// `kiosk enabled=off|false` | `kiosk enabled=on|true id=<dword>`.
fn kiosk(invocation: &mut Invocation<'_>) -> Hresult {
    let mut buffer = [0u8; KIOSK_SWITCH_BUFFER];
    let Some(value) = string_param(invocation, "enabled", &mut buffer) else {
        return BAD_PARAMETER;
    };
    let (enable, id) = if equals_any(value, &["off", "false"]) {
        (false, 0)
    } else if equals_any(value, &["on", "true"]) {
        match invocation.line.param("id").and_then(|value| value.dword()) {
            Some(id) => (true, id),
            None => return BAD_PARAMETER,
        }
    } else {
        return BAD_PARAMETER;
    };
    if modify_config_flag(
        invocation.backend,
        USER_FLAGS_INDEX,
        USER_FLAG_KIOSK,
        enable,
    )
    .is_failure()
        || invocation
            .backend
            .xconfig_set(SETTING_KIOSK_ID, &id.to_be_bytes())
            .is_err()
    {
        return ACCESS_DENIED;
    }
    Hresult::OK
}

/// `livesigninrequired [enabled=on]`: any other value, or none, clears it.
fn live_signin_required(invocation: &mut Invocation<'_>) -> Hresult {
    let mut buffer = [0u8; SWITCH_BUFFER];
    let enable = string_param(invocation, "enabled", &mut buffer)
        .is_some_and(|value| value.eq_ignore_ascii_case(b"on"));
    let _ = modify_config_flag(
        invocation.backend,
        USER_FLAGS_INDEX,
        USER_FLAG_LIVE_SIGNIN_REQUIRED,
        enable,
    );
    Hresult::OK
}

/// `resetnetra`: the result of the request is ignored.
fn reset_network_ra(invocation: &mut Invocation<'_>) -> Hresult {
    let _ = invocation
        .backend
        .network_ra_request(NetworkRaRequest::Reset);
    Hresult::OK
}

/// `setconfig category=<dword> index=<dword> value=<dword>`.
fn set_config(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(category) = util::required_dword(invocation, "category") else {
        return util::MISSING;
    };
    let Some(index) = util::required_dword(invocation, "index") else {
        return util::MISSING;
    };
    let Some(value) = util::required_dword(invocation, "value") else {
        return util::MISSING;
    };
    let setting = ConfigSetting::new(category as u16, index as u16);
    if invocation
        .backend
        .xconfig_set(setting, &value.to_be_bytes())
        .is_err()
    {
        invocation.text.set_bytes(b"setvalue failed");
        return Hresult::FAIL;
    }
    Hresult::OK
}

/// `setretail and=<dword> or=<dword>`: masked update of setting (3, 0xc)
/// through kernel export 700 only.
fn set_retail(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(and_mask) = util::required_dword(invocation, "and") else {
        return util::MISSING;
    };
    let Some(or_mask) = util::required_dword(invocation, "or") else {
        return util::MISSING;
    };
    if let Err(status) = invocation
        .backend
        .xconfig_modify(SETTING_RETAIL_FLAGS, and_mask, or_mask)
    {
        invocation.set_text(format_args!("Modify failed: 0x{:08x}", status.0));
        return Hresult::FAIL;
    }
    Hresult::OK
}

/// `setserver none` | `setserver name=<string>`: store the network share
/// server and remap the share drive.
fn set_server(invocation: &mut Invocation<'_>) -> Hresult {
    let mut setting = [0u8; NETWORK_SHARE_SIZE];
    if !invocation.line.has("none") && string_param(invocation, "name", &mut setting).is_none() {
        invocation.text.set_bytes(b"missing server name");
        return Hresult::FAIL;
    }
    if invocation
        .backend
        .xconfig_set(SETTING_NETWORK_SHARE, &setting)
        .is_err()
    {
        invocation.text.set_bytes(b"save setting failed");
        return Hresult::FAIL;
    }
    refresh_network_share(invocation.state, invocation.backend);
    Hresult::OK
}

/// `systeminfo`: four lines. Stock sends uninitialized stack text on the
/// 202 line; an empty text gives the default `multiline response follows`.
fn system_info(invocation: &mut Invocation<'_>) -> Hresult {
    let info = invocation.backend.system_information();
    let test_kit = invocation.backend.is_test_kit();
    let Some(session) = invocation.session.as_deref_mut() else {
        return Hresult::FAIL;
    };
    session.receive_remaining = None;
    session.continuation = AnyContinuation::Console(Continuation::SystemInfo {
        next: SystemInfoLine::Disk,
        info,
        test_kit,
    });
    invocation.text.clear();
    Hresult::MULTILINE
}

fn platform_name(flags: u32) -> &'static str {
    match flags & 3 {
        0 => "Alpha",
        1 => "Mongrel",
        2 => "Shiva",
        _ => "Waternoose",
    }
}

fn system_name(flags: u32) -> &'static str {
    match flags >> 28 {
        0 => "Xenon",
        1 => "Zephyr",
        2 => "Falcon",
        3 => "Jasper",
        4 => "Trinity",
        5 => "Corona",
        6 => "Winchester",
        8 => "Ridgeway",
        _ => "Unknown",
    }
}

/// Hardware flag: a hard disk is attached.
const HARDWARE_HDD: u32 = 0x20;

fn system_info_line(
    next: &mut SystemInfoLine,
    info: &SystemInformation,
    test_kit: bool,
    line: &mut LineText,
) -> Hresult {
    line.clear();
    let flags = info.hardware_flags;
    let _ = match *next {
        SystemInfoLine::Disk => {
            *next = SystemInfoLine::KitType;
            line.write_str(if flags & HARDWARE_HDD != 0 {
                "HDD=Enabled"
            } else {
                "HDD=Disabled"
            })
        }
        SystemInfoLine::KitType => {
            *next = SystemInfoLine::Hardware;
            line.write_str(if test_kit {
                "Type=TestKit"
            } else {
                "Type=DevKit"
            })
        }
        SystemInfoLine::Hardware => {
            *next = SystemInfoLine::Versions;
            write!(
                line,
                "Platform={} System={}",
                platform_name(flags),
                system_name(flags)
            )
        }
        SystemInfoLine::Versions => {
            *next = SystemInfoLine::End;
            let (Version(base), Version(kernel), Version(xdk)) =
                (info.base_kernel, info.kernel, XDK_VERSION);
            write!(
                line,
                "BaseKrnl={}.{}.{}.{} Krnl={}.{}.{}.{} XDK={}.{}.{}.{}",
                base[0],
                base[1],
                base[2],
                base[3],
                kernel[0],
                kernel[1],
                kernel[2],
                kernel[3],
                xdk[0],
                xdk[1],
                xdk[2],
                xdk[3]
            )
        }
        SystemInfoLine::End => return Hresult::END_OF_DATA,
    };
    Hresult::OK
}

/// `verbose level=<dword>`: the parsed prefix is stored even when the value
/// is rejected.
fn verbose(invocation: &mut Invocation<'_>) -> Hresult {
    if let Some(value) = invocation.line.param("level") {
        invocation.state.console.trace_mask = TraceMask(value.dword_prefix());
        invocation
            .backend
            .publish(Published::TraceMask(invocation.state.console.trace_mask));
    }
    if util::required_dword(invocation, "level").is_none() {
        return util::MISSING;
    }
    crate::commands::system::save_settings(invocation.state, invocation.backend);
    Hresult::OK
}

/// Shared by `welcomedefault` and `welcomehide`: `off` or `false` sets the
/// bit, anything else clears it.
fn welcome_flag(invocation: &mut Invocation<'_>, mask: u32) -> Hresult {
    let mut buffer = [0u8; SWITCH_BUFFER];
    let disabled = string_param(invocation, "enabled", &mut buffer)
        .is_some_and(|value| equals_any(value, &["off", "false"]));
    let _ = modify_config_flag(invocation.backend, RETAIL_FLAGS_INDEX, mask, disabled);
    Hresult::OK
}

fn welcome_default(invocation: &mut Invocation<'_>) -> Hresult {
    welcome_flag(invocation, RETAIL_FLAG_WELCOME_DEFAULT)
}

fn welcome_hide(invocation: &mut Invocation<'_>) -> Hresult {
    welcome_flag(invocation, RETAIL_FLAG_WELCOME_HIDE)
}

fn monitor_version(invocation: &mut Invocation<'_>) -> Hresult {
    invocation.text.set_bytes(MONITOR_VERSION.as_bytes());
    Hresult::OK
}

/// `verbose level=%d` when the trace mask is nonzero.
pub(crate) fn verbose_settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let TraceMask(mask) = state.console.trace_mask;
    if mask != 0 {
        write_line(backend, file, format_args!("verbose level={}", mask as i32));
    }
}

/// `dbgname name=<name>` when a name is set. The name is not quoted, so a
/// name with a space loads back truncated at the space.
pub(crate) fn debug_name_settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let name = state.console.debug_name;
    if !name.as_bytes().is_empty() {
        write_text(backend, file, format_args!("dbgname name="));
        write_bytes(backend, file, name.as_bytes());
        end_line(backend, file);
    }
}

/// A settings line stock formats into one buffer and writes with one
/// WriteIniSz call, so the trace echoes it once.
type SettingsLine = crate::text::Text<0x400>;

/// `dumpsettings rpt=.. dst=.. fmt=..[ path=..]` (stock 0x91f2d5c0).
pub(crate) fn dump_settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let mut line = SettingsLine::new();
    let _ = line.write_str("dumpsettings ");
    state.console.dump_settings.write_summary(&mut |bytes| {
        let _ = line.push_bytes(bytes);
    });
    write_bytes(backend, file, line.as_bytes());
    end_line(backend, file);
}

/// `dumpmode <mode>` and `eventdefer set ` followed by ` <name>` per event
/// (stock 0x91f3ce50).
pub(crate) fn dump_mode_settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    write_line(
        backend,
        file,
        format_args!("dumpmode {}", state.console.dump_mode.name()),
    );
    let mut line = SettingsLine::new();
    let _ = line.write_str("eventdefer set ");
    for name in state.console.event_defer.names() {
        let _ = write!(line, " {name}");
    }
    write_bytes(backend, file, line.as_bytes());
    end_line(backend, file);
}

/// `httpreg server=%s object=%s port=%u`, or `httpreg clear` without an
/// object (stock 0x91f30c88).
pub(crate) fn httpreg_settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let registration = &state.console.http_registration;
    if registration.object().is_empty() {
        write_line(backend, file, format_args!("httpreg clear"));
        return;
    }
    let mut line = SettingsLine::new();
    let _ = line.write_str("httpreg server=");
    let _ = line.push_bytes(registration.server());
    let _ = line.write_str(" object=");
    let _ = line.push_bytes(registration.object());
    let _ = write!(line, " port={}", registration.port);
    write_bytes(backend, file, line.as_bytes());
    end_line(backend, file);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_name_copy_cuts_to_the_buffer() {
        let name = DebugName::new(b"kit");
        let mut buffer = [0xffu8; 5];
        assert_eq!(copy_debug_name(&name, &mut buffer), Hresult::OK);
        assert_eq!(buffer, *b"kit\0\xff");
        assert_eq!(copy_debug_name(&name, &mut buffer[..4]), Hresult::OK);
        assert_eq!(copy_debug_name(&name, &mut buffer[..3]), BUFFER_TOO_SMALL);
        assert_eq!(buffer[..3], *b"ki\0");
        assert_eq!(copy_debug_name(&name, &mut []), BUFFER_TOO_SMALL);
        assert_eq!(copy_debug_name(&DebugName::EMPTY, &mut []), Hresult::OK);
    }

    #[test]
    fn system_settings_store_keeps_only_the_video_standard_flag() {
        let mut settings = SystemSettings::default();
        settings.store(&[0, 0, 0, 0x10, 0, 0, 0, 3, 0, 0, 0, 5, 0xee]);
        assert_eq!(settings.0, [0, 0, 0, 0x10, 0, 0, 0, 1, 0, 0, 0, 5]);
        assert_eq!(settings.video_standard(), Some(5));
        settings.store(&[0, 0, 0, 8, 0, 0, 0, 2]);
        assert_eq!(settings.video_standard(), None);
        assert_eq!(settings.0[8..], [0, 0, 0, 5]);
        settings.set_video_standard(7);
        assert_eq!(settings.video_standard(), Some(7));
    }

    #[test]
    fn registration_response_follows_the_state() {
        let mut registration = RegistrationResult::EMPTY;
        let failed = |code| RegistrationResponse {
            result: Hresult::error(code),
            transaction: 0,
            length: 0,
        };
        for (state, code) in [
            (RegistrationState::Pending, 0x150),
            (RegistrationState::InProgress, 0x150),
            (RegistrationState::Cleared, 0x2),
            (RegistrationState::Failed, 0x100),
            (RegistrationState::Rejected, 0x10a),
            (RegistrationState::ResponseTooLarge, 0xf),
        ] {
            registration.state = state;
            assert_eq!(
                registration.export_response(Some(&mut [0; 8])),
                failed(code)
            );
        }
        registration.state = RegistrationState::Registered;
        registration.transaction = 0x0123_4567_89ab_cdef;
        registration.response[..3].copy_from_slice(b"abc");
        registration.response_len = 3;
        let registered = |result| RegistrationResponse {
            result,
            transaction: 0x0123_4567_89ab_cdef,
            length: 3,
        };
        let mut buffer = [0xffu8; 4];
        assert_eq!(
            registration.export_response(Some(&mut buffer)),
            registered(Hresult::OK)
        );
        assert_eq!(buffer, *b"abc\xff");
        assert_eq!(
            registration.export_response(Some(&mut buffer[..2])),
            registered(BUFFER_TOO_SMALL)
        );
        assert_eq!(registration.export_response(None), registered(Hresult::OK));
    }
}
