//! Console identity and configuration commands.

mod config;
mod debug_name;
mod dump;
mod error;
mod network_ra;
mod network_share;
mod registration;
mod system_info;
mod system_settings;
mod trace;

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::KernelError;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::HardwareGeneration;

use self::config::set_config;
use self::config::set_retail;
use self::debug_name::debug_name;
use self::debug_name::persist_debug_name;
use self::dump::dump_mode;
use self::dump::dump_settings;
use self::dump::set_dump_mode;
use self::network_ra::configure_network_ra;
use self::network_ra::reset_network_ra;
use self::network_share::set_server;
use self::registration::http_registration;
use self::system_info::system_info;
use self::system_info::system_info_line;
use self::trace::verbose;
use crate::access::Access;
use crate::backend::Backend as AnyBackend;
use crate::commands::system::RebootKind;
use crate::commands::system::SettingsFile;
use crate::commands::system::end_line;
use crate::commands::system::write_bytes;
use crate::commands::system::write_line;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::text::LineText;

pub use self::config::ConfigFlags;
pub use self::config::ConfigSetting;
pub use self::config::ConsoleConfigFlags;
pub use self::config::RetailFlags;
pub use self::config::UserFlags;
pub use self::config::modify_config_flag;
pub use self::debug_name::DEBUG_NAME_CAPACITY;
pub use self::debug_name::DebugName;
pub use self::debug_name::copy_debug_name;
pub(crate) use self::debug_name::debug_name_settings_lines;
pub use self::dump::DUMP_SETTINGS_SIZE;
pub use self::dump::DumpMode;
pub use self::dump::DumpSettings;
pub(crate) use self::dump::dump_settings_lines;
pub use self::error::BufferTooSmall;
pub use self::error::ConsoleError;
pub use self::error::NetworkRaError;
pub use self::error::RegistrationError;
pub use self::network_ra::NetworkRaFlags;
pub use self::network_ra::NetworkRaRecord;
pub use self::network_ra::NetworkRaRequest;
pub(crate) use self::network_share::refresh_network_share;
pub use self::registration::HttpFailure;
pub use self::registration::HttpProgress;
pub use self::registration::HttpRegistration;
pub use self::registration::HttpRequest;
pub use self::registration::HttpStartFailure;
pub use self::registration::HttpStartStage;
pub use self::registration::REGISTRATION_RESPONSE_CAPACITY;
pub use self::registration::REGISTRATION_USER_AGENT;
pub use self::registration::RegistrationCheck;
pub use self::registration::RegistrationResponse;
pub use self::registration::RegistrationResult;
pub use self::registration::RegistrationState;
pub(crate) use self::registration::httpreg_settings_lines;
pub(crate) use self::registration::ini_httpreg;
pub(crate) use self::registration::poll_registration;
pub(crate) use self::registration::title_terminated;
pub use self::system_info::SystemInfoLine;
pub use self::system_info::SystemInformation;
pub use self::system_info::Version;
pub use self::system_info::XDK_VERSION;
pub use self::system_settings::SYSTEM_SETTINGS_SIZE;
pub use self::system_settings::SystemSettings;
pub(crate) use self::system_settings::ini_sysset;
pub(crate) use self::system_settings::sysset_settings_lines;
pub(crate) use self::trace::MessageText;
pub use self::trace::TraceMask;
pub(crate) use self::trace::trace;
pub(crate) use self::trace::trace_text;
pub(crate) use self::trace::verbose_settings_lines;

/// Monitor version reported by `dmversion`.
pub const MONITOR_VERSION: &str = "2.0.21256.0";

/// Bytes of the SMC I2C settings block that holds the debug name.
pub const SETTINGS_BLOCK_SIZE: usize = 0x20;

/// Bytes of a network address record (`XNADDR`).
pub const NETWORK_ADDRESS_SIZE: usize = 0x24;

/// Characters of a console identifier string.
pub const CONSOLE_ID_LENGTH: usize = 12;

/// Value buffer of the on/off string parameters.
const SWITCH_BUFFER: usize = 10;

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry(
        "altaddr",
        Access::CONTROL,
        DispatchFlags::empty(),
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
        DispatchFlags::empty(),
        console_features,
    ),
    entry(
        "consolemem",
        Access::CONTROL,
        DispatchFlags::empty(),
        console_memory_command,
    ),
    entry(
        "consoletype",
        Access::CONTROL,
        DispatchFlags::empty(),
        console_type,
    ),
    entry(
        "datacentermode",
        Access::CONTROL,
        DispatchFlags::empty(),
        data_center_mode,
    ),
    entry(
        "dbgname",
        Access::empty(),
        DispatchFlags::empty(),
        debug_name,
    ),
    entry(
        "debugmemsize",
        Access::CONTROL,
        DispatchFlags::empty(),
        debug_memory_size,
    ),
    entry(
        "debugmode",
        Access::empty(),
        DispatchFlags::empty(),
        debug_mode,
    ),
    entry(
        "discoverable",
        Access::CONTROL,
        DispatchFlags::empty(),
        discoverable,
    ),
    entry(
        "dmversion",
        Access::CONTROL,
        DispatchFlags::empty(),
        monitor_version,
    ),
    entry(
        "dumpmode",
        Access::CONFIG,
        DispatchFlags::empty(),
        dump_mode,
    ),
    entry(
        "dumpsettings",
        Access::CONFIG,
        DispatchFlags::empty(),
        dump_settings,
    ),
    entry(
        "eventdefer",
        Access::CONFIG,
        DispatchFlags::empty(),
        event_defer,
    ),
    entry("feature", Access::CONTROL, DispatchFlags::empty(), feature),
    entry(
        "getconsoleid",
        Access::CONTROL,
        DispatchFlags::empty(),
        console_id,
    ),
    entry(
        "getnetaddrs",
        Access::READ,
        DispatchFlags::empty(),
        network_addresses,
    ),
    entry(
        "httpreg",
        Access::MANAGE,
        DispatchFlags::empty(),
        http_registration,
    ),
    entry("kiosk", Access::CONTROL, DispatchFlags::DEVKIT_ONLY, kiosk),
    entry(
        "livesigninrequired",
        Access::CONTROL,
        DispatchFlags::empty(),
        live_signin_required,
    ),
    entry(
        "resetnetra",
        Access::CONTROL,
        DispatchFlags::DEVKIT_ONLY,
        reset_network_ra,
    ),
    entry(
        "setconfig",
        Access::CONFIG,
        DispatchFlags::empty(),
        set_config,
    ),
    entry(
        "setretail",
        Access::WRITE,
        DispatchFlags::DEVKIT_ONLY,
        set_retail,
    ),
    entry(
        "setserver",
        Access::MANAGE,
        DispatchFlags::empty(),
        set_server,
    ),
    entry(
        "systeminfo",
        Access::READ,
        DispatchFlags::empty(),
        system_info,
    ),
    entry("verbose", Access::CONFIG, DispatchFlags::empty(), verbose),
    entry(
        "welcomedefault",
        Access::CONTROL,
        DispatchFlags::empty(),
        welcome_default,
    ),
    entry(
        "welcomehide",
        Access::CONTROL,
        DispatchFlags::empty(),
        welcome_hide,
    ),
];

/// A settings line stock formats into one buffer and writes with one
/// WriteIniSz call, so the trace echoes it once.
type SettingsLine = crate::text::Text<0x400>;

xbox360_sys::flags! {
    /// Notifications queued to the server thread rather than delivered
    /// inline.
    pub struct EventDeferMask(u32) {
        BREAK = 0x1,
        DEBUG_STRING = 0x2,
        SINGLE_STEP = 0x4,
        ASSERT = 0x8,
        NT_ASSERT = 0x10,
        DATA_BREAK = 0x20,
        RIP = 0x40,
    }
}

impl EventDeferMask {
    /// Reply and parameter names, indexed by bit number.
    const NAMES: [&'static str; 7] = [
        "break",
        "debugstring",
        "singlestep",
        "assert",
        "ntassert",
        "databreak",
        "rip",
    ];

    pub const DEFAULT: Self = Self::BREAK
        .union(Self::DEBUG_STRING)
        .union(Self::SINGLE_STEP)
        .union(Self::DATA_BREAK);

    fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .iter()
            .enumerate()
            .filter(move |(bit, _)| self.0 & (1 << bit) != 0)
            .map(|(_, name)| *name)
    }
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
            trace_mask: TraceMask::empty(),
            dump_mode: DumpMode::Smart,
            dump_settings: DumpSettings::new(),
            event_defer: EventDeferMask::DEFAULT,
            http_registration: HttpRegistration::EMPTY,
            registration_check: RegistrationCheck::EMPTY,
        }
    }
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

/// Platform services this domain needs.
pub trait Backend {
    fn kit_features(&mut self) -> KitFeatures;
    /// Read a configuration setting into `output`; returns the stored length.
    fn xconfig_get(
        &mut self,
        setting: ConfigSetting,
        output: &mut [u8],
    ) -> Result<usize, KernelError>;
    fn xconfig_set(&mut self, setting: ConfigSetting, value: &[u8]) -> Result<(), KernelError>;
    /// Kernel export 700: replace a 4-byte setting with
    /// `(old & and_mask) | or_mask`. [`KernelError::OrdinalNotFound`] when
    /// the export is absent.
    fn xconfig_modify(
        &mut self,
        setting: ConfigSetting,
        and_mask: u32,
        or_mask: u32,
    ) -> Result<(), KernelError>;
    /// Read the SMC I2C settings block; `None` when the read fails.
    fn read_settings_block(&mut self) -> Option<[u8; SETTINGS_BLOCK_SIZE]>;
    /// Write the SMC I2C settings block; false when the write fails.
    fn write_settings_block(&mut self, block: &[u8; SETTINGS_BLOCK_SIZE]) -> bool;
    /// Kernel memory statistics; `None` when the query fails.
    fn memory_statistics(&mut self) -> Option<MemoryStatistics>;
    fn system_information(&mut self) -> SystemInformation;
    fn console_id(&mut self) -> Result<ConsoleId, KernelError>;
    fn debug_network_address(&mut self) -> NetworkAddress;
    fn title_network_address(&mut self) -> NetworkAddress;
    /// Apply the inactivity auto-shutoff configuration.
    fn apply_inactivity_time(&mut self);
    fn network_ra_request(&mut self, request: NetworkRaRequest<'_>) -> Result<(), NetworkRaError>;
    /// Whether the system UI library exports its feature switch (ordinal 515).
    fn feature_switch_present(&mut self) -> bool;
    fn set_feature(&mut self, enable: u32, feature: u32);
    /// Load the network file system client image.
    fn load_network_client(&mut self) -> Result<(), KernelError>;
    /// Millisecond tick count.
    fn tick_milliseconds(&mut self) -> u32;
    /// Version of the system software (XAM).
    fn xam_version(&mut self) -> u32;
    /// Start a registration request.
    fn http_begin(&mut self, request: &HttpRequest<'_>) -> Result<(), HttpStartFailure>;
    /// Advance the request. On completion the backend keeps the body until
    /// the next request starts and publishes it with
    /// [`Published::Registration`] through [`RegistrationResult::new`].
    fn http_poll(&mut self) -> HttpProgress;
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

/// Stock 0x91f50088 (export 214), shared with `consolemem` and
/// `addtitlemem`.
pub fn console_memory(backend: &mut dyn AnyBackend) -> ConsoleMemory {
    ConsoleMemory::of(backend.kit_features(), || backend.memory_statistics())
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

/// Stock 0x91f4e648: whether the I2C settings block can be read.
pub(crate) fn settings_block_readable(backend: &mut dyn AnyBackend) -> bool {
    /// Reads of the settings block before it counts as unreadable.
    const SETTINGS_BLOCK_READS: usize = 3;

    (0..SETTINGS_BLOCK_READS).any(|_| backend.read_settings_block().is_some())
}

/// Whether hardware `flags` describe a console from Trinity on.
pub(crate) fn trinity_or_later(flags: HardwareFlags) -> bool {
    flags.generation() >= HardwareGeneration::TRINITY
}

/// Stock 0x91f329f0, after the settings files when `drivemap internal` is
/// off: a console from Trinity on whose I2C settings block cannot be read
/// is a test kit. When the dword at +0x10 of the flash block at 0x80 is
/// nonzero, it is cleared and the console restarts.
pub(crate) fn check_settings_block(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    /// Flash block inspected, and the dword in it that is cleared.
    const FLASH_BLOCK_OFFSET: u32 = 0x80;
    const FLASH_BLOCK_SIZE: usize = 0x80;
    const FLASH_BLOCK_CLEARED: core::ops::Range<usize> = 0x10..0x14;

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

pub(crate) fn resume(
    continuation: &mut Continuation,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    match continuation {
        Continuation::SystemInfo {
            next,
            info,
            test_kit,
        } => system_info_line(next, info, *test_kit, cx.line),
    }
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
            let mask = EventDeferMask::from_bits_retain(mask);
            state.console.event_defer = mask;
            backend.publish(Published::EventDefer(mask));
        }
    }

    crate::commands::system::save_settings(state, backend);

    if let ExportedSetting::DebugName(name) = setting {
        persist_debug_name(backend, name.as_bytes());
    }
}

const fn entry(
    name: &'static str,
    any_of: Access,
    flags: DispatchFlags,
    handler: fn(&mut Invocation<'_>) -> CommandResult,
) -> CommandEntry {
    CommandEntry::new(name, any_of, Access::empty(), flags, handler)
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

/// Bytes before the first NUL, as a `%s` argument prints them.
#[inline(never)]
pub(crate) fn c_string(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());

    &bytes[..end]
}

/// `altaddr`: the title IPv4 address; fails while the address is pending.
fn alternate_address(invocation: &mut Invocation<'_>) -> CommandResult {
    let address = invocation.backend.title_network_address();
    if address.status <= 1 {
        return Err(CommandError::Fail);
    }

    let [first, second, third, fourth, ..] = address.record;
    invocation.set_text(format_args!(
        "addr=0x{:08x}",
        u32::from_be_bytes([first, second, third, fourth])
    ));

    Ok(Reply::Ok)
}

/// `autoshutoff timeout=<hours>`: 0, 1 or 6 hours; stored in minutes with
/// bit 15 set.
fn auto_shutoff(invocation: &mut Invocation<'_>) -> CommandResult {
    let value = invocation.line.param("timeout");
    let hours = value.map_or(0, |value| value.dword_prefix());
    let result = match value.and_then(|value| value.dword()) {
        None => Err(ErrorCode::Undefined.into()),
        Some(0 | 1 | 6) => {
            let minutes = ((hours * 60) as u16) | 0x8000;
            if invocation
                .backend
                .xconfig_set(ConfigSetting::AUTO_SHUTOFF, &minutes.to_be_bytes())
                .is_ok()
            {
                invocation.backend.apply_inactivity_time();
                Ok(Reply::Ok)
            } else {
                Err(ErrorCode::Undefined.into())
            }
        }
        Some(_) => Err(ErrorCode::BadParameter.into()),
    };

    let mut message = LineText::new();
    let _ = writeln!(
        message,
        "[xbdm] AutoShutoff, timeout={hours} hr:0x{:08X}",
        crate::reply::hresult(result).0
    );
    invocation.backend.debug_print(message.as_bytes());

    result
}

/// `consolefeatures`: each feature name is appended with a leading space.
fn console_features(invocation: &mut Invocation<'_>) -> CommandResult {
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

    Ok(Reply::Ok)
}

fn console_memory_command(invocation: &mut Invocation<'_>) -> CommandResult {
    let memory = console_memory(invocation.backend);
    invocation.set_text(format_args!("consolemem=0x{:x}", memory.value()));

    Ok(Reply::Ok)
}

/// `consoletype`: stock reports only these two kit types.
fn console_type(invocation: &mut Invocation<'_>) -> CommandResult {
    let kind: &[u8] = if invocation.backend.is_test_kit() {
        b"testkit"
    } else {
        b"devkit"
    };

    invocation.text.set_bytes(kind);

    Ok(Reply::Ok)
}

/// `datacentermode [enabled=on|true]`: any other value, or none, disables.
fn data_center_mode(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut buffer = [0u8; SWITCH_BUFFER];
    let enable = string_param(invocation, "enabled", &mut buffer)
        .is_some_and(|value| equals_any(value, &["on", "true"]));
    let _ = modify_config_flag(invocation.backend, UserFlags::DATA_CENTER, enable);

    Ok(Reply::Ok)
}

/// `debugmemsize`: bits 8..20 of debug monitor memory statistic 0x70.
fn debug_memory_size(invocation: &mut Invocation<'_>) -> CommandResult {
    // A failed query reports 0, as stock does.
    let size = invocation
        .backend
        .memory_statistics()
        .map_or(0, |statistics| statistics.debug_memory_size());
    invocation.set_text(format_args!("debugmemsize=0x{size:x}"));

    Ok(Reply::Ok)
}

/// `debugmode`: gated by a stock global (0x91fab9a8) that nothing sets, so
/// the command is always unknown.
fn debug_mode(_invocation: &mut Invocation<'_>) -> CommandResult {
    Err(ErrorCode::UnknownCommand.into())
}

/// `discoverable enabled=on|true|off|false`; the write result is ignored.
fn discoverable(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut buffer = [0u8; SWITCH_BUFFER];
    let value = match string_param(invocation, "enabled", &mut buffer) {
        Some(value) if equals_any(value, &["on", "true"]) => 1u8,
        Some(value) if equals_any(value, &["off", "false"]) => 0,
        _ => return Err(ErrorCode::BadParameter.into()),
    };

    let _ = invocation
        .backend
        .xconfig_set(ConfigSetting::DISCOVERABLE, &[value]);

    Ok(Reply::Ok)
}

/// `eventdefer [set [break] [debugstring] ...]`: `set` replaces the mask
/// with the named events. Replies with a leading space before each name.
fn event_defer(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.line.has("set") {
        let mut mask = EventDeferMask::empty();
        for (bit, name) in EventDeferMask::NAMES.iter().enumerate() {
            if invocation.line.has(name) {
                mask.insert(EventDeferMask::from_bits_retain(1 << bit));
            }
        }

        invocation.state.console.event_defer = mask;
        invocation.backend.publish(Published::EventDefer(mask));
        crate::commands::system::save_settings(invocation.state, invocation.backend);
    }

    invocation.text.clear();

    for name in invocation.state.console.event_defer.names() {
        let _ = invocation.text.push_bytes(b" ");
        let _ = invocation.text.push_bytes(name.as_bytes());
    }

    Ok(Reply::Ok)
}

/// `feature enable=<dword> feature=<dword>`: forwarded to the system UI
/// library; without that export the command does nothing.
fn feature(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(ErrorCode::BadParameter.into());
    }

    if !invocation.backend.feature_switch_present() {
        return Ok(Reply::Ok);
    }

    let Some(enable) = invocation.line.dword("enable") else {
        invocation.text.set_bytes(b"'enable' not specified");
        return Err(ErrorCode::BadParameter.into());
    };

    let Some(feature) = invocation.line.dword("feature") else {
        invocation.text.set_bytes(b"'feature' not specified");
        return Err(ErrorCode::BadParameter.into());
    };

    invocation.backend.set_feature(enable, feature);

    Ok(Reply::Ok)
}

/// `getconsoleid`: a failed read returns the status with bit 28 set.
fn console_id(invocation: &mut Invocation<'_>) -> CommandResult {
    match invocation.backend.console_id() {
        Ok(ConsoleId(id)) => {
            let length = c_string(&id).len();
            invocation.text.clear();
            let _ = invocation.text.push_bytes(b"consoleid=");
            let _ = invocation.text.push_bytes(&id[..length]);
            Ok(Reply::Ok)
        }
        Err(error) => Err(CommandError::Kernel(error)),
    }
}

/// `getnetaddrs`: debug name and both address records in hex.
fn network_addresses(invocation: &mut Invocation<'_>) -> CommandResult {
    let debug = invocation.backend.debug_network_address();
    let title = invocation.backend.title_network_address();
    if debug.status == 0 || title.status == 0 {
        invocation.set_text(format_args!(
            "debugstatus=0x{:08x} titlestatus=0x{:08x}",
            debug.status, title.status
        ));
        return Err(ConsoleError::AddressPending.into());
    }

    let name = invocation.state.console.debug_name;
    invocation.text.clear();
    let _ = invocation.text.push_bytes(b"name=");
    let _ = invocation.text.push_bytes(name.as_bytes());
    let _ = invocation.text.push_bytes(b" debug=");
    let _ = invocation.text.push_hex_upper(&debug.record);
    let _ = invocation.text.push_bytes(b" title=");
    let _ = invocation.text.push_hex_upper(&title.record);

    Ok(Reply::Ok)
}

/// `kiosk enabled=off|false` | `kiosk enabled=on|true id=<dword>`.
fn kiosk(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Value buffer of the `enabled=` parameter.
    const KIOSK_SWITCH_BUFFER: usize = 0x20;

    let mut buffer = [0u8; KIOSK_SWITCH_BUFFER];
    let Some(value) = string_param(invocation, "enabled", &mut buffer) else {
        return Err(ErrorCode::BadParameter.into());
    };

    let (enable, id) = if equals_any(value, &["off", "false"]) {
        (false, 0)
    } else if equals_any(value, &["on", "true"]) {
        match invocation.line.dword("id") {
            Some(id) => (true, id),
            None => return Err(ErrorCode::BadParameter.into()),
        }
    } else {
        return Err(ErrorCode::BadParameter.into());
    };

    if modify_config_flag(invocation.backend, UserFlags::KIOSK, enable).is_err()
        || invocation
            .backend
            .xconfig_set(ConfigSetting::KIOSK_ID, &id.to_be_bytes())
            .is_err()
    {
        return Err(ErrorCode::AccessDenied.into());
    }

    Ok(Reply::Ok)
}

/// `livesigninrequired [enabled=on]`: any other value, or none, clears it.
fn live_signin_required(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut buffer = [0u8; SWITCH_BUFFER];
    let enable = string_param(invocation, "enabled", &mut buffer)
        .is_some_and(|value| value.eq_ignore_ascii_case(b"on"));
    let _ = modify_config_flag(invocation.backend, UserFlags::LIVE_SIGNIN_REQUIRED, enable);

    Ok(Reply::Ok)
}

/// Shared by `welcomedefault` and `welcomehide`: `off` or `false` sets the
/// bit, anything else clears it.
fn welcome_flag(invocation: &mut Invocation<'_>, flag: RetailFlags) -> CommandResult {
    let mut buffer = [0u8; SWITCH_BUFFER];
    let disabled = string_param(invocation, "enabled", &mut buffer)
        .is_some_and(|value| equals_any(value, &["off", "false"]));
    let _ = modify_config_flag(invocation.backend, flag, disabled);

    Ok(Reply::Ok)
}

fn welcome_default(invocation: &mut Invocation<'_>) -> CommandResult {
    welcome_flag(invocation, RetailFlags::WELCOME_DEFAULT)
}

fn welcome_hide(invocation: &mut Invocation<'_>) -> CommandResult {
    welcome_flag(invocation, RetailFlags::WELCOME_HIDE)
}

fn monitor_version(invocation: &mut Invocation<'_>) -> CommandResult {
    invocation.text.set_bytes(MONITOR_VERSION.as_bytes());

    Ok(Reply::Ok)
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
