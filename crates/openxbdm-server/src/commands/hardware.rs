//! Hardware, input, and manufacturing control commands.

pub mod automation;
pub mod pgo;

use core::fmt::Write as _;

use openxbdm_core::line::Value;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::XbdmHresult;

use self::automation::AutomationError;
use self::automation::Gamepad;
use self::automation::QueueStatus;
use self::automation::UploadLayout;
use crate::access::Access;
use crate::commands::console;
use crate::commands::console::ConfigFlags;
use crate::commands::console::ConfigSetting;
use crate::commands::console::ConsoleConfigFlags;
use crate::commands::console::RetailFlags;
use crate::commands::console::UserFlags;
use crate::commands::util;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::ConnectionIndex;
use crate::invocation::Invocation;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::text::Text;

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry(
        "autoinput",
        Access::CONTROL,
        DispatchFlags::empty(),
        auto_input,
    ),
    entry("avatar", Access::CONTROL, DispatchFlags::empty(), avatar),
    entry(
        "bkgdmodetest",
        Access::CONTROL,
        DispatchFlags::empty(),
        background_mode_test,
    ),
    entry(
        "bootanim",
        Access::CONTROL,
        DispatchFlags::empty(),
        boot_animation,
    ),
    entry(
        "builtinmu",
        Access::CONTROL,
        DispatchFlags::empty(),
        built_in_memory_unit,
    ),
    entry(
        "enablewirelesscontrollers",
        Access::CONTROL,
        DispatchFlags::DEVKIT_ONLY,
        enable_wireless_controllers,
    ),
    entry(
        "irtsweep",
        Access::CONTROL,
        DispatchFlags::empty(),
        irt_sweep,
    ),
    entry(
        "kinecthsmsg",
        Access::CONTROL,
        DispatchFlags::empty(),
        kinect_health_message,
    ),
    entry(
        "mdetect",
        Access::CONTROL,
        DispatchFlags::empty(),
        motion_detection,
    ),
    entry("mixcmd", Access::READ, DispatchFlags::empty(), mix_command),
    entry(
        "mockcurrencyvalue",
        Access::CONTROL,
        DispatchFlags::DEVKIT_ONLY,
        mock_currency_value,
    ),
    entry(
        "oddlog",
        Access::CONTROL,
        DispatchFlags::empty(),
        optical_disc_log,
    ),
    entry(
        "playto",
        Access::empty(),
        DispatchFlags::DEVKIT_ONLY,
        play_to,
    ),
    entry(
        "pogoctrl",
        Access::CONTROL,
        DispatchFlags::empty(),
        pgo_control,
    ),
    entry(
        "runnuioobe",
        Access::CONTROL,
        DispatchFlags::empty(),
        run_nui_oobe,
    ),
    entry("runoobe", Access::CONTROL, DispatchFlags::empty(), run_oobe),
    entry(
        "runoobecheckpoint",
        Access::CONTROL,
        DispatchFlags::empty(),
        run_oobe_checkpoint,
    ),
    entry(
        "tdecomp",
        Access::empty(),
        DispatchFlags::empty(),
        title_decompression,
    ),
    entry(
        "usbportctrl",
        Access::CONFIG,
        DispatchFlags::empty(),
        usb_port_control,
    ),
];

const fn entry(
    name: &'static str,
    any_of: Access,
    flags: DispatchFlags,
    handler: fn(&mut Invocation<'_>) -> CommandResult,
) -> CommandEntry {
    CommandEntry::new(name, any_of, Access::empty(), flags, handler)
}

const BAD_PARAMETER: CommandError = CommandError::Status(ErrorCode::BadParameter);
const ACCESS_DENIED: CommandError = CommandError::Status(ErrorCode::AccessDenied);
const OUT_OF_MEMORY: CommandError = CommandError::Status(ErrorCode::OutOfMemory);
const UNKNOWN_COMMAND: CommandError = CommandError::Status(ErrorCode::UnknownCommand);
const MISSING_PARAMETER: CommandError = CommandError::Hardware(HardwareError::MissingParameter);
const SERVICE_FAILED: CommandError = CommandError::Hardware(HardwareError::ServiceFailed);
/// `400-` with no text.
const FAILED: CommandError = CommandError::Status(ErrorCode::Undefined);

/// Global state of this domain.
#[derive(Debug)]
pub struct State {
    /// Number used for the next default optical disc log file name.
    pub odd_log_index: u32,
}

impl State {
    pub const fn new() -> Self {
        Self { odd_log_index: 0 }
    }
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    /// `autoinput queuepackets`: the upload is stored by the backend.
    QueuePackets {
        user: u32,
        layout: UploadLayout,
        received: u32,
    },
    /// `autoinput setpacket`: one 12-byte gamepad state.
    SetPacket { user: u32 },
}

/// Test hook of the avatar system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvatarHook {
    /// Hook 0: delay applied to avatar asset loads.
    LoadAssetDelay(u32),
    /// Hook 8: delay applied to marketplace queries.
    QueryMarketplaceDelay(u32),
    /// Hook 7: change the avatar metadata.
    ChangeMetadata(u32),
    /// Hook 5: simulate an error.
    SimulateError { kind: u32, value: u32 },
}

impl AvatarHook {
    /// Index passed to the hook lookup.
    pub const fn index(self) -> u32 {
        match self {
            Self::LoadAssetDelay(_) => 0,
            Self::QueryMarketplaceDelay(_) => 8,
            Self::ChangeMetadata(_) => 7,
            Self::SimulateError { .. } => 5,
        }
    }
}

/// Failures of this domain without a status of the result table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareError {
    /// `424-`: no optical disc log is being written.
    NotLogging,
    /// `425-`: an optical disc log is being written.
    AlreadyLogging,
    /// `425-`: a PGO count block is allocated, so its settings are fixed.
    CountBlockAllocated,
    /// `437-`: a required `autoinput` parameter is missing.
    MissingParameter,
    /// `442-`: the virtual controller is absent or not connected.
    NotConnected,
    /// `400-` with no text: a monitor service call failed.
    ServiceFailed,
    /// A failed XAM call, passed through.
    Xam(XamError),
}

impl From<HardwareError> for Hresult {
    fn from(error: HardwareError) -> Self {
        match error {
            HardwareError::NotLogging => Hresult::NOT_STARTED,
            HardwareError::AlreadyLogging | HardwareError::CountBlockAllocated => {
                Hresult::ALREADY_STARTED
            }
            HardwareError::MissingParameter => Hresult::NO_SUCH_FIELD,
            HardwareError::NotConnected => Hresult::INVALID_STATE,
            HardwareError::ServiceFailed => Hresult::SERVICE_FAILED,
            HardwareError::Xam(error) => error.into(),
        }
    }
}

impl From<HardwareError> for CommandError {
    fn from(error: HardwareError) -> Self {
        Self::Hardware(error)
    }
}

/// A failed XAM or system service call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XamError {
    /// `E_FAIL`; also reported when the export is absent.
    Fail,
    InvalidArgument,
    Other(UnlistedXamResult),
}

/// A failure result without an [`XamError`] variant. Only
/// [`XamError::check`] creates it, so equal errors have equal variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnlistedXamResult(Hresult);

impl XamError {
    /// `Ok` for a success result of a XAM call, the failure otherwise.
    pub fn check(result: Hresult) -> Result<(), Self> {
        match result {
            _ if !result.is_failure() => Ok(()),
            Hresult::FAIL => Err(Self::Fail),
            Hresult::INVALID_ARGUMENT => Err(Self::InvalidArgument),
            other => Err(Self::Other(UnlistedXamResult(other))),
        }
    }
}

impl From<XamError> for Hresult {
    fn from(error: XamError) -> Self {
        match error {
            XamError::Fail => Hresult::FAIL,
            XamError::InvalidArgument => Hresult::INVALID_ARGUMENT,
            XamError::Other(UnlistedXamResult(result)) => result,
        }
    }
}

impl From<XamError> for CommandError {
    fn from(error: XamError) -> Self {
        Self::Hardware(HardwareError::Xam(error))
    }
}

/// Why an avatar hook could not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvatarError {
    /// The hook lookup failed.
    Lookup(XamError),
    /// The lookup returned no function.
    NoFunction,
    /// The hook failed.
    Hook(XamError),
}

impl From<AvatarError> for CommandError {
    fn from(error: AvatarError) -> Self {
        match error {
            AvatarError::Lookup(error) | AvatarError::Hook(error) => error.into(),
            AvatarError::NoFunction => ACCESS_DENIED,
        }
    }
}

/// Who receives controller input, as reported by the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOwner {
    Title,
    System,
}

/// A kernel or system export the command needs is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportMissing;

/// State reported by the media service's PlayTo query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlayToState {
    pub xmp_heap: u32,
    pub play_to: u32,
}

/// Request sent to the media service by `playto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayToCommand {
    /// Command 0: `set` with a value not starting with `0`.
    Enable,
    /// Command 1: `set` with a value starting with `0`.
    Disable,
    /// Command 2: `show`.
    Show,
}

impl PlayToCommand {
    pub const fn code(self) -> u32 {
        match self {
            Self::Enable => 0,
            Self::Disable => 1,
            Self::Show => 2,
        }
    }
}

/// IPv4 addresses of the title and debug network stacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StackAddresses {
    pub title: [u8; 4],
    pub debug: [u8; 4],
}

/// Why the optical disc log did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OddLogStartError {
    /// A log is already being written.
    Busy,
    /// The log file or writer thread could not be created.
    Failed(KernelError),
}

impl From<OddLogStartError> for CommandError {
    fn from(error: OddLogStartError) -> Self {
        match error {
            OddLogStartError::Busy => HardwareError::AlreadyLogging.into(),
            OddLogStartError::Failed(error) => {
                Self::from_kernel(error, Self::Status(ErrorCode::FileCannotBeCreated))
            }
        }
    }
}

/// Result of the start service (export 147).
impl From<OddLogStartError> for Hresult {
    fn from(error: OddLogStartError) -> Self {
        CommandError::from(error).into()
    }
}

/// No optical disc log is being written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OddLogNotRunning;

impl From<OddLogNotRunning> for CommandError {
    fn from(OddLogNotRunning: OddLogNotRunning) -> Self {
        HardwareError::NotLogging.into()
    }
}

/// Result of the stop service (export 148).
impl From<OddLogNotRunning> for Hresult {
    fn from(error: OddLogNotRunning) -> Self {
        CommandError::from(error).into()
    }
}

/// Selection of instrumented modules for `pogoctrl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgoModule {
    All,
    /// Address of an instrumented-module record.
    Record(u32),
}

impl PgoModule {
    /// Record address 0 selects every module.
    pub fn from_value(value: u32) -> Self {
        if value == 0 {
            Self::All
        } else {
            Self::Record(value)
        }
    }
}

/// Why a `pogoctrl` request or PGO export failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgoError {
    /// The module record is not registered.
    NoSuchModule,
    /// The module's count block is allocated; its settings are fixed.
    Busy,
}

impl From<PgoError> for CommandError {
    fn from(error: PgoError) -> Self {
        match error {
            PgoError::NoSuchModule => BAD_PARAMETER,
            PgoError::Busy => HardwareError::CountBlockAllocated.into(),
        }
    }
}

/// Result of the PGO exports 108 to 110.
impl From<PgoError> for Hresult {
    fn from(error: PgoError) -> Self {
        CommandError::from(error).into()
    }
}

/// Application of a system service message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemApp(pub u32);

impl SystemApp {
    pub const MARKETPLACE: Self = Self(0xfe);
}

/// Message of a system service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemMessage(pub u32);

impl SystemMessage {
    /// Mock currency setting of the marketplace service.
    pub const MOCK_CURRENCY: Self = Self(0x23100);
}

/// Identifier of a XAM heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XamHeapId(pub u32);

/// Information class of the XAM heap information export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XamHeapInfoClass {
    Name = 1,
    Limits = 2,
    Usage = 3,
}

impl XamHeapInfoClass {
    pub const fn code(self) -> u32 {
        self as u32
    }
}

/// Output block of a sized XAM heap information class.
#[derive(Debug)]
pub enum XamHeapBlock<'a> {
    Usage(&'a mut [u8; 0x18]),
    Limits(&'a mut [u8; 0x1c]),
}

impl<'a> XamHeapBlock<'a> {
    /// The information class and the block with its first dword set to
    /// the block size, as the export expects.
    pub fn sized(self) -> (XamHeapInfoClass, &'a mut [u8]) {
        match self {
            Self::Usage(block) => {
                block[..4].copy_from_slice(&0x18u32.to_be_bytes());
                (XamHeapInfoClass::Usage, &mut block[..])
            }
            Self::Limits(block) => {
                block[..4].copy_from_slice(&0x1cu32.to_be_bytes());
                (XamHeapInfoClass::Limits, &mut block[..])
            }
        }
    }
}

/// USB host controller number of `usbportctrl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbController(pub u32);

/// Port number on a USB host controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbPort(pub u32);

/// Platform services this domain needs.
pub trait Backend {
    fn automation_connect(&mut self, user: u32) -> Result<(), AutomationError>;
    fn automation_disconnect(&mut self, user: u32) -> Result<(), AutomationError>;
    /// Install a virtual controller with a queue of `queue_length` entries
    /// and bind it to the input system.
    fn automation_bind(&mut self, user: u32, queue_length: u32) -> Result<(), AutomationError>;
    fn automation_unbind(&mut self, user: u32) -> Result<(), AutomationError>;
    fn automation_clear_queue(&mut self, user: u32) -> Result<(), AutomationError>;
    fn automation_query_queue(&mut self, user: u32) -> Result<QueueStatus, AutomationError>;
    fn automation_set_packet(&mut self, user: u32, packet: Gamepad) -> Result<(), AutomationError>;
    /// Allocate the `queuepackets` upload buffer of a connection, replacing
    /// any previous one. `false` when the allocation fails.
    fn automation_begin_upload(&mut self, connection: ConnectionIndex, size: u32) -> bool;
    /// Store uploaded bytes at `offset` of the connection's upload buffer.
    fn automation_upload(&mut self, connection: ConnectionIndex, offset: u32, bytes: &[u8]);
    /// Release the connection's upload buffer without queueing it.
    fn automation_discard_upload(&mut self, connection: ConnectionIndex);
    /// Queue the uploaded packets and release the upload buffer. Returns
    /// the number of entries accepted.
    fn automation_queue_upload(
        &mut self,
        connection: ConnectionIndex,
        user: u32,
        layout: UploadLayout,
    ) -> Result<u32, AutomationError>;
    /// Query the system's input focus for `user` (export 166 passes the
    /// user to the XAM query unchecked).
    fn automation_input_owner(&mut self, user: u32) -> Result<InputOwner, ExportMissing>;

    /// Whether the avatar test hook lookup export is present.
    fn avatar_hooks_available(&mut self) -> bool;
    fn avatar_hook(&mut self, hook: AvatarHook) -> Result<(), AvatarError>;

    /// Switch the wireless controller radio on or off.
    fn set_wireless_radio(&mut self, enabled: bool) -> Result<(), KernelError>;

    /// Monitor service 8: fill the devkit memory statistics block whose
    /// header is already set.
    fn devkit_memory_statistics(&mut self, block: &mut [u8; 0x90]) -> Result<(), KernelError>;
    /// Resolve the XAM heap count export.
    fn xam_heap_count_available(&mut self) -> bool;
    /// Resolve the XAM heap information export.
    fn xam_heap_info_available(&mut self) -> bool;
    /// Fill the heap count block whose size dword is already set.
    fn xam_heap_count(&mut self, block: &mut [u8; 12]) -> Result<(), XamError>;
    /// Information class [`XamHeapInfoClass::Name`]: the heap name.
    fn xam_heap_name(&mut self, id: XamHeapId, name: &mut [u8; 0x20]) -> Result<(), XamError>;
    /// Information class of `block` into it.
    fn xam_heap_info(&mut self, id: XamHeapId, block: XamHeapBlock<'_>) -> Result<(), XamError>;

    /// Send the 0x14-byte mock currency setting to the marketplace service
    /// without completion notification.
    fn mock_currency(&mut self, setting: &mut [u8; 0x14]) -> Result<(), XamError>;
    /// Media service message 0x900002.
    fn play_to(&mut self, command: PlayToCommand) -> Result<PlayToState, XamError>;
    fn stack_addresses(&mut self) -> StackAddresses;

    /// Start writing the optical disc log to the object path `path`, or
    /// report the path translation failure as the writer's file status.
    fn odd_log_start(&mut self, path: Result<&[u8], KernelError>) -> Result<(), OddLogStartError>;
    /// Stop the optical disc log and wait for its writer.
    fn odd_log_stop(&mut self) -> Result<(), OddLogNotRunning>;

    fn pgo_start(&mut self, module: PgoModule) -> Result<(), PgoError>;
    fn pgo_stop(&mut self, module: PgoModule) -> Result<(), PgoError>;
    /// Write a profile for each selected module, named by `phase`.
    fn pgo_snapshot(
        &mut self,
        phase: &[u8],
        reset: bool,
        module: PgoModule,
    ) -> Result<(), PgoError>;
    fn pgo_set_allocation_scale(&mut self, module: PgoModule, scale: u32) -> Result<(), PgoError>;

    /// Store the title decompression GDF attribute mode.
    fn set_ignore_gdf_attributes(&mut self, ignore: bool);
    fn ignore_gdf_attributes(&mut self) -> bool;

    /// Resolve the USB port power export.
    fn usb_port_power_available(&mut self) -> bool;
    fn set_usb_port_power(
        &mut self,
        controller: UsbController,
        port: UsbPort,
        enable: bool,
    ) -> Result<(), KernelError>;
}

pub(crate) fn resume(
    continuation: &mut Continuation,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    match *continuation {
        Continuation::QueuePackets {
            user,
            layout,
            ref mut received,
        } => queue_packets_resume(user, layout, received, cx),
        Continuation::SetPacket { user } => set_packet_resume(user, cx),
    }
}

fn automation_result(result: Result<(), AutomationError>) -> CommandResult {
    result?;
    Ok(Reply::Ok)
}

/// `autoinput user=<dword> <subcommand>`: drive the virtual controller of
/// a user slot.
fn auto_input(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(user) = util::required_dword(invocation, "user") else {
        return Err(MISSING_PARAMETER);
    };
    let line = invocation.line;
    if line.has("connect") {
        return automation_result(invocation.backend.automation_connect(user));
    }
    if line.has("disconnect") {
        return automation_result(invocation.backend.automation_disconnect(user));
    }
    if line.has("bind") {
        let Some(queue_length) = util::required_dword(invocation, "queuelen") else {
            return Err(MISSING_PARAMETER);
        };
        return automation_result(invocation.backend.automation_bind(user, queue_length));
    }
    if line.has("unbind") {
        return automation_result(invocation.backend.automation_unbind(user));
    }
    if line.has("queuepackets") {
        return queue_packets(invocation, user);
    }
    if line.has("clearqueue") {
        return automation_result(invocation.backend.automation_clear_queue(user));
    }
    if line.has("queryqueue") {
        let status = invocation.backend.automation_query_queue(user)?;
        invocation.set_text(format_args!(
            "nQueue=0x{:08x}, nPacket=0x{:08x}, t_remain_ms=0x{:08x}, t_remain_count=0x{:08x}",
            status.queue_length, status.queued, status.remaining_ms, status.remaining_count
        ));
        return Ok(Reply::Ok);
    }
    if line.has("setpacket") {
        let Some(session) = invocation.session.as_deref_mut() else {
            return Err(CommandError::Fail);
        };
        session.continuation = AnyContinuation::Hardware(Continuation::SetPacket { user });
        session.receive_remaining = Some(Gamepad::WIRE_SIZE as u32);
        return Ok(Reply::SendBinary);
    }
    if line.has("process") {
        let owner = invocation
            .backend
            .automation_input_owner(user)
            .map_err(|ExportMissing| UNKNOWN_COMMAND)?;
        invocation.text.set_bytes(match owner {
            InputOwner::System => b"system",
            InputOwner::Title => b"title",
        });
    }
    Ok(Reply::Ok)
}

fn queue_packets(invocation: &mut Invocation<'_>, user: u32) -> CommandResult {
    let Some(count) = util::required_dword(invocation, "count") else {
        return Err(MISSING_PARAMETER);
    };
    let layout = UploadLayout {
        count,
        times: invocation.line.has("timearray"),
        counts: invocation.line.has("countarray"),
    };
    let Some(session) = invocation.session.as_deref_mut() else {
        return Err(CommandError::Fail);
    };
    // The monitor computes the size in 32 bits; a size that does not fit
    // would overrun its buffer, so it is refused as an allocation failure.
    let Some(size) = layout.size() else {
        return Err(OUT_OF_MEMORY);
    };
    if !invocation
        .backend
        .automation_begin_upload(session.index(), size)
    {
        return Err(OUT_OF_MEMORY);
    }
    session.continuation = AnyContinuation::Hardware(Continuation::QueuePackets {
        user,
        layout,
        received: 0,
    });
    session.receive_remaining = Some(size);
    Ok(Reply::SendBinary)
}

fn queue_packets_resume(
    user: u32,
    layout: UploadLayout,
    received: &mut u32,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    let connection = cx.session.index();
    if cx.received.is_empty() {
        cx.session.receive_remaining = Some(0);
        cx.backend.automation_discard_upload(connection);
        return Err(FAILED);
    }
    cx.backend
        .automation_upload(connection, *received, cx.received);
    *received += cx.received.len() as u32;
    let remaining = cx.session.receive_remaining.unwrap_or(0) - cx.received.len() as u32;
    cx.session.receive_remaining = Some(remaining);
    if remaining != 0 {
        return Ok(Reply::Ok);
    }
    let accepted = cx
        .backend
        .automation_queue_upload(connection, user, layout)?;
    let _ = write!(cx.line, "queued=0x{accepted:08x}");
    Ok(Reply::Ok)
}

fn set_packet_resume(user: u32, cx: &mut ContinuationContext<'_>) -> CommandResult {
    cx.session.receive_remaining = Some(0);
    let Ok(bytes) = <&[u8; Gamepad::WIRE_SIZE]>::try_from(cx.received) else {
        return Err(FAILED);
    };
    automation_result(
        cx.backend
            .automation_set_packet(user, Gamepad::from_wire(bytes)),
    )
}

/// `avatar`: run one avatar system test hook.
fn avatar(invocation: &mut Invocation<'_>) -> CommandResult {
    if !invocation.backend.avatar_hooks_available() {
        return Ok(Reply::Ok);
    }
    let clamp = |value: u32| (value as i32).max(0) as u32;
    let hook = if let Some(value) = invocation.line.dword("loadassetdelay") {
        AvatarHook::LoadAssetDelay(clamp(value))
    } else if let Some(value) = invocation.line.dword("querymarketplacedelay") {
        AvatarHook::QueryMarketplaceDelay(clamp(value))
    } else if let Some(value) = invocation.line.dword("changemetadata") {
        AvatarHook::ChangeMetadata(value)
    } else if let (Some(kind), Some(value)) = (
        invocation.line.dword("simulateerrortype"),
        invocation.line.dword("simulateerrorvalue"),
    ) {
        if kind >= 1 {
            return Err(CommandError::Fail);
        }
        AvatarHook::SimulateError { kind, value }
    } else {
        return Ok(Reply::Ok);
    };
    invocation.backend.avatar_hook(hook)?;
    Ok(Reply::Ok)
}

/// `enable` or `disable`: whether the `enable` form was given.
fn enable_flag(invocation: &mut Invocation<'_>) -> Option<bool> {
    if invocation.line.has("enable") {
        Some(true)
    } else if invocation.line.has("disable") {
        Some(false)
    } else {
        invocation.text.set_bytes(b"missing arguments");
        None
    }
}

/// Replace `mask` in a 4-byte configuration setting with `bits`.
fn update_setting(
    invocation: &mut Invocation<'_>,
    setting: ConfigSetting,
    mask: u32,
    bits: u32,
) -> CommandResult {
    let mut value = [0u8; 4];
    invocation
        .backend
        .xconfig_get(setting, &mut value)
        .and_then(|_| {
            let new = (u32::from_be_bytes(value) & !mask) | bits;
            invocation.backend.xconfig_set(setting, &new.to_be_bytes())
        })
        .map_err(|error| CommandError::from_kernel(error, CommandError::Unexpected))?;
    Ok(Reply::Ok)
}

fn background_mode_test(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(enable) = enable_flag(invocation) else {
        return Err(CommandError::Fail);
    };
    let bits = if enable {
        UserFlags::BACKGROUND_MODE_TEST.bits()
    } else {
        0
    };
    update_setting(
        invocation,
        UserFlags::SETTING,
        UserFlags::BACKGROUND_MODE_TEST.bits(),
        bits,
    )
}

fn built_in_memory_unit(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(enable) = enable_flag(invocation) else {
        return Err(CommandError::Fail);
    };
    let disabled = ConsoleConfigFlags::BUILT_IN_MEMORY_UNIT_DISABLED.bits();
    let bits = if enable { 0 } else { disabled };
    update_setting(invocation, ConfigSetting::CONSOLE_FLAGS, disabled, bits)
}

/// Whether `enabled=` is `off` or `false`, compared over the first
/// `capacity - 1` characters as the monitor copies them.
fn enabled_is_off(invocation: &Invocation<'_>, capacity: usize) -> bool {
    let mut buffer = [0u8; 0x20];
    invocation.line.param("enabled").is_some_and(|value| {
        let text = value.copy_into(&mut buffer[..capacity]);
        text.eq_ignore_ascii_case(b"off") || text.eq_ignore_ascii_case(b"false")
    })
}

/// Commands that set a configuration flag when `enabled` is `off` or
/// `false` copy the value into a 10-byte buffer.
const SHORT_VALUE: usize = 10;

/// The flag update result is discarded by every caller.
fn set_flag(invocation: &mut Invocation<'_>, flags: impl ConfigFlags, set: bool) -> CommandResult {
    let _ = console::modify_config_flag(invocation.backend, flags, set);
    Ok(Reply::Ok)
}

fn boot_animation(invocation: &mut Invocation<'_>) -> CommandResult {
    let off = enabled_is_off(invocation, SHORT_VALUE);
    set_flag(invocation, UserFlags::BOOT_ANIMATION_DISABLED, off)
}

fn kinect_health_message(invocation: &mut Invocation<'_>) -> CommandResult {
    let off = invocation.line.has("off");
    set_flag(invocation, UserFlags::KINECT_HEALTH_MESSAGE_DISABLED, off)
}

fn motion_detection(invocation: &mut Invocation<'_>) -> CommandResult {
    let off = enabled_is_off(invocation, SHORT_VALUE);
    set_flag(invocation, UserFlags::MOTION_DETECTION_DISABLED, off)
}

fn run_nui_oobe(invocation: &mut Invocation<'_>) -> CommandResult {
    let off = enabled_is_off(invocation, SHORT_VALUE);
    set_flag(invocation, RetailFlags::NUI_OOBE_DISABLED, off)
}

fn run_oobe(invocation: &mut Invocation<'_>) -> CommandResult {
    let off = enabled_is_off(invocation, SHORT_VALUE);
    set_flag(invocation, RetailFlags::OOBE_DISABLED, off)
}

fn run_oobe_checkpoint(invocation: &mut Invocation<'_>) -> CommandResult {
    let off = enabled_is_off(invocation, SHORT_VALUE);
    set_flag(invocation, RetailFlags::OOBE_CHECKPOINT_DISABLED, off)
}

/// Value buffer of `enabled=` for commands that accept on and off.
const LONG_VALUE: usize = 0x20;

/// `enabled=` as on (`on`, `true`) or off (`off`, `false`); `None` when
/// absent or anything else.
fn on_off(value: &[u8]) -> Option<bool> {
    if value.eq_ignore_ascii_case(b"off") || value.eq_ignore_ascii_case(b"false") {
        Some(false)
    } else if value.eq_ignore_ascii_case(b"on") || value.eq_ignore_ascii_case(b"true") {
        Some(true)
    } else {
        None
    }
}

fn debug_print(invocation: &mut Invocation<'_>, arguments: core::fmt::Arguments<'_>) {
    let mut message = Text::<0x100>::new();
    let _ = message.write_fmt(arguments);
    invocation.backend.debug_print(message.as_bytes());
}

fn enable_wireless_controllers(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut buffer = [0u8; LONG_VALUE];
    let Some(value) = invocation.line.param("enabled") else {
        return Err(BAD_PARAMETER);
    };
    let value = value.copy_into(&mut buffer);
    let length = value.len();
    let text = &buffer[..length];
    debug_print(
        invocation,
        format_args!(
            "[xbdm] EnableWirelessControllers, enabled={}\n",
            text.escape_ascii()
        ),
    );
    let Some(enable) = on_off(text) else {
        return Err(BAD_PARAMETER);
    };
    if invocation.backend.set_wireless_radio(enable).is_err() {
        return Err(ACCESS_DENIED);
    }
    let setting = UserFlags::SETTING;
    let mut stored = [0u8; 4];
    if invocation.backend.xconfig_get(setting, &mut stored) == Ok(4) {
        let old = u32::from_be_bytes(stored);
        let disabled = UserFlags::WIRELESS_CONTROLLERS_DISABLED.bits();
        let new = if enable {
            old & !disabled
        } else {
            old | disabled
        };
        if let Err(error) = invocation.backend.xconfig_set(setting, &new.to_be_bytes()) {
            debug_print(
                invocation,
                format_args!(
                    "[xbdm] EnableWirelessControllers, enabled={} ExSetXConfigSetting failed {:X}\n",
                    text.escape_ascii(),
                    NtStatus::from(error).0
                ),
            );
        }
    }
    Ok(Reply::Ok)
}

/// `irtsweep`: always fails with a fixed status.
fn irt_sweep(invocation: &mut Invocation<'_>) -> CommandResult {
    invocation.set_text(format_args!(
        "error status 0x{:08x}",
        NtStatus::from(KernelError::NotImplemented).0
    ));
    Err(FAILED)
}

/// Offset of the `mixcmd` subcommand: the monitor assumes `mixcmd ` precedes it.
const MIX_SUBCOMMAND: usize = 7;
/// Offset of the separator after `xamheap`.
const MIX_HEAP_SEPARATOR: usize = 14;
const MIX_HEAP_ID_DIGITS: usize = 8;

fn buffer_byte(buffer: &[u8], offset: usize) -> u8 {
    buffer.get(offset).copied().unwrap_or(0)
}

/// The NUL-terminated text at `offset` of the receive buffer.
fn buffer_text(buffer: &[u8], offset: usize) -> &[u8] {
    console::c_string(buffer.get(offset..).unwrap_or(&[]))
}

/// `mixcmd`: memory statistics passed through as hex. The subcommand is
/// read at a fixed offset of the receive buffer, as the monitor does.
fn mix_command(invocation: &mut Invocation<'_>) -> CommandResult {
    let buffer = invocation.buffer;
    let subcommand = buffer_text(buffer, MIX_SUBCOMMAND);
    if subcommand == b"querystats" {
        let mut block = [0u8; 0x90];
        block[0..4].copy_from_slice(&0x90u32.to_be_bytes());
        block[4..8].copy_from_slice(&0x68u32.to_be_bytes());
        if let Err(error) = invocation.backend.devkit_memory_statistics(&mut block) {
            debug_print(
                invocation,
                format_args!(
                    "WRN[MIX]: DMSVC_GET_DEVKIT_MEMORY_STATISTICS failed status 0x{:08X}\n",
                    NtStatus::from(error).0
                ),
            );
            return Err(SERVICE_FAILED);
        }
        invocation.text.set_bytes(b"OK querystats ");
        let _ = invocation.text.push_hex_upper(&block);
        return Ok(Reply::Ok);
    }
    if subcommand == b"countxamheaps" {
        if !invocation.backend.xam_heap_count_available() {
            return Err(ACCESS_DENIED);
        }
        let mut block = [0u8; 12];
        block[0..4].copy_from_slice(&12u32.to_be_bytes());
        if let Err(error) = invocation.backend.xam_heap_count(&mut block) {
            debug_print(
                invocation,
                format_args!(
                    "WRN[MIX]: XampHeapGetCount failed hr 0x{:08X}\n",
                    Hresult::from(error).0
                ),
            );
            return Err(SERVICE_FAILED);
        }
        let system = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        let cooperative = u32::from_be_bytes([block[8], block[9], block[10], block[11]]);
        invocation.set_text(format_args!(
            "OK countxamheaps System={system:08X} Coop={cooperative:08X}"
        ));
        return Ok(Reply::Ok);
    }
    if buffer.get(MIX_SUBCOMMAND..MIX_HEAP_SEPARATOR) == Some(b"xamheap".as_slice()) {
        return mix_xam_heap(invocation);
    }
    Ok(Reply::Ok)
}

fn mix_xam_heap(invocation: &mut Invocation<'_>) -> CommandResult {
    if !invocation.backend.xam_heap_info_available() {
        return Err(ACCESS_DENIED);
    }
    let buffer = invocation.buffer;
    // The monitor traps when no space follows `xamheap`; that is reported
    // as a malformed id instead.
    if buffer_byte(buffer, MIX_HEAP_SEPARATOR) != b' ' {
        return Err(BAD_PARAMETER);
    }
    let mut id = 0u32;
    for index in 0..MIX_HEAP_ID_DIGITS {
        let byte = buffer_byte(buffer, MIX_HEAP_SEPARATOR + 1 + index);
        if byte == 0 || byte == b' ' {
            break;
        }
        let Some(digit) = (byte as char).to_digit(16) else {
            debug_print(
                invocation,
                format_args!("WRN[MIX]: Unsupported id char '{}'\n", byte as char),
            );
            return Err(BAD_PARAMETER);
        };
        id = (id << 4) | digit;
    }
    let mut name = [0u8; 0x20];
    let mut usage = [0u8; 0x18];
    let mut limits = [0u8; 0x1c];
    let id = XamHeapId(id);
    for class in [
        XamHeapInfoClass::Name,
        XamHeapInfoClass::Usage,
        XamHeapInfoClass::Limits,
    ] {
        let result = match class {
            XamHeapInfoClass::Name => invocation.backend.xam_heap_name(id, &mut name),
            XamHeapInfoClass::Usage => invocation
                .backend
                .xam_heap_info(id, XamHeapBlock::Usage(&mut usage)),
            XamHeapInfoClass::Limits => invocation
                .backend
                .xam_heap_info(id, XamHeapBlock::Limits(&mut limits)),
        };
        if let Err(error) = result {
            if error != XamError::Fail {
                debug_print(
                    invocation,
                    format_args!(
                        "WRN[MIX]: XampHeapGetInfo for id {:X} info {} failed hr 0x{:08X}\n",
                        id.0,
                        class.code(),
                        Hresult::from(error).0
                    ),
                );
            }
            return Err(SERVICE_FAILED);
        }
    }
    invocation.text.set_bytes(b"OK xamheap Name=");
    let _ = invocation.text.push_bytes(console::c_string(&name));
    let _ = invocation.text.push_bytes(b" Data=");
    let _ = invocation.text.push_hex_upper(&usage);
    let _ = invocation.text.push_hex_upper(&limits);
    Ok(Reply::Ok)
}

/// `mockcurrencyvalue`: send a mock currency setting to the marketplace
/// service. Only the service's invalid-argument result counts as success.
fn mock_currency_value(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut buffer = [0u8; LONG_VALUE];
    let Some(value) = invocation.line.param("enabled") else {
        return Err(BAD_PARAMETER);
    };
    let mut message = [0u8; 0x14];
    match on_off(value.copy_into(&mut buffer)) {
        Some(true) => {
            let Some(amount) = invocation.line.dword("value") else {
                return Err(BAD_PARAMETER);
            };
            message[0..4].copy_from_slice(&1u32.to_be_bytes());
            message[4..8].copy_from_slice(&amount.to_be_bytes());
        }
        Some(false) => {}
        None => return Err(BAD_PARAMETER),
    }
    let result = invocation.backend.mock_currency(&mut message);
    match result {
        Err(XamError::InvalidArgument) => Ok(Reply::Ok),
        Ok(()) | Err(_) => Err(ACCESS_DENIED),
    }
}

/// Size of the optical disc log file name buffer.
const ODD_LOG_NAME: usize = 0x104;

fn optical_disc_log(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.line.has("stop") {
        invocation.backend.odd_log_stop()?;
        invocation.text.set_bytes(b"stopped logging");
        return Ok(Reply::Ok);
    }
    let mut name = Text::<{ ODD_LOG_NAME - 1 }>::new();
    match invocation.line.param("file") {
        Some(value) => {
            let mut buffer = [0u8; ODD_LOG_NAME];
            name.set_bytes(value.copy_into(&mut buffer));
        }
        None => {
            let index = invocation.state.hardware.odd_log_index;
            invocation.state.hardware.odd_log_index = index.wrapping_add(1);
            let _ = write!(name, "devkit:\\OpticalDiscLog_{}.txt", index as i32);
        }
    }
    let path = invocation
        .state
        .filesystem
        .drives
        .translate(invocation.backend, name.as_bytes());
    let path = path
        .as_ref()
        .map(|path| path.as_bytes())
        .ok_or(KernelError::NoSuchFile);
    invocation.backend.odd_log_start(path)?;
    invocation.text.set_bytes(b"Logging to '");
    let _ = invocation.text.push_bytes(name.as_bytes());
    let _ = invocation.text.push_bytes(b"'");
    Ok(Reply::Ok)
}

/// `playto set enable=<value>` or `playto show`.
fn play_to(invocation: &mut Invocation<'_>) -> CommandResult {
    let command = if invocation.line.has("set") {
        match invocation
            .line
            .param("enable")
            .map(|value| value.bytes().next())
        {
            Some(first) => {
                if first == Some(b'0') {
                    PlayToCommand::Disable
                } else {
                    PlayToCommand::Enable
                }
            }
            None => return invalid_play_to(invocation),
        }
    } else if invocation.line.has("show") {
        PlayToCommand::Show
    } else {
        return invalid_play_to(invocation);
    };
    let Ok(state) = invocation.backend.play_to(command) else {
        return invalid_play_to(invocation);
    };
    let addresses = invocation.backend.stack_addresses();
    let on_off = |value: u32| if value != 0 { "ON" } else { "OFF" };
    let [t0, t1, t2, t3] = addresses.title;
    let [d0, d1, d2, d3] = addresses.debug;
    invocation.set_text(format_args!(
        "XMP_HEAP: {}, PlayTo: {} [T:{t0}.{t1}.{t2}.{t3} / D:{d0}.{d1}.{d2}.{d3}]",
        on_off(state.xmp_heap),
        on_off(state.play_to)
    ));
    Ok(Reply::Ok)
}

fn invalid_play_to(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line.as_bytes();
    invocation.text.set_bytes(b"Invalid parameter: ");
    let _ = invocation.text.push_bytes(line);
    Err(BAD_PARAMETER)
}

/// A `pogoctrl` dword parameter. The monitor stores the digits it parsed
/// even when the getter reports the parameter as malformed, and leaves the
/// variable uninitialized when the parameter is absent; absent is read as
/// 0, which selects every module.
fn pgo_dword(invocation: &Invocation<'_>, name: &str) -> u32 {
    invocation
        .line
        .param(name)
        .map_or(0, |value: Value<'_>| value.dword_prefix())
}

/// Size of the `phase` name buffer.
const PGO_PHASE: usize = 0x141;

fn pgo_control(invocation: &mut Invocation<'_>) -> CommandResult {
    let result = if invocation.line.has("start") {
        invocation
            .backend
            .pgo_start(PgoModule::from_value(pgo_dword(invocation, "module")))
    } else if invocation.line.has("stop") {
        invocation
            .backend
            .pgo_stop(PgoModule::from_value(pgo_dword(invocation, "module")))
    } else if invocation.line.has("snapshot") {
        let mut buffer = [0u8; PGO_PHASE];
        let phase_length = invocation
            .line
            .param("phase")
            .map_or(0, |value| value.copy_into(&mut buffer).len());
        let reset = pgo_dword(invocation, "reset") != 0;
        let module = PgoModule::from_value(pgo_dword(invocation, "module"));
        invocation
            .backend
            .pgo_snapshot(&buffer[..phase_length], reset, module)
    } else if invocation.line.has("allocscale") {
        let module = PgoModule::from_value(pgo_dword(invocation, "module"));
        let scale = pgo_dword(invocation, "scale");
        invocation.backend.pgo_set_allocation_scale(module, scale)
    } else {
        invocation.set_text(format_args!("HRESULT 0x{:08x}", Hresult::from(FAILED).0));
        return Err(FAILED);
    };
    let result = result.map(|()| Reply::Ok).map_err(CommandError::from);
    invocation.set_text(format_args!("HRESULT 0x{:08x}", reply::hresult(result).0));
    result
}

/// `tdecomp`: select whether title decompression ignores GDF attributes.
fn title_decompression(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.line.has("UseGDFAttrib") {
        invocation.backend.set_ignore_gdf_attributes(false);
    } else if invocation.line.has("IgnoreGDFAttrib") {
        invocation.backend.set_ignore_gdf_attributes(true);
    }
    let text: &[u8] = if invocation.backend.ignore_gdf_attributes() {
        b"IgnoreGDFAttrib"
    } else {
        b"NoGDFAttrib"
    };
    invocation.text.set_bytes(text);
    Ok(Reply::Ok)
}

/// `usbportctrl controller=<dword> port=<dword> (enable | disable)`.
fn usb_port_control(invocation: &mut Invocation<'_>) -> CommandResult {
    if !invocation.backend.usb_port_power_available() {
        return Err(ACCESS_DENIED);
    }
    let (Some(controller), Some(port)) = (
        invocation.line.dword("controller"),
        invocation.line.dword("port"),
    ) else {
        return Err(BAD_PARAMETER);
    };
    let enable = if invocation.line.has("enable") {
        true
    } else if invocation.line.has("disable") {
        false
    } else {
        return Err(BAD_PARAMETER);
    };
    invocation
        .backend
        .set_usb_port_power(UsbController(controller), UsbPort(port), enable)
        .map_err(CommandError::Kernel)?;
    Ok(Reply::Ok)
}
