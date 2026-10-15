//! IPTV configuration and content integrity verification (CIV) commands.

use openxbdm_core::line::Value;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;

use crate::access::Access;
use crate::commands::console;
use crate::commands::console::ConfigSetting;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry("civfail", DispatchFlags::NONE, civ_fail),
    entry("civinject", DispatchFlags::OWN_THREAD, civ_inject),
    entry("civsetbits", DispatchFlags::DEVKIT_ONLY, civ_set_bits),
    entry("civstart", DispatchFlags::OWN_THREAD, civ_start),
    entry("civstatus", DispatchFlags::NONE, civ_status),
    entry("civstop", DispatchFlags::OWN_THREAD, civ_stop),
    entry("civverify", DispatchFlags::OWN_THREAD, civ_verify),
    entry("iptv", DispatchFlags::NONE, iptv),
    entry(
        "iptvallowuninstall",
        DispatchFlags::NONE,
        iptv_allow_uninstall,
    ),
    entry("iptvbootstrapurl", DispatchFlags::NONE, iptv_bootstrap_url),
    entry("iptvdvr", DispatchFlags::NONE, iptv_dvr),
    entry("iptvprovidername", DispatchFlags::NONE, iptv_provider_name),
    entry(
        "iptvprovisioningurl",
        DispatchFlags::NONE,
        iptv_provisioning_url,
    ),
    entry("iptvsupportinfo", DispatchFlags::NONE, iptv_support_info),
];

const fn entry(
    name: &'static str,
    flags: DispatchFlags,
    handler: crate::registry::Handler,
) -> CommandEntry {
    CommandEntry {
        name,
        any_of: Access::CONTROL,
        all_of: Access::NONE,
        flags,
        handler,
    }
}

/// Global state of this domain.
#[derive(Debug)]
pub struct State {}

impl State {
    pub const fn new() -> Self {
        Self {}
    }
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {}

/// Handle of a thread created for `civfail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadHandle(pub u32);

/// A thread last-error value (Win32 error code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastError(pub u32);

impl LastError {
    /// The procedure is not exported by the module.
    pub const PROC_NOT_FOUND: Self = Self(0x7f);
}

/// Value a CIV service call reports: the service's return value, or a
/// last-error value when the service cannot be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivResult(pub u32);

/// Bit index into the kernel's 64-bit security detection mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionBit(pub u32);

/// Kernel exports `civsetbits` resolves, in resolution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionRoutine {
    SetDetected,
    GetDetected,
    Initialize,
    SaveSettings,
}

impl DetectionRoutine {
    pub const ORDER: [Self; 4] = [
        Self::SetDetected,
        Self::GetDetected,
        Self::Initialize,
        Self::SaveSettings,
    ];

    /// Kernel export ordinal.
    pub const fn ordinal(self) -> u32 {
        match self {
            Self::SetDetected => 0x295,
            Self::GetDetected => 0x296,
            Self::Initialize => 0x292,
            Self::SaveSettings => 0x294,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::SetDetected => "SET_DETECTED",
            Self::GetDetected => "GET_DETECTED",
            Self::Initialize => "INITIALIZE",
            Self::SaveSettings => "SAVE_SETTINGS",
        }
    }
}

/// A detection routine could not be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionRoutineMissing {
    pub routine: DetectionRoutine,
    pub status: NtStatus,
}

/// Outcome of a `civsetbits` update. Masks are the low 32 bits of the
/// 64-bit detection mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionUpdate {
    /// Status of the set request, or of the last export resolution when no
    /// bit was requested.
    pub result: u32,
    pub old_mask: u32,
    pub new_mask: u32,
}

/// Content verification counters reported by `civstatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CivProgress {
    pub failed_reads: u32,
    pub failed_hashes: u32,
    pub blocks_checked: u32,
    pub total_blocks: u32,
    pub completed: bool,
}

/// Console configuration flag word (category 3) the IPTV switches live in.
pub const IPTV_FLAGS_SETTING: u16 = 0xc;

/// Bits of the IPTV flag word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IptvFlags(pub u32);

impl IptvFlags {
    pub const ENABLED: Self = Self(0x1000);
    pub const DVR: Self = Self(0x0008_0000);
    /// Set when uninstalling IPTV is not allowed.
    pub const UNINSTALL_BLOCKED: Self = Self(0x0200_0000);
}

/// IPTV configuration strings (category 9). Values are stored as
/// big-endian UTF-16 units in a zero-filled buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IptvString {
    ProviderName,
    ProvisioningUrl,
    SupportInfo,
    BootstrapUrl,
}

/// Largest IPTV string buffer in bytes.
pub const IPTV_STRING_CAPACITY: usize = 0x80;

impl IptvString {
    /// The category 9 configuration setting.
    pub const fn setting(self) -> ConfigSetting {
        ConfigSetting::new(
            9,
            match self {
                Self::ProviderName => 1,
                Self::ProvisioningUrl => 2,
                Self::SupportInfo => 3,
                Self::BootstrapUrl => 4,
            },
        )
    }

    /// Size of the stored buffer in bytes.
    pub const fn size(self) -> usize {
        match self {
            Self::ProviderName => 0x78,
            _ => IPTV_STRING_CAPACITY,
        }
    }

    /// Fixed line offset of the value: the command word plus one byte.
    const fn line_offset(self) -> usize {
        match self {
            Self::ProviderName | Self::BootstrapUrl => 0x11,
            Self::ProvisioningUrl => 0x14,
            Self::SupportInfo => 0x10,
        }
    }
}

/// Platform services this domain needs.
pub trait Backend {
    /// Create a system thread that reports a content integrity failure
    /// (XAM 0x9c0 with 0xff) and then, if `reboot`, returns to firmware
    /// with routine 1. Failure yields the thread's last-error value.
    fn start_civ_failure_thread(&mut self, reboot: bool) -> Result<ThreadHandle, LastError>;
    /// XAM 0x9bf(hash_errors, read_errors) when resolvable.
    fn inject_civ_errors(&mut self, hash_errors: u32, read_errors: u32);
    /// Read the detection mask, reinitialize and save the security state,
    /// set `bit` when given, and read the mask again.
    fn update_civ_detection(
        &mut self,
        bit: Option<DetectionBit>,
    ) -> Result<DetectionUpdate, DetectionRoutineMissing>;
    /// XAM 0x9bb(thread_id).
    fn create_civ_process(&mut self, thread_id: u32) -> CivResult;
    /// XAM 0x9bc() when resolvable.
    fn close_civ_process(&mut self);
    /// XAM 0x9bd(milliseconds, 0, 0).
    fn verify_civ(&mut self, milliseconds: u32) -> CivResult;
    /// XAM 0x9be with a 0x18-byte record; a nonzero return is the error.
    fn civ_progress(&mut self) -> Result<CivProgress, CivResult>;
}

pub(crate) fn resume(
    continuation: &mut Continuation,
    _cx: &mut ContinuationContext<'_>,
) -> Hresult {
    match *continuation {}
}

/// Highest process slot `civstart` passes.
const CIV_THREAD_ID_LIMIT: u32 = 5;
/// Verification budget used for non-positive values other than -1.
const CIV_DEFAULT_MILLISECONDS: u32 = 0x100;

/// A dword parameter as the monitor's getter stores it: the parsed prefix
/// whenever the parameter is present, whether or not it is well formed.
/// Absent parameters write `missing <name>` into the reply text.
fn stored_dword(invocation: &mut Invocation<'_>, name: &str) -> Option<u32> {
    let value = invocation.line.param(name);
    if value.is_none_or(|value| value.dword().is_none()) {
        invocation.set_text(format_args!("missing {name}"));
    }
    value.map(|value| value.dword_prefix())
}

/// A dword parameter the handler uses only when well formed.
fn checked_dword(invocation: &mut Invocation<'_>, name: &str) -> Option<u32> {
    let value = invocation.line.param(name).and_then(|value| value.dword());
    if value.is_none() {
        invocation.set_text(format_args!("missing {name}"));
    }
    value
}

/// `civfail [reboot=<dword>]`. The thread handle is not closed.
fn civ_fail(invocation: &mut Invocation<'_>) -> Hresult {
    // The stack variable starts at zero.
    let reboot = stored_dword(invocation, "reboot").unwrap_or(0) != 0;
    match invocation.backend.start_civ_failure_thread(reboot) {
        Ok(handle) => invocation.set_text(format_args!("Thread created: 0x{:08X}", handle.0)),
        Err(error) => invocation.set_text(format_args!("CreateThread failed 0x{:x}", error.0)),
    }
    Hresult::OK
}

/// `civinject readerrors=<dword> hasherrors=<dword>`: absent counts are 0;
/// the text names the last missing parameter.
fn civ_inject(invocation: &mut Invocation<'_>) -> Hresult {
    let read_errors = checked_dword(invocation, "readerrors").unwrap_or(0);
    let hash_errors = checked_dword(invocation, "hasherrors").unwrap_or(0);
    invocation
        .backend
        .inject_civ_errors(hash_errors, read_errors);
    Hresult::OK
}

/// `civsetbits on=<dword>`: `on` is a detection bit index; zero sets none.
fn civ_set_bits(invocation: &mut Invocation<'_>) -> Hresult {
    // Stock reads an uninitialized stack variable when `on` is absent; no
    // bit is set here.
    let bit = stored_dword(invocation, "on")
        .filter(|&on| on != 0)
        .map(DetectionBit);
    let update = match invocation.backend.update_civ_detection(bit) {
        Ok(update) => update,
        Err(missing) => {
            invocation.set_text(format_args!(
                "Cannot load ordinal {} ({}): 0x{:x}\n",
                missing.routine.ordinal(),
                missing.routine.name(),
                missing.status.0
            ));
            invocation.backend.debug_print(invocation.text.as_bytes());
            DetectionUpdate {
                result: missing.status.0,
                old_mask: 0xbaad_f00d,
                new_mask: 0xdead_beef,
            }
        }
    };
    invocation.set_text(format_args!(
        "Result 0x{:x}; old mask 0x{:x}, new mask 0x{:x}",
        update.result, update.old_mask, update.new_mask
    ));
    Hresult::OK
}

/// `civstart threadid=<dword>`: the id is clamped to 5.
fn civ_start(invocation: &mut Invocation<'_>) -> Hresult {
    let thread_id = stored_dword(invocation, "threadid")
        .unwrap_or(0)
        .min(CIV_THREAD_ID_LIMIT);
    let result = invocation.backend.create_civ_process(thread_id);
    invocation.set_text(format_args!("XSecurityCreateProcess 0x{:x}", result.0));
    Hresult::OK
}

fn civ_status(invocation: &mut Invocation<'_>) -> Hresult {
    match invocation.backend.civ_progress() {
        Ok(progress) => invocation.set_text(format_args!(
            "Blocks Checked {}, Failed Reads {}, Failed Hashes {}, Total Blocks {}, {}.",
            progress.blocks_checked as i32,
            progress.failed_reads as i32,
            progress.failed_hashes as i32,
            progress.total_blocks as i32,
            if progress.completed {
                "Completed"
            } else {
                "In Progress"
            }
        )),
        Err(error) => invocation.set_text(format_args!(
            "XSecurityFailedBlocks returned 0x{:x}",
            error.0
        )),
    }
    Hresult::OK
}

fn civ_stop(invocation: &mut Invocation<'_>) -> Hresult {
    invocation.backend.close_civ_process();
    invocation.text.set_bytes(b"XSecurityCloseProcess");
    Hresult::OK
}

/// `civverify milliseconds=<dword>`: non-positive budgets other than -1
/// become 0x100.
fn civ_verify(invocation: &mut Invocation<'_>) -> Hresult {
    // Stock reads an uninitialized stack variable when the parameter is
    // absent; the default budget applies here.
    let requested = stored_dword(invocation, "milliseconds").unwrap_or(0) as i32;
    let milliseconds = if requested <= 0 && requested != -1 {
        CIV_DEFAULT_MILLISECONDS
    } else {
        requested as u32
    };
    let result = invocation.backend.verify_civ(milliseconds);
    invocation.set_text(format_args!("XSecurityVerify 0x{:x}", result.0));
    Hresult::OK
}

/// `enable` (tested first) sets `on_enable`; `disable` sets the opposite.
fn update_iptv_flag(invocation: &mut Invocation<'_>, mask: IptvFlags, on_enable: bool) -> Hresult {
    let set = if invocation.line.has("enable") {
        on_enable
    } else if invocation.line.has("disable") {
        !on_enable
    } else {
        invocation.text.set_bytes(b"missing arguments");
        return Hresult::FAIL;
    };
    console::modify_config_flag(invocation.backend, IPTV_FLAGS_SETTING, mask.0, set)
}

fn iptv(invocation: &mut Invocation<'_>) -> Hresult {
    update_iptv_flag(invocation, IptvFlags::ENABLED, true)
}

fn iptv_allow_uninstall(invocation: &mut Invocation<'_>) -> Hresult {
    update_iptv_flag(invocation, IptvFlags::UNINSTALL_BLOCKED, false)
}

fn iptv_dvr(invocation: &mut Invocation<'_>) -> Hresult {
    update_iptv_flag(invocation, IptvFlags::DVR, true)
}

/// The value at the setting's fixed line offset, without validation, each
/// byte sign-extended to a big-endian UTF-16 unit.
fn store_iptv_string(invocation: &mut Invocation<'_>, setting: IptvString) -> Hresult {
    let size = setting.size();
    let mut text = [0u8; IPTV_STRING_CAPACITY / 2];
    let text =
        Value::at_offset(invocation.buffer, setting.line_offset()).copy_into(&mut text[..size / 2]);
    let mut stored = [0u8; IPTV_STRING_CAPACITY];
    for (unit, &byte) in stored.as_chunks_mut::<2>().0.iter_mut().zip(text) {
        *unit = (i16::from(byte as i8) as u16).to_be_bytes();
    }
    match invocation
        .backend
        .xconfig_set(setting.setting(), &stored[..size])
    {
        Ok(()) => Hresult::OK,
        Err(status) => Hresult::from_nt_status(status, Hresult::UNEXPECTED),
    }
}

fn iptv_bootstrap_url(invocation: &mut Invocation<'_>) -> Hresult {
    store_iptv_string(invocation, IptvString::BootstrapUrl)
}

fn iptv_provider_name(invocation: &mut Invocation<'_>) -> Hresult {
    store_iptv_string(invocation, IptvString::ProviderName)
}

fn iptv_provisioning_url(invocation: &mut Invocation<'_>) -> Hresult {
    store_iptv_string(invocation, IptvString::ProvisioningUrl)
}

fn iptv_support_info(invocation: &mut Invocation<'_>) -> Hresult {
    store_iptv_string(invocation, IptvString::SupportInfo)
}
