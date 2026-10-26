//! IPTV configuration and content integrity verification (CIV) commands.

mod civ;
mod error;
mod iptv;

use openxbdm_core::status::Win32Error;

use self::civ::civ_fail;
use self::civ::civ_inject;
use self::civ::civ_set_bits;
use self::civ::civ_start;
use self::civ::civ_status;
use self::civ::civ_stop;
use self::civ::civ_verify;
use self::iptv::iptv;
use self::iptv::iptv_allow_uninstall;
use self::iptv::iptv_bootstrap_url;
use self::iptv::iptv_dvr;
use self::iptv::iptv_provider_name;
use self::iptv::iptv_provisioning_url;
use self::iptv::iptv_support_info;
use crate::access::Access;
use crate::continuation::ContinuationContext;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply::CommandResult;

pub use self::civ::CivProgress;
pub use self::civ::CivResult;
pub use self::civ::DetectionBit;
pub use self::civ::DetectionMask;
pub use self::civ::DetectionRoutine;
pub use self::civ::DetectionUpdate;
pub use self::error::DetectionRoutineMissing;
pub use self::iptv::IPTV_STRING_CAPACITY;
pub use self::iptv::IptvString;

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry("civfail", DispatchFlags::empty(), civ_fail),
    entry("civinject", DispatchFlags::OWN_THREAD, civ_inject),
    entry("civsetbits", DispatchFlags::DEVKIT_ONLY, civ_set_bits),
    entry("civstart", DispatchFlags::OWN_THREAD, civ_start),
    entry("civstatus", DispatchFlags::empty(), civ_status),
    entry("civstop", DispatchFlags::OWN_THREAD, civ_stop),
    entry("civverify", DispatchFlags::OWN_THREAD, civ_verify),
    entry("iptv", DispatchFlags::empty(), iptv),
    entry(
        "iptvallowuninstall",
        DispatchFlags::empty(),
        iptv_allow_uninstall,
    ),
    entry(
        "iptvbootstrapurl",
        DispatchFlags::empty(),
        iptv_bootstrap_url,
    ),
    entry("iptvdvr", DispatchFlags::empty(), iptv_dvr),
    entry(
        "iptvprovidername",
        DispatchFlags::empty(),
        iptv_provider_name,
    ),
    entry(
        "iptvprovisioningurl",
        DispatchFlags::empty(),
        iptv_provisioning_url,
    ),
    entry("iptvsupportinfo", DispatchFlags::empty(), iptv_support_info),
];

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

/// Kernel handle of a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThreadHandle(pub u32);

/// A thread last-error value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastError {
    /// `ERROR_SUCCESS`: the thread holds no error.
    Success,
    /// `ERROR_PROC_NOT_FOUND`: the procedure is not exported by the module.
    ProcNotFound,
    Other(Win32Error),
}

impl LastError {
    pub fn from_win32(error: Option<Win32Error>) -> Self {
        match error {
            None => Self::Success,
            Some(Win32Error::PROC_NOT_FOUND) => Self::ProcNotFound,
            Some(error) => Self::Other(error),
        }
    }

    /// The Win32 code, as the reply text prints it.
    pub fn code(self) -> u32 {
        match self {
            Self::Success => 0,
            Self::ProcNotFound => Win32Error::PROC_NOT_FOUND.code(),
            Self::Other(error) => error.code(),
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

const fn entry(
    name: &'static str,
    flags: DispatchFlags,
    handler: crate::registry::Handler,
) -> CommandEntry {
    CommandEntry::new(name, Access::CONTROL, Access::empty(), flags, handler)
}

pub(crate) fn resume(
    continuation: &mut Continuation,
    _cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    match *continuation {}
}
