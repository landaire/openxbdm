//! Console configuration settings and flag edits.

use openxbdm_core::status::KernelError;

use crate::backend::Backend as AnyBackend;
use crate::commands::util;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// Address of a console configuration setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConfigSetting {
    pub category: u16,
    pub index: u16,
}

impl ConfigSetting {
    /// The console MAC address.
    pub const MAC_ADDRESS: Self = Self::new(2, 1);
    /// The reset button chord.
    pub const RESET_CHORD: Self = Self::new(2, 5);
    /// [`ConsoleConfigFlags`].
    pub const CONSOLE_FLAGS: Self = Self::new(2, 6);
    /// The automatic sign-in profile XUID.
    pub const AUTO_PROFILE_XUID: Self = Self::new(3, 8);
    pub const NETWORK_SHARE: Self = Self::new(3, 0x10);
    pub const AUTO_SHUTOFF: Self = Self::new(7, 2);
    pub const DISCOVERABLE: Self = Self::new(7, 0xf);
    /// The previous flash version.
    pub const PREVIOUS_FLASH_VERSION: Self = Self::new(0xa, 2);
    pub const KIOSK_ID: Self = Self::new(0xb, 3);

    pub const fn new(category: u16, index: u16) -> Self {
        Self { category, index }
    }
}

xbox360_sys::flags! {
    /// Bits of the console flags dword, setting (2, 6).
    pub struct ConsoleConfigFlags(u32) {
        HARD_DISK_DISABLED = 0x1,
        KD_LITE = 0x2,
        BUILT_IN_MEMORY_UNIT_DISABLED = 0x4,
    }
}

/// A category-3 configuration dword edited as a bit set.
pub trait ConfigFlags: Copy {
    const SETTING: ConfigSetting;

    fn bits(self) -> u32;
}

xbox360_sys::flags! {
    /// Bits of the user flags dword, setting (3, 0xd).
    pub struct UserFlags(u32) {
        MOTION_DETECTION_DISABLED = 0x01,
        BACKGROUND_MODE_TEST = 0x02,
        BOOT_ANIMATION_DISABLED = 0x04,
        LIVE_SIGNIN_REQUIRED = 0x08,
        KINECT_HEALTH_MESSAGE_DISABLED = 0x20,
        KIOSK = 0x40,
        DATA_CENTER = 0x400,
        WIRELESS_CONTROLLERS_DISABLED = 0x800,
    }
}

impl ConfigFlags for UserFlags {
    const SETTING: ConfigSetting = ConfigSetting::new(3, 0xd);

    fn bits(self) -> u32 {
        self.0
    }
}

xbox360_sys::flags! {
    /// Bits of the retail flags dword, setting (3, 0xc).
    pub struct RetailFlags(u32) {
        OOBE_DISABLED = 0x40,
        /// Boot device selection of `setdiscboot enable=0`; the meaning of
        /// the single bit is not known.
        DISC_BOOT_DISABLED = 0x80,
        /// Boot device selection of `setdiscboot enable=1`; the meaning of
        /// the single bit is not known.
        DISC_BOOT_ENABLED = 0x2000,
        /// Every bit `setdiscboot` clears before setting its selection.
        BOOT_DEVICE = 0x0002_2880,
        IPTV_ENABLED = 0x1000,
        OOBE_CHECKPOINT_DISABLED = 0x8000,
        IPTV_DVR = 0x0008_0000,
        /// Set when uninstalling IPTV is not allowed.
        IPTV_UNINSTALL_BLOCKED = 0x0200_0000,
        WELCOME_HIDE = 0x0400_0000,
        WELCOME_DEFAULT = 0x0800_0000,
        NUI_OOBE_DISABLED = 0x2000_0000,
    }
}

impl ConfigFlags for RetailFlags {
    const SETTING: ConfigSetting = ConfigSetting::new(3, 0xc);

    fn bits(self) -> u32 {
        self.0
    }
}

/// Stock 0x91f4d350: set or clear `flags` in their configuration dword
/// through kernel export 700, or read, modify and write the setting when
/// that export is absent. Failures map with fallback 0x8000ffff.
pub fn modify_config_flag<F>(
    backend: &mut dyn AnyBackend,
    flags: F,
    set: bool,
) -> Result<(), CommandError>
where
    F: ConfigFlags,
{
    modify_config_bits(backend, F::SETTING, flags.bits(), set)
}

fn modify_config_bits(
    backend: &mut dyn AnyBackend,
    setting: ConfigSetting,
    mask: u32,
    set: bool,
) -> Result<(), CommandError> {
    let or_mask = if set { mask } else { 0 };

    let result = match backend.xconfig_modify(setting, !mask, or_mask) {
        Err(KernelError::OrdinalNotFound) => {
            let mut value = [0u8; 4];
            backend.xconfig_get(setting, &mut value).and_then(|_| {
                let old = u32::from_be_bytes(value);
                let new = if set { old | mask } else { old & !mask };

                backend.xconfig_set(setting, &new.to_be_bytes())
            })
        }
        other => other,
    };

    result.map_err(|error| CommandError::from_kernel(error, CommandError::Unexpected))
}

/// `setconfig category=<dword> index=<dword> value=<dword>`.
pub(super) fn set_config(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(category) = util::required_dword(invocation, "category") else {
        return Err(util::MISSING);
    };

    let Some(index) = util::required_dword(invocation, "index") else {
        return Err(util::MISSING);
    };

    let Some(value) = util::required_dword(invocation, "value") else {
        return Err(util::MISSING);
    };

    let setting = ConfigSetting::new(category as u16, index as u16);
    if invocation
        .backend
        .xconfig_set(setting, &value.to_be_bytes())
        .is_err()
    {
        invocation.text.set_bytes(b"setvalue failed");
        return Err(CommandError::Fail);
    }

    Ok(Reply::Ok)
}

/// `setretail and=<dword> or=<dword>`: masked update of setting (3, 0xc)
/// through kernel export 700 only.
pub(super) fn set_retail(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(and_mask) = util::required_dword(invocation, "and") else {
        return Err(util::MISSING);
    };

    let Some(or_mask) = util::required_dword(invocation, "or") else {
        return Err(util::MISSING);
    };

    if let Err(error) = invocation
        .backend
        .xconfig_modify(RetailFlags::SETTING, and_mask, or_mask)
    {
        invocation.set_text(format_args!("Modify failed: 0x{:08x}", error.status().0));
        return Err(CommandError::Fail);
    }

    Ok(Reply::Ok)
}
