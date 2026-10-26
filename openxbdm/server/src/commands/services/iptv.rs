//! IPTV configuration commands.

use openxbdm_core::line::Value;

use crate::commands::console;
use crate::commands::console::ConfigSetting;
use crate::commands::console::RetailFlags;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// Largest IPTV string buffer in bytes.
pub const IPTV_STRING_CAPACITY: usize = 0x80;

/// IPTV configuration strings (category 9). Values are stored as
/// big-endian UTF-16 units in a zero-filled buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IptvString {
    ProviderName,
    ProvisioningUrl,
    SupportInfo,
    BootstrapUrl,
}

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

/// `enable` (tested first) sets `on_enable`; `disable` sets the opposite.
fn update_iptv_flag(
    invocation: &mut Invocation<'_>,
    flag: RetailFlags,
    on_enable: bool,
) -> CommandResult {
    let set = if invocation.line.has("enable") {
        on_enable
    } else if invocation.line.has("disable") {
        !on_enable
    } else {
        invocation.text.set_bytes(b"missing arguments");
        return Err(CommandError::Fail);
    };

    console::modify_config_flag(invocation.backend, flag, set).map(|()| Reply::Ok)
}

pub(super) fn iptv(invocation: &mut Invocation<'_>) -> CommandResult {
    update_iptv_flag(invocation, RetailFlags::IPTV_ENABLED, true)
}

pub(super) fn iptv_allow_uninstall(invocation: &mut Invocation<'_>) -> CommandResult {
    update_iptv_flag(invocation, RetailFlags::IPTV_UNINSTALL_BLOCKED, false)
}

pub(super) fn iptv_dvr(invocation: &mut Invocation<'_>) -> CommandResult {
    update_iptv_flag(invocation, RetailFlags::IPTV_DVR, true)
}

/// The value at the setting's fixed line offset, without validation, each
/// byte sign-extended to a big-endian UTF-16 unit.
fn store_iptv_string(invocation: &mut Invocation<'_>, setting: IptvString) -> CommandResult {
    let size = setting.size();
    let mut text = [0u8; IPTV_STRING_CAPACITY / 2];
    let text =
        Value::at_offset(invocation.buffer, setting.line_offset()).copy_into(&mut text[..size / 2]);

    let mut stored = [0u8; IPTV_STRING_CAPACITY];
    for (unit, &byte) in stored.as_chunks_mut::<2>().0.iter_mut().zip(text) {
        *unit = (i16::from(byte as i8) as u16).to_be_bytes();
    }

    invocation
        .backend
        .xconfig_set(setting.setting(), &stored[..size])
        .map(|()| Reply::Ok)
        .map_err(|error| CommandError::from_kernel(error, CommandError::Unexpected))
}

pub(super) fn iptv_bootstrap_url(invocation: &mut Invocation<'_>) -> CommandResult {
    store_iptv_string(invocation, IptvString::BootstrapUrl)
}

pub(super) fn iptv_provider_name(invocation: &mut Invocation<'_>) -> CommandResult {
    store_iptv_string(invocation, IptvString::ProviderName)
}

pub(super) fn iptv_provisioning_url(invocation: &mut Invocation<'_>) -> CommandResult {
    store_iptv_string(invocation, IptvString::ProvisioningUrl)
}

pub(super) fn iptv_support_info(invocation: &mut Invocation<'_>) -> CommandResult {
    store_iptv_string(invocation, IptvString::SupportInfo)
}
