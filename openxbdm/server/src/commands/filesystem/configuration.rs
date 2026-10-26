//! Storage configuration settings: `hdd` and `prevflash`.

use super::optional_dword;
use crate::commands::console::ConfigSetting;
use crate::commands::console::ConsoleConfigFlags;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// `hdd enable|disable`: clear or set bit 0 of configuration setting
/// (2, 6).
pub(super) fn hdd(invocation: &mut Invocation<'_>) -> CommandResult {
    let value = if invocation.line.has("enable") {
        ConsoleConfigFlags::empty()
    } else if invocation.line.has("disable") {
        ConsoleConfigFlags::HARD_DISK_DISABLED
    } else {
        invocation.set_text(format_args!("missing arguments"));
        return Err(CommandError::Fail);
    };

    let mut bytes = [0u8; 4];
    if let Err(error) = invocation
        .backend
        .xconfig_get(ConfigSetting::CONSOLE_FLAGS, &mut bytes)
    {
        return Err(CommandError::from_kernel(error, CommandError::Unexpected));
    }

    let flags = ConsoleConfigFlags::from_bits_retain(u32::from_be_bytes(bytes))
        .difference(ConsoleConfigFlags::HARD_DISK_DISABLED)
        .union(value);
    match invocation
        .backend
        .xconfig_set(ConfigSetting::CONSOLE_FLAGS, &flags.bits().to_be_bytes())
    {
        Ok(()) => Ok(Reply::Ok),
        Err(error) => Err(CommandError::from_kernel(error, CommandError::Unexpected)),
    }
}

/// `prevflash [prevflashver=<dword>]`.
pub(super) fn previous_flash(invocation: &mut Invocation<'_>) -> CommandResult {
    let version = optional_dword(invocation, "PREVFLASHVER", 0);

    match invocation.backend.xconfig_set(
        ConfigSetting::PREVIOUS_FLASH_VERSION,
        &version.to_be_bytes(),
    ) {
        Ok(()) => Ok(Reply::Ok),
        Err(error) => Err(CommandError::from_kernel(error, CommandError::Unexpected)),
    }
}
