//! Network share drive (`setserver`).

use super::ConfigSetting;
use super::string_param;
use crate::backend::Backend as AnyBackend;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;

/// Bytes of the network share setting.
const NETWORK_SHARE_SIZE: usize = 0x100;

/// `setserver none` | `setserver name=<string>`: store the network share
/// server and remap the share drive.
pub(super) fn set_server(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut setting = [0u8; NETWORK_SHARE_SIZE];
    if !invocation.line.has("none") && string_param(invocation, "name", &mut setting).is_none() {
        invocation.text.set_bytes(b"missing server name");
        return Err(CommandError::Fail);
    }

    if invocation
        .backend
        .xconfig_set(ConfigSetting::NETWORK_SHARE, &setting)
        .is_err()
    {
        invocation.text.set_bytes(b"save setting failed");
        return Err(CommandError::Fail);
    }

    refresh_network_share(invocation.state, invocation.backend);

    Ok(Reply::Ok)
}

/// Stock 0x91f2ec88: point the network share drive at the server named by
/// configuration setting (3, 0x10), or disable it when the name is empty or
/// too long. A failed setting read or client load leaves the drive as is.
pub(crate) fn refresh_network_share(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    /// Longest server name the drive refresh accepts.
    const NAME_LIMIT: usize = 0x3d;

    let mut setting = [0u8; NETWORK_SHARE_SIZE];
    if backend
        .xconfig_get(ConfigSetting::NETWORK_SHARE, &mut setting)
        .is_err()
    {
        return;
    }

    let mut length = 0;
    if setting[0] != 0 {
        let mut index = 0;

        while index <= NAME_LIMIT {
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

    if length == 0 || length > NAME_LIMIT || setting[0] == 0 {
        state.filesystem.drives.set_network_share(None);
    } else if backend.load_network_client().is_ok() {
        state
            .filesystem
            .drives
            .set_network_share(Some(&setting[..length]));
    }
}
