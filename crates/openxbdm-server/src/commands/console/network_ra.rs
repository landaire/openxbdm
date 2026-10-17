//! Data-center network configuration (`confignetra`, `resetnetra`).

use openxbdm_core::status::ErrorCode;

use super::SWITCH_BUFFER;
use super::error::NetworkRaError;
use super::string_param;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// Data-center network configuration record exchanged with the system
/// network service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkRaRecord {
    pub flags: NetworkRaFlags,
    pub custom_boot_address: u32,
}

xbox360_sys::flags! {
    /// Flags of a [`NetworkRaRecord`].
    pub struct NetworkRaFlags(u32) {
        CUSTOM_BOOT_ADDRESS = 0x4000_0000,
        RELAX_HEARTBEAT = 0x8000_0000,
    }
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

fn network_ra_failure(invocation: &mut Invocation<'_>, error: NetworkRaError) -> CommandResult {
    const VE_FAILURE: &str =
        "confignetra: failed to getting VE device config! Are you not running in DC mode?";

    let NetworkRaError(result) = error;
    invocation.set_text(format_args!(
        "\x1e{VE_FAILURE} (err 0x{:08X})\x1e",
        result.0
    ));

    Err(CommandError::Unexpected)
}

/// Stock 0x91f46560: query and print the configuration.
fn show_network_ra(invocation: &mut Invocation<'_>, record: &mut NetworkRaRecord) -> CommandResult {
    const VE_HEADER: &str = "[Current VE configurations]";

    record.flags = NetworkRaFlags::empty();
    if let Err(error) = invocation
        .backend
        .network_ra_request(NetworkRaRequest::Get(record))
    {
        return network_ra_failure(invocation, error);
    }

    let relax = if record.flags.contains(NetworkRaFlags::RELAX_HEARTBEAT) {
        "on"
    } else {
        "off"
    };

    invocation.set_text(format_args!(
        "\x1e{VE_HEADER}\x1erelaxheartbeat={relax} customubootaddr=0x{:08X}\x1e",
        record.custom_boot_address
    ));

    Ok(Reply::Ok)
}

/// `confignetra [show] [relaxheartbeat=on|off] [customubootaddr=<dword>]`.
pub(super) fn configure_network_ra(invocation: &mut Invocation<'_>) -> CommandResult {
    const VE_USAGE: &str =
        "Usage: xbsetcfg /confignetra {relaxheartbeat=[on|off]} {customubootaddr=<address>}";

    let mut record = NetworkRaRecord::default();
    if invocation.line.has("show") {
        return show_network_ra(invocation, &mut record);
    }

    if let Err(error) = invocation
        .backend
        .network_ra_request(NetworkRaRequest::Get(&mut record))
    {
        return network_ra_failure(invocation, error);
    }

    let mut changes = 0;
    if invocation.line.has("relaxheartbeat") {
        let mut buffer = [0u8; SWITCH_BUFFER];
        if let Some(value) = string_param(invocation, "relaxheartbeat", &mut buffer) {
            record.flags.remove(NetworkRaFlags::RELAX_HEARTBEAT);
            if value.eq_ignore_ascii_case(b"on") {
                record.flags.insert(NetworkRaFlags::RELAX_HEARTBEAT);
            }

            changes += 1;
        }
    }

    if invocation.line.has("customubootaddr")
        && let Some(address) = invocation.line.dword("customubootaddr")
    {
        record.custom_boot_address = address;
        record.flags.remove(NetworkRaFlags::CUSTOM_BOOT_ADDRESS);
        if address != 0 {
            record.flags.insert(NetworkRaFlags::CUSTOM_BOOT_ADDRESS);
        }

        changes += 1;
    }

    if changes == 0 {
        invocation.set_text(format_args!("\x1e{VE_USAGE}\x1e"));
        return Err(ErrorCode::UnknownCommand.into());
    }

    if let Err(error) = invocation
        .backend
        .network_ra_request(NetworkRaRequest::Set(&mut record))
    {
        return network_ra_failure(invocation, error);
    }

    show_network_ra(invocation, &mut record)
}

/// `resetnetra`: the result of the request is ignored.
pub(super) fn reset_network_ra(invocation: &mut Invocation<'_>) -> CommandResult {
    let _ = invocation
        .backend
        .network_ra_request(NetworkRaRequest::Reset);

    Ok(Reply::Ok)
}
