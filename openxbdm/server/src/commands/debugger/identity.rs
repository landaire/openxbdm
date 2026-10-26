//! `debugger` and `isdebugger`: the record of the attached debugger.

use core::fmt::Write as _;

use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;

use crate::backend::Backend as AnyBackend;
use crate::commands::system::SettingsFile;
use crate::commands::system::end_line;
use crate::commands::system::write_bytes;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::text::Text;

pub const DEBUGGER_NAME_CAPACITY: usize = 0x7f;
pub const DEBUGGER_USER_CAPACITY: usize = 0xf;

/// The attached debugger as recorded by `debugger`.
#[derive(Debug, Clone)]
pub struct DebuggerRecord {
    pub attached: bool,
    /// Address word as the monitor stores it: `addr=` puts the first octet
    /// in the low byte, a peer address is the network-order word.
    pub address: u32,
    pub port: u32,
    pub name: Text<DEBUGGER_NAME_CAPACITY>,
    pub user: Text<DEBUGGER_USER_CAPACITY>,
}

impl DebuggerRecord {
    pub const EMPTY: Self = Self {
        attached: false,
        address: 0,
        port: 0,
        name: Text::new(),
        user: Text::new(),
    };
}

/// `debugger connect|disconnect|init [addr=] [port=] [name=] [user=]
/// [override]`.
pub(super) fn debugger_identity(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line;
    let address = match line.param("addr") {
        Some(value) => {
            let mut buffer = [0u8; 0x14];
            parse_dotted_address(value.copy_into(&mut buffer))
        }
        None => match invocation.session.as_ref() {
            Some(session) => invocation
                .network
                .peer(session.socket())
                .map_or(0, |peer| u32::from_be_bytes(peer.address.octets())),
            None => 0,
        },
    };
    let port = line.dword("port");
    let override_existing = line.has("override");
    let state = &mut *invocation.state;

    if line.has("connect") {
        let record = &state.debugger.debugger;
        if record.attached
            && record.port != 0
            && debugger_target_exists(state, record.address, record.port)
            && !override_existing
        {
            return Err(ErrorCode::FileAlreadyExists.into());
        }

        let changed = apply_identity(state, &line, address, port, true);
        state.debugger.debugger.attached = true;
        state.debugger.kernel_debugger = Some(false);
        if changed {
            state.settings_dirty = true;
        }

        return Ok(Reply::Ok);
    }

    if line.has("disconnect") {
        let record = &state.debugger.debugger;
        if record.port != 0
            && !(port == Some(record.port) && address == record.address)
            && !override_existing
        {
            return Err(ErrorCode::AccessDenied.into());
        }

        state.debugger.debugger = DebuggerRecord::EMPTY;
        state.debugger.kernel_debugger = Some(true);
        state.settings_dirty = true;
        return Ok(Reply::Ok);
    }

    if line.has("init") {
        if apply_identity(state, &line, address, port, false) {
            state.settings_dirty = true;
        }

        return Ok(Reply::Ok);
    }

    invocation.set_text(format_args!("no command"));

    Err(CommandError::Fail)
}

/// Store the given identity fields; returns whether the settings changed.
/// `connect` counts name and user as changes, `init` does not.
fn apply_identity(
    state: &mut ServerState,
    line: &CommandLine<'_>,
    address: u32,
    port: Option<u32>,
    count_names: bool,
) -> bool {
    let record = &mut state.debugger.debugger;
    let mut changed = false;

    if let Some(port) = port {
        record.address = address;
        record.port = port;
        changed = true;
    }

    if let Some(value) = line.param("name") {
        let mut buffer = [0u8; DEBUGGER_NAME_CAPACITY + 1];
        record.name.set_bytes(value.copy_into(&mut buffer));
        changed |= count_names;
    }

    if let Some(value) = line.param("user") {
        let mut buffer = [0u8; DEBUGGER_USER_CAPACITY + 1];
        record.user.set_bytes(value.copy_into(&mut buffer));
        changed |= count_names;
    }

    changed
}

/// `isdebugger`: an attached debugger reports as status 410.
pub(super) fn is_debugger(invocation: &mut Invocation<'_>) -> CommandResult {
    let state = &*invocation.state;
    let record = &state.debugger.debugger;
    if !record.attached {
        return Ok(Reply::Ok);
    }

    if record.address != 0 && !debugger_target_exists(state, record.address, record.port) {
        return Ok(Reply::Ok);
    }

    if record.name.is_empty() && record.user.is_empty() {
        return Err(ErrorCode::FileAlreadyExists.into());
    }

    let text = &mut *invocation.text;
    text.clear();
    if !record.name.is_empty() {
        let _ = text.push_bytes(b"name=\"");
        let _ = text.push_bytes(record.name.as_bytes());
        let _ = text.push_bytes(b"\" ");
    }
    if !record.user.is_empty() {
        let _ = text.push_bytes(b"user=");
        let _ = text.push_bytes(record.user.as_bytes());
    }

    Err(ErrorCode::FileAlreadyExists.into())
}

/// Settings line of the attached debugger (stock 0x91f3ce50), written
/// when a debugger is attached. The address prints low byte first.
pub(crate) fn settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let record = &state.debugger.debugger;
    if !record.attached {
        return;
    }

    let [first, second, third, fourth] = record.address.to_le_bytes();
    let mut line = Text::<0x1ff>::new();
    let _ = write!(
        line,
        "debugger init addr={first}.{second}.{third}.{fourth} port=0x{:08x}",
        record.port
    );
    if !record.name.is_empty() {
        let _ = line.push_bytes(b" name=\"");
        let _ = line.push_bytes(record.name.as_bytes());
        let _ = line.push_bytes(b"\"");
    }
    if !record.user.is_empty() {
        let _ = line.push_bytes(b" user=");
        let _ = line.push_bytes(record.user.as_bytes());
    }

    write_bytes(backend, file, line.as_bytes());
    end_line(backend, file);
}

fn debugger_target_exists(state: &ServerState, address: u32, port: u32) -> bool {
    state.notifications.targets().any(|target| {
        u32::from_be_bytes(target.endpoint.address.octets()) == address
            && u32::from(target.endpoint.port) == port & 0xffff
    })
}

/// Parse `a.b.c.d`: up to three decimal digits per octet, `.` after the
/// first three and the end after the fourth; the first octet lands in the
/// low byte. Malformed text yields 0.
fn parse_dotted_address(text: &[u8]) -> u32 {
    let mut octets = [0u8; 4];
    let mut position = 0;
    for (index, slot) in octets.iter_mut().enumerate() {
        let mut value = 0u8;
        let mut digits = 0;
        while digits < 3 && text.get(position).is_some_and(u8::is_ascii_digit) {
            value = value.wrapping_mul(10).wrapping_add(text[position] - b'0');
            position += 1;
            digits += 1;
        }

        let expected = if index < 3 { Some(&b'.') } else { None };
        if digits == 0 || text.get(position) != expected {
            return 0;
        }

        position += 1;
        *slot = value;
    }

    u32::from_le_bytes(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_address_puts_first_octet_low() {
        assert_eq!(parse_dotted_address(b"192.168.1.20"), 0x1401_a8c0);
        assert_eq!(parse_dotted_address(b"1.2.3"), 0);
        assert_eq!(parse_dotted_address(b"1.2.3.4x"), 0);
        assert_eq!(parse_dotted_address(b"300.1.1.1"), 0x0101_012c);
        assert_eq!(parse_dotted_address(b"1234.1.1.1"), 0);
    }
}
