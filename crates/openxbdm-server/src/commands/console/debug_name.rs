//! Console debug name: storage, `dbgname`, and the SMC I2C settings block copy.

use openxbdm_core::status::ErrorCode;

use super::Published;
use super::SETTINGS_BLOCK_SIZE;
use super::error::BufferTooSmall;
use super::string_param;
use crate::access::Access;
use crate::backend::Backend as AnyBackend;
use crate::commands::system::SettingsFile;
use crate::commands::system::end_line;
use crate::commands::system::write_bytes;
use crate::commands::system::write_text;
use crate::invocation::Invocation;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;

/// Bytes of a stored debug name, including the terminator.
pub const DEBUG_NAME_CAPACITY: usize = 0x15;

/// Console debug name: at most 20 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugName {
    bytes: [u8; DEBUG_NAME_CAPACITY - 1],
    len: u8,
}

impl DebugName {
    pub const EMPTY: Self = Self {
        bytes: [0; DEBUG_NAME_CAPACITY - 1],
        len: 0,
    };

    /// The name, truncated to 20 bytes.
    pub fn new(name: &[u8]) -> Self {
        let mut stored = Self::EMPTY;
        let length = name.len().min(stored.bytes.len());
        stored.bytes[..length].copy_from_slice(&name[..length]);
        stored.len = length as u8;

        stored
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Stock export 17 (control code 0x33): copy the debug name and a
/// terminator into `output`, cut to fit; a cut name fails. Stock
/// underflows the size of an empty buffer and copies the whole name past
/// it; here nothing is written.
pub fn copy_debug_name(name: &DebugName, output: &mut [u8]) -> Result<(), BufferTooSmall> {
    let Some(room) = output.len().checked_sub(1) else {
        return if name.as_bytes().is_empty() {
            Ok(())
        } else {
            Err(BufferTooSmall)
        };
    };

    let name = name.as_bytes();
    let length = name.len().min(room);
    output[..length].copy_from_slice(&name[..length]);
    output[length] = 0;

    if length == name.len() {
        Ok(())
    } else {
        Err(BufferTooSmall)
    }
}

/// Stock 0x91f4e6b0: store the name in the SMC I2C settings block when it
/// differs. Block layout: +0 version (2), +1 size (0x20), +0xa name length,
/// +0xb name (20 bytes, zero padded).
pub(super) fn persist_debug_name(backend: &mut dyn AnyBackend, name: &[u8]) {
    let Some(mut block) = backend.read_settings_block() else {
        return;
    };

    let reformatted = block[0] < 2 || block[0] == 0xff;
    if reformatted {
        block[0] = 2;
        block[1] = SETTINGS_BLOCK_SIZE as u8;
    }

    let length = name.len();
    let renamed = usize::from(block[0xa]) != length || block[0xb..0xb + length] != *name;
    if !reformatted && !renamed {
        return;
    }

    block[0xa] = length as u8;
    block[0xb..0xb + length].copy_from_slice(name);
    block[0xb + length..0xb + DEBUG_NAME_CAPACITY - 1].fill(0);

    if !backend.write_settings_block(&block) {
        backend.debug_print(b"dm: I2C write failed.\n");
    }
}

/// `dbgname [name=<string>]`: report or set the debug name. Setting it
/// requires the config privilege and also rewrites the settings file.
pub(super) fn debug_name(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut buffer = [0u8; DEBUG_NAME_CAPACITY];
    let Some(value) = string_param(invocation, "name", &mut buffer) else {
        let name = invocation.state.console.debug_name;
        invocation.text.set_bytes(name.as_bytes());
        return Ok(Reply::Ok);
    };

    if !invocation.access().intersects(Access::CONFIG) {
        return Err(ErrorCode::AccessDenied.into());
    }

    let name = DebugName::new(value);
    invocation.state.console.debug_name = name;
    invocation.backend.publish(Published::DebugName(&name));
    persist_debug_name(invocation.backend, name.as_bytes());
    crate::commands::system::save_settings(invocation.state, invocation.backend);

    Ok(Reply::Ok)
}

/// `dbgname name=<name>` when a name is set. The name is not quoted, so a
/// name with a space loads back truncated at the space.
pub(crate) fn debug_name_settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let name = state.console.debug_name;
    if !name.as_bytes().is_empty() {
        write_text(backend, file, format_args!("dbgname name="));
        write_bytes(backend, file, name.as_bytes());
        end_line(backend, file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_name_copy_cuts_to_the_buffer() {
        let name = DebugName::new(b"kit");
        let mut buffer = [0xffu8; 5];
        assert_eq!(copy_debug_name(&name, &mut buffer), Ok(()));
        assert_eq!(buffer, *b"kit\0\xff");
        assert_eq!(copy_debug_name(&name, &mut buffer[..4]), Ok(()));
        assert_eq!(
            copy_debug_name(&name, &mut buffer[..3]),
            Err(BufferTooSmall)
        );
        assert_eq!(buffer[..3], *b"ki\0");
        assert_eq!(copy_debug_name(&name, &mut []), Err(BufferTooSmall));
        assert_eq!(copy_debug_name(&DebugName::EMPTY, &mut []), Ok(()));
    }
}
