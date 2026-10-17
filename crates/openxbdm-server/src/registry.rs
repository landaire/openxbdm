//! Built-in command table entries and lookup.

use crate::access::Access;
use crate::invocation::Invocation;
use crate::reply::CommandResult;

xbox360_sys::flags! {
    /// Dispatch flags carried by a command table entry.
    pub struct DispatchFlags(u8) {
        /// The command may run on a connection serviced outside the main
        /// server context (dedicated or title connections).
        ANY_CONTEXT = 0x1,
        /// The command exists only on development kits; test kits reply 407.
        DEVKIT_ONLY = 0x2,
        /// The monitor runs the handler on a separate thread and waits for it.
        OWN_THREAD = 0x4,
    }
}

/// A built-in command handler. Returning [`crate::reply::Reply::Sent`]
/// sends no status line; the handler has written its own reply or closed
/// the connection.
pub type Handler = fn(&mut Invocation<'_>) -> CommandResult;

/// One row of the built-in command table. Access masks and flags are
/// kept in bytes so a row takes 16 bytes.
#[derive(Debug, Clone, Copy)]
pub struct CommandEntry {
    pub name: &'static str,
    pub handler: Handler,
    /// Passes when the connection holds any of these bits; zero passes.
    any_of: u8,
    /// When nonzero, the connection must hold all of these bits and
    /// `any_of` is not consulted.
    all_of: u8,
    flags: DispatchFlags,
}

impl CommandEntry {
    pub const fn new(
        name: &'static str,
        any_of: Access,
        all_of: Access,
        flags: DispatchFlags,
        handler: Handler,
    ) -> Self {
        assert!(any_of.bits() <= 0xff && all_of.bits() <= 0xff);

        Self {
            name,
            handler,
            any_of: any_of.bits() as u8,
            all_of: all_of.bits() as u8,
            flags,
        }
    }

    pub const fn flags(&self) -> DispatchFlags {
        self.flags
    }

    /// The access rule of the monitor's table lookup.
    pub fn permits(&self, access: Access) -> bool {
        let all_of = Access::from_bits_retain(u32::from(self.all_of));

        if self.all_of != 0 {
            access.contains(all_of)
        } else if self.any_of == 0 {
            true
        } else {
            access.intersects(Access::from_bits_retain(u32::from(self.any_of)))
        }
    }
}

/// Find a built-in command by its command word, ignoring ASCII case.
pub fn lookup(word: &[u8]) -> Option<&'static CommandEntry> {
    if word.is_empty() {
        return None;
    }

    crate::commands::TABLES
        .iter()
        .flat_map(|table| table.iter())
        .find(|entry| entry.name.as_bytes().eq_ignore_ascii_case(word))
}
