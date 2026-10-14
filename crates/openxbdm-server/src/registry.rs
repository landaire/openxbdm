//! Built-in command table entries and lookup.

use openxbdm_core::status::Hresult;

use crate::access::Access;
use crate::invocation::Invocation;

/// Dispatch flags carried by a command table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchFlags(u32);

impl DispatchFlags {
    pub const NONE: Self = Self(0);
    /// The command may run on a connection serviced outside the main
    /// server context (dedicated or title connections).
    pub const ANY_CONTEXT: Self = Self(0x1);
    /// The command exists only on development kits; test kits reply 407.
    pub const DEVKIT_ONLY: Self = Self(0x2);
    /// The monitor runs the handler on a separate thread and waits for it.
    pub const OWN_THREAD: Self = Self(0x4);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// A built-in command handler. Returning [`Hresult::NO_REPLY`] sends no
/// status line; the handler has written its own reply or closed the
/// connection.
pub type Handler = fn(&mut Invocation<'_>) -> Hresult;

/// One row of the built-in command table.
#[derive(Debug, Clone, Copy)]
pub struct CommandEntry {
    pub name: &'static str,
    /// Passes when the connection holds any of these bits; zero passes.
    pub any_of: Access,
    /// When nonzero, the connection must hold all of these bits and
    /// `any_of` is not consulted.
    pub all_of: Access,
    pub flags: DispatchFlags,
    pub handler: Handler,
}

impl CommandEntry {
    /// The access rule of the monitor's table lookup.
    pub fn permits(&self, access: Access) -> bool {
        if self.all_of.bits() != 0 {
            access.contains(self.all_of)
        } else if self.any_of.bits() == 0 {
            true
        } else {
            access.intersects(self.any_of)
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
