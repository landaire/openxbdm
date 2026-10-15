//! Built-in commands, grouped by domain. Each domain module defines its
//! table rows, the backend services it needs, its global state, and its
//! transfer continuations.

pub mod console;
pub mod debugger;
pub mod filesystem;
pub mod hardware;
pub mod memory;
pub mod network;
pub mod performance;
pub mod security;
pub mod services;
pub mod session;
pub mod system;

use crate::registry::CommandEntry;

/// Every built-in command table.
pub(crate) const TABLES: &[&[CommandEntry]] = &[
    session::COMMANDS,
    security::COMMANDS,
    console::COMMANDS,
    system::COMMANDS,
    filesystem::COMMANDS,
    memory::COMMANDS,
    debugger::COMMANDS,
    network::COMMANDS,
    performance::COMMANDS,
    hardware::COMMANDS,
    services::COMMANDS,
];

/// Helpers shared by command handlers.
pub(crate) mod util {
    use openxbdm_core::status::Hresult;

    use crate::invocation::Invocation;

    /// A required dword parameter. When absent, the reply text becomes
    /// `missing <name>` and the caller fails with [`Hresult::FAIL`].
    pub fn required_dword(invocation: &mut Invocation<'_>, name: &str) -> Option<u32> {
        let value = invocation.line.dword(name);
        if value.is_none() {
            invocation.set_text(format_args!("missing {name}"));
        }
        value
    }

    /// The reply for a missing required parameter.
    pub const MISSING: Hresult = Hresult::FAIL;
}
