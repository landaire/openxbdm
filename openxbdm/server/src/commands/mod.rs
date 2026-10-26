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
pub(crate) mod util;

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
