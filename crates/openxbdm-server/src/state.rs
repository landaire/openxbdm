//! State shared by all connections.

use crate::commands;
use crate::notify::Notifications;

/// Lock mode, which requires authentication on new connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockMode {
    #[default]
    Unlocked,
    Locked,
    /// Locked with file encryption.
    LockedEncrypted,
}

/// Lock state and the box identifier announced in the lock-mode banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lock {
    pub mode: LockMode,
    /// High and low dwords of the box identifier.
    pub box_id: [u32; 2],
}

impl Lock {
    pub fn is_locked(&self) -> bool {
        self.mode != LockMode::Unlocked
    }
}

/// Global server state.
#[derive(Debug, Default)]
pub struct ServerState {
    pub lock: Lock,
    pub notifications: Notifications,
    /// Set by commands that change persisted settings; the server writes
    /// the settings file after the command.
    pub settings_dirty: bool,
    pub session: commands::session::State,
    pub security: commands::security::State,
    pub console: commands::console::State,
    pub system: commands::system::State,
    pub filesystem: commands::filesystem::State,
    pub memory: commands::memory::State,
    pub debugger: commands::debugger::State,
    pub network: commands::network::State,
    pub performance: commands::performance::State,
    pub hardware: commands::hardware::State,
    pub services: commands::services::State,
}
