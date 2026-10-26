//! State shared by all connections.

use crate::commands;
use crate::notify::Notifications;
use crate::transfer_blocks::TransferBlocks;

/// Lock mode, which requires authentication on new connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    Unlocked,
    Locked,
    /// Locked with file encryption.
    LockedEncrypted,
}

/// Lock state and the box identifier announced in the lock-mode banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lock {
    pub mode: LockMode,
    /// High and low dwords of the box identifier.
    pub box_id: [u32; 2],
}

impl Lock {
    pub const fn new() -> Self {
        Self {
            mode: LockMode::Unlocked,
            box_id: [0; 2],
        }
    }

    pub fn is_locked(&self) -> bool {
        self.mode != LockMode::Unlocked
    }
}

/// Global server state.
#[derive(Debug)]
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
    pub transfer_blocks: TransferBlocks,
}

impl ServerState {
    pub const fn new() -> Self {
        Self {
            lock: Lock::new(),
            notifications: Notifications::new(),
            settings_dirty: false,
            session: commands::session::State::new(),
            security: commands::security::State::new(),
            console: commands::console::State::new(),
            system: commands::system::State::new(),
            filesystem: commands::filesystem::State::new(),
            memory: commands::memory::State::new(),
            debugger: commands::debugger::State::new(),
            network: commands::network::State::new(),
            performance: commands::performance::State::new(),
            hardware: commands::hardware::State::new(),
            services: commands::services::State::new(),
            transfer_blocks: TransferBlocks::new(),
        }
    }
}
