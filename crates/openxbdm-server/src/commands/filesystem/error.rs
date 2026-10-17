//! Errors of the file commands.

use openxbdm_core::status::KernelError;

use crate::reply::CommandError;

/// Why `sysfileupd` failed before its upload started.
pub(super) enum UpdateError {
    Command(CommandError),
    /// Reported through its Win32 error code.
    Kernel(KernelError),
}

impl From<CommandError> for UpdateError {
    fn from(error: CommandError) -> Self {
        Self::Command(error)
    }
}
