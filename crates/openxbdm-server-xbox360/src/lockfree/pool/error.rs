use openxbdm_core::status::Hresult;

use crate::lockfree::Error;

/// A failed lock operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LockError {
    Container(Error),
    /// Export 351 with a mode other than shared or exclusive.
    BadMode,
    NotHeld,
    UpgradePending,
    ExclusiveWaiting,
    NotRecursive,
}

/// Stock keeps its internal codes of the lock failures and wait routine
/// results in one status word, so a wait result equal to a code reports as
/// that code.
impl From<Error> for LockError {
    fn from(error: Error) -> Self {
        const NOT_HELD: u32 = 0xe000_0001;
        const UPGRADE_PENDING: u32 = 0xe000_0002;
        const EXCLUSIVE_WAITING: u32 = 0xe000_0003;
        const NOT_RECURSIVE: u32 = 0xe000_0004;

        match error {
            Error::Wait(status) => match status.code() {
                NOT_HELD => Self::NotHeld,
                UPGRADE_PENDING => Self::UpgradePending,
                EXCLUSIVE_WAITING => Self::ExclusiveWaiting,
                NOT_RECURSIVE => Self::NotRecursive,
                _ => Self::Container(error),
            },
            error => Self::Container(error),
        }
    }
}

impl From<LockError> for Hresult {
    fn from(error: LockError) -> Self {
        let code = match error {
            LockError::Container(error) => return error.into(),
            LockError::BadMode => 3,
            LockError::NotHeld => 4,
            LockError::UpgradePending => 5,
            LockError::ExclusiveWaiting => 6,
            LockError::NotRecursive => 7,
        };

        Self::failure(Error::FACILITY, code)
    }
}

impl core::fmt::Display for LockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Container(error) => error.fmt(f),
            Self::BadMode => f.write_str("release mode is neither shared nor exclusive"),
            Self::NotHeld => f.write_str("lock not held"),
            Self::UpgradePending => f.write_str("another upgrade is pending"),
            Self::ExclusiveWaiting => f.write_str("an exclusive acquirer waits"),
            Self::NotRecursive => f.write_str("lock is not recursive"),
        }
    }
}

impl core::error::Error for LockError {}
