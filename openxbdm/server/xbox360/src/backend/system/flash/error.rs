use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;

#[derive(Debug)]
pub(super) enum Failure {
    /// Reported through `RtlNtStatusToDosError`.
    Kernel(KernelError),
    Win32(Win32Error),
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Kernel(error) => core::fmt::Display::fmt(error, f),
            Self::Win32(error) => core::fmt::Display::fmt(error, f),
        }
    }
}

impl core::error::Error for Failure {}

impl From<KernelError> for Failure {
    fn from(error: KernelError) -> Self {
        Self::Kernel(error)
    }
}
