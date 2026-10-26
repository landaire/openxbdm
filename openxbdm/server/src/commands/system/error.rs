//! System domain errors.

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use xbox360_sys::status::Facility;

/// Programming the flash failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashFailed(pub Win32Error);

/// The `flash` result: the Win32 facility applied to the low word of any
/// code, as the reply text prints it.
impl From<FlashFailed> for Hresult {
    fn from(FlashFailed(error): FlashFailed) -> Self {
        Hresult::failure(Facility::WIN32, error.code() as u16)
    }
}

/// Why the settings file could not be created for writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateSettingsError {
    /// The write buffer could not be allocated.
    NoBuffer,
    /// The file could not be created.
    Create(KernelError),
}
