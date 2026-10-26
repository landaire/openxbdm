use openxbdm_core::status::Hresult;

/// Why a processor could not be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// Every registry slot is taken.
    RegistryFull,
    /// The name is longer than [`crate::processors::PROCESSOR_NAME_CAPACITY`].
    NameTooLong,
}

impl From<RegisterError> for Hresult {
    fn from(error: RegisterError) -> Self {
        match error {
            RegisterError::RegistryFull => Hresult::OUT_OF_MEMORY,
            RegisterError::NameTooLong => Hresult::INVALID_ARGUMENT,
        }
    }
}
