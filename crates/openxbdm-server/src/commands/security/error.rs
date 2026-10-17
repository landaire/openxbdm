//! Security domain errors.

/// The user directory could not create the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserCreationFailed;
