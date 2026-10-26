//! Share path validation errors.

use crate::status::NtStatus;

/// Why a request path is not a valid share path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// The path starts with a separator; share paths are relative.
    LeadingSeparator,
    /// Two separators are adjacent, or the path ends with one.
    EmptyComponent,
    /// A component is `.` or `..`.
    RelativeComponent,
    /// A component holds a character NT file names exclude.
    ExcludedCharacter { unit: u16 },
}

impl core::fmt::Display for PathError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LeadingSeparator => formatter.write_str("path starts with a separator"),
            Self::EmptyComponent => formatter.write_str("path has an empty component"),
            Self::RelativeComponent => formatter.write_str("path has a `.` or `..` component"),
            Self::ExcludedCharacter { unit } => {
                write!(formatter, "path has the excluded character {unit:#06x}")
            }
        }
    }
}

impl core::error::Error for PathError {}

impl From<PathError> for NtStatus {
    fn from(error: PathError) -> Self {
        match error {
            PathError::LeadingSeparator => NtStatus::InvalidParameter,
            PathError::EmptyComponent
            | PathError::RelativeComponent
            | PathError::ExcludedCharacter { .. } => NtStatus::ObjectNameInvalid,
        }
    }
}
