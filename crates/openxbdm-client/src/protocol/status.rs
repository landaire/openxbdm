use crate::error::FramingError;
use crate::protocol::parse::run_framing;
use crate::protocol::parse::three_digit_code;

pub use openxbdm_core::status::Classified;
pub use openxbdm_core::status::ErrorCode;
pub use openxbdm_core::status::StatusCode;
pub use openxbdm_core::status::SuccessCode;

/// A 4xx status the console returned for a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteStatus {
    Listed(ErrorCode),
    /// A 4xx status outside the monitor's result table.
    Unlisted(StatusCode),
}

impl RemoteStatus {
    pub const fn raw(self) -> u16 {
        match self {
            Self::Listed(code) => code.raw(),
            Self::Unlisted(code) => code.raw(),
        }
    }

    /// Default text the monitor sends for this status; empty for an
    /// unlisted status.
    pub const fn message(self) -> &'static str {
        match self {
            Self::Listed(code) => code.message(),
            Self::Unlisted(_) => "",
        }
    }
}

impl From<ErrorCode> for RemoteStatus {
    fn from(code: ErrorCode) -> Self {
        Self::Listed(code)
    }
}

impl PartialEq<ErrorCode> for RemoteStatus {
    fn eq(&self, other: &ErrorCode) -> bool {
        *self == Self::Listed(*other)
    }
}

impl core::fmt::Display for RemoteStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({})", self.raw(), self.message())
    }
}

/// Parse a three-digit ASCII status code from the start of a line.
pub fn parse_status(text: &str) -> Result<StatusCode, FramingError> {
    if text.len() < 3 {
        return Err(FramingError::HeadTooShort);
    }
    let code = run_framing(three_digit_code, &text[..3], FramingError::NonDigitInStatus)?;
    StatusCode::new(code).ok_or(FramingError::StatusOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_code() {
        assert_eq!(parse_status("200- OK").unwrap().raw(), 200);
    }

    #[test]
    fn rejects_short_input() {
        assert!(matches!(
            parse_status("20"),
            Err(FramingError::HeadTooShort)
        ));
    }

    #[test]
    fn rejects_non_digit() {
        assert!(matches!(
            parse_status("2xx OK"),
            Err(FramingError::NonDigitInStatus)
        ));
    }
}
