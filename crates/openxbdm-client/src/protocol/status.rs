pub use openxbdm_core::status::Classified;
pub use openxbdm_core::status::ErrorCode;
pub use openxbdm_core::status::StatusCode;
pub use openxbdm_core::status::SuccessCode;

use crate::error::FramingError;
use crate::protocol::parse::run_framing;
use crate::protocol::parse::three_digit_code;

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
