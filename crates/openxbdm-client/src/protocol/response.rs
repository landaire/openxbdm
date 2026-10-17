use crate::error::Error;
use crate::error::ExpectedShape;
use crate::error::FramingError;
use crate::protocol::parse::response_head;
use crate::protocol::parse::run_framing;
use crate::protocol::status::StatusCode;
use crate::protocol::status::SuccessCode;
use crate::protocol::status::parse_status;

/// The parsed head of a response line (the `NNN[ -]rest` portion).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub code: StatusCode,
    pub rest: String,
}

/// A fully parsed response.
#[derive(Debug, Clone)]
pub enum Response {
    Line { code: SuccessCode, head: String },
    Multiline { head: String, lines: Vec<String> },
    Binary { head: String, data: Vec<u8> },
    SendBinary { head: String },
}

impl Response {
    pub fn head(&self) -> &str {
        match self {
            Self::Line { head, .. }
            | Self::Multiline { head, .. }
            | Self::Binary { head, .. }
            | Self::SendBinary { head } => head,
        }
    }

    /// Status code the console sent for this response.
    pub fn status(&self) -> StatusCode {
        let raw = match self {
            Self::Line { code, .. } => code.raw(),
            Self::Multiline { .. } => 202,
            Self::Binary { .. } => 203,
            Self::SendBinary { .. } => 204,
        };

        StatusCode::new(raw).expect("success codes are status codes")
    }

    pub fn expect_ok(self) -> Result<String, Error> {
        match self {
            Self::Line {
                code: SuccessCode::Ok,
                head,
            } => Ok(head),
            Self::Line { code, .. } => Err(Error::UnexpectedSuccessCode {
                expected: SuccessCode::Ok,
                got: code,
            }),
            other => Err(Error::UnexpectedStatus {
                expected: ExpectedShape::SingleLine200,
                got: other.status(),
            }),
        }
    }

    pub fn expect_multiline(self) -> Result<Vec<String>, Error> {
        match self {
            Self::Multiline { lines, .. } => Ok(lines),
            other => Err(Error::UnexpectedStatus {
                expected: ExpectedShape::Multiline202,
                got: other.status(),
            }),
        }
    }

    pub fn expect_binary(self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Binary { data, .. } => Ok(data),
            other => Err(Error::UnexpectedStatus {
                expected: ExpectedShape::Binary203,
                got: other.status(),
            }),
        }
    }
}

/// Parse a `NNN[- ]rest` header appearing at the start of every response.
pub fn parse_response_head(line: &str) -> Result<ResponseHead, Error> {
    // Validate the status digits first so a malformed code reports the
    // specific framing error rather than trailing garbage.
    parse_status(line)?;

    let (code, rest) = run_framing(response_head, line, FramingError::TrailingGarbageInHead)?;
    let code = StatusCode::new(code).ok_or(FramingError::StatusOutOfRange)?;

    Ok(ResponseHead {
        code,
        rest: rest.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_head() {
        let head = parse_response_head("200- OK").unwrap();
        assert_eq!(head.code, StatusCode::new(200).unwrap());
        assert_eq!(head.rest, "OK");
    }

    #[test]
    fn parses_connected_banner() {
        let head = parse_response_head("201- connected").unwrap();
        assert_eq!(head.code, StatusCode::new(201).unwrap());
        assert_eq!(head.rest, "connected");
    }

    #[test]
    fn parses_error_head() {
        let head = parse_response_head("407- unknown command").unwrap();
        assert_eq!(head.code, StatusCode::new(407).unwrap());
        assert_eq!(head.rest, "unknown command");
    }
}
