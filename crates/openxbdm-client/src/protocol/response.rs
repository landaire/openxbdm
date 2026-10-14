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

/// Parse a `NNN[- ]rest` header appearing at the start of every response.
pub fn parse_response_head(line: &str) -> Result<ResponseHead, Error> {
    let _ = parse_status(line)?;
    let (code, rest) = run_framing(response_head, line, FramingError::TrailingGarbageInHead)?;
    let code = StatusCode::new(code).ok_or(FramingError::StatusOutOfRange)?;
    Ok(ResponseHead { code, rest: rest.to_owned() })
}

impl Response {
    pub fn head(&self) -> &str {
        match self {
            Response::Line { head, .. }
            | Response::Multiline { head, .. }
            | Response::Binary { head, .. }
            | Response::SendBinary { head } => head,
        }
    }

    pub fn expect_ok(self) -> Result<String, Error> {
        match self {
            Response::Line { code: SuccessCode::Ok, head } => Ok(head),
            Response::Line { code, .. } => Err(Error::UnexpectedSuccessCode { expected: SuccessCode::Ok, got: code }),
            _ => Err(Error::UnexpectedStatus {
                expected: ExpectedShape::SingleLine200,
                got: StatusCode::new(200).unwrap(),
            }),
        }
    }

    pub fn expect_multiline(self) -> Result<Vec<String>, Error> {
        match self {
            Response::Multiline { lines, .. } => Ok(lines),
            _ => Err(Error::UnexpectedStatus {
                expected: ExpectedShape::Multiline202,
                got: StatusCode::new(202).unwrap(),
            }),
        }
    }

    pub fn expect_binary(self) -> Result<Vec<u8>, Error> {
        match self {
            Response::Binary { data, .. } => Ok(data),
            _ => {
                Err(Error::UnexpectedStatus { expected: ExpectedShape::Binary203, got: StatusCode::new(203).unwrap() })
            }
        }
    }
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
