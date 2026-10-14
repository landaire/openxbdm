use crate::error::FramingError;
use crate::protocol::parse::run_framing;
use crate::protocol::parse::three_digit_code;

/// A three-digit XBDM status code appearing at the head of every response.
///
/// The raw value is preserved verbatim so unknown-but-valid codes can be
/// round-tripped and surfaced in diagnostics without being silently coerced.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusCode(u16);

impl StatusCode {
    pub const fn new(raw: u16) -> Option<Self> {
        if raw < 100 || raw > 999 { None } else { Some(Self(raw)) }
    }

    pub const fn raw(self) -> u16 {
        self.0
    }

    pub const fn is_success(self) -> bool {
        self.0 >= 200 && self.0 < 300
    }

    pub const fn is_error(self) -> bool {
        self.0 >= 400 && self.0 < 500
    }

    pub fn try_classify(self) -> Classified {
        if let Some(s) = SuccessCode::from_raw(self.0) {
            Classified::Success(s)
        } else if let Some(e) = ErrorCode::from_raw(self.0) {
            Classified::Error(e)
        } else {
            Classified::Unknown(self)
        }
    }
}

impl core::fmt::Debug for StatusCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StatusCode({})", self.0)
    }
}

impl core::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:03}", self.0)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Classified {
    Success(SuccessCode),
    Error(ErrorCode),
    Unknown(StatusCode),
}

/// Well-known success codes (2xx). The numeric value of the enum matches the
/// wire code, so `SuccessCode::Ok as u16 == 200`.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuccessCode {
    /// 200: single-line success.
    Ok = 200,
    /// 201: banner / connection acknowledgment.
    Connected = 201,
    /// 202: multi-line body follows, terminated by a bare `.` line.
    MultilineFollows = 202,
    /// 203: binary payload follows the response head.
    BinaryFollows = 203,
    /// 204: the server is waiting for us to send binary data.
    SendBinary = 204,
    /// 205: the connection has been closed by the remote end (polite).
    Disconnecting = 205,
    /// 206: the connection has been dedicated to a named handler.
    Dedicated = 206,
}

impl SuccessCode {
    pub const fn from_raw(raw: u16) -> Option<Self> {
        Some(match raw {
            200 => Self::Ok,
            201 => Self::Connected,
            202 => Self::MultilineFollows,
            203 => Self::BinaryFollows,
            204 => Self::SendBinary,
            205 => Self::Disconnecting,
            206 => Self::Dedicated,
            _ => return None,
        })
    }

    pub const fn raw(self) -> u16 {
        self as u16
    }
}

impl core::fmt::Display for SuccessCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.raw())
    }
}

/// Well-known error codes (4xx). Message strings preserved from `xbdm.xex`
/// are available via [`ErrorCode::message`].
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    UndefinedError = 400,
    MaxConnectionsExceeded = 401,
    FileNotFound = 402,
    NoSuchModule = 403,
    MemoryNotMapped = 404,
    NoSuchThread = 405,
    ClockNotSet = 406,
    UnknownCommand = 407,
    NotStopped = 408,
    FileCannotBeOpened = 409,
    InvalidFilename = 410,
    FileAlreadyExists = 411,
    DirectoryNotEmpty = 412,
    BadFileName = 413,
    FileCannotBeCreated = 414,
    AccessDenied = 415,
    NoRoomOnDevice = 416,
    NotDebuggable = 417,
    TypeInvalid = 418,
    DataNotAvailable = 419,
    OtherError = 499,
}

impl ErrorCode {
    pub const fn from_raw(raw: u16) -> Option<Self> {
        Some(match raw {
            400 => Self::UndefinedError,
            401 => Self::MaxConnectionsExceeded,
            402 => Self::FileNotFound,
            403 => Self::NoSuchModule,
            404 => Self::MemoryNotMapped,
            405 => Self::NoSuchThread,
            406 => Self::ClockNotSet,
            407 => Self::UnknownCommand,
            408 => Self::NotStopped,
            409 => Self::FileCannotBeOpened,
            410 => Self::InvalidFilename,
            411 => Self::FileAlreadyExists,
            412 => Self::DirectoryNotEmpty,
            413 => Self::BadFileName,
            414 => Self::FileCannotBeCreated,
            415 => Self::AccessDenied,
            416 => Self::NoRoomOnDevice,
            417 => Self::NotDebuggable,
            418 => Self::TypeInvalid,
            419 => Self::DataNotAvailable,
            raw if raw >= 400 && raw < 500 => Self::OtherError,
            _ => return None,
        })
    }

    pub const fn raw(self) -> u16 {
        self as u16
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::UndefinedError => "undefined error",
            Self::MaxConnectionsExceeded => "max number of connections exceeded",
            Self::FileNotFound => "file not found",
            Self::NoSuchModule => "no such module",
            Self::MemoryNotMapped => "memory not mapped",
            Self::NoSuchThread => "no such thread",
            Self::ClockNotSet => "clock not set",
            Self::UnknownCommand => "unknown command",
            Self::NotStopped => "not stopped",
            Self::FileCannotBeOpened => "file cannot be opened",
            Self::InvalidFilename => "invalid filename",
            Self::FileAlreadyExists => "file already exists",
            Self::DirectoryNotEmpty => "directory not empty",
            Self::BadFileName => "bad file name",
            Self::FileCannotBeCreated => "file cannot be created",
            Self::AccessDenied => "access denied",
            Self::NoRoomOnDevice => "no room on device",
            Self::NotDebuggable => "not debuggable",
            Self::TypeInvalid => "type invalid",
            Self::DataNotAvailable => "data not available",
            Self::OtherError => "other error",
        }
    }
}

impl core::fmt::Display for ErrorCode {
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
        assert!(matches!(parse_status("20"), Err(FramingError::HeadTooShort)));
    }

    #[test]
    fn rejects_non_digit() {
        assert!(matches!(parse_status("2xx OK"), Err(FramingError::NonDigitInStatus)));
    }
}
