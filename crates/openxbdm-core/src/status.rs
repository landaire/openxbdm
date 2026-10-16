//! Status codes, monitor result codes, and their default reply text.

pub use xbox360_sys::status::Hresult;
pub use xbox360_sys::status::KernelError;
pub use xbox360_sys::status::NtStatus;
pub use xbox360_sys::status::UnlistedStatus;
pub use xbox360_sys::status::Win32Error;

/// A three-digit XBDM status code appearing at the head of every response.
///
/// The raw value is preserved verbatim so unknown-but-valid codes can be
/// round-tripped and surfaced in diagnostics without being silently coerced.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusCode(u16);

impl StatusCode {
    pub const fn new(raw: u16) -> Option<Self> {
        if raw < 100 || raw > 999 {
            None
        } else {
            Some(Self(raw))
        }
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
        } else if let Some(code) = ErrorCode::from_raw(self.0) {
            Classified::Error(code)
        } else if self.is_error() {
            Classified::UnlistedError(self)
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
    /// A 4xx status outside the monitor's result table.
    UnlistedError(StatusCode),
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
    /// 205: the connection now serves a dedicated handler or notifications.
    Dedicated = 205,
    /// 206: produced by no command in the analyzed monitor.
    Reserved206 = 206,
    /// 209: fast-pipe receive completion.
    FastPipe = 209,
}

impl SuccessCode {
    pub const fn from_raw(raw: u16) -> Option<Self> {
        Some(match raw {
            200 => Self::Ok,
            201 => Self::Connected,
            202 => Self::MultilineFollows,
            203 => Self::BinaryFollows,
            204 => Self::SendBinary,
            205 => Self::Dedicated,
            206 => Self::Reserved206,
            209 => Self::FastPipe,
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

/// An error status (4xx) of the monitor's result table. The numeric value
/// of the enum matches the wire code.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    Undefined = 400,
    MaxConnectionsExceeded = 401,
    FileNotFound = 402,
    NoSuchModule = 403,
    MemoryNotMapped = 404,
    NoSuchThread = 405,
    ClockNotSet = 406,
    UnknownCommand = 407,
    NotStopped = 408,
    FileMustBeCopied = 409,
    FileAlreadyExists = 410,
    DirectoryNotEmpty = 411,
    FilenameInvalid = 412,
    FileCannotBeCreated = 413,
    AccessDenied = 414,
    NoRoomOnDevice = 415,
    NotDebuggable = 416,
    TypeInvalid = 417,
    DataNotAvailable = 418,
    BoxNotLocked = 420,
    KeyExchangeRequired = 421,
    DedicatedConnectionRequired = 422,
    BadParameter = 423,
    OutOfMemory = 428,
    PathNotFound = 430,
    LineTooLong = 446,
}

impl ErrorCode {
    pub const fn from_raw(raw: u16) -> Option<Self> {
        Some(match raw {
            400 => Self::Undefined,
            401 => Self::MaxConnectionsExceeded,
            402 => Self::FileNotFound,
            403 => Self::NoSuchModule,
            404 => Self::MemoryNotMapped,
            405 => Self::NoSuchThread,
            406 => Self::ClockNotSet,
            407 => Self::UnknownCommand,
            408 => Self::NotStopped,
            409 => Self::FileMustBeCopied,
            410 => Self::FileAlreadyExists,
            411 => Self::DirectoryNotEmpty,
            412 => Self::FilenameInvalid,
            413 => Self::FileCannotBeCreated,
            414 => Self::AccessDenied,
            415 => Self::NoRoomOnDevice,
            416 => Self::NotDebuggable,
            417 => Self::TypeInvalid,
            418 => Self::DataNotAvailable,
            420 => Self::BoxNotLocked,
            421 => Self::KeyExchangeRequired,
            422 => Self::DedicatedConnectionRequired,
            423 => Self::BadParameter,
            428 => Self::OutOfMemory,
            430 => Self::PathNotFound,
            446 => Self::LineTooLong,
            _ => return None,
        })
    }

    pub const fn raw(self) -> u16 {
        self as u16
    }

    /// Default text the monitor sends for this code.
    pub const fn message(self) -> &'static str {
        match self {
            Self::Undefined | Self::MaxConnectionsExceeded | Self::ClockNotSet => "",
            Self::FileNotFound => "file not found",
            Self::NoSuchModule => "no such module",
            Self::MemoryNotMapped => "memory not mapped",
            Self::NoSuchThread => "no such thread",
            Self::UnknownCommand => "unknown command",
            Self::NotStopped => "not stopped",
            Self::FileMustBeCopied => "file must be copied",
            Self::FileAlreadyExists => "file already exists",
            Self::DirectoryNotEmpty => "directory not empty",
            Self::FilenameInvalid => "filename is invalid",
            Self::FileCannotBeCreated => "file cannot be created",
            Self::AccessDenied => "access denied",
            Self::NoRoomOnDevice => "no room on device",
            Self::NotDebuggable => "not debuggable",
            Self::TypeInvalid => "type invalid",
            Self::DataNotAvailable => "data not available",
            Self::BoxNotLocked => "box is not locked",
            Self::KeyExchangeRequired => "key exchange required",
            Self::DedicatedConnectionRequired => "dedicated connection required",
            Self::BadParameter => "bad parameter",
            Self::OutOfMemory => "out of memory",
            Self::PathNotFound => "path not found",
            Self::LineTooLong => "line too long",
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({})", self.raw(), self.message())
    }
}

/// Facility code of monitor results.
const FACILITY_XBDM: u32 = 0x02da_0000;

/// Facility 0x2da success with status `200 + code`.
pub const fn xbdm_success(code: u16) -> Hresult {
    Hresult(FACILITY_XBDM | code as u32)
}

/// Facility 0x2da failure with status `400 + code`.
pub const fn xbdm_error(code: u16) -> Hresult {
    Hresult(0x8000_0000 | FACILITY_XBDM | code as u32)
}

impl ErrorCode {
    /// The failure result for this status.
    pub const fn hresult(self) -> Hresult {
        xbdm_error(self.raw() - 400)
    }
}

/// The monitor's results and reply text on [`Hresult`]: facility 0x2da
/// results carry the status code in the low word; other values are generic
/// success or failure codes.
pub trait XbdmHresult: Sized {
    /// The handler sent its own reply or closed the connection.
    const NO_REPLY: Self;
    const OK: Self;
    const CONNECTED: Self;
    const MULTILINE: Self;
    const BINARY: Self;
    const SEND_BINARY: Self;
    const DEDICATED: Self;
    const FAST_PIPE: Self;
    /// End of a transfer or of a list.
    const END_OF_DATA: Self;

    /// The three status digits of the monitor's line builder: the first
    /// from the sign, the others `'0' + low / 10` and `'0' + low % 10` of
    /// a monitor result's low word. A low word above 0xff becomes failure
    /// 0 and another facility counts as low word 0. Low words 100..=255
    /// yield non-digit characters, as in the builder.
    fn status_digits(self) -> [u8; 3];

    /// Text sent when the handler supplies none.
    fn default_message(self) -> &'static str;
}

impl XbdmHresult for Hresult {
    const NO_REPLY: Self = Self(0);
    const OK: Self = xbdm_success(0);
    const CONNECTED: Self = xbdm_success(1);
    const MULTILINE: Self = xbdm_success(2);
    const BINARY: Self = xbdm_success(3);
    const SEND_BINARY: Self = xbdm_success(4);
    const DEDICATED: Self = xbdm_success(5);
    const FAST_PIPE: Self = xbdm_success(9);
    const END_OF_DATA: Self = xbdm_error(0x104);

    fn status_digits(self) -> [u8; 3] {
        let monitor = self.0 & 0x7fff_0000 == FACILITY_XBDM;
        let (failure, low) = if monitor && self.0 & 0xffff > 0xff {
            (true, 0)
        } else if monitor {
            (self.is_failure(), (self.0 & 0xffff) as u8)
        } else {
            (self.is_failure(), 0)
        };
        [
            if failure { b'4' } else { b'2' },
            b'0'.wrapping_add(low / 10),
            b'0' + low % 10,
        ]
    }

    fn default_message(self) -> &'static str {
        match self.0 {
            0x02da_0000 => "OK",
            0x02da_0002 => "multiline response follows",
            0x02da_0003 => "binary response follows",
            0x02da_0004 => "send binary data",
            0x8000_ffff => "unexpected error",
            0x8007_000e => "out of memory",
            0x8007_0057 => "bad parameter",
            value if value & 0xffff_0000 == 0x82da_0000 && value & 0xffff <= 0xff => {
                match ErrorCode::from_raw((400 + (value & 0xffff)) as u16) {
                    Some(code) => code.message(),
                    None => "",
                }
            }
            _ => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_follows_the_line_builder() {
        assert_eq!(&Hresult::OK.status_digits(), b"200");
        assert_eq!(&Hresult::MULTILINE.status_digits(), b"202");
        assert_eq!(&ErrorCode::AccessDenied.hresult().status_digits(), b"414");
        assert_eq!(&Hresult::END_OF_DATA.status_digits(), b"400");
        assert_eq!(&Hresult::FAIL.status_digits(), b"400");
        assert_eq!(&Hresult(0x0000_0001).status_digits(), b"200");
        assert_eq!(&Hresult(0x02da_0100).status_digits(), b"400");
        assert_eq!(&xbdm_success(0x64).status_digits(), b"2:0");
        assert_eq!(&xbdm_success(0xc8).status_digits(), b"2D0");
        assert_eq!(&xbdm_error(0x96).status_digits(), b"4?0");
    }

    #[test]
    fn default_messages_match_the_result_table() {
        assert_eq!(
            ErrorCode::FileMustBeCopied.hresult().default_message(),
            "file must be copied"
        );
        assert_eq!(
            ErrorCode::LineTooLong.hresult().default_message(),
            "line too long"
        );
        assert_eq!(xbdm_error(0x13).default_message(), "");
        assert_eq!(Hresult::INVALID_ARGUMENT.default_message(), "bad parameter");
        assert_eq!(Hresult::FAIL.default_message(), "");
        assert_eq!(Hresult::END_OF_DATA.default_message(), "");
    }
}
