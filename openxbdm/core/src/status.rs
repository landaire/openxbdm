//! Status codes, monitor result codes, and their default reply text.

mod hresult;

pub use self::hresult::XbdmHresult;
pub use self::hresult::xbdm_error;
pub use self::hresult::xbdm_success;
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
        if let Some(code) = SuccessCode::from_raw(self.0) {
            Classified::Success(code)
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
