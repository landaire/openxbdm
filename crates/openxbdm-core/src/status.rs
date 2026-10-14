//! Status codes, monitor result codes, and their default reply text.

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
        } else if self.is_error() {
            Classified::Error(ErrorCode(self.0))
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

/// An error status (4xx). Default text comes from the monitor's result
/// table; codes without table text have an empty message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(u16);

impl ErrorCode {
    pub const UNDEFINED: Self = Self(400);
    pub const MAX_CONNECTIONS_EXCEEDED: Self = Self(401);
    pub const FILE_NOT_FOUND: Self = Self(402);
    pub const NO_SUCH_MODULE: Self = Self(403);
    pub const MEMORY_NOT_MAPPED: Self = Self(404);
    pub const NO_SUCH_THREAD: Self = Self(405);
    pub const CLOCK_NOT_SET: Self = Self(406);
    pub const UNKNOWN_COMMAND: Self = Self(407);
    pub const NOT_STOPPED: Self = Self(408);
    pub const FILE_MUST_BE_COPIED: Self = Self(409);
    pub const FILE_ALREADY_EXISTS: Self = Self(410);
    pub const DIRECTORY_NOT_EMPTY: Self = Self(411);
    pub const FILENAME_INVALID: Self = Self(412);
    pub const FILE_CANNOT_BE_CREATED: Self = Self(413);
    pub const ACCESS_DENIED: Self = Self(414);
    pub const NO_ROOM_ON_DEVICE: Self = Self(415);
    pub const NOT_DEBUGGABLE: Self = Self(416);
    pub const TYPE_INVALID: Self = Self(417);
    pub const DATA_NOT_AVAILABLE: Self = Self(418);
    pub const BOX_NOT_LOCKED: Self = Self(420);
    pub const KEY_EXCHANGE_REQUIRED: Self = Self(421);
    pub const DEDICATED_CONNECTION_REQUIRED: Self = Self(422);
    pub const BAD_PARAMETER: Self = Self(423);
    pub const OUT_OF_MEMORY: Self = Self(428);
    pub const PATH_NOT_FOUND: Self = Self(430);
    pub const LINE_TOO_LONG: Self = Self(446);

    /// Any 4xx code.
    pub const fn from_raw(raw: u16) -> Option<Self> {
        if raw >= 400 && raw < 500 {
            Some(Self(raw))
        } else {
            None
        }
    }

    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Default text the monitor sends for this code.
    pub const fn message(self) -> &'static str {
        match self.0 {
            402 => "file not found",
            403 => "no such module",
            404 => "memory not mapped",
            405 => "no such thread",
            407 => "unknown command",
            408 => "not stopped",
            409 => "file must be copied",
            410 => "file already exists",
            411 => "directory not empty",
            412 => "filename is invalid",
            413 => "file cannot be created",
            414 => "access denied",
            415 => "no room on device",
            416 => "not debuggable",
            417 => "type invalid",
            418 => "data not available",
            420 => "box is not locked",
            421 => "key exchange required",
            422 => "dedicated connection required",
            423 => "bad parameter",
            428 => "out of memory",
            430 => "path not found",
            446 => "line too long",
            _ => "",
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

/// A kernel status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtStatus(pub u32);

impl NtStatus {
    pub const SUCCESS: Self = Self(0);

    pub const fn is_success(self) -> bool {
        (self.0 as i32) >= 0
    }
}

/// A handler result as the monitor represents it: facility 0x2da results
/// carry the status code in the low word; other values are generic
/// success or failure codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hresult(pub u32);

impl Hresult {
    /// The handler sent its own reply or closed the connection.
    pub const NO_REPLY: Self = Self(0);
    pub const OK: Self = Self::success(0);
    pub const CONNECTED: Self = Self::success(1);
    pub const MULTILINE: Self = Self::success(2);
    pub const BINARY: Self = Self::success(3);
    pub const SEND_BINARY: Self = Self::success(4);
    pub const DEDICATED: Self = Self::success(5);
    pub const FAST_PIPE: Self = Self::success(9);
    /// End of continuation data; never sent as a status.
    pub const END_OF_DATA: Self = Self::error(0x104);
    pub const FAIL: Self = Self(0x8000_4005);
    pub const UNEXPECTED: Self = Self(0x8000_ffff);
    pub const OUT_OF_MEMORY: Self = Self(0x8007_000e);
    pub const INVALID_ARGUMENT: Self = Self(0x8007_0057);

    /// Facility 0x2da success with status `200 + code`.
    pub const fn success(code: u16) -> Self {
        Self(FACILITY_XBDM | code as u32)
    }

    /// Facility 0x2da failure with status `400 + code`.
    pub const fn error(code: u16) -> Self {
        Self(0x8000_0000 | FACILITY_XBDM | code as u32)
    }

    /// The failure result for an error status.
    pub const fn from_error_code(code: ErrorCode) -> Self {
        Self::error(code.raw() - 400)
    }

    pub const fn is_failure(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }

    /// The three status digits of the monitor's line builder: the first
    /// from the sign, the others `'0' + low / 10` and `'0' + low % 10` of
    /// a monitor result's low word. A low word above 0xff becomes failure
    /// 0 and another facility counts as low word 0. Low words 100..=255
    /// yield non-digit characters, as in the builder.
    pub const fn status_digits(self) -> [u8; 3] {
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

    /// Text sent when the handler supplies none.
    pub const fn default_message(self) -> &'static str {
        match self.0 {
            0x02da_0000 => "OK",
            0x02da_0002 => "multiline response follows",
            0x02da_0003 => "binary response follows",
            0x02da_0004 => "send binary data",
            0x8000_ffff => "unexpected error",
            0x8007_000e => "out of memory",
            0x8007_0057 => "bad parameter",
            value if value & 0xffff_0000 == 0x82da_0000 && value & 0xffff <= 0xff => {
                ErrorCode((400 + (value & 0xffff)) as u16).message()
            }
            _ => "",
        }
    }

    /// Map a kernel status to a monitor result, falling back to `fallback`.
    pub const fn from_nt_status(status: NtStatus, fallback: Self) -> Self {
        match status.0 {
            0x0000_0000 => Self::OK,
            0xc000_0008 => Self::INVALID_ARGUMENT,
            0xc000_0022 => Self::from_error_code(ErrorCode::ACCESS_DENIED),
            0xc000_0033 | 0xc000_0039 => Self::from_error_code(ErrorCode::FILENAME_INVALID),
            0xc000_0034 | 0xc000_00ba => Self::from_error_code(ErrorCode::FILE_NOT_FOUND),
            0xc000_0035 => Self::from_error_code(ErrorCode::FILE_ALREADY_EXISTS),
            0xc000_003a => {
                if fallback.0 == Self::from_error_code(ErrorCode::FILE_CANNOT_BE_CREATED).0 {
                    Self::from_error_code(ErrorCode::PATH_NOT_FOUND)
                } else {
                    Self::from_error_code(ErrorCode::FILE_NOT_FOUND)
                }
            }
            0xc000_007f => Self::from_error_code(ErrorCode::NO_ROOM_ON_DEVICE),
            0xc000_009a => Self::OUT_OF_MEMORY,
            0xc000_0101 => Self::from_error_code(ErrorCode::DIRECTORY_NOT_EMPTY),
            _ => fallback,
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
        assert_eq!(
            &Hresult::from_error_code(ErrorCode::ACCESS_DENIED).status_digits(),
            b"414"
        );
        assert_eq!(&Hresult::END_OF_DATA.status_digits(), b"400");
        assert_eq!(&Hresult::FAIL.status_digits(), b"400");
        assert_eq!(&Hresult(0x0000_0001).status_digits(), b"200");
        assert_eq!(&Hresult(0x02da_0100).status_digits(), b"400");
        assert_eq!(&Hresult::success(0x64).status_digits(), b"2:0");
        assert_eq!(&Hresult::success(0xc8).status_digits(), b"2D0");
        assert_eq!(&Hresult::error(0x96).status_digits(), b"4?0");
    }

    #[test]
    fn default_messages_match_the_result_table() {
        assert_eq!(
            Hresult::from_error_code(ErrorCode::FILE_MUST_BE_COPIED).default_message(),
            "file must be copied"
        );
        assert_eq!(
            Hresult::from_error_code(ErrorCode::LINE_TOO_LONG).default_message(),
            "line too long"
        );
        assert_eq!(Hresult::error(0x13).default_message(), "");
        assert_eq!(Hresult::INVALID_ARGUMENT.default_message(), "bad parameter");
        assert_eq!(Hresult::FAIL.default_message(), "");
        assert_eq!(Hresult::END_OF_DATA.default_message(), "");
    }

    #[test]
    fn missing_path_maps_by_fallback() {
        let create = Hresult::from_error_code(ErrorCode::FILE_CANNOT_BE_CREATED);
        assert_eq!(
            &Hresult::from_nt_status(NtStatus(0xc000_003a), create).status_digits(),
            b"430"
        );
        assert_eq!(
            &Hresult::from_nt_status(NtStatus(0xc000_003a), Hresult::FAIL).status_digits(),
            b"402"
        );
    }
}
