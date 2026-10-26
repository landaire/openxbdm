use crate::protocol::RemoteStatus;
use crate::protocol::StatusCode;
use crate::protocol::SuccessCode;

pub type Result<T, E = rootcause::Report<Error>> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error")]
    Io(#[from] std::io::Error),

    #[error("connection closed unexpectedly")]
    ConnectionClosed,

    #[error(transparent)]
    Framing(#[from] FramingError),

    #[error(transparent)]
    Parse(#[from] ParseError),

    #[error(transparent)]
    Argument(#[from] ArgumentError),

    #[error(transparent)]
    Transport(#[from] TransportError),

    #[error(transparent)]
    ScreenshotDecode(#[from] crate::commands::screenshot::DecodeError),

    #[cfg(feature = "capture")]
    #[error(transparent)]
    Pix(#[from] crate::commands::pix::PixError),

    #[cfg(feature = "capture")]
    #[error(transparent)]
    Xbm(#[from] crate::commands::pix::XbmError),

    #[cfg(feature = "dangerous")]
    #[error(transparent)]
    Drivemap(#[from] crate::commands::dangerous::DrivemapError),

    #[cfg(feature = "dangerous")]
    #[error(transparent)]
    Pe(#[from] crate::commands::dangerous::PeError),

    #[error("remote reported error {code} ({message:?})")]
    Remote { code: RemoteStatus, message: String },

    #[error("{operation} failed on the console with result {:#010x}", .hresult.0)]
    ConsoleOperationFailed {
        operation: &'static str,
        hresult: crate::commands::Hresult,
    },

    #[error("unknown status code {code}")]
    UnknownStatusCode { code: StatusCode },

    #[error("module {name:?} was not reported by XBDM")]
    ModuleNotFound { name: String },

    #[error("module {name:?} has zero size")]
    EmptyModule { name: String },

    #[error("module memory at {address:#010x} is not mapped")]
    UnmappedModuleMemory { address: u32 },

    #[error("module range at {base:#010x} with size {size:#x} exceeds the address space")]
    ModuleRangeOverflow { base: u32, size: u32 },

    #[error("expected {expected:?} response but got status {got}")]
    UnexpectedStatus {
        expected: ExpectedShape,
        got: StatusCode,
    },

    #[error("expected success code {expected} but got {got}")]
    UnexpectedSuccessCode {
        expected: SuccessCode,
        got: SuccessCode,
    },

    #[error("streaming body abandoned; connection framing lost")]
    StreamAbandoned {
        /// Bytes known to be still queued on the wire, or `None` when
        /// the stream failed before the body length was established.
        unread: Option<u64>,
    },

    #[error("client engine misuse")]
    EngineMisuse(#[from] crate::client::SubmitError),
}

#[derive(Debug, Clone, Copy)]
pub enum ExpectedShape {
    SingleLine200,
    Multiline202,
    Binary203,
    SendBinary204,
    Connected201,
}

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("response line did not fit within the maximum length")]
    LineTooLong,
    #[error("response line contained non-UTF-8 bytes")]
    NonUtf8Line,
    #[error("response head shorter than three bytes")]
    HeadTooShort,
    #[error("status code contained a non-digit byte")]
    NonDigitInStatus,
    #[error("status code outside the 100-999 range")]
    StatusOutOfRange,
    #[error("expected the 201 connected banner")]
    MissingBanner,
    #[error("trailing garbage after response head")]
    TrailingGarbageInHead,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("missing required key {key:?} in response")]
    MissingKey { key: &'static str },
    #[error("value for {key:?} has invalid hex digits")]
    InvalidHexDigits { key: &'static str },
    #[error("value for {key:?} is not a valid decimal u32")]
    InvalidDecimalU32 { key: &'static str },
    #[error("value for {key:?} is not a valid decimal u64")]
    InvalidDecimalU64 { key: &'static str },
    #[error("value for {key:?} is not a valid decimal i32")]
    InvalidDecimalI32 { key: &'static str },
    #[error("value {value:#x} for {key:?} is out of range")]
    ValueOutOfRange { key: &'static str, value: u32 },
    #[error("value for {key:?} is missing the 0q quadword prefix")]
    MissingQuadwordPrefix { key: &'static str },
    #[error("quadword for {key:?} is not exactly 16 hex digits")]
    QuadwordWrongLength { key: &'static str },
    #[error("quadword for {key:?} contains invalid hex digits")]
    InvalidQuadwordHex { key: &'static str },
    #[error("response line did not match the expected shape")]
    UnrecognizedShape,
    #[error("value {value} for {key:?} is not a known code")]
    UnknownCode { key: &'static str, value: u32 },
    #[error("memory response length mismatch: expected {expected:#x} bytes, got {actual:#x}")]
    MemoryLengthMismatch { expected: usize, actual: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum ArgumentError {
    #[error("quoted argument cannot contain an unescaped double quote")]
    QuotedContainsDoubleQuote,
    #[error("quoted argument cannot contain a carriage return or line feed")]
    QuotedContainsCrlf,
    #[error("dbgname value cannot contain CR, LF, or double quote")]
    InvalidDbgNameChar,
    #[error("filename cannot be empty")]
    EmptyFilename,
    #[error("controller packet count exceeds the protocol's u32 limit")]
    ControllerPacketCountOverflow,
    #[error("controller packet queue cannot be empty")]
    EmptyControllerPacketQueue,
    #[error("controller queue length {length} exceeds the safe limit {maximum}")]
    ControllerQueueLengthOutOfRange { length: u32, maximum: u32 },
    #[error(
        "controller frame duration {duration_ms} ms is outside 1..={maximum_ms} ms"
    )]
    ControllerFrameDurationOutOfRange {
        duration_ms: u32,
        maximum_ms: u32,
    },
    #[error("memory length exceeds the protocol's u32 limit")]
    MemoryLengthOverflow,
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("command declared Binary body but did not supply binary_len")]
    MissingBinaryLen,
    #[error("timed out opening XBDM connection")]
    ConnectTimeout,
    #[error("neither DNS nor the console name lookup knows {name:?}")]
    UnknownHost { name: String },
}
