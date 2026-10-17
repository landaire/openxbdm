#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum CaptureParseError {
    #[error("capture line {line_no} is missing a direction tag")]
    MissingTag { line_no: usize },
    #[error("capture line {line_no} has an unknown direction tag")]
    UnknownTag { line_no: usize },
    #[error("capture line {line_no} contains an invalid escape sequence")]
    BadEscape { line_no: usize },
}
