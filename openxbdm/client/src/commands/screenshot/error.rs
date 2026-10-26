use crate::commands::screenshot::PixelFormat;

/// Why [`Screenshot::to_rgba8`](crate::commands::Screenshot::to_rgba8)
/// cannot decode a screenshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("no RGBA conversion for pixel format {format:?}")]
    UnsupportedFormat { format: PixelFormat },
    #[error("body of {length:#x} bytes does not hold every tile of the displayed rectangle")]
    BodyTooShort { length: usize },
}
