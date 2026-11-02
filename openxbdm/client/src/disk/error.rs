use crate::commands::DeviceName;

#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    #[error("the first sector of {device} cannot be read")]
    Unreadable { device: DeviceName },

    #[error("range {start:#x}..{end:#x} is not within the device of {size:#x} bytes")]
    RangeOutOfBounds { start: u64, end: u64, size: u64 },

    #[error("read of {length:#x} bytes exceeds the {maximum:#x}-byte limit of one read")]
    ReadTooLong { length: u64, maximum: u64 },

    #[error("progress file {journal} is the image file {image}")]
    JournalAliasesImage {
        journal: std::path::PathBuf,
        image: std::path::PathBuf,
    },

    #[error("image file is {actual:#x} bytes; the device is {expected:#x} bytes")]
    ImageLengthMismatch { expected: u64, actual: u64 },

    #[error("fed {actual:#x} bytes for a read of {expected:#x} bytes")]
    FeedLengthMismatch { expected: u64, actual: u64 },

    #[error("fed bytes with no read outstanding")]
    NoReadOutstanding,

    #[error("image bytes {start:#x}..{end:#x} do not match their progress record")]
    DigestMismatch { start: u64, end: u64 },

    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// A progress file that does not belong to the pull being resumed.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("progress file is empty")]
    Empty,

    #[error("line {line} is not a progress file header")]
    Header { line: usize },

    #[error("line {line} is not a segment record")]
    Record { line: usize },

    #[error("line {line}: {start:#x}..{end:#x} is not a segment of the image")]
    NotASegment { line: usize, start: u64, end: u64 },

    #[error("progress file is for {journal}, not {requested}")]
    DeviceMismatch {
        journal: DeviceName,
        requested: DeviceName,
    },

    #[error("progress file is for a device of {journal:#x} bytes; the device is {device:#x} bytes")]
    SizeMismatch { journal: u64, device: u64 },

    #[error("progress file uses segments of {journal:#x} bytes, not {expected:#x}")]
    SegmentMismatch { journal: u64, expected: u64 },
}
