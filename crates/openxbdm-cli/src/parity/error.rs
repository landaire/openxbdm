use std::io;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ParityError {
    #[error("--host is required to record")]
    MissingHost,
    #[error("reading {path} failed")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("writing {path} failed")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{path} is not a recording")]
    Recording {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid command list")]
    Script(#[from] ScriptError),
    #[error("invalid variance file")]
    Variance(#[from] VarianceError),
    #[error("recording failed")]
    Record(#[from] RecordError),
    #[error("recordings are not comparable")]
    Compare(#[from] CompareError),
}

/// A malformed line of a command list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {kind}")]
pub struct ScriptError {
    /// One-based line number in the command file.
    pub line: usize,
    pub kind: ScriptErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScriptErrorKind {
    #[error("unknown directive `%{name}`")]
    UnknownDirective { name: String },
    #[error("`%repeat` needs a decimal count and text")]
    InvalidRepeat,
    #[error("`%upload` data is not pairs of hex digits")]
    InvalidUpload,
    #[error("`%reconnect` takes no argument")]
    ReconnectArgument,
    #[error("`%upload` does not follow a command")]
    UploadWithoutCommand,
    #[error("the previous command already has an upload")]
    DuplicateUpload,
    #[error("command line contains a carriage return")]
    CarriageReturn,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("connecting to the console failed")]
    Connect(#[source] io::Error),
    #[error("no banner within the reply timeout")]
    BannerTimeout,
    #[error("connection closed before the banner")]
    BannerClosed,
    #[error("reading the banner failed")]
    Banner(#[source] io::Error),
}

/// A malformed line of a variance file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {kind}")]
pub struct VarianceError {
    /// One-based line number in the variance file.
    pub line: usize,
    pub kind: VarianceErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VarianceErrorKind {
    #[error("expected `<command> | <fields> | <reason>`")]
    Shape,
    #[error("unknown field `{field}`")]
    UnknownField { field: String },
    #[error("no fields given")]
    NoFields,
    #[error("no reason given")]
    NoReason,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompareError {
    #[error("exchange {index} ran `{a}` in one recording and `{b}` in the other")]
    CommandMismatch { index: usize, a: String, b: String },
}
