use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    #[error("could not open controller script {path:?}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse controller script {path:?}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("controller script contains no frames")]
    Empty,
    #[error("controller script contains {count} frames, exceeding the limit {maximum}")]
    TooManyFrames { count: usize, maximum: u32 },
    #[error("frame {index} has a zero duration")]
    ZeroDuration { index: usize },
    #[error("frame {index} duration {duration_ms} ms exceeds the timer limit {maximum_ms} ms")]
    DurationOutOfRange {
        index: usize,
        duration_ms: u32,
        maximum_ms: u32,
    },
    #[error("frame {index} {field} value {value} is outside {minimum}..={maximum}")]
    ValueOutOfRange {
        index: usize,
        field: &'static str,
        value: f32,
        minimum: f32,
        maximum: f32,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[cfg(not(target_os = "macos"))]
    #[error("could not initialize the host controller service")]
    Initialize(#[source] gilrs::Error),
    #[error("selected controller is no longer connected")]
    NotConnected,
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error(transparent)]
    Controller(#[from] ControllerError),
    #[error(transparent)]
    Script(#[from] ScriptError),
    #[error("could not create the network runtime")]
    Runtime(#[source] std::io::Error),
    #[error("console operation failed: {report}")]
    Console {
        report: rootcause::Report<openxbdm_client::Error>,
    },
    #[error("controller script was only partly queued: {accepted} of {requested} frames")]
    PartialScript { accepted: u32, requested: u32 },
    #[error("relay operation {operation} timed out")]
    Timeout { operation: &'static str },
    #[error("relay was cancelled")]
    Cancelled,
    #[error("relay worker stopped unexpectedly")]
    WorkerPanicked,
}
