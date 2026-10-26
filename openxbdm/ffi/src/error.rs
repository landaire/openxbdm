use std::fmt;

use self::ffi::OpenxbdmError;

#[diplomat::bridge]
pub mod ffi {
    use std::fmt::Write;

    use diplomat_runtime::DiplomatWrite;

    /// Error returned by any fallible FFI entry point. Carries a
    /// human-readable message accessible via [`OpenxbdmError::message`].
    #[diplomat::opaque]
    pub struct OpenxbdmError(pub(crate) String);

    impl OpenxbdmError {
        pub fn message(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.0);
        }
    }

    impl OpenxbdmError {
        pub(crate) fn new(message: String) -> Box<Self> {
            Box::new(Self(message))
        }

        pub(crate) fn index_out_of_range(idx: usize) -> Box<Self> {
            Self::new(format!("index {idx} out of range"))
        }
    }
}

/// Failure of a blocking client operation. `Display` is the message handed
/// to foreign callers.
#[derive(Debug)]
pub enum ClientError {
    Runtime(std::io::Error),
    ConnectTimeout {
        address: String,
    },
    Connect {
        address: String,
        source: std::io::Error,
    },
    Poisoned {
        resource: &'static str,
    },
    Protocol(rootcause::Report<openxbdm_client::Error>),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(source) => write!(f, "creating tokio runtime: {source}"),
            Self::ConnectTimeout { address } => write!(f, "connect to {address} timed out"),
            Self::Connect { address, source } => write!(f, "connecting to {address}: {source}"),
            Self::Poisoned { resource } => write!(f, "{resource} mutex poisoned"),
            Self::Protocol(report) => write!(f, "{}", report.current_context()),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<rootcause::Report<openxbdm_client::Error>> for ClientError {
    fn from(report: rootcause::Report<openxbdm_client::Error>) -> Self {
        Self::Protocol(report)
    }
}

impl From<ClientError> for Box<OpenxbdmError> {
    fn from(error: ClientError) -> Self {
        OpenxbdmError::new(error.to_string())
    }
}
