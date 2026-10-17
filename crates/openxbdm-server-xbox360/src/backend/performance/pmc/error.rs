use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;

/// Why a counter export failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PmcError {
    /// The counters could not be acquired.
    NotAcquired,
    /// Another owner holds the counters.
    NotOwner,
}

impl PmcError {
    /// `Err(self)` unless `succeeded`.
    pub(super) fn unless(self, succeeded: bool) -> Result<(), Self> {
        if succeeded { Ok(()) } else { Err(self) }
    }
}

impl From<PmcError> for Hresult {
    fn from(error: PmcError) -> Self {
        match error {
            PmcError::NotAcquired => Hresult::NOT_ACQUIRED,
            PmcError::NotOwner => Hresult::NOT_OWNER,
        }
    }
}

impl core::fmt::Display for PmcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotAcquired => "the performance counters could not be acquired",
            Self::NotOwner => "another owner holds the performance counters",
        })
    }
}

impl core::error::Error for PmcError {}
