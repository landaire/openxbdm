use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_server::commands::performance::counters::CounterError;
use openxbdm_server::reply::CommandError;

/// A failed counter registration (stock export 33).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RegisterError {
    /// The process has no counter directory.
    NoDirectory,
    /// The sampling period exceeds
    /// [`openxbdm_server::commands::performance::counters::MAX_PERIOD`].
    PeriodTooLong,
    Kernel(KernelError),
}

impl From<RegisterError> for Hresult {
    fn from(error: RegisterError) -> Self {
        match error {
            RegisterError::NoDirectory => Hresult::OUT_OF_MEMORY,
            RegisterError::PeriodTooLong => CounterError::TypeInvalid.into(),
            RegisterError::Kernel(error) => {
                CommandError::from_kernel(error, CommandError::Fail).into()
            }
        }
    }
}

/// A failed memory statistics query (stock export 75).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatisticsError {
    /// The block's length word is not
    /// [`MONITOR_STATISTICS_LENGTH`](super::counters::MONITOR_STATISTICS_LENGTH).
    BadLength,
    Kernel(KernelError),
}

impl From<StatisticsError> for Hresult {
    fn from(error: StatisticsError) -> Self {
        match error {
            StatisticsError::BadLength => Hresult::INVALID_ARGUMENT,
            StatisticsError::Kernel(error) => error.into(),
        }
    }
}
