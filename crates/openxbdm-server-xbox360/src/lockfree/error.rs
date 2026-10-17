use openxbdm_core::status::Hresult;
use openxbdm_core::status::Win32Error;
use xbox360_sys::status::Facility;

/// Failure of a container operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    /// A container, record or argument is not valid.
    InvalidArgument,
    /// The allocator returned no memory.
    NotEnoughMemory,
    /// No node or item in time, or a wait that timed out.
    Timeout,
    /// A sorted container with unique keys already holds the key.
    DuplicateKey,
    /// Another wait status or caller wait routine result.
    Wait(Win32Error),
    /// The first nonzero result of an enumeration callback.
    Callback(Win32Error),
}

impl Error {
    /// Facility of the container result codes.
    pub(super) const FACILITY: Facility = Facility::new(0x31);
    /// An insertion found no free node in time, or its unique key present.
    const INSERT_TIMEOUT: Hresult = Hresult::failure(Self::FACILITY, 1);

    /// Outcome of a wait status or caller wait routine result; stock
    /// treats both as Win32 codes.
    pub(super) fn of_wait(status: u32) -> Result<(), Self> {
        match Win32Error::new(status) {
            None => Ok(()),
            Some(error) if error == Win32Error::WAIT_TIMEOUT => Err(Self::Timeout),
            Some(error) => Err(Self::Wait(error)),
        }
    }

    /// Export result of a failed insertion.
    pub(crate) fn insert_result(self) -> Hresult {
        match self {
            Self::Timeout | Self::DuplicateKey => Self::INSERT_TIMEOUT,
            error => error.into(),
        }
    }

    /// Export result of a failed removal.
    pub(super) fn remove_result(self) -> Hresult {
        /// A removal found no item in time.
        const REMOVE_TIMEOUT: Hresult = Hresult::failure(Error::FACILITY, 2);

        match self {
            Self::Timeout => REMOVE_TIMEOUT,
            error => error.into(),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidArgument => f.write_str("invalid container or argument"),
            Self::NotEnoughMemory => f.write_str("not enough memory"),
            Self::Timeout => f.write_str("timed out"),
            Self::DuplicateKey => f.write_str("key already present"),
            Self::Wait(error) => write!(f, "wait failed with {:#x}", error.code()),
            Self::Callback(error) => write!(f, "callback failed with {:#x}", error.code()),
        }
    }
}

impl core::error::Error for Error {}

/// HRESULT of an operation without a timeout result of its own.
impl From<Error> for Hresult {
    fn from(error: Error) -> Self {
        match error {
            // Equal to HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER).
            Error::InvalidArgument => Self::INVALID_ARGUMENT,
            Error::NotEnoughMemory => Win32Error::NOT_ENOUGH_MEMORY.into(),
            Error::Timeout => Win32Error::WAIT_TIMEOUT.into(),
            Error::DuplicateKey => Error::INSERT_TIMEOUT,
            Error::Wait(error) | Error::Callback(error) => error.into(),
        }
    }
}
