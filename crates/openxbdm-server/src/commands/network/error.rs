use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;

use crate::commands::network::netcap;
use crate::commands::network::netsim;
use crate::reply::CommandError;

/// `linkstate setflags` without both masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingLinkMask;

impl From<MissingLinkMask> for CommandError {
    fn from(_: MissingLinkMask) -> Self {
        ErrorCode::BadParameter.into()
    }
}

/// A failed network command as its status reports it. A result of the
/// monitor facility keeps its value; any other reads as 0x82da0000, the
/// common exit of the stock handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    Netsim(netsim::NetsimError),
    CaptureStart(netcap::StartError),
    /// `ipproxy stop` without a running proxy (426, no default text).
    ProxyNotStarted,
    /// `netcap stop` without a capture (435, no default text).
    NotCapturing,
    /// Frames were lost to a full capture write buffer.
    FramesLost,
    /// A certificate upload was cut short by the connection.
    UploadAborted,
}

impl From<NetworkError> for Hresult {
    #[inline(never)]
    fn from(error: NetworkError) -> Self {
        let result = match error {
            NetworkError::Netsim(error) => error.into(),
            NetworkError::CaptureStart(error) => error.into(),
            NetworkError::ProxyNotStarted => Hresult::ALREADY_STOPPED,
            NetworkError::NotCapturing => Hresult::CAPTURE_NOT_ENABLED,
            NetworkError::FramesLost => Hresult::BUFFER_FULL,
            NetworkError::UploadAborted => Hresult::CONNECTION_LOST,
        };

        if result.facility() == Hresult::OK.facility() {
            result
        } else {
            ErrorCode::Undefined.hresult()
        }
    }
}

impl From<NetworkError> for CommandError {
    fn from(error: NetworkError) -> Self {
        Self::Network(error)
    }
}

/// Why a table snapshot failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableError {
    /// The network stack does not provide the table or refused the query.
    Unavailable,
    /// No memory for the snapshot.
    OutOfMemory,
}
