//! Errors of the session commands.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;

use crate::reply::CommandError;

/// Why a call block could not be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcCreateError {
    OutOfMemory,
    /// The call thread could not be created.
    Thread(KernelError),
}

impl From<RpcCreateError> for CommandError {
    fn from(error: RpcCreateError) -> Self {
        match error {
            RpcCreateError::OutOfMemory => ErrorCode::OutOfMemory.into(),
            RpcCreateError::Thread(error) => Self::Kernel(error),
        }
    }
}

/// Why the platform log engine could not be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogEngineError {
    /// The engine or a queue cell could not be allocated.
    OutOfMemory,
    /// A lock-free queue call failed with this result.
    Queue(Hresult),
    /// The worker thread could not be created.
    Thread(KernelError),
}

/// The engine's result word: a kernel status passes unchanged.
impl From<LogEngineError> for Hresult {
    fn from(error: LogEngineError) -> Self {
        match error {
            LogEngineError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            LogEngineError::Queue(result) => result,
            LogEngineError::Thread(error) => Hresult(error.status().0),
        }
    }
}

/// `dmtelllog start` could not start the log engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TellLogFailed(pub LogEngineError);

impl From<TellLogFailed> for Hresult {
    fn from(TellLogFailed(error): TellLogFailed) -> Self {
        // The engine result carries the NT bit as a kernel status would.
        Hresult::from_nt(NtStatus(Hresult::from(error).0))
    }
}
