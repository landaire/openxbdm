//! Error types shared across the server.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;

/// Why a handler or continuation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandError {
    /// A status of the monitor's result table.
    Status(ErrorCode),
    /// `400-` without default text.
    Fail,
    /// `400- unexpected error`.
    Unexpected,
    /// `400- out of memory`.
    OutOfMemory,
    /// `400- bad parameter`.
    InvalidArgument,
    /// The end of a 202 or 203 transfer, or of a list.
    EndOfData,
    /// A kernel status as an NT-facility result.
    Kernel(KernelError),
    /// A Win32 error as a Win32-facility result.
    Win32(Win32Error),
    /// A failed `dmtelllog start`.
    TellLog(crate::commands::session::TellLogFailed),
    /// A console failure outside the result table.
    Console(crate::commands::console::ConsoleError),
    /// A refused execution state change.
    Execution(crate::commands::debugger::ExecutionError),
    /// A failed debugger extension load or release.
    Extension(crate::commands::debugger::ExtensionError),
    /// A memory domain failure.
    Memory(crate::commands::memory::MemoryError),
    /// A network domain failure.
    Network(crate::commands::network::NetworkError),
    /// A failed capture operation.
    Capture(crate::commands::performance::capture::CaptureError),
    /// A failed performance counter query.
    Counter(crate::commands::performance::counters::CounterError),
    /// A failed CPU profiler operation.
    Profiler(crate::commands::performance::profiler::ProfilerError),
    /// A failed `vd` request.
    Display(crate::commands::performance::DisplayError),
    /// A failed `flash` programming.
    Flash(crate::commands::system::FlashFailed),
    /// A hardware domain failure outside the result table.
    Hardware(crate::commands::hardware::HardwareError),
    /// Another failure result of an external command processor, sent
    /// unchanged.
    Processor(Hresult),
    /// The thread of a dispatch flag 0x4 command could not be created or
    /// waited for; the monitor returns the status unchanged.
    CommandThread(NtStatus),
}

impl CommandError {
    /// The monitor's mapping of a failed kernel call to a reply. Statuses
    /// without a mapping take `fallback`; a missing path reports 430 only
    /// when the fallback is 413.
    pub fn from_kernel(error: KernelError, fallback: Self) -> Self {
        match error {
            KernelError::InvalidHandle => Self::InvalidArgument,
            KernelError::AccessDenied => Self::Status(ErrorCode::AccessDenied),
            KernelError::ObjectNameInvalid | KernelError::ObjectPathInvalid => {
                Self::Status(ErrorCode::FilenameInvalid)
            }
            KernelError::ObjectNameNotFound | KernelError::FileIsADirectory => {
                Self::Status(ErrorCode::FileNotFound)
            }
            KernelError::ObjectNameCollision => Self::Status(ErrorCode::FileAlreadyExists),
            KernelError::ObjectPathNotFound
                if fallback == Self::Status(ErrorCode::FileCannotBeCreated) =>
            {
                Self::Status(ErrorCode::PathNotFound)
            }
            KernelError::ObjectPathNotFound => Self::Status(ErrorCode::FileNotFound),
            KernelError::DiskFull => Self::Status(ErrorCode::NoRoomOnDevice),
            KernelError::InsufficientResources => Self::OutOfMemory,
            KernelError::DirectoryNotEmpty => Self::Status(ErrorCode::DirectoryNotEmpty),
            _ => fallback,
        }
    }
}

impl From<ErrorCode> for CommandError {
    fn from(code: ErrorCode) -> Self {
        Self::Status(code)
    }
}

impl From<CommandError> for Hresult {
    #[inline(never)]
    fn from(error: CommandError) -> Self {
        match error {
            CommandError::Status(code) => code.hresult(),
            CommandError::Fail => Hresult::FAIL,
            CommandError::Unexpected => Hresult::UNEXPECTED,
            CommandError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            CommandError::InvalidArgument => Hresult::INVALID_ARGUMENT,
            CommandError::EndOfData => Hresult::END_OF_DATA,
            CommandError::Kernel(error) => error.into(),
            CommandError::Win32(error) => error.into(),
            CommandError::TellLog(error) => error.into(),
            CommandError::Console(error) => error.into(),
            CommandError::Execution(error) => error.into(),
            CommandError::Extension(error) => error.into(),
            CommandError::Memory(error) => error.into(),
            CommandError::Network(error) => error.into(),
            CommandError::Capture(error) => error.into(),
            CommandError::Counter(error) => error.into(),
            CommandError::Profiler(error) => error.into(),
            CommandError::Display(error) => error.into(),
            CommandError::Flash(error) => error.into(),
            CommandError::Hardware(error) => error.into(),
            CommandError::Processor(result) => result,
            CommandError::CommandThread(status) => Hresult(status.0),
        }
    }
}

/// Failure of a socket operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// The peer closed the connection or the socket failed.
    Closed,
    /// A non-blocking operation could not proceed.
    WouldBlock,
    /// No resources for a new socket.
    Exhausted,
}

#[cfg(test)]
mod tests {
    use openxbdm_core::status::NtStatus;

    use super::*;

    #[test]
    fn missing_path_maps_by_fallback() {
        let missing = KernelError::from_status(NtStatus(0xc000_003a)).unwrap();
        let create = CommandError::Status(ErrorCode::FileCannotBeCreated);
        assert_eq!(
            CommandError::from_kernel(missing, create),
            CommandError::Status(ErrorCode::PathNotFound)
        );
        assert_eq!(
            CommandError::from_kernel(missing, CommandError::Fail),
            CommandError::Status(ErrorCode::FileNotFound)
        );
    }
}
