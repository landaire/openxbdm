//! Typed results of command handlers and continuations, and their
//! conversion to the result value of the reply line.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;

/// What a handler or continuation reports when it succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Result 0. After a handler no status line follows: the handler sent
    /// its own reply or closed the connection. After a 204 upload the
    /// line is `200-`.
    Sent,
    /// `200`.
    Ok,
    /// `202`: the session continuation produces the lines.
    Multiline,
    /// `203`: the session continuation produces the data.
    Binary,
    /// `204`: the session continuation consumes the data.
    SendBinary,
    /// `205` from an external command processor: the connection is
    /// dedicated to it.
    Dedicated,
    /// `209`.
    FastPipe,
    /// A `dmtelllog` result.
    TellLog(crate::commands::session::TellLogReply),
    /// A success result of the capture interface.
    Capture(crate::commands::performance::capture::CaptureReply),
    /// Another success result of an external command processor or a
    /// title capture, sent unchanged.
    Processor(Hresult),
}

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
}

/// The result of a handler or continuation.
pub type CommandResult = Result<Reply, CommandError>;

impl From<ErrorCode> for CommandError {
    fn from(code: ErrorCode) -> Self {
        Self::Status(code)
    }
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
        }
    }
}

impl From<Reply> for Hresult {
    fn from(reply: Reply) -> Self {
        match reply {
            Reply::Sent => Hresult::NO_REPLY,
            Reply::Ok => Hresult::OK,
            Reply::Multiline => Hresult::MULTILINE,
            Reply::Binary => Hresult::BINARY,
            Reply::SendBinary => Hresult::SEND_BINARY,
            Reply::Dedicated => Hresult::DEDICATED,
            Reply::FastPipe => Hresult::FAST_PIPE,
            Reply::TellLog(reply) => reply.into(),
            Reply::Capture(reply) => reply.into(),
            Reply::Processor(result) => result,
        }
    }
}

/// The result value the reply line and the title ABI carry.
pub fn hresult(result: CommandResult) -> Hresult {
    match result {
        Ok(reply) => reply.into(),
        Err(error) => error.into(),
    }
}

/// The typed form of an external command processor's result. Values
/// without a variant are kept, so [`hresult`] returns `result` unchanged.
pub fn from_processor(result: Hresult) -> CommandResult {
    let reply = match result {
        Hresult::OK => Reply::Ok,
        Hresult::MULTILINE => Reply::Multiline,
        Hresult::BINARY => Reply::Binary,
        Hresult::SEND_BINARY => Reply::SendBinary,
        Hresult::DEDICATED => Reply::Dedicated,
        Hresult::FAST_PIPE => Reply::FastPipe,
        Hresult::FAIL => return Err(CommandError::Fail),
        Hresult::UNEXPECTED => return Err(CommandError::Unexpected),
        Hresult::OUT_OF_MEMORY => return Err(CommandError::OutOfMemory),
        Hresult::INVALID_ARGUMENT => return Err(CommandError::InvalidArgument),
        Hresult::END_OF_DATA => return Err(CommandError::EndOfData),
        failure if failure.is_failure() => {
            return Err(ErrorCode::from_hresult(failure)
                .map_or(CommandError::Processor(failure), Into::into));
        }
        other => Reply::Processor(other),
    };
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use openxbdm_core::status::NtStatus;
    use openxbdm_core::status::xbdm_error;
    use openxbdm_core::status::xbdm_success;

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

    #[test]
    fn processor_results_pass_unchanged() {
        for result in [
            Hresult::SUCCESS,
            Hresult::FALSE,
            Hresult::OK,
            Hresult::MULTILINE,
            Hresult::DEDICATED,
            xbdm_success(0x64),
            ErrorCode::Undefined.hresult(),
            ErrorCode::AccessDenied.hresult(),
            xbdm_error(0x13),
            Hresult::END_OF_DATA,
            Hresult::FAIL,
            Hresult(0x8007_0002),
            Hresult(0xd000_0034),
        ] {
            assert_eq!(hresult(from_processor(result)), result, "{:#x}", result.0);
        }
    }
}
