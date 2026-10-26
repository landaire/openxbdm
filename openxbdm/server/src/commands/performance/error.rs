//! Errors of the performance commands.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;

use crate::commands::console::BufferTooSmall;
use crate::reply::CommandError;

/// A failed `vd` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayError {
    BadParameter,
    /// The extended video encoder banks are absent.
    MemoryNotMapped,
    /// The kernel lacks the EDID export.
    Unsupported,
    EdidFailed,
    /// No transfer block holds the EDID block.
    NoTransferBlock,
}

impl From<DisplayError> for Hresult {
    fn from(error: DisplayError) -> Self {
        match error {
            DisplayError::BadParameter => ErrorCode::BadParameter.hresult(),
            DisplayError::MemoryNotMapped => ErrorCode::MemoryNotMapped.hresult(),
            DisplayError::Unsupported => ErrorCode::UnknownCommand.hresult(),
            DisplayError::EdidFailed => Hresult::NO_RESPONSE,
            DisplayError::NoTransferBlock => BufferTooSmall.into(),
        }
    }
}

impl From<DisplayError> for CommandError {
    fn from(error: DisplayError) -> Self {
        CommandError::Display(error)
    }
}

/// A failed capture operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureError {
    /// The capture file cannot be created.
    FileFailed,
    FastCapDisabled,
    CallCapDisabled,
    /// No capture buffers exist, or the capture is stopped.
    NoCapture,
    AlreadyRunning,
    NoBufferMemory,
    TitleCaptureFailed,
    NotInstrumented,
    CallCapUnavailable,
    /// A processor ran out of buffer space.
    BufferFull,
    TitleTerminated,
    /// The capture ran longer than the 29-bit record timestamps cover.
    TooLong,
    CountersUnavailable,
    CountersLost,
    /// Another start or stop holds the engine.
    Busy,
    /// The kernel call-cap service failed.
    Kernel(KernelError),
    /// The capture file writer failed.
    Write(Win32Error),
    /// Failure result of a title that runs the capture.
    Title(Hresult),
}

impl From<CaptureError> for Hresult {
    #[inline(never)]
    fn from(error: CaptureError) -> Self {
        match error {
            CaptureError::FileFailed => ErrorCode::FileCannotBeCreated.hresult(),
            CaptureError::FastCapDisabled => Hresult::FAST_CAP_DISABLED,
            CaptureError::CallCapDisabled => Hresult::CALL_CAP_DISABLED,
            CaptureError::NoCapture => Hresult::NOT_STARTED,
            CaptureError::AlreadyRunning => Hresult::ALREADY_STARTED,
            CaptureError::NoBufferMemory => ErrorCode::OutOfMemory.hresult(),
            CaptureError::TitleCaptureFailed => Hresult::NO_RESPONSE,
            CaptureError::NotInstrumented => Hresult::CAPTURE_NOT_ENABLED,
            CaptureError::CallCapUnavailable => Hresult::CALL_CAP_UNAVAILABLE,
            CaptureError::BufferFull => Hresult::BUFFER_FULL,
            CaptureError::TitleTerminated => Hresult::TITLE_TERMINATED,
            CaptureError::TooLong => Hresult::DURATION_EXCEEDED,
            CaptureError::CountersUnavailable => Hresult::NOT_ACQUIRED,
            CaptureError::CountersLost => Hresult::NOT_OWNER,
            CaptureError::Busy => Win32Error::BUSY.into(),
            CaptureError::Kernel(error) => error.into(),
            CaptureError::Write(error) => error.into(),
            CaptureError::Title(result) => result,
        }
    }
}

impl From<CaptureError> for CommandError {
    fn from(error: CaptureError) -> Self {
        CommandError::Capture(error)
    }
}

/// A failed counter enumeration, open, or query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterError {
    /// The query does not match the counter type.
    TypeInvalid,
    /// No sample is available.
    DataNotAvailable,
    /// Failure result of the counter's reader or query routine.
    Routine(Hresult),
    /// The process has no counter directory.
    NoDirectory,
    /// The counter cannot be opened.
    NotFound,
    /// The counter object cannot be referenced.
    Kernel(KernelError),
    /// The end of the counter directory.
    End,
    /// A directory entry does not fit the enumeration buffer.
    NameTooLong,
    /// An enumerated counter cannot be opened.
    Unexpected,
}

impl From<CounterError> for CommandError {
    fn from(error: CounterError) -> Self {
        match error {
            CounterError::Kernel(error) => CommandError::from_kernel(error, CommandError::Fail),
            CounterError::End => CommandError::EndOfData,
            CounterError::Unexpected => CommandError::Unexpected,
            error => CommandError::Counter(error),
        }
    }
}

impl From<CounterError> for Hresult {
    #[inline(never)]
    fn from(error: CounterError) -> Self {
        match error {
            CounterError::TypeInvalid => ErrorCode::TypeInvalid.hresult(),
            CounterError::DataNotAvailable => ErrorCode::DataNotAvailable.hresult(),
            CounterError::Routine(result) => result,
            CounterError::NoDirectory => ErrorCode::FileNotFound.hresult(),
            CounterError::NotFound => ErrorCode::AccessDenied.hresult(),
            CounterError::NameTooLong => Hresult::BUFFER_TOO_SMALL,
            CounterError::Kernel(_) | CounterError::End | CounterError::Unexpected => {
                CommandError::from(error).into()
            }
        }
    }
}

/// A failed profiler operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfilerError {
    AlreadyRunning,
    NotRunning,
    /// `info` after a title ended while profiling.
    Suspended,
    /// The engine could not start its file writer thread (stock 0x91f90258).
    PrologueFailed,
    /// The kernel module cannot be found.
    NoKernel,
    /// The kernel lacks a profile interrupt export.
    NoProfileExport,
    /// The kernel refused to enable the profile interrupt.
    ProfileInterruptRefused,
    /// The sample buffers cannot be allocated.
    NoBuffers,
    /// The performance counters cannot be acquired or started.
    NoCounters,
    /// Another owner holds the performance counters.
    NotCounterOwner,
}

impl From<ProfilerError> for Hresult {
    fn from(error: ProfilerError) -> Self {
        match error {
            ProfilerError::AlreadyRunning => Hresult::ALREADY_STARTED,
            ProfilerError::NotRunning => Hresult::NOT_STARTED,
            ProfilerError::Suspended => Hresult::TITLE_TERMINATED,
            ProfilerError::PrologueFailed => ErrorCode::Undefined.hresult(),
            ProfilerError::NoKernel => ErrorCode::NoSuchModule.hresult(),
            ProfilerError::NoProfileExport => ErrorCode::UnknownCommand.hresult(),
            ProfilerError::ProfileInterruptRefused => ErrorCode::BadParameter.hresult(),
            ProfilerError::NoBuffers => ErrorCode::OutOfMemory.hresult(),
            ProfilerError::NoCounters => Hresult::NOT_ACQUIRED,
            ProfilerError::NotCounterOwner => Hresult::NOT_OWNER,
        }
    }
}

impl From<ProfilerError> for CommandError {
    fn from(error: ProfilerError) -> Self {
        CommandError::Profiler(error)
    }
}

/// A failed transport routine or request, as the studio service receives
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StudioError {
    /// The request is still queued.
    Pending,
    /// The connection is closed.
    NotConnected,
    /// Removed by a cancel or a disconnect.
    Aborted,
    /// No request slot or memory is free.
    OutOfMemory,
    /// A message longer than the receive buffer, or an unknown request.
    InvalidArgument,
    NotImplemented,
    Fail,
}

impl From<StudioError> for Hresult {
    fn from(error: StudioError) -> Self {
        match error {
            StudioError::Pending => Hresult::PENDING,
            StudioError::NotConnected => Hresult::NO_INTERFACE,
            StudioError::Aborted => Hresult::ABORT,
            StudioError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            StudioError::InvalidArgument => Hresult::INVALID_ARGUMENT,
            StudioError::NotImplemented => Hresult::NOT_IMPLEMENTED,
            StudioError::Fail => Hresult::FAIL,
        }
    }
}
