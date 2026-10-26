//! Typed results of command handlers and continuations, and their
//! conversion to the result value of the reply line.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;

pub use crate::error::CommandError;

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

/// The result of a handler or continuation.
pub type CommandResult = Result<Reply, CommandError>;

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
    use openxbdm_core::status::xbdm_error;
    use openxbdm_core::status::xbdm_success;

    use super::*;

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
