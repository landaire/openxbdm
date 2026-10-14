//! Continuations of 202, 203, and 204 transfers.
//!
//! A handler stores a continuation in its session and returns
//! [`Hresult::MULTILINE`], [`Hresult::BINARY`], or [`Hresult::SEND_BINARY`].
//! The server then calls the continuation once per socket event:
//!
//! - 202: write one line into [`ContinuationContext::line`]. A continuation
//!   that produces several lines at once writes them, each ending in CR LF,
//!   into [`ContinuationContext::binary`] and sets
//!   [`ContinuationContext::binary_len`]; those bytes are sent unchanged
//!   instead of the line. Return [`Hresult::END_OF_DATA`] to end with `.`.
//! - 203: fill [`ContinuationContext::binary`] and set
//!   [`ContinuationContext::binary_len`]; return [`Hresult::END_OF_DATA`] to
//!   end. Data written by the final call is not sent.
//! - 204: consume [`ContinuationContext::received`] and decrement
//!   `session.receive_remaining`. When it reaches zero, the result selects
//!   the next step and the reply text comes from [`ContinuationContext::line`].
//!
//! Any other failure closes the connection.

use openxbdm_core::status::Hresult;

use crate::backend::Backend;
use crate::commands;
use crate::invocation::Session;
use crate::network::Network;
use crate::processors::ExternalContinuation;
use crate::processors::ExternalTransfer;
use crate::processors::ProcessorProgress;
use crate::state::ServerState;
use crate::text::LineText;

/// State of an in-progress transfer.
// Continuations live in place in each connection; the core does not
// allocate, so large variants cannot be boxed.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Default)]
pub enum Continuation {
    #[default]
    None,
    Session(commands::session::Continuation),
    Security(commands::security::Continuation),
    Console(commands::console::Continuation),
    System(commands::system::Continuation),
    FileSystem(commands::filesystem::Continuation),
    Memory(commands::memory::Continuation),
    Debugger(commands::debugger::Continuation),
    Network(commands::network::Continuation),
    Performance(commands::performance::Continuation),
    Hardware(commands::hardware::Continuation),
    Services(commands::services::Continuation),
    /// Transfer of an external command processor.
    External(ExternalContinuation),
}

impl Continuation {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// What a continuation call receives.
pub struct ContinuationContext<'a> {
    /// One 202 line, or the reply text after a 204 upload.
    pub line: &'a mut LineText,
    /// Output buffer of a 203 transfer or of raw 202 output. Its content
    /// persists between calls.
    pub binary: &'a mut [u8],
    /// Bytes of `binary` to send after this call.
    pub binary_len: usize,
    /// Set by a 202 call that produced nothing to send for this event.
    pub no_output: bool,
    /// Set when an external continuation runs on another thread; the
    /// result is not final and nothing is sent until it ends.
    pub processor_running: bool,
    /// Bytes received for a 204 upload in this call.
    pub received: &'a [u8],
    /// Set when the peer stopped accepting 203 data; the transfer ends after
    /// this call.
    pub aborted: bool,
    pub session: &'a mut Session,
    pub state: &'a mut ServerState,
    pub backend: &'a mut dyn Backend,
    pub network: &'a mut dyn Network,
}

/// Call the active continuation.
pub(crate) fn resume(continuation: &mut Continuation, cx: &mut ContinuationContext<'_>) -> Hresult {
    match continuation {
        Continuation::None => Hresult::UNEXPECTED,
        Continuation::Session(state) => commands::session::resume(state, cx),
        Continuation::Security(state) => commands::security::resume(state, cx),
        Continuation::Console(state) => commands::console::resume(state, cx),
        Continuation::System(state) => commands::system::resume(state, cx),
        Continuation::FileSystem(state) => commands::filesystem::resume(state, cx),
        Continuation::Memory(state) => commands::memory::resume(state, cx),
        Continuation::Debugger(state) => commands::debugger::resume(state, cx),
        Continuation::Network(state) => commands::network::resume(state, cx),
        Continuation::Performance(state) => commands::performance::resume(state, cx),
        Continuation::Hardware(state) => commands::hardware::resume(state, cx),
        Continuation::Services(state) => commands::services::resume(state, cx),
        Continuation::External(state) => {
            let transfer = ExternalTransfer {
                line: cx.line,
                binary: cx.binary,
                binary_len: &mut cx.binary_len,
                no_output: &mut cx.no_output,
                received: cx.received,
                receive_remaining: &mut cx.session.receive_remaining,
                aborted: cx.aborted,
            };
            match cx.backend.resume_processor(state, transfer) {
                ProcessorProgress::Complete(result) => result,
                ProcessorProgress::Unavailable => Hresult::FAIL,
                ProcessorProgress::Running => {
                    cx.processor_running = true;
                    Hresult::OK
                }
            }
        }
    }
}
