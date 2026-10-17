//! Debug output capture: `dbgprint` and `spew`.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::XbdmHresult;

use super::Continuation;
use crate::backend::Backend as AnyBackend;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::text::Text;

/// Bytes of the debug capture ring.
pub const DEBUG_CAPTURE_SIZE: usize = 0x8000;

/// Write and read positions of the debug capture ring. The ring holds
/// messages back to back; a NUL follows the newest one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct DebugCapture {
    write: usize,
    /// Shared by every connection.
    read: usize,
}

impl DebugCapture {
    /// Find the record at the read cursor: bytes up to and including an LF,
    /// or `RECORD_LIMIT` bytes, before a NUL or the ring end. Reaching a NUL
    /// beyond the write position restarts once at the ring start. The
    /// monitor loops forever when the restarted scan meets a NUL without an
    /// LF before it; the stream ends there instead.
    fn next_record(&mut self, ring: &[u8; DEBUG_CAPTURE_SIZE]) -> Option<(usize, usize)> {
        /// A record ends after this many bytes when no LF ends it first; the
        /// continuation buffer holds 0x100 bytes and the reader is given one
        /// less, but stops only after copying one byte more.
        const RECORD_LIMIT: usize = 0x100;

        let mut start = self.read;
        let mut position = start;
        let mut restarted = false;

        loop {
            while position < DEBUG_CAPTURE_SIZE && ring[position] != 0 {
                position += 1;
                if ring[position - 1] == b'\n' || position - start >= RECORD_LIMIT {
                    self.read = position;
                    return Some((start, position));
                }
            }

            if position <= self.write {
                self.read = position;
                return None;
            }

            if restarted {
                self.read = 0;
                return None;
            }

            restarted = true;
            start = 0;
            position = 0;
        }
    }
}

/// `dbgprint start=` | `stop=` | `[reset=]`: control the debug capture ring
/// or stream its records.
pub(super) fn debug_print(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(ErrorCode::BadParameter.into());
    }

    let state = &mut invocation.state.session;
    if invocation.line.param("start").is_some() {
        if state.capture.is_some() {
            invocation.text.set_bytes(b"Debug capture already started");
            return Err(CommandError::Fail);
        }

        let result = if invocation.backend.allocate_debug_capture() {
            if let Some(ring) = invocation.backend.debug_capture() {
                ring[0] = 0;
            }

            state.capture = Some(DebugCapture::default());
            Ok(Reply::Ok)
        } else {
            Err(ErrorCode::OutOfMemory.into())
        };

        invocation
            .text
            .set_bytes(reply::hresult(result).default_message().as_bytes());
        return result;
    }

    if invocation.line.param("stop").is_some() {
        if state.capture.take().is_some() {
            invocation.backend.free_debug_capture();
        }

        invocation.text.set_bytes(b"OK");
        return Ok(Reply::Ok);
    }

    let Some(capture) = state.capture.as_mut() else {
        invocation
            .text
            .set_bytes(b"Debug capture not started (use 'start' option to start capture)");
        return Err(CommandError::Fail);
    };

    if invocation.line.param("reset").is_some() {
        capture.read = 0;
    }

    if let Some(session) = invocation.session.as_deref_mut() {
        session.continuation = AnyContinuation::Session(Continuation::DebugPrint);
    }

    invocation.text.set_bytes(b"Debug print strings follow");

    Ok(Reply::Multiline)
}

/// Send the next capture record without its trailing LF.
pub(super) fn debug_print_record(cx: &mut ContinuationContext<'_>) -> CommandResult {
    let Some(capture) = cx.state.session.capture.as_mut() else {
        return Err(CommandError::EndOfData);
    };

    let Some(ring) = cx.backend.debug_capture() else {
        return Err(CommandError::EndOfData);
    };

    let Some((start, end)) = capture.next_record(ring) else {
        return Err(CommandError::EndOfData);
    };

    let record = &ring[start..end];
    let record = record.strip_suffix(b"\n").unwrap_or(record);
    cx.line.set_bytes(record);

    Ok(Reply::Ok)
}

/// Append a message to the debug capture ring when capture is active. The
/// message is cut to 0x1ff bytes and stored with a NUL that the next
/// message overwrites; a message that does not fit before the ring end is
/// stored at the ring start.
pub fn debug_capture_print(state: &mut ServerState, backend: &mut dyn AnyBackend, message: &[u8]) {
    /// Longest message the ring stores.
    const MESSAGE_LIMIT: usize = 0x1ff;

    let Some(capture) = state.session.capture.as_mut() else {
        return;
    };

    let Some(ring) = backend.debug_capture() else {
        return;
    };

    let length = message.len().min(MESSAGE_LIMIT);
    let offset = if capture.write + length + 1 >= DEBUG_CAPTURE_SIZE {
        0
    } else {
        capture.write
    };

    ring[offset..offset + length].copy_from_slice(&message[..length]);
    ring[offset + length] = 0;
    capture.write = offset + length;
}

/// `spew <text>`: write the command line to the debug output.
pub(super) fn spew(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut output = Text::<{ crate::server::RECEIVE_CAPACITY + 8 }>::new();
    let _ = output.push_bytes(b"SPEW: ");
    let _ = output.push_bytes(invocation.line.as_bytes());
    let _ = output.push_bytes(b"\n");
    invocation.backend.debug_print(output.as_bytes());
    invocation.text.set_bytes(b"OK");

    Ok(Reply::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_records_split_at_lf_and_wrap_once() {
        let mut ring = [0u8; DEBUG_CAPTURE_SIZE];
        ring[..9].copy_from_slice(b"a\nbc\nde\n\0");
        let mut capture = DebugCapture { write: 8, read: 0 };
        assert_eq!(capture.next_record(&ring), Some((0, 2)));
        assert_eq!(capture.next_record(&ring), Some((2, 5)));
        assert_eq!(capture.next_record(&ring), Some((5, 8)));
        assert_eq!(capture.next_record(&ring), None);
        assert_eq!(capture.read, 8);

        // A NUL past the write position restarts the scan at the ring start.
        let mut capture = DebugCapture {
            write: 2,
            read: 0x7000,
        };

        assert_eq!(capture.next_record(&ring), Some((0, 2)));
    }

    #[test]
    fn capture_records_without_lf_end_after_0x100_bytes() {
        let mut ring = [0u8; DEBUG_CAPTURE_SIZE];
        ring[..0x180].fill(b'x');
        let mut capture = DebugCapture {
            write: 0x180,
            read: 0,
        };

        assert_eq!(capture.next_record(&ring), Some((0, 0x100)));
        assert_eq!(capture.next_record(&ring), None);
    }
}
