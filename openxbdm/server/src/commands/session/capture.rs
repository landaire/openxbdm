//! Debug output capture: `dbgprint` and `spew`.

use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::XbdmHresult;

use super::Continuation;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::text::Text;

/// Bytes of the debug capture ring.
pub const DEBUG_CAPTURE_SIZE: usize = 0x8000;

/// A record ends after this many bytes when no LF ends it first; the
/// continuation buffer holds 0x100 bytes and the reader is given one less,
/// but stops only after copying one byte more.
const RECORD_LIMIT: usize = 0x100;

/// The debug capture ring: messages back to back, a NUL after the newest
/// one, and the write offset (stock 0x91f9fdb4). Producers on any processor
/// and at any IRQL reserve space by advancing the offset, so every byte is
/// an atomic.
#[derive(Clone, Copy)]
pub struct DebugCaptureRing<'a> {
    pub bytes: &'a [AtomicU8; DEBUG_CAPTURE_SIZE],
    pub write: &'a AtomicU32,
}

/// Reservation failures the producer reports through DbgPrint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationEvent {
    /// Another producer moved the offset between the reservation past the
    /// ring end and the move to the ring start.
    ResetAttempt { offset: u32, expected: u32 },
    /// Reservations left after a failed reset.
    Retry { remaining: u32 },
    /// The fifth reset failed; the message is dropped.
    Aborted,
}

impl ReservationEvent {
    /// The stock DbgPrint text.
    #[allow(
        clippy::write_with_newline,
        reason = "the format strings are the stock texts verbatim"
    )]
    pub fn write_text(self, text: &mut impl core::fmt::Write) -> core::fmt::Result {
        match self {
            Self::ResetAttempt { offset, expected } => write!(
                text,
                "[dmdbgprn] - DbgPrint reset attempt.  Offset={} (Expect{})\n",
                offset as i32, expected as i32
            ),
            Self::Retry { remaining } => {
                write!(text, "[dmdbgprn] - Retry update (Remain={remaining})\n")
            }
            Self::Aborted => text.write_str("[dmdbgprn] - Reset pointer aborted\n"),
        }
    }
}

impl DebugCaptureRing<'_> {
    /// Append a message (stock producer 0x91f3ebb0). The message is cut to
    /// 0x1ff bytes and stored with a NUL that the next message overwrites.
    /// Space is reserved by adding the length to the write offset; a
    /// reservation that reaches the ring end moves the offset to the length
    /// and stores the message at the ring start, unless another producer
    /// moved the offset first, which is retried up to five reservations in
    /// all. The fifth reservation stores nothing even when it succeeds, as
    /// in the image.
    pub fn print(self, message: &[u8], report: &mut dyn FnMut(ReservationEvent)) {
        /// Longest message the ring stores.
        const MESSAGE_LIMIT: usize = 0x1ff;
        const RESERVATIONS: u32 = 5;

        let length = message.len().min(MESSAGE_LIMIT);
        let reserved = length as u32;
        let mut remaining = RESERVATIONS;
        let offset = loop {
            remaining -= 1;
            let start = self.write.fetch_add(reserved, Ordering::SeqCst);
            let end = start.wrapping_add(reserved);
            if (end as usize) + 1 < DEBUG_CAPTURE_SIZE {
                break start as usize;
            }

            match self
                .write
                .compare_exchange(end, reserved, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break 0,
                Err(offset) => {
                    report(ReservationEvent::ResetAttempt {
                        offset,
                        expected: end,
                    });
                    if remaining == 0 {
                        report(ReservationEvent::Aborted);
                        return;
                    }

                    report(ReservationEvent::Retry { remaining });
                }
            }
        };

        if remaining == 0 {
            return;
        }

        let bytes = &self.bytes[offset..=offset + length];
        for (slot, &byte) in bytes.iter().zip(&message[..length]) {
            slot.store(byte, Ordering::Relaxed);
        }
        bytes[length].store(0, Ordering::Relaxed);
    }

    fn byte(self, position: usize) -> u8 {
        self.bytes[position].load(Ordering::Relaxed)
    }
}

/// Read cursor of the debug capture ring, shared by every connection
/// (stock 0x91f9fdb8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct DebugCapture {
    read: usize,
}

impl DebugCapture {
    /// Find the record at the read cursor: bytes up to and including an LF,
    /// or `RECORD_LIMIT` bytes, before a NUL or the ring end. Reaching a NUL
    /// beyond the write position restarts once at the ring start. The
    /// monitor loops forever when the restarted scan meets a NUL without an
    /// LF before it; the stream ends there instead.
    fn next_record(&mut self, ring: DebugCaptureRing<'_>) -> Option<(usize, usize)> {
        let write = ring.write.load(Ordering::SeqCst) as usize;
        let mut start = self.read;
        let mut position = start;
        let mut restarted = false;

        loop {
            while position < DEBUG_CAPTURE_SIZE && ring.byte(position) != 0 {
                position += 1;
                if ring.byte(position - 1) == b'\n' || position - start >= RECORD_LIMIT {
                    self.read = position;
                    return Some((start, position));
                }
            }

            if position <= write {
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

    let mut record = [0u8; RECORD_LIMIT];
    let record = &mut record[..end - start];
    for (byte, slot) in record.iter_mut().zip(&ring.bytes[start..end]) {
        *byte = slot.load(Ordering::Relaxed);
    }
    let record = record.strip_suffix(b"\n").unwrap_or(record);
    cx.line.set_bytes(record);

    Ok(Reply::Ok)
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
    extern crate std;

    use std::boxed::Box;
    use std::string::String;
    use std::vec::Vec;

    use super::*;

    fn ring_with(contents: &[u8]) -> Box<[AtomicU8; DEBUG_CAPTURE_SIZE]> {
        let ring = Box::new([const { AtomicU8::new(0) }; DEBUG_CAPTURE_SIZE]);
        for (slot, &byte) in ring.iter().zip(contents) {
            slot.store(byte, Ordering::Relaxed);
        }

        ring
    }

    fn contents(ring: &[AtomicU8; DEBUG_CAPTURE_SIZE], range: core::ops::Range<usize>) -> Vec<u8> {
        ring[range]
            .iter()
            .map(|slot| slot.load(Ordering::Relaxed))
            .collect()
    }

    #[test]
    fn capture_records_split_at_lf_and_wrap_once() {
        let bytes = ring_with(b"a\nbc\nde\n\0");
        let write = AtomicU32::new(8);
        let ring = DebugCaptureRing {
            bytes: &bytes,
            write: &write,
        };
        let mut capture = DebugCapture { read: 0 };
        assert_eq!(capture.next_record(ring), Some((0, 2)));
        assert_eq!(capture.next_record(ring), Some((2, 5)));
        assert_eq!(capture.next_record(ring), Some((5, 8)));
        assert_eq!(capture.next_record(ring), None);
        assert_eq!(capture.read, 8);

        // A NUL past the write position restarts the scan at the ring start.
        write.store(2, Ordering::Relaxed);
        let mut capture = DebugCapture { read: 0x7000 };

        assert_eq!(capture.next_record(ring), Some((0, 2)));
    }

    #[test]
    fn capture_records_without_lf_end_after_0x100_bytes() {
        let bytes = ring_with(&[b'x'; 0x180]);
        let write = AtomicU32::new(0x180);
        let ring = DebugCaptureRing {
            bytes: &bytes,
            write: &write,
        };
        let mut capture = DebugCapture { read: 0 };

        assert_eq!(capture.next_record(ring), Some((0, 0x100)));
        assert_eq!(capture.next_record(ring), None);
    }

    #[test]
    fn print_appends_with_nul_and_moves_to_the_start_at_the_ring_end() {
        let bytes = ring_with(&[]);
        let write = AtomicU32::new(0);
        let ring = DebugCaptureRing {
            bytes: &bytes,
            write: &write,
        };
        let mut events = Vec::new();

        ring.print(b"ab\n", &mut |event| events.push(event));
        ring.print(b"cd\n", &mut |event| events.push(event));
        assert_eq!(contents(&bytes, 0..7), b"ab\ncd\n\0");
        assert_eq!(write.load(Ordering::Relaxed), 6);

        // Offset + length + 1 reaching the ring size stores at the start.
        write.store(DEBUG_CAPTURE_SIZE as u32 - 4, Ordering::Relaxed);
        ring.print(b"xyz", &mut |event| events.push(event));
        assert_eq!(contents(&bytes, 0..4), b"xyz\0");
        assert_eq!(write.load(Ordering::Relaxed), 3);

        // One byte less fits before the end.
        write.store(DEBUG_CAPTURE_SIZE as u32 - 5, Ordering::Relaxed);
        ring.print(b"xyz", &mut |event| events.push(event));
        assert_eq!(
            contents(&bytes, DEBUG_CAPTURE_SIZE - 5..DEBUG_CAPTURE_SIZE - 1),
            b"xyz\0"
        );
        assert_eq!(write.load(Ordering::Relaxed), DEBUG_CAPTURE_SIZE as u32 - 2);
        assert!(events.is_empty());
    }

    #[test]
    fn print_cuts_messages_at_0x1ff_bytes() {
        let bytes = ring_with(&[0xff; 0x210]);
        let write = AtomicU32::new(0);
        let ring = DebugCaptureRing {
            bytes: &bytes,
            write: &write,
        };

        ring.print(&[b'm'; 0x300], &mut |_| unreachable!());
        assert_eq!(write.load(Ordering::Relaxed), 0x1ff);
        assert_eq!(contents(&bytes, 0x1fe..0x201), [b'm', 0, 0xff]);
    }

    #[test]
    fn reservation_texts() {
        let mut text = String::new();
        ReservationEvent::ResetAttempt {
            offset: 0x8010,
            expected: 0x8001,
        }
        .write_text(&mut text)
        .unwrap();
        ReservationEvent::Retry { remaining: 3 }
            .write_text(&mut text)
            .unwrap();
        ReservationEvent::Aborted.write_text(&mut text).unwrap();
        assert_eq!(
            text,
            "[dmdbgprn] - DbgPrint reset attempt.  Offset=32784 (Expect32769)\n\
             [dmdbgprn] - Retry update (Remain=3)\n\
             [dmdbgprn] - Reset pointer aborted\n"
        );
    }
}
