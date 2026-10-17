//! `pixcmd`: PIX engine control. The subcommand is the byte at line offset
//! 7 and arguments start at offset 9, so the parser assumes exactly one
//! space after the command word. Bytes past the line are the stale content
//! of the receive buffer.

use openxbdm_core::line::CommandLine;

use super::CaptureValue;
use super::Continuation;
use crate::backend::Backend;
use crate::continuation::Continuation as AnyContinuation;
use crate::invocation::Invocation;
use crate::network::Network;
use crate::reply::CommandResult;
use crate::state::ServerState;
use crate::text::ResponseText;

/// Offset of the subcommand letter.
const LETTER_OFFSET: usize = 7;
/// Offset of the first argument.
const ARGUMENT_OFFSET: usize = 9;
/// Largest capture size `o` accepts.
const MAX_CAPTURE_SIZE: u32 = 0x140_0000;
/// Most frames `d` requests at once.
const MAX_FRAME_COUNT: u32 = 200;
/// PIX event signalled when a frame range is rejected.
const RANGE_REJECTED_EVENT: u32 = 6;
/// D3D version below which the old protocol is in use.
const LEGACY_VERSION: u32 = 0x1964;
/// Oldest D3D version `q` reports status for.
const MIN_STATUS_VERSION: u32 = 0x1770;
/// D3D version from which `p` requires a matching runtime.
const PROFILE_VERSION: u32 = 0x17e5;
/// Runtime version `u` requires for GPU captures.
const GPU_CAPTURE_VERSION: u32 = 0x209e;

xbox360_sys::value_enum! {
    /// Engine message codes.
    pub enum PixMessage: u32 {
        CaptureFrames = 1,
        Stop = 3,
        SetCapture = 4,
        Start = 5,
        Record = 6,
        Frames = 7,
        Profile = 0xa,
        Resume = 0xb,
        FrameRange = 0xc,
        FrameDetail = 0xe,
        GpuCapture = 0xf,
    }
}

/// Counter group of the enable bitmap; groups 2 to 6 have callbacks.
const BITMAP_GROUP: u32 = 1;

/// The receive buffer up to the line's NUL, read the way the monitor walks
/// it.
struct Arguments<'a> {
    text: &'a [u8],
    /// Start of the next item; `None` once the line is exhausted.
    next: Option<usize>,
}

impl<'a> Arguments<'a> {
    fn new(text: &'a [u8]) -> Self {
        let next = (text.len() >= ARGUMENT_OFFSET).then_some(ARGUMENT_OFFSET);
        Self { text, next }
    }

    fn at(&self, index: usize) -> u8 {
        self.text.get(index).copied().unwrap_or(0)
    }

    /// Unsigned decimal digits with wrapping; the first non-digit is
    /// consumed unless it is the terminating NUL. Returns the value and the
    /// position after it.
    fn number(&self, mut position: usize) -> (u32, usize) {
        let mut value = 0u32;
        loop {
            let byte = self.at(position);
            if byte == 0 {
                return (value, position);
            }
            position += 1;
            if !byte.is_ascii_digit() {
                return (value, position);
            }
            value = value.wrapping_mul(10).wrapping_add(u32::from(byte - b'0'));
        }
    }

    /// Skip spaces, tabs, and line feeds; `None` at the end of the line.
    fn skip(&self, mut position: usize) -> Option<usize> {
        while matches!(self.at(position), b' ' | b'\t' | b'\n') {
            position += 1;
        }
        (self.at(position) != 0).then_some(position)
    }

    /// The next item, or `None` when no item remains.
    fn take(&mut self) -> Option<u32> {
        let (value, after) = self.number(self.next?);
        self.next = self.skip(after);
        Some(value)
    }

    fn has_more(&self) -> bool {
        self.next.is_some()
    }

    /// The rest of the line from the next item.
    fn rest(&self) -> Option<&'a [u8]> {
        self.next.map(|start| &self.text[start..])
    }
}

/// Exactly eight characters at the argument offset, non-hex ones ignored:
/// the group is bits 16 to 20 and the identifier bits 0 to 15.
fn counter_selector(buffer: &[u8]) -> (u32, u32) {
    let mut value = 0u32;
    for index in ARGUMENT_OFFSET..ARGUMENT_OFFSET + 8 {
        let byte = buffer.get(index).copied().unwrap_or(0);
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => continue,
        };
        value = (value << 4) | u32::from(digit);
    }
    ((value >> 16) & 0x1f, value & 0xffff)
}

/// Reply of a subcommand: one of the fixed words or formatted text.
enum Reply {
    Ok,
    No,
    Busy,
    OldD3d,
    Text,
}

impl Reply {
    fn posted(posted: bool) -> Self {
        if posted { Self::Ok } else { Self::No }
    }

    fn posted_or_busy(posted: bool) -> Self {
        if posted { Self::Ok } else { Self::Busy }
    }
}

/// Run a `pixcmd` line a title passes through monitor control code 0x45
/// (stock calls the handler 0x91f57fe0 directly): `buffer` holds the line
/// up to its NUL and the bytes after it. `r` returns `Reply::Binary` with
/// no continuation; the caller transfers the snapshot itself.
pub fn run_title_command(
    state: &mut ServerState,
    backend: &mut dyn Backend,
    network: &mut dyn Network,
    buffer: &[u8],
    text: &mut ResponseText,
) -> CommandResult {
    let end = buffer
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(buffer.len());
    let mut invocation = Invocation {
        line: CommandLine::new(&buffer[..end]),
        buffer,
        text,
        session: None,
        state,
        backend,
        network,
    };
    pix_command(&mut invocation)
}

pub(super) fn pix_command(invocation: &mut Invocation<'_>) -> CommandResult {
    let end = invocation
        .buffer
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(invocation.buffer.len());
    let line = &invocation.buffer[..end];
    // The letter is read even when the line ends before it.
    let letter = invocation.buffer.get(LETTER_OFFSET).copied().unwrap_or(0);
    let mut arguments = Arguments::new(line);
    let reply = match letter {
        b'a' => Reply::posted(
            invocation
                .backend
                .pix_post(PixMessage::Start.raw(), &[1, 0, 0, 0, 0, 0, 0]),
        ),
        b'b' => {
            invocation.backend.pix_set_trace(true);
            Reply::Ok
        }
        b'c' => {
            let count = match arguments.take() {
                Some(0) | None => 1,
                Some(count) => count,
            };
            Reply::posted(
                invocation
                    .backend
                    .pix_post(PixMessage::CaptureFrames.raw(), &[count, 1, 0]),
            )
        }
        b'd' => frames(invocation, &mut arguments),
        b'e' => {
            invocation.backend.pix_set_trace(false);
            Reply::Ok
        }
        b'g' => Reply::posted(invocation.backend.pix_post(PixMessage::Resume.raw(), &[])),
        b'h' => match invocation.backend.pix_dogma() {
            Some(image) => Reply::posted(invocation.backend.pix_post(
                PixMessage::Start.raw(),
                &[
                    1,
                    0,
                    1,
                    image.handle,
                    image.procedure_1,
                    image.info,
                    image.procedure_3,
                ],
            )),
            None => Reply::No,
        },
        b'k' => set_capture(invocation, &mut arguments),
        b'm' => match arguments
            .take()
            .and_then(|frame| invocation.backend.pix_frame_statistics(frame))
        {
            Some([a, b, c]) => {
                invocation.set_text(format_args!("OK {a} {b} {c}"));
                Reply::Text
            }
            None => Reply::No,
        },
        b'n' | b'y' => {
            let (group, id) = counter_selector(invocation.buffer);
            if group == BITMAP_GROUP || (2..7).contains(&group) {
                invocation
                    .backend
                    .pix_counter_control(group, id, letter == b'y');
            }
            Reply::Ok
        }
        b'o' => record(invocation, &mut arguments),
        b'p' => {
            let pix = invocation.state.performance.pix;
            match invocation.backend.pix_status(pix.version, pix.flags) {
                Some(status) if pix.version >= PROFILE_VERSION && status[2] < PROFILE_VERSION => {
                    Reply::OldD3d
                }
                _ => Reply::posted(invocation.backend.pix_post(PixMessage::Profile.raw(), &[])),
            }
        }
        b'q' => status(invocation, &mut arguments),
        b'r' => return trace(invocation),
        b't' => Reply::posted(invocation.backend.pix_post(PixMessage::Stop.raw(), &[0])),
        b'u' => gpu_capture(invocation, &arguments),
        b'v' => frame_range(invocation, &mut arguments),
        b'w' => frame_detail(invocation, &mut arguments),
        _ => Reply::No,
    };
    match reply {
        Reply::Ok => invocation.text.set_bytes(b"OK"),
        Reply::No => invocation.text.set_bytes(b"NO"),
        Reply::Busy => invocation.text.set_bytes(b"BUSY"),
        Reply::OldD3d => invocation.text.set_bytes(b"OldD3D"),
        Reply::Text => {}
    }
    Ok(crate::reply::Reply::Ok)
}

/// A frame range `a..=b` counted back from the current frame; `b`
/// defaults to `a`. Signed comparisons, as in the monitor.
fn range(arguments: &mut Arguments<'_>) -> (i32, i32) {
    match arguments.take() {
        None => (0, 0),
        Some(first) => {
            let last = if arguments.has_more() {
                arguments.take().unwrap_or(first)
            } else {
                first
            };
            (first as i32, last as i32)
        }
    }
}

fn range_accepted(frame: i32, first: i32, last: i32) -> bool {
    frame > last && first > 0 && last >= first
}

fn frames(invocation: &mut Invocation<'_>, arguments: &mut Arguments<'_>) -> Reply {
    let (first, last) = range(arguments);
    let frame = invocation.backend.pix_frame_number();
    if !range_accepted(frame, first, last) {
        invocation.backend.pix_signal_event(RANGE_REJECTED_EVENT);
        return Reply::Ok;
    }
    let count = (last.wrapping_sub(first) as u32)
        .wrapping_add(1)
        .min(MAX_FRAME_COUNT);
    let payload = [frame.wrapping_sub(first) as u32, count, 1];
    Reply::posted_or_busy(
        invocation
            .backend
            .pix_post(PixMessage::Frames.raw(), &payload),
    )
}

fn frame_detail(invocation: &mut Invocation<'_>, arguments: &mut Arguments<'_>) -> Reply {
    let (first, last) = range(arguments);
    let detail = if arguments.has_more() {
        arguments.take().unwrap_or(0)
    } else {
        0
    };
    let frame = invocation.backend.pix_frame_number();
    if !range_accepted(frame, first, last) {
        invocation.backend.pix_signal_event(RANGE_REJECTED_EVENT);
        return Reply::Ok;
    }
    let payload = [
        frame.wrapping_sub(first) as u32,
        (last.wrapping_sub(first) as u32).wrapping_add(1),
        detail,
    ];
    Reply::posted(
        invocation
            .backend
            .pix_post(PixMessage::FrameDetail.raw(), &payload),
    )
}

/// `v [a b c d]`: all four values or none.
fn frame_range(invocation: &mut Invocation<'_>, arguments: &mut Arguments<'_>) -> Reply {
    let mut values = [0u32; 4];
    if arguments.has_more() {
        for value in &mut values {
            match arguments.take() {
                Some(item) => *value = item,
                None => return Reply::No,
            }
        }
    }
    let [first, last, start, end] = values;
    let payload = if first == 1 && last == 1 {
        [1, 1, start, end]
    } else {
        let frame = invocation.backend.pix_frame_number() as u32;
        [
            frame.wrapping_sub(first),
            last.wrapping_sub(first).wrapping_add(1),
            start,
            end,
        ]
    };
    Reply::posted_or_busy(
        invocation
            .backend
            .pix_post(PixMessage::FrameRange.raw(), &payload),
    )
}

/// `k a b text`.
fn set_capture(invocation: &mut Invocation<'_>, arguments: &mut Arguments<'_>) -> Reply {
    let Some(first) = arguments.take() else {
        return Reply::No;
    };
    // The first value is stored before the second is known to exist.
    invocation
        .backend
        .pix_set_capture_value(CaptureValue::First, first);
    let Some(second) = (if arguments.has_more() {
        arguments.take()
    } else {
        None
    }) else {
        return Reply::No;
    };
    invocation
        .backend
        .pix_set_capture_value(CaptureValue::Second, second);
    let Some(text) = arguments.rest() else {
        return Reply::No;
    };
    invocation.backend.pix_set_capture_text(text);
    Reply::posted(
        invocation
            .backend
            .pix_post(PixMessage::SetCapture.raw(), &[0]),
    )
}

/// `o a f s [t u]`.
fn record(invocation: &mut Invocation<'_>, arguments: &mut Arguments<'_>) -> Reply {
    let Some(target) = arguments.take() else {
        return Reply::No;
    };
    let Some(features) = (if arguments.has_more() {
        arguments.take()
    } else {
        None
    }) else {
        return Reply::No;
    };
    let Some(size) = (if arguments.has_more() {
        arguments.take()
    } else {
        None
    }) else {
        return Reply::No;
    };
    let (mut first_option, mut second_option) = (1, 0);
    if arguments.has_more() {
        first_option = arguments.take().unwrap_or(first_option);
        let Some(value) = (if arguments.has_more() {
            arguments.take()
        } else {
            None
        }) else {
            return Reply::No;
        };
        second_option = value;
    }
    let enabled = |bit: u32| if features & bit != 0 { 2 } else { 0 };
    let payload = [
        target,
        enabled(1),
        2,
        enabled(2),
        enabled(4),
        u32::MAX,
        0,
        0,
        size.min(MAX_CAPTURE_SIZE),
        0,
        first_option,
        second_option,
    ];
    if invocation.backend.pix_boot_animation_loaded() {
        return Reply::Busy;
    }
    Reply::posted_or_busy(
        invocation
            .backend
            .pix_post(PixMessage::Record.raw(), &payload),
    )
}

/// `q version flags`: store the title's D3D version and flags, then report
/// the engine status.
fn status(invocation: &mut Invocation<'_>, arguments: &mut Arguments<'_>) -> Reply {
    let Some(version) = arguments.take() else {
        return Reply::No;
    };
    invocation.state.performance.pix.version = version;
    let Some(flags) = (if arguments.has_more() {
        arguments.take()
    } else {
        None
    }) else {
        return Reply::No;
    };
    invocation.state.performance.pix.flags = flags;
    invocation
        .backend
        .pix_set_legacy_protocol(version < LEGACY_VERSION);
    match invocation.backend.pix_status(version, flags) {
        Some(out) if version > MIN_STATUS_VERSION => {
            invocation.set_text(format_args!(
                "OK {} {} {} {} {} {} {} {} {} {} {}",
                out[0],
                out[1],
                out[2],
                out[3],
                out[4],
                out[5],
                out[6],
                out[7],
                out[10],
                out[8],
                out[9]
            ));
            Reply::Text
        }
        _ => Reply::No,
    }
}

/// `u [m [x [y [z]]]]`. The optional values follow without whitespace
/// skipping.
fn gpu_capture(invocation: &mut Invocation<'_>, arguments: &Arguments<'_>) -> Reply {
    let mut payload = [0u32; 6];
    if let Some(start) = arguments.next {
        let (mode, mut position) = arguments.number(start);
        if mode == 99 {
            let ready = invocation.backend.pix_capture_ready();
            invocation.set_text(format_args!("OK {}", u32::from(ready)));
            return Reply::Text;
        }
        payload[0] = u32::from(mode & 1 == 0);
        payload[2] = u32::from((2..=3).contains(&mode));
        invocation.backend.pix_set_gpu_capture(payload[2] != 0);
        for word in &mut payload[3..] {
            if arguments.at(position) == 0 {
                break;
            }
            let (value, after) = arguments.number(position);
            *word = value;
            position = after;
        }
    }
    if payload[2] == 0 {
        let pix = invocation.state.performance.pix;
        if let Some(status) = invocation.backend.pix_status(pix.version, pix.flags)
            && status[2] < GPU_CAPTURE_VERSION
        {
            return Reply::OldD3d;
        }
    }
    Reply::posted(
        invocation
            .backend
            .pix_post(PixMessage::GpuCapture.raw(), &payload),
    )
}

/// `r`: sample the counters into the trace ring and send the queued
/// bytes.
fn trace(invocation: &mut Invocation<'_>) -> CommandResult {
    let queued = invocation.backend.pix_trace_snapshot();
    invocation.set_text(format_args!("OK {}", queued as i32));
    if let Some(session) = invocation.session.as_deref_mut() {
        session.continuation = AnyContinuation::Performance(Continuation::Trace);
    }
    Ok(crate::reply::Reply::Binary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_consume_one_separator_then_skip_whitespace() {
        let mut arguments = Arguments::new(b"pixcmd o 12,7 \t\n  99x");
        assert_eq!(arguments.take(), Some(12));
        assert_eq!(arguments.take(), Some(7));
        assert_eq!(arguments.take(), Some(99));
        assert_eq!(arguments.take(), None);
    }

    #[test]
    fn short_lines_have_no_items() {
        assert_eq!(Arguments::new(b"pixcmd c").take(), None);
        // Nine characters: one item, empty, parses as zero.
        assert_eq!(Arguments::new(b"pixcmd c ").take(), Some(0));
    }

    #[test]
    fn selector_reads_eight_characters_and_ignores_non_hex() {
        assert_eq!(counter_selector(b"pixcmd y 0002-0010"), (0, 0x2001));
        assert_eq!(counter_selector(b"pixcmd y 0001001f\0zz"), (1, 0x1f));
    }
}
