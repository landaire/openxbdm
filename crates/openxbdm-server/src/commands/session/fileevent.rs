//! Text of the `XBDMFE!` file event notifications: the switch announcements
//! of `fileevent` and exports 152/153, the file services' events (monitor
//! control codes 0x64 before an operation and 0x65 after it), and the events
//! titles report through exports 154 to 160.

use core::fmt::Write as _;

use crate::text::Text;

/// Characters of an event text: the monitor formats into 0x200 bytes and
/// stores a NUL in the last one.
pub const FILE_EVENT_TEXT_LIMIT: usize = 0x1ff;
/// Characters of a `Start` or `Stop` text (a 0x40-byte buffer).
const SWITCH_TEXT_LIMIT: usize = 0x3f;
/// The path text and its closing quote end before the last two bytes.
const PATH_LIMIT: usize = FILE_EVENT_TEXT_LIMIT - 1;
const PATH_PREFIX: &[u8] = b" \"Path=";

pub type FileEventText = Text<FILE_EVENT_TEXT_LIMIT>;
pub type FileEventSwitchText = Text<SWITCH_TEXT_LIMIT>;

/// `Flags=` bits.
pub const FLAG_SYNCHRONOUS: u32 = 0x8000_0000;
pub const FLAG_SCATTER_GATHER: u32 = 0x4000_0000;
pub const FLAG_BUFFERED: u32 = 0x2000_0000;
/// The event was reported by a title (exports 155 and 157).
pub const FLAG_REPORTED: u32 = 0x1000_0000;

/// Sequence number of the switch announcements and the events, one counter
/// for both (stock 0x91f9735c). The counter starts at 0, as stock's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileEventId(pub u32);

impl FileEventId {
    /// The identifier after `self`. Stock tests the incremented word for
    /// zero with a 64-bit compare of the zero-extended sum, which never
    /// matches, so the sequence wraps to 0.
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

/// Path of an event: the string's length field and its text up to the
/// first NUL. Text past `length` bytes is never printed, so callers may stop
/// reading there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventPath<'a> {
    pub length: u16,
    pub text: &'a [u8],
}

/// Fields of an `XBDMFE!Begin` text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEventBegin<'a> {
    pub id: FileEventId,
    pub time_base: u64,
    pub kind: u32,
    pub thread_id: u32,
    pub handle: u32,
    pub offset: u64,
    pub bytes: u32,
    pub flags: u32,
    pub path: Option<EventPath<'a>>,
}

/// Fields of the export 155 `XBDMFE!PseudoBegin` text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PseudoBegin<'a> {
    pub id: FileEventId,
    pub library: &'a [u8],
    pub time_base: u64,
    pub thread_id: u32,
    /// Caller option bits, see [`pseudo_flags`].
    pub options: u32,
    pub path: Option<EventPath<'a>>,
}

/// Fields of the export 157 `XBDMFE!PseudoBegin` text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PseudoBeginIo<'a> {
    pub id: FileEventId,
    pub library: &'a [u8],
    pub time_base: u64,
    /// Caller operation code, see [`pseudo_io_type`].
    pub operation: u32,
    pub event: &'a [u8],
    pub thread_id: u32,
    pub handle: u32,
    pub offset: u64,
    pub bytes: u32,
    /// Caller option bits, see [`pseudo_flags`].
    pub options: u32,
}

/// `Type=` of operation `operation` of the event record.
pub const fn file_event_kind(operation: u32) -> u32 {
    match operation {
        3 => 1,
        4 => 2,
        5 => 3,
        6 => 4,
        7 => 5,
        8 => 6,
        9 => 7,
        _ => 0,
    }
}

/// `Flags=` of a title-reported begin: option bit 0 synchronous, bit 1
/// buffered.
pub const fn pseudo_flags(options: u32) -> u32 {
    let mut flags = FLAG_REPORTED;
    if options & 1 != 0 {
        flags |= FLAG_SYNCHRONOUS;
    }
    if options & 2 != 0 {
        flags |= FLAG_BUFFERED;
    }
    flags
}

/// `Type=` of export 157 operation `operation`: 0..=6 map to 1..=7, any
/// other value to 8.
pub const fn pseudo_io_type(operation: u32) -> u32 {
    if operation < 7 { operation + 1 } else { 8 }
}

const fn pseudo_io_flags(operation: u32, options: u32) -> u32 {
    let flags = pseudo_flags(options);
    if matches!(operation, 2 | 3) {
        flags | FLAG_SCATTER_GATHER
    } else {
        flags
    }
}

const fn high(value: u64) -> u32 {
    (value >> 32) as u32
}

/// `XBDMFE!Start` or `XBDMFE!Stop` with the new sequence number.
pub fn format_file_event_switch(enable: bool, id: FileEventId) -> FileEventSwitchText {
    let mut text = FileEventSwitchText::new();
    let _ = write!(
        text,
        "XBDMFE!{} 0x{:08x}",
        if enable { "Start" } else { "Stop" },
        id.0
    );
    text
}

/// Append ` "Path=<text>` as the monitor does: it prints into room =
/// min(0x1fe - length, Length + 7) bytes and stores the closing quote after
/// that room, so the quote appears only when the text fills the room.
fn append_path(text: &mut FileEventText, path: EventPath<'_>) {
    let length = text.as_bytes().len();
    // Stock writes past its buffer from here on.
    if length > PATH_LIMIT {
        return;
    }
    let room = (PATH_LIMIT - length).min(path.length as usize + PATH_PREFIX.len());
    let prefix = &PATH_PREFIX[..room.min(PATH_PREFIX.len())];
    let name = &path.text[..path.text.len().min(room - prefix.len())];
    let _ = text.push_bytes(prefix);
    let _ = text.push_bytes(name);
    if prefix.len() + name.len() == room {
        let _ = text.push_bytes(b"\"");
    }
}

/// Format an `XBDMFE!Begin` text.
pub fn format_file_event_begin(event: &FileEventBegin<'_>) -> FileEventText {
    let mut text = FileEventText::new();
    let _ = write!(
        text,
        "XBDMFE!Begin 0x{:08x} \"Perf=0x{:08x}{:08x}\" \"Type=0x{:08x}\" \"ThreadId=0x{:08x}\" \"Handle=0x{:08x}\" \"Offset=0x{:08x}{:08x}\" \"Bytes=0x{:08x}\" \"Flags=0x{:08x}\"",
        event.id.0,
        high(event.time_base),
        event.time_base as u32,
        event.kind,
        event.thread_id,
        event.handle,
        high(event.offset),
        event.offset as u32,
        event.bytes,
        event.flags,
    );
    if let Some(path) = event.path {
        append_path(&mut text, path);
    }
    text
}

/// Format an `XBDMFE!End` text.
pub fn format_file_event_end(
    id: FileEventId,
    time_base: u64,
    handle: u32,
    result: u32,
) -> FileEventText {
    let mut text = FileEventText::new();
    let _ = write!(
        text,
        "XBDMFE!End 0x{:08x} \"Perf=0x{:08x}{:08x}\" \"Handle=0x{handle:08x}\" \"Result=0x{result:08x}\"",
        id.0,
        high(time_base),
        time_base as u32,
    );
    text
}

/// Export 154: `XBDMFE!Marker "Message=%s"`.
pub fn format_marker(message: &[u8]) -> FileEventText {
    let mut text = FileEventText::new();
    let _ = text
        .push_bytes(b"XBDMFE!Marker \"Message=")
        .and_then(|()| text.push_bytes(message))
        .and_then(|()| text.push_bytes(b"\""));
    text
}

/// Export 155: begin of a title-reported event, with `Type=` 0 and an
/// optional path.
pub fn format_pseudo_begin(event: &PseudoBegin<'_>) -> FileEventText {
    let mut text = FileEventText::new();
    let _ = write!(text, "XBDMFE!PseudoBegin 0x{:08x} \"Library=", event.id.0)
        .and_then(|()| text.push_bytes(event.library))
        .and_then(|()| {
            write!(
                text,
                "\" \"Perf=0x{:08x}{:08x}\" \"Type=0x00000000\" \"ThreadId=0x{:08x}\" \"Flags=0x{:08x}\"",
                high(event.time_base),
                event.time_base as u32,
                event.thread_id,
                pseudo_flags(event.options),
            )
        });
    if let Some(path) = event.path {
        append_path(&mut text, path);
    }
    text
}

/// Export 157: begin of a title-reported I/O operation.
pub fn format_pseudo_begin_io(event: &PseudoBeginIo<'_>) -> FileEventText {
    let mut text = FileEventText::new();
    let _ = write!(text, "XBDMFE!PseudoBegin 0x{:08x} \"Library=", event.id.0)
        .and_then(|()| text.push_bytes(event.library))
        .and_then(|()| {
            write!(
                text,
                "\" \"Perf=0x{:08x}{:08x}\" \"Type=0x{:08x}\" \"Event=",
                high(event.time_base),
                event.time_base as u32,
                pseudo_io_type(event.operation),
            )
        })
        .and_then(|()| text.push_bytes(event.event))
        .and_then(|()| {
            write!(
                text,
                "\" \"ThreadId=0x{:08x}\" \"Handle=0x{:08x}\" \"Offset=0x{:08x}{:08x}\" \"Bytes=0x{:08x}\" \"Flags=0x{:08x}\"",
                event.thread_id,
                event.handle,
                high(event.offset),
                event.offset as u32,
                event.bytes,
                pseudo_io_flags(event.operation, event.options),
            )
        });
    text
}

/// Exports 156 (with a handle) and 158 (without): end of a title-reported
/// event.
pub fn format_pseudo_end(
    id: FileEventId,
    time_base: u64,
    handle: Option<u32>,
    result: u32,
) -> FileEventText {
    let mut text = FileEventText::new();
    let _ = write!(
        text,
        "XBDMFE!PseudoEnd 0x{:08x} \"Perf=0x{:08x}{:08x}\"",
        id.0,
        high(time_base),
        time_base as u32
    )
    .and_then(|()| match handle {
        Some(handle) => write!(text, " \"Handle=0x{handle:08x}\""),
        None => Ok(()),
    })
    .and_then(|()| write!(text, " \"Result=0x{result:08x}\""));
    text
}

/// Export 159: `XBDMFE!MarkThread "Library=%s" "ThreadId=0x%08x"`.
pub fn format_mark_thread(library: &[u8], thread_id: u32) -> FileEventText {
    let mut text = FileEventText::new();
    let _ = text
        .push_bytes(b"XBDMFE!MarkThread \"Library=")
        .and_then(|()| text.push_bytes(library))
        .and_then(|()| write!(text, "\" \"ThreadId=0x{thread_id:08x}\""));
    text
}

/// Export 160: `XBDMFE!UnmarkThread "ThreadId=0x%08x" ` (the format ends
/// with a space).
pub fn format_unmark_thread(thread_id: u32) -> FileEventText {
    let mut text = FileEventText::new();
    let _ = write!(text, "XBDMFE!UnmarkThread \"ThreadId=0x{thread_id:08x}\" ");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn begin(path: Option<EventPath<'_>>) -> FileEventBegin<'_> {
        FileEventBegin {
            id: FileEventId(2),
            time_base: 0x1_0000_0002,
            kind: 0,
            thread_id: 0xf900_0010,
            handle: 0,
            offset: 0,
            bytes: 0,
            flags: 0xa000_0000,
            path,
        }
    }

    /// A PseudoBegin whose fixed text is `fixed` characters long.
    fn pseudo_with_fixed_length<'a>(
        library: &'a [u8; FILE_EVENT_TEXT_LIMIT],
        fixed: usize,
        path: EventPath<'a>,
    ) -> FileEventText {
        let bare = format_pseudo_begin(&PseudoBegin {
            id: FileEventId(1),
            library: b"",
            time_base: 0,
            thread_id: 0,
            options: 0,
            path: None,
        });
        let event = PseudoBegin {
            id: FileEventId(1),
            library: &library[..fixed - bare.as_bytes().len()],
            time_base: 0,
            thread_id: 0,
            options: 0,
            path: Some(path),
        };
        format_pseudo_begin(&event)
    }

    #[test]
    fn sequence_wraps_to_zero() {
        assert_eq!(FileEventId(0xffff_ffff).next(), FileEventId(0));
    }

    #[test]
    fn switch_texts() {
        assert_eq!(
            format_file_event_switch(true, FileEventId(1)).as_bytes(),
            b"XBDMFE!Start 0x00000001"
        );
        assert_eq!(
            format_file_event_switch(false, FileEventId(0x1234_abcd)).as_bytes(),
            b"XBDMFE!Stop 0x1234abcd"
        );
    }

    #[test]
    fn begin_text_with_path() {
        let text = format_file_event_begin(&begin(Some(EventPath {
            length: 5,
            text: b"e:\\ab",
        })));
        let expected: &[u8] = b"XBDMFE!Begin 0x00000002 \"Perf=0x0000000100000002\" \"Type=0x00000000\" \"ThreadId=0xf9000010\" \"Handle=0x00000000\" \"Offset=0x0000000000000000\" \"Bytes=0x00000000\" \"Flags=0xa0000000\" \"Path=e:\\ab\"";
        assert_eq!(text.as_bytes(), expected);
    }

    #[test]
    fn path_shorter_than_its_length_loses_the_quote() {
        let text = format_file_event_begin(&begin(Some(EventPath {
            length: 9,
            text: b"e:\\ab",
        })));
        assert!(
            text.as_bytes()
                .ends_with(b"\"Flags=0xa0000000\" \"Path=e:\\ab")
        );
    }

    #[test]
    fn path_longer_than_its_length_is_cut() {
        let text = format_file_event_begin(&begin(Some(EventPath {
            length: 2,
            text: b"e:\\ab",
        })));
        assert!(
            text.as_bytes()
                .ends_with(b"\"Flags=0xa0000000\" \"Path=e:\"")
        );
    }

    #[test]
    fn end_text() {
        let text = format_file_event_end(FileEventId(7), 0x2_0000_0001, 0x40, 0xc000_0034);
        assert_eq!(
            text.as_bytes(),
            b"XBDMFE!End 0x00000007 \"Perf=0x0000000200000001\" \"Handle=0x00000040\" \"Result=0xc0000034\""
        );
    }

    #[test]
    fn marker_text() {
        assert_eq!(
            format_marker(b"level 2").as_bytes(),
            b"XBDMFE!Marker \"Message=level 2\""
        );
    }

    #[test]
    fn marker_text_is_cut_to_the_limit() {
        let message = [b'm'; 0x300];
        let text = format_marker(&message);
        assert_eq!(text.as_bytes().len(), FILE_EVENT_TEXT_LIMIT);
        assert!(text.as_bytes().ends_with(b"mmm"));
    }

    #[test]
    fn pseudo_begin_text() {
        let text = format_pseudo_begin(&PseudoBegin {
            id: FileEventId(3),
            library: b"xmedia",
            time_base: 0x0000_0012_3456_789a,
            thread_id: 0xf900_0020,
            options: 3,
            path: Some(EventPath {
                length: 8,
                text: b"game:\\a\\b",
            }),
        });
        let expected: &[u8] = b"XBDMFE!PseudoBegin 0x00000003 \"Library=xmedia\" \"Perf=0x000000123456789a\" \"Type=0x00000000\" \"ThreadId=0xf9000020\" \"Flags=0xb0000000\" \"Path=game:\\a\\\"";
        assert_eq!(text.as_bytes(), expected);
    }

    #[test]
    fn pseudo_begin_without_path() {
        let text = format_pseudo_begin(&PseudoBegin {
            id: FileEventId(4),
            library: b"lib",
            time_base: 1,
            thread_id: 5,
            options: 2,
            path: None,
        });
        let expected: &[u8] = b"XBDMFE!PseudoBegin 0x00000004 \"Library=lib\" \"Perf=0x0000000000000001\" \"Type=0x00000000\" \"ThreadId=0x00000005\" \"Flags=0x30000000\"";
        assert_eq!(text.as_bytes(), expected);
    }

    #[test]
    fn path_after_a_full_text_is_only_the_quote() {
        let library = [b'l'; FILE_EVENT_TEXT_LIMIT];
        let text = pseudo_with_fixed_length(
            &library,
            0x1fe,
            EventPath {
                length: 3,
                text: b"abc",
            },
        );
        assert_eq!(text.as_bytes().len(), FILE_EVENT_TEXT_LIMIT);
        assert!(text.as_bytes().ends_with(b"\"\""));
    }

    #[test]
    fn path_room_cuts_the_prefix() {
        let library = [b'l'; FILE_EVENT_TEXT_LIMIT];
        let text = pseudo_with_fixed_length(
            &library,
            0x1fb,
            EventPath {
                length: 3,
                text: b"abc",
            },
        );
        assert!(text.as_bytes().ends_with(b"\" \"P\""));
    }

    #[test]
    fn no_path_after_a_text_that_fills_the_buffer() {
        let library = [b'l'; FILE_EVENT_TEXT_LIMIT];
        let text = pseudo_with_fixed_length(
            &library,
            0x1ff,
            EventPath {
                length: 3,
                text: b"abc",
            },
        );
        assert_eq!(text.as_bytes().len(), FILE_EVENT_TEXT_LIMIT);
        assert!(text.as_bytes().ends_with(b"\"Flags=0x10000000\""));
    }

    #[test]
    fn pseudo_begin_io_text() {
        let text = format_pseudo_begin_io(&PseudoBeginIo {
            id: FileEventId(9),
            library: b"xmedia",
            time_base: 0x1_0000_0000,
            operation: 2,
            event: b"stream",
            thread_id: 0xf900_0020,
            handle: 0x80,
            offset: 0x1_0000_0200,
            bytes: 0x800,
            options: 1,
        });
        let expected: &[u8] = b"XBDMFE!PseudoBegin 0x00000009 \"Library=xmedia\" \"Perf=0x0000000100000000\" \"Type=0x00000003\" \"Event=stream\" \"ThreadId=0xf9000020\" \"Handle=0x00000080\" \"Offset=0x0000000100000200\" \"Bytes=0x00000800\" \"Flags=0xd0000000\"";
        assert_eq!(text.as_bytes(), expected);
    }

    #[test]
    fn pseudo_io_types_and_flags() {
        let types: [u32; 9] = core::array::from_fn(|operation| pseudo_io_type(operation as u32));
        assert_eq!(types, [1, 2, 3, 4, 5, 6, 7, 8, 8]);
        assert_eq!(pseudo_io_type(u32::MAX), 8);
        let flags: [u32; 5] =
            core::array::from_fn(|operation| pseudo_io_flags(operation as u32, 0));
        assert_eq!(
            flags,
            [
                0x1000_0000,
                0x1000_0000,
                0x5000_0000,
                0x5000_0000,
                0x1000_0000
            ]
        );
    }

    #[test]
    fn pseudo_end_texts() {
        assert_eq!(
            format_pseudo_end(FileEventId(9), 0x2_0000_0003, Some(0x80), 0).as_bytes(),
            b"XBDMFE!PseudoEnd 0x00000009 \"Perf=0x0000000200000003\" \"Handle=0x00000080\" \"Result=0x00000000\""
        );
        assert_eq!(
            format_pseudo_end(FileEventId(9), 0x2_0000_0003, None, 0x8007_0057).as_bytes(),
            b"XBDMFE!PseudoEnd 0x00000009 \"Perf=0x0000000200000003\" \"Result=0x80070057\""
        );
    }

    #[test]
    fn thread_mark_texts() {
        assert_eq!(
            format_mark_thread(b"xmedia", 0xf900_0020).as_bytes(),
            b"XBDMFE!MarkThread \"Library=xmedia\" \"ThreadId=0xf9000020\""
        );
        assert_eq!(
            format_unmark_thread(0xf900_0020).as_bytes(),
            b"XBDMFE!UnmarkThread \"ThreadId=0xf9000020\" "
        );
    }
}
