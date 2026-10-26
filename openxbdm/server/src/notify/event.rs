//! Asynchronous events and their notification lines.

use crate::commands::debugger::ModuleEvent;
use crate::commands::debugger::ModuleFlags;
use crate::text::Text;

/// Capacity of a formatted notification line.
pub(super) const EVENT_LINE_CAPACITY: usize = 0x230;

/// Execution state reported by `execution` lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionState {
    Stopped,
    Started,
    Rebooting,
    Pending,
    RebootTitle,
    PendingTitle,
}

impl ExecutionState {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Started => "started",
            Self::Rebooting => "rebooting",
            Self::Pending => "pending",
            Self::RebootTitle => "reboot_title",
            Self::PendingTitle => "pending_title",
        }
    }
}

/// Kind of a data breakpoint hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAccess {
    Write,
    Read,
    Execute,
}

impl DataAccess {
    const fn name(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Read => "read",
            Self::Execute => "execute",
        }
    }
}

/// Exception detail of an `exception` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionDetail {
    /// Access violation (code 0xc0000005): `write` or `read` and the address.
    AccessViolation {
        write: bool,
        address: u32,
    },
    Parameters {
        count: u32,
        address: u32,
    },
}

/// An asynchronous event. `stopped` marks events after which the thread is
/// stopped; their lines end in ` stop`.
#[derive(Clone, Copy)]
pub enum Event<'a> {
    Break {
        address: u32,
        thread: u32,
        stopped: bool,
    },
    DebugString {
        thread: u32,
        text: &'a [u8],
        stopped: bool,
    },
    AssertString {
        thread: u32,
        text: &'a [u8],
        stopped: bool,
    },
    Execution(ExecutionState),
    /// `execution` line of a thread that stops with the state change (the
    /// title launch waiting in pending_title).
    ExecutionStop(ExecutionState),
    SingleStep {
        address: u32,
        thread: u32,
        stopped: bool,
    },
    ModuleLoad {
        module: &'a ModuleEvent,
        thread: u32,
        stopped: bool,
    },
    ModuleUnload {
        name: &'a str,
        base: u32,
        size: u32,
    },
    ThreadCreate {
        thread: u32,
        start: u32,
        stopped: bool,
    },
    ThreadTerminate {
        thread: u32,
        stopped: bool,
    },
    Exception {
        code: u32,
        thread: u32,
        address: u32,
        detail: ExceptionDetail,
        first_chance: bool,
        noncontinuable: bool,
        stopped: bool,
    },
    Assert {
        thread: u32,
        string_address: u32,
        string_length: u32,
        stopped: bool,
    },
    Data {
        access: DataAccess,
        value: u32,
        address: u32,
        thread: u32,
        stopped: bool,
    },
    Rip {
        thread: u32,
        text: Option<&'a str>,
        stopped: bool,
    },
    SectionLoad {
        name: &'a str,
        base: u32,
        size: u32,
        index: u32,
        flags: u32,
    },
    SectionUnload {
        name: &'a str,
        base: u32,
        size: u32,
        index: u32,
        flags: u32,
    },
    StackTrace {
        thread: u32,
        text: Option<&'a str>,
        stopped: bool,
    },
    NtAssert {
        address: u32,
        thread: u32,
        stopped: bool,
    },
    PogoModuleStartup {
        name: &'a str,
        module: u32,
        thread: u32,
        stopped: bool,
    },
}

impl Event<'_> {
    /// Write the notification line (without CR LF) for line-formatted events.
    pub(super) fn write_line(&self, out: &mut Text<EVENT_LINE_CAPACITY>) {
        match *self {
            Self::Break {
                address,
                thread,
                stopped,
            } => {
                hex(out, b"break addr=0x", address);
                hex(out, b" thread=0x", thread);
                put(out, stop(stopped))
            }
            Self::Execution(state) => {
                put(out, b"execution ");
                put(out, state.name().as_bytes())
            }
            Self::ExecutionStop(state) => {
                put(out, b"execution ");
                put(out, state.name().as_bytes());
                put(out, stop(true))
            }
            Self::SingleStep {
                address,
                thread,
                stopped,
            } => {
                hex(out, b"singlestep addr=0x", address);
                hex(out, b" thread=0x", thread);
                put(out, stop(stopped));
            }
            Self::ModuleLoad {
                module,
                thread,
                stopped,
            } => {
                let flag = |bit: ModuleFlags, text: &'static [u8]| {
                    if module.flags.intersects(bit) {
                        text
                    } else {
                        b""
                    }
                };

                put(out, b"modload name=\"");
                put(out, &module.name[..module.name_length]);
                hex(out, b"\" base=0x", module.base);
                hex(out, b" size=0x", module.size);
                hex(out, b" check=0x", module.checksum);
                hex(out, b" timestamp=0x", module.timestamp);
                hex(out, b" pdata=0x", module.pdata);
                hex(out, b" psize=0x", module.pdata_size);
                put(out, flag(ModuleFlags::XBE, b" xbe"));
                put(out, flag(ModuleFlags::TLS, b" tls"));
                put(out, flag(ModuleFlags::DLL, b" dll"));
                hex(out, b" thread=0x", thread);
                hex(out, b" osize=0x", module.image_size);
                put(out, stop(stopped))
            }
            Self::ModuleUnload { name, base, size } => {
                put(out, b"modunload name=\"");
                put(out, name.as_bytes());
                hex(out, b"\" base=0x", base);
                hex(out, b" size=0x", size);
            }
            Self::ThreadCreate {
                thread,
                start,
                stopped,
            } => {
                hex(out, b"create thread=0x", thread);
                hex(out, b" start=0x", start);
                put(out, stop(stopped))
            }
            Self::ThreadTerminate { thread, stopped } => {
                hex(out, b"terminate thread=0x", thread);
                put(out, stop(stopped))
            }
            Self::Exception {
                code,
                thread,
                address,
                detail,
                first_chance,
                noncontinuable,
                stopped,
            } => {
                hex(out, b"exception code=0x", code);
                hex(out, b" thread=0x", thread);
                hex(out, b" address=0x", address);
                match detail {
                    ExceptionDetail::AccessViolation { write, address } => {
                        let label: &[u8] = if write { b" write=0x" } else { b" read=0x" };
                        hex(out, label, address);
                    }
                    ExceptionDetail::Parameters { count, address } => {
                        put(out, b" nparam=");
                        decimal(out, count);
                        hex(out, b" params=0x", address);
                    }
                }
                if first_chance {
                    put(out, b" first");
                }
                if noncontinuable {
                    put(out, b" noncont");
                }
                put(out, stop(stopped))
            }
            // The monitor's assert case appends the stop suffix and then
            // falls into the common suffix code, so stopped lines carry it
            // twice.
            Self::Assert {
                thread,
                string_address,
                string_length,
                stopped,
            } => {
                hex(out, b"assert thread=0x", thread);
                hex(out, b" straddr=0x", string_address);
                hex(out, b" strlen=0x", string_length);
                put(out, stop(stopped));
                put(out, stop(stopped))
            }
            Self::Data {
                access,
                value,
                address,
                thread,
                stopped,
            } => {
                put(out, b"data ");
                put(out, access.name().as_bytes());
                hex(out, b"=0x", value);
                hex(out, b" addr=0x", address);
                hex(out, b" thread=0x", thread);
                put(out, stop(stopped))
            }
            Self::Rip {
                thread,
                text,
                stopped,
            } => text_line(out, b"rip", thread, text, stopped),
            Self::SectionLoad {
                name,
                base,
                size,
                index,
                flags,
            } => section_line(out, b"sectload", name, base, size, index, flags),
            Self::SectionUnload {
                name,
                base,
                size,
                index,
                flags,
            } => section_line(out, b"sectunload", name, base, size, index, flags),
            Self::StackTrace {
                thread,
                text,
                stopped,
            } => text_line(out, b"stacktrace", thread, text, stopped),
            Self::NtAssert {
                address,
                thread,
                stopped,
            } => {
                hex(out, b"ntassert addr=0x", address);
                hex(out, b" thread=0x", thread);
                put(out, stop(stopped))
            }
            Self::PogoModuleStartup {
                name,
                module,
                thread,
                stopped,
            } => {
                put(out, b"pogomodstartup name=\"");
                put(out, name.as_bytes());
                hex(out, b"\" module=0x", module);
                hex(out, b" thread=0x", thread);
                put(out, stop(stopped));
            }
            // Debug and assert strings are sent in pieces by
            // `Notifications::deliver`, not as one line.
            Self::DebugString { .. } | Self::AssertString { .. } => {}
        }
    }
}

/// `label` followed by `value` in eight hex digits.
fn hex(out: &mut Text<EVENT_LINE_CAPACITY>, label: &[u8], value: u32) {
    put(out, label);
    let _ = out.push_hex32(value);
}

/// Append `bytes`. A full line takes no more bytes, so later appends
/// after a truncated one change nothing and need no check.
fn put(out: &mut Text<EVENT_LINE_CAPACITY>, bytes: &[u8]) {
    let _ = out.push_bytes(bytes);
}

fn decimal(out: &mut Text<EVENT_LINE_CAPACITY>, value: u32) {
    let _ = out.push_decimal(value);
}

/// Text of the `stopped` suffix.
fn stop(stopped: bool) -> &'static [u8] {
    if stopped { b" stop" } else { b"" }
}

/// `<kind> name="<name>" base=0x... size=0x... index=<n> flags=<n>`.
fn section_line(
    out: &mut Text<EVENT_LINE_CAPACITY>,
    kind: &[u8],
    name: &str,
    base: u32,
    size: u32,
    index: u32,
    flags: u32,
) {
    put(out, kind);
    put(out, b" name=\"");
    put(out, name.as_bytes());
    hex(out, b"\" base=0x", base);
    hex(out, b" size=0x", size);
    put(out, b" index=");
    decimal(out, index);
    put(out, b" flags=");
    decimal(out, flags);
}

/// `<kind><stop> thread=0x...`, then ` string=<text>` when present.
fn text_line(
    out: &mut Text<EVENT_LINE_CAPACITY>,
    kind: &[u8],
    thread: u32,
    text: Option<&str>,
    stopped: bool,
) {
    put(out, kind);
    put(out, stop(stopped));
    hex(out, b" thread=0x", thread);
    if let Some(text) = text {
        put(out, b" string=");
        put(out, text.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(event: Event<'_>) -> Text<EVENT_LINE_CAPACITY> {
        let mut text = Text::new();
        event.write_line(&mut text);
        text
    }

    #[test]
    fn event_lines_follow_the_monitor_formats() {
        assert_eq!(
            line(Event::Break {
                address: 0x8201_0000,
                thread: 0xfb00_0018,
                stopped: true
            })
            .as_bytes(),
            b"break addr=0x82010000 thread=0xfb000018 stop"
        );
        assert_eq!(
            line(Event::Execution(ExecutionState::RebootTitle)).as_bytes(),
            b"execution reboot_title"
        );
        assert_eq!(
            line(Event::Exception {
                code: 0xc000_0005,
                thread: 1,
                address: 2,
                detail: ExceptionDetail::AccessViolation { write: true, address: 3 },
                first_chance: true,
                noncontinuable: false,
                stopped: true,
            })
            .as_bytes(),
            b"exception code=0xc0000005 thread=0x00000001 address=0x00000002 write=0x00000003 first stop"
        );
    }

    #[test]
    fn modload_names_keep_their_bytes() {
        let mut module = ModuleEvent {
            name: [0; crate::commands::debugger::MODULE_NAME_CAPACITY],
            name_length: 6,
            base: 0x8200_0000,
            size: 0x1000,
            checksum: 0,
            timestamp: 0,
            pdata: 0,
            pdata_size: 0,
            flags: ModuleFlags::DLL,
            image_size: 0x1000,
            has_header: false,
        };
        module.name[..6].copy_from_slice(b"m\xe9.xex");
        assert_eq!(
            line(Event::ModuleLoad { module: &module, thread: 1, stopped: false }).as_bytes(),
            b"modload name=\"m\xe9.xex\" base=0x82000000 size=0x00001000 check=0x00000000 timestamp=0x00000000 pdata=0x00000000 psize=0x00000000 dll thread=0x00000001 osize=0x00001000"
        );
    }

    #[test]
    fn every_event_line() {
        let module = ModuleEvent {
            name: [b'a'; crate::commands::debugger::MODULE_NAME_CAPACITY],
            name_length: 3,
            base: 0x8200_0000,
            size: 0xffff_ffff,
            checksum: 0x1234_abcd,
            timestamp: 7,
            pdata: 0x10,
            pdata_size: 0x20,
            flags: ModuleFlags::XBE | ModuleFlags::TLS | ModuleFlags::DLL,
            image_size: 0x30,
            has_header: true,
        };
        let events = [
            Event::Break {
                address: 1,
                thread: 2,
                stopped: false,
            },
            Event::ExecutionStop(ExecutionState::PendingTitle),
            Event::SingleStep {
                address: 0xdead_beef,
                thread: 0,
                stopped: true,
            },
            Event::ModuleLoad {
                module: &module,
                thread: 9,
                stopped: true,
            },
            Event::ModuleUnload {
                name: "x.xex",
                base: 0x8000_0000,
                size: 0x10,
            },
            Event::ModuleUnload {
                name: "",
                base: 0,
                size: 0,
            },
            Event::ThreadCreate {
                thread: 3,
                start: 0x8200_1000,
                stopped: false,
            },
            Event::ThreadTerminate {
                thread: 4,
                stopped: true,
            },
            Event::ThreadTerminate {
                thread: 4,
                stopped: false,
            },
            Event::Exception {
                code: 0x8000_0003,
                thread: 5,
                address: 6,
                detail: ExceptionDetail::Parameters {
                    count: 4_294_967_295,
                    address: 7,
                },
                first_chance: false,
                noncontinuable: true,
                stopped: false,
            },
            Event::Exception {
                code: 0xc000_0005,
                thread: 5,
                address: 6,
                detail: ExceptionDetail::AccessViolation {
                    write: false,
                    address: 8,
                },
                first_chance: true,
                noncontinuable: true,
                stopped: true,
            },
            Event::Assert {
                thread: 1,
                string_address: 2,
                string_length: 3,
                stopped: true,
            },
            Event::Assert {
                thread: 1,
                string_address: 2,
                string_length: 3,
                stopped: false,
            },
            Event::Data {
                access: DataAccess::Write,
                value: 0x11,
                address: 0x22,
                thread: 0x33,
                stopped: true,
            },
            Event::Rip {
                thread: 1,
                text: Some("message"),
                stopped: true,
            },
            Event::Rip {
                thread: 1,
                text: None,
                stopped: false,
            },
            Event::SectionLoad {
                name: ".text",
                base: 1,
                size: 2,
                index: 0,
                flags: 10,
            },
            Event::SectionUnload {
                name: ".data",
                base: 3,
                size: 4,
                index: 12345,
                flags: 0,
            },
            Event::StackTrace {
                thread: 2,
                text: Some(""),
                stopped: false,
            },
            Event::StackTrace {
                thread: 2,
                text: None,
                stopped: true,
            },
            Event::NtAssert {
                address: 0xffff_ffff,
                thread: 0x10,
                stopped: true,
            },
            Event::PogoModuleStartup {
                name: "pogo",
                module: 0x9000_0000,
                thread: 1,
                stopped: false,
            },
        ];
        extern crate std;
        let mut lines = std::string::String::new();
        for event in events {
            lines.push_str(core::str::from_utf8(line(event).as_bytes()).unwrap());
            lines.push('\n');
        }
        insta::assert_snapshot!(lines);
    }
}
