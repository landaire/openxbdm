//! Debug execution control: stop, go, halt, continue, suspend, resume,
//! breakpoint management, stop-reason queries, and crash dumps.

pub use openxbdm_core::status::NtStatus;

use crate::commands::kv::KvLine;
use crate::commands::kv::parse_kv_line;
use crate::commands::kv::value_u32;
use crate::commands::process::ThreadId;
use crate::error::Error;
use crate::error::ParseError;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ErrorCode;
use crate::protocol::ExpectedBody;
use crate::protocol::RemoteStatus;
use crate::protocol::Response;

fn report_parse(err: ParseError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

fn require_u32(kv: &KvLine<'_>, key: &'static str) -> Result<u32, ParseError> {
    value_u32(kv.require(key)?, key)
}

fn require_thread(kv: &KvLine<'_>) -> Result<ThreadId, ParseError> {
    require_u32(kv, "thread").map(ThreadId)
}

/// `stop`: suspend every title and system thread under debugger control.
/// The console replies `426- already stopped` when execution is already
/// stopped or pending.
#[derive(Debug, Clone, Copy)]
pub struct Stop;

impl Command for Stop {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("stop".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `go`: resume execution after a prior `stop`. The console replies
/// `408- not stopped` when execution is not stopped.
#[derive(Debug, Clone, Copy)]
pub struct Go;

impl Command for Go {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("go".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `halt THREAD=<id>`. Stock XBDM 2.0.21256 does not implement thread halt:
/// development kits always reply `400- ` with empty text (returned as
/// [`Error::Remote`]) and test kits reply `407- unknown command`. No state
/// changes on the console.
#[derive(Debug, Clone, Copy)]
pub struct Halt {
    pub thread: ThreadId,
}

impl Command for Halt {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("halt")
            .hex32("THREAD", self.thread.as_u32())
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `continue THREAD=<id> [EXCEPTION]`: release a thread stopped at a debug
/// event. A thread without a pending debug event is left unchanged and the
/// reply is still `200- OK`; a thread with a record that is not stopped
/// gives `408- not stopped`.
#[derive(Debug, Clone, Copy)]
pub struct Continue {
    pub thread: ThreadId,
    /// Mark the pending exception as continued (not handled by the
    /// debugger) before the thread is released, so the exception is passed
    /// on to the title's own exception handling.
    pub pass_exception: bool,
}

impl Command for Continue {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("continue").hex32("THREAD", self.thread.as_u32());
        if self.pass_exception {
            builder = builder.flag("EXCEPTION");
        }
        Ok(builder.finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `suspend THREAD=<id>`: suspend a thread (increments suspend count).
#[derive(Debug, Clone, Copy)]
pub struct Suspend {
    pub thread: ThreadId,
}

impl Command for Suspend {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("suspend")
            .hex32("THREAD", self.thread.as_u32())
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `resume THREAD=<id>`: decrement suspend count.
#[derive(Debug, Clone, Copy)]
pub struct Resume {
    pub thread: ThreadId,
}

impl Command for Resume {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("resume")
            .hex32("THREAD", self.thread.as_u32())
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `isstopped THREAD=<id>`: report whether a thread is currently stopped
/// at a debug event and, if so, why.
#[derive(Debug, Clone, Copy)]
pub struct IsStopped {
    pub thread: ThreadId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopState {
    /// `408- not stopped`.
    Running,
    Halted(StopReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// `stopped`: no exception record, or a record kind the console does
    /// not describe further.
    Stopped,
    /// `debugstr thread= stop`.
    DebugString {
        thread: ThreadId,
    },
    /// `assert thread= straddr= strlen=`.
    Assertion {
        thread: ThreadId,
        string_address: u32,
        string_length: u32,
    },
    /// `break addr= thread=`.
    Breakpoint {
        address: u32,
        thread: ThreadId,
    },
    /// `singlestep addr= thread=`.
    SingleStep {
        address: u32,
        thread: ThreadId,
    },
    /// `ntassert addr= thread=`.
    NtAssertion {
        address: u32,
        thread: ThreadId,
    },
    /// `data <access>=<data address> addr= thread=`.
    DataBreakpoint {
        access: DataAccess,
        data_address: u32,
        address: u32,
        thread: ThreadId,
    },
    /// `rip thread= [string=<text>]`. The text is printed with width and
    /// precision equal to the reported length, so it may carry trailing
    /// space padding.
    Rip {
        thread: ThreadId,
        message: Option<String>,
    },
    Exception(ExceptionStop),
}

/// Access named in a `data` stop line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAccess {
    Write,
    Read,
    Execute,
}

/// `exception code= thread= address= ... [first] [noncont]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionStop {
    pub code: NtStatus,
    pub thread: ThreadId,
    pub address: u32,
    pub detail: ExceptionDetail,
    pub first_chance: bool,
    pub noncontinuable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionDetail {
    /// Code 0xc0000005: ` read=<address>` or ` write=<address>`.
    AccessViolation {
        access: AccessViolationKind,
        data_address: u32,
    },
    /// Any other code: ` nparam=<count> params=<address of parameter array>`.
    Parameters { count: u32, address: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessViolationKind {
    Read,
    Write,
}

impl Command for IsStopped {
    type Output = StopState;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("isstopped")
            .hex32("THREAD", self.thread.as_u32())
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        parse_stop_reason(&head)
            .map(StopState::Halted)
            .map_err(report_parse)
    }

    fn handle_remote(
        &self,
        code: RemoteStatus,
        _message: &str,
    ) -> Option<Result<Self::Output, rootcause::Report<Error>>> {
        (code == ErrorCode::NotStopped).then_some(Ok(StopState::Running))
    }
}

fn parse_stop_reason(head: &str) -> Result<StopReason, ParseError> {
    let (word, rest) = head.split_once(' ').unwrap_or((head, ""));
    if word == "rip" {
        // The string runs to end of line and may contain spaces.
        let (thread_part, message) = match rest.split_once(" string=") {
            Some((thread_part, message)) => (thread_part, Some(message.to_owned())),
            None => (rest, None),
        };
        let thread = require_thread(&parse_kv_line(thread_part))?;
        return Ok(StopReason::Rip { thread, message });
    }
    let kv = parse_kv_line(rest);
    match word {
        "stopped" if rest.is_empty() => Ok(StopReason::Stopped),
        "debugstr" if kv.has_flag("stop") => Ok(StopReason::DebugString {
            thread: require_thread(&kv)?,
        }),
        "assert" => Ok(StopReason::Assertion {
            thread: require_thread(&kv)?,
            string_address: require_u32(&kv, "straddr")?,
            string_length: require_u32(&kv, "strlen")?,
        }),
        "break" => Ok(StopReason::Breakpoint {
            address: require_u32(&kv, "addr")?,
            thread: require_thread(&kv)?,
        }),
        "singlestep" => Ok(StopReason::SingleStep {
            address: require_u32(&kv, "addr")?,
            thread: require_thread(&kv)?,
        }),
        "ntassert" => Ok(StopReason::NtAssertion {
            address: require_u32(&kv, "addr")?,
            thread: require_thread(&kv)?,
        }),
        "data" => {
            let (access, key) = [
                (DataAccess::Write, "write"),
                (DataAccess::Read, "read"),
                (DataAccess::Execute, "execute"),
            ]
            .into_iter()
            .find(|(_, key)| kv.get(key).is_some())
            .ok_or(ParseError::MissingKey { key: "write" })?;
            Ok(StopReason::DataBreakpoint {
                access,
                data_address: require_u32(&kv, key)?,
                address: require_u32(&kv, "addr")?,
                thread: require_thread(&kv)?,
            })
        }
        "exception" => {
            let detail = if let Some(value) = kv.get("read") {
                ExceptionDetail::AccessViolation {
                    access: AccessViolationKind::Read,
                    data_address: value_u32(value, "read")?,
                }
            } else if let Some(value) = kv.get("write") {
                ExceptionDetail::AccessViolation {
                    access: AccessViolationKind::Write,
                    data_address: value_u32(value, "write")?,
                }
            } else {
                ExceptionDetail::Parameters {
                    count: require_u32(&kv, "nparam")?,
                    address: require_u32(&kv, "params")?,
                }
            };
            Ok(StopReason::Exception(ExceptionStop {
                code: NtStatus(require_u32(&kv, "code")?),
                thread: require_thread(&kv)?,
                address: require_u32(&kv, "address")?,
                detail,
                first_chance: kv.has_flag("first"),
                noncontinuable: kv.has_flag("noncont"),
            }))
        }
        _ => Err(ParseError::UnrecognizedShape),
    }
}

/// `break ADDR=<va>` / `break ADDR=<va> CLEAR`: set or clear a single
/// execution breakpoint. The address must be 4-byte aligned.
#[derive(Debug, Clone, Copy)]
pub struct Breakpoint {
    pub address: u32,
    pub clear: bool,
}

impl Command for Breakpoint {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("break").hex32("ADDR", self.address);
        if self.clear {
            builder = builder.flag("CLEAR");
        }
        Ok(builder.finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `break start`: place a one-shot breakpoint at the title's entry point
/// so a pending `go` halts the moment the title begins executing. The
/// console replies `400- execution not pending` unless execution is pending.
#[derive(Debug, Clone, Copy)]
pub struct SetInitialBreakpoint;

impl Command for SetInitialBreakpoint {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("break start".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `break now`: the console waits 250 ms, then executes a debug trap in
/// the command thread.
#[derive(Debug, Clone, Copy)]
pub struct BreakNow;

impl Command for BreakNow {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("break now".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// Access class monitored by the hardware data breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataBreakKind {
    Read,
    Write,
    ReadWrite,
}

impl DataBreakKind {
    pub fn token(self) -> &'static str {
        match self {
            DataBreakKind::Read => "READ",
            DataBreakKind::Write => "WRITE",
            DataBreakKind::ReadWrite => "READWRITE",
        }
    }
}

/// `break READ=<va> SIZE=<n>` / `break WRITE=<va> SIZE=<n> CLEAR` etc:
/// set (or clear) the single hardware data breakpoint. The watched range
/// must lie within one aligned doubleword; a second, different data
/// breakpoint gives `400- out of memory`.
#[derive(Debug, Clone, Copy)]
pub struct DataBreakpoint {
    pub address: u32,
    pub size: u32,
    pub kind: DataBreakKind,
    pub clear: bool,
}

impl Command for DataBreakpoint {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("break")
            .hex32(self.kind.token(), self.address)
            .dec("SIZE", self.size as u64);
        if self.clear {
            builder = builder.flag("CLEAR");
        }
        Ok(builder.finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `break clearall`: remove every execution breakpoint and the data
/// breakpoint.
#[derive(Debug, Clone, Copy)]
pub struct ClearAllBreakpoints;

impl Command for ClearAllBreakpoints {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("break clearall".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `isbreak ADDR=<va>`: query whether an address has a breakpoint (and of
/// what kind). Only exact address equality is tested.
#[derive(Debug, Clone, Copy)]
pub struct IsBreak {
    pub address: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointKind {
    /// `type=0`.
    None,
    /// `type=4`: software execution breakpoint.
    Execution,
    /// `type=1` write, `type=2` read/write, `type=5` read.
    Data(DataBreakKind),
}

impl BreakpointKind {
    /// The `type=` value of the `isbreak` reply.
    pub fn code(self) -> u32 {
        match self {
            BreakpointKind::None => 0,
            BreakpointKind::Execution => 4,
            BreakpointKind::Data(DataBreakKind::Write) => 1,
            BreakpointKind::Data(DataBreakKind::ReadWrite) => 2,
            BreakpointKind::Data(DataBreakKind::Read) => 5,
        }
    }

    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(BreakpointKind::None),
            4 => Some(BreakpointKind::Execution),
            1 => Some(BreakpointKind::Data(DataBreakKind::Write)),
            2 => Some(BreakpointKind::Data(DataBreakKind::ReadWrite)),
            5 => Some(BreakpointKind::Data(DataBreakKind::Read)),
            _ => None,
        }
    }
}

impl Command for IsBreak {
    type Output = BreakpointKind;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("isbreak")
            .hex32("ADDR", self.address)
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let kv = parse_kv_line(&head);
        let code = require_u32(&kv, "type").map_err(report_parse)?;
        BreakpointKind::from_code(code).ok_or_else(|| {
            report_parse(ParseError::UnknownCode {
                key: "type",
                value: code,
            })
        })
    }
}

/// `crashdump`: the console replies `200- OK`, waits 200 ms, then writes a
/// full system crash dump. Nothing further is sent on the connection.
#[derive(Debug, Clone, Copy)]
pub struct CrashDump;

impl Command for CrashDump {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("crashdump".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SuccessCode;

    fn ok(head: &str) -> Response {
        Response::Line {
            code: SuccessCode::Ok,
            head: head.to_owned(),
        }
    }

    fn stop_reasons(heads: &[&str]) -> Vec<StopState> {
        let command = IsStopped {
            thread: ThreadId(0xfb00_0018),
        };
        heads
            .iter()
            .map(|head| command.parse(ok(head)).unwrap())
            .collect()
    }

    #[test]
    fn isstopped_parses_stock_stop_lines() {
        let states = stop_reasons(&[
            "stopped",
            "debugstr thread=0xfb000018 stop",
            "assert thread=0xfb000018 straddr=0x82001000 strlen=0x00000010",
            "break addr=0x82010000 thread=0xfb000018",
            "singlestep addr=0x82010004 thread=0xfb000018",
            "ntassert addr=0x82010008 thread=0xfb000018",
            "data read=0x40001000 addr=0x8201000c thread=0xfb000018",
            "rip thread=0xfb000018",
            "rip thread=0xfb000018 string=fatal error  ",
            "exception code=0xc0000005 thread=0xfb000018 address=0x82010010 write=0x00000000 first",
            "exception code=0x80000002 thread=0xfb000018 address=0x82010014 nparam=2 params=0x7c150f00 noncont",
        ]);
        insta::assert_snapshot!(format!("{states:#x?}"));
    }

    #[test]
    fn isstopped_rejects_unknown_shape() {
        let command = IsStopped {
            thread: ThreadId(0xfb00_0018),
        };
        assert!(command.parse(ok("breakpoint addr=0x82010000")).is_err());
    }

    #[test]
    fn isbreak_maps_stock_type_codes() {
        let kinds: Vec<BreakpointKind> = ["type=0", "type=4", "type=1", "type=2", "type=5"]
            .iter()
            .map(|h| IsBreak { address: 0 }.parse(ok(h)).unwrap())
            .collect();
        insta::assert_debug_snapshot!(kinds, @r###"
        [
            None,
            Execution,
            Data(
                Write,
            ),
            Data(
                ReadWrite,
            ),
            Data(
                Read,
            ),
        ]
        "###);
        assert!(IsBreak { address: 0 }.parse(ok("type=3")).is_err());
    }
}
