//! Debug execution control: stop, go, halt, continue, suspend, resume,
//! breakpoint management, and stop-reason queries.

use crate::commands::kv::parse_kv_line;
use crate::commands::process::ThreadId;
use crate::error::ArgumentError;
use crate::error::Error;
use crate::error::ParseError;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ErrorCode;
use crate::protocol::ExpectedBody;
use crate::protocol::Response;

fn report_parse(err: ParseError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

fn report_argument(err: ArgumentError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

/// `stop`: request the whole system to halt so breakpoints can be set.
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

/// `go`: resume execution after a prior `stop`.
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

/// `halt THREAD=<id>`: halt a single thread.
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

/// `continue THREAD=<id>`: resume a halted thread.
#[derive(Debug, Clone, Copy)]
pub struct Continue {
    pub thread: ThreadId,
    /// Execute one instruction then re-halt.
    pub single_step: bool,
}

impl Command for Continue {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("continue").hex32("THREAD", self.thread.as_u32());
        if self.single_step {
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

/// `isstopped THREAD=<id>`: report whether a thread is currently halted
/// and, if so, why.
#[derive(Debug, Clone, Copy)]
pub struct IsStopped {
    pub thread: ThreadId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopState {
    /// The thread is running normally. XBDM maps this to `408 not stopped`.
    Running,
    /// The thread is halted for a recognised reason.
    Halted(StopReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    Breakpoint {
        address: u32,
    },
    DataBreakpoint {
        address: u32,
        access: DataAccess,
    },
    SingleStep,
    Exception {
        code: u32,
    },
    HardwareDebug,
    Assertion,
    /// Any 200-OK response shape we don't explicitly model. Kept as the
    /// raw "fail-open" string so callers can still inspect it.
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAccess {
    Read,
    Write,
    ReadWrite,
    Execute,
    Unknown(u32),
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
        Ok(StopState::Halted(parse_stop_reason(&head)))
    }

    fn handle_remote(
        &self,
        code: ErrorCode,
        _message: &str,
    ) -> Option<Result<Self::Output, rootcause::Report<Error>>> {
        match code {
            ErrorCode::NotStopped => Some(Ok(StopState::Running)),
            _ => None,
        }
    }
}

fn parse_stop_reason(head: &str) -> StopReason {
    let kv = parse_kv_line(head);
    if kv.has_flag("breakpoint")
        && let Some(addr_value) = kv.get("addr")
        && let Ok(addr) = addr_value
            .as_str()
            .trim_start_matches("0x")
            .parse::<u32>()
            .or_else(|_| u32::from_str_radix(addr_value.as_str().trim_start_matches("0x"), 16))
    {
        return StopReason::Breakpoint { address: addr };
    }
    if kv.has_flag("singlestep") {
        return StopReason::SingleStep;
    }
    if kv.has_flag("hwexcp") {
        return StopReason::HardwareDebug;
    }
    if kv.has_flag("assert") {
        return StopReason::Assertion;
    }
    if kv.has_flag("data")
        && let (Some(addr_value), Some(kind_value)) = (kv.get("addr"), kv.get("access"))
    {
        let addr =
            u32::from_str_radix(addr_value.as_str().trim_start_matches("0x"), 16).unwrap_or(0);
        let access = match kind_value.as_str() {
            "read" => DataAccess::Read,
            "write" => DataAccess::Write,
            "readwrite" => DataAccess::ReadWrite,
            "execute" => DataAccess::Execute,
            other => DataAccess::Unknown(
                u32::from_str_radix(other.trim_start_matches("0x"), 16).unwrap_or(0),
            ),
        };
        return StopReason::DataBreakpoint {
            address: addr,
            access,
        };
    }
    if kv.has_flag("exception")
        && let Some(code_value) = kv.get("code")
    {
        let code =
            u32::from_str_radix(code_value.as_str().trim_start_matches("0x"), 16).unwrap_or(0);
        return StopReason::Exception { code };
    }
    StopReason::Other(head.to_owned())
}

/// `break ADDR=<va>` / `break ADDR=<va> CLEAR`: set or clear a single
/// execution breakpoint.
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
/// so a pending `go` halts the moment the title begins executing.
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

/// Access class monitored by a data breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataBreakKind {
    Read,
    Write,
    ReadWrite,
    Execute,
}

impl DataBreakKind {
    pub fn token(self) -> &'static str {
        match self {
            DataBreakKind::Read => "READ",
            DataBreakKind::Write => "WRITE",
            DataBreakKind::ReadWrite => "READWRITE",
            DataBreakKind::Execute => "EXECUTE",
        }
    }
}

/// `break READ=<va> SIZE=<n>` / `break WRITE=<va> SIZE=<n> CLEAR` etc:
/// set (or clear) a data-access breakpoint.
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

/// `break clearall`: remove every execution breakpoint.
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

/// `isbreak ADDR=<va>`: query whether an address already has a breakpoint
/// (and of what kind).
#[derive(Debug, Clone, Copy)]
pub struct IsBreak {
    pub address: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointKind {
    None,
    Execution,
    DataRead,
    DataWrite,
    DataReadWrite,
    DataExecute,
    Unknown(u32),
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
        let type_value = kv.require("type").map_err(report_parse)?;
        let ty = u32::from_str_radix(type_value.as_str().trim_start_matches("0x"), 16)
            .map_err(|_| report_parse(ParseError::InvalidHexDigits { key: "type" }))?;
        Ok(match ty {
            0 => BreakpointKind::None,
            1 => BreakpointKind::Execution,
            2 => BreakpointKind::DataRead,
            3 => BreakpointKind::DataWrite,
            4 => BreakpointKind::DataReadWrite,
            5 => BreakpointKind::DataExecute,
            other => BreakpointKind::Unknown(other),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Debugger {
    pub do_override: bool,
    pub name: String,
    pub user: String,
}

impl Command for Debugger {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("debugger").flag("connect");
        if self.do_override {
            builder = builder.flag("override");
        }
        builder = builder
            .quoted("name", &self.name)
            .map_err(report_argument)?;
        builder = builder
            .quoted("user", &self.user)
            .map_err(report_argument)?;

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
