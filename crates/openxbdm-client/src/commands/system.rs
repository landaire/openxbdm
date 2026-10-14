//! System-level control: reboot, title, notification registration,
//! stop-on condition toggling.

use crate::commands::kv::parse_kv_line;
use crate::commands::kv::value_u32;
use crate::error::ArgumentError;
use crate::error::Error;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ExpectedBody;
use crate::protocol::Response;

fn report_argument(err: ArgumentError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

/// Bit flags accepted by `reboot`. The raw wire form is a sub-command on
/// a token basis (`reboot WARM STOP NODEBUG ...`). `Reboot::default()`
/// performs a cold reboot into the dashboard.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RebootFlags {
    /// `WARM`: keep the current title memory intact where possible.
    pub warm: bool,
    /// `STOP`: pause execution immediately after reboot so a debugger can
    /// attach before the title starts.
    pub stop_on_start: bool,
    /// `NODEBUG`: decline any debugger attach after the reboot.
    pub no_debug: bool,
    /// `WAIT`: block the response until the console is reachable again.
    /// Most clients prefer to poll themselves instead.
    pub wait: bool,
}

/// `reboot`: reboot the console. The default is a cold reboot into the
/// dashboard; populate [`RebootFlags`] to influence the kernel path.
#[derive(Debug, Clone, Default)]
pub struct Reboot {
    pub flags: RebootFlags,
    /// Optional `TITLE="..."` argument: reboot directly into this title.
    pub title: Option<String>,
    /// Optional `DIRECTORY="..."` argument.
    pub directory: Option<String>,
    /// Optional `CMDLINE="..."` argument.
    pub cmd_line: Option<String>,
}

impl Reboot {
    pub fn warm() -> Self {
        Self { flags: RebootFlags { warm: true, ..RebootFlags::default() }, ..Self::default() }
    }
}

impl Command for Reboot {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("reboot");
        if let Some(title) = &self.title {
            builder = builder.quoted("TITLE", title).map_err(report_argument)?;
        }
        if let Some(dir) = &self.directory {
            builder = builder.quoted("DIRECTORY", dir).map_err(report_argument)?;
        }
        if let Some(cmd) = &self.cmd_line {
            builder = builder.quoted("CMDLINE", cmd).map_err(report_argument)?;
        }
        if self.flags.warm {
            builder = builder.flag("WARM");
        }
        if self.flags.stop_on_start {
            builder = builder.flag("STOP");
        }
        if self.flags.no_debug {
            builder = builder.flag("NODEBUG");
        }
        if self.flags.wait {
            builder = builder.flag("WAIT");
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

/// `title`: set the default title to launch on next reboot.
#[derive(Debug, Clone)]
pub enum Title {
    Set { name: String },
    NoPersist,
}

impl Command for Title {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        match self {
            Title::Set { name } => {
                ArgBuilder::new("title").quoted("NAME", name).map_err(report_argument).map(ArgBuilder::finish)
            }
            Title::NoPersist => Ok(ArgBuilder::new("title").flag("NOPERSIST").finish()),
        }
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// Stop-on condition toggles. Maps to `stopon` / `nostopon` wire flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StopOnFlags {
    pub create_thread: bool,
    pub first_chance_exception: bool,
    pub debugstr: bool,
    pub stacktrace: bool,
    pub title_init: bool,
    pub title_exit: bool,
    pub debugger: bool,
    pub all: bool,
}

impl StopOnFlags {
    fn tokens(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.all {
            out.push("all");
            return out;
        }
        if self.create_thread {
            out.push("createthread");
        }
        if self.first_chance_exception {
            out.push("fce");
        }
        if self.debugstr {
            out.push("debugstr");
        }
        if self.stacktrace {
            out.push("stacktrace");
        }
        if self.title_init {
            out.push("titleinit");
        }
        if self.title_exit {
            out.push("titleexit");
        }
        if self.debugger {
            out.push("debugger");
        }
        out
    }
}

/// `stopon ...`: enable the named stop-on conditions.
#[derive(Debug, Clone, Copy)]
pub struct StopOn(pub StopOnFlags);

impl Command for StopOn {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("stopon");
        for token in self.0.tokens() {
            builder = builder.flag(token);
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

/// `nostopon ...`: disable the named stop-on conditions. Without any
/// flags, disables everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoStopOn(pub StopOnFlags);

impl Command for NoStopOn {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("nostopon");
        for token in self.0.tokens() {
            builder = builder.flag(token);
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

/// `notify reconnectport=<port>`: request the console to connect back to
/// us on a dedicated port for asynchronous notifications.
#[derive(Debug, Clone, Copy)]
pub struct Notify {
    pub reconnect_port: u16,
    pub reverse: bool,
    pub drop_on_reconnect: bool,
}

impl Command for Notify {
    type Output = NotifyReply;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("notify").dec("reconnectport", self.reconnect_port as u64);
        if self.reverse {
            builder = builder.flag("reverse");
        }
        if self.drop_on_reconnect {
            builder = builder.flag("drop");
        }
        Ok(builder.finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let kv = parse_kv_line(&head);
        let port = kv.get("reconnectport").and_then(|v| value_u32(v, "reconnectport").ok()).map(|v| v as u16);
        Ok(NotifyReply { reconnect_port: port, raw: head })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyReply {
    /// Port the console will dial back on, if we were able to parse one.
    pub reconnect_port: Option<u16>,
    /// Original response head for diagnostics when parsing fails open.
    pub raw: String,
}
