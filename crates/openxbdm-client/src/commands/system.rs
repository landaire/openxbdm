//! System-level control: reboot, title, notification registration,
//! stop-on condition toggling.

use crate::error::ArgumentError;
use crate::error::Error;
use crate::error::ParseError;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ExpectedBody;
use crate::protocol::Response;

fn report_argument(err: ArgumentError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

/// `reboot [STOP] [WAIT] [SMCRESET]`: reboot the console. The console
/// replies `200- OK` before it restarts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reboot {
    /// `STOP`: stop at the title entry point after the reboot.
    pub stop: bool,
    /// `WAIT`: wait for a debugger connection after the reboot. Ignored
    /// with `stop`, and when a boot-wait mode is already recorded.
    pub wait: bool,
    /// `SMCRESET`: reset through the system management controller.
    pub smc_reset: bool,
}

impl Command for Reboot {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("reboot");
        if self.stop {
            builder = builder.flag("STOP");
        }
        if self.wait {
            builder = builder.flag("WAIT");
        }
        if self.smc_reset {
            builder = builder.flag("SMCRESET");
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

/// `magicboot`: launch a title. Without `cold` the console relaunches the
/// title in place when it can; otherwise it reboots. Either way it replies
/// `200- OK`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MagicBoot {
    /// `COLD`: always reboot the console (`WARM` sets the same flag).
    pub cold: bool,
    /// `WAIT`: wait for a debugger connection after a reboot.
    pub wait: bool,
    /// `STOP`: stop at the title entry point after a reboot.
    pub stop: bool,
    /// `TITLE="..."`: drive path of the title image.
    pub title: Option<String>,
    /// `DIRECTORY="..."`: drive path of the title directory.
    pub directory: Option<String>,
    /// `CMDLINE="..."`: title command line.
    pub cmd_line: Option<String>,
}

impl Command for MagicBoot {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("magicboot");
        if let Some(title) = &self.title {
            builder = builder.quoted("TITLE", title).map_err(report_argument)?;
        }
        if let Some(dir) = &self.directory {
            builder = builder.quoted("DIRECTORY", dir).map_err(report_argument)?;
        }
        if let Some(cmd) = &self.cmd_line {
            builder = builder.quoted("CMDLINE", cmd).map_err(report_argument)?;
        }
        if self.cold {
            builder = builder.flag("COLD");
        }
        if self.wait {
            builder = builder.flag("WAIT");
        }
        if self.stop {
            builder = builder.flag("STOP");
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
            Title::Set { name } => ArgBuilder::new("title")
                .quoted("NAME", name)
                .map_err(report_argument)
                .map(ArgBuilder::finish),
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

/// Stop-on event flags. Maps to `stopon` / `nostopon` wire tokens; the
/// console ignores tokens it does not recognize.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StopOnFlags {
    /// `createthread` (mask 0x1).
    pub create_thread: bool,
    /// `fce` (mask 0x2).
    pub first_chance_exception: bool,
    /// `debugstr` (mask 0x4).
    pub debugstr: bool,
    /// `stacktrace` (mask 0x8).
    pub stacktrace: bool,
    /// `modload` (mask 0x10).
    pub module_load: bool,
    /// `pogomodstart` (mask 0x40).
    pub pogo_module_start: bool,
    /// `all` (mask 0xffffffff); the other flags are not sent.
    pub all: bool,
}

impl StopOnFlags {
    fn tokens(self) -> Vec<&'static str> {
        if self.all {
            return vec!["all"];
        }
        [
            (self.create_thread, "createthread"),
            (self.first_chance_exception, "fce"),
            (self.debugstr, "debugstr"),
            (self.stacktrace, "stacktrace"),
            (self.module_load, "modload"),
            (self.pogo_module_start, "pogomodstart"),
        ]
        .into_iter()
        .filter_map(|(set, token)| set.then_some(token))
        .collect()
    }
}

/// `stopon ...`: add the named conditions to the stop-on mask. The console
/// replies `200- stop on all` for `all`, else `200- OK`.
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

/// `nostopon ...`: remove the named conditions from the stop-on mask. The
/// console replies `200- stop on none` for `all`, else `200- OK`. Without
/// any flags the mask is unchanged.
#[derive(Debug, Clone, Copy)]
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

/// `notify [reconnectport=<port>] [debug] [reverse]`: turn the connection
/// into a notification channel. Sent through
/// [`Client::into_notification_channel`](crate::Client::into_notification_channel):
/// the console answers `205- now a notification channel` and an
/// `execution <state>` line, then sends only notification lines.
///
/// With `reconnect_port` the console also records a notification target at
/// the client's address and that port, which is persisted and reconnected
/// at the next boot.
#[derive(Debug, Clone, Copy, Default)]
pub struct Notify {
    pub reconnect_port: Option<u16>,
    /// Debugger notifications.
    pub debug: bool,
    /// The recorded target waits for the client to connect back.
    pub reverse: bool,
}

impl Notify {
    pub fn wire_line(&self) -> String {
        let mut builder = ArgBuilder::new("notify");
        if let Some(port) = self.reconnect_port {
            builder = builder.dec("reconnectport", u64::from(port));
        }
        if self.debug {
            builder = builder.flag("debug");
        }
        if self.reverse {
            builder = builder.flag("reverse");
        }
        builder.finish()
    }
}

/// Execution state reported by `execution` notification lines.
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
    const ALL: [Self; 6] = [
        Self::Stopped,
        Self::Started,
        Self::Rebooting,
        Self::Pending,
        Self::RebootTitle,
        Self::PendingTitle,
    ];

    /// The state's name in notification lines.
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

    /// Parse an `execution <state>` notification line.
    pub fn parse_line(line: &str) -> Result<Self, ParseError> {
        let name = line
            .strip_prefix("execution ")
            .ok_or(ParseError::UnrecognizedShape)?;
        Self::ALL
            .into_iter()
            .find(|state| state.name() == name)
            .ok_or(ParseError::UnrecognizedShape)
    }
}
