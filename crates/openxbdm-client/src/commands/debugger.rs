//! Attached debugger registration: `debugger` and `isdebugger`.

use core::fmt::Write as _;
use core::net::Ipv4Addr;

use crate::error::ArgumentError;
use crate::error::Error;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ErrorCode;
use crate::protocol::ExpectedBody;
use crate::protocol::RemoteStatus;
use crate::protocol::Response;

fn report_argument(err: ArgumentError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebuggerAction {
    /// Mark a debugger as attached. While another attached debugger has a
    /// live notification channel the console replies
    /// `410- file already exists` unless `override_existing` is set.
    Connect,
    /// Clear the debugger record. A recorded debugger at a different
    /// address or port gives `414- access denied` unless
    /// `override_existing` is set.
    Disconnect,
    /// Store the given fields without changing the attached state.
    Init,
}

/// `debugger connect|disconnect|init [addr=] [port=] [name=] [user=]
/// [override]`: update the persistent attached-debugger record. Without
/// `address` the console uses the peer address of this connection; the
/// address is only stored together with a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Debugger {
    pub action: DebuggerAction,
    pub address: Option<Ipv4Addr>,
    pub port: Option<u16>,
    /// At most 127 bytes are stored.
    pub name: Option<String>,
    /// At most 15 bytes are stored.
    pub user: Option<String>,
    pub override_existing: bool,
}

impl Command for Debugger {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let action = match self.action {
            DebuggerAction::Connect => "connect",
            DebuggerAction::Disconnect => "disconnect",
            DebuggerAction::Init => "init",
        };
        let mut builder = ArgBuilder::new("debugger").flag(action);
        if let Some(address) = self.address {
            let mut token = String::new();
            let _ = write!(token, "addr={address}");
            builder = builder.flag(&token);
        }
        if let Some(port) = self.port {
            builder = builder.dec("port", port);
        }
        if let Some(name) = &self.name {
            builder = builder.quoted("name", name).map_err(report_argument)?;
        }
        if let Some(user) = &self.user {
            builder = builder.quoted("user", user).map_err(report_argument)?;
        }
        if self.override_existing {
            builder = builder.flag("override");
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

/// `isdebugger`: report the attached debugger.
#[derive(Debug, Clone, Copy)]
pub struct IsDebugger;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebuggerAttachment {
    /// `200- OK`: no debugger attached, or the recorded debugger has no
    /// notification channel.
    None,
    /// `410- ...`: a debugger is attached. Name and user are absent when the
    /// console has none recorded; they may be truncated to the response
    /// line.
    Attached {
        name: Option<String>,
        user: Option<String>,
    },
}

fn parse_attachment(message: &str) -> DebuggerAttachment {
    if message == ErrorCode::FileAlreadyExists.message() {
        return DebuggerAttachment::Attached {
            name: None,
            user: None,
        };
    }
    let (name, rest) = match message.strip_prefix("name=\"") {
        Some(quoted) => match quoted.split_once("\" ") {
            Some((name, rest)) => (Some(name.to_owned()), rest),
            None => (Some(quoted.trim_end_matches('"').to_owned()), ""),
        },
        None => (None, message),
    };
    let user = rest.strip_prefix("user=").map(str::to_owned);
    DebuggerAttachment::Attached { name, user }
}

impl Command for IsDebugger {
    type Output = DebuggerAttachment;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("isdebugger".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(DebuggerAttachment::None)
    }

    fn handle_remote(
        &self,
        code: RemoteStatus,
        message: &str,
    ) -> Option<Result<Self::Output, rootcause::Report<Error>>> {
        (code == ErrorCode::FileAlreadyExists).then(|| Ok(parse_attachment(message)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isdebugger_parses_stock_410_forms() {
        let attachments: Vec<DebuggerAttachment> = [
            "file already exists",
            "name=\"Dev PC\" user=dev",
            "name=\"Dev PC\" ",
            "user=dev",
        ]
        .iter()
        .map(|message| {
            IsDebugger
                .handle_remote(ErrorCode::FileAlreadyExists.into(), message)
                .unwrap()
                .unwrap()
        })
        .collect();
        insta::assert_debug_snapshot!(attachments);
    }

    #[test]
    fn debugger_wire_line() {
        let line = Debugger {
            action: DebuggerAction::Connect,
            address: Some(Ipv4Addr::new(192, 168, 1, 20)),
            port: Some(731),
            name: Some("Dev PC".to_owned()),
            user: Some("dev".to_owned()),
            override_existing: true,
        }
        .wire_line()
        .unwrap();
        insta::assert_snapshot!(line, @r###"debugger connect addr=192.168.1.20 port=731 name="Dev PC" user="dev" override"###);
    }
}
