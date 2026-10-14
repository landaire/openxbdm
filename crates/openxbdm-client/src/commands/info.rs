//! Lightweight informational commands.

use std::net::Ipv4Addr;

use rootcause::prelude::*;

use crate::commands::kv::parse_kv_line;
use crate::commands::kv::value_u32;
use crate::error::ArgumentError;
use crate::error::Error;
use crate::error::ParseError;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ExpectedBody;
use crate::protocol::Response;
use crate::time::FileTime;

/// `dbgname`: both a getter and (when `Set`) a setter for the debuggable
/// name of the console.
#[derive(Debug, Clone)]
pub enum DbgName {
    Get,
    Set(String),
}

impl Command for DbgName {
    type Output = String;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        match self {
            DbgName::Get => Ok(ArgBuilder::new("dbgname").finish()),
            DbgName::Set(name) => {
                if name.contains(['\r', '\n', '"']) {
                    return Err(rootcause::Report::new(Error::from(ArgumentError::InvalidDbgNameChar)));
                }
                Ok(format!("dbgname name={name}"))
            }
        }
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new).attach("parsing dbgname response")
    }
}

/// `systime`: returns the console's clock as two 32-bit halves of a Windows
/// `FILETIME` (100-ns ticks since 1601-01-01 UTC).
#[derive(Debug, Clone, Copy)]
pub struct SysTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysTimeResult {
    pub file_time: FileTime,
}

impl Command for SysTime {
    type Output = SysTimeResult;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("systime").finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let kv = parse_kv_line(&head);
        let hi_value = kv.require("clockhi").map_err(|e| rootcause::Report::new(Error::from(e)))?;
        let lo_value = kv.require("clocklo").map_err(|e| rootcause::Report::new(Error::from(e)))?;
        let hi = value_u32(hi_value, "clockhi").map_err(|e| rootcause::Report::new(Error::from(e)))?;
        let lo = value_u32(lo_value, "clocklo").map_err(|e| rootcause::Report::new(Error::from(e)))?;
        Ok(SysTimeResult { file_time: FileTime::from_halves(hi, lo) })
    }
}

/// `dmversion`: returns an opaque string identifying the XBDM build.
#[derive(Debug, Clone, Copy)]
pub struct DmVersion;

impl Command for DmVersion {
    type Output = String;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("dmversion".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)
    }
}

/// `consoletype`: retail vs. devkit vs. testkit vs. reviewer kit.
#[derive(Debug, Clone, Copy)]
pub struct GetConsoleType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleType {
    Retail,
    DevKit,
    TestKit,
    ReviewerKit,
    Other(String),
}

impl Command for GetConsoleType {
    type Output = ConsoleType;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("consoletype".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(match head.trim().to_ascii_lowercase().as_str() {
            "devkit" => ConsoleType::DevKit,
            "testkit" => ConsoleType::TestKit,
            "retail" => ConsoleType::Retail,
            "reviewerkit" => ConsoleType::ReviewerKit,
            _ => ConsoleType::Other(head),
        })
    }
}

/// `consolefeatures`: returns a space-separated list of feature flags the
/// current kernel advertises.
#[derive(Debug, Clone, Copy)]
pub struct GetConsoleFeatures;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsoleFeatures {
    pub flags: Vec<String>,
}

impl Command for GetConsoleFeatures {
    type Output = ConsoleFeatures;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("consolefeatures".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let flags = head.split_ascii_whitespace().map(|s| s.to_owned()).collect();
        Ok(ConsoleFeatures { flags })
    }
}

/// `altaddr`: the alternate (debug) IPv4 address the console advertises.
#[derive(Debug, Clone, Copy)]
pub struct AltAddr;

impl Command for AltAddr {
    type Output = Ipv4Addr;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("altaddr".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let kv = parse_kv_line(&head);
        let raw = value_u32(kv.require("addr").map_err(|e| rootcause::Report::new(Error::from(e)))?, "addr")
            .map_err(|e| rootcause::Report::new(Error::from(e)))?;
        Ok(Ipv4Addr::from(raw))
    }
}

/// `getpid`: the pid of the currently running title process.
#[derive(Debug, Clone, Copy)]
pub struct GetPid;

impl Command for GetPid {
    type Output = u32;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("getpid".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let kv = parse_kv_line(&head);
        value_u32(kv.require("pid").map_err(|e| rootcause::Report::new(Error::from(e)))?, "pid")
            .map_err(|e| rootcause::Report::new(Error::from(e)))
    }
}

/// `consolemem`: memory class byte. The raw value is preserved alongside
/// any known classification we can derive.
#[derive(Debug, Clone, Copy)]
pub struct GetConsoleMem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleMem {
    /// Raw class value as reported by the kernel. Known on retail/devkit:
    /// `0x01` -> 512 MiB, `0x02` -> 1 GiB.
    pub class: u8,
}

impl Command for GetConsoleMem {
    type Output = ConsoleMem;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("consolemem".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let kv = parse_kv_line(&head);
        let raw =
            value_u32(kv.require("consolemem").map_err(|e| rootcause::Report::new(Error::from(e)))?, "consolemem")
                .map_err(|e| rootcause::Report::new(Error::from(e)))?;
        Ok(ConsoleMem { class: raw as u8 })
    }
}

/// `getnetaddrs`: the debug (XBDM) and title network-address blobs the
/// console knows about. Each blob is a 40-byte hex string the host side
/// interprets as a `sockaddr` plus extra XBDM metadata.
#[derive(Debug, Clone, Copy)]
pub struct GetNetAddrs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetAddrs {
    pub name: String,
    pub debug: Vec<u8>,
    pub title: Vec<u8>,
}

fn hex_string_to_bytes(s: &str) -> Result<Vec<u8>, ParseError> {
    if !s.len().is_multiple_of(2) {
        return Err(ParseError::InvalidHexDigits { key: "net-blob" });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let pair = core::str::from_utf8(chunk).map_err(|_| ParseError::InvalidHexDigits { key: "net-blob" })?;
        out.push(u8::from_str_radix(pair, 16).map_err(|_| ParseError::InvalidHexDigits { key: "net-blob" })?);
    }
    Ok(out)
}

impl Command for GetNetAddrs {
    type Output = NetAddrs;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("getnetaddrs".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let kv = parse_kv_line(&head);
        let name_value = kv.require("name").map_err(|e| rootcause::Report::new(Error::from(e)))?;
        let debug_value = kv.require("debug").map_err(|e| rootcause::Report::new(Error::from(e)))?;
        let title_value = kv.require("title").map_err(|e| rootcause::Report::new(Error::from(e)))?;
        Ok(NetAddrs {
            name: name_value.as_str().to_owned(),
            debug: hex_string_to_bytes(debug_value.as_str()).map_err(|e| rootcause::Report::new(Error::from(e)))?,
            title: hex_string_to_bytes(title_value.as_str()).map_err(|e| rootcause::Report::new(Error::from(e)))?,
        })
    }
}

/// `drivelist`: returns a multiline body of `drivename="<label>"` entries.
///
/// Historical Xbox 1 kits returned single-letter ids (`D`, `E`, `Z`); the
/// Xbox 360 kit also returns longer synthetic names (`SysCache0`, `HDD`,
/// `DEVKIT`). Both shapes collapse to the same `Vec<String>`.
#[derive(Debug, Clone, Copy)]
pub struct DriveList;

impl Command for DriveList {
    type Output = Vec<String>;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("drivelist".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let lines = response.expect_multiline().map_err(rootcause::Report::new)?;
        let mut drives = Vec::with_capacity(lines.len());
        for line in lines {
            let kv = parse_kv_line(&line);
            if let Some(value) = kv.get("drivename") {
                drives.push(value.as_str().to_owned());
            }
        }
        Ok(drives)
    }
}
