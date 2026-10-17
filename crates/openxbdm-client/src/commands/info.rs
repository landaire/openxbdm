//! Lightweight informational commands.

use std::net::Ipv4Addr;

use rootcause::prelude::ResultExt;

use crate::commands::error::report_parse;
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
            Self::Get => Ok(ArgBuilder::new("dbgname").finish()),
            Self::Set(name) => {
                if name.contains(['\r', '\n', '"']) {
                    return Err(rootcause::Report::new(Error::from(
                        ArgumentError::InvalidDbgNameChar,
                    )));
                }

                // The monitor ends an unquoted value at the first space.
                Ok(ArgBuilder::new("dbgname")
                    .quoted("name", name)
                    .map_err(Error::from)?
                    .finish())
            }
        }
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response
            .expect_ok()
            .map_err(rootcause::Report::new)
            .attach("parsing dbgname response")
    }
}

/// `systime`: returns the console's clock as two 32-bit halves of a Windows
/// `FILETIME` (100-ns ticks since 1601-01-01 UTC). The console answers
/// `406-` until `setsystime` has run since boot.
#[derive(Debug, Clone, Copy)]
pub struct SysTime;

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
        let hi_value = kv.require("high").map_err(report_parse)?;
        let lo_value = kv.require("low").map_err(report_parse)?;
        let hi = value_u32(hi_value, "high").map_err(report_parse)?;
        let lo = value_u32(lo_value, "low").map_err(report_parse)?;

        Ok(SysTimeResult {
            file_time: FileTime::from_halves(hi, lo),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysTimeResult {
    pub file_time: FileTime,
}

/// `setsystime clockhi= clocklo= [tz=]`: set the console clock. With
/// `time_zone_defaults` the console also writes a default time zone when
/// none is configured.
#[derive(Debug, Clone, Copy)]
pub struct SetSysTime {
    pub file_time: FileTime,
    pub time_zone_defaults: bool,
}

impl Command for SetSysTime {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("setsystime")
            .hex32("clockhi", self.file_time.high())
            .hex32("clocklo", self.file_time.low());
        if self.time_zone_defaults {
            builder = builder.hex32("tz", 1);
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

/// `consoletype`: development kit or test kit; the monitor reports no
/// other kind.
#[derive(Debug, Clone, Copy)]
pub struct GetConsoleType;

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
        match head.as_str() {
            "devkit" => Ok(ConsoleType::DevKit),
            "testkit" => Ok(ConsoleType::TestKit),
            _ => {
                Err(rootcause::Report::new(Error::from(ParseError::UnrecognizedShape)).attach(head))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleType {
    DevKit,
    TestKit,
}

/// `consolefeatures`: returns a space-separated list of feature flags the
/// current kernel advertises.
#[derive(Debug, Clone, Copy)]
pub struct GetConsoleFeatures;

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
        let flags = head
            .split_ascii_whitespace()
            .map(|flag| flag.to_owned())
            .collect();

        Ok(ConsoleFeatures { flags })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsoleFeatures {
    pub flags: Vec<String>,
}

/// `altaddr`: the IPv4 address of the title network stack.
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
        let raw =
            value_u32(kv.require("addr").map_err(report_parse)?, "addr").map_err(report_parse)?;

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
        value_u32(kv.require("pid").map_err(report_parse)?, "pid").map_err(report_parse)
    }
}

/// `consolemem`: memory configuration class.
#[derive(Debug, Clone, Copy)]
pub struct GetConsoleMem;

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
        let raw = value_u32(
            kv.require("consolemem").map_err(report_parse)?,
            "consolemem",
        )
        .map_err(report_parse)?;

        match raw {
            0 => Ok(ConsoleMem::Standard),
            1 => Ok(ConsoleMem::ExtraMemoryUnused),
            2 => Ok(ConsoleMem::ExtraMemoryInUse),
            value => Err(rootcause::Report::new(Error::from(
                ParseError::UnknownCode {
                    key: "consolemem",
                    value,
                },
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleMem {
    /// No additional memory is installed (value 0).
    Standard,
    /// Additional memory is installed but the kernel manages no more than
    /// 0x20000 pages (value 1).
    ExtraMemoryUnused,
    /// The kernel manages more than 0x20000 pages (value 2).
    ExtraMemoryInUse,
}

/// `getnetaddrs`: the debug name and the debug and title network address
/// records (36 bytes each, sent as 72 hex digits). The name is not quoted
/// and may contain spaces.
#[derive(Debug, Clone, Copy)]
pub struct GetNetAddrs;

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
        let shape = || rootcause::Report::new(Error::from(ParseError::UnrecognizedShape));
        let rest = head.strip_prefix("name=").ok_or_else(shape)?;
        let (rest, title) = rest.rsplit_once(" title=").ok_or_else(shape)?;
        let (name, debug) = rest.rsplit_once(" debug=").ok_or_else(shape)?;

        Ok(NetAddrs {
            name: name.to_owned(),
            debug: hex_string_to_bytes(debug).map_err(report_parse)?,
            title: hex_string_to_bytes(title).map_err(report_parse)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetAddrs {
    pub name: String,
    pub debug: Vec<u8>,
    pub title: Vec<u8>,
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
        let lines = response
            .expect_multiline()
            .map_err(rootcause::Report::new)?;
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

fn hex_string_to_bytes(text: &str) -> Result<Vec<u8>, ParseError> {
    if !text.len().is_multiple_of(2) {
        return Err(ParseError::InvalidHexDigits { key: "net-blob" });
    }

    let mut bytes = Vec::with_capacity(text.len() / 2);

    for chunk in text.as_bytes().chunks(2) {
        let pair = core::str::from_utf8(chunk)
            .map_err(|_| ParseError::InvalidHexDigits { key: "net-blob" })?;
        bytes.push(
            u8::from_str_radix(pair, 16)
                .map_err(|_| ParseError::InvalidHexDigits { key: "net-blob" })?,
        );
    }

    Ok(bytes)
}
