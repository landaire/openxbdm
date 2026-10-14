//! Commands for inspecting loaded modules and running threads.

use crate::commands::kv::KvLine;
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

fn report_parse(err: ParseError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

fn report_argument(err: ArgumentError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

fn require_u32(kv: &KvLine<'_>, key: &'static str) -> Result<u32, ParseError> {
    value_u32(kv.require(key)?, key)
}

/// `modules`: all kernel and user-space modules loaded on the console.
#[derive(Debug, Clone, Copy)]
pub struct Modules;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u32,
    pub size: u32,
    pub checksum: u32,
    pub timestamp: u32,
    pub pdata: u32,
    pub psize: u32,
    pub thread: u32,
    pub osize: u32,
    pub is_dll: bool,
    pub is_tls: bool,
    pub is_xbe: bool,
}

impl Command for Modules {
    type Output = Vec<ModuleInfo>;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("modules".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let lines = response
            .expect_multiline()
            .map_err(rootcause::Report::new)?;
        let mut out = Vec::with_capacity(lines.len());
        for line in lines {
            let kv = parse_kv_line(&line);
            let name = kv
                .require("name")
                .map_err(report_parse)?
                .as_str()
                .to_owned();
            out.push(ModuleInfo {
                name,
                base: require_u32(&kv, "base").map_err(report_parse)?,
                size: require_u32(&kv, "size").map_err(report_parse)?,
                checksum: require_u32(&kv, "check").map_err(report_parse)?,
                timestamp: require_u32(&kv, "timestamp").map_err(report_parse)?,
                pdata: require_u32(&kv, "pdata").map_err(report_parse)?,
                psize: require_u32(&kv, "psize").map_err(report_parse)?,
                thread: require_u32(&kv, "thread").map_err(report_parse)?,
                osize: require_u32(&kv, "osize").map_err(report_parse)?,
                is_dll: kv.has_flag("dll"),
                is_tls: kv.has_flag("tls"),
                is_xbe: kv.has_flag("xbe"),
            });
        }
        Ok(out)
    }
}

/// `modsections NAME="..."`: the section table of a loaded module.
#[derive(Debug, Clone)]
pub struct ModuleSections {
    pub module: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionFlags(pub u32);

impl SectionFlags {
    pub const READABLE: u32 = 0x02;
    pub const WRITABLE: u32 = 0x04;
    pub const EXECUTABLE: u32 = 0x08;
    pub const UNINITIALIZED: u32 = 0x10;

    pub fn readable(self) -> bool {
        self.0 & Self::READABLE != 0
    }
    pub fn writable(self) -> bool {
        self.0 & Self::WRITABLE != 0
    }
    pub fn executable(self) -> bool {
        self.0 & Self::EXECUTABLE != 0
    }
    pub fn uninitialized(self) -> bool {
        self.0 & Self::UNINITIALIZED != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSection {
    pub name: String,
    pub base: u32,
    pub size: u32,
    pub index: u32,
    pub flags: SectionFlags,
}

impl Command for ModuleSections {
    type Output = Vec<ModuleSection>;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        if self.module.is_empty() {
            return Err(report_argument(ArgumentError::EmptyFilename));
        }
        ArgBuilder::new("modsections")
            .quoted("NAME", &self.module)
            .map_err(report_argument)
            .map(ArgBuilder::finish)
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let lines = response
            .expect_multiline()
            .map_err(rootcause::Report::new)?;
        let mut out = Vec::with_capacity(lines.len());
        for line in lines {
            let kv = parse_kv_line(&line);
            out.push(ModuleSection {
                name: kv
                    .require("name")
                    .map_err(report_parse)?
                    .as_str()
                    .to_owned(),
                base: require_u32(&kv, "base").map_err(report_parse)?,
                size: require_u32(&kv, "size").map_err(report_parse)?,
                index: require_u32(&kv, "index").map_err(report_parse)?,
                flags: SectionFlags(require_u32(&kv, "flags").map_err(report_parse)?),
            });
        }
        Ok(out)
    }
}

/// Typed 32-bit thread handle. On the wire XBDM prints these as signed
/// decimals via `%d`, but they are really unsigned kernel handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ThreadId(pub u32);

impl ThreadId {
    pub fn from_signed(raw: i32) -> Self {
        Self(raw as u32)
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl core::fmt::Display for ThreadId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

/// `threads`: list of live thread ids.
#[derive(Debug, Clone, Copy)]
pub struct Threads;

impl Command for Threads {
    type Output = Vec<ThreadId>;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("threads".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let lines = response
            .expect_multiline()
            .map_err(rootcause::Report::new)?;
        let mut out = Vec::with_capacity(lines.len());
        for line in lines {
            let trimmed = line.trim();
            let signed = trimmed
                .parse::<i32>()
                .map_err(|_| report_parse(ParseError::InvalidDecimalU32 { key: "thread-id" }))?;
            out.push(ThreadId::from_signed(signed));
        }
        Ok(out)
    }
}

/// `threadinfo THREAD=<id>`: detailed info for a single thread.
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub thread: ThreadId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadDetail {
    pub thread: ThreadId,
    pub suspend: u32,
    pub priority: i32,
    pub tls_base: u32,
    pub start: u32,
    pub base: u32,
    pub limit: u32,
    pub slack: u32,
    pub create_time: FileTime,
    pub name_address: u32,
    pub name_length: u32,
    pub processor: u32,
    pub last_error: u32,
}

impl Command for ThreadInfo {
    type Output = ThreadDetail;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("threadinfo")
            .hex32("THREAD", self.thread.as_u32())
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let mut lines = response
            .expect_multiline()
            .map_err(rootcause::Report::new)?;
        let head = lines
            .pop()
            .ok_or_else(|| report_parse(ParseError::UnrecognizedShape))?;
        let kv = parse_kv_line(&head);
        let create_hi = require_u32(&kv, "createhi").map_err(report_parse)?;
        let create_lo = require_u32(&kv, "createlo").map_err(report_parse)?;
        let priority_value = kv.require("priority").map_err(report_parse)?;
        let priority = priority_value
            .as_str()
            .parse::<i32>()
            .map_err(|_| report_parse(ParseError::InvalidDecimalU32 { key: "priority" }))?;
        Ok(ThreadDetail {
            thread: self.thread,
            suspend: require_u32(&kv, "suspend").map_err(report_parse)?,
            priority,
            tls_base: require_u32(&kv, "tlsbase").map_err(report_parse)?,
            start: require_u32(&kv, "start").map_err(report_parse)?,
            base: require_u32(&kv, "base").map_err(report_parse)?,
            limit: require_u32(&kv, "limit").map_err(report_parse)?,
            slack: require_u32(&kv, "slack").map_err(report_parse)?,
            create_time: FileTime::from_halves(create_hi, create_lo),
            name_address: require_u32(&kv, "nameaddr").map_err(report_parse)?,
            name_length: require_u32(&kv, "namelen").map_err(report_parse)?,
            processor: require_u32(&kv, "proc").map_err(report_parse)?,
            last_error: require_u32(&kv, "lasterr").map_err(report_parse)?,
        })
    }
}

/// Kernel handle of a thread object, as opposed to a [`ThreadId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadHandle(pub u32);

/// Thread exit status reported by `threadstat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadExitCode(pub u32);

impl ThreadExitCode {
    /// Reported for threads that have not terminated (and for threads
    /// that exited with this value).
    pub const STILL_ACTIVE: Self = Self(0x103);
}

/// Win32 error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Win32Error(pub u32);

/// `threadstat handle=0x<handle>`: exit status of the thread object a
/// handle refers to. A missing handle gives `423- bad parameter`.
#[derive(Debug, Clone, Copy)]
pub struct ThreadStat {
    pub handle: ThreadHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadStatus {
    /// `200- Exit Code 0x%x`.
    ExitCode(ThreadExitCode),
    /// `200- Error 0x%x`: the handle did not reference a thread object.
    LookupFailed(Win32Error),
}

impl Command for ThreadStat {
    type Output = ThreadStatus;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("threadstat")
            .hex32("handle", self.handle.0)
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let hex = |text: &str, key: &'static str| {
            text.strip_prefix("0x")
                .and_then(|digits| u32::from_str_radix(digits, 16).ok())
                .ok_or_else(|| report_parse(ParseError::InvalidHexDigits { key }))
        };
        if let Some(value) = head.strip_prefix("Exit Code ") {
            hex(value, "Exit Code").map(|code| ThreadStatus::ExitCode(ThreadExitCode(code)))
        } else if let Some(value) = head.strip_prefix("Error ") {
            hex(value, "Error").map(|code| ThreadStatus::LookupFailed(Win32Error(code)))
        } else {
            Err(report_parse(ParseError::UnrecognizedShape))
        }
    }
}

/// `xbeinfo RUNNING` or `xbeinfo NAME="..."`: the object path of the
/// running executable. The console answers a named query with the running
/// executable too; timestamp and checksum are always 0.
#[derive(Debug, Clone)]
pub enum XbeInfo {
    Running,
    Named(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XbeInfoResult {
    pub timestamp: u32,
    pub checksum: u32,
    pub name: String,
}

impl Command for XbeInfo {
    type Output = XbeInfoResult;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        match self {
            XbeInfo::Running => Ok(ArgBuilder::new("xbeinfo").flag("RUNNING").finish()),
            XbeInfo::Named(path) => ArgBuilder::new("xbeinfo")
                .quoted("NAME", path)
                .map_err(report_argument)
                .map(ArgBuilder::finish),
        }
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let lines = response
            .expect_multiline()
            .map_err(rootcause::Report::new)?;
        let mut timestamp: Option<u32> = None;
        let mut checksum: Option<u32> = None;
        let mut name: Option<String> = None;
        for line in lines {
            let kv = parse_kv_line(&line);
            if let Some(value) = kv.get("timestamp") {
                timestamp = Some(value_u32(value, "timestamp").map_err(report_parse)?);
            }
            if let Some(value) = kv.get("checksum") {
                checksum = Some(value_u32(value, "checksum").map_err(report_parse)?);
            }
            if let Some(value) = kv.get("name") {
                name = Some(value.as_str().to_owned());
            }
        }
        Ok(XbeInfoResult {
            timestamp: timestamp
                .ok_or(ParseError::MissingKey { key: "timestamp" })
                .map_err(report_parse)?,
            checksum: checksum
                .ok_or(ParseError::MissingKey { key: "checksum" })
                .map_err(report_parse)?,
            name: name
                .ok_or(ParseError::MissingKey { key: "name" })
                .map_err(report_parse)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SuccessCode;

    #[test]
    fn threadstat_parses_both_reply_forms() {
        let command = ThreadStat {
            handle: ThreadHandle(0x10),
        };
        let replies: Vec<ThreadStatus> = ["Exit Code 0x103", "Exit Code 0x0", "Error 0x6"]
            .iter()
            .map(|head| {
                command
                    .parse(Response::Line {
                        code: SuccessCode::Ok,
                        head: (*head).to_owned(),
                    })
                    .unwrap()
            })
            .collect();
        insta::assert_snapshot!(
            format!("{replies:x?}"),
            @"[ExitCode(ThreadExitCode(103)), ExitCode(ThreadExitCode(0)), LookupFailed(Win32Error(6))]"
        );
    }
}
