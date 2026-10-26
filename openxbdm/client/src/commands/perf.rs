//! Performance-counter and socket-info probes.

use crate::commands::error::report_argument;
use crate::commands::error::report_parse;
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

/// `pclist`: enumerate every performance counter currently registered
/// with XBDM. The set is dynamic - the kernel registers a base set at
/// boot (CPU, audio, network, memory pools) and the running title can
/// add its own (GPU pipeline stages, cmd-buffer bytes, VMX usage).
///
/// Each entry carries a `name` (pass-through string) and a `kind` tag
/// that disambiguates counters sharing the same name but reporting
/// different families of values. Feed both back to [`QueryPerfCounter`]
/// to read a sample.
#[derive(Debug, Clone, Copy)]
pub struct PerfCounterList;

impl Command for PerfCounterList {
    type Output = Vec<PerfCounterEntry>;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("pclist".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let lines = response
            .expect_multiline()
            .map_err(rootcause::Report::new)?;

        let mut entries = Vec::with_capacity(lines.len());
        for line in lines {
            let kv = parse_kv_line(&line);
            entries.push(PerfCounterEntry {
                name: kv
                    .require("name")
                    .map_err(report_parse)?
                    .as_str()
                    .to_owned(),
                kind: require_u32(&kv, "type").map_err(report_parse)?,
            });
        }

        Ok(entries)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfCounterEntry {
    /// Counter name as the kernel/title registered it. Case-sensitive.
    pub name: String,
    /// Counter "type" tag from xbdm. Not an enum; treat as opaque and
    /// pass verbatim to [`QueryPerfCounter::kind`].
    pub kind: u32,
}

/// `querypc NAME="<counter>" TYPE=<kind>`: snapshot a single
/// performance counter's cumulative value and current rate.
///
/// Reply shape (from xbdm):
/// `type=0x%08x vallo=0x%08x valhi=0x%08x ratelo=0x%08x ratehi=0x%08x`.
/// The two 32-bit halves are combined into the `u64` fields on
/// [`PerfCounterSample`]. Units depend on the counter: "rate" is
/// typically per-second for time-based counters, per-frame for GPU
/// counters. There is no meta-description wire command, so unit
/// interpretation is on the caller.
#[derive(Debug, Clone)]
pub struct QueryPerfCounter {
    /// Counter name, exactly as returned by [`PerfCounterList`].
    pub name: String,
    /// `type` tag returned with the name in [`PerfCounterList`].
    pub kind: u32,
}

impl Command for QueryPerfCounter {
    type Output = PerfCounterSample;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        if self.name.is_empty() {
            return Err(
                report_argument(ArgumentError::EmptyFilename).attach("querypc NAME required")
            );
        }

        let builder = ArgBuilder::new("querypc")
            .quoted("NAME", &self.name)
            .map_err(report_argument)?
            .hex32("TYPE", self.kind);

        Ok(builder.finish())
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

        Ok(PerfCounterSample {
            kind: require_u32(&kv, "type").map_err(report_parse)?,
            value: hi_lo_u64(&kv, "valhi", "vallo").map_err(report_parse)?,
            rate: hi_lo_u64(&kv, "ratehi", "ratelo").map_err(report_parse)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfCounterSample {
    /// Echo of the counter's `type` tag.
    pub kind: u32,
    /// Cumulative counter value.
    pub value: u64,
    /// Per-interval rate. Interval and unit are counter-specific.
    pub rate: u64,
}

/// `getsockinfo`: every active socket of the console network stack.
#[derive(Debug, Clone, Copy)]
pub struct GetSocketInfo;

impl Command for GetSocketInfo {
    type Output = Vec<SocketEntry>;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("getsockinfo".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let lines = response
            .expect_multiline()
            .map_err(rootcause::Report::new)?;

        let mut sockets = Vec::with_capacity(lines.len());
        for line in lines {
            let kv = parse_kv_line(&line);
            sockets.push(SocketEntry {
                handle: require_u32(&kv, "handle").map_err(report_parse)?,
                owner_type: require_i32(&kv, "ownertype").map_err(report_parse)?,
                flags: require_u32(&kv, "flags").map_err(report_parse)?,
                addr_family: require_i32(&kv, "addrfamily").map_err(report_parse)?,
                socket_type: require_i32(&kv, "socktype").map_err(report_parse)?,
                protocol: require_i32(&kv, "protocol").map_err(report_parse)?,
                local_addr: require_u32(&kv, "localaddr").map_err(report_parse)?,
                remote_addr: require_u32(&kv, "remoteaddr").map_err(report_parse)?,
                local_port: require_u16(&kv, "localport").map_err(report_parse)?,
                remote_port: require_u16(&kv, "remoteport").map_err(report_parse)?,
                tcp_state: require_u8(&kv, "tcpstate").map_err(report_parse)?,
            });
        }

        Ok(sockets)
    }
}

/// One socket. The console prints owner type, family, type, and protocol
/// as signed decimals and the TCP state from a byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketEntry {
    pub handle: u32,
    pub owner_type: i32,
    pub flags: u32,
    pub addr_family: i32,
    pub socket_type: i32,
    pub protocol: i32,

    pub local_addr: u32,
    pub remote_addr: u32,
    pub local_port: u16,
    pub remote_port: u16,

    pub tcp_state: u8,
}

fn require_u32(kv: &KvLine<'_>, key: &'static str) -> Result<u32, ParseError> {
    value_u32(kv.require(key)?, key)
}

fn require_i32(kv: &KvLine<'_>, key: &'static str) -> Result<i32, ParseError> {
    kv.require(key)?
        .as_str()
        .parse::<i32>()
        .map_err(|_| ParseError::InvalidDecimalI32 { key })
}

fn require_u16(kv: &KvLine<'_>, key: &'static str) -> Result<u16, ParseError> {
    let value = require_u32(kv, key)?;
    u16::try_from(value).map_err(|_| ParseError::ValueOutOfRange { key, value })
}

fn require_u8(kv: &KvLine<'_>, key: &'static str) -> Result<u8, ParseError> {
    let value = require_u32(kv, key)?;
    u8::try_from(value).map_err(|_| ParseError::ValueOutOfRange { key, value })
}

fn hi_lo_u64(kv: &KvLine<'_>, hi: &'static str, lo: &'static str) -> Result<u64, ParseError> {
    let high = require_u32(kv, hi)?;
    let low = require_u32(kv, lo)?;

    Ok(((high as u64) << 32) | (low as u64))
}
