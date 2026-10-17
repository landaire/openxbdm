//! Kernel debugger control: `kd`, `kdlite`, and `kdnet`.

use core::fmt::Write as _;
use core::net::Ipv4Addr;

use crate::commands::error::report_parse;
use crate::error::Error;
use crate::error::ParseError;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ExpectedBody;
use crate::protocol::Response;

pub use openxbdm_core::status::Hresult;

/// `kd <subcommand>`: route debug exceptions to the kernel debugger or to
/// the debug monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kd {
    /// `kd enable`: pass debug exceptions to the kernel debugger.
    /// Reply `200- kd enabled`.
    Enable,
    /// `kd disable`: handle debug exceptions in the debug monitor.
    /// Reply `200- kd disabled`.
    Disable,
    /// `kd except`: enable, then release every stopped thread.
    /// Reply `200- OK`.
    Except,
    /// `kd exceptif`: perform `except` only when a kernel debugger is
    /// present; otherwise nothing changes. Reply `200- OK`.
    ExceptIf,
}

impl Command for Kd {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let token = match self {
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Except => "except",
            Self::ExceptIf => "exceptif",
        };

        Ok(ArgBuilder::new("kd").flag(token).finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;

        Ok(())
    }
}

/// `kdlite enable|disable`: set or clear the persistent kernel debugger
/// lite setting. Replies `200- kd lite enabled` / `200- kd lite disabled`;
/// consoles without the kernel capability, or a failed configuration
/// write, give `400- improper command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdLite {
    Enable,
    Disable,
}

impl Command for KdLite {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let token = match self {
            Self::Enable => "enable",
            Self::Disable => "disable",
        };

        Ok(ArgBuilder::new("kdlite").flag(token).finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;

        Ok(())
    }
}

/// Six-octet Ethernet address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl core::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [octet0, octet1, octet2, octet3, octet4, octet5] = self.0;
        write!(
            f,
            "{octet0:02X}-{octet1:02X}-{octet2:02X}-{octet3:02X}-{octet4:02X}-{octet5:02X}"
        )
    }
}

impl core::str::FromStr for MacAddress {
    type Err = ParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut parts = text.split('-');

        for octet in &mut octets {
            let part = parts.next().ok_or(ParseError::UnrecognizedShape)?;
            *octet = u8::from_str_radix(part, 16)
                .map_err(|_| ParseError::InvalidHexDigits { key: "Target MAC" })?;
        }

        if parts.next().is_some() {
            return Err(ParseError::UnrecognizedShape);
        }

        Ok(Self(octets))
    }
}

/// Outcome of `kdnet enable` / `kdnet disable`. Both forms reply 200.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdNetUpdate {
    /// `kdnet enabled: 0x%08x` / `kdnet disabled: 0x%08x`: status of the
    /// flash write, which may be a failure.
    Saved(Hresult),
    /// `kdnet: unable to load current kdnet settings: 0x%08x`.
    LoadFailed(Hresult),
}

/// `kdnet enable`: set the enable field of the network kernel debugger
/// record. A record without host address, MAC and port gives
/// `407- kdnet: can't enable kdnet without setting the parameters.`; flash
/// versions without kdnet give `407- kdnet is not supported on this flash
/// version.` followed by byte 0x1e.
#[derive(Debug, Clone, Copy)]
pub struct KdNetEnable;

impl Command for KdNetEnable {
    type Output = KdNetUpdate;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("kdnet enable".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        parse_update(&head, "kdnet enabled: ").map_err(report_parse)
    }
}

/// `kdnet disable`: clear the enable field of the network kernel debugger
/// record.
#[derive(Debug, Clone, Copy)]
pub struct KdNetDisable;

impl Command for KdNetDisable {
    type Output = KdNetUpdate;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("kdnet disable".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        parse_update(&head, "kdnet disabled: ").map_err(report_parse)
    }
}

/// Network kernel debugger record stored in flash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdNetSettings {
    /// Raw enable field (1 after `kdnet enable` or `kdnet set`).
    pub enable: u32,
    pub target_ip: Ipv4Addr,
    pub target_mac: MacAddress,
    pub host_ip: Ipv4Addr,
    pub host_port: u16,
    /// Raw encrypted field; not written by any `kdnet` subcommand.
    pub encrypted: u32,
}

/// Outcome of `kdnet show`. Both forms reply 200.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdNetQuery {
    Settings(KdNetSettings),
    /// `kdnet: failed to load current settings: 0x%08X`.
    LoadFailed(Hresult),
}

/// `kdnet show`: read the network kernel debugger record.
#[derive(Debug, Clone, Copy)]
pub struct KdNetShow;

impl Command for KdNetShow {
    type Output = KdNetQuery;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("kdnet show".to_owned())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        parse_settings(&head).map_err(report_parse)
    }
}

/// MAC address written by `kdnet set`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdNetMac {
    /// `Mac=` with an empty value: the console MAC with its last octet
    /// decremented.
    ConsoleDerived,
    Address(MacAddress),
}

/// `kdnet set [IP=<host>] [Port=<port>] [Mac=<mac>]`: write the network
/// kernel debugger record and set its enable field. Omitted fields keep
/// their flash values, except that an all-zero stored MAC is replaced as
/// for [`KdNetMac::ConsoleDerived`]. Reply `200- kdnet set succeeded.`;
/// failures reply `kdnet set failed: error code 0x%08x` with status 423
/// (no field given, or the resulting record is incomplete) or 400.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdNetSet {
    pub host_ip: Option<Ipv4Addr>,
    pub host_port: Option<u16>,
    pub target_mac: Option<KdNetMac>,
}

impl Command for KdNetSet {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut line = String::from("kdnet set");

        if let Some(ip) = self.host_ip {
            let _ = write!(line, " IP={ip}");
        }

        if let Some(port) = self.host_port {
            let _ = write!(line, " Port={port}");
        }

        match self.target_mac {
            Some(KdNetMac::ConsoleDerived) => line.push_str(" Mac="),
            Some(KdNetMac::Address(mac)) => {
                let _ = write!(line, " Mac={mac}");
            }
            // Omitted fields keep their flash values.
            None => {}
        }

        Ok(line)
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;

        Ok(())
    }
}

fn parse_status_hex(text: &str, key: &'static str) -> Result<Hresult, ParseError> {
    let digits = text
        .strip_prefix("0x")
        .ok_or(ParseError::InvalidHexDigits { key })?;

    u32::from_str_radix(digits, 16)
        .map(Hresult)
        .map_err(|_| ParseError::InvalidHexDigits { key })
}

fn parse_update(head: &str, saved_prefix: &str) -> Result<KdNetUpdate, ParseError> {
    if let Some(status) = head.strip_prefix(saved_prefix) {
        return parse_status_hex(status, "status").map(KdNetUpdate::Saved);
    }

    if let Some(status) = head.strip_prefix("kdnet: unable to load current kdnet settings: ") {
        return parse_status_hex(status, "status").map(KdNetUpdate::LoadFailed);
    }

    Err(ParseError::UnrecognizedShape)
}

/// Fields of the `kdnet show` line, separated by byte 0x1e and each
/// introduced by a tab.
fn parse_settings(head: &str) -> Result<KdNetQuery, ParseError> {
    if let Some(status) = head.strip_prefix("kdnet: failed to load current settings: ") {
        return parse_status_hex(status, "status").map(KdNetQuery::LoadFailed);
    }

    let body = head
        .strip_prefix("kdnet settings:\u{1e}")
        .ok_or(ParseError::UnrecognizedShape)?;

    let mut fields = body.split('\u{1e}');
    let mut field = |prefix: &str, key: &'static str| {
        fields
            .next()
            .and_then(|text| text.strip_prefix('\t'))
            .and_then(|text| text.strip_prefix(prefix))
            .ok_or(ParseError::MissingKey { key })
    };

    // `%d` of an unsigned field.
    let signed = |text: &str, key: &'static str| {
        text.parse::<i32>()
            .map(|value| value as u32)
            .map_err(|_| ParseError::InvalidDecimalU32 { key })
    };
    let ip = |text: &str| {
        text.parse::<Ipv4Addr>()
            .map_err(|_| ParseError::UnrecognizedShape)
    };

    let enable = signed(field("Enable=", "Enable")?, "Enable")?;
    let target_ip = ip(field("Target IP: ", "Target IP")?)?;
    let target_mac = field("Target MAC: ", "Target MAC")?.parse::<MacAddress>()?;
    let host_ip = ip(field("Host IP: ", "Host IP")?)?;
    let host_port = field("Host Port: ", "Host Port")?
        .parse::<u16>()
        .map_err(|_| ParseError::InvalidDecimalU32 { key: "Host Port" })?;
    let encrypted = signed(field("Encrypted: ", "Encrypted")?, "Encrypted")?;

    if fields.next() != Some("") || fields.next().is_some() {
        return Err(ParseError::UnrecognizedShape);
    }

    Ok(KdNetQuery::Settings(KdNetSettings {
        enable,
        target_ip,
        target_mac,
        host_ip,
        host_port,
        encrypted,
    }))
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

    #[test]
    fn kdnet_show_parses_settings_line() {
        let head = "kdnet settings:\u{1e}\tEnable=1\u{1e}\tTarget IP: 0.0.0.0\u{1e}\tTarget MAC: 00-0D-3A-12-34-55\u{1e}\tHost IP: 192.168.1.20\u{1e}\tHost Port: 50000\u{1e}\tEncrypted: 0\u{1e}";
        insta::assert_debug_snapshot!(KdNetShow.parse(ok(head)).unwrap());
    }

    #[test]
    fn kdnet_show_parses_load_failure() {
        let query = KdNetShow
            .parse(ok("kdnet: failed to load current settings: 0x9000000E"))
            .unwrap();
        insta::assert_snapshot!(format!("{query:x?}"), @"LoadFailed(Hresult(9000000e))");
    }

    #[test]
    fn kdnet_toggle_parses_both_reply_forms() {
        let replies = [
            KdNetEnable.parse(ok("kdnet enabled: 0x00000000")).unwrap(),
            KdNetDisable
                .parse(ok("kdnet disabled: 0x90000001"))
                .unwrap(),
            KdNetEnable
                .parse(ok(
                    "kdnet: unable to load current kdnet settings: 0x9000000e",
                ))
                .unwrap(),
        ];
        insta::assert_snapshot!(format!("{replies:x?}"), @"[Saved(Hresult(0)), Saved(Hresult(90000001)), LoadFailed(Hresult(9000000e))]");
    }

    #[test]
    fn kdnet_set_wire_line() {
        let full = KdNetSet {
            host_ip: Some(Ipv4Addr::new(192, 168, 1, 20)),
            host_port: Some(50000),
            target_mac: Some(KdNetMac::Address(MacAddress([
                0x00, 0x0d, 0x3a, 0x12, 0x34, 0x55,
            ]))),
        };
        let derived = KdNetSet {
            host_ip: None,
            host_port: None,
            target_mac: Some(KdNetMac::ConsoleDerived),
        };
        insta::assert_snapshot!(format!("{}\n{}", full.wire_line().unwrap(), derived.wire_line().unwrap()), @r###"
        kdnet set IP=192.168.1.20 Port=50000 Mac=00-0D-3A-12-34-55
        kdnet set Mac=
        "###);
    }
}
