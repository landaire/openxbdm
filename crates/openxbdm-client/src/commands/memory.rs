//! Memory reads and virtual-memory map enumeration.

use crate::commands::kv::KvLine;
use crate::commands::kv::parse_kv_line;
use crate::commands::kv::value_u32;
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

/// `getmem ADDR=<va> LENGTH=<n>`: read `n` bytes from virtual address `va`.
///
/// The response is a `202` multiline body of hex lines of up to 32 bytes.
/// Bytes of unmapped pages appear as `??` pairs; they decode to `0x00` in
/// the returned `Vec<u8>` and are listed in `unmapped_offsets`. The console
/// accepts any length, including 0.
#[derive(Debug, Clone, Copy)]
pub struct GetMem {
    pub address: u32,
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorySnapshot {
    pub address: u32,
    pub data: Vec<u8>,
    /// Byte offsets (relative to `address`) that the kernel reported as
    /// unmapped via `??` markers. The corresponding bytes in `data` are
    /// zero so callers can still hex-dump the full range.
    pub unmapped_offsets: Vec<u32>,
}

impl Command for GetMem {
    type Output = MemorySnapshot;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("getmem")
            .hex32("ADDR", self.address)
            .hex32("LENGTH", self.length)
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let lines = response
            .expect_multiline()
            .map_err(rootcause::Report::new)?;
        let expected = self.length as usize;
        let mut actual = 0usize;
        for line in &lines {
            let bytes = line.as_bytes();
            if bytes.len() % 2 != 0 {
                return Err(report_parse(ParseError::InvalidHexDigits {
                    key: "memory-hex",
                }));
            }
            actual = actual.saturating_add(bytes.len() / 2);
        }
        if actual != expected {
            return Err(report_parse(ParseError::MemoryLengthMismatch {
                expected,
                actual,
            }));
        }

        let mut data = Vec::with_capacity(expected);
        let mut unmapped = Vec::new();
        for line in lines {
            for chunk in line.as_bytes().chunks(2) {
                if chunk == b"??" {
                    unmapped.push(data.len() as u32);
                    data.push(0);
                    continue;
                }
                let pair = core::str::from_utf8(chunk).map_err(|_| {
                    report_parse(ParseError::InvalidHexDigits { key: "memory-hex" })
                })?;
                let byte = u8::from_str_radix(pair, 16).map_err(|_| {
                    report_parse(ParseError::InvalidHexDigits { key: "memory-hex" })
                })?;
                data.push(byte);
            }
        }
        Ok(MemorySnapshot {
            address: self.address,
            data,
            unmapped_offsets: unmapped,
        })
    }
}

/// `setmem ADDR=<va> DATA=<hex>`: write bytes to the console's virtual
/// address space. The console replies `200- set <n> bytes`, or `404- set
/// <n> bytes` when it stopped at an unmapped or unwritable page; both yield
/// the count written.
#[derive(Debug, Clone)]
pub struct SetMem {
    pub address: u32,
    pub data: Vec<u8>,
}

/// Result of a [`SetMem`] command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BytesWritten {
    pub requested: u32,
    pub written: u32,
}

impl Command for SetMem {
    type Output = BytesWritten;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut hex = String::with_capacity(self.data.len() * 2);
        use core::fmt::Write as _;
        for byte in &self.data {
            let _ = write!(hex, "{:02X}", byte);
        }
        Ok(format!("setmem addr=0x{:08x} data={}", self.address, hex))
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        self.bytes_written(&head)
    }

    fn handle_remote(
        &self,
        code: RemoteStatus,
        message: &str,
    ) -> Option<Result<Self::Output, rootcause::Report<Error>>> {
        (code == ErrorCode::MemoryNotMapped).then(|| self.bytes_written(message))
    }
}

impl SetMem {
    /// Parse `set N bytes`, N decimal.
    fn bytes_written(&self, text: &str) -> Result<BytesWritten, rootcause::Report<Error>> {
        let written = text
            .strip_prefix("set ")
            .and_then(|rest| rest.strip_suffix(" bytes"))
            .and_then(|count| count.parse::<u32>().ok())
            .ok_or_else(|| {
                report_parse(ParseError::InvalidDecimalU32 {
                    key: "setmem-count",
                })
            })?;
        Ok(BytesWritten {
            requested: self.data.len() as u32,
            written,
        })
    }
}

/// `walkmem`: enumerate all currently-valid virtual-address ranges.
#[derive(Debug, Clone, Copy)]
pub struct WalkMem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualRegion {
    pub base: u32,
    pub size: u32,
    pub protect: u32,
}

impl Command for WalkMem {
    type Output = Vec<VirtualRegion>;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok("walkmem".to_owned())
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
            out.push(VirtualRegion {
                base: require_u32(&kv, "base").map_err(report_parse)?,
                size: require_u32(&kv, "size").map_err(report_parse)?,
                protect: require_u32(&kv, "protect").map_err(report_parse)?,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getmem_rejects_truncated_response() {
        let command = GetMem {
            address: 0x1000,
            length: 2,
        };
        let error = command
            .parse(Response::Multiline {
                head: "memory data follows".to_owned(),
                lines: vec!["AA".to_owned()],
            })
            .unwrap_err();

        assert!(matches!(
            error.current_context(),
            Error::Parse(ParseError::MemoryLengthMismatch {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn getmem_reports_complete_oversized_response_length() {
        let command = GetMem {
            address: 0x1000,
            length: 2,
        };
        let error = command
            .parse(Response::Multiline {
                head: "memory data follows".to_owned(),
                lines: vec!["AABBCCDDEEFF".to_owned()],
            })
            .unwrap_err();

        assert!(matches!(
            error.current_context(),
            Error::Parse(ParseError::MemoryLengthMismatch {
                expected: 2,
                actual: 6
            })
        ));
    }
}
