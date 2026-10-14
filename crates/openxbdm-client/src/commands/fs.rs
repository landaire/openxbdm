//! Filesystem metadata and manipulation commands.
//!
//! All commands here are metadata-only; streaming file transfers live in
//! [`crate::commands::file`] so that their async read/write surface stays
//! separate from the simple request/response shapes here.

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

/// Composite u64 from `KEY_hi` + `KEY_lo` XBDM fields.
fn hi_lo_u64(kv: &KvLine<'_>, hi_key: &'static str, lo_key: &'static str) -> Result<u64, ParseError> {
    let hi = value_u32(kv.require(hi_key)?, hi_key)?;
    let lo = value_u32(kv.require(lo_key)?, lo_key)?;
    Ok(((hi as u64) << 32) | (lo as u64))
}

fn report_parse(err: ParseError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

fn report_argument(err: ArgumentError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

fn reject_empty(name: &str) -> Result<(), rootcause::Report<Error>> {
    if name.is_empty() { Err(report_argument(ArgumentError::EmptyFilename)) } else { Ok(()) }
}

/// `drivefreespace NAME="X:\"` -> free and total byte counters.
#[derive(Debug, Clone)]
pub struct DriveFreeSpace {
    pub drive: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriveSpace {
    pub free_to_caller_bytes: u64,
    pub total_bytes: u64,
    pub total_free_bytes: u64,
}

impl Command for DriveFreeSpace {
    type Output = DriveSpace;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        reject_empty(&self.drive)?;
        ArgBuilder::new("drivefreespace").quoted("NAME", &self.drive).map_err(report_argument).map(ArgBuilder::finish)
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let mut lines = response.expect_multiline().map_err(rootcause::Report::new)?;
        let head = lines.pop().ok_or_else(|| report_parse(ParseError::UnrecognizedShape))?;
        let kv = parse_kv_line(&head);
        Ok(DriveSpace {
            free_to_caller_bytes: hi_lo_u64(&kv, "freetocallerhi", "freetocallerlo").map_err(report_parse)?,
            total_bytes: hi_lo_u64(&kv, "totalbyteshi", "totalbyteslo").map_err(report_parse)?,
            total_free_bytes: hi_lo_u64(&kv, "totalfreebyteshi", "totalfreebyteslo").map_err(report_parse)?,
        })
    }
}

/// `dirlist NAME="X:\\path"` -> each entry's name, size, timestamps, and
/// `is_directory` flag.
#[derive(Debug, Clone)]
pub struct DirList {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub size: u64,
    pub create_time: FileTime,
    pub change_time: FileTime,
    pub is_directory: bool,
}

impl Command for DirList {
    type Output = Vec<DirEntry>;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        reject_empty(&self.path)?;
        ArgBuilder::new("dirlist").quoted("NAME", &self.path).map_err(report_argument).map(ArgBuilder::finish)
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let lines = response.expect_multiline().map_err(rootcause::Report::new)?;
        let mut entries = Vec::with_capacity(lines.len());
        for line in lines {
            let kv = parse_kv_line(&line);
            let name_value = kv.require("name").map_err(report_parse)?;
            let size = hi_lo_u64(&kv, "sizehi", "sizelo").map_err(report_parse)?;
            let create_raw = hi_lo_u64(&kv, "createhi", "createlo").map_err(report_parse)?;
            let change_raw = hi_lo_u64(&kv, "changehi", "changelo").map_err(report_parse)?;
            entries.push(DirEntry {
                name: name_value.as_str().to_owned(),
                size,
                create_time: FileTime::from_raw(create_raw),
                change_time: FileTime::from_raw(change_raw),
                is_directory: kv.has_flag("directory"),
            });
        }
        Ok(entries)
    }
}

/// `getfileattributes NAME="X:\\path"` -> size, timestamps, is_directory.
#[derive(Debug, Clone)]
pub struct GetFileAttributes {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAttributes {
    pub size: u64,
    pub create_time: FileTime,
    pub change_time: FileTime,
    pub is_directory: bool,
}

impl Command for GetFileAttributes {
    type Output = FileAttributes;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        reject_empty(&self.path)?;
        ArgBuilder::new("getfileattributes").quoted("NAME", &self.path).map_err(report_argument).map(ArgBuilder::finish)
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let mut lines = response.expect_multiline().map_err(rootcause::Report::new)?;
        let head = lines.pop().ok_or_else(|| report_parse(ParseError::UnrecognizedShape))?;
        let kv = parse_kv_line(&head);
        Ok(FileAttributes {
            size: hi_lo_u64(&kv, "sizehi", "sizelo").map_err(report_parse)?,
            create_time: FileTime::from_raw(hi_lo_u64(&kv, "createhi", "createlo").map_err(report_parse)?),
            change_time: FileTime::from_raw(hi_lo_u64(&kv, "changehi", "changelo").map_err(report_parse)?),
            is_directory: kv.has_flag("directory"),
        })
    }
}

/// `mkdir NAME="X:\\path"`.
#[derive(Debug, Clone)]
pub struct MakeDirectory {
    pub path: String,
}

impl Command for MakeDirectory {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        reject_empty(&self.path)?;
        ArgBuilder::new("mkdir").quoted("NAME", &self.path).map_err(report_argument).map(ArgBuilder::finish)
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `delete NAME="X:\\path"` or `delete NAME="X:\\path" DIR` for directories.
#[derive(Debug, Clone)]
pub struct Delete {
    pub path: String,
    pub is_directory: bool,
}

impl Command for Delete {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        reject_empty(&self.path)?;
        let mut builder = ArgBuilder::new("delete").quoted("NAME", &self.path).map_err(report_argument)?;
        if self.is_directory {
            builder = builder.flag("DIR");
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

/// `fileeof NAME="X:\\path" SIZE=<n>`: truncate or extend a file.
/// Optionally pass `CREATE` (via the `create_if_missing` flag) so the
/// file is created when absent.
#[derive(Debug, Clone)]
pub struct FileEof {
    pub path: String,
    pub size: u64,
    pub create_if_missing: bool,
}

impl Command for FileEof {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        reject_empty(&self.path)?;
        let mut builder =
            ArgBuilder::new("fileeof").quoted("NAME", &self.path).map_err(report_argument)?.dec("SIZE", self.size);
        if self.create_if_missing {
            builder = builder.flag("CREATE");
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

/// `rename NAME="X:\\src" NEWNAME="X:\\dst"`.
#[derive(Debug, Clone)]
pub struct Rename {
    pub from: String,
    pub to: String,
}

impl Command for Rename {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        reject_empty(&self.from)?;
        reject_empty(&self.to)?;
        let builder = ArgBuilder::new("rename")
            .quoted("NAME", &self.from)
            .map_err(report_argument)?
            .quoted("NEWNAME", &self.to)
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
