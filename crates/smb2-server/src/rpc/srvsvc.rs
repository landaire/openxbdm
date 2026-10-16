//! MS-SRVS share and server queries.

use super::PipeContext;
use super::ndr::Reader;
use super::ndr::StubString;
use super::ndr::Text;
use super::ndr::Writer;
use super::pdu::FaultStatus;
use crate::backend::COMPUTER_NAME_CAPACITY;
use crate::backend::SHARE_NAME_CAPACITY;
use crate::backend::ShareIndex;
use crate::utf16::Utf16Le;
use crate::utf16::fold_ascii;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Opnum(pub u16);

impl Opnum {
    const SHARE_ENUM: Self = Self(15);
    const SHARE_GET_INFO: Self = Self(16);
    const SERVER_GET_INFO: Self = Self(21);
}

/// Information level of a share or server query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InfoLevel(pub u32);

/// NET_API_STATUS return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetStatus(u32);

impl NetStatus {
    const SUCCESS: Self = Self(0);
    const ACCESS_DENIED: Self = Self(5);
    const INVALID_LEVEL: Self = Self(124);
    const NET_NAME_NOT_FOUND: Self = Self(2310);
}

/// Share type of a SHARE_INFO_1 (MS-SRVS 2.2.2.4): a base type and flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShareType(u32);

impl ShareType {
    const DISKTREE: Self = Self(0);
    const IPC: Self = Self(3);
    const SPECIAL: Self = Self(0x8000_0000);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

const IPC_SHARE: &[u8] = b"IPC$";
const IPC_REMARK: &[u8] = b"Remote IPC";

/// Platform identifier of a SERVER_INFO_100 or _101.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlatformId(u32);

impl PlatformId {
    const NT: Self = Self(500);
}

/// Operating system version of a SERVER_INFO_101.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OsVersion {
    major: u32,
    minor: u32,
}

impl OsVersion {
    /// Windows 7, the release that introduced SMB 2.1.
    const WINDOWS_7: Self = Self { major: 6, minor: 1 };
}

/// Server type bits of a SERVER_INFO_101 (MS-SRVS 2.2.2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServerType(u32);

impl ServerType {
    const WORKSTATION: Self = Self(0x0000_0001);
    const SERVER: Self = Self(0x0000_0002);
    const NT: Self = Self(0x0000_1000);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

const SERVER_TYPE: ServerType = ServerType::WORKSTATION
    .union(ServerType::SERVER)
    .union(ServerType::NT);

/// A decoded request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Call {
    /// NetrShareEnum. `resume` is the index of the first share to return.
    ShareEnum {
        level: InfoLevel,
        resume: Option<u32>,
    },
    /// NetrShareGetInfo; `name` lies in the retained request stub.
    ShareGetInfo { level: InfoLevel, name: StubString },
    /// NetrServerGetInfo.
    ServerGetInfo { level: InfoLevel },
}

pub(super) fn parse(opnum: Opnum, stub: &[u8]) -> Result<Call, FaultStatus> {
    let mut reader = Reader::new(stub);
    match opnum {
        Opnum::SHARE_ENUM => parse_share_enum(&mut reader),
        Opnum::SHARE_GET_INFO => {
            reader.skip_unique_string().ok_or(FaultStatus::NDR)?;
            let name = reader.string().ok_or(FaultStatus::NDR)?;
            let level = InfoLevel(reader.u32().ok_or(FaultStatus::NDR)?);
            Ok(Call::ShareGetInfo { level, name })
        }
        Opnum::SERVER_GET_INFO => {
            reader.skip_unique_string().ok_or(FaultStatus::NDR)?;
            let level = InfoLevel(reader.u32().ok_or(FaultStatus::NDR)?);
            if !server_info_arm(level) {
                return Err(FaultStatus::INVALID_TAG);
            }
            Ok(Call::ServerGetInfo { level })
        }
        _ => Err(FaultStatus::OPERATION_RANGE),
    }
}

/// ServerName, then SHARE_ENUM_STRUCT: Level, the SHARE_ENUM_UNION
/// discriminant and container pointer, the deferred container, then
/// PreferedMaximumLength and ResumeHandle.
fn parse_share_enum(reader: &mut Reader<'_>) -> Result<Call, FaultStatus> {
    reader.skip_unique_string().ok_or(FaultStatus::NDR)?;
    let level = InfoLevel(reader.u32().ok_or(FaultStatus::NDR)?);
    if reader.u32() != Some(level.0) {
        return Err(FaultStatus::NDR);
    }
    if !matches!(level.0, 0 | 1 | 2 | 501 | 502 | 503) {
        return Err(FaultStatus::INVALID_TAG);
    }
    if reader.u32().ok_or(FaultStatus::NDR)? != 0 {
        let _entries_read = reader.u32().ok_or(FaultStatus::NDR)?;
        // Clients send an empty container; entries on input are not
        // supported.
        if reader.u32().ok_or(FaultStatus::NDR)? != 0 {
            return Err(FaultStatus::NDR);
        }
    }
    // All entries are returned whatever the preferred maximum length.
    let _preferred_maximum_length = reader.u32().ok_or(FaultStatus::NDR)?;
    let resume = match reader.u32().ok_or(FaultStatus::NDR)? {
        0 => None,
        _ => Some(reader.u32().ok_or(FaultStatus::NDR)?),
    };
    Ok(Call::ShareEnum { level, resume })
}

/// Levels with an arm in the SERVER_INFO union, which has no default arm.
fn server_info_arm(level: InfoLevel) -> bool {
    matches!(
        level.0,
        100..=103
            | 502
            | 503
            | 599
            | 1005
            | 1010
            | 1016..=1018
            | 1107
            | 1501..=1503
            | 1506
            | 1510..=1516
            | 1518
            | 1523
            | 1528..=1530
            | 1533..=1536
            | 1538..=1550
            | 1552..=1556
    )
}

/// Pointer referent identifiers in marshalling order.
struct Referents(u32);

impl Referents {
    fn next(&mut self) -> u32 {
        let referent = 0x0002_0000 + 4 * self.0;
        self.0 += 1;
        referent
    }
}

/// A share as listed to clients.
struct ShareEntry<'a> {
    name: Text<'a>,
    share_type: ShareType,
    remark: &'static [u8],
}

const IPC_ENTRY: ShareEntry<'static> = ShareEntry {
    name: Text::Ascii(IPC_SHARE),
    share_type: ShareType::IPC.union(ShareType::SPECIAL),
    remark: IPC_REMARK,
};

/// Render the response stub of `call`.
#[inline(never)]
pub(super) fn render(
    call: &Call,
    stub: &[u8],
    context: &mut PipeContext<'_>,
    writer: &mut Writer<'_>,
) {
    let mut referents = Referents(0);
    match *call {
        Call::ShareEnum { level, resume } => {
            share_enum(level, resume, context, &mut referents, writer)
        }
        Call::ShareGetInfo { level, name } => {
            share_get_info(level, name.bytes(stub), context, &mut referents, writer)
        }
        Call::ServerGetInfo { level } => server_get_info(level, context, &mut referents, writer),
    }
}

fn disk_share_count(context: &mut PipeContext<'_>) -> u32 {
    let mut name = [0; SHARE_NAME_CAPACITY];
    let mut count = 0;
    while context
        .backend
        .share_name(ShareIndex(count), context.user, &mut name)
        .is_some()
    {
        count += 1;
    }
    count
}

/// The share at `index` of the list of `disk_count` disk shares followed
/// by IPC$.
fn share_at<'a>(
    context: &mut PipeContext<'_>,
    index: u32,
    disk_count: u32,
    name: &'a mut [u16; SHARE_NAME_CAPACITY],
) -> ShareEntry<'a> {
    if index >= disk_count {
        return IPC_ENTRY;
    }
    // A share removed since the list was counted is listed with an empty
    // name, which keeps the marshalled counts consistent.
    let length = context
        .backend
        .share_name(ShareIndex(index), context.user, name)
        .map_or(0, |length| length.min(SHARE_NAME_CAPACITY));
    ShareEntry {
        name: Text::Units(&name[..length]),
        share_type: ShareType::DISKTREE,
        remark: b"",
    }
}

/// Find a share by name, compared without ASCII case.
fn find_share<'a>(
    context: &mut PipeContext<'_>,
    requested: &[u8],
    name: &'a mut [u16; SHARE_NAME_CAPACITY],
) -> Option<ShareEntry<'a>> {
    let requested = Utf16Le::new(requested)?;
    let mut index = 0;
    let mut found = None;
    while let Some(length) = context
        .backend
        .share_name(ShareIndex(index), context.user, name)
    {
        let units = &name[..length.min(SHARE_NAME_CAPACITY)];
        if requested.len() == units.len()
            && requested
                .units()
                .zip(units)
                .all(|(a, &b)| fold_ascii(a) == fold_ascii(b))
        {
            found = Some(units.len());
            break;
        }
        index += 1;
    }
    match found {
        Some(length) => Some(ShareEntry {
            name: Text::Units(&name[..length]),
            share_type: ShareType::DISKTREE,
            remark: b"",
        }),
        None if requested.eq_ignore_ascii_case(IPC_SHARE) => Some(IPC_ENTRY),
        None => None,
    }
}

fn put_resume(writer: &mut Writer<'_>, referents: &mut Referents, resume: Option<u32>) {
    match resume {
        Some(value) => {
            writer.u32(referents.next());
            writer.u32(value);
        }
        None => writer.u32(0),
    }
}

/// SHARE_ENUM_STRUCT, TotalEntries, ResumeHandle, and the status. Levels 2
/// and 502 are denied as to a user without administrative rights.
fn share_enum(
    level: InfoLevel,
    resume: Option<u32>,
    context: &mut PipeContext<'_>,
    referents: &mut Referents,
    writer: &mut Writer<'_>,
) {
    writer.u32(level.0);
    writer.u32(level.0);
    let detailed = match level.0 {
        0 => false,
        1 => true,
        _ => {
            let status = if matches!(level.0, 2 | 502) {
                NetStatus::ACCESS_DENIED
            } else {
                NetStatus::INVALID_LEVEL
            };
            writer.u32(0);
            writer.u32(0);
            put_resume(writer, referents, resume);
            writer.u32(status.0);
            return;
        }
    };
    let disk_count = disk_share_count(context);
    let total = disk_count.saturating_add(1);
    // No resume handle starts at the beginning; one past the end returns
    // no entries.
    let first = resume.unwrap_or(0).min(total);
    let count = total - first;
    writer.u32(referents.next());
    writer.u32(count);
    if count == 0 {
        writer.u32(0);
    } else {
        writer.u32(referents.next());
        writer.u32(count);
        for index in first..total {
            writer.u32(referents.next());
            if detailed {
                let share_type = if index < disk_count {
                    ShareType::DISKTREE
                } else {
                    IPC_ENTRY.share_type
                };
                writer.u32(share_type.0);
                writer.u32(referents.next());
            }
        }
        let mut name = [0; SHARE_NAME_CAPACITY];
        for index in first..total {
            let entry = share_at(context, index, disk_count, &mut name);
            writer.string(entry.name);
            if detailed {
                writer.string(Text::Ascii(entry.remark));
            }
        }
    }
    writer.u32(count);
    // All entries are returned, so the enumeration is complete.
    put_resume(writer, referents, resume.map(|_| 0));
    writer.u32(NetStatus::SUCCESS.0);
}

/// The SHARE_INFO union and the status. Levels 2 and 502 are denied as to
/// a user without administrative rights.
fn share_get_info(
    level: InfoLevel,
    requested: &[u8],
    context: &mut PipeContext<'_>,
    referents: &mut Referents,
    writer: &mut Writer<'_>,
) {
    writer.u32(level.0);
    let mut name = [0; SHARE_NAME_CAPACITY];
    let status = match level.0 {
        0 | 1 | 501 | 1005 | 2 | 502 => match find_share(context, requested, &mut name) {
            None => NetStatus::NET_NAME_NOT_FOUND,
            Some(_) if matches!(level.0, 2 | 502) => NetStatus::ACCESS_DENIED,
            Some(entry) => {
                writer.u32(referents.next());
                put_share_info(level, &entry, referents, writer);
                writer.u32(NetStatus::SUCCESS.0);
                return;
            }
        },
        _ => NetStatus::INVALID_LEVEL,
    };
    if matches!(
        level.0,
        0 | 1 | 2 | 501 | 502 | 503 | 1004 | 1005 | 1006 | 1501
    ) {
        writer.u32(0);
    }
    writer.u32(status.0);
}

/// SHARE_INFO_0, _1, _501 (flags 0), or _1005 (flags 0) with deferred
/// strings.
fn put_share_info(
    level: InfoLevel,
    entry: &ShareEntry<'_>,
    referents: &mut Referents,
    writer: &mut Writer<'_>,
) {
    if level.0 == 1005 {
        writer.u32(0);
        return;
    }
    writer.u32(referents.next());
    if level.0 == 0 {
        writer.string(entry.name);
        return;
    }
    writer.u32(entry.share_type.0);
    writer.u32(referents.next());
    if level.0 == 501 {
        writer.u32(0);
    }
    writer.string(entry.name);
    writer.string(Text::Ascii(entry.remark));
}

/// The SERVER_INFO union and the status.
fn server_get_info(
    level: InfoLevel,
    context: &mut PipeContext<'_>,
    referents: &mut Referents,
    writer: &mut Writer<'_>,
) {
    writer.u32(level.0);
    if !matches!(level.0, 100 | 101) {
        writer.u32(0);
        writer.u32(NetStatus::INVALID_LEVEL.0);
        return;
    }
    let mut name = [0; COMPUTER_NAME_CAPACITY];
    let length = context
        .backend
        .computer_name(&mut name)
        .min(COMPUTER_NAME_CAPACITY);
    let name = Text::Ascii(&name[..length]);
    writer.u32(referents.next());
    writer.u32(PlatformId::NT.0);
    writer.u32(referents.next());
    if level.0 == 100 {
        writer.string(name);
    } else {
        writer.u32(OsVersion::WINDOWS_7.major);
        writer.u32(OsVersion::WINDOWS_7.minor);
        writer.u32(SERVER_TYPE.0);
        writer.u32(referents.next());
        writer.string(name);
        writer.string(Text::Ascii(b""));
    }
    writer.u32(NetStatus::SUCCESS.0);
}
