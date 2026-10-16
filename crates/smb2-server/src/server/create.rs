//! CREATE (MS-SMB2 3.3.5.9) and CLOSE (3.3.5.10).

use crate::backend::Backend;
use crate::backend::OPEN_OPTIONS;
use crate::backend::OpenRequest;
use crate::fs::AccessMask;
use crate::fs::CreateAction;
use crate::fs::CreateDisposition;
use crate::fs::CreateOptions;
use crate::fs::FileAttributes;
use crate::fs::FileInformation;
use crate::fs::ShareAccess;
use crate::path::SharePath;
use crate::server::Body;
use crate::server::Connection;
use crate::server::Exchange;
use crate::server::Failure;
use crate::server::Handled;
use crate::server::MAX_OPENS;
use crate::server::RequestError;
use crate::server::Server;
use crate::server::record_change;
use crate::server::shared::ChangeAction;
use crate::server::shared::ChangeFilter;
use crate::server::tables::FileOpen;
use crate::server::tables::Open;
use crate::server::tables::OpenKind;
use crate::server::tables::OpenSlot;
use crate::server::tables::PipeIndex;
use crate::server::tables::TreeKind;
use crate::server::wire;
use crate::server::wire::FileId;
use crate::server::wire::HEADER_SIZE;
use crate::utf16::Utf16Le;

/// Fixed part of the request body.
const REQUEST_FIXED: usize = 56;
/// Fixed part of the reply body; create contexts follow.
const REPLY_FIXED: usize = 88;
const CLOSE_REPLY: usize = 60;

/// Flags of a CLOSE request and reply (MS-SMB2 2.2.15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CloseFlags(u16);

impl CloseFlags {
    const POSTQUERY_ATTRIB: Self = Self(0x1);

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// An impersonation level (MS-SMB2 2.2.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ImpersonationLevel(u32);

impl ImpersonationLevel {
    /// The highest level.
    const DELEGATE: Self = Self(3);
}

/// Access mask bits that are reserved in a request.
const RESERVED_ACCESS: AccessMask = AccessMask(0x0ce0_fe00);
/// FILE_RESERVE_OPFILTER.
const RESERVE_OPFILTER: CreateOptions = CreateOptions(0x0010_0000);
/// Create options a server rejects as unsupported.
const UNSUPPORTED_OPTIONS: CreateOptions = CreateOptions::OPEN_BY_FILE_ID.union(RESERVE_OPFILTER);
/// Create options kept for FileModeInformation.
const MODE_OPTIONS: CreateOptions = CreateOptions(
    CreateOptions::WRITE_THROUGH.0
        | CreateOptions::SEQUENTIAL_ONLY.0
        | CreateOptions::NO_INTERMEDIATE_BUFFERING.0
        | CreateOptions::SYNCHRONOUS_IO_ALERT.0
        | CreateOptions::SYNCHRONOUS_IO_NONALERT.0
        | CreateOptions::DELETE_ON_CLOSE.0,
);
/// Generic rights and the file rights they map to (MS-SMB2 2.2.13.1.1).
const GENERIC_READ_MAPPING: AccessMask = AccessMask(0x0012_0089);
const GENERIC_WRITE_MAPPING: AccessMask = AccessMask(0x0012_0116);
const GENERIC_EXECUTE_MAPPING: AccessMask = AccessMask(0x0012_00a0);

/// The name of a create context (MS-SMB2 2.2.13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContextName([u8; 4]);

impl ContextName {
    const MAXIMAL_ACCESS: Self = Self(*b"MxAc");
    const QUERY_FILE_ID: Self = Self(*b"QFid");
    const ALLOCATION_SIZE: Self = Self(*b"AlSi");
    const EXTENDED_ATTRIBUTES: Self = Self(*b"ExtA");
    const TIMEWARP: Self = Self(*b"TWrp");
}

/// Create contexts the server recognizes.
#[derive(Debug, Clone, Copy, Default)]
struct Contexts {
    maximal_access: bool,
    query_file_id: bool,
    allocation_size: Option<u64>,
}

impl Connection {
    pub(super) fn create(
        &mut self,
        exchange: &Exchange<'_>,
        server: &mut Server,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Result<(Body, FileId), Failure> {
        let body = exchange.fixed_body(57, REQUEST_FIXED)?;
        if ImpersonationLevel(wire::u32_at(body, 4)) > ImpersonationLevel::DELEGATE {
            return Err(Failure::Error(RequestError::BadImpersonationLevel));
        }
        let requested = AccessMask(wire::u32_at(body, 24));
        if requested.intersects(RESERVED_ACCESS) {
            return Err(Failure::Error(RequestError::AccessDenied));
        }
        let attributes = FileAttributes(wire::u32_at(body, 28));
        let share_access = ShareAccess(wire::u32_at(body, 32) & ShareAccess::ALL.0);
        let disposition = CreateDisposition::from_wire(wire::u32_at(body, 36))
            .ok_or(RequestError::InvalidRequest)?;
        let options = CreateOptions(wire::u32_at(body, 40));
        if options.contains(CreateOptions::DIRECTORY_FILE.union(CreateOptions::NON_DIRECTORY_FILE))
        {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }
        if options.0 & UNSUPPORTED_OPTIONS.0 != 0 {
            return Err(Failure::Error(RequestError::Unsupported));
        }
        let name = wire::buffer(
            exchange.message,
            REQUEST_FIXED,
            usize::from(wire::u16_at(body, 44)),
            usize::from(wire::u16_at(body, 46)),
        )
        .and_then(Utf16Le::new)
        .ok_or(RequestError::InvalidRequest)?;
        let contexts = wire::buffer(
            exchange.message,
            REQUEST_FIXED,
            wire::u32_at(body, 48) as usize,
            wire::u32_at(body, 52) as usize,
        )
        .ok_or(RequestError::InvalidRequest)?;
        let contexts = parse_contexts(contexts)?;

        let slot = self
            .opens
            .iter()
            .position(Option::is_none)
            .map(|index| OpenSlot(index as u8))
            .ok_or(RequestError::TableFull)?;
        let session = exchange.session.ok_or(RequestError::SessionNotFound)?;
        let tree_slot = exchange.tree.ok_or(RequestError::TreeNotFound)?;
        let id = self.new_file_id();
        let (kind, granted, action, information) = match self.tree(tree_slot).kind {
            TreeKind::Pipe => {
                let pipe = self.open_pipe(slot, name)?;
                (
                    OpenKind::Pipe(pipe),
                    map_generic(requested),
                    CreateAction::Opened,
                    FileInformation {
                        attributes: FileAttributes::NORMAL,
                        ..FileInformation::default()
                    },
                )
            }
            TreeKind::Disk { share, writable } => {
                let path = SharePath::parse(name)?;
                let maximum = share_maximum(writable);
                let mut access = map_generic(requested);
                let mut disposition = disposition;
                if !writable {
                    if access.intersects(AccessMask::MODIFY) {
                        return Err(Failure::Error(RequestError::AccessDenied));
                    }
                    disposition = match disposition {
                        CreateDisposition::Open | CreateDisposition::OpenIf => {
                            CreateDisposition::Open
                        }
                        _ => return Err(Failure::Error(RequestError::AccessDenied)),
                    };
                }
                let granted = if access.contains(AccessMask::MAXIMUM_ALLOWED) {
                    maximum
                } else {
                    AccessMask(access.0 & maximum.0)
                };
                if options.contains(CreateOptions::DELETE_ON_CLOSE)
                    && !granted.contains(AccessMask::DELETE)
                {
                    return Err(Failure::Error(RequestError::AccessDenied));
                }
                if access.contains(AccessMask::MAXIMUM_ALLOWED) && !writable {
                    access = AccessMask((access.0 & !AccessMask::MAXIMUM_ALLOWED.0) | maximum.0);
                }
                let request = OpenRequest {
                    access,
                    share_access,
                    disposition,
                    options: CreateOptions(options.0 & OPEN_OPTIONS.0),
                    attributes,
                    allocation_size: contexts.allocation_size,
                };
                let opened = backend.open(share, path, &request)?;
                let file = match server.files.acquire(share, path) {
                    Ok(file) => file,
                    Err(error) => {
                        backend.close(opened.handle);
                        return Err(error.into());
                    }
                };
                let directory = opened.information.attributes.is_directory();
                if options.contains(CreateOptions::DELETE_ON_CLOSE) {
                    server.files.set_delete_pending(file, true);
                }
                match opened.action {
                    CreateAction::Created => record_change(
                        server,
                        file,
                        ChangeAction::Added,
                        ChangeFilter::name(directory),
                    ),
                    CreateAction::Overwritten | CreateAction::Superseded => record_change(
                        server,
                        file,
                        ChangeAction::Modified,
                        ChangeFilter::SIZE.union(ChangeFilter::LAST_WRITE),
                    ),
                    CreateAction::Opened => {}
                }
                (
                    OpenKind::File(FileOpen {
                        handle: opened.handle,
                        directory,
                        search: None,
                        position: 0,
                        mode: CreateOptions(options.0 & MODE_OPTIONS.0),
                        delete_pending: false,
                        file,
                        write_recorded: false,
                        notify: None,
                    }),
                    granted,
                    opened.action,
                    opened.information,
                )
            }
        };
        self.opens[usize::from(slot.0)] = Some(Open {
            id,
            session,
            tree: tree_slot,
            access: granted,
            kind,
        });

        output[..REPLY_FIXED].fill(0);
        wire::put_u16(output, 0, 89);
        wire::put_u32(output, 4, action as u32);
        write_times(output, 8, &information);
        wire::put_u32(output, 56, information.attributes.0);
        id.write(output, 64);
        let length = match self.append_contexts(slot, contexts, &information, backend, output) {
            Ok(length) => length,
            Err(failure) => {
                self.close_open(slot, server, backend);
                return Err(failure);
            }
        };
        Ok((Body::success(length), id))
    }

    /// Append the create context replies the request asked for; returns
    /// the reply length.
    fn append_contexts(
        &self,
        slot: OpenSlot,
        contexts: Contexts,
        information: &FileInformation,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Result<usize, Failure> {
        let open = self.open(slot);
        let mut length = REPLY_FIXED;
        let mut previous: Option<usize> = None;
        if contexts.maximal_access {
            let mut data = [0; 8];
            wire::put_u32(&mut data, 4, share_maximum_of(self, open.tree).0);
            length = append_context(
                output,
                length,
                &mut previous,
                ContextName::MAXIMAL_ACCESS,
                &data,
            )?;
        }
        if contexts.query_file_id
            && let (OpenKind::File(file), Some(index)) = (open.kind, information.index)
            && let Ok(volume) = backend.volume_information(file.handle)
        {
            // DiskFileId, VolumeId, and reserved bytes (MS-SMB2 2.2.14.2.9).
            let mut data = [0; 32];
            wire::put_u64(&mut data, 0, index.0);
            wire::put_u64(&mut data, 8, u64::from(volume.serial_number));
            length = append_context(
                output,
                length,
                &mut previous,
                ContextName::QUERY_FILE_ID,
                &data,
            )?;
        }
        if length > REPLY_FIXED {
            wire::put_u32(output, 80, (HEADER_SIZE + REPLY_FIXED) as u32);
            wire::put_u32(output, 84, (length - REPLY_FIXED) as u32);
        }
        Ok(length)
    }

    pub(super) fn close_request(
        &mut self,
        exchange: &Exchange<'_>,
        server: &mut Server,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        let body = exchange.fixed_body(24, 24)?;
        let flags = CloseFlags(wire::u16_at(body, 2));
        let slot = self.find_open(exchange, FileId::read(body, 8))?;
        let information = match self.open(slot).kind {
            OpenKind::File(file) if flags.contains(CloseFlags::POSTQUERY_ATTRIB) => {
                backend.information(file.handle).ok()
            }
            _ => None,
        };
        self.close_open(slot, server, backend);
        output[..CLOSE_REPLY].fill(0);
        wire::put_u16(output, 0, CLOSE_REPLY as u16);
        if let Some(information) = information {
            wire::put_u16(output, 2, CloseFlags::POSTQUERY_ATTRIB.0);
            write_times(output, 8, &information);
            wire::put_u32(output, 56, information.attributes.0);
        }
        Ok(Body::success(CLOSE_REPLY))
    }

    /// Open the named pipe `name` for the open in `slot`; returns the pipe
    /// slot.
    fn open_pipe(&mut self, slot: OpenSlot, name: Utf16Le<'_>) -> Result<PipeIndex, Failure> {
        if !crate::rpc::pipe_supported(name) {
            return Err(Failure::Error(RequestError::NameNotFound));
        }
        let index = self
            .pipes
            .iter()
            .position(|pipe| pipe.owner.is_none())
            .ok_or(RequestError::TableFull)?;
        self.pipes[index] = crate::server::tables::PipeSlot::new();
        self.pipes[index].owner = Some(slot);
        Ok(PipeIndex(index as u8))
    }

    fn new_file_id(&mut self) -> FileId {
        let id = self.next_file_id;
        self.next_file_id = id.next();
        id
    }
}

/// Times and sizes in the layout shared by CREATE and CLOSE replies:
/// four times, allocation size, end of file.
fn write_times(output: &mut [u8], offset: usize, information: &FileInformation) {
    wire::put_u64(output, offset, information.creation_time.0);
    wire::put_u64(output, offset + 8, information.last_access_time.0);
    wire::put_u64(output, offset + 16, information.last_write_time.0);
    wire::put_u64(output, offset + 24, information.change_time.0);
    wire::put_u64(output, offset + 32, information.allocation_size);
    wire::put_u64(output, offset + 40, information.end_of_file);
}

/// Replace generic rights with the file rights they stand for.
pub(super) fn map_generic(access: AccessMask) -> AccessMask {
    let mut mapped = access.0 & 0x0fff_ffff;
    if access.contains(AccessMask::GENERIC_READ) {
        mapped |= GENERIC_READ_MAPPING.0;
    }
    if access.contains(AccessMask::GENERIC_WRITE) {
        mapped |= GENERIC_WRITE_MAPPING.0;
    }
    if access.contains(AccessMask::GENERIC_EXECUTE) {
        mapped |= GENERIC_EXECUTE_MAPPING.0;
    }
    if access.contains(AccessMask::GENERIC_ALL) {
        mapped |= AccessMask::FILE_ALL_ACCESS.0;
    }
    AccessMask(mapped)
}

/// Rights a user holds on every file of a share.
pub(super) const fn share_maximum(writable: bool) -> AccessMask {
    if writable {
        AccessMask::FILE_ALL_ACCESS
    } else {
        AccessMask(0x0012_00a9)
    }
}

fn share_maximum_of(connection: &Connection, tree: crate::server::tables::TreeSlot) -> AccessMask {
    match connection.tree(tree).kind {
        TreeKind::Disk { writable, .. } => share_maximum(writable),
        TreeKind::Pipe => AccessMask::FILE_ALL_ACCESS,
    }
}

/// Recognize the create contexts of a request (MS-SMB2 2.2.13.2).
fn parse_contexts(mut contexts: &[u8]) -> Result<Contexts, Failure> {
    let mut found = Contexts::default();
    while !contexts.is_empty() {
        if contexts.len() < 16 {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }
        let next = wire::u32_at(contexts, 0) as usize;
        let name_offset = usize::from(wire::u16_at(contexts, 4));
        let name_length = usize::from(wire::u16_at(contexts, 6));
        let data_offset = usize::from(wire::u16_at(contexts, 10));
        let data_length = wire::u32_at(contexts, 12) as usize;
        let length = if next == 0 { contexts.len() } else { next };
        if length > contexts.len() || (next != 0 && !next.is_multiple_of(8)) {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }
        let context = &contexts[..length];
        let name = context
            .get(name_offset..name_offset + name_length)
            .ok_or(RequestError::InvalidRequest)?;
        let name = <[u8; 4]>::try_from(name).map(ContextName);
        let data = if data_length == 0 {
            &[][..]
        } else {
            context
                .get(data_offset..data_offset.saturating_add(data_length))
                .ok_or(RequestError::InvalidRequest)?
        };
        match name {
            Ok(ContextName::MAXIMAL_ACCESS) => found.maximal_access = true,
            Ok(ContextName::QUERY_FILE_ID) => found.query_file_id = true,
            Ok(ContextName::ALLOCATION_SIZE) => {
                if data.len() != 8 {
                    return Err(Failure::Error(RequestError::InvalidRequest));
                }
                found.allocation_size = Some(wire::u64_at(data, 0));
            }
            Ok(ContextName::EXTENDED_ATTRIBUTES) => {
                return Err(Failure::Error(RequestError::ExtendedAttributes));
            }
            // No previous versions of any file exist.
            Ok(ContextName::TIMEWARP) => return Err(Failure::Error(RequestError::NameNotFound)),
            // Durable handles, leases, security descriptors and other
            // contexts are not granted; the reply omits them.
            _ => {}
        }
        if next == 0 {
            break;
        }
        contexts = &contexts[next..];
    }
    Ok(found)
}

/// Append a create context reply at `length`; returns the new length.
fn append_context(
    output: &mut [u8],
    length: usize,
    previous: &mut Option<usize>,
    name: ContextName,
    data: &[u8],
) -> Result<usize, Failure> {
    let start = wire::align8(length);
    let end = start + 24 + data.len();
    if end > output.len() {
        return Err(Failure::Error(RequestError::ReplyOverflow));
    }
    output[length..end].fill(0);
    if let Some(previous) = *previous {
        wire::put_u32(output, previous, (start - previous) as u32);
    }
    wire::put_u16(output, start + 4, 16);
    wire::put_u16(output, start + 6, 4);
    wire::put_u16(output, start + 10, 24);
    wire::put_u32(output, start + 12, data.len() as u32);
    output[start + 16..start + 20].copy_from_slice(&name.0);
    output[start + 24..end].copy_from_slice(data);
    *previous = Some(start);
    Ok(end)
}

const _: () = assert!(MAX_OPENS <= u8::MAX as usize);
