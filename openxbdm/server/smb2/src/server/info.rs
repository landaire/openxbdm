//! QUERY_INFO (MS-SMB2 3.3.5.20) and SET_INFO (3.3.5.21) with the file,
//! file system, and security information classes (MS-FSCC 2.4, 2.5;
//! MS-DTYP 2.4.6).

mod query;
mod security;

use self::query::FsClass;
use self::query::query_file;
use self::query::query_pipe;
use self::query::query_volume;
use self::security::SecurityInformation;
use self::security::security_descriptor;
use crate::backend::Backend;
use crate::fs::AccessMask;
use crate::fs::BasicInformation;
use crate::fs::CreateOptions;
use crate::fs::FileAttributes;
use crate::fs::FileTime;
use crate::path::SharePath;
use crate::pattern::fold;
use crate::server::Connection;
use crate::server::Server;
use crate::server::error::RequestError;
use crate::server::request::Body;
use crate::server::request::Completion;
use crate::server::request::Exchange;
use crate::server::request::Failure;
use crate::server::request::Handled;
use crate::server::shared::ChangeAction;
use crate::server::shared::ChangeFilter;
use crate::server::shared::record_change;
use crate::server::shared::split_parent;
use crate::server::tables::FileOpen;
use crate::server::tables::Open;
use crate::server::tables::OpenKind;
use crate::server::tables::OpenSlot;
use crate::server::tables::TreeKind;
use crate::server::wire;
use crate::server::wire::FileId;
use crate::server::wire::HEADER_SIZE;
use crate::utf16::Utf16Le;

/// FileAllInformation before its name; the name length is its last field.
const ALL_FIXED: usize = 100;
/// FILE_NAME_INFORMATION before its name.
const NAME_FIXED: usize = 4;
/// Largest fixed or variable reply this module builds.
const SCRATCH: usize = 128;

/// InfoType of QUERY_INFO and SET_INFO (MS-SMB2 2.2.37).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InfoType {
    File,
    FileSystem,
    Security,
    Quota,
}

impl InfoType {
    const fn from_wire(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::File,
            2 => Self::FileSystem,
            3 => Self::Security,
            4 => Self::Quota,
            _ => return None,
        })
    }
}

/// A file information class (MS-FSCC 2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileClass(u8);

impl FileClass {
    const BASIC: Self = Self(4);
    const STANDARD: Self = Self(5);
    const INTERNAL: Self = Self(6);
    const EA: Self = Self(7);
    const ACCESS: Self = Self(8);
    const RENAME: Self = Self(10);
    const DISPOSITION: Self = Self(13);
    const POSITION: Self = Self(14);
    const FULL_EA: Self = Self(15);
    const MODE: Self = Self(16);
    const ALIGNMENT: Self = Self(17);
    const ALL: Self = Self(18);
    const ALLOCATION: Self = Self(19);
    const END_OF_FILE: Self = Self(20);
    const ALTERNATE_NAME: Self = Self(21);
    const STREAM: Self = Self(22);
    const PIPE: Self = Self(23);
    const PIPE_LOCAL: Self = Self(24);
    const COMPRESSION: Self = Self(28);
    const NETWORK_OPEN: Self = Self(34);
    const ATTRIBUTE_TAG: Self = Self(35);
    const NORMALIZED_NAME: Self = Self(48);
}

/// An information reply built in scratch memory.
struct Built {
    length: usize,
    /// Bytes a reply must hold at least; a shorter output buffer fails.
    minimum: usize,
    /// Bytes that carry information; a reply cut shorter overflows.
    complete: usize,
}

impl Built {
    const fn fixed(length: usize) -> Self {
        Self::variable(length, length)
    }

    const fn variable(length: usize, minimum: usize) -> Self {
        Self {
            length,
            minimum,
            complete: length,
        }
    }
}

/// A name written after the fixed part of an information structure.
struct NameField<'a> {
    path: &'a [u16],
    /// The name starts with a separator.
    separator: bool,
    /// Offset of the name; its length is the four bytes before.
    offset: usize,
}

impl Connection {
    pub(super) fn query_info(
        &mut self,
        exchange: &Exchange<'_>,
        server: &mut Server,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        const QUERY_FIXED: usize = 40;
        const REPLY_FIXED: usize = 8;

        let body = exchange.fixed_body(41, QUERY_FIXED)?;
        let info_type = InfoType::from_wire(wire::u8_at(body, 2));
        let class = wire::u8_at(body, 3);
        let limit = (wire::u32_at(body, 4) as usize)
            .min(exchange.config.max_io())
            .min(output.len().saturating_sub(REPLY_FIXED));
        let additional = SecurityInformation(wire::u32_at(body, 16));
        let slot = self.find_open(exchange, FileId::read(body, 24))?;
        let open = *self.open(slot);

        let mut scratch = [0u8; SCRATCH];
        let built = match (info_type, open.kind) {
            (Some(InfoType::File), OpenKind::File(file)) => {
                let information = backend.information(file.handle)?;
                query_file(
                    FileClass(class),
                    self.dialect(),
                    &open,
                    &file,
                    &information,
                    &mut scratch,
                )?
            }
            (Some(InfoType::File), OpenKind::Pipe(_)) => {
                query_pipe(FileClass(class), &mut scratch)?
            }
            (Some(InfoType::FileSystem), OpenKind::File(file)) => {
                let volume = backend.volume_information(file.handle)?;
                query_volume(FsClass(class), &volume, &mut scratch)?
            }
            (Some(InfoType::Security), OpenKind::File(file)) => {
                let writable = match self.tree(open.tree).kind {
                    TreeKind::Disk { writable, .. } => writable,
                    TreeKind::Pipe => false,
                };
                let built =
                    security_descriptor(additional, writable, file.directory, &mut scratch)?;
                if limit < built.length {
                    return Err(Failure::TooSmall {
                        required: built.length as u32,
                    });
                }

                built
            }
            (Some(InfoType::Quota), _) => return Err(Failure::Error(RequestError::Unsupported)),
            (Some(InfoType::FileSystem | InfoType::Security), OpenKind::Pipe(_)) => {
                return Err(Failure::Error(RequestError::WrongFileKind));
            }
            _ => return Err(Failure::Error(RequestError::InvalidRequest)),
        };

        // FileAllInformation ends with the name of the file from the share
        // root after a separator; FileNormalizedNameInformation is that
        // name without the separator.
        let name = match open.kind {
            OpenKind::File(file)
                if info_type == Some(InfoType::File) && FileClass(class) == FileClass::ALL =>
            {
                Some(NameField {
                    path: server.files.path(file.file),
                    separator: true,
                    offset: ALL_FIXED,
                })
            }
            OpenKind::File(file)
                if info_type == Some(InfoType::File)
                    && FileClass(class) == FileClass::NORMALIZED_NAME =>
            {
                Some(NameField {
                    path: server.files.path(file.file),
                    separator: false,
                    offset: NAME_FIXED,
                })
            }
            _ => None,
        };
        let built = match &name {
            Some(field) => {
                let length = (usize::from(field.separator) + field.path.len()) * 2;
                wire::put_u32(&mut scratch, field.offset - 4, length as u32);
                Built::variable(field.offset + length, field.offset)
            }
            None => built,
        };
        if limit < built.minimum {
            return Err(Failure::Error(RequestError::InformationLengthMismatch));
        }

        let count = built.length.min(limit);
        let fixed = count.min(SCRATCH);
        output[REPLY_FIXED..REPLY_FIXED + fixed].copy_from_slice(&scratch[..fixed]);
        if let Some(field) = name {
            let separator = field.separator.then_some(u16::from(b'\\'));
            let units = separator.into_iter().chain(field.path.iter().copied());
            let room = &mut output[REPLY_FIXED + field.offset..REPLY_FIXED + count];
            for (pair, unit) in room.chunks_mut(2).zip(units) {
                let bytes = unit.to_le_bytes();
                pair.copy_from_slice(&bytes[..pair.len()]);
            }
        }

        output[..REPLY_FIXED].fill(0);
        wire::put_u16(output, 0, 9);
        wire::put_u16(output, 2, (HEADER_SIZE + REPLY_FIXED) as u16);
        wire::put_u32(output, 4, count as u32);

        Ok(Body {
            completion: if count < built.complete {
                Completion::BufferOverflow
            } else {
                Completion::Success
            },
            length: REPLY_FIXED + count,
        })
    }

    pub(super) fn set_info(
        &mut self,
        exchange: &Exchange<'_>,
        server: &mut Server,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        const SET_FIXED: usize = 32;

        let body = exchange.fixed_body(33, SET_FIXED)?;
        let info_type = InfoType::from_wire(wire::u8_at(body, 2));
        let class = FileClass(wire::u8_at(body, 3));
        let data = wire::buffer(
            exchange.message,
            SET_FIXED,
            usize::from(wire::u16_at(body, 8)),
            wire::u32_at(body, 4) as usize,
        )
        .ok_or(RequestError::InvalidRequest)?;
        let slot = self.find_open(exchange, FileId::read(body, 16))?;
        let open = *self.open(slot);

        match (info_type, open.kind) {
            (Some(InfoType::File), OpenKind::File(file)) => {
                self.set_file(slot, &open, file, class, data, server, backend)?
            }
            (Some(InfoType::File), OpenKind::Pipe(_)) if class == FileClass::PIPE => {
                if data.len() < 8 {
                    return Err(Failure::Error(RequestError::InformationLengthMismatch));
                }
            }
            (Some(InfoType::File), OpenKind::Pipe(_)) => {
                return Err(Failure::Error(RequestError::InvalidRequest));
            }
            (Some(InfoType::FileSystem | InfoType::Security | InfoType::Quota), _) => {
                return Err(Failure::Error(RequestError::Unsupported));
            }
            _ => return Err(Failure::Error(RequestError::InvalidRequest)),
        }

        wire::put_u16(output, 0, 2);

        Ok(Body::success(2))
    }

    #[allow(clippy::too_many_arguments)]
    fn set_file(
        &mut self,
        slot: OpenSlot,
        open: &Open,
        file: FileOpen,
        class: FileClass,
        data: &[u8],
        server: &mut Server,
        backend: &mut dyn Backend,
    ) -> Result<(), Failure> {
        // Mode bits FileModeInformation may set.
        const SETTABLE_MODE: CreateOptions = CreateOptions(0x0000_003e);

        let required = match class {
            FileClass::BASIC => 40,
            FileClass::RENAME => 20,
            FileClass::DISPOSITION => 1,
            FileClass::POSITION | FileClass::ALLOCATION | FileClass::END_OF_FILE => 8,
            FileClass::MODE => 4,
            FileClass::FULL_EA => return Err(Failure::Error(RequestError::ExtendedAttributes)),
            _ => return Err(Failure::Error(RequestError::UnknownInformationClass)),
        };
        if data.len() < required {
            return Err(Failure::Error(RequestError::InformationLengthMismatch));
        }

        let demand = |rights: AccessMask| -> Result<(), Failure> {
            if open.access.intersects(rights) {
                Ok(())
            } else {
                Err(Failure::Error(RequestError::AccessDenied))
            }
        };

        match class {
            FileClass::BASIC => {
                demand(AccessMask::WRITE_ATTRIBUTES)?;
                let information = BasicInformation {
                    creation_time: settable_time(wire::u64_at(data, 0)),
                    last_access_time: settable_time(wire::u64_at(data, 8)),
                    last_write_time: settable_time(wire::u64_at(data, 16)),
                    change_time: settable_time(wire::u64_at(data, 24)),
                    attributes: match wire::u32_at(data, 32) {
                        0 => None,
                        attributes => Some(FileAttributes(attributes)),
                    },
                };
                backend.set_basic_information(file.handle, &information)?;
                record_change(
                    server,
                    file.file,
                    ChangeAction::Modified,
                    ChangeFilter::ATTRIBUTES
                        .union(ChangeFilter::LAST_WRITE)
                        .union(ChangeFilter::LAST_ACCESS)
                        .union(ChangeFilter::CREATION),
                );
            }
            FileClass::RENAME => {
                demand(AccessMask::DELETE)?;
                let replace = wire::u8_at(data, 0) != 0;
                if wire::u64_at(data, 8) != 0 {
                    return Err(Failure::Error(RequestError::InvalidRequest));
                }

                let length = wire::u32_at(data, 16) as usize;
                let name = data
                    .get(
                        20..20usize
                            .checked_add(length)
                            .ok_or(RequestError::InvalidRequest)?,
                    )
                    .and_then(Utf16Le::new)
                    .ok_or(RequestError::InvalidRequest)?;
                // The target is relative to the share root with or without a
                // leading separator.
                let name = if name.unit(0) == Some(u16::from(b'\\')) {
                    name.slice(1, name.len())
                } else {
                    name
                };
                let target = SharePath::parse(name)?;
                if target.is_root() {
                    return Err(Failure::Error(RequestError::NameInvalid));
                }

                // The file table takes the new name after the backend
                // renames; its room is checked first so that cannot fail.
                server.files.check_rename(target)?;
                backend.rename(file.handle, target, replace)?;

                let name_filter = ChangeFilter::name(file.directory);
                let same_directory = {
                    let (old_parent, _) = split_parent(server.files.path(file.file));
                    let new_parent = target.parent().map(|parent| parent.as_utf16());
                    new_parent.is_some_and(|parent| {
                        parent.len() == old_parent.len()
                            && parent
                                .units()
                                .zip(old_parent)
                                .all(|(new, &old)| fold(new) == fold(old))
                    })
                };
                let (old_action, new_action) = if same_directory {
                    (ChangeAction::RenamedOldName, ChangeAction::RenamedNewName)
                } else {
                    (ChangeAction::Removed, ChangeAction::Added)
                };
                record_change(server, file.file, old_action, name_filter);
                server.files.rename(file.file, target);
                record_change(server, file.file, new_action, name_filter);
            }
            FileClass::DISPOSITION => {
                demand(AccessMask::DELETE)?;
                let delete = wire::u8_at(data, 0) != 0;
                backend.set_delete_pending(file.handle, delete)?;
                server.files.set_delete_pending(file.file, delete);
                if let OpenKind::File(file) = &mut self.open_mut(slot).kind {
                    file.delete_pending = delete;
                }
            }
            FileClass::POSITION => {
                if let OpenKind::File(file) = &mut self.open_mut(slot).kind {
                    file.position = wire::u64_at(data, 0);
                }
            }
            FileClass::MODE => {
                let mode = CreateOptions(wire::u32_at(data, 0));
                if mode.without(SETTABLE_MODE) != CreateOptions(0) {
                    return Err(Failure::Error(RequestError::InvalidRequest));
                }

                if let OpenKind::File(file) = &mut self.open_mut(slot).kind {
                    file.mode = mode.union(file.mode.without(SETTABLE_MODE));
                }
            }
            FileClass::ALLOCATION => {
                demand(AccessMask::WRITE_DATA)?;
                // Space is allocated as data is written; a smaller
                // allocation truncates the file.
                let allocation = wire::u64_at(data, 0);
                if allocation < backend.information(file.handle)?.end_of_file {
                    backend.set_end_of_file(file.handle, allocation)?;
                    record_change(
                        server,
                        file.file,
                        ChangeAction::Modified,
                        ChangeFilter::SIZE,
                    );
                }
            }
            FileClass::END_OF_FILE => {
                demand(AccessMask::WRITE_DATA)?;
                backend.set_end_of_file(file.handle, wire::u64_at(data, 0))?;
                record_change(
                    server,
                    file.file,
                    ChangeAction::Modified,
                    ChangeFilter::SIZE,
                );
            }
            _ => return Err(Failure::Error(RequestError::UnknownInformationClass)),
        }

        Ok(())
    }
}

/// A time of FileBasicInformation: 0 leaves the time unchanged, and so do
/// -1 and -2, which control automatic updates the backend does not offer.
fn settable_time(value: u64) -> Option<FileTime> {
    match value as i64 {
        -2..=0 => None,
        _ => Some(FileTime(value)),
    }
}
