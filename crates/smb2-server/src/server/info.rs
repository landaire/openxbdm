//! QUERY_INFO (MS-SMB2 3.3.5.20) and SET_INFO (3.3.5.21) with the file,
//! file system, and security information classes (MS-FSCC 2.4, 2.5;
//! MS-DTYP 2.4.6).

use crate::backend::Backend;
use crate::fs::AccessMask;
use crate::fs::BasicInformation;
use crate::fs::CreateOptions;
use crate::fs::FileAttributes;
use crate::fs::FileInformation;
use crate::fs::FileTime;
use crate::fs::VolumeInformation;
use crate::path::SharePath;
use crate::server::Body;
use crate::server::Completion;
use crate::server::Connection;
use crate::server::Exchange;
use crate::server::Failure;
use crate::server::Handled;
use crate::server::RequestError;
use crate::server::Server;
use crate::server::create::share_maximum;
use crate::server::record_change;
use crate::server::shared::ChangeAction;
use crate::server::shared::ChangeFilter;
use crate::server::split_parent;
use crate::server::tables::FileOpen;
use crate::server::tables::Open;
use crate::server::tables::OpenKind;
use crate::server::tables::OpenSlot;
use crate::server::tables::TreeKind;
use crate::server::wire;
use crate::server::wire::Dialect;
use crate::server::wire::FileId;
use crate::server::wire::HEADER_SIZE;
use crate::utf16::Utf16Le;

const QUERY_FIXED: usize = 40;
const SET_FIXED: usize = 32;
const REPLY_FIXED: usize = 8;
/// FileAllInformation before its name; the name length is its last field.
const ALL_FIXED: usize = 100;
/// FILE_NAME_INFORMATION before its name.
const NAME_FIXED: usize = 4;

/// A name written after the fixed part of an information structure.
struct NameField<'a> {
    path: &'a [u16],
    /// The name starts with a separator.
    separator: bool,
    /// Offset of the name; its length is the four bytes before.
    offset: usize,
}

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

/// A file system information class (MS-FSCC 2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FsClass(u8);

impl FsClass {
    const VOLUME: Self = Self(1);
    const SIZE: Self = Self(3);
    const DEVICE: Self = Self(4);
    const ATTRIBUTE: Self = Self(5);
    const FULL_SIZE: Self = Self(7);
    const SECTOR_SIZE: Self = Self(11);
}

/// DeviceType of FileFsDeviceInformation (MS-FSCC 2.5.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeviceType(u32);

impl DeviceType {
    const DISK: Self = Self(0x7);
}

/// Characteristics of FileFsDeviceInformation (MS-FSCC 2.5.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeviceCharacteristics(u32);

impl DeviceCharacteristics {
    const IS_MOUNTED: Self = Self(0x20);
}

/// Flags of FileFsSectorSizeInformation (MS-FSCC 2.5.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SectorSizeFlags(u32);

impl SectorSizeFlags {
    const ALIGNED_DEVICE: Self = Self(0x1);
    const PARTITION_ALIGNED_ON_DEVICE: Self = Self(0x2);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Parts of a security descriptor a query asks for (MS-DTYP 2.4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecurityInformation(u32);

impl SecurityInformation {
    const OWNER: Self = Self(0x1);
    const GROUP: Self = Self(0x2);
    const DACL: Self = Self(0x4);
    const SACL: Self = Self(0x8);

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Control bits of a security descriptor (MS-DTYP 2.4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecurityControl(u16);

impl SecurityControl {
    const DACL_PRESENT: Self = Self(0x0004);
    const SELF_RELATIVE: Self = Self(0x8000);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// S-1-1-0, Everyone.
const EVERYONE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];

/// AceType of an ACE header (MS-DTYP 2.4.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AceType(u8);

impl AceType {
    const ACCESS_ALLOWED: Self = Self(0);
}

/// AceFlags of an ACE header (MS-DTYP 2.4.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AceFlags(u8);

impl AceFlags {
    const NONE: Self = Self(0);
    const OBJECT_INHERIT: Self = Self(0x1);
    const CONTAINER_INHERIT: Self = Self(0x2);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// The default data stream name, `::$DATA`.
const DATA_STREAM: [u16; 7] = [0x3a, 0x3a, 0x24, 0x44, 0x41, 0x54, 0x41];

/// Mode bits FileModeInformation may set.
const SETTABLE_MODE: CreateOptions = CreateOptions(0x0000_003e);

/// Largest fixed or variable reply this module builds.
const SCRATCH: usize = 128;

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

impl Connection {
    pub(super) fn query_info(
        &mut self,
        exchange: &Exchange<'_>,
        server: &mut Server,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
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
                                .all(|(a, &b)| crate::pattern::fold(a) == crate::pattern::fold(b))
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

fn put_basic(output: &mut [u8], offset: usize, information: &FileInformation) {
    wire::put_u64(output, offset, information.creation_time.0);
    wire::put_u64(output, offset + 8, information.last_access_time.0);
    wire::put_u64(output, offset + 16, information.last_write_time.0);
    wire::put_u64(output, offset + 24, information.change_time.0);
    wire::put_u32(output, offset + 32, information.attributes.0);
}

fn put_standard(output: &mut [u8], offset: usize, information: &FileInformation, file: &FileOpen) {
    wire::put_u64(output, offset, information.allocation_size);
    wire::put_u64(output, offset + 8, information.end_of_file);
    wire::put_u32(output, offset + 16, 1);
    wire::put_u8(output, offset + 20, u8::from(file.delete_pending));
    wire::put_u8(output, offset + 21, u8::from(file.directory));
}

/// An index number of zero tells the client that the file system has no
/// file identifiers.
fn index_number(information: &FileInformation) -> u64 {
    information.index.map_or(0, |index| index.0)
}

fn query_file(
    class: FileClass,
    dialect: Option<Dialect>,
    open: &Open,
    file: &FileOpen,
    information: &FileInformation,
    output: &mut [u8; SCRATCH],
) -> Result<Built, Failure> {
    Ok(match class {
        FileClass::BASIC => {
            put_basic(output, 0, information);
            Built::fixed(40)
        }
        FileClass::STANDARD => {
            put_standard(output, 0, information, file);
            Built::fixed(24)
        }
        FileClass::INTERNAL => {
            wire::put_u64(output, 0, index_number(information));
            Built::fixed(8)
        }
        FileClass::EA => Built::fixed(4),
        FileClass::ACCESS => {
            wire::put_u32(output, 0, open.access.0);
            Built::fixed(4)
        }
        FileClass::POSITION => {
            wire::put_u64(output, 0, file.position);
            Built::fixed(8)
        }
        FileClass::MODE => {
            wire::put_u32(output, 0, file.mode.0);
            Built::fixed(4)
        }
        FileClass::ALIGNMENT => Built::fixed(4),
        FileClass::ALL => {
            // The name follows; the caller writes it.
            put_basic(output, 0, information);
            put_standard(output, 40, information, file);
            wire::put_u64(output, 64, index_number(information));
            wire::put_u32(output, 76, open.access.0);
            wire::put_u64(output, 80, file.position);
            wire::put_u32(output, 88, file.mode.0);
            Built::fixed(ALL_FIXED)
        }
        // The name is the whole structure; the caller writes it. Only SMB
        // 3.1.1 defines the class (MS-SMB2 3.3.5.20.1).
        FileClass::NORMALIZED_NAME if dialect == Some(Dialect::SMB_3_1_1) => {
            Built::fixed(NAME_FIXED)
        }
        FileClass::NORMALIZED_NAME => return Err(Failure::Error(RequestError::Unsupported)),
        // Volumes behind the backend have no 8.3 short names.
        FileClass::ALTERNATE_NAME => return Err(Failure::Error(RequestError::Unsupported)),
        FileClass::STREAM if file.directory => Built::fixed(0),
        FileClass::STREAM => {
            wire::put_u32(output, 4, (DATA_STREAM.len() * 2) as u32);
            wire::put_u64(output, 8, information.end_of_file);
            wire::put_u64(output, 16, information.allocation_size);
            for (index, unit) in DATA_STREAM.iter().enumerate() {
                wire::put_u16(output, 24 + index * 2, *unit);
            }
            Built::variable(24 + DATA_STREAM.len() * 2, 24)
        }
        FileClass::COMPRESSION => {
            wire::put_u64(output, 0, information.end_of_file);
            Built::fixed(16)
        }
        FileClass::NETWORK_OPEN => {
            wire::put_u64(output, 0, information.creation_time.0);
            wire::put_u64(output, 8, information.last_access_time.0);
            wire::put_u64(output, 16, information.last_write_time.0);
            wire::put_u64(output, 24, information.change_time.0);
            wire::put_u64(output, 32, information.allocation_size);
            wire::put_u64(output, 40, information.end_of_file);
            wire::put_u32(output, 48, information.attributes.0);
            Built::fixed(56)
        }
        FileClass::ATTRIBUTE_TAG => {
            wire::put_u32(output, 0, information.attributes.0);
            Built::fixed(8)
        }
        FileClass::FULL_EA => return Err(Failure::Error(RequestError::ExtendedAttributes)),
        _ => return Err(Failure::Error(RequestError::UnknownInformationClass)),
    })
}

/// Information of a named pipe open: a connected, full-duplex,
/// message-mode server end.
fn query_pipe(class: FileClass, output: &mut [u8; SCRATCH]) -> Result<Built, Failure> {
    Ok(match class {
        FileClass::BASIC => {
            wire::put_u32(output, 32, FileAttributes::NORMAL.0);
            Built::fixed(40)
        }
        FileClass::STANDARD => {
            wire::put_u32(output, 16, 1);
            Built::fixed(24)
        }
        FileClass::PIPE_LOCAL => {
            wire::put_u32(output, 0, 1);
            wire::put_u32(output, 4, 2);
            wire::put_u32(output, 8, u32::MAX);
            wire::put_u32(output, 12, 1);
            wire::put_u32(output, 16, 0x1000);
            wire::put_u32(output, 24, 0x1000);
            wire::put_u32(output, 28, 0x1000);
            wire::put_u32(output, 32, 3);
            // The client's handle is the client end (0) of the pipe.
            wire::put_u32(output, 36, 0);
            Built::fixed(40)
        }
        _ => return Err(Failure::Error(RequestError::UnknownInformationClass)),
    })
}

fn query_volume(
    class: FsClass,
    volume: &VolumeInformation,
    output: &mut [u8; SCRATCH],
) -> Result<Built, Failure> {
    let size = &volume.size;
    Ok(match class {
        FsClass::VOLUME => {
            // The volume has no label. The reply keeps the 24-byte size of
            // the structure with its one-character label array, which
            // clients expect as the least length.
            wire::put_u64(output, 0, volume.creation_time.0);
            wire::put_u32(output, 8, volume.serial_number);
            Built {
                length: 24,
                minimum: 18,
                complete: 18,
            }
        }
        FsClass::SIZE => {
            wire::put_u64(output, 0, size.total_units);
            wire::put_u64(output, 8, size.available_units);
            wire::put_u32(output, 16, size.sectors_per_unit);
            wire::put_u32(output, 20, size.bytes_per_sector);
            Built::fixed(24)
        }
        FsClass::DEVICE => {
            wire::put_u32(output, 0, DeviceType::DISK.0);
            wire::put_u32(output, 4, DeviceCharacteristics::IS_MOUNTED.0);
            Built::fixed(8)
        }
        FsClass::ATTRIBUTE => {
            let name = volume.file_system_name;
            let name = name.as_bytes();
            wire::put_u32(output, 0, volume.attributes.0);
            wire::put_u32(output, 4, volume.maximum_component_length);
            wire::put_u32(output, 8, (name.len() * 2) as u32);
            for (index, &byte) in name.iter().enumerate() {
                wire::put_u16(output, 12 + index * 2, u16::from(byte));
            }
            Built::variable(12 + name.len() * 2, 12)
        }
        FsClass::FULL_SIZE => {
            wire::put_u64(output, 0, size.total_units);
            wire::put_u64(output, 8, size.available_units);
            wire::put_u64(output, 16, size.available_units);
            wire::put_u32(output, 24, size.sectors_per_unit);
            wire::put_u32(output, 28, size.bytes_per_sector);
            Built::fixed(32)
        }
        FsClass::SECTOR_SIZE => {
            for offset in [0, 4, 8, 12] {
                wire::put_u32(output, offset, size.bytes_per_sector);
            }
            wire::put_u32(
                output,
                16,
                SectorSizeFlags::ALIGNED_DEVICE
                    .union(SectorSizeFlags::PARTITION_ALIGNED_ON_DEVICE)
                    .0,
            );
            Built::fixed(28)
        }
        _ => return Err(Failure::Error(RequestError::UnknownInformationClass)),
    })
}

/// A self-relative security descriptor of the requested parts: Everyone
/// owns every file and holds the share's rights on it.
fn security_descriptor(
    requested: SecurityInformation,
    writable: bool,
    directory: bool,
    output: &mut [u8; SCRATCH],
) -> Result<Built, Failure> {
    if requested.contains(SecurityInformation::SACL) {
        return Err(Failure::Error(RequestError::PrivilegeNotHeld));
    }
    let mut control = SecurityControl::SELF_RELATIVE;
    let mut length = 20;
    output[0] = 1;
    if requested.contains(SecurityInformation::OWNER) {
        wire::put_u32(output, 4, length as u32);
        output[length..length + 12].copy_from_slice(&EVERYONE);
        length += 12;
    }
    if requested.contains(SecurityInformation::GROUP) {
        wire::put_u32(output, 8, length as u32);
        output[length..length + 12].copy_from_slice(&EVERYONE);
        length += 12;
    }
    if requested.contains(SecurityInformation::DACL) {
        control = control.union(SecurityControl::DACL_PRESENT);
        wire::put_u32(output, 16, length as u32);
        let acl = length;
        output[acl] = 2;
        wire::put_u16(output, acl + 2, 28);
        wire::put_u16(output, acl + 4, 1);
        let ace = acl + 8;
        output[ace] = AceType::ACCESS_ALLOWED.0;
        output[ace + 1] = if directory {
            AceFlags::OBJECT_INHERIT.union(AceFlags::CONTAINER_INHERIT)
        } else {
            AceFlags::NONE
        }
        .0;
        wire::put_u16(output, ace + 2, 20);
        wire::put_u32(output, ace + 4, share_maximum(writable).0);
        output[ace + 8..ace + 20].copy_from_slice(&EVERYONE);
        length += 28;
    }
    wire::put_u16(output, 2, control.0);
    Ok(Built::fixed(length))
}
