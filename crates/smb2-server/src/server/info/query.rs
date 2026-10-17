//! QUERY_INFO replies of the file and file system information classes
//! (MS-FSCC 2.4, 2.5).

use crate::fs::FileAttributes;
use crate::fs::FileInformation;
use crate::fs::VolumeInformation;
use crate::server::error::RequestError;
use crate::server::info::ALL_FIXED;
use crate::server::info::Built;
use crate::server::info::FileClass;
use crate::server::info::NAME_FIXED;
use crate::server::info::SCRATCH;
use crate::server::request::Failure;
use crate::server::tables::FileOpen;
use crate::server::tables::Open;
use crate::server::wire;
use crate::server::wire::Dialect;

/// A file system information class (MS-FSCC 2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FsClass(pub(super) u8);

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

/// A file information class of a file or directory open.
pub(super) fn query_file(
    class: FileClass,
    dialect: Option<Dialect>,
    open: &Open,
    file: &FileOpen,
    information: &FileInformation,
    output: &mut [u8; SCRATCH],
) -> Result<Built, Failure> {
    /// The default data stream name, `::$DATA`.
    const DATA_STREAM: [u16; 7] = [0x3a, 0x3a, 0x24, 0x44, 0x41, 0x54, 0x41];

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
pub(super) fn query_pipe(class: FileClass, output: &mut [u8; SCRATCH]) -> Result<Built, Failure> {
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

/// A file system information class of the volume of an open.
pub(super) fn query_volume(
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
