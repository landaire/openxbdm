//! File, drive, and storage commands.

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;

use crate::access::Access;
use crate::commands::console;
use crate::commands::console::ConfigSetting;
use crate::commands::console::TraceMask;
use crate::commands::util;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::notify::ExecutionState;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::state::ServerState;

/// Kernel status codes this domain produces or distinguishes.
pub mod nt {
    use openxbdm_core::status::NtStatus;

    pub const BUFFER_OVERFLOW: NtStatus = NtStatus(0x8000_0005);
    pub const NO_MORE_FILES: NtStatus = NtStatus(0x8000_0006);
    pub const INVALID_PARAMETER: NtStatus = NtStatus(0xc000_000d);
    /// Result of a path that does not translate to an object name.
    pub const NO_SUCH_FILE: NtStatus = NtStatus(0xc000_000f);
    pub const NO_MEDIA_IN_DEVICE: NtStatus = NtStatus(0xc000_0013);
    pub const NO_MEMORY: NtStatus = NtStatus(0xc000_0017);
    pub const ACCESS_DENIED: NtStatus = NtStatus(0xc000_0022);
    pub const OBJECT_NAME_INVALID: NtStatus = NtStatus(0xc000_0033);
    pub const OBJECT_NAME_NOT_FOUND: NtStatus = NtStatus(0xc000_0034);
    pub const OBJECT_NAME_COLLISION: NtStatus = NtStatus(0xc000_0035);
    pub const OBJECT_PATH_NOT_FOUND: NtStatus = NtStatus(0xc000_003a);
    pub const CRC_ERROR: NtStatus = NtStatus(0xc000_003f);
    pub const DISK_FULL: NtStatus = NtStatus(0xc000_007f);
    pub const FILE_IS_A_DIRECTORY: NtStatus = NtStatus(0xc000_00ba);
    pub const NOT_SAME_DEVICE: NtStatus = NtStatus(0xc000_00d4);
    pub const DIRECTORY_NOT_EMPTY: NtStatus = NtStatus(0xc000_0101);
    pub const NOT_A_DIRECTORY: NtStatus = NtStatus(0xc000_0103);
    pub const CANNOT_DELETE: NtStatus = NtStatus(0xc000_0121);
}

/// Most file name parameters are copied into 0x141-byte buffers.
const NAME_BUFFER: usize = 0x141;
/// Translated object names are limited to this many bytes.
pub const OBJECT_PATH_LIMIT: usize = 0x141;
/// Rows of the drive table (0x91f96bf8..0x91f9735c, 0x2c-byte rows); the
/// last row stays the terminator.
const DRIVE_TABLE_CAPACITY: usize = 43;
/// Bytes of the name field of a drive table row, terminator included.
const DRIVE_NAME_SIZE: usize = 0x20;
/// Name bytes the 0x190-byte directory query buffer holds after the fixed
/// 0x40-byte entry header.
const DIRECTORY_NAME_CAPACITY: usize = 0x150;
/// Name bytes the 0x10c-byte object directory query buffer holds.
const OBJECT_NAME_CAPACITY: usize = 0x100;
/// `dirlist` and `drivefreespace` build each line in a pool buffer of this
/// size.
const LINE_BUFFER: u32 = 0x200;
/// Upload staging: two halves of this size.
const UPLOAD_HALF: u32 = 0x4000;
/// `getfile` reads this many bytes per chunk.
const GETFILE_CHUNK: u32 = 0x3000;
/// `getvfattr` receives each piece into a 0x141-byte area.
const VFATTR_RECEIVE_AREA: u32 = 0x141;
/// Bytes per `getvfattr` record.
const VFATTR_RECORD: u32 = 0x1c;
/// `sendvfile` header bytes.
const VFILE_HEADER: u32 = 0x20;
/// `sendvfile` result array offset in its pool block.
const VFILE_RESULTS: u32 = 0x8000;
/// `sysfileupd` data buffer and name area.
const SYSFILE_DATA: u32 = 0x4000;
const SYSFILE_BLOCK: u32 = 0x4200;
const SYSFILE_NAME_BUFFER: usize = 0x200;
/// Block device sector sizes.
const DVD_SECTOR: u32 = 0x800;
const HDD_SECTOR: u32 = 0x200;
const DVD_MAX_BLOCKS: u32 = 0x40;
const HDD_MAX_BLOCKS: u32 = 0x100;
/// XTAF cluster size used by `fmtfat`.
const FORMAT_CLUSTER_SIZE: u32 = 0x4000;
/// `getsum` blocks emitted per continuation call fill at most this many
/// bytes.
const GETSUM_CHUNK: u32 = 0x1000;
const PAGE_SIZE: u32 = 0x1000;
/// Bytes per `dvdperf` trace record.
const DVD_TRACE_RECORD: u32 = 16;

const DEVICE_PREFIX: &[u8] = b"\\Device\\";
const DOS_DEVICES: &[u8] = b"\\??";

/// Configuration setting holding the hard disk disable flag.
const HDD_SETTING: ConfigSetting = ConfigSetting::new(2, 6);
/// Configuration setting holding the previous flash version.
const PREVIOUS_FLASH_SETTING: ConfigSetting = ConfigSetting::new(0xa, 2);

/// Opened file or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHandle(pub u32);

/// Opened object directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectDirectory(pub u32);

/// Referenced device object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceObject(pub u32);

/// Block of platform memory allocated for a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolBuffer(pub u32);

/// Part of a pool block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolRange {
    pub buffer: PoolBuffer,
    pub offset: u32,
    pub length: u32,
}

/// Source of a file write.
#[derive(Debug, Clone, Copy)]
pub enum FileData<'a> {
    Bytes(&'a [u8]),
    Pool(PoolRange),
}

/// Kernel access mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAccess(pub u32);

impl FileAccess {
    pub const LIST_DIRECTORY: Self = Self(0x1);
    pub const WRITE_ATTRIBUTES: Self = Self(0x100);
    pub const DELETE: Self = Self(0x1_0000);
    pub const SYNCHRONIZE: Self = Self(0x10_0000);
    pub const GENERIC_WRITE: Self = Self(0x4000_0000);
    pub const GENERIC_READ: Self = Self(0x8000_0000);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Kernel share mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareAccess(pub u32);

impl ShareAccess {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1);
    pub const READ_WRITE: Self = Self(3);
    pub const ALL: Self = Self(7);
}

/// Kernel create disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateDisposition {
    Supersede = 0,
    Open = 1,
    Create = 2,
    OpenIf = 3,
    Overwrite = 4,
    OverwriteIf = 5,
}

/// Kernel create options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateOptions(pub u32);

impl CreateOptions {
    pub const NONE: Self = Self(0);
    pub const DIRECTORY_FILE: Self = Self(0x1);
    pub const SYNCHRONOUS_IO_ALERT: Self = Self(0x10);
    pub const SYNCHRONOUS_IO_NONALERT: Self = Self(0x20);
    pub const NON_DIRECTORY_FILE: Self = Self(0x40);
    pub const OPEN_FOR_BACKUP: Self = Self(0x4000);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// File attribute bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileAttributes(pub u32);

impl FileAttributes {
    pub const NONE: Self = Self(0);
    pub const READONLY: Self = Self(0x1);
    pub const HIDDEN: Self = Self(0x2);
    pub const DIRECTORY: Self = Self(0x10);
    pub const NORMAL: Self = Self(0x80);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// A FILETIME value; 0 in a set request leaves the time unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileTime(pub u64);

impl FileTime {
    pub const fn high(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub const fn low(self) -> u32 {
        self.0 as u32
    }

    pub const fn from_parts(high: u32, low: u32) -> Self {
        Self((high as u64) << 32 | low as u64)
    }
}

/// Arguments of a file create or open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateRequest {
    pub access: FileAccess,
    pub allocation_size: Option<u64>,
    pub attributes: FileAttributes,
    pub share: ShareAccess,
    pub disposition: CreateDisposition,
    pub options: CreateOptions,
}

impl CreateRequest {
    /// Open an existing file without an allocation size or attributes.
    pub const fn open(access: FileAccess, share: ShareAccess, options: CreateOptions) -> Self {
        Self {
            access,
            allocation_size: None,
            attributes: FileAttributes::NONE,
            share,
            disposition: CreateDisposition::Open,
            options,
        }
    }
}

/// Size, times, and attributes of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileInformation {
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub attributes: FileAttributes,
}

/// Times and attributes to set; zero times are left unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BasicInformation {
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub attributes: FileAttributes,
}

/// One directory enumeration result; the name is in the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub information: FileInformation,
    pub name_length: usize,
}

/// Volume allocation sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeSize {
    pub total_units: u64,
    pub available_units: u64,
    pub sectors_per_unit: u32,
    pub bytes_per_sector: u32,
}

/// Direction of a raw device transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Read,
    Write,
}

/// A stopped optical drive trace: `length` bytes of 16-byte records at
/// the start of `buffer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DvdTrace {
    pub buffer: PoolBuffer,
    pub length: u32,
}

/// Platform services this domain needs. Paths are kernel object names.
pub trait Backend {
    fn create_file(&mut self, path: &[u8], request: &CreateRequest)
    -> Result<FileHandle, NtStatus>;
    /// Open `name` relative to an object directory.
    fn open_relative(
        &mut self,
        root: ObjectDirectory,
        name: &[u8],
        access: FileAccess,
        share: ShareAccess,
        options: CreateOptions,
    ) -> Result<FileHandle, NtStatus>;
    fn close_file(&mut self, handle: FileHandle);
    /// Count the close of a file a command may have changed (0x91f9feec,
    /// read by export 85).
    fn count_file_change(&mut self);
    /// Read up to `target.length` bytes at `offset`, or at the current
    /// position when `None`; returns the bytes read.
    fn read_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        target: PoolRange,
    ) -> Result<u32, NtStatus>;
    /// Write at `offset`, or at the current position when `None`.
    fn write_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        data: FileData<'_>,
    ) -> Result<(), NtStatus>;
    fn set_delete_disposition(&mut self, handle: FileHandle, delete: bool) -> Result<(), NtStatus>;
    fn set_end_of_file(&mut self, handle: FileHandle, size: u64) -> Result<(), NtStatus>;
    fn set_file_position(&mut self, handle: FileHandle, position: u64) -> Result<(), NtStatus>;
    fn set_basic_information(
        &mut self,
        handle: FileHandle,
        information: &BasicInformation,
    ) -> Result<(), NtStatus>;
    fn rename_file(
        &mut self,
        handle: FileHandle,
        target: &[u8],
        replace: bool,
    ) -> Result<(), NtStatus>;
    fn query_file_information(&mut self, handle: FileHandle) -> Result<FileInformation, NtStatus>;
    fn query_full_attributes(&mut self, path: &[u8]) -> Result<FileInformation, NtStatus>;
    /// Next entry of a directory; the name goes into `name`. A name longer
    /// than `name` fails with [`nt::BUFFER_OVERFLOW`].
    fn query_directory(
        &mut self,
        handle: FileHandle,
        restart: bool,
        name: &mut [u8],
    ) -> Result<DirectoryEntry, NtStatus>;
    fn query_volume_size(&mut self, handle: FileHandle) -> Result<VolumeSize, NtStatus>;
    /// Resolve the symbolic link object `link` into `target`; returns the
    /// target length.
    fn translate_symbolic_link(
        &mut self,
        link: &[u8],
        target: &mut [u8],
    ) -> Result<usize, NtStatus>;
    fn open_object_directory(&mut self, path: &[u8]) -> Result<ObjectDirectory, NtStatus>;
    /// Next object name of a directory; `context` carries the position.
    fn query_object_directory(
        &mut self,
        directory: ObjectDirectory,
        restart: bool,
        context: &mut u32,
        name: &mut [u8],
    ) -> Result<usize, NtStatus>;
    fn close_object_directory(&mut self, directory: ObjectDirectory);
    fn reference_device(&mut self, name: &[u8]) -> Result<DeviceObject, NtStatus>;
    fn dereference_device(&mut self, device: DeviceObject);
    /// Synchronous transfer of `buffer.length` bytes at byte `offset`.
    fn transfer_device(
        &mut self,
        device: DeviceObject,
        direction: TransferDirection,
        offset: u64,
        buffer: PoolRange,
    ) -> Result<(), NtStatus>;
    fn allocate_pool(&mut self, size: u32) -> Option<PoolBuffer>;
    fn free_pool(&mut self, buffer: PoolBuffer);
    fn pool(&mut self, buffer: PoolBuffer) -> &mut [u8];
    /// Open (nonzero) or close (zero) the optical drive tray.
    fn open_close_tray(&mut self, value: u32);
    /// Format a block device as XTAF.
    fn format_partition(&mut self, device: &[u8], cluster_size: u32) -> Result<(), NtStatus>;
    /// The kernel update sequence number used in system update file names.
    fn update_sequence(&mut self) -> u16;
    /// The Win32 error code of a kernel status.
    fn dos_error(&mut self, status: NtStatus) -> u32;
    /// Allocate a fresh optical drive trace buffer and enable tracing.
    /// Allocation failure leaves tracing off.
    fn start_dvd_trace(&mut self);
    /// Disable tracing and take the trace buffer.
    fn stop_dvd_trace(&mut self) -> Option<DvdTrace>;
    /// Whether a trace buffer is allocated.
    fn dvd_trace_active(&mut self) -> bool;
}

/// Global state of this domain.
#[derive(Debug, Default)]
pub struct State {
    pub drives: DriveTable,
}

/// Close a file a command may have changed and count the change.
fn close_changed(backend: &mut dyn crate::backend::Backend, handle: FileHandle) {
    backend.close_file(handle);
    backend.count_file_change();
}

/// Where a drive name points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveTarget {
    Object(&'static [u8]),
    /// The network share in [`DriveTable::set_network_share`].
    NetworkShare,
    /// A string in title memory, read on every use, whose length was
    /// taken when the title mapped the drive (control code 0x03).
    Mapped {
        address: u32,
        length: u32,
    },
}

/// Name of a drive table row.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DriveName {
    bytes: [u8; DRIVE_NAME_SIZE],
    len: u8,
}

impl DriveName {
    /// The name cut to the row's field less its terminator.
    pub const fn new(name: &[u8]) -> Self {
        let mut bytes = [0; DRIVE_NAME_SIZE];
        let mut len = 0;
        while len < name.len() && len < DRIVE_NAME_SIZE - 1 {
            bytes[len] = name[len];
            len += 1;
        }
        Self {
            bytes,
            len: len as u8,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for DriveName {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_bytes() == other.as_slice()
    }
}

impl core::fmt::Debug for DriveName {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:?}", self.as_bytes().escape_ascii())
    }
}

/// One row of the drive table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drive {
    pub name: DriveName,
    pub target: DriveTarget,
    /// Enabled drives are listed by `drivelist`; translation ignores it.
    pub enabled: bool,
}

const BADPATH: &[u8] = b"\\Badpath";
const NETWORK_SHARE_PREFIX: &[u8] = b"\\Network\\Smb\\";
/// `\Network\Smb\` plus at most 0x3d server characters.
const NETWORK_SHARE_CAPACITY: usize = 0x50;

const fn drive(name: &'static [u8], target: &'static [u8], enabled: bool) -> Option<Drive> {
    Some(Drive {
        name: DriveName::new(name),
        target: DriveTarget::Object(target),
        enabled,
    })
}

/// The drive table of the image, followed by the hidden `\x01` entry that
/// initialization maps to `\SystemRoot`.
const DEFAULT_DRIVES: [Option<Drive>; DRIVE_TABLE_CAPACITY] = [
    drive(b"A", b"\\Device\\Cdrom0", false),
    drive(b"DVD", b"\\Device\\Cdrom0", true),
    drive(b"E", b"\\Device\\Harddisk0\\Partition1\\DEVKIT", true),
    drive(b"DEVKIT", b"\\Device\\Harddisk0\\Partition1\\DEVKIT", true),
    drive(b"U", b"\\Network", false),
    drive(b"NET", b"\\Network", false),
    drive(b"MU0", b"\\Device\\Mu0", true),
    drive(b"MU1", b"\\Device\\Mu1", true),
    drive(b"HDD", b"\\Device\\Harddisk0\\Partition1", true),
    drive(b"MUINT", b"\\Device\\BuiltInMuSfc", true),
    drive(b"INTUSB", b"\\Device\\BuiltInMuUsb\\Storage", true),
    drive(
        b"USBMASS0MU",
        b"\\Device\\Mass0PartitionFile\\Storage",
        true,
    ),
    drive(
        b"USBMASS1MU",
        b"\\Device\\Mass1PartitionFile\\Storage",
        true,
    ),
    drive(b"F", BADPATH, false),
    drive(b"SMB", BADPATH, false),
    drive(b"Y", BADPATH, false),
    drive(b"Z", BADPATH, false),
    drive(b"FLASH", BADPATH, false),
    drive(b"MU0SYS", BADPATH, false),
    drive(b"MU1SYS", BADPATH, false),
    drive(b"USBMASS0", BADPATH, false),
    drive(b"USBMASS1", BADPATH, false),
    drive(b"USBMASS2", BADPATH, false),
    drive(b"MEDIA", BADPATH, false),
    drive(b"MUINTSYS", BADPATH, false),
    drive(b"HDDSYSEXT", BADPATH, false),
    drive(b"HDDSYSAUX", BADPATH, false),
    drive(b"INTUSBSYS", BADPATH, false),
    drive(b"INTUSBSYSEXT", BADPATH, false),
    drive(b"INTUSBSYSAUX", BADPATH, false),
    drive(b"INTMMC", BADPATH, false),
    drive(b"INTMMCSYS", BADPATH, false),
    drive(b"INTMMCSYSEXT", BADPATH, false),
    drive(b"INTMMCSYSAUX", BADPATH, false),
    drive(b"HDDVD", BADPATH, false),
    drive(b"HDDVDMU", BADPATH, false),
    drive(b"HDDVDSYS", BADPATH, false),
    drive(b"TRANSFERCABLE", BADPATH, false),
    drive(b"USBMASS0MUSYS", BADPATH, false),
    drive(b"USBMASS1MUSYS", BADPATH, false),
    drive(b"\x01", b"\\SystemRoot", false),
    None,
    None,
];

/// The mapping applied at startup when `drivemap internal` is nonzero
/// (0x91f2f0f8), in order.
const INTERNAL_DRIVES: &[(&[u8], &[u8], bool)] = &[
    (b"DEVICE", b"\\Device", false),
    (b"Y", b"\\Device\\Harddisk0\\SystemPartition", true),
    (b"Z", b"\\Device\\Harddisk0\\Partition1", true),
    (b"FLASH", b"\\Device\\Flash", true),
    (b"MU0SYS", b"\\Device\\Mu0System", false),
    (b"MU1SYS", b"\\Device\\Mu1System", false),
    (b"USBMASS0", b"\\Device\\Mass0", false),
    (b"USBMASS1", b"\\Device\\Mass1", false),
    (b"USBMASS2", b"\\Device\\Mass2", false),
    (b"MUINTSYS", b"\\Device\\BuiltInMuSfcSystem", false),
    (
        b"HDDSYSEXT",
        b"\\Device\\Harddisk0\\SystemExtPartition",
        false,
    ),
    (
        b"HDDSYSAUX",
        b"\\Device\\Harddisk0\\SystemAuxPartition",
        false,
    ),
    (b"INTUSB", b"\\Device\\BuiltInMuUsb\\Storage", true),
    (
        b"INTUSBSYS",
        b"\\Device\\BuiltInMuUsb\\StorageSystem",
        false,
    ),
    (
        b"INTUSBSYSEXT",
        b"\\Device\\BuiltInMuUsb\\SystemExtPartition",
        false,
    ),
    (
        b"INTUSBSYSAUX",
        b"\\Device\\BuiltInMuUsb\\SystemAuxPartition",
        false,
    ),
    (b"INTMMC", b"\\Device\\BuiltInMuMmc\\Storage", true),
    (
        b"INTMMCSYS",
        b"\\Device\\BuiltInMuMmc\\StorageSystem",
        false,
    ),
    (
        b"INTMMCSYSEXT",
        b"\\Device\\BuiltInMuMmc\\SystemExtPartition",
        false,
    ),
    (
        b"INTMMCSYSAUX",
        b"\\Device\\BuiltInMuMmc\\SystemAuxPartition",
        false,
    ),
    (b"HDDVD", b"\\Device\\HdDvdRom", false),
    (b"HDDVDMU", b"\\Device\\HdDvdStorage", false),
    (b"HDDVDSYS", b"\\Device\\HdDvdPlayer", false),
    (b"TRANSFERCABLE", b"\\Device\\TransferCable", false),
    (
        b"USBMASS0MU",
        b"\\Device\\Mass0PartitionFile\\Storage",
        true,
    ),
    (
        b"USBMASS1MU",
        b"\\Device\\Mass1PartitionFile\\Storage",
        true,
    ),
    (
        b"USBMASS0MUSYS",
        b"\\Device\\Mass0PartitionFile\\StorageSystem",
        false,
    ),
    (
        b"USBMASS1MUSYS",
        b"\\Device\\Mass1PartitionFile\\StorageSystem",
        false,
    ),
];

/// Drive names and the object directories they map to (0x91f96bf8).
#[derive(Debug, Clone)]
pub struct DriveTable {
    entries: [Option<Drive>; DRIVE_TABLE_CAPACITY],
    network_share: [u8; NETWORK_SHARE_CAPACITY],
    network_share_len: usize,
}

impl Default for DriveTable {
    fn default() -> Self {
        Self {
            entries: DEFAULT_DRIVES,
            network_share: [0; NETWORK_SHARE_CAPACITY],
            network_share_len: 0,
        }
    }
}

/// A translated object name.
#[derive(Clone)]
pub struct ObjectPath {
    bytes: [u8; OBJECT_PATH_LIMIT],
    len: usize,
}

impl ObjectPath {
    const fn new() -> Self {
        Self {
            bytes: [0; OBJECT_PATH_LIMIT],
            len: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Append within the limit, dropping the excess as the translator does.
    fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.len >= OBJECT_PATH_LIMIT {
                return;
            }
            self.bytes[self.len] = byte;
            self.len += 1;
        }
    }
}

impl core::fmt::Debug for ObjectPath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:?}", self.as_bytes().escape_ascii())
    }
}

impl DriveTable {
    /// Rows in table order.
    pub fn drives(&self) -> impl Iterator<Item = &Drive> {
        self.entries.iter().map_while(Option::as_ref)
    }

    /// The bytes of `target`; `None` when a mapped string cannot be read.
    /// Mapped strings are read only up to `limit` bytes.
    fn target_bytes<'a>(
        &'a self,
        backend: &'a mut dyn crate::backend::Backend,
        target: DriveTarget,
        limit: usize,
    ) -> Option<&'a [u8]> {
        match target {
            DriveTarget::Object(bytes) => Some(bytes),
            DriveTarget::NetworkShare => Some(&self.network_share[..self.network_share_len]),
            DriveTarget::Mapped { address, length } => {
                backend.target_bytes(address, (length as usize).min(limit))
            }
        }
    }

    /// Point a drive at `target` or remove it (`None`), appending unknown
    /// names (0x91f2ef60). Names compare case-sensitively; a full table
    /// ignores new names. Removal moves the last row into the gap.
    pub fn map(&mut self, name: DriveName, target: Option<DriveTarget>, enabled: bool) {
        let count = self.drives().count();
        let index = self.entries[..count]
            .iter()
            .position(|entry| entry.is_some_and(|drive| drive.name == name));
        let index = match index {
            Some(index) => index,
            None if count + 1 < DRIVE_TABLE_CAPACITY => count,
            None => return,
        };
        match target {
            Some(target) => {
                self.entries[index] = Some(Drive {
                    name,
                    target,
                    enabled,
                })
            }
            None if index < count => {
                self.entries[index] = self.entries[count - 1];
                self.entries[count - 1] = None;
            }
            None => {}
        }
    }

    /// Apply the internal drive mapping (0x91f2f0f8).
    pub fn map_internal_drives(&mut self) {
        for &(name, target, enabled) in INTERNAL_DRIVES {
            self.map(
                DriveName::new(name),
                Some(DriveTarget::Object(target)),
                enabled,
            );
        }
    }

    /// Point the first `F` or `SMB` drive at `\Network\Smb\<server>` and
    /// enable it, or at `\Badpath` disabled when `server` is `None`.
    pub fn set_network_share(&mut self, server: Option<&[u8]>) {
        let Some(entry) = self
            .entries
            .iter_mut()
            .map_while(Option::as_mut)
            .find(|drive| drive.name == b"F" || drive.name == b"SMB")
        else {
            return;
        };
        match server {
            Some(server) => {
                let server = &server[..server
                    .len()
                    .min(NETWORK_SHARE_CAPACITY - NETWORK_SHARE_PREFIX.len())];
                let prefix = NETWORK_SHARE_PREFIX.len();
                self.network_share[..prefix].copy_from_slice(NETWORK_SHARE_PREFIX);
                self.network_share[prefix..prefix + server.len()].copy_from_slice(server);
                self.network_share_len = prefix + server.len();
                entry.target = DriveTarget::NetworkShare;
                entry.enabled = true;
            }
            None => {
                entry.target = DriveTarget::Object(BADPATH);
                entry.enabled = false;
            }
        }
    }

    fn find(&self, drive: &[u8]) -> Option<&Drive> {
        self.drives()
            .find(|entry| entry.name.as_bytes().eq_ignore_ascii_case(drive))
    }

    /// Translate a drive path such as `E:\dir\file` to an object name
    /// (0x91f2e888). A leading `x` or `X` before a one-character drive is
    /// dropped. Drives missing from the table resolve through the `\??`
    /// symbolic link of the path, and to `\??\<path>` when that fails.
    pub fn translate(
        &self,
        backend: &mut dyn crate::backend::Backend,
        path: &[u8],
    ) -> Option<ObjectPath> {
        trace_path(backend, |message| {
            let _ = message.write_str("[xbdm] FFileNameToObName(sz='");
            let _ = message.push_bytes(console::c_string(path));
            let _ = message.write_str("',...)\n");
        });
        let translated = self.object_name(backend, path);
        match &translated {
            Some(output) => trace_path(backend, |message| {
                let _ = message.write_str("[xbdm] FFileNameToObName succeeded, osz='");
                let _ = message.push_bytes(console::c_string(output.as_bytes()));
                let _ = message.write_str("'\n");
            }),
            None => trace_path(backend, |message| {
                let _ =
                    message.write_str("[xbdm] FFileNameToObName - not a drive path - failing\n");
            }),
        }
        translated
    }

    fn object_name(
        &self,
        backend: &mut dyn crate::backend::Backend,
        path: &[u8],
    ) -> Option<ObjectPath> {
        let at = |index: usize| path.get(index).copied().unwrap_or(0);
        let input = if matches!(at(0), b'x' | b'X') && at(1) != b':' && at(1) != 0 && at(2) == b':'
        {
            &path[1..]
        } else {
            path
        };
        let colon = input.iter().position(|&byte| byte == b':')?;
        if input.get(colon + 1) != Some(&b'\\') {
            return None;
        }
        let drive = &input[..colon];
        let mut output = ObjectPath::new();
        if let Some(entry) = self.find(drive) {
            trace_path(backend, |message| {
                let _ = message
                    .write_str("[xbdm] FFileNameToObName - drive name in conversion table\n");
            });
            match entry.target {
                // The image copies the title's string up to its NUL on
                // every use; an unreadable page ends it (the image would
                // fault).
                DriveTarget::Mapped { address, .. } => {
                    let mut at = address;
                    while output.len < OBJECT_PATH_LIMIT {
                        let room = (PAGE_SIZE - (at & (PAGE_SIZE - 1))) as usize;
                        let Some(bytes) =
                            backend.target_bytes(at, room.min(OBJECT_PATH_LIMIT - output.len))
                        else {
                            break;
                        };
                        let end = bytes.iter().position(|&byte| byte == 0);
                        output.push(&bytes[..end.unwrap_or(bytes.len())]);
                        if end.is_some() || bytes.is_empty() {
                            break;
                        }
                        at = at.wrapping_add(bytes.len() as u32);
                    }
                }
                target => {
                    if let Some(target) = self.target_bytes(backend, target, OBJECT_PATH_LIMIT) {
                        output.push(target);
                    }
                }
            }
            output.push(&input[colon + 1..]);
            return Some(output);
        }

        // `_snprintf(buffer, 0x104, "%s%s", "\??\", path)`.
        let mut link = [0u8; 0x103];
        let mut link_len = 0;
        for &byte in b"\\??\\".iter().chain(input) {
            if link_len == link.len() {
                break;
            }
            link[link_len] = byte;
            link_len += 1;
        }
        let link = &link[..link_len];
        match backend.translate_symbolic_link(link, &mut output.bytes) {
            Ok(length) => {
                let mut length = length.min(OBJECT_PATH_LIMIT);
                if link.last() == Some(&b'\\')
                    && length > 0
                    && output.bytes[length - 1] != b'\\'
                    && length < OBJECT_PATH_LIMIT
                {
                    output.bytes[length] = b'\\';
                    length += 1;
                }
                output.len = length;
            }
            Err(_) => {
                output.push(b"\\??\\");
                for &byte in drive {
                    output.push(&[byte.to_ascii_uppercase()]);
                }
                output.push(&input[colon..]);
            }
        }
        Some(output)
    }

    /// Convert an object name back to a drive path (0x91f2e750): the
    /// first drive whose target is a case-insensitive prefix of
    /// `object_path` gives `<drive>:<rest>`, otherwise the name is copied.
    /// The output holds at most `output.len() - 1` bytes; returns the
    /// length.
    pub fn object_path_to_drive_path(
        &self,
        backend: &mut dyn crate::backend::Backend,
        object_path: &[u8],
        output: &mut [u8],
    ) -> usize {
        let limit = output.len().saturating_sub(1);
        for entry in self.drives() {
            let length = match entry.target {
                DriveTarget::Mapped { length, .. } => length as usize,
                DriveTarget::Object(bytes) => bytes.len(),
                DriveTarget::NetworkShare => self.network_share_len,
            };
            if object_path.len() < length {
                continue;
            }
            let Some(target) = self.target_bytes(backend, entry.target, length) else {
                continue;
            };
            if target.len() == length && object_path[..length].eq_ignore_ascii_case(target) {
                let mut length = 0;
                for &byte in entry.name.as_bytes().iter().chain(b":") {
                    if length < output.len() {
                        output[length] = byte;
                    }
                    length += 1;
                }
                let length = length.min(output.len());
                let room = limit.saturating_sub(length);
                let rest = &object_path[target.len()..];
                let count = rest.len().min(room);
                output[length..length + count].copy_from_slice(&rest[..count]);
                return length + count;
            }
        }
        let count = object_path.len().min(limit);
        output[..count].copy_from_slice(&object_path[..count]);
        count
    }
}

/// A FFileNameToObName trace text. The translation holds no server state;
/// the published mask follows every change of the server's.
fn trace_path(
    backend: &mut dyn crate::backend::Backend,
    build: impl FnOnce(&mut console::MessageText),
) {
    let mask = console::Backend::trace_mask(backend);
    console::trace_text(mask, backend, TraceMask::PATHS, build);
}

/// Control code 0x03 (0x91f2ef60, enabled): map the drive named by a title
/// request `{name: [u8; 0x20], target: u32}` at `request` to the string at
/// `target`, or remove it when `target` is null. The table keeps the
/// title's pointer. `F` and `SMB` refresh the network share drive from the
/// configuration instead. Unreadable request memory, on which the image
/// would fault, leaves the table unchanged.
pub fn map_title_drive(
    state: &mut ServerState,
    backend: &mut dyn crate::backend::Backend,
    request: u32,
) -> u32 {
    let Some(bytes) = backend.target_bytes(request, DRIVE_NAME_SIZE + 4) else {
        return 0;
    };
    let name_len = bytes[..DRIVE_NAME_SIZE]
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(DRIVE_NAME_SIZE);
    let name = DriveName::new(&bytes[..name_len]);
    let address = u32::from_be_bytes([
        bytes[DRIVE_NAME_SIZE],
        bytes[DRIVE_NAME_SIZE + 1],
        bytes[DRIVE_NAME_SIZE + 2],
        bytes[DRIVE_NAME_SIZE + 3],
    ]);
    if name == b"F" || name == b"SMB" {
        crate::commands::console::refresh_network_share(state, backend);
        return 0;
    }
    let target = match address {
        0 => None,
        _ => match mapped_length(backend, address) {
            Some(length) => Some(DriveTarget::Mapped { address, length }),
            None => return 0,
        },
    };
    state.filesystem.drives.map(name, target, true);
    0
}

/// Length of the title string at `address`. Strings longer than any object
/// name count as `OBJECT_PATH_LIMIT + 1` bytes, which no translation or
/// prefix comparison can tell apart from their real length.
fn mapped_length(backend: &mut dyn crate::backend::Backend, address: u32) -> Option<u32> {
    let mut length = 0;
    while length <= OBJECT_PATH_LIMIT {
        let at = address.wrapping_add(length as u32);
        let page_room = (PAGE_SIZE - (at & (PAGE_SIZE - 1))) as usize;
        let count = page_room.min(OBJECT_PATH_LIMIT + 1 - length);
        let bytes = backend.target_bytes(at, count)?;
        if let Some(end) = bytes.iter().position(|&byte| byte == 0) {
            return Some((length + end) as u32);
        }
        length += count;
    }
    Some(length as u32)
}

/// Whether `name` starts with `\Device\`, ignoring case.
fn is_device_path(name: &[u8]) -> bool {
    name.len() >= DEVICE_PREFIX.len()
        && name[..DEVICE_PREFIX.len()].eq_ignore_ascii_case(DEVICE_PREFIX)
}

/// Open a drive path (0x91f2eb68); a path that does not translate fails
/// with [`nt::NO_SUCH_FILE`].
pub fn open_translated(
    state: &ServerState,
    backend: &mut dyn crate::backend::Backend,
    name: &[u8],
    request: &CreateRequest,
) -> Result<FileHandle, NtStatus> {
    let path = state
        .filesystem
        .drives
        .translate(backend, name)
        .ok_or(nt::NO_SUCH_FILE)?;
    backend.create_file(path.as_bytes(), request)
}

/// Open `\Device\` names as object names and translate the others.
pub fn open_path(
    state: &ServerState,
    backend: &mut dyn crate::backend::Backend,
    name: &[u8],
    request: &CreateRequest,
) -> Result<FileHandle, NtStatus> {
    if is_device_path(name) {
        backend.create_file(name, request)
    } else {
        open_translated(state, backend, name, request)
    }
}

/// Appends formatted text to a byte buffer, truncating at its end.
struct SliceWriter<'a> {
    buffer: &'a mut [u8],
    len: usize,
}

impl<'a> SliceWriter<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, len: 0 }
    }

    fn push(&mut self, bytes: &[u8]) {
        let count = bytes.len().min(self.buffer.len() - self.len);
        self.buffer[self.len..self.len + count].copy_from_slice(&bytes[..count]);
        self.len += count;
    }
}

impl core::fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        self.push(value.as_bytes());
        Ok(())
    }
}

/// The size, time, and attribute fields shared by `dirlist` and
/// `getfileattributes` (0x91f45c90).
fn write_attributes(output: &mut impl core::fmt::Write, information: &FileInformation) {
    let attributes = information.attributes;
    let _ = write!(
        output,
        "sizehi=0x{:x} sizelo=0x{:x} createhi=0x{:08x} createlo=0x{:08x} changehi=0x{:08x} changelo=0x{:08x}{}{}{}",
        (information.end_of_file >> 32) as u32,
        information.end_of_file as u32,
        information.creation_time.high(),
        information.creation_time.low(),
        information.last_write_time.high(),
        information.last_write_time.low(),
        if attributes.contains(FileAttributes::DIRECTORY) {
            " directory"
        } else {
            ""
        },
        if attributes.contains(FileAttributes::READONLY) {
            " readonly"
        } else {
            ""
        },
        if attributes.contains(FileAttributes::HIDDEN) {
            " hidden"
        } else {
            ""
        },
    );
}

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry(
        "delete",
        Access::NONE,
        Access::READ.union(Access::WRITE),
        delete,
    ),
    entry("dirlist", Access::READ, Access::NONE, dirlist),
    entry(
        "drivefreespace",
        Access::READ,
        Access::NONE,
        drive_free_space,
    ),
    entry("drivelist", Access::READ, Access::NONE, drive_list),
    entry("dvdblk", Access::READ, Access::NONE, dvd_block),
    entry("dvdeject", Access::READ, Access::NONE, dvd_eject),
    entry("dvdperf", Access::CONTROL, Access::NONE, dvd_performance),
    entry(
        "fileeof",
        Access::NONE,
        Access::READ.union(Access::WRITE),
        file_eof,
    ),
    entry("fmtfat", Access::CONFIG, Access::NONE, format_fat),
    entry("getfile", Access::READ, Access::NONE, get_file),
    entry(
        "getfileattributes",
        Access::READ.union(Access::WRITE),
        Access::NONE,
        get_file_attributes,
    ),
    entry("gethddblk", Access::READ, Access::NONE, get_hdd_block),
    entry("getsum", Access::CONTROL, Access::NONE, get_sum),
    entry(
        "getvfattr",
        Access::READ.union(Access::WRITE),
        Access::NONE,
        get_vfattr,
    ),
    entry("hdd", Access::CONTROL, Access::NONE, hdd),
    entry("mkdir", Access::WRITE, Access::NONE, make_directory),
    entry("prevflash", Access::CONTROL, Access::NONE, previous_flash),
    entry(
        "rename",
        Access::NONE,
        Access::READ.union(Access::WRITE),
        rename,
    ),
    entry("sendfile", Access::WRITE, Access::NONE, send_file),
    entry("sendvfile", Access::WRITE, Access::NONE, send_vfile),
    entry(
        "setfileattributes",
        Access::WRITE,
        Access::NONE,
        set_file_attributes,
    ),
    entry("sethddblk", Access::WRITE, Access::NONE, set_hdd_block),
    entry(
        "sysfileupd",
        Access::CONFIG,
        Access::NONE,
        system_file_update,
    ),
    entry("writefile", Access::WRITE, Access::NONE, write_file),
];

const fn entry(
    name: &'static str,
    any_of: Access,
    all_of: Access,
    handler: crate::registry::Handler,
) -> CommandEntry {
    CommandEntry {
        name,
        any_of,
        all_of,
        flags: DispatchFlags::NONE,
        handler,
    }
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    DirectoryList {
        handle: FileHandle,
        count: u32,
        line: PoolBuffer,
    },
    DriveFreeSpace {
        handle: FileHandle,
        first: bool,
        line: PoolBuffer,
    },
    DriveList(DriveList),
    GetFile(GetFile),
    /// The single `getfileattributes` line; `None` once sent.
    FileAttributes(Option<FileInformation>),
    Upload(Upload),
    MultiUpload(MultiUpload),
    VirtualAttributes(VirtualAttributes),
    BlockRead(BlockRead),
    BlockWrite(BlockWrite),
    SystemFileUpdate(SystemFileUpdate),
    DvdReport(DvdReport),
    Checksum(Checksum),
}

pub(crate) fn resume(continuation: &mut Continuation, cx: &mut ContinuationContext<'_>) -> Hresult {
    match continuation {
        Continuation::DirectoryList {
            handle,
            count,
            line,
        } => directory_list_line(*handle, count, *line, cx),
        Continuation::DriveFreeSpace {
            handle,
            first,
            line,
        } => drive_free_space_line(*handle, first, *line, cx),
        Continuation::DriveList(list) => drive_list_line(list, cx),
        Continuation::GetFile(transfer) => get_file_data(transfer, cx),
        Continuation::FileAttributes(information) => match information.take() {
            Some(information) => {
                write_attributes(cx.line, &information);
                Hresult::OK
            }
            None => Hresult::END_OF_DATA,
        },
        Continuation::Upload(upload) => upload.resume(cx),
        Continuation::MultiUpload(upload) => upload.resume(cx),
        Continuation::VirtualAttributes(transfer) => transfer.resume(cx),
        Continuation::BlockRead(transfer) => transfer.resume(cx),
        Continuation::BlockWrite(transfer) => transfer.resume(cx),
        Continuation::SystemFileUpdate(transfer) => transfer.resume(cx),
        Continuation::DvdReport(report) => report.resume(cx),
        Continuation::Checksum(checksum) => checksum.resume(cx),
    }
}

fn string_param<'b>(
    invocation: &Invocation<'_>,
    key: &str,
    buffer: &'b mut [u8],
) -> Option<&'b [u8]> {
    invocation
        .line
        .param(key)
        .map(|value| value.copy_into(buffer))
}

/// The `name` parameter; when absent the reply text becomes
/// `missing name`.
fn name_param<'b>(invocation: &mut Invocation<'_>, buffer: &'b mut [u8]) -> Option<&'b [u8]> {
    let name = string_param(invocation, "name", buffer);
    if name.is_none() {
        invocation.set_text(format_args!("missing name"));
    }
    name
}

/// An optional dword; the monitor stores the parsed prefix even when the
/// value has trailing text.
fn optional_dword(invocation: &Invocation<'_>, key: &str, default: u32) -> u32 {
    invocation
        .line
        .param(key)
        .map_or(default, |value| value.dword_prefix())
}

/// Store a continuation; `false` without a connection.
fn begin(
    invocation: &mut Invocation<'_>,
    continuation: Continuation,
    receive: Option<u32>,
) -> bool {
    let Some(session) = invocation.session.as_deref_mut() else {
        return false;
    };
    session.receive_remaining = receive;
    session.continuation = AnyContinuation::FileSystem(continuation);
    true
}

const fn map(status: NtStatus, fallback: Hresult) -> Hresult {
    Hresult::from_nt_status(status, fallback)
}

const ACCESS_DENIED: Hresult = Hresult::from_error_code(ErrorCode::ACCESS_DENIED);
const CANNOT_CREATE: Hresult = Hresult::from_error_code(ErrorCode::FILE_CANNOT_BE_CREATED);
const SYNCHRONOUS: CreateOptions = CreateOptions::SYNCHRONOUS_IO_NONALERT;
const DIRECTORY: CreateOptions = CreateOptions::DIRECTORY_FILE.union(SYNCHRONOUS);

/// `delete name=<path> [dir]`.
fn delete(invocation: &mut Invocation<'_>) -> Hresult {
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return util::MISSING;
    };
    let directory = invocation.line.has("dir");
    let at = |index: usize| name.get(index).copied().unwrap_or(0);
    let base = usize::from(matches!(at(0), b'x' | b'X'));
    if at(base + 1) == b':' && at(base + 2) == b'\\' && at(base + 3) == 0 {
        return ACCESS_DENIED;
    }
    let options = if directory {
        DIRECTORY
    } else {
        CreateOptions::NON_DIRECTORY_FILE.union(SYNCHRONOUS)
    };
    let request = CreateRequest::open(
        FileAccess::DELETE.union(FileAccess::SYNCHRONIZE),
        ShareAccess::NONE,
        options,
    );
    match open_path(invocation.state, invocation.backend, name, &request) {
        Err(nt::FILE_IS_A_DIRECTORY) => {
            invocation.set_text(format_args!("is a directory"));
            ACCESS_DENIED
        }
        Err(nt::NOT_A_DIRECTORY) => {
            invocation.set_text(format_args!("not a directory"));
            ACCESS_DENIED
        }
        Err(status) => map(status, ACCESS_DENIED),
        Ok(handle) => {
            let result = invocation.backend.set_delete_disposition(handle, true);
            close_changed(invocation.backend, handle);
            match result {
                Ok(()) => Hresult::OK,
                Err(status) => map(status, ACCESS_DENIED),
            }
        }
    }
}

/// `dirlist name=<path>`: one line per directory entry.
fn dirlist(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return util::MISSING;
    };
    let Some(line) = invocation.backend.allocate_pool(LINE_BUFFER) else {
        return Hresult::OUT_OF_MEMORY;
    };
    let request = CreateRequest::open(
        FileAccess::LIST_DIRECTORY.union(FileAccess::SYNCHRONIZE),
        ShareAccess::READ_WRITE,
        DIRECTORY,
    );
    match open_path(invocation.state, invocation.backend, name, &request) {
        Err(status) => {
            invocation.backend.free_pool(line);
            map(status, ACCESS_DENIED)
        }
        Ok(handle) => {
            begin(
                invocation,
                Continuation::DirectoryList {
                    handle,
                    count: 0,
                    line,
                },
                None,
            );
            Hresult::MULTILINE
        }
    }
}

/// Names are not escaped and are cut at 0x1ff bytes, the line buffer
/// size less one.
fn directory_list_line(
    handle: FileHandle,
    count: &mut u32,
    line: PoolBuffer,
    cx: &mut ContinuationContext<'_>,
) -> Hresult {
    let mut name = [0u8; DIRECTORY_NAME_CAPACITY];
    let entry = match cx.backend.query_directory(handle, *count == 0, &mut name) {
        Ok(entry) => entry,
        Err(_) => {
            cx.backend.close_file(handle);
            cx.backend.free_pool(line);
            return Hresult::END_OF_DATA;
        }
    };
    *count += 1;
    let name = &name[..entry
        .name_length
        .min(DIRECTORY_NAME_CAPACITY)
        .min(LINE_BUFFER as usize - 1)];
    let pool = cx.backend.pool(line);
    let mut output = SliceWriter::new(&mut pool[..LINE_BUFFER as usize - 1]);
    output.push(b"name=\"");
    output.push(name);
    output.push(b"\" ");
    write_attributes(&mut output, &entry.information);
    let length = output.len;
    send_pool_line(&pool[..length], cx.binary, &mut cx.binary_len);
    Hresult::OK
}

/// Queue a line built in a pool line buffer as raw 202 output.
fn send_pool_line(text: &[u8], binary: &mut [u8], binary_len: &mut usize) {
    let mut output = SliceWriter::new(binary);
    output.push(text);
    output.push(b"\r\n");
    *binary_len = output.len;
}

/// `drivefreespace name=<path>`.
fn drive_free_space(invocation: &mut Invocation<'_>) -> Hresult {
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return util::MISSING;
    };
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let Some(line) = invocation.backend.allocate_pool(LINE_BUFFER) else {
        return Hresult::FAIL;
    };
    let request = CreateRequest::open(
        FileAccess::LIST_DIRECTORY.union(FileAccess::SYNCHRONIZE),
        ShareAccess::READ_WRITE,
        DIRECTORY,
    );
    // The image keeps the line buffer allocated when the open fails.
    match open_translated(invocation.state, invocation.backend, name, &request) {
        Err(status) => map(status, ACCESS_DENIED),
        Ok(handle) => {
            begin(
                invocation,
                Continuation::DriveFreeSpace {
                    handle,
                    first: true,
                    line,
                },
                None,
            );
            Hresult::MULTILINE
        }
    }
}

/// A failed query ends the transfer by closing the connection.
fn drive_free_space_line(
    handle: FileHandle,
    first: &mut bool,
    line: PoolBuffer,
    cx: &mut ContinuationContext<'_>,
) -> Hresult {
    if !core::mem::take(first) {
        cx.backend.close_file(handle);
        cx.backend.free_pool(line);
        return Hresult::END_OF_DATA;
    }
    let size = match cx.backend.query_volume_size(handle) {
        Ok(size) => size,
        Err(_) => {
            cx.backend.close_file(handle);
            cx.backend.free_pool(line);
            return Hresult::FAIL;
        }
    };
    let unit = u64::from(size.sectors_per_unit.wrapping_mul(size.bytes_per_sector));
    let total = size.total_units.wrapping_mul(unit);
    let free = size.available_units.wrapping_mul(unit);
    let pool = cx.backend.pool(line);
    let mut output = SliceWriter::new(&mut pool[..LINE_BUFFER as usize - 1]);
    let _ = write!(
        output,
        "freetocallerlo=0x{:08x} freetocallerhi=0x{:08x} totalbyteslo=0x{:08x} totalbyteshi=0x{:08x} totalfreebyteslo=0x{:08x} totalfreebyteshi=0x{:08x}",
        free as u32,
        (free >> 32) as u32,
        total as u32,
        (total >> 32) as u32,
        free as u32,
        (free >> 32) as u32,
    );
    let length = output.len;
    send_pool_line(&pool[..length], cx.binary, &mut cx.binary_len);
    Hresult::OK
}

/// `drivelist` progress: drive letters from `\??`, then the drive table.
#[derive(Debug)]
pub enum DriveList {
    Objects {
        directory: ObjectDirectory,
        context: u32,
    },
    Table {
        index: usize,
    },
}

/// `drivelist`.
fn drive_list(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    match invocation.backend.open_object_directory(DOS_DEVICES) {
        Err(status) => map(status, Hresult::FAIL),
        Ok(directory) => {
            begin(
                invocation,
                Continuation::DriveList(DriveList::Objects {
                    directory,
                    context: 0,
                }),
                None,
            );
            Hresult::MULTILINE
        }
    }
}

/// `_strnicmp(a, b, count) == 0` over NUL-terminated views.
fn prefix_equal(a: &[u8], b: &[u8], count: usize) -> bool {
    for index in 0..count {
        let left = a.get(index).copied().unwrap_or(0);
        let right = b.get(index).copied().unwrap_or(0);
        if !left.eq_ignore_ascii_case(&right) {
            return false;
        }
        if left == 0 {
            return true;
        }
    }
    true
}

fn drive_list_line(list: &mut DriveList, cx: &mut ContinuationContext<'_>) -> Hresult {
    if let DriveList::Objects { directory, context } = list {
        let directory = *directory;
        loop {
            let mut name = [0u8; OBJECT_NAME_CAPACITY];
            let restart = *context == 0;
            let length = match cx
                .backend
                .query_object_directory(directory, restart, context, &mut name)
            {
                Ok(length) => length.min(OBJECT_NAME_CAPACITY),
                Err(_) => {
                    cx.backend.close_object_directory(directory);
                    *list = DriveList::Table { index: 0 };
                    break;
                }
            };
            let name = &name[..length];
            let Some(colon) = name.iter().position(|&byte| byte == b':') else {
                continue;
            };
            if length < 2
                || cx
                    .state
                    .filesystem
                    .drives
                    .drives()
                    .any(|drive| prefix_equal(drive.name.as_bytes(), name, length - 1))
            {
                continue;
            }
            let opened = cx.backend.open_relative(
                directory,
                &name[..=colon],
                FileAccess::SYNCHRONIZE,
                ShareAccess::ALL,
                DIRECTORY,
            );
            if let Ok(handle) = opened {
                cx.backend.close_file(handle);
                cx.line.clear();
                let _ = cx.line.push_bytes(b"drivename=\"");
                let _ = cx.line.push_bytes(&name[..colon]);
                let _ = cx.line.push_bytes(b"\"");
                return Hresult::OK;
            }
        }
    }
    let DriveList::Table { index } = list else {
        return Hresult::END_OF_DATA;
    };
    loop {
        let Some(&drive) = cx.state.filesystem.drives.drives().nth(*index) else {
            return Hresult::END_OF_DATA;
        };
        let row = *index;
        *index += 1;
        if !drive.enabled {
            continue;
        }
        let mut path = [0u8; 0x24];
        let length = drive.name.as_bytes().len().min(path.len() - 2);
        path[..length].copy_from_slice(&drive.name.as_bytes()[..length]);
        path[length..length + 2].copy_from_slice(b":\\");
        let request = CreateRequest::open(FileAccess::SYNCHRONIZE, ShareAccess::ALL, DIRECTORY);
        match open_translated(cx.state, cx.backend, &path[..length + 2], &request) {
            Ok(handle) => {
                cx.backend.close_file(handle);
                let _ = cx.line.push_bytes(b"drivename=\"");
                let _ = cx.line.push_bytes(drive.name.as_bytes());
                let _ = cx.line.push_bytes(b"\"");
                return Hresult::OK;
            }
            Err(_) if drive.name == b"F" || drive.name == b"SMB" => {
                if let Some(entry) = cx.state.filesystem.drives.entries[row].as_mut() {
                    entry.enabled = false;
                }
            }
            Err(_) => {}
        }
    }
}

/// `fileeof name=<path> size=<dword> [mustcreate|cancreate]`.
fn file_eof(invocation: &mut Invocation<'_>) -> Hresult {
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return util::MISSING;
    };
    let Some(size) = util::required_dword(invocation, "size") else {
        return util::MISSING;
    };
    let disposition = if invocation.line.has("mustcreate") {
        CreateDisposition::Create
    } else if invocation.line.has("cancreate") {
        CreateDisposition::OverwriteIf
    } else {
        CreateDisposition::Open
    };
    let request = CreateRequest {
        access: FileAccess::GENERIC_WRITE
            .union(FileAccess::DELETE)
            .union(FileAccess::SYNCHRONIZE),
        allocation_size: Some(u64::from(size)),
        attributes: FileAttributes::NONE,
        share: ShareAccess::NONE,
        disposition,
        options: SYNCHRONOUS,
    };
    let handle = match open_path(invocation.state, invocation.backend, name, &request) {
        Ok(handle) => handle,
        Err(status) => return map(status, ACCESS_DENIED),
    };
    let result = invocation.backend.set_end_of_file(handle, u64::from(size));
    close_changed(invocation.backend, handle);
    match result {
        Ok(()) => Hresult::OK,
        Err(status) => map(status, ACCESS_DENIED),
    }
}

/// `getfile` transfer: a 4-byte little-endian length, then the data in
/// 0x3000-byte reads.
#[derive(Debug)]
pub struct GetFile {
    handle: FileHandle,
    buffer: PoolBuffer,
    length: u32,
    remaining: u32,
    header_sent: bool,
    chunk_sent: u32,
    chunk_length: u32,
}

/// `getfile name=<path> [offset=<dword> size=<dword>]`.
fn get_file(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return util::MISSING;
    };
    let offset_value = invocation.line.param("offset");
    let offset = offset_value.map_or(0, |value| value.dword_prefix());
    let mut size = 0;
    if offset_value.and_then(|value| value.dword()).is_some() {
        let Some(value) = util::required_dword(invocation, "size") else {
            return util::MISSING;
        };
        size = value;
    }
    let request = CreateRequest::open(
        FileAccess::GENERIC_READ.union(FileAccess::SYNCHRONIZE),
        ShareAccess::READ_WRITE,
        SYNCHRONOUS,
    );
    let handle = match open_path(invocation.state, invocation.backend, name, &request) {
        Ok(handle) => handle,
        Err(status) => return map(status, ACCESS_DENIED),
    };
    let backend = &mut *invocation.backend;
    let information = match backend.query_file_information(handle) {
        Ok(information) => information,
        Err(_) => {
            backend.close_file(handle);
            return Hresult::UNEXPECTED;
        }
    };
    if information.end_of_file >> 32 != 0 {
        backend.close_file(handle);
        invocation.set_text(format_args!("file is too big"));
        return Hresult::FAIL;
    }
    let end = information.end_of_file as u32;
    let mut length = if offset > end {
        0
    } else if offset == 0 {
        end
    } else {
        if let Err(status) = backend.set_file_position(handle, u64::from(offset)) {
            backend.close_file(handle);
            return map(status, ACCESS_DENIED);
        }
        end - offset
    };
    if size != 0 && size < length {
        length = size;
    }
    let Some(pool) = backend.allocate_pool(GETFILE_CHUNK) else {
        backend.close_file(handle);
        return Hresult::OUT_OF_MEMORY;
    };
    if offset != 0 || size != 0 {
        invocation.set_text(format_args!("partial send"));
    }
    let transfer = GetFile {
        handle,
        buffer: pool,
        length,
        remaining: length,
        header_sent: false,
        chunk_sent: 0,
        chunk_length: 0,
    };
    begin(invocation, Continuation::GetFile(transfer), None);
    Hresult::BINARY
}

/// A failed read sends zeros for its chunk.
fn get_file_data(transfer: &mut GetFile, cx: &mut ContinuationContext<'_>) -> Hresult {
    if cx.aborted {
        cx.backend.close_file(transfer.handle);
        cx.backend.free_pool(transfer.buffer);
        return Hresult::END_OF_DATA;
    }
    if !transfer.header_sent {
        transfer.header_sent = true;
        cx.binary[..4].copy_from_slice(&transfer.length.to_le_bytes());
        cx.binary_len = 4;
        return Hresult::OK;
    }
    if transfer.chunk_sent == transfer.chunk_length {
        if transfer.remaining == 0 {
            cx.backend.close_file(transfer.handle);
            cx.backend.free_pool(transfer.buffer);
            return Hresult::END_OF_DATA;
        }
        let count = transfer.remaining.min(GETFILE_CHUNK);
        let range = PoolRange {
            buffer: transfer.buffer,
            offset: 0,
            length: count,
        };
        if cx.backend.read_file(transfer.handle, None, range).is_err() {
            cx.backend.pool(transfer.buffer)[..count as usize].fill(0);
        }
        transfer.remaining -= count;
        transfer.chunk_length = count;
        transfer.chunk_sent = 0;
    }
    let start = transfer.chunk_sent as usize;
    let count = (transfer.chunk_length as usize - start).min(cx.binary.len());
    cx.binary[..count].copy_from_slice(&cx.backend.pool(transfer.buffer)[start..start + count]);
    transfer.chunk_sent += count as u32;
    cx.binary_len = count;
    Hresult::OK
}

/// `getfileattributes name=<path>`.
fn get_file_attributes(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return util::MISSING;
    };
    let result = if is_device_path(name) {
        invocation.backend.query_full_attributes(name)
    } else {
        let Some(path) = invocation
            .state
            .filesystem
            .drives
            .translate(invocation.backend, name)
        else {
            return Hresult::error(0);
        };
        invocation.backend.query_full_attributes(path.as_bytes())
    };
    match result {
        Err(status) => map(status, ACCESS_DENIED),
        Ok(information) => {
            begin(
                invocation,
                Continuation::FileAttributes(Some(information)),
                None,
            );
            Hresult::MULTILINE
        }
    }
}

/// `getvfattr` progress.
#[derive(Debug)]
pub struct VirtualAttributes {
    buffer: Option<PoolBuffer>,
    count: u32,
    index: u32,
    phase: VirtualAttributesPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VirtualAttributesPhase {
    Length,
    Name,
    Send { sent: u32 },
}

/// `getvfattr count=<dword>`, then `count` names, each a big-endian
/// length and the name bytes; replies with 0x1c-byte records.
fn get_vfattr(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(count) = util::required_dword(invocation, "count") else {
        return util::MISSING;
    };
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let size = count
        .wrapping_mul(VFATTR_RECORD)
        .wrapping_add(VFATTR_RECEIVE_AREA);
    let Some(buffer) = invocation.backend.allocate_pool(size) else {
        return Hresult::OUT_OF_MEMORY;
    };
    let transfer = VirtualAttributes {
        buffer: Some(buffer),
        count,
        index: 0,
        phase: VirtualAttributesPhase::Length,
    };
    begin(
        invocation,
        Continuation::VirtualAttributes(transfer),
        Some(4),
    );
    Hresult::SEND_BINARY
}

impl VirtualAttributes {
    fn release(&mut self, backend: &mut dyn crate::backend::Backend) {
        if let Some(buffer) = self.buffer.take() {
            backend.free_pool(buffer);
        }
    }

    fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> Hresult {
        if let VirtualAttributesPhase::Send { sent } = &mut self.phase {
            let Some(buffer) = self.buffer else {
                return Hresult::END_OF_DATA;
            };
            let total = self.count.wrapping_mul(VFATTR_RECORD);
            if cx.aborted || *sent >= total {
                self.release(cx.backend);
                return Hresult::END_OF_DATA;
            }
            let count = ((total - *sent) as usize).min(cx.binary.len());
            let start = (VFATTR_RECEIVE_AREA + *sent) as usize;
            cx.binary[..count].copy_from_slice(&cx.backend.pool(buffer)[start..start + count]);
            *sent += count as u32;
            cx.binary_len = count;
            return Hresult::OK;
        }

        let mut remaining = cx.session.receive_remaining.unwrap_or(0);
        if cx.received.is_empty() && remaining != 0 {
            self.release(cx.backend);
            return Hresult::FAIL;
        }
        let Some(buffer) = self.buffer else {
            return Hresult::OK;
        };
        if self.count == 0 {
            // The image frees the block on the first piece and keeps
            // receiving without ever completing.
            self.release(cx.backend);
            return Hresult::END_OF_DATA;
        }
        for piece in cx.received.chunks(VFATTR_RECEIVE_AREA as usize) {
            cx.backend.pool(buffer)[..piece.len()].copy_from_slice(piece);
        }
        remaining -= cx.received.len() as u32;
        cx.session.receive_remaining = Some(remaining);
        if remaining != 0 {
            return Hresult::OK;
        }
        match self.phase {
            VirtualAttributesPhase::Length => {
                let pool = cx.backend.pool(buffer);
                let length = u32::from_be_bytes([pool[0], pool[1], pool[2], pool[3]]);
                cx.session.receive_remaining = Some(length);
                self.phase = VirtualAttributesPhase::Name;
                if length == 0 {
                    self.release(cx.backend);
                }
                Hresult::OK
            }
            VirtualAttributesPhase::Name => {
                let mut name = [0u8; VFATTR_RECEIVE_AREA as usize];
                name.copy_from_slice(&cx.backend.pool(buffer)[..VFATTR_RECEIVE_AREA as usize]);
                let length = name
                    .iter()
                    .position(|&byte| byte == 0)
                    .unwrap_or(name.len());
                let name = &name[..length];
                let result = if is_device_path(name) {
                    cx.backend
                        .query_full_attributes(&name[..name.len().min(0x140)])
                } else {
                    match cx.state.filesystem.drives.translate(cx.backend, name) {
                        Some(path) => cx.backend.query_full_attributes(path.as_bytes()),
                        None => Err(nt::NO_SUCH_FILE),
                    }
                };
                let record: [u32; 7] = match result {
                    Ok(information) => [
                        information.creation_time.high(),
                        information.creation_time.low(),
                        information.last_write_time.high(),
                        information.last_write_time.low(),
                        (information.end_of_file >> 32) as u32,
                        information.end_of_file as u32,
                        information.attributes.0,
                    ],
                    Err(_) => [0, 0, 0, 0, 0, 0, u32::MAX],
                };
                let start = (VFATTR_RECEIVE_AREA + self.index * VFATTR_RECORD) as usize;
                let pool = cx.backend.pool(buffer);
                for (slot, value) in pool[start..start + VFATTR_RECORD as usize]
                    .as_chunks_mut::<4>()
                    .0
                    .iter_mut()
                    .zip(record)
                {
                    slot.copy_from_slice(&value.to_be_bytes());
                }
                self.index += 1;
                if self.index == self.count {
                    self.phase = VirtualAttributesPhase::Send { sent: 0 };
                    return Hresult::BINARY;
                }
                cx.session.receive_remaining = Some(4);
                self.phase = VirtualAttributesPhase::Length;
                Hresult::OK
            }
            VirtualAttributesPhase::Send { .. } => Hresult::OK,
        }
    }
}

/// `hdd enable|disable`: clear or set bit 0 of configuration setting
/// (2, 6).
fn hdd(invocation: &mut Invocation<'_>) -> Hresult {
    let value = if invocation.line.has("enable") {
        0
    } else if invocation.line.has("disable") {
        1
    } else {
        invocation.set_text(format_args!("missing arguments"));
        return Hresult::FAIL;
    };
    let mut bytes = [0u8; 4];
    if let Err(status) = invocation.backend.xconfig_get(HDD_SETTING, &mut bytes) {
        return map(status, Hresult::UNEXPECTED);
    }
    let flags = u32::from_be_bytes(bytes) & !1 | value;
    match invocation
        .backend
        .xconfig_set(HDD_SETTING, &flags.to_be_bytes())
    {
        Ok(()) => Hresult::OK,
        Err(status) => map(status, Hresult::UNEXPECTED),
    }
}

/// `mkdir name=<path>`.
fn make_directory(invocation: &mut Invocation<'_>) -> Hresult {
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return util::MISSING;
    };
    let request = CreateRequest {
        access: FileAccess::LIST_DIRECTORY.union(FileAccess::SYNCHRONIZE),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::NONE,
        disposition: CreateDisposition::Create,
        options: DIRECTORY,
    };
    match open_path(invocation.state, invocation.backend, name, &request) {
        Ok(handle) => {
            close_changed(invocation.backend, handle);
            Hresult::OK
        }
        Err(status) => map(status, CANNOT_CREATE),
    }
}

/// `prevflash [prevflashver=<dword>]`.
fn previous_flash(invocation: &mut Invocation<'_>) -> Hresult {
    let version = optional_dword(invocation, "PREVFLASHVER", 0);
    match invocation
        .backend
        .xconfig_set(PREVIOUS_FLASH_SETTING, &version.to_be_bytes())
    {
        Ok(()) => Hresult::OK,
        Err(status) => map(status, Hresult::UNEXPECTED),
    }
}

/// `rename name=<path> newname=<path>`.
fn rename(invocation: &mut Invocation<'_>) -> Hresult {
    let mut new_buffer = [0u8; NAME_BUFFER];
    let Some(new_name) = string_param(invocation, "newname", &mut new_buffer) else {
        invocation.set_text(format_args!("missing new name"));
        return Hresult::FAIL;
    };
    let Some(target) = invocation
        .state
        .filesystem
        .drives
        .translate(invocation.backend, new_name)
    else {
        invocation.set_text(format_args!("new name does not exist"));
        return Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND);
    };
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return util::MISSING;
    };
    let request = CreateRequest::open(
        FileAccess::GENERIC_WRITE.union(FileAccess::SYNCHRONIZE),
        ShareAccess::NONE,
        SYNCHRONOUS,
    );
    let Ok(handle) = open_translated(invocation.state, invocation.backend, name, &request) else {
        return ACCESS_DENIED;
    };
    let result = invocation
        .backend
        .rename_file(handle, target.as_bytes(), false);
    close_changed(invocation.backend, handle);
    match result {
        Ok(()) => Hresult::OK,
        Err(nt::NOT_SAME_DEVICE) => Hresult::from_error_code(ErrorCode::FILE_MUST_BE_COPIED),
        Err(status) => map(status, CANNOT_CREATE),
    }
}

/// `setfileattributes name=<path> [readonly=] [hidden=] [createhi= createlo=]
/// [changehi= changelo=]`.
fn set_file_attributes(invocation: &mut Invocation<'_>) -> Hresult {
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return util::MISSING;
    };
    let request = CreateRequest::open(
        FileAccess::SYNCHRONIZE,
        ShareAccess::READ_WRITE,
        SYNCHRONOUS,
    );
    let handle = match open_translated(invocation.state, invocation.backend, name, &request) {
        Ok(handle) => handle,
        Err(status) => return map(status, ACCESS_DENIED),
    };
    let line = invocation.line;
    let flag = |key: &str, bit: u32| {
        line.param(key)
            .and_then(|value| value.dword())
            .map(|value| if value != 0 { bit } else { 0 })
    };
    let readonly = flag("readonly", FileAttributes::READONLY.0);
    let hidden = flag("hidden", FileAttributes::HIDDEN.0);
    let mask = readonly.map_or(0, |_| FileAttributes::READONLY.0)
        | hidden.map_or(0, |_| FileAttributes::HIDDEN.0);
    let value = readonly.unwrap_or(0) | hidden.unwrap_or(0);
    let time = |high: &str, low: &str| {
        FileTime::from_parts(
            optional_dword(invocation, high, 0),
            optional_dword(invocation, low, 0),
        )
    };
    let creation_time = time("createhi", "createlo");
    let last_write_time = time("changehi", "changelo");
    let backend = &mut *invocation.backend;
    let result = backend
        .query_file_information(handle)
        .and_then(|information| {
            let mut attributes = information.attributes.0 & !mask | value & mask;
            if attributes == 0 {
                attributes = FileAttributes::NORMAL.0;
            }
            let basic = BasicInformation {
                creation_time,
                last_access_time: FileTime(0),
                last_write_time,
                change_time: FileTime(0),
                attributes: FileAttributes(attributes),
            };
            backend.set_basic_information(handle, &basic)
        });
    close_changed(invocation.backend, handle);
    match result {
        Ok(()) => Hresult::OK,
        Err(status) => map(status, Hresult::FAIL),
    }
}

/// Staging of uploaded file data into two 0x4000-byte halves, each
/// written when full or at the end of the upload (0x91f448d8).
#[derive(Debug)]
pub struct Writer {
    handle: Option<FileHandle>,
    buffer: PoolBuffer,
    staged: u32,
    half: u32,
    offset: u64,
    written: u32,
    failure: Option<NtStatus>,
    /// Failed writes mark the file for deletion, except in write-at mode.
    delete_on_failure: bool,
}

impl Writer {
    fn new(handle: FileHandle, buffer: PoolBuffer, offset: u64, delete_on_failure: bool) -> Self {
        Self {
            handle: Some(handle),
            buffer,
            staged: 0,
            half: 0,
            offset,
            written: 0,
            failure: None,
            delete_on_failure,
        }
    }

    /// Stage `data`, decrementing `remaining`; the last byte flushes.
    fn receive(
        &mut self,
        backend: &mut dyn crate::backend::Backend,
        mut data: &[u8],
        remaining: &mut u32,
    ) {
        if data.is_empty() && *remaining == 0 {
            self.flush(backend);
            return;
        }
        while !data.is_empty() {
            let count = ((UPLOAD_HALF - self.staged) as usize).min(data.len());
            let start = (self.half + self.staged) as usize;
            backend.pool(self.buffer)[start..start + count].copy_from_slice(&data[..count]);
            self.staged += count as u32;
            *remaining -= count as u32;
            data = &data[count..];
            if self.staged == UPLOAD_HALF || *remaining == 0 {
                self.flush(backend);
            }
        }
    }

    fn flush(&mut self, backend: &mut dyn crate::backend::Backend) {
        if let Some(handle) = self.handle {
            let range = PoolRange {
                buffer: self.buffer,
                offset: self.half,
                length: self.staged,
            };
            match backend.write_file(handle, Some(self.offset), FileData::Pool(range)) {
                Ok(()) => {
                    self.offset += u64::from(self.staged);
                    self.written = self.written.wrapping_add(self.staged);
                }
                Err(status) => {
                    if self.delete_on_failure {
                        let _ = backend.set_delete_disposition(handle, true);
                    }
                    close_changed(backend, handle);
                    self.handle = None;
                    self.failure = Some(status);
                }
            }
        }
        self.staged = 0;
        self.half ^= UPLOAD_HALF;
    }

    /// The upload ended before all bytes arrived: write what is staged.
    fn abandon(&mut self, backend: &mut dyn crate::backend::Backend) {
        if let (Some(handle), true) = (self.handle, self.delete_on_failure) {
            let _ = backend.set_delete_disposition(handle, true);
        }
        self.flush(backend);
        if let Some(handle) = self.handle.take() {
            close_changed(backend, handle);
        }
    }
}

/// `sendfile` or `writefile` upload.
#[derive(Debug)]
pub struct Upload {
    writer: Writer,
    write_at: bool,
}

impl Upload {
    fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> Hresult {
        let mut remaining = cx.session.receive_remaining.unwrap_or(0);
        if cx.received.is_empty() && remaining != 0 {
            cx.session.receive_remaining = Some(0);
            self.writer.abandon(cx.backend);
            cx.backend.free_pool(self.writer.buffer);
            return Hresult::UNEXPECTED;
        }
        self.writer.receive(cx.backend, cx.received, &mut remaining);
        cx.session.receive_remaining = Some(remaining);
        if remaining != 0 {
            return Hresult::OK;
        }
        if let Some(handle) = self.writer.handle.take() {
            close_changed(cx.backend, handle);
        }
        cx.backend.free_pool(self.writer.buffer);
        if self.write_at {
            let _ = write!(cx.line, "{} bytes written", self.writer.written);
        }
        if self.writer.failure.is_some() {
            Hresult::UNEXPECTED
        } else {
            Hresult::OK
        }
    }
}

/// `sendfile name=<path> length=<dword>`: create or replace a file.
fn send_file(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return util::MISSING;
    };
    let Some(length) = util::required_dword(invocation, "length") else {
        return util::MISSING;
    };
    let request = CreateRequest {
        access: FileAccess::GENERIC_WRITE
            .union(FileAccess::DELETE)
            .union(FileAccess::SYNCHRONIZE),
        allocation_size: Some(u64::from(length)),
        attributes: FileAttributes::NONE,
        share: ShareAccess::NONE,
        disposition: CreateDisposition::OverwriteIf,
        options: CreateOptions::NONE,
    };
    let handle = match open_path(invocation.state, invocation.backend, name, &request) {
        Ok(handle) => handle,
        Err(status) => return map(status, CANNOT_CREATE),
    };
    let backend = &mut *invocation.backend;
    let prepared = backend
        .set_end_of_file(handle, u64::from(length))
        .and_then(|()| backend.allocate_pool(2 * UPLOAD_HALF).ok_or(nt::NO_MEMORY));
    let pool = match prepared {
        Ok(pool) => pool,
        Err(status) => {
            let _ = backend.set_delete_disposition(handle, true);
            close_changed(backend, handle);
            return map(status, CANNOT_CREATE);
        }
    };
    let upload = Upload {
        writer: Writer::new(handle, pool, 0, true),
        write_at: false,
    };
    begin(invocation, Continuation::Upload(upload), Some(length));
    Hresult::SEND_BINARY
}

/// `writefile name=<path> offset=<dword> length=<dword>`: write into an
/// existing file.
fn write_file(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let mut buffer = [0u8; NAME_BUFFER];
    let Some(name) = name_param(invocation, &mut buffer) else {
        return util::MISSING;
    };
    let Some(offset) = util::required_dword(invocation, "offset") else {
        return util::MISSING;
    };
    let Some(length) = util::required_dword(invocation, "length") else {
        return util::MISSING;
    };
    let request = CreateRequest {
        access: FileAccess::GENERIC_READ
            .union(FileAccess::GENERIC_WRITE)
            .union(FileAccess::SYNCHRONIZE),
        allocation_size: Some(u64::from(length)),
        attributes: FileAttributes::NONE,
        share: ShareAccess::NONE,
        disposition: CreateDisposition::Open,
        options: CreateOptions::NONE,
    };
    let handle = match open_path(invocation.state, invocation.backend, name, &request) {
        Ok(handle) => handle,
        Err(status) => return map(status, ACCESS_DENIED),
    };
    let backend = &mut *invocation.backend;
    let prepared = backend
        .set_file_position(handle, u64::from(offset))
        .and_then(|()| backend.allocate_pool(2 * UPLOAD_HALF).ok_or(nt::NO_MEMORY));
    let pool = match prepared {
        Ok(pool) => pool,
        Err(status) => {
            close_changed(backend, handle);
            return map(status, ACCESS_DENIED);
        }
    };
    let upload = Upload {
        writer: Writer::new(handle, pool, u64::from(offset), false),
        write_at: true,
    };
    begin(invocation, Continuation::Upload(upload), Some(length));
    Hresult::SEND_BINARY
}

/// `sendvfile` progress.
#[derive(Debug)]
pub struct MultiUpload {
    buffer: Option<PoolBuffer>,
    total: u32,
    files_left: u32,
    staged: u32,
    header: VirtualFileHeader,
    phase: MultiUploadPhase,
}

/// Fields of one `sendvfile` header.
#[derive(Debug, Clone, Copy, Default)]
struct VirtualFileHeader {
    creation_time: FileTime,
    last_write_time: FileTime,
    size: u64,
    attributes: FileAttributes,
}

#[derive(Debug)]
enum MultiUploadPhase {
    Header,
    Name,
    /// The file could not be created; its data is discarded.
    Discard,
    Data(Writer),
    Send {
        sent: u32,
    },
}

/// `sendvfile count=<dword>`, then per file a 0x20-byte big-endian
/// header, the name, and the data; replies with one HRESULT per file.
fn send_vfile(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(count) = util::required_dword(invocation, "count") else {
        return util::MISSING;
    };
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let Some(buffer) = invocation
        .backend
        .allocate_pool(count.wrapping_add(0x2000).wrapping_mul(4))
    else {
        return Hresult::OUT_OF_MEMORY;
    };
    let results = VFILE_RESULTS as usize;
    invocation.backend.pool(buffer)[results..results + count as usize * 4].fill(0);
    let upload = MultiUpload {
        buffer: Some(buffer),
        total: count,
        files_left: count,
        staged: 0,
        header: VirtualFileHeader::default(),
        phase: MultiUploadPhase::Header,
    };
    begin(
        invocation,
        Continuation::MultiUpload(upload),
        Some(VFILE_HEADER),
    );
    Hresult::SEND_BINARY
}

impl MultiUpload {
    fn release(&mut self, backend: &mut dyn crate::backend::Backend) {
        self.abandon(backend);
        if let Some(buffer) = self.buffer.take() {
            backend.free_pool(buffer);
        }
    }

    fn abandon(&mut self, backend: &mut dyn crate::backend::Backend) {
        if let MultiUploadPhase::Data(writer) = &mut self.phase {
            writer.abandon(backend);
        }
    }

    fn set_result(&mut self, backend: &mut dyn crate::backend::Backend, result: Hresult) {
        let Some(buffer) = self.buffer else {
            return;
        };
        let start = (VFILE_RESULTS + (self.total - self.files_left) * 4) as usize;
        backend.pool(buffer)[start..start + 4].copy_from_slice(&result.0.to_be_bytes());
    }

    /// Stage header or name bytes after those already received.
    fn stage(
        &mut self,
        backend: &mut dyn crate::backend::Backend,
        buffer: PoolBuffer,
        data: &[u8],
    ) {
        let start = (self.staged as usize).min(UPLOAD_HALF as usize);
        let count = data.len().min(UPLOAD_HALF as usize - start);
        backend.pool(buffer)[start..start + count].copy_from_slice(&data[..count]);
        self.staged += data.len() as u32;
    }

    /// Set the times and attributes of a completed file and close it.
    fn complete(&mut self, backend: &mut dyn crate::backend::Backend, handle: FileHandle) {
        match backend.query_file_information(handle) {
            Ok(_) => {
                let basic = BasicInformation {
                    creation_time: self.header.creation_time,
                    last_access_time: FileTime(0),
                    last_write_time: self.header.last_write_time,
                    change_time: FileTime(0),
                    attributes: self.header.attributes,
                };
                let _ = backend.set_basic_information(handle, &basic);
            }
            Err(status) => self.set_result(backend, map(status, CANNOT_CREATE)),
        }
        close_changed(backend, handle);
    }

    /// Advance to the next file header, or to the reply after the last.
    fn next_file(&mut self, remaining: &mut u32) -> Hresult {
        self.files_left -= 1;
        self.staged = 0;
        if self.files_left == 0 {
            self.phase = MultiUploadPhase::Send { sent: 0 };
            return Hresult::BINARY;
        }
        self.phase = MultiUploadPhase::Header;
        *remaining = VFILE_HEADER;
        Hresult::OK
    }

    fn open(
        &mut self,
        cx: &mut ContinuationContext<'_>,
        buffer: PoolBuffer,
        remaining: &mut u32,
    ) -> Hresult {
        let mut name = [0u8; NAME_BUFFER];
        let staged = (self.staged as usize).min(UPLOAD_HALF as usize);
        let pool = cx.backend.pool(buffer);
        let length = pool[..staged]
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(staged)
            .min(NAME_BUFFER);
        name[..length].copy_from_slice(&pool[..length]);
        let request = CreateRequest {
            access: FileAccess::GENERIC_WRITE
                .union(FileAccess::DELETE)
                .union(FileAccess::SYNCHRONIZE),
            allocation_size: Some(self.header.size),
            attributes: FileAttributes::NONE,
            share: ShareAccess::NONE,
            disposition: CreateDisposition::OverwriteIf,
            options: CreateOptions::NONE,
        };
        let opened =
            open_path(cx.state, cx.backend, &name[..length], &request).and_then(|handle| match cx
                .backend
                .set_end_of_file(handle, self.header.size)
            {
                Ok(()) => Ok(handle),
                Err(status) => {
                    let _ = cx.backend.set_delete_disposition(handle, true);
                    close_changed(cx.backend, handle);
                    Err(status)
                }
            });
        self.staged = 0;
        *remaining = self.header.size as u32;
        match opened {
            Err(status) => {
                self.set_result(cx.backend, map(status, CANNOT_CREATE));
                self.phase = MultiUploadPhase::Discard;
                if *remaining == 0 {
                    return self.next_file(remaining);
                }
            }
            Ok(handle) if *remaining == 0 => {
                self.complete(cx.backend, handle);
                return self.next_file(remaining);
            }
            Ok(handle) => self.phase = MultiUploadPhase::Data(Writer::new(handle, buffer, 0, true)),
        }
        Hresult::OK
    }

    fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> Hresult {
        if let MultiUploadPhase::Send { sent } = &mut self.phase {
            let Some(buffer) = self.buffer else {
                return Hresult::END_OF_DATA;
            };
            let total = self.total * 4;
            if cx.aborted || *sent >= total {
                cx.backend.free_pool(buffer);
                self.buffer = None;
                return Hresult::END_OF_DATA;
            }
            let count = ((total - *sent) as usize).min(cx.binary.len());
            let start = (VFILE_RESULTS + *sent) as usize;
            cx.binary[..count].copy_from_slice(&cx.backend.pool(buffer)[start..start + count]);
            *sent += count as u32;
            cx.binary_len = count;
            return Hresult::OK;
        }

        let mut remaining = cx.session.receive_remaining.unwrap_or(0);
        if cx.received.is_empty() && remaining != 0 {
            // The image keeps the block allocated when the connection
            // drops.
            self.abandon(cx.backend);
            return Hresult::FAIL;
        }
        let Some(buffer) = self.buffer else {
            return Hresult::OK;
        };
        if self.total == 0 {
            // The image frees the block on the first piece and keeps
            // receiving without ever completing.
            self.release(cx.backend);
            return Hresult::END_OF_DATA;
        }
        let received = cx.received;
        let result = match &mut self.phase {
            MultiUploadPhase::Header => {
                self.stage(cx.backend, buffer, received);
                remaining -= received.len() as u32;
                if remaining != 0 {
                    Hresult::OK
                } else {
                    let pool = cx.backend.pool(buffer);
                    let dword = |offset: usize| {
                        u32::from_be_bytes([
                            pool[offset],
                            pool[offset + 1],
                            pool[offset + 2],
                            pool[offset + 3],
                        ])
                    };
                    let qword = |offset: usize| {
                        u64::from(dword(offset)) << 32 | u64::from(dword(offset + 4))
                    };
                    let header_length = dword(0);
                    self.header = VirtualFileHeader {
                        creation_time: FileTime(qword(4)),
                        last_write_time: FileTime(qword(0xc)),
                        size: qword(0x14),
                        attributes: FileAttributes(dword(0x1c)),
                    };
                    self.staged = 0;
                    remaining = header_length.wrapping_sub(VFILE_HEADER);
                    if remaining == 0 && self.header.size == 0 {
                        self.next_file(&mut remaining)
                    } else if remaining == 0 {
                        self.open(cx, buffer, &mut remaining)
                    } else {
                        self.phase = MultiUploadPhase::Name;
                        Hresult::OK
                    }
                }
            }
            MultiUploadPhase::Name => {
                self.stage(cx.backend, buffer, received);
                remaining -= received.len() as u32;
                if remaining != 0 {
                    Hresult::OK
                } else {
                    self.open(cx, buffer, &mut remaining)
                }
            }
            MultiUploadPhase::Discard => {
                remaining -= received.len() as u32;
                if remaining != 0 {
                    Hresult::OK
                } else {
                    self.next_file(&mut remaining)
                }
            }
            MultiUploadPhase::Data(writer) => {
                writer.receive(cx.backend, received, &mut remaining);
                if let Some(status) = writer.failure {
                    self.set_result(cx.backend, map(status, Hresult::UNEXPECTED));
                    self.phase = MultiUploadPhase::Discard;
                    if remaining != 0 {
                        Hresult::OK
                    } else {
                        self.next_file(&mut remaining)
                    }
                } else if remaining != 0 {
                    Hresult::OK
                } else {
                    let handle = writer.handle.take();
                    if let Some(handle) = handle {
                        self.complete(cx.backend, handle);
                    }
                    self.next_file(&mut remaining)
                }
            }
            MultiUploadPhase::Send { .. } => Hresult::OK,
        };
        cx.session.receive_remaining = Some(remaining);
        result
    }
}

/// A raw device read sent as one 203 body.
#[derive(Debug)]
pub struct BlockRead {
    buffer: PoolBuffer,
    length: u32,
    sent: u32,
}

impl BlockRead {
    fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> Hresult {
        if cx.aborted || self.sent >= self.length {
            cx.backend.free_pool(self.buffer);
            return Hresult::END_OF_DATA;
        }
        let count = ((self.length - self.sent) as usize).min(cx.binary.len());
        let start = self.sent as usize;
        cx.binary[..count].copy_from_slice(&cx.backend.pool(self.buffer)[start..start + count]);
        self.sent += count as u32;
        cx.binary_len = count;
        Hresult::OK
    }
}

/// Transfer length from the `count` parameter of the block commands. A
/// count that does not parse leaves the text `missing count` and uses its
/// parsed prefix as a byte length without the limit check.
fn block_length(invocation: &mut Invocation<'_>, limit: u32, sector: u32) -> Option<u32> {
    let value = invocation.line.param("count");
    match value.and_then(|value| value.dword()) {
        Some(count) if count > limit => {
            invocation.set_text(format_args!("Invalid block count: '{}'.", count as i32));
            None
        }
        Some(count) => Some(count * sector),
        None => {
            invocation.set_text(format_args!("missing count"));
            Some(value.map_or(0, |value| value.dword_prefix()))
        }
    }
}

fn read_blocks(
    invocation: &mut Invocation<'_>,
    device: &[u8],
    block: u32,
    length: u32,
    sector: u32,
) -> Hresult {
    let backend = &mut *invocation.backend;
    let Ok(object) = backend.reference_device(device) else {
        return Hresult::FAIL;
    };
    let Some(buffer) = backend.allocate_pool(length) else {
        backend.dereference_device(object);
        return Hresult::FAIL;
    };
    let range = PoolRange {
        buffer,
        offset: 0,
        length,
    };
    let offset = u64::from(block) * u64::from(sector);
    let result = backend.transfer_device(object, TransferDirection::Read, offset, range);
    backend.dereference_device(object);
    if result.is_err() {
        backend.free_pool(buffer);
        return Hresult::FAIL;
    }
    begin(
        invocation,
        Continuation::BlockRead(BlockRead {
            buffer,
            length,
            sent: 0,
        }),
        None,
    );
    Hresult::BINARY
}

/// `dvdblk block=<dword> count=<dword>`: read 2048-byte optical sectors.
fn dvd_block(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let Some(block) = util::required_dword(invocation, "block") else {
        return util::MISSING;
    };
    let Some(length) = block_length(invocation, DVD_MAX_BLOCKS, DVD_SECTOR) else {
        return Hresult::FAIL;
    };
    read_blocks(invocation, b"\\Device\\Cdrom0", block, length, DVD_SECTOR)
}

/// `gethddblk name=<device> block=<dword> count=<dword>`: read 512-byte
/// sectors of a named device.
fn get_hdd_block(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let mut buffer = [0u8; 0x100];
    let Some(name) = string_param(invocation, "name", &mut buffer) else {
        return Hresult::FAIL;
    };
    let Some(block) = util::required_dword(invocation, "block") else {
        return util::MISSING;
    };
    let Some(length) = block_length(invocation, HDD_MAX_BLOCKS, HDD_SECTOR) else {
        return Hresult::FAIL;
    };
    read_blocks(invocation, name, block, length, HDD_SECTOR)
}

/// `sethddblk` upload.
#[derive(Debug)]
pub struct BlockWrite {
    device: DeviceObject,
    buffer: PoolBuffer,
    block: u32,
    length: u32,
}

impl BlockWrite {
    fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> Hresult {
        let remaining = cx.session.receive_remaining.unwrap_or(0);
        if cx.received.is_empty() {
            cx.backend.free_pool(self.buffer);
            cx.backend.dereference_device(self.device);
            cx.session.receive_remaining = Some(0);
            return Hresult::FAIL;
        }
        let start = (self.length - remaining) as usize;
        let count = cx.received.len();
        cx.backend.pool(self.buffer)[start..start + count].copy_from_slice(cx.received);
        let remaining = remaining - count as u32;
        cx.session.receive_remaining = Some(remaining);
        if remaining != 0 {
            return Hresult::OK;
        }
        let range = PoolRange {
            buffer: self.buffer,
            offset: 0,
            length: self.length,
        };
        let offset = u64::from(self.block) * u64::from(HDD_SECTOR);
        let result =
            cx.backend
                .transfer_device(self.device, TransferDirection::Write, offset, range);
        cx.backend.dereference_device(self.device);
        cx.backend.free_pool(self.buffer);
        if result.is_ok() {
            Hresult::OK
        } else {
            Hresult::UNEXPECTED
        }
    }
}

/// `sethddblk name=<device> block=<dword> count=<dword>`, then the sector
/// data.
fn set_hdd_block(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let mut buffer = [0u8; 0x100];
    let Some(name) = string_param(invocation, "name", &mut buffer) else {
        return Hresult::FAIL;
    };
    let Some(block) = util::required_dword(invocation, "block") else {
        return util::MISSING;
    };
    let Some(length) = block_length(invocation, HDD_MAX_BLOCKS, HDD_SECTOR) else {
        return Hresult::FAIL;
    };
    let backend = &mut *invocation.backend;
    let Ok(device) = backend.reference_device(name) else {
        return Hresult::FAIL;
    };
    let Some(pool) = backend.allocate_pool(length) else {
        backend.dereference_device(device);
        return Hresult::FAIL;
    };
    begin(
        invocation,
        Continuation::BlockWrite(BlockWrite {
            device,
            buffer: pool,
            block,
            length,
        }),
        Some(length),
    );
    Hresult::SEND_BINARY
}

/// `dvdeject [eject=<dword>]`.
fn dvd_eject(invocation: &mut Invocation<'_>) -> Hresult {
    let value = optional_dword(invocation, "eject", 1);
    invocation.backend.open_close_tray(value);
    Hresult::OK
}

/// `dvdperf report`: one line per valid trace record.
#[derive(Debug)]
pub struct DvdReport {
    trace: DvdTrace,
    cursor: u32,
    base: u64,
}

/// `dvdperf start` | `dvdperf stop [report]`.
fn dvd_performance(invocation: &mut Invocation<'_>) -> Hresult {
    if !invocation.line.has("stop") {
        if !invocation.line.has("start") {
            return Hresult::FAIL;
        }
        invocation.backend.start_dvd_trace();
        return Hresult::OK;
    }
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let trace = invocation.backend.stop_dvd_trace();
    if !invocation.line.has("report") {
        if let Some(trace) = trace {
            invocation.backend.free_pool(trace.buffer);
        }
        return Hresult::OK;
    }
    let Some(trace) = trace else {
        invocation.set_text(format_args!("nothing to report"));
        return Hresult::FAIL;
    };
    let pool = invocation.backend.pool(trace.buffer);
    let mut base = [0u8; 8];
    base.copy_from_slice(&pool[..8]);
    let report = DvdReport {
        trace,
        cursor: 0,
        base: u64::from_be_bytes(base),
    };
    begin(invocation, Continuation::DvdReport(report), None);
    Hresult::MULTILINE
}

impl DvdReport {
    fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> Hresult {
        while self.cursor + DVD_TRACE_RECORD <= self.trace.length {
            let start = self.cursor as usize;
            let mut record = [0u8; DVD_TRACE_RECORD as usize];
            record.copy_from_slice(
                &cx.backend.pool(self.trace.buffer)[start..start + DVD_TRACE_RECORD as usize],
            );
            self.cursor += DVD_TRACE_RECORD;
            let mut time = [0u8; 8];
            time.copy_from_slice(&record[..8]);
            let word = u32::from_be_bytes([record[8], record[9], record[10], record[11]]);
            let elapsed = u32::from_be_bytes([record[12], record[13], record[14], record[15]]);
            if word & 1 == 0 {
                continue;
            }
            let timestamp = u64::from_be_bytes(time).wrapping_sub(self.base) / 1000;
            let _ = write!(
                cx.line,
                "timestamp={} time={} lba={} cblk={}",
                timestamp as u32,
                elapsed as i32,
                (word >> 1) & 0xff_ffff,
                word >> 25,
            );
            return Hresult::OK;
        }
        cx.backend.free_pool(self.trace.buffer);
        Hresult::END_OF_DATA
    }
}

/// `fmtfat partition=<1..5> [force=<dword>]`: format a hard disk
/// partition as XTAF.
fn format_fat(invocation: &mut Invocation<'_>) -> Hresult {
    let force_value = invocation.line.param("force");
    if force_value.and_then(|value| value.dword()).is_none() {
        invocation.set_text(format_args!("missing force"));
    }
    let force = force_value.map_or(0, |value| value.dword_prefix());
    if force == 0 && invocation.backend.execution_state() != ExecutionState::Pending {
        invocation.set_text(format_args!("not stopped"));
        return Hresult::from_error_code(ErrorCode::NOT_STOPPED);
    }
    let Some(partition) = util::required_dword(invocation, "partition") else {
        return util::MISSING;
    };
    if !(1..=5).contains(&partition) {
        return Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND);
    }
    let mut device = [0u8; 0x20];
    let mut output = SliceWriter::new(&mut device);
    let _ = write!(output, "\\Device\\Harddisk0\\Partition{partition}");
    let length = output.len;
    match invocation
        .backend
        .format_partition(&device[..length], FORMAT_CLUSTER_SIZE)
    {
        Ok(()) => Hresult::OK,
        Err(_) => {
            invocation.set_text(format_args!("unable to format"));
            ACCESS_DENIED
        }
    }
}

/// CRC-32/MPEG-2 table: polynomial 0x04c11db7, most significant bit first.
const CHECKSUM_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = (index as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 0x8000_0000 != 0 {
                (value << 1) ^ 0x04c1_1db7
            } else {
                value << 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
};

/// `getsum` progress.
#[derive(Debug)]
pub struct Checksum {
    address: u32,
    block_size: u32,
    remaining: u32,
}

/// `getsum ADDR=<dword> LENGTH=<dword> BLOCKSIZE=<dword>`: one CRC per
/// block of target memory, 0 for blocks touching an unreadable page.
fn get_sum(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(address) = util::required_dword(invocation, "ADDR") else {
        return util::MISSING;
    };
    let Some(length) = util::required_dword(invocation, "LENGTH") else {
        return util::MISSING;
    };
    let Some(block_size) = util::required_dword(invocation, "BLOCKSIZE") else {
        return util::MISSING;
    };
    if block_size == 0 {
        invocation.set_text(format_args!("Zero BLOCKSIZE not allowed."));
        return Hresult::from_error_code(ErrorCode::BAD_PARAMETER);
    }
    let remaining = (length / block_size).wrapping_mul(4);
    if !begin(
        invocation,
        Continuation::Checksum(Checksum {
            address,
            block_size,
            remaining,
        }),
        None,
    ) {
        return Hresult::FAIL;
    }
    Hresult::BINARY
}

impl Checksum {
    fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> Hresult {
        if cx.aborted || self.remaining == 0 {
            return Hresult::END_OF_DATA;
        }
        let count = self.remaining.min(GETSUM_CHUNK);
        for slot in cx.binary[..count as usize].as_chunks_mut::<4>().0 {
            let value = block_checksum(cx.backend, self.address, self.block_size);
            slot.copy_from_slice(&value.to_be_bytes());
            self.address = self.address.wrapping_add(self.block_size);
        }
        self.remaining -= count;
        cx.binary_len = count as usize;
        Hresult::OK
    }
}

fn block_checksum(backend: &mut dyn crate::backend::Backend, address: u32, size: u32) -> u32 {
    let last = address.wrapping_add(size - 1) & !(PAGE_SIZE - 1);
    let mut page = address & !(PAGE_SIZE - 1);
    loop {
        if !backend.is_readable(page) {
            return 0;
        }
        if page == last {
            break;
        }
        page = page.wrapping_add(PAGE_SIZE);
    }
    let mut crc = u32::MAX;
    let mut chunk = [0u8; 0x100];
    let mut offset = 0u32;
    while offset < size {
        let count = (size - offset).min(chunk.len() as u32) as usize;
        backend.read_memory(address.wrapping_add(offset), &mut chunk[..count]);
        for &byte in &chunk[..count] {
            crc = CHECKSUM_TABLE[((crc >> 24) ^ u32::from(byte)) as usize] ^ (crc << 8);
        }
        offset += count as u32;
    }
    crc
}

/// Reflected CRC-32 table (polynomial 0xedb88320) of the system update
/// upload check.
const UPDATE_CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ 0xedb8_8320
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
};

/// Continue a reflected CRC-32 without final inversion.
pub fn update_crc(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc = UPDATE_CRC_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

/// The HRESULT of a kernel status through its Win32 error code.
fn dos_hresult(backend: &mut dyn crate::backend::Backend, status: NtStatus) -> Hresult {
    let error = backend.dos_error(status);
    if error as i32 > 0 {
        Hresult(0x8007_0000 | (error & 0xffff))
    } else {
        Hresult(error)
    }
}

/// `sysfileupd` upload: data in [0, 0x4000), target name at 0x4000.
#[derive(Debug)]
pub struct SystemFileUpdate {
    buffer: PoolBuffer,
    handle: Option<FileHandle>,
    name_length: usize,
    time: FileTime,
    crc: u32,
    expected: u32,
    staged: u32,
}

/// Create each missing parent directory of `path` (0x91f64448).
fn create_parent_directories(backend: &mut dyn crate::backend::Backend, path: &[u8]) {
    let request = CreateRequest {
        access: FileAccess::LIST_DIRECTORY.union(FileAccess::SYNCHRONIZE),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::READ_WRITE,
        disposition: CreateDisposition::Create,
        options: CreateOptions::OPEN_FOR_BACKUP.union(DIRECTORY),
    };
    for index in 1..path.len() {
        if path[index] == b'\\'
            && let Ok(handle) = backend.create_file(&path[..index], &request)
        {
            backend.close_file(handle);
        }
    }
}

fn hresult_text(invocation_text: &mut crate::text::ResponseText, result: Hresult) {
    invocation_text.clear();
    let _ = write!(invocation_text, "HRESULT 0x{:x}", result.0);
}

/// `sysfileupd name=<object path>` with `query=<nonzero>`, `localsrc=`, or
/// an upload of `size` bytes checked against `crc`.
fn system_file_update(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.session.is_none() {
        return Hresult::FAIL;
    }
    let Some(buffer) = invocation.backend.allocate_pool(SYSFILE_BLOCK) else {
        hresult_text(invocation.text, Hresult::OUT_OF_MEMORY);
        return Hresult::OUT_OF_MEMORY;
    };
    let result = system_file_update_start(invocation, buffer);
    if !matches!(result, Ok(Hresult::SEND_BINARY)) {
        invocation.backend.free_pool(buffer);
    }
    match result {
        Ok(result) => result,
        Err(result) => {
            hresult_text(invocation.text, result);
            result
        }
    }
}

fn system_file_update_start(
    invocation: &mut Invocation<'_>,
    buffer: PoolBuffer,
) -> Result<Hresult, Hresult> {
    let mut name = [0u8; SYSFILE_NAME_BUFFER];
    let name = string_param(invocation, "name", &mut name).ok_or(Hresult::INVALID_ARGUMENT)?;
    if invocation
        .line
        .param("query")
        .and_then(|value| value.dword())
        .is_some_and(|value| value != 0)
    {
        let request = CreateRequest::open(
            FileAccess::GENERIC_READ.union(FileAccess::SYNCHRONIZE),
            ShareAccess::READ,
            CreateOptions::NON_DIRECTORY_FILE.union(CreateOptions::SYNCHRONOUS_IO_ALERT),
        );
        let backend = &mut *invocation.backend;
        let queried = backend.create_file(name, &request).and_then(|handle| {
            let information = backend.query_file_information(handle);
            backend.close_file(handle);
            information
        });
        let status = queried.err().unwrap_or(NtStatus::SUCCESS);
        let result = dos_hresult(backend, status);
        if result.is_failure() {
            return Err(result);
        }
        let information = queried.unwrap_or_default();
        invocation.set_text(format_args!(
            "0x{:x} 0x{:x}",
            information.end_of_file, information.last_write_time.0
        ));
        return Ok(Hresult::OK);
    }
    let time_high = util::required_dword(invocation, "ftimehi").ok_or(Hresult::INVALID_ARGUMENT)?;
    let time_low = util::required_dword(invocation, "ftimelo").ok_or(Hresult::INVALID_ARGUMENT)?;
    let time = FileTime::from_parts(time_high, time_low);
    let mut source = [0u8; SYSFILE_NAME_BUFFER];
    if let Some(source) = string_param(invocation, "localsrc", &mut source) {
        // The copy result does not reach the reply.
        copy_local_file(invocation.backend, source, name, time);
        return Ok(Hresult::OK);
    }
    let size = util::required_dword(invocation, "size").ok_or(Hresult::INVALID_ARGUMENT)?;
    let expected = util::required_dword(invocation, "crc").ok_or(Hresult::INVALID_ARGUMENT)?;
    invocation.text.clear();

    let mut temporary = [0u8; SYSFILE_NAME_BUFFER];
    let separator = name
        .iter()
        .rposition(|&byte| byte == b'\\')
        .ok_or(Hresult(0x8007_007b))?;
    if SYSFILE_NAME_BUFFER - 1 - separator < 0xe {
        return Err(Hresult(0x8007_007b));
    }
    temporary[..separator].copy_from_slice(&name[..separator]);
    let sequence = invocation.backend.update_sequence();
    let mut output = SliceWriter::new(&mut temporary[separator..]);
    let _ = write!(output, "\\temp{sequence:04x}.tmp");
    let length = separator + output.len;
    let temporary = &temporary[..length];

    let backend = &mut *invocation.backend;
    create_parent_directories(backend, temporary);
    let request = CreateRequest {
        access: FileAccess::GENERIC_WRITE
            .union(FileAccess::DELETE)
            .union(FileAccess::SYNCHRONIZE),
        allocation_size: Some(u64::from(size)),
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::ALL,
        disposition: CreateDisposition::Create,
        options: CreateOptions::OPEN_FOR_BACKUP.union(SYNCHRONOUS),
    };
    let handle = backend
        .create_file(temporary, &request)
        .map_err(|status| dos_hresult(backend, status))?;
    if let Err(status) = backend.set_end_of_file(handle, u64::from(size)) {
        let _ = backend.set_delete_disposition(handle, true);
        backend.close_file(handle);
        return Err(dos_hresult(backend, status));
    }
    let name_start = SYSFILE_DATA as usize;
    backend.pool(buffer)[name_start..name_start + name.len()].copy_from_slice(name);
    let update = SystemFileUpdate {
        buffer,
        handle: Some(handle),
        name_length: name.len(),
        time,
        crc: u32::MAX,
        expected,
        staged: 0,
    };
    begin(
        invocation,
        Continuation::SystemFileUpdate(update),
        Some(size),
    );
    Ok(Hresult::SEND_BINARY)
}

/// Copy `source` to `target` in 64 KiB pieces and set all four times to
/// `time` (0x91f64858).
fn copy_local_file(
    backend: &mut dyn crate::backend::Backend,
    source: &[u8],
    target: &[u8],
    time: FileTime,
) {
    create_parent_directories(backend, target);
    let Some(buffer) = backend.allocate_pool(0x1_0000) else {
        return;
    };
    let mut source_handle = None;
    let mut target_handle = None;
    let result = (|| {
        let read = CreateRequest::open(
            FileAccess::GENERIC_READ.union(FileAccess::SYNCHRONIZE),
            ShareAccess::READ,
            CreateOptions::NON_DIRECTORY_FILE.union(SYNCHRONOUS),
        );
        let input = *source_handle.insert(backend.create_file(source, &read)?);
        let information = backend.query_file_information(input)?;
        let write = CreateRequest {
            access: FileAccess::GENERIC_WRITE.union(FileAccess::SYNCHRONIZE),
            allocation_size: Some(information.end_of_file),
            attributes: FileAttributes::NORMAL,
            share: ShareAccess::NONE,
            disposition: CreateDisposition::OverwriteIf,
            options: CreateOptions::NON_DIRECTORY_FILE
                .union(SYNCHRONOUS)
                .union(CreateOptions(0x4)),
        };
        let output = *target_handle.insert(backend.create_file(target, &write)?);
        backend.set_end_of_file(output, information.end_of_file)?;
        let mut offset = 0u64;
        while offset < information.end_of_file {
            let range = PoolRange {
                buffer,
                offset: 0,
                length: 0x1_0000,
            };
            let count = backend.read_file(input, Some(offset), range)?;
            backend.write_file(
                output,
                Some(offset),
                FileData::Pool(PoolRange {
                    length: count,
                    ..range
                }),
            )?;
            if count == 0 {
                break;
            }
            offset += u64::from(count);
        }
        let basic = BasicInformation {
            creation_time: time,
            last_access_time: time,
            last_write_time: time,
            change_time: time,
            attributes: information.attributes,
        };
        let _ = backend.set_basic_information(output, &basic);
        Ok::<(), NtStatus>(())
    })();
    if let (Err(_), Some(output)) = (result, target_handle) {
        let _ = backend.set_delete_disposition(output, true);
    }
    backend.free_pool(buffer);
    if let Some(input) = source_handle {
        backend.close_file(input);
    }
    if let Some(output) = target_handle {
        backend.close_file(output);
    }
}

impl SystemFileUpdate {
    fn fail(&mut self, cx: &mut ContinuationContext<'_>, status: NtStatus) -> Hresult {
        if let Some(handle) = self.handle.take() {
            let _ = cx.backend.set_delete_disposition(handle, true);
            cx.backend.close_file(handle);
        }
        let result = dos_hresult(cx.backend, status);
        cx.line.clear();
        let _ = write!(cx.line, "HRESULT 0x{:x}", result.0);
        result
    }

    /// Replace the target with the uploaded temporary file (0x91f64340).
    fn finalize(
        &mut self,
        cx: &mut ContinuationContext<'_>,
        handle: FileHandle,
    ) -> Result<(), NtStatus> {
        let mut name = [0u8; SYSFILE_NAME_BUFFER];
        let start = SYSFILE_DATA as usize;
        name[..self.name_length]
            .copy_from_slice(&cx.backend.pool(self.buffer)[start..start + self.name_length]);
        let name = &name[..self.name_length];
        let request = CreateRequest::open(
            FileAccess::SYNCHRONIZE.union(FileAccess::WRITE_ATTRIBUTES),
            ShareAccess::ALL,
            CreateOptions::OPEN_FOR_BACKUP.union(SYNCHRONOUS),
        );
        if let Ok(existing) = cx.backend.create_file(name, &request) {
            let basic = BasicInformation {
                attributes: FileAttributes::NORMAL,
                ..BasicInformation::default()
            };
            let _ = cx.backend.set_basic_information(existing, &basic);
            cx.backend.close_file(existing);
        }
        let _ = cx.backend.rename_file(handle, name, true);
        let basic = BasicInformation {
            creation_time: self.time,
            last_access_time: self.time,
            last_write_time: self.time,
            change_time: self.time,
            attributes: FileAttributes::NORMAL,
        };
        cx.backend.set_basic_information(handle, &basic)
    }

    fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> Hresult {
        let remaining = cx.session.receive_remaining.unwrap_or(0);
        if cx.received.is_empty() && remaining != 0 {
            cx.backend.free_pool(self.buffer);
            // The image marks the temporary file for deletion but never
            // closes its handle, so the file stays until reboot.
            if let Some(handle) = self.handle {
                let _ = cx.backend.set_delete_disposition(handle, true);
            }
            cx.session.receive_remaining = Some(0);
            let _ = write!(cx.line, "HRESULT 0x{:x}", Hresult::UNEXPECTED.0);
            return Hresult::UNEXPECTED;
        }
        let mut data = cx.received;
        let mut remaining = remaining;
        let mut result = Hresult::OK;
        loop {
            let count = ((SYSFILE_DATA - self.staged) as usize).min(data.len());
            let start = self.staged as usize;
            cx.backend.pool(self.buffer)[start..start + count].copy_from_slice(&data[..count]);
            self.staged += count as u32;
            remaining -= count as u32;
            data = &data[count..];
            if remaining == 0 || self.staged == SYSFILE_DATA {
                result = self.flush(cx, remaining);
            }
            if data.is_empty() {
                break;
            }
        }
        cx.session.receive_remaining = Some(remaining);
        if remaining == 0 {
            cx.backend.free_pool(self.buffer);
        }
        result
    }

    fn flush(&mut self, cx: &mut ContinuationContext<'_>, remaining: u32) -> Hresult {
        let staged = self.staged;
        self.staged = 0;
        let pool = cx.backend.pool(self.buffer);
        self.crc = update_crc(self.crc, &pool[..staged as usize]);
        let range = PoolRange {
            buffer: self.buffer,
            offset: 0,
            length: staged,
        };
        // After a failure the image keeps writing through a null handle.
        let written = match self.handle {
            Some(handle) => cx.backend.write_file(handle, None, FileData::Pool(range)),
            None => Err(NtStatus(0xc000_0008)),
        };
        if let Err(status) = written {
            return self.fail(cx, status);
        }
        if remaining != 0 {
            return Hresult::OK;
        }
        if self.crc != self.expected {
            return self.fail(cx, nt::CRC_ERROR);
        }
        let Some(handle) = self.handle else {
            return Hresult::OK;
        };
        if let Err(status) = self.finalize(cx, handle) {
            return self.fail(cx, status);
        }
        self.handle = None;
        cx.backend.close_file(handle);
        Hresult::OK
    }
}

/// `dvdperf start` while a trace buffer is allocated, so tracing resumes
/// after a reboot.
pub(crate) fn dvdperf_settings_lines(
    _state: &ServerState,
    backend: &mut dyn crate::backend::Backend,
    file: crate::commands::system::SettingsFile,
) {
    if backend.dvd_trace_active() {
        crate::commands::system::write_line(backend, file, format_args!("dvdperf start"));
    }
}
