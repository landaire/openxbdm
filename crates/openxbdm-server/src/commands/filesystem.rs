//! File, drive, and storage commands.
// The pool and device tokens of `Backend` are released by unsafe methods.
#![allow(unsafe_code)]

mod attributes;
mod block;
mod checksum;
mod configuration;
mod directory;
mod download;
mod drive;
mod dvd;
mod error;
mod sysfile;
mod upload;
mod volume;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
#[cfg(feature = "smb")]
use xbox360_sys::xboxkrnl::FileSystemAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use self::attributes::file_eof;
use self::attributes::get_file_attributes;
use self::attributes::get_vfattr;
use self::attributes::set_file_attributes;
use self::block::dvd_block;
use self::block::format_fat;
use self::block::get_hdd_block;
use self::block::set_hdd_block;
use self::checksum::get_sum;
use self::configuration::hdd;
use self::configuration::previous_flash;
use self::directory::delete;
use self::directory::directory_list_line;
use self::directory::dirlist;
use self::directory::make_directory;
use self::directory::rename;
use self::download::get_file;
use self::dvd::dvd_eject;
use self::dvd::dvd_performance;
use self::sysfile::system_file_update;
use self::upload::send_file;
use self::upload::send_vfile;
use self::upload::write_file;
use self::volume::drive_free_space;
use self::volume::drive_free_space_line;
use self::volume::drive_list;
use self::volume::drive_list_line;
use crate::access::Access;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

pub use self::attributes::VirtualAttributes;
pub use self::block::BlockRead;
pub use self::block::BlockWrite;
pub use self::checksum::Checksum;
pub use self::download::GetFile;
#[cfg(feature = "smb")]
pub(crate) use self::drive::BADPATH;
pub use self::drive::Drive;
pub use self::drive::DriveName;
pub use self::drive::DriveTable;
pub use self::drive::DriveTarget;
pub use self::drive::OBJECT_PATH_LIMIT;
pub use self::drive::ObjectPath;
#[cfg(feature = "smb")]
pub(crate) use self::drive::internal_drives;
pub use self::drive::map_title_drive;
pub use self::drive::open_path;
pub use self::drive::open_translated;
pub use self::dvd::DvdReport;
pub(crate) use self::dvd::dvdperf_settings_lines;
pub use self::sysfile::SystemFileUpdate;
pub use self::sysfile::update_crc;
pub use self::upload::MultiUpload;
pub use self::upload::Upload;
pub use self::upload::Writer;
pub use self::volume::DriveList;

/// Most file name parameters are copied into 0x141-byte buffers.
const NAME_BUFFER: usize = 0x141;

/// `dirlist` and `drivefreespace` build each line in a pool buffer of this
/// size.
const LINE_BUFFER: u32 = 0x200;

/// Bytes of a file system name the backend reports.
#[cfg(feature = "smb")]
pub const FILE_SYSTEM_NAME_CAPACITY: usize = 16;

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry(
        "delete",
        Access::empty(),
        Access::READ.union(Access::WRITE),
        delete,
    ),
    entry("dirlist", Access::READ, Access::empty(), dirlist),
    entry(
        "drivefreespace",
        Access::READ,
        Access::empty(),
        drive_free_space,
    ),
    entry("drivelist", Access::READ, Access::empty(), drive_list),
    entry("dvdblk", Access::READ, Access::empty(), dvd_block),
    entry("dvdeject", Access::READ, Access::empty(), dvd_eject),
    entry("dvdperf", Access::CONTROL, Access::empty(), dvd_performance),
    entry(
        "fileeof",
        Access::empty(),
        Access::READ.union(Access::WRITE),
        file_eof,
    ),
    entry("fmtfat", Access::CONFIG, Access::empty(), format_fat),
    entry("getfile", Access::READ, Access::empty(), get_file),
    entry(
        "getfileattributes",
        Access::READ.union(Access::WRITE),
        Access::empty(),
        get_file_attributes,
    ),
    entry("gethddblk", Access::READ, Access::empty(), get_hdd_block),
    entry("getsum", Access::CONTROL, Access::empty(), get_sum),
    entry(
        "getvfattr",
        Access::READ.union(Access::WRITE),
        Access::empty(),
        get_vfattr,
    ),
    entry("hdd", Access::CONTROL, Access::empty(), hdd),
    entry("mkdir", Access::WRITE, Access::empty(), make_directory),
    entry(
        "prevflash",
        Access::CONTROL,
        Access::empty(),
        previous_flash,
    ),
    entry(
        "rename",
        Access::empty(),
        Access::READ.union(Access::WRITE),
        rename,
    ),
    entry("sendfile", Access::WRITE, Access::empty(), send_file),
    entry("sendvfile", Access::WRITE, Access::empty(), send_vfile),
    entry(
        "setfileattributes",
        Access::WRITE,
        Access::empty(),
        set_file_attributes,
    ),
    entry("sethddblk", Access::WRITE, Access::empty(), set_hdd_block),
    entry(
        "sysfileupd",
        Access::CONFIG,
        Access::empty(),
        system_file_update,
    ),
    entry("writefile", Access::WRITE, Access::empty(), write_file),
];

const ACCESS_DENIED: CommandError = CommandError::Status(ErrorCode::AccessDenied);

const CANNOT_CREATE: CommandError = CommandError::Status(ErrorCode::FileCannotBeCreated);

const SYNCHRONOUS: CreateOptions = CreateOptions::SYNCHRONOUS_IO_NONALERT;

const DIRECTORY: CreateOptions = CreateOptions::DIRECTORY_FILE.union(SYNCHRONOUS);

/// Opened file or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHandle(pub u32);

/// Opened object directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectDirectory(pub u32);

/// A device object the backend referenced, until it is passed to
/// [`Backend::dereference_device`]. Only the backend makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceObject(u32);

impl DeviceObject {
    /// # Safety
    ///
    /// `value` names a device object that the backend's
    /// [`Backend::transfer_device`] and [`Backend::dereference_device`]
    /// accept, with a reference held until it is dereferenced.
    pub const unsafe fn from_raw(value: u32) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Block of platform memory allocated for a transfer, until it is passed
/// to [`Backend::free_pool`]. Only the backend makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolBuffer(u32);

impl PoolBuffer {
    /// # Safety
    ///
    /// `value` names a block that the backend's [`Backend::pool`] and
    /// [`Backend::free_pool`] accept, which stays allocated until it is
    /// freed.
    pub const unsafe fn from_raw(value: u32) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Pool memory the server holds directly, without a borrow of the backend,
/// until it is passed to [`Backend::free_scratch`].
#[derive(Debug)]
pub struct ScratchBlock(&'static mut [u8]);

impl ScratchBlock {
    /// # Safety
    ///
    /// `block` is memory that the backend's [`Backend::free_scratch`]
    /// accepts, and nothing else refers to it.
    pub unsafe fn from_raw(block: &'static mut [u8]) -> Self {
        Self(block)
    }

    /// The memory, which is not freed through this token again.
    pub fn into_raw(self) -> &'static mut [u8] {
        self.0
    }
}

impl core::ops::Deref for ScratchBlock {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0
    }
}

impl core::ops::DerefMut for ScratchBlock {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

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

/// Destination of a file read.
#[derive(Debug)]
pub enum ReadTarget<'a> {
    Bytes(&'a mut [u8]),
    Pool(PoolRange),
}

impl ReadTarget<'_> {
    pub fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Pool(range) => range.length as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    pub access: AccessMask,
    pub allocation_size: Option<u64>,
    pub attributes: FileAttributes,
    pub share: ShareAccess,
    pub disposition: CreateDisposition,
    pub options: CreateOptions,
}

impl CreateRequest {
    /// Open an existing file without an allocation size or attributes.
    pub const fn open(access: AccessMask, share: ShareAccess, options: CreateOptions) -> Self {
        Self {
            access,
            allocation_size: None,
            attributes: FileAttributes::empty(),
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

/// Name and capabilities of the file system of a volume
/// (FileFsAttributeInformation).
#[cfg(feature = "smb")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeAttributes {
    pub flags: FileSystemAttributes,
    /// Longest file name component, in characters.
    pub maximum_component_length: u32,
    /// The file system name in ASCII, such as `FATX`.
    pub name: [u8; FILE_SYSTEM_NAME_CAPACITY],
    pub name_length: usize,
}

#[cfg(feature = "smb")]
impl VolumeAttributes {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_length.min(FILE_SYSTEM_NAME_CAPACITY)]
    }
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
    fn create_file(
        &mut self,
        path: &[u8],
        request: &CreateRequest,
    ) -> Result<FileHandle, KernelError>;
    /// Open `name` relative to an object directory.
    fn open_relative(
        &mut self,
        root: ObjectDirectory,
        name: &[u8],
        access: AccessMask,
        share: ShareAccess,
        options: CreateOptions,
    ) -> Result<FileHandle, KernelError>;
    fn close_file(&mut self, handle: FileHandle);
    /// Count the close of a file a command may have changed (0x91f9feec,
    /// read by export 85).
    fn count_file_change(&mut self);
    /// Read up to `target.len()` bytes at `offset`, or at the current
    /// position when `None`; returns the bytes read.
    fn read_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        target: ReadTarget<'_>,
    ) -> Result<u32, KernelError>;
    /// Write at `offset`, or at the current position when `None`.
    fn write_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        data: FileData<'_>,
    ) -> Result<(), KernelError>;
    fn set_delete_disposition(
        &mut self,
        handle: FileHandle,
        delete: bool,
    ) -> Result<(), KernelError>;
    fn set_end_of_file(&mut self, handle: FileHandle, size: u64) -> Result<(), KernelError>;
    fn set_file_position(&mut self, handle: FileHandle, position: u64) -> Result<(), KernelError>;
    fn set_basic_information(
        &mut self,
        handle: FileHandle,
        information: &BasicInformation,
    ) -> Result<(), KernelError>;
    fn rename_file(
        &mut self,
        handle: FileHandle,
        target: &[u8],
        replace: bool,
    ) -> Result<(), KernelError>;
    fn query_file_information(
        &mut self,
        handle: FileHandle,
    ) -> Result<FileInformation, KernelError>;
    fn query_full_attributes(&mut self, path: &[u8]) -> Result<FileInformation, KernelError>;
    /// Next entry of a directory; the name goes into `name`. A name longer
    /// than `name` fails with [`KernelError::BufferOverflow`].
    fn query_directory(
        &mut self,
        handle: FileHandle,
        restart: bool,
        name: &mut [u8],
    ) -> Result<DirectoryEntry, KernelError>;
    fn query_volume_size(&mut self, handle: FileHandle) -> Result<VolumeSize, KernelError>;
    /// File system name and attributes of the volume holding the file.
    #[cfg(feature = "smb")]
    fn query_volume_attributes(
        &mut self,
        handle: FileHandle,
    ) -> Result<VolumeAttributes, KernelError>;
    /// Resolve the symbolic link object `link` into `target`; returns the
    /// target length.
    fn translate_symbolic_link(
        &mut self,
        link: &[u8],
        target: &mut [u8],
    ) -> Result<usize, KernelError>;
    fn open_object_directory(&mut self, path: &[u8]) -> Result<ObjectDirectory, KernelError>;
    /// Next object name of a directory; `context` carries the position.
    fn query_object_directory(
        &mut self,
        directory: ObjectDirectory,
        restart: bool,
        context: &mut u32,
        name: &mut [u8],
    ) -> Result<usize, KernelError>;
    fn close_object_directory(&mut self, directory: ObjectDirectory);
    fn reference_device(&mut self, name: &[u8]) -> Result<DeviceObject, KernelError>;
    /// # Safety
    ///
    /// No copy of `device` is used afterwards.
    unsafe fn dereference_device(&mut self, device: DeviceObject);
    /// Synchronous transfer of `buffer.length` bytes at byte `offset`.
    fn transfer_device(
        &mut self,
        device: DeviceObject,
        direction: TransferDirection,
        offset: u64,
        buffer: PoolRange,
    ) -> Result<(), KernelError>;
    fn allocate_pool(&mut self, size: u32) -> Option<PoolBuffer>;
    /// # Safety
    ///
    /// No copy of `buffer` is used afterwards.
    unsafe fn free_pool(&mut self, buffer: PoolBuffer);
    fn pool(&mut self, buffer: PoolBuffer) -> &mut [u8];
    fn allocate_scratch(&mut self, size: u32) -> Option<ScratchBlock>;
    fn free_scratch(&mut self, block: ScratchBlock);
    /// Open (nonzero) or close (zero) the optical drive tray.
    fn open_close_tray(&mut self, value: u32);
    /// Format a block device as XTAF.
    fn format_partition(&mut self, device: &[u8], cluster_size: u32) -> Result<(), KernelError>;
    /// The kernel update sequence number used in system update file names.
    fn update_sequence(&mut self) -> u16;
    /// The Win32 error code of a failed kernel call; `None` for
    /// `ERROR_SUCCESS`.
    fn dos_error(&mut self, error: KernelError) -> Option<Win32Error>;
    /// Allocate a fresh optical drive trace buffer and enable tracing.
    /// Allocation failure leaves tracing off.
    fn start_dvd_trace(&mut self);
    /// Disable tracing and take the trace buffer.
    fn stop_dvd_trace(&mut self) -> Option<DvdTrace>;
    /// Whether a trace buffer is allocated.
    fn dvd_trace_active(&mut self) -> bool;
}

/// Global state of this domain.
#[derive(Debug)]
pub struct State {
    pub drives: DriveTable,
}

impl State {
    pub const fn new() -> Self {
        Self {
            drives: DriveTable::new(),
        }
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

    /// `label` then `value` in lowercase hex of at least `width` digits,
    /// as `{:0width$x}` writes it.
    #[inline(never)]
    fn push_hex(&mut self, label: &[u8], value: u32, width: u32) {
        self.push(label);

        let mut digits = [0u8; 8];
        for (index, digit) in digits.iter_mut().enumerate() {
            *digit = b"0123456789abcdef"[(value >> (28 - 4 * index)) as usize & 0xf];
        }

        let skip = (value.leading_zeros() / 4).min(8 - width);
        self.push(&digits[skip as usize..]);
    }
}

/// Close a file a command may have changed and count the change.
fn close_changed(backend: &mut dyn crate::backend::Backend, handle: FileHandle) {
    backend.close_file(handle);
    backend.count_file_change();
}

/// The size, time, and attribute fields shared by `dirlist` and
/// `getfileattributes` (0x91f45c90).
#[inline(never)]
fn write_attributes(output: &mut SliceWriter<'_>, information: &FileInformation) {
    let attributes = information.attributes;
    output.push_hex(b"sizehi=0x", (information.end_of_file >> 32) as u32, 1);
    output.push_hex(b" sizelo=0x", information.end_of_file as u32, 1);
    output.push_hex(b" createhi=0x", information.creation_time.high(), 8);
    output.push_hex(b" createlo=0x", information.creation_time.low(), 8);
    output.push_hex(b" changehi=0x", information.last_write_time.high(), 8);
    output.push_hex(b" changelo=0x", information.last_write_time.low(), 8);

    for (bit, text) in [
        (FileAttributes::DIRECTORY, &b" directory"[..]),
        (FileAttributes::READONLY, b" readonly"),
        (FileAttributes::HIDDEN, b" hidden"),
    ] {
        if attributes.contains(bit) {
            output.push(text);
        }
    }
}

const fn entry(
    name: &'static str,
    any_of: Access,
    all_of: Access,
    handler: crate::registry::Handler,
) -> CommandEntry {
    CommandEntry::new(name, any_of, all_of, DispatchFlags::empty(), handler)
}

pub(crate) fn resume(
    continuation: &mut Continuation,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
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
        Continuation::GetFile(transfer) => transfer.resume(cx),
        Continuation::FileAttributes(information) => match information.take() {
            Some(information) => {
                let mut text = [0u8; crate::text::LINE_TEXT_CAPACITY];
                let mut output = SliceWriter::new(&mut text);
                write_attributes(&mut output, &information);
                let length = output.len;
                let _ = cx.line.push_bytes(&text[..length]);

                Ok(Reply::Ok)
            }
            None => Err(CommandError::EndOfData),
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

/// Queue a line built in a pool line buffer as raw 202 output.
fn send_pool_line(text: &[u8], binary: &mut [u8], binary_len: &mut usize) {
    let mut output = SliceWriter::new(binary);
    output.push(text);
    output.push(b"\r\n");
    *binary_len = output.len;
}

/// Queue the next piece of the `total` bytes at `offset` in `buffer` as
/// binary output, advancing `sent`.
#[inline(never)]
fn send_pool_piece(
    cx: &mut ContinuationContext<'_>,
    buffer: PoolBuffer,
    offset: u32,
    total: u32,
    sent: &mut u32,
) -> CommandResult {
    let count = ((total - *sent) as usize).min(cx.binary.len());
    let start = (offset + *sent) as usize;
    cx.binary[..count].copy_from_slice(&cx.backend.pool(buffer)[start..start + count]);
    *sent += count as u32;
    cx.binary_len = count;

    Ok(Reply::Ok)
}
