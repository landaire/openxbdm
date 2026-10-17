//! File system, object namespace, and block device services.

use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands;
use openxbdm_server::commands::filesystem::BasicInformation;
use openxbdm_server::commands::filesystem::CreateOptions;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::DeviceObject;
use openxbdm_server::commands::filesystem::DirectoryEntry;
use openxbdm_server::commands::filesystem::DvdTrace;
use openxbdm_server::commands::filesystem::FileAccess;
use openxbdm_server::commands::filesystem::FileAttributes;
use openxbdm_server::commands::filesystem::FileData;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::filesystem::FileInformation;
use openxbdm_server::commands::filesystem::FileTime;
use openxbdm_server::commands::filesystem::ObjectDirectory;
use openxbdm_server::commands::filesystem::PoolBuffer;
use openxbdm_server::commands::filesystem::PoolRange;
use openxbdm_server::commands::filesystem::ReadTarget;
use openxbdm_server::commands::filesystem::ShareAccess;
use openxbdm_server::commands::filesystem::TransferDirection;
use openxbdm_server::commands::filesystem::VolumeSize;
use xbox360::module::SystemModule;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::DebugMonitorFlags;
use xbox360_sys::xboxkrnl::FileDeviceType;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::FsInformationClass;
use xbox360_sys::xboxkrnl::HalOpenCloseODDTray;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoControlCode;
use xbox360_sys::xboxkrnl::IoDeviceObjectType;
use xbox360_sys::xboxkrnl::IoDismountVolumeByFileHandle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::IoSynchronousFsdRequest;
use xbox360_sys::xboxkrnl::IrpMajorFunction;
use xbox360_sys::xboxkrnl::NtOpenDirectoryObject;
use xbox360_sys::xboxkrnl::NtQueryDirectoryFile;
use xbox360_sys::xboxkrnl::NtQueryVolumeInformationFile;
use xbox360_sys::xboxkrnl::ObCreateSymbolicLink;
use xbox360_sys::xboxkrnl::ObTranslateSymbolicLink;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ProcessorMode;

use super::Console;
use crate::exports::export;
use crate::kernel;

const STATUS_PENDING: u32 = 0x103;
const POOL_TAG: PoolTag = PoolTag::new(*b"xdbm");
/// Pool blocks carry their size in a header of this many bytes.
const POOL_HEADER: u32 = 8;
/// Directory query buffer of the image.
const DIRECTORY_BUFFER: usize = 0x190;
const DIRECTORY_NAME_OFFSET: usize = 0x40;
/// Object directory query buffer of the image.
const OBJECT_DIRECTORY_BUFFER: usize = 0x10c;
/// Size of the optical drive trace buffer.
const DVD_TRACE_SIZE: u32 = 0x20_0000;
/// Longest object name passed to the kernel.
const PATH_CAPACITY: usize = 0x200;

/// FileFsAttributeInformation fields. The kernel's file information
/// structures carry names as single bytes, as FileDirectoryInformation
/// does. `None` when the name is longer than the capacity or holds a byte
/// outside printable ASCII.
#[cfg(feature = "smb")]
fn volume_attributes(
    flags: u32,
    maximum_component_length: u32,
    name: &[u8],
) -> Option<commands::filesystem::VolumeAttributes> {
    if name.len() > commands::filesystem::FILE_SYSTEM_NAME_CAPACITY
        || !name.iter().all(u8::is_ascii_graphic)
    {
        return None;
    }
    let mut output = [0u8; commands::filesystem::FILE_SYSTEM_NAME_CAPACITY];
    output[..name.len()].copy_from_slice(name);
    Some(commands::filesystem::VolumeAttributes {
        flags: commands::filesystem::FileSystemFlags(flags),
        maximum_component_length,
        name: output,
        name_length: name.len(),
    })
}

/// Platform state of this domain.
pub struct Data {
    /// The optical drive trace buffer while tracing.
    dvd_trace: Option<PoolBuffer>,
}

impl Data {
    pub const fn new() -> Self {
        Self { dvd_trace: None }
    }
}

fn status(raw: u32) -> Result<(), KernelError> {
    NtStatus(raw).result()
}

/// `RtlNtStatusToDosError` of a failed kernel call.
fn dos_error(error: KernelError) -> Option<Win32Error> {
    xboxkrnl::RtlNtStatusToDosError(NtStatus::from(error)).error()
}

/// A counted name; the kernel copies it, so the bytes only live for the
/// call.
fn ansi(bytes: &[u8]) -> AnsiString {
    kernel::ansi_string(&bytes[..bytes.len().min(PATH_CAPACITY)])
}

fn attributes(root: u32, name: &AnsiString) -> ObjectAttributes {
    ObjectAttributes {
        root_directory: Handle::from_raw(root),
        object_name: name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    }
}

/// Wait for an asynchronous operation started on `handle`.
fn complete(handle: u32, raw: u32, io_status: &IoStatusBlock) -> u32 {
    if raw != STATUS_PENDING {
        return raw;
    }
    // SAFETY: `handle` is the open file the pending request was issued on.
    unsafe {
        xboxkrnl::NtWaitForSingleObjectEx(
            Handle::from_raw(handle),
            ProcessorMode::Kernel,
            false,
            core::ptr::null(),
        )
    };
    // SAFETY: the kernel completed the request and wrote the status block.
    unsafe { core::ptr::read_volatile(&io_status.status) }.0
}

/// Create or open a file by object name.
pub(crate) fn create_file(path: &[u8], request: &CreateRequest) -> Result<FileHandle, KernelError> {
    let name = ansi(path);
    let object = attributes(0, &name);
    let mut io_status = IoStatusBlock::default();
    let mut handle = 0u32;
    let allocation = request.allocation_size;
    let allocation_pointer = allocation
        .as_ref()
        .map_or(core::ptr::null(), |size| size as *const u64);
    // SAFETY: every pointer refers to a live local; `name` outlives the call.
    let raw = unsafe {
        xboxkrnl::NtCreateFile(
            (&raw mut handle).cast(),
            xboxkrnl::AccessMask::from_bits_retain(request.access.0),
            &object,
            &mut io_status,
            allocation_pointer,
            xboxkrnl::FileAttributes::from_bits_retain(request.attributes.0),
            xboxkrnl::ShareAccess::from_bits_retain(request.share.0),
            kernel_disposition(request.disposition),
            xboxkrnl::CreateOptions::from_bits_retain(request.options.0),
        )
    };
    status(raw.0)?;
    Ok(FileHandle(handle))
}

/// The kernel value of a create disposition.
pub(crate) fn kernel_disposition(
    disposition: commands::filesystem::CreateDisposition,
) -> xboxkrnl::CreateDisposition {
    use commands::filesystem::CreateDisposition;
    match disposition {
        CreateDisposition::Supersede => xboxkrnl::CreateDisposition::Supersede,
        CreateDisposition::Open => xboxkrnl::CreateDisposition::Open,
        CreateDisposition::Create => xboxkrnl::CreateDisposition::Create,
        CreateDisposition::OpenIf => xboxkrnl::CreateDisposition::OpenIf,
        CreateDisposition::Overwrite => xboxkrnl::CreateDisposition::Overwrite,
        CreateDisposition::OverwriteIf => xboxkrnl::CreateDisposition::OverwriteIf,
    }
}

fn set_information(
    handle: FileHandle,
    class: FileInformationClass,
    information: &[u8],
) -> Result<(), KernelError> {
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `information` is a live slice of the stated length.
    let raw = unsafe {
        xboxkrnl::NtSetInformationFile(
            Handle::from_raw(handle.0),
            &mut io_status,
            information.as_ptr(),
            information.len() as u32,
            class,
        )
    };
    status(raw.0)
}

fn time(bytes: &[u8]) -> FileTime {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[..8]);
    FileTime(u64::from_be_bytes(value))
}

fn word(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// FILE_NETWORK_OPEN_INFORMATION: four times, allocation size, end of
/// file, attributes.
fn network_open_information(bytes: &[u8; 0x38]) -> FileInformation {
    FileInformation {
        creation_time: time(&bytes[0..]),
        last_access_time: time(&bytes[8..]),
        last_write_time: time(&bytes[0x10..]),
        change_time: time(&bytes[0x18..]),
        allocation_size: time(&bytes[0x20..]).0,
        end_of_file: time(&bytes[0x28..]).0,
        attributes: FileAttributes(word(&bytes[0x30..])),
    }
}

fn pool_bytes(buffer: PoolBuffer) -> &'static mut [u8] {
    let base = buffer.0 - POOL_HEADER;
    // SAFETY: `allocate_pool` stored the length in the header of a block
    // that stays allocated until `free_pool`.
    unsafe {
        let length = core::ptr::read(base as usize as *const u32);
        core::slice::from_raw_parts_mut(buffer.0 as usize as *mut u8, length as usize)
    }
}

fn pool_range(range: PoolRange) -> &'static mut [u8] {
    &mut pool_bytes(range.buffer)[range.offset as usize..(range.offset + range.length) as usize]
}

/// Format `device` as XTAF (0x91f72e58): header, FAT, and an empty root
/// directory cluster.
fn format_xtaf(device: &[u8], cluster_size: u32) -> Result<(), KernelError> {
    const ACCESS: FileAccess = FileAccess::SYNCHRONIZE
        .union(FileAccess::READ_DATA)
        .union(FileAccess::WRITE_DATA);
    const OPTIONS: CreateOptions =
        CreateOptions::SYNCHRONOUS_IO_ALERT.union(CreateOptions::NO_INTERMEDIATE_BUFFERING);
    let handle = open_file(None, device, ACCESS, ShareAccess::NONE, OPTIONS)?;
    let result = format_open_volume(handle, cluster_size);
    // SAFETY: `handle` was opened above and is closed once.
    unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
    result
}

/// Open a file by name relative to directory `root`.
#[inline(never)]
fn open_file(
    root: Option<ObjectDirectory>,
    name: &[u8],
    access: FileAccess,
    share: ShareAccess,
    options: CreateOptions,
) -> Result<FileHandle, KernelError> {
    let name = ansi(name);
    let object = attributes(root.map_or(0, |root| root.0), &name);
    let mut io_status = IoStatusBlock::default();
    let mut handle = 0u32;
    // SAFETY: every pointer refers to a live local; `name` outlives the call.
    let raw = unsafe {
        xboxkrnl::NtOpenFile(
            (&raw mut handle).cast(),
            xboxkrnl::AccessMask::from_bits_retain(access.0),
            &object,
            &mut io_status,
            xboxkrnl::ShareAccess::from_bits_retain(share.0),
            xboxkrnl::CreateOptions::from_bits_retain(options.0),
        )
    };
    status(raw.0)?;
    Ok(FileHandle(handle))
}

/// Synchronous device control without input that fills `output`.
#[inline(never)]
pub(crate) fn device_control(
    handle: FileHandle,
    code: IoControlCode,
    output: &mut [u8],
) -> Result<(), KernelError> {
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `output` is a live mutable slice of the stated length.
    let raw = unsafe {
        xboxkrnl::NtDeviceIoControlFile(
            Handle::from_raw(handle.0),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            code,
            core::ptr::null(),
            0,
            output.as_mut_ptr(),
            output.len() as u32,
        )
    };
    status(raw.0)
}

fn format_open_volume(handle: FileHandle, cluster_size: u32) -> Result<(), KernelError> {
    let mut io_status = IoStatusBlock::default();
    let mut device = [0u8; 8];
    // SAFETY: `device` is a live 8-byte local.
    let raw = unsafe {
        NtQueryVolumeInformationFile(
            Handle::from_raw(handle.0),
            &mut io_status,
            device.as_mut_ptr(),
            8,
            FsInformationClass::Device,
        )
    };
    status(raw.0)?;
    let mut geometry = [0u8; 8];
    device_control(
        handle,
        IoControlCode::DISK_GET_DRIVE_GEOMETRY,
        &mut geometry,
    )?;
    let bytes_per_sector = word(&geometry[4..]);
    let sector_shift = if bytes_per_sector == 0 {
        0
    } else {
        31 - bytes_per_sector.leading_zeros()
    };
    let mut partition = [0u8; 0x10];
    device_control(
        handle,
        IoControlCode::DISK_GET_PARTITION_INFO,
        &mut partition,
    )?;
    let length = time(&partition[8..]).0;
    if length == 0 {
        return Err(KernelError::ObjectNameNotFound);
    }
    let page = (bytes_per_sector + 0xfff) & !0xfff;
    let cluster = cluster_size.max(page);
    let header = page.max(0x1000);
    if u64::from(header) >= length {
        return Err(KernelError::DiskFull);
    }
    let clusters = (length / u64::from(cluster)) as u32 + 1;
    /// Device type whose volumes the monitor formats with a 32-bit FAT
    /// whatever their size.
    const FORCE_FAT32: FileDeviceType = FileDeviceType(0x46);
    let fat16 = clusters < 0xfff0 && FileDeviceType(word(&device)) != FORCE_FAT32;
    let entries = if fat16 {
        clusters.wrapping_mul(2)
    } else {
        clusters.wrapping_mul(4)
    };
    let fat = entries.wrapping_add(page - 1) & !(page - 1);
    let space = length - u64::from(header);
    if u64::from(fat) > space || u64::from(cluster) > space - u64::from(fat) {
        return Err(KernelError::DiskFull);
    }
    let Some(base) = allocate(page) else {
        return Err(KernelError::InsufficientResources);
    };
    let buffer = pool_bytes(base);
    let result = write_format(
        handle,
        buffer,
        page,
        header,
        fat,
        cluster,
        fat16,
        sector_shift,
    );
    free(base);
    // SAFETY: `handle` is an open volume handle owned by the caller.
    unsafe { IoDismountVolumeByFileHandle(Handle::from_raw(handle.0)) };
    result
}

#[allow(clippy::too_many_arguments)]
fn write_format(
    handle: FileHandle,
    buffer: &mut [u8],
    page: u32,
    header: u32,
    fat: u32,
    cluster: u32,
    fat16: bool,
    sector_shift: u32,
) -> Result<(), KernelError> {
    let mut offset = 0u64;
    let write = |buffer: &mut [u8], offset: &mut u64| -> Result<(), KernelError> {
        let mut io_status = IoStatusBlock::default();
        // SAFETY: `buffer` holds at least `page` bytes and `offset` is live.
        let raw = unsafe {
            xboxkrnl::NtWriteFile(
                Handle::from_raw(handle.0),
                Handle::NULL,
                0,
                0,
                &mut io_status,
                buffer.as_ptr(),
                page,
                offset,
            )
        };
        status(raw.0)?;
        *offset += u64::from(page);
        Ok(())
    };
    buffer.fill(0);
    write(buffer, &mut offset)?;
    buffer.fill(0);
    offset = u64::from(header);
    if fat16 {
        buffer[..4].copy_from_slice(&[0xff, 0xf8, 0xff, 0xff]);
    } else {
        buffer[..8].copy_from_slice(&[0xff, 0xff, 0xff, 0xf8, 0xff, 0xff, 0xff, 0xff]);
    }
    let mut left = fat;
    while left != 0 {
        write(buffer, &mut offset)?;
        buffer[..8].fill(0);
        left -= page;
    }
    buffer.fill(0xff);
    let mut left = cluster;
    while left != 0 {
        write(buffer, &mut offset)?;
        left -= page;
    }
    buffer.fill(0xff);
    buffer[..4].copy_from_slice(b"XTAF");
    buffer[4..8]
        .copy_from_slice(&(xbox360::time::FileTime::now().intervals() as u32).to_be_bytes());
    buffer[8..12].copy_from_slice(&((cluster >> sector_shift) & 0xff).to_be_bytes());
    buffer[12..16].copy_from_slice(&1u32.to_be_bytes());
    buffer[16..18].fill(0);
    offset = 0;
    let mut left = header;
    while left != 0 {
        write(buffer, &mut offset)?;
        buffer.fill(0);
        left -= page;
    }
    Ok(())
}

fn allocate(size: u32) -> Option<PoolBuffer> {
    // SAFETY: pool allocation has no pointer arguments.
    let base = unsafe { xboxkrnl::ExAllocatePoolWithTag(size.checked_add(POOL_HEADER)?, POOL_TAG) };
    if base == 0 {
        return None;
    }
    // SAFETY: the block holds the header and `size` bytes.
    unsafe { core::ptr::write(base as usize as *mut u32, size) };
    Some(PoolBuffer(base + POOL_HEADER))
}

fn free(buffer: PoolBuffer) {
    // SAFETY: `buffer` came from `allocate`, which offset the block by the header.
    unsafe { xboxkrnl::ExFreePool(buffer.0 - POOL_HEADER) };
}

impl commands::filesystem::Backend for Console {
    fn create_file(
        &mut self,
        path: &[u8],
        request: &CreateRequest,
    ) -> Result<FileHandle, KernelError> {
        create_file(path, request)
    }

    fn open_relative(
        &mut self,
        root: ObjectDirectory,
        name: &[u8],
        access: FileAccess,
        share: ShareAccess,
        options: CreateOptions,
    ) -> Result<FileHandle, KernelError> {
        open_file(Some(root), name, access, share, options)
    }

    fn close_file(&mut self, handle: FileHandle) {
        // SAFETY: the protocol layer passes an open handle and drops it after.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
    }

    fn count_file_change(&mut self) {
        FILE_CHANGES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    fn read_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        target: ReadTarget<'_>,
    ) -> Result<u32, KernelError> {
        let buffer = match target {
            ReadTarget::Bytes(bytes) => bytes,
            ReadTarget::Pool(range) => pool_range(range),
        };
        let mut io_status = IoStatusBlock::default();
        let offset_pointer = offset
            .as_ref()
            .map_or(core::ptr::null(), |offset| offset as *const u64);
        // SAFETY: `buffer` is a live mutable slice; `io_status` and the offset
        // stay live until `complete` returns.
        let raw = unsafe {
            xboxkrnl::NtReadFile(
                Handle::from_raw(handle.0),
                Handle::NULL,
                0,
                0,
                &mut io_status,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                offset_pointer,
            )
        };
        status(complete(handle.0, raw.0, &io_status))?;
        Ok(io_status.information)
    }

    fn write_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        data: FileData<'_>,
    ) -> Result<(), KernelError> {
        let bytes: &[u8] = match data {
            FileData::Bytes(bytes) => bytes,
            FileData::Pool(range) => pool_range(range),
        };
        let mut io_status = IoStatusBlock::default();
        let offset_pointer = offset
            .as_ref()
            .map_or(core::ptr::null(), |offset| offset as *const u64);
        // SAFETY: `bytes` is a live slice; `io_status` and the offset stay live
        // until `complete` returns.
        let raw = unsafe {
            xboxkrnl::NtWriteFile(
                Handle::from_raw(handle.0),
                Handle::NULL,
                0,
                0,
                &mut io_status,
                bytes.as_ptr(),
                bytes.len() as u32,
                offset_pointer,
            )
        };
        status(complete(handle.0, raw.0, &io_status))
    }

    fn set_delete_disposition(
        &mut self,
        handle: FileHandle,
        delete: bool,
    ) -> Result<(), KernelError> {
        set_information(
            handle,
            FileInformationClass::Disposition,
            &[u8::from(delete)],
        )
    }

    fn set_end_of_file(&mut self, handle: FileHandle, size: u64) -> Result<(), KernelError> {
        set_information(handle, FileInformationClass::EndOfFile, &size.to_be_bytes())
    }

    fn set_file_position(&mut self, handle: FileHandle, position: u64) -> Result<(), KernelError> {
        set_information(
            handle,
            FileInformationClass::Position,
            &position.to_be_bytes(),
        )
    }

    fn set_basic_information(
        &mut self,
        handle: FileHandle,
        information: &BasicInformation,
    ) -> Result<(), KernelError> {
        let mut bytes = [0u8; 0x28];
        let times = [
            information.creation_time,
            information.last_access_time,
            information.last_write_time,
            information.change_time,
        ];
        for (slot, time) in bytes.chunks_exact_mut(8).zip(times) {
            slot.copy_from_slice(&time.0.to_be_bytes());
        }
        bytes[0x20..0x24].copy_from_slice(&information.attributes.0.to_be_bytes());
        set_information(handle, FileInformationClass::Basic, &bytes)
    }

    fn rename_file(
        &mut self,
        handle: FileHandle,
        target: &[u8],
        replace: bool,
    ) -> Result<(), KernelError> {
        #[repr(C)]
        struct RenameInformation {
            replace: u8,
            root_directory: u32,
            name: AnsiString,
        }
        let information = RenameInformation {
            replace: u8::from(replace),
            root_directory: 0,
            name: ansi(target),
        };
        let mut io_status = IoStatusBlock::default();
        let pointer = (&information as *const RenameInformation).cast::<u8>();
        // SAFETY: `information` and the name it refers to outlive the call.
        let raw = unsafe {
            xboxkrnl::NtSetInformationFile(
                Handle::from_raw(handle.0),
                &mut io_status,
                pointer,
                size_of::<RenameInformation>() as u32,
                FileInformationClass::Rename,
            )
        };
        status(raw.0)
    }

    fn query_file_information(
        &mut self,
        handle: FileHandle,
    ) -> Result<FileInformation, KernelError> {
        let mut bytes = [0u8; 0x38];
        let mut io_status = IoStatusBlock::default();
        // SAFETY: `bytes` is a live local of the stated length.
        let raw = unsafe {
            xboxkrnl::NtQueryInformationFile(
                Handle::from_raw(handle.0),
                &mut io_status,
                bytes.as_mut_ptr(),
                0x38,
                FileInformationClass::NetworkOpen,
            )
        };
        status(raw.0)?;
        Ok(network_open_information(&bytes))
    }

    fn query_full_attributes(&mut self, path: &[u8]) -> Result<FileInformation, KernelError> {
        let name = ansi(path);
        let object = attributes(0, &name);
        let mut bytes = [0u8; 0x38];
        // SAFETY: `object` refers to `name`; `bytes` holds the 0x38-byte result.
        let raw = unsafe { xboxkrnl::NtQueryFullAttributesFile(&object, bytes.as_mut_ptr()) };
        status(raw.0)?;
        Ok(network_open_information(&bytes))
    }

    fn query_directory(
        &mut self,
        handle: FileHandle,
        restart: bool,
        name: &mut [u8],
    ) -> Result<DirectoryEntry, KernelError> {
        let mut bytes = [0u8; DIRECTORY_BUFFER];
        let mut io_status = IoStatusBlock::default();
        // SAFETY: `bytes` and `io_status` stay live until `complete` returns.
        let raw = unsafe {
            NtQueryDirectoryFile(
                Handle::from_raw(handle.0),
                Handle::NULL,
                0,
                0,
                &mut io_status,
                bytes.as_mut_ptr(),
                DIRECTORY_BUFFER as u32,
                core::ptr::null(),
                restart,
            )
        };
        status(complete(handle.0, raw.0, &io_status))?;
        let length = (word(&bytes[0x3c..]) as usize).min(DIRECTORY_BUFFER - DIRECTORY_NAME_OFFSET);
        if length > name.len() {
            return Err(KernelError::BufferOverflow);
        }
        name[..length]
            .copy_from_slice(&bytes[DIRECTORY_NAME_OFFSET..DIRECTORY_NAME_OFFSET + length]);
        let information = FileInformation {
            creation_time: time(&bytes[8..]),
            last_access_time: time(&bytes[0x10..]),
            last_write_time: time(&bytes[0x18..]),
            change_time: time(&bytes[0x20..]),
            end_of_file: time(&bytes[0x28..]).0,
            allocation_size: time(&bytes[0x30..]).0,
            attributes: FileAttributes(word(&bytes[0x38..])),
        };
        Ok(DirectoryEntry {
            information,
            name_length: length,
        })
    }

    fn query_volume_size(&mut self, handle: FileHandle) -> Result<VolumeSize, KernelError> {
        let mut bytes = [0u8; 0x18];
        let mut io_status = IoStatusBlock::default();
        // SAFETY: `bytes` is a live local of the stated length.
        let raw = unsafe {
            NtQueryVolumeInformationFile(
                Handle::from_raw(handle.0),
                &mut io_status,
                bytes.as_mut_ptr(),
                0x18,
                FsInformationClass::Size,
            )
        };
        status(raw.0)?;
        Ok(VolumeSize {
            total_units: time(&bytes[0..]).0,
            available_units: time(&bytes[8..]).0,
            sectors_per_unit: word(&bytes[0x10..]),
            bytes_per_sector: word(&bytes[0x14..]),
        })
    }

    #[cfg(feature = "smb")]
    fn query_volume_attributes(
        &mut self,
        handle: FileHandle,
    ) -> Result<commands::filesystem::VolumeAttributes, KernelError> {
        // Attributes, maximum component length, name length, and the name.
        let mut bytes = [0u8; 12 + commands::filesystem::FILE_SYSTEM_NAME_CAPACITY];
        let mut io_status = IoStatusBlock::default();
        // SAFETY: `bytes` is a live local of the stated length.
        let raw = unsafe {
            NtQueryVolumeInformationFile(
                Handle::from_raw(handle.0),
                &mut io_status,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                FsInformationClass::Attribute,
            )
        };
        status(raw.0)?;
        let name = bytes[12..]
            .get(..word(&bytes[8..]) as usize)
            .ok_or(KernelError::BufferOverflow)?;
        volume_attributes(word(&bytes[0..]), word(&bytes[4..]), name)
            .ok_or(KernelError::ObjectNameInvalid)
    }

    fn translate_symbolic_link(
        &mut self,
        link: &[u8],
        target: &mut [u8],
    ) -> Result<usize, KernelError> {
        let name = ansi(link);
        let object = attributes(0, &name);
        let mut output = AnsiString {
            length: 0,
            maximum_length: target.len() as u16,
            buffer: target.as_mut_ptr(),
        };
        // SAFETY: `output` describes the live `target` slice; `object` refers to `name`.
        let raw = unsafe { ObTranslateSymbolicLink(&object, &mut output) };
        status(raw.0)?;
        Ok(usize::from(output.length))
    }

    fn open_object_directory(&mut self, path: &[u8]) -> Result<ObjectDirectory, KernelError> {
        let name = ansi(path);
        let object = attributes(0, &name);
        let mut handle = 0u32;
        // SAFETY: `handle` and `object` are live locals.
        let raw = unsafe { NtOpenDirectoryObject((&raw mut handle).cast(), &object) };
        status(raw.0)?;
        Ok(ObjectDirectory(handle))
    }

    fn query_object_directory(
        &mut self,
        directory: ObjectDirectory,
        restart: bool,
        context: &mut u32,
        name: &mut [u8],
    ) -> Result<usize, KernelError> {
        #[repr(C, align(4))]
        struct Buffer([u8; OBJECT_DIRECTORY_BUFFER]);
        let mut buffer = Buffer([0; OBJECT_DIRECTORY_BUFFER]);
        // SAFETY: `buffer` and `context` are live for the stated length.
        let raw = unsafe {
            xboxkrnl::NtQueryDirectoryObject(
                Handle::from_raw(directory.0),
                buffer.0.as_mut_ptr(),
                OBJECT_DIRECTORY_BUFFER as u32,
                restart,
                context,
                core::ptr::null_mut(),
            )
        };
        status(raw.0)?;
        // SAFETY: the kernel wrote an object name descriptor at the start
        // of the buffer whose text lies inside the buffer.
        let entry = unsafe { core::ptr::read((buffer.0.as_ptr()).cast::<AnsiString>()) };
        let length = usize::from(entry.length).min(name.len());
        // SAFETY: see above.
        let text = unsafe { core::slice::from_raw_parts(entry.buffer, length) };
        name[..length].copy_from_slice(text);
        Ok(length)
    }

    fn close_object_directory(&mut self, directory: ObjectDirectory) {
        // SAFETY: the protocol layer passes an open directory handle and drops it after.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(directory.0)) };
    }

    fn reference_device(&mut self, name: &[u8]) -> Result<DeviceObject, KernelError> {
        let name = ansi(name);
        let object_type = kernel::resolved(&IoDeviceObjectType);
        let mut object = 0u32;
        // SAFETY: `name` and `object` are live locals; `object_type` is the
        // kernel device object type.
        let raw = unsafe {
            xboxkrnl::ObReferenceObjectByName(
                &name,
                ObjectAttributeFlags::empty(),
                core::ptr::from_ref(object_type).expose_provenance() as u32,
                0,
                &mut object,
            )
        };
        status(raw.0)?;
        Ok(DeviceObject(object))
    }

    fn dereference_device(&mut self, device: DeviceObject) {
        // SAFETY: `device` holds the reference taken by `reference_device`.
        unsafe { xboxkrnl::ObDereferenceObject(device.0) };
    }

    fn transfer_device(
        &mut self,
        device: DeviceObject,
        direction: TransferDirection,
        offset: u64,
        buffer: PoolRange,
    ) -> Result<(), KernelError> {
        let major = match direction {
            TransferDirection::Read => IrpMajorFunction::Read,
            TransferDirection::Write => IrpMajorFunction::Write,
        };
        let bytes = pool_range(buffer);
        // SAFETY: `device` is referenced; `bytes` is a live pool range of
        // `buffer.length` bytes.
        let raw = unsafe {
            IoSynchronousFsdRequest(
                major,
                core::ptr::with_exposed_provenance_mut(device.0 as usize),
                bytes.as_mut_ptr(),
                buffer.length,
                &offset,
            )
        };
        status(raw.0)
    }

    fn allocate_pool(&mut self, size: u32) -> Option<PoolBuffer> {
        allocate(size)
    }

    fn free_pool(&mut self, buffer: PoolBuffer) {
        free(buffer);
    }

    fn pool(&mut self, buffer: PoolBuffer) -> &mut [u8] {
        pool_bytes(buffer)
    }

    fn allocate_scratch(&mut self, size: u32) -> Option<&'static mut [u8]> {
        allocate(size).map(pool_bytes)
    }

    fn free_scratch(&mut self, block: &'static mut [u8]) {
        free(PoolBuffer(block.as_mut_ptr() as usize as u32));
    }

    fn open_close_tray(&mut self, value: u32) {
        // SAFETY: the request takes no pointers.
        unsafe { HalOpenCloseODDTray(value) };
    }

    fn format_partition(&mut self, device: &[u8], cluster_size: u32) -> Result<(), KernelError> {
        format_xtaf(device, cluster_size)
    }

    fn update_sequence(&mut self) -> u16 {
        // Stock reads the halfword at +0x12: the low half of the tick count.
        kernel::resolved(&xboxkrnl::KeTimeStampBundle)
            .tick_count
            .load(Ordering::Relaxed) as u16
    }

    fn dos_error(&mut self, error: KernelError) -> Option<Win32Error> {
        dos_error(error)
    }

    fn start_dvd_trace(&mut self) {
        let block = kernel::published_debug_monitor_data();
        if let Some(block) = block {
            // SAFETY: 0 stops the recording before the old buffer is freed.
            unsafe { block.dvd_trace_pointer.store(0, Ordering::Relaxed) };
        }
        if let Some(buffer) = self.filesystem.dvd_trace.take() {
            free(buffer);
        }
        let Some(buffer) = allocate(DVD_TRACE_SIZE) else {
            return;
        };
        self.filesystem.dvd_trace = Some(buffer);
        let first = pool_bytes(buffer);
        first[8] &= !1;
        if let Some(block) = block {
            let flags = &block.flags;
            flags.store(
                flags.load(Ordering::Relaxed) | DebugMonitorFlags::DVD_TRACE.bits(),
                Ordering::Relaxed,
            );
            // SAFETY: the buffer is a live pool block of `DVD_TRACE_SIZE`
            // bytes, kept until the pointer is cleared again.
            unsafe { block.dvd_trace_pointer.store(buffer.0, Ordering::Relaxed) };
        }
    }

    fn stop_dvd_trace(&mut self) -> Option<DvdTrace> {
        let end = match kernel::published_debug_monitor_data() {
            Some(block) => {
                // The driver updates the write pointer atomically.
                // SAFETY: 0 stops the recording before the buffer is freed.
                let end = unsafe { block.dvd_trace_pointer.swap(0, Ordering::SeqCst) };
                let flags = &block.flags;
                flags.store(
                    flags.load(Ordering::Relaxed) & !DebugMonitorFlags::DVD_TRACE.bits(),
                    Ordering::Relaxed,
                );
                end
            }
            None => 0,
        };
        let buffer = self.filesystem.dvd_trace.take()?;
        let length = if end > buffer.0 {
            (end - buffer.0).min(DVD_TRACE_SIZE)
        } else {
            0
        };
        Some(DvdTrace { buffer, length })
    }

    fn dvd_trace_active(&mut self) -> bool {
        self.filesystem.dvd_trace.is_some()
    }
}

/// Control code 0x7e: 1 when the emulator reports revision `0002`, else
/// the value of a monitor global that nothing in the image writes.
pub(crate) fn service_dvd_emulator_state(_argument: u32) -> u32 {
    u32::from(super::dvd_hotplug::emulator_revision_0002())
}

/// Control code 0x03, run on the server thread: a title maps or removes a
/// drive. The control code always returns 0.
pub(crate) fn service_set_drive_mapping(
    server: &mut openxbdm_server::Server,
    console: &mut Console,
    _network: &mut crate::net::XamNetwork,
    request: u32,
) -> u32 {
    commands::filesystem::map_title_drive(&mut server.state, console, request);
    0
}

/// Closes of files commands may have changed (0x91f9feec).
static FILE_CHANGES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Export 85 (stock 0x91f46fd8): store the file change counter.
extern "C" fn file_change_count(count: u32) -> u32 {
    // SAFETY: the caller passes a writable dword, as the image assumes.
    unsafe {
        core::ptr::write_volatile(
            count as usize as *mut u32,
            FILE_CHANGES.load(core::sync::atomic::Ordering::Relaxed),
        )
    };
    Hresult::OK.0
}
export!(85, file_change_count);

/// Export 141 (stock 0x91f33438): link `E:` and `DEVKIT:` to the devkit
/// directory in the caller's process namespace. Existing links count as
/// success; the result is the HRESULT of the DOS error.
extern "C" fn map_devkit_drive() -> u32 {
    let (drive, devkit): (&[u8], &[u8]) =
        if xboxkrnl::KeGetCurrentProcessType() == ProcessType::SYSTEM {
            (b"\\system??\\E:", b"\\system??\\DEVKIT:")
        } else {
            (b"\\??\\E:", b"\\??\\DEVKIT:")
        };
    let target = ansi(b"\\Device\\Harddisk0\\Partition1\\DEVKIT");
    // SAFETY: both counted names refer to live bytes for the call.
    let link = |name: &[u8]| status(unsafe { ObCreateSymbolicLink(&ansi(name), &target) }.0);
    let linked = match link(drive) {
        Ok(()) | Err(KernelError::ObjectNameCollision) => match link(devkit) {
            Err(KernelError::ObjectNameCollision) => Ok(()),
            other => other,
        },
        Err(error) => Err(error),
    };
    // ERROR_SUCCESS and S_OK are 0.
    match linked.err().and_then(dos_error) {
        Some(error) => Hresult::from(error).0,
        None => 0,
    }
}
export!(141, map_devkit_drive);

/// Kernel export resolved on first use of export 144.
const KERNEL_ROUTINE_ORDINAL: u32 = 0x273;
/// The resolved routine (0x91f9f684); zero when absent.
static KERNEL_ROUTINE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Set by the first caller, which resolves the routine (0x91f9f688).
static KERNEL_ROUTINE_CLAIMED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
const ERROR_NOT_SUPPORTED: u32 = 50;

/// Export 144 (stock 0x91f334e8): call kernel export 0x273 as
/// `routine(0, a, b, c, d)` and return the DOS error of its status. A
/// caller that finds the routine claimed but not yet resolved, or a kernel
/// without it, gets ERROR_NOT_SUPPORTED.
extern "C" fn call_kernel_routine(a: u32, b: u32, c: u32, d: u32) -> u32 {
    use core::sync::atomic::Ordering;
    let mut routine = KERNEL_ROUTINE.load(Ordering::Acquire);
    if routine == 0 && !KERNEL_ROUTINE_CLAIMED.swap(true, Ordering::AcqRel) {
        let mut address = 0u32;
        let resolved = SystemModule::Kernel.handle().is_ok_and(|module| {
            // SAFETY: `module` is a loaded module handle; `address` is a live local.
            let raw = unsafe {
                xboxkrnl::XexGetProcedureAddress(module.raw(), KERNEL_ROUTINE_ORDINAL, &mut address)
            };
            status(raw.0).is_ok()
        });
        routine = if resolved { address } else { 0 };
        KERNEL_ROUTINE.store(routine, Ordering::Release);
    }
    if routine == 0 {
        return ERROR_NOT_SUPPORTED;
    }
    // SAFETY: the kernel export takes five register arguments.
    let status = unsafe { call_five(routine, 0, a, b, c, d) };
    xboxkrnl::RtlNtStatusToDosError(NtStatus(status)).0
}
export!(144, call_kernel_routine);

/// Call a console function with five register arguments through a frame
/// that reserves the home area.
///
/// # Safety
/// `function` must take at most five register arguments.
#[unsafe(naked)]
unsafe extern "C" fn call_five(function: u32, a0: u32, a1: u32, a2: u32, a3: u32, a4: u32) -> u32 {
    core::arch::naked_asm!(
        "stwu 1, -0x50(1)",
        "mflr 0",
        "stw 0, 0x54(1)",
        "mtctr 3",
        "mr 3, 4",
        "mr 4, 5",
        "mr 5, 6",
        "mr 6, 7",
        "mr 7, 8",
        "bctrl",
        "lwz 0, 0x54(1)",
        "mtlr 0",
        "addi 1, 1, 0x50",
        "blr",
    )
}
