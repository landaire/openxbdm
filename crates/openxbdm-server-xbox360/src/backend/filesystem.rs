//! File system, object namespace, and block device services.

use openxbdm_core::status::NtStatus;
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
use openxbdm_server::commands::filesystem::ShareAccess;
use openxbdm_server::commands::filesystem::TransferDirection;
use openxbdm_server::commands::filesystem::VolumeSize;
use openxbdm_server::commands::filesystem::nt;

use super::Console;
use crate::exports::export;
use crate::kernel;
use crate::kernel::AnsiString;
use crate::kernel::IoStatusBlock;
use crate::kernel::ObjectAttributes;
use crate::kernel::import_thunk;
use crate::kernel::import_thunk_stack;

import_thunk_stack!(
    NtQueryDirectoryFile(
        handle: u32,
        event: u32,
        apc_routine: u32,
        apc_context: u32,
        io_status: *mut IoStatusBlock,
        information: *mut u8,
        length: u32,
        file_name: *const AnsiString,
        restart: u32,
    ) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 228
);
use crate::kernel::NtQueryVolumeInformationFile;
import_thunk!(
    ObTranslateSymbolicLink(attributes: *const ObjectAttributes, target: *mut AnsiString) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 275
);
use crate::kernel::NtOpenDirectoryObject;
import_thunk!(
    IoSynchronousFsdRequest(
        major: u32,
        device: u32,
        buffer: *mut u8,
        length: u32,
        offset: *const u64,
    ) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 76
);
import_thunk!(
    IoDismountVolumeByFileHandle(handle: u32) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 60
);
import_thunk!(
    HalOpenCloseODDTray(value: u32) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 36
);
use crate::kernel::IO_DEVICE_OBJECT_TYPE;

const STATUS_PENDING: u32 = 0x103;
const POOL_TAG: u32 = 0x7864_626d;
/// Pool blocks carry their size in a header of this many bytes.
const POOL_HEADER: u32 = 8;
const FILE_POSITION_INFORMATION: u32 = 0xe;
const FILE_BASIC_INFORMATION: u32 = 4;
const FILE_RENAME_INFORMATION: u32 = 0xa;
const FILE_DISPOSITION_INFORMATION: u32 = 0xd;
const FILE_END_OF_FILE_INFORMATION: u32 = 0x14;
const FILE_NETWORK_OPEN_INFORMATION: u32 = 0x22;
const FILE_FS_SIZE_INFORMATION: u32 = 3;
const FILE_FS_DEVICE_INFORMATION: u32 = 4;
const IRP_MJ_READ: u32 = 2;
const IRP_MJ_WRITE: u32 = 3;
const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x7_0000;
const IOCTL_DISK_GET_PARTITION_INFO: u32 = 0x7_4004;
/// Device type of the devices that always get a 32-bit FAT.
const FILE_DEVICE_FORCE_FAT32: u32 = 0x46;
/// Directory query buffer of the image.
const DIRECTORY_BUFFER: usize = 0x190;
const DIRECTORY_NAME_OFFSET: usize = 0x40;
/// Object directory query buffer of the image.
const OBJECT_DIRECTORY_BUFFER: usize = 0x10c;
/// Size of the optical drive trace buffer.
const DVD_TRACE_SIZE: u32 = 0x20_0000;
/// Debug monitor block: trace flags word and current trace write pointer.
const MONITOR_FLAGS: u32 = 0xc;
const MONITOR_TRACE_POINTER: u32 = 0x3c;
const MONITOR_DVD_TRACE: u32 = 0x20;
/// Longest object name passed to the kernel.
const PATH_CAPACITY: usize = 0x200;

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

fn status(raw: u32) -> Result<(), NtStatus> {
    if (raw as i32) < 0 {
        Err(NtStatus(raw))
    } else {
        Ok(())
    }
}

/// A counted name; the kernel copies it, so the bytes only live for the
/// call.
fn ansi(bytes: &[u8]) -> AnsiString {
    AnsiString::new(&bytes[..bytes.len().min(PATH_CAPACITY)])
}

fn attributes(root: u32, name: &AnsiString) -> ObjectAttributes {
    ObjectAttributes {
        root_directory: root,
        object_name: name,
        attributes: kernel::OBJ_CASE_INSENSITIVE,
    }
}

/// Wait for an asynchronous operation started on `handle`.
fn complete(handle: u32, raw: u32, io_status: &IoStatusBlock) -> u32 {
    if raw != STATUS_PENDING {
        return raw;
    }
    kernel::NtWaitForSingleObjectEx(handle, 0, 0, core::ptr::null());
    // SAFETY: the kernel completed the request and wrote the status block.
    unsafe { core::ptr::read_volatile(&io_status.status) }
}

/// Create or open a file by object name.
pub(crate) fn create_file(path: &[u8], request: &CreateRequest) -> Result<FileHandle, NtStatus> {
    let name = ansi(path);
    let object = attributes(0, &name);
    let mut io_status = IoStatusBlock::default();
    let mut handle = 0u32;
    let allocation = request.allocation_size;
    let allocation_pointer = allocation
        .as_ref()
        .map_or(core::ptr::null(), |size| size as *const u64);
    status(kernel::NtCreateFile(
        &mut handle,
        request.access.0,
        &object,
        &mut io_status,
        allocation_pointer,
        request.attributes.0,
        request.share.0,
        request.disposition as u32,
        request.options.0,
    ))?;
    Ok(FileHandle(handle))
}

fn set_information(handle: FileHandle, class: u32, information: &[u8]) -> Result<(), NtStatus> {
    let mut io_status = IoStatusBlock::default();
    status(kernel::NtSetInformationFile(
        handle.0,
        &mut io_status,
        information.as_ptr(),
        information.len() as u32,
        class,
    ))
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

fn monitor_block() -> Option<u32> {
    let slot = kernel::KE_DEBUG_MONITOR_DATA.load(core::sync::atomic::Ordering::Relaxed);
    // SAFETY: the loader stored the address of the kernel variable.
    let block = unsafe { core::ptr::read_volatile(slot as usize as *const u32) };
    (block != 0).then_some(block)
}

/// Format `device` as XTAF (0x91f72e58): header, FAT, and an empty root
/// directory cluster.
fn format_xtaf(device: &[u8], cluster_size: u32) -> Result<(), NtStatus> {
    let name = ansi(device);
    let object = attributes(0, &name);
    let mut io_status = IoStatusBlock::default();
    let mut handle = 0u32;
    status(kernel::NtOpenFile(
        &mut handle,
        0x10_0003,
        &object,
        &mut io_status,
        0,
        0x18,
    ))?;
    let result = format_open_volume(handle, cluster_size);
    kernel::NtClose(handle);
    result
}

fn format_open_volume(handle: u32, cluster_size: u32) -> Result<(), NtStatus> {
    let mut io_status = IoStatusBlock::default();
    let mut device = [0u8; 8];
    status(NtQueryVolumeInformationFile(
        handle,
        &mut io_status,
        device.as_mut_ptr(),
        8,
        FILE_FS_DEVICE_INFORMATION,
    ))?;
    let mut geometry = [0u8; 8];
    status(kernel::NtDeviceIoControlFile(
        handle,
        0,
        0,
        0,
        &mut io_status,
        IOCTL_DISK_GET_DRIVE_GEOMETRY,
        core::ptr::null(),
        0,
        geometry.as_mut_ptr(),
        8,
    ))?;
    let bytes_per_sector = word(&geometry[4..]);
    let sector_shift = if bytes_per_sector == 0 {
        0
    } else {
        31 - bytes_per_sector.leading_zeros()
    };
    let mut partition = [0u8; 0x10];
    status(kernel::NtDeviceIoControlFile(
        handle,
        0,
        0,
        0,
        &mut io_status,
        IOCTL_DISK_GET_PARTITION_INFO,
        core::ptr::null(),
        0,
        partition.as_mut_ptr(),
        0x10,
    ))?;
    let length = time(&partition[8..]).0;
    if length == 0 {
        return Err(nt::OBJECT_NAME_NOT_FOUND);
    }
    let page = (bytes_per_sector + 0xfff) & !0xfff;
    let cluster = cluster_size.max(page);
    let header = page.max(0x1000);
    if u64::from(header) >= length {
        return Err(nt::DISK_FULL);
    }
    let clusters = (length / u64::from(cluster)) as u32 + 1;
    let fat16 = clusters < 0xfff0 && word(&device) != FILE_DEVICE_FORCE_FAT32;
    let entries = if fat16 {
        clusters.wrapping_mul(2)
    } else {
        clusters.wrapping_mul(4)
    };
    let fat = entries.wrapping_add(page - 1) & !(page - 1);
    let space = length - u64::from(header);
    if u64::from(fat) > space || u64::from(cluster) > space - u64::from(fat) {
        return Err(nt::DISK_FULL);
    }
    let Some(base) = allocate(page) else {
        return Err(NtStatus(0xc000_009a));
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
    IoDismountVolumeByFileHandle(handle);
    result
}

#[allow(clippy::too_many_arguments)]
fn write_format(
    handle: u32,
    buffer: &mut [u8],
    page: u32,
    header: u32,
    fat: u32,
    cluster: u32,
    fat16: bool,
    sector_shift: u32,
) -> Result<(), NtStatus> {
    let mut offset = 0u64;
    let write = |buffer: &mut [u8], offset: &mut u64| -> Result<(), NtStatus> {
        let mut io_status = IoStatusBlock::default();
        status(kernel::NtWriteFile(
            handle,
            0,
            0,
            0,
            &mut io_status,
            buffer.as_ptr(),
            page,
            offset,
        ))?;
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
    buffer[4..8].copy_from_slice(&(kernel::system_time() as u32).to_be_bytes());
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
    let base = kernel::ExAllocatePoolWithTag(size.checked_add(POOL_HEADER)?, POOL_TAG);
    if base == 0 {
        return None;
    }
    // SAFETY: the block holds the header and `size` bytes.
    unsafe { core::ptr::write(base as usize as *mut u32, size) };
    Some(PoolBuffer(base + POOL_HEADER))
}

fn free(buffer: PoolBuffer) {
    kernel::ExFreePool(buffer.0 - POOL_HEADER);
}

impl commands::filesystem::Backend for Console {
    fn create_file(
        &mut self,
        path: &[u8],
        request: &CreateRequest,
    ) -> Result<FileHandle, NtStatus> {
        create_file(path, request)
    }

    fn open_relative(
        &mut self,
        root: ObjectDirectory,
        name: &[u8],
        access: FileAccess,
        share: ShareAccess,
        options: CreateOptions,
    ) -> Result<FileHandle, NtStatus> {
        let name = ansi(name);
        let object = attributes(root.0, &name);
        let mut io_status = IoStatusBlock::default();
        let mut handle = 0u32;
        status(kernel::NtOpenFile(
            &mut handle,
            access.0,
            &object,
            &mut io_status,
            share.0,
            options.0,
        ))?;
        Ok(FileHandle(handle))
    }

    fn close_file(&mut self, handle: FileHandle) {
        kernel::NtClose(handle.0);
    }

    fn count_file_change(&mut self) {
        FILE_CHANGES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    fn read_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        target: PoolRange,
    ) -> Result<u32, NtStatus> {
        let buffer = pool_range(target);
        let mut io_status = IoStatusBlock::default();
        let offset_pointer = offset
            .as_ref()
            .map_or(core::ptr::null(), |offset| offset as *const u64);
        let raw = kernel::NtReadFile(
            handle.0,
            0,
            0,
            0,
            &mut io_status,
            buffer.as_mut_ptr(),
            target.length,
            offset_pointer,
        );
        status(complete(handle.0, raw, &io_status))?;
        Ok(io_status.information)
    }

    fn write_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        data: FileData<'_>,
    ) -> Result<(), NtStatus> {
        let bytes: &[u8] = match data {
            FileData::Bytes(bytes) => bytes,
            FileData::Pool(range) => pool_range(range),
        };
        let mut io_status = IoStatusBlock::default();
        let offset_pointer = offset
            .as_ref()
            .map_or(core::ptr::null(), |offset| offset as *const u64);
        let raw = kernel::NtWriteFile(
            handle.0,
            0,
            0,
            0,
            &mut io_status,
            bytes.as_ptr(),
            bytes.len() as u32,
            offset_pointer,
        );
        status(complete(handle.0, raw, &io_status))
    }

    fn set_delete_disposition(&mut self, handle: FileHandle, delete: bool) -> Result<(), NtStatus> {
        set_information(handle, FILE_DISPOSITION_INFORMATION, &[u8::from(delete)])
    }

    fn set_end_of_file(&mut self, handle: FileHandle, size: u64) -> Result<(), NtStatus> {
        set_information(handle, FILE_END_OF_FILE_INFORMATION, &size.to_be_bytes())
    }

    fn set_file_position(&mut self, handle: FileHandle, position: u64) -> Result<(), NtStatus> {
        set_information(handle, FILE_POSITION_INFORMATION, &position.to_be_bytes())
    }

    fn set_basic_information(
        &mut self,
        handle: FileHandle,
        information: &BasicInformation,
    ) -> Result<(), NtStatus> {
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
        set_information(handle, FILE_BASIC_INFORMATION, &bytes)
    }

    fn rename_file(
        &mut self,
        handle: FileHandle,
        target: &[u8],
        replace: bool,
    ) -> Result<(), NtStatus> {
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
        status(kernel::NtSetInformationFile(
            handle.0,
            &mut io_status,
            pointer,
            size_of::<RenameInformation>() as u32,
            FILE_RENAME_INFORMATION,
        ))
    }

    fn query_file_information(&mut self, handle: FileHandle) -> Result<FileInformation, NtStatus> {
        let mut bytes = [0u8; 0x38];
        let mut io_status = IoStatusBlock::default();
        status(kernel::NtQueryInformationFile(
            handle.0,
            &mut io_status,
            bytes.as_mut_ptr(),
            0x38,
            FILE_NETWORK_OPEN_INFORMATION,
        ))?;
        Ok(network_open_information(&bytes))
    }

    fn query_full_attributes(&mut self, path: &[u8]) -> Result<FileInformation, NtStatus> {
        let name = ansi(path);
        let object = attributes(0, &name);
        let mut bytes = [0u8; 0x38];
        status(kernel::NtQueryFullAttributesFile(
            &object,
            bytes.as_mut_ptr(),
        ))?;
        Ok(network_open_information(&bytes))
    }

    fn query_directory(
        &mut self,
        handle: FileHandle,
        restart: bool,
        name: &mut [u8],
    ) -> Result<DirectoryEntry, NtStatus> {
        let mut bytes = [0u8; DIRECTORY_BUFFER];
        let mut io_status = IoStatusBlock::default();
        let raw = NtQueryDirectoryFile(
            handle.0,
            0,
            0,
            0,
            &mut io_status,
            bytes.as_mut_ptr(),
            DIRECTORY_BUFFER as u32,
            core::ptr::null(),
            u32::from(restart),
        );
        status(complete(handle.0, raw, &io_status))?;
        let length = (word(&bytes[0x3c..]) as usize).min(DIRECTORY_BUFFER - DIRECTORY_NAME_OFFSET);
        if length > name.len() {
            return Err(nt::BUFFER_OVERFLOW);
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

    fn query_volume_size(&mut self, handle: FileHandle) -> Result<VolumeSize, NtStatus> {
        let mut bytes = [0u8; 0x18];
        let mut io_status = IoStatusBlock::default();
        status(NtQueryVolumeInformationFile(
            handle.0,
            &mut io_status,
            bytes.as_mut_ptr(),
            0x18,
            FILE_FS_SIZE_INFORMATION,
        ))?;
        Ok(VolumeSize {
            total_units: time(&bytes[0..]).0,
            available_units: time(&bytes[8..]).0,
            sectors_per_unit: word(&bytes[0x10..]),
            bytes_per_sector: word(&bytes[0x14..]),
        })
    }

    fn translate_symbolic_link(
        &mut self,
        link: &[u8],
        target: &mut [u8],
    ) -> Result<usize, NtStatus> {
        let name = ansi(link);
        let object = attributes(0, &name);
        let mut output = AnsiString {
            length: 0,
            maximum_length: target.len() as u16,
            buffer: target.as_mut_ptr(),
        };
        status(ObTranslateSymbolicLink(&object, &mut output))?;
        Ok(usize::from(output.length))
    }

    fn open_object_directory(&mut self, path: &[u8]) -> Result<ObjectDirectory, NtStatus> {
        let name = ansi(path);
        let object = attributes(0, &name);
        let mut handle = 0u32;
        status(NtOpenDirectoryObject(&mut handle, &object))?;
        Ok(ObjectDirectory(handle))
    }

    fn query_object_directory(
        &mut self,
        directory: ObjectDirectory,
        restart: bool,
        context: &mut u32,
        name: &mut [u8],
    ) -> Result<usize, NtStatus> {
        #[repr(C, align(4))]
        struct Buffer([u8; OBJECT_DIRECTORY_BUFFER]);
        let mut buffer = Buffer([0; OBJECT_DIRECTORY_BUFFER]);
        status(kernel::NtQueryDirectoryObject(
            directory.0,
            buffer.0.as_mut_ptr(),
            OBJECT_DIRECTORY_BUFFER as u32,
            u32::from(restart),
            context,
            core::ptr::null_mut(),
        ))?;
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
        kernel::NtClose(directory.0);
    }

    fn reference_device(&mut self, name: &[u8]) -> Result<DeviceObject, NtStatus> {
        let name = ansi(name);
        let slot = IO_DEVICE_OBJECT_TYPE.load(core::sync::atomic::Ordering::Relaxed);
        let mut object = 0u32;
        status(kernel::ObReferenceObjectByName(
            &name,
            0,
            slot,
            0,
            &mut object,
        ))?;
        Ok(DeviceObject(object))
    }

    fn dereference_device(&mut self, device: DeviceObject) {
        kernel::ObDereferenceObject(device.0);
    }

    fn transfer_device(
        &mut self,
        device: DeviceObject,
        direction: TransferDirection,
        offset: u64,
        buffer: PoolRange,
    ) -> Result<(), NtStatus> {
        let major = match direction {
            TransferDirection::Read => IRP_MJ_READ,
            TransferDirection::Write => IRP_MJ_WRITE,
        };
        let bytes = pool_range(buffer);
        status(IoSynchronousFsdRequest(
            major,
            device.0,
            bytes.as_mut_ptr(),
            buffer.length,
            &offset,
        ))
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

    fn open_close_tray(&mut self, value: u32) {
        HalOpenCloseODDTray(value);
    }

    fn format_partition(&mut self, device: &[u8], cluster_size: u32) -> Result<(), NtStatus> {
        format_xtaf(device, cluster_size)
    }

    fn update_sequence(&mut self) -> u16 {
        let address = kernel::KE_TIME_STAMP_BUNDLE.load(core::sync::atomic::Ordering::Relaxed);
        // SAFETY: the loader stored the address of the kernel export.
        unsafe { core::ptr::read_volatile((address + 0x12) as usize as *const u16) }
    }

    fn dos_error(&mut self, status: NtStatus) -> u32 {
        kernel::RtlNtStatusToDosError(status.0)
    }

    fn start_dvd_trace(&mut self) {
        let block = monitor_block();
        if let Some(block) = block {
            // SAFETY: the debug monitor block stays mapped while the module runs.
            unsafe {
                core::ptr::write_volatile((block + MONITOR_TRACE_POINTER) as usize as *mut u32, 0)
            };
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
            // SAFETY: as above.
            unsafe {
                let flags = (block + MONITOR_FLAGS) as usize as *mut u32;
                core::ptr::write_volatile(
                    flags,
                    core::ptr::read_volatile(flags) | MONITOR_DVD_TRACE,
                );
                core::ptr::write_volatile(
                    (block + MONITOR_TRACE_POINTER) as usize as *mut u32,
                    buffer.0,
                );
            }
        }
    }

    fn stop_dvd_trace(&mut self) -> Option<DvdTrace> {
        let end = match monitor_block() {
            Some(block) => {
                let pointer = (block + MONITOR_TRACE_POINTER) as usize
                    as *const core::sync::atomic::AtomicU32;
                // SAFETY: the write pointer is a naturally aligned word of the
                // debug monitor block, updated atomically by the driver.
                let end = unsafe { (*pointer).swap(0, core::sync::atomic::Ordering::SeqCst) };
                // SAFETY: as above.
                unsafe {
                    let flags = (block + MONITOR_FLAGS) as usize as *mut u32;
                    core::ptr::write_volatile(
                        flags,
                        core::ptr::read_volatile(flags) & !MONITOR_DVD_TRACE,
                    );
                }
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
/// drive.
pub(crate) fn service_set_drive_mapping(
    server: &mut openxbdm_server::Server,
    console: &mut Console,
    _network: &mut crate::net::XamNetwork,
    request: u32,
) -> u32 {
    commands::filesystem::map_title_drive(&mut server.state, console, request)
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
    openxbdm_core::status::Hresult::OK.0
}
export!(85, file_change_count);

import_thunk!(
    ObCreateSymbolicLink(link: *const AnsiString, target: *const AnsiString) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 0x103
);

const STATUS_OBJECT_NAME_COLLISION: u32 = 0xc000_0035;
/// `KeGetCurrentProcessType` of the system process.
const SYSTEM_PROCESS: u32 = 2;

/// Export 141 (stock 0x91f33438): link `E:` and `DEVKIT:` to the devkit
/// directory in the caller's process namespace. Existing links count as
/// success; the result is the HRESULT of the DOS error.
extern "C" fn map_devkit_drive() -> u32 {
    let (drive, devkit): (&[u8], &[u8]) = if kernel::KeGetCurrentProcessType() == SYSTEM_PROCESS {
        (b"\\system??\\E:", b"\\system??\\DEVKIT:")
    } else {
        (b"\\??\\E:", b"\\??\\DEVKIT:")
    };
    let target = ansi(b"\\Device\\Harddisk0\\Partition1\\DEVKIT");
    let mut status = ObCreateSymbolicLink(&ansi(drive), &target);
    if (status as i32) >= 0 || status == STATUS_OBJECT_NAME_COLLISION {
        status = match ObCreateSymbolicLink(&ansi(devkit), &target) {
            STATUS_OBJECT_NAME_COLLISION => 0,
            status => status,
        };
    }
    let error = kernel::RtlNtStatusToDosError(status);
    if (error as i32) > 0 {
        0x8007_0000 | (error & 0xffff)
    } else {
        error
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
        let resolved = kernel::module_handle(c"xboxkrnl.exe").is_ok_and(|module| {
            (kernel::XexGetProcedureAddress(module, KERNEL_ROUTINE_ORDINAL, &mut address) as i32)
                >= 0
        });
        routine = if resolved { address } else { 0 };
        KERNEL_ROUTINE.store(routine, Ordering::Release);
    }
    if routine == 0 {
        return ERROR_NOT_SUPPORTED;
    }
    // SAFETY: the kernel export takes five register arguments.
    let status = unsafe { call_five(routine, 0, a, b, c, d) };
    kernel::RtlNtStatusToDosError(status)
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
