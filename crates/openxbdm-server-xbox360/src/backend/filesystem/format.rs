//! XTAF volume formatting.

use openxbdm_core::status::KernelError;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::memory::PAGE_SIZE;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::DiskGeometry;
use xbox360_sys::xboxkrnl::FileDeviceType;
use xbox360_sys::xboxkrnl::FsDeviceInformation;
use xbox360_sys::xboxkrnl::FsInformationClass;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoControlCode;
use xbox360_sys::xboxkrnl::IoDismountVolumeByFileHandle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::NtQueryVolumeInformationFile;
use xbox360_sys::xboxkrnl::PartitionInformation;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::bytes_of_mut;
use super::device_control;
use super::open_file;
use super::pool::PoolBlock;

/// Volume header of an XTAF partition, at offset 0. Fields are big-endian.
#[repr(C)]
struct XtafHeader {
    magic: [u8; 4],
    serial_number: [u8; 4],
    sectors_per_cluster: [u8; 4],
    root_directory_cluster: [u8; 4],
    /// Purpose unknown; a new volume has 0.
    unknown_10: [u8; 2],
}

const _: () = {
    assert!(size_of::<XtafHeader>() == 0x12);
    assert!(align_of::<XtafHeader>() == 1);
};

impl XtafHeader {
    const MAGIC: [u8; 4] = *b"XTAF";

    /// The header at the start of `bytes`.
    fn at_start_of(bytes: &mut [u8]) -> &mut Self {
        let bytes = &mut bytes[..size_of::<Self>()];
        // SAFETY: `bytes` holds a header, which has alignment 1 and accepts
        // any bytes.
        unsafe { &mut *bytes.as_mut_ptr().cast::<Self>() }
    }
}

/// Format `device` as XTAF (0x91f72e58): header, FAT, and an empty root
/// directory cluster.
pub(super) fn format_xtaf(device: &[u8], cluster_size: u32) -> Result<(), KernelError> {
    const ACCESS: AccessMask = AccessMask::SYNCHRONIZE
        .union(AccessMask::READ_DATA)
        .union(AccessMask::WRITE_DATA);
    const OPTIONS: CreateOptions =
        CreateOptions::SYNCHRONOUS_IO_ALERT.union(CreateOptions::NO_INTERMEDIATE_BUFFERING);

    let handle = open_file(None, device, ACCESS, ShareAccess::empty(), OPTIONS)?;
    let result = format_open_volume(handle, cluster_size);

    // SAFETY: `handle` was opened above and is closed once.
    unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };

    result
}

fn format_open_volume(handle: FileHandle, cluster_size: u32) -> Result<(), KernelError> {
    /// Device type whose volumes the monitor formats with a 32-bit FAT
    /// whatever their size.
    const FORCE_FAT32: FileDeviceType = FileDeviceType(0x46);
    /// Clusters from which a volume gets a 32-bit FAT.
    const FAT32_CLUSTERS: u32 = 0xfff0;

    let mut io_status = IoStatusBlock::default();
    let mut device = FsDeviceInformation {
        device_type: FileDeviceType(0),
        characteristics: 0,
    };
    // SAFETY: `device` is a live local of the size passed.
    let raw = unsafe {
        NtQueryVolumeInformationFile(
            Handle::from_raw(handle.0),
            &mut io_status,
            (&raw mut device).cast(),
            size_of::<FsDeviceInformation>() as u32,
            FsInformationClass::Device,
        )
    };
    raw.result()?;

    let mut geometry = DiskGeometry::default();
    device_control(
        handle,
        IoControlCode::DISK_GET_DRIVE_GEOMETRY,
        // SAFETY: the geometry is two words.
        unsafe { bytes_of_mut(&mut geometry) },
    )?;
    let bytes_per_sector = geometry.bytes_per_sector;
    let sector_shift = if bytes_per_sector == 0 {
        0
    } else {
        31 - bytes_per_sector.leading_zeros()
    };

    let mut partition = PartitionInformation::default();
    device_control(
        handle,
        IoControlCode::DISK_GET_PARTITION_INFO,
        // SAFETY: the partition information is two doublewords.
        unsafe { bytes_of_mut(&mut partition) },
    )?;
    let length = partition.partition_length;
    if length == 0 {
        return Err(KernelError::ObjectNameNotFound);
    }

    let page = (bytes_per_sector + (PAGE_SIZE - 1)) & !(PAGE_SIZE - 1);
    let cluster = cluster_size.max(page);
    let header = page.max(PAGE_SIZE);
    if u64::from(header) >= length {
        return Err(KernelError::DiskFull);
    }

    let clusters = (length / u64::from(cluster)) as u32 + 1;
    let fat16 = clusters < FAT32_CLUSTERS && device.device_type != FORCE_FAT32;
    let entries = if fat16 {
        clusters.wrapping_mul(size_of::<u16>() as u32)
    } else {
        clusters.wrapping_mul(size_of::<u32>() as u32)
    };
    let fat = entries.wrapping_add(page - 1) & !(page - 1);
    let space = length - u64::from(header);
    if u64::from(fat) > space || u64::from(cluster) > space - u64::from(fat) {
        return Err(KernelError::DiskFull);
    }

    let result = {
        let Some(mut block) = PoolBlock::allocate(page) else {
            return Err(KernelError::InsufficientResources);
        };

        write_format(
            handle,
            block.bytes(),
            page,
            header,
            fat,
            cluster,
            fat16,
            sector_shift,
        )
    };

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
    /// Cluster of the root directory of a new XTAF volume.
    const ROOT_DIRECTORY_CLUSTER: u32 = 1;
    /// FAT entries 0 and 1 of a new volume: the media entry and the end of
    /// the root directory's chain.
    const FAT16_HEAD: [[u8; 2]; 2] = [0xfff8_u16.to_be_bytes(), 0xffff_u16.to_be_bytes()];
    const FAT32_HEAD: [[u8; 4]; 2] = [0xffff_fff8_u32.to_be_bytes(), 0xffff_ffff_u32.to_be_bytes()];

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
        raw.result()?;
        *offset += u64::from(page);

        Ok(())
    };

    buffer.fill(0);
    write(buffer, &mut offset)?;

    buffer.fill(0);
    offset = u64::from(header);
    if fat16 {
        buffer[..size_of_val(&FAT16_HEAD)].copy_from_slice(FAT16_HEAD.as_flattened());
    } else {
        buffer[..size_of_val(&FAT32_HEAD)].copy_from_slice(FAT32_HEAD.as_flattened());
    }
    let mut left = fat;

    while left != 0 {
        write(buffer, &mut offset)?;
        // The pages after the first hold free entries.
        buffer[..size_of_val(&FAT32_HEAD)].fill(0);
        left -= page;
    }

    buffer.fill(0xff);
    let mut left = cluster;

    while left != 0 {
        write(buffer, &mut offset)?;
        left -= page;
    }

    buffer.fill(0xff);
    let volume = XtafHeader::at_start_of(buffer);
    volume.magic = XtafHeader::MAGIC;
    volume.serial_number = (xbox360::time::FileTime::now().intervals() as u32).to_be_bytes();
    volume.sectors_per_cluster = ((cluster >> sector_shift) & 0xff).to_be_bytes();
    volume.root_directory_cluster = ROOT_DIRECTORY_CLUSTER.to_be_bytes();
    volume.unknown_10 = [0; 2];

    offset = 0;
    let mut left = header;

    while left != 0 {
        write(buffer, &mut offset)?;
        buffer.fill(0);
        left -= page;
    }

    Ok(())
}
