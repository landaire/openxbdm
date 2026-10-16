//! Kernel image flash writer (stock 0x91f735d0, `XapiFlashKernelImage`).
//!
//! Bytes 0x80..0x100 of flash and the patch block region are never written,
//! so the patch block already on flash survives a reflash.

use core::num::NonZeroU32;
use core::ptr::NonNull;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_server::commands::filesystem::CreateDisposition;
use openxbdm_server::commands::filesystem::FileAccess;

use super::FILE_SYNCHRONOUS_IO_NONALERT;
use super::POOL_TAG;
use crate::kernel;
use crate::kernel::AnsiString;
use crate::kernel::IoStatusBlock;
use crate::kernel::OBJ_CASE_INSENSITIVE;
use crate::kernel::ObjectAttributes;

const DEVICE_NAME: &[u8] = b"\\Device\\Flash\0";
/// Returns the 0x14-byte flash geometry; dwords 0 and 2 multiply to the
/// device write unit.
const IOCTL_FLASH_GEOMETRY: u32 = 0x003c_0028;
const GEOMETRY_SIZE: u32 = 0x14;
const PAGE_SIZE: u32 = 0x4000;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 4;
/// `MmAllocatePhysicalMemory` protection of the boot loader buffer.
const BOOT_LOADER_PROTECT: u32 = 0x2000_0004;
const ERROR_BAD_FORMAT: Win32Error = Win32Error::new(0xb).unwrap();
const ERROR_REVISION_MISMATCH: Win32Error = Win32Error::new(0x51a).unwrap();
const HEADER_WRITE_SIZE: u32 = 0x80;
const BODY_START: u32 = 0x100;
/// Stock traps when the patch block ends past this offset but continues.
const PATCH_LIMIT: u32 = 0x2_0000;

/// Header word: image offset of the 16-bit hardware identifier.
const HEADER_HARDWARE_ID_OFFSET: usize = 0x08;
/// Header word: boot loader size passed to `XeKeysSaveBootLoader`.
const HEADER_BOOT_LOADER_SIZE: usize = 0x0c;
/// Header word: patch block size; 0 means `PAGE_SIZE`.
const HEADER_PATCH_SIZE: usize = 0x60;
/// Header word rounded up to the write unit and copied to
/// `HEADER_BOOT_LOADER_SIZE`.
const HEADER_LOADER_EXTENT: usize = 0x64;
/// Header half-word that must match the flash copy to reuse its patch block.
const HEADER_PATCH_VERSION: usize = 0x6a;
/// Header word: flash offset of the patch block; 0 means none.
const HEADER_PATCH_OFFSET: usize = 0x6c;
/// Header word of unknown purpose: rounded up to the write unit, and when 0
/// no header word is rounded.
const HEADER_FIELD_70: usize = 0x70;

/// Pool buffer holding a `flash` upload.
pub struct FlashImage {
    base: NonNull<u8>,
    size: u32,
}

impl FlashImage {
    /// Allocate `rounded_size` bytes (a multiple of 0x4000). None on allocation failure.
    pub fn allocate(rounded_size: u32) -> Option<Self> {
        let address = kernel::ExAllocatePoolWithTag(rounded_size, POOL_TAG);
        NonNull::new(address as usize as *mut u8).map(|base| Self {
            base,
            size: rounded_size,
        })
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the pool block is `size` bytes and owned by `self`.
        unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr(), self.size as usize) }
    }

    /// Write the image to flash.
    pub fn program(
        &mut self,
        ignore_version_checking: bool,
        stock_image: bool,
    ) -> Result<(), Win32Error> {
        let image = Image {
            base: self.base.as_ptr(),
        };
        let mut buffers = Buffers::default();
        let result = flash_kernel_image(
            image,
            self.size,
            ignore_version_checking,
            stock_image,
            &mut buffers,
        );
        buffers.release();
        match result {
            Ok(()) => Ok(()),
            Err(Failure::Kernel(error)) => {
                match Win32Error::new(kernel::RtlNtStatusToDosError(error.status().0)) {
                    Some(error) => Err(error),
                    None => Ok(()),
                }
            }
            Err(Failure::Win32(error)) => Err(error),
        }
    }
}

impl Drop for FlashImage {
    fn drop(&mut self) {
        kernel::ExFreePool(self.base.as_ptr() as usize as u32);
    }
}

enum Failure {
    /// Reported through `RtlNtStatusToDosError`.
    Kernel(KernelError),
    Win32(Win32Error),
}

impl From<KernelError> for Failure {
    fn from(error: KernelError) -> Self {
        Self::Kernel(error)
    }
}

/// Buffers released when the writer returns, in this order.
#[derive(Default)]
struct Buffers {
    patch: Option<NonZeroU32>,
    boot_loader: Option<NonZeroU32>,
}

impl Buffers {
    fn release(self) {
        if let Some(patch) = self.patch {
            let mut base = patch.get();
            let mut size = 0;
            kernel::NtFreeVirtualMemory(&mut base, &mut size, MEM_RELEASE, 0);
        }
        if let Some(boot_loader) = self.boot_loader {
            kernel::MmFreePhysicalMemory(0, boot_loader.get());
        }
    }
}

/// Big-endian header access. Offsets come from the image itself and are not
/// bounded by the buffer, as in stock.
#[derive(Clone, Copy)]
struct Image {
    base: *mut u8,
}

impl Image {
    fn word(self, offset: usize) -> u32 {
        // SAFETY: stock reads the same address.
        u32::from_be_bytes(unsafe { self.base.wrapping_add(offset).cast::<[u8; 4]>().read() })
    }

    fn half(self, offset: usize) -> u16 {
        // SAFETY: stock reads the same address.
        u16::from_be_bytes(unsafe { self.base.wrapping_add(offset).cast::<[u8; 2]>().read() })
    }

    fn set_word(self, offset: usize, value: u32) {
        // SAFETY: stock writes the same address.
        unsafe {
            self.base
                .wrapping_add(offset)
                .cast::<[u8; 4]>()
                .write(value.to_be_bytes())
        };
    }

    fn patch_size(self) -> u32 {
        match self.word(HEADER_PATCH_SIZE) {
            0 => PAGE_SIZE,
            declared => declared,
        }
    }
}

/// Location of the patch block kept from the current flash contents.
#[derive(Clone, Copy)]
enum PatchBlock {
    Absent,
    Present { offset: NonZeroU32, moved: bool },
}

impl PatchBlock {
    fn offset(self) -> Option<NonZeroU32> {
        match self {
            Self::Absent => None,
            Self::Present { offset, .. } => Some(offset),
        }
    }
}

fn trap_patch_layout() {
    // SAFETY: the same trap stock executes; the kernel resumes after it.
    unsafe { core::arch::asm!("twi 31, 0, 0x19") };
}

fn flash_kernel_image(
    image: Image,
    size: u32,
    ignore_version_checking: bool,
    stock_image: bool,
    buffers: &mut Buffers,
) -> Result<(), Failure> {
    if size & (PAGE_SIZE - 1) != 0 {
        return Err(KernelError::InvalidParameter.into());
    }
    if !ignore_version_checking && !hardware_matches(image) {
        return Err(Failure::Win32(ERROR_REVISION_MISMATCH));
    }
    align_to_write_unit(image)?;

    let mut patch_size = image.patch_size();
    let mut patch_base = 0;
    let status = kernel::NtAllocateVirtualMemory(
        &mut patch_base,
        &mut patch_size,
        MEM_COMMIT,
        PAGE_READWRITE,
        0,
    );
    buffers.patch = NonZeroU32::new(patch_base);
    NtStatus(status).result()?;

    let patch = match read_patch_block(image, patch_base as usize as *mut u8, patch_size) {
        Some(patch) => patch,
        // Stock continues with the cleared outputs, so no region is kept.
        None if ignore_version_checking => PatchBlock::Absent,
        None => return Err(Failure::Win32(ERROR_BAD_FORMAT)),
    };
    if let PatchBlock::Present {
        offset,
        moved: true,
    } = patch
    {
        device_write(offset.get(), patch_base as usize as *const u8, patch_size)?;
    }
    write_ranges(image.base, size, patch.offset(), patch_size)?;
    if stock_image {
        return Ok(());
    }

    let mut loader_size = image.word(HEADER_BOOT_LOADER_SIZE);
    let mut flags = 0;
    let loader = NonZeroU32::new(kernel::MmAllocatePhysicalMemory(
        0,
        loader_size,
        BOOT_LOADER_PROTECT,
    ))
    .ok_or(KernelError::NoMemory)?;
    buffers.boot_loader = Some(loader);
    let status = kernel::XeKeysSaveBootLoader(&mut flags, &mut loader_size, loader.get());
    if !NtStatus(status).is_success() || flags != 0 {
        // Stock reports this only on the debug output and returns success.
        kernel::debug_print(
            c"WRN[XAPI]: XapiFlashKernelImage(): unable to reencrypt boot loader\n",
        );
        return Ok(());
    }
    write_ranges(
        loader.get() as usize as *const u8,
        loader_size,
        patch.offset(),
        patch_size,
    )?;
    Ok(())
}

/// Stock 0x91f73260.
fn hardware_matches(image: Image) -> bool {
    let identifier = image.half(image.word(HEADER_HARDWARE_ID_OFFSET) as usize);
    if kernel::hardware_flags() & 3 == 3 {
        identifier & 0xfff == 0x342
    } else {
        identifier == 0
    }
}

/// Stock 0x91f732a8.
fn align_to_write_unit(image: Image) -> Result<(), KernelError> {
    let mut device = Device::open_read()?;
    let unit = device.write_unit()?;
    let field_70 = image.word(HEADER_FIELD_70);
    if unit > PAGE_SIZE && field_70 != 0 {
        let mask = !(unit - 1);
        let extent = image.word(HEADER_LOADER_EXTENT).wrapping_add(unit - 1) & mask;
        image.set_word(HEADER_LOADER_EXTENT, extent);
        image.set_word(HEADER_FIELD_70, field_70.wrapping_add(unit - 1) & mask);
        image.set_word(HEADER_BOOT_LOADER_SIZE, extent);
    }
    Ok(())
}

/// Stock 0x91f733b8: read the patch block of the current flash contents into
/// `buffer`. None when the flash header does not describe a compatible one.
fn read_patch_block(image: Image, buffer: *mut u8, size: u32) -> Option<PatchBlock> {
    let Some(offset) = NonZeroU32::new(image.word(HEADER_PATCH_OFFSET)) else {
        return Some(PatchBlock::Absent);
    };
    let mut header = [0u8; HEADER_WRITE_SIZE as usize];
    device_read(0, header.as_mut_ptr(), HEADER_WRITE_SIZE).ok()?;
    let current = Image {
        base: header.as_mut_ptr(),
    };
    let current_offset = NonZeroU32::new(current.word(HEADER_PATCH_OFFSET))?;
    if current.half(HEADER_PATCH_VERSION) != image.half(HEADER_PATCH_VERSION) {
        return None;
    }
    let current_size = current.patch_size();
    if current_size != size {
        return None;
    }
    device_read(current_offset.get(), buffer, size).ok()?;
    Some(PatchBlock::Present {
        offset,
        moved: current_offset != offset,
    })
}

/// Stock 0x91f734a0 with no progress routine; the `flash` command passes
/// none, which also makes the 0x20000-byte chunked path unreachable.
fn write_ranges(
    buffer: *const u8,
    total: u32,
    patch: Option<NonZeroU32>,
    patch_size: u32,
) -> Result<(), KernelError> {
    if patch.is_some_and(|offset| offset.get() < BODY_START) {
        trap_patch_layout();
        return Err(KernelError::InvalidParameter);
    }
    // Stock adds the size to a zero offset when there is no patch block.
    let patch_end = patch.map_or(0, NonZeroU32::get).wrapping_add(patch_size);
    if patch_end > PATCH_LIMIT {
        trap_patch_layout();
    }
    device_write(0, buffer, HEADER_WRITE_SIZE)?;
    let resume = match patch {
        None => BODY_START,
        Some(offset) => {
            device_write(
                BODY_START,
                buffer.wrapping_add(BODY_START as usize),
                offset.get() - BODY_START,
            )?;
            patch_end
        }
    };
    // A total below `resume` wraps to a huge length, as in stock.
    device_write(
        resume,
        buffer.wrapping_add(resume as usize),
        total.wrapping_sub(resume),
    )
}

/// `\Device\Flash`, opened per operation as stock does.
struct Device {
    handle: u32,
    io_status: IoStatusBlock,
}

impl Device {
    fn attributes(name: &AnsiString) -> ObjectAttributes {
        ObjectAttributes {
            root_directory: 0,
            object_name: name,
            attributes: OBJ_CASE_INSENSITIVE,
        }
    }

    fn name() -> AnsiString {
        let length = (DEVICE_NAME.len() - 1) as u16;
        AnsiString {
            length,
            maximum_length: length + 1,
            buffer: DEVICE_NAME.as_ptr(),
        }
    }

    fn open_read() -> Result<Self, KernelError> {
        let name = Self::name();
        let attributes = Self::attributes(&name);
        let mut device = Self {
            handle: 0,
            io_status: IoStatusBlock::default(),
        };
        NtStatus(kernel::NtOpenFile(
            &mut device.handle,
            FileAccess::GENERIC_READ.union(FileAccess::SYNCHRONIZE).0,
            &attributes,
            &mut device.io_status,
            0,
            FILE_SYNCHRONOUS_IO_NONALERT,
        ))
        .result()?;
        Ok(device)
    }

    fn open_read_write() -> Result<Self, KernelError> {
        let name = Self::name();
        let attributes = Self::attributes(&name);
        let mut device = Self {
            handle: 0,
            io_status: IoStatusBlock::default(),
        };
        NtStatus(kernel::NtCreateFile(
            &mut device.handle,
            FileAccess::GENERIC_READ
                .union(FileAccess::GENERIC_WRITE)
                .union(FileAccess::SYNCHRONIZE)
                .0,
            &attributes,
            &mut device.io_status,
            core::ptr::null(),
            0,
            0,
            CreateDisposition::Open as u32,
            FILE_SYNCHRONOUS_IO_NONALERT,
        ))
        .result()?;
        Ok(device)
    }

    fn write_unit(&mut self) -> Result<u32, KernelError> {
        let mut geometry = [0u32; GEOMETRY_SIZE as usize / 4];
        NtStatus(kernel::NtDeviceIoControlFile(
            self.handle,
            0,
            0,
            0,
            &mut self.io_status,
            IOCTL_FLASH_GEOMETRY,
            core::ptr::null(),
            0,
            geometry.as_mut_ptr().cast(),
            GEOMETRY_SIZE,
        ))
        .result()?;
        Ok(geometry[0].wrapping_mul(geometry[2]))
    }

    fn read(&mut self, buffer: *mut u8, length: u32, offset: u64) -> Result<(), KernelError> {
        NtStatus(kernel::NtReadFile(
            self.handle,
            0,
            0,
            0,
            &mut self.io_status,
            buffer,
            length,
            &offset,
        ))
        .result()
    }

    fn write(&mut self, buffer: *const u8, length: u32, offset: u64) -> Result<(), KernelError> {
        NtStatus(kernel::NtWriteFile(
            self.handle,
            0,
            0,
            0,
            &mut self.io_status,
            buffer,
            length,
            &offset,
        ))
        .result()
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        kernel::NtClose(self.handle);
    }
}

/// Stock 0x91f72bd0.
pub(in crate::backend) fn device_read(
    offset: u32,
    buffer: *mut u8,
    length: u32,
) -> Result<(), KernelError> {
    Device::open_read_write()?.read(buffer, length, u64::from(offset))
}

/// Unit-sized bounce buffer for partial-unit writes, allocated on first use.
struct Scratch {
    base: Option<NonZeroU32>,
    size: u32,
}

impl Scratch {
    fn page(&mut self) -> Result<*mut u8, KernelError> {
        if let Some(base) = self.base {
            return Ok(base.get() as usize as *mut u8);
        }
        let mut base = 0;
        let status = kernel::NtAllocateVirtualMemory(
            &mut base,
            &mut self.size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
            0,
        );
        self.base = NonZeroU32::new(base);
        NtStatus(status).result()?;
        Ok(base as usize as *mut u8)
    }

    /// Stock passes the size the allocation reported.
    fn release(mut self) {
        if let Some(base) = self.base {
            let mut base = base.get();
            kernel::NtFreeVirtualMemory(&mut base, &mut self.size, MEM_RELEASE, 0);
        }
    }
}

/// Stock 0x91f72c78: whole units are written from `source`; partial units
/// are read, merged, and written back.
pub(in crate::backend) fn device_write(
    offset: u32,
    source: *const u8,
    length: u32,
) -> Result<(), KernelError> {
    let mut device = Device::open_read_write()?;
    let unit = device.write_unit()?;
    let mut scratch = Scratch {
        base: None,
        size: unit,
    };
    let result = write_units(&mut device, unit, &mut scratch, offset, source, length);
    scratch.release();
    result
}

fn write_units(
    device: &mut Device,
    unit: u32,
    scratch: &mut Scratch,
    mut offset: u32,
    mut source: *const u8,
    mut length: u32,
) -> Result<(), KernelError> {
    while length != 0 {
        let misalignment = offset & unit.wrapping_sub(1);
        let (data, position, chunk) = if misalignment == 0 && length >= unit {
            (source, offset, unit)
        } else {
            let chunk = unit.wrapping_sub(misalignment).min(length);
            let page = scratch.page()?;
            let position = offset.wrapping_sub(misalignment);
            device.read(page, unit, u64::from(position))?;
            // SAFETY: stock copies the same range into its unit-sized buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    source,
                    page.wrapping_add(misalignment as usize),
                    chunk as usize,
                )
            };
            (page.cast_const(), position, chunk)
        };
        device.write(data, unit, u64::from(position))?;
        length -= chunk;
        offset = offset.wrapping_add(chunk);
        source = source.wrapping_add(chunk as usize);
    }
    Ok(())
}
