//! Kernel image flash writer (stock 0x91f735d0, `XapiFlashKernelImage`).
//!
//! Bytes 0x80..0x100 of flash and the patch block region are never written,
//! so the patch block already on flash survives a reflash.
//!
//! Deviation: stock trusts the offsets and sizes in the image header and
//! reads past the upload or boot loader buffer when they leave it. This
//! writer checks them and fails instead:
//! - An image shorter than its 0x80-byte header fails with
//!   `ERROR_INVALID_PARAMETER` before any write.
//! - A hardware identifier offset outside the image does not match, so the
//!   write fails with `ERROR_REVISION_MISMATCH` unless version checking is
//!   off.
//! - A range that leaves its buffer fails with `ERROR_INVALID_PARAMETER`
//!   when its write comes up; earlier writes stay. These are a patch block
//!   offset past the end of the image, an image or boot loader that ends
//!   before the body or the end of the patch block, a boot loader shorter
//!   than the header, and a boot loader size from `XeKeysSaveBootLoader`
//!   above the allocated size.

mod error;

use core::num::NonZeroU32;
use core::ptr::NonNull;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use xbox360::console::hardware_flags;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::AllocationType;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::IoControlCode;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::MemoryRegion;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::ShareAccess;

use crate::kernel;
use crate::kernel::pool_tag;

use self::error::Failure;

const PAGE_SIZE: u32 = 0x4000;

/// Bytes of the header that a reflash writes.
const HEADER_WRITE_SIZE: usize = size_of::<ImageHeader>();

/// A big-endian word of an image header.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct Be32([u8; 4]);

impl Be32 {
    fn get(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    fn set(&mut self, value: u32) {
        self.0 = value.to_be_bytes();
    }
}

/// A big-endian halfword of an image header.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct Be16([u8; 2]);

impl Be16 {
    fn get(self) -> u16 {
        u16::from_be_bytes(self.0)
    }
}

/// The header of a kernel image, the part of flash a reflash writes first.
/// Every field is bytes, so any bytes form a header.
#[repr(C)]
struct ImageHeader {
    _reserved_00: [u8; 8],
    /// Image offset of the 16-bit hardware identifier.
    hardware_id_offset: Be32,
    /// Boot loader size passed to `XeKeysSaveBootLoader`.
    boot_loader_size: Be32,
    _reserved_10: [u8; 0x50],
    /// Patch block size; 0 means `PAGE_SIZE`.
    patch_size: Be32,
    /// Rounded up to the write unit and copied to `boot_loader_size`.
    loader_extent: Be32,
    _reserved_68: [u8; 2],
    /// Must match the flash copy to reuse its patch block.
    patch_version: Be16,
    /// Flash offset of the patch block; 0 means none.
    patch_offset: Be32,
    /// Purpose unknown: rounded up to the write unit, and when 0 no header
    /// word is rounded.
    unknown_70: Be32,
    _reserved_74: [u8; 0xc],
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(ImageHeader, hardware_id_offset) == 0x08);
    assert!(offset_of!(ImageHeader, boot_loader_size) == 0x0c);
    assert!(offset_of!(ImageHeader, patch_size) == 0x60);
    assert!(offset_of!(ImageHeader, loader_extent) == 0x64);
    assert!(offset_of!(ImageHeader, patch_version) == 0x6a);
    assert!(offset_of!(ImageHeader, patch_offset) == 0x6c);
    assert!(offset_of!(ImageHeader, unknown_70) == 0x70);
    assert!(size_of::<ImageHeader>() == 0x80);
    assert!(align_of::<ImageHeader>() == 1);
};

impl ImageHeader {
    const EMPTY: Self = Self {
        _reserved_00: [0; 8],
        hardware_id_offset: Be32([0; 4]),
        boot_loader_size: Be32([0; 4]),
        _reserved_10: [0; 0x50],
        patch_size: Be32([0; 4]),
        loader_extent: Be32([0; 4]),
        _reserved_68: [0; 2],
        patch_version: Be16([0; 2]),
        patch_offset: Be32([0; 4]),
        unknown_70: Be32([0; 4]),
        _reserved_74: [0; 0xc],
    };

    fn patch_size(&self) -> u32 {
        match self.patch_size.get() {
            0 => PAGE_SIZE,
            declared => declared,
        }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8; HEADER_WRITE_SIZE] {
        // SAFETY: the header is `HEADER_WRITE_SIZE` bytes of alignment 1,
        // and any bytes form a header.
        unsafe { &mut *core::ptr::from_mut(self).cast() }
    }
}

/// A kernel image of at least a header.
struct Image<'a>(&'a mut [u8]);

impl<'a> Image<'a> {
    /// None for an image shorter than the header (a deviation: stock reads
    /// the header past the buffer).
    fn new(bytes: &'a mut [u8]) -> Option<Self> {
        (bytes.len() >= HEADER_WRITE_SIZE).then_some(Self(bytes))
    }

    fn header(&self) -> &ImageHeader {
        // SAFETY: the image holds a header (checked in `new`), which has
        // alignment 1 and accepts any bytes.
        unsafe { &*self.0.as_ptr().cast() }
    }

    fn header_mut(&mut self) -> &mut ImageHeader {
        // SAFETY: as in `header`.
        unsafe { &mut *self.0.as_mut_ptr().cast() }
    }
}

/// Pool buffer holding a `flash` upload.
pub struct FlashImage {
    base: NonNull<u8>,
    size: u32,
}

impl FlashImage {
    /// Allocate `rounded_size` bytes (a multiple of 0x4000). None on allocation failure.
    pub fn allocate(rounded_size: u32) -> Option<Self> {
        // SAFETY: the allocation takes only a size and tag.
        let address = unsafe { xboxkrnl::ExAllocatePoolWithTag(rounded_size, pool_tag::BUFFER) };
        NonNull::new(core::ptr::with_exposed_provenance_mut(address as usize)).map(|base| Self {
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
        let mut buffers = Buffers::default();
        let result = flash_kernel_image(
            self.bytes_mut(),
            ignore_version_checking,
            stock_image,
            &mut buffers,
        );
        buffers.release();
        match result {
            Ok(()) => Ok(()),
            Err(Failure::Kernel(error)) => xbox360::status::dos_error(error).map_or(Ok(()), Err),
            Err(Failure::Win32(error)) => Err(error),
        }
    }
}

impl Drop for FlashImage {
    fn drop(&mut self) {
        // SAFETY: `base` is the pool block `allocate` returned and `self` owns it.
        unsafe { xboxkrnl::ExFreePool(self.base.as_ptr().expose_provenance() as u32) };
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
            // SAFETY: `patch` is the virtual allocation of the writer.
            unsafe {
                xboxkrnl::NtFreeVirtualMemory(&mut base, &mut size, AllocationType::RELEASE, 0)
            };
        }
        if let Some(boot_loader) = self.boot_loader {
            // SAFETY: `boot_loader` is the physical allocation of the writer.
            unsafe {
                xboxkrnl::MmFreePhysicalMemory(MemoryRegion::CurrentProcess, boot_loader.get())
            };
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

/// `\Device\Flash`, opened per operation as stock does.
struct Device {
    handle: Handle,
    io_status: IoStatusBlock,
}

impl Device {
    fn attributes(name: &AnsiString) -> ObjectAttributes {
        ObjectAttributes {
            root_directory: Handle::NULL,
            object_name: name,
            attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
        }
    }

    fn name() -> AnsiString {
        const DEVICE_NAME: &[u8] = b"\\Device\\Flash\0";

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
            handle: Handle::NULL,
            io_status: IoStatusBlock::default(),
        };
        // SAFETY: `attributes` refers to the static device name; the handle
        // and status block are fields of the local `device`.
        unsafe {
            xboxkrnl::NtOpenFile(
                &mut device.handle,
                AccessMask::GENERIC_READ | AccessMask::SYNCHRONIZE,
                &attributes,
                &mut device.io_status,
                ShareAccess::empty(),
                CreateOptions::SYNCHRONOUS_IO_NONALERT,
            )
        }
        .result()?;

        Ok(device)
    }

    fn open_read_write() -> Result<Self, KernelError> {
        let name = Self::name();
        let attributes = Self::attributes(&name);
        let mut device = Self {
            handle: Handle::NULL,
            io_status: IoStatusBlock::default(),
        };
        // SAFETY: as in `open_read`.
        unsafe {
            xboxkrnl::NtCreateFile(
                &mut device.handle,
                AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE | AccessMask::SYNCHRONIZE,
                &attributes,
                &mut device.io_status,
                core::ptr::null(),
                FileAttributes::empty(),
                ShareAccess::empty(),
                xboxkrnl::CreateDisposition::Open,
                CreateOptions::SYNCHRONOUS_IO_NONALERT,
            )
        }
        .result()?;

        Ok(device)
    }

    /// Bytes of the unit the device writes: the product of geometry words 0
    /// and 2.
    fn write_unit(&mut self) -> Result<u32, KernelError> {
        /// Bytes of the `IoControlCode::FLASH_GEOMETRY` output.
        const GEOMETRY_SIZE: u32 = 0x14;

        let mut geometry = [0u32; GEOMETRY_SIZE as usize / 4];
        // SAFETY: the handle is open and `geometry` holds GEOMETRY_SIZE bytes.
        unsafe {
            xboxkrnl::NtDeviceIoControlFile(
                self.handle,
                Handle::NULL,
                0,
                0,
                &mut self.io_status,
                IoControlCode::FLASH_GEOMETRY,
                core::ptr::null(),
                0,
                geometry.as_mut_ptr().cast(),
                GEOMETRY_SIZE,
            )
        }
        .result()?;

        Ok(geometry[0].wrapping_mul(geometry[2]))
    }

    fn read(&mut self, buffer: &mut [u8], offset: u64) -> Result<(), KernelError> {
        // SAFETY: the handle is open; the device is synchronous, so the
        // kernel writes `buffer` only during the call.
        unsafe {
            xboxkrnl::NtReadFile(
                self.handle,
                Handle::NULL,
                0,
                0,
                &mut self.io_status,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &offset,
            )
        }
        .result()
    }

    fn write(&mut self, data: &[u8], offset: u64) -> Result<(), KernelError> {
        // SAFETY: as in `read`.
        unsafe {
            xboxkrnl::NtWriteFile(
                self.handle,
                Handle::NULL,
                0,
                0,
                &mut self.io_status,
                data.as_ptr(),
                data.len() as u32,
                &offset,
            )
        }
        .result()
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: `self` owns the open device handle.
        unsafe { xboxkrnl::NtClose(self.handle) };
    }
}

/// Unit-sized bounce buffer for partial-unit writes, allocated on first use.
struct Scratch {
    base: Option<NonZeroU32>,
    /// The size to allocate, then the size the allocation reported.
    size: u32,
    unit: u32,
}

impl Scratch {
    fn page(&mut self) -> Result<&mut [u8], KernelError> {
        let base = match self.base {
            Some(base) => base.get(),
            None => {
                let mut base = 0;
                // SAFETY: `base` and `self.size` are live.
                let status = unsafe {
                    xboxkrnl::NtAllocateVirtualMemory(
                        &mut base,
                        &mut self.size,
                        AllocationType::COMMIT | AllocationType::RESERVE,
                        PageProtection::READWRITE,
                        MemoryRegion::CurrentProcess,
                    )
                };
                self.base = NonZeroU32::new(base);
                status.result()?;
                base
            }
        };
        // SAFETY: the allocation holds at least the `unit` bytes requested,
        // and `self` lends them for the borrow.
        Ok(unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::with_exposed_provenance_mut(base as usize),
                self.unit as usize,
            )
        })
    }

    /// Stock passes the size the allocation reported.
    fn release(mut self) {
        if let Some(base) = self.base {
            let mut base = base.get();
            // SAFETY: `base` is the allocation `page` made.
            unsafe {
                xboxkrnl::NtFreeVirtualMemory(&mut base, &mut self.size, AllocationType::RELEASE, 0)
            };
        }
    }
}

fn trap_patch_layout() {
    // SAFETY: the same trap stock executes; the kernel resumes after it.
    unsafe { core::arch::asm!("twi 31, 0, 0x19") };
}

/// `bytes[start..end]`. Deviation: stock reads past the buffer when header
/// offsets leave it; this fails instead.
fn range(bytes: &[u8], start: u32, end: Option<u32>) -> Result<&[u8], KernelError> {
    match end {
        Some(end) => bytes.get(start as usize..end as usize),
        None => bytes.get(start as usize..),
    }
    .ok_or(KernelError::InvalidParameter)
}

fn flash_kernel_image(
    image: &mut [u8],
    ignore_version_checking: bool,
    stock_image: bool,
    buffers: &mut Buffers,
) -> Result<(), Failure> {
    /// `MmAllocatePhysicalMemory` protection of the boot loader buffer.
    const BOOT_LOADER_PROTECT: PageProtection =
        PageProtection::READWRITE.union(PageProtection::LARGE_PAGES);

    if image.len() as u32 & (PAGE_SIZE - 1) != 0 {
        return Err(KernelError::InvalidParameter.into());
    }

    let mut image = Image::new(image).ok_or(KernelError::InvalidParameter)?;
    if !ignore_version_checking && !hardware_matches(&image) {
        return Err(Failure::Win32(Win32Error::REVISION_MISMATCH));
    }

    align_to_write_unit(&mut image)?;

    let mut patch_size = image.header().patch_size();
    let mut patch_base = 0;
    // SAFETY: `patch_base` and `patch_size` are live locals.
    let status = unsafe {
        xboxkrnl::NtAllocateVirtualMemory(
            &mut patch_base,
            &mut patch_size,
            AllocationType::COMMIT,
            PageProtection::READWRITE,
            MemoryRegion::CurrentProcess,
        )
    };
    buffers.patch = NonZeroU32::new(patch_base);
    status.result()?;
    // SAFETY: the kernel committed `patch_size` bytes at `patch_base`, which
    // `buffers` releases only after the writer returns.
    let patch_buffer = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::with_exposed_provenance_mut::<u8>(patch_base as usize),
            patch_size as usize,
        )
    };

    let patch = match read_patch_block(image.header(), patch_buffer) {
        Some(patch) => patch,
        // Stock continues with the cleared outputs, so no region is kept.
        None if ignore_version_checking => PatchBlock::Absent,
        None => return Err(Failure::Win32(Win32Error::BAD_FORMAT)),
    };
    if let PatchBlock::Present {
        offset,
        moved: true,
    } = patch
    {
        device_write(offset.get(), patch_buffer)?;
    }
    write_ranges(image.0, patch.offset(), patch_size)?;
    if stock_image {
        return Ok(());
    }

    let allocated = image.header().boot_loader_size.get();
    let mut loader_size = allocated;
    let mut flags = 0;
    // SAFETY: the allocation takes only a size and protection.
    let loader = NonZeroU32::new(unsafe {
        xboxkrnl::MmAllocatePhysicalMemory(0, loader_size, BOOT_LOADER_PROTECT)
    })
    .ok_or(KernelError::NoMemory)?;
    buffers.boot_loader = Some(loader);
    // SAFETY: `flags` and `loader_size` are live locals; `loader` holds
    // `loader_size` bytes.
    let status =
        unsafe { xboxkrnl::XeKeysSaveBootLoader(&mut flags, &mut loader_size, loader.get()) };
    if !status.is_success() || flags != 0 {
        // Stock reports this only on the debug output and returns success.
        kernel::debug_print(
            c"WRN[XAPI]: XapiFlashKernelImage(): unable to reencrypt boot loader\n",
        );
        return Ok(());
    }

    // SAFETY: the physical allocation holds `allocated` bytes, which
    // `buffers` releases only after the writer returns.
    let loader = unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance::<u8>(loader.get() as usize),
            allocated as usize,
        )
    };
    // Deviation: a size above the allocation fails instead of reading past it.
    write_ranges(
        range(loader, 0, Some(loader_size))?,
        patch.offset(),
        patch_size,
    )?;

    Ok(())
}

/// Stock 0x91f73260. Deviation: an identifier offset outside the image does
/// not match; stock reads past the image.
fn hardware_matches(image: &Image<'_>) -> bool {
    /// Hardware flag bits that select the identifier check; their kernel
    /// meaning is unknown.
    const IDENTIFIED_HARDWARE: HardwareFlags = HardwareFlags::from_bits_retain(0x3);
    const IDENTIFIER_MASK: u16 = 0xfff;
    const IDENTIFIER: u16 = 0x342;

    let offset = image.header().hardware_id_offset.get() as usize;
    let Some(&identifier) = image.0.get(offset..).and_then(<[u8]>::first_chunk::<2>) else {
        return false;
    };

    let identifier = u16::from_be_bytes(identifier);
    if hardware_flags().contains(IDENTIFIED_HARDWARE) {
        identifier & IDENTIFIER_MASK == IDENTIFIER
    } else {
        identifier == 0
    }
}

/// Stock 0x91f732a8.
fn align_to_write_unit(image: &mut Image<'_>) -> Result<(), KernelError> {
    let mut device = Device::open_read()?;
    let unit = device.write_unit()?;
    let header = image.header_mut();
    let field_70 = header.unknown_70.get();
    if unit > PAGE_SIZE && field_70 != 0 {
        let mask = !(unit - 1);
        let extent = header.loader_extent.get().wrapping_add(unit - 1) & mask;
        header.loader_extent.set(extent);
        header
            .unknown_70
            .set(field_70.wrapping_add(unit - 1) & mask);
        header.boot_loader_size.set(extent);
    }

    Ok(())
}

/// Stock 0x91f733b8: read the patch block of the current flash contents into
/// `buffer`. None when the flash header does not describe a compatible one.
fn read_patch_block(image: &ImageHeader, buffer: &mut [u8]) -> Option<PatchBlock> {
    let Some(offset) = NonZeroU32::new(image.patch_offset.get()) else {
        return Some(PatchBlock::Absent);
    };

    let mut current = ImageHeader::EMPTY;
    device_read(0, current.as_bytes_mut()).ok()?;
    let current_offset = NonZeroU32::new(current.patch_offset.get())?;
    if current.patch_version.get() != image.patch_version.get() {
        return None;
    }

    if current.patch_size() != buffer.len() as u32 {
        return None;
    }

    device_read(current_offset.get(), buffer).ok()?;
    Some(PatchBlock::Present {
        offset,
        moved: current_offset != offset,
    })
}

/// Stock 0x91f734a0 with no progress routine; the `flash` command passes
/// none, which also makes the 0x20000-byte chunked path unreachable.
fn write_ranges(
    buffer: &[u8],
    patch: Option<NonZeroU32>,
    patch_size: u32,
) -> Result<(), KernelError> {
    /// Stock traps when the patch block ends past this offset but continues.
    const PATCH_LIMIT: u32 = 0x2_0000;
    const BODY_START: u32 = 0x100;

    if patch.is_some_and(|offset| offset.get() < BODY_START) {
        trap_patch_layout();
        return Err(KernelError::InvalidParameter);
    }

    // Stock adds the size to a zero offset when there is no patch block.
    let patch_end = patch.map_or(0, NonZeroU32::get).wrapping_add(patch_size);
    if patch_end > PATCH_LIMIT {
        trap_patch_layout();
    }
    device_write(0, range(buffer, 0, Some(HEADER_WRITE_SIZE as u32))?)?;
    let resume = match patch {
        None => BODY_START,
        Some(offset) => {
            device_write(BODY_START, range(buffer, BODY_START, Some(offset.get()))?)?;
            patch_end
        }
    };

    device_write(resume, range(buffer, resume, None)?)
}

/// Stock 0x91f72bd0.
pub(in crate::backend) fn device_read(offset: u32, buffer: &mut [u8]) -> Result<(), KernelError> {
    Device::open_read_write()?.read(buffer, u64::from(offset))
}

/// Stock 0x91f72c78: whole units are written from `source`; partial units
/// are read, merged, and written back.
pub(in crate::backend) fn device_write(offset: u32, source: &[u8]) -> Result<(), KernelError> {
    let mut device = Device::open_read_write()?;
    let unit = device.write_unit()?;
    let mut scratch = Scratch {
        base: None,
        size: unit,
        unit,
    };
    let result = write_units(&mut device, unit, &mut scratch, offset, source);
    scratch.release();

    result
}

fn write_units(
    device: &mut Device,
    unit: u32,
    scratch: &mut Scratch,
    mut offset: u32,
    mut source: &[u8],
) -> Result<(), KernelError> {
    while !source.is_empty() {
        let length = source.len() as u32;
        let misalignment = offset & unit.wrapping_sub(1);
        let chunk = if misalignment == 0 && length >= unit {
            device.write(&source[..unit as usize], u64::from(offset))?;
            unit
        } else {
            let chunk = unit.wrapping_sub(misalignment).min(length);
            let page = scratch.page()?;
            let position = offset.wrapping_sub(misalignment);
            device.read(page, u64::from(position))?;
            page[misalignment as usize..(misalignment + chunk) as usize]
                .copy_from_slice(&source[..chunk as usize]);
            device.write(page, u64::from(position))?;
            chunk
        };
        offset = offset.wrapping_add(chunk);
        source = &source[chunk as usize..];
    }

    Ok(())
}
