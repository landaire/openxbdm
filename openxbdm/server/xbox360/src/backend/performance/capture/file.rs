//! Capture file writer: the module snapshot header followed by the
//! recorded chunks of every processor.

use core::ffi::CStr;
use core::sync::atomic::Ordering;

use openxbdm_core::status::KernelError;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::memory::PAGE_SIZE;
use openxbdm_server::commands::performance::capture;
use openxbdm_server::commands::performance::capture::MAX_PROCESSORS;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::RtlAssert;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::BLOCKS;
use super::Block;
use super::module_snapshot;
use super::processor_count;
use crate::kernel;

/// Statuses that the capture file writer reports for failures that are not
/// kernel calls. The backend trait carries a [`KernelError`] to
/// `dos_error`, so these are the values stock returns; a separate error
/// type would add a conversion to the writer.
pub(super) mod write_failure {
    use openxbdm_core::status::KernelError;

    /// The module snapshot block could not be allocated.
    pub(in super::super) const NO_SNAPSHOT: KernelError = KernelError::NoMemory;
    /// A recorded chunk has invalid bounds.
    pub(in super::super) const INVALID_CHUNK: KernelError = KernelError::Unsuccessful;
}

/// Start and end address of a recorded chunk.
#[derive(Clone, Copy)]
struct ChunkBounds {
    start: u32,
    end: u32,
}

fn file_attributes(name: &AnsiString) -> ObjectAttributes {
    ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    }
}

/// Create (overwrite) the capture file `path`.
pub(super) fn create_file(path: &[u8]) -> Result<FileHandle, KernelError> {
    /// Access of the capture file (stock 0x91f2eb68 callers).
    const FILE_ACCESS: AccessMask = AccessMask::SYNCHRONIZE.union(AccessMask::GENERIC_WRITE);

    let name = kernel::ansi_string(path);
    let attributes = file_attributes(&name);
    let mut handle = 0u32;
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `handle`, `attributes`, the name it refers to, and `io_status`
    // are live for the call.
    let status = unsafe {
        xboxkrnl::NtCreateFile(
            (&raw mut handle).cast(),
            FILE_ACCESS,
            &attributes,
            &mut io_status,
            core::ptr::null(),
            FileAttributes::NORMAL,
            ShareAccess::READ,
            CreateDisposition::OverwriteIf,
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
        )
    };
    status.result()?;

    Ok(FileHandle(handle))
}

pub(super) fn delete_file(path: &[u8]) {
    let name = kernel::ansi_string(path);
    // SAFETY: the attributes and the name they refer to are live for the call.
    unsafe { xboxkrnl::NtDeleteFile(&file_attributes(&name)) };
}

/// Write `length` bytes at `address` to the capture file.
///
/// # Safety
///
/// The `length` bytes at `address` must be readable for the call.
unsafe fn write_file(handle: FileHandle, address: u32, length: u32) -> Result<(), KernelError> {
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `handle` is the open capture file; `io_status` is live and the
    // caller guarantees the `length` bytes at `address` for the synchronous
    // call.
    let status = unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(handle.0),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            address as usize as *const u8,
            length,
            core::ptr::null(),
        )
    };

    status.result()
}

/// A recorded chunk of one processor, or `None` after printing `message`
/// when its bounds are invalid.
///
/// # Safety
///
/// As for [`Block::chunk`].
unsafe fn chunk_bounds(block: &Block, index: u32, message: &CStr) -> Option<ChunkBounds> {
    // SAFETY: guaranteed by the caller.
    let (start, end) = unsafe {
        (
            block.chunk(&block.chunk_starts, index),
            block.chunk(&block.chunk_ends, index),
        )
    };
    if start == 0 || end == 0 || end <= start {
        kernel::debug_print(message);
        return None;
    }

    Some(ChunkBounds { start, end })
}

/// Byte count of every recording processor, stored in the snapshot's
/// data sizes.
pub(super) fn store_data_sizes(sizes: &mut [u32; MAX_PROCESSORS]) -> Result<(), KernelError> {
    for (size, block) in sizes.iter_mut().zip(&BLOCKS).take(processor_count()) {
        if !block.enabled.load(Ordering::Relaxed) {
            *size = 0;
            continue;
        }

        for chunk in 0..block.chunk_count.load(Ordering::Relaxed) {
            // SAFETY: the block is enabled, so its arrays start in the chunk
            // list and `chunk` is below its chunk count; past the list only
            // in the case that [`super::word`] describes, as in stock.
            let Some(bounds) = (unsafe {
                chunk_bounds(block, chunk, c"DmCapWrite: Invalid bufstart and bufend during fileheader->DataSize computation!\n")
            }) else {
                return Err(write_failure::INVALID_CHUNK);
            };
            *size = size.wrapping_sub(bounds.start).wrapping_add(bounds.end);
        }
    }

    Ok(())
}

/// Write the snapshot and every recorded chunk to `handle`.
pub(super) fn write_capture(
    handle: FileHandle,
    snapshot: &module_snapshot::Snapshot,
) -> Result<(), KernelError> {
    const ASSERT_FILE: &[u8] =
        b"e:\\xenon\\xdksep13\\core\\private\\xdk\\tools\\debug\\xbdm\\core\\dmcap.c\0";
    const ASSERT_PAGE_ALIGNED: &[u8] = b"((ULONG_PTR)bufstart % PAGE_SIZE) == 0\0";
    const ASSERT_PAGE_ALIGNED_LINE: u32 = 0x7ec;

    // SAFETY: the snapshot owns `FILE_HEADER_SIZE` bytes.
    unsafe { write_file(handle, snapshot.address(), capture::FILE_HEADER_SIZE) }?;

    let mut total = 0u32;
    for block in BLOCKS
        .iter()
        .take(processor_count())
        .filter(|block| block.enabled.load(Ordering::Relaxed))
    {
        for chunk in 0..block.chunk_count.load(Ordering::Relaxed) {
            // SAFETY: as in `store_data_sizes`.
            let Some(ChunkBounds { start, end }) = (unsafe {
                chunk_bounds(block, chunk, c"DmCapWrite: Invalid bufstart and bufend!\n")
            }) else {
                return Err(write_failure::INVALID_CHUNK);
            };
            total = total.wrapping_add(end - start);

            if start & (PAGE_SIZE - 1) != 0 {
                // SAFETY: the assertion strings are static and NUL-terminated.
                unsafe {
                    RtlAssert(
                        ASSERT_PAGE_ALIGNED.as_ptr(),
                        ASSERT_FILE.as_ptr(),
                        ASSERT_PAGE_ALIGNED_LINE,
                        core::ptr::null(),
                    )
                };
            }

            // SAFETY: a valid recorded chunk lies in the record buffer, which
            // stays allocated until `release_buffers` after the write.
            unsafe { write_file(handle, start, end - start) }?;
        }
    }

    let size = u64::from(total.wrapping_add(capture::FILE_HEADER_SIZE)).to_be_bytes();
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `handle` is the open capture file; `io_status` and the 8-byte
    // `size` are live.
    let status = unsafe {
        xboxkrnl::NtSetInformationFile(
            Handle::from_raw(handle.0),
            &mut io_status,
            size.as_ptr(),
            8,
            FileInformationClass::EndOfFile,
        )
    };
    status.result()?;

    // SAFETY: as above.
    let status = unsafe {
        xboxkrnl::NtSetInformationFile(
            Handle::from_raw(handle.0),
            &mut io_status,
            size.as_ptr(),
            8,
            FileInformationClass::Allocation,
        )
    };

    status.result()
}
