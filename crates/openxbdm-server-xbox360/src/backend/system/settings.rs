//! Settings text writer and settings copies to caller files and buffers.

use core::mem::offset_of;

use openxbdm_core::status::KernelError;
use openxbdm_server::commands;
use openxbdm_server::commands::system::SettingsCopy;
use xbox360_sys::status::Severity;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::BugCheckCode;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FileNetworkOpenInformation;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ShareAccess;

use crate::backend::dispatcher;
use crate::kernel;
use crate::kernel::pool_tag;

/// Where buffered settings text goes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Destination {
    /// A file the monitor opened.
    File,
    /// A caller's file; with `pad`, the last write is a whole buffer.
    CallerFile { pad: bool },
    /// A caller's memory buffer.
    Memory,
}

/// Settings text being written.
pub(super) struct WriteBuffer {
    pub(super) destination: Destination,
    pub(super) handle: u32,
    /// Pool block of a file destination, or the caller's memory. A pointer,
    /// not a slice: a pool block is uninitialized and the caller's memory
    /// is used only as stock uses it.
    buffer: *mut u8,
    capacity: usize,
    pub(super) count: usize,
    /// Bytes written out so far.
    pub(super) total: u32,
}

impl WriteBuffer {
    /// # Safety
    /// `buffer` is writable for `capacity` bytes until the writer is
    /// dropped, and nothing else accesses it meanwhile.
    pub(super) unsafe fn new(
        destination: Destination,
        handle: u32,
        buffer: *mut u8,
        capacity: usize,
    ) -> Self {
        Self {
            destination,
            handle,
            buffer,
            capacity,
            count: 0,
            total: 0,
        }
    }

    /// Buffer address as the pool routines and the bug check take it.
    pub(super) fn address(&self) -> u32 {
        self.buffer as usize as u32
    }

    /// Write `length` buffered bytes. A failure stops the console, as in
    /// stock.
    fn write_out(&self, length: usize) {
        /// Bug check code stock raises when a settings write fails.
        const BUG_CHECK_SETTINGS_WRITE: BugCheckCode = BugCheckCode(0x2c);

        let mut status_block = IoStatusBlock::default();
        // SAFETY: `handle` is open and `buffer` holds at least `length`
        // bytes; the file is synchronous.
        let status = unsafe {
            xboxkrnl::NtWriteFile(
                Handle::from_raw(self.handle),
                Handle::NULL,
                0,
                0,
                &mut status_block,
                self.buffer,
                length as u32,
                core::ptr::null(),
            )
        };
        if status.severity() == Severity::Error {
            xboxkrnl::KeBugCheckEx(
                BUG_CHECK_SETTINGS_WRITE,
                status.0,
                self.handle,
                &status_block as *const IoStatusBlock as usize as u32,
                self.address(),
            );
        }
    }

    /// Append bytes, writing out each filled buffer (stock 0x91f31860).
    /// Stock bug checks when a memory copy outgrows its buffer, since it
    /// writes the full buffer to handle 0; the excess is dropped instead.
    pub(super) fn append(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let count = bytes.len().min(self.capacity - self.count);
            if count == 0 {
                return;
            }

            // SAFETY: `new`'s contract makes `buffer` writable for
            // `capacity` bytes, and `count` fits after `self.count`.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.buffer.add(self.count), count)
            };
            self.count += count;
            bytes = &bytes[count..];
            if self.count == self.capacity && self.destination != Destination::Memory {
                self.write_out(self.capacity);
                self.total += self.capacity as u32;
                self.count = 0;
            }
        }
    }

    /// Write out the rest (stock 0x91f31860 with no data). A padded write
    /// sends the whole buffer; stock sends whatever the buffer held after
    /// the text, which is zeroed here.
    pub(super) fn finish(&mut self) {
        if self.count == 0 {
            return;
        }

        self.total += self.count as u32;
        let length = match self.destination {
            Destination::CallerFile { pad: true } => {
                // SAFETY: `new`'s contract makes `buffer` writable for
                // `capacity` bytes, and `count` does not exceed it.
                unsafe {
                    core::ptr::write_bytes(
                        self.buffer.add(self.count),
                        0,
                        self.capacity - self.count,
                    )
                };
                self.capacity
            }
            _ => self.count,
        };
        self.write_out(length);
        self.count = 0;
    }
}

/// Request of control code 0x1d.
#[repr(C)]
struct SettingsCopyRequest {
    handle: u32,
    /// Out: bytes written.
    length: u32,
    /// Nonzero: the last write is a whole buffer.
    pad: u8,
}

const _: () = assert!(offset_of!(SettingsCopyRequest, pad) == 8);

/// Request of control code 0x22.
#[repr(C)]
struct SettingsCaptureRequest {
    buffer: u32,
    /// In: buffer size. Out: bytes stored.
    length: u32,
}

/// A pool block of `size` bytes for settings text.
pub(super) fn allocate_buffer(size: usize) -> Option<*mut u8> {
    // SAFETY: the allocation takes only a size, tag and pool type.
    let address = unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(size as u32, pool_tag::BUFFER, PoolType::System)
    };

    (address != 0).then_some(address as usize as *mut u8)
}

pub(super) fn create_file(
    path: &[u8],
    access: AccessMask,
    disposition: CreateDisposition,
) -> Result<u32, KernelError> {
    let name = kernel::ansi_string(path);
    let attributes = ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: &name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    let mut status_block = IoStatusBlock::default();
    let mut handle = 0u32;
    // SAFETY: `handle`, `attributes`, the name it refers to and
    // `status_block` are live locals.
    let status = unsafe {
        xboxkrnl::NtCreateFile(
            (&raw mut handle).cast(),
            access,
            &attributes,
            &mut status_block,
            core::ptr::null(),
            FileAttributes::empty(),
            ShareAccess::empty(),
            disposition,
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
        )
    };
    status.result()?;

    Ok(handle)
}

pub(super) fn file_exists(path: &[u8]) -> bool {
    let name = kernel::ansi_string(path);
    let attributes = ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: &name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    let mut information = FileNetworkOpenInformation::default();
    // SAFETY: `attributes` and its name are live; `information` holds the
    // result.
    unsafe { xboxkrnl::NtQueryFullAttributesFile(&attributes, (&raw mut information).cast()) }
        .is_success()
}

/// Monitor control code 0x1d (stock 0x91f32110): write the settings text
/// to the caller's file.
///
/// # Safety
///
/// `argument` must be the address of a writable [`SettingsCopyRequest`]
/// the caller does not touch until the code returns.
pub(crate) unsafe fn service_write_settings_copy(argument: u32) -> u32 {
    let mut request = argument as usize as *mut SettingsCopyRequest;
    dispatcher::call_on_server_with(
        &mut request,
        |server, console, _, request: &mut *mut SettingsCopyRequest| {
            // SAFETY: the caller's contract.
            let request = unsafe { &mut **request };
            let copy = SettingsCopy::File {
                handle: request.handle,
                pad: request.pad != 0,
            };
            if let Some(length) = commands::system::copy_settings(&server.state, console, copy) {
                request.length = length;
            }
            0
        },
    );

    0
}

/// Monitor control code 0x22 (stock 0x91f32080): store the settings text
/// in the caller's buffer.
///
/// # Safety
///
/// `argument` must be the address of a writable [`SettingsCaptureRequest`]
/// whose buffer holds `length` writable bytes, which the caller does not
/// touch until the code returns.
pub(crate) unsafe fn service_capture_settings(argument: u32) -> u32 {
    let mut request = argument as usize as *mut SettingsCaptureRequest;
    dispatcher::call_on_server_with(
        &mut request,
        |server, console, _, request: &mut *mut SettingsCaptureRequest| {
            // SAFETY: the caller's contract.
            let request = unsafe { &mut **request };
            let copy = SettingsCopy::Memory {
                address: request.buffer,
                capacity: request.length,
            };
            if let Some(length) = commands::system::copy_settings(&server.state, console, copy) {
                request.length = length;
            }
            0
        },
    );

    1
}
