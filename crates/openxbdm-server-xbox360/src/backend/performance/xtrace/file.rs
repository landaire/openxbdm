use core::mem::size_of;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::filesystem::CreateRequest;
use xbox360::status::set_last_error;
use xbox360_sys::status::NtStatus;
use xbox360_sys::status::Severity;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ShareAccess;

use crate::backend::filesystem;

const FILE_NAME_SIZE: usize = 0x100;

/// The session file name, NUL-padded.
static FILE_NAME: [AtomicU8; FILE_NAME_SIZE] = [const { AtomicU8::new(0) }; FILE_NAME_SIZE];

/// The session file name.
pub(super) fn file_name() -> ([u8; FILE_NAME_SIZE], usize) {
    let mut name = [0u8; FILE_NAME_SIZE];
    for (byte, stored) in name.iter_mut().zip(&FILE_NAME) {
        *byte = stored.load(Ordering::Relaxed);
    }

    let length = name
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(FILE_NAME_SIZE);
    (name, length)
}

pub(super) fn has_file_name() -> bool {
    FILE_NAME[0].load(Ordering::Relaxed) != 0
}

/// Store the session file name as stock's bounded copy does: at most
/// 0xff bytes and a terminator.
#[inline(never)]
pub(super) fn set_file_name(name: &[u8]) {
    for (index, stored) in FILE_NAME.iter().enumerate() {
        let byte = match name.get(index) {
            Some(&byte) if index < FILE_NAME_SIZE - 1 => byte,
            _ => 0,
        };
        stored.store(byte, Ordering::Relaxed);
    }
}

/// Open a drive path (stock 0x91f2eb68), translated on the caller's
/// thread; a name that does not translate fails, where stock would use an
/// uninitialized handle.
pub(super) fn open(name: &[u8], request: &CreateRequest) -> Option<u32> {
    filesystem::open_translated(name, request)
        .ok()
        .map(|handle| handle.0)
}

pub(super) fn create_request(
    access: AccessMask,
    share: ShareAccess,
    disposition: CreateDisposition,
    options: CreateOptions,
) -> CreateRequest {
    CreateRequest {
        access,
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share,
        disposition,
        options,
    }
}

/// The trace file opened for writing, replaced or created.
pub(super) fn create_trace_file(name: &[u8]) -> Option<u32> {
    open(
        name,
        &create_request(
            AccessMask::GENERIC_WRITE.union(AccessMask::SYNCHRONIZE),
            ShareAccess::READ,
            CreateDisposition::OverwriteIf,
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
        ),
    )
}

/// Append `length` bytes at `data` to the trace file; true when all were
/// written.
pub(super) fn append(name: &[u8], data: u32, length: u32) -> bool {
    let Some(handle) = open(
        name,
        &create_request(
            AccessMask::GENERIC_WRITE.union(AccessMask::SYNCHRONIZE),
            ShareAccess::READ,
            CreateDisposition::Open,
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
        ),
    ) else {
        return false;
    };

    let mut io_status = IoStatusBlock::default();
    let mut information = xboxkrnl::FileNetworkOpenInformation::default();
    // SAFETY: `handle` was opened above; `io_status` and `information` are
    // live and sized as stated.
    let status = unsafe {
        xboxkrnl::NtQueryInformationFile(
            Handle::from_raw(handle),
            &mut io_status,
            (&raw mut information).cast::<u8>(),
            size_of::<xboxkrnl::FileNetworkOpenInformation>() as u32,
            FileInformationClass::NetworkOpen,
        )
    };

    // Stock seeks to the end; when that fails the write goes to the start.
    let offset = match status.result() {
        Err(error) => {
            set_last_error(error);
            0
        }
        Ok(()) => information.end_of_file,
    };

    let mut io_status = IoStatusBlock::default();
    // SAFETY: `handle` was opened above; `io_status`, `offset`, and the
    // `length` bytes at `data` stay live until the write completes, which
    // the wait below ensures.
    let status = unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(handle),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            data as usize as *const u8,
            length,
            &offset,
        )
    };
    let status = if status == NtStatus::PENDING {
        // SAFETY: `handle` was opened above.
        let waited = unsafe {
            xboxkrnl::NtWaitForSingleObjectEx(
                Handle::from_raw(handle),
                ProcessorMode::User,
                false,
                core::ptr::null(),
            )
        };
        if waited.is_success() {
            io_status.status
        } else {
            waited
        }
    } else {
        status
    };

    // A warning status, such as a partial write, still reports the bytes
    // written.
    let written = if status.severity() != Severity::Error {
        io_status.information
    } else {
        0
    };

    if let Err(error) = status.result() {
        set_last_error(error);
    }

    // SAFETY: `handle` was opened above and is closed once.
    unsafe { xboxkrnl::NtClose(Handle::from_raw(handle)) };

    written == length
}
