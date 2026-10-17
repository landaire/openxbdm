//! Profile files.

use core::sync::atomic::Ordering;

use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::hardware::pgo;
use openxbdm_server::commands::hardware::pgo::BlockFormat;
use openxbdm_server::commands::hardware::pgo::Fatal;
use openxbdm_server::commands::hardware::pgo::PATH_UNITS;
use openxbdm_server::commands::hardware::pgo::ProfileName;
use openxbdm_server::commands::hardware::pgo::SweepKind;
use openxbdm_server::commands::hardware::pgo::WidePath;
use openxbdm_server::commands::hardware::pgo::WriteWarning;
use xbox360::status::set_last_error;
use xbox360_sys::status::KernelError;
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

use super::fatal;
use super::layout::CountBlock;
use super::layout::ModuleRecord;
use super::layout::load_units;
use super::stop_counting;
use super::sweep::close_handle;
use super::warn;
use crate::backend::filesystem;

fn profile_request(access: AccessMask, disposition: CreateDisposition) -> CreateRequest {
    CreateRequest {
        access: access
            .union(AccessMask::SYNCHRONIZE)
            .union(AccessMask::READ_ATTRIBUTES),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::empty(),
        disposition,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    }
}

/// Create the first free profile `<name>!<n>.pgc` from 1 (0x91f6d038).
/// The image also scans the directory for existing numbers but compares
/// the character after the name, which is always `!`, so the scan never
/// raises the start. `None` when a name can neither be created nor opened.
fn create_profile(name: &ProfileName) -> Option<Handle> {
    let mut number = 1u32;
    loop {
        let mut bytes = [0u8; pgo::FILE_NAME_BYTES];
        let length = name.file_name(number, &mut bytes);
        let path = &bytes[..length];

        if let Ok(handle) = filesystem::create_file(
            path,
            &profile_request(AccessMask::GENERIC_WRITE, CreateDisposition::Create),
        ) {
            return Some(Handle::from_raw(handle.0));
        }

        let handle = filesystem::create_file(
            path,
            &profile_request(AccessMask::GENERIC_READ, CreateDisposition::Open),
        )
        .ok()?;
        // SAFETY: `handle` was opened above and is closed once.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };

        number = number.wrapping_add(1);
    }
}

/// Write `length` bytes at `buffer` to a file; a failure sets the last
/// error.
///
/// # Safety
///
/// `buffer` is valid for reads of `length` bytes until the call returns.
unsafe fn write_file(handle: Handle, buffer: *const u8, length: u32) -> Result<(), KernelError> {
    let mut io_status = IoStatusBlock::default();
    // SAFETY: the caller guarantees the buffer; `io_status` outlives the
    // request, which is waited for below when pending.
    let status = unsafe {
        xboxkrnl::NtWriteFile(
            handle,
            Handle::NULL,
            0,
            0,
            &mut io_status,
            buffer,
            length,
            core::ptr::null(),
        )
    };

    let status = if status == NtStatus::PENDING {
        // SAFETY: `handle` is the open profile file.
        unsafe {
            xboxkrnl::NtWaitForSingleObjectEx(handle, ProcessorMode::User, false, core::ptr::null())
        };
        // The kernel completed the request before it signaled the file.
        io_status.status
    } else {
        status
    };

    status.result().inspect_err(|&error| set_last_error(error))
}

/// Write the count block to a new profile file (0x91f6d420), from the
/// module's directory or the devkit directory, then mark it complete.
pub(super) fn write_profile(record: &ModuleRecord) {
    let base = record.base_path();
    let mut phase = [0u16; PATH_UNITS];
    let mut continuation = [0u16; PATH_UNITS];
    let phase_set = record.phase_set.load(Ordering::Relaxed) != 0;
    if phase_set {
        load_units(&record.phase, &mut phase);
        load_units(&record.module_name, &mut continuation);
    }
    let phase = phase_set.then_some((&phase, &continuation[..]));

    let open = |path: &WidePath| {
        create_profile(&ProfileName::new(path, phase).unwrap_or_else(|failure| fatal(failure)))
    };
    let handle = open(&base)
        .or_else(|| open(&pgo::fallback_path(&base)))
        .unwrap_or_else(|| fatal(Fatal::WriteFailed));

    let block = record.count_block();
    let length = block
        .used
        .load(Ordering::Relaxed)
        .min(block.committed.load(Ordering::Relaxed));
    let start = core::ptr::with_exposed_provenance::<u8>(block.address() as usize);
    // SAFETY: the block's first `committed` bytes are committed.
    if unsafe { write_file(handle, start, length) }.is_err() {
        warn(WriteWarning::Write);
    }

    let mut io_status = IoStatusBlock::default();
    // SAFETY: `handle` is the open profile file; `io_status` is a live local.
    let status = unsafe { xboxkrnl::NtFlushBuffersFile(handle, &mut io_status) };
    if let Err(error) = status.result() {
        set_last_error(error);
        warn(WriteWarning::Flush);
    }

    // The image reports a seek only when the new position is 0.
    let position = pgo::COMPLETION_OFFSET.to_be_bytes();
    // SAFETY: `position` holds the 8-byte position information.
    let status = unsafe {
        xboxkrnl::NtSetInformationFile(
            handle,
            &mut io_status,
            position.as_ptr(),
            8,
            FileInformationClass::Position,
        )
    };
    if let Err(error) = status.result() {
        set_last_error(error);
    }

    let complete = 1u8;
    // SAFETY: `complete` is a live local byte.
    if unsafe { write_file(handle, &complete, 1) }.is_err() {
        warn(WriteWarning::Write);
    }

    if close_handle(handle).is_err() {
        warn(WriteWarning::Close);
    }
}

/// The shutdown profile of one module (0x91f6d740).
pub(super) fn shutdown_profile(record: &ModuleRecord, block: &CountBlock) {
    stop_counting(record);
    record.phase_set.store(0, Ordering::Relaxed);

    if block.format() == BlockFormat::Extended {
        let state = block.extended_state();
        state.live.store(0, Ordering::Relaxed);
        state
            .sweep_kind
            .store(SweepKind::Shutdown as u8, Ordering::Relaxed);
    } else {
        block.standard_state().live.store(0, Ordering::Relaxed);
    }

    write_profile(record);
}
