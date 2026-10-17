//! File system, object namespace, and block device services.

mod exports;
mod format;
mod pool;

use core::cell::UnsafeCell;
use core::sync::atomic::Ordering;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_server::commands;
use openxbdm_server::commands::filesystem::BasicInformation;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::DeviceObject;
use openxbdm_server::commands::filesystem::DirectoryEntry;
use openxbdm_server::commands::filesystem::DvdTrace;
use openxbdm_server::commands::filesystem::FileData;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::filesystem::FileInformation;
use openxbdm_server::commands::filesystem::FileTime;
use openxbdm_server::commands::filesystem::ObjectDirectory;
use openxbdm_server::commands::filesystem::PoolBuffer;
use openxbdm_server::commands::filesystem::PoolRange;
use openxbdm_server::commands::filesystem::ReadTarget;
use openxbdm_server::commands::filesystem::ScratchBlock;
use openxbdm_server::commands::filesystem::TransferDirection;
use openxbdm_server::commands::filesystem::VolumeSize;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::DebugMonitorFlags;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FileBasicInformation;
use xbox360_sys::xboxkrnl::FileDirectoryInformation;
use xbox360_sys::xboxkrnl::FileDispositionInformation;
use xbox360_sys::xboxkrnl::FileEndOfFileInformation;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::FileNetworkOpenInformation;
use xbox360_sys::xboxkrnl::FilePositionInformation;
use xbox360_sys::xboxkrnl::FileRenameInformation;
use xbox360_sys::xboxkrnl::FileSystemAttributes;
use xbox360_sys::xboxkrnl::FsInformationClass;
use xbox360_sys::xboxkrnl::FsSizeInformation;
use xbox360_sys::xboxkrnl::HalOpenCloseODDTray;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoControlCode;
use xbox360_sys::xboxkrnl::IoDeviceObjectType;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::IoSynchronousFsdRequest;
use xbox360_sys::xboxkrnl::IrpMajorFunction;
use xbox360_sys::xboxkrnl::NtOpenDirectoryObject;
use xbox360_sys::xboxkrnl::NtQueryDirectoryFile;
use xbox360_sys::xboxkrnl::NtQueryVolumeInformationFile;
use xbox360_sys::xboxkrnl::ObTranslateSymbolicLink;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ShareAccess;

use self::exports::FILE_CHANGES;
use self::format::format_xtaf;
use self::pool::PoolBlock;
use self::pool::pool_range;
use super::Console;
use crate::kernel;

/// Size of the optical drive trace buffer.
const DVD_TRACE_SIZE: u32 = 0x20_0000;

/// Platform state of this domain.
pub struct Data {
    /// The optical drive trace buffer while tracing.
    dvd_trace: Option<PoolBlock>,
}

impl Data {
    pub const fn new() -> Self {
        Self { dvd_trace: None }
    }
}

/// The status block of a request that may complete asynchronously: the
/// kernel writes it through the pointer it was given until the request
/// completes.
struct PendingStatus(UnsafeCell<IoStatusBlock>);

impl PendingStatus {
    fn new() -> Self {
        Self(UnsafeCell::new(IoStatusBlock::default()))
    }

    fn as_ptr(&self) -> *mut IoStatusBlock {
        self.0.get()
    }

    /// Wait for the request started on `handle` that returned `status`;
    /// the bytes it transferred on success.
    fn complete(&self, handle: FileHandle, status: NtStatus) -> Result<u32, KernelError> {
        let status = if status == NtStatus::PENDING {
            // SAFETY: `handle` is the open file the pending request was
            // issued on.
            unsafe {
                xboxkrnl::NtWaitForSingleObjectEx(
                    Handle::from_raw(handle.0),
                    ProcessorMode::Kernel,
                    false,
                    core::ptr::null(),
                )
            };
            // SAFETY: the request completed, so the kernel no longer writes
            // the block.
            unsafe { (*self.as_ptr()).status }
        } else {
            status
        };

        status.result()?;

        // SAFETY: as above.
        Ok(unsafe { (*self.as_ptr()).information })
    }
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
        access: AccessMask,
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
        FILE_CHANGES.fetch_add(1, Ordering::Relaxed);
    }

    fn read_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        target: ReadTarget<'_>,
    ) -> Result<u32, KernelError> {
        let buffer = match target {
            ReadTarget::Bytes(bytes) => bytes,
            // SAFETY: a pool range names a live block (the `PoolBuffer`
            // contract), and `&mut self` excludes any slice of it from
            // `pool` during the call.
            ReadTarget::Pool(range) => unsafe { pool_range(range) },
        };
        let io_status = PendingStatus::new();
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
                io_status.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                offset_pointer,
            )
        };

        io_status.complete(handle, raw)
    }

    fn write_file(
        &mut self,
        handle: FileHandle,
        offset: Option<u64>,
        data: FileData<'_>,
    ) -> Result<(), KernelError> {
        let bytes: &[u8] = match data {
            FileData::Bytes(bytes) => bytes,
            // SAFETY: as in `read_file`.
            FileData::Pool(range) => unsafe { pool_range(range) },
        };
        let io_status = PendingStatus::new();
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
                io_status.as_ptr(),
                bytes.as_ptr(),
                bytes.len() as u32,
                offset_pointer,
            )
        };
        io_status.complete(handle, raw)?;

        Ok(())
    }

    fn set_delete_disposition(
        &mut self,
        handle: FileHandle,
        delete: bool,
    ) -> Result<(), KernelError> {
        let information = FileDispositionInformation {
            delete_file: delete,
        };
        // SAFETY: the structure is one byte.
        let bytes = unsafe { bytes_of(&information) };

        set_information(handle, FileInformationClass::Disposition, bytes)
    }

    fn set_end_of_file(&mut self, handle: FileHandle, size: u64) -> Result<(), KernelError> {
        let information = FileEndOfFileInformation { end_of_file: size };
        // SAFETY: the structure is one doubleword.
        let bytes = unsafe { bytes_of(&information) };

        set_information(handle, FileInformationClass::EndOfFile, bytes)
    }

    fn set_file_position(&mut self, handle: FileHandle, position: u64) -> Result<(), KernelError> {
        let information = FilePositionInformation {
            current_byte_offset: position,
        };
        // SAFETY: the structure is one doubleword.
        let bytes = unsafe { bytes_of(&information) };

        set_information(handle, FileInformationClass::Position, bytes)
    }

    fn set_basic_information(
        &mut self,
        handle: FileHandle,
        information: &BasicInformation,
    ) -> Result<(), KernelError> {
        let mut basic = FileBasicInformation::default();
        basic.creation_time = information.creation_time.0;
        basic.last_access_time = information.last_access_time.0;
        basic.last_write_time = information.last_write_time.0;
        basic.change_time = information.change_time.0;
        basic.attributes = information.attributes;
        // SAFETY: the structure is doublewords and words, its last word an
        // explicit padding field.
        let bytes = unsafe { bytes_of(&basic) };

        set_information(handle, FileInformationClass::Basic, bytes)
    }

    fn rename_file(
        &mut self,
        handle: FileHandle,
        target: &[u8],
        replace: bool,
    ) -> Result<(), KernelError> {
        let information = FileRenameInformation {
            replace_if_exists: replace,
            root_directory: Handle::NULL,
            file_name: ansi(target),
        };
        let mut io_status = IoStatusBlock::default();
        // SAFETY: `information` and the name it refers to outlive the call.
        let raw = unsafe {
            xboxkrnl::NtSetInformationFile(
                Handle::from_raw(handle.0),
                &mut io_status,
                (&raw const information).cast(),
                size_of::<FileRenameInformation>() as u32,
                FileInformationClass::Rename,
            )
        };

        raw.result()
    }

    fn query_file_information(
        &mut self,
        handle: FileHandle,
    ) -> Result<FileInformation, KernelError> {
        let mut information = FileNetworkOpenInformation::default();
        let mut io_status = IoStatusBlock::default();
        // SAFETY: `information` is a live local of the size passed.
        let raw = unsafe {
            xboxkrnl::NtQueryInformationFile(
                Handle::from_raw(handle.0),
                &mut io_status,
                (&raw mut information).cast(),
                size_of::<FileNetworkOpenInformation>() as u32,
                FileInformationClass::NetworkOpen,
            )
        };
        raw.result()?;

        Ok(network_open_information(&information))
    }

    fn query_full_attributes(&mut self, path: &[u8]) -> Result<FileInformation, KernelError> {
        let name = ansi(path);
        let object = attributes(0, &name);
        let mut information = FileNetworkOpenInformation::default();
        // SAFETY: `object` refers to `name`; `information` holds the result.
        let raw =
            unsafe { xboxkrnl::NtQueryFullAttributesFile(&object, (&raw mut information).cast()) };
        raw.result()?;

        Ok(network_open_information(&information))
    }

    fn query_directory(
        &mut self,
        handle: FileHandle,
        restart: bool,
        name: &mut [u8],
    ) -> Result<DirectoryEntry, KernelError> {
        /// Directory query buffer of the image.
        const DIRECTORY_BUFFER: usize = 0x190;

        /// The query output: one entry, then its name.
        #[repr(C)]
        struct Buffer {
            entry: FileDirectoryInformation,
            name: [u8; DIRECTORY_BUFFER - size_of::<FileDirectoryInformation>()],
        }
        const _: () = assert!(size_of::<Buffer>() == DIRECTORY_BUFFER);
        let mut buffer = Buffer {
            entry: FileDirectoryInformation::default(),
            name: [0; DIRECTORY_BUFFER - size_of::<FileDirectoryInformation>()],
        };
        let io_status = PendingStatus::new();
        // SAFETY: `buffer` and `io_status` stay live until `complete` returns.
        let raw = unsafe {
            NtQueryDirectoryFile(
                Handle::from_raw(handle.0),
                Handle::NULL,
                0,
                0,
                io_status.as_ptr(),
                (&raw mut buffer).cast(),
                DIRECTORY_BUFFER as u32,
                core::ptr::null(),
                restart,
            )
        };
        io_status.complete(handle, raw)?;
        let entry = &buffer.entry;
        let length = (entry.file_name_length as usize).min(buffer.name.len());
        if length > name.len() {
            return Err(KernelError::BufferOverflow);
        }

        name[..length].copy_from_slice(&buffer.name[..length]);
        let information = FileInformation {
            creation_time: FileTime(entry.creation_time),
            last_access_time: FileTime(entry.last_access_time),
            last_write_time: FileTime(entry.last_write_time),
            change_time: FileTime(entry.change_time),
            end_of_file: entry.end_of_file,
            allocation_size: entry.allocation_size,
            attributes: FileAttributes::from_bits_retain(entry.attributes.bits()),
        };
        Ok(DirectoryEntry {
            information,
            name_length: length,
        })
    }

    fn query_volume_size(&mut self, handle: FileHandle) -> Result<VolumeSize, KernelError> {
        let mut information = FsSizeInformation::default();
        let mut io_status = IoStatusBlock::default();
        // SAFETY: `information` is a live local of the size passed.
        let raw = unsafe {
            NtQueryVolumeInformationFile(
                Handle::from_raw(handle.0),
                &mut io_status,
                (&raw mut information).cast(),
                size_of::<FsSizeInformation>() as u32,
                FsInformationClass::Size,
            )
        };
        raw.result()?;

        Ok(VolumeSize {
            total_units: information.total_allocation_units,
            available_units: information.available_allocation_units,
            sectors_per_unit: information.sectors_per_allocation_unit,
            bytes_per_sector: information.bytes_per_sector,
        })
    }

    #[cfg(feature = "smb")]
    fn query_volume_attributes(
        &mut self,
        handle: FileHandle,
    ) -> Result<commands::filesystem::VolumeAttributes, KernelError> {
        use commands::filesystem::FILE_SYSTEM_NAME_CAPACITY;
        use xbox360_sys::xboxkrnl::FsAttributeInformation;
        /// The query output: the attributes, then the file system name.
        #[repr(C)]
        struct Buffer {
            information: FsAttributeInformation,
            name: [u8; FILE_SYSTEM_NAME_CAPACITY],
        }
        const _: () = assert!(
            size_of::<Buffer>() == size_of::<FsAttributeInformation>() + FILE_SYSTEM_NAME_CAPACITY
        );
        let mut buffer = Buffer {
            information: FsAttributeInformation::default(),
            name: [0; FILE_SYSTEM_NAME_CAPACITY],
        };
        let mut io_status = IoStatusBlock::default();
        // SAFETY: `buffer` is a live local of the size passed.
        let raw = unsafe {
            NtQueryVolumeInformationFile(
                Handle::from_raw(handle.0),
                &mut io_status,
                (&raw mut buffer).cast(),
                size_of::<Buffer>() as u32,
                FsInformationClass::Attribute,
            )
        };
        raw.result()?;

        let information = &buffer.information;
        let name = buffer
            .name
            .get(..information.file_system_name_length as usize)
            .ok_or(KernelError::BufferOverflow)?;
        volume_attributes(
            information.attributes,
            information.maximum_component_name_length,
            name,
        )
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
        raw.result()?;

        Ok(usize::from(output.length))
    }

    fn open_object_directory(&mut self, path: &[u8]) -> Result<ObjectDirectory, KernelError> {
        let name = ansi(path);
        let object = attributes(0, &name);
        let mut handle = 0u32;
        // SAFETY: `handle` and `object` are live locals.
        let raw = unsafe { NtOpenDirectoryObject((&raw mut handle).cast(), &object) };
        raw.result()?;

        Ok(ObjectDirectory(handle))
    }

    fn query_object_directory(
        &mut self,
        directory: ObjectDirectory,
        restart: bool,
        context: &mut u32,
        name: &mut [u8],
    ) -> Result<usize, KernelError> {
        /// Object directory query buffer of the image.
        const OBJECT_DIRECTORY_BUFFER: usize = 0x10c;

        /// The query output: the name descriptor, then its text.
        #[repr(C)]
        struct Buffer {
            name: AnsiString,
            _text: [u8; OBJECT_DIRECTORY_BUFFER - size_of::<AnsiString>()],
        }
        let mut buffer = Buffer {
            name: AnsiString {
                length: 0,
                maximum_length: 0,
                buffer: core::ptr::null(),
            },
            _text: [0; OBJECT_DIRECTORY_BUFFER - size_of::<AnsiString>()],
        };
        // SAFETY: `buffer` and `context` are live for the stated length.
        let raw = unsafe {
            xboxkrnl::NtQueryDirectoryObject(
                Handle::from_raw(directory.0),
                (&raw mut buffer).cast(),
                OBJECT_DIRECTORY_BUFFER as u32,
                restart,
                context,
                core::ptr::null_mut(),
            )
        };
        raw.result()?;

        let entry = &buffer.name;
        let length = usize::from(entry.length).min(name.len());
        // SAFETY: the kernel wrote a name whose text lies inside `buffer`.
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
        // SAFETY: `data_imports_resolved` held at module load.
        let object_type = unsafe { IoDeviceObjectType.get_unchecked() };
        let mut object = 0u32;
        // SAFETY: `name` and `object` are live locals; `object_type` is the
        // kernel device object type.
        let raw = unsafe {
            xboxkrnl::ObReferenceObjectByName(
                &name,
                ObjectAttributeFlags::empty(),
                kernel::address_of(object_type),
                0,
                &mut object,
            )
        };
        raw.result()?;

        // SAFETY: the reference taken above, held until it is dereferenced.
        Ok(unsafe { DeviceObject::from_raw(object) })
    }

    unsafe fn dereference_device(&mut self, device: DeviceObject) {
        // SAFETY: `device` holds a reference taken by `reference_device`,
        // released once (the trait contract).
        unsafe { xboxkrnl::ObDereferenceObject(device.raw()) };
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
        // SAFETY: as in `read_file`.
        let bytes = unsafe { pool_range(buffer) };
        // SAFETY: `device` is referenced; `bytes` is a live pool range of
        // `buffer.length` bytes.
        let raw = unsafe {
            IoSynchronousFsdRequest(
                major,
                core::ptr::with_exposed_provenance_mut(device.raw() as usize),
                bytes.as_mut_ptr(),
                buffer.length,
                &offset,
            )
        };

        raw.result()
    }

    fn allocate_pool(&mut self, size: u32) -> Option<PoolBuffer> {
        PoolBlock::allocate(size).map(PoolBlock::into_buffer)
    }

    unsafe fn free_pool(&mut self, buffer: PoolBuffer) {
        // SAFETY: a `PoolBuffer` names the data of a live block of
        // `into_buffer`, and no copy is used after this (the trait
        // contract).
        drop(unsafe { PoolBlock::from_data(buffer.raw() as usize) });
    }

    fn pool(&mut self, buffer: PoolBuffer) -> &mut [u8] {
        // SAFETY: a `PoolBuffer` names the data of a live block of
        // `into_buffer`, which stays allocated until it is freed; the
        // slice borrows `self`, so no other slice of a block exists while
        // it lives.
        unsafe { PoolBlock::data(PoolBlock::header_of(buffer.raw() as usize)) }
    }

    fn allocate_scratch(&mut self, size: u32) -> Option<ScratchBlock> {
        PoolBlock::allocate(size).map(PoolBlock::into_scratch)
    }

    fn free_scratch(&mut self, block: ScratchBlock) {
        let data = block.into_raw();
        // SAFETY: a `ScratchBlock` holds the data of a block of
        // `into_scratch` and is consumed here.
        drop(unsafe { PoolBlock::from_data(data.as_mut_ptr().expose_provenance()) });
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
        // SAFETY: `data_imports_resolved` held at module load.
        unsafe { xboxkrnl::KeTimeStampBundle.get_unchecked() }
            .tick_count
            .load(Ordering::Relaxed) as u16
    }

    fn dos_error(&mut self, error: KernelError) -> Option<Win32Error> {
        xbox360::status::dos_error(error)
    }

    fn start_dvd_trace(&mut self) {
        let block = kernel::published_debug_monitor_data();
        if let Some(block) = block {
            // SAFETY: 0 stops the recording before the old buffer is freed.
            unsafe { block.dvd_trace_pointer.store(0, Ordering::Relaxed) };
        }
        self.filesystem.dvd_trace = None;
        let Some(mut buffer) = PoolBlock::allocate(DVD_TRACE_SIZE) else {
            return;
        };

        /// Byte of the trace buffer whose bit 0 stock clears before the
        /// driver records; its meaning is unknown.
        const TRACE_FLAGS_OFFSET: usize = 8;
        const TRACE_FLAG_0: u8 = 0x1;

        buffer.bytes()[TRACE_FLAGS_OFFSET] &= !TRACE_FLAG_0;
        let address = buffer.address();
        self.filesystem.dvd_trace = Some(buffer);
        if let Some(block) = block {
            let flags = &block.flags;
            flags.store(
                flags.load(Ordering::Relaxed) | DebugMonitorFlags::DVD_TRACE.bits(),
                Ordering::Relaxed,
            );
            // SAFETY: the buffer is a live pool block of `DVD_TRACE_SIZE`
            // bytes, kept until the pointer is cleared again.
            unsafe { block.dvd_trace_pointer.store(address, Ordering::Relaxed) };
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
        let start = buffer.address();
        let length = if end > start {
            (end - start).min(DVD_TRACE_SIZE)
        } else {
            0
        };

        Some(DvdTrace {
            buffer: buffer.into_buffer(),
            length,
        })
    }

    fn dvd_trace_active(&mut self) -> bool {
        self.filesystem.dvd_trace.is_some()
    }
}

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
        flags: FileSystemAttributes::from_bits_retain(flags),
        maximum_component_length,
        name: output,
        name_length: name.len(),
    })
}

/// A counted name; the kernel copies it, so the bytes only live for the
/// call.
fn ansi(bytes: &[u8]) -> AnsiString {
    /// Longest object name passed to the kernel.
    const PATH_CAPACITY: usize = 0x200;

    kernel::ansi_string(&bytes[..bytes.len().min(PATH_CAPACITY)])
}

fn attributes(root: u32, name: &AnsiString) -> ObjectAttributes {
    ObjectAttributes {
        root_directory: Handle::from_raw(root),
        object_name: name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    }
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
            request.access,
            &object,
            &mut io_status,
            allocation_pointer,
            request.attributes,
            request.share,
            request.disposition,
            request.options,
        )
    };
    raw.result()?;

    Ok(FileHandle(handle))
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

    raw.result()
}

/// The bytes of `value`, an information structure the kernel reads.
///
/// # Safety
///
/// `T` must have no padding bytes.
unsafe fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: every byte of `value` is initialized (guaranteed by the
    // caller) and lies inside it.
    unsafe { core::slice::from_raw_parts(core::ptr::from_ref(value).cast(), size_of::<T>()) }
}

/// The bytes of `value`, an information structure the kernel fills.
///
/// # Safety
///
/// `T` must have no padding bytes, and every byte pattern must be a valid
/// `T`.
unsafe fn bytes_of_mut<T>(value: &mut T) -> &mut [u8] {
    // SAFETY: as in `bytes_of`; any bytes written form a valid `T`
    // (guaranteed by the caller).
    unsafe { core::slice::from_raw_parts_mut(core::ptr::from_mut(value).cast(), size_of::<T>()) }
}

fn network_open_information(information: &FileNetworkOpenInformation) -> FileInformation {
    FileInformation {
        creation_time: FileTime(information.creation_time),
        last_access_time: FileTime(information.last_access_time),
        last_write_time: FileTime(information.last_write_time),
        change_time: FileTime(information.change_time),
        allocation_size: information.allocation_size,
        end_of_file: information.end_of_file,
        attributes: FileAttributes::from_bits_retain(information.attributes.bits()),
    }
}

/// Open a file by name relative to directory `root`.
#[inline(never)]
fn open_file(
    root: Option<ObjectDirectory>,
    name: &[u8],
    access: AccessMask,
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
            access,
            &object,
            &mut io_status,
            share,
            options,
        )
    };
    raw.result()?;

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

    raw.result()
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
    request: &mut u32,
) -> u32 {
    commands::filesystem::map_title_drive(&mut server.state, console, *request);

    0
}
