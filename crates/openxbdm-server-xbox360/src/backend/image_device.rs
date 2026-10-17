//! Image file devices (stock export 130, 0x91f54138 and 0x91f54310..0x91f54a9c):
//! a file opened for read is served as a block device until the title
//! terminates.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::ptr::null;
use core::ptr::null_mut;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use xbox360_sys::export_raw;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::DeviceObject;
use xbox360_sys::xboxkrnl::DeviceObjectFlags;
use xbox360_sys::xboxkrnl::DriverDispatch;
use xbox360_sys::xboxkrnl::DriverObject;
use xbox360_sys::xboxkrnl::DriverStartIo;
use xbox360_sys::xboxkrnl::EventType;
use xbox360_sys::xboxkrnl::FileDeviceType;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoControlCode;
use xbox360_sys::xboxkrnl::IoCreateDevice;
use xbox360_sys::xboxkrnl::IoDismountVolume;
use xbox360_sys::xboxkrnl::IoInvalidDeviceRequest;
use xbox360_sys::xboxkrnl::IoStackControl;
use xbox360_sys::xboxkrnl::IoStackFlags;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::Irp;
use xbox360_sys::xboxkrnl::IrpMajorFunction;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeSetPriorityThread;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ShareAccess;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;

/// `ExCreateThread` flags of the mount thread.
const MOUNT_THREAD_FLAGS: ThreadCreationFlags = ThreadCreationFlags::from_bits_retain(0x22);
/// `ExCreateThread` flags of the worker; 0x80 returns a referenced thread
/// object instead of a handle.
const WORKER_THREAD_FLAGS: u32 = 0x0400_00a8;
/// Added to the worker flags when the creator runs in the system process.
const THREAD_SYSTEM_PROCESS: u32 = 0x2;
const WORKER_STACK_SIZE: u32 = 0x4000;
const WORKER_PRIORITY: u32 = 0x1f;

const DEVICE_TYPE: FileDeviceType = FileDeviceType(0x3d);
/// Alignment requirement of the device: word aligned transfer buffers.
const WORD_ALIGNMENT: u32 = 1;
const SECTOR_SIZE: u32 = 0x200;
const SECTOR_SHIFT: u32 = 9;
const SECTOR_MASK: u32 = SECTOR_SIZE - 1;

/// Stack location parameter words as the worker reads them once a request
/// is queued: transfer length, transfer address or user buffer, first
/// sector, and the offset added to the buffer word.
const LENGTH: usize = 0;
const BUFFER: usize = 1;
const SECTOR: usize = 2;
const BUFFER_OFFSET: usize = 3;
const NOTIFICATION: u8 = 0;
const SYNCHRONIZATION: u8 = 1;

/// Kernel event object.
#[repr(C)]
struct EventObject {
    kind: u8,
    _header: [u8; 3],
    signal_state: u32,
    wait_list: [*mut u32; 2],
}

impl EventObject {
    /// Unsignaled event of `kind` with an empty wait list; the other header
    /// bytes are left as they are, as stock does.
    ///
    /// # Safety
    /// `event` must be writable and unused by the kernel.
    unsafe fn initialize(event: *mut Self, kind: u8) {
        // SAFETY: guaranteed by the caller.
        unsafe {
            let list = (&raw mut (*event).wait_list).cast::<u32>();
            (*event).kind = kind;
            (*event).signal_state = 0;
            (*event).wait_list = [list, list];
        }
    }
}

/// Event in static storage, initialized in the image like stock's.
struct GlobalEvent(UnsafeCell<EventObject>);

// SAFETY: the kernel synchronizes access to dispatcher objects.
unsafe impl Sync for GlobalEvent {}

impl GlobalEvent {
    const fn new(kind: u8, this: &'static Self) -> Self {
        let list = this.pointer().wrapping_add(2);
        Self(UnsafeCell::new(EventObject {
            kind,
            _header: [0; 3],
            signal_state: 0,
            wait_list: [list, list],
        }))
    }

    const fn pointer(&self) -> *mut u32 {
        self.0.get().cast()
    }
}

/// Set at title termination; every mount thread waits on it, then deletes
/// its device (stock 0x91f98e74).
static DISMOUNT: GlobalEvent = GlobalEvent::new(NOTIFICATION, &DISMOUNT);
/// Set by the last mount thread to finish (stock 0x91f98e84).
static DISMOUNTED: GlobalEvent = GlobalEvent::new(SYNCHRONIZATION, &DISMOUNTED);
/// Mount threads holding a device (stock 0x91fab7d0).
static MOUNTED: AtomicU32 = AtomicU32::new(0);

/// Device extension. Packed because the kernel places it.
#[repr(C, packed(4))]
struct Extension {
    /// Image file handle.
    file: u32,
    /// Event handle for the file transfers.
    io_event: u32,
    /// Request handed from start I/O to the worker.
    irp: Option<NonNull<Irp>>,
    /// Referenced worker thread object.
    thread: Option<NonNull<u32>>,
    /// Device start in the file in bytes.
    start: u64,
    /// Device length in bytes.
    length: u64,
    /// Wakes the worker.
    work: EventObject,
    /// Completed writes.
    writes: u64,
    _unused: [u32; 4],
}

/// Stack block of the export (stock frame +0x50), the mount thread context.
#[repr(C)]
struct MountRequest {
    file: *const AnsiString,
    name: *const AnsiString,
    length: u64,
    done: EventObject,
    status: u32,
}

const _: () = {
    assert!(core::mem::offset_of!(Extension, start) == 0x10);
    assert!(core::mem::offset_of!(Extension, work) == 0x20);
    assert!(core::mem::offset_of!(Extension, writes) == 0x30);
    assert!(size_of::<Extension>() == 0x48);
    assert!(size_of::<DriverObject>() == 0x38);
    assert!(core::mem::offset_of!(MountRequest, done) == 0x10);
    assert!(core::mem::offset_of!(MountRequest, status) == 0x20);
};

/// Entry of a routine the kernel calls, through `export_bridge` for the
/// console register convention.
macro_rules! kernel_entry {
    ($entry:ident: $ty:ty, $function:path) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $entry(_: *mut DeviceObject, _: *mut Irp) -> $ty {
            core::arch::naked_asm!(
                "lis 12, {function}@ha",
                "addi 12, 12, {function}@l",
                "b {bridge}",
                function = sym $function,
                bridge = sym crate::exports::export_bridge,
            )
        }
    };
}

kernel_entry!(start_io_entry: (), start_io);
kernel_entry!(read_write_entry: NtStatus, read_write);
kernel_entry!(flush_entry: NtStatus, flush);
kernel_entry!(device_control_entry: NtStatus, device_control);
kernel_entry!(invalid_request_entry: NtStatus, IoInvalidDeviceRequest);

/// Writable like stock's (0x91f98e94, in .data); the kernel keeps a
/// pointer to it.
struct Driver(UnsafeCell<DriverObject>);

// SAFETY: never written by this module.
unsafe impl Sync for Driver {}

const START_IO: DriverStartIo = start_io_entry;
const INVALID: Option<DriverDispatch> = Some(invalid_request_entry);
const READ_WRITE: Option<DriverDispatch> = Some(read_write_entry);

static DRIVER: Driver = Driver(UnsafeCell::new(DriverObject::new(
    Some(START_IO),
    [
        INVALID,
        INVALID,
        READ_WRITE,
        READ_WRITE,
        INVALID,
        INVALID,
        Some(flush_entry),
        INVALID,
        INVALID,
        Some(device_control_entry),
        INVALID,
    ],
)));

/// Stock assertion trap (`twi 31, 0, 0x19`).
fn assertion_trap() {
    // SAFETY: raises the trap exception stock raises; the debugger or the
    // kernel handles it and execution continues.
    unsafe { core::arch::asm!("twi 31, 0, 0x19") };
}

fn succeeded(status: u32) -> bool {
    NtStatus(status).is_success()
}

/// Export 130 entry: the console passes the 64-bit length in r5; `mount`
/// takes it as two words.
#[unsafe(naked)]
unsafe extern "C" fn mount_entry() {
    core::arch::naked_asm!(
        // rldicl 6, 5, 0, 32: the low word.
        ".long 0x78a60020",
        // rldicl 5, 5, 32, 32: the high word.
        ".long 0x78a50022",
        "lis 12, {function}@ha",
        "addi 12, 12, {function}@l",
        "b {bridge}",
        function = sym mount,
        bridge = sym crate::exports::export_bridge,
    )
}
export_raw!(130, mount_entry);

/// Export 130 (stock 0x91f549f8): mount the image file `file` as device
/// `name` of `length` bytes on a system thread and return its status.
extern "C" fn mount(
    file: *const AnsiString,
    name: *const AnsiString,
    length_high: u32,
    length_low: u32,
) -> u32 {
    let mut storage = MaybeUninit::<MountRequest>::uninit();
    let request = storage.as_mut_ptr();
    // SAFETY: `request` is the local block; the fields are written in place
    // and `status` is read only after the mount thread stored it and set
    // `done`, its last access to the block.
    unsafe {
        (*request).file = file;
        (*request).name = name;
        (*request).length = (u64::from(length_high) << 32) | u64::from(length_low);
        EventObject::initialize(&raw mut (*request).done, SYNCHRONIZATION);
        xboxkrnl::KeEnterCriticalRegion();
        let mut status = xboxkrnl::ExCreateThread(
            null_mut(),
            0,
            null_mut(),
            0,
            mount_thread as *const () as usize as u32,
            request as usize as u32,
            MOUNT_THREAD_FLAGS,
        )
        .0;
        if succeeded(status) {
            xboxkrnl::KeWaitForSingleObject(
                (&raw mut (*request).done).cast(),
                WaitReason::UserRequest,
                ProcessorMode::Kernel,
                false,
                null(),
            );
            status = (*request).status;
        }
        xboxkrnl::KeLeaveCriticalRegion();
        status
    }
}

/// Mount thread (stock 0x91f548b0). A mounted device stays until
/// [`dismount_all`]. The exit status is the result of the last kernel
/// call, as in stock.
extern "C" fn mount_thread(request: *mut MountRequest) -> u32 {
    // SAFETY: `mount` keeps the request alive until `done` is set.
    let (file_name, name, length) =
        unsafe { ((*request).file, (*request).name, (*request).length) };
    let attributes = ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: file_name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    let mut io_status = IoStatusBlock::default();
    let mut file = 0u32;
    let mut device = None;
    // SAFETY: `attributes` refers to the request's name, which `mount` keeps
    // alive; `file` and `io_status` are live locals.
    let opened = unsafe {
        xboxkrnl::NtOpenFile(
            (&raw mut file).cast(),
            AccessMask::GENERIC_READ,
            &attributes,
            &mut io_status,
            ShareAccess::READ,
            CreateOptions::empty(),
        )
    };
    let status = if succeeded(opened.0) {
        match create_device(file, name, length) {
            Ok(created) => {
                device = Some(created);
                MOUNTED.fetch_add(1, Ordering::Relaxed);
                NtStatus::SUCCESS
            }
            Err(error) => NtStatus::from(error),
        }
        .0
    } else {
        file = 0;
        opened.0
    };
    // SAFETY: as above; `mount` may release the request once `done` is set.
    let mut result = unsafe {
        (*request).status = status;
        xboxkrnl::KeSetEvent((&raw mut (*request).done).cast(), 1, false)
    };
    let mounted = succeeded(status);
    if mounted {
        // SAFETY: `DISMOUNT` is a static event built by `GlobalEvent::new`.
        result = unsafe {
            xboxkrnl::KeWaitForSingleObject(
                DISMOUNT.pointer().cast(),
                WaitReason::UserRequest,
                ProcessorMode::Kernel,
                false,
                null(),
            )
        }
        .0;
    }
    if let Some(device) = device {
        // SAFETY: the device was created by `create_device` and is deleted once.
        result = unsafe { delete_device(device) };
    }
    if file != 0 {
        // SAFETY: `file` was opened above and is closed once.
        result = unsafe { xboxkrnl::NtClose(Handle::from_raw(file)) }.0;
    }
    if mounted && MOUNTED.fetch_sub(1, Ordering::Relaxed) == 1 {
        // SAFETY: `DISMOUNTED` is a static event built by `GlobalEvent::new`.
        result = unsafe { xboxkrnl::KeSetEvent(DISMOUNTED.pointer().cast(), 1, false) };
    }
    result
}

/// Title termination part (stock 0x91f54138, the first call of the title
/// terminate routine 0x91f32398): release every mounted device and wait
/// until the last mount thread deleted its device.
pub(crate) fn dismount_all() {
    if MOUNTED.load(Ordering::Relaxed) != 0 {
        // SAFETY: `DISMOUNT` and `DISMOUNTED` are static events built by
        // `GlobalEvent::new`.
        unsafe {
            xboxkrnl::KeSetEvent(DISMOUNT.pointer().cast(), 1, false);
            xboxkrnl::KeWaitForSingleObject(
                DISMOUNTED.pointer().cast(),
                WaitReason::UserRequest,
                ProcessorMode::Kernel,
                false,
                null(),
            );
            xboxkrnl::KeResetEvent(DISMOUNT.pointer().cast());
        }
    }
}

/// Create the device for `file` and start its worker (stock 0x91f54718).
/// The start offset and the additional extension size stock takes are 0
/// at its only call.
fn create_device(
    file: u32,
    name: *const AnsiString,
    length: u64,
) -> Result<*mut DeviceObject, KernelError> {
    if length as u32 & SECTOR_MASK != 0 {
        return Err(KernelError::MappedAlignment);
    }
    let mut io_event = 0u32;
    // SAFETY: `io_event` is a live local.
    let created = unsafe {
        xboxkrnl::NtCreateEvent(
            (&raw mut io_event).cast(),
            null(),
            EventType::Synchronization,
            false,
        )
    };
    created.result()?;
    let mut device: *mut DeviceObject = null_mut();
    // SAFETY: `DRIVER` is the static driver object, `name` is the caller's
    // counted name, and `device` is a live local.
    let status = unsafe {
        IoCreateDevice(
            DRIVER.0.get(),
            size_of::<Extension>() as u32,
            name,
            DEVICE_TYPE,
            // Stock passes 0 for `options`; its meaning is not reverse
            // engineered.
            0,
            &mut device,
        )
    };
    if let Err(error) = status.result() {
        // SAFETY: `io_event` was created above and is closed once.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(io_event)) };
        return Err(error);
    }
    // SAFETY: the kernel created the device with an extension of the
    // requested size; nothing else uses it yet.
    unsafe {
        let Some(extension) = NonNull::new((*device).device_extension.cast::<Extension>()) else {
            assertion_trap();
            // Stock goes on to write through the null extension.
            panic!();
        };
        let extension = extension.as_ptr();
        (*device).alignment_requirement = WORD_ALIGNMENT;
        (*extension).file = file;
        (*extension).io_event = io_event;
        (*extension).irp = None;
        (*extension).start = 0;
        (*extension).length = length;
        EventObject::initialize(&raw mut (*extension).work, SYNCHRONIZATION);
        let process_flags = if xboxkrnl::KeGetCurrentProcessType() == ProcessType::SYSTEM {
            THREAD_SYSTEM_PROCESS
        } else {
            0
        };
        let status = xboxkrnl::ExCreateThread(
            (&raw mut (*extension).thread).cast(),
            WORKER_STACK_SIZE,
            null_mut(),
            0,
            worker as *const () as usize as u32,
            device as usize as u32,
            ThreadCreationFlags::from_bits_retain(WORKER_THREAD_FLAGS | process_flags),
        );
        if let Err(error) = status.result() {
            (*extension).thread = None;
            delete_device(device);
            return Err(error);
        }
        // A null thread passes as a null pointer, as the stock call does.
        KeSetPriorityThread(
            (*extension)
                .thread
                .map_or(null_mut(), |thread| thread.as_ptr().cast()),
            WORKER_PRIORITY,
        );
        (*device).flags.remove(DeviceObjectFlags::INITIALIZING);
    }
    Ok(device)
}

/// Dismount and delete a device after ending its worker (stock
/// 0x91f54680). Returns the r3 of the final dereference, as stock.
///
/// # Safety
/// `device` must be a device of this driver that is not yet deleted.
unsafe fn delete_device(device: *mut DeviceObject) -> u32 {
    // SAFETY: guaranteed by the caller; the worker ends before the device
    // is released.
    unsafe {
        let extension = (*device).device_extension.cast::<Extension>();
        (*device).flags.insert(DeviceObjectFlags::INITIALIZING);
        IoDismountVolume(device);
        let thread = (*extension).thread;
        (*extension).thread = None;
        if let Some(thread) = thread {
            if !(*device).current_irp.is_null() {
                assertion_trap();
            }
            xboxkrnl::KeSetEvent((&raw mut (*extension).work).cast(), 1, false);
            xboxkrnl::KeWaitForSingleObject(
                thread.as_ptr().cast(),
                WaitReason::UserRequest,
                ProcessorMode::Kernel,
                false,
                null(),
            );
            xboxkrnl::ObDereferenceObject(thread.as_ptr() as usize as u32);
        }
        xboxkrnl::NtClose(Handle::from_raw((*extension).io_event));
        xboxkrnl::ObMakeTemporaryObject(device as usize as u32);
        dereference_object(device as usize as u32)
    }
}

crate::kernel::forward!(
    /// ObDereferenceObject with its r3 passed through, as stock returns it.
    fn dereference_object(u32) -> u32 => xboxkrnl::ObDereferenceObject
);

/// Worker thread (stock 0x91f545a8): performs each request start I/O hands
/// over, completes it, and starts the next. Ends when woken without a
/// request; the exit status is that wait's result.
extern "C" fn worker(device: *mut DeviceObject) -> u32 {
    // SAFETY: the device outlives its worker; `delete_device` waits for the
    // worker before it releases the device.
    unsafe {
        let extension = (*device).device_extension.cast::<Extension>();
        loop {
            let waited = xboxkrnl::KeWaitForSingleObject(
                (&raw mut (*extension).work).cast(),
                WaitReason::UserRequest,
                ProcessorMode::Kernel,
                false,
                null(),
            );
            let Some(irp) = (*extension).irp else {
                return waited.0;
            };
            (*extension).irp = None;
            let irp = irp.as_ptr();
            let status = if (*(*irp).current_stack_location).major_function
                > IrpMajorFunction::Write.raw()
            {
                xboxkrnl::NtFlushBuffersFile(
                    Handle::from_raw((*extension).file),
                    &raw mut (*irp).io_status,
                )
                .0
            } else {
                transfer(extension, irp)
            };
            (*irp).io_status.status = NtStatus(status);
            xboxkrnl::KfRaiseIrql(Irql::DISPATCH);
            xboxkrnl::IoCompleteRequest(irp, u32::from(succeeded(status)));
            xboxkrnl::IoStartNextPacket(device);
            xboxkrnl::KfLowerIrql(Irql::PASSIVE);
        }
    }
}

/// Read or write the queued sectors in the image file (stock 0x91f541a8).
///
/// # Safety
/// `extension` and `irp` must be the worker's device extension and the
/// request it took.
unsafe fn transfer(extension: *mut Extension, irp: *mut Irp) -> u32 {
    // SAFETY: guaranteed by the caller; the transfer address was checked or
    // asserted when the request was queued.
    unsafe {
        let location = (*irp).current_stack_location;
        let parameters = (*location).parameters.words;
        let length = parameters[LENGTH];
        // Stock forms the byte offset in 32 bits.
        let offset = u64::from(parameters[SECTOR] << SECTOR_SHIFT);
        let buffer = parameters[BUFFER_OFFSET].wrapping_add(parameters[BUFFER]);
        let (file, event) = ((*extension).file, (*extension).io_event);
        let mut io_status = IoStatusBlock::default();
        let io_status = &raw mut io_status;
        let read = (*location).major_function == IrpMajorFunction::Read.raw();
        let started = if read {
            xboxkrnl::NtReadFile(
                Handle::from_raw(file),
                Handle::from_raw(event),
                0,
                0,
                io_status,
                buffer as usize as *mut u8,
                length,
                &offset,
            )
        } else {
            xboxkrnl::NtWriteFile(
                Handle::from_raw(file),
                Handle::from_raw(event),
                0,
                0,
                io_status,
                buffer as usize as *const u8,
                length,
                &offset,
            )
        };
        let mut status = if started == NtStatus::PENDING {
            if !succeeded(
                xboxkrnl::NtWaitForSingleObjectEx(
                    Handle::from_raw(event),
                    ProcessorMode::Kernel,
                    false,
                    null(),
                )
                .0,
            ) {
                assertion_trap();
            }
            (&raw const (*io_status).status).read_volatile().0
        } else {
            started.0
        };
        let information = (&raw const (*io_status).information).read_volatile();
        (*irp).io_status.information = information;
        if read {
            if NtStatus(status) == KernelError::EndOfFile.status() {
                core::ptr::write_bytes(buffer as usize as *mut u8, 0, length as usize);
                (*irp).io_status.information = length;
                status = NtStatus::SUCCESS.0;
            } else if information < length {
                core::ptr::write_bytes(
                    buffer.wrapping_add(information) as usize as *mut u8,
                    0,
                    (length - information) as usize,
                );
                (*irp).io_status.information = length;
            }
        } else if succeeded(status) {
            (*extension).writes = (*extension).writes.wrapping_add(1);
            if information < length {
                status = KernelError::EndOfFile.status().0;
            }
        }
        status
    }
}

/// Store `status` in the request and complete it without a priority boost.
///
/// # Safety
/// `irp` must be a request this driver owns.
unsafe fn complete(irp: *mut Irp, status: NtStatus) -> NtStatus {
    // SAFETY: guaranteed by the caller.
    unsafe {
        (*irp).io_status.status = status;
        xboxkrnl::IoCompleteRequest(irp, 0);
    }
    status
}

/// Start I/O (stock 0x91f54658): hand the request to the worker.
extern "C" fn start_io(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    // SAFETY: the kernel passes a device of this driver; the worker has
    // taken the previous request before the next packet starts.
    unsafe {
        let extension = (*device).device_extension.cast::<Extension>();
        if (*extension).irp.is_some() {
            assertion_trap();
        }
        (*extension).irp = NonNull::new(irp);
        xboxkrnl::KeSetEvent((&raw mut (*extension).work).cast(), 1, false)
    }
}

/// Read and write dispatch (stock 0x91f54310): checks the request, converts
/// it to sectors, and queues it.
extern "C" fn read_write(device: *mut DeviceObject, irp: *mut Irp) -> NtStatus {
    // SAFETY: the kernel passes a device of this driver and a request with
    // its current stack location.
    unsafe {
        let extension = (*device).device_extension.cast::<Extension>();
        let location = (*irp).current_stack_location;
        let parameters = (*location).parameters.read_write;
        let length = parameters.length;
        let offset = parameters.byte_offset();
        let end = u64::from(length).wrapping_add(offset) as i64;
        let limit = (*extension).length as i64;
        let user_buffer = (*irp).user_buffer.addr() as u32;
        let address_given = (*location).flags.contains(IoStackFlags::BUFFER_ADDRESS);
        if address_given {
            if parameters.buffer & SECTOR_MASK != 0 {
                assertion_trap();
            }
            if length & SECTOR_MASK != 0 {
                assertion_trap();
            }
            if offset as u32 & SECTOR_MASK != 0 {
                assertion_trap();
            }
            if end > limit {
                assertion_trap();
            }
        } else if user_buffer & WORD_ALIGNMENT != 0
            || parameters.buffer & WORD_ALIGNMENT != 0
            || length & SECTOR_MASK != 0
            || offset as u32 & SECTOR_MASK != 0
            || end > limit
        {
            return complete(irp, KernelError::InvalidParameter.status());
        }
        if length == 0 {
            (*irp).io_status.information = 0;
            return complete(irp, NtStatus::SUCCESS);
        }
        let words = &mut (*location).parameters.words;
        words[SECTOR] = ((*extension).start.wrapping_add(offset) as i64 >> SECTOR_SHIFT) as u32;
        if address_given {
            words[BUFFER_OFFSET] = 0;
        } else {
            words[BUFFER_OFFSET] = parameters.buffer;
            words[BUFFER] = user_buffer;
        }
        (*irp).io_status.information = length;
        (*location).control |= IoStackControl::PENDING_RETURNED;
    }
    // SAFETY: the kernel passed `device` and `irp` to this dispatch routine.
    unsafe { xboxkrnl::IoStartPacket(device, irp, null()) };
    NtStatus::PENDING
}

/// Flush dispatch (stock 0x91f54470): queued for the worker.
extern "C" fn flush(device: *mut DeviceObject, irp: *mut Irp) -> NtStatus {
    // SAFETY: the kernel passes a request with its current stack location.
    unsafe { (*(*irp).current_stack_location).control |= IoStackControl::PENDING_RETURNED };
    // SAFETY: the kernel passed `device` and `irp` to this dispatch routine.
    unsafe { xboxkrnl::IoStartPacket(device, irp, null()) };
    NtStatus::PENDING
}

/// Device control dispatch (stock 0x91f544f0, geometry in 0x91f544a8).
extern "C" fn device_control(device: *mut DeviceObject, irp: *mut Irp) -> NtStatus {
    // SAFETY: the kernel passes a device of this driver and a request whose
    // user buffer holds the stated output length.
    unsafe {
        let extension = (*device).device_extension.cast::<Extension>();
        let parameters = (*(*irp).current_stack_location).parameters.device_control;
        let output_length = parameters.output_length;
        let output = (*irp).user_buffer;
        let status = match parameters.control_code {
            IoControlCode::DISK_GET_DRIVE_GEOMETRY if output_length < 8 => {
                KernelError::BufferTooSmall.status()
            }
            IoControlCode::DISK_GET_DRIVE_GEOMETRY => {
                let output = output.cast::<u32>();
                output.add(1).write_unaligned(SECTOR_SIZE);
                output.write_unaligned(((*extension).length as i64 >> SECTOR_SHIFT) as u32);
                (*irp).io_status.information = 8;
                NtStatus::SUCCESS
            }
            IoControlCode::DISK_GET_PARTITION_INFO if output_length < 0x10 => {
                KernelError::BufferTooSmall.status()
            }
            IoControlCode::DISK_GET_PARTITION_INFO => {
                let output = output.cast::<u64>();
                output.write_unaligned((*extension).start);
                output.add(1).write_unaligned((*extension).length);
                (*irp).io_status.information = 0x10;
                NtStatus::SUCCESS
            }
            _ => KernelError::InvalidDeviceRequest.status(),
        };
        complete(irp, status)
    }
}
