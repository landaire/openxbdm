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

use openxbdm_core::status::NtStatus;

use crate::exports::export_raw;
use crate::kernel;
use crate::kernel::AnsiString;
use crate::kernel::IoStatusBlock;
use crate::kernel::ObjectAttributes;
use crate::kernel::import_thunk;

import_thunk!(
    /// Stock passes 0 for `options`; its meaning is not reverse engineered.
    IoCreateDevice(
        driver: *const DriverObject,
        extension_size: u32,
        name: *const AnsiString,
        device_type: u32,
        options: u32,
        device: *mut *mut DeviceObject,
    ) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 0x37
);
import_thunk!(
    IoDismountVolume(device: *mut DeviceObject) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 0x3b
);
import_thunk!(
    IoInvalidDeviceRequest(device: *mut DeviceObject, irp: *mut Irp) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 0x41
);
import_thunk!(
    KeSetPriorityThread(thread: Option<NonNull<u32>>, priority: u32) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 0xa3
);

const STATUS_PENDING: NtStatus = NtStatus(0x103);
const STATUS_INVALID_PARAMETER: NtStatus = NtStatus(0xc000_000d);
const STATUS_INVALID_DEVICE_REQUEST: NtStatus = NtStatus(0xc000_0010);
const STATUS_END_OF_FILE: NtStatus = NtStatus(0xc000_0011);
const STATUS_BUFFER_TOO_SMALL: NtStatus = NtStatus(0xc000_0023);
const STATUS_MAPPED_ALIGNMENT: NtStatus = NtStatus(0xc000_0220);

const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 1;
const WAIT_USER_REQUEST: u32 = 3;
const KERNEL_MODE: u32 = 0;
const PASSIVE_LEVEL: u32 = 0;
const DISPATCH_LEVEL: u32 = 2;
/// `KeGetCurrentProcessType` of the system process.
const SYSTEM_PROCESS: u32 = 2;

/// `ExCreateThread` flags of the mount thread.
const MOUNT_THREAD_FLAGS: u32 = 0x22;
/// `ExCreateThread` flags of the worker; 0x80 returns a referenced thread
/// object instead of a handle.
const WORKER_THREAD_FLAGS: u32 = 0x0400_00a8;
/// Added to the worker flags when the creator runs in the system process.
const THREAD_SYSTEM_PROCESS: u32 = 0x2;
const WORKER_STACK_SIZE: u32 = 0x4000;
const WORKER_PRIORITY: u32 = 0x1f;

const DEVICE_TYPE: u32 = 0x3d;
/// Device flag set by the kernel at creation, cleared once the device is
/// ready and set again before its volume is dismounted.
const DEVICE_INITIALIZING: u32 = 0x10;
/// Alignment requirement of the device: word aligned transfer buffers.
const WORD_ALIGNMENT: u32 = 1;
const SECTOR_SIZE: u32 = 0x200;
const SECTOR_SHIFT: u32 = 9;
const SECTOR_MASK: u32 = SECTOR_SIZE - 1;

const MAJOR_READ: u8 = 2;
const MAJOR_WRITE: u8 = 3;
const MAJOR_FUNCTIONS: usize = 11;
/// Stack location flag: the buffer parameter is the transfer address and
/// the request is checked with assertion traps instead of refused.
const LOCATION_BUFFER_ADDRESS: u8 = 1;
/// Stack location control bit set before a request is queued.
const CONTROL_PENDING_RETURNED: u8 = 1;
/// Control code returning the sector count and the sector size (two dwords).
const CONTROL_GET_GEOMETRY: u32 = 0x0007_0000;
/// Control code returning the start offset and the length in bytes (two
/// quadwords).
const CONTROL_GET_PARTITION: u32 = 0x0007_4004;

/// Stack location parameter words (+0x04): transfer length, or output
/// buffer length of a control request.
const LENGTH: usize = 0;
/// Transfer address, or offset into the user buffer.
const BUFFER: usize = 1;
/// Byte offset as received, high word first.
const OFFSET: usize = 2;
/// Once queued: the first sector.
const SECTOR: usize = 2;
/// Once queued: added to the buffer parameter to form the transfer address.
const BUFFER_OFFSET: usize = 3;
const CONTROL_CODE: usize = 3;

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

/// I/O request packet; only the fields this driver uses.
#[repr(C)]
struct Irp {
    _header: [u32; 4],
    io_status: IoStatusBlock,
    _reserved: u32,
    user_buffer: u32,
    _overlay: [u32; 12],
    location: *mut StackLocation,
}

/// I/O stack location.
#[repr(C)]
struct StackLocation {
    major_function: u8,
    _minor_function: u8,
    flags: u8,
    control: u8,
    parameters: [u32; 4],
}

/// Device object; only the fields this driver uses.
#[repr(C)]
struct DeviceObject {
    _header: [u32; 4],
    current_irp: Option<NonNull<Irp>>,
    flags: u32,
    extension: *mut Extension,
    _type: [u8; 4],
    _unknown: u32,
    alignment: u32,
}

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

type Dispatch = extern "C" fn(*mut DeviceObject, *mut Irp) -> u32;

/// Driver object.
#[repr(C)]
struct DriverObject {
    start_io: Dispatch,
    /// Routines this driver does not supply.
    unsupplied: [Option<Dispatch>; 2],
    major_function: [Dispatch; MAJOR_FUNCTIONS],
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
    assert!(core::mem::offset_of!(Irp, io_status) == 0x10);
    assert!(core::mem::offset_of!(Irp, user_buffer) == 0x1c);
    assert!(core::mem::offset_of!(Irp, location) == 0x50);
    assert!(core::mem::offset_of!(StackLocation, parameters) == 4);
    assert!(core::mem::offset_of!(DeviceObject, current_irp) == 0x10);
    assert!(core::mem::offset_of!(DeviceObject, extension) == 0x18);
    assert!(core::mem::offset_of!(DeviceObject, alignment) == 0x24);
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
    ($entry:ident, $function:path) => {
        #[unsafe(naked)]
        extern "C" fn $entry(_: *mut DeviceObject, _: *mut Irp) -> u32 {
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

kernel_entry!(start_io_entry, start_io);
kernel_entry!(read_write_entry, read_write);
kernel_entry!(flush_entry, flush);
kernel_entry!(device_control_entry, device_control);
kernel_entry!(invalid_request_entry, IoInvalidDeviceRequest);

/// Writable like stock's (0x91f98e94, in .data); the kernel keeps a
/// pointer to it.
struct Driver(UnsafeCell<DriverObject>);

// SAFETY: never written by this module.
unsafe impl Sync for Driver {}

static DRIVER: Driver = Driver(UnsafeCell::new(DriverObject {
    start_io: start_io_entry,
    unsupplied: [None, None],
    major_function: [
        invalid_request_entry,
        invalid_request_entry,
        read_write_entry,
        read_write_entry,
        invalid_request_entry,
        invalid_request_entry,
        flush_entry,
        invalid_request_entry,
        invalid_request_entry,
        device_control_entry,
        invalid_request_entry,
    ],
}));

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
        kernel::KeEnterCriticalRegion();
        let mut status = kernel::ExCreateThread(
            null_mut(),
            0,
            null_mut(),
            0,
            mount_thread as *const () as usize as u32,
            request as usize as u32,
            MOUNT_THREAD_FLAGS,
        );
        if succeeded(status) {
            kernel::KeWaitForSingleObject(
                (&raw mut (*request).done).cast(),
                WAIT_USER_REQUEST,
                KERNEL_MODE,
                0,
                null(),
            );
            status = (*request).status;
        }
        kernel::KeLeaveCriticalRegion();
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
        root_directory: 0,
        object_name: file_name,
        attributes: kernel::OBJ_CASE_INSENSITIVE,
    };
    let mut io_status = IoStatusBlock::default();
    let mut file = 0u32;
    let mut device = None;
    let opened = kernel::NtOpenFile(
        &mut file,
        GENERIC_READ,
        &attributes,
        &mut io_status,
        FILE_SHARE_READ,
        0,
    );
    let status = if succeeded(opened) {
        match create_device(file, name, length) {
            Ok(created) => {
                device = Some(created);
                MOUNTED.fetch_add(1, Ordering::Relaxed);
                NtStatus::SUCCESS.0
            }
            Err(status) => status.0,
        }
    } else {
        file = 0;
        opened
    };
    // SAFETY: as above; `mount` may release the request once `done` is set.
    let mut result = unsafe {
        (*request).status = status;
        kernel::KeSetEvent((&raw mut (*request).done).cast(), 1, 0)
    };
    let mounted = succeeded(status);
    if mounted {
        result = kernel::KeWaitForSingleObject(
            DISMOUNT.pointer(),
            WAIT_USER_REQUEST,
            KERNEL_MODE,
            0,
            null(),
        );
    }
    if let Some(device) = device {
        // SAFETY: the device was created by `create_device` and is deleted once.
        result = unsafe { delete_device(device) };
    }
    if file != 0 {
        result = kernel::NtClose(file);
    }
    if mounted && MOUNTED.fetch_sub(1, Ordering::Relaxed) == 1 {
        result = kernel::KeSetEvent(DISMOUNTED.pointer(), 1, 0);
    }
    result
}

/// Title termination part (stock 0x91f54138, the first call of the title
/// terminate routine 0x91f32398): release every mounted device and wait
/// until the last mount thread deleted its device.
pub(crate) fn dismount_all() {
    if MOUNTED.load(Ordering::Relaxed) != 0 {
        kernel::KeSetEvent(DISMOUNT.pointer(), 1, 0);
        kernel::KeWaitForSingleObject(
            DISMOUNTED.pointer(),
            WAIT_USER_REQUEST,
            KERNEL_MODE,
            0,
            null(),
        );
        kernel::KeResetEvent(DISMOUNT.pointer());
    }
}

/// Create the device for `file` and start its worker (stock 0x91f54718).
/// The start offset and the additional extension size stock takes are 0
/// at its only call.
fn create_device(
    file: u32,
    name: *const AnsiString,
    length: u64,
) -> Result<*mut DeviceObject, NtStatus> {
    if length as u32 & SECTOR_MASK != 0 {
        return Err(STATUS_MAPPED_ALIGNMENT);
    }
    let mut io_event = 0u32;
    let created = kernel::NtCreateEvent(&mut io_event, null(), u32::from(SYNCHRONIZATION), 0);
    if !succeeded(created) {
        return Err(NtStatus(created));
    }
    let mut device: *mut DeviceObject = null_mut();
    let status = IoCreateDevice(
        DRIVER.0.get(),
        size_of::<Extension>() as u32,
        name,
        DEVICE_TYPE,
        0,
        &mut device,
    );
    if !succeeded(status) {
        kernel::NtClose(io_event);
        return Err(NtStatus(status));
    }
    // SAFETY: the kernel created the device with an extension of the
    // requested size; nothing else uses it yet.
    unsafe {
        let Some(extension) = NonNull::new((*device).extension) else {
            assertion_trap();
            // Stock goes on to write through the null extension.
            panic!();
        };
        let extension = extension.as_ptr();
        (*device).alignment = WORD_ALIGNMENT;
        (*extension).file = file;
        (*extension).io_event = io_event;
        (*extension).irp = None;
        (*extension).start = 0;
        (*extension).length = length;
        EventObject::initialize(&raw mut (*extension).work, SYNCHRONIZATION);
        let process_flags = if kernel::KeGetCurrentProcessType() == SYSTEM_PROCESS {
            THREAD_SYSTEM_PROCESS
        } else {
            0
        };
        let status = kernel::ExCreateThread(
            (&raw mut (*extension).thread).cast(),
            WORKER_STACK_SIZE,
            null_mut(),
            0,
            worker as *const () as usize as u32,
            device as usize as u32,
            WORKER_THREAD_FLAGS | process_flags,
        );
        if !succeeded(status) {
            (*extension).thread = None;
            delete_device(device);
            return Err(NtStatus(status));
        }
        KeSetPriorityThread((*extension).thread, WORKER_PRIORITY);
        (*device).flags &= !DEVICE_INITIALIZING;
    }
    Ok(device)
}

/// Dismount and delete a device after ending its worker (stock
/// 0x91f54680). Returns the result of the final dereference, as stock.
///
/// # Safety
/// `device` must be a device of this driver that is not yet deleted.
unsafe fn delete_device(device: *mut DeviceObject) -> u32 {
    // SAFETY: guaranteed by the caller; the worker ends before the device
    // is released.
    unsafe {
        let extension = (*device).extension;
        (*device).flags |= DEVICE_INITIALIZING;
        IoDismountVolume(device);
        let thread = (*extension).thread;
        (*extension).thread = None;
        if let Some(thread) = thread {
            if (*device).current_irp.is_some() {
                assertion_trap();
            }
            kernel::KeSetEvent((&raw mut (*extension).work).cast(), 1, 0);
            kernel::KeWaitForSingleObject(
                thread.as_ptr(),
                WAIT_USER_REQUEST,
                KERNEL_MODE,
                0,
                null(),
            );
            kernel::ObDereferenceObject(thread.as_ptr() as usize as u32);
        }
        kernel::NtClose((*extension).io_event);
        kernel::ObMakeTemporaryObject(device as usize as u32);
        kernel::ObDereferenceObject(device as usize as u32)
    }
}

/// Worker thread (stock 0x91f545a8): performs each request start I/O hands
/// over, completes it, and starts the next. Ends when woken without a
/// request; the exit status is that wait's result.
extern "C" fn worker(device: *mut DeviceObject) -> u32 {
    // SAFETY: the device outlives its worker; `delete_device` waits for the
    // worker before it releases the device.
    unsafe {
        let extension = (*device).extension;
        loop {
            let waited = kernel::KeWaitForSingleObject(
                (&raw mut (*extension).work).cast(),
                WAIT_USER_REQUEST,
                KERNEL_MODE,
                0,
                null(),
            );
            let Some(irp) = (*extension).irp else {
                return waited;
            };
            (*extension).irp = None;
            let irp = irp.as_ptr();
            let status = if (*(*irp).location).major_function > MAJOR_WRITE {
                kernel::NtFlushBuffersFile((*extension).file, &raw mut (*irp).io_status)
            } else {
                transfer(extension, irp)
            };
            (*irp).io_status.status = status;
            kernel::KfRaiseIrql(DISPATCH_LEVEL);
            kernel::IoCompleteRequest(irp as usize as u32, u32::from(succeeded(status)));
            kernel::IoStartNextPacket(device as usize as u32);
            kernel::KfLowerIrql(PASSIVE_LEVEL);
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
        let location = (*irp).location;
        let parameters = (*location).parameters;
        let length = parameters[LENGTH];
        // Stock forms the byte offset in 32 bits.
        let offset = u64::from(parameters[SECTOR] << SECTOR_SHIFT);
        let buffer = parameters[BUFFER_OFFSET].wrapping_add(parameters[BUFFER]);
        let (file, event) = ((*extension).file, (*extension).io_event);
        let mut io_status = IoStatusBlock::default();
        let io_status = &raw mut io_status;
        let read = (*location).major_function == MAJOR_READ;
        let started = if read {
            kernel::NtReadFile(
                file,
                event,
                0,
                0,
                io_status,
                buffer as usize as *mut u8,
                length,
                &offset,
            )
        } else {
            kernel::NtWriteFile(
                file,
                event,
                0,
                0,
                io_status,
                buffer as usize as *const u8,
                length,
                &offset,
            )
        };
        let mut status = if NtStatus(started) == STATUS_PENDING {
            if !succeeded(kernel::NtWaitForSingleObjectEx(
                event,
                KERNEL_MODE,
                0,
                null(),
            )) {
                assertion_trap();
            }
            (&raw const (*io_status).status).read_volatile()
        } else {
            started
        };
        let information = (&raw const (*io_status).information).read_volatile();
        (*irp).io_status.information = information;
        if read {
            if NtStatus(status) == STATUS_END_OF_FILE {
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
                status = STATUS_END_OF_FILE.0;
            }
        }
        status
    }
}

/// Store `status` in the request and complete it without a priority boost.
///
/// # Safety
/// `irp` must be a request this driver owns.
unsafe fn complete(irp: *mut Irp, status: NtStatus) -> u32 {
    // SAFETY: guaranteed by the caller.
    unsafe { (*irp).io_status.status = status.0 };
    kernel::IoCompleteRequest(irp as usize as u32, 0);
    status.0
}

/// Start I/O (stock 0x91f54658): hand the request to the worker.
extern "C" fn start_io(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    // SAFETY: the kernel passes a device of this driver; the worker has
    // taken the previous request before the next packet starts.
    unsafe {
        let extension = (*device).extension;
        if (*extension).irp.is_some() {
            assertion_trap();
        }
        (*extension).irp = NonNull::new(irp);
        kernel::KeSetEvent((&raw mut (*extension).work).cast(), 1, 0)
    }
}

/// Read and write dispatch (stock 0x91f54310): checks the request, converts
/// it to sectors, and queues it.
extern "C" fn read_write(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    // SAFETY: the kernel passes a device of this driver and a request with
    // its current stack location.
    unsafe {
        let extension = (*device).extension;
        let location = (*irp).location;
        let parameters = (*location).parameters;
        let length = parameters[LENGTH];
        let offset = (u64::from(parameters[OFFSET]) << 32) | u64::from(parameters[OFFSET + 1]);
        let end = u64::from(length).wrapping_add(offset) as i64;
        let limit = (*extension).length as i64;
        let address_given = (*location).flags & LOCATION_BUFFER_ADDRESS != 0;
        if address_given {
            if parameters[BUFFER] & SECTOR_MASK != 0 {
                assertion_trap();
            }
            if length & SECTOR_MASK != 0 {
                assertion_trap();
            }
            if parameters[OFFSET + 1] & SECTOR_MASK != 0 {
                assertion_trap();
            }
            if end > limit {
                assertion_trap();
            }
        } else if (*irp).user_buffer & WORD_ALIGNMENT != 0
            || parameters[BUFFER] & WORD_ALIGNMENT != 0
            || length & SECTOR_MASK != 0
            || parameters[OFFSET + 1] & SECTOR_MASK != 0
            || end > limit
        {
            return complete(irp, STATUS_INVALID_PARAMETER);
        }
        if length == 0 {
            (*irp).io_status.information = 0;
            return complete(irp, NtStatus::SUCCESS);
        }
        (*location).parameters[SECTOR] =
            ((*extension).start.wrapping_add(offset) as i64 >> SECTOR_SHIFT) as u32;
        if address_given {
            (*location).parameters[BUFFER_OFFSET] = 0;
        } else {
            (*location).parameters[BUFFER_OFFSET] = parameters[BUFFER];
            (*location).parameters[BUFFER] = (*irp).user_buffer;
        }
        (*irp).io_status.information = length;
        (*location).control |= CONTROL_PENDING_RETURNED;
    }
    kernel::IoStartPacket(device as usize as u32, irp as usize as u32, null());
    STATUS_PENDING.0
}

/// Flush dispatch (stock 0x91f54470): queued for the worker.
extern "C" fn flush(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    // SAFETY: the kernel passes a request with its current stack location.
    unsafe { (*(*irp).location).control |= CONTROL_PENDING_RETURNED };
    kernel::IoStartPacket(device as usize as u32, irp as usize as u32, null());
    STATUS_PENDING.0
}

/// Device control dispatch (stock 0x91f544f0, geometry in 0x91f544a8).
extern "C" fn device_control(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    // SAFETY: the kernel passes a device of this driver and a request whose
    // user buffer holds the stated output length.
    unsafe {
        let extension = (*device).extension;
        let location = (*irp).location;
        let output_length = (*location).parameters[LENGTH];
        let output = (*irp).user_buffer as usize;
        let status = match (*location).parameters[CONTROL_CODE] {
            CONTROL_GET_GEOMETRY if output_length < 8 => STATUS_BUFFER_TOO_SMALL,
            CONTROL_GET_GEOMETRY => {
                let output = output as *mut u32;
                output.add(1).write_unaligned(SECTOR_SIZE);
                output.write_unaligned(((*extension).length as i64 >> SECTOR_SHIFT) as u32);
                (*irp).io_status.information = 8;
                NtStatus::SUCCESS
            }
            CONTROL_GET_PARTITION if output_length < 0x10 => STATUS_BUFFER_TOO_SMALL,
            CONTROL_GET_PARTITION => {
                let output = output as *mut u64;
                output.write_unaligned((*extension).start);
                output.add(1).write_unaligned((*extension).length);
                (*irp).io_status.information = 0x10;
                NtStatus::SUCCESS
            }
            _ => STATUS_INVALID_DEVICE_REQUEST,
        };
        complete(irp, status)
    }
}
