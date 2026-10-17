//! Xbox Studio subsystem (stock 0x91f654e8 to 0x91f65dd0). The studio
//! service of XAM (export 1670) runs on a worker thread over the USB null
//! cable (kernel export 810) while a device is attached and test mode is
//! off, or over a TCP connection accepted on a listener that
//! `xstudio DedicateSocket` opens. The service drives either transport
//! through a table of six routines at the start of the transport object.

mod null_cable;
mod socket;

use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::SocketId;
use openxbdm_server::commands::performance::studio::StudioError;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::status::set_last_error;
use xbox360::time::sleep;
use xbox360_sys::xam;
use xbox360_sys::xam::AddressFamily;
use xbox360_sys::xam::IoctlCommand;
use xbox360_sys::xam::NetworkEvents;
use xbox360_sys::xam::Protocol;
use xbox360_sys::xam::SockAddrIn;
use xbox360_sys::xam::Socket;
use xbox360_sys::xam::SocketType;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitType;

use self::null_cable::create_null_cable_transport;
use self::socket::create_socket_transport;
use crate::kernel;
use crate::kernel::CriticalSection;

/// Kernel export that queues null-cable transfers.
const NULL_CABLE_ORDINAL: Ordinal = Ordinal::new(810).unwrap();

/// Guards the flags below (stock 0x91fab700).
static LOCK: KspinLock = KspinLock::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static DEVICE_ATTACHED: AtomicBool = AtomicBool::new(false);
static DEDICATED: AtomicBool = AtomicBool::new(false);
/// The worker ended; the server pass collects it.
static FINISHED: AtomicBool = AtomicBool::new(false);
static TEST_MODE: AtomicBool = AtomicBool::new(false);

static SECTION: CriticalSection = CriticalSection::new();
static SECTION_READY: AtomicBool = AtomicBool::new(false);
static SESSION: SessionCell = SessionCell(UnsafeCell::new(Session {
    failure: None,
    worker: None,
    stop_event: None,
    listener: None,
    attached: false,
    stopping: false,
}));

static NULL_CABLE_REQUEST: AtomicU32 = AtomicU32::new(0);
static STUDIO_SERVICE: AtomicU32 = AtomicU32::new(0);

/// Call code of the studio service export.
#[repr(u32)]
enum StudioServiceCall {
    /// Made before a session starts; failure skips the session.
    Prepare = 1,
    /// Runs a session over [`SessionArguments`] until the stop event is set
    /// or the connection ends.
    Run = 0x101,
}

/// Argument record of [`StudioServiceCall::Run`].
#[repr(C)]
struct SessionArguments {
    transport: u32,
    stop_event: u32,
}

const _: () = {
    assert!(offset_of!(SessionArguments, transport) == 0);
    assert!(offset_of!(SessionArguments, stop_event) == 4);
    assert!(size_of::<SessionArguments>() == 8);
};

/// Request code of the null-cable export.
#[repr(u32)]
enum NullCableRequest {
    Send = 1,
    Receive = 2,
    Cancel = 3,
    /// Report the device status again through monitor control code 0x99.
    ReportStatus = 4,
}

/// Value the kind routine of a transport returns.
#[repr(u32)]
enum TransportKind {
    NullCable = 1,
    Socket = 2,
}

/// Caller request record of the transport send, receive and result
/// routines. The null-cable driver completes it asynchronously.
#[repr(C)]
struct TransferRequest {
    /// Null-cable transfer count, or the socket transport's request handle.
    result: AtomicU32,
    /// Null-cable status; [`NtStatus::PENDING`] until the transfer ends.
    status: AtomicU32,
    _reserved: [AtomicU32; 2],
    /// Event handle the caller waits on.
    event: AtomicU32,
}

const _: () = {
    assert!(offset_of!(TransferRequest, result) == 0);
    assert!(offset_of!(TransferRequest, status) == 4);
    assert!(offset_of!(TransferRequest, event) == 0x10);
    assert!(size_of::<TransferRequest>() == 0x14);
};

impl TransferRequest {
    /// # Safety
    /// `address` is a caller request record that stays live for `'a`.
    unsafe fn from_address<'a>(address: u32) -> &'a Self {
        // SAFETY: per the contract; every field is an atomic word, so
        // concurrent writes by the null-cable driver are permitted.
        unsafe { kernel::object_at(address) }
    }

    fn event(&self) -> u32 {
        self.event.load(Ordering::Relaxed)
    }
}

/// Routine table at the start of every transport object, through which the
/// studio service drives the transport.
#[repr(C)]
struct Routines {
    kind: u32,
    release: u32,
    receive: u32,
    send: u32,
    result: u32,
    cancel: u32,
}

const _: () = {
    assert!(offset_of!(Routines, kind) == 0);
    assert!(offset_of!(Routines, release) == 4);
    assert!(offset_of!(Routines, receive) == 8);
    assert!(offset_of!(Routines, send) == 0xc);
    assert!(offset_of!(Routines, result) == 0x10);
    assert!(offset_of!(Routines, cancel) == 0x14);
    assert!(size_of::<Routines>() == 0x18);
};

/// Argument record of monitor control code 0x9f.
#[repr(C)]
struct TestModeArgument {
    _reserved: AtomicU32,
    enable: AtomicU32,
}

const _: () = {
    assert!(offset_of!(TestModeArgument, enable) == 4);
    assert!(size_of::<TestModeArgument>() == 8);
};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Handle(u32);

impl Handle {
    fn new(raw: u32) -> Option<Self> {
        (raw != 0).then_some(Self(raw))
    }
}

/// Session state guarded by [`SECTION`].
struct Session {
    /// Failure of a null-cable transport creation; disables the subsystem.
    failure: Option<StudioError>,
    worker: Option<Handle>,
    stop_event: Option<Handle>,
    listener: Option<SocketId>,
    /// The dedicated listener accepted its connection.
    attached: bool,
    /// A stop waits for the worker; unloading can stop concurrently with
    /// the server pass, and only one of them waits on the handle.
    stopping: bool,
}

struct SessionCell(UnsafeCell<Session>);

// SAFETY: every access holds `SECTION`.
unsafe impl Sync for SessionCell {}

/// Caller word that receives a transfer count.
///
/// # Safety
/// `address` is an aligned writable u32 that stays live for `'a`.
unsafe fn count_word<'a>(address: u32) -> &'a AtomicU32 {
    // SAFETY: per the contract.
    unsafe { kernel::object_at(address) }
}

/// Stock assertion trap (`twi 31, 0, 0x19`); execution continues after it.
fn assertion_trap() {
    // SAFETY: raises the trap exception stock raises; the debug routine or
    // the kernel resumes after it.
    unsafe { core::arch::asm!("twi 31, 0, 0x19") };
}

fn raw_handle(handle: Option<Handle>) -> u32 {
    handle.map_or(0, |handle| handle.0)
}

/// `SetEvent` (stock 0x91f738b8).
fn set_event(handle: Option<Handle>) {
    // SAFETY: the handle is an event handle of this module or 0, which the
    // kernel rejects; the previous-state pointer is null.
    let status = unsafe {
        xboxkrnl::NtSetEvent(
            xboxkrnl::Handle::from_raw(raw_handle(handle)),
            core::ptr::null_mut(),
        )
    };
    if let Err(error) = status.result() {
        set_last_error(error);
    }
}

/// `CloseHandle` (stock 0x91f738f8).
fn close_handle(handle: Handle) {
    // SAFETY: callers pass an owned handle and drop it afterwards.
    let status = unsafe { xboxkrnl::NtClose(xboxkrnl::Handle::from_raw(handle.0)) };
    if let Err(error) = status.result() {
        set_last_error(error);
    }
}

fn close_socket(socket: SocketId) {
    // SAFETY: callers pass an owned socket and drop it afterwards.
    unsafe { xam::NetDll_closesocket(XnCaller::DebugMonitor, Socket::from_raw(socket.0)) };
}

/// Run `operation` holding [`LOCK`].
fn with_lock<R>(operation: impl FnOnce() -> R) -> R {
    // SAFETY: LOCK is a static spin lock.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(LOCK.as_ptr()) };
    let result = operation();
    // SAFETY: acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(LOCK.as_ptr(), irql) };
    result
}

/// Run `operation` on the session; the caller holds [`SECTION`] and
/// `operation` does not reenter.
fn with_session<R>(operation: impl FnOnce(&mut Session) -> R) -> R {
    // SAFETY: `SECTION` serializes all access and calls do not nest.
    operation(unsafe { &mut *SESSION.0.get() })
}

fn resolve(module: SystemModule, ordinal: Ordinal) -> Result<u32, KernelError> {
    let handle = module.handle()?;
    let mut address = 0u32;
    // SAFETY: `handle` is a loaded module handle and `address` a live u32.
    let status = unsafe {
        xboxkrnl::XexGetProcedureAddress(handle.raw(), u32::from(ordinal.get()), &mut address)
    };

    status.result()?;
    Ok(address)
}

fn call(function: &AtomicU32, a0: u32, a1: u32) -> u32 {
    // SAFETY: set to a resolved export before `INITIALIZED`; both exports
    // take two register arguments.
    unsafe { kernel::call_export(function.load(Ordering::Acquire), a0, a1, 0, 0) }
}

/// Stock 0x91f654e8. Runs on the server thread once the network is up,
/// where stock runs it last in module initialization.
pub(crate) fn initialize() {
    /// XAM export of the studio service.
    const STUDIO_SERVICE_ORDINAL: Ordinal = Ordinal::new(1670).unwrap();

    SECTION.initialize();
    SECTION_READY.store(true, Ordering::Release);

    let exports = resolve(SystemModule::Kernel, NULL_CABLE_ORDINAL)
        .and_then(|request| Ok((request, resolve(SystemModule::Xam, STUDIO_SERVICE_ORDINAL)?)));
    match exports {
        Err(error) => {
            super::pmc::print(
                c"XStudio: Failed initialization %d\n",
                &[u64::from(NtStatus::from(error).0)],
            );
        }
        Ok((request, service)) => {
            NULL_CABLE_REQUEST.store(request, Ordering::Release);
            STUDIO_SERVICE.store(service, Ordering::Release);
            with_lock(|| INITIALIZED.store(true, Ordering::Relaxed));
            call(
                &NULL_CABLE_REQUEST,
                NullCableRequest::ReportStatus as u32,
                0,
            );
        }
    }
}

/// Stop the worker before the image unloads. Clearing the initialized flag
/// keeps a new worker from starting; a stop already running on the server
/// thread is waited out.
pub(super) fn shut_down() {
    with_lock(|| INITIALIZED.store(false, Ordering::Relaxed));
    if !SECTION_READY.load(Ordering::Acquire) {
        return;
    }

    loop {
        stop_session();
        SECTION.enter();
        let idle = with_session(|session| session.worker.is_none());
        SECTION.leave();

        if idle {
            break;
        }

        sleep(Duration::from_millis(1));
    }
}

/// Stock 0x91f65a18, run on every server pass. Stock alerts the server
/// thread to run it sooner; the passes here are at most 20 ms apart.
pub(crate) fn poll() {
    let (start, stop) = with_lock(|| {
        let (start, stop) =
            if INITIALIZED.load(Ordering::Relaxed) && !DEDICATED.load(Ordering::Relaxed) {
                let ready =
                    DEVICE_ATTACHED.load(Ordering::Relaxed) && !TEST_MODE.load(Ordering::Relaxed);
                (ready, !ready)
            } else {
                (false, false)
            };
        (start, stop || FINISHED.load(Ordering::Relaxed))
    });

    if start {
        start_session();
    }

    if stop {
        stop_session();
    }
}

/// Monitor control code 0x99 (stock 0x91f65ab8), issued by the kernel's
/// null-cable driver with `{+0 u8 status}`.
///
/// # Safety
///
/// `argument` must be the address of the status byte, kept valid by the
/// caller for the call.
pub(crate) unsafe fn service_set_device_status(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let status = unsafe { kernel::object_at::<AtomicU8>(argument) };

    // SAFETY: LOCK is a static spin lock; the kernel calls this at raised
    // IRQL.
    unsafe { xboxkrnl::KeAcquireSpinLockAtRaisedIrql(LOCK.as_ptr()) };
    if INITIALIZED.load(Ordering::Relaxed) {
        DEVICE_ATTACHED.store(status.load(Ordering::Relaxed) != 0, Ordering::Relaxed);
    }
    // SAFETY: acquired above.
    unsafe { xboxkrnl::KeReleaseSpinLockFromRaisedIrql(LOCK.as_ptr()) };

    0
}

/// Monitor control code 0x9f (stock 0x91f65dd0): `{+4 enable}`.
///
/// # Safety
///
/// `argument` must be the address of a test mode argument record the
/// caller keeps valid for the call.
pub(crate) unsafe fn service_set_test_mode(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let argument = unsafe { kernel::object_at::<TestModeArgument>(argument) };
    let enable = argument.enable.load(Ordering::Relaxed) != 0;

    kernel::debug_print(if enable {
        c"XStudioSlave: Setting Test Mode\n"
    } else {
        c"XStudioSlave: Disabling Test Mode\n"
    });
    with_lock(|| TEST_MODE.store(enable, Ordering::Relaxed));

    0
}

/// `xstudio DedicateSocket` (stock 0x91f65b18): open a listener on an
/// ephemeral port for the next session and return the port.
pub(super) fn dedicate() -> Result<u16, StudioError> {
    if !INITIALIZED.load(Ordering::Relaxed) {
        return Err(StudioError::Fail);
    }

    SECTION.enter();
    let outcome = open_listener();
    SECTION.leave();

    outcome
}

/// Runs with [`SECTION`] held.
fn open_listener() -> Result<u16, StudioError> {
    let (failure, running, attached) =
        with_session(|session| (session.failure, session.worker.is_some(), session.attached));

    if running && failure.is_none() {
        if !DEDICATED.load(Ordering::Relaxed) || attached {
            return Err(StudioError::Fail);
        }

        SECTION.leave();
        stop_session();
        SECTION.enter();
    }

    if let Some(failure) = failure {
        return Err(failure);
    }

    // SAFETY: no pointer arguments; the result is checked below.
    let socket = unsafe {
        xam::NetDll_socket(
            XnCaller::DebugMonitor,
            AddressFamily::Inet,
            SocketType::Stream,
            Protocol::Tcp,
        )
    };
    if socket == Socket::INVALID {
        return Err(StudioError::Fail);
    }

    let socket = SocketId(socket.raw());
    let Some(port) = configure_listener(socket) else {
        close_socket(socket);
        return Err(StudioError::Fail);
    };

    with_session(|session| session.listener = Some(socket));
    DEDICATED.store(true, Ordering::Relaxed);
    start_session();

    Ok(port)
}

/// Non-blocking, bound to an ephemeral port on every interface, backlog 1.
fn configure_listener(socket: SocketId) -> Option<u16> {
    const SOCKADDR_SIZE: usize = size_of::<SockAddrIn>();

    let mut nonblocking = 1u32;
    // SAFETY: `socket` is the listener opened by the caller; `nonblocking`
    // is a live u32.
    if unsafe {
        xam::NetDll_ioctlsocket(
            XnCaller::DebugMonitor,
            Socket::from_raw(socket.0),
            IoctlCommand::Fionbio,
            &mut nonblocking,
        )
    } != 0
    {
        return None;
    }

    let mut address = [0u8; SOCKADDR_SIZE];
    address[..2].copy_from_slice(&(AddressFamily::Inet.raw() as u16).to_be_bytes());
    // SAFETY: `address` is a live sockaddr of SOCKADDR_SIZE bytes.
    if unsafe {
        xam::NetDll_bind(
            XnCaller::DebugMonitor,
            Socket::from_raw(socket.0),
            address.as_ptr(),
            SOCKADDR_SIZE as i32,
        ) != 0
            || xam::NetDll_listen(XnCaller::DebugMonitor, Socket::from_raw(socket.0), 1) != 0
    } {
        return None;
    }

    let mut length = SOCKADDR_SIZE as i32;
    // SAFETY: `address` and `length` are live and describe SOCKADDR_SIZE bytes.
    if unsafe {
        xam::NetDll_getsockname(
            XnCaller::DebugMonitor,
            Socket::from_raw(socket.0),
            address.as_mut_ptr(),
            &mut length,
        )
    } != 0
    {
        return None;
    }

    Some(u16::from_be_bytes([address[2], address[3]]))
}

/// Stock 0x91f65850.
fn start_session() {
    SECTION.enter();

    // Stock has no initialized check here; it only matters while unloading.
    let ready = with_session(|session| session.worker.is_none() && session.failure.is_none())
        && !TEST_MODE.load(Ordering::Relaxed)
        && INITIALIZED.load(Ordering::Relaxed);
    if ready {
        let mut reply = 0u32;
        let prepared = NtStatus(call(
            &STUDIO_SERVICE,
            StudioServiceCall::Prepare as u32,
            &mut reply as *mut u32 as usize as u32,
        ))
        .is_success();
        if !(prepared && create_worker())
            && let Some(event) = with_session(|session| session.stop_event.take())
        {
            close_handle(event);
        }
    }

    SECTION.leave();
}

fn create_worker() -> bool {
    const STACK_SIZE: u32 = 0x4000;
    /// Bit 0x4, which `ExCreateThread` does not test and which has no name
    /// in [`ThreadCreationFlags`].
    const UNTESTED_FLAG: ThreadCreationFlags = ThreadCreationFlags::from_bits_retain(0x4);
    const CREATION_FLAGS: ThreadCreationFlags = ThreadCreationFlags::SUSPENDED
        .union(ThreadCreationFlags::SYSTEM_PROCESS)
        .union(UNTESTED_FLAG)
        .union(ThreadCreationFlags::TLS_DATA)
        .union(ThreadCreationFlags::PRIORITY_CLASS_13)
        .union(ThreadCreationFlags::NOT_DEBUGGABLE)
        .union(ThreadCreationFlags::PROCESSOR4);
    const _: () = assert!(CREATION_FLAGS.bits() == 0x1000_042f);

    // SAFETY: unnamed event without security attributes.
    let event = unsafe { xam::CreateEventA(0, false, false, core::ptr::null()) };
    let Some(event) = Handle::new(event.raw()) else {
        return false;
    };

    with_session(|session| session.stop_event = Some(event));

    let mut thread = 0u32;
    let entry = worker as *const () as usize as u32;
    // SAFETY: `thread` is a live u32; the worker takes no context and reads
    // the session under SECTION.
    let status = unsafe {
        xboxkrnl::ExCreateThread(
            &mut thread,
            STACK_SIZE,
            core::ptr::null_mut(),
            0,
            entry,
            0,
            CREATION_FLAGS,
        )
    };
    if !status.is_success() {
        return false;
    }

    // SAFETY: `thread` is the handle of the suspended worker created above.
    unsafe { xam::ResumeThread(xboxkrnl::Handle::from_raw(thread)) };
    with_session(|session| session.worker = Handle::new(thread));

    true
}

/// Stock 0x91f65950: end the session and wait for the worker.
fn stop_session() {
    SECTION.enter();
    let worker = with_session(|session| {
        if session.stopping {
            return None;
        }

        if session.worker.is_some() {
            session.stopping = true;
            set_event(session.stop_event);
        }

        session.worker
    });
    SECTION.leave();

    let Some(worker) = worker else { return };

    // SAFETY: `worker` is the owned worker thread handle, closed below.
    unsafe { xam::WaitForSingleObject(xboxkrnl::Handle::from_raw(worker.0), xam::INFINITE) };

    SECTION.enter();
    let event = with_session(|session| {
        session.worker = None;
        session.stopping = false;
        session.stop_event.take()
    });
    if let Some(event) = event {
        close_handle(event);
    }
    close_handle(worker);
    FINISHED.store(false, Ordering::Relaxed);
    SECTION.leave();

    call(
        &NULL_CABLE_REQUEST,
        NullCableRequest::ReportStatus as u32,
        0,
    );
}

/// Session thread (stock 0x91f656e8).
extern "C" fn worker(_context: u32) -> u32 {
    SECTION.enter();
    let dedicated = DEDICATED.load(Ordering::Relaxed);
    let (stop_event, listener) = with_session(|session| (session.stop_event, session.listener));
    SECTION.leave();

    let (transport, accepted) = match listener.filter(|_| dedicated) {
        Some(listener) => match accept_connection(listener, stop_event) {
            Ok(socket) => {
                SECTION.enter();
                with_session(|session| session.attached = true);
                SECTION.leave();
                (create_socket_transport(socket).ok(), Some(socket))
            }
            Err(_) => (None, None),
        },
        None => match create_null_cable_transport() {
            Ok(object) => (Some(object), None),
            Err(failure) => {
                SECTION.enter();
                with_session(|session| session.failure = Some(failure));
                SECTION.leave();
                (None, None)
            }
        },
    };

    if let Some(object) = transport {
        let run = SessionArguments {
            transport: object,
            stop_event: raw_handle(stop_event),
        };
        call(
            &STUDIO_SERVICE,
            StudioServiceCall::Run as u32,
            &run as *const SessionArguments as usize as u32,
        );

        // SAFETY: `object` is the transport created above, which the studio
        // service no longer uses; every transport starts with its routine
        // table.
        let release = unsafe { kernel::object_at::<Routines>(object) }.release;
        // SAFETY: the release routine takes the object and frees it.
        unsafe { kernel::call_export(release, object, 0, 0, 0) };
    }

    if let Some(socket) = accepted {
        close_socket(socket);
    }

    SECTION.enter();
    DEDICATED.store(false, Ordering::Relaxed);
    let listener = with_session(|session| {
        session.attached = false;
        if dedicated {
            session.listener.take()
        } else {
            None
        }
    });

    if let Some(listener) = listener {
        close_socket(listener);
    }

    with_lock(|| FINISHED.store(true, Ordering::Relaxed));
    SECTION.leave();

    0
}

/// Wait for a connection on `listener` or for `stop_event` (stock
/// 0x91f655e8).
fn accept_connection(
    listener: SocketId,
    stop_event: Option<Handle>,
) -> Result<SocketId, StudioError> {
    // SAFETY: unnamed event without security attributes.
    let ready = unsafe { xam::CreateEventA(0, true, false, core::ptr::null()) };
    let Some(ready) = Handle::new(ready.raw()) else {
        return Err(StudioError::OutOfMemory);
    };

    // SAFETY: `listener` is the open listener and `ready` the event created
    // above.
    let selected = unsafe {
        xam::NetDll_WSAEventSelect(
            XnCaller::DebugMonitor,
            Socket::from_raw(listener.0),
            xboxkrnl::Handle::from_raw(ready.0),
            NetworkEvents::ACCEPT,
        )
    } == 0;
    let outcome = if selected {
        let handles = [raw_handle(stop_event), ready.0];
        loop {
            // SAFETY: `handles` is a live array of two handle words.
            let wait = unsafe {
                xboxkrnl::NtWaitForMultipleObjectsEx(
                    2,
                    handles.as_ptr().cast(),
                    WaitType::Any,
                    ProcessorMode::User,
                    false,
                    core::ptr::null(),
                )
            };
            if let Err(error) = wait.result() {
                set_last_error(error);
            } else if wait == NtStatus::WAIT_0 {
                break Err(StudioError::Aborted);
            } else if wait == NtStatus::WAIT_1 {
                // SAFETY: `listener` is the open listener; no address is requested.
                let socket = unsafe {
                    xam::NetDll_accept(
                        XnCaller::DebugMonitor,
                        Socket::from_raw(listener.0),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                };
                if socket != Socket::INVALID {
                    break Ok(SocketId(socket.raw()));
                }
            }
        }
    } else {
        Err(StudioError::Fail)
    };

    // SAFETY: `listener` is the open listener; a null event clears the selection.
    unsafe {
        xam::NetDll_WSAEventSelect(
            XnCaller::DebugMonitor,
            Socket::from_raw(listener.0),
            xboxkrnl::Handle::NULL,
            NetworkEvents::empty(),
        )
    };
    close_handle(ready);

    outcome
}

fn routine(entry: unsafe extern "C" fn()) -> u32 {
    entry as *const () as usize as u32
}
