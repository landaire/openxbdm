//! Xbox Studio subsystem (stock 0x91f654e8 to 0x91f65dd0). The studio
//! service of XAM (export 1670) runs on a worker thread over the USB null
//! cable (kernel export 810) while a device is attached and test mode is
//! off, or over a TCP connection accepted on a listener that
//! `xstudio DedicateSocket` opens. The service drives either transport
//! through a table of six routines at the start of the transport object.

use core::cell::UnsafeCell;
use core::fmt::Write as _;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_server::SocketId;
use openxbdm_server::commands::performance::studio::ABORTED;
use openxbdm_server::commands::performance::studio::COMPLETED;
use openxbdm_server::commands::performance::studio::CallerBuffer;
use openxbdm_server::commands::performance::studio::Direction;
use openxbdm_server::commands::performance::studio::Incoming;
use openxbdm_server::commands::performance::studio::NOT_CONNECTED;
use openxbdm_server::commands::performance::studio::Outgoing;
use openxbdm_server::commands::performance::studio::PENDING;
use openxbdm_server::commands::performance::studio::Slot;
use openxbdm_server::commands::performance::studio::Stream;
use openxbdm_server::commands::performance::studio::Transport;
use openxbdm_server::text::Text;

use crate::kernel;
use crate::kernel::CriticalSection;
use crate::net;
use crate::net::INVALID_SOCKET;
use crate::net::XNCALLER_XBDM;

/// Kernel export that queues null-cable transfers.
const NULL_CABLE_ORDINAL: u32 = 810;
/// XAM export of the studio service.
const STUDIO_SERVICE_ORDINAL: u32 = 1670;
/// Studio service call made before a session starts; failure skips it.
const SERVICE_PREPARE: u32 = 1;
/// Studio service call that runs a session over `{transport, stop event}`
/// until the event is set or the connection ends.
const SERVICE_RUN: u32 = 0x101;

/// Null-cable request codes.
const NULL_CABLE_SEND: u32 = 1;
const NULL_CABLE_RECEIVE: u32 = 2;
const NULL_CABLE_CANCEL: u32 = 3;
/// Report the device status again through monitor control code 0x99.
const NULL_CABLE_REPORT_STATUS: u32 = 4;

const WORKER_STACK_SIZE: u32 = 0x4000;
const WORKER_CREATION_FLAGS: u32 = 0x1000_042f;
const POOL_TYPE: u32 = 2;
const NULL_CABLE_POOL_TAG: u32 = 0x754e_5358;
const SOCKET_POOL_TAG: u32 = 0x734e_5358;

const SOCK_STREAM: u32 = 1;
const IPPROTO_TCP: u32 = 6;
const FIONBIO: u32 = 0x8004_667e;
const FD_READ_WRITE: u32 = 3;
const FD_ACCEPT: u32 = 8;
const SOCKADDR_SIZE: i32 = 16;
const WSAEWOULDBLOCK: i32 = 10035;

const STATUS_PENDING: u32 = 0x103;
const STATUS_NOT_IMPLEMENTED: u32 = 0xc000_0002;
const STATUS_NO_SUCH_DEVICE: u32 = 0xc000_000e;
const STATUS_NO_MEMORY: u32 = 0xc000_0017;
const NOT_IMPLEMENTED: Hresult = Hresult(0x8000_4001);
const INFINITE: u32 = u32::MAX;
const WAIT_ANY: u32 = 1;
const USER_MODE: u32 = 1;

/// Offset of the event handle in a caller request; +0 receives the
/// transfer count or request handle and +4 the null-cable status.
const REQUEST_EVENT: u32 = 0x10;
const REQUEST_STATUS: u32 = 4;

fn failed(status: u32) -> bool {
    (status as i32) < 0
}

fn read_u32(address: u32) -> u32 {
    // SAFETY: the caller passes the address of a readable dword.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn write_u32(address: u32, value: u32) {
    // SAFETY: the caller passes the address of a writable dword.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

/// Stock assertion trap (`twi 31, 0, 0x19`); execution continues after it.
fn assertion_trap() {
    // SAFETY: raises the trap exception stock raises; the debug routine or
    // the kernel resumes after it.
    unsafe { core::arch::asm!("twi 31, 0, 0x19") };
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Handle(u32);

impl Handle {
    fn new(raw: u32) -> Option<Self> {
        (raw != 0).then_some(Self(raw))
    }
}

fn raw_handle(handle: Option<Handle>) -> u32 {
    handle.map_or(0, |handle| handle.0)
}

/// `SetEvent` (stock 0x91f738b8).
fn set_event(handle: Option<Handle>) {
    let status = kernel::NtSetEvent(raw_handle(handle), core::ptr::null_mut());
    if failed(status) {
        kernel::set_last_error(status);
    }
}

/// `CloseHandle` (stock 0x91f738f8).
fn close_handle(handle: Handle) {
    let status = kernel::NtClose(handle.0);
    if failed(status) {
        kernel::set_last_error(status);
    }
}

fn close_socket(socket: SocketId) {
    net::NetDll_closesocket(XNCALLER_XBDM, socket.0);
}

/// A kernel spin lock word in static memory.
struct SpinLock(UnsafeCell<u32>);

// SAFETY: the kernel serializes access to the lock word.
unsafe impl Sync for SpinLock {}

impl SpinLock {
    fn pointer(&self) -> *mut u32 {
        self.0.get()
    }

    fn with<R>(&self, operation: impl FnOnce() -> R) -> R {
        let irql = kernel::KfAcquireSpinLock(self.pointer());
        let result = operation();
        kernel::KfReleaseSpinLock(self.pointer(), irql);
        result
    }
}

/// Session state guarded by [`SECTION`].
struct Session {
    /// Failure of a null-cable transport creation; disables the subsystem.
    result: Hresult,
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

/// Run `operation` on the session; the caller holds [`SECTION`] and
/// `operation` does not reenter.
fn with_session<R>(operation: impl FnOnce(&mut Session) -> R) -> R {
    // SAFETY: `SECTION` serializes all access and calls do not nest.
    operation(unsafe { &mut *SESSION.0.get() })
}

/// Guards the flags below (stock 0x91fab700).
static LOCK: SpinLock = SpinLock(UnsafeCell::new(0));
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static DEVICE_ATTACHED: AtomicBool = AtomicBool::new(false);
static DEDICATED: AtomicBool = AtomicBool::new(false);
/// The worker ended; the server pass collects it.
static FINISHED: AtomicBool = AtomicBool::new(false);
static TEST_MODE: AtomicBool = AtomicBool::new(false);

static SECTION: CriticalSection = CriticalSection::new();
static SECTION_READY: AtomicBool = AtomicBool::new(false);
static SESSION: SessionCell = SessionCell(UnsafeCell::new(Session {
    result: COMPLETED,
    worker: None,
    stop_event: None,
    listener: None,
    attached: false,
    stopping: false,
}));

static NULL_CABLE_REQUEST: AtomicU32 = AtomicU32::new(0);
static STUDIO_SERVICE: AtomicU32 = AtomicU32::new(0);

fn resolve(module: &core::ffi::CStr, ordinal: u32) -> Result<u32, u32> {
    let handle = kernel::module_handle(module)?;
    let mut address = 0u32;
    let status = kernel::XexGetProcedureAddress(handle, ordinal, &mut address);
    if failed(status) {
        Err(status)
    } else {
        Ok(address)
    }
}

fn call(function: &AtomicU32, a0: u32, a1: u32) -> u32 {
    // SAFETY: set to a resolved export before `INITIALIZED`; both exports
    // take two register arguments.
    unsafe { kernel::call_export(function.load(Ordering::Acquire), a0, a1, 0, 0) }
}

/// Stock 0x91f654e8. Runs on the server thread once the network is up,
/// where stock runs it last in module initialization.
pub(crate) fn initialize() {
    SECTION.initialize();
    SECTION_READY.store(true, Ordering::Release);
    let exports = resolve(c"xboxkrnl.exe", NULL_CABLE_ORDINAL)
        .and_then(|request| Ok((request, resolve(c"xam.xex", STUDIO_SERVICE_ORDINAL)?)));
    match exports {
        Err(status) => {
            let mut message = Text::<48>::new();
            let _ = write!(
                message,
                "XStudio: Failed initialization {}\n",
                status as i32
            );
            kernel::debug_print_bytes(message.as_bytes());
        }
        Ok((request, service)) => {
            NULL_CABLE_REQUEST.store(request, Ordering::Release);
            STUDIO_SERVICE.store(service, Ordering::Release);
            LOCK.with(|| INITIALIZED.store(true, Ordering::Relaxed));
            call(&NULL_CABLE_REQUEST, NULL_CABLE_REPORT_STATUS, 0);
        }
    }
}

/// Stop the worker before the image unloads. Clearing the initialized flag
/// keeps a new worker from starting; a stop already running on the server
/// thread is waited out.
pub(super) fn shut_down() {
    LOCK.with(|| INITIALIZED.store(false, Ordering::Relaxed));
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
        kernel::sleep_milliseconds(1);
    }
}

/// Stock 0x91f65a18, run on every server pass. Stock alerts the server
/// thread to run it sooner; the passes here are at most 20 ms apart.
pub(crate) fn poll() {
    let (start, stop) = LOCK.with(|| {
        let mut start = false;
        let mut stop = false;
        if INITIALIZED.load(Ordering::Relaxed) && !DEDICATED.load(Ordering::Relaxed) {
            if DEVICE_ATTACHED.load(Ordering::Relaxed) && !TEST_MODE.load(Ordering::Relaxed) {
                start = true;
            } else {
                stop = true;
            }
        }
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
pub(crate) fn service_set_device_status(argument: u32) -> u32 {
    kernel::KeAcquireSpinLockAtRaisedIrql(LOCK.pointer());
    if INITIALIZED.load(Ordering::Relaxed) {
        // SAFETY: the kernel passes the address of the status byte.
        let status = unsafe { core::ptr::read_volatile(argument as usize as *const u8) };
        DEVICE_ATTACHED.store(status != 0, Ordering::Relaxed);
    }
    kernel::KeReleaseSpinLockFromRaisedIrql(LOCK.pointer());
    0
}

/// Monitor control code 0x9f (stock 0x91f65dd0): `{+4 enable}`.
pub(crate) fn service_set_test_mode(argument: u32) -> u32 {
    let enable = read_u32(argument.wrapping_add(4)) != 0;
    kernel::debug_print(if enable {
        c"XStudioSlave: Setting Test Mode\n"
    } else {
        c"XStudioSlave: Disabling Test Mode\n"
    });
    LOCK.with(|| TEST_MODE.store(enable, Ordering::Relaxed));
    0
}

/// `xstudio DedicateSocket` (stock 0x91f65b18): open a listener on an
/// ephemeral port for the next session and return the port.
pub(super) fn dedicate() -> Result<u16, Hresult> {
    if !INITIALIZED.load(Ordering::Relaxed) {
        return Err(Hresult::FAIL);
    }
    SECTION.enter();
    let outcome = open_listener();
    SECTION.leave();
    outcome
}

/// Runs with [`SECTION`] held.
fn open_listener() -> Result<u16, Hresult> {
    let (result, running, attached) =
        with_session(|session| (session.result, session.worker.is_some(), session.attached));
    if running && !result.is_failure() {
        if !DEDICATED.load(Ordering::Relaxed) || attached {
            return Err(Hresult::FAIL);
        }
        SECTION.leave();
        stop_session();
        SECTION.enter();
    }
    if result.is_failure() {
        return Err(result);
    }
    let socket = net::NetDll_socket(XNCALLER_XBDM, net::AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if socket == INVALID_SOCKET {
        return Err(Hresult::FAIL);
    }
    let socket = SocketId(socket);
    let Some(port) = configure_listener(socket) else {
        close_socket(socket);
        return Err(Hresult::FAIL);
    };
    with_session(|session| session.listener = Some(socket));
    DEDICATED.store(true, Ordering::Relaxed);
    start_session();
    Ok(port)
}

/// Non-blocking, bound to an ephemeral port on every interface, backlog 1.
fn configure_listener(socket: SocketId) -> Option<u16> {
    let mut nonblocking = 1u32;
    if net::NetDll_ioctlsocket(XNCALLER_XBDM, socket.0, FIONBIO, &mut nonblocking) != 0 {
        return None;
    }
    let mut address = [0u8; SOCKADDR_SIZE as usize];
    address[..2].copy_from_slice(&(net::AF_INET as u16).to_be_bytes());
    if net::NetDll_bind(XNCALLER_XBDM, socket.0, address.as_ptr(), SOCKADDR_SIZE) != 0
        || net::NetDll_listen(XNCALLER_XBDM, socket.0, 1) != 0
    {
        return None;
    }
    let mut length = SOCKADDR_SIZE;
    if net::NetDll_getsockname(XNCALLER_XBDM, socket.0, address.as_mut_ptr(), &mut length) != 0 {
        return None;
    }
    Some(u16::from_be_bytes([address[2], address[3]]))
}

/// Stock 0x91f65850.
fn start_session() {
    SECTION.enter();
    // Stock has no initialized check here; it only matters while unloading.
    let ready = with_session(|session| session.worker.is_none() && !session.result.is_failure())
        && !TEST_MODE.load(Ordering::Relaxed)
        && INITIALIZED.load(Ordering::Relaxed);
    if ready {
        let mut reply = 0u32;
        let prepared = !failed(call(
            &STUDIO_SERVICE,
            SERVICE_PREPARE,
            &mut reply as *mut u32 as usize as u32,
        ));
        if !(prepared && create_worker())
            && let Some(event) = with_session(|session| session.stop_event.take())
        {
            close_handle(event);
        }
    }
    SECTION.leave();
}

fn create_worker() -> bool {
    let Some(event) = Handle::new(kernel::CreateEventA(0, 0, 0, core::ptr::null())) else {
        return false;
    };
    with_session(|session| session.stop_event = Some(event));
    let mut thread = 0u32;
    let entry = worker as *const () as usize as u32;
    let status = kernel::ExCreateThread(
        &mut thread,
        WORKER_STACK_SIZE,
        core::ptr::null_mut(),
        0,
        entry,
        0,
        WORKER_CREATION_FLAGS,
    );
    if failed(status) {
        return false;
    }
    kernel::ResumeThread(thread);
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
    kernel::WaitForSingleObject(worker.0, INFINITE);
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
    call(&NULL_CABLE_REQUEST, NULL_CABLE_REPORT_STATUS, 0);
}

/// Session thread (stock 0x91f656e8).
extern "C" fn worker(_context: u32) -> u32 {
    SECTION.enter();
    let dedicated = DEDICATED.load(Ordering::Relaxed);
    let (stop_event, listener) = with_session(|session| (session.stop_event, session.listener));
    SECTION.leave();
    let mut accepted = None;
    let transport = match listener.filter(|_| dedicated) {
        Some(listener) => match accept_connection(listener, stop_event) {
            Ok(socket) => {
                SECTION.enter();
                with_session(|session| session.attached = true);
                SECTION.leave();
                accepted = Some(socket);
                create_socket_transport(socket).ok()
            }
            Err(_) => None,
        },
        None => match create_null_cable_transport() {
            Ok(object) => Some(object),
            Err(result) => {
                SECTION.enter();
                with_session(|session| session.result = result);
                SECTION.leave();
                None
            }
        },
    };
    if let Some(object) = transport {
        let run = [object, raw_handle(stop_event)];
        call(&STUDIO_SERVICE, SERVICE_RUN, run.as_ptr() as usize as u32);
        // SAFETY: routine 1 of every transport is its release routine.
        unsafe { kernel::call_export(read_u32(object + 4), object, 0, 0, 0) };
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
    LOCK.with(|| FINISHED.store(true, Ordering::Relaxed));
    SECTION.leave();
    0
}

/// Wait for a connection on `listener` or for `stop_event` (stock
/// 0x91f655e8).
fn accept_connection(listener: SocketId, stop_event: Option<Handle>) -> Result<SocketId, Hresult> {
    let Some(ready) = Handle::new(kernel::CreateEventA(0, 1, 0, core::ptr::null())) else {
        return Err(Hresult::OUT_OF_MEMORY);
    };
    let mut outcome = Err(Hresult::FAIL);
    if net::NetDll_WSAEventSelect(XNCALLER_XBDM, listener.0, ready.0, FD_ACCEPT) == 0 {
        let handles = [raw_handle(stop_event), ready.0];
        outcome = loop {
            let wait = kernel::NtWaitForMultipleObjectsEx(
                2,
                handles.as_ptr(),
                WAIT_ANY,
                USER_MODE,
                0,
                core::ptr::null(),
            );
            if failed(wait) {
                kernel::set_last_error(wait);
            } else if wait == 0 {
                break Err(ABORTED);
            } else if wait == 1 {
                let socket = net::NetDll_accept(
                    XNCALLER_XBDM,
                    listener.0,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                );
                if socket != INVALID_SOCKET {
                    break Ok(SocketId(socket));
                }
            }
        };
    }
    net::NetDll_WSAEventSelect(XNCALLER_XBDM, listener.0, 0, 0);
    close_handle(ready);
    outcome
}

use crate::exports::bridged;

fn routine(entry: unsafe extern "C" fn()) -> u32 {
    entry as *const () as usize as u32
}

/// Null-cable transport object (stock 0x91f830e0).
#[repr(C)]
struct NullCableTransport {
    routines: [u32; 6],
    request: u32,
}

fn create_null_cable_transport() -> Result<u32, Hresult> {
    let object = kernel::ExAllocatePoolTypeWithTag(
        size_of::<NullCableTransport>() as u32,
        NULL_CABLE_POOL_TAG,
        POOL_TYPE,
    );
    // Stock passes the null pointer to ExFreePool here.
    if object == 0 {
        return Err(Hresult::OUT_OF_MEMORY);
    }
    let request = kernel::module_handle(c"xboxkrnl.exe")
        .map_err(|_| Hresult::FAIL)
        .and_then(|module| {
            let mut address = 0u32;
            if failed(kernel::XexGetProcedureAddress(
                module,
                NULL_CABLE_ORDINAL,
                &mut address,
            )) {
                Err(NOT_IMPLEMENTED)
            } else {
                Ok(address)
            }
        });
    let request = match request {
        Ok(request) => request,
        Err(result) => {
            kernel::ExFreePool(object);
            return Err(result);
        }
    };
    let routines = [
        routine(null_cable_kind_entry),
        routine(null_cable_release_entry),
        routine(null_cable_receive_entry),
        routine(null_cable_send_entry),
        routine(null_cable_result_entry),
        routine(null_cable_cancel_entry),
    ];
    // SAFETY: the pool returned a block of the object's size.
    unsafe {
        (object as usize as *mut NullCableTransport).write(NullCableTransport { routines, request })
    };
    Ok(object)
}

fn null_cable_request(this: u32) -> u32 {
    // SAFETY: `this` is a null-cable transport.
    unsafe { (*(this as usize as *const NullCableTransport)).request }
}

/// Map a null-cable request status (stock 0x91f83290).
fn null_cable_result_code(status: u32) -> u32 {
    match status {
        0 => 0,
        STATUS_NO_SUCH_DEVICE => NOT_CONNECTED.0,
        STATUS_NO_MEMORY => Hresult::OUT_OF_MEMORY.0,
        STATUS_NOT_IMPLEMENTED => NOT_IMPLEMENTED.0,
        _ => Hresult::FAIL.0,
    }
}

fn null_cable_transfer(this: u32, code: u32, buffer: u32, length: u32, request: u32) -> u32 {
    let parameters = [
        buffer,
        length,
        read_u32(request + REQUEST_EVENT),
        kernel::KeGetCurrentProcessType(),
        request,
        request + REQUEST_STATUS,
    ];
    write_u32(request, 0);
    write_u32(request + REQUEST_STATUS, STATUS_PENDING);
    // SAFETY: the object holds the resolved kernel export.
    let status = unsafe {
        kernel::call_export(
            null_cable_request(this),
            code,
            parameters.as_ptr() as usize as u32,
            0,
            0,
        )
    };
    null_cable_result_code(status)
}

extern "C" fn null_cable_kind(_this: u32) -> u32 {
    1
}

extern "C" fn null_cable_release(this: u32) -> u32 {
    kernel::ExFreePool(this);
    0
}

extern "C" fn null_cable_receive(this: u32, buffer: u32, length: u32, request: u32) -> u32 {
    null_cable_transfer(this, NULL_CABLE_RECEIVE, buffer, length, request)
}

extern "C" fn null_cable_send(this: u32, buffer: u32, length: u32, request: u32) -> u32 {
    if read_u32(request + REQUEST_EVENT) == 0 {
        assertion_trap();
    }
    null_cable_transfer(this, NULL_CABLE_SEND, buffer, length, request)
}

extern "C" fn null_cable_result(_this: u32, request: u32, transferred: u32, wait: u32) -> u32 {
    let event = read_u32(request + REQUEST_EVENT);
    if event == 0 {
        assertion_trap();
    }
    let status = loop {
        core::sync::atomic::fence(Ordering::Acquire);
        let status = read_u32(request + REQUEST_STATUS);
        if status != STATUS_PENDING {
            break status;
        }
        if wait == 0 {
            return PENDING.0;
        }
        kernel::WaitForSingleObject(event, INFINITE);
    };
    core::sync::atomic::fence(Ordering::Acquire);
    write_u32(transferred, read_u32(request));
    if status != 0 { Hresult::FAIL.0 } else { 0 }
}

extern "C" fn null_cable_cancel(this: u32) -> u32 {
    let parameters = [kernel::KeGetCurrentProcessType()];
    // SAFETY: the object holds the resolved kernel export.
    let status = unsafe {
        kernel::call_export(
            null_cable_request(this),
            NULL_CABLE_CANCEL,
            parameters.as_ptr() as usize as u32,
            0,
            0,
        )
    };
    match status {
        0 => 0,
        STATUS_NOT_IMPLEMENTED => NOT_IMPLEMENTED.0,
        _ => Hresult::FAIL.0,
    }
}

bridged!(null_cable_kind_entry, null_cable_kind);
bridged!(null_cable_release_entry, null_cable_release);
bridged!(null_cable_receive_entry, null_cable_receive);
bridged!(null_cable_send_entry, null_cable_send);
bridged!(null_cable_result_entry, null_cable_result);
bridged!(null_cable_cancel_entry, null_cable_cancel);

/// Socket transport object (stock 0x91f83698). Request handles are
/// addresses inside the object, as stock's request nodes are.
#[repr(C)]
struct SocketTransport {
    routines: [u32; 6],
    section: CriticalSection,
    /// Caller event bound by the first request.
    event: Option<Handle>,
    socket: SocketId,
    engine: Transport,
}

struct SocketStream {
    socket: SocketId,
    event: Option<Handle>,
}

impl Stream for SocketStream {
    fn send(&mut self, data: Outgoing<'_>) -> Option<u32> {
        let (pointer, length) = match data {
            Outgoing::Local(bytes) => (bytes.as_ptr(), bytes.len() as i32),
            Outgoing::Caller(buffer) => {
                (buffer.address as usize as *const u8, buffer.length as i32)
            }
        };
        u32::try_from(net::NetDll_send(
            XNCALLER_XBDM,
            self.socket.0,
            pointer,
            length,
            0,
        ))
        .ok()
    }

    fn receive(&mut self, into: Incoming<'_>) -> Option<u32> {
        let (pointer, length) = match into {
            Incoming::Local(bytes) => (bytes.as_mut_ptr(), bytes.len() as i32),
            Incoming::Caller(buffer) => (buffer.address as usize as *mut u8, buffer.length as i32),
        };
        u32::try_from(net::NetDll_recv(
            XNCALLER_XBDM,
            self.socket.0,
            pointer,
            length,
            0,
        ))
        .ok()
    }

    fn would_block(&mut self) -> bool {
        net::NetDll_WSAGetLastError(XNCALLER_XBDM) == WSAEWOULDBLOCK
    }

    fn read_length(&mut self, address: u32) -> u32 {
        read_u32(address)
    }

    fn signal(&mut self) {
        set_event(self.event);
    }

    fn short_buffer(&mut self) {
        assertion_trap();
    }
}

fn create_socket_transport(socket: SocketId) -> Result<u32, Hresult> {
    let object = kernel::ExAllocatePoolTypeWithTag(
        size_of::<SocketTransport>() as u32,
        SOCKET_POOL_TAG,
        POOL_TYPE,
    );
    if object == 0 {
        return Err(Hresult::OUT_OF_MEMORY);
    }
    let routines = [
        routine(socket_kind_entry),
        routine(socket_release_entry),
        routine(socket_receive_entry),
        routine(socket_send_entry),
        routine(socket_result_entry),
        routine(socket_cancel_entry),
    ];
    let pointer = object as usize as *mut SocketTransport;
    // SAFETY: the pool returned a block of the object's size.
    unsafe {
        pointer.write(SocketTransport {
            routines,
            section: CriticalSection::new(),
            event: None,
            socket,
            engine: Transport::new(),
        });
        (*pointer).section.initialize();
    }
    let mut nonblocking = 1u32;
    if net::NetDll_ioctlsocket(XNCALLER_XBDM, socket.0, FIONBIO, &mut nonblocking)
        == net::SOCKET_ERROR
    {
        kernel::ExFreePool(object);
        return Err(Hresult::FAIL);
    }
    Ok(object)
}

/// Enter the object's critical section and borrow the object.
///
/// # Safety
/// `this` is a socket transport; the borrow ends before [`leave`].
unsafe fn enter<'a>(this: u32) -> &'a mut SocketTransport {
    let pointer = this as usize as *mut SocketTransport;
    // SAFETY: per the contract; the section serializes the borrow.
    unsafe {
        (*pointer).section.enter();
        &mut *pointer
    }
}

fn leave(this: u32) {
    let pointer = this as usize as *mut SocketTransport;
    // SAFETY: `this` is a socket transport whose section the thread holds.
    unsafe { &(*pointer).section }.leave();
}

impl SocketTransport {
    fn stream(&self) -> SocketStream {
        SocketStream {
            socket: self.socket,
            event: self.event,
        }
    }

    fn pump(&mut self) {
        let mut stream = self.stream();
        self.engine.pump(&mut stream);
    }

    fn handle_base(&self) -> u32 {
        core::ptr::addr_of!(self.engine) as usize as u32
    }

    fn handle(&self, slot: Slot) -> u32 {
        self.handle_base() + slot.index() as u32
    }

    fn slot(&self, handle: u32) -> Option<Slot> {
        Slot::from_index(handle.wrapping_sub(self.handle_base()) as usize)
    }

    /// Bind the caller's event on the first request (stock 0x91f84030).
    fn bind_event(&mut self, event: u32) {
        if self.event.is_none() {
            self.event = Handle::new(event);
            let status =
                net::NetDll_WSAEventSelect(XNCALLER_XBDM, self.socket.0, event, FD_READ_WRITE);
            set_event(self.event);
            if status == net::SOCKET_ERROR {
                let mut stream = self.stream();
                self.engine.socket_error(&mut stream);
            }
        }
        if raw_handle(self.event) != event {
            assertion_trap();
        }
    }
}

fn socket_queue(this: u32, direction: Direction, buffer: u32, length: u32, request: u32) -> u32 {
    // SAFETY: the studio service passes the transport it was given.
    let object = unsafe { enter(this) };
    let result = match object.engine.reserve() {
        Err(result) => result.0,
        Ok(slot) => {
            object.bind_event(read_u32(request + REQUEST_EVENT));
            write_u32(request, object.handle(slot));
            let mut stream = object.stream();
            object.engine.submit(
                slot,
                direction,
                CallerBuffer {
                    address: buffer,
                    length,
                },
                &mut stream,
            );
            0
        }
    };
    leave(this);
    result
}

extern "C" fn socket_kind(_this: u32) -> u32 {
    2
}

extern "C" fn socket_release(this: u32) -> u32 {
    socket_cancel(this);
    kernel::ExFreePool(this);
    0
}

extern "C" fn socket_receive(this: u32, buffer: u32, length: u32, request: u32) -> u32 {
    socket_queue(this, Direction::Receive, buffer, length, request)
}

extern "C" fn socket_send(this: u32, buffer: u32, length: u32, request: u32) -> u32 {
    socket_queue(this, Direction::Send, buffer, length, request)
}

/// Stock 0x91f843c8. Stock dereferences any handle; a handle that names no
/// slot fails here. When the connection ends during a wait, stock returns
/// without leaving the section, so a later call from another thread would
/// block forever; the section is left here.
extern "C" fn socket_result(this: u32, request: u32, transferred: u32, wait: u32) -> u32 {
    let handle = read_u32(request);
    // SAFETY: the studio service passes the transport it was given.
    let object = unsafe { enter(this) };
    let Some(slot) = object.slot(handle) else {
        leave(this);
        return Hresult::INVALID_ARGUMENT.0;
    };
    object.pump();
    if wait != 0 {
        loop {
            // SAFETY: the section is held.
            let object = unsafe { &mut *(this as usize as *mut SocketTransport) };
            if !object.engine.is_pending(slot) {
                break;
            }
            if !object.engine.is_connected() {
                leave(this);
                return NOT_CONNECTED.0;
            }
            let event = object.event;
            leave(this);
            kernel::WaitForSingleObject(raw_handle(event), INFINITE);
            // SAFETY: as above.
            unsafe { enter(this) }.pump();
        }
    }
    // SAFETY: the section is held.
    let object = unsafe { &mut *(this as usize as *mut SocketTransport) };
    let result = match object.engine.complete(slot) {
        None => PENDING,
        Some((status, count)) => {
            write_u32(transferred, count);
            write_u32(request, 0);
            status
        }
    };
    leave(this);
    result.0
}

extern "C" fn socket_cancel(this: u32) -> u32 {
    // SAFETY: the studio service passes the transport it was given.
    let object = unsafe { enter(this) };
    let mut stream = object.stream();
    object.engine.cancel(&mut stream);
    leave(this);
    0
}

bridged!(socket_kind_entry, socket_kind);
bridged!(socket_release_entry, socket_release);
bridged!(socket_receive_entry, socket_receive);
bridged!(socket_send_entry, socket_send);
bridged!(socket_result_entry, socket_result);
bridged!(socket_cancel_entry, socket_cancel);
