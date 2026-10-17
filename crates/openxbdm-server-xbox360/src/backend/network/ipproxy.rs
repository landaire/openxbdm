//! `ipproxy` services: the XAM IP packet hook, the UDP tunnel socket, and
//! the receive thread.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::network::WsaError;
use openxbdm_server::commands::network::XnAddr;
use openxbdm_server::commands::network::ipproxy;
use openxbdm_server::commands::network::ipproxy::RegisterStatus;
use openxbdm_server::commands::network::ipproxy::RoutineMissing;
use openxbdm_server::commands::network::ipproxy::SocketFailed;
use openxbdm_server::commands::network::ipproxy::ThreadFailed;
use openxbdm_server::commands::network::ipproxy::tunnel;
use openxbdm_server::commands::network::ipproxy::tunnel::Inbound;
use openxbdm_server::commands::network::ipproxy::tunnel::Tunnel;
use openxbdm_server::network::Endpoint;
use openxbdm_server::network::Ipv4Address;
use xbox360::module::Ordinal;
use xbox360::status::Win32Error;
use xbox360::time::TickCount;
use xbox360_sys::xam;
use xbox360_sys::xam::AddressFamily;
use xbox360_sys::xam::MessageFlags;
use xbox360_sys::xam::Protocol;
use xbox360_sys::xam::SockAddrIn;
use xbox360_sys::xam::Socket;
use xbox360_sys::xam::SocketLevel;
use xbox360_sys::xam::SocketOption;
use xbox360_sys::xam::SocketType;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;

use super::xam_procedure;
use crate::backend::Console;
use crate::kernel;
use crate::net::socket_address;

/// XAM export that registers (or, with no record, unregisters) the
/// outbound IP packet hook: `register(caller, record, 1)`.
const REGISTER_ORDINAL: Ordinal = xam::ordinal::XNP_TOOL_SET_CALLBACKS;
/// XAM export that injects an IPv4 packet given as pieces:
/// `inject(caller, pieces, count, direction)`.
const INJECT_ORDINAL: Ordinal = xam::ordinal::XNP_TOOL_IP_PROXY_INJECT;
/// Last argument of every register call.
const REGISTER_FLAGS: u32 = 1;
/// Second field of the hook record.
const HOOK_RECORD_LIMIT: u32 = 0x5a7;
const RECEIVE_STACK_SIZE: u32 = 0x4000;
/// `ExCreateThread` creation flags of the receive thread. Bit 0x4 has no
/// known meaning; stock passes it.
const RECEIVE_THREAD_FLAGS: ThreadCreationFlags = ThreadCreationFlags::SYSTEM_PROCESS
    .union(ThreadCreationFlags::NOT_DEBUGGABLE)
    .union(ThreadCreationFlags::PROCESSOR2)
    .union(ThreadCreationFlags::PRIORITY_CLASS_13)
    .union(ThreadCreationFlags::from_bits_retain(0x4));

/// Where the inject routine delivers a packet (its last argument).
#[derive(Clone, Copy)]
#[repr(u32)]
enum InjectDirection {
    /// Up the console's network stack: packets the host tunnels in.
    ToConsole = 0,
    /// Out to the host: datagrams the hook diverts.
    ToHost = 1,
}

/// Tunnel state read by the hook and the receive thread (stock block
/// 0x91f9f6a0). Fields are written only while neither runs, except the
/// clocks.
struct Shared {
    /// Address of the inject routine while the proxy is started.
    inject: AtomicU32,
    socket: AtomicU32,
    host_address: AtomicU32,
    host_port: AtomicU32,
    local_address: AtomicU32,
    local_port: AtomicU32,
    last_receive: AtomicU32,
    last_send: AtomicU32,
}

impl Shared {
    fn context(&'static self) -> u32 {
        self as *const Self as usize as u32
    }

    fn local(&self) -> Endpoint {
        Endpoint {
            address: Ipv4Address(self.local_address.load(Ordering::Relaxed).to_be_bytes()),
            port: self.local_port.load(Ordering::Relaxed) as u16,
        }
    }

    fn tunnel(&self) -> Tunnel {
        Tunnel {
            local: self.local(),
            host: Endpoint {
                address: Ipv4Address(self.host_address.load(Ordering::Relaxed).to_be_bytes()),
                port: self.host_port.load(Ordering::Relaxed) as u16,
            },
        }
    }

    /// Call the inject routine with `pieces`.
    fn inject(&self, caller: XnCaller, pieces: &[Piece], direction: InjectDirection) {
        // SAFETY: the inject routine takes (caller, pieces, count, direction)
        // and reads the pieces before returning.
        unsafe {
            kernel::call_export(
                self.inject.load(Ordering::Relaxed),
                caller.raw(),
                pieces.as_ptr() as usize as u32,
                pieces.len() as u32,
                direction as u32,
            )
        };
    }
}

static SHARED: Shared = Shared {
    inject: AtomicU32::new(0),
    socket: AtomicU32::new(Socket::INVALID.raw()),
    host_address: AtomicU32::new(0),
    host_port: AtomicU32::new(0),
    local_address: AtomicU32::new(0),
    local_port: AtomicU32::new(0),
    last_receive: AtomicU32::new(0),
    last_send: AtomicU32::new(0),
};

/// One piece of a packet passed to the inject routine.
#[repr(C)]
struct Piece {
    length: u32,
    address: u32,
}

impl Piece {
    const EMPTY: Self = Self {
        length: 0,
        address: 0,
    };

    fn of(bytes: &[u8]) -> Self {
        Self {
            length: bytes.len() as u32,
            address: bytes.as_ptr() as usize as u32,
        }
    }
}

/// The record `register` takes.
#[repr(C)]
struct HookRecord {
    /// Bytes of the record.
    size: u32,
    limit: u32,
    context: u32,
    hook: u32,
}

const _: () = assert!(size_of::<HookRecord>() == 0x10);

crate::exports::bridged!(outbound_hook_entry, outbound_hook);

/// Outbound IP packet hook (stock 0x91f355e8): the stack passes the IPv4
/// packet and a pointer to its length. Returns 1 when the packet was sent
/// through the tunnel instead.
extern "C" fn outbound_hook(context: u32, packet: *mut u8, length: *const u32) -> u32 {
    // SAFETY: the context is `SHARED`, given at registration; the stack
    // passes a writable packet of `*length` bytes.
    let (shared, packet) = unsafe {
        (
            &*(context as usize as *const Shared),
            core::slice::from_raw_parts_mut(packet, *length as usize),
        )
    };
    let Some(outbound) = tunnel::encapsulate(packet, &shared.tunnel()) else {
        return 0;
    };
    let pieces = [
        Piece::of(&packet[..outbound.header_length]),
        Piece::of(&outbound.udp),
        Piece::of(outbound.message()),
        Piece::of(&packet[outbound.payload.clone()]),
    ];
    shared.inject(XnCaller::DebugMonitor, &pieces, InjectDirection::ToHost);
    shared
        .last_send
        .store(TickCount::now().milliseconds(), Ordering::Relaxed);
    1
}

/// Receive loop (stock 0x91f35798): injects the host's packets, sends
/// keepalives, and ends when a receive fails other than by timeout.
extern "C" fn receive_thread(context: u32) -> u32 {
    // SAFETY: the context is `SHARED`, given at thread creation.
    let shared = unsafe { &*(context as usize as *const Shared) };
    let timeout = tunnel::RECEIVE_TIMEOUT.as_millis() as u32;
    // SAFETY: `timeout` is a live u32 option value of the stated size.
    unsafe {
        xam::NetDll_setsockopt(
            XnCaller::DebugMonitor,
            Socket::from_raw(shared.socket.load(Ordering::Relaxed)),
            SocketLevel::Socket,
            SocketOption::SO_RCVTIMEO,
            (&timeout as *const u32).cast(),
            size_of::<u32>() as i32,
        )
    };
    let keepalive_interval = tunnel::KEEPALIVE_INTERVAL.as_millis() as u32;
    let mut buffer = [0u8; tunnel::MESSAGE_LIMIT];
    loop {
        let socket = shared.socket.load(Ordering::Relaxed);
        // SAFETY: `buffer` is a live stack buffer of the stated length.
        let received = unsafe {
            xam::NetDll_recv(
                XnCaller::DebugMonitor,
                Socket::from_raw(socket),
                buffer.as_mut_ptr(),
                buffer.len() as i32,
                MessageFlags::empty(),
            )
        };
        let length = if received == xam::SOCKET_ERROR {
            if xam::NetDll_WSAGetLastError(XnCaller::DebugMonitor).error()
                != Some(Win32Error::TIMED_OUT)
            {
                return 0;
            }
            0
        } else {
            received as u32 as usize
        };
        let now = TickCount::now().milliseconds();
        if now.wrapping_sub(shared.last_send.load(Ordering::Relaxed)) >= keepalive_interval {
            // SAFETY: KEEPALIVE is a static message of the stated length.
            unsafe {
                xam::NetDll_send(
                    XnCaller::DebugMonitor,
                    Socket::from_raw(socket),
                    tunnel::KEEPALIVE.as_ptr(),
                    tunnel::KEEPALIVE.len() as i32,
                    MessageFlags::empty(),
                )
            };
            shared.last_send.store(now, Ordering::Relaxed);
        }
        match buffer.get(..length).and_then(tunnel::decapsulate) {
            None => {}
            Some(Inbound::Keepalive) => shared.last_receive.store(now, Ordering::Relaxed),
            Some(Inbound::Packet(packet)) => {
                shared.last_receive.store(now, Ordering::Relaxed);
                let pieces = match &packet.udp {
                    Some(udp) => [
                        Piece::of(&packet.ip),
                        Piece::of(udp),
                        Piece::of(packet.payload),
                    ],
                    None => [
                        Piece::of(&packet.ip),
                        Piece::of(packet.payload),
                        Piece::EMPTY,
                    ],
                };
                shared.inject(XnCaller::SystemApp, &pieces, InjectDirection::ToConsole);
            }
        }
    }
}

/// Platform state of `ipproxy`.
pub struct Data {
    /// Address of the register routine; held means started.
    register: Option<u32>,
    socket: Option<Socket>,
    thread: Option<Handle>,
}

impl Data {
    pub const fn new() -> Self {
        Self {
            register: None,
            socket: None,
            thread: None,
        }
    }

    /// Whether the proxy counts as started (stock 0x91f9f6a0 != 0).
    pub(crate) fn is_started(&self) -> bool {
        self.register.is_some()
    }

    /// Call the register routine with `record` (0 unregisters). The core
    /// calls this only while the routine is held; without it no hook can
    /// be registered, so there is nothing to change.
    fn call_register(&self, record: u32) -> Result<(), RegisterStatus> {
        let Some(register) = self.register else {
            return Ok(());
        };
        // SAFETY: the register routine takes (caller, record, flags).
        let status = unsafe {
            kernel::call_export(
                register,
                XnCaller::SystemApp.raw(),
                record,
                REGISTER_FLAGS,
                0,
            )
        };
        RegisterStatus::new(status).map_or(Ok(()), Err)
    }

    fn close_socket(&mut self) {
        if let Some(socket) = self.socket.take() {
            // SAFETY: the socket was opened by `open_proxy_socket` and is owned here.
            unsafe { xam::NetDll_closesocket(XnCaller::DebugMonitor, socket) };
        }
        SHARED
            .socket
            .store(Socket::INVALID.raw(), Ordering::Relaxed);
    }
}

/// The socket failure with the thread's last Winsock error, which may be
/// unset.
fn socket_failed() -> SocketFailed {
    SocketFailed(WsaError::new(
        xam::NetDll_WSAGetLastError(XnCaller::DebugMonitor).0 as i32,
    ))
}

impl ipproxy::Backend for Console {
    fn proxy_started(&mut self) -> bool {
        self.network.ipproxy.is_started()
    }

    fn resolve_proxy_routines(&mut self) -> Result<(), RoutineMissing> {
        let data = &mut self.network.ipproxy;
        data.register = Some(xam_procedure(REGISTER_ORDINAL).ok_or(RoutineMissing)?);
        SHARED.inject.store(
            xam_procedure(INJECT_ORDINAL).ok_or(RoutineMissing)?,
            Ordering::Relaxed,
        );
        Ok(())
    }

    fn release_proxy_routines(&mut self) {
        self.network.ipproxy.register = None;
        SHARED.inject.store(0, Ordering::Relaxed);
    }

    fn open_proxy_socket(&mut self, host: Endpoint) -> Result<(), SocketFailed> {
        SHARED
            .host_address
            .store(u32::from_be_bytes(host.address.octets()), Ordering::Relaxed);
        SHARED
            .host_port
            .store(u32::from(host.port), Ordering::Relaxed);
        let now = TickCount::now().milliseconds();
        SHARED.last_send.store(now, Ordering::Relaxed);
        SHARED.last_receive.store(now, Ordering::Relaxed);
        // SAFETY: no pointer arguments; the result is checked below.
        let socket = unsafe {
            xam::NetDll_socket(
                XnCaller::DebugMonitor,
                AddressFamily::Inet,
                SocketType::Datagram,
                Protocol::Udp,
            )
        };
        if socket == Socket::INVALID {
            return Err(socket_failed());
        }
        let data = &mut self.network.ipproxy;
        data.socket = Some(socket);
        SHARED.socket.store(socket.raw(), Ordering::Relaxed);
        let mut address = socket_address(host);
        // SAFETY: `address` is a live sockaddr.
        if unsafe {
            xam::NetDll_connect(
                XnCaller::DebugMonitor,
                socket,
                (&raw const address).cast(),
                size_of::<SockAddrIn>() as i32,
            )
        } != 0
        {
            let error = socket_failed();
            data.close_socket();
            return Err(error);
        }
        let mut length = size_of::<SockAddrIn>() as i32;
        // SAFETY: `address` and `length` are live and describe the sockaddr.
        let named = unsafe {
            xam::NetDll_getsockname(
                XnCaller::DebugMonitor,
                socket,
                (&raw mut address).cast(),
                &mut length,
            )
        };
        // Recorded before the result is checked, as stock does.
        SHARED
            .local_port
            .store(u32::from(address.port), Ordering::Relaxed);
        let mut xnaddr = XnAddr::default();
        // SAFETY: `xnaddr` is a live XNADDR.
        unsafe { xam::NetDll_XNetGetDebugXnAddr(XnCaller::DebugMonitor, xnaddr.0.as_mut_ptr()) };
        let [a, b, c, d, ..] = xnaddr.0;
        SHARED
            .local_address
            .store(u32::from_be_bytes([a, b, c, d]), Ordering::Relaxed);
        if named != 0 {
            let error = socket_failed();
            data.close_socket();
            return Err(error);
        }
        Ok(())
    }

    fn close_proxy_socket(&mut self) {
        self.network.ipproxy.close_socket();
    }

    fn proxy_local_endpoint(&mut self) -> Endpoint {
        SHARED.local()
    }

    fn set_proxy_bypass(&mut self, active: bool) {
        super::netsim::set_proxy_bypass(self, active);
    }

    fn install_proxy_hook(&mut self) -> Result<(), RegisterStatus> {
        let record = HookRecord {
            size: size_of::<HookRecord>() as u32,
            limit: HOOK_RECORD_LIMIT,
            context: SHARED.context(),
            hook: outbound_hook_entry as *const () as usize as u32,
        };
        self.network
            .ipproxy
            .call_register(&record as *const HookRecord as usize as u32)
    }

    fn remove_proxy_hook(&mut self) -> Result<(), RegisterStatus> {
        self.network.ipproxy.call_register(0)
    }

    fn start_proxy_thread(&mut self) -> Result<(), ThreadFailed> {
        let mut handle = Handle::NULL;
        // SAFETY: `handle` is a live handle word; `receive_thread` takes the static
        // `SHARED` context, which outlives the thread.
        let status = unsafe {
            xboxkrnl::ExCreateThread(
                (&raw mut handle).cast(),
                RECEIVE_STACK_SIZE,
                core::ptr::null_mut(),
                0,
                receive_thread as *const () as usize as u32,
                SHARED.context(),
                RECEIVE_THREAD_FLAGS,
            )
        };
        if !status.is_success() {
            return Err(ThreadFailed);
        }
        self.network.ipproxy.thread = Some(handle);
        Ok(())
    }

    fn stop_proxy_thread(&mut self) {
        let data = &mut self.network.ipproxy;
        // Closing the socket fails the pending receive, which ends the
        // thread.
        data.close_socket();
        if let Some(thread) = data.thread.take() {
            // SAFETY: `thread` is the owned handle from `start_proxy_thread`,
            // closed once after the wait.
            unsafe {
                xboxkrnl::NtWaitForSingleObjectEx(
                    thread,
                    ProcessorMode::Kernel,
                    false,
                    core::ptr::null(),
                );
                xboxkrnl::NtClose(thread);
            }
        }
    }
}
