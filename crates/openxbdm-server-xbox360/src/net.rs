//! Sockets through the XAM network stack.

use openxbdm_server::network::Endpoint;
use openxbdm_server::network::Ipv4Address;
use openxbdm_server::network::NetError;
use openxbdm_server::network::Network;
use openxbdm_server::network::SocketId;

use crate::kernel::LIB_XAM;
use crate::kernel::import_thunk;

/// Caller identifier the monitor passes to network functions.
pub const XNCALLER_XBDM: u32 = 3;
pub const INVALID_SOCKET: u32 = u32::MAX;
pub(crate) const SOCKET_ERROR: i32 = -1;
pub(crate) const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;
const IPPROTO_TCP: u32 = 6;
pub(crate) const SOL_SOCKET: i32 = 0xffff;
const SO_REUSEADDR: i32 = 4;
const FIONBIO: u32 = 0x8004_667e;
const FIONREAD: u32 = 0x4004_667f;
const WSAEWOULDBLOCK: i32 = 10035;
pub(crate) const SOCK_DGRAM: u32 = 2;
pub(crate) const IPPROTO_UDP: u32 = 17;
const SO_BROADCAST: i32 = 0x20;
/// Sockets per select set.
pub const FD_SETSIZE: usize = 64;
/// `XNetGetOpt` option that reports the secondary network interface.
const XNET_OPT_SECONDARY_NIC: u32 = 0x2f00;

import_thunk!(pub NetDll_WSAStartup(caller: u32, version: u32, data: *mut u8) -> i32, lib = LIB_XAM, ordinal = 1);
import_thunk!(pub(crate) NetDll_socket(caller: u32, af: u32, ty: u32, protocol: u32) -> u32, lib = LIB_XAM, ordinal = 3);
import_thunk!(pub(crate) NetDll_closesocket(caller: u32, socket: u32) -> i32, lib = LIB_XAM, ordinal = 4);
import_thunk!(pub(crate) NetDll_ioctlsocket(caller: u32, socket: u32, command: u32, argument: *mut u32) -> i32, lib = LIB_XAM, ordinal = 6);
import_thunk!(
    pub(crate) NetDll_setsockopt(caller: u32, socket: u32, level: i32, name: i32, value: *const u8, length: i32) -> i32,
    lib = LIB_XAM,
    ordinal = 7
);
import_thunk!(
    pub(crate) NetDll_getsockname(caller: u32, socket: u32, name: *mut u8, length: *mut i32) -> i32,
    lib = LIB_XAM,
    ordinal = 9
);
import_thunk!(
    NetDll_getpeername(caller: u32, socket: u32, name: *mut u8, length: *mut i32) -> i32,
    lib = LIB_XAM,
    ordinal = 10
);
import_thunk!(pub(crate) NetDll_bind(caller: u32, socket: u32, name: *const u8, length: i32) -> i32, lib = LIB_XAM, ordinal = 11);
import_thunk!(pub(crate) NetDll_connect(caller: u32, socket: u32, name: *const u8, length: i32) -> i32, lib = LIB_XAM, ordinal = 12);
import_thunk!(pub(crate) NetDll_listen(caller: u32, socket: u32, backlog: i32) -> i32, lib = LIB_XAM, ordinal = 13);
import_thunk!(pub(crate) NetDll_accept(caller: u32, socket: u32, name: *mut u8, length: *mut i32) -> u32, lib = LIB_XAM, ordinal = 14);
import_thunk!(
    NetDll_select(
        caller: u32,
        count: i32,
        read: *mut FdSet,
        write: *mut FdSet,
        except: *mut FdSet,
        timeout: *const TimeVal,
    ) -> i32,
    lib = LIB_XAM,
    ordinal = 15
);
import_thunk!(pub(crate) NetDll_recv(caller: u32, socket: u32, buffer: *mut u8, length: i32, flags: i32) -> i32, lib = LIB_XAM, ordinal = 18);
import_thunk!(pub(crate) NetDll_send(caller: u32, socket: u32, buffer: *const u8, length: i32, flags: i32) -> i32, lib = LIB_XAM, ordinal = 22);
import_thunk!(pub(crate) NetDll_WSAGetLastError(caller: u32) -> i32, lib = LIB_XAM, ordinal = 27);
import_thunk!(pub(crate) NetDll_WSAEventSelect(caller: u32, socket: u32, event: u32, events: u32) -> i32, lib = LIB_XAM, ordinal = 35);
import_thunk!(pub NetDll_XNetStartup(caller: u32, params: *const u8) -> i32, lib = LIB_XAM, ordinal = 51);
import_thunk!(
    NetDll_XNetRandom(caller: u32, buffer: *mut u8, length: u32) -> i32,
    lib = LIB_XAM,
    ordinal = 53
);
import_thunk!(
    NetDll_XNetGetOpt(caller: u32, option: u32, value: *mut u8, length: *mut i32) -> i32,
    lib = LIB_XAM,
    ordinal = 78
);
import_thunk!(
    NetDll_recvfrom(
        caller: u32,
        socket: u32,
        buffer: *mut u8,
        length: i32,
        flags: i32,
        from: *mut u8,
        from_length: *mut i32,
    ) -> i32,
    lib = LIB_XAM,
    ordinal = 20
);
import_thunk!(
    NetDll_sendto(
        caller: u32,
        socket: u32,
        buffer: *const u8,
        length: i32,
        flags: i32,
        to: *const u8,
        to_length: i32,
    ) -> i32,
    lib = LIB_XAM,
    ordinal = 24
);

#[repr(C)]
struct SockAddrIn {
    family: u16,
    port: u16,
    address: u32,
    zero: [u8; 8],
}

impl SockAddrIn {
    fn new(endpoint: Endpoint) -> Self {
        Self {
            family: AF_INET as u16,
            port: endpoint.port,
            address: u32::from_be_bytes(endpoint.address.octets()),
            zero: [0; 8],
        }
    }
}

/// Winsock descriptor set.
#[repr(C)]
pub struct FdSet {
    count: u32,
    sockets: [u32; FD_SETSIZE],
}

impl FdSet {
    pub const fn new() -> Self {
        Self {
            count: 0,
            sockets: [0; FD_SETSIZE],
        }
    }

    pub fn insert(&mut self, socket: u32) {
        if (self.count as usize) < FD_SETSIZE {
            self.sockets[self.count as usize] = socket;
            self.count += 1;
        }
    }

    pub fn contains(&self, socket: u32) -> bool {
        self.sockets[..self.count as usize].contains(&socket)
    }
}

#[repr(C)]
pub struct TimeVal {
    seconds: i32,
    microseconds: i32,
}

impl TimeVal {
    pub const fn from_milliseconds(milliseconds: u32) -> Self {
        Self {
            seconds: (milliseconds / 1000) as i32,
            microseconds: ((milliseconds % 1000) * 1000) as i32,
        }
    }
}

/// Wait until sockets are readable or writable. Returns the number of ready
/// sockets.
pub fn select(
    read: &mut FdSet,
    write: &mut FdSet,
    timeout: Option<&TimeVal>,
) -> Result<u32, NetError> {
    let timeout = timeout.map_or(core::ptr::null(), |t| t as *const TimeVal);
    match NetDll_select(
        XNCALLER_XBDM,
        0,
        read,
        write,
        core::ptr::null_mut(),
        timeout,
    ) {
        SOCKET_ERROR => Err(NetError::Closed),
        count => Ok(count as u32),
    }
}

/// Open a listening TCP socket on `port` with address reuse, as the monitor's
/// command thread does.
pub fn listen(port: u16, backlog: i32) -> Result<u32, NetError> {
    let socket = NetDll_socket(XNCALLER_XBDM, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if socket == INVALID_SOCKET {
        return Err(NetError::Exhausted);
    }
    let enable = 1u32.to_be_bytes();
    let address = SockAddrIn::new(Endpoint {
        address: Ipv4Address::UNSPECIFIED,
        port,
    });
    if NetDll_setsockopt(
        XNCALLER_XBDM,
        socket,
        SOL_SOCKET,
        SO_REUSEADDR,
        enable.as_ptr(),
        enable.len() as i32,
    ) == SOCKET_ERROR
        || NetDll_bind(
            XNCALLER_XBDM,
            socket,
            (&address as *const SockAddrIn).cast(),
            size_of::<SockAddrIn>() as i32,
        ) == SOCKET_ERROR
        || NetDll_listen(XNCALLER_XBDM, socket, backlog) == SOCKET_ERROR
    {
        NetDll_closesocket(XNCALLER_XBDM, socket);
        return Err(NetError::Closed);
    }
    Ok(socket)
}

pub fn accept(listener: u32) -> Option<u32> {
    let socket = NetDll_accept(
        XNCALLER_XBDM,
        listener,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    (socket != INVALID_SOCKET).then_some(socket)
}

/// Open a UDP socket on `port` that may send broadcasts. Failure is
/// reported, not fatal: the monitor serves TCP without it.
pub fn bind_datagram(port: u16) -> Result<u32, NetError> {
    let socket = NetDll_socket(XNCALLER_XBDM, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if socket == INVALID_SOCKET {
        return Err(NetError::Exhausted);
    }
    let enable = 1u32.to_be_bytes();
    NetDll_setsockopt(
        XNCALLER_XBDM,
        socket,
        SOL_SOCKET,
        SO_REUSEADDR,
        enable.as_ptr(),
        enable.len() as i32,
    );
    NetDll_setsockopt(
        XNCALLER_XBDM,
        socket,
        SOL_SOCKET,
        SO_BROADCAST,
        enable.as_ptr(),
        enable.len() as i32,
    );
    let address = SockAddrIn::new(Endpoint {
        address: Ipv4Address::UNSPECIFIED,
        port,
    });
    if NetDll_bind(
        XNCALLER_XBDM,
        socket,
        (&address as *const SockAddrIn).cast(),
        size_of::<SockAddrIn>() as i32,
    ) == SOCKET_ERROR
    {
        NetDll_closesocket(XNCALLER_XBDM, socket);
        return Err(NetError::Closed);
    }
    Ok(socket)
}

/// Receive one datagram; returns its length and sender.
pub fn receive_from(socket: u32, buffer: &mut [u8]) -> Result<(usize, Endpoint), NetError> {
    let mut from = SockAddrIn::new(Endpoint {
        address: Ipv4Address::UNSPECIFIED,
        port: 0,
    });
    let mut length = size_of::<SockAddrIn>() as i32;
    match NetDll_recvfrom(
        XNCALLER_XBDM,
        socket,
        buffer.as_mut_ptr(),
        buffer.len() as i32,
        0,
        (&mut from as *mut SockAddrIn).cast(),
        &mut length,
    ) {
        SOCKET_ERROR => Err(last_error()),
        count => Ok((
            count as usize,
            Endpoint {
                address: Ipv4Address(from.address.to_be_bytes()),
                port: from.port,
            },
        )),
    }
}

/// Send one datagram to `endpoint`.
pub fn send_to(socket: u32, data: &[u8], endpoint: Endpoint) {
    let to = SockAddrIn::new(endpoint);
    NetDll_sendto(
        XNCALLER_XBDM,
        socket,
        data.as_ptr(),
        data.len() as i32,
        0,
        (&to as *const SockAddrIn).cast(),
        size_of::<SockAddrIn>() as i32,
    );
}

pub fn close(socket: u32) {
    NetDll_closesocket(XNCALLER_XBDM, socket);
}

/// Fill `output` from the network stack's random source.
pub fn random_bytes(output: &mut [u8]) {
    NetDll_XNetRandom(XNCALLER_XBDM, output.as_mut_ptr(), output.len() as u32);
}

/// Whether a secondary network interface is present.
pub fn has_secondary_nic() -> bool {
    let mut value = [0u8; 6];
    let mut length = value.len() as i32;
    let result = NetDll_XNetGetOpt(
        XNCALLER_XBDM,
        XNET_OPT_SECONDARY_NIC,
        value.as_mut_ptr(),
        &mut length,
    ) as u32;
    result != 0xc000_00c0 && result != 0x2726
}

fn last_error() -> NetError {
    if NetDll_WSAGetLastError(XNCALLER_XBDM) == WSAEWOULDBLOCK {
        NetError::WouldBlock
    } else {
        NetError::Closed
    }
}

/// `Network` over XAM sockets. Socket identifiers are socket handles.
pub struct XamNetwork;

impl Network for XamNetwork {
    fn receive(&mut self, socket: SocketId, buffer: &mut [u8]) -> Result<usize, NetError> {
        match NetDll_recv(
            XNCALLER_XBDM,
            socket.0,
            buffer.as_mut_ptr(),
            buffer.len() as i32,
            0,
        ) {
            SOCKET_ERROR => Err(last_error()),
            count => Ok(count as usize),
        }
    }

    fn send(&mut self, socket: SocketId, data: &[u8]) -> Result<usize, NetError> {
        match NetDll_send(XNCALLER_XBDM, socket.0, data.as_ptr(), data.len() as i32, 0) {
            SOCKET_ERROR => Err(last_error()),
            count => Ok(count as usize),
        }
    }

    fn close(&mut self, socket: SocketId) {
        close(socket.0);
    }

    fn peer(&mut self, socket: SocketId) -> Result<Endpoint, NetError> {
        let mut address = SockAddrIn::new(Endpoint {
            address: Ipv4Address::UNSPECIFIED,
            port: 0,
        });
        let mut length = size_of::<SockAddrIn>() as i32;
        if NetDll_getpeername(
            XNCALLER_XBDM,
            socket.0,
            (&mut address as *mut SockAddrIn).cast(),
            &mut length,
        ) == SOCKET_ERROR
        {
            return Err(last_error());
        }
        Ok(Endpoint {
            address: Ipv4Address(address.address.to_be_bytes()),
            port: address.port,
        })
    }

    /// Bind to a random local port in `0x1000..0x5000` with address reuse, as
    /// the monitor does for notification connections.
    fn connect(&mut self, endpoint: Endpoint, blocking: bool) -> Result<SocketId, NetError> {
        let socket = NetDll_socket(XNCALLER_XBDM, AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if socket == INVALID_SOCKET {
            return Err(NetError::Exhausted);
        }
        let reuse = 1u32.to_be_bytes();
        NetDll_setsockopt(
            XNCALLER_XBDM,
            socket,
            SOL_SOCKET,
            SO_REUSEADDR,
            reuse.as_ptr(),
            reuse.len() as i32,
        );
        let mut random = [0u8; 2];
        random_bytes(&mut random);
        let local_port = (u16::from_be_bytes(random) & 0x3fff) + 0x1000;
        let local = SockAddrIn::new(Endpoint {
            address: Ipv4Address::UNSPECIFIED,
            port: local_port,
        });
        let remote = SockAddrIn::new(endpoint);
        let mut non_blocking = u32::from(!blocking);
        let connected = NetDll_bind(
            XNCALLER_XBDM,
            socket,
            (&local as *const SockAddrIn).cast(),
            size_of::<SockAddrIn>() as i32,
        ) != SOCKET_ERROR
            && NetDll_ioctlsocket(XNCALLER_XBDM, socket, FIONBIO, &mut non_blocking)
                != SOCKET_ERROR
            && NetDll_connect(
                XNCALLER_XBDM,
                socket,
                (&remote as *const SockAddrIn).cast(),
                size_of::<SockAddrIn>() as i32,
            ) != SOCKET_ERROR;
        if !connected {
            close(socket);
            return Err(NetError::Closed);
        }
        Ok(SocketId(socket))
    }

    fn wait_writable(&mut self, socket: SocketId, timeout_ms: u32) -> Result<(), NetError> {
        let mut read = FdSet::new();
        let mut write = FdSet::new();
        write.insert(socket.0);
        let timeout = TimeVal::from_milliseconds(timeout_ms);
        match select(&mut read, &mut write, Some(&timeout))? {
            0 => Err(NetError::WouldBlock),
            _ => Ok(()),
        }
    }

    fn set_blocking(&mut self, socket: SocketId, blocking: bool) -> Result<(), NetError> {
        let mut non_blocking = u32::from(!blocking);
        match NetDll_ioctlsocket(XNCALLER_XBDM, socket.0, FIONBIO, &mut non_blocking) {
            SOCKET_ERROR => Err(last_error()),
            _ => Ok(()),
        }
    }

    fn pending_input(&mut self, socket: SocketId) -> Result<usize, NetError> {
        let mut pending = 0u32;
        match NetDll_ioctlsocket(XNCALLER_XBDM, socket.0, FIONREAD, &mut pending) {
            0 => Ok(pending as usize),
            _ => Err(last_error()),
        }
    }
}
