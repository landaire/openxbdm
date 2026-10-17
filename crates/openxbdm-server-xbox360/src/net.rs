//! Sockets through the XAM network stack.

use openxbdm_server::network::Endpoint;
use openxbdm_server::network::Ipv4Address;
use openxbdm_server::network::NetError;
use openxbdm_server::network::Network;
use openxbdm_server::network::SocketId;
use xbox360::status::KernelError;
use xbox360::status::Win32Error;
use xbox360::status::Win32ErrorCode;
use xbox360_sys::xam::AddressFamily;
use xbox360_sys::xam::FD_SETSIZE;
use xbox360_sys::xam::FdSet;
use xbox360_sys::xam::IoctlCommand;
use xbox360_sys::xam::MessageFlags;
use xbox360_sys::xam::NetDll_WSAGetLastError;
use xbox360_sys::xam::NetDll_XNetGetOpt;
use xbox360_sys::xam::NetDll_XNetRandom;
use xbox360_sys::xam::NetDll_accept;
use xbox360_sys::xam::NetDll_bind;
use xbox360_sys::xam::NetDll_closesocket;
use xbox360_sys::xam::NetDll_connect;
use xbox360_sys::xam::NetDll_getpeername;
use xbox360_sys::xam::NetDll_ioctlsocket;
use xbox360_sys::xam::NetDll_listen;
use xbox360_sys::xam::NetDll_recv;
use xbox360_sys::xam::NetDll_recvfrom;
use xbox360_sys::xam::NetDll_select;
use xbox360_sys::xam::NetDll_send;
use xbox360_sys::xam::NetDll_sendto;
use xbox360_sys::xam::NetDll_setsockopt;
use xbox360_sys::xam::NetDll_socket;
use xbox360_sys::xam::Protocol;
use xbox360_sys::xam::SOCKET_ERROR;
use xbox360_sys::xam::SockAddrIn;
use xbox360_sys::xam::Socket;
use xbox360_sys::xam::SocketLevel;
use xbox360_sys::xam::SocketOption;
use xbox360_sys::xam::SocketType;
use xbox360_sys::xam::TimeVal;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xam::XnetOption;

/// `endpoint` as an IPv4 `sockaddr`.
pub(crate) fn socket_address(endpoint: Endpoint) -> SockAddrIn {
    SockAddrIn {
        family: AddressFamily::Inet.raw() as u16,
        port: endpoint.port,
        address: u32::from_be_bytes(endpoint.address.octets()),
        zero: [0; 8],
    }
}

/// The XAM socket of a server socket identifier.
#[inline]
pub(crate) fn socket_of(id: SocketId) -> Socket {
    Socket::from_raw(id.0)
}

/// Membership operations on a Winsock descriptor set.
pub trait FdSetExt {
    fn insert(&mut self, socket: Socket);
    fn contains(&self, socket: Socket) -> bool;
}

impl FdSetExt for FdSet {
    fn insert(&mut self, socket: Socket) {
        if (self.count as usize) < FD_SETSIZE {
            self.sockets[self.count as usize] = socket;
            self.count += 1;
        }
    }

    fn contains(&self, socket: Socket) -> bool {
        self.sockets[..self.count as usize].contains(&socket)
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
    // SAFETY: both sets are live for the call; `timeout` is null or live.
    match unsafe {
        NetDll_select(
            XnCaller::DebugMonitor,
            0,
            read,
            write,
            core::ptr::null_mut(),
            timeout,
        )
    } {
        SOCKET_ERROR => Err(NetError::Closed),
        count => Ok(count as u32),
    }
}

/// Open a listening TCP socket on `port` with address reuse, as the monitor's
/// command thread does.
pub fn listen(port: u16, backlog: i32) -> Result<Socket, NetError> {
    // SAFETY: socket creation takes scalar arguments.
    let socket = unsafe {
        NetDll_socket(
            XnCaller::DebugMonitor,
            AddressFamily::Inet,
            SocketType::Stream,
            Protocol::Tcp,
        )
    };
    if socket == Socket::INVALID {
        return Err(NetError::Exhausted);
    }
    let enable = 1u32.to_be_bytes();
    let address = socket_address(Endpoint {
        address: Ipv4Address::UNSPECIFIED,
        port,
    });
    // SAFETY: `socket` was created above; `enable` and `address` are live
    // locals of the stated lengths.
    if unsafe {
        NetDll_setsockopt(
            XnCaller::DebugMonitor,
            socket,
            SocketLevel::Socket,
            SocketOption::SO_REUSEADDR,
            enable.as_ptr(),
            enable.len() as i32,
        )
    } == SOCKET_ERROR
        // SAFETY: as above.
        || unsafe {
            NetDll_bind(
                XnCaller::DebugMonitor,
                socket,
                (&address as *const SockAddrIn).cast(),
                size_of::<SockAddrIn>() as i32,
            )
        } == SOCKET_ERROR
        // SAFETY: as above.
        || unsafe { NetDll_listen(XnCaller::DebugMonitor, socket, backlog) } == SOCKET_ERROR
    {
        // SAFETY: the socket is owned here and not used again.
        unsafe { NetDll_closesocket(XnCaller::DebugMonitor, socket) };
        return Err(NetError::Closed);
    }
    Ok(socket)
}

pub fn accept(listener: Socket) -> Option<Socket> {
    // SAFETY: null address pointers are allowed; the listener is owned by
    // the caller.
    let socket = unsafe {
        NetDll_accept(
            XnCaller::DebugMonitor,
            listener,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    (socket != Socket::INVALID).then_some(socket)
}

/// Open a UDP socket on `port` that may send broadcasts. Failure is
/// reported, not fatal: the monitor serves TCP without it.
pub fn bind_datagram(port: u16) -> Result<Socket, NetError> {
    // SAFETY: socket creation takes scalar arguments.
    let socket = unsafe {
        NetDll_socket(
            XnCaller::DebugMonitor,
            AddressFamily::Inet,
            SocketType::Datagram,
            Protocol::Udp,
        )
    };
    if socket == Socket::INVALID {
        return Err(NetError::Exhausted);
    }
    let enable = 1u32.to_be_bytes();
    // SAFETY: `socket` was created above; `enable` is a live 4-byte local.
    unsafe {
        NetDll_setsockopt(
            XnCaller::DebugMonitor,
            socket,
            SocketLevel::Socket,
            SocketOption::SO_REUSEADDR,
            enable.as_ptr(),
            enable.len() as i32,
        );
        NetDll_setsockopt(
            XnCaller::DebugMonitor,
            socket,
            SocketLevel::Socket,
            SocketOption::SO_BROADCAST,
            enable.as_ptr(),
            enable.len() as i32,
        );
    }
    let address = socket_address(Endpoint {
        address: Ipv4Address::UNSPECIFIED,
        port,
    });
    // SAFETY: `socket` was created above; `address` is a live local.
    if unsafe {
        NetDll_bind(
            XnCaller::DebugMonitor,
            socket,
            (&address as *const SockAddrIn).cast(),
            size_of::<SockAddrIn>() as i32,
        )
    } == SOCKET_ERROR
    {
        // SAFETY: the socket is owned here and not used again.
        unsafe { NetDll_closesocket(XnCaller::DebugMonitor, socket) };
        return Err(NetError::Closed);
    }
    Ok(socket)
}

/// Receive one datagram; returns its length and sender.
pub fn receive_from(socket: Socket, buffer: &mut [u8]) -> Result<(usize, Endpoint), NetError> {
    let mut from = socket_address(Endpoint {
        address: Ipv4Address::UNSPECIFIED,
        port: 0,
    });
    let mut length = size_of::<SockAddrIn>() as i32;
    // SAFETY: `buffer`, `from` and `length` are live for the call.
    match unsafe {
        NetDll_recvfrom(
            XnCaller::DebugMonitor,
            socket,
            buffer.as_mut_ptr(),
            buffer.len() as i32,
            MessageFlags::empty(),
            (&mut from as *mut SockAddrIn).cast(),
            &mut length,
        )
    } {
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
pub fn send_to(socket: Socket, data: &[u8], endpoint: Endpoint) {
    let to = socket_address(endpoint);
    // SAFETY: `data` and `to` are live for the call.
    unsafe {
        NetDll_sendto(
            XnCaller::DebugMonitor,
            socket,
            data.as_ptr(),
            data.len() as i32,
            MessageFlags::empty(),
            (&to as *const SockAddrIn).cast(),
            size_of::<SockAddrIn>() as i32,
        )
    };
}

pub fn close(socket: Socket) {
    // SAFETY: callers pass a socket they own and do not use again.
    unsafe { NetDll_closesocket(XnCaller::DebugMonitor, socket) };
}

/// Fill `output` from the network stack's random source.
pub fn random_bytes(output: &mut [u8]) {
    // SAFETY: `output` is live and writable for its length.
    unsafe {
        NetDll_XNetRandom(
            XnCaller::DebugMonitor,
            output.as_mut_ptr(),
            output.len() as u32,
        )
    };
}

/// Whether a secondary network interface is present.
pub fn has_secondary_nic() -> bool {
    let mut value = [0u8; 6];
    let mut length = value.len() as i32;
    // SAFETY: `value` and `length` are live locals.
    let result = unsafe {
        NetDll_XNetGetOpt(
            XnCaller::DebugMonitor,
            XnetOption::SECONDARY_NIC,
            value.as_mut_ptr(),
            &mut length,
        )
    } as u32;
    // Stock treats every other result, success or failure, as present.
    result != KernelError::DeviceDoesNotExist.status().0
        && Win32ErrorCode(result).error() != Some(Win32Error::INVALID_SOCKET_ARGUMENT)
}

fn last_error() -> NetError {
    if NetDll_WSAGetLastError(XnCaller::DebugMonitor).error() == Some(Win32Error::WOULD_BLOCK) {
        NetError::WouldBlock
    } else {
        NetError::Closed
    }
}

/// `Network` over XAM sockets. Socket identifiers are socket handles.
pub struct XamNetwork;

impl Network for XamNetwork {
    fn receive(&mut self, socket: SocketId, buffer: &mut [u8]) -> Result<usize, NetError> {
        // SAFETY: `buffer` is live and writable for its length.
        match unsafe {
            NetDll_recv(
                XnCaller::DebugMonitor,
                socket_of(socket),
                buffer.as_mut_ptr(),
                buffer.len() as i32,
                MessageFlags::empty(),
            )
        } {
            SOCKET_ERROR => Err(last_error()),
            count => Ok(count as usize),
        }
    }

    fn send(&mut self, socket: SocketId, data: &[u8]) -> Result<usize, NetError> {
        // SAFETY: `data` is live for its length.
        match unsafe {
            NetDll_send(
                XnCaller::DebugMonitor,
                socket_of(socket),
                data.as_ptr(),
                data.len() as i32,
                MessageFlags::empty(),
            )
        } {
            SOCKET_ERROR => Err(last_error()),
            count => Ok(count as usize),
        }
    }

    fn close(&mut self, socket: SocketId) {
        close(socket_of(socket));
    }

    fn peer(&mut self, socket: SocketId) -> Result<Endpoint, NetError> {
        let mut address = socket_address(Endpoint {
            address: Ipv4Address::UNSPECIFIED,
            port: 0,
        });
        let mut length = size_of::<SockAddrIn>() as i32;
        // SAFETY: `address` and `length` are live locals.
        if unsafe {
            NetDll_getpeername(
                XnCaller::DebugMonitor,
                socket_of(socket),
                (&mut address as *mut SockAddrIn).cast(),
                &mut length,
            )
        } == SOCKET_ERROR
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
        // SAFETY: socket creation takes scalar arguments.
        let socket = unsafe {
            NetDll_socket(
                XnCaller::DebugMonitor,
                AddressFamily::Inet,
                SocketType::Stream,
                Protocol::Tcp,
            )
        };
        if socket == Socket::INVALID {
            return Err(NetError::Exhausted);
        }
        let reuse = 1u32.to_be_bytes();
        // SAFETY: `socket` was created above; `reuse` is a live 4-byte local.
        unsafe {
            NetDll_setsockopt(
                XnCaller::DebugMonitor,
                socket,
                SocketLevel::Socket,
                SocketOption::SO_REUSEADDR,
                reuse.as_ptr(),
                reuse.len() as i32,
            )
        };
        let mut random = [0u8; 2];
        random_bytes(&mut random);
        /// Local ports are drawn from `LOCAL_PORT_BASE..LOCAL_PORT_BASE + 0x4000`.
        const LOCAL_PORT_BASE: u16 = 0x1000;
        const LOCAL_PORT_MASK: u16 = 0x3fff;
        let local_port = (u16::from_be_bytes(random) & LOCAL_PORT_MASK) + LOCAL_PORT_BASE;
        let local = socket_address(Endpoint {
            address: Ipv4Address::UNSPECIFIED,
            port: local_port,
        });
        let remote = socket_address(endpoint);
        let mut non_blocking = u32::from(!blocking);
        // SAFETY: `socket` was created above; `local`, `remote` and
        // `non_blocking` are live locals.
        let connected = unsafe {
            NetDll_bind(
                XnCaller::DebugMonitor,
                socket,
                (&local as *const SockAddrIn).cast(),
                size_of::<SockAddrIn>() as i32,
            )
        } != SOCKET_ERROR
            // SAFETY: as above.
            && unsafe {
                NetDll_ioctlsocket(
                    XnCaller::DebugMonitor,
                    socket,
                    IoctlCommand::Fionbio,
                    &mut non_blocking,
                )
            } != SOCKET_ERROR
            // SAFETY: as above.
            && unsafe {
                NetDll_connect(
                    XnCaller::DebugMonitor,
                    socket,
                    (&remote as *const SockAddrIn).cast(),
                    size_of::<SockAddrIn>() as i32,
                )
            } != SOCKET_ERROR;
        if !connected {
            close(socket);
            return Err(NetError::Closed);
        }
        Ok(SocketId(socket.raw()))
    }

    fn wait_writable(&mut self, socket: SocketId, timeout_ms: u32) -> Result<(), NetError> {
        let mut read = FdSet::new();
        let mut write = FdSet::new();
        write.insert(socket_of(socket));
        let timeout = TimeVal::from_milliseconds(timeout_ms);
        match select(&mut read, &mut write, Some(&timeout))? {
            0 => Err(NetError::WouldBlock),
            _ => Ok(()),
        }
    }

    fn set_blocking(&mut self, socket: SocketId, blocking: bool) -> Result<(), NetError> {
        let mut non_blocking = u32::from(!blocking);
        // SAFETY: `non_blocking` is a live local.
        match unsafe {
            NetDll_ioctlsocket(
                XnCaller::DebugMonitor,
                socket_of(socket),
                IoctlCommand::Fionbio,
                &mut non_blocking,
            )
        } {
            SOCKET_ERROR => Err(last_error()),
            _ => Ok(()),
        }
    }

    fn pending_input(&mut self, socket: SocketId) -> Result<usize, NetError> {
        let mut pending = 0u32;
        // SAFETY: `pending` is a live local.
        match unsafe {
            NetDll_ioctlsocket(
                XnCaller::DebugMonitor,
                socket_of(socket),
                IoctlCommand::Fionread,
                &mut pending,
            )
        } {
            0 => Ok(pending as usize),
            _ => Err(last_error()),
        }
    }
}
