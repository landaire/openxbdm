//! `Network` over std TCP sockets.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::TcpStream;
use std::time::Duration;

use openxbdm_server::network::Endpoint;
use openxbdm_server::network::Ipv4Address;
use openxbdm_server::network::NetError;
use openxbdm_server::network::Network;
use openxbdm_server::network::SocketId;

/// Longest a blocking send may wait for the peer, as the monitor gives a
/// notification socket 60 seconds to become writable.
const SEND_LIMIT: Duration = Duration::from_secs(60);

/// Wait up to `timeout` until `stream` can accept data or has failed.
/// `false` means the time ran out.
pub fn wait_writable(stream: &TcpStream, timeout: Duration) -> io::Result<bool> {
    let milliseconds =
        std::ffi::c_int::try_from(timeout.as_millis()).unwrap_or(std::ffi::c_int::MAX);
    match poll::wait_writable(stream, milliseconds) {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(false),
        _ => Ok(true),
    }
}

#[cfg(unix)]
mod poll {
    use std::net::TcpStream;
    use std::os::fd::AsRawFd;

    #[repr(C)]
    struct PollFd {
        fd: std::ffi::c_int,
        events: std::ffi::c_short,
        revents: std::ffi::c_short,
    }

    const POLLOUT: std::ffi::c_short = 0x4;

    #[cfg(target_os = "linux")]
    type PollCount = std::ffi::c_ulong;
    #[cfg(not(target_os = "linux"))]
    type PollCount = std::ffi::c_uint;

    unsafe extern "C" {
        fn poll(fds: *mut PollFd, count: PollCount, timeout: std::ffi::c_int) -> std::ffi::c_int;
    }

    /// `poll` for writability: the number of ready sockets, or -1.
    pub fn wait_writable(stream: &TcpStream, milliseconds: std::ffi::c_int) -> std::ffi::c_int {
        let mut entry = PollFd {
            fd: stream.as_raw_fd(),
            events: POLLOUT,
            revents: 0,
        };
        // SAFETY: `entry` is one valid pollfd for the duration of the call.
        unsafe { poll(&mut entry, 1, milliseconds) }
    }
}

#[cfg(windows)]
mod poll {
    use std::net::TcpStream;
    use std::os::windows::io::AsRawSocket;

    #[repr(C)]
    struct WsaPollFd {
        fd: usize,
        events: std::ffi::c_short,
        revents: std::ffi::c_short,
    }

    /// POLLWRNORM, which WinSock names POLLOUT.
    const POLLOUT: std::ffi::c_short = 0x10;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAPoll(
            fds: *mut WsaPollFd,
            count: std::ffi::c_ulong,
            timeout: std::ffi::c_int,
        ) -> std::ffi::c_int;
    }

    /// `WSAPoll` for writability: the number of ready sockets, or -1
    /// (SOCKET_ERROR, with the error in `GetLastError`).
    pub fn wait_writable(stream: &TcpStream, milliseconds: std::ffi::c_int) -> std::ffi::c_int {
        let mut entry = WsaPollFd {
            fd: stream.as_raw_socket() as usize,
            events: POLLOUT,
            revents: 0,
        };
        // SAFETY: `entry` is one valid WSAPOLLFD for the duration of the call.
        unsafe { WSAPoll(&mut entry, 1, milliseconds) }
    }
}

/// The send buffer space at which `poll` reports a socket writable
/// (SO_SNDLOWAT). The engine sends at most `TRANSFER_CAPACITY` bytes per
/// writable report, so with that much free the send does not block while
/// the host lock is held. macOS defaults to 2048 bytes; Linux reports
/// writable only with a third of the buffer free and does not accept the
/// option, and Windows has no such option.
#[cfg(target_os = "macos")]
fn reserve_send_space(stream: &TcpStream) {
    use std::os::fd::AsRawFd;

    use openxbdm_server::server::TRANSFER_CAPACITY;

    const SOL_SOCKET: std::ffi::c_int = 0xffff;
    const SO_SNDLOWAT: std::ffi::c_int = 0x1003;

    unsafe extern "C" {
        fn setsockopt(
            socket: std::ffi::c_int,
            level: std::ffi::c_int,
            name: std::ffi::c_int,
            value: *const std::ffi::c_void,
            length: u32,
        ) -> std::ffi::c_int;
    }

    let low_water =
        std::ffi::c_int::try_from(TRANSFER_CAPACITY).expect("TRANSFER_CAPACITY fits in c_int");
    // SAFETY: `low_water` outlives the call and its size is passed.
    // A failure leaves the default, under which a send may block.
    unsafe {
        setsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_SNDLOWAT,
            (&raw const low_water).cast(),
            size_of::<std::ffi::c_int>() as u32,
        );
    }
}

#[cfg(not(target_os = "macos"))]
fn reserve_send_space(_stream: &TcpStream) {}

/// Open sockets by identifier.
#[derive(Debug, Default)]
pub struct SocketTable {
    sockets: HashMap<u32, TcpStream>,
    /// Sockets switched to non-blocking mode.
    non_blocking: HashSet<u32>,
    next: u32,
}

impl SocketTable {
    pub fn insert(&mut self, stream: TcpStream) -> SocketId {
        // A peer that stops reading fails the send instead of holding the
        // host lock indefinitely.
        let _ = stream.set_write_timeout(Some(SEND_LIMIT));
        reserve_send_space(&stream);
        self.next += 1;
        self.sockets.insert(self.next, stream);
        SocketId(self.next)
    }

    pub fn get(&self, socket: SocketId) -> Option<&TcpStream> {
        self.sockets.get(&socket.0)
    }

    /// A second handle to the socket for waiting without the table lock.
    pub fn try_clone(&self, socket: SocketId) -> Option<TcpStream> {
        self.get(socket).and_then(|stream| stream.try_clone().ok())
    }

    fn stream(&mut self, socket: SocketId) -> Result<&mut TcpStream, NetError> {
        self.sockets.get_mut(&socket.0).ok_or(NetError::Closed)
    }
}

fn map_error(error: io::Error) -> NetError {
    match error.kind() {
        io::ErrorKind::WouldBlock => NetError::WouldBlock,
        _ => NetError::Closed,
    }
}

impl Network for SocketTable {
    fn receive(&mut self, socket: SocketId, buffer: &mut [u8]) -> Result<usize, NetError> {
        self.stream(socket)?.read(buffer).map_err(map_error)
    }

    fn send(&mut self, socket: SocketId, data: &[u8]) -> Result<usize, NetError> {
        let blocking = !self.non_blocking.contains(&socket.0);
        self.stream(socket)?
            .write(data)
            .map_err(|error| match error.kind() {
                // The write timeout of a blocking socket expired.
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut if blocking => NetError::Closed,
                _ => map_error(error),
            })
    }

    fn close(&mut self, socket: SocketId) {
        self.non_blocking.remove(&socket.0);
        if let Some(stream) = self.sockets.remove(&socket.0) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    fn peer(&mut self, socket: SocketId) -> Result<Endpoint, NetError> {
        match self.stream(socket)?.peer_addr().map_err(map_error)? {
            SocketAddr::V4(address) => Ok(Endpoint {
                address: Ipv4Address(address.ip().octets()),
                port: address.port(),
            }),
            SocketAddr::V6(address) => match address.ip().to_ipv4_mapped() {
                Some(ip) => Ok(Endpoint {
                    address: Ipv4Address(ip.octets()),
                    port: address.port(),
                }),
                None => Err(NetError::Closed),
            },
        }
    }

    fn connect(&mut self, endpoint: Endpoint, blocking: bool) -> Result<SocketId, NetError> {
        let address = SocketAddrV4::new(Ipv4Addr::from(endpoint.address.octets()), endpoint.port);
        let stream = TcpStream::connect(address).map_err(map_error)?;
        stream.set_nonblocking(!blocking).map_err(map_error)?;
        let socket = self.insert(stream);
        if !blocking {
            self.non_blocking.insert(socket.0);
        }
        Ok(socket)
    }

    fn wait_writable(&mut self, socket: SocketId, timeout_ms: u32) -> Result<(), NetError> {
        match wait_writable(
            self.stream(socket)?,
            Duration::from_millis(u64::from(timeout_ms)),
        ) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(NetError::Closed),
        }
    }

    fn set_blocking(&mut self, socket: SocketId, blocking: bool) -> Result<(), NetError> {
        self.stream(socket)?
            .set_nonblocking(!blocking)
            .map_err(map_error)?;
        if blocking {
            self.non_blocking.remove(&socket.0);
        } else {
            self.non_blocking.insert(socket.0);
        }
        Ok(())
    }

    fn pending_input(&mut self, socket: SocketId) -> Result<usize, NetError> {
        const PEEK_LIMIT: usize = 0x10000;
        let restore_blocking = !self.non_blocking.contains(&socket.0);
        let stream = self.stream(socket)?;
        stream.set_nonblocking(true).map_err(map_error)?;
        let mut buffer = vec![0u8; PEEK_LIMIT];
        let pending = match stream.peek(&mut buffer) {
            Ok(count) => Ok(count),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(error) => Err(map_error(error)),
        };
        if restore_blocking {
            stream.set_nonblocking(false).map_err(map_error)?;
        }
        pending
    }
}
