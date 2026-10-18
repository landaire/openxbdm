//! `Network` over std TCP sockets.

mod socket_option;
mod wait;

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
use openxbdm_server::network::SendBufferSize;
use openxbdm_server::network::SocketId;

use self::socket_option::reserve_send_space;
use self::socket_option::send_buffer_size;

pub use self::socket_option::set_keepalive;
pub use self::wait::wait_readable;
pub use self::wait::wait_writable;

/// Open sockets by identifier.
#[derive(Debug, Default)]
pub struct SocketTable {
    sockets: HashMap<u32, TcpStream>,
    /// Sockets switched to non-blocking mode.
    non_blocking: HashSet<u32>,
    /// Send buffer sizes set through `set_send_buffer_size`. The platform
    /// buffer is left unchanged, as Linux doubles the value it is given.
    send_buffers: HashMap<u32, SendBufferSize>,

    next: u32,
}

impl SocketTable {
    pub fn insert(&mut self, stream: TcpStream) -> SocketId {
        /// Longest a blocking send may wait for the peer, as the monitor
        /// gives a notification socket 60 seconds to become writable.
        const SEND_LIMIT: Duration = Duration::from_secs(60);

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

    /// Identifiers of the open sockets.
    pub fn sockets(&self) -> impl Iterator<Item = SocketId> + '_ {
        self.sockets.keys().map(|&socket| SocketId(socket))
    }

    /// The send buffer size last set on `socket`, if any.
    pub fn recorded_send_buffer_size(&self, socket: SocketId) -> Option<SendBufferSize> {
        self.send_buffers.get(&socket.0).copied()
    }

    fn stream(&mut self, socket: SocketId) -> Result<&mut TcpStream, NetError> {
        self.sockets.get_mut(&socket.0).ok_or(NetError::Closed)
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
        self.send_buffers.remove(&socket.0);

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
            Ok(false) => Err(NetError::WouldBlock),
            Err(_) => Err(NetError::Closed),
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

    fn send_buffer_size(&mut self, socket: SocketId) -> Result<SendBufferSize, NetError> {
        if let Some(size) = self.recorded_send_buffer_size(socket) {
            return Ok(size);
        }

        send_buffer_size(self.stream(socket)?)
            .map(SendBufferSize)
            .map_err(map_error)
    }

    fn set_send_buffer_size(
        &mut self,
        socket: SocketId,
        size: SendBufferSize,
    ) -> Result<(), NetError> {
        self.stream(socket)?;
        self.send_buffers.insert(socket.0, size);

        Ok(())
    }
}

fn map_error(error: io::Error) -> NetError {
    match error.kind() {
        io::ErrorKind::WouldBlock => NetError::WouldBlock,
        _ => NetError::Closed,
    }
}
