//! Socket operations the server needs from the platform.

/// A platform socket handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketId(pub u32);

/// An IPv4 address in network byte order (`octets()[0]` is the first
/// dotted-decimal group).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Address(pub [u8; 4]);

impl Ipv4Address {
    pub const UNSPECIFIED: Self = Self([0; 4]);

    pub const fn octets(self) -> [u8; 4] {
        self.0
    }

    pub const fn is_unspecified(self) -> bool {
        u32::from_be_bytes(self.0) == 0
    }
}

/// An IPv4 endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub address: Ipv4Address,
    pub port: u16,
}

/// Failure of a socket operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// The peer closed the connection or the socket failed.
    Closed,
    /// A non-blocking operation could not proceed.
    WouldBlock,
    /// No resources for a new socket.
    Exhausted,
}

pub trait Network {
    /// Receive into `buffer`. `Ok(0)` means the peer closed the connection.
    fn receive(&mut self, socket: SocketId, buffer: &mut [u8]) -> Result<usize, NetError>;
    /// Send part of `data`; returns the number of bytes accepted.
    fn send(&mut self, socket: SocketId, data: &[u8]) -> Result<usize, NetError>;
    fn close(&mut self, socket: SocketId);
    fn peer(&mut self, socket: SocketId) -> Result<Endpoint, NetError>;
    /// Open a TCP connection from a local port in `0x1000..0x5000`.
    fn connect(&mut self, endpoint: Endpoint, blocking: bool) -> Result<SocketId, NetError>;
    /// Wait until `socket` can accept data, up to `timeout_ms`.
    fn wait_writable(&mut self, socket: SocketId, timeout_ms: u32) -> Result<(), NetError>;
    /// Switch a socket between blocking and non-blocking mode.
    fn set_blocking(&mut self, socket: SocketId, blocking: bool) -> Result<(), NetError>;
    /// Bytes of input waiting to be received (FIONREAD).
    fn pending_input(&mut self, socket: SocketId) -> Result<usize, NetError>;
}

/// Send all of `data`, looping on partial sends.
pub fn send_all(
    network: &mut dyn Network,
    socket: SocketId,
    mut data: &[u8],
) -> Result<(), NetError> {
    while !data.is_empty() {
        match network.send(socket, data)? {
            0 => return Err(NetError::Closed),
            sent => data = &data[sent..],
        }
    }
    Ok(())
}

/// Send `text` followed by CR LF.
pub fn send_line(network: &mut dyn Network, socket: SocketId, text: &[u8]) -> Result<(), NetError> {
    send_all(network, socket, text)?;
    send_all(network, socket, b"\r\n")
}
