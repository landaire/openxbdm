//! Datagram transports.

use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::time::Duration;
use std::time::Instant;

use openxbdm_kd_core::packet::Datagram;
use openxbdm_kd_core::packet::MAX_DATAGRAM_LEN;

/// UDP port of the host and the target in the stock kdnet settings.
pub const DEFAULT_PORT: u16 = 50000;

/// Blocking datagram exchange with one target.
pub trait DatagramTransport {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()>;

    /// Waits up to `timeout` for a datagram from the target. Returns the
    /// datagram length, or `None` when the timeout elapsed.
    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> io::Result<Option<usize>>;
}

/// UDP transport bound to the host port from the kdnet settings.
///
/// The kernel accepts only datagrams whose source port equals the
/// configured host port, so the socket binds that port.
pub struct UdpTransport {
    socket: UdpSocket,
    target: SocketAddr,
}

impl UdpTransport {
    pub fn bind(local: SocketAddr, target: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;
        Ok(Self { socket, target })
    }

    /// Binds `local` and waits for a beacon or packet to learn the target
    /// address from its source.
    pub fn discover(local: SocketAddr, timeout: Duration) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;
        let deadline = Instant::now() + timeout;
        let mut buffer = [0u8; MAX_DATAGRAM_LEN];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no kdnet datagram arrived; is kdnet enabled with this host's address?",
                ));
            }
            socket.set_read_timeout(Some(remaining))?;
            match socket.recv_from(&mut buffer) {
                Ok((length, source)) => {
                    if Datagram::decode(&buffer[..length]).is_ok() {
                        tracing::info!(%source, "target discovered");
                        return Ok(Self {
                            socket,
                            target: source,
                        });
                    }
                }
                Err(error) if is_timeout(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }

    pub fn target(&self) -> SocketAddr {
        self.target
    }
}

pub fn default_local() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DEFAULT_PORT))
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

impl DatagramTransport for UdpTransport {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        self.socket.send_to(datagram, self.target).map(|_| ())
    }

    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            self.socket.set_read_timeout(Some(remaining))?;
            match self.socket.recv_from(buffer) {
                Ok((length, source)) if source == self.target => return Ok(Some(length)),
                Ok((_, source)) => tracing::debug!(%source, "ignored datagram from another peer"),
                Err(error) if is_timeout(&error) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
    }
}
