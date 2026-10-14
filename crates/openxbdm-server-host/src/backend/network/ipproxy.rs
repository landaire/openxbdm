//! Simulated `ipproxy` services: a host UDP socket is the tunnel socket and
//! a host thread runs the receive loop.

use std::io;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;
use std::thread::JoinHandle;
use std::time::Instant;

use openxbdm_server::commands::network::WsaError;
use openxbdm_server::commands::network::ipproxy;
use openxbdm_server::commands::network::ipproxy::RegisterStatus;
use openxbdm_server::commands::network::ipproxy::RoutineMissing;
use openxbdm_server::commands::network::ipproxy::ThreadFailed;
use openxbdm_server::commands::network::ipproxy::tunnel;
use openxbdm_server::commands::network::ipproxy::tunnel::Inbound;
use openxbdm_server::commands::network::ipproxy::tunnel::Tunnel;
use openxbdm_server::network::Endpoint;
use openxbdm_server::network::Ipv4Address;

use crate::backend::MockBackend;

/// An export of the network stack that `ipproxy` resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Routine {
    Register,
    Inject,
}

/// Tunnel state shared with the receive thread.
#[derive(Debug)]
pub struct Link {
    /// Last message from the host (stock state +0x10).
    pub last_receive: Instant,
    /// Last message to the host (stock state +0x14).
    pub last_send: Instant,
    /// Packets the receive loop injected into the console network stack.
    pub injected: Vec<Vec<u8>>,
}

/// Simulated state of `ipproxy`.
#[derive(Debug)]
pub struct Mock {
    /// Export the network stack lacks.
    pub missing_routine: Option<Routine>,
    /// Error of the next socket open.
    pub socket_failure: Option<WsaError>,
    /// Result of the next register routine call.
    pub register_failure: Option<RegisterStatus>,
    /// The next receive thread creation fails.
    pub thread_failure: bool,
    pub register_routine: bool,
    pub inject_routine: bool,
    pub host: Option<Endpoint>,
    pub local: Endpoint,
    pub socket: Option<UdpSocket>,
    pub hook_installed: bool,
    /// Proxy bypass flag of the network simulator instance.
    pub proxy_bypass: bool,
    link: Arc<Mutex<Link>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Default for Mock {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            missing_routine: None,
            socket_failure: None,
            register_failure: None,
            thread_failure: false,
            register_routine: false,
            inject_routine: false,
            host: None,
            local: Endpoint {
                address: Ipv4Address::UNSPECIFIED,
                port: 0,
            },
            socket: None,
            hook_installed: false,
            proxy_bypass: false,
            link: Arc::new(Mutex::new(Link {
                last_receive: now,
                last_send: now,
                injected: Vec::new(),
            })),
            stopping: Arc::new(AtomicBool::new(false)),
            thread: None,
        }
    }
}

impl Mock {
    /// Tunnel state shared with the receive thread.
    pub fn link(&self) -> MutexGuard<'_, Link> {
        lock(&self.link)
    }

    /// Send `packet` out through the console network stack: with the hook
    /// installed, a tunneled packet goes to the host as a tunnel message.
    /// Returns whether the hook consumed the packet.
    pub fn transmit(&self, packet: &mut [u8]) -> bool {
        let (Some(socket), Some(host), true) = (&self.socket, self.host, self.hook_installed)
        else {
            return false;
        };
        let Some(outbound) = tunnel::encapsulate(
            packet,
            &Tunnel {
                local: self.local,
                host,
            },
        ) else {
            return false;
        };
        let mut datagram = outbound.message().to_vec();
        datagram.extend_from_slice(&packet[outbound.payload]);
        // The stack reports no delivery result to the hook.
        let _ = socket.send(&datagram);
        self.link().last_send = Instant::now();
        true
    }
}

/// Lock the shared tunnel state; a panicked receive loop leaves it usable.
fn lock(link: &Mutex<Link>) -> MutexGuard<'_, Link> {
    link.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Winsock code of a host socket error. Host errors without a Winsock
/// counterpart report the network as down.
fn wsa_error(error: &io::Error) -> WsaError {
    WsaError(match error.kind() {
        ErrorKind::PermissionDenied => 10013,
        ErrorKind::InvalidInput => 10022,
        ErrorKind::AddrInUse => 10048,
        ErrorKind::AddrNotAvailable => 10049,
        ErrorKind::NetworkUnreachable => 10051,
        ErrorKind::ConnectionRefused => 10061,
        ErrorKind::HostUnreachable => 10065,
        _ => 10050,
    })
}

fn connect(host: Endpoint) -> Result<(UdpSocket, u16), WsaError> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|error| wsa_error(&error))?;
    let target = SocketAddrV4::new(Ipv4Addr::from(host.address.octets()), host.port);
    socket.connect(target).map_err(|error| wsa_error(&error))?;
    let port = socket
        .local_addr()
        .map_err(|error| wsa_error(&error))?
        .port();
    Ok((socket, port))
}

/// The receive loop of stock thread 0x91f35798.
fn receive(socket: UdpSocket, link: Arc<Mutex<Link>>, stopping: Arc<AtomicBool>) {
    if socket
        .set_read_timeout(Some(tunnel::RECEIVE_TIMEOUT))
        .is_err()
    {
        return;
    }
    let mut buffer = [0u8; tunnel::MESSAGE_LIMIT];
    loop {
        let length = match socket.recv(&mut buffer) {
            Ok(length) => length,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => 0,
            Err(_) => return,
        };
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let now = Instant::now();
        let mut link = lock(&link);
        if now.duration_since(link.last_send) >= tunnel::KEEPALIVE_INTERVAL {
            let _ = socket.send(&tunnel::KEEPALIVE);
            link.last_send = now;
        }
        match tunnel::decapsulate(&buffer[..length]) {
            None => {}
            Some(Inbound::Keepalive) => link.last_receive = now,
            Some(Inbound::Packet(packet)) => {
                link.last_receive = now;
                let mut bytes = packet.ip.to_vec();
                bytes.extend_from_slice(packet.udp.as_ref().map_or(&[][..], |udp| &udp[..]));
                bytes.extend_from_slice(packet.payload);
                link.injected.push(bytes);
            }
        }
    }
}

impl ipproxy::Backend for MockBackend {
    fn proxy_started(&mut self) -> bool {
        self.network.ipproxy.register_routine
    }

    fn resolve_proxy_routines(&mut self) -> Result<(), RoutineMissing> {
        let mock = &mut self.network.ipproxy;
        if mock.missing_routine == Some(Routine::Register) {
            return Err(RoutineMissing);
        }
        mock.register_routine = true;
        if mock.missing_routine == Some(Routine::Inject) {
            return Err(RoutineMissing);
        }
        mock.inject_routine = true;
        Ok(())
    }

    fn release_proxy_routines(&mut self) {
        self.network.ipproxy.register_routine = false;
        self.network.ipproxy.inject_routine = false;
    }

    fn open_proxy_socket(&mut self, host: Endpoint) -> Result<(), WsaError> {
        let mock = &mut self.network.ipproxy;
        mock.host = Some(host);
        let now = Instant::now();
        {
            let mut link = lock(&mock.link);
            link.last_receive = now;
            link.last_send = now;
        }
        if let Some(error) = mock.socket_failure.take() {
            return Err(error);
        }
        let (socket, port) = connect(host)?;
        // The local address is the first dword of the debug XNADDR.
        let record = self.console.debug_address.record;
        mock.local = Endpoint {
            address: Ipv4Address([record[0], record[1], record[2], record[3]]),
            port,
        };
        mock.socket = Some(socket);
        Ok(())
    }

    fn close_proxy_socket(&mut self) {
        self.network.ipproxy.socket = None;
    }

    fn proxy_local_endpoint(&mut self) -> Endpoint {
        self.network.ipproxy.local
    }

    fn set_proxy_bypass(&mut self, active: bool) {
        self.network.ipproxy.proxy_bypass = active;
    }

    fn install_proxy_hook(&mut self) -> Result<(), RegisterStatus> {
        let mock = &mut self.network.ipproxy;
        if let Some(status) = mock.register_failure.take() {
            return Err(status);
        }
        mock.hook_installed = true;
        Ok(())
    }

    fn remove_proxy_hook(&mut self) -> Result<(), RegisterStatus> {
        let mock = &mut self.network.ipproxy;
        if let Some(status) = mock.register_failure.take() {
            return Err(status);
        }
        mock.hook_installed = false;
        Ok(())
    }

    fn start_proxy_thread(&mut self) -> Result<(), ThreadFailed> {
        let mock = &mut self.network.ipproxy;
        if std::mem::take(&mut mock.thread_failure) {
            return Err(ThreadFailed);
        }
        let socket = mock
            .socket
            .as_ref()
            .ok_or(ThreadFailed)?
            .try_clone()
            .map_err(|_| ThreadFailed)?;
        mock.stopping.store(false, Ordering::SeqCst);
        let link = Arc::clone(&mock.link);
        let stopping = Arc::clone(&mock.stopping);
        mock.thread = Some(thread::spawn(move || receive(socket, link, stopping)));
        Ok(())
    }

    fn stop_proxy_thread(&mut self) {
        let mock = &mut self.network.ipproxy;
        mock.stopping.store(true, Ordering::SeqCst);
        if let Some(socket) = mock.socket.take() {
            // Closing a host socket does not end a pending receive on its
            // clone: wake the loop with a datagram to itself instead.
            if let Ok(own) = socket.local_addr()
                && socket.connect(own).is_ok()
            {
                let _ = socket.send(&[]);
            }
        }
        if let Some(thread) = mock.thread.take() {
            let _ = thread.join();
        }
    }
}
