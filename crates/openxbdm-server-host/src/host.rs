//! The server, simulated console, and sockets, and the threads that drive
//! them.

#[cfg(feature = "smb")]
mod smb;

use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::thread;
use std::time::Duration;

use openxbdm_server::ConnectionIndex;
use openxbdm_server::Outcome;
use openxbdm_server::Server;
use openxbdm_server::SocketId;
use openxbdm_server::commands::session;
use openxbdm_server::server::Owner;

use crate::backend::MockBackend;
use crate::network::SocketTable;

/// Server, simulated console, and sockets.
#[derive(Default)]
pub struct Host {
    pub server: Server,
    pub backend: MockBackend,
    pub network: SocketTable,
}

impl Host {
    /// Startup work of the monitor: execute the settings files.
    pub fn start(&mut self) {
        let Self {
            server,
            backend,
            network,
        } = self;
        openxbdm_server::commands::system::load_settings(server, backend, network);
    }
}

/// A host shared between connection threads.
#[derive(Clone)]
pub struct SharedHost {
    host: Arc<Mutex<Host>>,
    #[cfg(feature = "smb")]
    smb: Arc<Mutex<smb::Service>>,
}

impl SharedHost {
    /// Start `host` and share it.
    pub fn new(mut host: Host) -> Self {
        host.start();

        #[cfg(feature = "smb")]
        let smb = smb::start(&mut host);

        Self {
            host: Arc::new(Mutex::new(host)),
            #[cfg(feature = "smb")]
            smb,
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, Host> {
        self.host
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Accept connections until the listener fails.
    pub fn serve(&self, listener: &TcpListener) -> io::Result<()> {
        let timers = self.clone();
        thread::spawn(move || timers.run_timers());

        loop {
            let (stream, _) = listener.accept()?;
            self.accept(stream);
        }
    }

    /// Run the server's periodic work. The console runs it on every pass of
    /// its loop; this thread runs it at least every `TIMER_PERIOD`.
    fn run_timers(&self) {
        /// Longest delay between runs of the server's periodic work.
        const TIMER_PERIOD: Duration = Duration::from_millis(50);

        loop {
            let delay = {
                let mut guard = self.lock();
                let Host {
                    server,
                    backend,
                    network,
                } = &mut *guard;
                server.drain_posted_notifications(backend, network);
                server.poll_timers(backend)
            };

            #[cfg(feature = "smb")]
            self.poll_smb_timers();

            let delay = delay.map_or(TIMER_PERIOD, |milliseconds| {
                Duration::from_millis(u64::from(milliseconds))
            });
            thread::sleep(delay.min(TIMER_PERIOD));
        }
    }

    /// Hand a new TCP connection to the server.
    pub fn accept(&self, stream: TcpStream) {
        let Ok(waiter) = stream.try_clone() else {
            return;
        };

        let mut guard = self.lock();
        let Host {
            server,
            backend,
            network,
        } = &mut *guard;
        let socket = network.insert(stream);
        if let Some(index) = server.accept(socket, backend, network) {
            let host = self.clone();
            thread::spawn(move || host.service(index, socket, &waiter));
        }
    }

    fn service(&self, index: ConnectionIndex, socket: SocketId, waiter: &TcpStream) {
        /// Interval at which a connection waiting for a processor call is
        /// checked.
        const PROCESSOR_POLL: Duration = Duration::from_millis(1);
        /// Longest wait for a transfer socket to become writable before the
        /// connection state is checked again.
        const WRITE_POLL: Duration = Duration::from_millis(50);

        let mut probe = [0u8; 1];
        loop {
            let wants_write = {
                let guard = self.lock();
                let Some(owner) = guard
                    .server
                    .connections()
                    .find(|(i, s, _)| *i == index && *s == socket)
                    .map(|(_, _, o)| o)
                else {
                    return;
                };

                if owner == Owner::Unserviced {
                    return;
                }

                if guard.server.awaits_processor(index) {
                    None
                } else {
                    Some(guard.server.wants_write(index))
                }
            };

            let Some(wants_write) = wants_write else {
                thread::sleep(PROCESSOR_POLL);
                continue;
            };

            if wants_write {
                // The monitor sends only to sockets select reports writable;
                // the wait runs without the lock. A failed socket counts as
                // writable so that the send reports the failure.
                if matches!(crate::network::wait_writable(waiter, WRITE_POLL), Ok(false)) {
                    continue;
                }

                let mut guard = self.lock();
                let Host {
                    server,
                    backend,
                    network,
                } = &mut *guard;
                if !server
                    .connections()
                    .any(|(i, s, _)| i == index && s == socket)
                {
                    return;
                }

                if server.wants_write(index)
                    && server.on_writable(index, backend, network) == Outcome::Released
                {
                    return;
                }

                continue;
            }

            let _ = waiter.peek(&mut probe);

            let released = {
                let mut guard = self.lock();
                let Host {
                    server,
                    backend,
                    network,
                } = &mut *guard;
                if !server
                    .connections()
                    .any(|(i, s, _)| i == index && s == socket)
                {
                    return;
                }

                server.on_readable(index, backend, network) == Outcome::Released
            };

            if released {
                return self.service_fast_pipe(socket, waiter);
            }
        }
    }

    /// Service a socket the `fastpipe` engine took over until the engine
    /// closes it.
    fn service_fast_pipe(&self, socket: SocketId, waiter: &TcpStream) {
        let mut probe = [0u8; 1];
        loop {
            if !self
                .lock()
                .server
                .fast_pipe_sockets()
                .any(|pipe| pipe == socket)
            {
                return;
            }

            let _ = waiter.peek(&mut probe);

            let mut guard = self.lock();
            let Host {
                server,
                backend,
                network,
            } = &mut *guard;
            if !server.fast_pipe_sockets().any(|pipe| pipe == socket) {
                return;
            }

            server.on_fast_pipe_readable(socket, backend, network);
        }
    }

    /// Answer name discovery datagrams on `socket` until it fails.
    pub fn serve_discovery(&self, socket: &UdpSocket) -> io::Result<()> {
        socket.set_broadcast(true)?;

        let mut request = [0u8; session::DISCOVERY_PACKET_CAPACITY];
        loop {
            let (length, sender) = socket.recv_from(&mut request)?;

            let mut reply = [0u8; session::DISCOVERY_PACKET_CAPACITY];
            let answer = session::answer_discovery(
                &self.lock().server.state,
                &request[..length],
                &mut reply,
            );
            let Some(answer) = answer else { continue };

            let destination = match answer.destination {
                session::DiscoveryDestination::Sender => sender,
                session::DiscoveryDestination::Broadcast => {
                    SocketAddr::from((Ipv4Addr::BROADCAST, sender.port()))
                }
            };

            // A failed send loses this reply only.
            let _ = socket.send_to(&reply[..answer.length], destination);
        }
    }
}
