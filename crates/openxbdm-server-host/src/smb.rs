//! SMB file server over the simulated console. Each connection has a
//! thread that waits for its socket without a lock and then reports the
//! event to the service.

use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::thread;
use std::time::Duration;

use openxbdm_server::SocketId;
use openxbdm_server::smb::SmbService;

use crate::Host;
use crate::SharedHost;
use crate::network;

/// Concurrent SMB connections.
const CONNECTIONS: usize = 4;
/// Longest wait for a socket before the connection state is checked
/// again.
const POLL: Duration = Duration::from_millis(500);
/// Delay after a failed accept, which may repeat while the process has no
/// free descriptors.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

pub(crate) type Service = SmbService<CONNECTIONS>;

/// A started service.
pub(crate) fn start(host: &mut Host) -> Arc<Mutex<Service>> {
    let mut service = Service::new();
    service.start(&mut host.backend);
    Arc::new(Mutex::new(service))
}

impl SharedHost {
    fn lock_smb(&self) -> MutexGuard<'_, Service> {
        self.smb
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Accept SMB connections; a failed accept is retried.
    pub fn serve_smb(&self, listener: &TcpListener) -> ! {
        loop {
            match listener.accept() {
                Ok((stream, _)) => self.accept_smb(stream),
                Err(_) => thread::sleep(ACCEPT_RETRY),
            }
        }
    }

    /// Close SMB connections that exceeded a time limit.
    pub(crate) fn poll_smb_timers(&self) {
        let mut smb = self.lock_smb();
        let mut guard = self.lock();
        let Host {
            server,
            backend,
            network,
        } = &mut *guard;
        smb.poll_timers(&server.state, backend, network);
    }

    fn accept_smb(&self, stream: TcpStream) {
        let Ok(waiter) = stream.try_clone() else {
            return;
        };
        // Without keep-alive probes the time limits still end the
        // connection.
        let _ = network::set_keepalive(&stream);
        let mut smb = self.lock_smb();
        let mut guard = self.lock();
        let Host {
            server,
            backend,
            network,
        } = &mut *guard;
        let socket = network.insert(stream);
        smb.accept(socket, &server.state, backend, network);
        if smb.contains(socket) {
            let host = self.clone();
            thread::spawn(move || host.service_smb(socket, &waiter));
        }
    }

    fn service_smb(&self, socket: SocketId, waiter: &TcpStream) {
        loop {
            let wants_write = {
                let smb = self.lock_smb();
                if !smb.contains(socket) {
                    return;
                }
                smb.wants_write(socket)
            };
            let ready = if wants_write {
                network::wait_writable(waiter, POLL)
            } else {
                network::wait_readable(waiter, POLL)
            };
            // A failed socket counts as ready so that the service sees the
            // failure.
            if matches!(ready, Ok(false)) {
                continue;
            }
            let mut smb = self.lock_smb();
            let mut guard = self.lock();
            let Host {
                server,
                backend,
                network,
            } = &mut *guard;
            if smb.wants_write(socket) {
                smb.on_writable(socket, &server.state, backend, network);
            } else {
                smb.on_readable(socket, &server.state, backend, network);
            }
        }
    }
}
