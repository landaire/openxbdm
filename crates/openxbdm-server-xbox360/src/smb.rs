//! SMB file server on TCP port 445. The server thread services it in its
//! select loop next to the XBDM sockets.

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::Platform;
use openxbdm_server::Server;
use openxbdm_server::SocketId;
use openxbdm_server::smb::SmbService;

use crate::backend::Console;
use crate::kernel;
use crate::net;
use crate::net::FdSet;
use crate::net::INVALID_SOCKET;
use crate::net::XamNetwork;

const SMB_PORT: u16 = 445;
const LISTEN_BACKLOG: i32 = 4;
/// Each connection holds two pool blocks of `smb::BUFFER_SIZE` bytes.
const CONNECTIONS: usize = 2;
/// Delay before a failed listen is tried again, in FILETIME units (5 s).
const LISTEN_RETRY: u64 = 5 * 10_000_000;

/// Service state used by the server thread only.
struct Local {
    service: SmbService<CONNECTIONS>,
    /// When to try to listen again while there is no listener.
    listen_at: Option<u64>,
}

/// Connection state is static: the server thread's stack could not hold
/// it.
struct LocalCell(UnsafeCell<Local>);

// SAFETY: only the server thread uses the state.
unsafe impl Sync for LocalCell {}

static LOCAL: LocalCell = LocalCell(UnsafeCell::new(Local {
    service: SmbService::new(),
    listen_at: None,
}));
/// The listener; unload closes it from another thread.
static LISTENER: AtomicU32 = AtomicU32::new(INVALID_SOCKET);

/// The service state.
///
/// # Safety
///
/// Called on the server thread only, and the reference is dropped before
/// the next call.
unsafe fn local() -> &'static mut Local {
    // SAFETY: exclusivity per the contract.
    unsafe { &mut *LOCAL.0.get() }
}

/// Sockets of one select pass: the listener and each connection with
/// whether it waits to send.
pub(crate) struct Sockets {
    listener: Option<u32>,
    connections: [Option<(SocketId, bool)>; CONNECTIONS],
}

/// Start the service and listen on its port. Without a listener the
/// monitor serves XBDM and tries again later.
#[inline(never)]
pub(crate) fn open(console: &mut Console) {
    // SAFETY: called on the server thread.
    let local = unsafe { local() };
    local.service.start(console);
    listen(local, console);
}

fn listen(local: &mut Local, console: &mut Console) {
    match net::listen(SMB_PORT, LISTEN_BACKLOG) {
        Ok(listener) => {
            LISTENER.store(listener, Ordering::SeqCst);
            local.listen_at = None;
            kernel::debug_print(c"openxbdm: SMB listening on TCP port 445\n");
        }
        Err(_) => {
            local.listen_at = Some(console.system_time().wrapping_add(LISTEN_RETRY));
            kernel::debug_print(c"openxbdm: SMB listen failed\n");
        }
    }
}

/// Close the listener; safe on any thread.
pub(crate) fn close_listener() {
    let socket = LISTENER.swap(INVALID_SOCKET, Ordering::SeqCst);
    if socket != INVALID_SOCKET {
        net::close(socket);
    }
}

/// Close the listener and every connection.
#[inline(never)]
pub(crate) fn shut_down(server: &Server, console: &mut Console, network: &mut XamNetwork) {
    close_listener();
    // SAFETY: called on the server thread.
    let local = unsafe { local() };
    local.listen_at = None;
    local.service.close_all(&server.state, console, network);
}

/// Periodic work: close connections past their time limits and retry a
/// failed listen.
#[inline(never)]
pub(crate) fn poll(server: &Server, console: &mut Console, network: &mut XamNetwork) {
    // SAFETY: called on the server thread.
    let local = unsafe { local() };
    local.service.poll_timers(&server.state, console, network);
    if let Some(at) = local.listen_at
        && console.system_time() >= at
    {
        listen(local, console);
    }
}

/// Add the service's sockets to the select sets.
#[inline(never)]
pub(crate) fn select_sockets(read: &mut FdSet, write: &mut FdSet) -> Sockets {
    let listener = Some(LISTENER.load(Ordering::SeqCst)).filter(|&socket| socket != INVALID_SOCKET);
    if let Some(listener) = listener {
        read.insert(listener);
    }
    let mut connections = [None; CONNECTIONS];
    // SAFETY: called on the server thread.
    let service = &unsafe { local() }.service;
    for (slot, (socket, wants_write)) in connections.iter_mut().zip(service.sockets()) {
        *slot = Some((socket, wants_write));
        if wants_write {
            write.insert(socket.0);
        } else {
            read.insert(socket.0);
        }
    }
    Sockets {
        listener,
        connections,
    }
}

/// Report the ready sockets of `sockets` to the service. A failed accept
/// closes the listener, which is opened again after `LISTEN_RETRY`, so a
/// broken listener does not keep select returning.
#[inline(never)]
pub(crate) fn dispatch(
    sockets: &Sockets,
    read: &FdSet,
    write: &FdSet,
    server: &Server,
    console: &mut Console,
    network: &mut XamNetwork,
) {
    // SAFETY: called on the server thread.
    let local = unsafe { local() };
    for &(socket, wants_write) in sockets.connections.iter().flatten() {
        if wants_write && write.contains(socket.0) {
            local
                .service
                .on_writable(socket, &server.state, console, network);
        } else if !wants_write && read.contains(socket.0) {
            local
                .service
                .on_readable(socket, &server.state, console, network);
        }
    }
    let Some(listener) = sockets.listener else {
        return;
    };
    if !read.contains(listener) {
        return;
    }
    match net::accept(listener) {
        Some(socket) => local
            .service
            .accept(SocketId(socket), &server.state, console, network),
        None => {
            close_listener();
            local.listen_at = Some(console.system_time().wrapping_add(LISTEN_RETRY));
            kernel::debug_print(c"openxbdm: SMB accept failed\n");
        }
    }
}
