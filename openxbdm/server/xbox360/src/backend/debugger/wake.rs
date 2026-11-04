//! Ending the server thread's select at once when a thread posts an event.
//!
//! Stock does an event's work on the posting thread. Here the server thread
//! does it, and it waits in `NetDll_select`, which only socket readiness
//! ends before its timeout. The server selects on a datagram socket of its
//! own, and a posting thread sends one byte to it.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_server::network::Endpoint;
use openxbdm_server::network::Ipv4Address;
use xbox360::time::sleep;
use xbox360_sys::xam;
use xbox360_sys::xam::FdSet;
use xbox360_sys::xam::IoctlCommand;
use xbox360_sys::xam::SOCKET_ERROR;
use xbox360_sys::xam::SockAddrIn;
use xbox360_sys::xam::Socket;
use xbox360_sys::xam::TimeVal;
use xbox360_sys::xam::XnAddr;

use crate::net;
use crate::net::FdSetExt as _;

/// The wake socket while the server selects on it.
static WAKE_SOCKET: AtomicU32 = AtomicU32::new(Socket::INVALID.raw());
/// Address and port the wake datagram goes to, in socket address form.
static WAKE_ADDRESS: AtomicU32 = AtomicU32::new(0);
static WAKE_PORT: AtomicU32 = AtomicU32::new(0);
/// Threads inside [`wake_server`]; the socket is closed only at 0.
static SENDERS: AtomicU32 = AtomicU32::new(0);

/// Open the wake socket and find an address on which a datagram the console
/// sends to itself arrives: the loopback address, else the debug address.
/// `None` when the socket cannot be opened or no datagram arrives; the
/// server then keeps its short select timeout.
pub(crate) fn open_wake() -> Option<Socket> {
    /// How long a test datagram may take to arrive.
    const DELIVERY_WAIT_MS: u32 = 100;

    let socket = net::bind_datagram(0).ok()?;
    let mut local = net::socket_address(Endpoint {
        address: Ipv4Address::UNSPECIFIED,
        port: 0,
    });
    let mut length = size_of::<SockAddrIn>() as i32;
    let mut non_blocking = 1u32;
    // SAFETY: `socket` was opened above; `local`, `length` and
    // `non_blocking` are live locals of the stated sizes.
    let configured = unsafe {
        xam::NetDll_getsockname(
            crate::net::CALLER,
            socket,
            (&raw mut local).cast(),
            &mut length,
        ) != SOCKET_ERROR
            && xam::NetDll_ioctlsocket(
                crate::net::CALLER,
                socket,
                IoctlCommand::Fionbio,
                &mut non_blocking,
            ) != SOCKET_ERROR
    };
    if !configured {
        net::close(socket);
        return None;
    }

    let mut debug = XnAddr::default();
    // SAFETY: the query stores one XNADDR.
    unsafe { xam::NetDll_XNetGetDebugXnAddr(crate::net::CALLER, (&raw mut debug).cast()) };

    for address in [
        Ipv4Address([127, 0, 0, 1]),
        Ipv4Address(debug.address.to_be_bytes()),
    ] {
        // No debug address is assigned yet.
        if address.octets() == [0; 4] {
            continue;
        }

        let target = Endpoint {
            address,
            port: local.port,
        };
        net::send_to(socket, &[0], target);

        let mut read = FdSet::new();
        let mut write = FdSet::new();
        read.insert(socket);
        let timeout = TimeVal::from_milliseconds(DELIVERY_WAIT_MS);
        if net::select(&mut read, &mut write, Some(&timeout)).is_ok() && read.contains(socket) {
            drain_wake(socket);
            let target = net::socket_address(target);
            WAKE_ADDRESS.store(target.address, Ordering::Relaxed);
            WAKE_PORT.store(u32::from(target.port), Ordering::Relaxed);
            WAKE_SOCKET.store(socket.raw(), Ordering::SeqCst);
            return Some(socket);
        }
    }

    net::close(socket);
    None
}

/// Stop waking the server and close `socket`, once no thread sends on it.
pub(crate) fn close_wake(socket: Socket) {
    WAKE_SOCKET.store(Socket::INVALID.raw(), Ordering::SeqCst);
    while SENDERS.load(Ordering::SeqCst) != 0 {
        sleep(Duration::from_millis(1));
    }

    net::close(socket);
}

/// Take every wake datagram queued on `socket`.
pub(crate) fn drain_wake(socket: Socket) {
    let mut byte = [0u8; 1];
    while net::receive_from(socket, &mut byte).is_ok() {}
}

/// Make the server's select return, so that it takes the event just
/// posted. Called by posting threads at passive level, as stock sends its
/// notifications from the posting thread.
pub(super) fn wake_server() {
    SENDERS.fetch_add(1, Ordering::SeqCst);
    let socket = Socket::from_raw(WAKE_SOCKET.load(Ordering::SeqCst));
    if socket != Socket::INVALID {
        let target = SockAddrIn {
            address: WAKE_ADDRESS.load(Ordering::Relaxed),
            port: WAKE_PORT.load(Ordering::Relaxed) as u16,
            ..net::socket_address(Endpoint {
                address: Ipv4Address::UNSPECIFIED,
                port: 0,
            })
        };
        // A full queue drops the datagram; the server wakes for the queued
        // ones.
        // SAFETY: the byte and `target` are live for the call; the socket
        // stays open while `SENDERS` is nonzero.
        unsafe {
            xam::NetDll_sendto(
                crate::net::CALLER,
                socket,
                [0u8].as_ptr(),
                1,
                xam::MessageFlags::empty(),
                (&raw const target).cast(),
                size_of::<SockAddrIn>() as i32,
            )
        };
    }
    SENDERS.fetch_sub(1, Ordering::SeqCst);
}
