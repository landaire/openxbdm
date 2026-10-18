use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::XBDM_PORT;
use openxbdm_server::ConnectionIndex;
use openxbdm_server::Server;
use openxbdm_server::SocketId;
use openxbdm_server::commands::session;
use openxbdm_server::network::Endpoint;
use openxbdm_server::network::Ipv4Address;
use openxbdm_server::server::MAX_CONNECTIONS;
use openxbdm_server::server::Owner;
use xbox360::time::sleep;
use xbox360_sys::xam;
use xbox360_sys::xam::FdSet;
use xbox360_sys::xam::Socket;
use xbox360_sys::xam::TimeVal;
use xbox360_sys::xam::WinsockVersion;
use xbox360_sys::xam::WsaData;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xam::XnetStartupFlags;
use xbox360_sys::xam::XnetStartupParams;

use crate::backend::Console;
use crate::kernel;
use crate::net;
use crate::net::FdSetExt as _;
use crate::net::XamNetwork;
use crate::thread::shutting_down;

/// Delay between attempts of startup work that waits for the network or
/// the file system.
pub(crate) const RETRY_DELAY: Duration = Duration::from_secs(1);

static LISTENER_SOCKET: AtomicU32 = AtomicU32::new(Socket::INVALID.raw());

/// A connection selected for one pass.
#[derive(Clone, Copy)]
struct ActiveConnection {
    index: ConnectionIndex,
    socket: SocketId,
    wants_write: bool,
}

// Startup work and rare paths stay out of line: a frame inlined into
// the server loop would stay allocated under every command.
#[inline(never)]
fn initialize_network() -> bool {
    let startup = XnetStartupParams {
        // Stock also sets bit 0x80, which has no name.
        flags: XnetStartupFlags::BYPASS_SECURITY | XnetStartupFlags::from_bits_retain(0x80),
        default_receive_buffer_kib: 0x40,
        ..XnetStartupParams::new()
    };
    // SAFETY: `startup` is a live parameter block.
    if unsafe { xam::NetDll_XNetStartup(XnCaller::DebugMonitor, &startup) } != 0 {
        return false;
    }

    let mut wsa_data = WsaData::new();
    // SAFETY: `wsa_data` is live storage for the call to fill.
    unsafe {
        xam::NetDll_WSAStartup(
            XnCaller::DebugMonitor,
            WinsockVersion::new(2, 0),
            &mut wsa_data,
        )
    }
    .error()
    .is_none()
}

pub(crate) fn close_listener() {
    let socket = Socket::from_raw(LISTENER_SOCKET.swap(Socket::INVALID.raw(), Ordering::SeqCst));
    if socket != Socket::INVALID {
        net::close(socket);
    }
}

/// Service connections until the listener fails or shutdown starts.
/// `discovery` is the UDP socket of the name discovery responder.
/// Threads wait at debug events only while these passes run.
fn serve(
    server: &mut Server,
    console: &mut Console,
    network: &mut XamNetwork,
    listener: Socket,
    discovery: Option<Socket>,
) {
    let wake = crate::backend::debugger::open_wake();
    if wake.is_none() {
        kernel::debug_print(c"openxbdm: no wake socket; debug events wait up to 20 ms\n");
    }

    crate::backend::debugger::begin_event_service();
    serve_passes(server, console, network, listener, discovery, wake);
    crate::backend::debugger::end_event_service();
    if let Some(wake) = wake {
        crate::backend::debugger::close_wake(wake);
    }
}

#[inline(never)]
fn serve_passes(
    server: &mut Server,
    console: &mut Console,
    network: &mut XamNetwork,
    listener: Socket,
    discovery: Option<Socket>,
    wake: Option<Socket>,
) {
    /// Select timeout, which bounds the delay before a shutdown request is
    /// seen.
    const POLL_INTERVAL_MS: u32 = 1000;
    /// Longest wait before work other threads queue for the server thread
    /// is seen (dispatcher requests, posted notifications, processor calls,
    /// and debug events when no wake socket is available).
    const PASS_INTERVAL_MS: u32 = 20;

    let mut timer_ms = POLL_INTERVAL_MS;
    while !shutting_down() {
        let mut active = [None::<ActiveConnection>; MAX_CONNECTIONS];
        for (slot, (index, socket, owner)) in server.connections().enumerate() {
            if owner != Owner::Unserviced && !server.awaits_processor(index) {
                active[slot] = Some(ActiveConnection {
                    index,
                    socket,
                    wants_write: server.wants_write(index),
                });
            }
        }

        let mut read = FdSet::new();
        let mut write = FdSet::new();
        read.insert(listener);
        if let Some(discovery) = discovery {
            read.insert(discovery);
        }
        if let Some(wake) = wake {
            read.insert(wake);
        }

        for &ActiveConnection {
            socket,
            wants_write,
            ..
        } in active.iter().flatten()
        {
            if wants_write {
                write.insert(net::socket_of(socket));
            } else {
                read.insert(net::socket_of(socket));
            }
        }

        let mut pipes = [None::<SocketId>; session::PIPE_SLOTS];
        for (slot, socket) in pipes.iter_mut().zip(server.fast_pipe_sockets()) {
            *slot = Some(socket);
            read.insert(net::socket_of(socket));
        }

        #[cfg(feature = "smb")]
        let smb_sockets = crate::smb::select_sockets(&mut read, &mut write);

        // A thread posting a debug event makes the wake socket readable.
        let timeout =
            TimeVal::from_milliseconds(timer_ms.min(POLL_INTERVAL_MS).min(PASS_INTERVAL_MS));
        if net::select(&mut read, &mut write, Some(&timeout)).is_err() {
            return;
        }

        for &ActiveConnection {
            index,
            socket,
            wants_write,
        } in active.iter().flatten()
        {
            if wants_write && write.contains(net::socket_of(socket)) {
                server.on_writable(index, console, network);
            } else if !wants_write && read.contains(net::socket_of(socket)) {
                server.on_readable(index, console, network);
            }
        }

        for socket in pipes.into_iter().flatten() {
            if read.contains(net::socket_of(socket)) {
                server.on_fast_pipe_readable(socket, console, network);
            }
        }

        #[cfg(feature = "smb")]
        crate::smb::dispatch(&smb_sockets, &read, &write, server, console, network);
        if let Some(discovery) = discovery
            && read.contains(discovery)
        {
            answer_discovery(server, discovery);
        }
        if let Some(wake) = wake
            && read.contains(wake)
        {
            crate::backend::debugger::drain_wake(wake);
        }

        timer_ms = server
            .poll_timers(console, network)
            .unwrap_or(POLL_INTERVAL_MS);
        #[cfg(feature = "smb")]
        crate::smb::poll(server, console, network);
        crate::backend::dispatcher::drain(server, console, network);
        crate::backend::session::poll_processor_calls(server, console, network);
        server.poll_debug_events(console, network);
        server.drain_posted_notifications(console, network);
        crate::backend::performance::studio::poll();
        crate::backend::performance::pix::poll();

        if !read.contains(listener) {
            continue;
        }
        let Some(socket) = net::accept(listener) else {
            return;
        };
        server.accept(SocketId(socket.raw()), console, network);
    }
}

#[inline(never)]
fn answer_discovery(server: &Server, socket: Socket) {
    /// Destination of a discovery reply to every host.
    const BROADCAST: Ipv4Address = Ipv4Address([0xff; 4]);

    let mut request = [0u8; session::DISCOVERY_PACKET_CAPACITY];
    let Ok((length, sender)) = net::receive_from(socket, &mut request) else {
        return;
    };

    let mut reply = [0u8; session::DISCOVERY_PACKET_CAPACITY];
    let Some(answer) = session::answer_discovery(&server.state, &request[..length], &mut reply)
    else {
        return;
    };

    let destination = match answer.destination {
        session::DiscoveryDestination::Sender => sender,
        session::DiscoveryDestination::Broadcast => Endpoint {
            address: BROADCAST,
            port: sender.port,
        },
    };
    net::send_to(socket, &reply[..answer.length], destination);
}

pub(crate) fn run_server() {
    const LISTEN_BACKLOG: i32 = 8;
    /// A failed listen is retried after LISTEN_RETRY_STEPS steps of
    /// LISTEN_RETRY_STEP; each step serves queued requests.
    const LISTEN_RETRY_STEPS: u32 = 10;
    const LISTEN_RETRY_STEP: Duration = Duration::from_millis(100);

    while !initialize_network() {
        if shutting_down() {
            return;
        }

        kernel::debug_print(c"openxbdm: network initialization failed\n");
        sleep(RETRY_DELAY);
    }

    // Stock initializes the studio subsystem last, once the network runs.
    crate::backend::performance::studio::initialize();
    load_settings();

    let mut network = XamNetwork;
    // From here on the server thread takes queued requests until it
    // stops: in its passes, and between listen attempts.
    let Some((server, console)) = crate::backend::dispatcher::begin_serving() else {
        return;
    };

    #[cfg(feature = "smb")]
    crate::smb::open(console);

    while !shutting_down() {
        let Ok(listener) = net::listen(XBDM_PORT, LISTEN_BACKLOG) else {
            kernel::debug_print(c"openxbdm: listen failed\n");
            for _ in 0..LISTEN_RETRY_STEPS {
                if shutting_down() {
                    break;
                }

                crate::backend::dispatcher::drain(server, console, &mut network);
                sleep(LISTEN_RETRY_STEP);
            }

            continue;
        };
        LISTENER_SOCKET.store(listener.raw(), Ordering::SeqCst);
        if shutting_down() {
            break;
        }

        // The message names XBDM_PORT.
        const _: () = assert!(XBDM_PORT == 730);
        kernel::debug_print(c"openxbdm: listening on TCP port 730\n");

        let discovery = net::bind_datagram(XBDM_PORT).ok();
        serve(server, console, &mut network, listener, discovery);
        if let Some(discovery) = discovery {
            net::close(discovery);
        }
        close_listener();
    }

    close_listener();
    #[cfg(feature = "smb")]
    crate::smb::shut_down(server, console, &mut network);
    server.shut_down();

    let mut open = [None::<ConnectionIndex>; MAX_CONNECTIONS];
    for (slot, (index, _, _)) in server.connections().enumerate() {
        open[slot] = Some(index);
    }

    for index in open.into_iter().flatten() {
        server.close(index, &mut network);
    }

    // Processor threads run this module's code.
    crate::backend::session::release_processor_threads(console);
}

#[inline(never)]
fn load_settings() {
    let mut network = XamNetwork;
    crate::backend::dispatcher::with_startup_host(|server, console| {
        openxbdm_server::commands::system::load_settings(server, console, &mut network);
        crate::backend::dvd_hotplug::install(server.state.console.trace_mask);
    });
}
