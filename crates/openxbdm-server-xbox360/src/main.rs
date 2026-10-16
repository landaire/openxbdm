#![cfg_attr(target_arch = "powerpc", no_std)]
#![cfg_attr(target_arch = "powerpc", no_main)]

#[cfg(not(target_arch = "powerpc"))]
fn main() {
    println!("openxbdm-server-xbox360 must be built for powerpc-unknown-xbox360");
}

#[cfg(target_arch = "powerpc")]
mod backend;
#[cfg(target_arch = "powerpc")]
mod exports;
#[cfg(target_arch = "powerpc")]
mod kernel;
#[cfg(target_arch = "powerpc")]
mod lockfree;
#[cfg(target_arch = "powerpc")]
mod net;

#[cfg(target_arch = "powerpc")]
mod xbox360 {
    use core::panic::PanicInfo;
    use core::sync::atomic::AtomicBool;
    use core::sync::atomic::AtomicU32;
    use core::sync::atomic::Ordering;

    use openxbdm_core::status::KernelError;
    use openxbdm_core::status::NtStatus;
    use openxbdm_server::ConnectionIndex;
    use openxbdm_server::Server;
    use openxbdm_server::SocketId;
    use openxbdm_server::commands::session;
    use openxbdm_server::network::Endpoint;
    use openxbdm_server::network::Ipv4Address;
    use openxbdm_server::server::MAX_CONNECTIONS;
    use openxbdm_server::server::Owner;

    use crate::backend::Console;
    use crate::kernel;
    use crate::kernel::AnsiString;
    use crate::kernel::ObjectAttributes;
    use crate::net;
    use crate::net::FdSet;
    use crate::net::INVALID_SOCKET;
    use crate::net::TimeVal;
    use crate::net::XNCALLER_XBDM;
    use crate::net::XamNetwork;

    const XBDM_PORT: u16 = 730;
    const LISTEN_BACKLOG: i32 = 8;
    /// Stack of stock's server thread (docs framework notes). The server
    /// state is static, and no frame on this thread may hold large buffers.
    const SERVER_STACK_SIZE: u32 = 0x8000;
    /// `ExCreateThread` flags of stock's server thread (docs framework
    /// notes); bit 0x400 makes it not debuggable, so its own thread
    /// notifications never wait for it.
    const SERVER_THREAD_FLAGS: u32 = 0x0400_04a6;
    /// Bug check code of a panic above passive level ('OXDP').
    const BUG_CHECK_PANIC: u32 = 0x4f58_4450;
    /// A failed listen is retried after LISTEN_RETRY_STEPS steps of
    /// LISTEN_RETRY_STEP_MS; each step serves queued requests.
    const LISTEN_RETRY_STEPS: u32 = 10;
    const LISTEN_RETRY_STEP_MS: u32 = 100;
    /// Select timeout, which bounds the delay before a shutdown request is
    /// seen.
    const POLL_INTERVAL_MS: u32 = 1000;
    /// Longest wait before a thread posted at a debug event is processed.
    const DEBUG_EVENT_POLL_MS: u32 = 20;
    const OVERRIDE_REMOVAL_ATTEMPTS: u32 = 30;

    static SHUTDOWN: AtomicBool = AtomicBool::new(false);
    static THREAD_HANDLE: AtomicU32 = AtomicU32::new(0);
    static LISTENER_SOCKET: AtomicU32 = AtomicU32::new(INVALID_SOCKET);

    fn shutting_down() -> bool {
        SHUTDOWN.load(Ordering::SeqCst)
    }

    /// Stop the server thread after its current pass (control code 0x02).
    pub(crate) fn request_shutdown() {
        SHUTDOWN.store(true, Ordering::SeqCst);
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Removal {
        Removed,
        Absent,
        Failed,
    }

    // XAM loads xbdm.xex with the system-root-only flag. The kernel still
    // searches \FlashEx\ before \SystemRoot\ and accepts a module there whose
    // bounding path names that file, so this file replaces the flash XBDM
    // until it is removed.
    const OVERRIDE_MODULE_PATH: &[u8] = br"\Device\Harddisk0\Partition1\DEVKIT\FlashEx\xbdm.xex";

    fn delete_file(path: &[u8]) -> Removal {
        let name = AnsiString::new(path);
        let attributes = ObjectAttributes {
            root_directory: 0,
            object_name: &name,
            attributes: kernel::OBJ_CASE_INSENSITIVE,
        };
        match NtStatus(kernel::NtDeleteFile(&attributes)).result() {
            Ok(()) => Removal::Removed,
            Err(
                KernelError::NoSuchFile
                | KernelError::ObjectNameNotFound
                | KernelError::ObjectPathNotFound,
            ) => Removal::Absent,
            Err(_) => Removal::Failed,
        }
    }

    // Startup work and rare paths stay out of line: a frame inlined into
    // the server loop would stay allocated under every command.
    #[inline(never)]
    fn initialize_network() -> bool {
        let mut startup = [0u8; 13];
        startup[0] = 0x0d;
        startup[1] = 0x81;
        startup[4] = 0x40;
        if net::NetDll_XNetStartup(XNCALLER_XBDM, startup.as_ptr()) != 0 {
            return false;
        }
        let mut wsa_data = [0u8; 512];
        net::NetDll_WSAStartup(XNCALLER_XBDM, 2, wsa_data.as_mut_ptr()) == 0
    }

    fn close_listener() {
        let socket = LISTENER_SOCKET.swap(INVALID_SOCKET, Ordering::SeqCst);
        if socket != INVALID_SOCKET {
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
        listener: u32,
        discovery: Option<u32>,
    ) {
        crate::backend::debugger::begin_event_service();
        serve_passes(server, console, network, listener, discovery);
        crate::backend::debugger::end_event_service();
    }

    #[inline(never)]
    fn serve_passes(
        server: &mut Server,
        console: &mut Console,
        network: &mut XamNetwork,
        listener: u32,
        discovery: Option<u32>,
    ) {
        let mut timer_ms = POLL_INTERVAL_MS;
        while !shutting_down() {
            let mut active = [None::<(ConnectionIndex, SocketId, bool)>; MAX_CONNECTIONS];
            for (slot, (index, socket, owner)) in server.connections().enumerate() {
                if owner != Owner::Unserviced && !server.awaits_processor(index) {
                    active[slot] = Some((index, socket, server.wants_write(index)));
                }
            }

            let mut read = FdSet::new();
            let mut write = FdSet::new();
            read.insert(listener);
            if let Some(discovery) = discovery {
                read.insert(discovery);
            }
            for &(_, socket, wants_write) in active.iter().flatten() {
                if wants_write {
                    write.insert(socket.0);
                } else {
                    read.insert(socket.0);
                }
            }
            let mut pipes = [None::<SocketId>; session::PIPE_SLOTS];
            for (slot, socket) in pipes.iter_mut().zip(server.fast_pipe_sockets()) {
                *slot = Some(socket);
                read.insert(socket.0);
            }
            // Threads waiting at debug events are seen at the next pass.
            let timeout =
                TimeVal::from_milliseconds(timer_ms.min(POLL_INTERVAL_MS).min(DEBUG_EVENT_POLL_MS));
            if net::select(&mut read, &mut write, Some(&timeout)).is_err() {
                return;
            }

            for &(index, socket, wants_write) in active.iter().flatten() {
                if wants_write && write.contains(socket.0) {
                    server.on_writable(index, console, network);
                } else if !wants_write && read.contains(socket.0) {
                    server.on_readable(index, console, network);
                }
            }
            for socket in pipes.into_iter().flatten() {
                if read.contains(socket.0) {
                    server.on_fast_pipe_readable(socket, console, network);
                }
            }
            if let Some(discovery) = discovery
                && read.contains(discovery)
            {
                answer_discovery(server, discovery);
            }
            timer_ms = server.poll_timers(console).unwrap_or(POLL_INTERVAL_MS);
            crate::backend::dispatcher::drain(server, console, network);
            crate::backend::session::poll_processor_calls(server, console, network);
            server.poll_debug_events(console, network);
            server.drain_posted_notifications(console, network);
            crate::backend::performance::studio::poll();
            crate::backend::performance::pix::poll();
            if read.contains(listener) {
                match net::accept(listener) {
                    Some(socket) => {
                        server.accept(SocketId(socket), console, network);
                    }
                    None => return,
                }
            }
        }
    }

    #[inline(never)]
    fn answer_discovery(server: &Server, socket: u32) {
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
                address: Ipv4Address([0xff; 4]),
                port: sender.port,
            },
        };
        net::send_to(socket, &reply[..answer.length], destination);
    }

    fn run_server() {
        while !initialize_network() {
            if shutting_down() {
                return;
            }
            kernel::debug_print(c"openxbdm: network initialization failed\n");
            kernel::sleep_milliseconds(1000);
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
        while !shutting_down() {
            let Ok(listener) = net::listen(XBDM_PORT, LISTEN_BACKLOG) else {
                kernel::debug_print(c"openxbdm: listen failed\n");
                for _ in 0..LISTEN_RETRY_STEPS {
                    if shutting_down() {
                        break;
                    }
                    crate::backend::dispatcher::drain(server, console, &mut network);
                    kernel::sleep_milliseconds(LISTEN_RETRY_STEP_MS);
                }
                continue;
            };
            LISTENER_SOCKET.store(listener, Ordering::SeqCst);
            if shutting_down() {
                break;
            }
            kernel::debug_print(c"openxbdm: listening on TCP port 730\n");
            let discovery = net::bind_datagram(XBDM_PORT).ok();
            serve(server, console, &mut network, listener, discovery);
            if let Some(discovery) = discovery {
                net::close(discovery);
            }
            close_listener();
        }
        close_listener();
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

    /// Remove the override, retrying while the file system is not ready.
    #[inline(never)]
    fn remove_override_module() -> Removal {
        let mut removal = delete_file(OVERRIDE_MODULE_PATH);
        for _ in 1..OVERRIDE_REMOVAL_ATTEMPTS {
            if removal != Removal::Failed || shutting_down() {
                break;
            }
            kernel::sleep_milliseconds(1000);
            removal = delete_file(OVERRIDE_MODULE_PATH);
        }
        kernel::debug_print(match removal {
            Removal::Removed => c"openxbdm: removed FlashEx override module\n",
            Removal::Absent => c"openxbdm: FlashEx override module is absent\n",
            Removal::Failed => c"openxbdm: failed to remove FlashEx override module\n",
        });
        removal
    }

    extern "C" fn server_thread(_context: u32) -> u32 {
        // Recorded first: debug prints and calls from this thread must
        // never wait for the server.
        crate::backend::debugger::set_server_thread();
        crate::backend::dispatcher::create_host();
        remove_override_module();
        if !shutting_down() {
            run_server();
        }
        stop_server_services();
        kernel::ExTerminateThread(0);
        loop {
            core::hint::spin_loop();
        }
    }

    /// Later calls and events take their default without waiting.
    fn stop_server_services() {
        crate::backend::dispatcher::stop_serving();
        crate::backend::debugger::end_event_service();
    }

    /// Module entry point named by the linker script. The loader calls it
    /// with the console ABI, so it runs `module_entry` behind the bridge.
    #[unsafe(no_mangle)]
    #[unsafe(naked)]
    pub unsafe extern "C" fn _start() {
        core::arch::naked_asm!(
            "lis 12, {target}@ha",
            "addi 12, 12, {target}@l",
            "b {bridge}",
            target = sym module_entry,
            bridge = sym crate::exports::module_bridge,
        )
    }

    extern "C" fn module_entry(module: u32, reason: u32, _reserved: u32) -> u32 {
        match reason {
            0 => {
                SHUTDOWN.store(true, Ordering::SeqCst);
                close_listener();
                let handle = THREAD_HANDLE.swap(0, Ordering::SeqCst);
                if handle != 0 {
                    // Commands on the server thread can arm engine hooks,
                    // so the engines stop only after it has exited.
                    kernel::NtWaitForSingleObjectEx(handle, 0, 0, core::ptr::null());
                    kernel::NtClose(handle);
                }
                stop_server_services();
                crate::backend::debugger::uninstall();
                crate::backend::session::uninstall();
                crate::backend::performance::shut_down();
                crate::backend::dispatcher::wait_for_callers();
                crate::backend::debugger::wait_for_event_waiters();
                1
            }
            1 => {
                // The recovery installs nothing, refuses every export, and
                // never waits on the loader thread.
                #[cfg(feature = "boot-guard")]
                if delete_file(BOOT_MARKER_PATH) != Removal::Removed {
                    crate::exports::RECOVERY.store(1, Ordering::SeqCst);
                    return start_thread(recovery_thread).map_or(0, |()| 1);
                }
                crate::backend::dispatcher::initialize_host();
                if !kernel::register_debug_monitor(module) {
                    kernel::debug_print(c"openxbdm: debug monitor registration failed\n");
                    return 0;
                }
                crate::backend::debugger::install();
                crate::backend::network::xhttpproxy::initialize();
                crate::backend::session::initialize();
                crate::backend::hardware::initialize();
                crate::backend::dispatcher::install();
                crate::backend::performance::initialize();
                crate::backend::memory::initialize();
                // The hooks above point into the image, so it stays loaded
                // without a server; calls and events take their defaults.
                if start_thread(server_thread).is_err() {
                    stop_server_services();
                }
                1
            }
            _ => 1,
        }
    }

    struct ThreadCreationFailed;

    fn start_thread(entry: extern "C" fn(u32) -> u32) -> Result<(), ThreadCreationFailed> {
        SHUTDOWN.store(false, Ordering::SeqCst);
        let mut handle = 0u32;
        let entry = entry as *const () as usize as u32;
        let status = NtStatus(kernel::ExCreateThread(
            &mut handle,
            SERVER_STACK_SIZE,
            core::ptr::null_mut(),
            0,
            entry,
            0,
            SERVER_THREAD_FLAGS,
        ));
        if status.result().is_err() {
            kernel::debug_print(c"openxbdm: server thread creation failed\n");
            return Err(ThreadCreationFailed);
        }
        THREAD_HANDLE.store(handle, Ordering::SeqCst);
        kernel::debug_print(c"openxbdm: server thread started\n");
        Ok(())
    }

    /// Boot without the marker after a deployment: the previous boot of this
    /// build armed the monitor and did not remove the override, so remove it
    /// and restart into the flash monitor without installing any hook.
    #[cfg(feature = "boot-guard")]
    extern "C" fn recovery_thread(_context: u32) -> u32 {
        kernel::debug_print(c"openxbdm: boot marker absent, restoring the flash monitor\n");
        if remove_override_module() != Removal::Failed {
            kernel::HalReturnToFirmware(kernel::FIRMWARE_REBOOT);
        }
        kernel::ExTerminateThread(0);
        loop {
            core::hint::spin_loop();
        }
    }

    #[cfg(feature = "boot-guard")]
    const BOOT_MARKER_PATH: &[u8] = br"\Device\Harddisk0\Partition1\DEVKIT\FlashEx\openxbdm.arm";

    /// Above passive level nothing may wait, so the console stops with a
    /// bug check. The server thread releases every waiter and exits; other
    /// threads break into the debugger and then stay parked.
    #[panic_handler]
    fn panic(_info: &PanicInfo<'_>) -> ! {
        if kernel::current_irql() != 0 {
            kernel::KeBugCheckEx(BUG_CHECK_PANIC, 0, 0, 0, 0);
        }
        kernel::debug_print(c"openxbdm: panic\n");
        if kernel::current_thread() == crate::backend::debugger::server_thread() {
            stop_server_services();
            kernel::ExTerminateThread(0);
        }
        kernel::DbgBreakPoint();
        loop {
            kernel::sleep_milliseconds(1000);
        }
    }
}
