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
#[cfg(all(target_arch = "powerpc", feature = "smb"))]
mod smb;

#[cfg(target_arch = "powerpc")]
mod xbox360 {
    use core::panic::PanicInfo;
    use core::sync::atomic::AtomicBool;
    use core::sync::atomic::AtomicU32;
    use core::sync::atomic::Ordering;
    use core::time::Duration;

    use openxbdm_core::XBDM_PORT;
    use openxbdm_core::status::KernelError;
    use openxbdm_server::ConnectionIndex;
    use openxbdm_server::Server;
    use openxbdm_server::SocketId;
    use openxbdm_server::commands::session;
    use openxbdm_server::network::Endpoint;
    use openxbdm_server::network::Ipv4Address;
    use openxbdm_server::server::MAX_CONNECTIONS;
    use openxbdm_server::server::Owner;
    use xbox360_sys::processor;
    use xbox360_sys::xam;
    use xbox360_sys::xam::FdSet;
    use xbox360_sys::xam::Socket;
    use xbox360_sys::xam::TimeVal;
    use xbox360_sys::xam::WinsockVersion;
    use xbox360_sys::xam::WsaData;
    use xbox360_sys::xam::XnCaller;
    use xbox360_sys::xam::XnetStartupFlags;
    use xbox360_sys::xam::XnetStartupParams;
    use xbox360_sys::xboxkrnl;
    use xbox360_sys::xboxkrnl::Boolean;
    use xbox360_sys::xboxkrnl::BugCheckCode;
    use xbox360_sys::xboxkrnl::DllEntryReason;
    use xbox360_sys::xboxkrnl::Handle;
    use xbox360_sys::xboxkrnl::Irql;
    use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
    use xbox360_sys::xboxkrnl::ObjectAttributes;
    use xbox360_sys::xboxkrnl::ProcessorMode;
    use xbox360_sys::xboxkrnl::ThreadCreationFlags;
    // The crate, not this module.
    use ::xbox360::time::sleep;

    use crate::backend::Console;
    use crate::kernel;
    use crate::net;
    use crate::net::FdSetExt as _;
    use crate::net::XamNetwork;

    const LISTEN_BACKLOG: i32 = 8;
    /// Stack of stock's server thread (docs framework notes). The server
    /// state is static, and no frame on this thread may hold large buffers.
    const SERVER_STACK_SIZE: u32 = 0x8000;
    /// `ExCreateThread` flags of stock's server thread (docs framework
    /// notes). The server thread is not debuggable, so its own thread
    /// notifications never wait for it.
    const SERVER_THREAD_FLAGS: ThreadCreationFlags =
        kernel::SYSTEM_THREAD_FLAGS.union(ThreadCreationFlags::NOT_DEBUGGABLE);
    /// Exit code of the server and recovery threads.
    const THREAD_EXIT_CODE: u32 = 0;
    /// Bug check code of a panic above passive level ('OXDP').
    const BUG_CHECK_PANIC: BugCheckCode = BugCheckCode(0x4f58_4450);
    /// Delay between attempts of startup work that waits for the network or
    /// the file system.
    const RETRY_DELAY: Duration = Duration::from_secs(1);
    /// A failed listen is retried after LISTEN_RETRY_STEPS steps of
    /// LISTEN_RETRY_STEP; each step serves queued requests.
    const LISTEN_RETRY_STEPS: u32 = 10;
    const LISTEN_RETRY_STEP: Duration = Duration::from_millis(100);
    /// Select timeout, which bounds the delay before a shutdown request is
    /// seen.
    const POLL_INTERVAL_MS: u32 = 1000;
    /// Longest wait before a thread posted at a debug event is processed.
    const DEBUG_EVENT_POLL_MS: u32 = 20;
    const OVERRIDE_REMOVAL_ATTEMPTS: u32 = 30;
    /// Sleep of a thread parked after a panic.
    const PARKED_SLEEP: Duration = Duration::from_secs(1);
    /// Destination of a discovery reply to every host.
    const BROADCAST: Ipv4Address = Ipv4Address([0xff; 4]);

    static SHUTDOWN: AtomicBool = AtomicBool::new(false);
    /// The server or recovery thread, or `Handle::NULL` when none runs.
    static THREAD_HANDLE: AtomicU32 = AtomicU32::new(Handle::NULL.raw());
    static LISTENER_SOCKET: AtomicU32 = AtomicU32::new(Socket::INVALID.raw());

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
        let name = kernel::ansi_string(path);
        let attributes = ObjectAttributes {
            root_directory: Handle::NULL,
            object_name: &name,
            attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
        };
        // SAFETY: `attributes` and the name it points at are live locals.
        match unsafe { xboxkrnl::NtDeleteFile(&attributes) }.result() {
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

    fn close_listener() {
        let socket =
            Socket::from_raw(LISTENER_SOCKET.swap(Socket::INVALID.raw(), Ordering::SeqCst));
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
        crate::backend::debugger::begin_event_service();
        serve_passes(server, console, network, listener, discovery);
        crate::backend::debugger::end_event_service();
    }

    /// A connection selected for one pass.
    #[derive(Clone, Copy)]
    struct ActiveConnection {
        index: ConnectionIndex,
        socket: SocketId,
        wants_write: bool,
    }

    #[inline(never)]
    fn serve_passes(
        server: &mut Server,
        console: &mut Console,
        network: &mut XamNetwork,
        listener: Socket,
        discovery: Option<Socket>,
    ) {
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
            // Threads waiting at debug events are seen at the next pass.
            let timeout =
                TimeVal::from_milliseconds(timer_ms.min(POLL_INTERVAL_MS).min(DEBUG_EVENT_POLL_MS));
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
            timer_ms = server.poll_timers(console).unwrap_or(POLL_INTERVAL_MS);
            #[cfg(feature = "smb")]
            crate::smb::poll(server, console, network);
            crate::backend::dispatcher::drain(server, console, network);
            crate::backend::session::poll_processor_calls(server, console, network);
            server.poll_debug_events(console, network);
            server.drain_posted_notifications(console, network);
            crate::backend::performance::studio::poll();
            crate::backend::performance::pix::poll();
            if read.contains(listener) {
                match net::accept(listener) {
                    Some(socket) => {
                        server.accept(SocketId(socket.raw()), console, network);
                    }
                    None => return,
                }
            }
        }
    }

    #[inline(never)]
    fn answer_discovery(server: &Server, socket: Socket) {
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

    fn run_server() {
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

    /// Remove the override, retrying while the file system is not ready.
    #[inline(never)]
    fn remove_override_module() -> Removal {
        let mut removal = delete_file(OVERRIDE_MODULE_PATH);
        for _ in 1..OVERRIDE_REMOVAL_ATTEMPTS {
            if removal != Removal::Failed || shutting_down() {
                break;
            }
            sleep(RETRY_DELAY);
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
        // SAFETY: called on the server thread, which owns no further state.
        unsafe { xboxkrnl::ExTerminateThread(THREAD_EXIT_CODE) }
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
            bridge = sym xbox360_sys::entry_bridge,
        )
    }

    extern "C" fn module_entry(module: u32, reason: u32, _reserved: u32) -> Boolean {
        let succeeded = match DllEntryReason::from_raw(reason) {
            Some(DllEntryReason::ProcessDetach) => {
                unload();
                true
            }
            Some(DllEntryReason::ProcessAttach) => load(module),
            // Other reasons need no work.
            _ => true,
        };
        Boolean::from(succeeded)
    }

    #[inline(always)]
    fn unload() {
        SHUTDOWN.store(true, Ordering::SeqCst);
        close_listener();
        #[cfg(feature = "smb")]
        crate::smb::close_listener();
        let handle = Handle::from_raw(THREAD_HANDLE.swap(Handle::NULL.raw(), Ordering::SeqCst));
        if !handle.is_null() {
            // Commands on the server thread can arm engine hooks, so the
            // engines stop only after it has exited.
            // SAFETY: the handle came from `ExCreateThread` and the swap
            // above makes this the only owner.
            unsafe {
                xboxkrnl::NtWaitForSingleObjectEx(
                    handle,
                    ProcessorMode::Kernel,
                    false,
                    core::ptr::null(),
                );
                xboxkrnl::NtClose(handle);
            }
        }
        stop_server_services();
        crate::backend::debugger::uninstall();
        crate::backend::session::uninstall();
        crate::backend::performance::shut_down();
        crate::backend::dispatcher::wait_for_callers();
        crate::backend::debugger::wait_for_event_waiters();
    }

    /// Whether the module stays loaded.
    #[inline(always)]
    fn load(module: u32) -> bool {
        // Every later read of these imports skips the check.
        if !kernel::data_imports_resolved() {
            kernel::debug_print(c"openxbdm: unresolved data import\n");
            return false;
        }
        // The recovery installs nothing, refuses every export, and never
        // waits on the loader thread.
        #[cfg(feature = "boot-guard")]
        if delete_file(BOOT_MARKER_PATH) != Removal::Removed {
            crate::exports::RECOVERY.store(1, Ordering::SeqCst);
            return start_thread(recovery_thread).is_ok();
        }
        crate::backend::dispatcher::initialize_host();
        if !kernel::register_debug_monitor(module) {
            kernel::debug_print(c"openxbdm: debug monitor registration failed\n");
            return false;
        }
        crate::backend::debugger::install();
        crate::backend::network::xhttpproxy::initialize();
        crate::backend::session::initialize();
        crate::backend::hardware::initialize();
        crate::backend::dispatcher::install();
        crate::backend::performance::initialize();
        crate::backend::memory::initialize();
        // The hooks above point into the image, so it stays loaded without
        // a server; calls and events take their defaults.
        if start_thread(server_thread).is_err() {
            stop_server_services();
        }
        true
    }

    struct ThreadCreationFailed;

    fn start_thread(entry: extern "C" fn(u32) -> u32) -> Result<(), ThreadCreationFailed> {
        SHUTDOWN.store(false, Ordering::SeqCst);
        let mut handle = Handle::NULL.raw();
        let entry = entry as *const () as usize as u32;
        // SAFETY: `handle` is a live local and `entry` is a thread routine
        // with the start signature.
        let status = unsafe {
            xboxkrnl::ExCreateThread(
                &mut handle,
                SERVER_STACK_SIZE,
                core::ptr::null_mut(),
                0,
                entry,
                0,
                SERVER_THREAD_FLAGS,
            )
        };
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
            // SAFETY: no hook is installed; the reboot ends the title.
            unsafe { xboxkrnl::HalReturnToFirmware(xboxkrnl::FirmwareRequest::RebootQuiesce) };
        }
        // SAFETY: called on the recovery thread, which owns no further state.
        unsafe { xboxkrnl::ExTerminateThread(THREAD_EXIT_CODE) }
    }

    #[cfg(feature = "boot-guard")]
    const BOOT_MARKER_PATH: &[u8] = br"\Device\Harddisk0\Partition1\DEVKIT\FlashEx\openxbdm.arm";

    /// Above passive level nothing may wait, so the console stops with a
    /// bug check. The server thread releases every waiter and exits; other
    /// threads break into the debugger and then stay parked.
    #[panic_handler]
    fn panic(_info: &PanicInfo<'_>) -> ! {
        if processor::current_irql() != Irql::PASSIVE {
            xboxkrnl::KeBugCheckEx(BUG_CHECK_PANIC, 0, 0, 0, 0);
        }
        kernel::debug_print(c"openxbdm: panic\n");
        if crate::backend::debugger::server_thread()
            .is_some_and(|server| server.get() == processor::current_thread())
        {
            stop_server_services();
            // SAFETY: the server thread has released every waiter above.
            unsafe { xboxkrnl::ExTerminateThread(THREAD_EXIT_CODE) };
        }
        xboxkrnl::DbgBreakPoint();
        loop {
            sleep(PARKED_SLEEP);
        }
    }
}
