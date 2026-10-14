#![cfg_attr(target_arch = "powerpc", no_std)]
#![cfg_attr(target_arch = "powerpc", no_main)]

#[cfg(not(target_arch = "powerpc"))]
fn main() {
    println!("openxbdm-server-xbox360 must be built for powerpc-unknown-xbox360");
}

#[cfg(target_arch = "powerpc")]
mod xbox360 {
    use core::panic::PanicInfo;
    use core::sync::atomic::AtomicBool;
    use core::sync::atomic::AtomicU32;
    use core::sync::atomic::Ordering;

    use openxbdm_server::Address;
    use openxbdm_server::BackendError;
    use openxbdm_server::ConsoleBackend;
    use openxbdm_server::FileSystemBackend;
    use openxbdm_server::MemoryBackend;
    use openxbdm_server::ProcessBackend;
    use openxbdm_server::ProcessId;
    use openxbdm_server::ReadableMask;
    use openxbdm_server::ResponseSink;
    use openxbdm_server::Service;
    use openxbdm_server::SessionControl;
    use openxbdm_server::TransferCount;

    const XNCALLER_XBDM: u32 = 3;
    const AF_INET: u32 = 2;
    const SOCK_STREAM: u32 = 1;
    const IPPROTO_TCP: u32 = 6;
    const INVALID_SOCKET: u32 = u32::MAX;
    const SOCKET_ERROR: i32 = -1;
    const XBDM_PORT: u16 = 730;
    const COMMAND_CAPACITY: usize = 4096;
    const RECEIVE_CAPACITY: usize = 1024;
    const FEATURES: &[&str] = &["DEBUGGING", "OPENXBDM"];
    const DRIVES: &[&str] = &["HDD", "FLASH"];

    static SHUTDOWN: AtomicBool = AtomicBool::new(false);
    static THREAD_HANDLE: AtomicU32 = AtomicU32::new(0);
    static LISTENER_SOCKET: AtomicU32 = AtomicU32::new(INVALID_SOCKET);
    static CLIENT_SOCKET: AtomicU32 = AtomicU32::new(INVALID_SOCKET);

    // System callees home r3-r10 into the caller frame at sp+0x10..sp+0x50.
    // SysV frames do not reserve that area, so each import is called through
    // a stub that allocates it. Stack-passed arguments are not forwarded.
    macro_rules! import_thunk {
        ($(#[$meta:meta])* $name:ident($($arg:ident: $argty:ty),* $(,)?) -> $ret:ty, lib = $lib:expr, ordinal = $ordinal:expr) => {
            const _: () = assert!(<[&str]>::len(&[$(stringify!($arg)),*]) <= 8);

            $(#[$meta])*
            #[unsafe(naked)]
            #[unsafe(no_mangle)]
            pub extern "C" fn $name($(_: $argty),*) -> $ret {
                core::arch::naked_asm!(
                    "stwu 1, -0x50(1)",
                    "mflr 0",
                    "stw 0, 0x54(1)",
                    "bl 2f",
                    "lwz 0, 0x54(1)",
                    "mtlr 0",
                    "addi 1, 1, 0x50",
                    "blr",
                    ".pushsection .xthunks, \"ax\"",
                    ".balign 4",
                    "2:",
                    ".long {record}",
                    ".long 0x60000000",
                    ".long 0x60000000",
                    ".long 0x4e800020",
                    ".popsection",
                    record = const (1u32 << 24) | (($lib as u32) << 16) | ($ordinal as u32),
                )
            }
        };
    }

    import_thunk!(DbgPrint(format: *const core::ffi::c_char) -> u32, lib = 0, ordinal = 3);
    // Returns the address when the debugger may read it and null otherwise;
    // stock XBDM guards its reads with the same export.
    import_thunk!(DebugReadCheck(address: u32) -> u32, lib = 0, ordinal = 427);
    import_thunk!(
        ExCreateThread(
            handle_out: *mut u32,
            stack_size: u32,
            thread_id_out: *mut u32,
            xapi_thread_startup: u32,
            start_address: u32,
            start_context: u32,
            creation_flags: u32,
        ) -> u32,
        lib = 0,
        ordinal = 13
    );
    import_thunk!(ExTerminateThread(exit_code: u32) -> u32, lib = 0, ordinal = 25);
    import_thunk!(KeDelayExecutionThread(mode: u32, alertable: u32, interval: *const i64) -> u32, lib = 0, ordinal = 90);
    import_thunk!(NtClose(handle: u32) -> u32, lib = 0, ordinal = 207);
    import_thunk!(NtDeleteFile(object_attributes: *const ObjectAttributes) -> u32, lib = 0, ordinal = 216);
    import_thunk!(NetDll_XNetStartup(caller: u32, params: *const u8) -> i32, lib = 1, ordinal = 51);
    import_thunk!(NetDll_WSAStartup(caller: u32, version: u32, data: *mut u8) -> i32, lib = 1, ordinal = 1);
    import_thunk!(NetDll_socket(caller: u32, af: u32, ty: u32, protocol: u32) -> u32, lib = 1, ordinal = 3);
    import_thunk!(NetDll_closesocket(caller: u32, socket: u32) -> i32, lib = 1, ordinal = 4);
    import_thunk!(NetDll_bind(caller: u32, socket: u32, name: *const u8, name_len: i32) -> i32, lib = 1, ordinal = 11);
    import_thunk!(NetDll_listen(caller: u32, socket: u32, backlog: i32) -> i32, lib = 1, ordinal = 13);
    import_thunk!(NetDll_accept(caller: u32, socket: u32, name: *mut u8, name_len: *mut i32) -> u32, lib = 1, ordinal = 14);
    import_thunk!(NetDll_recv(caller: u32, socket: u32, buffer: *mut u8, length: i32, flags: i32) -> i32, lib = 1, ordinal = 18);
    import_thunk!(NetDll_send(caller: u32, socket: u32, buffer: *const u8, length: i32, flags: i32) -> i32, lib = 1, ordinal = 22);

    #[repr(C)]
    struct SockAddrIn {
        family: u16,
        port: u16,
        address: u32,
        zero: [u8; 8],
    }

    #[repr(C)]
    pub(crate) struct AnsiString {
        length: u16,
        maximum_length: u16,
        buffer: *const u8,
    }

    #[repr(C)]
    pub(crate) struct ObjectAttributes {
        root_directory: u32,
        object_name: *const AnsiString,
        attributes: u32,
    }

    struct Console;

    impl ConsoleBackend for Console {
        fn debug_name(&self) -> &str {
            "openxbdm-deanxbox"
        }

        fn set_debug_name(&mut self, _name: &str) -> Result<(), BackendError> {
            Err(BackendError::AccessDenied)
        }

        fn dm_version(&self) -> &str {
            "2.0.21256.0"
        }

        fn console_type(&self) -> &str {
            "DevKit"
        }

        fn console_features(&self) -> &[&str] {
            FEATURES
        }
    }

    impl FileSystemBackend for Console {
        fn drives(&self) -> &[&str] {
            DRIVES
        }

        fn delete_file(&mut self, path: &str) -> Result<(), BackendError> {
            if !path.eq_ignore_ascii_case(OVERRIDE_MODULE_XBDM_PATH) {
                return Err(BackendError::AccessDenied);
            }
            delete_override_module()
        }
    }

    impl MemoryBackend for Console {
        fn read_memory(&self, address: Address, output: &mut [u8]) -> Result<ReadableMask, BackendError> {
            const PAGE_SIZE: u32 = 0x1000;
            let mut bits = 0u64;
            let mut checked_page = None;
            for (index, byte) in output.iter_mut().enumerate().take(u64::BITS as usize) {
                let Some(current) = u32::try_from(index).ok().and_then(|offset| address.get().checked_add(offset))
                else {
                    break;
                };
                let page = current & !(PAGE_SIZE - 1);
                let readable = match checked_page {
                    Some((checked, readable)) if checked == page => readable,
                    _ => {
                        let readable = DebugReadCheck(page) != 0;
                        checked_page = Some((page, readable));
                        readable
                    }
                };
                if readable {
                    // The kernel reported the page readable for the debugger.
                    *byte = unsafe { core::ptr::read_volatile(current as usize as *const u8) };
                    bits |= 1u64 << index;
                }
            }
            if bits == 0 {
                return Err(BackendError::MemoryNotMapped);
            }
            Ok(ReadableMask::from_bits(bits))
        }

        fn write_memory(&mut self, _address: Address, _data: &[u8]) -> Result<TransferCount, BackendError> {
            Err(BackendError::Unavailable)
        }
    }

    impl ProcessBackend for Console {
        fn process_id(&self) -> ProcessId {
            ProcessId::new(2)
        }
    }

    // XAM loads xbdm.xex with the system-root-only flag. The kernel still
    // searches \FlashEx\ before \SystemRoot\ and accepts a module there whose
    // bounding path names that file, so this file replaces the flash XBDM
    // until it is removed.
    const OVERRIDE_MODULE_XBDM_PATH: &str = r"DEVKIT:\FlashEx\xbdm.xex";
    const OVERRIDE_REMOVAL_ATTEMPTS: u32 = 30;

    fn delete_override_module() -> Result<(), BackendError> {
        const PATH: &[u8] = br"\Device\Harddisk0\Partition1\DEVKIT\FlashEx\xbdm.xex";
        let name = AnsiString { length: PATH.len() as u16, maximum_length: PATH.len() as u16, buffer: PATH.as_ptr() };
        let attributes = ObjectAttributes { root_directory: 0, object_name: &name, attributes: 0x40 };
        let status = NtDeleteFile(&attributes);
        if status as i32 >= 0 {
            return Ok(());
        }
        match status {
            0xC000_000F | 0xC000_0034 | 0xC000_003A => Err(BackendError::NotFound),
            0xC000_0022 => Err(BackendError::AccessDenied),
            _ => Err(BackendError::Unavailable),
        }
    }

    #[derive(Clone, Copy)]
    struct SocketError;

    struct SocketSink {
        socket: u32,
    }

    impl SocketSink {
        fn write_status(&mut self, code: u16, message: &str) -> Result<(), SocketError> {
            let prefix = [
                b'0' + ((code / 100) % 10) as u8,
                b'0' + ((code / 10) % 10) as u8,
                b'0' + (code % 10) as u8,
                b'-',
                b' ',
            ];
            send_all(self.socket, &prefix)?;
            send_all(self.socket, message.as_bytes())?;
            send_all(self.socket, b"\r\n")
        }
    }

    impl ResponseSink for SocketSink {
        type Error = SocketError;

        fn single(&mut self, code: u16, message: &str) -> Result<(), Self::Error> {
            self.write_status(code, message)
        }

        fn multiline_start(&mut self, message: &str) -> Result<(), Self::Error> {
            self.write_status(202, message)
        }

        fn multiline_line(&mut self, line: &str) -> Result<(), Self::Error> {
            send_all(self.socket, line.as_bytes())?;
            send_all(self.socket, b"\r\n")
        }

        fn multiline_end(&mut self) -> Result<(), Self::Error> {
            self.multiline_line(".")
        }
    }

    fn send_all(socket: u32, mut bytes: &[u8]) -> Result<(), SocketError> {
        while !bytes.is_empty() {
            let count = NetDll_send(XNCALLER_XBDM, socket, bytes.as_ptr(), bytes.len() as i32, 0);
            if count <= 0 {
                return Err(SocketError);
            }
            bytes = &bytes[count as usize..];
        }
        Ok(())
    }

    fn close_tracked_socket(socket: &AtomicU32) {
        let handle = socket.swap(INVALID_SOCKET, Ordering::SeqCst);
        if handle != INVALID_SOCKET {
            NetDll_closesocket(XNCALLER_XBDM, handle);
        }
    }

    fn serve_client(socket: u32) {
        let mut sink = SocketSink { socket };
        if sink.single(201, "connected to openxbdm").is_err() {
            return;
        }

        let mut service = Service::new(Console);
        let mut command = [0u8; COMMAND_CAPACITY];
        let mut command_len = 0usize;
        let mut discarding = false;
        let mut receive = [0u8; RECEIVE_CAPACITY];

        while !SHUTDOWN.load(Ordering::SeqCst) {
            let count = NetDll_recv(XNCALLER_XBDM, socket, receive.as_mut_ptr(), receive.len() as i32, 0);
            if count <= 0 {
                return;
            }

            for &byte in &receive[..count as usize] {
                if byte == b'\n' {
                    if discarding {
                        if sink.single(400, "command exceeds protocol limit").is_err() {
                            return;
                        }
                    } else {
                        let line_len = command_len - usize::from(command_len > 0 && command[command_len - 1] == b'\r');
                        let Ok(line) = core::str::from_utf8(&command[..line_len]) else {
                            if sink.single(400, "invalid command encoding").is_err() {
                                return;
                            }
                            command_len = 0;
                            continue;
                        };
                        let control = match service.dispatch(line, &mut sink) {
                            Ok(control) => control,
                            Err(_) => return,
                        };
                        if control == SessionControl::Disconnect {
                            return;
                        }
                    }
                    command_len = 0;
                    discarding = false;
                } else if !discarding {
                    if command_len == command.len() {
                        discarding = true;
                    } else {
                        command[command_len] = byte;
                        command_len += 1;
                    }
                }
            }
        }
    }

    fn open_listener() -> Result<u32, ()> {
        let socket = NetDll_socket(XNCALLER_XBDM, AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if socket == INVALID_SOCKET {
            return Err(());
        }

        let address = SockAddrIn { family: AF_INET as u16, port: XBDM_PORT, address: 0, zero: [0; 8] };
        let bound = NetDll_bind(
            XNCALLER_XBDM,
            socket,
            &address as *const SockAddrIn as *const u8,
            core::mem::size_of::<SockAddrIn>() as i32,
        );
        if bound == SOCKET_ERROR || NetDll_listen(XNCALLER_XBDM, socket, 8) == SOCKET_ERROR {
            NetDll_closesocket(XNCALLER_XBDM, socket);
            return Err(());
        }
        Ok(socket)
    }

    fn initialize_network() -> Result<(), ()> {
        let mut startup = [0u8; 13];
        startup[0] = 0x0d;
        startup[1] = 0x81;
        startup[4] = 0x40;
        if NetDll_XNetStartup(XNCALLER_XBDM, startup.as_ptr()) != 0 {
            return Err(());
        }

        let mut wsa_data = [0u8; 512];
        if NetDll_WSAStartup(XNCALLER_XBDM, 2, wsa_data.as_mut_ptr()) != 0 {
            return Err(());
        }
        Ok(())
    }

    fn sleep_one_second() {
        let interval = -10_000_000i64;
        KeDelayExecutionThread(1, 0, &interval);
    }

    fn run_server() {
        while initialize_network().is_err() {
            if SHUTDOWN.load(Ordering::SeqCst) {
                return;
            }
            DbgPrint(c"openxbdm: network initialization failed\n".as_ptr());
            sleep_one_second();
        }

        while !SHUTDOWN.load(Ordering::SeqCst) {
            let Ok(listener) = open_listener() else {
                if SHUTDOWN.load(Ordering::SeqCst) {
                    return;
                }
                DbgPrint(c"openxbdm: listen failed\n".as_ptr());
                sleep_one_second();
                continue;
            };
            LISTENER_SOCKET.store(listener, Ordering::SeqCst);
            if SHUTDOWN.load(Ordering::SeqCst) {
                close_tracked_socket(&LISTENER_SOCKET);
                return;
            }
            DbgPrint(c"openxbdm: listening on TCP port 730\n".as_ptr());

            while !SHUTDOWN.load(Ordering::SeqCst) {
                let client = NetDll_accept(XNCALLER_XBDM, listener, core::ptr::null_mut(), core::ptr::null_mut());
                if client == INVALID_SOCKET {
                    break;
                }
                CLIENT_SOCKET.store(client, Ordering::SeqCst);
                if SHUTDOWN.load(Ordering::SeqCst) {
                    close_tracked_socket(&CLIENT_SOCKET);
                    break;
                }
                serve_client(client);
                close_tracked_socket(&CLIENT_SOCKET);
            }

            close_tracked_socket(&LISTENER_SOCKET);
            if !SHUTDOWN.load(Ordering::SeqCst) {
                sleep_one_second();
            }
        }
    }

    extern "C" fn server_thread(_context: u32) -> u32 {
        // A boot-time attempt left the file in place while a later delete
        // command removed it, so removal is retried before the listener starts.
        let mut removal = delete_override_module();
        for _ in 1..OVERRIDE_REMOVAL_ATTEMPTS {
            if matches!(removal, Ok(()) | Err(BackendError::NotFound)) || SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }
            sleep_one_second();
            removal = delete_override_module();
        }
        match removal {
            Ok(()) => DbgPrint(c"openxbdm: removed FlashEx override module\n".as_ptr()),
            Err(BackendError::NotFound) => DbgPrint(c"openxbdm: FlashEx override module is absent\n".as_ptr()),
            Err(_) => DbgPrint(c"openxbdm: failed to remove FlashEx override module\n".as_ptr()),
        };
        if !SHUTDOWN.load(Ordering::SeqCst) {
            run_server();
        }
        ExTerminateThread(0);
        loop {
            core::hint::spin_loop();
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn _start(_module: u32, reason: u32, _reserved: u32) -> u32 {
        match reason {
            0 => {
                SHUTDOWN.store(true, Ordering::SeqCst);
                close_tracked_socket(&CLIENT_SOCKET);
                close_tracked_socket(&LISTENER_SOCKET);
                let handle = THREAD_HANDLE.swap(0, Ordering::SeqCst);
                if handle != 0 {
                    NtClose(handle);
                }
                1
            }
            1 => {
                SHUTDOWN.store(false, Ordering::SeqCst);
                let mut handle = 0u32;
                let entry = server_thread as *const () as usize as u32;
                let status = ExCreateThread(&mut handle, 64 * 1024, core::ptr::null_mut(), 0, entry, 0, 0);
                if status as i32 >= 0 {
                    THREAD_HANDLE.store(handle, Ordering::SeqCst);
                    DbgPrint(c"openxbdm: server thread started\n".as_ptr());
                    1
                } else {
                    DbgPrint(c"openxbdm: server thread creation failed\n".as_ptr());
                    0
                }
            }
            _ => 1,
        }
    }

    #[panic_handler]
    fn panic(_info: &PanicInfo<'_>) -> ! {
        DbgPrint(c"openxbdm: panic\n".as_ptr());
        loop {
            sleep_one_second();
        }
    }
}
