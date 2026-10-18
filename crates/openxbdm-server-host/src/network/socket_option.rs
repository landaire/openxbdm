//! Socket options the host sets on accepted and connected sockets.

use std::io;
use std::net::TcpStream;

#[cfg(unix)]
mod keepalive {
    use std::net::TcpStream;
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn setsockopt(
            socket: std::ffi::c_int,
            level: std::ffi::c_int,
            name: std::ffi::c_int,
            value: *const std::ffi::c_void,
            length: u32,
        ) -> std::ffi::c_int;
    }

    /// 0 on success, -1 on failure.
    pub fn enable(stream: &TcpStream) -> std::ffi::c_int {
        #[cfg(target_os = "linux")]
        const SOL_SOCKET: std::ffi::c_int = 1;
        #[cfg(target_os = "linux")]
        const SO_KEEPALIVE: std::ffi::c_int = 9;
        #[cfg(not(target_os = "linux"))]
        const SOL_SOCKET: std::ffi::c_int = 0xffff;
        #[cfg(not(target_os = "linux"))]
        const SO_KEEPALIVE: std::ffi::c_int = 8;

        let enabled: std::ffi::c_int = 1;

        // SAFETY: `enabled` outlives the call and its size is passed.
        unsafe {
            setsockopt(
                stream.as_raw_fd(),
                SOL_SOCKET,
                SO_KEEPALIVE,
                (&enabled as *const std::ffi::c_int).cast(),
                size_of::<std::ffi::c_int>() as u32,
            )
        }
    }
}

#[cfg(windows)]
mod keepalive {
    use std::net::TcpStream;
    use std::os::windows::io::AsRawSocket;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(
            socket: usize,
            level: std::ffi::c_int,
            name: std::ffi::c_int,
            value: *const std::ffi::c_char,
            length: std::ffi::c_int,
        ) -> std::ffi::c_int;
    }

    /// 0 on success, SOCKET_ERROR (-1) on failure.
    pub fn enable(stream: &TcpStream) -> std::ffi::c_int {
        const SOL_SOCKET: std::ffi::c_int = 0xffff;
        const SO_KEEPALIVE: std::ffi::c_int = 8;

        let enabled: u32 = 1;

        // SAFETY: `enabled` outlives the call and its size is passed.
        unsafe {
            setsockopt(
                stream.as_raw_socket() as usize,
                SOL_SOCKET,
                SO_KEEPALIVE,
                (&enabled as *const u32).cast(),
                size_of::<u32>() as std::ffi::c_int,
            )
        }
    }
}

/// Enable TCP keep-alive probes on `stream`, so a peer that vanished
/// fails the socket.
pub fn set_keepalive(stream: &TcpStream) -> io::Result<()> {
    match keepalive::enable(stream) {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

/// The send buffer space at which `poll` reports a socket writable
/// (SO_SNDLOWAT). The engine sends at most `TRANSFER_CAPACITY` bytes per
/// writable report, so with that much free the send does not block while
/// the host lock is held. macOS defaults to 2048 bytes; Linux reports
/// writable only with a third of the buffer free and does not accept the
/// option, and Windows has no such option.
#[cfg(target_os = "macos")]
pub(super) fn reserve_send_space(stream: &TcpStream) {
    use std::os::fd::AsRawFd;

    use openxbdm_server::server::TRANSFER_CAPACITY;

    const SOL_SOCKET: std::ffi::c_int = 0xffff;
    const SO_SNDLOWAT: std::ffi::c_int = 0x1003;

    unsafe extern "C" {
        fn setsockopt(
            socket: std::ffi::c_int,
            level: std::ffi::c_int,
            name: std::ffi::c_int,
            value: *const std::ffi::c_void,
            length: u32,
        ) -> std::ffi::c_int;
    }

    let low_water =
        std::ffi::c_int::try_from(TRANSFER_CAPACITY).expect("TRANSFER_CAPACITY fits in c_int");

    // SAFETY: `low_water` outlives the call and its size is passed.
    // A failure leaves the default, under which a send may block.
    unsafe {
        setsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_SNDLOWAT,
            (&raw const low_water).cast(),
            size_of::<std::ffi::c_int>() as u32,
        );
    }
}

#[cfg(not(target_os = "macos"))]
pub(super) fn reserve_send_space(_stream: &TcpStream) {}

#[cfg(unix)]
mod send_buffer {
    use std::net::TcpStream;
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn getsockopt(
            socket: std::ffi::c_int,
            level: std::ffi::c_int,
            name: std::ffi::c_int,
            value: *mut std::ffi::c_void,
            length: *mut u32,
        ) -> std::ffi::c_int;
    }

    /// 0 on success, -1 on failure.
    pub fn query(stream: &TcpStream, size: &mut std::ffi::c_int) -> std::ffi::c_int {
        #[cfg(target_os = "linux")]
        const SOL_SOCKET: std::ffi::c_int = 1;
        #[cfg(target_os = "linux")]
        const SO_SNDBUF: std::ffi::c_int = 7;
        #[cfg(not(target_os = "linux"))]
        const SOL_SOCKET: std::ffi::c_int = 0xffff;
        #[cfg(not(target_os = "linux"))]
        const SO_SNDBUF: std::ffi::c_int = 0x1001;

        let mut length = size_of::<std::ffi::c_int>() as u32;

        // SAFETY: `size` and `length` outlive the call; `length` holds the
        // size of `size`.
        unsafe {
            getsockopt(
                stream.as_raw_fd(),
                SOL_SOCKET,
                SO_SNDBUF,
                (size as *mut std::ffi::c_int).cast(),
                &mut length,
            )
        }
    }
}

#[cfg(windows)]
mod send_buffer {
    use std::net::TcpStream;
    use std::os::windows::io::AsRawSocket;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn getsockopt(
            socket: usize,
            level: std::ffi::c_int,
            name: std::ffi::c_int,
            value: *mut std::ffi::c_char,
            length: *mut std::ffi::c_int,
        ) -> std::ffi::c_int;
    }

    /// 0 on success, SOCKET_ERROR (-1) on failure.
    pub fn query(stream: &TcpStream, size: &mut std::ffi::c_int) -> std::ffi::c_int {
        const SOL_SOCKET: std::ffi::c_int = 0xffff;
        const SO_SNDBUF: std::ffi::c_int = 0x1001;

        let mut length = size_of::<std::ffi::c_int>() as std::ffi::c_int;

        // SAFETY: `size` and `length` outlive the call; `length` holds the
        // size of `size`.
        unsafe {
            getsockopt(
                stream.as_raw_socket() as usize,
                SOL_SOCKET,
                SO_SNDBUF,
                (size as *mut std::ffi::c_int).cast(),
                &mut length,
            )
        }
    }
}

/// The platform send buffer size of `stream` (SO_SNDBUF).
pub(super) fn send_buffer_size(stream: &TcpStream) -> io::Result<u32> {
    let mut size: std::ffi::c_int = 0;
    match send_buffer::query(stream, &mut size) {
        0 => u32::try_from(size).map_err(|_| io::Error::from(io::ErrorKind::InvalidData)),
        _ => Err(io::Error::last_os_error()),
    }
}
