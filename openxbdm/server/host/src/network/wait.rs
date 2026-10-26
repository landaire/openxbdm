//! Readiness waits on a single socket.

use std::io;
use std::net::TcpStream;
use std::time::Duration;

#[cfg(unix)]
mod poll {
    use std::net::TcpStream;
    use std::os::fd::AsRawFd;

    #[repr(C)]
    struct PollFd {
        fd: std::ffi::c_int,
        events: std::ffi::c_short,
        revents: std::ffi::c_short,
    }

    pub const READABLE: std::ffi::c_short = 0x1;
    pub const WRITABLE: std::ffi::c_short = 0x4;

    #[cfg(target_os = "linux")]
    type PollCount = std::ffi::c_ulong;
    #[cfg(not(target_os = "linux"))]
    type PollCount = std::ffi::c_uint;

    unsafe extern "C" {
        fn poll(fds: *mut PollFd, count: PollCount, timeout: std::ffi::c_int) -> std::ffi::c_int;
    }

    /// `poll` for `events`: the number of ready sockets, or -1.
    pub fn wait(
        stream: &TcpStream,
        events: std::ffi::c_short,
        milliseconds: std::ffi::c_int,
    ) -> std::ffi::c_int {
        let mut entry = PollFd {
            fd: stream.as_raw_fd(),
            events,
            revents: 0,
        };

        // SAFETY: `entry` is one valid pollfd for the duration of the call.
        unsafe { poll(&mut entry, 1, milliseconds) }
    }
}

#[cfg(windows)]
mod poll {
    use std::net::TcpStream;
    use std::os::windows::io::AsRawSocket;

    #[repr(C)]
    struct WsaPollFd {
        fd: usize,
        events: std::ffi::c_short,
        revents: std::ffi::c_short,
    }

    /// POLLRDNORM and POLLWRNORM, which WinSock names POLLIN and POLLOUT.
    pub const READABLE: std::ffi::c_short = 0x100;
    pub const WRITABLE: std::ffi::c_short = 0x10;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAPoll(
            fds: *mut WsaPollFd,
            count: std::ffi::c_ulong,
            timeout: std::ffi::c_int,
        ) -> std::ffi::c_int;
    }

    /// `WSAPoll` for `events`: the number of ready sockets, or -1
    /// (SOCKET_ERROR, with the error in `GetLastError`).
    pub fn wait(
        stream: &TcpStream,
        events: std::ffi::c_short,
        milliseconds: std::ffi::c_int,
    ) -> std::ffi::c_int {
        let mut entry = WsaPollFd {
            fd: stream.as_raw_socket() as usize,
            events,
            revents: 0,
        };

        // SAFETY: `entry` is one valid WSAPOLLFD for the duration of the call.
        unsafe { WSAPoll(&mut entry, 1, milliseconds) }
    }
}

/// Wait up to `timeout` until `stream` can accept data or has failed.
/// `false` means the time ran out.
pub fn wait_writable(stream: &TcpStream, timeout: Duration) -> io::Result<bool> {
    wait(stream, poll::WRITABLE, timeout)
}

/// Wait up to `timeout` until `stream` has input, has been closed by the
/// peer, or has failed. `false` means the time ran out.
pub fn wait_readable(stream: &TcpStream, timeout: Duration) -> io::Result<bool> {
    wait(stream, poll::READABLE, timeout)
}

fn wait(stream: &TcpStream, events: std::ffi::c_short, timeout: Duration) -> io::Result<bool> {
    // Timeouts beyond the poll range wait the longest the range allows.
    let milliseconds =
        std::ffi::c_int::try_from(timeout.as_millis()).unwrap_or(std::ffi::c_int::MAX);

    match poll::wait(stream, events, milliseconds) {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(false),
        _ => Ok(true),
    }
}
