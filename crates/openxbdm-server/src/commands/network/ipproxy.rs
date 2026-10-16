//! `ipproxy`: tunnel the console's IP traffic to a host over UDP.

pub mod tunnel;

use core::num::NonZeroU32;

use openxbdm_core::status::ErrorCode;

use super::NetworkError;
use super::SystemVersion;
use super::WsaError;
use crate::invocation::Invocation;
use crate::network::Endpoint;
use crate::network::Ipv4Address;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// First system version with the packet intercept exports.
const IPPROXY_VERSION: SystemVersion = SystemVersion(0x201c_7d00);
/// Protocol version reported by `start`.
const VERSION: u32 = 1;

/// Global state of `ipproxy`; the proxy state lives in the backend, which
/// shares it with the packet hook and the receive thread.
#[derive(Debug)]
pub struct State {}

impl State {
    pub const fn new() -> Self {
        Self {}
    }
}

/// The register or inject export of the network stack is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutineMissing;

/// Nonzero result of the register routine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterStatus(NonZeroU32);

impl RegisterStatus {
    /// `None` for success.
    pub const fn new(status: u32) -> Option<Self> {
        match NonZeroU32::new(status) {
            Some(status) => Some(Self(status)),
            None => None,
        }
    }

    /// The result as `err=` reports it.
    pub const fn code(self) -> i32 {
        self.0.get() as i32
    }
}

/// The proxy socket could not be opened. The thread's last Winsock error
/// may be unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketFailed(pub Option<WsaError>);

/// The receive thread could not be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadFailed;

/// Platform services `ipproxy` needs.
pub trait Backend {
    /// Whether the register routine is held (stock 0x91f9f6a0 != 0).
    fn proxy_started(&mut self) -> bool;
    /// Resolve the register routine, then the inject routine. A missing
    /// inject routine leaves the register routine held.
    fn resolve_proxy_routines(&mut self) -> Result<(), RoutineMissing>;
    /// Drop both routines; the proxy no longer counts as started.
    fn release_proxy_routines(&mut self);
    /// Record `host` and reset the tunnel clocks, then open a UDP socket
    /// connected to `host`. The local endpoint is recorded from the socket
    /// port and the debug XNADDR address. On failure the socket is closed.
    fn open_proxy_socket(&mut self, host: Endpoint) -> Result<(), SocketFailed>;
    fn close_proxy_socket(&mut self);
    /// Local endpoint recorded by the last [`Backend::open_proxy_socket`].
    fn proxy_local_endpoint(&mut self) -> Endpoint;
    /// Let tunnel traffic pass the network simulator unchanged (stock
    /// 0x91f8c6a0 on the simulator instance, if one exists).
    fn set_proxy_bypass(&mut self, active: bool);
    /// Register the outbound packet hook: `register(2, {0x10, 0x5a7,
    /// context, hook}, 1)`.
    fn install_proxy_hook(&mut self) -> Result<(), RegisterStatus>;
    /// Unregister the outbound packet hook: `register(2, NULL, 1)`.
    fn remove_proxy_hook(&mut self) -> Result<(), RegisterStatus>;
    fn start_proxy_thread(&mut self) -> Result<(), ThreadFailed>;
    /// Close the socket, wait for the receive thread to end, and release
    /// its handle.
    fn stop_proxy_thread(&mut self);
}

/// `ipproxy start ver=<dword> addr=<dword> port=<dword>` or `ipproxy stop`.
pub(super) fn ipproxy(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.line.has("start") {
        start(invocation)
    } else if invocation.line.has("stop") {
        stop(invocation)
    } else {
        Err(ErrorCode::BadParameter.into())
    }
}

fn start(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line;
    // Absent and unparsable values read as 0, which is rejected.
    let value = |name| line.dword(name).filter(|&value| value != 0);
    let (Some(_version), Some(address), Some(port)) = (value("ver"), value("addr"), value("port"))
    else {
        return Err(ErrorCode::BadParameter.into());
    };
    let Ok(port) = u16::try_from(port) else {
        return Err(ErrorCode::BadParameter.into());
    };
    let backend = &mut *invocation.backend;
    if backend.proxy_started() {
        return Err(ErrorCode::FileAlreadyExists.into());
    }
    if backend.system_version() < IPPROXY_VERSION {
        return Err(ErrorCode::UnknownCommand.into());
    }
    if backend.resolve_proxy_routines().is_err() {
        return Err(ErrorCode::AccessDenied.into());
    }
    let host = Endpoint {
        address: Ipv4Address(address.to_be_bytes()),
        port,
    };
    let error = match open_tunnel(backend, host) {
        Err(TunnelError::Socket(SocketFailed(Some(error)))) => error.code(),
        Err(TunnelError::Register(status)) => status.code(),
        Err(TunnelError::Thread) => WsaError::NO_BUFFERS.code(),
        // Stock tests the error code, not the failed step: a socket
        // failure with last error 0 reports success and stays started.
        Ok(()) | Err(TunnelError::Socket(SocketFailed(None))) => {
            let local = backend.proxy_local_endpoint();
            invocation.set_text(format_args!(
                "started ver={VERSION} addr=0x{:08x} port=0x{:04x}",
                u32::from_be_bytes(local.address.octets()),
                local.port
            ));
            return Ok(Reply::Ok);
        }
    };
    backend.release_proxy_routines();
    invocation.set_text(format_args!("err={error}"));
    Err(ErrorCode::Undefined.into())
}

/// The step of [`open_tunnel`] that failed.
enum TunnelError {
    Socket(SocketFailed),
    Register(RegisterStatus),
    Thread,
}

/// Open the socket, install the hook, and start the receive thread,
/// undoing the earlier steps when one fails.
fn open_tunnel(backend: &mut (impl Backend + ?Sized), host: Endpoint) -> Result<(), TunnelError> {
    backend
        .open_proxy_socket(host)
        .map_err(TunnelError::Socket)?;
    backend.set_proxy_bypass(true);
    if let Err(status) = backend.install_proxy_hook() {
        backend.set_proxy_bypass(false);
        backend.close_proxy_socket();
        return Err(TunnelError::Register(status));
    }
    if backend.start_proxy_thread().is_err() {
        backend.set_proxy_bypass(false);
        // Stock ignores the result of unregistering here.
        let _ = backend.remove_proxy_hook();
        backend.close_proxy_socket();
        return Err(TunnelError::Thread);
    }
    Ok(())
}

fn stop(invocation: &mut Invocation<'_>) -> CommandResult {
    let backend = &mut *invocation.backend;
    if !backend.proxy_started() {
        return Err(NetworkError::ProxyNotStarted.into());
    }
    if let Err(status) = backend.remove_proxy_hook() {
        invocation.set_text(format_args!("err={}", status.code()));
        return Err(ErrorCode::Undefined.into());
    }
    backend.stop_proxy_thread();
    backend.release_proxy_routines();
    backend.set_proxy_bypass(false);
    invocation.set_text(format_args!("stopped"));
    Ok(Reply::Ok)
}
