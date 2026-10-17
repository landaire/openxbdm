use crate::commands::network::WsaError;
use crate::commands::network::ipproxy::RegisterStatus;

/// The register or inject export of the network stack is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutineMissing;

/// The proxy socket could not be opened. The thread's last Winsock error
/// may be unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketFailed(pub Option<WsaError>);

/// The receive thread could not be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadFailed;

/// The step of `open_tunnel` that failed.
pub(super) enum TunnelError {
    Socket(SocketFailed),
    Register(RegisterStatus),
    Thread,
}
