//! Connecting to the target and bringing it to a stop.

use std::net::SocketAddr;
use std::time::Duration;

use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::client::KdClient;
use crate::error::CliError;
use crate::print::print_notification;
use crate::transport::UdpTransport;

/// Binds `local` and connects to `target`, or to the first target whose
/// beacon arrives when `target` is `None`. Notifications are printed.
pub fn connect(
    target: Option<SocketAddr>,
    local: SocketAddr,
) -> Result<KdClient<UdpTransport>, Report<CliError>> {
    // The kernel sends a beacon every 3 s.
    const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

    let transport = match target {
        Some(target) => UdpTransport::bind(local, target),
        None => UdpTransport::discover(local, DISCOVERY_TIMEOUT),
    }
    .map_err(CliError::from)
    .attach(format!("local {local}"))?;
    tracing::info!(target = %transport.target(), "connected");

    let mut client = KdClient::new(transport);
    client.set_notify(Box::new(print_notification));

    Ok(client)
}

/// Breaks in unless the kernel already waits in a stop. A break-in
/// request that reaches a stopped kernel is latched (0x802196a7) and stops
/// it again right after the next continue, so the kernel's own
/// retransmissions are awaited first.
pub(crate) fn stop_target(client: &mut KdClient<UdpTransport>) -> Result<(), Report<CliError>> {
    const BREAK_IN_TIMEOUT: Duration = Duration::from_secs(10);
    const BREAK_IN_RETRY: Duration = Duration::from_secs(2);
    // Longer than the kernel retransmission interval (0.5 s).
    const PENDING_STOP_WAIT: Duration = Duration::from_millis(1200);

    if client
        .wait_for_stop(PENDING_STOP_WAIT)
        .map_err(CliError::from)?
    {
        return Ok(());
    }

    let mut waited = Duration::ZERO;
    while waited < BREAK_IN_TIMEOUT {
        client.break_in().map_err(CliError::from)?;

        if client
            .wait_for_stop(BREAK_IN_RETRY)
            .map_err(CliError::from)?
        {
            return Ok(());
        }

        waited += BREAK_IN_RETRY;
    }

    Err(Report::new(CliError::NoStop {
        seconds: BREAK_IN_TIMEOUT.as_secs(),
    }))
}
