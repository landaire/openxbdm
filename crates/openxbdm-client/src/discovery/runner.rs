//! Tokio driver around the sans-io [`Discovery`](super::Discovery)
//! state machine.
//!
//! The state machine handles every protocol-level concern -- when to
//! send, when to retransmit, when to stop, dedup, parsing. This module
//! only provides the I/O primitives the machine asks for: a UDP socket
//! to send through, a `recv_from` to feed inbound datagrams in, and a
//! `tokio::time::sleep_until` for the wait-until intervals.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Instant;

use rootcause::Report;
use rootcause::prelude::ResultExt;
use tokio::net::UdpSocket;

use crate::discovery::engine::Discovery;
use crate::discovery::engine::DiscoveryAction;
use crate::discovery::engine::DiscoveryConfig;
use crate::discovery::wire::DiscoveredConsole;
use crate::error::Error;
use crate::error::TransportError;

/// Look up a specific name. Returns the first matching reply, or `None`
/// if no console answers within `config.listen_for`.
pub async fn find_by_name(
    name: &str,
    config: DiscoveryConfig,
) -> Result<Option<DiscoveredConsole>, Report<Error>> {
    let engine = Discovery::lookup(name, config.clone(), Instant::now()).map_err(|e| {
        Report::new(Error::from(TransportError::ConnectTimeout))
            .attach(format!("nap encode error: {e}"))
    })?;

    let results = drive(engine, config).await?;

    Ok(results.into_iter().next())
}

/// Ask every console on the segment to identify itself. Collects
/// replies until the deadline; duplicates by source address are
/// dropped.
pub async fn discover_all(
    config: DiscoveryConfig,
) -> Result<Vec<DiscoveredConsole>, Report<Error>> {
    let engine = Discovery::broadcast(config.clone(), Instant::now());

    drive(engine, config).await
}

async fn drive(
    mut engine: Discovery,
    config: DiscoveryConfig,
) -> Result<Vec<DiscoveredConsole>, Report<Error>> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .await
        .map_err(Error::from)
        .into_report()
        .attach("binding udp socket for nap discovery")?;
    if config.broadcast {
        socket
            .set_broadcast(true)
            .map_err(Error::from)
            .into_report()
            .attach("enabling SO_BROADCAST")?;
    }

    tracing::debug!(
        target = %config.destination,
        "nap discovery start"
    );

    let mut buf = [0u8; 1024];

    loop {
        match engine.poll(Instant::now()) {
            DiscoveryAction::Done(consoles) => return Ok(consoles),
            DiscoveryAction::SendDatagram { dest, payload } => {
                tracing::debug!(target = %dest, bytes = payload.len(), "nap send");
                if let Err(e) = socket.send_to(&payload, dest).await {
                    // UDP sends rarely fail; when they do, log and let
                    // the engine schedule the next retransmit (or hit
                    // the deadline) rather than aborting outright.
                    tracing::debug!(error = %e, "nap send failed (continuing)");
                }
            }
            DiscoveryAction::Wait { until } => {
                let until = tokio::time::Instant::from_std(until);
                match tokio::time::timeout_at(until, socket.recv_from(&mut buf)).await {
                    // The timer fired; poll the engine again.
                    Err(_) => {}
                    Ok(Err(e)) => {
                        tracing::debug!(error = %e, "nap recv_from error (continuing)");
                    }
                    Ok(Ok((len, src))) => engine.handle_inbound(src, &buf[..len]),
                }
            }
        }
    }
}
