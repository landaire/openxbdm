//! `listen`: log every datagram, decoded.

use std::io::Write;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::Duration;

use openxbdm_kd_core::packet::MAX_DATAGRAM_LEN;
use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::client::Direction;
use crate::client::KdClient;
use crate::datagram_log::log_line;
use crate::datagram_log::open_log;
use crate::describe::describe;
use crate::error::CliError;
use crate::print::print_stop_report;
use crate::transport::UdpTransport;

/// Prints every datagram in both directions and continues every stop.
/// Received datagrams are appended to `log_file` when given.
pub fn listen(
    client: &mut KdClient<UdpTransport>,
    log_file: Option<PathBuf>,
) -> Result<(), Report<CliError>> {
    let peer = client.transport().target();
    let mut log = log_file.map(open_log).transpose()?;

    client.set_trace(Box::new(move |direction, datagram| {
        let arrow = match direction {
            Direction::Sent => "->",
            Direction::Received => "<-",
        };
        println!("{arrow} {}", describe(datagram, direction));

        if let Some(log) = log.as_mut()
            && direction == Direction::Received
        {
            // Logging is best effort; the session continues without it.
            let _ = writeln!(log, "{}", log_line(peer, datagram));
        }
    }));

    loop {
        if !client
            .wait_for_stop(Duration::from_secs(1))
            .map_err(CliError::from)?
        {
            continue;
        }

        if let Some(stop) = client.stop() {
            print_stop_report(stop);
        }

        client.continue_from_stop().map_err(CliError::from)?;
    }
}

/// Receives and prints datagrams on `local` without sending.
pub fn listen_passive(
    local: SocketAddr,
    log_file: Option<PathBuf>,
) -> Result<(), Report<CliError>> {
    let socket = UdpSocket::bind(local)
        .map_err(CliError::from)
        .attach(format!("local {local}"))?;
    let mut log = log_file.map(open_log).transpose()?;
    let mut buffer = [0u8; MAX_DATAGRAM_LEN];

    loop {
        let (length, peer) = socket.recv_from(&mut buffer).map_err(CliError::from)?;
        let datagram = &buffer[..length];

        println!("<- {peer} {}", describe(datagram, Direction::Received));

        if let Some(log) = log.as_mut() {
            writeln!(log, "{}", log_line(peer, datagram)).map_err(CliError::from)?;
        }
    }
}
