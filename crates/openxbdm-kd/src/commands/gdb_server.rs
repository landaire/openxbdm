//! `gdbserver`: serve one GDB or LLDB client over TCP.

use std::net::SocketAddr;
use std::net::TcpListener;
use std::time::Duration;

use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::client::KdClient;
use crate::connection::stop_target;
use crate::error::CliError;
use crate::gdb;
use crate::gdb::KdTarget;
use crate::print::print_stop_report;
use crate::transport::UdpTransport;

/// Accepts one debugger on `listen`, serves it, then lets the console run.
pub fn gdb_server(
    mut client: KdClient<UdpTransport>,
    listen: SocketAddr,
) -> Result<(), Report<CliError>> {
    let listener = TcpListener::bind(listen)
        .map_err(CliError::from)
        .attach(format!("listen {listen}"))?;
    println!("waiting for a GDB client on {listen}");

    // Keep servicing the kernel while no debugger is attached.
    listener.set_nonblocking(true).map_err(CliError::from)?;
    let stream = loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                println!("debugger connected from {peer}");
                break stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if client
                    .wait_for_stop(Duration::from_millis(200))
                    .map_err(CliError::from)?
                {
                    client.continue_from_stop().map_err(CliError::from)?;
                }
            }
            Err(error) => return Err(Report::new(CliError::from(error))),
        }
    };
    stream.set_nonblocking(false).map_err(CliError::from)?;

    stop_target(&mut client)?;
    if let Some(stop) = client.stop() {
        print_stop_report(stop);
    }

    let mut target = KdTarget::new(client).map_err(CliError::from)?;
    let outcome = gdb::serve(&mut target, stream);
    let released = target.release();

    let reason = match outcome {
        Ok(reason) => reason,
        Err(error) => {
            released.map_err(CliError::from)?;
            return Err(Report::new(CliError::Gdb {
                message: error.to_string(),
            }));
        }
    };
    println!("debugger session ended: {reason:?}");

    released.map_err(CliError::from)?;
    println!("console resumed");

    Ok(())
}
