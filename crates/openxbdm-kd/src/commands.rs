//! Command-line subcommands.

mod gdb_server;
mod host;
mod listen;

use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::client::KdClient;
use crate::connection::stop_target;
use crate::error::CliError;
use crate::print::hexdump;
use crate::print::print_stop;
use crate::transport::UdpTransport;

pub use self::gdb_server::gdb_server;
pub use self::host::check_host_files;
pub use self::host::host;
pub use self::listen::listen;
pub use self::listen::listen_passive;

/// Stops the target, prints the stop, then continues.
pub fn break_in(
    client: &mut KdClient<UdpTransport>,
    stack_words: usize,
) -> Result<(), Report<CliError>> {
    stop_target(client)?;
    print_stop(client, stack_words)?;

    client.continue_from_stop().map_err(CliError::from)?;
    println!("continued");

    Ok(())
}

/// Stops the target, dumps `length` bytes at `address`, then continues.
pub fn memory(
    client: &mut KdClient<UdpTransport>,
    address: u64,
    length: u64,
) -> Result<(), Report<CliError>> {
    stop_target(client)?;

    let mut bytes = vec![0u8; length as usize];
    let read = client.read_memory(address, &mut bytes);

    // Continue before reporting a read failure so the console is not left stopped.
    let resumed = client.continue_from_stop();
    let read = read.map_err(CliError::from).attach("reading memory")?;
    resumed.map_err(CliError::from)?;

    hexdump(address, &bytes[..read]);
    if read < bytes.len() {
        println!("({read} of {} bytes readable)", bytes.len());
    }

    Ok(())
}

/// Stops the target and restarts the console.
pub fn reboot(client: &mut KdClient<UdpTransport>) -> Result<(), Report<CliError>> {
    stop_target(client)?;

    client.reboot().map_err(CliError::from)?;
    println!("reboot requested");

    Ok(())
}
