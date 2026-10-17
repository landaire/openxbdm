//! `host`: act as the console's debugger host.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::client::Direction;
use crate::client::KdClient;
use crate::datagram_log::log_line;
use crate::datagram_log::open_log;
use crate::error::CliError;
use crate::error::ValueError;
use crate::host_files::FileMapping;
use crate::host_files::HostFiles;
use crate::parse::parse_hex;
use crate::parse::parse_u64;
use crate::print::hexdump;
use crate::print::print_stop_report;
use crate::transport::UdpTransport;

/// Fails unless every mapped local file can be opened.
pub fn check_host_files(files: &[FileMapping]) -> Result<(), Report<CliError>> {
    for mapping in files {
        File::open(&mapping.local_path)
            .map_err(CliError::from)
            .attach(format!(
                "local file for {}: {}",
                mapping.console_path,
                mapping.local_path.display()
            ))?;
    }

    Ok(())
}

/// Serves `files`, continues every event, and holds the load of each image
/// in `stop_on_load` while commands from standard input run. Received
/// datagrams are appended to `log_file` when given.
pub fn host(
    client: &mut KdClient<UdpTransport>,
    files: Vec<FileMapping>,
    stop_on_load: Vec<String>,
    log_file: Option<PathBuf>,
) -> Result<(), Report<CliError>> {
    client.set_host_files(HostFiles::new(files));
    client.set_hold_loads(stop_on_load);

    if let Some(path) = log_file {
        let mut log = open_log(path)?;
        let peer = client.transport().target();

        client.set_trace(Box::new(move |direction, datagram| {
            if direction == Direction::Received
                && let Err(error) = writeln!(log, "{}", log_line(peer, datagram))
            {
                tracing::warn!(%error, "log file write failed");
            }
        }));
    }

    let mut commands = None;
    loop {
        if !client
            .wait_for_stop(Duration::from_secs(1))
            .map_err(CliError::from)?
        {
            continue;
        }

        let Some(stop) = client.stop().cloned() else {
            continue;
        };

        match &stop.image {
            Some(image) => {
                println!(
                    "stopped at load of {} base {:#x} size {:#x}",
                    String::from_utf8_lossy(&image.name),
                    image.base,
                    image.size
                );
                println!("commands: mem ADDRESS [LENGTH], write ADDRESS HEXBYTES, continue");
                serve_commands(client, commands.get_or_insert_with(spawn_stdin_reader))?;
            }
            None => print_stop_report(&stop),
        }

        client.continue_from_stop().map_err(CliError::from)?;
        println!("continued");
    }
}

/// Runs commands while the console is stopped. Returns at `continue` or at
/// end of input. The kernel is serviced between commands.
fn serve_commands(
    client: &mut KdClient<UdpTransport>,
    commands: &mpsc::Receiver<String>,
) -> Result<(), Report<CliError>> {
    loop {
        let line = match commands.try_recv() {
            Ok(line) => line,
            Err(mpsc::TryRecvError::Empty) => {
                client
                    .service(Duration::from_millis(100))
                    .map_err(CliError::from)?;
                continue;
            }
            Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
        };

        let words: Vec<&str> = line.split_whitespace().collect();
        let outcome = match words.as_slice() {
            [] => Ok(()),
            ["continue"] => return Ok(()),
            ["mem", address] => command_mem(client, address, "64"),
            ["mem", address, length] => command_mem(client, address, length),
            ["write", address, bytes] => command_write(client, address, bytes),
            _ => Err(Report::new(CliError::UnrecognizedCommand {
                line: line.clone(),
            })),
        };

        if let Err(report) = outcome {
            println!("error: {report:?}");
        }
    }
}

fn command_mem(
    client: &mut KdClient<UdpTransport>,
    address: &str,
    length: &str,
) -> Result<(), Report<CliError>> {
    let address = parse_u64(address).map_err(CliError::from)?;
    let length = parse_u64(length).map_err(CliError::from)?;
    let length =
        usize::try_from(length).map_err(|error| CliError::from(ValueError::Length { error }))?;

    let mut bytes = vec![0u8; length];
    let read = client
        .read_memory(address, &mut bytes)
        .map_err(CliError::from)?;

    hexdump(address, &bytes[..read]);
    if read < length {
        println!("({read} of {length} bytes readable)");
    }

    Ok(())
}

fn command_write(
    client: &mut KdClient<UdpTransport>,
    address: &str,
    hex: &str,
) -> Result<(), Report<CliError>> {
    let address = parse_u64(address).map_err(CliError::from)?;
    let bytes = parse_hex(hex).map_err(CliError::from)?;

    client
        .write_memory(address, &bytes)
        .map_err(CliError::from)?;
    println!("wrote {} bytes at {address:#x}", bytes.len());

    Ok(())
}

/// Standard input lines. The reader thread ends at end of input.
fn spawn_stdin_reader() -> mpsc::Receiver<String> {
    let (sender, receiver) = mpsc::channel();

    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            let Ok(line) = line else { break };

            if sender.send(line).is_err() {
                break;
            }
        }
    });

    receiver
}
