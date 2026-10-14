//! `openxbdm-kd`: kernel debugger client for the Xbox 360 kdnet transport.

use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

use clap::Parser;
use clap::Subcommand;
use openxbdm_kd::FileOpenAnswer;
use openxbdm_kd::KdClient;
use openxbdm_kd::KdError;
use openxbdm_kd::Notification;
use openxbdm_kd::StopReport;
use openxbdm_kd::client::Direction;
use openxbdm_kd::describe::describe;
use openxbdm_kd::gdb;
use openxbdm_kd::gdb::KdTarget;
use openxbdm_kd::host_files::FileMapping;
use openxbdm_kd::host_files::HostFiles;
use openxbdm_kd::transport::DEFAULT_PORT;
use openxbdm_kd::transport::UdpTransport;
use openxbdm_kd_core::context::Context;
use openxbdm_kd_core::context::Gpr;
use openxbdm_kd_core::packet::MAX_DATAGRAM_LEN;
use rootcause::prelude::*;

/// Time to wait for a beacon when the target address is not given; the
/// kernel sends one every 3 s.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const BREAK_IN_TIMEOUT: Duration = Duration::from_secs(10);
const BREAK_IN_RETRY: Duration = Duration::from_secs(2);
/// Longer than the kernel retransmission interval (0.5 s).
const PENDING_STOP_WAIT: Duration = Duration::from_millis(1200);

#[derive(Parser)]
#[command(
    name = "openxbdm-kd",
    version,
    about = "Xbox 360 kernel debugger client (kdnet)"
)]
struct Cli {
    /// kdnet target address, `IP` or `IP:PORT`. Learned from the target's
    /// beacon when omitted.
    #[arg(long, short = 't', env = "OPENXBDM_KD_TARGET", value_parser = parse_target)]
    target: Option<SocketAddr>,
    /// Local UDP address. The port must equal the host port in the kdnet
    /// settings; the kernel drops datagrams from any other port.
    #[arg(long, default_value = "0.0.0.0:50000")]
    local: SocketAddr,
    /// tracing filter, for example `debug` or `openxbdm_kd=trace`.
    #[arg(long, default_value = "info")]
    log: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log every datagram, decoded. Acknowledges and continues kernel
    /// events unless `--passive`.
    Listen {
        /// Only receive; never send.
        #[arg(long)]
        passive: bool,
        /// Append `unix-time peer length hex` lines for every datagram.
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Break in, print the stop, registers and stack, then continue.
    Break {
        /// Words to print from the stack pointer.
        #[arg(long, default_value_t = 16)]
        stack_words: usize,
    },
    /// Break in, read memory, then continue.
    Mem {
        /// Virtual address (hex with 0x prefix, or decimal).
        #[arg(value_parser = parse_u64)]
        address: u64,
        /// Byte count.
        #[arg(value_parser = parse_u64, default_value = "64")]
        length: u64,
    },
    /// Serve one GDB or LLDB client over the GDB remote serial protocol.
    Gdbserver {
        /// TCP address to accept the debugger on.
        #[arg(long, default_value = "127.0.0.1:2159")]
        listen: SocketAddr,
    },
    /// Act as the console's debugger host: acknowledge and continue every
    /// event, print debug output and module loads, and answer the kernel's
    /// host file requests. Unmapped paths are answered as not found, so the
    /// kernel opens them from its own devices.
    Host {
        /// Serve a console path from a local file, `CONSOLE_PATH=LOCAL_PATH`.
        /// The console path is the path the kernel requests, for example
        /// `host:\Device\Flash\xbdm.xex`, compared case-insensitively.
        #[arg(long = "file", value_name = "CONSOLE_PATH=LOCAL_PATH", value_parser = parse_file_mapping)]
        files: Vec<FileMapping>,
        /// Keep the console stopped at the load-symbols event of this image
        /// (for example `xbdm.xex`), before its entry point runs, and read
        /// commands from standard input: `mem ADDRESS [LENGTH]`,
        /// `write ADDRESS HEXBYTES`, `continue`. End of input continues.
        #[arg(long, value_name = "IMAGE_NAME")]
        stop_on_load: Vec<String>,
        /// Append `unix-time peer length hex` lines for every received
        /// datagram.
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Break in and restart the console.
    Reboot,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("kernel debugger")]
    Kd(#[from] KdError),
    #[error("I/O")]
    Io(#[from] std::io::Error),
    #[error("the kernel did not stop within {seconds} s")]
    NoStop { seconds: u64 },
    #[error("GDB session failed: {message}")]
    Gdb { message: String },
    #[error("{reason}")]
    InvalidCommand { reason: String },
}

fn parse_target(text: &str) -> Result<SocketAddr, String> {
    if let Ok(address) = text.parse::<SocketAddr>() {
        return Ok(address);
    }
    text.parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, DEFAULT_PORT))
        .map_err(|error| format!("{text:?} is not an address: {error}"))
}

fn parse_file_mapping(text: &str) -> Result<FileMapping, String> {
    let Some((console_path, local_path)) = text.split_once('=') else {
        return Err(format!("{text:?} is not CONSOLE_PATH=LOCAL_PATH"));
    };
    if console_path.is_empty() || local_path.is_empty() {
        return Err(format!("{text:?} has an empty path"));
    }
    Ok(FileMapping {
        console_path: console_path.to_owned(),
        local_path: PathBuf::from(local_path),
    })
}

fn parse_u64(text: &str) -> Result<u64, String> {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|error| format!("{text:?}: {error}"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cli.log)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(report) => {
            eprintln!("error: {report:?}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Report<CliError>> {
    match cli.command {
        Command::Listen {
            passive: true,
            log_file,
        } => listen_passive(cli.local, log_file),
        Command::Listen {
            passive: false,
            log_file,
        } => {
            let mut client = connect(&cli.target, cli.local)?;
            listen(&mut client, log_file)
        }
        Command::Break { stack_words } => {
            let mut client = connect(&cli.target, cli.local)?;
            stop_target(&mut client)?;
            print_stop(&mut client, stack_words)?;
            client.continue_from_stop().map_err(CliError::from)?;
            println!("continued");
            Ok(())
        }
        Command::Mem { address, length } => {
            let mut client = connect(&cli.target, cli.local)?;
            stop_target(&mut client)?;
            let mut bytes = vec![0u8; length as usize];
            let read = client.read_memory(address, &mut bytes);
            let resumed = client.continue_from_stop();
            let read = read.map_err(CliError::from).attach("reading memory")?;
            resumed.map_err(CliError::from)?;
            hexdump(address, &bytes[..read]);
            if read < bytes.len() {
                println!("({read} of {} bytes readable)", bytes.len());
            }
            Ok(())
        }
        Command::Gdbserver { listen } => {
            let client = connect(&cli.target, cli.local)?;
            gdbserver(client, listen)
        }
        Command::Host {
            files,
            stop_on_load,
            log_file,
        } => {
            for mapping in &files {
                File::open(&mapping.local_path)
                    .map_err(CliError::from)
                    .attach(format!(
                        "local file for {}: {}",
                        mapping.console_path,
                        mapping.local_path.display()
                    ))?;
            }
            let mut client = connect(&cli.target, cli.local)?;
            client.set_host_files(HostFiles::new(files));
            client.set_hold_loads(stop_on_load);
            if let Some(path) = log_file {
                let mut log = open_log(path)?;
                let peer = client_target(&client);
                client.set_trace(Box::new(move |direction, datagram| {
                    if direction == Direction::Received
                        && let Err(error) = writeln!(log, "{}", log_line(peer, datagram))
                    {
                        tracing::warn!(%error, "log file write failed");
                    }
                }));
            }
            host(&mut client)
        }
        Command::Reboot => {
            let mut client = connect(&cli.target, cli.local)?;
            stop_target(&mut client)?;
            client.reboot().map_err(CliError::from)?;
            println!("reboot requested");
            Ok(())
        }
    }
}

fn connect(
    target: &Option<SocketAddr>,
    local: SocketAddr,
) -> Result<KdClient<UdpTransport>, Report<CliError>> {
    let transport = match target {
        Some(target) => UdpTransport::bind(local, *target),
        None => UdpTransport::discover(local, DISCOVERY_TIMEOUT),
    }
    .map_err(CliError::from)
    .attach(format!("local {local}"))?;
    tracing::info!(target = %transport.target(), "connected");
    let mut client = KdClient::new(transport);
    client.set_notify(Box::new(print_notification));
    Ok(client)
}

fn print_notification(notification: Notification<'_>) {
    match notification {
        Notification::Print(text) => print!("{}", String::from_utf8_lossy(text)),
        Notification::Prompt(text) => {
            println!("prompt (answered empty): {}", String::from_utf8_lossy(text))
        }
        Notification::LoadSymbols {
            path,
            base,
            size,
            unload,
        } => println!(
            "{} {} at {base:#x} size {size:#x}",
            if unload { "unload" } else { "load" },
            String::from_utf8_lossy(path)
        ),
        Notification::FileOpen { path, answer } => match answer {
            FileOpenAnswer::Served { local_path, size } => {
                println!(
                    "file open {path}: served from {} ({size} bytes)",
                    local_path.display()
                )
            }
            FileOpenAnswer::NotMapped => {
                println!("file open {path}: not mapped, answered not found")
            }
            FileOpenAnswer::Failed { local_path } => {
                println!(
                    "file open {path}: {} cannot be opened, answered not found",
                    local_path.display()
                )
            }
        },
        Notification::FileClosed {
            console_path,
            bytes_served,
        } => {
            println!("file close {console_path}: {bytes_served} bytes served")
        }
        Notification::Beacon(_) => {}
    }
}

/// Breaks in unless the kernel already waits in a stop. A break-in
/// request that reaches a stopped kernel is latched (0x802196a7) and stops
/// it again right after the next continue, so the kernel's own
/// retransmissions are awaited first.
fn stop_target(client: &mut KdClient<UdpTransport>) -> Result<(), Report<CliError>> {
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

fn print_stop(
    client: &mut KdClient<UdpTransport>,
    stack_words: usize,
) -> Result<(), Report<CliError>> {
    let Some(stop) = client.stop().cloned() else {
        return Err(Report::new(CliError::Kd(KdError::NotStopped)));
    };
    print_stop_report(&stop);
    let version = client.version().map_err(CliError::from)?;
    println!(
        "kernel build {} protocol {} base {:#x}",
        version.minor, version.protocol_version, version.kernel_base
    );
    let context = client
        .read_context(stop.processor)
        .map_err(CliError::from)?;
    print_registers(&context);
    let Some(sp_register) = Gpr::new(1) else {
        unreachable!("r1 is a valid register")
    };
    let sp = context.gpr(sp_register) as u32;
    let mut stack = vec![0u8; stack_words * 4];
    let read = client
        .read_memory(u64::from(sp), &mut stack)
        .map_err(CliError::from)?;
    println!("stack at {sp:#010x}:");
    for (index, word) in stack[..read].as_chunks::<4>().0.iter().enumerate() {
        let value = u32::from_be_bytes(*word);
        if index.is_multiple_of(4) {
            print!("  {:08x}:", sp as usize + index * 4);
        }
        print!(" {value:08x}");
        if index % 4 == 3 {
            println!();
        }
    }
    if !(read / 4).is_multiple_of(4) {
        println!();
    }
    Ok(())
}

fn print_stop_report(stop: &StopReport) {
    println!(
        "stopped: processor {} of {}, thread {:#x}, pc {:#010x}",
        stop.processor.0,
        stop.number_processors,
        stop.thread,
        stop.pc()
    );
    if let Some(exception) = stop.exception {
        println!(
            "exception {} at {:#x}, {} chance, parameters {:x?}",
            exception.record.code,
            exception.record.address,
            if exception.first_chance {
                "first"
            } else {
                "second"
            },
            &exception.record.information[..(exception.record.number_parameters as usize).min(15)]
        );
    }
    let stream = &stop.control_report.instruction_stream;
    println!(
        "instructions at pc: {}",
        stream
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| format!("{:08x}", u32::from_be_bytes(*word)))
            .collect::<Vec<_>>()
            .join(" ")
    );
}

fn print_registers(context: &Context) {
    for row in 0..8u8 {
        let mut line = String::new();
        for column in 0..4u8 {
            let index = row + column * 8;
            let Some(register) = Gpr::new(index) else {
                unreachable!("index below 32")
            };
            line.push_str(&format!("r{index:<2} {:016x}  ", context.gpr(register)));
        }
        println!("{}", line.trim_end());
    }
    println!(
        "pc  {:08x}  msr {:08x}  lr  {:08x}  ctr {:016x}  cr {:08x}  xer {:08x}",
        context.iar(),
        context.msr(),
        context.lr(),
        context.ctr(),
        context.cr(),
        context.xer()
    );
}

fn hexdump(address: u64, bytes: &[u8]) {
    for (index, line) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = line.iter().map(|byte| format!("{byte:02x}")).collect();
        let text: String = line
            .iter()
            .map(|&byte| {
                if byte.is_ascii_graphic() || byte == b' ' {
                    byte as char
                } else {
                    '.'
                }
            })
            .collect();
        println!(
            "{:08x}  {:<47}  {text}",
            address + (index * 16) as u64,
            hex.join(" ")
        );
    }
}

fn log_line(peer: SocketAddr, datagram: &[u8]) -> String {
    let now = jiff::Timestamp::now();
    let hex: String = datagram.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}.{:03} {peer} {} {hex}",
        now.as_second(),
        now.subsec_millisecond(),
        datagram.len()
    )
}

fn listen(
    client: &mut KdClient<UdpTransport>,
    log_file: Option<PathBuf>,
) -> Result<(), Report<CliError>> {
    let peer = client_target(client);
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
            let _ = writeln!(log, "{}", log_line(peer, datagram));
        }
    }));
    loop {
        if client
            .wait_for_stop(Duration::from_secs(1))
            .map_err(CliError::from)?
        {
            if let Some(stop) = client.stop() {
                print_stop_report(stop);
            }
            client.continue_from_stop().map_err(CliError::from)?;
        }
    }
}

fn host(client: &mut KdClient<UdpTransport>) -> Result<(), Report<CliError>> {
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
            _ => Err(Report::new(CliError::InvalidCommand {
                reason: format!("unrecognized command {line:?}"),
            })),
        };
        if let Err(report) = outcome {
            println!("error: {report:?}");
        }
    }
}

fn invalid(reason: String) -> Report<CliError> {
    Report::new(CliError::InvalidCommand { reason })
}

fn command_mem(
    client: &mut KdClient<UdpTransport>,
    address: &str,
    length: &str,
) -> Result<(), Report<CliError>> {
    let address = parse_u64(address).map_err(invalid)?;
    let length = parse_u64(length).map_err(invalid)?;
    let length = usize::try_from(length).map_err(|error| invalid(error.to_string()))?;
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
    let address = parse_u64(address).map_err(invalid)?;
    let bytes = parse_hex(hex).map_err(invalid)?;
    client
        .write_memory(address, &bytes)
        .map_err(CliError::from)?;
    println!("wrote {} bytes at {address:#x}", bytes.len());
    Ok(())
}

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return Err(format!("{text:?} is not an even number of hex digits"));
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            text.get(index..index + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("{text:?} is not hex"))
        })
        .collect()
}

fn client_target(client: &KdClient<UdpTransport>) -> SocketAddr {
    client.transport().target()
}

fn open_log(path: PathBuf) -> Result<File, Report<CliError>> {
    File::options()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(CliError::from)
        .attach(format!("log file {}", path.display()))
}

fn listen_passive(local: SocketAddr, log_file: Option<PathBuf>) -> Result<(), Report<CliError>> {
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

fn gdbserver(
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
    match outcome {
        Ok(reason) => println!("debugger session ended: {reason:?}"),
        Err(error) => {
            released.map_err(CliError::from)?;
            return Err(Report::new(CliError::Gdb {
                message: error.to_string(),
            }));
        }
    }
    released.map_err(CliError::from)?;
    println!("console resumed");
    Ok(())
}
