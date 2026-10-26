//! `openxbdm-kd`: kernel debugger client for the Xbox 360 kdnet transport.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use clap::Subcommand;
use openxbdm_kd::commands;
use openxbdm_kd::connection::connect;
use openxbdm_kd::error::CliError;
use openxbdm_kd::host_files::FileMapping;
use openxbdm_kd::parse::parse_target;
use openxbdm_kd::parse::parse_u64;
use rootcause::Report;

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
    /// Wait indefinitely when discovering a target from its kdnet beacon.
    #[arg(long)]
    no_timeout: bool,
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
    /// Every processor is a thread; debug output and module loads go to
    /// the debugger console.
    Gdbserver {
        /// TCP address to accept the debugger on.
        #[arg(long, default_value = "127.0.0.1:2159")]
        listen: SocketAddr,
        /// Register width to describe. Use `32` with GDB and an ELF
        /// compiled as 32-bit PowerPC, such as a rust-xbox360 title.
        #[arg(long, value_enum, default_value = "64")]
        registers: commands::RegisterWidth,
        /// Stop the console at the load of this image (for example
        /// `debugprobe.xex`), after it is mapped and before its entry point
        /// runs. The stop waits for the debugger if none is attached.
        #[arg(long, value_name = "IMAGE_NAME")]
        stop_on_load: Vec<String>,
        /// Keep the attachment stop while waiting for the debugger instead
        /// of resuming the console until the debugger connects.
        #[arg(long)]
        stop_on_connect: bool,
        /// Launch GDB with this command file after the listener and target
        /// stop are ready. GDB output uses this process's standard streams.
        #[arg(long, value_name = "FILE")]
        gdb_command: Option<PathBuf>,
        /// GDB executable used with `--gdb-command`.
        #[arg(long, default_value = "gdb")]
        gdb: PathBuf,
    },
    /// Record every mapped kernel function entered before an image loads.
    FunctionTrace {
        /// Lines of `ADDRESS NAME`, one function entry per line.
        #[arg(long, value_name = "FILE")]
        points: PathBuf,
        /// Tab-separated function-entry trace to write.
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
        /// Stop tracing when this image's load-symbols event arrives.
        #[arg(long, default_value = "xshell.xex", value_name = "IMAGE_NAME")]
        until_load: String,
        /// Reboot through KD before attaching the tracer to the fresh kernel.
        #[arg(long)]
        reboot_first: bool,
        /// Record only the first execution of each function.
        #[arg(long)]
        once: bool,
    },
    /// Act as the console's debugger host: acknowledge and continue every
    /// event, print debug output and module loads, and answer the kernel's
    /// host file requests. Unmapped paths are answered as not found, so the
    /// kernel opens them from its own devices.
    Host {
        /// Serve a console path from a local file, `CONSOLE_PATH=LOCAL_PATH`.
        /// The console path is the path the kernel requests, for example
        /// `host:\Device\Flash\xbdm.xex`, compared case-insensitively.
        #[arg(long = "file", value_name = "CONSOLE_PATH=LOCAL_PATH", value_parser = FileMapping::parse)]
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

fn run(cli: Cli) -> Result<(), Report<CliError>> {
    match cli.command {
        Command::Listen {
            passive: true,
            log_file,
        } => commands::listen_passive(cli.local, log_file),
        Command::Listen {
            passive: false,
            log_file,
        } => {
            let mut client = connect(cli.target, cli.local, cli.no_timeout)?;
            commands::listen(&mut client, log_file)
        }
        Command::Break { stack_words } => {
            let mut client = connect(cli.target, cli.local, cli.no_timeout)?;
            commands::break_in(&mut client, stack_words)
        }
        Command::Mem { address, length } => {
            let mut client = connect(cli.target, cli.local, cli.no_timeout)?;
            commands::memory(&mut client, address, length)
        }
        Command::Gdbserver {
            listen,
            registers,
            stop_on_load,
            stop_on_connect,
            gdb_command,
            gdb,
        } => {
            let debugger = gdb_command.map(|commands| commands::DebuggerCommand {
                program: gdb,
                commands,
            });
            let client = connect(cli.target, cli.local, cli.no_timeout)?;
            commands::gdb_server(
                client,
                listen,
                registers,
                stop_on_load,
                stop_on_connect,
                debugger,
            )
        }
        Command::FunctionTrace {
            points,
            output,
            until_load,
            reboot_first,
            once,
        } => {
            if reboot_first {
                {
                    let mut client = connect(cli.target, cli.local, cli.no_timeout)?;
                    commands::reboot_for_reconnect(&mut client)?;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            let mut client = connect(cli.target, cli.local, cli.no_timeout)?;
            commands::function_trace(&mut client, points, output, until_load, once)
        }
        Command::Host {
            files,
            stop_on_load,
            log_file,
        } => {
            commands::check_host_files(&files)?;
            let mut client = connect(cli.target, cli.local, cli.no_timeout)?;
            commands::host(&mut client, files, stop_on_load, log_file)
        }
        Command::Reboot => {
            let mut client = connect(cli.target, cli.local, cli.no_timeout)?;
            commands::reboot(&mut client)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // An invalid filter falls back to the default level rather than
    // refusing to start.
    let filter = tracing_subscriber::EnvFilter::try_new(&cli.log)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
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
