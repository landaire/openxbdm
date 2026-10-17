mod args;
#[cfg(feature = "capture")]
mod capture;
#[cfg(feature = "dangerous")]
mod dangerous;
mod debug;
mod discovery;
mod file;
mod kd;
mod memory;
mod modules;
mod network;
mod parity;
mod perf;
#[cfg(feature = "capture")]
mod pix;
mod progress;
mod recording;
mod screenshot;
mod system;
mod ui;
#[cfg(feature = "capture")]
mod xbm;

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::MagicBoot;
use openxbdm_client::commands::Reboot;
use openxbdm_client::error::ArgumentError;
use openxbdm_client::error::Error;
use openxbdm_client::transport::RecordingTransport;
use openxbdm_client::transport::tokio::Target;
use openxbdm_client::transport::tokio::connect_target_timeout;
use rootcause::Report;

use crate::args::Cli;
use crate::args::Command;
#[cfg(feature = "dangerous")]
use crate::args::DangerousCommand;
use crate::ui::UiOptions;

async fn run(cli: Cli) -> Result<(), Report<Error>> {
    let ui = UiOptions {
        format: cli.format,
        no_progress: cli.no_progress,
        raw_bytes: cli.bytes,
    };

    // Discovery and `xbm` need no console connection.
    if let Command::Discover {
        listen_ms,
        broadcast,
    } = &cli.cmd
    {
        return discovery::discover(*listen_ms, broadcast.as_deref(), ui).await;
    }

    if let Command::Resolve { name, listen_ms } = &cli.cmd {
        return discovery::resolve(name, *listen_ms).await;
    }

    #[cfg(feature = "capture")]
    if let Command::Xbm(command) = &cli.cmd {
        return xbm::run(command);
    }

    let Some(host) = cli.host.as_deref() else {
        return Err(Report::new(Error::from(ArgumentError::EmptyFilename))
            .attach("--host is required for this subcommand"));
    };
    let target = Target::parse(host, cli.port);
    let conn_timeout = Duration::from_secs(cli.timeout);
    tracing::info!(target: "openxbdm_client", console = %target, "connecting");

    // These subcommands open their own connections (drivemap-enable
    // abandons one with a hung read; nand-dump may run enable first), so
    // they bypass the shared connection and are not recorded by --capture.
    #[cfg(feature = "dangerous")]
    if let Command::Dangerous(DangerousCommand::DrivemapEnable) = &cli.cmd {
        return dangerous::drivemap_enable(&target, conn_timeout).await;
    }

    #[cfg(feature = "dangerous")]
    if let Command::Dangerous(DangerousCommand::NandDump { output }) = &cli.cmd {
        return dangerous::nand_dump(&target, conn_timeout, output.as_deref(), ui).await;
    }

    #[cfg(feature = "capture")]
    if let Command::PixNotify { duration, log } = &cli.cmd {
        return pix::pix_notify(&target, conn_timeout, *duration, log.as_deref()).await;
    }

    #[cfg(feature = "capture")]
    if let Command::Capture {
        remote,
        size_limit_mb,
        duration,
        output_dir,
        no_conversion,
    } = &cli.cmd
    {
        let options = capture::CaptureOptions {
            remote: remote.clone(),
            size_limit_mb: *size_limit_mb,
            duration: duration.map(Duration::from_secs),
            output_dir: output_dir.clone(),
            no_conversion: *no_conversion,
        };
        return capture::capture(&target, conn_timeout, options, ui).await;
    }

    let transport = connect_target_timeout(&target, conn_timeout).await?;

    let Some(capture_path) = cli.capture else {
        let client = Client::new(transport).read_banner().await?;
        return drive_connected(client, cli.cmd, ui).await;
    };

    let recording = RecordingTransport::new(transport);
    let capture_log = recording.log_handle();

    let outcome = drive(Client::new(recording), cli.cmd, ui).await;
    recording::write_capture(&capture_path, &capture_log)?;

    outcome
}

async fn drive<T>(client: Client<T>, cmd: Command, ui: UiOptions) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let client = client.read_banner().await?;

    drive_connected(client, cmd, ui).await
}

async fn drive_connected<T>(
    mut client: Client<T, Connected>,
    cmd: Command,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // Each handler future is boxed so that its state lives on the heap.
    // Awaited inline, every arm's state would share one future whose resume
    // function overflows the 1 MiB main thread stack on Windows in debug
    // builds.
    let client_ref = &mut client;
    match cmd {
        Command::Discover { .. } | Command::Resolve { .. } | Command::Parity(_) => {
            unreachable!()
        }
        Command::Ping => println!("connected"),
        Command::Dbgname { set } => Box::pin(system::dbg_name(client_ref, set)).await?,
        Command::Systime => Box::pin(system::sys_time(client_ref, ui)).await?,
        Command::Dmversion => Box::pin(system::dm_version(client_ref)).await?,
        Command::Consoletype => Box::pin(system::console_type(client_ref)).await?,
        Command::Consolefeatures => Box::pin(system::console_features(client_ref)).await?,
        Command::Drivelist => Box::pin(file::drive_list(client_ref, ui)).await?,
        Command::Df { drive } => Box::pin(file::drive_free_space(client_ref, drive, ui)).await?,
        Command::File(command) => Box::pin(file::run(client_ref, command, ui)).await?,
        Command::Altaddr => Box::pin(network::alt_addr(client_ref)).await?,
        Command::Getpid => Box::pin(system::get_pid(client_ref)).await?,
        Command::Consolemem => Box::pin(system::console_mem(client_ref)).await?,
        Command::Netaddrs => Box::pin(network::net_addrs(client_ref)).await?,
        Command::Modules => Box::pin(modules::modules(client_ref, ui)).await?,
        Command::DumpModule { module, output } => {
            Box::pin(modules::dump_module(client_ref, &module, &output, ui)).await?;
        }
        Command::Modsections { module } => {
            Box::pin(modules::module_sections(client_ref, &module, ui)).await?;
        }
        Command::Threads => Box::pin(debug::threads(client_ref, ui)).await?,
        Command::Threadinfo { thread } => Box::pin(debug::thread_info(client_ref, &thread)).await?,
        Command::Xbeinfo { name } => Box::pin(system::xbe_info(client_ref, name)).await?,
        Command::Walkmem => Box::pin(memory::walk_mem(client_ref, ui)).await?,
        Command::Getmem { address, length } => {
            Box::pin(memory::get_mem(client_ref, &address, &length)).await?;
        }
        Command::Pclist => Box::pin(perf::pc_list(client_ref, ui)).await?,
        Command::Querypc { name, kind } => Box::pin(perf::query_pc(client_ref, name, kind)).await?,
        Command::Sockets => Box::pin(network::sockets(client_ref, ui)).await?,
        Command::Isstopped { thread } => Box::pin(debug::is_stopped(client_ref, &thread)).await?,
        Command::Reboot {
            stop,
            wait,
            smc_reset,
        } => {
            let request = Reboot {
                stop,
                wait,
                smc_reset,
            };
            Box::pin(system::reboot(client_ref, request)).await?;
        }
        Command::Magicboot {
            cold,
            wait,
            stop,
            title,
            directory,
            cmd_line,
        } => {
            let request = MagicBoot {
                cold,
                wait,
                stop,
                title,
                directory,
                cmd_line,
            };
            Box::pin(system::magic_boot(client_ref, request)).await?;
        }
        Command::SetTitle { nopersist, name } => {
            Box::pin(system::set_title(client_ref, nopersist, name)).await?;
        }
        Command::Setmem { address, hex } => {
            Box::pin(memory::set_mem(client_ref, &address, &hex)).await?;
        }
        Command::Bp { address, clear } => {
            Box::pin(debug::breakpoint(client_ref, &address, clear)).await?;
        }
        Command::Databp {
            address,
            size,
            kind,
            clear,
        } => {
            Box::pin(debug::data_breakpoint(
                client_ref, &address, size, kind, clear,
            ))
            .await?;
        }
        Command::Screenshot { output, raw } => {
            Box::pin(screenshot::screenshot(client_ref, &output, raw)).await?;
        }
        #[cfg(feature = "capture")]
        Command::Capture { .. } => {
            unreachable!("Capture is handled by capture::capture before drive_connected")
        }
        #[cfg(feature = "capture")]
        Command::PixcmdProbe { subcommand } => {
            Box::pin(pix::pixcmd_probe(client_ref, &subcommand)).await?;
        }
        #[cfg(feature = "capture")]
        Command::PixNotify { .. } => {
            unreachable!("PixNotify is handled by pix::pix_notify before drive_connected")
        }
        #[cfg(feature = "capture")]
        Command::Xbm(_) => {
            unreachable!("Xbm is handled by xbm::run before drive_connected")
        }
        Command::Raw { line } => Box::pin(system::raw(client_ref, &line)).await?,
        Command::Kd(command) => kd::kd(client_ref, command).await?,
        Command::Kdlite(command) => kd::kd_lite(client_ref, command).await?,
        Command::Kdnet(command) => Box::pin(kd::kd_net(client_ref, command)).await?,
        #[cfg(feature = "dangerous")]
        Command::Dangerous(command) => Box::pin(dangerous::run(client_ref, command)).await?,
    }

    let _ = client.bye().await;

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // An invalid --log filter falls back to the documented default.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cli.log)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Command::Parity(command) = &cli.cmd {
        let target = cli
            .host
            .as_deref()
            .map(|host| Target::parse(host, cli.port));
        let timeout = Duration::from_secs(cli.timeout);
        return match runtime.block_on(parity::run(command, target, timeout)) {
            Ok(code) => code,
            Err(report) => {
                eprintln!("error: {report:?}");
                ExitCode::FAILURE
            }
        };
    }

    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(report) => {
            eprintln!("error: {report:?}");
            ExitCode::FAILURE
        }
    }
}
