//! Mount an Xbox 360 devkit's drives as a local FUSE filesystem.
//!
//! Standalone binary, deliberately independent of `xeedee-cli`: `fuser` is
//! Linux/macOS-only, so keeping it out of the main CLI's dependency graph
//! keeps that binary buildable everywhere.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use xeedee::Client;
use xeedee::transport::tokio::Target;
use xeedee::transport::tokio::connect_target_timeout;

mod filesystem;

use filesystem::XbdmFs;

/// Mount an Xbox 360 devkit's drives as a local FUSE filesystem.
#[derive(Parser, Debug)]
struct Cli {
    /// Console hostname or IP (same accepted forms as `xeedee --host`).
    host: String,
    /// Local directory to mount onto. Must already exist.
    mountpoint: PathBuf,
    /// XBDM port.
    #[arg(long, default_value_t = 730)]
    port: u16,
    /// Connection timeout in seconds.
    #[arg(long, default_value_t = 15)]
    timeout: u64,
    /// Mount read-only: mutating operations (write, mkdir, rm, mv, create,
    /// truncate) fail with EROFS.
    #[arg(long)]
    read_only: bool,
    /// Log filter, e.g. `info`, `debug`, `xeedee=trace`.
    #[arg(long, default_value = "info")]
    log: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cli.log)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let target = Target::parse(&cli.host, cli.port);
    let timeout = Duration::from_secs(cli.timeout);
    let client = match rt.block_on(async {
        let transport = connect_target_timeout(&target, timeout).await?;
        Client::new(transport).read_banner().await
    }) {
        Ok(client) => client,
        Err(report) => {
            eprintln!("error connecting to {target}: {report:?}");
            return ExitCode::FAILURE;
        }
    };

    let fs = XbdmFs::new(target, timeout, client, rt, cli.read_only);
    let mut config = fuser::Config::default();
    config.mount_options = vec![fuser::MountOption::FSName("xeedee".to_owned())];

    match fuser::mount2(fs, &cli.mountpoint, &config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mount error: {e}");
            ExitCode::FAILURE
        }
    }
}
