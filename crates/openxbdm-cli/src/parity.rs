//! Differential testing between two monitors: record the replies to a
//! command list, then compare recordings.

mod compare;
mod error;
mod record;
mod script;

use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Subcommand;
use openxbdm_client::transport::tokio::Target;
use rootcause::Report;
use tokio::net::TcpStream;

use self::compare::Variances;
use self::error::ParityError;
use self::record::Recording;

#[derive(Subcommand, Debug)]
pub enum ParityCommand {
    /// Send each line of a command list to the console and record every
    /// reply (head, body lines, binary length and digest) as JSON.
    Record {
        /// Command list; see docs/re-notes/parity/hardware-commands.txt.
        #[arg(long)]
        commands: PathBuf,
        /// JSON file to write.
        #[arg(long)]
        output: PathBuf,
        /// Seconds to wait for each reply.
        #[arg(long, default_value_t = 30)]
        reply_timeout: u64,
    },
    /// Compare two recordings of the same command list. Exits with status 1
    /// when they differ outside the varying fields.
    Compare {
        a: PathBuf,
        b: PathBuf,
        /// Fields known to vary, per command line.
        #[arg(long)]
        variances: Option<PathBuf>,
    },
}

pub async fn run(
    command: &ParityCommand,
    target: Option<Target>,
    connect_timeout: Duration,
) -> Result<ExitCode, Report<ParityError>> {
    let result = match command {
        ParityCommand::Record {
            commands,
            output,
            reply_timeout,
        } => {
            let reply_timeout = Duration::from_secs(*reply_timeout);
            record_to_file(commands, output, target, connect_timeout, reply_timeout).await
        }
        ParityCommand::Compare { a, b, variances } => compare_files(a, b, variances.as_deref()),
    };

    result.map_err(Report::new)
}

async fn record_to_file(
    commands: &Path,
    output: &Path,
    target: Option<Target>,
    connect_timeout: Duration,
    reply_timeout: Duration,
) -> Result<ExitCode, ParityError> {
    let target = target.ok_or(ParityError::MissingHost)?;
    let steps = script::parse(&read_text(commands)?)?;

    let mut index = 0usize;
    let outcome = record::record(
        &steps,
        || connect(&target, connect_timeout),
        reply_timeout,
        |exchange| {
            eprintln!(
                "{index:>4} {}  =>  {}",
                exchange.command,
                compare::describe(&exchange.reply)
            );
            index += 1;
        },
    )
    .await;

    // The exchanges before a failure are kept for inspection.
    let write_error = |source| ParityError::Write {
        path: output.to_owned(),
        source,
    };
    let mut writer = BufWriter::new(File::create(output).map_err(write_error)?);
    serde_json::to_writer_pretty(&mut writer, &outcome.recording)
        .map_err(|error| write_error(error.into()))?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(write_error)?;

    match outcome.error {
        Some(error) => Err(error.into()),
        None => Ok(ExitCode::SUCCESS),
    }
}

fn compare_files(a: &Path, b: &Path, variances: Option<&Path>) -> Result<ExitCode, ParityError> {
    let variances = match variances {
        Some(path) => Variances::parse(&read_text(path)?)?,
        None => Variances::default(),
    };

    let comparison = compare::compare(&read_recording(a)?, &read_recording(b)?, &variances)?;
    print!(
        "{}",
        compare::render(
            &comparison,
            &a.display().to_string(),
            &b.display().to_string()
        )
    );

    if comparison.is_equal() {
        return Ok(ExitCode::SUCCESS);
    }

    Ok(ExitCode::FAILURE)
}

async fn connect(target: &Target, timeout: Duration) -> io::Result<TcpStream> {
    let connecting = async {
        match target {
            Target::Addr(address) => TcpStream::connect(address).await,
            Target::HostPort { host, port } => TcpStream::connect((host.as_str(), *port)).await,
        }
    };

    tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

fn read_text(path: &Path) -> Result<String, ParityError> {
    std::fs::read_to_string(path).map_err(|source| ParityError::Read {
        path: path.to_owned(),
        source,
    })
}

fn read_recording(path: &Path) -> Result<Recording, ParityError> {
    let file = File::open(path).map_err(|source| ParityError::Read {
        path: path.to_owned(),
        source,
    })?;

    serde_json::from_reader(BufReader::new(file)).map_err(|source| ParityError::Recording {
        path: path.to_owned(),
        source,
    })
}
