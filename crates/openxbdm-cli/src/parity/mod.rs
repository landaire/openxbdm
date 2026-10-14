//! Differential testing between two monitors: record the replies to a
//! command list, then compare recordings.

mod compare;
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
use rootcause::prelude::*;

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

#[derive(Debug, thiserror::Error)]
pub enum ParityError {
    #[error("--host is required to record")]
    MissingHost,
    #[error("reading {path} failed")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("writing {path} failed")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{path} is not a recording")]
    Recording {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid command list")]
    Script(#[from] script::ScriptError),
    #[error("invalid variance file")]
    Variance(#[from] compare::VarianceError),
    #[error("recording failed")]
    Record(#[from] record::RecordError),
    #[error("recordings are not comparable")]
    Compare(#[from] compare::CompareError),
}

pub async fn run(
    command: &ParityCommand,
    target: Option<Target>,
    connect_timeout: Duration,
) -> Result<ExitCode, Report<ParityError>> {
    execute(command, target, connect_timeout)
        .await
        .map_err(Report::new)
}

async fn execute(
    command: &ParityCommand,
    target: Option<Target>,
    connect_timeout: Duration,
) -> Result<ExitCode, ParityError> {
    match command {
        ParityCommand::Record {
            commands,
            output,
            reply_timeout,
        } => {
            let target = target.ok_or(ParityError::MissingHost)?;
            let steps = script::parse(&read_text(commands)?)?;
            let connect = || connect(&target, connect_timeout);
            let mut index = 0usize;
            let outcome = record::record(
                &steps,
                connect,
                Duration::from_secs(*reply_timeout),
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
                path: output.clone(),
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
        ParityCommand::Compare { a, b, variances } => {
            let variances = match variances {
                Some(path) => compare::Variances::parse(&read_text(path)?)?,
                None => compare::Variances::default(),
            };
            let comparison =
                compare::compare(&read_recording(a)?, &read_recording(b)?, &variances)?;
            print!(
                "{}",
                compare::render(
                    &comparison,
                    &a.display().to_string(),
                    &b.display().to_string()
                )
            );
            Ok(if comparison.is_equal() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

async fn connect(target: &Target, timeout: Duration) -> io::Result<tokio::net::TcpStream> {
    let connecting = async {
        match target {
            Target::Addr(address) => tokio::net::TcpStream::connect(address).await,
            Target::HostPort { host, port } => {
                tokio::net::TcpStream::connect((host.as_str(), *port)).await
            }
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

fn read_recording(path: &Path) -> Result<record::Recording, ParityError> {
    let file = File::open(path).map_err(|source| ParityError::Read {
        path: path.to_owned(),
        source,
    })?;
    serde_json::from_reader(BufReader::new(file)).map_err(|source| ParityError::Recording {
        path: path.to_owned(),
        source,
    })
}
