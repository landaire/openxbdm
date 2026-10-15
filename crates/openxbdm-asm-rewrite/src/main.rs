use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use openxbdm_asm_rewrite::{audit, link, reservation, rewrite};
use thiserror::Error;

/// Rewrites callee-saved register saves and restores in the Xbox 360
/// module assembly into calls to shared helper routines.
#[derive(Parser)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Rewrite an assembly file.
    Rewrite {
        input: PathBuf,
        output: PathBuf,
        /// Receives the compiled function list for `audit`.
        #[arg(long)]
        scope: PathBuf,
        /// Receives one line per refused site.
        #[arg(long)]
        refusals: PathBuf,
    },
    /// Replay a recorded link command with another module object.
    Relink {
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        object: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Also link a copy that keeps the symbol table.
        #[arg(long)]
        unstripped: Option<PathBuf>,
    },
    /// Check `llvm-objdump -d --no-show-raw-insn` output of the linked
    /// image for sequences the rules still rewrite.
    Audit {
        disassembly: PathBuf,
        #[arg(long)]
        scope: PathBuf,
    },
    /// Check a linked ELF image for reservations the kernel loader reports
    /// as unprotected.
    Reservations { image: PathBuf },
}

#[derive(Debug, Error)]
enum Error {
    #[error("opening {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Rewrite(#[from] rewrite::Error),
    #[error(transparent)]
    Link(#[from] link::Error),
    #[error(transparent)]
    Audit(#[from] audit::Error),
    #[error(transparent)]
    Image(#[from] reservation::ElfError),
    #[error(
        "{count} unprotected reservations; LLVM emits them for `core::sync::atomic` read-modify-write operations unless the active toolchain's rust-src carries the xbox360 atomics overlay (llvm-xbox-360/toolchain/rust-std-xbox360/apply.sh)"
    )]
    Unprotected { count: usize },
    #[error("running {linker}")]
    Spawn {
        linker: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{linker} failed with {status}")]
    LinkFailed {
        linker: PathBuf,
        status: std::process::ExitStatus,
    },
    #[error("{count} functions still hold rewritable sequences")]
    Rewritable { count: usize },
}

fn open(path: &Path) -> Result<BufReader<File>, Error> {
    File::open(path)
        .map(BufReader::new)
        .map_err(|source| Error::Open {
            path: path.to_owned(),
            source,
        })
}

fn create(path: &Path) -> Result<BufWriter<File>, Error> {
    File::create(path)
        .map(BufWriter::new)
        .map_err(|source| Error::Open {
            path: path.to_owned(),
            source,
        })
}

fn relink(
    record: &link::LinkRecord,
    object: &Path,
    output: &Path,
    keep_symbols: bool,
) -> Result<(), Error> {
    let mut command = record.command(object, output, keep_symbols)?;
    let status = command.status().map_err(|source| Error::Spawn {
        linker: record.linker.clone(),
        source,
    })?;
    if !status.success() {
        return Err(Error::LinkFailed {
            linker: record.linker.clone(),
            status,
        });
    }
    Ok(())
}

fn run(arguments: Arguments) -> Result<(), Error> {
    match arguments.command {
        Command::Rewrite {
            input,
            output,
            scope,
            refusals,
        } => {
            let listings = rewrite::Listings {
                scope: create(&scope)?,
                refusals: create(&refusals)?,
            };
            let report = rewrite::rewrite(open(&input)?, create(&output)?, listings)?;
            println!("{report}");
        }
        Command::Relink {
            record,
            object,
            output,
            unstripped,
        } => {
            let record = link::LinkRecord::read(open(&record)?)?;
            relink(&record, &object, &output, false)?;
            if let Some(unstripped) = unstripped {
                relink(&record, &object, &unstripped, true)?;
            }
        }
        Command::Audit { disassembly, scope } => {
            let scope = audit::read_scope(open(&scope)?)?;
            let report = audit::audit(open(&disassembly)?, &scope)?;
            print!("{report}");
            if !report.passed() {
                return Err(Error::Rewritable {
                    count: report.rewritable.len(),
                });
            }
        }
        Command::Reservations { image } => {
            let found = reservation::scan_elf(&image)?;
            for site in &found {
                println!("unprotected {site}");
            }
            if !found.is_empty() {
                return Err(Error::Unprotected { count: found.len() });
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut message = format!("error: {error}");
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                message.push_str(&format!(": {cause}"));
                source = cause.source();
            }
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
