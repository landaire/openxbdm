//! Linker for `rustc -C linker=`: records the command line to the file
//! named by `OPENXBDM_LINK_RECORD` (when set), then runs the target linker
//! with the same arguments.

use std::ffi::OsString;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::process::Command;
use std::process::ExitCode;

use openxbdm_asm_rewrite::link::LinkRecord;
use openxbdm_asm_rewrite::link::{
    self,
};

const RECORD_VARIABLE: &str = "OPENXBDM_LINK_RECORD";

fn record(record_path: &Path, linker: &Path, arguments: &[OsString]) -> Result<(), String> {
    let inputs = record_path.with_extension("inputs");
    let record = LinkRecord::capture(linker.to_owned(), arguments, &inputs)
        .map_err(|error| format!("recording the link command: {error}"))?;
    let file = File::create(record_path)
        .map_err(|error| format!("creating {}: {error}", record_path.display()))?;
    record
        .write(BufWriter::new(file))
        .map_err(|error| format!("writing {}: {error}", record_path.display()))
}

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let linker = match link::find_linker() {
        Ok(linker) => linker,
        Err(error) => {
            eprintln!("openxbdm-link-record: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(record_path) = std::env::var_os(RECORD_VARIABLE)
        && let Err(message) = record(Path::new(&record_path), &linker, &arguments)
    {
        eprintln!("openxbdm-link-record: {message}");
        return ExitCode::FAILURE;
    }
    match Command::new(&linker).args(&arguments).status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => {
            eprintln!(
                "openxbdm-link-record: {} failed with {status}",
                linker.display()
            );
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!(
                "openxbdm-link-record: running {}: {error}",
                linker.display()
            );
            ExitCode::FAILURE
        }
    }
}
