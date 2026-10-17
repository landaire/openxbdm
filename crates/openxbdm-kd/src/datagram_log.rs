//! Datagram log files: one `unix-time peer length hex` line per datagram.

use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;

use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::error::CliError;

/// Opens `path` for appending, creating it when missing.
pub fn open_log(path: PathBuf) -> Result<File, Report<CliError>> {
    File::options()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(CliError::from)
        .attach(format!("log file {}", path.display()))
}

pub fn log_line(peer: SocketAddr, datagram: &[u8]) -> String {
    let now = jiff::Timestamp::now();
    let hex: String = datagram.iter().map(|byte| format!("{byte:02x}")).collect();

    format!(
        "{}.{:03} {peer} {} {hex}",
        now.as_second(),
        now.subsec_millisecond(),
        datagram.len()
    )
}
