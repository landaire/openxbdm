//! `--capture`: save the byte-level conversation of a session.

use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

use openxbdm_client::error::Error;
use openxbdm_client::transport::CaptureLog;
use rootcause::Report;
use rootcause::prelude::ResultExt;

pub fn write_capture(path: &Path, log: &Arc<Mutex<CaptureLog>>) -> Result<(), Report<Error>> {
    let snapshot = log.lock().expect("capture log poisoned").clone();

    std::fs::write(path, snapshot.to_text())
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("writing capture to {}", path.display()))?;
    eprintln!("capture written to {}", path.display());

    Ok(())
}
