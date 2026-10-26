//! Scan every `.xex` under a directory, decrypt+decompress each one's
//! inner PE via the `xex2` crate, and grep the resulting bytes for
//! user-supplied substrings. Used to check which (if any) xex file on
//! a NAND dump implements a given command/API without trusting raw
//! `strings` output on the still-encrypted on-disk form.
//!
//! Usage:
//!
//!     cargo run --example xexgrep -- ./flash BeginCapture EndCapture
//!
//! Prints one line per hit: `<filename>  <needle>  @offset=<hex>`

use std::fs;
use std::path::PathBuf;

use xex2::Xex2;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dir = args.next().ok_or("usage: xexgrep <dir> <needle>...")?;
    let needles: Vec<String> = args.collect();
    if needles.is_empty() {
        return Err("need at least one needle".into());
    }

    // Bytes of context shown on each side of a hit; an unset or invalid
    // XEXGREP_CTX uses the default.
    let context_len: usize = std::env::var("XEXGREP_CTX")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(16);

    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("xex"))
        .collect();
    paths.sort();

    for path in &paths {
        let bytes = fs::read(path)?;
        let parsed = match Xex2::parse(bytes) {
            Ok(parsed) => parsed,
            Err(e) => {
                eprintln!("{}: parse failed: {e:?}", path.display());
                continue;
            }
        };
        let base = match parsed.extract_basefile() {
            Ok(base) => base,
            Err(e) => {
                eprintln!("{}: extract_basefile failed: {e:?}", path.display());
                continue;
            }
        };

        let name = path.file_name().unwrap().to_string_lossy();
        for needle in &needles {
            let needle_bytes = needle.as_bytes();
            for (offset, window) in base.windows(needle_bytes.len()).enumerate() {
                if window != needle_bytes {
                    continue;
                }

                let context_start = offset.saturating_sub(context_len);
                let context_end = (offset + needle_bytes.len() + context_len * 2).min(base.len());
                let context: String = base[context_start..context_end]
                    .iter()
                    .map(|&byte| {
                        if (0x20..0x7f).contains(&byte) {
                            byte as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                println!("{name:30}  {needle:30}  @0x{offset:08x}  |{context}|");
            }
        }
    }

    Ok(())
}
