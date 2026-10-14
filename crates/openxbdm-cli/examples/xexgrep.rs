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

    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("xex"))
        .collect();
    entries.sort();

    for path in &entries {
        let bytes = fs::read(path)?;
        let parsed = match Xex2::parse(bytes) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{}: parse failed: {e:?}", path.display());
                continue;
            }
        };
        let base = match parsed.extract_basefile() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{}: extract_basefile failed: {e:?}", path.display());
                continue;
            }
        };
        let name = path.file_name().unwrap().to_string_lossy();
        for needle in &needles {
            let nb = needle.as_bytes();
            for (i, w) in base.windows(nb.len()).enumerate() {
                if w == nb {
                    let ctx_size: usize = std::env::var("XEXGREP_CTX")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(16);
                    let ctx_start = i.saturating_sub(ctx_size);
                    let ctx_end = (i + nb.len() + ctx_size * 2).min(base.len());
                    let ctx: String = base[ctx_start..ctx_end]
                        .iter()
                        .map(|&b| {
                            if (0x20..0x7f).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    println!("{name:30}  {needle:30}  @0x{i:08x}  |{ctx}|");
                }
            }
        }
    }
    Ok(())
}
