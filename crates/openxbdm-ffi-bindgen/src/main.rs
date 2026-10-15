//! Writes the C++ headers that describe the `openxbdm-ffi` libraries.
//!
//! Usage: `openxbdm-ffi-bindgen <lib.rs> <output directory>`. The entry is
//! the `lib.rs` of `openxbdm-ffi`; its inline and file modules are read
//! from beside it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use diplomat_core::hir::DocsUrlGenerator;
use diplomat_tool::config::Config;

fn main() -> ExitCode {
    let arguments: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [entry, output] = arguments.as_slice() else {
        eprintln!("usage: openxbdm-ffi-bindgen <lib.rs> <output directory>");
        return ExitCode::FAILURE;
    };
    if let Err(error) = std::fs::create_dir_all(output) {
        eprintln!(
            "openxbdm-ffi-bindgen: creating {}: {error}",
            output.display()
        );
        return ExitCode::FAILURE;
    }
    let docs = DocsUrlGenerator::with_base_urls(None, HashMap::new());
    match diplomat_tool::r#gen(entry, "cpp", output, &docs, Config::default(), true) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openxbdm-ffi-bindgen: {error}");
            ExitCode::FAILURE
        }
    }
}
