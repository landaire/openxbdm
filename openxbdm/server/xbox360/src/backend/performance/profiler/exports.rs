use openxbdm_server::commands::performance::profiler::ProfilerFlags;

use super::super::module_snapshot;
use super::info;
use super::start;
use super::stop;
use crate::backend::filesystem;
use crate::exports::export;
use crate::kernel;

/// Export 149: start profiling into drive path `name`, translated on the
/// caller's thread.
extern "C" fn export_start(name: u32, interval: u32, flags: u32) -> u32 {
    /// Characters of the name `lopctrl` accepts at most.
    const NAME_LIMIT: usize = 0x140;

    // SAFETY: the export takes a NUL-terminated drive path, not 0 (stock
    // reads it without a check; here 0 breaks the export contract), that
    // the caller keeps unchanged during the call.
    let name = unsafe { kernel::bounded_c_string(name, NAME_LIMIT).unwrap_unchecked() };
    let path = filesystem::translate(name);

    let mut executable = [0u8; module_snapshot::PATH_LIMIT + 2];
    let executable_length = module_snapshot::executable_drive_path(&mut executable);

    crate::exports::export_result(start(
        path.as_ref().map(|path| path.as_bytes()),
        &executable[..executable_length],
        interval,
        ProfilerFlags(flags),
    ))
    .0
}

/// Export 150.
extern "C" fn export_stop() -> u32 {
    crate::exports::export_result(stop()).0
}

/// Export 151: elapsed seconds, total samples, and overhead interrupts;
/// the outputs are written only on success.
extern "C" fn export_info(elapsed: *mut u32, samples: *mut u32, overhead: *mut u32) -> u32 {
    let result = info().map(|info| {
        // SAFETY: the export takes three writable u32 outputs.
        unsafe {
            *elapsed = info.elapsed_time;
            *samples = info.total_samples;
            *overhead = info.overhead_interrupts;
        }
    });
    crate::exports::export_result(result).0
}

export!(149, export_start);
export!(150, export_stop);
export!(151, export_info);
