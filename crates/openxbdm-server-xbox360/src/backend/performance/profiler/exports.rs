use openxbdm_server::Server;
use openxbdm_server::commands::filesystem::ObjectPath;
use openxbdm_server::commands::performance::profiler::ProfilerFlags;

use super::super::module_snapshot;
use super::info;
use super::start;
use super::stop;
use crate::backend::Console;
use crate::backend::dispatcher;
use crate::exports::export;
use crate::kernel;
use crate::net::XamNetwork;

/// Request of [`translate_on_server`].
struct Translation<'a> {
    name: &'a [u8],
    path: Option<ObjectPath>,
    executable: [u8; module_snapshot::PATH_LIMIT + 2],
    executable_length: usize,
}

fn translate_on_server(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    request: &mut Translation<'_>,
) -> u32 {
    let drives = &server.state.filesystem.drives;
    request.path = drives.translate(console, request.name);

    request.executable_length = drives.object_path_to_drive_path(
        console,
        module_snapshot::ExecutableObjectPath::read().as_bytes(),
        &mut request.executable,
    );

    0
}

/// Export 149: start profiling into drive path `name`. The drive table is
/// read on the server thread; where that cannot wait, the name has no
/// object path.
extern "C" fn export_start(name: u32, interval: u32, flags: u32) -> u32 {
    /// Characters of the name `lopctrl` accepts at most.
    const NAME_LIMIT: usize = 0x140;

    let mut request = Translation {
        // SAFETY: the export takes a NUL-terminated drive path, not 0 (stock
        // reads it without a check; here 0 breaks the export contract),
        // that the caller keeps unchanged during the call.
        name: unsafe { kernel::bounded_c_string(name, NAME_LIMIT).unwrap_unchecked() },
        path: None,
        executable: [0; module_snapshot::PATH_LIMIT + 2],
        executable_length: 0,
    };
    if dispatcher::call_on_server_with(&mut request, translate_on_server).is_none() {
        request.executable_length =
            module_snapshot::copy_executable_object_path(&mut request.executable);
    }

    let path = request.path.as_ref().map(|path| path.as_bytes());
    crate::exports::export_result(start(
        path,
        &request.executable[..request.executable_length],
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
