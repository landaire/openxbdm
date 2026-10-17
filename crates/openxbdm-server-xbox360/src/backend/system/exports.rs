//! Title launch and reboot exports.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_server::commands;
use openxbdm_server::commands::system::BootFlags;
use openxbdm_server::commands::system::TitleFlags;
use openxbdm_server::reply;
use openxbdm_server::reply::CommandError;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::ProcessType;

use super::CallerWork;
use super::call_for_caller;
use crate::backend::Console;
use crate::backend::dispatcher;
use crate::exports::export;
use crate::kernel;

/// Arguments of a title export, passed to the server thread. The paths
/// are the export's arguments: 0 or NUL-terminated strings the caller
/// keeps until the export returns, read only by the server step.
pub(super) struct TitleArguments {
    flags: u32,
    image: u32,
    drive: u32,
    command_line: u32,
    /// Set by the server when the launch relaunched the title in place.
    relaunched: AtomicBool,
}

impl TitleArguments {
    fn new(flags: u32, image: u32, drive: u32, command_line: u32) -> Self {
        Self {
            flags,
            image,
            drive,
            command_line,
            relaunched: AtomicBool::new(false),
        }
    }
}

fn call_with_arguments(
    service: dispatcher::ServerService<TitleArguments>,
    arguments: &mut TitleArguments,
) -> Hresult {
    /// Result of an export whose server part could not run (on the server
    /// thread, above passive level, or after code 0x02 stopped the server).
    const SERVER_UNAVAILABLE: CommandError = CommandError::Fail;

    call_for_caller(CallerWork::Title { service, arguments })
        .map_or(Hresult::from(SERVER_UNAVAILABLE), Hresult)
}

/// Exports 28 and 125: run the launch on the server thread. Stock calls
/// the relaunch routine on the caller's thread and then ends that thread
/// when it belongs to the title process (0x91f278a8).
fn launch_export(
    service: dispatcher::ServerService<TitleArguments>,
    arguments: &mut TitleArguments,
) -> Hresult {
    let result = call_with_arguments(service, arguments);
    if arguments.relaunched.load(Ordering::Acquire)
        && xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE
    {
        // SAFETY: the calling title thread was relaunched in place and owns
        // nothing the monitor still uses; stock ends it here.
        unsafe { xboxkrnl::ExTerminateThread(0) };
    }

    result
}

/// Report an in-place relaunch of the server request `arguments`.
fn note_relaunch(console: &mut Console, arguments: &TitleArguments) {
    arguments.relaunched.store(
        core::mem::take(&mut console.system.relaunched),
        Ordering::Release,
    );
}

/// Stock export 28 (0x91f27b80): `(flags) -> HRESULT`; launch the current
/// title, relaunching in place when possible, else restart.
extern "C" fn reboot_export(flags: u32) -> Hresult {
    let mut arguments = TitleArguments::new(flags, 0, 0, 0);
    launch_export(
        |server, console, network, arguments| {
            console.system.relaunched = false;
            let flags = BootFlags::from_bits_retain(arguments.flags);
            let result =
                commands::system::launch_without_connection(server, console, network, flags, None);
            note_relaunch(console, arguments);
            reply::hresult(result).0
        },
        &mut arguments,
    )
}
export!(28, reboot_export);

/// Stock export 125 (0x91f27ab8): `(flags, image, drive, command line) ->
/// HRESULT`; launch a title by drive paths, or object paths with flag
/// 0x10.
extern "C" fn launch_title_export(
    flags: u32,
    image: u32,
    drive: u32,
    command_line: u32,
) -> Hresult {
    let mut arguments = TitleArguments::new(flags, image, drive, command_line);
    launch_export(
        |server, console, network, arguments| {
            console.system.relaunched = false;
            // SAFETY: export 125 takes null or NUL-terminated paths.
            let (image, drive, command_line) = unsafe {
                (
                    kernel::c_string(arguments.image),
                    kernel::c_string(arguments.drive),
                    kernel::c_string(arguments.command_line),
                )
            };
            let result = commands::system::launch_from_paths(
                server,
                console,
                network,
                BootFlags::from_bits_retain(arguments.flags),
                image,
                drive,
                command_line,
            );
            note_relaunch(console, arguments);
            reply::hresult(result).0
        },
        &mut arguments,
    )
}
export!(125, launch_title_export);

/// Stock export 81 (0x91f47140): `(dir, name, command line, flags) ->
/// HRESULT`; set the launch title from drive paths.
extern "C" fn set_title_export(dir: u32, name: u32, command_line: u32, flags: u32) -> Hresult {
    let mut arguments = TitleArguments::new(flags, name, dir, command_line);
    call_with_arguments(
        |server, console, _, arguments| {
            // SAFETY: export 81 takes null or NUL-terminated paths.
            let (dir, name, command_line) = unsafe {
                (
                    kernel::c_string(arguments.drive),
                    kernel::c_string(arguments.image),
                    kernel::c_string(arguments.command_line),
                )
            };
            let result = commands::system::set_title_from_paths(
                &mut server.state,
                console,
                dir,
                name,
                command_line,
                TitleFlags::from_bits_retain(arguments.flags),
            );
            reply::hresult(result).0
        },
        &mut arguments,
    )
}
export!(81, set_title_export);

/// Stock export 42 (0x91f47208): export 81 with no flags.
extern "C" fn set_title_default_export(dir: u32, name: u32, command_line: u32) -> Hresult {
    set_title_export(dir, name, command_line, 0)
}
export!(42, set_title_default_export);
