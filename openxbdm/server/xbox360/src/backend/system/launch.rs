//! Title launch registration, launch information, and the disc wait.

use core::fmt::Write as _;
use core::mem::offset_of;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_server::Server;
use openxbdm_server::commands;
use openxbdm_server::commands::console::TraceMask;
use openxbdm_server::commands::system::LaunchReason;
use openxbdm_server::commands::system::LaunchTitle;
use openxbdm_server::commands::system::TitleRebootStop;
use openxbdm_server::notify::ExecutionState;
use openxbdm_server::text::Text;
use xbox360::module::Ordinal;
use xbox360::time::sleep;
use xbox360_sys::xam::NotificationAreas;
use xbox360_sys::xam::XamLoaderGetDvdTrayState;
use xbox360_sys::xam::XamNotifyCreateListenerInternal;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::CallerWork;
use super::call_for_caller;
use crate::backend::Console;
use crate::backend::console;
use crate::backend::debugger as monitor;
use crate::backend::dispatcher;
use crate::backend::network;
use crate::backend::session;
use crate::kernel;

const LAUNCH_STRING_SIZE: usize = 0x100;

/// Launch reason whose disc image may need the disc wait.
const REASON_DISC: LaunchReason = LaunchReason(4);

/// Version assumed when the system software registers without one.
const XAM_VERSION_BASE: u32 = 0x2007_6000;

/// Longest disc wait of a launch, polled every 100 ms.
const DISC_WAIT_MS: u32 = 5000;

pub(super) static XAM_GLOBALS: XamGlobals = XamGlobals {
    size: AtomicU32::new(0),
    launch_routine: AtomicU32::new(0),
    version: AtomicU32::new(0),
};

/// Version of the registered system software (stock 0x91fa2000).
static XAM_VERSION: AtomicU32 = AtomicU32::new(0);

/// XAM disc query routine and the flag of its one-time lookup (stock
/// 0x91fa1ff8, 0x91fa1ffc).
static DISC_QUERY: AtomicU32 = AtomicU32::new(0);

static DISC_QUERY_LOOKED_UP: AtomicBool = AtomicBool::new(false);

/// Launch information of the system software (codes 0x21 and 0x77).
#[repr(C)]
pub(super) struct LaunchInformation {
    reason: u32,
    _reserved_04: [u8; 0xc],
    image: [u8; LAUNCH_STRING_SIZE],
    drive: [u8; LAUNCH_STRING_SIZE],
    command_line: [u8; LAUNCH_STRING_SIZE],
    /// Cleared for system software newer than [`XAM_VERSION_BASE`].
    extra: u32,
}

const _: () = {
    assert!(offset_of!(LaunchInformation, image) == 0x10);
    assert!(offset_of!(LaunchInformation, drive) == 0x110);
    assert!(offset_of!(LaunchInformation, command_line) == 0x210);
    assert!(offset_of!(LaunchInformation, extra) == 0x310);
};

impl LaunchInformation {
    fn reason(&self) -> LaunchReason {
        LaunchReason(self.reason)
    }

    /// Store a title as stock's `strncpy` of 0x100 bytes with a forced
    /// terminator does.
    fn set_title(&mut self, title: &LaunchTitle) {
        for (destination, text) in [
            (&mut self.image, &title.image),
            (&mut self.drive, &title.drive),
            (&mut self.command_line, &title.command_line),
        ] {
            let bytes = text.as_bytes();
            destination[..bytes.len()].copy_from_slice(bytes);
            destination[bytes.len()..].fill(0);
        }
    }
}

/// Registration of code 0x20 (stock 0x91fa2004), as copied from the
/// caller.
#[repr(C)]
pub(super) struct XamGlobals {
    size: AtomicU32,
    pub(super) launch_routine: AtomicU32,
    pub(super) version: AtomicU32,
}

const _: () = assert!(size_of::<XamGlobals>() == 12);

impl XamGlobals {
    fn words(&self) -> [&AtomicU32; 3] {
        [&self.size, &self.launch_routine, &self.version]
    }
}

/// Server steps of a title reboot before the launch.
pub(super) struct TitleReboot {
    reason: LaunchReason,
    /// Stays `Run` when the server is unavailable.
    stop: TitleRebootStop,
}

/// Launch override of code 0x77, passed to the server thread.
struct LaunchOverride {
    /// The system software's launch information, which it does not touch
    /// until the code returns.
    information: *mut LaunchInformation,
    /// Set by the server when the launch information took the title.
    replaced: bool,
}

/// Stock assertion trap of the registration (`twi 31, 0, 0x19`).
fn assertion_trap() {
    // SAFETY: raises the trap exception stock raises; the debug routine
    // or the kernel handles it.
    unsafe { core::arch::asm!("twi 31, 0, 0x19") };
}

/// Monitor control code 0x20 (stock 0x91f51df8): the system software
/// registers its globals: `{size >= 8, title launch routine, version}`.
///
/// # Safety
///
/// `argument` must be 0 or the address of the registration record, whose
/// first word is its size in bytes and which holds at least the smaller of
/// that size and 12 readable bytes, unchanged for the call.
pub(crate) unsafe fn service_register_xam_globals(argument: u32) -> u32 {
    /// Highest version of the notifications the listener accepts.
    const NOTIFICATION_VERSION: u32 = 0xa;

    // SAFETY: the caller's contract.
    let size_word =
        unsafe { core::ptr::with_exposed_provenance::<AtomicU32>(argument as usize).as_ref() };
    if size_word.is_none_or(|size| size.load(Ordering::Relaxed) < 8) {
        assertion_trap();
    }
    // Stock faults reading a null record after the trap; this returns 0.
    let Some(size_word) = size_word else {
        return 0;
    };

    // Stock reads the size again after the trap.
    let size = size_word.load(Ordering::Relaxed).min(12);
    // SAFETY: the caller's contract; the record holds its size in bytes.
    let record = unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance::<u8>(argument as usize),
            size as usize,
        )
    };

    let words = XAM_GLOBALS.words();
    let mut bytes = [0u8; 12];

    for (index, word) in words.iter().enumerate() {
        bytes[index * 4..index * 4 + 4]
            .copy_from_slice(&word.load(Ordering::Relaxed).to_be_bytes());
    }

    bytes[..record.len()].copy_from_slice(record);

    for (index, word) in words.iter().enumerate() {
        let value = u32::from_be_bytes([
            bytes[index * 4],
            bytes[index * 4 + 1],
            bytes[index * 4 + 2],
            bytes[index * 4 + 3],
        ]);
        word.store(value, Ordering::Release);
    }

    let version = if XAM_GLOBALS.size.load(Ordering::Relaxed) <= 8 {
        XAM_VERSION_BASE
    } else {
        let version = XAM_GLOBALS.version.load(Ordering::Relaxed);
        if version <= XAM_VERSION_BASE {
            assertion_trap();
        }

        version
    };

    XAM_VERSION.store(version, Ordering::Release);
    // Stock keeps the listener handle but never reads it.
    // SAFETY: the listener takes no caller memory.
    let listener = unsafe {
        XamNotifyCreateListenerInternal(
            NotificationAreas::SYSTEM.bits(),
            u32::from(true),
            NOTIFICATION_VERSION,
        )
    };
    if listener == Handle::NULL && console::trace_mask().contains(TraceMask::TITLE_LAUNCH) {
        kernel::debug_print(c"[xbdm] Failed to register for XAM notifications.\n");
    }

    0
}

/// Whether a launch string starts with `\Device\Cdrom0`, ignoring case
/// (stock `_strnicmp` with 14 bytes).
fn is_disc_image(image: &[u8; LAUNCH_STRING_SIZE]) -> bool {
    const DISC_IMAGE_PREFIX: &[u8; 14] = b"\\Device\\Cdrom0";

    image[..DISC_IMAGE_PREFIX.len()].eq_ignore_ascii_case(DISC_IMAGE_PREFIX)
}

/// Stock 0x91f52040: wait for the disc tray to close, ask the system
/// software about the disc, and open the image once. The outcome is not
/// used; the wait is what matters.
fn wait_for_disc(image: &[u8; LAUNCH_STRING_SIZE], milliseconds: u32) {
    /// XAM export queried before a disc image is opened (stock 0x91f52040).
    const XAM_DISC_QUERY: Ordinal = Ordinal::new(0x1a3).unwrap();
    const DISC_POLL_MS: u32 = 100;
    /// Tray state that ends the wait.
    const TRAY_READY: u32 = 0;

    if DISC_QUERY.load(Ordering::Acquire) == 0
        && !DISC_QUERY_LOOKED_UP.swap(true, Ordering::AcqRel)
        && let Some(address) = network::xam_procedure(XAM_DISC_QUERY)
    {
        DISC_QUERY.store(address, Ordering::Release);
    }
    let mut polls = milliseconds / DISC_POLL_MS;
    let mut tray = XamLoaderGetDvdTrayState();

    while polls != 0 && tray != TRAY_READY {
        sleep(Duration::from_millis(u64::from(DISC_POLL_MS)));
        polls -= 1;
        tray = XamLoaderGetDvdTrayState();
    }

    if tray != TRAY_READY {
        kernel::debug_print(c"[xbdm] Timed-out waiting for media detect\n");
        return;
    }

    let query = DISC_QUERY.load(Ordering::Acquire);
    if query != 0 {
        let mut media = 0u32;
        let mut kind = 0u32;
        // SAFETY: the XAM disc query takes two output dwords.
        unsafe {
            kernel::call_export(
                query,
                &raw mut media as usize as u32,
                &raw mut kind as usize as u32,
                0,
                0,
            )
        };
        let mut text = Text::<0x40>::new();
        let _ = writeln!(
            text,
            "[xbdm] XamGetMediaInfo() - (media={},type={})",
            media as i32, kind as i32
        );
        kernel::debug_print_bytes(text.as_bytes());
        if media == 0 {
            return;
        }
    }

    // An unterminated string is used whole, as stock's open does.
    let length = image
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(LAUNCH_STRING_SIZE);
    let name = kernel::ansi_string(&image[..length]);
    let attributes = ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: &name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    let mut status_block = IoStatusBlock::default();
    let mut handle = Handle::NULL;
    // SAFETY: `handle`, `attributes`, the path it refers to and
    // `status_block` are live.
    let status = unsafe {
        xboxkrnl::NtOpenFile(
            &mut handle,
            AccessMask::SYNCHRONIZE,
            &attributes,
            &mut status_block,
            ShareAccess::READ,
            CreateOptions::SYNCHRONOUS_IO_NONALERT | CreateOptions::NON_DIRECTORY_FILE,
        )
    };
    if status.is_success() {
        // SAFETY: `handle` was opened above and is closed once.
        unsafe { xboxkrnl::NtClose(handle) };
    }
}

fn newer_system_software() -> bool {
    XAM_VERSION.load(Ordering::Acquire) > XAM_VERSION_BASE
}

/// Monitor control code 0x21 after the controller rebind (stock
/// DmpTitleReboot 0x91f523a0): the system software launches a title.
/// Execution goes through pending_title, the launching thread may stop
/// there, and the launch information takes the monitor's launch title.
/// Returns 1 when it was replaced and the image exists. Each server step
/// runs where stock runs it relative to the execution changes, the disc
/// wait, and the stop.
///
/// # Safety
///
/// `argument` must be 0 or the address of the system software's writable
/// launch information, which it does not touch until the code returns.
pub(crate) unsafe fn service_title_reboot(argument: u32) -> u32 {
    /// System software below this version needs the disc wait at a title
    /// reboot.
    const XAM_VERSION_DISC_WAIT: u32 = 0x2018_3800;

    session::reset_title_wait_statistics();
    // SAFETY: the caller's contract.
    let Some(information) = (unsafe { (argument as usize as *mut LaunchInformation).as_mut() })
    else {
        monitor::request_execution(ExecutionState::PendingTitle, false);
        monitor::request_execution(ExecutionState::Started, true);
        return 0;
    };

    let mut reboot = TitleReboot {
        reason: information.reason(),
        stop: TitleRebootStop::Run,
    };
    dispatcher::call_on_server_with(
        &mut reboot,
        |server, console, _, reboot: &mut TitleReboot| {
            commands::system::trace_title_reboot(&server.state, console, reboot.reason);
            0
        },
    );
    monitor::request_execution(ExecutionState::PendingTitle, false);
    if reboot.reason == REASON_DISC
        && XAM_VERSION.load(Ordering::Acquire) < XAM_VERSION_DISC_WAIT
        && is_disc_image(&information.image)
    {
        wait_for_disc(&information.image, DISC_WAIT_MS);
    }
    dispatcher::call_on_server_with(
        &mut reboot,
        |server, console, _, reboot: &mut TitleReboot| {
            reboot.stop =
                commands::system::title_reboot_stop(&mut server.state, console, reboot.reason);
            0
        },
    );
    let released = match reboot.stop {
        TitleRebootStop::Run => false,
        TitleRebootStop::Stop { forever } => monitor::stop_at_pending_title(forever),
    };
    if reboot.stop != TitleRebootStop::Run
        && !released
        && console::trace_mask().contains(TraceMask::TITLE_LAUNCH)
    {
        kernel::debug_print(c"[xbdm] DmpTitleReboot: DMN_EXEC_PENDING_TITLE state timed out\n");
    }
    if !released {
        monitor::request_execution(ExecutionState::Started, true);
    }

    call_for_caller(CallerWork::TitleReboot(information)).unwrap_or(0)
}

pub(super) fn title_reboot_on_server(
    server: &mut Server,
    console: &mut Console,
    information: &mut LaunchInformation,
) -> u32 {
    let reason = information.reason();
    let Some(title) = commands::system::title_reboot_launch(&mut server.state, console, reason)
    else {
        return 0;
    };

    information.set_title(&title);
    if newer_system_software() {
        information.extra = 0;
    }
    u32::from(commands::system::launch_image_exists(
        &server.state,
        console,
        title.image.as_bytes(),
    ))
}

/// Monitor control code 0x77 (stock 0x91f52260): fill the launch
/// information with the monitor's launch title, if any.
///
/// # Safety
///
/// `argument` must be the address of the system software's writable
/// launch information, which it does not touch until the code returns.
pub(crate) unsafe fn service_launch_override(argument: u32) -> u32 {
    let mut request = LaunchOverride {
        information: argument as usize as *mut LaunchInformation,
        replaced: false,
    };
    dispatcher::call_on_server_with(
        &mut request,
        |server, _, _, request: &mut LaunchOverride| {
            // SAFETY: the caller's contract.
            let information = unsafe { &mut *request.information };
            if let Some(title) =
                commands::system::launch_override(&server.state, information.reason())
            {
                information.set_title(&title);
                request.replaced = true;
            }
            0
        },
    );
    if request.replaced && newer_system_software() {
        // SAFETY: as on the server; the server just used it.
        let information = unsafe { &mut *request.information };
        if information.reason() == REASON_DISC && is_disc_image(&information.image) {
            wait_for_disc(&information.image, DISC_WAIT_MS);
        }
        information.extra = 0;
    }

    0
}
