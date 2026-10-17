//! Restart, clock, flash, the settings files, and the title launch
//! services of the debug monitor dispatcher.

mod exports;
pub(super) mod flash;
mod launch;
mod settings;

use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use openxbdm_server::Server;
use openxbdm_server::commands;
use openxbdm_server::commands::system::CreateSettingsError;
use openxbdm_server::commands::system::FlashOptions;
use openxbdm_server::commands::system::RebootKind;
use openxbdm_server::commands::system::SettingsCopy;
use openxbdm_server::commands::system::SettingsFile;
use openxbdm_server::commands::system::SettingsSource;
use xbox360::console::hardware_flags;
use xbox360::time::sleep;
use xbox360_sys::xam;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::FileNetworkOpenInformation;
use xbox360_sys::xboxkrnl::FirmwareRequest;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::HardwareBootFlags;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::ProcessType;

use self::exports::TitleArguments;
use self::flash::FlashImage;
use self::launch::LaunchInformation;
use self::launch::XAM_GLOBALS;
use self::launch::title_reboot_on_server;
use self::settings::Destination;
use self::settings::WriteBuffer;
use self::settings::allocate_buffer;
use self::settings::create_file;
use self::settings::file_exists;
use super::Console;
use super::dispatcher;
use crate::kernel;
use crate::net::XamNetwork;

pub(crate) use self::launch::service_launch_override;
pub(crate) use self::launch::service_register_xam_globals;
pub(crate) use self::launch::service_title_reboot;
pub(crate) use self::settings::service_capture_settings;
pub(crate) use self::settings::service_write_settings_copy;

/// The settings file the monitor writes.
const SAVED_SETTINGS_PATH: &[u8] = b"\\SystemRoot\\MobileJ.dat";

/// Platform state of this domain.
pub struct Data {
    write: Option<WriteBuffer>,
    flash: Option<FlashImage>,
    /// The server request being served came from a thread of the title
    /// process.
    title_caller: bool,
    /// Set when the registered launch routine runs; exports 28 and 125
    /// clear it before their launch.
    relaunched: bool,
}

impl Data {
    pub const fn new() -> Self {
        Self {
            write: None,
            flash: None,
            title_caller: false,
            relaunched: false,
        }
    }
}

impl commands::system::Backend for Console {
    fn create_settings(&mut self) -> Result<SettingsFile, CreateSettingsError> {
        /// Write buffer of the settings writer, allocated per write as stock does.
        const WRITE_BUFFER_SIZE: usize = 0x4000;

        let buffer = allocate_buffer(WRITE_BUFFER_SIZE).ok_or(CreateSettingsError::NoBuffer)?;
        let handle = match create_file(
            SAVED_SETTINGS_PATH,
            AccessMask::GENERIC_WRITE.union(AccessMask::SYNCHRONIZE),
            CreateDisposition::OverwriteIf,
        ) {
            Ok(handle) => handle,
            Err(status) => {
                // SAFETY: `buffer` was allocated above and is not stored.
                unsafe { xboxkrnl::ExFreePool(buffer as usize as u32) };
                return Err(CreateSettingsError::Create(status));
            }
        };
        // SAFETY: the pool block holds WRITE_BUFFER_SIZE bytes and only the
        // writer uses it until `close_settings` frees it.
        let write =
            unsafe { WriteBuffer::new(Destination::File, handle, buffer, WRITE_BUFFER_SIZE) };
        self.system.write = Some(write);

        Ok(SettingsFile(handle))
    }

    fn booted_from_disc(&mut self) -> bool {
        kernel::hardware_info()
            .boot_flags
            .contains(HardwareBootFlags::FROM_DISC)
    }

    fn title_process_caller(&mut self) -> bool {
        self.system.title_caller
    }

    fn settings_file_size(&mut self, file: SettingsFile) -> Result<u32, KernelError> {
        let mut status_block = IoStatusBlock::default();
        let mut information = FileNetworkOpenInformation::default();
        // SAFETY: `information` holds the size passed; `status_block` is a
        // live local.
        let status = unsafe {
            xboxkrnl::NtQueryInformationFile(
                Handle::from_raw(file.0),
                &mut status_block,
                (&raw mut information).cast(),
                size_of::<FileNetworkOpenInformation>() as u32,
                FileInformationClass::NetworkOpen,
            )
        };
        status.result()?;

        // Stock reports the low dword of the size.
        Ok(information.end_of_file as u32)
    }

    fn begin_settings_copy(&mut self, copy: SettingsCopy) -> Option<SettingsFile> {
        /// Write buffer of a settings copy to a caller's file.
        const COPY_BUFFER_SIZE: usize = 0x1000;

        let write = match copy {
            SettingsCopy::File { handle, pad } => {
                let buffer = allocate_buffer(COPY_BUFFER_SIZE)?;
                // SAFETY: the pool block holds COPY_BUFFER_SIZE bytes and
                // only the writer uses it until `end_settings_copy` frees it.
                unsafe {
                    WriteBuffer::new(
                        Destination::CallerFile { pad },
                        handle,
                        buffer,
                        COPY_BUFFER_SIZE,
                    )
                }
            }
            // SAFETY: only control code 0x22 makes a memory copy; its caller
            // passes a buffer of `capacity` bytes that it does not touch
            // until the copy ends within the control code.
            SettingsCopy::Memory { address, capacity } => unsafe {
                WriteBuffer::new(
                    Destination::Memory,
                    address,
                    address as usize as *mut u8,
                    capacity as usize,
                )
            },
        };
        let file = SettingsFile(write.handle);
        self.system.write = Some(write);

        Some(file)
    }

    fn end_settings_copy(&mut self, file: SettingsFile) -> u32 {
        let Some(mut write) = self.system.write.take_if(|write| write.handle == file.0) else {
            return 0;
        };

        match write.destination {
            Destination::Memory => write.count as u32,
            _ => {
                write.finish();
                // SAFETY: a file copy owns the pool buffer allocated in
                // `begin_settings_copy`.
                unsafe { xboxkrnl::ExFreePool(write.address()) };
                write.total
            }
        }
    }

    fn open_settings(&mut self, source: SettingsSource) -> Option<SettingsFile> {
        /// Read at startup instead of the saved settings when it exists.
        const INI_OVERRIDE_PATH: &[u8] = b"\\SystemRoot\\xbdm.ini";
        const RECINT_PATH: &[u8] = b"\\SystemRoot\\recint.ini";

        let path = match source {
            SettingsSource::Saved if file_exists(INI_OVERRIDE_PATH) => INI_OVERRIDE_PATH,
            SettingsSource::Saved => SAVED_SETTINGS_PATH,
            SettingsSource::Recint => RECINT_PATH,
        };
        create_file(
            path,
            AccessMask::GENERIC_READ.union(AccessMask::SYNCHRONIZE),
            CreateDisposition::Open,
        )
        .ok()
        .map(SettingsFile)
    }

    fn write_settings(&mut self, file: SettingsFile, bytes: &[u8]) {
        if let Some(write) = self
            .system
            .write
            .as_mut()
            .filter(|write| write.handle == file.0)
        {
            write.append(bytes);
        }
    }

    fn read_settings(&mut self, file: SettingsFile, buffer: &mut [u8]) -> Option<usize> {
        let mut status_block = IoStatusBlock::default();
        // SAFETY: `buffer` is valid for its length; the file is synchronous.
        let status = unsafe {
            xboxkrnl::NtReadFile(
                Handle::from_raw(file.0),
                Handle::NULL,
                0,
                0,
                &mut status_block,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                core::ptr::null(),
            )
        };
        status
            .is_success()
            .then_some(status_block.information as usize)
    }

    fn close_settings(&mut self, file: SettingsFile) {
        if let Some(mut write) = self.system.write.take_if(|write| write.handle == file.0) {
            write.finish();
            // SAFETY: the writer owns the file handle and the pool buffer of
            // a file destination.
            unsafe {
                xboxkrnl::NtClose(Handle::from_raw(write.handle));
                xboxkrnl::ExFreePool(write.address());
            }
        } else {
            // SAFETY: `file` is a handle `open_settings` returned.
            unsafe { xboxkrnl::NtClose(Handle::from_raw(file.0)) };
        }
    }

    fn sleep_milliseconds(&mut self, milliseconds: u32) {
        sleep(Duration::from_millis(u64::from(milliseconds)));
    }

    /// Handlers run below dispatch level, so a normal restart uses the
    /// reboot routine rather than the halt routine.
    fn reboot(&mut self, kind: RebootKind) {
        // SAFETY: both requests restart the console.
        unsafe {
            xboxkrnl::HalReturnToFirmware(match kind {
                RebootKind::Normal => FirmwareRequest::RebootQuiesce,
                RebootKind::SmcReset => FirmwareRequest::SmcReset,
            })
        };
    }

    fn set_system_time(&mut self, file_time: u64) {
        let mut previous = 0u64;
        // SAFETY: `file_time` and `previous` are live locals.
        unsafe {
            xboxkrnl::NtSetSystemTime(&file_time, &mut previous);
            xam::NetDll_XnpNoteSystemTime(XnCaller::DebugMonitor);
        }
    }

    fn hardware_flags(&mut self) -> HardwareFlags {
        hardware_flags()
    }

    /// A registration without the version dword cannot relaunch.
    fn title_launch_registered(&mut self) -> bool {
        XAM_GLOBALS.version.load(Ordering::Acquire) != 0
    }

    fn launch_title(&mut self) {
        self.system.relaunched = true;
        let routine = XAM_GLOBALS.launch_routine.load(Ordering::Acquire);
        // SAFETY: the system software registered this routine through
        // control code 0x20; it takes one argument.
        unsafe { kernel::call_export(routine, 0, 0, 0, 0) };
    }

    fn flash_begin(&mut self, rounded_size: u32) -> bool {
        self.system.flash = FlashImage::allocate(rounded_size);

        self.system.flash.is_some()
    }

    fn flash_write(&mut self, offset: u32, bytes: &[u8]) {
        if let Some(image) = self.system.flash.as_mut() {
            let start = offset as usize;
            image.bytes_mut()[start..start + bytes.len()].copy_from_slice(bytes);
        }
    }

    fn flash_commit(&mut self, length: u32, options: FlashOptions) -> Result<(), Win32Error> {
        let Some(mut image) = self.system.flash.take() else {
            return Ok(());
        };

        image.bytes_mut()[length as usize..].fill(0);

        image.program(options.ignore_version_checking, options.stock_image)
    }

    fn flash_abort(&mut self) {
        self.system.flash = None;
    }
}

/// Server work whose caller's process type matters: stock writes or wipes
/// the settings file on the calling thread unless it belongs to the title
/// process, which hands the work to the server thread.
enum CallerWork<'a> {
    PrepareReboot,
    WipeSettings,
    TitleReboot(&'a mut LaunchInformation),
    Title {
        service: dispatcher::ServerService<TitleArguments>,
        arguments: &'a mut TitleArguments,
    },
}

struct CallerRequest<'a> {
    work: CallerWork<'a>,
    title_process: bool,
}

fn call_for_caller(work: CallerWork<'_>) -> Option<u32> {
    let mut request = CallerRequest {
        work,
        title_process: xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE,
    };

    dispatcher::call_on_server_with(&mut request, serve_for_caller)
}

fn serve_for_caller(
    server: &mut Server,
    console: &mut Console,
    network: &mut XamNetwork,
    request: &mut CallerRequest<'_>,
) -> u32 {
    console.system.title_caller = request.title_process;
    let result = match &mut request.work {
        CallerWork::PrepareReboot => prepare_reboot_on_server(server, console, network),
        CallerWork::WipeSettings => {
            commands::system::wipe_settings(&server.state, console);
            0
        }
        CallerWork::TitleReboot(information) => {
            title_reboot_on_server(server, console, information)
        }
        CallerWork::Title { service, arguments } => (*service)(server, console, network, arguments),
    };
    console.system.title_caller = false;

    result
}

/// Monitor control code 0x02 (stock 0x91f3b208): prepare for a restart
/// and stop the server.
pub(crate) fn service_prepare_reboot(_argument: u32) -> u32 {
    call_for_caller(CallerWork::PrepareReboot);

    0
}

fn prepare_reboot_on_server(
    server: &mut Server,
    console: &mut Console,
    network: &mut XamNetwork,
) -> u32 {
    commands::system::prepare_reboot(server, console, network);
    dispatcher::stop_serving();
    crate::thread::request_shutdown();

    0
}

/// Monitor control code 0x17 (stock 0x91f321d8): empty the settings file.
pub(crate) fn service_wipe_settings(_argument: u32) -> u32 {
    call_for_caller(CallerWork::WipeSettings);

    0
}
