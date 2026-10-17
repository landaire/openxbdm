//! Restart, clock, flash, the settings files, and the title launch
//! services of the debug monitor dispatcher.

pub(super) mod flash;

use core::ffi::CStr;
use core::ffi::c_char;
use core::fmt::Write as _;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use openxbdm_server::Server;
use openxbdm_server::commands;
use openxbdm_server::commands::console::TraceMask;
use openxbdm_server::commands::filesystem::CreateDisposition;
use openxbdm_server::commands::filesystem::FileAccess;
use openxbdm_server::commands::system::BootFlags;
use openxbdm_server::commands::system::CreateSettingsError;
use openxbdm_server::commands::system::FlashOptions;
use openxbdm_server::commands::system::LaunchReason;
use openxbdm_server::commands::system::LaunchTitle;
use openxbdm_server::commands::system::RebootKind;
use openxbdm_server::commands::system::SettingsCopy;
use openxbdm_server::commands::system::SettingsFile;
use openxbdm_server::commands::system::SettingsSource;
use openxbdm_server::commands::system::TitleFlags;
use openxbdm_server::commands::system::TitleRebootStop;
use openxbdm_server::notify::ExecutionState;
use openxbdm_server::reply;
use openxbdm_server::reply::CommandError;
use openxbdm_server::text::Text;
use xbox360::console::hardware_flags;
use xbox360::module::Ordinal;
use xbox360::time::sleep;
use xbox360_sys::xam;
use xbox360_sys::xam::XamLoaderGetDvdTrayState;
use xbox360_sys::xam::XamNotifyCreateListenerInternal;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::BugCheckCode;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::FirmwareRequest;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::HardwareBootFlags;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ShareAccess;

use self::flash::FlashImage;
use super::Console;
use super::debugger as monitor;
use super::dispatcher;
use super::network;
use super::session;
use crate::exports::export;
use crate::kernel;
use crate::net::XamNetwork;

/// The settings file the monitor writes.
const SAVED_SETTINGS_PATH: &[u8] = b"\\SystemRoot\\MobileJ.dat";
/// Read at startup instead of the saved settings when it exists.
const INI_OVERRIDE_PATH: &[u8] = b"\\SystemRoot\\xbdm.ini";
const RECINT_PATH: &[u8] = b"\\SystemRoot\\recint.ini";
/// Write buffer of the settings writer, allocated per write as stock does.
const WRITE_BUFFER_SIZE: usize = 0x4000;
/// Write buffer of a settings copy to a caller's file.
const COPY_BUFFER_SIZE: usize = 0x1000;
const POOL_TAG: PoolTag = PoolTag::new(*b"mdbX");
/// Bug check code stock raises when a settings write fails.
const BUG_CHECK_SETTINGS_WRITE: BugCheckCode = BugCheckCode(0x2c);
/// Size of the network open information stock queries for the size of the
/// settings file; the low dword of the end of file is at +0x2c.
const NETWORK_OPEN_INFORMATION_SIZE: usize = 0x38;
const END_OF_FILE_LOW: usize = 0x2c;

/// Launch information of the system software (codes 0x21 and 0x77):
/// reason at +0, then three 0x100-byte strings and a dword.
const LAUNCH_IMAGE: u32 = 0x10;
const LAUNCH_DRIVE: u32 = 0x110;
const LAUNCH_COMMAND_LINE: u32 = 0x210;
const LAUNCH_STRING_SIZE: u32 = 0x100;
/// Dword cleared for system software newer than [`XAM_VERSION_BASE`].
const LAUNCH_EXTRA: u32 = 0x310;
const DISC_IMAGE_PREFIX: &[u8] = b"\\Device\\Cdrom0";
/// Version assumed when the system software registers without one.
const XAM_VERSION_BASE: u32 = 0x2007_6000;
/// System software below this version needs the disc wait at a title
/// reboot.
const XAM_VERSION_DISC_WAIT: u32 = 0x2018_3800;
/// Longest disc wait of a launch, polled every 100 ms.
const DISC_WAIT_MS: u32 = 5000;
const DISC_POLL_MS: u32 = 100;
/// XAM export queried before a disc image is opened (stock 0x91f52040).
const XAM_DISC_QUERY: Ordinal = Ordinal::new(0x1a3).unwrap();

/// Registration of code 0x20 (stock 0x91fa2004): size, title launch
/// routine, system software version, as copied from the caller.
static XAM_GLOBALS: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
/// Version of the registered system software (stock 0x91fa2000).
static XAM_VERSION: AtomicU32 = AtomicU32::new(0);
/// XAM disc query routine and the flag of its one-time lookup (stock
/// 0x91fa1ff8, 0x91fa1ffc).
static DISC_QUERY: AtomicU32 = AtomicU32::new(0);
static DISC_QUERY_LOOKED_UP: AtomicBool = AtomicBool::new(false);

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

/// Where buffered settings text goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Destination {
    /// A file the monitor opened.
    File,
    /// A caller's file; with `pad`, the last write is a whole buffer.
    CallerFile { pad: bool },
    /// A caller's memory buffer.
    Memory,
}

/// Settings text being written.
struct WriteBuffer {
    destination: Destination,
    handle: u32,
    buffer: *mut u8,
    capacity: usize,
    count: usize,
    /// Bytes written out so far.
    total: u32,
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

fn is_error(status: u32) -> bool {
    status & 0xc000_0000 == 0xc000_0000
}

fn read_u32(address: u32) -> u32 {
    // SAFETY: the caller of the control code passed this address.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn write_u32(address: u32, value: u32) {
    // SAFETY: the caller of the control code passed this address.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

fn create_file(
    path: &[u8],
    access: FileAccess,
    disposition: CreateDisposition,
) -> Result<u32, KernelError> {
    let name = kernel::ansi_string(path);
    let attributes = ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: &name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    let mut status_block = IoStatusBlock::default();
    let mut handle = 0u32;
    // SAFETY: `handle`, `attributes`, the name it refers to and
    // `status_block` are live locals.
    let status = unsafe {
        xboxkrnl::NtCreateFile(
            (&raw mut handle).cast(),
            AccessMask::from_bits_retain(access.0),
            &attributes,
            &mut status_block,
            core::ptr::null(),
            FileAttributes::empty(),
            ShareAccess::empty(),
            super::filesystem::kernel_disposition(disposition),
            CreateOptions::SYNCHRONOUS_IO_NONALERT,
        )
    };
    status.result()?;
    Ok(handle)
}

fn file_exists(path: &[u8]) -> bool {
    let name = kernel::ansi_string(path);
    let attributes = ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: &name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    let mut information = [0u8; 0x38];
    // SAFETY: `attributes` and its name are live; `information` holds the
    // 0x38-byte result.
    (unsafe { xboxkrnl::NtQueryFullAttributesFile(&attributes, information.as_mut_ptr()) }.0 as i32)
        >= 0
}

impl WriteBuffer {
    /// Write `length` buffered bytes. A failure stops the console, as in
    /// stock.
    fn write_out(&self, length: usize) {
        let mut status_block = IoStatusBlock::default();
        // SAFETY: `handle` is open and `buffer` holds at least `length`
        // bytes; the file is synchronous.
        let status = unsafe {
            xboxkrnl::NtWriteFile(
                Handle::from_raw(self.handle),
                Handle::NULL,
                0,
                0,
                &mut status_block,
                self.buffer,
                length as u32,
                core::ptr::null(),
            )
        };
        if is_error(status.0) {
            xboxkrnl::KeBugCheckEx(
                BUG_CHECK_SETTINGS_WRITE,
                status.0,
                self.handle,
                &status_block as *const IoStatusBlock as usize as u32,
                self.buffer as usize as u32,
            );
        }
    }

    /// Append bytes, writing out each filled buffer (stock 0x91f31860).
    /// Stock bug checks when a memory copy outgrows its buffer, since it
    /// writes the full buffer to handle 0; the excess is dropped instead.
    fn append(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let count = bytes.len().min(self.capacity - self.count);
            if count == 0 {
                return;
            }
            // SAFETY: the buffer holds `capacity` bytes and `count` fits
            // after `self.count`.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.buffer.add(self.count), count)
            };
            self.count += count;
            bytes = &bytes[count..];
            if self.count == self.capacity && self.destination != Destination::Memory {
                self.write_out(self.capacity);
                self.total += self.capacity as u32;
                self.count = 0;
            }
        }
    }

    /// Write out the rest (stock 0x91f31860 with no data). A padded write
    /// sends the whole buffer; stock sends whatever the buffer held after
    /// the text, which is zeroed here.
    fn finish(&mut self) {
        if self.count == 0 {
            return;
        }
        self.total += self.count as u32;
        let length = match self.destination {
            Destination::CallerFile { pad: true } => {
                // SAFETY: the buffer holds `capacity` bytes.
                unsafe {
                    core::ptr::write_bytes(
                        self.buffer.add(self.count),
                        0,
                        self.capacity - self.count,
                    )
                };
                self.capacity
            }
            _ => self.count,
        };
        self.write_out(length);
        self.count = 0;
    }
}

impl commands::system::Backend for Console {
    fn create_settings(&mut self) -> Result<SettingsFile, CreateSettingsError> {
        // SAFETY: the allocation takes only a size, tag and pool type.
        let buffer = unsafe {
            xboxkrnl::ExAllocatePoolTypeWithTag(
                WRITE_BUFFER_SIZE as u32,
                POOL_TAG,
                PoolType::System,
            )
        } as usize as *mut u8;
        if buffer.is_null() {
            return Err(CreateSettingsError::NoBuffer);
        }
        let handle = match create_file(
            SAVED_SETTINGS_PATH,
            FileAccess::GENERIC_WRITE.union(FileAccess::SYNCHRONIZE),
            CreateDisposition::OverwriteIf,
        ) {
            Ok(handle) => handle,
            Err(status) => {
                // SAFETY: `buffer` was allocated above and is not stored.
                unsafe { xboxkrnl::ExFreePool(buffer as usize as u32) };
                return Err(CreateSettingsError::Create(status));
            }
        };
        self.system.write = Some(WriteBuffer {
            destination: Destination::File,
            handle,
            buffer,
            capacity: WRITE_BUFFER_SIZE,
            count: 0,
            total: 0,
        });
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
        let mut information = [0u8; NETWORK_OPEN_INFORMATION_SIZE];
        // SAFETY: `information` holds the size passed; `status_block` is a
        // live local.
        let status = unsafe {
            xboxkrnl::NtQueryInformationFile(
                Handle::from_raw(file.0),
                &mut status_block,
                information.as_mut_ptr(),
                NETWORK_OPEN_INFORMATION_SIZE as u32,
                FileInformationClass::NetworkOpen,
            )
        };
        status.result()?;
        let low = &information[END_OF_FILE_LOW..END_OF_FILE_LOW + 4];
        Ok(u32::from_be_bytes([low[0], low[1], low[2], low[3]]))
    }

    fn begin_settings_copy(&mut self, copy: SettingsCopy) -> Option<SettingsFile> {
        let write = match copy {
            SettingsCopy::File { handle, pad } => {
                // SAFETY: the allocation takes only a size, tag and pool type.
                let buffer = unsafe {
                    xboxkrnl::ExAllocatePoolTypeWithTag(
                        COPY_BUFFER_SIZE as u32,
                        POOL_TAG,
                        PoolType::System,
                    )
                } as usize as *mut u8;
                if buffer.is_null() {
                    return None;
                }
                WriteBuffer {
                    destination: Destination::CallerFile { pad },
                    handle,
                    buffer,
                    capacity: COPY_BUFFER_SIZE,
                    count: 0,
                    total: 0,
                }
            }
            SettingsCopy::Memory { address, capacity } => WriteBuffer {
                destination: Destination::Memory,
                handle: address,
                buffer: address as usize as *mut u8,
                capacity: capacity as usize,
                count: 0,
                total: 0,
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
                unsafe { xboxkrnl::ExFreePool(write.buffer as usize as u32) };
                write.total
            }
        }
    }

    fn open_settings(&mut self, source: SettingsSource) -> Option<SettingsFile> {
        let path = match source {
            SettingsSource::Saved if file_exists(INI_OVERRIDE_PATH) => INI_OVERRIDE_PATH,
            SettingsSource::Saved => SAVED_SETTINGS_PATH,
            SettingsSource::Recint => RECINT_PATH,
        };
        create_file(
            path,
            FileAccess::GENERIC_READ.union(FileAccess::SYNCHRONIZE),
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
        ((status.0 as i32) >= 0).then_some(status_block.information as usize)
    }

    fn close_settings(&mut self, file: SettingsFile) {
        if let Some(mut write) = self.system.write.take_if(|write| write.handle == file.0) {
            write.finish();
            // SAFETY: the writer owns the file handle and the pool buffer of
            // a file destination.
            unsafe {
                xboxkrnl::NtClose(Handle::from_raw(write.handle));
                xboxkrnl::ExFreePool(write.buffer as usize as u32);
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

    fn hardware_flags(&mut self) -> u32 {
        hardware_flags().bits()
    }

    /// A registration without the version dword cannot relaunch.
    fn title_launch_registered(&mut self) -> bool {
        XAM_GLOBALS[2].load(Ordering::Acquire) != 0
    }

    fn launch_title(&mut self) {
        self.system.relaunched = true;
        let routine = XAM_GLOBALS[1].load(Ordering::Acquire);
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

/// Stock assertion trap of the registration (`twi 31, 0, 0x19`).
fn assertion_trap() {
    // SAFETY: raises the trap exception stock raises; the debug routine
    // or the kernel handles it.
    unsafe { core::arch::asm!("twi 31, 0, 0x19") };
}

/// Monitor control code 0x20 (stock 0x91f51df8): the system software
/// registers its globals: `{size >= 8, title launch routine, version}`.
pub(crate) fn service_register_xam_globals(argument: u32) -> u32 {
    if argument == 0 || read_u32(argument) < 8 {
        assertion_trap();
    }
    let size = read_u32(argument).min(12) as usize;
    let mut bytes = [0u8; 12];
    for (index, word) in XAM_GLOBALS.iter().enumerate() {
        bytes[index * 4..index * 4 + 4]
            .copy_from_slice(&word.load(Ordering::Relaxed).to_be_bytes());
    }
    // SAFETY: the caller's structure holds `size` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(argument as usize as *const u8, bytes.as_mut_ptr(), size)
    };
    for (index, word) in XAM_GLOBALS.iter().enumerate() {
        let value = u32::from_be_bytes([
            bytes[index * 4],
            bytes[index * 4 + 1],
            bytes[index * 4 + 2],
            bytes[index * 4 + 3],
        ]);
        word.store(value, Ordering::Release);
    }
    let version = if XAM_GLOBALS[0].load(Ordering::Relaxed) <= 8 {
        XAM_VERSION_BASE
    } else {
        let version = XAM_GLOBALS[2].load(Ordering::Relaxed);
        if version <= XAM_VERSION_BASE {
            assertion_trap();
        }
        version
    };
    XAM_VERSION.store(version, Ordering::Release);
    // Stock keeps the listener handle but never reads it.
    // SAFETY: the listener takes no caller memory.
    if unsafe { XamNotifyCreateListenerInternal(1, 1, 0xa) } == Handle::NULL
        && super::console::trace_mask().contains(TraceMask::TITLE_LAUNCH)
    {
        kernel::debug_print(c"[xbdm] Failed to register for XAM notifications.\n");
    }
    0
}

/// Whether the NUL-terminated string at `address` starts with
/// `\Device\Cdrom0`, ignoring case (stock `_strnicmp` with 14 bytes).
fn is_disc_image(address: u32) -> bool {
    DISC_IMAGE_PREFIX
        .iter()
        .enumerate()
        .all(|(index, expected)| {
            // SAFETY: the launch information string holds 0x100 bytes.
            let byte = unsafe { core::ptr::read_volatile((address as usize + index) as *const u8) };
            byte.eq_ignore_ascii_case(expected)
        })
}

/// Stock 0x91f52040: wait for the disc tray to close, ask the system
/// software about the disc, and open the image once. The outcome is not
/// used; the wait is what matters.
fn wait_for_disc(image: u32, milliseconds: u32) {
    if DISC_QUERY.load(Ordering::Acquire) == 0
        && !DISC_QUERY_LOOKED_UP.swap(true, Ordering::AcqRel)
        && let Some(address) = network::xam_procedure(XAM_DISC_QUERY)
    {
        DISC_QUERY.store(address, Ordering::Release);
    }
    let mut polls = milliseconds / DISC_POLL_MS;
    let mut tray = XamLoaderGetDvdTrayState();
    while polls != 0 && tray != 0 {
        sleep(Duration::from_millis(u64::from(DISC_POLL_MS)));
        polls -= 1;
        tray = XamLoaderGetDvdTrayState();
    }
    if tray != 0 {
        kernel::debug_print(c"[xbdm] Timed-out waiting for media detect\n");
        return;
    }
    let query = DISC_QUERY.load(Ordering::Acquire);
    if query != 0 {
        let mut media = 0u32;
        let mut kind = 0u32;
        // SAFETY: XAM export 0x1a3 takes two output dwords.
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
    let length = (0..LAUNCH_STRING_SIZE as usize)
        // SAFETY: the launch information string holds 0x100 bytes.
        .position(
            |index| unsafe { core::ptr::read_volatile((image as usize + index) as *const u8) } == 0,
        )
        .unwrap_or(LAUNCH_STRING_SIZE as usize);
    // SAFETY: `length` bytes at `image` were just read.
    let path = unsafe { core::slice::from_raw_parts(image as usize as *const u8, length) };
    let name = kernel::ansi_string(path);
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
    if (status.0 as i32) >= 0 {
        // SAFETY: `handle` was opened above and is closed once.
        unsafe { xboxkrnl::NtClose(handle) };
    }
}

/// Store a title into launch information as stock's `strncpy` of 0x100
/// bytes with a forced terminator does.
fn write_launch_info(argument: u32, title: &LaunchTitle) {
    for (offset, text) in [
        (LAUNCH_IMAGE, &title.image),
        (LAUNCH_DRIVE, &title.drive),
        (LAUNCH_COMMAND_LINE, &title.command_line),
    ] {
        let bytes = text.as_bytes();
        let destination = (argument + offset) as usize as *mut u8;
        // SAFETY: each launch information string holds 0x100 bytes; the
        // text holds at most 0xff.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len());
            core::ptr::write_bytes(
                destination.add(bytes.len()),
                0,
                LAUNCH_STRING_SIZE as usize - bytes.len(),
            );
        }
    }
}

fn newer_system_software() -> bool {
    XAM_VERSION.load(Ordering::Acquire) > XAM_VERSION_BASE
}

/// A server request that carries the caller's process type: stock writes
/// or wipes the settings file on the calling thread unless it belongs to
/// the title process, which hands the work to the server thread.
struct CallerRequest<'a, T> {
    service: dispatcher::ServerService<T>,
    request: &'a mut T,
    title_process: bool,
}

fn call_for_caller<T>(request: &mut T, service: dispatcher::ServerService<T>) -> Option<u32> {
    let mut request = CallerRequest {
        service,
        request,
        title_process: xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE,
    };
    dispatcher::call_on_server_with(&mut request, serve_for_caller)
}

fn serve_for_caller<T>(
    server: &mut Server,
    console: &mut Console,
    network: &mut XamNetwork,
    request: &mut CallerRequest<'_, T>,
) -> u32 {
    console.system.title_caller = request.title_process;
    let result = (request.service)(server, console, network, request.request);
    console.system.title_caller = false;
    result
}

/// Monitor control code 0x02 (stock 0x91f3b208): prepare for a restart
/// and stop the server.
pub(crate) fn service_prepare_reboot(_argument: u32) -> u32 {
    call_for_caller(&mut (), prepare_reboot_on_server);
    0
}

fn prepare_reboot_on_server(
    server: &mut Server,
    console: &mut Console,
    network: &mut XamNetwork,
    _request: &mut (),
) -> u32 {
    commands::system::prepare_reboot(server, console, network);
    dispatcher::stop_serving();
    crate::xbox360::request_shutdown();
    0
}

/// Monitor control code 0x17 (stock 0x91f321d8): empty the settings file.
pub(crate) fn service_wipe_settings(_argument: u32) -> u32 {
    call_for_caller(&mut (), |server, console, _, _| {
        commands::system::wipe_settings(&server.state, console);
        0
    });
    0
}

/// Monitor control code 0x1d (stock 0x91f32110): write the settings text
/// to the caller's file `{+0 handle, +4 length out, +8 u8 pad}`.
pub(crate) fn service_write_settings_copy(argument: u32) -> u32 {
    let mut address = argument;
    dispatcher::call_on_server_with(&mut address, |server, console, _, address: &mut u32| {
        let argument = *address;
        // SAFETY: the caller's structure holds the pad byte at +8.
        let pad = unsafe { core::ptr::read_volatile((argument + 8) as usize as *const u8) } != 0;
        let copy = SettingsCopy::File {
            handle: read_u32(argument),
            pad,
        };
        if let Some(length) = commands::system::copy_settings(&server.state, console, copy) {
            write_u32(argument + 4, length);
        }
        0
    });
    0
}

/// Monitor control code 0x22 (stock 0x91f32080): store the settings text
/// in the caller's buffer `{+0 address, +4 size in, length out}`.
pub(crate) fn service_capture_settings(argument: u32) -> u32 {
    let mut address = argument;
    dispatcher::call_on_server_with(&mut address, |server, console, _, address: &mut u32| {
        let argument = *address;
        let copy = SettingsCopy::Memory {
            address: read_u32(argument),
            capacity: read_u32(argument + 4),
        };
        if let Some(length) = commands::system::copy_settings(&server.state, console, copy) {
            write_u32(argument + 4, length);
        }
        0
    });
    1
}

const STOP_RUN: u32 = 0;
const STOP_TIMED: u32 = 1;
const STOP_FOREVER: u32 = 2;

/// Monitor control code 0x21 after the controller rebind (stock
/// DmpTitleReboot 0x91f523a0): the system software launches a title.
/// Execution goes through pending_title, the launching thread may stop
/// there, and the launch information takes the monitor's launch title.
/// Returns 1 when it was replaced and the image exists. Each server step
/// runs where stock runs it relative to the execution changes, the disc
/// wait, and the stop.
pub(crate) fn service_title_reboot(argument: u32) -> u32 {
    session::reset_title_wait_statistics();
    if argument == 0 {
        monitor::request_execution(ExecutionState::PendingTitle, false);
        monitor::request_execution(ExecutionState::Started, true);
        return 0;
    }
    let mut reason = read_u32(argument);
    dispatcher::call_on_server_with(&mut reason, |server, console, _, reason: &mut u32| {
        commands::system::trace_title_reboot(&server.state, console, LaunchReason(*reason));
        0
    });
    monitor::request_execution(ExecutionState::PendingTitle, false);
    if reason == 4
        && XAM_VERSION.load(Ordering::Acquire) < XAM_VERSION_DISC_WAIT
        && is_disc_image(argument + LAUNCH_IMAGE)
    {
        wait_for_disc(argument + LAUNCH_IMAGE, DISC_WAIT_MS);
    }
    let stop =
        dispatcher::call_on_server_with(&mut reason, |server, console, _, reason: &mut u32| {
            match commands::system::title_reboot_stop(
                &mut server.state,
                console,
                LaunchReason(*reason),
            ) {
                TitleRebootStop::Run => STOP_RUN,
                TitleRebootStop::Stop { forever: false } => STOP_TIMED,
                TitleRebootStop::Stop { forever: true } => STOP_FOREVER,
            }
        });
    let released = match stop {
        Some(STOP_TIMED) => monitor::stop_at_pending_title(false),
        Some(STOP_FOREVER) => monitor::stop_at_pending_title(true),
        _ => false,
    };
    if matches!(stop, Some(STOP_TIMED | STOP_FOREVER))
        && !released
        && super::console::trace_mask().contains(TraceMask::TITLE_LAUNCH)
    {
        kernel::debug_print(c"[xbdm] DmpTitleReboot: DMN_EXEC_PENDING_TITLE state timed out\n");
    }
    if !released {
        monitor::request_execution(ExecutionState::Started, true);
    }
    let mut address = argument;
    call_for_caller(&mut address, |server, console, _, address: &mut u32| {
        let argument = *address;
        let reason = LaunchReason(read_u32(argument));
        let Some(title) = commands::system::title_reboot_launch(&mut server.state, console, reason)
        else {
            return 0;
        };
        write_launch_info(argument, &title);
        if newer_system_software() {
            write_u32(argument + LAUNCH_EXTRA, 0);
        }
        u32::from(commands::system::launch_image_exists(
            &server.state,
            console,
            title.image.as_bytes(),
        ))
    })
    .unwrap_or(0)
}

/// Monitor control code 0x77 (stock 0x91f52260): fill the launch
/// information with the monitor's launch title, if any.
pub(crate) fn service_launch_override(argument: u32) -> u32 {
    let mut address = argument;
    let replaced =
        dispatcher::call_on_server_with(&mut address, |server, _, _, address: &mut u32| {
            let argument = *address;
            match commands::system::launch_override(&server.state, LaunchReason(read_u32(argument)))
            {
                Some(title) => {
                    write_launch_info(argument, &title);
                    1
                }
                None => 0,
            }
        });
    if replaced == Some(1) && newer_system_software() {
        if read_u32(argument) == 4 && is_disc_image(argument + LAUNCH_IMAGE) {
            wait_for_disc(argument + LAUNCH_IMAGE, DISC_WAIT_MS);
        }
        write_u32(argument + LAUNCH_EXTRA, 0);
    }
    0
}

/// Result of an export whose server part could not run (on the server
/// thread, above passive level, or after code 0x02 stopped the server).
const SERVER_UNAVAILABLE: CommandError = CommandError::Fail;

/// A caller's NUL-terminated string; `None` for a null pointer.
fn caller_string<'a>(address: u32) -> Option<&'a [u8]> {
    // SAFETY: the export's caller passes a NUL-terminated string.
    (address != 0).then(|| unsafe { CStr::from_ptr(address as usize as *const c_char) }.to_bytes())
}

/// Arguments of a title export, passed to the server thread.
struct TitleArguments {
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
) -> u32 {
    call_for_caller(arguments, service).unwrap_or(Hresult::from(SERVER_UNAVAILABLE).0)
}

/// Exports 28 and 125: run the launch on the server thread. Stock calls
/// the relaunch routine on the caller's thread and then ends that thread
/// when it belongs to the title process (0x91f278a8).
fn launch_export(
    service: dispatcher::ServerService<TitleArguments>,
    arguments: &mut TitleArguments,
) -> u32 {
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
extern "C" fn reboot_export(flags: u32) -> u32 {
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
extern "C" fn launch_title_export(flags: u32, image: u32, drive: u32, command_line: u32) -> u32 {
    let mut arguments = TitleArguments::new(flags, image, drive, command_line);
    launch_export(
        |server, console, network, arguments| {
            console.system.relaunched = false;
            let result = commands::system::launch_from_paths(
                server,
                console,
                network,
                BootFlags::from_bits_retain(arguments.flags),
                caller_string(arguments.image),
                caller_string(arguments.drive),
                caller_string(arguments.command_line),
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
extern "C" fn set_title_export(dir: u32, name: u32, command_line: u32, flags: u32) -> u32 {
    let mut arguments = TitleArguments::new(flags, name, dir, command_line);
    call_with_arguments(
        |server, console, _, arguments| {
            let result = commands::system::set_title_from_paths(
                &mut server.state,
                console,
                caller_string(arguments.drive),
                caller_string(arguments.image),
                caller_string(arguments.command_line),
                TitleFlags::from_bits_retain(arguments.flags),
            );
            reply::hresult(result).0
        },
        &mut arguments,
    )
}
export!(81, set_title_export);

/// Stock export 42 (0x91f47208): export 81 with no flags.
extern "C" fn set_title_default_export(dir: u32, name: u32, command_line: u32) -> u32 {
    set_title_export(dir, name, command_line, 0)
}
export!(42, set_title_default_export);
