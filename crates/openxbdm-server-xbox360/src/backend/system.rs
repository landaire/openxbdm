//! Restart, clock, flash, the settings files, and the title launch
//! services of the debug monitor dispatcher.

pub(super) mod flash;

use core::fmt::Write as _;
use core::mem::offset_of;
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
use xbox360_sys::status::Severity;
use xbox360_sys::xam;
use xbox360_sys::xam::NotificationAreas;
use xbox360_sys::xam::XamLoaderGetDvdTrayState;
use xbox360_sys::xam::XamNotifyCreateListenerInternal;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::BugCheckCode;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FileInformationClass;
use xbox360_sys::xboxkrnl::FileNetworkOpenInformation;
use xbox360_sys::xboxkrnl::FirmwareRequest;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::HardwareBootFlags;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
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
use crate::kernel::pool_tag;
use crate::net::XamNetwork;
use xbox360_sys::xboxkrnl::CreateDisposition;

/// The settings file the monitor writes.
const SAVED_SETTINGS_PATH: &[u8] = b"\\SystemRoot\\MobileJ.dat";
/// Read at startup instead of the saved settings when it exists.
const INI_OVERRIDE_PATH: &[u8] = b"\\SystemRoot\\xbdm.ini";
const RECINT_PATH: &[u8] = b"\\SystemRoot\\recint.ini";
/// Write buffer of the settings writer, allocated per write as stock does.
const WRITE_BUFFER_SIZE: usize = 0x4000;
/// Write buffer of a settings copy to a caller's file.
const COPY_BUFFER_SIZE: usize = 0x1000;
/// Bug check code stock raises when a settings write fails.
const BUG_CHECK_SETTINGS_WRITE: BugCheckCode = BugCheckCode(0x2c);

const LAUNCH_STRING_SIZE: usize = 0x100;
const DISC_IMAGE_PREFIX: &[u8; 14] = b"\\Device\\Cdrom0";
/// Launch reason whose disc image may need the disc wait.
const REASON_DISC: LaunchReason = LaunchReason(4);
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

/// Launch information of the system software (codes 0x21 and 0x77).
#[repr(C)]
struct LaunchInformation {
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
struct XamGlobals {
    size: AtomicU32,
    launch_routine: AtomicU32,
    version: AtomicU32,
}

const _: () = assert!(size_of::<XamGlobals>() == 12);

impl XamGlobals {
    fn words(&self) -> [&AtomicU32; 3] {
        [&self.size, &self.launch_routine, &self.version]
    }
}

static XAM_GLOBALS: XamGlobals = XamGlobals {
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
    /// Pool block of a file destination, or the caller's memory. A pointer,
    /// not a slice: a pool block is uninitialized and the caller's memory
    /// is used only as stock uses it.
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

/// A pool block of `size` bytes for settings text.
fn allocate_buffer(size: usize) -> Option<*mut u8> {
    // SAFETY: the allocation takes only a size, tag and pool type.
    let address = unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(size as u32, pool_tag::BUFFER, PoolType::System)
    };
    (address != 0).then_some(address as usize as *mut u8)
}

fn create_file(
    path: &[u8],
    access: AccessMask,
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
            access,
            &attributes,
            &mut status_block,
            core::ptr::null(),
            FileAttributes::empty(),
            ShareAccess::empty(),
            disposition,
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
    let mut information = FileNetworkOpenInformation::default();
    // SAFETY: `attributes` and its name are live; `information` holds the
    // result.
    unsafe { xboxkrnl::NtQueryFullAttributesFile(&attributes, (&raw mut information).cast()) }
        .is_success()
}

impl WriteBuffer {
    /// # Safety
    /// `buffer` is writable for `capacity` bytes until the writer is
    /// dropped, and nothing else accesses it meanwhile.
    unsafe fn new(destination: Destination, handle: u32, buffer: *mut u8, capacity: usize) -> Self {
        Self {
            destination,
            handle,
            buffer,
            capacity,
            count: 0,
            total: 0,
        }
    }

    /// Buffer address as the pool routines and the bug check take it.
    fn address(&self) -> u32 {
        self.buffer as usize as u32
    }

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
        if status.severity() == Severity::Error {
            xboxkrnl::KeBugCheckEx(
                BUG_CHECK_SETTINGS_WRITE,
                status.0,
                self.handle,
                &status_block as *const IoStatusBlock as usize as u32,
                self.address(),
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
            // SAFETY: `new`'s contract makes `buffer` writable for
            // `capacity` bytes, and `count` fits after `self.count`.
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
                // SAFETY: `new`'s contract makes `buffer` writable for
                // `capacity` bytes, and `count` does not exceed it.
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
    if listener == Handle::NULL && super::console::trace_mask().contains(TraceMask::TITLE_LAUNCH) {
        kernel::debug_print(c"[xbdm] Failed to register for XAM notifications.\n");
    }
    0
}

/// Whether a launch string starts with `\Device\Cdrom0`, ignoring case
/// (stock `_strnicmp` with 14 bytes).
fn is_disc_image(image: &[u8; LAUNCH_STRING_SIZE]) -> bool {
    image[..DISC_IMAGE_PREFIX.len()].eq_ignore_ascii_case(DISC_IMAGE_PREFIX)
}

/// Stock 0x91f52040: wait for the disc tray to close, ask the system
/// software about the disc, and open the image once. The outcome is not
/// used; the wait is what matters.
fn wait_for_disc(image: &[u8; LAUNCH_STRING_SIZE], milliseconds: u32) {
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
    crate::xbox360::request_shutdown();
    0
}

/// Monitor control code 0x17 (stock 0x91f321d8): empty the settings file.
pub(crate) fn service_wipe_settings(_argument: u32) -> u32 {
    call_for_caller(CallerWork::WipeSettings);
    0
}

/// Request of control code 0x1d.
#[repr(C)]
struct SettingsCopyRequest {
    handle: u32,
    /// Out: bytes written.
    length: u32,
    /// Nonzero: the last write is a whole buffer.
    pad: u8,
}

const _: () = assert!(offset_of!(SettingsCopyRequest, pad) == 8);

/// Monitor control code 0x1d (stock 0x91f32110): write the settings text
/// to the caller's file.
///
/// # Safety
///
/// `argument` must be the address of a writable [`SettingsCopyRequest`]
/// the caller does not touch until the code returns.
pub(crate) unsafe fn service_write_settings_copy(argument: u32) -> u32 {
    let mut request = argument as usize as *mut SettingsCopyRequest;
    dispatcher::call_on_server_with(
        &mut request,
        |server, console, _, request: &mut *mut SettingsCopyRequest| {
            // SAFETY: the caller's contract.
            let request = unsafe { &mut **request };
            let copy = SettingsCopy::File {
                handle: request.handle,
                pad: request.pad != 0,
            };
            if let Some(length) = commands::system::copy_settings(&server.state, console, copy) {
                request.length = length;
            }
            0
        },
    );
    0
}

/// Request of control code 0x22.
#[repr(C)]
struct SettingsCaptureRequest {
    buffer: u32,
    /// In: buffer size. Out: bytes stored.
    length: u32,
}

/// Monitor control code 0x22 (stock 0x91f32080): store the settings text
/// in the caller's buffer.
///
/// # Safety
///
/// `argument` must be the address of a writable [`SettingsCaptureRequest`]
/// whose buffer holds `length` writable bytes, which the caller does not
/// touch until the code returns.
pub(crate) unsafe fn service_capture_settings(argument: u32) -> u32 {
    let mut request = argument as usize as *mut SettingsCaptureRequest;
    dispatcher::call_on_server_with(
        &mut request,
        |server, console, _, request: &mut *mut SettingsCaptureRequest| {
            // SAFETY: the caller's contract.
            let request = unsafe { &mut **request };
            let copy = SettingsCopy::Memory {
                address: request.buffer,
                capacity: request.length,
            };
            if let Some(length) = commands::system::copy_settings(&server.state, console, copy) {
                request.length = length;
            }
            0
        },
    );
    1
}

/// Server steps of a title reboot before the launch.
struct TitleReboot {
    reason: LaunchReason,
    /// Stays `Run` when the server is unavailable.
    stop: TitleRebootStop,
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
        && super::console::trace_mask().contains(TraceMask::TITLE_LAUNCH)
    {
        kernel::debug_print(c"[xbdm] DmpTitleReboot: DMN_EXEC_PENDING_TITLE state timed out\n");
    }
    if !released {
        monitor::request_execution(ExecutionState::Started, true);
    }
    call_for_caller(CallerWork::TitleReboot(information)).unwrap_or(0)
}

fn title_reboot_on_server(
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

/// Launch override of code 0x77, passed to the server thread.
struct LaunchOverride {
    /// The system software's launch information, which it does not touch
    /// until the code returns.
    information: *mut LaunchInformation,
    /// Set by the server when the launch information took the title.
    replaced: bool,
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

/// Result of an export whose server part could not run (on the server
/// thread, above passive level, or after code 0x02 stopped the server).
const SERVER_UNAVAILABLE: CommandError = CommandError::Fail;

/// Arguments of a title export, passed to the server thread. The paths
/// are the export's arguments: 0 or NUL-terminated strings the caller
/// keeps until the export returns, read only by the server step.
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
) -> Hresult {
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
