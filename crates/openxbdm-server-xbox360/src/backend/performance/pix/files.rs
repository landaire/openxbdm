//! PIX capture file (stock 0x91f98ef0) and resource capture file (stock
//! 0x91f98ef4): opened through the drive table on the server thread,
//! written with records `{type | 0x80000000, dwords + 2}` and their data.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::Server;
use openxbdm_server::commands::filesystem;
use openxbdm_server::commands::filesystem::CreateDisposition;
use openxbdm_server::commands::filesystem::CreateOptions;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::FileAccess;
use openxbdm_server::commands::filesystem::FileAttributes;
use openxbdm_server::commands::filesystem::ShareAccess;
use xbox360_sys::xam;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;

use super::session;
use super::status;
use super::status::Status;
use crate::backend::Console;
use crate::backend::dispatcher;
use crate::kernel;
use crate::net::XamNetwork;

/// An open capture file handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct CaptureFile(pub(super) u32);

/// Stock keeps -1 in the handle words while no file is open.
const NO_FILE: u32 = u32::MAX;
static CAPTURE: AtomicU32 = AtomicU32::new(NO_FILE);
static RESOURCE: AtomicU32 = AtomicU32::new(NO_FILE);
/// Resource capture: bytes written, truncation requested, and the flag of
/// `resource_capture_begin` (stock 0x91fa2a9c, 0x91fa2aa0, 0x91fa2a74).
static RESOURCE_BYTES: AtomicU32 = AtomicU32::new(0);
static RESOURCE_TRUNCATED: AtomicBool = AtomicBool::new(false);
static RESOURCE_FLAG: AtomicU32 = AtomicU32::new(0);
/// Resource capture size limit before the engine is asked to truncate.
const RESOURCE_LIMIT: u32 = 0x2000_0000;
const RECORD_FLAG: u32 = 0x8000_0000;
/// Plugin data record type.
const PLUGIN_RECORD: u32 = 0x8000_0020;
/// Header and end records of the resource capture file.
const RESOURCE_HEADER: u32 = 0x0100_006f;
const RESOURCE_END: u32 = 0x0100_0018;
const RESOURCE_TIMER: u32 = 0x7f;
/// Session message that truncates a resource capture.
const MESSAGE_TRUNCATE: u32 = 0xf;
const PATH_CAPACITY: usize = 0x104;

pub(super) fn capture_file() -> Option<CaptureFile> {
    Some(CAPTURE.load(Ordering::Acquire))
        .filter(|&handle| handle != NO_FILE)
        .map(CaptureFile)
}

pub(super) fn resource_file() -> Option<CaptureFile> {
    Some(RESOURCE.load(Ordering::Acquire))
        .filter(|&handle| handle != NO_FILE)
        .map(CaptureFile)
}

/// Write `bytes` at the current position unless output is discarded
/// (stock 0x91f55128).
pub(super) fn write(file: CaptureFile, data: u32, length: u32) -> u32 {
    if super::discard_output() {
        return 0;
    }
    let mut io_status = IoStatusBlock::default();
    // SAFETY: the handle is an open capture file and callers pass `length`
    // readable bytes at `data`; the write is synchronous.
    unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(file.0),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            data as usize as *const u8,
            length,
            core::ptr::null(),
        )
    }
    .0
}

pub(super) fn write_words(file: CaptureFile, words: &[u32]) -> u32 {
    write(
        file,
        words.as_ptr() as usize as u32,
        (words.len() * 4) as u32,
    )
}

/// Writer handed to the counter plugin (stock 0x91f55968): a plugin record
/// in the capture file.
pub(super) extern "C" fn plugin_write(data: u32, length: u32) {
    if let Some(file) = capture_file() {
        write_words(file, &[PLUGIN_RECORD, (length >> 2) + 2]);
        write(file, data, length);
    }
}

/// Request of [`open`] on the server thread.
struct OpenRequest {
    name: u32,
    in_pix_directory: bool,
    handle: u32,
}

/// Open capture file `name` (stock 0x91f55180). A name without a drive
/// goes to `E:\pix` when `in_pix_directory` is set or for
/// `crashdump.pix2`, else to `D:`. `None` when it cannot be created.
pub(super) fn open(name: u32, in_pix_directory: bool) -> Option<CaptureFile> {
    let mut request = OpenRequest {
        name,
        in_pix_directory,
        handle: NO_FILE,
    };
    dispatcher::call_on_server(
        open_on_server,
        core::ptr::from_mut(&mut request) as usize as u32,
    )?;
    Some(request.handle)
        .filter(|&handle| handle != NO_FILE)
        .map(CaptureFile)
}

fn c_string(address: u32) -> &'static [u8] {
    let mut length = 0;
    while super::read_u8(address + length as u32) != 0 {
        length += 1;
    }
    // SAFETY: a NUL-terminated string of `length` bytes.
    unsafe { core::slice::from_raw_parts(address as usize as *const u8, length) }
}

fn open_on_server(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    argument: u32,
) -> u32 {
    // SAFETY: the poster waits in `call_on_server` while the request lives.
    let request = unsafe { &mut *(argument as usize as *mut OpenRequest) };
    let name = c_string(request.name);
    let mut path = [0u8; PATH_CAPACITY];
    let mut length = 0;
    let mut push = |bytes: &[u8]| {
        // Stock formats with a 0x104-byte bound and no terminator past it.
        let count = bytes.len().min(PATH_CAPACITY - 1 - length);
        path[length..length + count].copy_from_slice(&bytes[..count]);
        length += count;
    };
    if name.contains(&b':') {
        push(name);
    } else {
        let directory: &[u8] =
            if !request.in_pix_directory && !name.eq_ignore_ascii_case(b"crashdump.pix2") {
                b"D:"
            } else {
                b"E:\\pix"
            };
        let create = CreateRequest {
            access: FileAccess(0x10_0001),
            allocation_size: None,
            attributes: FileAttributes(0x80),
            share: ShareAccess::NONE,
            disposition: CreateDisposition::Create,
            options: CreateOptions(0x21),
        };
        if let Ok(handle) = filesystem::open_translated(&server.state, console, directory, &create)
        {
            // SAFETY: the handle was just opened and is not used again.
            unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
        }
        push(directory);
        push(b"\\");
        push(name);
    }
    let create = CreateRequest {
        access: FileAccess(0x4010_0100),
        allocation_size: None,
        attributes: FileAttributes(0x80),
        share: ShareAccess::NONE,
        disposition: CreateDisposition::Supersede,
        options: CreateOptions(0x64),
    };
    match filesystem::open_translated(&server.state, console, &path[..length], &create) {
        Ok(handle) => request.handle = handle.0,
        Err(_) => {
            let mut message = [0u8; 0x140];
            let prefix = b"Unable to open PIX capture file: \"";
            let mut end = prefix.len();
            message[..end].copy_from_slice(prefix);
            for &byte in name.iter().take(message.len() - end - 4) {
                message[end] = byte;
                end += 1;
            }
            message[end..end + 2].copy_from_slice(b"\"\n");
            kernel::debug_print_bytes(&message[..end + 2]);
        }
    }
    0
}

/// Monitor control code 0x53 (stock 0x91f56130): open the capture file and
/// queue engine message 1 `{1, 0, file}`; 1 when queued.
pub(crate) fn service_open_for_capture(name: u32) -> u32 {
    let Some(file) = open(name, false) else {
        CAPTURE.store(NO_FILE, Ordering::Release);
        return 0;
    };
    CAPTURE.store(file.0, Ordering::Release);
    u32::from(session::post(1, &[1, 0, file.0]))
}

/// Monitor control code 0x54 (stock 0x91f561c0): open the capture file and
/// queue engine message 5 `{0, file, 0...}`. Stock returns a stale
/// register; this returns 0.
pub(crate) fn service_open_for_start(name: u32) -> u32 {
    match open(name, false) {
        Some(file) => {
            CAPTURE.store(file.0, Ordering::Release);
            session::post(5, &[0, file.0, 0, 0, 0, 0, 0]);
        }
        None => CAPTURE.store(NO_FILE, Ordering::Release),
    }
    0
}

/// Append `{type, dwords, data}` as a record to `file`.
fn write_record(file: CaptureFile, argument: u32) -> u32 {
    let kind = super::read_u32(argument);
    let dwords = super::read_u32(argument + 4);
    write_words(file, &[kind | RECORD_FLAG, dwords + 2]);
    write(file, super::read_u32(argument + 8), dwords << 2);
    dwords
}

/// Monitor control code 0x55 (stock 0x91f56238).
pub(crate) fn service_write_capture_record(argument: u32) -> u32 {
    let Some(file) = capture_file() else { return 0 };
    write_record(file, argument);
    1
}

/// Monitor control code 0x83 (stock 0x91f57e50): `{+0 path, +4 flag}`.
/// Stock returns a stale register; this returns 0.
pub(crate) fn service_resource_begin(argument: u32) -> u32 {
    let name = super::read_u32(argument);
    let flag = super::read_u32(argument + 4);
    RESOURCE_BYTES.store(0, Ordering::Release);
    RESOURCE_TRUNCATED.store(false, Ordering::Release);
    if resource_file().is_some() {
        kernel::debug_print(c"XBDM: A resource capature was initiated while another capture was still being recorded!\n");
        return 0;
    }
    let Some(file) = open(name, flag != 0) else {
        RESOURCE.store(NO_FILE, Ordering::Release);
        let mut message = [0u8; 0x140];
        let prefix = b"XBDM: Could not create resource capture file ";
        let mut end = prefix.len();
        message[..end].copy_from_slice(prefix);
        for &byte in c_string(name).iter().take(message.len() - end - 3) {
            message[end] = byte;
            end += 1;
        }
        message[end..end + 2].copy_from_slice(b".\n");
        if let Ok(text) = core::ffi::CStr::from_bytes_until_nul(&message) {
            kernel::debug_print(text);
        }
        return 0;
    };
    RESOURCE.store(file.0, Ordering::Release);
    write_words(file, &[RESOURCE_HEADER]);
    RESOURCE_FLAG.store(flag, Ordering::Release);
    // `{frequency, counter}` as stock lays out its two stack quadwords.
    let mut timer = [0u64; 2];
    // SAFETY: both point to quadwords of `timer`.
    unsafe {
        xam::QueryPerformanceCounter(&mut timer[1]);
        xam::QueryPerformanceFrequency(&mut timer[0]);
    }
    let record = [RESOURCE_TIMER, 4, timer.as_ptr() as usize as u32];
    service_resource_record(record.as_ptr() as usize as u32);
    0
}

/// Monitor control code 0x84 (stock 0x91f562c0): append a record; past 512
/// MiB the engine is asked once to truncate the capture.
pub(crate) fn service_resource_record(argument: u32) -> u32 {
    let Some(file) = resource_file() else {
        return 0;
    };
    let dwords = write_record(file, argument);
    let total = RESOURCE_BYTES
        .load(Ordering::Acquire)
        .wrapping_add((dwords + 2) << 2);
    RESOURCE_BYTES.store(total, Ordering::Release);
    if total >= RESOURCE_LIMIT && !RESOURCE_TRUNCATED.load(Ordering::Acquire) {
        let gpu = RESOURCE_FLAG.load(Ordering::Acquire) != 0 && super::gpu_capture_requested();
        if session::post(MESSAGE_TRUNCATE, &[0, 1, u32::from(gpu), 0, 0, 0]) {
            RESOURCE_TRUNCATED.store(true, Ordering::Release);
        }
    }
    1
}

/// Monitor control code 0x85 (stock 0x91f57f30): `{+0 notify}`.
pub(crate) fn service_resource_end(argument: u32) -> u32 {
    let Some(file) = resource_file() else {
        return 0;
    };
    write_words(file, &[RESOURCE_END]);
    // SAFETY: the resource file handle, closed once here. RESOURCE keeps
    // the stale value until the reset below, in stock order.
    unsafe { xboxkrnl::NtClose(Handle::from_raw(file.0)) };
    if super::read_u32(argument) != 0 {
        let result: &[u8] = if RESOURCE_TRUNCATED.load(Ordering::Acquire) {
            b"Trunc\0"
        } else {
            b"Complete\0"
        };
        status::post(Status::Resource, result.as_ptr() as usize as u32);
    }
    RESOURCE.store(NO_FILE, Ordering::Release);
    1
}

/// Whether a resource capture is open with its flag set (`pixcmd u 99`).
pub(super) fn resource_capture_flagged() -> bool {
    resource_file().is_some() && RESOURCE_FLAG.load(Ordering::Acquire) != 0
}

/// Title terminate part (stock 0x91f566f0): forget both files without
/// closing them.
pub(super) fn title_terminated() {
    CAPTURE.store(NO_FILE, Ordering::Release);
    RESOURCE.store(NO_FILE, Ordering::Release);
}

/// Replace the capture file handle (session start and stop paths).
pub(super) fn set_capture_file(file: Option<CaptureFile>) {
    CAPTURE.store(file.map_or(NO_FILE, |file| file.0), Ordering::Release);
}
