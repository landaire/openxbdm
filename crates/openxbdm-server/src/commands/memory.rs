//! Memory, module, and image inspection commands.
// `Backend::read_memory` copies from addresses the debugger checked.
#![allow(unsafe_code)]

pub mod detour;
mod detour_commands;
mod error;
mod tracking;

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use xbox360_sys::image::XexHeaderKey;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use self::detour_commands::detour_command;
use self::detour_commands::detour_log_record;
use self::tracking::memory_tracking;
use crate::access::Access;
use crate::commands::console;
use crate::commands::console::c_string;
use crate::commands::filesystem;
use crate::commands::util;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::text::Text;
use crate::transfer_blocks::TransferBlock;

pub use self::detour_commands::DetourLogName;
pub(crate) use self::detour_commands::module_unloaded;
pub use self::error::MemoryError;
pub use self::error::NoSuchModule;
pub use self::error::XexFieldError;
pub use self::tracking::ACTIVE_STACK_DEPTH;
pub use self::tracking::StackDepth;
pub use self::tracking::TRACKING_TYPE_NAMES;
pub use self::tracking::TrackingFlags;
pub use self::tracking::TrackingSettings;
pub(crate) use self::tracking::ini_memtrack;
pub(crate) use self::tracking::memtrack_settings_lines;

/// Size of a small page in bytes.
pub const PAGE_SIZE: u32 = 0x1000;
/// Bytes of a module base name buffer, including the terminator.
pub const MODULE_NAME_CAPACITY: usize = 0x104;
/// Bytes of a section name.
pub const SECTION_NAME_LENGTH: usize = 8;
/// Bytes of a PDB path buffer, including the terminator.
pub const PDB_PATH_CAPACITY: usize = 0x104;
/// Bytes of the `name` buffer of `modsections`, `xexfield`, and `xbeinfo`.
const NAME_PARAMETER_CAPACITY: usize = 0x141;
/// Bytes of an executable path buffer, including the terminator.
pub const EXECUTABLE_PATH_CAPACITY: usize = 0x105;
/// Byte offset of the advanced memory flag word in the raw flash device.
pub const ADVANCED_MEMORY_FLASH_OFFSET: u32 = 6;

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry(
        "addtitlemem",
        DispatchFlags::empty(),
        additional_title_memory,
    ),
    entry("advmem", DispatchFlags::empty(), advanced_memory),
    entry("detour", DispatchFlags::DEVKIT_ONLY, detour_command),
    entry("getmem", DispatchFlags::empty(), get_memory),
    entry("getmemex", DispatchFlags::empty(), get_memory_binary),
    entry("memtrack", DispatchFlags::empty(), memory_tracking),
    entry("modsections", DispatchFlags::empty(), module_sections),
    entry("modules", DispatchFlags::empty(), modules),
    entry("pdbinfo", DispatchFlags::empty(), pdb_info),
    entry("setmem", DispatchFlags::DEVKIT_ONLY, set_memory),
    entry("traceimports", DispatchFlags::empty(), trace_imports),
    entry("walkmem", DispatchFlags::empty(), walk_memory),
    entry("xbeinfo", DispatchFlags::empty(), executable_info),
    entry("xexfield", DispatchFlags::empty(), xex_field),
];

/// Global state of this domain.
#[derive(Debug)]
pub struct State {
    /// Settings written to and loaded from the settings file.
    pub tracking: TrackingSettings,
    /// `detour start` file name, translated again by `detour stop` to
    /// delete the log (0x91f9f348).
    pub detour_log: DetourLogName,
}

impl State {
    pub const fn new() -> Self {
        Self {
            tracking: TrackingSettings {
                flags: TrackingFlags::empty(),
                stack_depth: StackDepth(0),
            },
            detour_log: DetourLogName::EMPTY,
        }
    }
}

/// A module base name as the monitor copies it: the low byte of each
/// UTF-16 unit, at most `MODULE_NAME_CAPACITY - 1` bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ModuleName {
    bytes: [u8; MODULE_NAME_CAPACITY],
    len: usize,
}

impl ModuleName {
    /// Copy the low byte of each unit, truncated to the capacity.
    pub fn from_units(units: impl IntoIterator<Item = u16>) -> Self {
        let mut name = Self {
            bytes: [0; MODULE_NAME_CAPACITY],
            len: 0,
        };

        for unit in units.into_iter().take(MODULE_NAME_CAPACITY - 1) {
            name.bytes[name.len] = unit as u8;
            name.len += 1;
        }

        name
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl core::fmt::Debug for ModuleName {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:?}", self.as_bytes().escape_ascii())
    }
}

/// A loaded module as `modules` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleInfo {
    pub name: ModuleName,
    pub base: u32,
    /// Image size recorded by the loader.
    pub size: u32,
    pub checksum: u32,
    pub timestamp: u32,
    /// Address and size of the exception directory, zero when absent.
    pub pdata: u32,
    pub pdata_size: u32,
    /// The image is a DLL.
    pub dll: bool,
    /// Image size from the optional header.
    pub image_size: u32,
}

/// A PE section header of a loaded module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionInfo {
    /// Section name, NUL-padded.
    pub name: [u8; SECTION_NAME_LENGTH],
    /// Module base plus the section's virtual address.
    pub address: u32,
    pub size: u32,
    /// PE section characteristics.
    pub characteristics: u32,
}

impl SectionInfo {
    /// Flags `modsections` reports for the characteristics.
    pub fn flags(&self) -> u32 {
        let mut flags = 0;
        if self.characteristics & 0x4000_0000 != 0 {
            flags |= 0x2;
        }
        if self.characteristics & 0x8000_0000 != 0 {
            flags |= 0x4;
        }
        if self.characteristics & 0x2000_0000 != 0 {
            flags |= 0x8;
        }
        if self.characteristics & 0x80 != 0 {
            flags |= 0x10;
        }

        flags
    }
}

/// One-based index of a section in its module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionIndex(pub u16);

/// Index into the modules `modules` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleIndex(pub u32);

/// A CodeView `RSDS` record of a loaded module.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CodeView {
    pub guid: [u8; 16],
    pub age: [u8; 4],

    path: [u8; PDB_PATH_CAPACITY],
    path_len: usize,
}

impl CodeView {
    /// `path` is truncated to `PDB_PATH_CAPACITY - 1` bytes and ends at the
    /// first NUL.
    pub fn new(guid: [u8; 16], age: [u8; 4], path: &[u8]) -> Self {
        Self::read(guid, age, |index| path.get(index).copied().unwrap_or(0))
    }

    /// As [`CodeView::new`] with the path read one byte at a time by
    /// `byte_at`, stopping at the first NUL.
    pub fn read(guid: [u8; 16], age: [u8; 4], mut byte_at: impl FnMut(usize) -> u8) -> Self {
        let mut view = Self {
            guid,
            age,
            path: [0; PDB_PATH_CAPACITY],
            path_len: 0,
        };

        while view.path_len < PDB_PATH_CAPACITY - 1 {
            let byte = byte_at(view.path_len);
            if byte == 0 {
                break;
            }

            view.path[view.path_len] = byte;
            view.path_len += 1;
        }

        view
    }

    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

impl core::fmt::Debug for CodeView {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CodeView")
            .field("guid", &self.guid)
            .field("age", &self.age)
            .field("path", &self.path().escape_ascii())
            .finish()
    }
}

/// Platform services this domain needs.
pub trait Backend {
    /// Whether the page containing `address` is mapped (`MmIsAddressValid`).
    fn is_address_valid(&mut self, address: u32) -> bool;
    /// Read one byte through the debugger mapping. `None` when the kernel
    /// refuses the read or maps the address to a device range.
    fn read_byte(&mut self, address: u32) -> Option<u8>;
    /// Write one byte through a writable debugger mapping and flush the
    /// instruction cache for it. Returns `false` when the address cannot be
    /// mapped writable.
    fn write_byte(&mut self, address: u32, value: u8) -> bool;
    /// Whether the debugger may read the page containing `address`.
    fn is_readable(&mut self, address: u32) -> bool;
    /// Copy memory whose pages [`Backend::is_readable`] accepted.
    ///
    /// # Safety
    ///
    /// [`Backend::is_readable`] accepted every page of the `output.len()`
    /// bytes at `address` (wrapping past 0xffffffff to 0) on this thread
    /// just before the call. A title may still unmap a page in between, as
    /// with stock.
    unsafe fn read_memory(&mut self, address: u32, output: &mut [u8]);

    /// The `index`th loaded module with an NT header, walking the loader's
    /// module list and then its second list.
    fn module(&mut self, index: ModuleIndex) -> Option<ModuleInfo>;
    /// A section of the loaded module whose base name exactly matches
    /// `name` ([`module_name_matches`]); `Ok(None)` past the last section.
    fn module_section(
        &mut self,
        name: &[u8],
        index: SectionIndex,
    ) -> Result<Option<SectionInfo>, NoSuchModule>;
    /// The CodeView record of the module loaded at `base`.
    fn code_view(&mut self, base: u32) -> Option<CodeView>;
    /// `RtlImageXexHeaderField` of the exactly named module: the field
    /// value for inline keys, else the field address.
    fn xex_header_field(
        &mut self,
        module: &[u8],
        field: XexHeaderKey,
    ) -> Result<u32, XexFieldError>;
    /// Copy bytes at `offset` of the data of a non-inline XEX header field.
    /// Fails with [`XexFieldError::FieldAbsent`] for bytes past the data.
    fn read_xex_header_field(
        &mut self,
        module: &[u8],
        field: XexHeaderKey,
        offset: u32,
        output: &mut [u8],
    ) -> Result<(), XexFieldError>;
    /// The running title's additional title memory (XEX header field
    /// 0x40801); `Ok(None)` when the field is absent.
    fn title_additional_memory(&mut self) -> Result<Option<u32>, NoSuchModule>;
    /// Object path of the running executable; returns its length.
    fn running_executable_path(&mut self, output: &mut [u8]) -> usize;

    /// Read bytes at `offset` of the raw flash device.
    fn read_flash(&mut self, offset: u32, output: &mut [u8]) -> Result<(), KernelError>;
    /// Write bytes at `offset` of the raw flash device.
    fn write_flash(&mut self, offset: u32, data: &[u8]) -> Result<(), KernelError>;

    /// Configure kernel import tracing for `module`; `false` when the
    /// kernel rejects the module name.
    fn trace_imports(&mut self, module: &[u8], enable: bool) -> bool;

    /// Allocation tracking flags in effect.
    fn tracking_flags(&mut self) -> TrackingFlags;
    fn set_tracking_flags(&mut self, flags: TrackingFlags);
    /// Write every allocation tracking record to `file`.
    fn write_tracking_records(&mut self, file: filesystem::FileHandle) -> Result<(), KernelError>;
    /// `RtlNtStatusToDosError`; `None` when the kernel translates `error`
    /// to `ERROR_SUCCESS`.
    fn dos_error_from_nt_status(&mut self, error: KernelError) -> Option<Win32Error>;

    /// Run `operation` with the detour engine and the platform services
    /// it uses.
    fn detour(&mut self, operation: &mut dyn FnMut(&detour::Engine, &dyn detour::Platform));
    /// Create the detour log writer and completion workers. `log` is the
    /// translated log file name, `None` when translation failed. The engine
    /// is starting; the writer opens the log and moves it to running or
    /// back to stopped. Fails when a worker cannot be created.
    fn start_detour_log(&mut self, log: Option<&[u8]>) -> Result<(), KernelError>;
    /// Shut down the workers after [`detour::Engine::begin_stop`], delete
    /// `log` when it translated, and return the engine to stopped.
    fn stop_detour_log(&mut self, log: Option<&[u8]>);
    /// Read the next record of the log; `false` when every written record
    /// was read or the read failed.
    fn read_detour_record(&mut self, output: &mut [u8; detour::RECORD_SIZE]) -> bool;
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    GetMemory {
        address: u32,
        remaining: u32,
    },
    GetMemoryBinary {
        address: u32,
        remaining: u32,
    },
    WalkMemory {
        cursor: u32,
        active: bool,
    },
    Modules {
        next: ModuleIndex,
    },
    /// The module name is held in `name`.
    Sections {
        name: TransferBlock,
        next: SectionIndex,
    },
    ExecutableInfo {
        path: TransferBlock,
        path_len: u16,
        line: ExecutableInfoLine,
    },
    /// The module name is held in `module`.
    XexField {
        module: TransferBlock,
        field: XexHeaderKey,
        value: u32,
        size: u32,
        remaining: u32,
    },
    /// `detour log getentries`: bytes of records still to send.
    DetourLog {
        remaining: u32,
    },
}

/// Next line of an `xbeinfo` reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableInfoLine {
    Header,
    Name,
    End,
}

/// Raw output into the continuation buffer.
struct RawWriter<'a> {
    buffer: &'a mut [u8],
    len: usize,
}

impl RawWriter<'_> {
    fn push_bytes(&mut self, bytes: &[u8]) {
        let end = (self.len + bytes.len()).min(self.buffer.len());
        let count = end - self.len;
        self.buffer[self.len..end].copy_from_slice(&bytes[..count]);
        self.len = end;
    }
}

impl core::fmt::Write for RawWriter<'_> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let end = self.len + text.len();
        let target = self.buffer.get_mut(self.len..end).ok_or(core::fmt::Error)?;
        target.copy_from_slice(text.as_bytes());
        self.len = end;

        Ok(())
    }
}

/// A valid virtual address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    base: u32,
    size: u32,
    protect: u32,
}

/// Whether `address` lies in a device range the debugger never accesses.
pub fn is_device_address(address: u32) -> bool {
    /// Physical ranges the debugger never reads (device registers). Bounds
    /// are inclusive.
    const DEVICE_RANGES: [(u32, u32); 6] = [
        (0x7fc8_0000, 0x7fc9_ffff),
        (0x7fd0_0000, 0x7fdf_ffff),
        (0x7fea_0000, 0x7fea_ffff),
        (0x7fed_0000, 0x7fed_ffff),
        (0x8fff_0000, 0x8fff_0fff),
        (0x8fff_1000, 0x8fff_1fff),
    ];

    DEVICE_RANGES
        .iter()
        .any(|&(low, high)| (low..=high).contains(&address))
}

/// Whether a loader entry base name (as UTF-16 units) matches `query` the
/// way the monitor's module lookup compares them: ASCII letters compare
/// without case, only the low byte of each unit counts, and an inexact
/// lookup also accepts `query` followed by an extension (`xam` for
/// `xam.xex`).
pub fn module_name_matches(name: impl IntoIterator<Item = u16>, query: &[u8], exact: bool) -> bool {
    let mut position = 0;
    for unit in name {
        let expected = query.get(position).copied().unwrap_or(0);
        let actual = unit as u8;
        if !actual.eq_ignore_ascii_case(&expected) {
            return !exact && expected == 0 && actual == b'.';
        }

        position += 1;
    }

    position == query.len()
}

/// The page after the one containing `address`: 4 KiB pages below
/// 0x40000000 and in 0x90000000-0x9fffffff, 64 KiB pages elsewhere.
pub fn next_page(address: u32) -> u32 {
    const LARGE_PAGE_SIZE: u32 = 0x1_0000;

    if address <= 0x3fff_ffff || (0x9000_0000..=0x9fff_ffff).contains(&address) {
        (address & !(PAGE_SIZE - 1)).wrapping_add(PAGE_SIZE)
    } else {
        (address & !(LARGE_PAGE_SIZE - 1)).wrapping_add(LARGE_PAGE_SIZE)
    }
}

const fn entry(
    name: &'static str,
    flags: DispatchFlags,
    handler: crate::registry::Handler,
) -> CommandEntry {
    CommandEntry::new(name, Access::CONTROL, Access::empty(), flags, handler)
}

pub(crate) fn resume(
    continuation: &mut Continuation,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    match continuation {
        Continuation::GetMemory { address, remaining } => get_memory_lines(address, remaining, cx),
        Continuation::GetMemoryBinary { address, remaining } => {
            get_memory_chunk(address, remaining, cx)
        }
        Continuation::WalkMemory { cursor, active } => walk_memory_lines(cursor, active, cx),
        Continuation::Modules { next } => module_line(next, cx),
        Continuation::Sections { name, next } => section_line(*name, next, cx),
        Continuation::ExecutableInfo {
            path,
            path_len,
            line,
        } => executable_info_line(*path, usize::from(*path_len), line, cx),
        Continuation::XexField {
            module,
            field,
            value,
            size,
            remaining,
        } => xex_field_line(*module, *field, *value, *size, remaining, cx),
        Continuation::DetourLog { remaining } => detour_log_record(remaining, cx),
    }
}

/// Copy a string parameter the way the monitor does; `None` when absent.
fn string_param<'b>(
    invocation: &Invocation<'_>,
    name: &str,
    output: &'b mut [u8],
) -> Option<&'b [u8]> {
    invocation
        .line
        .param(name)
        .map(|value| value.copy_into(output))
}

fn hex_digit(value: u8) -> u8 {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

    HEX_UPPER[usize::from(value & 0xf)]
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Bytes `xexfield` reports for `field`; `data_length` reads the leading
/// size word of its data. The key's low byte gives the form of the data:
/// 0 a value in the key entry, 0xff a leading size word, else that many
/// words.
fn xex_field_size(
    field: XexHeaderKey,
    data_length: impl FnOnce() -> Result<u32, XexFieldError>,
) -> Result<u32, XexFieldError> {
    match field.0 & 0xff {
        // The entry point is reported with its inline value as data.
        0 if field == XexHeaderKey::ENTRY_POINT => Ok(4),
        0 => Ok(0),
        0xff => data_length(),
        words => Ok(words << 2),
    }
}

/// `getmem addr=<dword> length=<dword>`: hex dump in 32-byte lines; bytes
/// of unmapped pages print as `??`.
fn get_memory(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let Some(address) = util::required_dword(invocation, "addr") else {
        return Err(util::MISSING);
    };
    let Some(length) = util::required_dword(invocation, "length") else {
        return Err(util::MISSING);
    };
    let Some(session) = invocation.session.as_deref_mut() else {
        return Err(CommandError::Fail);
    };

    session.receive_remaining = None;
    session.continuation = AnyContinuation::Memory(Continuation::GetMemory {
        address,
        remaining: length,
    });
    invocation.set_text(format_args!("memory data follows"));

    Ok(Reply::Multiline)
}

/// Write up to 16 lines of raw output. A byte whose read fails inside a
/// mapped page keeps the stale content of the output buffer, and the rest
/// of that page prints as `??`.
fn get_memory_lines(
    address: &mut u32,
    remaining: &mut u32,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    /// Lines emitted per continuation call.
    const LINES_PER_CALL: usize = 16;
    /// Bytes per line.
    const BYTES_PER_LINE: u32 = 32;

    if *remaining == 0 {
        return Err(CommandError::EndOfData);
    }

    let mut offset = 0usize;
    let mut page_valid = false;
    let mut checked_page = None;

    for _ in 0..LINES_PER_CALL {
        if *remaining == 0 {
            break;
        }

        let count = (*remaining).min(BYTES_PER_LINE);

        for _ in 0..count {
            let page = *address & !(PAGE_SIZE - 1);
            if checked_page != Some(page) {
                checked_page = Some(page);
                page_valid = cx.backend.is_address_valid(*address);
            }

            if page_valid {
                let byte = match cx.state.debugger.shadow_read(*address) {
                    Some(byte) => Some(byte),
                    None => cx.backend.read_byte(*address),
                };
                match byte {
                    Some(byte) => {
                        cx.binary[offset] = hex_digit(byte >> 4);
                        cx.binary[offset + 1] = hex_digit(byte);
                    }
                    None => {
                        page_valid = false;
                    }
                }
            } else {
                cx.binary[offset..offset + 2].copy_from_slice(b"??");
            }

            offset += 2;
            *address = address.wrapping_add(1);
        }

        cx.binary[offset..offset + 2].copy_from_slice(b"\r\n");
        offset += 2;
        *remaining -= count;
    }

    cx.binary_len = offset;

    Ok(Reply::Ok)
}

/// `setmem addr=<dword> data=<hex>`: write bytes until a page is invalid or
/// a byte cannot be written.
fn set_memory(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(address) = util::required_dword(invocation, "addr") else {
        return Err(util::MISSING);
    };

    let mut digits = invocation.line.param("data").map(|value| value.bytes());
    let mut written = 0u32;
    let mut current = address;
    let mut checked_page = None;

    let stopped = loop {
        let Some(high) = digits.as_mut().and_then(Iterator::next) else {
            break false;
        };
        let low = digits.as_mut().and_then(Iterator::next);
        let (Some(high), Some(low)) = (hex_value(high), low.and_then(hex_value)) else {
            invocation.text.set_bytes(b"400- syntax error in data");
            return Err(CommandError::Fail);
        };

        let page = current & !(PAGE_SIZE - 1);
        if checked_page != Some(page) {
            checked_page = Some(page);
            if !invocation.backend.is_address_valid(current) {
                break true;
            }
        }

        let value = high << 4 | low;
        if !invocation.state.debugger.shadow_write(current, value)
            && !invocation.backend.write_byte(current, value)
        {
            break true;
        }

        written += 1;
        current = current.wrapping_add(1);
    };

    invocation.set_text(format_args!("set {written} bytes"));

    if stopped {
        Err(ErrorCode::MemoryNotMapped.into())
    } else {
        Ok(Reply::Ok)
    }
}

/// `getmemex addr=<dword> length=<dword>`: binary chunks of at most 0x400
/// bytes, each after a little-endian u16 header.
/// The monitor looks up `ADDR` and `LENGTH`; the missing texts name them so.
fn get_memory_binary(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(address) = util::required_dword(invocation, "ADDR") else {
        return Err(util::MISSING);
    };
    let Some(length) = util::required_dword(invocation, "LENGTH") else {
        return Err(util::MISSING);
    };
    let Some(session) = invocation.session.as_deref_mut() else {
        return Err(CommandError::Fail);
    };

    session.continuation = AnyContinuation::Memory(Continuation::GetMemoryBinary {
        address,
        remaining: length,
    });

    Ok(Reply::Binary)
}

/// One chunk. The data ends at the first unreadable page, which also ends
/// the transfer; breakpoint bytes read as their saved originals. Stock
/// compares page addresses and so skips the check for a chunk that wraps
/// past 0xffffffff; every page is checked here.
fn get_memory_chunk(
    address: &mut u32,
    remaining: &mut u32,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    /// Data bytes per chunk.
    const CHUNK_SIZE: u32 = 0x400;
    /// Chunk header bit marking the final chunk.
    const LAST_CHUNK: u16 = 0x8000;

    if cx.aborted || *remaining == 0 {
        return Err(CommandError::EndOfData);
    }

    let start = *address;
    let requested = (*remaining).min(CHUNK_SIZE);
    let first_page = start & !(PAGE_SIZE - 1);
    let pages = ((start & (PAGE_SIZE - 1)) + requested - 1) / PAGE_SIZE + 1;
    let unreadable = (0..pages).find(|&index| {
        !cx.backend
            .is_readable(first_page.wrapping_add(index * PAGE_SIZE))
    });
    let (count, left) = match unreadable {
        None => (requested, *remaining - requested),
        Some(0) => (0, 0),
        Some(index) => {
            let page = first_page.wrapping_add(index * PAGE_SIZE);
            (page.wrapping_sub(start), 0)
        }
    };
    *address = start.wrapping_add(count);
    *remaining = left;

    let header = count as u16 | if *remaining == 0 { LAST_CHUNK } else { 0 };
    let data = &mut cx.binary[2..2 + count as usize];
    // SAFETY: `is_readable` accepted every page of the `count` bytes.
    unsafe { cx.backend.read_memory(start, data) };
    cx.state.debugger.restore_saved(start, data);

    cx.binary[..2].copy_from_slice(&header.to_le_bytes());
    cx.binary_len = count as usize + 2;

    Ok(Reply::Ok)
}

/// `walkmem`: every valid virtual range below 0xa0000000, excluding device
/// ranges.
fn walk_memory(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(session) = invocation.session.as_deref_mut() else {
        return Err(CommandError::Fail);
    };

    session.continuation = AnyContinuation::Memory(Continuation::WalkMemory {
        cursor: 0,
        active: true,
    });
    invocation.set_text(format_args!("Valid Virtual Address Ranges Follow"));

    Ok(Reply::Multiline)
}

/// The next region at or after `cursor`. A region can extend past the walk
/// limit; only its start is bounded.
fn next_region(backend: &mut dyn crate::backend::Backend, cursor: &mut u32) -> Option<Region> {
    /// No region starts at or above this address.
    const WALK_LIMIT: u32 = 0xa000_0000;

    loop {
        let base = *cursor;
        if base >= WALK_LIMIT {
            return None;
        }

        let mut end = base;
        if backend.is_address_valid(base) {
            while !is_device_address(end) {
                end = next_page(end);
                if !backend.is_address_valid(end) {
                    break;
                }
            }
        }

        *cursor = next_page(end);
        if end > base {
            let protect = if (0x8000_0000..=0x9fff_ffff).contains(&base) {
                0x40
            } else {
                0x04
            };
            return Some(Region {
                base,
                size: end - base,
                protect,
            });
        }
    }
}

fn walk_memory_lines(
    cursor: &mut u32,
    active: &mut bool,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    /// Length of one line including CR LF.
    const LINE_LENGTH: usize = 52;

    let mut writer = RawWriter {
        buffer: cx.binary,
        len: 0,
    };

    while *active && writer.buffer.len() - writer.len >= LINE_LENGTH {
        let Some(region) = next_region(cx.backend, cursor) else {
            *active = false;
            break;
        };

        let _ = write!(
            writer,
            "base=0x{:08x} size=0x{:08x} protect=0x{:08x}\r\n",
            region.base, region.size, region.protect
        );
    }

    if writer.len == 0 {
        return Err(CommandError::EndOfData);
    }

    cx.binary_len = writer.len;

    Ok(Reply::Ok)
}

/// `modules`: every loaded module with an NT header.
fn modules(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(session) = invocation.session.as_deref_mut() else {
        return Err(CommandError::Fail);
    };

    session.continuation = AnyContinuation::Memory(Continuation::Modules {
        next: ModuleIndex(0),
    });

    Ok(Reply::Multiline)
}

fn module_line(next: &mut ModuleIndex, cx: &mut ContinuationContext<'_>) -> CommandResult {
    let Some(module) = cx.backend.module(*next) else {
        return Err(CommandError::EndOfData);
    };

    next.0 += 1;

    let mut writer = RawWriter {
        buffer: cx.binary,
        len: 0,
    };
    writer.push_bytes(b"name=\"");
    writer.push_bytes(module.name.as_bytes());
    let _ = write!(
        writer,
        "\" base=0x{:08x} size=0x{:08x} check=0x{:08x} timestamp=0x{:08x} pdata=0x{:08x} psize=0x{:08x}{} thread=0x{:08x} osize=0x{:08x}\r\n",
        module.base,
        module.size,
        module.checksum,
        module.timestamp,
        module.pdata,
        module.pdata_size,
        if module.dll { " dll" } else { "" },
        0,
        module.image_size,
    );
    cx.binary_len = writer.len;

    Ok(Reply::Ok)
}

/// `modsections name=<str>`: the section table of a loaded module.
fn module_sections(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let mut name = [0u8; NAME_PARAMETER_CAPACITY];
    if string_param(invocation, "name", &mut name).is_none() {
        invocation.set_text(format_args!("missing name"));
        return Err(CommandError::Fail);
    }

    if invocation
        .backend
        .module_section(c_string(&name), SectionIndex(1))
        .is_err()
    {
        return Err(ErrorCode::NoSuchModule.into());
    }

    let Some(name) = hold(invocation, &name) else {
        return Err(CommandError::OutOfMemory);
    };

    if let Some(session) = invocation.session.as_deref_mut() {
        session.continuation = AnyContinuation::Memory(Continuation::Sections {
            name,
            next: SectionIndex(1),
        });
    }

    Ok(Reply::Multiline)
}

/// Hold `data` for the transfer of the invocation's connection (stock
/// allocates these copies from pool memory).
fn hold(invocation: &mut Invocation<'_>, data: &[u8]) -> Option<TransferBlock> {
    let socket = invocation.session.as_ref()?.socket();

    invocation
        .state
        .transfer_blocks
        .hold(invocation.backend, socket, data)
}

/// A copy of the module name a transfer holds.
fn held_name(
    cx: &mut ContinuationContext<'_>,
    block: TransferBlock,
) -> [u8; NAME_PARAMETER_CAPACITY] {
    let mut name = [0; NAME_PARAMETER_CAPACITY];
    name.copy_from_slice(
        &cx.state.transfer_blocks.bytes(cx.backend, block)[..NAME_PARAMETER_CAPACITY],
    );

    name
}

fn section_line(
    held: TransferBlock,
    next: &mut SectionIndex,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    let name = held_name(cx, held);
    let Ok(Some(section)) = cx.backend.module_section(c_string(&name), *next) else {
        // SAFETY: the transfer ends with this result, so the server drops the
        // continuation, the only other holder.
        unsafe { cx.state.transfer_blocks.release(cx.backend, held) };
        return Err(CommandError::EndOfData);
    };

    let index = next.0;
    next.0 = next.0.wrapping_add(1);

    let mut writer = RawWriter {
        buffer: cx.binary,
        len: 0,
    };
    writer.push_bytes(b"name=\"");
    writer.push_bytes(c_string(&section.name));
    let _ = write!(
        writer,
        "\" base=0x{:08x} size=0x{:08x} index={index} flags={}\r\n",
        section.address,
        section.size,
        section.flags()
    );
    cx.binary_len = writer.len;

    Ok(Reply::Ok)
}

/// `pdbinfo addr=<dword>`: GUID, age, and PDB path of the module loaded at
/// `addr`.
fn pdb_info(invocation: &mut Invocation<'_>) -> CommandResult {
    let code_view = match invocation.line.dword("addr") {
        Some(base) => invocation
            .backend
            .code_view(base)
            // The module has no CodeView record.
            .ok_or(CommandError::Win32(Win32Error::NOT_FOUND)),
        None => Err(CommandError::InvalidArgument),
    };
    let code_view = match code_view {
        Ok(code_view) => code_view,
        Err(error) => {
            invocation.set_text(format_args!("HRESULT 0x{:X}", Hresult::from(error).0));
            return Err(error);
        }
    };

    invocation.text.clear();
    for byte in code_view.guid.iter().chain(&code_view.age) {
        let _ = invocation
            .text
            .push_bytes(&[hex_digit(byte >> 4), hex_digit(*byte)]);
    }

    let _ = invocation.text.push_bytes(code_view.path());

    Ok(Reply::Ok)
}

/// `xexfield module=<str> field=<dword>`: an XEX optional header field of a
/// loaded module as hex.
fn xex_field(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let mut module = [0u8; NAME_PARAMETER_CAPACITY];
    if string_param(invocation, "module", &mut module).is_none() {
        invocation.set_text(format_args!("missing module"));
        return Err(CommandError::Fail);
    }

    let Some(field) = invocation.line.dword("field").map(XexHeaderKey) else {
        invocation.set_text(format_args!("missing field"));
        return Err(CommandError::Fail);
    };

    let name = c_string(&module);
    let backend = &mut *invocation.backend;
    let (value, size) = backend.xex_header_field(name, field).and_then(|value| {
        let size = xex_field_size(field, || {
            let mut length = [0u8; 4];
            backend
                .read_xex_header_field(name, field, 0, &mut length)
                .map(|()| u32::from_be_bytes(length))
        })?;
        Ok((value, size))
    })?;
    if size == 0 {
        return Ok(Reply::Ok);
    }

    let Some(module) = hold(invocation, &module) else {
        return Err(CommandError::OutOfMemory);
    };

    if let Some(session) = invocation.session.as_deref_mut() {
        session.continuation = AnyContinuation::Memory(Continuation::XexField {
            module,
            field,
            value,
            size,
            remaining: size.wrapping_add(4),
        });
    }

    Ok(Reply::Multiline)
}

fn xex_field_line(
    held: TransferBlock,
    field: XexHeaderKey,
    value: u32,
    size: u32,
    remaining: &mut u32,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    /// Bytes per data line.
    const BYTES_PER_LINE: u32 = 32;

    if *remaining > size {
        let _ = write!(cx.line, "fieldsize=0x{size:08x}");
        *remaining = remaining.wrapping_sub(4);
        return Ok(Reply::Ok);
    }

    if *remaining == 0 {
        // SAFETY: the transfer ends with this result, so the server drops the
        // continuation, the only other holder.
        unsafe { cx.state.transfer_blocks.release(cx.backend, held) };
        return Err(CommandError::EndOfData);
    }

    let offset = size - *remaining;
    let count = (*remaining).min(BYTES_PER_LINE);
    let mut data = [0u8; BYTES_PER_LINE as usize];
    let data = &mut data[..count as usize];
    if field.0 & 0xff == 0 {
        let inline = value.to_be_bytes();
        data.copy_from_slice(&inline[offset as usize..(offset + count) as usize]);
    } else {
        let module = held_name(cx, held);
        if cx
            .backend
            .read_xex_header_field(c_string(&module), field, offset, data)
            .is_err()
        {
            return Err(CommandError::Fail);
        }
    }

    for byte in data.iter() {
        let _ = cx
            .line
            .push_bytes(&[hex_digit(byte >> 4), hex_digit(*byte)]);
    }

    *remaining -= count;

    Ok(Reply::Ok)
}

/// `xbeinfo running` or `xbeinfo name=<str> [ondiskonly]`: the object path
/// of the running executable. A named query reports the running executable
/// too; `ondiskonly` opens the named file and reports it missing.
fn executable_info(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let mut name = [0u8; NAME_PARAMETER_CAPACITY];
    let running = invocation.line.has("running");
    if !running && string_param(invocation, "name", &mut name).is_none() {
        invocation.set_text(format_args!("missing name"));
        return Err(CommandError::Fail);
    }

    let Some(socket) = invocation.session.as_ref().map(|session| session.socket()) else {
        return Err(CommandError::Fail);
    };
    // Stock allocates the reply block (0x114 bytes) before the query.
    let Some(held) = invocation.state.transfer_blocks.acquire(
        invocation.backend,
        socket,
        EXECUTABLE_PATH_CAPACITY as u32,
    ) else {
        return Err(CommandError::OutOfMemory);
    };

    if !running && invocation.line.has("ondiskonly") {
        // Stock leaves the handle open and reports the file missing
        // whatever the open returned.
        let request = filesystem::CreateRequest {
            access: AccessMask::GENERIC_READ.union(AccessMask::SYNCHRONIZE),
            allocation_size: None,
            attributes: FileAttributes::empty(),
            share: ShareAccess::empty(),
            disposition: CreateDisposition::Open,
            options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
        };
        let _ = filesystem::open_translated(
            invocation.state,
            invocation.backend,
            c_string(&name),
            &request,
        );

        // SAFETY: the transfer was not started, so this command holds the only
        // copy.
        unsafe {
            invocation
                .state
                .transfer_blocks
                .release(invocation.backend, held)
        };
        return Err(ErrorCode::FileNotFound.into());
    }

    let mut object_path = [0u8; EXECUTABLE_PATH_CAPACITY];
    let length = invocation.backend.running_executable_path(&mut object_path);
    let mut path = [0u8; EXECUTABLE_PATH_CAPACITY];
    let path_len = invocation
        .state
        .filesystem
        .drives
        .object_path_to_drive_path(invocation.backend, &object_path[..length], &mut path);
    invocation
        .state
        .transfer_blocks
        .bytes(invocation.backend, held)[..path_len]
        .copy_from_slice(&path[..path_len]);

    if let Some(session) = invocation.session.as_deref_mut() {
        session.continuation = AnyContinuation::Memory(Continuation::ExecutableInfo {
            path: held,
            path_len: path_len as u16,
            line: ExecutableInfoLine::Header,
        });
    }

    Ok(Reply::Multiline)
}

fn executable_info_line(
    held: TransferBlock,
    path_len: usize,
    line: &mut ExecutableInfoLine,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    match *line {
        ExecutableInfoLine::Header => {
            // This build reports no timestamp or checksum.
            let _ = write!(cx.line, "timestamp=0x{:08x} checksum=0x{:08x}", 0, 0);
            *line = ExecutableInfoLine::Name;
        }
        ExecutableInfoLine::Name => {
            let path = &cx.state.transfer_blocks.bytes(cx.backend, held)[..path_len];
            let mut writer = RawWriter {
                buffer: cx.binary,
                len: 0,
            };
            writer.push_bytes(b"name=\"");
            writer.push_bytes(path);
            writer.push_bytes(b"\"\r\n");
            cx.binary_len = writer.len;
            *line = ExecutableInfoLine::End;
        }
        ExecutableInfoLine::End => {
            // SAFETY: the transfer ends with this result, so the server drops
            // the continuation, the only other holder.
            unsafe { cx.state.transfer_blocks.release(cx.backend, held) };
            return Err(CommandError::EndOfData);
        }
    }

    Ok(Reply::Ok)
}

/// `addtitlemem`: the running title's additional title memory when the
/// console runs its extra memory; 0 otherwise.
fn additional_title_memory(invocation: &mut Invocation<'_>) -> CommandResult {
    let value = if console::console_memory(invocation.backend).value() & 0x2 != 0 {
        match invocation.backend.title_additional_memory() {
            // A title without the header field has no additional memory.
            Ok(field) => field.unwrap_or(0),
            Err(NoSuchModule) => return Err(ErrorCode::NoSuchModule.into()),
        }
    } else {
        0
    };

    invocation.set_text(format_args!("addtitlemem=0x{value:x}"));

    Ok(Reply::Ok)
}

/// `advmem on|off|status`: the advanced memory flag in the raw flash.
fn advanced_memory(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Flash flag word bit that disables advanced memory.
    const DISABLED: u16 = 0x100;

    let mut word = [0u8; 2];
    if invocation
        .backend
        .read_flash(ADVANCED_MEMORY_FLASH_OFFSET, &mut word)
        .is_err()
    {
        return Err(CommandError::Unexpected);
    }

    let word = u16::from_be_bytes(word);
    let disabled = word & DISABLED != 0;
    let text = if invocation.line.has("on") {
        if !disabled {
            invocation.set_text(format_args!("already enabled"));
            return Ok(Reply::Ok);
        }
        "enabled"
    } else if invocation.line.has("off") {
        if disabled {
            invocation.set_text(format_args!("already disabled"));
            return Ok(Reply::Ok);
        }
        "disabled"
    } else if invocation.line.has("status") {
        let status = if disabled { "disabled" } else { "enabled" };
        invocation.set_text(format_args!("{status}"));
        return Ok(Reply::Ok);
    } else {
        invocation.set_text(format_args!("improper command"));
        return Err(CommandError::Fail);
    };

    let toggled = (word ^ DISABLED).to_be_bytes();
    if invocation
        .backend
        .write_flash(ADVANCED_MEMORY_FLASH_OFFSET, &toggled)
        .is_err()
    {
        return Err(CommandError::Unexpected);
    }

    invocation.set_text(format_args!("{text}"));

    Ok(Reply::Ok)
}

/// `traceimports modulename=<str> [enabled=on]`: configure kernel import
/// tracing for the next title launch.
fn trace_imports(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Bytes of the `modulename` buffer.
    const MODULE_CAPACITY: usize = 0x104;
    /// Bytes of the `enabled` buffer.
    const ENABLED_CAPACITY: usize = 10;

    let mut enabled = [0u8; ENABLED_CAPACITY];
    let enable = string_param(invocation, "enabled", &mut enabled)
        .is_some_and(|value| value.eq_ignore_ascii_case(b"on"));
    let mut module = [0u8; MODULE_CAPACITY];
    let Some(module) = string_param(invocation, "modulename", &mut module) else {
        return Err(CommandError::Fail);
    };

    let mut message = Text::<{ MODULE_CAPACITY + 0x50 }>::new();
    let accepted = invocation.backend.trace_imports(module, enable);
    if accepted {
        let _ = message.push_bytes(b"[xbdm] ");
        let _ = message.push_bytes(if enable { b"enabled" } else { b"disabled" });
        let _ = message.push_bytes(b" tracing for module ");
        let _ = message.push_bytes(module);
        let _ = message.push_bytes(b", title reboot required to activate\n");
    } else {
        let _ = message.push_bytes(b"[xbdm] module '");
        let _ = message.push_bytes(module);
        let _ = message.push_bytes(b"' is not a valid choice\n");
    }
    invocation.backend.debug_print(message.as_bytes());

    if accepted {
        Ok(Reply::Ok)
    } else {
        Err(CommandError::Fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(name: &str) -> impl Iterator<Item = u16> + '_ {
        name.bytes().map(u16::from)
    }

    #[test]
    fn module_lookup_ignores_case_and_requires_the_full_name() {
        assert!(module_name_matches(
            units("xboxkrnl.exe"),
            b"XBOXKRNL.EXE",
            true
        ));
        assert!(!module_name_matches(
            units("xboxkrnl.exe"),
            b"xboxkrnl",
            true
        ));
        assert!(!module_name_matches(units("xam.xex"), b"xam.xex2", true));
    }

    #[test]
    fn inexact_module_lookup_accepts_a_missing_extension() {
        assert!(module_name_matches(units("xam.xex"), b"XAM", false));
        assert!(!module_name_matches(units("xam.xex"), b"xa", false));
    }

    #[test]
    fn module_lookup_compares_the_low_byte_of_each_unit() {
        assert!(module_name_matches([0x0141u16, 0x0062], b"AB", true));
    }

    #[test]
    fn page_steps_follow_the_address_space_layout() {
        assert_eq!(next_page(0x3fff_f123), 0x4000_0000);
        assert_eq!(next_page(0x4000_0000), 0x4001_0000);
        assert_eq!(next_page(0x9000_0123), 0x9000_1000);
        assert_eq!(next_page(0xa000_0000), 0xa001_0000);
    }

    #[test]
    fn xex_field_sizes_follow_the_key_low_byte() {
        let no_data = || -> Result<u32, XexFieldError> { unreachable!() };
        assert_eq!(xex_field_size(XexHeaderKey(0x10100), no_data), Ok(4));
        assert_eq!(xex_field_size(XexHeaderKey(0x20000), no_data), Ok(0));
        assert_eq!(xex_field_size(XexHeaderKey(0x10001), no_data), Ok(4));
        assert_eq!(xex_field_size(XexHeaderKey(0x40006), no_data), Ok(0x18));
        assert_eq!(xex_field_size(XexHeaderKey(0x103ff), || Ok(0x2c)), Ok(0x2c));
    }
}
