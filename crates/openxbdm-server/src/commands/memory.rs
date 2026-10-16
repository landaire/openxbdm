//! Memory, module, and image inspection commands.

pub mod detour;

use core::fmt::Write as _;

use openxbdm_core::line::Value;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;

use crate::access::Access;
use crate::commands::console;
use crate::commands::debugger;
use crate::commands::filesystem;
use crate::commands::system::SettingsFile;
use crate::commands::system::write_line;
use crate::commands::util;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::text::Text;
use crate::transfer_blocks::TransferBlock;

const PAGE_SIZE: u32 = 0x1000;
const LARGE_PAGE_SIZE: u32 = 0x1_0000;
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
/// `getmem` emits at most this many lines per continuation call.
const GETMEM_LINES_PER_CALL: usize = 16;
/// Bytes per `getmem` line.
const GETMEM_BYTES_PER_LINE: u32 = 32;
/// Data bytes per `getmemex` chunk.
const GETMEMEX_CHUNK: u32 = 0x400;
/// `getmemex` chunk header bit marking the final chunk.
const GETMEMEX_LAST_CHUNK: u16 = 0x8000;
/// `walkmem` stops starting regions at this address.
const WALK_LIMIT: u32 = 0xa000_0000;
/// Length of one `walkmem` line including CR LF.
const WALK_LINE_LENGTH: usize = 52;
/// Bytes per `xexfield` data line.
const XEX_FIELD_BYTES_PER_LINE: u32 = 32;
/// Optional header 0x10100 is reported with its inline value as data.
const XEX_FIELD_INLINE_REPORTED: u32 = 0x10100;
/// Optional header holding the additional title memory.
const XEX_FIELD_ADDITIONAL_TITLE_MEMORY: u32 = 0x40801;

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
/// Bytes of the `modulename` buffer of `traceimports`.
const TRACE_MODULE_CAPACITY: usize = 0x104;
/// Bytes of the `enabled` buffer of `traceimports`.
const TRACE_ENABLED_CAPACITY: usize = 10;
/// Bytes of the `cmd` buffer of `memtrack`.
const MEMTRACK_COMMAND_CAPACITY: usize = 0x20;
/// Bytes of the `filename` buffer of `memtrack save`.
const MEMTRACK_FILENAME_CAPACITY: usize = 0x140;
/// Largest stack depth `memtrack enable` accepts.
const MEMTRACK_MAX_STACK_DEPTH: u32 = 0x20;
/// Byte offset of the advanced memory flag word in the raw flash device.
pub const ADVANCED_MEMORY_FLASH_OFFSET: u32 = 6;
/// Flash flag word bit that disables advanced memory.
const ADVANCED_MEMORY_DISABLED: u16 = 0x100;

/// Physical ranges the debugger never reads (device registers). Bounds are
/// inclusive.
const DEVICE_RANGES: [(u32, u32); 6] = [
    (0x7fc8_0000, 0x7fc9_ffff),
    (0x7fd0_0000, 0x7fdf_ffff),
    (0x7fea_0000, 0x7fea_ffff),
    (0x7fed_0000, 0x7fed_ffff),
    (0x8fff_0000, 0x8fff_0fff),
    (0x8fff_1000, 0x8fff_1fff),
];

/// Whether `address` lies in a device range the debugger never accesses.
pub fn is_device_address(address: u32) -> bool {
    DEVICE_RANGES
        .iter()
        .any(|&(low, high)| (low..=high).contains(&address))
}

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry("addtitlemem", DispatchFlags::NONE, additional_title_memory),
    entry("advmem", DispatchFlags::NONE, advanced_memory),
    entry("detour", DispatchFlags::DEVKIT_ONLY, detour_command),
    entry("getmem", DispatchFlags::NONE, get_memory),
    entry("getmemex", DispatchFlags::NONE, get_memory_binary),
    entry("memtrack", DispatchFlags::NONE, memory_tracking),
    entry("modsections", DispatchFlags::NONE, module_sections),
    entry("modules", DispatchFlags::NONE, modules),
    entry("pdbinfo", DispatchFlags::NONE, pdb_info),
    entry("setmem", DispatchFlags::DEVKIT_ONLY, set_memory),
    entry("traceimports", DispatchFlags::NONE, trace_imports),
    entry("walkmem", DispatchFlags::NONE, walk_memory),
    entry("xbeinfo", DispatchFlags::NONE, executable_info),
    entry("xexfield", DispatchFlags::NONE, xex_field),
];

const fn entry(
    name: &'static str,
    flags: DispatchFlags,
    handler: crate::registry::Handler,
) -> CommandEntry {
    CommandEntry::new(name, Access::CONTROL, Access::NONE, flags, handler)
}

/// Allocation tracking type flags. The low eight bits select allocation
/// types, bit 8 turns tracking diagnostics into assertions, and bit 31 of
/// the saved value marks a pending `enableonce`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrackingFlags(pub u32);

impl TrackingFlags {
    /// Bits `enable` replaces and `disable` clears.
    pub const TYPE_MASK: u32 = 0x1ff;
    /// Default `flags` value of `enable` and `enableonce`.
    pub const DEFAULT: Self = Self(0x1ff);
    /// Set in the saved flags by `enableonce`; cleared when the settings
    /// file is loaded.
    pub const ONCE: u32 = 0x8000_0000;

    /// Whether any tracking type is selected.
    pub fn is_active(self) -> bool {
        self.0 & Self::TYPE_MASK != 0
    }
}

/// Number of return addresses captured per tracked allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StackDepth(pub u32);

/// Capture depth in effect for tracked allocations. Stock keeps it in a
/// global that no code path writes, so it is always zero.
pub const ACTIVE_STACK_DEPTH: StackDepth = StackDepth(0);

/// Names of the built-in allocation tracking types, by type index.
pub const TRACKING_TYPE_NAMES: [&str; 14] = [
    "heap",
    "virtual-mapped memory",
    "contiguous memory",
    "system memory",
    "debugger memory",
    "kernel pool",
    "directory object",
    "event",
    "file",
    "I/O completion",
    "mutex",
    "semaphore",
    "timer",
    "thread",
];

/// Persisted allocation tracking settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrackingSettings {
    pub flags: TrackingFlags,
    pub stack_depth: StackDepth,
}

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
                flags: TrackingFlags(0),
                stack_depth: StackDepth(0),
            },
            detour_log: DetourLogName::EMPTY,
        }
    }
}

/// Bytes of the `detour start` file name buffer.
const DETOUR_LOG_NAME_CAPACITY: usize = 0x104;

/// The `detour start` file name.
#[derive(Debug, Clone, Copy)]
pub struct DetourLogName {
    bytes: [u8; DETOUR_LOG_NAME_CAPACITY],
    len: usize,
}

impl DetourLogName {
    pub const EMPTY: Self = Self {
        bytes: [0; DETOUR_LOG_NAME_CAPACITY],
        len: 0,
    };

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
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

/// The named module is not loaded or has no NT header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoSuchModule;

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

/// Why an XEX optional header field cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XexFieldError {
    NoSuchModule,
    /// The module's XEX header has no such field.
    FieldAbsent,
}

impl From<XexFieldError> for CommandError {
    fn from(error: XexFieldError) -> Self {
        match error {
            XexFieldError::NoSuchModule => ErrorCode::NoSuchModule.into(),
            XexFieldError::FieldAbsent => Self::Memory(MemoryError::NoSuchField),
        }
    }
}

/// Failures of this domain that no other [`CommandError`] form reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    /// 437: the XEX header has no such field.
    NoSuchField,
    /// 442: the detour engine is not running.
    DetourNotRunning,
    /// Saving the tracking records failed; the kernel's Win32 translation
    /// of the status.
    TrackingSave(Win32Error),
}

impl From<MemoryError> for Hresult {
    fn from(error: MemoryError) -> Self {
        match error {
            MemoryError::NoSuchField => Hresult::error(0x25),
            MemoryError::DetourNotRunning => Hresult::error(0x2a),
            // Stock moves the code to the Win32 facility without the sign
            // test of HRESULT_FROM_WIN32.
            MemoryError::TrackingSave(error) => Hresult(0x8007_0000 | (error.code() & 0xffff)),
        }
    }
}

impl From<detour::DetourError> for CommandError {
    fn from(error: detour::DetourError) -> Self {
        match error {
            detour::DetourError::NotRunning => Self::Memory(MemoryError::DetourNotRunning),
            detour::DetourError::BadEntry => ErrorCode::Undefined.into(),
            detour::DetourError::NoFreeEntry => ErrorCode::OutOfMemory.into(),
        }
    }
}

/// `ERROR_NOT_FOUND`: the module has no CodeView record.
const NOT_FOUND: Win32Error = Win32Error::new(0x490).unwrap();
/// `ERROR_SERVICE_NOT_ACTIVE`: no allocation type is tracked.
const SERVICE_NOT_ACTIVE: Win32Error = Win32Error::new(0x426).unwrap();

/// XEX optional header field key: the high bits identify the field and the
/// low byte encodes its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XexFieldKey(pub u32);

impl XexFieldKey {
    /// Bytes `xexfield` reports for a field whose header lookup returned
    /// `value`; `data` reads the field's leading dword.
    fn size(
        self,
        data_length: impl FnOnce() -> Result<u32, XexFieldError>,
    ) -> Result<u32, XexFieldError> {
        match self.0 & 0xff {
            0 if self.0 == XEX_FIELD_INLINE_REPORTED => Ok(4),
            0 => Ok(0),
            1 => Ok(4),
            0xff => data_length(),
            count => Ok(count << 2),
        }
    }

    fn is_inline(self) -> bool {
        self.0 & 0xff == 0
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
    fn read_memory(&mut self, address: u32, output: &mut [u8]);

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
    /// value for keys whose low byte is 0, else the field address.
    fn xex_header_field(&mut self, module: &[u8], field: XexFieldKey)
    -> Result<u32, XexFieldError>;
    /// Copy bytes at `offset` of the data of a non-inline XEX header field.
    fn read_xex_header_field(
        &mut self,
        module: &[u8],
        field: XexFieldKey,
        offset: u32,
        output: &mut [u8],
    ) -> Result<(), XexFieldError>;
    /// First dword of the running title's XEX header field 0x40801;
    /// `Ok(None)` when the field is absent.
    fn title_xex_dword(&mut self, field: XexFieldKey) -> Result<Option<u32>, NoSuchModule>;
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
        field: XexFieldKey,
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

/// Raw output into the continuation buffer.
struct RawWriter<'a> {
    buffer: &'a mut [u8],
    len: usize,
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

impl RawWriter<'_> {
    fn push_bytes(&mut self, bytes: &[u8]) {
        let end = (self.len + bytes.len()).min(self.buffer.len());
        let count = end - self.len;
        self.buffer[self.len..end].copy_from_slice(&bytes[..count]);
        self.len = end;
    }
}

/// Bytes before the first NUL.
fn c_string(buffer: &[u8]) -> &[u8] {
    buffer.split(|&byte| byte == 0).next().unwrap_or_default()
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

/// The dword the monitor's getters store: the parsed prefix whenever the
/// parameter is present. `None` in the flag means the getter reported it
/// missing.
fn dword_param(value: Option<Value<'_>>) -> (Option<u32>, bool) {
    match value {
        Some(value) => (Some(value.dword_prefix()), value.dword().is_some()),
        None => (None, false),
    }
}

fn hex_digit(value: u8) -> u8 {
    HEX_UPPER[usize::from(value & 0xf)]
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
    if *remaining == 0 {
        return Err(CommandError::EndOfData);
    }
    let mut offset = 0usize;
    let mut page_valid = false;
    let mut checked_page = None;
    for _ in 0..GETMEM_LINES_PER_CALL {
        if *remaining == 0 {
            break;
        }
        let count = (*remaining).min(GETMEM_BYTES_PER_LINE);
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
                    None => page_valid = false,
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
    let mut stopped = false;
    while let Some(high) = digits.as_mut().and_then(Iterator::next) {
        let low = digits.as_mut().and_then(Iterator::next);
        let (Some(high), Some(low)) = (hex_value(high), low.and_then(hex_value)) else {
            invocation.text.set_bytes(b"400- syntax error in data");
            return Err(CommandError::Fail);
        };
        let page = current & !(PAGE_SIZE - 1);
        if checked_page != Some(page) {
            checked_page = Some(page);
            if !invocation.backend.is_address_valid(current) {
                stopped = true;
                break;
            }
        }
        let value = high << 4 | low;
        if !invocation.state.debugger.shadow_write(current, value)
            && !invocation.backend.write_byte(current, value)
        {
            stopped = true;
            break;
        }
        written += 1;
        current = current.wrapping_add(1);
    }
    invocation.set_text(format_args!("set {written} bytes"));
    if stopped {
        Err(ErrorCode::MemoryNotMapped.into())
    } else {
        Ok(Reply::Ok)
    }
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
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
    if cx.aborted || *remaining == 0 {
        return Err(CommandError::EndOfData);
    }
    let start = *address;
    let mut count = (*remaining).min(GETMEMEX_CHUNK);
    let first_page = start & !(PAGE_SIZE - 1);
    let pages = ((start & (PAGE_SIZE - 1)) + count - 1) / PAGE_SIZE + 1;
    let mut truncated = false;
    for index in 0..pages {
        let current = first_page.wrapping_add(index * PAGE_SIZE);
        if !cx.backend.is_readable(current) {
            count = if index == 0 {
                0
            } else {
                current.wrapping_sub(start)
            };
            truncated = true;
            break;
        }
    }
    *address = start.wrapping_add(count);
    *remaining = if truncated { 0 } else { *remaining - count };
    let header = count as u16
        | if *remaining == 0 {
            GETMEMEX_LAST_CHUNK
        } else {
            0
        };
    let data = &mut cx.binary[2..2 + count as usize];
    cx.backend.read_memory(start, data);
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

/// A valid virtual address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    base: u32,
    size: u32,
    protect: u32,
}

/// The page after the one containing `address`: 4 KiB pages below
/// 0x40000000 and in 0x90000000-0x9fffffff, 64 KiB pages elsewhere.
pub fn next_page(address: u32) -> u32 {
    if address <= 0x3fff_ffff || (0x9000_0000..=0x9fff_ffff).contains(&address) {
        (address & !(PAGE_SIZE - 1)).wrapping_add(PAGE_SIZE)
    } else {
        (address & !(LARGE_PAGE_SIZE - 1)).wrapping_add(LARGE_PAGE_SIZE)
    }
}

/// The next region at or after `cursor`. A region can extend past the walk
/// limit; only its start is bounded.
fn next_region(backend: &mut dyn crate::backend::Backend, cursor: &mut u32) -> Option<Region> {
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
    let mut writer = RawWriter {
        buffer: cx.binary,
        len: 0,
    };
    while *active && writer.buffer.len() - writer.len >= WALK_LINE_LENGTH {
        match next_region(cx.backend, cursor) {
            Some(region) => {
                let _ = write!(
                    writer,
                    "base=0x{:08x} size=0x{:08x} protect=0x{:08x}\r\n",
                    region.base, region.size, region.protect
                );
            }
            None => *active = false,
        }
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
        cx.state.transfer_blocks.release(cx.backend, held);
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
        "\" base=0x{:08x} size=0x{:08x} index={} flags={}\r\n",
        section.address,
        section.size,
        index,
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
            .ok_or(CommandError::Win32(NOT_FOUND)),
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
    let Some(field) = invocation.line.dword("field") else {
        invocation.set_text(format_args!("missing field"));
        return Err(CommandError::Fail);
    };
    let field = XexFieldKey(field);
    let name = c_string(&module);
    let backend = &mut *invocation.backend;
    let size = backend.xex_header_field(name, field).and_then(|value| {
        let size = field.size(|| {
            let mut length = [0u8; 4];
            backend
                .read_xex_header_field(name, field, 0, &mut length)
                .map(|()| u32::from_be_bytes(length))
        })?;
        Ok((value, size))
    });
    let (value, size) = size?;
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
    field: XexFieldKey,
    value: u32,
    size: u32,
    remaining: &mut u32,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    if *remaining > size {
        let _ = write!(cx.line, "fieldsize=0x{size:08x}");
        *remaining = remaining.wrapping_sub(4);
        return Ok(Reply::Ok);
    }
    if *remaining == 0 {
        cx.state.transfer_blocks.release(cx.backend, held);
        return Err(CommandError::EndOfData);
    }
    let offset = size - *remaining;
    let count = (*remaining).min(XEX_FIELD_BYTES_PER_LINE);
    let mut data = [0u8; XEX_FIELD_BYTES_PER_LINE as usize];
    let data = &mut data[..count as usize];
    if field.is_inline() {
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
            access: filesystem::FileAccess(0x8010_0000),
            allocation_size: None,
            attributes: filesystem::FileAttributes(0),
            share: filesystem::ShareAccess(0),
            disposition: filesystem::CreateDisposition::Open,
            options: filesystem::CreateOptions(0x20),
        };
        let _ = filesystem::open_translated(
            invocation.state,
            invocation.backend,
            c_string(&name),
            &request,
        );
        invocation
            .state
            .transfer_blocks
            .release(invocation.backend, held);
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
            cx.state.transfer_blocks.release(cx.backend, held);
            return Err(CommandError::EndOfData);
        }
    }
    Ok(Reply::Ok)
}

/// `addtitlemem`: the running title's additional title memory when the
/// console runs its extra memory; 0 otherwise.
fn additional_title_memory(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut value = 0;
    if console::console_memory(invocation.backend).value() & 0x2 != 0 {
        match invocation
            .backend
            .title_xex_dword(XexFieldKey(XEX_FIELD_ADDITIONAL_TITLE_MEMORY))
        {
            Ok(field) => value = field.unwrap_or(0),
            Err(NoSuchModule) => return Err(ErrorCode::NoSuchModule.into()),
        }
    }
    invocation.set_text(format_args!("addtitlemem=0x{value:x}"));
    Ok(Reply::Ok)
}

/// `advmem on|off|status`: the advanced memory flag in the raw flash.
fn advanced_memory(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut word = [0u8; 2];
    if invocation
        .backend
        .read_flash(ADVANCED_MEMORY_FLASH_OFFSET, &mut word)
        .is_err()
    {
        return Err(CommandError::Unexpected);
    }
    let word = u16::from_be_bytes(word);
    let disabled = word & ADVANCED_MEMORY_DISABLED != 0;
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
        invocation.set_text(format_args!(
            "{}",
            if disabled { "disabled" } else { "enabled" }
        ));
        return Ok(Reply::Ok);
    } else {
        invocation.set_text(format_args!("improper command"));
        return Err(CommandError::Fail);
    };
    let toggled = (word ^ ADVANCED_MEMORY_DISABLED).to_be_bytes();
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
    let mut enabled = [0u8; TRACE_ENABLED_CAPACITY];
    let enable = string_param(invocation, "enabled", &mut enabled)
        .is_some_and(|value| value.eq_ignore_ascii_case(b"on"));
    let mut module = [0u8; TRACE_MODULE_CAPACITY];
    let Some(module) = string_param(invocation, "modulename", &mut module) else {
        return Err(CommandError::Fail);
    };
    let mut message = Text::<{ TRACE_MODULE_CAPACITY + 0x50 }>::new();
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

/// `detour log|entry|start|stop|getstate ...`: the function detour engine.
/// Selectors are flags tested in that order.
fn detour_command(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line;
    if line.has("log") {
        if line.has("available") {
            return detour_available(invocation);
        }
        if line.has("getentries") {
            return detour_get_entries(invocation);
        }
        return Err(ErrorCode::UnknownCommand.into());
    }
    if line.has("entry") {
        return detour_entry(invocation);
    }
    if line.has("start") {
        return detour_start(invocation);
    }
    if line.has("stop") {
        return detour_stop(invocation);
    }
    if line.has("getstate") {
        let reply = run_detour(invocation.backend, DetourOperation::State);
        let status = match reply.log_error {
            Some(error) => NtStatus::from(error),
            None => NtStatus::SUCCESS,
        };
        invocation.set_text(format_args!(
            "state=0x{:x} status=0x{:x}",
            reply.values[0], status.0
        ));
        return Ok(Reply::Ok);
    }
    Err(ErrorCode::UnknownCommand.into())
}

/// An operation of the detour engine.
#[derive(Clone, Copy)]
enum DetourOperation<'a> {
    State,
    Running,
    Available,
    Acquire,
    Release(detour::EntryId),
    Query(detour::EntryId),
    Configure(detour::EntryId, &'a detour::HookSettings),
    BeginStart,
    CancelStart,
    BeginStop,
    ReleaseRange { base: u32, size: u32 },
}

/// Result of a [`DetourOperation`] and the values it reports.
#[derive(Clone, Copy)]
struct DetourReply {
    result: Result<(), detour::DetourError>,
    values: [u32; 3],
    /// `State`: the error of the last log open.
    log_error: Option<KernelError>,
}

impl DetourReply {
    fn of(result: Result<(), detour::DetourError>) -> Self {
        Self {
            result,
            values: [0; 3],
            log_error: None,
        }
    }

    fn of_values(values: Result<[u32; 3], detour::DetourError>) -> Self {
        match values {
            Ok(values) => Self {
                values,
                ..Self::of(Ok(()))
            },
            Err(error) => Self::of(Err(error)),
        }
    }

    /// Fails with [`detour::DetourError::NotRunning`] unless `running`.
    fn of_running(running: bool) -> Self {
        Self::of(if running {
            Ok(())
        } else {
            Err(detour::DetourError::NotRunning)
        })
    }

    fn command_result(self) -> CommandResult {
        self.result.map(|()| Reply::Ok).map_err(CommandError::from)
    }
}

impl DetourOperation<'_> {
    fn run(self, engine: &detour::Engine, platform: &dyn detour::Platform) -> DetourReply {
        match self {
            Self::State => DetourReply {
                log_error: engine.log_error(),
                ..DetourReply::of_values(Ok([engine.state().code(), 0, 0]))
            },
            Self::Running => {
                DetourReply::of_running(engine.state() == detour::EngineState::Running)
            }
            Self::Available => {
                DetourReply::of_values(engine.available().map(|count| [count, 0, 0]))
            }
            Self::Acquire => DetourReply::of_values(engine.acquire().map(|id| [id.0, 0, 0])),
            Self::Release(id) => DetourReply::of(engine.release(platform, id)),
            Self::Query(id) => {
                DetourReply::of_values(engine.query(platform, id).map(|trampoline| {
                    [
                        trampoline.enter,
                        trampoline.scribble,
                        trampoline.scribble_size,
                    ]
                }))
            }
            Self::Configure(id, settings) => {
                DetourReply::of(engine.configure(platform, id, settings))
            }
            Self::BeginStart => DetourReply::of_running(engine.begin_start()),
            Self::CancelStart => {
                engine.cancel_start();
                DetourReply::of(Ok(()))
            }
            Self::BeginStop => DetourReply::of_running(engine.begin_stop()),
            Self::ReleaseRange { base, size } => {
                engine.release_range(platform, base, size);
                DetourReply::of(Ok(()))
            }
        }
    }
}

/// Run `operation` through [`Backend::detour`]. Every operation shares one
/// closure, so one closure body and vtable serve them all.
fn run_detour(
    backend: &mut dyn crate::backend::Backend,
    operation: DetourOperation<'_>,
) -> DetourReply {
    let mut reply = DetourReply::of(Err(detour::DetourError::NotRunning));
    backend.detour(&mut |engine, platform| reply = operation.run(engine, platform));
    reply
}

/// Set the reply text `hresult=0x<result>` and return `result`.
fn hresult_reply(invocation: &mut Invocation<'_>, result: CommandResult) -> CommandResult {
    invocation.set_text(format_args!("hresult=0x{:x}", reply::hresult(result).0));
    result
}

fn detour_available(invocation: &mut Invocation<'_>) -> CommandResult {
    let reply = run_detour(invocation.backend, DetourOperation::Available);
    reply.result?;
    invocation.set_text(format_args!("available=0x{:x}", reply.values[0]));
    Ok(Reply::Ok)
}

/// `log getentries [count=]`: up to `count` 0x70-byte records after a 203
/// line, without a length; the stream ends early when the unread records
/// run out.
fn detour_get_entries(invocation: &mut Invocation<'_>) -> CommandResult {
    // The getter's result is ignored: an absent count is 0 and a malformed
    // one keeps its parsed prefix.
    let count = invocation
        .line
        .param("count")
        .map_or(0, |value| value.dword_prefix());
    run_detour(invocation.backend, DetourOperation::Running).result?;
    invocation.set_text(format_args!(
        "OK count=0x{count:x} entrysize=0x{:x}",
        detour::RECORD_SIZE
    ));
    let Some(session) = invocation.session.as_deref_mut() else {
        return Err(CommandError::Fail);
    };
    session.continuation = AnyContinuation::Memory(Continuation::DetourLog {
        remaining: count.wrapping_mul(detour::RECORD_SIZE as u32),
    });
    Ok(Reply::Binary)
}

fn detour_log_record(remaining: &mut u32, cx: &mut ContinuationContext<'_>) -> CommandResult {
    if cx.aborted || *remaining == 0 {
        return Err(CommandError::EndOfData);
    }
    let Some(record) = cx.binary.first_chunk_mut::<{ detour::RECORD_SIZE }>() else {
        return Err(CommandError::EndOfData);
    };
    if !cx.backend.read_detour_record(record) {
        return Err(CommandError::EndOfData);
    }
    *remaining = remaining.wrapping_sub(detour::RECORD_SIZE as u32);
    cx.binary_len = detour::RECORD_SIZE;
    Ok(Reply::Ok)
}

fn detour_entry(invocation: &mut Invocation<'_>) -> CommandResult {
    let line = invocation.line;
    let id = line.dword("Id").map(detour::EntryId);
    let bad_parameter: CommandResult = Err(ErrorCode::BadParameter.into());
    if line.has("acquire") {
        let reply = run_detour(invocation.backend, DetourOperation::Acquire);
        reply.result?;
        invocation.set_text(format_args!(
            "hresult=0x{:x} id=0x{:x}",
            Hresult::OK.0,
            reply.values[0]
        ));
        return Ok(Reply::Ok);
    }
    if line.has("release") {
        let result = match id {
            Some(id) => {
                run_detour(invocation.backend, DetourOperation::Release(id)).command_result()
            }
            None => bad_parameter,
        };
        return hresult_reply(invocation, result);
    }
    if line.has("query") {
        let (result, [enter, scribble, size]) = match id {
            Some(id) => {
                let reply = run_detour(invocation.backend, DetourOperation::Query(id));
                (reply.command_result(), reply.values)
            }
            None => (bad_parameter, [0; 3]),
        };
        invocation.set_text(format_args!(
            "hresult=0x{:x} enterdetour=0x{enter:x} scribble=0x{scribble:x} size=0x{size:x}",
            reply::hresult(result).0
        ));
        return result;
    }
    if line.has("setinfo") {
        let required = |name: &str| line.dword(name);
        // Optional values the getter rejects or that are absent are 0.
        let optional = |name: &str| required(name).unwrap_or(0);
        let settings = (|| {
            Some((
                id?,
                detour::HookSettings {
                    address: required("addr")?,
                    param_size: required("paramsize")?,
                    flags: detour::HookFlags(required("flags")?),
                    return_value: detour::ReturnValue(required("return")?),
                    sleep_milliseconds: optional("sleep"),
                    discard_frequency: optional("disccallfreq"),
                    overlapped_offset: optional("OverlappedOffset"),
                    extended_error: Win32Error::new(optional("ExtendedError")),
                },
            ))
        })();
        let result = match &settings {
            Some((id, settings)) => run_detour(
                invocation.backend,
                DetourOperation::Configure(*id, settings),
            )
            .command_result(),
            None => bad_parameter,
        };
        return hresult_reply(invocation, result);
    }
    Err(ErrorCode::UnknownCommand.into())
}

/// `start file=<name>`: open the log (truncating it) in the writer worker.
/// The reply reports worker creation; a log that fails to open returns
/// the engine to stopped with the open status in `getstate`.
fn detour_start(invocation: &mut Invocation<'_>) -> CommandResult {
    // Stock leaves the name buffer uninitialized when `file` is absent; an
    // absent name is empty here and fails translation.
    let mut name = DetourLogName::EMPTY;
    if let Some(value) = invocation.line.param("file") {
        name.len = value.copy_into(&mut name.bytes).len();
    }
    let mut result = run_detour(invocation.backend, DetourOperation::BeginStart).command_result();
    if result.is_ok() {
        let state = &mut *invocation.state;
        state.memory.detour_log = name;
        let path = state
            .filesystem
            .drives
            .translate(invocation.backend, state.memory.detour_log.as_bytes());
        if let Err(error) = invocation
            .backend
            .start_detour_log(path.as_ref().map(|path| path.as_bytes()))
        {
            run_detour(invocation.backend, DetourOperation::CancelStart);
            result = Err(CommandError::from_kernel(
                error,
                ErrorCode::FileCannotBeCreated.into(),
            ));
        }
    }
    hresult_reply(invocation, result)
}

/// `stop`: stop the workers, dropping unwritten records and pending
/// completions, and delete the log file.
fn detour_stop(invocation: &mut Invocation<'_>) -> CommandResult {
    let result = run_detour(invocation.backend, DetourOperation::BeginStop).command_result();
    if result.is_ok() {
        let state = &mut *invocation.state;
        let path = state
            .filesystem
            .drives
            .translate(invocation.backend, state.memory.detour_log.as_bytes());
        invocation
            .backend
            .stop_detour_log(path.as_ref().map(|path| path.as_bytes()));
    }
    hresult_reply(invocation, result)
}

/// A module unloaded: release the detour entries hooking it (0x91f2c608).
pub(crate) fn module_unloaded(backend: &mut dyn crate::backend::Backend, base: u32, size: u32) {
    run_detour(backend, DetourOperation::ReleaseRange { base, size });
}

/// A `memtrack` command.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TrackingCommand {
    Enable,
    EnableOnce,
    Disable,
    Save,
    QueryStackDepth,
    QueryFlags,
    QueryType,
}

const TRACKING_COMMANDS: [(&str, TrackingCommand); 7] = [
    ("enable", TrackingCommand::Enable),
    ("enableonce", TrackingCommand::EnableOnce),
    ("disable", TrackingCommand::Disable),
    ("save", TrackingCommand::Save),
    ("querystackdepth", TrackingCommand::QueryStackDepth),
    ("queryflags", TrackingCommand::QueryFlags),
    ("querytype", TrackingCommand::QueryType),
];

/// `memtrack cmd=<command> ...`: allocation tracking settings, queries, and
/// record dump.
fn memory_tracking(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut command = [0u8; MEMTRACK_COMMAND_CAPACITY];
    let command = string_param(invocation, "cmd", &mut command).and_then(|command| {
        TRACKING_COMMANDS
            .iter()
            .find(|(name, _)| command.eq_ignore_ascii_case(name.as_bytes()))
            .map(|&(_, command)| command)
    });
    let result = match command {
        Some(command @ (TrackingCommand::Enable | TrackingCommand::EnableOnce)) => {
            tracking_enable(invocation, command == TrackingCommand::EnableOnce)
        }
        Some(TrackingCommand::Disable) => {
            invocation.state.memory.tracking.flags.0 &= !TrackingFlags::TYPE_MASK;
            invocation.state.settings_dirty = true;
            Ok(Reply::Ok)
        }
        Some(TrackingCommand::Save) => {
            let mut filename = [0u8; MEMTRACK_FILENAME_CAPACITY];
            match string_param(invocation, "filename", &mut filename) {
                Some(filename) => save_tracking_records(invocation, filename),
                None => Err(CommandError::InvalidArgument),
            }
        }
        Some(command @ (TrackingCommand::QueryStackDepth | TrackingCommand::QueryFlags)) => {
            let value = if command == TrackingCommand::QueryFlags {
                invocation.backend.tracking_flags().0
            } else {
                ACTIVE_STACK_DEPTH.0
            };
            invocation.set_text(format_args!("0x{value:x}"));
            return Ok(Reply::Ok);
        }
        Some(TrackingCommand::QueryType) => {
            match invocation
                .line
                .dword("type")
                .and_then(|index| TRACKING_TYPE_NAMES.get(usize::from(index as u16)))
            {
                Some(name) => {
                    invocation.text.set_bytes(name.as_bytes());
                    return Ok(Reply::Ok);
                }
                None => Err(CommandError::InvalidArgument),
            }
        }
        None => Err(CommandError::InvalidArgument),
    };
    if let Err(error) = result {
        invocation.set_text(format_args!("HRESULT 0x{:x}", Hresult::from(error).0));
    }
    result
}

/// `enable` persists the settings; `enableonce` changes the flags in
/// effect and marks the saved flags. The reply text names the last
/// parameter that was missing.
fn tracking_enable(invocation: &mut Invocation<'_>, once: bool) -> CommandResult {
    let mut missing = None;
    let (depth, depth_valid) = dword_param(invocation.line.param("stackdepth"));
    if !depth_valid {
        missing = Some("stackdepth");
    }
    let (flags, flags_valid) = dword_param(invocation.line.param("flags"));
    if !flags_valid {
        missing = Some("flags");
    }
    let depth = StackDepth(depth.unwrap_or(0));
    let flags = TrackingFlags(flags.unwrap_or(TrackingFlags::DEFAULT.0));
    if depth.0 > MEMTRACK_MAX_STACK_DEPTH || flags.0 & 0xff == 0 {
        return Err(CommandError::InvalidArgument);
    }
    let saved = &mut invocation.state.memory.tracking;
    if once {
        invocation.backend.set_tracking_flags(flags);
        saved.flags.0 |= TrackingFlags::ONCE;
    } else {
        saved.stack_depth = depth;
        saved.flags.0 = (saved.flags.0 & !TrackingFlags::TYPE_MASK) | flags.0;
        invocation.state.settings_dirty = true;
    }
    match missing {
        Some(name) => invocation.set_text(format_args!("missing {name}")),
        None => invocation.text.clear(),
    }
    Ok(Reply::Ok)
}

/// Write the tracking records to `filename` with the title stopped. A
/// failed write deletes the file.
fn save_tracking_records(invocation: &mut Invocation<'_>, filename: &[u8]) -> CommandResult {
    if !invocation.backend.tracking_flags().is_active() {
        return Err(CommandError::Win32(SERVICE_NOT_ACTIVE));
    }
    let request = filesystem::CreateRequest {
        access: filesystem::FileAccess(0x4011_0000),
        allocation_size: None,
        attributes: filesystem::FileAttributes(0x80),
        share: filesystem::ShareAccess(1),
        disposition: filesystem::CreateDisposition::OverwriteIf,
        options: filesystem::CreateOptions(0x20),
    };
    let written =
        filesystem::open_translated(invocation.state, invocation.backend, filename, &request)
            .and_then(|file| {
                let stopped = debugger::stop_execution(
                    invocation.state,
                    invocation.backend,
                    invocation.network,
                );
                let written = invocation.backend.write_tracking_records(file);
                if stopped.is_ok() {
                    let _ = debugger::go_execution(
                        invocation.state,
                        invocation.backend,
                        invocation.network,
                    );
                }
                if written.is_err() {
                    let _ = invocation.backend.set_delete_disposition(file, true);
                }
                invocation.backend.close_file(file);
                written
            });
    let Err(error) = written else {
        return Ok(Reply::Ok);
    };
    match invocation.backend.dos_error_from_nt_status(error) {
        Some(error) => Err(CommandError::Memory(MemoryError::TrackingSave(error))),
        None => Ok(Reply::Ok),
    }
}

/// Settings file line of the allocation tracking settings.
pub(crate) fn memtrack_settings_lines(
    state: &ServerState,
    backend: &mut dyn crate::backend::Backend,
    file: SettingsFile,
) {
    let tracking = state.memory.tracking;
    write_line(
        backend,
        file,
        format_args!(
            "memtrack flags=0x{:x} stackdepth=0x{:x}",
            tracking.flags.0, tracking.stack_depth.0
        ),
    );
}

/// Settings file `memtrack` line: restore the saved settings without a
/// pending one-time enable.
pub(crate) fn ini_memtrack(invocation: &mut Invocation<'_>) {
    let tracking = &mut invocation.state.memory.tracking;
    if let Some(value) = invocation.line.param("flags") {
        tracking.flags = TrackingFlags(value.dword_prefix());
    }
    if let Some(value) = invocation.line.param("stackdepth") {
        tracking.stack_depth = StackDepth(value.dword_prefix());
    }
    tracking.flags.0 &= !TrackingFlags::ONCE;
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
        assert_eq!(XexFieldKey(0x10100).size(no_data), Ok(4));
        assert_eq!(XexFieldKey(0x20000).size(no_data), Ok(0));
        assert_eq!(XexFieldKey(0x10001).size(no_data), Ok(4));
        assert_eq!(XexFieldKey(0x40006).size(no_data), Ok(0x18));
        assert_eq!(XexFieldKey(0x103ff).size(|| Ok(0x2c)), Ok(0x2c));
    }
}
