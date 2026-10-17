//! `dmtelllog`: a log file on the DEVKIT partition fed with records from
//! title and system components, shared by area bits.
//!
//! Producers on any thread hand records to a platform log engine: fixed-
//! size entries that a worker thread passes to a [`TellLogWriter`]. The
//! open-log state lives with the engine so that the producers' queries
//! (entry size, area bits) need no server state.

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::error::LogEngineError;
use super::error::TellLogFailed;
use crate::backend::Backend as AnyBackend;
use crate::commands::filesystem::CreateRequest;
use crate::commands::filesystem::FileHandle;
use crate::invocation::Invocation;
use crate::reply;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::text::Text;

/// Bytes the writer collects before writing to the file.
pub const TELL_LOG_BUFFER_SIZE: usize = 0x2000;

xbox360_sys::flags! {
    /// Area bits of the open log; each producer component owns bits.
    pub struct TellLogAreas(u32) {
        /// Enables the critical section wait trace lines.
        CRITICAL_SECTIONS = 2,
    }
}

/// Longest trace line the monitor formats.
pub const TELL_LOG_LINE_LIMIT: u32 = 0x400;
const PATH_PREFIX: &[u8] = br"\Device\Harddisk0\Partition1\DEVKIT\";
/// Buffer the monitor copies `file=` into.
const FILE_NAME_CAPACITY: usize = 0x104;
const DEFAULT_ENTRY_SIZE: u32 = 0x80;
const DEFAULT_ENTRIES: u32 = 0x200;

/// Record engine parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TellLogConfig {
    /// Bytes of one entry; longer records are cut to it.
    pub entry_size: u32,
    pub entries: u32,
    /// Producers wait for a free entry instead of dropping the record.
    pub block: bool,
}

/// Engine counters reported when the log closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TellLogCounters {
    /// Records rejected because no entry was free.
    pub dropped: u32,
    /// Failed waits of the worker.
    pub missed: u32,
}

/// A `dmtelllog` success result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TellLogReply {
    /// `start` while the log is open, with no new area bit.
    AlreadyOpen,
    /// `stop` while no log is open.
    NotOpen,
    Started,
    Stopped,
}

impl TellLogReply {
    /// Stock returns the bare Win32 codes 1056 and 1172 for these replies,
    /// not HRESULTs built from them.
    const ALREADY_OPEN: Hresult = Hresult(0x420);
    const NOT_OPEN: Hresult = Hresult(0x494);
}

impl From<TellLogReply> for Hresult {
    fn from(reply: TellLogReply) -> Self {
        match reply {
            TellLogReply::AlreadyOpen => TellLogReply::ALREADY_OPEN,
            TellLogReply::NotOpen => TellLogReply::NOT_OPEN,
            TellLogReply::Started | TellLogReply::Stopped => Hresult::from_nt(NtStatus::SUCCESS),
        }
    }
}

/// Platform log engine and open-log state.
pub trait TellLogBackend {
    /// Area bits while a log is open.
    fn tell_log_area(&mut self) -> Option<TellLogAreas>;
    fn set_tell_log_area(&mut self, area: TellLogAreas);
    /// Start the engine that writes records to `file`.
    fn tell_log_start(
        &mut self,
        file: FileHandle,
        area: TellLogAreas,
        config: TellLogConfig,
    ) -> Result<(), LogEngineError>;
    /// Mark the log closing and queue the closing record that makes the
    /// writer flush; the engine counters.
    fn tell_log_close(&mut self) -> Option<TellLogCounters>;
    /// Stop the engine once its queue is processed; the log file.
    fn tell_log_stop(&mut self) -> Option<FileHandle>;
}

/// The engine's writer: collects record text and writes the collection
/// when the next record would not fit or when the log closes.
#[derive(Debug, Clone)]
pub struct TellLogWriter {
    buffer: [u8; TELL_LOG_BUFFER_SIZE],
    count: usize,
}

impl Default for TellLogWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl TellLogWriter {
    pub const fn new() -> Self {
        Self {
            buffer: [0; TELL_LOG_BUFFER_SIZE],
            count: 0,
        }
    }

    /// Process one entry: its text ends at the first NUL. Once the log is
    /// closing, an entry only writes out what was collected.
    pub fn process(
        &mut self,
        entry: &[u8],
        closing: bool,
        write: &mut dyn FnMut(&[u8]) -> Result<(), KernelError>,
    ) -> Result<(), KernelError> {
        let length = entry
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(entry.len());
        if closing {
            return self.flush(write);
        }

        if self.count + length > TELL_LOG_BUFFER_SIZE {
            self.flush(write)?;
        }

        // An entry larger than the buffer is cut to it.
        let length = length.min(TELL_LOG_BUFFER_SIZE - self.count);
        self.buffer[self.count..self.count + length].copy_from_slice(&entry[..length]);
        self.count += length;

        Ok(())
    }

    fn flush(
        &mut self,
        write: &mut dyn FnMut(&[u8]) -> Result<(), KernelError>,
    ) -> Result<(), KernelError> {
        if self.count == 0 {
            return Ok(());
        }

        let count = core::mem::take(&mut self.count);

        write(&self.buffer[..count])
    }
}

/// `E` or `L` trace line of a critical section wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitTrace {
    /// The thread starts waiting.
    Enter,
    /// The thread acquired the section after waiting.
    Leave,
}

/// Fields of a critical section wait trace line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitTraceLine {
    pub trace: WaitTrace,
    /// The waiting thread belongs to the title process.
    pub title: bool,
    pub time_base: u64,
    pub section: u32,
    /// KTHREAD +0x14c of the waiting thread.
    pub thread_id: u32,
    /// Low halves of section +0x10 and +0x14.
    pub lock_count: u16,
    pub recursion_count: u16,
    pub processor: u8,
    /// Section +0x18, the owner KTHREAD.
    pub owner: u32,
    /// Owner KTHREAD +0x14c.
    pub owner_id: u32,
    /// Owner KTHREAD byte +0xbf; -1 without an owner.
    pub owner_processor: i32,
    /// Return addresses of the waiting code.
    pub callers: [u32; 3],
}

/// Format a trace line as the monitor's line writer (0x91f2b530) does for
/// an entry size of `entry_size`: the text and its NUL fit `min(entry_size,
/// 0x400)` bytes; a longer line is cut and ends with LF and NUL. Returns
/// the record length including the NUL.
pub fn format_wait_trace(
    line: &WaitTraceLine,
    entry_size: u32,
    output: &mut [u8; TELL_LOG_LINE_LIMIT as usize],
) -> usize {
    let limit = entry_size.min(TELL_LOG_LINE_LIMIT) as usize;
    let mut text = Text::<{ TELL_LOG_LINE_LIMIT as usize + 0x80 }>::new();
    let letter = match line.trace {
        WaitTrace::Enter => 'E',
        WaitTrace::Leave => 'L',
    };

    let _ = write!(
        text,
        "{letter}:{} 0x{:016x} 0x{:08x} 0x{:08x} 0x{:08x} 0x{:08x} {:02} | 0x{:08x} 0x{:08x} {:02} 0x{:08x} 0x{:08x} 0x{:08x}\r\n",
        if line.title { 'T' } else { 'S' },
        line.time_base,
        line.section,
        line.thread_id,
        line.lock_count,
        line.recursion_count,
        line.processor,
        line.owner,
        line.owner_id,
        line.owner_processor,
        line.callers[0],
        line.callers[1],
        line.callers[2],
    );
    let bytes = text.as_bytes();
    if bytes.len() + 1 < limit {
        output[..bytes.len()].copy_from_slice(bytes);
        output[bytes.len()] = 0;
        return bytes.len() + 1;
    }

    if limit < 2 {
        // The monitor writes the LF before the buffer; only the NUL remains.
        output[..limit].fill(0);
        return limit;
    }

    output[..limit - 2].copy_from_slice(&bytes[..limit - 2]);
    output[limit - 2] = b'\n';
    output[limit - 1] = 0;

    limit
}

/// `dmtelllog start file=<name> area=<dword> [block=<dword>] [size=<dword>]
/// [entries=<dword>]` | `dmtelllog stop [area=<dword>]`. The reply text is
/// `hresult=0x%x`.
pub(super) fn tell_log(invocation: &mut Invocation<'_>) -> CommandResult {
    let result = if invocation.line.has("start") {
        let mut file = [0u8; FILE_NAME_CAPACITY];
        let Some(file) = invocation
            .line
            .param("file")
            .map(|value| value.copy_into(&mut file))
        else {
            return Err(ErrorCode::BadParameter.into());
        };

        let Some(area) = invocation
            .line
            .dword("area")
            .map(TellLogAreas::from_bits_retain)
        else {
            return Err(ErrorCode::BadParameter.into());
        };

        // Absent values select blocking off and the engine defaults.
        let block = invocation
            .line
            .dword("block")
            .is_some_and(|value| value != 0);
        let size = invocation.line.dword("size").unwrap_or(0);
        let entries = invocation.line.dword("entries").unwrap_or(0);
        start(invocation.backend, file, area, block, size, entries)
    } else if invocation.line.has("stop") {
        // An absent area stops the log for every component.
        let area = invocation
            .line
            .dword("area")
            .map_or(TellLogAreas::empty(), TellLogAreas::from_bits_retain);
        stop(invocation.backend, area)
    } else {
        return Err(ErrorCode::UnknownCommand.into());
    };

    // A result of 0 sends no reply line.
    invocation.set_text(format_args!("hresult=0x{:x}", reply::hresult(result).0));

    result
}

fn start(
    backend: &mut dyn AnyBackend,
    file: &[u8],
    area: TellLogAreas,
    block: bool,
    size: u32,
    entries: u32,
) -> CommandResult {
    if let Some(open) = backend.tell_log_area() {
        if !area.is_empty() && !open.intersects(area) {
            backend.set_tell_log_area(open.union(area));
            return Ok(Reply::Sent);
        }

        return Ok(Reply::TellLog(TellLogReply::AlreadyOpen));
    }

    let mut path = Text::<{ PATH_PREFIX.len() + FILE_NAME_CAPACITY }>::new();
    let _ = path.push_bytes(PATH_PREFIX);
    let _ = path.push_bytes(file);
    let mut message = Text::<0x200>::new();
    let _ = message.push_bytes(b"DmTellLog: Open file = ");
    let _ = message.push_bytes(path.as_bytes());
    let _ = message.push_bytes(b"\n");
    backend.debug_print(message.as_bytes());
    let request = CreateRequest {
        access: AccessMask::GENERIC_WRITE.union(AccessMask::SYNCHRONIZE),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::READ.union(ShareAccess::WRITE),
        disposition: CreateDisposition::OverwriteIf,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT.union(CreateOptions::NON_DIRECTORY_FILE),
    };

    let opened = backend.create_file(path.as_bytes(), &request);
    if let Err(error) = opened {
        debug_print(
            backend,
            format_args!("DmTellLog: Failed to open file 0x{:x}\n", error.status().0),
        );
    }

    debug_print(backend, format_args!("Logging mask = 0x{:x}\n", area.0));
    // An unopened file sends no reply line.
    let Ok(file) = opened else {
        return Ok(Reply::Sent);
    };

    let config = TellLogConfig {
        entry_size: if size == 0 { DEFAULT_ENTRY_SIZE } else { size },
        entries: if entries == 0 {
            DEFAULT_ENTRIES
        } else {
            entries
        },
        block,
    };

    match backend.tell_log_start(file, area, config) {
        Ok(()) => Ok(Reply::TellLog(TellLogReply::Started)),
        Err(error) => {
            debug_print(backend, format_args!("DmTellLog: Unable to start Log\n"));
            backend.close_file(file);
            Err(CommandError::TellLog(TellLogFailed(error)))
        }
    }
}

fn stop(backend: &mut dyn AnyBackend, area: TellLogAreas) -> CommandResult {
    let not_open = Ok(Reply::TellLog(TellLogReply::NotOpen));
    let Some(open) = backend.tell_log_area() else {
        return not_open;
    };

    let remaining = open.difference(area);
    backend.set_tell_log_area(remaining);
    if !remaining.is_empty() && !area.is_empty() {
        return Ok(Reply::Sent);
    }

    let Some(counters) = backend.tell_log_close() else {
        return not_open;
    };

    debug_print(
        backend,
        format_args!(
            "DmTellLog: Closing Log: dropped {} messages, missed {} messages\n",
            counters.dropped as i32, counters.missed as i32
        ),
    );
    let Some(file) = backend.tell_log_stop() else {
        return not_open;
    };

    // The monitor ignores the flush status.
    let _ = backend.flush_file(file);
    backend.close_file(file);

    Ok(Reply::TellLog(TellLogReply::Stopped))
}

fn debug_print(backend: &mut dyn AnyBackend, arguments: core::fmt::Arguments<'_>) {
    let mut text = Text::<0x200>::new();
    let _ = text.write_fmt(arguments);
    backend.debug_print(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line() -> WaitTraceLine {
        WaitTraceLine {
            trace: WaitTrace::Enter,
            title: true,
            time_base: 0x1234_5678_9abc,
            section: 0x8204_0010,
            thread_id: 0xf900_0004,
            lock_count: 1,
            recursion_count: 0,
            processor: 3,
            owner: 0x8200_1000,
            owner_id: 0xf900_0008,
            owner_processor: -1,
            callers: [0x8201_0000, 0x8202_0000, 0x8203_0000],
        }
    }

    #[test]
    fn wait_trace_line_format() {
        let mut output = [0u8; TELL_LOG_LINE_LIMIT as usize];
        let length = format_wait_trace(&line(), 0x200, &mut output);
        let expected: &[u8] = b"E:T 0x0000123456789abc 0x82040010 0xf9000004 0x00000001 0x00000000 03 | 0x82001000 0xf9000008 -1 0x82010000 0x82020000 0x82030000\r\n\0";
        assert_eq!(&output[..length], expected);
    }

    #[test]
    fn wait_trace_line_cut_to_entry_size() {
        let mut output = [0u8; TELL_LOG_LINE_LIMIT as usize];
        let length = format_wait_trace(&line(), 0x10, &mut output);
        assert_eq!(&output[..length], b"E:T 0x00001234\n\0");
    }

    #[test]
    fn writer_collects_until_full_and_flushes_on_close() {
        let mut writer = TellLogWriter::new();
        let mut written = [0usize; 4];
        let mut writes = 0;
        let mut write = |bytes: &[u8]| {
            written[writes] = bytes.len();
            writes += 1;
            Ok(())
        };

        let entry = [b'a'; 0x1000];
        writer.process(&entry, false, &mut write).unwrap();
        writer.process(&entry, false, &mut write).unwrap();
        writer.process(b"tail\0stale", false, &mut write).unwrap();
        writer.process(b"closing", true, &mut write).unwrap();
        writer.process(b"later", true, &mut write).unwrap();
        assert_eq!(written, [0x2000, 4, 0, 0]);
    }
}
