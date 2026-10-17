//! The `netsim` configuration file: `reload` executes its lines, and every
//! change rewrites it.
// Pool blocks are freed through the unsafe `Backend::free_pool`.
#![allow(unsafe_code)]

use core::fmt::Write as _;

use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use crate::backend::Backend as AnyBackend;
use crate::commands::console;
use crate::commands::console::TraceMask;
use crate::commands::filesystem::CreateRequest;
use crate::commands::filesystem::FileData;
use crate::commands::filesystem::FileHandle;
use crate::commands::filesystem::PoolBuffer;
use crate::commands::filesystem::PoolRange;
use crate::commands::filesystem::ReadTarget;
use crate::commands::network;
use crate::commands::network::LinkFlags;
use crate::commands::network::MissingLinkMask;
use crate::commands::network::netsim::CONFIG_CAPACITY;
use crate::commands::network::netsim::Direction;
use crate::commands::network::netsim::NetsimError;
use crate::commands::network::netsim::QueueIndex;
use crate::commands::network::netsim::RedirectIndex;
use crate::commands::network::netsim::Request;
use crate::commands::network::netsim::execute;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::text::HEX_UPPER;
use crate::text::ResponseText;

/// Pool buffer of the file reader and writer.
const FILE_BUFFER_SIZE: usize = 0x4000;
const LINE_END: &[u8] = b"\r\n";

/// A file line the reader executes. One value lives briefly on the stack;
/// there is no allocator to box the larger variant.
#[allow(clippy::large_enum_variant)]
enum FileLine {
    Netsim(Result<Request, CommandError>),
    LinkState(Result<Option<LinkFlags>, MissingLinkMask>),
}

/// Buffered writer over a pool block (0x91f319c8 and 0x91f31860).
struct PoolWriter {
    handle: FileHandle,
    buffer: PoolBuffer,
    used: usize,
}

impl PoolWriter {
    fn push(&mut self, backend: &mut dyn AnyBackend, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let count = bytes.len().min(FILE_BUFFER_SIZE - self.used);
            backend.pool(self.buffer)[self.used..self.used + count]
                .copy_from_slice(&bytes[..count]);
            self.used += count;
            bytes = &bytes[count..];

            if self.used == FILE_BUFFER_SIZE {
                self.flush(backend);
            }
        }
    }

    /// Stock stops the system on a failed write; the result is ignored here.
    fn flush(&mut self, backend: &mut dyn AnyBackend) {
        if self.used == 0 {
            return;
        }

        let range = PoolRange {
            buffer: self.buffer,
            offset: 0,
            length: self.used as u32,
        };
        let _ = backend.write_file(self.handle, None, FileData::Pool(range));
        self.used = 0;
    }

    fn line(&mut self, backend: &mut dyn AnyBackend, prefix: &[u8], blob: &[u8]) {
        self.push(backend, prefix);

        for &byte in blob {
            self.push(
                backend,
                &[
                    HEX_UPPER[usize::from(byte >> 4)],
                    HEX_UPPER[usize::from(byte & 0xf)],
                ],
            );
        }

        self.push(backend, LINE_END);
    }
}

/// `reload` (0x91f36818): replace the instance with the file's
/// configuration. The reply text is always `file="<stored name>"`.
pub(super) fn reload(invocation: &mut Invocation<'_>, name: &[u8]) -> CommandResult {
    if invocation.state.network.netsim.reloading {
        return Err(NetsimError::Busy.into());
    }

    invocation.state.network.netsim.reloading = true;
    let result = run_reload(invocation, name);

    invocation.text.clear();
    let _ = invocation.text.write_str("file=\"");
    let _ = invocation
        .text
        .push_bytes(invocation.state.network.netsim.file.as_bytes());
    let _ = invocation.text.write_str("\"");
    invocation.state.network.netsim.reloading = false;

    result
}

fn run_reload(invocation: &mut Invocation<'_>, name: &[u8]) -> CommandResult {
    if !name.is_empty() {
        let translated = invocation
            .state
            .filesystem
            .drives
            .translate(invocation.backend, name);
        let file = &mut invocation.state.network.netsim.file;
        match translated {
            Some(path) => file.set(path.as_bytes()),
            None => file.set(name),
        }
    } else if invocation.state.network.netsim.file.as_bytes().is_empty() {
        return Err(ErrorCode::FilenameInvalid.into());
    }

    if invocation.backend.simulator_exists()
        && let Err(error) = invocation.backend.destroy_simulator()
    {
        return Err(error.into());
    }

    let file = &invocation.state.network.netsim.file;
    let request = CreateRequest {
        access: AccessMask::GENERIC_READ,
        allocation_size: None,
        attributes: FileAttributes::empty(),
        share: ShareAccess::empty(),
        disposition: CreateDisposition::Open,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    };
    let handle = match invocation.backend.create_file(file.as_bytes(), &request) {
        Ok(handle) => handle,
        Err(error) => {
            return Err(CommandError::from_kernel(
                error,
                ErrorCode::Undefined.into(),
            ));
        }
    };

    let result = match invocation.backend.allocate_pool(FILE_BUFFER_SIZE as u32) {
        Some(buffer) => {
            let failed = execute_file(invocation, handle, buffer);
            // SAFETY: the block is local to this command and not used after.
            unsafe { invocation.backend.free_pool(buffer) };

            // Stock rewrites before closing the reader, whose handle shares
            // nothing.
            if failed {
                write_file(
                    invocation.state.network.netsim.file.as_bytes(),
                    invocation.backend,
                );
            }

            Ok(Reply::Ok)
        }
        None => Err(NetsimError::OutOfMemory.into()),
    };
    invocation.backend.close_file(handle);

    result
}

/// Execute the file's lines (reader 0x91f315a0, line callback 0x91f35f88).
/// Lines end at CR or LF; a remainder that starts with NUL ends the file,
/// and text that fills the buffer or ends the file without a terminator
/// loses its last byte. Returns whether a line failed.
fn execute_file(invocation: &mut Invocation<'_>, handle: FileHandle, buffer: PoolBuffer) -> bool {
    let mut failed = false;
    let mut count = 0usize;

    loop {
        if count != 0 {
            let mut start = 0;
            let mut position = 0;

            while position < count {
                let byte = invocation.backend.pool(buffer)[position];
                if matches!(byte, b'\n' | b'\r') {
                    failed |= execute_line(invocation, buffer, start..position);
                    start = position + 1;
                }
                position += 1;
            }

            // The byte past the data is taken as nonzero.
            if start < count && invocation.backend.pool(buffer)[start] == 0 {
                return failed;
            }

            if start != 0 {
                invocation.backend.pool(buffer).copy_within(start..count, 0);
                count -= start;
            } else {
                failed |= execute_line(invocation, buffer, 0..count - 1);
                count = 0;
            }
        }

        let target = PoolRange {
            buffer,
            offset: count as u32,
            length: (FILE_BUFFER_SIZE - count) as u32,
        };
        if let Ok(read) = invocation
            .backend
            .read_file(handle, None, ReadTarget::Pool(target))
        {
            count += read as usize;
        }

        if count == 0 {
            return failed;
        }
    }
}

/// Run a `netsim` or `linkstate` line of the reader's buffer without a
/// connection; other lines are ignored. Returns whether it failed.
fn execute_line(
    invocation: &mut Invocation<'_>,
    buffer: PoolBuffer,
    range: core::ops::Range<usize>,
) -> bool {
    trace_line(
        invocation.state.console.trace_mask,
        invocation.backend,
        buffer,
        range.clone(),
    );

    let line = CommandLine::new(&invocation.backend.pool(buffer)[range]);
    let request = if line.is_command("netsim") {
        FileLine::Netsim(Request::parse(line))
    } else if line.is_command("linkstate") {
        FileLine::LinkState(network::parse_link_state(line))
    } else {
        return false;
    };

    let mut text = ResponseText::new();
    let mut nested = Invocation {
        line: CommandLine::new(&[]),
        buffer: &[],
        text: &mut text,
        session: None,
        state: &mut *invocation.state,
        backend: &mut *invocation.backend,
        network: &mut *invocation.network,
    };
    let result = match request {
        FileLine::Netsim(request) => execute(&mut nested, request),
        FileLine::LinkState(flags) => network::execute_link_state(&mut nested, flags),
    };
    let Err(error) = result else {
        return false;
    };

    console::trace(
        invocation.state,
        invocation.backend,
        TraceMask::SETTINGS,
        format_args!(
            "XBDM: NetSimReadIniLine processing command failed (0x{:08x})\n",
            Hresult::from(error).0
        ),
    );

    true
}

#[inline(never)]
fn trace_line(
    mask: TraceMask,
    backend: &mut dyn AnyBackend,
    buffer: PoolBuffer,
    range: core::ops::Range<usize>,
) {
    if !mask.contains(TraceMask::SETTINGS) {
        return;
    }

    let mut message = console::MessageText::new();
    let _ = message.write_str("XBDM: NetSimReadIniLine '");
    let _ = message.push_bytes(console::c_string(&backend.pool(buffer)[range]));
    let _ = message.write_str("'\n");
    backend.debug_print(message.as_bytes());
}

/// NetSimWriteIniFile (0x91f36290): replace the file with one line per in
/// queue, out queue, and redirect. Nothing is written without a stored
/// name, pool memory, or a created file.
pub(super) fn write_file(name: &[u8], backend: &mut dyn AnyBackend) {
    let mask = console::Backend::trace_mask(backend);
    let trace = |backend: &mut dyn AnyBackend, arguments: core::fmt::Arguments<'_>| {
        console::trace_text(mask, backend, TraceMask::SETTINGS, |message| {
            let _ = message.write_fmt(arguments);
        });
    };

    if name.is_empty() {
        trace(
            backend,
            format_args!("XBDM: NetSimWriteIniFile - No filename configured.\n"),
        );
        return;
    }

    console::trace_text(mask, backend, TraceMask::SETTINGS, |message| {
        let _ = message.write_str("XBDM: NetSimWriteIniFile - Starting to write \"");
        let _ = message.push_bytes(console::c_string(name));
        let _ = message.write_str("\".\n");
    });

    let Some(buffer) = backend.allocate_pool(FILE_BUFFER_SIZE as u32) else {
        trace(
            backend,
            format_args!("XBDM: NetSimWriteIniFile - No memory!\n"),
        );
        return;
    };
    backend.pool(buffer).fill(0);

    let request = CreateRequest {
        access: AccessMask::GENERIC_WRITE,
        allocation_size: None,
        attributes: FileAttributes::empty(),
        share: ShareAccess::empty(),
        disposition: CreateDisposition::OverwriteIf,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    };
    let handle = match backend.create_file(name, &request) {
        Ok(handle) => handle,
        Err(error) => {
            trace(
                backend,
                format_args!(
                    "XBDM: NetSimWriteIniFile - Failed to create file: 0x{:08x}\n",
                    NtStatus::from(error).0
                ),
            );
            // SAFETY: the block is local to this command and not used after.
            unsafe { backend.free_pool(buffer) };
            return;
        }
    };

    let mut writer = PoolWriter {
        handle,
        buffer,
        used: 0,
    };
    writer.push(backend, b"[xbdm]");
    writer.push(backend, LINE_END);

    let exists = backend.simulator_exists();
    for (direction, prefix) in [
        (Direction::Inbound, b"netsim insertq in cfg=".as_slice()),
        (Direction::Outbound, b"netsim insertq out cfg=".as_slice()),
    ] {
        let count = if exists {
            backend.queue_count(direction)
        } else {
            0
        };
        for index in 0..count {
            let Ok(snapshot) = backend.queue(direction, QueueIndex(index)) else {
                break;
            };
            let mut blob = [0u8; CONFIG_CAPACITY];
            let Ok(length) = snapshot.serialize(&mut blob) else {
                break;
            };
            writer.line(backend, prefix, &blob[..length]);
        }
    }

    let count = if exists { backend.redirect_count() } else { 0 };
    for index in 0..count {
        let Some(redirect) = backend.redirect(RedirectIndex(index)) else {
            break;
        };
        let mut blob = [0u8; CONFIG_CAPACITY];
        let Ok(length) = redirect.serialize(&mut blob) else {
            break;
        };
        writer.line(backend, b"netsim insertipv4redir cfg=", &blob[..length]);
    }

    writer.flush(backend);
    backend.close_file(handle);
    trace(
        backend,
        format_args!("XBDM: NetSimWriteIniFile - Done writing ini file.\n"),
    );

    // SAFETY: the block is local to this command and not used after.
    unsafe { backend.free_pool(buffer) };
}
