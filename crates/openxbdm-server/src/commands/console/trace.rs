//! Diagnostic trace mask and DbgPrint texts.

use core::fmt::Write as _;

use super::Published;
use crate::backend::Backend as AnyBackend;
use crate::commands::system::SettingsFile;
use crate::commands::system::write_line;
use crate::commands::util;
use crate::invocation::Invocation;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;

xbox360_sys::flags! {
    /// Diagnostic trace mask set by `verbose` (stock 0x91f9fef4); each bit
    /// enables the monitor's DbgPrint texts of one area.
    pub struct TraceMask(u32) {
        /// Command lines, status lines, title command processor thread.
        REPLIES = 0x1,
        /// 204 binary receive.
        BINARY_RECEIVE = 0x2,
        /// Settings file reads and writes.
        SETTINGS = 0x4,
        /// Drive path and title image resolution.
        PATHS = 0x8,
        /// Title launch control codes.
        TITLE_LAUNCH = 0x10,
        /// CD-ROM driver setup at startup.
        CDROM = 0x20,
    }
}

/// Diagnostic message; holds the longest registration message (a 0x3ff-byte
/// path plus the server).
pub(crate) type MessageText = crate::text::Text<0x600>;

/// DbgPrint `arguments` when `bits` are set in the trace mask.
pub(crate) fn trace(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    bits: TraceMask,
    arguments: core::fmt::Arguments<'_>,
) {
    if state.console.trace_mask.intersects(bits) {
        print(backend, arguments);
    }
}

/// DbgPrint the text `build` writes when `bits` are set in `mask`. For
/// texts with byte strings, and for callers that hold only a backend
/// (`mask` is then [`super::Backend::trace_mask`]).
pub(crate) fn trace_text(
    mask: TraceMask,
    backend: &mut dyn AnyBackend,
    bits: TraceMask,
    build: impl FnOnce(&mut MessageText),
) {
    if mask.intersects(bits) {
        let mut message = MessageText::new();
        build(&mut message);
        backend.debug_print(message.as_bytes());
    }
}

pub(super) fn print(backend: &mut dyn AnyBackend, arguments: core::fmt::Arguments<'_>) {
    let mut message = MessageText::new();
    let _ = message.write_fmt(arguments);
    backend.debug_print(message.as_bytes());
}

/// `verbose level=<dword>`: the parsed prefix is stored even when the value
/// is rejected.
pub(super) fn verbose(invocation: &mut Invocation<'_>) -> CommandResult {
    if let Some(value) = invocation.line.param("level") {
        invocation.state.console.trace_mask = TraceMask::from_bits_retain(value.dword_prefix());
        invocation
            .backend
            .publish(Published::TraceMask(invocation.state.console.trace_mask));
    }

    if util::required_dword(invocation, "level").is_none() {
        return Err(util::MISSING);
    }

    crate::commands::system::save_settings(invocation.state, invocation.backend);

    Ok(Reply::Ok)
}

/// `verbose level=%d` when the trace mask is nonzero.
pub(crate) fn verbose_settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let mask = state.console.trace_mask.bits();
    if mask != 0 {
        write_line(backend, file, format_args!("verbose level={}", mask as i32));
    }
}
