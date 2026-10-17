//! Crash dump mode and settings.

use core::fmt::Write as _;

use super::Published;
use super::SettingsLine;
use super::c_string;
use super::string_param;
use crate::backend::Backend as AnyBackend;
use crate::commands::system::SettingsFile;
use crate::commands::system::end_line;
use crate::commands::system::write_bytes;
use crate::invocation::Invocation;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;

/// Bytes of the crash dump settings block of exports 119 and 120.
pub const DUMP_SETTINGS_SIZE: usize = 0x108;

/// Bytes of the path in that block.
const DUMP_SETTINGS_PATH_SIZE: usize = DUMP_SETTINGS_SIZE - 4;

/// Selector names in stock's table order (0x91f96bd0): reports,
/// destinations, formats, then a NULL entry the kernel formatter prints as
/// `(null)`. The summary indexes past a group as stock does.
const DUMP_NAMES: [&str; 10] = [
    "prompt", "always", "never", "local", "remote", "full", "partial", "noheap", "retail", "(null)",
];

const DUMP_REPORT: DumpField = DumpField {
    shift: 0,
    first: 0,
    count: 3,
    shown: 3,
};

const DUMP_DESTINATION: DumpField = DumpField {
    shift: 4,
    first: 3,
    count: 2,
    shown: 2,
};

const DUMP_FORMAT: DumpField = DumpField {
    shift: 8,
    first: 5,
    count: 4,
    shown: 4,
};

/// Crash dump mode set by `dumpmode` and export 118 (stock 0x91f9f660).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DumpMode {
    #[default]
    Smart,
    Enabled,
    Disabled,
    /// A value only export 118 stores; it acts and reads as `smart` but
    /// export 117 returns it unchanged.
    Other(u32),
}

impl DumpMode {
    const ALL: [Self; 3] = [Self::Smart, Self::Enabled, Self::Disabled];

    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Smart,
            1 => Self::Enabled,
            2 => Self::Disabled,
            other => Self::Other(other),
        }
    }

    pub const fn raw(self) -> u32 {
        match self {
            Self::Smart => 0,
            Self::Enabled => 1,
            Self::Disabled => 2,
            Self::Other(raw) => raw,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Smart | Self::Other(_) => "smart",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

/// Crash dump settings set by `dumpsettings` and export 120 (stock
/// 0x91f9f520): flags with the report in bits 0-3, the destination in
/// bits 4-7 and the format in bits 8-11, and the dump directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DumpSettings {
    flags: u32,
    path: [u8; DUMP_SETTINGS_PATH_SIZE],
    path_len: u16,
}

impl DumpSettings {
    pub const fn new() -> Self {
        Self {
            flags: 0,
            path: [0; DUMP_SETTINGS_PATH_SIZE],
            path_len: 0,
        }
    }

    /// The dump directory; empty when unset.
    pub fn path(&self) -> &[u8] {
        &self.path[..usize::from(self.path_len)]
    }

    fn set_path(&mut self, path: &[u8]) {
        let length = path.len().min(DUMP_SETTINGS_PATH_SIZE);
        self.path = [0; DUMP_SETTINGS_PATH_SIZE];
        self.path[..length].copy_from_slice(&path[..length]);
        self.path_len = length as u16;
    }

    fn set(&mut self, field: DumpField, value: u32) {
        self.flags = (self.flags & !(0xf << field.shift)) | value << field.shift;
    }

    fn name(&self, field: DumpField) -> &'static str {
        let value = (self.flags >> field.shift) & 0xf;
        let value = if value > field.shown { 0 } else { value };

        DUMP_NAMES[field.first + value as usize]
    }

    /// The block of export 119: big-endian flags, then the path. A path
    /// that fills its room has no terminator, as in stock.
    pub fn to_block(&self) -> [u8; DUMP_SETTINGS_SIZE] {
        let mut block = [0u8; DUMP_SETTINGS_SIZE];
        block[..4].copy_from_slice(&self.flags.to_be_bytes());
        block[4..].copy_from_slice(&self.path);

        block
    }

    /// The settings of an export 120 block; the path ends at its first NUL.
    pub fn from_block(block: &[u8; DUMP_SETTINGS_SIZE]) -> Self {
        let mut settings = Self {
            flags: u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
            ..Self::new()
        };

        settings.set_path(c_string(&block[4..]));

        settings
    }

    /// `rpt=%s dst=%s fmt=%s[ path=%s]`.
    fn write_summary(&self, output: &mut dyn FnMut(&[u8])) {
        output(b"rpt=");
        output(self.name(DUMP_REPORT).as_bytes());
        output(b" dst=");
        output(self.name(DUMP_DESTINATION).as_bytes());
        output(b" fmt=");
        output(self.name(DUMP_FORMAT).as_bytes());

        if self.path_len != 0 {
            output(b" path=");
            output(self.path());
        }
    }
}

/// A 4-bit field of the crash dump flags.
#[derive(Clone, Copy)]
struct DumpField {
    shift: u32,
    /// Index of the field's first name in [`DUMP_NAMES`].
    first: usize,
    /// Names `dumpsettings` accepts.
    count: usize,
    /// Largest value the summary shows; larger values show as 0.
    shown: u32,
}

/// `dumpmode [smart|enabled|disabled]`: the first present flag is stored
/// through export 118. Replies with the current mode.
pub(super) fn dump_mode(invocation: &mut Invocation<'_>) -> CommandResult {
    if let Some(mode) = DumpMode::ALL
        .into_iter()
        .find(|mode| invocation.line.has(mode.name()))
    {
        set_dump_mode(invocation.state, invocation.backend, mode);
        crate::commands::system::save_settings(invocation.state, invocation.backend);
    }

    invocation
        .text
        .set_bytes(invocation.state.console.dump_mode.name().as_bytes());

    Ok(Reply::Ok)
}

/// Stock export 118, also behind `dumpmode`: a test kit stores `enabled`
/// for `smart`.
pub(super) fn set_dump_mode(state: &mut ServerState, backend: &mut dyn AnyBackend, mode: DumpMode) {
    let mode = if mode == DumpMode::Smart && backend.is_test_kit() {
        backend.debug_print(b"Reset Dump mode to ENABLED for the TEST KIT!\n");
        DumpMode::Enabled
    } else {
        mode
    };

    state.console.dump_mode = mode;
    backend.publish(Published::DumpMode(mode));
}

/// The index of the name a `dumpsettings` selector gives for `field`.
fn dump_selector(invocation: &Invocation<'_>, name: &str, field: DumpField) -> Option<u32> {
    /// Value buffer of the selectors.
    const SELECTOR_BUFFER: usize = 0x3f;

    let mut buffer = [0u8; SELECTOR_BUFFER];
    let value = string_param(invocation, name, &mut buffer)?;
    let names = &DUMP_NAMES[field.first..field.first + field.count];

    names
        .iter()
        .position(|word| value.eq_ignore_ascii_case(word.as_bytes()))
        .map(|index| index as u32)
}

/// `dumpsettings [rpt=] [dst=] [fmt=] [path=]`: unrecognized values are
/// ignored; replies with the current settings.
pub(super) fn dump_settings(invocation: &mut Invocation<'_>) -> CommandResult {
    let mut settings = invocation.state.console.dump_settings;

    let mut changed = false;
    for (name, field) in [
        ("rpt", DUMP_REPORT),
        ("dst", DUMP_DESTINATION),
        ("fmt", DUMP_FORMAT),
    ] {
        if let Some(value) = dump_selector(invocation, name, field) {
            settings.set(field, value);
            changed = true;
        }
    }

    if let Some(value) = invocation.line.param("path") {
        /// Characters kept of a crash dump path.
        const PATH_CAPACITY: usize = 0x102;

        let mut buffer = [0u8; PATH_CAPACITY + 1];
        settings.set_path(value.copy_into(&mut buffer));
        changed = true;
    }

    if changed {
        invocation.state.console.dump_settings = settings;
        invocation
            .backend
            .publish(Published::DumpSettings(&settings));
        crate::commands::system::save_settings(invocation.state, invocation.backend);
    }

    let text = &mut *invocation.text;
    text.clear();
    settings.write_summary(&mut |bytes| {
        let _ = text.push_bytes(bytes);
    });

    Ok(Reply::Ok)
}

/// `dumpsettings rpt=.. dst=.. fmt=..[ path=..]` (stock 0x91f2d5c0).
pub(crate) fn dump_settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let mut line = SettingsLine::new();
    let _ = line.write_str("dumpsettings ");
    state.console.dump_settings.write_summary(&mut |bytes| {
        let _ = line.push_bytes(bytes);
    });
    write_bytes(backend, file, line.as_bytes());
    end_line(backend, file);
}
