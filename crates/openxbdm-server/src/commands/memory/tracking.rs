//! `memtrack` allocation tracking settings and record dump.

use openxbdm_core::line::Value;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::Win32Error;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::MemoryError;
use super::string_param;
use crate::commands::debugger;
use crate::commands::filesystem;
use crate::commands::system::SettingsFile;
use crate::commands::system::write_line;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;

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

xbox360_sys::flags! {
    /// Allocation tracking type flags. The low eight bits select allocation
    /// types, bit 8 turns tracking diagnostics into assertions, and bit 31 of
    /// the saved value marks a pending `enableonce`.
    pub struct TrackingFlags(u32) {
        /// Allocation type selection; `enable` needs at least one.
        TYPES = 0xff,
        ASSERT = 0x100,
        /// Set in the saved flags by `enableonce`; cleared when the settings
        /// file is loaded.
        ONCE = 0x8000_0000,
    }
}

impl TrackingFlags {
    /// Bits `enable` replaces and `disable` clears.
    pub const TYPE_MASK: Self = Self::TYPES.union(Self::ASSERT);
    /// Default `flags` value of `enable` and `enableonce`.
    pub const DEFAULT: Self = Self::TYPE_MASK;

    /// Whether any tracking type is selected.
    pub fn is_active(self) -> bool {
        self.intersects(Self::TYPE_MASK)
    }
}

/// Number of return addresses captured per tracked allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StackDepth(pub u32);

/// Persisted allocation tracking settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrackingSettings {
    pub flags: TrackingFlags,
    pub stack_depth: StackDepth,
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

/// `memtrack cmd=<command> ...`: allocation tracking settings, queries, and
/// record dump.
pub(super) fn memory_tracking(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Bytes of the `cmd` buffer.
    const COMMAND_CAPACITY: usize = 0x20;
    /// Bytes of the `filename` buffer of `save`.
    const FILENAME_CAPACITY: usize = 0x140;
    const COMMANDS: [(&str, TrackingCommand); 7] = [
        ("enable", TrackingCommand::Enable),
        ("enableonce", TrackingCommand::EnableOnce),
        ("disable", TrackingCommand::Disable),
        ("save", TrackingCommand::Save),
        ("querystackdepth", TrackingCommand::QueryStackDepth),
        ("queryflags", TrackingCommand::QueryFlags),
        ("querytype", TrackingCommand::QueryType),
    ];

    let mut buffer = [0u8; COMMAND_CAPACITY];
    let command = string_param(invocation, "cmd", &mut buffer).and_then(|text| {
        COMMANDS
            .iter()
            .find(|(name, _)| text.eq_ignore_ascii_case(name.as_bytes()))
            .map(|&(_, command)| command)
    });

    let result = match command {
        Some(command @ (TrackingCommand::Enable | TrackingCommand::EnableOnce)) => {
            tracking_enable(invocation, command == TrackingCommand::EnableOnce)
        }
        Some(TrackingCommand::Disable) => {
            invocation
                .state
                .memory
                .tracking
                .flags
                .remove(TrackingFlags::TYPE_MASK);
            invocation.state.settings_dirty = true;
            Ok(Reply::Ok)
        }
        Some(TrackingCommand::Save) => {
            let mut buffer = [0u8; FILENAME_CAPACITY];
            match string_param(invocation, "filename", &mut buffer) {
                Some(filename) => save_tracking_records(invocation, filename),
                None => Err(CommandError::InvalidArgument),
            }
        }
        Some(command @ (TrackingCommand::QueryStackDepth | TrackingCommand::QueryFlags)) => {
            let value = if command == TrackingCommand::QueryFlags {
                invocation.backend.tracking_flags().bits()
            } else {
                ACTIVE_STACK_DEPTH.0
            };
            invocation.set_text(format_args!("0x{value:x}"));
            return Ok(Reply::Ok);
        }
        Some(TrackingCommand::QueryType) => {
            let name = invocation
                .line
                .dword("type")
                .and_then(|index| TRACKING_TYPE_NAMES.get(usize::from(index as u16)));
            match name {
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
            tracking.flags.bits(),
            tracking.stack_depth.0
        ),
    );
}

/// Settings file `memtrack` line: restore the saved settings without a
/// pending one-time enable.
pub(crate) fn ini_memtrack(invocation: &mut Invocation<'_>) {
    let tracking = &mut invocation.state.memory.tracking;
    if let Some(value) = invocation.line.param("flags") {
        tracking.flags = TrackingFlags::from_bits_retain(value.dword_prefix());
    }
    if let Some(value) = invocation.line.param("stackdepth") {
        tracking.stack_depth = StackDepth(value.dword_prefix());
    }

    tracking.flags.remove(TrackingFlags::ONCE);
}

/// The dword the monitor's getters store, which is the parsed prefix
/// whenever the parameter is present, and whether the getter accepted the
/// parameter.
fn dword_param(value: Option<Value<'_>>) -> (Option<u32>, bool) {
    match value {
        Some(value) => (Some(value.dword_prefix()), value.dword().is_some()),
        None => (None, false),
    }
}

/// `enable` persists the settings; `enableonce` changes the flags in
/// effect and marks the saved flags. The reply text names the last
/// parameter that was missing.
fn tracking_enable(invocation: &mut Invocation<'_>, once: bool) -> CommandResult {
    /// Largest stack depth accepted.
    const MAX_STACK_DEPTH: u32 = 0x20;

    let (depth, depth_valid) = dword_param(invocation.line.param("stackdepth"));
    let (flags, flags_valid) = dword_param(invocation.line.param("flags"));
    let missing = if !flags_valid {
        Some("flags")
    } else if !depth_valid {
        Some("stackdepth")
    } else {
        None
    };

    // Absent parameters take the `enable` defaults.
    let depth = StackDepth(depth.unwrap_or(0));
    let flags = TrackingFlags::from_bits_retain(flags.unwrap_or(TrackingFlags::DEFAULT.bits()));
    if depth.0 > MAX_STACK_DEPTH || !flags.intersects(TrackingFlags::TYPES) {
        return Err(CommandError::InvalidArgument);
    }

    let saved = &mut invocation.state.memory.tracking;
    if once {
        invocation.backend.set_tracking_flags(flags);
        saved.flags.insert(TrackingFlags::ONCE);
    } else {
        saved.stack_depth = depth;
        saved.flags = saved
            .flags
            .difference(TrackingFlags::TYPE_MASK)
            .union(flags);
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
        // No allocation type is tracked.
        return Err(CommandError::Win32(Win32Error::SERVICE_NOT_ACTIVE));
    }

    let request = filesystem::CreateRequest {
        access: AccessMask::GENERIC_WRITE
            .union(AccessMask::DELETE)
            .union(AccessMask::SYNCHRONIZE),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::READ,
        disposition: CreateDisposition::OverwriteIf,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
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
