//! `netsim` (stock 0x91f37418): the Ethernet-level network simulator. Frames
//! pass through ordered inbound and outbound queues that delay, limit, or
//! drop them, and IPv4 redirects rewrite their addresses. The configuration
//! is kept in a file of `netsim` lines that `reload` executes.

pub mod api;
pub mod classifier;
mod config;
mod error;
mod settings_file;

use core::fmt::Write as _;

use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;

use self::config::parse_insert_blob;
use self::settings_file::reload;
use self::settings_file::write_file;
use super::SystemVersion;
use super::decode_hex;
use crate::backend::Backend as AnyBackend;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

pub use self::classifier::Program;
pub use self::classifier::Source;
pub use self::config::CONFIG_CAPACITY;
pub use self::config::ConfigMask;
pub use self::config::LOSS_SCALE;
pub use self::config::QueueConfig;
pub use self::config::QueueKind;
pub use self::config::RedirectConfig;
pub use self::config::parse_program;
pub use self::config::parse_queue_blob;
pub use self::error::InvalidConfig;
pub use self::error::NetsimError;

/// First system version with the simulator.
const NETSIM_VERSION: SystemVersion = SystemVersion(0x2027_8700);
/// Characters of the stored file name (0x91f9fc88 holds 0x104 bytes).
const PATH_LIMIT: usize = 0x103;
/// Capacity of the `file=` copy, terminator included.
const FILE_PARAMETER_CAPACITY: usize = 0x104;

/// Global state of `netsim`.
#[derive(Debug)]
pub struct State {
    /// File the configuration is written to and reloaded from.
    pub file: FilePath,
    /// A reload is running (0x91f9f69c).
    pub reloading: bool,
}

impl State {
    pub const fn new() -> Self {
        Self {
            file: FilePath::EMPTY,
            reloading: false,
        }
    }
}

/// Stored configuration file name.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FilePath {
    bytes: [u8; PATH_LIMIT],
    len: usize,
}

impl FilePath {
    const EMPTY: Self = Self {
        bytes: [0; PATH_LIMIT],
        len: 0,
    };

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn set(&mut self, name: &[u8]) {
        let count = name.len().min(PATH_LIMIT);
        self.bytes[..count].copy_from_slice(&name[..count]);
        self.len = count;
    }
}

impl core::fmt::Debug for FilePath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(core::str::from_utf8(self.as_bytes()).unwrap_or("<binary>"))
    }
}

/// Direction of a queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Received frames (stock direction 1, flag `in`).
    Inbound,
    /// Transmitted frames (stock direction 0, flag `out`).
    Outbound,
}

/// Position of a queue in its direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueueIndex(pub u32);

/// Position of a redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RedirectIndex(pub u32);

/// Counters of a queue (queue +0x40..+0x57).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueStats {
    pub total_packets: u32,
    pub total_bytes: u64,
    pub dropped_packets: u32,
    pub dropped_bytes: u64,
}

/// A queue's type, stored settings, and classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueSnapshot {
    pub kind: QueueKind,
    pub config: QueueConfig,
    pub program: Option<Program>,
}

impl QueueSnapshot {
    /// The `cfg=` blob of `getq` and the settings file.
    pub fn serialize(&self, blob: &mut [u8; CONFIG_CAPACITY]) -> Result<usize, NetsimError> {
        api::queue_blob(
            self.kind as u32,
            &self.config,
            self.program.as_ref().map(Source::Parsed),
            blob,
        )
    }
}

/// A redirect with its classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectSnapshot {
    pub config: RedirectConfig,
    pub program: Option<Program>,
}

impl RedirectSnapshot {
    /// The `cfg=` blob of the settings file.
    pub fn serialize(&self, blob: &mut [u8; CONFIG_CAPACITY]) -> Result<usize, NetsimError> {
        api::redirect_blob(
            &self.config,
            self.program.as_ref().map(Source::Parsed),
            blob,
        )
    }
}

/// Queues removed and left by [`remove_queues`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueRemoval {
    pub removed: u32,
    pub inbound_left: u32,
    pub outbound_left: u32,
}

/// Redirects removed and left by [`remove_redirects`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectRemoval {
    pub removed: u32,
    pub left: u32,
}

xbox360_sys::flags! {
    /// `XeKeysGetStatus` result.
    pub struct KeyStatus(u32) {
        /// Settings-file `netsim reload` lines are skipped while this status
        /// bit is set (DoIniLine 0x91f311b8); its meaning is not identified.
        SKIP_SETTINGS_RELOAD = 0x8,
    }
}

/// Platform services `netsim` needs: the simulator library. Every queue and
/// redirect operation is called only while the instance exists.
pub trait Backend {
    /// Whether the instance exists (0x91f9fc84).
    fn simulator_exists(&mut self) -> bool;
    /// Create the instance and attach it to the Ethernet intercept
    /// (0x91f365e8).
    fn create_simulator(&mut self) -> Result<(), NetsimError>;
    /// Detach and free the instance, restoring a running capture's own
    /// intercept (0x91f36750).
    fn destroy_simulator(&mut self) -> Result<(), NetsimError>;
    fn queue_count(&mut self, direction: Direction) -> u32;
    fn redirect_count(&mut self) -> u32;
    /// Create a queue from validated settings and insert it before
    /// `position`, or append it (0x91f8ea98).
    fn insert_queue(
        &mut self,
        direction: Direction,
        position: Option<QueueIndex>,
        kind: QueueKind,
        update: &QueueConfig,
        program: Option<&Program>,
    ) -> Result<QueueIndex, NetsimError>;
    /// Apply validated settings to a queue (0x91f8ec80).
    fn modify_queue(
        &mut self,
        direction: Direction,
        index: QueueIndex,
        update: &QueueConfig,
    ) -> Result<(), NetsimError>;
    /// Remove the queue at `position`, or every queue (0x91f8e0e8); returns
    /// the number removed.
    fn remove_queues(
        &mut self,
        direction: Direction,
        position: Option<QueueIndex>,
    ) -> Result<u32, NetsimError>;
    fn queue_stats(
        &mut self,
        direction: Direction,
        index: QueueIndex,
    ) -> Result<QueueStats, NetsimError>;
    fn queue(
        &mut self,
        direction: Direction,
        index: QueueIndex,
    ) -> Result<QueueSnapshot, NetsimError>;
    /// Insert a redirect before `position`, or append it (0x91f8d7c0).
    fn insert_redirect(
        &mut self,
        position: Option<RedirectIndex>,
        redirect: &RedirectConfig,
        program: Option<&Program>,
    ) -> Result<RedirectIndex, NetsimError>;
    /// Remove the redirect at `position`, or every redirect (0x91f8d960).
    fn remove_redirects(&mut self, position: Option<RedirectIndex>) -> Result<u32, NetsimError>;
    fn redirect(&mut self, index: RedirectIndex) -> Option<RedirectSnapshot>;
    fn key_status(&mut self) -> KeyStatus;
}

/// Parameters shared by the queue and redirect subcommands.
struct Selection {
    inbound: bool,
    outbound: bool,
    index: Option<u32>,
}

impl Selection {
    /// The single direction `in` or `out` names.
    fn direction(&self) -> Option<Direction> {
        match (self.inbound, self.outbound) {
            (true, false) => Some(Direction::Inbound),
            (false, true) => Some(Direction::Outbound),
            _ => None,
        }
    }
}

/// Subcommands that take a [`Selection`] and an optional `cfg=` blob.
#[derive(Clone, Copy)]
enum Edit {
    InsertQueue,
    RemoveQueues,
    ModifyQueue,
    QueueStats,
    Queue,
    InsertRedirect,
    RemoveRedirects,
}

/// A parsed `netsim` line. Execution does not read the line, so settings
/// file lines run from the reader's pool buffer without a copy.
enum Request {
    Reload {
        file: [u8; FILE_PARAMETER_CAPACITY],
        length: usize,
    },
    QueueCounts,
    RedirectCount,
    Edit {
        edit: Option<Edit>,
        selection: Selection,
        blob: [u8; CONFIG_CAPACITY],
        blob_length: usize,
    },
}

impl Request {
    /// A bad `cfg=` digit is an unknown command.
    fn parse(line: CommandLine<'_>) -> Result<Self, CommandError> {
        const EDITS: [(&str, Edit); 7] = [
            ("insertq", Edit::InsertQueue),
            ("removeq", Edit::RemoveQueues),
            ("modifyq", Edit::ModifyQueue),
            ("getqstats", Edit::QueueStats),
            ("getq", Edit::Queue),
            ("insertipv4redir", Edit::InsertRedirect),
            ("removeipv4redir", Edit::RemoveRedirects),
        ];

        if line.has("reload") {
            let mut file = [0u8; FILE_PARAMETER_CAPACITY];
            let length = match line.param("file") {
                Some(value) => value.copy_into(&mut file).len(),
                None => 0,
            };
            return Ok(Self::Reload { file, length });
        }

        if line.has("getnumqs") {
            return Ok(Self::QueueCounts);
        }

        if line.has("getnumipv4redirs") {
            return Ok(Self::RedirectCount);
        }

        let selection = Selection {
            inbound: line.has("in"),
            outbound: line.has("out"),
            index: line.dword("index").filter(|&index| index != u32::MAX),
        };

        let mut blob = [0u8; CONFIG_CAPACITY];
        let blob_length = match line.param("cfg") {
            Some(value) => {
                let raw = value.raw();
                let text = raw.strip_prefix(b"\"").unwrap_or(raw);
                decode_hex(text, &mut blob).ok_or(ErrorCode::UnknownCommand)?
            }
            None => 0,
        };

        let edit = EDITS
            .iter()
            .find(|(name, _)| line.has(name))
            .map(|&(_, edit)| edit);

        Ok(Self::Edit {
            edit,
            selection,
            blob,
            blob_length,
        })
    }
}

/// The `err=` text of a failed helper, with its reported status.
fn fail(invocation: &mut Invocation<'_>, error: NetsimError) -> CommandResult {
    invocation.set_text(format_args!("err=0x{:08x}", Hresult::from(error).0));

    Err(error.into())
}

/// `netsim reload [file=<name>] | getnumqs | getnumipv4redirs |
/// insertq in|out [index=<n>] cfg=<hex> | removeq [in] [out] [index=<n>] |
/// modifyq in|out index=<n> cfg=<hex> | getqstats in|out index=<n> |
/// getq in|out index=<n> | insertipv4redir [index=<n>] cfg=<hex> |
/// removeipv4redir [index=<n>]`.
pub(super) fn netsim(invocation: &mut Invocation<'_>) -> CommandResult {
    let request = Request::parse(invocation.line);

    execute(invocation, request)
}

#[inline(never)]
fn execute(
    invocation: &mut Invocation<'_>,
    request: Result<Request, CommandError>,
) -> CommandResult {
    if super::Backend::system_version(invocation.backend) < NETSIM_VERSION {
        return Err(ErrorCode::UnknownCommand.into());
    }

    let (edit, selection, blob, blob_length) = match request? {
        Request::Reload { file, length } => return reload(invocation, &file[..length]),
        Request::QueueCounts => return queue_counts_command(invocation),
        Request::RedirectCount => {
            let count = redirect_count(invocation.backend);
            invocation.set_text(format_args!("num={count}"));
            return Ok(Reply::Ok);
        }
        Request::Edit {
            edit,
            selection,
            blob,
            blob_length,
        } => (edit, selection, blob, blob_length),
    };

    // An empty `cfg=` counts as missing.
    let blob = (blob_length != 0).then_some(&blob[..blob_length]);
    let persist = invocation.session.is_some();
    let Some(edit) = edit else {
        return Err(NetsimError::Invalid.into());
    };

    match edit {
        Edit::InsertQueue => {
            let (Some(direction), Some(blob)) = (selection.direction(), blob) else {
                return Err(NetsimError::Invalid.into());
            };
            insert_queue_command(
                invocation,
                direction,
                selection.index.map(QueueIndex),
                blob,
                persist,
            )
        }
        Edit::RemoveQueues => {
            let (inbound, outbound) = match selection.index {
                None if !selection.inbound && !selection.outbound => (true, true),
                None => (selection.inbound, selection.outbound),
                Some(_) if selection.direction().is_none() => {
                    return Err(NetsimError::Invalid.into());
                }
                Some(_) => (selection.inbound, selection.outbound),
            };
            remove_queues_command(
                invocation,
                inbound,
                outbound,
                selection.index.map(QueueIndex),
                persist,
            )
        }
        Edit::ModifyQueue => {
            let (Some(direction), Some(index), Some(blob)) =
                (selection.direction(), selection.index, blob)
            else {
                return Err(NetsimError::Invalid.into());
            };
            modify_queue_command(invocation, direction, QueueIndex(index), blob, persist)
        }
        Edit::QueueStats | Edit::Queue => {
            let (Some(direction), Some(index)) = (selection.direction(), selection.index) else {
                return Err(NetsimError::Invalid.into());
            };
            if matches!(edit, Edit::QueueStats) {
                queue_stats_command(invocation, direction, QueueIndex(index))
            } else {
                queue_config(invocation, direction, QueueIndex(index))
            }
        }
        Edit::InsertRedirect => {
            let Some(blob) = blob else {
                return Err(NetsimError::Invalid.into());
            };
            insert_redirect_command(
                invocation,
                selection.index.map(RedirectIndex),
                blob,
                persist,
            )
        }
        Edit::RemoveRedirects => {
            remove_redirects_command(invocation, selection.index.map(RedirectIndex), persist)
        }
    }
}

/// Settings-file `netsim` line (DoIniLine 0x91f311b8).
pub(crate) fn ini_netsim(invocation: &mut Invocation<'_>) {
    let key_status = invocation.backend.key_status();
    if key_status.intersects(KeyStatus::SKIP_SETTINGS_RELOAD) && invocation.line.has("reload") {
        return;
    }

    let _ = netsim(invocation);
}

/// Queue counts per direction; zero without an instance (0x91f37028).
pub fn queue_counts(backend: &mut dyn AnyBackend) -> (u32, u32) {
    if backend.simulator_exists() {
        (
            backend.queue_count(Direction::Inbound),
            backend.queue_count(Direction::Outbound),
        )
    } else {
        (0, 0)
    }
}

/// Redirect count; zero without an instance.
pub fn redirect_count(backend: &mut dyn AnyBackend) -> u32 {
    if backend.simulator_exists() {
        backend.redirect_count()
    } else {
        0
    }
}

fn queue_counts_command(invocation: &mut Invocation<'_>) -> CommandResult {
    let (inbound, outbound) = queue_counts(invocation.backend);
    invocation.set_text(format_args!("in={inbound} out={outbound}"));

    Ok(Reply::Ok)
}

/// Create the instance when it is missing; returns whether it was created.
fn ensure_simulator(backend: &mut dyn AnyBackend) -> Result<bool, NetsimError> {
    if backend.simulator_exists() {
        return Ok(false);
    }

    backend.create_simulator().map(|()| true)
}

/// Destroy the instance once it has no queues and no redirects.
fn release_if_idle(backend: &mut dyn AnyBackend) -> Result<(), NetsimError> {
    let idle = backend.queue_count(Direction::Inbound) == 0
        && backend.queue_count(Direction::Outbound) == 0
        && backend.redirect_count() == 0;

    if idle {
        backend.destroy_simulator()
    } else {
        Ok(())
    }
}

fn persist_file(state: &State, backend: &mut dyn AnyBackend, persist: bool) {
    if persist {
        write_file(state.file.as_bytes(), backend);
    }
}

/// Insert a queue from an `insertq` blob, creating the instance on demand
/// (0x91f36a18); `persist` rewrites the configuration file.
pub fn insert_queue(
    state: &State,
    backend: &mut dyn AnyBackend,
    direction: Direction,
    position: Option<QueueIndex>,
    blob: &[u8],
    persist: bool,
) -> Result<QueueIndex, NetsimError> {
    let created = ensure_simulator(backend)?;
    let mut slot = Program::EMPTY;
    let inserted = parse_insert_blob(blob, &mut slot).and_then(|(kind, update, program)| {
        backend.insert_queue(direction, position, kind, &update, program)
    });

    match inserted {
        Ok(index) => {
            persist_file(state, backend, persist);

            Ok(index)
        }
        Err(error) => {
            if created {
                let _ = backend.destroy_simulator();
            }

            Err(error)
        }
    }
}

fn insert_queue_command(
    invocation: &mut Invocation<'_>,
    direction: Direction,
    position: Option<QueueIndex>,
    blob: &[u8],
    persist: bool,
) -> CommandResult {
    match insert_queue(
        &invocation.state.network.netsim,
        invocation.backend,
        direction,
        position,
        blob,
        persist,
    ) {
        Ok(QueueIndex(index)) => {
            invocation.set_text(format_args!("index={index}"));

            Ok(Reply::Ok)
        }
        Err(error) => fail(invocation, error),
    }
}

/// Remove the queue at `position`, or every queue, of the selected
/// directions and release an idle instance (0x91f36b50).
pub fn remove_queues(
    state: &State,
    backend: &mut dyn AnyBackend,
    inbound: bool,
    outbound: bool,
    position: Option<QueueIndex>,
    persist: bool,
) -> Result<QueueRemoval, NetsimError> {
    if !backend.simulator_exists() {
        if position.is_some() {
            return Err(NetsimError::NoInstance);
        }

        return Ok(QueueRemoval {
            removed: 0,
            inbound_left: 0,
            outbound_left: 0,
        });
    }

    let mut removed = 0u32;
    for (selected, direction) in [
        (inbound, Direction::Inbound),
        (outbound, Direction::Outbound),
    ] {
        if selected {
            removed = removed.wrapping_add(backend.remove_queues(direction, position)?);
        }
    }

    let inbound_left = backend.queue_count(Direction::Inbound);
    let outbound_left = backend.queue_count(Direction::Outbound);
    release_if_idle(backend)?;
    persist_file(state, backend, persist);

    Ok(QueueRemoval {
        removed,
        inbound_left,
        outbound_left,
    })
}

fn remove_queues_command(
    invocation: &mut Invocation<'_>,
    inbound: bool,
    outbound: bool,
    position: Option<QueueIndex>,
    persist: bool,
) -> CommandResult {
    match remove_queues(
        &invocation.state.network.netsim,
        invocation.backend,
        inbound,
        outbound,
        position,
        persist,
    ) {
        Ok(QueueRemoval {
            removed,
            inbound_left,
            outbound_left,
        }) => {
            invocation.set_text(format_args!(
                "removed={removed} inleft={inbound_left} outleft={outbound_left}"
            ));

            Ok(Reply::Ok)
        }
        Err(error) => fail(invocation, error),
    }
}

/// Apply a `modifyq` blob (no type byte) to a queue (0x91f36cf0).
pub fn modify_queue(
    state: &State,
    backend: &mut dyn AnyBackend,
    direction: Direction,
    index: QueueIndex,
    blob: &[u8],
    persist: bool,
) -> Result<(), NetsimError> {
    if !backend.simulator_exists() {
        return Err(NetsimError::NoInstance);
    }

    let update = parse_queue_blob(blob, false).and_then(|(_, config, program)| {
        if program.is_empty() {
            config.validate()
        } else {
            Err(InvalidConfig)
        }
    })?;
    backend.modify_queue(direction, index, &update)?;
    persist_file(state, backend, persist);

    Ok(())
}

fn modify_queue_command(
    invocation: &mut Invocation<'_>,
    direction: Direction,
    index: QueueIndex,
    blob: &[u8],
    persist: bool,
) -> CommandResult {
    match modify_queue(
        &invocation.state.network.netsim,
        invocation.backend,
        direction,
        index,
        blob,
        persist,
    ) {
        Ok(()) => Ok(Reply::Ok),
        Err(error) => fail(invocation, error),
    }
}

/// Counters of a queue (0x91f36da8).
pub fn queue_stats(
    backend: &mut dyn AnyBackend,
    direction: Direction,
    index: QueueIndex,
) -> Result<QueueStats, NetsimError> {
    if !backend.simulator_exists() {
        return Err(NetsimError::NoInstance);
    }

    backend.queue_stats(direction, index)
}

fn queue_stats_command(
    invocation: &mut Invocation<'_>,
    direction: Direction,
    index: QueueIndex,
) -> CommandResult {
    match queue_stats(invocation.backend, direction, index) {
        Ok(stats) => {
            invocation.set_text(format_args!(
                "totalpkts={} totalbytes=0q{:08x}{:08x} droppkts={} dropbytes=0q{:08x}{:08x}",
                stats.total_packets,
                (stats.total_bytes >> 32) as u32,
                stats.total_bytes as u32,
                stats.dropped_packets,
                (stats.dropped_bytes >> 32) as u32,
                stats.dropped_bytes as u32,
            ));

            Ok(Reply::Ok)
        }
        Err(error) => fail(invocation, error),
    }
}

/// 0x91f36ef0.
fn queue_config(
    invocation: &mut Invocation<'_>,
    direction: Direction,
    index: QueueIndex,
) -> CommandResult {
    let result = if invocation.backend.simulator_exists() {
        invocation.backend.queue(direction, index)
    } else {
        Err(NetsimError::NoInstance)
    };
    let snapshot = match result {
        Ok(snapshot) => snapshot,
        Err(error) => return fail(invocation, error),
    };

    let mut blob = [0u8; CONFIG_CAPACITY];
    let length = match snapshot.serialize(&mut blob) {
        Ok(length) => length,
        Err(error) => return fail(invocation, error),
    };

    invocation.text.clear();
    let _ = invocation.text.write_str("cfg=");
    let _ = invocation.text.push_hex_upper(&blob[..length]);

    Ok(Reply::Ok)
}

/// Insert a redirect from an `insertipv4redir` blob, creating the instance
/// on demand (0x91f370f0).
pub fn insert_redirect(
    state: &State,
    backend: &mut dyn AnyBackend,
    position: Option<RedirectIndex>,
    blob: &[u8],
    persist: bool,
) -> Result<RedirectIndex, NetsimError> {
    let created = ensure_simulator(backend)?;
    let mut slot = Program::EMPTY;
    let inserted = RedirectConfig::parse(blob)
        .map_err(NetsimError::from)
        .and_then(|(redirect, program)| {
            let program = parse_program(program, &mut slot)?;
            redirect.validate()?;
            backend.insert_redirect(position, &redirect, program)
        });

    match inserted {
        Ok(index) => {
            persist_file(state, backend, persist);

            Ok(index)
        }
        Err(error) => {
            if created {
                let _ = backend.destroy_simulator();
            }

            Err(error)
        }
    }
}

fn insert_redirect_command(
    invocation: &mut Invocation<'_>,
    position: Option<RedirectIndex>,
    blob: &[u8],
    persist: bool,
) -> CommandResult {
    match insert_redirect(
        &invocation.state.network.netsim,
        invocation.backend,
        position,
        blob,
        persist,
    ) {
        Ok(RedirectIndex(index)) => {
            invocation.set_text(format_args!("index={index}"));

            Ok(Reply::Ok)
        }
        Err(error) => fail(invocation, error),
    }
}

/// Remove the redirect at `position`, or every redirect, and release an
/// idle instance (0x91f37220).
pub fn remove_redirects(
    state: &State,
    backend: &mut dyn AnyBackend,
    position: Option<RedirectIndex>,
    persist: bool,
) -> Result<RedirectRemoval, NetsimError> {
    if !backend.simulator_exists() {
        if position.is_some() {
            return Err(NetsimError::NoInstance);
        }

        return Ok(RedirectRemoval {
            removed: 0,
            left: 0,
        });
    }

    let removed = backend.remove_redirects(position)?;
    let left = backend.redirect_count();
    release_if_idle(backend)?;
    persist_file(state, backend, persist);

    Ok(RedirectRemoval { removed, left })
}

fn remove_redirects_command(
    invocation: &mut Invocation<'_>,
    position: Option<RedirectIndex>,
    persist: bool,
) -> CommandResult {
    match remove_redirects(
        &invocation.state.network.netsim,
        invocation.backend,
        position,
        persist,
    ) {
        Ok(RedirectRemoval { removed, left }) => {
            invocation.set_text(format_args!("removed={removed} left={left}"));

            Ok(Reply::Ok)
        }
        Err(error) => fail(invocation, error),
    }
}
