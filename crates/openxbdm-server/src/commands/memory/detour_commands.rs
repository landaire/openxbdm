//! `detour` command handlers over the detour engine.
// `detour entry setinfo` configures hooks from client-supplied addresses.
#![allow(unsafe_code)]

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;

use super::Continuation;
use super::detour;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

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
                // SAFETY: the settings come from the debugger client's
                // `detour entry setinfo`, which stock trusts to describe the
                // hooked function (docs/re-notes/nuances.md, Memory).
                DetourReply::of(unsafe { engine.configure(platform, id, settings) })
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

/// `detour log|entry|start|stop|getstate ...`: the function detour engine.
/// Selectors are flags tested in that order.
pub(super) fn detour_command(invocation: &mut Invocation<'_>) -> CommandResult {
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

pub(super) fn detour_log_record(
    remaining: &mut u32,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
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

/// A module unloaded: release the detour entries hooking it (0x91f2c608).
pub(crate) fn module_unloaded(backend: &mut dyn crate::backend::Backend, base: u32, size: u32) {
    run_detour(backend, DetourOperation::ReleaseRange { base, size });
}

/// Run `operation` through [`super::Backend::detour`]. Every operation
/// shares one closure, so one closure body and vtable serve them all.
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
                    flags: detour::HookFlags::from_bits_retain(required("flags")?),
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

    let result = run_detour(invocation.backend, DetourOperation::BeginStart)
        .command_result()
        .and_then(|reply| start_log(invocation, name).map(|()| reply));

    hresult_reply(invocation, result)
}

/// Record `name` and create the log workers for a starting engine; on
/// failure return the engine to stopped.
fn start_log(invocation: &mut Invocation<'_>, name: DetourLogName) -> Result<(), CommandError> {
    let state = &mut *invocation.state;
    state.memory.detour_log = name;
    let path = state
        .filesystem
        .drives
        .translate(invocation.backend, state.memory.detour_log.as_bytes());
    let Err(error) = invocation
        .backend
        .start_detour_log(path.as_ref().map(|path| path.as_bytes()))
    else {
        return Ok(());
    };

    run_detour(invocation.backend, DetourOperation::CancelStart);

    Err(CommandError::from_kernel(
        error,
        ErrorCode::FileCannotBeCreated.into(),
    ))
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
