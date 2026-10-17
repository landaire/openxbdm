//! `xbdm.xex` exports of the network domain: capture control, link state,
//! and the network simulator (stock 0x91f384d0..0x91f38848, 0x91f36eb8).
//! Calls that change server state run on the server thread; queries of the
//! simulator instance run on the caller's thread, as in stock.

use core::ffi::c_char;
use core::mem::MaybeUninit;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::Server;
use openxbdm_server::commands::network::LinkFlags;
use openxbdm_server::commands::network::NetworkError;
use openxbdm_server::commands::network::link_error;
use openxbdm_server::commands::network::netcap;
use openxbdm_server::commands::network::netcap::CaptureFlags;
use openxbdm_server::commands::network::netsim;
use openxbdm_server::commands::network::netsim::CONFIG_CAPACITY;
use openxbdm_server::commands::network::netsim::Direction;
use openxbdm_server::commands::network::netsim::NetsimError;
use openxbdm_server::commands::network::netsim::QueueIndex;
use openxbdm_server::commands::network::netsim::RedirectConfig;
use openxbdm_server::commands::network::netsim::RedirectIndex;
use openxbdm_server::commands::network::netsim::Source;
use openxbdm_server::commands::network::netsim::api;
use openxbdm_server::commands::network::netsim::classifier;
use xbox360::status::Hresult;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::ProcessType;

use crate::backend::Console;
use crate::backend::dispatcher;
use crate::exports::export;
use crate::exports::export_result;
use crate::kernel;
use crate::net::XamNetwork;

/// A caller dword, which stock accesses without an alignment requirement.
type Dword = [u8; 4];

/// A caller output dword, which may be uninitialized.
type DwordOut = MaybeUninit<Dword>;

/// Queue settings structure of the caller.
type Settings = [u8; api::SETTINGS_SIZE];

/// Queue counter structure of the caller.
type Stats = [u8; api::STATS_SIZE];

/// Position argument of the queue and redirect exports.
#[derive(Clone, Copy)]
enum Position {
    /// Every entry, or the end of the list for an insert (stock -1).
    All,
    Index(u32),
}

impl Position {
    const fn from_raw(raw: u32) -> Self {
        if raw == u32::MAX {
            Self::All
        } else {
            Self::Index(raw)
        }
    }

    const fn index(self) -> Option<u32> {
        match self {
            Self::All => None,
            Self::Index(index) => Some(index),
        }
    }
}

struct CaptureStart<'a> {
    name: &'a [u8],
    data_limit: u32,
    buffer: u32,
    flags: CaptureFlags,
}

/// A settings blob the server thread applies to a queue.
struct QueueRequest {
    direction: Direction,
    index: QueueIndex,
    blob: [u8; CONFIG_CAPACITY],
    length: usize,
}

/// Queues of the selected directions to remove, and the count removed.
struct RemoveQueues {
    inbound: bool,
    outbound: bool,
    position: Position,
    /// Count the helper reports, 0 after a failure; `None` when it did not
    /// run.
    removed: Option<u32>,
}

/// An insert blob the server thread applies to `target` (a queue
/// direction, or nothing for a redirect), and the index it reports.
struct InsertRequest<T> {
    target: T,
    position: Position,
    blob: [u8; CONFIG_CAPACITY],
    length: usize,
    /// What the helper stored; `None` when it did not run.
    inserted: Option<InsertOutcome>,
}

impl<T> InsertRequest<T> {
    fn new(target: T, index: u32) -> Self {
        Self {
            target,
            position: Position::from_raw(index),
            blob: [0; CONFIG_CAPACITY],
            length: 0,
            inserted: None,
        }
    }

    /// Build the blob around the program compiled from `text` (0x91f8bdd0);
    /// a null text or a constant true program adds none.
    ///
    /// # Safety
    ///
    /// `text` is null or a NUL-terminated string.
    unsafe fn build(
        &mut self,
        text: *const c_char,
        build: impl FnOnce(Option<Source<'_>>, &mut [u8; CONFIG_CAPACITY]) -> Result<usize, NetsimError>,
    ) -> Result<(), NetsimError> {
        // SAFETY: guaranteed by the caller.
        let compiled = match unsafe { kernel::c_string(text.expose_provenance() as u32) } {
            Some(text) => classifier::compile_text(text)?,
            None => None,
        };

        self.length = build(compiled.as_ref().map(Source::Compiled), &mut self.blob)?;

        Ok(())
    }

    /// Record the helper's outcome and return the mapped result word.
    fn record(&mut self, result: Result<u32, NetsimError>) -> u32 {
        self.inserted = Some(match result {
            Ok(index) => InsertOutcome::Inserted(index),
            Err(_) => InsertOutcome::Failed,
        });

        result.map_or_else(|error| reported(error).0, |_| Hresult::OK.0)
    }

    /// Store the outcome for the caller.
    fn finish(self, result: Hresult, output: Option<&mut DwordOut>) -> Hresult {
        if let Some(outcome) = self.inserted {
            let index = match outcome {
                InsertOutcome::Inserted(index) => index,
                InsertOutcome::Failed => u32::MAX,
            };
            store(output, index);
        }

        result
    }
}

/// Result of an insert helper, for the caller's index output.
#[derive(Clone, Copy)]
enum InsertOutcome {
    Inserted(u32),
    /// Stored as -1.
    Failed,
}

struct RemoveRedirects {
    position: Position,
    removed: Option<u32>,
}

/// Run `service` on the server thread with `request`. The server thread
/// cannot serve a call made on itself or above passive level; those
/// report a generic failure.
fn on_server<T>(request: &mut T, service: dispatcher::ServerService<T>) -> Hresult {
    dispatcher::call_on_server_with(request, service)
        .map_or(ErrorCode::Undefined.hresult(), Hresult)
}

/// A helper failure as the exports report it, through the facility rule
/// of the command status.
fn reported(error: NetsimError) -> Hresult {
    Hresult::from(NetworkError::Netsim(error))
}

fn direction(inbound: u32) -> Direction {
    if inbound != 0 {
        Direction::Inbound
    } else {
        Direction::Outbound
    }
}

fn store(output: Option<&mut DwordOut>, value: u32) {
    if let Some(output) = output {
        output.write(value.to_be_bytes());
    }
}

/// Caller queue settings (0x91f8bc38): the size dword is checked before the
/// rest of the structure is read.
///
/// # Safety
///
/// `settings` is null or points at a readable size dword, followed by the
/// rest of the structure when the dword declares its full size.
unsafe fn read_settings(settings: *const Settings) -> Result<netsim::QueueConfig, NetsimError> {
    // SAFETY: the size dword is readable per the contract.
    if let Some(size) = unsafe { settings.cast::<Dword>().as_ref() }
        && !api::declares_size(size, api::SETTINGS_SIZE)
    {
        return Err(NetsimError::Invalid);
    }

    // SAFETY: the structure declares its full size, so it is readable.
    api::decode_settings(unsafe { settings.as_ref() }).map_err(NetsimError::from)
}

fn remove_queues(request: &mut RemoveQueues) -> Hresult {
    on_server(
        request,
        |server: &mut Server,
         console: &mut Console,
         _: &mut XamNetwork,
         request: &mut RemoveQueues| {
            let state = &server.state.network.netsim;
            let position = request.position.index().map(QueueIndex);
            match netsim::remove_queues(
                state,
                console,
                request.inbound,
                request.outbound,
                position,
                true,
            ) {
                Ok(removal) => {
                    request.removed = Some(removal.removed);
                    Hresult::OK.0
                }
                Err(error) => {
                    request.removed = Some(0);
                    reported(error).0
                }
            }
        },
    )
}

/// Start a capture (0x91f384d0 calling 0x91f34f80 without reply text).
extern "C" fn capture_start(
    name: *const c_char,
    data_limit: u32,
    buffer: u32,
    flags: u32,
) -> Hresult {
    let flags = CaptureFlags::from_bits_retain(flags);

    if flags.contains(CaptureFlags::PERSISTENT)
        && xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE
    {
        return Hresult::PERSISTENT_FROM_TITLE;
    }

    let mut start = CaptureStart {
        // SAFETY: the caller passes a capture file name or null.
        name: unsafe { kernel::c_string(name.expose_provenance() as u32) }.unwrap_or_default(),
        data_limit,
        buffer,
        flags,
    };

    on_server(
        &mut start,
        |server: &mut Server,
         console: &mut Console,
         _: &mut XamNetwork,
         start: &mut CaptureStart<'_>| {
            let result = netcap::start_capture(
                &mut server.state,
                console,
                start.name,
                start.data_limit,
                start.buffer,
                start.flags,
            );
            export_result(result).0
        },
    )
}
export!(163, capture_start);

/// Stop the capture (0x91f38530 tail-calling 0x91f351e0).
extern "C" fn capture_stop() -> Hresult {
    on_server(
        &mut (),
        |server: &mut Server, console: &mut Console, _: &mut XamNetwork, _: &mut ()| {
            export_result(netcap::stop_capture(
                &mut server.state.network.netcap,
                console,
            ))
            .0
        },
    )
}
export!(164, capture_stop);

/// Force the link down or restore it (0x91f38540: the `linkstate` helper
/// with `disconnect` or `restore` and no reply text).
extern "C" fn set_link_disconnected(disconnect: u32) -> Hresult {
    let flags = if disconnect != 0 {
        LinkFlags::DISCONNECT
    } else {
        LinkFlags::RESTORE
    };

    // The helper reads the state for its reply before changing it.
    let _ = super::link_status();

    match super::set_link_flags(flags) {
        Ok(()) => Hresult::OK,
        Err(error) => Hresult::from(link_error(error)),
    }
}
export!(215, set_link_disconnected);

/// Remove one queue of a direction (0x91f38650).
extern "C" fn remove_queue(inbound: u32, index: u32) -> Hresult {
    let mut request = RemoveQueues {
        inbound: inbound != 0,
        outbound: inbound == 0,
        position: Position::from_raw(index),
        removed: None,
    };

    remove_queues(&mut request)
}
export!(217, remove_queue);

/// Remove every queue of the selected directions (0x91f38670); `removed`
/// receives the count, 0 after a failure.
extern "C" fn remove_all_queues(inbound: u32, outbound: u32, removed: *mut DwordOut) -> Hresult {
    let mut request = RemoveQueues {
        inbound: inbound != 0,
        outbound: outbound != 0,
        position: Position::All,
        removed: None,
    };

    let result = remove_queues(&mut request);

    if let Some(count) = request.removed {
        // SAFETY: the caller passes a writable dword or null.
        store(unsafe { removed.as_mut() }, count);
    }

    result
}
export!(218, remove_all_queues);

/// Apply caller settings to a queue (0x91f38688): validate, build a blob
/// without a type, then the `modifyq` helper.
extern "C" fn modify_queue(inbound: u32, index: u32, settings: *const Settings) -> Hresult {
    // SAFETY: the caller passes queue settings that declare their size, or
    // null.
    let config = match unsafe { read_settings(settings) } {
        Ok(config) => config,
        Err(error) => return Hresult::from(error),
    };

    let mut request = QueueRequest {
        direction: direction(inbound),
        index: QueueIndex(index),
        blob: [0; CONFIG_CAPACITY],
        length: 0,
    };

    request.length = match api::queue_blob(0, &config, None, &mut request.blob) {
        Ok(length) => length,
        Err(error) => return Hresult::from(error),
    };

    on_server(
        &mut request,
        |server: &mut Server,
         console: &mut Console,
         _: &mut XamNetwork,
         request: &mut QueueRequest| {
            let blob = &request.blob[..request.length];
            match netsim::modify_queue(
                &server.state.network.netsim,
                console,
                request.direction,
                request.index,
                blob,
                true,
            ) {
                Ok(()) => Hresult::OK.0,
                Err(error) => reported(error).0,
            }
        },
    )
}
export!(219, modify_queue);

/// Insert a queue from caller settings and classifier text (0x91f38570):
/// validate, compile, build a blob with the type byte when `kind` is
/// nonzero, then the `insertq` helper.
extern "C" fn insert_queue(
    inbound: u32,
    index: u32,
    kind: u32,
    settings: *const Settings,
    text: *const c_char,
    inserted_index: *mut DwordOut,
) -> Hresult {
    // SAFETY: the caller passes queue settings that declare their size, or
    // null.
    let config = match unsafe { read_settings(settings) } {
        Ok(config) => config,
        Err(error) => return Hresult::from(error),
    };

    let mut request = InsertRequest::new(direction(inbound), index);

    // SAFETY: the caller passes classifier text or null.
    if let Err(error) = unsafe {
        request.build(text, |program, blob| {
            api::queue_blob(kind, &config, program, blob)
        })
    } {
        return Hresult::from(error);
    }

    let result = on_server(
        &mut request,
        |server: &mut Server,
         console: &mut Console,
         _: &mut XamNetwork,
         request: &mut InsertRequest<Direction>| {
            let blob = &request.blob[..request.length];
            let position = request.position.index().map(QueueIndex);
            let result = netsim::insert_queue(
                &server.state.network.netsim,
                console,
                request.target,
                position,
                blob,
                true,
            );
            request.record(result.map(|QueueIndex(index)| index))
        },
    );

    // SAFETY: the caller passes a writable dword or null.
    request.finish(result, unsafe { inserted_index.as_mut() })
}
export!(216, insert_queue);

/// Insert a redirect from caller endpoints and classifier text
/// (0x91f38738): validate (0x91f8bf98), compile, build the blob, then the
/// `insertipv4redir` helper.
#[allow(clippy::too_many_arguments)]
extern "C" fn insert_redirect(
    index: u32,
    match_address: *const Dword,
    match_port: u32,
    target_address: *const Dword,
    target_port: u32,
    text: *const c_char,
    sessions: u32,
    inserted_index: *mut DwordOut,
) -> Hresult {
    // Stock reads a null address as 0.0.0.0.
    // SAFETY: the caller passes readable addresses or null.
    let address = |pointer: *const Dword| unsafe { pointer.as_ref() }.copied().unwrap_or([0; 4]);

    // The session count is checked before it is narrowed to 16 bits.
    let Ok(sessions) = u16::try_from(sessions) else {
        return Hresult::from(NetsimError::Invalid);
    };

    let config = RedirectConfig {
        match_address: address(match_address),
        match_port: match_port as u16,
        target_address: address(target_address),
        target_port: target_port as u16,
        sessions,
    };

    if let Err(error) = config.validate() {
        return Hresult::from(NetsimError::from(error));
    }

    let mut request = InsertRequest::new((), index);

    // SAFETY: the caller passes classifier text or null.
    if let Err(error) = unsafe {
        request.build(text, |program, blob| {
            api::redirect_blob(&config, program, blob)
        })
    } {
        return Hresult::from(error);
    }

    let result = on_server(
        &mut request,
        |server: &mut Server,
         console: &mut Console,
         _: &mut XamNetwork,
         request: &mut InsertRequest<()>| {
            let blob = &request.blob[..request.length];
            let position = request.position.index().map(RedirectIndex);
            let result = netsim::insert_redirect(
                &server.state.network.netsim,
                console,
                position,
                blob,
                true,
            );
            request.record(result.map(|RedirectIndex(index)| index))
        },
    );

    // SAFETY: the caller passes a writable dword or null.
    request.finish(result, unsafe { inserted_index.as_mut() })
}
export!(224, insert_redirect);

/// Counters of a queue (0x91f38718 calling 0x91f36da8): the structure must
/// declare 0x20 bytes.
extern "C" fn queue_stats(inbound: u32, index: u32, stats: *mut MaybeUninit<Stats>) -> Hresult {
    let result = if super::netsim::simulator_exists() {
        // SAFETY: the caller passes a counter structure, whose size dword
        // is readable, or null.
        match unsafe { stats.cast::<Dword>().as_ref() } {
            Some(size) if !api::declares_size(size, api::STATS_SIZE) => Err(NetsimError::Invalid),
            // SAFETY: stock runs the query on the caller thread without
            // excluding `destroy_simulator` (the race `netsim::instance`
            // documents).
            _ => unsafe { super::netsim::queue_stats(direction(inbound), QueueIndex(index)) },
        }
    } else {
        Err(NetsimError::NoInstance)
    };

    match result {
        Ok(counters) => {
            // SAFETY: the structure declares its full size, so it is
            // writable.
            if let Some(stats) = unsafe { stats.as_mut() } {
                stats.write(api::encode_stats(&counters));
            }
            Hresult::OK
        }
        Err(error) => reported(error),
    }
}
export!(221, queue_stats);

/// Type and stored settings of a queue (0x91f36eb8 calling 0x91f8d620).
extern "C" fn queue_settings(
    inbound: u32,
    index: u32,
    kind: *mut DwordOut,
    settings: *mut MaybeUninit<Settings>,
) -> Hresult {
    if !super::netsim::simulator_exists() {
        return Hresult::from(NetsimError::NoInstance);
    }

    // SAFETY: the caller passes a settings structure, whose size dword is
    // readable, or null.
    if let Some(size) = unsafe { settings.cast::<Dword>().as_ref() }
        && !api::declares_size(size, api::SETTINGS_SIZE)
    {
        return Hresult::from(NetsimError::Invalid);
    }

    // SAFETY: as in `queue_stats`.
    match unsafe { super::netsim::queue(direction(inbound), QueueIndex(index)) } {
        Ok(snapshot) => {
            // SAFETY: the caller passes a writable dword or null.
            store(unsafe { kind.as_mut() }, snapshot.kind as u32);
            // SAFETY: the structure declares its full size, so it is
            // writable.
            if let Some(settings) = unsafe { settings.as_mut() } {
                settings.write(api::encode_settings(&snapshot.config));
            }
            Hresult::OK
        }
        Err(error) => Hresult::from(error),
    }
}
export!(222, queue_settings);

/// Queue counts (0x91f38728 calling 0x91f37028).
extern "C" fn queue_counts(inbound: *mut DwordOut, outbound: *mut DwordOut) -> Hresult {
    // SAFETY: as in `queue_stats`.
    let (inbound_count, outbound_count) = unsafe { super::netsim::queue_counts() };

    // SAFETY: the caller passes writable dwords or null.
    unsafe {
        store(inbound.as_mut(), inbound_count);
        store(outbound.as_mut(), outbound_count);
    }

    Hresult::OK
}
export!(223, queue_counts);

/// Remove one or every redirect (0x91f38838 calling 0x91f37220);
/// `removed` receives the count, 0 after a failure.
extern "C" fn remove_redirects(index: u32, removed: *mut DwordOut) -> Hresult {
    let mut request = RemoveRedirects {
        position: Position::from_raw(index),
        removed: None,
    };

    let result = on_server(
        &mut request,
        |server: &mut Server,
         console: &mut Console,
         _: &mut XamNetwork,
         request: &mut RemoveRedirects| {
            let position = request.position.index().map(RedirectIndex);
            match netsim::remove_redirects(&server.state.network.netsim, console, position, true) {
                Ok(removal) => {
                    request.removed = Some(removal.removed);
                    Hresult::OK.0
                }
                Err(error) => {
                    request.removed = Some(0);
                    reported(error).0
                }
            }
        },
    );

    if let Some(count) = request.removed {
        // SAFETY: the caller passes a writable dword or null.
        store(unsafe { removed.as_mut() }, count);
    }

    result
}
export!(225, remove_redirects);

/// Redirect count (0x91f38848); always succeeds.
extern "C" fn redirect_count(count: *mut DwordOut) -> Hresult {
    // SAFETY: as in `queue_stats`; the caller passes a writable dword or
    // null.
    store(unsafe { count.as_mut() }, unsafe {
        super::netsim::redirect_count()
    });

    Hresult::OK
}
export!(226, redirect_count);
