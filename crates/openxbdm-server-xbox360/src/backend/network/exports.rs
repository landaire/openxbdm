//! `xbdm.xex` exports of the network domain: capture control, link state,
//! and the network simulator (stock 0x91f384d0..0x91f38848, 0x91f36eb8).
//! Calls that change server state run on the server thread; queries of the
//! simulator instance run on the caller's thread, as in stock.

use core::ffi::CStr;
use core::ffi::c_char;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
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
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::ProcessType;

use crate::backend::Console;
use crate::backend::dispatcher;
use crate::exports::export;
use crate::exports::export_result;
use crate::net::XamNetwork;

/// Position argument that selects every entry or appends.
const ALL: u32 = u32::MAX;

/// Run `service` on the server thread with `request`. The server thread
/// cannot serve a call made on itself or above passive level; those
/// report a generic failure.
fn on_server<T>(request: &mut T, service: dispatcher::ServerService<T>) -> Hresult {
    dispatcher::call_on_server_with(request, service)
        .map_or(ErrorCode::Undefined.hresult(), Hresult)
}

/// A helper failure as the exports report it, through the facility rule
/// of the command status.
fn reported(error: NetsimError) -> u32 {
    Hresult::from(NetworkError::Netsim(error)).0
}

fn direction(inbound: u32) -> Direction {
    if inbound != 0 {
        Direction::Inbound
    } else {
        Direction::Outbound
    }
}

fn position(index: u32) -> Option<u32> {
    (index != ALL).then_some(index)
}

fn write_u32(address: u32, value: u32) {
    if address != 0 {
        // SAFETY: the caller passes a writable dword or null.
        unsafe { core::ptr::write_unaligned(address as usize as *mut u32, value) };
    }
}

fn read_bytes<const N: usize>(address: u32) -> Option<[u8; N]> {
    // SAFETY: the caller passes `N` readable bytes or null.
    (address != 0).then(|| unsafe { core::ptr::read_unaligned(address as usize as *const [u8; N]) })
}

/// Caller queue settings (0x91f8bc38): the size dword is checked before the
/// rest of the structure is read.
fn read_settings(address: u32) -> Result<netsim::QueueConfig, NetsimError> {
    if let Some(size) = read_bytes::<4>(address)
        && !api::declares_size(&size, api::SETTINGS_SIZE)
    {
        return Err(NetsimError::Invalid);
    }
    api::decode_settings(read_bytes::<{ api::SETTINGS_SIZE }>(address).as_ref())
        .map_err(NetsimError::from)
}

fn write_bytes<const N: usize>(address: u32, bytes: &[u8; N]) {
    // SAFETY: the caller passes `N` writable bytes; null was checked.
    unsafe { core::ptr::write_unaligned(address as usize as *mut [u8; N], *bytes) };
}

fn c_string<'a>(address: u32) -> Option<&'a [u8]> {
    // SAFETY: the caller passes a terminated string or null.
    (address != 0).then(|| unsafe { CStr::from_ptr(address as usize as *const c_char) }.to_bytes())
}

struct CaptureStart<'a> {
    name: &'a [u8],
    data_limit: u32,
    buffer: u32,
    flags: CaptureFlags,
}

/// Start a capture (0x91f384d0 calling 0x91f34f80 without reply text).
extern "C" fn capture_start(name: u32, data_limit: u32, buffer: u32, flags: u32) -> u32 {
    let flags = CaptureFlags(flags);
    if flags.contains(CaptureFlags::PERSISTENT)
        && xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE
    {
        return Hresult::PERSISTENT_FROM_TITLE.0;
    }
    let mut start = CaptureStart {
        name: c_string(name).unwrap_or_default(),
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
    .0
}
export!(163, capture_start);

/// Stop the capture (0x91f38530 tail-calling 0x91f351e0).
extern "C" fn capture_stop() -> u32 {
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
    .0
}
export!(164, capture_stop);

/// Force the link down or restore it (0x91f38540: the `linkstate` helper
/// with `disconnect` or `restore` and no reply text).
extern "C" fn set_link_disconnected(disconnect: u32) -> u32 {
    let flags = if disconnect != 0 {
        LinkFlags::DISCONNECT
    } else {
        LinkFlags::RESTORE
    };
    // The helper reads the state for its reply before changing it.
    let _ = super::link_status();
    match super::set_link_flags(flags) {
        Ok(()) => Hresult::OK.0,
        Err(error) => Hresult::from(link_error(error)).0,
    }
}
export!(215, set_link_disconnected);

/// A settings blob the server thread applies to a queue.
struct QueueRequest {
    direction: Direction,
    index: Option<u32>,
    blob: [u8; CONFIG_CAPACITY],
    length: usize,
}

/// Queues of the selected directions to remove, and the count removed.
struct RemoveQueues {
    inbound: bool,
    outbound: bool,
    index: Option<u32>,
    /// Count the helper reports, 0 after a failure; `None` when it did not
    /// run.
    removed: Option<u32>,
}

fn remove_queues(request: &mut RemoveQueues) -> Hresult {
    on_server(
        request,
        |server: &mut Server,
         console: &mut Console,
         _: &mut XamNetwork,
         request: &mut RemoveQueues| {
            let state = &server.state.network.netsim;
            let position = request.index.map(QueueIndex);
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
                    reported(error)
                }
            }
        },
    )
}

/// Remove one queue of a direction (0x91f38650).
extern "C" fn remove_queue(inbound: u32, index: u32) -> u32 {
    let mut request = RemoveQueues {
        inbound: inbound != 0,
        outbound: inbound == 0,
        index: position(index),
        removed: None,
    };
    remove_queues(&mut request).0
}
export!(217, remove_queue);

/// Remove every queue of the selected directions (0x91f38670); `removed`
/// receives the count, 0 after a failure.
extern "C" fn remove_all_queues(inbound: u32, outbound: u32, removed: u32) -> u32 {
    let mut request = RemoveQueues {
        inbound: inbound != 0,
        outbound: outbound != 0,
        index: None,
        removed: None,
    };
    let result = remove_queues(&mut request);
    if let Some(count) = request.removed {
        write_u32(removed, count);
    }
    result.0
}
export!(218, remove_all_queues);

/// Apply caller settings to a queue (0x91f38688): validate, build a blob
/// without a type, then the `modifyq` helper.
extern "C" fn modify_queue(inbound: u32, index: u32, settings: u32) -> u32 {
    let config = match read_settings(settings) {
        Ok(config) => config,
        Err(error) => return Hresult::from(error).0,
    };
    let mut request = QueueRequest {
        direction: direction(inbound),
        index: Some(index),
        blob: [0; CONFIG_CAPACITY],
        length: 0,
    };
    request.length = match api::queue_blob(0, &config, None, &mut request.blob) {
        Ok(length) => length,
        Err(error) => return Hresult::from(error).0,
    };
    on_server(
        &mut request,
        |server: &mut Server,
         console: &mut Console,
         _: &mut XamNetwork,
         request: &mut QueueRequest| {
            let blob = &request.blob[..request.length];
            let index = QueueIndex(request.index.unwrap_or(ALL));
            match netsim::modify_queue(
                &server.state.network.netsim,
                console,
                request.direction,
                index,
                blob,
                true,
            ) {
                Ok(()) => Hresult::OK.0,
                Err(error) => reported(error),
            }
        },
    )
    .0
}
export!(219, modify_queue);

/// An insert blob the server thread applies to `target` (a queue
/// direction, or nothing for a redirect), and the index it reports.
struct InsertRequest<T> {
    target: T,
    index: Option<u32>,
    blob: [u8; CONFIG_CAPACITY],
    length: usize,
    /// The index the helper stores, -1 after a failure; `None` when it did
    /// not run.
    inserted: Option<u32>,
}

impl<T> InsertRequest<T> {
    fn new(target: T, index: u32) -> Self {
        Self {
            target,
            index: position(index),
            blob: [0; CONFIG_CAPACITY],
            length: 0,
            inserted: None,
        }
    }

    /// Build the blob around the program compiled from `text` (0x91f8bdd0);
    /// a null text or a constant true program adds none.
    fn build(
        &mut self,
        text: u32,
        build: impl FnOnce(Option<Source<'_>>, &mut [u8; CONFIG_CAPACITY]) -> Result<usize, NetsimError>,
    ) -> Result<(), NetsimError> {
        let compiled = match c_string(text) {
            Some(text) => classifier::compile_text(text)?,
            None => None,
        };
        self.length = build(compiled.as_ref().map(Source::Compiled), &mut self.blob)?;
        Ok(())
    }

    /// Record the helper's outcome: the index or -1, and the mapped result.
    fn record(&mut self, result: Result<u32, NetsimError>) -> u32 {
        self.inserted = Some(*result.as_ref().unwrap_or(&ALL));
        result.map_or_else(reported, |_| Hresult::OK.0)
    }

    fn finish(self, result: Hresult, inserted: u32) -> u32 {
        if let Some(index) = self.inserted {
            write_u32(inserted, index);
        }
        result.0
    }
}

/// Insert a queue from caller settings and classifier text (0x91f38570):
/// validate, compile, build a blob with the type byte when `kind` is
/// nonzero, then the `insertq` helper.
extern "C" fn insert_queue(
    inbound: u32,
    index: u32,
    kind: u32,
    settings: u32,
    text: u32,
    inserted_index: u32,
) -> u32 {
    let config = match read_settings(settings) {
        Ok(config) => config,
        Err(error) => return Hresult::from(error).0,
    };
    let mut request = InsertRequest::new(direction(inbound), index);
    if let Err(error) = request.build(text, |program, blob| {
        api::queue_blob(kind, &config, program, blob)
    }) {
        return Hresult::from(error).0;
    }
    let result = on_server(
        &mut request,
        |server: &mut Server,
         console: &mut Console,
         _: &mut XamNetwork,
         request: &mut InsertRequest<Direction>| {
            let blob = &request.blob[..request.length];
            let position = request.index.map(QueueIndex);
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
    request.finish(result, inserted_index)
}
export!(216, insert_queue);

/// Insert a redirect from caller endpoints and classifier text
/// (0x91f38738): validate (0x91f8bf98), compile, build the blob, then the
/// `insertipv4redir` helper.
#[allow(clippy::too_many_arguments)]
extern "C" fn insert_redirect(
    index: u32,
    match_address: u32,
    match_port: u32,
    target_address: u32,
    target_port: u32,
    text: u32,
    sessions: u32,
    inserted_index: u32,
) -> u32 {
    // Stock reads a null address as 0.0.0.0.
    let address = |pointer| read_bytes::<4>(pointer).unwrap_or([0; 4]);
    // The session count is checked before it is narrowed to 16 bits.
    let Ok(sessions) = u16::try_from(sessions) else {
        return Hresult::from(NetsimError::Invalid).0;
    };
    let config = RedirectConfig {
        match_address: address(match_address),
        match_port: match_port as u16,
        target_address: address(target_address),
        target_port: target_port as u16,
        sessions,
    };
    if let Err(error) = config.validate() {
        return Hresult::from(NetsimError::from(error)).0;
    }
    let mut request = InsertRequest::new((), index);
    if let Err(error) = request.build(text, |program, blob| {
        api::redirect_blob(&config, program, blob)
    }) {
        return Hresult::from(error).0;
    }
    let result = on_server(
        &mut request,
        |server: &mut Server,
         console: &mut Console,
         _: &mut XamNetwork,
         request: &mut InsertRequest<()>| {
            let blob = &request.blob[..request.length];
            let position = request.index.map(RedirectIndex);
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
    request.finish(result, inserted_index)
}
export!(224, insert_redirect);

/// Counters of a queue (0x91f38718 calling 0x91f36da8): the structure must
/// declare 0x20 bytes.
extern "C" fn queue_stats(inbound: u32, index: u32, stats: u32) -> u32 {
    let result = if super::netsim::simulator_exists() {
        match read_bytes::<4>(stats) {
            Some(size) if !api::declares_size(&size, api::STATS_SIZE) => Err(NetsimError::Invalid),
            _ => super::netsim::queue_stats(direction(inbound), QueueIndex(index)),
        }
    } else {
        Err(NetsimError::NoInstance)
    };
    match result {
        Ok(counters) => {
            if stats != 0 {
                write_bytes(stats, &api::encode_stats(&counters));
            }
            Hresult::OK.0
        }
        Err(error) => reported(error),
    }
}
export!(221, queue_stats);

/// Type and stored settings of a queue (0x91f36eb8 calling 0x91f8d620).
extern "C" fn queue_settings(inbound: u32, index: u32, kind: u32, settings: u32) -> u32 {
    if !super::netsim::simulator_exists() {
        return Hresult::from(NetsimError::NoInstance).0;
    }
    if let Some(size) = read_bytes::<4>(settings)
        && !api::declares_size(&size, api::SETTINGS_SIZE)
    {
        return Hresult::from(NetsimError::Invalid).0;
    }
    match super::netsim::queue(direction(inbound), QueueIndex(index)) {
        Ok(snapshot) => {
            write_u32(kind, snapshot.kind as u32);
            if settings != 0 {
                write_bytes(settings, &api::encode_settings(&snapshot.config));
            }
            Hresult::OK.0
        }
        Err(error) => Hresult::from(error).0,
    }
}
export!(222, queue_settings);

/// Queue counts (0x91f38728 calling 0x91f37028).
extern "C" fn queue_counts(inbound: u32, outbound: u32) -> u32 {
    let (inbound_count, outbound_count) = super::netsim::queue_counts();
    write_u32(inbound, inbound_count);
    write_u32(outbound, outbound_count);
    Hresult::OK.0
}
export!(223, queue_counts);

struct RemoveRedirects {
    index: Option<u32>,
    removed: Option<u32>,
}

/// Remove one or every redirect (0x91f38838 calling 0x91f37220);
/// `removed` receives the count, 0 after a failure.
extern "C" fn remove_redirects(index: u32, removed: u32) -> u32 {
    let mut request = RemoveRedirects {
        index: position(index),
        removed: None,
    };
    let result = on_server(
        &mut request,
        |server: &mut Server,
         console: &mut Console,
         _: &mut XamNetwork,
         request: &mut RemoveRedirects| {
            let position = request.index.map(RedirectIndex);
            match netsim::remove_redirects(&server.state.network.netsim, console, position, true) {
                Ok(removal) => {
                    request.removed = Some(removal.removed);
                    Hresult::OK.0
                }
                Err(error) => {
                    request.removed = Some(0);
                    reported(error)
                }
            }
        },
    );
    if let Some(count) = request.removed {
        write_u32(removed, count);
    }
    result.0
}
export!(225, remove_redirects);

/// Redirect count (0x91f38848); always succeeds.
extern "C" fn redirect_count(count: u32) -> u32 {
    write_u32(count, super::netsim::redirect_count());
    Hresult::OK.0
}
export!(226, redirect_count);
