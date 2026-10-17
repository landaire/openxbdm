//! HTTP registration with a lab server (`httpreg`).

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Win32Error;

use super::MONITOR_VERSION;
use super::NETWORK_ADDRESS_SIZE;
use super::Published;
use super::SettingsLine;
use super::error::RegistrationError;
use super::system_info::Version;
use super::trace::MessageText;
use super::trace::print;
use crate::backend::Backend as AnyBackend;
use crate::commands::system::SettingsFile;
use crate::commands::system::end_line;
use crate::commands::system::write_bytes;
use crate::commands::system::write_line;
use crate::invocation::Invocation;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;

/// Characters kept of the server and object of `httpreg`.
const REGISTRATION_TEXT_CAPACITY: usize = 0xff;

/// Bytes kept of a registration response body.
pub const REGISTRATION_RESPONSE_CAPACITY: usize = 0x400;

/// Bytes of the registration request path and query.
const REGISTRATION_PATH_CAPACITY: usize = 0x3ff;

/// User agent of the registration request.
pub const REGISTRATION_USER_AGENT: &str = "Xbox Debugger/2.0.21256.0";

/// Address check period of the registration task.
const REGISTRATION_PERIOD_MS: u32 = 30_000;

/// Task period while a request or the network address is pending.
const REGISTRATION_RETRY_MS: u32 = 1;

/// System software version from which the title need not be running.
const REGISTRATION_ANY_STATE_VERSION: u32 = 0x2016_5400;

/// State of the HTTP registration with a lab server (stock 0x91f9f638).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegistrationState {
    /// Waiting to register (stock state 0).
    #[default]
    Pending,
    /// A request is in progress (stock states 1 to 7).
    InProgress,
    /// `httpreg clear`, or no object to register (stock state 8).
    Cleared,
    /// The server accepted the registration (stock state 9).
    Registered,
    /// The last `httpreg` was rejected or the request failed (stock
    /// state 10).
    Failed,
    /// The server answered with a status other than 200 (stock state 11).
    Rejected,
    /// The response body exceeded 0x400 bytes (stock state 12).
    ResponseTooLarge,
}

/// Address check of the registration task: the debug address registered
/// and the tick of the last check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationCheck {
    pub address: [u8; NETWORK_ADDRESS_SIZE],
    pub tick: u32,
}

impl RegistrationCheck {
    pub const EMPTY: Self = Self {
        address: [0; NETWORK_ADDRESS_SIZE],
        tick: 0,
    };
}

/// Lab server registration set by `httpreg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpRegistration {
    pub state: RegistrationState,
    server: [u8; REGISTRATION_TEXT_CAPACITY],
    server_len: u8,
    object: [u8; REGISTRATION_TEXT_CAPACITY],
    object_len: u8,
    pub port: u16,
    /// Random identifier sent with the request; 0 when none was sent.
    pub transaction: u64,
    /// Length of the last accepted response, which the backend holds.
    response_len: u16,
}

impl HttpRegistration {
    pub const EMPTY: Self = Self {
        state: RegistrationState::Pending,
        server: [0; REGISTRATION_TEXT_CAPACITY],
        server_len: 0,
        object: [0; REGISTRATION_TEXT_CAPACITY],
        object_len: 0,
        port: 0,
        transaction: 0,
        response_len: 0,
    };

    pub fn server(&self) -> &[u8] {
        &self.server[..usize::from(self.server_len)]
    }

    pub fn object(&self) -> &[u8] {
        &self.object[..usize::from(self.object_len)]
    }

    /// Length of the last accepted registration response.
    pub const fn response_len(&self) -> usize {
        self.response_len as usize
    }
}

/// State, transaction, and response of a registration, as export 194
/// reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationResult {
    pub state: RegistrationState,
    pub transaction: u64,
    response: [u8; REGISTRATION_RESPONSE_CAPACITY],
    response_len: u16,
}

impl RegistrationResult {
    pub const EMPTY: Self = Self {
        state: RegistrationState::Pending,
        transaction: 0,
        response: [0; REGISTRATION_RESPONSE_CAPACITY],
        response_len: 0,
    };

    /// The view of `registration`, whose response body the backend keeps
    /// in `body`. Bytes past the response length are never reported.
    pub fn new(
        registration: &HttpRegistration,
        body: &[u8; REGISTRATION_RESPONSE_CAPACITY],
    ) -> Self {
        Self {
            state: registration.state,
            transaction: registration.transaction,
            response: *body,
            response_len: registration.response_len,
        }
    }

    /// Export 194 (stock 0x91f30b48) after its argument checks: copy the
    /// response of a registered console into `output`, the caller's buffer
    /// (`None` without a size pointer).
    pub fn export_response(&self, output: Option<&mut [u8]>) -> RegistrationResponse {
        let none = |error| RegistrationResponse {
            result: Err(error),
            transaction: 0,
            length: 0,
        };

        match self.state {
            RegistrationState::Pending | RegistrationState::InProgress => {
                none(RegistrationError::NotRegistered)
            }
            RegistrationState::Cleared => none(RegistrationError::Cleared),
            RegistrationState::Failed => none(RegistrationError::Failed),
            RegistrationState::Rejected => none(RegistrationError::Rejected),
            RegistrationState::ResponseTooLarge => none(RegistrationError::ResponseTooLarge),
            RegistrationState::Registered => {
                let response = &self.response[..usize::from(self.response_len)];
                let result = match output {
                    Some(output) if output.len() >= response.len() => {
                        output[..response.len()].copy_from_slice(response);
                        Ok(())
                    }
                    Some(_) => Err(RegistrationError::BufferTooSmall),
                    // Without a size pointer nothing is copied, yet stock reports success.
                    None => Ok(()),
                };

                RegistrationResponse {
                    result,
                    transaction: self.transaction,
                    length: response.len() as u32,
                }
            }
        }
    }
}

/// What export 194 stores and returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationResponse {
    pub result: Result<(), RegistrationError>,
    pub transaction: u64,
    pub length: u32,
}

/// A registration request: `GET <path>` to `server` on `port` (0 for the
/// default port).
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest<'a> {
    pub server: &'a [u8],
    pub port: u16,
    pub path: &'a [u8],
}

/// Step of starting a request that failed (stock 0x91f300e0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpStartStage {
    Startup,
    Session,
    Connection,
    Request,
    Send,
}

/// A failed request start and the last error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpStartFailure {
    pub stage: HttpStartStage,
    pub error: Option<Win32Error>,
}

/// How an in-progress request failed. Errors are last errors; `None` is
/// `ERROR_SUCCESS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFailure {
    Work {
        error: Option<Win32Error>,
    },
    Receive {
        error: Option<Win32Error>,
    },
    StatusQuery {
        error: Option<Win32Error>,
    },
    /// The server answered with a status other than 200.
    Status {
        code: u32,
    },
    ContentLength {
        error: Option<Win32Error>,
    },
    /// The announced body exceeds [`REGISTRATION_RESPONSE_CAPACITY`].
    TooLarge {
        length: u32,
    },
    Read {
        error: Option<Win32Error>,
    },
    /// The request failed in stock state `state` (1 sending, 3 receiving
    /// headers, 5 reading).
    Request {
        state: u32,
        error: Option<Win32Error>,
    },
    /// The connection ended with `expected` body bytes outstanding.
    Truncated {
        received: u32,
        expected: u32,
    },
}

/// Progress of an in-progress request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpProgress {
    Pending,
    /// The status was 200 and this many body bytes were stored.
    Complete(usize),
    Failed(HttpFailure),
}

/// Request path text cut at [`REGISTRATION_PATH_CAPACITY`] bytes.
struct PathWriter<'a> {
    buffer: &'a mut [u8; REGISTRATION_PATH_CAPACITY],
    len: usize,
}

impl PathWriter<'_> {
    fn push(&mut self, bytes: &[u8]) {
        let count = bytes.len().min(self.buffer.len() - self.len);
        self.buffer[self.len..self.len + count].copy_from_slice(&bytes[..count]);
        self.len += count;
    }
}

impl core::fmt::Write for PathWriter<'_> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        self.push(text.as_bytes());

        Ok(())
    }
}

/// Stock 0x91f30998, run when the title ends: before system software
/// 0x20165400 a registration request in progress is abandoned and started
/// again.
pub(crate) fn title_terminated(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    let registration = &mut state.console.http_registration;
    if backend.xam_version() < REGISTRATION_ANY_STATE_VERSION
        && registration.state == RegistrationState::InProgress
    {
        backend.http_close();
        registration.state = RegistrationState::Pending;
        backend.publish(Published::Registration(registration));
    }
}

/// `httpreg clear` | `httpreg server=<s> object=</path> [port=<dword>]`.
/// Every call clears the previous registration and rewrites the settings
/// file.
pub(super) fn http_registration(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.state.console.http_registration.state == RegistrationState::InProgress {
        invocation.backend.http_close();
    }

    let registration = &mut invocation.state.console.http_registration;
    *registration = HttpRegistration::EMPTY;
    let result = if invocation.line.has("clear") {
        registration.state = RegistrationState::Cleared;
        Ok(Reply::Ok)
    } else {
        let mut buffer = [0u8; REGISTRATION_TEXT_CAPACITY + 1];
        let server = invocation
            .line
            .param("server")
            .map(|value| value.copy_into(&mut buffer).len());
        if let Some(length) = server {
            registration.server[..length].copy_from_slice(&buffer[..length]);
            registration.server_len = length as u8;
        }

        let object = server
            .and(invocation.line.param("object"))
            .map(|value| value.copy_into(&mut buffer).len());
        if let Some(length) = object {
            registration.object[..length].copy_from_slice(&buffer[..length]);
            registration.object_len = length as u8;
        }

        if object.is_none() {
            registration.state = RegistrationState::Failed;
            Err(ErrorCode::BadParameter.into())
        } else if registration.object().first() != Some(&b'/') {
            registration.state = RegistrationState::Failed;
            Err(ErrorCode::FilenameInvalid.into())
        } else {
            registration.port = invocation.line.dword("port").map_or(0, |port| port as u16);
            registration.state = RegistrationState::Pending;
            Ok(Reply::Ok)
        }
    };

    invocation.backend.publish(Published::Registration(
        &invocation.state.console.http_registration,
    ));
    crate::commands::system::save_settings(invocation.state, invocation.backend);

    result
}

/// Settings-file `httpreg` line (stock DoIniLine calls the handler).
pub(crate) fn ini_httpreg(invocation: &mut Invocation<'_>) {
    let _ = http_registration(invocation);
}

/// The registration request path: object, then the query of stock
/// 0x91f300e0, truncated as `_snprintf` with a 0x400-byte buffer.
fn registration_path(
    state: &ServerState,
    test_kit: bool,
    kernel: Version,
    buffer: &mut [u8; REGISTRATION_PATH_CAPACITY],
) -> usize {
    let console = &state.console;
    let registration = &console.http_registration;
    let address = &console.registration_check.address;
    let Version(version) = kernel;

    let mut path = PathWriter { buffer, len: 0 };

    path.push(registration.object());
    path.push(b"?name=");
    path.push(console.debug_name.as_bytes());
    let _ = write!(
        path,
        "&dbgmac={:02X}{:02X}{:02X}{:02X}{:02X}{:02X}&dbgip={}.{}.{}.{}&verflash={}.{}.{}.{}&verxdk={MONITOR_VERSION}\
         &type={}&locked={}&transaction={:016X}",
        address[10],
        address[11],
        address[12],
        address[13],
        address[14],
        address[15],
        address[0],
        address[1],
        address[2],
        address[3],
        version[0],
        version[1],
        version[2],
        version[3] & 0x7fff,
        u32::from(test_kit),
        i32::from(state.lock.is_locked()),
        registration.transaction,
    );

    path.len
}

/// A last error as the registration texts print it; `ERROR_SUCCESS` is 0.
fn last_error_code(error: Option<Win32Error>) -> u32 {
    error.map_or(0, Win32Error::code)
}

/// Stock 0x91f300e0: build the request and start it.
fn start_registration(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
) -> Result<(), HttpStartFailure> {
    let mut transaction = [0u8; 8];
    backend.random_bytes(&mut transaction);
    state.console.http_registration.transaction = u64::from_be_bytes(transaction);
    state.console.http_registration.response_len = 0;

    let test_kit = backend.is_test_kit();
    let kernel = backend.system_information().kernel;
    let mut path = [0u8; REGISTRATION_PATH_CAPACITY];
    let length = registration_path(state, test_kit, kernel, &mut path);

    let registration = &state.console.http_registration;
    let request = HttpRequest {
        server: registration.server(),
        port: registration.port,
        path: &path[..length],
    };

    if let Err(failure) = backend.http_begin(&request) {
        let stage = match failure.stage {
            HttpStartStage::Startup => "starting up XHttp",
            HttpStartStage::Session => "creating XHttp session object",
            HttpStartStage::Connection => "creating XHttp connection object",
            HttpStartStage::Request => "creating XHttp request object",
            HttpStartStage::Send => "starting HTTP request",
        };

        print(
            backend,
            format_args!(
                "XBDM: Failed {stage} (err = {})!\n",
                last_error_code(failure.error)
            ),
        );

        state.console.http_registration.transaction = 0;
        return Err(failure);
    }

    let mut message = MessageText::new();
    let _ = message.write_str("XBDM: Attempting to register at [http://");
    let _ = message.push_bytes(request.server);
    if request.port != 0 {
        let _ = write!(message, ":{}", request.port);
    }

    let _ = message.push_bytes(request.path);
    let _ = message.write_str("]...\n");
    backend.debug_print(message.as_bytes());

    state.console.http_registration.state = RegistrationState::InProgress;

    Ok(())
}

/// Advance an in-progress request (stock 0x91f30580 states 1 to 7).
fn advance_registration(state: &mut ServerState, backend: &mut dyn AnyBackend) -> u32 {
    let registration = &mut state.console.http_registration;
    let failure = match backend.http_poll() {
        HttpProgress::Pending => return REGISTRATION_RETRY_MS,
        HttpProgress::Complete(length) => {
            registration.response_len = length as u16;
            print(
                backend,
                format_args!("XBDM: Received {length} byte HTTP registration response.\n"),
            );
            registration.state = RegistrationState::Registered;
            backend.http_close();
            return REGISTRATION_PERIOD_MS;
        }
        HttpProgress::Failed(failure) => failure,
    };

    let next = match failure {
        HttpFailure::Status { .. } => RegistrationState::Rejected,
        HttpFailure::TooLarge { .. } => RegistrationState::ResponseTooLarge,
        _ => RegistrationState::Failed,
    };

    match failure {
        HttpFailure::Work { error } => print(
            backend,
            format_args!(
                "XBDM: Failed doing XHttp work (err = {})!\n",
                last_error_code(error)
            ),
        ),
        HttpFailure::Receive { error } => print(
            backend,
            format_args!(
                "XBDM: Failed starting to receive HTTP response (err = {})!\n",
                last_error_code(error)
            ),
        ),
        HttpFailure::StatusQuery { error } => print(
            backend,
            format_args!(
                "XBDM: Failed retrieving HTTP status code (err = {})!\n",
                last_error_code(error)
            ),
        ),
        HttpFailure::Status { code } => print(
            backend,
            format_args!("XBDM: HTTP server returned status code other than OK ({code})!\n"),
        ),
        HttpFailure::ContentLength { error } => print(
            backend,
            format_args!(
                "XBDM: Failed retrieving content length (err = {})!\n",
                last_error_code(error)
            ),
        ),
        HttpFailure::TooLarge { length } => print(
            backend,
            format_args!(
                "XBDM: HTTP registration response too large ({length} > {REGISTRATION_RESPONSE_CAPACITY})!\n"
            ),
        ),
        HttpFailure::Read { error } => print(
            backend,
            format_args!(
                "XBDM: Failed reading XHttp data (err = {})!\n",
                last_error_code(error)
            ),
        ),
        HttpFailure::Request { state, error } => print(
            backend,
            format_args!(
                "XBDM: HTTP registration failed (state {state}, err = {})!\n",
                last_error_code(error)
            ),
        ),
        HttpFailure::Truncated { received, expected } => print(
            backend,
            format_args!(
                "XBDM: HTTP registration response truncated (received {received} bytes, expecting {expected} more)!\n"
            ),
        ),
    }

    backend.http_close();
    state.console.http_registration.state = next;

    REGISTRATION_PERIOD_MS
}

/// Stock 0x91f30580, run on every pass of the server loop: drive the lab
/// server registration and return the milliseconds until it needs to run
/// again. A registered or failed console registers again when its debug
/// address changes.
pub(crate) fn poll_registration(state: &mut ServerState, backend: &mut dyn AnyBackend) -> u32 {
    let registration = &state.console.http_registration;
    let before = (registration.state, registration.transaction);

    let wait = run_registration(state, backend);

    let registration = &state.console.http_registration;
    if (registration.state, registration.transaction) != before {
        backend.publish(Published::Registration(registration));
    }

    wait
}

fn run_registration(state: &mut ServerState, backend: &mut dyn AnyBackend) -> u32 {
    /// Task period while no registration is configured.
    const REGISTRATION_IDLE_MS: u32 = 3_600_000;

    let now = backend.tick_milliseconds();
    match state.console.http_registration.state {
        RegistrationState::Cleared => return REGISTRATION_IDLE_MS,
        RegistrationState::InProgress => return advance_registration(state, backend),
        // Register now.
        RegistrationState::Pending => {}
        RegistrationState::Registered
        | RegistrationState::Failed
        | RegistrationState::Rejected
        | RegistrationState::ResponseTooLarge => {
            let elapsed = now.wrapping_sub(state.console.registration_check.tick);
            if elapsed < REGISTRATION_PERIOD_MS {
                return REGISTRATION_PERIOD_MS - elapsed;
            }

            let address = backend.debug_network_address();
            if address.status == 0 {
                return REGISTRATION_RETRY_MS;
            }

            if address.record == state.console.registration_check.address {
                state.console.registration_check.tick = now;
                return REGISTRATION_PERIOD_MS;
            }

            state.console.http_registration.state = RegistrationState::Pending;
        }
    }

    let address = backend.debug_network_address();
    if address.status == 0 {
        return REGISTRATION_RETRY_MS;
    }

    if backend.xam_version() < REGISTRATION_ANY_STATE_VERSION
        && backend.execution_state() != crate::notify::ExecutionState::Started
    {
        return REGISTRATION_RETRY_MS;
    }

    state.console.registration_check = RegistrationCheck {
        address: address.record,
        tick: now,
    };

    if state.console.http_registration.object().is_empty() {
        state.console.http_registration.state = RegistrationState::Cleared;
        return REGISTRATION_IDLE_MS;
    }

    if address.record[..4] == [0; 4] {
        state.console.http_registration.state = RegistrationState::Failed;
        return REGISTRATION_PERIOD_MS;
    }

    match start_registration(state, backend) {
        Ok(()) => advance_registration(state, backend),
        Err(failure) => {
            print(
                backend,
                format_args!(
                    "XBDM: Failed starting up HTTP registration task (err = {})!\n",
                    last_error_code(failure.error)
                ),
            );

            state.console.http_registration.state = RegistrationState::Failed;
            REGISTRATION_PERIOD_MS
        }
    }
}

/// `httpreg server=%s object=%s port=%u`, or `httpreg clear` without an
/// object (stock 0x91f30c88).
pub(crate) fn httpreg_settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let registration = &state.console.http_registration;
    if registration.object().is_empty() {
        write_line(backend, file, format_args!("httpreg clear"));
        return;
    }

    let mut line = SettingsLine::new();
    let _ = line.write_str("httpreg server=");
    let _ = line.push_bytes(registration.server());
    let _ = line.write_str(" object=");
    let _ = line.push_bytes(registration.object());
    let _ = write!(line, " port={}", registration.port);
    write_bytes(backend, file, line.as_bytes());
    end_line(backend, file);
}

#[cfg(test)]
mod tests {
    use openxbdm_core::status::Hresult;

    use super::*;

    #[test]
    fn registration_response_follows_the_state() {
        let mut registration = RegistrationResult::EMPTY;
        let failed = |error| RegistrationResponse {
            result: Err(error),
            transaction: 0,
            length: 0,
        };

        for (state, error, result) in [
            (
                RegistrationState::Pending,
                RegistrationError::NotRegistered,
                0x82da_0150,
            ),
            (
                RegistrationState::InProgress,
                RegistrationError::NotRegistered,
                0x82da_0150,
            ),
            (
                RegistrationState::Cleared,
                RegistrationError::Cleared,
                0x82da_0002,
            ),
            (
                RegistrationState::Failed,
                RegistrationError::Failed,
                0x82da_0100,
            ),
            (
                RegistrationState::Rejected,
                RegistrationError::Rejected,
                0x82da_010a,
            ),
            (
                RegistrationState::ResponseTooLarge,
                RegistrationError::ResponseTooLarge,
                0x82da_000f,
            ),
        ] {
            registration.state = state;
            assert_eq!(
                registration.export_response(Some(&mut [0; 8])),
                failed(error)
            );
            assert_eq!(Hresult::from(error), Hresult(result));
        }

        registration.state = RegistrationState::Registered;
        registration.transaction = 0x0123_4567_89ab_cdef;
        registration.response[..3].copy_from_slice(b"abc");
        registration.response_len = 3;
        let registered = |result| RegistrationResponse {
            result,
            transaction: 0x0123_4567_89ab_cdef,
            length: 3,
        };

        let mut buffer = [0xffu8; 4];
        assert_eq!(
            registration.export_response(Some(&mut buffer)),
            registered(Ok(()))
        );
        assert_eq!(buffer, *b"abc\xff");
        assert_eq!(
            registration.export_response(Some(&mut buffer[..2])),
            registered(Err(RegistrationError::BufferTooSmall))
        );
        assert_eq!(
            Hresult::from(RegistrationError::BufferTooSmall),
            Hresult(0x82da_0105)
        );
        assert_eq!(registration.export_response(None), registered(Ok(())));
    }
}
