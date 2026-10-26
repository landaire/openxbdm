//! Lab server registration request over XHTTP, whose values follow WinHTTP.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Win32Error;
use openxbdm_server::commands::console::HttpFailure;
use openxbdm_server::commands::console::HttpProgress;
use openxbdm_server::commands::console::HttpRequest;
use openxbdm_server::commands::console::HttpStartFailure;
use openxbdm_server::commands::console::HttpStartStage;
use openxbdm_server::commands::console::REGISTRATION_RESPONSE_CAPACITY;
use xbox360::status::last_error;
use xbox360_sys::value_enum;
use xbox360_sys::xam::NetDll_XHttpCloseHandle;
use xbox360_sys::xam::NetDll_XHttpConnect;
use xbox360_sys::xam::NetDll_XHttpDoWork;
use xbox360_sys::xam::NetDll_XHttpOpen;
use xbox360_sys::xam::NetDll_XHttpOpenRequest;
use xbox360_sys::xam::NetDll_XHttpQueryHeaders;
use xbox360_sys::xam::NetDll_XHttpReadData;
use xbox360_sys::xam::NetDll_XHttpReceiveResponse;
use xbox360_sys::xam::NetDll_XHttpSendRequest;
use xbox360_sys::xam::NetDll_XHttpSetOption;
use xbox360_sys::xam::NetDll_XHttpSetStatusCallback;
use xbox360_sys::xam::NetDll_XHttpShutdown;
use xbox360_sys::xam::NetDll_XHttpStartup;
use xbox360_sys::xam::XnCaller;

use super::Data;
use crate::exports::bridged;

/// Raw [`HttpState`], the body bytes still expected and received, and the
/// failure the callback recorded: a raw [`HttpFailureKind`], the state it
/// failed in, and its Win32 error.
static HTTP_STATE: AtomicU32 = AtomicU32::new(0);
static HTTP_REMAINING: AtomicU32 = AtomicU32::new(0);
static HTTP_RECEIVED: AtomicU32 = AtomicU32::new(0);
static HTTP_FAILURE_KIND: AtomicU32 = AtomicU32::new(0);
static HTTP_FAILURE_STATE: AtomicU32 = AtomicU32::new(0);
static HTTP_FAILURE_ERROR: AtomicU32 = AtomicU32::new(0);

/// Registration response body. XAM keeps its address from
/// `NetDll_XHttpReadData` and fills it during later `NetDll_XHttpDoWork`
/// calls, so it is accessed only through raw pointers on the server thread.
/// It holds the body of the last accepted registration, which `publish`
/// copies into the export 194 view.
pub(super) static mut HTTP_BODY: [u8; REGISTRATION_RESPONSE_CAPACITY] =
    [0; REGISTRATION_RESPONSE_CAPACITY];

/// Request state shared with the status callback (stock 0x91f9f638).
#[repr(u32)]
#[derive(Clone, Copy)]
enum HttpState {
    Idle = 0,
    Sending = 1,
    Sent = 2,
    Receiving = 3,
    HeadersAvailable = 4,
    Reading = 5,
    ReadComplete = 6,
    Failed = 7,
}

impl HttpState {
    /// The raw state; the failure record reports it as is.
    fn load() -> u32 {
        HTTP_STATE.load(Ordering::Relaxed)
    }

    fn store(self) {
        HTTP_STATE.store(self as u32, Ordering::Relaxed);
    }
}

value_enum! {
    /// Failure the status callback recorded.
    pub enum HttpFailureKind: u32 {
        Request = 1,
        Truncated = 2,
    }
}

impl Data {
    /// Stock 0x91f300e0 after the URL is built.
    pub(super) fn begin_http(&mut self, request: &HttpRequest<'_>) -> Result<(), HttpStartFailure> {
        // `XHttpOpen` flag of an asynchronous session.
        const SESSION_ASYNC: u32 = 0x1000_0000;
        // `XHttpConnect` flags of the registration connection.
        const CONNECT_FLAGS: u32 = 1;
        // Status callback notification mask: every notification.
        const ALL_NOTIFICATIONS: u32 = u32::MAX;
        const OPTION_MAX_REDIRECTS: u32 = 0x59;
        const MAX_REDIRECTS: u32 = 3;
        const OPTION_DISABLE_FEATURE: u32 = 0x3f;
        const DISABLE_KEEP_ALIVE: u32 = 8;

        let fail = |data: &mut Self, stage| {
            let error = last_error();
            data.close_http();
            Err(HttpStartFailure { stage, error })
        };

        // SAFETY: startup takes scalar arguments.
        if unsafe { NetDll_XHttpStartup(XnCaller::DebugMonitor, 0, 0) } == 0 {
            return Err(HttpStartFailure {
                stage: HttpStartStage::Startup,
                error: last_error(),
            });
        }

        self.http_started = true;
        // SAFETY: the user agent string is NUL-terminated.
        self.http_session = unsafe {
            NetDll_XHttpOpen(
                XnCaller::DebugMonitor,
                c"Xbox Debugger/2.0.21256.0".as_ptr().cast(),
                0,
                0,
                0,
                SESSION_ASYNC,
            )
        };
        if self.http_session == 0 {
            return fail(self, HttpStartStage::Session);
        }

        let server_length = request.server.len().min(self.http_server.len() - 1);
        self.http_server[..server_length].copy_from_slice(&request.server[..server_length]);
        self.http_server[server_length] = 0;
        // SAFETY: `http_server` is NUL-terminated module state that outlives
        // the session.
        self.http_connection = unsafe {
            NetDll_XHttpConnect(
                XnCaller::DebugMonitor,
                self.http_session,
                self.http_server.as_ptr(),
                u32::from(request.port),
                CONNECT_FLAGS,
            )
        };
        if self.http_connection == 0 {
            return fail(self, HttpStartStage::Connection);
        }

        let path_length = request.path.len().min(self.http_path.len() - 1);
        self.http_path[..path_length].copy_from_slice(&request.path[..path_length]);
        self.http_path[path_length] = 0;
        // SAFETY: the verb and `http_path` are NUL-terminated; `http_path`
        // is module state that outlives the request.
        self.http_request = unsafe {
            NetDll_XHttpOpenRequest(
                XnCaller::DebugMonitor,
                self.http_connection,
                c"GET".as_ptr().cast(),
                self.http_path.as_ptr(),
                0,
                0,
                0,
                0,
            )
        };
        if self.http_request == 0 {
            return fail(self, HttpStartStage::Request);
        }

        let mut value = MAX_REDIRECTS;
        // SAFETY: `http_status_entry` has the status callback signature and
        // `value` is a live 4-byte option buffer.
        unsafe {
            NetDll_XHttpSetStatusCallback(
                XnCaller::DebugMonitor,
                self.http_request,
                http_status_entry as *const () as usize as u32,
                ALL_NOTIFICATIONS,
                0,
            );
            NetDll_XHttpSetOption(
                XnCaller::DebugMonitor,
                self.http_request,
                OPTION_MAX_REDIRECTS,
                &mut value,
                size_of::<u32>() as u32,
            );
            value = DISABLE_KEEP_ALIVE;
            NetDll_XHttpSetOption(
                XnCaller::DebugMonitor,
                self.http_request,
                OPTION_DISABLE_FEATURE,
                &mut value,
                size_of::<u32>() as u32,
            );
        }

        HttpState::Sending.store();
        // SAFETY: the request handle was opened above; no headers or body.
        let sent = unsafe {
            NetDll_XHttpSendRequest(XnCaller::DebugMonitor, self.http_request, 0, 0, 0, 0, 0, 0)
        };
        if sent == 0 {
            return fail(self, HttpStartStage::Send);
        }

        Ok(())
    }

    /// Stock 0x91f30580 states 1 to 7; the status callback advances the
    /// state during `NetDll_XHttpDoWork`. XAM reads into `HTTP_BODY`, which
    /// keeps the body for `publish`.
    pub(super) fn poll_http(&mut self) -> HttpProgress {
        // Header queries with the number flag.
        const QUERY_STATUS_CODE: u32 = 0x2000_fffe;
        const QUERY_CONTENT_LENGTH: u32 = 0x2000_0009;
        const STATUS_OK: u32 = 200;

        // SAFETY: the session handle was opened by `begin_http`.
        if unsafe { NetDll_XHttpDoWork(XnCaller::DebugMonitor, self.http_session, 0) } == 0 {
            return HttpProgress::Failed(HttpFailure::Work {
                error: last_error(),
            });
        }

        if HttpState::load() == HttpState::Sent as u32 {
            HttpState::Receiving.store();
            // SAFETY: the request handle was opened by `begin_http`.
            let receiving = unsafe {
                NetDll_XHttpReceiveResponse(XnCaller::DebugMonitor, self.http_request, 0)
            };
            if receiving == 0 {
                return HttpProgress::Failed(HttpFailure::Receive {
                    error: last_error(),
                });
            }
        }

        if HttpState::load() == HttpState::HeadersAvailable as u32 {
            let mut code = 0u32;
            let mut length = size_of::<u32>() as u32;
            // SAFETY: `code` and `length` are live locals of the stated size.
            let queried = unsafe {
                NetDll_XHttpQueryHeaders(
                    XnCaller::DebugMonitor,
                    self.http_request,
                    QUERY_STATUS_CODE,
                    0,
                    &mut code,
                    &mut length,
                    0,
                )
            };
            if queried == 0 {
                return HttpProgress::Failed(HttpFailure::StatusQuery {
                    error: last_error(),
                });
            }
            if code != STATUS_OK {
                return HttpProgress::Failed(HttpFailure::Status { code });
            }

            let mut content_length = 0u32;
            let mut length = size_of::<u32>() as u32;
            // SAFETY: `content_length` and `length` are live locals of the
            // stated size.
            let queried = unsafe {
                NetDll_XHttpQueryHeaders(
                    XnCaller::DebugMonitor,
                    self.http_request,
                    QUERY_CONTENT_LENGTH,
                    0,
                    &mut content_length,
                    &mut length,
                    0,
                )
            };
            if queried == 0 {
                return HttpProgress::Failed(HttpFailure::ContentLength {
                    error: last_error(),
                });
            }
            if content_length as usize > REGISTRATION_RESPONSE_CAPACITY {
                return HttpProgress::Failed(HttpFailure::TooLarge {
                    length: content_length,
                });
            }

            // SAFETY: only this thread accesses `HTTP_BODY`, and no read into
            // it is outstanding before the content length is known.
            unsafe { (&raw mut HTTP_BODY).write_bytes(0, 1) };
            HTTP_REMAINING.store(content_length, Ordering::Relaxed);
            HTTP_RECEIVED.store(0, Ordering::Relaxed);
            HttpState::ReadComplete.store();
        }

        if HttpState::load() == HttpState::ReadComplete as u32 {
            let remaining = HTTP_REMAINING.load(Ordering::Relaxed);
            let received = HTTP_RECEIVED.load(Ordering::Relaxed);
            if remaining == 0 {
                return HttpProgress::Complete(received as usize);
            }

            HttpState::Reading.store();
            let target = (&raw mut HTTP_BODY)
                .cast::<u8>()
                .wrapping_add(received as usize);
            // SAFETY: `target` is `received` bytes into the static
            // `HTTP_BODY`, and `received + remaining` is the content length,
            // at most its size; no reference covers it; `read` is not used.
            let reading = unsafe {
                NetDll_XHttpReadData(
                    XnCaller::DebugMonitor,
                    self.http_request,
                    target,
                    remaining,
                    core::ptr::null_mut(),
                )
            };
            if reading == 0 {
                return HttpProgress::Failed(HttpFailure::Read {
                    error: last_error(),
                });
            }
        }

        if HttpState::load() == HttpState::Failed as u32 {
            let kind = HttpFailureKind::from_raw(HTTP_FAILURE_KIND.load(Ordering::Relaxed));
            let failure = match kind {
                Some(HttpFailureKind::Truncated) => HttpFailure::Truncated {
                    received: HTTP_RECEIVED.load(Ordering::Relaxed),
                    expected: HTTP_REMAINING.load(Ordering::Relaxed),
                },
                Some(HttpFailureKind::Request) | None => HttpFailure::Request {
                    state: HTTP_FAILURE_STATE.load(Ordering::Relaxed),
                    error: Win32Error::new(HTTP_FAILURE_ERROR.load(Ordering::Relaxed)),
                },
            };
            return HttpProgress::Failed(failure);
        }

        HttpProgress::Pending
    }

    /// Stock 0x91f30480: close the request, connection and session, then
    /// shut the HTTP client down.
    pub(super) fn close_http(&mut self) {
        for handle in [
            &mut self.http_request,
            &mut self.http_connection,
            &mut self.http_session,
        ] {
            if *handle == 0 {
                continue;
            }

            // SAFETY: nonzero handles were opened by `begin_http` and are
            // cleared after closing.
            unsafe { NetDll_XHttpCloseHandle(XnCaller::DebugMonitor, *handle) };
            *handle = 0;
        }

        if core::mem::take(&mut self.http_started) {
            // SAFETY: matches the successful startup recorded in `http_started`.
            unsafe { NetDll_XHttpShutdown(XnCaller::DebugMonitor) };
        }

        HttpState::Idle.store();
    }
}

bridged!(http_status_entry, http_status);

/// Stock 0x91f2ffa0, called by `NetDll_XHttpDoWork` and the request functions
/// through [`http_status_entry`].
extern "C" fn http_status(
    _handle: u32,
    _context: u32,
    status: u32,
    information: *const u32,
    length: u32,
) -> u32 {
    // Status callback notifications.
    const HEADERS_AVAILABLE: u32 = 0x0002_0000;
    const READ_COMPLETE: u32 = 0x0008_0000;
    const REQUEST_ERROR: u32 = 0x0020_0000;
    const SEND_REQUEST_COMPLETE: u32 = 0x0040_0000;

    match status {
        HEADERS_AVAILABLE => HttpState::HeadersAvailable.store(),
        READ_COMPLETE => {
            if length == 0 {
                HTTP_FAILURE_KIND.store(HttpFailureKind::Truncated.raw(), Ordering::Relaxed);
                HttpState::Failed.store();
            } else {
                HTTP_REMAINING.fetch_sub(length, Ordering::Relaxed);
                HTTP_RECEIVED.fetch_add(length, Ordering::Relaxed);
                HttpState::ReadComplete.store();
            }
        }
        REQUEST_ERROR => {
            HTTP_FAILURE_KIND.store(HttpFailureKind::Request.raw(), Ordering::Relaxed);
            HTTP_FAILURE_STATE.store(HttpState::load(), Ordering::Relaxed);
            let error = if information.is_null() {
                0
            } else {
                // SAFETY: the request error information is {result, error}.
                unsafe { information.add(1).read() }
            };
            HTTP_FAILURE_ERROR.store(error, Ordering::Relaxed);
            HttpState::Failed.store();
        }
        SEND_REQUEST_COMPLETE => HttpState::Sent.store(),
        // Other notifications leave the request state unchanged.
        _ => {}
    }

    0
}
