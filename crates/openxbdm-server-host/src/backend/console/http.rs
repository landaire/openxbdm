//! Simulated HTTP client of the registration task.

use std::io;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::TryRecvError;
use std::thread;
use std::time::Duration;

use openxbdm_core::status::Win32Error;
use openxbdm_server::commands::console::HttpFailure;
use openxbdm_server::commands::console::HttpProgress;
use openxbdm_server::commands::console::HttpRequest;
use openxbdm_server::commands::console::REGISTRATION_RESPONSE_CAPACITY;
use openxbdm_server::commands::console::REGISTRATION_USER_AGENT;

/// Simulated HTTP client of the registration task: an HTTP/1.1 exchange
/// over TCP on a worker thread, so the server polls it like the console's
/// asynchronous client. The request has the header lines XAM's client
/// writes for the task's GET without keep-alive: request line and user
/// agent (0x818d4dd0), then connection and host (0x818daa30). Redirects are
/// followed as XAM follows them (0x818dc49c, 0x818d6530); the task sees
/// only the final response.
#[derive(Debug)]
pub struct HttpClient {
    /// Result of the request in progress, delivered by its worker.
    pending: Option<Receiver<Result<Vec<u8>, HttpFailure>>>,
    /// Body of the last completed request.
    pub body: [u8; REGISTRATION_RESPONSE_CAPACITY],
    /// Times the client was released.
    pub closes: u32,
}

impl Default for HttpClient {
    fn default() -> Self {
        Self {
            pending: None,
            body: [0; REGISTRATION_RESPONSE_CAPACITY],
            closes: 0,
        }
    }
}

impl HttpClient {
    /// Start `request` on a worker thread.
    pub(super) fn begin(&mut self, request: &HttpRequest<'_>) {
        let server = String::from_utf8_lossy(request.server).into_owned();
        let port = request.port;
        let path = request.path.to_vec();

        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(Self::exchange(&server, port, &path));
        });
        self.pending = Some(receiver);
    }

    /// Progress of the request in progress; a completed body is copied to
    /// [`HttpClient::body`].
    pub(super) fn poll(&mut self) -> HttpProgress {
        let Some(receiver) = &self.pending else {
            return HttpProgress::Failed(HttpFailure::Work { error: None });
        };

        match receiver.try_recv() {
            Err(TryRecvError::Empty) => HttpProgress::Pending,
            Err(TryRecvError::Disconnected) => {
                HttpProgress::Failed(HttpFailure::Work { error: None })
            }
            Ok(Err(failure)) => HttpProgress::Failed(failure),
            Ok(Ok(content)) => {
                self.body.fill(0);
                self.body[..content.len()].copy_from_slice(&content);
                HttpProgress::Complete(content.len())
            }
        }
    }

    pub(super) fn close(&mut self) {
        self.pending = None;
        self.closes += 1;
    }

    fn exchange(server: &str, port: u16, path: &[u8]) -> Result<Vec<u8>, HttpFailure> {
        /// Header lookup error of the console HTTP stack (header not found).
        const HTTP_HEADER_NOT_FOUND: Win32Error = Win32Error::new(12150).unwrap();
        /// Redirects the registration task allows (XHttp option 0x59).
        const REDIRECTS: u32 = 3;
        /// Statuses XAM follows (0x818dcabc).
        const REDIRECT_STATUSES: [u32; 6] = [300, 301, 302, 303, 305, 307];
        /// `ERROR_GEN_FAILURE`, the result of an unusable location.
        const GENERAL_FAILURE: Win32Error = Win32Error::new(31).unwrap();

        let mut target = Target {
            server: server.to_owned(),
            port: if port == 0 { HTTP_DEFAULT_PORT } else { port },
            path: path.to_vec(),
        };
        let mut redirects = REDIRECTS;
        let mut relative_seen = false;
        // Failures before the first headers arrive are reported in the
        // sending state; after a redirect the task is already receiving.
        let mut send_state = 1;

        loop {
            let Response {
                mut stream,
                head,
                body,
            } = target.send(send_state)?;

            let code = head
                .split("\r\n")
                .next()
                .and_then(|status| status.split(' ').nth(1))
                .and_then(|code| code.parse::<u32>().ok());
            let code = code.ok_or(HttpFailure::StatusQuery {
                error: Some(HTTP_HEADER_NOT_FOUND),
            })?;
            let header = |wanted: &str| {
                head.split("\r\n").skip(1).find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.trim()
                        .eq_ignore_ascii_case(wanted)
                        .then(|| value.trim().to_owned())
                })
            };

            if REDIRECT_STATUSES.contains(&code) && redirects > 0 {
                redirects -= 1;
                let location = header("location").ok_or(HttpFailure::Request {
                    state: 3,
                    error: Some(HTTP_HEADER_NOT_FOUND),
                })?;
                match target.redirect(&location, &mut relative_seen) {
                    Redirect::Follow(next) => {
                        target = next;
                        send_state = 3;
                        continue;
                    }
                    // XAM stops and reports the redirect status.
                    Redirect::Loop => return Err(HttpFailure::Status { code }),
                    Redirect::Secure => {
                        return Err(HttpFailure::Request {
                            state: 3,
                            error: None,
                        });
                    }
                    Redirect::Invalid => {
                        return Err(HttpFailure::Request {
                            state: 3,
                            error: Some(GENERAL_FAILURE),
                        });
                    }
                }
            }
            if code != 200 {
                return Err(HttpFailure::Status { code });
            }

            let length = header("content-length").and_then(|value| value.parse::<u32>().ok());
            let length = length.ok_or(HttpFailure::ContentLength {
                error: Some(HTTP_HEADER_NOT_FOUND),
            })?;
            if length as usize > REGISTRATION_RESPONSE_CAPACITY {
                return Err(HttpFailure::TooLarge { length });
            }

            let mut content = body;
            while content.len() < length as usize {
                let mut chunk = [0u8; 512];
                match stream.read(&mut chunk) {
                    Ok(0) => {
                        let received = content.len() as u32;
                        return Err(HttpFailure::Truncated {
                            received,
                            expected: length - received,
                        });
                    }
                    Ok(count) => content.extend_from_slice(&chunk[..count]),
                    Err(error) => return Err(request_error(5, &error)),
                }
            }

            content.truncate(length as usize);

            return Ok(content);
        }
    }
}

/// Port of a request without one.
const HTTP_DEFAULT_PORT: u16 = 80;

/// Server and path of one request of the exchange.
struct Target {
    server: String,
    port: u16,
    path: Vec<u8>,
}

/// What XAM does with a redirect's `Location` (0x818d6530).
enum Redirect {
    /// Send the request again to this target.
    Follow(Target),
    /// The location names the current port and path: the redirect status
    /// reaches the task (8259, 0x818d7174).
    Loop,
    /// An `https://` location needs a TLS session, which the host lacks.
    Secure,
    /// The location's server part does not parse (0x818d2d80): the request
    /// fails with `ERROR_GEN_FAILURE`.
    Invalid,
}

/// A response head and the connection it arrived on.
struct Response {
    stream: TcpStream,
    /// Status line and header lines, without the empty line.
    head: String,
    /// Body bytes received with the head.
    body: Vec<u8>,
}

impl Target {
    /// Connect, send the request lines XAM writes and read the response
    /// head. Connection and send failures are reported in `state`.
    fn send(&self, state: u32) -> Result<Response, HttpFailure> {
        /// Limit on each socket wait of a request.
        const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

        let mut stream = TcpStream::connect((self.server.as_str(), self.port))
            .map_err(|error| request_error(state, &error))?;
        let _ = stream.set_read_timeout(Some(HTTP_TIMEOUT));
        let _ = stream.set_write_timeout(Some(HTTP_TIMEOUT));

        // XAM omits the port from the host line when it is the default.
        let host = if self.port == HTTP_DEFAULT_PORT {
            self.server.clone()
        } else {
            format!("{}:{}", self.server, self.port)
        };
        let mut request = b"GET ".to_vec();
        request.extend_from_slice(&self.path);
        request.extend_from_slice(
            format!(
                " HTTP/1.1\r\nUser-Agent: {REGISTRATION_USER_AGENT}\r\nConnection: Close\r\nHost:{host}\r\n\r\n"
            )
            .as_bytes(),
        );
        stream
            .write_all(&request)
            .map_err(|error| request_error(state, &error))?;

        let mut received = Vec::new();
        let header_end = loop {
            if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                break position;
            }

            let mut chunk = [0u8; 512];
            match stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(HttpFailure::Request {
                        state: 3,
                        error: None,
                    });
                }
                Ok(count) => received.extend_from_slice(&chunk[..count]),
                Err(error) => return Err(request_error(3, &error)),
            }
        };

        let body = received.split_off(header_end + 4);
        received.truncate(header_end);

        Ok(Response {
            stream,
            head: String::from_utf8_lossy(&received).into_owned(),
            body,
        })
    }

    /// The target of `location`. `relative_seen` is the connection flag
    /// 0x20000000 a relative location sets (0x818d6d58); with it, a location
    /// path equal to the current one on the same port is a loop.
    fn redirect(&self, location: &str, relative_seen: &mut bool) -> Redirect {
        if location.starts_with("https://") {
            return Redirect::Secure;
        }

        let (server, port, path) = match location.strip_prefix("http://") {
            Some(rest) => {
                let (authority, path) = rest.find('/').map_or((rest, "/"), |at| rest.split_at(at));
                let Some((server, port)) = parse_authority(authority) else {
                    return Redirect::Invalid;
                };
                (server.to_owned(), port, path.to_owned())
            }
            None => {
                *relative_seen = true;
                // A path without a leading slash is taken from the root
                // (0x818d6d90).
                let path = if location.starts_with('/') {
                    location.to_owned()
                } else {
                    format!("/{location}")
                };
                (self.server.clone(), self.port, path)
            }
        };

        if *relative_seen && port == self.port && path.as_bytes() == self.path {
            return Redirect::Loop;
        }

        Redirect::Follow(Target {
            server,
            port,
            path: path.into_bytes(),
        })
    }
}

/// 0x818d2d80: a server name without `?`, `=`, `#`, `%` or spaces and an
/// optional port of 1..=65535.
fn parse_authority(authority: &str) -> Option<(&str, u16)> {
    let (server, port) = match authority.split_once(':') {
        Some((server, port)) => {
            let port = port
                .bytes()
                .all(|byte| byte.is_ascii_digit())
                .then(|| port.parse::<u16>().ok())
                .flatten()
                .filter(|&port| port != 0)?;
            (server, port)
        }
        None => (authority, HTTP_DEFAULT_PORT),
    };

    let valid = !server.is_empty() && !server.contains(['?', '=', '#', '%', ' ']);

    valid.then_some((server, port))
}

fn request_error(state: u32, error: &io::Error) -> HttpFailure {
    HttpFailure::Request {
        state,
        error: os_error(error),
    }
}

fn os_error(error: &io::Error) -> Option<Win32Error> {
    error
        .raw_os_error()
        .and_then(|code| Win32Error::new(code as u32))
}
