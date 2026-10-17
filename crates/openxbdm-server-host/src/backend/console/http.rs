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
/// asynchronous client. The request carries the user agent and the host;
/// the further headers of the console's HTTP stack are not known.
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
        /// Port of a request without one.
        const HTTP_DEFAULT_PORT: u16 = 80;
        /// Limit on each socket wait of a request.
        const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

        let request_error = |state: u32, error: &io::Error| HttpFailure::Request {
            state,
            error: os_error(error),
        };

        let effective_port = if port == 0 { HTTP_DEFAULT_PORT } else { port };
        let mut stream = TcpStream::connect((server, effective_port))
            .map_err(|error| request_error(1, &error))?;
        let _ = stream.set_read_timeout(Some(HTTP_TIMEOUT));
        let _ = stream.set_write_timeout(Some(HTTP_TIMEOUT));

        let host = if port == 0 {
            server.to_owned()
        } else {
            format!("{server}:{port}")
        };
        let mut request = b"GET ".to_vec();
        request.extend_from_slice(path);
        request.extend_from_slice(
            format!(" HTTP/1.1\r\nUser-Agent: {REGISTRATION_USER_AGENT}\r\nHost: {host}\r\n\r\n")
                .as_bytes(),
        );
        stream
            .write_all(&request)
            .map_err(|error| request_error(1, &error))?;

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

        let head = String::from_utf8_lossy(&received[..header_end]).into_owned();
        let mut lines = head.split("\r\n");
        let code = lines
            .next()
            .and_then(|status| status.split(' ').nth(1))
            .and_then(|code| code.parse::<u32>().ok());
        let code = code.ok_or(HttpFailure::StatusQuery {
            error: Some(HTTP_HEADER_NOT_FOUND),
        })?;
        if code != 200 {
            return Err(HttpFailure::Status { code });
        }

        let length = lines.find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<u32>().ok())?
        });
        let length = length.ok_or(HttpFailure::ContentLength {
            error: Some(HTTP_HEADER_NOT_FOUND),
        })?;
        if length as usize > REGISTRATION_RESPONSE_CAPACITY {
            return Err(HttpFailure::TooLarge { length });
        }

        let mut content = received[header_end + 4..].to_vec();
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

        Ok(content)
    }
}

fn os_error(error: &io::Error) -> Option<Win32Error> {
    error
        .raw_os_error()
        .and_then(|code| Win32Error::new(code as u32))
}
