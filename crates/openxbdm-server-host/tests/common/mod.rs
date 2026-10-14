//! Harness for client-server integration tests.

#![allow(dead_code)]

use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::transport::tokio::TokioTransport;
use openxbdm_server_host::Host;
use openxbdm_server_host::SharedHost;

/// Limit for a whole async test body.
const RUN_LIMIT: Duration = Duration::from_secs(60);
const WAIT_LIMIT: Duration = Duration::from_secs(10);

/// A server on a loopback port with its own simulated console.
pub struct TestServer {
    pub host: SharedHost,
    pub address: SocketAddr,
}

impl TestServer {
    pub fn start() -> Self {
        Self::with_host(Host::default())
    }

    pub fn with_host(host: Host) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let host = SharedHost::new(host);
        let serving = host.clone();
        thread::spawn(move || serving.serve(&listener));
        Self { host, address }
    }

    /// Connect the openxbdm client and read the banner.
    pub async fn client(&self) -> Client<TokioTransport, Connected> {
        let transport =
            openxbdm_client::transport::tokio::connect_timeout(self.address, WAIT_LIMIT)
                .await
                .unwrap();
        Client::new(transport).read_banner().await.unwrap()
    }

    /// Connect a raw line-oriented session.
    pub fn raw(&self) -> RawSession {
        let stream = TcpStream::connect(self.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        RawSession { stream, reader }
    }

    /// Poll `done` on the locked host until it holds, failing after a
    /// deadline.
    pub fn wait_until(&self, done: impl Fn(&Host) -> bool) {
        let deadline = Instant::now() + WAIT_LIMIT;
        while !done(&self.host.lock()) {
            assert!(Instant::now() < deadline, "condition not reached");
            thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Run an async test body on a current-thread runtime, failing after a
/// deadline.
pub fn run<F: Future>(future: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(RUN_LIMIT, future)
            .await
            .expect("test body timed out")
    })
}

/// A session that exchanges exact protocol lines.
pub struct RawSession {
    pub stream: TcpStream,
    pub reader: BufReader<TcpStream>,
}

impl RawSession {
    /// Read one line without its CR LF.
    pub fn line(&mut self) -> String {
        let mut line = String::new();
        let count = self.reader.read_line(&mut line).unwrap();
        assert_ne!(count, 0, "connection closed");
        line.trim_end_matches(['\r', '\n']).to_owned()
    }

    /// Send `command` with CR LF.
    pub fn send(&mut self, command: &str) {
        self.stream.write_all(command.as_bytes()).unwrap();
        self.stream.write_all(b"\r\n").unwrap();
    }

    /// Send a command and read its single-line reply.
    pub fn command(&mut self, command: &str) -> String {
        self.send(command);
        self.line()
    }

    /// Read lines up to and excluding the `.` terminator.
    pub fn multiline(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            let line = self.line();
            if line == "." {
                return lines;
            }
            lines.push(line);
        }
    }
}
