//! `ipproxy` over TCP.

use std::net::Ipv4Addr;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use openxbdm_server::commands::network::SystemVersion;
use openxbdm_server::commands::network::WsaError;
use openxbdm_server::commands::network::ipproxy::RegisterStatus;
use openxbdm_server::commands::network::ipproxy::SocketFailed;
use openxbdm_server::commands::network::ipproxy::tunnel;
use openxbdm_server_host::backend::network::ipproxy::Routine;

use crate::common::RawSession;
use crate::common::TestServer;

fn session(server: &TestServer) -> RawSession {
    let mut session = server.raw();
    session.line();

    session
}

/// A UDP socket standing in for the host end of the tunnel.
fn host_socket() -> UdpSocket {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    socket
}

fn start_line(host: &UdpSocket) -> String {
    format!(
        "ipproxy start ver=1 addr=0x7f000001 port={}",
        host.local_addr().unwrap().port()
    )
}

fn local_port(server: &TestServer) -> u16 {
    server.host.lock().backend.network.ipproxy.local.port
}

fn started(server: &TestServer) -> bool {
    server.host.lock().backend.network.ipproxy.register_routine
}

/// Start the proxy toward `host` and connect `host` back to the console end.
fn start(server: &TestServer, session: &mut RawSession, host: &UdpSocket) {
    /// First dword of the simulated console's debug XNADDR.
    const LOCAL_ADDRESS: &str = "0xc0a8011a";

    let reply = session.command(&start_line(host));
    let port = local_port(server);
    assert_eq!(
        reply,
        format!("200- started ver=1 addr={LOCAL_ADDRESS} port=0x{port:04x}")
    );

    host.connect((Ipv4Addr::LOCALHOST, port)).unwrap();
}

/// Packets the receive loop injected, waiting until there are `count`.
fn injected(server: &TestServer, count: usize) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(5);

    loop {
        let packets = server
            .host
            .lock()
            .backend
            .network
            .ipproxy
            .link()
            .injected
            .clone();
        if packets.len() >= count || Instant::now() >= deadline {
            return packets;
        }

        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn start_and_stop_report_the_tunnel() {
    let server = TestServer::start();
    let mut session = session(&server);
    let host = host_socket();
    start(&server, &mut session, &host);

    {
        let backend = &server.host.lock().backend;
        let mock = &backend.network.ipproxy;
        assert!(mock.hook_installed && mock.proxy_bypass && mock.inject_routine);
        let socket = mock.socket.as_ref().unwrap();
        assert_eq!(socket.peer_addr().unwrap(), host.local_addr().unwrap());
    }

    assert_eq!(session.command("ipproxy stop"), "200- stopped");

    let backend = &server.host.lock().backend;
    let mock = &backend.network.ipproxy;
    assert!(
        !mock.register_routine
            && !mock.inject_routine
            && !mock.hook_installed
            && !mock.proxy_bypass
    );
    assert!(mock.socket.is_none());
}

#[test]
fn start_validates_parameters() {
    let server = TestServer::start();
    let mut session = session(&server);

    for line in [
        "ipproxy",
        "ipproxy restart",
        "ipproxy start",
        "ipproxy start addr=0x7f000001 port=1",
        "ipproxy start ver=1 port=1",
        "ipproxy start ver=1 addr=0x7f000001",
        "ipproxy start ver=0 addr=0x7f000001 port=1",
        "ipproxy start ver=1 addr=0 port=1",
        "ipproxy start ver=1 addr=0x7f000001 port=0",
        "ipproxy start ver=1 addr=0x7f000001 port=0x10000",
        "ipproxy start ver=x addr=0x7f000001 port=1",
        "ipproxy stop start ver=1 addr=0x7f000001",
    ] {
        assert_eq!(session.command(line), "423- bad parameter", "{line}");
    }

    assert!(!started(&server));
}

#[test]
fn start_twice_and_stop_without_start() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("ipproxy stop"), "426- ");

    let host = host_socket();
    start(&server, &mut session, &host);
    assert_eq!(
        session.command(&start_line(&host)),
        "410- file already exists"
    );
    assert_eq!(session.command("ipproxy stop"), "200- stopped");
    assert_eq!(session.command("ipproxy stop"), "426- ");
}

#[test]
fn start_requires_the_system_version() {
    let server = TestServer::start();
    let mut session = session(&server);
    let host = host_socket();

    server.host.lock().backend.network.system_version = SystemVersion(0x201c_7cff);
    assert_eq!(session.command(&start_line(&host)), "407- unknown command");
    assert!(!started(&server));

    server.host.lock().backend.network.system_version = SystemVersion(0x201c_7d00);
    start(&server, &mut session, &host);
}

#[test]
fn missing_exports_deny_access() {
    let server = TestServer::start();
    let mut session = session(&server);
    let host = host_socket();

    server.host.lock().backend.network.ipproxy.missing_routine = Some(Routine::Register);
    assert_eq!(session.command(&start_line(&host)), "414- access denied");
    assert_eq!(session.command("ipproxy stop"), "426- ");

    // The register routine stays resolved: the proxy counts as started.
    server.host.lock().backend.network.ipproxy.missing_routine = Some(Routine::Inject);
    assert_eq!(session.command(&start_line(&host)), "414- access denied");
    assert_eq!(
        session.command(&start_line(&host)),
        "410- file already exists"
    );
    assert_eq!(session.command("ipproxy stop"), "200- stopped");
    assert!(!started(&server));
}

#[test]
fn socket_errors_are_reported() {
    let server = TestServer::start();
    let mut session = session(&server);
    let host = host_socket();

    server.host.lock().backend.network.ipproxy.socket_failure =
        Some(SocketFailed(WsaError::new(10050)));
    assert_eq!(session.command(&start_line(&host)), "400- err=10050");
    assert!(!started(&server));
    assert!(!server.host.lock().backend.network.ipproxy.proxy_bypass);
}

#[test]
fn socket_error_zero_reports_started() {
    let server = TestServer::start();
    let mut session = session(&server);
    let host = host_socket();

    server.host.lock().backend.network.ipproxy.socket_failure = Some(SocketFailed(None));
    assert_eq!(
        session.command(&start_line(&host)),
        "200- started ver=1 addr=0x00000000 port=0x0000"
    );
    assert!(started(&server));
    assert!(server.host.lock().backend.network.ipproxy.socket.is_none());
    assert_eq!(session.command("ipproxy stop"), "200- stopped");
}

#[test]
fn register_failures_are_reported() {
    let server = TestServer::start();
    let mut session = session(&server);
    let host = host_socket();

    server.host.lock().backend.network.ipproxy.register_failure = RegisterStatus::new(0x8000_4005);
    assert_eq!(session.command(&start_line(&host)), "400- err=-2147467259");
    {
        let backend = &server.host.lock().backend;
        let mock = &backend.network.ipproxy;
        assert!(!mock.register_routine && !mock.proxy_bypass && !mock.hook_installed);
        assert!(mock.socket.is_none());
    }

    start(&server, &mut session, &host);

    server.host.lock().backend.network.ipproxy.register_failure = RegisterStatus::new(5);
    assert_eq!(session.command("ipproxy stop"), "400- err=5");
    assert!(started(&server));
    assert!(server.host.lock().backend.network.ipproxy.hook_installed);
    assert_eq!(session.command("ipproxy stop"), "200- stopped");
}

#[test]
fn thread_failure_reports_no_buffers() {
    let server = TestServer::start();
    let mut session = session(&server);
    let host = host_socket();

    server.host.lock().backend.network.ipproxy.thread_failure = true;
    assert_eq!(session.command(&start_line(&host)), "400- err=10055");

    let backend = &server.host.lock().backend;
    let mock = &backend.network.ipproxy;
    assert!(!mock.register_routine && !mock.proxy_bypass && !mock.hook_installed);
    assert!(mock.socket.is_none());
}

#[test]
fn host_messages_are_injected() {
    let server = TestServer::start();
    let mut session = session(&server);
    let host = host_socket();
    start(&server, &mut session, &host);

    host.send(&[0x02, 10, 0, 0, 9, 0xaa, 0xbb]).unwrap();
    host.send(&[0x03, 10, 0, 0, 9, 0x00, 0x35, 0x04, 0xd2, b'x'])
        .unwrap();
    host.send(&[0x02, 10, 0, 0]).unwrap();
    host.send(&[0x04, 10, 0, 0, 9, 0x00, 0x43, 0x00, 0x44])
        .unwrap();

    let packets = injected(&server, 3);
    assert_eq!(
        packets,
        [
            vec![
                0x45, 0, 0, 22, 0, 0, 0, 0, 1, 6, 0, 0, 10, 0, 0, 9, 127, 0, 0, 1, 0xaa, 0xbb
            ],
            vec![
                0x45, 0, 0, 29, 0, 0, 0, 0, 1, 17, 0, 0, 10, 0, 0, 9, 127, 0, 0, 1, 0x00, 0x35,
                0x04, 0xd2, 0, 9, 0, 0, b'x',
            ],
            vec![
                0x45, 0, 0, 28, 0, 0, 0, 0, 1, 17, 0, 0, 10, 0, 0, 9, 255, 255, 255, 255, 0x00,
                0x43, 0x00, 0x44, 0, 8, 0, 0,
            ],
        ]
    );

    assert_eq!(session.command("ipproxy stop"), "200- stopped");
}

#[test]
fn outbound_packets_reach_the_host() {
    let server = TestServer::start();
    let mut session = session(&server);
    let host = host_socket();
    let mut packet = vec![
        0x45, 0, 0, 31, 0, 1, 0x40, 0, 64, 17, 0x12, 0x34, 192, 168, 1, 26, 8, 8, 8, 8, 0x04, 0xd2,
        0x00, 0x35, 0, 11, 0, 0, b'a', b'b', b'c',
    ];

    assert!(
        !server
            .host
            .lock()
            .backend
            .network
            .ipproxy
            .transmit(&mut packet.clone())
    );

    start(&server, &mut session, &host);
    assert!(
        server
            .host
            .lock()
            .backend
            .network
            .ipproxy
            .transmit(&mut packet)
    );

    let mut message = [0u8; tunnel::MESSAGE_LIMIT];
    let length = host.recv(&mut message).unwrap();
    assert_eq!(
        message[..length],
        [0x03, 8, 8, 8, 8, 0x00, 0x35, 0x04, 0xd2, b'a', b'b', b'c']
    );

    assert_eq!(session.command("ipproxy stop"), "200- stopped");
    assert!(
        !server
            .host
            .lock()
            .backend
            .network
            .ipproxy
            .transmit(&mut packet)
    );
}

#[test]
fn keepalive_follows_a_quiet_interval() {
    let server = TestServer::start();
    let mut session = session(&server);
    let host = host_socket();
    start(&server, &mut session, &host);

    let earlier = Instant::now()
        .checked_sub(tunnel::KEEPALIVE_INTERVAL)
        .unwrap();
    server.host.lock().backend.network.ipproxy.link().last_send = earlier;

    // Any datagram wakes the receive loop, which then checks the interval.
    host.send(&[0x00]).unwrap();
    let mut message = [0u8; 16];
    let length = host.recv(&mut message).unwrap();
    assert_eq!(message[..length], tunnel::KEEPALIVE);

    {
        let backend = &server.host.lock().backend;
        let link = backend.network.ipproxy.link();
        assert!(link.last_send > earlier);
        assert!(link.injected.is_empty());
    }

    let before = server
        .host
        .lock()
        .backend
        .network
        .ipproxy
        .link()
        .last_receive;
    host.send(&tunnel::KEEPALIVE).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while server
        .host
        .lock()
        .backend
        .network
        .ipproxy
        .link()
        .last_receive
        == before
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        server
            .host
            .lock()
            .backend
            .network
            .ipproxy
            .link()
            .last_receive
            > before
    );

    assert_eq!(session.command("ipproxy stop"), "200- stopped");
}
