//! Network commands over TCP.

mod common;
#[path = "network/ipproxy.rs"]
mod ipproxy;
#[path = "network/netcap.rs"]
mod netcap;
#[path = "network/netsim.rs"]
mod netsim;

use std::io::Write;

use common::TestServer;
use common::run;
use openxbdm_client::commands::GetSocketInfo;
use openxbdm_client::commands::SocketEntry;
use openxbdm_server::commands::network::KeyRecord;
use openxbdm_server::commands::network::LinkFlags;
use openxbdm_server::commands::network::NicStats;
use openxbdm_server::commands::network::QosLookupRecord;
use openxbdm_server::commands::network::SecurityAssociationRecord;
use openxbdm_server::commands::network::SocketRecord;
use openxbdm_server::commands::network::SystemVersion;
use openxbdm_server::commands::network::Table;
use openxbdm_server::commands::network::WsaError;
use openxbdm_server::commands::network::XnAddr;
use openxbdm_server::commands::network::Xnkid;
use openxbdm_server::commands::network::xhttpproxy::ProxyFlags;

fn session(server: &TestServer) -> common::RawSession {
    let mut session = server.raw();
    session.line();
    session
}

fn listening_socket() -> SocketRecord {
    SocketRecord {
        handle: 0x3eab_c000,
        owner_type: -1,
        flags: 0x0080_8000,
        address_family: 2,
        socket_type: 1,
        protocol: 6,
        local_address: 0,
        remote_address: 0xc0a8_0171,
        local_port: 0x02da,
        remote_port: 0xe3f3,
        tcp_state: 8,
    }
}

#[test]
fn getsockinfo_lists_the_snapshot() {
    let server = TestServer::start();
    server.host.lock().backend.network.sockets = vec![listening_socket(), SocketRecord::default()];
    let mut session = session(&server);
    assert_eq!(
        session.command("getsockinfo"),
        "202- multiline response follows"
    );
    assert_eq!(
        session.multiline(),
        [
            "handle=0x3eabc000 ownertype=-1 flags=0x00808000 addrfamily=2 socktype=1 protocol=6 localaddr=0x00000000 \
             remoteaddr=0xc0a80171 localport=0x02da remoteport=0xe3f3 tcpstate=8",
            "handle=0x00000000 ownertype=0 flags=0x00000000 addrfamily=0 socktype=0 protocol=0 localaddr=0x00000000 \
             remoteaddr=0x00000000 localport=0x0000 remoteport=0x0000 tcpstate=0",
        ]
    );
    assert!(server.host.lock().backend.network.snapshots.is_empty());
}

#[test]
fn getsockinfo_parses_with_the_client() {
    let server = TestServer::start();
    server.host.lock().backend.network.sockets = vec![listening_socket()];
    let sockets = run(async {
        let mut client = server.client().await;
        client.run(GetSocketInfo).await.unwrap()
    });
    assert_eq!(
        sockets,
        [SocketEntry {
            handle: 0x3eab_c000,
            owner_type: -1,
            flags: 0x0080_8000,
            addr_family: 2,
            socket_type: 1,
            protocol: 6,
            local_addr: 0,
            remote_addr: 0xc0a8_0171,
            local_port: 0x02da,
            remote_port: 0xe3f3,
            tcp_state: 8,
        }]
    );
}

#[test]
fn table_snapshot_failures() {
    let server = TestServer::start();
    let mut session = session(&server);
    server.host.lock().backend.network.unavailable = vec![Table::Sockets];
    assert_eq!(session.command("getsockinfo"), "414- access denied");
    server.host.lock().backend.network.exhausted = vec![Table::Keys];
    assert_eq!(session.command("getxnkeyinfo"), "428- out of memory");
    assert_eq!(
        session.command("getxnsecassocinfo"),
        "202- multiline response follows"
    );
    assert!(session.multiline().is_empty());
}

#[test]
fn xn_tables_require_the_system_version() {
    let server = TestServer::start();
    server.host.lock().backend.network.system_version = SystemVersion(0x200a_99ff);
    let mut session = session(&server);
    for command in ["getxnkeyinfo", "getxnqoslookupinfo", "getxnsecassocinfo"] {
        assert_eq!(session.command(command), "407- unknown command");
    }
    assert_eq!(
        session.command("getsockinfo"),
        "202- multiline response follows"
    );
}

#[test]
fn getxnkeyinfo_prints_the_key_identifier_in_upper_case() {
    let server = TestServer::start();
    server.host.lock().backend.network.keys = vec![KeyRecord {
        xnkid: Xnkid([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
        owner_type: 2,
        flags: 0x10,
        qos_data_size: 0x40,
        qos_bits_per_second: 0xffff_ffff,
    }];
    let mut session = session(&server);
    assert_eq!(
        session.command("getxnkeyinfo"),
        "202- multiline response follows"
    );
    assert_eq!(
        session.multiline(),
        [
            "xnkid=\"0123456789ABCDEF\" ownertype=2 flags=0x00000010 qosdatasize=64 qosbps=4294967295"
        ]
    );
}

fn xnaddr() -> XnAddr {
    let mut bytes = [0u8; 0x24];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = 0xa0 + index as u8;
    }
    XnAddr(bytes)
}

#[test]
fn getxnsecassocinfo_prints_each_association() {
    let server = TestServer::start();
    server.host.lock().backend.network.security_associations = vec![SecurityAssociationRecord {
        secure_address: 0x0102_0304,
        owner_type: 1,
        flags: 0x8000_0001,
        xnkid: Xnkid([0xfe; 8]),
        xnaddr: xnaddr(),
        service_id: -2,
        remote_address: 0xc0a8_0102,
        remote_port: 0x0c02,
        state: 3,
        nat_address: 0x0a00_0001,
        nat_port: 0x1234,
    }];
    let mut session = session(&server);
    assert_eq!(
        session.command("getxnsecassocinfo"),
        "202- multiline response follows"
    );
    assert_eq!(
        session.multiline(),
        [
            "secaddr=0x01020304 ownertype=1 flags=0x80000001 xnkid=\"FEFEFEFEFEFEFEFE\" \
             xnaddr=\"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3\" serviceid=-2 \
             remoteaddr=0xc0a80102 remoteport=0x0c02 state=3 nataddr=0x0a000001 natport=0x1234"
        ]
    );
}

#[test]
fn getxnqoslookupinfo_truncates_lines_to_the_monitor_buffer() {
    let server = TestServer::start();
    let lookup = QosLookupRecord {
        owner_type: i32::MIN,
        flags: u32::MAX,
        target_address: 0xc0a8_0101,
        target_port: 0x0c02,
        state: 0xff,
        retry: 0xff,
        secure_address: 0x0102_0304,
        probes_requested: u32::MAX,
        probes_sent: u32::MAX,
        probes_received: u32::MAX,
        data_received: u32::MAX,
        bits_per_second: u32::MAX,
        xnkid: Xnkid([0x11; 8]),
        xnaddr: xnaddr(),
    };
    server.host.lock().backend.network.qos_lookups = vec![lookup];
    let mut session = session(&server);
    assert_eq!(
        session.command("getxnqoslookupinfo"),
        "202- multiline response follows"
    );
    let full = "ownertype=-2147483648 flags=0xffffffff preq=4294967295 ptx=4294967295 prx=4294967295 \
                datarx=4294967295 bps=4294967295 targetaddr=0xc0a80101 targetport=0x0c02 state=255 retry=255 \
                secaddr=0x01020304 xnkid=\"1111111111111111\" \
                xnaddr=\"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3\"";
    assert_eq!(session.multiline(), [&full[..255]]);
}

#[test]
fn linkstate_reports_and_forces_the_link() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("linkstate"), "200- state=0x00000001");
    assert_eq!(
        session.command("linkstate disconnect"),
        "200- set, andflags=0x00000000 orflags=0x00010000 oldstate=0x00000001"
    );
    assert_eq!(session.command("linkstate"), "200- state=0x00010000");
    assert_eq!(
        session.command("linkstate setflags and=0xffff or=0x20"),
        "200- set, andflags=0x0000ffff orflags=0x00000020 oldstate=0x00010000"
    );
    assert_eq!(
        session.command("linkstate restore setflags"),
        "200- set, andflags=0xffffffff orflags=0x00000000 oldstate=0x00000021"
    );
    assert_eq!(
        server.host.lock().backend.network.link_flags,
        LinkFlags::RESTORE
    );
}

#[test]
fn linkstate_errors() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("linkstate setflags and=1"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("linkstate setflags or=1"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("linkstate setflags and=1x or=2"),
        "423- bad parameter"
    );
    server.host.lock().backend.network.link_error = Some(WsaError::INVALID_ARGUMENT);
    assert_eq!(session.command("linkstate restore"), "407- err=10022");
    server.host.lock().backend.network.link_error = WsaError::new(10050);
    assert_eq!(session.command("linkstate disconnect"), "400- err=10050");
}

#[test]
fn nicstats_prints_counters() {
    let server = TestServer::start();
    server.host.lock().backend.network.nic_stats = NicStats {
        transmitted_bytes: 0x1_0000_00ab,
        received_unicast_bytes: 0,
        received_unicast1_bytes: 1,
        received_unicast2_bytes: 2,
        received_multicast_bytes: 3,
        received_broadcast_bytes: 0xffff_ffff_ffff_ffff,
        transmitted_frames: 10,
        received_unicast_frames: 11,
        received_unicast1_frames: 12,
        received_unicast2_frames: 13,
        received_multicast_frames: 14,
        received_broadcast_frames: 15,
        transmit_underrun_errors: 16,
        transmit_other_errors: 17,
        receive_frame_errors: 18,
        receive_crc_errors: 19,
        receive_other_errors: 4_000_000_000,
    };
    let mut session = session(&server);
    let expected = "200- tb=0q1000000ab rub=0q0 ru1b=0q1 ru2b=0q2 rmb=0q3 rbb=0qffffffffffffffff tf=10 ruf=11 \
                    ru1f=12 ru2f=13 rmf=14 rbf=15 tue=16 toe=17 rfe=18 rce=19 roe=4000000000";
    assert_eq!(session.command("nicstats"), expected);
    assert_eq!(session.command("nicstats deviceflags=2"), expected);
    assert_eq!(session.command("nicstats deviceflags=x"), expected);
    assert_eq!(
        server.host.lock().backend.network.nic_queries,
        [u32::MAX, 2, u32::MAX]
    );
}

/// The observable fields of a proxy entry.
#[derive(Debug, PartialEq, Eq)]
struct Proxy {
    flags: u32,
    name: Option<Vec<u8>>,
    port: u32,
    certificate: Vec<u8>,
}

fn proxy(flags: u32, name: Option<&[u8]>, port: u32, certificate: &[u8]) -> Proxy {
    Proxy {
        flags,
        name: name.map(<[u8]>::to_vec),
        port,
        certificate: certificate.to_vec(),
    }
}

fn proxies(server: &TestServer) -> Vec<Proxy> {
    let host = server.host.lock();
    host.backend
        .network
        .xhttpproxy
        .entries
        .iter()
        .map(|entry| Proxy {
            flags: entry.flags.0,
            name: entry.name.clone(),
            port: entry.port,
            certificate: entry.certificate.clone(),
        })
        .collect()
}

#[test]
fn xhttpproxy_replaces_the_proxy_of_each_scope() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("xhttpproxy"), "200- OK");
    assert_eq!(
        session.command("xhttpproxy name=proxy port=8080"),
        "200-  applied"
    );
    assert_eq!(
        session.command("xhttpproxy name=sysproxy port=3128 sysonly force"),
        "200-  applied"
    );
    assert_eq!(
        session.command("xhttpproxy name=other port=81 temp"),
        "200- cleared applied"
    );
    assert_eq!(
        proxies(&server),
        [
            proxy(
                ProxyFlags::SYS | ProxyFlags::SYS_ONLY | ProxyFlags::ACTIVE | ProxyFlags::FORCE,
                Some(b"sysproxy"),
                3128,
                &[]
            ),
            proxy(
                ProxyFlags::ACTIVE | ProxyFlags::TEMP,
                Some(b"other"),
                81,
                &[]
            ),
        ]
    );
    assert_eq!(session.command("xhttpproxy sys"), "200- cleared");
    assert_eq!(session.command("xhttpproxy force"), "200- cleared applied");
    assert_eq!(
        proxies(&server),
        [proxy(ProxyFlags::ACTIVE | ProxyFlags::FORCE, None, 0, &[])]
    );
    assert_eq!(
        session.command("xhttpproxy name=\"\" port=0 certsize=4"),
        "200- cleared"
    );
    assert!(proxies(&server).is_empty());
}

#[test]
fn xhttpproxy_validates_name_and_port() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("xhttpproxy name=proxy"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("xhttpproxy name=proxy port=0x10000"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("xhttpproxy name=\"\" port=1"),
        "423- bad parameter"
    );
    // `port` and `certsize` are not read without `name`.
    assert_eq!(session.command("xhttpproxy port=1 certsize=2"), "200- OK");
    server
        .host
        .lock()
        .backend
        .network
        .xhttpproxy
        .fail_allocation = true;
    assert_eq!(
        session.command("xhttpproxy name=proxy port=1"),
        "428- err=0x82da001c "
    );
    assert!(proxies(&server).is_empty());
}

#[test]
fn xhttpproxy_decodes_inline_certificates() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("xhttpproxy name=p port=1 certsize=3 cert=\"00aBFf\""),
        "200-  applied"
    );
    assert_eq!(proxies(&server)[0].certificate, [0x00, 0xab, 0xff]);
    for command in [
        "xhttpproxy name=p port=1 certsize=3 cert=00ab",
        "xhttpproxy name=p port=1 certsize=3 cert=00abffee",
        "xhttpproxy name=p port=1 certsize=3 cert=00abf",
        "xhttpproxy name=p port=1 certsize=3 cert=00abfg",
    ] {
        assert_eq!(
            session.command(command),
            "407- err=0x82da0007 cleared",
            "{command}"
        );
        assert_eq!(session.command("xhttpproxy name=p port=1"), "200-  applied");
    }
    // The decoder stops at a space; `cert` without certsize is ignored.
    assert_eq!(
        session.command("xhttpproxy name=p port=1 cert=zz"),
        "200- cleared applied"
    );
    assert_eq!(
        session.command("xhttpproxy name=p port=1 certsize=1 cert=ab cd"),
        "200- cleared applied"
    );
}

#[test]
fn xhttpproxy_receives_an_uploaded_certificate() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("xhttpproxy name=p port=443 certsize=4 sys"),
        "204-  applying"
    );
    {
        let entries = proxies(&server);
        assert_eq!(
            entries[0].flags & ProxyFlags::CERTIFICATE_PENDING,
            ProxyFlags::CERTIFICATE_PENDING
        );
    }
    session.stream.write_all(&[1, 2]).unwrap();
    session.stream.write_all(&[3, 4]).unwrap();
    assert_eq!(session.line(), "200- OK");
    assert_eq!(
        proxies(&server),
        [proxy(
            ProxyFlags::SYS | ProxyFlags::ACTIVE,
            Some(b"p"),
            443,
            &[1, 2, 3, 4]
        )]
    );
    let host = server.host.lock();
    assert_eq!(host.backend.network.xhttpproxy.entries[0].references, 1);
}

#[test]
fn xhttpproxy_drops_an_entry_whose_upload_is_cut_short() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("xhttpproxy name=p port=443 certsize=4"),
        "204-  applying"
    );
    session.stream.write_all(&[1]).unwrap();
    session.stream.shutdown(std::net::Shutdown::Both).unwrap();
    for _ in 0..100 {
        if proxies(&server).is_empty() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("entry kept: {:?}", proxies(&server));
}

#[test]
fn title_exit_drops_temporary_title_proxies() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("xhttpproxy name=t port=1 temp"),
        "200-  applied"
    );
    assert_eq!(
        session.command("xhttpproxy name=s port=2 sys temp"),
        "200-  applied"
    );
    terminate_title(&server);
    assert_eq!(
        proxies(&server),
        [proxy(
            ProxyFlags::SYS | ProxyFlags::ACTIVE | ProxyFlags::TEMP,
            Some(b"s"),
            2,
            &[]
        )]
    );
}

#[test]
fn settings_file_round_trips_addresses_and_proxies() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend.system.ini_override = Some(
            b"xhttpproxy sys name=u port=3 certsize=4\r\nstaticip use=1, addr=0x0a000001\r\nsubnet addr=0xffffff00\r\ngateway addr=0x0a0000fe\r\n\
              xhttpproxy sysonly name=\"p\" port=8080 force certsize=2 cert=ABcd\r\n\
              xhttpproxy name=t port=1 temp\r\n"
                .to_vec(),
        );
        let openxbdm_server_host::Host {
            server,
            backend,
            network,
        } = &mut *host;
        openxbdm_server::commands::system::load_settings(server, backend, network);
    }
    let mut session = session(&server);
    assert_eq!(
        session.command("xhttpproxy name=pending port=2 certsize=1"),
        "204- cleared applying"
    );
    session.stream.write_all(&[0x5a]).unwrap();
    assert_eq!(session.line(), "200- OK");
    let settings = server.host.lock().backend.system.settings.clone().unwrap();
    let settings = String::from_utf8(settings).unwrap();
    let lines: Vec<&str> = settings.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.starts_with("staticip"))
        .unwrap();
    assert_eq!(
        lines[start..start + 3],
        [
            "staticip use=1, addr=0x0a000001",
            "subnet addr=0xffffff00",
            "gateway addr=0x0a0000fe"
        ]
    );
    let proxies: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| line.starts_with("xhttpproxy"))
        .collect();
    assert_eq!(
        proxies,
        [
            "xhttpproxy sysonly name=\"p\" port=8080 force certsize=2 cert=ABCD",
            "xhttpproxy name=\"pending\" port=2 certsize=1 cert=5A",
        ]
    );
}

#[test]
fn settings_file_writes_unnamed_proxies_and_skips_temporary_ones() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        let openxbdm_server_host::Host {
            server,
            backend,
            network,
        } = &mut *host;
        openxbdm_server::commands::system::load_settings(server, backend, network);
    }
    let mut session = session(&server);
    assert_eq!(session.command("xhttpproxy sys force"), "200-  applied");
    assert_eq!(
        session.command("xhttpproxy force name=n port=5 temp"),
        "200-  applied"
    );
    let settings = server.host.lock().backend.system.settings.clone().unwrap();
    let settings = String::from_utf8(settings).unwrap();
    let proxies: Vec<&str> = settings
        .lines()
        .filter(|line| line.starts_with("xhttpproxy"))
        .collect();
    assert_eq!(proxies, ["xhttpproxy sys force"]);
}

fn terminate_title(server: &TestServer) {
    let mut host = server.host.lock();
    let openxbdm_server_host::Host {
        server,
        backend,
        network,
    } = &mut *host;
    server.title_terminated(backend, network);
}

#[test]
fn title_exit_stops_a_capture_unless_it_is_persistent() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command(r"netcap start file=e:\title.cap"),
        "200- started"
    );
    terminate_title(&server);
    assert!(server.host.lock().backend.network.netcap.capture.is_none());
    assert_eq!(session.command("netcap stop"), "435- ");

    assert_eq!(
        session.command(r"netcap start file=e:\kept.cap flags=8"),
        "200- started"
    );
    terminate_title(&server);
    assert!(server.host.lock().backend.network.netcap.capture.is_some());
    assert_eq!(session.command("netcap stop"), "200- stopped frames=0");
}
