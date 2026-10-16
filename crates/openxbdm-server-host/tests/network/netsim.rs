//! `netsim` over TCP.

use openxbdm_server::commands::network::LinkFlags;
use openxbdm_server::commands::network::SystemVersion;
use openxbdm_server::commands::network::WsaError;
use openxbdm_server::commands::network::netsim::ConfigMask;
use openxbdm_server::commands::network::netsim::NetsimError;
use openxbdm_server::commands::network::netsim::QueueConfig;
use openxbdm_server::commands::network::netsim::QueueKind;
use openxbdm_server::commands::network::netsim::QueueStats;
use openxbdm_server::commands::network::netsim::RedirectConfig;
use openxbdm_server_host::backend::network::netsim::Mock;

use crate::common::RawSession;
use crate::common::TestServer;

/// Object name of `e:\netsim.ini`.
const FILE: &str = "\\Device\\Harddisk0\\Partition1\\DEVKIT\\netsim.ini";
/// An unshaped queue.
const UNSHAPED: &str = "100100000000";
/// A link queue: limits 10 packets and 0x4000 bytes, 1 Mbit/s, loss
/// 500/100000, latency 20..40 ms.
const LINK: &str = "1002000000330000000A00004000000F4240000001F400140028";
/// A token bucket queue: 10 Mbit/s rate, 500 kbit/s tokens, 0x2000-byte
/// bucket that starts full.
const TOKEN_BUCKET: &str = "10030000008E009896800007A12000002000";
/// Redirect of 10.0.0.1:3128 to 10.0.0.2 with four sessions.
const REDIRECT: &str = "100A0000010C380A00000200000004";

fn session(server: &TestServer) -> RawSession {
    let mut session = server.raw();
    assert_eq!(session.line(), "201- connected");
    session
}

fn with_mock<T>(server: &TestServer, action: impl FnOnce(&mut Mock) -> T) -> T {
    action(&mut server.host.lock().backend.network.netsim)
}

fn file_bytes(server: &TestServer) -> Vec<u8> {
    server
        .host
        .lock()
        .backend
        .filesystem
        .read(FILE)
        .expect("netsim file")
        .to_vec()
}

fn seed_file(server: &TestServer, contents: &[u8]) {
    server.host.lock().backend.filesystem.write(FILE, contents);
}

#[test]
fn requires_the_system_version() {
    let server = TestServer::start();
    server.host.lock().backend.network.system_version = SystemVersion(0x2027_86ff);
    let mut session = session(&server);
    assert_eq!(session.command("netsim getnumqs"), "407- unknown command");
}

#[test]
fn counts_without_an_instance() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("netsim getnumqs"), "200- in=0 out=0");
    assert_eq!(session.command("netsim getnumipv4redirs"), "200- num=0");
    assert_eq!(
        session.command("netsim removeq"),
        "200- removed=0 inleft=0 outleft=0"
    );
    assert_eq!(
        session.command("netsim removeipv4redir"),
        "200- removed=0 left=0"
    );
    assert!(!with_mock(&server, |mock| mock.has_instance()));
}

#[test]
fn parameter_errors() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("netsim"), "423- bad parameter");
    assert_eq!(session.command("netsim bogus"), "423- bad parameter");
    assert_eq!(
        session.command(&format!("netsim insertq cfg={UNSHAPED}")),
        "423- bad parameter"
    );
    assert_eq!(
        session.command(&format!("netsim insertq in out cfg={UNSHAPED}")),
        "423- bad parameter"
    );
    assert_eq!(session.command("netsim insertq in"), "423- bad parameter");
    assert_eq!(
        session.command("netsim insertq in cfg="),
        "423- bad parameter"
    );
    assert_eq!(
        session.command(&format!("netsim modifyq in cfg={UNSHAPED}")),
        "423- bad parameter"
    );
    assert_eq!(session.command("netsim getqstats in"), "423- bad parameter");
    assert_eq!(session.command("netsim getq index=0"), "423- bad parameter");
    assert_eq!(
        session.command("netsim removeq index=0"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("netsim insertipv4redir"),
        "423- bad parameter"
    );
    // The hex value is decoded before the subcommand is chosen.
    assert_eq!(
        session.command("netsim insertq in cfg=1001000"),
        "407- unknown command"
    );
    assert_eq!(
        session.command("netsim bogus cfg=zz"),
        "407- unknown command"
    );
    assert!(!with_mock(&server, |mock| mock.has_instance()));
}

#[test]
fn insertq_orders_queues_and_reports_the_index() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command(&format!("netsim insertq in cfg={UNSHAPED}")),
        "200- index=0"
    );
    assert_eq!(
        session.command(&format!("netsim insertq in cfg=\"{LINK}\"")),
        "200- index=1"
    );
    assert_eq!(
        session.command(&format!("netsim insertq in index=0 cfg={TOKEN_BUCKET}")),
        "200- index=0"
    );
    assert_eq!(
        session.command(&format!("netsim insertq out index=-1 cfg={UNSHAPED}")),
        "200- index=0"
    );
    assert_eq!(session.command("netsim getnumqs"), "200- in=3 out=1");
    let kinds = with_mock(&server, |mock| {
        let instance = mock.instance.as_ref().unwrap();
        instance
            .inbound
            .iter()
            .map(|queue| queue.kind)
            .collect::<Vec<_>>()
    });
    assert_eq!(
        kinds,
        [QueueKind::TokenBucket, QueueKind::Unshaped, QueueKind::Link]
    );
    assert_eq!(with_mock(&server, |mock| mock.created), 1);
}

#[test]
fn insertq_rejections() {
    let server = TestServer::start();
    let mut session = session(&server);
    // A rejected blob destroys the instance it created.
    assert_eq!(
        session.command("netsim insertq in cfg=100400000000"),
        "423- err=0x82da0017"
    );
    assert_eq!(
        with_mock(&server, |mock| (
            mock.created,
            mock.destroyed,
            mock.has_instance()
        )),
        (1, 1, false)
    );
    // A link queue has no bucket; an unshaped queue takes no settings.
    assert_eq!(
        session.command("netsim insertq in cfg=10020000000800001000"),
        "423- err=0x82da0017"
    );
    assert_eq!(
        session.command("netsim insertq in cfg=1001000000020000FFFF"),
        "423- err=0x82da0017"
    );
    // A zero rate, a loss above 100000, and both bucket start bits.
    assert_eq!(
        session.command("netsim insertq in cfg=10020000000200000000"),
        "423- err=0x82da0017"
    );
    assert_eq!(
        session.command("netsim insertq in cfg=100200000010000186A1"),
        "423- err=0x82da0017"
    );
    assert_eq!(
        session.command("netsim insertq in cfg=100300000188000000FF"),
        "423- err=0x82da0017"
    );
    // Trailing classifier bytes.
    assert_eq!(
        session.command("netsim insertq in cfg=10010000000000"),
        "423- err=0x82da0017"
    );

    assert_eq!(
        session.command(&format!("netsim insertq out cfg={UNSHAPED}")),
        "200- index=0"
    );
    assert_eq!(
        session.command(&format!("netsim insertq out index=1 cfg={UNSHAPED}")),
        "423- err=0x82da0017"
    );
    assert!(with_mock(&server, |mock| mock.has_instance()));
}

#[test]
fn instance_creation_failures() {
    let server = TestServer::start();
    let mut session = session(&server);
    // ERROR_ACCESS_DENIED from the intercept registration.
    with_mock(&server, |mock| {
        mock.create_error = WsaError::new(5).map(NetsimError::Intercept)
    });
    assert_eq!(
        session.command(&format!("netsim insertq in cfg={UNSHAPED}")),
        "400- err=0x80070005"
    );
    with_mock(&server, |mock| {
        mock.create_error = Some(NetsimError::InterceptBusy)
    });
    assert_eq!(
        session.command(&format!("netsim insertipv4redir cfg={REDIRECT}")),
        "416- err=0x82da0010"
    );
    assert!(!with_mock(&server, |mock| mock.has_instance()));
}

#[test]
fn getq_reports_the_applied_settings() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("netsim getq in index=0"),
        "402- err=0x82da0002"
    );
    // Unknown mask bits are dropped; the reorder bit needs a latency.
    assert_eq!(
        session.command("netsim insertq in cfg=10020008004200989680"),
        "200- index=0"
    );
    assert_eq!(
        session.command("netsim getq in index=0"),
        "200- cfg=10020000000200989680"
    );
    assert_eq!(
        session.command(&format!("netsim insertq in cfg={LINK}")),
        "200- index=1"
    );
    assert_eq!(
        session.command("netsim getq in index=1"),
        format!("200- cfg={LINK}")
    );
    assert_eq!(
        session.command(&format!("netsim insertq in cfg={UNSHAPED}")),
        "200- index=2"
    );
    assert_eq!(
        session.command("netsim getq in index=2"),
        format!("200- cfg={UNSHAPED}")
    );
    assert_eq!(
        session.command("netsim getq in index=3"),
        "423- err=0x82da0017"
    );
    assert_eq!(
        session.command("netsim getq out index=0"),
        "423- err=0x82da0017"
    );
}

#[test]
fn modifyq_merges_settings() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("netsim modifyq out index=0 cfg=1000000000"),
        "402- err=0x82da0002"
    );
    assert_eq!(
        session.command(&format!("netsim insertq out cfg={TOKEN_BUCKET}")),
        "200- index=0"
    );
    // The modify blob has no type byte.
    assert_eq!(
        session.command("netsim modifyq out index=0 cfg=10000000010000000500001000"),
        "200- OK"
    );
    assert_eq!(
        session.command("netsim getq out index=0"),
        "200- cfg=10030000008F0000000500001000009896800007A12000002000"
    );
    // A bucket depth without a start bit clears the stored start bit.
    assert_eq!(
        session.command("netsim modifyq out index=0 cfg=100000000800004000"),
        "200- OK"
    );
    let config = with_mock(&server, |mock| {
        mock.instance.as_ref().unwrap().outbound[0].config
    });
    assert_eq!(
        config,
        QueueConfig {
            mask: ConfigMask(0x0f),
            packet_limit: 5,
            byte_limit: 0x1000,
            rate: 10_000_000,
            token_rate: 500_000,
            bucket_depth: 0x4000,
            ..QueueConfig::default()
        }
    );
    assert_eq!(
        session.command("netsim modifyq out index=0 cfg=10000000100000000A"),
        "423- err=0x82da0017"
    );
    assert_eq!(
        session.command("netsim modifyq out index=1 cfg=1000000000"),
        "423- err=0x82da0017"
    );
    assert_eq!(
        session.command("netsim modifyq out index=0 cfg=100100000000"),
        "423- err=0x82da0017"
    );
}

#[test]
fn getqstats_prints_counters() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("netsim getqstats in index=0"),
        "402- err=0x82da0002"
    );
    assert_eq!(
        session.command(&format!("netsim insertq in cfg={LINK}")),
        "200- index=0"
    );
    with_mock(&server, |mock| {
        mock.instance.as_mut().unwrap().inbound[0].stats = QueueStats {
            total_packets: 5,
            total_bytes: 0x1_0000_0002,
            dropped_packets: 1,
            dropped_bytes: 0x40,
        };
    });
    assert_eq!(
        session.command("netsim getqstats in index=0"),
        "200- totalpkts=5 totalbytes=0q0000000100000002 droppkts=1 dropbytes=0q0000000000000040"
    );
    assert_eq!(
        session.command("netsim getqstats in index=1"),
        "423- err=0x82da0017"
    );
}

#[test]
fn removeq_releases_the_idle_instance() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("netsim removeq in index=0"),
        "402- err=0x82da0002"
    );
    for direction in ["in", "in", "out"] {
        session.command(&format!("netsim insertq {direction} cfg={UNSHAPED}"));
    }
    assert_eq!(
        session.command("netsim removeq in index=2"),
        "423- err=0x82da0017"
    );
    assert_eq!(
        session.command("netsim removeq in index=1"),
        "200- removed=1 inleft=1 outleft=1"
    );
    assert_eq!(
        session.command("netsim removeq out"),
        "200- removed=1 inleft=1 outleft=0"
    );
    assert!(with_mock(&server, |mock| mock.has_instance()));
    assert_eq!(
        session.command(&format!("netsim insertq out cfg={UNSHAPED}")),
        "200- index=0"
    );
    assert_eq!(
        session.command("netsim removeq"),
        "200- removed=2 inleft=0 outleft=0"
    );
    assert_eq!(
        with_mock(&server, |mock| (mock.destroyed, mock.has_instance())),
        (1, false)
    );
}

#[test]
fn redirects() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("netsim removeipv4redir index=0"),
        "402- err=0x82da0002"
    );
    assert_eq!(
        session.command(&format!("netsim insertipv4redir cfg={REDIRECT}")),
        "200- index=0"
    );
    assert_eq!(
        session.command(&format!("netsim insertipv4redir index=0 cfg={REDIRECT}")),
        "200- index=0"
    );
    assert_eq!(
        session.command(&format!("netsim insertipv4redir index=2 cfg={REDIRECT}")),
        "423- err=0x82da0017"
    );
    // A target without address and port, and too many sessions.
    assert_eq!(
        session.command("netsim insertipv4redir cfg=100A0000010C380000000000000004"),
        "423- err=0x82da0017"
    );
    assert_eq!(
        session.command("netsim insertipv4redir cfg=100A0000010C380A000002000001F5"),
        "423- err=0x82da0017"
    );
    assert_eq!(session.command("netsim getnumipv4redirs"), "200- num=2");
    assert_eq!(
        with_mock(&server, |mock| mock.instance.as_ref().unwrap().redirects[0]
            .config),
        RedirectConfig {
            match_address: [10, 0, 0, 1],
            match_port: 3128,
            target_address: [10, 0, 0, 2],
            target_port: 0,
            sessions: 4
        }
    );
    assert_eq!(
        session.command("netsim removeipv4redir index=2"),
        "423- err=0x82da0017"
    );
    assert_eq!(
        session.command("netsim removeipv4redir index=1"),
        "200- removed=1 left=1"
    );
    assert_eq!(
        session.command("netsim removeipv4redir"),
        "200- removed=1 left=0"
    );
    assert!(!with_mock(&server, |mock| mock.has_instance()));
}

#[test]
fn mutations_rewrite_the_configured_file() {
    let server = TestServer::start();
    seed_file(&server, b"");
    let mut session = session(&server);
    assert_eq!(
        session.command("netsim reload file=e:\\netsim.ini"),
        format!("200- file=\"{FILE}\"")
    );
    session.command(&format!("netsim insertq out cfg={UNSHAPED}"));
    session.command(&format!("netsim insertq in cfg={LINK}"));
    session.command(&format!("netsim insertipv4redir cfg={REDIRECT}"));
    let expected = format!(
        "[xbdm]\r\nnetsim insertq in cfg={LINK}\r\nnetsim insertq out cfg={UNSHAPED}\r\nnetsim insertipv4redir cfg={REDIRECT}\r\n"
    );
    assert_eq!(String::from_utf8(file_bytes(&server)).unwrap(), expected);
    // Releasing the instance leaves the header only.
    session.command("netsim removeq");
    session.command("netsim removeipv4redir");
    assert_eq!(file_bytes(&server), b"[xbdm]\r\n");
    // Failed mutations and queries leave the file alone.
    seed_file(&server, b"unchanged");
    session.command("netsim insertq in cfg=100400000000");
    session.command("netsim getnumqs");
    assert_eq!(file_bytes(&server), b"unchanged");
}

#[test]
fn reload_executes_netsim_and_linkstate_lines() {
    let server = TestServer::start();
    let contents = format!(
        "[xbdm]\r\nnetsim insertq in cfg={LINK}\r\nlinkstate disconnect\nnotify\r\n\r\nnetsim insertipv4redir cfg={REDIRECT}\r\n"
    );
    seed_file(&server, contents.as_bytes());
    let mut session = session(&server);
    session.command(&format!("netsim insertq out cfg={UNSHAPED}"));
    assert_eq!(
        session.command("netsim reload file=e:\\netsim.ini"),
        format!("200- file=\"{FILE}\"")
    );
    let instance = with_mock(&server, |mock| mock.instance.clone().unwrap());
    assert_eq!(instance.inbound.len(), 1);
    assert!(
        instance.outbound.is_empty(),
        "the previous instance is destroyed first"
    );
    assert_eq!(instance.redirects.len(), 1);
    assert_eq!(
        server.host.lock().backend.network.link_flags,
        LinkFlags::DISCONNECT
    );
    // Lines from the file do not rewrite it, and the stored name is reused.
    assert_eq!(String::from_utf8(file_bytes(&server)).unwrap(), contents);
    assert_eq!(
        session.command("netsim reload"),
        format!("200- file=\"{FILE}\"")
    );
    assert_eq!(session.command("netsim getnumqs"), "200- in=1 out=0");
}

#[test]
fn reload_drops_the_last_byte_of_an_unterminated_file() {
    let server = TestServer::start();
    seed_file(
        &server,
        format!("netsim insertq in cfg={UNSHAPED}0").as_bytes(),
    );
    let mut session = session(&server);
    assert_eq!(
        session.command("netsim reload file=e:\\netsim.ini"),
        format!("200- file=\"{FILE}\"")
    );
    assert_eq!(session.command("netsim getnumqs"), "200- in=1 out=0");
}

#[test]
fn reload_errors() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("netsim reload"), "412- file=\"\"");
    assert_eq!(
        session.command("netsim reload file=e:\\missing.ini"),
        "402- file=\"\\Device\\Harddisk0\\Partition1\\DEVKIT\\missing.ini\""
    );
    // A name that does not translate is stored as given.
    assert!(
        session
            .command("netsim reload file=netsim.ini")
            .ends_with("- file=\"netsim.ini\"")
    );
    server.host.lock().server.state.network.netsim.reloading = true;
    assert_eq!(session.command("netsim reload"), "400- ");
}

/// Classifier program: item UDP.DestinationPort (u16) compared with 53.
const PROGRAM: &str = "101001030908270000220009003535";
/// String.Length of a literal, little-endian with a one-byte string table.
const STRING_PROGRAM: &str = "13060403020361626312003e";
/// Its canonical form.
const STRING_PROGRAM_CANONICAL: &str = "10040403020361626312003E";
/// An item holding a string, which parses but cannot be serialized.
const STRING_ITEM_PROGRAM: &str = "101402010101017a120801002200";

#[test]
fn classifier_programs_are_stored_in_canonical_form() {
    let server = TestServer::start();
    seed_file(&server, b"");
    let mut session = session(&server);
    session.command("netsim reload file=e:\\netsim.ini");
    assert_eq!(
        session.command(&format!("netsim insertq in cfg={UNSHAPED}{STRING_PROGRAM}")),
        "200- index=0"
    );
    assert_eq!(
        session.command("netsim getq in index=0"),
        format!("200- cfg={UNSHAPED}{STRING_PROGRAM_CANONICAL}")
    );
    assert_eq!(
        session.command(&format!("netsim insertq out cfg={LINK}{PROGRAM}")),
        "200- index=0"
    );
    assert_eq!(
        session.command("netsim getq out index=0"),
        format!("200- cfg={LINK}{PROGRAM}")
    );
    assert_eq!(
        session.command(&format!("netsim insertipv4redir cfg={REDIRECT}{PROGRAM}")),
        "200- index=0"
    );
    let expected = format!(
        "[xbdm]\r\nnetsim insertq in cfg={UNSHAPED}{STRING_PROGRAM_CANONICAL}\r\nnetsim insertq out cfg={LINK}{PROGRAM}\r\nnetsim insertipv4redir cfg={REDIRECT}{PROGRAM}\r\n"
    );
    assert_eq!(String::from_utf8(file_bytes(&server)).unwrap(), expected);
}

#[test]
fn classifier_program_rejections() {
    let server = TestServer::start();
    let mut session = session(&server);
    // A constant result, a floating point literal, a function call.
    for program in ["10000102", "1000020c3f8000003e", "100003010124"] {
        assert_eq!(
            session.command(&format!("netsim insertq in cfg={UNSHAPED}{program}")),
            "423- err=0x82da0017"
        );
    }
    // 33 nodes exceed the stored copy.
    let chain = format!("10002101{}", "012d".repeat(16));
    assert_eq!(
        session.command(&format!("netsim insertq in cfg={UNSHAPED}{chain}")),
        "428- err=0x82da001c"
    );
    let chain = format!("10002001{}28", "012d".repeat(15));
    assert_eq!(
        session.command(&format!("netsim insertq in cfg={UNSHAPED}{chain}")),
        "200- index=0"
    );
    // IPv4.SourceAddress == 10.0.0.1: address literals are allowed.
    let address = "1010010301080b22000f0a00000135";
    assert_eq!(
        session.command(&format!("netsim insertq in cfg={UNSHAPED}{address}")),
        "200- index=1"
    );
    assert_eq!(
        session.command("netsim getq in index=1"),
        format!("200- cfg={UNSHAPED}{}", address.to_uppercase())
    );
    // The program is parsed before the settings are validated.
    let oversized = format!("10002101{}", "012d".repeat(16));
    assert_eq!(
        session.command(&format!(
            "netsim insertq in cfg=10020000000200000000{oversized}"
        )),
        "428- err=0x82da001c"
    );
    // A modify blob takes no program.
    assert_eq!(
        session.command(&format!(
            "netsim modifyq in index=0 cfg=1000000000{PROGRAM}"
        )),
        "423- err=0x82da0017"
    );
    assert_eq!(
        session.command(&format!("netsim insertipv4redir cfg={REDIRECT}10000102")),
        "423- err=0x82da0017"
    );
}

#[test]
fn string_items_block_serialization() {
    let server = TestServer::start();
    seed_file(&server, b"");
    let mut session = session(&server);
    session.command("netsim reload file=e:\\netsim.ini");
    session.command(&format!("netsim insertq in cfg={UNSHAPED}"));
    assert_eq!(
        session.command(&format!(
            "netsim insertq in cfg={UNSHAPED}{STRING_ITEM_PROGRAM}"
        )),
        "200- index=1"
    );
    session.command(&format!("netsim insertq in cfg={UNSHAPED}"));
    session.command(&format!("netsim insertq out cfg={UNSHAPED}"));
    assert_eq!(
        session.command("netsim getq in index=1"),
        "400- err=0x80070545"
    );
    // The settings file stops each list at the queue that fails.
    let expected = format!(
        "[xbdm]\r\nnetsim insertq in cfg={UNSHAPED}\r\nnetsim insertq out cfg={UNSHAPED}\r\n"
    );
    assert_eq!(String::from_utf8(file_bytes(&server)).unwrap(), expected);
}
