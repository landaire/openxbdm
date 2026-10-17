//! Trace texts the `verbose` mask enables (stock 0x91f9fef4).

mod common;

use std::io::Write;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::processors::ProcessorFlags;
use openxbdm_server_host::Host;
use openxbdm_server_host::backend::console::SERVER_THREAD;

use common::RawSession;
use common::TestServer;

/// Object name of `e:\netsim.ini`.
const NETSIM_FILE: &str = "\\Device\\Harddisk0\\Partition1\\DEVKIT\\netsim.ini";

fn session(server: &TestServer) -> RawSession {
    let mut session = server.raw();
    assert_eq!(session.line(), "201- connected");
    session
}

/// Debug output with the given prefix.
fn traced(server: &TestServer, prefix: &str) -> Vec<String> {
    let host = server.host.lock();
    host.backend
        .debug_output
        .iter()
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .filter(|line| line.starts_with(prefix))
        .collect()
}

fn thread_line(text: &str) -> String {
    format!("XBDM(thr=0x{SERVER_THREAD:08x}): {text}\n")
}

#[test]
fn command_and_status_lines() {
    let server = TestServer::start();
    let mut session = session(&server);

    // The mask is set by the handler, so the command line itself is not
    // traced but its status line is.
    assert_eq!(session.command("verbose level=1"), "200- OK");
    assert_eq!(session.command("bogus x"), "407- unknown command");
    assert_eq!(session.command("dmversion"), "200- 2.0.21256.0");
    session.stream.write_all(&[b'a'; 0x200]).unwrap();
    assert_eq!(session.command(""), "446- line too long");
    assert_eq!(
        traced(&server, "XBDM("),
        [
            thread_line("R=200- OK"),
            thread_line("0:bogus x"),
            thread_line("R=407- unknown command"),
            thread_line("0:dmversion"),
            thread_line("R=200- 2.0.21256.0"),
            thread_line("R=446- line too long"),
        ]
    );
}

#[test]
fn connection_index_follows_the_slot() {
    let server = TestServer::start();
    let mut first = session(&server);
    let mut second = session(&server);
    assert_eq!(first.command("verbose level=1"), "200- OK");
    assert_eq!(second.command("dbgname"), first.command("dbgname"));
    let lines = traced(&server, "XBDM(");
    assert!(lines.contains(&thread_line("1:dbgname")), "{lines:?}");
    assert!(lines.contains(&thread_line("0:dbgname")), "{lines:?}");
}

#[test]
fn binary_receive_counts() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("verbose level=2"), "200- OK");

    // Bytes that arrive with the command line are taken from the line
    // buffer first; the rest comes from the socket.
    session
        .stream
        .write_all(b"sendfile name=e:\\t length=4\r\nab")
        .unwrap();
    assert_eq!(session.line(), "204- send binary data");
    session.stream.write_all(b"cd").unwrap();
    assert_eq!(session.line(), "200- OK");
    assert_eq!(
        traced(&server, "XBDM("),
        [
            thread_line("BR(buffer): 2 of 4 bytes"),
            thread_line("BR(recv): 2 of 2 bytes")
        ]
    );
}

#[test]
fn upload_completion_status_line() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("verbose level=1"), "200- OK");
    assert_eq!(
        session.command("sendfile name=e:\\t length=2"),
        "204- send binary data"
    );
    session.stream.write_all(b"ab").unwrap();
    assert_eq!(session.line(), "200- OK");
    assert_eq!(
        traced(&server, "XBDM(")[1..],
        [
            thread_line("0:sendfile name=e:\\t length=2"),
            thread_line("R=204- send binary data"),
            thread_line("R=200- OK"),
        ]
    );
}

#[test]
fn title_processor_hand_off_traces_the_line_twice() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .register_processor(
            b"ttl",
            Some(Box::new(|_, _| Hresult::OK)),
            ProcessorFlags::TITLE,
        )
        .unwrap();
    let mut session = session(&server);
    assert_eq!(session.command("verbose level=1"), "200- OK");
    assert_eq!(session.command("ttl!a"), "200- OK");
    assert_eq!(session.command("ttl!b"), "200- OK");
    assert_eq!(
        traced(&server, "XBDM(")[1..],
        [
            thread_line("0:ttl!a"),
            thread_line("0:ttl!a"),
            thread_line("R=200- OK"),
            thread_line("0:ttl!b"),
            thread_line("R=200- OK"),
        ]
    );
}

#[test]
fn drive_path_translation() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("verbose level=8"), "200- OK");
    assert_eq!(session.command("mkdir name=e:\\dir"), "200- OK");
    assert_eq!(
        traced(&server, "[xbdm] FFileNameToObName"),
        [
            "[xbdm] FFileNameToObName(sz='e:\\dir',...)\n",
            "[xbdm] FFileNameToObName - drive name in conversion table\n",
            "[xbdm] FFileNameToObName succeeded, osz='\\Device\\Harddisk0\\Partition1\\DEVKIT\\dir'\n",
        ]
    );
    server.host.lock().backend.debug_output.clear();
    session.command("mkdir name=dir");
    session.command("mkdir name=q:\\dir");
    assert_eq!(
        traced(&server, "[xbdm] FFileNameToObName"),
        [
            "[xbdm] FFileNameToObName(sz='dir',...)\n",
            "[xbdm] FFileNameToObName - not a drive path - failing\n",
            "[xbdm] FFileNameToObName(sz='q:\\dir',...)\n",
            "[xbdm] FFileNameToObName succeeded, osz='\\??\\Q:\\dir'\n",
        ]
    );
}

#[test]
fn settings_file_lines() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        let Host {
            server: core,
            backend,
            network,
        } = &mut *host;
        backend.debug_output.clear();
        for line in [
            &b"verbose level=5"[..],
            b"dbgname name=box",
            b"notify",
            b"",
            b"bogus",
        ] {
            core.execute_settings_line(line, backend, network);
        }
    }

    // The settings writer traces its own lines under the same bit.
    let lines: Vec<String> = traced(&server, "XBDM")
        .into_iter()
        .filter(|line| line.starts_with("XBDM: DoIniLine") || line.starts_with("XBDM("))
        .collect();
    assert_eq!(
        lines,
        [
            "XBDM: DoIniLine 'dbgname name=box'\n".to_owned(),
            thread_line("-1:dbgname name=box"),
            "XBDM: DoIniLine 'notify'\n".to_owned(),
            "XBDM: DoIniLine ''\n".to_owned(),
            "XBDM: DoIniLine 'bogus'\n".to_owned(),
            thread_line("-1:bogus"),
        ]
    );
}

#[test]
fn netsim_settings_file() {
    let server = TestServer::start();
    server.host.lock().backend.filesystem.write(
        NETSIM_FILE,
        b"[xbdm]\r\nnetsim insertq in cfg=100400000000\r\n",
    );
    let mut session = session(&server);
    assert_eq!(session.command("verbose level=4"), "200- OK");
    session.command("netsim insertq out cfg=100100000000");
    session.command("netsim removeq");
    session.command("netsim reload file=e:\\netsim.ini");
    assert_eq!(
        traced(&server, "XBDM: NetSim"),
        [
            "XBDM: NetSimWriteIniFile - No filename configured.\n".to_owned(),
            "XBDM: NetSimWriteIniFile - No filename configured.\n".to_owned(),
            // CR and LF each end a line.
            "XBDM: NetSimReadIniLine '[xbdm]'\n".to_owned(),
            "XBDM: NetSimReadIniLine ''\n".to_owned(),
            "XBDM: NetSimReadIniLine 'netsim insertq in cfg=100400000000'\n".to_owned(),
            "XBDM: NetSimReadIniLine processing command failed (0x82da0017)\n".to_owned(),
            "XBDM: NetSimReadIniLine ''\n".to_owned(),
            format!("XBDM: NetSimWriteIniFile - Starting to write \"{NETSIM_FILE}\".\n"),
            "XBDM: NetSimWriteIniFile - Done writing ini file.\n".to_owned(),
        ]
    );
}

#[test]
fn nothing_is_traced_with_the_bits_clear() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("verbose level=0x10"), "200- OK");
    assert_eq!(
        session.command("sendfile name=e:\\t length=2"),
        "204- send binary data"
    );
    session.stream.write_all(b"ab").unwrap();
    assert_eq!(session.line(), "200- OK");
    session.command("netsim insertq out cfg=100100000000");
    {
        let mut host = server.host.lock();
        let Host {
            server: core,
            backend,
            network,
        } = &mut *host;
        core.execute_settings_line(b"dbgname name=box", backend, network);
    }

    assert!(traced(&server, "XBDM").is_empty());
    assert!(traced(&server, "[xbdm] FFileNameToObName").is_empty());
}

#[test]
fn console_settings_write_precedes_the_status_line() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("verbose level=5"), "200- OK");
    server.host.lock().backend.debug_output.clear();
    assert_eq!(session.command("eventdefer set break"), "200-  break");
    let lines = traced(&server, "XBDM");
    let position = |text: &str| {
        lines
            .iter()
            .position(|line| line == text)
            .unwrap_or_else(|| panic!("{text}: {lines:?}"))
    };

    let done = position("XBDM: WriteIniFileImpl - Done writing ini file...\n");
    assert!(position("XBDM: WriteIniFileImpl - entry\n") < done);
    assert!(done < position(&thread_line("R=200-  break")));
}
