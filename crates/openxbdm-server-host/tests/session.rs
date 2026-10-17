//! Session commands, notification channels, and name discovery over TCP
//! and UDP.

mod common;

use std::io::Read;
use std::io::Write;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use common::RawSession;
use common::TestServer;
use common::run;
use openxbdm_client::commands::system::ExecutionState;
use openxbdm_client::commands::system::Notify;
use openxbdm_client::discovery::DiscoveryConfig;
use openxbdm_client::discovery::discover_all;
use openxbdm_client::discovery::find_by_name;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use openxbdm_core::status::xbdm_error;
use openxbdm_core::status::xbdm_success;
use openxbdm_server::ConnectionIndex;
use openxbdm_server::commands::session::FileEventId;
use openxbdm_server::commands::session::TellLogAreas;
use openxbdm_server::commands::session::debug_capture_print;
use openxbdm_server::processors::ProcessorFlags;
use openxbdm_server_host::Host;
use openxbdm_server_host::backend::session::RpcRegisters;

const DEVKIT: &str = "\\Device\\Harddisk0\\Partition1\\DEVKIT";

fn session(server: &TestServer) -> RawSession {
    let mut session = server.raw();
    assert_eq!(session.line(), "201- connected");
    session
}

/// Open a notification channel and check the monitor's reply sequence.
fn channel(server: &TestServer) -> RawSession {
    let mut session = session(server);
    assert_eq!(session.command("notify"), "205- now a notification channel");
    assert_eq!(session.line(), "execution started");
    session
}

fn read_exact(session: &mut RawSession, count: usize) -> Vec<u8> {
    let mut bytes = vec![0; count];
    session.reader.read_exact(&mut bytes).unwrap();
    bytes
}

#[test]
fn notify_turns_the_connection_into_a_channel() {
    let server = TestServer::start();
    run(async {
        let (mut events, execution) = server
            .client()
            .await
            .into_notification_channel(Notify::default())
            .await
            .unwrap();
        assert_eq!(execution, ExecutionState::Started);
        server
            .host
            .lock()
            .backend
            .post_notification(b"PIX!test text");
        assert_eq!(events.next_notification().await.unwrap(), "PIX!test text");
    });
}

#[test]
fn a_seventeenth_channel_sends_null_to_every_channel_and_fails() {
    let server = TestServer::start();
    let mut channels: Vec<RawSession> = (0..16).map(|_| channel(&server)).collect();
    let mut session = session(&server);
    assert_eq!(
        session.command("notifyport"),
        "400- notification limit exceeded"
    );
    for channel in &mut channels {
        assert_eq!(channel.line(), "null");
    }
    // The failed connection stays a command connection.
    assert_eq!(session.command("srvproc num=2"), "200- prev=0");
}

#[test]
fn notifyat_connects_sends_the_state_and_drops_on_request() {
    let server = TestServer::start();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut session = session(&server);
    // The groups of `addr=` name the address bytes in reverse order.
    assert_eq!(
        session.command(&format!("notifyat port={port} addr=1.0.0.127")),
        "200- OK"
    );
    let (mut target, _) = listener.accept().unwrap();
    target
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut line = [0u8; 19];
    target.read_exact(&mut line).unwrap();
    assert_eq!(&line, b"execution started\r\n");

    let settings =
        String::from_utf8(server.host.lock().backend.system.settings.clone().unwrap()).unwrap();
    assert!(
        settings.contains(&format!("notifyat addr=1.0.0.127 port={port}\r\n")),
        "{settings}"
    );

    assert_eq!(
        session.command(&format!("notifyat port={port} addr=1.0.0.127 drop")),
        "200- OK"
    );
    let mut rest = Vec::new();
    target.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
}

#[test]
fn notifyat_requires_a_port() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("notifyat addr=1.0.0.127"), "400- ");
}

#[test]
fn dedicate_moves_the_connection_between_contexts() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        let echo = Box::new(
            |line: &[u8], text: &mut openxbdm_server::text::ResponseText| {
                text.set_bytes(line);
                Hresult::OK
            },
        );
        host.backend
            .register_processor(b"ttl", Some(echo), ProcessorFlags::TITLE)
            .unwrap();
    }
    let mut session = session(&server);
    assert_eq!(session.command("dedicate"), "400- missing handler");
    assert_eq!(
        session.command("dedicate handler=none"),
        "402- file not found"
    );
    assert_eq!(
        session.command("dedicate handler=TTL"),
        "205- connection dedicated"
    );
    assert_eq!(session.command("ttl!echo"), "200- ttl!echo");
    assert_eq!(
        session.command("srvproc"),
        "422- dedicated connection required"
    );
    assert_eq!(
        session.command("dedicate global"),
        "205- connection dedicated"
    );
    assert_eq!(session.command("srvproc num=1"), "200- prev=0");
}

#[test]
fn processor_answering_205_takes_the_connection() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend
            .register_processor(
                b"own",
                Some(Box::new(|_, _| Hresult::DEDICATED)),
                ProcessorFlags::TITLE,
            )
            .unwrap();
        host.backend
            .register_processor(
                b"sys",
                Some(Box::new(|_, _| Hresult::OK)),
                ProcessorFlags::empty(),
            )
            .unwrap();
    }
    let mut session = session(&server);
    assert_eq!(session.command("sys!x"), "200- OK");
    assert_eq!(session.command("own!take"), "205- connection dedicated");
    assert_eq!(
        session.command("sys!x"),
        "422- dedicated connection required"
    );
    assert_eq!(session.command("own!x"), "205- connection dedicated");
}

#[test]
fn status_lines_follow_the_line_builder() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend
            .register_processor(
                b"low",
                Some(Box::new(|_, _| xbdm_success(0x64))),
                ProcessorFlags::empty(),
            )
            .unwrap();
        host.backend
            .register_processor(
                b"mid",
                Some(Box::new(|_, _| xbdm_success(0xc8))),
                ProcessorFlags::empty(),
            )
            .unwrap();
        host.backend
            .register_processor(
                b"bad",
                Some(Box::new(|_, _| xbdm_error(0x96))),
                ProcessorFlags::empty(),
            )
            .unwrap();
        host.backend
            .register_processor(
                b"big",
                Some(Box::new(|_, _| xbdm_success(0x100))),
                ProcessorFlags::empty(),
            )
            .unwrap();
    }
    let mut session = session(&server);
    assert_eq!(session.command("low!x"), "2:0- ");
    assert_eq!(session.command("mid!x"), "2D0- ");
    assert_eq!(session.command("bad!x"), "4?0- ");
    assert_eq!(session.command("big!x"), "400- ");
}

#[test]
fn transfer_without_continuation_keeps_the_original_text() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend
            .register_processor(
                b"multi",
                Some(Box::new(|_, _| Hresult::MULTILINE)),
                ProcessorFlags::empty(),
            )
            .unwrap();
        host.backend
            .register_processor(
                b"send",
                Some(Box::new(|_, _| Hresult::SEND_BINARY)),
                ProcessorFlags::empty(),
            )
            .unwrap();
    }
    let mut session = session(&server);
    assert_eq!(
        session.command("multi!x"),
        "400- multiline response follows"
    );
    assert_eq!(session.command("send!x"), "400- send binary data");
    assert_eq!(session.command("srvproc num=1"), "200- prev=0");
}

#[test]
fn processor_calls_on_other_threads_reply_when_they_end() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend.defer_processor_calls = true;
        let echo = Box::new(
            |line: &[u8], text: &mut openxbdm_server::text::ResponseText| {
                text.set_bytes(line);
                Hresult::OK
            },
        );
        host.backend
            .register_processor(b"ttl", Some(echo), ProcessorFlags::TITLE)
            .unwrap();
    }
    let mut title = session(&server);
    title.send("ttl!echo");
    server.wait_until(|host| host.server.awaits_processor(ConnectionIndex(0)));
    let mut other = session(&server);
    assert_eq!(other.command("srvproc num=1"), "200- prev=0");
    {
        let mut host = server.host.lock();
        let Host {
            server,
            backend,
            network,
        } = &mut *host;
        server.complete_processor_call(ConnectionIndex(0), backend, network);
    }
    assert_eq!(title.line(), "200- ttl!echo");
    assert_eq!(
        title.command("srvproc"),
        "422- dedicated connection required"
    );
}

#[test]
fn title_termination_closes_title_connections_and_processors() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        let ok = || Box::new(|_: &[u8], _: &mut openxbdm_server::text::ResponseText| Hresult::OK);
        host.backend
            .register_processor(b"ttl", Some(ok()), ProcessorFlags::TITLE)
            .unwrap();
        let dedicated = ProcessorFlags::TITLE.union(ProcessorFlags::DEDICATED_THREAD);
        host.backend
            .register_processor(b"dttl", Some(ok()), dedicated)
            .unwrap();
        host.backend
            .register_processor(b"dsys", Some(ok()), ProcessorFlags::DEDICATED_THREAD)
            .unwrap();
    }
    let mut shared = session(&server);
    assert_eq!(shared.command("ttl!x"), "200- OK");
    let mut title_thread = session(&server);
    assert_eq!(
        title_thread.command("dedicate handler=dttl"),
        "205- connection dedicated"
    );
    let mut system_thread = session(&server);
    assert_eq!(
        system_thread.command("dedicate handler=dsys"),
        "205- connection dedicated"
    );
    let mut main = session(&server);
    {
        let mut host = server.host.lock();
        let Host {
            server,
            backend,
            network,
        } = &mut *host;
        server.title_terminated(backend, network);
    }
    for closed in [&mut shared, &mut title_thread] {
        let mut rest = Vec::new();
        closed.reader.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }
    assert_eq!(system_thread.command("dsys!x"), "200- OK");
    assert_eq!(main.command("ttl!x"), "407- unknown command");
    assert_eq!(
        main.command("dedicate handler=dsys"),
        "205- connection dedicated"
    );
}

#[test]
fn dbgprint_streams_captured_records() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("dbgprint"),
        "400- Debug capture not started (use 'start' option to start capture)"
    );
    assert_eq!(
        session.command("dbgprint start"),
        "400- Debug capture not started (use 'start' option to start capture)"
    );
    assert_eq!(session.command("dbgprint start="), "200- OK");
    assert_eq!(
        session.command("dbgprint start=1"),
        "400- Debug capture already started"
    );
    {
        let mut host = server.host.lock();
        let Host {
            server, backend, ..
        } = &mut *host;
        debug_capture_print(
            &mut server.state,
            backend,
            b"XBDM: Updating CD-ROM driver.\n",
        );
        debug_capture_print(&mut server.state, backend, b"XBDM: Updated Channel ISR.\n");
    }
    assert_eq!(
        session.command("dbgprint"),
        "202- Debug print strings follow"
    );
    assert_eq!(
        session.multiline(),
        [
            "XBDM: Updating CD-ROM driver.",
            "XBDM: Updated Channel ISR."
        ]
    );
    assert_eq!(
        session.command("dbgprint"),
        "202- Debug print strings follow"
    );
    assert!(session.multiline().is_empty());
    assert_eq!(
        session.command("dbgprint reset=1"),
        "202- Debug print strings follow"
    );
    assert_eq!(session.multiline().len(), 2);
    assert_eq!(session.command("dbgprint stop=1"), "200- OK");
    assert_eq!(
        session.command("dbgprint"),
        "400- Debug capture not started (use 'start' option to start capture)"
    );

    server.host.lock().backend.session.exhausted = true;
    assert_eq!(session.command("dbgprint start="), "428- out of memory");
}

#[test]
fn fileevent_announces_start_and_stop_after_posted_texts() {
    let server = TestServer::start();
    let mut channel = channel(&server);
    let mut session = session(&server);
    assert_eq!(session.command("fileevent"), "400- ");
    assert_eq!(session.command("fileevent advise"), "200- OK");
    assert_eq!(channel.line(), "XBDMFE!Start 0x00000001");
    assert!(server.host.lock().backend.session.file_events);
    {
        let mut host = server.host.lock();
        host.backend.post_notification(b"XBDMFE!Begin 0x00000002");
        host.backend.post_notification(b"XBDMFE!End 0x00000002");
    }
    assert_eq!(session.command("fileevent unadvise"), "200- OK");
    assert_eq!(channel.line(), "XBDMFE!Begin 0x00000002");
    assert_eq!(channel.line(), "XBDMFE!End 0x00000002");
    assert_eq!(channel.line(), "XBDMFE!Stop 0x00000002");
    assert!(!server.host.lock().backend.session.file_events);
}

#[test]
fn fileevent_sequence_wraps_to_zero() {
    let server = TestServer::start();
    let mut channel = channel(&server);
    let mut session = session(&server);
    server.host.lock().backend.session.file_event_id = FileEventId(0xffff_fffe);
    assert_eq!(session.command("fileevent advise"), "200- OK");
    assert_eq!(channel.line(), "XBDMFE!Start 0xffffffff");
    assert_eq!(session.command("fileevent unadvise"), "200- OK");
    assert_eq!(channel.line(), "XBDMFE!Stop 0x00000000");
    assert_eq!(session.command("fileevent advise"), "200- OK");
    assert_eq!(channel.line(), "XBDMFE!Start 0x00000001");
}

#[test]
fn srvproc_reports_and_moves_the_server_processor() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("srvproc num=4"), "200- prev=0");
    assert_eq!(session.command("srvproc"), "200- prev=4");
    assert_eq!(server.host.lock().backend.session.processor, 2);
    assert_eq!(session.command("srvproc num=6"), "407- unknown command");
    assert_eq!(server.host.lock().backend.session.processor, 2);
}

#[test]
fn spew_writes_the_line_to_the_debug_output() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("spew some text"), "200- OK");
    assert!(
        server
            .host
            .lock()
            .backend
            .debug_output
            .iter()
            .any(|line| line == b"SPEW: spew some text\n")
    );
}

/// A call buffer: result, return, last error request, flags, counts,
/// module, target, then the arguments.
fn call_buffer(
    module: u64,
    target: u64,
    integers: &[u64],
    doubles: &[f64],
    size: usize,
) -> Vec<u8> {
    let mut buffer = Vec::new();
    for word in [
        0,
        0,
        1,
        0,
        integers.len() as u64,
        doubles.len() as u64,
        module,
        target,
    ] {
        buffer.extend_from_slice(&word.to_be_bytes());
    }
    for integer in integers {
        buffer.extend_from_slice(&integer.to_be_bytes());
    }
    for double in doubles {
        buffer.extend_from_slice(&double.to_bits().to_be_bytes());
    }
    buffer.resize(size, 0);
    buffer
}

fn qword(buffer: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(buffer[offset..offset + 8].try_into().unwrap())
}

#[test]
fn rpc_checks_the_version_and_parameters() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("rpc system buf_size=8"),
        "200- error=Version is not specified, expecting major version 4"
    );
    assert_eq!(
        session.command("rpc version=0xffffffff system buf_size=8"),
        "200- error=Version mismatch, expected 4 but got -1"
    );
    assert_eq!(
        session.command("rpc version=4 buf_size=8"),
        "423- bad parameter"
    );
    assert_eq!(session.command("rpc version=4 title"), "423- bad parameter");
    assert_eq!(
        session.command("rpc version=4 title buf_size=0x1000001"),
        "428- out of memory"
    );
    server.host.lock().backend.session.rpc_exhausted = true;
    assert_eq!(
        session.command("rpc version=4 title buf_size=8"),
        "428- out of memory"
    );
}

#[test]
fn rpc_runs_on_its_own_thread_and_returns_the_buffer() {
    const SIZE: usize = 0x50;
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend.session.rpc_last_error = 0x57;
        host.backend.session.rpc_functions.insert(
            0x8200_1000,
            Box::new(|arguments| RpcRegisters {
                r3: arguments.integers.iter().sum(),
                f1: 0.0,
            }),
        );
    }
    let mut session = session(&server);
    assert_eq!(
        session.command(&format!("rpc version=4 title buf_size={SIZE}")),
        "204- buf_addr=4A000068"
    );
    session
        .stream
        .write_all(&call_buffer(0, 0x8200_1000, &[5, 7], &[], SIZE))
        .unwrap();
    assert_eq!(session.line(), "203- binary response follows");
    assert_eq!(read_exact(&mut session, 8), [0; 8]);
    let buffer = read_exact(&mut session, SIZE);
    assert_eq!(qword(&buffer, 0), 0);
    assert_eq!(qword(&buffer, 8), 12);
    assert_eq!(qword(&buffer, 0x10), 0x57);
    // The stream ends; the connection takes commands again.
    assert_eq!(session.command("srvproc num=2"), "200- prev=0");
}

#[test]
fn rpc_argument_counts_stop_at_the_buffer_end() {
    const SIZE: usize = 0x50;
    let server = TestServer::start();
    server.host.lock().backend.session.rpc_functions.insert(
        0x8200_1000,
        Box::new(|arguments| RpcRegisters {
            r3: (arguments.integers.len() + arguments.doubles.len()) as u64,
            f1: 0.0,
        }),
    );
    let mut session = session(&server);
    assert_eq!(
        session.command(&format!("rpc version=4 title buf_size={SIZE}")),
        "204- buf_addr=4A000068"
    );
    let mut buffer = call_buffer(0, 0x8200_1000, &[], &[], SIZE);
    buffer[0x20..0x28].copy_from_slice(&0xffff_ffffu64.to_be_bytes());
    buffer[0x28..0x30].copy_from_slice(&0xffff_ffffu64.to_be_bytes());
    session.stream.write_all(&buffer).unwrap();
    assert_eq!(session.line(), "203- binary response follows");
    assert_eq!(read_exact(&mut session, 8), [0; 8]);
    assert_eq!(qword(&read_exact(&mut session, SIZE), 8), 2);
}

#[test]
fn rpc_reports_an_unknown_module() {
    const SIZE: usize = 0x48;
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command(&format!("rpc version=4 system buf_size={SIZE}")),
        "204- buf_addr=4A000068"
    );
    // The module name sits in the buffer after the header.
    let mut buffer = call_buffer(0x4a00_0068 + 0x40, 1, &[], &[], SIZE);
    buffer[0x40..0x45].copy_from_slice(b"none\0");
    session.stream.write_all(&buffer).unwrap();
    assert_eq!(session.line(), "203- binary response follows");
    assert_eq!(read_exact(&mut session, 8), [0; 8]);
    assert_eq!(
        qword(&read_exact(&mut session, SIZE), 0),
        0xffff_ffff_8007_007e
    );
}

#[test]
fn rpc_for_a_named_thread_sends_markers_until_the_thread_drains() {
    const SIZE: usize = 0x48;
    let server = TestServer::start();
    let drains = {
        let mut host = server.host.lock();
        host.backend.session.rpc_functions.insert(
            0x8200_2000,
            Box::new(|arguments| RpcRegisters {
                r3: 0,
                f1: arguments.doubles[0] * 2.0,
            }),
        );
        host.backend.session.rpc_drains.sender()
    };
    let mut session = session(&server);
    assert_eq!(
        session.command(&format!("rpc version=4 title thread=main buf_size={SIZE}")),
        "204- buf_addr=4A000068"
    );
    let mut buffer = call_buffer(0, 0x8200_2000, &[], &[1.5], SIZE);
    // Flag bit 0: the return value is the double.
    buffer[0x1f] = 1;
    session.stream.write_all(&buffer).unwrap();
    assert_eq!(session.line(), "203- binary response follows");
    assert_eq!(read_exact(&mut session, 8), [0, 0, 0, 0, 0, 0, 3, 0xe5]);
    // A thread of another name runs nothing.
    drains.send(b"other".to_vec()).unwrap();
    assert_eq!(read_exact(&mut session, 8), [0, 0, 0, 0, 0, 0, 3, 0xe5]);
    drains.send(b"main".to_vec()).unwrap();
    let mut marker = read_exact(&mut session, 8);
    while marker != [0; 8] {
        assert_eq!(marker, [0, 0, 0, 0, 0, 0, 3, 0xe5]);
        marker = read_exact(&mut session, 8);
    }
    let buffer = read_exact(&mut session, SIZE);
    assert_eq!(f64::from_bits(qword(&buffer, 8)), 3.0);
}

fn tell_log(server: &TestServer) -> Vec<u8> {
    server
        .host
        .lock()
        .backend
        .filesystem
        .read(&format!("{DEVKIT}\\tell.log"))
        .expect("log file")
        .to_vec()
}

#[test]
fn dmtelllog_result_codes() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("dmtelllog"), "407- unknown command");
    assert_eq!(
        session.command("dmtelllog start area=1"),
        "423- bad parameter"
    );
    assert_eq!(session.command("dmtelllog stop"), "200- hresult=0x494");
    assert_eq!(
        session.command("dmtelllog start file=tell.log area=1"),
        "200- hresult=0x10000000"
    );
    assert_eq!(
        session.command("dmtelllog start file=other.log area=1"),
        "200- hresult=0x420"
    );
    // A new area bit joins the open log, and a stop that leaves area bits
    // keeps it open; neither sends a reply.
    // The monitor takes one line per receive, so each line goes alone.
    let area = |expected: TellLogAreas| {
        move |host: &Host| {
            host.backend.session.tell_log.as_ref().map(|log| log.area) == Some(expected)
        }
    };
    session.send("dmtelllog start file=other.log area=2");
    server.wait_until(area(TellLogAreas::from_bits_retain(3)));
    session.send("dmtelllog stop area=1");
    server.wait_until(area(TellLogAreas::CRITICAL_SECTIONS));
    assert_eq!(session.command("dmtelllog stop"), "200- hresult=0x10000000");
    assert_eq!(
        session.command("dmtelllog start file=tell.log area=1 size=0x10000 entries=0x1000"),
        "400- hresult=0x9007000e"
    );
}

#[test]
fn dmtelllog_writes_record_text_on_close() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("dmtelllog start file=tell.log area=3 size=8 entries=2"),
        "200- hresult=0x10000000"
    );
    {
        let mut host = server.host.lock();
        host.backend.tell_log_record(b"first\n\0");
        // Records are cut to the entry size.
        host.backend.tell_log_record(b"second line\n");
        // The entry keeps the bytes beyond a shorter record.
        host.backend.tell_log_record(b"x");
    }
    assert!(tell_log(&server).is_empty());
    assert_eq!(session.command("dmtelllog stop"), "200- hresult=0x10000000");
    assert_eq!(tell_log(&server), b"first\nsecond lxirst\n");
    let output = &server.host.lock().backend.debug_output;
    assert!(
        output
            .iter()
            .any(|line| line == b"DmTellLog: Closing Log: dropped 0 messages, missed 0 messages\n")
    );
}

#[test]
fn dmtelllog_drops_records_when_the_queue_is_full() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("dmtelllog start file=tell.log area=1 entries=2"),
        "200- hresult=0x10000000"
    );
    {
        let mut host = server.host.lock();
        host.backend.session.tell_log_worker_paused = true;
        for record in [b"a\0".as_slice(), b"b\0", b"c\0"] {
            host.backend.tell_log_record(record);
        }
    }
    assert_eq!(session.command("dmtelllog stop"), "200- hresult=0x10000000");
    // The closing record found no entry either; the collection was never
    // written.
    assert!(tell_log(&server).is_empty());
    let output = &server.host.lock().backend.debug_output;
    assert!(
        output
            .iter()
            .any(|line| line == b"DmTellLog: Closing Log: dropped 2 messages, missed 0 messages\n")
    );
}

/// A pipe packet padded to the first receive of 0x5b4 bytes.
fn packet(magic: &[u8; 2], id: u16, offset: u32, body: &[u8]) -> Vec<u8> {
    let length = 0xc + body.len() as u32;
    let mut packet = Vec::new();
    packet.extend_from_slice(magic);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&offset.to_be_bytes());
    packet.extend_from_slice(body);
    if packet.len() < 0x5b4 {
        packet.resize(0x5b4, 0);
    }
    packet
}

fn create_body(path: &str, size: u64, attributes: u32, data: &[u8]) -> Vec<u8> {
    let header = 0x20 + path.len() as u32 + 1;
    let mut body = Vec::new();
    body.extend_from_slice(&header.to_be_bytes());
    body.extend_from_slice(&0x01d0_0000_0000_0001u64.to_be_bytes());
    body.extend_from_slice(&0x01d0_0000_0000_0002u64.to_be_bytes());
    body.extend_from_slice(&size.to_be_bytes());
    body.extend_from_slice(&attributes.to_be_bytes());
    body.extend_from_slice(path.as_bytes());
    body.push(0);
    body.extend_from_slice(data);
    body
}

fn reply(stream: &mut TcpStream) -> [u8; 12] {
    let mut reply = [0u8; 12];
    stream.read_exact(&mut reply).unwrap();
    reply
}

fn expected_reply(id: u16, create_length: u32, result: u32) -> [u8; 12] {
    let mut reply = [0u8; 12];
    reply[..2].copy_from_slice(b"BB");
    reply[2..4].copy_from_slice(&id.to_be_bytes());
    reply[4..8].copy_from_slice(&create_length.to_be_bytes());
    reply[8..].copy_from_slice(&result.to_be_bytes());
    reply
}

#[test]
fn fastpipe_receives_inline_and_block_files() {
    let server = TestServer::start();
    server.host.lock().backend.session.file_cache_elements = 0x40;
    let mut first = session(&server);
    assert_eq!(first.command("fastpipe"), "209- result code 1");
    assert_eq!(
        server.host.lock().backend.session.file_cache_elements,
        0x400
    );
    let mut second = session(&server);
    assert_eq!(second.command("fastpipe group=1"), "209- result code 1");
    let mut other = session(&server);
    assert_eq!(
        other.command("fastpipe group=5"),
        "400- fastpipe limit exceeded"
    );
    let mut first = first.stream;

    let inline_path = format!("{DEVKIT}\\inline.bin");
    let body = create_body(&inline_path, 5, 0, b"hello");
    let create = packet(b"CC", 1, 0, &body);
    first.write_all(&create).unwrap();
    assert_eq!(
        reply(&mut first),
        expected_reply(1, 0xc + body.len() as u32, 0)
    );
    assert_eq!(
        server.host.lock().backend.filesystem.read(&inline_path),
        Some(&b"hello"[..])
    );

    // A data packet that arrives before its create packet waits for it.
    let block_path = format!("{DEVKIT}\\block.bin");
    let tail = packet(b"AA", 2, 0x10000, b"!");
    second.stream.write_all(&tail).unwrap();
    let body = create_body(&block_path, 0x10001, 0x20, &[]);
    first.write_all(&packet(b"CC", 2, 0, &body)).unwrap();
    let data = vec![b'd'; 0x10000];
    first.write_all(&packet(b"AA", 2, 0, &data)).unwrap();
    assert_eq!(
        reply(&mut first),
        expected_reply(2, 0xc + body.len() as u32, 0)
    );
    {
        let host = server.host.lock();
        let entry = host.backend.filesystem.entry(&block_path).unwrap();
        assert_eq!(entry.data.len(), 0x10001);
        assert_eq!(entry.data[0x10000], b'!');
        assert_eq!(entry.attributes.0, 0x20);
        assert_eq!(entry.creation_time.0, 0x01d0_0000_0000_0001);
        assert_eq!(entry.last_write_time.0, 0x01d0_0000_0000_0002);
    }

    // Closing one pipe closes the group and restores the cache size.
    first.shutdown(Shutdown::Both).unwrap();
    let mut rest = Vec::new();
    second
        .stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    second.stream.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    assert_eq!(server.host.lock().backend.session.file_cache_elements, 0x40);
}

#[test]
fn fastpipe_requires_the_large_memory_configuration() {
    let server = TestServer::start();
    server.host.lock().backend.console.features.one_gigabyte_ram = false;
    let mut session = session(&server);
    assert_eq!(session.command("fastpipe"), "400- ");
}

fn discovery_responder(server: &TestServer) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let host = server.host.clone();
    thread::spawn(move || host.serve_discovery(&socket));
    address
}

#[test]
fn discovery_answers_identify_and_name_lookup() {
    let server = TestServer::start();
    let address = discovery_responder(&server);
    let mut session = session(&server);
    assert_eq!(session.command("dbgname name=DevKit-1"), "200- OK");

    let consoles = run(discover_all(DiscoveryConfig::unicast(address))).unwrap();
    assert_eq!(consoles.len(), 1);
    assert_eq!(consoles[0].name, "DevKit-1");
    assert_eq!(consoles[0].addr, address);

    // A lookup ignores ASCII case.
    let found = run(find_by_name("devkit-1", DiscoveryConfig::unicast(address))).unwrap();
    assert_eq!(
        found.map(|console| console.name),
        Some("DevKit-1".to_owned())
    );
    assert_eq!(
        run(find_by_name("other", DiscoveryConfig::unicast(address))).unwrap(),
        None
    );
}
