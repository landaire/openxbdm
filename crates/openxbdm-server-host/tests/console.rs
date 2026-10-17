//! Console identity and configuration commands over TCP.

mod common;

use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use common::RawSession;
use common::TestServer;
use common::run;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_server::commands::console::ConfigSetting;
use openxbdm_server::commands::console::DumpMode;
use openxbdm_server::commands::console::NetworkRaError;
use openxbdm_server::commands::console::NetworkRaFlags;
use openxbdm_server::commands::console::NetworkRaRecord;
use openxbdm_server::commands::console::RegistrationState;
use openxbdm_server::commands::filesystem::DriveTarget;
use openxbdm_server::commands::system::RebootKind;
use openxbdm_server_host::Host;

fn session(server: &TestServer) -> RawSession {
    let mut session = server.raw();
    assert_eq!(session.line(), "201- connected");
    session
}

fn server_with(configure: impl FnOnce(&mut Host)) -> TestServer {
    let mut host = Host::default();
    configure(&mut host);
    TestServer::with_host(host)
}

#[test]
fn identity_replies() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("dmversion"), "200- 2.0.21256.0");
    assert_eq!(session.command("consoletype"), "200- devkit");
    assert_eq!(
        session.command("consolefeatures"),
        "200-  DEBUGGING 1GB_RAM"
    );
    assert_eq!(session.command("consolemem"), "200- consolemem=0x2");
    assert_eq!(session.command("debugmemsize"), "200- debugmemsize=0x200");
    assert_eq!(
        session.command("getconsoleid"),
        "200- consoleid=012345678901"
    );
    assert_eq!(session.command("altaddr"), "200- addr=0xc0a80119");
    assert_eq!(session.command("debugmode"), "407- unknown command");
}

#[test]
fn test_kit_identity_and_devkit_only_commands() {
    let server = server_with(|host| host.backend.test_kit = true);
    let mut session = session(&server);
    assert_eq!(session.command("consoletype"), "200- testkit");
    for command in [
        "autoshutoff timeout=1",
        "confignetra show",
        "kiosk enabled=off",
        "resetnetra",
        "setretail and=0 or=0",
    ] {
        assert_eq!(
            session.command(command),
            "407- unknown command",
            "{command}"
        );
    }
}

#[test]
fn console_memory_classes() {
    use openxbdm_server::commands::console::MemoryStatistics;

    let server = server_with(|host| host.backend.console.features.one_gigabyte_ram = false);
    assert_eq!(
        session(&server).command("consolemem"),
        "200- consolemem=0x0"
    );

    let base = MemoryStatistics {
        physical_pages: 0x2_0000,
        debug_memory: 0,
        page_threshold: 0x2_0000,
    };
    let server = server_with(|host| host.backend.console.memory_statistics = Some(base));
    assert_eq!(
        session(&server).command("consolemem"),
        "200- consolemem=0x1"
    );

    let server = server_with(|host| host.backend.console.memory_statistics = None);
    let mut session = session(&server);
    assert_eq!(session.command("consolemem"), "200- consolemem=0x0");
    assert_eq!(session.command("debugmemsize"), "200- debugmemsize=0x0");
}

#[test]
fn console_id_failure_sets_bit_28() {
    let server =
        server_with(|host| host.backend.console.console_id = Err(KernelError::Unsuccessful));
    assert_eq!(session(&server).command("getconsoleid"), "400- ");
}

#[test]
fn network_addresses() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("getnetaddrs"),
        "200- name=openxbdm-mock debug=C0A8011A0000000000007CED8D74F5D70000000000000000000000000000000001000000 \
         title=C0A801190000000000007CED8D74F5D60000000000000000000000000000000001000000"
    );
    server.host.lock().backend.console.title_address.status = 1;
    assert_eq!(session.command("altaddr"), "400- ");
    server.host.lock().backend.console.title_address.status = 0;
    assert_eq!(
        session.command("getnetaddrs"),
        "442- debugstatus=0x00000066 titlestatus=0x00000000"
    );
}

#[test]
fn client_reads_network_addresses_with_a_spaced_name() {
    use openxbdm_client::commands::ConsoleMem;
    use openxbdm_client::commands::DbgName;
    use openxbdm_client::commands::GetConsoleMem;
    use openxbdm_client::commands::GetNetAddrs;

    let server = TestServer::start();
    run(async {
        let mut client = server.client().await;
        client
            .run(DbgName::Set("Lab Kit".to_owned()))
            .await
            .unwrap();
        let addresses = client.run(GetNetAddrs).await.unwrap();
        assert_eq!(addresses.name, "Lab Kit");
        assert_eq!(addresses.debug[..4], [0xc0, 0xa8, 0x01, 0x1a]);
        assert_eq!(addresses.title.len(), 36);
        assert_eq!(
            client.run(GetConsoleMem).await.unwrap(),
            ConsoleMem::ExtraMemoryInUse
        );
    });
}

#[test]
fn debug_name_is_truncated_and_written_to_the_settings_block() {
    let server = TestServer::start();
    assert_eq!(
        server.host.lock().backend.console.published.name,
        b"openxbdm-mock"
    );
    let mut session = session(&server);
    assert_eq!(
        session.command("dbgname name=\"a name longer than twenty\""),
        "200- OK"
    );
    assert_eq!(session.command("dbgname"), "200- a name longer than t");
    assert_eq!(
        server.host.lock().backend.console.published.name,
        b"a name longer than t"
    );
    let block = server.host.lock().backend.console.settings_block;
    let mut expected = [0xffu8; 0x20];
    expected[0] = 2;
    expected[1] = 0x20;
    expected[0xa] = 20;
    expected[0xb..0x1f].copy_from_slice(b"a name longer than t");
    assert_eq!(block, expected);

    assert_eq!(session.command("dbgname name=x"), "200- OK");
    let block = server.host.lock().backend.console.settings_block;
    assert_eq!(block[0xa], 1);
    assert_eq!(
        block[0xb..0x1f],
        *b"x\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    assert_eq!(block[0x1f], 0xff);
}

#[test]
fn debug_name_survives_a_failed_settings_block() {
    let server = server_with(|host| host.backend.console.i2c_failure = true);
    let mut session = session(&server);
    assert_eq!(session.command("dbgname name=kit"), "200- OK");
    assert_eq!(session.command("dbgname"), "200- kit");
}

#[test]
fn user_flag_settings() {
    let server = TestServer::start();
    let mut session = session(&server);
    let flags = |server: &TestServer| server.host.lock().backend.console.xconfig.dword(3, 0xd);

    assert_eq!(session.command("datacentermode enabled=TRUE"), "200- OK");
    assert_eq!(flags(&server), 0x400);
    assert_eq!(session.command("livesigninrequired enabled=on"), "200- OK");
    assert_eq!(flags(&server), 0x408);
    assert_eq!(
        session.command("livesigninrequired enabled=true"),
        "200- OK"
    );
    assert_eq!(flags(&server), 0x400);
    assert_eq!(session.command("datacentermode"), "200- OK");
    assert_eq!(flags(&server), 0);

    assert_eq!(session.command("kiosk"), "423- bad parameter");
    assert_eq!(session.command("kiosk enabled=on"), "423- bad parameter");
    assert_eq!(
        session.command("kiosk enabled=maybe id=1"),
        "423- bad parameter"
    );
    assert_eq!(session.command("kiosk enabled=true id=0x1234"), "200- OK");
    assert_eq!(flags(&server), 0x40);
    assert_eq!(
        server.host.lock().backend.console.xconfig.dword(0xb, 3),
        0x1234
    );
    assert_eq!(session.command("kiosk enabled=off id=7"), "200- OK");
    assert_eq!(flags(&server), 0);
    assert_eq!(server.host.lock().backend.console.xconfig.dword(0xb, 3), 0);

    server
        .host
        .lock()
        .backend
        .console
        .xconfig
        .failures
        .insert(ConfigSetting::new(0xb, 3), KernelError::Unsuccessful);
    assert_eq!(session.command("kiosk enabled=off"), "414- access denied");
}

#[test]
fn flag_update_falls_back_without_the_modify_export() {
    let server = server_with(|host| {
        host.backend.console.xconfig.modify_export = false;
        host.backend.console.xconfig.settings.insert(
            ConfigSetting::new(3, 0xc),
            0x0000_0001u32.to_be_bytes().to_vec(),
        );
    });
    let mut session = session(&server);
    assert_eq!(session.command("welcomedefault enabled=False"), "200- OK");
    assert_eq!(session.command("welcomehide enabled=off"), "200- OK");
    assert_eq!(
        server.host.lock().backend.console.xconfig.dword(3, 0xc),
        0x0c00_0001
    );
    assert_eq!(session.command("welcomehide"), "200- OK");
    assert_eq!(
        server.host.lock().backend.console.xconfig.dword(3, 0xc),
        0x0800_0001
    );
    assert_eq!(
        session.command("setretail and=0xffffffff or=2"),
        "400- Modify failed: 0xc0000138"
    );
}

#[test]
fn retail_flags_and_raw_settings() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("setretail or=1"), "400- missing and");
    assert_eq!(session.command("setretail and=1"), "400- missing or");
    assert_eq!(
        session.command("setretail and=0xffff0000 or=0x12"),
        "200- OK"
    );
    assert_eq!(
        server.host.lock().backend.console.xconfig.dword(3, 0xc),
        0x12
    );

    assert_eq!(
        session.command("setconfig index=1 value=2"),
        "400- missing category"
    );
    assert_eq!(
        session.command("setconfig category=1 value=2"),
        "400- missing index"
    );
    assert_eq!(
        session.command("setconfig category=1 index=2"),
        "400- missing value"
    );
    assert_eq!(
        session.command("setconfig category=0x10005 index=0x20003 value=0x11223344"),
        "200- OK"
    );
    assert_eq!(
        server.host.lock().backend.console.xconfig.value(5, 3),
        Some(&[0x11, 0x22, 0x33, 0x44][..])
    );
    server
        .host
        .lock()
        .backend
        .console
        .xconfig
        .failures
        .insert(ConfigSetting::new(5, 3), KernelError::Unsuccessful);
    assert_eq!(
        session.command("setconfig category=5 index=3 value=0"),
        "400- setvalue failed"
    );

    assert_eq!(session.command("discoverable"), "423- bad parameter");
    assert_eq!(
        session.command("discoverable enabled=yes"),
        "423- bad parameter"
    );
    assert_eq!(session.command("discoverable enabled=On"), "200- OK");
    assert_eq!(
        server.host.lock().backend.console.xconfig.value(7, 0xf),
        Some(&[1][..])
    );
    assert_eq!(session.command("discoverable enabled=false"), "200- OK");
    assert_eq!(
        server.host.lock().backend.console.xconfig.value(7, 0xf),
        Some(&[0][..])
    );
}

#[test]
fn auto_shutoff() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("autoshutoff"), "400- ");
    assert_eq!(
        session.command("autoshutoff timeout=2"),
        "423- bad parameter"
    );
    assert_eq!(session.command("autoshutoff timeout=6"), "200- OK");
    let host = server.host.lock();
    assert_eq!(
        host.backend.console.xconfig.value(7, 2),
        Some(&[0x81, 0x68][..])
    );
    assert_eq!(host.backend.console.inactivity_updates, 1);
    let output: Vec<&[u8]> = host
        .backend
        .debug_output
        .iter()
        .map(Vec::as_slice)
        .collect();
    assert_eq!(
        output,
        [
            &b"[xbdm] AutoShutoff, timeout=0 hr:0x82DA0000\n"[..],
            b"[xbdm] AutoShutoff, timeout=2 hr:0x82DA0017\n",
            b"[xbdm] AutoShutoff, timeout=6 hr:0x02DA0000\n",
        ]
    );
}

#[test]
fn data_center_network_configuration() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("confignetra show"),
        "200- \x1e[Current VE configurations]\x1erelaxheartbeat=off customubootaddr=0x00000000\x1e"
    );
    assert_eq!(
        session.command("confignetra relaxheartbeat"),
        "407- \x1eUsage: xbsetcfg /confignetra {relaxheartbeat=[on|off]} {customubootaddr=<address>}\x1e"
    );
    assert_eq!(
        session.command("confignetra relaxheartbeat=ON customubootaddr=0xabc"),
        "200- \x1e[Current VE configurations]\x1erelaxheartbeat=on customubootaddr=0x00000ABC\x1e"
    );
    assert_eq!(
        server.host.lock().backend.console.network_ra.record,
        NetworkRaRecord {
            flags: NetworkRaFlags::RELAX_HEARTBEAT | NetworkRaFlags::CUSTOM_BOOT_ADDRESS,
            custom_boot_address: 0xabc
        }
    );
    assert_eq!(
        session.command("confignetra customubootaddr=0"),
        "200- \x1e[Current VE configurations]\x1erelaxheartbeat=on customubootaddr=0x00000000\x1e"
    );
    assert_eq!(
        server.host.lock().backend.console.network_ra.record.flags,
        NetworkRaFlags::RELAX_HEARTBEAT
    );

    assert_eq!(session.command("resetnetra"), "200- OK");
    assert_eq!(server.host.lock().backend.console.network_ra.resets, 1);

    server.host.lock().backend.console.network_ra.failure =
        Some(NetworkRaError(Hresult(0x8007_048f)));
    assert_eq!(
        session.command("confignetra show"),
        "400- \x1econfignetra: failed to getting VE device config! Are you not running in DC mode? (err 0x8007048F)\x1e"
    );
    assert_eq!(session.command("resetnetra"), "200- OK");
}

#[test]
fn dump_mode() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("dumpmode"), "200- smart");
    assert_eq!(session.command("dumpmode disabled enabled"), "200- enabled");
    assert_eq!(session.command("dumpmode disabled"), "200- disabled");

    let server = server_with(|host| host.backend.test_kit = true);
    let mut session = self::session(&server);
    assert_eq!(session.command("dumpmode smart"), "200- enabled");
    assert_eq!(
        server.host.lock().server.state.console.dump_mode,
        DumpMode::Enabled
    );
    assert_eq!(
        server.host.lock().backend.debug_output,
        [b"Reset Dump mode to ENABLED for the TEST KIT!\n".to_vec()]
    );
}

#[test]
fn dump_settings() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("dumpsettings"),
        "200- rpt=prompt dst=local fmt=full"
    );
    assert_eq!(
        session.command("dumpsettings rpt=NEVER dst=remote fmt=bogus"),
        "200- rpt=never dst=remote fmt=full"
    );
    assert_eq!(
        session.command("dumpsettings fmt=noheap path=\"e:\\dumps dir\""),
        "200- rpt=never dst=remote fmt=noheap path=e:\\dumps dir"
    );
    assert_eq!(
        session.command("dumpsettings path="),
        "200- rpt=never dst=remote fmt=noheap"
    );
}

#[test]
fn event_defer() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("eventdefer"),
        "200-  break debugstring singlestep databreak"
    );
    assert_eq!(
        session.command("eventdefer break rip"),
        "200-  break debugstring singlestep databreak"
    );
    assert_eq!(
        session.command("eventdefer set rip assert"),
        "200-  assert rip"
    );
    assert_eq!(session.command("eventdefer set"), "200- OK");
}

#[test]
fn verbose() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("verbose"), "400- missing level");
    assert_eq!(session.command("verbose level=5x"), "400- missing level");
    assert_eq!(server.host.lock().server.state.console.trace_mask.bits(), 5);
    assert_eq!(session.command("verbose level=0x24"), "200- OK");
    assert_eq!(
        server.host.lock().server.state.console.trace_mask.bits(),
        0x24
    );
}

#[test]
fn http_registration() {
    // With the debug address pending the task waits, so the state the
    // command leaves is observable.
    let server = server_with(|host| host.backend.console.debug_address.status = 0);
    let mut session = session(&server);
    let state = |server: &TestServer| server.host.lock().server.state.console.http_registration;

    assert_eq!(session.command("httpreg clear"), "200- OK");
    assert_eq!(state(&server).state, RegistrationState::Cleared);
    assert_eq!(session.command("httpreg object=/x"), "423- bad parameter");
    assert_eq!(state(&server).state, RegistrationState::Failed);
    assert_eq!(session.command("httpreg server=lab"), "423- bad parameter");
    assert_eq!(
        session.command("httpreg server=lab object=reg"),
        "412- filename is invalid"
    );
    assert_eq!(
        session.command("httpreg server=lab object=/reg port=0x10050"),
        "200- OK"
    );
    let registration = state(&server);
    assert_eq!(registration.state, RegistrationState::Pending);
    assert_eq!(
        (
            registration.server(),
            registration.object(),
            registration.port
        ),
        (&b"lab"[..], &b"/reg"[..], 0x50)
    );
    assert_eq!(
        session.command("httpreg server=lab object=/reg port=x"),
        "200- OK"
    );
    assert_eq!(state(&server).port, 0);
}

/// Wait until the registration reaches `expected`.
fn wait_for_registration(server: &TestServer, expected: RegistrationState) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let current = server
            .host
            .lock()
            .server
            .state
            .console
            .http_registration
            .state;
        if current == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "registration stayed {current:?}, expected {expected:?}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

/// Accept the registration request and return its head (request line and
/// headers, without the blank line).
fn accept_registration(listener: &TcpListener) -> (TcpStream, String) {
    let (stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut head = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            return (stream, head);
        }
        head.push_str(&line);
    }
}

fn register(server: &TestServer, listener: &TcpListener) -> (TcpStream, String) {
    let port = listener.local_addr().unwrap().port();
    let mut session = session(server);
    assert_eq!(
        session.command(&format!(
            "httpreg server=127.0.0.1 object=/lab/reg port={port}"
        )),
        "200- OK"
    );
    accept_registration(listener)
}

fn debug_output(server: &TestServer) -> Vec<String> {
    server
        .host
        .lock()
        .backend
        .debug_output
        .iter()
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect()
}

#[test]
fn http_registration_exchange() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = TestServer::start();
    let (mut stream, head) = register(&server, &listener);
    let transaction = server
        .host
        .lock()
        .server
        .state
        .console
        .http_registration
        .transaction;
    let path = format!(
        "/lab/reg?name=openxbdm-mock&dbgmac=7CED8D74F5D7&dbgip=192.168.1.26&verflash=2.0.17559.0&verxdk=2.0.21256.0\
         &type=0&locked=0&transaction={transaction:016X}"
    );
    assert_eq!(
        head,
        format!(
            "GET {path} HTTP/1.1\r\nUser-Agent: Xbox Debugger/2.0.21256.0\r\nHost: 127.0.0.1:{port}\r\n"
        )
    );
    wait_for_registration(&server, RegistrationState::InProgress);
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        .unwrap();
    wait_for_registration(&server, RegistrationState::Registered);

    let host = server.host.lock();
    assert_eq!(
        host.server.state.console.http_registration.response(),
        b"hello"
    );
    assert_eq!(host.backend.console.http.closes, 1);
    drop(host);
    let output = debug_output(&server);
    assert!(
        output.contains(&format!(
            "XBDM: Attempting to register at [http://127.0.0.1:{port}{path}]...\n"
        )),
        "{output:?}"
    );
    assert!(
        output.contains(&"XBDM: Received 5 byte HTTP registration response.\n".to_owned()),
        "{output:?}"
    );
}

#[test]
fn http_registration_failures() {
    for (reply, state, message) in [
        (
            &b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"[..],
            RegistrationState::Rejected,
            "XBDM: HTTP server returned status code other than OK (404)!\n",
        ),
        (
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1025\r\n\r\n"[..],
            RegistrationState::ResponseTooLarge,
            "XBDM: HTTP registration response too large (1025 > 1024)!\n",
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = TestServer::start();
        let (mut stream, _) = register(&server, &listener);
        stream.write_all(reply).unwrap();
        wait_for_registration(&server, state);
        assert!(
            debug_output(&server).contains(&message.to_owned()),
            "{message}"
        );
    }
}

#[test]
fn title_end_restarts_registration_on_old_system_software() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = server_with(|host| host.backend.console.system_version = 0x2016_53ff);
    let (_first, _) = register(&server, &listener);
    wait_for_registration(&server, RegistrationState::InProgress);
    {
        let mut host = server.host.lock();
        let Host {
            server,
            backend,
            network,
        } = &mut *host;
        server.title_terminated(backend, network);
        assert_eq!(
            server.state.console.http_registration.state,
            RegistrationState::Pending
        );
        assert_eq!(backend.console.http.closes, 1);
    }
    // The task starts the registration again.
    let (_second, head) = accept_registration(&listener);
    assert!(
        head.starts_with("GET /lab/reg?name=openxbdm-mock&"),
        "{head}"
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = server_with(|host| host.backend.console.system_version = 0x2016_5400);
    let (_first, _) = register(&server, &listener);
    wait_for_registration(&server, RegistrationState::InProgress);
    let mut host = server.host.lock();
    let Host {
        server,
        backend,
        network,
    } = &mut *host;
    server.title_terminated(backend, network);
    assert_eq!(
        server.state.console.http_registration.state,
        RegistrationState::InProgress
    );
}

#[test]
fn unreadable_settings_block_makes_a_test_kit() {
    let failing = |host: &mut Host| host.backend.console.i2c_failure = true;
    let server = server_with(|host| {
        failing(host);
        host.backend.memory.flash[0x90..0x94].copy_from_slice(&[0, 0, 0, 1]);
    });
    let host = server.host.lock();
    assert_eq!(host.server.state.console.dump_mode, DumpMode::Enabled);
    assert_eq!(host.backend.memory.flash[0x90..0x94], [0; 4]);
    assert_eq!(host.backend.system.reboots, [RebootKind::Normal]);
    drop(host);
    assert_eq!(session(&server).command("consoletype"), "200- testkit");

    // A cleared flash field needs no restart; a stored dump mode is kept.
    let server = server_with(|host| {
        failing(host);
        host.backend.system.settings = Some(b"dumpmode disabled\r\n".to_vec());
    });
    let host = server.host.lock();
    assert!(host.backend.console.marked_test_kit);
    assert_eq!(host.server.state.console.dump_mode, DumpMode::Disabled);
    assert!(host.backend.system.reboots.is_empty());
    drop(host);

    // Mapped internal drives, a readable block, or a console before Trinity
    // skip the check.
    for configure in [
        (|host: &mut Host| host.backend.system.settings = Some(b"drivemap internal=1\r\n".to_vec()))
            as fn(&mut Host),
        |host| host.backend.console.i2c_failure = false,
        |host| host.backend.system.hardware_flags = 0x3000_0013,
    ] {
        let server = server_with(|host| {
            failing(host);
            configure(host);
        });
        assert!(!server.host.lock().backend.console.marked_test_kit);
    }
}

#[test]
fn feature_switch() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("feature feature=1"),
        "423- 'enable' not specified"
    );
    assert_eq!(
        session.command("feature enable=1"),
        "423- 'feature' not specified"
    );
    assert_eq!(session.command("feature enable=1 feature=0x20"), "200- OK");
    assert_eq!(
        server.host.lock().backend.console.feature_calls,
        Some(vec![(1, 0x20)])
    );

    let server = server_with(|host| host.backend.console.feature_calls = None);
    assert_eq!(self::session(&server).command("feature"), "200- OK");
}

#[test]
fn network_share_server() {
    let server = TestServer::start();
    let mut session = session(&server);
    let share = |server: &TestServer| {
        let host = server.host.lock();
        let drive = host
            .server
            .state
            .filesystem
            .drives
            .drives()
            .find(|drive| drive.name == b"SMB" || drive.name == b"F")
            .copied();
        drive.map(|drive| (drive.target, drive.enabled))
    };

    assert_eq!(session.command("setserver"), "400- missing server name");
    assert_eq!(
        session.command("setserver name=\"labserver\tshare\""),
        "200- OK"
    );
    let stored = server
        .host
        .lock()
        .backend
        .console
        .xconfig
        .value(3, 0x10)
        .map(<[u8]>::to_vec)
        .unwrap();
    assert_eq!(stored.len(), 0x100);
    assert_eq!(&stored[..16], b"labserver\tshare\0");
    assert_eq!(share(&server), Some((DriveTarget::NetworkShare, true)));

    assert_eq!(session.command("setserver none"), "200- OK");
    assert_eq!(
        server.host.lock().backend.console.xconfig.value(3, 0x10),
        Some(&[0u8; 0x100][..])
    );
    assert_eq!(
        share(&server),
        Some((DriveTarget::Object(b"\\Badpath"), false))
    );

    server
        .host
        .lock()
        .backend
        .console
        .xconfig
        .failures
        .insert(ConfigSetting::new(3, 0x10), KernelError::Unsuccessful);
    assert_eq!(
        session.command("setserver name=x"),
        "400- save setting failed"
    );
}

#[test]
fn system_info() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("systeminfo"),
        "202- multiline response follows"
    );
    assert_eq!(
        session.multiline(),
        [
            "HDD=Enabled",
            "Type=DevKit",
            "Platform=Waternoose System=Corona",
            "BaseKrnl=2.0.1888.0 Krnl=2.0.17559.0 XDK=2.0.21256.0",
        ]
    );

    let server = server_with(|host| {
        host.backend.test_kit = true;
        host.backend.console.system_information.hardware_flags = 0x7000_0001;
    });
    let mut session = self::session(&server);
    session.command("systeminfo");
    assert_eq!(
        session.multiline()[..3],
        [
            "HDD=Disabled",
            "Type=TestKit",
            "Platform=Mongrel System=Unknown"
        ]
    );
}

#[test]
fn exported_settings_reach_commands_and_mirrors() {
    use openxbdm_server::commands::console::DUMP_SETTINGS_SIZE;
    use openxbdm_server::commands::console::ExportedSetting;
    use openxbdm_server::commands::console::apply_exported_setting;

    let server = TestServer::start();
    let apply = |setting| {
        let mut host = server.host.lock();
        let Host {
            server, backend, ..
        } = &mut *host;
        apply_exported_setting(&mut server.state, backend, setting);
    };
    apply(ExportedSetting::DumpMode(7));
    // Stock indexes past each name group for values only export 120 stores.
    let mut block = [0u8; DUMP_SETTINGS_SIZE];
    block[2..4].copy_from_slice(&[0x04, 0x23]);
    block[4..8].copy_from_slice(b"e:\\d");
    apply(ExportedSetting::DumpSettings(block));
    apply(ExportedSetting::EventDefer(0x41));
    apply(ExportedSetting::DebugName(
        openxbdm_server::commands::console::DebugName::new(b"kit"),
    ));

    let mut session = session(&server);
    assert_eq!(session.command("dumpmode"), "200- smart");
    assert_eq!(
        session.command("dumpsettings"),
        "200- rpt=local dst=full fmt=(null) path=e:\\d"
    );
    assert_eq!(session.command("eventdefer"), "200-  break rip");
    assert_eq!(session.command("dbgname"), "200- kit");
    let host = server.host.lock();
    let published = &host.backend.console.published;
    assert_eq!(
        (
            published.dump_mode,
            published.event_defer,
            &published.name[..]
        ),
        (7, 0x41, &b"kit"[..])
    );
    assert_eq!(published.dump_settings, block);
    assert_eq!(host.backend.console.settings_block[0xa..0xe], *b"\x03kit");
}

#[test]
fn settings_lines_formatted_whole_echo_once() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("verbose level=4"), "200- OK");
    assert_eq!(
        session.command("dumpsettings path=e:\\d"),
        "200- rpt=prompt dst=local fmt=full path=e:\\d"
    );
    server.host.lock().backend.debug_output.clear();
    assert_eq!(
        session.command("httpreg server=lab object=/reg port=81"),
        "200- OK"
    );
    let host = server.host.lock();
    let file =
        String::from_utf8(host.backend.system.settings.clone().expect("settings file")).unwrap();
    let echoes: Vec<String> = host
        .backend
        .debug_output
        .iter()
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .filter_map(|line| {
            line.strip_prefix("XBDM: WriteIniSzNoCRLF: '")?
                .strip_suffix("'\n")
                .map(str::to_owned)
        })
        .collect();
    for prefix in ["dumpsettings ", "eventdefer set ", "httpreg server="] {
        let line = file
            .split("\r\n")
            .find(|line| line.starts_with(prefix))
            .expect(prefix);
        let pieces: Vec<&String> = echoes
            .iter()
            .filter(|echo| line.starts_with(echo.as_str()) || echo.starts_with(prefix))
            .collect();
        assert_eq!(pieces, [line], "{prefix}");
    }
    assert!(file.contains("httpreg server=lab object=/reg port=81\r\n"));
}
