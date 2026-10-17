//! Hardware, input, and manufacturing control commands over TCP.

mod common;

use std::io::Write;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::KernelError;
use openxbdm_server::commands::console::ConfigSetting;
use openxbdm_server::commands::hardware::AvatarError;
use openxbdm_server::commands::hardware::AvatarHook;
use openxbdm_server::commands::hardware::InputOwner;
use openxbdm_server::commands::hardware::PlayToCommand;
use openxbdm_server::commands::hardware::PlayToState;
use openxbdm_server::commands::hardware::UsbController;
use openxbdm_server::commands::hardware::UsbPort;
use openxbdm_server::commands::hardware::XamError;
use openxbdm_server::commands::hardware::automation::DebuggerMessage;
use openxbdm_server::commands::hardware::automation::Gamepad;
use openxbdm_server::commands::hardware::automation::Poll;
use openxbdm_server_host::backend::hardware::PgoRecord;
use openxbdm_server_host::backend::hardware::UsbPortRequest;

use common::RawSession;
use common::TestServer;

fn session(server: &TestServer) -> RawSession {
    let mut session = server.raw();
    assert_eq!(session.line(), "201- connected");
    session
}

fn wire_packet(buttons: u16, left_trigger: u8, thumb_lx: i16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&buttons.to_le_bytes());
    bytes.extend_from_slice(&[left_trigger, 0]);
    bytes.extend_from_slice(&thumb_lx.to_le_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes
}

fn upload(session: &mut RawSession, bytes: &[u8]) -> String {
    session.stream.write_all(bytes).unwrap();
    session.line()
}

fn polled(server: &TestServer, user: u32) -> Option<Poll> {
    server.host.lock().backend.hardware.poll(user)
}

fn buttons(poll: Option<Poll>) -> u16 {
    match poll {
        Some(Poll::State { packet, .. }) => packet.buttons,
        other => panic!("unexpected poll result {other:?}"),
    }
}

fn config(server: &TestServer, category: u16, index: u16) -> u32 {
    server
        .host
        .lock()
        .backend
        .console
        .xconfig
        .dword(category, index)
}

fn set_config(server: &TestServer, category: u16, index: u16, value: u32) {
    let mut host = server.host.lock();
    host.backend.console.xconfig.settings.insert(
        ConfigSetting::new(category, index),
        value.to_be_bytes().to_vec(),
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn pgo_record(address: u32) -> PgoRecord {
    PgoRecord {
        address,
        enabled: false,
        counts_allocated: false,
        allocation_scale: 0,
        snapshots: Vec::new(),
        resets: 0,
    }
}

#[test]
fn autoinput_requires_user_and_parameters() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("autoinput connect"), "437- missing user");
    assert_eq!(session.command("autoinput user=0"), "200- OK");
    assert_eq!(
        session.command("autoinput user=0 bind"),
        "437- missing queuelen"
    );
    assert_eq!(
        session.command("autoinput user=0 queuepackets"),
        "437- missing count"
    );
    assert_eq!(
        session.command("autoinput user=4 bind queuelen=1"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("autoinput user=4 connect"),
        "423- bad parameter"
    );
    assert_eq!(session.command("autoinput user=0 connect"), "442- ");
    assert_eq!(session.command("autoinput user=0 disconnect"), "442- ");
    assert_eq!(session.command("autoinput user=0 clearqueue"), "442- ");
    assert_eq!(session.command("autoinput user=0 queryqueue"), "442- ");
}

#[test]
fn autoinput_bind_and_unbind_notify_the_debugger_extension() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("autoinput user=1 bind queuelen=4"),
        "200- OK"
    );
    assert_eq!(
        session.command("autoinput user=1 queryqueue"),
        "200- nQueue=0x00000004, nPacket=0x00000000, t_remain_ms=0x00000000, t_remain_count=0x00000000"
    );
    assert_eq!(session.command("autoinput user=1 unbind"), "200- OK");
    assert_eq!(session.command("autoinput user=1 queryqueue"), "442- ");
    let host = server.host.lock();
    let input = &host.backend.hardware.input;
    assert_eq!(input.binds, [1]);
    assert_eq!(input.unbinds, [1]);
    assert_eq!(
        input.debugger_messages,
        [
            DebuggerMessage::Binding {
                user: 1,
                bound: true
            },
            DebuggerMessage::Binding {
                user: 1,
                bound: false
            }
        ]
    );
}

#[test]
fn autoinput_refused_binding_reports_unknown_command() {
    let server = TestServer::start();
    server.host.lock().backend.hardware.input.refuse_bind = true;
    let mut session = session(&server);
    assert_eq!(
        session.command("autoinput user=0 bind queuelen=2"),
        "407- unknown command"
    );
    assert_eq!(session.command("autoinput user=0 queryqueue"), "442- ");
    server.host.lock().backend.hardware.input.refuse_unbind = true;
    assert_eq!(
        session.command("autoinput user=0 unbind"),
        "407- unknown command"
    );
    assert_eq!(
        session.command("autoinput user=0 bind queuelen=0x7fffffff"),
        "428- out of memory"
    );
}

#[test]
fn autoinput_setpacket_presents_a_fixed_state() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("autoinput user=2 bind queuelen=0"),
        "200- OK"
    );
    assert_eq!(
        session.command("autoinput user=2 setpacket"),
        "204- send binary data"
    );
    assert_eq!(
        upload(&mut session, &wire_packet(0x0410, 0x80, -2)),
        "200- OK"
    );
    let packet = Gamepad {
        buttons: 0x0410,
        left_trigger: 0x80,
        thumb_lx: -2,
        ..Gamepad::default()
    };

    assert_eq!(
        polled(&server, 2),
        Some(Poll::State {
            packet_number: 1,
            packet
        })
    );
    {
        let host = server.host.lock();
        let input = &host.backend.hardware.input;
        assert_eq!(input.guide_presses, [2]);
        assert_eq!(
            input.debugger_messages.last(),
            Some(&DebuggerMessage::Packet { user: 2, packet })
        );
    }

    assert_eq!(session.command("autoinput user=2 disconnect"), "200- OK");
    assert_eq!(polled(&server, 2), Some(Poll::NotConnected));
    assert_eq!(
        session.command("autoinput user=2 setpacket"),
        "204- send binary data"
    );
    assert_eq!(upload(&mut session, &wire_packet(1, 0, 0)), "442- ");
    assert_eq!(session.command("autoinput user=2 connect"), "200- OK");
    assert_eq!(buttons(polled(&server, 2)), 0);
    let messages = server
        .host
        .lock()
        .backend
        .hardware
        .input
        .debugger_messages
        .len();
    assert_eq!(messages, 3);
}

#[test]
fn autoinput_queuepackets_plays_back_timed_states() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("autoinput user=0 bind queuelen=3"),
        "200- OK"
    );
    assert_eq!(
        session.command("autoinput user=0 queuepackets count=4 timearray countarray"),
        "204- send binary data"
    );
    let mut bytes = Vec::new();
    for buttons in 1..=4u16 {
        bytes.extend_from_slice(&wire_packet(buttons, 0, 0));
    }

    for time in [100u32, 0, 0, 0] {
        bytes.extend_from_slice(&time.to_le_bytes());
    }

    for count in [1u32, 2, 0, 0] {
        bytes.extend_from_slice(&count.to_le_bytes());
    }

    assert_eq!(upload(&mut session, &bytes), "200- queued=0x00000003");
    server.host.lock().backend.hardware.input.now = 40;
    assert_eq!(
        session.command("autoinput user=0 queryqueue"),
        "200- nQueue=0x00000003, nPacket=0x00000003, t_remain_ms=0x0000003c, t_remain_count=0x00000003"
    );
    assert_eq!(buttons(polled(&server, 0)), 1);
    server.host.lock().backend.hardware.input.now = 100;
    assert_eq!(buttons(polled(&server, 0)), 2);
    assert_eq!(buttons(polled(&server, 0)), 2);
    assert_eq!(buttons(polled(&server, 0)), 0);
    assert_eq!(
        session.command("autoinput user=0 queryqueue"),
        "200- nQueue=0x00000003, nPacket=0x00000000, t_remain_ms=0x00000000, t_remain_count=0x00000000"
    );
}

#[test]
fn autoinput_queuepackets_errors_after_the_upload() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("autoinput user=0 queuepackets count=1 timearray"),
        "204- send binary data"
    );
    assert_eq!(upload(&mut session, &[0; 16]), "442- ");
    assert_eq!(
        session.command("autoinput user=0 bind queuelen=2"),
        "200- OK"
    );
    assert_eq!(
        session.command("autoinput user=0 queuepackets count=1"),
        "204- send binary data"
    );
    assert_eq!(upload(&mut session, &[0; 12]), "423- bad parameter");
    assert_eq!(
        session.command("autoinput user=0 queuepackets count=0 timearray"),
        "204- send binary data"
    );
    assert_eq!(session.line(), "400- ");
    assert_eq!(
        session.command("autoinput user=0 queuepackets count=0x20000000 timearray"),
        "428- out of memory"
    );
    assert_eq!(
        session.command("autoinput user=7 queuepackets count=1 countarray"),
        "204- send binary data"
    );
    assert_eq!(upload(&mut session, &[0; 16]), "423- bad parameter");
}

#[test]
fn autoinput_clearqueue_keeps_playback_with_an_empty_queue() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("autoinput user=3 bind queuelen=2"),
        "200- OK"
    );
    assert_eq!(
        session.command("autoinput user=3 queuepackets count=1 countarray"),
        "204- send binary data"
    );
    let mut bytes = wire_packet(7, 0, 0);
    bytes.extend_from_slice(&5u32.to_le_bytes());
    assert_eq!(upload(&mut session, &bytes), "200- queued=0x00000001");
    assert_eq!(session.command("autoinput user=3 clearqueue"), "200- OK");
    assert_eq!(buttons(polled(&server, 3)), 0);
    assert_eq!(
        session.command("autoinput user=3 queryqueue"),
        "200- nQueue=0x00000002, nPacket=0x00000000, t_remain_ms=0x00000000, t_remain_count=0x00000005"
    );
}

#[test]
fn autoinput_process_reports_input_focus() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("autoinput user=9 process"), "200- title");
    server.host.lock().backend.hardware.input_owner = Some(InputOwner::System);
    assert_eq!(session.command("autoinput user=0 process"), "200- system");
    server.host.lock().backend.hardware.input_owner = None;
    assert_eq!(
        session.command("autoinput user=0 process"),
        "407- unknown command"
    );
    assert_eq!(
        server.host.lock().backend.hardware.input_focus_users,
        [9, 0]
    );
}

#[test]
fn avatar_runs_test_hooks() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("avatar loadassetdelay=-5"), "200- OK");
    assert_eq!(
        session.command("avatar querymarketplacedelay=300 loadassetdelay=x"),
        "200- OK"
    );
    assert_eq!(
        session.command("avatar changemetadata=0xffffffff"),
        "200- OK"
    );
    assert_eq!(
        session.command("avatar simulateerrortype=0 simulateerrorvalue=9"),
        "200- OK"
    );
    assert_eq!(
        session.command("avatar simulateerrortype=1 simulateerrorvalue=9"),
        "400- "
    );
    assert_eq!(session.command("avatar simulateerrortype=0"), "200- OK");
    assert_eq!(
        server.host.lock().backend.hardware.avatar_calls,
        [
            AvatarHook::LoadAssetDelay(0),
            AvatarHook::QueryMarketplaceDelay(300),
            AvatarHook::ChangeMetadata(0xffff_ffff),
            AvatarHook::SimulateError { kind: 0, value: 9 },
        ]
    );

    {
        let mut host = server.host.lock();
        let failures = &mut host.backend.hardware.avatar_failures;
        failures.insert(0, AvatarError::NoFunction);
        failures.insert(8, AvatarError::Lookup(XamError::InvalidArgument));
        failures.insert(
            7,
            AvatarError::Hook(XamError::check(ErrorCode::NotStopped.hresult()).unwrap_err()),
        );
    }

    assert_eq!(
        session.command("avatar loadassetdelay=1"),
        "414- access denied"
    );
    assert_eq!(
        session.command("avatar querymarketplacedelay=1"),
        "400- bad parameter"
    );
    assert_eq!(
        session.command("avatar changemetadata=1"),
        "408- not stopped"
    );
    server.host.lock().backend.hardware.avatar_available = false;
    assert_eq!(
        session.command("avatar simulateerrortype=1 simulateerrorvalue=9"),
        "200- OK"
    );
}

#[test]
fn bkgdmodetest_and_builtinmu_edit_configuration_bits() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("bkgdmodetest"), "400- missing arguments");
    assert_eq!(session.command("builtinmu"), "400- missing arguments");
    set_config(&server, 3, 0xd, 0x1000);
    assert_eq!(session.command("bkgdmodetest enable disable"), "200- OK");
    assert_eq!(config(&server, 3, 0xd), 0x1002);
    assert_eq!(session.command("bkgdmodetest disable"), "200- OK");
    assert_eq!(config(&server, 3, 0xd), 0x1000);
    assert_eq!(session.command("builtinmu disable"), "200- OK");
    assert_eq!(config(&server, 2, 6), 0x4);
    assert_eq!(session.command("builtinmu enable"), "200- OK");
    assert_eq!(config(&server, 2, 6), 0);

    server
        .host
        .lock()
        .backend
        .console
        .xconfig
        .failures
        .insert(ConfigSetting::new(2, 6), KernelError::Unsuccessful);
    assert_eq!(session.command("builtinmu enable"), "400- unexpected error");
    server
        .host
        .lock()
        .backend
        .console
        .xconfig
        .failures
        .insert(ConfigSetting::new(3, 0xd), KernelError::AccessDenied);
    assert_eq!(session.command("bkgdmodetest enable"), "414- access denied");
}

#[test]
fn configuration_flag_commands_always_succeed() {
    let server = TestServer::start();
    let mut session = session(&server);
    for (command, index, mask) in [
        ("bootanim enabled=OFF", 0xd, 0x4),
        ("mdetect enabled=false", 0xd, 0x1),
        ("kinecthsmsg off", 0xd, 0x20),
        ("runnuioobe enabled=off", 0xc, 0x2000_0000),
        ("runoobe enabled=False", 0xc, 0x40),
        ("runoobecheckpoint enabled=off", 0xc, 0x8000),
    ] {
        assert_eq!(session.command(command), "200- OK", "{command}");
        assert_eq!(config(&server, 3, index) & mask, mask, "{command}");
    }

    for (command, index, mask) in [
        ("bootanim", 0xd, 0x4),
        ("mdetect enabled=on", 0xd, 0x1),
        ("kinecthsmsg", 0xd, 0x20),
        ("runnuioobe enabled=offline", 0xc, 0x2000_0000),
        ("runoobe", 0xc, 0x40),
        ("runoobecheckpoint enabled=true", 0xc, 0x8000),
    ] {
        assert_eq!(session.command(command), "200- OK", "{command}");
        assert_eq!(config(&server, 3, index) & mask, 0, "{command}");
    }

    server
        .host
        .lock()
        .backend
        .console
        .xconfig
        .failures
        .insert(ConfigSetting::new(3, 0xd), KernelError::Unsuccessful);
    assert_eq!(session.command("bootanim enabled=off"), "200- OK");
}

#[test]
fn enablewirelesscontrollers_switches_the_radio_and_flag() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("enablewirelesscontrollers"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("enablewirelesscontrollers enabled=maybe"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("enablewirelesscontrollers enabled=OFF"),
        "200- OK"
    );
    assert_eq!(config(&server, 3, 0xd), 0x800);
    assert_eq!(
        session.command("enablewirelesscontrollers enabled=true"),
        "200- OK"
    );
    assert_eq!(config(&server, 3, 0xd), 0);
    server.host.lock().backend.hardware.radio_result = Err(KernelError::Unsuccessful);
    assert_eq!(
        session.command("enablewirelesscontrollers enabled=off"),
        "414- access denied"
    );
    assert_eq!(config(&server, 3, 0xd), 0);
    {
        let host = server.host.lock();
        assert_eq!(host.backend.hardware.radio_requests, [false, true, false]);
        let printed: Vec<&[u8]> = host
            .backend
            .debug_output
            .iter()
            .map(Vec::as_slice)
            .collect();
        assert!(printed.contains(&b"[xbdm] EnableWirelessControllers, enabled=maybe\n".as_slice()));
    }

    server.host.lock().backend.test_kit = true;
    assert_eq!(
        session.command("enablewirelesscontrollers enabled=on"),
        "407- unknown command"
    );
}

#[test]
fn irtsweep_always_fails() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("irtsweep anything"),
        "400- error status 0xc0000002"
    );
}

#[test]
fn mixcmd_reports_memory_statistics() {
    let server = TestServer::start();
    let mut session = session(&server);
    let mut block = vec![0, 0, 0, 0x90, 0, 0, 0, 0x68];
    block.extend((8..0x90).map(|index| index as u8));
    assert_eq!(
        session.command("mixcmd querystats"),
        format!("200- OK querystats {}", hex(&block))
    );
    assert_eq!(session.command("mixcmd querystats now"), "200- OK");
    assert_eq!(
        session.command("mixcmd countxamheaps"),
        "200- OK countxamheaps System=00000003 Coop=00000005"
    );
    let usage: Vec<u8> = [0, 0, 0, 0x18].into_iter().chain(0..0x14).collect();
    let limits: Vec<u8> = [0, 0, 0, 0x1c]
        .into_iter()
        .chain((0..0x18).map(|index| 0xe0 | index))
        .collect();
    assert_eq!(
        session.command("mixcmd xamheap 1A"),
        format!(
            "200- OK xamheap Name=XamSystemHeap Data={}{}",
            hex(&usage),
            hex(&limits)
        )
    );
    assert_eq!(
        session.command("mixcmd xamheap 0000001a99"),
        session.command("mixcmd xamheap 1a")
    );
    assert_eq!(session.command("mixcmd xamheap 2"), "400- ");
    assert_eq!(session.command("mixcmd xamheap 1g"), "423- bad parameter");
    assert_eq!(session.command("mixcmd xamheapx"), "423- bad parameter");
    assert_eq!(session.command("mixcmd other"), "200- OK");

    {
        let mut host = server.host.lock();
        let hardware = &mut host.backend.hardware;
        hardware.memory_statistics_result = Err(KernelError::Unsuccessful);
        hardware.xam_heap_count_result = Err(XamError::Fail);
    }

    assert_eq!(session.command("mixcmd querystats"), "400- ");
    assert_eq!(session.command("mixcmd countxamheaps"), "400- ");
    {
        let mut host = server.host.lock();
        host.backend.hardware.xam_heap_count_available = false;
        host.backend.hardware.xam_heap_info_available = false;
    }

    assert_eq!(
        session.command("mixcmd countxamheaps"),
        "414- access denied"
    );
    assert_eq!(session.command("mixcmd xamheap 1a"), "414- access denied");
}

#[test]
fn mockcurrencyvalue_messages_the_marketplace() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("mockcurrencyvalue"), "423- bad parameter");
    assert_eq!(
        session.command("mockcurrencyvalue enabled=on"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("mockcurrencyvalue enabled=yes value=1"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("mockcurrencyvalue enabled=TRUE value=0x1234"),
        "200- OK"
    );
    assert_eq!(
        session.command("mockcurrencyvalue enabled=off value=7"),
        "200- OK"
    );
    let mut expected = [0u8; 0x14];
    expected[..8].copy_from_slice(&[0, 0, 0, 1, 0, 0, 0x12, 0x34]);
    assert_eq!(
        server.host.lock().backend.hardware.mock_currency_settings,
        [expected, [0; 0x14]]
    );
    server.host.lock().backend.hardware.mock_currency_result = Ok(());
    assert_eq!(
        session.command("mockcurrencyvalue enabled=off"),
        "414- access denied"
    );
    server.host.lock().backend.test_kit = true;
    assert_eq!(
        session.command("mockcurrencyvalue enabled=off"),
        "407- unknown command"
    );
}

#[test]
fn oddlog_starts_and_stops_the_writer() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("oddlog stop"), "424- ");
    assert_eq!(
        session.command("oddlog"),
        "200- Logging to 'devkit:\\OpticalDiscLog_0.txt'"
    );
    assert_eq!(session.command("oddlog file=e:\\odd.txt"), "425- ");
    assert_eq!(session.command("oddlog stop"), "200- stopped logging");
    assert_eq!(session.command("oddlog stop"), "424- ");
    assert_eq!(
        session.command("oddlog"),
        "200- Logging to 'devkit:\\OpticalDiscLog_1.txt'"
    );
    assert_eq!(session.command("oddlog stop"), "200- stopped logging");
    assert_eq!(server.host.lock().backend.hardware.odd_log.files.len(), 2);
}

#[test]
fn oddlog_file_failure_leaves_the_writer_stoppable() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("oddlog file=odd.txt"),
        "413- file cannot be created"
    );
    assert_eq!(session.command("oddlog stop"), "200- stopped logging");
    server.host.lock().backend.hardware.odd_log.file_result = Err(KernelError::ObjectPathNotFound);
    assert_eq!(session.command("oddlog"), "430- path not found");
    assert_eq!(session.command("oddlog stop"), "200- stopped logging");
}

#[test]
fn playto_queries_the_media_service() {
    let server = TestServer::start();
    let mut session = session(&server);
    server.host.lock().backend.hardware.play_to = Ok(PlayToState {
        xmp_heap: 0,
        play_to: 1,
    });

    assert_eq!(
        session.command("playto show"),
        "200- XMP_HEAP: OFF, PlayTo: ON [T:192.168.1.30 / D:192.168.1.31]"
    );
    assert_eq!(
        session.command("playto set enable=0"),
        "200- XMP_HEAP: OFF, PlayTo: ON [T:192.168.1.30 / D:192.168.1.31]"
    );
    assert_eq!(
        session.command("playto set enable=1 show"),
        "200- XMP_HEAP: OFF, PlayTo: ON [T:192.168.1.30 / D:192.168.1.31]"
    );
    assert_eq!(
        session.command("playto set enable show"),
        "423- Invalid parameter: playto set enable show"
    );
    assert_eq!(session.command("playto"), "423- Invalid parameter: playto");
    assert_eq!(
        server.host.lock().backend.hardware.play_to_requests,
        [
            PlayToCommand::Show,
            PlayToCommand::Disable,
            PlayToCommand::Enable
        ]
    );
    server.host.lock().backend.hardware.play_to = Err(XamError::Fail);
    assert_eq!(
        session.command("playto show"),
        "423- Invalid parameter: playto show"
    );
    server.host.lock().backend.test_kit = true;
    assert_eq!(session.command("playto show"), "407- unknown command");
}

#[test]
fn pogoctrl_controls_instrumented_modules() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("pogoctrl"), "400- HRESULT 0x82da0000");
    assert_eq!(session.command("pogoctrl start"), "200- HRESULT 0x02da0000");
    assert_eq!(
        session.command("pogoctrl start module=0x1000"),
        "423- HRESULT 0x82da0017"
    );
    {
        let mut host = server.host.lock();
        host.backend.hardware.pgo_records = vec![pgo_record(0x1000), pgo_record(0x2000)];
        host.backend.hardware.pgo_records[1].counts_allocated = true;
    }

    assert_eq!(
        session.command("pogoctrl start module=0x1000"),
        "200- HRESULT 0x02da0000"
    );
    assert_eq!(
        session.command("pogoctrl snapshot phase=boot reset=1"),
        "200- HRESULT 0x02da0000"
    );
    assert_eq!(session.command("pogoctrl stop"), "200- HRESULT 0x02da0000");
    assert_eq!(
        session.command("pogoctrl allocscale module=0x1000 scale=3"),
        "200- HRESULT 0x02da0000"
    );
    assert_eq!(
        session.command("pogoctrl allocscale module=0x2000 scale=3"),
        "425- HRESULT 0x82da0019"
    );
    assert_eq!(
        session.command("pogoctrl allocscale scale=3"),
        "423- HRESULT 0x82da0017"
    );
    let host = server.host.lock();
    let records = &host.backend.hardware.pgo_records;
    assert!(!records[0].enabled);
    assert_eq!(records[0].allocation_scale, 3);
    assert_eq!(records[1].snapshots, [b"boot".to_vec()]);
    assert_eq!(records[1].resets, 1);
}

#[test]
fn tdecomp_selects_the_gdf_attribute_mode() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("tdecomp"), "200- NoGDFAttrib");
    assert_eq!(
        session.command("tdecomp IgnoreGDFAttrib"),
        "200- IgnoreGDFAttrib"
    );
    assert_eq!(session.command("tdecomp"), "200- IgnoreGDFAttrib");
    assert_eq!(
        session.command("tdecomp ignoregdfattrib usegdfattrib"),
        "200- NoGDFAttrib"
    );
}

#[test]
fn usbportctrl_switches_port_power() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("usbportctrl port=1 enable"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("usbportctrl controller=0 enable"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("usbportctrl controller=0 port=1"),
        "423- bad parameter"
    );
    assert_eq!(
        session.command("usbportctrl controller=0 port=1 disable enable"),
        "200- OK"
    );
    server.host.lock().backend.hardware.usb_port_result = Err(KernelError::Unsuccessful);
    assert_eq!(
        session.command("usbportctrl controller=1 port=2 disable"),
        "400- "
    );
    let request = |controller, port, enable| UsbPortRequest {
        controller: UsbController(controller),
        port: UsbPort(port),
        enable,
    };

    assert_eq!(
        server.host.lock().backend.hardware.usb_port_requests,
        [request(0, 1, true), request(1, 2, false)]
    );
    server.host.lock().backend.hardware.usb_port_available = false;
    assert_eq!(session.command("usbportctrl"), "414- access denied");
}
