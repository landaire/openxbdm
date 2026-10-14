//! IPTV configuration and CIV commands over TCP.

mod common;

use std::io::Write;

use common::RawSession;
use common::TestServer;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::console::ConfigSetting;
use openxbdm_server::commands::services::CivProgress;
use openxbdm_server::commands::services::CivResult;
use openxbdm_server::commands::services::DetectionRoutine;
use openxbdm_server::commands::services::DetectionRoutineMissing;
use openxbdm_server::commands::services::LastError;
use openxbdm_server::processors::ProcessorFlags;
use openxbdm_server_host::backend::services::CivCall;

fn session(server: &TestServer) -> RawSession {
    let mut session = server.raw();
    session.line();
    session
}

fn iptv_flags(server: &TestServer) -> u32 {
    server.host.lock().backend.console.xconfig.dword(3, 0xc)
}

/// Big-endian UTF-16 encoding of `text` padded with zeros to `size` bytes.
fn stored(text: &[u8], size: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = text
        .iter()
        .flat_map(|&byte| (i16::from(byte as i8) as u16).to_be_bytes())
        .collect();
    bytes.resize(size, 0);
    bytes
}

fn iptv_string(server: &TestServer, index: u16) -> Vec<u8> {
    server
        .host
        .lock()
        .backend
        .console
        .xconfig
        .value(9, index)
        .unwrap()
        .to_vec()
}

fn civ_calls(server: &TestServer) -> Vec<CivCall> {
    server.host.lock().backend.services.calls.clone()
}

#[test]
fn iptv_switches_set_and_clear_their_bits() {
    let server = TestServer::start();
    server.host.lock().backend.console.xconfig.settings.insert(
        ConfigSetting::new(3, 0xc),
        0x0000_0005u32.to_be_bytes().to_vec(),
    );
    let mut session = session(&server);

    assert_eq!(session.command("iptv enable"), "200- OK");
    assert_eq!(iptv_flags(&server), 0x0000_1005);
    assert_eq!(session.command("iptvdvr enable"), "200- OK");
    assert_eq!(iptv_flags(&server), 0x0008_1005);
    assert_eq!(session.command("iptvallowuninstall disable"), "200- OK");
    assert_eq!(iptv_flags(&server), 0x0208_1005);
    assert_eq!(session.command("iptvallowuninstall enable"), "200- OK");
    assert_eq!(iptv_flags(&server), 0x0008_1005);
    assert_eq!(session.command("iptvdvr disable"), "200- OK");
    assert_eq!(session.command("iptv disable"), "200- OK");
    assert_eq!(iptv_flags(&server), 0x0000_0005);
}

#[test]
fn iptv_switches_test_enable_first_and_require_a_flag() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("iptv disable enable"), "200- OK");
    assert_eq!(iptv_flags(&server), 0x1000);
    assert_eq!(session.command("iptv"), "400- missing arguments");
    assert_eq!(session.command("iptvdvr enabled"), "400- missing arguments");
    assert_eq!(session.command("iptvallowuninstall disable=0"), "200- OK");
    assert_eq!(iptv_flags(&server), 0x0200_1000);
}

#[test]
fn iptv_switches_fall_back_without_the_modify_export() {
    let server = TestServer::start();
    server.host.lock().backend.console.xconfig.modify_export = false;
    let mut session = session(&server);
    assert_eq!(session.command("iptvdvr enable"), "200- OK");
    assert_eq!(session.command("iptv enable"), "200- OK");
    assert_eq!(iptv_flags(&server), 0x0008_1000);
}

#[test]
fn iptv_failures_map_kernel_status() {
    let server = TestServer::start();
    let mut session = session(&server);
    let failures = [
        (0xc000_0022, "414- access denied"),
        (0xc000_000d, "400- unexpected error"),
    ];
    for (status, reply) in failures {
        let mut host = server.host.lock();
        host.backend
            .console
            .xconfig
            .failures
            .insert(ConfigSetting::new(3, 0xc), NtStatus(status));
        host.backend
            .console
            .xconfig
            .failures
            .insert(ConfigSetting::new(9, 4), NtStatus(status));
        drop(host);
        assert_eq!(session.command("iptv enable"), reply);
        assert_eq!(session.command("iptvbootstrapurl x"), reply);
    }
}

#[test]
fn iptv_strings_are_read_at_fixed_offsets() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command(r#"iptvprovidername Some"Name x"y z"#),
        "200- OK"
    );
    assert_eq!(iptv_string(&server, 1), stored(b"SomeName xy", 0x78));
    assert_eq!(
        session.command("iptvprovisioningurl http://a/b c"),
        "200- OK"
    );
    assert_eq!(iptv_string(&server, 2), stored(b"http://a/b", 0x80));
    assert_eq!(session.command("iptvsupportinfo  second"), "200- OK");
    assert_eq!(iptv_string(&server, 3), stored(b"", 0x80));
    assert_eq!(session.command("IPTVBOOTSTRAPURL key=value"), "200- OK");
    assert_eq!(iptv_string(&server, 4), stored(b"key=value", 0x80));
}

#[test]
fn iptv_strings_truncate_and_sign_extend() {
    let server = TestServer::start();
    let mut session = session(&server);
    let long = "u".repeat(100);
    assert_eq!(
        session.command(&format!("iptvprovidername {long}")),
        "200- OK"
    );
    assert_eq!(iptv_string(&server, 1), stored(&[b'u'; 59], 0x78));
    assert_eq!(
        session.command(&format!("iptvbootstrapurl {long}")),
        "200- OK"
    );
    assert_eq!(iptv_string(&server, 4), stored(&[b'u'; 63], 0x80));

    session
        .stream
        .write_all(b"iptvsupportinfo a\xe9\x80\r\n")
        .unwrap();
    assert_eq!(session.line(), "200- OK");
    assert_eq!(
        &iptv_string(&server, 3)[..8],
        &[0x00, 0x61, 0xff, 0xe9, 0xff, 0x80, 0x00, 0x00]
    );
}

#[test]
fn iptv_strings_past_a_short_line_read_the_receive_buffer() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("iptvsupportinfo ABCDEFGHIJ"), "200- OK");
    assert_eq!(session.command("iptvsupportinfo"), "200- OK");
    assert_eq!(iptv_string(&server, 3), stored(b"\nBCDEFGHIJ", 0x80));
}

#[test]
fn civfail_reports_the_thread_handle() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("civfail"),
        "200- Thread created: 0xF8000040"
    );
    assert_eq!(
        session.command("civfail reboot=2z"),
        "200- Thread created: 0xF8000044"
    );
    assert_eq!(
        session.command("civfail reboot=0"),
        "200- Thread created: 0xF8000048"
    );
    assert_eq!(
        civ_calls(&server),
        [
            CivCall::Failure { reboot: false },
            CivCall::Failure { reboot: true },
            CivCall::Failure { reboot: false }
        ]
    );

    server.host.lock().backend.services.thread_failure = Some(LastError(0x8));
    assert_eq!(
        session.command("civfail reboot=1"),
        "200- CreateThread failed 0x8"
    );
}

#[test]
fn civinject_names_the_last_missing_count() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("civinject readerrors=3 hasherrors=0x10"),
        "200- OK"
    );
    assert_eq!(session.command("civinject"), "200- missing hasherrors");
    assert_eq!(
        session.command("civinject hasherrors=5"),
        "200- missing readerrors"
    );
    assert_eq!(
        session.command("civinject readerrors=7x hasherrors=2"),
        "200- missing readerrors"
    );
    assert_eq!(
        civ_calls(&server),
        [
            CivCall::Inject {
                hash_errors: 0x10,
                read_errors: 3
            },
            CivCall::Inject {
                hash_errors: 0,
                read_errors: 0
            },
            CivCall::Inject {
                hash_errors: 5,
                read_errors: 0
            },
            CivCall::Inject {
                hash_errors: 2,
                read_errors: 0
            },
        ]
    );
}

#[test]
fn civsetbits_reinitializes_then_sets_one_bit() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("civsetbits on=3"),
        "200- Result 0x0; old mask 0x0, new mask 0x8"
    );
    assert_eq!(
        session.command("civsetbits on=5"),
        "200- Result 0x0; old mask 0x8, new mask 0x20"
    );
    assert_eq!(
        session.command("civsetbits on=0"),
        "200- Result 0x0; old mask 0x20, new mask 0x0"
    );
    assert_eq!(
        session.command("civsetbits on=33"),
        "200- Result 0x0; old mask 0x0, new mask 0x0"
    );
    assert_eq!(
        server.host.lock().backend.services.detection_mask,
        Some(1 << 33)
    );
    assert_eq!(
        session.command("civsetbits on=64"),
        "200- Result 0xc000000d; old mask 0x0, new mask 0x0"
    );
    assert_eq!(
        session.command("civsetbits on=1z"),
        "200- Result 0x0; old mask 0x0, new mask 0x2"
    );

    server.host.lock().backend.services.detection_mask = None;
    assert_eq!(
        session.command("civsetbits"),
        "200- Result 0x0; old mask 0xffffffff, new mask 0x0"
    );
}

#[test]
fn civsetbits_reports_an_unresolved_export() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .services
        .missing_detection_routine = Some(DetectionRoutineMissing {
        routine: DetectionRoutine::GetDetected,
        status: NtStatus(0xc000_0139),
    });
    let mut session = session(&server);
    assert_eq!(
        session.command("civsetbits on=2"),
        "200- Result 0xc0000139; old mask 0xbaadf00d, new mask 0xdeadbeef"
    );
    assert_eq!(
        server
            .host
            .lock()
            .backend
            .debug_output
            .last()
            .map(Vec::as_slice),
        Some(&b"Cannot load ordinal 662 (GET_DETECTED): 0xc0000139\n"[..])
    );
}

#[test]
fn civsetbits_is_absent_on_test_kits() {
    let server = TestServer::start();
    server.host.lock().backend.test_kit = true;
    let mut session = session(&server);
    assert_eq!(session.command("civsetbits on=1"), "407- unknown command");
    assert_eq!(
        session.command("civstatus"),
        "200- Blocks Checked 0, Failed Reads 0, Failed Hashes 0, Total Blocks 0, In Progress."
    );
}

#[test]
fn civstart_clamps_the_thread_id() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("civstart threadid=9"),
        "200- XSecurityCreateProcess 0x0"
    );
    assert_eq!(
        session.command("civstart threadid=-1"),
        "200- XSecurityCreateProcess 0x0"
    );
    server.host.lock().backend.services.create_result = CivResult(0x8007_0005);
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x80070005"
    );
    assert_eq!(
        session.command("civstart threadid=3"),
        "200- XSecurityCreateProcess 0x80070005"
    );
    assert_eq!(
        civ_calls(&server),
        [
            CivCall::CreateProcess { thread_id: 5 },
            CivCall::CreateProcess { thread_id: 5 },
            CivCall::CreateProcess { thread_id: 0 },
            CivCall::CreateProcess { thread_id: 3 },
        ]
    );
}

#[test]
fn civstatus_formats_the_progress_record() {
    let server = TestServer::start();
    let mut session = session(&server);
    server.host.lock().backend.services.progress = Ok(CivProgress {
        failed_reads: 2,
        failed_hashes: 3,
        blocks_checked: 10,
        total_blocks: 100,
        completed: false,
    });
    assert_eq!(
        session.command("civstatus"),
        "200- Blocks Checked 10, Failed Reads 2, Failed Hashes 3, Total Blocks 100, In Progress."
    );
    server.host.lock().backend.services.progress = Ok(CivProgress {
        failed_reads: 0xffff_ffff,
        failed_hashes: 0,
        blocks_checked: 100,
        total_blocks: 100,
        completed: true,
    });
    assert_eq!(
        session.command("civstatus"),
        "200- Blocks Checked 100, Failed Reads -1, Failed Hashes 0, Total Blocks 100, Completed."
    );
    server.host.lock().backend.services.progress = Err(CivResult(0x8000_4005));
    assert_eq!(
        session.command("civstatus"),
        "200- XSecurityFailedBlocks returned 0x80004005"
    );
}

#[test]
fn civstop_closes_the_process() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("civstop now"), "200- XSecurityCloseProcess");
    assert_eq!(civ_calls(&server), [CivCall::CloseProcess]);
}

#[test]
fn own_thread_commands_run_on_title_connections() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend.register_processor(
            b"ttl",
            Some(Box::new(|_, _| Hresult::OK)),
            ProcessorFlags::TITLE,
        );
    }
    let mut session = session(&server);
    assert_eq!(session.command("ttl!x"), "200- OK");
    assert_eq!(session.command("civstop"), "200- XSecurityCloseProcess");
    assert_eq!(
        session.command("civverify milliseconds=1"),
        "200- XSecurityVerify 0x0"
    );
    assert_eq!(
        session.command("civstatus"),
        "422- dedicated connection required"
    );
    assert_eq!(
        session.command("iptv enable"),
        "422- dedicated connection required"
    );
}

#[test]
fn civverify_replaces_non_positive_budgets() {
    let server = TestServer::start();
    let mut session = session(&server);
    for command in [
        "civverify milliseconds=500",
        "civverify milliseconds=0",
        "civverify milliseconds=-1",
        "civverify milliseconds=-5",
        "civverify",
    ] {
        assert_eq!(
            session.command(command),
            "200- XSecurityVerify 0x0",
            "{command}"
        );
    }
    server.host.lock().backend.services.verify_result = CivResult(0x103);
    assert_eq!(
        session.command("civverify milliseconds=0x20q"),
        "200- XSecurityVerify 0x103"
    );
    let budgets: Vec<u32> = civ_calls(&server)
        .into_iter()
        .map(|call| match call {
            CivCall::Verify { milliseconds } => milliseconds,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(budgets, [500, 0x100, 0xffff_ffff, 0x100, 0x100, 0x20]);
}
