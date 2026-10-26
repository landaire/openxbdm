//! IPTV configuration and CIV commands over TCP.

mod common;

use std::io::Write;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands::console::ConfigSetting;
use openxbdm_server::commands::services::CivProgress;
use openxbdm_server::commands::services::DetectionRoutine;
use openxbdm_server::commands::services::DetectionRoutineMissing;
use openxbdm_server::commands::services::LastError;
use openxbdm_server::processors::ProcessorFlags;
use openxbdm_server_host::backend::services::CivCall;
use openxbdm_server_host::backend::services::SessionState;

use common::RawSession;
use common::TestServer;

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
        (KernelError::AccessDenied, "414- access denied"),
        (KernelError::InvalidParameter, "400- unexpected error"),
    ];

    for (error, reply) in failures {
        {
            let mut host = server.host.lock();
            host.backend
                .console
                .xconfig
                .failures
                .insert(ConfigSetting::new(3, 0xc), error);
            host.backend
                .console
                .xconfig
                .failures
                .insert(ConfigSetting::new(9, 4), error);
        }

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

    server.host.lock().backend.services.thread_failure =
        Some(LastError::Other(Win32Error::new(0x8).unwrap()));
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
        error: KernelError::from_status(NtStatus(0xc000_0139)).unwrap(),
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

/// State and pending injected errors of the simulated XAM service.
#[derive(Debug, PartialEq, Eq)]
struct Verification {
    state: SessionState,
    pending_hash_errors: u32,
    pending_read_errors: u32,
}

fn verification(server: &TestServer) -> Verification {
    let host = server.host.lock();
    let verification = &host.backend.services.verification;
    Verification {
        state: verification.state,
        pending_hash_errors: verification.pending_hash_errors,
        pending_read_errors: verification.pending_read_errors,
    }
}

#[test]
fn civstart_clamps_the_thread_id_and_opens_one_session() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command("civstart threadid=9"),
        "200- XSecurityCreateProcess 0x0"
    );
    assert_eq!(
        session.command("civstart threadid=-1"),
        "200- XSecurityCreateProcess 0x5"
    );
    assert_eq!(session.command("civstop"), "200- XSecurityCloseProcess");
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x0"
    );
    assert_eq!(
        session.command("civstart threadid=3"),
        "200- XSecurityCreateProcess 0x5"
    );
    assert_eq!(
        civ_calls(&server),
        [
            CivCall::CreateProcess { thread_id: 5 },
            CivCall::CreateProcess { thread_id: 5 },
            CivCall::CloseProcess,
            CivCall::CreateProcess { thread_id: 0 },
            CivCall::CreateProcess { thread_id: 3 },
        ]
    );
}

#[test]
fn civverify_needs_a_ready_session() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command("civverify milliseconds=500"),
        "200- XSecurityVerify 0x21"
    );
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x0"
    );
    assert_eq!(
        session.command("civverify milliseconds=500"),
        "200- XSecurityVerify 0x0"
    );
    assert_eq!(
        session.command("civstatus"),
        "200- Blocks Checked 0, Failed Reads 0, Failed Hashes 0, Total Blocks 0, In Progress."
    );
    assert_eq!(session.command("civstop"), "200- XSecurityCloseProcess");
    assert_eq!(
        session.command("civverify milliseconds=500"),
        "200- XSecurityVerify 0x21"
    );
    assert_eq!(verification(&server).state, SessionState::Idle);
}

#[test]
fn civinject_failures_fail_the_next_startup() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command("civinject readerrors=2 hasherrors=1"),
        "200- OK"
    );
    // Pending counts are only replaced once used up.
    assert_eq!(
        session.command("civinject readerrors=7 hasherrors=9"),
        "200- OK"
    );
    assert_eq!(
        verification(&server),
        Verification {
            state: SessionState::Idle,
            pending_hash_errors: 1,
            pending_read_errors: 2,
        }
    );

    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x571"
    );
    assert_eq!(
        verification(&server),
        Verification {
            state: SessionState::Failed,
            pending_hash_errors: 0,
            pending_read_errors: 1,
        }
    );
    assert_eq!(
        session.command("civstatus"),
        "200- XSecurityFailedBlocks returned 0x570"
    );
    assert_eq!(
        session.command("civverify milliseconds=1"),
        "200- XSecurityVerify 0x21"
    );
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x5"
    );

    assert_eq!(session.command("civstop"), "200- XSecurityCloseProcess");
    assert_eq!(
        session.command("civstatus"),
        "200- Blocks Checked 0, Failed Reads 0, Failed Hashes 0, Total Blocks 0, In Progress."
    );
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x571"
    );
    assert_eq!(session.command("civstop"), "200- XSecurityCloseProcess");
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x0"
    );
    assert_eq!(
        verification(&server),
        Verification {
            state: SessionState::Ready,
            pending_hash_errors: 0,
            pending_read_errors: 0,
        }
    );
}

#[test]
fn civinject_without_counts_opens_a_session() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command("civinject readerrors=0 hasherrors=0"),
        "200- OK"
    );
    assert_eq!(verification(&server).state, SessionState::Ready);
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x5"
    );
}

#[test]
fn civstatus_formats_the_progress_record() {
    let server = TestServer::start();
    let mut session = session(&server);

    server.host.lock().backend.services.verification.record = CivProgress {
        failed_reads: 2,
        failed_hashes: 3,
        blocks_checked: 10,
        total_blocks: 100,
        completed: false,
    };
    assert_eq!(
        session.command("civstatus"),
        "200- Blocks Checked 10, Failed Reads 2, Failed Hashes 3, Total Blocks 100, In Progress."
    );

    server.host.lock().backend.services.verification.record = CivProgress {
        failed_reads: 0xffff_ffff,
        failed_hashes: 0,
        blocks_checked: 100,
        total_blocks: 100,
        completed: true,
    };
    assert_eq!(
        session.command("civstatus"),
        "200- Blocks Checked 100, Failed Reads -1, Failed Hashes 0, Total Blocks 100, Completed."
    );

    // A startup clears the checked count, the total and the completion
    // flag; the failure counters stay.
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x0"
    );
    assert_eq!(session.command("civstop"), "200- XSecurityCloseProcess");
    assert_eq!(
        session.command("civstatus"),
        "200- Blocks Checked 0, Failed Reads -1, Failed Hashes 0, Total Blocks 0, In Progress."
    );
}

#[test]
fn civstop_without_a_session_changes_nothing() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(session.command("civstop now"), "200- XSecurityCloseProcess");
    assert_eq!(civ_calls(&server), [CivCall::CloseProcess]);
    assert_eq!(verification(&server).state, SessionState::Idle);
}

#[test]
fn own_thread_commands_run_on_title_connections() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend
            .register_processor(
                b"ttl",
                Some(Box::new(|_, _| Hresult::OK)),
                ProcessorFlags::TITLE,
            )
            .unwrap();
    }
    let mut session = session(&server);

    assert_eq!(session.command("ttl!x"), "200- OK");
    assert_eq!(session.command("civstop"), "200- XSecurityCloseProcess");
    assert_eq!(
        session.command("civverify milliseconds=1"),
        "200- XSecurityVerify 0x21"
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
        "civverify milliseconds=0x20q",
    ] {
        assert_eq!(
            session.command("civstart"),
            "200- XSecurityCreateProcess 0x0"
        );
        assert_eq!(
            session.command(command),
            "200- XSecurityVerify 0x0",
            "{command}"
        );
        assert_eq!(session.command("civstop"), "200- XSecurityCloseProcess");
    }

    let budgets: Vec<u32> = civ_calls(&server)
        .into_iter()
        .filter_map(|call| match call {
            CivCall::Verify { milliseconds } => Some(milliseconds),
            _ => None,
        })
        .collect();

    assert_eq!(budgets, [500, 0x100, 0xffff_ffff, 0x100, 0x100, 0x20]);
}

fn set_clock(server: &TestServer, milliseconds: u64) {
    server.host.lock().backend.services.now = milliseconds;
}

fn progress(checked: u32, reads: u32, hashes: u32, total: u32) -> String {
    format!(
        "200- Blocks Checked {checked}, Failed Reads {reads}, Failed Hashes {hashes}, Total Blocks {total}, In Progress."
    )
}

/// Blocks of the no-media layout.
const TOTAL_BLOCKS: u32 = 264_354;

#[test]
fn civverify_runs_a_pass_until_its_budget_ends() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x0"
    );

    // The first block also reads the hash index block: 200 ms.
    assert_eq!(
        session.command("civverify milliseconds=250"),
        "200- XSecurityVerify 0x0"
    );
    assert_eq!(
        session.command("civverify milliseconds=250"),
        "200- XSecurityVerify 0x21"
    );
    set_clock(&server, 150);
    assert_eq!(session.command("civstatus"), progress(0, 0, 0, 0));
    set_clock(&server, 200);
    assert_eq!(
        session.command("civstatus"),
        progress(1, 0, 0, TOTAL_BLOCKS)
    );
    assert_eq!(
        session.command("civverify milliseconds=250"),
        "200- XSecurityVerify 0x21"
    );

    // The second block ends the pass at 300 ms; the next pass checks
    // blocks of 100 ms until 300 ms have passed.
    set_clock(&server, 300);
    assert_eq!(
        session.command("civverify milliseconds=250"),
        "200- XSecurityVerify 0x0"
    );
    set_clock(&server, 599);
    assert_eq!(
        session.command("civverify milliseconds=250"),
        "200- XSecurityVerify 0x21"
    );
    assert_eq!(
        session.command("civstatus"),
        progress(4, 0, 0, TOTAL_BLOCKS)
    );
    set_clock(&server, 600);
    assert_eq!(
        session.command("civstatus"),
        progress(5, 0, 0, TOTAL_BLOCKS)
    );
    assert_eq!(
        session.command("civverify milliseconds=250"),
        "200- XSecurityVerify 0x0"
    );
}

#[test]
fn civverify_consumes_injected_errors_per_check() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x0"
    );
    assert_eq!(
        session.command("civinject readerrors=1 hasherrors=1"),
        "200- OK"
    );

    // The index read fails and ends the block.
    assert_eq!(
        session.command("civverify milliseconds=1"),
        "200- XSecurityVerify 0x0"
    );
    set_clock(&server, 100);
    assert_eq!(
        session.command("civstatus"),
        progress(1, 1, 0, TOTAL_BLOCKS)
    );

    // The index read succeeds and its hash check fails.
    assert_eq!(
        session.command("civverify milliseconds=1"),
        "200- XSecurityVerify 0x0"
    );
    set_clock(&server, 200);
    assert_eq!(
        session.command("civstatus"),
        progress(2, 1, 1, TOTAL_BLOCKS)
    );

    assert_eq!(
        session.command("civverify milliseconds=1"),
        "200- XSecurityVerify 0x0"
    );
    set_clock(&server, 399);
    assert_eq!(
        session.command("civverify milliseconds=1"),
        "200- XSecurityVerify 0x21"
    );
    set_clock(&server, 400);
    assert_eq!(
        session.command("civstatus"),
        progress(3, 1, 1, TOTAL_BLOCKS)
    );

    // The next session's verifier starts from the failure counts.
    assert_eq!(session.command("civstop"), "200- XSecurityCloseProcess");
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x0"
    );
    assert_eq!(
        session.command("civverify milliseconds=1"),
        "200- XSecurityVerify 0x0"
    );
    set_clock(&server, 600);
    assert_eq!(
        session.command("civstatus"),
        progress(1, 1, 1, TOTAL_BLOCKS)
    );
}

#[test]
fn civstop_ends_an_unlimited_pass_after_its_block() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x0"
    );

    // Each block of an unlimited pass is followed by a 200 ms wait.
    assert_eq!(
        session.command("civverify milliseconds=-1"),
        "200- XSecurityVerify 0x0"
    );
    set_clock(&server, 1000);
    assert_eq!(
        session.command("civstatus"),
        progress(3, 0, 0, TOTAL_BLOCKS)
    );
    assert_eq!(
        session.command("civverify milliseconds=100"),
        "200- XSecurityVerify 0x21"
    );

    assert_eq!(session.command("civstop"), "200- XSecurityCloseProcess");
    assert_eq!(
        session.command("civstatus"),
        progress(0, 0, 0, TOTAL_BLOCKS)
    );
    assert_eq!(verification(&server).state, SessionState::Idle);
}

#[test]
fn detected_hash_failure_makes_passes_unlimited() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("civsetbits on=12"),
        "200- Result 0x0; old mask 0x0, new mask 0x1000"
    );
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x0"
    );

    // The budget is ignored; the worker waits 200 ms once more than 300 ms
    // have passed since the last wait: blocks end at 200, 300, 400 (wait
    // to 600), 700, 800 (wait to 1000).
    assert_eq!(
        session.command("civverify milliseconds=100"),
        "200- XSecurityVerify 0x0"
    );
    set_clock(&server, 1000);
    assert_eq!(
        session.command("civstatus"),
        progress(5, 0, 0, TOTAL_BLOCKS)
    );
    assert_eq!(
        session.command("civverify milliseconds=100"),
        "200- XSecurityVerify 0x21"
    );
}

/// The devkit sequence with an empty tray: the checked count accumulates
/// over the passes of a session. Observed: 4 after the first pass, 23
/// three seconds into the unlimited pass (4 + 5 + 5 + 9).
#[test]
fn checked_blocks_accumulate_over_the_passes_of_a_session() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("civstart"),
        "200- XSecurityCreateProcess 0x0"
    );

    // First block 200 ms (with the hash index block), then 100 ms each.
    assert_eq!(
        session.command("civverify milliseconds=500"),
        "200- XSecurityVerify 0x0"
    );
    set_clock(&server, 1000);
    assert_eq!(
        session.command("civstatus"),
        progress(4, 0, 0, TOTAL_BLOCKS)
    );

    assert_eq!(
        session.command("civverify milliseconds=500"),
        "200- XSecurityVerify 0x0"
    );
    assert_eq!(
        session.command("civverify milliseconds=500"),
        "200- XSecurityVerify 0x21"
    );
    set_clock(&server, 2000);
    assert_eq!(
        session.command("civverify milliseconds=500"),
        "200- XSecurityVerify 0x0"
    );
    set_clock(&server, 3000);
    assert_eq!(
        session.command("civstatus"),
        progress(14, 0, 0, TOTAL_BLOCKS)
    );

    // Unlimited: a 100 ms block, then a 200 ms wait; the ninth block ends
    // 2500 ms after the start, the tenth 2800 ms.
    assert_eq!(
        session.command("civverify milliseconds=-1"),
        "200- XSecurityVerify 0x0"
    );
    set_clock(&server, 5799);
    assert_eq!(
        session.command("civstatus"),
        progress(23, 0, 0, TOTAL_BLOCKS)
    );
    set_clock(&server, 5800);
    assert_eq!(
        session.command("civstatus"),
        progress(24, 0, 0, TOTAL_BLOCKS)
    );

    assert_eq!(session.command("civstop"), "200- XSecurityCloseProcess");
    assert_eq!(
        session.command("civstatus"),
        progress(0, 0, 0, TOTAL_BLOCKS)
    );
}

/// The devkit sequence of the gaps run: a successful startup clears the
/// total a pass left; failed startups do not, and count no failures.
#[test]
fn successful_startup_clears_the_total() {
    let server = TestServer::start();
    let mut session = session(&server);

    for (command, reply) in [
        ("civstart", "200- XSecurityCreateProcess 0x0"),
        ("civstart", "200- XSecurityCreateProcess 0x5"),
        ("civverify milliseconds=100", "200- XSecurityVerify 0x0"),
        ("civstop", "200- XSecurityCloseProcess"),
        ("civverify milliseconds=100", "200- XSecurityVerify 0x21"),
        ("civinject readerrors=2 hasherrors=1", "200- OK"),
        ("civstart", "200- XSecurityCreateProcess 0x571"),
        ("civstatus", "200- XSecurityFailedBlocks returned 0x570"),
        ("civstop", "200- XSecurityCloseProcess"),
        ("civstatus", &progress(0, 0, 0, TOTAL_BLOCKS)),
        ("civstart", "200- XSecurityCreateProcess 0x571"),
        ("civstop", "200- XSecurityCloseProcess"),
        ("civstart", "200- XSecurityCreateProcess 0x0"),
        ("civstop", "200- XSecurityCloseProcess"),
        ("civstatus", &progress(0, 0, 0, 0)),
    ] {
        assert_eq!(session.command(command), reply, "{command}");
    }
}
