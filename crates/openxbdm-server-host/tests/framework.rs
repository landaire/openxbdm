//! Connection framework behavior over TCP.

mod common;

use common::TestServer;
use common::run;

#[test]
fn banner_unknown_command_and_bye() {
    let server = TestServer::start();
    let mut session = server.raw();
    assert_eq!(session.line(), "201- connected");
    assert_eq!(session.command("notacommand"), "407- unknown command");
    assert_eq!(session.command(""), "407- unknown command");
    assert_eq!(session.command("BYE"), "200- bye");
}

#[test]
fn overlong_line_is_rejected_and_discarded() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    session.send(&"x".repeat(0x300));
    assert_eq!(session.line(), "446- line too long");
    assert_eq!(session.command("dmversion"), "200- 2.0.21256.0");
}

#[test]
fn ninth_connection_is_refused() {
    let server = TestServer::start();
    let mut sessions: Vec<_> = (0..8).map(|_| server.raw()).collect();
    for session in &mut sessions {
        assert_eq!(session.line(), "201- connected");
    }
    let mut extra = server.raw();
    assert_eq!(extra.line(), "401- max number of connections exceeded");
}

#[test]
fn client_reads_console_identity_and_memory() {
    use openxbdm_client::commands::ConsoleType;
    use openxbdm_client::commands::DbgName;
    use openxbdm_client::commands::DmVersion;
    use openxbdm_client::commands::GetConsoleFeatures;
    use openxbdm_client::commands::GetConsoleType;
    use openxbdm_client::commands::GetMem;
    use openxbdm_client::commands::GetPid;
    use openxbdm_client::commands::SetMem;
    use openxbdm_server_host::backend::memory::MEMORY_BASE;

    let server = TestServer::start();
    run(async {
        let mut client = server.client().await;
        assert_eq!(client.run(DmVersion).await.unwrap(), "2.0.21256.0");
        assert_eq!(client.run(DbgName::Get).await.unwrap(), "openxbdm-mock");
        client
            .run(DbgName::Set("Development Kit".to_owned()))
            .await
            .unwrap();
        assert_eq!(client.run(DbgName::Get).await.unwrap(), "Development Kit");
        let pid = client.run(GetPid).await.unwrap();
        assert_ne!(pid, 0);
        assert_eq!(client.run(GetPid).await.unwrap(), pid);
        assert_eq!(
            client.run(GetConsoleType).await.unwrap(),
            ConsoleType::DevKit
        );
        assert_eq!(
            client.run(GetConsoleFeatures).await.unwrap().flags,
            ["DEBUGGING", "1GB_RAM"]
        );

        let written = client
            .run(SetMem {
                address: MEMORY_BASE + 2,
                data: vec![0xAA, 0xBB, 0xCC],
            })
            .await
            .unwrap();
        assert_eq!(written.written, 3);
        let snapshot = client
            .run(GetMem {
                address: MEMORY_BASE,
                length: 8,
            })
            .await
            .unwrap();
        assert_eq!(snapshot.data, [0, 1, 0xAA, 0xBB, 0xCC, 5, 6, 7]);
        client.bye().await.unwrap();
    });
}

#[test]
fn getmem_marks_unmapped_bytes_and_wraps_lines() {
    use openxbdm_server_host::backend::memory::MEMORY_BASE;

    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    session.send(&format!("getmem addr=0x{:08x} length=34", MEMORY_BASE - 2));
    assert_eq!(session.line(), "202- memory data follows");
    let lines = session.multiline();
    assert_eq!(lines.len(), 2);
    let expected = format!(
        "????{}",
        (0u8..0x1e)
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    );
    assert_eq!(lines[0], expected);
    assert_eq!(lines[1], "1E1F");
}

#[test]
fn setmem_reports_partial_writes_and_syntax_errors() {
    use openxbdm_server_host::backend::memory::MEMORY_BASE;
    use openxbdm_server_host::backend::memory::MEMORY_SIZE;

    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    let end = MEMORY_BASE + MEMORY_SIZE as u32 - 1;
    assert_eq!(
        session.command(&format!("setmem addr=0x{end:08x} data=AABB")),
        "404- set 1 bytes"
    );
    assert_eq!(
        session.command(&format!("setmem addr=0x{MEMORY_BASE:08x} data=AG")),
        "400- 400- syntax error in data"
    );
    assert_eq!(
        session.command(&format!("setmem addr=0x{MEMORY_BASE:08x}")),
        "200- set 0 bytes"
    );
    assert_eq!(session.command("setmem data=00"), "400- missing addr");
}
