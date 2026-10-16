//! Memory, module, and image inspection commands over TCP.

mod common;

use std::io::Read;

use common::RawSession;
use common::TestServer;
use common::run;
use openxbdm_client::commands::GetMem;
use openxbdm_client::commands::ModuleSections;
use openxbdm_client::commands::Modules;
use openxbdm_client::commands::SectionFlags;
use openxbdm_client::commands::SetMem;
use openxbdm_client::commands::VirtualRegion;
use openxbdm_client::commands::WalkMem;
use openxbdm_client::commands::XbeInfo;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::memory::TrackingFlags;
use openxbdm_server::commands::memory::detour::EntryId;
use openxbdm_server::commands::memory::detour::ReturnValue;
use openxbdm_server_host::backend::memory::MEMORY_BASE;
use openxbdm_server_host::backend::memory::detour::CallOutcome;
use openxbdm_server_host::backend::memory::detour::SimulatedCall;

fn session(server: &TestServer) -> RawSession {
    let mut session = server.raw();
    assert_eq!(session.line(), "201- connected");
    session
}

fn read_bytes(session: &mut RawSession, count: usize) -> Vec<u8> {
    let mut bytes = vec![0; count];
    session.reader.read_exact(&mut bytes).unwrap();
    bytes
}

/// Read one `getmemex` chunk: the little-endian header and its data.
fn read_chunk(session: &mut RawSession) -> (u16, Vec<u8>) {
    let header = u16::from_le_bytes(read_bytes(session, 2).try_into().unwrap());
    let data = read_bytes(session, usize::from(header & 0x7fff));
    (header, data)
}

#[test]
fn client_reads_and_writes_memory() {
    let server = TestServer::start();
    run(async {
        let mut client = server.client().await;
        let written = client
            .run(SetMem {
                address: MEMORY_BASE + 0x40,
                data: vec![0x12, 0x34],
            })
            .await
            .unwrap();
        assert_eq!((written.requested, written.written), (2, 2));
        let snapshot = client
            .run(GetMem {
                address: MEMORY_BASE + 0x3f,
                length: 4,
            })
            .await
            .unwrap();
        assert_eq!(snapshot.data, [0x3f, 0x12, 0x34, 0x42]);
        assert!(snapshot.unmapped_offsets.is_empty());

        let partial = client
            .run(SetMem {
                address: 0x3000_1fff,
                data: vec![0xaa, 0xbb],
            })
            .await
            .unwrap();
        assert_eq!((partial.requested, partial.written), (2, 1));
        let empty = client
            .run(SetMem {
                address: MEMORY_BASE,
                data: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(empty.written, 0);
        assert!(
            client
                .run(GetMem {
                    address: MEMORY_BASE,
                    length: 0
                })
                .await
                .unwrap()
                .data
                .is_empty()
        );
    });
}

#[test]
fn memory_commands_see_original_bytes_under_breakpoints() {
    let server = TestServer::start();
    let mut session = session(&server);
    let address = MEMORY_BASE + 0x100;
    assert_eq!(
        session.command(&format!("setmem addr=0x{address:08x} data=11223344")),
        "200- set 4 bytes"
    );
    assert_eq!(
        session.command(&format!("break addr=0x{address:08x}")),
        "200- OK"
    );
    let patched = server.host.lock().backend.memory.regions[4].bytes[0x100..0x104].to_vec();
    assert_ne!(patched, [0x11, 0x22, 0x33, 0x44]);

    session.send(&format!("getmem addr=0x{:08x} length=6", address - 1));
    assert_eq!(session.line(), "202- memory data follows");
    assert_eq!(session.multiline(), ["FF1122334404"]);

    assert_eq!(
        session.command(&format!("setmem addr=0x{:08x} data=AABB", address + 1)),
        "200- set 2 bytes"
    );
    assert_eq!(
        server.host.lock().backend.memory.regions[4].bytes[0x100..0x104],
        patched
    );

    assert_eq!(
        session.command(&format!("getmemex addr=0x{address:08x} length=4")),
        "203- binary response follows"
    );
    assert_eq!(
        read_chunk(&mut session),
        (0x8004, vec![0x11, 0xaa, 0xbb, 0x44])
    );

    assert_eq!(
        session.command(&format!("break clear addr=0x{address:08x}")),
        "200- OK"
    );
    assert_eq!(
        server.host.lock().backend.memory.regions[4].bytes[0x100..0x104],
        [0x11, 0xaa, 0xbb, 0x44]
    );
}

#[test]
fn getmem_failed_read_in_a_valid_page_leaves_a_gap_and_masks_the_page() {
    let server = TestServer::start();
    let mut session = session(&server);
    session.send("getmem addr=0x7fe9fff0 length=0x20");
    assert_eq!(session.line(), "202- memory data follows");
    let lines = session.multiline();
    assert_eq!(lines.len(), 1);
    let line = lines[0].as_bytes();
    assert_eq!(line.len(), 64);
    assert_eq!(&line[..32], b"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
    assert_eq!(&line[34..], "??".repeat(15).as_bytes());
}

#[test]
fn getmemex_streams_chunks_and_stops_at_unreadable_pages() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(&format!("getmemex addr=0x{:08x} length=0x500", MEMORY_BASE)),
        "203- binary response follows"
    );
    let (header, data) = read_chunk(&mut session);
    assert_eq!(header, 0x400);
    assert_eq!(
        data,
        (0..0x400).map(|offset| offset as u8).collect::<Vec<_>>()
    );
    let (header, data) = read_chunk(&mut session);
    assert_eq!(header, 0x8100);
    assert_eq!(data.len(), 0x100);

    assert_eq!(
        session.command("getmemex addr=0x7fe9fff8 length=0x20"),
        "203- binary response follows"
    );
    let (header, data) = read_chunk(&mut session);
    assert_eq!(header, 0x8008);
    assert_eq!(data, [0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff]);

    assert_eq!(
        session.command("getmemex addr=0x7fea0000 length=0x20"),
        "203- binary response follows"
    );
    assert_eq!(read_chunk(&mut session), (0x8000, Vec::new()));

    assert_eq!(
        session.command("getmemex addr=0x80000000 length=0"),
        "203- binary response follows"
    );
    assert_eq!(
        session.command("getmemex addr=0x80000000"),
        "400- missing LENGTH"
    );
    assert_eq!(session.command("getmemex length=1"), "400- missing ADDR");
}

#[test]
fn getmem2_reads_the_whole_last_trampoline_page() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("getmemex addr=0x91f23000 length=0x400"),
        "203- binary response follows"
    );
    let (_, data) = read_chunk(&mut session);
    // The trampolines end at 0x91f231f0; the rest of the page reads as zero.
    assert!(data[0x1f0..].iter().all(|&byte| byte == 0));
}

#[test]
fn walkmem_reports_valid_ranges_without_device_pages() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("walkmem"),
        "202- Valid Virtual Address Ranges Follow"
    );
    assert_eq!(
        session.multiline(),
        [
            "base=0x30000000 size=0x00002000 protect=0x00000004",
            "base=0x30003000 size=0x00001000 protect=0x00000004",
            "base=0x40000000 size=0x00020000 protect=0x00000004",
            "base=0x7fe90000 size=0x00010000 protect=0x00000004",
            "base=0x80000000 size=0x00100000 protect=0x00000040",
            "base=0x90000000 size=0x00003000 protect=0x00000040",
            "base=0x91f13000 size=0x00011000 protect=0x00000040",
        ]
    );

    run(async {
        let mut client = server.client().await;
        let regions = client.run(WalkMem).await.unwrap();
        assert_eq!(
            regions[4],
            VirtualRegion {
                base: 0x8000_0000,
                size: 0x10_0000,
                protect: 0x40
            }
        );
    });
}

#[test]
fn modules_lists_flagged_modules_in_loader_order() {
    let server = TestServer::start();
    let mut session = session(&server);
    session.send("modules");
    assert_eq!(session.line(), "202- multiline response follows");
    assert_eq!(
        session.multiline(),
        [
            "name=\"xboxkrnl.exe\" base=0x80040000 size=0x00230000 check=0x00241d5e timestamp=0x4b6f0a10 pdata=0x80046000 psize=0x0008c4a0 thread=0x00000000 osize=0x00230000",
            "name=\"xam.xex\" base=0x81700000 size=0x00800000 check=0x007f1a2b timestamp=0x4b6f0a12 pdata=0x81702000 psize=0x00031000 dll thread=0x00000000 osize=0x00780000",
            "name=\"default.xex\" base=0x82000000 size=0x00100000 check=0x00000000 timestamp=0x5e1f2a3b pdata=0x82001000 psize=0x00000400 thread=0x00000000 osize=0x000f0000",
        ]
    );

    run(async {
        let mut client = server.client().await;
        let modules = client.run(Modules).await.unwrap();
        assert_eq!(
            modules
                .iter()
                .map(|module| module.name.as_str())
                .collect::<Vec<_>>(),
            ["xboxkrnl.exe", "xam.xex", "default.xex"]
        );
        assert!(modules[1].is_dll);
        assert_eq!(modules[1].osize, 0x78_0000);
    });
}

#[test]
fn modsections_reports_section_flags_and_lookup_errors() {
    let server = TestServer::start();
    let mut session = session(&server);
    session.send("modsections name=XAM.XEX");
    assert_eq!(session.line(), "202- multiline response follows");
    assert_eq!(
        session.multiline(),
        [
            "name=\".rdata\" base=0x81701000 size=0x00001000 index=1 flags=2",
            "name=\".text\" base=0x81702000 size=0x00400000 index=2 flags=10",
            "name=\".bss\" base=0x81b02000 size=0x00020000 index=3 flags=22",
        ]
    );
    // Lookup includes modules `modules` omits.
    session.send("modsections name=\"bootanim.xex\"");
    assert_eq!(session.line(), "202- multiline response follows");
    assert_eq!(session.multiline().len(), 1);
    assert_eq!(
        session.command("modsections name=xam"),
        "403- no such module"
    );
    assert_eq!(session.command("modsections"), "400- missing name");

    run(async {
        let mut client = server.client().await;
        let sections = client
            .run(ModuleSections {
                module: "default.xex".to_owned(),
            })
            .await
            .unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(
            sections[0].flags,
            SectionFlags(SectionFlags::READABLE | SectionFlags::EXECUTABLE)
        );
    });
}

#[test]
fn pdbinfo_formats_guid_age_and_path() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("pdbinfo addr=0x81700000"),
        "200- 9A1B2C3D4E5F60718293A4B5C6D7E8F902000000e:\\build\\xam.pdb"
    );
    assert_eq!(
        session.command("pdbinfo addr=0x82000000"),
        "200- 1111111111111111111111111111111101000000d:\\title\\default.pdb"
    );
    assert_eq!(
        session.command("pdbinfo addr=0x80040000"),
        "400- HRESULT 0x80070490"
    );
    assert_eq!(
        session.command("pdbinfo addr=0x12345678"),
        "400- HRESULT 0x80070490"
    );
    assert_eq!(session.command("pdbinfo"), "400- HRESULT 0x80070057");
}

#[test]
fn xexfield_dumps_field_data() {
    let server = TestServer::start();
    let mut session = session(&server);
    let field = |session: &mut RawSession, command: &str| {
        assert_eq!(session.command(command), "202- multiline response follows");
        session.multiline()
    };
    assert_eq!(
        field(&mut session, "xexfield module=xam.xex field=0x10100"),
        ["fieldsize=0x00000004", "00001234"]
    );
    assert_eq!(
        field(&mut session, "xexfield module=xam.xex field=0x10001"),
        ["fieldsize=0x00000004", "DEADBEEF"]
    );
    assert_eq!(
        field(&mut session, "xexfield module=XAM.xex field=0x18002"),
        ["fieldsize=0x00000008", "0001020304050607"]
    );
    let blob = field(&mut session, "xexfield module=xam.xex field=0x183ff");
    assert_eq!(blob[0], "fieldsize=0x00000028");
    assert_eq!(
        blob[1],
        "00000028A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABB"
    );
    assert_eq!(blob[2], "BCBDBEBFC0C1C2C3");
    assert_eq!(blob.len(), 3);

    assert_eq!(
        session.command("xexfield module=xam.xex field=0x20000"),
        "200- OK"
    );
    assert_eq!(
        session.command("xexfield module=xam.xex field=0x30000"),
        "437- "
    );
    assert_eq!(
        session.command("xexfield module=xam field=0x10100"),
        "403- no such module"
    );
    assert_eq!(
        session.command("xexfield module=xam.xex"),
        "400- missing field"
    );
    assert_eq!(session.command("xexfield field=1"), "400- missing module");
}

#[test]
fn xbeinfo_reports_the_running_executable_for_every_name() {
    let server = TestServer::start();
    let mut session = session(&server);
    for command in [
        "xbeinfo running",
        "xbeinfo name=\"e:\\other.xex\"",
        "xbeinfo running name=x ondiskonly",
    ] {
        assert_eq!(session.command(command), "202- multiline response follows");
        assert_eq!(
            session.multiline(),
            [
                "timestamp=0x00000000 checksum=0x00000000",
                "name=\"E:\\title\\default.xex\""
            ]
        );
    }
    assert_eq!(
        session.command("xbeinfo name=\"e:\\title\\default.xex\" ondiskonly"),
        "402- file not found"
    );
    assert_eq!(session.command("xbeinfo"), "400- missing name");

    run(async {
        let mut client = server.client().await;
        let named = client
            .run(XbeInfo::Named("e:\\other.xex".to_owned()))
            .await
            .unwrap();
        assert_eq!(named.name, "E:\\title\\default.xex");
        assert_eq!((named.timestamp, named.checksum), (0, 0));
    });
}

#[test]
fn addtitlemem_reads_the_title_field_in_extended_memory() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("addtitlemem"), "200- addtitlemem=0x4000000");
    server.host.lock().backend.memory.title_module = None;
    assert_eq!(session.command("addtitlemem"), "403- no such module");
}

#[test]
fn advmem_toggles_the_flash_flag() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("advmem status"), "200- disabled");
    assert_eq!(session.command("advmem off"), "200- already disabled");
    assert_eq!(session.command("advmem on"), "200- enabled");
    assert_eq!(server.host.lock().backend.memory.flash[6..8], [0, 0]);
    assert_eq!(session.command("advmem on"), "200- already enabled");
    assert_eq!(session.command("advmem status"), "200- enabled");
    assert_eq!(session.command("advmem off"), "200- disabled");
    assert_eq!(server.host.lock().backend.memory.flash[6..8], [1, 0]);
    assert_eq!(session.command("advmem"), "400- improper command");

    server.host.lock().backend.memory.flash_write_failure =
        Some(KernelError::from_status(NtStatus(0xc000_0185)));
    assert_eq!(session.command("advmem on"), "400- unexpected error");
    server.host.lock().backend.memory.flash_read_failure = Some(KernelError::ObjectNameNotFound);
    assert_eq!(session.command("advmem"), "400- unexpected error");
}

#[test]
fn traceimports_configures_the_kernel_and_prints_the_outcome() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("traceimports modulename=xam.xex enabled=ON"),
        "200- OK"
    );
    assert_eq!(
        session.command("traceimports modulename=xam.xex enabled=yes"),
        "200- OK"
    );
    assert_eq!(
        session.command("traceimports modulename=game.xex enabled=on"),
        "400- "
    );
    assert_eq!(session.command("traceimports enabled=on"), "400- ");
    let host = server.host.lock();
    assert_eq!(
        host.backend.memory.traced_modules,
        [(b"xam.xex".to_vec(), true), (b"xam.xex".to_vec(), false)]
    );
    let output: Vec<&[u8]> = host
        .backend
        .debug_output
        .iter()
        .map(Vec::as_slice)
        .collect();
    assert_eq!(
        output,
        [
            b"[xbdm] enabled tracing for module xam.xex, title reboot required to activate\n"
                .as_slice(),
            b"[xbdm] disabled tracing for module xam.xex, title reboot required to activate\n",
            b"[xbdm] module 'game.xex' is not a valid choice\n",
        ]
    );
}

#[test]
fn memtrack_settings_and_queries() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("memtrack cmd=querytype type=13"),
        "200- thread"
    );
    assert_eq!(
        session.command("memtrack cmd=QUERYTYPE type=0x10000"),
        "200- heap"
    );
    assert_eq!(
        session.command("memtrack cmd=querytype type=14"),
        "400- HRESULT 0x80070057"
    );
    assert_eq!(
        session.command("memtrack cmd=querytype"),
        "400- HRESULT 0x80070057"
    );
    assert_eq!(session.command("memtrack cmd=querystackdepth"), "200- 0x0");
    assert_eq!(session.command("memtrack cmd=queryflags"), "200- 0x0");
    assert_eq!(session.command("memtrack"), "400- HRESULT 0x80070057");
    assert_eq!(
        session.command("memtrack cmd=start"),
        "400- HRESULT 0x80070057"
    );
    assert_eq!(
        session.command("memtrack cmd=save filename=e:\\track.bin"),
        "400- HRESULT 0x80070426"
    );
    assert_eq!(
        session.command("memtrack cmd=save"),
        "400- HRESULT 0x80070057"
    );

    assert_eq!(
        session.command("memtrack cmd=enable stackdepth=0x21"),
        "400- HRESULT 0x80070057"
    );
    assert_eq!(
        session.command("memtrack cmd=enable stackdepth=4 flags=0x100"),
        "400- HRESULT 0x80070057"
    );
    assert_eq!(
        session.command("memtrack cmd=enable stackdepth=4 flags=0x7"),
        "200- OK"
    );
    assert_eq!(
        session.command("memtrack cmd=enable stackdepth=8"),
        "200- missing flags"
    );
    {
        let host = server.host.lock();
        let tracking = host.server.state.memory.tracking;
        assert_eq!(
            (tracking.flags, tracking.stack_depth.0),
            (TrackingFlags(0x1ff), 8)
        );
        assert_eq!(host.backend.memory.tracking_flags, TrackingFlags(0));
    }
    assert_eq!(session.command("memtrack cmd=queryflags"), "200- 0x0");

    assert_eq!(
        session.command("memtrack cmd=enableonce flags=0x3"),
        "200- missing stackdepth"
    );
    assert_eq!(session.command("memtrack cmd=queryflags"), "200- 0x3");
    assert_eq!(
        server.host.lock().server.state.memory.tracking.flags,
        TrackingFlags(0x8000_01ff)
    );

    assert_eq!(session.command("memtrack cmd=disable"), "200- OK");
    assert_eq!(
        server.host.lock().server.state.memory.tracking.flags,
        TrackingFlags(0x8000_0000)
    );
    assert_eq!(session.command("memtrack cmd=queryflags"), "200- 0x3");
}

#[test]
fn memtrack_save_writes_the_records_in_list_order() {
    let server = TestServer::start();
    server.host.lock().backend.memory.tracking_records = vec![vec![1; 0xe], vec![2; 0xe]];
    let mut session = session(&server);
    assert_eq!(
        session.command("memtrack cmd=enableonce flags=0x1"),
        "200- missing stackdepth"
    );
    assert_eq!(
        session.command("memtrack cmd=save filename=e:\\track.bin"),
        "200- OK"
    );
    let host = server.host.lock();
    let file = host
        .backend
        .filesystem
        .read("\\Device\\Harddisk0\\Partition1\\DEVKIT\\track.bin")
        .unwrap();
    assert_eq!(file, [[1u8; 0xe], [2; 0xe]].concat());
    drop(host);
    assert_eq!(
        session.command("memtrack cmd=save filename=e:\\missing\\track.bin"),
        "400- HRESULT 0x80070003"
    );
}

const DETOUR_LOG: &str = "\\Device\\Harddisk0\\Partition1\\DEVKIT\\detour.log";

/// Big-endian dword `index` of a detour record.
fn word(record: &[u8], index: usize) -> u32 {
    u32::from_be_bytes(record[index * 4..index * 4 + 4].try_into().unwrap())
}

fn detour_records(server: &TestServer) -> Vec<Vec<u8>> {
    let host = server.host.lock();
    host.backend
        .filesystem
        .read(DETOUR_LOG)
        .unwrap()
        .chunks(0x70)
        .map(<[u8]>::to_vec)
        .collect()
}

#[test]
fn detour_commands_need_a_running_engine() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("detour getstate"),
        "200- state=0x0 status=0x0"
    );
    assert_eq!(session.command("detour log available"), "442- ");
    assert_eq!(session.command("detour log getentries count=1"), "442- ");
    assert_eq!(session.command("detour entry acquire"), "442- ");
    assert_eq!(
        session.command("detour entry release Id=0"),
        "442- hresult=0x82da002a"
    );
    assert_eq!(
        session.command("detour entry release"),
        "423- hresult=0x82da0017"
    );
    assert_eq!(
        session.command("detour entry query Id=0"),
        "442- hresult=0x82da002a enterdetour=0x0 scribble=0x0 size=0x0"
    );
    assert_eq!(
        session.command("detour entry setinfo Id=0 addr=1 paramsize=0 flags=0"),
        "423- hresult=0x82da0017"
    );
    assert_eq!(session.command("detour stop"), "442- hresult=0x82da002a");
    assert_eq!(session.command("detour log"), "407- unknown command");
    assert_eq!(session.command("detour entry"), "407- unknown command");
    assert_eq!(session.command("detour"), "407- unknown command");
}

#[test]
fn detour_start_reports_a_log_that_fails_to_open_in_getstate() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("detour start"), "200- hresult=0x2da0000");
    assert_eq!(
        session.command("detour getstate"),
        "200- state=0x0 status=0xc000000f"
    );
    assert_eq!(
        session.command("detour start file=e:\\missing\\detour.log"),
        "200- hresult=0x2da0000"
    );
    assert_eq!(
        session.command("detour getstate"),
        "200- state=0x0 status=0xc000003a"
    );
}

#[test]
fn detour_start_without_pool_memory_for_the_records_stops_again() {
    let server = TestServer::start();
    let mut session = session(&server);
    server.host.lock().backend.filesystem.pool_exhausted = true;
    assert_eq!(
        session.command("detour start file=e:\\detour.log"),
        "200- hresult=0x2da0000"
    );
    assert_eq!(
        session.command("detour getstate"),
        "200- state=0x0 status=0x0"
    );
    server.host.lock().backend.filesystem.pool_exhausted = false;
    assert_eq!(
        session.command("detour start file=e:\\detour.log"),
        "200- hresult=0x2da0000"
    );
    assert_eq!(
        session.command("detour getstate"),
        "200- state=0x2 status=0x0"
    );
}

#[test]
fn detour_entries_log_setinfo_and_release_records() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("detour start file=e:\\detour.log"),
        "200- hresult=0x2da0000"
    );
    assert_eq!(
        session.command("detour start file=e:\\other.log"),
        "442- hresult=0x82da002a"
    );
    assert_eq!(
        session.command("detour getstate"),
        "200- state=0x2 status=0x0"
    );
    assert_eq!(
        session.command("detour entry acquire"),
        "200- hresult=0x2da0000 id=0x0"
    );
    assert_eq!(
        session.command("detour entry acquire"),
        "200- hresult=0x2da0000 id=0x1"
    );
    assert_eq!(
        session.command("detour entry query Id=1"),
        "200- hresult=0x2da0000 enterdetour=0x91f13288 scribble=0x91f13290 size=0x50"
    );
    // Stock accepts the entry count itself and reads past the table.
    assert_eq!(
        session.command("detour entry query Id=0x2e8"),
        "400- hresult=0x82da0000 enterdetour=0x0 scribble=0x0 size=0x0"
    );
    assert_eq!(
        session.command("getmem addr=0x91f13288 length=12"),
        "202- memory data follows"
    );
    assert_eq!(session.multiline(), ["398000014BFFFD747C000038"]);

    assert_eq!(
        session.command(
            "detour entry setinfo Id=1 addr=0x82000000 paramsize=0x10 flags=0x3 return=7 sleep=9"
        ),
        "200- hresult=0x2da0000"
    );
    assert_eq!(
        session.command("detour entry release Id=0"),
        "200- hresult=0x2da0000"
    );
    assert_eq!(
        session.command("detour entry acquire"),
        "200- hresult=0x2da0000 id=0x0"
    );
    assert_eq!(
        session.command("detour log available"),
        "200- available=0x2"
    );

    let records = detour_records(&server);
    assert_eq!(records.len(), 2);
    let setinfo = &records[0];
    assert_eq!((word(setinfo, 0), word(setinfo, 1)), (5, 0));
    assert_eq!((word(setinfo, 6), word(setinfo, 7)), (1, 3));
    assert_eq!(
        (word(setinfo, 8), word(setinfo, 9), word(setinfo, 10)),
        (0x8200_0000, 0x10, 7)
    );
    let release = &records[1];
    assert_eq!(
        (word(release, 0), word(release, 1), word(release, 6)),
        (6, 0, 0)
    );

    session.send("detour log getentries count=5");
    assert_eq!(session.line(), "203- OK count=0x5 entrysize=0x70");
    assert_eq!(read_bytes(&mut session, 0x70), records[0]);
    assert_eq!(read_bytes(&mut session, 0x70), records[1]);
    assert_eq!(
        session.command("detour log available"),
        "200- available=0x0"
    );

    assert_eq!(session.command("detour stop"), "200- hresult=0x2da0000");
    assert_eq!(
        session.command("detour getstate"),
        "200- state=0x0 status=0x0"
    );
    assert!(
        server
            .host
            .lock()
            .backend
            .filesystem
            .read(DETOUR_LOG)
            .is_none()
    );
    // Entries stay acquired across sessions.
    assert_eq!(
        session.command("detour start file=e:\\detour.log"),
        "200- hresult=0x2da0000"
    );
    assert_eq!(
        session.command("detour entry acquire"),
        "200- hresult=0x2da0000 id=0x2"
    );
}

#[test]
fn detour_discarded_call_completes_its_overlapped_request() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("detour start file=e:\\detour.log"),
        "200- hresult=0x2da0000"
    );
    assert_eq!(
        session.command("detour entry acquire"),
        "200- hresult=0x2da0000 id=0x0"
    );
    // Log parameters and returns, registers, stack; overlapped pointer in r4.
    assert_eq!(
        session.command(
            "detour entry setinfo Id=0 addr=0x82000000 paramsize=0x70 flags=0xc93 return=0x55 OverlappedOffset=1 ExtendedError=0x1234"
        ),
        "200- hresult=0x2da0000"
    );
    let overlapped = MEMORY_BASE + 0x100;
    let call = SimulatedCall {
        frame: MEMORY_BASE + 0x200,
        registers: [3, u64::from(overlapped), 5, 6, 7, 8, 9, 10],
        original_result: ReturnValue(0x99),
        ..SimulatedCall::default()
    };
    let outcome = server.host.lock().backend.detour_call(EntryId(0), call);
    assert_eq!(
        outcome,
        CallOutcome {
            called: false,
            returned: ReturnValue::IO_PENDING
        }
    );
    {
        let host = server.host.lock();
        assert_eq!(host.backend.memory.detour.signaled_events, [0x0c0d_0e0f]);
    }
    let mut overlapped_bytes = [0u8; 0x1c];
    for (offset, byte) in overlapped_bytes.iter_mut().enumerate() {
        *byte = server.host.lock().backend.memory.regions[4].bytes[0x100 + offset];
    }
    assert_eq!(word(&overlapped_bytes, 0), 0x55);
    assert_eq!(word(&overlapped_bytes, 1), 0);
    assert_eq!(word(&overlapped_bytes, 6), 0x1234);

    let records = detour_records(&server);
    let types: Vec<u32> = records.iter().map(|record| word(record, 0)).collect();
    assert_eq!(types, [5, 0, 4, 4, 7, 1]);
    let call_record = &records[1];
    assert_eq!(
        (
            word(call_record, 1),
            word(call_record, 6),
            word(call_record, 7)
        ),
        (1, 0, 0xc9b)
    );
    assert_eq!(
        (
            word(call_record, 8),
            word(call_record, 9),
            word(call_record, 11)
        ),
        (0, 3, overlapped)
    );
    assert_eq!(
        records[2][8..],
        (0x200..0x268)
            .map(|offset: u32| offset as u8)
            .collect::<Vec<_>>()[..]
    );
    assert_eq!(
        records[3][8..],
        (0x268..0x2d0)
            .map(|offset: u32| offset as u8)
            .collect::<Vec<_>>()[..]
    );
    let completion = &records[4];
    assert_eq!(
        (
            word(completion, 1),
            word(completion, 4),
            word(completion, 5)
        ),
        (1, 0, 0x1c9b)
    );
    assert_eq!((word(completion, 6), word(completion, 7)), (0x55, 0x1234));
    let returned = &records[5];
    assert_eq!(
        (
            word(returned, 1),
            word(returned, 4),
            word(returned, 5),
            word(returned, 6)
        ),
        (1, 0, 0x1c9b, 0x3e5)
    );
}

#[test]
fn detour_call_through_to_the_original_counts_discards() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("detour start file=e:\\detour.log"),
        "200- hresult=0x2da0000"
    );
    assert_eq!(
        session.command("detour entry acquire"),
        "200- hresult=0x2da0000 id=0x0"
    );
    // Every second call is discarded and returns 7.
    assert_eq!(
        session.command("detour entry setinfo Id=0 addr=0x82000000 paramsize=0 flags=0x302 return=7 sleep=0x20 disccallfreq=2"),
        "200- hresult=0x2da0000"
    );
    let call = SimulatedCall {
        original_result: ReturnValue(9),
        ..SimulatedCall::default()
    };
    let first = server.host.lock().backend.detour_call(EntryId(0), call);
    let second = server.host.lock().backend.detour_call(EntryId(0), call);
    assert_eq!(
        first,
        CallOutcome {
            called: true,
            returned: ReturnValue(9)
        }
    );
    assert_eq!(
        second,
        CallOutcome {
            called: false,
            returned: ReturnValue(7)
        }
    );
    // Sleep before the call and after it, twice.
    assert_eq!(
        server.host.lock().backend.memory.detour.sleeps,
        [0x20, 0x20, 0x20, 0x20]
    );

    let records = detour_records(&server);
    let summary: Vec<(u32, u32)> = records
        .iter()
        .map(|record| (word(record, 0), word(record, 1)))
        .collect();
    assert_eq!(summary, [(5, 0), (0, 1), (1, 1), (0, 2), (1, 2)]);
    assert_eq!(
        (word(&records[1], 7), word(&records[1], 0x60 / 4)),
        (0x306, 0x20)
    );
    assert_eq!(
        (
            word(&records[2], 5),
            word(&records[2], 6),
            word(&records[2], 7)
        ),
        (0x1306, 9, 0x20)
    );
    assert_eq!((word(&records[4], 5), word(&records[4], 6)), (0x130a, 7));
}
