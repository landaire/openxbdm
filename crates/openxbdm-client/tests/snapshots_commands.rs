//! Snapshot tests that replay captured XBDM traffic through `MockTransport`,
//! execute a typed command, and snapshot the parsed output via `insta`.
//!
//! Captures live under `tests/fixtures/*.capture`. Running `cargo insta
//! review` after a change rolls the snapshots forward.

use std::path::PathBuf;

use openxbdm_client::Client;
use openxbdm_client::commands::AltAddr;
use openxbdm_client::commands::ConsoleMem;
use openxbdm_client::commands::ConsoleType;
use openxbdm_client::commands::DbgName;
use openxbdm_client::commands::DirList;
use openxbdm_client::commands::DmVersion;
use openxbdm_client::commands::DriveFreeSpace;
use openxbdm_client::commands::DriveList;
use openxbdm_client::commands::FileUploadKind;
use openxbdm_client::commands::GetConsoleFeatures;
use openxbdm_client::commands::GetConsoleMem;
use openxbdm_client::commands::GetConsoleType;
use openxbdm_client::commands::GetFileAttributes;
use openxbdm_client::commands::GetFileRange;
use openxbdm_client::commands::GetMem;
use openxbdm_client::commands::GetNetAddrs;
use openxbdm_client::commands::GetPid;
use openxbdm_client::commands::GetSocketInfo;
#[cfg(feature = "capture")]
use openxbdm_client::commands::Hresult;
use openxbdm_client::commands::IsStopped;
use openxbdm_client::commands::ModuleSections;
use openxbdm_client::commands::Modules;
use openxbdm_client::commands::PerfCounterList;
use openxbdm_client::commands::PixelFormat;
use openxbdm_client::commands::QueryPerfCounter;
use openxbdm_client::commands::SetMem;
use openxbdm_client::commands::SysTime;
use openxbdm_client::commands::ThreadId;
use openxbdm_client::commands::ThreadInfo;
use openxbdm_client::commands::Threads;
use openxbdm_client::commands::WalkMem;
use openxbdm_client::commands::XbeInfo;
#[cfg(feature = "capture")]
use openxbdm_client::commands::pix::CaptureSession;
#[cfg(feature = "capture")]
use openxbdm_client::commands::pix::Notification;
use openxbdm_client::transport::CaptureLog;
use openxbdm_client::transport::MockTransport;

fn fixture(name: &str) -> CaptureLog {
    // Buck2 sets CARGO_MANIFEST_DIR at run time relative to the project
    // root, where its tests run; the compile-time value does not serve.
    let manifest_dir =
        std::env::var_os("CARGO_MANIFEST_DIR").expect("the test runner sets CARGO_MANIFEST_DIR");
    let mut path = PathBuf::from(manifest_dir);
    path.push("tests/fixtures");
    path.push(format!("{name}.capture"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()));
    CaptureLog::from_text(&text).expect("parsing capture fixture")
}

fn run_command<C>(fixture_name: &str, command: C) -> C::Output
where
    C: openxbdm_client::Command,
{
    let log = fixture(fixture_name);
    let mock = MockTransport::from_log(log);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let mut client = Client::new(mock).read_banner().await.unwrap();
        client.run(command).await.unwrap()
    })
}

#[test]
fn dbgname_get_parses_canned_response() {
    let name = run_command("dbgname_get", DbgName::Get);
    insta::assert_debug_snapshot!(name, @r###""deanxbox""###);
}

#[test]
fn systime_parses_filetime() {
    let result = run_command("systime", SysTime);
    insta::assert_debug_snapshot!(result, @r###"
    SysTimeResult {
        file_time: FileTime(
            133476389166481920,
        ),
    }
    "###);
}

#[test]
fn drivelist_parses_multiline() {
    let drives = run_command("drivelist", DriveList);
    insta::assert_debug_snapshot!(drives, @r###"
    [
        "D",
        "E",
        "Z",
    ]
    "###);
}

#[test]
fn drivelist_360_multi_segment_chunk() {
    let drives = run_command("drivelist_360", DriveList);
    insta::assert_debug_snapshot!(drives, @r###"
    [
        "SysCache0",
        "SysCache1",
        "SysCache2",
        "E",
        "DEVKIT",
        "HDD",
        "MUINT",
        "INTUSB",
    ]
    "###);
}

#[test]
fn drivefreespace_parses_hi_lo_pairs() {
    let space = run_command(
        "drivefreespace",
        DriveFreeSpace {
            drive: "DEVKIT:\\".to_owned(),
        },
    );
    insta::assert_debug_snapshot!(space, @r###"
    DriveSpace {
        free_to_caller_bytes: 216171921408,
        total_bytes: 233545236480,
        total_free_bytes: 216171921408,
    }
    "###);
}

#[test]
fn dirlist_parses_entries_with_mixed_types() {
    let entries = run_command(
        "dirlist_devkit",
        DirList {
            path: "DEVKIT:\\".to_owned(),
        },
    );
    insta::assert_debug_snapshot!(entries, @r###"
    [
        DirEntry {
            name: "dmext",
            size: 0,
            create_time: FileTime(
                130407778600000000,
            ),
            change_time: FileTime(
                130407778600000000,
            ),
            is_directory: true,
        },
        DirEntry {
            name: "music1.wma",
            size: 243079,
            create_time: FileTime(
                130228794180000000,
            ),
            change_time: FileTime(
                130228794180000000,
            ),
            is_directory: false,
        },
    ]
    "###);
}

#[test]
fn getfileattributes_parses_single_entry() {
    let attrs = run_command(
        "getfileattributes",
        GetFileAttributes {
            path: "DEVKIT:\\music1.wma".to_owned(),
        },
    );
    insta::assert_debug_snapshot!(attrs, @r###"
    FileAttributes {
        size: 243079,
        create_time: FileTime(
            130228794180000000,
        ),
        change_time: FileTime(
            130228794180000000,
        ),
        is_directory: false,
    }
    "###);
}

#[test]
fn getfile_streams_prefixed_payload() {
    let log = fixture("getfile_small");
    let mock = MockTransport::from_log(log).with_lax_writes();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (bytes, total) = runtime.block_on(async move {
        let mut client = Client::new(mock).read_banner().await.unwrap();
        let download = client
            .get_file("E:\\greet.txt", GetFileRange::WholeFile)
            .await
            .unwrap();
        let total = download.total();
        let bytes = download.into_vec().await.unwrap();
        (bytes, total)
    });
    assert_eq!(total, 14);
    assert_eq!(bytes, b"hello, xbdm!\r\n");
}

#[test]
fn screenshot_streams_metadata_and_framebuffer() {
    let log = fixture("screenshot_small");
    let mock = MockTransport::from_log(log).with_lax_writes();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let shot = runtime.block_on(async move {
        let mut client = Client::new(mock).read_banner().await.unwrap();
        client.screenshot().await.unwrap()
    });
    assert_eq!(shot.metadata.pitch, 0x10);
    assert_eq!(shot.metadata.width, 4);
    assert_eq!(shot.metadata.height, 2);
    assert_eq!(shot.metadata.format, PixelFormat::LeX8R8G8B8);
    assert_eq!(shot.metadata.framebuffer_size, 0x20);
    assert_eq!(shot.data.len(), 0x20);
    assert_eq!(&shot.data[..4], &[0x10, 0x20, 0x30, 0xFF]);
    assert_eq!(&shot.data[28..], &[0x17, 0x27, 0x37, 0xFF]);
}

#[test]
fn dmversion_parses_build_identifier() {
    let version = run_command("dmversion", DmVersion);
    assert_eq!(version, "2.0.21256.0");
}

#[test]
fn consoletype_parses_devkit() {
    let kind = run_command("consoletype", GetConsoleType);
    assert_eq!(kind, ConsoleType::DevKit);
}

#[test]
fn consolefeatures_parses_leading_space_separated_flags() {
    let features = run_command("consolefeatures", GetConsoleFeatures);
    assert_eq!(features.flags, vec!["DEBUGGING", "1GB_RAM"]);
}

#[test]
fn consolemem_parses_memory_class() {
    let mem = run_command("consolemem", GetConsoleMem);
    assert_eq!(mem, ConsoleMem::ExtraMemoryInUse);
}

#[test]
fn getpid_parses_hex_pid() {
    let pid = run_command("getpid", GetPid);
    assert_eq!(pid, 0xf24e_abcd);
}

#[test]
fn netaddrs_parses_name_and_hex_blobs() {
    let addrs = run_command("netaddrs", GetNetAddrs);
    assert_eq!(addrs.name, "deanxbox");
    // Blobs lead with the IPv4 address: C0A8011A == 192.168.1.26.
    assert_eq!(&addrs.debug[..4], &[0xC0, 0xA8, 0x01, 0x1A]);
    assert_eq!(&addrs.title[..4], &[0xC0, 0xA8, 0x01, 0x19]);
    assert_eq!(addrs.debug.len(), 36);
    assert_eq!(addrs.title.len(), 36);
}

#[test]
fn modsections_parses_every_section_with_flags() {
    let sections = run_command(
        "modsections",
        ModuleSections {
            module: "xbdm.xex".to_owned(),
        },
    );
    assert_eq!(sections.len(), 8);
    assert_eq!(sections[0].name, ".rdata");
    assert_eq!(sections[0].base, 0x91f0_0400);
    assert_eq!(sections[0].size, 0xf33c);
    assert_eq!(sections[0].index, 1);
    // `flags` is bare decimal on the wire, unlike the 0x-prefixed fields.
    let text = sections.iter().find(|s| s.name == ".text").unwrap();
    assert_eq!(text.flags.0, 10);
    assert_eq!(sections[7].name, ".reloc");
}

#[test]
fn threadinfo_parses_detail_block() {
    let detail = run_command(
        "threadinfo",
        ThreadInfo {
            thread: ThreadId(0xfb00_0000),
        },
    );
    assert_eq!(detail.thread, ThreadId(0xfb00_0000));
    assert_eq!(detail.suspend, 0);
    assert_eq!(detail.priority, 13);
    assert_eq!(detail.tls_base, 0x3c07_cb50);
    assert_eq!(detail.start, 0x8177_abb8);
    assert_eq!(detail.base, 0x7c16_0000);
    assert_eq!(detail.limit, 0x7c15_0000);
    assert_eq!(detail.slack, 0x540);
    assert_eq!(detail.name_length, 0x0e);
    assert_eq!(detail.processor, 0x05);
    assert_eq!(detail.last_error, None);
}

#[test]
fn getmem_parses_hex_rows_into_bytes() {
    let snapshot = run_command(
        "getmem",
        GetMem {
            address: 0x8004_0000,
            length: 64,
        },
    );
    assert_eq!(snapshot.address, 0x8004_0000);
    assert_eq!(snapshot.data.len(), 64);
    // XEX2 image header at the kernel base.
    assert_eq!(&snapshot.data[..4], b"MZ\x90\x00");
    assert_eq!(&snapshot.data[60..], &[0xE8, 0x00, 0x00, 0x00]);
    assert!(snapshot.unmapped_offsets.is_empty());
}

#[test]
fn walkmem_parses_virtual_regions() {
    let regions = run_command("walkmem", WalkMem);
    assert!(!regions.is_empty());
    // Ranges are non-empty and strictly ascending with no overlap.
    for pair in regions.windows(2) {
        assert!(pair[0].size > 0);
        assert!(
            pair[0].base.checked_add(pair[0].size).unwrap() <= pair[1].base,
            "overlapping regions: {:#x}+{:#x} vs {:#x}",
            pair[0].base,
            pair[0].size,
            pair[1].base
        );
    }
}

#[test]
fn sockets_parses_tracked_socket_entries() {
    let sockets = run_command("sockets", GetSocketInfo);
    assert!(!sockets.is_empty());
    // The XBDM command port itself is always in the list.
    assert!(sockets.iter().any(|s| s.local_port == 730));
}

#[test]
fn pclist_parses_type_and_name_pairs() {
    let counters = run_command("pclist", PerfCounterList);
    assert!(!counters.is_empty());
    let pages = counters
        .iter()
        .find(|c| c.name == "Debugger Pages")
        .expect("Debugger Pages counter present");
    assert_eq!(pages.kind, 0x01);
    // Names may contain spaces; the parser must not split on them.
    assert!(counters.iter().any(|c| c.name.contains(' ')));
}

#[test]
fn querypc_parses_split_hi_lo_value_and_rate() {
    let sample = run_command(
        "querypc",
        QueryPerfCounter {
            name: "Debugger Pages".to_owned(),
            kind: 0x01,
        },
    );
    assert_eq!(sample.value, 0);
    // rate = (ratehi << 32) | ratelo
    assert_eq!(sample.rate, 0x0000_000d_3c07_cb50);
}

#[test]
fn altaddr_parses_ipv4() {
    let addr = run_command("altaddr", AltAddr);
    insta::assert_debug_snapshot!(addr, @"192.168.1.25");
}

#[test]
fn modules_parse_flags_and_sizes() {
    let mods = run_command("modules_small", Modules);
    insta::assert_debug_snapshot!(mods, @r###"
    [
        ModuleInfo {
            name: "xboxkrnl.exe",
            base: 2147745792,
            size: 2359296,
            checksum: 1862603,
            timestamp: 1385584266,
            pdata: 2147925504,
            psize: 28592,
            thread: 0,
            osize: 2359296,
            is_dll: false,
            is_tls: false,
            is_xbe: false,
        },
        ModuleInfo {
            name: "xbdm.xex",
            base: 2448424960,
            size: 716800,
            checksum: 741891,
            timestamp: 1378429206,
            pdata: 2448488448,
            psize: 11904,
            thread: 0,
            osize: 802816,
            is_dll: true,
            is_tls: false,
            is_xbe: false,
        },
    ]
    "###);
}

#[test]
fn threads_parse_signed_decimal_as_unsigned() {
    let ids = run_command("threads", Threads);
    insta::assert_debug_snapshot!(ids, @r###"
    [
        ThreadId(
            4211081304,
        ),
        ThreadId(
            4211081296,
        ),
    ]
    "###);
}

#[test]
fn xbeinfo_parses_running_title() {
    let info = run_command("xbeinfo_running", XbeInfo::Running);
    insta::assert_debug_snapshot!(info, @r###"
    XbeInfoResult {
        timestamp: 0,
        checksum: 0,
        name: "\\Device\\Flash\\xshell.xex",
    }
    "###);
}

#[test]
fn setmem_parses_written_count() {
    let result = run_command(
        "setmem",
        SetMem {
            address: 0xFEEF_0000,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        },
    );
    insta::assert_debug_snapshot!(result, @r###"
    BytesWritten {
        requested: 4,
        written: 4,
    }
    "###);
}

#[test]
fn sendfile_streams_upload_and_finalizes() {
    let log = fixture("sendfile_small");
    let mock = MockTransport::from_log(log);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let mut client = Client::new(mock).read_banner().await.unwrap();
        let upload = client
            .send_file(r"E:\hi.txt", FileUploadKind::Create { size: 5 })
            .await
            .unwrap();
        upload.send_all(b"hello").await.unwrap();
    });
}

#[test]
fn isstopped_maps_408_to_running() {
    let state = run_command(
        "isstopped_running",
        IsStopped {
            thread: ThreadId(0xfb000018),
        },
    );
    insta::assert_debug_snapshot!(state, @"Running");
}

#[test]
fn error_response_is_typed() {
    let log = fixture("error_unknown");
    let mock = MockTransport::from_log(log).with_lax_writes();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = runtime.block_on(async move {
        let mut client = Client::new(mock).read_banner().await.unwrap();
        client.send_raw("notacommand").await.unwrap_err()
    });
    let kind = err.current_context();
    insta::assert_debug_snapshot!(kind, @r###"
    Remote {
        code: Listed(
            UnknownCommand,
        ),
        message: "unknown command",
    }
    "###);
}

#[cfg(feature = "capture")]
#[test]
#[ignore = "fixture capture predates the current PIX handshake wire format; re-record against a live console"]
fn pix_full_handshake_walks_every_token_in_order() {
    let log = fixture("pix_handshake");
    let mock = MockTransport::from_log(log);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let mut client = Client::new(mock).read_banner().await.unwrap();
        let mut session = CaptureSession::connect(&mut client).await.unwrap().session;
        session.limit_capture_size_mb(256).await.unwrap();
        session
            .begin_capture_file_creation(r"DEVKIT:\snip.wmv")
            .await
            .unwrap();
        session.begin_capture().await.unwrap();
        session.end_capture().await.unwrap();
        session.end_capture_file_creation().await.unwrap();
        session.disconnect().await.unwrap();
    });
}

#[cfg(feature = "capture")]
#[test]
fn pix_notification_parser_matches_xbmovie_shapes() {
    let segment = Notification::parse("PIX!{CaptureFileCreationEnded}7").unwrap();
    assert_eq!(
        segment,
        Some(Notification::CaptureFileCreationEnded { result: Hresult(7) })
    );
    let end = Notification::parse("PIX!{CaptureEnded}").unwrap();
    assert_eq!(end, Some(Notification::CaptureEnded));
    assert!(
        Notification::parse("202- not a pix line")
            .unwrap()
            .is_none()
    );
}
