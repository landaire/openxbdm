//! File, drive, and storage commands over TCP.

mod common;

use std::io::Read;
use std::io::Write;

use common::RawSession;
use common::TestServer;
use common::run;
use openxbdm_client::commands::Delete;
use openxbdm_client::commands::DirList;
use openxbdm_client::commands::DriveFreeSpace;
use openxbdm_client::commands::EofDisposition;
use openxbdm_client::commands::FileEof;
use openxbdm_client::commands::FileUploadKind;
use openxbdm_client::commands::GetFileAttributes;
use openxbdm_client::commands::GetFileRange;
use openxbdm_client::commands::MakeDirectory;
use openxbdm_client::commands::Rename;
use openxbdm_server::commands::filesystem::FileAttributes;
use openxbdm_server::notify::ExecutionState;
use openxbdm_server_host::backend::filesystem::HARDDISK;
use openxbdm_server_host::backend::memory::MEMORY_BASE;

const DEVKIT: &str = "\\Device\\Harddisk0\\Partition1\\DEVKIT";

fn devkit(name: &str) -> String {
    format!("{DEVKIT}\\{name}")
}

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

/// Upload `data` after a 204 reply and return the final line.
fn upload(session: &mut RawSession, command: &str, data: &[u8]) -> String {
    assert_eq!(session.command(command), "204- send binary data");
    session.stream.write_all(data).unwrap();
    session.line()
}

#[test]
fn client_file_operations_round_trip() {
    let server = TestServer::start();
    run(async {
        let mut client = server.client().await;
        client
            .run(MakeDirectory {
                path: "E:\\dir".into(),
            })
            .await
            .unwrap();
        let payload: Vec<u8> = (0..0x9000u32).map(|value| (value * 7) as u8).collect();
        let upload = client
            .send_file(
                "E:\\dir\\data.bin",
                FileUploadKind::Create {
                    size: payload.len() as u32,
                },
            )
            .await
            .unwrap();
        upload.send_all(&payload).await.unwrap();

        let download = client
            .get_file("E:\\dir\\data.bin", GetFileRange::WholeFile)
            .await
            .unwrap();
        assert_eq!(download.into_vec().await.unwrap(), payload);

        let range = GetFileRange::Range {
            offset: 0x10,
            size: core::num::NonZeroU32::new(0x20),
        };
        let range = client.get_file("E:\\dir\\data.bin", range).await.unwrap();
        assert_eq!(range.into_vec().await.unwrap(), payload[0x10..0x30]);

        let attributes = client
            .run(GetFileAttributes {
                path: "E:\\dir\\data.bin".into(),
            })
            .await
            .unwrap();
        assert_eq!(attributes.size, payload.len() as u64);
        assert!(!attributes.is_directory);

        let entries = client
            .run(DirList {
                path: "E:\\dir".into(),
            })
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "data.bin");
        assert_eq!(entries[0].size, payload.len() as u64);

        client
            .run(Rename {
                from: "E:\\dir\\data.bin".into(),
                to: "E:\\dir\\moved.bin".into(),
            })
            .await
            .unwrap();
        client
            .run(FileEof {
                path: "E:\\dir\\moved.bin".into(),
                size: 4,
                disposition: EofDisposition::OpenExisting,
            })
            .await
            .unwrap();
        client
            .run(Delete {
                path: "E:\\dir\\moved.bin".into(),
                is_directory: false,
            })
            .await
            .unwrap();
        client
            .run(Delete {
                path: "E:\\dir".into(),
                is_directory: true,
            })
            .await
            .unwrap();

        let space = client
            .run(DriveFreeSpace {
                drive: "E:\\".into(),
            })
            .await
            .unwrap();
        assert_eq!(space.total_bytes, 0x1000 * 0x4000);
        assert_eq!(space.free_to_caller_bytes, space.total_free_bytes);
    });
    let host = server.host.lock();
    assert!(host.backend.filesystem.entry(&devkit("dir")).is_none());
    assert_eq!(host.backend.filesystem.open_handles(), 0);
    assert_eq!(host.backend.filesystem.pool_blocks(), 0);
}

#[test]
fn getfile_ranges_clamp_to_the_file() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("ten.bin"), b"0123456789");
    let mut session = session(&server);

    session.send("getfile name=e:\\ten.bin");
    assert_eq!(session.line(), "203- binary response follows");
    assert_eq!(
        read_bytes(&mut session, 14),
        [&[10, 0, 0, 0][..], b"0123456789"].concat()
    );

    session.send("getfile name=e:\\ten.bin offset=4 size=0x100");
    assert_eq!(session.line(), "203- partial send");
    assert_eq!(
        read_bytes(&mut session, 10),
        [&[6, 0, 0, 0][..], b"456789"].concat()
    );

    session.send("getfile name=e:\\ten.bin offset=2 size=0");
    assert_eq!(session.line(), "203- partial send");
    assert_eq!(
        read_bytes(&mut session, 12),
        [&[8, 0, 0, 0][..], b"23456789"].concat()
    );

    session.send("getfile name=e:\\ten.bin offset=11 size=3");
    assert_eq!(session.line(), "203- partial send");
    assert_eq!(read_bytes(&mut session, 4), b"\0\0\0\0");

    assert_eq!(
        session.command("getfile name=e:\\ten.bin offset=1"),
        "400- missing size"
    );
    assert_eq!(session.command("getfile"), "400- missing name");
    assert_eq!(
        session.command("getfile name=e:\\absent"),
        "402- file not found"
    );
}

#[test]
fn delete_reports_kind_mismatches_and_protects_roots() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend.filesystem.write(&devkit("file"), b"x");
        host.backend.filesystem.write(&devkit("full\\child"), b"y");
    }
    let mut session = session(&server);
    assert_eq!(session.command("delete"), "400- missing name");
    assert_eq!(
        session.command("delete name=E:\\ dir"),
        "414- access denied"
    );
    assert_eq!(session.command("delete name=xE:\\"), "414- access denied");
    assert_eq!(
        session.command("delete name=e:\\file dir"),
        "414- not a directory"
    );
    assert_eq!(
        session.command("delete name=e:\\full"),
        "414- is a directory"
    );
    assert_eq!(
        session.command("delete name=e:\\full dir"),
        "411- directory not empty"
    );
    assert_eq!(
        session.command("delete name=e:\\missing"),
        "402- file not found"
    );
    assert_eq!(
        session.command("delete name=e:\\nodir\\x"),
        "402- file not found"
    );
    assert_eq!(
        session.command("delete name=\\Device\\Harddisk0\\Partition1\\DEVKIT\\file"),
        "200- OK"
    );
    assert!(
        server
            .host
            .lock()
            .backend
            .filesystem
            .entry(&devkit("file"))
            .is_none()
    );
}

#[test]
fn mkdir_and_create_errors_map_kernel_statuses() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("mkdir name=e:\\a"), "200- OK");
    assert_eq!(
        session.command("mkdir name=e:\\a"),
        "410- file already exists"
    );
    assert_eq!(
        session.command("mkdir name=e:\\b\\c"),
        "430- path not found"
    );
    assert_eq!(
        session.command("mkdir name=e:\\bad?name"),
        "412- filename is invalid"
    );
    assert_eq!(
        session.command("mkdir name=nodrive"),
        "413- file cannot be created"
    );
    assert_eq!(session.command("mkdir"), "400- missing name");
}

#[test]
fn fileeof_dispositions() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("f"), b"abcdef");
    let mut session = session(&server);
    assert_eq!(session.command("fileeof name=e:\\f"), "400- missing size");
    assert_eq!(
        session.command("fileeof name=e:\\new size=3"),
        "402- file not found"
    );
    assert_eq!(session.command("fileeof name=e:\\f size=3"), "200- OK");
    assert_eq!(
        session.command("fileeof name=e:\\f size=3 mustcreate"),
        "410- file already exists"
    );
    assert_eq!(
        session.command("fileeof name=e:\\new size=2 mustcreate"),
        "200- OK"
    );
    assert_eq!(
        session.command("fileeof name=e:\\f size=2 cancreate"),
        "200- OK"
    );
    let host = server.host.lock();
    assert_eq!(
        host.backend.filesystem.read(&devkit("new")),
        Some(&[0u8, 0][..])
    );
    assert_eq!(
        host.backend.filesystem.read(&devkit("f")),
        Some(&[0u8, 0][..])
    );
}

#[test]
fn writefile_reports_bytes_written() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("w"), b"aaaaaaaa");
    let mut session = session(&server);
    assert_eq!(
        upload(
            &mut session,
            "writefile name=e:\\w offset=2 length=3",
            b"XYZ"
        ),
        "200- 3 bytes written"
    );
    assert_eq!(
        session.command("writefile name=e:\\absent offset=0 length=1"),
        "402- file not found"
    );
    assert_eq!(
        session.command("writefile name=e:\\w length=1"),
        "400- missing offset"
    );
    assert_eq!(
        session.command("writefile name=e:\\w offset=0 length=0"),
        "204- send binary data"
    );
    assert_eq!(session.line(), "200- 0 bytes written");
    assert_eq!(
        server.host.lock().backend.filesystem.read(&devkit("w")),
        Some(&b"aaXYZaaa"[..])
    );
}

#[test]
fn upload_write_failures_follow_the_staging_halves() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend.filesystem.write(&devkit("w"), b"");
        host.backend.filesystem.write_limit = Some(0x4000);
    }
    let mut session = session(&server);
    let data = vec![0x5a; 0x4800];
    assert_eq!(
        upload(&mut session, "sendfile name=e:\\big length=0x4800", &data),
        "400- unexpected error"
    );
    assert_eq!(
        upload(
            &mut session,
            "writefile name=e:\\w offset=0 length=0x4800",
            &data
        ),
        "400- 16384 bytes written"
    );
    let host = server.host.lock();
    assert!(host.backend.filesystem.entry(&devkit("big")).is_none());
    assert_eq!(
        host.backend.filesystem.read(&devkit("w")).map(<[u8]>::len),
        Some(0x4000)
    );
    assert_eq!(host.backend.filesystem.pool_blocks(), 0);
    assert_eq!(host.backend.filesystem.open_handles(), 0);
}

#[test]
fn dirlist_lines_follow_the_stock_format() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend.filesystem.write(&devkit("sub\\x"), b"12345");
        host.backend
            .filesystem
            .set_attributes(&devkit("sub\\x"), FileAttributes(0x3));
    }
    let mut session = session(&server);
    assert_eq!(
        session.command("dirlist name=e:\\"),
        "202- multiline response follows"
    );
    let lines = session.multiline();
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].starts_with("name=\"sub\" sizehi=0x0 sizelo=0x0 createhi=0x"),
        "{}",
        lines[0]
    );
    assert!(lines[0].ends_with(" directory"), "{}", lines[0]);
    assert_eq!(
        session.command("dirlist name=e:\\sub"),
        "202- multiline response follows"
    );
    let lines = session.multiline();
    assert!(
        lines[0].starts_with("name=\"x\" sizehi=0x0 sizelo=0x5 "),
        "{}",
        lines[0]
    );
    assert!(lines[0].ends_with(" readonly hidden"), "{}", lines[0]);
    assert_eq!(
        session.command("dirlist name=e:\\sub\\x"),
        "414- access denied"
    );

    assert_eq!(
        session.command("getfileattributes name=e:\\sub\\x"),
        "202- multiline response follows"
    );
    let lines = session.multiline();
    assert!(
        lines[0].starts_with("sizehi=0x0 sizelo=0x5 createhi=0x")
            && lines[0].ends_with(" readonly hidden")
    );
    assert_eq!(
        session.command("getfileattributes name=e:\\none"),
        "402- file not found"
    );
}

#[test]
fn opening_a_file_keeps_its_stored_name_case() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("dir\\foo.txt"), b"x");
    let mut session = session(&server);
    assert_eq!(
        session.command("getfile name=e:\\DIR\\FOO.TXT"),
        "203- binary response follows"
    );
    assert_eq!(read_bytes(&mut session, 5), [1, 0, 0, 0, b'x']);
    assert_eq!(session.command("mkdir name=e:\\DIR\\NEW"), "200- OK");
    assert_eq!(
        session.command("dirlist name=e:\\dir"),
        "202- multiline response follows"
    );
    let names: Vec<String> = session
        .multiline()
        .iter()
        .map(|line| line.split(' ').next().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["name=\"foo.txt\"", "name=\"NEW\""]);
}

#[test]
fn rename_into_its_own_subtree_fails() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("mkdir name=e:\\a"), "200- OK");
    assert_eq!(
        session.command("rename name=e:\\a newname=e:\\a\\b"),
        "413- file cannot be created"
    );
    assert_eq!(
        session.command("dirlist name=e:\\"),
        "202- multiline response follows"
    );
    assert!(session.multiline()[0].starts_with("name=\"a\" "));
}

#[test]
fn drivelist_combines_dos_devices_and_the_drive_table() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("drivelist"),
        "202- multiline response follows"
    );
    assert_eq!(
        session.multiline(),
        [
            "drivename=\"SysCache0\"",
            "drivename=\"Q\"",
            "drivename=\"E\"",
            "drivename=\"DEVKIT\"",
            "drivename=\"HDD\"",
            "drivename=\"MUINT\""
        ]
    );
}

#[test]
fn a_stalled_transfer_reader_does_not_block_other_connections() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("big"), &vec![0x5a; 0x100_0000]);
    let mut stalled = session(&server);
    assert_eq!(
        stalled.command("getfile name=e:\\big"),
        "203- binary response follows"
    );
    // Let the transfer fill the socket buffers.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let mut other = session(&server);
    assert_eq!(other.command("srvproc num=1"), "200- prev=0");
}

#[test]
fn translation_handles_prefixes_and_dos_links() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("t"), b"t");
    let mut session = session(&server);
    for name in [
        "xe:\\t",
        "DEVKIT:\\t",
        "hdd:\\DEVKIT\\t",
        "Q:\\t",
        "\\Device\\Harddisk0\\Partition1\\DEVKIT\\t",
    ] {
        assert_eq!(
            session.command(&format!("getfileattributes name={name}")),
            "202- multiline response follows",
            "{name}"
        );
        session.multiline();
    }
    assert_eq!(session.command("getfileattributes name=e:t"), "400- ");
    assert_eq!(
        session.command("getfileattributes name=W:\\t"),
        "402- file not found"
    );
}

#[test]
fn rename_checks_both_names() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("r"), b"r");
    let mut session = session(&server);
    assert_eq!(
        session.command("rename name=e:\\r"),
        "400- missing new name"
    );
    assert_eq!(
        session.command("rename name=e:\\r newname=nodrive"),
        "402- new name does not exist"
    );
    assert_eq!(session.command("rename newname=e:\\s"), "400- missing name");
    assert_eq!(
        session.command("rename name=e:\\absent newname=e:\\s"),
        "414- access denied"
    );
    assert_eq!(
        session.command("rename name=e:\\r newname=muint:\\s"),
        "409- file must be copied"
    );
    assert_eq!(
        session.command("rename name=e:\\r newname=e:\\s"),
        "200- OK"
    );
    assert_eq!(
        server.host.lock().backend.filesystem.read(&devkit("s")),
        Some(&b"r"[..])
    );
}

#[test]
fn setfileattributes_changes_flags_and_times() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("a"), b"a");
    let mut session = session(&server);
    assert_eq!(
        session.command("setfileattributes name=e:\\a readonly=1 createhi=0x1 createlo=0x2 changehi=0x3 changelo=0x4"),
        "200- OK"
    );
    {
        let host = server.host.lock();
        let entry = host.backend.filesystem.entry(&devkit("a")).unwrap();
        assert_eq!(entry.attributes, FileAttributes::READONLY);
        assert_eq!(entry.creation_time.0, 0x1_0000_0002);
        assert_eq!(entry.last_write_time.0, 0x3_0000_0004);
    }
    assert_eq!(session.command("delete name=e:\\a"), "414- access denied");
    assert_eq!(
        session.command("setfileattributes name=e:\\a readonly=0"),
        "200- OK"
    );
    assert_eq!(
        server
            .host
            .lock()
            .backend
            .filesystem
            .entry(&devkit("a"))
            .unwrap()
            .attributes,
        FileAttributes::NONE
    );
}

#[test]
fn getvfattr_returns_records_in_order() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("v"), b"vvv");
    let mut session = session(&server);
    assert_eq!(session.command("getvfattr"), "400- missing count");
    assert_eq!(
        session.command("getvfattr count=2"),
        "204- send binary data"
    );
    for name in [&b"e:\\v\0"[..], b"e:\\none\0"] {
        session
            .stream
            .write_all(&(name.len() as u32).to_be_bytes())
            .unwrap();
        session.stream.write_all(name).unwrap();
    }
    assert_eq!(session.line(), "203- binary response follows");
    let records = read_bytes(&mut session, 2 * 0x1c);
    let word =
        |index: usize| u32::from_be_bytes(records[index * 4..index * 4 + 4].try_into().unwrap());
    assert_eq!((word(4), word(5), word(6)), (0, 3, 0));
    assert_eq!(word(13), u32::MAX);
    assert!((7..13).all(|index| word(index) == 0));
}

#[test]
fn sendvfile_reports_one_result_per_file() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("sendvfile count=3"),
        "204- send binary data"
    );
    let mut stream = Vec::new();
    for (name, data) in [
        (&b"e:\\one\0"[..], &b"first"[..]),
        (b"q:\\no\\two\0", b"xy"),
        (b"", b""),
    ] {
        stream.extend_from_slice(&(0x20 + name.len() as u32).to_be_bytes());
        stream.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        stream.extend_from_slice(&0x1112_1314_1516_1718u64.to_be_bytes());
        stream.extend_from_slice(&(data.len() as u64).to_be_bytes());
        stream.extend_from_slice(&0x1u32.to_be_bytes());
        stream.extend_from_slice(name);
        stream.extend_from_slice(data);
    }
    session.stream.write_all(&stream).unwrap();
    assert_eq!(session.line(), "203- binary response follows");
    let results = read_bytes(&mut session, 12);
    assert_eq!(results, [0, 0, 0, 0, 0x82, 0xda, 0, 0x1e, 0, 0, 0, 0]);
    let host = server.host.lock();
    let entry = host.backend.filesystem.entry(&devkit("one")).unwrap();
    assert_eq!(entry.data, b"first");
    assert_eq!(entry.creation_time.0, 0x0102_0304_0506_0708);
    assert_eq!(entry.last_write_time.0, 0x1112_1314_1516_1718);
    assert_eq!(entry.attributes, FileAttributes::READONLY);
}

#[test]
fn end_of_file_beyond_the_volume_is_disk_full() {
    use openxbdm_core::status::KernelError;
    use openxbdm_server::commands::filesystem::Backend as _;
    use openxbdm_server::commands::filesystem::CreateOptions;
    use openxbdm_server::commands::filesystem::CreateRequest;
    use openxbdm_server::commands::filesystem::FileAccess;
    use openxbdm_server::commands::filesystem::ShareAccess;

    let server = TestServer::start();
    let mut host = server.host.lock();
    host.backend.filesystem.write(&devkit("other"), b"data");
    host.backend.filesystem.write(&devkit("huge"), b"");
    let request = CreateRequest::open(
        FileAccess::GENERIC_WRITE,
        ShareAccess::NONE,
        CreateOptions::NONE,
    );
    let handle = host
        .backend
        .create_file(devkit("huge").as_bytes(), &request)
        .unwrap();
    assert_eq!(
        host.backend.set_end_of_file(handle, u64::MAX),
        Err(KernelError::DiskFull)
    );
    assert_eq!(
        host.backend.write_file(
            handle,
            Some(u64::MAX),
            openxbdm_server::commands::filesystem::FileData::Bytes(b"x")
        ),
        Err(KernelError::DiskFull)
    );
    host.backend.close_file(handle);
}

/// CRC-32/MPEG-2 without final inversion, bit by bit.
fn mpeg2_crc(data: impl IntoIterator<Item = u8>) -> u32 {
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(byte) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[test]
fn getsum_checksums_blocks_and_zeroes_unreadable_ones() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("getsum ADDR=0x80000000 LENGTH=0x20"),
        "400- missing BLOCKSIZE"
    );
    assert_eq!(
        session.command("getsum ADDR=0 LENGTH=0x20 BLOCKSIZE=0"),
        "423- Zero BLOCKSIZE not allowed."
    );
    let start = MEMORY_BASE + 0x0f_ff00;
    session.send(&format!(
        "getsum ADDR=0x{start:x} LENGTH=0x250 BLOCKSIZE=0x100"
    ));
    assert_eq!(session.line(), "203- binary response follows");
    let sums = read_bytes(&mut session, 8);
    let expected = mpeg2_crc((0xff00u32..0x1_0000).map(|offset| offset as u8));
    assert_eq!(u32::from_be_bytes(sums[..4].try_into().unwrap()), expected);
    assert_eq!(&sums[4..], [0, 0, 0, 0]);
    assert_eq!(
        session.command("getsum ADDR=0 LENGTH=4 BLOCKSIZE=8"),
        "203- binary response follows"
    );
    assert_eq!(session.command("getsum"), "400- missing ADDR");
}

#[test]
fn block_commands_transfer_raw_sectors() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("dvdblk block=1 count=0x41"),
        "400- Invalid block count: '65'."
    );
    assert_eq!(session.command("dvdblk count=1"), "400- missing block");
    assert_eq!(
        session.command("dvdblk block=2 count=1"),
        "203- binary response follows"
    );
    let sector = read_bytes(&mut session, 0x800);
    let expected = server.host.lock().backend.filesystem.devices[0].bytes[0x1000..0x1800].to_vec();
    assert_eq!(sector, expected);
    assert_eq!(session.command("dvdblk block=0"), "203- missing count");

    let data: Vec<u8> = (0..0x400u32).map(|value| (value ^ 0xa5) as u8).collect();
    assert_eq!(
        upload(
            &mut session,
            &format!("sethddblk name={HARDDISK} block=3 count=2"),
            &data
        ),
        "200- OK"
    );
    session.send(&format!("gethddblk name={HARDDISK} block=3 count=2"));
    assert_eq!(session.line(), "203- binary response follows");
    assert_eq!(read_bytes(&mut session, 0x400), data);
    assert_eq!(session.command("gethddblk block=0 count=1"), "400- ");
    assert_eq!(
        session.command("gethddblk name=\\Device\\None block=0 count=1"),
        "400- "
    );
    assert_eq!(
        session.command(&format!("sethddblk name={HARDDISK} block=0")),
        "204- missing count"
    );
    assert_eq!(session.line(), "400- ");
    assert_eq!(server.host.lock().backend.filesystem.pool_blocks(), 0);
}

#[test]
fn configuration_commands_update_settings() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("hdd"), "400- missing arguments");
    assert_eq!(session.command("hdd disable"), "200- OK");
    assert_eq!(server.host.lock().backend.console.xconfig.dword(2, 6), 1);
    assert_eq!(session.command("hdd enable"), "200- OK");
    assert_eq!(server.host.lock().backend.console.xconfig.dword(2, 6), 0);
    assert_eq!(session.command("prevflash prevflashver=0x1234"), "200- OK");
    assert_eq!(
        server.host.lock().backend.console.xconfig.dword(0xa, 2),
        0x1234
    );
    assert_eq!(session.command("dvdeject eject=0"), "200- OK");
    assert_eq!(session.command("dvdeject"), "200- OK");
    assert_eq!(server.host.lock().backend.filesystem.tray, [0, 1]);
}

#[test]
fn fmtfat_requires_force_or_a_pending_title() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("old"), b"x");
    let mut session = session(&server);
    assert_eq!(session.command("fmtfat partition=1"), "408- not stopped");
    assert_eq!(
        session.command("fmtfat force=1 partition=6"),
        "402- file not found"
    );
    assert_eq!(
        session.command("fmtfat force=1 partition=2"),
        "414- unable to format"
    );
    server.host.lock().backend.execution_state = ExecutionState::Pending;
    assert_eq!(session.command("fmtfat partition=1"), "200- missing force");
    let host = server.host.lock();
    assert_eq!(
        host.backend.filesystem.formatted,
        [b"\\Device\\Harddisk0\\Partition1".to_vec()]
    );
    assert!(host.backend.filesystem.entry(DEVKIT).is_none());
}

/// Reflected CRC-32 without final inversion.
fn reflected_crc(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[test]
fn sysfileupd_replaces_files_after_the_crc_check() {
    let server = TestServer::start();
    let mut session = session(&server);
    let target = "\\Device\\Harddisk0\\Partition1\\sys\\file.bin";
    let data: Vec<u8> = (0..0x5000u32).map(|value| (value * 3) as u8).collect();
    assert_eq!(
        session.command("sysfileupd ftimehi=0 ftimelo=0"),
        "400- HRESULT 0x80070057"
    );
    assert_eq!(
        upload(
            &mut session,
            &format!("sysfileupd name={target} ftimehi=1 ftimelo=2 size=0x5000 crc=0x1"),
            &data
        ),
        "400- HRESULT 0x80070017"
    );
    let crc = reflected_crc(&data);
    let command = format!("sysfileupd name={target} ftimehi=1 ftimelo=2 size=0x5000 crc=0x{crc:x}");
    assert_eq!(upload(&mut session, &command, &data), "200- OK");
    {
        let host = server.host.lock();
        let entry = host.backend.filesystem.entry(target).unwrap();
        assert_eq!(entry.data, data);
        assert_eq!(entry.last_write_time.0, 0x1_0000_0002);
        assert!(
            host.backend
                .filesystem
                .entry("\\Device\\Harddisk0\\Partition1\\sys\\temp1234.tmp")
                .is_none()
        );
    }
    assert_eq!(
        session.command(&format!("sysfileupd name={target} query=1")),
        "200- 0x5000 0x100000002"
    );
    assert_eq!(
        session.command("sysfileupd name=\\Device\\None\\x query=1"),
        "400- HRESULT 0x80070003"
    );
}

#[test]
fn dvdperf_reports_valid_trace_records() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("dvdperf stop report"),
        "400- nothing to report"
    );
    assert_eq!(session.command("dvdperf start"), "200- OK");
    {
        let mut host = server.host.lock();
        host.backend
            .filesystem
            .record_dvd_request(5000, 0x20, 4, 7, true);
        host.backend
            .filesystem
            .record_dvd_request(6000, 0x30, 1, 8, false);
        host.backend
            .filesystem
            .record_dvd_request(9000, 0x40, 2, 9, true);
    }
    assert_eq!(
        session.command("dvdperf stop report"),
        "202- multiline response follows"
    );
    assert_eq!(
        session.multiline(),
        [
            "timestamp=0 time=7 lba=32 cblk=4",
            "timestamp=4 time=9 lba=64 cblk=2"
        ]
    );
    assert_eq!(session.command("dvdperf"), "400- ");
}

#[test]
fn interrupted_transfers_release_their_resources() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("big"), &vec![0x5a; 0x100_0000]);
    let released = |host: &openxbdm_server_host::Host| {
        host.backend.filesystem.open_handles() == 0 && host.backend.filesystem.pool_blocks() == 0
    };

    let mut sender = session(&server);
    assert_eq!(
        sender.command("getfile name=e:\\big"),
        "203- binary response follows"
    );
    read_bytes(&mut sender, 0x1000);
    drop(sender);
    server.wait_until(released);

    let mut receiver = session(&server);
    assert_eq!(
        receiver.command("sendfile name=e:\\part length=0x10000"),
        "204- send binary data"
    );
    receiver.stream.write_all(&[1; 0x100]).unwrap();
    drop(receiver);
    server.wait_until(released);

    // A cut `sysfileupd` upload leaves its temporary file open and marked
    // for deletion.
    let mut update = session(&server);
    let command = "sysfileupd name=\\Device\\Harddisk0\\Partition1\\sys\\x.bin ftimehi=0 ftimelo=0 size=0x100 crc=0";
    assert_eq!(update.command(command), "204- send binary data");
    update.stream.write_all(&[2; 0x10]).unwrap();
    drop(update);
    server.wait_until(|host| host.backend.filesystem.pool_blocks() == 0);
    let host = server.host.lock();
    assert_eq!(host.backend.filesystem.open_handles(), 1);
    assert!(
        host.backend
            .filesystem
            .entry("\\Device\\Harddisk0\\Partition1\\sys\\temp1234.tmp")
            .is_some()
    );
}

#[test]
fn line_buffer_allocation_failures() {
    let server = TestServer::start();
    server.host.lock().backend.filesystem.pool_exhausted = true;
    let mut session = session(&server);
    assert_eq!(session.command("dirlist name=e:\\"), "400- out of memory");
    assert_eq!(session.command("drivefreespace name=e:\\"), "400- ");
    assert_eq!(server.host.lock().backend.filesystem.open_handles(), 0);
}

fn write_memory(server: &TestServer, address: u32, bytes: &[u8]) {
    let mut host = server.host.lock();
    let region = host
        .backend
        .memory
        .regions
        .iter_mut()
        .find(|region| region.base == MEMORY_BASE)
        .unwrap();
    let offset = (address - MEMORY_BASE) as usize;
    region.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
}

/// Run control code 0x03 for `name`, pointing at a string stored at
/// `target` (or removing the drive).
fn map_title_drive(server: &TestServer, name: &[u8], target: Option<(u32, &[u8])>) {
    let request = MEMORY_BASE + 0x8000;
    let mut bytes = [0u8; 0x24];
    bytes[..name.len()].copy_from_slice(name);
    if let Some((address, text)) = target {
        write_memory(server, address, &[text, b"\0"].concat());
        bytes[0x20..].copy_from_slice(&address.to_be_bytes());
    }
    write_memory(server, request, &bytes);
    let mut guard = server.host.lock();
    let openxbdm_server_host::Host {
        server, backend, ..
    } = &mut *guard;
    openxbdm_server::commands::filesystem::map_title_drive(&mut server.state, backend, request);
}

#[test]
fn title_drive_mappings_follow_the_monitor_table() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        host.backend.filesystem.write(&devkit("sub\\f"), b"f");
        host.backend.filesystem.write(&devkit("sux\\g"), b"g");
    }
    let target = MEMORY_BASE + 0x8100;
    map_title_drive(
        &server,
        b"T",
        Some((target, b"\\Device\\Harddisk0\\Partition1\\DEVKIT\\sub")),
    );
    // The table is full after the appended row.
    map_title_drive(&server, b"V", Some((MEMORY_BASE + 0x8200, b"\\Device")));
    let mut session = session(&server);
    assert_eq!(
        session.command("getfileattributes name=T:\\f"),
        "202- multiline response follows"
    );
    session.multiline();
    assert_eq!(
        session.command("drivelist"),
        "202- multiline response follows"
    );
    let table = [
        "drivename=\"E\"",
        "drivename=\"DEVKIT\"",
        "drivename=\"HDD\"",
        "drivename=\"MUINT\"",
    ];
    let listed = session.multiline();
    assert_eq!(listed[2..], [&table[..], &["drivename=\"T\""]].concat());

    // The table keeps the title's pointer.
    write_memory(&server, target + 0x26, b"x");
    assert_eq!(
        session.command("getfileattributes name=T:\\g"),
        "202- multiline response follows"
    );
    session.multiline();
    // Translation reads the string to its current end.
    write_memory(&server, target + 0x23, b"\0");
    assert_eq!(
        session.command("getfileattributes name=T:\\sub\\f"),
        "202- multiline response follows"
    );
    session.multiline();

    // Removing a row moves the last row into its place.
    map_title_drive(&server, b"A", None);
    assert_eq!(
        session.command("drivelist"),
        "202- multiline response follows"
    );
    let listed = session.multiline();
    assert_eq!(listed[2..], [&["drivename=\"T\""], &table[..]].concat());
}

#[test]
fn file_change_counter_counts_closes_of_changed_files() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .filesystem
        .write(&devkit("c"), b"c");
    let mut session = session(&server);
    let changes = |server: &TestServer| server.host.lock().backend.filesystem.file_changes;
    assert_eq!(session.command("mkdir name=e:\\d"), "200- OK");
    assert_eq!(session.command("fileeof name=e:\\c size=4"), "200- OK");
    assert_eq!(
        session.command("rename name=e:\\c newname=e:\\d\\c"),
        "200- OK"
    );
    assert_eq!(changes(&server), 3);
    // Failed opens and read-only commands do not count.
    assert_eq!(
        session.command("delete name=e:\\none"),
        "402- file not found"
    );
    assert_eq!(
        session.command("getfileattributes name=e:\\d\\c"),
        "202- multiline response follows"
    );
    session.multiline();
    assert_eq!(
        upload(&mut session, "sendfile name=e:\\s length=2", b"ab"),
        "200- OK"
    );
    assert_eq!(changes(&server), 4);
}
