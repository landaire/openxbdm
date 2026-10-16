//! CREATE, READ, WRITE, FLUSH, CLOSE, SET_INFO, and path validation.

use smb2_server::status::NtStatus;

use crate::backend::DATA;
use crate::backend::PUBLIC;
use crate::backend::TIME;
use crate::backend::utf16;
use crate::client::Client;
use crate::client::access;
use crate::client::command;
use crate::client::create_body;
use crate::client::create_context;
use crate::client::disposition;
use crate::client::options;
use crate::client::u16_at;
use crate::client::u32_at;
use crate::client::u64_at;

const INFO_FILE: u8 = 1;
const FILE_BASIC_INFORMATION: u8 = 4;
const FILE_STANDARD_INFORMATION: u8 = 5;
const FILE_INTERNAL_INFORMATION: u8 = 6;
const FILE_RENAME_INFORMATION: u8 = 10;
const FILE_DISPOSITION_INFORMATION: u8 = 13;
const FILE_END_OF_FILE_INFORMATION: u8 = 20;
const CLOSE_POSTQUERY_ATTRIB: u16 = 1;

fn pattern(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index * 7 + index / 251) as u8)
        .collect()
}

#[test]
fn write_and_read_64_kib_in_one_request() {
    let mut client = Client::connected("Data");
    let file = client.open("big.bin", disposition::CREATE);
    let data = pattern(0x1_0000);
    let reply = client.write(file, 0, &data);
    reply.expect(NtStatus::Success);
    assert_eq!(u32_at(reply.body(), 4), 0x1_0000);

    let reply = client.read(file, 0, 0x1_0000);
    reply.expect(NtStatus::Success);
    assert_eq!(reply.data(), &data[..]);

    let reply = client.read(file, 0x1_0000 - 100, 1000);
    assert_eq!(reply.data(), &data[0x1_0000 - 100..]);
    client.read(file, 0x1_0000, 1).expect(NtStatus::EndOfFile);
    client.read(file, 0x10_0000, 1).expect(NtStatus::EndOfFile);
    client
        .read(file, 0, 0x1_0001)
        .expect(NtStatus::InvalidParameter);
}

#[test]
fn write_at_all_ones_offset_appends() {
    let mut client = Client::connected("Data");
    let file = client.open("log.txt", disposition::CREATE);
    client.write(file, 0, b"abc").expect(NtStatus::Success);
    client
        .write(file, u64::MAX, b"def")
        .expect(NtStatus::Success);
    client
        .write(file, u64::MAX, b"gh")
        .expect(NtStatus::Success);
    assert_eq!(
        client.backend.contents(DATA, "log.txt"),
        Some(&b"abcdefgh"[..])
    );
}

#[test]
fn flush_requires_write_access() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"a");
    let file = client.open("a.txt", disposition::OPEN);
    client.flush(file).expect(NtStatus::Success);
    let file = client
        .create("a.txt", access::READ, disposition::OPEN, 0)
        .file_id();
    client.flush(file).expect(NtStatus::AccessDenied);
}

#[test]
fn close_with_postquery_returns_attributes() {
    let mut client = Client::connected("Data");
    let file = client.open("sized.bin", disposition::CREATE);
    client
        .write(file, 0, &[0x5a; 5000])
        .expect(NtStatus::Success);
    let reply = client.close(file, CLOSE_POSTQUERY_ATTRIB);
    reply.expect(NtStatus::Success);
    let body = reply.body();
    assert_eq!(u16_at(body, 0), 60);
    assert_eq!(u16_at(body, 2), CLOSE_POSTQUERY_ATTRIB);
    assert_eq!(u64_at(body, 8), TIME.0);
    assert_eq!(u64_at(body, 40), 8192);
    assert_eq!(u64_at(body, 48), 5000);
    assert_eq!(u32_at(body, 56), 0x20);
    client.close(file, 0).expect(NtStatus::FileClosed);

    let file = client.open("sized.bin", disposition::OPEN);
    let reply = client.close(file, 0);
    assert!(reply.body()[2..60].iter().all(|&byte| byte == 0));
}

#[test]
fn create_dispositions_and_directory_options() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"old");
    client.backend.add_directory(DATA, "dir");
    let create = |client: &mut Client, name, disposition, options| {
        client.create(name, access::ALL, disposition, options)
    };
    create(&mut client, "a.txt", disposition::CREATE, 0).expect(NtStatus::ObjectNameCollision);
    let reply = create(&mut client, "a.txt", disposition::OVERWRITE_IF, 0);
    // CreateAction FILE_OVERWRITTEN, EndofFile 0.
    assert_eq!(u32_at(reply.body(), 4), 3);
    assert_eq!(u64_at(reply.body(), 48), 0);
    let reply = create(&mut client, "b.txt", disposition::OPEN_IF, 0);
    assert_eq!(u32_at(reply.body(), 4), 2);
    create(&mut client, "missing\\c.txt", disposition::CREATE, 0)
        .expect(NtStatus::ObjectPathNotFound);
    create(
        &mut client,
        "dir",
        disposition::OPEN,
        options::NON_DIRECTORY_FILE,
    )
    .expect(NtStatus::FileIsADirectory);
    create(
        &mut client,
        "a.txt",
        disposition::OPEN,
        options::DIRECTORY_FILE,
    )
    .expect(NtStatus::NotADirectory);
    create(
        &mut client,
        "a.txt",
        disposition::OPEN,
        options::DIRECTORY_FILE | options::NON_DIRECTORY_FILE,
    )
    .expect(NtStatus::InvalidParameter);
    let reply = create(
        &mut client,
        "dir",
        disposition::OPEN,
        options::DIRECTORY_FILE,
    );
    assert_eq!(u32_at(reply.body(), 56), 0x10);
    let file = reply.file_id();
    client
        .read(file, 0, 10)
        .expect(NtStatus::InvalidDeviceRequest);
}

/// FILE_RENAME_INFORMATION_TYPE_2 naming `target`.
pub fn rename_information(target: &str, replace: bool) -> Vec<u8> {
    let name = utf16(target);
    let mut data = vec![0u8; 20];
    data[0] = u8::from(replace);
    data[16..20].copy_from_slice(&(name.len() as u32).to_le_bytes());
    data.extend(name);
    data
}

#[test]
fn rename_without_replace_refuses_existing_target() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"from a");
    client.backend.add_file(DATA, "b.txt", b"from b");
    let file = client.open("a.txt", disposition::OPEN);
    client
        .set_info(
            file,
            INFO_FILE,
            FILE_RENAME_INFORMATION,
            &rename_information("b.txt", false),
        )
        .expect(NtStatus::ObjectNameCollision);
    assert_eq!(client.backend.contents(DATA, "b.txt"), Some(&b"from b"[..]));

    client
        .set_info(
            file,
            INFO_FILE,
            FILE_RENAME_INFORMATION,
            &rename_information("c.txt", false),
        )
        .expect(NtStatus::Success);
    assert!(client.backend.contents(DATA, "a.txt").is_none());
    assert_eq!(client.backend.contents(DATA, "c.txt"), Some(&b"from a"[..]));
    // The open follows the file.
    assert_eq!(client.read(file, 0, 100).data(), b"from a");
}

#[test]
fn rename_with_replace_overwrites_target() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"from a");
    client.backend.add_file(DATA, "b.txt", b"from b");
    client.backend.add_directory(DATA, "dir");
    let file = client.open("a.txt", disposition::OPEN);
    // A leading separator names the share root.
    client
        .set_info(
            file,
            INFO_FILE,
            FILE_RENAME_INFORMATION,
            &rename_information("\\b.txt", true),
        )
        .expect(NtStatus::Success);
    assert!(client.backend.contents(DATA, "a.txt").is_none());
    assert_eq!(client.backend.contents(DATA, "b.txt"), Some(&b"from a"[..]));
    client
        .set_info(
            file,
            INFO_FILE,
            FILE_RENAME_INFORMATION,
            &rename_information("dir\\d.txt", true),
        )
        .expect(NtStatus::Success);
    assert_eq!(
        client.backend.contents(DATA, "dir\\d.txt"),
        Some(&b"from a"[..])
    );
}

#[test]
fn rename_requires_delete_access() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"");
    let file = client
        .create(
            "a.txt",
            access::READ | access::WRITE_DATA,
            disposition::OPEN,
            0,
        )
        .file_id();
    client
        .set_info(
            file,
            INFO_FILE,
            FILE_RENAME_INFORMATION,
            &rename_information("b.txt", false),
        )
        .expect(NtStatus::AccessDenied);
}

#[test]
fn delete_pending_removes_file_on_last_close() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "doomed.txt", b"bye");
    let first = client.open("doomed.txt", disposition::OPEN);
    let second = client.open("doomed.txt", disposition::OPEN);
    client
        .set_info(first, INFO_FILE, FILE_DISPOSITION_INFORMATION, &[1])
        .expect(NtStatus::Success);
    client.close(first, 0).expect(NtStatus::Success);
    assert!(client.backend.contents(DATA, "doomed.txt").is_some());
    client.close(second, 0).expect(NtStatus::Success);
    assert!(client.backend.contents(DATA, "doomed.txt").is_none());
    client
        .create("doomed.txt", access::READ, disposition::OPEN, 0)
        .expect(NtStatus::ObjectNameNotFound);
}

#[test]
fn cleared_delete_pending_keeps_file() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "kept.txt", b"stay");
    let file = client.open("kept.txt", disposition::OPEN);
    for value in [1, 0] {
        client
            .set_info(file, INFO_FILE, FILE_DISPOSITION_INFORMATION, &[value])
            .expect(NtStatus::Success);
    }
    client.close(file, 0);
    assert!(client.backend.contents(DATA, "kept.txt").is_some());
}

#[test]
fn end_of_file_truncates_and_extends() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.bin", b"0123456789abcdef");
    let file = client.open("a.bin", disposition::OPEN);
    client
        .set_info(
            file,
            INFO_FILE,
            FILE_END_OF_FILE_INFORMATION,
            &4u64.to_le_bytes(),
        )
        .expect(NtStatus::Success);
    let standard = client.query_info(file, INFO_FILE, FILE_STANDARD_INFORMATION, 0, 24);
    assert_eq!(u64_at(standard.output(), 8), 4);
    client
        .set_info(
            file,
            INFO_FILE,
            FILE_END_OF_FILE_INFORMATION,
            &8u64.to_le_bytes(),
        )
        .expect(NtStatus::Success);
    assert_eq!(client.read(file, 0, 100).data(), b"0123\0\0\0\0");
    client
        .set_info(file, INFO_FILE, FILE_END_OF_FILE_INFORMATION, &[0; 7])
        .expect(NtStatus::InfoLengthMismatch);
}

#[test]
fn basic_information_sets_given_times_only() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"");
    let file = client.open("a.txt", disposition::OPEN);
    let written = 0x01da_0000_1234_5678u64;
    let mut data = vec![0u8; 40];
    data[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    data[16..24].copy_from_slice(&written.to_le_bytes());
    data[32..36].copy_from_slice(&0x21u32.to_le_bytes());
    client
        .set_info(file, INFO_FILE, FILE_BASIC_INFORMATION, &data)
        .expect(NtStatus::Success);
    let basic = client.query_info(file, INFO_FILE, FILE_BASIC_INFORMATION, 0, 40);
    let output = basic.output();
    assert_eq!(u64_at(output, 0), TIME.0);
    assert_eq!(u64_at(output, 8), TIME.0);
    assert_eq!(u64_at(output, 16), written);
    assert_eq!(u64_at(output, 24), TIME.0);
    assert_eq!(u32_at(output, 32), 0x21);

    let file = client
        .create("a.txt", access::READ, disposition::OPEN, 0)
        .file_id();
    client
        .set_info(file, INFO_FILE, FILE_BASIC_INFORMATION, &data)
        .expect(NtStatus::AccessDenied);
}

#[test]
fn invalid_paths_are_rejected() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"a");
    client.backend.add_directory(DATA, "dir");
    for (name, status) in [
        ("dir\\..\\a.txt", NtStatus::ObjectNameInvalid),
        ("..\\a.txt", NtStatus::ObjectNameInvalid),
        (".", NtStatus::ObjectNameInvalid),
        ("dir\\\\a.txt", NtStatus::ObjectNameInvalid),
        ("a*.txt", NtStatus::ObjectNameInvalid),
        ("\\a.txt", NtStatus::InvalidParameter),
    ] {
        let reply = client.create(name, access::READ, disposition::OPEN, 0);
        assert_eq!(reply.status(), status, "{name}");
    }
    let file = client
        .create("a.txt::$DATA", access::READ, disposition::OPEN, 0)
        .file_id();
    assert_eq!(client.read(file, 0, 10).data(), b"a");

    let file = client.open("a.txt", disposition::OPEN);
    client
        .set_info(
            file,
            INFO_FILE,
            FILE_RENAME_INFORMATION,
            &rename_information("..\\b.txt", false),
        )
        .expect(NtStatus::ObjectNameInvalid);
    client
        .set_info(
            file,
            INFO_FILE,
            FILE_RENAME_INFORMATION,
            &rename_information("\\", false),
        )
        .expect(NtStatus::ObjectNameInvalid);
}

#[test]
fn delete_on_close_removes_file_on_writable_share() {
    let mut client = Client::connected("Data");
    let file = client
        .create(
            "temp.txt",
            access::ALL,
            disposition::CREATE,
            options::NON_DIRECTORY_FILE | options::DELETE_ON_CLOSE,
        )
        .file_id();
    client.write(file, 0, b"scratch").expect(NtStatus::Success);
    assert!(client.backend.contents(DATA, "temp.txt").is_some());
    client.close(file, 0).expect(NtStatus::Success);
    assert!(client.backend.contents(DATA, "temp.txt").is_none());

    client.backend.add_file(DATA, "max.txt", b"");
    let file = client
        .create(
            "max.txt",
            access::MAXIMUM_ALLOWED,
            disposition::OPEN,
            options::DELETE_ON_CLOSE,
        )
        .file_id();
    client.close(file, 0).expect(NtStatus::Success);
    assert!(client.backend.contents(DATA, "max.txt").is_none());
}

#[test]
fn delete_on_close_requires_delete_access() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "kept.txt", b"stay");
    client
        .create(
            "kept.txt",
            access::READ | access::WRITE_DATA,
            disposition::OPEN,
            options::DELETE_ON_CLOSE,
        )
        .expect(NtStatus::AccessDenied);
    assert_eq!(client.backend.open_handles(), 0);
}

#[test]
fn delete_on_close_on_read_only_share_is_denied() {
    let mut client = Client::logged_on();
    client.backend.add_file(PUBLIC, "readme.txt", b"read me");
    client.tree_connect("Public").expect(NtStatus::Success);
    for rights in [access::MAXIMUM_ALLOWED, access::READ] {
        client
            .create(
                "readme.txt",
                rights,
                disposition::OPEN,
                options::DELETE_ON_CLOSE,
            )
            .expect(NtStatus::AccessDenied);
    }
    assert_eq!(client.backend.open_handles(), 0);
    assert_eq!(
        client.backend.contents(PUBLIC, "readme.txt"),
        Some(&b"read me"[..])
    );
}

#[test]
fn query_on_disk_id_context_layout() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "id.txt", b"");
    let body = create_body(
        "id.txt",
        access::READ,
        disposition::OPEN,
        0,
        &create_context(b"QFid"),
    );
    let reply = client.call(command::CREATE, &body);
    reply.expect(NtStatus::Success);
    let index = client
        .query_info(reply.file_id(), INFO_FILE, FILE_INTERNAL_INFORMATION, 0, 8)
        .output()
        .to_vec();
    let start = u32_at(reply.body(), 80) as usize;
    assert_eq!(u32_at(reply.body(), 84), 56);
    let context = &reply.0[start..];
    // Next 0, NameOffset 16, NameLength 4, DataOffset 24, DataLength 32.
    assert_eq!(u32_at(context, 0), 0);
    assert_eq!(u16_at(context, 4), 16);
    assert_eq!(u16_at(context, 6), 4);
    assert_eq!(u16_at(context, 10), 24);
    assert_eq!(u32_at(context, 12), 32);
    assert_eq!(&context[16..20], b"QFid");
    // DiskFileId, VolumeId, 16 reserved bytes.
    let data = &context[24..56];
    assert_eq!(&data[..8], &index[..]);
    assert_ne!(u64_at(data, 0), 0);
    assert_eq!(u64_at(data, 8), 0x1234_5678);
    assert!(data[16..].iter().all(|&byte| byte == 0));
}

#[test]
fn open_share_root_does_not_hold_path_space() {
    let mut client = Client::connected("Data");
    let first = "a".repeat(3000);
    let second = "b".repeat(3000);
    client.backend.add_file(DATA, &first, b"");
    client.backend.add_file(DATA, &second, b"");
    let file = client.open(&first, disposition::OPEN);
    client.open_directory("");
    client.close(file, 0).expect(NtStatus::Success);
    client.open(&second, disposition::OPEN);
}

#[test]
fn rename_without_path_space_leaves_the_file_in_place() {
    let mut client = Client::connected("Data");
    for index in 0..4 {
        let name = format!("{index}{}", "n".repeat(999));
        client.backend.add_file(DATA, &name, b"");
        client.open(&name, disposition::OPEN);
    }
    client.backend.add_file(DATA, "x.txt", b"x");
    let file = client.open("x.txt", disposition::OPEN);
    let target = "y".repeat(200);
    client
        .set_info(
            file,
            INFO_FILE,
            FILE_RENAME_INFORMATION,
            &rename_information(&target, false),
        )
        .expect(NtStatus::InsufficientResources);
    assert_eq!(client.backend.contents(DATA, "x.txt"), Some(&b"x"[..]));
    assert!(client.backend.contents(DATA, &target).is_none());
}
