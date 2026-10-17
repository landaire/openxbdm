//! QUERY_INFO file, file system, and security classes.

use smb2_server::server::FileId;
use smb2_server::status::NtStatus;

use crate::backend::DATA;
use crate::backend::utf16;
use crate::client::Client;
use crate::client::config;
use crate::client::dialect;
use crate::client::disposition;
use crate::client::hex;
use crate::client::u32_at;
use crate::client::u64_at;

const INFO_FILE: u8 = 1;
const INFO_FILESYSTEM: u8 = 2;
const INFO_SECURITY: u8 = 3;
const FILE_STANDARD_INFORMATION: u8 = 5;
const FILE_ALL_INFORMATION: u8 = 18;
const FILE_STREAM_INFORMATION: u8 = 22;
const FILE_NETWORK_OPEN_INFORMATION: u8 = 34;
const FILE_FS_VOLUME_INFORMATION: u8 = 1;
const FILE_FS_ATTRIBUTE_INFORMATION: u8 = 5;
const OWNER_GROUP_DACL: u32 = 0x7;
const LARGE: u32 = 0x1_0000;

/// One QUERY_INFO request and the snapshot name of its output.
struct InformationCase {
    name: &'static str,
    info_type: u8,
    class: u8,
    additional: u32,
}

impl InformationCase {
    const fn new(name: &'static str, info_type: u8, class: u8, additional: u32) -> Self {
        Self {
            name,
            info_type,
            class,
            additional,
        }
    }
}

fn client_with_file() -> (Client, FileId) {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "info.txt", &[0x42; 5000]);
    let file = client.open("info.txt", disposition::OPEN);

    (client, file)
}

#[test]
fn information_classes() {
    const FILE_FS_FULL_SIZE_INFORMATION: u8 = 7;

    let (mut client, file) = client_with_file();

    for case in [
        InformationCase::new("file_all", INFO_FILE, FILE_ALL_INFORMATION, 0),
        InformationCase::new(
            "file_network_open",
            INFO_FILE,
            FILE_NETWORK_OPEN_INFORMATION,
            0,
        ),
        InformationCase::new("file_stream", INFO_FILE, FILE_STREAM_INFORMATION, 0),
        InformationCase::new("fs_volume", INFO_FILESYSTEM, FILE_FS_VOLUME_INFORMATION, 0),
        InformationCase::new(
            "fs_attribute",
            INFO_FILESYSTEM,
            FILE_FS_ATTRIBUTE_INFORMATION,
            0,
        ),
        InformationCase::new(
            "fs_full_size",
            INFO_FILESYSTEM,
            FILE_FS_FULL_SIZE_INFORMATION,
            0,
        ),
        InformationCase::new(
            "security_owner_group_dacl",
            INFO_SECURITY,
            0,
            OWNER_GROUP_DACL,
        ),
    ] {
        let reply = client.query_info(file, case.info_type, case.class, case.additional, LARGE);
        reply.expect(NtStatus::Success);
        insta::assert_snapshot!(case.name, hex(reply.output()));
    }
}

#[test]
fn directory_standard_information() {
    let mut client = Client::connected("Data");
    client.backend.add_directory(DATA, "dir");
    let directory = client.open_directory("dir");

    let reply = client.query_info(directory, INFO_FILE, FILE_STANDARD_INFORMATION, 0, 24);
    // Directory flag.
    assert_eq!(reply.output()[21], 1);

    let reply = client.query_info(directory, INFO_FILE, FILE_STREAM_INFORMATION, 0, LARGE);
    reply.expect(NtStatus::Success);
    assert!(reply.output().is_empty());
}

#[test]
fn small_security_buffer_reports_required_length() {
    let (mut client, file) = client_with_file();

    let full = client.query_info(file, INFO_SECURITY, 0, OWNER_GROUP_DACL, LARGE);
    let required = full.output().len() as u32;
    assert_eq!(required, 72);

    let reply = client.query_info(file, INFO_SECURITY, 0, OWNER_GROUP_DACL, required - 1);
    reply.expect(NtStatus::BufferTooSmall);
    assert_eq!(reply.error_data(), required.to_le_bytes());

    // Owner only: header and one SID.
    let owner = client.query_info(file, INFO_SECURITY, 0, 0x1, LARGE);
    assert_eq!(owner.output().len(), 32);
    assert_eq!(u32_at(owner.output(), 4), 20);
    assert_eq!(u32_at(owner.output(), 16), 0);
}

#[test]
fn small_fixed_class_buffer_is_length_mismatch() {
    let (mut client, file) = client_with_file();

    client
        .query_info(file, INFO_FILE, FILE_NETWORK_OPEN_INFORMATION, 0, 55)
        .expect(NtStatus::InfoLengthMismatch);
    let reply = client.query_info(file, INFO_FILE, FILE_NETWORK_OPEN_INFORMATION, 0, 56);
    reply.expect(NtStatus::Success);
    assert_eq!(u64_at(reply.output(), 40), 5000);

    client
        .query_info(file, INFO_FILE, FILE_STREAM_INFORMATION, 0, 23)
        .expect(NtStatus::InfoLengthMismatch);
}

#[test]
fn truncated_variable_class_overflows() {
    let (mut client, file) = client_with_file();

    let full = client.query_info(file, INFO_FILE, FILE_STREAM_INFORMATION, 0, LARGE);
    let full = full.output().to_vec();
    let reply = client.query_info(file, INFO_FILE, FILE_STREAM_INFORMATION, 0, 30);
    reply.expect(NtStatus::BufferOverflow);
    assert_eq!(reply.output(), &full[..30]);

    let reply = client.query_info(file, INFO_FILESYSTEM, FILE_FS_ATTRIBUTE_INFORMATION, 0, 14);
    reply.expect(NtStatus::BufferOverflow);
    assert_eq!(reply.output().len(), 14);
    // FileSystemNameLength keeps the full length.
    assert_eq!(u32_at(reply.output(), 8), 8);
}

#[test]
fn file_all_information_ends_with_the_share_relative_name() {
    let (mut client, file) = client_with_file();
    client
        .query_info(file, INFO_FILE, FILE_ALL_INFORMATION, 0, 99)
        .expect(NtStatus::InfoLengthMismatch);

    // The fixed part fits, the name does not: the reply is cut short and
    // FileNameLength keeps the full length.
    let fixed = client.query_info(file, INFO_FILE, FILE_ALL_INFORMATION, 0, 100);
    fixed.expect(NtStatus::BufferOverflow);
    assert_eq!(fixed.output().len(), 100);
    assert_eq!(u32_at(fixed.output(), 96), 18);

    let full = client.query_info(file, INFO_FILE, FILE_ALL_INFORMATION, 0, LARGE);
    full.expect(NtStatus::Success);
    assert_eq!(full.output().len(), 118);
    assert_eq!(&full.output()[..100], fixed.output());
    assert_eq!(&full.output()[100..], utf16("\\info.txt"));

    client.backend.add_directory(DATA, "dir");
    client.backend.add_file(DATA, "dir\\inner.txt", b"");
    let inner = client.open("dir\\inner.txt", disposition::OPEN);
    let reply = client.query_info(inner, INFO_FILE, FILE_ALL_INFORMATION, 0, LARGE);
    reply.expect(NtStatus::Success);
    assert_eq!(&reply.output()[100..], utf16("\\dir\\inner.txt"));
}

#[test]
fn normalized_name_is_a_smb_3_1_1_class() {
    const FILE_NORMALIZED_NAME_INFORMATION: u8 = 48;

    let (mut client, file) = client_with_file();
    client
        .query_info(file, INFO_FILE, FILE_NORMALIZED_NAME_INFORMATION, 0, LARGE)
        .expect(NtStatus::NotSupported);

    let mut client = Client::smb3(config(false), dialect::SMB_3_1_1, &[], &[]);
    client.tree_connect("Data").expect(NtStatus::Success);
    client.backend.add_directory(DATA, "dir");
    client.backend.add_file(DATA, "dir\\a.txt", b"");
    let file = client.open("dir\\a.txt", disposition::OPEN);

    let reply = client.query_info(file, INFO_FILE, FILE_NORMALIZED_NAME_INFORMATION, 0, LARGE);
    reply.expect(NtStatus::Success);
    let mut expected = 18u32.to_le_bytes().to_vec();
    expected.extend(utf16("dir\\a.txt"));
    assert_eq!(reply.output(), expected);

    let short = client.query_info(file, INFO_FILE, FILE_NORMALIZED_NAME_INFORMATION, 0, 8);
    short.expect(NtStatus::BufferOverflow);
    assert_eq!(short.output(), &expected[..8]);

    client
        .query_info(file, INFO_FILE, FILE_NORMALIZED_NAME_INFORMATION, 0, 3)
        .expect(NtStatus::InfoLengthMismatch);
}

#[test]
fn volume_information_accepts_its_fixed_part() {
    let (mut client, file) = client_with_file();
    client
        .query_info(file, INFO_FILESYSTEM, FILE_FS_VOLUME_INFORMATION, 0, 17)
        .expect(NtStatus::InfoLengthMismatch);

    let fixed = client.query_info(file, INFO_FILESYSTEM, FILE_FS_VOLUME_INFORMATION, 0, 18);
    fixed.expect(NtStatus::Success);
    assert_eq!(fixed.output().len(), 18);
    // VolumeLabelLength.
    assert_eq!(u32_at(fixed.output(), 12), 0);
}

#[test]
fn standard_information_reports_delete_pending_of_the_open() {
    const FILE_DISPOSITION_INFORMATION: u8 = 13;

    let (mut client, file) = client_with_file();
    let delete_pending = |client: &mut Client| {
        client
            .query_info(file, INFO_FILE, FILE_STANDARD_INFORMATION, 0, 24)
            .output()[20]
    };
    assert_eq!(delete_pending(&mut client), 0);

    client
        .set_info(file, INFO_FILE, FILE_DISPOSITION_INFORMATION, &[1])
        .expect(NtStatus::Success);
    assert_eq!(delete_pending(&mut client), 1);

    let all = client.query_info(file, INFO_FILE, FILE_ALL_INFORMATION, 0, 104);
    assert_eq!(all.output()[60], 1);

    client
        .set_info(file, INFO_FILE, FILE_DISPOSITION_INFORMATION, &[0])
        .expect(NtStatus::Success);
    assert_eq!(delete_pending(&mut client), 0);
}
