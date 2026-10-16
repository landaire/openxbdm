//! QUERY_DIRECTORY (MS-SMB2 3.3.5.18) with FileIdBothDirectoryInformation.

use smb2_server::server::FileId;
use smb2_server::status::NtStatus;

use crate::backend::DATA;
use crate::client::Client;
use crate::client::Message;
use crate::client::hex;
use crate::client::u32_at;

const ID_BOTH: u8 = 37;
/// Bytes of FileIdBothDirectoryInformation before the name.
const ID_BOTH_FIXED: usize = 104;
const RESTART_SCANS: u8 = 0x01;
const RETURN_SINGLE_ENTRY: u8 = 0x02;
const LARGE: u32 = 0x1_0000;

const ROOT: [&str; 7] = [".", "..", "a.txt", "b.txt", "c.dat", "sub", "x.y.txt"];

fn client_with_tree() -> (Client, FileId) {
    let mut client = Client::connected("Data");
    for name in ["a.txt", "b.txt", "c.dat", "x.y.txt"] {
        client.backend.add_file(DATA, name, name.as_bytes());
    }
    client.backend.add_directory(DATA, "sub");
    client.backend.add_file(DATA, "sub\\inner.txt", b"");
    let root = client.open_directory("");
    (client, root)
}

/// Names of the entries of a FileIdBothDirectoryInformation buffer,
/// checking the NextEntryOffset chain.
fn names(reply: &Message) -> Vec<String> {
    reply.expect(NtStatus::Success);
    let output = reply.output();
    let mut names = Vec::new();
    let mut offset = 0;
    loop {
        let entry = &output[offset..];
        let length = u32_at(entry, 60) as usize;
        let units: Vec<u16> = entry[ID_BOTH_FIXED..ID_BOTH_FIXED + length]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        names.push(String::from_utf16(&units).unwrap());
        let next = u32_at(entry, 0) as usize;
        if next == 0 {
            assert_eq!(offset + ID_BOTH_FIXED + length, output.len());
            return names;
        }
        assert_eq!(next % 8, 0);
        assert!(next >= ID_BOTH_FIXED + length);
        offset += next;
    }
}

fn query(client: &mut Client, file: FileId, flags: u8, pattern: &str, length: u32) -> Message {
    client.query_directory(file, ID_BOTH, flags, pattern, length)
}

#[test]
fn listing_of_share_root() {
    let (mut client, root) = client_with_tree();
    let reply = query(&mut client, root, 0, "*", LARGE);
    assert_eq!(names(&reply), ROOT);
    insta::assert_snapshot!(hex(reply.output()));
    query(&mut client, root, 0, "*", LARGE).expect(NtStatus::NoMoreFiles);
}

#[test]
fn listing_of_subdirectory() {
    let (mut client, _) = client_with_tree();
    let sub = client.open_directory("sub");
    let reply = query(&mut client, sub, 0, "*", LARGE);
    assert_eq!(names(&reply), [".", "..", "inner.txt"]);
}

#[test]
fn patterns_select_entries() {
    for (pattern, expected) in [
        ("*.txt", &["a.txt", "b.txt", "x.y.txt"][..]),
        ("<.txt", &["a.txt", "b.txt", "x.y.txt"][..]),
        ("?.txt", &["a.txt", "b.txt"][..]),
        ("B.TXT", &["b.txt"][..]),
        (".*", &[".", ".."][..]),
    ] {
        let (mut client, root) = client_with_tree();
        let reply = query(&mut client, root, 0, pattern, LARGE);
        assert_eq!(names(&reply), expected, "{pattern}");
        query(&mut client, root, 0, pattern, LARGE).expect(NtStatus::NoMoreFiles);
    }
}

#[test]
fn no_match_is_no_such_file_then_no_more_files() {
    let (mut client, root) = client_with_tree();
    query(&mut client, root, 0, "*.zzz", LARGE).expect(NtStatus::NoSuchFile);
    query(&mut client, root, 0, "*.zzz", LARGE).expect(NtStatus::NoMoreFiles);
    query(&mut client, root, RESTART_SCANS, "*.zzz", LARGE).expect(NtStatus::NoSuchFile);
}

#[test]
fn restart_scans_lists_again() {
    let (mut client, root) = client_with_tree();
    assert_eq!(names(&query(&mut client, root, 0, "*", LARGE)), ROOT);
    query(&mut client, root, 0, "*", LARGE).expect(NtStatus::NoMoreFiles);
    assert_eq!(
        names(&query(&mut client, root, RESTART_SCANS, "*", LARGE)),
        ROOT
    );
    // A restart takes the new pattern.
    assert_eq!(
        names(&query(&mut client, root, RESTART_SCANS, "*.dat", LARGE)),
        ["c.dat"]
    );
}

fn single_entries(client: &mut Client, root: FileId, first_flags: u8) -> Vec<String> {
    let mut listed = Vec::new();
    let mut flags = first_flags | RETURN_SINGLE_ENTRY;
    loop {
        let reply = query(client, root, flags, "*", LARGE);
        if reply.status() == NtStatus::NoMoreFiles {
            return listed;
        }
        let names = names(&reply);
        assert_eq!(names.len(), 1);
        listed.extend(names);
        flags = RETURN_SINGLE_ENTRY;
    }
}

#[test]
fn return_single_entry_lists_one_at_a_time() {
    let (mut client, root) = client_with_tree();
    assert_eq!(single_entries(&mut client, root, 0), ROOT);
}

#[test]
fn restart_with_single_entries_lists_everything() {
    let (mut client, root) = client_with_tree();
    assert_eq!(names(&query(&mut client, root, 0, "*", LARGE)), ROOT);
    assert_eq!(single_entries(&mut client, root, RESTART_SCANS), ROOT);
}

#[test]
fn small_buffers_return_every_entry_once() {
    let mut client = Client::connected("Data");
    let mut expected = vec![".".to_owned(), "..".to_owned()];
    for index in 0..20 {
        let name = format!("file-{index:02}-{}.txt", "x".repeat(60 + index * 7));
        client.backend.add_file(DATA, &name, b"");
        expected.push(name);
    }
    let root = client.open_directory("");
    let mut listed = Vec::new();
    let mut queries = 0;
    loop {
        let reply = query(&mut client, root, 0, "*", 1000);
        if reply.status() == NtStatus::NoMoreFiles {
            break;
        }
        assert!(reply.output().len() <= 1000);
        listed.extend(names(&reply));
        queries += 1;
    }
    assert!(queries > 5, "{queries} queries");
    assert_eq!(listed, expected);
}

#[test]
fn buffer_smaller_than_one_entry_holds_it_for_retry() {
    let (mut client, root) = client_with_tree();
    // `.` takes 106 bytes.
    query(&mut client, root, 0, "*", 100).expect(NtStatus::InfoLengthMismatch);
    assert_eq!(names(&query(&mut client, root, 0, "*", LARGE)), ROOT);

    let (mut client, root) = client_with_tree();
    // "x.y.txt" takes 118 bytes.
    query(&mut client, root, 0, "x*", 117).expect(NtStatus::InfoLengthMismatch);
    assert_eq!(names(&query(&mut client, root, 0, "x*", 118)), ["x.y.txt"]);
    query(&mut client, root, 0, "x*", LARGE).expect(NtStatus::NoMoreFiles);
}

#[test]
fn query_on_file_is_invalid() {
    let (mut client, _) = client_with_tree();
    let file = client.open("a.txt", crate::client::disposition::OPEN);
    query(&mut client, file, 0, "*", LARGE).expect(NtStatus::InvalidParameter);
}

#[test]
fn failed_restart_drops_the_search_and_its_pattern() {
    let (mut client, root) = client_with_tree();
    assert_eq!(
        names(&query(
            &mut client,
            root,
            RETURN_SINGLE_ENTRY,
            "*.txt",
            LARGE
        )),
        ["a.txt"]
    );
    // A restart with an expression longer than a pattern holds fails.
    query(&mut client, root, RESTART_SCANS, &"?".repeat(256), LARGE)
        .expect(NtStatus::ObjectNameInvalid);
    // Another open takes the freed pattern slot.
    let sub = client.open_directory("sub");
    assert_eq!(
        names(&query(&mut client, sub, 0, "inner*", LARGE)),
        ["inner.txt"]
    );
    // The failed open starts a new search with the expression it sends.
    assert_eq!(
        names(&query(&mut client, root, 0, "*.dat", LARGE)),
        ["c.dat"]
    );
}
