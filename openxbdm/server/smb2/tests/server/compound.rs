//! Related compound chains (MS-SMB2 3.3.5.2.7).

use smb2_server::server::FileId;
use smb2_server::status::NtStatus;

use crate::backend::DATA;
use crate::backend::MemoryBackend;
use crate::backend::PASSWORD;
use crate::backend::USER;
use crate::client::Client;
use crate::client::Outcome;
use crate::client::Request;
use crate::client::access;
use crate::client::close_body;
use crate::client::command;
use crate::client::config;
use crate::client::create_body;
use crate::client::disposition;
use crate::client::flags;
use crate::client::hex;
use crate::client::query_info_body;
use crate::client::u64_at;

const INFO_FILE: u8 = 1;
const FILE_STANDARD_INFORMATION: u8 = 5;

fn create_query_close(name: &str) -> [Request; 3] {
    [
        Request {
            command: command::CREATE,
            body: create_body(name, access::READ, disposition::OPEN, 0, &[]),
            related: false,
        },
        Request {
            command: command::QUERY_INFO,
            body: query_info_body(FileId::RELATED, INFO_FILE, FILE_STANDARD_INFORMATION, 0, 24),
            related: true,
        },
        Request {
            command: command::CLOSE,
            body: close_body(FileId::RELATED, 0),
            related: true,
        },
    ]
}

#[test]
fn create_query_close_chain() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"hello");

    let Outcome::Replies(frames) = client.compound(&create_query_close("a.txt")) else {
        panic!("expected replies");
    };
    let [frame] = &frames[..] else {
        panic!("expected one frame, got {frames:?}");
    };
    let replies = &frame.messages;
    let bytes = &frame.bytes;

    // split_chain checked the 8-byte alignment of every response.
    let commands: Vec<u16> = replies.iter().map(|reply| reply.command()).collect();
    assert_eq!(
        commands,
        [command::CREATE, command::QUERY_INFO, command::CLOSE]
    );

    for reply in replies {
        reply.expect(NtStatus::Success);
    }

    // CREATE: header and 88-byte body; QUERY_INFO: header, 8-byte body,
    // and 24 bytes of information padded to 8.
    assert_eq!(replies[0].next_command(), 152);
    assert_eq!(replies[1].next_command(), 96);
    assert_eq!(replies[2].next_command(), 0);

    assert_eq!(replies[0].flags() & flags::RELATED_OPERATIONS, 0);
    assert_ne!(replies[1].flags() & flags::RELATED_OPERATIONS, 0);
    assert_ne!(replies[2].flags() & flags::RELATED_OPERATIONS, 0);

    assert_eq!(u64_at(replies[1].output(), 8), 5);
    assert_eq!(client.backend.open_handles(), 0);
    assert_eq!(client.backend.closed.len(), 1);
    insta::assert_snapshot!(hex(bytes));
}

#[test]
fn failed_create_fails_related_requests_with_its_status() {
    let mut client = Client::connected("Data");

    let replies = client
        .compound(&create_query_close("missing.txt"))
        .replies();
    assert_eq!(replies.len(), 3);

    for reply in &replies {
        reply.expect(NtStatus::ObjectNameNotFound);
    }

    assert_eq!(replies[0].next_command(), 80);
    assert_eq!(replies[1].next_command(), 80);
}

#[test]
fn related_first_request_is_invalid() {
    let mut client = Client::connected("Data");
    let [_, query, close] = create_query_close("a.txt");

    let replies = client.compound(&[query, close]).replies();
    replies[0].expect(NtStatus::InvalidParameter);
}

#[test]
fn signed_chain_replies_are_signed() {
    let mut client = Client::negotiated(MemoryBackend::new(), config(false));
    client.logon(USER, PASSWORD, true).expect(NtStatus::Success);
    client.tree_connect("Data").expect(NtStatus::Success);
    client.backend.add_file(DATA, "a.txt", b"hello");

    // Client::transmit verified each signature over its padded response.
    let replies = client.compound(&create_query_close("a.txt")).replies();
    assert!(
        replies
            .iter()
            .all(|reply| reply.signed() && reply.status() == NtStatus::Success)
    );
}

#[test]
fn related_request_after_explicit_file_id_uses_that_file() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"first");
    client.backend.add_file(DATA, "b.txt", b"second");
    let first = client.open("a.txt", disposition::OPEN);

    let replies = client
        .compound(&[
            Request {
                command: command::CREATE,
                body: create_body("b.txt", access::READ, disposition::OPEN, 0, &[]),
                related: false,
            },
            Request {
                command: command::QUERY_INFO,
                body: query_info_body(first, INFO_FILE, FILE_STANDARD_INFORMATION, 0, 24),
                related: true,
            },
            Request {
                command: command::CLOSE,
                body: close_body(FileId::RELATED, 0),
                related: true,
            },
        ])
        .replies();

    for reply in &replies {
        reply.expect(NtStatus::Success);
    }

    let second = replies[0].file_id();
    assert_eq!(u64_at(replies[1].output(), 8), 5);
    client.read(first, 0, 10).expect(NtStatus::FileClosed);
    assert_eq!(client.read(second, 0, 10).data(), b"second");
}

#[test]
fn failed_middle_request_does_not_stop_related_close() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"hello");
    let mut chain = create_query_close("a.txt");
    chain[1].body = query_info_body(FileId::RELATED, INFO_FILE, FILE_STANDARD_INFORMATION, 0, 23);

    let replies = client.compound(&chain).replies();
    replies[0].expect(NtStatus::Success);
    replies[1].expect(NtStatus::InfoLengthMismatch);
    replies[2].expect(NtStatus::Success);

    assert_eq!(client.backend.open_handles(), 0);
    assert!(!client.connection.has_opens());
}

#[test]
fn unrelated_requests_in_a_chain_are_independent() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"hello");
    let mut chain = create_query_close("missing.txt");
    chain[1].related = false;
    chain[2].related = false;

    let replies = client.compound(&chain).replies();
    replies[0].expect(NtStatus::ObjectNameNotFound);
    // FileId all ones names no open outside a related chain.
    replies[1].expect(NtStatus::FileClosed);
    replies[2].expect(NtStatus::FileClosed);
}
