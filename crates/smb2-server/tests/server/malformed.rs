//! Requests with inconsistent offsets, lengths, and chain links.

use smb2_server::server::FileId;
use smb2_server::status::NtStatus;

use crate::backend::DATA;
use crate::backend::utf16;
use crate::client::Client;
use crate::client::HEADER;
use crate::client::access;
use crate::client::close_body;
use crate::client::command;
use crate::client::create_body;
use crate::client::create_context;
use crate::client::disposition;
use crate::client::empty_body;
use crate::client::put_u16;
use crate::client::put_u32;
use crate::client::query_info_body;
use crate::client::read_body;
use crate::client::session_setup_body;

#[test]
fn create_name_outside_message_is_invalid() {
    let mut client = Client::connected("Data");
    let mut body = create_body("a.txt", access::ALL, disposition::OPEN_IF, 0, &[]);
    let length = body.len();
    put_u16(&mut body, 44, (HEADER + length) as u16);
    client
        .call(command::CREATE, &body)
        .expect(NtStatus::InvalidParameter);

    let mut body = create_body("a.txt", access::ALL, disposition::OPEN_IF, 0, &[]);
    put_u16(&mut body, 46, 9);
    client
        .call(command::CREATE, &body)
        .expect(NtStatus::InvalidParameter);

    // NameOffset inside the fixed part of the body.
    let mut body = create_body("a.txt", access::ALL, disposition::OPEN_IF, 0, &[]);
    put_u16(&mut body, 44, (HEADER + 8) as u16);
    client
        .call(command::CREATE, &body)
        .expect(NtStatus::InvalidParameter);
    assert!(client.backend.contents(DATA, "a.txt").is_none());
}

#[test]
fn truncated_bodies_are_invalid() {
    let mut client = Client::connected("Data");
    for (command, body) in [
        (
            command::CREATE,
            create_body("a.txt", access::ALL, disposition::OPEN_IF, 0, &[]),
        ),
        (command::READ, read_body(FileId::RELATED, 0, 1)),
        (command::CLOSE, close_body(FileId::RELATED, 0)),
        (
            command::QUERY_INFO,
            query_info_body(FileId::RELATED, 1, 5, 0, 24),
        ),
        (command::TREE_CONNECT, vec![9, 0, 0, 0, 0, 0, 0, 0]),
    ] {
        let reply = client.call(command, &body[..body.len() / 2]);
        assert_eq!(
            reply.status(),
            NtStatus::InvalidParameter,
            "command {command:#04x}"
        );
    }
}

#[test]
fn chain_links_must_be_aligned_and_inside_the_message() {
    for next in [65, 68, 4, 0x1000, u32::MAX] {
        let mut client = Client::connected("Data");
        let mut chain = client.message(command::ECHO, &empty_body());
        chain.resize(72, 0);
        put_u32(&mut chain, 20, next);
        let mut second = client.message(command::ECHO, &empty_body());
        chain.append(&mut second);
        assert!(
            client.transmit(&chain).is_disconnect(),
            "NextCommand {next}"
        );
    }
}

#[test]
fn short_or_foreign_messages_disconnect() {
    for message in [
        &b""[..],
        b"\xfeSM",
        b"\xfeSMB\x40\x00",
        b"\x00SMB\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ] {
        let mut client = Client::connected("Data");
        assert!(client.transmit(message).is_disconnect(), "{message:?}");
    }
}

#[test]
fn malformed_create_contexts_are_invalid() {
    let mut client = Client::connected("Data");
    let mut context = create_context(b"MxAc");
    // NameOffset past the context.
    put_u16(&mut context, 4, 40);
    let body = create_body("a.txt", access::ALL, disposition::OPEN_IF, 0, &context);
    client
        .call(command::CREATE, &body)
        .expect(NtStatus::InvalidParameter);
    let mut context = create_context(b"MxAc");
    // Next not a multiple of 8.
    put_u32(&mut context, 0, 12);
    let body = create_body("a.txt", access::ALL, disposition::OPEN_IF, 0, &context);
    client
        .call(command::CREATE, &body)
        .expect(NtStatus::InvalidParameter);
    assert_eq!(client.backend.open_handles(), 0);
}

/// Valid requests whose every body byte the mutation test replaces.
fn sample_requests(client: &mut Client) -> Vec<(u16, Vec<u8>)> {
    let file = client.open("sample.txt", disposition::OPEN_IF);
    let directory = client.open_directory("");
    let mut write = vec![0u8; 48];
    put_u16(&mut write, 0, 49);
    put_u16(&mut write, 2, (HEADER + 48) as u16);
    put_u32(&mut write, 4, 4);
    file.write(&mut write, 16);
    write.extend(b"data");
    let mut query_directory = vec![0u8; 32];
    put_u16(&mut query_directory, 0, 33);
    query_directory[2] = 37;
    directory.write(&mut query_directory, 8);
    put_u16(&mut query_directory, 24, (HEADER + 32) as u16);
    put_u16(&mut query_directory, 26, 2);
    put_u32(&mut query_directory, 28, 0x1000);
    query_directory.extend(utf16("*"));
    let rename = utf16("other.txt");
    let mut set_info = vec![0u8; 32];
    put_u16(&mut set_info, 0, 33);
    set_info[2] = 1;
    set_info[3] = 10;
    put_u32(&mut set_info, 4, (20 + rename.len()) as u32);
    put_u16(&mut set_info, 8, (HEADER + 32) as u16);
    file.write(&mut set_info, 16);
    set_info.extend([0; 16]);
    set_info.extend((rename.len() as u32).to_le_bytes());
    set_info.extend(rename);
    let mut ioctl = vec![0u8; 56];
    put_u16(&mut ioctl, 0, 57);
    put_u32(&mut ioctl, 4, 0x0011_c017);
    file.write(&mut ioctl, 8);
    put_u32(&mut ioctl, 24, (HEADER + 56) as u32);
    put_u32(&mut ioctl, 28, 4);
    put_u32(&mut ioctl, 44, 0x100);
    put_u32(&mut ioctl, 48, 1);
    ioctl.extend([5, 0, 11, 3]);
    let path = utf16("\\\\TESTSRV\\Data");
    let mut tree_connect = vec![0u8; 8];
    put_u16(&mut tree_connect, 0, 9);
    put_u16(&mut tree_connect, 4, (HEADER + 8) as u16);
    put_u16(&mut tree_connect, 6, path.len() as u16);
    tree_connect.extend(path);
    vec![
        (
            command::CREATE,
            create_body(
                "m.txt",
                access::ALL,
                disposition::OPEN_IF,
                0,
                &create_context(b"MxAc"),
            ),
        ),
        (command::READ, read_body(file, 0, 16)),
        (command::WRITE, write),
        (command::QUERY_DIRECTORY, query_directory),
        (command::QUERY_INFO, query_info_body(file, 1, 18, 0, 0x100)),
        (command::SET_INFO, set_info),
        (command::IOCTL, ioctl),
        (command::TREE_CONNECT, tree_connect),
        (
            command::SESSION_SETUP,
            session_setup_body(b"NTLMSSP\0\x01\0\0\0", 1),
        ),
    ]
}

/// Each body byte set to 0x00, 0x7f, and 0xff in turn. The server answers
/// every request with a well-formed reply; it never panics or disconnects.
#[test]
fn mutated_bodies_never_panic() {
    let mut client = Client::connected("Data");
    let requests = sample_requests(&mut client);
    for (command, body) in &requests {
        for index in 0..body.len() {
            for value in [0x00, 0x7f, 0xff] {
                let mut mutated = body.clone();
                mutated[index] = value;
                let message = client.message(*command, &mutated);
                let reply = client.transmit(&message).single();
                assert_eq!(reply.command(), *command);
            }
        }
    }
}
