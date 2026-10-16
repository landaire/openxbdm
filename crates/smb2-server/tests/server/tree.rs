//! TREE_CONNECT and the access a read-only share grants.

use smb2_server::status::NtStatus;

use crate::backend::PUBLIC;
use crate::client::Client;
use crate::client::access;
use crate::client::command;
use crate::client::create_body;
use crate::client::create_context;
use crate::client::disposition;
use crate::client::u32_at;

const SHARE_TYPE_DISK: u8 = 1;
const SHARE_TYPE_PIPE: u8 = 2;
const READ_ONLY_ACCESS: u32 = 0x0012_00a9;

#[test]
fn unknown_share_is_bad_network_name() {
    let mut client = Client::logged_on();
    client.tree_connect("Nope").expect(NtStatus::BadNetworkName);
}

#[test]
fn share_types_and_maximal_access() {
    let mut client = Client::logged_on();
    let ipc = client.tree_connect("IPC$");
    ipc.expect(NtStatus::Success);
    assert_eq!(ipc.body()[2], SHARE_TYPE_PIPE);
    let data = client.tree_connect("data");
    assert_eq!(data.body()[2], SHARE_TYPE_DISK);
    assert_eq!(u32_at(data.body(), 12), access::ALL);
    let public = client.tree_connect("PUBLIC");
    assert_eq!(public.body()[2], SHARE_TYPE_DISK);
    assert_eq!(u32_at(public.body(), 12), READ_ONLY_ACCESS);
    assert_ne!(ipc.tree_id(), data.tree_id());
    assert_ne!(data.tree_id(), public.tree_id());
}

#[test]
fn read_only_share_refuses_modification() {
    let mut client = Client::logged_on();
    client.backend.add_file(PUBLIC, "readme.txt", b"read me");
    client.tree_connect("Public").expect(NtStatus::Success);

    let file = client
        .create("readme.txt", access::READ, disposition::OPEN, 0)
        .file_id();
    assert_eq!(client.read(file, 0, 100).data(), b"read me");
    client.write(file, 0, b"x").expect(NtStatus::AccessDenied);

    for rights in [
        access::WRITE_DATA,
        access::GENERIC_WRITE,
        access::DELETE,
        access::ALL,
    ] {
        client
            .create("readme.txt", rights, disposition::OPEN, 0)
            .expect(NtStatus::AccessDenied);
    }
    for disposition in [disposition::CREATE, disposition::OVERWRITE_IF] {
        client
            .create("new.txt", access::READ, disposition, 0)
            .expect(NtStatus::AccessDenied);
    }
    // OpenIf opens without creating.
    client
        .create("new.txt", access::READ, disposition::OPEN_IF, 0)
        .expect(NtStatus::ObjectNameNotFound);
    assert!(client.backend.contents(PUBLIC, "new.txt").is_none());
}

#[test]
fn maximal_access_context_reports_share_rights() {
    let mut client = Client::logged_on();
    client.backend.add_file(PUBLIC, "readme.txt", b"");
    client.tree_connect("Public").expect(NtStatus::Success);
    let body = create_body(
        "readme.txt",
        access::READ,
        disposition::OPEN,
        0,
        &create_context(b"MxAc"),
    );
    let reply = client.call(command::CREATE, &body);
    reply.expect(NtStatus::Success);
    let contexts = reply.0[u32_at(reply.body(), 80) as usize..].to_vec();
    assert_eq!(u32_at(reply.body(), 84), 32);
    assert_eq!(&contexts[16..20], b"MxAc");
    // QueryStatus, then MaximalAccess.
    assert_eq!(u32_at(&contexts, 24), 0);
    assert_eq!(u32_at(&contexts, 28), READ_ONLY_ACCESS);
}
