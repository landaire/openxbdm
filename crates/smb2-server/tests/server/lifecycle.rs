//! LOGOFF, TREE_DISCONNECT, and Connection::close release opens.

use smb2_server::backend::ShareId;
use smb2_server::status::NtStatus;

use crate::backend::DATA;
use crate::backend::MemoryBackend;
use crate::backend::PASSWORD;
use crate::backend::PUBLIC;
use crate::backend::USER;
use crate::client::Client;
use crate::client::PIPE_ACCESS;
use crate::client::SIGNING_ENABLED;
use crate::client::command;
use crate::client::config;
use crate::client::disposition;
use crate::client::negotiate_body;
use crate::ntlm::negotiate_message;

#[test]
fn logoff_closes_session_opens() {
    let mut client = Client::connected("Data");
    client.open("a.txt", disposition::CREATE);
    client.open("b.txt", disposition::CREATE);
    assert_eq!(client.backend.open_handles(), 2);

    client.logoff().expect(NtStatus::Success);
    assert_eq!(client.backend.open_handles(), 0);
    assert_eq!(client.backend.closed.len(), 2);

    client
        .tree_connect("Data")
        .expect(NtStatus::UserSessionDeleted);
}

#[test]
fn logoff_leaves_other_sessions_open() {
    let mut client = Client::connected("Data");
    let first_session = client.session_id;
    let first_tree = client.tree_id;
    let kept = client.open("kept.txt", disposition::CREATE);

    client
        .logon(USER, PASSWORD, false)
        .expect(NtStatus::Success);
    client.tree_connect("Data").expect(NtStatus::Success);
    client.open("dropped.txt", disposition::CREATE);

    client.logoff().expect(NtStatus::Success);
    assert_eq!(client.backend.open_handles(), 1);

    client.session_id = first_session;
    client.tree_id = first_tree;
    client
        .write(kept, 0, b"still open")
        .expect(NtStatus::Success);
}

#[test]
fn tree_disconnect_closes_tree_opens() {
    let mut client = Client::connected("Data");
    let first_tree = client.tree_id;
    let first = client.open("first.txt", disposition::CREATE);

    client.tree_connect("Data").expect(NtStatus::Success);
    let second_tree = client.tree_id;
    let second = client.open("second.txt", disposition::CREATE);
    assert_eq!(client.backend.open_handles(), 2);

    client.tree_id = first_tree;
    client.tree_disconnect().expect(NtStatus::Success);
    assert_eq!(client.backend.open_handles(), 1);
    client
        .read(first, 0, 1)
        .expect(NtStatus::NetworkNameDeleted);

    client.tree_id = second_tree;
    // An open is reachable only through its own tree.
    client.write(second, 0, b"x").expect(NtStatus::Success);
    client.read(first, 0, 1).expect(NtStatus::FileClosed);
}

#[test]
fn connection_close_releases_everything_and_resets() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, "a.txt", b"a");
    client.open("a.txt", disposition::OPEN);
    client.tree_connect("IPC$").expect(NtStatus::Success);
    client
        .create("srvsvc", PIPE_ACCESS, disposition::OPEN, 0)
        .expect(NtStatus::Success);

    client
        .connection
        .close(&mut client.server, &mut client.backend);
    assert_eq!(client.backend.open_handles(), 0);
    assert_eq!(client.connection.dialect(), None);
    assert!(!client.connection.has_sessions());
    assert!(!client.connection.has_opens());
    assert_eq!(client.connection.shares().count(), 0);

    // The connection starts over as a new one: message identifier 0 and
    // a NEGOTIATE.
    client.next_message_id = 0;
    client.credit_limit = 1;
    client.session_id = 0;
    client.tree_id = 0;
    client.key = None;

    let reply = client.call(command::NEGOTIATE, &negotiate_body(&[0x0210]));
    reply.expect(NtStatus::Success);
    client
        .logon(USER, PASSWORD, false)
        .expect(NtStatus::Success);
    client.tree_connect("Data").expect(NtStatus::Success);

    let file = client.open("a.txt", disposition::OPEN);
    assert_eq!(client.read(file, 0, 1).data(), b"a");
}

#[test]
fn connection_reports_sessions_opens_and_shares() {
    let mut client = Client::negotiated(MemoryBackend::new(), config(false));
    assert!(!client.connection.has_sessions());

    let negotiate = negotiate_message();
    let reply = client.session_setup(&negotiate, SIGNING_ENABLED);
    reply.expect(NtStatus::MoreProcessingRequired);
    // A session in authentication does not count.
    assert!(!client.connection.has_sessions());

    client
        .logon(USER, PASSWORD, false)
        .expect(NtStatus::Success);
    assert!(client.connection.has_sessions());

    client.tree_connect("IPC$").expect(NtStatus::Success);
    let ipc_tree = client.tree_id;
    client
        .create("srvsvc", PIPE_ACCESS, disposition::OPEN, 0)
        .expect(NtStatus::Success);
    client.tree_connect("Public").expect(NtStatus::Success);
    client.tree_connect("Data").expect(NtStatus::Success);
    let data_tree = client.tree_id;

    let mut shares: Vec<ShareId> = client.connection.shares().collect();
    shares.sort_by_key(|share| share.0);
    assert_eq!(shares, [DATA, PUBLIC]);
    assert!(client.connection.has_opens());

    client.tree_id = ipc_tree;
    client.tree_disconnect().expect(NtStatus::Success);
    assert!(!client.connection.has_opens());

    client.tree_id = data_tree;
    let file = client.open("a.txt", disposition::CREATE);
    assert!(client.connection.has_opens());

    client.close(file, 0).expect(NtStatus::Success);
    assert!(!client.connection.has_opens());

    client.logoff().expect(NtStatus::Success);
    assert!(!client.connection.has_sessions());
    assert_eq!(client.connection.shares().count(), 0);
}
