//! SESSION_SETUP with NTLMv2, guest and null sessions, and message
//! signing.

use smb2_server::status::NtStatus;

use crate::backend::MemoryBackend;
use crate::backend::PASSWORD;
use crate::backend::USER;
use crate::client::Client;
use crate::client::SESSION_FLAG_IS_GUEST;
use crate::client::SESSION_FLAG_IS_NULL;
use crate::client::SIGNING_ENABLED;
use crate::client::SIGNING_REQUIRED;
use crate::client::command;
use crate::client::config;
use crate::client::u16_at;
use crate::ntlm;

fn negotiated(backend: MemoryBackend) -> Client {
    Client::negotiated(backend, config(false))
}

fn session_flags(reply: &crate::client::Message) -> u16 {
    u16_at(reply.body(), 2)
}

#[test]
fn client_required_signing_signs_final_setup_and_later_replies() {
    let mut client = negotiated(MemoryBackend::new());
    let reply = client.logon(USER, PASSWORD, true);
    reply.expect(NtStatus::Success);
    assert_eq!(session_flags(&reply), 0);
    // Client::transmit verified the signature with the derived key.
    assert!(reply.signed());
    assert!(client.sign);
    let tree = client.tree_connect("Data");
    tree.expect(NtStatus::Success);
    assert!(tree.signed());
    let file = client.open("signed.txt", crate::client::disposition::CREATE);
    assert!(client.close(file, 0).signed());
}

#[test]
fn server_required_signing_signs_replies() {
    let mut client = Client::negotiated(MemoryBackend::new(), config(true));
    let reply = client.logon(USER, PASSWORD, false);
    assert!(reply.signed());
    assert!(client.tree_connect("Data").signed());
}

#[test]
fn optional_signing_signs_final_setup_then_only_signed_requests() {
    let mut client = negotiated(MemoryBackend::new());
    let reply = client.logon(USER, PASSWORD, false);
    reply.expect(NtStatus::Success);
    assert!(reply.signed());
    assert!(!client.sign);
    assert!(!client.tree_connect("Data").signed());
    client.sign = true;
    let reply = client.tree_connect("Data");
    reply.expect(NtStatus::Success);
    assert!(reply.signed());
    client.sign = false;
    assert!(!client.tree_connect("Data").signed());
}

#[test]
fn spnego_logon_derives_signing_key() {
    let mut client = negotiated(MemoryBackend::new());
    let security_mode = SIGNING_ENABLED | SIGNING_REQUIRED;
    let negotiate = ntlm::negotiate_message();
    let reply = client.session_setup(&ntlm::neg_token_init(&negotiate), security_mode);
    reply.expect(NtStatus::MoreProcessingRequired);
    client.session_id = reply.session_id();
    let resp = ntlm::parse_neg_token_resp(reply.buffer16(4, 6, 16));
    assert_eq!(resp.state, Some(1));
    let challenge = resp.token.expect("challenge token");
    let authenticate =
        ntlm::authenticate_message(USER, "WORKGROUP", PASSWORD, &negotiate, &challenge);
    let reply = client.finish_logon(
        &ntlm::neg_token_resp(&authenticate.message),
        authenticate.session_key,
        security_mode,
    );
    reply.expect(NtStatus::Success);
    assert!(reply.signed());
    assert_eq!(
        ntlm::parse_neg_token_resp(reply.buffer16(4, 6, 16)).state,
        Some(0)
    );
    assert!(client.tree_connect("Data").signed());
}

#[test]
fn wrong_password_fails_and_session_is_unusable() {
    let mut client = negotiated(MemoryBackend::new());
    let reply = client.logon(USER, "wrong", false);
    reply.expect(NtStatus::LogonFailure);
    let failed = reply.session_id();
    assert_ne!(failed, 0);
    client.session_id = failed;
    client
        .tree_connect("Data")
        .expect(NtStatus::UserSessionDeleted);
    client
        .session_setup(&ntlm::negotiate_message(), SIGNING_ENABLED)
        .expect(NtStatus::UserSessionDeleted);
    client
        .logon(USER, PASSWORD, false)
        .expect(NtStatus::Success);
    assert_ne!(client.session_id, failed);
}

#[test]
fn unknown_user_is_guest_when_allowed() {
    let mut backend = MemoryBackend::new();
    backend.guest = true;
    let mut client = negotiated(backend);
    let reply = client.logon("mallory", "whatever", true);
    reply.expect(NtStatus::Success);
    assert_eq!(session_flags(&reply), SESSION_FLAG_IS_GUEST);
    assert!(!reply.signed());
    let tree = client.tree_connect("Data");
    tree.expect(NtStatus::Success);
    assert!(!tree.signed());
}

#[test]
fn unknown_user_fails_without_guest() {
    let mut client = negotiated(MemoryBackend::new());
    client
        .logon("mallory", "whatever", false)
        .expect(NtStatus::LogonFailure);
}

#[test]
fn wrong_password_of_known_user_fails_with_guest_allowed() {
    let mut backend = MemoryBackend::new();
    backend.guest = true;
    let mut client = negotiated(backend);
    client
        .logon(USER, "wrong", false)
        .expect(NtStatus::LogonFailure);
}

#[test]
fn reauthentication_as_same_user_keeps_session() {
    let mut client = Client::connected("Data");
    let file = client.open("kept.txt", crate::client::disposition::CREATE);
    let reply = client.reauthenticate(USER, PASSWORD);
    reply.expect(NtStatus::Success);
    assert_eq!(reply.session_id(), client.session_id);
    assert!(reply.signed());
    client.write(file, 0, b"x").expect(NtStatus::Success);
}

#[test]
fn reauthentication_as_other_user_kind_removes_session() {
    let mut backend = MemoryBackend::new();
    backend.guest = true;
    let mut client = negotiated(backend);
    client
        .logon(USER, PASSWORD, false)
        .expect(NtStatus::Success);
    client.tree_connect("Data").expect(NtStatus::Success);
    client.open("a.txt", crate::client::disposition::CREATE);
    client
        .reauthenticate("mallory", "whatever")
        .expect(NtStatus::AccessDenied);
    assert!(!client.connection.has_sessions());
    assert!(!client.connection.has_opens());
    assert_eq!(client.backend.open_handles(), 0);
    client
        .tree_connect("Data")
        .expect(NtStatus::UserSessionDeleted);
}

fn anonymous_logon(client: &mut Client) -> crate::client::Message {
    client.session_id = 0;
    let reply = client.session_setup(&ntlm::negotiate_message(), SIGNING_ENABLED);
    reply.expect(NtStatus::MoreProcessingRequired);
    client.session_id = reply.session_id();
    client.session_setup(&ntlm::anonymous_message(), SIGNING_ENABLED)
}

#[test]
fn anonymous_logon_is_null_session() {
    let mut backend = MemoryBackend::new();
    backend.anonymous = true;
    let mut client = negotiated(backend);
    let reply = anonymous_logon(&mut client);
    reply.expect(NtStatus::Success);
    assert_eq!(session_flags(&reply), SESSION_FLAG_IS_NULL);
    assert!(!reply.signed());
    client.tree_connect("IPC$").expect(NtStatus::Success);
}

#[test]
fn anonymous_logon_fails_when_not_allowed() {
    let mut client = negotiated(MemoryBackend::new());
    anonymous_logon(&mut client).expect(NtStatus::LogonFailure);
}

fn signing_client() -> Client {
    let mut client = negotiated(MemoryBackend::new());
    client.logon(USER, PASSWORD, true).expect(NtStatus::Success);
    client
}

fn tree_connect_message(client: &mut Client) -> Vec<u8> {
    let path = crate::backend::utf16("\\\\TESTSRV\\Data");
    let mut body = vec![0u8; 8];
    crate::client::put_u16(&mut body, 0, 9);
    crate::client::put_u16(&mut body, 4, 72);
    crate::client::put_u16(&mut body, 6, path.len() as u16);
    body.extend(path);
    client.message(command::TREE_CONNECT, &body)
}

#[test]
fn corrupted_signature_is_access_denied() {
    let mut client = signing_client();
    let mut message = tree_connect_message(&mut client);
    message[50] ^= 0x01;
    client
        .transmit(&message)
        .single()
        .expect(NtStatus::AccessDenied);

    let mut message = tree_connect_message(&mut client);
    let last = message.len() - 1;
    message[last] ^= 0x01;
    client
        .transmit(&message)
        .single()
        .expect(NtStatus::AccessDenied);

    client.tree_connect("Data").expect(NtStatus::Success);
}

#[test]
fn unsigned_request_on_signing_session_is_access_denied() {
    let mut client = signing_client();
    client.sign = false;
    client.tree_connect("Data").expect(NtStatus::AccessDenied);
}

#[test]
fn logon_with_previous_session_id_ends_that_session() {
    let mut client = Client::connected("Data");
    let old = (client.session_id, client.tree_id);
    client.open("kept.txt", crate::client::disposition::CREATE);
    client.previous_session_id = old.0;
    client
        .logon(USER, PASSWORD, false)
        .expect(NtStatus::Success);
    assert_ne!(client.session_id, old.0);
    assert_eq!(client.backend.open_handles(), 0);
    let new = client.session_id;
    (client.session_id, client.tree_id) = old;
    client.echo().expect(NtStatus::Success);
    client
        .tree_connect("Data")
        .expect(NtStatus::UserSessionDeleted);
    client.session_id = new;
    client.tree_connect("Data").expect(NtStatus::Success);
}

#[test]
fn previous_session_of_another_kind_is_kept() {
    let mut backend = MemoryBackend::new();
    backend.guest = true;
    let mut client = negotiated(backend);
    client
        .logon(USER, PASSWORD, false)
        .expect(NtStatus::Success);
    let old = client.session_id;
    client.previous_session_id = old;
    let reply = client.logon("nobody", "x", false);
    assert_eq!(session_flags(&reply), SESSION_FLAG_IS_GUEST);
    client.session_id = old;
    client.tree_connect("Data").expect(NtStatus::Success);
}

#[test]
fn previous_session_on_another_connection_ends_through_the_server() {
    let mut client = Client::connected("Data");
    client.open("kept.txt", crate::client::disposition::CREATE);
    let mut peer = client.peer();
    let old = client.session_id;
    client.with_peer(&mut peer, |peer| {
        peer.negotiate(&crate::client::negotiate_body(&[0x0210]))
            .expect(NtStatus::Success);
        peer.backend.guest = true;
        peer.previous_session_id = old;
        // A guest logon does not end an authenticated session.
        peer.logon("nobody", "x", false).expect(NtStatus::Success);
        peer.backend.guest = false;
        peer.logon(USER, PASSWORD, false).expect(NtStatus::Success);
    });
    let guest = client.server.take_superseded().unwrap();
    assert_eq!(guest.id.0, old);
    assert!(
        !client
            .connection
            .end_session(&mut client.server, &mut client.backend, guest)
    );
    client.tree_connect("Data").expect(NtStatus::Success);

    let superseded = client.server.take_superseded().unwrap();
    assert_eq!(client.server.take_superseded(), None);
    assert!(
        client
            .connection
            .end_session(&mut client.server, &mut client.backend, superseded)
    );
    assert_eq!(client.backend.open_handles(), 0);
    client
        .tree_connect("Data")
        .expect(NtStatus::UserSessionDeleted);
}
