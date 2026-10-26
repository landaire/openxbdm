//! NEGOTIATE, the SMB 1 multi-protocol negotiate, message identifiers, and
//! credits.

use smb2_server::server::Dialect;
use smb2_server::status::NtStatus;

use crate::backend::MemoryBackend;
use crate::backend::PASSWORD;
use crate::backend::USER;
use crate::client::Client;
use crate::client::command;
use crate::client::config;
use crate::client::empty_body;
use crate::client::hex;
use crate::client::negotiate_body;
use crate::client::u16_at;
use crate::client::u32_at;

/// SMB 1 NEGOTIATE (MS-CIFS 2.2.4.52.1) offering `dialects`.
fn smb1_negotiate(dialects: &[&str]) -> Vec<u8> {
    let mut message = vec![0u8; 32];
    message[..4].copy_from_slice(b"\xffSMB");
    message[4] = 0x72;
    message[9] = 0x18;
    message[10..12].copy_from_slice(&0xc853u16.to_le_bytes());

    let mut dialect_bytes = Vec::new();
    for dialect in dialects {
        dialect_bytes.push(0x02);
        dialect_bytes.extend_from_slice(dialect.as_bytes());
        dialect_bytes.push(0);
    }

    message.push(0);
    message.extend((dialect_bytes.len() as u16).to_le_bytes());
    message.extend(dialect_bytes);

    message
}

fn new_client() -> Client {
    Client::new(MemoryBackend::new(), config(false))
}

#[test]
fn multi_protocol_wildcard_then_smb2_negotiate() {
    let mut client = new_client();
    let request = smb1_negotiate(&["NT LM 0.12", "SMB 2.002", "SMB 2.???"]);
    client.allocate_id();

    let wildcard = client.transmit(&request).single();
    wildcard.expect(NtStatus::Success);
    assert_eq!(wildcard.command(), command::NEGOTIATE);
    assert_eq!(wildcard.message_id(), 0);
    assert_eq!(u16_at(wildcard.body(), 4), 0x02ff);
    assert_eq!(client.connection.dialect(), None);
    insta::assert_snapshot!("wildcard_reply", hex(&wildcard.0));

    let reply = client.call(command::NEGOTIATE, &negotiate_body(&[0x0202, 0x0210]));
    reply.expect(NtStatus::Success);
    assert_eq!(reply.message_id(), 1);
    assert_eq!(u16_at(reply.body(), 4), 0x0210);
    assert_eq!(client.connection.dialect(), Some(Dialect::SMB_2_1));
    insta::assert_snapshot!("smb2_reply", hex(&reply.0));
}

#[test]
fn multi_protocol_smb_2_002_completes_negotiation() {
    let mut client = new_client();
    client.allocate_id();
    let reply = client
        .transmit(&smb1_negotiate(&["NT LM 0.12", "SMB 2.002"]))
        .single();

    assert_eq!(u16_at(reply.body(), 4), 0x0202);
    assert_eq!(client.connection.dialect(), Some(Dialect::SMB_2_0_2));
    client
        .logon(USER, PASSWORD, false)
        .expect(NtStatus::Success);
}

#[test]
fn multi_protocol_without_smb2_dialect_disconnects() {
    let mut client = new_client();
    assert!(
        client
            .transmit(&smb1_negotiate(&["NT LM 0.12"]))
            .is_disconnect()
    );
}

#[test]
fn smb2_negotiate_selects_highest_common_dialect() {
    let mut client = new_client();
    let reply = client.call(command::NEGOTIATE, &negotiate_body(&[0x0202]));
    assert_eq!(u16_at(reply.body(), 4), 0x0202);

    let mut client = new_client();
    let reply = client.call(command::NEGOTIATE, &negotiate_body(&[0x0222, 0x0310]));
    reply.expect(NtStatus::NotSupported);
    assert_eq!(client.connection.dialect(), None);
}

#[test]
fn second_negotiate_disconnects() {
    let mut client = Client::negotiated(MemoryBackend::new(), config(false));
    let message = client.message(command::NEGOTIATE, &negotiate_body(&[0x0210]));
    assert!(client.transmit(&message).is_disconnect());
}

#[test]
fn smb1_negotiate_after_negotiation_disconnects() {
    let mut client = Client::negotiated(MemoryBackend::new(), config(false));
    assert!(
        client
            .transmit(&smb1_negotiate(&["SMB 2.???"]))
            .is_disconnect()
    );
}

#[test]
fn request_before_negotiate_disconnects() {
    for command in [command::ECHO, command::SESSION_SETUP, command::TREE_CONNECT] {
        let mut client = new_client();
        let message = client.message(command, &empty_body());
        assert!(
            client.transmit(&message).is_disconnect(),
            "command {command:#04x}"
        );
    }
}

#[test]
fn reused_message_id_disconnects() {
    let mut client = Client::negotiated(MemoryBackend::new(), config(false));
    client.echo().expect(NtStatus::Success);
    let used = client.next_message_id - 1;
    let mut message = client.header(command::ECHO, used, 0);
    message.extend(empty_body());
    assert!(client.transmit(&message).is_disconnect());
}

#[test]
fn message_id_outside_window_disconnects() {
    let mut client = Client::negotiated(MemoryBackend::new(), config(false));
    let mut message = client.header(command::ECHO, client.credit_limit, 0);
    message.extend(empty_body());
    assert!(client.transmit(&message).is_disconnect());
}

#[test]
fn highest_granted_message_id_is_accepted_out_of_order() {
    let mut client = Client::negotiated(MemoryBackend::new(), config(false));
    let highest = client.credit_limit - 1;
    assert!(highest > client.next_message_id);
    let mut message = client.header(command::ECHO, highest, 0);
    message.extend(empty_body());
    client.transmit(&message).single().expect(NtStatus::Success);
    client.echo().expect(NtStatus::Success);
}

#[test]
fn credits_never_exceed_128_outstanding() {
    let mut client = Client::negotiated(MemoryBackend::new(), config(false));
    client.credit_request = 1000;

    let mut reached = false;
    for _ in 0..300 {
        // Client::transmit asserts the bound after each reply.
        client.echo().expect(NtStatus::Success);
        reached |= client.credit_limit - client.next_message_id == 128;
    }

    assert!(reached, "the window fills to 128");

    let mut message = client.header(command::ECHO, client.credit_limit, 0);
    message.extend(empty_body());
    assert!(client.transmit(&message).is_disconnect());
}

#[test]
fn credit_charge_is_echoed_and_consumes_one_identifier() {
    let mut client = new_client();
    let reply = client.call(command::NEGOTIATE, &negotiate_body(&[0x0210]));

    // No SMB2_GLOBAL_CAP_LARGE_MTU: the server does not support
    // multi-credit requests, so CreditCharge does not reserve identifiers.
    assert_eq!(u32_at(reply.body(), 24) & 0x4, 0);

    for charge in [0u16, 1, 3] {
        let id = client.allocate_id();
        let mut message = client.header(command::ECHO, id, 0);
        message[6..8].copy_from_slice(&charge.to_le_bytes());
        message.extend(empty_body());
        let reply = client.transmit(&message).single();
        reply.expect(NtStatus::Success);
        assert_eq!(u16_at(&reply.0, 6), charge);
    }

    // The identifier after a charge of 3 is still unused.
    client.echo().expect(NtStatus::Success);
}

#[test]
fn unused_lowest_identifier_holds_the_window() {
    let mut client = Client::negotiated(MemoryBackend::new(), config(false));
    client.credit_request = 1000;
    client.echo().expect(NtStatus::Success);
    assert_eq!(client.credit_limit - client.next_message_id, 128);

    let held = client.next_message_id;
    let limit = client.credit_limit;
    for id in held + 1..limit {
        let mut message = client.header(command::ECHO, id, 0);
        message.extend(empty_body());
        let reply = client.transmit(&message).single();
        reply.expect(NtStatus::Success);
        assert_eq!(reply.credits(), 0, "grant for message {id}");
    }

    assert_eq!(client.credit_limit, limit);

    client.next_message_id = limit;
    let mut message = client.header(command::ECHO, held, 0);
    message.extend(empty_body());
    let reply = client.transmit(&message).single();
    reply.expect(NtStatus::Success);
    assert_eq!(reply.credits(), 128);

    // Every identifier below the new grant is used.
    let mut message = client.header(command::ECHO, limit - 1, 0);
    message.extend(empty_body());
    assert!(client.transmit(&message).is_disconnect());
}
