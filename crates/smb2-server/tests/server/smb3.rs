//! SMB 3 dialects: negotiate contexts, signing with the derived keys,
//! encryption, and FSCTL_VALIDATE_NEGOTIATE_INFO.

use smb2_server::ServerConfig;
use smb2_server::server::Dialect;
use smb2_server::server::FileId;
use smb2_server::status::NtStatus;

use crate::backend::DATA;
use crate::backend::MemoryBackend;
use crate::backend::PASSWORD;
use crate::backend::USER;
use crate::client::CAP_ENCRYPTION;
use crate::client::CLIENT_GUID;
use crate::client::Cipher;
use crate::client::Client;
use crate::client::SERVER_GUID;
use crate::client::SESSION_FLAG_ENCRYPT_DATA;
use crate::client::SIGNING_ENABLED;
use crate::client::Signing;
use crate::client::command;
use crate::client::config;
use crate::client::context;
use crate::client::dialect;
use crate::client::disposition;
use crate::client::flags;
use crate::client::list_context;
use crate::client::negotiate_body_with;
use crate::client::preauth_context;
use crate::client::put_u16;
use crate::client::put_u32;
use crate::client::seal;
use crate::client::smb3_negotiate_body;
use crate::client::tree_connect_body;
use crate::client::u16_at;
use crate::client::u32_at;

const FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
/// The NEGOTIATE reply status when no hash algorithm is shared (MS-SMB2
/// 3.3.5.4).
const NO_PREAUTH_INTEGRITY_HASH_OVERLAP: u32 = 0xc05d_0000;
const BOTH_CIPHERS: [u16; 2] = [context::AES_128_GCM, context::AES_128_CCM];

fn encrypting() -> ServerConfig {
    ServerConfig {
        encrypt_data: true,
        ..config(false)
    }
}

fn negotiate(body: &[u8]) -> (Client, crate::client::Message) {
    let mut client = Client::new(MemoryBackend::new(), config(false));
    let reply = client.negotiate(body);
    (client, reply)
}

#[test]
fn each_dialect_is_selected_when_offered_alone() {
    for offered in [
        dialect::SMB_2_0_2,
        dialect::SMB_2_1,
        dialect::SMB_3_0,
        dialect::SMB_3_0_2,
        dialect::SMB_3_1_1,
    ] {
        let (client, reply) = negotiate(&smb3_negotiate_body(
            offered,
            &BOTH_CIPHERS,
            &[context::AES_CMAC],
        ));
        reply.expect(NtStatus::Success);
        assert_eq!(client.dialect, offered);
        assert_eq!(client.connection.dialect(), Some(Dialect(offered)));
        // Only SMB 3.0 and 3.0.2 announce encryption as a capability;
        // only SMB 3.1.1 answers with negotiate contexts.
        let capabilities = u32_at(reply.body(), 24);
        let contexts = u16_at(reply.body(), 6);
        match offered {
            dialect::SMB_3_0 | dialect::SMB_3_0_2 => {
                assert_eq!(capabilities, CAP_ENCRYPTION);
                assert_eq!(contexts, 0);
                assert_eq!(client.cipher, Some(Cipher::Aes128Ccm));
            }
            dialect::SMB_3_1_1 => {
                assert_eq!(capabilities, 0);
                assert_eq!(contexts, 3);
            }
            _ => {
                assert_eq!(capabilities, 0);
                assert_eq!(contexts, 0);
                assert_eq!(client.cipher, None);
            }
        }
    }
}

#[test]
fn smb_3_0_without_encryption_capability_has_no_cipher() {
    let (client, reply) = negotiate(&negotiate_body_with(&[dialect::SMB_3_0_2], 0, &[]));
    reply.expect(NtStatus::Success);
    assert_eq!(u32_at(reply.body(), 24), 0);
    assert_eq!(client.cipher, None);
}

#[test]
fn highest_offered_dialect_wins() {
    let (client, reply) = negotiate(&negotiate_body_with(
        &[
            dialect::SMB_2_1,
            dialect::SMB_3_1_1,
            dialect::SMB_3_0,
            dialect::SMB_3_0_2,
        ],
        0,
        &[preauth_context(&[context::SHA_512])],
    ));
    reply.expect(NtStatus::Success);
    assert_eq!(client.dialect, dialect::SMB_3_1_1);
}

#[test]
fn smb_3_1_1_reply_carries_a_sha_512_preauth_context_with_salt() {
    let (_, reply) = negotiate(&smb3_negotiate_body(dialect::SMB_3_1_1, &[], &[]));
    reply.expect(NtStatus::Success);
    let contexts = reply.negotiate_contexts();
    assert_eq!(contexts.len(), 1);
    let (kind, data) = &contexts[0];
    assert_eq!(*kind, context::PREAUTH_INTEGRITY);
    // HashAlgorithmCount 1, SaltLength 32, SHA-512, salt.
    assert_eq!(u16_at(data, 0), 1);
    assert_eq!(u16_at(data, 2), 32);
    assert_eq!(u16_at(data, 4), context::SHA_512);
    assert_eq!(data.len(), 6 + 32);
}

#[test]
fn smb_3_1_1_requires_the_preauth_context() {
    for contexts in [
        Vec::new(),
        vec![list_context(context::ENCRYPTION, &[context::AES_128_GCM])],
    ] {
        let (client, reply) = negotiate(&negotiate_body_with(&[dialect::SMB_3_1_1], 0, &contexts));
        reply.expect(NtStatus::InvalidParameter);
        assert_eq!(client.connection.dialect(), None);
    }
}

#[test]
fn smb_3_1_1_without_sha_512_has_no_hash_overlap() {
    let (client, reply) = negotiate(&negotiate_body_with(
        &[dialect::SMB_3_1_1],
        0,
        &[preauth_context(&[0x0002, 0x0003])],
    ));
    assert_eq!(reply.status().raw(), NO_PREAUTH_INTEGRITY_HASH_OVERLAP);
    assert_eq!(client.connection.dialect(), None);
}

#[test]
fn cipher_choice_prefers_gcm() {
    for (offered, chosen) in [
        (
            &[context::AES_128_CCM, context::AES_128_GCM][..],
            context::AES_128_GCM,
        ),
        (
            &[context::AES_128_GCM, context::AES_128_CCM][..],
            context::AES_128_GCM,
        ),
        (&[context::AES_128_CCM][..], context::AES_128_CCM),
        // AES-256-CCM and AES-256-GCM only: no common cipher.
        (&[0x0003, 0x0004][..], 0),
    ] {
        let (_, reply) = negotiate(&smb3_negotiate_body(dialect::SMB_3_1_1, offered, &[]));
        reply.expect(NtStatus::Success);
        assert_eq!(
            reply.negotiate_choice(context::ENCRYPTION),
            Some(chosen),
            "offered {offered:?}"
        );
    }
    let (client, reply) = negotiate(&smb3_negotiate_body(dialect::SMB_3_1_1, &[], &[]));
    assert_eq!(reply.negotiate_choice(context::ENCRYPTION), None);
    assert_eq!(client.cipher, None);
}

#[test]
fn signing_choice_prefers_gmac_then_cmac() {
    for (offered, chosen) in [
        (
            &[context::HMAC_SHA256, context::AES_CMAC, context::AES_GMAC][..],
            context::AES_GMAC,
        ),
        (
            &[context::HMAC_SHA256, context::AES_CMAC][..],
            context::AES_CMAC,
        ),
        (&[context::HMAC_SHA256][..], context::HMAC_SHA256),
    ] {
        let (_, reply) = negotiate(&smb3_negotiate_body(dialect::SMB_3_1_1, &[], offered));
        reply.expect(NtStatus::Success);
        assert_eq!(
            reply.negotiate_choice(context::SIGNING),
            Some(chosen),
            "offered {offered:?}"
        );
    }
    let (client, reply) = negotiate(&smb3_negotiate_body(dialect::SMB_3_1_1, &[], &[]));
    assert_eq!(reply.negotiate_choice(context::SIGNING), None);
    assert_eq!(client.signing, Signing::AesCmac);
}

/// Sessions of each SMB 3 dialect and signing algorithm: the final
/// SESSION_SETUP reply and every reply to a signed request carry the
/// signature the client derives on its own.
#[test]
fn signed_sessions_use_the_derived_key() {
    for (offered, signing, expected) in [
        (dialect::SMB_3_0, &[][..], Signing::AesCmac),
        (dialect::SMB_3_0_2, &[][..], Signing::AesCmac),
        (
            dialect::SMB_3_1_1,
            &[context::AES_CMAC][..],
            Signing::AesCmac,
        ),
        (
            dialect::SMB_3_1_1,
            &[context::AES_GMAC, context::AES_CMAC][..],
            Signing::AesGmac,
        ),
        (
            dialect::SMB_3_1_1,
            &[context::HMAC_SHA256][..],
            Signing::HmacSha256,
        ),
    ] {
        let mut client = Client::new(MemoryBackend::new(), config(false));
        client
            .negotiate(&smb3_negotiate_body(offered, &[], signing))
            .expect(NtStatus::Success);
        assert_eq!(client.signing, expected);
        let reply = client.logon(USER, PASSWORD, false);
        reply.expect(NtStatus::Success);
        assert!(
            reply.signed(),
            "final SESSION_SETUP reply of {offered:#06x}"
        );

        client.sign = true;
        let reply = client.tree_connect("Data");
        reply.expect(NtStatus::Success);
        assert!(reply.signed());
        let file = client.open("signed.txt", disposition::CREATE);
        client
            .write(file, 0, b"signed data")
            .expect(NtStatus::Success);
        let reply = client.read(file, 0, 64);
        assert!(reply.signed());
        assert_eq!(reply.data(), b"signed data");

        // Unsigned requests are accepted and answered unsigned when
        // signing is not required.
        client.sign = false;
        let reply = client.tree_connect("Data");
        reply.expect(NtStatus::Success);
        assert!(!reply.signed());
    }
}

#[test]
fn bad_signatures_are_denied() {
    for (offered, signing) in [
        (dialect::SMB_3_0, &[][..]),
        (dialect::SMB_3_1_1, &[context::AES_CMAC][..]),
        (dialect::SMB_3_1_1, &[context::AES_GMAC][..]),
    ] {
        let mut client = Client::smb3(config(false), offered, &[], signing);
        client.sign = true;
        client.tree_connect("Data").expect(NtStatus::Success);

        let mut message = client.message(command::TREE_CONNECT, &tree_connect_body("Data"));
        message[60] ^= 0x01;
        let reply = client.transmit(&message).single();
        reply.expect(NtStatus::AccessDenied);
        assert!(!reply.signed());

        // A body changed after signing.
        let mut message = client.message(command::TREE_CONNECT, &tree_connect_body("Data"));
        let last = message.len() - 2;
        message[last] ^= 0x20;
        client
            .transmit(&message)
            .single()
            .expect(NtStatus::AccessDenied);

        client.tree_connect("Data").expect(NtStatus::Success);
    }
}

#[test]
fn signing_required_denies_unsigned_smb3_requests() {
    let mut client = Client::smb3(config(true), dialect::SMB_3_1_1, &[], &[context::AES_GMAC]);
    assert!(client.sign);
    client.tree_connect("Data").expect(NtStatus::Success);
    client.sign = false;
    client.tree_connect("Data").expect(NtStatus::AccessDenied);
}

#[test]
fn encrypt_data_sets_the_session_flag_where_encryption_is_possible() {
    for (offered, ciphers, encrypted) in [
        (dialect::SMB_3_0, &[][..], true),
        (dialect::SMB_3_0_2, &[][..], true),
        (dialect::SMB_3_1_1, &[context::AES_128_GCM][..], true),
        (dialect::SMB_3_1_1, &[context::AES_128_CCM][..], true),
        // No cipher in common: the session cannot encrypt.
        (dialect::SMB_3_1_1, &[][..], false),
        (dialect::SMB_2_1, &[][..], false),
    ] {
        let mut client = Client::new(MemoryBackend::new(), encrypting());
        client
            .negotiate(&smb3_negotiate_body(offered, ciphers, &[]))
            .expect(NtStatus::Success);
        let reply = client.logon(USER, PASSWORD, false);
        reply.expect(NtStatus::Success);
        assert_eq!(
            u16_at(reply.body(), 2) & SESSION_FLAG_ENCRYPT_DATA != 0,
            encrypted,
            "dialect {offered:#06x}, ciphers {ciphers:?}"
        );
        assert_eq!(client.encrypt, encrypted);
        client.tree_connect("Data").expect(NtStatus::Success);
    }
}

#[test]
fn unencrypted_request_on_an_encrypting_session_is_denied() {
    let mut client = Client::smb3(encrypting(), dialect::SMB_3_1_1, &BOTH_CIPHERS, &[]);
    assert!(client.encrypt);
    client.encrypt = false;
    client.tree_connect("Data").expect(NtStatus::AccessDenied);
    client.sign = true;
    client.tree_connect("Data").expect(NtStatus::AccessDenied);
    client.encrypt = true;
    client.tree_connect("Data").expect(NtStatus::Success);
}

#[test]
fn encrypted_requests_and_replies_round_trip() {
    for (offered, ciphers, cipher) in [
        (dialect::SMB_3_0, &[][..], Cipher::Aes128Ccm),
        (dialect::SMB_3_0_2, &[][..], Cipher::Aes128Ccm),
        (
            dialect::SMB_3_1_1,
            &[context::AES_128_GCM][..],
            Cipher::Aes128Gcm,
        ),
        (
            dialect::SMB_3_1_1,
            &[context::AES_128_CCM][..],
            Cipher::Aes128Ccm,
        ),
    ] {
        let mut client = Client::smb3(encrypting(), offered, ciphers, &[]);
        assert_eq!(client.cipher, Some(cipher));
        client.reply_nonces.clear();
        client.tree_connect("Data").expect(NtStatus::Success);
        let file = client.open("secret.txt", disposition::CREATE);
        client
            .write(file, 0, b"encrypted contents")
            .expect(NtStatus::Success);
        let reply = client.read(file, 0, 64);
        reply.expect(NtStatus::Success);
        assert!(!reply.signed());
        assert_eq!(reply.data(), b"encrypted contents");
        client.close(file, 0).expect(NtStatus::Success);
        assert_eq!(
            client.backend.contents(DATA, "secret.txt"),
            Some(&b"encrypted contents"[..])
        );
        // Every reply was encrypted, each under a new nonce.
        assert_eq!(client.reply_nonces.len(), 5, "dialect {offered:#06x}");
        assert!(
            client.reply_nonces.windows(2).all(|pair| pair[0] < pair[1]),
            "nonces {:?}",
            client.reply_nonces
        );
    }
}

#[test]
fn encryption_is_optional_without_encrypt_data() {
    let mut client = Client::smb3(config(false), dialect::SMB_3_1_1, &BOTH_CIPHERS, &[]);
    assert!(!client.encrypt);
    client.tree_connect("Data").expect(NtStatus::Success);
    client.encrypt = true;
    let frames = client
        .call_all(command::TREE_CONNECT, &tree_connect_body("Data"))
        .frames();
    assert!(frames.iter().all(|frame| frame.nonce.is_some()));
    client.encrypt = false;
    client.sign = true;
    let frames = client
        .call_all(command::TREE_CONNECT, &tree_connect_body("Data"))
        .frames();
    assert!(frames.iter().all(|frame| frame.nonce.is_none()));
    assert!(frames[0].messages[0].signed());
}

#[test]
fn tampered_encrypted_requests_disconnect() {
    // Ciphertext, tag, and nonce bytes.
    for (cipher, offset) in [
        (context::AES_128_GCM, 60),
        (context::AES_128_CCM, 60),
        (context::AES_128_GCM, 10),
        (context::AES_128_CCM, 22),
    ] {
        let mut client = Client::smb3(encrypting(), dialect::SMB_3_1_1, &[cipher], &[]);
        let message = client.message(command::ECHO, &crate::client::empty_body());
        let mut sealed = client.seal_request(&message);
        sealed[offset] ^= 0x80;
        assert!(client.deliver(&sealed).is_disconnect());
    }
}

#[test]
fn request_decrypted_with_another_sessions_key_disconnects() {
    let mut client = Client::smb3(encrypting(), dialect::SMB_3_1_1, &BOTH_CIPHERS, &[]);
    let first = (client.session_id, client.encryption.unwrap());
    client
        .logon(USER, PASSWORD, false)
        .expect(NtStatus::Success);
    assert_ne!(client.session_id, first.0);
    // A request of the second session, encrypted under the first one's key.
    let message = client.message(command::TREE_CONNECT, &tree_connect_body("Data"));
    let sealed = seal(
        &message,
        &first.1.encryption,
        client.cipher.unwrap(),
        first.0,
        [0; 16],
    );
    assert!(client.deliver(&sealed).is_disconnect());
}

/// FSCTL_VALIDATE_NEGOTIATE_INFO input (MS-SMB2 2.2.31.4).
fn validate_input(capabilities: u32, security_mode: u16, dialects: &[u16]) -> Vec<u8> {
    let mut input = vec![0u8; 24];
    put_u32(&mut input, 0, capabilities);
    input[4..20].copy_from_slice(&CLIENT_GUID);
    put_u16(&mut input, 20, security_mode);
    put_u16(&mut input, 22, dialects.len() as u16);
    for dialect in dialects {
        input.extend(dialect.to_le_bytes());
    }
    input
}

fn validating_client() -> Client {
    let mut client = Client::smb3(config(false), dialect::SMB_3_0_2, &[], &[]);
    client.sign = true;
    client.tree_connect("Data").expect(NtStatus::Success);
    client
}

#[test]
fn validate_negotiate_info_confirms_the_negotiation() {
    let mut client = validating_client();
    let reply = client.ioctl(
        FileId::RELATED,
        FSCTL_VALIDATE_NEGOTIATE_INFO,
        &validate_input(
            CAP_ENCRYPTION,
            u16::from(SIGNING_ENABLED),
            &[dialect::SMB_3_0_2],
        ),
        24,
    );
    reply.expect(NtStatus::Success);
    assert!(reply.signed());
    let output = reply.ioctl_output();
    assert_eq!(output.len(), 24);
    assert_eq!(u32_at(output, 0), CAP_ENCRYPTION);
    assert_eq!(output[4..20], SERVER_GUID.0);
    assert_eq!(u16_at(output, 20), u16::from(SIGNING_ENABLED));
    assert_eq!(u16_at(output, 22), dialect::SMB_3_0_2);
}

#[test]
fn validate_negotiate_info_mismatch_disconnects() {
    for input in [
        validate_input(0, u16::from(SIGNING_ENABLED), &[dialect::SMB_3_0_2]),
        validate_input(CAP_ENCRYPTION, 3, &[dialect::SMB_3_0_2]),
        // The offered list would have selected another dialect.
        validate_input(
            CAP_ENCRYPTION,
            u16::from(SIGNING_ENABLED),
            &[dialect::SMB_3_0_2, dialect::SMB_3_1_1],
        ),
        validate_input(
            CAP_ENCRYPTION,
            u16::from(SIGNING_ENABLED),
            &[dialect::SMB_2_1],
        ),
    ] {
        let mut client = validating_client();
        let message = client.message(
            command::IOCTL,
            &crate::client::ioctl_body(FileId::RELATED, FSCTL_VALIDATE_NEGOTIATE_INFO, &input, 24),
        );
        assert!(client.transmit(&message).is_disconnect(), "{input:?}");
    }
    // Another client GUID.
    let mut client = validating_client();
    let mut input = validate_input(
        CAP_ENCRYPTION,
        u16::from(SIGNING_ENABLED),
        &[dialect::SMB_3_0_2],
    );
    input[4] ^= 1;
    let message = client.message(
        command::IOCTL,
        &crate::client::ioctl_body(FileId::RELATED, FSCTL_VALIDATE_NEGOTIATE_INFO, &input, 24),
    );
    assert!(client.transmit(&message).is_disconnect());
}

/// A watch on `watch` with a CHANGE_NOTIFY waiting; returns its interim
/// reply.
fn waiting_notify(client: &mut Client) -> crate::client::Message {
    client.tree_connect("Data").expect(NtStatus::Success);
    client.backend.add_directory(DATA, "watch");
    let directory = client.open_directory("watch");
    let interim = client.change_notify(directory, 0x3, false).single();
    interim.expect(NtStatus::Pending);
    interim
}

#[test]
fn cancel_names_requests_of_its_own_session_only() {
    let mut client = Client::connected("Data");
    let interim = waiting_notify(&mut client);
    let first = client.session_id;
    client
        .logon(USER, PASSWORD, false)
        .expect(NtStatus::Success);
    assert!(
        client
            .cancel(interim.message_id(), interim.async_id())
            .is_nothing()
    );
    client.session_id = first;
    client
        .cancel(interim.message_id(), interim.async_id())
        .single()
        .expect(NtStatus::Cancelled);
}

#[test]
fn cancel_on_a_signing_session_needs_a_valid_signature() {
    let mut client = Client::smb3(config(true), dialect::SMB_3_1_1, &[], &[context::AES_GMAC]);
    assert!(client.sign);
    let interim = waiting_notify(&mut client);
    client.sign = false;
    assert!(
        client
            .cancel(interim.message_id(), interim.async_id())
            .is_nothing()
    );
    client.sign = true;
    let mut message = client.header(command::CANCEL, interim.message_id(), flags::ASYNC_COMMAND);
    message[32..40].copy_from_slice(&interim.async_id().to_le_bytes());
    message.extend(crate::client::empty_body());
    client.sign_message(&mut message);
    message[50] ^= 1;
    assert!(client.deliver(&message).is_nothing());
    // A signature computed without the cancel bit of the GMAC nonce.
    let mut message = client.header(command::CANCEL, interim.message_id(), flags::ASYNC_COMMAND);
    message[32..40].copy_from_slice(&interim.async_id().to_le_bytes());
    message.extend(crate::client::empty_body());
    message[16] |= flags::SIGNED as u8;
    let key = client.key.unwrap();
    let mut as_echo = message.clone();
    as_echo[12] = command::ECHO as u8;
    let signature = crate::client::sign_with(&as_echo, &key, Signing::AesGmac);
    message[48..64].copy_from_slice(&signature);
    assert!(client.deliver(&message).is_nothing());

    let reply = client
        .cancel(interim.message_id(), interim.async_id())
        .single();
    reply.expect(NtStatus::Cancelled);
    assert!(reply.signed());
}

#[test]
fn cancel_on_an_encrypting_session_must_be_encrypted() {
    let mut client = Client::smb3(encrypting(), dialect::SMB_3_1_1, &BOTH_CIPHERS, &[]);
    let interim = waiting_notify(&mut client);
    client.encrypt = false;
    assert!(
        client
            .cancel(interim.message_id(), interim.async_id())
            .is_nothing()
    );
    client.encrypt = true;
    let frames = client
        .cancel(interim.message_id(), interim.async_id())
        .frames();
    assert!(frames[0].nonce.is_some());
    frames[0].messages[0].expect(NtStatus::Cancelled);
}

#[test]
fn unencrypted_session_setup_on_an_encrypting_session_is_denied() {
    let mut client = Client::smb3(encrypting(), dialect::SMB_3_1_1, &BOTH_CIPHERS, &[]);
    client.encrypt = false;
    client
        .session_setup(&crate::ntlm::negotiate_message(), SIGNING_ENABLED)
        .expect(NtStatus::AccessDenied);
    client.encrypt = true;
    client.tree_connect("Data").expect(NtStatus::Success);
}

#[test]
fn signing_context_without_a_common_algorithm_selects_cmac() {
    let mut client = Client::smb3(config(false), dialect::SMB_3_1_1, &[], &[0x0007]);
    assert_eq!(client.signing, Signing::AesCmac);
    client.sign = true;
    let reply = client.tree_connect("Data");
    reply.expect(NtStatus::Success);
    assert!(reply.signed());
}
