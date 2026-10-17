//! End-to-end exchanges against a test-only NTLM client.

extern crate std;

use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use super::AuthError;
use super::AuthStep;
use super::AuthenticatedSession;
use super::Authenticator;
use super::NtlmMessage;
use super::der::Reader;
use super::der::Tag;
use super::negotiate_token;
use super::ntlm::Direction;
use super::ntlm::Flags;
use super::ntlm::first_message_signature;
use crate::backend::Accounts;
use crate::backend::COMPUTER_NAME_CAPACITY;
use crate::backend::FileHandle;
use crate::backend::FileSystem;
use crate::backend::NtOwf;
use crate::backend::OpenRequest;
use crate::backend::Opened;
use crate::backend::Platform;
use crate::backend::SHARE_NAME_CAPACITY;
use crate::backend::Share;
use crate::backend::Shares;
use crate::backend::UserKind;
use crate::crypto::Rc4;
use crate::crypto::hmac_md5;
use crate::crypto::md4;
use crate::fs::BasicInformation;
use crate::fs::DirectoryEntry;
use crate::fs::FileInformation;
use crate::fs::FileTime;
use crate::fs::FsError;
use crate::fs::NAME_CAPACITY;
use crate::fs::VolumeInformation;
use crate::path::SharePath;
use crate::utf16::Utf16Le;

const NTLMSSP_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const KERBEROS_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// What a Windows client requests, plus OEM and LM_KEY, which the server
/// must not grant.
const CLIENT_FLAGS: u32 = Flags::UNICODE.0
    | 0x2
    | Flags::REQUEST_TARGET.0
    | Flags::SIGN.0
    | Flags::SEAL.0
    | 0x80
    | Flags::NTLM.0
    | Flags::ALWAYS_SIGN.0
    | Flags::EXTENDED_SESSIONSECURITY.0
    | Flags::VERSION.0
    | Flags::NEGOTIATE_128.0
    | Flags::KEY_EXCH.0
    | Flags::NEGOTIATE_56.0;

const RANDOM_SESSION_KEY: [u8; 16] = [0x55; 16];

/// NTLMSSP_NEGOTIATE_ANONYMOUS, which the server does not interpret.
const NEGOTIATE_ANONYMOUS: u32 = 0x800;

const GOOD: Credentials = Credentials {
    user: "user",
    domain: "WORKGROUP",
    key_domain: "WORKGROUP",
    password: "Password",
};

const WRONG_PASSWORD: Credentials = Credentials {
    user: "User",
    domain: "WORKGROUP",
    key_domain: "WORKGROUP",
    password: "password",
};

const UNKNOWN_USER: Credentials = Credentials {
    user: "nobody",
    domain: "WORKGROUP",
    key_domain: "WORKGROUP",
    password: "Password",
};

/// Accounts are matched without case on the user name; the domain is
/// ignored.
pub(super) struct TestBackend {
    pub accounts: &'static [(&'static str, &'static str)],
    pub guest: bool,
    pub anonymous: bool,
    pub random: [u8; 8],
    pub time: FileTime,
    pub name: &'static [u8],
}

impl TestBackend {
    pub(super) fn new() -> Self {
        Self {
            accounts: &[("User", "Password")],
            guest: false,
            anonymous: false,
            random: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            time: FileTime(0x01d9_8f6d_1c2a_b000),
            name: b"Xbox360",
        }
    }
}

impl Platform for TestBackend {
    fn system_time(&mut self) -> FileTime {
        self.time
    }

    fn random_bytes(&mut self, output: &mut [u8]) {
        for (byte, value) in output.iter_mut().zip(self.random.iter().cycle()) {
            *byte = *value;
        }
    }

    fn computer_name(&mut self, output: &mut [u8; COMPUTER_NAME_CAPACITY]) -> usize {
        output[..self.name.len()].copy_from_slice(self.name);
        self.name.len()
    }
}

impl Accounts for TestBackend {
    fn password(&mut self, user: Utf16Le<'_>, _domain: Utf16Le<'_>) -> Option<NtOwf> {
        self.accounts
            .iter()
            .find(|(name, _)| user.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, password)| nt_owf(password))
    }

    fn allow_guest(&mut self) -> bool {
        self.guest
    }

    fn allow_anonymous(&mut self) -> bool {
        self.anonymous
    }
}

impl Shares for TestBackend {
    fn find_share(&mut self, _: Utf16Le<'_>, _: UserKind) -> Option<Share> {
        unreachable!()
    }

    fn share_name(
        &mut self,
        _: crate::backend::ShareIndex,
        _: UserKind,
        _: &mut [u16; SHARE_NAME_CAPACITY],
    ) -> Option<usize> {
        unreachable!()
    }
}

impl FileSystem for TestBackend {
    fn open(
        &mut self,
        _: crate::backend::ShareId,
        _: SharePath<'_>,
        _: &OpenRequest,
    ) -> Result<Opened, FsError> {
        unreachable!()
    }
    fn close(&mut self, _: FileHandle) {
        unreachable!()
    }
    fn read(&mut self, _: FileHandle, _: u64, _: &mut [u8]) -> Result<usize, FsError> {
        unreachable!()
    }
    fn write(&mut self, _: FileHandle, _: u64, _: &[u8]) -> Result<(), FsError> {
        unreachable!()
    }
    fn flush(&mut self, _: FileHandle) -> Result<(), FsError> {
        unreachable!()
    }
    fn information(&mut self, _: FileHandle) -> Result<FileInformation, FsError> {
        unreachable!()
    }
    fn set_basic_information(
        &mut self,
        _: FileHandle,
        _: &BasicInformation,
    ) -> Result<(), FsError> {
        unreachable!()
    }
    fn set_end_of_file(&mut self, _: FileHandle, _: u64) -> Result<(), FsError> {
        unreachable!()
    }
    fn set_delete_pending(&mut self, _: FileHandle, _: bool) -> Result<(), FsError> {
        unreachable!()
    }
    fn rename(&mut self, _: FileHandle, _: SharePath<'_>, _: bool) -> Result<(), FsError> {
        unreachable!()
    }
    fn read_directory(
        &mut self,
        _: FileHandle,
        _: bool,
        _: &mut [u16; NAME_CAPACITY],
    ) -> Result<Option<DirectoryEntry>, FsError> {
        unreachable!()
    }
    fn volume_information(&mut self, _: FileHandle) -> Result<VolumeInformation, FsError> {
        unreachable!()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ServerResp {
    state: u8,
    supported_mech: Option<Vec<u8>>,
    token: Option<Vec<u8>>,
    mic: Option<Vec<u8>>,
}

struct Credentials {
    user: &'static str,
    /// Domain sent in the AUTHENTICATE.
    domain: &'static str,
    /// Domain the client puts into NTOWFv2; normally the one it sends.
    key_domain: &'static str,
    password: &'static str,
}

struct Options {
    key_exch: bool,
    mic: bool,
}

/// A client AUTHENTICATE answering `challenge`, with the flags it
/// negotiated and its ExportedSessionKey.
#[derive(Debug)]
struct ClientAuthenticate {
    message: Vec<u8>,
    flags: Flags,
    session_key: [u8; 16],
}

pub(super) fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub(super) fn nt_owf(password: &str) -> NtOwf {
    NtOwf(md4(&utf16(password)))
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else if length <= 0xff {
        out.extend([0x81, length as u8]);
    } else {
        out.extend([0x82, (length >> 8) as u8, length as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// Client NegTokenInit; returns the token and its MechTypeList DER.
fn neg_token_init(mechanisms: &[&[u8]], token: Option<&[u8]>) -> (Vec<u8>, Vec<u8>) {
    let oids: Vec<u8> = mechanisms.iter().flat_map(|oid| tlv(0x06, oid)).collect();
    let mech_types = tlv(0x30, &oids);
    let mut fields = tlv(0xa0, &mech_types);
    if let Some(token) = token {
        fields.extend(tlv(0xa2, &tlv(0x04, token)));
    }
    let body = concat(&[&tlv(0x06, SPNEGO_OID), &tlv(0xa0, &tlv(0x30, &fields))]);
    (tlv(0x60, &body), mech_types)
}

fn neg_token_resp(token: Option<&[u8]>, mic: Option<&[u8]>) -> Vec<u8> {
    let mut fields = Vec::new();
    if let Some(token) = token {
        fields.extend(tlv(0xa2, &tlv(0x04, token)));
    }
    if let Some(mic) = mic {
        fields.extend(tlv(0xa3, &tlv(0x04, mic)));
    }
    tlv(0xa1, &tlv(0x30, &fields))
}

fn parse_server_resp(bytes: &[u8]) -> ServerResp {
    let outer = Reader::new(bytes).expect(Tag(0xa1)).unwrap();
    let mut fields = Reader::new(Reader::new(outer).expect(Tag(0x30)).unwrap());
    let mut parsed = ServerResp {
        state: 0xff,
        supported_mech: None,
        token: None,
        mic: None,
    };
    while !fields.is_empty() {
        let field = fields.read().unwrap();
        let mut inner = Reader::new(field.content);
        match field.tag.0 {
            0xa0 => parsed.state = inner.expect(Tag(0x0a)).unwrap()[0],
            0xa1 => parsed.supported_mech = Some(inner.expect(Tag(0x06)).unwrap().to_vec()),
            0xa2 => parsed.token = Some(inner.expect(Tag(0x04)).unwrap().to_vec()),
            0xa3 => parsed.mic = Some(inner.expect(Tag(0x04)).unwrap().to_vec()),
            tag => panic!("unexpected field {tag:#x}"),
        }
    }
    parsed
}

fn negotiate_message(flags: u32) -> Vec<u8> {
    concat(&[
        b"NTLMSSP\0",
        &1u32.to_le_bytes(),
        &flags.to_le_bytes(),
        &[0; 16],
        &[10, 0, 0x61, 0x4a, 0, 0, 0, 0x0f],
    ])
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn u16_at(data: &[u8], offset: usize) -> usize {
    usize::from(u16::from_le_bytes(
        data[offset..offset + 2].try_into().unwrap(),
    ))
}

fn authenticate_message(
    credentials: &Credentials,
    options: &Options,
    negotiate: &[u8],
    challenge: &[u8],
) -> ClientAuthenticate {
    assert_eq!(&challenge[..12], b"NTLMSSP\0\x02\0\0\0");
    let mut flags = u32_at(challenge, 20);
    if !options.key_exch {
        flags &= !Flags::KEY_EXCH.0;
    }
    let server_challenge = &challenge[24..32];
    let info_offset = u32_at(challenge, 44) as usize;
    let mut info = &challenge[info_offset..info_offset + u16_at(challenge, 40)];

    let mut pairs = Vec::new();
    let mut timestamp = [0u8; 8];
    loop {
        let id = u16_at(info, 0);
        let length = u16_at(info, 2);
        if id == 0 {
            break;
        }
        if id == 7 {
            timestamp.copy_from_slice(&info[4..12]);
        }
        pairs.extend_from_slice(&info[..4 + length]);
        info = &info[4 + length..];
    }
    if options.mic {
        pairs.extend([6, 0, 4, 0, 2, 0, 0, 0]);
    }
    pairs.extend([0, 0, 0, 0]);

    let blob = concat(&[
        &[1, 1, 0, 0, 0, 0, 0, 0],
        &timestamp,
        &[0xaa; 8],
        &[0; 4],
        &pairs,
        &[0; 4],
    ]);
    let user_upper = credentials.user.to_ascii_uppercase();
    let response_key = hmac_md5(
        &nt_owf(credentials.password).0,
        &concat(&[&utf16(&user_upper), &utf16(credentials.key_domain)]),
    );
    let proof = hmac_md5(&response_key, &concat(&[server_challenge, &blob]));
    let nt_response = concat(&[&proof, &blob]);
    let base_key = hmac_md5(&response_key, &proof);
    let (session_key, encrypted_key) = if options.key_exch {
        let mut encrypted = RANDOM_SESSION_KEY;
        Rc4::new(&base_key).apply(&mut encrypted);
        (RANDOM_SESSION_KEY, encrypted.to_vec())
    } else {
        (base_key, Vec::new())
    };
    let message = authenticate_fields(
        flags,
        &[0; 24],
        &nt_response,
        &utf16(credentials.domain),
        &utf16(credentials.user),
        &encrypted_key,
    );
    let mut message = message;
    if options.mic {
        let mic = hmac_md5(&session_key, &concat(&[negotiate, challenge, &message]));
        message[72..88].copy_from_slice(&mic);
    }
    ClientAuthenticate {
        message,
        flags: Flags(flags & u32_at(challenge, 20)),
        session_key,
    }
}

/// AUTHENTICATE with a zero MIC field and payload in field order.
fn authenticate_fields(
    flags: u32,
    lm: &[u8],
    nt: &[u8],
    domain: &[u8],
    user: &[u8],
    encrypted_key: &[u8],
) -> Vec<u8> {
    let workstation = utf16("CLIENT");
    let payload = [lm, nt, domain, user, &workstation, encrypted_key];
    let mut message = concat(&[b"NTLMSSP\0", &3u32.to_le_bytes()]);
    let mut offset = 88u32;
    for field in payload {
        let length = field.len() as u16;
        message.extend(length.to_le_bytes());
        message.extend(length.to_le_bytes());
        message.extend(offset.to_le_bytes());
        offset += u32::from(length);
    }
    message.extend(flags.to_le_bytes());
    message.extend([10, 0, 0x61, 0x4a, 0, 0, 0, 0x0f]);
    message.extend([0; 16]);
    for field in payload {
        message.extend_from_slice(field);
    }
    message
}

fn step(
    authenticator: &mut Authenticator,
    backend: &mut TestBackend,
    input: &[u8],
) -> Result<(AuthStep, Vec<u8>), AuthError> {
    let mut output = [0u8; 512];
    let step = authenticator.step(input, &mut output, backend)?;
    let length = match step {
        AuthStep::Continue { length } | AuthStep::Complete { length, .. } => length,
    };
    Ok((step, output[..length].to_vec()))
}

fn expect_continue(result: Result<(AuthStep, Vec<u8>), AuthError>) -> Vec<u8> {
    match result {
        Ok((AuthStep::Continue { .. }, output)) => output,
        other => panic!("expected Continue, got {other:?}"),
    }
}

fn expect_complete(
    result: Result<(AuthStep, Vec<u8>), AuthError>,
) -> (AuthenticatedSession, Vec<u8>) {
    match result {
        Ok((AuthStep::Complete { session, .. }, output)) => (session, output),
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[derive(Debug)]
struct SpnegoExchange {
    session: AuthenticatedSession,
    output: Vec<u8>,
    client: ClientAuthenticate,
    mech_types: Vec<u8>,
}

#[derive(Debug)]
struct RawExchange {
    session: AuthenticatedSession,
    output: Vec<u8>,
    client: ClientAuthenticate,
}

/// SPNEGO exchange with NTLMSSP as the only mechanism and the NEGOTIATE
/// sent optimistically, as Windows does.
fn spnego_exchange(
    credentials: &Credentials,
    options: &Options,
    send_mic: bool,
    backend: &mut TestBackend,
) -> Result<SpnegoExchange, AuthError> {
    let mut authenticator = Authenticator::new();
    let negotiate = negotiate_message(CLIENT_FLAGS);
    let (init, mech_types) = neg_token_init(&[NTLMSSP_OID], Some(&negotiate));
    let reply = parse_server_resp(&expect_continue(step(&mut authenticator, backend, &init)));
    assert_eq!(reply.state, 1);
    assert_eq!(reply.supported_mech.as_deref(), Some(NTLMSSP_OID));
    assert!(reply.mic.is_none());
    let challenge = reply.token.unwrap();
    let client = authenticate_message(credentials, options, &negotiate, &challenge);
    let client_mic = first_message_signature(
        &client.session_key,
        client.flags,
        Direction::ClientToServer,
        &mech_types,
    )
    .unwrap();
    let response = neg_token_resp(Some(&client.message), send_mic.then_some(&client_mic[..]));
    let result = step(&mut authenticator, backend, &response);
    let (session, output) = match result {
        Ok((AuthStep::Complete { session, .. }, output)) => (session, output),
        Ok(other) => panic!("expected Complete, got {other:?}"),
        Err(status) => return Err(status),
    };
    Ok(SpnegoExchange {
        session,
        output,
        client,
        mech_types,
    })
}

fn raw_exchange(
    credentials: &Credentials,
    options: &Options,
    backend: &mut TestBackend,
    authenticator: &mut Authenticator,
) -> Result<RawExchange, AuthError> {
    let negotiate = negotiate_message(CLIENT_FLAGS);
    let challenge = expect_continue(step(authenticator, backend, &negotiate));
    let client = authenticate_message(credentials, options, &negotiate, &challenge);
    let (step, output) = step(authenticator, backend, &client.message)?;
    match step {
        AuthStep::Complete { session, .. } => Ok(RawExchange {
            session,
            output,
            client,
        }),
        other => panic!("expected Complete, got {other:?}"),
    }
}

fn anonymous_message(lm: &[u8]) -> Vec<u8> {
    authenticate_fields(CLIENT_FLAGS | NEGOTIATE_ANONYMOUS, lm, &[], &[], &[], &[])
}

fn hex_dump(bytes: &[u8]) -> String {
    let mut text = String::new();
    for (index, line) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = line.iter().map(|byte| format!("{byte:02x}")).collect();
        text.push_str(&format!("{:04x}: {}\n", index * 16, hex.join(" ")));
    }
    text
}

#[test]
fn authenticator_state_is_small() {
    assert!(core::mem::size_of::<Authenticator>() < 1024);
}

#[test]
fn negotiate_token_is_ntlm_only_neg_token_init() {
    let mut output = [0u8; 64];
    let length = negotiate_token(&mut output).unwrap();
    let (expected, _) = neg_token_init(&[NTLMSSP_OID], None);
    assert_eq!(&output[..length], &expected[..]);
    assert_eq!(negotiate_token(&mut [0u8; 29]), None);
}

#[test]
fn spnego_key_exchange_with_mic_and_mech_list_mic() {
    let mut backend = TestBackend::new();
    let options = Options {
        key_exch: true,
        mic: true,
    };
    let SpnegoExchange {
        session,
        output,
        client,
        mech_types,
    } = spnego_exchange(&GOOD, &options, true, &mut backend).unwrap();
    assert_eq!(session.kind, UserKind::Authenticated);
    assert_eq!(session.session_key.unwrap().0, RANDOM_SESSION_KEY);
    let reply = parse_server_resp(&output);
    let server_mic = first_message_signature(
        &client.session_key,
        client.flags,
        Direction::ServerToClient,
        &mech_types,
    )
    .unwrap();
    assert_eq!(
        reply,
        ServerResp {
            state: 0,
            supported_mech: None,
            token: None,
            mic: Some(server_mic.to_vec()),
        }
    );
}

#[test]
fn spnego_without_key_exchange_exports_session_base_key() {
    let mut backend = TestBackend::new();
    let options = Options {
        key_exch: false,
        mic: true,
    };
    let SpnegoExchange {
        session,
        output,
        client,
        ..
    } = spnego_exchange(&GOOD, &options, true, &mut backend).unwrap();
    assert_eq!(session.kind, UserKind::Authenticated);
    assert_ne!(client.session_key, RANDOM_SESSION_KEY);
    assert_eq!(session.session_key.unwrap().0, client.session_key);
    assert!(parse_server_resp(&output).mic.is_some());
}

#[test]
fn spnego_without_mech_list_mic_when_ntlm_is_first() {
    let mut backend = TestBackend::new();
    let options = Options {
        key_exch: true,
        mic: false,
    };
    let SpnegoExchange {
        session, output, ..
    } = spnego_exchange(&GOOD, &options, false, &mut backend).unwrap();
    assert_eq!(session.kind, UserKind::Authenticated);
    assert_eq!(
        parse_server_resp(&output),
        ServerResp {
            state: 0,
            supported_mech: None,
            token: None,
            mic: None,
        }
    );
}

#[test]
fn wrong_mech_list_mic_fails() {
    let mut backend = TestBackend::new();
    let mut authenticator = Authenticator::new();
    let negotiate = negotiate_message(CLIENT_FLAGS);
    let (init, _) = neg_token_init(&[NTLMSSP_OID], Some(&negotiate));
    let reply = parse_server_resp(&expect_continue(step(
        &mut authenticator,
        &mut backend,
        &init,
    )));
    let options = Options {
        key_exch: true,
        mic: true,
    };
    let client = authenticate_message(&GOOD, &options, &negotiate, &reply.token.unwrap());
    let response = neg_token_resp(
        Some(&client.message),
        Some(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    );
    assert_eq!(
        step(&mut authenticator, &mut backend, &response).unwrap_err(),
        AuthError::MechListMicMismatch
    );
}

#[test]
fn kerberos_first_requires_mech_list_mic() {
    let options = Options {
        key_exch: true,
        mic: true,
    };
    for send_mic in [false, true] {
        let mut backend = TestBackend::new();
        let mut authenticator = Authenticator::new();
        let (init, mech_types) = neg_token_init(
            &[KERBEROS_OID, NTLMSSP_OID],
            Some(&[0x6e, 0x82, 0x01, 0x00]),
        );
        let reply = parse_server_resp(&expect_continue(step(
            &mut authenticator,
            &mut backend,
            &init,
        )));
        assert_eq!(
            reply,
            ServerResp {
                state: 3,
                supported_mech: Some(NTLMSSP_OID.to_vec()),
                token: None,
                mic: None,
            }
        );
        let negotiate = negotiate_message(CLIENT_FLAGS);
        let reply = parse_server_resp(&expect_continue(step(
            &mut authenticator,
            &mut backend,
            &neg_token_resp(Some(&negotiate), None),
        )));
        assert_eq!(reply.state, 1);
        assert!(reply.supported_mech.is_none());
        let client = authenticate_message(&GOOD, &options, &negotiate, &reply.token.unwrap());
        let client_mic = first_message_signature(
            &client.session_key,
            client.flags,
            Direction::ClientToServer,
            &mech_types,
        )
        .unwrap();
        let response = neg_token_resp(Some(&client.message), send_mic.then_some(&client_mic[..]));
        let result = step(&mut authenticator, &mut backend, &response);
        if send_mic {
            let (session, output) = expect_complete(result);
            assert_eq!(session.kind, UserKind::Authenticated);
            assert!(parse_server_resp(&output).mic.is_some());
        } else {
            assert_eq!(result.unwrap_err(), AuthError::MechListMicMissing);
        }
    }
}

#[test]
fn mech_list_without_ntlm_is_refused() {
    let mut backend = TestBackend::new();
    let (init, _) = neg_token_init(&[KERBEROS_OID], Some(&[0x6e, 0x00]));
    assert_eq!(
        step(&mut Authenticator::new(), &mut backend, &init).unwrap_err(),
        AuthError::MechanismNotOffered
    );
}

#[test]
fn raw_ntlmssp_exchange() {
    for key_exch in [false, true] {
        let mut backend = TestBackend::new();
        let options = Options {
            key_exch,
            mic: true,
        };
        let RawExchange {
            session,
            output,
            client,
        } = raw_exchange(&GOOD, &options, &mut backend, &mut Authenticator::new()).unwrap();
        assert_eq!(session.kind, UserKind::Authenticated);
        assert_eq!(session.session_key.unwrap().0, client.session_key);
        assert!(output.is_empty());
    }
}

#[test]
fn empty_domain_is_accepted() {
    let mut backend = TestBackend::new();
    let credentials = Credentials {
        user: "USER",
        domain: "",
        key_domain: "",
        password: "Password",
    };
    let options = Options {
        key_exch: true,
        mic: true,
    };
    let RawExchange { session, .. } = raw_exchange(
        &credentials,
        &options,
        &mut backend,
        &mut Authenticator::new(),
    )
    .unwrap();
    assert_eq!(session.kind, UserKind::Authenticated);
}

/// A client that sends a domain but computes NTOWFv2 without one is
/// verified by the retry with an empty domain.
#[test]
fn empty_domain_retry_verifies_existing_account() {
    let options = Options {
        key_exch: true,
        mic: true,
    };
    for (password, expected) in [
        ("Password", Ok(UserKind::Authenticated)),
        ("password", Err(AuthError::WrongPassword)),
    ] {
        let mut backend = TestBackend::new();
        backend.guest = true;
        let credentials = Credentials {
            user: "User",
            domain: "WORKGROUP",
            key_domain: "",
            password,
        };
        let result = raw_exchange(
            &credentials,
            &options,
            &mut backend,
            &mut Authenticator::new(),
        );
        assert_eq!(result.map(|exchange| exchange.session.kind), expected);
    }
}

#[test]
fn tampered_mic_fails() {
    let mut backend = TestBackend::new();
    let mut authenticator = Authenticator::new();
    let negotiate = negotiate_message(CLIENT_FLAGS);
    let challenge = expect_continue(step(&mut authenticator, &mut backend, &negotiate));
    let options = Options {
        key_exch: true,
        mic: true,
    };
    let mut client = authenticate_message(&GOOD, &options, &negotiate, &challenge);
    client.message[80] ^= 1;
    assert_eq!(
        step(&mut authenticator, &mut backend, &client.message).unwrap_err(),
        AuthError::MicMismatch
    );
}

#[test]
fn failed_logons_without_guest() {
    let options = Options {
        key_exch: true,
        mic: true,
    };
    for (credentials, error) in [
        (&WRONG_PASSWORD, AuthError::WrongPassword),
        (&UNKNOWN_USER, AuthError::UnknownAccount),
    ] {
        let mut backend = TestBackend::new();
        let mut authenticator = Authenticator::new();
        assert_eq!(
            raw_exchange(credentials, &options, &mut backend, &mut authenticator).unwrap_err(),
            error
        );
        let RawExchange { session, .. } =
            raw_exchange(&GOOD, &options, &mut backend, &mut authenticator).unwrap();
        assert_eq!(session.kind, UserKind::Authenticated);
        assert_eq!(
            spnego_exchange(credentials, &options, true, &mut backend).unwrap_err(),
            error
        );
    }
}

/// The guest policy admits unknown accounts only; a wrong password for an
/// existing account still fails.
#[test]
fn failed_logons_with_guest() {
    let options = Options {
        key_exch: true,
        mic: true,
    };
    let mut backend = TestBackend::new();
    backend.guest = true;
    assert_eq!(
        raw_exchange(
            &WRONG_PASSWORD,
            &options,
            &mut backend,
            &mut Authenticator::new(),
        )
        .unwrap_err(),
        AuthError::WrongPassword
    );
    assert_eq!(
        spnego_exchange(&WRONG_PASSWORD, &options, true, &mut backend).unwrap_err(),
        AuthError::WrongPassword
    );

    let RawExchange { session, .. } = raw_exchange(
        &UNKNOWN_USER,
        &options,
        &mut backend,
        &mut Authenticator::new(),
    )
    .unwrap();
    assert_eq!(session.kind, UserKind::Guest);
    assert!(session.session_key.is_none());
    let SpnegoExchange {
        session, output, ..
    } = spnego_exchange(&UNKNOWN_USER, &options, true, &mut backend).unwrap();
    assert_eq!(session.kind, UserKind::Guest);
    assert!(session.session_key.is_none());
    assert_eq!(
        parse_server_resp(&output),
        ServerResp {
            state: 0,
            supported_mech: None,
            token: None,
            mic: None,
        }
    );
}

/// negState = reject from the client ends the exchange at either SPNEGO
/// round, and the authenticator starts over.
#[test]
fn client_reject_fails_and_resets() {
    let reject = tlv(0xa1, &tlv(0x30, &tlv(0xa0, &tlv(0x0a, &[2]))));
    let negotiate = negotiate_message(CLIENT_FLAGS);
    for kerberos_first in [false, true] {
        let mut backend = TestBackend::new();
        let mut authenticator = Authenticator::new();
        let (init, _) = if kerberos_first {
            neg_token_init(&[KERBEROS_OID, NTLMSSP_OID], None)
        } else {
            neg_token_init(&[NTLMSSP_OID], Some(&negotiate))
        };
        expect_continue(step(&mut authenticator, &mut backend, &init));
        assert_eq!(
            step(&mut authenticator, &mut backend, &reject).unwrap_err(),
            AuthError::ClientRejected
        );
        let raw = expect_continue(step(&mut authenticator, &mut backend, &negotiate));
        assert_eq!(&raw[..8], b"NTLMSSP\0");
    }
}

#[test]
fn anonymous_logon() {
    for allowed in [false, true] {
        for lm in [&[][..], &[0][..]] {
            let mut backend = TestBackend::new();
            backend.anonymous = allowed;
            let mut authenticator = Authenticator::new();
            let negotiate = negotiate_message(CLIENT_FLAGS);
            let (init, _) = neg_token_init(&[NTLMSSP_OID], Some(&negotiate));
            expect_continue(step(&mut authenticator, &mut backend, &init));
            let response = neg_token_resp(Some(&anonymous_message(lm)), None);
            let result = step(&mut authenticator, &mut backend, &response);
            if allowed {
                let (session, output) = expect_complete(result);
                assert_eq!(session.kind, UserKind::Anonymous);
                assert!(session.session_key.is_none());
                assert_eq!(parse_server_resp(&output).state, 0);
            } else {
                assert_eq!(result.unwrap_err(), AuthError::AnonymousRefused);
            }
        }
    }
}

#[test]
fn ntlm_v1_is_refused() {
    let mut backend = TestBackend::new();
    backend.guest = true;
    let mut authenticator = Authenticator::new();
    let negotiate = negotiate_message(CLIENT_FLAGS);
    expect_continue(step(&mut authenticator, &mut backend, &negotiate));
    let message = authenticate_fields(
        CLIENT_FLAGS,
        &[0x11; 24],
        &[0x22; 24],
        &[],
        &utf16("User"),
        &[],
    );
    assert_eq!(
        step(&mut authenticator, &mut backend, &message).unwrap_err(),
        AuthError::NtlmV1Response
    );
}

#[test]
fn malformed_tokens() {
    let mut backend = TestBackend::new();
    let mut authenticator = Authenticator::new();
    for (input, error) in [
        (&b"garbage"[..], AuthError::MalformedToken),
        (&[0x60, 0x05, 0x06, 0x03], AuthError::MalformedToken),
        (&[], AuthError::MalformedToken),
        (b"NTLMSSP\0\x01\0", AuthError::MalformedToken),
        (
            b"NTLMSSP\0\x03\0\0\0",
            AuthError::UnexpectedMessage {
                expected: NtlmMessage::Negotiate,
            },
        ),
    ] {
        assert_eq!(
            step(&mut authenticator, &mut backend, input).unwrap_err(),
            error,
            "{input:02x?}"
        );
    }
    let negotiate = negotiate_message(CLIENT_FLAGS);
    expect_continue(step(&mut authenticator, &mut backend, &negotiate));
    let truncated = &anonymous_message(&[])[..60];
    assert_eq!(
        step(&mut authenticator, &mut backend, truncated).unwrap_err(),
        AuthError::MalformedToken
    );
    // The failure reset the exchange: an AUTHENTICATE is now out of order.
    assert_eq!(
        step(&mut authenticator, &mut backend, &anonymous_message(&[])).unwrap_err(),
        AuthError::UnexpectedMessage {
            expected: NtlmMessage::Negotiate
        }
    );
    let oversized = [negotiate.as_slice(), &[0; 256]].concat();
    assert_eq!(
        step(&mut authenticator, &mut backend, &oversized).unwrap_err(),
        AuthError::MessageTooLarge {
            length: 296,
            capacity: 256
        }
    );
    expect_continue(step(&mut authenticator, &mut backend, &negotiate));
    assert_eq!(
        step(&mut authenticator, &mut backend, &negotiate).unwrap_err(),
        AuthError::UnexpectedMessage {
            expected: NtlmMessage::Authenticate
        }
    );
}

#[test]
fn small_output_buffer() {
    let mut backend = TestBackend::new();
    let mut authenticator = Authenticator::new();
    let negotiate = negotiate_message(CLIENT_FLAGS);
    assert_eq!(
        authenticator
            .step(&negotiate, &mut [0u8; 16], &mut backend)
            .unwrap_err(),
        AuthError::OutputTooSmall
    );
}

#[test]
fn oem_only_client_is_refused() {
    let mut backend = TestBackend::new();
    let negotiate = negotiate_message(CLIENT_FLAGS & !Flags::UNICODE.0);
    assert_eq!(
        step(&mut Authenticator::new(), &mut backend, &negotiate).unwrap_err(),
        AuthError::NotUnicode
    );
}

#[test]
fn challenge_message() {
    let mut backend = TestBackend::new();
    let challenge = expect_continue(step(
        &mut Authenticator::new(),
        &mut backend,
        &negotiate_message(CLIENT_FLAGS),
    ));
    insta::assert_snapshot!(hex_dump(&challenge));
}
