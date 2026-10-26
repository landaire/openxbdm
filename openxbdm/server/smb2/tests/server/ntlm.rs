//! NTLMv2 client messages (MS-NLMP 2.2.1, 3.3.2) and the SPNEGO tokens
//! that carry them (RFC 4178).

use smb2_server::crypto::Rc4;
use smb2_server::crypto::hmac_md5;
use smb2_server::crypto::md4;

use crate::backend::utf16;

const NTLMSSP_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// UNICODE, REQUEST_TARGET, SIGN, SEAL, NTLM, ALWAYS_SIGN,
/// EXTENDED_SESSIONSECURITY, VERSION, 128, KEY_EXCH, 56.
const CLIENT_FLAGS: u32 = 0xe208_8235;
const KEY_EXCH: u32 = 0x4000_0000;
const NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;
const VERSION: [u8; 8] = [10, 0, 0x61, 0x4a, 0, 0, 0, 0x0f];
const CLIENT_CHALLENGE: [u8; 8] = [0xaa; 8];
const EXPORTED_SESSION_KEY: [u8; 16] = [0x55; 16];

/// An AUTHENTICATE message and the session key both sides derive.
pub struct Authenticate {
    pub message: Vec<u8>,
    pub session_key: [u8; 16],
}

/// Fields of a server NegTokenResp: negState and the response token.
pub struct NegTokenResp {
    pub state: Option<u8>,
    pub token: Option<Vec<u8>>,
}

pub fn negotiate_message() -> Vec<u8> {
    [
        &b"NTLMSSP\0"[..],
        &1u32.to_le_bytes(),
        &CLIENT_FLAGS.to_le_bytes(),
        &[0; 16],
        &VERSION,
    ]
    .concat()
}

/// NTLMv2 AUTHENTICATE answering `challenge`, with key exchange and a MIC.
pub fn authenticate_message(
    user: &str,
    domain: &str,
    password: &str,
    negotiate: &[u8],
    challenge: &[u8],
) -> Authenticate {
    assert_eq!(&challenge[..12], b"NTLMSSP\0\x02\0\0\0");
    let flags = u32_at(challenge, 20);
    assert_ne!(flags & KEY_EXCH, 0, "server grants key exchange");
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

    // MsvAvFlags: the message carries a MIC.
    pairs.extend([6, 0, 4, 0, 2, 0, 0, 0]);
    pairs.extend([0, 0, 0, 0]);
    let blob = [
        &[1, 1, 0, 0, 0, 0, 0, 0][..],
        &timestamp,
        &CLIENT_CHALLENGE,
        &[0; 4],
        &pairs,
        &[0; 4],
    ]
    .concat();

    let nt_owf = md4(&utf16(password));
    let response_key = hmac_md5(
        &nt_owf,
        &[utf16(&user.to_uppercase()), utf16(domain)].concat(),
    );
    let proof = hmac_md5(&response_key, &[server_challenge, &blob].concat());
    let nt_response = [&proof[..], &blob].concat();
    let base_key = hmac_md5(&response_key, &proof);

    let mut encrypted_key = EXPORTED_SESSION_KEY;
    Rc4::new(&base_key).apply(&mut encrypted_key);

    let mut message = authenticate_fields(
        flags,
        &[0; 24],
        &nt_response,
        &utf16(domain),
        &utf16(user),
        &encrypted_key,
    );
    let mic = hmac_md5(
        &EXPORTED_SESSION_KEY,
        &[negotiate, challenge, &message].concat(),
    );
    message[72..88].copy_from_slice(&mic);

    Authenticate {
        message,
        session_key: EXPORTED_SESSION_KEY,
    }
}

/// AUTHENTICATE of a null session: empty user and responses.
pub fn anonymous_message() -> Vec<u8> {
    authenticate_fields(CLIENT_FLAGS | NEGOTIATE_ANONYMOUS, &[], &[], &[], &[], &[])
}

/// NegTokenInit offering NTLMSSP with `token` as the optimistic token.
pub fn neg_token_init(token: &[u8]) -> Vec<u8> {
    let mech_types = tlv(0x30, &tlv(0x06, NTLMSSP_OID));
    let fields = [tlv(0xa0, &mech_types), tlv(0xa2, &tlv(0x04, token))].concat();
    let body = [tlv(0x06, SPNEGO_OID), tlv(0xa0, &tlv(0x30, &fields))].concat();

    tlv(0x60, &body)
}

/// NegTokenResp carrying `token`.
pub fn neg_token_resp(token: &[u8]) -> Vec<u8> {
    tlv(0xa1, &tlv(0x30, &tlv(0xa2, &tlv(0x04, token))))
}

pub fn parse_neg_token_resp(bytes: &[u8]) -> NegTokenResp {
    let outer = read_element(bytes);
    assert_eq!((outer.tag, outer.rest.len()), (0xa1, 0));
    let sequence = read_element(outer.content);
    assert_eq!(sequence.tag, 0x30);
    let mut fields = sequence.content;

    let mut parsed = NegTokenResp {
        state: None,
        token: None,
    };

    while !fields.is_empty() {
        let field = read_element(fields);
        let inner = read_element(field.content).content;
        match field.tag {
            0xa0 => parsed.state = Some(inner[0]),
            0xa2 => parsed.token = Some(inner.to_vec()),
            // supportedMech and mechListMIC are not checked.
            _ => {}
        }
        fields = field.rest;
    }

    parsed
}

fn u16_at(data: &[u8], offset: usize) -> usize {
    usize::from(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// AUTHENTICATE with a zero MIC and the payload in field order.
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
    let mut message = [&b"NTLMSSP\0"[..], &3u32.to_le_bytes()].concat();

    let mut offset = 88u32;
    for field in payload {
        let length = field.len() as u16;
        message.extend(length.to_le_bytes());
        message.extend(length.to_le_bytes());
        message.extend(offset.to_le_bytes());
        offset += u32::from(length);
    }

    message.extend(flags.to_le_bytes());
    message.extend(VERSION);
    message.extend([0; 16]);

    for field in payload {
        message.extend_from_slice(field);
    }

    message
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut element = vec![tag];
    let length = content.len();
    if length < 0x80 {
        element.push(length as u8);
    } else if length <= 0xff {
        element.extend([0x81, length as u8]);
    } else {
        element.extend([0x82, (length >> 8) as u8, length as u8]);
    }
    element.extend_from_slice(content);

    element
}

/// One DER element and the rest of the input.
struct Element<'a> {
    tag: u8,
    content: &'a [u8],
    rest: &'a [u8],
}

fn read_element(bytes: &[u8]) -> Element<'_> {
    let tag = bytes[0];
    let (length, header) = match bytes[1] {
        length if length < 0x80 => (usize::from(length), 2),
        0x81 => (usize::from(bytes[2]), 3),
        0x82 => (usize::from(bytes[2]) << 8 | usize::from(bytes[3]), 4),
        other => panic!("unsupported DER length form {other:#04x}"),
    };

    Element {
        tag,
        content: &bytes[header..header + length],
        rest: &bytes[header + length..],
    }
}
