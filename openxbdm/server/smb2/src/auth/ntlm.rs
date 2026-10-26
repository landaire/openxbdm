//! NTLMSSP messages and NTLMv2 verification (MS-NLMP).

use super::AuthError;
use super::NtlmMessage;
use super::der::Writer;
use crate::backend::Backend;
use crate::backend::COMPUTER_NAME_CAPACITY;
use crate::backend::NtOwf;
use crate::backend::UserKind;
use crate::crypto::HmacMd5;
use crate::crypto::Md5;
use crate::crypto::Rc4;
use crate::crypto::constant_time_eq;
use crate::crypto::hmac_md5;
use crate::fs::FileTime;
use crate::utf16::Utf16Le;
use crate::utf16::upper_ascii;

pub(super) const SIGNATURE: [u8; 8] = *b"NTLMSSP\0";

const CHALLENGE_HEADER: usize = 56;

/// Largest CHALLENGE: header, TargetName, and five AV pairs.
pub(super) const CHALLENGE_CAPACITY: usize =
    CHALLENGE_HEADER + 2 * COMPUTER_NAME_CAPACITY + 3 * (4 + 2 * COMPUTER_NAME_CAPACITY) + 12 + 4;

/// MIC field of an AUTHENTICATE (MS-NLMP 2.2.1.3).
const MIC_OFFSET: usize = 72;
const MIC_END: usize = MIC_OFFSET + 16;

/// MessageType of an NTLMSSP message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MessageType {
    Negotiate,
    Challenge,
    Authenticate,
}

impl MessageType {
    const fn from_wire(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Negotiate),
            2 => Some(Self::Challenge),
            3 => Some(Self::Authenticate),
            _ => None,
        }
    }

    const fn wire(self) -> u32 {
        match self {
            Self::Negotiate => 1,
            Self::Challenge => 2,
            Self::Authenticate => 3,
        }
    }
}

/// NegotiateFlags (MS-NLMP 2.2.2.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Flags(pub u32);

impl Flags {
    pub const UNICODE: Self = Self(0x0000_0001);
    pub const REQUEST_TARGET: Self = Self(0x0000_0004);
    pub const SIGN: Self = Self(0x0000_0010);
    pub const SEAL: Self = Self(0x0000_0020);
    pub const NTLM: Self = Self(0x0000_0200);
    pub const ALWAYS_SIGN: Self = Self(0x0000_8000);
    pub const TARGET_TYPE_SERVER: Self = Self(0x0002_0000);
    pub const EXTENDED_SESSIONSECURITY: Self = Self(0x0008_0000);
    pub const TARGET_INFO: Self = Self(0x0080_0000);
    pub const VERSION: Self = Self(0x0200_0000);
    pub const NEGOTIATE_128: Self = Self(0x2000_0000);
    pub const KEY_EXCH: Self = Self(0x4000_0000);
    pub const NEGOTIATE_56: Self = Self(0x8000_0000);

    /// Set in every CHALLENGE.
    const ALWAYS: Self = Self(
        Self::UNICODE.0
            | Self::REQUEST_TARGET.0
            | Self::NTLM.0
            | Self::ALWAYS_SIGN.0
            | Self::TARGET_TYPE_SERVER.0
            | Self::TARGET_INFO.0
            | Self::VERSION.0,
    );
    /// Set in CHALLENGE when the client requests them.
    const NEGOTIABLE: Self = Self(
        Self::SIGN.0
            | Self::SEAL.0
            | Self::EXTENDED_SESSIONSECURITY.0
            | Self::NEGOTIATE_128.0
            | Self::KEY_EXCH.0
            | Self::NEGOTIATE_56.0,
    );

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Session security (signing or sealing) is negotiated.
    const fn session_security(self) -> bool {
        self.intersects(Self(Self::SIGN.0 | Self::SEAL.0))
    }
}

/// AvId of an AV_PAIR (MS-NLMP 2.2.2.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct AvId(u16);

impl AvId {
    const EOL: Self = Self(0);
    const NB_COMPUTER_NAME: Self = Self(1);
    const NB_DOMAIN_NAME: Self = Self(2);
    const DNS_COMPUTER_NAME: Self = Self(3);
    const FLAGS: Self = Self(6);
    const TIMESTAMP: Self = Self(7);
}

/// Value of the MsvAvFlags AV pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct MsvAvFlags(u32);

impl MsvAvFlags {
    /// The AUTHENTICATE carries a MIC.
    const MIC: Self = Self(0x2);

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Messages and values of the exchange so far.
pub(super) struct Exchange<'a> {
    pub negotiate: &'a [u8],
    pub challenge: &'a [u8],
    pub flags: Flags,
    pub server_challenge: [u8; 8],
}

/// Result of a successful AUTHENTICATE.
pub(super) struct Outcome {
    pub kind: UserKind,
    /// ExportedSessionKey; `None` for guest and anonymous.
    pub session_key: Option<[u8; 16]>,
    /// Flags in effect: those of the CHALLENGE that the client kept.
    pub flags: Flags,
}

/// Which side signs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Direction {
    ClientToServer,
    ServerToClient,
}

struct AuthenticateMessage<'a> {
    lm_response: &'a [u8],
    nt_response: &'a [u8],
    domain: Utf16Le<'a>,
    user: Utf16Le<'a>,
    encrypted_session_key: &'a [u8],
    flags: Flags,
}

/// NTLMv2_RESPONSE (MS-NLMP 2.2.2.8).
struct Ntlmv2Response<'a> {
    proof: &'a [u8],
    /// NTLMv2_CLIENT_CHALLENGE, the `temp` of MS-NLMP 3.3.2.
    blob: &'a [u8],
    mic_present: bool,
}

/// Outcome of checking an NTLMv2 response against the account database.
enum Verification {
    /// No account matches the user name.
    UnknownAccount,
    /// The account exists and the response does not prove its password.
    WrongPassword,
    /// The SessionBaseKey of a proven password.
    Verified([u8; 16]),
}

/// Flags of the CHALLENGE that answers `negotiate`.
pub(super) fn challenge_flags(negotiate: &[u8]) -> Result<Flags, AuthError> {
    expect_type(negotiate, NtlmMessage::Negotiate)?;

    let requested = Flags(u32_at(negotiate, 12).ok_or(AuthError::MalformedToken)?);
    if !requested.contains(Flags::UNICODE) {
        return Err(AuthError::NotUnicode);
    }

    Ok(Flags(Flags::ALWAYS.0 | (requested.0 & Flags::NEGOTIABLE.0)))
}

/// Encode a CHALLENGE (MS-NLMP 2.2.1.2) for the computer `name` (ASCII,
/// at most [`COMPUTER_NAME_CAPACITY`] bytes); returns its length.
///
/// A standalone server is its own NetBIOS domain, so TargetName and
/// MsvAvNbDomainName carry the computer name. It has no DNS domain, so
/// MsvAvDnsDomainName is omitted (MS-NLMP 3.2.5.1.1 adds it only when
/// not NIL).
pub(super) fn write_challenge(
    flags: Flags,
    server_challenge: &[u8; 8],
    time: FileTime,
    name: &[u8],
    output: &mut [u8],
) -> Option<usize> {
    /// Product 6.1 build 7601 with NTLMSSP_REVISION_W2K3 (MS-NLMP 2.2.2.10).
    /// Clients use the field for diagnostics only.
    const VERSION: [u8; 8] = [6, 1, 0xb1, 0x1d, 0, 0, 0, 0x0f];

    if name.len() > COMPUTER_NAME_CAPACITY {
        return None;
    }

    let name_bytes = 2 * name.len() as u16;
    let info_length = 3 * (4 + name_bytes) + 12 + 4;

    let mut writer = Writer::new(output);
    writer.bytes(&SIGNATURE)?;
    writer.u32(MessageType::Challenge.wire())?;
    writer.u16(name_bytes)?;
    writer.u16(name_bytes)?;
    writer.u32(CHALLENGE_HEADER as u32)?;
    writer.u32(flags.0)?;
    writer.bytes(server_challenge)?;
    writer.bytes(&[0; 8])?;
    writer.u16(info_length)?;
    writer.u16(info_length)?;
    writer.u32(CHALLENGE_HEADER as u32 + u32::from(name_bytes))?;
    writer.bytes(&VERSION)?;
    write_name(&mut writer, name, true)?;

    for (id, upper) in [
        (AvId::NB_COMPUTER_NAME, true),
        (AvId::NB_DOMAIN_NAME, true),
        (AvId::DNS_COMPUTER_NAME, false),
    ] {
        writer.u16(id.0)?;
        writer.u16(name_bytes)?;
        write_name(&mut writer, name, upper)?;
    }

    writer.u16(AvId::TIMESTAMP.0)?;
    writer.u16(8)?;
    writer.bytes(&time.0.to_le_bytes())?;
    writer.u16(AvId::EOL.0)?;
    writer.u16(0)?;

    Some(writer.position())
}

/// Process an AUTHENTICATE (MS-NLMP 3.2.5.1.2). Only NTLMv2 responses
/// authenticate a user.
#[inline(never)]
pub(super) fn authenticate(
    message: &[u8],
    exchange: &Exchange<'_>,
    backend: &mut dyn Backend,
) -> Result<Outcome, AuthError> {
    expect_type(message, NtlmMessage::Authenticate)?;

    let parsed = parse_authenticate(message).ok_or(AuthError::MalformedToken)?;
    if !parsed.flags.contains(Flags::UNICODE) {
        return Err(AuthError::MalformedToken);
    }

    let flags = Flags(exchange.flags.0 & parsed.flags.0);
    let unauthenticated = |kind| Outcome {
        kind,
        session_key: None,
        flags,
    };

    if parsed.user.is_empty()
        && parsed.nt_response.is_empty()
        && matches!(parsed.lm_response, [] | [0])
    {
        return if backend.allow_anonymous() {
            Ok(unauthenticated(UserKind::Anonymous))
        } else {
            Err(AuthError::AnonymousRefused)
        };
    }

    if parsed.nt_response.len() <= 24 {
        return Err(AuthError::NtlmV1Response);
    }

    let response = parse_ntlmv2(parsed.nt_response).ok_or(AuthError::MalformedToken)?;
    if response.mic_present && message.len() < MIC_END {
        return Err(AuthError::MalformedToken);
    }

    let base_key = match verify_password(
        backend,
        parsed.user,
        parsed.domain,
        &exchange.server_challenge,
        &response,
    ) {
        Verification::Verified(key) => key,
        Verification::UnknownAccount if backend.allow_guest() => {
            return Ok(unauthenticated(UserKind::Guest));
        }
        Verification::UnknownAccount => return Err(AuthError::UnknownAccount),
        Verification::WrongPassword => return Err(AuthError::WrongPassword),
    };

    // NTLMv2 KeyExchangeKey is the SessionBaseKey (MS-NLMP 3.4.5.1).
    let session_key = if flags.contains(Flags::KEY_EXCH) && flags.session_security() {
        let mut key: [u8; 16] = parsed
            .encrypted_session_key
            .try_into()
            .map_err(|_| AuthError::MalformedToken)?;
        Rc4::new(&base_key).apply(&mut key);
        key
    } else {
        base_key
    };

    if response.mic_present && !mic_matches(&session_key, exchange, message) {
        return Err(AuthError::MicMismatch);
    }

    Ok(Outcome {
        kind: UserKind::Authenticated,
        session_key: Some(session_key),
        flags,
    })
}

/// NTOWFv2 (MS-NLMP 3.3.2): user name in upper case, domain as sent.
pub(super) fn ntowfv2(password: &NtOwf, user: Utf16Le<'_>, domain: Utf16Le<'_>) -> [u8; 16] {
    let mut mac = HmacMd5::new(&password.0);
    for unit in user.units() {
        mac.update(&upper_ascii(unit).to_le_bytes());
    }

    mac.update(domain.as_bytes());

    mac.finalize()
}

/// SIGNKEY with extended session security (MS-NLMP 3.4.5.2).
pub(super) fn signing_key(session_key: &[u8; 16], direction: Direction) -> [u8; 16] {
    let magic: &[u8] = match direction {
        Direction::ClientToServer => {
            b"session key to client-to-server signing key magic constant\0"
        }
        Direction::ServerToClient => {
            b"session key to server-to-client signing key magic constant\0"
        }
    };

    derive_key(session_key, magic)
}

/// SEALKEY with extended session security (MS-NLMP 3.4.5.3).
pub(super) fn sealing_key(session_key: &[u8; 16], flags: Flags, direction: Direction) -> [u8; 16] {
    let magic: &[u8] = match direction {
        Direction::ClientToServer => {
            b"session key to client-to-server sealing key magic constant\0"
        }
        Direction::ServerToClient => {
            b"session key to server-to-client sealing key magic constant\0"
        }
    };

    let length = if flags.contains(Flags::NEGOTIATE_128) {
        16
    } else if flags.contains(Flags::NEGOTIATE_56) {
        7
    } else {
        5
    };

    derive_key(&session_key[..length], magic)
}

/// NTLMSSP_MESSAGE_SIGNATURE of `message` as the first message in
/// `direction` (sequence number 0, fresh sealing state), MS-NLMP 3.4.4.
/// `None` when session security is negotiated without extended session
/// security, which this server does not implement.
#[inline(never)]
pub(super) fn first_message_signature(
    session_key: &[u8; 16],
    flags: Flags,
    direction: Direction,
    message: &[u8],
) -> Option<[u8; 16]> {
    let mut signature = [0u8; 16];
    signature[0] = 1;

    if !flags.session_security() {
        return Some(signature);
    }

    if !flags.contains(Flags::EXTENDED_SESSIONSECURITY) {
        return None;
    }

    let mut mac = HmacMd5::new(&signing_key(session_key, direction));
    mac.update(&0u32.to_le_bytes());
    mac.update(message);
    let digest = mac.finalize();

    let checksum = &mut signature[4..12];
    checksum.copy_from_slice(&digest[..8]);
    if flags.contains(Flags::KEY_EXCH) {
        Rc4::new(&sealing_key(session_key, flags, direction)).apply(checksum);
    }

    Some(signature)
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(*data.get(offset..)?.first_chunk()?))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(*data.get(offset..)?.first_chunk()?))
}

/// Check that `message` is an NTLMSSP message of `expected` type.
fn expect_type(message: &[u8], expected: NtlmMessage) -> Result<(), AuthError> {
    if message.get(..8) != Some(&SIGNATURE[..]) {
        return Err(AuthError::MalformedToken);
    }

    let code = match expected {
        NtlmMessage::Negotiate => MessageType::Negotiate,
        NtlmMessage::Authenticate => MessageType::Authenticate,
    };

    match u32_at(message, 8) {
        None => Err(AuthError::MalformedToken),
        Some(found) if MessageType::from_wire(found) != Some(code) => {
            Err(AuthError::UnexpectedMessage { expected })
        }
        Some(_) => Ok(()),
    }
}

fn write_name(writer: &mut Writer<'_>, name: &[u8], upper: bool) -> Option<()> {
    for &byte in name {
        let byte = if upper {
            byte.to_ascii_uppercase()
        } else {
            byte
        };
        writer.u16(u16::from(byte))?;
    }

    Some(())
}

/// Bytes of a security buffer descriptor at `offset`. Empty fields may
/// carry any offset.
fn field(message: &[u8], offset: usize) -> Option<&[u8]> {
    let length = usize::from(u16_at(message, offset)?);
    if length == 0 {
        return Some(&[]);
    }

    let start = usize::try_from(u32_at(message, offset + 4)?).ok()?;
    message.get(start..start.checked_add(length)?)
}

/// Fields of an AUTHENTICATE whose type was checked.
fn parse_authenticate(message: &[u8]) -> Option<AuthenticateMessage<'_>> {
    Some(AuthenticateMessage {
        lm_response: field(message, 12)?,
        nt_response: field(message, 20)?,
        domain: Utf16Le::new(field(message, 28)?)?,
        user: Utf16Le::new(field(message, 36)?)?,
        encrypted_session_key: field(message, 52)?,
        flags: Flags(u32_at(message, 60)?),
    })
}

fn parse_ntlmv2(response: &[u8]) -> Option<Ntlmv2Response<'_>> {
    /// Offset of the AV pairs in NTLMv2_CLIENT_CHALLENGE.
    const BLOB_AV_PAIRS: usize = 28;

    let (proof, blob) = response.split_at_checked(16)?;
    let mut pairs = blob.get(BLOB_AV_PAIRS..)?;
    if blob[0] != 1 || blob[1] != 1 {
        return None;
    }

    let mut mic_present = false;
    while !pairs.is_empty() {
        let id = AvId(u16_at(pairs, 0)?);
        let length = usize::from(u16_at(pairs, 2)?);
        let value = pairs.get(4..4 + length)?;
        pairs = &pairs[4 + length..];

        match id {
            AvId::EOL => break,
            AvId::FLAGS => mic_present = MsvAvFlags(u32_at(value, 0)?).contains(MsvAvFlags::MIC),
            // Other AV pairs do not affect verification.
            _ => {}
        }
    }

    Some(Ntlmv2Response {
        proof,
        blob,
        mic_present,
    })
}

/// SessionBaseKey when NTProofStr under `response_key` matches.
fn session_base_key(
    response_key: &[u8; 16],
    server_challenge: &[u8; 8],
    response: &Ntlmv2Response<'_>,
) -> Option<[u8; 16]> {
    let mut mac = HmacMd5::new(response_key);
    mac.update(server_challenge);
    mac.update(response.blob);
    let proof = mac.finalize();

    constant_time_eq(&proof, response.proof).then(|| hmac_md5(response_key, &proof))
}

/// Verify the response against the account database, retrying with an
/// empty domain for clients that compute NTOWFv2 without one (MS-NLMP
/// 3.2.5.1.2). User names outside ASCII name no account.
fn verify_password(
    backend: &mut dyn Backend,
    user: Utf16Le<'_>,
    domain: Utf16Le<'_>,
    server_challenge: &[u8; 8],
    response: &Ntlmv2Response<'_>,
) -> Verification {
    if user.units().any(|unit| unit >= 0x80) {
        return Verification::UnknownAccount;
    }

    let mut attempt = |domain: Utf16Le<'_>| match backend.password(user, domain) {
        None => Verification::UnknownAccount,
        Some(password) => match session_base_key(
            &ntowfv2(&password, user, domain),
            server_challenge,
            response,
        ) {
            Some(key) => Verification::Verified(key),
            None => Verification::WrongPassword,
        },
    };

    match attempt(domain) {
        first @ Verification::Verified(_) => first,
        first if domain.is_empty() => first,
        first => match attempt(Utf16Le::EMPTY) {
            Verification::UnknownAccount => first,
            second => second,
        },
    }
}

#[inline(never)]
fn mic_matches(session_key: &[u8; 16], exchange: &Exchange<'_>, message: &[u8]) -> bool {
    let (Some(head), Some(received), Some(tail)) = (
        message.get(..MIC_OFFSET),
        message.get(MIC_OFFSET..MIC_END),
        message.get(MIC_END..),
    ) else {
        return false;
    };

    let mut mac = HmacMd5::new(session_key);
    mac.update(exchange.negotiate);
    mac.update(exchange.challenge);
    mac.update(head);
    mac.update(&[0; 16]);
    mac.update(tail);

    constant_time_eq(&mac.finalize(), received)
}

fn derive_key(material: &[u8], magic: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(material);
    hasher.update(magic);

    hasher.finalize()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::Direction;
    use super::Exchange;
    use super::Flags;
    use super::authenticate;
    use super::ntowfv2;
    use super::parse_ntlmv2;
    use super::sealing_key;
    use super::session_base_key;
    use super::signing_key;
    use crate::auth::tests::TestBackend;
    use crate::auth::tests::nt_owf;
    use crate::auth::tests::utf16;
    use crate::backend::UserKind;
    use crate::crypto::HmacMd5;
    use crate::crypto::Rc4;
    use crate::crypto::tests::decode_hex;
    use crate::utf16::Utf16Le;

    const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    const FLAGS: Flags = Flags(0xe28a_8233);

    /// MS-NLMP 4.2.4.3 CHALLENGE_MESSAGE.
    const CHALLENGE: &str = "4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef\
        00000000000000002400240044000000060070170000000f53006500720076006500720002000c00\
        44006f006d00610069006e0001000c0053006500720076006500720000000000";

    /// MS-NLMP 4.2.4.3 AUTHENTICATE_MESSAGE.
    const AUTHENTICATE: &str = "4e544c4d5353500003000000180018006c00000054005400840000000c000c00\
        480000000800080054000000100010005c00000010001000d8000000358288e20501280a0000000f\
        44006f006d00610069006e00550073006500720043004f004d005000550054004500520086c35097\
        ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa68cd0ab851e51c96aabc927bebef6a1c01010000\
        000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e00\
        01000c005300650072007600650072000000000000000000c5dad2544fc9799094ce1ce90bc9d03e";

    fn decode(text: &str) -> std::vec::Vec<u8> {
        let text: std::string::String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn ms_nlmp_ntlmv2_calculations() {
        let user = utf16("User");
        let domain = utf16("Domain");
        let response_key = ntowfv2(
            &nt_owf("Password"),
            Utf16Le::new(&user).unwrap(),
            Utf16Le::new(&domain).unwrap(),
        );
        assert_eq!(
            response_key,
            decode_hex::<16>("0c868a403bfd7a93a3001ef22ef02e3f")
        );

        let message = decode(AUTHENTICATE);
        let response = parse_ntlmv2(&message[0x84..0x84 + 0x54]).unwrap();
        assert_eq!(
            response.proof,
            decode_hex::<16>("68cd0ab851e51c96aabc927bebef6a1c")
        );
        assert!(!response.mic_present);
        let base_key = session_base_key(&response_key, &SERVER_CHALLENGE, &response).unwrap();
        assert_eq!(
            base_key,
            decode_hex::<16>("8de40ccadbc14a82f15cb0ad0de95ca3")
        );

        let mut encrypted = [0x55; 16];
        Rc4::new(&base_key).apply(&mut encrypted);
        assert_eq!(
            encrypted,
            decode_hex::<16>("c5dad2544fc9799094ce1ce90bc9d03e")
        );
    }

    #[test]
    fn ms_nlmp_authenticate_message() {
        let mut backend = TestBackend::new();
        backend.accounts = &[("user", "Password")];
        let challenge = decode(CHALLENGE);
        let exchange = Exchange {
            negotiate: &[],
            challenge: &challenge,
            flags: FLAGS,
            server_challenge: SERVER_CHALLENGE,
        };
        let outcome = authenticate(&decode(AUTHENTICATE), &exchange, &mut backend).unwrap();
        assert_eq!(outcome.kind, UserKind::Authenticated);
        assert_eq!(outcome.session_key, Some([0x55; 16]));
    }

    /// MS-NLMP 4.2.4.4: SealKey, SignKey, and the sealed checksum after
    /// the sealing stream encrypted the 18-byte message.
    #[test]
    fn ms_nlmp_signing_keys_and_checksum() {
        let key = [0x55; 16];
        let seal = sealing_key(&key, FLAGS, Direction::ClientToServer);
        assert_eq!(seal, decode_hex::<16>("59f600973cc4960a25480a7c196e4c58"));
        let sign = signing_key(&key, Direction::ClientToServer);
        assert_eq!(sign, decode_hex::<16>("4788dc861b4782f35d43fd98fe1a2d39"));

        let mut message = utf16("Plaintext");
        let mut mac = HmacMd5::new(&sign);
        mac.update(&[0; 4]);
        mac.update(&message);
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&mac.finalize()[..8]);
        assert_eq!(checksum, decode_hex::<8>("70352851f2564309"));

        let mut cipher = Rc4::new(&seal);
        cipher.apply(&mut message);
        assert_eq!(message, decode("54e50165bf1936dc996020c1811b0f06fb5f"));
        cipher.apply(&mut checksum);
        assert_eq!(checksum, decode_hex::<8>("7fb38ec5c55d4976"));
    }
}
