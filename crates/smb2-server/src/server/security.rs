//! Message signing (MS-SMB2 3.1.4.1), key derivation (3.1.4.2), and
//! encryption (3.1.4.3, 2.2.41).

use crate::auth::SessionKey;
use crate::crypto::AesCmac;
use crate::crypto::HmacSha256;
use crate::crypto::Sha512;
use crate::crypto::ccm_open;
use crate::crypto::ccm_seal;
use crate::crypto::gcm_open;
use crate::crypto::gcm_seal;
use crate::crypto::gmac;
use crate::crypto::smb3_kdf;
use crate::server::tables::SessionId;
use crate::server::wire;
use crate::server::wire::Command;
use crate::server::wire::Dialect;
use crate::server::wire::HeaderFlags;
use crate::server::wire::header;

/// Bytes of the transform header that precedes an encrypted message.
pub(super) const TRANSFORM_HEADER: usize = 52;
pub(super) const TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xfd, b'S', b'M', b'B'];
const TRANSFORM_SIGNATURE: usize = 4;
const TRANSFORM_NONCE: usize = 20;
const TRANSFORM_SIZE: usize = 36;
const TRANSFORM_FLAGS: usize = 42;
const TRANSFORM_SESSION: usize = 44;

/// Flags of a transform header (MS-SMB2 2.2.41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransformFlags(u16);

impl TransformFlags {
    const ENCRYPTED: Self = Self(0x0001);
}

/// The counter part of an encryption nonce; it must not repeat for a
/// session's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Nonce(pub u64);

impl Nonce {
    pub const FIRST: Self = Self(0);

    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// A signing algorithm (MS-SMB2 2.2.3.1.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigningAlgorithm {
    HmacSha256,
    AesCmac,
    AesGmac,
}

impl SigningAlgorithm {
    pub(super) const fn wire(self) -> u16 {
        match self {
            Self::HmacSha256 => 0,
            Self::AesCmac => 1,
            Self::AesGmac => 2,
        }
    }
}

/// A cipher (MS-SMB2 2.2.3.1.2). The 256-bit ciphers are not offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cipher {
    Aes128Ccm,
    Aes128Gcm,
}

impl Cipher {
    pub(super) const fn wire(self) -> u16 {
        match self {
            Self::Aes128Ccm => 1,
            Self::Aes128Gcm => 2,
        }
    }
}

/// The key that signs a session's messages.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SigningKey {
    pub key: [u8; 16],
    pub algorithm: SigningAlgorithm,
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "SigningKey({:?}, ..)", self.algorithm)
    }
}

/// The keys that encrypt a session's messages.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncryptionKeys {
    pub cipher: Cipher,
    /// Encrypts messages to the client.
    pub encryption: [u8; 16],
    /// Decrypts messages from the client.
    pub decryption: [u8; 16],
}

impl core::fmt::Debug for EncryptionKeys {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "EncryptionKeys({:?}, ..)", self.cipher)
    }
}

/// A preauthentication integrity hash value (MS-SMB2 3.3.5.4).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreauthHash(pub [u8; 64]);

impl PreauthHash {
    pub(super) const ZERO: Self = Self([0; 64]);

    /// The hash after `message`.
    pub(super) fn update(self, message: &[u8]) -> Self {
        let mut hash = Sha512::new();
        hash.update(&self.0);
        hash.update(message);
        Self(hash.finalize())
    }
}

impl core::fmt::Debug for PreauthHash {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PreauthHash(..)")
    }
}

/// The keys of an authenticated session for `dialect`.
pub(super) fn derive_keys(
    dialect: Dialect,
    session_key: &SessionKey,
    preauth: &PreauthHash,
    signing: SigningAlgorithm,
    cipher: Option<Cipher>,
) -> (SigningKey, Option<EncryptionKeys>) {
    let key = &session_key.0;
    match dialect {
        Dialect::SMB_3_1_1 => (
            SigningKey {
                key: smb3_kdf(key, b"SMBSigningKey\0", &preauth.0),
                algorithm: signing,
            },
            cipher.map(|cipher| EncryptionKeys {
                cipher,
                encryption: smb3_kdf(key, b"SMBS2CCipherKey\0", &preauth.0),
                decryption: smb3_kdf(key, b"SMBC2SCipherKey\0", &preauth.0),
            }),
        ),
        Dialect::SMB_3_0 | Dialect::SMB_3_0_2 => (
            SigningKey {
                key: smb3_kdf(key, b"SMB2AESCMAC\0", b"SmbSign\0"),
                algorithm: SigningAlgorithm::AesCmac,
            },
            cipher.map(|cipher| EncryptionKeys {
                cipher,
                encryption: smb3_kdf(key, b"SMB2AESCCM\0", b"ServerOut\0"),
                decryption: smb3_kdf(key, b"SMB2AESCCM\0", b"ServerIn \0"),
            }),
        ),
        _ => (
            SigningKey {
                key: *key,
                algorithm: SigningAlgorithm::HmacSha256,
            },
            None,
        ),
    }
}

/// The signature of a message whose signature field counts as zero.
pub(super) fn signature(message: &[u8], key: &SigningKey) -> [u8; 16] {
    let head = &message[..header::SIGNATURE];
    let tail = &message[header::SIGNATURE + 16..];
    match key.algorithm {
        SigningAlgorithm::HmacSha256 => {
            let mut mac = HmacSha256::new(&key.key);
            mac.update(head);
            mac.update(&[0; 16]);
            mac.update(tail);
            let digest = mac.finalize();
            let mut signature = [0; 16];
            signature.copy_from_slice(&digest[..16]);
            signature
        }
        SigningAlgorithm::AesCmac => {
            let mut mac = AesCmac::new(&key.key);
            mac.update(head);
            mac.update(&[0; 16]);
            mac.update(tail);
            mac.finalize()
        }
        SigningAlgorithm::AesGmac => {
            // The nonce is the message identifier and a word whose bit 0
            // marks a reply and bit 1 a cancel (MS-SMB2 3.1.4.1).
            let mut nonce = [0; 12];
            nonce[..8].copy_from_slice(&message[header::MESSAGE_ID..header::MESSAGE_ID + 8]);
            let flags = HeaderFlags(wire::u32_at(message, header::FLAGS));
            let mut role = u32::from(flags.contains(HeaderFlags::SERVER_TO_REDIR));
            if wire::u16_at(message, header::COMMAND) == Command::CANCEL.0 {
                role |= 2;
            }
            nonce[8..].copy_from_slice(&role.to_le_bytes());
            gmac(&key.key, &nonce, &[head, &[0; 16], tail])
        }
    }
}

/// Sign a message in place.
pub(super) fn sign(message: &mut [u8], key: &SigningKey) {
    let signature = signature(message, key);
    message[header::SIGNATURE..header::SIGNATURE + 16].copy_from_slice(&signature);
}

/// Whether a request carries the signature of `key`.
pub(super) fn verify(message: &[u8], key: &SigningKey) -> bool {
    crate::crypto::constant_time_eq(
        &signature(message, key),
        &message[header::SIGNATURE..header::SIGNATURE + 16],
    )
}

/// The session identifier of a transform header.
pub(super) fn transform_session(message: &[u8]) -> SessionId {
    SessionId(wire::u64_at(message, TRANSFORM_SESSION))
}

/// Decrypt the message after a transform header in place; returns its
/// length, or `None` when the header is malformed or the tag is wrong.
pub(super) fn decrypt(message: &mut [u8], keys: &EncryptionKeys) -> Option<usize> {
    if message.len() < TRANSFORM_HEADER
        || TransformFlags(wire::u16_at(message, TRANSFORM_FLAGS)) != TransformFlags::ENCRYPTED
    {
        return None;
    }
    let length = wire::u32_at(message, TRANSFORM_SIZE) as usize;
    if length != message.len() - TRANSFORM_HEADER {
        return None;
    }
    let (header, payload) = message.split_at_mut(TRANSFORM_HEADER);
    let mut tag = [0; 16];
    tag.copy_from_slice(&header[TRANSFORM_SIGNATURE..TRANSFORM_SIGNATURE + 16]);
    let aad = &header[TRANSFORM_NONCE..];
    let opened = match keys.cipher {
        Cipher::Aes128Ccm => {
            let mut nonce = [0; 11];
            nonce.copy_from_slice(&header[TRANSFORM_NONCE..TRANSFORM_NONCE + 11]);
            ccm_open(&keys.decryption, &nonce, aad, payload, &tag)
        }
        Cipher::Aes128Gcm => {
            let mut nonce = [0; 12];
            nonce.copy_from_slice(&header[TRANSFORM_NONCE..TRANSFORM_NONCE + 12]);
            gcm_open(&keys.decryption, &nonce, aad, payload, &tag)
        }
    };
    opened.then_some(length)
}

/// Encrypt `message[TRANSFORM_HEADER..]` in place and fill the transform
/// header before it. `nonce` must not repeat for the session's key.
pub(super) fn encrypt(
    message: &mut [u8],
    keys: &EncryptionKeys,
    session: SessionId,
    nonce: Nonce,
) -> Option<()> {
    let length = message.len().checked_sub(TRANSFORM_HEADER)?;
    let (header, payload) = message.split_at_mut(TRANSFORM_HEADER);
    header.fill(0);
    header[..4].copy_from_slice(&TRANSFORM_PROTOCOL_ID);
    header[TRANSFORM_NONCE..TRANSFORM_NONCE + 8].copy_from_slice(&nonce.0.to_le_bytes());
    wire::put_u32(header, TRANSFORM_SIZE, length as u32);
    wire::put_u16(header, TRANSFORM_FLAGS, TransformFlags::ENCRYPTED.0);
    wire::put_u64(header, TRANSFORM_SESSION, session.0);
    let (prefix, aad) = header.split_at_mut(TRANSFORM_NONCE);
    let tag = match keys.cipher {
        Cipher::Aes128Ccm => {
            let mut nonce = [0; 11];
            nonce.copy_from_slice(&aad[..11]);
            ccm_seal(&keys.encryption, &nonce, aad, payload).ok()?
        }
        Cipher::Aes128Gcm => {
            let mut nonce = [0; 12];
            nonce.copy_from_slice(&aad[..12]);
            gcm_seal(&keys.encryption, &nonce, aad, payload).ok()?
        }
    };
    prefix[TRANSFORM_SIGNATURE..TRANSFORM_SIGNATURE + 16].copy_from_slice(&tag);
    Some(())
}

#[cfg(test)]
mod tests;
