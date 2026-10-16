//! HMAC (RFC 2104) over MD5 and SHA-256.

use super::engine::Engine;
use super::md::Md5;
use super::sha256::Sha256;

#[derive(Clone)]
struct Hmac {
    inner: Engine,
    outer: Engine,
}

impl Hmac {
    fn new(hash: Engine, digest_length: usize, key: &[u8]) -> Self {
        let mut padded = [0u8; 64];
        if key.len() > padded.len() {
            let mut hashed = hash.clone();
            hashed.update(key);
            hashed.finish(&mut padded[..digest_length]);
        } else {
            padded[..key.len()].copy_from_slice(key);
        }
        let mut inner = hash.clone();
        let mut outer = hash;
        for byte in &mut padded {
            *byte ^= 0x36;
        }
        inner.update(&padded);
        for byte in &mut padded {
            *byte ^= 0x36 ^ 0x5c;
        }
        outer.update(&padded);
        Self { inner, outer }
    }

    fn finish(&mut self, output: &mut [u8]) {
        self.inner.finish(output);
        self.outer.update(output);
        self.outer.finish(output);
    }
}

/// Streaming HMAC-MD5.
#[derive(Clone)]
pub struct HmacMd5(Hmac);

impl HmacMd5 {
    /// MAC keyed with `key` over empty input.
    pub fn new(key: &[u8]) -> Self {
        Self(Hmac::new(Md5::engine(), 16, key))
    }

    /// Append `data` to the input.
    pub fn update(&mut self, data: &[u8]) {
        self.0.inner.update(data);
    }

    /// MAC of the input.
    pub fn finalize(mut self) -> [u8; 16] {
        let mut mac = [0; 16];
        self.0.finish(&mut mac);
        mac
    }
}

/// HMAC-MD5 of `data` under `key`.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new(key);
    mac.update(data);
    mac.finalize()
}

/// Streaming HMAC-SHA256.
#[derive(Clone)]
pub struct HmacSha256(Hmac);

impl HmacSha256 {
    /// MAC keyed with `key` over empty input.
    pub fn new(key: &[u8]) -> Self {
        Self(Hmac::new(Sha256::engine(), 32, key))
    }

    /// Append `data` to the input.
    pub fn update(&mut self, data: &[u8]) {
        self.0.inner.update(data);
    }

    /// MAC of the input.
    pub fn finalize(mut self) -> [u8; 32] {
        let mut mac = [0; 32];
        self.0.finish(&mut mac);
        mac
    }
}

/// HMAC-SHA256 of `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new(key);
    mac.update(data);
    mac.finalize()
}

#[cfg(test)]
mod tests {
    use super::hmac_md5;
    use super::hmac_sha256;
    use crate::crypto::tests::decode_hex;

    const LARGE_KEY_DATA: &[u8] = b"Test Using Larger Than Block-Size Key - Hash Key First";

    #[test]
    fn hmac_md5_rfc2104_and_rfc2202() {
        assert_eq!(
            hmac_md5(&[0x0b; 16], b"Hi There"),
            decode_hex::<16>("9294727a3638bb1c13f48ef8158bfc9d")
        );
        assert_eq!(
            hmac_md5(b"Jefe", b"what do ya want for nothing?"),
            decode_hex::<16>("750c783e6ab0b503eaa86e310a5db738")
        );
        assert_eq!(
            hmac_md5(&[0xaa; 16], &[0xdd; 50]),
            decode_hex::<16>("56be34521d144c88dbb8c733f0e8b3f6")
        );
        assert_eq!(
            hmac_md5(&[0xaa; 80], LARGE_KEY_DATA),
            decode_hex::<16>("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd")
        );
    }

    #[test]
    fn hmac_sha256_rfc4231() {
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There"),
            decode_hex::<32>("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            decode_hex::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        assert_eq!(
            hmac_sha256(&[0xaa; 131], LARGE_KEY_DATA),
            decode_hex::<32>("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }
}
