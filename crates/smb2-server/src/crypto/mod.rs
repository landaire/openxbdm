//! Hash, MAC, cipher, and key derivation primitives the protocol requires.

mod aes;
mod ccm;
mod chain;
mod cmac;
mod engine;
mod gcm;
mod hmac;
mod kdf;
mod md;
mod rc4;
mod sha256;
mod sha512;

pub use aes::Aes128;
pub use ccm::ccm_open;
pub use ccm::ccm_seal;
pub use cmac::AesCmac;
pub use cmac::aes_cmac;
pub use gcm::gcm_open;
pub use gcm::gcm_seal;
pub use gcm::gmac;
pub use hmac::HmacMd5;
pub use hmac::HmacSha256;
pub use hmac::hmac_md5;
pub use hmac::hmac_sha256;
pub use kdf::smb3_kdf;
pub use md::Md4;
pub use md::Md5;
pub use md::md4;
pub use md::md5;
pub use rc4::Rc4;
pub use sha256::Sha256;
pub use sha256::sha256;
pub use sha512::Sha512;
pub use sha512::sha512;

/// The message exceeds the length the cipher mode can protect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageTooLong;

/// Whether `a` equals `b`, in time that depends only on the lengths.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let difference = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    core::hint::black_box(difference) == 0
}

#[cfg(test)]
pub(crate) mod tests {
    use super::constant_time_eq;

    /// Decode exactly `N` bytes of hexadecimal text.
    pub(crate) fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2, "hex length");
        let mut out = [0; N];
        for (byte, pair) in out.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        out
    }

    #[test]
    fn constant_time_eq_compares_contents_and_lengths() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
