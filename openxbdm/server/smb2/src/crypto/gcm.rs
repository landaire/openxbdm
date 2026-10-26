//! AES-128-GCM and GMAC (NIST SP 800-38D) with 96-bit nonces.
//!
//! GHASH multiplies bit by bit with masks instead of branches or tables:
//! constant-time and small, at about 128 shift-and-XOR steps per block.

use super::MessageTooLong;
use super::aes::Aes128;
use super::chain::Chain;
use super::chain::ChainStep;
use super::constant_time_eq;

/// Longest plaintext GCM permits: 2^32 - 2 blocks.
const MAX_DATA: u64 = (1 << 36) - 32;

/// The hash subkey H = E(K, 0).
struct GhashKey(u128);

impl GhashKey {
    fn new(cipher: &Aes128) -> Self {
        let mut block = [0; 16];
        cipher.encrypt_block(&mut block);

        Self(u128::from_be_bytes(block))
    }

    /// Absorb the AAD and data length block and return the GHASH value.
    fn finish(&self, mut chain: Chain, aad_length: u64, data_length: u64) -> [u8; 16] {
        chain.pad(self);

        let mut lengths = [0; 16];
        lengths[..8].copy_from_slice(&(aad_length * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&(data_length * 8).to_be_bytes());
        chain.update(&lengths, self);
        chain.pad(self);

        chain.state
    }
}

impl ChainStep for GhashKey {
    /// Multiply the state by H in GF(2^128). Bit 0 of a block is the most
    /// significant bit of its first byte.
    fn step(&self, state: &mut [u8; 16]) {
        const REDUCTION: u128 = 0xe1 << 120;

        let operand = u128::from_be_bytes(*state);
        let mut multiple = self.0;
        let mut product = 0;
        for bit in (0..128).rev() {
            product ^= multiple & ((operand >> bit) & 1).wrapping_neg();
            multiple = (multiple >> 1) ^ (REDUCTION & (multiple & 1).wrapping_neg());
        }

        *state = product.to_be_bytes();
    }
}

/// GHASH over `aad` and `data`, each zero-padded to whole blocks.
fn ghash(key: &GhashKey, aad: &[u8], data: &[u8]) -> [u8; 16] {
    let mut chain = Chain::new();
    chain.update(aad, key);
    chain.pad(key);
    chain.update(data, key);

    key.finish(chain, aad.len() as u64, data.len() as u64)
}

/// Encrypt `data` in place with AES-128-GCM and return the tag.
pub fn gcm_seal(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> Result<[u8; 16], MessageTooLong> {
    if data.len() as u64 > MAX_DATA {
        return Err(MessageTooLong);
    }

    let cipher = Aes128::new(key);
    cipher.apply_counter_mode(nonce, 2, data);
    let mut tag = ghash(&GhashKey::new(&cipher), aad, data);
    cipher.apply_counter_mode(nonce, 1, &mut tag);

    Ok(tag)
}

/// Verify `tag` over the ciphertext `data` and `aad`, then decrypt `data`
/// in place. On failure `data` is left as ciphertext.
pub fn gcm_open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    if data.len() as u64 > MAX_DATA {
        return false;
    }

    let cipher = Aes128::new(key);
    let mut expected = ghash(&GhashKey::new(&cipher), aad, data);
    cipher.apply_counter_mode(nonce, 1, &mut expected);

    if !constant_time_eq(&expected, tag) {
        return false;
    }

    cipher.apply_counter_mode(nonce, 2, data);

    true
}

/// GMAC: the AES-128-GCM tag of the concatenation of `aad_parts` with no
/// plaintext.
pub fn gmac(key: &[u8; 16], nonce: &[u8; 12], aad_parts: &[&[u8]]) -> [u8; 16] {
    let cipher = Aes128::new(key);
    let hash_key = GhashKey::new(&cipher);

    let mut chain = Chain::new();
    let mut aad_length = 0;
    for part in aad_parts {
        chain.update(part, &hash_key);
        aad_length += part.len() as u64;
    }

    let mut tag = hash_key.finish(chain, aad_length, 0);
    cipher.apply_counter_mode(nonce, 1, &mut tag);

    tag
}

#[cfg(test)]
mod tests {
    use super::gcm_open;
    use super::gcm_seal;
    use super::gmac;
    use crate::crypto::tests::decode_hex;

    const KEY_3: &str = "feffe9928665731c6d6a8f9467308308";
    const NONCE_3: &str = "cafebabefacedbaddecaf888";
    const PLAINTEXT_3: &str = concat!(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    );
    const CIPHERTEXT_3: &str = concat!(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
    );

    fn check<const N: usize>(
        key: &str,
        nonce: &str,
        aad: &[u8],
        plaintext: &str,
        ciphertext: &str,
        tag: &str,
    ) {
        let key = decode_hex(key);
        let nonce = decode_hex(nonce);
        let plaintext = decode_hex::<N>(plaintext);
        let ciphertext = decode_hex::<N>(ciphertext);
        let tag = decode_hex(tag);
        let mut data = plaintext;
        assert_eq!(gcm_seal(&key, &nonce, aad, &mut data), Ok(tag));
        assert_eq!(data, ciphertext);
        assert!(gcm_open(&key, &nonce, aad, &mut data, &tag));
        assert_eq!(data, plaintext);
        let mut forged = tag;
        forged[15] ^= 1;
        let mut data = ciphertext;
        assert!(!gcm_open(&key, &nonce, aad, &mut data, &forged));
        assert_eq!(data, ciphertext);
    }

    /// Test cases 1 to 4 of McGrew and Viega, "The Galois/Counter Mode of
    /// Operation (GCM)", revised submission to NIST, Appendix B.
    #[test]
    fn mcgrew_viega_test_cases() {
        let zero_key = "00000000000000000000000000000000";
        let zero_nonce = "000000000000000000000000";
        check::<0>(
            zero_key,
            zero_nonce,
            b"",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a",
        );
        check::<16>(
            zero_key,
            zero_nonce,
            b"",
            "00000000000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        );
        check::<64>(
            KEY_3,
            NONCE_3,
            b"",
            PLAINTEXT_3,
            CIPHERTEXT_3,
            "4d5c2af327cd64a62cf35abd2ba6fab4",
        );
        check::<60>(
            KEY_3,
            NONCE_3,
            &decode_hex::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
            &PLAINTEXT_3[..120],
            &CIPHERTEXT_3[..120],
            "5bc94fbc3221a5db94fae95ae7121a47",
        );
    }

    /// WRITE request and response of Appendix A.1 of "SMB 3.1.1 Encryption
    /// in Windows 10" (Microsoft Open Specifications blog). The AAD is the
    /// transform header from the Nonce field on.
    #[test]
    fn smb_3_1_1_transform() {
        let request = decode_hex::<187>(concat!(
            "fd534d42bd73d97d2bc9001bcafac0fdff5feebcc7d6822d269caf48904c664c",
            "00000000870000000000010025000000001000006ecdd2a7afc7b47763057a04",
            "1b8fd4daffe990b70c9e09d36c084e02d14ef247f8bde38acf6256f8b1d3b56f",
            "77fbdeb312fea5e92cbcc1ed8fb2ebbfaa75e49a4a394bb44576545567c24d4c",
            "014d47c9fbdfdafd2c4f9b72f8d256452620a299f48e29e53d6b61d1c13a19e9",
            "1af013f00d17e3abc2fc3d36c8c1b6b93973253852dbd442e46ee8",
        ));
        let mut data = decode_hex::<135>(concat!(
            "fe534d4240000100000000000900010008000000000000000500000000000000",
            "fffe000001000000250000000010000000000000000000000000000000000000",
            "3100700017000000000000000000000006000000040000000100000004000000",
            "00000000000000007000000000000000536d623320656e6372797074696f6e20",
            "74657374696e67",
        ));
        let key = decode_hex("a2f5e80e5d59103034f32e52f698e5ec");
        let nonce = request[20..32].try_into().unwrap();
        let tag = gcm_seal(&key, nonce, &request[20..52], &mut data).unwrap();
        assert_eq!(tag[..], request[4..20]);
        assert_eq!(data[..], request[52..]);

        let response = decode_hex::<132>(concat!(
            "fd534d42acbe1cb7ed343adf1725ef144d90d4b0e06831dd2e8eb7b400000000",
            "000000005000000000000100250000000010000026bbbf949983a6c1c796559d",
            "0f2c510cb651d1f7b6ac8ded32a2a0b8f2d793a815c6f6b848d69767a215841a",
            "42d400ae6ddb5f0b44173a014973321fdd7950da6179159b82e03c9e18a050ff",
            "0ea1c967",
        ));
        let mut data = [0; 80];
        data.copy_from_slice(&response[52..]);
        let key = decode_hex("748c50868c90f302962a5c35f5f9a8bf");
        let nonce = response[20..32].try_into().unwrap();
        let tag = response[4..20].try_into().unwrap();
        assert!(gcm_open(&key, nonce, &response[20..52], &mut data, tag));
        assert_eq!(
            data,
            decode_hex::<80>(concat!(
                "fe534d4240000100000000000900010001000000000000000500000000000000",
                "fffe000001000000250000000010000000000000000000000000000000000000",
                "11000000170000000000000000000000",
            ))
        );
    }

    /// NIST CAVP gcmEncryptExtIV128.rsp, PTlen = 0, Count = 0 of
    /// AADlen = 128 and AADlen = 720.
    #[test]
    fn nist_gmac() {
        let key = decode_hex("77be63708971c4e240d1cb79e8d77feb");
        let nonce = decode_hex("e0e00f19fed7ba0136a797f3");
        let aad = decode_hex::<16>("7a43ec1d9c0a5a78a0b16533a6213cab");
        let expected = decode_hex("209fcc8d3675ed938e9c7166709dd946");
        assert_eq!(gmac(&key, &nonce, &[&aad]), expected);
        assert_eq!(gmac(&key, &nonce, &[&aad[..3], &[], &aad[3..]]), expected);
        let mut data = [];
        assert_eq!(gcm_seal(&key, &nonce, &aad, &mut data), Ok(expected));

        let key = decode_hex("20b5b6b854e187b058a84d57bc1538b6");
        let nonce = decode_hex("94c1935afc061cbf254b936f");
        let aad = decode_hex::<90>(concat!(
            "ca418e71dbf810038174eaa3719b3fcb80531c7110ad9192d105eeaafa15b819",
            "ac005668752b344ed1b22faf77048baf03dbddb3b47d6b00e95c4f005e0cc9b7",
            "627ccafd3f21b3312aa8d91d3fa0893fe5bff7d44ca46f23afe0",
        ));
        let expected = decode_hex("b37286ebaf4a54e0ffc2a1deafc9f6db");
        for split in 0..=aad.len() {
            let (head, tail) = aad.split_at(split);
            assert_eq!(gmac(&key, &nonce, &[head, tail]), expected, "split {split}");
        }
    }
}
