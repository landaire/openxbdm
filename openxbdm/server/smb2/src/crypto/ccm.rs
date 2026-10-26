//! AES-128-CCM (RFC 3610) with the SMB 3 parameters: 11-byte nonce, 16-byte
//! tag (M = 16), and 4-byte length field (L = 4).

use super::MessageTooLong;
use super::aes::Aes128;
use super::chain::Chain;
use super::constant_time_eq;

fn counter_prefix(nonce: &[u8; 11]) -> [u8; 12] {
    /// The counter blocks carry L - 1 alone.
    const COUNTER_FLAGS: u8 = 3;

    let mut prefix = [COUNTER_FLAGS; 12];
    prefix[1..].copy_from_slice(nonce);

    prefix
}

/// CBC-MAC over B0, the length-prefixed `aad`, and the plaintext `data`.
fn cbc_mac(cipher: &Aes128, nonce: &[u8; 11], aad: &[u8], data: &[u8], length: u32) -> [u8; 16] {
    /// Flags byte of B0 without Adata: (M - 2) / 2 in bits 3-5, L - 1 in
    /// bits 0-2.
    const B0_FLAGS: u8 = (7 << 3) | 3;

    let mut chain = Chain::new();

    let mut b0 = [B0_FLAGS; 16];
    if !aad.is_empty() {
        b0[0] |= 0x40;
    }
    b0[1..12].copy_from_slice(nonce);
    b0[12..].copy_from_slice(&length.to_be_bytes());
    chain.update(&b0, cipher);

    if !aad.is_empty() {
        let aad_length = aad.len() as u64;
        let mut encoded = [0; 10];
        let encoded = if aad_length < 0xff00 {
            encoded[..2].copy_from_slice(&(aad_length as u16).to_be_bytes());
            &encoded[..2]
        } else if aad_length <= u64::from(u32::MAX) {
            encoded[..2].copy_from_slice(&[0xff, 0xfe]);
            encoded[2..6].copy_from_slice(&(aad_length as u32).to_be_bytes());
            &encoded[..6]
        } else {
            encoded[..2].copy_from_slice(&[0xff, 0xff]);
            encoded[2..].copy_from_slice(&aad_length.to_be_bytes());
            &encoded[..]
        };
        chain.update(encoded, cipher);
        chain.update(aad, cipher);
        chain.pad(cipher);
    }

    chain.update(data, cipher);
    chain.pad(cipher);

    chain.state
}

/// Encrypt `data` in place with AES-128-CCM and return the tag. `data`
/// must be shorter than 2^32 bytes.
pub fn ccm_seal(
    key: &[u8; 16],
    nonce: &[u8; 11],
    aad: &[u8],
    data: &mut [u8],
) -> Result<[u8; 16], MessageTooLong> {
    let length = u32::try_from(data.len()).map_err(|_| MessageTooLong)?;
    let cipher = Aes128::new(key);
    let prefix = counter_prefix(nonce);

    let mut tag = cbc_mac(&cipher, nonce, aad, data, length);
    cipher.apply_counter_mode(&prefix, 0, &mut tag);
    cipher.apply_counter_mode(&prefix, 1, data);

    Ok(tag)
}

/// Decrypt `data` in place and verify `tag` over the plaintext and `aad`.
/// CCM authenticates the plaintext, so on failure `data` is zeroed.
pub fn ccm_open(
    key: &[u8; 16],
    nonce: &[u8; 11],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    let Ok(length) = u32::try_from(data.len()) else {
        return false;
    };

    let cipher = Aes128::new(key);
    let prefix = counter_prefix(nonce);

    cipher.apply_counter_mode(&prefix, 1, data);
    let mut expected = cbc_mac(&cipher, nonce, aad, data, length);
    cipher.apply_counter_mode(&prefix, 0, &mut expected);

    if constant_time_eq(&expected, tag) {
        true
    } else {
        data.fill(0);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::ccm_open;
    use super::ccm_seal;
    use crate::crypto::tests::decode_hex;

    /// Seal `plaintext` with the nonce and AAD of the SMB transform header
    /// at the start of `transformed` and compare with its signature and
    /// ciphertext, then open it again.
    fn check_transform(key: &str, transformed: &[u8], plaintext: &mut [u8]) {
        let key = decode_hex(key);
        let nonce = transformed[20..31].try_into().unwrap();
        let aad = &transformed[20..52];
        let tag = ccm_seal(&key, nonce, aad, plaintext).unwrap();
        assert_eq!(tag[..], transformed[4..20]);
        assert_eq!(plaintext, &transformed[52..]);
        assert!(ccm_open(&key, nonce, aad, plaintext, &tag));
        let mut forged = tag;
        forged[0] ^= 0x80;
        let mut ciphertext = [0; 256];
        let ciphertext = &mut ciphertext[..plaintext.len()];
        ciphertext.copy_from_slice(&transformed[52..]);
        assert!(!ccm_open(&key, nonce, aad, ciphertext, &forged));
        assert!(ciphertext.iter().all(|&byte| byte == 0));
    }

    /// WRITE request of the test vector in "Encryption in SMB 3.0: A
    /// protocol perspective" (Microsoft Open Specifications blog).
    #[test]
    fn smb_3_0_transform() {
        let transformed = decode_hex::<187>(concat!(
            "fd534d4281a286535415445dae393921e44fa42e66e69a111892584fb5ed524a",
            "744da3ee87000000000001001100001400e4080025c8fee16605a437832d1cd5",
            "2da9f4645333482a175fe5384563f45fcdafaef38bc62ba4d5c62897996625a4",
            "4c29be5658de2e6117585779e7b59ffd971278d08580d7fa899e410e910eabf5",
            "aa1db43050b33b49182637759ac15d84bfcdf5b6b238993c0f4cf4d6012023f6",
            "c627297075d84b7803912d0a9639634453595ef3e33ffe4e7ac2ab",
        ));
        let mut plaintext = decode_hex::<135>(concat!(
            "fe534d4240000100000000000900400008000000000000000400000000000000",
            "fffe0000010000001100001400e4080000000000000000000000000000000000",
            "3100700017000000000000000000000015010000390000020100000039020000",
            "00000000000000007000000000000000536d623320656e6372797074696f6e20",
            "74657374696e67",
        ));
        check_transform(
            "261b72350558f2e9dcf613070383edbf",
            &transformed,
            &mut plaintext,
        );
    }

    /// WRITE request of Appendix A.2 of "SMB 3.1.1 Encryption in Windows
    /// 10" (Microsoft Open Specifications blog).
    #[test]
    fn smb_3_1_1_transform() {
        let transformed = decode_hex::<187>(concat!(
            "fd534d42e89551d666dab8993488f5a97103116c9f6f1eaad7e9f24aacd38f00",
            "000000008700000000000100210000000010000056a74778199a9d2b6e9c3a37",
            "6fd88d27680694fed253a313beb07381ae8689f973acdb8d716e4477803bce53",
            "a92e1b81fa3e965ad9af2c89c08ce66a344664453b8fc88118edc9814cf58e92",
            "aa465e6efb09958a9fdad96fbd55b36a710c30d5e7c64ad7b9449f9f17edd024",
            "fe8ba79154f340a82740d1d5180c69b0a2de6a4ba893bd55d3210e",
        ));
        let mut plaintext = decode_hex::<135>(concat!(
            "fe534d4240000100000000000900010008000000000000000500000000000000",
            "fffe000001000000210000000010000000000000000000000000000000000000",
            "3100700017000000000000000000000005000000040000000100000004000000",
            "00000000000000007000000000000000536d623320656e6372797074696f6e20",
            "74657374696e67",
        ));
        check_transform(
            "dfaaa31aae40a2485d47ac4df09fda1d",
            &transformed,
            &mut plaintext,
        );
    }

    /// NIST CAVP VNT128.rsp (CCM, Alen = 32, Plen = 24, Tlen = 16), Nlen =
    /// 11, Count = 40 and 41. CT is the ciphertext followed by the tag.
    #[test]
    fn nist_variable_nonce() {
        let key = decode_hex("e6ab9e70a4fb51b01c2e262233e64c0d");
        let cases = [
            (
                "74e689eb5af9441dd690a6",
                "42f6518ee0fbe42f28e13b4bb2eb60517b37c9744394d9143393a879c3e107c7",
                "ba15916733550d7aa82b2f6b117cd3f54c83ddc16cd0288a",
                "dcc151443288f35d39ed8fae6f0ce1d1eb656f4f7fd65c0b16f322ce85d7c54e71ac560fd4da9651",
            ),
            (
                "eb118fb41284bfcb1bc338",
                "b5a6067fbac46578cfc8d3fe04108588c9de077eb009249374f205553bba9d02",
                "863da00c7accf45418d47c1eda72338734dcc49cd599f328",
                "d64de7a56146b971e21bf5784d67bab32dd837cfb81591da4a0177883346dc896eb39e8a32bc1393",
            ),
        ];
        for (nonce, aad, payload, expected) in cases {
            let nonce = decode_hex(nonce);
            let aad = decode_hex::<32>(aad);
            let expected = decode_hex::<40>(expected);
            let mut data = decode_hex::<24>(payload);
            let tag = ccm_seal(&key, &nonce, &aad, &mut data).unwrap();
            assert_eq!(data[..], expected[..24]);
            assert_eq!(tag[..], expected[24..]);
            assert!(ccm_open(&key, &nonce, &aad, &mut data, &tag));
            assert_eq!(data, decode_hex::<24>(payload));
        }
    }
}
