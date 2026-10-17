//! SMB 3 key derivation: NIST SP 800-108 counter mode with HMAC-SHA256,
//! r = 32 and L = 128 (MS-SMB2 3.1.4.2).

use super::hmac::HmacSha256;

/// The 128-bit key derived from `key` for `label` and `context`. SMB
/// labels and SMB 3.0 contexts include their terminating NUL.
pub fn smb3_kdf(key: &[u8; 16], label: &[u8], context: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new(key);
    mac.update(&1u32.to_be_bytes());
    mac.update(label);
    mac.update(&[0]);
    mac.update(context);
    mac.update(&128u32.to_be_bytes());

    let mut derived = [0; 16];
    derived.copy_from_slice(&mac.finalize()[..16]);

    derived
}

#[cfg(test)]
mod tests {
    use super::smb3_kdf;
    use crate::crypto::tests::decode_hex;

    /// "SMB 2 and SMB 3 security in Windows 10: the anatomy of signing and
    /// cryptographic keys" (Microsoft Open Specifications blog), appendix
    /// key derivation examples. Encryption and decryption keys are the
    /// client's.
    #[test]
    fn smb_3_0_example() {
        let session_key = decode_hex("7cd451825d0450d235424e44ba6e78cc");
        let cases: [(&[u8], &[u8], &str); 4] = [
            (
                b"SMB2AESCMAC\0",
                b"SmbSign\0",
                "0b7e9c5cac36c0f6ea9ab275298cedce",
            ),
            (
                b"SMB2AESCCM\0",
                b"ServerIn \0",
                "fad27796665b313ebb578f388632b4f7",
            ),
            (
                b"SMB2AESCCM\0",
                b"ServerOut\0",
                "b0f0427f7ceb416d1d9dcc0cd4f99447",
            ),
            (
                b"SMB2APP\0",
                b"SmbRpc\0",
                "bb23a4575aa26c721af525af15a87b4f",
            ),
        ];
        for (label, context, expected) in cases {
            assert_eq!(
                smb3_kdf(&session_key, label, context),
                decode_hex::<16>(expected)
            );
        }
    }

    #[test]
    fn smb_3_1_1_example() {
        let session_key = decode_hex("270e1ba896585eeb7af3472d3b4c75a7");
        let preauth_hash = decode_hex::<64>(concat!(
            "0dd13628cc3ed218ef9df9772d436d0887ab9814bfae63a80aa845f36909db79",
            "28622dddad522d9751640a459762c5a9d6bb084cbb3ce6bdadef5d5bce3c6c01",
        ));
        let cases: [(&[u8], &str); 4] = [
            (b"SMBSigningKey\0", "73fe7a9a77bef0bde49c650d8ccb5f76"),
            (b"SMBC2SCipherKey\0", "629bcbc54422a0f572b97f45989b6073"),
            (b"SMBS2CCipherKey\0", "e2af0dcefac68da71a0dfbd0d1350d74"),
            (b"SMBAppKey\0", "6d7ad7954e9ec61e907b4d473dc178ff"),
        ];
        for (label, expected) in cases {
            assert_eq!(
                smb3_kdf(&session_key, label, &preauth_hash),
                decode_hex::<16>(expected)
            );
        }
    }
}
