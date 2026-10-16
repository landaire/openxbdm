//! AES-CMAC (RFC 4493).

use super::aes::Aes128;
use super::chain::Chain;

/// Multiply by x in GF(2^128) with the CMAC bit order.
fn double(block: [u8; 16]) -> [u8; 16] {
    let value = u128::from_be_bytes(block);
    ((value << 1) ^ ((value >> 127) * 0x87)).to_be_bytes()
}

/// Streaming AES-128-CMAC.
#[derive(Clone)]
pub struct AesCmac {
    cipher: Aes128,
    chain: Chain,
}

impl AesCmac {
    /// MAC keyed with `key` over empty input.
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128::new(key),
            chain: Chain::new(),
        }
    }

    /// Append `data` to the input.
    pub fn update(&mut self, data: &[u8]) {
        self.chain.update(data, &self.cipher);
    }

    /// MAC of the input.
    pub fn finalize(mut self) -> [u8; 16] {
        let mut subkey = [0; 16];
        self.cipher.encrypt_block(&mut subkey);
        subkey = double(subkey);
        let used = self.chain.fold();
        if used < 16 {
            self.chain.state[used] ^= 0x80;
            subkey = double(subkey);
        }
        for (byte, key) in self.chain.state.iter_mut().zip(subkey) {
            *byte ^= key;
        }
        self.cipher.encrypt_block(&mut self.chain.state);
        self.chain.state
    }
}

/// AES-128-CMAC under `key` of the concatenation of `parts`.
pub fn aes_cmac(key: &[u8; 16], parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = AesCmac::new(key);
    for part in parts {
        mac.update(part);
    }
    mac.finalize()
}

#[cfg(test)]
mod tests {
    use super::AesCmac;
    use super::aes_cmac;
    use crate::crypto::tests::decode_hex;

    const MESSAGE: &str = concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    );

    #[test]
    fn rfc_4493_examples() {
        let key = decode_hex("2b7e151628aed2a6abf7158809cf4f3c");
        let message = decode_hex::<64>(MESSAGE);
        let cases = [
            (0, "bb1d6929e95937287fa37d129b756746"),
            (16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (40, "dfa66747de9ae63030ca32611497c827"),
            (64, "51f0bebf7e3b9d92fc49741779363cfe"),
        ];
        for (length, expected) in cases {
            let expected = decode_hex::<16>(expected);
            assert_eq!(aes_cmac(&key, &[&message[..length]]), expected);
            // The same input split at every boundary.
            for split in 0..=length {
                let (head, tail) = message[..length].split_at(split);
                assert_eq!(aes_cmac(&key, &[head, tail]), expected, "split {split}");
            }
        }
    }

    /// The final SESSION_SETUP response of the SMB 3.1.1 multichannel
    /// example in "SMB 2 and SMB 3 security in Windows 10: the anatomy of
    /// signing and cryptographic keys" (Microsoft Open Specifications blog),
    /// signed with its SigningKey over the message with a zeroed signature.
    #[test]
    fn smb_3_1_1_session_setup_signature() {
        let mut message = decode_hex::<101>(concat!(
            "fe534d4240000100000000000100800009000000000000000300000000000000",
            "fffe0000000000001900000000100000ebe146da120ba25fc3376a49dfe31bc1",
            "0900000048001d00a11b3019a0030a0100a3120410010000003b453cdc352416",
            "4200000000",
        ));
        let mut signature = [0; 16];
        signature.copy_from_slice(&message[48..64]);
        message[48..64].fill(0);
        let mut mac = AesCmac::new(&decode_hex("73fe7a9a77bef0bde49c650d8ccb5f76"));
        mac.update(&message[..64]);
        mac.update(&message[64..]);
        assert_eq!(mac.finalize(), signature);
    }
}
