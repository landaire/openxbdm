//! AES-128 encryption (FIPS 197).
//!
//! Byte-oriented with a 256-byte S-box and no round tables. S-box lookups
//! are indexed by secret data, so the cipher is not constant-time against
//! an observer of cache timing on the same machine.

const SBOX: [u8; 256] = sbox();

/// Walks the multiplicative group of GF(2^8) with generator 3, tracking
/// the inverse of each element, and applies the affine transformation.
const fn sbox() -> [u8; 256] {
    let mut table = [0x63; 256];
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    loop {
        p ^= (p << 1) ^ xtime_carry(p);
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        table[p as usize] =
            q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4) ^ 0x63;
        if p == 1 {
            return table;
        }
    }
}

/// Reduction term of doubling `x` in GF(2^8).
const fn xtime_carry(x: u8) -> u8 {
    (x >> 7) * 0x1b
}

fn xtime(x: u8) -> u8 {
    (x << 1) ^ xtime_carry(x)
}

fn add_round_key(block: &mut [u8; 16], key: &[u8; 16]) {
    for (byte, key) in block.iter_mut().zip(key) {
        *byte ^= key;
    }
}

/// AES-128 block cipher with an expanded key schedule.
#[derive(Clone)]
pub struct Aes128 {
    round_keys: [[u8; 16]; 11],
}

impl Aes128 {
    /// Cipher keyed with `key`.
    pub fn new(key: &[u8; 16]) -> Self {
        let mut round_keys = [*key; 11];
        let mut rcon = 1;
        for round in 1..11 {
            let previous = round_keys[round - 1];
            let mut word = [
                SBOX[usize::from(previous[13])] ^ rcon,
                SBOX[usize::from(previous[14])],
                SBOX[usize::from(previous[15])],
                SBOX[usize::from(previous[12])],
            ];
            rcon = xtime(rcon);
            for (index, (out, byte)) in round_keys[round].iter_mut().zip(previous).enumerate() {
                word[index % 4] ^= byte;
                *out = word[index % 4];
            }
        }
        Self { round_keys }
    }

    /// Encrypt one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        add_round_key(block, &self.round_keys[0]);
        for (round, key) in self.round_keys.iter().enumerate().skip(1) {
            // SubBytes and ShiftRows; byte 4c+r of the column-major state
            // takes row r from column c+r.
            let state = *block;
            for (index, byte) in block.iter_mut().enumerate() {
                *byte = SBOX[usize::from(state[(index * 5) % 16])];
            }
            if round < 10 {
                for column in block.as_chunks_mut::<4>().0 {
                    let [a0, a1, a2, a3] = *column;
                    let all = a0 ^ a1 ^ a2 ^ a3;
                    *column = [
                        a0 ^ all ^ xtime(a0 ^ a1),
                        a1 ^ all ^ xtime(a1 ^ a2),
                        a2 ^ all ^ xtime(a2 ^ a3),
                        a3 ^ all ^ xtime(a3 ^ a0),
                    ];
                }
            }
            add_round_key(block, key);
        }
    }

    /// XOR `data` with the keystream of counter blocks `prefix || counter`,
    /// `prefix || counter + 1`, and so on (32-bit big-endian counter).
    pub(super) fn apply_counter_mode(&self, prefix: &[u8; 12], counter: u32, data: &mut [u8]) {
        let mut block = [0; 16];
        for (index, chunk) in data.chunks_mut(16).enumerate() {
            block[..12].copy_from_slice(prefix);
            block[12..].copy_from_slice(&counter.wrapping_add(index as u32).to_be_bytes());
            self.encrypt_block(&mut block);
            for (byte, key) in chunk.iter_mut().zip(block) {
                *byte ^= key;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Aes128;
    use crate::crypto::tests::decode_hex;

    #[test]
    fn fips_197_examples() {
        // FIPS 197 Appendix B.
        let mut block = decode_hex::<16>("3243f6a8885a308d313198a2e0370734");
        Aes128::new(&decode_hex("2b7e151628aed2a6abf7158809cf4f3c")).encrypt_block(&mut block);
        assert_eq!(block, decode_hex("3925841d02dc09fbdc118597196a0b32"));
        // FIPS 197 Appendix C.1.
        let mut block = decode_hex::<16>("00112233445566778899aabbccddeeff");
        Aes128::new(&decode_hex("000102030405060708090a0b0c0d0e0f")).encrypt_block(&mut block);
        assert_eq!(block, decode_hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }
}
