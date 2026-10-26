//! RC4 stream cipher.

/// RC4 keystream state.
#[derive(Clone)]
pub struct Rc4 {
    permutation: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Cipher keyed with `key`. An empty key leaves the identity
    /// permutation.
    pub fn new(key: &[u8]) -> Self {
        let mut permutation = [0u8; 256];
        for (slot, value) in permutation.iter_mut().zip(0u8..=255) {
            *slot = value;
        }

        let mut j = 0u8;
        for (i, &key_byte) in (0..256).zip(key.iter().cycle()) {
            j = j.wrapping_add(permutation[i]).wrapping_add(key_byte);
            permutation.swap(i, usize::from(j));
        }

        Self {
            permutation,
            i: 0,
            j: 0,
        }
    }

    /// XOR the next keystream bytes into `data`.
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            let at_i = self.permutation[usize::from(self.i)];
            self.j = self.j.wrapping_add(at_i);
            let at_j = self.permutation[usize::from(self.j)];
            self.permutation[usize::from(self.i)] = at_j;
            self.permutation[usize::from(self.j)] = at_i;
            *byte ^= self.permutation[usize::from(at_i.wrapping_add(at_j))];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rc4;
    use crate::crypto::tests::decode_hex;

    #[test]
    fn rfc6229_40_bit_key() {
        let mut cipher = Rc4::new(&[0x01, 0x02, 0x03, 0x04, 0x05]);
        let mut stream = [0u8; 32];
        cipher.apply(&mut stream);
        assert_eq!(
            stream,
            decode_hex::<32>("b2396305f03dc027ccc3524a0a1118a86982944f18fc82d589c403a47a0d0919")
        );
    }

    #[test]
    fn rfc6229_128_bit_key() {
        let key = decode_hex::<16>("0102030405060708090a0b0c0d0e0f10");
        let mut cipher = Rc4::new(&key);
        let mut stream = [0u8; 16];
        cipher.apply(&mut stream);
        assert_eq!(stream, decode_hex::<16>("9ac7cc9a609d1ef7b2932899cde41b97"));
    }
}
