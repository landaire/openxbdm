//! MD4 (RFC 1320) and MD5 (RFC 1321).

use super::engine::Engine;

const INITIAL: [u32; 8] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0,
    0,
    0,
    0,
];

/// Streaming MD4 hasher.
#[derive(Clone)]
pub struct Md4(Engine);

impl Md4 {
    /// Hasher over empty input.
    pub const fn new() -> Self {
        Self(Engine::new(INITIAL, md4_compress, false))
    }

    /// Append `data` to the input.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Digest of the input.
    pub fn finalize(mut self) -> [u8; 16] {
        let mut digest = [0; 16];
        self.0.finish(&mut digest);
        digest
    }
}

/// MD4 digest of `data`.
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(data);
    hasher.finalize()
}

/// Streaming MD5 hasher.
#[derive(Clone)]
pub struct Md5(Engine);

impl Md5 {
    /// Hasher over empty input.
    pub const fn new() -> Self {
        Self(Engine::new(INITIAL, md5_compress, false))
    }

    /// Append `data` to the input.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Digest of the input.
    pub fn finalize(mut self) -> [u8; 16] {
        let mut digest = [0; 16];
        self.0.finish(&mut digest);
        digest
    }

    pub(super) const fn engine() -> Engine {
        Self::new().0
    }
}

/// MD5 digest of `data`.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize()
}

fn load_words(block: &[u8; 64]) -> [u32; 16] {
    let mut words = [0; 16];
    for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    words
}

/// Each step updates `v[0]` from `v[1..4]`, then the registers rotate so
/// that the next step updates the previous `v[3]` (RFC 1320 and RFC 1321
/// order ABCD, DABC, CDAB, BCDA).
fn md4_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let x = load_words(block);
    let mut v = [state[0], state[1], state[2], state[3]];
    for step in 0..48 {
        let index = step % 16;
        let (b, c, d) = (v[1], v[2], v[3]);
        let (mixed, word, constant, shifts) = match step / 16 {
            0 => ((b & c) | (!b & d), index, 0, [3, 7, 11, 19]),
            1 => (
                (b & c) | (b & d) | (c & d),
                (index % 4) * 4 + index / 4,
                0x5a82_7999,
                [3, 5, 9, 13],
            ),
            _ => (
                b ^ c ^ d,
                (index & 1) << 3 | (index & 2) << 1 | (index & 4) >> 1 | (index & 8) >> 3,
                0x6ed9_eba1,
                [3, 9, 11, 15],
            ),
        };
        let updated = v[0]
            .wrapping_add(mixed)
            .wrapping_add(x[word])
            .wrapping_add(constant)
            .rotate_left(shifts[index % 4]);
        v = [d, updated, b, c];
    }
    for (word, value) in state.iter_mut().zip(v) {
        *word = word.wrapping_add(value);
    }
}

const MD5_SINES: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

const MD5_SHIFTS: [[u32; 4]; 4] = [
    [7, 12, 17, 22],
    [5, 9, 14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21],
];

fn md5_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let x = load_words(block);
    let mut v = [state[0], state[1], state[2], state[3]];
    for (step, sine) in MD5_SINES.iter().enumerate() {
        let round = step / 16;
        let (b, c, d) = (v[1], v[2], v[3]);
        let (mixed, word) = match round {
            0 => ((b & c) | (!b & d), step),
            1 => ((b & d) | (c & !d), 5 * step + 1),
            2 => (b ^ c ^ d, 3 * step + 5),
            _ => (c ^ (b | !d), 7 * step),
        };
        let updated = v[0]
            .wrapping_add(mixed)
            .wrapping_add(x[word % 16])
            .wrapping_add(*sine)
            .rotate_left(MD5_SHIFTS[round][step % 4])
            .wrapping_add(b);
        v = [d, updated, b, c];
    }
    for (word, value) in state.iter_mut().zip(v) {
        *word = word.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::Md5;
    use super::md4;
    use super::md5;
    use crate::crypto::tests::decode_hex as decode;

    const RFC_INPUTS: [&[u8]; 7] = [
        b"",
        b"a",
        b"abc",
        b"message digest",
        b"abcdefghijklmnopqrstuvwxyz",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    ];

    #[test]
    fn md4_rfc1320_suite() {
        let expected = [
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "bde52cb31de33e46245e05fbdbd6fb24",
            "a448017aaf21d8525fc10ae87aa6729d",
            "d9130a8164549fe818874806e1c7014b",
            "d79e1c308aa5bbcdeea8ed63df412da9",
            "043f8582f241db351ce627e153e7f0e4",
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ];
        for (input, digest) in RFC_INPUTS.iter().zip(expected) {
            assert_eq!(md4(input), decode::<16>(digest));
        }
    }

    #[test]
    fn md5_rfc1321_suite() {
        let expected = [
            "d41d8cd98f00b204e9800998ecf8427e",
            "0cc175b9c0f1b6a831c399e269772661",
            "900150983cd24fb0d6963f7d28e17f72",
            "f96b697d7cb7938d525a2f31aaf161d0",
            "c3fcd3d76192e4007dfb496cca67e13b",
            "d174ab98d277d9f5a5611c2c9f419d9f",
            "57edf4a22be3c955ac49da2e2107b67a",
        ];
        for (input, digest) in RFC_INPUTS.iter().zip(expected) {
            assert_eq!(md5(input), decode::<16>(digest));
        }
    }

    #[test]
    fn md5_split_updates_match_one_shot() {
        let input = RFC_INPUTS[6];
        for split in [1, 55, 56, 63, 64, 65] {
            let mut hasher = Md5::new();
            hasher.update(&input[..split]);
            hasher.update(&input[split..]);
            assert_eq!(hasher.finalize(), md5(input), "split {split}");
        }
    }
}
