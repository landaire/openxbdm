//! SHA-512 (FIPS 180-4).

const INITIAL: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const ROUND_CONSTANTS: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

/// Streaming SHA-512 hasher.
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    block: [u8; 128],
    used: usize,
    length: u64,
}

impl Sha512 {
    /// Hasher over empty input.
    pub const fn new() -> Self {
        Self {
            state: INITIAL,
            block: [0; 128],
            used: 0,
            length: 0,
        }
    }

    /// Append `data` to the input.
    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.used > 0 {
            let take = data.len().min(128 - self.used);
            let (head, rest) = data.split_at(take);
            self.block[self.used..self.used + take].copy_from_slice(head);
            self.used += take;
            data = rest;
            if self.used < 128 {
                return;
            }
            compress(&mut self.state, &self.block);
            self.used = 0;
        }
        while let Some((block, rest)) = data.split_first_chunk::<128>() {
            compress(&mut self.state, block);
            data = rest;
        }
        self.block[..data.len()].copy_from_slice(data);
        self.used = data.len();
    }

    /// Digest of the input.
    pub fn finalize(mut self) -> [u8; 64] {
        self.block[self.used] = 0x80;
        self.block[self.used + 1..].fill(0);
        if self.used >= 112 {
            compress(&mut self.state, &self.block);
            self.block.fill(0);
        }
        // The 128-bit bit count; byte counts below 2^64 reach only the low
        // 67 bits.
        self.block[112..].copy_from_slice(&(u128::from(self.length) * 8).to_be_bytes());
        compress(&mut self.state, &self.block);
        let mut digest = [0; 64];
        for (bytes, word) in digest.as_chunks_mut::<8>().0.iter_mut().zip(self.state) {
            *bytes = word.to_be_bytes();
        }
        digest
    }
}

/// SHA-512 digest of `data`.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

/// The message schedule is kept as a 16-word ring to bound the frame size.
fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut schedule = [0u64; 16];
    for (word, bytes) in schedule.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*bytes);
    }
    let mut v = *state;
    for (round, constant) in ROUND_CONSTANTS.iter().enumerate() {
        let slot = round % 16;
        if round >= 16 {
            let w15 = schedule[(round + 1) % 16];
            let w2 = schedule[(round + 14) % 16];
            let s0 = w15.rotate_right(1) ^ w15.rotate_right(8) ^ (w15 >> 7);
            let s1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);
            schedule[slot] = schedule[slot]
                .wrapping_add(s0)
                .wrapping_add(schedule[(round + 9) % 16])
                .wrapping_add(s1);
        }
        let [a, b, c, d, e, f, g, h] = v;
        let sum1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let choice = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(sum1)
            .wrapping_add(choice)
            .wrapping_add(*constant)
            .wrapping_add(schedule[slot]);
        let sum0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = sum0.wrapping_add(majority);
        v = [
            temp1.wrapping_add(temp2),
            a,
            b,
            c,
            d.wrapping_add(temp1),
            e,
            f,
            g,
        ];
    }
    for (word, value) in state.iter_mut().zip(v) {
        *word = word.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::Sha512;
    use super::sha512;
    use crate::crypto::tests::decode_hex;

    #[test]
    fn fips_180_examples() {
        assert_eq!(
            sha512(b"abc"),
            decode_hex::<64>(concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ))
        );
        assert_eq!(
            sha512(b""),
            decode_hex::<64>(concat!(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ))
        );
        let message = concat!(
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn",
            "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        );
        let expected = decode_hex::<64>(concat!(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018",
            "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ));
        assert_eq!(sha512(message.as_bytes()), expected);
        let mut hasher = Sha512::new();
        for byte in message.as_bytes() {
            hasher.update(core::slice::from_ref(byte));
        }
        assert_eq!(hasher.finalize(), expected);
    }

    /// The first preauthentication integrity step of Appendix A.1 of "SMB
    /// 3.1.1 Encryption in Windows 10" (Microsoft Open Specifications
    /// blog): the zero hash value followed by the NEGOTIATE request.
    #[test]
    fn smb_3_1_1_preauth_integrity() {
        let request = decode_hex::<174>(concat!(
            "fe534d4240000100000000000000010000000000000000000000000000000000",
            "fffe000000000000000000000000000000000000000000000000000000000000",
            "2400050001000000660000004f0d7fa009f5b246b2ef62551d7d7c0970000000",
            "020000000202100200030203110300000100260000000000010020000100d170",
            "9d7196e1bd0b6ebf95213d76553435763514392649fd6f216ed8bf269cd80000",
            "0200060000000000020002000100",
        ));
        let mut hasher = Sha512::new();
        hasher.update(&[0; 64]);
        hasher.update(&request);
        assert_eq!(
            hasher.finalize(),
            decode_hex::<64>(concat!(
                "550442daf311412870ad9e58e602b0312d61328d6b1ac28f22af46d6ea581f23",
                "a9bfabe0cc0411976bf3f9da23d3433352cb48cf00b8659bc1a3695e1b1a52a8",
            ))
        );
    }
}
