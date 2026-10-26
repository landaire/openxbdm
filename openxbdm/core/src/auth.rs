//! Lock-mode authentication: the challenge response function, the
//! Diffie-Hellman key exchange, and the session key derived from it.

mod key_exchange;

pub use self::key_exchange::DH_LENGTH;
pub use self::key_exchange::DhValue;
pub use self::key_exchange::dh_mod_exp;

/// Box identifier of a locked console.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxIdentifier(pub u64);

/// Challenge from the banner of a locked console.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce(pub u64);

/// Plaintext user or administrator password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Password(pub u64);

/// Value an `authuser resp=` carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthResponse(pub u64);

/// Key established by a key exchange. Passwords sent after the exchange
/// are XORed with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKey(pub u64);

impl SessionKey {
    /// Derive the key from the shared secret: each 8-byte chunk, read as a
    /// little-endian qword, is mixed into a zero state high word first.
    pub fn derive(shared: &DhValue) -> Self {
        let mut state = [0u32; 2];
        for chunk in shared.0.as_chunks::<8>().0 {
            state = mix(state, words(u64::from_le_bytes(*chunk)));
        }

        Self(qword(state))
    }

    /// Password as sent after the exchange.
    pub const fn encrypt(self, password: Password) -> u64 {
        password.0 ^ self.0
    }
}

/// The response that proves knowledge of `secret` for `challenge`.
pub fn response(secret: Password, challenge: Nonce) -> AuthResponse {
    /// Initial state of the response function.
    const RESPONSE_SEED: u64 = 0x2718_2818_3141_5926;

    let state = mix(words(RESPONSE_SEED), words(secret.0));
    let challenge = mix(state, words(challenge.0));

    AuthResponse(qword(mix(state, challenge)))
}

/// Block function: eight rounds over `block` keyed by `key`.
fn encrypt(key: [u32; 2], block: [u32; 2]) -> [u32; 2] {
    /// Round constants of the block function.
    const ROUND_CONSTANTS: [u32; 8] = [
        0x283c_481d,
        0x9ad8_2aa1,
        0x85a5_e1f9,
        0x1b23_963c,
        0xf70b_4975,
        0xdfdc_02c7,
        0xf291_76fc,
        0x6b04_bd38,
    ];

    let [mut first, mut second] = block;

    for round in 0..8 {
        second ^= (key[1] ^ first)
            .wrapping_add(!first << 6)
            .wrapping_add(first >> 5)
            .wrapping_add(ROUND_CONSTANTS[round]);
        first ^= (key[0] ^ second)
            .wrapping_add(!second >> 5)
            .wrapping_add(second << 6)
            .wrapping_add(ROUND_CONSTANTS[7 - round]);
    }

    [first, second]
}

/// `state = data ^ encrypt(state, data)`.
fn mix(state: [u32; 2], data: [u32; 2]) -> [u32; 2] {
    let encrypted = encrypt(state, data);

    [data[0] ^ encrypted[0], data[1] ^ encrypted[1]]
}

fn words(value: u64) -> [u32; 2] {
    [(value >> 32) as u32, value as u32]
}

fn qword(words: [u32; 2]) -> u64 {
    (u64::from(words[0]) << 32) | u64::from(words[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected values come from executing the monitor's response routine and
    // its session-key absorb routine on these inputs.
    #[test]
    fn response_matches_the_monitor() {
        assert_eq!(
            response(Password(0x1234), Nonce(0x0011_2233_4455_6677)),
            AuthResponse(0x6505_5474_e882_68d6)
        );
        assert_eq!(
            response(
                Password(0x0123_4567_89ab_cdef),
                Nonce(0xfedc_ba98_7654_3210)
            ),
            AuthResponse(0x9d5b_8150_4b4e_d21c)
        );
    }

    #[test]
    fn session_key_matches_the_monitor() {
        let mut shared = [0u8; DH_LENGTH];
        for (index, byte) in shared.iter_mut().enumerate() {
            *byte = index as u8 + 1;
        }

        assert_eq!(
            SessionKey::derive(&DhValue(shared)),
            SessionKey(0x4706_5d78_66bd_9f82)
        );
    }
}
