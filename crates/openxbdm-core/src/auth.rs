//! Lock-mode authentication: the challenge response function, the
//! Diffie-Hellman key exchange, and the session key derived from it.

/// Bytes of a key exchange value on the wire.
pub const DH_LENGTH: usize = 0x60;

const LIMBS: usize = DH_LENGTH / 4;

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

/// Initial state of the response function.
const RESPONSE_SEED: u64 = 0x2718_2818_3141_5926;

/// Group modulus in wire layout (little-endian 768-bit number).
const MODULUS: [u8; DH_LENGTH] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x34, 0xc2, 0x68, 0x21, 0xa2, 0xda, 0x0f, 0xc9,
    0xd1, 0x1c, 0xdc, 0x80, 0x8b, 0x62, 0xc6, 0xc4, 0x74, 0xcc, 0x67, 0x8a, 0x08, 0x4e, 0x02, 0x29,
    0x22, 0x9b, 0x13, 0x3b, 0xa6, 0xbe, 0x0b, 0x02, 0xdd, 0x04, 0x34, 0x8e, 0x79, 0x08, 0x4a, 0x51,
    0x1b, 0x43, 0x3a, 0xcd, 0xb3, 0x19, 0x95, 0xef, 0x37, 0x14, 0x5f, 0xf2, 0x6d, 0x0a, 0x2b, 0x30,
    0x45, 0xc2, 0x51, 0x6d, 0x6d, 0x35, 0xe1, 0x4f, 0xc6, 0x7e, 0x5e, 0x62, 0x76, 0xb5, 0x85, 0xe4,
    0x20, 0x36, 0x3a, 0xa6, 0xe9, 0x42, 0x4c, 0xf4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// Offset of the only nonzero generator byte (value 2) in wire layout.
const GENERATOR_BYTE: usize = 0x58;

/// A group element or exponent of the key exchange, in wire layout.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DhValue(pub [u8; DH_LENGTH]);

impl DhValue {
    /// The group generator.
    pub const fn generator() -> Self {
        let mut bytes = [0; DH_LENGTH];
        bytes[GENERATOR_BYTE] = 2;
        Self(bytes)
    }

    /// The group modulus.
    pub const fn modulus() -> Self {
        Self(MODULUS)
    }
}

impl core::fmt::Debug for DhValue {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// `base ^ exponent mod modulus`, with `None` selecting the generator.
pub fn dh_mod_exp(base: Option<&DhValue>, exponent: &DhValue) -> DhValue {
    let modulus = limbs(&MODULUS);
    let base = base.copied().unwrap_or_else(DhValue::generator);
    let mut base = limbs(&base.0);
    // Every 768-bit value is below twice the modulus.
    if !less_than(&base, &modulus) {
        subtract(&mut base, &modulus);
    }
    let factor = montgomery_factor(&modulus);

    // R mod m, then doubled 768 times: R^2 mod m.
    let mut one = [0u32; LIMBS];
    subtract(&mut one, &modulus);
    let mut squared = one;
    for _ in 0..LIMBS * 32 {
        let carry = shift_left(&mut squared);
        if carry || !less_than(&squared, &modulus) {
            subtract(&mut squared, &modulus);
        }
    }

    let base = multiply(&base, &squared, &modulus, factor);
    let mut result = one;
    let exponent = limbs(&exponent.0);
    for bit in (0..LIMBS * 32).rev() {
        result = multiply(&result, &result, &modulus, factor);
        if exponent[bit / 32] >> (bit % 32) & 1 != 0 {
            result = multiply(&result, &base, &modulus, factor);
        }
    }
    let mut unit = [0u32; LIMBS];
    unit[0] = 1;
    let result = multiply(&result, &unit, &modulus, factor);

    let mut output = [0u8; DH_LENGTH];
    for (chunk, limb) in output.as_chunks_mut::<4>().0.iter_mut().zip(result) {
        *chunk = limb.to_le_bytes();
    }
    DhValue(output)
}

fn limbs(bytes: &[u8; DH_LENGTH]) -> [u32; LIMBS] {
    let mut limbs = [0u32; LIMBS];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *limb = u32::from_le_bytes(*chunk);
    }
    limbs
}

fn less_than(left: &[u32; LIMBS], right: &[u32; LIMBS]) -> bool {
    left.iter().rev().cmp(right.iter().rev()) == core::cmp::Ordering::Less
}

/// `value -= other` modulo 2^768.
fn subtract(value: &mut [u32; LIMBS], other: &[u32; LIMBS]) {
    let mut borrow = 0u64;
    for (limb, &other) in value.iter_mut().zip(other) {
        let difference = u64::from(*limb)
            .wrapping_sub(u64::from(other))
            .wrapping_sub(borrow);
        *limb = difference as u32;
        borrow = difference >> 63;
    }
}

/// Shift left one bit; returns the bit shifted out.
fn shift_left(value: &mut [u32; LIMBS]) -> bool {
    let mut carry = 0;
    for limb in value.iter_mut() {
        let next = *limb >> 31;
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    carry != 0
}

/// `-m^-1 mod 2^32` for odd `m`.
fn montgomery_factor(modulus: &[u32; LIMBS]) -> u32 {
    let low = modulus[0];
    let mut inverse = low;
    for _ in 0..4 {
        inverse = inverse.wrapping_mul(2u32.wrapping_sub(low.wrapping_mul(inverse)));
    }
    inverse.wrapping_neg()
}

/// Montgomery product `a * b / R mod m` for `a, b < m`.
fn multiply(
    a: &[u32; LIMBS],
    b: &[u32; LIMBS],
    modulus: &[u32; LIMBS],
    factor: u32,
) -> [u32; LIMBS] {
    let mut total = [0u32; LIMBS + 2];
    for &digit in a {
        let mut carry = 0u64;
        for (slot, &other) in total.iter_mut().zip(b) {
            let sum = u64::from(*slot) + u64::from(digit) * u64::from(other) + carry;
            *slot = sum as u32;
            carry = sum >> 32;
        }
        let sum = u64::from(total[LIMBS]) + carry;
        total[LIMBS] = sum as u32;
        total[LIMBS + 1] = (sum >> 32) as u32;

        let quotient = total[0].wrapping_mul(factor);
        let mut carry = (u64::from(total[0]) + u64::from(quotient) * u64::from(modulus[0])) >> 32;
        for index in 1..LIMBS {
            let sum =
                u64::from(total[index]) + u64::from(quotient) * u64::from(modulus[index]) + carry;
            total[index - 1] = sum as u32;
            carry = sum >> 32;
        }
        let sum = u64::from(total[LIMBS]) + carry;
        total[LIMBS - 1] = sum as u32;
        total[LIMBS] = total[LIMBS + 1] + (sum >> 32) as u32;
    }
    let mut result = [0u32; LIMBS];
    result.copy_from_slice(&total[..LIMBS]);
    if total[LIMBS] != 0 || !less_than(&result, modulus) {
        subtract(&mut result, modulus);
    }
    result
}

/// Block function: eight rounds over `block` keyed by `key`.
fn encrypt(key: [u32; 2], block: [u32; 2]) -> [u32; 2] {
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

/// The response that proves knowledge of `secret` for `challenge`.
pub fn response(secret: Password, challenge: Nonce) -> AuthResponse {
    let state = mix(words(RESPONSE_SEED), words(secret.0));
    let challenge = mix(state, words(challenge.0));
    AuthResponse(qword(mix(state, challenge)))
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn value(seed: u8) -> DhValue {
        let mut bytes = [0u8; DH_LENGTH];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(0x9d).wrapping_add(seed);
        }
        DhValue(bytes)
    }

    #[test]
    fn exchange_agrees() {
        let first = value(3);
        let second = value(0x51);
        let first_public = dh_mod_exp(None, &first);
        let second_public = dh_mod_exp(None, &second);
        assert_eq!(
            dh_mod_exp(Some(&second_public), &first),
            dh_mod_exp(Some(&first_public), &second)
        );
    }

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

    #[test]
    fn small_exponents() {
        let mut one = [0u8; DH_LENGTH];
        one[0] = 1;
        let mut two = [0u8; DH_LENGTH];
        two[0] = 2;
        let generator = DhValue::generator();
        assert_eq!(dh_mod_exp(None, &DhValue([0; DH_LENGTH])), DhValue(one));
        assert_eq!(dh_mod_exp(None, &DhValue(one)), generator);
        // The generator is 2^705; its square is 2^705 doubled 705 times.
        let squared = dh_mod_exp(None, &DhValue(two));
        let mut expected = limbs(&generator.0);
        let modulus = limbs(&MODULUS);
        for _ in 0..705 {
            let carry = shift_left(&mut expected);
            if carry || !less_than(&expected, &modulus) {
                subtract(&mut expected, &modulus);
            }
        }
        assert_eq!(limbs(&squared.0), expected);
    }

    #[test]
    fn modulus_reduces_to_zero() {
        let mut one = [0u8; DH_LENGTH];
        one[0] = 1;
        assert_eq!(
            dh_mod_exp(Some(&DhValue::modulus()), &DhValue(one)),
            DhValue([0; DH_LENGTH])
        );
    }
}
