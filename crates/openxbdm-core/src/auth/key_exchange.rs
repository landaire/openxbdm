//! Diffie-Hellman key exchange over the 768-bit group the monitor uses.

/// Bytes of a key exchange value on the wire.
pub const DH_LENGTH: usize = 0x60;

const LIMBS: usize = DH_LENGTH / 4;

/// Group modulus in wire layout (little-endian 768-bit number). Stock
/// passes its group table (0x91f06098) to the kernel without the per-qword
/// byte swap it applies to client values, so each table qword appears
/// byte reversed here.
const MODULUS: [u8; DH_LENGTH] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
    0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
    0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
    0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37,
    0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
    0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// A group element or exponent of the key exchange, in wire layout.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DhValue(pub [u8; DH_LENGTH]);

impl DhValue {
    /// The group generator.
    pub const fn generator() -> Self {
        /// Offset of the only nonzero generator byte (value 2) in wire
        /// layout: the table byte 0x91f06150, swapped like the modulus.
        const GENERATOR_BYTE: usize = 0x5f;

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

/// Montgomery product `left * right / R mod m` for `left, right < m`.
fn multiply(
    left: &[u32; LIMBS],
    right: &[u32; LIMBS],
    modulus: &[u32; LIMBS],
    factor: u32,
) -> [u32; LIMBS] {
    let mut total = [0u32; LIMBS + 2];

    for &digit in left {
        let mut carry = 0u64;
        for (slot, &other) in total.iter_mut().zip(right) {
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

    #[test]
    fn small_exponents() {
        let mut one = [0u8; DH_LENGTH];
        one[0] = 1;
        let mut two = [0u8; DH_LENGTH];
        two[0] = 2;
        let generator = DhValue::generator();

        assert_eq!(dh_mod_exp(None, &DhValue([0; DH_LENGTH])), DhValue(one));
        assert_eq!(dh_mod_exp(None, &DhValue(one)), generator);

        // The generator is 2^761; its square is 2^761 doubled 761 times.
        let squared = dh_mod_exp(None, &DhValue(two));
        let mut expected = limbs(&generator.0);
        let modulus = limbs(&MODULUS);

        for _ in 0..761 {
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

    /// Client values that stock XBDM turned into a shared value of 1 and 0
    /// on a devkit, checked through `adminpw passwd=` and `authuser`.
    #[test]
    fn stock_group_reduces_the_modulus_and_its_successor() {
        let wire = |hex: &str| {
            let mut bytes = [0u8; DH_LENGTH];
            for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
                *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
            }

            DhValue(bytes)
        };
        let successor = wire(
            "0000000000000000ca0fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
             020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\
             4fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff",
        );
        let modulus = wire(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
             020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\
             4fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff",
        );
        let mut one = [0u8; DH_LENGTH];
        one[0] = 1;

        assert_eq!(dh_mod_exp(Some(&successor), &value(3)), DhValue(one));
        assert_eq!(
            dh_mod_exp(Some(&modulus), &value(3)),
            DhValue([0; DH_LENGTH])
        );
    }
}
