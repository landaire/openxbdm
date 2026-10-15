//! Values of a classifier program and the operators over them (stock
//! value library 0x91f898e0..0x91f8b9d0), shared by constant folding and
//! frame evaluation.
//!
//! Specialized to the netsim configuration: no float values exist, string
//! flags are 0 (no backslash escapes, so a string is its raw byte range),
//! and the conversion flag that arithmetic, comparison and the string
//! functions pass to the integer conversion is always set, which disables
//! its signedness check.

use openxbdm_core::status::Hresult;

use super::Operator;

/// The value has no type (0x80070483).
const NO_VALUE: Hresult = Hresult(0x8007_0483);
/// The operation does not accept the value's type (0x80070545).
const WRONG_TYPE: Hresult = Hresult(0x8007_0545);
/// The value is wider than the target integer (0x800700ea).
const TOO_WIDE: Hresult = Hresult(0x8007_00ea);
/// Signed value to unsigned target or the reverse (0x800700d1).
const SIGN_MISMATCH: Hresult = Hresult(0x8007_00d1);
const DIVIDE_BY_ZERO: Hresult = Hresult(0x8002_0012);
/// Signed division of `i64::MIN` by -1 (0x80070216).
const OVERFLOW: Hresult = Hresult(0x8007_0216);
const NEGATIVE_SHIFT: Hresult = Hresult(0x8007_0083);
const BAD_INDEX: Hresult = Hresult(0x8007_0585);
const BAD_LENGTH: Hresult = Hresult(0x8007_0018);

/// A string value: a byte range of the text the operators receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Text {
    pub start: usize,
    pub end: usize,
}

impl Text {
    fn len(self) -> usize {
        self.end - self.start
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Null,
    Bool(bool),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Mac([u8; 6]),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Str(Text),
}

/// Stock operator codes 0..9 in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arithmetic {
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
    ShiftLeft,
    ShiftRight,
    And,
    Xor,
    Or,
}

/// Stock comparison codes 0..5 in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Less,
    Greater,
    LessEqual,
    GreaterEqual,
    Equal,
    NotEqual,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sign {
    Bool,
    Signed,
    Unsigned,
}

/// An integer value extended to 64 bits by its signedness.
struct Integer {
    bits: u64,
    width: u32,
    sign: Sign,
}

fn integer(value: &Variant) -> Result<Integer, Hresult> {
    use Variant::*;
    let (bits, width, sign) = match *value {
        Null => return Err(NO_VALUE),
        Bool(value) => (u64::from(value), 1, Sign::Bool),
        I8(value) => (value as u64, 8, Sign::Signed),
        I16(value) => (value as u64, 16, Sign::Signed),
        I32(value) => (value as u64, 32, Sign::Signed),
        I64(value) => (value as u64, 64, Sign::Signed),
        U8(value) => (value.into(), 8, Sign::Unsigned),
        U16(value) => (value.into(), 16, Sign::Unsigned),
        U32(value) => (value.into(), 32, Sign::Unsigned),
        U64(value) => (value, 64, Sign::Unsigned),
        Mac(_) | Ipv4(_) | Ipv6(_) | Str(_) => return Err(WRONG_TYPE),
    };
    Ok(Integer { bits, width, sign })
}

fn is_unsigned(value: &Variant) -> bool {
    matches!(
        value,
        Variant::U8(_) | Variant::U16(_) | Variant::U32(_) | Variant::U64(_)
    )
}

/// 0x91f89fe0.
pub fn to_bool(value: &Variant) -> Result<bool, Hresult> {
    integer(value).map(|value| value.bits != 0)
}

/// 0x91f8a0b8 with target type i64 and the signedness check enabled.
pub fn to_i64(value: &Variant) -> Result<i64, Hresult> {
    let value = integer(value)?;
    if value.sign == Sign::Unsigned {
        return Err(SIGN_MISMATCH);
    }
    Ok(value.bits as i64)
}

/// 0x91f8a0b8 with target type u64 and the signedness check enabled.
pub fn to_u64(value: &Variant) -> Result<u64, Hresult> {
    let value = integer(value)?;
    if value.sign == Sign::Signed {
        return Err(SIGN_MISMATCH);
    }
    Ok(value.bits)
}

/// 0x91f8a0b8 with target type i32 and the signedness check disabled.
fn to_i32(value: &Variant) -> Result<i32, Hresult> {
    let value = integer(value)?;
    if value.width > 32 {
        return Err(TOO_WIDE);
    }
    Ok(value.bits as i32)
}

/// Result width rank of an operand: 64, 32 (and bool), 16, 8 bits, or 0
/// for a type of the other signedness.
fn rank(value: &Variant, unsigned: bool) -> u8 {
    use Variant::*;
    match (*value, unsigned) {
        (I64(_), false) | (U64(_), true) => 4,
        (Bool(_), _) | (I32(_), false) | (U32(_), true) => 3,
        (I16(_), false) | (U16(_), true) => 2,
        (I8(_), false) | (U8(_), true) => 1,
        _ => 0,
    }
}

/// 0x91f8b1c0. Operands are unsigned when either one has an unsigned type;
/// the result takes the widest operand type of that signedness (32 bits
/// when the other operand supplies none) and truncates to it.
///
/// Signed division of `i64::MIN` by -1 executes a trap instruction in
/// stock; here it fails.
fn arithmetic(left: &Variant, op: Arithmetic, right: &Variant) -> Result<Variant, Hresult> {
    let unsigned = is_unsigned(left) || is_unsigned(right);
    let l = integer(left)?.bits;
    let r = integer(right)?.bits;
    let bits = match op {
        Arithmetic::Add => l.wrapping_add(r),
        Arithmetic::Subtract => l.wrapping_sub(r),
        Arithmetic::Multiply => l.wrapping_mul(r),
        Arithmetic::Divide | Arithmetic::Remainder if r == 0 => return Err(DIVIDE_BY_ZERO),
        Arithmetic::Divide if unsigned => l / r,
        Arithmetic::Divide => (l as i64).checked_div(r as i64).ok_or(OVERFLOW)? as u64,
        Arithmetic::Remainder if unsigned => l % r,
        Arithmetic::Remainder => (l as i64).checked_rem(r as i64).ok_or(OVERFLOW)? as u64,
        Arithmetic::ShiftLeft | Arithmetic::ShiftRight if !unsigned && (r as i64) < 0 => {
            return Err(NEGATIVE_SHIFT);
        }
        // The shift instructions use the low seven bits of the count.
        Arithmetic::ShiftLeft => l.checked_shl((r & 0x7f) as u32).unwrap_or(0),
        Arithmetic::ShiftRight if unsigned => l.checked_shr((r & 0x7f) as u32).unwrap_or(0),
        Arithmetic::ShiftRight => ((l as i64) >> (r & 0x7f).min(63)) as u64,
        Arithmetic::And => l & r,
        Arithmetic::Xor => l ^ r,
        Arithmetic::Or => l | r,
    };
    Ok(
        match (rank(left, unsigned).max(rank(right, unsigned)), unsigned) {
            (4, false) => Variant::I64(bits as i64),
            (2, false) => Variant::I16(bits as i16),
            (1, false) => Variant::I8(bits as i8),
            (_, false) => Variant::I32(bits as i32),
            (4, true) => Variant::U64(bits),
            (2, true) => Variant::U16(bits as u16),
            (1, true) => Variant::U8(bits as u8),
            (_, true) => Variant::U32(bits as u32),
        },
    )
}

fn address(value: &Variant) -> Option<&[u8]> {
    match value {
        Variant::Mac(bytes) => Some(bytes),
        Variant::Ipv4(bytes) => Some(bytes),
        Variant::Ipv6(bytes) => Some(bytes),
        _ => None,
    }
}

/// 0x91f8b5e8. Two strings compare as text (case-sensitive), two addresses
/// of the same kind bytewise; anything else compares as integers, unsigned
/// when either operand has an unsigned type. Addresses of different kinds
/// are rejected.
fn compare(
    left: &Variant,
    op: Comparison,
    right: &Variant,
    text: &[u8],
) -> Result<Variant, Hresult> {
    use core::cmp::Ordering;
    let ordering = match (left, right) {
        (Variant::Str(l), Variant::Str(r)) => compare_text(text, *l, *r, false).cmp(&0),
        _ => match (address(left), address(right)) {
            (Some(l), Some(r)) if l.len() != r.len() => return Err(WRONG_TYPE),
            (Some(l), Some(r)) => l.cmp(r),
            _ => {
                let unsigned = is_unsigned(left) || is_unsigned(right);
                let l = integer(left)?.bits;
                let r = integer(right)?.bits;
                if unsigned {
                    l.cmp(&r)
                } else {
                    (l as i64).cmp(&(r as i64))
                }
            }
        },
    };
    Ok(Variant::Bool(match op {
        Comparison::Less => ordering == Ordering::Less,
        Comparison::Greater => ordering == Ordering::Greater,
        Comparison::LessEqual => ordering != Ordering::Greater,
        Comparison::GreaterEqual => ordering != Ordering::Less,
        Comparison::Equal => ordering == Ordering::Equal,
        Comparison::NotEqual => ordering != Ordering::Equal,
    }))
}

/// 0x91f8a7b8. Bitwise complement; a bool becomes the i32 complement of
/// 0 or 1.
fn complement(value: &Variant) -> Result<Variant, Hresult> {
    use Variant::*;
    Ok(match *value {
        Null => return Err(NO_VALUE),
        Bool(value) => I32(!i32::from(value)),
        I8(value) => I8(!value),
        I16(value) => I16(!value),
        I32(value) => I32(!value),
        I64(value) => I64(!value),
        U8(value) => U8(!value),
        U16(value) => U16(!value),
        U32(value) => U32(!value),
        U64(value) => U64(!value),
        Mac(_) | Ipv4(_) | Ipv6(_) | Str(_) => return Err(WRONG_TYPE),
    })
}

/// 0x91f8a888. Both operands are converted before either is tested.
fn logical(left: &Variant, and: bool, right: &Variant) -> Result<Variant, Hresult> {
    let left = to_bool(left)?;
    let right = to_bool(right)?;
    Ok(Variant::Bool(if and {
        left && right
    } else {
        left || right
    }))
}

fn strings(left: &Variant, right: &Variant) -> Result<(Text, Text), Hresult> {
    match (left, right) {
        (Variant::Str(left), Variant::Str(right)) => Ok((*left, *right)),
        _ => Err(WRONG_TYPE),
    }
}

/// An absent ignore-case argument selects a case-sensitive comparison.
fn ignore_case(value: Option<&Variant>) -> Result<bool, Hresult> {
    value.map_or(Ok(false), to_bool)
}

/// 0x91f8a938. `I32` of [`compare_text`].
fn string_compare(
    text: &[u8],
    left: &Variant,
    right: &Variant,
    ignore_case_value: Option<&Variant>,
) -> Result<Variant, Hresult> {
    let (left, right) = strings(left, right)?;
    let ignore_case = ignore_case(ignore_case_value)?;
    Ok(Variant::I32(compare_text(text, left, right, ignore_case)))
}

/// 0x91f8a9f0. Searches `pattern` in the window of `source` that `start`
/// and `length` select. Returns the match offset from the start of
/// `source` or -1, or with `contains` whether there is a match.
fn index_of(
    text: &[u8],
    source: &Variant,
    pattern: &Variant,
    start: Option<&Variant>,
    length: Option<&Variant>,
    ignore_case_value: Option<&Variant>,
    contains: bool,
) -> Result<Variant, Hresult> {
    let (source, pattern) = strings(source, pattern)?;
    let mut window = source;
    if let Some(start) = start {
        let offset = usize::try_from(to_i32(start)?).map_err(|_| BAD_INDEX)?;
        window.start += offset;
        if window.start >= source.end {
            return Err(BAD_INDEX);
        }
    }
    if let Some(length) = length {
        let length = to_i32(length)?;
        window.end = window.start + usize::try_from(length).map_err(|_| BAD_LENGTH)?;
        if length == 0 || window.end > source.end {
            return Err(BAD_LENGTH);
        }
    }
    let found = search(text, window, pattern, ignore_case(ignore_case_value)?);
    Ok(match found {
        _ if contains => Variant::Bool(found.is_some()),
        Some(index) => Variant::I32((window.start - source.start + index) as i32),
        None => Variant::I32(-1),
    })
}

/// 0x91f8abb0. An empty source or pattern never matches.
fn starts_with(
    text: &[u8],
    source: &Variant,
    pattern: &Variant,
    ignore_case_value: Option<&Variant>,
) -> Result<Variant, Hresult> {
    let (source, pattern) = strings(source, pattern)?;
    let ignore_case = ignore_case(ignore_case_value)?;
    Ok(Variant::Bool(
        source.len() != 0
            && pattern.len() != 0
            && compare_ranges(text, source, pattern, ignore_case, true) == 0,
    ))
}

/// 0x91f8ac90. An empty source or pattern never matches.
fn ends_with(
    text: &[u8],
    source: &Variant,
    pattern: &Variant,
    ignore_case_value: Option<&Variant>,
) -> Result<Variant, Hresult> {
    let (source, pattern) = strings(source, pattern)?;
    let ignore_case = ignore_case(ignore_case_value)?;
    let tail = Text {
        start: source.end.wrapping_sub(pattern.len()),
        end: source.end,
    };
    Ok(Variant::Bool(
        source.len() != 0
            && pattern.len() != 0
            && source.len() >= pattern.len()
            && compare_text(text, tail, pattern, ignore_case) == 0,
    ))
}

/// 0x91f8b0b0. The range of `source` from `start` (at most its length)
/// spanning `length` bytes, or to its end.
fn substring(source: &Variant, start: &Variant, length: Option<&Variant>) -> Result<Text, Hresult> {
    let Variant::Str(source) = *source else {
        return Err(WRONG_TYPE);
    };
    let start = source.start + usize::try_from(to_i32(start)?).map_err(|_| BAD_INDEX)?;
    if start > source.end {
        return Err(BAD_INDEX);
    }
    let end = match length {
        Some(length) => start + usize::try_from(to_i32(length)?).map_err(|_| BAD_LENGTH)?,
        None => source.end,
    };
    if end > source.end {
        return Err(BAD_LENGTH);
    }
    Ok(Text { start, end })
}

/// An operator of 0x91f89310 over its evaluated operands: the unary
/// operators, arithmetic, comparisons, `&&` and `||` over two values, and
/// the string functions. Callers pass the operand count the operator
/// takes.
pub fn apply(text: &[u8], operator: Operator, operands: &[Variant]) -> Result<Variant, Hresult> {
    let first = &operands[0];
    let optional = |index: usize| operands.get(index);
    match operator.0 {
        6 => arithmetic(&Variant::I32(-1), Arithmetic::Multiply, first),
        8 => to_bool(first).map(|truth| Variant::Bool(!truth)),
        9 => complement(first),
        0xa..=0x10 | 0x17..=0x19 => {
            let op = match operator.0 {
                0xa => Arithmetic::Multiply,
                0xb => Arithmetic::Divide,
                0xc => Arithmetic::Remainder,
                0xd => Arithmetic::Add,
                0xe => Arithmetic::Subtract,
                0xf => Arithmetic::ShiftLeft,
                0x10 => Arithmetic::ShiftRight,
                0x17 => Arithmetic::And,
                0x18 => Arithmetic::Xor,
                _ => Arithmetic::Or,
            };
            arithmetic(first, op, &operands[1])
        }
        0x11..=0x16 => {
            let op = match operator.0 {
                0x11 => Comparison::Less,
                0x12 => Comparison::Greater,
                0x13 => Comparison::LessEqual,
                0x14 => Comparison::GreaterEqual,
                0x15 => Comparison::Equal,
                _ => Comparison::NotEqual,
            };
            compare(first, op, &operands[1], text)
        }
        0x1a | 0x1b => logical(first, operator.0 == 0x1a, &operands[1]),
        0x1e => {
            let Variant::Str(string) = *first else {
                return Err(WRONG_TYPE);
            };
            match i32::try_from(string.len()) {
                Ok(length) => Ok(Variant::I32(length)),
                Err(_) => Err(BAD_LENGTH),
            }
        }
        0x1f => string_compare(text, first, &operands[1], optional(2)),
        // String.IndexOf(s, t[, start][, length][, ignorecase]): a boolean
        // in the last position is the case flag.
        0x20 => {
            let is_bool = |index: usize| matches!(operands[index], Variant::Bool(_));
            let (start, length, ignore_case) = match operands.len() {
                2 => (None, None, None),
                3 if is_bool(2) => (None, None, optional(2)),
                3 => (optional(2), None, None),
                4 if is_bool(3) => (optional(2), None, optional(3)),
                4 => (optional(2), optional(3), None),
                _ => (optional(2), optional(3), optional(4)),
            };
            index_of(text, first, &operands[1], start, length, ignore_case, false)
        }
        0x21 => index_of(text, first, &operands[1], None, None, optional(2), true),
        0x22 => starts_with(text, first, &operands[1], optional(2)),
        0x23 => ends_with(text, first, &operands[1], optional(2)),
        0x24 => substring(first, &operands[1], optional(2)).map(Variant::Str),
        _ => Err(WRONG_TYPE),
    }
}

/// 0x91f898e0 with string flags 0 and no prefix match: -1, 0 or 1.
pub fn compare_text(text: &[u8], left: Text, right: Text, ignore_case: bool) -> i32 {
    compare_ranges(text, left, right, ignore_case, false)
}

/// 0x91f76570 (`tolower`) as the comparison applies it, compared as
/// signed chars. For bytes 0x80..=0xfe the stock CRT raises an assertion
/// trap before the lookup and then leaves the byte unchanged; that trap is
/// not reproduced.
fn fold(byte: u8, ignore_case: bool) -> i8 {
    (if ignore_case {
        byte.to_ascii_lowercase()
    } else {
        byte
    }) as i8
}

/// 0x91f898e0. With `prefix`, `left` matches when `right` is a prefix of
/// it. Identical ranges are equal without comparing bytes.
fn compare_ranges(text: &[u8], left: Text, right: Text, ignore_case: bool, prefix: bool) -> i32 {
    if left == right {
        return 0;
    }
    let mut other = right.start;
    for &byte in &text[left.start..left.end] {
        if other >= right.end {
            return i32::from(!prefix);
        }
        let (l, r) = (fold(byte, ignore_case), fold(text[other], ignore_case));
        if l != r {
            return if l < r { -1 } else { 1 };
        }
        other += 1;
    }
    -i32::from(other < right.end)
}

/// 0x91f89a00. Offset of the first match of `pattern` in `source`; empty
/// operands never match.
fn search(text: &[u8], source: Text, pattern: Text, ignore_case: bool) -> Option<usize> {
    if pattern.len() == 0 {
        return None;
    }
    (0..source.len()).find(|&offset| {
        let rest = Text {
            start: source.start + offset,
            end: source.end,
        };
        compare_ranges(text, rest, pattern, ignore_case, true) == 0
    })
}

#[cfg(test)]
mod tests {
    use super::Variant::*;
    use super::*;

    const TEXT: &[u8] = b"abcABCabxyz";

    fn s(start: usize, end: usize) -> Variant {
        Str(Text { start, end })
    }

    // Expected values: stock 0x91f89fe0 and 0x91f8a0b8 run in the emulator.
    #[test]
    fn conversions() {
        assert_eq!(to_bool(&I8(-1)), Ok(true));
        assert_eq!(to_bool(&U64(0)), Ok(false));
        assert_eq!(to_bool(&Null), Err(NO_VALUE));
        assert_eq!(to_bool(&Mac([0; 6])), Err(WRONG_TYPE));
        assert_eq!(to_i64(&Bool(true)), Ok(1));
        assert_eq!(to_i64(&I64(-5)), Ok(-5));
        assert_eq!(to_i64(&U8(200)), Err(SIGN_MISMATCH));
        assert_eq!(to_u64(&U64(5)), Ok(5));
        assert_eq!(to_u64(&I8(-1)), Err(SIGN_MISMATCH));
        assert_eq!(to_u64(&Null), Err(NO_VALUE));
        assert_eq!(to_i64(&s(0, 1)), Err(WRONG_TYPE));
    }

    // Expected values: stock 0x91f8b1c0 run in the emulator.
    #[test]
    fn arithmetic_results() {
        use Arithmetic::*;
        let cases = [
            (I32(7), Add, I32(-9), Ok(I32(-2))),
            (I32(7), Subtract, I32(9), Ok(I32(-2))),
            (I16(-300), Multiply, I8(3), Ok(I16(-900))),
            (I8(100), Multiply, I8(3), Ok(I8(44))),
            (Bool(true), Add, I8(1), Ok(I32(2))),
            (I64(-1), Divide, I32(2), Ok(I64(0))),
            (I32(7), Divide, I32(0), Err(DIVIDE_BY_ZERO)),
            (I64(i64::MIN), Divide, I32(-1), Err(OVERFLOW)),
            (I64(i64::MIN), Remainder, I64(-1), Err(OVERFLOW)),
            (U8(7), Remainder, U8(0), Err(DIVIDE_BY_ZERO)),
            (I32(-7), Remainder, I32(3), Ok(I32(-1))),
            (I32(1), ShiftLeft, I32(-1), Err(NEGATIVE_SHIFT)),
            (I32(1), ShiftLeft, I32(64), Ok(I32(0))),
            (I32(-8), ShiftRight, I32(1), Ok(I32(-4))),
            (I32(-8), ShiftRight, I32(200), Ok(I32(-1))),
            (U32(1), ShiftLeft, U64(63), Ok(U64(1 << 63))),
            (U32(0x8000_0000), ShiftRight, I32(-1), Ok(U32(0))),
            (I32(-1), Add, U8(1), Ok(U8(0))),
            (U16(1), Add, I32(-1), Ok(U16(0))),
            (U8(250), Multiply, I8(-1), Ok(U8(6))),
            (U64(7), Divide, U64(2), Ok(U64(3))),
            (I64(12), And, I64(10), Ok(I64(8))),
            (I64(12), Xor, I64(10), Ok(I64(6))),
            (I64(12), Or, I64(10), Ok(I64(14))),
            (Null, Add, I32(1), Err(NO_VALUE)),
            (I32(1), Add, Mac([0; 6]), Err(WRONG_TYPE)),
            (s(0, 1), Add, I32(1), Err(WRONG_TYPE)),
        ];
        for (left, op, right, expected) in cases {
            assert_eq!(
                arithmetic(&left, op, &right),
                expected,
                "{left:?} {op:?} {right:?}"
            );
        }
    }

    // Expected values: stock 0x91f8b5e8 run in the emulator.
    #[test]
    fn comparisons() {
        use Comparison::*;
        let mac = Mac([0, 1, 2, 3, 4, 5]);
        let cases = [
            (I32(-1), Less, I32(1), Ok(Bool(true))),
            (I32(-1), Less, U32(1), Ok(Bool(false))),
            (Bool(true), Equal, U8(1), Ok(Bool(true))),
            (mac, Less, Mac([0, 1, 2, 3, 4, 0x80]), Ok(Bool(true))),
            (mac, NotEqual, mac, Ok(Bool(false))),
            (mac, Equal, Ipv4([0; 4]), Err(WRONG_TYPE)),
            (mac, Equal, I32(0), Err(WRONG_TYPE)),
            (s(0, 3), Less, s(3, 6), Ok(Bool(false))),
            (s(0, 3), Equal, s(6, 9), Ok(Bool(false))),
            (s(0, 3), Equal, I32(1), Err(WRONG_TYPE)),
            (Null, Equal, I32(0), Err(NO_VALUE)),
            (
                Ipv4([1, 2, 3, 4]),
                GreaterEqual,
                Ipv4([1, 2, 3, 4]),
                Ok(Bool(true)),
            ),
            (I64(-5), LessEqual, I64(-5), Ok(Bool(true))),
            (U64(5), Greater, U64(6), Ok(Bool(false))),
        ];
        for (left, op, right, expected) in cases {
            assert_eq!(
                compare(&left, op, &right, TEXT),
                expected,
                "{left:?} {op:?} {right:?}"
            );
        }
    }

    // Expected values: stock 0x91f8a7b8 and 0x91f8a888 run in the emulator.
    #[test]
    fn complement_and_logical() {
        assert_eq!(complement(&Bool(true)), Ok(I32(-2)));
        assert_eq!(complement(&Bool(false)), Ok(I32(-1)));
        assert_eq!(complement(&I8(5)), Ok(I8(-6)));
        assert_eq!(complement(&U16(1)), Ok(U16(0xfffe)));
        assert_eq!(complement(&U64(0)), Ok(U64(u64::MAX)));
        assert_eq!(complement(&Null), Err(NO_VALUE));
        assert_eq!(complement(&Ipv6([0; 16])), Err(WRONG_TYPE));
        assert_eq!(logical(&Bool(true), true, &I32(0)), Ok(Bool(false)));
        assert_eq!(logical(&Bool(true), false, &I32(0)), Ok(Bool(true)));
        assert_eq!(logical(&Null, true, &s(0, 1)), Err(NO_VALUE));
        assert_eq!(logical(&I32(1), true, &s(0, 1)), Err(WRONG_TYPE));
    }

    // Expected values: stock 0x91f8a938, 0x91f8abb0 and 0x91f8ac90 run in
    // the emulator; columns are compare, starts with, ends with.
    #[test]
    fn string_predicates() {
        let yes = Bool(true);
        let cases = [
            (s(0, 3), s(3, 6), None, Ok((1, false, false))),
            (s(0, 3), s(3, 6), Some(yes), Ok((0, true, true))),
            (s(0, 3), s(0, 2), None, Ok((1, true, false))),
            (s(0, 2), s(0, 3), None, Ok((-1, false, false))),
            (s(0, 3), s(6, 8), None, Ok((1, true, false))),
            (s(0, 3), I32(1), None, Err(WRONG_TYPE)),
            (s(0, 3), s(3, 6), Some(Null), Err(NO_VALUE)),
            (s(0, 3), s(3, 6), Some(Ipv4([0; 4])), Err(WRONG_TYPE)),
        ];
        for (left, right, case, expected) in cases {
            let case = case.as_ref();
            let actual = string_compare(TEXT, &left, &right, case).map(|order| {
                let starts = starts_with(TEXT, &left, &right, case).unwrap();
                let ends = ends_with(TEXT, &left, &right, case).unwrap();
                (order, starts, ends)
            });
            let expected =
                expected.map(|(order, starts, ends)| (I32(order), Bool(starts), Bool(ends)));
            assert_eq!(actual, expected, "{left:?} {right:?} {case:?}");
            if let Err(error) = expected {
                assert_eq!(starts_with(TEXT, &left, &right, case), Err(error));
                assert_eq!(ends_with(TEXT, &left, &right, case), Err(error));
            }
        }
    }

    // Expected values: stock 0x91f8a9f0 run in the emulator.
    #[test]
    fn index_of_results() {
        let all = s(0, 11);
        let cases = [
            (s(1, 3), None, None, None, false, Ok(I32(1))),
            (s(3, 4), None, None, Some(Bool(true)), false, Ok(I32(0))),
            (s(3, 4), None, None, None, true, Ok(Bool(true))),
            (s(9, 11), None, None, None, false, Ok(I32(9))),
            (s(1, 3), Some(I32(2)), None, None, false, Ok(I32(-1))),
            (
                s(6, 8),
                Some(I32(2)),
                Some(I32(3)),
                None,
                false,
                Ok(I32(-1)),
            ),
            (s(6, 8), Some(I32(2)), Some(I32(6)), None, false, Ok(I32(6))),
            (s(0, 2), Some(I32(-1)), None, None, false, Err(BAD_INDEX)),
            (s(0, 2), Some(I32(11)), None, None, false, Err(BAD_INDEX)),
            (s(0, 2), Some(I64(1)), None, None, false, Err(TOO_WIDE)),
            (
                s(0, 2),
                Some(U32(1)),
                Some(I32(0)),
                None,
                false,
                Err(BAD_LENGTH),
            ),
            (s(0, 2), None, Some(I32(12)), None, false, Err(BAD_LENGTH)),
            (s(5, 5), None, None, None, true, Ok(Bool(false))),
            (I32(1), None, None, None, false, Err(WRONG_TYPE)),
        ];
        for (pattern, start, length, case, contains, expected) in cases {
            let actual = index_of(
                TEXT,
                &all,
                &pattern,
                start.as_ref(),
                length.as_ref(),
                case.as_ref(),
                contains,
            );
            assert_eq!(actual, expected, "{pattern:?} {start:?} {length:?}");
        }
    }

    // Expected values: stock 0x91f8b0b0 run in the emulator.
    #[test]
    fn substring_results() {
        let text = |start, end| Ok(Text { start, end });
        let source = s(2, 8);
        let cases = [
            (source, I32(1), None, text(3, 8)),
            (source, I32(1), Some(I32(2)), text(3, 5)),
            (source, I32(6), Some(I32(0)), text(8, 8)),
            (source, I32(7), None, Err(BAD_INDEX)),
            (source, I32(-1), None, Err(BAD_INDEX)),
            (source, I32(1), Some(I32(6)), Err(BAD_LENGTH)),
            (source, I32(1), Some(I32(-1)), Err(BAD_LENGTH)),
            (source, U64(1), None, Err(TOO_WIDE)),
            (I32(1), I32(0), None, Err(WRONG_TYPE)),
        ];
        for (source, start, length, expected) in cases {
            assert_eq!(substring(&source, &start, length.as_ref()), expected);
        }
    }

    // Expected values: stock 0x91f898e0 run in the emulator.
    #[test]
    fn text_order() {
        let t = |start, end| Text { start, end };
        assert_eq!(compare_text(TEXT, t(0, 3), t(3, 6), false), 1);
        assert_eq!(compare_text(TEXT, t(0, 3), t(3, 6), true), 0);
        assert_eq!(compare_text(TEXT, t(0, 3), t(6, 9), false), -1);
        assert_eq!(compare_text(TEXT, t(0, 2), t(0, 3), false), -1);
        assert_eq!(compare_text(TEXT, t(0, 3), t(0, 2), false), 1);
        assert_eq!(compare_text(TEXT, t(1, 1), t(4, 4), false), 0);
    }
}
