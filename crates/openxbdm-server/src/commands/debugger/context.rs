//! Thread register context: the `getcontext` line formats and the
//! `setcontext` register parameters.

use core::fmt::Write as _;

use openxbdm_core::line::CommandLine;

use crate::text::Text;

/// Register groups of a context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ContextFlags(pub u32);

impl ContextFlags {
    pub const NONE: Self = Self(0);
    pub const CONTROL: Self = Self(0x1);
    pub const FLOATING_POINT: Self = Self(0x2);
    pub const INTEGER: Self = Self(0x4);
    pub const VECTOR: Self = Self(0x10);
    pub const FULL: Self = Self(0x17);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// Register state of a thread, in the layout groups of the kernel context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// Groups that hold valid values.
    pub flags: ContextFlags,
    pub msr: u32,
    pub iar: u32,
    pub lr: u32,
    pub ctr: u64,
    pub gpr: [u64; 32],
    pub cr: u32,
    pub xer: u32,
    pub fpscr: u64,
    /// Raw IEEE bits.
    pub fpr: [u64; 32],
    pub vscr: [u32; 4],
    pub vr: [[u32; 4]; 128],
}

impl Default for Context {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Context {
    pub const EMPTY: Self = Self {
        flags: ContextFlags::NONE,
        msr: 0,
        iar: 0,
        lr: 0,
        ctr: 0,
        gpr: [0; 32],
        cr: 0,
        xer: 0,
        fpscr: 0,
        fpr: [0; 32],
        vscr: [0; 4],
        vr: [[0; 4]; 128],
    };
}

/// Bytes of the kernel context layout (`ContextFlags` word first).
pub const CONTEXT_SIZE: usize = 0xa40;

mod offset {
    pub const MSR: usize = 0x4;
    pub const IAR: usize = 0x8;
    pub const LR: usize = 0xc;
    pub const CTR: usize = 0x10;
    pub const GPR: usize = 0x18;
    pub const CR: usize = 0x118;
    pub const XER: usize = 0x11c;
    pub const FPSCR: usize = 0x120;
    pub const FPR: usize = 0x128;
    pub const VSCR: usize = 0x230;
    pub const VR: usize = 0x240;
}

impl Context {
    /// Store every register in the big-endian kernel layout.
    pub fn encode(&self, out: &mut [u8; CONTEXT_SIZE]) {
        let mut put = |at: usize, bytes: &[u8]| out[at..at + bytes.len()].copy_from_slice(bytes);
        put(0, &self.flags.0.to_be_bytes());
        put(offset::MSR, &self.msr.to_be_bytes());
        put(offset::IAR, &self.iar.to_be_bytes());
        put(offset::LR, &self.lr.to_be_bytes());
        put(offset::CTR, &self.ctr.to_be_bytes());
        for (n, gpr) in self.gpr.iter().enumerate() {
            put(offset::GPR + 8 * n, &gpr.to_be_bytes());
        }
        put(offset::CR, &self.cr.to_be_bytes());
        put(offset::XER, &self.xer.to_be_bytes());
        put(offset::FPSCR, &self.fpscr.to_be_bytes());
        for (n, fpr) in self.fpr.iter().enumerate() {
            put(offset::FPR + 8 * n, &fpr.to_be_bytes());
        }
        for (n, word) in self.vscr.iter().enumerate() {
            put(offset::VSCR + 4 * n, &word.to_be_bytes());
        }
        for (index, vector) in self.vr.iter().enumerate() {
            for (n, word) in vector.iter().enumerate() {
                put(offset::VR + 0x10 * index + 4 * n, &word.to_be_bytes());
            }
        }
    }

    /// Read every register from the big-endian kernel layout.
    pub fn decode(bytes: &[u8; CONTEXT_SIZE]) -> Self {
        let word = |at: usize| {
            u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let dword = |at: usize| (u64::from(word(at)) << 32) | u64::from(word(at + 4));
        Self {
            flags: ContextFlags(word(0)),
            msr: word(offset::MSR),
            iar: word(offset::IAR),
            lr: word(offset::LR),
            ctr: dword(offset::CTR),
            gpr: core::array::from_fn(|n| dword(offset::GPR + 8 * n)),
            cr: word(offset::CR),
            xer: word(offset::XER),
            fpscr: dword(offset::FPSCR),
            fpr: core::array::from_fn(|n| dword(offset::FPR + 8 * n)),
            vscr: core::array::from_fn(|n| word(offset::VSCR + 4 * n)),
            vr: core::array::from_fn(|index| {
                core::array::from_fn(|n| word(offset::VR + 0x10 * index + 4 * n))
            }),
        }
    }
}

/// MSR single-step trace enable.
pub const MSR_SINGLE_STEP: u32 = 0x400;
/// MSR external interrupt enable.
pub const MSR_EXTERNAL_INTERRUPTS: u32 = 0x8000;

/// One `getcontext` line, in output order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextLine {
    Msr,
    Iar,
    Lr,
    Ctr,
    Gpr(u8),
    Cr,
    Xer,
    Fpscr,
    Fpr(u8),
    Vscr,
    Vr(u8),
}

impl ContextLine {
    /// The first line at or after `self` whose group is in `flags`.
    pub fn first_from(position: usize, flags: ContextFlags) -> Option<(usize, Self)> {
        (position..LINE_COUNT).find_map(|index| {
            let line = Self::at(index);
            flags.contains(line.group()).then_some((index, line))
        })
    }

    fn at(index: usize) -> Self {
        match index {
            0 => Self::Msr,
            1 => Self::Iar,
            2 => Self::Lr,
            3 => Self::Ctr,
            4..=35 => Self::Gpr((index - 4) as u8),
            36 => Self::Cr,
            37 => Self::Xer,
            38 => Self::Fpscr,
            39..=70 => Self::Fpr((index - 39) as u8),
            71 => Self::Vscr,
            _ => Self::Vr((index - 72) as u8),
        }
    }

    fn group(self) -> ContextFlags {
        match self {
            Self::Msr | Self::Iar | Self::Lr | Self::Ctr => ContextFlags::CONTROL,
            Self::Gpr(_) | Self::Cr | Self::Xer => ContextFlags::INTEGER,
            Self::Fpscr | Self::Fpr(_) => ContextFlags::FLOATING_POINT,
            Self::Vscr | Self::Vr(_) => ContextFlags::VECTOR,
        }
    }

    /// Write the line without its line end.
    pub fn write<const N: usize>(self, context: &Context, out: &mut Text<N>) {
        let _ = match self {
            Self::Msr => write!(out, "Msr=0x{:08x}", context.msr),
            Self::Iar => write!(out, "Iar=0x{:08x}", context.iar),
            Self::Lr => write!(out, "Lr=0x{:08x}", context.lr),
            Self::Ctr => write!(out, "Ctr=0q{:016x}", context.ctr),
            Self::Gpr(n) => write!(out, "Gpr{n}=0q{:016x}", context.gpr[usize::from(n)]),
            Self::Cr => write!(out, "Cr=0x{:08x}", context.cr),
            Self::Xer => write!(out, "Xer=0x{:08x}", context.xer),
            Self::Fpscr => write!(out, "Fpscr=0q{:016x}", context.fpscr),
            Self::Fpr(n) => write!(out, "Fpr{n}=0q{:016x}", context.fpr[usize::from(n)]),
            Self::Vscr => write_vector(out, "Vscr", None, &context.vscr),
            Self::Vr(n) => write_vector(out, "Vr", Some(n), &context.vr[usize::from(n)]),
        };
    }
}

const LINE_COUNT: usize = 72 + 128;

fn write_vector<const N: usize>(
    out: &mut Text<N>,
    name: &str,
    index: Option<u8>,
    words: &[u32; 4],
) -> core::fmt::Result {
    out.write_str(name)?;
    if let Some(index) = index {
        write!(out, "{index}")?;
    }
    write!(
        out,
        "=0x{:08X},0x{:08X},0x{:08X},0x{:08X}",
        words[0], words[1], words[2], words[3]
    )
}

/// Overlay every register parameter of a `setcontext` line. Unknown keys
/// and values that do not parse are ignored.
pub fn apply_parameters(line: &CommandLine<'_>, context: &mut Context) {
    if let Some(value) = line.dword("Msr") {
        context.msr = value;
    }
    if let Some(value) = line.dword("Iar") {
        context.iar = value;
    }
    if let Some(value) = line.dword("Lr") {
        context.lr = value;
    }
    if let Some(value) = qword(line, "Ctr") {
        context.ctr = value;
    }
    if let Some(value) = line.dword("Cr") {
        context.cr = value;
    }
    if let Some(value) = line.dword("Xer") {
        context.xer = value;
    }
    if let Some(value) = qword(line, "Fpscr") {
        context.fpscr = value;
    }
    if let Some(words) = vector(line, "Vscr") {
        context.vscr = words;
    }
    let mut name = Text::<8>::new();
    for (prefix, registers) in [("Gpr", &mut context.gpr), ("Fpr", &mut context.fpr)] {
        for (n, register) in registers.iter_mut().enumerate() {
            if let Some(value) = qword(line, register_name(&mut name, prefix, n)) {
                *register = value;
            }
        }
    }
    for (n, register) in context.vr.iter_mut().enumerate() {
        if let Some(words) = vector(line, register_name(&mut name, "Vr", n)) {
            *register = words;
        }
    }
}

fn qword(line: &CommandLine<'_>, key: &str) -> Option<u64> {
    line.param(key).and_then(|value| value.qword())
}

/// `<prefix><n>`, the parameter name of register `n`.
fn register_name<'a>(name: &'a mut Text<8>, prefix: &str, n: usize) -> &'a str {
    name.clear();
    let _ = name.push_bytes(prefix.as_bytes());
    let _ = name.push_decimal(n as u32);
    core::str::from_utf8(name.as_bytes()).unwrap_or_default()
}

/// Characters of a vector value the monitor copies before parsing.
const VECTOR_TEXT_LIMIT: usize = 62;

/// Four numbers with C `strtoul` base-0 rules, each followed by `,`,
/// space, CR, or the end of the copied value.
fn vector(line: &CommandLine<'_>, key: &str) -> Option<[u32; 4]> {
    let mut buffer = [0u8; VECTOR_TEXT_LIMIT + 1];
    let text = line.param(key)?.copy_into(&mut buffer);
    let mut words = [0u32; 4];
    let mut position = 0;
    for word in &mut words {
        let (value, consumed) = strtoul(&text[position.min(text.len())..]);
        position += consumed;
        match text.get(position) {
            None => {}
            Some(b',' | b' ' | b'\r') => position += 1,
            Some(_) => return None,
        }
        *word = value;
    }
    Some(words)
}

/// C `strtoul(text, &end, 0)`: returns the value and the bytes consumed
/// (0 when no digits were parsed).
pub(super) fn strtoul(text: &[u8]) -> (u32, usize) {
    let mut position = 0;
    while matches!(
        text.get(position),
        Some(b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
    ) {
        position += 1;
    }
    let negative = match text.get(position) {
        Some(b'-') => {
            position += 1;
            true
        }
        Some(b'+') => {
            position += 1;
            false
        }
        _ => false,
    };
    let mut base = 10;
    if text.get(position) == Some(&b'0') {
        if matches!(text.get(position + 1), Some(b'x' | b'X'))
            && text
                .get(position + 2)
                .is_some_and(|byte| byte.is_ascii_hexdigit())
        {
            base = 16;
            position += 2;
        } else {
            base = 8;
        }
    }
    let start = position;
    let mut value: u32 = 0;
    let mut overflow = false;
    while let Some(digit) = text
        .get(position)
        .and_then(|&byte| (byte as char).to_digit(base))
    {
        match value
            .checked_mul(base)
            .and_then(|value| value.checked_add(digit))
        {
            Some(next) => value = next,
            None => overflow = true,
        }
        position += 1;
    }
    if position == start && base != 8 {
        return (0, 0);
    }
    let value = if overflow {
        u32::MAX
    } else if negative {
        value.wrapping_neg()
    } else {
        value
    };
    (value, position)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_values_follow_strtoul_rules() {
        let line = CommandLine::new(b"setcontext Vr3=0x10,020,30,-1 Vscr=1,2,3");
        assert_eq!(vector(&line, "Vr3"), Some([0x10, 0o20, 30, 0xffff_ffff]));
        assert_eq!(vector(&line, "Vscr"), Some([1, 2, 3, 0]));
        let bad = CommandLine::new(b"setcontext Vr0=1;2,3,4");
        assert_eq!(vector(&bad, "Vr0"), None);
    }

    #[test]
    fn lines_follow_group_order() {
        let flags = ContextFlags::INTEGER.union(ContextFlags::VECTOR);
        assert_eq!(
            ContextLine::first_from(0, flags),
            Some((4, ContextLine::Gpr(0)))
        );
        assert_eq!(
            ContextLine::first_from(38, flags),
            Some((71, ContextLine::Vscr))
        );
        assert_eq!(ContextLine::first_from(LINE_COUNT, flags), None);
    }
}
