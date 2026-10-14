//! Thread register context: `getcontext` and `setcontext`.

use core::fmt::Write as _;

use crate::commands::kv::value_qword;
use crate::commands::process::ThreadId;
use crate::error::Error;
use crate::error::ParseError;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ExpectedBody;
use crate::protocol::Qword;
use crate::protocol::Response;
use crate::protocol::parse::KvValue;

fn report_parse(err: ParseError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

/// Register groups requested from `getcontext`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContextGroups {
    /// `control`: Msr, Iar, Lr, Ctr.
    pub control: bool,
    /// `int`: Gpr0..Gpr31, Cr, Xer.
    pub integer: bool,
    /// `fp`: Fpscr, Fpr0..Fpr31.
    pub floating_point: bool,
    /// `vr`: Vscr, Vr0..Vr127.
    pub vector: bool,
}

impl ContextGroups {
    pub const FULL: Self = Self {
        control: true,
        integer: true,
        floating_point: true,
        vector: true,
    };
}

/// Index of a general purpose register (0..=31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GprIndex(u8);

impl GprIndex {
    pub const fn new(index: u8) -> Option<Self> {
        if index < 32 { Some(Self(index)) } else { None }
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Index of a floating point register (0..=31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FprIndex(u8);

impl FprIndex {
    pub const fn new(index: u8) -> Option<Self> {
        if index < 32 { Some(Self(index)) } else { None }
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Index of a vector register (0..=127).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VrIndex(u8);

impl VrIndex {
    pub const fn new(index: u8) -> Option<Self> {
        if index < 128 { Some(Self(index)) } else { None }
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// A 128-bit vector register as four words in memory order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Vector128(pub [u32; 4]);

impl core::fmt::Display for Vector128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "0x{a:08X},0x{b:08X},0x{c:08X},0x{d:08X}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlRegisters {
    pub msr: u32,
    pub iar: u32,
    pub lr: u32,
    pub ctr: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegerRegisters {
    pub gpr: [u64; 32],
    pub cr: u32,
    pub xer: u32,
}

/// Floating point registers as raw IEEE 754 bit patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloatingPointRegisters {
    pub fpscr: u64,
    pub fpr: [u64; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorRegisters {
    pub vscr: Vector128,
    pub vr: [Vector128; 128],
}

/// Register groups returned by `getcontext`. A thread that is not stopped
/// at a debug event only reports control and integer registers, whatever
/// was requested; for such a thread Gpr0..Gpr13, Ctr, Msr and Xer read as
/// all ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThreadContext {
    pub control: Option<ControlRegisters>,
    pub integer: Option<IntegerRegisters>,
    pub floating_point: Option<FloatingPointRegisters>,
    pub vector: Option<Box<VectorRegisters>>,
}

/// `getcontext thread=<id> [control] [int] [fp] [vr]`.
#[derive(Debug, Clone, Copy)]
pub struct GetContext {
    pub thread: ThreadId,
    pub groups: ContextGroups,
}

impl Command for GetContext {
    type Output = ThreadContext;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("getcontext").hex32("thread", self.thread.as_u32());
        for (set, token) in [
            (self.groups.control, "control"),
            (self.groups.integer, "int"),
            (self.groups.floating_point, "fp"),
            (self.groups.vector, "vr"),
        ] {
            if set {
                builder = builder.flag(token);
            }
        }
        Ok(builder.finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let lines = response
            .expect_multiline()
            .map_err(rootcause::Report::new)?;
        parse_context(&lines).map_err(report_parse)
    }
}

#[derive(Debug, Clone, Copy)]
enum Register {
    Msr,
    Iar,
    Lr,
    Ctr,
    Gpr(GprIndex),
    Cr,
    Xer,
    Fpscr,
    Fpr(FprIndex),
    Vscr,
    Vr(VrIndex),
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

impl Register {
    fn parse(name: &str) -> Option<Self> {
        let index = |digits: &str| digits.parse::<u8>().ok();
        let fixed = [
            ("Msr", Register::Msr),
            ("Iar", Register::Iar),
            ("Lr", Register::Lr),
            ("Ctr", Register::Ctr),
            ("Cr", Register::Cr),
            ("Xer", Register::Xer),
            ("Fpscr", Register::Fpscr),
            ("Vscr", Register::Vscr),
        ];
        if let Some((_, register)) = fixed
            .into_iter()
            .find(|(text, _)| text.eq_ignore_ascii_case(name))
        {
            return Some(register);
        }
        if let Some(digits) = strip_prefix_ignore_case(name, "Gpr") {
            return GprIndex::new(index(digits)?).map(Register::Gpr);
        }
        if let Some(digits) = strip_prefix_ignore_case(name, "Fpr") {
            return FprIndex::new(index(digits)?).map(Register::Fpr);
        }
        if let Some(digits) = strip_prefix_ignore_case(name, "Vr") {
            return VrIndex::new(index(digits)?).map(Register::Vr);
        }
        None
    }

    fn key(self) -> &'static str {
        match self {
            Register::Msr => "Msr",
            Register::Iar => "Iar",
            Register::Lr => "Lr",
            Register::Ctr => "Ctr",
            Register::Gpr(_) => "Gpr",
            Register::Cr => "Cr",
            Register::Xer => "Xer",
            Register::Fpscr => "Fpscr",
            Register::Fpr(_) => "Fpr",
            Register::Vscr => "Vscr",
            Register::Vr(_) => "Vr",
        }
    }
}

fn parse_dword(text: &str, key: &'static str) -> Result<u32, ParseError> {
    let digits =
        strip_prefix_ignore_case(text, "0x").ok_or(ParseError::InvalidHexDigits { key })?;
    u32::from_str_radix(digits, 16).map_err(|_| ParseError::InvalidHexDigits { key })
}

fn parse_vector(text: &str, key: &'static str) -> Result<Vector128, ParseError> {
    let mut words = [0u32; 4];
    let mut parts = text.split(',');
    for word in &mut words {
        *word = parse_dword(parts.next().ok_or(ParseError::UnrecognizedShape)?, key)?;
    }
    if parts.next().is_some() {
        return Err(ParseError::UnrecognizedShape);
    }
    Ok(Vector128(words))
}

#[derive(Default)]
struct ContextBuilder {
    msr: Option<u32>,
    iar: Option<u32>,
    lr: Option<u32>,
    ctr: Option<u64>,
    gpr: [Option<u64>; 32],
    cr: Option<u32>,
    xer: Option<u32>,
    fpscr: Option<u64>,
    fpr: [Option<u64>; 32],
    vscr: Option<Vector128>,
    vr: Vec<Option<Vector128>>,
}

/// Collect a register group: `None` when no member was reported, an error
/// when only some members were.
fn group<T>(
    present: bool,
    build: impl FnOnce() -> Option<T>,
    key: &'static str,
) -> Result<Option<T>, ParseError> {
    if !present {
        return Ok(None);
    }
    build().map(Some).ok_or(ParseError::MissingKey { key })
}

fn all<T: Copy, const N: usize>(values: &[Option<T>]) -> Option<[T; N]> {
    let mut out = [values.first().copied()??; N];
    for (slot, value) in out.iter_mut().zip(values) {
        *slot = (*value)?;
    }
    (values.len() == N).then_some(out)
}

fn parse_context(lines: &[String]) -> Result<ThreadContext, ParseError> {
    let mut b = ContextBuilder {
        vr: vec![None; 128],
        ..ContextBuilder::default()
    };
    for line in lines {
        let (name, value) = line
            .trim_end()
            .split_once('=')
            .ok_or(ParseError::UnrecognizedShape)?;
        let register = Register::parse(name).ok_or(ParseError::UnrecognizedShape)?;
        let key = register.key();
        let qword = |text: &str| value_qword(KvValue::Bare(text), key);
        match register {
            Register::Msr => b.msr = Some(parse_dword(value, key)?),
            Register::Iar => b.iar = Some(parse_dword(value, key)?),
            Register::Lr => b.lr = Some(parse_dword(value, key)?),
            Register::Ctr => b.ctr = Some(qword(value)?),
            Register::Gpr(index) => b.gpr[index.get() as usize] = Some(qword(value)?),
            Register::Cr => b.cr = Some(parse_dword(value, key)?),
            Register::Xer => b.xer = Some(parse_dword(value, key)?),
            Register::Fpscr => b.fpscr = Some(qword(value)?),
            Register::Fpr(index) => b.fpr[index.get() as usize] = Some(qword(value)?),
            Register::Vscr => b.vscr = Some(parse_vector(value, key)?),
            Register::Vr(index) => b.vr[index.get() as usize] = Some(parse_vector(value, key)?),
        }
    }

    let control_present = b.msr.is_some() || b.iar.is_some() || b.lr.is_some() || b.ctr.is_some();
    let integer_present = b.cr.is_some() || b.xer.is_some() || b.gpr.iter().any(Option::is_some);
    let fp_present = b.fpscr.is_some() || b.fpr.iter().any(Option::is_some);
    let vector_present = b.vscr.is_some() || b.vr.iter().any(Option::is_some);

    Ok(ThreadContext {
        control: group(
            control_present,
            || {
                Some(ControlRegisters {
                    msr: b.msr?,
                    iar: b.iar?,
                    lr: b.lr?,
                    ctr: b.ctr?,
                })
            },
            "control",
        )?,
        integer: group(
            integer_present,
            || {
                Some(IntegerRegisters {
                    gpr: all(&b.gpr)?,
                    cr: b.cr?,
                    xer: b.xer?,
                })
            },
            "int",
        )?,
        floating_point: group(
            fp_present,
            || {
                Some(FloatingPointRegisters {
                    fpscr: b.fpscr?,
                    fpr: all(&b.fpr)?,
                })
            },
            "fp",
        )?,
        vector: group(
            vector_present,
            || {
                Some(Box::new(VectorRegisters {
                    vscr: b.vscr?,
                    vr: all(&b.vr)?,
                }))
            },
            "vr",
        )?,
    })
}

/// One register assignment for `setcontext`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterWrite {
    Msr(u32),
    Iar(u32),
    Lr(u32),
    Ctr(u64),
    Gpr(GprIndex, u64),
    Cr(u32),
    Xer(u32),
    Fpscr(u64),
    /// Raw IEEE 754 bit pattern.
    Fpr(FprIndex, u64),
    Vscr(Vector128),
    Vr(VrIndex, Vector128),
}

/// `setcontext thread=<id> <Reg>=<value> ...`: overwrite registers of a
/// thread stopped at a debug event. Registers not listed keep their saved
/// values. A thread not stopped at a debug event gives `408- not stopped`.
/// The whole line must fit the console's command line length.
#[derive(Debug, Clone)]
pub struct SetContext {
    pub thread: ThreadId,
    pub registers: Vec<RegisterWrite>,
}

impl Command for SetContext {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let mut builder = ArgBuilder::new("setcontext").hex32("thread", self.thread.as_u32());
        let mut key = String::new();
        for register in &self.registers {
            key.clear();
            builder = match *register {
                RegisterWrite::Msr(value) => builder.hex32("Msr", value),
                RegisterWrite::Iar(value) => builder.hex32("Iar", value),
                RegisterWrite::Lr(value) => builder.hex32("Lr", value),
                RegisterWrite::Ctr(value) => builder.qword("Ctr", Qword(value)),
                RegisterWrite::Gpr(index, value) => {
                    let _ = write!(key, "Gpr{}", index.get());
                    builder.qword(&key, Qword(value))
                }
                RegisterWrite::Cr(value) => builder.hex32("Cr", value),
                RegisterWrite::Xer(value) => builder.hex32("Xer", value),
                RegisterWrite::Fpscr(value) => builder.qword("Fpscr", Qword(value)),
                RegisterWrite::Fpr(index, value) => {
                    let _ = write!(key, "Fpr{}", index.get());
                    builder.qword(&key, Qword(value))
                }
                RegisterWrite::Vscr(value) => {
                    let _ = write!(key, "Vscr={value}");
                    builder.flag(&key)
                }
                RegisterWrite::Vr(index, value) => {
                    let _ = write!(key, "Vr{}={value}", index.get());
                    builder.flag(&key)
                }
            };
        }
        Ok(builder.finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multiline(lines: Vec<String>) -> Response {
        Response::Multiline {
            head: "multiline response follows".to_owned(),
            lines,
        }
    }

    fn stopped_lines() -> Vec<String> {
        let mut lines = vec![
            "Msr=0x00029032".to_owned(),
            "Iar=0x82010000".to_owned(),
            "Lr=0x8200fff0".to_owned(),
            "Ctr=0q0000000000000010".to_owned(),
        ];
        lines.extend((0..32).map(|n| format!("Gpr{n}=0q{:016x}", 0x7000_0000_0000_0000u64 + n)));
        lines.push("Cr=0x22000084".to_owned());
        lines.push("Xer=0x20000000".to_owned());
        lines.push("Fpscr=0q0000000000000000".to_owned());
        lines.extend((0..32).map(|n| format!("Fpr{n}=0q{:016x}", 0x3ff0_0000_0000_0000u64 + n)));
        lines.push("Vscr=0x00000000,0x00000000,0x00000000,0x00010000".to_owned());
        lines.extend((0..128).map(|n| format!("Vr{n}=0x{n:08X},0x3F800000,0xDEADBEEF,0x00000000")));
        lines
    }

    #[test]
    fn getcontext_wire_line_lists_groups() {
        let line = GetContext {
            thread: ThreadId(0xfb00_0018),
            groups: ContextGroups::FULL,
        }
        .wire_line()
        .unwrap();
        assert_eq!(line, "getcontext thread=0xfb000018 control int fp vr");
    }

    #[test]
    fn getcontext_parses_running_thread_groups() {
        let mut lines = stopped_lines();
        lines.truncate(4 + 32 + 2);
        let context = GetContext {
            thread: ThreadId(0xfb00_0018),
            groups: ContextGroups::FULL,
        }
        .parse(multiline(lines))
        .unwrap();
        insta::assert_snapshot!(format!("{context:#x?}"));
    }

    #[test]
    fn getcontext_parses_vector_and_floating_point_groups() {
        let context = GetContext {
            thread: ThreadId(0xfb00_0018),
            groups: ContextGroups::FULL,
        }
        .parse(multiline(stopped_lines()))
        .unwrap();
        let fp = context.floating_point.unwrap();
        let vector = context.vector.unwrap();
        insta::assert_snapshot!(format!(
            "{:#x?}",
            (
                fp.fpscr,
                fp.fpr[31],
                vector.vscr,
                vector.vr[0],
                vector.vr[127]
            )
        ));
    }

    #[test]
    fn getcontext_rejects_partial_group() {
        let lines = vec!["Msr=0x00029032".to_owned(), "Iar=0x82010000".to_owned()];
        let command = GetContext {
            thread: ThreadId(0xfb00_0018),
            groups: ContextGroups::FULL,
        };
        assert!(command.parse(multiline(lines)).is_err());
    }

    #[test]
    fn getcontext_parses_empty_selection() {
        let command = GetContext {
            thread: ThreadId(0xfb00_0018),
            groups: ContextGroups::default(),
        };
        assert_eq!(
            command.parse(multiline(Vec::new())).unwrap(),
            ThreadContext::default()
        );
    }

    #[test]
    fn setcontext_wire_line_uses_stock_value_grammar() {
        let line = SetContext {
            thread: ThreadId(0xfb00_0018),
            registers: vec![
                RegisterWrite::Iar(0x8201_0004),
                RegisterWrite::Ctr(0x10),
                RegisterWrite::Gpr(GprIndex::new(3).unwrap(), 0xffff_ffff_8000_0000),
                RegisterWrite::Fpr(FprIndex::new(1).unwrap(), 0x3ff0_0000_0000_0000),
                RegisterWrite::Vr(
                    VrIndex::new(127).unwrap(),
                    Vector128([1, 2, 0xdead_beef, 0]),
                ),
            ],
        }
        .wire_line()
        .unwrap();
        insta::assert_snapshot!(line, @"setcontext thread=0xfb000018 Iar=0x82010004 Ctr=0q0000000000000010 Gpr3=0qffffffff80000000 Fpr1=0q3ff0000000000000 Vr127=0x00000001,0x00000002,0xDEADBEEF,0x00000000");
    }
}
