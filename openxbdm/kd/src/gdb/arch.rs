//! Xenon register layouts and target descriptions for gdbstub.
//!
//! Xenon is 64-bit PowerPC. [`Xenon64`] describes its registers as they
//! are (`powerpc:common64`). [`Xenon32`] describes their low words as
//! 32-bit PowerPC (`powerpc:common`): titles compiled as 32-bit code use
//! that ABI, and GDB accepts a 32-bit ELF as the symbol file only with a
//! 32-bit description. A 32-bit register write replaces the low word of the
//! 64-bit register and keeps the high word.
//!
//! The context record holds IAR, MSR and LR as 32-bit fields.

use gdbstub::arch::Arch;
use gdbstub::arch::Registers;
use openxbdm_kd_core::context::Context;
use openxbdm_kd_core::context::Fpr;
use openxbdm_kd_core::context::Gpr;

/// Registers of one processor, converted from and to its context record.
pub trait ContextRegisters {
    fn load(&mut self, context: &Context);
    fn store(&self, context: &mut Context);
}

/// A register view of a Xenon processor.
pub trait XenonArch:
    Arch<Usize = u64, BreakpointKind = usize, RegId = (), Registers: ContextRegisters>
{
}

macro_rules! target_xml {
    ($architecture:literal, $bits:literal, $int:literal) => {
        concat!(
            r#"<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd"><target version="1.0">"#,
            "<architecture>",
            $architecture,
            "</architecture>",
            r#"<feature name="org.gnu.gdb.power.core">"#,
            r#"<reg name="r0" bitsize=""#, $bits, r#"" type=""#, $int, r#"" regnum="0"/>"#,
            r#"<reg name="r1" bitsize=""#, $bits, r#"" type="data_ptr"/>"#,
            r#"<reg name="r2" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r3" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r4" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r5" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r6" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r7" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r8" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r9" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r10" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r11" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r12" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r13" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r14" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r15" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r16" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r17" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r18" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r19" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r20" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r21" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r22" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r23" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r24" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r25" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r26" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r27" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r28" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r29" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r30" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="r31" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="pc" bitsize=""#, $bits, r#"" type="code_ptr" regnum="64"/>"#,
            r#"<reg name="msr" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="cr" bitsize="32" type="uint32"/>"#,
            r#"<reg name="lr" bitsize=""#, $bits, r#"" type="code_ptr"/>"#,
            r#"<reg name="ctr" bitsize=""#, $bits, r#"" type=""#, $int, r#""/>"#,
            r#"<reg name="xer" bitsize="32" type="uint32"/>"#,
            "</feature>",
            r#"<feature name="org.gnu.gdb.power.fpu">"#,
            r#"<reg name="f0" bitsize="64" type="ieee_double" regnum="32"/>"#,
            r#"<reg name="f1" bitsize="64" type="ieee_double"/><reg name="f2" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f3" bitsize="64" type="ieee_double"/><reg name="f4" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f5" bitsize="64" type="ieee_double"/><reg name="f6" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f7" bitsize="64" type="ieee_double"/><reg name="f8" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f9" bitsize="64" type="ieee_double"/><reg name="f10" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f11" bitsize="64" type="ieee_double"/><reg name="f12" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f13" bitsize="64" type="ieee_double"/><reg name="f14" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f15" bitsize="64" type="ieee_double"/><reg name="f16" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f17" bitsize="64" type="ieee_double"/><reg name="f18" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f19" bitsize="64" type="ieee_double"/><reg name="f20" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f21" bitsize="64" type="ieee_double"/><reg name="f22" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f23" bitsize="64" type="ieee_double"/><reg name="f24" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f25" bitsize="64" type="ieee_double"/><reg name="f26" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f27" bitsize="64" type="ieee_double"/><reg name="f28" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f29" bitsize="64" type="ieee_double"/><reg name="f30" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="f31" bitsize="64" type="ieee_double"/>"#,
            r#"<reg name="fpscr" bitsize="64" group="float" regnum="70"/>"#,
            "</feature></target>"
        )
    };
}

/// The 64-bit registers as they are.
pub enum Xenon64 {}

impl Arch for Xenon64 {
    type Usize = u64;
    type Registers = Registers64;
    type BreakpointKind = usize;
    type RegId = ();

    fn target_description_xml() -> Option<&'static str> {
        Some(target_xml!("powerpc:common64", "64", "uint64"))
    }
}

impl XenonArch for Xenon64 {}

/// The low words, for code compiled as 32-bit PowerPC.
pub enum Xenon32 {}

impl Arch for Xenon32 {
    type Usize = u64;
    type Registers = Registers32;
    type BreakpointKind = usize;
    type RegId = ();

    fn target_description_xml() -> Option<&'static str> {
        Some(target_xml!("powerpc:common", "32", "uint32"))
    }
}

impl XenonArch for Xenon32 {}

/// Registers in the order of the target description, with general-purpose
/// and wide special registers of type `W`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct XenonRegisters<W> {
    pub gpr: [W; 32],
    pub fpr: [u64; 32],

    pub pc: W,
    pub msr: W,
    pub cr: u32,
    pub lr: W,
    pub ctr: W,
    pub xer: u32,
    pub fpscr: u64,
}

pub type Registers64 = XenonRegisters<u64>;
pub type Registers32 = XenonRegisters<u32>;

/// A register field of the target description: big-endian, `SIZE` bytes.
pub trait Field: Copy + Default + core::fmt::Debug + PartialEq + Send + 'static {
    const SIZE: usize;

    fn put(self, write_byte: &mut impl FnMut(Option<u8>));
    fn take(bytes: &[u8]) -> Self;
    fn wide(self) -> u64;
}

impl Field for u32 {
    const SIZE: usize = 4;

    fn put(self, write_byte: &mut impl FnMut(Option<u8>)) {
        self.to_be_bytes()
            .iter()
            .for_each(|&byte| write_byte(Some(byte)));
    }

    fn take(bytes: &[u8]) -> Self {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(bytes);
        Self::from_be_bytes(raw)
    }

    fn wide(self) -> u64 {
        u64::from(self)
    }
}

impl Field for u64 {
    const SIZE: usize = 8;

    fn put(self, write_byte: &mut impl FnMut(Option<u8>)) {
        self.to_be_bytes()
            .iter()
            .for_each(|&byte| write_byte(Some(byte)));
    }

    fn take(bytes: &[u8]) -> Self {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        Self::from_be_bytes(raw)
    }

    fn wide(self) -> u64 {
        self
    }
}

impl<W> Registers for XenonRegisters<W>
where
    W: Field,
{
    /// gdbstub requires the program counter in the address type.
    type ProgramCounter = u64;

    fn pc(&self) -> u64 {
        self.pc.wide()
    }

    fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
        self.gpr.iter().for_each(|value| value.put(&mut write_byte));
        self.fpr.iter().for_each(|value| value.put(&mut write_byte));

        self.pc.put(&mut write_byte);
        self.msr.put(&mut write_byte);
        self.cr.put(&mut write_byte);
        self.lr.put(&mut write_byte);
        self.ctr.put(&mut write_byte);
        self.xer.put(&mut write_byte);
        self.fpscr.put(&mut write_byte);
    }

    fn gdb_deserialize(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let length = 36 * W::SIZE + 32 * u64::SIZE + 2 * u32::SIZE + u64::SIZE;
        if bytes.len() != length {
            return Err(());
        }

        let mut cursor = Cursor { bytes, offset: 0 };

        for value in self.gpr.iter_mut() {
            *value = cursor.take();
        }

        for value in self.fpr.iter_mut() {
            *value = cursor.take();
        }

        self.pc = cursor.take();
        self.msr = cursor.take();
        self.cr = cursor.take();
        self.lr = cursor.take();
        self.ctr = cursor.take();
        self.xer = cursor.take();
        self.fpscr = cursor.take();

        Ok(())
    }
}

impl ContextRegisters for Registers64 {
    fn load(&mut self, context: &Context) {
        for (gpr, value) in gprs().zip(self.gpr.iter_mut()) {
            *value = context.gpr(gpr);
        }
        for (fpr, value) in fprs().zip(self.fpr.iter_mut()) {
            *value = context.fpr(fpr);
        }

        self.pc = u64::from(context.iar());
        self.msr = u64::from(context.msr());
        self.cr = context.cr();
        self.lr = u64::from(context.lr());
        self.ctr = context.ctr();
        self.xer = context.xer();
        self.fpscr = context.fpscr();
    }

    fn store(&self, context: &mut Context) {
        for (gpr, value) in gprs().zip(self.gpr) {
            context.set_gpr(gpr, value);
        }
        for (fpr, value) in fprs().zip(self.fpr) {
            context.set_fpr(fpr, value);
        }

        // The record has no high words for these.
        context.set_iar(self.pc as u32);
        context.set_msr(self.msr as u32);
        context.set_lr(self.lr as u32);
        context.set_cr(self.cr);
        context.set_ctr(self.ctr);
        context.set_xer(self.xer);
        context.set_fpscr(self.fpscr);
    }
}

impl ContextRegisters for Registers32 {
    fn load(&mut self, context: &Context) {
        for (gpr, value) in gprs().zip(self.gpr.iter_mut()) {
            *value = context.gpr(gpr) as u32;
        }
        for (fpr, value) in fprs().zip(self.fpr.iter_mut()) {
            *value = context.fpr(fpr);
        }

        self.pc = context.iar();
        self.msr = context.msr();
        self.cr = context.cr();
        self.lr = context.lr();
        self.ctr = context.ctr() as u32;
        self.xer = context.xer();
        self.fpscr = context.fpscr();
    }

    fn store(&self, context: &mut Context) {
        for (gpr, value) in gprs().zip(self.gpr) {
            context.set_gpr(gpr, with_low_word(context.gpr(gpr), value));
        }
        for (fpr, value) in fprs().zip(self.fpr) {
            context.set_fpr(fpr, value);
        }

        context.set_iar(self.pc);
        context.set_msr(self.msr);
        context.set_lr(self.lr);
        context.set_cr(self.cr);
        context.set_ctr(with_low_word(context.ctr(), self.ctr));
        context.set_xer(self.xer);
        context.set_fpscr(self.fpscr);
    }
}

fn gprs() -> impl Iterator<Item = Gpr> {
    (0..32u8).filter_map(Gpr::new)
}

fn fprs() -> impl Iterator<Item = Fpr> {
    (0..32u8).filter_map(Fpr::new)
}

/// `register` with its low word replaced by `low`.
fn with_low_word(register: u64, low: u32) -> u64 {
    (register & 0xffff_ffff_0000_0000) | u64::from(low)
}

/// Reader over a buffer whose length the caller checked.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn take<F: Field>(&mut self) -> F {
        let value = F::take(&self.bytes[self.offset..self.offset + F::SIZE]);
        self.offset += F::SIZE;

        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 32-bit write of an unchanged register leaves its high word, and a
    /// changed low word keeps the high word.
    #[test]
    fn narrow_write_keeps_high_words() {
        let mut context = Context::from_bytes([0; openxbdm_kd_core::context::CONTEXT_LEN]);
        let r3 = Gpr::new(3).expect("r3");
        context.set_gpr(r3, 0xffff_ffff_8203_0000);
        context.set_ctr(0x0000_0001_0000_0002);

        let mut registers = Registers32::default();
        registers.load(&context);
        assert_eq!(registers.gpr[3], 0x8203_0000);
        assert_eq!(registers.ctr, 2);

        registers.gpr[3] = 0x8204_0000;
        registers.store(&mut context);
        assert_eq!(context.gpr(r3), 0xffff_ffff_8204_0000);
        assert_eq!(context.ctr(), 0x0000_0001_0000_0002);
    }

    /// Serialized registers read back to the same values in both widths.
    #[test]
    fn serialization_matches_description_lengths() {
        fn round_trip<W: Field>(registers: XenonRegisters<W>, bits: usize)
        where
            XenonRegisters<W>: Registers,
        {
            let mut bytes = Vec::new();
            registers.gdb_serialize(|byte| bytes.push(byte.expect("byte")));
            // 32 GPRs, pc, msr, lr and ctr of the view width; 32 FPRs and
            // fpscr of 64 bits; cr and xer of 32 bits.
            assert_eq!(bytes.len() * 8, 36 * bits + 33 * 64 + 2 * 32);

            let mut decoded = XenonRegisters::<W>::default();
            decoded.gdb_deserialize(&bytes).expect("deserialize");
            assert_eq!(decoded, registers);
        }

        let mut wide = Registers64::default();
        wide.gpr[1] = 0x8000_0200_ea00_1000;
        wide.pc = 0x800a_f588;
        round_trip(wide, 64);

        let mut narrow = Registers32::default();
        narrow.gpr[1] = 0x7000_f000;
        narrow.pc = 0x8201_0000;
        round_trip(narrow, 32);
    }
}
