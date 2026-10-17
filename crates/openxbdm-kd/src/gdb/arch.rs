//! Xenon register layout and target description for gdbstub.

use gdbstub::arch::Arch;
use gdbstub::arch::Registers;

pub enum Xenon {}

impl Arch for Xenon {
    type Usize = u64;
    type Registers = XenonRegisters;
    type BreakpointKind = usize;
    type RegId = ();

    fn target_description_xml() -> Option<&'static str> {
        const TARGET_XML: &str = concat!(
            r#"<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd"><target version="1.0">"#,
            "<architecture>powerpc:common64</architecture>",
            r#"<feature name="org.gnu.gdb.power.core">"#,
            r#"<reg name="r0" bitsize="64" type="uint64" regnum="0"/>"#,
            r#"<reg name="r1" bitsize="64" type="data_ptr"/>"#,
            r#"<reg name="r2" bitsize="64" type="uint64"/><reg name="r3" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r4" bitsize="64" type="uint64"/><reg name="r5" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r6" bitsize="64" type="uint64"/><reg name="r7" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r8" bitsize="64" type="uint64"/><reg name="r9" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r10" bitsize="64" type="uint64"/><reg name="r11" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r12" bitsize="64" type="uint64"/><reg name="r13" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r14" bitsize="64" type="uint64"/><reg name="r15" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r16" bitsize="64" type="uint64"/><reg name="r17" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r18" bitsize="64" type="uint64"/><reg name="r19" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r20" bitsize="64" type="uint64"/><reg name="r21" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r22" bitsize="64" type="uint64"/><reg name="r23" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r24" bitsize="64" type="uint64"/><reg name="r25" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r26" bitsize="64" type="uint64"/><reg name="r27" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r28" bitsize="64" type="uint64"/><reg name="r29" bitsize="64" type="uint64"/>"#,
            r#"<reg name="r30" bitsize="64" type="uint64"/><reg name="r31" bitsize="64" type="uint64"/>"#,
            r#"<reg name="pc" bitsize="64" type="code_ptr" regnum="64"/>"#,
            r#"<reg name="msr" bitsize="64" type="uint64"/>"#,
            r#"<reg name="cr" bitsize="32" type="uint32"/>"#,
            r#"<reg name="lr" bitsize="64" type="code_ptr"/>"#,
            r#"<reg name="ctr" bitsize="64" type="uint64"/>"#,
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
        );

        Some(TARGET_XML)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct XenonRegisters {
    pub gpr: [u64; 32],
    pub fpr: [u64; 32],

    pub pc: u64,
    pub msr: u64,
    pub cr: u32,
    pub lr: u64,
    pub ctr: u64,
    pub xer: u32,
    pub fpscr: u64,
}

impl Registers for XenonRegisters {
    type ProgramCounter = u64;

    fn pc(&self) -> u64 {
        self.pc
    }

    fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
        let mut put = |bytes: &[u8]| bytes.iter().for_each(|&byte| write_byte(Some(byte)));

        self.gpr.iter().for_each(|value| put(&value.to_be_bytes()));
        self.fpr.iter().for_each(|value| put(&value.to_be_bytes()));

        put(&self.pc.to_be_bytes());
        put(&self.msr.to_be_bytes());
        put(&self.cr.to_be_bytes());
        put(&self.lr.to_be_bytes());
        put(&self.ctr.to_be_bytes());
        put(&self.xer.to_be_bytes());
        put(&self.fpscr.to_be_bytes());
    }

    fn gdb_deserialize(&mut self, bytes: &[u8]) -> Result<(), ()> {
        const LEN: usize = 32 * 8 + 32 * 8 + 8 + 8 + 4 + 8 + 8 + 4 + 8;

        if bytes.len() != LEN {
            return Err(());
        }

        let mut cursor = Cursor { bytes, offset: 0 };

        for value in self.gpr.iter_mut() {
            *value = cursor.u64();
        }

        for value in self.fpr.iter_mut() {
            *value = cursor.u64();
        }

        self.pc = cursor.u64();
        self.msr = cursor.u64();
        self.cr = cursor.u32();
        self.lr = cursor.u64();
        self.ctr = cursor.u64();
        self.xer = cursor.u32();
        self.fpscr = cursor.u64();

        Ok(())
    }
}

/// Reader over a buffer whose length the caller checked.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn u32(&mut self) -> u32 {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&self.bytes[self.offset..self.offset + 4]);
        self.offset += 4;

        u32::from_be_bytes(raw)
    }

    fn u64(&mut self) -> u64 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&self.bytes[self.offset..self.offset + 8]);
        self.offset += 8;

        u64::from_be_bytes(raw)
    }
}
