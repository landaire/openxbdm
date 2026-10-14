//! Thin helpers wrapping the `powerpc` crate for the patterns our
//! signature scanners care about.
//!
//! The `powerpc` crate exposes each instruction as an [`Ins`] with a
//! decoded `Opcode` enum and machine-readable operands; the helpers
//! below translate between that model and the `(register, immediate)`
//! shapes our scanners want to assert. We deliberately stay in that
//! decoded form rather than matching raw bytes so the patterns are
//! robust to register allocation changes across xbdm builds.

use powerpc::Argument;
use powerpc::Extensions;
use powerpc::Ins;
use powerpc::InsIter;
use powerpc::Opcode;
use powerpc::Uimm;

/// Compute `(hi, lo)` halves of an address as they appear in a typical
/// `lis rX, hi(addr) ; addi rY, rX, lo(addr)` pair. PPC's `addi`
/// sign-extends its 16-bit immediate, so when the low half has its top
/// bit set (`>= 0x8000`) the high half must be incremented to
/// compensate.
pub fn address_halves(addr: u32) -> (u16, i16) {
    let lo = addr as i16;
    let mut hi = (addr >> 16) as u16;
    if (addr & 0xFFFF) >= 0x8000 {
        hi = hi.wrapping_add(1);
    }
    (hi, lo)
}

/// PPC extensions flag set for the Xbox 360 PPC variant (Xenon is a
/// cut-down POWER4 with VMX128; Opcode::detect treats plain `Ins::new`
/// with empty extensions as classical PPC which is sufficient for the
/// control-flow we care about).
pub fn xenon_extensions() -> Extensions {
    Extensions::none()
}

/// Helper to construct an [`Ins`] from a big-endian 4-byte slice.
pub fn decode(word_be: u32) -> Ins {
    Ins::new(word_be, xenon_extensions())
}

/// Iterate instructions out of a byte slice assumed to be big-endian
/// 4-byte-aligned machine code loaded at `base_va`.
pub fn iter<'a>(bytes: &'a [u8], base_va: u32) -> InsIter<'a> {
    InsIter::new(bytes, base_va, xenon_extensions())
}

/// Match `lis rT, imm16`. Returns `Some(rT)` when the instruction is
/// `addis rT, 0, imm16` with the given immediate.
pub fn as_lis(ins: &Ins, imm16: u16) -> Option<u8> {
    let parsed = ins.basic();
    if ins.op != Opcode::Addis {
        return None;
    }
    let args = parsed.args_iter().collect::<Vec<_>>();
    if args.len() < 3 {
        return None;
    }
    let rt = gpr(args[0])?;
    let ra = gpr(args[1])?;
    let simm = uimm(args[2])? as u16;
    if ra != 0 || simm != imm16 {
        return None;
    }
    Some(rt)
}

/// Match `addi rT, rA, simm16` with the given immediate. Returns
/// `Some((rT, rA))` on match.
pub fn as_addi(ins: &Ins, imm16: i16) -> Option<(u8, u8)> {
    let parsed = ins.basic();
    if ins.op != Opcode::Addi {
        return None;
    }
    let args = parsed.args_iter().collect::<Vec<_>>();
    if args.len() < 3 {
        return None;
    }
    let rt = gpr(args[0])?;
    let ra = gpr(args[1])?;
    let simm = simm(args[2])?;
    if simm != imm16 {
        return None;
    }
    Some((rt, ra))
}

/// Match `li rT, simm16` (which the simplified mnemonic expresses as
/// `Li` but the basic form is `addi rT, 0, simm16`). Returns the target
/// register on match.
pub fn as_li(ins: &Ins, imm16: i16) -> Option<u8> {
    let (rt, ra) = as_addi(ins, imm16)?;
    if ra != 0 {
        return None;
    }
    Some(rt)
}

/// Is this instruction the `mflr r12` commonly seen at the start of a
/// stw-ing prologue?
pub fn is_mflr_r12(ins: &Ins) -> bool {
    // `mflr rT` is `mfspr rT, 8`. The `powerpc` crate decodes it as
    // `Opcode::Mfspr` with an operand list `(rT, SPR8)`.
    if ins.op != Opcode::Mfspr {
        return false;
    }
    let parsed = ins.basic();
    let args = parsed.args_iter().collect::<Vec<_>>();
    if args.len() < 2 {
        return false;
    }
    let rt = match gpr(args[0]) {
        Some(r) => r,
        None => return false,
    };
    let spr = match args[1] {
        Argument::SPR(s) => s.0,
        _ => return false,
    };
    rt == 12 && spr == 8
}

/// Extract the absolute branch target for a `bl` instruction at
/// `address`. Returns `None` for non-calls.
pub fn bl_target(ins: &Ins, address: u32) -> Option<u32> {
    if ins.op != Opcode::B {
        return None;
    }
    // `B` covers b / ba / bl / bla; "is_direct_branch" plus the LK
    // bit in the raw word gives us the `bl` discriminator.
    if ins.code & 1 == 0 {
        return None;
    }
    ins.branch_dest(address)
}

fn gpr(arg: &Argument) -> Option<u8> {
    match arg {
        Argument::GPR(g) => Some(g.0),
        _ => None,
    }
}

fn uimm(arg: &Argument) -> Option<u32> {
    match arg {
        Argument::Uimm(Uimm(v)) => Some(*v as u32),
        _ => None,
    }
}

fn simm(arg: &Argument) -> Option<i16> {
    match arg {
        Argument::Simm(s) => Some(s.0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `lis r11, 0x91F0` == 0x3d6091f0.
    #[test]
    fn decodes_lis() {
        let ins = decode(0x3d60_91f0);
        assert_eq!(as_lis(&ins, 0x91f0), Some(11));
        assert_eq!(as_lis(&ins, 0x1234), None);
    }

    /// `addi r4, r11, 0x08a4` == 0x388b08a4.
    #[test]
    fn decodes_addi() {
        let ins = decode(0x388b_08a4);
        assert_eq!(as_addi(&ins, 0x08a4), Some((4, 11)));
    }

    /// `li r5, 0` == 0x38a00000.
    #[test]
    fn decodes_li() {
        let ins = decode(0x38a0_0000);
        assert_eq!(as_li(&ins, 0), Some(5));
    }

    /// `mflr r12` == 0x7d8802a6.
    #[test]
    fn decodes_mflr_r12() {
        let ins = decode(0x7d88_02a6);
        assert!(is_mflr_r12(&ins));
        // `mflr r11` must not match.
        let ins = decode(0x7d68_02a6);
        assert!(!is_mflr_r12(&ins));
    }
}
