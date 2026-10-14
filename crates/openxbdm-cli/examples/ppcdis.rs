//! Dev tool: disassemble a PPC byte stream (hex on stdin, one word per
//! line or whitespace/hyphen-separated bytes) and highlight `lis`+`addi`
//! pairs that compose .rdata string loads. Used to reverse-engineer
//! pixcmd sub-handler keyword vocabularies without relying on Binary
//! Ninja's broken LLIL for these functions.
//!
//! Usage:
//!
//!     echo "7d 88 02 a6 48 02 11 6d ..." | \
//!         cargo run --example ppcdis --features dangerous -- 0x91f57324
//!
//! The argument is the base virtual address. `lis rX, hi`+`addi rY, rX, lo`
//! pairs are resolved to their combined 32-bit address and printed next to
//! the instructions.

use std::collections::HashMap;
use std::io::Read;

use powerpc::Argument;
use powerpc::Extensions;
use powerpc::Ins;
use powerpc::InsIter;
use powerpc::Opcode;
use powerpc::Uimm;

fn main() {
    let mut args = std::env::args().skip(1);
    let base_str = args.next().expect("usage: ppcdis <hex-base-addr>");
    let base = parse_u32(&base_str).expect("base addr must parse as hex/decimal");

    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .expect("stdin read");
    let bytes = parse_hex(&buf);
    assert!(bytes.len().is_multiple_of(4), "need a multiple of 4 bytes");

    // First pass: collect lis destinations so we can annotate the
    // matching addi and follow bl targets.
    let ext = Extensions::none();
    let mut lis_state: HashMap<u8, (u32, u16)> = HashMap::new();

    for (address, ins) in InsIter::new(&bytes, base, ext) {
        let parsed = ins.basic();
        let operands: Vec<&Argument> = parsed.args_iter().collect();
        let mnemonic = format!("{}", parsed);

        let mut annotation = String::new();

        match ins.op {
            Opcode::Addis => {
                // lis is addis rT, 0, simm
                if let (Some(Argument::GPR(rt)), Some(Argument::GPR(ra)), Some(uimm)) = (
                    operands.first().copied(),
                    operands.get(1).copied(),
                    operands.get(2).and_then(|a| uimm_of(a)),
                ) && ra.0 == 0
                {
                    lis_state.insert(rt.0, (address, uimm));
                }
            }
            Opcode::Addi => {
                if let (Some(Argument::GPR(rt)), Some(Argument::GPR(ra)), Some(simm)) = (
                    operands.first().copied(),
                    operands.get(1).copied(),
                    operands.get(2).and_then(|a| simm_of(a)),
                ) && ra.0 != 0
                    && let Some(&(lis_addr, hi)) = lis_state.get(&ra.0)
                {
                    let resolved = combine(hi, simm);
                    annotation = format!("  # addr {resolved:#010x} (lis @ {lis_addr:#010x})");
                    // The target register rT is now holding the
                    // resolved address, so track it for chained
                    // references.
                    lis_state.insert(rt.0, (lis_addr, hi));
                    let _ = lis_addr; // silence for older rustc
                }
            }
            Opcode::B => {
                // Direct branch: show absolute target.
                if let Some(target) = ins.branch_dest(address) {
                    let kind = if ins.code & 1 == 1 { "bl" } else { "b" };
                    annotation = format!("  # {kind} {target:#010x}");
                }
            }
            _ => {}
        }

        println!("{address:#010x}  {:08x}  {mnemonic}{annotation}", ins.code);
    }
}

fn uimm_of(a: &Argument) -> Option<u16> {
    match a {
        Argument::Uimm(Uimm(v)) => Some(*v),
        _ => None,
    }
}

fn simm_of(a: &Argument) -> Option<i16> {
    match a {
        Argument::Simm(s) => Some(s.0),
        _ => None,
    }
}

fn combine(hi: u16, lo: i16) -> u32 {
    let hi_part = (hi as u32) << 16;
    hi_part.wrapping_add(lo as i32 as u32)
}

fn parse_hex(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_ascii_hexdigit() {
            cur.push(ch);
            if cur.len() == 2 {
                out.push(u8::from_str_radix(&cur, 16).unwrap());
                cur.clear();
            }
        } else {
            assert!(cur.is_empty() || cur.len() == 2, "odd hex digit");
        }
    }
    out
}

fn parse_u32(s: &str) -> Option<u32> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(h, 16).ok()
    } else {
        t.parse().ok()
    }
}

#[allow(dead_code)]
fn ins_to_string(_ins: &Ins) -> String {
    String::new()
}
