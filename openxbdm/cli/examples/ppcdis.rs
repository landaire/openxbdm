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
use powerpc::InsIter;
use powerpc::Opcode;
use powerpc::Uimm;

fn main() {
    let mut args = std::env::args().skip(1);
    let base_text = args.next().expect("usage: ppcdis <hex-base-addr>");
    let base = parse_u32(&base_text).expect("base addr must parse as hex/decimal");

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("stdin read");
    let bytes = parse_hex(&input);
    assert!(bytes.len().is_multiple_of(4), "need a multiple of 4 bytes");

    // Register -> (address of the `lis`, its high half), so a later `addi`
    // on that register can be resolved.
    let mut lis_state: HashMap<u8, (u32, u16)> = HashMap::new();

    for (address, ins) in InsIter::new(&bytes, base, Extensions::none()) {
        let parsed = ins.basic();
        let operands: Vec<&Argument> = parsed.args_iter().collect();
        let mnemonic = format!("{parsed}");

        let annotation = match ins.op {
            Opcode::Addis => {
                // `lis` is `addis rT, 0, simm`.
                if let (Some(Argument::GPR(rt)), Some(Argument::GPR(ra)), Some(uimm)) = (
                    operands.first().copied(),
                    operands.get(1).copied(),
                    operands.get(2).and_then(|argument| uimm_of(argument)),
                ) && ra.0 == 0
                {
                    lis_state.insert(rt.0, (address, uimm));
                }
                String::new()
            }
            Opcode::Addi => {
                if let (Some(Argument::GPR(rt)), Some(Argument::GPR(ra)), Some(simm)) = (
                    operands.first().copied(),
                    operands.get(1).copied(),
                    operands.get(2).and_then(|argument| simm_of(argument)),
                ) && ra.0 != 0
                    && let Some(&(lis_addr, hi)) = lis_state.get(&ra.0)
                {
                    let resolved = combine(hi, simm);
                    // rT now holds the resolved address; track it for
                    // chained references.
                    lis_state.insert(rt.0, (lis_addr, hi));
                    format!("  # addr {resolved:#010x} (lis @ {lis_addr:#010x})")
                } else {
                    String::new()
                }
            }
            Opcode::B => match ins.branch_dest(address) {
                Some(target) => {
                    let kind = if ins.code & 1 == 1 { "bl" } else { "b" };
                    format!("  # {kind} {target:#010x}")
                }
                None => String::new(),
            },
            _ => String::new(),
        };

        println!("{address:#010x}  {:08x}  {mnemonic}{annotation}", ins.code);
    }
}

fn uimm_of(argument: &Argument) -> Option<u16> {
    match argument {
        Argument::Uimm(Uimm(value)) => Some(*value),
        _ => None,
    }
}

fn simm_of(argument: &Argument) -> Option<i16> {
    match argument {
        Argument::Simm(simm) => Some(simm.0),
        _ => None,
    }
}

fn combine(hi: u16, lo: i16) -> u32 {
    let hi_part = (hi as u32) << 16;
    hi_part.wrapping_add(lo as i32 as u32)
}

/// Decode every pair of hex digits in `text`. Separators may only appear
/// between pairs.
fn parse_hex(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut digits = String::new();
    for ch in text.chars() {
        if !ch.is_ascii_hexdigit() {
            assert!(digits.is_empty() || digits.len() == 2, "odd hex digit");
            continue;
        }

        digits.push(ch);
        if digits.len() == 2 {
            bytes.push(u8::from_str_radix(&digits, 16).unwrap());
            digits.clear();
        }
    }

    bytes
}

fn parse_u32(text: &str) -> Option<u32> {
    let trimmed = text.trim();
    let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    else {
        return trimmed.parse().ok();
    };

    u32::from_str_radix(hex, 16).ok()
}
