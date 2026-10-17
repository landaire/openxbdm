//! Walk xbdm's command dispatch table (an array of 20-byte entries,
//! each `{name_ptr, auth_flag, handler_ptr, 0, extra}`) and print every
//! registered command name. The table is a linked list where the first
//! entry's `name_ptr` field actually points at the next entry minus 8,
//! but in practice the entries are laid out contiguously so a simple
//! stride-20 walk over a supplied address range works.
//!
//! Usage: feed the raw bytes of the table on stdin as hex and pass the
//! base VA.
//!
//!   cargo run --example cmdtbl --features dangerous -- 0x91f97000

use std::io::Read;

fn main() {
    const ENTRY_LEN: usize = 20;

    let mut args = std::env::args().skip(1);
    let base_text = args.next().expect("usage: cmdtbl <base>");
    let base = parse_u32(&base_text).expect("base must parse");

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("stdin read");
    let bytes = parse_hex(&input);

    let mut offset = 0usize;
    while offset + ENTRY_LEN <= bytes.len() {
        let entry_addr = base.wrapping_add(offset as u32);
        let name_ptr = read_u32_be(&bytes[offset..]);
        let auth = read_u32_be(&bytes[offset + 4..]);
        let handler = read_u32_be(&bytes[offset + 8..]);
        let extra = read_u32_be(&bytes[offset + 16..]);
        println!(
            "{entry_addr:#010x}  name_ptr={name_ptr:#010x} \
             auth={auth:#010x} handler={handler:#010x} extra={extra:#010x}"
        );
        offset += ENTRY_LEN;
    }
}

fn read_u32_be(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes[..4].try_into().unwrap())
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

/// Decode every pair of hex digits in `text`, skipping other characters.
fn parse_hex(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut digits = String::new();
    for ch in text.chars() {
        if !ch.is_ascii_hexdigit() {
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
