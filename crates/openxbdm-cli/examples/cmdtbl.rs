//! Walk xbdm's command dispatch table (an array of 20-byte entries,
//! each `{name_ptr, auth_flag, handler_ptr, 0, extra}`) and print every
//! registered command name. The table is a linked list where the first
//! entry's `name_ptr` field actually points at the next entry minus 8,
//! but in practice the entries are laid out contiguously so a simple
//! stride-20 walk over a supplied address range works.
//!
//! Usage: feed the raw bytes of the table on stdin as hex, pass the
//! base VA and byte length.
//!
//!   cargo run --example cmdtbl --features dangerous -- 0x91f97000 2048

use std::io::Read;

fn main() {
    let mut args = std::env::args().skip(1);
    let base_str = args.next().expect("usage: cmdtbl <base> [len]");
    let base = parse_u32(&base_str).expect("base must parse");
    let _len = args.next().and_then(|s| parse_u32(&s)).unwrap_or(u32::MAX);

    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .expect("stdin read");
    let bytes = parse_hex(&buf);

    let stride = 20usize;
    let mut off = 0usize;
    while off + stride <= bytes.len() {
        let entry_addr = base.wrapping_add(off as u32);
        let name_ptr = read_u32_be(&bytes[off..]);
        let auth = read_u32_be(&bytes[off + 4..]);
        let handler = read_u32_be(&bytes[off + 8..]);
        let extra = read_u32_be(&bytes[off + 16..]);
        println!(
            "{entry_addr:#010x}  name_ptr={name_ptr:#010x} \
             auth={auth:#010x} handler={handler:#010x} extra={extra:#010x}"
        );
        off += stride;
    }
}

fn read_u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}

fn parse_u32(s: &str) -> Option<u32> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(h, 16).ok()
    } else {
        t.parse().ok()
    }
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
        }
    }
    out
}
