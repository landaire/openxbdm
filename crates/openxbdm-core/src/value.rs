//! Wire value formats shared by the client and server.

/// A 64-bit value formatted using XBDM's `0q` quadword notation: sixteen
/// lowercase hex digits split into two eight-digit halves, prefixed `0q`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Qword(pub u64);

impl core::fmt::Display for Qword {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let hi = (self.0 >> 32) as u32;
        let lo = self.0 as u32;
        write!(f, "0q{:08x}{:08x}", hi, lo)
    }
}
