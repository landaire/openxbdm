//! Processor context record exchanged by the context manipulate requests.
//!
//! The record is the kernel's native big-endian structure; the transport
//! does not byte-swap it. Layout, from the trap frame conversion at
//! 0x80097910 and its inverse at 0x80097a40:
//!
//! | Offset | Size | Field |
//! |-------:|-----:|-------|
//! | 0x000 | 4 | context flags |
//! | 0x004 | 4 | MSR |
//! | 0x008 | 4 | IAR (program counter) |
//! | 0x00c | 4 | LR |
//! | 0x010 | 8 | CTR |
//! | 0x018 | 8 x 32 | GPR 0-31 |
//! | 0x118 | 4 | CR |
//! | 0x11c | 4 | XER |
//! | 0x120 | 8 | FPSCR |
//! | 0x128 | 8 x 32 | FPR 0-31 |
//! | 0x228 | 4 | copied from trap frame +0x1bc (PCR +0x58); purpose not analyzed |
//! | 0x22c | 4 | unused |
//! | 0x230 | 0x810 | vector state copied from thread +0x170; layout not analyzed |

pub const CONTEXT_LEN: usize = 0xa40;

const FLAGS: usize = 0x000;
const MSR: usize = 0x004;
const IAR: usize = 0x008;
const LR: usize = 0x00c;
const CTR: usize = 0x010;
const GPR: usize = 0x018;
const CR: usize = 0x118;
const XER: usize = 0x11c;
const FPSCR: usize = 0x120;
const FPR: usize = 0x128;

/// Register group bits of the context flags word (0x80097910).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ContextFlags(pub u32);

impl ContextFlags {
    /// MSR, IAR, LR, CTR.
    pub const CONTROL: u32 = 0x1;
    /// FPSCR and FPRs.
    pub const FLOATING_POINT: u32 = 0x2;
    /// GPRs, CR, XER.
    pub const INTEGER: u32 = 0x4;
    /// Vector state.
    pub const VECTOR: u32 = 0x10;
}

/// General purpose register number, 0 to 31.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Gpr(u8);

impl Gpr {
    pub const fn new(index: u8) -> Option<Self> {
        if index < 32 { Some(Self(index)) } else { None }
    }

    pub const fn index(self) -> u8 {
        self.0
    }
}

/// Floating point register number, 0 to 31.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Fpr(u8);

impl Fpr {
    pub const fn new(index: u8) -> Option<Self> {
        if index < 32 { Some(Self(index)) } else { None }
    }

    pub const fn index(self) -> u8 {
        self.0
    }
}

/// Owned copy of a context record.
#[derive(Clone, PartialEq, Eq)]
pub struct Context {
    bytes: [u8; CONTEXT_LEN],
}

impl Default for Context {
    fn default() -> Self {
        Self {
            bytes: [0; CONTEXT_LEN],
        }
    }
}

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Context")
            .field("flags", &self.flags())
            .field("msr", &self.msr())
            .field("iar", &self.iar())
            .finish_non_exhaustive()
    }
}

impl Context {
    pub fn from_bytes(bytes: [u8; CONTEXT_LEN]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; CONTEXT_LEN] {
        &self.bytes
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; CONTEXT_LEN] {
        &mut self.bytes
    }

    fn get32(&self, offset: usize) -> u32 {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&self.bytes[offset..offset + 4]);
        u32::from_be_bytes(raw)
    }

    fn get64(&self, offset: usize) -> u64 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&self.bytes[offset..offset + 8]);
        u64::from_be_bytes(raw)
    }

    fn set32(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn set64(&mut self, offset: usize, value: u64) {
        self.bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }

    pub fn flags(&self) -> ContextFlags {
        ContextFlags(self.get32(FLAGS))
    }

    pub fn msr(&self) -> u32 {
        self.get32(MSR)
    }

    pub fn set_msr(&mut self, value: u32) {
        self.set32(MSR, value)
    }

    pub fn iar(&self) -> u32 {
        self.get32(IAR)
    }

    pub fn set_iar(&mut self, value: u32) {
        self.set32(IAR, value)
    }

    pub fn lr(&self) -> u32 {
        self.get32(LR)
    }

    pub fn set_lr(&mut self, value: u32) {
        self.set32(LR, value)
    }

    pub fn ctr(&self) -> u64 {
        self.get64(CTR)
    }

    pub fn set_ctr(&mut self, value: u64) {
        self.set64(CTR, value)
    }

    pub fn gpr(&self, register: Gpr) -> u64 {
        self.get64(GPR + 8 * usize::from(register.0))
    }

    pub fn set_gpr(&mut self, register: Gpr, value: u64) {
        self.set64(GPR + 8 * usize::from(register.0), value)
    }

    pub fn cr(&self) -> u32 {
        self.get32(CR)
    }

    pub fn set_cr(&mut self, value: u32) {
        self.set32(CR, value)
    }

    pub fn xer(&self) -> u32 {
        self.get32(XER)
    }

    pub fn set_xer(&mut self, value: u32) {
        self.set32(XER, value)
    }

    pub fn fpscr(&self) -> u64 {
        self.get64(FPSCR)
    }

    pub fn set_fpscr(&mut self, value: u64) {
        self.set64(FPSCR, value)
    }

    /// Raw IEEE 754 double bits.
    pub fn fpr(&self, register: Fpr) -> u64 {
        self.get64(FPR + 8 * usize::from(register.0))
    }

    pub fn set_fpr(&mut self, register: Fpr, value: u64) {
        self.set64(FPR + 8 * usize::from(register.0), value)
    }
}

/// A byte range of the context record transferred by one request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ContextChunk {
    pub offset: u32,
    pub length: u32,
}

/// Splits the context into ranges whose replies fit one packet. The
/// write handler (0x801b6438) commits the staged record only when a range
/// ends at [`CONTEXT_LEN`], so the last chunk must be sent last.
pub fn context_chunks() -> impl Iterator<Item = ContextChunk> {
    let step = crate::manipulate::MAX_TRANSFER_LEN;
    (0..CONTEXT_LEN)
        .step_by(step)
        .map(move |offset| ContextChunk {
            // Both bounded by CONTEXT_LEN.
            offset: offset as u32,
            length: (CONTEXT_LEN - offset).min(step) as u32,
        })
}
