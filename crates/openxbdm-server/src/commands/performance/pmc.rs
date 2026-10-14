//! Performance monitor counters: event names and their decoding (stock
//! 0x91f90be0..0x91f913ec), counter routing (0x91f91f20), bus unit selection
//! (0x91f91d80), and the built-in setups (0x91f9c990).
//!
//! Stock keeps separate string tables; here every name is one entry of
//! [`NAMES`], and each table entry packs the name offset (low 13 bits) with
//! an index into [`FLAGS`] (high 3 bits). Equal stock strings share one
//! entry; stock compares only the instruction counters by address, and no
//! other entry has their text.

/// Counters of the performance monitor.
pub const COUNTERS: usize = 16;
/// Built-in setups.
pub const SETUP_COUNT: u32 = 45;
/// Counter events within one processor unit; higher event numbers use
/// the common table.
const UNIT_EVENTS: u32 = 19;

/// A NUL-terminated entry of [`NAMES`]; the first byte is the counting
/// kind (`C` cycles, `E` and `S` edges).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name(u16);

/// How a counter counts its event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counting {
    Cycles,
    Edges,
    Unknown,
}

impl Name {
    /// The text including its terminating NUL.
    pub fn text(self) -> &'static [u8] {
        let start = usize::from(self.0);
        let mut end = start;
        while NAMES[end] != 0 {
            end += 1;
        }
        &NAMES[start..=end]
    }

    pub fn counting(self) -> Counting {
        match NAMES[usize::from(self.0)] {
            b'C' => Counting::Cycles,
            b'E' | b'S' => Counting::Edges,
            _ => Counting::Unknown,
        }
    }
}

pub const COUNTER_DISABLED: Name = Name(0);
pub const UNKNOWN_SOURCE: Name = Name(17);
pub const INVALID_EVENT: Name = Name(55);
pub const BAD_COUNTER: Name = Name(75);
pub const NCU2_COLLISION: Name = Name(110);
pub const NCU0_COLLISION: Name = Name(153);
pub const CIU_COLLISION: Name = Name(196);
pub const BIU_ALT_COLLISION: Name = Name(240);
pub const L2_COLLISION: Name = Name(288);
pub const BIU_COLLISION: Name = Name(329);
pub const L2_GROUP_UNSET: Name = Name(373);
pub const NO_EVENT: Name = Name(399);
pub const INSTRUCTIONS: Name = Name(647);
pub const FP_INSTRUCTIONS: Name = Name(786);
pub const INT_INSTRUCTIONS: Name = Name(758);
pub const VSU_INSTRUCTIONS: Name = Name(1241);
pub const RC_BUSY: Name = Name(2154);

pub(crate) const NAMES: &[u8] = b"\
Counter Disabled\0UNKNOWN - Get Someone to type them in\0** INVALID EVENT **\0Bad counter number - must be 0-15.\0\
ERROR - NCU2 multiple events on this lane!\0ERROR - NCU0 multiple events on this lane!\0ERROR - CIU - multiple events on this lane!\0\
ERROR - BIU ALT - multiple events on this lane!\0ERROR - L2 multiple events on this lane!\0ERROR - BIU - multiple events on this lane!\0\
ERROR - L2 group not set?\0ERROR - NO EVENT SET!\0Cbranches committed\0Ebranch flushes\0Ci-buf empty cycles\0\
Ei-ERAT misses\0Ci-cache miss cycles\0Eu-code instructions committed\0Cdispatch blocked cycles\0CIS2 stall cycles\0\
CIS2 dependency stall cycles\0Epipeline flushes\0Cdual-issues\0Cinstructions committed\0Cexternal interrupt pending cycles\0\
Cexternal interrupt pending hardware latency cycles\0Cint instructions committed\0Cfp instructions committed\0\
Cisync stalls\0CVIQ stall cycles\0CVIQ dependency stall cycles\0Cmfspr stall cycles\0Cinteger mult/div stall cycles\0\
Sd-ERAT misses (S)\0Sstore requests (S)\0Eloads (S)\0Sload misses (S)\0Smisaligned flushes (S)\0Sstore queue full flushes (S)\0\
Cstcx bottom of store queue cycles\0Csync bottom of store queue cycles\0Sstcx fails (S)\0Sload-hit-stores (S)\0\
Sload hit reloads (S)\0Sload miss load hit reloads (S)\0Sdcbt sends (S)\0Sdcbt L1 hits (S)\0CVSU instructions committed\0\
Cslot 0 instructions committed\0Cslot 1 instructions committed\0SVMX simple committed (S)\0SVMX float committed (S)\0\
SVMX estimate committed (S)\0SVMX permute committed (S)\0SFP load committed (S)\0SVMX load committed (S)\0\
SVMX store committed (S)\0CVIQ other stall cycles\0EVIQ div/sqrt stalls\0EVIQ denorm stalls\0EVIQ NAN stalls\0\
EVIQ dot products\0SVMX abnormal results (S)\0ETLB invalidate entries\0ETLB local invalidates\0ETLB remote invalidates\0\
Epage faults\0ETLB misses\0Ctable walk cycles\0ETLB accesses\0ESLB misses\0ESLB invalidates\0ESLB invalidate alls\0\
ESPR reads\0ESPR writes\0Eload misses (S)\0Ecore 0 L2 dstore miss !dcbz\0Ecore 0 L2 store miss\0Ecore 0 L2 ld miss (!I-fetch)\0\
Ecore 0 L2 ld miss data only\0Ecore 0 L2 i miss\0Ecore 0 L2 i miss prefetch\0Ecore 0 L2 dcbt miss\0Eunused\0\
EL2 acc collision with L2 prefetch\0Eld/st disp retries/congr conflict\0Eld/st disp retries\0Eld/st disp retry and no RC\0\
Call RC busy cycles\0Eld req !grant RC avail\0Eld req !grant NO RC avail\0ERC disp due to dload,iload,dcbt,st\0\
CSTQ not empty\0CSTQ full\0CSTQ wait for RC\0ESTQ gathered a store\0EL2 stores dispatched to RC\0EST req from CIU\0\
ERC disp for dload,iload,dcbt, or st\0CRC machine dispatches\0Ecore 0 L2 data misses\0Ecore 1 L2 data misses\0\
Ecore 2 L2 data misses\0Ecore 0 L2 data hits\0Ecore 1 L2 data hits\0Ecore 2 L2 data hits\0EL2 miss dcbz128\0\
EL2 access for store\0EL2 miss on store\0Eld req !grant !RC\0EL2 read trans busretry\0CP0 STQ wait for RC\0\
CP1 STQ wait for RC\0CP2 STQ wait for RC\0To be entered by industrious soul\0ERC dispatched\0EL2 miss p0\0\
EL2 miss p1\0EL2 miss p2\0EL1 D snoop invalidation\0EL1 D castout/flush invalidation\0EL1 D invalidate sent L2 incl\0\
Ecore 0 L2 dcbt hits\0Ecore 1 L2 dcbt hits\0Ecore 2 L2 dcbt hits\0EL2 RC disp \0EL2 d load hits\0EL2 Hits hit L2 dir + dcbf/dcbst\0\
EL2 hits ifetch/prefetch\0EL2 hits dfetch/dcbt*\0EL2 hits dcbt*\0EL2 hits dload\0EL2 st to Mx/E !dcbf/dcbst\0\
EL2 ld/st misses\0EL2 castouts !dcbf/dcbst\0Eld/st retried due to castout conf\0Eld/st retried due to snoop conf\0\
Eld/st retried due to RC conf\0Eld/st retried !RC\0EL2 i misses\0EL2 i miss prefetch\0EL2 unused\0CRC0 busy for p0\0\
CRC1 busy for p0\0CRC2 busy for p0\0CRC3 busy for p0\0CRC4 busy for p0\0CRC5 busy for p0\0CRC6 busy for p0\0\
CRC7 busy for p0\0EL2 acc collide w L2 pref\0Eld/st dsp retry/cngr cflct\0Eld/st dsp retries\0Eld/st dsp retry & !RC\0\
Eld req & !grant & RC avail\0Eld req & !grant & !RC\0ERC disp due dload/iload/dcbt*/st\0Ecore 1 L2 hits\0\
Ecore 1 L2 I fetch/pre hits\0Ecore 1 L2 stores to Mx/E\0Ecore 1 L2 store miss!dcbz\0Ecore 1 L2 store miss\0\
Ecore 1 L2 I fetch miss\0Ecore 1 L2 I pref miss\0Ecore 1 L2 castouts\0Ecore 2 L2 hits\0Ecore 2 L2 I fetch/pre hits\0\
Ecore 2 L2 stores to Mx/E\0Ecore 2 L2 store miss!dcbz\0Ecore 2 L2 store miss\0Ecore 2 L2 I fetch miss\0\
Ecore 2 L2 I pref miss\0Ecore 2 L2 castouts\0CCIU STQ Full P0\0CCIU STQ Not Empty & L2_STQ not avail P0\0\
CCIU Slice Load Queue Full P0\0ECIU Load Req to L2 canceled by LHS P0\0CCIU STQ Full P1\0CCIU STQ Not Empty & L2_STQ not avail P1\0\
CCIU Slice Load Queue Full P1\0ECIU Load Req to L2 canceled by LHS P1\0CCIU STQ Full P2\0CCIU STQ Not Empty & L2_STQ not avail P2\0\
CCIU Slice Load Queue Full P2\0ECIU Load Req to L2 canceled by LHS P2\0E448 NCU ST Req (E)\0C466 NCU STQ Full (C)\0\
E452 NCU Non-Ugly ST (E)\0E453 NCU Non-Guarded ST (E)\0C463 NCU ST Buffer Full (C)\0E460 NCU STQ Last Gather (E)\0\
C450 NCU STQ Last SHS (C)\0C451 NCU STQ Wait (C)\0C456 NCU STQ Last Sync (C)\0C457 NCU STQ Last LWSync (C)\0\
C458 NCU STQ Last EIEIO (C)\0E461 NCU Load Cancel (E)\0E462 NCU LDQ LHS (E)\0E464 NCU LDQ LD (E)\0C475R NCU ICBI Valid (C)\0\
C476 NCU TLBIE Valid (C)\0E387 Retry issued by BIU\0C389 Only 2 stations are busy\0C391 All 3 stations are busy\0\
C391 Any of 3 comd stations are busy\0C393 All 3 stations stalled\0E394 Rcv 8-beat data from MPi\0E395 Send 8-beat data to MPi\0\
E396 Send Addr_cmd(incl retries)\0C397 cycles bet data req and grant\0C403 NCU ld q not empty (1)\0C405 Castout q full(8)\0\
C406 Push q full(4)\0C407 NCU G=0 stq full(4)\0E13A Castout/Push retry\0E Loads from PM MMIO space\0\
E Stores to PM MMIO space\0E Only 2 stations busy\0E All 3 stations busy\0E All 3 stations stalled\0\
C No credit for a command\0C RC Cmd q not empty (8)\0C Castout Cmd q not empty (8)\0C Push Cmd Q not empty (4)\0\
C NCU St Cmd q not empty (5)\0C RC Cmd q full (8)\0C Castout Data Buffer full\0C Push/Intervention Data Buffer full\0\
C NCU G=0 St Data Buffer full\0reserved\0";

/// Flag values of the table entries.
const FLAGS: [u32; 7] = [0, 1, 2, 5, 11, 40, 685];

fn entry(packed: u16) -> (Name, u32) {
    (Name(packed & 0x1fff), FLAGS[usize::from(packed >> 13)])
}

/// Events of processor units 0..3 (stock names 0x91f0eef4, flags
/// 0x91f9b5a8), `UNIT_EVENTS` per unit.
const UNIT_TABLE: [u16; 76] = [
    0x21a5, 0xa1b9, 0x21c9, 0xa1dd, 0x21ec, 0x8201, 0x2220, 0x2239, 0x224b, 0xa268, 0x227a, 0x2287,
    0x229f, 0x22c2, 0x22f6, 0x2312, 0xa32d, 0x233b, 0x234d, 0x236a, 0x237e, 0xa39d, 0x23b0, 0x43c4,
    0xa3cf, 0xa3e0, 0xa3f8, 0x2416, 0x2439, 0x245c, 0xa46c, 0x2481, 0x2497, 0x24b7, 0x24c7, 0x0037,
    0x0037, 0x0037, 0x24d9, 0x24f5, 0x2514, 0x2533, 0x254d, 0x2566, 0x2582, 0x259d, 0x25b4, 0x25cc,
    0x25e5, 0x25fd, 0x2612, 0x2625, 0x2635, 0x2647, 0x0037, 0x0037, 0x0037, 0xa661, 0xa679, 0xa690,
    0xa6a8, 0xc6b5, 0x26c1, 0xa6d4, 0xa6e2, 0x26ee, 0x26ff, 0x6714, 0x671f, 0x0037, 0x0037, 0x0037,
    0x0037, 0x0037, 0x0037, 0x0037,
];
/// Events 19..31 of every unit (stock 0x91f0eec0, 0x91f9b174).
const COMMON_TABLE: [u16; 13] = [
    0x21ec, 0x2287, 0xa72b, 0x21ec, 0x2287, 0xa72b, 0x0037, 0x0037, 0x0037, 0x0037, 0x0037, 0x0037,
    0x0037,
];
/// Bus events in stock memory order: the L2 groups (0x91f9b9d0, 50 rows of
/// 8), then the CIU (0x91f9c650), NCU (0x91f9c6d0), BIU (0x91f9c750), and
/// alternate BIU (0x91f9c7d0) lanes.
const BUS_TABLE: [u16; 464] = [
    0x273c, 0x2759, 0xc76f, 0xc78d, 0xc7aa, 0xc7bc, 0x27d7, 0x27ec, 0x27f4, 0x2817, 0x283a, 0x284e,
    0x286a, 0x287e, 0x2896, 0x28b1, 0x28d5, 0x28e4, 0x28ee, 0x28ff, 0x2915, 0x2931, 0x2942, 0x286a,
    0x286a, 0x2967, 0xc97e, 0xc995, 0xc9ac, 0xa9c3, 0xa9d8, 0xa9ed, 0x2a02, 0x2a13, 0x2a28, 0x2a3a,
    0x2a4d, 0x2a65, 0x2a79, 0x2a8d, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2a02, 0x2ac3, 0xcad2, 0xcade, 0xcaea, 0x2af6, 0x2b0f, 0x2b30,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2b4e, 0x2b63, 0x2b78, 0xc97e, 0xc995, 0xc9ac, 0x2b8d, 0x2b9a,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2baa, 0x2bcb, 0x2be4, 0x2bfa,
    0x2c09, 0x2c18, 0xcc33, 0x2c44, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2c5d, 0x2c80, 0x2ca1, 0x2cbf,
    0x2a02, 0xccd2, 0x2cdf, 0x2cf3, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2cfe, 0x2d0f, 0x2d20, 0x2d31, 0x2d42, 0x2d53, 0x2d64, 0x2d75,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2d86, 0x2da0, 0x2dbc, 0x2dcf, 0x286a, 0x2de6, 0x2e02, 0x2e19,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0xae3b, 0xae4b, 0x2e67, 0xce81, 0xce9c, 0xceb2, 0xceca, 0x2ee1, 0xaef5, 0xaf05, 0x2f21, 0xcf3b,
    0xcf56, 0xcf6c, 0xcf84, 0x2f9b, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1,
    0x2aa1, 0x2aa1, 0x2aa1, 0x2aa1, 0x2faf, 0x2fc0, 0x2fe9, 0x3007, 0x2faf, 0x2fc0, 0x2fe9, 0x3007,
    0x302e, 0x303f, 0x3068, 0x3086, 0x30ad, 0x30be, 0x30e7, 0x3105, 0x312c, 0x3140, 0x3156, 0x316f,
    0x318b, 0x31a7, 0x31c4, 0x31de, 0x31f4, 0x320f, 0x322c, 0x3248, 0x3261, 0x3276, 0x328a, 0x32a3,
    0x32bc, 0x32bc, 0x32d5, 0x32f3, 0x3310, 0x3335, 0x3351, 0x336f, 0x338c, 0x33ad, 0x33d0, 0x33ec,
    0x3403, 0x3417, 0x3430, 0x3430, 0x3448, 0x3463, 0x347d, 0x3494, 0x34aa, 0x34c3, 0x34dd, 0x34f6,
    0x3514, 0x352f, 0x354c, 0x3560, 0x357b, 0x35a0, 0x35be, 0x35be,
];
const CIU_EVENTS: usize = 400;
const NCU_EVENTS: usize = 416;
const BIU_EVENTS: usize = 432;
const BIU_ALTERNATE_EVENTS: usize = 448;

/// Processor unit per 3-bit selection of each select register slot pair
/// (stock 0x91f9b4a8); unit 5 has no event names.
const UNITS: [[u8; 8]; 4] = [
    [0, 1, 2, 5, 3, 5, 5, 5],
    [0, 1, 2, 2, 3, 5, 5, 5],
    [0, 1, 2, 2, 3, 5, 5, 5],
    [0, 1, 2, 5, 3, 5, 5, 5],
];

/// Thread of each slot pair per 2-bit selection (stock 0x91f9c878): 0 and
/// 1 a hardware thread, 2 both.
const THREADS: [[u8; 4]; 4] = [[0, 1, 1, 2], [0, 1, 0, 1], [1, 0, 0, 1], [1, 0, 0, 2]];

/// Counter inputs per group of four counters (stock 0x91f9c888): source,
/// first lane, last lane, input of the first lane.
const ROUTING: [[u8; 4]; COUNTERS] = [
    [0, 0, 7, 0],
    [1, 0, 7, 8],
    [3, 0, 3, 16],
    [3, 4, 15, 20],
    [0, 0, 7, 0],
    [2, 0, 7, 8],
    [3, 0, 3, 16],
    [3, 4, 15, 20],
    [1, 0, 7, 0],
    [2, 0, 7, 8],
    [3, 4, 15, 16],
    [4, 0, 3, 28],
    [0, 0, 7, 0],
    [3, 0, 3, 8],
    [3, 4, 15, 12],
    [4, 0, 7, 24],
];

/// Select register values of the setups (SPR 0x3fa).
const SETUP_SELECTS: [u64; 16] = [
    0x000873c8c8682000,
    0x03082d498e562000,
    0x04483a0d0a562000,
    0x0b8a191190925000,
    0x0b907c531a8ef000,
    0x0b9252d31a9cf000,
    0x1498aa45ec309000,
    0x14a973cb9e2f8000,
    0x14a9b1ccce2f8000,
    0x14a9be0d2a2f8000,
    0x2321b880021cf000,
    0x26395880c20b5000,
    0x37295881120e8000,
    0x492b191990171000,
    0x4e7b52db1a172000,
    0x843421a10c562000,
];
/// L2 group register values of the setups (PMW 0x310).
const SETUP_GROUPS: [u64; 5] = [
    0x0002000002000000,
    0x1000000000100000,
    0x1000000000200000,
    0x1000000002000000,
    0x8000000002000000,
];
/// Counter routes of the setups: source in the high nibble, lane in the
/// low nibble.
const SETUP_ROUTES: [[u8; COUNTERS]; 9] = [
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x34, 0x35, 0x36, 0x37, 0x30, 0x31, 0x32,
        0x33,
    ],
    [
        0x00, 0x01, 0x12, 0x13, 0x24, 0x25, 0x06, 0x07, 0x34, 0x35, 0x36, 0x37, 0x30, 0x31, 0x32,
        0x33,
    ],
    [
        0x10, 0x11, 0x12, 0x13, 0x30, 0x31, 0x32, 0x33, 0x14, 0x15, 0x16, 0x17, 0x34, 0x35, 0x36,
        0x37,
    ],
    [
        0x10, 0x11, 0x12, 0x13, 0x38, 0x39, 0x33, 0x3b, 0x14, 0x15, 0x16, 0x17, 0x3c, 0x3d, 0x3e,
        0x3f,
    ],
    [
        0x30, 0x31, 0x32, 0x33, 0x00, 0x01, 0x02, 0x03, 0x34, 0x35, 0x36, 0x37, 0x04, 0x05, 0x06,
        0x07,
    ],
    [
        0x30, 0x31, 0x32, 0x33, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x34, 0x35, 0x36,
        0x37,
    ],
    [
        0x38, 0x39, 0x34, 0x3b, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x3c, 0x3d, 0x3e,
        0x3f,
    ],
    [
        0x3c, 0x30, 0x31, 0x32, 0x24, 0x25, 0x22, 0x23, 0x14, 0x15, 0x12, 0x13, 0x04, 0x05, 0x02,
        0x03,
    ],
    [
        0x3c, 0x32, 0x33, 0x34, 0x20, 0x21, 0x22, 0x23, 0x10, 0x11, 0x12, 0x13, 0x00, 0x01, 0x02,
        0x03,
    ],
];
/// Setups: select index (bits 0..3), group index (4..6), routes (8..11).
const SETUPS: [u16; 45] = [
    0x0032, 0x003c, 0x0232, 0x023c, 0x0532, 0x053c, 0x0036, 0x0236, 0x0536, 0x0839, 0x0030, 0x003a,
    0x0230, 0x023a, 0x0530, 0x053a, 0x0031, 0x003b, 0x0231, 0x023b, 0x0531, 0x053b, 0x0033, 0x003d,
    0x0233, 0x023d, 0x0533, 0x053d, 0x0035, 0x003e, 0x0235, 0x023e, 0x0535, 0x053e, 0x0034, 0x0034,
    0x0234, 0x0234, 0x0534, 0x0534, 0x0707, 0x0448, 0x0328, 0x0618, 0x013f,
];

/// High word of a counter control register (PRV 0x280 + 8 * counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterControl(pub u32);

impl CounterControl {
    /// Value after the monitor resets the counters (stock 0x91f91800).
    pub const RESET: Self = Self(0x0200_0000);
    const ROUTED: u32 = 0x0400_0000;
    const CYCLES: u32 = 0x0100_0000;

    /// The input the counter is routed to.
    pub fn input(self) -> Option<u32> {
        (self.0 & Self::ROUTED != 0).then_some(self.0 >> 27)
    }

    pub fn counts_cycles(self) -> bool {
        self.0 & Self::CYCLES != 0
    }

    pub fn with_cycles(self, cycles: bool) -> Self {
        if cycles {
            Self(self.0 | Self::CYCLES)
        } else {
            Self(self.0 & !Self::CYCLES)
        }
    }

    /// Route the counter to `input` (stock 0x91f91f20).
    pub fn routed(self, input: u32) -> Self {
        Self(self.0 & 0x00ff_ffff | input << 27 | 0x0600_0000)
    }
}

/// A performance monitor bus register (PMW).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusRegister(pub u32);

impl BusRegister {
    /// Lane sources of the bus units, in the order stock decodes them.
    pub const NCU1: Self = Self(0x580);
    pub const NCU2: Self = Self(0x680);
    pub const NCU0: Self = Self(0x480);
    pub const CIU: Self = Self(0x708);
    pub const BIU: Self = Self(0xb50);
    /// L2 event group selection.
    pub const L2_GROUP: Self = Self(0x310);
    pub const L2: Self = Self(0x318);
}

/// Registers the event decoding reads.
pub trait Registers {
    /// Event select register (SPR 0x3fa).
    fn select(&mut self) -> u64;
    fn bus(&mut self, register: BusRegister) -> u64;
}

/// Where a counter input comes from (stock 0x91f9b5d0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Slot `slot` of the event select register on processor bus `bus`.
    Processor { bus: u8, slot: u8 },
    /// Lane of the bus units.
    Bus(u8),
    /// External interface, which has no names.
    External,
}

fn source(counter: usize, input: u32) -> Source {
    let input = input as u8;
    let processor = |bus, first| Source::Processor {
        bus,
        slot: input - first,
    };
    match (counter / 4, input) {
        (0 | 1 | 3, 0..=7) => processor(0, 0),
        (2, 0..=7) => processor(1, 0),
        (0, 8..=15) => processor(1, 8),
        (1 | 2, 8..=15) => processor(2, 8),
        (0 | 1, _) => Source::Bus(input - 16),
        (2, 16..=27) => Source::Bus(input - 12),
        (3, 8..=23) => Source::Bus(input - 8),
        _ => Source::External,
    }
}

/// Shift of the 5-bit event field of each select register slot.
const EVENT_SHIFTS: [u32; 8] = [56, 51, 43, 38, 30, 25, 17, 12];
/// Shift of the unit selection of each slot pair.
const UNIT_SHIFTS: [u32; 4] = [3, 16, 29, 42];

/// How stock returns a counter's event name: most point into the tables;
/// L2 events are copied into a static buffer first (0x91faaee8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventName {
    Table(Name),
    Formatted(Name),
}

impl EventName {
    pub fn name(self) -> Name {
        match self {
            Self::Table(name) | Self::Formatted(name) => name,
        }
    }
}

/// A counter's event: its name and table flag (stock 0x91f910f8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub name: EventName,
    pub flag: u32,
}

impl Event {
    fn table((name, flag): (Name, u32)) -> Self {
        Self {
            name: EventName::Table(name),
            flag,
        }
    }

    /// Names without an entry keep the flag stock initializes to 1.
    fn fixed(name: Name) -> Self {
        Self {
            name: EventName::Table(name),
            flag: 1,
        }
    }
}

/// Decode the event counter `counter` counts.
pub fn event(counter: usize, control: CounterControl, registers: &mut dyn Registers) -> Event {
    let Some(input) = control.input() else {
        return Event::fixed(COUNTER_DISABLED);
    };
    match source(counter, input) {
        Source::Processor { slot, .. } => processor_event(registers.select(), slot),
        Source::Bus(lane) => bus_event(lane, registers),
        Source::External => Event::fixed(UNKNOWN_SOURCE),
    }
}

fn processor_event(select: u64, slot: u8) -> Event {
    let pair = usize::from(slot / 2);
    let event = (select >> EVENT_SHIFTS[usize::from(slot)]) as u32 & 0x1f;
    let unit = UNITS[pair][(select >> UNIT_SHIFTS[pair]) as usize & 7];
    if event >= UNIT_EVENTS {
        Event::table(entry(COMMON_TABLE[(event - UNIT_EVENTS) as usize]))
    } else if unit < 4 {
        Event::table(entry(
            UNIT_TABLE[usize::from(unit) * UNIT_EVENTS as usize + event as usize],
        ))
    } else {
        // Stock reads the name table of unit 5 past its end and dereferences
        // string bytes as a pointer.
        Event::fixed(INVALID_EVENT)
    }
}

/// Index of `lane` among the lanes a bus unit drives (stock 0x91f90be0).
fn lane_index(lane: u8, rotation: u32, mask: u32) -> Option<u32> {
    let bit = (0x8000u32 >> lane) & 0xffff;
    if bit & mask == 0 {
        return None;
    }
    let low = ((1u32 << (rotation + 1)).wrapping_add(0xffff) & bit) << (16 - rotation) & 0xffff;
    Some(((bit >> rotation) | low).leading_zeros() - 16)
}

/// Lane `lane` of the bus units (stock 0x91f90cb8). Each active unit
/// replaces the remembered index, also when it does not drive this lane;
/// stock then reads the entry before the unit's table, which `BUS_TABLE`
/// keeps in stock order.
fn bus_event(lane: u8, registers: &mut dyn Registers) -> Event {
    const UNITS: [(BusRegister, Option<Name>); 4] = [
        (BusRegister::NCU1, None),
        (BusRegister::NCU2, Some(NCU2_COLLISION)),
        (BusRegister::NCU0, Some(NCU0_COLLISION)),
        (BusRegister::CIU, Some(CIU_COLLISION)),
    ];
    const TABLES: [usize; 4] = [NCU_EVENTS, NCU_EVENTS, NCU_EVENTS, CIU_EVENTS];
    let mut table: Option<usize> = None;
    let mut index: isize = 0;
    for (unit, (register, name)) in UNITS.into_iter().enumerate() {
        let value = (registers.bus(register) >> 32) as u32;
        let mask = (value >> 8) & 0xffff;
        if value & 0x8000_0000 == 0 || mask == 0 {
            continue;
        }
        let slot = lane_index(lane, (value >> 4) & 0xf, mask);
        index = slot.map_or(-1, |slot| slot as isize);
        if slot.is_some() {
            if let (Some(_), Some(name)) = (table, name) {
                return Event::fixed(name);
            }
            table = Some(TABLES[unit]);
        }
    }
    let biu = (registers.bus(BusRegister::BIU) >> 32) as u32;
    let alternate = biu & 0x0100_0000 != 0;
    let biu_table = if alternate {
        BIU_ALTERNATE_EVENTS
    } else {
        BIU_EVENTS
    };
    let mask = (biu >> 8) & 0xffff;
    if biu & 0x8000_0000 != 0 && mask != 0 {
        if alternate && (0x8000u32 >> lane) & (biu >> 8) != 0 {
            if table.is_some() {
                return Event::fixed(BIU_ALT_COLLISION);
            }
            index = isize::from(lane);
            table = Some(biu_table);
        } else {
            let slot = lane_index(lane, (biu >> 4) & 0xf, mask);
            index = slot.map_or(-1, |slot| slot as isize);
            if slot.is_some() {
                if table.is_some() {
                    return Event::fixed(BIU_COLLISION);
                }
                table = Some(biu_table);
            }
        }
    }
    let group = registers.bus(BusRegister::L2_GROUP);
    let l2 = registers.bus(BusRegister::L2) as u32;
    if l2 & 0x1_0000 != 0 && (0x8000u32 >> lane) & l2 != 0 {
        if table.is_some() {
            return Event::fixed(L2_COLLISION);
        }
        let (row, column) = if lane < 8 {
            (group.leading_zeros(), lane)
        } else {
            ((group << 25).leading_zeros() + 25, lane - 8)
        };
        if row > 0x31 {
            return Event::fixed(L2_GROUP_UNSET);
        }
        let (name, flag) = entry(BUS_TABLE[row as usize * 8 + usize::from(column)]);
        return Event {
            name: EventName::Formatted(name),
            flag,
        };
    }
    match table {
        Some(table) => Event::table(entry(BUS_TABLE[table.wrapping_add_signed(index)])),
        None => Event::fixed(NO_EVENT),
    }
}

/// Hardware thread whose events a counter counts (stock 0x91f90fd8): 0 or
/// 1, 2 for both or an unrouted counter, 3 for the bus units and the
/// external interface.
pub fn thread(counter: usize, control: CounterControl, registers: &mut dyn Registers) -> u8 {
    let Some(input) = control.input() else {
        return 2;
    };
    match source(counter, input) {
        Source::Processor { slot, .. } => {
            let pair = usize::from(slot / 2);
            THREADS[pair][(registers.select() >> UNIT_SHIFTS[pair]) as usize & 3]
        }
        Source::Bus(_) | Source::External => 3,
    }
}

/// Source class of a counter (stock export 210, 0x91f91320): processor
/// bus times two, plus one when bound to one thread; 6 for the bus units;
/// 7 for the external interface or an unrouted counter.
pub fn source_class(counter: usize, control: CounterControl, registers: &mut dyn Registers) -> u32 {
    let Some(input) = control.input() else {
        return 7;
    };
    let source = source(counter, input);
    let bound = u32::from(thread(counter, control, registers) != 0);
    match source {
        Source::Processor { bus, .. } => u32::from(bus) * 2 + bound,
        Source::Bus(_) => 6,
        Source::External => 7,
    }
}

/// Label of a routed counter's source in the statistics printout (stock
/// 0x91f92438).
pub fn source_label(counter: usize, input: u32) -> &'static core::ffi::CStr {
    match source(counter, input) {
        Source::Processor { bus: 0, .. } => c"PB0",
        Source::Processor { bus: 1, .. } => c"PB1",
        Source::Processor { .. } => c"PB2",
        Source::Bus(_) => c"PMW",
        Source::External => c"XIF",
    }
}

/// Input of counter `counter` for lane `lane` of `source` (stock
/// 0x91f91f20).
pub fn route(source: u32, lane: u8, counter: usize) -> Option<u32> {
    ROUTING[counter & !3..][..4]
        .iter()
        .find_map(|&[row_source, first, last, input]| {
            (u32::from(row_source) == source && (first..=last).contains(&lane))
                .then(|| u32::from(input) - u32::from(first) + u32::from(lane))
        })
}

/// Bus register values that make `unit` drive the lanes (stock
/// 0x91f91d80): 0 NCU1, 1 NCU2, 2 NCU0, 3 BIU, 4 CIU, 5 L2.
pub fn bus_selection(unit: u32) -> [(BusRegister, u64); 6] {
    let source = |register, selected: u32| {
        let value: u32 = if unit == selected {
            0xffc0_ffff
        } else {
            0xff80_0000
        };
        (register, u64::from(value << 8) << 32)
    };
    let l2 = if unit == 5 {
        0x8000_0000_0001_ffff
    } else {
        0x1_0000
    };
    [
        source(BusRegister::BIU, 3),
        source(BusRegister::NCU0, 2),
        source(BusRegister::NCU1, 0),
        source(BusRegister::NCU2, 1),
        source(BusRegister::CIU, 4),
        (BusRegister::L2, l2),
    ]
}

/// Whether a counter counts committed instructions (stock export 205,
/// 0x91f921a8, compares the name addresses).
pub fn counts_instructions(name: EventName) -> bool {
    name == EventName::Table(INSTRUCTIONS)
}

/// A counter value as stock export 205 reports it: the instruction
/// counters and the cycle counter of busy machines count every other event.
pub fn reported(name: EventName, value: u64) -> u64 {
    let mut value = value;
    if let EventName::Table(INSTRUCTIONS | FP_INSTRUCTIONS | INT_INSTRUCTIONS | VSU_INSTRUCTIONS) =
        name
    {
        value <<= 1;
    }
    if name.name() == RC_BUSY {
        value <<= 1;
    }
    value
}

/// A counter route of a setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub source: u32,
    pub lane: u8,
}

/// A counter configuration (stock layout 0x98 bytes: select register,
/// L2 group, trigger, then 16 routes of a source word and a lane byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setup {
    /// Event select register (SPR 0x3fa).
    pub select: u64,
    /// L2 group register (PMW 0x310).
    pub group: u64,
    pub trigger: u32,
    pub routes: [Route; COUNTERS],
}

/// Built-in setup `index`.
pub fn setup(index: u32) -> Option<Setup> {
    let packed = *SETUPS.get(index as usize)?;
    let routes = &SETUP_ROUTES[usize::from(packed >> 8)];
    Some(Setup {
        select: SETUP_SELECTS[usize::from(packed & 0xf)],
        group: SETUP_GROUPS[usize::from((packed >> 4) & 7)],
        trigger: 3,
        routes: core::array::from_fn(|counter| Route {
            source: u32::from(routes[counter] >> 4),
            lane: routes[counter] & 0xf,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Registers after a setup is installed: the setup's select and group
    /// values, the L2 unit driving the bus.
    struct Installed(Setup);

    impl Registers for Installed {
        fn select(&mut self) -> u64 {
            self.0.select
        }

        fn bus(&mut self, register: BusRegister) -> u64 {
            if register == BusRegister::L2_GROUP {
                return self.0.group;
            }
            bus_selection(5)
                .into_iter()
                .find(|&(selected, _)| selected == register)
                .map_or(0, |(_, value)| value)
        }
    }

    /// Expected names come from evaluating stock's tables at their stock
    /// addresses; counters whose unit is 5 read past stock's name table and
    /// decode as the invalid event here.
    #[test]
    fn built_in_setups_decode_to_stock_names() {
        type SetupCase = (u32, [(&'static [u8], u32); COUNTERS]);
        let cases: [SetupCase; 3] = [
            (
                0,
                [
                    (b"Ci-cache miss cycles\0".as_slice(), 1),
                    (b"Epipeline flushes\0".as_slice(), 40),
                    (b"** INVALID EVENT **\0".as_slice(), 1),
                    (b"** INVALID EVENT **\0".as_slice(), 1),
                    (b"Cinstructions committed\0".as_slice(), 1),
                    (b"Eu-code instructions committed\0".as_slice(), 11),
                    (b"** INVALID EVENT **\0".as_slice(), 1),
                    (b"** INVALID EVENT **\0".as_slice(), 1),
                    (b"Ecore 2 L2 data misses\0".as_slice(), 685),
                    (b"Ecore 0 L2 data hits\0".as_slice(), 40),
                    (b"Ecore 1 L2 data hits\0".as_slice(), 40),
                    (b"Ecore 2 L2 data hits\0".as_slice(), 40),
                    (b"Call RC busy cycles\0".as_slice(), 1),
                    (b"CRC machine dispatches\0".as_slice(), 1),
                    (b"Ecore 0 L2 data misses\0".as_slice(), 685),
                    (b"Ecore 1 L2 data misses\0".as_slice(), 685),
                ],
            ),
            (
                7,
                [
                    (b"Cinstructions committed\0".as_slice(), 1),
                    (b"Ci-cache miss cycles\0".as_slice(), 1),
                    (b"Eload misses (S)\0".as_slice(), 40),
                    (b"Epipeline flushes\0".as_slice(), 40),
                    (b"Call RC busy cycles\0".as_slice(), 1),
                    (b"CRC machine dispatches\0".as_slice(), 1),
                    (b"Ecore 0 L2 data misses\0".as_slice(), 685),
                    (b"Ecore 1 L2 data misses\0".as_slice(), 685),
                    (b"Cinstructions committed\0".as_slice(), 1),
                    (b"Ci-cache miss cycles\0".as_slice(), 1),
                    (b"Eload misses (S)\0".as_slice(), 40),
                    (b"SVMX store committed (S)\0".as_slice(), 1),
                    (b"Ecore 2 L2 data misses\0".as_slice(), 685),
                    (b"Ecore 0 L2 data hits\0".as_slice(), 40),
                    (b"Ecore 1 L2 data hits\0".as_slice(), 40),
                    (b"Ecore 2 L2 data hits\0".as_slice(), 40),
                ],
            ),
            (
                30,
                [
                    (b"Cinstructions committed\0".as_slice(), 1),
                    (b"CVIQ dependency stall cycles\0".as_slice(), 1),
                    (b"ESPR reads\0".as_slice(), 5),
                    (b"ESPR writes\0".as_slice(), 5),
                    (b"Call RC busy cycles\0".as_slice(), 1),
                    (b"CRC machine dispatches\0".as_slice(), 1),
                    (b"Ecore 0 L2 data misses\0".as_slice(), 685),
                    (b"Ecore 1 L2 data misses\0".as_slice(), 685),
                    (b"Cexternal interrupt pending cycles\0".as_slice(), 1),
                    (
                        b"Cexternal interrupt pending hardware latency cycles\0".as_slice(),
                        1,
                    ),
                    (b"** INVALID EVENT **\0".as_slice(), 0),
                    (b"** INVALID EVENT **\0".as_slice(), 0),
                    (b"Ecore 2 L2 data misses\0".as_slice(), 685),
                    (b"Ecore 0 L2 data hits\0".as_slice(), 40),
                    (b"Ecore 1 L2 data hits\0".as_slice(), 40),
                    (b"Ecore 2 L2 data hits\0".as_slice(), 40),
                ],
            ),
        ];
        for (index, expected) in cases {
            let setup = setup(index).unwrap();
            let mut registers = Installed(setup);
            for (counter, (text, flag)) in expected.into_iter().enumerate() {
                let Route { source, lane } = setup.routes[counter];
                let control = route(source, lane, counter).map_or(CounterControl::RESET, |input| {
                    CounterControl::RESET.routed(input)
                });
                let event = event(counter, control, &mut registers);
                assert_eq!(
                    (event.name.name().text(), event.flag),
                    (text, flag),
                    "setup {index} counter {counter}"
                );
            }
        }
    }

    struct Bus(&'static [(BusRegister, u64)]);

    impl Registers for Bus {
        fn select(&mut self) -> u64 {
            0
        }

        fn bus(&mut self, register: BusRegister) -> u64 {
            self.0
                .iter()
                .find(|&&(selected, _)| selected == register)
                .map_or(0, |&(_, value)| value)
        }
    }

    /// Bus unit decoding against stock's tables, including the stale lane
    /// index a later unit leaves behind, a collision, and both BIU modes.
    #[test]
    fn bus_lanes_decode_to_stock_names() {
        type LaneCase = (&'static [(BusRegister, u64)], u8, &'static [u8]);
        let cases: [LaneCase; 9] = [
            (
                &[
                    (BusRegister::NCU1, 0x80f0000000000000),
                    (BusRegister::CIU, 0x800f002000000000),
                ],
                0,
                b"ECIU Load Req to L2 canceled by LHS P2\0".as_slice(),
            ),
            (
                &[
                    (BusRegister::NCU1, 0x80f0000000000000),
                    (BusRegister::CIU, 0x800f002000000000),
                ],
                1,
                b"ECIU Load Req to L2 canceled by LHS P2\0".as_slice(),
            ),
            (
                &[
                    (BusRegister::NCU1, 0x80f0000000000000),
                    (BusRegister::CIU, 0x800f002000000000),
                ],
                5,
                b"ECIU Load Req to L2 canceled by LHS P0\0".as_slice(),
            ),
            (
                &[
                    (BusRegister::NCU1, 0x80f0000000000000),
                    (BusRegister::CIU, 0x800f002000000000),
                ],
                6,
                b"CCIU STQ Full P1\0".as_slice(),
            ),
            (
                &[
                    (BusRegister::NCU2, 0x8020001000000000),
                    (BusRegister::NCU0, 0x8020003000000000),
                ],
                2,
                b"ERROR - NCU0 multiple events on this lane!\0".as_slice(),
            ),
            (
                &[(BusRegister::BIU, 0x8100ff0000000000)],
                9,
                b"C NCU St Cmd q not empty (5)\0".as_slice(),
            ),
            (
                &[(BusRegister::BIU, 0x8100ff0000000000)],
                12,
                b"C Push/Intervention Data Buffer full\0".as_slice(),
            ),
            (
                &[(BusRegister::BIU, 0x800f001000000000)],
                4,
                b"C393 All 3 stations stalled\0".as_slice(),
            ),
            (
                &[(BusRegister::BIU, 0x800f001000000000)],
                5,
                b"E394 Rcv 8-beat data from MPi\0".as_slice(),
            ),
        ];
        for (registers, lane, text) in cases {
            let control = CounterControl::RESET.routed(u32::from(lane) + 16);
            let event = event(0, control, &mut Bus(registers));
            assert_eq!(event.name.name().text(), text, "lane {lane}");
        }
    }
}
