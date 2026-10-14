//! Instruction trace stream (stock 0x91f671e8-0x91f67e90): the encoder the
//! single-step handler runs for each traced instruction, and the memory
//! map record of the trace file header.
//!
//! The stream is a sequence of big-endian words. An instruction word is
//! written the first time its address misses the lookup cache, followed by
//! the effective address (and for string and touch forms a third word) of
//! storage accesses. Branches and traps are deferred until the next traced
//! address, which is written after the branch word.

/// First word of a trace file.
pub const TRACE_MAGIC: u32 = u32::from_be_bytes(*b"TRAC");
/// Second word of a trace file.
pub const TRACE_VERSION: u32 = 3;
/// Tag of the module snapshot record; the snapshot follows in
/// [`MODULE_WORDS`] words.
pub const MODULE_MAGIC: u32 = u32::from_be_bytes(*b"MODL");
pub const MODULE_WORDS: u32 = 0x3000;
/// Tag of the memory map record; a word count and
/// [`write_memory_map`] entries follow.
pub const MAP_MAGIC: u32 = u32::from_be_bytes(*b"MMAP");
/// Words of the address lookup cache: two-way sets of address words with
/// the most recently used way marked in bit 0.
pub const CACHE_WORDS: usize = 0x4000;
/// Address mismatches kept for the stop report.
pub const MISMATCH_CAPACITY: usize = 30;

/// `blr`, which ends the walk of a function the handler runs natively.
pub const BLR: u32 = 0x4e80_0020;
/// Address written when the traced code returns out of the recorded
/// function, and the branch word deferred with it.
const LEFT_RECORDED_FUNCTION: u32 = 0xffff_fffc;
const LEFT_RECORDED_BRANCH: u32 = 0x4800_0001;
/// `VirtualQuery` state of committed pages.
const MEM_COMMIT: u32 = 0x1000;

/// The traced thread at a trace exception.
pub trait Thread {
    /// The instruction word at `address`.
    fn instruction(&self, address: u32) -> u32;
    /// Low word of general register `index`.
    fn gpr(&self, index: u32) -> u32;
    fn xer(&self) -> u32;
}

/// Destination of stream words.
pub trait Sink {
    fn push(&mut self, word: u32);
}

/// A traced address that did not follow from the previous instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mismatch {
    /// Recorded instruction count at the mismatch.
    pub instruction: u64,
    pub expected: u32,
    pub found: u32,
}

/// Encoder state (stock 0x91fa2e78-0x91fa30a0).
#[derive(Debug, Clone)]
pub struct Encoder {
    total: u64,
    recorded: u64,
    depth: u32,
    start: Option<u32>,
    record_nested: bool,
    expected: Option<u32>,
    return_pending: bool,
    call_pending: bool,
    after_trap: Option<u32>,
    first_written: bool,
    deferred: bool,
    deferred_word: u32,
    deferred_address: u32,
    mismatch_count: u32,
    mismatches: [Mismatch; MISMATCH_CAPACITY],
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Mark `address` most recently used in its set; true when it was absent
/// (stock 0x91f67510).
fn cache_miss(cache: &mut [u32; CACHE_WORDS], address: u32) -> bool {
    let index = ((address & 0x7ffc) >> 1) as usize;
    let (first, second) = (cache[index], cache[index + 1]);
    let (first_address, second_address) = (first & !1, second & !1);
    let (first, second, miss) = if first_address == address {
        (first | 1, second_address, false)
    } else if second_address == address {
        (first_address, second | 1, false)
    } else if first & 1 == 0 {
        (address | 1, second_address, true)
    } else {
        (first_address, address | 1, true)
    };
    cache[index] = first;
    cache[index + 1] = second;
    miss
}

fn sign_extend(word: u32) -> u32 {
    word as u16 as i16 as i32 as u32
}

/// Extended opcodes of primary opcode 4 (masked with 0x7f3) that address
/// storage with `RA|0 + RB`.
const VECTOR_INDEXED: [u16; 14] = [
    0x83, 0xc3, 0x183, 0x1c3, 0x2c3, 0x3c3, 0x403, 0x443, 0x503, 0x543, 0x603, 0x643, 0x703, 0x743,
];

/// Extended opcodes of primary opcode 31 that address storage with
/// `RA|0 + RB`.
const INDEXED: [u16; 70] = [
    0x7, 0x14, 0x15, 0x17, 0x27, 0x35, 0x36, 0x37, 0x47, 0x54, 0x56, 0x57, 0x67, 0x77, 0x87, 0x95,
    0x96, 0x97, 0xa7, 0xb5, 0xb7, 0xc7, 0xd6, 0xd7, 0xe7, 0xf6, 0xf7, 0x116, 0x117, 0x132, 0x137,
    0x152, 0x155, 0x157, 0x167, 0x172, 0x175, 0x177, 0x197, 0x1b2, 0x1b7, 0x1d2, 0x1d6, 0x1e7,
    0x1f2, 0x207, 0x216, 0x217, 0x227, 0x236, 0x237, 0x257, 0x277, 0x287, 0x296, 0x297, 0x2a7,
    0x2b7, 0x2d7, 0x2f7, 0x307, 0x316, 0x327, 0x376, 0x387, 0x396, 0x3a7, 0x3d6, 0x3d7, 0x3f6,
];

/// Words of one instruction record: the instruction, then its storage
/// operands.
struct Operands {
    words: [u32; 3],
    count: usize,
}

enum Class {
    /// Written when the next traced address is known.
    Deferred,
    Plain(Operands),
}

fn classify(word: u32, thread: &impl Thread) -> Class {
    let opcode = word >> 26;
    let extended = (word >> 1) & 0x3ff;
    let ra = (word >> 16) & 0x1f;
    let rb = (word >> 11) & 0x1f;
    let base = || if ra != 0 { thread.gpr(ra) } else { 0 };
    let indexed = || thread.gpr(rb).wrapping_add(base());
    let mut operands = Operands {
        words: [word, 0, 0],
        count: 1,
    };
    let mut set = |values: &[u32]| {
        operands.words[1..=values.len()].copy_from_slice(values);
        operands.count = 1 + values.len();
    };
    match opcode {
        2 | 3 | 0x10..=0x12 => return Class::Deferred,
        0x13 if matches!(
            extended,
            0x4 | 0x10 | 0x12 | 0x32 | 0x33 | 0x44 | 0x52 | 0x210
        ) =>
        {
            return Class::Deferred;
        }
        4 if VECTOR_INDEXED.contains(&((word & 0x7f3) as u16)) => set(&[indexed()]),
        0x1f => match extended {
            0x4 | 0x24 => return Class::Deferred,
            // String forms carry the byte count from XER.
            0x215 | 0x235 | 0x295 | 0x2b5 => set(&[indexed(), thread.xer() & 0x7f]),
            0x156 | 0x176 => set(&[indexed(), 0]),
            0x255 | 0x275 | 0x2d5 | 0x2f5 => set(&[base()]),
            _ if INDEXED.contains(&(extended as u16)) => set(&[indexed()]),
            _ => {}
        },
        0x20..=0x39 | 0x3c | 0x3d => set(&[base().wrapping_add(sign_extend(word))]),
        0x3a | 0x3e => {
            let offset = sign_extend(word) & !3;
            // The update form adds RA even when it names r0.
            let address = if word & 3 == 1 || ra != 0 {
                thread.gpr(ra).wrapping_add(offset)
            } else {
                offset
            };
            set(&[address]);
        }
        _ => {}
    }
    Class::Plain(operands)
}

impl Encoder {
    pub const fn new() -> Self {
        Self {
            total: 0,
            recorded: 0,
            depth: 0,
            start: None,
            record_nested: false,
            expected: None,
            return_pending: false,
            call_pending: false,
            after_trap: None,
            first_written: false,
            deferred: false,
            deferred_word: 0,
            deferred_address: 0,
            mismatch_count: 0,
            mismatches: [Mismatch {
                instruction: 0,
                expected: 0,
                found: 0,
            }; MISMATCH_CAPACITY],
        }
    }

    /// Instructions the handler saw since [`Encoder::arm`].
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Instructions written to the stream.
    pub fn recorded(&self) -> u64 {
        self.recorded
    }

    /// Whether a branch waits for its target (stock 0x91f67120).
    pub fn deferred(&self) -> bool {
        self.deferred
    }

    /// Mismatches seen and the kept ones (stock 0x91f67138 reads them).
    pub fn mismatches(&self) -> (u32, &[Mismatch]) {
        let kept = (self.mismatch_count as usize).min(MISMATCH_CAPACITY);
        (self.mismatch_count, &self.mismatches[..kept])
    }

    pub fn clear_mismatches(&mut self) {
        self.mismatch_count = 0;
    }

    /// Reset the call depth (session start, stock 0x91f665e0).
    pub fn reset_depth(&mut self) {
        self.depth = 0;
    }

    /// Record only from `start` onward, and calls below it only with
    /// `record_nested` (export 134).
    pub fn set_start(&mut self, start: Option<u32>, record_nested: bool) {
        self.start = start;
        self.record_nested = record_nested;
    }

    /// Record from the first traced instruction again; the nested flag
    /// stays.
    pub fn clear_start(&mut self) {
        self.start = None;
    }

    /// Reset the stream state when the header is written (stock
    /// 0x91f673e8).
    pub fn begin(&mut self) {
        self.recorded = 0;
        self.after_trap = None;
        self.expected = None;
        self.mismatch_count = 0;
        self.call_pending = false;
        self.deferred = false;
        self.first_written = false;
        self.return_pending = false;
    }

    /// Reset the counters when single-stepping starts (stock 0x91f66138).
    pub fn arm(&mut self) {
        self.total = 0;
        self.recorded = 0;
    }

    /// Record the instruction at `iar`, about to execute (stock
    /// 0x91f67de8). The instruction after a system call or trap executes
    /// without a trace exception of its own; it is recorded before the
    /// next traced address unless execution continues there.
    pub fn record(
        &mut self,
        iar: u32,
        thread: &impl Thread,
        cache: &mut [u32; CACHE_WORDS],
        sink: &mut impl Sink,
    ) {
        if let Some(skipped) = self.after_trap
            && skipped != iar
        {
            self.encode(skipped, thread.instruction(skipped), thread, cache, sink);
        }
        let word = thread.instruction(iar);
        self.after_trap = None;
        self.encode(iar, word, thread, cache, sink);
        if matches!(word >> 26, 0x11 | 3) {
            self.after_trap = Some(iar.wrapping_add(4));
        }
    }

    /// Stock 0x91f67578.
    fn encode(
        &mut self,
        iar: u32,
        word: u32,
        thread: &impl Thread,
        cache: &mut [u32; CACHE_WORDS],
        sink: &mut impl Sink,
    ) {
        self.total = self.total.wrapping_add(1);
        let opcode = word >> 26;
        let extended = (word >> 1) & 0x3ff;
        let mut expected = self.expected;
        if self.call_pending || self.return_pending {
            if expected == Some(iar) {
                // The call or return was not taken.
                if self.call_pending {
                    self.depth = self.depth.wrapping_sub(1);
                } else {
                    self.depth = self.depth.wrapping_add(1);
                }
            } else if self.return_pending && self.depth == 0 {
                if self.deferred && cache_miss(cache, self.deferred_address) {
                    sink.push(self.deferred_word);
                }
                sink.push(LEFT_RECORDED_FUNCTION);
                self.deferred_address = LEFT_RECORDED_FUNCTION;
                self.deferred_word = LEFT_RECORDED_BRANCH;
            }
            self.call_pending = false;
            self.return_pending = false;
        }

        let mut record = true;
        if let Some(start) = self.start {
            if iar == start && self.depth == 0 {
                self.depth = 1;
                expected = Some(start);
            }
            if self.depth == 0 || (self.depth != 1 && !self.record_nested) {
                record = false;
            }
            if self.depth != 0 {
                if opcode == 0x13 && extended == 0x10 {
                    self.return_pending = true;
                    self.depth = self.depth.wrapping_sub(1);
                }
                let branch = matches!(opcode, 0x10 | 0x12)
                    || (opcode == 0x13 && matches!(extended, 0x10 | 0x210));
                if branch && word & 1 != 0 {
                    self.call_pending = true;
                    self.depth = self.depth.wrapping_add(1);
                }
            }
        }
        let expected = expected.unwrap_or(iar);
        self.expected = Some(iar.wrapping_add(4));
        if !record {
            return;
        }

        self.recorded = self.recorded.wrapping_add(1);
        if !self.deferred && expected != iar {
            if let Some(slot) = self.mismatches.get_mut(self.mismatch_count as usize) {
                *slot = Mismatch {
                    instruction: self.recorded,
                    expected,
                    found: iar,
                };
            }
            self.mismatch_count = self.mismatch_count.wrapping_add(1);
        }
        if !self.first_written {
            sink.push(iar);
            self.first_written = true;
        }
        if self.deferred {
            if cache_miss(cache, self.deferred_address) {
                sink.push(self.deferred_word);
            }
            sink.push(iar);
            self.deferred = false;
        }

        match classify(word, thread) {
            Class::Deferred => {
                self.deferred = true;
                self.deferred_word = word;
                self.deferred_address = iar;
            }
            Class::Plain(operands) => {
                let words = if cache_miss(cache, iar) {
                    &operands.words[..operands.count]
                } else {
                    &operands.words[1..operands.count]
                };
                for &word in words {
                    sink.push(word);
                }
            }
        }
    }
}

/// One `VirtualQuery` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub size: u32,
    pub state: u32,
    pub protect: u32,
}

/// Address space queries of the memory map record.
pub trait AddressSpace {
    /// `VirtualQuery`; `None` on failure.
    fn query(&mut self, address: u32) -> Option<Region>;
    /// `MmQueryAddressProtect`; 0 for unmapped addresses.
    fn protect(&mut self, address: u32) -> u32;
    /// `MmQueryAllocationSize` in bytes.
    fn allocation_size(&mut self, address: u32) -> u32;
}

/// Entries of the memory map record (stock 0x91f671e8): `{first page,
/// page count, protection}` for committed user regions below 0x80000000,
/// then runs of system allocations from 0xa0000000. System allocations
/// are walked in 64 KiB pages below 0xe0000000 and 4 KiB pages above;
/// every page of an allocation takes the protection of its first page.
pub fn write_memory_map(space: &mut impl AddressSpace, sink: &mut impl Sink) {
    let mut emit = |start: u32, count: u32, protect: u32| {
        sink.push(start);
        sink.push(count);
        sink.push(protect);
    };
    let mut page = 0u32;
    while page < 0x8_0000 {
        let mut step = 0x10;
        if let Some(region) = space.query(page << 12)
            && region.size != 0
        {
            step = region.size >> 12;
            if region.state == MEM_COMMIT {
                emit(page, step, region.protect);
            }
        }
        page = page.wrapping_add(step);
    }

    let (mut run_start, mut run_end, mut run_protect) = (0u32, 0u32, 0u32);
    let mut page = 0xa_0000u32;
    while page < 0x10_0000 {
        let address = page << 12;
        let system = address >= 0xe000_0000;
        let protect = space.protect(address);
        let pages = if protect != 0 {
            space.allocation_size(address) >> 12
        } else {
            0
        };
        let step = if pages == 0 {
            if system { 1 } else { 0x10 }
        } else {
            let granule = if system { 1 } else { 0x10 };
            let (mut done, mut cursor) = (0, page);
            while done < pages {
                let protect = space.protect(address);
                if run_start != run_end && !(run_end == cursor && run_protect == protect) {
                    emit(run_start, run_end.wrapping_sub(run_start), run_protect);
                    run_start = 0;
                    run_end = 0;
                }
                if run_start == run_end {
                    run_protect = protect;
                    run_start = cursor;
                    run_end = cursor;
                }
                done += granule;
                run_end = run_end.wrapping_add(granule);
                cursor = cursor.wrapping_add(granule);
            }
            pages
        };
        page = page.wrapping_add(step);
    }
    if run_end != run_start {
        emit(run_start, run_end.wrapping_sub(run_start), run_protect);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Words {
        words: [u32; 64],
        len: usize,
    }

    impl Words {
        fn new() -> Self {
            Self {
                words: [0; 64],
                len: 0,
            }
        }

        fn as_slice(&self) -> &[u32] {
            &self.words[..self.len]
        }
    }

    impl Sink for Words {
        fn push(&mut self, word: u32) {
            self.words[self.len] = word;
            self.len += 1;
        }
    }

    /// Code at 0x1000 and registers.
    struct Program {
        code: &'static [u32],
        gpr: [u32; 32],
        xer: u32,
    }

    impl Thread for Program {
        fn instruction(&self, address: u32) -> u32 {
            // Code outside the program reads as `li r3, 1`.
            self.code
                .get((address.wrapping_sub(0x1000) / 4) as usize)
                .copied()
                .unwrap_or(ADDI)
        }

        fn gpr(&self, index: u32) -> u32 {
            self.gpr[index as usize]
        }

        fn xer(&self) -> u32 {
            self.xer
        }
    }

    fn run(
        encoder: &mut Encoder,
        program: &Program,
        cache: &mut [u32; CACHE_WORDS],
        trace: &[u32],
    ) -> Words {
        let mut words = Words::new();
        for &iar in trace {
            encoder.record(iar, program, cache, &mut words);
        }
        words
    }

    const ADDI: u32 = 0x3860_0001; // li r3, 1
    const LWZ: u32 = 0x8064_0010; // lwz r3, 0x10(r4)
    const B_BACK: u32 = 0x4bff_fff8; // b -8

    #[test]
    fn loop_writes_instructions_once_and_addresses_every_pass() {
        let mut gpr = [0; 32];
        gpr[4] = 0x8000_0000;
        let program = Program {
            code: &[ADDI, LWZ, B_BACK],
            gpr,
            xer: 0,
        };
        let mut cache = [0; CACHE_WORDS];
        let mut encoder = Encoder::new();
        let words = run(
            &mut encoder,
            &program,
            &mut cache,
            &[0x1000, 0x1004, 0x1008, 0x1000, 0x1004, 0x1008, 0x1000],
        );
        assert_eq!(
            words.as_slice(),
            &[
                0x1000,
                ADDI,
                LWZ,
                0x8000_0010,
                // The branch word on its first use, then its target.
                B_BACK,
                0x1000,
                0x8000_0010,
                0x1000,
            ]
        );
        assert_eq!((encoder.total(), encoder.recorded()), (7, 7));
        assert!(!encoder.deferred());
        assert_eq!(encoder.mismatches().0, 0);
    }

    #[test]
    fn indexed_string_form_carries_xer_count() {
        let mut gpr = [0; 32];
        gpr[5] = 0x100;
        gpr[6] = 0x20;
        // lswx r3, r5, r6
        const LSWX: u32 = 0x7c65_342a;
        let program = Program {
            code: &[LSWX],
            gpr,
            xer: 0x2000_0085,
        };
        let mut cache = [0; CACHE_WORDS];
        let words = run(&mut Encoder::new(), &program, &mut cache, &[0x1000]);
        assert_eq!(words.as_slice(), &[0x1000, LSWX, 0x120, 0x05]);
    }

    #[test]
    fn unexplained_jump_is_a_mismatch() {
        let program = Program {
            code: &[ADDI, ADDI, ADDI, ADDI],
            gpr: [0; 32],
            xer: 0,
        };
        let mut cache = [0; CACHE_WORDS];
        let mut encoder = Encoder::new();
        run(&mut encoder, &program, &mut cache, &[0x1000, 0x100c]);
        assert_eq!(
            encoder.mismatches(),
            (
                1,
                &[Mismatch {
                    instruction: 2,
                    expected: 0x1004,
                    found: 0x100c
                }][..]
            )
        );
    }

    #[test]
    fn instruction_after_system_call_is_recorded() {
        // sc; li r3, 1; li r3, 1
        let program = Program {
            code: &[0x4400_0002, ADDI, ADDI],
            gpr: [0; 32],
            xer: 0,
        };
        let mut cache = [0; CACHE_WORDS];
        let mut encoder = Encoder::new();
        let words = run(&mut encoder, &program, &mut cache, &[0x1000, 0x1008]);
        // The system call is deferred to its continuation, which executed
        // without a trace exception of its own.
        assert_eq!(words.as_slice(), &[0x1000, 0x4400_0002, 0x1004, ADDI, ADDI]);
        assert_eq!(encoder.total(), 3);
    }

    #[test]
    fn start_address_records_one_call_level() {
        // 0x1000: bl +8; 0x1004: blr; 0x1008: li; 0x100c: blr
        let program = Program {
            code: &[0x4800_0009, BLR, ADDI, BLR],
            gpr: [0; 32],
            xer: 0,
        };
        let mut cache = [0; CACHE_WORDS];
        let mut encoder = Encoder::new();
        encoder.set_start(Some(0x1000), false);
        let words = run(
            &mut encoder,
            &program,
            &mut cache,
            &[0x1000, 0x1008, 0x100c, 0x1004, 0x2000],
        );
        // The callee is skipped; the return out of the start function
        // writes the leave marker.
        assert_eq!(
            words.as_slice(),
            &[0x1000, 0x4800_0009, 0x1004, BLR, LEFT_RECORDED_FUNCTION]
        );
        assert_eq!(encoder.recorded(), 2);
    }

    #[test]
    fn cache_replaces_the_least_recent_way() {
        let mut cache = [0; CACHE_WORDS];
        assert!(cache_miss(&mut cache, 0x1000));
        assert!(cache_miss(&mut cache, 0x9000));
        assert!(!cache_miss(&mut cache, 0x1000));
        assert!(cache_miss(&mut cache, 0x11000));
        assert!(!cache_miss(&mut cache, 0x1000));
        assert!(cache_miss(&mut cache, 0x9000));
    }

    struct Space;

    impl AddressSpace for Space {
        fn query(&mut self, address: u32) -> Option<Region> {
            match address {
                0x0000_0000 => Some(Region {
                    size: 0x8_0000,
                    state: 0x1_0000,
                    protect: 0,
                }),
                0x0008_0000 => Some(Region {
                    size: 0x2000,
                    state: MEM_COMMIT,
                    protect: 4,
                }),
                _ => None,
            }
        }

        fn protect(&mut self, address: u32) -> u32 {
            match address {
                0xa000_0000 | 0xa002_0000 => 4,
                0xa003_0000 => 2,
                _ => 0,
            }
        }

        fn allocation_size(&mut self, address: u32) -> u32 {
            match address {
                0xa000_0000 => 0x2_0000,
                _ => 0x1_0000,
            }
        }
    }

    #[test]
    fn memory_map_merges_adjacent_system_allocations() {
        let mut words = Words::new();
        write_memory_map(&mut Space, &mut words);
        assert_eq!(
            words.as_slice(),
            &[0x80, 2, 4, 0xa_0000, 0x30, 4, 0xa_0030, 0x10, 2]
        );
    }
}
