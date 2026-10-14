//! Software execution breakpoints and the hardware data breakpoint.

use super::Backend;

/// `twi 31, r0, 0x16`, the instruction written over a breakpoint.
pub const TRAP_INSTRUCTION: u32 = 0x0fe0_0016;
/// Blocks the table can obtain. Stock allocates each 0x488-byte block from
/// pool memory; a fixed arena keeps the server state allocation-free.
pub const BREAKPOINT_BLOCKS: usize = 8;
/// Entries per block.
const BLOCK_ENTRIES: usize = 0x80;

/// Arena index of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockId(u8);

/// One block of the sorted chain (stock layout: count, addresses, saved
/// instruction words, flag bytes, next).
#[derive(Debug, Clone, Copy)]
struct Block {
    count: usize,
    addresses: [u32; BLOCK_ENTRIES],
    /// Instruction each trap replaced.
    saved: [u32; BLOCK_ENTRIES],
    /// Flag bit 0: the trap is in memory. Stock also refuses to arm on
    /// bit 1, which has no writer.
    armed: [bool; BLOCK_ENTRIES],
    next: Option<BlockId>,
}

impl Block {
    const EMPTY: Self = Self {
        count: 0,
        addresses: [0; BLOCK_ENTRIES],
        saved: [0; BLOCK_ENTRIES],
        armed: [false; BLOCK_ENTRIES],
        next: None,
    };

    fn search(&self, address: u32) -> Result<usize, usize> {
        self.addresses[..self.count].binary_search(&address)
    }

    fn remove(&mut self, index: usize) {
        let count = self.count;
        self.addresses.copy_within(index + 1..count, index);
        self.saved.copy_within(index + 1..count, index);
        self.armed.copy_within(index + 1..count, index);
        self.count -= 1;
    }
}

/// Position of an entry. A step over a breakpoint records this rather than
/// the address, and re-arms whatever entry occupies it afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Slot {
    block: BlockId,
    index: usize,
}

/// Code memory the table patches.
pub(crate) trait CodeWords {
    /// Store `value` and return the previous word, or `None` when the
    /// address cannot be mapped.
    fn replace_code_word(&mut self, address: u32, value: u32) -> Option<u32>;
}

impl<T: Backend + ?Sized> CodeWords for T {
    fn replace_code_word(&mut self, address: u32, value: u32) -> Option<u32> {
        Backend::replace_code_word(self, address, value)
    }
}

/// Execution breakpoints: a chain of sorted blocks that split in half when
/// full, plus one spare block. Blocks are never freed.
#[derive(Debug)]
pub struct Breakpoints {
    blocks: [Block; BREAKPOINT_BLOCKS],
    /// Blocks handed out so far.
    allocated: usize,
    head: Option<BlockId>,
    spare: Option<BlockId>,
}

impl Default for Breakpoints {
    fn default() -> Self {
        Self {
            blocks: [Block::EMPTY; BREAKPOINT_BLOCKS],
            allocated: 0,
            head: None,
            spare: None,
        }
    }
}

/// Why a set did not take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetError {
    Misaligned,
    /// The entry needed a block split and no spare block could be obtained.
    NoSpareBlock,
}

impl Breakpoints {
    fn block(&self, id: BlockId) -> &Block {
        &self.blocks[usize::from(id.0)]
    }

    fn block_mut(&mut self, id: BlockId) -> &mut Block {
        &mut self.blocks[usize::from(id.0)]
    }

    fn allocate(&mut self) -> Option<BlockId> {
        if self.allocated == BREAKPOINT_BLOCKS {
            return None;
        }
        let id = BlockId(self.allocated as u8);
        self.allocated += 1;
        Some(id)
    }

    /// Block an address belongs to (stock 0x91f25480). The test reads the
    /// first address of every block, including stale ones of emptied
    /// blocks, and an address below the head's first entry falls through
    /// to the last block.
    fn walk(&self, head: BlockId, address: u32) -> BlockId {
        let mut current = head;
        while let Some(next) = self.block(current).next {
            if address >= self.block(current).addresses[0]
                && address < self.block(next).addresses[0]
            {
                break;
            }
            current = next;
        }
        current
    }

    fn find(&self, address: u32) -> Option<Slot> {
        let block = self.walk(self.head?, address);
        self.block(block)
            .search(address)
            .ok()
            .map(|index| Slot { block, index })
    }

    /// Lookup with insertion: `Ok` for an existing entry, `Err` for the
    /// position a new entry takes, `None` when a needed block is missing.
    fn locate_for_insert(&mut self, address: u32) -> Option<Result<Slot, Slot>> {
        let head = match self.head {
            Some(head) => head,
            None => {
                let head = self.spare.take()?;
                *self.block_mut(head) = Block::EMPTY;
                self.head = Some(head);
                head
            }
        };
        let mut block = self.walk(head, address);
        loop {
            let index = match self.block(block).search(address) {
                Ok(index) => return Some(Ok(Slot { block, index })),
                Err(index) => index,
            };
            if self.block(block).count != BLOCK_ENTRIES {
                return Some(Err(Slot { block, index }));
            }
            let upper = self.spare.take()?;
            self.split(block, upper);
            if address >= self.block(upper).addresses[0] {
                block = upper;
            }
        }
    }

    /// Move the upper half of the full block `lower` into `upper` and link
    /// it after `lower`.
    fn split(&mut self, lower: BlockId, upper: BlockId) {
        let (low, high) = (usize::from(lower.0), usize::from(upper.0));
        let (source, target) = if low < high {
            let (left, right) = self.blocks.split_at_mut(high);
            (&mut left[low], &mut right[0])
        } else {
            let (left, right) = self.blocks.split_at_mut(low);
            (&mut right[0], &mut left[high])
        };
        let moved = source.count / 2;
        let kept = source.count - moved;
        target.count = moved;
        target.addresses[..moved].copy_from_slice(&source.addresses[kept..source.count]);
        target.saved[..moved].copy_from_slice(&source.saved[kept..source.count]);
        target.armed[..moved].copy_from_slice(&source.armed[kept..source.count]);
        target.next = source.next;
        source.next = Some(upper);
        source.count = kept;
    }

    fn blocks_in_chain(&self) -> impl Iterator<Item = BlockId> + '_ {
        core::iter::successors(self.head, |&id| self.block(id).next)
    }

    pub fn contains(&self, address: u32) -> bool {
        self.find(address).is_some()
    }

    fn armed_entry(&self, address: u32) -> Option<Slot> {
        self.find(address & !3)
            .filter(|slot| self.block(slot.block).armed[slot.index])
    }

    /// Original byte under an armed breakpoint (stock 0x91f26bc8).
    pub fn shadow_read(&self, address: u32) -> Option<u8> {
        let slot = self.armed_entry(address)?;
        Some(self.block(slot.block).saved[slot.index].to_be_bytes()[(address & 3) as usize])
    }

    /// Store a byte into the saved instruction of an armed breakpoint
    /// (stock 0x91f26cb8). Returns whether the address is covered.
    pub fn shadow_write(&mut self, address: u32, value: u8) -> bool {
        let Some(slot) = self.armed_entry(address) else {
            return false;
        };
        let saved = &mut self.block_mut(slot.block).saved[slot.index];
        let mut bytes = saved.to_be_bytes();
        bytes[(address & 3) as usize] = value;
        *saved = u32::from_be_bytes(bytes);
        true
    }

    /// Copy the saved words of every entry overlapping `data`, read from
    /// `start`, over it, armed or not (stock 0x91f256d0). A block whose first
    /// address is at or past the end stops the whole walk.
    pub fn restore_saved(&self, start: u32, data: &mut [u8]) {
        let length = data.len() as u32;
        let end = start.wrapping_add(length);
        for id in self.blocks_in_chain() {
            let block = self.block(id);
            if block.count == 0 {
                continue;
            }
            if end <= block.addresses[0] {
                break;
            }
            if start > block.addresses[block.count - 1].wrapping_add(4) {
                continue;
            }
            for (&address, saved) in block.addresses[..block.count].iter().zip(&block.saved) {
                if end <= address {
                    break;
                }
                if start >= address.wrapping_add(4) {
                    continue;
                }
                for (byte_offset, byte) in (0u32..).zip(saved.to_be_bytes()) {
                    let offset = address.wrapping_add(byte_offset).wrapping_sub(start);
                    if offset < length {
                        data[offset as usize] = byte;
                    }
                }
            }
        }
    }

    /// Add or re-arm a breakpoint (stock 0x91f26fc8). A new entry counts as
    /// set even when its address cannot be mapped for the trap.
    pub(crate) fn set<C: CodeWords + ?Sized>(
        &mut self,
        address: u32,
        code: &mut C,
    ) -> Result<(), SetError> {
        if address & 3 != 0 {
            return Err(SetError::Misaligned);
        }
        if self.spare.is_none() {
            self.spare = self.allocate();
        }
        let slot = match self
            .locate_for_insert(address)
            .ok_or(SetError::NoSpareBlock)?
        {
            Ok(slot) => slot,
            Err(slot) => {
                let block = self.block_mut(slot.block);
                let count = block.count;
                block
                    .addresses
                    .copy_within(slot.index..count, slot.index + 1);
                // The saved word at the new index keeps its previous value
                // until the trap is written.
                block.saved.copy_within(slot.index..count, slot.index + 1);
                block.armed.copy_within(slot.index..count, slot.index + 1);
                block.count += 1;
                block.addresses[slot.index] = address;
                block.armed[slot.index] = false;
                slot
            }
        };
        self.arm(slot, code);
        Ok(())
    }

    /// Remove a breakpoint, restoring the original instruction (stock
    /// 0x91f27178). Returns whether it existed.
    pub(crate) fn clear<C: CodeWords + ?Sized>(&mut self, address: u32, code: &mut C) -> bool {
        let Some(slot) = self.find(address) else {
            return false;
        };
        self.disarm(slot, code);
        self.block_mut(slot.block).remove(slot.index);
        true
    }

    /// Disarm every entry and empty every block (stock 0x91f27290). The
    /// addresses stay in the blocks and keep steering the walk.
    pub(crate) fn clear_all<C: CodeWords + ?Sized>(&mut self, code: &mut C) {
        let mut current = self.head;
        while let Some(block) = current {
            for index in 0..self.block(block).count {
                self.disarm(Slot { block, index }, code);
            }
            let block = self.block_mut(block);
            block.count = 0;
            current = block.next;
        }
    }

    /// Forget breakpoints that overlap `[base, base + size)` after
    /// restoring their instructions (module unload, stock 0x91f26e90). A
    /// block whose first address is at or past the end stops the whole walk.
    pub(crate) fn remove_range<C: CodeWords + ?Sized>(
        &mut self,
        base: u32,
        size: u32,
        code: &mut C,
    ) {
        let end = base.wrapping_add(size);
        let mut current = self.head;
        while let Some(block) = current {
            let count = self.block(block).count;
            if count != 0 {
                if end <= self.block(block).addresses[0] {
                    break;
                }
                if base <= self.block(block).addresses[count - 1].wrapping_add(4) {
                    let mut index = 0;
                    while index < self.block(block).count {
                        let address = self.block(block).addresses[index];
                        if end <= address {
                            break;
                        }
                        if base < address.wrapping_add(4) {
                            self.disarm(Slot { block, index }, code);
                            self.block_mut(block).remove(index);
                        } else {
                            index += 1;
                        }
                    }
                }
            }
            current = self.block(block).next;
        }
    }

    /// Put the original instruction back to step over a breakpoint (stock
    /// 0x91f27550).
    pub(crate) fn lift<C: CodeWords + ?Sized>(
        &mut self,
        address: u32,
        code: &mut C,
    ) -> Option<Slot> {
        let slot = self.find(address)?;
        self.disarm(slot, code);
        Some(slot)
    }

    /// Arm the entry at `slot` after a step (stock 0x91f27630), whichever
    /// entry occupies it by then.
    pub(crate) fn rearm<C: CodeWords + ?Sized>(&mut self, slot: Slot, code: &mut C) {
        self.arm(slot, code);
    }

    /// Stock 0x91f269f0.
    fn arm<C: CodeWords + ?Sized>(&mut self, slot: Slot, code: &mut C) {
        let block = self.block_mut(slot.block);
        if block.armed[slot.index] {
            return;
        }
        if let Some(original) =
            code.replace_code_word(block.addresses[slot.index], TRAP_INSTRUCTION)
        {
            block.saved[slot.index] = original;
            block.armed[slot.index] = true;
        }
    }

    /// Stock 0x91f26ac0.
    fn disarm<C: CodeWords + ?Sized>(&mut self, slot: Slot, code: &mut C) {
        let block = self.block_mut(slot.block);
        if block.armed[slot.index] {
            code.replace_code_word(block.addresses[slot.index], block.saved[slot.index]);
        }
        block.armed[slot.index] = false;
    }
}

/// Access that triggers the data breakpoint, with the monitor's kind
/// numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataKind {
    Write = 1,
    ReadWrite = 2,
    Read = 5,
}

impl DataKind {
    /// Access bits of the data address breakpoint register.
    const fn register_bits(self) -> u32 {
        match self {
            Self::Write => 0x2,
            Self::ReadWrite => 0x3,
            Self::Read => 0x1,
        }
    }
}

/// The single hardware data breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataBreakpoint {
    pub address: u32,
    pub size: u32,
    pub kind: DataKind,
}

impl DataBreakpoint {
    /// Register value: aligned address, translation enable, access bits.
    pub const fn register(self) -> u32 {
        (self.address & !3) | 0x4 | self.kind.register_bits()
    }

    /// Whether an access of `length` bytes at `address` overlaps the
    /// watched range.
    pub fn overlaps(self, address: u32, length: u32) -> bool {
        self.address.wrapping_add(self.size).wrapping_sub(1) >= address
            && address.wrapping_add(length).wrapping_sub(1) >= self.address
    }
}

/// Bytes the load or store instruction `word` accesses (stock 0x91f25880):
/// the string forms report their byte count field, anything not decoded
/// reports 8.
pub(crate) fn access_length(word: u32) -> u32 {
    let byte_count = (word >> 11) & 0x1f;
    match word >> 26 {
        31 => match (word >> 1) & 0x3ff {
            0x07 | 0x57 | 0x77 | 0x87 | 0xd7 | 0xf7 => 1,
            0x27 | 0xa7 | 0x117 | 0x137 | 0x157 | 0x177 | 0x197 | 0x1b7 | 0x316 | 0x396 => 2,
            0x14 | 0x17 | 0x37 | 0x47 | 0x96 | 0x97 | 0xb7 | 0xc7 | 0x155 | 0x175 | 0x216
            | 0x217 | 0x237 | 0x296 | 0x297 | 0x2b7 | 0x3d7 => 4,
            0x67 | 0xe7 | 0x167 | 0x1e7 => 16,
            0x215 | 0x255 | 0x295 | 0x2d5 => byte_count,
            _ => 8,
        },
        34 | 35 | 38 | 39 => 1,
        40..=45 => 2,
        32 | 33 | 36 | 37 | 48 | 49 | 52 | 53 => 4,
        58 if word & 3 == 2 => 4,
        _ => 8,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::collections::BTreeMap;
    use std::vec::Vec;

    use super::*;

    /// Code memory in which only the listed words are mapped.
    #[derive(Default)]
    struct Code(BTreeMap<u32, u32>);

    impl Code {
        fn mapped(words: &[(u32, u32)]) -> Self {
            Self(words.iter().copied().collect())
        }
    }

    impl CodeWords for Code {
        fn replace_code_word(&mut self, address: u32, value: u32) -> Option<u32> {
            self.0
                .get_mut(&address)
                .map(|word| core::mem::replace(word, value))
        }
    }

    /// Set `count` breakpoints 8 bytes apart from 0x1000.
    fn set_ascending(table: &mut Breakpoints, code: &mut Code, count: usize) {
        for index in 0..count as u32 {
            assert_eq!(table.set(0x1000 + index * 8, code), Ok(()));
        }
    }

    fn chain(table: &Breakpoints) -> Vec<&[u32]> {
        table
            .blocks_in_chain()
            .map(|id| &table.block(id).addresses[..table.block(id).count])
            .collect()
    }

    #[test]
    fn full_block_splits_in_half_and_inserts_by_the_upper_first_address() {
        let mut table = Breakpoints::default();
        let mut code = Code::default();
        set_ascending(&mut table, &mut code, BLOCK_ENTRIES);
        assert_eq!(table.set(0x1004, &mut code), Ok(()));
        let blocks = chain(&table);
        assert_eq!(blocks.len(), 2);
        assert_eq!((blocks[0].len(), blocks[1].len()), (0x41, 0x40));
        assert_eq!(blocks[0][..3], [0x1000, 0x1004, 0x1008]);
        assert_eq!(blocks[1][0], 0x1200);
    }

    #[test]
    fn address_below_the_head_goes_to_the_last_block() {
        let mut table = Breakpoints::default();
        let mut code = Code::default();
        set_ascending(&mut table, &mut code, BLOCK_ENTRIES + 1);
        assert!(table.contains(0x1100));
        assert_eq!(table.set(0x800, &mut code), Ok(()));
        assert_eq!(chain(&table)[1][0], 0x800);
        // The last block's first address no longer bounds the head, so the
        // head's entries are out of reach.
        assert!(!table.contains(0x1100));
        assert!(!table.clear(0x1100, &mut code));
        // Module unload stops at the head, whose first address is past the
        // range.
        table.remove_range(0x800, 4, &mut code);
        assert!(table.contains(0x800));
    }

    #[test]
    fn emptied_blocks_keep_steering_with_their_stale_first_address() {
        let mut table = Breakpoints::default();
        let mut code = Code::default();
        set_ascending(&mut table, &mut code, BLOCK_ENTRIES + 1);
        table.clear_all(&mut code);
        assert_eq!(table.set(0x3000, &mut code), Ok(()));
        assert_eq!(table.set(0x1100, &mut code), Ok(()));
        assert_eq!(chain(&table), [&[0x1100][..], &[0x3000][..]]);
    }

    #[test]
    fn new_entry_keeps_the_saved_word_of_its_position() {
        let mut table = Breakpoints::default();
        let mut code = Code::mapped(&[(0x2000, 0x1122_3344)]);
        assert_eq!(table.set(0x2000, &mut code), Ok(()));
        assert_eq!(table.set(0x1000, &mut code), Ok(()));
        assert_eq!(table.shadow_read(0x1000), None);
        let mut data = [0u8; 6];
        table.restore_saved(0x0ffe, &mut data);
        assert_eq!(data, [0, 0, 0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn set_fails_once_no_spare_block_can_be_obtained() {
        let mut table = Breakpoints::default();
        let mut code = Code::default();
        let capacity = (BREAKPOINT_BLOCKS - 1) * BLOCK_ENTRIES / 2 + BLOCK_ENTRIES;
        set_ascending(&mut table, &mut code, capacity);
        assert_eq!(
            table.set(0x1000 + capacity as u32 * 8, &mut code),
            Err(SetError::NoSpareBlock)
        );
        // A block with room still takes entries.
        assert_eq!(table.set(0x1004, &mut code), Ok(()));
    }

    #[test]
    fn rearm_targets_the_recorded_position() {
        let mut table = Breakpoints::default();
        let mut code = Code::mapped(&[(0x0ffc, 1), (0x1000, 2), (0x1004, 3)]);
        assert_eq!(table.set(0x1000, &mut code), Ok(()));
        assert_eq!(table.set(0x1004, &mut code), Ok(()));
        let slot = table.lift(0x1004, &mut code).unwrap();
        assert_eq!(table.set(0x0ffc, &mut code), Ok(()));
        table.rearm(slot, &mut code);
        assert_eq!(code.0[&0x1000], TRAP_INSTRUCTION);
        assert_eq!(code.0[&0x1004], 3);
    }
}
