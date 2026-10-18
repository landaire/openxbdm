//! Software execution breakpoints and the hardware data breakpoint.
// Pool memory is reinterpreted as a block.
#![allow(unsafe_code)]

use super::SetError;
use super::direct::DirectStep;

/// `twi 31, r0, 0x16`, the instruction written over a breakpoint.
pub const TRAP_INSTRUCTION: u32 = 0x0fe0_0016;
/// Entries per block.
const BLOCK_ENTRIES: usize = 0x80;

xbox360_sys::flags! {
    /// Flags byte of a breakpoint slot. Stock also refuses to arm on bit 1,
    /// which has no writer.
    pub struct BreakpointFlags(u8) {
        /// The trap is in memory.
        ARMED = 1,
    }
}

/// Stock block layout: count, sorted addresses, saved instruction words,
/// flag bytes, next link (0x488 bytes, pool tag `Xbdm`, type 2).
#[derive(Debug)]
#[repr(C)]
struct Block {
    count: u32,
    addresses: [u32; BLOCK_ENTRIES],
    saved: [u32; BLOCK_ENTRIES],
    flags: [u8; BLOCK_ENTRIES],
    next: Option<&'static mut Block>,
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<Block>() == 0x488);

impl Block {
    /// Zero `memory` and use it as a block. Stock leaves a block's unused
    /// slots as the pool returned them.
    fn from_pool(memory: &'static mut [u8]) -> Option<&'static mut Self> {
        if memory.len() < core::mem::size_of::<Self>()
            || !memory.as_ptr().cast::<Self>().is_aligned()
        {
            return None;
        }

        memory.fill(0);

        // SAFETY: the memory is held for the life of the program by nothing
        // else, large enough and aligned, and zero bytes are a valid block
        // (zero words, no next link).
        Some(unsafe { &mut *memory.as_mut_ptr().cast::<Self>() })
    }

    fn count(&self) -> usize {
        self.count as usize
    }

    fn identity(&self) -> BlockIdentity {
        BlockIdentity(core::ptr::from_ref(self).addr())
    }

    fn armed(&self, index: usize) -> bool {
        BreakpointFlags::from_bits_retain(self.flags[index]).intersects(BreakpointFlags::ARMED)
    }

    /// Whether the walk of stock 0x91f25480 stops here: this is the last
    /// block, or the address lies between this block's first address and
    /// the next one's. Stale first addresses of emptied blocks count.
    fn covers(&self, address: u32) -> bool {
        match self.next.as_deref() {
            None => true,
            Some(next) => address >= self.addresses[0] && address < next.addresses[0],
        }
    }

    fn search(&self, address: u32) -> Result<usize, usize> {
        let (mut low, mut high) = (0, self.count());

        while low < high {
            let middle = (low + high) / 2;
            match self.addresses[middle].cmp(&address) {
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Equal => return Ok(middle),
                core::cmp::Ordering::Greater => high = middle,
            }
        }

        Err(low)
    }

    /// Move the entries from index `from` to the end to index `to`.
    fn shift(&mut self, from: usize, to: usize) {
        let count = self.count();
        self.addresses.copy_within(from..count, to);
        self.saved.copy_within(from..count, to);
        self.flags.copy_within(from..count, to);
    }

    /// Move the upper half of this full block into `upper`, link it after
    /// this one, and return the half that covers `address`.
    fn split(&mut self, upper: &'static mut Self, address: u32) -> &mut Self {
        let count = self.count();
        let moved = count / 2;
        let kept = count - moved;

        upper.addresses[..moved].copy_from_slice(&self.addresses[kept..count]);
        upper.saved[..moved].copy_from_slice(&self.saved[kept..count]);
        upper.flags[..moved].copy_from_slice(&self.flags[kept..count]);
        upper.count = moved as u32;
        upper.next = self.next.take();
        self.count = kept as u32;

        if address >= upper.addresses[0] {
            self.next.insert(upper)
        } else {
            self.next = Some(upper);
            self
        }
    }

    fn insert(&mut self, index: usize, address: u32) {
        // The saved word at the new index keeps its previous value until
        // the trap is written.
        self.shift(index, index + 1);
        self.count += 1;
        self.addresses[index] = address;
        self.flags[index] = 0;
    }

    fn remove(&mut self, index: usize) {
        self.shift(index + 1, index);
        self.count -= 1;
    }

    /// Stock 0x91f269f0.
    fn arm<C>(&mut self, index: usize, code: &mut C)
    where
        C: CodeWords + ?Sized,
    {
        if self.armed(index) {
            return;
        }

        if let Some(original) = code.replace_code_word(self.addresses[index], TRAP_INSTRUCTION) {
            self.saved[index] = original;
            self.flags[index] = BreakpointFlags::ARMED.bits();
        }
    }

    /// Stock 0x91f26ac0.
    fn disarm<C>(&mut self, index: usize, code: &mut C)
    where
        C: CodeWords + ?Sized,
    {
        if self.armed(index) {
            code.replace_code_word(self.addresses[index], self.saved[index]);
        }

        self.flags[index] = 0;
    }
}

/// Address of a block, which never moves or is freed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockIdentity(usize);

/// Position of an entry. A step over a breakpoint records this rather than
/// the address, and re-arms whatever entry occupies it afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Slot {
    block: BlockIdentity,
    index: usize,
}

/// Code memory the table patches.
pub trait CodeWords {
    /// Store `value` through a writable mapping, synchronizing the
    /// instruction cache, and return the previous word; `None` when the
    /// address cannot be mapped.
    fn replace_code_word(&mut self, address: u32, value: u32) -> Option<u32>;
}

/// A zeroed pool block for the table. The platform obtains it before it
/// takes the table lock, as stock allocates the spare before raising IRQL
/// (0x91f27018).
#[derive(Debug)]
pub struct SpareBlock(&'static mut Block);

impl SpareBlock {
    /// Bytes of pool memory a block needs.
    pub const SIZE: u32 = core::mem::size_of::<Block>() as u32;

    /// `memory` is held for the life of the program, as blocks are never
    /// freed.
    pub fn from_pool(memory: &'static mut [u8]) -> Option<Self> {
        Block::from_pool(memory).map(Self)
    }
}

/// The breakpoint table and the step state of exceptions dispatched in
/// place. The platform keeps both under its table lock (stock spin lock
/// 0x91fae9c0, taken at IRQL 0x7c), so that threads that cannot wait for
/// the server reach them.
#[derive(Debug)]
pub struct BreakpointState {
    pub(crate) table: Breakpoints,
    /// Step over a breakpoint or the data breakpoint begun in place (stock
    /// keeps it in the context of the deferred dispatch, 0x91fae9b0).
    pub(crate) direct_step: Option<DirectStep>,
}

impl BreakpointState {
    pub const fn new() -> Self {
        Self {
            table: Breakpoints::new(),
            direct_step: None,
        }
    }

    /// Whether the table holds no spare block, which a set may need.
    pub fn needs_spare(&self) -> bool {
        self.table.needs_spare()
    }

    pub fn provide_spare(&mut self, spare: SpareBlock) {
        self.table.provide_spare(spare);
    }

    /// Add or re-arm a breakpoint (stock 0x91f26fc8 under the table lock);
    /// a split fails when no spare block is held.
    pub fn set(&mut self, address: u32, code: &mut dyn CodeWords) -> Result<(), SetError> {
        if address & 3 != 0 {
            return Err(SetError::Misaligned);
        }

        self.table.set(address, code)
    }

    /// Remove a breakpoint (stock 0x91f27178); whether it existed.
    pub fn clear(&mut self, address: u32, code: &mut dyn CodeWords) -> bool {
        self.table.clear(address, code)
    }

    /// Original byte under an armed breakpoint (stock 0x91f26bc8).
    pub fn shadow_read(&self, address: u32) -> Option<u8> {
        self.table.shadow_read(address)
    }

    /// Store a byte into the saved instruction of an armed breakpoint
    /// (stock 0x91f26cb8); whether the address is covered.
    pub fn shadow_write(&mut self, address: u32, value: u8) -> bool {
        self.table.shadow_write(address, value)
    }

    /// Whether a software breakpoint is set at `address`.
    pub fn contains(&self, address: u32) -> bool {
        self.table.contains(address)
    }

    /// Forget the breakpoints of an unloaded module after restoring their
    /// instructions (stock 0x91f26e90), as the dispatch of its unload trap
    /// does in place (0x91f3a3dc).
    pub fn remove_module(&mut self, base: u32, size: u32, code: &mut dyn CodeWords) {
        self.table.remove_range(base, size, code);
    }
}

/// Execution breakpoints (stock head 0x91fae980, spare 0x91fae97c): a
/// chain of sorted pool blocks that split in half when full, plus one
/// spare block. Blocks are never freed.
#[derive(Debug)]
pub(crate) struct Breakpoints {
    head: Option<&'static mut Block>,
    spare: Option<&'static mut Block>,
}

impl Breakpoints {
    pub(crate) const fn new() -> Self {
        Self {
            head: None,
            spare: None,
        }
    }

    pub(crate) fn needs_spare(&self) -> bool {
        self.spare.is_none()
    }

    pub(crate) fn provide_spare(&mut self, spare: SpareBlock) {
        self.spare = Some(spare.0);
    }

    fn blocks(&self) -> impl Iterator<Item = &Block> + '_ {
        core::iter::successors(self.head.as_deref(), |block| block.next.as_deref())
    }

    /// Block an address belongs to (stock 0x91f25480). An address below
    /// the head's first entry falls through to the last block.
    fn walk(&self, address: u32) -> Option<&Block> {
        let mut current = self.head.as_deref()?;

        while !current.covers(address) {
            current = current.next.as_deref()?;
        }

        Some(current)
    }

    fn find(&self, address: u32) -> Option<(&Block, usize)> {
        let block = self.walk(address)?;
        let index = block.search(address).ok()?;

        Some((block, index))
    }

    fn find_mut(&mut self, address: u32) -> Option<(&mut Block, usize)> {
        let mut current = self.head.as_deref_mut()?;

        while !current.covers(address) {
            current = current.next.as_deref_mut()?;
        }

        let index = current.search(address).ok()?;

        Some((current, index))
    }

    pub(crate) fn contains(&self, address: u32) -> bool {
        self.find(address).is_some()
    }

    /// Original byte under an armed breakpoint (stock 0x91f26bc8).
    pub(crate) fn shadow_read(&self, address: u32) -> Option<u8> {
        let (block, index) = self.find(address & !3)?;
        if !block.armed(index) {
            return None;
        }

        Some(block.saved[index].to_be_bytes()[(address & 3) as usize])
    }

    /// Store a byte into the saved instruction of an armed breakpoint
    /// (stock 0x91f26cb8). Returns whether the address is covered.
    pub fn shadow_write(&mut self, address: u32, value: u8) -> bool {
        let Some((block, index)) = self.find_mut(address & !3) else {
            return false;
        };

        if !block.armed(index) {
            return false;
        }

        let mut bytes = block.saved[index].to_be_bytes();
        bytes[(address & 3) as usize] = value;
        block.saved[index] = u32::from_be_bytes(bytes);

        true
    }

    /// Copy the saved words of every entry overlapping `data`, read from
    /// `start`, over it, armed or not (stock 0x91f256d0). A block whose first
    /// address is at or past the end stops the whole walk.
    pub fn restore_saved(&self, start: u32, data: &mut [u8]) {
        let length = data.len() as u32;
        let end = start.wrapping_add(length);

        for block in self.blocks() {
            let count = block.count();
            if count == 0 {
                continue;
            }

            if end <= block.addresses[0] {
                break;
            }

            if start > block.addresses[count - 1].wrapping_add(4) {
                continue;
            }

            for (&address, &saved) in block.addresses[..count].iter().zip(&block.saved) {
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

    /// Add or re-arm a breakpoint (stock 0x91f26fc8) at an aligned address.
    /// A new entry counts as set even when its address cannot be mapped for
    /// the trap. Fails only when a block is needed and no spare is held.
    pub(crate) fn set<C>(&mut self, address: u32, code: &mut C) -> Result<(), SetError>
    where
        C: CodeWords + ?Sized,
    {
        let Self { head, spare } = self;
        let mut block: &mut Block = match head {
            Some(head) => head,
            None => head.insert(spare.take().ok_or(SetError::NoBlock)?),
        };

        while !block.covers(address) {
            block = block.next.as_deref_mut().ok_or(SetError::NoBlock)?;
        }

        let index = loop {
            let index = match block.search(address) {
                Ok(index) => break index,
                Err(index) => index,
            };

            if block.count() != BLOCK_ENTRIES {
                block.insert(index, address);
                break index;
            }

            block = block.split(spare.take().ok_or(SetError::NoBlock)?, address);
        };

        block.arm(index, code);

        Ok(())
    }

    /// Remove a breakpoint, restoring the original instruction (stock
    /// 0x91f27178). Returns whether it existed.
    pub(crate) fn clear<C>(&mut self, address: u32, code: &mut C) -> bool
    where
        C: CodeWords + ?Sized,
    {
        let Some((block, index)) = self.find_mut(address) else {
            return false;
        };

        block.disarm(index, code);
        block.remove(index);

        true
    }

    /// Disarm every entry and empty every block (stock 0x91f27290). The
    /// addresses stay in the blocks and keep steering the walk.
    pub(crate) fn clear_all<C>(&mut self, code: &mut C)
    where
        C: CodeWords + ?Sized,
    {
        let mut current = self.head.as_deref_mut();

        while let Some(block) = current {
            for index in 0..block.count() {
                block.disarm(index, code);
            }

            block.count = 0;
            current = block.next.as_deref_mut();
        }
    }

    /// Forget breakpoints that overlap `[base, base + size)` after
    /// restoring their instructions (module unload, stock 0x91f26e90). A
    /// block whose first address is at or past the end stops the whole walk.
    pub(crate) fn remove_range<C>(&mut self, base: u32, size: u32, code: &mut C)
    where
        C: CodeWords + ?Sized,
    {
        let end = base.wrapping_add(size);
        let mut current = self.head.as_deref_mut();

        while let Some(block) = current {
            let count = block.count();
            if count != 0 {
                if end <= block.addresses[0] {
                    break;
                }

                if base <= block.addresses[count - 1].wrapping_add(4) {
                    let mut index = 0;

                    while index < block.count() {
                        let address = block.addresses[index];
                        if end <= address {
                            break;
                        }

                        if base < address.wrapping_add(4) {
                            block.disarm(index, code);
                            block.remove(index);
                        } else {
                            index += 1;
                        }
                    }
                }
            }

            current = block.next.as_deref_mut();
        }
    }

    /// Put the original instruction back to step over a breakpoint (stock
    /// 0x91f27550).
    pub(crate) fn lift<C>(&mut self, address: u32, code: &mut C) -> Option<Slot>
    where
        C: CodeWords + ?Sized,
    {
        let (block, index) = self.find_mut(address)?;
        block.disarm(index, code);

        Some(Slot {
            block: block.identity(),
            index,
        })
    }

    /// Restore the instruction of the breakpoint at `address`, keeping the
    /// entry (stock 0x91f26b80). Returns whether one is set there.
    pub(crate) fn disarm_at<C>(&mut self, address: u32, code: &mut C) -> bool
    where
        C: CodeWords + ?Sized,
    {
        let Some((block, index)) = self.find_mut(address) else {
            return false;
        };

        block.disarm(index, code);

        true
    }

    /// Arm the entry at `slot` after a step (stock 0x91f27630), whichever
    /// entry occupies it by then.
    pub(crate) fn rearm<C>(&mut self, slot: Slot, code: &mut C)
    where
        C: CodeWords + ?Sized,
    {
        let mut current = self.head.as_deref_mut();

        while let Some(block) = current {
            if block.identity() == slot.block {
                block.arm(slot.index, code);
                return;
            }

            current = block.next.as_deref_mut();
        }
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

    /// Code memory in which only the listed words are mapped, and the pool
    /// blocks left (`None`: unlimited).
    #[derive(Default)]
    struct Code(BTreeMap<u32, u32>, Option<usize>);

    impl Code {
        fn mapped(words: &[(u32, u32)]) -> Self {
            Self(words.iter().copied().collect(), None)
        }

        fn allocate(&mut self) -> Option<SpareBlock> {
            if let Some(left) = &mut self.1 {
                *left = left.checked_sub(1)?;
            }

            // Pool memory is not zeroed and is 8-byte aligned.
            let size = SpareBlock::SIZE as usize;
            let words = Vec::leak(std::vec![0xa5a5_a5a5_a5a5_a5a5u64; size.div_ceil(8)]);
            // SAFETY: the leaked words are referenced only through the
            // returned bytes.
            SpareBlock::from_pool(unsafe {
                core::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), size)
            })
        }
    }

    impl CodeWords for Code {
        fn replace_code_word(&mut self, address: u32, value: u32) -> Option<u32> {
            self.0
                .get_mut(&address)
                .map(|word| core::mem::replace(word, value))
        }
    }

    /// A set as the server makes it: the spare comes from the pool first.
    fn set(table: &mut Breakpoints, code: &mut Code, address: u32) -> Result<(), SetError> {
        if table.needs_spare()
            && let Some(spare) = code.allocate()
        {
            table.provide_spare(spare);
        }

        table.set(address, code)
    }

    /// Set `count` breakpoints 8 bytes apart from 0x1000.
    fn set_ascending(table: &mut Breakpoints, code: &mut Code, count: usize) {
        for index in 0..count as u32 {
            assert_eq!(set(table, code, 0x1000 + index * 8), Ok(()));
        }
    }

    fn chain(table: &Breakpoints) -> Vec<Vec<u32>> {
        table
            .blocks()
            .map(|block| block.addresses[..block.count()].to_vec())
            .collect()
    }

    #[test]
    fn full_block_splits_in_half_and_inserts_by_the_upper_first_address() {
        let mut table = Breakpoints::new();
        let mut code = Code::default();
        set_ascending(&mut table, &mut code, BLOCK_ENTRIES);
        assert_eq!(set(&mut table, &mut code, 0x1004), Ok(()));
        let blocks = chain(&table);
        assert_eq!(blocks.len(), 2);
        assert_eq!((blocks[0].len(), blocks[1].len()), (0x41, 0x40));
        assert_eq!(blocks[0][..3], [0x1000, 0x1004, 0x1008]);
        assert_eq!(blocks[1][0], 0x1200);
    }

    #[test]
    fn address_below_the_head_goes_to_the_last_block() {
        let mut table = Breakpoints::new();
        let mut code = Code::default();
        set_ascending(&mut table, &mut code, BLOCK_ENTRIES + 1);
        assert!(table.contains(0x1100));
        assert_eq!(set(&mut table, &mut code, 0x800), Ok(()));
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
        let mut table = Breakpoints::new();
        let mut code = Code::default();
        set_ascending(&mut table, &mut code, BLOCK_ENTRIES + 1);
        table.clear_all(&mut code);
        assert_eq!(set(&mut table, &mut code, 0x3000), Ok(()));
        assert_eq!(set(&mut table, &mut code, 0x1100), Ok(()));
        assert_eq!(chain(&table), [&[0x1100][..], &[0x3000][..]]);
    }

    #[test]
    fn new_entry_keeps_the_saved_word_of_its_position() {
        let mut table = Breakpoints::new();
        let mut code = Code::mapped(&[(0x2000, 0x1122_3344)]);
        assert_eq!(set(&mut table, &mut code, 0x2000), Ok(()));
        assert_eq!(set(&mut table, &mut code, 0x1000), Ok(()));
        assert_eq!(table.shadow_read(0x1000), None);
        let mut data = [0u8; 6];
        table.restore_saved(0x0ffe, &mut data);
        assert_eq!(data, [0, 0, 0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn chain_grows_while_pool_memory_lasts() {
        let mut table = Breakpoints::new();
        let mut code = Code::default();
        // Ascending sets split each full block in half: every block but the
        // last keeps 0x40 entries.
        set_ascending(&mut table, &mut code, 15 * BLOCK_ENTRIES / 2 + 1);
        let blocks = chain(&table);
        assert_eq!(blocks.len(), 15);
        assert_eq!(blocks[14].len(), 0x41);
    }

    #[test]
    fn set_fails_once_a_split_needs_a_block_the_pool_cannot_give() {
        let mut table = Breakpoints::new();
        // Head, then one spare per split; the spare after the second split
        // cannot be obtained.
        let mut code = Code(BTreeMap::new(), Some(3));
        let capacity = 2 * BLOCK_ENTRIES;
        set_ascending(&mut table, &mut code, capacity);
        let past = 0x1000 + capacity as u32 * 8;
        assert_eq!(set(&mut table, &mut code, past), Err(SetError::NoBlock));
        assert!(!table.contains(past));
        // A block with room still takes entries.
        assert_eq!(set(&mut table, &mut code, 0x1004), Ok(()));
        assert_eq!(chain(&table).len(), 3);
    }

    #[test]
    fn set_fails_without_pool_memory_for_the_first_block() {
        let mut table = Breakpoints::new();
        let mut code = Code(BTreeMap::new(), Some(0));
        assert_eq!(set(&mut table, &mut code, 0x1000), Err(SetError::NoBlock));
        assert!(!table.contains(0x1000));
        assert!(chain(&table).is_empty());
    }

    #[test]
    fn rearm_targets_the_recorded_position() {
        let mut table = Breakpoints::new();
        let mut code = Code::mapped(&[(0x0ffc, 1), (0x1000, 2), (0x1004, 3)]);
        assert_eq!(set(&mut table, &mut code, 0x1000), Ok(()));
        assert_eq!(set(&mut table, &mut code, 0x1004), Ok(()));
        let slot = table.lift(0x1004, &mut code).unwrap();
        assert_eq!(set(&mut table, &mut code, 0x0ffc), Ok(()));
        table.rearm(slot, &mut code);
        assert_eq!(code.0[&0x1000], TRAP_INSTRUCTION);
        assert_eq!(code.0[&0x1004], 3);
    }

    #[test]
    fn disarm_at_keeps_the_entry() {
        let mut table = Breakpoints::new();
        let mut code = Code::mapped(&[(0x1000, 7)]);
        assert_eq!(set(&mut table, &mut code, 0x1000), Ok(()));
        assert!(table.disarm_at(0x1000, &mut code));
        assert_eq!(code.0[&0x1000], 7);
        assert!(table.contains(0x1000));
        assert!(!table.disarm_at(0x1004, &mut code));
    }
}
