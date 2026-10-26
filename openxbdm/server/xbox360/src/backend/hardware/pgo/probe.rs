//! Value probes instrumented code calls (exports 181-193).

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::hardware::pgo;
use openxbdm_server::commands::hardware::pgo::Fatal;
use openxbdm_server::commands::hardware::pgo::ListHead;
use openxbdm_server::commands::hardware::pgo::RangeTable;
use openxbdm_server::commands::hardware::pgo::SweepKind;
use xbox360_sys::export_raw;

use super::SWEEP_ON_OVERFLOW;
use super::SWEEPING;
use super::fatal;
use super::layout::CallTree;
use super::layout::CountBlock;
use super::layout::ProbeContext;
use super::layout::RangeTableHeader;
use super::layout::ThreadRecord;
use super::layout::TreeEntry;
use super::layout::WideEntry;
use super::layout::WideListHead;
use super::layout::WordEntry;
use super::module::snapshot;
use super::record_of_block;
use super::sweep::acquire;
use super::sweep::allocate;
use super::sweep::enter_probe;
use super::sweep::leave_probe;
use super::sweep::wait_for_sweep;
use super::validate::check_list_entries;
use super::validate::check_list_head;
use super::validate::check_tree_descriptor;
use crate::exports::export;
use crate::kernel::address_of;
use crate::kernel::object_at;

/// Whether a 64-bit argument is a zero- or sign-extended 32-bit value.
fn fits32(value: u64) -> bool {
    value == u64::from(value as u32) || value == value as u32 as i32 as i64 as u64
}

/// Export 181 (stock 0x91f6f7d0): find or insert `key` in a path tree
/// and count it in the first 8-byte slot; returns the entry's slots.
extern "C" fn probe_path(block: u32, tree: u32, key: u32) -> u32 {
    // SAFETY: instrumented code passes the standard count block that
    // export 112 published to it.
    let block = unsafe { CountBlock::from_address(block) };
    check_tree_descriptor(block, tree);

    // SAFETY: instrumented code passes one of the block's call tree
    // descriptors.
    let tree = unsafe { object_at::<CallTree>(tree) };
    let key = pgo::tree_key(key);
    let mut link = &tree.root;
    let mut allocated = None;

    let entry = loop {
        let offset = link.load(Ordering::Relaxed);
        if offset != 0 {
            // SAFETY: tree links hold offsets of entries of the tree.
            let entry: &TreeEntry = unsafe { block.at(offset) };
            let existing = entry.key.load(Ordering::Relaxed);
            if existing == key {
                break Some(entry);
            }

            link = if existing > key {
                &entry.lower
            } else {
                &entry.higher
            };
            continue;
        }

        let offset = match allocated {
            Some(offset) => offset,
            None => match allocate(block, block.format().path_entry_size(tree.descriptor())) {
                Some(offset) => *allocated.insert(offset),
                None => break None,
            },
        };

        // SAFETY: `allocate` returned room for an entry of the tree.
        let entry: &TreeEntry = unsafe { block.at(offset) };
        entry.key.store(key, Ordering::Relaxed);
        entry.lower.store(0, Ordering::Relaxed);
        entry.higher.store(0, Ordering::Relaxed);
        if link
            .compare_exchange(0, offset, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            block.path_entries.fetch_add(1, Ordering::AcqRel);
            break Some(entry);
        }
    };

    match entry {
        Some(entry) => {
            if tree.counters != 0 {
                // SAFETY: the tree has a counter; standard entries are
                // 8-byte aligned.
                unsafe { entry.wide_count() }.fetch_add_relaxed(1);
            }
            entry.slots()
        }
        // The image increments at address 0x10 when the tree has counters.
        None => size_of::<TreeEntry>() as u32,
    }
}

/// Find or insert `key` in a call tree: exports 182 and 193 share it.
/// `None` when no entry could be allocated.
///
/// # Safety
///
/// `tree` is the address of a call tree descriptor of `block`.
unsafe fn tree_entry(block: &CountBlock, tree: u32, key: u32) -> Option<&TreeEntry> {
    check_tree_descriptor(block, tree);

    // SAFETY: the caller guarantees the descriptor.
    let tree = unsafe { object_at::<CallTree>(tree) };
    let key = pgo::tree_key(key);
    let mut allocated: Option<u32> = None;

    'restart: loop {
        let mut link = &tree.root;

        loop {
            let offset = link.load(Ordering::Relaxed);
            if offset != 0 {
                // SAFETY: tree links hold offsets of entries of the tree.
                let entry: &TreeEntry = unsafe { block.at(offset) };
                let existing = entry.key.load(Ordering::Relaxed);
                if existing == key {
                    return Some(entry);
                }

                link = if existing > key {
                    &entry.lower
                } else {
                    &entry.higher
                };
                continue;
            }

            let offset = match allocated {
                Some(offset) => offset,
                None => {
                    let generation = block.generation.load(Ordering::Relaxed);
                    let offset =
                        allocate(block, block.format().tree_entry_size(tree.descriptor()))?;
                    allocated = Some(offset);
                    if block.generation.load(Ordering::Relaxed) != generation {
                        continue 'restart;
                    }

                    offset
                }
            };

            // SAFETY: `allocate` returned room for an entry of the tree.
            let entry: &TreeEntry = unsafe { block.at(offset) };
            entry.key.store(key, Ordering::Relaxed);
            entry.lower.store(0, Ordering::Relaxed);
            entry.higher.store(0, Ordering::Relaxed);
            if link
                .compare_exchange(0, offset, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(entry);
            }
        }
    }
}

/// Export 182 (stock 0x91f6fb18): count `key` in a call tree and fill
/// the caller's context for the value probes of the entry.
extern "C" fn probe_call(block: u32, tree: u32, key: u32, frame: u32) {
    // SAFETY: instrumented code passes the extended count block that
    // export 112 published to it and its probe context on its stack.
    let (block, frame) = unsafe {
        (
            CountBlock::from_address(block),
            ProbeContext::from_address(frame),
        )
    };
    let (record, entered) = acquire(block);
    let thread = record.map_or(0, ThreadRecord::address);
    let fill_failed = |frame: &mut ProbeContext| {
        frame.block = block.address();
        frame.generation = 0;
        frame.thread = thread;
        frame.payload = block.scratch;
        frame.descriptor = tree;
    };

    if !entered {
        fill_failed(frame);
        block.lose();
        return;
    }

    // SAFETY: instrumented code passes one of the block's call tree
    // descriptors.
    let Some(entry) = (unsafe { tree_entry(block, tree, key) }) else {
        fill_failed(frame);
        leave_probe(block, record);
        return;
    };

    let payload = entry.slots();
    // SAFETY: as above.
    if unsafe { object_at::<CallTree>(tree) }.counters != 0 {
        // SAFETY: the tree has a counter.
        let count = unsafe { entry.word_count() };
        // Stock's overflow test (`addic.` then `ble` toward 0x91f70920)
        // judges the 64-bit sum of a zero-extended word, which is
        // never <= 0, so the count wraps.
        loop {
            let current = count.load(Ordering::Relaxed);
            if count
                .compare_exchange(
                    current,
                    current.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break;
            }
        }
    }

    frame.block = block.address();
    frame.thread = thread;
    frame.generation = block.generation.load(Ordering::Relaxed);
    frame.payload = payload;
    frame.descriptor = tree;
    if SWEEPING.load(Ordering::Acquire) {
        // SAFETY: the context was filled above.
        unsafe { refresh(frame) };
    }

    leave_probe(block, record);
}

/// Export 193 (stock 0x91f6d940): 1 when the context refers to its entry
/// again, 0 on failure.
extern "C" fn export_lookup(frame: u32) -> u32 {
    // SAFETY: instrumented code passes the probe context export 182
    // filled, on its stack.
    let frame = unsafe { ProbeContext::from_address(frame) };

    // SAFETY: as above.
    u32::from(unsafe { refresh(frame) })
}

/// Refresh a context after a sweep: wait out the sweep, then find or
/// insert its key again. On failure the payload is the block's scratch
/// word.
///
/// # Safety
///
/// Export 182 filled `frame`: its block, thread, and descriptor words
/// name a count block, the calling thread's record or 0, and a call tree
/// descriptor of the block.
unsafe fn refresh(frame: &mut ProbeContext) -> bool {
    loop {
        // SAFETY: the caller guarantees the context's block.
        let block = unsafe { CountBlock::from_address(frame.block) };

        if SWEEPING.load(Ordering::Acquire) {
            if frame.thread == 0 {
                block.lose();
                frame.generation = 0;
                frame.payload = block.scratch;
                return false;
            }

            loop {
                // SAFETY: the caller guarantees the context's thread record.
                leave_probe(block, unsafe { ThreadRecord::from_address(frame.thread) });
                wait_for_sweep();
                // SAFETY: as above.
                enter_probe(block, unsafe { ThreadRecord::from_address(frame.thread) });
                if !SWEEPING.load(Ordering::Acquire) {
                    break;
                }
            }
        }

        // SAFETY: the caller guarantees the context's descriptor.
        let Some(entry) = (unsafe { tree_entry(block, frame.descriptor, frame.key) }) else {
            frame.generation = 0;
            frame.payload = block.scratch;
            return false;
        };

        frame.payload = entry.slots();
        frame.generation = block.generation.load(Ordering::Relaxed);
        if !SWEEPING.load(Ordering::Acquire) {
            return true;
        }
    }
}

/// Insert or count `value` in a sorted list of [`WideEntry`] headed by
/// `list` (exports 183 and 186). `limit` redirects new values past
/// [`pgo::LIST_LIMIT`] to the overflow entry and counts entries in the
/// head.
fn count_wide(block: &CountBlock, list: &WideListHead, mut value: u64, limit: bool) {
    let mut allocated: Option<u32> = None;

    'restart: loop {
        check_list_head(block, address_of(list), size_of::<WideListHead>() as u32);
        // SAFETY: `list` is a value list head of the block.
        unsafe { check_list_entries(block, address_of(list)) };
        let mut link = &list.first;

        'search: loop {
            let mut current = link.load(Ordering::Relaxed);
            while current != 0 {
                // SAFETY: list links hold offsets of wide entries.
                let entry: &WideEntry = unsafe { block.at(current) };
                let existing = entry.value();
                if existing == value {
                    entry.count.fetch_add_relaxed(1);
                    return;
                }
                if existing > value {
                    break;
                }

                link = &entry.next;
                current = link.load(Ordering::Relaxed);
            }

            let offset = match allocated {
                Some(offset) => offset,
                None => {
                    if limit
                        && list.count.load(Ordering::Relaxed) >= pgo::LIST_LIMIT
                        && value != pgo::OVERFLOW_VALUE
                    {
                        value = pgo::OVERFLOW_VALUE;
                        continue 'restart;
                    }

                    // The image increments at address 8 when allocation fails.
                    let Some(offset) = allocate(block, pgo::WIDE_ENTRY_SIZE) else {
                        return;
                    };

                    *allocated.insert(offset)
                }
            };

            // SAFETY: `allocate` returned room for a wide entry.
            let entry: &WideEntry = unsafe { block.at(offset) };
            entry.set_value(value);
            entry
                .next
                .store(link.load(Ordering::Relaxed), Ordering::Relaxed);
            if link
                .compare_exchange(current, offset, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue 'search;
            }

            block.wide_entries.fetch_add(1, Ordering::AcqRel);
            if limit {
                list.count.store(
                    list.count.load(Ordering::Relaxed).wrapping_add(1),
                    Ordering::Relaxed,
                );
            }
            entry.count.fetch_add_relaxed(1);
            return;
        }
    }
}

/// Insert or count `value` in a sorted list of [`WordEntry`] with a
/// [`ListHead`] `list` (exports 184, 185, 187, 188). `limit` applies
/// [`pgo::LIST_LIMIT`] by the head's counter. `frame` is the context of a
/// probe that rebases `list` onto a refreshed call tree entry after a
/// sweep.
///
/// # Safety
///
/// `frame`, when given, satisfies [`refresh`], and `list` lies in the
/// slots of its entry.
unsafe fn count_word(
    block: &CountBlock,
    mut list: &AtomicU32,
    mut value: u64,
    limit: bool,
    mut frame: Option<&mut ProbeContext>,
) {
    let mut allocated: Option<u32> = None;

    'restart: loop {
        check_list_head(block, address_of(list), size_of::<AtomicU32>() as u32);
        // SAFETY: `list` is a value list head of the block.
        unsafe { check_list_entries(block, address_of(list)) };
        let mut previous: Option<&AtomicU32> = None;
        let mut head = list.load(Ordering::Relaxed);
        let mut current = ListHead(head).offset();

        loop {
            let mut found = None;
            while current != 0 {
                // SAFETY: list links hold offsets of word entries.
                let entry: &WordEntry = unsafe { block.at(current) };
                let existing = entry.value.load(Ordering::Relaxed);
                if existing == value as u32 {
                    found = Some(entry);
                    break;
                }
                if existing > value as u32 {
                    break;
                }

                previous = Some(&entry.next);
                current = entry.next.load(Ordering::Relaxed);
            }

            if let Some(entry) = found {
                entry.count.fetch_add(1, Ordering::AcqRel);
                return;
            }

            let offset = match allocated {
                Some(offset) => offset,
                None => {
                    if limit
                        && ListHead(list.load(Ordering::Relaxed)).counter() >= pgo::LIST_LIMIT
                        && value != pgo::OVERFLOW_VALUE
                    {
                        value = pgo::OVERFLOW_VALUE;
                        continue 'restart;
                    }

                    let generation = block.generation.load(Ordering::Relaxed);
                    let Some(offset) = allocate(block, block.format().word_entry_size()) else {
                        return;
                    };
                    allocated = Some(offset);

                    if block.generation.load(Ordering::Relaxed) != generation {
                        if let Some(frame) = frame.as_deref_mut() {
                            let delta = address_of(list).wrapping_sub(frame.payload);
                            // SAFETY: the caller guarantees the context.
                            if !unsafe { refresh(frame) } {
                                return;
                            }

                            // SAFETY: the list keeps its place in the slots of
                            // the refreshed entry.
                            list = unsafe { object_at(frame.payload.wrapping_add(delta)) };
                        }
                        continue 'restart;
                    }

                    offset
                }
            };

            // SAFETY: `allocate` returned room for a word entry.
            let entry: &WordEntry = unsafe { block.at(offset) };
            entry.value.store(value as u32, Ordering::Relaxed);

            match previous {
                None => {
                    entry.next.store(ListHead(head).offset(), Ordering::Relaxed);
                    match list.compare_exchange(
                        head,
                        ListHead(head).advanced(offset).0,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            entry.count.fetch_add(1, Ordering::AcqRel);
                            return;
                        }
                        Err(replaced) => {
                            // The search resumes at the entry it last compared.
                            if current == 0 {
                                current = ListHead(replaced).offset();
                                if current == 0 {
                                    fatal(Fatal::InvalidValueListHead);
                                }
                            }
                            head = replaced;
                        }
                    }
                }
                Some(link) => {
                    entry
                        .next
                        .store(link.load(Ordering::Relaxed), Ordering::Relaxed);
                    if link
                        .compare_exchange(current, offset, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        if limit {
                            let mut expected = head;
                            while let Err(replaced) = list.compare_exchange(
                                expected,
                                ListHead(expected).advanced(ListHead(expected).offset()).0,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            ) {
                                expected = replaced;
                            }
                        }

                        entry.count.fetch_add(1, Ordering::AcqRel);
                        return;
                    }

                    current = link.load(Ordering::Relaxed);
                }
            }
        }
    }
}

/// Exports 184 and 187: count a 32-bit value on the calling thread.
fn word_probe(block: &CountBlock, list: &AtomicU32, value: u64, limit: bool) {
    if !fits32(value) {
        block.lose();
        return;
    }

    let (record, entered) = acquire(block);
    if !entered {
        block.lose();
        return;
    }

    // SAFETY: no context.
    unsafe { count_word(block, list, value, limit, None) };
    leave_probe(block, record);
}

/// Exports 185 and 188: count a 32-bit value of the call tree entry the
/// context refers to, refreshing the context after a sweep.
///
/// # Safety
///
/// As [`count_word`] with `frame`.
unsafe fn tracked_word_probe(
    block: &CountBlock,
    list: &AtomicU32,
    value: u64,
    frame: &mut ProbeContext,
    limit: bool,
) {
    if !fits32(value) {
        block.lose();
        return;
    }

    // SAFETY: the caller guarantees the context's block and thread record.
    let (owner, record) = unsafe {
        (
            CountBlock::from_address(frame.block),
            ThreadRecord::from_address(frame.thread),
        )
    };
    if !enter_probe(owner, record) {
        owner.lose();
        return;
    }

    // SAFETY: the caller guarantees the context and the list.
    if frame.generation == block.generation.load(Ordering::Relaxed) || unsafe { refresh(frame) } {
        // SAFETY: as above.
        unsafe { count_word(block, list, value, limit, Some(&mut *frame)) };
    }

    // SAFETY: the caller guarantees the context's block and thread record.
    let (owner, record) = unsafe {
        (
            CountBlock::from_address(frame.block),
            ThreadRecord::from_address(frame.thread),
        )
    };
    leave_probe(owner, record);
}

/// Export 183 (stock 0x91f6dd18): count a 64-bit value.
extern "C" fn probe_wide(block: u32, list: u32, value: u64) {
    // SAFETY: instrumented code passes the standard count block that
    // export 112 published to it and one of its value list heads.
    let (block, list) = unsafe {
        (
            CountBlock::from_address(block),
            object_at::<WideListHead>(list),
        )
    };

    count_wide(block, list, value, false);
}

/// Export 184 (stock 0x91f6e030).
extern "C" fn probe_word(block: u32, list: u32, value: u64) {
    // SAFETY: instrumented code passes the extended count block that
    // export 112 published to it and one of its value list heads.
    let (block, list) = unsafe {
        (
            CountBlock::from_address(block),
            object_at::<AtomicU32>(list),
        )
    };

    word_probe(block, list, value, false);
}

/// Export 185 (stock 0x91f6e448).
extern "C" fn probe_tracked_word(block: u32, list: u32, value: u64, frame: u32) {
    // SAFETY: instrumented code passes its extended count block, a value
    // list head in the slots of the entry its context refers to, and that
    // context, which export 182 filled, on its stack.
    unsafe {
        tracked_word_probe(
            CountBlock::from_address(block),
            object_at::<AtomicU32>(list),
            value,
            ProbeContext::from_address(frame),
            false,
        )
    };
}

/// Export 186 (stock 0x91f6e8f8): count a 64-bit value, at most ten
/// distinct ones.
extern "C" fn probe_limited_wide(block: u32, list: u32, value: u64) {
    // SAFETY: as in `probe_wide`.
    let (block, list) = unsafe {
        (
            CountBlock::from_address(block),
            object_at::<WideListHead>(list),
        )
    };

    count_wide(block, list, value, true);
}

/// Export 187 (stock 0x91f6ec48).
extern "C" fn probe_limited_word(block: u32, list: u32, value: u64) {
    // SAFETY: as in `probe_word`.
    let (block, list) = unsafe {
        (
            CountBlock::from_address(block),
            object_at::<AtomicU32>(list),
        )
    };

    word_probe(block, list, value, true);
}

/// Export 188 (stock 0x91f6f148).
extern "C" fn probe_limited_tracked_word(block: u32, list: u32, value: u64, frame: u32) {
    // SAFETY: as in `probe_tracked_word`.
    unsafe {
        tracked_word_probe(
            CountBlock::from_address(block),
            object_at::<AtomicU32>(list),
            value,
            ProbeContext::from_address(frame),
            true,
        )
    };
}

/// The bucket of `value` in a range table.
///
/// # Safety
///
/// `table` is the address of a range table with at least one entry, and
/// `count` entries when `count` is nonzero.
unsafe fn range_bucket(value: u64, table: u32) -> u64 {
    // SAFETY: the caller guarantees the table.
    let header = unsafe { object_at::<RangeTableHeader>(table) };
    let range = RangeTable {
        count: header.count,
        flags: header.flags,
    };
    let entries = table + size_of::<RangeTableHeader>() as u32;

    let bucket = range.bucket(value, |index| {
        if range.wide() {
            // SAFETY: the search reads entries the caller guarantees.
            let entry = unsafe { object_at::<[u32; 2]>(entries + 8 * index) };
            u64::from(entry[0]) << 32 | u64::from(entry[1])
        } else {
            // SAFETY: as above.
            u64::from(*unsafe { object_at::<u32>(entries + 4 * index) })
        }
    });

    u64::from(bucket)
}

/// Export 189 (stock 0x91f6f6f0): count the range of a value as export 183.
extern "C" fn probe_wide_range(block: u32, list: u32, value: u64, table: u32) {
    // SAFETY: instrumented code passes the range table of the probe site.
    probe_wide(block, list, unsafe { range_bucket(value, table) });
}

/// Export 190 (stock 0x91f6f740): as export 184.
extern "C" fn probe_word_range(block: u32, list: u32, value: u64, table: u32) {
    // SAFETY: as in `probe_wide_range`.
    probe_word(block, list, unsafe { range_bucket(value, table) });
}

/// Export 191 (stock 0x91f6f790): as export 185.
extern "C" fn probe_tracked_word_range(block: u32, list: u32, value: u64, table: u32, frame: u32) {
    // SAFETY: as in `probe_wide_range`.
    probe_tracked_word(block, list, unsafe { range_bucket(value, table) }, frame);
}

/// Export 192 (stock 0x91f70920): a 31-bit call counter is about to
/// overflow: write a profile and reset, or stop the console.
extern "C" fn export_overflow(block: u32) {
    if !SWEEP_ON_OVERFLOW.load(Ordering::Relaxed) {
        fatal(Fatal::CounterOverflow);
    }

    if let Some(record) = record_of_block(block) {
        snapshot(record, None, true, SweepKind::Overflow);
    }
}

/// Probe entries: the console passes a 64-bit value in one register; the
/// 32-bit routines take it as a register pair, so later arguments move up
/// one register (rldicl 5,5,32,32 puts the high word in r5).
macro_rules! probe_entry {
    ($entry:ident, $target:path, [$($adapt:literal),*]) => {
        #[unsafe(naked)]
        pub(super) unsafe extern "C" fn $entry() {
            core::arch::naked_asm!(
                $($adapt,)*
                "lis 12, {target}@ha",
                "addi 12, 12, {target}@l",
                "b {bridge}",
                target = sym $target,
                bridge = sym crate::exports::export_bridge,
            )
        }
    };
}

probe_entry!(entry_181, probe_path, []);
probe_entry!(entry_182, probe_call, []);
probe_entry!(entry_183, probe_wide, ["mr 6, 5", ".long 0x78a50022"]);
probe_entry!(entry_184, probe_word, ["mr 6, 5", ".long 0x78a50022"]);
probe_entry!(
    entry_185,
    probe_tracked_word,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_186,
    probe_limited_wide,
    ["mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_187,
    probe_limited_word,
    ["mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_188,
    probe_limited_tracked_word,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_189,
    probe_wide_range,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_190,
    probe_word_range,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_191,
    probe_tracked_word_range,
    ["mr 8, 7", "mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);

export_raw!(181, entry_181);
export_raw!(182, entry_182);
export_raw!(183, entry_183);
export_raw!(184, entry_184);
export_raw!(185, entry_185);
export_raw!(186, entry_186);
export_raw!(187, entry_187);
export_raw!(188, entry_188);
export_raw!(189, entry_189);
export_raw!(190, entry_190);
export_raw!(191, entry_191);
export!(192, export_overflow);
export!(193, export_lookup);
