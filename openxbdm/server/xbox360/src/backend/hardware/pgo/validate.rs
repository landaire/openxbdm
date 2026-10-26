//! `ValidateEPLH`, `ValidateVPLH`, and `ValidateVPLE` checks of count block lists.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::hardware::pgo::BlockFormat;
use openxbdm_server::commands::hardware::pgo::Fatal;
use openxbdm_server::commands::hardware::pgo::ListHead;

use super::VALIDATE_EPLH;
use super::VALIDATE_VPLE;
use super::VALIDATE_VPLH;
use super::fatal;
use super::layout::CallTree;
use super::layout::CountBlock;
use super::layout::TreeEntry;
use super::layout::WideEntry;
use super::layout::WideListHead;
use super::layout::WordEntry;
use crate::kernel::object_at;

/// `ValidateEPLH` (0x91f6c278): `descriptor` is the address of a call
/// tree descriptor of the block.
pub(super) fn check_tree_descriptor(block: &CountBlock, descriptor: u32) {
    if !VALIDATE_EPLH.load(Ordering::Relaxed) {
        return;
    }

    let stride = size_of::<CallTree>() as u32;
    let trees = block.address().wrapping_add(block.trees);

    if descriptor < trees
        || descriptor & (stride - 1) != 0
        || descriptor
            > (block.tree_count.wrapping_mul(stride))
                .wrapping_add(trees)
                .wrapping_sub(stride)
    {
        fatal(Fatal::InvalidTreeHead);
    }
}

/// `ValidateVPLH` (0x91f6c3f8): a value list head of the block or of one
/// of its call tree entries, at address `head`.
pub(super) fn check_list_head(block: &CountBlock, head: u32, alignment: u32) {
    if !VALIDATE_VPLH.load(Ordering::Relaxed) {
        return;
    }

    let lists = block.address().wrapping_add(block.lists);

    if head < lists || head & (alignment - 1) != 0 {
        fatal(Fatal::InvalidValueListHead);
    }

    if head
        <= block
            .list_count
            .wrapping_sub(1)
            .wrapping_mul(alignment)
            .wrapping_add(lists)
    {
        return;
    }

    for tree in block.trees() {
        let root = tree.root.load(Ordering::Relaxed);
        // SAFETY: the root link of a descriptor of the block.
        if tree.lists != 0
            && root != 0
            && unsafe { head_in_tree(block, tree, root, head, alignment) }
        {
            return;
        }
    }

    fatal(Fatal::InvalidValueListHead);
}

/// # Safety
///
/// As [`super::sweep::reset_tree`].
unsafe fn head_in_tree(
    block: &CountBlock,
    tree: &CallTree,
    mut offset: u32,
    head: u32,
    alignment: u32,
) -> bool {
    while offset != 0 {
        let entry_address = block.address() + offset;
        let start = block.format().width() * u32::from(tree.counters)
            + entry_address
            + size_of::<TreeEntry>() as u32;
        let last = (u32::from(tree.lists).wrapping_sub(1))
            .wrapping_mul(alignment)
            .wrapping_add(start);

        if head >= start && head <= last {
            return true;
        }

        // SAFETY: the caller guarantees the entry; links of an entry lead
        // to entries of the same tree.
        let entry: &TreeEntry = unsafe { block.at(offset) };

        // SAFETY: as above.
        if unsafe {
            head_in_tree(
                block,
                tree,
                entry.lower.load(Ordering::Relaxed),
                head,
                alignment,
            )
        } {
            return true;
        }

        offset = entry.higher.load(Ordering::Relaxed);
    }

    false
}

/// `ValidateVPLE` (0x91f6c520): every entry of a list lies in the
/// allocated area.
///
/// # Safety
///
/// `head` is the address of a value list head of `block`.
pub(super) unsafe fn check_list_entries(block: &CountBlock, head: u32) {
    if !VALIDATE_VPLE.load(Ordering::Relaxed) {
        return;
    }

    let extended = block.format() == BlockFormat::Extended;
    let mut offset = if extended {
        // SAFETY: the caller guarantees the head.
        ListHead(unsafe { object_at::<AtomicU32>(head) }.load(Ordering::Relaxed)).offset()
    } else {
        // SAFETY: the caller guarantees the head.
        unsafe { object_at::<WideListHead>(head) }
            .first
            .load(Ordering::Relaxed)
    };
    let first = block
        .word_count
        .wrapping_mul(4)
        .wrapping_add(block.words)
        .wrapping_add(block.address());
    let entry_size = if extended {
        size_of::<WordEntry>()
    } else {
        size_of::<WideEntry>()
    };

    while offset != 0 {
        let entry_address = block.address() + offset;
        let last = block
            .address()
            .wrapping_sub(entry_size as u32)
            .wrapping_add(block.used.load(Ordering::Relaxed));
        if entry_address < first || entry_address > last {
            fatal(Fatal::InvalidValueListEntry);
        }

        offset = if extended {
            // SAFETY: the entry lies in the allocated area (checked above).
            unsafe { block.at::<WordEntry>(offset) }
                .next
                .load(Ordering::Relaxed)
        } else {
            // SAFETY: as above.
            unsafe { block.at::<WideEntry>(offset) }
                .next
                .load(Ordering::Relaxed)
        };
    }
}
