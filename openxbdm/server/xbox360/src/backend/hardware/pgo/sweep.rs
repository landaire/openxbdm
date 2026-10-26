//! Thread records, probe entry and sweeps, and count block allocation and reset.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::sync::atomic::fence;

use openxbdm_server::commands::hardware::pgo;
use openxbdm_server::commands::hardware::pgo::BlockFormat;
use openxbdm_server::commands::hardware::pgo::Fatal;
use openxbdm_server::commands::hardware::pgo::ListHead;
use openxbdm_server::commands::hardware::pgo::SweepKind;
use openxbdm_server::commands::memory::PAGE_SIZE;
use xbox360::atomic::AtomicU64;
use xbox360::status::set_last_error;
use xbox360::time::FileTime;
use xbox360_sys::status::KernelError;
use xbox360_sys::xam;
use xbox360_sys::xam::DuplicateHandle;
use xbox360_sys::xam::DuplicateOptions;
use xbox360_sys::xam::GetCurrentThreadId;
use xbox360_sys::xam::GetProcessHeap;
use xbox360_sys::xam::HeapFlags;
use xbox360_sys::xam::ResetEvent;
use xbox360_sys::xam::RtlAllocateHeap;
use xbox360_sys::xam::RtlFreeHeap;
use xbox360_sys::xam::WaitResult;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::KeTlsGetValue;
use xbox360_sys::xboxkrnl::KeTlsSetValue;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::TlsIndex;

use super::SECTION;
use super::SWEEP_EVENT;
use super::SWEEP_FULL_BUFFER;
use super::SWEEPING;
use super::THREADS;
use super::TLS_INDEX;
use super::fatal;
use super::layout::CallTree;
use super::layout::CountBlock;
use super::layout::ModuleRecord;
use super::layout::ThreadRecord;
use super::layout::TreeEntry;
use super::layout::WideEntry;
use super::layout::WideListHead;
use super::layout::WordEntry;
use super::layout::list_head_size;
use super::locked_record_of_block;
use super::profile::write_profile;
use super::record_of_block;
use super::start_counting;
use super::stop_counting;
use super::title_thread;

fn sleep_zero() {
    let interval = 0i64;
    // SAFETY: `interval` is a live local.
    unsafe { xboxkrnl::KeDelayExecutionThread(ProcessorMode::User, false, &interval) };
}

/// Close a handle; a failure sets the last error.
pub(super) fn close_handle(handle: Handle) -> Result<(), KernelError> {
    // SAFETY: callers pass a handle they own and close once.
    let result = unsafe { xboxkrnl::NtClose(handle) }.result();

    result.inspect_err(|&error| set_last_error(error))
}

pub(super) fn wait_for_sweep() {
    // SAFETY: SWEEP_EVENT holds the event created at startup.
    unsafe {
        xam::WaitForSingleObject(
            Handle::from_raw(SWEEP_EVENT.load(Ordering::Acquire)),
            xam::INFINITE,
        )
    };
}

/// Enter a probe (0x91f6c690): mark the thread inside, or count it
/// without a record, then wait out a sweep. A thread without a record
/// cannot wait and fails; its count stays raised, as in the image.
pub(super) fn enter_probe(block: &CountBlock, record: Option<&ThreadRecord>) -> bool {
    match record {
        Some(record) => {
            record.enter();
            fence(Ordering::Release);
        }
        None => {
            block.untracked.fetch_add(1, Ordering::AcqRel);
        }
    }

    while SWEEPING.load(Ordering::Acquire) {
        let Some(record) = record else {
            return false;
        };

        record.leave();
        wait_for_sweep();
        record.enter();
        fence(Ordering::Release);
    }

    true
}

pub(super) fn leave_probe(block: &CountBlock, record: Option<&ThreadRecord>) {
    match record {
        Some(record) => record.leave(),
        None => {
            block.untracked.fetch_add(u32::MAX, Ordering::AcqRel);
        }
    }
}

/// The calling thread's record, if it has one.
fn own_record() -> Option<&'static ThreadRecord> {
    let index = TlsIndex(TLS_INDEX.load(Ordering::Acquire));

    // SAFETY: the slot holds 0 or the calling thread's record.
    unsafe { ThreadRecord::from_address(KeTlsGetValue(index)) }
}

/// The calling thread's record, created on first use (0x91f6c728).
fn thread_record(block: &CountBlock) -> Option<&'static ThreadRecord> {
    if !title_thread() {
        return None;
    }

    let index = TlsIndex(TLS_INDEX.load(Ordering::Acquire));
    // SAFETY: the slot holds 0 or the calling thread's record.
    if let Some(existing) = unsafe { ThreadRecord::from_address(KeTlsGetValue(index)) } {
        return Some(existing);
    }

    // SAFETY: the process heap takes a size only.
    let address = unsafe {
        RtlAllocateHeap(
            GetProcessHeap(),
            HeapFlags::empty(),
            size_of::<ThreadRecord>() as u32,
        )
    };
    if address == 0 {
        fatal(Fatal::ThreadListAllocation);
    }

    let pointer = core::ptr::with_exposed_provenance_mut::<ThreadRecord>(address as usize);
    // SAFETY: a new heap block of the record's size and alignment, which
    // only this thread reaches until it is linked below.
    unsafe {
        (&raw mut (*pointer).state).write(AtomicU32::new(0));
        (&raw mut (*pointer).id).write(GetCurrentThreadId());
    }

    let mut handle = Handle::NULL;
    // SAFETY: `handle` is a local handle slot.
    let duplicated = unsafe {
        DuplicateHandle(
            Handle::NULL,
            Handle::CURRENT_THREAD,
            Handle::NULL,
            &mut handle,
            AccessMask::empty(),
            false,
            DuplicateOptions::SAME_ACCESS,
        )
    }
    .get();
    if !duplicated {
        fatal(Fatal::ThreadHandle);
    }

    // SAFETY: as above.
    unsafe { (&raw mut (*pointer).handle).write(handle) };
    block.threads.fetch_add(1, Ordering::AcqRel);

    loop {
        let head = THREADS.load(Ordering::Acquire);
        // SAFETY: as above; the record is not linked yet.
        unsafe { (&raw mut (*pointer).next).write(AtomicU32::new(head)) };
        if THREADS
            .compare_exchange(head, address, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }

    // SAFETY: every field is written; the record stays allocated while its
    // thread runs.
    let record = unsafe { &*pointer };
    // SAFETY: `index` is the slot allocated at startup.
    unsafe { KeTlsSetValue(index, address) };

    Some(record)
}

pub(super) fn acquire(block: &CountBlock) -> (Option<&'static ThreadRecord>, bool) {
    let record = thread_record(block);

    (record, enter_probe(block, record))
}

/// Leave the probe ahead of a sweep (0x91f6c618).
fn release_for_sweep(block: &CountBlock) -> Option<&'static ThreadRecord> {
    let record = if title_thread() { own_record() } else { None };
    leave_probe(block, record);

    record
}

/// Stop probes for a sweep (0x91f6c8d8, extended blocks only): optionally
/// start a new generation, then wait until no other thread is inside a
/// probe, freeing the records of threads that ended. Runs under the
/// registration lock.
fn begin_sweep(block: &CountBlock, new_generation: bool) {
    if block.format() != BlockFormat::Extended {
        return;
    }

    // SAFETY: SWEEP_EVENT holds the event created at startup.
    unsafe { ResetEvent(Handle::from_raw(SWEEP_EVENT.load(Ordering::Acquire))) };
    fence(Ordering::Release);
    SWEEPING.store(true, Ordering::Release);

    if new_generation {
        fence(Ordering::Release);
        block.generation.store(
            block.generation.load(Ordering::Relaxed).wrapping_add(1),
            Ordering::Relaxed,
        );
    }
    fence(Ordering::SeqCst);

    let own_address = if title_thread() {
        KeTlsGetValue(TlsIndex(TLS_INDEX.load(Ordering::Acquire)))
    } else {
        0
    };

    loop {
        let mut link = &THREADS;
        let mut busy = block.untracked.load(Ordering::Relaxed);
        let mut current = link.load(Ordering::Relaxed);

        // SAFETY: THREADS links records of thread_record; only this
        // function frees them, under the registration lock.
        while let Some(record) = unsafe { ThreadRecord::from_address(current) } {
            if current != own_address {
                // SAFETY: a record holds the duplicated handle of its thread.
                if unsafe { xam::WaitForSingleObject(record.handle, 0) } == WaitResult::OBJECT_0
                    && link
                        .compare_exchange(
                            current,
                            record.next.load(Ordering::Relaxed),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                {
                    let _ = close_handle(record.handle);
                    // SAFETY: the record was unlinked above and came from the
                    // process heap; its thread ended.
                    unsafe { RtlFreeHeap(GetProcessHeap(), HeapFlags::empty(), current) };
                    current = link.load(Ordering::Relaxed);
                    continue;
                }

                if record.state.load(Ordering::Relaxed) == current {
                    busy = busy.wrapping_add(1);
                }
            }

            link = &record.next;
            current = link.load(Ordering::Relaxed);
        }

        if busy == 0 {
            return;
        }

        sleep_zero();
    }
}

fn end_sweep() {
    fence(Ordering::SeqCst);
    SWEEPING.store(false, Ordering::Release);

    // SAFETY: SWEEP_EVENT holds the event created at startup.
    let status = unsafe {
        xboxkrnl::NtSetEvent(
            Handle::from_raw(SWEEP_EVENT.load(Ordering::Acquire)),
            core::ptr::null_mut(),
        )
    };
    if let Err(error) = status.result() {
        set_last_error(error);
    }
}

/// Count block time: GetSystemTime through SystemTimeToFileTime keeps
/// whole milliseconds.
pub(super) fn block_time() -> u64 {
    FileTime::now().intervals() / 10_000 * 10_000
}

/// Raise the committed size to cover `offset` (0x91f6bc18); past the
/// reservation the console stops.
fn grow(block: &CountBlock, offset: u32) {
    let committed = pgo::align_up(offset.wrapping_add(PAGE_SIZE), PAGE_SIZE);
    if committed > block.reserved {
        locked_record_of_block(block.address());
        fatal(Fatal::ReservationExhausted);
    }

    block.committed.swap(committed, Ordering::AcqRel);
}

/// Allocate `size` bytes of a count block for an entry, sweeping a full
/// extended block when `EnableSweepFullBuffer` is set. Returns the
/// entry's offset; `None` when the thread cannot take part in the sweep.
pub(super) fn allocate(block: &CountBlock, size: u32) -> Option<u32> {
    let mut offset = block.used.fetch_add(size, Ordering::AcqRel);

    loop {
        let end = offset.wrapping_add(size);
        if end <= block.committed.load(Ordering::Relaxed) {
            return (offset != 0).then_some(offset);
        }

        let sweep_full = block.format() == BlockFormat::Extended
            && SWEEP_FULL_BUFFER.load(Ordering::Relaxed)
            && end > block.reserved;
        if !sweep_full {
            grow(block, offset);
            return (offset != 0).then_some(offset);
        }

        // Without a record the image would use the offset past the
        // reservation; the entry is dropped instead.
        let record = record_of_block(block.address())?;
        let Some(thread) = release_for_sweep(block) else {
            block.lose();
            return None;
        };

        SECTION.enter();
        if block.used.load(Ordering::Relaxed).wrapping_add(size) > block.reserved {
            full_buffer_sweep(record, block);
        }
        SECTION.leave();

        enter_probe(block, Some(thread));
        offset = block.used.fetch_add(size, Ordering::AcqRel);
    }
}

fn full_buffer_sweep(record: &ModuleRecord, block: &CountBlock) {
    begin_sweep(block, true);
    stop_counting(record);

    let state = block.extended_state();
    state.resetting.store(1, Ordering::Relaxed);
    state
        .sweep_kind
        .store(SweepKind::FullBuffer as u8, Ordering::Relaxed);
    state.full_buffer[0].store(1, Ordering::Relaxed);
    state.full_buffer[1].store(1, Ordering::Relaxed);
    write_profile(record);
    state.sweep_kind.store(0, Ordering::Relaxed);
    state.resetting.store(0, Ordering::Relaxed);

    block.set_time(block_time());
    clear_block(block);
    block.committed.store(
        pgo::align_up(block.used.load(Ordering::Relaxed), PAGE_SIZE),
        Ordering::Relaxed,
    );

    start_counting(record);
    end_sweep();
}

/// Clear every count and free every entry (0x91f70f88). Extended blocks
/// only, from a full-buffer sweep.
fn clear_block(block: &CountBlock) {
    let width = block.format().width();
    // SAFETY: the counts and list regions hold `count_slots` counters and
    // `list_count` heads (create_block) at word-aligned offsets; only
    // instrumented code writes the counts, and the sweep stopped the
    // probes. The image clears 4 bytes per head in both formats.
    unsafe {
        block.zero(block.counts, width.wrapping_mul(block.count_slots));
        block.zero(block.lists, block.list_count.wrapping_mul(4));
    }

    for tree in block.trees().iter().skip(1) {
        tree.root.store(0, Ordering::Relaxed);
    }

    let used = pgo::align_up(
        block.word_count.wrapping_mul(4).wrapping_add(block.words),
        size_of::<u32>() as u32,
    );
    block.used.store(used, Ordering::Relaxed);

    // SAFETY: the entry area lies between the word table and the committed
    // end, both word-aligned; the sweep stopped the probes.
    unsafe {
        block.zero(
            used,
            block.committed.load(Ordering::Relaxed).wrapping_sub(used),
        )
    };
}

/// Clear counts and keep entries (0x91f70e40).
pub(super) fn reset_counts(block: &CountBlock) {
    let format = block.format();
    // SAFETY: the counts region holds `count_slots` counters at a
    // word-aligned offset, which only instrumented code writes.
    unsafe { block.zero(block.counts, format.width().wrapping_mul(block.count_slots)) };

    for index in 0..block.list_count {
        // SAFETY: the list region holds `list_count` heads.
        unsafe { reset_list(block, format, block.lists + list_head_size(format) * index) };
    }

    for tree in block.trees().iter().skip(1) {
        // SAFETY: the root link of a descriptor of the block.
        unsafe { reset_tree(block, format, tree, tree.root.load(Ordering::Relaxed)) };
    }
}

/// Clear the counts of one value list.
///
/// # Safety
///
/// `slot` is the offset of a value list head of `block` in `format`.
unsafe fn reset_list(block: &CountBlock, format: BlockFormat, slot: u32) {
    match format {
        BlockFormat::Extended => {
            // SAFETY: the caller guarantees the head.
            let head: &AtomicU32 = unsafe { block.at(slot) };
            let mut offset = ListHead(head.load(Ordering::Relaxed)).offset();
            while offset != 0 {
                // SAFETY: list links hold offsets of word entries.
                let entry: &WordEntry = unsafe { block.at(offset) };
                offset = entry.next.load(Ordering::Relaxed);
                entry.count.store(0, Ordering::Relaxed);
            }
        }
        BlockFormat::Standard => {
            // SAFETY: the caller guarantees the head.
            let head: &WideListHead = unsafe { block.at(slot) };
            let mut offset = head.first.load(Ordering::Relaxed);
            while offset != 0 {
                // SAFETY: list links hold offsets of wide entries.
                let entry: &WideEntry = unsafe { block.at(offset) };
                offset = entry.next.load(Ordering::Relaxed);
                entry.count.store_relaxed(0);
            }
        }
    }
}

/// Clear the counts of a call tree (0x91f70cf0).
///
/// # Safety
///
/// `offset` is 0 or the offset of an entry of `tree`, a descriptor of
/// `block`.
unsafe fn reset_tree(block: &CountBlock, format: BlockFormat, tree: &CallTree, mut offset: u32) {
    let width = format.width();

    while offset != 0 {
        // SAFETY: the caller guarantees the entry; links of an entry lead
        // to entries of the same tree.
        let entry: &TreeEntry = unsafe { block.at(offset) };
        let counters = u32::from(tree.counters);
        let lists = u32::from(tree.lists);
        let slots = offset + size_of::<TreeEntry>() as u32;

        match format {
            // SAFETY: the word-aligned entry holds `counters` word counters
            // after its links.
            BlockFormat::Extended => unsafe { block.zero(slots, width * counters) },
            // Probes update these counters as doublewords, so they are
            // cleared as doublewords where stock calls memset (deviation).
            BlockFormat::Standard => {
                for index in 0..counters {
                    // SAFETY: the 8-byte aligned entry holds `counters`
                    // doubleword counters after its links.
                    let counter: &AtomicU64 = unsafe { block.at(slots + width * index) };
                    counter.store_relaxed(0);
                }
            }
        }

        let heads = slots + width * counters;
        for index in 0..lists {
            // SAFETY: the entry holds `lists` heads after its counters.
            unsafe { reset_list(block, format, heads + list_head_size(format) * index) };
        }

        // SAFETY: as above.
        unsafe { reset_tree(block, format, tree, entry.lower.load(Ordering::Relaxed)) };
        offset = entry.higher.load(Ordering::Relaxed);
    }
}
