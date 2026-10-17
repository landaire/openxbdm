//! Capture start and stop (stock 0x91f5fb68, 0x91f60800): per-hardware-
//! thread capture buffers installed in the processor control regions by
//! IPI (0x91f5e810, 0x91f5fd98), the context swap record routine
//! (0x91f5f948), the 100 ms marker timer, and the frame records
//! (0x91f5e5b8).

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_server::notify::ExecutionState;
use xbox360::time::Timebase;
use xbox360_sys::mmio::GpuRegisters;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::KernelU32;
use xbox360_sys::xboxkrnl::Kthread;

use super::super::RecordTag;
use super::super::session;
use super::super::session::EngineFlags;
use super::super::session::FrameRecord;
use super::super::session::Part;
use super::super::session::PixSession;
use super::super::session::StreamId;
use super::super::session::TEMPORARY_BLOCKS;
use super::super::session::TEMPORARY_BYTES;
use super::super::session::TemporaryState;
use super::TimingRecordId;
use super::buffers;
use super::buffers::BufferEntry;
use super::buffers::BufferType;
use super::buffers::HEADER_BYTES;
use super::gpu::CommandBufferError;
use super::gpu::StreamRecordKind;
use super::gpu::fence_header;
use super::timing;
use super::timing::RecordKind;
use crate::kernel;

/// Limits of the per-thread buffers the kernel and titles fill and of the
/// second buffers, as offsets from the buffer data.
pub(super) const THREAD_LIMIT: u32 = 0x3f2c;
const SECOND_THREAD_LIMIT: u32 = 0x3ff0;
/// Frame record kind of [`stop`].
const STOP_RECORD: u32 = 1;
/// Return addresses of a call stack in a context swap record.
const STACK_FRAMES: u32 = 0x13;
/// Dwords of a call stack in a context swap record, with its terminator.
const STACK_SLOTS: usize = STACK_FRAMES as usize + 1;
/// Dwords of the longest context swap record: the two header words, the
/// incoming thread, two call stacks, the outgoing thread.
const SWAP_RECORD_WORDS: usize = 3 + 2 * STACK_SLOTS + 1;
const _: () = assert!(SWAP_RECORD_WORDS as u32 * 4 <= timing::RECORD_RESERVE);

xbox360_sys::flags! {
    /// PCR PIX flags.
    pub struct PixFlags(u32) {
        /// Instruction trace switch of `pixcmd b`/`e`; capture keeps it.
        TRACE = 0x1,
    }
}

/// Bounds of one PIX buffer in an [`InstallContext`].
#[repr(C)]
struct BufferBounds {
    cursor: AtomicU32,
    limit: AtomicU32,
}

/// Capture context of one processor that [`start`] hands to [`install`].
#[repr(C)]
struct InstallContext {
    session: AtomicU32,
    buffers: [BufferBounds; 2],
    /// PCR PIX flags of the second buffer.
    flags: AtomicU32,
}

impl InstallContext {
    const fn new() -> Self {
        Self {
            session: AtomicU32::new(0),
            buffers: [const {
                BufferBounds {
                    cursor: AtomicU32::new(0),
                    limit: AtomicU32::new(0),
                }
            }; 2],
            flags: AtomicU32::new(0),
        }
    }
}

/// Context of one processor that [`stop`] hands to [`uninstall`], over a
/// `[u32; 3]` of its array: the session, then the cursors of the two
/// buffers.
#[repr(C)]
struct UninstallContext {
    session: AtomicU32,
    cursors: [AtomicU32; 2],
}

const _: () = assert!(size_of::<UninstallContext>() == size_of::<[u32; 3]>());

/// Start capturing with the current configuration (stock 0x91f5fb68).
pub(super) fn start(s: &PixSession) {
    /// Bounds of a buffer that is always full: while tracing, every writer
    /// asks code 0x50.
    const FULL_CURSOR: u32 = 0x8000_0000;
    const FULL_LIMIT: u32 = 1;
    /// The marker timer expires 100 ms from now (relative, in 100 ns
    /// units), then every 100 ms.
    const MARKER_DUE: i64 = -1_000_000;
    const MARKER_PERIOD_MS: u32 = 100;

    let context = [const { InstallContext::new() }; HARDWARE_THREAD_COUNT];
    let configuration = &s.configuration;
    let mut streams = 0u32;
    s.set_engine_flags(s.engine_flags() | EngineFlags::RUNNING);
    let (first_entries, second_entries) = s.entries.split_at(BufferType::SECOND_THREAD as usize);
    let slots = context.iter().zip(first_entries).zip(second_entries);
    for (index, ((slot, first_entry), second_entry)) in slots.enumerate() {
        let [first, second] = &slot.buffers;
        slot.session.store(s.address(), Relaxed);
        let part = configuration.part(Part::Thread);
        if !part.is_off() {
            streams |= part.bit();
            let entry = buffers::take(s, BufferType(index as u32), part.0);
            first_entry.store(entry.address(), Relaxed);
            let data = entry.data();
            first.cursor.store(data + HEADER_BYTES, Relaxed);
            first.limit.store(data + THREAD_LIMIT, Relaxed);
        } else if configuration.tracing.load(Relaxed) != 0 {
            first.limit.store(FULL_LIMIT, Relaxed);
            first.cursor.store(FULL_CURSOR, Relaxed);
        }
        let part = configuration.part(Part::SecondThread);
        if !part.is_off() && configuration.second_threads.load(Relaxed) & 1 << index != 0 {
            streams |= part.bit();
            let kind = BufferType(index as u32 + BufferType::SECOND_THREAD);
            let entry = buffers::take(s, kind, part.0);
            second_entry.store(entry.address(), Relaxed);
            slot.flags
                .store(configuration.second_flags.load(Relaxed), Relaxed);
            let data = entry.data();
            second.cursor.store(data + HEADER_BYTES, Relaxed);
            second.limit.store(data + SECOND_THREAD_LIMIT, Relaxed);
        }
        for &part in &[Part::Gpu, Part::Audio] {
            let part = configuration.part(part);
            if !part.is_off() {
                streams |= part.bit();
            }
        }
    }
    // SAFETY: `install_entry` is an IPI routine; `context` outlives the
    // call, which returns after every processor ran it.
    unsafe {
        xboxkrnl::KeIpiGenericCall(
            install_entry as *const () as usize as u32,
            context.as_ptr().expose_provenance() as u32,
        )
    };
    if !configuration.part(Part::Thread).is_off() {
        // SAFETY: the DPC and timer lie in the session block, which is
        // never freed; `stop` cancels the timer.
        unsafe {
            xboxkrnl::KeInitializeDpc(s.marker_dpc.as_ptr(), marker_entry as *const () as usize, 0)
        };
        // SAFETY: as above.
        unsafe {
            xboxkrnl::KeInitializeTimerEx(
                s.marker_timer.as_ptr(),
                xboxkrnl::TimerType::Notification,
                xboxkrnl::ProcessType::SYSTEM,
            )
        };
        // SAFETY: as above; the timer and the DPC were just initialized.
        unsafe {
            xboxkrnl::KeSetTimerEx(
                s.marker_timer.as_ptr(),
                MARKER_DUE,
                MARKER_PERIOD_MS,
                s.marker_dpc.as_ptr(),
            )
        };
    }
    for k in 0..2 {
        if streams & 1 << k != 0 {
            let id = StreamId::from_raw(k);
            let entry = buffers::take(s, BufferType::records(id), k);
            s.record_entries[id as usize].store(entry.address(), Relaxed);
            let data = entry.data();
            s.record_cursors[id as usize].store(data + HEADER_BYTES, Relaxed);
            s.record_ends[id as usize].store(data + buffers::BUFFER_BYTES, Relaxed);
        }
    }
    s.streams_mask.store(streams, Relaxed);
    if !configuration.part(Part::Audio).is_off() {
        s.audio_enabled.store(1, Relaxed);
    }
    update_swap_routine(s);
}

/// Register the swap routine while capturing per-thread data and not
/// paused, else remove it (stock 0x91f5fad0).
pub(super) fn update_swap_routine(s: &PixSession) {
    let flags = s.engine_flags();
    let wanted = flags.contains(EngineFlags::RUNNING)
        & !flags.contains(EngineFlags::PAUSED)
        & !s.configuration.part(Part::Thread).is_off();
    let registered = &s.swap_routine_registered;
    if wanted != (registered.load(Relaxed) != 0) {
        if wanted {
            crate::backend::session::register_swap_routine(swap_record, false);
        } else {
            crate::backend::session::unregister_swap_routine(swap_record);
        }
        registered.store(u32::from(wanted), Relaxed);
    }
}

crate::exports::bridged!(install_entry, install);
crate::exports::bridged!(uninstall_entry, uninstall);
crate::exports::bridged!(marker_entry, marker_dpc);
crate::exports::bridged!(marker_ipi_entry, marker_ipi);

/// The session whose address [`start`] or [`stop`] put in an IPI context.
///
/// # Safety
///
/// `address` must be the address of the session block.
unsafe fn context_session(address: u32) -> &'static PixSession {
    // SAFETY: guaranteed by the caller; the block is never freed.
    unsafe { kernel::object_at(address) }
}

/// IPI routine of [`start`] (stock 0x91f5e810): hand the processor its
/// buffers and publish where its cursors live.
extern "C" fn install(context: u32) -> u32 {
    let processor = super::processor();
    // SAFETY: `start` passes its context array, which outlives the IPI
    // call; the processors only read it.
    let contexts = unsafe { kernel::object_at::<[InstallContext; HARDWARE_THREAD_COUNT]>(context) };
    let slot = &contexts[processor];
    // SAFETY: `start` puts the session's address in every slot.
    let s = unsafe { context_session(slot.session.load(Relaxed)) };
    let pcr = Kpcr::current();
    super::interrupts_off();
    s.cursors[processor].store(
        crate::kernel::address_of(&pcr.pix_buffers[0].cursor),
        Relaxed,
    );
    s.second_cursors[processor].store(
        crate::kernel::address_of(&pcr.pix_buffers[1].cursor),
        Relaxed,
    );
    let [first, second] = &pcr.pix_buffers;
    let [first_bounds, second_bounds] = &slot.buffers;
    // SAFETY: the bounds of this processor's buffers in the session, which
    // stay allocated until `uninstall` takes them back, or empty ranges.
    unsafe {
        super::set_pcr_word(&first.cursor, first_bounds.cursor.load(Relaxed));
        super::set_pcr_word(&first.limit, first_bounds.limit.load(Relaxed));
        super::set_pcr_word(&second.cursor, second_bounds.cursor.load(Relaxed));
        super::set_pcr_word(&second.limit, second_bounds.limit.load(Relaxed));
    }
    let flags = PixFlags::from_bits_retain(slot.flags.load(Relaxed)).difference(PixFlags::TRACE)
        | PixFlags::from_bits_retain(pcr.pix_flags.load(Relaxed)) & PixFlags::TRACE;
    // SAFETY: the flags the configuration selects for the second buffer,
    // which is installed or empty.
    unsafe { super::set_pcr_word(&pcr.pix_flags, flags.bits()) };
    super::interrupts_on();
    0
}

/// IPI routine of [`stop`] (stock 0x91f5fd98): take the buffers back and
/// report the cursors in the context.
extern "C" fn uninstall(context: u32) -> u32 {
    let processor = super::processor();
    // SAFETY: `stop` passes its context array, which outlives the IPI
    // call; each processor writes its own slot only.
    let contexts =
        unsafe { kernel::object_at::<[UninstallContext; HARDWARE_THREAD_COUNT]>(context) };
    let slot = &contexts[processor];
    // SAFETY: `stop` puts the session's address in every slot.
    let s = unsafe { context_session(slot.session.load(Relaxed)) };
    let pcr = Kpcr::current();
    super::interrupts_off();
    for (second, buffer) in pcr.pix_buffers.iter().enumerate() {
        let index = processor + second * BufferType::SECOND_THREAD as usize;
        // SAFETY: `processor` is below 6 and `second` below 2.
        unsafe { core::hint::assert_unchecked(index < TEMPORARY_BLOCKS) };
        let cursor = buffer.cursor.load(Relaxed);
        let base = s.temporary_blocks[index].load(Relaxed);
        if (base..base.wrapping_add(TEMPORARY_BYTES)).contains(&cursor) {
            // The raw word: values above 2 do nothing here, as in stock,
            // where `TemporaryState::from_raw` would merge.
            let state = s.temporary_states[index].load(Relaxed);
            if state == TemporaryState::InUse as u32 {
                // SAFETY: the saved cursor lies in this processor's buffer;
                // interrupts stay off until both words are cleared below, so
                // no writer uses the range meanwhile.
                unsafe {
                    super::set_pcr_word(&buffer.cursor, s.saved_cursors[index].load(Relaxed))
                };
                super::fence();
                s.set_temporary_state(index, TemporaryState::None);
                super::fence();
                if second == 0 {
                    kernel::debug_print(
                        c"WRN[PIX]: EndStreaming discarded overflowed raised-IRQL data.\n",
                    );
                }
            } else if state == TemporaryState::Merge as u32 {
                timing::merge(s);
            }
        }
    }
    let [first, second] = &pcr.pix_buffers;
    slot.cursors[0].store(first.cursor.load(Relaxed), Relaxed);
    slot.cursors[1].store(second.cursor.load(Relaxed), Relaxed);
    // SAFETY: empty buffers stop the kernel and titles from writing records
    // on this processor.
    unsafe {
        super::set_pcr_word(&first.cursor, 0);
        super::set_pcr_word(&first.limit, 0);
        super::set_pcr_word(&second.cursor, 0);
        super::set_pcr_word(&second.limit, 0);
    }
    let flags = PixFlags::from_bits_retain(pcr.pix_flags.load(Relaxed)) & PixFlags::TRACE;
    // SAFETY: cleared capture flags; the trace switch stays.
    unsafe { super::set_pcr_word(&pcr.pix_flags, flags.bits()) };
    super::interrupts_on();
    0
}

/// Timer DPC (stock 0x91f5cf20): a marker record on every processor.
extern "C" fn marker_dpc(_dpc: u32, _context: u32, _argument1: u32, _argument2: u32) {
    // SAFETY: `marker_ipi_entry` is an IPI routine without a context.
    unsafe { xboxkrnl::KeIpiGenericCall(marker_ipi_entry as *const () as usize as u32, 0) };
}

/// Stock 0x91f5cef0.
extern "C" fn marker_ipi(_context: u32) -> u32 {
    timing::write_record(TimingRecordId::Marker, &[]);
    0
}

/// Context swap routine (stock 0x91f5f948): a record with both threads'
/// call stacks and identifiers in the outgoing processor's buffer.
extern "C" fn swap_record(old: u32, frame: u32, new: u32) {
    let Some(s) = session::session() else {
        return;
    };
    let processor = super::processor();
    let pcr = Kpcr::current();
    // SAFETY: the kernel passes the objects of the outgoing and the
    // incoming thread, which stay allocated during the switch.
    let (old, new) = unsafe { (kernel::thread_at(old), kernel::thread_at(new)) };
    let old_id = old.id;
    let new_id = timing::record_thread_id(pcr, new);
    let buffer = &pcr.pix_buffers[0];
    super::interrupts_off();
    let mut cursor = buffer.cursor.load(Relaxed);
    if cursor >= buffer.limit.load(Relaxed) {
        super::interrupts_on();
        timing::request_at_raised_level(s);
        super::interrupts_off();
        cursor = buffer.cursor.load(Relaxed);
        if cursor >= buffer.limit.load(Relaxed) {
            s.lost[processor].store(1, Relaxed);
            super::interrupts_on();
            return;
        }
    }
    // SAFETY: the cursor, read with interrupts off, is below the limit, so
    // the longest record fits in the reserve after it; only this processor
    // writes there.
    let record = unsafe { crate::kernel::object_at::<[AtomicU32; SWAP_RECORD_WORDS]>(cursor) };
    record[0].store(RecordKind::Data.header(), Relaxed);
    record[2].store(new_id, Relaxed);
    let first = walk_stack(stack_slots(record, 3), frame, old, 1);
    let second_start = 3 + first;
    let second = walk_stack(
        stack_slots(record, second_start),
        new.switch_frame.load(Relaxed),
        new,
        0,
    );
    // SAFETY: `walk_stack` stores at most `STACK_SLOTS` dwords.
    unsafe { core::hint::assert_unchecked(second <= STACK_SLOTS) };
    let end = second_start + second;
    record[end].store(old_id, Relaxed);
    let total = end as u32 + 1;
    record[1].store(timing::id_word(TimingRecordId::ContextSwap, total), Relaxed);
    // SAFETY: the new cursor ends the record written inside the buffer.
    unsafe { super::set_pcr_word(&buffer.cursor, cursor + total * 4) };
    super::interrupts_on();
}

/// The [`STACK_SLOTS`] dwords of a context swap record from `start`, the
/// start of a call stack.
#[inline(always)]
fn stack_slots(record: &[AtomicU32; SWAP_RECORD_WORDS], start: usize) -> &[AtomicU32; STACK_SLOTS] {
    // SAFETY: the first call stack starts at 3 and holds at most
    // `STACK_SLOTS` dwords, as `walk_stack` stores.
    unsafe { core::hint::assert_unchecked(start <= 3 + STACK_SLOTS) };
    match record[start..].first_chunk() {
        Some(slots) => slots,
        None => unreachable!(),
    }
}

/// Whether `address` is inside `thread`'s stack (stock 0x91f5cd08; the
/// monitor's own exception stacks stock also accepts do not exist here).
fn in_stack(thread: &Kthread, address: u32) -> bool {
    address < thread.stack_base.load(Relaxed) && address > thread.stack_limit.load(Relaxed)
}

/// Word of a thread's stack at `address`.
///
/// # Safety
///
/// `address` must be an aligned word inside the stack of a thread of the
/// switch, as [`in_stack`] checks; the stack stays mapped and its frames
/// above the swap routine do not change during the switch.
unsafe fn stack_word(address: u32) -> u32 {
    // SAFETY: guaranteed by the caller.
    unsafe { kernel::object_at::<AtomicU32>(address) }.load(Relaxed)
}

/// Store up to [`STACK_FRAMES`] return addresses of the frame chain from
/// `frame`, after skipping `skip` frames, and a terminating 0 in `slots`
/// (stock 0x91f5cd88); the dwords stored.
fn walk_stack(
    slots: &[AtomicU32; STACK_SLOTS],
    mut frame: u32,
    thread: &Kthread,
    skip: u32,
) -> usize {
    for _ in 0..skip {
        if !in_stack(thread, frame) {
            break;
        }
        // SAFETY: the back chain word of a frame inside the stack.
        frame = unsafe { stack_word(frame) };
    }
    let mut count = 0;
    while count < STACK_FRAMES as usize
        && in_stack(thread, frame)
        && in_stack(thread, frame.wrapping_sub(8))
    {
        // SAFETY: the saved return address, inside the stack.
        let address = unsafe { stack_word(frame - 8) };
        if address != 0 {
            slots[count].store(address, Relaxed);
            count += 1;
        }
        // SAFETY: the back chain word of a frame inside the stack.
        frame = unsafe { stack_word(frame) };
    }
    // SAFETY: the loop stores while `count` is below STACK_FRAMES and adds
    // one per store.
    unsafe { core::hint::assert_unchecked(count <= STACK_FRAMES as usize) };
    slots[count].store(0, Relaxed);
    count + 1
}

/// Stop capturing (stock 0x91f60800): take the buffers back, close and
/// queue every open buffer, and wait for the writes. `closing` writes the
/// final GPU records; `notify` reports an execution state change.
pub(super) fn stop(s: &PixSession, record: &FrameRecord, closing: bool, notify: bool) {
    /// Fence record header of the two frame records that close a capture:
    /// the refusal status of GPU capture off.
    const CLOSING_HEADER: u32 = (CommandBufferError::Off as u32) << fence_header::STATUS_SHIFT
        | StreamRecordKind::GpuFrame as u32;

    s.set_engine_flags(s.engine_flags().difference(EngineFlags::RUNNING));
    update_swap_routine(s);
    // SAFETY: the audio lock of the session block.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(s.audio_lock.as_ptr()) };
    s.audio_enabled.store(0, Relaxed);
    // SAFETY: as above; the lock is held.
    unsafe { xboxkrnl::KfReleaseSpinLock(s.audio_lock.as_ptr(), irql) };
    super::gpu::service(s, false);
    let mut context = [[s.address(), 0, 0]; HARDWARE_THREAD_COUNT];
    if !s.configuration.part(Part::Thread).is_off() {
        // SAFETY: the timer `start` initialized in the session block.
        unsafe { xboxkrnl::KeCancelTimer(s.marker_timer.as_ptr()) };
    }
    // SAFETY: `uninstall_entry` is an IPI routine; `context` outlives the
    // call.
    unsafe {
        xboxkrnl::KeIpiGenericCall(
            uninstall_entry as *const () as usize as u32,
            context.as_mut_ptr().expose_provenance() as u32,
        )
    };
    if !s.configuration.part(Part::Thread).is_off() || !s.configuration.part(Part::Gpu).is_off() {
        let routine = record.stop_routine.load(Relaxed);
        if routine != 0 {
            s.lock_override.store(1, Relaxed);
            // SAFETY: the title's frame record names a routine taking one
            // argument.
            unsafe { kernel::call_export(routine, record.routine_argument.load(Relaxed), 0, 0, 0) };
            s.lock_override.store(0, Relaxed);
        } else {
            super::gpu::wait_for_idle();
            s.set_engine_flags(s.engine_flags() | EngineFlags::PAUSED_OUTPUT);
        }
    }
    if notify {
        crate::backend::debugger::request_execution(ExecutionState::Stopped, true);
    }
    frame_record(
        s,
        record.gpu_cursor.load(Relaxed),
        Some(&context),
        STOP_RECORD,
    );
    let frame_buffer = &s.entries[BufferType::FRAME_BUFFER.0 as usize];
    if frame_buffer.load(Relaxed) != 0 {
        super::gpu::close_frame_buffer(s);
        frame_buffer.store(0, Relaxed);
    }
    super::gpu::poll(s, false);
    if closing {
        let header = |frame: u32| {
            CLOSING_HEADER | (frame << fence_header::FRAME_SHIFT & fence_header::FRAME_FIELD)
        };
        super::gpu::write_frame(
            s,
            [header(s.frame_index().wrapping_sub(1)), 0, 0, 0, 0],
            false,
        );
        super::gpu::write_frame(s, [header(s.frame_index()), 0, 0, 0, 0], false);
        s.fence_done.store(0, Relaxed);
        s.fence_ready.store(0, Relaxed);
        s.fence_next.store(0, Relaxed);
    }
    let frame = s.frame_index();
    super::gpu::flush_frame_buffers(s, frame.wrapping_sub(1));
    super::gpu::flush_frame_buffers(s, frame);
    // Buffer types 0 to 0xc: the per-thread buffers and the audio buffer.
    for (index, word) in s.entries[..BufferType::COMMAND_DATA.0 as usize]
        .iter()
        .enumerate()
    {
        let address = word.load(Relaxed);
        if address == 0 {
            continue;
        }
        // SAFETY: a nonzero entry word holds an entry of the session's
        // buffer table.
        let entry = unsafe { BufferEntry::at(address) };
        let mut cursor = match index {
            0..=5 => context[index][1],
            6..=11 => context[index - 6][2],
            _ => 0,
        };
        if cursor == 0 {
            cursor = entry.data() + HEADER_BYTES;
        }
        buffers::close(entry, BufferType(index as u32), cursor);
        buffers::submit(s, entry, s.frame_index());
        word.store(0, Relaxed);
    }
    let command_data = &s.entries[BufferType::COMMAND_DATA.0 as usize];
    let address = command_data.load(Relaxed);
    if address != 0 {
        // SAFETY: as above.
        let entry = unsafe { BufferEntry::at(address) };
        let header = s.pending_frame.header.load(Relaxed);
        super::gpu::push_finished(s, entry, fence_header::frame(header));
        super::gpu::write_pending_frame(s, true);
        command_data.store(0, Relaxed);
    }
    for k in 0..2 {
        let id = StreamId::from_raw(k);
        let word = &s.record_entries[id as usize];
        let address = word.load(Relaxed);
        if address != 0 {
            // SAFETY: as above.
            let entry = unsafe { BufferEntry::at(address) };
            // Stock indexes the cursors with the entry's stream, which is
            // `id`; bit 0 selects, as everywhere.
            let stream = StreamId::from_raw(entry.info().stream());
            buffers::close(
                entry,
                BufferType::records(id),
                s.record_cursors[stream as usize].load(Relaxed),
            );
            buffers::submit(s, entry, s.frame_index());
            word.store(0, Relaxed);
        }
    }
    for k in 0..2 {
        let id = StreamId::from_raw(k);
        while s.stream(id).pending_count.load(Relaxed) != 0 {
            let entry = buffers::take(s, BufferType::FILLER, id.raw());
            // SAFETY: the data of a buffer table entry is a 16 KiB block the
            // engine owns while the entry is out of the queues.
            let header = unsafe { crate::kernel::object_at::<AtomicU32>(entry.data()) };
            // The header of an empty buffer, as `buffers::close` writes it.
            header.store(BufferType::FILLER.0, Relaxed);
            buffers::submit(s, entry, s.frame_index());
        }
    }
    buffers::drain(s);
    s.buffers_used.store(0, Relaxed);
    s.completed_request.store(0, Relaxed);
    s.completed_index.store(0, Relaxed);
    s.audio_ready_head.store(0, Relaxed);
    s.audio_ready_tail.store(0, Relaxed);
    s.audio_queue_head.store(0, Relaxed);
    s.staged.store(0, Relaxed);
    s.audio_queue_tail.store(0, Relaxed);
    s.set_engine_flags(s.engine_flags().difference(EngineFlags::PAUSED_OUTPUT));
}

/// Frame record of 0x28 bytes on every record stream (stock 0x91f5e5b8):
/// the configuration, frame index, stream sequences, time, GPU read
/// pointer, and where each per-thread buffer and the frame buffer at
/// `gpu_cursor` stand. `context` holds the cursors [`uninstall`]
/// reported.
pub(super) fn frame_record(
    s: &PixSession,
    gpu_cursor: u32,
    context: Option<&[[u32; 3]; HARDWARE_THREAD_COUNT]>,
    kind: u32,
) {
    /// GPU register 0x7fc8_112c: the GPU read pointer.
    const GPU_READ_POINTER: u16 = 0x44b;
    /// Position of a buffer type without a buffer.
    const NO_BUFFER: u32 = 0xffff;

    let configuration = &s.configuration;
    let configuration = (configuration.part(Part::Thread).0 & 3)
        | (configuration.part(Part::SecondThread).0 & 3) << 2
        | (configuration.part(Part::Gpu).0 & 3) << 4
        | (configuration.part(Part::Audio).0 & 3) << 6;
    let mut words = [
        configuration << 3 | (kind & 7),
        s.frame_index(),
        s.stream(StreamId::First).sequence.load(Relaxed),
        s.stream(StreamId::Second).sequence.load(Relaxed),
        super::timebase_low(),
        GpuRegisters::get().register(GPU_READ_POINTER).read(),
        0,
        0,
        0,
        0,
    ];
    // Halfword slots from word 6, odd slots in the high half: buffers 0
    // to 5, then the frame buffer.
    for slot in 0..7usize {
        let index = if slot == 6 {
            BufferType::FRAME_BUFFER.0 as usize
        } else {
            slot
        };
        let value = position(s, gpu_cursor, context, index).unwrap_or(NO_BUFFER);
        words[6 + slot / 2] |= (value & 0xffff) << (slot % 2 * 16);
    }
    for k in 0..2 {
        let id = StreamId::from_raw(k);
        if s.streams_mask.load(Relaxed) & 1 << id.raw() != 0 {
            buffers::append(s, id, &words);
        }
    }
}

/// Cursor of a per-thread buffer the kernel holds, through the PCR word
/// whose address [`install`] stored in `published`.
fn published_cursor(published: &AtomicU32) -> u32 {
    // SAFETY: `install` stored the address of a PIX cursor of a processor
    // control region before the buffer's entry was read as nonzero; the
    // regions stay mapped.
    unsafe { kernel::object_at::<KernelU32>(published.load(Relaxed)) }.load(Relaxed)
}

/// Dword position of buffer type `index`'s cursor (part of stock
/// 0x91f5e5b8); `None` without a buffer.
fn position(
    s: &PixSession,
    gpu_cursor: u32,
    context: Option<&[[u32; 3]; HARDWARE_THREAD_COUNT]>,
    index: usize,
) -> Option<u32> {
    let address = s.entries[index].load(Relaxed);
    if address == 0 {
        return (index == BufferType::FRAME_BUFFER.0 as usize
            && !s.configuration.part(Part::Thread).is_off())
        .then_some(0);
    }
    let cursor = match index {
        0..=5 => context.map_or_else(
            || published_cursor(&s.cursors[index]),
            |context| context[index][1],
        ),
        6..=11 => context.map_or_else(
            || published_cursor(&s.second_cursors[index - 6]),
            |context| context[index - 6][2],
        ),
        0xe => gpu_cursor,
        _ => 0,
    };
    if cursor == 0 {
        return Some(0);
    }
    // SAFETY: a nonzero entry word holds an entry of the session's buffer
    // table.
    let entry = unsafe { BufferEntry::at(address) };
    let bytes = match s.temporary_blocks.get(index).map(|base| base.load(Relaxed)) {
        Some(base) if (base..base.wrapping_add(TEMPORARY_BYTES)).contains(&cursor) => {
            super::fence();
            if s.temporary_state(index) == TemporaryState::InUse {
                super::fence();
                s.saved_cursors[index]
                    .load(Relaxed)
                    .wrapping_sub(entry.data())
                    .wrapping_sub(HEADER_BYTES)
            } else {
                cursor.wrapping_sub(base)
            }
        }
        _ => cursor.wrapping_sub(entry.data()).wrapping_sub(HEADER_BYTES),
    };
    Some(((bytes as i32) >> 2) as u32)
}

/// `Ccap` stream record of the active parts (stock 0x91f5ce58); retried at
/// the next frame when the ring dropped it.
pub(super) fn capture_record(s: &PixSession) {
    let time = Timebase::now().ticks();
    let words = [super::active_parts(s), (time >> 32) as u32, time as u32];
    s.capture_record_dropped.store(
        u32::from(!super::super::write_tagged_words(
            RecordTag::CCAP.raw(),
            &words,
        )),
        Relaxed,
    );
}
