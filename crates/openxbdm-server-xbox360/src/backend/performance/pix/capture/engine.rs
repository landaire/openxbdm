//! Capture start and stop (stock 0x91f5fb68, 0x91f60800): per-hardware-
//! thread capture buffers installed in the processor control regions by
//! IPI (0x91f5e810, 0x91f5fd98), the context swap record routine
//! (0x91f5f948), the 100 ms marker timer, and the frame records
//! (0x91f5e5b8).

use super::S;
use super::buffers;
use super::rd;
use super::wr;
use crate::kernel;
use openxbdm_server::notify::ExecutionState;

/// Processor control region fields of the capture buffers: cursor and
/// limit of the first (types 0-5) and second (types 6-11) buffer, the
/// four consecutive from `PCR_CURSOR`, and flags.
pub(super) const PCR_CURSOR: u32 = 0x2b0;
pub(super) const PCR_LIMIT: u32 = 0x2b4;
const PCR_CURSOR2: u32 = 0x2b8;
const PCR_FLAGS: u32 = 0x2c0;
pub(super) const PCR_PROCESSOR: u32 = 0x10c;
/// Data bytes of a per-thread buffer the kernel and titles fill, and of
/// the second buffer.
const THREAD_LIMIT: u32 = 0x3f2c;
const THREAD_LIMIT2: u32 = 0x3ff0;
const PROCESSORS: u32 = 6;
const TIMER: u32 = 0x1_22b0;
const MARKER_DPC: u32 = 0x1_22d8;
/// Capture context per processor handed to the IPI: `{session, cursor,
/// limit, cursor2, limit2, flags}`.
const CONTEXT: usize = 6;

/// Start capturing with the current configuration (stock 0x91f5fb68).
pub(super) fn start(s: S) {
    let mut context = [[0u32; CONTEXT]; PROCESSORS as usize];
    let mut streams = 0u32;
    s.set_word(super::FLAGS, s.word(super::FLAGS) | super::RUNNING);
    for (index, slot) in context.iter_mut().enumerate() {
        let index = index as u32;
        slot[0] = s.0;
        let k = s.word(0);
        if k != super::OFF {
            streams |= super::stream_bit(k);
            let entry = buffers::take(s, index, k);
            s.set_word(0xc8 + index * 4, entry);
            slot[1] = buffers::data(entry) + 4;
            slot[2] = buffers::data(entry) + THREAD_LIMIT;
        } else if s.word(0x18) != 0 {
            slot[2] = 1;
            slot[1] = 0x8000_0000;
        }
        let k = s.word(4);
        if k != super::OFF && s.word(0x10) & 1 << index != 0 {
            streams |= super::stream_bit(k);
            let entry = buffers::take(s, index + 6, k);
            s.set_word(0xc8 + (index + 6) * 4, entry);
            slot[5] = s.word(0x14);
            slot[3] = buffers::data(entry) + 4;
            slot[4] = buffers::data(entry) + THREAD_LIMIT2;
        }
        let gpu = s.word(8);
        if gpu != super::OFF {
            streams |= super::stream_bit(gpu);
        }
        let audio = s.word(0xc);
        if audio != super::OFF {
            streams |= super::stream_bit(audio);
        }
    }
    crate::backend::debugger::KeIpiGenericCall(
        install_entry as *const () as usize as u32,
        context.as_ptr() as usize as u32,
    );
    if s.word(0) != super::OFF {
        kernel::KeInitializeDpc(
            s.at(MARKER_DPC).cast(),
            marker_entry as *const () as usize,
            0,
        );
        initialize_timer(s.at(TIMER).cast());
        super::super::super::counters::set_timer(
            s.at(TIMER).cast(),
            u32::MAX,
            (-1_000_000i32) as u32,
            100,
            s.at(MARKER_DPC).cast(),
        );
    }
    for k in 0..2 {
        if streams & 1 << k != 0 {
            let entry = buffers::take(s, k + 0xf, k);
            s.set_word(0x104 + k * 4, entry);
            s.set_word(0x110 + k * 4, buffers::data(entry) + 4);
            s.set_word(0x118 + k * 4, buffers::data(entry) + buffers::BUFFER_BYTES);
        }
    }
    s.set_word(0x5f0, streams);
    if s.word(0xc) != super::OFF {
        s.set_word(0x1b0, 1);
    }
    update_swap_routine(s);
}

/// `KeInitializeTimerEx(timer, NotificationTimer, 2)` as stock passes it.
fn initialize_timer(timer: *mut u8) {
    // SAFETY: the export takes the timer, its type and a process type in
    // r3 to r5; the shared declaration names the first two.
    let initialize: extern "C" fn(*mut u8, u32, u32) -> u32 =
        unsafe { core::mem::transmute(kernel::KeInitializeTimerEx as *const ()) };
    initialize(timer, 0, 2);
}

/// Register the swap routine while capturing per-thread data and not
/// paused, else remove it (stock 0x91f5fad0).
pub(super) fn update_swap_routine(s: S) {
    let flags = s.word(super::FLAGS);
    let wanted =
        flags & super::RUNNING != 0 && flags & super::PAUSED == 0 && s.word(0) != super::OFF;
    let registered = s.word(0x87d4) != 0;
    if wanted && !registered {
        crate::backend::session::register_swap_routine(swap_record as *const () as usize as u32, 0);
        s.set_word(0x87d4, 1);
    } else if !wanted && registered {
        crate::backend::session::unregister_swap_routine(swap_record as *const () as usize as u32);
        s.set_word(0x87d4, 0);
    }
}

crate::exports::bridged!(install_entry, install);
crate::exports::bridged!(uninstall_entry, uninstall);
crate::exports::bridged!(marker_entry, marker_dpc);
crate::exports::bridged!(marker_ipi_entry, marker_ipi);

/// IPI routine of [`start`] (stock 0x91f5e810): hand the processor its
/// buffers and publish where its cursors live.
extern "C" fn install(context: u32) -> u32 {
    let processor = super::processor();
    let slot = context + processor * (CONTEXT as u32 * 4);
    let s = S(rd(slot));
    let pcr = super::pcr();
    super::interrupts_off();
    s.set_word(0x98 + processor * 4, pcr + PCR_CURSOR);
    s.set_word(0xb0 + processor * 4, pcr + PCR_CURSOR2);
    // Cursor, limit, second cursor and second limit are consecutive.
    for index in 0..4 {
        wr(pcr + PCR_CURSOR + index * 4, rd(slot + 4 + index * 4));
    }
    wr(
        pcr + PCR_FLAGS,
        (rd(slot + 0x14) & !1) | (rd(pcr + PCR_FLAGS) & 1),
    );
    super::interrupts_on();
    0
}

/// IPI routine of [`stop`] (stock 0x91f5fd98): take the buffers back and
/// report the cursors in the context `{session, cursor, cursor2}`.
extern "C" fn uninstall(context: u32) -> u32 {
    let processor = super::processor();
    let slot = context + processor * 0xc;
    let s = S(rd(slot));
    let pcr = super::pcr();
    super::interrupts_off();
    for second in 0..2 {
        let index = processor + second * 6;
        let field = PCR_CURSOR + second * (PCR_CURSOR2 - PCR_CURSOR);
        let cursor = rd(pcr + field);
        let base = s.word(0x87a0 + index * 4);
        if (base..base.wrapping_add(0x800)).contains(&cursor) {
            match s.word(0x876c + index * 4) {
                2 => super::timing::merge(s),
                1 => {
                    wr(pcr + field, s.word(0x8738 + index * 4));
                    super::fence();
                    s.set_word(0x876c + index * 4, 0);
                    super::fence();
                    if second == 0 {
                        kernel::debug_print(
                            c"WRN[PIX]: EndStreaming discarded overflowed raised-IRQL data.\n",
                        );
                    }
                }
                _ => {}
            }
        }
    }
    wr(slot + 4, rd(pcr + PCR_CURSOR));
    wr(slot + 8, rd(pcr + PCR_CURSOR2));
    for index in 0..4 {
        wr(pcr + PCR_CURSOR + index * 4, 0);
    }
    wr(pcr + PCR_FLAGS, rd(pcr + PCR_FLAGS) & 1);
    super::interrupts_on();
    0
}

/// Timer DPC (stock 0x91f5cf20): a marker record on every processor.
extern "C" fn marker_dpc(_dpc: u32, _context: u32, _argument1: u32, _argument2: u32) {
    crate::backend::debugger::KeIpiGenericCall(marker_ipi_entry as *const () as usize as u32, 0);
}

/// Stock 0x91f5cef0.
extern "C" fn marker_ipi(_context: u32) -> u32 {
    super::timing::write_record(0x6e, &[]);
    0
}

/// Context swap routine (stock 0x91f5f948): a record with both threads'
/// call stacks and identifiers in the outgoing processor's buffer.
extern "C" fn swap_record(old: u32, frame: u32, new: u32) -> u32 {
    let Some(s) = super::super::session::session() else {
        return 0;
    };
    let processor = super::processor();
    let pcr = super::pcr();
    let old_id = rd(old + super::THREAD_ID);
    let mut new_id = rd(new + super::THREAD_ID);
    if super::rd8(pcr + 0x19) != 0 && new_id == 0 {
        new_id = (-2i32) as u32;
    }
    super::interrupts_off();
    let mut cursor = rd(pcr + PCR_CURSOR);
    if cursor >= rd(pcr + PCR_LIMIT) {
        super::interrupts_on();
        super::timing::request_at_raised_level(s);
        super::interrupts_off();
        cursor = rd(pcr + PCR_CURSOR);
        if cursor >= rd(pcr + PCR_LIMIT) {
            s.set_word(0x1_2298 + processor * 4, 1);
            super::interrupts_on();
            return 0;
        }
    }
    wr(cursor, super::timebase_low() << 7 | 1);
    wr(cursor + 8, new_id);
    let first = walk_stack(cursor + 0xc, frame, old, 1);
    let second = walk_stack(cursor + (first + 3) * 4, rd(new + 0x64), new, 0);
    let total = first + second + 4;
    wr(cursor + (first + second + 3) * 4, old_id);
    wr(cursor + 4, total << 24 | 0x45);
    wr(pcr + PCR_CURSOR, cursor + total * 4);
    super::interrupts_on();
    0
}

/// Whether `address` is inside `thread`'s stack (stock 0x91f5cd08; the
/// monitor's own exception stacks stock also accepts do not exist here).
fn in_stack(thread: u32, address: u32) -> bool {
    address < rd(thread + 0x5c) && address > rd(thread + 0x60)
}

/// Store up to 19 return addresses of the frame chain from `frame`, after
/// skipping `skip` frames, and a terminating 0 (stock 0x91f5cd88); the
/// dwords stored.
fn walk_stack(output: u32, mut frame: u32, thread: u32, skip: u32) -> u32 {
    for _ in 0..skip {
        if !in_stack(thread, frame) {
            break;
        }
        frame = rd(frame);
    }
    let mut count = 0u32;
    let mut slot = output;
    while count < 0x13 && in_stack(thread, frame) && in_stack(thread, frame.wrapping_sub(8)) {
        let address = rd(frame - 8);
        if address != 0 {
            wr(slot, address);
            slot += 4;
            count += 1;
        }
        frame = rd(frame);
    }
    wr(slot, 0);
    count + 1
}

/// Stop capturing (stock 0x91f60800): take the buffers back, close and
/// queue every open buffer, and wait for the writes. `closing` writes the
/// final GPU records; `notify` reports an execution state change.
pub(super) fn stop(s: S, record: u32, closing: bool, notify: bool) {
    s.set_word(super::FLAGS, s.word(super::FLAGS) & !super::RUNNING);
    update_swap_routine(s);
    let irql = kernel::KfAcquireSpinLock(s.at(0x1b4));
    s.set_word(0x1b0, 0);
    kernel::KfReleaseSpinLock(s.at(0x1b4), irql);
    super::gpu::service(s, false);
    let mut context = [[s.0, 0, 0]; PROCESSORS as usize];
    if s.word(0) != super::OFF {
        kernel::KeCancelTimer(s.at(TIMER).cast());
    }
    crate::backend::debugger::KeIpiGenericCall(
        uninstall_entry as *const () as usize as u32,
        context.as_mut_ptr() as usize as u32,
    );
    if s.word(0) != super::OFF || s.word(8) != super::OFF {
        let routine = rd(record + 0x18);
        if routine != 0 {
            s.set_word(super::super::session::LOCK_OVERRIDE, 1);
            // SAFETY: the title's frame record names a routine taking one
            // argument.
            unsafe { kernel::call_export(routine, rd(record + 0x1c), 0, 0, 0) };
            s.set_word(super::super::session::LOCK_OVERRIDE, 0);
        } else {
            super::gpu::wait_for_idle();
            s.set_word(super::FLAGS, s.word(super::FLAGS) | super::PAUSED_OUTPUT);
        }
    }
    if notify {
        crate::backend::debugger::request_execution(ExecutionState::Stopped, true);
    }
    frame_record(s, record, Some(&context), 1);
    if s.word(0x100) != 0 {
        super::gpu::close_frame_buffer(s);
        s.set_word(0x100, 0);
    }
    super::gpu::poll(s, false);
    if closing {
        let frame = s.word(super::FLAGS) >> 5;
        let mut marker = [0u32; 5];
        marker[0] = (frame.wrapping_sub(1) << 3 & 0x07ff_fff8) | 0x4000_0004;
        super::gpu::write_frame(s, marker.as_ptr() as usize as u32, false);
        marker[0] = (marker[0] & !0x07ff_fff8) | (s.word(super::FLAGS) >> 2 & 0x07ff_fff8);
        super::gpu::write_frame(s, marker.as_ptr() as usize as u32, false);
        s.set_word(0x1a4, 0);
        s.set_word(0x1a8, 0);
        s.set_word(0x1a0, 0);
    }
    let frame = super::frame_index(s);
    super::gpu::flush_frame_buffers(s, frame.wrapping_sub(1));
    super::gpu::flush_frame_buffers(s, frame);
    for index in 0..13u32 {
        let entry = s.word(0xc8 + index * 4);
        if entry == 0 {
            continue;
        }
        let mut cursor = match index {
            0..=5 => context[index as usize][1],
            6..=11 => context[index as usize - 6][2],
            _ => 0,
        };
        if cursor == 0 {
            cursor = buffers::data(entry) + 4;
        }
        buffers::close(entry, index, cursor);
        buffers::submit(s, entry, super::frame_index(s));
        s.set_word(0xc8 + index * 4, 0);
    }
    let current = s.word(0xfc);
    if current != 0 {
        super::gpu::push_finished(s, current, s.word(0xe174) >> 3 & 0x00ff_ffff);
        super::gpu::write_frame(s, s.0 + 0xe174, true);
        s.set_word(0xfc, 0);
    }
    for k in 0..2 {
        let entry = s.word(0x104 + k * 4);
        if entry != 0 {
            let stream = buffers::entry_stream(entry);
            buffers::close(entry, 0xf + k, s.word(0x110 + stream * 4));
            buffers::submit(s, entry, super::frame_index(s));
            s.set_word(0x104 + k * 4, 0);
        }
    }
    for k in 0..2 {
        while s.word(buffers::stream(k) + buffers::STREAM_PENDING_COUNT) != 0 {
            let entry = buffers::take(s, 0x11, k);
            wr(buffers::data(entry), 0x11);
            buffers::submit(s, entry, super::frame_index(s));
        }
    }
    buffers::drain(s);
    s.set_word(0x2a0, 0);
    s.set_word(0x2a4, 0);
    s.set_word(0x2a8, 0);
    s.set_word(0x1c8, 0);
    s.set_word(0x1cc, 0);
    s.set_word(0x298, 0);
    s.set_word(0x1_2280, 0);
    s.set_word(0x29c, 0);
    s.set_word(super::FLAGS, s.word(super::FLAGS) & !super::PAUSED_OUTPUT);
}

/// Frame record of 0x28 bytes on every record stream (stock 0x91f5e5b8):
/// the configuration, frame index, stream sequences, time, GPU read
/// pointer, and where each per-thread buffer stands. `context` holds the
/// cursors [`uninstall`] reported.
pub(super) fn frame_record(
    s: S,
    record: u32,
    context: Option<&[[u32; 3]; PROCESSORS as usize]>,
    kind: u32,
) {
    let configuration =
        (s.word(0) & 3) | (s.word(4) & 3) << 2 | (s.word(8) & 3) << 4 | (s.word(0xc) & 3) << 6;
    let mut words = [0u32; 10];
    words[0] = configuration << 3 | (kind & 7);
    words[1] = super::frame_index(s);
    words[2] = s.word(buffers::stream(0) + buffers::STREAM_SEQUENCE);
    words[3] = s.word(buffers::stream(1) + buffers::STREAM_SEQUENCE);
    words[4] = super::timebase_low();
    words[5] = rd(0x7fc8_112c);
    // Buffers 0 to 5, then the GPU buffer 0xe in halfword slot 6.
    for slot in 0..7u32 {
        let index = if slot == 6 { 0xe } else { slot };
        let value = position(s, record, context, index);
        let halfword = 0x18 + ((slot << 1) ^ 2);
        let word = &mut words[(halfword / 4) as usize];
        let shift = if halfword & 2 == 0 { 16 } else { 0 };
        *word = (*word & !(0xffff << shift)) | (value & 0xffff) << shift;
    }
    for k in 0..2 {
        if s.word(0x5f0) & 1 << k != 0 {
            buffers::append(s, k, words.as_ptr() as usize as u32, 0x28);
        }
    }
}

/// Dword position of buffer `index`'s cursor (part of stock 0x91f5e5b8).
fn position(
    s: S,
    record: u32,
    context: Option<&[[u32; 3]; PROCESSORS as usize]>,
    index: u32,
) -> u32 {
    let entry = s.word(0xc8 + index * 4);
    if entry == 0 {
        return if index == 0xe && s.word(0) != super::OFF {
            0
        } else {
            0xffff
        };
    }
    let cursor = match index {
        0..=5 => context.map_or_else(
            || rd(s.word(0x98 + index * 4)),
            |context| context[index as usize][1],
        ),
        6..=11 => context.map_or_else(
            || rd(s.word(0xb0 + (index - 6) * 4)),
            |context| context[index as usize - 6][2],
        ),
        0xe => rd(record + 0x10),
        _ => 0,
    };
    if cursor == 0 {
        return 0;
    }
    let base = s.word(0x87a0 + index * 4);
    let dwords = if (base..base.wrapping_add(0x800)).contains(&cursor) {
        super::fence();
        if s.word(0x876c + index * 4) == 1 {
            super::fence();
            s.word(0x8738 + index * 4)
                .wrapping_sub(buffers::data(entry))
                .wrapping_sub(4)
        } else {
            cursor.wrapping_sub(base)
        }
    } else {
        cursor.wrapping_sub(buffers::data(entry)).wrapping_sub(4)
    };
    ((dwords as i32) >> 2) as u32
}

/// `Ccap` stream record of the active parts (stock 0x91f5ce58); retried at
/// the next frame when the ring dropped it.
pub(super) fn capture_record(s: S) {
    let time = kernel::timebase();
    let words = [super::active_parts(s), (time >> 32) as u32, time as u32];
    s.set_word(
        0xe208,
        u32::from(!super::super::write_tagged_words(0x4363_6170, &words)),
    );
}
