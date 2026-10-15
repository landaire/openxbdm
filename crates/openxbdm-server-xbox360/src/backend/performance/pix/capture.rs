//! PIX frame capture engine (stock 0x91f58f10 to 0x91f62560): at each
//! title frame boundary it processes the session's messages, writes the
//! per-thread timing buffers, GPU command buffers and audio of the
//! configured parts to the `PixStream`/`PixDump` partition, and extracts
//! captured frames into PIX capture files.
//!
//! The engine keeps the stock layout of the session block (see
//! [`super::session`]); offsets are named where several modules share
//! them. Configuration words `+0..+0xc` select the record stream (0 or 1,
//! 2 off) of the per-thread buffers (types 0-5), the second per-thread
//! buffers (6-11), the GPU buffers (0xd, 0xe) and the audio (0xc).
//! Internal consistency assertions of stock are not reproduced.

mod audio;
mod buffers;
mod engine;
mod gpu;
mod messages;
mod replay;
mod timing;
mod video;

use super::session;
use super::session::Session as S;
use crate::kernel;
use crate::kernel::current_thread;
use crate::kernel::pcr;

pub(crate) use audio::service_samples;
pub(crate) use timing::service_end;
pub(crate) use timing::service_nuicam_begin;

/// Configuration value of a part that is off.
const OFF: u32 = session::CONFIGURATION_OFF;
const FLAGS: u32 = session::FLAGS;
/// Engine flags: capturing, paused by message 13, buffer output paused.
const RUNNING: u32 = 0x8000_0000;
const PAUSED: u32 = 0x4000_0000;
const PAUSED_OUTPUT: u32 = 0x2000_0000;
const CURRENT_MESSAGE: u32 = session::CURRENT_MESSAGE;
const FRAME_RECORD: u32 = 0x5f4;
/// `KTHREAD` thread identifier.
const THREAD_ID: u32 = 0x14c;
/// Engine status version reported in frame records.
const STATUS_VERSION: u32 = 0x5308;

fn rd(address: u32) -> u32 {
    super::read_u32(address)
}

fn wr(address: u32, value: u32) {
    super::write_u32(address, value);
}

fn rd8(address: u32) -> u8 {
    super::read_u8(address)
}

fn wr8(address: u32, value: u8) {
    super::write_u8(address, value);
}

fn rd16(address: u32) -> u16 {
    // SAFETY: an aligned halfword of engine or capture memory.
    unsafe { core::ptr::read_volatile(address as usize as *const u16) }
}

/// Hardware thread of the calling processor.
fn processor() -> u32 {
    u32::from(rd8(pcr() + engine::PCR_PROCESSOR))
}

fn timebase_low() -> u32 {
    kernel::timebase() as u32
}

/// Bit of stream `k` in a stream mask (`slw`: 0 from 32 on).
fn stream_bit(k: u32) -> u32 {
    if k & 0x20 == 0 { 1 << (k & 0x1f) } else { 0 }
}

/// Frame index of the session (flags bits 5 to 28).
fn frame_index(s: S) -> u32 {
    s.word(FLAGS) >> 5 & 0x00ff_ffff
}

/// Active parts as `Ccap` and capture timing report them: per-thread data,
/// GPU, audio.
fn active_parts(s: S) -> u32 {
    u32::from(s.word(0) != OFF)
        | u32::from(s.word(8) != OFF) << 1
        | u32::from(s.word(0xc) != OFF) << 2
}

fn interrupts_off() {
    // SAFETY: mtmsrd r13, 1 copies the interrupt enable bit of the PCR
    // address, which is clear.
    unsafe { core::arch::asm!(".long 0x7da10164", options(nostack)) };
}

fn interrupts_on() {
    // SAFETY: mtmsrd r11, 1 with r11 = 0x8000 sets the interrupt enable bit.
    unsafe {
        core::arch::asm!("lis 11, 0", "ori 11, 11, 0x8000", ".long 0x7d610164", out("r11") _, options(nostack))
    };
}

fn fence() {
    // SAFETY: orders the state word against the cursor stores.
    unsafe { core::arch::asm!("lwsync", options(nostack)) };
}

fn sync() {
    // SAFETY: as `fence`.
    unsafe { core::arch::asm!("sync", options(nostack)) };
}

/// Title part of the frame boundary with the title's frame record (stock
/// 0x91f622d8, code 0x52): start capturing on the first frame, process
/// the messages, write the frame record, and report the engine state in
/// the record (`+0x20` version, `+0x24` revision, `+0x28` flags, `+0x2c`
/// with flag 4 in `+0xc`).
pub(super) fn frame(record: u32) {
    let Some(locked) = session::lock() else {
        return;
    };
    let s = locked.0;
    if s.word(FLAGS) & RUNNING == 0 {
        if s.word(0x87d8) == 0 {
            buffers::allocate_all(s);
        }
        engine::capture_record(s);
        engine::start(s);
        engine::frame_record(s, 0, None, 0);
    }
    timing::service_buffers(s);
    let mut empty = [0u32; 0x10];
    let record = if record != 0 {
        record
    } else {
        empty.as_mut_ptr() as usize as u32
    };
    let full = rd(record + 0xc) & 4 != 0;
    for index in 0..0x10 {
        let word = if full || index < 0xc {
            rd(record + index * 4)
        } else {
            0
        };
        s.set_word(FRAME_RECORD + index * 4, word);
    }
    s.set_word(
        session::FRAME_TIMES + (s.word(FLAGS) >> 5 & 0x1f) * 4,
        timebase_low(),
    );
    let flags = s.word(FLAGS);
    s.set_word(
        FLAGS,
        ((flags & !0x1f).wrapping_add(0x20) & 0x1fff_ffe0) | (flags & 0xe000_001f),
    );
    gpu::poll(s, false);
    gpu::flush_frame_buffers(s, frame_index(s).wrapping_sub(2));
    let mut state = 0u32;
    messages::dispatch(s, rd(record + 0xc), &mut state);
    engine::frame_record(s, record, None, 0);
    if s.word(0) != OFF {
        state |= 1;
        if s.word(0x100) == 0 {
            state |= 0x10;
        }
    } else {
        state |= 0x10;
    }
    if s.word(8) != OFF {
        state |= 4;
    }
    if s.word(CURRENT_MESSAGE) == 5 {
        state |= 2;
    }
    wr(record + 0x28, state);
    wr(record + 0x20, STATUS_VERSION);
    wr(record + 0x24, s.word(session::REVISION));
    if full {
        wr(record + 0x2c, s.word(0x20));
    }
    if s.word(0xe208) != 0 {
        engine::capture_record(s);
    }
}

/// Frame boundary without a frame record (stock 0x91f62508): a record
/// with `milliseconds` in `+4` and the GPU idle wait as the stop routine.
pub(super) fn frame_without_record(milliseconds: u32) {
    let mut record = [0u32; 0x10];
    record[1] = milliseconds;
    record[6] = wait_for_gpu as *const () as usize as u32;
    frame(record.as_ptr() as usize as u32);
}

extern "C" fn wait_for_gpu(_argument: u32) {
    gpu::wait_for_idle();
}

/// Module records at the frame boundary (stock 0x91f55db8): the threads of
/// the debug monitor data's processor table, then each loaded module and
/// its debug directory; skipped while paused by message 13.
pub(super) fn module_records() {
    if session::session().is_some_and(|s| s.word(FLAGS) & PAUSED != 0) {
        return;
    }
    let table = kernel::debug_monitor_data().words[0x17];
    if table != 0 {
        // Stock leaves the identifiers of empty slots unset.
        let mut threads = [0u32; 6];
        for (index, thread) in threads.iter_mut().enumerate() {
            let entry = rd(table + index as u32 * 4);
            if entry != 0 {
                *thread = rd(rd(entry) + THREAD_ID);
            }
        }
        timing::write_typed_record(0x46, &threads);
    }
    timing::write_record(0x66, &[]);
    let mut walk = 0u32;
    let mut module = [0u32; 0x124 / 4];
    let mut directory = [0u32; 0x118 / 4];
    let walk_address = core::ptr::from_mut(&mut walk) as usize as u32;
    while crate::backend::memory::walk_modules(walk_address, module.as_mut_ptr() as usize as u32)
        == 0x02da_0000
    {
        crate::backend::memory::get_module_debug_directory(
            module[0x104 / 4],
            directory.as_mut_ptr() as usize as u32,
        );
        timing::write_long_record(0x66, &module[..0x49]);
        timing::write_long_record(0x67, &directory[..0x46]);
    }
    if walk != 0 {
        kernel::ExFreePool(walk);
    }
}

/// Title end part (stock 0x91f62100), from the title terminate routine.
pub(super) fn title_ended() {
    if let Some(locked) = session::lock() {
        messages::title_ended(locked.0);
    }
}

/// Server pass (stock 0x91f62228): replace the buffers a raised-level
/// writer switched away from.
pub(super) fn poll() {
    let Some(s) = session::session() else { return };
    if timing::take_pending_service(s)
        && let Some(locked) = session::lock()
    {
        timing::service_buffers(locked.0);
    }
}

/// Thread termination part (stock 0x91f5df80): wait for the thread's
/// partition writes.
pub(crate) fn thread_terminated() {
    if let Some(s) = session::session() {
        buffers::wait_for_thread(s);
    }
}

/// Stop capturing before the image is unloaded: the timer, the swap
/// routine and the per-thread buffers refer to it.
pub(super) fn shut_down() {
    if let Some(locked) = session::lock() {
        let s = locked.0;
        if s.word(FLAGS) & RUNNING != 0 {
            let record = [0u32; 0x10];
            engine::stop(s, record.as_ptr() as usize as u32, true, false);
        }
        buffers::free(s);
    }
}

/// Monitor control code 0x50.
pub(crate) fn service_timing_request(argument: u32) -> u32 {
    timing::timing_request(argument)
}

/// Monitor control code 0x51.
pub(crate) fn service_frame_buffer(argument: u32) -> u32 {
    gpu::service_frame_buffer(argument)
}

/// Monitor control code 0x56.
pub(crate) fn service_configure(argument: u32) -> u32 {
    messages::configure(argument)
}

/// Monitor control code 0x5c.
pub(crate) fn service_command_buffers(argument: u32) -> u32 {
    gpu::service_command_buffers(argument)
}

/// Monitor control code 0x5d.
pub(crate) fn service_fence(argument: u32) -> u32 {
    gpu::service_fence(argument)
}
