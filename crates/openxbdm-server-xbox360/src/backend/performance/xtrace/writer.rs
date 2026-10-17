use core::ptr::null_mut;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::sync::atomic::fence;
use core::time::Duration;

use xbox360::time::sleep;
use xbox360_sys::status::NtStatus;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::ProcessorMode;

use super::super::load_pair;
use super::super::store_pair;
use super::BUFFER_COUNT;
use super::Buffer;
use super::FAILED;
use super::FILLED;
use super::FREE;
use super::PROGRESS_MARK;
use super::SESSION;
use super::WRITER_RUNNING;
use super::break_trap;
use super::file::append;
use super::file::file_name;
use super::handler::HOOK_SLOT;
use super::output_debug_string;
use super::print;

const WRITER_CAPACITY: usize = 16;

/// Handles of every writer thread not known to have ended. Title
/// termination abandons the running writer as stock does; it ends at the
/// next stop, and unload waits for all of them.
pub(super) static WRITERS: [AtomicU32; WRITER_CAPACITY] =
    [const { AtomicU32::new(0) }; WRITER_CAPACITY];

/// Write the queued buffers to the file in sequence order (stock
/// 0x91f65e50) and print the progress.
pub(super) fn flush() {
    const PROGRESS_INTERVAL: i64 = 100_000;
    /// Progress interval when the kernel has the fast trace hook.
    const FAST_PROGRESS_INTERVAL: i64 = 500_000;

    let mut collected = [null_mut::<Buffer>(); BUFFER_COUNT];
    let mut count = 0;
    let mut sequence = u32::MAX;
    for slot in &FILLED {
        let buffer = slot.swap(null_mut(), Ordering::AcqRel);
        // SAFETY: buffer slots hold null or an element of `BUFFERS`.
        if let Some(reference) = unsafe { buffer.as_ref() } {
            collected[count] = buffer;
            count += 1;
            sequence = sequence.min(reference.sequence.load(Ordering::Acquire));
        }
    }

    fence(Ordering::AcqRel);

    let mut written = 0;
    for _ in 0..count {
        // Entries past `count` are null.
        for (position, slot) in collected.iter_mut().enumerate() {
            // SAFETY: as above.
            let Some(buffer) = (unsafe { slot.as_ref() }) else {
                continue;
            };

            if buffer.sequence.load(Ordering::Acquire) != sequence {
                continue;
            }

            written += 1;
            let (name, length) = file_name();
            if !FAILED.load(Ordering::Acquire)
                && !append(
                    &name[..length],
                    buffer.data.load(Ordering::Relaxed),
                    4 * buffer.used.load(Ordering::Relaxed),
                )
            {
                output_debug_string(b"Tracing: Error writing trace data to file.\n");
                FAILED.store(true, Ordering::Release);
            }

            buffer.used.store(0, Ordering::Release);
            // Free slots are refilled by position in the collected list,
            // as in stock.
            FREE[position].store(*slot, Ordering::Release);
            *slot = null_mut();
        }

        sequence = sequence.wrapping_add(1);
    }

    if written != count {
        break_trap();
    }

    let interval = if HOOK_SLOT.load(Ordering::Acquire) != 0 {
        FAST_PROGRESS_INTERVAL
    } else {
        PROGRESS_INTERVAL
    };

    loop {
        let total = SESSION.encoder.total() as i64;
        let recorded = SESSION.encoder.recorded() as i64;
        if load_pair(&PROGRESS_MARK) as i64 + interval > total {
            break;
        }

        print(
            c"Tracing: %I64d K instructions recorded of %I64d K.\r\n",
            &[
                (recorded / interval * interval / 1000) as u64,
                (total / interval * interval / 1000) as u64,
            ],
        );
        store_pair(
            &PROGRESS_MARK,
            (load_pair(&PROGRESS_MARK) as i64 + interval) as u64,
        );
    }
}

/// Writer thread (stock 0x91f660f0).
pub(super) extern "C" fn writer(_context: u32) -> u32 {
    const INTERVAL: Duration = Duration::from_millis(10);

    while WRITER_RUNNING.load(Ordering::Acquire) {
        sleep(INTERVAL);
        flush();
    }

    flush();

    0
}

/// Keep a new writer's handle for unload, after closing the handles of
/// writers that have ended. A seventeenth live writer is not tracked.
pub(super) fn track_writer(handle: u32) {
    let now = 0i64;
    for slot in &WRITERS {
        let ended = slot.load(Ordering::Acquire);
        if ended == 0 {
            continue;
        }

        // SAFETY: `ended` is a tracked writer handle; `now` is a live zero
        // timeout.
        let wait = unsafe {
            xboxkrnl::NtWaitForSingleObjectEx(
                Handle::from_raw(ended),
                ProcessorMode::User,
                false,
                &now,
            )
        };
        if wait == NtStatus::WAIT_0 {
            // SAFETY: the writer has ended; its tracked handle is closed once.
            unsafe { xboxkrnl::NtClose(Handle::from_raw(ended)) };
            slot.store(0, Ordering::Release);
        }
    }

    if let Some(slot) = WRITERS
        .iter()
        .find(|slot| slot.load(Ordering::Acquire) == 0)
    {
        slot.store(handle, Ordering::Release);
    }
}

/// A writer handle the stop closed.
pub(super) fn forget_writer(handle: u32) {
    for slot in &WRITERS {
        let _ = slot.compare_exchange(handle, 0, Ordering::AcqRel, Ordering::Relaxed);
    }
}
