//! Critical section wait tracing: the wait statistics counts and the `E:`
//! and `L:` lines written to the `dmtelllog` log.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::session::TELL_LOG_LINE_LIMIT;
use openxbdm_server::commands::session::TellLogAreas;
use openxbdm_server::commands::session::WaitTrace;
use openxbdm_server::commands::session::WaitTraceLine;
use openxbdm_server::commands::session::format_wait_trace;
use xbox360::thread::ThreadObject;
use xbox360::thread::current_object;
use xbox360::time::Timebase;
use xbox360_sys::processor;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::processor::WaitCounts;
use xbox360_sys::processor::WaitStatistics;
use xbox360_sys::processor::WaitStatisticsFlags;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::RtlCriticalSection;
use xbox360_sys::xboxkrnl::RtlCriticalSectionFields;

use super::tell_log::TellLogRecord;
use crate::backend::dispatcher;
use crate::backend::dispatcher::ControlCode;

/// Which end of a critical section wait a count records.
#[derive(Clone, Copy)]
enum WaitEdge {
    Begin,
    End,
}

impl WaitEdge {
    #[inline(always)]
    fn counter(self, counts: &WaitCounts) -> &AtomicU32 {
        match self {
            WaitEdge::Begin => &counts.begins,
            WaitEdge::End => &counts.ends,
        }
    }
}

/// The section of control codes 0x81 and 0x82.
///
/// # Safety
///
/// `section` must be 0 or the address of an initialized critical section
/// that stays initialized while the calling thread waits for it.
#[inline(always)]
unsafe fn waited_section<'a>(section: u32) -> Option<&'a RtlCriticalSectionFields> {
    // SAFETY: the caller guarantees the section.
    unsafe { core::ptr::with_exposed_provenance::<RtlCriticalSection>(section as usize).as_ref() }
        .map(RtlCriticalSection::fields)
}

/// Monitor control code 0x81 (stock 0x91f2b798): a thread starts waiting
/// for critical section `section`. `entry_stack` is the caller's stack
/// pointer at the dispatcher.
///
/// # Safety
///
/// `section` must be 0 or the address of an initialized critical section
/// the calling thread waits for, whose owner stays allocated for the call
/// (see [`trace_wait`]). `entry_stack` must be the stack pointer of the
/// dispatcher's caller, with a valid back chain.
pub(crate) unsafe fn service_cs_trace_wait_begin(section: u32, entry_stack: u32) -> u32 {
    count_wait(WaitEdge::Begin);

    // SAFETY: the caller's contract.
    unsafe { trace_wait(WaitTrace::Enter, waited_section(section), entry_stack) };

    0
}

/// Monitor control code 0x82 (stock 0x91f2b828): the thread acquired the
/// section after waiting.
///
/// # Safety
///
/// As [`service_cs_trace_wait_begin`], for the section the calling thread
/// acquired.
pub(crate) unsafe fn service_cs_trace_wait_end(section: u32, entry_stack: u32) -> u32 {
    count_wait(WaitEdge::End);

    // SAFETY: the caller's contract.
    unsafe { trace_wait(WaitTrace::Leave, waited_section(section), entry_stack) };

    0
}

/// The wait statistics of the current processor while they are enabled.
#[inline(always)]
fn current_wait_statistics() -> Option<&'static WaitStatistics> {
    let address = Kpcr::current().wait_statistics.load(Ordering::Relaxed);

    // SAFETY: the kernel keeps 0 or the address of the processor's
    // statistics block, which stays mapped, in the PCR.
    let statistics =
        unsafe { core::ptr::with_exposed_provenance::<WaitStatistics>(address as usize).as_ref() }?;

    WaitStatisticsFlags::from_bits_retain(statistics.flags.load(Ordering::Relaxed))
        .contains(WaitStatisticsFlags::ENABLED)
        .then_some(statistics)
}

/// Count the wait in the processor's wait statistics when they are
/// enabled, under the counts of title or system threads.
fn count_wait(edge: WaitEdge) {
    let Some(statistics) = current_wait_statistics() else {
        return;
    };

    // SAFETY: re-enabled below; nothing in between waits or faults.
    unsafe { processor::disable_interrupts() };

    let counts = if xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE {
        &statistics.title
    } else {
        &statistics.system
    };
    let counter = edge.counter(counts);
    counter.store(
        counter.load(Ordering::Relaxed).wrapping_add(1),
        Ordering::Relaxed,
    );

    // SAFETY: interrupts were disabled above.
    unsafe { processor::enable_interrupts() };
}

/// Title reboot (stock 0x91f2b410): on every processor with statistics
/// enabled, set the title wait-end count to the wait-begin count.
pub(crate) fn reset_title_wait_statistics() {
    // SAFETY: the bridged routine runs at IPI level and only touches the
    // processor's own statistics.
    unsafe {
        xboxkrnl::KeIpiGenericCall(
            reset_title_wait_counts_entry as *const () as usize as u32,
            0,
        )
    };
}

crate::exports::bridged!(reset_title_wait_counts_entry, reset_title_wait_counts);

/// Per-processor routine of [`reset_title_wait_statistics`] (stock
/// 0x91f2b3d8).
extern "C" fn reset_title_wait_counts(_context: u32) -> u32 {
    // SAFETY: re-enabled below; nothing in between waits or faults.
    unsafe { processor::disable_interrupts() };

    if let Some(statistics) = current_wait_statistics() {
        let title = &statistics.title;
        title
            .ends
            .store(title.begins.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    // SAFETY: interrupts were disabled above.
    unsafe { processor::enable_interrupts() };

    0
}

/// Write an `E:` or `L:` line into the log when area bit 2 is set (stock
/// 0x91f2b680 and line writer 0x91f2b530).
///
/// # Safety
///
/// The thread object `section` names as its owner, if any, must stay
/// allocated for the call. Stock reads the owner's id and processor
/// without a reference, so an owner that releases the section and ends
/// after the owner word is read races with those reads; the trace keeps
/// that race.
unsafe fn trace_wait(
    trace: WaitTrace,
    section: Option<&RtlCriticalSectionFields>,
    entry_stack: u32,
) {
    // SAFETY: the code takes no argument.
    let open = TellLogAreas::from_bits_retain(unsafe {
        dispatcher::dispatch(ControlCode::TELL_LOG_AREAS, 0)
    });
    if !open.intersects(TellLogAreas::CRITICAL_SECTIONS) {
        return;
    }

    let thread = current_object();
    let time_base = Timebase::now().ticks();
    let processor = Kpcr::current().processor_number().get();
    let title = xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE;

    let (lock_count, recursion_count, owner) = match section {
        None => (0, 0, 0),
        Some(section) => (
            section.lock_count.load(Ordering::Relaxed) as u16,
            section.recursion_count.load(Ordering::Relaxed) as u16,
            section.owning_thread.load(Ordering::Relaxed),
        ),
    };
    let (owner_id, owner_processor) = match owner {
        0 => (0, -1),
        owner => {
            // SAFETY: the caller's contract.
            let owner = unsafe { ThreadObject::from_raw(owner) };
            (owner.id().raw(), i32::from(owner.hardware_thread().get()))
        }
    };

    let line = WaitTraceLine {
        trace,
        title,
        time_base,
        section: section.map_or(0, |section| {
            core::ptr::from_ref(section).expose_provenance() as u32
        }),
        thread_id: thread.id().raw(),
        lock_count,
        recursion_count,
        processor,
        owner,
        owner_id,
        owner_processor,
        callers: callers(entry_stack),
    };

    // SAFETY: the codes take no argument.
    let size = unsafe { dispatcher::dispatch(ControlCode::TELL_LOG_ENTRY_SIZE, 0) };
    if size == 0 || unsafe { dispatcher::dispatch(ControlCode::TELL_LOG_AREAS, 0) } == 0 {
        return;
    }

    let mut text = [0u8; TELL_LOG_LINE_LIMIT as usize];
    let length = format_wait_trace(&line, size, &mut text);
    let record = TellLogRecord::new(length as u16, text.as_ptr() as usize as u32);

    // SAFETY: `record` and its text are live locals; the length is the
    // formatted length within `text`.
    unsafe {
        dispatcher::dispatch(
            ControlCode::TELL_LOG_RECORD,
            &record as *const TellLogRecord as usize as u32,
        )
    };
}

/// Return addresses three frames up from the dispatcher's caller (stock
/// 0x91f2b428 with skip 5 from the trace routine's frame): the frames are
/// followed through their back chains within the thread's stack, and a
/// console frame's return address is saved 8 bytes below it.
fn callers(entry_stack: u32) -> [u32; 3] {
    let pcr = Kpcr::current();
    let base = pcr.stack_base.load(Ordering::Relaxed);
    let limit = pcr.stack_limit.load(Ordering::Relaxed);

    let mut callers = [0u32; 3];
    let mut skip = 2;
    let mut found = 0;
    let mut frame = entry_stack;

    while frame != 0 && frame >= limit && frame < base && found < callers.len() {
        let word = |address: u32| {
            // SAFETY: `frame` lies in the calling thread's stack between its
            // limit and base, which stays mapped; the save word 8 bytes
            // below a frame lies in the stack as well.
            unsafe { core::ptr::with_exposed_provenance::<u32>(address as usize).read() }
        };

        if skip != 0 {
            skip -= 1;
        } else {
            callers[found] = word(frame - 8);
            found += 1;
        }

        frame = word(frame);
    }

    callers
}
