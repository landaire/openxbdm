//! Slots in which threads post events and wait for the server.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_server::commands::debugger::DebugEvent;
use openxbdm_server::commands::debugger::Disposition;
use openxbdm_server::commands::debugger::ProcessKind;
use openxbdm_server::commands::debugger::ThreadId;
use xbox360::time::relative_interval;
use xbox360::time::sleep;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::EVENT_INCREMENT;
use xbox360_sys::xboxkrnl::EventType;
use xbox360_sys::xboxkrnl::ExceptionRecord as KernelExceptionRecord;
use xbox360_sys::xboxkrnl::Kevent;
use xbox360_sys::xboxkrnl::Kthread;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;

use super::execution::execution_from_code;
use super::hook::exception_record;
use super::thread::MonitorRecord;
use super::thread::OwnThread;
use super::thread::ThreadListLock;
use super::thread::has_record;
use super::thread::owning_process;
use super::thread::process_kind_of;
use super::thread::record_of;
use super::wake::wake_server;
use crate::backend::dispatcher::Handoff;
use crate::backend::dispatcher::HandoffState;
use crate::backend::dispatcher::posts_blocked;
use crate::kernel::address_of;
use crate::kernel::object_at;
use crate::kernel::thread_at;

/// [`SlotEventKind::Execution`] argument bit: send the `execution` line.
pub(super) const EXECUTION_NOTIFY: u32 = 0x100;

const SLOT_COUNT: usize = 16;

pub(super) static SLOTS: [Slot; SLOT_COUNT] = [const { Slot::new() }; SLOT_COUNT];

/// The server thread takes slot events in its passes. Until then, and once
/// it stops, threads take the monitor's default disposition instead of
/// waiting.
static EVENTS_SERVED: AtomicBool = AtomicBool::new(false);

/// Threads inside `post_and_wait`; unload waits for them to leave.
static WAITERS: AtomicU32 = AtomicU32::new(0);

xbox360_sys::value_enum! {
    /// Event a thread posts to a slot.
    pub enum SlotEventKind: u32 {
        Exception = 0,
        Create = 1,
        Terminate = 2,
        /// `argument`: execution code, plus [`EXECUTION_NOTIFY`] to send
        /// the `execution` line.
        Execution = 3,
        /// `argument`: nonzero to wait without the timeout.
        TitleStop = 4,
        /// `record`: module path address, `context`: profile record.
        Pogo = 5,
        /// `record`: stop record, `context`: context built from the trap
        /// frame.
        StackOverflow = 6,
    }
}

xbox360_sys::flags! {
    /// Disposition the server returns to a thread waiting in a slot.
    pub struct SlotDisposition(u32) {
        HANDLED = 0x1,
        DUMP = 0x2,
        CHAIN = 0x4,
        BREAK = 0x8,
    }
}

/// `KEVENT` built in place: dispatcher header, signal state, wait list.
#[repr(C)]
struct SlotEvent {
    header: AtomicU32,
    signal_state: AtomicU32,
    wait_list: [AtomicU32; 2],
}

const _: () = assert!(core::mem::size_of::<SlotEvent>() == core::mem::size_of::<Kevent>());

impl SlotEvent {
    /// Dispatcher header word: synchronization event type, not absolute,
    /// size in words, not inserted.
    const HEADER: u32 = EventType::Synchronization.raw() << 24
        | (core::mem::size_of::<SlotEvent>() as u32 / 4) << 8;

    const fn new() -> Self {
        Self {
            header: AtomicU32::new(0),
            signal_state: AtomicU32::new(0),
            wait_list: [const { AtomicU32::new(0) }; 2],
        }
    }

    /// Not signaled, empty wait list.
    fn reset(&self) {
        let wait_list = address_of(&self.wait_list);
        self.header.store(Self::HEADER, Ordering::Relaxed);
        self.signal_state.store(0, Ordering::Relaxed);
        self.wait_list[0].store(wait_list, Ordering::Relaxed);
        self.wait_list[1].store(wait_list, Ordering::Relaxed);
    }

    #[inline(always)]
    fn as_ptr(&self) -> *mut Kevent {
        core::ptr::from_ref(self).cast_mut().cast()
    }
}

/// A thread waiting for the server to decide on its event.
pub(super) struct Slot {
    state: Handoff,
    /// [`SlotEventKind`].
    pub(super) kind: AtomicU32,
    thread_object: AtomicU32,
    thread_id: AtomicU32,
    record: AtomicU32,
    pub(super) context: AtomicU32,
    /// Second chance of an exception, or the kind's argument.
    argument: AtomicU32,
    /// [`SlotDisposition`].
    disposition: AtomicU32,
    /// Synchronization event the thread waits on.
    event: SlotEvent,
}

impl Slot {
    pub(super) const fn new() -> Self {
        Self {
            state: Handoff::new(),
            kind: AtomicU32::new(0),
            thread_object: AtomicU32::new(0),
            thread_id: AtomicU32::new(0),
            record: AtomicU32::new(0),
            context: AtomicU32::new(0),
            argument: AtomicU32::new(0),
            disposition: AtomicU32::new(0),
            event: SlotEvent::new(),
        }
    }

    #[inline(always)]
    pub(super) fn kind(&self) -> Option<SlotEventKind> {
        SlotEventKind::from_raw(self.kind.load(Ordering::Relaxed))
    }
}

/// The server thread begins a pass loop that takes slot events.
pub(crate) fn begin_event_service() {
    EVENTS_SERVED.store(true, Ordering::Release);
}

/// The server thread stopped taking slot events: waiting threads leave
/// with their default disposition at their next check.
pub(crate) fn end_event_service() {
    EVENTS_SERVED.store(false, Ordering::Release);
    discard_detached();
}

/// Wait until no thread runs in `post_and_wait`; call after
/// [`end_event_service`] before the image unloads.
pub(crate) fn wait_for_event_waiters() {
    while WAITERS.load(Ordering::Acquire) != 0 {
        sleep(Duration::from_millis(10));
    }
}

/// Post an event for the calling thread and wait for its disposition;
/// `None` when the server does not take events, which the caller resolves
/// with the monitor's default disposition. `record` and `context` are
/// addresses the server reads and writes while the thread waits. While the
/// server waits for a dispatch flag 0x4 command thread the event is not
/// posted and `None` is returned.
pub(super) fn post_and_wait(
    kind: SlotEventKind,
    own: OwnThread,
    record: u32,
    context: u32,
    argument: u32,
) -> Option<SlotDisposition> {
    post_and_wait_stopping(kind, own, record, context, argument, &|| false)
}

/// [`post_and_wait`] for an event that may stop its thread: when `stops`
/// answers true, the thread waits for the server even while it waits for a
/// dispatch flag 0x4 command thread, as stock's thread stays stopped
/// whatever its server thread does (0x91f3a980). `stops` is asked at most
/// once, and only while posts are blocked.
pub(super) fn post_and_wait_stopping(
    kind: SlotEventKind,
    own: OwnThread,
    record: u32,
    context: u32,
    argument: u32,
    stops: &dyn Fn() -> bool,
) -> Option<SlotDisposition> {
    WAITERS.fetch_add(1, Ordering::AcqRel);
    let disposition = post_and_wait_served(kind, own, record, context, argument, stops);
    WAITERS.fetch_sub(1, Ordering::AcqRel);

    disposition
}

fn post_and_wait_served(
    kind: SlotEventKind,
    own: OwnThread,
    record: u32,
    context: u32,
    argument: u32,
    stops: &dyn Fn() -> bool,
) -> Option<SlotDisposition> {
    /// Interval at which a waiting thread checks whether the server stopped.
    const STOP_CHECK_INTERVAL: i64 = relative_interval(Duration::from_millis(100));

    let mut stopping = None;
    let mut stays = || *stopping.get_or_insert_with(stops);

    let thread = own.kthread();
    let (slot_index, slot) = claim_slot(Claim::Wait, &mut stays)?;
    let thread_record = own.record();
    slot.event.reset();
    slot.kind.store(kind.raw(), Ordering::Relaxed);
    slot.thread_object
        .store(address_of(thread), Ordering::Relaxed);
    slot.thread_id.store(thread.id, Ordering::Relaxed);
    slot.record.store(record, Ordering::Relaxed);
    slot.context.store(context, Ordering::Relaxed);
    slot.argument.store(argument, Ordering::Relaxed);
    if let Some(thread_record) = thread_record {
        thread_record
            .slot
            .store(slot_index as u32 + 1, Ordering::Relaxed);
    }
    slot.state.store(HandoffState::Posted, Ordering::Release);
    wake_server();
    let disposition = loop {
        if slot.state.is(HandoffState::Completed, Ordering::Acquire) {
            break Some(SlotDisposition::from_bits_retain(
                slot.disposition.load(Ordering::Relaxed),
            ));
        }
        // A slot the server has not completed is reclaimed once it stops;
        // completion claims the slot first, so exactly one side wins. While
        // the server waits for a command thread, a slot it has not taken is
        // reclaimed too unless the event stops its thread: the command may
        // wait for this thread. A taken slot (a stopped thread) stays.
        let served = EVENTS_SERVED.load(Ordering::Acquire);
        if (!served || (posts_blocked() && !stays()))
            && (slot.state.transition(
                HandoffState::Posted,
                HandoffState::Filling,
                Ordering::AcqRel,
            ) || (!served
                && slot.state.transition(
                    HandoffState::Taken,
                    HandoffState::Filling,
                    Ordering::AcqRel,
                )))
        {
            break None;
        }
        // SAFETY: `reset` built the slot event before the slot was posted.
        unsafe {
            xboxkrnl::KeWaitForSingleObject(
                slot.event.as_ptr().cast(),
                WaitReason::UserRequest,
                ProcessorMode::User,
                false,
                &STOP_CHECK_INTERVAL,
            )
        };
    };
    if let Some(thread_record) = own.record() {
        // Context services of other threads follow the slot under this
        // lock; once it is cleared the context on this stack is no longer
        // reachable.
        let _lock = ThreadListLock::acquire(owning_process(thread));
        thread_record.slot.store(0, Ordering::Relaxed);
    }
    slot.state.store(HandoffState::Free, Ordering::Release);

    disposition
}

/// Whether a poster waits for the server to complete its slot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Claim {
    Wait,
    Detached,
}

/// Take a free slot while the server takes events. While the server waits
/// for a command thread, a waiting poster gets one only when `stays`
/// answers that its event stops it (it then waits for a free slot as
/// usual), and a detached one none when all slots are in use.
fn claim_slot(claim: Claim, stays: &mut dyn FnMut() -> bool) -> Option<(usize, &'static Slot)> {
    loop {
        if !EVENTS_SERVED.load(Ordering::Acquire) {
            return None;
        }

        let blocked = posts_blocked() && !(claim == Claim::Wait && stays());
        if blocked && claim == Claim::Wait {
            return None;
        }

        if let Some(index) = SLOTS.iter().position(|slot| {
            slot.state
                .transition(HandoffState::Free, HandoffState::Filling, Ordering::Acquire)
        }) {
            return Some((index, &SLOTS[index]));
        }
        if blocked {
            return None;
        }

        sleep(Duration::from_millis(1));
    }
}

/// Post a thread event without waiting, as stock queues thread
/// notifications (0x91f39ad0). The thread object may be gone when the
/// server takes the event, so the slot carries everything the event
/// needs and its `thread_object` is 0: `record` the start address,
/// `context` the title entry flag, `argument` the title process flag.
pub(super) fn post_detached(kind: SlotEventKind, thread: &Kthread) {
    WAITERS.fetch_add(1, Ordering::AcqRel);
    if let Some((_, slot)) = claim_slot(Claim::Detached, &mut || false) {
        slot.kind.store(kind.raw(), Ordering::Relaxed);
        slot.thread_object.store(0, Ordering::Relaxed);
        slot.thread_id.store(thread.id, Ordering::Relaxed);
        slot.record.store(thread.start_address, Ordering::Relaxed);
        let title_entry = thread
            .creation_flags
            .contains(ThreadCreationFlags::TITLE_ENTRY);
        slot.context
            .store(u32::from(title_entry), Ordering::Relaxed);
        slot.argument.store(
            u32::from(process_kind_of(thread) == ProcessKind::Title),
            Ordering::Relaxed,
        );
        slot.state.store(HandoffState::Posted, Ordering::Release);
        wake_server();
    }
    WAITERS.fetch_sub(1, Ordering::AcqRel);
}

/// Free the slots of detached events once the server stopped taking
/// events.
fn discard_detached() {
    for slot in &SLOTS {
        // Claimed first: a posted slot's fields are stable only while held.
        if slot.state.transition(
            HandoffState::Posted,
            HandoffState::Filling,
            Ordering::AcqRel,
        ) {
            let next = if slot.thread_object.load(Ordering::Relaxed) == 0 {
                HandoffState::Free
            } else {
                HandoffState::Posted
            };
            slot.state.store(next, Ordering::Release);
        }
    }
}

pub(super) fn next_event() -> Option<DebugEvent> {
    /// Title launch wait before the monitor starts execution itself (stock
    /// 0x91f523a0).
    const TITLE_STOP_TIMEOUT_MS: u32 = 15_000;
    /// [`SlotEventKind::Execution`] argument bits of the execution code.
    const EXECUTION_CODE_MASK: u32 = 0xff;

    for slot in &SLOTS {
        if !slot
            .state
            .transition(HandoffState::Posted, HandoffState::Taken, Ordering::Acquire)
        {
            continue;
        }
        let thread = ThreadId(slot.thread_id.load(Ordering::Relaxed));
        let argument = slot.argument.load(Ordering::Relaxed);
        let thread_object = slot.thread_object.load(Ordering::Relaxed);
        if thread_object == 0 {
            let process = if argument != 0 {
                ProcessKind::Title
            } else {
                ProcessKind::System
            };
            return Some(match slot.kind() {
                Some(SlotEventKind::Create) => DebugEvent::ThreadCreate {
                    thread,
                    process,
                    start: slot.record.load(Ordering::Relaxed),
                    title_entry: slot.context.load(Ordering::Relaxed) != 0,
                },
                _ => DebugEvent::ThreadTerminate { thread, process },
            });
        }
        // SAFETY: the posting thread waits in the slot until it is
        // completed, so its object stays allocated while it is taken.
        let thread_object = unsafe { thread_at(thread_object) };
        let process = process_kind_of(thread_object);
        let has_record = has_record(thread_object);
        // SAFETY: the thread waits in the slot, so it does not end.
        let debuggable =
            unsafe { record_of(thread_object) }.is_some_and(MonitorRecord::is_debuggable);
        let event = match slot.kind() {
            Some(SlotEventKind::Create) => DebugEvent::ThreadCreate {
                thread,
                process,
                start: thread_object.start_address,
                title_entry: thread_object
                    .creation_flags
                    .contains(ThreadCreationFlags::TITLE_ENTRY),
            },
            Some(SlotEventKind::Execution) => DebugEvent::ExecutionRequest {
                thread,
                process,
                target: execution_from_code(argument & EXECUTION_CODE_MASK),
                notify: argument & EXECUTION_NOTIFY != 0,
            },
            Some(SlotEventKind::TitleStop) => DebugEvent::PendingTitleStop {
                thread,
                process,
                debuggable,
                timeout: (argument == 0).then_some(TITLE_STOP_TIMEOUT_MS),
            },
            Some(SlotEventKind::Pogo) => DebugEvent::PogoModuleStart {
                thread,
                process,
                name: slot.record.load(Ordering::Relaxed),
                module: slot.context.load(Ordering::Relaxed),
            },
            Some(SlotEventKind::StackOverflow) => {
                let record = slot.record.load(Ordering::Relaxed);
                // SAFETY: the record lies on the stack of the thread
                // waiting in the slot.
                let address = unsafe { object_at::<KernelExceptionRecord>(record) }.address;
                // Only threads that can stop are posted.
                DebugEvent::StackOverflow {
                    thread,
                    process,
                    address,
                    record_address: record,
                    can_stop: true,
                }
            }
            _ => DebugEvent::Exception {
                thread,
                process,
                // SAFETY: the kernel's exception record of the thread
                // waiting in the slot.
                record: exception_record(unsafe { object_at(slot.record.load(Ordering::Relaxed)) }),
                second_chance: argument != 0,
                has_record,
                debuggable,
            },
        };
        return Some(event);
    }

    None
}

pub(super) fn complete_event(thread: ThreadId, disposition: Disposition) {
    // Claimed before the disposition is written: a waiter released by
    // a stop reclaims its taken slot with the same exchange.
    let Some(slot) = SLOTS.iter().find(|slot| {
        slot.thread_id.load(Ordering::Relaxed) == thread.0
            && slot
                .state
                .transition(HandoffState::Taken, HandoffState::Filling, Ordering::AcqRel)
    }) else {
        return;
    };
    if slot.thread_object.load(Ordering::Relaxed) == 0 {
        // Nobody waits on a detached event.
        slot.state.store(HandoffState::Free, Ordering::Release);
        return;
    }

    let mut bits = SlotDisposition::empty();
    if disposition.handled {
        bits |= SlotDisposition::HANDLED;
    }
    if disposition.write_dump {
        bits |= SlotDisposition::DUMP;
    }
    if disposition.chain_kernel_debugger {
        bits |= SlotDisposition::CHAIN;
    }
    if disposition.break_after {
        bits |= SlotDisposition::BREAK;
    }
    slot.disposition.store(bits.bits(), Ordering::Relaxed);
    slot.state.store(HandoffState::Completed, Ordering::Release);
    // SAFETY: `reset` built the slot event before the slot was posted.
    unsafe { xboxkrnl::KeSetEvent(slot.event.as_ptr(), EVENT_INCREMENT, false) };
}
