//! Debug monitor services: the kernel debug routine hook, thread
//! notifications, monitor thread records, thread control, breakpoints in
//! code memory, and debugger extensions.
//!
//! The kernel calls the debug routine and the thread notification on the
//! thread concerned. While the server thread takes events, that thread
//! posts its event to a slot and waits; the server thread takes the event,
//! decides, and completes the slot. Otherwise the thread takes the
//! monitor's default disposition without waiting.

mod exports;

pub(crate) use self::exports::apply_pending_stop_on;

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::console::DumpMode;
use openxbdm_server::commands::console::EventDeferMask;
use openxbdm_server::commands::debugger;
use openxbdm_server::commands::debugger::Context;
use openxbdm_server::commands::debugger::ContextFlags;
use openxbdm_server::commands::debugger::DataBreakpoint;
use openxbdm_server::commands::debugger::DataKind;
use openxbdm_server::commands::debugger::DebugEvent;
use openxbdm_server::commands::debugger::Delivery;
use openxbdm_server::commands::debugger::DirectException;
use openxbdm_server::commands::debugger::DirectNotice;
use openxbdm_server::commands::debugger::DirectNotification;
use openxbdm_server::commands::debugger::DirectPolicy;
use openxbdm_server::commands::debugger::DirectRegisters;
use openxbdm_server::commands::debugger::DirectStep;
use openxbdm_server::commands::debugger::Disposition;
use openxbdm_server::commands::debugger::ExceptionFlags;
use openxbdm_server::commands::debugger::ExceptionRecord;
use openxbdm_server::commands::debugger::ExitStatus;
use openxbdm_server::commands::debugger::ExtensionHandle;
use openxbdm_server::commands::debugger::MODULE_NAME_CAPACITY;
use openxbdm_server::commands::debugger::ModuleEvent;
use openxbdm_server::commands::debugger::NOTICE_TEXT_CAPACITY;
use openxbdm_server::commands::debugger::NoSuchThread;
use openxbdm_server::commands::debugger::ProcessKind;
use openxbdm_server::commands::debugger::StopOn;
use openxbdm_server::commands::debugger::StoppedThreadError;
use openxbdm_server::commands::debugger::ThreadId;
use openxbdm_server::commands::debugger::ThreadInfo;
use openxbdm_server::commands::debugger::ThreadName;
use openxbdm_server::commands::debugger::dispatch_direct;
use openxbdm_server::commands::debugger::ModuleFlags;
use openxbdm_server::commands::services::ThreadHandle;
use openxbdm_server::notify::ExecutionState;
use xbox360::console::hardware_flags;
use xbox360::console::kernel_version;
use xbox360::time::sleep;
use xbox360_sys::image::ImageCharacteristics;
use xbox360_sys::image::ImageDirectory;
use xbox360_sys::processor;
use xbox360_sys::processor::Msr;
use xbox360_sys::processor::current_irql;
use xbox360_sys::processor::current_thread;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DebugMonitorFlags;
use xbox360_sys::xboxkrnl::DumpWriteDump;
use xbox360_sys::xboxkrnl::ExRegisterThreadNotification;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::ImageFlags;
use xbox360_sys::xboxkrnl::ImageVersion;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeContextFromKframes;
use xbox360_sys::xboxkrnl::KeIpiGenericCall;
use xbox360_sys::xboxkrnl::KeResumeThread;
use xbox360_sys::xboxkrnl::KeSetSpecialPurposeRegister;
use xbox360_sys::xboxkrnl::KeSuspendThread;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::Kthread;
use xbox360_sys::xboxkrnl::ObLookupAnyThreadByThreadId;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::RtlCaptureContext;
use xbox360_sys::xboxkrnl::RtlImageDirectoryEntryToData;
use xbox360_sys::xboxkrnl::RtlImageNtHeader;
use xbox360_sys::xboxkrnl::SpecialPurposeRegister;
use xbox360_sys::xboxkrnl::WaitReason;
use xbox360_sys::xboxkrnl::XexUnloadImage;

use super::Console;
use crate::kernel;

/// Pool tag of monitor thread records ('Dmtd').
const RECORD_TAG: PoolTag = PoolTag::new(*b"dtmD");
/// Monitor record flag: the thread is under debugger control.
const RECORD_DEBUGGABLE: u32 = 0x2000;
/// Monitor record flag: execution stops do not suspend the thread.
const RECORD_EXEMPT: u32 = 0x0200_0000;
/// Thread creation flags tested when the record is made.
const THREAD_NOT_DEBUGGABLE: u32 = 0x400;
const THREAD_EXEMPT: u32 = 0x200;
const THREAD_TITLE_ENTRY: u32 = 0x100;

/// Kernel thread object offsets used by the monitor.
mod thread {
    pub const START_ADDRESS: u32 = 0x150;
    pub const STACK_BASE: u32 = 0x5c;
    pub const STACK_LIMIT: u32 = 0x60;
    pub const SWITCH_FRAME: u32 = 0x64;
    pub const TLS: u32 = 0x68;
    pub const PRIORITY: u32 = 0x70;
    pub const PROCESS_TYPE: u32 = 0x73;
    pub const PROCESS: u32 = 0x84;
    pub const SUSPEND_COUNT: u32 = 0xbc;
    pub const PROCESSOR: u32 = 0xbf;
    pub const LIST_ENTRY: u32 = 0x110;
    pub const CREATE_TIME: u32 = 0x130;
    pub const EXIT_STATUS: u32 = 0x140;
    pub const ID: u32 = 0x14c;
    pub const MONITOR_RECORD: u32 = 0x15c;
    pub const LAST_ERROR: u32 = 0x160;
    pub const CREATE_FLAGS: u32 = 0x16c;
}

/// Kernel context offsets.
mod context {
    pub const MSR: u32 = 0x4;
    pub const IAR: u32 = 0x8;
    pub const LR: u32 = 0xc;
    pub const CTR: u32 = 0x10;
    pub const GPR: u32 = 0x18;
    pub const CR: u32 = 0x118;
    pub const XER: u32 = 0x11c;
    pub const FPSCR: u32 = 0x120;
    pub const FPR: u32 = 0x128;
    pub const VSCR: u32 = 0x230;
    pub const VR: u32 = 0x240;
    /// Bytes `RtlCaptureContext` writes.
    pub const SIZE: usize = 0xa50;
}

fn read_u8(address: u32) -> u8 {
    // SAFETY: callers pass addresses of live kernel objects.
    unsafe { core::ptr::read_volatile(address as usize as *const u8) }
}

fn read_u32(address: u32) -> u32 {
    // SAFETY: callers pass addresses of live kernel objects.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn write_u32(address: u32, value: u32) {
    // SAFETY: callers pass addresses of live, writable kernel objects.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

fn read_u64(address: u32) -> u64 {
    (u64::from(read_u32(address)) << 32) | u64::from(read_u32(address + 4))
}

fn write_u64(address: u32, value: u64) {
    write_u32(address, (value >> 32) as u32);
    write_u32(address + 4, value as u32);
}

/// Per-thread monitor record, referenced from the thread object.
#[repr(C)]
struct MonitorRecord {
    flags: u32,
    monitor_suspended: u32,
    /// Pool copy of the thread name.
    name: u32,
    /// Index plus one of the slot the thread waits in.
    slot: u32,
    /// Word owned by the thread; export 49 hands out its address.
    debug_data: u32,
}

/// Offset of [`MonitorRecord::debug_data`].
const RECORD_DEBUG_DATA: u32 = core::mem::offset_of!(MonitorRecord, debug_data) as u32;

fn record_of(thread_object: u32) -> Option<u32> {
    Some(read_u32(thread_object + thread::MONITOR_RECORD)).filter(|&record| record != 0)
}

fn record_flags(record: u32) -> u32 {
    read_u32(record)
}

/// Create the monitor record of a thread (stock 0x91f31028).
fn create_record(thread_object: u32) -> Option<u32> {
    if let Some(record) = record_of(thread_object) {
        return Some(record);
    }
    let pool_type = if read_u8(thread_object + thread::PROCESS_TYPE) == 2 {
        PoolType::System
    } else {
        PoolType::Title
    };
    // SAFETY: pool allocation has no pointer arguments.
    let record = unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(
            core::mem::size_of::<MonitorRecord>() as u32,
            RECORD_TAG,
            pool_type,
        )
    };
    if record == 0 {
        return None;
    }
    let create_flags = read_u32(thread_object + thread::CREATE_FLAGS);
    let mut flags = 0;
    if create_flags & THREAD_NOT_DEBUGGABLE == 0 {
        flags |= RECORD_DEBUGGABLE;
    }
    if create_flags & THREAD_EXEMPT != 0 {
        flags |= RECORD_EXEMPT;
    }
    write_u32(record, flags);
    write_u32(record + 4, 0);
    write_u32(record + 8, 0);
    write_u32(record + 12, 0);
    write_u32(record + RECORD_DEBUG_DATA, 0);
    write_u32(thread_object + thread::MONITOR_RECORD, record);
    Some(record)
}

/// The process objects published in the debug monitor data (stock reads
/// +0x50 and +0x54 of its copy as the objects themselves).
fn process_of(kind: ProcessKind) -> u32 {
    let data = kernel::debug_monitor_data();
    match kind {
        ProcessKind::Title => data.title_process.load(Ordering::Relaxed),
        ProcessKind::System => data.system_process.load(Ordering::Relaxed),
    }
}

fn process_kind_of(thread_object: u32) -> ProcessKind {
    let process = read_u32(thread_object + thread::PROCESS);
    if process != 0 && process == process_of(ProcessKind::Title) {
        ProcessKind::Title
    } else {
        ProcessKind::System
    }
}

/// Call `visit` with each thread object of `kind` under the process lock.
fn for_each_thread(kind: ProcessKind, mut visit: impl FnMut(u32)) {
    let process = process_of(kind);
    if process == 0 {
        return;
    }
    // SAFETY: the process object starts with its thread list spin lock.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(process as usize as *mut KspinLock) };
    let head = process + 4;
    let mut entry = read_u32(head);
    while entry != head && entry != 0 {
        let next = read_u32(entry);
        visit(entry - thread::LIST_ENTRY);
        entry = next;
    }
    // SAFETY: the lock was acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(process as usize as *mut KspinLock, irql) };
}

/// A referenced thread object.
struct ThreadRef(u32);

impl ThreadRef {
    fn lookup(id: ThreadId) -> Result<Self, NoSuchThread> {
        let mut object = 0u32;
        // SAFETY: `object` is a live local that receives the thread pointer.
        let status = unsafe { ObLookupAnyThreadByThreadId(id.0, (&raw mut object).cast()) };
        if (status.0 as i32) < 0 {
            return Err(NoSuchThread);
        }
        Ok(Self(object))
    }
}

impl Drop for ThreadRef {
    fn drop(&mut self) {
        // SAFETY: `lookup` took the reference this releases.
        unsafe { xboxkrnl::ObDereferenceObject(self.0) };
    }
}

/// Slot states.
const SLOT_FREE: u32 = 0;
const SLOT_FILLING: u32 = 1;
const SLOT_POSTED: u32 = 2;
const SLOT_TAKEN: u32 = 3;
const SLOT_COMPLETED: u32 = 4;

/// Slot event kinds.
const KIND_EXCEPTION: u32 = 0;
const KIND_CREATE: u32 = 1;
const KIND_TERMINATE: u32 = 2;
/// `argument`: target state code, 0x100 to send the `execution` line.
const KIND_EXECUTION: u32 = 3;
/// `argument`: nonzero to wait without the timeout.
const KIND_TITLE_STOP: u32 = 4;
/// `record`: module path address, `context`: profile record.
const KIND_POGO: u32 = 5;
/// `record`: stop record, `context`: context built from the trap frame.
const KIND_STACK_OVERFLOW: u32 = 6;

/// Title launch wait before the monitor starts execution itself (stock
/// 0x91f523a0).
const TITLE_STOP_TIMEOUT_MS: u32 = 15_000;

/// Disposition bits.
const DISPOSITION_HANDLED: u32 = 0x1;
const DISPOSITION_DUMP: u32 = 0x2;
const DISPOSITION_CHAIN: u32 = 0x4;
const DISPOSITION_BREAK: u32 = 0x8;

const SLOT_COUNT: usize = 16;

/// A thread waiting for the server to decide on its event.
struct Slot {
    state: AtomicU32,
    kind: AtomicU32,
    thread_object: AtomicU32,
    thread_id: AtomicU32,
    record: AtomicU32,
    context: AtomicU32,
    /// Second chance of an exception, or the kind's argument.
    argument: AtomicU32,
    disposition: AtomicU32,
    /// Synchronization event the thread waits on.
    event: [AtomicU32; 4],
}

impl Slot {
    const fn new() -> Self {
        Self {
            state: AtomicU32::new(SLOT_FREE),
            kind: AtomicU32::new(0),
            thread_object: AtomicU32::new(0),
            thread_id: AtomicU32::new(0),
            record: AtomicU32::new(0),
            context: AtomicU32::new(0),
            argument: AtomicU32::new(0),
            disposition: AtomicU32::new(0),
            event: [const { AtomicU32::new(0) }; 4],
        }
    }

    fn event(&self) -> *mut u32 {
        self.event.as_ptr() as *mut u32
    }

    /// Initialize the synchronization event: type 1, size 4 dwords, not
    /// signaled, empty wait list.
    fn reset_event(&self) {
        let address = self.event() as usize as u32;
        self.event[0].store(0x0100_0400, Ordering::Relaxed);
        self.event[1].store(0, Ordering::Relaxed);
        self.event[2].store(address + 8, Ordering::Relaxed);
        self.event[3].store(address + 8, Ordering::Relaxed);
    }
}

static SLOTS: [Slot; SLOT_COUNT] = [const { Slot::new() }; SLOT_COUNT];
/// Debug routine the kernel had before the hook.
static PREVIOUS_DEBUG_ROUTINE: AtomicU32 = AtomicU32::new(0);
/// Thread object of the server thread, which must never wait in a slot.
static SERVER_THREAD: AtomicU32 = AtomicU32::new(0);
/// Thread notification registration: routine, then the kernel's links.
static THREAD_NOTIFICATION: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
/// Loaded extension exports read off the server thread.
static EXTENSION_TELL_DEBUGGER: AtomicU32 = AtomicU32::new(0);
static EXTENSION_PREPARE_TO_UNLOAD: AtomicU32 = AtomicU32::new(0);
static EXTENSION_CALLS: AtomicU32 = AtomicU32::new(0);

/// Execution state in the monitor's numbering (0 stopped .. 5
/// pending_title).
static EXECUTION_STATE: AtomicU32 = AtomicU32::new(1);

pub(crate) const fn execution_code(state: ExecutionState) -> u32 {
    match state {
        ExecutionState::Stopped => 0,
        ExecutionState::Started => 1,
        ExecutionState::Rebooting => 2,
        ExecutionState::Pending => 3,
        ExecutionState::RebootTitle => 4,
        ExecutionState::PendingTitle => 5,
    }
}

/// Current execution state.
pub(crate) fn execution_state() -> ExecutionState {
    match EXECUTION_STATE.load(Ordering::Acquire) {
        0 => ExecutionState::Stopped,
        2 => ExecutionState::Rebooting,
        3 => ExecutionState::Pending,
        4 => ExecutionState::RebootTitle,
        5 => ExecutionState::PendingTitle,
        _ => ExecutionState::Started,
    }
}

/// The server thread takes slot events in its passes. Until then, and once
/// it stops, threads take the monitor's default disposition instead of
/// waiting.
static EVENTS_SERVED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// Threads inside `post_and_wait`; unload waits for them to leave.
static WAITERS: AtomicU32 = AtomicU32::new(0);
/// Interval at which a waiting thread checks whether the server stopped,
/// in 100 ns units (negative: relative).
const STOP_CHECK_INTERVAL: i64 = -100 * 10_000;

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
/// with the monitor's default disposition.
fn post_and_wait(
    kind: u32,
    thread_object: u32,
    record: u32,
    context: u32,
    argument: u32,
) -> Option<u32> {
    WAITERS.fetch_add(1, Ordering::AcqRel);
    let disposition = post_and_wait_served(kind, thread_object, record, context, argument);
    WAITERS.fetch_sub(1, Ordering::AcqRel);
    disposition
}

fn post_and_wait_served(
    kind: u32,
    thread_object: u32,
    record: u32,
    context: u32,
    argument: u32,
) -> Option<u32> {
    let (slot_index, slot) = claim_slot()?;
    let thread_record = record_of(thread_object);
    slot.reset_event();
    slot.kind.store(kind, Ordering::Relaxed);
    slot.thread_object.store(thread_object, Ordering::Relaxed);
    slot.thread_id
        .store(read_u32(thread_object + thread::ID), Ordering::Relaxed);
    slot.record.store(record, Ordering::Relaxed);
    slot.context.store(context, Ordering::Relaxed);
    slot.argument.store(argument, Ordering::Relaxed);
    if let Some(thread_record) = thread_record {
        write_u32(thread_record + 12, slot_index as u32 + 1);
    }
    slot.state.store(SLOT_POSTED, Ordering::Release);
    let disposition = loop {
        if slot.state.load(Ordering::Acquire) == SLOT_COMPLETED {
            break Some(slot.disposition.load(Ordering::Relaxed));
        }
        // A slot the server has not completed is reclaimed once it stops;
        // completion claims the slot first, so exactly one side wins.
        if !EVENTS_SERVED.load(Ordering::Acquire)
            && (slot
                .state
                .compare_exchange(
                    SLOT_POSTED,
                    SLOT_FILLING,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
                || slot
                    .state
                    .compare_exchange(
                        SLOT_TAKEN,
                        SLOT_FILLING,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok())
        {
            break None;
        }
        // SAFETY: `reset_event` built the slot event before the slot was posted.
        unsafe {
            xboxkrnl::KeWaitForSingleObject(
                slot.event().cast(),
                WaitReason::UserRequest,
                ProcessorMode::User,
                false,
                &STOP_CHECK_INTERVAL,
            )
        };
    };
    if let Some(thread_record) = record_of(thread_object) {
        // Context services of other threads follow the slot under this
        // lock; once it is cleared the context on this stack is no longer
        // reachable.
        let process = read_u32(thread_object + thread::PROCESS) as usize as *mut KspinLock;
        // SAFETY: the process object of a live thread starts with its
        // thread list spin lock.
        unsafe {
            let irql = xboxkrnl::KfAcquireSpinLock(process);
            write_u32(thread_record + 12, 0);
            xboxkrnl::KfReleaseSpinLock(process, irql);
        }
    }
    slot.state.store(SLOT_FREE, Ordering::Release);
    disposition
}

/// Take a free slot while the server takes events.
fn claim_slot() -> Option<(usize, &'static Slot)> {
    loop {
        if !EVENTS_SERVED.load(Ordering::Acquire) {
            return None;
        }
        if let Some(index) = SLOTS.iter().position(|slot| {
            slot.state
                .compare_exchange(
                    SLOT_FREE,
                    SLOT_FILLING,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
        }) {
            return Some((index, &SLOTS[index]));
        }
        sleep(Duration::from_millis(1));
    }
}

/// Post a thread event without waiting, as stock queues thread
/// notifications (0x91f39ad0). The thread object may be gone when the
/// server takes the event, so the slot carries everything the event
/// needs and its `thread_object` is 0: `record` the start address,
/// `context` the title entry flag, `argument` the title process flag.
fn post_detached(kind: u32, thread_object: u32) {
    WAITERS.fetch_add(1, Ordering::AcqRel);
    if let Some((_, slot)) = claim_slot() {
        slot.kind.store(kind, Ordering::Relaxed);
        slot.thread_object.store(0, Ordering::Relaxed);
        slot.thread_id
            .store(read_u32(thread_object + thread::ID), Ordering::Relaxed);
        slot.record.store(
            read_u32(thread_object + thread::START_ADDRESS),
            Ordering::Relaxed,
        );
        let title_entry = read_u32(thread_object + thread::CREATE_FLAGS) & THREAD_TITLE_ENTRY != 0;
        slot.context
            .store(u32::from(title_entry), Ordering::Relaxed);
        slot.argument.store(
            u32::from(process_kind_of(thread_object) == ProcessKind::Title),
            Ordering::Relaxed,
        );
        slot.state.store(SLOT_POSTED, Ordering::Release);
    }
    WAITERS.fetch_sub(1, Ordering::AcqRel);
}

/// Free the slots of detached events once the server stopped taking
/// events.
fn discard_detached() {
    for slot in &SLOTS {
        // Claimed first: a posted slot's fields are stable only while held.
        if slot
            .state
            .compare_exchange(
                SLOT_POSTED,
                SLOT_FILLING,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            let next = if slot.thread_object.load(Ordering::Relaxed) == 0 {
                SLOT_FREE
            } else {
                SLOT_POSTED
            };
            slot.state.store(next, Ordering::Release);
        }
    }
}

/// Mark the data block as writing a crash dump (+0x0c bit 0x40), as stock
/// does before each dump; returns the updated flags.
fn mark_dump() -> u32 {
    let data = kernel::debug_monitor_data();
    let flags = data.flags.load(Ordering::Relaxed) | DebugMonitorFlags::DUMP.bits();
    data.flags.store(flags, Ordering::Release);
    flags
}

/// Write a crash dump of an exception; bit 4 of the data block flags, set
/// by a bug check, selects the dump kind.
fn write_dump(record: u32, context: u32) {
    let flags = mark_dump();
    // SAFETY: `record` and `context` are the exception record and context
    // the kernel passed to the debug routine.
    unsafe { DumpWriteDump(record, context, (flags & 4) >> 2) };
}

crate::exports::bridged!(debug_routine_entry, debug_routine);

/// Replacement kernel debug routine (stock 0x91f3a980). Threads that can
/// wait are handed to the server; threads above passive level and the
/// server thread are dispatched in place, as is every thread while the
/// server does not take events.
extern "C" fn debug_routine(trap_frame: u32, record: u32, context: u32, second_chance: u32) -> u32 {
    let previous = PREVIOUS_DEBUG_ROUTINE.load(Ordering::Acquire);
    let chain = move || {
        if previous == 0 {
            0
        } else {
            // SAFETY: the kernel's previous routine takes four register
            // arguments.
            unsafe { kernel::call_export(previous, trap_frame, record, context, second_chance) }
        }
    };
    let thread_object = current_thread();
    let irql = current_irql();
    let server = thread_object == SERVER_THREAD.load(Ordering::Relaxed);
    if server
        && irql == Irql::PASSIVE
        && NtStatus(read_u32(record)) == NtStatus::BREAKPOINT
        && BREAK_NOW_ARMED.swap(false, Ordering::AcqRel)
    {
        capture_break_now(record, context);
        return 1;
    }
    if irql != Irql::PASSIVE || server {
        let delivery = if irql == Irql::PASSIVE {
            Delivery::Inline
        } else if irql == Irql::APC || irql == Irql::DISPATCH {
            Delivery::Deferred
        } else {
            Delivery::Discarded
        };
        return dispatch_in_place(
            thread_object,
            record,
            context,
            second_chance != 0,
            delivery,
            &chain,
        );
    }
    if record_of(thread_object).is_some_and(|thread_record| read_u32(thread_record + 12) != 0) {
        // A nested exception while the thread waits in a slot.
        return chain();
    }
    let Some(disposition) = post_and_wait(
        KIND_EXCEPTION,
        thread_object,
        record,
        context,
        second_chance,
    ) else {
        return dispatch_in_place(
            thread_object,
            record,
            context,
            second_chance != 0,
            Delivery::Deferred,
            &chain,
        );
    };
    let mut handled = disposition & DISPOSITION_HANDLED != 0;
    if disposition & DISPOSITION_DUMP != 0 {
        write_dump(record, context);
    }
    if disposition & DISPOSITION_CHAIN != 0 {
        handled = chain() & 0xff != 0;
    }
    u32::from(handled)
}

/// Kernel trap frame offsets.
mod trap_frame {
    pub const IAR: u32 = 0x1ac;
    /// Low word of the saved Msr.
    pub const MSR_LOW: u32 = 0x1b4;
}

/// Context block the kernel fills; vector registers need 16-byte
/// alignment.
#[repr(C, align(16))]
struct KernelContext([u8; context::SIZE]);

/// Kernel stack overflow notification entry (stock 0x91f23330). The trap
/// frame in r3 holds only the volatile registers, so r13-r31 are stored
/// into its register area (GPR n at +0x50 + 8 * n) before the context is
/// built from it.
#[unsafe(naked)]
unsafe extern "C" fn stack_overflow_entry() {
    core::arch::naked_asm!(
        ".irp reg, 13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31",
        // std \reg, 0x50 + 8 * \reg(r3)
        ".long (62 << 26) | (\\reg << 21) | (3 << 16) | (0x50 + 8 * \\reg)",
        ".endr",
        "lis 12, {target}@ha",
        "addi 12, 12, {target}@l",
        "b {bridge}",
        target = sym stack_overflow,
        bridge = sym crate::exports::export_bridge,
    )
}

/// Kernel stack overflow notification (stock 0x91f3aab0), called before the
/// bug check with the trap frame of the overflowing thread. The first call
/// unhooks it. A thread that can stop reports the overflow until it is no
/// longer continued; the dump follows unless the kernel debugger has it.
/// Returns the faulting address as stock does; the kernel ignores it.
extern "C" fn stack_overflow(frame: u32) -> u32 {
    let address = read_u32(frame + trap_frame::IAR);
    let variable = kernel::debug_monitor_data()
        .stack_overflow_notification
        .load(Ordering::Relaxed);
    // SAFETY: the variable is the kernel's word-aligned notification
    // pointer, which `install` found nonzero.
    let hooked =
        unsafe { AtomicU32::from_ptr(variable as usize as *mut u32) }.swap(0, Ordering::AcqRel);
    let policy = load_policy();
    if hooked == 0
        || (policy.kernel_debugger
            && hardware_flags().contains(xboxkrnl::HardwareFlags::KERNEL_DEBUGGER))
    {
        return address;
    }
    let thread_object = current_thread();
    let can_stop = record_of(thread_object)
        .is_some_and(|record| record_flags(record) & RECORD_DEBUGGABLE != 0)
        && current_irql() == Irql::PASSIVE
        && read_u32(frame + trap_frame::MSR_LOW) != 0
        && (policy.dump_mode != DumpMode::Enabled || policy.attached);
    if !can_stop && policy.dump_mode == DumpMode::Disabled {
        return address;
    }
    let mut context = KernelContext([0; context::SIZE]);
    context.0[..4].copy_from_slice(&ContextFlags::FULL.bits().to_be_bytes());
    // SAFETY: `frame` is the trap frame the kernel passed; `context` is a
    // live local of the full context size.
    unsafe { KeContextFromKframes(frame, context.0.as_mut_ptr()) };
    let mut record = [0u32; 0x14];
    record[0] = NtStatus::STACK_OVERFLOW.0;
    record[1] = ExceptionFlags::NONCONTINUABLE.bits();
    record[3] = address;
    let record_address = record.as_mut_ptr() as usize as u32;
    let context_address = context.0.as_mut_ptr() as usize as u32;
    let dump = if can_stop {
        // SAFETY: the kernel calls with interrupts off and the thread must
        // wait.
        unsafe { processor::enable_interrupts() };
        loop {
            let Some(disposition) = post_and_wait(
                KIND_STACK_OVERFLOW,
                thread_object,
                record_address,
                context_address,
                0,
            ) else {
                // As for a thread that cannot stop.
                break policy.dump_mode != DumpMode::Disabled;
            };
            if disposition & DISPOSITION_HANDLED == 0 {
                break disposition & DISPOSITION_DUMP != 0;
            }
        }
    } else {
        true
    };
    if dump {
        // Stock passes dump kind 0 here, whatever the data block flags.
        mark_dump();
        // SAFETY: both addresses refer to the live locals filled above.
        unsafe { DumpWriteDump(record_address, context_address, 0) };
    }
    address
}

fn read_exception_record(raw: u32) -> ExceptionRecord {
    ExceptionRecord {
        code: NtStatus(read_u32(raw)),
        flags: ExceptionFlags::from_bits_retain(read_u32(raw + 4)),
        address: read_u32(raw + 0xc),
        parameter_count: read_u32(raw + 0x10),
        parameters: core::array::from_fn(|n| read_u32(raw + 0x14 + 4 * n as u32)),
        record_address: raw,
    }
}

/// The monitor's dispatch on a thread that cannot wait for the server.
fn dispatch_in_place(
    thread_object: u32,
    record: u32,
    context: u32,
    second_chance: bool,
    delivery: Delivery,
    chain: &dyn Fn() -> u32,
) -> u32 {
    let policy = load_policy();
    let gpr = |n: u32| context + context::GPR + 8 * n;
    let mut registers = DirectRegisters {
        msr: Msr::from_bits_retain(read_u32(context + context::MSR)),
        iar: read_u32(context + context::IAR),
        gpr3: read_u64(gpr(3)),
        gpr4: read_u64(gpr(4)),
    };
    let iar = registers.iar;
    let thread = ThreadId(read_u32(thread_object + thread::ID));
    let event = DirectException {
        thread,
        record: read_exception_record(record),
        second_chance,
        has_record: record_of(thread_object).is_some(),
        hardware_flags: hardware_flags(),
        delivery,
    };
    let instruction = readable(iar).then(|| read_u32(iar));
    let mut step = match DIRECT_STEP.swap(0, Ordering::AcqRel) {
        0 => None,
        saved => Some(DirectStep {
            saved_trace: saved == 2,
        }),
    };
    let outcome = dispatch_direct(&policy, &event, &mut registers, instruction, &mut step);
    DIRECT_STEP.store(
        step.map_or(0, |step| 1 + u32::from(step.saved_trace)),
        Ordering::Release,
    );
    write_u32(context + context::MSR, registers.msr.bits());
    write_u32(context + context::IAR, registers.iar);
    write_u64(gpr(3), registers.gpr3);
    write_u64(gpr(4), registers.gpr4);
    if let Some(value) = outcome.data_breakpoint_register {
        // SAFETY: the routine is this module's IPI entry, which takes the
        // register value as its argument.
        unsafe {
            KeIpiGenericCall(
                set_data_breakpoint_entry as *const () as usize as u32,
                value,
            )
        };
    }
    if let Some(request) = outcome.thread_name {
        name_thread(Some(request.thread), request.address);
    }
    if let Some(notice) = outcome.notice
        && delivery != Delivery::Discarded
    {
        queue_direct(thread, iar, outcome.record, notice);
    }
    if outcome.disposition.write_dump {
        write_dump(record, context);
    }
    let mut handled = outcome.disposition.handled;
    if outcome.disposition.chain_kernel_debugger {
        handled = chain() & 0xff != 0;
    }
    u32::from(handled)
}

crate::exports::bridged!(thread_notification_entry, thread_notification);

/// Thread creation and termination routine (stock 0x91f32530).
extern "C" fn thread_notification(_registration: u32, thread_object: u32, create: u32) -> u32 {
    if create == 0 {
        let process = read_u32(thread_object + thread::PROCESS);
        // SAFETY: the kernel passes a live thread object whose process
        // object starts with its thread list spin lock; the record and its
        // name are pool blocks this module allocated and detaches here.
        unsafe {
            xboxkrnl::KeEnterCriticalRegion();
            let irql = xboxkrnl::KfAcquireSpinLock(process as usize as *mut KspinLock);
            let record = record_of(thread_object);
            let mut debuggable = false;
            if let Some(record) = record {
                write_u32(thread_object + thread::MONITOR_RECORD, 0);
                debuggable = record_flags(record) & RECORD_DEBUGGABLE != 0;
                if read_u32(record + 4) != 0 {
                    KeResumeThread(thread_object as usize as *mut Kthread);
                }
            }
            xboxkrnl::KfReleaseSpinLock(process as usize as *mut KspinLock, irql);
            if debuggable && thread_object != SERVER_THREAD.load(Ordering::Relaxed) {
                post_detached(KIND_TERMINATE, thread_object);
            }
            if let Some(record) = record {
                let name = read_u32(record + 8);
                if name != 0 {
                    xboxkrnl::ExFreePool(name);
                }
                xboxkrnl::ExFreePool(record);
            }
            crate::backend::performance::pix::thread_terminated();
            xboxkrnl::KeLeaveCriticalRegion();
        }
        return 0;
    }
    match create_record(thread_object) {
        Some(record) if record_flags(record) & RECORD_DEBUGGABLE != 0 => {
            // Stock waits only when the thread may stop (0x91f39b30): with
            // `stopon createthread`, or a title entry that may break.
            let title_entry =
                read_u32(thread_object + thread::CREATE_FLAGS) & THREAD_TITLE_ENTRY != 0;
            if !title_entry && !load_policy().stop_on.contains(StopOn::CREATE_THREAD) {
                post_detached(KIND_CREATE, thread_object);
                return 0;
            }
            let disposition = post_and_wait(KIND_CREATE, thread_object, 0, 0, 0);
            if disposition.is_some_and(|disposition| disposition & DISPOSITION_BREAK != 0) {
                // SAFETY: executes the breakpoint trap, handled by the
                // debug routine.
                unsafe { core::arch::asm!("twi 31, 0, 0x16") };
            }
        }
        Some(_) => {}
        None => kernel::debug_print(c"dm: could not alloc thread data\n"),
    }
    0
}

/// Hook the kernel debug routine and the stack overflow notification and
/// register for thread notifications (stock 0x91f3bc38 and the thread
/// notification registration in 0x91f32628). Call once after the debug
/// monitor data is available.
pub(crate) fn install() {
    let data = kernel::debug_monitor_data();
    let routine_variable = data.debug_routine.load(Ordering::Relaxed);
    if routine_variable != 0 && PREVIOUS_DEBUG_ROUTINE.load(Ordering::Relaxed) == 0 {
        PREVIOUS_DEBUG_ROUTINE.store(read_u32(routine_variable), Ordering::Release);
        write_u32(
            routine_variable,
            debug_routine_entry as *const () as usize as u32,
        );
    }
    let overflow_variable = data.stack_overflow_notification.load(Ordering::Relaxed);
    if overflow_variable != 0 {
        write_u32(
            overflow_variable,
            stack_overflow_entry as *const () as usize as u32,
        );
    }
    THREAD_NOTIFICATION[0].store(
        thread_notification_entry as *const () as usize as u32,
        Ordering::Relaxed,
    );
    // SAFETY: the registration block is static and stays registered until
    // `uninstall`.
    unsafe { ExRegisterThreadNotification(THREAD_NOTIFICATION.as_ptr().cast_mut().cast(), true) };
}

/// Undo [`install`] before the image unloads.
pub(crate) fn uninstall() {
    if THREAD_NOTIFICATION[0].load(Ordering::Relaxed) != 0 {
        // SAFETY: `install` registered this static block.
        unsafe { ExRegisterThreadNotification(THREAD_NOTIFICATION.as_ptr().cast_mut().cast(), false) };
        THREAD_NOTIFICATION[0].store(0, Ordering::Relaxed);
    }
    let data = kernel::debug_monitor_data();
    let overflow_variable = data.stack_overflow_notification.load(Ordering::Relaxed);
    if overflow_variable != 0 {
        // SAFETY: the kernel's word-aligned notification pointer.
        let slot = unsafe { AtomicU32::from_ptr(overflow_variable as usize as *mut u32) };
        let _ = slot.compare_exchange(
            stack_overflow_entry as *const () as usize as u32,
            0,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
    let routine_variable = data.debug_routine.load(Ordering::Relaxed);
    if routine_variable != 0
        && read_u32(routine_variable) == debug_routine_entry as *const () as usize as u32
    {
        write_u32(
            routine_variable,
            PREVIOUS_DEBUG_ROUTINE.swap(0, Ordering::AcqRel),
        );
    }
}

/// Record the server thread; it never waits for its own events. Its
/// monitor record is exempt and not debuggable, as stock's command thread
/// (0x91f50cb0) marks its own.
pub(crate) fn set_server_thread() {
    let thread_object = current_thread();
    SERVER_THREAD.store(thread_object, Ordering::Relaxed);
    if let Some(record) = create_record(thread_object) {
        write_u32(
            record,
            (record_flags(record) | RECORD_EXEMPT) & !RECORD_DEBUGGABLE,
        );
    }
}

/// Words of a published policy copy.
const POLICY_WORDS: usize = 7;
const POLICY_KD_LITE: u32 = 0x1;
const POLICY_KERNEL_DEBUGGER: u32 = 0x2;
const POLICY_TRAP_PASSTHROUGH: u32 = 0x4;
const POLICY_DUMP_IN_PROGRESS: u32 = 0x8;
const POLICY_ATTACHED: u32 = 0x10;
const POLICY_DATA_BREAKPOINT: u32 = 0x20;

/// Two copies of the published policy; `POLICY_SEQUENCE` selects the
/// current one. The server thread writes the other copy before switching,
/// so a reader at raised level never waits on the writer.
static POLICY: [[AtomicU32; POLICY_WORDS]; 2] =
    [const { [const { AtomicU32::new(0) }; POLICY_WORDS] }; 2];
static POLICY_SEQUENCE: AtomicU32 = AtomicU32::new(0);
/// Step over the data breakpoint begun in place: 0 none, else 1 plus the
/// saved trace flag.
static DIRECT_STEP: AtomicU32 = AtomicU32::new(0);

fn encode_policy(policy: &DirectPolicy) -> [u32; POLICY_WORDS] {
    let bit = |set: bool, bit: u32| if set { bit } else { 0 };
    let flags = bit(policy.kd_lite, POLICY_KD_LITE)
        | bit(policy.kernel_debugger, POLICY_KERNEL_DEBUGGER)
        | bit(policy.trap_passthrough, POLICY_TRAP_PASSTHROUGH)
        | bit(policy.dump_in_progress, POLICY_DUMP_IN_PROGRESS)
        | bit(policy.attached, POLICY_ATTACHED)
        | bit(policy.data_breakpoint.is_some(), POLICY_DATA_BREAKPOINT);
    let dump_mode = match policy.dump_mode {
        DumpMode::Smart => 0,
        DumpMode::Enabled => 1,
        DumpMode::Disabled => 2,
        DumpMode::Other(raw) => raw,
    };
    let data = policy.data_breakpoint;
    [
        flags,
        dump_mode,
        policy.defer_mask.bits(),
        policy.stop_on.bits(),
        data.map_or(0, |data| data.address),
        data.map_or(0, |data| data.size),
        data.map_or(0, |data| data.kind as u32),
    ]
}

fn decode_policy(words: [u32; POLICY_WORDS]) -> DirectPolicy {
    let flag = |bit: u32| words[0] & bit != 0;
    let kind = match words[6] {
        1 => DataKind::Write,
        2 => DataKind::ReadWrite,
        _ => DataKind::Read,
    };
    DirectPolicy {
        stop_on: StopOn::from_bits_retain(words[3]),
        kd_lite: flag(POLICY_KD_LITE),
        kernel_debugger: flag(POLICY_KERNEL_DEBUGGER),
        trap_passthrough: flag(POLICY_TRAP_PASSTHROUGH),
        dump_mode: DumpMode::from_raw(words[1]),
        dump_in_progress: flag(POLICY_DUMP_IN_PROGRESS),
        attached: flag(POLICY_ATTACHED),
        defer_mask: EventDeferMask::from_bits_retain(words[2]),
        data_breakpoint: flag(POLICY_DATA_BREAKPOINT).then_some(DataBreakpoint {
            address: words[4],
            size: words[5],
            kind,
        }),
    }
}

/// The policy the server last published.
pub(crate) fn load_policy() -> DirectPolicy {
    loop {
        let sequence = POLICY_SEQUENCE.load(Ordering::Acquire);
        let copy = &POLICY[(sequence & 1) as usize];
        let words = core::array::from_fn(|index| copy[index].load(Ordering::Relaxed));
        if POLICY_SEQUENCE.load(Ordering::Acquire) == sequence {
            return decode_policy(words);
        }
    }
}

fn store_policy(policy: &DirectPolicy) {
    let words = encode_policy(policy);
    let sequence = POLICY_SEQUENCE.load(Ordering::Relaxed);
    let current = &POLICY[(sequence & 1) as usize];
    if words
        .iter()
        .zip(current)
        .all(|(word, slot)| *word == slot.load(Ordering::Relaxed))
    {
        return;
    }
    for (slot, word) in POLICY[((sequence + 1) & 1) as usize].iter().zip(words) {
        slot.store(word, Ordering::Relaxed);
    }
    POLICY_SEQUENCE.store(sequence.wrapping_add(1), Ordering::Release);
}

/// Pool tag of queued direct notifications ('Ddfn').
const DIRECT_TAG: PoolTag = PoolTag::new(*b"nfdD");

/// A queued direct notification; the captured text follows it.
#[repr(C)]
struct DirectNode {
    next: u32,
    notification: DirectNotification,
}

static DIRECT_LOCK: AtomicU32 = AtomicU32::new(0);
static DIRECT_HEAD: AtomicU32 = AtomicU32::new(0);
static DIRECT_TAIL: AtomicU32 = AtomicU32::new(0);

/// Capture what a direct notice names and queue it for the server (stock
/// 0x91f39768 allocates the same way at raised level).
fn queue_direct(thread: ThreadId, iar: u32, record: ExceptionRecord, notice: DirectNotice) {
    let (text_address, text_length) = match notice {
        DirectNotice::DebugString { address, length } | DirectNotice::Rip { address, length } => (
            address,
            readable_length(address, usize::from(length).min(NOTICE_TEXT_CAPACITY)),
        ),
        _ => (0, 0),
    };
    let module = match notice {
        DirectNotice::ModuleLoad { name_string, entry }
        | DirectNotice::ModuleUnload {
            name_string, entry, ..
        } => describe_module(name_string, entry),
        _ => None,
    };
    let header = core::mem::size_of::<DirectNode>();
    // SAFETY: pool allocation has no pointer arguments.
    let node = unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(
            (header + text_length) as u32,
            DIRECT_TAG,
            PoolType::System,
        )
    };
    if node == 0 {
        return;
    }
    let notification = DirectNotification {
        thread,
        iar,
        record,
        notice,
        module,
        text_length,
    };
    // SAFETY: the pool block holds the node and `text_length` bytes.
    unsafe {
        core::ptr::write(
            node as usize as *mut DirectNode,
            DirectNode {
                next: 0,
                notification,
            },
        );
        for offset in 0..text_length {
            let byte = read_u8(text_address + offset as u32);
            core::ptr::write((node as usize + header + offset) as *mut u8, byte);
        }
    }
    let lock = DIRECT_LOCK.as_ptr();
    // SAFETY: `lock` is the static direct notification spin lock.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(lock.cast()) };
    match DIRECT_TAIL.swap(node, Ordering::Relaxed) {
        0 => DIRECT_HEAD.store(node, Ordering::Relaxed),
        tail => write_u32(tail, node),
    }
    // SAFETY: the lock was acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(lock.cast(), irql) };
}

/// Bytes of `length` at `address` that can be read without a fault.
fn readable_length(address: u32, length: usize) -> usize {
    (0..length)
        .find(|&offset| {
            let byte = address.wrapping_add(offset as u32);
            (offset == 0 || byte & 0xfff == 0) && !readable(byte)
        })
        .unwrap_or(length)
}

/// Context of the command thread stopped by `break now`.
struct BreakNowCapture(
    core::cell::UnsafeCell<[u8; context::SIZE]>,
    core::cell::UnsafeCell<[u32; 0x14]>,
);

// SAFETY: the server thread writes the capture while `BREAK_NOW_STOPPED` is
// clear and only the server thread reads or writes it while it is set.
unsafe impl Sync for BreakNowCapture {}

static BREAK_NOW: BreakNowCapture = BreakNowCapture(
    core::cell::UnsafeCell::new([0; context::SIZE]),
    core::cell::UnsafeCell::new([0; 0x14]),
);
static BREAK_NOW_ARMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static BREAK_NOW_STOPPED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// The command thread hit the `break now` trap: keep its exception record
/// and context for the monitor and let the thread run on past the trap.
fn capture_break_now(record: u32, context: u32) {
    let context_copy = BREAK_NOW.0.get() as usize as u32;
    let record_copy = BREAK_NOW.1.get() as usize as u32;
    for offset in (0..context::SIZE as u32).step_by(4) {
        write_u32(context_copy + offset, read_u32(context + offset));
    }
    for offset in (0..0x50).step_by(4) {
        write_u32(record_copy + offset, read_u32(record + offset));
    }
    write_u32(
        context + context::IAR,
        read_u32(context + context::IAR).wrapping_add(4),
    );
    BREAK_NOW_STOPPED.store(true, Ordering::Release);
}

fn caller_can_wait() -> Option<u32> {
    let thread_object = current_thread();
    (thread_object != SERVER_THREAD.load(Ordering::Relaxed) && current_irql() == Irql::PASSIVE)
        .then_some(thread_object)
}

/// Run the monitor's execution state machine (stock 0x91f2da88 without
/// its wait flag) on the server thread; the caller waits until it ran. A
/// pending_title request while stopped waits for the state to change.
/// Does nothing on the server thread, above passive level, or while the
/// server does not take events.
pub(crate) fn request_execution(target: ExecutionState, notify: bool) {
    if let Some(thread_object) = caller_can_wait() {
        post_and_wait(
            KIND_EXECUTION,
            thread_object,
            0,
            0,
            execution_code(target) | u32::from(notify) << 8,
        );
    }
}

/// Stop the calling thread with `execution pending_title stop` until
/// execution starts (stock 0x91f523a0). Without `forever` the wait ends
/// after 15 s and the caller starts execution itself. Returns whether the
/// thread was released before that; false on the server thread, above
/// passive level, or while the server does not take events.
pub(crate) fn stop_at_pending_title(forever: bool) -> bool {
    caller_can_wait().is_some_and(|thread_object| {
        post_and_wait(KIND_TITLE_STOP, thread_object, 0, 0, u32::from(forever))
            .is_some_and(|disposition| disposition & DISPOSITION_HANDLED != 0)
    })
}

/// A profile-guided module registered (stock export 107): with
/// `stopon pogomodstart` the calling thread stops with a `pogomodstartup`
/// line until it is continued. `name` is the address of the module path.
pub(crate) fn report_pogo_module_start(name: u32, module: u32) {
    if !load_policy().stop_on.contains(StopOn::POGO_MODULE_START) {
        return;
    }
    if let Some(thread_object) = caller_can_wait() {
        post_and_wait(KIND_POGO, thread_object, name, module, 0);
    }
}

const fn execution_from_code(code: u32) -> ExecutionState {
    match code {
        0 => ExecutionState::Stopped,
        2 => ExecutionState::Rebooting,
        3 => ExecutionState::Pending,
        4 => ExecutionState::RebootTitle,
        5 => ExecutionState::PendingTitle,
        _ => ExecutionState::Started,
    }
}

/// Call the loaded extension's OnTellDebugger export with a dispatcher
/// result (stock 0x91f2e2e8); its return replaces the result.
pub(crate) fn tell_extension(code: u32, argument: u32, result: u32) -> u32 {
    EXTENSION_CALLS.fetch_add(1, Ordering::AcqRel);
    let routine = EXTENSION_TELL_DEBUGGER.load(Ordering::Acquire);
    let result = if routine == 0 {
        result
    } else {
        // SAFETY: the export was resolved from the loaded extension image
        // and takes three register arguments.
        unsafe { kernel::call_export(routine, code, argument, result, 0) }
    };
    EXTENSION_CALLS.fetch_sub(1, Ordering::AcqRel);
    result
}

/// Collected debuggable thread identifiers.
pub(crate) struct ThreadList {
    pub(crate) count: usize,
    /// Threads were left unvisited once `capacity` were stored.
    pub(crate) overflow: bool,
}

/// Store the identifiers of the debuggable threads, title threads first,
/// as stock export 15 (0x91f25f28) walks them: records are created on the
/// way and the walk stops visiting threads once `capacity` are stored.
#[inline(never)]
pub(crate) fn collect_thread_ids(
    capacity: usize,
    store: &mut dyn FnMut(usize, ThreadId),
) -> ThreadList {
    let mut list = ThreadList {
        count: 0,
        overflow: false,
    };
    for process in [ProcessKind::Title, ProcessKind::System] {
        for_each_thread(process, |thread_object| {
            if list.count >= capacity {
                list.overflow = true;
                return;
            }
            let Some(record) = create_record(thread_object) else {
                return;
            };
            if record_flags(record) & RECORD_DEBUGGABLE != 0 {
                store(list.count, ThreadId(read_u32(thread_object + thread::ID)));
                list.count += 1;
            }
        });
    }
    list
}

/// Identifiers of the debuggable threads, title threads first (stock
/// export 15); `None` when they do not fit.
pub(crate) fn debuggable_thread_ids(ids: &mut [ThreadId]) -> Option<usize> {
    let list = collect_thread_ids(ids.len(), &mut |index, id| ids[index] = id);
    (!list.overflow).then_some(list.count)
}

/// Address of the name a thread was given, if any.
pub(crate) fn thread_name(thread_object: u32) -> Option<u32> {
    record_of(thread_object)
        .map(|record| read_u32(record + 8))
        .filter(|&name| name != 0)
}

/// The server thread object, 0 before the server runs.
pub(crate) fn server_thread() -> u32 {
    SERVER_THREAD.load(Ordering::Relaxed)
}

/// Replace the bits `mask` of a thread's monitor record flags with those
/// of `value` (PIX pause, stock 0x91f61610); the previous flags, `None`
/// without a record.
pub(crate) fn exchange_record_flags(thread_object: u32, mask: u32, value: u32) -> Option<u32> {
    let record = record_of(thread_object)?;
    let previous = record_flags(record);
    write_u32(record, (previous & !mask) | (value & mask));
    Some(previous)
}

/// Set the name of `thread` from a NUL-terminated string (stock
/// 0x91f39dc0). `None` names the calling thread.
pub(crate) fn name_thread(thread: Option<ThreadId>, address: u32) {
    if address == 0 || read_u8(address) == 0 {
        return;
    }
    let reference = match thread {
        Some(id) => match ThreadRef::lookup(id) {
            Ok(reference) => Some(reference),
            Err(NoSuchThread) => return,
        },
        None => None,
    };
    let thread_object = reference
        .as_ref()
        .map_or_else(current_thread, |reference| reference.0);
    let Some(record) = create_record(thread_object) else {
        return;
    };
    let mut length = 0u32;
    while read_u8(address + length) != 0 {
        length += 1;
    }
    let pool_type = if read_u8(thread_object + thread::PROCESS_TYPE) == 2 {
        PoolType::System
    } else {
        PoolType::Title
    };
    let old = read_u32(record + 8);
    if old != 0 {
        // SAFETY: the old name is a pool block this module allocated.
        unsafe { xboxkrnl::ExFreePool(old) };
    }
    // SAFETY: pool allocation has no pointer arguments.
    let copy = unsafe { xboxkrnl::ExAllocatePoolTypeWithTag(length + 1, RECORD_TAG, pool_type) };
    write_u32(record + 8, copy);
    if copy != 0 {
        for offset in 0..=length {
            // SAFETY: the pool block holds `length + 1` bytes.
            unsafe {
                core::ptr::write_volatile(
                    (copy + offset) as usize as *mut u8,
                    read_u8(address + offset),
                )
            };
        }
    }
}

crate::exports::bridged!(set_data_breakpoint_entry, set_data_breakpoint_on_processor);

extern "C" fn set_data_breakpoint_on_processor(value: u32) -> u32 {
    // SAFETY: writing DABR on this processor only arms a data breakpoint.
    unsafe { KeSetSpecialPurposeRegister(SpecialPurposeRegister::DABR, u64::from(value)) };
    value
}

/// Address ranges the debugger never maps (memory-mapped devices).
const EXCLUDED_RANGES: &[(u32, u32)] = &[
    (0x7fc8_0000, 0x7fc9_ffff),
    (0x7fd0_0000, 0x7fdf_ffff),
    (0x7fea_0000, 0x7fea_ffff),
    (0x7fed_0000, 0x7fed_ffff),
    (0x8fff_0000, 0x8fff_0fff),
    (0x8fff_1000, 0x8fff_1fff),
];

fn is_excluded(address: u32) -> bool {
    EXCLUDED_RANGES
        .iter()
        .any(|&(low, high)| (low..=high).contains(&address))
}

fn readable(address: u32) -> bool {
    // SAFETY: the kernel validates the address before it maps it.
    let mapped = unsafe { xboxkrnl::MmDbgReadCheck(address) };
    mapped != 0 && !is_excluded(mapped)
}

/// Copy the groups in `flags` between a kernel context and a [`Context`].
fn read_context(address: u32, flags: ContextFlags, out: &mut Context) {
    if flags.contains(ContextFlags::CONTROL) {
        out.msr = Msr::from_bits_retain(read_u32(address + context::MSR));
        out.iar = read_u32(address + context::IAR);
        out.lr = read_u32(address + context::LR);
        out.ctr = read_u64(address + context::CTR);
    }
    if flags.contains(ContextFlags::INTEGER) {
        for (n, gpr) in out.gpr.iter_mut().enumerate() {
            *gpr = read_u64(address + context::GPR + 8 * n as u32);
        }
        out.cr = read_u32(address + context::CR);
        out.xer = read_u32(address + context::XER);
    }
    if flags.contains(ContextFlags::FLOATING_POINT) {
        out.fpscr = read_u64(address + context::FPSCR);
        for (n, fpr) in out.fpr.iter_mut().enumerate() {
            *fpr = read_u64(address + context::FPR + 8 * n as u32);
        }
    }
    if flags.contains(ContextFlags::VECTOR) {
        for (n, word) in out.vscr.iter_mut().enumerate() {
            *word = read_u32(address + context::VSCR + 4 * n as u32);
        }
        for (index, vector) in out.vr.iter_mut().enumerate() {
            for (n, word) in vector.iter_mut().enumerate() {
                *word = read_u32(address + context::VR + 0x10 * index as u32 + 4 * n as u32);
            }
        }
    }
}

fn write_context(address: u32, source: &Context) {
    let flags = source.flags;
    if flags.contains(ContextFlags::CONTROL) {
        write_u32(address + context::MSR, source.msr.bits());
        write_u32(address + context::IAR, source.iar);
        write_u32(address + context::LR, source.lr);
        write_u64(address + context::CTR, source.ctr);
    }
    if flags.contains(ContextFlags::INTEGER) {
        for (n, &gpr) in source.gpr.iter().enumerate() {
            write_u64(address + context::GPR + 8 * n as u32, gpr);
        }
        write_u32(address + context::CR, source.cr);
        write_u32(address + context::XER, source.xer);
    }
    if flags.contains(ContextFlags::FLOATING_POINT) {
        write_u64(address + context::FPSCR, source.fpscr);
        for (n, &fpr) in source.fpr.iter().enumerate() {
            write_u64(address + context::FPR + 8 * n as u32, fpr);
        }
    }
    if flags.contains(ContextFlags::VECTOR) {
        for (n, &word) in source.vscr.iter().enumerate() {
            write_u32(address + context::VSCR + 4 * n as u32, word);
        }
        for (index, vector) in source.vr.iter().enumerate() {
            for (n, &word) in vector.iter().enumerate() {
                write_u32(
                    address + context::VR + 0x10 * index as u32 + 4 * n as u32,
                    word,
                );
            }
        }
    }
}

/// Exception context of a thread stopped at an event: a thread waiting in
/// a slot, or the command thread at the `break now` trap.
fn slot_context(thread_object: u32) -> Option<u32> {
    if thread_object == SERVER_THREAD.load(Ordering::Relaxed) {
        return BREAK_NOW_STOPPED
            .load(Ordering::Acquire)
            .then(|| BREAK_NOW.0.get() as usize as u32);
    }
    let record = record_of(thread_object)?;
    let slot = read_u32(record + 12);
    if slot == 0 {
        return None;
    }
    let slot = &SLOTS[slot as usize - 1];
    matches!(
        slot.kind.load(Ordering::Relaxed),
        KIND_EXCEPTION | KIND_STACK_OVERFLOW
    )
    .then(|| slot.context.load(Ordering::Relaxed))
}

/// Describe the module of a load or unload trap from the loader's name
/// string and module entry.
fn describe_module(name_string: u32, entry: u32) -> Option<ModuleEvent> {
    if name_string == 0 || entry == 0 {
        return None;
    }
    let mut module = ModuleEvent::default();
    let length = usize::from((read_u32(name_string) >> 16) as u16).min(MODULE_NAME_CAPACITY - 1);
    let buffer = read_u32(name_string + 4);
    for (offset, byte) in module.name[..length].iter_mut().enumerate() {
        *byte = read_u8(buffer + offset as u32);
    }
    module.name_length = length;
    module.base = read_u32(entry);
    module.size = read_u32(entry + 0xc);
    // SAFETY: `module.base` is the image base from the loader's module entry.
    let header = unsafe { RtlImageNtHeader(module.base) };
    // SAFETY: a non-null result is the NT headers of the mapped image, which
    // the loader keeps mapped across the load or unload trap.
    if let Some(header) = unsafe { header.as_ref() } {
        module.has_header = true;
        module.checksum = header.optional_header.check_sum.get();
        module.timestamp = header.file_header.time_date_stamp.get();
        module.image_size = header.optional_header.size_of_image.get();
        if header
            .file_header
            .characteristics()
            .contains(ImageCharacteristics::DLL)
        {
            module.flags |= ModuleFlags::DLL;
        }
        let mut size = 0u32;
        // SAFETY: the image has the NT header found above; `size` is a live local.
        module.pdata = unsafe {
            RtlImageDirectoryEntryToData(module.base, true, ImageDirectory::Exception, &mut size)
        };
        module.pdata_size = size;
    }
    Some(module)
}

/// Scheduler, stack, and name information of a thread (`threadinfo`,
/// stock export 89).
pub(crate) fn thread_information(id: ThreadId) -> Result<ThreadInfo, NoSuchThread> {
    let reference = ThreadRef::lookup(id)?;
    let object = reference.0;
    let process = read_u32(object + thread::PROCESS);
    // SAFETY: the referenced thread's process object starts with its thread
    // list spin lock.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(process as usize as *mut KspinLock) };
    let record = record_of(object);
    let name = record
        .map(|record| read_u32(record + 8))
        .filter(|&name| name != 0)
        .map(|address| {
            let mut length = 0;
            while read_u8(address + length) != 0 {
                length += 1;
            }
            ThreadName {
                address,
                length: length + 1,
            }
        });
    let info = ThreadInfo {
        suspend_count: read_u8(object + thread::SUSPEND_COUNT) as i8,
        monitor_suspended: record.is_some_and(|record| read_u32(record + 4) != 0),
        priority: read_u8(object + thread::PRIORITY),
        tls_base: read_u32(object + thread::TLS),
        start_address: read_u32(object + thread::START_ADDRESS),
        stack_base: read_u32(object + thread::STACK_BASE),
        stack_limit: read_u32(object + thread::STACK_LIMIT),
        create_time: read_u64(object + thread::CREATE_TIME),
        name,
        processor: read_u8(object + thread::PROCESSOR),
        last_error: read_u32(object + thread::LAST_ERROR),
    };
    // SAFETY: the lock was acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(process as usize as *mut KspinLock, irql) };
    Ok(info)
}

/// `suspend` and stock export 48 (0x91f267e8).
pub(crate) fn suspend(thread: ThreadId) -> Result<(), NoSuchThread> {
    let reference = ThreadRef::lookup(thread)?;
    // SAFETY: `reference` holds a reference to the thread object.
    unsafe { KeSuspendThread(reference.0 as usize as *mut Kthread) };
    Ok(())
}

/// `resume` and stock export 35 (0x91f26838).
pub(crate) fn resume(thread: ThreadId) -> Result<(), NoSuchThread> {
    let reference = ThreadRef::lookup(thread)?;
    // SAFETY: `reference` holds a reference to the thread object.
    unsafe { KeResumeThread(reference.0 as usize as *mut Kthread) };
    Ok(())
}

/// Read the groups in `out.flags` of a thread with a monitor record (stock
/// export 13, 0x91f26260); `out.flags` becomes the groups read. A thread
/// stopped in the monitor reports its exception context, another its
/// switch frame with the monitor's fill values.
pub(crate) fn read_thread_context(thread: ThreadId, out: &mut Context) -> Result<(), NoSuchThread> {
    let reference = ThreadRef::lookup(thread)?;
    let object = reference.0;
    let process = read_u32(object + thread::PROCESS);
    // SAFETY: the referenced thread's process object starts with its thread
    // list spin lock.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(process as usize as *mut KspinLock) };
    let requested = out.flags & ContextFlags::FULL;
    let result = if record_of(object).is_none() {
        Err(NoSuchThread)
    } else if let Some(address) = slot_context(object) {
        read_context(address, requested, out);
        out.flags = requested;
        Ok(())
    } else {
        // Switch frame: only the nonvolatile state is meaningful.
        let frame = read_u32(object + thread::SWITCH_FRAME);
        let mut flags = ContextFlags::empty();
        if requested.contains(ContextFlags::INTEGER) {
            flags = flags.union(ContextFlags::INTEGER);
            out.gpr = [u64::MAX; 32];
            for n in 14..32 {
                out.gpr[n] = read_u64(frame + 0x50 + 8 * (n as u32 - 14));
            }
            out.gpr[1] = u64::from(frame);
            out.cr = read_u32(frame + 0xe0);
            out.xer = u32::MAX;
        }
        if requested.contains(ContextFlags::CONTROL) {
            flags = flags.union(ContextFlags::CONTROL);
            out.msr = Msr::from_bits_retain(u32::MAX);
            out.iar = read_u32(frame + 0xe4);
            out.lr = read_u32(frame + 0xe8);
            out.ctr = u64::MAX;
        }
        out.flags = flags;
        Ok(())
    };
    // SAFETY: the lock was acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(process as usize as *mut KspinLock, irql) };
    result
}

/// Write the groups in `source.flags` to the exception context of a thread
/// stopped in the monitor (stock export 41, 0x91f26468).
pub(crate) fn write_thread_context(
    thread: ThreadId,
    source: &Context,
) -> Result<(), StoppedThreadError> {
    let reference = ThreadRef::lookup(thread)?;
    let object = reference.0;
    let process = read_u32(object + thread::PROCESS);
    // SAFETY: the referenced thread's process object starts with its thread
    // list spin lock.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(process as usize as *mut KspinLock) };
    let result = if record_of(object).is_none() {
        Err(StoppedThreadError::NoSuchThread)
    } else if let Some(address) = slot_context(object) {
        write_context(address, source);
        Ok(())
    } else {
        Err(StoppedThreadError::NotStopped)
    };
    // SAFETY: the lock was acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(process as usize as *mut KspinLock, irql) };
    result
}

/// Capture the calling thread's context and write a crash dump of it
/// (`crashdump`, stock export 83).
pub(crate) fn dump_calling_thread(flags: u32) {
    let mut context = KernelContext([0; context::SIZE]);
    // SAFETY: `context` is a live local of the full context size.
    unsafe {
        RtlCaptureContext(context.0.as_mut_ptr());
        DumpWriteDump(0, context.0.as_ptr() as usize as u32, flags);
    }
}

/// The groups in `flags` of the kernel context at `address`.
pub(crate) fn context_from_memory(address: u32, flags: ContextFlags) -> Context {
    let mut context = Context {
        flags,
        ..Context::default()
    };
    read_context(address, flags, &mut context);
    context
}

/// Store the groups in `source.flags` into the kernel context at `address`.
pub(crate) fn context_to_memory(address: u32, source: &Context) {
    write_context(address, source);
}

/// The calling thread's monitor record.
pub(crate) fn current_record() -> Option<u32> {
    record_of(current_thread())
}

/// Address of a record's debug data word (stock record +0x18).
pub(crate) const fn debug_data_of(record: u32) -> u32 {
    record + RECORD_DEBUG_DATA
}

/// Platform state of this domain.
pub struct Data {
    /// Name of the module under `target_bytes`, copied for the event.
    scratch: [u8; 0x800],
}

impl Data {
    pub const fn new() -> Self {
        Self {
            scratch: [0; 0x800],
        }
    }
}

impl debugger::Backend for Console {
    fn set_execution_state(&mut self, state: ExecutionState) {
        EXECUTION_STATE.store(execution_code(state), Ordering::Release);
    }

    fn suspend_threads(&mut self, process: ProcessKind) {
        let server = SERVER_THREAD.load(Ordering::Relaxed);
        for_each_thread(process, |thread_object| {
            let Some(record) = record_of(thread_object) else {
                return;
            };
            let flags = record_flags(record);
            if thread_object != server
                && flags & RECORD_DEBUGGABLE != 0
                && flags & RECORD_EXEMPT == 0
                && read_u32(record + 12) == 0
                && read_u32(record + 4) == 0
            {
                write_u32(record + 4, 1);
                // SAFETY: `for_each_thread` visits live thread objects under
                // the process lock.
                unsafe { KeSuspendThread(thread_object as usize as *mut Kthread) };
            }
        });
    }

    fn resume_threads(&mut self, process: ProcessKind) {
        let server = SERVER_THREAD.load(Ordering::Relaxed);
        for_each_thread(process, |thread_object| {
            let Some(record) = record_of(thread_object) else {
                return;
            };
            if thread_object != server
                && record_flags(record) & RECORD_DEBUGGABLE != 0
                && read_u32(record + 4) != 0
            {
                write_u32(record + 4, 0);
                // SAFETY: `for_each_thread` visits live thread objects under
                // the process lock.
                unsafe { KeResumeThread(thread_object as usize as *mut Kthread) };
            }
        });
    }

    fn monitor_suspend(&mut self, thread: ThreadId) {
        let Ok(reference) = ThreadRef::lookup(thread) else {
            return;
        };
        if let Some(record) = record_of(reference.0)
            && read_u32(record + 4) == 0
        {
            // SAFETY: `reference` holds a reference to the thread object.
            unsafe { KeSuspendThread(reference.0 as usize as *mut Kthread) };
            write_u32(record + 4, 1);
        }
    }

    fn thread_ids(&mut self, ids: &mut [ThreadId]) -> Option<usize> {
        debuggable_thread_ids(ids)
    }

    fn thread_info(&mut self, id: ThreadId) -> Result<ThreadInfo, NoSuchThread> {
        thread_information(id)
    }

    fn has_monitor_record(&mut self, thread: ThreadId) -> Result<bool, NoSuchThread> {
        let reference = ThreadRef::lookup(thread)?;
        Ok(record_of(reference.0).is_some())
    }

    fn suspend_thread(&mut self, thread: ThreadId) -> Result<(), NoSuchThread> {
        suspend(thread)
    }

    fn resume_thread(&mut self, thread: ThreadId) -> Result<(), NoSuchThread> {
        resume(thread)
    }

    fn thread_context(&mut self, thread: ThreadId, out: &mut Context) -> Result<(), NoSuchThread> {
        read_thread_context(thread, out)
    }

    fn set_thread_context(
        &mut self,
        thread: ThreadId,
        source: &Context,
    ) -> Result<(), StoppedThreadError> {
        write_thread_context(thread, source)
    }

    fn set_thread_name(&mut self, thread: ThreadId, address: u32) {
        name_thread(Some(thread), address);
    }

    fn thread_exit_status(&mut self, handle: ThreadHandle) -> Result<ExitStatus, KernelError> {
        let object_type =
            core::ptr::from_ref(kernel::resolved(&xboxkrnl::ExThreadObjectType)).addr() as u32;
        let mut object = 0u32;
        // SAFETY: `object` is a live local; the kernel validates the handle
        // against the thread object type.
        let status = unsafe {
            xboxkrnl::ObReferenceObjectByHandle(
                Handle::from_raw(handle.0),
                object_type,
                &mut object,
            )
        };
        status.result()?;
        let code = if read_u32(object + 4) & 0xff == 0 {
            ExitStatus::STILL_ACTIVE
        } else {
            ExitStatus(read_u32(object + thread::EXIT_STATUS))
        };
        // SAFETY: releases the reference taken above.
        unsafe { xboxkrnl::ObDereferenceObject(object) };
        Ok(code)
    }

    fn replace_code_word(&mut self, address: u32, value: u32) -> Option<u32> {
        let mut mapping = [0u32; 14];
        // SAFETY: `mapping` is a live local of the size the kernel fills.
        let mapped = unsafe { xboxkrnl::MmDbgWriteCheck(address, mapping.as_mut_ptr()) };
        if mapped == 0 {
            return None;
        }
        if is_excluded(mapped) {
            // SAFETY: `mapped` and `mapping` come from `MmDbgWriteCheck` above.
            unsafe { xboxkrnl::MmDbgReleaseAddress(mapped, mapping.as_mut_ptr()) };
            return None;
        }
        let previous = read_u32(mapped);
        write_u32(mapped, value);
        // SAFETY: `mapped` is the writable word mapped above; `mapped` and
        // `mapping` come from `MmDbgWriteCheck`.
        unsafe {
            xboxkrnl::KeSweepIcacheRange(mapped as usize as *mut u8, 4);
            xboxkrnl::MmDbgReleaseAddress(mapped, mapping.as_mut_ptr());
        }
        Some(previous)
    }

    fn target_bytes(&mut self, address: u32, length: usize) -> Option<&[u8]> {
        let length = length.min(self.debugger.scratch.len());
        for (offset, byte) in self.debugger.scratch[..length].iter_mut().enumerate() {
            let source = address.wrapping_add(offset as u32);
            if offset == 0 || source & 0xfff == 0 {
                if !readable(source) {
                    return None;
                }
            }
            *byte = read_u8(source);
        }
        Some(&self.debugger.scratch[..length])
    }

    fn set_data_breakpoint_register(&mut self, value: u32) {
        // SAFETY: the routine is this module's IPI entry, which takes the
        // register value as its argument.
        unsafe {
            KeIpiGenericCall(
                set_data_breakpoint_entry as *const () as usize as u32,
                value,
            )
        };
    }

    fn module_event(
        &mut self,
        name_string: u32,
        entry: u32,
        _thread: ThreadId,
    ) -> Option<ModuleEvent> {
        describe_module(name_string, entry)
    }

    fn next_event(&mut self) -> Option<DebugEvent> {
        for slot in &SLOTS {
            if slot
                .state
                .compare_exchange(
                    SLOT_POSTED,
                    SLOT_TAKEN,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                continue;
            }
            let thread = ThreadId(slot.thread_id.load(Ordering::Relaxed));
            let argument = slot.argument.load(Ordering::Relaxed);
            if slot.thread_object.load(Ordering::Relaxed) == 0 {
                let process = if argument != 0 {
                    ProcessKind::Title
                } else {
                    ProcessKind::System
                };
                return Some(match slot.kind.load(Ordering::Relaxed) {
                    KIND_CREATE => DebugEvent::ThreadCreate {
                        thread,
                        process,
                        start: slot.record.load(Ordering::Relaxed),
                        title_entry: slot.context.load(Ordering::Relaxed) != 0,
                    },
                    _ => DebugEvent::ThreadTerminate { thread, process },
                });
            }
            let thread_object = slot.thread_object.load(Ordering::Relaxed);
            let process = process_kind_of(thread_object);
            let has_record = record_of(thread_object).is_some();
            let debuggable = record_of(thread_object)
                .is_some_and(|record| record_flags(record) & RECORD_DEBUGGABLE != 0);
            let event = match slot.kind.load(Ordering::Relaxed) {
                KIND_CREATE => DebugEvent::ThreadCreate {
                    thread,
                    process,
                    start: read_u32(thread_object + thread::START_ADDRESS),
                    title_entry: read_u32(thread_object + thread::CREATE_FLAGS)
                        & THREAD_TITLE_ENTRY
                        != 0,
                },
                KIND_EXECUTION => DebugEvent::ExecutionRequest {
                    thread,
                    process,
                    target: execution_from_code(argument & 0xff),
                    notify: argument & 0x100 != 0,
                },
                KIND_TITLE_STOP => DebugEvent::PendingTitleStop {
                    thread,
                    process,
                    debuggable,
                    timeout: (argument == 0).then_some(TITLE_STOP_TIMEOUT_MS),
                },
                KIND_POGO => DebugEvent::PogoModuleStart {
                    thread,
                    process,
                    name: slot.record.load(Ordering::Relaxed),
                    module: slot.context.load(Ordering::Relaxed),
                },
                KIND_STACK_OVERFLOW => {
                    let record = slot.record.load(Ordering::Relaxed);
                    // Only threads that can stop are posted.
                    DebugEvent::StackOverflow {
                        thread,
                        process,
                        address: read_u32(record + 0xc),
                        record_address: record,
                        can_stop: true,
                    }
                }
                _ => DebugEvent::Exception {
                    thread,
                    process,
                    record: read_exception_record(slot.record.load(Ordering::Relaxed)),
                    second_chance: argument != 0,
                    has_record,
                    debuggable,
                },
            };
            return Some(event);
        }
        None
    }

    fn complete_event(&mut self, thread: ThreadId, disposition: Disposition) {
        let server = SERVER_THREAD.load(Ordering::Relaxed);
        if server != 0 && read_u32(server + thread::ID) == thread.0 {
            BREAK_NOW_STOPPED.store(false, Ordering::Release);
            return;
        }
        // Claimed before the disposition is written: a waiter released by
        // a stop reclaims its taken slot with the same exchange.
        let Some(slot) = SLOTS.iter().find(|slot| {
            slot.thread_id.load(Ordering::Relaxed) == thread.0
                && slot
                    .state
                    .compare_exchange(
                        SLOT_TAKEN,
                        SLOT_FILLING,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
        }) else {
            return;
        };
        if slot.thread_object.load(Ordering::Relaxed) == 0 {
            // Nobody waits on a detached event.
            slot.state.store(SLOT_FREE, Ordering::Release);
            return;
        }
        let mut bits = 0;
        if disposition.handled {
            bits |= DISPOSITION_HANDLED;
        }
        if disposition.write_dump {
            bits |= DISPOSITION_DUMP;
        }
        if disposition.chain_kernel_debugger {
            bits |= DISPOSITION_CHAIN;
        }
        if disposition.break_after {
            bits |= DISPOSITION_BREAK;
        }
        slot.disposition.store(bits, Ordering::Relaxed);
        slot.state.store(SLOT_COMPLETED, Ordering::Release);
        // SAFETY: `reset_event` built the slot event before the slot was posted.
        unsafe { xboxkrnl::KeSetEvent(slot.event().cast(), 1, false) };
    }

    fn publish_direct_policy(&mut self, policy: &DirectPolicy) {
        store_policy(policy);
    }

    fn next_direct_notification(
        &mut self,
        text: &mut [u8; NOTICE_TEXT_CAPACITY],
    ) -> Option<DirectNotification> {
        let lock = DIRECT_LOCK.as_ptr();
        // SAFETY: `lock` is the static direct notification spin lock.
        let irql = unsafe { xboxkrnl::KfAcquireSpinLock(lock.cast()) };
        let node = DIRECT_HEAD.load(Ordering::Relaxed);
        if node != 0 {
            let next = read_u32(node);
            DIRECT_HEAD.store(next, Ordering::Relaxed);
            if next == 0 {
                DIRECT_TAIL.store(0, Ordering::Relaxed);
            }
        }
        // SAFETY: the lock was acquired above at `irql`.
        unsafe { xboxkrnl::KfReleaseSpinLock(lock.cast(), irql) };
        if node == 0 {
            return None;
        }
        // SAFETY: `queue_direct` wrote the node and its text.
        let mut notification =
            unsafe { core::ptr::read(node as usize as *const DirectNode) }.notification;
        let header = core::mem::size_of::<DirectNode>() as u32;
        let length = notification.text_length.min(NOTICE_TEXT_CAPACITY);
        for (offset, byte) in text[..length].iter_mut().enumerate() {
            *byte = read_u8(node + header + offset as u32);
        }
        notification.text_length = length;
        // SAFETY: the node is a pool block `queue_direct` allocated and this
        // call unlinked.
        unsafe { xboxkrnl::ExFreePool(node) };
        Some(notification)
    }

    fn break_now(&mut self) -> Option<DebugEvent> {
        sleep(Duration::from_millis(250));
        BREAK_NOW_ARMED.store(true, Ordering::Release);
        // SAFETY: executes the breakpoint trap; the debug routine records it
        // and resumes after it.
        unsafe { core::arch::asm!("twi 31, 0, 0x16") };
        BREAK_NOW_ARMED.store(false, Ordering::Release);
        if !BREAK_NOW_STOPPED.load(Ordering::Acquire) {
            return None;
        }
        let thread_object = current_thread();
        Some(DebugEvent::Exception {
            thread: ThreadId(read_u32(thread_object + thread::ID)),
            process: ProcessKind::System,
            record: read_exception_record(BREAK_NOW.1.get() as usize as u32),
            second_chance: false,
            has_record: record_of(thread_object).is_some(),
            debuggable: false,
        })
    }

    fn crash_dump(&mut self) {
        sleep(Duration::from_millis(200));
        dump_calling_thread(0);
    }

    fn kernel_build(&mut self) -> u16 {
        kernel_version().build
    }

    fn load_extension(&mut self, path: &[u8]) -> Result<ExtensionHandle, KernelError> {
        let mut name = [0u8; 0x6c];
        let length = path.len().min(name.len() - 1);
        name[..length].copy_from_slice(&path[..length]);
        let mut handle = 0u32;
        // SAFETY: `name` is NUL-terminated and `handle` is a live local.
        let status = unsafe {
            xboxkrnl::XexLoadImage(
                name.as_ptr(),
                ImageFlags::SYSTEM_DEBUGGER | ImageFlags::DLL,
                ImageVersion::ANY,
                &mut handle,
            )
        };
        status.result()?;
        let export = |export_name: &core::ffi::CStr| {
            let mut address = 0u32;
            // Extensions export by name; the loader takes the name pointer
            // in place of an ordinal.
            // SAFETY: `handle` is the image loaded above, the name is
            // NUL-terminated, and `address` is a live local.
            unsafe {
                xboxkrnl::XexGetProcedureAddress(
                    handle,
                    export_name.as_ptr() as usize as u32,
                    &mut address,
                )
            };
            address
        };
        let on_load = export(c"OnLoad");
        let tell_debugger = export(c"OnTellDebugger");
        EXTENSION_PREPARE_TO_UNLOAD.store(export(c"PrepareToUnload"), Ordering::Release);
        if on_load != 0 {
            // SAFETY: the export was resolved from the loaded image and
            // takes no arguments.
            unsafe { kernel::call_export(on_load, 0, 0, 0, 0) };
        }
        EXTENSION_TELL_DEBUGGER.store(tell_debugger, Ordering::Release);
        Ok(ExtensionHandle(handle))
    }

    fn unload_extension(&mut self, handle: ExtensionHandle) -> Result<(), KernelError> {
        EXTENSION_TELL_DEBUGGER.store(0, Ordering::Release);
        while EXTENSION_CALLS.load(Ordering::Acquire) != 0 {
            sleep(Duration::from_millis(1));
        }
        let prepare = EXTENSION_PREPARE_TO_UNLOAD.swap(0, Ordering::AcqRel);
        if prepare != 0 {
            // SAFETY: the export was resolved from the loaded image and
            // takes no arguments.
            unsafe { kernel::call_export(prepare, 0, 0, 0, 0) };
        }
        // SAFETY: `handle` is the image `load_extension` loaded.
        unsafe { XexUnloadImage(handle.0) }.result()
    }
}
