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

use core::cell::UnsafeCell;
use core::ffi::CStr;
use core::ffi::c_char;
use core::num::NonZeroU32;
use core::ptr::NonNull;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU8;
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
use openxbdm_server::commands::debugger::ModuleFlags;
use openxbdm_server::commands::debugger::NOTICE_TEXT_CAPACITY;
use openxbdm_server::commands::debugger::NoSuchThread;
use openxbdm_server::commands::debugger::ProcessKind;
use openxbdm_server::commands::debugger::StopOn;
use openxbdm_server::commands::debugger::StoppedThreadError;
use openxbdm_server::commands::debugger::ThreadId;
use openxbdm_server::commands::debugger::ThreadInfo;
use openxbdm_server::commands::debugger::ThreadName;
use openxbdm_server::commands::debugger::dispatch_direct;
use openxbdm_server::commands::services::ThreadHandle;
use openxbdm_server::notify::ExecutionState;
use xbox360::console::hardware_flags;
use xbox360::console::kernel_version;
use xbox360::time::relative_interval;
use xbox360::time::sleep;
use xbox360_sys::image::ImageCharacteristics;
use xbox360_sys::image::ImageDirectory;
use xbox360_sys::processor;
use xbox360_sys::processor::Msr;
use xbox360_sys::processor::current_irql;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AnsiString;
use xbox360_sys::xboxkrnl::Context as KernelContext;
use xbox360_sys::xboxkrnl::ContextFlags as KernelContextFlags;
use xbox360_sys::xboxkrnl::DebugMonitorFlags;
use xbox360_sys::xboxkrnl::DumpWriteDump;
use xbox360_sys::xboxkrnl::EVENT_INCREMENT;
use xbox360_sys::xboxkrnl::EventType;
use xbox360_sys::xboxkrnl::ExRegisterThreadNotification;
use xbox360_sys::xboxkrnl::ExceptionFlags as KernelExceptionFlags;
use xbox360_sys::xboxkrnl::ExceptionRecord as KernelExceptionRecord;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::ImageFlags;
use xbox360_sys::xboxkrnl::ImageVersion;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeContextFromKframes;
use xbox360_sys::xboxkrnl::KeIpiGenericCall;
use xbox360_sys::xboxkrnl::KeResumeThread;
use xbox360_sys::xboxkrnl::KeSetSpecialPurposeRegister;
use xbox360_sys::xboxkrnl::KeSuspendThread;
use xbox360_sys::xboxkrnl::Kevent;
use xbox360_sys::xboxkrnl::Kprocess;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::KswitchFrame;
use xbox360_sys::xboxkrnl::Kthread;
use xbox360_sys::xboxkrnl::KtrapFrame;
use xbox360_sys::xboxkrnl::NotificationRegistration;
use xbox360_sys::xboxkrnl::ObLookupAnyThreadByThreadId;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::RtlCaptureContext;
use xbox360_sys::xboxkrnl::RtlImageDirectoryEntryToData;
use xbox360_sys::xboxkrnl::RtlImageNtHeader;
use xbox360_sys::xboxkrnl::SpecialPurposeRegister;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;
use xbox360_sys::xboxkrnl::XexUnloadImage;

use super::Console;
use super::dispatcher::ControlCode;
use super::dispatcher::Handoff;
use super::dispatcher::HandoffState;
use crate::kernel;
use crate::kernel::RoutineVariable;
use crate::kernel::address_of;
use crate::kernel::object_at;
use crate::kernel::thread_at;

pub(crate) use self::exports::apply_pending_stop_on;

/// Pool tag of monitor thread records ('Dmtd').
const RECORD_TAG: PoolTag = PoolTag::new(*b"dtmD");

/// Size of a PowerPC instruction.
const INSTRUCTION_SIZE: u32 = 4;

/// A byte of target memory.
///
/// # Safety
///
/// `address` must be mapped readable, as [`readable`] checks.
#[inline(always)]
unsafe fn target_u8(address: u32) -> u8 {
    // SAFETY: the caller guarantees a readable byte; other threads may
    // write it, so it is read atomically.
    unsafe { AtomicU8::from_ptr(core::ptr::with_exposed_provenance_mut(address as usize)) }
        .load(Ordering::Relaxed)
}

/// The length of an `ANSI_STRING`, read as stock reads it: one word load
/// of the first word, whose high half (big-endian) holds the length. The
/// load is atomic so that it is not narrowed to a halfword load.
#[inline(always)]
pub(crate) fn ansi_string_length(string: &AnsiString) -> u16 {
    // SAFETY: the string starts with the two halfwords of an aligned word
    // that nothing writes while the reference lives.
    let word = unsafe { AtomicU32::from_ptr(core::ptr::from_ref(string).cast::<u32>().cast_mut()) };
    (word.load(Ordering::Relaxed) >> 16) as u16
}

/// The thread object of the calling thread.
#[inline(always)]
fn current() -> &'static Kthread {
    xbox360::thread::current_object().kthread()
}

/// The thread object as kernel thread calls take it.
#[inline(always)]
fn thread_pointer(thread: &Kthread) -> *mut Kthread {
    core::ptr::from_ref(thread).cast_mut()
}

fn is_server(thread: &Kthread) -> bool {
    address_of(thread) == SERVER_THREAD.load(Ordering::Relaxed)
}

/// Pool of the blocks the monitor allocates for a thread.
fn pool_type_of(thread: &Kthread) -> PoolType {
    let process_type = ProcessType(u32::from(
        thread.current_process_type.load(Ordering::Relaxed),
    ));
    if process_type == ProcessType::SYSTEM {
        PoolType::System
    } else {
        PoolType::Title
    }
}

xbox360_sys::flags! {
    /// Flags of a monitor thread record.
    pub struct MonitorRecordFlags(u32) {
        /// Set with [`Self::EXEMPT`] by the PIX capture pause, as stock sets
        /// it there. No monitor code tests it; its stock meaning is
        /// unknown.
        CAPTURE_PAUSE = 0x1000,
        /// The thread is under debugger control.
        DEBUGGABLE = 0x2000,
        /// Execution stops do not suspend the thread.
        EXEMPT = 0x0200_0000,
    }
}

/// Per-thread monitor record, referenced from [`Kthread::debug_data`].
/// Other threads read and change it under the process thread list lock.
/// Only `thread_notification` frees it, on the thread itself as the thread
/// ends, after it cleared the word under that lock; a thread ends only by
/// itself. So a record stays allocated while the process lock is held, for
/// code on its own thread, and while its thread waits in a slot.
#[repr(C)]
struct MonitorRecord {
    /// [`MonitorRecordFlags`].
    flags: AtomicU32,
    /// Nonzero while the monitor holds a suspension of the thread.
    monitor_suspended: AtomicU32,
    /// Pool copy of the thread name, or 0.
    name: AtomicU32,
    /// Index plus one of the slot the thread waits in, or 0.
    slot: AtomicU32,
    /// Word owned by the thread; export 49 hands out its address.
    debug_data: AtomicU32,
}

const _: () = assert!(core::mem::offset_of!(MonitorRecord, debug_data) == 0x10);

impl MonitorRecord {
    #[inline(always)]
    fn flags(&self) -> MonitorRecordFlags {
        MonitorRecordFlags::from_bits_retain(self.flags.load(Ordering::Relaxed))
    }

    #[inline(always)]
    fn set_flags(&self, flags: MonitorRecordFlags) {
        self.flags.store(flags.bits(), Ordering::Relaxed);
    }

    #[inline(always)]
    fn is_debuggable(&self) -> bool {
        self.flags().contains(MonitorRecordFlags::DEBUGGABLE)
    }

    #[inline(always)]
    fn is_monitor_suspended(&self) -> bool {
        self.monitor_suspended.load(Ordering::Relaxed) != 0
    }

    #[inline(always)]
    fn waits_in_slot(&self) -> bool {
        self.slot.load(Ordering::Relaxed) != 0
    }

    /// Address of the pool copy of the thread name.
    #[inline(always)]
    fn name(&self) -> Option<u32> {
        Some(self.name.load(Ordering::Relaxed)).filter(|&name| name != 0)
    }
}

/// Whether `thread` has a monitor record. Only the thread's word is read.
#[inline(always)]
fn has_record(thread: &Kthread) -> bool {
    thread.debug_data.load(Ordering::Relaxed) != 0
}

/// The monitor record of `thread`.
///
/// # Safety
///
/// The record must stay allocated while the result is used, as
/// [`MonitorRecord`] states: the process lock is held, or `thread` does not
/// end in that time (it is the calling thread or waits in a slot).
unsafe fn record_of<'a>(thread: &'a Kthread) -> Option<&'a MonitorRecord> {
    let record = thread.debug_data.load(Ordering::Relaxed);
    if record == 0 {
        return None;
    }
    // SAFETY: the word holds 0 or a record `create_record` allocated for
    // this thread; the caller keeps it allocated.
    Some(unsafe { object_at(record) })
}

/// The monitor record of `thread`, created when it has none (stock
/// 0x91f31028).
///
/// # Safety
///
/// As [`record_of`].
unsafe fn create_record<'a>(thread: &'a Kthread) -> Option<&'a MonitorRecord> {
    // SAFETY: the caller's contract.
    if let Some(record) = unsafe { record_of(thread) } {
        return Some(record);
    }
    // SAFETY: pool allocation has no pointer arguments.
    let address = unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(
            core::mem::size_of::<MonitorRecord>() as u32,
            RECORD_TAG,
            pool_type_of(thread),
        )
    };
    let record = NonNull::new(core::ptr::with_exposed_provenance_mut::<MonitorRecord>(
        address as usize,
    ))?;
    let creation = thread.creation_flags;
    let mut flags = MonitorRecordFlags::empty();
    if !creation.contains(ThreadCreationFlags::NOT_DEBUGGABLE) {
        flags |= MonitorRecordFlags::DEBUGGABLE;
    }
    if creation.contains(ThreadCreationFlags::EXEMPT_FROM_STOPS) {
        flags |= MonitorRecordFlags::EXEMPT;
    }
    // SAFETY: the pool block is sized and aligned for a record, and only
    // this call reaches it until the store below publishes it.
    unsafe {
        record.write(MonitorRecord {
            flags: AtomicU32::new(flags.bits()),
            monitor_suspended: AtomicU32::new(0),
            name: AtomicU32::new(0),
            slot: AtomicU32::new(0),
            debug_data: AtomicU32::new(0),
        })
    };
    // The fields are stored before the record is published.
    core::sync::atomic::compiler_fence(Ordering::Release);
    thread.debug_data.store(address, Ordering::Relaxed);
    // SAFETY: initialized above; the caller keeps it allocated.
    Some(unsafe { record.as_ref() })
}

/// The object of the calling thread. Its monitor record stays allocated
/// while code on the thread holds it, as [`MonitorRecord`] states; a
/// [`Kthread`] reference is not `Send`, so neither is this.
#[derive(Clone, Copy)]
struct OwnThread(&'static Kthread);

impl OwnThread {
    #[inline(always)]
    fn current() -> Self {
        Self(current())
    }

    /// # Safety
    ///
    /// `thread` must be the object of the calling thread.
    #[inline(always)]
    unsafe fn from_kthread(thread: &'static Kthread) -> Self {
        Self(thread)
    }

    #[inline(always)]
    fn kthread(&self) -> &'static Kthread {
        self.0
    }

    #[inline(always)]
    fn record(&self) -> Option<&MonitorRecord> {
        // SAFETY: the record of the calling thread, held by code on it.
        unsafe { record_of(self.0) }
    }

    #[inline(always)]
    fn create_record(&self) -> Option<&MonitorRecord> {
        // SAFETY: as in `record`.
        unsafe { create_record(self.0) }
    }
}

/// The process object addresses published in the debug monitor data
/// (stock reads +0x50 and +0x54 of its copy as the objects themselves).
fn process_address(kind: ProcessKind) -> u32 {
    let data = kernel::debug_monitor_data();
    match kind {
        ProcessKind::Title => data.title_process.load(Ordering::Relaxed),
        ProcessKind::System => data.system_process.load(Ordering::Relaxed),
    }
}

fn process_of(kind: ProcessKind) -> Option<&'static Kprocess> {
    let address = process_address(kind);
    // SAFETY: the query service stores the addresses of the kernel's
    // process objects, which live as long as the system, or leaves 0.
    unsafe { core::ptr::with_exposed_provenance::<Kprocess>(address as usize).as_ref() }
}

/// The process that owns `thread`.
fn owning_process(thread: &Kthread) -> &Kprocess {
    // SAFETY: a thread object holds the address of its process object,
    // which outlives the thread.
    unsafe { object_at(thread.process) }
}

fn process_kind_of(thread: &Kthread) -> ProcessKind {
    let process = thread.process;
    if process != 0 && process == process_address(ProcessKind::Title) {
        ProcessKind::Title
    } else {
        ProcessKind::System
    }
}

/// The thread list lock of a process, held until dropped. It is taken only
/// for the process that owns the threads whose records are read through
/// it.
struct ThreadListLock<'a> {
    process: &'a Kprocess,
    irql: Irql,
}

impl<'a> ThreadListLock<'a> {
    #[inline(always)]
    fn acquire(process: &'a Kprocess) -> Self {
        // SAFETY: the lock is the process's thread list spin lock.
        let irql = unsafe { xboxkrnl::KfAcquireSpinLock(process.thread_list_lock.as_ptr()) };
        Self { process, irql }
    }

    /// The record of `thread`, a thread of the locked process.
    #[inline(always)]
    fn record<'b>(&'b self, thread: &'b Kthread) -> Option<&'b MonitorRecord> {
        // SAFETY: the lock of the thread's process is held while the
        // result borrows it.
        unsafe { record_of(thread) }
    }

    /// [`Self::record`], created when the thread has none.
    #[inline(always)]
    fn create_record<'b>(&'b self, thread: &'b Kthread) -> Option<&'b MonitorRecord> {
        // SAFETY: as in `record`.
        unsafe { create_record(thread) }
    }
}

impl Drop for ThreadListLock<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: `acquire` took the lock at `irql`.
        unsafe { xboxkrnl::KfReleaseSpinLock(self.process.thread_list_lock.as_ptr(), self.irql) };
    }
}

/// Offset of the thread list link in a thread object.
const THREAD_LIST_ENTRY: u32 = core::mem::offset_of!(Kthread, thread_list_entry) as u32;

/// Call `visit` with each thread object of `kind` under the process lock.
fn for_each_thread(kind: ProcessKind, mut visit: impl FnMut(&ThreadListLock<'_>, &Kthread)) {
    let Some(process) = process_of(kind) else {
        return;
    };
    let lock = ThreadListLock::acquire(process);
    let head = address_of(&process.thread_list);
    let mut entry = process.thread_list.flink.load(Ordering::Relaxed);
    while entry != head && entry != 0 {
        // SAFETY: under the thread list lock each link of the list is the
        // thread list entry of a live thread object of the process.
        let thread = unsafe { thread_at(entry - THREAD_LIST_ENTRY) };
        let next = thread.thread_list_entry.flink.load(Ordering::Relaxed);
        visit(&lock, thread);
        entry = next;
    }
}

/// A referenced thread object.
struct ThreadRef(NonNull<Kthread>);

impl ThreadRef {
    fn lookup(id: ThreadId) -> Result<Self, NoSuchThread> {
        let mut object = core::ptr::null_mut();
        // SAFETY: `object` is a live local that receives the thread pointer.
        let status = unsafe { ObLookupAnyThreadByThreadId(id.0, &mut object) };
        if !status.is_success() {
            return Err(NoSuchThread);
        }
        // SAFETY: a successful lookup stores a referenced thread object.
        Ok(Self(unsafe { NonNull::new_unchecked(object) }))
    }

    fn by_handle(handle: ThreadHandle) -> Result<Self, KernelError> {
        // SAFETY: `data_imports_resolved` held at module load.
        let object_type = address_of(unsafe { xboxkrnl::ExThreadObjectType.get_unchecked() });
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
        // SAFETY: a successful reference stores the referenced object.
        Ok(Self(unsafe {
            NonNull::new_unchecked(core::ptr::with_exposed_provenance_mut(object as usize))
        }))
    }

    #[inline(always)]
    fn thread(&self) -> &Kthread {
        // SAFETY: the reference keeps the object allocated while held.
        unsafe { self.0.as_ref() }
    }
}

impl Drop for ThreadRef {
    fn drop(&mut self) {
        // SAFETY: `lookup` or `by_handle` took the reference this releases.
        unsafe { xboxkrnl::ObDereferenceObject(self.0.as_ptr().expose_provenance() as u32) };
    }
}

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

/// [`SlotEventKind::Execution`] argument bits of the execution code.
const EXECUTION_CODE_MASK: u32 = 0xff;
/// [`SlotEventKind::Execution`] argument bit: send the `execution` line.
const EXECUTION_NOTIFY: u32 = 0x100;

/// Title launch wait before the monitor starts execution itself (stock
/// 0x91f523a0).
const TITLE_STOP_TIMEOUT_MS: u32 = 15_000;

xbox360_sys::flags! {
    /// Disposition the server returns to a thread waiting in a slot.
    pub struct SlotDisposition(u32) {
        HANDLED = 0x1,
        DUMP = 0x2,
        CHAIN = 0x4,
        BREAK = 0x8,
    }
}

const SLOT_COUNT: usize = 16;

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
struct Slot {
    state: Handoff,
    /// [`SlotEventKind`].
    kind: AtomicU32,
    thread_object: AtomicU32,
    thread_id: AtomicU32,
    record: AtomicU32,
    context: AtomicU32,
    /// Second chance of an exception, or the kind's argument.
    argument: AtomicU32,
    /// [`SlotDisposition`].
    disposition: AtomicU32,
    /// Synchronization event the thread waits on.
    event: SlotEvent,
}

impl Slot {
    const fn new() -> Self {
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
    fn kind(&self) -> Option<SlotEventKind> {
        SlotEventKind::from_raw(self.kind.load(Ordering::Relaxed))
    }
}

static SLOTS: [Slot; SLOT_COUNT] = [const { Slot::new() }; SLOT_COUNT];
/// Debug routine the kernel had before the hook.
static PREVIOUS_DEBUG_ROUTINE: AtomicU32 = AtomicU32::new(0);
/// Thread object of the server thread, which must never wait in a slot.
static SERVER_THREAD: AtomicU32 = AtomicU32::new(0);
/// Thread notification registration, priority 0. The kernel uses all 0x10
/// bytes of the record.
static THREAD_NOTIFICATION: NotificationRegistration = NotificationRegistration::new();
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

/// Current execution state.
pub(crate) fn execution_state() -> ExecutionState {
    execution_from_code(EXECUTION_STATE.load(Ordering::Acquire))
}

/// The server thread takes slot events in its passes. Until then, and once
/// it stops, threads take the monitor's default disposition instead of
/// waiting.
static EVENTS_SERVED: AtomicBool = AtomicBool::new(false);
/// Threads inside `post_and_wait`; unload waits for them to leave.
static WAITERS: AtomicU32 = AtomicU32::new(0);
/// Interval at which a waiting thread checks whether the server stopped.
const STOP_CHECK_INTERVAL: i64 = relative_interval(Duration::from_millis(100));

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
/// addresses the server reads and writes while the thread waits.
fn post_and_wait(
    kind: SlotEventKind,
    own: OwnThread,
    record: u32,
    context: u32,
    argument: u32,
) -> Option<SlotDisposition> {
    WAITERS.fetch_add(1, Ordering::AcqRel);
    let disposition = post_and_wait_served(kind, own, record, context, argument);
    WAITERS.fetch_sub(1, Ordering::AcqRel);
    disposition
}

fn post_and_wait_served(
    kind: SlotEventKind,
    own: OwnThread,
    record: u32,
    context: u32,
    argument: u32,
) -> Option<SlotDisposition> {
    let thread = own.kthread();
    let (slot_index, slot) = claim_slot()?;
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
    let disposition = loop {
        if slot.state.is(HandoffState::Completed, Ordering::Acquire) {
            break Some(SlotDisposition::from_bits_retain(
                slot.disposition.load(Ordering::Relaxed),
            ));
        }
        // A slot the server has not completed is reclaimed once it stops;
        // completion claims the slot first, so exactly one side wins.
        if !EVENTS_SERVED.load(Ordering::Acquire)
            && (slot.state.transition(
                HandoffState::Posted,
                HandoffState::Filling,
                Ordering::AcqRel,
            ) || slot.state.transition(
                HandoffState::Taken,
                HandoffState::Filling,
                Ordering::AcqRel,
            ))
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

/// Take a free slot while the server takes events.
fn claim_slot() -> Option<(usize, &'static Slot)> {
    loop {
        if !EVENTS_SERVED.load(Ordering::Acquire) {
            return None;
        }
        if let Some(index) = SLOTS.iter().position(|slot| {
            slot.state
                .transition(HandoffState::Free, HandoffState::Filling, Ordering::Acquire)
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
fn post_detached(kind: SlotEventKind, thread: &Kthread) {
    WAITERS.fetch_add(1, Ordering::AcqRel);
    if let Some((_, slot)) = claim_slot() {
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

/// Mark the data block as writing a crash dump, as stock does before each
/// dump; returns the updated flags.
fn mark_dump() -> DebugMonitorFlags {
    let data = kernel::debug_monitor_data();
    let flags = DebugMonitorFlags::from_bits_retain(data.flags.load(Ordering::Relaxed))
        | DebugMonitorFlags::DUMP;
    data.flags.store(flags.bits(), Ordering::Release);
    flags
}

/// Write a crash dump of an exception; the kernel's bug check flag selects
/// the dump kind.
fn write_dump(record: &KernelExceptionRecord, context: &KernelContext) {
    let kind = if mark_dump().contains(DebugMonitorFlags::BUG_CHECK) {
        DumpKind::BugCheck
    } else {
        DumpKind::Default
    };
    // SAFETY: both are the live exception record and context of the
    // exception.
    unsafe { DumpWriteDump(address_of(record), address_of(context), kind as u32) };
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
    // SAFETY: the kernel passes the exception record of the calling
    // thread, live for the call; the monitor only reads it.
    let exception = unsafe { object_at::<KernelExceptionRecord>(record) };
    // The server writes the context while the thread waits in a slot and
    // the previous debug routine may write it in `chain`, so it is
    // borrowed only around each use below, never across those.
    let registers = core::ptr::with_exposed_provenance_mut::<KernelContext>(context as usize);
    let own = OwnThread::current();
    let thread = own.kthread();
    let irql = current_irql();
    let server = is_server(thread);
    if server
        && irql == Irql::PASSIVE
        && exception.code == NtStatus::BREAKPOINT
        && BREAK_NOW_ARMED.swap(false, Ordering::AcqRel)
    {
        // SAFETY: the kernel's context of the calling thread, live for the
        // call; neither a slot nor `chain` reaches it on this path.
        capture_break_now(exception, unsafe { &mut *registers });
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
        // SAFETY: the kernel's record and context of the calling thread,
        // live for the call; no slot holds them on this path.
        return unsafe {
            dispatch_in_place(
                thread,
                exception,
                registers,
                second_chance != 0,
                delivery,
                &chain,
            )
        };
    }
    if own.record().is_some_and(MonitorRecord::waits_in_slot) {
        // A nested exception while the thread waits in a slot.
        return chain();
    }
    let Some(disposition) = post_and_wait(
        SlotEventKind::Exception,
        own,
        record,
        context,
        second_chance,
    ) else {
        // SAFETY: as above; the thread did not post to a slot.
        return unsafe {
            dispatch_in_place(
                thread,
                exception,
                registers,
                second_chance != 0,
                Delivery::Deferred,
                &chain,
            )
        };
    };
    let mut handled = disposition.contains(SlotDisposition::HANDLED);
    if disposition.contains(SlotDisposition::DUMP) {
        // SAFETY: the kernel's context of the calling thread; the slot was
        // released and `chain` runs after this borrow ends.
        write_dump(exception, unsafe { &*registers });
    }
    if disposition.contains(SlotDisposition::CHAIN) {
        handled = chain() & 0xff != 0;
    }
    u32::from(handled)
}

/// Bytes `RtlCaptureContext` and `KeContextFromKframes` may write: the
/// kernel context and 0x10 more.
const CONTEXT_STORAGE_SIZE: usize = 0xa50;

/// Context block the kernel fills.
#[repr(C, align(16))]
struct ContextStorage {
    context: KernelContext,
    _tail: [u8; CONTEXT_STORAGE_SIZE - core::mem::size_of::<KernelContext>()],
}

const _: () = assert!(core::mem::size_of::<ContextStorage>() == CONTEXT_STORAGE_SIZE);

impl ContextStorage {
    const fn new(flags: KernelContextFlags) -> Self {
        Self {
            context: KernelContext::new(flags),
            _tail: [0; CONTEXT_STORAGE_SIZE - core::mem::size_of::<KernelContext>()],
        }
    }

    #[inline(always)]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        core::ptr::from_mut(self).cast()
    }
}

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
extern "C" fn stack_overflow(frame_address: u32) -> u32 {
    // SAFETY: the kernel passes the trap frame of the overflowing thread,
    // live for the call.
    let frame = unsafe { object_at::<KtrapFrame>(frame_address) };
    let address = frame.iar;
    // SAFETY: the kernel calls only after `install` stored this routine in
    // the variable whose address the query service published.
    let variable =
        unsafe { kernel::routine_variable(RoutineVariable::StackOverflow).unwrap_unchecked() };
    // SAFETY: `KernelU32` is a transparent `AtomicU32`; storing 0 unhooks
    // the notification, which the kernel accepts.
    let hooked =
        unsafe { &*core::ptr::from_ref(variable).cast::<AtomicU32>() }.swap(0, Ordering::AcqRel);
    let policy = load_policy();
    if hooked == 0
        || (policy.kernel_debugger && hardware_flags().contains(HardwareFlags::KERNEL_DEBUGGER))
    {
        return address;
    }
    let own = OwnThread::current();
    let can_stop = own.record().is_some_and(MonitorRecord::is_debuggable)
        && current_irql() == Irql::PASSIVE
        && !frame.msr.is_empty()
        && (policy.dump_mode != DumpMode::Enabled || policy.attached);
    if !can_stop && policy.dump_mode == DumpMode::Disabled {
        return address;
    }
    let mut context = ContextStorage::new(KernelContextFlags::FULL);
    // SAFETY: `frame_address` is the trap frame the kernel passed;
    // `context` is a live local of the size the kernel writes.
    unsafe { KeContextFromKframes(frame_address, context.as_mut_ptr()) };
    let record = KernelExceptionRecord {
        code: NtStatus::STACK_OVERFLOW,
        flags: KernelExceptionFlags::NONCONTINUABLE,
        next_record: 0,
        address,
        parameter_count: 0,
        parameters: [0; 15],
    };
    let record_address = address_of(&record);
    let context_address = core::ptr::from_mut(&mut context.context).expose_provenance() as u32;
    let dump = if can_stop {
        // SAFETY: the kernel calls with interrupts off and the thread must
        // wait.
        unsafe { processor::enable_interrupts() };
        loop {
            let Some(disposition) = post_and_wait(
                SlotEventKind::StackOverflow,
                own,
                record_address,
                context_address,
                0,
            ) else {
                // As for a thread that cannot stop.
                break policy.dump_mode != DumpMode::Disabled;
            };
            if !disposition.contains(SlotDisposition::HANDLED) {
                break disposition.contains(SlotDisposition::DUMP);
            }
        }
    } else {
        true
    };
    if dump {
        // Stock passes the default dump kind here, whatever the data block
        // flags.
        mark_dump();
        // SAFETY: both addresses refer to the live locals filled above.
        unsafe { DumpWriteDump(record_address, context_address, DumpKind::Default as u32) };
    }
    address
}

/// The server's copy of a kernel exception record.
fn exception_record(record: &KernelExceptionRecord) -> ExceptionRecord {
    ExceptionRecord {
        code: record.code,
        flags: ExceptionFlags::from_bits_retain(record.flags.bits()),
        address: record.address,
        parameter_count: record.parameter_count,
        parameters: core::array::from_fn(|n| record.parameters[n]),
        record_address: address_of(record),
    }
}

/// The monitor's dispatch on a thread that cannot wait for the server.
///
/// # Safety
///
/// `record` and `context` must be the live exception record and context
/// of the calling thread, which nothing else accesses during the call
/// except `chain`.
unsafe fn dispatch_in_place(
    thread: &Kthread,
    record: *const KernelExceptionRecord,
    context: *mut KernelContext,
    second_chance: bool,
    delivery: Delivery,
    chain: &dyn Fn() -> u32,
) -> u32 {
    // The borrows end before `chain`, which hands the same record and
    // context to the previous debug routine.
    // SAFETY: the caller guarantees both objects.
    let disposition =
        unsafe { direct_dispatch(thread, &*record, &mut *context, delivery, second_chance) };
    let mut handled = disposition.handled;
    if disposition.chain_kernel_debugger {
        handled = chain() & 0xff != 0;
    }
    u32::from(handled)
}

/// Dispatch an exception in place, without the kernel debugger chain.
fn direct_dispatch(
    thread: &Kthread,
    record: &KernelExceptionRecord,
    context: &mut KernelContext,
    delivery: Delivery,
    second_chance: bool,
) -> Disposition {
    let policy = load_policy();
    let mut registers = DirectRegisters {
        msr: context.msr,
        iar: context.iar,
        gpr3: context.gpr[3],
        gpr4: context.gpr[4],
    };
    let iar = registers.iar;
    let thread_id = ThreadId(thread.id);
    let event = DirectException {
        thread: thread_id,
        record: exception_record(record),
        second_chance,
        has_record: has_record(thread),
        hardware_flags: hardware_flags(),
        delivery,
    };
    // SAFETY: `readable` found the instruction word mapped; instruction
    // addresses are word-aligned.
    let instruction = readable(iar).then(|| {
        unsafe { AtomicU32::from_ptr(core::ptr::with_exposed_provenance_mut(iar as usize)) }
            .load(Ordering::Relaxed)
    });
    let mut step = StepWord::decode(DIRECT_STEP.swap(StepWord::Idle as u32, Ordering::AcqRel));
    let outcome = dispatch_direct(&policy, &event, &mut registers, instruction, &mut step);
    DIRECT_STEP.store(StepWord::encode(step), Ordering::Release);
    context.msr = registers.msr;
    context.iar = registers.iar;
    context.gpr[3] = registers.gpr3;
    context.gpr[4] = registers.gpr4;
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
        // SAFETY: the address is the name parameter of the thread-name
        // exception the calling thread raised, live while it runs here. The
        // named thread may be another one that ends during the call; stock
        // names it without the process lock and the monitor keeps that
        // race.
        unsafe { name_thread(Some(request.thread), request.address) };
    }
    if let Some(notice) = outcome.notice
        && delivery != Delivery::Discarded
    {
        queue_direct(thread_id, iar, outcome.record, notice);
    }
    if outcome.disposition.write_dump {
        write_dump(record, context);
    }
    outcome.disposition
}

crate::exports::bridged!(thread_notification_entry, thread_notification);

/// Thread creation and termination routine (stock 0x91f32530).
extern "C" fn thread_notification(_registration: u32, thread_object: u32, create: u32) -> u32 {
    // SAFETY: the kernel passes the live thread object it notifies about,
    // which stays allocated for the call.
    let thread = unsafe { thread_at(thread_object) };
    // SAFETY: the kernel calls the routine on the thread it notifies about:
    // the new thread at its start and the ending thread at its end.
    let own = unsafe { OwnThread::from_kthread(thread) };
    if create == 0 {
        // SAFETY: enters a critical region of the calling thread, left
        // below.
        unsafe { xboxkrnl::KeEnterCriticalRegion() };
        let lock = ThreadListLock::acquire(owning_process(thread));
        let record = own.record();
        let mut debuggable = false;
        if let Some(record) = record {
            thread.debug_data.store(0, Ordering::Relaxed);
            debuggable = record.is_debuggable();
            if record.is_monitor_suspended() {
                // SAFETY: `thread` is the live thread object the kernel
                // passed.
                unsafe { KeResumeThread(thread_pointer(thread)) };
            }
        }
        drop(lock);
        if debuggable && !is_server(thread) {
            post_detached(SlotEventKind::Terminate, thread);
        }
        if let Some(record) = record {
            let name = record.name();
            // SAFETY: the record and its name are pool blocks this module
            // allocated; the record was detached above.
            unsafe {
                if let Some(name) = name {
                    xboxkrnl::ExFreePool(name);
                }
                xboxkrnl::ExFreePool(address_of(record));
            }
        }
        crate::backend::performance::pix::thread_terminated();
        // SAFETY: leaves the critical region entered above.
        unsafe { xboxkrnl::KeLeaveCriticalRegion() };
        return 0;
    }
    match own.create_record() {
        Some(record) if record.is_debuggable() => {
            // Stock waits only when the thread may stop (0x91f39b30): with
            // `stopon createthread`, or a title entry that may break.
            let title_entry = thread
                .creation_flags
                .contains(ThreadCreationFlags::TITLE_ENTRY);
            if !title_entry && !load_policy().stop_on.contains(StopOn::CREATE_THREAD) {
                post_detached(SlotEventKind::Create, thread);
                return 0;
            }
            let disposition = post_and_wait(SlotEventKind::Create, own, 0, 0, 0);
            if disposition.is_some_and(|disposition| disposition.contains(SlotDisposition::BREAK)) {
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
    if let Some(variable) = kernel::routine_variable(RoutineVariable::Debug)
        && PREVIOUS_DEBUG_ROUTINE.load(Ordering::Relaxed) == 0
    {
        PREVIOUS_DEBUG_ROUTINE.store(variable.load(Ordering::Relaxed), Ordering::Release);
        // SAFETY: the entry is a debug routine of the kernel's form that
        // chains to the previous one.
        unsafe {
            variable.store(
                debug_routine_entry as *const () as usize as u32,
                Ordering::Relaxed,
            );
        }
    }
    if let Some(variable) = kernel::routine_variable(RoutineVariable::StackOverflow) {
        // SAFETY: the entry is a stack overflow notification of the
        // kernel's form.
        unsafe {
            variable.store(
                stack_overflow_entry as *const () as usize as u32,
                Ordering::Relaxed,
            );
        }
    }
    // SAFETY: the record is not registered yet; the routine is the bridged
    // entry of `thread_notification`, which takes the arguments of a thread
    // notification routine.
    unsafe {
        THREAD_NOTIFICATION.routine.store(
            thread_notification_entry as *const () as usize as u32,
            Ordering::Relaxed,
        )
    };
    // SAFETY: the registration block is static and stays registered until
    // `uninstall`.
    unsafe { ExRegisterThreadNotification(THREAD_NOTIFICATION.as_ptr(), true) };
}

/// Undo [`install`] before the image unloads.
pub(crate) fn uninstall() {
    if THREAD_NOTIFICATION.routine.load(Ordering::Relaxed) != 0 {
        // SAFETY: `install` registered this static block.
        unsafe { ExRegisterThreadNotification(THREAD_NOTIFICATION.as_ptr(), false) };
        // SAFETY: the record is no longer registered.
        unsafe { THREAD_NOTIFICATION.routine.store(0, Ordering::Relaxed) };
    }
    if let Some(variable) = kernel::routine_variable(RoutineVariable::StackOverflow) {
        // SAFETY: `KernelU32` is a transparent `AtomicU32`; the exchange
        // stores only 0, which unhooks the notification.
        let variable = unsafe { &*core::ptr::from_ref(variable).cast::<AtomicU32>() };
        let _ = variable.compare_exchange(
            stack_overflow_entry as *const () as usize as u32,
            0,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
    if let Some(variable) = kernel::routine_variable(RoutineVariable::Debug)
        && variable.load(Ordering::Relaxed) == debug_routine_entry as *const () as usize as u32
    {
        // SAFETY: the stored value is the routine the kernel had before
        // `install`.
        unsafe {
            variable.store(
                PREVIOUS_DEBUG_ROUTINE.swap(0, Ordering::AcqRel),
                Ordering::Relaxed,
            );
        }
    }
}

/// Record the server thread; it never waits for its own events. Its
/// monitor record is exempt and not debuggable, as stock's command thread
/// (0x91f50cb0) marks its own.
pub(crate) fn set_server_thread() {
    let own = OwnThread::current();
    SERVER_THREAD.store(address_of(own.kthread()), Ordering::Relaxed);
    if let Some(record) = own.create_record() {
        record.set_flags(
            record
                .flags()
                .union(MonitorRecordFlags::EXEMPT)
                .difference(MonitorRecordFlags::DEBUGGABLE),
        );
    }
}

xbox360_sys::flags! {
    /// Flags word of a published policy copy.
    pub struct PolicyFlags(u32) {
        KD_LITE = 0x1,
        KERNEL_DEBUGGER = 0x2,
        TRAP_PASSTHROUGH = 0x4,
        DUMP_IN_PROGRESS = 0x8,
        ATTACHED = 0x10,
        DATA_BREAKPOINT = 0x20,
    }
}

/// Words of a published policy copy.
mod policy_word {
    /// [`super::PolicyFlags`].
    pub(super) const FLAGS: usize = 0;
    pub(super) const DUMP_MODE: usize = 1;
    pub(super) const DEFER_MASK: usize = 2;
    pub(super) const STOP_ON: usize = 3;
    pub(super) const DATA_ADDRESS: usize = 4;
    pub(super) const DATA_SIZE: usize = 5;
    pub(super) const DATA_KIND: usize = 6;
    pub(super) const COUNT: usize = 7;
}

/// Two copies of the published policy; `POLICY_SEQUENCE` selects the
/// current one. The server thread writes the other copy before switching,
/// so a reader at raised level never waits on the writer.
static POLICY: [[AtomicU32; policy_word::COUNT]; 2] =
    [const { [const { AtomicU32::new(0) }; policy_word::COUNT] }; 2];
static POLICY_SEQUENCE: AtomicU32 = AtomicU32::new(0);
/// Step over the data breakpoint begun in place, as a [`StepWord`].
static DIRECT_STEP: AtomicU32 = AtomicU32::new(StepWord::Idle as u32);

/// Encoding of an in-place [`DirectStep`] in [`DIRECT_STEP`].
#[repr(u32)]
#[derive(Clone, Copy)]
enum StepWord {
    /// No step.
    Idle = 0,
    /// A step; trace was off before it.
    Step = 1,
    /// A step; trace was on before it.
    TracedStep = 2,
}

impl StepWord {
    #[inline(always)]
    fn decode(word: u32) -> Option<DirectStep> {
        (word != Self::Idle as u32).then_some(DirectStep {
            saved_trace: word == Self::TracedStep as u32,
        })
    }

    #[inline(always)]
    fn encode(step: Option<DirectStep>) -> u32 {
        const { assert!(StepWord::TracedStep as u32 == StepWord::Step as u32 + 1) };
        step.map_or(Self::Idle as u32, |step| {
            Self::Step as u32 + u32::from(step.saved_trace)
        })
    }
}

fn encode_policy(policy: &DirectPolicy) -> [u32; policy_word::COUNT] {
    let bit = |set: bool, bit: PolicyFlags| if set { bit } else { PolicyFlags::empty() };
    let flags = bit(policy.kd_lite, PolicyFlags::KD_LITE)
        | bit(policy.kernel_debugger, PolicyFlags::KERNEL_DEBUGGER)
        | bit(policy.trap_passthrough, PolicyFlags::TRAP_PASSTHROUGH)
        | bit(policy.dump_in_progress, PolicyFlags::DUMP_IN_PROGRESS)
        | bit(policy.attached, PolicyFlags::ATTACHED)
        | bit(
            policy.data_breakpoint.is_some(),
            PolicyFlags::DATA_BREAKPOINT,
        );
    let data = policy.data_breakpoint;
    let mut words = [0; policy_word::COUNT];
    words[policy_word::FLAGS] = flags.bits();
    words[policy_word::DUMP_MODE] = policy.dump_mode.raw();
    words[policy_word::DEFER_MASK] = policy.defer_mask.bits();
    words[policy_word::STOP_ON] = policy.stop_on.bits();
    words[policy_word::DATA_ADDRESS] = data.map_or(0, |data| data.address);
    words[policy_word::DATA_SIZE] = data.map_or(0, |data| data.size);
    words[policy_word::DATA_KIND] = data.map_or(0, |data| data.kind as u32);
    words
}

fn decode_policy(words: [u32; policy_word::COUNT]) -> DirectPolicy {
    let flags = PolicyFlags::from_bits_retain(words[policy_word::FLAGS]);
    const WRITE: u32 = DataKind::Write as u32;
    const READ_WRITE: u32 = DataKind::ReadWrite as u32;
    let kind = match words[policy_word::DATA_KIND] {
        WRITE => DataKind::Write,
        READ_WRITE => DataKind::ReadWrite,
        _ => DataKind::Read,
    };
    DirectPolicy {
        stop_on: StopOn::from_bits_retain(words[policy_word::STOP_ON]),
        kd_lite: flags.contains(PolicyFlags::KD_LITE),
        kernel_debugger: flags.contains(PolicyFlags::KERNEL_DEBUGGER),
        trap_passthrough: flags.contains(PolicyFlags::TRAP_PASSTHROUGH),
        dump_mode: DumpMode::from_raw(words[policy_word::DUMP_MODE]),
        dump_in_progress: flags.contains(PolicyFlags::DUMP_IN_PROGRESS),
        attached: flags.contains(PolicyFlags::ATTACHED),
        defer_mask: EventDeferMask::from_bits_retain(words[policy_word::DEFER_MASK]),
        data_breakpoint: flags
            .contains(PolicyFlags::DATA_BREAKPOINT)
            .then_some(DataBreakpoint {
                address: words[policy_word::DATA_ADDRESS],
                size: words[policy_word::DATA_SIZE],
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
    /// Address of the next node, or 0; guarded by `DIRECT_LOCK`.
    next: AtomicU32,
    notification: DirectNotification,
}

static DIRECT_LOCK: KspinLock = KspinLock::new();
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
        } => {
            // SAFETY: the notice carries the loader's name string and module
            // entry from the parameters of the trap the calling thread
            // raised, live while the debug routine runs.
            unsafe { describe_module(name_string, entry) }
        }
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
    let node_pointer = core::ptr::with_exposed_provenance_mut::<DirectNode>(node as usize);
    // SAFETY: the pool block holds the node and `text_length` bytes and
    // only this call reaches it until it is linked; `readable_length`
    // found the text readable.
    unsafe {
        node_pointer.write(DirectNode {
            next: AtomicU32::new(0),
            notification,
        });
        let text = node_pointer.cast::<u8>().add(header);
        for offset in 0..text_length {
            text.add(offset)
                .write(target_u8(text_address + offset as u32));
        }
    }
    let lock = DIRECT_LOCK.as_ptr();
    // SAFETY: `lock` is the static direct notification spin lock.
    let irql = unsafe { xboxkrnl::KfAcquireSpinLock(lock) };
    match DIRECT_TAIL.swap(node, Ordering::Relaxed) {
        0 => DIRECT_HEAD.store(node, Ordering::Relaxed),
        // SAFETY: under the lock the tail is a queued node that
        // `next_direct_notification` has not freed.
        tail => unsafe { object_at::<DirectNode>(tail) }
            .next
            .store(node, Ordering::Relaxed),
    }
    // SAFETY: the lock was acquired above at `irql`.
    unsafe { xboxkrnl::KfReleaseSpinLock(lock, irql) };
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

/// Exception record and context of the command thread stopped by
/// `break now`.
struct BreakNowCapture {
    context: UnsafeCell<KernelContext>,
    record: UnsafeCell<KernelExceptionRecord>,
}

// SAFETY: the server thread writes the capture while `BREAK_NOW_STOPPED` is
// clear and only the server thread reads or writes it while it is set.
unsafe impl Sync for BreakNowCapture {}

static BREAK_NOW: BreakNowCapture = BreakNowCapture {
    context: UnsafeCell::new(KernelContext::new(KernelContextFlags::empty())),
    record: UnsafeCell::new(KernelExceptionRecord {
        code: NtStatus::SUCCESS,
        flags: KernelExceptionFlags::empty(),
        next_record: 0,
        address: 0,
        parameter_count: 0,
        parameters: [0; 15],
    }),
};
static BREAK_NOW_ARMED: AtomicBool = AtomicBool::new(false);
static BREAK_NOW_STOPPED: AtomicBool = AtomicBool::new(false);

/// The command thread hit the `break now` trap: keep its exception record
/// and context for the monitor and let the thread run on past the trap.
fn capture_break_now(record: &KernelExceptionRecord, context: &mut KernelContext) {
    // SAFETY: the server thread runs this while `BREAK_NOW_STOPPED` is
    // clear, so nothing else accesses the capture.
    unsafe {
        *BREAK_NOW.context.get() = *context;
        *BREAK_NOW.record.get() = *record;
    }
    context.iar = context.iar.wrapping_add(INSTRUCTION_SIZE);
    BREAK_NOW_STOPPED.store(true, Ordering::Release);
}

fn caller_can_wait() -> Option<OwnThread> {
    let own = OwnThread::current();
    (!is_server(own.kthread()) && current_irql() == Irql::PASSIVE).then_some(own)
}

/// Run the monitor's execution state machine (stock 0x91f2da88 without
/// its wait flag) on the server thread; the caller waits until it ran. A
/// pending_title request while stopped waits for the state to change.
/// Does nothing on the server thread, above passive level, or while the
/// server does not take events.
pub(crate) fn request_execution(target: ExecutionState, notify: bool) {
    if let Some(thread) = caller_can_wait() {
        let notify = if notify { EXECUTION_NOTIFY } else { 0 };
        post_and_wait(
            SlotEventKind::Execution,
            thread,
            0,
            0,
            execution_code(target) | notify,
        );
    }
}

/// Stop the calling thread with `execution pending_title stop` until
/// execution starts (stock 0x91f523a0). Without `forever` the wait ends
/// after 15 s and the caller starts execution itself. Returns whether the
/// thread was released before that; false on the server thread, above
/// passive level, or while the server does not take events.
pub(crate) fn stop_at_pending_title(forever: bool) -> bool {
    caller_can_wait().is_some_and(|thread| {
        post_and_wait(SlotEventKind::TitleStop, thread, 0, 0, u32::from(forever))
            .is_some_and(|disposition| disposition.contains(SlotDisposition::HANDLED))
    })
}

/// A profile-guided module registered (stock export 107): with
/// `stopon pogomodstart` the calling thread stops with a `pogomodstartup`
/// line until it is continued. `name` is the address of the module path.
pub(crate) fn report_pogo_module_start(name: u32, module: u32) {
    if !load_policy().stop_on.contains(StopOn::POGO_MODULE_START) {
        return;
    }
    if let Some(thread) = caller_can_wait() {
        post_and_wait(SlotEventKind::Pogo, thread, name, module, 0);
    }
}

/// Call the loaded extension's OnTellDebugger export with a dispatcher
/// result (stock 0x91f2e2e8); its return replaces the result.
pub(crate) fn tell_extension(code: ControlCode, argument: u32, result: u32) -> u32 {
    EXTENSION_CALLS.fetch_add(1, Ordering::AcqRel);
    let routine = EXTENSION_TELL_DEBUGGER.load(Ordering::Acquire);
    let result = if routine == 0 {
        result
    } else {
        // SAFETY: the export was resolved from the loaded extension image
        // and takes three register arguments.
        unsafe { kernel::call_export(routine, code.raw(), argument, result, 0) }
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
        for_each_thread(process, |lock, thread| {
            if list.count >= capacity {
                list.overflow = true;
                return;
            }
            let Some(record) = lock.create_record(thread) else {
                return;
            };
            if record.is_debuggable() {
                store(list.count, ThreadId(thread.id));
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
///
/// # Safety
///
/// `thread` must not end during the call (its record is read without the
/// process lock, as stock reads it).
pub(crate) unsafe fn thread_name(thread: &Kthread) -> Option<u32> {
    // SAFETY: the caller's contract.
    unsafe { record_of(thread) }.and_then(MonitorRecord::name)
}

/// The server thread object, `None` before the server runs.
pub(crate) fn server_thread() -> Option<NonZeroU32> {
    NonZeroU32::new(SERVER_THREAD.load(Ordering::Relaxed))
}

/// Replace the bits `mask` of a thread's monitor record flags with those
/// of `value` (PIX pause, stock 0x91f61610); the previous flags, `None`
/// without a record.
///
/// # Safety
///
/// `thread` must not end during the call (its record is changed without
/// the process lock, as stock changes it).
pub(crate) unsafe fn exchange_record_flags(
    thread: &Kthread,
    mask: MonitorRecordFlags,
    value: MonitorRecordFlags,
) -> Option<MonitorRecordFlags> {
    // SAFETY: the caller's contract.
    let record = unsafe { record_of(thread) }?;
    let previous = record.flags();
    record.set_flags(previous.difference(mask).union(value & mask));
    Some(previous)
}

/// Set the name of `thread` from a NUL-terminated string at `address`
/// (stock 0x91f39dc0). `None` names the calling thread.
///
/// # Safety
///
/// `address` must be 0 or the address of a NUL-terminated string the
/// caller keeps unchanged for the call. The thread `thread` names must not
/// end during the call (its record is changed without the process lock, as
/// stock changes it).
pub(crate) unsafe fn name_thread(thread: Option<ThreadId>, address: u32) {
    let name = core::ptr::with_exposed_provenance::<c_char>(address as usize);
    // SAFETY: the caller's contract.
    if address == 0 || unsafe { name.read() } == 0 {
        return;
    }
    let reference = match thread {
        Some(id) => match ThreadRef::lookup(id) {
            Ok(reference) => Some(reference),
            Err(NoSuchThread) => return,
        },
        None => None,
    };
    let thread: &Kthread = match &reference {
        Some(reference) => reference.thread(),
        None => current(),
    };
    // SAFETY: the caller's contract keeps the named thread from ending; the
    // calling thread does not end while it runs here.
    let Some(record) = (unsafe { create_record(thread) }) else {
        return;
    };
    // SAFETY: as above.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes_with_nul();
    let pool_type = pool_type_of(thread);
    if let Some(old) = record.name() {
        // SAFETY: the old name is a pool block this module allocated.
        unsafe { xboxkrnl::ExFreePool(old) };
    }
    // SAFETY: pool allocation has no pointer arguments.
    let copy =
        unsafe { xboxkrnl::ExAllocatePoolTypeWithTag(name.len() as u32, RECORD_TAG, pool_type) };
    record.name.store(copy, Ordering::Relaxed);
    if copy != 0 {
        // SAFETY: the pool block holds `name.len()` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                name.as_ptr(),
                core::ptr::with_exposed_provenance_mut(copy as usize),
                name.len(),
            )
        };
    }
}

crate::exports::bridged!(set_data_breakpoint_entry, set_data_breakpoint_on_processor);

extern "C" fn set_data_breakpoint_on_processor(value: u32) -> u32 {
    // SAFETY: writing DABR on this processor only arms a data breakpoint.
    unsafe { KeSetSpecialPurposeRegister(SpecialPurposeRegister::DABR, u64::from(value)) };
    value
}

/// An inclusive range of addresses.
struct AddressRange {
    first: u32,
    last: u32,
}

/// Address ranges the debugger never maps (memory-mapped devices).
const EXCLUDED_RANGES: &[AddressRange] = &[
    AddressRange {
        first: 0x7fc8_0000,
        last: 0x7fc9_ffff,
    },
    AddressRange {
        first: 0x7fd0_0000,
        last: 0x7fdf_ffff,
    },
    AddressRange {
        first: 0x7fea_0000,
        last: 0x7fea_ffff,
    },
    AddressRange {
        first: 0x7fed_0000,
        last: 0x7fed_ffff,
    },
    AddressRange {
        first: 0x8fff_0000,
        last: 0x8fff_0fff,
    },
    AddressRange {
        first: 0x8fff_1000,
        last: 0x8fff_1fff,
    },
];

fn is_excluded(address: u32) -> bool {
    EXCLUDED_RANGES
        .iter()
        .any(|range| (range.first..=range.last).contains(&address))
}

fn readable(address: u32) -> bool {
    // SAFETY: the kernel validates the address before it maps it.
    let mapped = unsafe { xboxkrnl::MmDbgReadCheck(address) };
    mapped != 0 && !is_excluded(mapped)
}

/// Copy the groups in `flags` from a kernel context to a [`Context`].
///
/// The context is reached through field pointers, not a reference: a
/// caller's CONTEXT is only known to have the 8-byte alignment of its
/// widest scalar field, not the 16 bytes of [`KernelContext`].
///
/// # Safety
///
/// `source` must be valid for reads of a kernel context, aligned to 8
/// bytes, and not written during the call.
unsafe fn read_context(source: *const KernelContext, flags: ContextFlags, out: &mut Context) {
    // SAFETY: the caller's contract; no field needs more than 8-byte
    // alignment.
    unsafe {
        if flags.contains(ContextFlags::CONTROL) {
            out.msr = (&raw const (*source).msr).read();
            out.iar = (&raw const (*source).iar).read();
            out.lr = (&raw const (*source).lr).read();
            out.ctr = (&raw const (*source).ctr).read();
        }
        if flags.contains(ContextFlags::INTEGER) {
            out.gpr = (&raw const (*source).gpr).read();
            out.cr = (&raw const (*source).cr).read();
            out.xer = (&raw const (*source).xer).read();
        }
        if flags.contains(ContextFlags::FLOATING_POINT) {
            out.fpscr = (&raw const (*source).fpscr).read();
            out.fpr = (&raw const (*source).fpr).read();
        }
        if flags.contains(ContextFlags::VECTOR) {
            out.vscr = (&raw const (*source).vscr).read();
            out.vr = (&raw const (*source).vr).read();
        }
    }
}

/// Copy the groups in `source.flags` from a [`Context`] to a kernel
/// context, through field pointers as [`read_context`] reads.
///
/// # Safety
///
/// `target` must be valid for writes of a kernel context, aligned to 8
/// bytes, and not accessed by anything else during the call.
unsafe fn write_context(target: *mut KernelContext, source: &Context) {
    let flags = source.flags;
    // SAFETY: the caller's contract; no field needs more than 8-byte
    // alignment.
    unsafe {
        if flags.contains(ContextFlags::CONTROL) {
            (&raw mut (*target).msr).write(source.msr);
            (&raw mut (*target).iar).write(source.iar);
            (&raw mut (*target).lr).write(source.lr);
            (&raw mut (*target).ctr).write(source.ctr);
        }
        if flags.contains(ContextFlags::INTEGER) {
            (&raw mut (*target).gpr).write(source.gpr);
            (&raw mut (*target).cr).write(source.cr);
            (&raw mut (*target).xer).write(source.xer);
        }
        if flags.contains(ContextFlags::FLOATING_POINT) {
            (&raw mut (*target).fpscr).write(source.fpscr);
            (&raw mut (*target).fpr).write(source.fpr);
        }
        if flags.contains(ContextFlags::VECTOR) {
            (&raw mut (*target).vscr).write(source.vscr);
            (&raw mut (*target).vr).write(source.vr);
        }
    }
}

/// Exception context of a thread stopped at an event: a thread waiting in
/// a slot, or the command thread at the `break now` trap. `lock` is the
/// lock of the thread's process.
fn slot_context(lock: &ThreadListLock<'_>, thread: &Kthread) -> Option<*mut KernelContext> {
    if is_server(thread) {
        return BREAK_NOW_STOPPED
            .load(Ordering::Acquire)
            .then(|| BREAK_NOW.context.get());
    }
    let slot = lock.record(thread)?.slot.load(Ordering::Relaxed);
    if slot == 0 {
        return None;
    }
    let slot = &SLOTS[slot as usize - 1];
    matches!(
        slot.kind(),
        Some(SlotEventKind::Exception | SlotEventKind::StackOverflow)
    )
    .then(|| core::ptr::with_exposed_provenance_mut(slot.context.load(Ordering::Relaxed) as usize))
}

/// Module entry of a load or unload trap.
#[repr(C)]
struct TrapModuleEntry {
    base: u32,
    _reserved_04: [u32; 2],
    size: u32,
}

const _: () = assert!(core::mem::offset_of!(TrapModuleEntry, size) == 0xc);

/// Describe the module of a load or unload trap from the loader's name
/// string and module entry.
///
/// # Safety
///
/// `name_string` and `entry` must each be 0 or the loader's live name
/// string and module entry of the trap, and the image must stay mapped for
/// the call.
unsafe fn describe_module(name_string: u32, entry: u32) -> Option<ModuleEvent> {
    if name_string == 0 || entry == 0 {
        return None;
    }
    // SAFETY: the caller guarantees both objects.
    let (name, entry) = unsafe {
        (
            object_at::<AnsiString>(name_string),
            object_at::<TrapModuleEntry>(entry),
        )
    };
    let mut module = ModuleEvent::default();
    let length = usize::from(ansi_string_length(name)).min(MODULE_NAME_CAPACITY - 1);
    // SAFETY: the loader's name buffer holds `length` bytes.
    module.name[..length]
        .copy_from_slice(unsafe { core::slice::from_raw_parts(name.buffer, length) });
    module.name_length = length;
    module.base = entry.base;
    module.size = entry.size;
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
    let thread = reference.thread();
    let lock = ThreadListLock::acquire(owning_process(thread));
    let record = lock.record(thread);
    let name = record.and_then(MonitorRecord::name).map(|address| {
        // SAFETY: the record's name is a NUL-terminated pool copy that
        // `name_thread` made. The lock does not exclude a rename:
        // `name_thread` frees the old copy without the process lock, as
        // stock does, so a rename during this read reads a freed block.
        // The monitor keeps that stock race (see the nuances ledger).
        let name = unsafe {
            CStr::from_ptr(core::ptr::with_exposed_provenance::<c_char>(
                address as usize,
            ))
        };
        ThreadName {
            address,
            length: name.to_bytes_with_nul().len() as u32,
        }
    });
    Ok(ThreadInfo {
        suspend_count: thread.suspend_count.load(Ordering::Relaxed) as i8,
        monitor_suspended: record.is_some_and(MonitorRecord::is_monitor_suspended),
        priority: thread.priority.load(Ordering::Relaxed),
        tls_base: thread.tls_base,
        start_address: thread.start_address,
        stack_base: thread.stack_base.load(Ordering::Relaxed),
        stack_limit: thread.stack_limit.load(Ordering::Relaxed),
        create_time: thread.create_time(),
        name,
        processor: thread.processor().get(),
        last_error: thread.last_error.load(Ordering::Relaxed),
    })
}

/// `suspend` and stock export 48 (0x91f267e8).
pub(crate) fn suspend(thread: ThreadId) -> Result<(), NoSuchThread> {
    let reference = ThreadRef::lookup(thread)?;
    // SAFETY: `reference` holds a reference to the thread object.
    unsafe { KeSuspendThread(thread_pointer(reference.thread())) };
    Ok(())
}

/// `resume` and stock export 35 (0x91f26838).
pub(crate) fn resume(thread: ThreadId) -> Result<(), NoSuchThread> {
    let reference = ThreadRef::lookup(thread)?;
    // SAFETY: `reference` holds a reference to the thread object.
    unsafe { KeResumeThread(thread_pointer(reference.thread())) };
    Ok(())
}

/// Read the groups in `out.flags` of a thread with a monitor record (stock
/// export 13, 0x91f26260); `out.flags` becomes the groups read. A thread
/// stopped in the monitor reports its exception context, another its
/// switch frame with the monitor's fill values.
pub(crate) fn read_thread_context(thread: ThreadId, out: &mut Context) -> Result<(), NoSuchThread> {
    let reference = ThreadRef::lookup(thread)?;
    let thread = reference.thread();
    let lock = ThreadListLock::acquire(owning_process(thread));
    let requested = out.flags & ContextFlags::FULL;
    if !has_record(thread) {
        return Err(NoSuchThread);
    }
    if let Some(context) = slot_context(&lock, thread) {
        // SAFETY: the context of a thread waiting in a slot is the kernel's
        // aligned context, which stays live and unchanged while the process
        // lock keeps the thread from leaving the slot; the `break now`
        // capture is only touched by the server thread.
        unsafe { read_context(context, requested, out) };
        out.flags = requested;
        return Ok(());
    }
    // Switch frame: only the nonvolatile state is meaningful. The thread may
    // run and overwrite the frame meanwhile, so each word is read with one
    // relaxed load.
    let frame_address = thread.switch_frame.load(Ordering::Relaxed);
    let frame = core::ptr::with_exposed_provenance_mut::<KswitchFrame>(frame_address as usize);
    // SAFETY: the switch frame lies on the stack of the referenced thread,
    // which stays allocated while the reference is held; the words are
    // aligned and only read atomically here.
    let word = |address: *mut u32| unsafe { AtomicU32::from_ptr(address) }.load(Ordering::Relaxed);
    let mut flags = ContextFlags::empty();
    if requested.contains(ContextFlags::INTEGER) {
        flags = flags.union(ContextFlags::INTEGER);
        out.gpr = [u64::MAX; 32];
        // SAFETY: field pointers within the frame described above.
        let gpr = unsafe { &raw mut (*frame).gpr }.cast::<u32>();
        for (index, register) in out.gpr[14..].iter_mut().enumerate() {
            // SAFETY: both words lie within the frame's register array.
            let (high, low) = unsafe { (gpr.add(2 * index), gpr.add(2 * index + 1)) };
            *register = (u64::from(word(high)) << 32) | u64::from(word(low));
        }
        out.gpr[1] = u64::from(frame_address);
        // SAFETY: as above.
        out.cr = word(unsafe { &raw mut (*frame).cr });
        out.xer = u32::MAX;
    }
    if requested.contains(ContextFlags::CONTROL) {
        flags = flags.union(ContextFlags::CONTROL);
        out.msr = Msr::from_bits_retain(u32::MAX);
        // SAFETY: as above.
        out.iar = word(unsafe { &raw mut (*frame).iar });
        // SAFETY: as above.
        out.lr = word(unsafe { &raw mut (*frame).lr });
        out.ctr = u64::MAX;
    }
    out.flags = flags;
    Ok(())
}

/// Write the groups in `source.flags` to the exception context of a thread
/// stopped in the monitor (stock export 41, 0x91f26468).
pub(crate) fn write_thread_context(
    thread: ThreadId,
    source: &Context,
) -> Result<(), StoppedThreadError> {
    let reference = ThreadRef::lookup(thread)?;
    let thread = reference.thread();
    let lock = ThreadListLock::acquire(owning_process(thread));
    if !has_record(thread) {
        return Err(StoppedThreadError::NoSuchThread);
    }
    let context = slot_context(&lock, thread).ok_or(StoppedThreadError::NotStopped)?;
    // SAFETY: as in `read_thread_context`; the stopped thread does not
    // touch its context while it waits.
    unsafe { write_context(context, source) };
    Ok(())
}

/// `DumpWriteDump` dump kinds.
#[repr(u32)]
#[derive(Clone, Copy)]
pub(crate) enum DumpKind {
    Default = 0,
    /// The kind stock passes for an exception once the kernel's bug check
    /// flag ([`DebugMonitorFlags::BUG_CHECK`]) is set.
    BugCheck = 1,
    Full = 2,
}

/// Capture the calling thread's context and write a crash dump of it
/// (`crashdump`, stock export 83) with dump kind `kind`.
pub(crate) fn dump_calling_thread(kind: DumpKind) {
    let mut context = ContextStorage::new(KernelContextFlags::empty());
    // SAFETY: `context` is a live local of the size the kernel writes.
    unsafe {
        RtlCaptureContext(context.as_mut_ptr());
        DumpWriteDump(0, address_of(&context.context), kind as u32);
    }
}

/// The groups in `flags` of a kernel context.
///
/// # Safety
///
/// As [`read_context`].
pub(crate) unsafe fn context_from_memory(
    source: *const KernelContext,
    flags: ContextFlags,
) -> Context {
    let mut context = Context {
        flags,
        ..Context::default()
    };
    // SAFETY: the caller's contract.
    unsafe { read_context(source, flags, &mut context) };
    context
}

/// Store the groups in `source.flags` into a kernel context.
///
/// # Safety
///
/// As [`write_context`].
pub(crate) unsafe fn context_to_memory(target: *mut KernelContext, source: &Context) {
    // SAFETY: the caller's contract.
    unsafe { write_context(target, source) };
}

/// Address of the calling thread's record debug data word (stock record
/// +0x10).
pub(crate) fn current_debug_data() -> Option<u32> {
    OwnThread::current()
        .record()
        .map(|record| address_of(&record.debug_data))
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
        for_each_thread(process, |lock, thread| {
            let Some(record) = lock.record(thread) else {
                return;
            };
            let flags = record.flags();
            if !is_server(thread)
                && flags.contains(MonitorRecordFlags::DEBUGGABLE)
                && !flags.contains(MonitorRecordFlags::EXEMPT)
                && !record.waits_in_slot()
                && !record.is_monitor_suspended()
            {
                record.monitor_suspended.store(1, Ordering::Relaxed);
                // SAFETY: `for_each_thread` visits live thread objects under
                // the process lock.
                unsafe { KeSuspendThread(thread_pointer(thread)) };
            }
        });
    }

    fn resume_threads(&mut self, process: ProcessKind) {
        for_each_thread(process, |lock, thread| {
            let Some(record) = lock.record(thread) else {
                return;
            };
            if !is_server(thread) && record.is_debuggable() && record.is_monitor_suspended() {
                record.monitor_suspended.store(0, Ordering::Relaxed);
                // SAFETY: `for_each_thread` visits live thread objects under
                // the process lock.
                unsafe { KeResumeThread(thread_pointer(thread)) };
            }
        });
    }

    fn monitor_suspend(&mut self, thread: ThreadId) {
        let Ok(reference) = ThreadRef::lookup(thread) else {
            return;
        };
        let thread = reference.thread();
        // SAFETY: not guaranteed: `continue` calls this for a thread with a
        // pending event, which usually waits in its slot until
        // `complete_event`, but a create event posted detached under an
        // older policy leaves its thread running. Stock reads the record
        // here without the process lock as well; the race is kept.
        if let Some(record) = unsafe { record_of(thread) }
            && !record.is_monitor_suspended()
        {
            // SAFETY: `reference` holds a reference to the thread object.
            unsafe { KeSuspendThread(thread_pointer(thread)) };
            record.monitor_suspended.store(1, Ordering::Relaxed);
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
        Ok(has_record(reference.thread()))
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

    unsafe fn set_thread_name(&mut self, thread: ThreadId, address: u32) {
        // SAFETY: the server passes the name parameter of the thread-name
        // exception of a thread that waits in its slot for the call. The
        // named thread may be another one that ends during the call; stock
        // names it without the process lock and the monitor keeps that
        // race.
        unsafe { name_thread(Some(thread), address) };
    }

    fn thread_exit_status(&mut self, handle: ThreadHandle) -> Result<ExitStatus, KernelError> {
        let reference = ThreadRef::by_handle(handle)?;
        let thread = reference.thread();
        // The low byte of the signal state is set once the thread ended.
        Ok(if thread.signal_state.load(Ordering::Relaxed) as u8 == 0 {
            ExitStatus::STILL_ACTIVE
        } else {
            ExitStatus(thread.exit_status.load(Ordering::Relaxed))
        })
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
        // SAFETY: `MmDbgWriteCheck` mapped the word-aligned code word
        // writable at `mapped` until the release below.
        let word =
            unsafe { AtomicU32::from_ptr(core::ptr::with_exposed_provenance_mut(mapped as usize)) };
        let previous = word.load(Ordering::Relaxed);
        word.store(value, Ordering::Relaxed);
        // SAFETY: `mapped` is the writable word mapped above; `mapped` and
        // `mapping` come from `MmDbgWriteCheck`.
        unsafe {
            xboxkrnl::KeSweepIcacheRange(
                core::ptr::with_exposed_provenance_mut(mapped as usize),
                INSTRUCTION_SIZE,
            );
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
            // SAFETY: `readable` checked the page of `source` above.
            *byte = unsafe { target_u8(source) };
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

    unsafe fn module_event(
        &mut self,
        name_string: u32,
        entry: u32,
        _thread: ThreadId,
    ) -> Option<ModuleEvent> {
        // SAFETY: the caller upholds the same contract.
        unsafe { describe_module(name_string, entry) }
    }

    fn next_event(&mut self) -> Option<DebugEvent> {
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
                    record: exception_record(unsafe {
                        object_at(slot.record.load(Ordering::Relaxed))
                    }),
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
        // SAFETY: the server thread object stays allocated while the server
        // runs, and the server calls this on its own thread.
        if let Some(server) = server_thread()
            && unsafe { thread_at(server.get()) }.id == thread.0
        {
            BREAK_NOW_STOPPED.store(false, Ordering::Release);
            return;
        }
        // Claimed before the disposition is written: a waiter released by
        // a stop reclaims its taken slot with the same exchange.
        let Some(slot) = SLOTS.iter().find(|slot| {
            slot.thread_id.load(Ordering::Relaxed) == thread.0
                && slot.state.transition(
                    HandoffState::Taken,
                    HandoffState::Filling,
                    Ordering::AcqRel,
                )
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

    fn publish_direct_policy(&mut self, policy: &DirectPolicy) {
        store_policy(policy);
    }

    fn next_direct_notification(
        &mut self,
        text: &mut [u8; NOTICE_TEXT_CAPACITY],
    ) -> Option<DirectNotification> {
        let lock = DIRECT_LOCK.as_ptr();
        // SAFETY: `lock` is the static direct notification spin lock.
        let irql = unsafe { xboxkrnl::KfAcquireSpinLock(lock) };
        let node = DIRECT_HEAD.load(Ordering::Relaxed);
        if node != 0 {
            // SAFETY: under the lock the head is a queued node.
            let next = unsafe { object_at::<DirectNode>(node) }
                .next
                .load(Ordering::Relaxed);
            DIRECT_HEAD.store(next, Ordering::Relaxed);
            if next == 0 {
                DIRECT_TAIL.store(0, Ordering::Relaxed);
            }
        }
        // SAFETY: the lock was acquired above at `irql`.
        unsafe { xboxkrnl::KfReleaseSpinLock(lock, irql) };
        if node == 0 {
            return None;
        }
        // SAFETY: `queue_direct` wrote the node and its text; this call
        // unlinked it, so nothing else reaches it.
        let node_ref = unsafe { object_at::<DirectNode>(node) };
        let mut notification = node_ref.notification;
        let length = notification.text_length.min(NOTICE_TEXT_CAPACITY);
        // SAFETY: the node is followed by `text_length` bytes of text.
        let source = unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(node_ref)
                    .cast::<u8>()
                    .add(core::mem::size_of::<DirectNode>()),
                length,
            )
        };
        text[..length].copy_from_slice(source);
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
        let thread = current();
        // SAFETY: the capture is set and only the server thread reads it.
        let record = exception_record(unsafe { &*BREAK_NOW.record.get() });
        Some(DebugEvent::Exception {
            thread: ThreadId(thread.id),
            process: ProcessKind::System,
            record,
            second_chance: false,
            has_record: has_record(thread),
            debuggable: false,
        })
    }

    fn crash_dump(&mut self) {
        sleep(Duration::from_millis(200));
        dump_calling_thread(DumpKind::Default);
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
        // SAFETY: `handle` is the image loaded above, and this call hands
        // out its only token.
        Ok(unsafe { ExtensionHandle::from_raw(handle) })
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
        // SAFETY: the token names the loaded extension image and is
        // consumed here.
        unsafe { XexUnloadImage(handle.raw()) }.result()
    }
}
