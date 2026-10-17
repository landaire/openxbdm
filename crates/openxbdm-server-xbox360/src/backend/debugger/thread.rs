//! Monitor thread records, process thread lists, and thread services.

use core::ffi::CStr;
use core::ffi::c_char;
use core::num::NonZeroU32;
use core::ptr::NonNull;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::KernelError;
use openxbdm_server::commands::debugger::NoSuchThread;
use openxbdm_server::commands::debugger::ProcessKind;
use openxbdm_server::commands::debugger::ThreadId;
use openxbdm_server::commands::debugger::ThreadInfo;
use openxbdm_server::commands::debugger::ThreadName;
use openxbdm_server::commands::services::ThreadHandle;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeResumeThread;
use xbox360_sys::xboxkrnl::KeSuspendThread;
use xbox360_sys::xboxkrnl::Kprocess;
use xbox360_sys::xboxkrnl::Kthread;
use xbox360_sys::xboxkrnl::ObLookupAnyThreadByThreadId;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;

use crate::kernel;
use crate::kernel::address_of;
use crate::kernel::object_at;
use crate::kernel::thread_at;

/// Pool tag of monitor thread records ('Dmtd').
const RECORD_TAG: PoolTag = PoolTag::new(*b"dtmD");

/// Thread object of the server thread, which must never wait in a slot.
static SERVER_THREAD: AtomicU32 = AtomicU32::new(0);

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
pub(super) struct MonitorRecord {
    /// [`MonitorRecordFlags`].
    flags: AtomicU32,
    /// Nonzero while the monitor holds a suspension of the thread.
    monitor_suspended: AtomicU32,
    /// Pool copy of the thread name, or 0.
    name: AtomicU32,
    /// Index plus one of the slot the thread waits in, or 0.
    pub(super) slot: AtomicU32,
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
    pub(super) fn is_debuggable(&self) -> bool {
        self.flags().contains(MonitorRecordFlags::DEBUGGABLE)
    }

    #[inline(always)]
    pub(super) fn is_monitor_suspended(&self) -> bool {
        self.monitor_suspended.load(Ordering::Relaxed) != 0
    }

    #[inline(always)]
    pub(super) fn waits_in_slot(&self) -> bool {
        self.slot.load(Ordering::Relaxed) != 0
    }

    /// Address of the pool copy of the thread name.
    #[inline(always)]
    pub(super) fn name(&self) -> Option<u32> {
        Some(self.name.load(Ordering::Relaxed)).filter(|&name| name != 0)
    }
}

/// The object of the calling thread. Its monitor record stays allocated
/// while code on the thread holds it, as [`MonitorRecord`] states; a
/// [`Kthread`] reference is not `Send`, so neither is this.
#[derive(Clone, Copy)]
pub(super) struct OwnThread(&'static Kthread);

impl OwnThread {
    #[inline(always)]
    pub(super) fn current() -> Self {
        Self(current())
    }

    /// # Safety
    ///
    /// `thread` must be the object of the calling thread.
    #[inline(always)]
    pub(super) unsafe fn from_kthread(thread: &'static Kthread) -> Self {
        Self(thread)
    }

    #[inline(always)]
    pub(super) fn kthread(&self) -> &'static Kthread {
        self.0
    }

    #[inline(always)]
    pub(super) fn record(&self) -> Option<&MonitorRecord> {
        // SAFETY: the record of the calling thread, held by code on it.
        unsafe { record_of(self.0) }
    }

    #[inline(always)]
    pub(super) fn create_record(&self) -> Option<&MonitorRecord> {
        // SAFETY: as in `record`.
        unsafe { create_record(self.0) }
    }
}

/// The thread list lock of a process, held until dropped. It is taken only
/// for the process that owns the threads whose records are read through
/// it.
pub(super) struct ThreadListLock<'a> {
    process: &'a Kprocess,
    irql: Irql,
}

impl<'a> ThreadListLock<'a> {
    #[inline(always)]
    pub(super) fn acquire(process: &'a Kprocess) -> Self {
        // SAFETY: the lock is the process's thread list spin lock.
        let irql = unsafe { xboxkrnl::KfAcquireSpinLock(process.thread_list_lock.as_ptr()) };

        Self { process, irql }
    }

    /// The record of `thread`, a thread of the locked process.
    #[inline(always)]
    pub(super) fn record<'b>(&'b self, thread: &'b Kthread) -> Option<&'b MonitorRecord> {
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

/// A referenced thread object.
pub(super) struct ThreadRef(NonNull<Kthread>);

impl ThreadRef {
    pub(super) fn lookup(id: ThreadId) -> Result<Self, NoSuchThread> {
        let mut object = core::ptr::null_mut();
        // SAFETY: `object` is a live local that receives the thread pointer.
        let status = unsafe { ObLookupAnyThreadByThreadId(id.0, &mut object) };
        if !status.is_success() {
            return Err(NoSuchThread);
        }

        // SAFETY: a successful lookup stores a referenced thread object.
        Ok(Self(unsafe { NonNull::new_unchecked(object) }))
    }

    pub(super) fn by_handle(handle: ThreadHandle) -> Result<Self, KernelError> {
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
    pub(super) fn thread(&self) -> &Kthread {
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

/// Collected debuggable thread identifiers.
pub(crate) struct ThreadList {
    pub(crate) count: usize,
    /// Threads were left unvisited once `capacity` were stored.
    pub(crate) overflow: bool,
}

/// The thread object of the calling thread.
#[inline(always)]
pub(super) fn current() -> &'static Kthread {
    xbox360::thread::current_object().kthread()
}

/// The thread object as kernel thread calls take it.
#[inline(always)]
pub(super) fn thread_pointer(thread: &Kthread) -> *mut Kthread {
    core::ptr::from_ref(thread).cast_mut()
}

pub(super) fn is_server(thread: &Kthread) -> bool {
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

/// Whether `thread` has a monitor record. Only the thread's word is read.
#[inline(always)]
pub(super) fn has_record(thread: &Kthread) -> bool {
    thread.debug_data.load(Ordering::Relaxed) != 0
}

/// The monitor record of `thread`.
///
/// # Safety
///
/// The record must stay allocated while the result is used, as
/// [`MonitorRecord`] states: the process lock is held, or `thread` does not
/// end in that time (it is the calling thread or waits in a slot).
pub(super) unsafe fn record_of<'a>(thread: &'a Kthread) -> Option<&'a MonitorRecord> {
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
pub(super) fn owning_process(thread: &Kthread) -> &Kprocess {
    // SAFETY: a thread object holds the address of its process object,
    // which outlives the thread.
    unsafe { object_at(thread.process) }
}

pub(super) fn process_kind_of(thread: &Kthread) -> ProcessKind {
    let process = thread.process;
    if process != 0 && process == process_address(ProcessKind::Title) {
        ProcessKind::Title
    } else {
        ProcessKind::System
    }
}

/// Call `visit` with each thread object of `kind` under the process lock.
fn for_each_thread(kind: ProcessKind, mut visit: impl FnMut(&ThreadListLock<'_>, &Kthread)) {
    /// Offset of the thread list link in a thread object.
    const THREAD_LIST_ENTRY: u32 = core::mem::offset_of!(Kthread, thread_list_entry) as u32;

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

/// Address of the calling thread's record debug data word (stock record
/// +0x10).
pub(crate) fn current_debug_data() -> Option<u32> {
    OwnThread::current()
        .record()
        .map(|record| address_of(&record.debug_data))
}

pub(super) fn suspend_threads(process: ProcessKind) {
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

pub(super) fn resume_threads(process: ProcessKind) {
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

pub(super) fn monitor_suspend(thread: ThreadId) {
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
