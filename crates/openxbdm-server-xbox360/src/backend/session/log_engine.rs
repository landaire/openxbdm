//! Log engine (exports 355-358 and 360-364; stock create 0x91f79470,
//! worker 0x91f78d48). Producers on any thread copy or format a record into
//! an entry taken from the free queue and append it to the pending queue;
//! a worker thread hands each pending entry to a callback, or writes its
//! text to a file, and returns it to the free queue. Both queues are the
//! lock-free queues of exports 302-309.
//!
//! The engine object ([`LogEngine`]) is caller-visible and its entries
//! follow it. The exports turn their engine argument into an [`Engine`]
//! once, under the export contract: the caller passes 0 or an engine of
//! the create exports that close has not freed. The free and pending
//! queues hold only addresses of the engine's entries, and an entry
//! belongs to the thread that took it from a queue until it queues it
//! again.

use core::ffi::CStr;
use core::fmt::Write as _;
use core::num::NonZeroU32;
use core::ptr;
use core::ptr::NonNull;
use core::slice;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::sync::atomic::Ordering::Relaxed;
use core::time::Duration;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_server::commands::session::LogEngineError;
use openxbdm_server::commands::session::TellLogConfig;
use openxbdm_server::commands::session::TellLogCounters;
use openxbdm_server::text::Text;
use xbox360::status::last_error;
use xbox360::status::set_last_error;
use xbox360::thread;
use xbox360::time::sleep;
use xbox360_sys::export_raw;
use xbox360_sys::xam::CreateFileA;
use xbox360_sys::xam::CreationDisposition;
use xbox360_sys::xam::INVALID_HANDLE_VALUE;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::DispatcherObject;
use xbox360_sys::xboxkrnl::EVENT_INCREMENT;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::Kevent;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ShareAccess;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;
use xbox360_sys::xboxkrnl::WaitType;

use crate::exports::export;
use crate::kernel;
use crate::lockfree;
use crate::lockfree::Creation;
use crate::lockfree::CreationDescriptor;
use crate::lockfree::OptionFlags;
use crate::lockfree::OutputWord;
use crate::lockfree::Queue;
use crate::lockfree::Routine;
use crate::lockfree::Timeout;

/// Bytes of the file name field.
const NAME_CAPACITY: usize = 0x104;

/// Engine object (caller-visible, 0x160 bytes; the entries follow).
#[repr(C)]
struct LogEngine {
    entry_size: AtomicU32,
    /// Log file of file-name mode; [`INVALID_HANDLE_VALUE`] when none is
    /// open.
    file: AtomicU32,
    /// Worker thread handle.
    worker: AtomicU32,
    /// Address of `quit_event`, 0 once destroyed.
    quit_pointer: AtomicU32,
    /// Address of `done_event`, 0 once destroyed.
    done_pointer: AtomicU32,
    /// Why the worker stopped early ([`WorkerError`]).
    status: AtomicU32,
    /// Records dropped for want of a free entry.
    dropped: AtomicU32,
    /// Failed waits of the worker.
    missed: AtomicU32,
    /// `callback(context, entry, entry_size)`, or 0 in file-name mode.
    callback: AtomicU32,
    context: AtomicU32,
    /// File name of file-name mode, NUL-terminated.
    name: [AtomicU8; NAME_CAPACITY],
    worker_id: AtomicU32,
    done_event: Kevent,
    quit_event: Kevent,
    /// Address of the cell that holds the pending queue.
    pending_cell: AtomicU32,
    /// Address of the cell that holds the free queue.
    free_cell: AtomicU32,
    /// Free routine and context of a caller allocator, or 0.
    free_routine: AtomicU32,
    free_context: AtomicU32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(LogEngine, quit_pointer) == 0x0c);
    assert!(offset_of!(LogEngine, done_pointer) == 0x10);
    assert!(offset_of!(LogEngine, status) == 0x14);
    assert!(offset_of!(LogEngine, callback) == 0x20);
    assert!(offset_of!(LogEngine, name) == 0x28);
    assert!(offset_of!(LogEngine, worker_id) == 0x12c);
    assert!(offset_of!(LogEngine, done_event) == 0x130);
    assert!(offset_of!(LogEngine, quit_event) == 0x140);
    assert!(offset_of!(LogEngine, pending_cell) == 0x150);
    assert!(offset_of!(LogEngine, free_routine) == 0x158);
    assert!(size_of::<LogEngine>() == 0x160);
};

/// Why the worker stopped early; its result word goes to the engine's
/// status field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerError {
    /// The quit or done event is missing.
    MissingEvent,
    /// The log file could not be created.
    NoFile,
    /// The callback failed with this result.
    Callback(Hresult),
    /// The file write failed; the thread's last error, if any.
    Write(Option<Win32Error>),
    /// An entry could not be returned to the free queue.
    Requeue,
}

impl core::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingEvent => f.write_str("quit or done event missing"),
            Self::NoFile => f.write_str("log file not created"),
            Self::Callback(result) => write!(f, "callback failed with {:#x}", result.0),
            Self::Write(_) => f.write_str("log file write failed"),
            Self::Requeue => f.write_str("entry not returned to the free queue"),
        }
    }
}

impl core::error::Error for WorkerError {}

/// The engine status word of a worker failure.
impl From<WorkerError> for Hresult {
    fn from(error: WorkerError) -> Self {
        match error {
            WorkerError::MissingEvent => Self::INVALID_ARGUMENT,
            // Stock stores the NTSTATUS itself in the status word.
            WorkerError::NoFile => Self(KernelError::ObjectNameInvalid.status().0),
            WorkerError::Callback(result) => result,
            // Stock stores the conversion of a zero last error as is.
            WorkerError::Write(error) => error.map_or(Self::SUCCESS, Self::from),
            WorkerError::Requeue => Self::FAIL,
        }
    }
}

/// Exit code of the worker thread.
#[derive(Clone, Copy)]
#[repr(u32)]
enum WorkerExit {
    Finished = 0,
    Failed = u32::MAX,
}

/// Pending-queue dequeue failure once the wait routine reports the quit
/// event: the queue takes the routine's STATUS_WAIT_1 (wait index 1) as
/// Win32 code 1.
const QUIT_SIGNALED: lockfree::Error = lockfree::Error::Wait(Win32Error::INVALID_FUNCTION);

/// An engine of this module.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Engine(NonNull<LogEngine>);

impl Engine {
    /// The engine at `address`, none for 0.
    ///
    /// # Safety
    ///
    /// `address` is 0 or an engine of this module that is not destroyed
    /// while the returned value or a copy of it is used.
    pub(super) unsafe fn new(address: u32) -> Option<Self> {
        NonNull::new(ptr::with_exposed_provenance_mut(address as usize)).map(Self)
    }

    pub(super) fn address(self) -> u32 {
        self.0.as_ptr().expose_provenance() as u32
    }

    fn get(&self) -> &LogEngine {
        // SAFETY: an `Engine` names a live engine (`Engine::new`, or a
        // creation of this module) until `destroy` frees it.
        unsafe { self.0.as_ref() }
    }
}

/// An engine event, by the address its pointer word holds. It keeps no
/// reference to the engine: once the done event is set, close may free the
/// engine.
#[derive(Clone, Copy)]
struct Event(*mut Kevent);

impl Event {
    fn set(self) {
        // SAFETY: the pointer came from a pointer word of an engine in use,
        // which holds the engine's initialized event from creation until
        // destroy (export contract).
        unsafe { xboxkrnl::KeSetEvent(self.0, EVENT_INCREMENT, false) };
    }

    fn as_dispatcher(self) -> *mut DispatcherObject {
        self.0.cast()
    }
}

impl LogEngine {
    /// Record why the worker stopped in the caller-visible status field.
    fn fail(&self, error: WorkerError) {
        self.status.store(Hresult::from(error).0, Relaxed);
    }

    /// The quit event through its pointer word, as stock reads it.
    fn quit(&self) -> Event {
        Event(ptr::with_exposed_provenance_mut(
            self.quit_pointer.load(Relaxed) as usize,
        ))
    }

    /// The done event through its pointer word, as stock reads it.
    fn done(&self) -> Event {
        Event(ptr::with_exposed_provenance_mut(
            self.done_pointer.load(Relaxed) as usize,
        ))
    }

    fn worker_running(&self) -> bool {
        thread::current_object().id().raw() == self.worker_id.load(Relaxed)
    }

    fn file(&self) -> Option<Handle> {
        Some(Handle::from_raw(self.file.load(Relaxed))).filter(|&file| file != INVALID_HANDLE_VALUE)
    }

    fn cell_word(&self, cell: Cell) -> &AtomicU32 {
        match cell {
            Cell::Pending => &self.pending_cell,
            Cell::Free => &self.free_cell,
        }
    }

    /// The queue held by `cell`.
    fn queue(&self, cell: Cell) -> Option<&Queue> {
        let cell = NonZeroU32::new(self.cell_word(cell).load(Relaxed))?;
        // SAFETY: the engine allocated the cell, which stays until destroy;
        // it holds 0 or a queue the engine created, which no destroy frees
        // while the engine is in use.
        unsafe { Queue::from_handle(Self::cell(cell).load(Relaxed)) }
    }

    /// The queue cell at `address`.
    ///
    /// # Safety
    ///
    /// `address` is a cell this engine allocated and has not freed.
    unsafe fn cell<'a>(address: NonZeroU32) -> &'a AtomicU32 {
        // SAFETY: the caller guarantees the cell.
        unsafe { &*ptr::with_exposed_provenance(address.get() as usize) }
    }

    fn enqueue(&self, cell: Cell, entry: u32) -> Result<(), lockfree::Error> {
        self.queue(cell)
            .ok_or(lockfree::Error::InvalidArgument)?
            .enqueue(entry)
    }

    fn dequeue(&self, cell: Cell) -> Result<u32, lockfree::Error> {
        self.queue(cell)
            .ok_or(lockfree::Error::InvalidArgument)?
            .dequeue()
    }

    /// A free entry, or nothing (the record is dropped).
    fn take_free(&self) -> Option<NonNull<u8>> {
        self.dequeue(Cell::Free)
            .ok()
            .and_then(|entry| NonNull::new(ptr::with_exposed_provenance_mut(entry as usize)))
    }

    fn append(&self, entry: NonNull<u8>) {
        let entry = entry.as_ptr().expose_provenance() as u32;
        if self.enqueue(Cell::Pending, entry).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Queue cell of an engine.
#[derive(Clone, Copy)]
enum Cell {
    Pending,
    Free,
}

/// Allocator routines of the caller options.
#[derive(Clone, Copy)]
struct CallerAllocator {
    allocate: Routine,
    free: Option<Routine>,
    context: u32,
}

impl CallerAllocator {
    fn of(options: Option<&CreationDescriptor>) -> Option<Self> {
        let options = options?;
        Some(Self {
            allocate: options.allocate?,
            free: options.free,
            context: options.context,
        })
    }
}

fn allocate(allocator: Option<CallerAllocator>, size: u32) -> Option<NonZeroU32> {
    match allocator {
        Some(allocator) => NonZeroU32::new(allocator.allocate.call(allocator.context, size, 0, 0)),
        None => lockfree::pool_allocate(size),
    }
}

/// Free routine of the engine's memory: the caller's, or the pool's when
/// the caller options gave none.
#[derive(Clone, Copy)]
struct Release {
    routine: Option<Routine>,
    context: u32,
}

impl Release {
    /// # Safety
    ///
    /// `address` is a block of the engine's allocator that is not used
    /// after.
    unsafe fn free(self, address: NonZeroU32) {
        match self.routine {
            // SAFETY: the caller guarantees the block.
            None => unsafe { lockfree::pool_free(address) },
            Some(routine) => {
                routine.call(self.context, address.get(), 0, 0);
            }
        }
    }
}

/// Engine parameters of the create exports.
struct Request<'a> {
    processor: u32,
    /// File-name mode: the name without its NUL; none for the default
    /// name.
    name: Option<&'a [u8]>,
    context: u32,
    /// Callback mode: `callback(context, entry, entry_size)`.
    callback: Option<Routine>,
    entry_size: u32,
    entries: u32,
    block: bool,
    /// The caller options, a queue creation descriptor.
    options: Option<&'a CreationDescriptor>,
}

impl Request<'_> {
    const DEFAULT_ENTRY_SIZE: u32 = 0x100;
    const DEFAULT_ENTRIES: u32 = 0x3e8;
    const DEFAULT_PROCESSOR: u32 = 5;
    const DEFAULT_NAME: &'static CStr = c"game:\\logfile.txt";
}

/// Create an engine and store it through `output` (stock 0x91f79470).
fn create(request: &Request<'_>, output: OutputWord<'_>) -> Hresult {
    output.store(0);
    match create_engine(request) {
        Ok(engine) => {
            output.store(engine.address());
            Hresult::SUCCESS
        }
        Err(error) => Hresult::from(error),
    }
}

fn create_engine(request: &Request<'_>) -> Result<Engine, LogEngineError> {
    let processor = request.processor.min(Request::DEFAULT_PROCESSOR);
    let entry_size =
        NonZeroU32::new(request.entry_size).map_or(Request::DEFAULT_ENTRY_SIZE, NonZeroU32::get);
    let entries =
        NonZeroU32::new(request.entries).map_or(Request::DEFAULT_ENTRIES, NonZeroU32::get);
    // Stock sizes the object without an overflow check and then queues
    // entries beyond a wrapped allocation; an overflowing size is refused.
    let size = entry_size
        .checked_mul(entries)
        .and_then(|size| size.checked_add(size_of::<LogEngine>() as u32));
    let allocator = CallerAllocator::of(request.options);
    let Some(address) = size.and_then(|size| allocate(allocator, size)) else {
        return Err(LogEngineError::OutOfMemory);
    };
    let object = ptr::with_exposed_provenance_mut::<LogEngine>(address.get() as usize);
    // SAFETY: the new allocation holds the header and the entries, aligned
    // for the header (4 bytes): pool blocks are, and the export 357 and 358
    // contract requires it of a caller allocator. Zero bytes are a valid
    // header.
    let engine = unsafe {
        object.write_bytes(0, 1);
        Engine(NonNull::new_unchecked(object))
    };
    let fields = engine.get();
    if let Some(allocator) = allocator {
        fields
            .free_routine
            .store(allocator.free.map_or(0, Routine::raw), Relaxed);
        fields.free_context.store(allocator.context, Relaxed);
    }
    if request.callback.is_none() {
        let name = request.name.unwrap_or(Request::DEFAULT_NAME.to_bytes());
        // The zeroed header holds the NUL: names stop a byte short of the
        // field.
        for (slot, &byte) in fields.name.iter().zip(name) {
            slot.store(byte, Relaxed);
        }
    }
    fields.context.store(request.context, Relaxed);
    fields.entry_size.store(entry_size, Relaxed);
    fields.file.store(INVALID_HANDLE_VALUE.raw(), Relaxed);
    fields
        .callback
        .store(request.callback.map_or(0, Routine::raw), Relaxed);
    fields
        .quit_pointer
        .store(initialize_event(&fields.quit_event), Relaxed);
    fields
        .done_pointer
        .store(initialize_event(&fields.done_event), Relaxed);
    let built = build(engine, request, entry_size, entries, processor);
    if built.is_err() {
        // SAFETY: the engine is not returned.
        unsafe { destroy(engine) };
    }
    built.map(|()| engine)
}

/// Queues, free entries and worker of a new engine.
fn build(
    engine: Engine,
    request: &Request<'_>,
    entry_size: u32,
    entries: u32,
    processor: u32,
) -> Result<(), LogEngineError> {
    /// Worker thread stack (stock 0x91f82d88).
    const WORKER_STACK: u32 = 0x8000;
    /// Worker thread creation flags (stock 0x91f82d88).
    const WORKER_FLAGS: ThreadCreationFlags = ThreadCreationFlags::EXEMPT_FROM_STOPS
        .union(ThreadCreationFlags::PRIORITY_CLASS_13)
        .union(UNTESTED_FLAG);
    /// Bit 0x4, which stock sets and `ExCreateThread` does not test.
    const UNTESTED_FLAG: ThreadCreationFlags = ThreadCreationFlags::from_bits_retain(0x4);

    let fields = engine.get();
    let capacity = entries.wrapping_add(1);
    let options = request.options;
    let mut pending = seed_descriptor(options, capacity);
    pending.options.flags |= OptionFlags::REMOVE_WAITS;
    if request.block {
        pending.options.flags |= OptionFlags::INSERT_WAITS;
    }
    pending.options.remove_context = ptr::from_ref(&fields.quit_pointer).expose_provenance() as u32;
    pending.options.remove_timeout = Timeout::INFINITE;
    pending.options.remove_routine = Some(Routine::from(
        wait_for_item_or_quit as extern "C" fn(u32, u32, u32, u32) -> NtStatus,
    ));
    create_queue(&fields.pending_cell, options, pending)?;
    let mut free = seed_descriptor(options, capacity);
    if request.block {
        free.options.remove_timeout = Timeout::INFINITE;
        free.options.insert_timeout = Timeout::INFINITE;
        free.options.flags |= OptionFlags::INSERT_WAITS | OptionFlags::REMOVE_WAITS;
    }
    create_queue(&fields.free_cell, options, free)?;
    let mut entry = engine.address().wrapping_add(size_of::<LogEngine>() as u32);
    for _ in 0..(entries as i32).max(0) {
        fields
            .enqueue(Cell::Free, entry)
            .map_err(|error| LogEngineError::Queue(error.insert_result()))?;
        entry = entry.wrapping_add(entry_size);
    }
    let system =
        request.callback.is_none() || thread::current_object().process_type() != ProcessType::TITLE;
    let mut flags = ThreadCreationFlags::processors(1 << processor) | WORKER_FLAGS;
    if system {
        flags |= ThreadCreationFlags::SYSTEM_PROCESS;
    }
    // SAFETY: the handle and id outputs are words of the engine object;
    // `worker` takes the engine as its context.
    let status = unsafe {
        xboxkrnl::ExCreateThread(
            fields.worker.as_ptr(),
            WORKER_STACK,
            fields.worker_id.as_ptr(),
            0,
            worker as extern "C" fn(u32) -> u32 as usize as u32,
            engine.address(),
            flags,
        )
    };
    status.result().map_err(LogEngineError::Thread)
}

/// A queue descriptor from the caller options, with the node count of
/// `capacity`. One out-of-line copy serves both queues.
#[inline(never)]
fn seed_descriptor(options: Option<&CreationDescriptor>, capacity: u32) -> CreationDescriptor {
    // Without caller options stock seeds a zeroed descriptor.
    let mut descriptor = options.copied().unwrap_or_default();
    descriptor.per_block = capacity;
    descriptor.node_limit = capacity;
    descriptor
}

/// Create the queue whose cell `cell` holds.
fn create_queue(
    cell: &AtomicU32,
    options: Option<&CreationDescriptor>,
    mut descriptor: CreationDescriptor,
) -> Result<(), LogEngineError> {
    // Stock stores through a null cell from a caller allocator; it counts
    // as an allocation failure here.
    let address = allocate(CallerAllocator::of(options), 4);
    if let Some(address) = address {
        // SAFETY: the cell is the new allocation, 4-byte aligned (as for
        // the engine header in `create_engine`).
        unsafe { LogEngine::cell(address) }.store(0, Relaxed);
    }
    cell.store(address.map_or(0, NonZeroU32::get), Relaxed);
    let Some(address) = address else {
        return Err(LogEngineError::OutOfMemory);
    };
    // SAFETY: as above.
    let queue_cell = unsafe { LogEngine::cell(address) };
    descriptor.size = CreationDescriptor::SIZE;
    let queue = Creation::new(Some(&descriptor))
        .and_then(|creation| Queue::create_with(&creation))
        .map_err(|error| LogEngineError::Queue(error.into()))?;
    queue_cell.store(queue.get(), Relaxed);
    Ok(())
}

/// Initialize an unsignaled notification event; returns its address.
fn initialize_event(event: &Kevent) -> u32 {
    let address = event.as_ptr().expose_provenance() as u32;
    // The empty wait list links to itself.
    let list = address + 8;
    // SAFETY: the event lies in a new engine, which no other thread uses
    // yet.
    unsafe { event.as_ptr().cast::<[u32; 4]>().write([0, 0, list, list]) };
    address
}

/// Pending-queue wait routine (stock 0x91f82f80): wait for an item or for
/// the quit event, whose address the engine word at `context` holds. Wait
/// index 1 is the quit event.
extern "C" fn wait_for_item_or_quit(
    context: u32,
    semaphore: u32,
    timeout: u32,
    alertable: u32,
) -> NtStatus {
    let timeout = Timeout::from_raw(timeout);
    if timeout == Timeout::IMMEDIATE {
        return NtStatus::TIMEOUT;
    }
    let interval = timeout.interval();
    let pointer = interval.as_ref().map_or(ptr::null(), ptr::from_ref);
    // SAFETY: the pending queue of an engine passes the address of the
    // engine's quit word.
    let quit =
        unsafe { &*ptr::with_exposed_provenance::<AtomicU32>(context as usize) }.load(Relaxed);
    let objects = [
        ptr::with_exposed_provenance_mut::<DispatcherObject>(semaphore as usize),
        ptr::with_exposed_provenance_mut::<DispatcherObject>(quit as usize),
    ];
    let mut wait_blocks = [0u32; 16];
    // SAFETY: both objects are dispatcher objects of the queue and engine;
    // `interval` and `wait_blocks` outlive the wait.
    unsafe {
        xboxkrnl::KeWaitForMultipleObjects(
            2,
            objects.as_ptr(),
            WaitType::Any,
            WaitReason::UserRequest,
            ProcessorMode::Kernel,
            alertable & 0xff != 0,
            pointer,
            wait_blocks.as_mut_ptr(),
        )
    }
}

/// Worker thread (stock 0x91f78d48).
extern "C" fn worker(engine: u32) -> u32 {
    // SAFETY: `build` passes its engine, which close frees only after the
    // worker signals the done event or ends.
    let code = match unsafe { Engine::new(engine) } {
        Some(engine) => run(engine),
        None => WorkerExit::Failed,
    };
    // SAFETY: the worker owns no resources once `run` returns.
    unsafe { xboxkrnl::ExTerminateThread(code as u32) }
}

/// The worker's work. Close may free the engine once the done event is
/// signaled, so only a local reference reaches it.
fn run(engine: Engine) -> WorkerExit {
    let engine = engine.get();
    if engine.pending_cell.load(Relaxed) == 0 {
        return WorkerExit::Failed;
    }
    if engine.quit_pointer.load(Relaxed) == 0 || engine.done_pointer.load(Relaxed) == 0 {
        engine.fail(WorkerError::MissingEvent);
        return WorkerExit::Failed;
    }
    if engine.callback.load(Relaxed) == 0 {
        // SAFETY: the name field holds a NUL-terminated name.
        let file = unsafe {
            CreateFileA(
                ptr::from_ref(&engine.name).expose_provenance() as u32,
                AccessMask::GENERIC_WRITE,
                ShareAccess::empty(),
                0,
                CreationDisposition::CreateAlways,
                FileAttributes::NORMAL,
                Handle::NULL,
            )
        };
        engine.file.store(file.raw(), Relaxed);
        if file == INVALID_HANDLE_VALUE {
            engine.fail(WorkerError::NoFile);
            return WorkerExit::Failed;
        }
    }
    // Until the quit event, a failed delivery ends the worker without
    // signaling the done event.
    loop {
        let entry = match engine.dequeue(Cell::Pending) {
            Ok(entry) => entry,
            Err(error) if error == QUIT_SIGNALED => break,
            Err(_) => {
                engine.missed.fetch_add(1, Ordering::Release);
                continue;
            }
        };
        if let Err(error) = deliver(engine, entry) {
            engine.fail(error);
            return WorkerExit::Failed;
        }
        if engine.enqueue(Cell::Free, entry).is_err() {
            engine.fail(WorkerError::Requeue);
            engine.done().set();
            return WorkerExit::Failed;
        }
    }
    loop {
        let Some(pending) = engine
            .queue(Cell::Pending)
            .filter(|pending| !pending.is_empty())
        else {
            write_summary(engine);
            engine.done().set();
            return WorkerExit::Finished;
        };
        let entry = match pending.dequeue() {
            Ok(entry) if entry != 0 => entry,
            _ => continue,
        };
        if let Err(error) = deliver(engine, entry) {
            engine.fail(error);
            engine.done().set();
            return WorkerExit::Failed;
        }
        if engine.enqueue(Cell::Free, entry).is_err() {
            engine.fail(WorkerError::Requeue);
            write_summary(engine);
            engine.done().set();
            return WorkerExit::Failed;
        }
    }
}

/// Hand a pending entry to the callback, or write its text to the file.
fn deliver(engine: &LogEngine, entry: u32) -> Result<(), WorkerError> {
    let callback = engine.callback.load(Relaxed);
    let entry_size = engine.entry_size.load(Relaxed);
    // SAFETY: the callback word holds 0 or the callback the create export's
    // caller passed (export contract).
    if let Some(callback) = unsafe { Routine::new(callback) } {
        let result = Hresult(callback.call(engine.context.load(Relaxed), entry, entry_size, 0));
        return if result.is_failure() {
            Err(WorkerError::Callback(result))
        } else {
            Ok(())
        };
    }
    // Stock's strlen runs on into the following entries when the entry
    // holds no NUL; the text here ends with the entry.
    // SAFETY: a pending entry holds `entry_size` bytes after the engine
    // header and belongs to the worker until it is queued again.
    let bytes = unsafe {
        slice::from_raw_parts(
            ptr::with_exposed_provenance::<u8>(entry as usize),
            entry_size as usize,
        )
    };
    let length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    let file = Handle::from_raw(engine.file.load(Relaxed));
    write_file(file, &bytes[..length]).map_err(|_| WorkerError::Write(last_error()))
}

/// `TERMINATING LOG` line and file close of file-name mode (stock
/// 0x91f78c78).
fn write_summary(engine: &LogEngine) {
    let Some(file) = engine.file() else {
        return;
    };
    let mut text = Text::<0x60>::new();
    let _ = writeln!(
        text,
        "TERMINATING LOG: Dropped messages = {}, Missed Messages = {}",
        engine.dropped.load(Relaxed) as i32,
        engine.missed.load(Relaxed) as i32
    );
    // A failed write only records the thread's last error, as stock.
    let _ = write_file(file, text.as_bytes());
    close_handle(file);
    engine.file.store(INVALID_HANDLE_VALUE.raw(), Relaxed);
}

/// `WriteFile` without overlapped I/O (stock 0x91f73af8); a failure
/// records the thread's last error.
fn write_file(file: Handle, bytes: &[u8]) -> Result<(), KernelError> {
    let mut io_status = IoStatusBlock::default();
    // SAFETY: `bytes` is valid for its length; `io_status` outlives the
    // request, which is waited for below when pending.
    let mut status = unsafe {
        xboxkrnl::NtWriteFile(
            file,
            Handle::NULL,
            0,
            0,
            &mut io_status,
            bytes.as_ptr(),
            bytes.len() as u32,
            ptr::null(),
        )
    };
    if status == NtStatus::PENDING {
        // SAFETY: `file` is the engine's open log file.
        status = unsafe {
            xboxkrnl::NtWaitForSingleObjectEx(file, ProcessorMode::User, false, ptr::null())
        };
        if status.is_success() {
            status = io_status.status;
        }
    }
    status.result().inspect_err(|&error| set_last_error(error))
}

/// `CloseHandle` (stock 0x91f738f8).
fn close_handle(handle: Handle) {
    // SAFETY: callers pass a handle the engine owns and close once.
    if let Err(error) = unsafe { xboxkrnl::NtClose(handle) }.result() {
        set_last_error(error);
    }
}

/// Free the queues, the worker handle and the object (stock 0x91f79320).
///
/// # Safety
///
/// No thread uses `engine` or a copy of it after the call; the worker has
/// ended or never started.
unsafe fn destroy(engine: Engine) {
    // The reference is not used once the object is freed.
    let fields = engine.get();
    // SAFETY: the word holds 0 or the free routine of the caller options
    // (export contract).
    let release = Release {
        routine: unsafe { Routine::new(fields.free_routine.load(Relaxed)) },
        context: fields.free_context.load(Relaxed),
    };
    for word in [&fields.pending_cell, &fields.free_cell] {
        let Some(address) = NonZeroU32::new(word.load(Relaxed)) else {
            continue;
        };
        // SAFETY: the engine allocated the cell.
        let cell = unsafe { LogEngine::cell(address) };
        let queue = cell.load(Relaxed);
        if queue != 0 {
            // SAFETY: the engine's queue; no thread uses the engine anymore.
            unsafe { Queue::destroy(queue) };
            cell.store(0, Relaxed);
        }
        // SAFETY: the cell is not used after.
        unsafe { release.free(address) };
        word.store(0, Relaxed);
    }
    // The events need no cleanup.
    fields.quit_pointer.store(0, Relaxed);
    fields.done_pointer.store(0, Relaxed);
    let worker = fields.worker.load(Relaxed);
    if worker != 0 {
        close_handle(Handle::from_raw(worker));
        fields.worker.store(0, Relaxed);
    }
    let address = engine.0.as_ptr().expose_provenance() as u32;
    // SAFETY: the engine block is not used after; an engine is not at
    // address 0.
    unsafe { release.free(NonZeroU32::new_unchecked(address)) };
}

/// Engine of `dmtelllog`: processor 5 and `callback(context, entry,
/// entry_size)`, as stock creates it through export 356.
pub(super) fn create_for_callback(
    context: u32,
    callback: extern "C" fn(u32, u32, u32) -> Hresult,
    config: TellLogConfig,
) -> Result<Engine, LogEngineError> {
    let request = Request {
        processor: Request::DEFAULT_PROCESSOR,
        name: None,
        context,
        callback: Some(Routine::from(callback)),
        entry_size: config.entry_size,
        entries: config.entries,
        block: config.block,
        options: None,
    };
    create_engine(&request)
}

/// Stop the worker once the queued entries are processed and destroy the
/// engine. Export 360 waits for the done event, which a worker ended by a
/// callback failure never signals; this waits for the worker thread.
///
/// # Safety
///
/// No thread uses `engine` or a copy of it after the call.
pub(super) unsafe fn close_after_worker(engine: Engine) {
    let fields = engine.get();
    fields.quit().set();
    // SAFETY: the worker word holds the worker thread handle until
    // `destroy`.
    unsafe {
        xboxkrnl::NtWaitForSingleObjectEx(
            Handle::from_raw(fields.worker.load(Relaxed)),
            ProcessorMode::Kernel,
            false,
            ptr::null(),
        )
    };
    sleep(Duration::from_millis(1));
    // SAFETY: the worker has ended; the caller guarantees the rest.
    unsafe { destroy(engine) };
}

/// Thread id of the worker.
pub(super) fn worker_id(engine: Engine) -> u32 {
    engine.get().worker_id.load(Relaxed)
}

/// Copy up to an entry of `record` into a free entry and queue it (export
/// 363). Records of the worker thread itself are ignored.
pub(super) fn write(engine: Engine, record: &[u8]) {
    let fields = engine.get();
    if fields.worker_running() {
        return;
    }
    let Some(entry) = fields.take_free() else {
        fields.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let length = record.len().min(fields.entry_size.load(Relaxed) as usize);
    // SAFETY: a free entry holds `entry_size` bytes and belongs to this
    // producer until it is queued.
    unsafe { ptr::copy_nonoverlapping(record.as_ptr(), entry.as_ptr(), length) };
    fields.append(entry);
}

pub(super) fn counters(engine: Engine) -> TellLogCounters {
    let fields = engine.get();
    TellLogCounters {
        dropped: fields.dropped.load(Relaxed),
        missed: fields.missed.load(Relaxed),
    }
}

/// Format into a free entry and queue it (stock 0x91f79060 without and
/// 0x91f79160 with the worker check). Stock formats with the kernel's
/// `vsprintf` without a limit; text that does not fit the entry is cut to
/// it here.
///
/// # Safety
///
/// `format` is the address of a format string and `arguments` a va_list of
/// arguments that match it.
unsafe fn print(engine: &LogEngine, format: u32, arguments: u32) {
    let Some(entry) = engine.take_free() else {
        engine.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let entry_size = engine.entry_size.load(Relaxed);
    // SAFETY: the free entry holds `entry_size` bytes and belongs to this
    // producer; the caller guarantees the format and the va_list.
    let length = unsafe { xboxkrnl::_vsnprintf(entry.as_ptr(), entry_size, format, arguments) };
    if length < 0 || length as u32 >= entry_size {
        // SAFETY: the last byte of the entry.
        unsafe { entry.add(entry_size as usize - 1).write(0) };
    }
    engine.append(entry);
}

/// The caller options at `address`, a queue creation descriptor; none for
/// 0.
///
/// # Safety
///
/// `address` is 0 or the address of a creation descriptor that stays
/// unchanged for `'a`, whose routine fields hold console routines; its
/// allocate routine, if any, returns 4-byte aligned blocks.
unsafe fn caller_options<'a>(address: u32) -> Option<&'a CreationDescriptor> {
    // SAFETY: the caller guarantees the descriptor.
    unsafe { ptr::with_exposed_provenance::<CreationDescriptor>(address as usize).as_ref() }
}

/// Export 355: export 357 without options.
extern "C" fn create_file_log(
    processor: u32,
    name: u32,
    entry_size: u32,
    entries: u32,
    block: u32,
    output: u32,
) -> Hresult {
    create_file_log_with_options(processor, name, entry_size, entries, block, 0, output)
}
export!(355, create_file_log);

/// Export 356: export 358 without options.
extern "C" fn create_callback_log(
    processor: u32,
    context: u32,
    callback: u32,
    entry_size: u32,
    entries: u32,
    block: u32,
    output: u32,
) -> Hresult {
    create_callback_log_with_options(
        processor, context, callback, entry_size, entries, block, 0, output,
    )
}
export!(356, create_callback_log);

#[inline(never)]
extern "C" fn create_file_log_with_options(
    processor: u32,
    name: u32,
    entry_size: u32,
    entries: u32,
    block: u32,
    options: u32,
    output_word: u32,
) -> Hresult {
    // SAFETY: export 357 contract: `output_word` is 0 or a writable word.
    let Some(output_word) = (unsafe { OutputWord::new(output_word) }) else {
        return Hresult::INVALID_ARGUMENT;
    };
    // SAFETY: export 357 contract: `name` is 0 or a NUL-terminated file
    // name and `options` 0 or a creation descriptor whose allocator returns
    // 4-byte aligned blocks.
    let (name, options) = unsafe {
        (
            kernel::bounded_c_string(name, NAME_CAPACITY - 1),
            caller_options(options),
        )
    };
    let request = Request {
        processor,
        name,
        context: 0,
        callback: None,
        entry_size,
        entries,
        block: block != 0,
        options,
    };
    create(&request, output_word)
}
export!(357, create_file_log_with_options);

#[allow(clippy::too_many_arguments)]
#[inline(never)]
extern "C" fn create_callback_log_with_options(
    processor: u32,
    context: u32,
    callback: u32,
    entry_size: u32,
    entries: u32,
    block: u32,
    options: u32,
    output_word: u32,
) -> Hresult {
    // SAFETY: export 358 contract: `output_word` is 0 or a writable word.
    let Some(output_word) = (unsafe { OutputWord::new(output_word) }) else {
        return Hresult::INVALID_ARGUMENT;
    };
    // SAFETY: export 358 contract: `callback` is 0 or a console routine and
    // `options` 0 or a creation descriptor whose allocator returns 4-byte
    // aligned blocks.
    let (callback, options) = unsafe { (Routine::new(callback), caller_options(options)) };
    let request = Request {
        processor,
        name: None,
        context,
        callback,
        entry_size,
        entries,
        block: block != 0,
        options,
    };
    create(&request, output_word)
}
export!(358, create_callback_log_with_options);

/// Stop the worker once the queued entries are processed, wait for the
/// done event and destroy the engine (stock 0x91f79998).
extern "C" fn close(engine: u32) {
    // SAFETY: export 360 contract: `engine` is 0 or an engine of the create
    // exports, which no other call uses during or after this one.
    let Some(engine) = (unsafe { Engine::new(engine) }) else {
        return;
    };
    let fields = engine.get();
    fields.quit().set();
    let done = fields.done();
    // SAFETY: the done pointer word held the engine's initialized event.
    let status = unsafe {
        xboxkrnl::KeWaitForSingleObject(
            done.as_dispatcher(),
            WaitReason::UserRequest,
            ProcessorMode::Kernel,
            false,
            ptr::null(),
        )
    };
    if status != NtStatus::WAIT_0 {
        return;
    }
    sleep(Duration::from_millis(1));
    // SAFETY: the worker has signaled the done event; the export contract
    // covers the rest.
    unsafe { destroy(engine) };
}
export!(360, close);

/// `(engine, format, va_list)` of export 361 (stock 0x91f79060).
extern "C" fn print_arguments(engine: u32, format: u32, arguments: u32) {
    // SAFETY: export 361 contract: `engine` is 0 or an engine of the create
    // exports.
    let Some(engine) = (unsafe { Engine::new(engine) }) else {
        return;
    };
    // SAFETY: export 361 contract: `format` is a format string and the
    // arguments match it.
    unsafe { print(engine.get(), format, arguments) };
}

/// Export 361 `(engine, format, ...)`: store r5-r10 in the caller's home
/// slots (sp+0x20..sp+0x48), which precede the stack arguments, and pass
/// their address as the va_list.
#[unsafe(naked)]
unsafe extern "C" fn print_entry() {
    core::arch::naked_asm!(
        ".irp reg, 5,6,7,8,9,10",
        // std \reg, 0x10 + 8 * (\reg - 3)(r1)
        ".long (62 << 26) | (\\reg << 21) | (1 << 16) | (8 * \\reg - 8)",
        ".endr",
        "addi 5, 1, 0x20",
        "lis 12, {target}@ha",
        "addi 12, 12, {target}@l",
        "b {bridge}",
        target = sym print_arguments,
        bridge = sym crate::exports::export_bridge,
    )
}
export_raw!(361, print_entry);

/// Export 362 `(engine, format, va_list)` (stock 0x91f79160).
extern "C" fn print_list(engine: u32, format: u32, arguments: u32) {
    // SAFETY: export 362 contract: `engine` is 0 or an engine of the create
    // exports.
    let Some(engine) = (unsafe { Engine::new(engine) }) else {
        return;
    };
    let fields = engine.get();
    if !fields.worker_running() {
        // SAFETY: export 362 contract: `format` is a format string and
        // `arguments` a va_list that matches it.
        unsafe { print(fields, format, arguments) };
    }
}
export!(362, print_list);

extern "C" fn write_export(engine: u32, data: u32, length: u32) {
    // SAFETY: export 363 contract: `engine` is 0 or an engine of the create
    // exports.
    let Some(engine) = (unsafe { Engine::new(engine) }) else {
        return;
    };
    let Some(data) = NonNull::new(ptr::with_exposed_provenance_mut::<u8>(data as usize)) else {
        return;
    };
    // Stock copies at most an entry.
    let length = length.min(engine.get().entry_size.load(Relaxed));
    // SAFETY: export 363 contract: `data` holds `length` bytes.
    let record = unsafe { slice::from_raw_parts(data.as_ptr(), length as usize) };
    write(engine, record);
}
export!(363, write_export);

extern "C" fn counters_export(engine: u32, dropped: u32, missed: u32) {
    // SAFETY: export 364 contract: `engine` is 0 or an engine of the create
    // exports.
    let Some(engine) = (unsafe { Engine::new(engine) }) else {
        return;
    };
    let fields = engine.get();
    // SAFETY: export 364 contract: `dropped` is 0 or a writable word.
    if let Some(dropped) = unsafe { OutputWord::new(dropped) } {
        dropped.store(fields.dropped.load(Relaxed));
    }
    // SAFETY: export 364 contract: `missed` is 0 or a writable word.
    if let Some(missed) = unsafe { OutputWord::new(missed) } {
        missed.store(fields.missed.load(Relaxed));
    }
}
export!(364, counters_export);
