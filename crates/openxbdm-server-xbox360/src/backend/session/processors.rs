//! Command processors other modules register (stock dmserv.c: registry
//! 0x91f9ff98 under critical section 0x91facee0, exports 30 and 72) and the
//! threads their handlers run on: the server thread for system processors,
//! one title command thread for title processors (stock 0x91f42aa0), and a
//! thread per connection dedicated to a processor with its own thread
//! (stock 0x91f50b98).
//!
//! Handlers and continuations use the monitor's call convention: a handler
//! is `handler(line, response, 0x1fb, context)` and a continuation
//! `continuation(context, response, 0x100)`, with the context of stock
//! connection +0x228. A call on another thread that does not end within
//! `FAST_WAIT` continues in the background; the server's pass completes it
//! once it has ended, so a handler can use services that need the server
//! thread.

use core::cell::UnsafeCell;
use core::fmt::Write as _;
use core::num::NonZeroU32;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::ConnectionIndex;
use openxbdm_server::Server;
use openxbdm_server::SocketId;
use openxbdm_server::commands::console::TraceMask;
use openxbdm_server::processors::ExternalContinuation;
use openxbdm_server::processors::ExternalTransfer;
use openxbdm_server::processors::PROCESSOR_NAME_CAPACITY;
use openxbdm_server::processors::Processor;
use openxbdm_server::processors::ProcessorBackend;
use openxbdm_server::processors::ProcessorCall;
use openxbdm_server::processors::ProcessorFlags;
use openxbdm_server::processors::ProcessorHandle;
use openxbdm_server::processors::ProcessorProgress;
use openxbdm_server::processors::ProcessorThread;
use openxbdm_server::processors::Processors;
use openxbdm_server::server::MAX_CONNECTIONS;
use openxbdm_server::server::Owner;
use openxbdm_server::text::ResponseText;
use openxbdm_server::text::Text;
use xbox360::thread::current_object;
use xbox360::time::TickCount;
use xbox360::time::relative_interval;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::KeResumeThread;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;
use xbox360_sys::xboxkrnl::WaitType;

use super::super::Console;
use super::CriticalSection;
use super::until_nul;
use crate::exports::export;
use crate::kernel;
use crate::kernel::KernelEvent;
use crate::net::XamNetwork;

/// Size of a handler's reply text.
const HANDLER_RESPONSE_SIZE: u32 = 0x1fb;
/// Size of a continuation's reply text and of its default data buffer.
const CONTINUATION_BUFFER_SIZE: u32 = 0x100;
/// Command line buffer; a line plus CR LF fits the receive buffer.
const LINE_SIZE: usize = 0x200;
/// Scratch area a context points at (stock connection +0x240).
const SCRATCH_SIZE: usize = 0x58;

/// `ExCreateThread` flags of the title command thread and of dedicated
/// threads (stock 0x91f50500, 0x91f51730); a thread of the system process
/// adds [`ThreadCreationFlags::SYSTEM_PROCESS`]. Bit 0x4 has no name: no
/// kernel code tests it, and it passes on as stock sets it.
const THREAD_FLAGS: ThreadCreationFlags = ThreadCreationFlags::SUSPENDED
    .union(ThreadCreationFlags::RETURN_THREAD_OBJECT)
    .union(ThreadCreationFlags::EXEMPT_FROM_STOPS)
    .union(ThreadCreationFlags::PROCESSOR2)
    .union(ThreadCreationFlags::PRIORITY_CLASS_13)
    .union(ThreadCreationFlags::from_bits_retain(0x4));
const _: () = assert!(THREAD_FLAGS.bits() == 0x0400_02a5);
const THREAD_STACK_SIZE: u32 = 0x8000;
/// Executor context of the title command thread; dedicated threads get
/// their connection index.
const TITLE_EXECUTOR: u8 = MAX_CONNECTIONS as u8;
/// The title command thread ends after this long without a title-owned
/// connection (stock 0x91f42b98 waits 30 s).
const TITLE_IDLE_MILLISECONDS: u32 = 30_000;
/// How long the server thread waits for a call before it continues with
/// other work; one pass of its loop.
const FAST_WAIT: i64 = relative_interval(core::time::Duration::from_millis(20));
const NO_WAIT: i64 = 0;

/// Registry entries (stock 0x91f9ff98, 16 pool records of 0x48 bytes).
struct Registry {
    lock: CriticalSection,
    processors: UnsafeCell<Processors>,
}

// SAFETY: `processors` is only accessed with the critical section held.
unsafe impl Sync for Registry {}

impl Registry {
    fn with<R>(&self, operation: impl FnOnce(&mut Processors) -> R) -> R {
        self.lock.enter();
        // SAFETY: the critical section is held.
        let result = operation(unsafe { &mut *self.processors.get() });
        self.lock.leave();
        result
    }
}

static REGISTRY: Registry = Registry {
    lock: CriticalSection::new(),
    processors: UnsafeCell::new(Processors::new()),
};

/// Prepare the registry, the call slots, and the executors; called once at
/// module start.
pub(super) fn initialize() {
    REGISTRY.lock.initialize();
    for slot in &SLOTS {
        slot.done.initialize();
    }
    for executor in &EXECUTORS {
        executor.work.initialize();
    }
}

export!(30, register_processor);
export!(72, register_processor_ex);

/// Export 30 (stock 0x91f51438): export 72 without a dedicated thread.
extern "C" fn register_processor(name: u32, handler: u32) -> Hresult {
    register_processor_ex(name, handler, 0)
}

/// Export 72 (stock 0x91f431e8): register `handler` under `name`, or
/// unregister every processor named `name` when `handler` is null. A
/// nonzero `dedicated` runs connections dedicated to the processor on
/// their own thread.
extern "C" fn register_processor_ex(name: u32, handler: u32, dedicated: u32) -> Hresult {
    // One byte past the longest stored name tells an overlong name apart.
    // SAFETY: callers pass 0 or a NUL-terminated name.
    let Some(name) = (unsafe { kernel::bounded_c_string(name, PROCESSOR_NAME_CAPACITY + 1) })
    else {
        return Hresult::INVALID_ARGUMENT;
    };
    let mut flags = ProcessorFlags::empty();
    if xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE {
        flags = flags.union(ProcessorFlags::TITLE);
    }
    if dedicated != 0 {
        flags = flags.union(ProcessorFlags::DEDICATED_THREAD);
    }
    // SAFETY: export callers pass 0 or a processor function that stays
    // loaded while registered and while its calls run, the stock contract.
    let handler = (handler != 0).then(|| unsafe { ProcessorHandle::from_raw(handler) });
    crate::exports::export_result(
        REGISTRY.with(|processors| processors.register(name, handler, flags)),
    )
}

/// Monitor control code 0x1c (stock 0x91f3b6c0): register the `PIX`
/// processor through export 30.
///
/// # Safety
///
/// `handler` must be 0 or a processor function that stays loaded while
/// registered and while its calls run.
pub(crate) unsafe fn service_register_pix_processor(handler: u32) -> u32 {
    register_processor(c"PIX".as_ptr() as usize as u32, handler).0
}

/// Record of monitor control code 0x32.
#[repr(C)]
struct ProcessorRegistration {
    name: u32,
    handler: u32,
}

/// Monitor control code 0x32 (stock 0x91f3b8a4): export 30 with a
/// [`ProcessorRegistration`].
///
/// # Safety
///
/// `argument` must be the address of a [`ProcessorRegistration`] whose
/// name is 0 or a NUL-terminated string and whose handler is 0 or a
/// processor function that stays loaded while registered and while its
/// calls run, unchanged for the call.
pub(crate) unsafe fn service_register_processor(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let registration = unsafe { kernel::object_at::<ProcessorRegistration>(argument) };
    register_processor(registration.name, registration.handler).0
}

/// Context of a handler call (stock connection +0x228, handler argument 4).
#[repr(C)]
struct Context {
    /// Continuation routine; 0 when none.
    continuation: u32,
    /// Bytes in `buffer`, or [`Context::TEXT_LINE`].
    count: u32,
    /// Data buffer; 0 makes the transfer pump supply one.
    buffer: u32,
    size: u32,
    scratch: u32,
    /// Bytes still expected in a 204 upload, or [`Context::NOT_RECEIVING`].
    remaining: u32,
}

/// What a continuation left in its data buffer.
#[derive(Clone, Copy)]
enum ContinuationData {
    /// One NUL-terminated line.
    Line,
    Bytes(u32),
    Nothing,
}

impl Context {
    /// `count`: the data buffer holds one NUL-terminated line.
    const TEXT_LINE: u32 = u32::MAX;
    /// `remaining` outside a 204 upload.
    const NOT_RECEIVING: u32 = u32::MAX;

    #[inline(always)]
    fn data(&self) -> ContinuationData {
        match self.count {
            Self::TEXT_LINE => ContinuationData::Line,
            0 => ContinuationData::Nothing,
            count => ContinuationData::Bytes(count),
        }
    }
}

/// Memory a call reads and writes; handlers and continuations get
/// pointers into it.
#[repr(C)]
struct CallBlock {
    context: Context,
    scratch: [u8; SCRATCH_SIZE],
    /// Command line of a handler call, or the default data buffer of a
    /// continuation call.
    line: [u8; LINE_SIZE],
    /// Reply text of the call.
    response: [u8; HANDLER_RESPONSE_SIZE as usize],
}

/// Call state of a connection slot.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum CallSlotState {
    Idle = 0,
    Posted = 1,
    Running = 2,
    Finished = 3,
    /// The thread of a posted or running call ended without finishing it.
    Lost = 4,
}

/// Word of a [`CallSlotState`]; only these methods store it.
#[repr(transparent)]
struct SlotState(AtomicU32);

impl SlotState {
    const fn new() -> Self {
        Self(AtomicU32::new(CallSlotState::Idle as u32))
    }

    #[inline(always)]
    fn load(&self, order: Ordering) -> CallSlotState {
        let raw = self.0.load(order);
        // SAFETY: the word only ever holds a `CallSlotState` value.
        unsafe { core::mem::transmute::<u32, CallSlotState>(raw) }
    }

    #[inline(always)]
    fn store(&self, state: CallSlotState, order: Ordering) {
        self.0.store(state as u32, order);
    }

    /// Compare-exchange from `from` to `to`; the failure ordering is
    /// relaxed.
    #[inline(always)]
    fn transition(&self, from: CallSlotState, to: CallSlotState, success: Ordering) -> bool {
        self.0
            .compare_exchange(from as u32, to as u32, success, Ordering::Relaxed)
            .is_ok()
    }
}

/// Call state of one connection slot.
struct Slot {
    block: UnsafeCell<CallBlock>,
    state: SlotState,
    /// Tag of the executor thread the call is posted to.
    executor: AtomicU32,
    routine: AtomicU32,
    arguments: [AtomicU32; 4],
    result: AtomicU32,
    done: KernelEvent,
}

// SAFETY: the block is written by the server thread while the slot is idle
// and by the executor while the call runs; `state` orders the hand-offs.
unsafe impl Sync for Slot {}

impl Slot {
    fn block(&self) -> *mut CallBlock {
        self.block.get()
    }

    fn context(&self) -> *mut Context {
        // SAFETY: field projection of the slot's block.
        unsafe { &raw mut (*self.block()).context }
    }

    fn line_address(&self) -> u32 {
        // SAFETY: field projection of the slot's block.
        unsafe { &raw mut (*self.block()).line as usize as u32 }
    }

    fn response_address(&self) -> u32 {
        // SAFETY: field projection of the slot's block.
        unsafe { &raw mut (*self.block()).response as usize as u32 }
    }

    fn scratch_address(&self) -> u32 {
        // SAFETY: field projection of the slot's block.
        unsafe { &raw mut (*self.block()).scratch as usize as u32 }
    }

    fn busy(&self) -> bool {
        matches!(
            self.state.load(Ordering::Acquire),
            CallSlotState::Posted | CallSlotState::Running
        )
    }
}

static SLOTS: [Slot; MAX_CONNECTIONS] = [const {
    Slot {
        block: UnsafeCell::new(CallBlock {
            context: Context {
                continuation: 0,
                count: 0,
                buffer: 0,
                size: 0,
                scratch: 0,
                remaining: Context::NOT_RECEIVING,
            },
            scratch: [0; SCRATCH_SIZE],
            line: [0; LINE_SIZE],
            response: [0; HANDLER_RESPONSE_SIZE as usize],
        }),
        state: SlotState::new(),
        executor: AtomicU32::new(0),
        routine: AtomicU32::new(0),
        arguments: [const { AtomicU32::new(0) }; 4],
        result: AtomicU32::new(0),
        done: KernelEvent::new(),
    }
}; MAX_CONNECTIONS];

/// Wake-up event of an executor and the generation of its current thread;
/// a thread whose generation is no longer current exits.
struct Executor {
    work: KernelEvent,
    generation: AtomicU32,
}

static EXECUTORS: [Executor; MAX_CONNECTIONS + 1] = [const {
    Executor {
        work: KernelEvent::new(),
        generation: AtomicU32::new(0),
    }
}; MAX_CONNECTIONS + 1];

/// Context of an executor thread: the executor index in the low byte and
/// the generation of the thread above it, modulo 2^24.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ThreadTag(u32);

impl ThreadTag {
    const GENERATION_SHIFT: u32 = 8;

    #[inline(always)]
    const fn new(context: u8, generation: u32) -> Self {
        Self(context as u32 | generation << Self::GENERATION_SHIFT)
    }

    #[inline(always)]
    const fn context(self) -> usize {
        (self.0 & ((1 << Self::GENERATION_SHIFT) - 1)) as usize
    }

    /// Whether an executor's generation counter names this tag's thread.
    #[inline(always)]
    const fn is_generation(self, generation: u32) -> bool {
        generation & (u32::MAX >> Self::GENERATION_SHIFT) == self.0 >> Self::GENERATION_SHIFT
    }
}

/// Trace text of the title command thread, under trace mask bit 0x1 (stock
/// 0x91f504d8, 0x91f42ae8, 0x91f43104): `text`, then `0x%08x` of `thread`
/// and a line end when there is one.
fn trace_title_thread(text: &str, thread: Option<u32>) {
    if super::super::console::trace_mask().contains(TraceMask::REPLIES) {
        let mut line = Text::<0x40>::new();
        let _ = line.push_bytes(text.as_bytes());
        if let Some(thread) = thread {
            let _ = writeln!(line, "0x{thread:08x}");
        }
        kernel::debug_print_bytes(line.as_bytes());
    }
}

/// Executor thread: run the calls posted to it, in connection order.
extern "C" fn executor_thread(tag: u32) -> u32 {
    // `ExecutorThread::start` passes the thread's tag as its context.
    let tag = ThreadTag(tag);
    let title = tag.context() == usize::from(TITLE_EXECUTOR);
    if title {
        trace_title_thread(
            "XBDM: New title command processor thread = ",
            Some(current_object().raw()),
        );
    }
    let executor = &EXECUTORS[tag.context()];
    let current = || tag.is_generation(executor.generation.load(Ordering::Acquire));
    loop {
        executor.work.wait();
        while current()
            && let Some(slot) = SLOTS.iter().find(|slot| {
                slot.executor.load(Ordering::Acquire) == tag.0
                    && slot.state.transition(
                        CallSlotState::Posted,
                        CallSlotState::Running,
                        Ordering::AcqRel,
                    )
            })
        {
            let argument = |index: usize| slot.arguments[index].load(Ordering::Relaxed);
            // SAFETY: the routine is a handler or continuation of a
            // registered processor, called with the monitor's arguments.
            let result = unsafe {
                kernel::call_export(
                    slot.routine.load(Ordering::Relaxed),
                    argument(0),
                    argument(1),
                    argument(2),
                    argument(3),
                )
            };
            slot.result.store(result, Ordering::Relaxed);
            slot.state.store(CallSlotState::Finished, Ordering::Release);
            slot.done.set();
        }
        if !current() {
            // The wake-up may have been meant for the executor's next thread.
            executor.work.set();
            if title {
                trace_title_thread(
                    "XBDM: Terminating title command processor thread=",
                    Some(current_object().raw()),
                );
            }
            return 0;
        }
    }
}

/// An executor thread: its referenced kernel thread object and its tag.
#[derive(Debug, PartialEq, Eq)]
struct ExecutorThread {
    object: NonZeroU32,
    tag: ThreadTag,
}

impl ExecutorThread {
    fn start(context: u8, title: bool) -> Option<Self> {
        let executor = &EXECUTORS[usize::from(context)];
        let generation = executor.generation.load(Ordering::Acquire).wrapping_add(1);
        executor.generation.store(generation, Ordering::Release);
        let tag = ThreadTag::new(context, generation);
        let flags = if title {
            THREAD_FLAGS
        } else {
            THREAD_FLAGS | ThreadCreationFlags::SYSTEM_PROCESS
        };
        let mut object = 0u32;
        // SAFETY: `object` is a local word; `executor_thread` takes the tag
        // as its context.
        let status = unsafe {
            xboxkrnl::ExCreateThread(
                &mut object,
                THREAD_STACK_SIZE,
                core::ptr::null_mut(),
                0,
                executor_thread as *const () as usize as u32,
                tag.0,
                flags,
            )
        };
        if !status.is_success() {
            return None;
        }
        let object = NonZeroU32::new(object)?;
        // SAFETY: `object` is the referenced, suspended thread created above.
        unsafe { KeResumeThread(object.get() as usize as *mut xboxkrnl::Kthread) };
        Some(Self { object, tag })
    }

    fn ended(&self) -> bool {
        // SAFETY: `object` is the referenced thread object `self` owns.
        let status = unsafe {
            xboxkrnl::KeWaitForSingleObject(
                self.object.get() as usize as *mut xboxkrnl::DispatcherObject,
                WaitReason::Executive,
                ProcessorMode::Kernel,
                false,
                &NO_WAIT,
            )
        };
        status == NtStatus::WAIT_0
    }

    /// Whether a call posted to this thread is waiting or running.
    fn busy(&self) -> bool {
        SLOTS
            .iter()
            .any(|slot| slot.executor.load(Ordering::Acquire) == self.tag.0 && slot.busy())
    }

    /// Ask the thread to exit after its current call.
    fn retire(&self) {
        let executor = &EXECUTORS[self.tag.context()];
        executor.generation.fetch_add(1, Ordering::AcqRel);
        executor.work.set();
    }

    /// Wait for a retired thread to exit and release the object.
    fn join(self) {
        let object = self.object.get();
        // SAFETY: `object` is the referenced thread object `self` owned; the
        // reference is dropped once.
        unsafe {
            xboxkrnl::KeWaitForSingleObject(
                object as usize as *mut xboxkrnl::DispatcherObject,
                WaitReason::Executive,
                ProcessorMode::Kernel,
                false,
                core::ptr::null(),
            );
            xboxkrnl::ObDereferenceObject(object);
        }
    }

    /// Make an idle thread exit and release the object.
    fn stop(self) {
        self.retire();
        self.join();
    }

    /// Stop an idle thread; a busy one is asked to exit after its call and
    /// kept in `retired` until it does.
    fn release(self, retired: &mut [Option<ExecutorThread>; MAX_CONNECTIONS + 1]) {
        if self.busy() {
            self.retire();
            let slot = &mut retired[self.tag.context()];
            if let Some(older) = slot.replace(self) {
                older.join();
            }
        } else {
            self.stop();
        }
    }

    /// Release a thread that ended; its posted and running calls are lost.
    fn release_ended(self) {
        for slot in &SLOTS {
            if slot.executor.load(Ordering::Acquire) == self.tag.0 && slot.busy() {
                slot.state.store(CallSlotState::Lost, Ordering::Release);
            }
        }
        // SAFETY: `self` owns the reference and is consumed here.
        unsafe { xboxkrnl::ObDereferenceObject(self.object.get()) };
    }
}

/// Transfer of an external processor on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Idle,
    /// 202: lines.
    Lines,
    /// 203: binary output.
    Binary,
    /// 204: upload.
    Upload,
}

/// Output of one continuation call still to be passed to the server.
#[derive(Debug, Clone, Copy)]
struct Output {
    address: u32,
    length: u32,
    /// `length`, plus 2 when CR LF follows the bytes.
    total: u32,
    passed: u32,
}

impl Output {
    /// Copy the next bytes into `binary` and store their count in
    /// `binary_len`; the output while bytes remain.
    fn pass(mut self, binary: &mut [u8], binary_len: &mut usize) -> Option<Self> {
        let mut written = 0;
        if self.passed < self.length {
            let count = ((self.length - self.passed) as usize).min(binary.len());
            // SAFETY: the processor's buffer holds `length` bytes.
            let source = unsafe {
                core::slice::from_raw_parts(
                    (self.address + self.passed) as usize as *const u8,
                    count,
                )
            };
            binary[..count].copy_from_slice(source);
            written = count;
            self.passed += count as u32;
        }
        while written < binary.len() && self.passed < self.total {
            binary[written] = b"\r\n"[(self.passed - self.length) as usize];
            written += 1;
            self.passed += 1;
        }
        *binary_len = written;
        (self.passed < self.total).then_some(self)
    }
}

/// Which call of a connection runs in the background.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InFlight {
    Handler,
    Continuation { aborted: bool },
}

#[derive(Debug, Clone, Copy)]
struct ConnectionCalls {
    mode: Mode,
    output: Option<Output>,
    in_flight: Option<InFlight>,
}

#[derive(Debug)]
struct DedicatedThread {
    thread: ExecutorThread,
    title: bool,
    /// Socket and owner of the connection at the first pass after the
    /// thread started; the thread ends when they change.
    seen: Option<(SocketId, Owner)>,
}

/// Processor state owned by the server thread.
#[derive(Debug)]
pub struct Data {
    connections: [ConnectionCalls; MAX_CONNECTIONS],
    title: Option<ExecutorThread>,
    /// Tick count since which no connection is title-owned.
    title_idle_since: Option<u32>,
    dedicated: [Option<DedicatedThread>; MAX_CONNECTIONS],
    /// Threads asked to exit while a call ran, per executor context.
    retired: [Option<ExecutorThread>; MAX_CONNECTIONS + 1],
}

/// How a call started.
enum Started {
    /// The routine's result.
    Finished(Hresult),
    Running,
    /// No thread could run the call.
    Unavailable,
}

/// Outcome of a background call.
enum Taken {
    Returned(Hresult),
    Lost,
}

fn take_result(slot: &Slot) -> Option<Taken> {
    match slot.state.load(Ordering::Acquire) {
        CallSlotState::Finished => {
            let result = Hresult(slot.result.load(Ordering::Relaxed));
            slot.state.store(CallSlotState::Idle, Ordering::Release);
            Some(Taken::Returned(result))
        }
        CallSlotState::Lost => {
            slot.state.store(CallSlotState::Idle, Ordering::Release);
            Some(Taken::Lost)
        }
        _ => None,
    }
}

impl Data {
    pub const fn new() -> Self {
        Self {
            connections: [ConnectionCalls {
                mode: Mode::Idle,
                output: None,
                in_flight: None,
            }; MAX_CONNECTIONS],
            title: None,
            title_idle_since: None,
            dedicated: [const { None }; MAX_CONNECTIONS],
            retired: [const { None }; MAX_CONNECTIONS + 1],
        }
    }

    /// Thread for a call on `thread`, started when needed; `None` on the
    /// server thread or when no thread could be started.
    fn executor(&mut self, slot: usize, thread: ProcessorThread) -> Option<&ExecutorThread> {
        match thread {
            ProcessorThread::Server => None,
            ProcessorThread::Title => {
                if let Some(ended) = self.title.take_if(|thread| thread.ended()) {
                    ended.release_ended();
                }
                if self.title.is_none() {
                    trace_title_thread("XBDM: Creating new title command processor thread\n", None);
                    self.title = Some(ExecutorThread::start(TITLE_EXECUTOR, true)?);
                }
                self.title.as_ref()
            }
            ProcessorThread::Dedicated { title } => {
                let dedicated = &mut self.dedicated[slot];
                if let Some(ended) = dedicated.take_if(|dedicated| dedicated.thread.ended()) {
                    ended.thread.release_ended();
                }
                if let Some(other) = dedicated.take_if(|dedicated| dedicated.title != title) {
                    other.thread.stop();
                }
                if dedicated.is_none() {
                    let thread = ExecutorThread::start(slot as u8, title)?;
                    *dedicated = Some(DedicatedThread {
                        thread,
                        title,
                        seen: None,
                    });
                }
                dedicated.as_ref().map(|dedicated| &dedicated.thread)
            }
        }
    }

    /// Run `routine(arguments)` for the connection in `slot` on `thread`.
    fn start(
        &mut self,
        slot: usize,
        thread: ProcessorThread,
        routine: u32,
        arguments: [u32; 4],
    ) -> Started {
        let Some(executor) = self.executor(slot, thread) else {
            if thread != ProcessorThread::Server {
                return Started::Unavailable;
            }
            let [first, second, third, fourth] = arguments;
            // SAFETY: the routine is a handler or continuation of a
            // registered processor, called with the monitor's arguments.
            return Started::Finished(Hresult(unsafe {
                kernel::call_export(routine, first, second, third, fourth)
            }));
        };
        let (tag, object) = (executor.tag, executor.object.get());
        let call = &SLOTS[slot];
        call.executor.store(tag.0, Ordering::Relaxed);
        call.routine.store(routine, Ordering::Relaxed);
        for (stored, &argument) in call.arguments.iter().zip(&arguments) {
            stored.store(argument, Ordering::Relaxed);
        }
        call.done.reset();
        call.state.store(CallSlotState::Posted, Ordering::Release);
        EXECUTORS[tag.context()].work.set();
        let objects = [call.done.pointer() as usize as u32, object];
        let mut wait_blocks = [0u32; 0x10];
        loop {
            // SAFETY: the slot's event and the executor thread are live
            // dispatcher objects; `wait_blocks` outlives the wait.
            let status = unsafe {
                xboxkrnl::KeWaitForMultipleObjects(
                    2,
                    objects.as_ptr().cast(),
                    WaitType::Any,
                    WaitReason::Executive,
                    ProcessorMode::Kernel,
                    false,
                    &FAST_WAIT,
                    wait_blocks.as_mut_ptr(),
                )
            };
            return match take_result(call) {
                Some(Taken::Returned(result)) => Started::Finished(result),
                Some(Taken::Lost) => Started::Unavailable,
                None if status == NtStatus::TIMEOUT => Started::Running,
                // A late signal of the slot's previous call.
                None if status == NtStatus::WAIT_0 => continue,
                // The thread ended (the title process went away) before the
                // call finished.
                None => {
                    self.find_lost_calls();
                    take_result(call);
                    Started::Unavailable
                }
            };
        }
    }

    /// Stop threads no connection needs: a dedicated thread whose
    /// connection closed or changed, and the title command thread after
    /// `TITLE_IDLE_MILLISECONDS` without a title-owned connection.
    fn retain(&mut self, connections: &[Option<(SocketId, Owner)>; MAX_CONNECTIONS]) {
        for (connection, slot) in connections.iter().zip(&mut self.dedicated) {
            let Some(dedicated) = slot.as_mut() else {
                continue;
            };
            let keep = match (connection, dedicated.seen) {
                (Some((_, Owner::Processor(_))), None) => {
                    dedicated.seen = *connection;
                    true
                }
                (Some(current), Some(seen)) => *current == seen,
                _ => false,
            };
            if let Some(unneeded) = slot.take_if(|dedicated| !keep && !dedicated.thread.busy()) {
                unneeded.thread.stop();
            }
        }
        if connections
            .iter()
            .any(|connection| matches!(connection, Some((_, Owner::Title))))
        {
            self.title_idle_since = None;
        } else if self.title.as_ref().is_some_and(|thread| !thread.busy()) {
            let now = TickCount::now().milliseconds();
            let since = *self.title_idle_since.get_or_insert(now);
            if now.wrapping_sub(since) >= TITLE_IDLE_MILLISECONDS {
                self.title_idle_since = None;
                if let Some(thread) = self.title.take() {
                    thread.stop();
                }
            }
        }
    }

    /// Mark the calls of threads that ended as lost, and release retired
    /// threads that finished their call.
    fn find_lost_calls(&mut self) {
        if let Some(ended) = self.title.take_if(|thread| thread.ended()) {
            ended.release_ended();
        }
        for dedicated in &mut self.dedicated {
            if let Some(ended) = dedicated.take_if(|dedicated| dedicated.thread.ended()) {
                ended.thread.release_ended();
            }
        }
        for retired in &mut self.retired {
            if let Some(ended) = retired.take_if(|thread| thread.ended()) {
                ended.release_ended();
            } else if let Some(idle) = retired.take_if(|thread| !thread.busy()) {
                idle.join();
            }
        }
    }

    /// The title process ended (stock 0x91f42850 forgets the title command
    /// thread). Its threads are normally gone; one still running a call
    /// exits after it.
    fn release_title_threads(&mut self) {
        self.find_lost_calls();
        self.title_idle_since = None;
        if let Some(thread) = self.title.take() {
            thread.release(&mut self.retired);
        }
        for slot in &mut self.dedicated {
            if let Some(dedicated) = slot.take_if(|dedicated| dedicated.title) {
                dedicated.thread.release(&mut self.retired);
            }
        }
    }

    /// Stop every thread; the server is exiting.
    fn release_all(&mut self) {
        if let Some(thread) = self.title.take() {
            thread.stop();
        }
        for slot in &mut self.dedicated {
            if let Some(dedicated) = slot.take() {
                dedicated.thread.stop();
            }
        }
        for slot in &mut self.retired {
            if let Some(thread) = slot.take() {
                thread.join();
            }
        }
    }
}

/// Reset the context as the monitor does before a command (stock
/// 0x91f50680) and after a transfer.
fn reset_context(slot: &Slot) {
    let context = slot.context();
    // SAFETY: the slot is idle; only the server thread uses it.
    unsafe {
        (*context).buffer = 0;
        (*context).remaining = Context::NOT_RECEIVING;
        (*context).continuation = 0;
        (*context).scratch = slot.scratch_address();
    }
}

/// Supply the default data buffer when the context has none (stock pump
/// 0x91f423f8).
fn supply_buffer(slot: &Slot) {
    let context = slot.context();
    // SAFETY: the slot is idle; only the server thread uses it.
    unsafe {
        if (*context).buffer == 0 {
            (*context).buffer = slot.line_address();
            (*context).size = CONTINUATION_BUFFER_SIZE;
            (*slot.block()).line[0] = 0;
        }
    }
}

/// Drop the default data buffer after a call, as stock clears the stack
/// buffer it supplied.
fn withdraw_buffer(slot: &Slot) {
    let context = slot.context();
    // SAFETY: the slot is idle; only the server thread uses it.
    unsafe {
        if (*context).buffer == slot.line_address() {
            (*context).buffer = 0;
        }
    }
}

impl Console {
    fn finish_handler(
        &mut self,
        call: ProcessorCall,
        result: Hresult,
        text: &mut ResponseText,
        continuation: &mut Option<ExternalContinuation>,
        receive_remaining: &mut Option<u32>,
    ) -> Hresult {
        let index = call.connection.0 as usize;
        let slot = &SLOTS[index];
        // SAFETY: the slot is idle; only the server thread uses it.
        let block = unsafe { &*slot.block() };
        text.set_bytes(until_nul(&block.response));
        let context = slot.context();
        let mode = if result == Hresult::MULTILINE {
            // SAFETY: the slot is idle; only the server thread uses it.
            unsafe { (*context).count = Context::TEXT_LINE };
            Mode::Lines
        } else if result == Hresult::BINARY {
            Mode::Binary
        } else if result == Hresult::SEND_BINARY {
            Mode::Upload
        } else {
            return result;
        };
        // SAFETY: the slot is idle; only the server thread uses it.
        let (routine, remaining) = unsafe { ((*context).continuation, (*context).remaining) };
        if routine == 0 {
            return result;
        }
        self.session.processors.connections[index].mode = mode;
        if mode == Mode::Upload {
            *receive_remaining = Some(remaining);
        }
        *continuation = Some(ExternalContinuation { call });
        result
    }

    fn finish_continuation(
        &mut self,
        index: usize,
        aborted: bool,
        taken: Taken,
        transfer: ExternalTransfer<'_>,
    ) -> Hresult {
        let slot = &SLOTS[index];
        let calls = &mut self.session.processors.connections[index];
        let result = match taken {
            Taken::Returned(result) => result,
            Taken::Lost => {
                withdraw_buffer(slot);
                reset_context(slot);
                if calls.mode == Mode::Upload {
                    *transfer.receive_remaining = Some(0);
                }
                calls.mode = Mode::Idle;
                return Hresult::UNEXPECTED;
            }
        };
        if aborted {
            withdraw_buffer(slot);
            return result;
        }
        let context = slot.context();
        if calls.mode == Mode::Upload {
            withdraw_buffer(slot);
            // SAFETY: the slot is idle; only the server thread uses it.
            let remaining = unsafe { (*context).remaining };
            if remaining != 0 {
                *transfer.receive_remaining = Some(remaining);
                return result;
            }
            let mut result = result;
            // SAFETY: the slot is idle; only the server thread uses it.
            unsafe { (*context).remaining = Context::NOT_RECEIVING };
            calls.mode = if result == Hresult::MULTILINE {
                // SAFETY: as above.
                unsafe { (*context).count = Context::TEXT_LINE };
                Mode::Lines
            } else if result == Hresult::BINARY {
                Mode::Binary
            } else {
                if result != Hresult::FAST_PIPE {
                    reset_context(slot);
                }
                Mode::Idle
            };
            // SAFETY: as above.
            if calls.mode != Mode::Idle && unsafe { (*context).continuation } == 0 {
                calls.mode = Mode::Idle;
                result = Hresult::UNEXPECTED;
            } else {
                // SAFETY: as above.
                let block = unsafe { &*slot.block() };
                transfer.line.set_bytes(until_nul(
                    &block.response[..CONTINUATION_BUFFER_SIZE as usize],
                ));
            }
            *transfer.receive_remaining = Some(0);
            return result;
        }
        if result.is_failure() {
            withdraw_buffer(slot);
            if result == Hresult::END_OF_DATA {
                reset_context(slot);
                calls.mode = Mode::Idle;
            }
            return result;
        }
        // SAFETY: the slot is idle; only the server thread uses it.
        let (data, buffer) = unsafe { ((*context).data(), (*context).buffer) };
        let output = match data {
            ContinuationData::Line => {
                // The supplied buffer bounds the line; a processor's own
                // buffer is read to its NUL, as stock does.
                let length = if buffer == slot.line_address() {
                    // SAFETY: as above.
                    let block = unsafe { &*slot.block() };
                    until_nul(&block.line[..CONTINUATION_BUFFER_SIZE as usize]).len()
                } else {
                    // SAFETY: a continuation that reports a line leaves it
                    // NUL-terminated in its buffer, which is not 0; stock
                    // reads it without a check.
                    unsafe { kernel::c_string(buffer).unwrap_unchecked() }.len()
                } as u32;
                Some(Output {
                    address: buffer,
                    length,
                    total: length + 2,
                    passed: 0,
                })
            }
            ContinuationData::Bytes(count) => Some(Output {
                address: buffer,
                length: count,
                total: count,
                passed: 0,
            }),
            ContinuationData::Nothing => None,
        };
        match output {
            Some(output) => {
                calls.output = output.pass(transfer.binary, transfer.binary_len);
            }
            None => *transfer.no_output = calls.mode == Mode::Lines,
        }
        withdraw_buffer(slot);
        result
    }
}

impl ProcessorBackend for Console {
    fn find_processor(&mut self, name: &[u8]) -> Option<(u8, Processor)> {
        REGISTRY.with(|processors| processors.find(name))
    }

    fn processor(&mut self, index: u8) -> Option<Processor> {
        REGISTRY.with(|processors| processors.get(index))
    }

    /// Stock 0x91f42850.
    fn remove_title_processors(&mut self) {
        REGISTRY.with(Processors::remove_title_processors);
        self.session.processors.release_title_threads();
    }

    fn call_processor(
        &mut self,
        call: ProcessorCall,
        line: &[u8],
        text: &mut ResponseText,
        continuation: &mut Option<ExternalContinuation>,
        receive_remaining: &mut Option<u32>,
    ) -> ProcessorProgress {
        let index = call.connection.0 as usize;
        let slot = &SLOTS[index];
        let calls = &mut self.session.processors.connections[index];
        if let Some(in_flight) = calls.in_flight {
            let Some(taken) = take_result(slot) else {
                if line.is_empty() {
                    return ProcessorProgress::Running;
                }
                // A call of a connection that closed still uses the slot.
                return ProcessorProgress::Unavailable;
            };
            calls.in_flight = None;
            if line.is_empty() && in_flight == InFlight::Handler {
                let result = match taken {
                    Taken::Returned(result) => result,
                    Taken::Lost => Hresult::UNEXPECTED,
                };
                return ProcessorProgress::Complete(self.finish_handler(
                    call,
                    result,
                    text,
                    continuation,
                    receive_remaining,
                ));
            }
        }
        calls.mode = Mode::Idle;
        calls.output = None;
        reset_context(slot);
        // SAFETY: the slot is idle; only the server thread uses it.
        unsafe {
            let block = &mut *slot.block();
            let length = line.len().min(LINE_SIZE - 1);
            block.line[..length].copy_from_slice(&line[..length]);
            block.line[length] = 0;
            block.response[0] = 0;
        }
        let arguments = [
            slot.line_address(),
            slot.response_address(),
            HANDLER_RESPONSE_SIZE,
            slot.context() as usize as u32,
        ];
        match self
            .session
            .processors
            .start(index, call.thread, call.handle.raw(), arguments)
        {
            Started::Finished(result) => ProcessorProgress::Complete(self.finish_handler(
                call,
                result,
                text,
                continuation,
                receive_remaining,
            )),
            Started::Running => {
                self.session.processors.connections[index].in_flight = Some(InFlight::Handler);
                ProcessorProgress::Running
            }
            Started::Unavailable => ProcessorProgress::Unavailable,
        }
    }

    fn resume_processor(
        &mut self,
        continuation: &mut ExternalContinuation,
        transfer: ExternalTransfer<'_>,
    ) -> ProcessorProgress {
        let call = continuation.call;
        let index = call.connection.0 as usize;
        let slot = &SLOTS[index];
        let calls = &mut self.session.processors.connections[index];
        if let Some(InFlight::Continuation { aborted }) = calls.in_flight {
            let Some(taken) = take_result(slot) else {
                return ProcessorProgress::Running;
            };
            calls.in_flight = None;
            return ProcessorProgress::Complete(
                self.finish_continuation(index, aborted, taken, transfer),
            );
        }
        if !transfer.aborted
            && let Some(output) = calls.output.take()
        {
            calls.output = output.pass(transfer.binary, transfer.binary_len);
            return ProcessorProgress::Complete(Hresult::OK);
        }
        calls.output = None;
        supply_buffer(slot);
        let context = slot.context();
        // SAFETY: the slot is idle; only the server thread uses it.
        unsafe {
            if calls.mode == Mode::Upload {
                let count = transfer.received.len().min((*context).size as usize);
                core::ptr::copy_nonoverlapping(
                    transfer.received.as_ptr(),
                    (*context).buffer as usize as *mut u8,
                    count,
                );
                (*context).count = count as u32;
            }
            if transfer.aborted {
                (*context).remaining = 0;
            }
            (*slot.block()).response[0] = 0;
        }
        let aborted = transfer.aborted;
        // SAFETY: as above.
        let routine = unsafe { (*context).continuation };
        let arguments = [
            context as usize as u32,
            slot.response_address(),
            CONTINUATION_BUFFER_SIZE,
            0,
        ];
        match self
            .session
            .processors
            .start(index, call.thread, routine, arguments)
        {
            Started::Finished(result) => ProcessorProgress::Complete(self.finish_continuation(
                index,
                aborted,
                Taken::Returned(result),
                transfer,
            )),
            Started::Running => {
                self.session.processors.connections[index].in_flight =
                    Some(InFlight::Continuation { aborted });
                ProcessorProgress::Running
            }
            Started::Unavailable => ProcessorProgress::Complete(self.finish_continuation(
                index,
                aborted,
                Taken::Lost,
                transfer,
            )),
        }
    }

    fn processor_receive_limit(&mut self, continuation: &ExternalContinuation) -> usize {
        let context = SLOTS[continuation.call.connection.0 as usize].context();
        // SAFETY: the slot is idle; only the server thread uses it.
        match unsafe { ((*context).buffer, (*context).size) } {
            (0, _) => CONTINUATION_BUFFER_SIZE as usize,
            (_, size) => size as usize,
        }
    }
}

/// Server pass: end threads no connection needs, and finish the processor
/// calls that ended on other threads.
pub(crate) fn poll_processor_calls(
    server: &mut Server,
    console: &mut Console,
    network: &mut XamNetwork,
) {
    let mut connections = [None; MAX_CONNECTIONS];
    for (index, socket, owner) in server.connections() {
        connections[index.0 as usize] = Some((socket, owner));
    }
    let data = &mut console.session.processors;
    data.find_lost_calls();
    data.retain(&connections);
    for (index, slot) in SLOTS.iter().enumerate() {
        if !matches!(
            slot.state.load(Ordering::Acquire),
            CallSlotState::Finished | CallSlotState::Lost
        ) {
            continue;
        }
        let connection = ConnectionIndex(index as u8);
        server.complete_processor_call(connection, console, network);
        // Nothing collects the result of a connection that closed.
        if !server.awaits_processor(connection) && take_result(slot).is_some() {
            console.session.processors.connections[index].in_flight = None;
        }
    }
}

/// The server is exiting: stop the processor threads.
pub(crate) fn release_processor_threads(console: &mut Console) {
    console.session.processors.release_all();
}
