//! Remote calls of `rpc`: call blocks the stream creates and a runner
//! thread makes, either an own thread or a named thread that drains the
//! queue.

use core::num::NonZeroU32;
use core::ptr::NonNull;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_core::status::Win32Error;
use openxbdm_server::commands::session::RpcBackend;
use openxbdm_server::commands::session::RpcCall;
use openxbdm_server::commands::session::RpcContext;
use openxbdm_server::commands::session::RpcCreateError;
use openxbdm_server::commands::session::RpcThread;
use xbox360::status::Win32ErrorCode;
use xbox360::time::TickCount;
use xbox360::time::relative_interval;
use xbox360::time::sleep;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::KeResumeThread;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;

use super::error::CallError;
use super::until_nul;
use crate::backend::Console;
use crate::kernel;
use crate::kernel::CriticalSection;

const CALL_NAME_CAPACITY: usize = 0x40;

/// Head of the named-call queue (stock 0x91f9fda8), newest first.
static RPC_QUEUE: AtomicU32 = AtomicU32::new(0);
/// Lock of the named-call queue (stock 0x91f9766c).
static RPC_QUEUE_LOCK: CriticalSection = CriticalSection::new();

/// A quadword the stream and the runner share, accessed as two words, as
/// the monitor's 32-bit code does.
#[repr(C)]
struct Quad([AtomicU32; 2]);

impl Quad {
    #[inline(always)]
    fn get(&self) -> u64 {
        (u64::from(self.0[0].load(Ordering::Relaxed)) << 32)
            | u64::from(self.0[1].load(Ordering::Relaxed))
    }

    /// The low word alone, with one load.
    #[inline(always)]
    fn low(&self) -> u32 {
        self.0[1].load(Ordering::Relaxed)
    }

    #[inline(always)]
    fn set(&self, value: u64) {
        self.0[0].store((value >> 32) as u32, Ordering::Relaxed);
        self.0[1].store(value as u32, Ordering::Relaxed);
    }
}

/// Owner of a call block that released it last: the stream that created
/// it or the runner that makes the call.
#[repr(u32)]
#[derive(Clone, Copy)]
enum ReleaseState {
    Held = 0,
    RunnerFinished = 1,
    StreamReleased = 2,
}

/// Word of a [`ReleaseState`].
#[repr(transparent)]
struct ReleaseWord(AtomicU32);

impl ReleaseWord {
    /// Store `state`; whether the word held `previous` before.
    #[inline(always)]
    fn swap_from(&self, state: ReleaseState, previous: ReleaseState) -> bool {
        self.0.swap(state as u32, Ordering::AcqRel) == previous as u32
    }
}

/// Call block (stock 0x91f3e7c8), followed by the call buffer of the size
/// the client gives.
#[repr(C)]
struct CallBlock {
    /// Next queued call, under [`RPC_QUEUE_LOCK`]; 0 ends the queue.
    link: AtomicU32,
    /// Nonzero once the stream abandoned an own-thread call before it ran.
    abort: AtomicU32,
    /// Nonzero for a call in the system process.
    system: AtomicU32,
    /// Referenced, suspended thread object of an own-thread call; 0 for a
    /// call queued for a named thread.
    thread: AtomicU32,
    /// Size of the call buffer.
    size: AtomicU32,
    _reserved_14: AtomicU32,
    /// `ERROR_IO_PENDING` from the creation on; nothing reads it.
    marker: Quad,
    /// Name of the thread that runs a queued call, NUL-terminated.
    name: [u8; CALL_NAME_CAPACITY],
    /// Nonzero once the call finished.
    done: AtomicU32,
    release: ReleaseWord,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(CallBlock, abort) == 0x4);
    assert!(offset_of!(CallBlock, system) == 0x8);
    assert!(offset_of!(CallBlock, thread) == 0xc);
    assert!(offset_of!(CallBlock, size) == 0x10);
    assert!(offset_of!(CallBlock, marker) == 0x18);
    assert!(offset_of!(CallBlock, name) == 0x20);
    assert!(offset_of!(CallBlock, done) == 0x60);
    assert!(offset_of!(CallBlock, release) == 0x64);
    assert!(core::mem::size_of::<CallBlock>() == 0x68);
};

impl CallBlock {
    #[inline(always)]
    fn thread_object(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.thread.load(Ordering::Relaxed))
    }
}

xbox360_sys::flags! {
    /// Flags quadword of a call buffer.
    pub struct CallFlags(u64) {
        /// The return value is the double in f1.
        DOUBLE_RESULT = 0x1,
    }
}

/// Header of a call buffer, followed by the integer arguments, then the
/// doubles. The client fills it before the call; the runner stores the
/// results.
#[repr(C)]
struct CallBuffer {
    /// HRESULT, sign-extended.
    result: Quad,
    value: Quad,
    /// [`CallBuffer::LAST_ERROR_REQUESTED`] asks for the last error.
    last_error: Quad,
    flags: Quad,
    integer_count: Quad,
    double_count: Quad,
    /// Address of the module name, or 0 for a target address.
    module: Quad,
    /// Function address, or the export ordinal or name address in `module`.
    target: Quad,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(CallBuffer, value) == 0x8);
    assert!(offset_of!(CallBuffer, last_error) == 0x10);
    assert!(offset_of!(CallBuffer, flags) == 0x18);
    assert!(offset_of!(CallBuffer, integer_count) == 0x20);
    assert!(offset_of!(CallBuffer, double_count) == 0x28);
    assert!(offset_of!(CallBuffer, module) == 0x30);
    assert!(offset_of!(CallBuffer, target) == 0x38);
    assert!(core::mem::size_of::<CallBuffer>() == 0x40);
};

impl CallBuffer {
    const LAST_ERROR_REQUESTED: u64 = 1;
}

/// A call block allocated by [`RpcBackend::rpc_create`], possibly freed.
#[derive(Clone, Copy, PartialEq, Eq)]
struct CallPointer(NonNull<CallBlock>);

impl CallPointer {
    /// `None` for 0.
    ///
    /// # Safety
    ///
    /// `address` must be 0 or the address of a call block.
    #[inline(always)]
    unsafe fn new(address: u32) -> Option<Self> {
        NonNull::new(core::ptr::with_exposed_provenance_mut(address as usize)).map(Self)
    }

    /// # Safety
    ///
    /// `address` must be the address of a call block.
    #[inline(always)]
    unsafe fn from_address(address: u32) -> Self {
        // SAFETY: the address of a call block is not 0.
        Self(unsafe {
            NonNull::new_unchecked(core::ptr::with_exposed_provenance_mut(address as usize))
        })
    }

    #[inline(always)]
    fn address(self) -> u32 {
        self.0.as_ptr().expose_provenance() as u32
    }

    /// # Safety
    ///
    /// The block must stay allocated while the reference is used: the
    /// caller is the stream before `rpc_release`, the runner before
    /// [`release_runner`], or holds [`RPC_QUEUE_LOCK`] while the block is
    /// queued.
    #[inline(always)]
    unsafe fn block<'a>(self) -> &'a CallBlock {
        // SAFETY: the caller guarantees the block for `'a`.
        unsafe { self.0.as_ref() }
    }

    /// The call buffer after the block.
    #[inline(always)]
    fn buffer(self) -> *mut CallBuffer {
        self.0.as_ptr().wrapping_add(1).cast()
    }

    /// # Safety
    ///
    /// The caller is the last owner of the block and does not use it after.
    #[inline(always)]
    unsafe fn free(self) {
        // SAFETY: the caller releases the last use of the pool block.
        unsafe { xboxkrnl::ExFreePool(self.address()) };
    }
}

impl RpcBackend for Console {
    fn rpc_create(
        &mut self,
        size: u32,
        context: RpcContext,
        thread: RpcThread<'_>,
    ) -> Result<RpcCall, RpcCreateError> {
        /// Pool tag of call blocks.
        const CALL_TAG: PoolTag = PoolTag::new(*b"drpc");

        // Stock adds without a carry, so a size near 4 GB gets a small block
        // its upload overruns; here that size fails as an allocation does.
        let total = size
            .checked_add(core::mem::size_of::<CallBlock>() as u32)
            .ok_or(RpcCreateError::OutOfMemory)?;

        // SAFETY: the allocation takes only a size and tag.
        let address = unsafe { xboxkrnl::ExAllocatePoolWithTag(total, CALL_TAG) };
        // SAFETY: the allocation is 0 or a new block sized for a call block
        // and its buffer.
        let Some(call) = (unsafe { CallPointer::new(address) }) else {
            return Err(RpcCreateError::OutOfMemory);
        };

        let name = match thread {
            RpcThread::Named(name) => &name[..name.len().min(CALL_NAME_CAPACITY - 1)],
            RpcThread::Own { .. } => &[],
        };
        // SAFETY: the new block is not shared; its name field holds
        // CALL_NAME_CAPACITY bytes.
        unsafe {
            let field = (&raw mut (*call.0.as_ptr()).name).cast::<u8>();
            core::ptr::copy_nonoverlapping(name.as_ptr(), field, name.len());
            field.add(name.len()).write(0);
        }

        // SAFETY: the stream owns the new block.
        let block = unsafe { call.block() };
        let system = context == RpcContext::System;
        block.link.store(0, Ordering::Relaxed);
        block.abort.store(0, Ordering::Relaxed);
        block.thread.store(0, Ordering::Relaxed);
        block.done.store(0, Ordering::Relaxed);
        block
            .release
            .0
            .store(ReleaseState::Held as u32, Ordering::Relaxed);
        block.system.store(u32::from(system), Ordering::Relaxed);
        block.size.store(size, Ordering::Relaxed);
        block.marker.set(u64::from(Win32Error::IO_PENDING.code()));

        if let RpcThread::Own { processor } = thread {
            // Only the low six bits of the processor reach the shift.
            // Numbers 6 and 7 set bits above PROCESSOR5, which pass on
            // unchanged as stock passes them.
            let processor = processor & 0x3f;
            let affinity = ThreadCreationFlags::from_bits_retain(if processor < 32 {
                (1u32 << processor) << 24
            } else {
                0
            });
            let mut flags = affinity
                | ThreadCreationFlags::RETURN_THREAD_OBJECT
                | ThreadCreationFlags::SUSPENDED;
            if system {
                flags |= ThreadCreationFlags::SYSTEM_PROCESS;
            }

            let mut object = 0u32;
            // SAFETY: `object` is a local word; `call_thread` takes the block
            // as its context.
            let status = unsafe {
                xboxkrnl::ExCreateThread(
                    &mut object,
                    0,
                    core::ptr::null_mut(),
                    0,
                    call_thread as *const () as usize as u32,
                    call.address(),
                    flags,
                )
            };
            if let Err(error) = status.result() {
                // SAFETY: the block was allocated above and no thread owns it.
                unsafe { call.free() };
                return Err(RpcCreateError::Thread(error));
            }

            block.thread.store(object, Ordering::Relaxed);
        }

        // SAFETY: the block is new; it is freed only through `rpc_abort` or
        // `rpc_release`, whose contracts end the use of every copy.
        Ok(unsafe { RpcCall::from_raw(call.address()) })
    }

    fn rpc_buffer_address(&mut self, call: RpcCall) -> u32 {
        call.raw() + core::mem::size_of::<CallBlock>() as u32
    }

    unsafe fn rpc_write(&mut self, call: RpcCall, offset: u32, data: &[u8]) {
        let call = call_pointer(call);
        let destination = call.buffer().cast::<u8>().wrapping_add(offset as usize);

        // SAFETY: the bytes lie in the buffer the block was allocated with,
        // per the trait contract.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), destination, data.len()) };
    }

    fn rpc_start(&mut self, call: RpcCall) {
        let call = call_pointer(call);

        // SAFETY: the stream owns the block until it releases it.
        match unsafe { call.block() }.thread_object() {
            None => push_call(call),
            Some(thread) => {
                // SAFETY: the block holds the referenced, suspended thread object.
                unsafe { KeResumeThread(thread.get() as usize as *mut xboxkrnl::Kthread) };
            }
        }
    }

    unsafe fn rpc_abort(&mut self, call: RpcCall) {
        let call = call_pointer(call);
        // SAFETY: the stream owns the block until it releases it.
        let block = unsafe { call.block() };

        match block.thread_object() {
            None => {
                unlink_call(call);
                // SAFETY: the unlinked block has no runner.
                unsafe { call.free() };
            }
            Some(thread) => {
                // The thread sees the abort flag and frees the block.
                block.abort.store(1, Ordering::Release);
                // SAFETY: the block holds the referenced thread object; the
                // reference is dropped once here.
                unsafe {
                    KeResumeThread(thread.get() as usize as *mut xboxkrnl::Kthread);
                    xboxkrnl::ObDereferenceObject(thread.get());
                }
            }
        }
    }

    fn rpc_wait(&mut self, call: RpcCall) -> bool {
        /// How long the stream waits for a call: 100 ms.
        const CALL_WAIT_MS: u32 = 100;
        const CALL_WAIT: i64 = relative_interval(Duration::from_millis(CALL_WAIT_MS as u64));
        const CALL_POLL_MS: u32 = 10;

        let call = call_pointer(call);
        // SAFETY: the stream owns the block until it releases it.
        let block = unsafe { call.block() };

        match block.thread_object() {
            None => {
                let start = TickCount::now().milliseconds();

                loop {
                    if block.done.load(Ordering::Acquire) != 0 {
                        return true;
                    }

                    if TickCount::now().milliseconds().wrapping_sub(start) >= CALL_WAIT_MS {
                        return false;
                    }

                    sleep(Duration::from_millis(u64::from(CALL_POLL_MS)));
                }
            }
            Some(thread) => {
                let timeout = CALL_WAIT;
                // SAFETY: the block holds the referenced thread object;
                // `timeout` is a live local.
                let status = unsafe {
                    xboxkrnl::KeWaitForSingleObject(
                        thread.get() as usize as *mut xboxkrnl::DispatcherObject,
                        WaitReason::UserRequest,
                        ProcessorMode::Kernel,
                        false,
                        &timeout,
                    )
                };

                status == NtStatus::WAIT_0
            }
        }
    }

    unsafe fn rpc_read(&mut self, call: RpcCall, offset: u32, output: &mut [u8]) {
        let call = call_pointer(call);
        let source = call.buffer().cast::<u8>().wrapping_add(offset as usize);

        // SAFETY: the bytes lie in the buffer the block was allocated with,
        // per the trait contract.
        unsafe { core::ptr::copy_nonoverlapping(source, output.as_mut_ptr(), output.len()) };
    }

    unsafe fn rpc_release(&mut self, call: RpcCall) {
        let call = call_pointer(call);
        // SAFETY: the stream owns the block until it releases it here.
        let block = unsafe { call.block() };

        match block.thread_object() {
            Some(thread) => {
                // SAFETY: the block holds the reference ExCreateThread returned.
                unsafe { xboxkrnl::ObDereferenceObject(thread.get()) };
            }
            None => {
                // Still queued: no runner exists.
                if unlink_call(call) {
                    // SAFETY: the unlinked block has no runner.
                    unsafe { call.free() };
                    return;
                }
            }
        }

        // The monitor frees the block at once; a runner still in the call
        // frees it when it finishes instead.
        if block
            .release
            .swap_from(ReleaseState::StreamReleased, ReleaseState::RunnerFinished)
        {
            // SAFETY: the runner finished, so this is the last use.
            unsafe { call.free() };
        }
    }
}

pub(super) fn initialize() {
    RPC_QUEUE_LOCK.initialize();
}

/// The result quadword of a call buffer: the HRESULT sign-extended.
const fn result_quad(result: Hresult) -> u64 {
    result.0 as i32 as i64 as u64
}

fn push_call(call: CallPointer) {
    RPC_QUEUE_LOCK.enter();

    // SAFETY: the stream owns the block until it releases it.
    unsafe { call.block() }
        .link
        .store(RPC_QUEUE.load(Ordering::Relaxed), Ordering::Relaxed);
    RPC_QUEUE.store(call.address(), Ordering::Relaxed);

    RPC_QUEUE_LOCK.leave();
}

/// Remove `call` from the queue; returns whether it was queued.
fn unlink_call(call: CallPointer) -> bool {
    RPC_QUEUE_LOCK.enter();

    // The word that links the current call: the head, then a call's link.
    let mut link = &RPC_QUEUE;
    let mut found = false;

    // SAFETY: the queue links call blocks, which stay allocated while they
    // are queued and the lock is held.
    while let Some(current) = unsafe { CallPointer::new(link.load(Ordering::Relaxed)) } {
        // SAFETY: as above.
        let block = unsafe { current.block() };
        if current == call {
            link.store(block.link.load(Ordering::Relaxed), Ordering::Relaxed);
            found = true;
            break;
        }

        link = &block.link;
    }

    RPC_QUEUE_LOCK.leave();

    found
}

/// Take the newest call queued for `name` (stock 0x91f3e208). A busy lock
/// reads as an empty queue.
fn take_call(name: &[u8]) -> Option<CallPointer> {
    if !RPC_QUEUE_LOCK.try_enter() {
        return None;
    }

    let mut link = &RPC_QUEUE;
    let mut taken = None;

    // SAFETY: the queue links call blocks, which stay allocated while they
    // are queued and the lock is held.
    while let Some(current) = unsafe { CallPointer::new(link.load(Ordering::Relaxed)) } {
        // SAFETY: as above.
        let block = unsafe { current.block() };
        if until_nul(&block.name) == name {
            link.store(block.link.load(Ordering::Relaxed), Ordering::Relaxed);
            block.link.store(0, Ordering::Relaxed);
            taken = Some(current);
            break;
        }

        link = &block.link;
    }

    RPC_QUEUE_LOCK.leave();

    taken
}

/// Monitor control code 0xa8 (export 372, stock 0x91f3ea50): run every
/// call queued for the calling thread's name, newest first.
///
/// # Safety
///
/// `name` must be 0 or the NUL-terminated name of the calling thread,
/// unchanged for the call.
pub(crate) unsafe fn service_rpc_drain(name: u32) -> u32 {
    // SAFETY: the caller's contract.
    let Some(name) = (unsafe { kernel::c_string(name) }) else {
        return 0;
    };

    while let Some(call) = take_call(name) {
        // SAFETY: the taken call is unlinked, so this thread is its runner.
        unsafe { run_call(call) };
    }

    0
}

/// Own-thread call start routine.
extern "C" fn call_thread(context: u32) -> u32 {
    // SAFETY: `rpc_create` starts the thread with its call block as the
    // context; the thread is the block's runner.
    let call = unsafe { CallPointer::from_address(context) };

    // SAFETY: the runner's block stays allocated until it releases it.
    if unsafe { call.block() }.abort.load(Ordering::Acquire) != 0 {
        // SAFETY: an aborted block is owned by this thread and freed once.
        unsafe { call.free() };
    } else {
        // SAFETY: this thread is the runner of the block.
        unsafe { run_call(call) };
    }

    // SAFETY: this thread was created for the call and holds no resources.
    unsafe { xboxkrnl::ExTerminateThread(0) }
}

/// Make the call described by the block's buffer (stock 0x91f3e630).
///
/// # Safety
///
/// The caller must be the runner of `call`, which owns the block until
/// [`release_runner`].
unsafe fn run_call(call: CallPointer) {
    /// Register slots: eight integers, then eight doubles.
    const ARGUMENT_SLOTS: usize = 16;

    // SAFETY: the runner's block stays allocated until it releases it.
    let block = unsafe { call.block() };
    // SAFETY: the client sizes the buffer for the header and the arguments
    // it gives; as in stock, nothing checks the size.
    let buffer = unsafe { &*call.buffer() };

    let mut target = buffer.target.low();
    let module = buffer.module.get();
    let failure = if module != 0 {
        let mut handle = 0u32;
        // SAFETY: the client supplied the module name address; `handle` and
        // `target` are live locals.
        unsafe {
            if !xboxkrnl::XexGetModuleHandle(module as u32 as usize as *const u8, &mut handle)
                .is_success()
            {
                Some(CallError::ModuleNotFound)
            } else if !xboxkrnl::XexGetProcedureAddress(handle, target, &mut target).is_success() {
                Some(CallError::ProcedureNotFound)
            } else {
                None
            }
        }
    } else {
        None
    };

    if let Some(failure) = failure {
        // Failures store the result before the done flag.
        buffer.result.set(result_quad(Hresult::from(failure)));
        block.done.store(1, Ordering::Release);
        // SAFETY: this thread is the runner and does not use the block after.
        unsafe { release_runner(call) };
        return;
    }

    // The monitor copies the integers to slot 0 and the doubles to slot 8
    // of two adjacent eight-slot arrays without bounds; the copies are
    // limited to the arrays here.
    let mut slots = [0u64; ARGUMENT_SLOTS];
    let integers = (buffer.integer_count.low() as usize).min(ARGUMENT_SLOTS);
    let doubles = (buffer.double_count.low() as usize).min(ARGUMENT_SLOTS / 2);
    let first = call.buffer().wrapping_add(1).cast::<Quad>();
    // SAFETY: the arguments follow the header, integers first; the client
    // sizes the buffer for them as for the header.
    let (integer_arguments, double_arguments) = unsafe {
        (
            core::slice::from_raw_parts(first, integers),
            core::slice::from_raw_parts(first.add(integers), doubles),
        )
    };

    for (slot, argument) in slots.iter_mut().zip(integer_arguments) {
        *slot = argument.get();
    }

    for (slot, argument) in slots[ARGUMENT_SLOTS / 2..].iter_mut().zip(double_arguments) {
        *slot = argument.get();
    }

    let mut registers = [0u64; 2];
    // SAFETY: the client supplied the target and its arguments; the call is
    // the purpose of the command.
    unsafe { invoke(target, slots.as_ptr(), registers.as_mut_ptr()) };

    // The defined flag lies in the low word.
    let flags = CallFlags::from_bits_retain(u64::from(buffer.flags.low()));
    let value = if flags.contains(CallFlags::DOUBLE_RESULT) {
        registers[1]
    } else {
        registers[0]
    };
    buffer.value.set(value);

    if buffer.last_error.get() == CallBuffer::LAST_ERROR_REQUESTED {
        let code = Win32ErrorCode::from(xbox360::status::last_error());
        buffer.last_error.set(u64::from(code.0));
    }

    // The done flag is set before the success result is stored.
    block.done.store(1, Ordering::Release);
    buffer.result.set(result_quad(Hresult::SUCCESS));

    // SAFETY: this thread is the runner and does not use the block after.
    unsafe { release_runner(call) };
}

/// The runner is done with the block; free it when the stream already
/// released it.
///
/// # Safety
///
/// The caller must be the runner of `call` and must not use it after.
unsafe fn release_runner(call: CallPointer) {
    // SAFETY: the runner's block stays allocated until this release.
    if unsafe { call.block() }
        .release
        .swap_from(ReleaseState::RunnerFinished, ReleaseState::StreamReleased)
    {
        // SAFETY: both owners released the block; this is the last use.
        unsafe { call.free() };
    }
}

/// Load r3..r10 from `slots[0..8]` and f1..f8 from `slots[8..16]`, call
/// `target` with a console frame, and store r3 (all 64 bits) and f1 in
/// `registers`.
#[unsafe(naked)]
unsafe extern "C" fn invoke(target: u32, slots: *const u64, registers: *mut u64) {
    core::arch::naked_asm!(
        "stwu 1, -0x80(1)",
        "mflr 0",
        "stw 0, 0x84(1)",
        "stw 31, 0x7c(1)",
        "mr 31, 5",
        "mtctr 3",
        "mr 11, 4",
        "lfd 1, 0x40(11)",
        "lfd 2, 0x48(11)",
        "lfd 3, 0x50(11)",
        "lfd 4, 0x58(11)",
        "lfd 5, 0x60(11)",
        "lfd 6, 0x68(11)",
        "lfd 7, 0x70(11)",
        "lfd 8, 0x78(11)",
        // ld 3..10, 0..0x38(11): the target CPU model has no 64-bit
        // mnemonics.
        ".long 0xe86b0000",
        ".long 0xe88b0008",
        ".long 0xe8ab0010",
        ".long 0xe8cb0018",
        ".long 0xe8eb0020",
        ".long 0xe90b0028",
        ".long 0xe92b0030",
        ".long 0xe94b0038",
        "bctrl",
        // std 3, 0(31)
        ".long 0xf87f0000",
        "stfd 1, 8(31)",
        "lwz 31, 0x7c(1)",
        "lwz 0, 0x84(1)",
        "mtlr 0",
        "addi 1, 1, 0x80",
        "blr",
    )
}

/// The call block of `call`.
#[inline(always)]
fn call_pointer(call: RpcCall) -> CallPointer {
    // SAFETY: an `RpcCall` names a call block until it is aborted or
    // released (`RpcCall::from_raw`), after which no copy is used.
    unsafe { CallPointer::from_address(call.raw()) }
}
