//! Detour engine on the console: trampolines and stubs in this module's
//! code section, the logger the stubs call on title threads, and the log
//! writer and completion workers.
//!
//! The stubs reproduce stock 0x91f13000 (entry), 0x91f130ac (call the
//! original with a copied parameter area), 0x91f1313c (save f1-f13), and
//! 0x91f1319c (save v1-v13 with stock's overlapping offsets). They reach
//! the Rust logger through `openxbdm_detour_notify`, which keeps the
//! title's full 64-bit r14-r31 and its floating-point arguments f1-f13.

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::filesystem::CreateDisposition;
use openxbdm_server::commands::filesystem::CreateOptions;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::FileAccess;
use openxbdm_server::commands::filesystem::FileAttributes;
use openxbdm_server::commands::filesystem::ShareAccess;
use openxbdm_server::commands::memory::detour;
use openxbdm_server::commands::memory::detour::BLOCK_SIZE;
use openxbdm_server::commands::memory::detour::CallContext;
use openxbdm_server::commands::memory::detour::Engine;
use openxbdm_server::commands::memory::detour::RECORD_SIZE;
use xbox360::time::FileTime;
use xbox360::time::TickCount;
use xbox360::time::Timebase;
use xbox360::time::relative_interval;
use xbox360_sys::status::Severity;
use xbox360_sys::xam::INFINITE;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DispatcherObject;
use xbox360_sys::xboxkrnl::EVENT_INCREMENT;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::Kevent;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;
use xbox360_sys::xboxkrnl::WaitType;

use crate::backend::filesystem::create_file;
use crate::kernel;
use crate::kernel::CriticalSection;
use crate::kernel::KernelEvent;
use crate::kernel::pool_tag;

core::arch::global_asm!(
    ".section .text.openxbdm_detour,\"ax\",@progbits",
    ".p2align 4",
    // Entry stub (0x91f13000). r12 holds the entry id; the locals live at
    // r1 + 0x50 of a 0xc0-byte frame.
    ".globl openxbdm_detour_entry",
    "openxbdm_detour_entry:",
    "stw 12, -112(1)",
    "mflr 12",
    "stw 12, -8(1)",
    "stwu 1, -192(1)",
    // std r3..r10, 0x68..0xa0(r1)
    ".long 0xf8610068, 0xf8810070, 0xf8a10078, 0xf8c10080",
    ".long 0xf8e10088, 0xf9010090, 0xf9210098, 0xf94100a0",
    "addi 3, 1, 0x50",
    "addi 4, 1, 0xd0",
    "li 5, 0",
    "bl openxbdm_detour_notify",
    "lwz 12, 88(1)",
    "rlwinm. 11, 12, 0, 26, 26",
    "beq .Ldetour_no_fp",
    "mr 3, 1",
    "bl openxbdm_detour_save_fp",
    ".Ldetour_no_fp:",
    "lwz 12, 88(1)",
    "rlwinm. 11, 12, 0, 25, 25",
    "beq .Ldetour_no_vector",
    "mr 3, 1",
    "bl openxbdm_detour_save_vector",
    ".Ldetour_no_vector:",
    "lwz 12, 96(1)",
    "cmplwi 12, 0",
    "lwz 3, 100(1)",
    "beq .Ldetour_discarded",
    "mr 3, 1",
    "lwz 4, 92(1)",
    "bl openxbdm_detour_call_original",
    ".Ldetour_discarded:",
    "stw 3, 100(1)",
    "addi 3, 1, 0x50",
    "li 4, 0",
    "li 5, 3",
    "bl openxbdm_detour_notify",
    "lwz 3, 100(1)",
    "addi 1, 1, 0xc0",
    "lwz 12, -8(1)",
    "mtlr 12",
    "blr",
    // 0x91f130ac: r3 = entry stub frame, r4 = parameter size. Copies the
    // parameter area into a frame of at least 0x40 + 0x30 bytes, reloads
    // r3-r10, and calls the function in the locals.
    "openxbdm_detour_call_original:",
    ".long 0xfbe1fff0", // std r31, -16(r1)
    "mflr 12",
    "stw 12, -8(1)",
    "mr 31, 1",
    "mr 12, 4",
    "cmplwi 4, 0x40",
    "bge .Ldetour_size",
    "li 12, 0x40",
    ".Ldetour_size:",
    "addi 12, 12, 0x30",
    "subf 12, 12, 1",
    "stw 1, 0(12)",
    "mr 1, 12",
    "stw 3, -20(31)",
    "stw 4, -24(31)",
    "lwz 5, 0(31)",
    "addi 5, 5, 0x10",
    "addi 6, 1, 0x10",
    "cmplwi 4, 0",
    "beq .Ldetour_copied",
    "mtctr 4",
    "addi 5, 5, -1",
    "addi 6, 6, -1",
    ".Ldetour_copy:",
    "lbzu 0, 1(5)",
    "stbu 0, 1(6)",
    "bdnz .Ldetour_copy",
    ".Ldetour_copied:",
    "lwz 12, -20(31)",
    // ld r3..r10, 0x68..0xa0(r12)
    ".long 0xe86c0068, 0xe88c0070, 0xe8ac0078, 0xe8cc0080",
    ".long 0xe8ec0088, 0xe90c0090, 0xe92c0098, 0xe94c00a0",
    "lwz 12, 96(12)",
    "mtctr 12",
    "bctrl",
    "lwz 1, 0(1)",
    ".long 0xebe1fff0", // ld r31, -16(r1)
    "lwz 12, -8(1)",
    "mtlr 12",
    "blr",
    // 0x91f1313c: f1-f13 at frame + 0x50, notification 1.
    "openxbdm_detour_save_fp:",
    "mflr 12",
    "stw 12, -8(1)",
    "stwu 1, -192(1)",
    ".irp reg, 1,2,3,4,5,6,7,8,9,10,11,12,13",
    "stfd \\reg, (72 + 8 * \\reg)(1)",
    ".endr",
    "addi 3, 1, 0x110",
    "addi 4, 1, 0x50",
    "li 5, 1",
    "bl openxbdm_detour_notify",
    "addi 1, 1, 0xc0",
    "lwz 12, -8(1)",
    "mtlr 12",
    "blr",
    // 0x91f1319c: v1-v13 stored at offsets 0x50 + 8 * (n - 1); stvx
    // ignores the low four address bits, so odd registers are overwritten
    // by the next one. Notification 2 logs 0xd0 bytes from frame + 0x50.
    "openxbdm_detour_save_vector:",
    "mflr 12",
    "stw 12, -8(1)",
    "stwu 1, -288(1)",
    ".irp reg, 1,2,3,4,5,6,7,8,9,10,11,12,13",
    "li 11, (72 + 8 * \\reg)",
    // stvx \reg, r11, r1
    ".long (31 << 26) | (\\reg << 21) | (11 << 16) | (1 << 11) | (231 << 1)",
    ".endr",
    "addi 3, 1, 0x170",
    "addi 4, 1, 0x50",
    "li 5, 2",
    "bl openxbdm_detour_notify",
    "addi 1, 1, 0x120",
    "lwz 12, -8(1)",
    "mtlr 12",
    "blr",
    // Logger call from title code: keep the full 64-bit r14-r31 and the
    // floating-point argument registers around the 32-bit Rust logger.
    "openxbdm_detour_notify:",
    "stwu 1, -0x110(1)",
    "mflr 0",
    "stw 0, 0x100(1)",
    ".irp reg, 14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31",
    // std \reg, 8 + 8 * (\reg - 14)(r1)
    ".long (62 << 26) | (\\reg << 21) | (1 << 16) | (8 + 8 * (\\reg - 14))",
    ".endr",
    ".irp reg, 1,2,3,4,5,6,7,8,9,10,11,12,13",
    "stfd \\reg, (0x90 + 8 * \\reg)(1)",
    ".endr",
    "bl openxbdm_detour_notify_rust",
    ".irp reg, 1,2,3,4,5,6,7,8,9,10,11,12,13",
    "lfd \\reg, (0x90 + 8 * \\reg)(1)",
    ".endr",
    ".irp reg, 14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31",
    // ld \reg, 8 + 8 * (\reg - 14)(r1)
    ".long (58 << 26) | (\\reg << 21) | (1 << 16) | (8 + 8 * (\\reg - 14))",
    ".endr",
    "lwz 0, 0x100(1)",
    "mtlr 0",
    "addi 1, 1, 0x110",
    "blr",
    // 0x2e8 trampolines of 0x58 bytes (0x91f13230); module init writes the
    // first two words of each.
    ".p2align 3",
    ".globl openxbdm_detour_trampolines",
    "openxbdm_detour_trampolines:",
    ".rept 0x3ff0",
    ".long 0x7c000038",
    ".endr",
    ".previous",
);

unsafe extern "C" {
    static openxbdm_detour_entry: u32;
    static openxbdm_detour_trampolines: u32;
}

fn trampolines() -> u32 {
    &raw const openxbdm_detour_trampolines as usize as u32
}

fn entry_stub() -> u32 {
    &raw const openxbdm_detour_entry as usize as u32
}

const _: () = assert!(detour::ENTRY_COUNT * detour::TRAMPOLINE_SIZE == 0x3ff0 * 4);

static ENGINE: Engine = Engine::new();
/// A record returned to the pool (0x91f9f4c8).
static RECORD_FREED: KernelEvent = KernelEvent::new();
/// A record queued for the writer (0x91f9f4d8).
static RECORD_QUEUED: KernelEvent = KernelEvent::new();
/// The writer finished (0x91f9f4e8); signaled while no writer runs.
static WRITER_DONE: KernelEvent = KernelEvent::new();
/// A completion was queued (0x91f9f308).
static COMPLETION_WORK: KernelEvent = KernelEvent::new();
/// The completion worker must exit (0x91f9f318).
static COMPLETION_STOP: KernelEvent = KernelEvent::new();
static COMPLETION_LOCK: CriticalSection = CriticalSection::new();
/// Thread object of the completion worker (0x91f9e4c8).
static COMPLETION_THREAD: HandleSlot = HandleSlot::new();
static WRITE_HANDLE: HandleSlot = HandleSlot::new();
static READ_HANDLE: HandleSlot = HandleSlot::new();
static LOG_PATH: LogPath = LogPath(UnsafeCell::new(None));
/// Record pool storage, obtained at the first start and kept; 0 before.
static RECORDS: AtomicU32 = AtomicU32::new(0);

/// Stock passes a positive (absolute, already past) timeout, so these
/// waits return at once.
const ELAPSED_TIMEOUT: i64 = 1_000_000;
const COMPLETION_POLL: i64 = relative_interval(Duration::from_millis(
    detour::COMPLETION_POLL_MILLISECONDS as u64,
));
const WORKER_STACK_SIZE: u32 = 0x8000;
const WORKER_FLAGS: ThreadCreationFlags =
    kernel::SYSTEM_THREAD_FLAGS.union(ThreadCreationFlags::EXEMPT_FROM_STOPS);
/// Bytes of an object path the log name translates to.
const LOG_PATH_CAPACITY: usize = 0x141;

/// A kernel handle or object pointer that may be absent.
struct HandleSlot {
    open: AtomicBool,
    handle: AtomicU32,
}

impl HandleSlot {
    const fn new() -> Self {
        Self {
            open: AtomicBool::new(false),
            handle: AtomicU32::new(0),
        }
    }

    fn get(&self) -> Option<u32> {
        self.open
            .load(Ordering::Acquire)
            .then(|| self.handle.load(Ordering::Relaxed))
    }

    fn set(&self, handle: u32) {
        self.handle.store(handle, Ordering::Relaxed);
        self.open.store(true, Ordering::Release);
    }

    fn take(&self) -> Option<u32> {
        let handle = self.get();
        self.open.store(false, Ordering::Release);
        handle
    }
}

/// Translated log name the writer opens; written by the server thread
/// before the writer starts.
struct LogPath(UnsafeCell<Option<([u8; LOG_PATH_CAPACITY], usize)>>);

// SAFETY: the server thread writes the path only while no writer runs.
unsafe impl Sync for LogPath {}

/// Platform services on the console; callable from any thread.
struct ConsolePlatform;

impl detour::Platform for ConsolePlatform {
    fn trampolines(&self) -> u32 {
        trampolines()
    }

    fn timebase(&self) -> u64 {
        Timebase::now().ticks()
    }

    fn system_time(&self) -> u64 {
        FileTime::now().intervals()
    }

    fn tick_count(&self) -> u32 {
        TickCount::now().milliseconds()
    }

    /// 0x91f72a58: [`INFINITE`] sleeps forever.
    fn sleep(&self, milliseconds: u32) {
        let interval = if milliseconds == INFINITE {
            i64::MIN
        } else {
            relative_interval(Duration::from_millis(milliseconds as u64))
        };
        // SAFETY: `interval` is a live local.
        unsafe { xboxkrnl::KeDelayExecutionThread(ProcessorMode::User, false, &interval) };
    }

    fn wait_for_record(&self) {
        // SAFETY: `RECORD_FREED` is a static event initialized by `initialize`.
        unsafe {
            xboxkrnl::KeWaitForSingleObject(
                RECORD_FREED.pointer().cast(),
                WaitReason::Executive,
                ProcessorMode::Kernel,
                false,
                &ELAPSED_TIMEOUT,
            )
        };
    }

    fn records(&self) -> Option<&'static [AtomicU32]> {
        let base = RECORDS.load(Ordering::Acquire);
        if base == 0 {
            return None;
        }
        // SAFETY: the pool block holds the storage, is aligned for words,
        // and is never freed.
        Some(unsafe {
            core::slice::from_raw_parts(
                base as usize as *const AtomicU32,
                detour::RECORD_STORAGE_WORDS,
            )
        })
    }

    /// Stock 0x91f2cb28 allocates 0x1c00 bytes, tag `Detr`, pool type 2.
    fn allocate_records(&self) -> bool {
        if RECORDS.load(Ordering::Acquire) != 0 {
            return true;
        }
        // SAFETY: pool allocation has no pointer arguments.
        let base = unsafe {
            xboxkrnl::ExAllocatePoolTypeWithTag(
                (detour::RECORD_STORAGE_WORDS * 4) as u32,
                pool_tag::DETOUR,
                PoolType::System,
            )
        };
        RECORDS.store(base, Ordering::Release);
        base != 0
    }

    fn record_queued(&self) {
        RECORD_QUEUED.set();
    }

    fn record_freed(&self) {
        RECORD_FREED.set();
    }

    // The engine passes addresses in the stub locals, the hooked call's
    // stack parameters or register save area, which stay live during the
    // hooked call, or the call's XOVERLAPPED, which the title keeps live
    // until the completion worker has written it. The trait from
    // openxbdm-server takes addresses and is safe, so these four rely on
    // that engine contract instead of an `unsafe fn` signature.

    fn read_u32(&self, address: u32) -> u32 {
        // SAFETY: the engine contract above; stock does not align them.
        unsafe { core::ptr::with_exposed_provenance::<u32>(address as usize).read_unaligned() }
    }

    fn read_u64(&self, address: u32) -> u64 {
        // SAFETY: the engine contract above; stock does not align them.
        unsafe { core::ptr::with_exposed_provenance::<u64>(address as usize).read_unaligned() }
    }

    fn read_block(&self, address: u32, output: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the engine contract above.
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::with_exposed_provenance::<u8>(address as usize),
                output.as_mut_ptr(),
                BLOCK_SIZE,
            )
        };
    }

    fn write_u32(&self, address: u32, value: u32) {
        // SAFETY: the engine contract above: an aligned word of the title's
        // XOVERLAPPED, which title threads may read concurrently.
        let word = unsafe {
            AtomicU32::from_ptr(core::ptr::with_exposed_provenance_mut::<u32>(
                address as usize,
            ))
        };
        word.store(value, Ordering::Relaxed);
    }

    fn reference_event(&self, handle: u32) -> Option<u32> {
        let mut object = 0u32;
        // SAFETY: `object` is a live local; the kernel validates the handle.
        unsafe { xboxkrnl::ObReferenceObjectByHandle(Handle::from_raw(handle), 0, &mut object) };
        (object != 0).then_some(object)
    }

    fn signal_event(&self, event: u32) {
        // SAFETY: `event` is an event object referenced by `reference_event`.
        unsafe { xboxkrnl::KeSetEvent(event as usize as *mut Kevent, EVENT_INCREMENT, false) };
    }

    fn lock_completions(&self) {
        COMPLETION_LOCK.enter();
    }

    fn unlock_completions(&self) {
        COMPLETION_LOCK.leave();
    }

    fn completion_queued(&self) {
        COMPLETION_WORK.set();
    }

    fn completions_idle(&self) {
        COMPLETION_WORK.reset();
    }
}

/// Module init (0x91f2c458): link the entry table and write `li r12, id`
/// and a branch to the entry stub at the start of every trampoline.
pub(crate) fn initialize() {
    /// `li r12, 0`; the entry id goes in the low half.
    const LOAD_ENTRY_ID: u32 = 0x3980_0000;
    /// `b 0`; the word offset goes in the masked bits.
    const BRANCH: u32 = 0x4800_0000;
    const BRANCH_OFFSET_MASK: u32 = 0x03ff_fffc;
    ENGINE.initialize();
    RECORD_FREED.initialize();
    RECORD_QUEUED.initialize();
    WRITER_DONE.initialize();
    WRITER_DONE.set();
    COMPLETION_WORK.initialize();
    COMPLETION_STOP.initialize();
    COMPLETION_LOCK.initialize();
    let entry = entry_stub();
    for id in 0..detour::ENTRY_COUNT {
        let trampoline = trampolines() + id * detour::TRAMPOLINE_SIZE;
        write_code_word(trampoline, LOAD_ENTRY_ID | id);
        write_code_word(
            trampoline + 4,
            BRANCH | (entry.wrapping_sub(trampoline + 4) & BRANCH_OFFSET_MASK),
        );
    }
}

/// Write an instruction word of this module's code section through a
/// writable debugger mapping.
fn write_code_word(address: u32, value: u32) {
    let mut context = [0u32; super::WRITE_CONTEXT_WORDS];
    // SAFETY: `context` is a live local of the size the kernel fills.
    let mapped = unsafe { xboxkrnl::MmDbgWriteCheck(address, context.as_mut_ptr()) };
    if mapped == 0 {
        return;
    }
    let pointer = mapped as usize as *mut u32;
    // SAFETY: the kernel mapped the aligned code word writable for the
    // debugger; `mapped` and `context` come from `MmDbgWriteCheck` above.
    // The sweep takes the pointer, so the store is kept before it.
    unsafe {
        pointer.write(value);
        xboxkrnl::KeSweepIcacheRange(pointer.cast(), 4);
        xboxkrnl::MmDbgReleaseAddress(mapped, context.as_mut_ptr());
    }
}

/// The entry stub's locals (stub frame + 0x50) in the title's stack, up to
/// the last field the logger uses. Stock accesses them without assuming
/// alignment.
#[repr(C, packed)]
struct StubLocals {
    hook: u32,
    sequence: u32,
    flags: u32,
    param_size: u32,
    function: u32,
    return_value: u32,
    registers: [u64; 8],
    overlapped: u32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(StubLocals, hook) == CallContext::HOOK as usize);
    assert!(offset_of!(StubLocals, sequence) == CallContext::SEQUENCE as usize);
    assert!(offset_of!(StubLocals, flags) == CallContext::FLAGS as usize);
    assert!(offset_of!(StubLocals, param_size) == CallContext::PARAM_SIZE as usize);
    assert!(offset_of!(StubLocals, function) == CallContext::FUNCTION as usize);
    assert!(offset_of!(StubLocals, return_value) == CallContext::RETURN_VALUE as usize);
    assert!(offset_of!(StubLocals, registers) == CallContext::REGISTERS as usize);
    assert!(offset_of!(StubLocals, overlapped) == CallContext::OVERLAPPED as usize);
};

impl StubLocals {
    /// The engine's view of the locals at `address`.
    fn context(&self, address: u32) -> CallContext {
        let optional = |value: u32| (value != 0).then_some(value);
        CallContext {
            address,
            hook: self.hook,
            sequence: self.sequence,
            flags: detour::HookFlags::from_bits_retain(self.flags),
            param_size: self.param_size,
            function: optional(self.function),
            return_value: detour::ReturnValue(self.return_value),
            registers: self.registers,
            overlapped: optional(self.overlapped),
        }
    }

    /// Write back the fields the engine may change.
    fn store(&mut self, call: &CallContext) {
        self.sequence = call.sequence;
        self.flags = call.flags.bits();
        self.param_size = call.param_size;
        // The stub reads 0 as a discarded call and no XOVERLAPPED.
        self.function = call.function.unwrap_or(0);
        self.return_value = call.return_value.0;
        self.overlapped = call.overlapped.unwrap_or(0);
    }
}

/// Notification codes the stubs pass to the logger.
mod notification {
    /// Entry, with the stack parameters.
    pub(super) const ENTER: u32 = 0;
    /// f1-f13 saved.
    pub(super) const FLOATING_POINT: u32 = 1;
    /// v1-v13 saved.
    pub(super) const VECTOR: u32 = 2;
    /// The call returned.
    pub(super) const EXIT: u32 = 3;
}

/// Logger entry from the stubs (0x91f2c6d0): `context` is the stub
/// locals, `area` the stack parameters (notification 0) or a register save
/// area (1, 2).
#[unsafe(no_mangle)]
extern "C" fn openxbdm_detour_notify_rust(context: u32, area: u32, notify: u32) {
    let locals = core::ptr::with_exposed_provenance_mut::<StubLocals>(context as usize);
    // SAFETY: the stubs pass the address of their locals, which stay live
    // on the calling thread's stack for this call.
    let mut call = unsafe { &*locals }.context(context);
    match notify {
        notification::ENTER => ENGINE.enter(&ConsolePlatform, &mut call, area),
        notification::FLOATING_POINT => ENGINE.floating_point(&ConsolePlatform, &call, area),
        notification::VECTOR => ENGINE.vector(&ConsolePlatform, &call, area),
        notification::EXIT => ENGINE.exit(&ConsolePlatform, &mut call),
        _ => return,
    }
    // SAFETY: as above; the engine's accesses to the locals have ended.
    unsafe { &mut *locals }.store(&call);
}

/// Run `operation` with the engine.
pub(super) fn with_engine(operation: &mut dyn FnMut(&Engine, &dyn detour::Platform)) {
    operation(&ENGINE, &ConsolePlatform);
}

/// Create the writer and completion workers (0x91f2d378).
pub(super) fn start(log: Option<&[u8]>) -> Result<(), KernelError> {
    // SAFETY: no writer runs while the engine is starting.
    let stored = unsafe { &mut *LOG_PATH.0.get() };
    *stored = None;
    if let Some(log) = log {
        let length = log.len().min(LOG_PATH_CAPACITY);
        let (bytes, _) = stored.insert(([0; LOG_PATH_CAPACITY], length));
        bytes[..length].copy_from_slice(&log[..length]);
    }
    let mut writer = 0u32;
    let mut completion = 0u32;
    // SAFETY: the thread entries are functions of this module and the
    // handle outputs are live locals.
    unsafe {
        WRITER_DONE.reset();
        let created = xboxkrnl::ExCreateThread(
            &mut writer,
            WORKER_STACK_SIZE,
            core::ptr::null_mut(),
            0,
            writer_thread as *const () as usize as u32,
            0,
            WORKER_FLAGS,
        );
        created.result()?;
        let created = xboxkrnl::ExCreateThread(
            &mut completion,
            WORKER_STACK_SIZE,
            core::ptr::null_mut(),
            0,
            completion_thread as *const () as usize as u32,
            0,
            WORKER_FLAGS,
        );
        created.result()?;
    }
    COMPLETION_THREAD.set(completion);
    Ok(())
}

/// The rest of `stop` (0x91f2cd54).
pub(super) fn stop(log: Option<&[u8]>) {
    // SAFETY: `RECORD_QUEUED` is a static event initialized by `initialize`.
    unsafe { xboxkrnl::KeSetEvent(RECORD_QUEUED.pointer(), EVENT_INCREMENT, true) };
    WRITER_DONE.wait();
    if let Some(log) = log {
        let name = kernel::ansi_string(log);
        let attributes = ObjectAttributes {
            root_directory: Handle::NULL,
            object_name: &name,
            attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
        };
        // SAFETY: `attributes` refers to `name`, which refers to `log`.
        unsafe { xboxkrnl::NtDeleteFile(&attributes) };
    }
    // SAFETY: `COMPLETION_STOP` is a static event initialized by
    // `initialize`; `thread` is the referenced completion worker thread
    // object.
    unsafe {
        xboxkrnl::KeSetEvent(COMPLETION_STOP.pointer(), EVENT_INCREMENT, true);
        if let Some(thread) = COMPLETION_THREAD.take() {
            xboxkrnl::KeWaitForSingleObject(
                thread as usize as *mut DispatcherObject,
                WaitReason::Executive,
                ProcessorMode::Kernel,
                false,
                core::ptr::null(),
            );
            xboxkrnl::ObDereferenceObject(thread);
        }
    }
    COMPLETION_STOP.reset();
    COMPLETION_WORK.reset();
    ENGINE.finish_stop(&ConsolePlatform);
}

/// One `log getentries` read from the read handle (0x91f2bc90).
pub(super) fn read_record(output: &mut [u8; RECORD_SIZE]) -> bool {
    if !ENGINE.has_unread() {
        return false;
    }
    let Some(handle) = READ_HANDLE.get() else {
        return false;
    };
    let mut io = IoStatusBlock::default();
    // SAFETY: `output` holds RECORD_SIZE bytes and `io` is a live local.
    let status = unsafe {
        xboxkrnl::NtReadFile(
            Handle::from_raw(handle),
            Handle::NULL,
            0,
            0,
            &mut io,
            output.as_mut_ptr(),
            RECORD_SIZE as u32,
            core::ptr::null(),
        )
    };
    if status.severity() == Severity::Error {
        return false;
    }
    ENGINE.note_read();
    true
}

/// Create request of the log with `access` and `disposition`.
const fn log_request(access: FileAccess, disposition: CreateDisposition) -> CreateRequest {
    CreateRequest {
        access,
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::ALL,
        disposition,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    }
}

/// Create the log for writing and open it again for reading
/// (0x91f2cb28).
fn open_log() -> Result<(), KernelError> {
    const WRITE: CreateRequest =
        log_request(FileAccess::GENERIC_WRITE, CreateDisposition::OverwriteIf);
    const READ: CreateRequest = log_request(
        FileAccess::GENERIC_READ.union(FileAccess::SYNCHRONIZE),
        CreateDisposition::Open,
    );
    // SAFETY: the server thread wrote the path before creating this thread.
    let Some((bytes, length)) = (unsafe { &*LOG_PATH.0.get() }) else {
        return Err(KernelError::NoSuchFile);
    };
    let path = &bytes[..*length];
    WRITE_HANDLE.set(create_file(path, &WRITE)?.0);
    READ_HANDLE.set(create_file(path, &READ)?.0);
    Ok(())
}

/// 0x91f2b930.
fn close_log() {
    for slot in [&READ_HANDLE, &WRITE_HANDLE] {
        if let Some(handle) = slot.take() {
            // SAFETY: the slot held an open handle and `take` cleared it.
            unsafe { xboxkrnl::NtClose(Handle::from_raw(handle)) };
        }
    }
}

fn write_record(record: &[u8; RECORD_SIZE]) -> bool {
    let Some(handle) = WRITE_HANDLE.get() else {
        return false;
    };
    let mut io = IoStatusBlock::default();
    // SAFETY: `record` holds RECORD_SIZE bytes and `io` is a live local.
    let status = unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(handle),
            Handle::NULL,
            0,
            0,
            &mut io,
            record.as_ptr(),
            RECORD_SIZE as u32,
            core::ptr::null(),
        )
    };
    status.is_success()
}

/// Log writer (0x91f2d040).
extern "C" fn writer_thread(_context: u32) -> u32 {
    const EXIT_SUCCESS: u32 = 0;
    const EXIT_FAILURE: u32 = 1;
    if !ENGINE.prepare_log(&ConsolePlatform) {
        ENGINE.abort_start();
        WRITER_DONE.set();
        return EXIT_FAILURE;
    }
    let opened = open_log();
    ENGINE.set_log_result(opened);
    if opened.is_err() {
        close_log();
        ENGINE.abort_start();
        WRITER_DONE.set();
        return EXIT_FAILURE;
    }
    ENGINE.mark_running();
    while ENGINE.writing() {
        RECORD_QUEUED.wait();
        ENGINE.write_queued(&ConsolePlatform, &mut write_record);
    }
    while ENGINE.discard_queued(&ConsolePlatform) {
        // SAFETY: `RECORD_QUEUED` is a static event initialized by `initialize`.
        unsafe {
            xboxkrnl::KeWaitForSingleObject(
                RECORD_QUEUED.pointer().cast(),
                WaitReason::Executive,
                ProcessorMode::Kernel,
                false,
                &ELAPSED_TIMEOUT,
            )
        };
    }
    close_log();
    WRITER_DONE.set();
    EXIT_SUCCESS
}

/// Completion worker (0x91f2d2b8, 0x91f2c2f8). Stock's poll wait consumes
/// the stop signal and then waits again for work, so a `stop` with delayed
/// completions pending never finishes; here the consumed signal ends the
/// worker.
extern "C" fn completion_thread(_context: u32) -> u32 {
    /// Wait block storage stock passes for the two objects.
    const WAIT_BLOCK_WORDS: usize = 0x10;
    let objects: [*mut DispatcherObject; 2] = [
        COMPLETION_WORK.pointer().cast(),
        COMPLETION_STOP.pointer().cast(),
    ];
    let mut wait_blocks = [0u32; WAIT_BLOCK_WORDS];
    // SAFETY: `objects` holds two static events initialized by
    // `initialize`; `wait_blocks` is a live local.
    while unsafe {
        xboxkrnl::KeWaitForMultipleObjects(
            objects.len() as u32,
            objects.as_ptr(),
            WaitType::Any,
            WaitReason::Executive,
            ProcessorMode::Kernel,
            false,
            core::ptr::null(),
            wait_blocks.as_mut_ptr(),
        )
    } == NtStatus::WAIT_0
    {
        while ENGINE.service_completions(&ConsolePlatform) {
            // SAFETY: `COMPLETION_STOP` is a static event initialized by `initialize`.
            let waited = unsafe {
                xboxkrnl::KeWaitForSingleObject(
                    COMPLETION_STOP.pointer().cast(),
                    WaitReason::Executive,
                    ProcessorMode::Kernel,
                    false,
                    &COMPLETION_POLL,
                )
            };
            if waited != NtStatus::TIMEOUT {
                return 0;
            }
        }
    }
    0
}
