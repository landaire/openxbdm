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

use crate::backend::filesystem::create_file;
use crate::kernel;
use crate::kernel::AnsiString;
use crate::kernel::CriticalSection;
use crate::kernel::IoStatusBlock;
use crate::kernel::KernelEvent;
use crate::kernel::ObjectAttributes;

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

/// Stock passes a positive (absolute, already past) timeout, so these
/// waits return at once.
const ELAPSED_TIMEOUT: i64 = 1_000_000;
const COMPLETION_POLL: i64 = -(detour::COMPLETION_POLL_MILLISECONDS as i64) * 10_000;
const STATUS_TIMEOUT: u32 = 0x102;
const STATUS_NO_SUCH_FILE: u32 = 0xc000_000f;
const WORKER_STACK_SIZE: u32 = 0x8000;
const WORKER_FLAGS: u32 = 0x0400_02a6;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ_SYNCHRONIZE: u32 = 0x8010_0000;
const WAIT_ANY: u32 = 1;
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
        kernel::timebase()
    }

    fn system_time(&self) -> u64 {
        kernel::system_time()
    }

    fn tick_count(&self) -> u32 {
        kernel::tick_count()
    }

    /// 0x91f72a58: `u32::MAX` sleeps forever.
    fn sleep(&self, milliseconds: u32) {
        let interval = if milliseconds == u32::MAX {
            i64::MIN
        } else {
            -(i64::from(milliseconds) * 10_000)
        };
        kernel::KeDelayExecutionThread(1, 0, &interval);
    }

    fn wait_for_record(&self) {
        kernel::KeWaitForSingleObject(RECORD_FREED.pointer(), 0, 0, 0, &ELAPSED_TIMEOUT);
    }

    fn record_queued(&self) {
        RECORD_QUEUED.set();
    }

    fn record_freed(&self) {
        RECORD_FREED.set();
    }

    fn read_u32(&self, address: u32) -> u32 {
        // SAFETY: the title supplied the address as stock reads it.
        unsafe { core::ptr::read_unaligned(address as usize as *const u32) }
    }

    fn read_u64(&self, address: u32) -> u64 {
        // SAFETY: as above.
        unsafe { core::ptr::read_unaligned(address as usize as *const u64) }
    }

    fn read_block(&self, address: u32, output: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: as above.
        unsafe {
            core::ptr::copy_nonoverlapping(
                address as usize as *const u8,
                output.as_mut_ptr(),
                BLOCK_SIZE,
            )
        };
    }

    fn write_u32(&self, address: u32, value: u32) {
        // SAFETY: the address is the title's overlapped structure.
        unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) };
    }

    fn reference_event(&self, handle: u32) -> Option<u32> {
        let mut object = 0u32;
        kernel::ObReferenceObjectByHandle(handle, 0, &mut object);
        (object != 0).then_some(object)
    }

    fn signal_event(&self, event: u32) {
        kernel::KeSetEvent(event as usize as *mut u32, 1, 0);
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
        kernel::KeResetEvent(COMPLETION_WORK.pointer());
    }
}

/// Module init (0x91f2c458): link the entry table and write `li r12, id`
/// and a branch to the entry stub at the start of every trampoline.
pub(crate) fn initialize() {
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
        write_code_word(trampoline, 0x3980_0000 | id);
        write_code_word(
            trampoline + 4,
            0x4800_0000 | (entry.wrapping_sub(trampoline + 4) & 0x03ff_fffc),
        );
    }
}

/// Write an instruction word of this module's code section through a
/// writable debugger mapping.
fn write_code_word(address: u32, value: u32) {
    let mut context = [0u32; super::WRITE_CONTEXT_WORDS];
    let mapped = kernel::MmDbgWriteCheck(address, context.as_mut_ptr());
    if mapped == 0 {
        return;
    }
    let pointer = mapped as usize as *mut u32;
    // SAFETY: the kernel mapped the word writable for the debugger.
    unsafe { core::ptr::write_volatile(pointer, value) };
    kernel::KeSweepIcacheRange(pointer.cast(), 4);
    kernel::MmDbgReleaseAddress(mapped, context.as_mut_ptr());
}

fn load_context(address: u32) -> CallContext {
    let field = |offset: u32| ConsolePlatform.read_u32_at(address + offset);
    let optional = |value: u32| (value != 0).then_some(value);
    CallContext {
        address,
        hook: field(CallContext::HOOK),
        sequence: field(CallContext::SEQUENCE),
        flags: detour::HookFlags(field(CallContext::FLAGS)),
        param_size: field(CallContext::PARAM_SIZE),
        function: optional(field(CallContext::FUNCTION)),
        return_value: field(CallContext::RETURN_VALUE),
        registers: core::array::from_fn(|index| {
            detour::Platform::read_u64(
                &ConsolePlatform,
                address + CallContext::REGISTERS + index as u32 * 8,
            )
        }),
        overlapped: optional(field(CallContext::OVERLAPPED)),
    }
}

fn store_context(call: &CallContext) {
    let platform = ConsolePlatform;
    let store = |offset: u32, value: u32| {
        detour::Platform::write_u32(&platform, call.address + offset, value)
    };
    store(CallContext::SEQUENCE, call.sequence);
    store(CallContext::FLAGS, call.flags.0);
    store(CallContext::PARAM_SIZE, call.param_size);
    store(CallContext::FUNCTION, call.function.unwrap_or(0));
    store(CallContext::RETURN_VALUE, call.return_value);
    store(CallContext::OVERLAPPED, call.overlapped.unwrap_or(0));
}

impl ConsolePlatform {
    fn read_u32_at(&self, address: u32) -> u32 {
        detour::Platform::read_u32(self, address)
    }
}

/// Logger entry from the stubs (0x91f2c6d0): `context` is the stub
/// locals, `area` the stack parameters (notification 0) or a register save
/// area (1, 2).
#[unsafe(no_mangle)]
extern "C" fn openxbdm_detour_notify_rust(context: u32, area: u32, notify: u32) {
    let mut call = load_context(context);
    match notify {
        0 => ENGINE.enter(&ConsolePlatform, &mut call, area),
        1 => ENGINE.floating_point(&ConsolePlatform, &call, area),
        2 => ENGINE.vector(&ConsolePlatform, &call, area),
        3 => ENGINE.exit(&ConsolePlatform, &mut call),
        _ => return,
    }
    store_context(&call);
}

/// Run `operation` with the engine.
pub(super) fn with_engine(operation: &mut dyn FnMut(&Engine, &dyn detour::Platform)) {
    operation(&ENGINE, &ConsolePlatform);
}

/// Create the writer and completion workers (0x91f2d378).
pub(super) fn start(log: Option<&[u8]>) -> NtStatus {
    // SAFETY: no writer runs while the engine is starting.
    let stored = unsafe { &mut *LOG_PATH.0.get() };
    *stored = None;
    if let Some(log) = log {
        let length = log.len().min(LOG_PATH_CAPACITY);
        let (bytes, _) = stored.insert(([0; LOG_PATH_CAPACITY], length));
        bytes[..length].copy_from_slice(&log[..length]);
    }
    kernel::KeResetEvent(WRITER_DONE.pointer());
    let mut writer = 0u32;
    let status = kernel::ExCreateThread(
        &mut writer,
        WORKER_STACK_SIZE,
        core::ptr::null_mut(),
        0,
        writer_thread as *const () as usize as u32,
        0,
        WORKER_FLAGS,
    );
    if (status as i32) < 0 {
        return NtStatus(status);
    }
    let mut completion = 0u32;
    let status = kernel::ExCreateThread(
        &mut completion,
        WORKER_STACK_SIZE,
        core::ptr::null_mut(),
        0,
        completion_thread as *const () as usize as u32,
        0,
        WORKER_FLAGS,
    );
    if (status as i32) >= 0 {
        COMPLETION_THREAD.set(completion);
    }
    NtStatus(status)
}

/// The rest of `stop` (0x91f2cd54).
pub(super) fn stop(log: Option<&[u8]>) {
    kernel::KeSetEvent(RECORD_QUEUED.pointer(), 1, 1);
    WRITER_DONE.wait();
    if let Some(log) = log {
        let name = AnsiString::new(log);
        let attributes = ObjectAttributes {
            root_directory: 0,
            object_name: &name,
            attributes: OBJ_CASE_INSENSITIVE,
        };
        kernel::NtDeleteFile(&attributes);
    }
    kernel::KeSetEvent(COMPLETION_STOP.pointer(), 1, 1);
    if let Some(thread) = COMPLETION_THREAD.take() {
        kernel::KeWaitForSingleObject(thread as usize as *mut u32, 0, 0, 0, core::ptr::null());
        kernel::ObDereferenceObject(thread);
    }
    kernel::KeResetEvent(COMPLETION_STOP.pointer());
    kernel::KeResetEvent(COMPLETION_WORK.pointer());
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
    let status = kernel::NtReadFile(
        handle,
        0,
        0,
        0,
        &mut io,
        output.as_mut_ptr(),
        RECORD_SIZE as u32,
        core::ptr::null(),
    );
    if status & 0xc000_0000 == 0xc000_0000 {
        return false;
    }
    ENGINE.note_read();
    true
}

/// Create request of the log with `access` and `disposition`.
const fn log_request(access: u32, disposition: CreateDisposition) -> CreateRequest {
    CreateRequest {
        access: FileAccess(access),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::ALL,
        disposition,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    }
}

/// Create the log for writing and open it again for reading
/// (0x91f2cb28); the status of the last open.
fn open_log() -> u32 {
    const WRITE: CreateRequest = log_request(GENERIC_WRITE, CreateDisposition::OverwriteIf);
    const READ: CreateRequest = log_request(GENERIC_READ_SYNCHRONIZE, CreateDisposition::Open);
    // SAFETY: the server thread wrote the path before creating this thread.
    let Some((bytes, length)) = (unsafe { &*LOG_PATH.0.get() }) else {
        return STATUS_NO_SUCH_FILE;
    };
    let path = &bytes[..*length];
    match create_file(path, &WRITE) {
        Ok(handle) => WRITE_HANDLE.set(handle.0),
        Err(status) => return status.0,
    }
    match create_file(path, &READ) {
        Ok(handle) => {
            READ_HANDLE.set(handle.0);
            0
        }
        Err(status) => status.0,
    }
}

/// 0x91f2b930.
fn close_log() {
    for slot in [&READ_HANDLE, &WRITE_HANDLE] {
        if let Some(handle) = slot.take() {
            kernel::NtClose(handle);
        }
    }
}

fn write_record(record: &[u8; RECORD_SIZE]) -> bool {
    let Some(handle) = WRITE_HANDLE.get() else {
        return false;
    };
    let mut io = IoStatusBlock::default();
    let status = kernel::NtWriteFile(
        handle,
        0,
        0,
        0,
        &mut io,
        record.as_ptr(),
        RECORD_SIZE as u32,
        core::ptr::null(),
    );
    (status as i32) >= 0
}

/// Log writer (0x91f2d040).
extern "C" fn writer_thread(_context: u32) -> u32 {
    ENGINE.prepare_log();
    let status = open_log();
    ENGINE.set_status(NtStatus(status));
    if (status as i32) < 0 {
        close_log();
        ENGINE.abort_start();
        WRITER_DONE.set();
        return 1;
    }
    ENGINE.mark_running();
    while ENGINE.writing() {
        RECORD_QUEUED.wait();
        ENGINE.write_queued(&ConsolePlatform, &mut write_record);
    }
    while ENGINE.discard_queued(&ConsolePlatform) {
        kernel::KeWaitForSingleObject(RECORD_QUEUED.pointer(), 0, 0, 0, &ELAPSED_TIMEOUT);
    }
    close_log();
    WRITER_DONE.set();
    0
}

/// Completion worker (0x91f2d2b8, 0x91f2c2f8). Stock's poll wait consumes
/// the stop signal and then waits again for work, so a `stop` with delayed
/// completions pending never finishes; here the consumed signal ends the
/// worker.
extern "C" fn completion_thread(_context: u32) -> u32 {
    let objects = [
        COMPLETION_WORK.pointer() as usize as u32,
        COMPLETION_STOP.pointer() as usize as u32,
    ];
    let mut wait_blocks = [0u32; 0x10];
    while kernel::KeWaitForMultipleObjects(
        2,
        objects.as_ptr(),
        WAIT_ANY,
        0,
        0,
        0,
        core::ptr::null(),
        wait_blocks.as_mut_ptr(),
    ) == 0
    {
        while ENGINE.service_completions(&ConsolePlatform) {
            if kernel::KeWaitForSingleObject(COMPLETION_STOP.pointer(), 0, 0, 0, &COMPLETION_POLL)
                != STATUS_TIMEOUT
            {
                return 0;
            }
        }
    }
    0
}
