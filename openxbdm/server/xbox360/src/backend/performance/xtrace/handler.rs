use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::performance::xtrace;
use openxbdm_server::commands::performance::xtrace::Thread;
use xbox360::console::hardware_flags;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360_sys::processor::Msr;
use xbox360_sys::status::NtStatus;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Context;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::ExceptionRecord;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::KernelU32;
use xbox360_sys::xboxkrnl::KtrapFrame;

use super::ARMED;
use super::BASE;
use super::CACHE;
use super::CURRENT;
use super::Cache;
use super::Cursor;
use super::FAILED;
use super::RECORD_RESERVE;
use super::SESSION;
use super::STOP_REQUESTED;
use super::TERMINATE_REGISTERED;
use super::TITLE_TERMINATE;
use super::break_trap;
use super::instruction_at;
use super::queue_current;
use super::stop_entry;
use super::take_free_buffer;
use super::title_terminated_entry;
use crate::exports::bridged;
use crate::kernel;
use crate::kernel::RoutineVariable;

/// A kernel routine the handler runs natively instead of stepping through
/// it (its reservation loop never completes under single-step).
struct SpoofedRoutine {
    ordinal: Ordinal,
    /// The walk of the routine's body follows forward branches.
    follows_forward_branches: bool,
}

const SPOOFED_ROUTINES: [SpoofedRoutine; 5] = [
    // RtlEnterCriticalSection
    SpoofedRoutine {
        ordinal: Ordinal::new(0x125).unwrap(),
        follows_forward_branches: false,
    },
    // KeAcquireSpinLockAtRaisedIrql
    SpoofedRoutine {
        ordinal: Ordinal::new(0x4d).unwrap(),
        follows_forward_branches: false,
    },
    // KfAcquireSpinLock
    SpoofedRoutine {
        ordinal: Ordinal::new(0xb1).unwrap(),
        follows_forward_branches: false,
    },
    // ObReferenceObject
    SpoofedRoutine {
        ordinal: Ordinal::new(0x10f).unwrap(),
        follows_forward_branches: false,
    },
    // ObDereferenceObject
    SpoofedRoutine {
        ordinal: Ordinal::new(0x105).unwrap(),
        follows_forward_branches: true,
    },
];

static SPOOF_ENABLED: AtomicBool = AtomicBool::new(true);
static SPOOF_RESOLVED: AtomicBool = AtomicBool::new(false);
static SPOOF_TARGETS: [AtomicU32; SPOOFED_ROUTINES.len()] =
    [const { AtomicU32::new(0) }; SPOOFED_ROUTINES.len()];
pub(super) static SPOOFED: AtomicU32 = AtomicU32::new(0);

/// Address of the kernel debug routine variable this engine hooked, and
/// its prior value.
static ROUTINE_SLOT: AtomicU32 = AtomicU32::new(0);
static PREVIOUS_ROUTINE: AtomicU32 = AtomicU32::new(0);
/// Address of the kernel trace hook variable (debug monitor service 6).
pub(super) static HOOK_SLOT: AtomicU32 = AtomicU32::new(0);

/// Scratch output of a record made while no buffer is free; two encodings
/// of at most eight words each.
static SCRATCH: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];

/// The traced thread at a trace exception: its trap frame and its code.
struct TracedThread<'a>(&'a KtrapFrame);

impl Thread for TracedThread<'_> {
    unsafe fn instruction(&self, address: u32) -> u32 {
        // SAFETY: the encoder reads the instruction the thread is about to
        // execute and the one after a system call or trap it executed:
        // code of the traced thread, which is mapped.
        unsafe { instruction_at(address) }
    }

    fn gpr(&self, index: u32) -> u32 {
        // Register fields are five bits; the mask keeps the index in
        // bounds without a check.
        self.0.gpr[(index & 0x1f) as usize] as u32
    }

    fn xer(&self) -> u32 {
        self.0.xer
    }
}

/// The encoder's lookup cache in the session allocation.
///
/// # Safety
///
/// `initialize` set CACHE, and the session allocation stays allocated
/// while the result is used.
unsafe fn cache<'a>() -> &'a Cache {
    // SAFETY: `initialize` set CACHE to the cache of the session
    // allocation, which the caller keeps allocated.
    unsafe { &*CACHE.load(Ordering::Relaxed) }
}

/// Record the instruction at `iar` (stock 0x91f66288); false when no
/// buffer was free, which ends the recording. Runs in the traced thread's
/// handler.
fn record(iar: u32, frame: &KtrapFrame) -> bool {
    if BASE.load(Ordering::Acquire) == 0 {
        return false;
    }

    let current = CURRENT.load(Ordering::Acquire);
    let buffer = if current.is_null() {
        take_free_buffer()
    } else {
        current
    };
    // SAFETY: buffer slots hold null or an element of `BUFFERS`.
    let start = match unsafe { buffer.as_ref() } {
        Some(buffer) => {
            buffer.data.load(Ordering::Relaxed) + 4 * buffer.used.load(Ordering::Relaxed)
        }
        None => kernel::address_of(&SCRATCH),
    };

    // SAFETY: `start` is the free part of the current stream buffer in the
    // session allocation, or the scratch block, which holds two encodings.
    // A buffer keeps only RECORD_RESERVE (8) words free, but a record after
    // a system call or trap is two encodings of up to 16 words: with 8 to
    // 15 words free it runs into the next buffer, which the kernel may be
    // writing to the file for the writer thread, or, past the last buffer,
    // into the start of the cache, as in stock. Both stay in the
    // allocation, and the cache is atomic. The allocation stays while the
    // handler runs, except under a stop or save on another thread, which
    // frees it without synchronizing with the handler, as in stock.
    let mut cursor = unsafe { Cursor::new(start) };
    // SAFETY: as above.
    let cache = unsafe { cache() };
    // SAFETY: `iar` is the traced thread's next instruction at this trace
    // exception. The encoder's skipped address is the word after a system
    // call or trap the thread executed: its return address, in the same code.
    unsafe {
        SESSION
            .encoder
            .record(iar, &TracedThread(frame), cache, &mut cursor)
    };

    // SAFETY: buffer slots hold null or an element of `BUFFERS`.
    let Some(buffer) = (unsafe { CURRENT.load(Ordering::Acquire).as_ref() }) else {
        SESSION.stop_address.store(iar, Ordering::Relaxed);
        FAILED.store(true, Ordering::Release);
        return false;
    };

    let used = buffer.used.load(Ordering::Relaxed) + (cursor.0 - start) / 4;
    buffer.used.store(used, Ordering::Release);
    if buffer.capacity.load(Ordering::Relaxed).wrapping_sub(used) < RECORD_RESERVE {
        queue_current();
    }

    true
}

/// Skip the way out of the start function, then record; false ends the
/// recording. Runs in the traced thread's handler.
fn skip_or_record(iar: u32, frame: &KtrapFrame) -> bool {
    let returns = SESSION.skip_returns.load(Ordering::Relaxed);
    let instructions = SESSION.skip_instructions.load(Ordering::Relaxed);
    if returns != 0 && instructions != 0 {
        SESSION
            .skip_instructions
            .store(instructions - 1, Ordering::Relaxed);
        // SAFETY: `iar` is the instruction the traced thread is about to
        // execute, which is mapped code.
        if unsafe { instruction_at(iar) } == xtrace::BLR {
            SESSION.skip_returns.store(returns - 1, Ordering::Relaxed);
        }
        return true;
    }

    record(iar, frame)
}

fn spoofed_routine(iar: u32) -> Option<usize> {
    SPOOF_TARGETS
        .iter()
        .rposition(|target| target.load(Ordering::Relaxed) == iar)
}

/// Call the console routine at `function` with r3 loaded from the 64-bit
/// value at `argument`, and store its 64-bit result. The CPU model of the
/// target has no 64-bit mnemonics, so `ld`/`std` are encoded directly.
///
/// # Safety
///
/// `function` is a console routine that takes one 64-bit argument in r3
/// and may run on the calling thread; `argument` is readable and `result`
/// writable, both 8-byte aligned.
#[unsafe(naked)]
unsafe extern "C" fn call_native(function: u32, argument: *const u64, result: *mut u64) {
    core::arch::naked_asm!(
        "stwu 1, -0x60(1)",
        "mflr 0",
        "stw 0, 0x64(1)",
        "stw 5, 0x58(1)",
        "mtctr 3",
        // ld 3, 0(4)
        ".long 0xe8640000",
        "bctrl",
        "lwz 5, 0x58(1)",
        // std 3, 0(5)
        ".long 0xf8650000",
        "lwz 0, 0x64(1)",
        "mtlr 0",
        "addi 1, 1, 0x60",
        "blr",
    )
}

/// Run a spoofed routine natively and record its body up to its `blr` as
/// if it had been stepped, with r4, r5, r11, and r31 set to plausible
/// values for the effective addresses. The thread resumes at the `blr`
/// with the routine's result.
fn spoof(
    entry: usize,
    frame: &mut KtrapFrame,
    exception: &mut ExceptionRecord,
    context: &mut Context,
) -> u32 {
    /// Distance below the argument of the plausible addresses.
    const STACK_OFFSET: u64 = 0x10;
    /// `bc`: a conditional branch, forward when the sign bit of its
    /// displacement is clear.
    const OPCODE: u32 = 0xfc00_0000;
    const BRANCH_CONDITIONAL: u32 = 0x4000_0000;
    const DISPLACEMENT_SIGN: u32 = 0x8000;
    const DISPLACEMENT: u32 = 0xfffc;
    const INSTRUCTION_SIZE: u32 = 4;

    SPOOFED.fetch_add(1, Ordering::Relaxed);
    let function = SPOOF_TARGETS[entry].load(Ordering::Relaxed);
    let mut result = 0u64;
    // SAFETY: `function` is a resolved kernel routine of SPOOFED_ROUTINES,
    // which takes the r3 of the trapped call; `argument` is that register in
    // the trap frame and `result` a live local.
    unsafe { call_native(function, &frame.gpr[3], &mut result) };

    let saved = *frame;
    let argument = frame.gpr[3];
    frame.gpr[5] = STACK_OFFSET;
    frame.gpr[11] = argument.wrapping_sub(STACK_OFFSET);
    frame.gpr[4] = argument;
    frame.gpr[31] = argument.wrapping_sub(STACK_OFFSET);

    let follow_forward = SPOOFED_ROUTINES[entry].follows_forward_branches;
    let mut address = function;
    loop {
        // SAFETY: `address` walks the body of a resolved kernel routine up
        // to its `blr`, which is mapped kernel code.
        let word = unsafe { instruction_at(address) };
        if word == xtrace::BLR {
            break;
        }

        frame.iar = address;
        exception.address = address;
        record(address, frame);

        let forward_branch = word & OPCODE == BRANCH_CONDITIONAL && word & DISPLACEMENT_SIGN == 0;
        address = address.wrapping_add(if follow_forward && forward_branch {
            word & DISPLACEMENT
        } else {
            INSTRUCTION_SIZE
        });
    }

    *frame = saved;
    context.iar = address;
    context.gpr[3] = result;
    exception.address = address;

    address
}

fn stop_entry_address() -> u32 {
    stop_entry as *const () as usize as u32
}

/// Kernel trace hook (stock 0x91f66ab0): handles trace exceptions before
/// the debug routine. Spoofed routines are left to the debug routine.
extern "C" fn trace_hook(trap_frame: u32, record_address: u32) -> u32 {
    // SAFETY: the kernel passes the exception record of the current
    // exception of this thread, which it does not change during the call.
    let exception = unsafe { crate::kernel::object_at::<ExceptionRecord>(record_address) };
    if exception.code != NtStatus::SINGLE_STEP {
        return 0;
    }

    // SAFETY: the kernel passes the trap frame of the current exception of
    // this thread; nothing else uses it during the call.
    let frame = unsafe { crate::kernel::object_at_mut::<KtrapFrame>(trap_frame) };
    if ARMED.load(Ordering::Acquire) && !FAILED.load(Ordering::Acquire) {
        let iar = exception.address;
        let stop = iar == stop_entry_address() || STOP_REQUESTED.load(Ordering::Acquire);
        if SPOOF_ENABLED.load(Ordering::Relaxed) {
            let spoofed = spoofed_routine(iar).is_some();
            // The spin lock routines do not run natively on a console with
            // this flag.
            let spoofed = if hardware_flags().contains(HardwareFlags::TEST_KIT) {
                SPOOF_ENABLED.store(false, Ordering::Relaxed);
                false
            } else {
                spoofed
            };
            if spoofed {
                return 0;
            }
        }

        let stop = stop || !skip_or_record(iar, frame);
        if !(ARMED.load(Ordering::Acquire) && stop) {
            return 1;
        }
    } else if !ARMED.load(Ordering::Acquire) {
        return 1;
    }

    frame.msr.remove(Msr::SINGLE_STEP);
    ARMED.store(false, Ordering::Release);

    1
}

/// Debug routine (stock 0x91f66c30): trace exceptions while a session
/// exists; every other exception goes to the previous routine.
extern "C" fn debug_routine(
    trap_frame: u32,
    record_address: u32,
    context_address: u32,
    second_chance: u32,
) -> u32 {
    // SAFETY: the kernel passes the exception record of the current
    // exception of this thread. The reference is not used after the
    // exception is passed on.
    let exception = unsafe { crate::kernel::object_at::<ExceptionRecord>(record_address) };
    if exception.code != NtStatus::SINGLE_STEP {
        let previous = PREVIOUS_ROUTINE.load(Ordering::Acquire);
        // SAFETY: the kernel's debug routine variable held this routine.
        return unsafe {
            kernel::call_export(
                previous,
                trap_frame,
                record_address,
                context_address,
                second_chance,
            )
        };
    }

    // SAFETY: the kernel passes the trap frame, the exception record, and
    // the 16-byte aligned context of the current exception of this thread;
    // nothing else uses them during the call.
    let (frame, exception, context) = unsafe {
        (
            crate::kernel::object_at_mut::<KtrapFrame>(trap_frame),
            crate::kernel::object_at_mut::<ExceptionRecord>(record_address),
            crate::kernel::object_at_mut::<Context>(context_address),
        )
    };
    if ARMED.load(Ordering::Acquire) && !FAILED.load(Ordering::Acquire) {
        let iar = exception.address;
        let stop = iar == stop_entry_address() || STOP_REQUESTED.load(Ordering::Acquire);
        let iar = if SPOOF_ENABLED.load(Ordering::Relaxed)
            && let Some(entry) = spoofed_routine(iar)
        {
            spoof(entry, frame, exception, context)
        } else {
            iar
        };

        let stop = stop || !skip_or_record(iar, frame);
        if !(ARMED.load(Ordering::Acquire) && stop) {
            return 1;
        }
    } else if !ARMED.load(Ordering::Acquire) {
        return 1;
    }

    context.msr.remove(Msr::SINGLE_STEP);
    ARMED.store(false, Ordering::Release);

    1
}

bridged!(trace_hook_entry, trace_hook);
bridged!(debug_routine_entry, debug_routine);

/// Resolve the spoofed kernel routines once (stock reads the targets of
/// its import thunks at the first start).
pub(super) fn resolve_spoofed_routines() {
    if SPOOF_RESOLVED.swap(true, Ordering::AcqRel) {
        return;
    }

    let Ok(module) = SystemModule::Kernel.handle() else {
        return;
    };

    for (target, routine) in SPOOF_TARGETS.iter().zip(&SPOOFED_ROUTINES) {
        if let Ok(address) = resolve_export(module, routine.ordinal) {
            target.store(address.raw(), Ordering::Relaxed);
        }
    }
}

/// Install the hooks (stock 0x91f66e88).
pub(super) fn hook() {
    const TITLE_TERMINATE_PRIORITY: u32 = 0x6f00_0000;

    if BASE.load(Ordering::Acquire) == 0 {
        return;
    }

    // Stock registers at every start; a session saved by export 137
    // without a stop keeps the registration, and registering it again
    // would corrupt the kernel's list.
    if !TERMINATE_REGISTERED.swap(true, Ordering::AcqRel) {
        // SAFETY: the record is not registered, so the kernel does not use
        // it while it is written. The routine stays loaded until `unhook`
        // or `shut_down` removes the record.
        unsafe {
            TITLE_TERMINATE.routine.store(
                title_terminated_entry as *const () as usize as u32,
                Ordering::Relaxed,
            );
            TITLE_TERMINATE
                .priority
                .store(TITLE_TERMINATE_PRIORITY, Ordering::Relaxed);
            TITLE_TERMINATE.link.flink.store(0, Ordering::Relaxed);
            TITLE_TERMINATE.link.blink.store(0, Ordering::Relaxed);
            xboxkrnl::ExRegisterTitleTerminateNotification(TITLE_TERMINATE.as_ptr(), true)
        };
    }

    let mut hook_slot = [0u32; 2];
    // SAFETY: `hook_slot` is a live two-word reply block.
    let status = unsafe {
        xboxkrnl::ExDebugMonitorService(
            DebugMonitorService::TraceHook,
            hook_slot.as_mut_ptr() as usize as u32,
            0,
            0,
        )
    };
    if status.is_success() {
        HOOK_SLOT.store(hook_slot[0], Ordering::Release);
        // SAFETY: the service replies with the address of the kernel's
        // trace hook variable, kernel data that stays mapped.
        let slot = unsafe { kernel::object_at::<KernelU32>(hook_slot[0]) };
        // SAFETY: `trace_hook_entry` follows the kernel's trace hook
        // convention and stays loaded until `unhook` clears the variable.
        unsafe {
            slot.store(
                trace_hook_entry as *const () as usize as u32,
                Ordering::Relaxed,
            )
        };
    }

    // SAFETY: the monitor registered before any trace starts, so the query
    // service published the address of `KiDebugRoutine`; stock uses it
    // without a check.
    let slot = unsafe { kernel::routine_variable(RoutineVariable::Debug).unwrap_unchecked() };
    ROUTINE_SLOT.store(kernel::address_of(slot), Ordering::Release);

    let routine = debug_routine_entry as *const () as usize as u32;
    let previous = slot.load(Ordering::Relaxed);
    if previous == routine {
        // Stock asserts and then chains the routine to itself, which
        // recurses on the next exception; the chain is kept instead.
        break_trap();
    } else {
        PREVIOUS_ROUTINE.store(previous, Ordering::Release);
    }

    // SAFETY: `debug_routine_entry` follows the kernel's debug routine
    // convention and stays loaded until `unhook` restores the previous
    // routine.
    unsafe { slot.store(routine, Ordering::Relaxed) };
}

/// Remove the debug routine and the trace hook.
pub(super) fn unhook() {
    let slot = ROUTINE_SLOT.swap(0, Ordering::AcqRel);
    if slot != 0 {
        // SAFETY: `hook` stored the address of the kernel's debug routine
        // variable, which stays mapped.
        let slot = unsafe { kernel::object_at::<KernelU32>(slot) };
        // SAFETY: restores the routine the kernel called before `hook`.
        unsafe { slot.store(PREVIOUS_ROUTINE.load(Ordering::Acquire), Ordering::Relaxed) };
        // SAFETY: TITLE_TERMINATE is the static registration added by `hook`.
        unsafe { xboxkrnl::ExRegisterTitleTerminateNotification(TITLE_TERMINATE.as_ptr(), false) };
        TERMINATE_REGISTERED.store(false, Ordering::Release);
    }

    let hook_slot = HOOK_SLOT.load(Ordering::Acquire);
    if hook_slot != 0 {
        // SAFETY: `hook` stored the address of the kernel's trace hook
        // variable, which stays mapped.
        let hook_slot = unsafe { kernel::object_at::<KernelU32>(hook_slot) };
        // SAFETY: a zero variable removes the hook.
        unsafe { hook_slot.store(0, Ordering::Relaxed) };
    }
}
