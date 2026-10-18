//! Kernel debug routine, stack overflow, and thread notification hooks.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::console::DumpMode;
use openxbdm_server::commands::debugger::Delivery;
use openxbdm_server::commands::debugger::DirectException;
use openxbdm_server::commands::debugger::DirectNotice;
use openxbdm_server::commands::debugger::DirectRegisters;
use openxbdm_server::commands::debugger::Disposition;
use openxbdm_server::commands::debugger::ExceptionFlags;
use openxbdm_server::commands::debugger::ExceptionRecord;
use openxbdm_server::commands::debugger::StopOn;
use openxbdm_server::commands::debugger::ThreadId;
use openxbdm_server::commands::debugger::dispatch_direct;
use openxbdm_server::commands::debugger::exception_stops;
use xbox360::console::hardware_flags;
use xbox360::time::sleep;
use xbox360_sys::processor;
use xbox360_sys::processor::current_irql;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Context as KernelContext;
use xbox360_sys::xboxkrnl::ContextFlags as KernelContextFlags;
use xbox360_sys::xboxkrnl::DumpWriteDump;
use xbox360_sys::xboxkrnl::ExRegisterThreadNotification;
use xbox360_sys::xboxkrnl::ExceptionFlags as KernelExceptionFlags;
use xbox360_sys::xboxkrnl::ExceptionRecord as KernelExceptionRecord;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeContextFromKframes;
use xbox360_sys::xboxkrnl::KeIpiGenericCall;
use xbox360_sys::xboxkrnl::KeResumeThread;
use xbox360_sys::xboxkrnl::KeSetSpecialPurposeRegister;
use xbox360_sys::xboxkrnl::KtrapFrame;
use xbox360_sys::xboxkrnl::NotificationRegistration;
use xbox360_sys::xboxkrnl::SpecialPurposeRegister;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;

use super::context::ContextStorage;
use super::direct::queue_direct;
use super::dump::DumpKind;
use super::dump::mark_dump;
use super::dump::write_dump;
use super::memory::readable;
use super::module::describe_module;
use super::policy::load_policy;
use super::slot::SlotDisposition;
use super::slot::SlotEventKind;
use super::slot::post_and_wait;
use super::slot::post_and_wait_stopping;
use super::slot::post_detached;
use super::table::with_breakpoints;
use super::thread::MonitorRecord;
use super::thread::OwnThread;
use super::thread::ThreadListLock;
use super::thread::is_server;
use super::thread::name_thread;
use super::thread::owning_process;
use super::thread::process_kind_of;
use super::thread::thread_pointer;
use crate::kernel;
use crate::kernel::RoutineVariable;
use crate::kernel::address_of;
use crate::kernel::object_at;
use crate::kernel::thread_at;

/// Debug routine the kernel had before the hook.
static PREVIOUS_DEBUG_ROUTINE: AtomicU32 = AtomicU32::new(0);

/// Thread notification registration, priority 0. The kernel uses all 0x10
/// bytes of the record.
static THREAD_NOTIFICATION: NotificationRegistration = NotificationRegistration::new();

crate::exports::bridged!(pub(super) debug_routine_entry, debug_routine);

/// Replacement kernel debug routine (stock 0x91f3a980). Threads that can
/// wait are handed to the server; threads above passive level, the server
/// thread, threads that overflowed their stack, and threads that already
/// wait at an event are dispatched in place, as is every thread while the
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
    let irql = current_irql();
    let server = is_server(own.kthread());
    let marked = own
        .record()
        .is_some_and(|record| record.has_overflowed() || record.waits_in_slot());
    if irql != Irql::PASSIVE || server || marked {
        let delivery = if irql == Irql::PASSIVE && server {
            Delivery::Inline
        } else if irql == Irql::PASSIVE || irql == Irql::APC || irql == Irql::DISPATCH {
            Delivery::Deferred
        } else {
            Delivery::Discarded
        };
        // SAFETY: the kernel's record and context of the calling thread,
        // live for the call; no slot holds them on this path (a thread
        // waiting in its slot raises this exception with its own record
        // and context).
        return unsafe {
            dispatch_in_place(
                own,
                exception,
                registers,
                second_chance != 0,
                delivery,
                &chain,
            )
        };
    }

    // Read before posting: the server writes the context once it takes the
    // slot.
    // SAFETY: the kernel's context of the calling thread; nothing else
    // writes it before the post.
    let raised = direct_registers(unsafe { &*registers });
    // While the server waits for a dispatch flag 0x4 command thread, an
    // exception that stops this thread still waits for the server, as
    // stock's thread stays stopped; any other is dispatched in place.
    let stops = || exception_stops_thread(own, exception, &raised, second_chance != 0);
    let Some(disposition) = post_and_wait_stopping(
        SlotEventKind::Exception,
        own,
        record,
        context,
        second_chance,
        &stops,
    ) else {
        // While the server waits for a command thread every notification
        // is queued for it, as stock's raising thread sends them itself.
        let delivery = if crate::backend::dispatcher::posts_blocked() {
            Delivery::Inline
        } else {
            Delivery::Deferred
        };
        // SAFETY: as above; the thread did not post to a slot.
        return unsafe {
            dispatch_in_place(
                own,
                exception,
                registers,
                second_chance != 0,
                delivery,
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
    // Stock stores the flag through the record pointer without a check.
    if let Some(record) = own.record() {
        record.mark_stack_overflow();
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
            // The thread stops, so it waits even while the server waits for
            // a command thread.
            let Some(disposition) = post_and_wait_stopping(
                SlotEventKind::StackOverflow,
                own,
                record_address,
                context_address,
                0,
                &|| true,
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
pub(super) fn exception_record(record: &KernelExceptionRecord) -> ExceptionRecord {
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
    own: OwnThread,
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
        unsafe { direct_dispatch(own, &*record, &mut *context, delivery, second_chance) };
    let mut handled = disposition.handled;
    if disposition.chain_kernel_debugger {
        handled = chain() & 0xff != 0;
    }

    u32::from(handled)
}

/// The registers the in-place dispatch reads and changes.
fn direct_registers(context: &KernelContext) -> DirectRegisters {
    DirectRegisters {
        msr: context.msr,
        iar: context.iar,
        gpr3: context.gpr[3],
        gpr4: context.gpr[4],
    }
}

/// The calling thread's exception as the in-place dispatch takes it.
fn direct_event(
    own: OwnThread,
    record: &KernelExceptionRecord,
    delivery: Delivery,
    second_chance: bool,
) -> DirectException {
    let monitor_record = own.record();
    DirectException {
        thread: ThreadId(own.kthread().id),
        record: exception_record(record),
        second_chance,
        has_record: monitor_record.is_some(),
        debuggable: monitor_record.is_some_and(MonitorRecord::is_debuggable),
        stack_overflowed: monitor_record.is_some_and(MonitorRecord::has_overflowed),
        nested: monitor_record.is_some_and(MonitorRecord::waits_in_slot),
        hardware_flags: hardware_flags(),
        delivery,
    }
}

/// The instruction word at `iar`, when mapped.
fn instruction_at(iar: u32) -> Option<u32> {
    // SAFETY: `readable` found the instruction word mapped; instruction
    // addresses are word-aligned.
    readable(iar).then(|| {
        unsafe { AtomicU32::from_ptr(core::ptr::with_exposed_provenance_mut(iar as usize)) }
            .load(Ordering::Relaxed)
    })
}

/// Whether the monitor's dispatch stops the calling thread at this
/// exception, from the registers it raised it with.
fn exception_stops_thread(
    own: OwnThread,
    record: &KernelExceptionRecord,
    registers: &DirectRegisters,
    second_chance: bool,
) -> bool {
    exception_stops(
        &load_policy(),
        &direct_event(own, record, Delivery::Inline, second_chance),
        process_kind_of(own.kthread()),
        registers,
        instruction_at(registers.iar),
        &mut |address| with_breakpoints(|shared, _| shared.contains(address)),
        &mut |name_string, entry| {
            // SAFETY: the calling thread raised the module load trap with
            // these r3 and r4 and stays at it for the call.
            unsafe { describe_module(name_string, entry) }.is_some_and(|module| module.has_header)
        },
    )
}

/// Dispatch an exception in place, without the kernel debugger chain.
fn direct_dispatch(
    own: OwnThread,
    record: &KernelExceptionRecord,
    context: &mut KernelContext,
    delivery: Delivery,
    second_chance: bool,
) -> Disposition {
    let policy = load_policy();
    let mut registers = direct_registers(context);
    let iar = registers.iar;
    let thread_id = ThreadId(own.kthread().id);
    let event = direct_event(own, record, delivery, second_chance);
    let instruction = instruction_at(iar);
    let outcome = with_breakpoints(|shared, code| {
        dispatch_direct(&policy, &event, &mut registers, instruction, shared, code)
    });
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
    if let Some(DirectNotice::ModuleUnload {
        name_string, entry, ..
    }) = outcome.notice
        // SAFETY: the calling thread raised the module unload trap with
        // these r3 and r4, and stays at it for the call.
        && let Some(module) = unsafe { describe_module(name_string, entry) }
    {
        with_breakpoints(|shared, code| shared.remove_module(module.base, module.size, code));
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

crate::exports::bridged!(pub(super) thread_notification_entry, thread_notification);

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

        let (record, debuggable) = {
            let _lock = ThreadListLock::acquire(owning_process(thread));
            let record = own.record();
            let debuggable = match record {
                Some(record) => {
                    thread.debug_data.store(0, Ordering::Relaxed);
                    let debuggable = record.is_debuggable();
                    if record.is_monitor_suspended() {
                        // SAFETY: `thread` is the live thread object the
                        // kernel passed.
                        unsafe { KeResumeThread(thread_pointer(thread)) };
                    }

                    debuggable
                }
                None => false,
            };

            (record, debuggable)
        };

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
            // `stopon createthread`, or a title entry that may break. While
            // the server waits for a command thread the event is posted
            // without waiting, so the thread cannot stop.
            let title_entry = thread
                .creation_flags
                .contains(ThreadCreationFlags::TITLE_ENTRY);
            if (!title_entry && !load_policy().stop_on.contains(StopOn::CREATE_THREAD))
                || crate::backend::dispatcher::posts_blocked()
            {
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
    super::table::initialize();
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
    // The query service always stores the variable's address (K16547
    // 0x800894d4), and stock stores through it without a check (0x91f3bdec).
    // SAFETY: `register_debug_monitor` succeeded before this call; the
    // entry is a stack overflow notification of the kernel's form.
    unsafe {
        kernel::routine_variable(RoutineVariable::StackOverflow)
            .unwrap_unchecked()
            .store(
                stack_overflow_entry as *const () as usize as u32,
                Ordering::Relaxed,
            );
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

crate::exports::bridged!(pub(super) set_data_breakpoint_entry, set_data_breakpoint_on_processor);

extern "C" fn set_data_breakpoint_on_processor(value: u32) -> u32 {
    // SAFETY: writing DABR on this processor only arms a data breakpoint.
    unsafe { KeSetSpecialPurposeRegister(SpecialPurposeRegister::DABR, u64::from(value)) };

    value
}

/// `break now` (stock 0x91f48a64): the server thread traps, and the debug
/// routine dispatches the trap in place.
pub(super) fn break_now() {
    sleep(Duration::from_millis(250));
    // SAFETY: executes the breakpoint trap, which the debug routine
    // resolves on this thread before execution continues.
    unsafe { core::arch::asm!("twi 31, 0, 0x16") };
}
