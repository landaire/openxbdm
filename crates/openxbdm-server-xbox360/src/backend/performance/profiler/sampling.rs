use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::performance::profiler::ProfilerError;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::thread::current_object;
use xbox360::time::Timebase;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::xam::GetCurrentThreadId;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Boolean8;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KtrapFrame;

use super::super::pmc;
use super::Counter;
use super::HEADER;
use super::INTERVAL;
use super::RECORD_HEADER_WORDS;
use super::SAMPLING_ACTIVE;
use super::blocks::THREADS;
use super::count;
use super::last_processor;
use super::sampled;
use crate::kernel;

xbox360_sys::flags! {
    /// Word 9 of a sample record: these flags and the number of the
    /// sampled processor in the low bits ([`SampleFlags::processor`]).
    pub struct SampleFlags(u32) {
        /// The sample came from a leaf function's epilogue.
        LEAF = 0x8000_0000,
    }
}

impl SampleFlags {
    /// The processor number field holding hardware thread `processor`,
    /// which is below `HARDWARE_THREAD_COUNT`.
    const fn processor(processor: usize) -> Self {
        Self::from_bits_retain(processor as u32)
    }
}

/// Per-processor busy words of the sample in progress (stock 0x91fa3b10).
/// Stock builds each record in a static block next to its busy word; here
/// the stack is walked once for the size and again into the reserved
/// block space.
pub(super) static BUSY: [AtomicU32; HARDWARE_THREAD_COUNT] =
    [const { AtomicU32::new(0) }; HARDWARE_THREAD_COUNT];

fn valid(address: u32) -> bool {
    xboxkrnl::MmIsAddressValid(address).get()
}

/// The interrupted code at `address` is a leaf epilogue: the instructions
/// up to `blr` (at most 13) only load, branch, or restore the link register
/// (stock 0x91f90030). The result is the record flag; `None` when the code
/// is unreadable, where stock catches the fault.
///
/// # Safety
///
/// The word at `address` must be readable. Later words are checked with
/// `MmIsAddressValid` where they start a page.
unsafe fn in_leaf_epilogue(address: u32) -> Option<SampleFlags> {
    const EPILOGUE_LIMIT: usize = 13;
    const PAGE_MASK: u32 = 0xfff;
    const BLR: u32 = 0x4e80_0020;
    const MTLR_R12: u32 = 0x7d88_03a6;
    // Primary opcodes of `ld`, `lwz`, `lfd`, `b`, and the X-form group.
    const LD: u32 = 0x3a;
    const LWZ: u32 = 0x20;
    const LFD: u32 = 0x32;
    const B: u32 = 0x12;
    const X_FORM: u32 = 0x1f;
    // Extended opcode field of an X-form instruction, and its `lvx` value.
    const EXTENDED_OPCODE: u32 = 0x7fe;
    const LVX: u32 = 0xce;

    let mut address = address;
    for _ in 0..EPILOGUE_LIMIT {
        if address & PAGE_MASK == 0 && !valid(address) {
            return None;
        }

        // SAFETY: the first word is readable by the contract; a later word
        // lies on the page of the previous one or on a page checked above.
        let instruction = unsafe { *core::ptr::with_exposed_provenance::<u32>(address as usize) };
        if instruction == BLR {
            return Some(SampleFlags::LEAF);
        }

        let opcode = instruction >> 26;
        let allowed = matches!(opcode, LD | LWZ | LFD | B)
            || (opcode == X_FORM && instruction & EXTENDED_OPCODE == LVX)
            || instruction == MTLR_R12;
        if !allowed {
            return Some(SampleFlags::empty());
        }

        address += 4;
    }

    Some(SampleFlags::LEAF)
}

/// Return addresses of the interrupted thread's stack, the interrupted
/// `address` first, stored in `frames` when given; `None` at `MAX_FRAMES`
/// (stock 0x91f900b8). Takes the two registers rather than the trap frame,
/// which the compiler would pass field by field.
///
/// # Safety
///
/// `stack` must be the r1 of the interrupted running thread, with the word
/// at it and the word 8 bytes below readable. `frames`, when given, must
/// hold `depth` words, where `depth` is the result of a walk over the same
/// unchanged stack.
unsafe fn walk_stack(
    mut stack: u32,
    address: u32,
    mut frames: Option<&mut [u32]>,
) -> Option<usize> {
    /// Deepest call stack a sample records, the interrupted address included.
    const MAX_FRAMES: usize = 500;

    let mut store = |index: usize, value: u32| {
        if let Some(frames) = frames.as_deref_mut() {
            // SAFETY: `index` is below the depth of the walk, which `frames`
            // holds by the contract.
            unsafe { *frames.get_unchecked_mut(index) = value };
        }
    };

    store(0, address);
    let mut count = 1;
    loop {
        let thread = current_object().kthread();
        // SAFETY: the first back chain is at r1, readable by the contract;
        // later ones lie between the stack limits of the running thread.
        stack = unsafe { *core::ptr::with_exposed_provenance::<u32>(stack as usize) };
        if stack >= thread.stack_base.load(Ordering::Relaxed)
            || stack <= thread.stack_limit.load(Ordering::Relaxed)
        {
            return Some(count);
        }

        // SAFETY: the saved link register below a frame between the stack
        // limits of the running thread.
        store(count, unsafe {
            *core::ptr::with_exposed_provenance::<u32>((stack - 8) as usize)
        });
        count += 1;
        if count == MAX_FRAMES {
            return None;
        }
    }
}

/// Record one sample of `processor` (stock 0x91f90420, 0x91f8fe70,
/// 0x91f8f7f8). Stock reads the code and the stack under an exception
/// handler; an unreadable address counts as a faulted walk here.
///
/// # Safety
///
/// `frame` must be the trap frame of the thread that the profile interrupt
/// stopped on this processor, and `processor` the number of this
/// processor.
unsafe fn sample(frame: &KtrapFrame, processor: usize) {
    const RECORD_MAGIC: u32 = 0x0cdc_dce8;

    // SAFETY: guaranteed by the caller.
    unsafe { core::hint::assert_unchecked(processor < HARDWARE_THREAD_COUNT) };

    let stack = frame.gpr[1] as u32;
    let readable = valid(frame.iar) && valid(stack) && valid(stack.wrapping_sub(8));
    let walked = if readable {
        // SAFETY: the word at `iar` is valid, checked above.
        unsafe { in_leaf_epilogue(frame.iar) }.and_then(|leaf| {
            // SAFETY: r1 and the word 8 bytes below are valid, checked
            // above.
            unsafe { walk_stack(stack, frame.iar, None) }.map(|depth| (leaf, depth))
        })
    } else {
        None
    };

    let Some((leaf, depth)) = walked else {
        count(Counter::Faulted, processor);
        return;
    };

    count(Counter::Samples, processor);
    let size = ((depth + RECORD_HEADER_WORDS) * 4) as u32;
    let mut head = [
        RECORD_MAGIC,
        0,
        0,
        size,
        GetCurrentThreadId(),
        frame.lr,
        // SAFETY: valid, checked above.
        unsafe { *core::ptr::with_exposed_provenance::<u32>((stack - 8) as usize) },
        frame.gpr[12] as u32,
        // SAFETY: valid, checked above.
        unsafe { *core::ptr::with_exposed_provenance::<u32>(frame.iar as usize) },
        (SampleFlags::processor(processor) | leaf).bits(),
    ];

    HEADER.bytes[processor].fetch_add(size, Ordering::Relaxed);
    HEADER.largest[processor].fetch_max(size, Ordering::Relaxed);
    HEADER.smallest[processor].fetch_min(size, Ordering::Relaxed);

    let time = Timebase::now().ticks();
    head[1] = (time >> 32) as u32;
    head[2] = time as u32;

    let blocks = &THREADS[processor];
    // SAFETY: the interrupt routine runs only while the profiler is
    // initialized, so the blocks lie in the allocated sample buffer, which
    // `free_buffers` releases only after `unhook`. The record's last use is
    // the walk below, before the entry is pushed.
    match unsafe { blocks.allocate(size) } {
        Some((index, record)) => {
            count(Counter::Stored, processor);
            // SAFETY: the record holds `RECORD_HEADER_WORDS` words more than
            // `depth`.
            let (header, frames) = unsafe { record.split_at_mut_unchecked(RECORD_HEADER_WORDS) };
            header.copy_from_slice(&head);
            // SAFETY: `frames` holds the `depth` words of the walk above;
            // the stack does not change while its thread is interrupted.
            unsafe { walk_stack(stack, frame.iar, Some(frames)) };
            blocks.free.push(blocks.entry(index));
        }
        None => count(Counter::Dropped, processor),
    }
}

/// Profile interrupt routine (stock 0x91f90528): the last sampled
/// processor reloads the interval; samples are skipped above dispatch level
/// and in an idle thread without pending DPCs.
extern "C" fn profile_interrupt(frame: *const KtrapFrame, irql: Irql) {
    // SAFETY: the kernel passes the trap frame of the thread it interrupted
    // on this processor, unchanged until the routine returns.
    let frame = unsafe { &*frame };

    let pcr = Kpcr::current();
    let processor = pcr.processor_number().index();
    // SAFETY: the kernel keeps processor numbers below the hardware thread
    // count (`HardwareThread`).
    unsafe { core::hint::assert_unchecked(processor < HARDWARE_THREAD_COUNT) };

    if !sampled(processor) {
        return;
    }

    if processor == last_processor() {
        pmc::set_interval_reload(INTERVAL.load(Ordering::Relaxed).wrapping_neg());
        pmc::wait_interval_reload();
    }

    if !SAMPLING_ACTIVE.load(Ordering::Acquire) {
        return;
    }

    count(Counter::Interrupts, processor);
    let prcb = &pcr.prcb;
    if irql > Irql::DISPATCH
        || (prcb.idle_thread.load(Ordering::Relaxed) == prcb.current_thread.load(Ordering::Relaxed)
            && prcb.dpc_active.load(Ordering::Relaxed) == 0)
    {
        count(Counter::Skipped, processor);
        return;
    }

    count(Counter::Sampled, processor);
    let busy = &BUSY[processor];
    if busy
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        // SAFETY: `frame` is the kernel's trap frame of the thread stopped
        // on this processor.
        unsafe { sample(frame, processor) };
        busy.store(0, Ordering::Release);
    } else {
        count(Counter::Busy, processor);
    }
}

// Kernel entry of `profile_interrupt`, preserving the full nonvolatile
// registers.
crate::exports::bridged!(pub(super) profile_interrupt_entry, profile_interrupt);

/// Call profile interrupt export `ordinal` of the kernel (stock
/// 0x91f8eeb0, 0x91f8ef48, 0x91f8efd0): 669 enables it on a processor
/// mask, 670 disables it and 671 sets the routine.
fn call_kernel(ordinal: Ordinal, argument: u32) -> Result<u32, ProfilerError> {
    let kernel = SystemModule::Kernel
        .handle()
        .map_err(|_| ProfilerError::NoKernel)?;
    let function = resolve_export(kernel, ordinal).map_err(|_| ProfilerError::NoProfileExport)?;

    // SAFETY: the profile exports take one register argument.
    Ok(unsafe { kernel::call_export(function.raw(), argument, 0, 0, 0) })
}

pub(super) fn set_profile_routine(routine: u32) -> Result<(), ProfilerError> {
    const SET_PROFILE_ROUTINE: Ordinal = Ordinal::new(671).unwrap();

    call_kernel(SET_PROFILE_ROUTINE, routine).map(|_| ())
}

pub(super) fn enable_profile_interrupt(mask: u32) -> Result<(), ProfilerError> {
    const ENABLE_PROFILE_INTERRUPT: Ordinal = Ordinal::new(669).unwrap();

    if Boolean8(call_kernel(ENABLE_PROFILE_INTERRUPT, mask)?).get() {
        Ok(())
    } else {
        Err(ProfilerError::ProfileInterruptRefused)
    }
}

pub(super) fn disable_profile_interrupt() {
    const DISABLE_PROFILE_INTERRUPT: Ordinal = Ordinal::new(670).unwrap();

    let _ = call_kernel(DISABLE_PROFILE_INTERRUPT, 1);
}
