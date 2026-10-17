//! Exports 196-211.

use openxbdm_core::status::Hresult;
use openxbdm_server::commands::performance::pmc;
use openxbdm_server::commands::performance::pmc::COUNTERS;
use xbox360::time::TickCount;
use xbox360_sys::export_raw;
use xbox360_sys::processor::Kpcr;

use super::CLOCK;
use super::Locked;
use super::Owner;
use super::PmcState;
use super::PrintFlags;
use super::acquire;
use super::clear;
use super::control;
use super::counter;
use super::counter_flag;
use super::error::PmcError;
use super::event;
use super::frequency;
use super::install;
use super::name_address;
use super::read_reported;
use super::registers::LiveRegisters;
use super::registers::MonitorRegisters;
use super::release;
use super::report::print_state;
use super::report::print_statistics;
use super::reset;
use super::set_trigger_processor;
use super::start;
use super::stop;
use crate::exports::export;
use crate::exports::export_result;

/// Acquire, install setup `index`, and run the counters (stock 0x91f92d68).
fn begin(owner: Owner, index: u32) -> bool {
    acquire(owner)
        && install(owner, index)
        && clear(owner)
        && set_trigger_processor(
            owner,
            u32::from(Kpcr::current().processor_number().get() >> 1),
        )
        && start(owner)
}

/// Stop the counters, release them, and print the statistics (stock
/// 0x91f92df0).
fn end(owner: Owner) -> bool {
    let mut state = PmcState::new();
    if !stop(owner) || !read_reported(owner, &mut state) {
        return false;
    }

    release(owner);
    print_statistics(&mut state, PrintFlags::NO_ECC);
    true
}

/// Measure the processor clock over 100 ms of the interval counter (stock
/// export 211, 0x91f927e0); 0 when the counters are unavailable. A failed
/// step keeps the counters acquired, as in stock.
fn measure_clock() -> u64 {
    const SAMPLE_MILLISECONDS: u32 = 100;
    /// The clock is truncated to a multiple of 100 kHz.
    const RESOLUTION: i64 = 100_000;

    let begun = TickCount::now().milliseconds();
    let clock = if acquire(Owner::EXPORTS)
        && {
            reset();
            clear(Owner::EXPORTS)
        }
        && start(Owner::EXPORTS)
    {
        // Stock compares the zero-extended tick counts, which never ends
        // when the count wraps during the wait.
        while TickCount::now().milliseconds().wrapping_sub(begun) < SAMPLE_MILLISECONDS {}

        if stop(Owner::EXPORTS) {
            let interval = MonitorRegisters::get().interval_count() as i64 as f64;
            let ticks = {
                let mut locked = Locked::take();
                let hardware = locked.hardware();
                hardware.stopped.wrapping_sub(hardware.started)
            };
            release(Owner::EXPORTS);

            let seconds = ticks as i64 as f64 / frequency();
            ((interval / seconds) as i64 / RESOLUTION) as f64 * RESOLUTION as f64
        } else {
            0.0
        }
    } else {
        0.0
    };

    CLOCK.store(clock);
    clock as i64 as u64
}

/// Export 196: acquire, install setup `index`, and run the counters.
extern "C" fn export_begin(index: u32) -> Hresult {
    export_result(PmcError::NotAcquired.unless(begin(Owner::EXPORTS, index)))
}

/// Export 197: stop, release, and print the statistics.
extern "C" fn export_end() -> Hresult {
    export_result(PmcError::NotOwner.unless(end(Owner::EXPORTS)))
}

/// Export 198: acquire and install setup `index`.
extern "C" fn export_install(index: u32) -> Hresult {
    export_result(
        PmcError::NotAcquired.unless(acquire(Owner::EXPORTS) && install(Owner::EXPORTS, index)),
    )
}

/// Export 199: stop and release.
extern "C" fn export_stop_and_release() {
    stop(Owner::EXPORTS);
    release(Owner::EXPORTS);
}

/// Export 200.
extern "C" fn export_clear() -> Hresult {
    export_result(PmcError::NotOwner.unless(clear(Owner::EXPORTS)))
}

/// Export 201.
extern "C" fn export_set_trigger_processor(processor: u32) -> Hresult {
    export_result(PmcError::NotOwner.unless(set_trigger_processor(Owner::EXPORTS, processor)))
}

/// Export 202.
extern "C" fn export_start() -> Hresult {
    export_result(PmcError::NotOwner.unless(start(Owner::EXPORTS)))
}

/// Export 203.
extern "C" fn export_stop() -> Hresult {
    export_result(PmcError::NotOwner.unless(stop(Owner::EXPORTS)))
}

/// Export 204 (stock 0x91f92378): count of counter `index` into `value`;
/// 0 while a higher owner holds the counters.
extern "C" fn export_query_counter(index: u32, value: *mut u32) -> Hresult {
    // SAFETY: the caller passes a writable u32.
    let value = unsafe { &mut *value };

    let (count, succeeded) = {
        let mut locked = Locked::take();
        if locked.preempted(Owner::EXPORTS) {
            (0, false)
        } else {
            (counter(index), true)
        }
    };

    *value = count;
    export_result(PmcError::NotOwner.unless(succeeded))
}

/// Export 205.
extern "C" fn export_read_state(state: *mut PmcState) -> Hresult {
    // SAFETY: the caller passes a writable 0xa0-byte state.
    let state = unsafe { &mut *state };
    export_result(PmcError::NotOwner.unless(read_reported(Owner::EXPORTS, state)))
}

/// Export 206 (stock 0x91f91290): event name of counter `counter` without
/// its counting kind.
extern "C" fn export_counter_name(counter: i32) -> u32 {
    match usize::try_from(counter) {
        Ok(counter) if counter < COUNTERS => name_address(event(counter).name) as u32 + 1,
        _ => pmc::BAD_COUNTER.text().as_ptr() as usize as u32,
    }
}

/// Export 207.
extern "C" fn export_print_state(state: *const PmcState) {
    // SAFETY: the caller passes a 0xa0-byte state.
    print_state(unsafe { &*state });
}

/// Export 208.
extern "C" fn export_print_statistics(state: *mut PmcState, flags: u32) {
    // SAFETY: the caller passes a writable 0xa0-byte state.
    print_statistics(unsafe { &mut *state }, PrintFlags::from_bits_retain(flags));
}

/// Export 209: the counter number is signed, so negative numbers are past
/// the last as unsigned values.
extern "C" fn export_counter_flag(counter: i32) -> u32 {
    counter_flag(counter as u32)
}

/// Export 210 (stock 0x91f91320): source class of counter `counter`. Stock
/// does not check the number and reads past the controls; here other
/// numbers report an unrouted counter.
extern "C" fn export_counter_source(counter: i32) -> u32 {
    /// Class `pmc::source_class` reports for an unrouted counter.
    const UNROUTED: u32 = 7;

    match usize::try_from(counter) {
        Ok(counter) if counter < COUNTERS => {
            pmc::source_class(counter, control(counter), &mut LiveRegisters)
        }
        _ => UNROUTED,
    }
}

/// Export 211: the measured clock, returned in one 64-bit register.
#[unsafe(naked)]
unsafe extern "C" fn export_measure_clock() {
    core::arch::naked_asm!(
        "stwu 1, -0x10(1)",
        "mflr 0",
        "stw 0, 0x8(1)",
        "lis 12, {measure}@ha",
        "addi 12, 12, {measure}@l",
        "bl {bridge}",
        // rldimi 4, 3, 32, 0: join r3:r4 into r4.
        ".long 0x7864000e",
        "mr 3, 4",
        "lwz 0, 0x8(1)",
        "mtlr 0",
        "addi 1, 1, 0x10",
        "blr",
        measure = sym measure_clock_entry,
        bridge = sym crate::exports::export_bridge,
    )
}

extern "C" fn measure_clock_entry() -> u64 {
    measure_clock()
}

export!(196, export_begin);
export!(197, export_end);
export!(198, export_install);
export!(199, export_stop_and_release);
export!(200, export_clear);
export!(201, export_set_trigger_processor);
export!(202, export_start);
export!(203, export_stop);
export!(204, export_query_counter);
export!(205, export_read_state);
export!(206, export_counter_name);
export!(207, export_print_state);
export!(208, export_print_statistics);
export!(209, export_counter_flag);
export!(210, export_counter_source);
export_raw!(211, export_measure_clock);
