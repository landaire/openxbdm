//! Debug printing and the counter statistics printouts.

use core::sync::atomic::Ordering;

use openxbdm_server::commands::performance::pmc;
use openxbdm_server::commands::performance::pmc::COUNTERS;
use xbox360_sys::xboxkrnl::PmwRegister;

use super::CLOCK;
use super::CURRENT_SETUP;
use super::PmcState;
use super::PrintFlags;
use super::control;
use super::event;
use super::frequency;
use super::name_address;
use super::print_flags;
use super::registers::LiveRegisters;
use super::registers::PmcStatus;
use super::registers::get_pmw;
use super::to_double;
use crate::kernel;

/// `DbgPrint(format, arguments...)` with each argument in one 64-bit
/// register, as the console passes variadic arguments.
#[unsafe(naked)]
pub(in crate::backend::performance) unsafe extern "C" fn debug_print(
    format: *const u8,
    arguments: *const [u64; 7],
) -> u32 {
    core::arch::naked_asm!(
        "mr 11, 4",
        ".irp reg, 4,5,6,7,8,9,10",
        // ld \reg, 8 * (\reg - 4)(r11)
        ".long (58 << 26) | (\\reg << 21) | (11 << 16) | (8 * (\\reg - 4))",
        ".endr",
        "b {print}",
        print = sym kernel::DbgPrint,
    )
}

/// Print `format` with up to seven arguments.
pub(in crate::backend::performance) fn print(format: &core::ffi::CStr, arguments: &[u64]) {
    let mut slots = [0u64; 7];
    slots[..arguments.len()].copy_from_slice(arguments);

    // SAFETY: `format` is NUL-terminated and `slots` holds every argument
    // it consumes.
    unsafe { debug_print(format.as_ptr().cast(), &slots) };
}

pub(super) fn pointer(text: &[u8]) -> u64 {
    u64::from(text.as_ptr() as usize as u32)
}

/// Print a counter state (stock export 207, 0x91f919c8).
pub(super) fn print_state(state: &PmcState) {
    let ticks = state.ticks as i64 as f64;
    let rate = ticks / frequency();

    // Stock passes the interval's bit pattern for `%u`.
    print(
        c"CPU ticks %I64d interval %u frequency %.1f\n",
        &[
            state.ticks,
            state.interval.to_bits(),
            (state.interval / rate).to_bits(),
        ],
    );

    for (index, &value) in state.counters.iter().enumerate() {
        print(c"pmc[%d] = %I64u\n", &[index as u64, value]);
    }
}

/// Percentages of one counter (stock 0x91f91a60).
fn print_rates(counter: usize, state: &PmcState) {
    let event = event(counter);
    let value = to_double(state.counters[counter]);
    if pmc::counts_instructions(event.name) {
        print(c"(%6.2f%%)", &[(value / state.interval * 100.0).to_bits()]);
        if !PmcStatus(state.status).counter_overflow(counter) {
            print(c" IPC=|%.3f|", &[(value / state.interval).to_bits()]);
        }
        return;
    }

    let flag = f64::from(event.flag as i32);
    print(
        c"(%6.2f%%)",
        &[(flag / state.interval * value * 100.0).to_bits()],
    );
    if state.instructions != 0 {
        print(
            c"[%6.2f%%]",
            &[(value * 100.0 / state.instructions as i64 as f64).to_bits()],
        );
    }
}

/// Print the statistics of a counter state (stock export 208, 0x91f92438).
pub(super) fn print_statistics(state: &mut PmcState, flags: PrintFlags) {
    const THREADS: [&core::ffi::CStr; 4] = [c"T0", c"T1", c"EE", c""];
    static SPACE: [u16; 2] = [0x20, 0];

    let ticks = state.ticks as i64 as f64;
    let rate = ticks / frequency();
    print(
        c"\n\nCPU ticks=|%I64d| interval=|%.0f| frequency=|%.1f|\n",
        &[
            state.ticks,
            state.interval.to_bits(),
            (state.interval / rate).to_bits(),
        ],
    );

    let print_flags = print_flags();
    if !print_flags.contains(PrintFlags::NO_TIME) {
        let time = ticks / frequency();
        print(c"time=|%.3f| ", &[time.to_bits()]);
        if !print_flags.contains(PrintFlags::NO_FRAME_RATE) {
            print(c"FPS=|%7.2f|", &[(1.0 / time).to_bits()]);
        }
        match CURRENT_SETUP.load(Ordering::Relaxed).checked_sub(1) {
            Some(setup) => print(c" using setup %2d", &[u64::from(setup)]),
            None => print(c"               ", &[]),
        }
        print(
            c"%12ls( /cycle)[ /inst ]\n",
            &[u64::from(SPACE.as_ptr() as usize as u32)],
        );
    }

    if PmcStatus(state.status).interval_overflow() {
        let time = ticks / frequency();
        let clock = CLOCK.load();
        let interval = time * clock;
        print(
            c"Interval overflow, using ticks (freq is %.2fGhz) = |%.0f|\n",
            &[(clock * 1e-9).to_bits(), interval.to_bits()],
        );
        state.interval = interval;
        state.status &= !PmcStatus::INTERVAL_OVERFLOW;
    }

    // Stock advances the overflow bit only for routed counters.
    let mut overflow = PmcStatus::FIRST_COUNTER_OVERFLOW;
    for counter in 0..COUNTERS {
        let Some(input) = control(counter).input() else {
            continue;
        };

        let thread = pmc::thread(counter, control(counter), &mut LiveRegisters);
        let label = pmc::source_label(counter, input);
        let value = state.counters[counter];
        let name = name_address(event(counter).name) + 1;
        print(
            c"[%2d]%s%2s(%29s)=%10I64u ",
            &[
                counter as u64,
                pointer(label.to_bytes()),
                pointer(THREADS[usize::from(thread)].to_bytes()),
                name,
                value,
            ],
        );

        if state.status & overflow != 0 {
            print(c" OVERFLOW\n", &[]);
        } else {
            print_rates(counter, state);
            print(c"\n", &[]);
        }
        overflow >>= 1;
    }

    if !flags.contains(PrintFlags::NO_ECC) && !print_flags.contains(PrintFlags::NO_ECC) {
        print_ecc_counts();
    }
}

/// Stock 0x91f92020: one line per field, A0Q0 in the top byte.
fn print_ecc_counts() {
    let counts = get_pmw(PmwRegister::L2_ECC);
    print(c"L2 ECC ERROR COUNTS\n", &[]);

    let words = [(counts >> 32) as u32, counts as u32];
    for index in 0..8u32 {
        let word = words[(index >> 2) as usize];
        let field = word >> (24 - 8 * (index & 3)) & 0x3f;
        print(
            c"A%dQ%d = %d\n",
            &[
                u64::from(index & 1),
                u64::from(index >> 1),
                u64::from(field),
            ],
        );
    }
}
