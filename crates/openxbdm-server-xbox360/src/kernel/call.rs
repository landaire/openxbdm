//! Calls into console code with the console ABI.

use xbox360_sys::xboxkrnl::KeQueryPerformanceFrequency;

/// Define `$name` as a branch to `$target`: the arguments reach it in
/// r3-r10 unchanged and its r3 comes back unchanged. Stock passes some
/// values that the typed imports do not model (the r3 of a VOID call, a raw
/// user number, a stale register), and a forward keeps them exact. The
/// forward is `unsafe` with the contract of `$target`.
macro_rules! forward {
    ($(#[$meta:meta])* $vis:vis fn $name:ident($($argty:ty),* $(,)?) -> $ret:ty => $target:path) => {
        $(#[$meta])*
        #[unsafe(naked)]
        $vis unsafe extern "C" fn $name($(_: $argty),*) -> $ret {
            core::arch::naked_asm!("b {target}", target = sym $target)
        }
    };
}
pub(crate) use forward;

xbox360_sys::import_thunk!(
    /// Variadic; callers pass at most the two arguments `%.*s` takes.
    #[allow(non_snake_case)]
    pub DbgPrint(format: *const u8, length: u32, text: *const u8) -> u32,
    lib = xbox360_sys::lib_index::XBOXKRNL,
    ordinal = 3
);

/// Call a resolved export with up to four arguments through a frame that
/// reserves the console home area, as the import thunks do.
///
/// # Safety
/// `function` must be the address of a console function taking at most
/// four register arguments.
#[unsafe(naked)]
pub unsafe extern "C" fn call_export(function: u32, a0: u32, a1: u32, a2: u32, a3: u32) -> u32 {
    core::arch::naked_asm!(
        "stwu 1, -0x50(1)",
        "mflr 0",
        "stw 0, 0x54(1)",
        "mtctr 3",
        "mr 3, 4",
        "mr 4, 5",
        "mr 5, 6",
        "mr 6, 7",
        "bctrl",
        "lwz 0, 0x54(1)",
        "mtlr 0",
        "addi 1, 1, 0x50",
        "blr",
    )
}

/// [`call_export`] for console functions taking up to seven register
/// arguments; unused arguments may be passed as zero.
///
/// # Safety
/// `function` must be the address of a console function taking at most
/// seven register arguments.
#[unsafe(naked)]
pub unsafe extern "C" fn call_console(
    function: u32,
    a0: u32,
    a1: u32,
    a2: u32,
    a3: u32,
    a4: u32,
    a5: u32,
    a6: u32,
) -> u32 {
    core::arch::naked_asm!(
        "stwu 1, -0x50(1)",
        "mflr 0",
        "stw 0, 0x54(1)",
        "mtctr 3",
        "mr 3, 4",
        "mr 4, 5",
        "mr 5, 6",
        "mr 6, 7",
        "mr 7, 8",
        "mr 8, 9",
        "mr 9, 10",
        "bctrl",
        "lwz 0, 0x54(1)",
        "mtlr 0",
        "addi 1, 1, 0x50",
        "blr",
    )
}

/// `KeQueryPerformanceFrequency`. The console returns the quadword in one
/// 64-bit register; this splits it into the r3:r4 pair the 32-bit ABI
/// expects. The CPU model of the target has no 64-bit mnemonics, so the
/// shift is encoded directly.
#[unsafe(naked)]
pub extern "C" fn performance_frequency() -> u64 {
    core::arch::naked_asm!(
        "stwu 1, -0x20(1)",
        "mflr 0",
        "stw 0, 0x24(1)",
        "bl {query}",
        "mr 4, 3",
        // rldicl 3, 3, 32, 32: the high word into the low half of r3.
        ".long 0x78630022",
        "lwz 0, 0x24(1)",
        "mtlr 0",
        "addi 1, 1, 0x20",
        "blr",
        query = sym KeQueryPerformanceFrequency,
    )
}
