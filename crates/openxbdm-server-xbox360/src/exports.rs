//! Export declarations. Each `export!` emits an (ordinal, address) record into
//! `.xexports`; xex-link turns the records into the XEX export table that the
//! loader resolves `xbdm.xex` imports against.
//!
//! Importers follow the console ABI, which runs with 64-bit registers and
//! expects r14-r31 preserved in full. The 32-bit code here saves only their
//! low words, so every export enters through `export_bridge`, which preserves
//! the full nonvolatile registers around the call. Arguments in r3-r10 and
//! a 32-bit result in r3 pass through unchanged; an export that takes or
//! returns a 64-bit value, takes more than eight arguments, or is variadic
//! must adapt the console convention itself and be declared with
//! `export_raw!`.

mod generic;

/// One `.xexports` record: big-endian ordinal, then the entry address.
#[repr(C)]
pub(crate) struct ExportRecord {
    ordinal: u32,
    entry: *const (),
}

// SAFETY: the record is immutable and only read by the linker.
unsafe impl Sync for ExportRecord {}

impl ExportRecord {
    pub(crate) const fn new(ordinal: u16, entry: *const ()) -> Self {
        assert!(ordinal != 0, "export ordinals start at 1");
        Self {
            ordinal: ordinal as u32,
            entry,
        }
    }
}

/// Call the function in r12 with r3-r10 unchanged and the full 64-bit
/// r14-r31 preserved. The CPU model of the target has no 64-bit mnemonics,
/// so `std`/`ld` are encoded directly.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn module_bridge() {
    core::arch::naked_asm!(
        "stwu 1, -0xa0(1)",
        "mflr 0",
        "stw 0, 0x8(1)",
        ".irp reg, 14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31",
        // std \reg, 0x10 + 8 * (\reg - 14)(r1)
        ".long (62 << 26) | (\\reg << 21) | (1 << 16) | (0x10 + 8 * (\\reg - 14))",
        ".endr",
        "mtctr 12",
        "bctrl",
        ".irp reg, 14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31",
        // ld \reg, 0x10 + 8 * (\reg - 14)(r1)
        ".long (58 << 26) | (\\reg << 21) | (1 << 16) | (0x10 + 8 * (\\reg - 14))",
        ".endr",
        "lwz 0, 0x8(1)",
        "mtlr 0",
        "addi 1, 1, 0xa0",
        "blr",
    )
}

#[cfg(not(feature = "boot-guard"))]
pub(crate) use self::module_bridge as export_bridge;

/// Nonzero while the module runs the boot-guard recovery: no state or
/// hook exists, so every export returns [`RECOVERY_RESULT`] at once.
#[cfg(feature = "boot-guard")]
pub(crate) static RECOVERY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// E_FAIL.
#[cfg(feature = "boot-guard")]
const RECOVERY_RESULT: u32 = 0x8000_4005;

/// [`module_bridge`] for exports and callbacks: refuses every call during
/// the recovery. The module entry point keeps the unchecked bridge.
#[cfg(feature = "boot-guard")]
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn export_bridge() {
    core::arch::naked_asm!(
        "lis 11, {recovery}@ha",
        "lwz 11, {recovery}@l(11)",
        "cmpwi 11, 0",
        "beq {bridge}",
        "lis 3, {result_high}",
        "ori 3, 3, {result_low}",
        "blr",
        recovery = sym RECOVERY,
        bridge = sym module_bridge,
        result_high = const RECOVERY_RESULT >> 16,
        result_low = const RECOVERY_RESULT & 0xffff,
    )
}

/// Export `function` (an `extern "C" fn` with at most eight 32-bit
/// arguments and a 32-bit or no result) at `ordinal` through the bridge.
/// Ordinals that share one stock address are declared once each.
macro_rules! export {
    ($ordinal:literal, $function:path) => {
        const _: () = {
            #[unsafe(naked)]
            unsafe extern "C" fn entry() {
                core::arch::naked_asm!(
                    "lis 12, {function}@ha",
                    "addi 12, 12, {function}@l",
                    "b {bridge}",
                    function = sym $function,
                    bridge = sym $crate::exports::export_bridge,
                )
            }
            #[used]
            #[unsafe(link_section = ".xexports")]
            static RECORD: $crate::exports::ExportRecord =
                $crate::exports::ExportRecord::new($ordinal, entry as *const ());
        };
    };
}
pub(crate) use export;

/// Export `entry` at `ordinal` with no bridge. `entry` must implement the
/// console calling convention itself, including full 64-bit preservation of
/// any of r14-r31 it changes.
macro_rules! export_raw {
    ($ordinal:literal, $entry:path) => {
        const _: () = {
            #[used]
            #[unsafe(link_section = ".xexports")]
            static RECORD: $crate::exports::ExportRecord =
                $crate::exports::ExportRecord::new($ordinal, $entry as *const ());
        };
    };
}
pub(crate) use export_raw;

/// Define `$entry`, an entry for console-ABI callers (the kernel, importers,
/// callbacks handed to other modules) that runs `$target` behind the
/// bridge.
macro_rules! bridged {
    ($vis:vis $entry:ident, $target:path) => {
        #[unsafe(naked)]
        $vis unsafe extern "C" fn $entry() {
            core::arch::naked_asm!(
                "lis 12, {target}@ha",
                "addi 12, 12, {target}@l",
                "b {bridge}",
                target = sym $target,
                bridge = sym $crate::exports::export_bridge,
            )
        }
    };
}
pub(crate) use bridged;
