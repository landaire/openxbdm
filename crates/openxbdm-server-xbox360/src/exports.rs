//! Export declarations. Each `export!` emits an (ordinal, address) record into
//! `.xexports`; xex-link turns the records into the XEX export table that the
//! loader resolves `xbdm.xex` imports against.
//!
//! Importers follow the console ABI, which runs with 64-bit registers and
//! expects r14-r31 preserved in full. The 32-bit code here saves only their
//! low words, so every export enters through `export_bridge`, which runs
//! `xbox360_sys::entry_bridge` to preserve the full nonvolatile registers
//! around the call. Arguments in r3-r10 and a 32-bit result in r3 pass
//! through unchanged; an export that takes or returns a 64-bit value, takes
//! more than eight arguments, or is variadic must adapt the console
//! convention itself and be declared with `export_raw!`.

mod generic;

#[cfg(not(feature = "boot-guard"))]
pub(crate) use xbox360_sys::entry_bridge as export_bridge;

/// Nonzero while the module runs the boot-guard recovery: no state or
/// hook exists, so every export returns [`RECOVERY_RESULT`] at once.
#[cfg(feature = "boot-guard")]
pub(crate) static RECOVERY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// E_FAIL.
#[cfg(feature = "boot-guard")]
const RECOVERY_RESULT: u32 = 0x8000_4005;

/// `xbox360_sys::entry_bridge` for exports and callbacks: refuses every
/// call during the recovery. The module entry point keeps the unchecked bridge.
#[cfg(feature = "boot-guard")]
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn export_bridge() {
    core::arch::naked_asm!(
        "lis 11, {recovery}@ha",
        "lwz 11, {recovery}@l(11)",
        "cmpwi 11, 0",
        // `beq` reaches only 32 KiB; the bridge is in another crate.
        "bne 1f",
        "b {bridge}",
        "1:",
        "lis 3, {result_high}",
        "ori 3, 3, {result_low}",
        "blr",
        recovery = sym RECOVERY,
        bridge = sym xbox360_sys::entry_bridge,
        result_high = const RECOVERY_RESULT >> 16,
        result_low = const RECOVERY_RESULT & 0xffff,
    )
}

/// `xbox360_sys::export!` through [`export_bridge`].
macro_rules! export {
    ($ordinal:literal, $function:path) => {
        xbox360_sys::export!($ordinal, $function, bridge = $crate::exports::export_bridge);
    };
}
pub(crate) use export;

/// `xbox360_sys::bridged!` through [`export_bridge`].
macro_rules! bridged {
    ($(#[$meta:meta])* $vis:vis $entry:ident, $target:path) => {
        xbox360_sys::bridged!(
            $(#[$meta])* $vis $entry,
            $target,
            bridge = $crate::exports::export_bridge
        );
    };
}
pub(crate) use bridged;
