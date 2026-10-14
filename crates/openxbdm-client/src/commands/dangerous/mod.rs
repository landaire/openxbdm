//! Low-level, patch-xbdm-at-runtime helpers.
//!
//! This module is gated behind the `dangerous` feature for a reason:
//! every routine in here writes into xbdm's own memory image (code,
//! dispatch tables, or data globals). A misidentified target crashes
//! the console; a failed restore leaves it in a loudly broken state.
//!
//! Everything in here follows the same discipline:
//!
//! 1. **Anchor on content, not addresses.** We find targets by looking
//!    for stable string literals or instruction-level semantic patterns
//!    inside xbdm's own image, then derive addresses from those. The
//!    drivemap implementation relies on `"DEVICE"`, `"\Device"`,
//!    `"drivemap"`, `"internal"`, and `"altaddr"` - all stable
//!    regardless of xbdm build.
//!
//! 2. **Verify every discovery two ways.** Each time we think we've
//!    located a function or data address, we cross-check with at least
//!    one independent structural property (function prologue bytes,
//!    expected first-call shape, pointer range inside the right
//!    section). Any single check failing aborts the operation.
//!
//! 3. **Always restore on patch.** When we temporarily overwrite an
//!    xbdm structure, we read the original bytes first, write the
//!    replacement, invoke, and `setmem` the original back immediately.
//!    If the restore fails we surface a typed error rather than carry
//!    on with the console in an inconsistent state.

pub mod drivemap;
pub mod pe;
pub mod ppc;
pub mod sigscan;

pub use drivemap::DrivemapEnableReport;
pub use drivemap::DrivemapError;
pub use drivemap::DrivemapPersistReport;
pub use drivemap::DrivemapStatus;
pub use drivemap::XbdmLayout;
