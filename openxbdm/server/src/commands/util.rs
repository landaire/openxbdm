//! Helpers shared by command handlers.

use crate::invocation::Invocation;
use crate::reply::CommandError;

/// The reply for a missing required parameter.
pub const MISSING: CommandError = CommandError::Fail;

/// A required dword parameter. When absent, the reply text becomes
/// `missing <name>` and the caller fails with [`MISSING`].
pub fn required_dword(invocation: &mut Invocation<'_>, name: &str) -> Option<u32> {
    let value = invocation.line.dword(name);
    if value.is_none() {
        invocation.set_text(format_args!("missing {name}"));
    }

    value
}
