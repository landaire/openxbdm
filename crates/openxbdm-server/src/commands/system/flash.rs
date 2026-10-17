//! `flash`: system flash image upload and programming.

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;

use super::Continuation;
use super::error::FlashFailed;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;

/// A `flash` image being received.
#[derive(Debug, Clone, Copy)]
pub struct FlashUpload {
    /// Bytes received so far.
    received: u32,
    options: FlashOptions,
}

/// Options of a flash write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashOptions {
    /// Skip the image hardware check.
    pub ignore_version_checking: bool,
    pub stock_image: bool,
}

/// `flash size_<hw>=<dword> [ignoreversionchecking=<dword>] [stockimage]`:
/// receive a system flash image for this hardware and program it.
pub(super) fn flash(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Flash images are programmed in whole 0x4000-byte blocks.
    const FLASH_BLOCK: u32 = 0x4000;

    /// Hardware selector values (kernel hardware flags & 0xff000003) and the
    /// size parameter each requires; the parameter name after
    /// [`FLASH_SIZE_PREFIX`] is the suffix reported for it.
    const FLASH_HARDWARE: [(u32, &str); 16] = [
        (0x0000_0003, "size_w2"),
        (0x0200_0003, "size_tw2"),
        (0x1000_0003, "size_z"),
        (0x1200_0003, "size_zt"),
        (0x2000_0003, "size_f"),
        (0x2200_0003, "size_ft"),
        (0x3000_0003, "size_j"),
        (0x3200_0003, "size_jt"),
        (0x4000_0003, "size_t"),
        (0x4200_0003, "size_tt"),
        (0x5000_0003, "size_c"),
        (0x5200_0003, "size_ct"),
        (0x6000_0003, "size_wi"),
        (0x6200_0003, "size_wit"),
        (0x8000_0003, "size_r"),
        (0x8200_0003, "size_rt"),
    ];

    const FLASH_SIZE_PREFIX: &str = "size_";

    const FLASH_HARDWARE_MASK: u32 = 0xff00_0003;

    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let line = invocation.line;
    let selector = invocation.backend.hardware_flags().bits() & FLASH_HARDWARE_MASK;
    let Some(&(_, parameter)) = FLASH_HARDWARE.iter().find(|(value, _)| *value == selector) else {
        // Stock formats a null suffix, which the CRT prints as `(null)`.
        invocation.set_text(format_args!("unsupported hardware type, requires (null)"));
        return Err(CommandError::Fail);
    };

    let suffix = &parameter.as_bytes()[FLASH_SIZE_PREFIX.len()..];

    let Some(size) = line.dword(parameter) else {
        invocation.text.clear();
        let _ = invocation
            .text
            .push_bytes(b"unsupported hardware type, requires ");
        let _ = invocation.text.push_bytes(suffix);

        return Err(CommandError::Fail);
    };

    // Stock reads this with the required-parameter getter; its `missing`
    // text is always replaced below.
    let ignore_version_checking = line
        .param("ignoreversionchecking")
        .is_some_and(|value| value.dword_prefix() != 0);
    let options = FlashOptions {
        ignore_version_checking,
        stock_image: line.has("stockimage"),
    };

    let rounded = size.wrapping_add(FLASH_BLOCK - 1) & !(FLASH_BLOCK - 1);
    if !invocation.backend.flash_begin(rounded) {
        invocation.set_text(format_args!("Not enough memory"));
        return Err(ErrorCode::Undefined.into());
    }

    invocation.text.clear();
    let _ = invocation.text.push_bytes(b"send=");
    let _ = invocation.text.push_bytes(suffix);

    if let Some(session) = invocation.session.as_deref_mut() {
        session.receive_remaining = Some(size);
        session.continuation =
            crate::continuation::Continuation::System(Continuation::Flash(FlashUpload {
                received: 0,
                options,
            }));
    }

    Ok(Reply::SendBinary)
}

pub(super) fn resume_flash(
    upload: &mut FlashUpload,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    if cx.received.is_empty() {
        cx.backend.flash_abort();
        return Err(CommandError::Unexpected);
    }

    cx.backend.flash_write(upload.received, cx.received);
    let count = cx.received.len() as u32;
    upload.received += count;

    let remaining = cx
        .session
        .receive_remaining
        .unwrap_or(0)
        .saturating_sub(count);
    cx.session.receive_remaining = Some(remaining);
    if remaining != 0 {
        return Ok(Reply::Ok);
    }

    match cx.backend.flash_commit(upload.received, upload.options) {
        Ok(()) => {
            let _ = cx.line.write_str("Done, new image flashed");
            Ok(Reply::Ok)
        }
        Err(error) => {
            let error = FlashFailed(error);
            let result = Hresult::from(error).0;
            let _ = write!(cx.line, "Flash failed with HRESULT 0x{result:x}");

            Err(CommandError::Flash(error))
        }
    }
}
