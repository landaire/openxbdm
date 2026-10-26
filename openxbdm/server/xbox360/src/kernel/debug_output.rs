//! Messages to the kernel debug output.

use core::ffi::CStr;

use super::call::DbgPrint;

/// Write a NUL-terminated message to the debug output.
pub fn debug_print(message: &CStr) {
    // SAFETY: the format and `message` are NUL-terminated.
    unsafe {
        DbgPrint(
            c"%s".as_ptr().cast(),
            message.as_ptr() as u32,
            core::ptr::null(),
        )
    };
}

/// Write `text` to the debug output as the argument of `%.*s`, so it is
/// printed literally and the kernel applies the same length limit as to a
/// formatted message.
pub fn debug_print_bytes(text: &[u8]) {
    // SAFETY: `text` is valid for its length, which `%.*s` bounds.
    unsafe { DbgPrint(c"%.*s".as_ptr().cast(), text.len() as u32, text.as_ptr()) };
}
