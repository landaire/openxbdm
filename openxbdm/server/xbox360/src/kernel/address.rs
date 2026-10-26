//! Conversions between references and the 32-bit addresses kernel calls
//! and callers use.

use xbox360_sys::xboxkrnl::Kthread;

/// The address of `value`, as kernel calls and caller-visible words take
/// it. The provenance is exposed so that [`object_at`] can return to it.
#[inline(always)]
pub fn address_of<T>(value: &T) -> u32
where
    T: ?Sized,
{
    core::ptr::from_ref(value).cast::<u8>().expose_provenance() as u32
}

/// The `T` at `address`.
///
/// # Safety
///
/// `address` must hold an initialized, aligned `T` that stays allocated
/// and is not written through another path except by interior mutability
/// for `'a`.
#[inline(always)]
pub unsafe fn object_at<'a, T>(address: u32) -> &'a T {
    // SAFETY: the caller guarantees the object for `'a`.
    unsafe { &*core::ptr::with_exposed_provenance::<T>(address as usize) }
}

/// The `T` at `address`, for writing.
///
/// # Safety
///
/// As [`object_at`], and no other reference to the object is used for
/// `'a`.
#[inline(always)]
pub unsafe fn object_at_mut<'a, T>(address: u32) -> &'a mut T {
    // SAFETY: the caller guarantees exclusive access for `'a`.
    unsafe { &mut *core::ptr::with_exposed_provenance_mut::<T>(address as usize) }
}

/// The thread object at `address`.
///
/// # Safety
///
/// `address` must be a thread object that stays allocated for `'a`.
#[inline(always)]
pub unsafe fn thread_at<'a>(address: u32) -> &'a Kthread {
    // SAFETY: the caller guarantees the object for `'a`.
    unsafe { xbox360::thread::ThreadObject::from_raw(address) }.kthread()
}

/// Bytes before the NUL of the string at `address`; none for 0.
///
/// # Safety
///
/// `address` must be 0 or the address of a NUL-terminated string that
/// stays unchanged for `'a`.
pub unsafe fn c_string<'a>(address: u32) -> Option<&'a [u8]> {
    let start = core::ptr::with_exposed_provenance::<core::ffi::c_char>(address as usize);

    // SAFETY: guaranteed by the caller.
    (!start.is_null()).then(|| unsafe { core::ffi::CStr::from_ptr(start) }.to_bytes())
}

/// Bytes before the NUL of the string at `address`, at most `limit`; none
/// for 0.
///
/// # Safety
///
/// `address` must be 0, or readable up to its NUL or `limit` bytes,
/// whichever comes first, and the bytes must stay unchanged for `'a`.
#[inline(never)]
pub unsafe fn bounded_c_string<'a>(address: u32, limit: usize) -> Option<&'a [u8]> {
    let start = core::ptr::with_exposed_provenance::<u8>(address as usize);
    if start.is_null() {
        return None;
    }

    let mut length = 0;
    // SAFETY: the caller guarantees the bytes up to the NUL or the limit.
    while length < limit && unsafe { start.add(length).read() } != 0 {
        length += 1;
    }

    // SAFETY: the `length` bytes were just read.
    Some(unsafe { core::slice::from_raw_parts(start, length) })
}
