//! Pool blocks the server holds as buffers and scratch data.

use core::mem::ManuallyDrop;
use core::ptr::NonNull;

use openxbdm_server::commands::filesystem::PoolBuffer;
use openxbdm_server::commands::filesystem::PoolRange;
use openxbdm_server::commands::filesystem::ScratchBlock;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::PoolTag;

/// Header before the data of a [`PoolBlock`].
#[repr(C, align(8))]
pub(super) struct PoolHeader {
    /// Length of the data in bytes.
    length: u32,
}

/// A pool block whose data length is in a [`PoolHeader`] before the data.
/// The server holds a block as the [`PoolBuffer`] or [`ScratchBlock`] of
/// its data.
pub(super) struct PoolBlock(NonNull<PoolHeader>);

impl PoolBlock {
    pub(super) fn allocate(length: u32) -> Option<Self> {
        const POOL_TAG: PoolTag = PoolTag::new(*b"xdbm");

        let size = length.checked_add(size_of::<PoolHeader>() as u32)?;
        // SAFETY: pool allocation has no pointer arguments.
        let base = unsafe { xboxkrnl::ExAllocatePoolWithTag(size, POOL_TAG) };
        let header = NonNull::new(core::ptr::with_exposed_provenance_mut::<PoolHeader>(
            base as usize,
        ))?;
        // SAFETY: the block holds the header and `length` bytes.
        unsafe { header.write(PoolHeader { length }) };

        Some(Self(header))
    }

    /// The header of the block whose data starts at `data`.
    ///
    /// # Safety
    ///
    /// `data` must be the data address of a block of [`PoolBlock::allocate`]
    /// that is not freed.
    pub(super) unsafe fn header_of(data: usize) -> NonNull<PoolHeader> {
        let header = data.wrapping_sub(size_of::<PoolHeader>());
        // SAFETY: guaranteed by the caller; the header precedes the data.
        unsafe { NonNull::new_unchecked(core::ptr::with_exposed_provenance_mut(header)) }
    }

    /// Take back the ownership a token carries.
    ///
    /// # Safety
    ///
    /// As for [`PoolBlock::header_of`]; the token that carried the block is
    /// not used afterwards.
    pub(super) unsafe fn from_data(data: usize) -> Self {
        // SAFETY: guaranteed by the caller.
        Self(unsafe { Self::header_of(data) })
    }

    /// The data of the block at `header`.
    ///
    /// # Safety
    ///
    /// `header` must be a live block, and no other reference to its data
    /// may exist for `'a`.
    pub(super) unsafe fn data<'a>(header: NonNull<PoolHeader>) -> &'a mut [u8] {
        // SAFETY: guaranteed by the caller; `allocate` wrote the length.
        unsafe {
            let length = header.as_ref().length;
            core::slice::from_raw_parts_mut(header.add(1).cast::<u8>().as_ptr(), length as usize)
        }
    }

    pub(super) fn address(&self) -> u32 {
        // SAFETY: the data follows the header inside the block.
        unsafe { self.0.add(1) }.as_ptr().expose_provenance() as u32
    }

    pub(super) fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: `self` owns the block and lends its data for the borrow.
        unsafe { Self::data(self.0) }
    }

    /// Hand the block to the server, which frees it with
    /// [`Backend::free_pool`](commands::filesystem::Backend::free_pool).
    pub(super) fn into_buffer(self) -> PoolBuffer {
        let address = ManuallyDrop::new(self).address();
        // SAFETY: the data address of a block the server holds from here
        // on; `free_pool` takes it back with `from_data`.
        unsafe { PoolBuffer::from_raw(address) }
    }

    /// Hand the data to the server, which frees it with
    /// [`Backend::free_scratch`](commands::filesystem::Backend::free_scratch).
    pub(super) fn into_scratch(self) -> ScratchBlock {
        let block = ManuallyDrop::new(self);
        // SAFETY: the block is never freed through `self` again, so the
        // slice is the only reference to its data; `free_scratch` takes it
        // back with `from_data`.
        unsafe { ScratchBlock::from_raw(Self::data(block.0)) }
    }
}

impl Drop for PoolBlock {
    fn drop(&mut self) {
        // SAFETY: `self` owns the block that `allocate` made.
        unsafe { xboxkrnl::ExFreePool(self.0.as_ptr().expose_provenance() as u32) };
    }
}

/// The data of a part of a block the server holds.
///
/// # Safety
///
/// No other reference to the block's data may exist for `'a`.
pub(super) unsafe fn pool_range<'a>(range: PoolRange) -> &'a mut [u8] {
    // SAFETY: a `PoolBuffer` names the data of a live block of
    // `into_buffer`; the caller guarantees exclusive use.
    let data = unsafe { PoolBlock::data(PoolBlock::header_of(range.buffer.raw() as usize)) };

    &mut data[range.offset as usize..(range.offset + range.length) as usize]
}
