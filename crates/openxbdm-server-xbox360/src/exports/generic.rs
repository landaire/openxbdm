//! Exports that touch no command state: pool wrappers, handle close, and
//! constant results.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::reply::CommandError;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::PoolTag;

use crate::exports::export;
use crate::exports::export_result;
use crate::kernel::pool_tag;

extern "C" fn allocate_monitor_pool(size: u32) -> u32 {
    // SAFETY: nonpaged pool allocation of any size is valid; failure is null.
    unsafe { xboxkrnl::ExAllocatePoolWithTag(size, pool_tag::MONITOR) }
}
export!(1, allocate_monitor_pool);

extern "C" fn allocate_pool_with_tag(size: u32, tag: u32) -> u32 {
    // SAFETY: nonpaged pool allocation of any size is valid; failure is null.
    unsafe { xboxkrnl::ExAllocatePoolWithTag(size, PoolTag::from_raw(tag)) }
}
export!(2, allocate_pool_with_tag);

extern "C" fn no_operation() -> Hresult {
    Hresult::OK
}
export!(3, no_operation);
export!(55, no_operation);
export!(57, no_operation);
export!(124, no_operation);

extern "C" fn free_pool_if_present(address: u32) -> Hresult {
    if address != 0 {
        // SAFETY: the export contract requires a pool block from the caller.
        unsafe { xboxkrnl::ExFreePool(address) };
    }
    Hresult::OK
}
export!(4, free_pool_if_present);
export!(5, free_pool_if_present);

extern "C" fn close_handle(handle: u32) -> Hresult {
    // SAFETY: the export contract requires a handle owned by the caller.
    let result = unsafe { xboxkrnl::NtClose(Handle::from_raw(handle)) }.result();
    export_result(result.map_err(|error| CommandError::from_kernel(error, CommandError::Fail)))
}
export!(7, close_handle);

crate::kernel::forward!(
    /// Stock tail-calls ExFreePool, so its r3 passes through.
    fn free_pool(u32) -> u32 => xboxkrnl::ExFreePool
);
export!(9, free_pool);

extern "C" fn not_implemented() -> Hresult {
    Hresult::NOT_IMPLEMENTED
}
export!(11, not_implemented);

extern "C" fn monitor_failure() -> Hresult {
    Hresult::from(CommandError::from(ErrorCode::Undefined))
}
export!(20, monitor_failure);

extern "C" fn failure() -> Hresult {
    Hresult::FAIL
}
export!(88, failure);
