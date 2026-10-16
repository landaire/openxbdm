//! Exports that touch no command state: pool wrappers, handle close, and
//! constant results.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_server::reply::CommandError;

use crate::exports::export;
use crate::kernel;

/// E_NOTIMPL.
const NOT_IMPLEMENTED: Hresult = Hresult(0x8000_4001);
/// Pool tag of monitor allocations ('xbdm').
const MONITOR_POOL_TAG: u32 = u32::from_be_bytes(*b"xbdm");

extern "C" fn allocate_monitor_pool(size: u32) -> u32 {
    kernel::ExAllocatePoolWithTag(size, MONITOR_POOL_TAG)
}
export!(1, allocate_monitor_pool);

extern "C" fn allocate_pool_with_tag(size: u32, tag: u32) -> u32 {
    kernel::ExAllocatePoolWithTag(size, tag)
}
export!(2, allocate_pool_with_tag);

extern "C" fn no_operation() -> u32 {
    Hresult::OK.0
}
export!(3, no_operation);
export!(55, no_operation);
export!(57, no_operation);
export!(124, no_operation);

extern "C" fn free_pool_if_present(address: u32) -> u32 {
    if address != 0 {
        kernel::ExFreePool(address);
    }
    Hresult::OK.0
}
export!(4, free_pool_if_present);
export!(5, free_pool_if_present);

extern "C" fn close_handle(handle: u32) -> u32 {
    match NtStatus(kernel::NtClose(handle)).result() {
        Ok(()) => Hresult::OK.0,
        Err(error) => Hresult::from(CommandError::from_kernel(error, CommandError::Fail)).0,
    }
}
export!(7, close_handle);

/// Stock tail-calls ExFreePool, so its result passes through.
extern "C" fn free_pool(address: u32) -> u32 {
    kernel::ExFreePool(address)
}
export!(9, free_pool);

extern "C" fn not_implemented() -> u32 {
    NOT_IMPLEMENTED.0
}
export!(11, not_implemented);

extern "C" fn monitor_failure() -> u32 {
    Hresult::from(CommandError::from(ErrorCode::Undefined)).0
}
export!(20, monitor_failure);

extern "C" fn failure() -> u32 {
    Hresult::FAIL.0
}
export!(88, failure);
