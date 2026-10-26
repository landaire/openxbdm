use core::mem::offset_of;
use core::sync::atomic::Ordering;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::performance::studio::StudioError;
use openxbdm_server::commands::performance::studio::routine_result;
use xbox360::module::SystemModule;
use xbox360_sys::xam;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;

use super::NULL_CABLE_ORDINAL;
use super::NullCableRequest;
use super::Routines;
use super::TransferRequest;
use super::TransportKind;
use super::assertion_trap;
use super::count_word;
use super::routine;
use crate::exports::bridged;
use crate::kernel;

/// Parameter record of [`NullCableRequest::Send`] and
/// [`NullCableRequest::Receive`].
#[repr(C)]
struct NullCableTransfer {
    buffer: u32,
    length: u32,
    event: u32,
    process_type: u32,
    /// Address of the word that receives the transfer count.
    count_address: u32,
    /// Address of the word that receives the status.
    status_address: u32,
}

const _: () = {
    assert!(offset_of!(NullCableTransfer, buffer) == 0);
    assert!(offset_of!(NullCableTransfer, length) == 4);
    assert!(offset_of!(NullCableTransfer, event) == 8);
    assert!(offset_of!(NullCableTransfer, process_type) == 0xc);
    assert!(offset_of!(NullCableTransfer, count_address) == 0x10);
    assert!(offset_of!(NullCableTransfer, status_address) == 0x14);
    assert!(size_of::<NullCableTransfer>() == 0x18);
};

/// Null-cable transport object (stock 0x91f830e0).
#[repr(C)]
struct NullCableTransport {
    routines: Routines,
    /// Address of the null-cable export.
    request: u32,
}

const _: () = {
    assert!(offset_of!(NullCableTransport, routines) == 0);
    assert!(offset_of!(NullCableTransport, request) == 0x18);
    assert!(size_of::<NullCableTransport>() == 0x1c);
};

impl NullCableTransport {
    /// # Safety
    /// `this` is a transport from [`create_null_cable_transport`] that is
    /// not yet released.
    unsafe fn from_address<'a>(this: u32) -> &'a Self {
        // SAFETY: per the contract.
        unsafe { kernel::object_at(this) }
    }
}

pub(super) fn create_null_cable_transport() -> Result<u32, StudioError> {
    const POOL_TAG: PoolTag = PoolTag::new(*b"uNSX");
    // SAFETY: pool allocation of the object size; the result is checked below.
    let object = unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(
            size_of::<NullCableTransport>() as u32,
            POOL_TAG,
            PoolType::System,
        )
    };
    // Stock passes the null pointer to ExFreePool here.
    if object == 0 {
        return Err(StudioError::OutOfMemory);
    }
    let request = SystemModule::Kernel
        .handle()
        .map_err(|_| StudioError::Fail)
        .and_then(|module| {
            let mut address = 0u32;
            // SAFETY: `module` is the loaded kernel handle and `address` a live u32.
            let status = unsafe {
                xboxkrnl::XexGetProcedureAddress(
                    module.raw(),
                    u32::from(NULL_CABLE_ORDINAL.get()),
                    &mut address,
                )
            };
            status
                .result()
                .map(|()| address)
                .map_err(|_| StudioError::NotImplemented)
        });
    let request = match request {
        Ok(request) => request,
        Err(failure) => {
            // SAFETY: `object` was allocated above and is not used afterwards.
            unsafe { xboxkrnl::ExFreePool(object) };
            return Err(failure);
        }
    };
    let routines = Routines {
        kind: routine(null_cable_kind_entry),
        release: routine(null_cable_release_entry),
        receive: routine(null_cable_receive_entry),
        send: routine(null_cable_send_entry),
        result: routine(null_cable_result_entry),
        cancel: routine(null_cable_cancel_entry),
    };
    // SAFETY: the pool returned a block of the object's size.
    unsafe {
        (object as usize as *mut NullCableTransport).write(NullCableTransport { routines, request })
    };
    Ok(object)
}

/// Map a null-cable request status (stock 0x91f83290); any other nonzero
/// status, informational ones included, fails.
fn null_cable_status(status: NtStatus) -> Result<(), StudioError> {
    match status {
        NtStatus::SUCCESS => Ok(()),
        status => Err(match KernelError::from_status(status) {
            Some(KernelError::NoSuchDevice) => StudioError::NotConnected,
            Some(KernelError::NoMemory) => StudioError::OutOfMemory,
            Some(KernelError::NotImplemented) => StudioError::NotImplemented,
            _ => StudioError::Fail,
        }),
    }
}

fn null_cable_transfer(
    transport: &NullCableTransport,
    code: NullCableRequest,
    buffer: u32,
    length: u32,
    request: &TransferRequest,
) -> u32 {
    let parameters = NullCableTransfer {
        buffer,
        length,
        event: request.event(),
        process_type: xboxkrnl::KeGetCurrentProcessType().0,
        count_address: request.result.as_ptr() as usize as u32,
        status_address: request.status.as_ptr() as usize as u32,
    };
    request.result.store(0, Ordering::Relaxed);
    request.status.store(NtStatus::PENDING.0, Ordering::Relaxed);
    // SAFETY: the object holds the resolved kernel export; `parameters` is
    // live for the call.
    let status = unsafe {
        kernel::call_export(
            transport.request,
            code as u32,
            &parameters as *const NullCableTransfer as usize as u32,
            0,
            0,
        )
    };
    routine_result(null_cable_status(NtStatus(status))).0
}

extern "C" fn null_cable_kind(_this: u32) -> u32 {
    TransportKind::NullCable as u32
}

extern "C" fn null_cable_release(this: u32) -> u32 {
    // SAFETY: the studio service releases each transport once, after its last use.
    unsafe { xboxkrnl::ExFreePool(this) };
    0
}

extern "C" fn null_cable_receive(this: u32, buffer: u32, length: u32, request: u32) -> u32 {
    // SAFETY: the studio service passes the transport it was given and a
    // request record that stays live until the request completes.
    let (transport, request) = unsafe {
        (
            NullCableTransport::from_address(this),
            TransferRequest::from_address(request),
        )
    };
    null_cable_transfer(
        transport,
        NullCableRequest::Receive,
        buffer,
        length,
        request,
    )
}

extern "C" fn null_cable_send(this: u32, buffer: u32, length: u32, request: u32) -> u32 {
    // SAFETY: the studio service passes the transport it was given and a
    // request record that stays live until the request completes.
    let (transport, request) = unsafe {
        (
            NullCableTransport::from_address(this),
            TransferRequest::from_address(request),
        )
    };
    if request.event() == 0 {
        assertion_trap();
    }
    null_cable_transfer(transport, NullCableRequest::Send, buffer, length, request)
}

extern "C" fn null_cable_result(_this: u32, request: u32, transferred: u32, wait: u32) -> u32 {
    // SAFETY: the studio service passes a submitted request record and the
    // address of its count word, both live for the call.
    let (request, transferred) = unsafe {
        (
            TransferRequest::from_address(request),
            count_word(transferred),
        )
    };
    let event = request.event();
    if event == 0 {
        assertion_trap();
    }
    let status = loop {
        core::sync::atomic::fence(Ordering::Acquire);
        let status = NtStatus(request.status.load(Ordering::Relaxed));
        if status != NtStatus::PENDING {
            break status;
        }
        if wait == 0 {
            return routine_result(Err(StudioError::Pending)).0;
        }
        // SAFETY: `event` is the caller's event handle of the request.
        unsafe { xam::WaitForSingleObject(xboxkrnl::Handle::from_raw(event), xam::INFINITE) };
    };
    core::sync::atomic::fence(Ordering::Acquire);
    transferred.store(request.result.load(Ordering::Relaxed), Ordering::Relaxed);
    routine_result(if status != NtStatus::SUCCESS {
        Err(StudioError::Fail)
    } else {
        Ok(())
    })
    .0
}

extern "C" fn null_cable_cancel(this: u32) -> u32 {
    // SAFETY: the studio service passes the transport it was given.
    let transport = unsafe { NullCableTransport::from_address(this) };
    let parameters = [xboxkrnl::KeGetCurrentProcessType()];
    // SAFETY: the object holds the resolved kernel export.
    let status = unsafe {
        kernel::call_export(
            transport.request,
            NullCableRequest::Cancel as u32,
            parameters.as_ptr() as usize as u32,
            0,
            0,
        )
    };
    let result = match NtStatus(status) {
        NtStatus::SUCCESS => Ok(()),
        status => Err(match KernelError::from_status(status) {
            Some(KernelError::NotImplemented) => StudioError::NotImplemented,
            _ => StudioError::Fail,
        }),
    };
    routine_result(result).0
}

bridged!(null_cable_kind_entry, null_cable_kind);
bridged!(null_cable_release_entry, null_cable_release);
bridged!(null_cable_receive_entry, null_cable_receive);
bridged!(null_cable_send_entry, null_cable_send);
bridged!(null_cable_result_entry, null_cable_result);
bridged!(null_cable_cancel_entry, null_cable_cancel);
