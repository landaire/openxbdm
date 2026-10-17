use core::sync::atomic::Ordering;

use openxbdm_server::SocketId;
use openxbdm_server::commands::performance::studio::CallerBuffer;
use openxbdm_server::commands::performance::studio::Direction;
use openxbdm_server::commands::performance::studio::Incoming;
use openxbdm_server::commands::performance::studio::Outgoing;
use openxbdm_server::commands::performance::studio::Slot;
use openxbdm_server::commands::performance::studio::Stream;
use openxbdm_server::commands::performance::studio::StudioError;
use openxbdm_server::commands::performance::studio::Transport;
use openxbdm_server::commands::performance::studio::routine_result;
use xbox360_sys::status::Win32Error;
use xbox360_sys::xam;
use xbox360_sys::xam::IoctlCommand;
use xbox360_sys::xam::MessageFlags;
use xbox360_sys::xam::NetworkEvents;
use xbox360_sys::xam::Socket;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;

use super::Handle;
use super::Routines;
use super::TransferRequest;
use super::TransportKind;
use super::assertion_trap;
use super::count_word;
use super::raw_handle;
use super::routine;
use super::set_event;
use crate::exports::bridged;
use crate::kernel;
use crate::kernel::CriticalSection;

/// Socket transport object (stock 0x91f83698). Request handles are
/// addresses inside the object, as stock's request nodes are.
#[repr(C)]
struct SocketTransport {
    routines: Routines,
    section: CriticalSection,
    /// Caller event bound by the first request.
    event: Option<Handle>,
    socket: SocketId,
    engine: Transport,
}

impl SocketTransport {
    fn stream(&self) -> SocketStream {
        SocketStream {
            socket: self.socket,
            event: self.event,
        }
    }

    fn pump(&mut self) {
        let mut stream = self.stream();
        self.engine.pump(&mut stream);
    }

    fn handle_base(&self) -> u32 {
        core::ptr::addr_of!(self.engine) as usize as u32
    }

    fn handle(&self, slot: Slot) -> u32 {
        self.handle_base() + slot.index() as u32
    }

    fn slot(&self, handle: u32) -> Option<Slot> {
        Slot::from_index(handle.wrapping_sub(self.handle_base()) as usize)
    }

    /// Bind the caller's event on the first request (stock 0x91f84030).
    fn bind_event(&mut self, event: u32) {
        const FD_READ_WRITE: NetworkEvents = NetworkEvents::READ.union(NetworkEvents::WRITE);

        if self.event.is_none() {
            self.event = Handle::new(event);
            // SAFETY: `socket` is the transport's connection and `event` the
            // caller's event handle.
            let status = unsafe {
                xam::NetDll_WSAEventSelect(
                    XnCaller::DebugMonitor,
                    Socket::from_raw(self.socket.0),
                    xboxkrnl::Handle::from_raw(event),
                    FD_READ_WRITE,
                )
            };
            set_event(self.event);
            if status == xam::SOCKET_ERROR {
                let mut stream = self.stream();
                self.engine.socket_error(&mut stream);
            }
        }

        if raw_handle(self.event) != event {
            assertion_trap();
        }
    }
}

struct SocketStream {
    socket: SocketId,
    event: Option<Handle>,
}

impl Stream for SocketStream {
    unsafe fn send(&mut self, data: Outgoing<'_>) -> Option<u32> {
        let (pointer, length) = match data {
            Outgoing::Local(bytes) => (bytes.as_ptr(), bytes.len() as i32),
            Outgoing::Caller(buffer) => {
                (buffer.address as usize as *const u8, buffer.length as i32)
            }
        };
        // SAFETY: `pointer` addresses `length` readable bytes: a local slice
        // or caller memory under the trait contract.
        let sent = unsafe {
            xam::NetDll_send(
                XnCaller::DebugMonitor,
                Socket::from_raw(self.socket.0),
                pointer,
                length,
                MessageFlags::empty(),
            )
        };
        u32::try_from(sent).ok()
    }

    unsafe fn receive(&mut self, into: Incoming<'_>) -> Option<u32> {
        let (pointer, length) = match into {
            Incoming::Local(bytes) => (bytes.as_mut_ptr(), bytes.len() as i32),
            Incoming::Caller(buffer) => (buffer.address as usize as *mut u8, buffer.length as i32),
        };

        // SAFETY: `pointer` addresses `length` writable bytes: a local slice
        // or caller memory under the trait contract.
        let received = unsafe {
            xam::NetDll_recv(
                XnCaller::DebugMonitor,
                Socket::from_raw(self.socket.0),
                pointer,
                length,
                MessageFlags::empty(),
            )
        };

        u32::try_from(received).ok()
    }

    fn would_block(&mut self) -> bool {
        xam::NetDll_WSAGetLastError(XnCaller::DebugMonitor).error() == Some(Win32Error::WOULD_BLOCK)
    }

    unsafe fn read_length(&mut self, address: u32) -> u32 {
        // SAFETY: the caller passes 4 readable bytes, of any alignment.
        unsafe { (address as usize as *const u32).read_unaligned() }
    }

    fn signal(&mut self) {
        set_event(self.event);
    }

    fn short_buffer(&mut self) {
        assertion_trap();
    }
}

pub(super) fn create_socket_transport(socket: SocketId) -> Result<u32, StudioError> {
    const POOL_TAG: PoolTag = PoolTag::new(*b"sNSX");

    // SAFETY: pool allocation of the object size; the result is checked below.
    let object = unsafe {
        xboxkrnl::ExAllocatePoolTypeWithTag(
            size_of::<SocketTransport>() as u32,
            POOL_TAG,
            PoolType::System,
        )
    };
    if object == 0 {
        return Err(StudioError::OutOfMemory);
    }

    let routines = Routines {
        kind: routine(socket_kind_entry),
        release: routine(socket_release_entry),
        receive: routine(socket_receive_entry),
        send: routine(socket_send_entry),
        result: routine(socket_result_entry),
        cancel: routine(socket_cancel_entry),
    };

    let pointer = object as usize as *mut SocketTransport;
    // SAFETY: the pool returned a block of the object's size.
    unsafe {
        pointer.write(SocketTransport {
            routines,
            section: CriticalSection::new(),
            event: None,
            socket,
            engine: Transport::new(),
        });
        (*pointer).section.initialize();
    }

    let mut nonblocking = 1u32;
    // SAFETY: `socket` is the accepted connection; `nonblocking` is a live u32.
    if unsafe {
        xam::NetDll_ioctlsocket(
            XnCaller::DebugMonitor,
            Socket::from_raw(socket.0),
            IoctlCommand::Fionbio,
            &mut nonblocking,
        )
    } == xam::SOCKET_ERROR
    {
        // SAFETY: `object` was allocated above and is not used afterwards.
        unsafe { xboxkrnl::ExFreePool(object) };
        return Err(StudioError::Fail);
    }

    Ok(object)
}

/// Enter the object's critical section and borrow the object.
///
/// # Safety
/// `this` is a socket transport; the borrow ends before [`leave`].
unsafe fn enter<'a>(this: u32) -> &'a mut SocketTransport {
    let pointer = this as usize as *mut SocketTransport;
    // SAFETY: per the contract; the section serializes the borrow.
    unsafe {
        (*pointer).section.enter();
        &mut *pointer
    }
}

/// Leave the object's critical section.
///
/// # Safety
/// `this` is a socket transport whose section the calling thread holds, and
/// no borrow from [`enter`] is used afterwards.
unsafe fn leave(this: u32) {
    let pointer = this as usize as *mut SocketTransport;
    // SAFETY: per the contract.
    unsafe { &(*pointer).section }.leave();
}

fn socket_queue(
    this: u32,
    direction: Direction,
    buffer: u32,
    length: u32,
    request: &TransferRequest,
) -> u32 {
    // SAFETY: the studio service passes the transport it was given.
    let object = unsafe { enter(this) };
    let result = object.engine.reserve().map(|slot| {
        object.bind_event(request.event());
        request.result.store(object.handle(slot), Ordering::Relaxed);
        let mut stream = object.stream();
        // SAFETY: the studio service queues a buffer that it keeps until it
        // reads the request's result or the transport is cancelled, both
        // after the request finishes. Its receive buffers hold at least the
        // 4-byte length prefix, the precondition stock asserts.
        unsafe {
            object.engine.submit(
                slot,
                direction,
                CallerBuffer {
                    address: buffer,
                    length,
                },
                &mut stream,
            )
        };
    });

    // SAFETY: entered above; `object` is not used afterwards.
    unsafe { leave(this) };

    routine_result(result).0
}

extern "C" fn socket_kind(_this: u32) -> u32 {
    TransportKind::Socket as u32
}

extern "C" fn socket_release(this: u32) -> u32 {
    socket_cancel(this);
    // SAFETY: the studio service releases each transport once, after its last use.
    unsafe { xboxkrnl::ExFreePool(this) };

    0
}

extern "C" fn socket_receive(this: u32, buffer: u32, length: u32, request: u32) -> u32 {
    // SAFETY: the studio service passes a request record that stays live
    // until the request completes.
    let request = unsafe { TransferRequest::from_address(request) };
    socket_queue(this, Direction::Receive, buffer, length, request)
}

extern "C" fn socket_send(this: u32, buffer: u32, length: u32, request: u32) -> u32 {
    // SAFETY: the studio service passes a request record that stays live
    // until the request completes.
    let request = unsafe { TransferRequest::from_address(request) };
    socket_queue(this, Direction::Send, buffer, length, request)
}

/// Stock 0x91f843c8. Stock dereferences any handle; a handle that names no
/// slot fails here. When the connection ends during a wait, stock returns
/// without leaving the section, so a later call from another thread would
/// block forever; the section is left here.
extern "C" fn socket_result(this: u32, request: u32, transferred: u32, wait: u32) -> u32 {
    // SAFETY: the studio service passes a submitted request record and the
    // address of its count word, both live for the call.
    let (request, transferred) = unsafe {
        (
            TransferRequest::from_address(request),
            count_word(transferred),
        )
    };

    let handle = request.result.load(Ordering::Relaxed);
    // SAFETY: the studio service passes the transport it was given.
    let object = unsafe { enter(this) };
    let Some(slot) = object.slot(handle) else {
        // SAFETY: entered above; `object` is not used afterwards.
        unsafe { leave(this) };
        return routine_result(Err(StudioError::InvalidArgument)).0;
    };

    object.pump();

    if wait != 0 {
        loop {
            // SAFETY: the section is held.
            let object = unsafe { kernel::object_at_mut::<SocketTransport>(this) };
            if !object.engine.is_pending(slot) {
                break;
            }

            if !object.engine.is_connected() {
                // SAFETY: the section is held; `object` is not used afterwards.
                unsafe { leave(this) };
                return routine_result(Err(StudioError::NotConnected)).0;
            }

            let event = object.event;
            // SAFETY: the section is held; `object` is not used afterwards.
            unsafe { leave(this) };
            // SAFETY: `event` is the caller's event handle bound to the transport.
            unsafe {
                xam::WaitForSingleObject(
                    xboxkrnl::Handle::from_raw(raw_handle(event)),
                    xam::INFINITE,
                )
            };
            // SAFETY: the studio service passes the transport it was given.
            unsafe { enter(this) }.pump();
        }
    }

    // SAFETY: the section is held.
    let object = unsafe { kernel::object_at_mut::<SocketTransport>(this) };
    let result = match object.engine.complete(slot) {
        None => Err(StudioError::Pending),
        Some((status, count)) => {
            transferred.store(count, Ordering::Relaxed);
            request.result.store(0, Ordering::Relaxed);
            status
        }
    };

    // SAFETY: the section is held; `object` is not used afterwards.
    unsafe { leave(this) };

    routine_result(result).0
}

extern "C" fn socket_cancel(this: u32) -> u32 {
    // SAFETY: the studio service passes the transport it was given.
    let object = unsafe { enter(this) };
    let mut stream = object.stream();
    object.engine.cancel(&mut stream);

    // SAFETY: entered above; `object` is not used afterwards.
    unsafe { leave(this) };

    0
}

bridged!(socket_kind_entry, socket_kind);
bridged!(socket_release_entry, socket_release);
bridged!(socket_receive_entry, socket_receive);
bridged!(socket_send_entry, socket_send);
bridged!(socket_result_entry, socket_result);
bridged!(socket_cancel_entry, socket_cancel);
