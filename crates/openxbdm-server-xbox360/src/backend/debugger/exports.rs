//! Debugger exports. Those that read or change monitor state the server
//! owns (stopped threads, breakpoints, execution state, the extension) run
//! on the server thread through the dispatcher; thread and context
//! services act on the caller's thread directly, as stock does.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use openxbdm_core::status::xbdm_error;
use openxbdm_server::commands::debugger;
use openxbdm_server::commands::debugger::ContextFlags;
use openxbdm_server::commands::debugger::DataTarget;
use openxbdm_server::commands::debugger::ExtensionHandle;
use openxbdm_server::commands::debugger::NoSuchThread;
use openxbdm_server::commands::debugger::StopOn;
use openxbdm_server::commands::debugger::ThreadId;
use openxbdm_server::notify::ExecutionState;
use openxbdm_server::reply::CommandError;
use openxbdm_server::state::ServerState;
use xbox360::status::set_last_error;
use xbox360_sys::export_raw;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::RtlGetStackLimits;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;

use super::super::dispatcher;
use super::super::dispatcher::ServerService;
use crate::exports::export;

/// Export 178's result for a missing or overlong name.
const BAD_PARAMETER: Hresult = ErrorCode::BadParameter.hresult();
/// More threads exist than the caller's list holds.
const BUFFER_TOO_SMALL: Hresult = xbdm_error(0x105);
/// Longest extension name export 178 accepts.
const EXTENSION_NAME_LIMIT: usize = 0x3f;
/// Return addresses export 82 stores at most.
const BACK_TRACE_LIMIT: u32 = 0x100;
/// Stack slack reported by export 89, as `threadinfo` reports it.
const THREAD_SLACK: u32 = 0x540;
/// `ExCreateThread` flags of export 180; bit 0 (suspended) comes from the
/// caller's flag 4.
const DEBUG_THREAD_FLAGS: u32 = 0x0400_0026;

fn read_u32(address: u32) -> u32 {
    // SAFETY: the caller passes a readable location.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn write_u32(address: u32, value: u32) {
    // SAFETY: the caller passes a writable location.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

fn write_u8(address: u32, value: u8) {
    // SAFETY: the caller passes a writable location.
    unsafe { core::ptr::write_volatile(address as usize as *mut u8, value) }
}

/// The result word of a failed export.
fn error_word(error: impl Into<CommandError>) -> u32 {
    Hresult::from(error.into()).0
}

/// The result word of an export without outputs.
fn result_word(result: Result<(), impl Into<CommandError>>) -> u32 {
    match result {
        Ok(()) => Hresult::OK.0,
        Err(error) => error_word(error),
    }
}

/// Arguments of an export, passed to the server thread on the caller's
/// stack, and the words the service hands back. The caller stores outputs
/// through its own pointers, so a bad pointer faults on the calling thread
/// as in stock.
#[repr(C)]
struct Request {
    first: u32,
    second: u32,
    third: u32,
    words: [u32; 7],
    /// Words of `words` the service filled.
    count: usize,
}

impl Request {
    const fn new(first: u32, second: u32, third: u32) -> Self {
        Self {
            first,
            second,
            third,
            words: [0; 7],
            count: 0,
        }
    }

    /// Store the filled words at `address`.
    fn store(&self, address: u32) {
        for (index, &word) in self.words[..self.count].iter().enumerate() {
            write_u32(address + 4 * index as u32, word);
        }
    }
}

/// Run `service` on the server thread with `request`. On the server thread
/// itself, above passive level, or after the server stopped, the server
/// state is unreachable and the export fails with E_UNEXPECTED.
fn run(service: ServerService<Request>, request: &mut Request) -> u32 {
    dispatcher::call_on_server_with(request, service).unwrap_or(Hresult::UNEXPECTED.0)
}

fn on_server(service: ServerService<Request>, first: u32, second: u32, third: u32) -> u32 {
    run(service, &mut Request::new(first, second, third))
}

/// Stock export 8 (0x91f25c60): `(thread, exception) -> HRESULT`.
extern "C" fn continue_thread(thread: u32, exception: u32) -> u32 {
    on_server(
        |server, console, network, request| {
            result_word(debugger::continue_stopped_thread(
                &mut server.state,
                console,
                network,
                ThreadId(request.first),
                request.second != 0,
            ))
        },
        thread,
        exception,
        0,
    )
}
export!(8, continue_thread);

/// Stock export 13 (0x91f26260): `(thread, context) -> HRESULT`; the
/// context's flags select the groups and are replaced by those read.
extern "C" fn get_thread_context(thread: u32, context: u32) -> u32 {
    if context == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let flags = ContextFlags(read_u32(context));
    let mut read = debugger::Context {
        flags,
        ..debugger::Context::default()
    };
    let result = super::read_thread_context(ThreadId(thread), &mut read).map(|()| {
        write_u32(context, read.flags.0);
        super::context_to_memory(context, &read);
    });
    result_word(result)
}
export!(13, get_thread_context);

/// Stock export 15 (0x91f25f28): `(ids, count) -> HRESULT`; `count` holds
/// the list capacity and receives the number stored.
extern "C" fn get_thread_list(ids: u32, count: u32) -> u32 {
    if ids == 0 || count == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    if super::execution_state() == ExecutionState::Pending {
        write_u32(count, 0);
        return Hresult::OK.0;
    }
    let capacity = read_u32(count) as usize;
    let list = super::collect_thread_ids(capacity, &mut |index, id| {
        write_u32(ids + 4 * index as u32, id.0)
    });
    write_u32(count, list.count as u32);
    if list.overflow {
        BUFFER_TOO_SMALL.0
    } else {
        Hresult::OK.0
    }
}
export!(15, get_thread_list);

/// Stock export 19 (0x91f25b50): `go`.
extern "C" fn go() -> u32 {
    on_server(
        |server, console, network, _| {
            result_word(debugger::go_execution(&mut server.state, console, network))
        },
        0,
        0,
        0,
    )
}
export!(19, go);

/// Stock export 21 (0x91f49430): whether a debugger is attached.
extern "C" fn is_debugger_attached() -> u32 {
    dispatcher::published_debugger().attached
}
export!(21, is_debugger_attached);

/// Stock export 22 (0x91f26058): `(thread, record) -> HRESULT`; the stop
/// record of a stopped thread.
extern "C" fn is_thread_stopped(thread: u32, record: u32) -> u32 {
    if record == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let mut stop = Request::new(thread, 0, 0);
    let result = run(
        |server, console, _, request| match debugger::stop_reason(
            &server.state,
            console,
            ThreadId(request.first),
        ) {
            Ok(reason) => {
                (request.words, request.count) = reason.encode();
                Hresult::OK.0
            }
            Err(error) => error_word(error),
        },
        &mut stop,
    );
    stop.store(record);
    result
}
export!(22, is_thread_stopped);

/// Stock export 34 (0x91f27258): `(address) -> HRESULT`.
extern "C" fn remove_breakpoint(address: u32) -> u32 {
    on_server(
        |server, console, _, request| {
            result_word(debugger::clear_software_breakpoint(
                &mut server.state,
                console,
                request.first,
            ))
        },
        address,
        0,
        0,
    )
}
export!(34, remove_breakpoint);

/// Stock export 35 (0x91f26838): `(thread) -> HRESULT`.
extern "C" fn resume_thread(thread: u32) -> u32 {
    result_word(super::resume(ThreadId(thread)))
}
export!(35, resume_thread);

/// Stock export 37 (0x91f27140): `(address) -> HRESULT`.
extern "C" fn set_breakpoint(address: u32) -> u32 {
    on_server(
        |server, console, _, request| {
            result_word(debugger::set_software_breakpoint(
                &mut server.state,
                console,
                request.first,
            ))
        },
        address,
        0,
        0,
    )
}
export!(37, set_breakpoint);

/// Stock export 38 (0x91f27370): `(address, type, size) -> HRESULT`; type
/// 0 clears, 1 write, 2 read/write, 5 read.
extern "C" fn set_data_breakpoint(address: u32, kind: u32, size: u32) -> u32 {
    on_server(
        |server, console, _, request| {
            let target = DataTarget::from_type(request.second);
            result_word(debugger::set_data_breakpoint(
                &mut server.state,
                console,
                request.first,
                request.third,
                target,
            ))
        },
        address,
        kind,
        size,
    )
}
export!(38, set_data_breakpoint);

/// Stock export 39 (0x91f26728): `break start`.
extern "C" fn break_at_title_start() -> u32 {
    on_server(
        |server, console, _, _| {
            result_word(debugger::break_at_title_start(&mut server.state, console))
        },
        0,
        0,
        0,
    )
}
export!(39, break_at_title_start);

/// Stock export 41 (0x91f26468): `(thread, context) -> HRESULT`; writes the
/// groups the context's flags select.
extern "C" fn set_thread_context(thread: u32, context: u32) -> u32 {
    if context == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let flags = ContextFlags(read_u32(context)).intersection(ContextFlags::FULL);
    let source = super::context_from_memory(context, flags);
    result_word(super::write_thread_context(ThreadId(thread), &source))
}
export!(41, set_thread_context);

/// Stock export 45 (0x91f25be0): `stop`.
extern "C" fn stop() -> u32 {
    on_server(
        |server, console, network, _| {
            result_word(debugger::stop_execution(
                &mut server.state,
                console,
                network,
            ))
        },
        0,
        0,
        0,
    )
}
export!(45, stop);

/// Stop-on bits set and cleared while the server state was unreachable,
/// applied by the server thread before its next pass.
static PENDING_STOP_ON_SET: AtomicU32 = AtomicU32::new(0);
static PENDING_STOP_ON_CLEAR: AtomicU32 = AtomicU32::new(0);

/// Apply stop-on changes export 46 could not make directly.
pub(crate) fn apply_pending_stop_on(state: &mut ServerState) {
    let clear = PENDING_STOP_ON_CLEAR.swap(0, Ordering::AcqRel);
    let set = PENDING_STOP_ON_SET.swap(0, Ordering::AcqRel);
    debugger::change_stop_on(state, StopOn(clear), false);
    debugger::change_stop_on(state, StopOn(set), true);
}

/// Stock export 46 (0x91f26790): `(flags, set) -> HRESULT`; stock changes
/// the word atomically at any level, so a caller that cannot reach the
/// server thread queues the change for it.
extern "C" fn stop_on(flags: u32, set: u32) -> u32 {
    let applied = dispatcher::call_on_server_with(
        &mut Request::new(flags, set, 0),
        |server, _, _, request| {
            debugger::change_stop_on(
                &mut server.state,
                StopOn(request.first),
                request.second != 0,
            );
            0
        },
    );
    if applied.is_none() {
        let (add, remove) = if set != 0 {
            (&PENDING_STOP_ON_SET, &PENDING_STOP_ON_CLEAR)
        } else {
            (&PENDING_STOP_ON_CLEAR, &PENDING_STOP_ON_SET)
        };
        add.fetch_or(flags, Ordering::AcqRel);
        remove.fetch_and(!flags, Ordering::AcqRel);
    }
    Hresult::OK.0
}
export!(46, stop_on);

/// Stock export 48 (0x91f267e8): `(thread) -> HRESULT`.
extern "C" fn suspend_thread(thread: u32) -> u32 {
    result_word(super::suspend(ThreadId(thread)))
}
export!(48, suspend_thread);

/// Stock export 49 (0x91f433b8): `(thread, address) -> HRESULT`; the
/// address of the per-thread debug data word. `thread` -1 is the caller.
/// Stock looks the thread up but hands out the word of the calling
/// thread's record.
extern "C" fn thread_debug_data(thread: u32, address: u32) -> u32 {
    if address == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    if thread != u32::MAX && super::ThreadRef::lookup(ThreadId(thread)).is_err() {
        return error_word(NoSuchThread);
    }
    match super::current_record() {
        Some(record) => {
            write_u32(address, super::debug_data_of(record));
            Hresult::OK.0
        }
        None => error_word(NoSuchThread),
    }
}
export!(49, thread_debug_data);

/// Stock export 56 (0x91f257f8): `(address, kind) -> HRESULT`; 4 for a
/// software breakpoint, else the data breakpoint kind at that exact
/// address, else 0.
extern "C" fn breakpoint_kind(address: u32, kind: u32) -> u32 {
    let mut query = Request::new(address, 0, 0);
    let result = run(
        |server, _, _, request| {
            request.words[0] = debugger::breakpoint_kind(&server.state, request.first);
            request.count = 1;
            Hresult::OK.0
        },
        &mut query,
    );
    query.store(kind);
    result
}
export!(56, breakpoint_kind);

/// Export 82 entry: the target also receives the caller's stack pointer
/// and return address.
#[unsafe(naked)]
extern "C" fn back_trace_entry() {
    core::arch::naked_asm!(
        "mr 5, 1",
        "mflr 6",
        "lis 12, {target}@ha",
        "addi 12, 12, {target}@l",
        "b {bridge}",
        target = sym capture_back_trace,
        bridge = sym crate::exports::export_bridge,
    )
}
export_raw!(82, back_trace_entry);

/// Stock export 82 (0x91f33d98): `(count, buffer) -> HRESULT`; return
/// addresses of the frames from the caller outward while they lie within
/// the thread's stack, the rest of the `count` entries zeroed. Stock reads
/// each from the word below the frame, where the callee saved it; the
/// first is the caller's return address.
extern "C" fn capture_back_trace(count: u32, buffer: u32, stack: u32, return_address: u32) -> u32 {
    if count == 0 || count > BACK_TRACE_LIMIT {
        return BAD_PARAMETER.0;
    }
    let (mut low, mut high) = (0u32, 0u32);
    // SAFETY: both outputs are live locals.
    unsafe { RtlGetStackLimits(&mut low, &mut high) };
    let mut stored = 0;
    let mut frame = stack;
    while stored < count && frame < high && frame > low {
        let address = if stored == 0 {
            return_address
        } else {
            read_u32(frame - 8)
        };
        write_u32(buffer + 4 * stored, address);
        stored += 1;
        frame = read_u32(frame);
    }
    for index in stored..count {
        write_u32(buffer + 4 * index, 0);
    }
    Hresult::OK.0
}

/// Stock export 83 (0x91f26888): `(full)`; dump the calling thread, a full
/// dump when `full` is nonzero.
extern "C" fn write_dump(full: u32) -> u32 {
    super::dump_calling_thread(if full != 0 { 2 } else { 0 });
    0
}
export!(83, write_dump);

/// Stock export 89 (0x91f265b0): `(thread, info) -> HRESULT`. `info` starts
/// with its size (at least 0x10); the fields that fit are filled and the
/// rest of the stated size is zeroed.
extern "C" fn thread_info(thread: u32, info: u32) -> u32 {
    if info == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let size = read_u32(info);
    if size < 0x10 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let Ok(details) = super::thread_information(ThreadId(thread)) else {
        return error_word(NoSuchThread);
    };
    for offset in 4..size {
        write_u8(info + offset, 0);
    }
    let suspend = i32::from(details.suspend_count) - i32::from(details.monitor_suspended);
    write_u32(info + 0x4, suspend as u32);
    write_u32(info + 0x8, u32::from(details.priority));
    write_u32(info + 0xc, details.tls_base);
    if size >= 0x30 {
        write_u32(info + 0x10, details.start_address);
        write_u32(info + 0x14, details.stack_base);
        write_u32(info + 0x18, details.stack_limit);
        write_u32(info + 0x1c, (details.create_time >> 32) as u32);
        write_u32(info + 0x20, details.create_time as u32);
        write_u32(info + 0x24, THREAD_SLACK);
        if let Some(name) = details.name {
            write_u32(info + 0x28, name.address);
            write_u32(info + 0x2c, name.length);
        }
    }
    if size > 0x30 {
        write_u8(info + 0x30, details.processor);
    }
    if size >= 0x38 {
        write_u32(info + 0x34, details.last_error);
    }
    Hresult::OK.0
}
export!(89, thread_info);

/// Stock export 178 (0x91f2e5e0): `(name, handle) -> HRESULT`.
extern "C" fn load_extension(name: u32, handle: u32) -> u32 {
    if name == 0 {
        return BAD_PARAMETER.0;
    }
    let mut length = 0usize;
    // SAFETY: the caller passes a NUL-terminated name.
    while unsafe { core::ptr::read_volatile((name as usize + length) as *const u8) } != 0 {
        length += 1;
        if length > EXTENSION_NAME_LIMIT {
            return BAD_PARAMETER.0;
        }
    }
    if handle != 0 {
        write_u32(handle, 0);
    }
    let mut load = Request::new(name, 0, length as u32);
    let result = run(
        |server, console, _, request| {
            // SAFETY: the caller measured the name before posting the request
            // and waits until it is answered.
            let name = unsafe {
                core::slice::from_raw_parts(
                    request.first as usize as *const u8,
                    request.third as usize,
                )
            };
            match debugger::load_extension(&mut server.state, console, name) {
                Ok(loaded) => {
                    request.words[0] = loaded.0;
                    request.count = 1;
                    Hresult::OK.0
                }
                Err(error) => error_word(error),
            }
        },
        &mut load,
    );
    if handle != 0 {
        load.store(handle);
    }
    result
}
export!(178, load_extension);

/// Stock export 179 (0x91f2e6e0): `(handle) -> HRESULT`.
extern "C" fn release_extension(handle: u32) -> u32 {
    on_server(
        |server, console, _, request| {
            result_word(debugger::release_extension(
                &mut server.state,
                console,
                ExtensionHandle(request.first),
            ))
        },
        handle,
        0,
        0,
    )
}
export!(179, release_extension);

/// Stock export 180 (0x91f2e3b8): `(attributes, stack size, start,
/// parameter, flags, thread id) -> handle`; flag 4 creates the thread
/// suspended. 0 after a failure, with the last error set.
extern "C" fn create_thread(
    _attributes: u32,
    stack_size: u32,
    start: u32,
    parameter: u32,
    flags: u32,
    thread_id: u32,
) -> u32 {
    let mut handle = 0u32;
    let creation = DEBUG_THREAD_FLAGS | ((flags >> 2) & 1);
    // SAFETY: `handle` is a live local; the caller supplies the thread id
    // output (or null) and the start routine, as the stock export takes them.
    let status = unsafe {
        xboxkrnl::ExCreateThread(
            &mut handle,
            stack_size,
            thread_id as usize as *mut u32,
            0,
            start,
            parameter,
            ThreadCreationFlags::from_bits_retain(creation),
        )
    };
    if let Err(error) = status.result() {
        set_last_error(error);
        return 0;
    }
    handle
}
export!(180, create_thread);

/// Stock export 373 (0x91f49440): `(address, port) -> attached`; both
/// outputs are optional and written only while a debugger is attached.
extern "C" fn debugger_address(address: u32, port: u32) -> u32 {
    let published = dispatcher::published_debugger();
    if published.attached != 0 {
        if address != 0 {
            write_u32(address, published.address);
        }
        if port != 0 {
            write_u32(port, published.port);
        }
    }
    published.attached
}
export!(373, debugger_address);
