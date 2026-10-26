//! Debugger exports. Those that read or change monitor state the server
//! owns (stopped threads, breakpoints, execution state, the extension) run
//! on the server thread through the dispatcher; thread and context
//! services act on the caller's thread directly, as stock does.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands::debugger;
use openxbdm_server::commands::debugger::ContextFlags;
use openxbdm_server::commands::debugger::DataTarget;
use openxbdm_server::commands::debugger::NoSuchThread;
use openxbdm_server::commands::debugger::StopOn;
use openxbdm_server::commands::debugger::ThreadId;
use openxbdm_server::notify::ExecutionState;
use openxbdm_server::reply::CommandError;
use openxbdm_server::state::ServerState;
use xbox360::status::set_last_error;
use xbox360_sys::export_raw;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Context as KernelContext;
use xbox360_sys::xboxkrnl::ContextFlags as KernelContextFlags;
use xbox360_sys::xboxkrnl::RtlGetStackLimits;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;

use super::super::dispatcher;
use super::super::dispatcher::HresultService;
use super::DumpKind;
use crate::exports::export;
use crate::kernel;
use crate::kernel::object_at;
use crate::kernel::object_at_mut;

/// Export 178's result for a missing or overlong name.
const BAD_PARAMETER: Hresult = ErrorCode::BadParameter.hresult();

/// Longest extension name export 178 accepts.
const EXTENSION_NAME_LIMIT: usize = 0x3f;

/// `ExCreateThread` flags of export 180: a system thread on hardware
/// thread 2. Bit 0x4 has no name: no kernel code tests it, and stock
/// passes it.
const DEBUG_THREAD_FLAGS: ThreadCreationFlags = ThreadCreationFlags::SYSTEM_PROCESS
    .union(ThreadCreationFlags::PROCESSOR2)
    .union(ThreadCreationFlags::PRIORITY_CLASS_13)
    .union(ThreadCreationFlags::from_bits_retain(0x4));
const _: () = assert!(DEBUG_THREAD_FLAGS.bits() == 0x0400_0026);

/// Stop-on bits set and cleared while the server state was unreachable,
/// applied by the server thread before its next pass.
static PENDING_STOP_ON_SET: AtomicU32 = AtomicU32::new(0);
static PENDING_STOP_ON_CLEAR: AtomicU32 = AtomicU32::new(0);

xbox360_sys::flags! {
    /// Creation flags a caller passes to export 180 (`CreateThread`
    /// flags).
    pub struct CreateThreadFlags(u32) {
        /// Create the thread suspended (`CREATE_SUSPENDED`).
        SUSPENDED = 0x4,
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
    ///
    /// # Safety
    ///
    /// `address` must be writable for the filled words, as the export's
    /// caller guarantees for its output.
    unsafe fn store(&self, address: u32) {
        let out = core::ptr::with_exposed_provenance_mut::<u32>(address as usize);

        for (index, &word) in self.words[..self.count].iter().enumerate() {
            // SAFETY: the caller guarantees the output words.
            unsafe { out.add(index).write(word) };
        }
    }
}

/// The work of an export on the server thread.
type ExportService = HresultService<Request>;

/// Bounds of the calling thread's stack.
struct StackLimits {
    low: u32,
    high: u32,
}

/// `DM_THREADINFO_EX` as export 89 fills it.
#[repr(C)]
struct ThreadInfoEx {
    size: u32,
    suspend_count: u32,
    priority: u32,
    tls_base: u32,
    start_address: u32,
    stack_base: u32,
    stack_limit: u32,
    create_time_high: u32,
    create_time_low: u32,
    stack_slack: u32,
    name_address: u32,
    name_length: u32,
    processor: u8,
    _reserved_31: [u8; 3],
    last_error: u32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(ThreadInfoEx, start_address) == 0x10);
    assert!(offset_of!(ThreadInfoEx, stack_slack) == 0x24);
    assert!(offset_of!(ThreadInfoEx, processor) == 0x30);
    assert!(offset_of!(ThreadInfoEx, last_error) == 0x34);
    assert!(core::mem::size_of::<ThreadInfoEx>() == 0x38);
};

impl ThreadInfoEx {
    /// Smallest size a caller may state.
    const MINIMUM_SIZE: u32 = 0x10;
    /// Size that holds the fields through the name.
    const NAME_SIZE: u32 = 0x30;
    /// Size that holds every field.
    const FULL_SIZE: u32 = core::mem::size_of::<Self>() as u32;
}

/// The result of a failed export.
fn error_result(error: impl Into<CommandError>) -> Hresult {
    Hresult::from(error.into())
}

/// The result of an export without outputs.
fn command_result(result: Result<(), impl Into<CommandError>>) -> Hresult {
    match result {
        Ok(()) => Hresult::OK,
        Err(error) => error_result(error),
    }
}

/// Run `service` on the server thread with `request`; `None` when the
/// server state is unreachable: on the server thread itself, above passive
/// level, or after the server stopped.
fn call(service: ExportService, request: &mut Request) -> Option<Hresult> {
    dispatcher::call_hresult_service(request, service)
}

/// [`call`], failing the export with E_UNEXPECTED when the server state is
/// unreachable.
fn run(service: ExportService, request: &mut Request) -> Hresult {
    call(service, request).unwrap_or(Hresult::UNEXPECTED)
}

fn on_server(service: ExportService, first: u32, second: u32, third: u32) -> Hresult {
    run(service, &mut Request::new(first, second, third))
}

/// Stock export 8 (0x91f25c60): `(thread, exception) -> HRESULT`.
extern "C" fn continue_thread(thread: u32, exception: u32) -> Hresult {
    on_server(
        |server, console, _network, request| {
            command_result(debugger::continue_stopped_thread(
                &mut server.state,
                console,
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
extern "C" fn get_thread_context(thread: u32, context: u32) -> Hresult {
    if context == 0 {
        return Hresult::INVALID_ARGUMENT;
    }

    // A caller's CONTEXT has the 8-byte alignment of its scalar fields; the
    // 16 bytes of `KernelContext` are not guaranteed, so it is reached only
    // through field pointers.
    let target = core::ptr::with_exposed_provenance_mut::<KernelContext>(context as usize);
    // SAFETY: the caller passes its CONTEXT, aligned to at least 8 bytes,
    // and does not use it during the call.
    let requested = unsafe { (&raw const (*target).context_flags).read() };
    let mut read = debugger::Context {
        flags: ContextFlags::from_bits_retain(requested.bits()),
        ..debugger::Context::default()
    };
    let result = super::read_thread_context(ThreadId(thread), &mut read).map(|()| {
        // SAFETY: as above.
        unsafe {
            (&raw mut (*target).context_flags)
                .write(KernelContextFlags::from_bits_retain(read.flags.bits()));
            super::context_to_memory(target, &read);
        }
    });

    command_result(result)
}
export!(13, get_thread_context);

/// Stock export 15 (0x91f25f28): `(ids, count) -> HRESULT`; `count` holds
/// the list capacity and receives the number stored.
extern "C" fn get_thread_list(ids: u32, count: u32) -> Hresult {
    if ids == 0 || count == 0 {
        return Hresult::INVALID_ARGUMENT;
    }

    // The count word is converted at each access: the caller's id array
    // may overlap it.
    if super::execution_state() == ExecutionState::Pending {
        // SAFETY: the caller passes its count word.
        *unsafe { object_at_mut::<u32>(count) } = 0;
        return Hresult::OK;
    }

    // SAFETY: as above.
    let capacity = *unsafe { object_at::<u32>(count) } as usize;
    let ids = core::ptr::with_exposed_provenance_mut::<u32>(ids as usize);
    let list = super::collect_thread_ids(capacity, &mut |index, id| {
        // SAFETY: the caller's array holds `capacity` ids and the walk
        // stores fewer.
        unsafe { ids.add(index).write(id.0) }
    });
    // SAFETY: as above.
    *unsafe { object_at_mut::<u32>(count) } = list.count as u32;
    if list.overflow {
        Hresult::BUFFER_TOO_SMALL
    } else {
        Hresult::OK
    }
}
export!(15, get_thread_list);

/// Stock export 19 (0x91f25b50): `go`.
extern "C" fn go() -> Hresult {
    on_server(
        |server, console, network, _| {
            command_result(debugger::go_execution(&mut server.state, console, network))
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
extern "C" fn is_thread_stopped(thread: u32, record: u32) -> Hresult {
    if record == 0 {
        return Hresult::INVALID_ARGUMENT;
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
                Hresult::OK
            }
            Err(error) => error_result(error),
        },
        &mut stop,
    );
    // SAFETY: the caller passes a stop record that holds the words.
    unsafe { stop.store(record) };

    result
}
export!(22, is_thread_stopped);

/// Stock export 34 (0x91f27258): `(address) -> HRESULT`, on the calling
/// thread under the table lock.
extern "C" fn remove_breakpoint(address: u32) -> Hresult {
    let removed = if super::table::clear_breakpoint(address) {
        Ok(())
    } else {
        Err(debugger::NoSuchBreakpoint)
    };

    command_result(removed)
}
export!(34, remove_breakpoint);

/// Stock export 35 (0x91f26838): `(thread) -> HRESULT`.
extern "C" fn resume_thread(thread: u32) -> Hresult {
    command_result(super::resume(ThreadId(thread)))
}
export!(35, resume_thread);

/// Stock export 37 (0x91f27140): `(address) -> HRESULT`, on the calling
/// thread; the spare block is allocated before the table lock is taken.
extern "C" fn set_breakpoint(address: u32) -> Hresult {
    command_result(super::table::set_breakpoint(address))
}
export!(37, set_breakpoint);

/// Stock export 38 (0x91f27370): `(address, type, size) -> HRESULT`; type
/// 0 clears, 1 write, 2 read/write, 5 read.
extern "C" fn set_data_breakpoint(address: u32, kind: u32, size: u32) -> Hresult {
    on_server(
        |server, console, _, request| {
            let target = DataTarget::from_type(request.second);
            command_result(debugger::set_data_breakpoint(
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
extern "C" fn break_at_title_start() -> Hresult {
    on_server(
        |server, console, _, _| {
            command_result(debugger::break_at_title_start(&mut server.state, console))
        },
        0,
        0,
        0,
    )
}
export!(39, break_at_title_start);

/// Stock export 41 (0x91f26468): `(thread, context) -> HRESULT`; writes the
/// groups the context's flags select.
extern "C" fn set_thread_context(thread: u32, context: u32) -> Hresult {
    if context == 0 {
        return Hresult::INVALID_ARGUMENT;
    }

    // Reached through field pointers, as in export 13.
    let source = core::ptr::with_exposed_provenance::<KernelContext>(context as usize);
    // SAFETY: the caller passes its CONTEXT, aligned to at least 8 bytes,
    // and does not change it during the call.
    let flags = unsafe { (&raw const (*source).context_flags).read() };
    let flags = ContextFlags::from_bits_retain(flags.bits()) & ContextFlags::FULL;
    // SAFETY: as above.
    let source = unsafe { super::context_from_memory(source, flags) };

    command_result(super::write_thread_context(ThreadId(thread), &source))
}
export!(41, set_thread_context);

/// Stock export 45 (0x91f25be0): `stop`.
extern "C" fn stop() -> Hresult {
    on_server(
        |server, console, network, _| {
            command_result(debugger::stop_execution(
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

/// Apply stop-on changes export 46 could not make directly.
pub(crate) fn apply_pending_stop_on(state: &mut ServerState) {
    let clear = PENDING_STOP_ON_CLEAR.swap(0, Ordering::AcqRel);
    let set = PENDING_STOP_ON_SET.swap(0, Ordering::AcqRel);
    debugger::change_stop_on(state, StopOn::from_bits_retain(clear), false);
    debugger::change_stop_on(state, StopOn::from_bits_retain(set), true);
}

/// Stock export 46 (0x91f26790): `(flags, set) -> HRESULT`; stock changes
/// the word atomically at any level, so a caller that cannot reach the
/// server thread queues the change for it.
extern "C" fn stop_on(flags: u32, set: u32) -> Hresult {
    let applied = call(
        |server, _, _, request| {
            debugger::change_stop_on(
                &mut server.state,
                StopOn::from_bits_retain(request.first),
                request.second != 0,
            );
            Hresult::OK
        },
        &mut Request::new(flags, set, 0),
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

    Hresult::OK
}
export!(46, stop_on);

/// Stock export 48 (0x91f267e8): `(thread) -> HRESULT`.
extern "C" fn suspend_thread(thread: u32) -> Hresult {
    command_result(super::suspend(ThreadId(thread)))
}
export!(48, suspend_thread);

/// Stock export 49 (0x91f433b8): `(thread, address) -> HRESULT`; the
/// address of the per-thread debug data word. `thread` -1 is the caller.
/// Stock looks the thread up but hands out the word of the calling
/// thread's record.
extern "C" fn thread_debug_data(thread: u32, address: u32) -> Hresult {
    if address == 0 {
        return Hresult::INVALID_ARGUMENT;
    }

    if thread != u32::MAX && super::ThreadRef::lookup(ThreadId(thread)).is_err() {
        return error_result(NoSuchThread);
    }

    match super::current_debug_data() {
        Some(debug_data) => {
            // SAFETY: the caller passes its output word.
            *unsafe { object_at_mut::<u32>(address) } = debug_data;
            Hresult::OK
        }
        None => error_result(NoSuchThread),
    }
}
export!(49, thread_debug_data);

/// Stock export 56 (0x91f257f8): `(address, kind) -> HRESULT`; 4 for a
/// software breakpoint, else the data breakpoint kind at that exact
/// address, else 0.
extern "C" fn breakpoint_kind(address: u32, kind: u32) -> Hresult {
    let mut query = Request::new(address, 0, 0);
    let result = run(
        |server, console, _, request| {
            request.words[0] = debugger::breakpoint_kind(&server.state, console, request.first);
            request.count = 1;
            Hresult::OK
        },
        &mut query,
    );
    // SAFETY: the caller passes its output word.
    unsafe { query.store(kind) };

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
extern "C" fn capture_back_trace(
    count: u32,
    buffer: u32,
    stack: u32,
    return_address: u32,
) -> Hresult {
    /// Return addresses export 82 stores at most.
    const BACK_TRACE_LIMIT: u32 = 0x100;

    if count == 0 || count > BACK_TRACE_LIMIT {
        return BAD_PARAMETER;
    }

    let (mut low, mut high) = (0u32, 0u32);
    // SAFETY: both outputs are live locals.
    unsafe { RtlGetStackLimits(&mut low, &mut high) };
    // SAFETY: the caller passes a buffer of `count` words; `stack` is its
    // stack pointer and the frames lie on the calling thread's stack.
    unsafe {
        back_trace(
            core::ptr::with_exposed_provenance_mut(buffer as usize),
            count,
            stack,
            return_address,
            StackLimits { low, high },
        )
    };

    Hresult::OK
}

/// Store the return addresses of the frames from `stack` outward into
/// `buffer` and zero the rest of its `count` entries.
///
/// # Safety
///
/// `buffer` must be writable for `count` words, and each frame address
/// strictly within `limits` reached through the back chain from `stack`
/// must be readable at the frame and 8 bytes below it.
unsafe fn back_trace(
    buffer: *mut u32,
    count: u32,
    stack: u32,
    return_address: u32,
    limits: StackLimits,
) {
    let mut stored = 0;
    let mut frame = stack;

    while stored < count && frame < limits.high && frame > limits.low {
        let address = if stored == 0 {
            return_address
        } else {
            // SAFETY: the caller guarantees the saved return address word.
            unsafe { *object_at::<u32>(frame - 8) }
        };
        // SAFETY: `stored` is below `count`.
        unsafe { buffer.add(stored as usize).write(address) };
        stored += 1;
        // SAFETY: the caller guarantees the back chain word.
        frame = unsafe { *object_at::<u32>(frame) };
    }

    for index in stored..count {
        // SAFETY: `index` is below `count`.
        unsafe { buffer.add(index as usize).write(0) };
    }
}

/// Stock export 83 (0x91f26888): `(resume)`; dump the calling thread, and
/// return afterwards instead of restarting when `resume` is nonzero.
extern "C" fn write_dump(resume: u32) -> u32 {
    super::dump_calling_thread(if resume != 0 {
        DumpKind::Return
    } else {
        DumpKind::Default
    });

    0
}
export!(83, write_dump);

/// Stock export 89 (0x91f265b0): `(thread, info) -> HRESULT`. `info` starts
/// with its size (at least 0x10); the fields that fit are filled and the
/// rest of the stated size is zeroed.
extern "C" fn thread_info(thread: u32, info: u32) -> Hresult {
    /// Stack slack reported by export 89, as `threadinfo` reports it.
    const THREAD_SLACK: u32 = 0x540;

    if info == 0 {
        return Hresult::INVALID_ARGUMENT;
    }

    // SAFETY: the caller passes its `DM_THREADINFO_EX`, a record of words
    // that starts with its size.
    let size = unsafe { *object_at::<u32>(info) };
    if size < ThreadInfoEx::MINIMUM_SIZE {
        return Hresult::INVALID_ARGUMENT;
    }

    let Ok(details) = super::thread_information(ThreadId(thread)) else {
        return error_result(NoSuchThread);
    };

    let suspend = i32::from(details.suspend_count) - i32::from(details.monitor_suspended);
    let mut filled = ThreadInfoEx {
        size,
        suspend_count: suspend as u32,
        priority: u32::from(details.priority),
        tls_base: details.tls_base,
        start_address: 0,
        stack_base: 0,
        stack_limit: 0,
        create_time_high: 0,
        create_time_low: 0,
        stack_slack: 0,
        name_address: 0,
        name_length: 0,
        processor: 0,
        _reserved_31: [0; 3],
        last_error: 0,
    };
    if size >= ThreadInfoEx::NAME_SIZE {
        filled.start_address = details.start_address;
        filled.stack_base = details.stack_base;
        filled.stack_limit = details.stack_limit;
        filled.create_time_high = (details.create_time >> 32) as u32;
        filled.create_time_low = details.create_time as u32;
        filled.stack_slack = THREAD_SLACK;
        if let Some(name) = details.name {
            filled.name_address = name.address;
            filled.name_length = name.length;
        }
    }
    if size > ThreadInfoEx::NAME_SIZE {
        filled.processor = details.processor;
    }
    if size >= ThreadInfoEx::FULL_SIZE {
        filled.last_error = details.last_error;
    }
    // SAFETY: the caller's record holds the `size` bytes it states, and it
    // does not use them during the call. The slice covers exactly the bytes
    // stock writes (its size word excepted, which is not written), so the
    // export trusts the stated size as stock does; byte elements need no
    // alignment.
    let out = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::with_exposed_provenance_mut::<u8>(info as usize),
            size as usize,
        )
    };
    // SAFETY: `ThreadInfoEx` is plain words and bytes without padding.
    let source = unsafe {
        core::slice::from_raw_parts(
            core::ptr::from_ref(&filled).cast::<u8>(),
            core::mem::size_of::<ThreadInfoEx>(),
        )
    };
    let copied = out.len().min(source.len());
    let skip = core::mem::size_of::<u32>();
    out[skip..copied].copy_from_slice(&source[skip..copied]);
    out[copied..].fill(0);

    Hresult::OK
}
export!(89, thread_info);

/// Stock export 178 (0x91f2e5e0): `(name, handle) -> HRESULT`.
extern "C" fn load_extension(name: u32, handle: u32) -> Hresult {
    // SAFETY: the caller passes 0 or a NUL-terminated name; at most the
    // limit plus one bytes are read.
    let Some(characters) = (unsafe { kernel::bounded_c_string(name, EXTENSION_NAME_LIMIT + 1) })
        .filter(|characters| characters.len() <= EXTENSION_NAME_LIMIT)
    else {
        return BAD_PARAMETER;
    };
    let length = characters.len();
    if handle != 0 {
        // SAFETY: the caller passes 0 or its output word.
        *unsafe { object_at_mut::<u32>(handle) } = 0;
    }
    let mut load = Request::new(name, 0, length as u32);
    let result = run(
        |server, console, _, request| {
            // SAFETY: the caller measured the name before posting the request
            // and waits until it is answered.
            let name = unsafe {
                core::slice::from_raw_parts(
                    core::ptr::with_exposed_provenance::<u8>(request.first as usize),
                    request.third as usize,
                )
            };
            match debugger::load_extension(&mut server.state, console, name) {
                Ok(loaded) => {
                    request.words[0] = loaded;
                    request.count = 1;
                    Hresult::OK
                }
                Err(error) => error_result(error),
            }
        },
        &mut load,
    );
    if handle != 0 {
        // SAFETY: as above.
        unsafe { load.store(handle) };
    }

    result
}
export!(178, load_extension);

/// Stock export 179 (0x91f2e6e0): `(handle) -> HRESULT`.
extern "C" fn release_extension(handle: u32) -> Hresult {
    on_server(
        |server, console, _, request| {
            command_result(debugger::release_extension(
                &mut server.state,
                console,
                request.first,
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
    let mut creation = DEBUG_THREAD_FLAGS;
    if CreateThreadFlags::from_bits_retain(flags).contains(CreateThreadFlags::SUSPENDED) {
        creation |= ThreadCreationFlags::SUSPENDED;
    }
    // SAFETY: `handle` is a live local; the caller supplies the thread id
    // output (or null) and the start routine, as the stock export takes them.
    let status = unsafe {
        xboxkrnl::ExCreateThread(
            &mut handle,
            stack_size,
            core::ptr::with_exposed_provenance_mut(thread_id as usize),
            0,
            start,
            parameter,
            creation,
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
        // Each output is converted and stored alone: the caller may pass
        // the same word for both.
        // SAFETY: the caller passes 0 or its output word.
        if let Some(address) =
            unsafe { core::ptr::with_exposed_provenance_mut::<u32>(address as usize).as_mut() }
        {
            *address = published.address;
        }
        // SAFETY: as above.
        if let Some(port) =
            unsafe { core::ptr::with_exposed_provenance_mut::<u32>(port as usize).as_mut() }
        {
            *port = published.port;
        }
    }

    published.attached
}
export!(373, debugger_address);
