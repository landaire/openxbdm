//! Log engine (exports 355-358 and 360-364; stock create 0x91f79470,
//! worker 0x91f78d48). Producers on any thread copy or format a record into
//! an entry taken from the free queue and append it to the pending queue;
//! a worker thread hands each pending entry to a callback, or writes its
//! text to a file, and returns it to the free queue. Both queues are the
//! lock-free queues of exports 302-309.
//!
//! Object (caller-visible; the entries follow at +0x160): +0x00 entry size,
//! +0x04 file handle (file-name mode), +0x08 worker thread handle, +0x0c
//! and +0x10 pointers to the quit and done KEVENTs at +0x140 and +0x130,
//! +0x14 worker failure status, +0x18 dropped records, +0x1c failed worker
//! waits, +0x20 callback, +0x24 its context, +0x28 file name (0x104 bytes),
//! +0x12c worker thread id, +0x150 and +0x154 cells holding the pending and
//! free queues, +0x158 and +0x15c free routine and context of a caller
//! allocator.
//!
//! Engine memory is caller-visible and every address below comes from the
//! caller or from an engine the caller passed, as in stock: the validity of
//! each access rests on the caller's contract with the export.

use core::fmt::Write as _;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_server::commands::session::TellLogConfig;
use openxbdm_server::commands::session::TellLogCounters;
use openxbdm_server::text::Text;

use super::THREAD_ID;
use super::THREAD_PROCESS_TYPE;
use super::THREAD_SYSTEM_PROCESS;
use super::TITLE_PROCESS;
use super::current_thread;
use super::read_u8;
use crate::exports::export;
use crate::exports::export_raw;
use crate::kernel;
use crate::kernel::IoStatusBlock;
use crate::kernel::LIB_XAM;
use crate::kernel::import_thunk;
use crate::lockfree;
use crate::lockfree::queue;

import_thunk!(
    CreateFileA(
        name: u32,
        access: u32,
        share: u32,
        security: u32,
        disposition: u32,
        flags: u32,
        template: u32,
    ) -> u32,
    lib = LIB_XAM,
    ordinal = 0x447
);

const ENTRY_SIZE: u32 = 0x00;
const FILE: u32 = 0x04;
const WORKER: u32 = 0x08;
const QUIT: u32 = 0x0c;
const DONE: u32 = 0x10;
const STATUS: u32 = 0x14;
const DROPPED: u32 = 0x18;
const MISSED: u32 = 0x1c;
const CALLBACK: u32 = 0x20;
const CONTEXT: u32 = 0x24;
const NAME: u32 = 0x28;
const WORKER_ID: u32 = 0x12c;
const DONE_EVENT: u32 = 0x130;
const QUIT_EVENT: u32 = 0x140;
const PENDING: u32 = 0x150;
const FREE: u32 = 0x154;
const FREE_ROUTINE: u32 = 0x158;
const FREE_CONTEXT: u32 = 0x15c;
/// Offset of the first entry; the header bytes the engine zeroes.
const ENTRIES: u32 = 0x160;

const NAME_CAPACITY: u32 = 0x104;
const DEFAULT_NAME: &core::ffi::CStr = c"game:\\logfile.txt";
const DEFAULT_ENTRY_SIZE: u32 = 0x100;
const DEFAULT_ENTRIES: u32 = 0x3e8;
const DEFAULT_PROCESSOR: u32 = 5;
const NO_FILE: u32 = u32::MAX;

/// Creation descriptor of a lock-free queue (export 304): +0 flags, +8
/// remove wait context, +0xc/+0x10 insert/remove timeouts, +0x18 remove
/// wait routine, +0x1c descriptor size, +0x20 nodes per block, +0x24 node
/// limit, +0x28..+0x30 allocator of the caller options.
const DESCRIPTOR_WORDS: usize = 13;
const DESCRIPTOR_SIZE: u32 = 0x34;
const INSERT_WAITS: u32 = 0x4;
const REMOVE_WAITS: u32 = 0x8;
const NO_LIMIT: u32 = u32::MAX;

/// Worker thread stack and creation flags (stock 0x91f82d88).
const WORKER_STACK: u32 = 0x8000;
const WORKER_FLAGS: u32 = 0x224;
const WORKER_FAILED: u32 = u32::MAX;
/// A pending-queue wait ended by the quit event (wait index 1 as an
/// HRESULT from the queue).
const QUIT_REQUESTED: u32 = 0x8007_0001;
/// Status of a worker whose file could not be created.
const STATUS_OBJECT_NAME_INVALID: u32 = 0xc000_0033;
const STATUS_PENDING: u32 = 0x103;
const STATUS_TIMEOUT: u32 = 0x102;
const WAIT_ANY: u32 = 1;
const WAIT_USER_REQUEST: u32 = 3;
const KERNEL_MODE: u32 = 0;
const USER_MODE: u32 = 1;
const GENERIC_WRITE: u32 = 0x4000_0000;
const CREATE_ALWAYS: u32 = 2;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

fn load(address: u32) -> u32 {
    // SAFETY: see the module documentation.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn store(address: u32, value: u32) {
    // SAFETY: see the module documentation.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

/// Call a console routine supplied by the caller or by the engine.
fn call(routine: u32, a0: u32, a1: u32, a2: u32) -> u32 {
    // SAFETY: the routine comes from the caller's arguments, as in stock.
    unsafe { kernel::call_export(routine, a0, a1, a2, 0) }
}

/// HRESULT_FROM_WIN32 for positive codes; other values pass through.
const fn win32_result(code: u32) -> u32 {
    if code as i32 > 0 {
        0x8007_0000 | (code & 0xffff)
    } else {
        code
    }
}

fn current_thread_id() -> u32 {
    load(current_thread() + THREAD_ID)
}

/// An engine object.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Engine(u32);

impl Engine {
    pub(super) fn new(address: u32) -> Option<Self> {
        (address != 0).then_some(Self(address))
    }

    pub(super) fn address(self) -> u32 {
        self.0
    }

    fn field(self, offset: u32) -> u32 {
        self.0.wrapping_add(offset)
    }

    fn get(self, offset: u32) -> u32 {
        load(self.field(offset))
    }

    fn set(self, offset: u32, value: u32) {
        store(self.field(offset), value);
    }

    fn pointer(self, offset: u32) -> *mut u32 {
        self.field(offset) as usize as *mut u32
    }

    fn count(self, offset: u32, ordering: Ordering) {
        // SAFETY: the counters are aligned words of the engine object.
        unsafe { AtomicU32::from_ptr(self.pointer(offset)) }.fetch_add(1, ordering);
    }

    /// The queue held by the cell at `offset`.
    fn queue(self, offset: u32) -> u32 {
        load(self.get(offset))
    }

    fn set_event(self, offset: u32) {
        kernel::KeSetEvent(self.get(offset) as usize as *mut u32, 1, 0);
    }

    fn worker_running(self) -> bool {
        current_thread_id() == self.get(WORKER_ID)
    }

    /// A free entry, or nothing (the record is dropped).
    fn take_free(self) -> Option<u32> {
        let mut entry = 0u32;
        let status = queue::dequeue(self.queue(FREE), &raw mut entry as usize as u32);
        ((status as i32) >= 0 && entry != 0).then_some(entry)
    }

    fn append(self, entry: u32) {
        if (queue::enqueue(self.queue(PENDING), entry) as i32) < 0 {
            self.count(DROPPED, Ordering::Relaxed);
        }
    }
}

/// Allocator routines of the caller options: +0x28 allocate(context, size),
/// +0x2c free(context, address), +0x30 their context.
#[derive(Clone, Copy)]
struct CallerAllocator {
    allocate: u32,
    free: u32,
    context: u32,
}

impl CallerAllocator {
    fn of(options: u32) -> Option<Self> {
        if options == 0 || load(options + 0x28) == 0 {
            return None;
        }
        Some(Self {
            allocate: load(options + 0x28),
            free: load(options + 0x2c),
            context: load(options + 0x30),
        })
    }
}

fn allocate(allocator: Option<CallerAllocator>, size: u32) -> u32 {
    match allocator {
        Some(allocator) => call(allocator.allocate, allocator.context, size, 0),
        None => lockfree::allocate(size),
    }
}

/// Engine parameters of the create exports.
struct Request {
    processor: u32,
    /// File-name mode: the name, or null for the default name.
    name: u32,
    context: u32,
    callback: u32,
    entry_size: u32,
    entries: u32,
    block: bool,
    options: u32,
}

/// Create an engine and store it through `output` (stock 0x91f79470).
/// Returns the worker creation status or the failure.
fn create(request: &Request, output: u32) -> u32 {
    if output == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    store(output, 0);
    match create_engine(request) {
        Ok((engine, status)) => {
            store(output, engine.0);
            status
        }
        Err(status) => status,
    }
}

fn create_engine(request: &Request) -> Result<(Engine, u32), u32> {
    let processor = if request.processor > DEFAULT_PROCESSOR {
        DEFAULT_PROCESSOR
    } else {
        request.processor
    };
    let entry_size = if request.entry_size == 0 {
        DEFAULT_ENTRY_SIZE
    } else {
        request.entry_size
    };
    let entries = if request.entries == 0 {
        DEFAULT_ENTRIES
    } else {
        request.entries
    };
    // Stock sizes the object without an overflow check and then queues
    // entries beyond a wrapped allocation; an overflowing size is refused.
    let size = entry_size
        .checked_mul(entries)
        .and_then(|size| size.checked_add(ENTRIES));
    let allocator = CallerAllocator::of(request.options);
    let Some(engine) = size.and_then(|size| Engine::new(allocate(allocator, size))) else {
        return Err(Hresult::OUT_OF_MEMORY.0);
    };
    // SAFETY: the header lies inside the new allocation.
    unsafe { core::ptr::write_bytes(engine.0 as usize as *mut u8, 0, ENTRIES as usize) };
    if let Some(allocator) = allocator {
        engine.set(FREE_ROUTINE, allocator.free);
        engine.set(FREE_CONTEXT, allocator.context);
    }
    if request.callback == 0 {
        let name = if request.name == 0 {
            DEFAULT_NAME.as_ptr() as usize as u32
        } else {
            request.name
        };
        copy_name(engine.field(NAME), name);
    }
    engine.set(CONTEXT, request.context);
    engine.set(ENTRY_SIZE, entry_size);
    engine.set(FILE, NO_FILE);
    engine.set(CALLBACK, request.callback);
    engine.set(QUIT, initialize_event(engine.field(QUIT_EVENT)));
    engine.set(DONE, initialize_event(engine.field(DONE_EVENT)));
    let built = build(engine, request, entry_size, entries, processor);
    if built.is_err() {
        destroy(engine);
    }
    built.map(|status| (engine, status))
}

/// Queues, free entries and worker of a new engine; the worker creation
/// status.
fn build(
    engine: Engine,
    request: &Request,
    entry_size: u32,
    entries: u32,
    processor: u32,
) -> Result<u32, u32> {
    let capacity = entries.wrapping_add(1);
    let mut pending = descriptor(request.options, capacity);
    pending[0] |= REMOVE_WAITS | if request.block { INSERT_WAITS } else { 0 };
    pending[2] = engine.field(QUIT);
    pending[4] = NO_LIMIT;
    pending[6] = wait_for_item_or_quit as *const () as usize as u32;
    create_queue(engine, PENDING, request.options, &mut pending)?;
    let mut free = descriptor(request.options, capacity);
    if request.block {
        free[4] = NO_LIMIT;
        free[3] = NO_LIMIT;
        free[0] |= INSERT_WAITS | REMOVE_WAITS;
    }
    create_queue(engine, FREE, request.options, &mut free)?;
    let mut entry = engine.field(ENTRIES);
    for _ in 0..(entries as i32).max(0) {
        let status = queue::enqueue(engine.queue(FREE), entry);
        if (status as i32) < 0 {
            return Err(status);
        }
        entry = entry.wrapping_add(entry_size);
    }
    let system = request.callback == 0
        || u32::from(read_u8(current_thread() + THREAD_PROCESS_TYPE)) != TITLE_PROCESS;
    let flags =
        ((1 << processor) << 24) | WORKER_FLAGS | if system { THREAD_SYSTEM_PROCESS } else { 0 };
    let status = kernel::ExCreateThread(
        engine.pointer(WORKER),
        WORKER_STACK,
        engine.pointer(WORKER_ID),
        0,
        worker as *const () as usize as u32,
        engine.0,
        flags,
    );
    if (status as i32) < 0 {
        Err(status)
    } else {
        Ok(status)
    }
}

/// Queue descriptor seeded from the caller options, with the node count
/// of `capacity`.
fn descriptor(options: u32, capacity: u32) -> [u32; DESCRIPTOR_WORDS] {
    let mut descriptor = [0u32; DESCRIPTOR_WORDS];
    if options != 0 {
        // SAFETY: the caller passes a descriptor-sized options block.
        unsafe {
            core::ptr::copy_nonoverlapping(
                options as usize as *const u32,
                descriptor.as_mut_ptr(),
                DESCRIPTOR_WORDS,
            );
        }
    }
    descriptor[8] = capacity;
    descriptor[9] = capacity;
    descriptor
}

/// Create the queue whose cell the engine keeps at `offset`.
fn create_queue(
    engine: Engine,
    offset: u32,
    options: u32,
    descriptor: &mut [u32; DESCRIPTOR_WORDS],
) -> Result<(), u32> {
    // Stock stores through a null cell from a caller allocator; it counts
    // as an allocation failure here.
    let cell = allocate(CallerAllocator::of(options), 4);
    if cell != 0 {
        store(cell, 0);
    }
    engine.set(offset, cell);
    if cell == 0 {
        return Err(Hresult::OUT_OF_MEMORY.0);
    }
    descriptor[7] = DESCRIPTOR_SIZE;
    let status = queue::create_export(descriptor.as_ptr() as usize as u32, cell);
    if (status as i32) < 0 {
        Err(status)
    } else {
        Ok(())
    }
}

/// Copy the file name. Stock copies without a limit over the following
/// fields; the copy here ends at the field.
fn copy_name(destination: u32, name: u32) {
    let mut offset = 0;
    while offset < NAME_CAPACITY - 1 {
        // SAFETY: the name is a caller string, as in stock.
        let byte = unsafe { core::ptr::read_volatile((name + offset) as usize as *const u8) };
        if byte == 0 {
            break;
        }
        // SAFETY: the name field lies inside the engine header.
        unsafe { core::ptr::write_volatile((destination + offset) as usize as *mut u8, byte) };
        offset += 1;
    }
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile((destination + offset) as usize as *mut u8, 0) };
}

/// Initialize an unsignaled notification event; returns its address.
fn initialize_event(event: u32) -> u32 {
    store(event, 0);
    store(event + 4, 0);
    store(event + 8, event + 8);
    store(event + 0xc, event + 8);
    event
}

/// Pending-queue wait routine (stock 0x91f82f80): wait for an item or for
/// the quit event in the cell at `context`. Wait index 1 is the quit event.
extern "C" fn wait_for_item_or_quit(
    context: u32,
    semaphore: u32,
    timeout: u32,
    alertable: u32,
) -> u32 {
    if timeout == 0 {
        return STATUS_TIMEOUT;
    }
    let interval = -(i64::from(timeout) * 10_000);
    let pointer = if timeout == NO_LIMIT {
        core::ptr::null()
    } else {
        &raw const interval
    };
    let objects = [semaphore, load(context)];
    let mut wait_blocks = [0u32; 16];
    kernel::KeWaitForMultipleObjects(
        2,
        objects.as_ptr(),
        WAIT_ANY,
        WAIT_USER_REQUEST,
        KERNEL_MODE,
        alertable & 0xff,
        pointer,
        wait_blocks.as_mut_ptr(),
    )
}

/// Worker thread (stock 0x91f78d48).
extern "C" fn worker(engine: u32) -> u32 {
    let code = run(Engine(engine));
    kernel::ExTerminateThread(code);
    code
}

fn run(engine: Engine) -> u32 {
    if engine.get(PENDING) == 0 {
        return WORKER_FAILED;
    }
    if engine.get(QUIT) == 0 || engine.get(DONE) == 0 {
        engine.set(STATUS, Hresult::INVALID_ARGUMENT.0);
        return WORKER_FAILED;
    }
    if engine.get(CALLBACK) == 0 {
        let file = CreateFileA(
            engine.field(NAME),
            GENERIC_WRITE,
            0,
            0,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        engine.set(FILE, file);
        if file == NO_FILE {
            engine.set(STATUS, STATUS_OBJECT_NAME_INVALID);
            return WORKER_FAILED;
        }
    }
    // Until the quit event, a failed delivery ends the worker without
    // signaling the done event.
    loop {
        let mut entry = 0u32;
        let status = queue::dequeue(engine.queue(PENDING), &raw mut entry as usize as u32);
        if (status as i32) < 0 {
            if status == QUIT_REQUESTED {
                break;
            }
            engine.count(MISSED, Ordering::Release);
            continue;
        }
        if let Err(status) = deliver(engine, entry) {
            engine.set(STATUS, status);
            return WORKER_FAILED;
        }
        if (queue::enqueue(engine.queue(FREE), entry) as i32) < 0 {
            engine.set(STATUS, Hresult::FAIL.0);
            engine.set_event(DONE);
            return WORKER_FAILED;
        }
    }
    loop {
        let pending = engine.queue(PENDING);
        if pending == 0 || queue::is_empty(pending) != 0 {
            write_summary(engine);
            engine.set_event(DONE);
            return 0;
        }
        let mut entry = 0u32;
        if (queue::dequeue(pending, &raw mut entry as usize as u32) as i32) < 0 || entry == 0 {
            continue;
        }
        if let Err(status) = deliver(engine, entry) {
            engine.set(STATUS, status);
            engine.set_event(DONE);
            return WORKER_FAILED;
        }
        if (queue::enqueue(engine.queue(FREE), entry) as i32) < 0 {
            engine.set(STATUS, Hresult::FAIL.0);
            write_summary(engine);
            engine.set_event(DONE);
            return WORKER_FAILED;
        }
    }
}

/// Hand an entry to the callback, or write its text to the file.
fn deliver(engine: Engine, entry: u32) -> Result<(), u32> {
    let callback = engine.get(CALLBACK);
    let entry_size = engine.get(ENTRY_SIZE);
    if callback != 0 {
        let status = call(callback, engine.get(CONTEXT), entry, entry_size);
        return if (status as i32) < 0 {
            Err(status)
        } else {
            Ok(())
        };
    }
    // Stock's strlen runs on into the following entries when the entry
    // holds no NUL; the text here ends with the entry.
    // SAFETY: the entry lies inside the engine object.
    let bytes =
        unsafe { core::slice::from_raw_parts(entry as usize as *const u8, entry_size as usize) };
    let length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    if write_file(engine.get(FILE), &bytes[..length]) {
        Ok(())
    } else {
        Err(win32_result(kernel::last_error()))
    }
}

/// `TERMINATING LOG` line and file close of file-name mode (stock
/// 0x91f78c78).
fn write_summary(engine: Engine) {
    let file = engine.get(FILE);
    if file == NO_FILE {
        return;
    }
    let mut text = Text::<0x60>::new();
    let _ = writeln!(
        text,
        "TERMINATING LOG: Dropped messages = {}, Missed Messages = {}",
        engine.get(DROPPED) as i32,
        engine.get(MISSED) as i32
    );
    write_file(file, text.as_bytes());
    close_handle(file);
    engine.set(FILE, NO_FILE);
}

/// `WriteFile` without overlapped I/O (stock 0x91f73af8); a failure
/// records the thread's last error.
fn write_file(file: u32, bytes: &[u8]) -> bool {
    let mut io_status = IoStatusBlock::default();
    let mut status = kernel::NtWriteFile(
        file,
        0,
        0,
        0,
        &mut io_status,
        bytes.as_ptr(),
        bytes.len() as u32,
        core::ptr::null(),
    );
    if status == STATUS_PENDING {
        status = kernel::NtWaitForSingleObjectEx(file, USER_MODE, 0, core::ptr::null());
        if (status as i32) >= 0 {
            status = io_status.status;
        }
    }
    if (status as i32) < 0 {
        kernel::set_last_error(status);
        return false;
    }
    true
}

/// `CloseHandle` (stock 0x91f738f8).
fn close_handle(handle: u32) {
    let status = kernel::NtClose(handle);
    if (status as i32) < 0 {
        kernel::set_last_error(status);
    }
}

/// Free the queues, the worker handle and the object (stock 0x91f79320).
fn destroy(engine: Engine) {
    let free_routine = engine.get(FREE_ROUTINE);
    for offset in [PENDING, FREE] {
        let cell = engine.get(offset);
        if cell == 0 {
            continue;
        }
        let queue = load(cell);
        if queue != 0 {
            queue::destroy(queue);
            store(cell, 0);
        }
        release(engine, free_routine, cell);
        engine.set(offset, 0);
    }
    // The events need no cleanup.
    engine.set(QUIT, 0);
    engine.set(DONE, 0);
    let worker = engine.get(WORKER);
    if worker != 0 {
        close_handle(worker);
        engine.set(WORKER, 0);
    }
    release(engine, free_routine, engine.0);
}

fn release(engine: Engine, free_routine: u32, address: u32) {
    if free_routine == 0 {
        lockfree::free(address);
    } else {
        call(free_routine, engine.get(FREE_CONTEXT), address, 0);
    }
}

/// Engine of `dmtelllog`: processor 5 and `callback(context, entry,
/// entry_size)`, as stock creates it through export 356. Returns the engine
/// and the worker creation status.
pub(super) fn create_for_callback(
    context: u32,
    callback: u32,
    config: TellLogConfig,
) -> Result<(Engine, Hresult), Hresult> {
    let request = Request {
        processor: DEFAULT_PROCESSOR,
        name: 0,
        context,
        callback,
        entry_size: config.entry_size,
        entries: config.entries,
        block: config.block,
        options: 0,
    };
    let mut output = 0u32;
    let status = create(&request, &raw mut output as usize as u32);
    match Engine::new(output) {
        Some(engine) => Ok((engine, Hresult(status))),
        None => Err(Hresult(status)),
    }
}

/// Stop the worker once the queued entries are processed and destroy the
/// engine. Export 360 waits for the done event, which a worker ended by a
/// callback failure never signals; this waits for the worker thread.
pub(super) fn close_after_worker(engine: Engine) {
    engine.set_event(QUIT);
    kernel::NtWaitForSingleObjectEx(engine.get(WORKER), KERNEL_MODE, 0, core::ptr::null());
    kernel::sleep_milliseconds(1);
    destroy(engine);
}

/// Thread id of the worker.
pub(super) fn worker_id(engine: Engine) -> u32 {
    engine.get(WORKER_ID)
}

/// Copy up to an entry of `length` bytes at `data` into a free entry and
/// queue it (export 363). Records of the worker thread itself are ignored.
pub(super) fn write(engine: Engine, data: u32, length: u32) {
    if data == 0 || engine.worker_running() {
        return;
    }
    let Some(entry) = engine.take_free() else {
        engine.count(DROPPED, Ordering::Relaxed);
        return;
    };
    let length = length.min(engine.get(ENTRY_SIZE));
    // SAFETY: the record is caller memory and the entry belongs to this
    // producer until it is queued.
    unsafe {
        core::ptr::copy_nonoverlapping(
            data as usize as *const u8,
            entry as usize as *mut u8,
            length as usize,
        )
    };
    engine.append(entry);
}

pub(super) fn counters(engine: Engine) -> TellLogCounters {
    TellLogCounters {
        dropped: engine.get(DROPPED),
        missed: engine.get(MISSED),
    }
}

/// Format into a free entry and queue it (stock 0x91f79060 without and
/// 0x91f79160 with the worker check). Stock formats with the kernel's
/// `vsprintf` without a limit; text that does not fit the entry is cut to
/// it here.
fn print(engine: Engine, format: u32, arguments: u32) {
    let Some(entry) = engine.take_free() else {
        engine.count(DROPPED, Ordering::Relaxed);
        return;
    };
    let entry_size = engine.get(ENTRY_SIZE);
    let length = kernel::_vsnprintf(entry as usize as *mut u8, entry_size, format, arguments);
    if length < 0 || length as u32 >= entry_size {
        store_byte(entry + entry_size - 1, 0);
    }
    engine.append(entry);
}

fn store_byte(address: u32, value: u8) {
    // SAFETY: the byte lies inside an entry this producer owns.
    unsafe { core::ptr::write_volatile(address as usize as *mut u8, value) }
}

extern "C" fn create_file_log(
    processor: u32,
    name: u32,
    entry_size: u32,
    entries: u32,
    block: u32,
    output: u32,
) -> u32 {
    let request = Request {
        processor,
        name,
        context: 0,
        callback: 0,
        entry_size,
        entries,
        block: block != 0,
        options: 0,
    };
    create(&request, output)
}
export!(355, create_file_log);

extern "C" fn create_callback_log(
    processor: u32,
    context: u32,
    callback: u32,
    entry_size: u32,
    entries: u32,
    block: u32,
    output: u32,
) -> u32 {
    let request = Request {
        processor,
        name: 0,
        context,
        callback,
        entry_size,
        entries,
        block: block != 0,
        options: 0,
    };
    create(&request, output)
}
export!(356, create_callback_log);

extern "C" fn create_file_log_with_options(
    processor: u32,
    name: u32,
    entry_size: u32,
    entries: u32,
    block: u32,
    options: u32,
    output: u32,
) -> u32 {
    let request = Request {
        processor,
        name,
        context: 0,
        callback: 0,
        entry_size,
        entries,
        block: block != 0,
        options,
    };
    create(&request, output)
}
export!(357, create_file_log_with_options);

#[allow(clippy::too_many_arguments)]
extern "C" fn create_callback_log_with_options(
    processor: u32,
    context: u32,
    callback: u32,
    entry_size: u32,
    entries: u32,
    block: u32,
    options: u32,
    output: u32,
) -> u32 {
    let request = Request {
        processor,
        name: 0,
        context,
        callback,
        entry_size,
        entries,
        block: block != 0,
        options,
    };
    create(&request, output)
}
export!(358, create_callback_log_with_options);

/// Stop the worker once the queued entries are processed, wait for the
/// done event and destroy the engine (stock 0x91f79998).
extern "C" fn close(engine: u32) {
    let Some(engine) = Engine::new(engine) else {
        return;
    };
    engine.set_event(QUIT);
    let done = engine.get(DONE) as usize as *mut u32;
    if kernel::KeWaitForSingleObject(done, WAIT_USER_REQUEST, KERNEL_MODE, 0, core::ptr::null())
        != 0
    {
        return;
    }
    kernel::sleep_milliseconds(1);
    destroy(engine);
}
export!(360, close);

/// `(engine, format, va_list)` of export 361 (stock 0x91f79060).
extern "C" fn print_arguments(engine: u32, format: u32, arguments: u32) {
    if let Some(engine) = Engine::new(engine) {
        print(engine, format, arguments);
    }
}

/// Export 361 `(engine, format, ...)`: store r5-r10 in the caller's home
/// slots (sp+0x20..sp+0x48), which precede the stack arguments, and pass
/// their address as the va_list.
#[unsafe(naked)]
unsafe extern "C" fn print_entry() {
    core::arch::naked_asm!(
        ".irp reg, 5,6,7,8,9,10",
        // std \reg, 0x10 + 8 * (\reg - 3)(r1)
        ".long (62 << 26) | (\\reg << 21) | (1 << 16) | (8 * \\reg - 8)",
        ".endr",
        "addi 5, 1, 0x20",
        "lis 12, {target}@ha",
        "addi 12, 12, {target}@l",
        "b {bridge}",
        target = sym print_arguments,
        bridge = sym crate::exports::export_bridge,
    )
}
export_raw!(361, print_entry);

/// Export 362 `(engine, format, va_list)` (stock 0x91f79160).
extern "C" fn print_list(engine: u32, format: u32, arguments: u32) {
    let Some(engine) = Engine::new(engine) else {
        return;
    };
    if !engine.worker_running() {
        print(engine, format, arguments);
    }
}
export!(362, print_list);

extern "C" fn write_export(engine: u32, data: u32, length: u32) {
    if let Some(engine) = Engine::new(engine) {
        write(engine, data, length);
    }
}
export!(363, write_export);

extern "C" fn counters_export(engine: u32, dropped: u32, missed: u32) {
    let Some(engine) = Engine::new(engine) else {
        return;
    };
    if dropped != 0 {
        store(dropped, engine.get(DROPPED));
    }
    if missed != 0 {
        store(missed, engine.get(MISSED));
    }
}
export!(364, counters_export);
