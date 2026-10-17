//! Notification sessions (stock dmnotify, exports 6, 24, 25, 32 and 36):
//! handlers that system software and titles register for monitor
//! notification kinds, and named text processors. Sessions are pool blocks
//! in the monitor's layout, linked from a list under a reader-writer spin
//! lock held at DISPATCH_LEVEL (stock 0x91fadc00, lock 0x91fadc08).

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands::memory::is_device_address;
use openxbdm_server::commands::session::compare_names;
use openxbdm_server::commands::session::notification_kind_length;
use openxbdm_server::notify::DataAccess;
use openxbdm_server::notify::Event;
use openxbdm_server::notify::ExceptionDetail;
use xbox360_sys::processor;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::PoolTag;

use super::THREAD_ID;
use super::TITLE_PROCESS;
use super::c_string;
use super::passive;
use super::post_notification;
use super::read_u32;
use super::swap;
use super::write_u32;
use crate::backend::debugger::execution_code;
use crate::backend::debugger::execution_state;
use crate::exports::export;
use crate::kernel;

export!(6, close_notification_session);
export!(24, register_notification_handler);
export!(25, open_notification_session);
export!(32, register_notification_processor);
export!(36, send_notification);

/// Session block: +0x0 tag, +0x4 next session, +0x8 flags, +0xc handler
/// lists (0x20 per kind, kinds 1..=0x16), +0xb08 + 4 * kind handler
/// counts, +0xb64 processors.
const SESSION_TAG: u32 = 0x786e_6f74;
const SESSION_POOL_TAG: PoolTag = PoolTag::new(*b"snmd");
const SESSION_SIZE: u32 = 0xba4;
const SESSION_NEXT: u32 = 0x4;
const SESSION_FLAGS: u32 = 0x8;
const SESSION_HANDLERS: u32 = 0xc;
const SESSION_COUNTS: u32 = 0xb08;
const SESSION_PROCESSORS: u32 = 0xb64;
const HANDLER_SLOTS: u32 = 0x20;
const PROCESSOR_SLOTS: u32 = 0x10;
const LAST_KIND: u32 = 0x16;
/// Opened by a title process; unlinked when the title ends.
const SESSION_TITLE: u32 = 0x1_0000;
/// Processor block: a name of at most 0x3f characters, then the handler.
const PROCESSOR_POOL_TAG: PoolTag = PoolTag::new(*b"hcmd");
const PROCESSOR_SIZE: u32 = 0x44;
const PROCESSOR_NAME_LIMIT: usize = 0x3f;
const PROCESSOR_HANDLER: u32 = 0x40;
const KIND_MASK: u32 = 0xff_ffff;
const KIND_EXECUTION: u32 = 3;
/// Handlers of this kind get the notification data 4 bytes in.
const KIND_MODULE_LOAD: u32 = 5;
/// The kernel calls the routine stored through debug monitor data +0x10
/// while kind 0xa has handlers [purpose of the kernel call unknown].
const KIND_KERNEL_CALLBACK: u32 = 0xa;
const KIND_THREAD_SWITCH: u32 = 0xf;
const ASSERT_PASSIVE: &core::ffi::CStr = c"KeGetCurrentIrql() == PASSIVE_LEVEL";
const ASSERT_FILE: &core::ffi::CStr =
    c"e:\\xenon\\xdksep13\\core\\private\\xdk\\tools\\debug\\xbdm\\core\\dmnotify.c";

/// Head of the session list.
static SESSIONS: AtomicU32 = AtomicU32::new(0);
static LOCK: ListLock = ListLock(AtomicU32::new(0));
/// The thread switch routine is in the swap chain.
static THREAD_SWITCH_HOOKED: AtomicBool = AtomicBool::new(false);

/// Reader-writer spin lock (stock words 0x91f23230 shared, 0x91f232bc
/// exclusive, 0x91f23278/0x91f23304 release) taken at DISPATCH_LEVEL
/// (stock 0x91f54e88, 0x91f54f10). A waiting writer keeps new readers out
/// until a writer releases the lock.
struct ListLock(AtomicU32);

const WRITER_WAITING: u32 = 0x2;
const WRITER: u32 = 0x4;
const READER: u32 = 0x8;

impl ListLock {
    fn shared(&self) -> ListGuard<'_> {
        // SAFETY: the guard lowers the IRQL back to `irql` on drop.
        let irql = unsafe { xboxkrnl::KfRaiseIrql(Irql::DISPATCH) };
        loop {
            let state = self.0.load(Ordering::Relaxed);
            if state & (WRITER | WRITER_WAITING) == 0
                && self
                    .0
                    .compare_exchange_weak(
                        state,
                        state + READER,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                return ListGuard {
                    lock: self,
                    irql,
                    exclusive: false,
                };
            }
            core::hint::spin_loop();
        }
    }

    fn exclusive(&self) -> ListGuard<'_> {
        // SAFETY: the guard lowers the IRQL back to `irql` on drop.
        let irql = unsafe { xboxkrnl::KfRaiseIrql(Irql::DISPATCH) };
        loop {
            let state = self.0.load(Ordering::Relaxed);
            if state & !WRITER_WAITING == 0 {
                if self
                    .0
                    .compare_exchange_weak(state, WRITER, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return ListGuard {
                        lock: self,
                        irql,
                        exclusive: true,
                    };
                }
            } else if state & WRITER_WAITING == 0 {
                self.0.fetch_or(WRITER_WAITING, Ordering::Relaxed);
            }
            core::hint::spin_loop();
        }
    }
}

struct ListGuard<'a> {
    lock: &'a ListLock,
    irql: Irql,
    exclusive: bool,
}

impl Drop for ListGuard<'_> {
    fn drop(&mut self) {
        if self.exclusive {
            // Stock clears the whole word, including another writer's wait.
            self.lock.0.store(0, Ordering::Release);
        } else {
            self.lock.0.fetch_sub(READER, Ordering::Release);
        }
        // SAFETY: `irql` is the level the guard raised from.
        unsafe { xboxkrnl::KfLowerIrql(self.irql) };
    }
}

/// `RtlAssert` as stock reports a call above passive level.
fn assert_passive(line: u32) {
    if !passive() {
        // SAFETY: the message and file name are static NUL-terminated strings.
        unsafe {
            xboxkrnl::RtlAssert(
                ASSERT_PASSIVE.as_ptr().cast(),
                ASSERT_FILE.as_ptr().cast(),
                line,
                core::ptr::null(),
            )
        };
    }
}

fn is_session(session: u32) -> bool {
    session != 0 && read_u32(session) == SESSION_TAG
}

fn sessions() -> impl Iterator<Item = u32> {
    let mut next = SESSIONS.load(Ordering::Acquire);
    core::iter::from_fn(move || {
        let session = next;
        if session == 0 {
            return None;
        }
        next = read_u32(session + SESSION_NEXT);
        Some(session)
    })
}

fn count_address(session: u32, kind: u32) -> u32 {
    session + SESSION_COUNTS + 4 * kind
}

fn handler_address(session: u32, kind: u32, index: u32) -> u32 {
    session + SESSION_HANDLERS + (kind - 1) * HANDLER_SLOTS * 4 + index * 4
}

/// Unlink every session for which `remove` holds; returns them through
/// `removed`. Called with the lock held exclusively.
fn unlink_sessions(mut remove: impl FnMut(u32) -> bool, mut removed: impl FnMut(u32)) {
    // The word that links the current session: the head, then a session's
    // next field.
    let mut link = &SESSIONS;
    loop {
        let current = link.load(Ordering::Relaxed);
        if current == 0 {
            return;
        }
        if remove(current) {
            link.store(read_u32(current + SESSION_NEXT), Ordering::Release);
            removed(current);
        } else {
            // SAFETY: an aligned word of a linked session block.
            link = unsafe { AtomicU32::from_ptr((current + SESSION_NEXT) as usize as *mut u32) };
        }
    }
}

/// Export 25 (stock 0x91f3acc0): open a session with `flags`; sessions of
/// title processes are marked to go with the title.
extern "C" fn open_notification_session(flags: u32, session: *mut u32) -> u32 {
    if session.is_null() {
        return Hresult::INVALID_ARGUMENT.0;
    }
    assert_passive(0xbf9);
    let flags = if xboxkrnl::KeGetCurrentProcessType().0 == TITLE_PROCESS {
        flags | SESSION_TITLE
    } else {
        flags
    };
    // SAFETY: the allocation takes only a size and tag.
    let block = unsafe { xboxkrnl::ExAllocatePoolWithTag(SESSION_SIZE, SESSION_POOL_TAG) };
    // SAFETY: the caller passes a writable handle location.
    unsafe { session.write_unaligned(block) };
    if block == 0 {
        return Hresult::OUT_OF_MEMORY.0;
    }
    let _guard = LOCK.exclusive();
    // SAFETY: the pool block is SESSION_SIZE bytes and not yet shared.
    unsafe { core::ptr::write_bytes(block as usize as *mut u8, 0, SESSION_SIZE as usize) };
    write_u32(block + SESSION_FLAGS, flags);
    write_u32(block, SESSION_TAG);
    write_u32(block + SESSION_NEXT, SESSIONS.load(Ordering::Relaxed));
    SESSIONS.store(block, Ordering::Release);
    Hresult::OK.0
}

/// Export 6 (stock 0x91f3adb8): unlink and free a session. A readable
/// session block that is not linked is left alone. Kernel hooks keep their
/// state until the next registration change.
extern "C" fn close_notification_session(session: u32) -> u32 {
    let readable = session != 0 && {
        // SAFETY: the check only translates the address.
        let mapped = unsafe { xboxkrnl::MmDbgReadCheck(session) };
        mapped != 0 && !is_device_address(mapped)
    };
    if !readable || read_u32(session) != SESSION_TAG {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let _guard = LOCK.exclusive();
    unlink_sessions(
        |candidate| candidate == session,
        |removed| {
            // SAFETY: the unlinked session is a pool block of this module.
            unsafe { xboxkrnl::ExFreePool(removed) };
        },
    );
    Hresult::OK.0
}

/// Export 24 (stock 0x91f3ca48): add `handler` for notification `kind`
/// (1..=0x16, at most 0x20 per kind; a handler already present or a full
/// list is ignored). A new kind-3 handler is called at once with the
/// execution state. Kind 0 with no handler clears every list.
///
/// Kind 0 with a handler: stock removes it from the kind-1 list and then
/// repeats the removal forever with the lock held. openxbdm removes it
/// once and returns.
extern "C" fn register_notification_handler(session: u32, kind: u32, handler: u32) -> u32 {
    if !is_session(session) {
        return Hresult::INVALID_ARGUMENT.0;
    }
    assert_passive(0xc5c);
    let kind = kind & KIND_MASK;
    let _guard = LOCK.exclusive();
    if kind == 0 {
        if handler == 0 {
            for kind in 1..LAST_KIND + 1 {
                write_u32(count_address(session, kind), 0);
                refresh_kernel_hooks(kind);
            }
        } else {
            remove_handler(session, 1, handler);
            refresh_kernel_hooks(1);
        }
        return Hresult::OK.0;
    }
    if kind > LAST_KIND || handler == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let count = read_u32(count_address(session, kind));
    let present =
        (0..count).any(|index| read_u32(handler_address(session, kind, index)) == handler);
    if !present && count != HANDLER_SLOTS {
        write_u32(handler_address(session, kind, count), handler);
        write_u32(count_address(session, kind), count + 1);
        refresh_kernel_hooks(kind);
        if kind == KIND_EXECUTION {
            call_handler(handler, KIND_EXECUTION, execution_code(execution_state()));
        }
    }
    Hresult::OK.0
}

/// Remove every copy of `handler` from the list of `kind`, moving the last
/// entry into each freed place.
fn remove_handler(session: u32, kind: u32, handler: u32) {
    let mut index = 0;
    while index < read_u32(count_address(session, kind)) {
        if read_u32(handler_address(session, kind, index)) == handler {
            let last = read_u32(count_address(session, kind)) - 1;
            write_u32(count_address(session, kind), last);
            write_u32(
                handler_address(session, kind, index),
                read_u32(handler_address(session, kind, last)),
            );
        } else {
            index += 1;
        }
    }
}

fn call_handler(handler: u32, kind: u32, data: u32) {
    // SAFETY: registrants pass console `void (*)(DWORD kind, void *data)`
    // routines.
    unsafe { kernel::call_export(handler, kind, data, 0, 0) };
}

/// Install or remove the kernel hooks of `kind` by whether any session
/// has handlers for it (stock 0x91f3c8c8). Called with the lock held.
fn refresh_kernel_hooks(kind: u32) {
    let wanted = || sessions().any(|session| read_u32(count_address(session, kind)) != 0);
    match kind {
        KIND_KERNEL_CALLBACK => {
            let slot = kernel::debug_monitor_data()
                .callback_routine
                .load(Ordering::Relaxed);
            if slot != 0 {
                let routine = if wanted() {
                    kernel_callback_entry as *const () as usize as u32
                } else {
                    0
                };
                write_u32(slot, routine);
            }
        }
        KIND_THREAD_SWITCH => {
            let hooked = THREAD_SWITCH_HOOKED.load(Ordering::Relaxed);
            if wanted() {
                if !hooked {
                    swap::register_swap_routine(thread_switched as *const () as usize as u32, 1);
                    THREAD_SWITCH_HOOKED.store(true, Ordering::Relaxed);
                }
            } else if hooked {
                swap::unregister_swap_routine(thread_switched as *const () as usize as u32);
                THREAD_SWITCH_HOOKED.store(false, Ordering::Relaxed);
            }
        }
        _ => {}
    }
}

/// Kernel callback of kind 0xa (stock 0x91f3b1c0); like the delivery
/// routine it tail-calls, it returns 0.
extern "C" fn kernel_callback() -> u32 {
    notify_sessions(KIND_KERNEL_CALLBACK, 0);
    0
}
crate::exports::bridged!(kernel_callback_entry, kernel_callback);

/// Swap routine of kind 0xf (stock 0x91f3b1d0): handlers get the thread
/// identifiers of the outgoing and the incoming thread.
extern "C" fn thread_switched(old: u32, _frame: u32, new: u32) -> u32 {
    let threads = [read_u32(old + THREAD_ID), read_u32(new + THREAD_ID)];
    notify_sessions(KIND_THREAD_SWITCH, threads.as_ptr() as usize as u32);
    0
}

/// Run every session handler of `kind & 0xffffff`, newest first, with
/// `kind` and `data` (stock 0x91f395c0); module-load handlers get `data`
/// 4 bytes in. Nothing runs above DISPATCH_LEVEL.
fn notify_sessions(kind: u32, data: u32) {
    let data = if kind == KIND_MODULE_LOAD {
        data + 4
    } else {
        data
    };
    if processor::current_irql() > Irql::DISPATCH {
        return;
    }
    let list = kind & KIND_MASK;
    let _guard = LOCK.shared();
    for session in sessions() {
        let mut index = read_u32(count_address(session, list));
        while index != 0 {
            index -= 1;
            call_handler(read_u32(handler_address(session, list, index)), kind, data);
        }
    }
}

/// Notification kinds of the stock event structures.
const KIND_BREAK: u32 = 1;
const KIND_DEBUG_STRING: u32 = 2;
const KIND_SINGLE_STEP: u32 = 4;
const KIND_MODULE_UNLOAD: u32 = 6;
const KIND_THREAD_CREATE: u32 = 7;
const KIND_THREAD_TERMINATE: u32 = 8;
const KIND_EXCEPTION: u32 = 9;
const KIND_ASSERT: u32 = 0xc;
const KIND_DATA: u32 = 0xd;
const KIND_RIP: u32 = 0xe;
const KIND_SECTION_LOAD: u32 = 0x10;
const KIND_SECTION_UNLOAD: u32 = 0x11;
const KIND_STACK_TRACE: u32 = 0x13;
const KIND_NT_ASSERT: u32 = 0x15;
const KIND_POGO_MODULE_STARTUP: u32 = 0x16;
/// Kind flag of an event after which the thread is stopped.
const KIND_STOPPED: u32 = 0x8000_0000;
const EXCEPTION_NONCONTINUABLE: u32 = 0x1;
const EXCEPTION_FIRST_CHANCE: u32 = 0x2;
const NAME_CAPACITY: usize = 0x104;

/// Module record of kinds 5 and 6 (stock 0x91f39fc0 fills them, formatter
/// 0x91f39080 reads them). Stock leaves the unload record's fields after
/// name, base, and size uninitialized; they are zero here.
#[repr(C)]
#[derive(Default)]
struct ModuleRecord {
    name: NameField,
    base: u32,
    size: u32,
    timestamp: u32,
    checksum: u32,
    flags: u32,
    pdata: u32,
    pdata_size: u32,
    thread: u32,
    image_size: u32,
}

/// Kind 5 data: the record length, then the module record. Handlers of
/// kind 5 get the module record, those of a stopping load the length.
#[repr(C)]
struct ModuleLoadRecord {
    length: u32,
    module: ModuleRecord,
}

const MODULE_LOAD_RECORD_LENGTH: u32 = 0x12c;
const _: () =
    assert!(core::mem::size_of::<ModuleLoadRecord>() == MODULE_LOAD_RECORD_LENGTH as usize);

/// A NUL-terminated name of the stock records.
#[repr(transparent)]
struct NameField([u8; NAME_CAPACITY]);

impl Default for NameField {
    fn default() -> Self {
        Self([0; NAME_CAPACITY])
    }
}

/// Section record of kinds 0x10 and 0x11.
#[repr(C)]
struct SectionRecord {
    name: NameField,
    base: u32,
    size: u32,
    index: u16,
    flags: u16,
}

/// `name` as a NUL-terminated field, cut to fit; shared by the records, so
/// not inlined.
#[inline(never)]
fn name_field(name: &[u8]) -> NameField {
    let mut field = NameField::default();
    let length = name.len().min(NAME_CAPACITY - 1);
    field.0[..length].copy_from_slice(&name[..length]);
    field
}

fn kind_of(kind: u32, stopped: bool) -> u32 {
    kind | (KIND_STOPPED * u32::from(stopped))
}

fn address_of<T>(value: &T) -> u32 {
    value as *const T as usize as u32
}

/// Run the session handlers of `event` with the monitor's structure for
/// its kind.
pub(crate) fn notify_event(event: &Event<'_>) {
    match *event {
        Event::Break {
            address,
            thread,
            stopped,
        } => {
            notify_sessions(kind_of(KIND_BREAK, stopped), address_of(&[address, thread]));
        }
        Event::SingleStep {
            address,
            thread,
            stopped,
        } => {
            notify_sessions(
                kind_of(KIND_SINGLE_STEP, stopped),
                address_of(&[address, thread]),
            );
        }
        Event::NtAssert {
            address,
            thread,
            stopped,
        } => {
            notify_sessions(
                kind_of(KIND_NT_ASSERT, stopped),
                address_of(&[address, thread]),
            );
        }
        Event::DebugString {
            thread,
            text,
            stopped,
        } => {
            let record = [thread, text.len() as u32, text.as_ptr() as usize as u32];
            notify_sessions(kind_of(KIND_DEBUG_STRING, stopped), address_of(&record));
        }
        Event::Execution(state) => notify_sessions(KIND_EXECUTION, execution_code(state)),
        Event::ExecutionStop(state) => {
            notify_sessions(KIND_EXECUTION | KIND_STOPPED, execution_code(state))
        }
        Event::ModuleLoad {
            module,
            thread,
            stopped,
        } => {
            let record = ModuleLoadRecord {
                length: MODULE_LOAD_RECORD_LENGTH,
                module: ModuleRecord {
                    name: name_field(&module.name[..module.name_length]),
                    base: module.base,
                    size: module.size,
                    timestamp: module.timestamp,
                    checksum: module.checksum,
                    flags: module.flags.bits(),
                    pdata: module.pdata,
                    pdata_size: module.pdata_size,
                    thread,
                    image_size: module.image_size,
                },
            };
            notify_sessions(kind_of(KIND_MODULE_LOAD, stopped), address_of(&record));
        }
        Event::ModuleUnload { name, base, size } => {
            let record = ModuleRecord {
                name: name_field(name.as_bytes()),
                base,
                size,
                ..ModuleRecord::default()
            };
            notify_sessions(KIND_MODULE_UNLOAD, address_of(&record));
        }
        Event::ThreadCreate {
            thread,
            start,
            stopped,
        } => {
            notify_sessions(
                kind_of(KIND_THREAD_CREATE, stopped),
                address_of(&[thread, start]),
            );
        }
        Event::ThreadTerminate { thread, stopped } => {
            notify_sessions(kind_of(KIND_THREAD_TERMINATE, stopped), thread)
        }
        Event::Exception {
            code,
            thread,
            address,
            detail,
            first_chance,
            noncontinuable,
            stopped,
        } => {
            let mut flags = 0;
            if first_chance {
                flags |= EXCEPTION_FIRST_CHANCE;
            }
            if noncontinuable {
                flags |= EXCEPTION_NONCONTINUABLE;
            }
            let (first, second) = match detail {
                ExceptionDetail::AccessViolation { write, address } => (u32::from(write), address),
                ExceptionDetail::Parameters { count, address } => (count, address),
            };
            let record = [thread, code, address, flags, first, second];
            notify_sessions(kind_of(KIND_EXCEPTION, stopped), address_of(&record));
        }
        Event::Assert {
            thread,
            string_address,
            string_length,
            stopped,
        } => {
            let record = [thread, string_length, string_address];
            notify_sessions(kind_of(KIND_ASSERT, stopped), address_of(&record));
        }
        Event::Data {
            access,
            value,
            address,
            thread,
            stopped,
        } => {
            let access = match access {
                DataAccess::Write => 1,
                DataAccess::Read => 2,
                DataAccess::Execute => 3,
            };
            notify_sessions(
                kind_of(KIND_DATA, stopped),
                address_of(&[address, thread, access, value]),
            );
        }
        Event::Rip {
            thread,
            text,
            stopped,
        } => notify_text(kind_of(KIND_RIP, stopped), thread, text),
        Event::StackTrace {
            thread,
            text,
            stopped,
        } => notify_text(kind_of(KIND_STACK_TRACE, stopped), thread, text),
        Event::SectionLoad {
            name,
            base,
            size,
            index,
            flags,
        }
        | Event::SectionUnload {
            name,
            base,
            size,
            index,
            flags,
        } => {
            let record = SectionRecord {
                name: name_field(name.as_bytes()),
                base,
                size,
                index: index as u16,
                flags: flags as u16,
            };
            let kind = if matches!(event, Event::SectionLoad { .. }) {
                KIND_SECTION_LOAD
            } else {
                KIND_SECTION_UNLOAD
            };
            notify_sessions(kind, address_of(&record));
        }
        Event::PogoModuleStartup {
            name,
            module,
            thread,
            stopped,
        } => {
            let name = name_field(name.as_bytes());
            let record = [name.0.as_ptr() as usize as u32, module, thread];
            notify_sessions(
                kind_of(KIND_POGO_MODULE_STARTUP, stopped),
                address_of(&record),
            );
        }
        // No stock producer of assert prompt text runs the session path.
        Event::AssertString { .. } => {}
    }
}

/// Kinds 0xe and 0x13: `{thread, length, string}`, no string as 0.
fn notify_text(kind: u32, thread: u32, text: Option<&str>) {
    let (length, string) = text.map_or((0, 0), |text| {
        (text.len() as u32, text.as_ptr() as usize as u32)
    });
    notify_sessions(kind, address_of(&[thread, length, string]));
}

/// Title termination part of stock 0x91f3c9b0: sessions of the title are
/// unlinked (not freed), then the kernel hooks of kinds 2..=0x17 are
/// refreshed.
pub(crate) fn unlink_title_notification_sessions() {
    let _guard = LOCK.exclusive();
    unlink_sessions(
        |session| read_u32(session + SESSION_FLAGS) & SESSION_TITLE != 0,
        |_| {},
    );
    for kind in 2..LAST_KIND + 2 {
        refresh_kernel_hooks(kind);
    }
}

/// Export 32 (stock 0x91f3ae68): with a handler, add a processor named
/// `name` (at most 0x3f characters, 16 per session). Without one, remove
/// the processors whose name equals `name` ignoring case, or all of them
/// for no name.
extern "C" fn register_notification_processor(session: u32, name: u32, handler: u32) -> u32 {
    if !is_session(session) {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let mut block = None;
    if handler != 0 {
        if name == 0 {
            return Hresult::INVALID_ARGUMENT.0;
        }
        // SAFETY: the allocation takes only a size and tag.
        match unsafe { xboxkrnl::ExAllocatePoolWithTag(PROCESSOR_SIZE, PROCESSOR_POOL_TAG) } {
            0 => return Hresult::OUT_OF_MEMORY.0,
            allocated => block = Some(allocated),
        }
    }
    assert_passive(0xce4);
    let guard = LOCK.exclusive();
    let mut processors = (0..PROCESSOR_SLOTS).map(|slot| session + SESSION_PROCESSORS + 4 * slot);
    let result: Result<(), AddProcessorError> = match block {
        None => {
            let name = if name == 0 {
                None
            } else {
                Some(c_string(name, usize::MAX))
            };
            for slot in processors {
                let processor = read_u32(slot);
                if processor == 0 {
                    continue;
                }
                let matches = match name {
                    None => true,
                    Some(name) => {
                        compare_names(
                            c_string(processor, PROCESSOR_NAME_LIMIT + 1),
                            name,
                            name.len(),
                        ) == 0
                    }
                };
                if matches {
                    // SAFETY: a session slot holds a processor pool block; the
                    // slot is cleared below with the lock held.
                    unsafe { xboxkrnl::ExFreePool(processor) };
                    write_u32(slot, 0);
                }
            }
            Ok(())
        }
        Some(processor) => match processors.find(|&slot| read_u32(slot) == 0) {
            None => Err(AddProcessorError::NoFreeSlot),
            Some(slot) => {
                let name = c_string(name, PROCESSOR_NAME_LIMIT + 1);
                if name.len() > PROCESSOR_NAME_LIMIT {
                    Err(AddProcessorError::NameTooLong)
                } else {
                    // SAFETY: the block holds PROCESSOR_SIZE bytes.
                    unsafe {
                        let bytes = processor as usize as *mut u8;
                        core::ptr::copy_nonoverlapping(name.as_ptr(), bytes, name.len());
                        bytes.add(name.len()).write(0);
                    }
                    write_u32(processor + PROCESSOR_HANDLER, handler);
                    write_u32(slot, processor);
                    block = None;
                    Ok(())
                }
            }
        },
    };
    drop(guard);
    if let Some(unused) = block {
        // SAFETY: the block was allocated above and never linked.
        unsafe { xboxkrnl::ExFreePool(unused) };
    }
    crate::exports::export_result(result).0
}

/// Why export 32 could not add a session processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddProcessorError {
    NoFreeSlot,
    NameTooLong,
}

impl From<AddProcessorError> for Hresult {
    fn from(error: AddProcessorError) -> Self {
        match error {
            AddProcessorError::NoFreeSlot => ErrorCode::MaxConnectionsExceeded.hresult(),
            AddProcessorError::NameTooLong => Hresult::INVALID_ARGUMENT,
        }
    }
}

/// Export 36 (stock 0x91f3b070): send `text` to every notification
/// channel. The text must name its kind with a `!` before any space,
/// control character, or byte of 0x80 and above. Channels get it only from
/// callers at passive level.
///
/// Stock also offers the text to the session processors whose name
/// matches the kind, but its compare (0x91f411f0) is called with the text
/// first, which continues with the `!`, so no processor ever matches.
pub(super) extern "C" fn send_notification(text: u32) -> u32 {
    if text == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    notification_result(send_notification_text(c_string(text, usize::MAX)))
}

/// A notification text that names no kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MissingKind;

/// The export result word of a notification send.
pub(super) fn notification_result(result: Result<(), MissingKind>) -> u32 {
    match result {
        Ok(()) => Hresult::OK.0,
        Err(MissingKind) => Hresult::INVALID_ARGUMENT.0,
    }
}

/// [`send_notification`] for a text formatted by this module.
pub(super) fn send_notification_text(text: &[u8]) -> Result<(), MissingKind> {
    notification_kind_length(text).ok_or(MissingKind)?;
    if passive() {
        post_notification(text);
    }
    Ok(())
}

/// Word stored by export 76 (stock 0x91fadd20); the monitor never reads it.
static EXPORT_76_VALUE: AtomicU32 = AtomicU32::new(0);
/// Word of exports 370 and 371 (stock 0x91fa3afc); only they use it.
static EXPORT_370_VALUE: AtomicU32 = AtomicU32::new(0);

export!(76, store_value);
export!(370, load_value);
export!(371, exchange_value);
export!(372, drain_named_calls);

/// Export 76 (stock 0x91f3b4b8).
extern "C" fn store_value(value: u32) -> u32 {
    EXPORT_76_VALUE.store(value, Ordering::Relaxed);
    Hresult::OK.0
}

/// Export 370 (stock 0x91f78c50).
extern "C" fn load_value() -> u32 {
    EXPORT_370_VALUE.load(Ordering::Relaxed)
}

/// Export 371 (stock 0x91f78c60): store `value`, return the previous one.
extern "C" fn exchange_value(value: u32) -> u32 {
    EXPORT_370_VALUE.swap(value, Ordering::Relaxed)
}

/// Export 372 (stock 0x91f3ea50): run the remote calls queued for the
/// thread name `name`, newest first.
extern "C" fn drain_named_calls(name: u32) -> u32 {
    super::service_rpc_drain(name)
}
