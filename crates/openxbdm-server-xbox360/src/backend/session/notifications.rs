//! Notification sessions (stock dmnotify, exports 6, 24, 25, 32 and 36):
//! handlers that system software and titles register for monitor
//! notification kinds, and named text processors. Sessions are pool blocks
//! in the monitor's layout, linked from a list under a reader-writer spin
//! lock held at DISPATCH_LEVEL (stock 0x91fadc00, lock 0x91fadc08).

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands::debugger::ExceptionNotificationFlags;
use openxbdm_server::commands::memory::is_device_address;
use openxbdm_server::commands::session::compare_names;
use openxbdm_server::commands::session::notification_kind_length;
use openxbdm_server::notify::DataAccess;
use openxbdm_server::notify::Event;
use openxbdm_server::notify::ExceptionDetail;
use xbox360::thread::ThreadObject;
use xbox360_sys::processor;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::ProcessType;

use super::error::AddProcessorError;
use super::error::MissingKind;
use super::passive;
use super::post_notification;
use super::service_rpc_drain;
use super::swap;
use super::until_nul;
use crate::backend::debugger::execution_code;
use crate::backend::debugger::execution_state;
use crate::exports::export;
use crate::kernel;
use crate::kernel::address_of;

export!(6, close_notification_session);
export!(24, register_notification_handler);
export!(25, open_notification_session);
export!(32, register_notification_processor);
export!(36, send_notification);
export!(76, store_value);
export!(370, load_value);
export!(371, exchange_value);
export!(372, drain_named_calls);

/// Tag word of a session block, 'xnot'.
const SESSION_TAG: u32 = 0x786e_6f74;
/// Handler lists of a session, one per kind 1..=0x16.
const LIST_COUNT: usize = 0x16;
const HANDLER_SLOTS: usize = 0x20;
const PROCESSOR_SLOTS: usize = 0x10;
const PROCESSOR_NAME_LIMIT: usize = 0x3f;
const NAME_CAPACITY: usize = 0x104;
const MODULE_LOAD_RECORD_LENGTH: u32 = 0x12c;

/// Head of the session list.
static SESSIONS: AtomicU32 = AtomicU32::new(0);
static LOCK: ListLock = ListLock(AtomicU32::new(0));
/// The thread switch routine is in the swap chain.
static THREAD_SWITCH_HOOKED: AtomicBool = AtomicBool::new(false);
/// Word stored by export 76 (stock 0x91fadd20); the monitor never reads it.
static EXPORT_76_VALUE: AtomicU32 = AtomicU32::new(0);
/// Word of exports 370 and 371 (stock 0x91fa3afc); only they use it.
static EXPORT_370_VALUE: AtomicU32 = AtomicU32::new(0);

xbox360_sys::value_enum! {
    /// Notification kinds of the stock event structures.
    pub enum NotificationKind: u32 {
        Break = 1,
        DebugString = 2,
        Execution = 3,
        SingleStep = 4,
        /// Handlers of this kind get the notification data 4 bytes in.
        ModuleLoad = 5,
        ModuleUnload = 6,
        ThreadCreate = 7,
        ThreadTerminate = 8,
        Exception = 9,
        /// The kernel calls the routine stored through debug monitor data
        /// +0x10 while the kind has handlers [purpose of the kernel call
        /// unknown].
        KernelCallback = 0xa,
        Assert = 0xc,
        Data = 0xd,
        Rip = 0xe,
        ThreadSwitch = 0xf,
        SectionLoad = 0x10,
        SectionUnload = 0x11,
        StackTrace = 0x13,
        NtAssert = 0x15,
        PogoModuleStartup = 0x16,
    }
}

const _: () = assert!(NotificationKind::PogoModuleStartup.raw() as usize == LIST_COUNT);

/// The kind word handlers get: the kind in the low 24 bits, and
/// [`NotificationWord::STOPPED`] when the thread stops after the event.
#[derive(Clone, Copy, PartialEq, Eq)]
struct NotificationWord(u32);

impl NotificationWord {
    const KIND_MASK: u32 = 0xff_ffff;
    const STOPPED: u32 = 0x8000_0000;

    #[inline(always)]
    const fn new(kind: NotificationKind, stopped: bool) -> Self {
        Self(kind.raw() | (Self::STOPPED * stopped as u32))
    }

    #[inline(always)]
    const fn list(self) -> HandlerList {
        HandlerList(self.0 & Self::KIND_MASK)
    }
}

/// Handler list of a session: a kind number in 1..=[`LIST_COUNT`].
#[derive(Clone, Copy, PartialEq, Eq)]
struct HandlerList(u32);

impl HandlerList {
    #[inline(always)]
    const fn of(kind: NotificationKind) -> Self {
        Self(kind.raw())
    }

    /// `None` outside 1..=[`LIST_COUNT`].
    #[inline(always)]
    fn new(kind: u32) -> Option<Self> {
        (kind != 0 && kind <= LIST_COUNT as u32).then_some(Self(kind))
    }

    fn all() -> impl Iterator<Item = Self> {
        (1..=LIST_COUNT as u32).map(Self)
    }

    #[inline(always)]
    const fn index(self) -> usize {
        self.0 as usize - 1
    }
}

xbox360_sys::flags! {
    /// Flags word of a session; the opener's other bits are kept.
    pub struct SessionFlags(u32) {
        /// Opened by a title process; unlinked when the title ends.
        TITLE = 0x1_0000,
    }
}

/// Session block (pool tag `snmd`). The handle a session's opener gets is
/// its address.
#[repr(C)]
struct NotificationSession {
    tag: AtomicU32,
    /// Next linked session, under the list lock.
    next: AtomicU32,
    flags: AtomicU32,
    handlers: [[AtomicU32; HANDLER_SLOTS]; LIST_COUNT],
    /// Handlers in use per list; at most HANDLER_SLOTS.
    counts: [AtomicU32; LIST_COUNT],
    /// Addresses of [`ProcessorBlock`]s, or 0.
    processors: [AtomicU32; PROCESSOR_SLOTS],
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(NotificationSession, next) == 0x4);
    assert!(offset_of!(NotificationSession, flags) == 0x8);
    assert!(offset_of!(NotificationSession, handlers) == 0xc);
    // Stock addresses the count of kind k at +0xb08 + 4 * k.
    assert!(offset_of!(NotificationSession, counts) == 0xb08 + 4);
    assert!(offset_of!(NotificationSession, processors) == 0xb64);
    assert!(core::mem::size_of::<NotificationSession>() == 0xba4);
};

impl NotificationSession {
    /// The session at `address` when it carries the session tag.
    ///
    /// # Safety
    ///
    /// `address` must be 0 or readable for a session block for `'a`, as a
    /// session handle from export 25 that is not closed is.
    #[inline(always)]
    unsafe fn from_handle<'a>(address: u32) -> Option<&'a Self> {
        // SAFETY: the caller guarantees the block.
        let session =
            unsafe { core::ptr::with_exposed_provenance::<Self>(address as usize).as_ref() }?;
        (session.tag.load(Ordering::Relaxed) == SESSION_TAG).then_some(session)
    }

    /// The linked session at `address`; `None` for 0.
    ///
    /// # Safety
    ///
    /// `address` must be 0 or a session linked in the list, and the list
    /// lock must be held for `'a`; a session is freed only after it is
    /// unlinked under the exclusive lock.
    #[inline(always)]
    unsafe fn linked<'a>(address: u32) -> Option<&'a Self> {
        // SAFETY: the caller guarantees the block.
        unsafe { core::ptr::with_exposed_provenance::<Self>(address as usize).as_ref() }
    }

    #[inline(always)]
    fn count(&self, list: HandlerList) -> &AtomicU32 {
        // SAFETY: a handler list number is in 1..=LIST_COUNT.
        unsafe { self.counts.get_unchecked(list.index()) }
    }

    /// # Safety
    ///
    /// `index` must be below HANDLER_SLOTS.
    #[inline(always)]
    unsafe fn handler(&self, list: HandlerList, index: u32) -> &AtomicU32 {
        // SAFETY: the list number is in range; the caller bounds `index`.
        unsafe {
            self.handlers
                .get_unchecked(list.index())
                .get_unchecked(index as usize)
        }
    }

    fn address(&self) -> u32 {
        core::ptr::from_ref(self).expose_provenance() as u32
    }
}

/// Processor block (pool tag `hcmd`): a NUL-terminated name of at most
/// [`PROCESSOR_NAME_LIMIT`] characters, then the handler.
#[repr(C)]
struct ProcessorBlock {
    name: [u8; PROCESSOR_NAME_LIMIT + 1],
    handler: u32,
}

const _: () = {
    assert!(core::mem::offset_of!(ProcessorBlock, handler) == 0x40);
    assert!(core::mem::size_of::<ProcessorBlock>() == 0x44);
};

xbox360_sys::flags! {
    /// Writer bits of the list lock word; the reader count is above them.
    pub struct ListLockState(u32) {
        /// A writer waits; new readers stay out.
        WRITER_WAITING = 0x2,
        WRITER = 0x4,
    }
}

/// Reader-writer spin lock (stock words 0x91f23230 shared, 0x91f232bc
/// exclusive, 0x91f23278/0x91f23304 release) taken at DISPATCH_LEVEL
/// (stock 0x91f54e88, 0x91f54f10). A waiting writer keeps new readers out
/// until a writer releases the lock.
struct ListLock(AtomicU32);

impl ListLock {
    /// One reader in the count above the writer bits.
    const READER: u32 = 0x8;

    fn shared(&self) -> ListGuard<'_> {
        // SAFETY: the guard lowers the IRQL back to `irql` on drop.
        let irql = unsafe { xboxkrnl::KfRaiseIrql(Irql::DISPATCH) };

        loop {
            let state = self.0.load(Ordering::Relaxed);
            if !ListLockState::from_bits_retain(state)
                .intersects(ListLockState::WRITER | ListLockState::WRITER_WAITING)
                && self
                    .0
                    .compare_exchange_weak(
                        state,
                        state + Self::READER,
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
            let state = ListLockState::from_bits_retain(self.0.load(Ordering::Relaxed));
            if state.difference(ListLockState::WRITER_WAITING).is_empty() {
                if self
                    .0
                    .compare_exchange_weak(
                        state.bits(),
                        ListLockState::WRITER.bits(),
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    return ListGuard {
                        lock: self,
                        irql,
                        exclusive: true,
                    };
                }
            } else if !state.contains(ListLockState::WRITER_WAITING) {
                self.0
                    .fetch_or(ListLockState::WRITER_WAITING.bits(), Ordering::Relaxed);
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
            self.lock.0.fetch_sub(ListLock::READER, Ordering::Release);
        }

        // SAFETY: `irql` is the level the guard raised from.
        unsafe { xboxkrnl::KfLowerIrql(self.irql) };
    }
}

/// Access word of the kind 0xd data breakpoint record.
#[repr(u32)]
#[derive(Clone, Copy)]
enum DataAccessCode {
    Write = 1,
    Read = 2,
    Execute = 3,
}

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

/// `RtlAssert` as stock reports a call above passive level.
fn assert_passive(line: u32) {
    const ASSERT_PASSIVE: &core::ffi::CStr = c"KeGetCurrentIrql() == PASSIVE_LEVEL";
    const ASSERT_FILE: &core::ffi::CStr =
        c"e:\\xenon\\xdksep13\\core\\private\\xdk\\tools\\debug\\xbdm\\core\\dmnotify.c";

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

/// The linked sessions, newest first, while `_guard` holds the lock.
fn sessions<'g>(_guard: &'g ListGuard<'_>) -> impl Iterator<Item = &'g NotificationSession> {
    let mut next = SESSIONS.load(Ordering::Acquire);
    core::iter::from_fn(move || {
        // SAFETY: the list links sessions, and the guard holds the lock.
        let session = unsafe { NotificationSession::linked(next) }?;
        next = session.next.load(Ordering::Relaxed);
        Some(session)
    })
}

/// Unlink every session for which `remove` holds; passes the address of
/// each to `removed`. Called with the lock held exclusively.
fn unlink_sessions(
    _guard: &ListGuard<'_>,
    mut remove: impl FnMut(&NotificationSession) -> bool,
    mut removed: impl FnMut(u32),
) {
    // The word that links the current session: the head, then a session's
    // next field.
    let mut link = &SESSIONS;

    loop {
        let current = link.load(Ordering::Relaxed);
        // SAFETY: the list links sessions, and the guard holds the lock.
        let Some(session) = (unsafe { NotificationSession::linked(current) }) else {
            return;
        };
        if remove(session) {
            link.store(session.next.load(Ordering::Relaxed), Ordering::Release);
            removed(current);
        } else {
            link = &session.next;
        }
    }
}

/// Export 25 (stock 0x91f3acc0): open a session with `flags`; sessions of
/// title processes are marked to go with the title.
extern "C" fn open_notification_session(flags: u32, session: *mut u32) -> Hresult {
    const SESSION_POOL_TAG: PoolTag = PoolTag::new(*b"snmd");

    if session.is_null() {
        return Hresult::INVALID_ARGUMENT;
    }

    assert_passive(0xbf9);

    let flags = SessionFlags::from_bits_retain(flags);
    let flags = if xboxkrnl::KeGetCurrentProcessType() == ProcessType::TITLE {
        flags | SessionFlags::TITLE
    } else {
        flags
    };

    // SAFETY: the allocation takes only a size and tag.
    let block = unsafe {
        xboxkrnl::ExAllocatePoolWithTag(
            core::mem::size_of::<NotificationSession>() as u32,
            SESSION_POOL_TAG,
        )
    };
    // SAFETY: the caller passes a writable handle location.
    unsafe { session.write_unaligned(block) };
    if block == 0 {
        return Hresult::OUT_OF_MEMORY;
    }

    let _guard = LOCK.exclusive();
    // SAFETY: the pool block holds a session and is not yet shared.
    let new = unsafe {
        let pointer = core::ptr::with_exposed_provenance_mut::<NotificationSession>(block as usize);
        pointer.write_bytes(0, 1);
        &*pointer
    };
    new.flags.store(flags.bits(), Ordering::Relaxed);
    new.tag.store(SESSION_TAG, Ordering::Relaxed);
    new.next
        .store(SESSIONS.load(Ordering::Relaxed), Ordering::Relaxed);
    SESSIONS.store(block, Ordering::Release);

    Hresult::OK
}

/// Export 6 (stock 0x91f3adb8): unlink and free a session. A readable
/// session block that is not linked is left alone. Kernel hooks keep their
/// state until the next registration change.
extern "C" fn close_notification_session(session: u32) -> Hresult {
    let readable = session != 0 && {
        // SAFETY: the check only translates the address.
        let mapped = unsafe { xboxkrnl::MmDbgReadCheck(session) };
        mapped != 0 && !is_device_address(mapped)
    };
    // SAFETY: the debugger read check found the tag word readable.
    if !readable
        || unsafe { &*core::ptr::with_exposed_provenance::<AtomicU32>(session as usize) }
            .load(Ordering::Relaxed)
            != SESSION_TAG
    {
        return Hresult::INVALID_ARGUMENT;
    }

    let guard = LOCK.exclusive();
    unlink_sessions(
        &guard,
        |candidate| candidate.address() == session,
        |removed| {
            // SAFETY: the unlinked session is a pool block of this module.
            unsafe { xboxkrnl::ExFreePool(removed) };
        },
    );

    Hresult::OK
}

/// Export 24 (stock 0x91f3ca48): add `handler` for notification `kind`
/// (1..=0x16, at most 0x20 per kind; a handler already present or a full
/// list is ignored). A new kind-3 handler is called at once with the
/// execution state. Kind 0 with no handler clears every list.
///
/// Kind 0 with a handler: stock removes it from the kind-1 list and then
/// repeats the removal forever with the lock held. openxbdm removes it
/// once and returns.
extern "C" fn register_notification_handler(session: u32, kind: u32, handler: u32) -> Hresult {
    // SAFETY: callers pass a session handle from export 25.
    let Some(session) = (unsafe { NotificationSession::from_handle(session) }) else {
        return Hresult::INVALID_ARGUMENT;
    };

    assert_passive(0xc5c);

    let kind = kind & NotificationWord::KIND_MASK;
    let guard = LOCK.exclusive();
    if kind == 0 {
        if handler == 0 {
            for list in HandlerList::all() {
                session.count(list).store(0, Ordering::Relaxed);
                refresh_kernel_hooks(&guard, list.0);
            }
        } else {
            let list = HandlerList::of(NotificationKind::Break);
            remove_handler(session, list, handler);
            refresh_kernel_hooks(&guard, list.0);
        }

        return Hresult::OK;
    }

    let Some(list) = HandlerList::new(kind) else {
        return Hresult::INVALID_ARGUMENT;
    };
    if handler == 0 {
        return Hresult::INVALID_ARGUMENT;
    }

    let count = session.count(list).load(Ordering::Relaxed);
    // SAFETY (both): counts stay at most HANDLER_SLOTS; only this module
    // writes them, under the exclusive lock.
    let present = (0..count)
        .any(|index| unsafe { session.handler(list, index) }.load(Ordering::Relaxed) == handler);
    if present || count == HANDLER_SLOTS as u32 {
        return Hresult::OK;
    }

    // SAFETY: `count` is below HANDLER_SLOTS here.
    unsafe { session.handler(list, count) }.store(handler, Ordering::Relaxed);
    session.count(list).store(count + 1, Ordering::Relaxed);
    refresh_kernel_hooks(&guard, list.0);
    if list == HandlerList::of(NotificationKind::Execution) {
        call_handler(
            handler,
            NotificationWord::new(NotificationKind::Execution, false),
            execution_code(execution_state()),
        );
    }

    Hresult::OK
}

/// Remove every copy of `handler` from `list`, moving the last entry into
/// each freed place.
fn remove_handler(session: &NotificationSession, list: HandlerList, handler: u32) {
    let count = session.count(list);
    let mut index = 0;

    while index < count.load(Ordering::Relaxed) {
        // SAFETY (all): `index` and `last` are below the count, which stays
        // at most HANDLER_SLOTS.
        if unsafe { session.handler(list, index) }.load(Ordering::Relaxed) == handler {
            let last = count.load(Ordering::Relaxed) - 1;
            count.store(last, Ordering::Relaxed);
            unsafe { session.handler(list, index) }.store(
                unsafe { session.handler(list, last) }.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        } else {
            index += 1;
        }
    }
}

fn call_handler(handler: u32, kind: NotificationWord, data: u32) {
    // SAFETY: registrants pass console `void (*)(DWORD kind, void *data)`
    // routines.
    unsafe { kernel::call_export(handler, kind.0, data, 0, 0) };
}

/// Install or remove the kernel hooks of list `kind` by whether any
/// session has handlers in it (stock 0x91f3c8c8). Called with the lock
/// held.
fn refresh_kernel_hooks(guard: &ListGuard<'_>, kind: u32) {
    let wanted = |kind: NotificationKind| {
        let list = HandlerList::of(kind);
        sessions(guard).any(|session| session.count(list).load(Ordering::Relaxed) != 0)
    };

    if kind == NotificationKind::KernelCallback.raw() {
        let Some(variable) = kernel::routine_variable(kernel::RoutineVariable::Callback) else {
            return;
        };
        let routine = if wanted(NotificationKind::KernelCallback) {
            kernel_callback_entry as *const () as usize as u32
        } else {
            0
        };
        // SAFETY: the routine is 0 or this module's bridged entry, which
        // takes no arguments and stays loaded while installed.
        unsafe { variable.store(routine, Ordering::Relaxed) };
    } else if kind == NotificationKind::ThreadSwitch.raw() {
        let hooked = THREAD_SWITCH_HOOKED.load(Ordering::Relaxed);
        if wanted(NotificationKind::ThreadSwitch) {
            if !hooked {
                swap::register_swap_routine(thread_switched, true);
                THREAD_SWITCH_HOOKED.store(true, Ordering::Relaxed);
            }
        } else if hooked {
            swap::unregister_swap_routine(thread_switched);
            THREAD_SWITCH_HOOKED.store(false, Ordering::Relaxed);
        }
    }
}

/// Kernel callback of kind 0xa (stock 0x91f3b1c0); like the delivery
/// routine it tail-calls, it returns 0.
extern "C" fn kernel_callback() -> u32 {
    notify_sessions(
        NotificationWord::new(NotificationKind::KernelCallback, false),
        0,
    );

    0
}
crate::exports::bridged!(kernel_callback_entry, kernel_callback);

/// Swap routine of kind 0xf (stock 0x91f3b1d0): handlers get the thread
/// identifiers of the outgoing and the incoming thread.
extern "C" fn thread_switched(old: u32, _frame: u32, new: u32) {
    // SAFETY: the kernel passes the thread objects of the switch, which
    // stay allocated during it.
    let (old, new) = unsafe { (ThreadObject::from_raw(old), ThreadObject::from_raw(new)) };
    let threads = [old.id().raw(), new.id().raw()];
    notify_sessions(
        NotificationWord::new(NotificationKind::ThreadSwitch, false),
        threads.as_ptr() as usize as u32,
    );
}

/// Run every session handler of the word's kind, newest first, with the
/// word and `data` (stock 0x91f395c0); module-load handlers get `data` 4
/// bytes in. Nothing runs above DISPATCH_LEVEL.
fn notify_sessions(word: NotificationWord, data: u32) {
    let data = if word == NotificationWord::new(NotificationKind::ModuleLoad, false) {
        data + 4
    } else {
        data
    };
    if processor::current_irql() > Irql::DISPATCH {
        return;
    }

    let list = word.list();
    let guard = LOCK.shared();
    for session in sessions(&guard) {
        let mut index = session.count(list).load(Ordering::Relaxed);
        while index != 0 {
            index -= 1;
            // SAFETY: `index` is below the count, which stays at most
            // HANDLER_SLOTS.
            let handler = unsafe { session.handler(list, index) }.load(Ordering::Relaxed);
            call_handler(handler, word, data);
        }
    }
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

/// Run the session handlers of `event` with the monitor's structure for
/// its kind.
pub(crate) fn notify_event(event: &Event<'_>) {
    use NotificationKind as K;
    use NotificationWord as W;

    match *event {
        Event::Break {
            address,
            thread,
            stopped,
        } => {
            notify_sessions(W::new(K::Break, stopped), address_of(&[address, thread]));
        }
        Event::SingleStep {
            address,
            thread,
            stopped,
        } => {
            notify_sessions(
                W::new(K::SingleStep, stopped),
                address_of(&[address, thread]),
            );
        }
        Event::NtAssert {
            address,
            thread,
            stopped,
        } => {
            notify_sessions(W::new(K::NtAssert, stopped), address_of(&[address, thread]));
        }
        Event::DebugString {
            thread,
            text,
            stopped,
        } => {
            let record = [thread, text.len() as u32, text.as_ptr() as usize as u32];
            notify_sessions(W::new(K::DebugString, stopped), address_of(&record));
        }
        Event::Execution(state) => {
            notify_sessions(W::new(K::Execution, false), execution_code(state))
        }
        Event::ExecutionStop(state) => {
            notify_sessions(W::new(K::Execution, true), execution_code(state))
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
            notify_sessions(W::new(K::ModuleLoad, stopped), address_of(&record));
        }
        Event::ModuleUnload { name, base, size } => {
            let record = ModuleRecord {
                name: name_field(name.as_bytes()),
                base,
                size,
                ..ModuleRecord::default()
            };
            notify_sessions(W::new(K::ModuleUnload, false), address_of(&record));
        }
        Event::ThreadCreate {
            thread,
            start,
            stopped,
        } => {
            notify_sessions(
                W::new(K::ThreadCreate, stopped),
                address_of(&[thread, start]),
            );
        }
        Event::ThreadTerminate { thread, stopped } => {
            notify_sessions(W::new(K::ThreadTerminate, stopped), thread)
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
            let mut flags = ExceptionNotificationFlags::empty();
            if first_chance {
                flags |= ExceptionNotificationFlags::FIRST_CHANCE;
            }
            if noncontinuable {
                flags |= ExceptionNotificationFlags::NONCONTINUABLE;
            }
            let (first, second) = match detail {
                ExceptionDetail::AccessViolation { write, address } => (u32::from(write), address),
                ExceptionDetail::Parameters { count, address } => (count, address),
            };
            let record = [thread, code, address, flags.bits(), first, second];
            notify_sessions(W::new(K::Exception, stopped), address_of(&record));
        }
        Event::Assert {
            thread,
            string_address,
            string_length,
            stopped,
        } => {
            let record = [thread, string_length, string_address];
            notify_sessions(W::new(K::Assert, stopped), address_of(&record));
        }
        Event::Data {
            access,
            value,
            address,
            thread,
            stopped,
        } => {
            let access = match access {
                DataAccess::Write => DataAccessCode::Write,
                DataAccess::Read => DataAccessCode::Read,
                DataAccess::Execute => DataAccessCode::Execute,
            };
            notify_sessions(
                W::new(K::Data, stopped),
                address_of(&[address, thread, access as u32, value]),
            );
        }
        Event::Rip {
            thread,
            text,
            stopped,
        } => notify_text(W::new(K::Rip, stopped), thread, text),
        Event::StackTrace {
            thread,
            text,
            stopped,
        } => notify_text(W::new(K::StackTrace, stopped), thread, text),
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
                K::SectionLoad
            } else {
                K::SectionUnload
            };
            notify_sessions(W::new(kind, false), address_of(&record));
        }
        Event::PogoModuleStartup {
            name,
            module,
            thread,
            stopped,
        } => {
            let name = name_field(name.as_bytes());
            let record = [name.0.as_ptr() as usize as u32, module, thread];
            notify_sessions(W::new(K::PogoModuleStartup, stopped), address_of(&record));
        }
        // No stock producer of assert prompt text runs the session path.
        Event::AssertString { .. } => {}
    }
}

/// Kinds 0xe and 0x13: `{thread, length, string}`, no string as 0.
fn notify_text(word: NotificationWord, thread: u32, text: Option<&str>) {
    let (length, string) = text.map_or((0, 0), |text| {
        (text.len() as u32, text.as_ptr() as usize as u32)
    });

    notify_sessions(word, address_of(&[thread, length, string]));
}

/// Title termination part of stock 0x91f3c9b0: sessions of the title are
/// unlinked (not freed), then the kernel hooks of kinds 2..=0x17 are
/// refreshed.
pub(crate) fn unlink_title_notification_sessions() {
    let guard = LOCK.exclusive();
    unlink_sessions(
        &guard,
        |session| {
            SessionFlags::from_bits_retain(session.flags.load(Ordering::Relaxed))
                .contains(SessionFlags::TITLE)
        },
        |_| {},
    );

    for kind in 2..LIST_COUNT as u32 + 2 {
        refresh_kernel_hooks(&guard, kind);
    }
}

/// Export 32 (stock 0x91f3ae68): with a handler, add a processor named
/// `name` (at most 0x3f characters, 16 per session). Without one, remove
/// the processors whose name equals `name` ignoring case, or all of them
/// for no name.
extern "C" fn register_notification_processor(session: u32, name: u32, handler: u32) -> Hresult {
    const PROCESSOR_POOL_TAG: PoolTag = PoolTag::new(*b"hcmd");

    // SAFETY: callers pass a session handle from export 25.
    let Some(session) = (unsafe { NotificationSession::from_handle(session) }) else {
        return Hresult::INVALID_ARGUMENT;
    };

    let block = if handler == 0 {
        None
    } else {
        if name == 0 {
            return Hresult::INVALID_ARGUMENT;
        }

        // SAFETY: the allocation takes only a size and tag.
        let allocated = unsafe {
            xboxkrnl::ExAllocatePoolWithTag(
                core::mem::size_of::<ProcessorBlock>() as u32,
                PROCESSOR_POOL_TAG,
            )
        };
        if allocated == 0 {
            return Hresult::OUT_OF_MEMORY;
        }

        Some(allocated)
    };

    assert_passive(0xce4);

    let (result, unused) = {
        let _guard = LOCK.exclusive();
        let mut processors = session.processors.iter();
        match block {
            None => {
                // SAFETY: callers pass 0 or a NUL-terminated name.
                let name = unsafe { kernel::c_string(name) };
                for slot in processors {
                    let address = slot.load(Ordering::Relaxed);
                    // SAFETY: a slot holds 0 or a processor block of this
                    // module, which is freed only here under the exclusive
                    // lock.
                    let Some(processor) = (unsafe {
                        core::ptr::with_exposed_provenance::<ProcessorBlock>(address as usize)
                            .as_ref()
                    }) else {
                        continue;
                    };
                    let selected = match name {
                        None => true,
                        Some(name) => {
                            compare_names(until_nul(&processor.name), name, name.len()) == 0
                        }
                    };
                    if selected {
                        // SAFETY: the slot holds a processor pool block; the
                        // slot is cleared below with the lock held.
                        unsafe { xboxkrnl::ExFreePool(address) };
                        slot.store(0, Ordering::Relaxed);
                    }
                }

                (Ok(()), None)
            }
            Some(processor) => match processors.find(|slot| slot.load(Ordering::Relaxed) == 0) {
                None => (Err(AddProcessorError::NoFreeSlot), block),
                // SAFETY: a block exists only for a nonzero name (checked
                // above), which callers pass NUL-terminated.
                Some(slot) => match unsafe {
                    kernel::bounded_c_string(name, PROCESSOR_NAME_LIMIT + 1).unwrap_unchecked()
                } {
                    name if name.len() > PROCESSOR_NAME_LIMIT => {
                        (Err(AddProcessorError::NameTooLong), block)
                    }
                    name => {
                        // SAFETY: the new block holds a processor block and is
                        // not yet shared; the name fits its field with the NUL.
                        unsafe {
                            let pointer = core::ptr::with_exposed_provenance_mut::<ProcessorBlock>(
                                processor as usize,
                            );
                            let bytes = (&raw mut (*pointer).name).cast::<u8>();
                            core::ptr::copy_nonoverlapping(name.as_ptr(), bytes, name.len());
                            bytes.add(name.len()).write(0);
                            (&raw mut (*pointer).handler).write(handler);
                        }
                        slot.store(processor, Ordering::Relaxed);

                        (Ok(()), None)
                    }
                },
            },
        }
    };

    if let Some(unused) = unused {
        // SAFETY: the block was allocated above and never linked.
        unsafe { xboxkrnl::ExFreePool(unused) };
    }

    crate::exports::export_result(result)
}

/// Export 36 (stock 0x91f3b070): send `text` to every notification
/// channel. The text must name its kind with a `!` before any space,
/// control character, or byte of 0x80 and above. Channels get it only from
/// callers at passive level.
///
/// Stock also offers the text to the session processors whose name
/// matches the kind, but its compare (0x91f411f0) is called with the text
/// first, which continues with the `!`, so no processor ever matches.
pub(super) extern "C" fn send_notification(text: u32) -> Hresult {
    // SAFETY: callers pass 0 or a NUL-terminated text.
    let Some(text) = (unsafe { kernel::c_string(text) }) else {
        return Hresult::INVALID_ARGUMENT;
    };

    notification_result(send_notification_text(text))
}

/// The export result of a notification send.
pub(super) fn notification_result(result: Result<(), MissingKind>) -> Hresult {
    match result {
        Ok(()) => Hresult::OK,
        Err(MissingKind) => Hresult::INVALID_ARGUMENT,
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

/// Export 76 (stock 0x91f3b4b8).
extern "C" fn store_value(value: u32) -> Hresult {
    EXPORT_76_VALUE.store(value, Ordering::Relaxed);
    Hresult::OK
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
    // SAFETY: the importer passes 0 or the NUL-terminated name of the
    // calling thread.
    unsafe { service_rpc_drain(name) }
}
