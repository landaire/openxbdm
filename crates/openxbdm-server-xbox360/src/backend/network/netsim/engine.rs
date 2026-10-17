//! The simulator instance (stock 0xa8-byte object, vtable 0x91f0d240): queue
//! and redirect lists, the frame processor 0x91f8e260, and the release
//! timer 0x91f8dec0. Everything below the spin lock is shared with the
//! network stack's intercept callbacks and the timer DPC.

use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::ptr::null_mut;

use openxbdm_server::commands::network::netsim::Direction;
use openxbdm_server::commands::network::netsim::NetsimError;
use openxbdm_server::commands::network::netsim::Program;
use openxbdm_server::commands::network::netsim::QueueConfig;
use openxbdm_server::commands::network::netsim::QueueIndex;
use openxbdm_server::commands::network::netsim::QueueKind;
use openxbdm_server::commands::network::netsim::QueueSnapshot;
use openxbdm_server::commands::network::netsim::QueueStats;
use openxbdm_server::commands::network::netsim::RedirectConfig;
use openxbdm_server::commands::network::netsim::RedirectIndex;
use openxbdm_server::commands::network::netsim::RedirectSnapshot;
use xbox360::module::Ordinal;
use xbox360::time::TickCount;
use xbox360::time::Timebase;
use xbox360_sys::processor::HardwareThread;
use xbox360_sys::xam::NetDll_XnpEthernetInterceptRecv;
use xbox360_sys::xam::NetDll_XnpEthernetInterceptXmit;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::Kdpc;
use xbox360_sys::xboxkrnl::KeCancelTimer;
use xbox360_sys::xboxkrnl::KeInitializeDpc;
use xbox360_sys::xboxkrnl::KeInitializeTimerEx;
use xbox360_sys::xboxkrnl::KeRemoveQueueDpc;
use xbox360_sys::xboxkrnl::KeSetTimerEx;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::Ktimer;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::TimerType;
use xbox360_sys::xboxkrnl::XeCryptRandom;

use super::filter;
use super::frame;
use super::frame::FrameFlags;
use super::frame::Ipv4Frame;
use super::frame::Parsed;
use super::memory;
use super::pipeline;
use super::pipeline::Batch;
use super::pipeline::OwnedPacket;
use super::pipeline::Pipeline;
use super::pipeline::Random;
use super::pipeline::ReleaseTime;
use crate::backend::network::FrameCallback;
use crate::backend::network::FrameHook;
use crate::kernel;

/// Idle time after which a redirect session may be reused (120 s).
const SESSION_IDLE_MILLISECONDS: u32 = 120_000;
/// XAM export that sends a frame past the intercept.
const TRANSMIT_UNMODIFIED_ORDINAL: Ordinal =
    xbox360_sys::xam::ordinal::XNP_ETHERNET_INTERCEPT_XMIT_AS_IP;

/// Hardware thread that runs the release DPC.
const RELEASE_DPC_PROCESSOR: HardwareThread = HardwareThread::new(2).unwrap();

/// `XeCryptRandom`.
struct CryptRandom;

impl Random for CryptRandom {
    fn fill(&mut self, buffer: &mut [u8]) {
        // SAFETY: `buffer` is a live slice of the stated length.
        unsafe { XeCryptRandom(buffer.as_mut_ptr(), buffer.len() as u32) };
    }
}

/// The time base, read again when its low word is zero as stock does.
fn now() -> u64 {
    let time = Timebase::now().ticks();
    if time as u32 == 0 {
        Timebase::now().ticks()
    } else {
        time
    }
}

/// A classifier copy in its own pool block, as stock keeps queue +0x08 and
/// the redirect classifier: queues and redirects without one stay small.
struct StoredProgram(NonNull<Program>);

impl StoredProgram {
    fn new(program: &Program) -> Result<Self, NetsimError> {
        let block = memory::allocate(core::mem::size_of::<Program>())
            .ok_or(NetsimError::OutOfMemory)?
            .cast::<Program>();
        // SAFETY: the block holds a `Program`; pool blocks are 8-aligned.
        unsafe { block.write(*program) };
        Ok(Self(block))
    }

    fn store(program: Option<&Program>) -> Result<Option<Self>, NetsimError> {
        program.map(Self::new).transpose()
    }

    fn get(&self) -> &Program {
        // SAFETY: the block lives until `drop`.
        unsafe { self.0.as_ref() }
    }

    /// A copy for a queue or redirect snapshot.
    #[inline(never)]
    fn snapshot(program: &Option<Self>) -> Option<Program> {
        program.as_ref().map(|program| *program.get())
    }
}

impl Drop for StoredProgram {
    fn drop(&mut self) {
        // SAFETY: the block came from `memory::allocate` and is freed once.
        unsafe { memory::free(self.0.as_ptr().cast()) };
    }
}

/// Whether a classifier takes the frame; none takes every frame.
fn accepts(
    program: &Option<StoredProgram>,
    frame: &[u8],
    parsed: &Parsed,
) -> Result<bool, filter::EvaluationFailed> {
    match program {
        None => Ok(true),
        Some(program) => filter::matches(program.get(), frame, parsed),
    }
}

/// A queue (stock 0x78..0x110-byte object).
struct Queue {
    next: *mut Queue,
    kind: QueueKind,
    config: QueueConfig,
    stats: QueueStats,
    pipeline: Pipeline,
    /// Frames the queue takes; none takes every frame.
    program: Option<StoredProgram>,
}

/// A remembered redirected flow: frames in the other direction from the
/// rewritten endpoint get the original endpoint back.
struct Session {
    next: *mut Session,
    prev: *mut Session,
    /// Direction of the frames this slot rewrites back, which names the
    /// list holding it while in use.
    lookup: Direction,
    /// `None` while free; else [`FrameFlags::TCP`], [`FrameFlags::UDP`] or
    /// empty.
    protocol: Option<FrameFlags>,
    last_used: u32,
    new_address: [u8; 4],
    original_address: [u8; 4],
    new_port: u16,
    original_port: u16,
}

/// A redirect with its session slots after it.
struct Redirect {
    next: *mut Redirect,
    config: RedirectConfig,
    program: Option<StoredProgram>,
}

impl Redirect {
    /// # Safety
    /// `redirect` is a live block from `insert_redirect` with its slots
    /// written, and the slots are not otherwise borrowed for `'a`.
    unsafe fn sessions<'a>(redirect: *mut Redirect) -> &'a mut [Session] {
        // SAFETY: guaranteed by the caller; `insert_redirect` placed
        // `sessions` slots after the header.
        unsafe {
            let count = usize::from((*redirect).config.sessions);
            core::slice::from_raw_parts_mut(redirect.add(1).cast::<Session>(), count)
        }
    }
}

/// A singly linked list with positions.
trait Chained: Sized {
    /// # Safety
    /// `node` is live.
    unsafe fn next(node: *mut Self) -> *mut *mut Self;
}

impl Chained for Queue {
    unsafe fn next(node: *mut Self) -> *mut *mut Self {
        // SAFETY: guaranteed by the caller.
        unsafe { &raw mut (*node).next }
    }
}

impl Chained for Redirect {
    unsafe fn next(node: *mut Self) -> *mut *mut Self {
        // SAFETY: guaranteed by the caller.
        unsafe { &raw mut (*node).next }
    }
}

/// Members are live nodes the chain owns; `count` of them are linked.
struct Chain<T> {
    head: *mut T,
    count: u32,
}

impl<T: Chained> Chain<T> {
    const fn new() -> Self {
        Self {
            head: null_mut(),
            count: 0,
        }
    }

    /// The link that points at position `index`.
    ///
    /// # Safety
    /// `index` is at most `count`.
    unsafe fn link(&mut self, index: u32) -> *mut *mut T {
        let mut link = &raw mut self.head;
        for _ in 0..index {
            // SAFETY: `index` is at most `count`, so every link followed is
            // a live node.
            link = unsafe { T::next(*link) };
        }
        link
    }

    fn get(&mut self, index: u32) -> Option<*mut T> {
        (index < self.count).then(|| {
            // SAFETY: `index < count`.
            unsafe { *self.link(index) }
        })
    }

    /// Insert before `position`, or append; returns the new index.
    ///
    /// # Safety
    /// `node` is live, in no chain, and stays allocated until it is
    /// removed.
    unsafe fn insert(&mut self, position: Option<u32>, node: *mut T) -> Option<u32> {
        let index = match position {
            None => self.count,
            Some(index) if index < self.count => index,
            Some(_) => return None,
        };
        // SAFETY: `index <= count`; `link` is a link of the chain and `node`
        // is live and unlinked.
        unsafe {
            let link = self.link(index);
            *T::next(node) = *link;
            *link = node;
        }
        self.count += 1;
        Some(index)
    }

    /// Unlink the node at `index` and pass its ownership to the caller.
    ///
    /// # Safety
    /// `index < count`.
    unsafe fn remove(&mut self, index: u32) -> *mut T {
        // SAFETY: guaranteed by the caller.
        unsafe {
            let link = self.link(index);
            let node = *link;
            *link = *T::next(node);
            self.count -= 1;
            node
        }
    }

    fn iter(&self) -> impl Iterator<Item = *mut T> {
        let mut node = self.head;
        core::iter::from_fn(move || {
            (!node.is_null()).then(|| {
                let current = node;
                // SAFETY: members are live nodes.
                node = unsafe { *T::next(current) };
                current
            })
        })
    }
}

/// Head of a session list. Members are live slots of linked redirects.
struct SessionList(*mut Session);

impl SessionList {
    /// # Safety
    /// `session` is a live slot in no list.
    unsafe fn push_front(&mut self, session: *mut Session) {
        // SAFETY: guaranteed by the caller; members are live.
        unsafe {
            (*session).prev = null_mut();
            (*session).next = self.0;
            if !self.0.is_null() {
                (*self.0).prev = session;
            }
        }
        self.0 = session;
    }

    /// # Safety
    /// `session` is a member.
    unsafe fn unlink(&mut self, session: *mut Session) {
        // SAFETY: guaranteed by the caller; members are live.
        unsafe {
            let (prev, next) = ((*session).prev, (*session).next);
            if prev.is_null() {
                self.0 = next;
            } else {
                (*prev).next = next;
            }
            if !next.is_null() {
                (*next).prev = prev;
            }
        }
    }

    fn find(&self, protocol: FrameFlags, address: [u8; 4], port: u16) -> Option<*mut Session> {
        let mut session = self.0;
        // SAFETY: members are live slots.
        unsafe {
            while !session.is_null() {
                let slot = &*session;
                if slot
                    .protocol
                    .is_some_and(|stored| stored.intersects(protocol))
                    && slot.new_address == address
                    && slot.new_port == port
                {
                    return Some(session);
                }
                session = slot.next;
            }
        }
        None
    }
}

/// State guarded by the spin lock.
struct Inner {
    inbound: Chain<Queue>,
    outbound: Chain<Queue>,
    redirects: Chain<Redirect>,
    /// Sessions looked up for received frames (stock +0x34), made by
    /// transmitted ones, and the reverse (+0x3c).
    receive_sessions: SessionList,
    transmit_sessions: SessionList,
    /// Release time the timer is set for (+0x48); `None` while not armed.
    due: Option<ReleaseTime>,
    /// Capture callbacks chained in front of or behind the simulation
    /// (+0x94..+0x9c).
    chain: Option<FrameHook>,
    /// Received frames reach the chained receive callback before the
    /// simulation and transmitted ones after it (+0xa0 bit 30).
    receive_first: bool,
    /// Frames bypass the simulation while the IP proxy runs (+0xa0 bit 31).
    bypass: bool,
    /// XAM export 0x8e, which sends redirected frames.
    transmit_unmodified: u32,
}

impl Inner {
    fn sessions(&mut self, lookup: Direction) -> &mut SessionList {
        match lookup {
            Direction::Inbound => &mut self.receive_sessions,
            Direction::Outbound => &mut self.transmit_sessions,
        }
    }

    fn queues(&mut self, direction: Direction) -> &mut Chain<Queue> {
        match direction {
            Direction::Inbound => &mut self.inbound,
            Direction::Outbound => &mut self.outbound,
        }
    }

    fn chained(&self, direction: Direction) -> Option<(FrameCallback, usize)> {
        let hook = self.chain?;
        Some(match direction {
            Direction::Outbound => (hook.transmit, hook.context),
            Direction::Inbound => (hook.receive, hook.context),
        })
    }

    /// Arm the timer for `next` unless it is already due earlier
    /// (0x91f8d350). Stock converts the tick difference by shifting it right
    /// 62 bits, so the relative due time is zero or a few 100 ns units and
    /// the DPC runs again at once.
    fn schedule(&mut self, instance: &Instance, now: u64, next: Option<ReleaseTime>) {
        let Some(release) = next.filter(|&next| pipeline::is_before(next, self.due)) else {
            return;
        };
        let next = release.ticks();
        let difference = next.wrapping_sub(now) as i64;
        let difference = if next >= now {
            if difference < 0 { i64::MAX } else { difference }
        } else {
            0
        };
        let due = if difference > 0 {
            -((difference as u64 >> 62) as i64)
        } else {
            0
        };
        // SAFETY: the timer and DPC of the instance were initialized by `create`
        // and stay at their pool address until `destroy` cancels them.
        unsafe { KeSetTimerEx(instance.timer.as_ptr(), due, 0, instance.dpc.as_ptr()) };
        self.due = Some(release);
    }

    /// Take ready frames of every queue of `direction` (0x91f8d280); returns
    /// the earliest next release time.
    fn release(
        &mut self,
        direction: Direction,
        now: u64,
        batch: &mut Batch,
        mut next: Option<ReleaseTime>,
    ) -> Option<ReleaseTime> {
        let mut random = CryptRandom;
        for queue in self.queues(direction).iter() {
            // SAFETY: members are live queues.
            let queue = unsafe { &mut *queue };
            while let Some(released) = queue.pipeline.dequeue(now, &mut random) {
                if released.dropped {
                    queue.stats.dropped_packets = queue.stats.dropped_packets.wrapping_add(1);
                    let length = released.packet.length();
                    queue.stats.dropped_bytes =
                        queue.stats.dropped_bytes.wrapping_add(u64::from(length));
                    released.packet.free();
                } else {
                    batch.push(released.packet);
                }
            }
            next = pipeline::earliest(next, queue.pipeline.next_time(now));
        }
        next
    }
}

/// The instance; lives in pool memory at a fixed address because the timer,
/// the DPC, and the intercept context point into it.
pub(super) struct Instance {
    timer: Ktimer,
    dpc: Kdpc,
    lock: KspinLock,
    inner: UnsafeCell<Inner>,
}

/// The locked state.
struct Guard<'a> {
    instance: &'a Instance,
    irql: Irql,
}

impl Guard<'_> {
    fn inner(&mut self) -> &mut Inner {
        // SAFETY: the spin lock is held.
        unsafe { &mut *self.instance.inner.get() }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        // SAFETY: the instance spin lock was acquired by `lock` at `irql`.
        unsafe { xboxkrnl::KfReleaseSpinLock(self.instance.lock.as_ptr(), self.irql) };
    }
}

// SAFETY: `inner` is only reached under the spin lock; the kernel objects
// are used through kernel calls.
unsafe impl Sync for Instance {}

impl Instance {
    /// Allocate and initialize (0x91f8ee60, 0x91f8ed88, 0x91f8c758).
    pub(super) fn create() -> Result<NonNull<Instance>, NetsimError> {
        let instance = memory::allocate(core::mem::size_of::<Instance>())
            .ok_or(NetsimError::OutOfMemory)?
            .cast::<Instance>();
        // SAFETY: the block is large enough and pool blocks are 8-aligned.
        unsafe {
            instance.write(Instance {
                timer: Ktimer::new(),
                dpc: Kdpc::new(),
                lock: KspinLock::new(),
                inner: UnsafeCell::new(Inner {
                    inbound: Chain::new(),
                    outbound: Chain::new(),
                    redirects: Chain::new(),
                    receive_sessions: SessionList(null_mut()),
                    transmit_sessions: SessionList(null_mut()),
                    due: None,
                    chain: None,
                    receive_first: false,
                    bypass: false,
                    transmit_unmodified: 0,
                }),
            });
            let this = instance.as_ref();
            KeInitializeTimerEx(
                this.timer.as_ptr(),
                TimerType::Notification,
                ProcessType::SYSTEM,
            );
            let dpc = this.dpc.as_ptr();
            KeInitializeDpc(
                dpc,
                release_dpc_entry as *const () as usize,
                instance.as_ptr() as usize,
            );
            this.dpc.set_target_processor(Some(RELEASE_DPC_PROCESSOR));
        }
        // SAFETY: just initialized.
        let this = unsafe { instance.as_ref() };
        match super::super::xam_procedure(TRANSMIT_UNMODIFIED_ORDINAL) {
            Some(address) => this.lock().inner().transmit_unmodified = address,
            None => {
                // SAFETY: created here and never published.
                unsafe { Instance::destroy(instance) };
                return Err(NetsimError::RoutineMissing);
            }
        }
        Ok(instance)
    }

    /// Remove every queue and redirect, stop the timer, and free the
    /// instance (0x91f8e788). Stock leaves the redirects allocated.
    ///
    /// # Safety
    /// `instance` came from [`Instance::create`], no intercept callback is
    /// installed for it any longer, and no reference to it is live, except
    /// the ones stock does not exclude either: a query export that loaded
    /// it before it was unpublished (see `netsim::instance`), and a release
    /// DPC or intercept callback already running on another processor,
    /// which this cancels only when it is still queued.
    pub(super) unsafe fn destroy(instance: NonNull<Instance>) {
        // SAFETY: guaranteed by the caller.
        let this = unsafe { instance.as_ref() };
        {
            let mut guard = this.lock();
            let inner = guard.inner();
            for direction in [Direction::Inbound, Direction::Outbound] {
                let queues = inner.queues(direction);
                while queues.count != 0 {
                    // SAFETY: `0 < count`; the removed queue is owned here.
                    unsafe { free_queue(queues.remove(0)) };
                }
            }
            while inner.redirects.count != 0 {
                // SAFETY: `0 < count`; the removed redirect is owned here.
                unsafe {
                    let redirect = inner.redirects.remove(0);
                    unlink_sessions(inner, redirect);
                    free_redirect(redirect);
                }
            }
        }
        // SAFETY: the timer and DPC were initialized by `create`; the instance
        // is detached, so nothing arms them again.
        unsafe {
            KeCancelTimer(this.timer.as_ptr());
            KeRemoveQueueDpc(this.dpc.as_ptr());
        }
        // SAFETY: the block came from `memory::allocate`; nothing uses it now.
        unsafe { memory::free(instance.as_ptr().cast()) };
    }

    fn lock(&self) -> Guard<'_> {
        // SAFETY: the spin lock word lives in the instance for its lifetime.
        let irql = unsafe { xboxkrnl::KfAcquireSpinLock(self.lock.as_ptr()) };
        Guard {
            instance: self,
            irql,
        }
    }

    pub(super) fn context(&self) -> usize {
        self as *const Self as usize
    }

    /// Chain a capture (0x91f8d428): set only while nothing is chained.
    pub(super) fn chain(&self, hook: Option<FrameHook>, receive_first: bool) {
        let mut guard = self.lock();
        let inner = guard.inner();
        match hook {
            Some(hook) if inner.chain.is_none() => {
                inner.chain = Some(hook);
                inner.receive_first = receive_first;
            }
            Some(_) => {}
            None => inner.chain = None,
        }
    }

    /// 0x91f8d3d8.
    pub(super) fn set_bypass(&self, active: bool) {
        self.lock().inner().bypass = active;
    }

    pub(super) fn queue_count(&self, direction: Direction) -> u32 {
        self.lock().inner().queues(direction).count
    }

    pub(super) fn redirect_count(&self) -> u32 {
        self.lock().inner().redirects.count
    }

    /// 0x91f8ea98 from the queue allocation on; `update` is validated.
    pub(super) fn insert_queue(
        &self,
        direction: Direction,
        position: Option<QueueIndex>,
        kind: QueueKind,
        update: &QueueConfig,
        program: Option<&Program>,
    ) -> Result<QueueIndex, NetsimError> {
        let mut config = QueueConfig::default();
        config.merge(kind, update)?;
        let program = StoredProgram::store(program)?;
        let queue = memory::allocate(core::mem::size_of::<Queue>())
            .ok_or(NetsimError::OutOfMemory)?
            .cast::<Queue>()
            .as_ptr();
        let mut pipeline = Pipeline::new(kind);
        pipeline.configure(update, now());
        // SAFETY: the block holds a `Queue`.
        unsafe {
            queue.write(Queue {
                next: null_mut(),
                kind,
                config,
                stats: QueueStats::default(),
                pipeline,
                program,
            })
        };
        // SAFETY: the queue is live and unlinked; the chain owns it until it
        // is removed.
        let inserted = unsafe {
            self.lock()
                .inner()
                .queues(direction)
                .insert(position.map(|QueueIndex(index)| index), queue)
        };
        inserted.map(QueueIndex).ok_or_else(|| {
            // SAFETY: not inserted, so still owned here.
            unsafe { free_queue(queue) };
            NetsimError::Invalid
        })
    }

    /// 0x91f8ec80 after validation.
    pub(super) fn modify_queue(
        &self,
        direction: Direction,
        index: QueueIndex,
        update: &QueueConfig,
    ) -> Result<(), NetsimError> {
        let mut guard = self.lock();
        let queue = guard
            .inner()
            .queues(direction)
            .get(index.0)
            .ok_or(NetsimError::Invalid)?;
        // SAFETY: members are live queues; the lock is held.
        let queue = unsafe { &mut *queue };
        queue.config.merge(queue.kind, update)?;
        queue.pipeline.configure(update, now());
        Ok(())
    }

    /// 0x91f8e0e8; removed frames are discarded.
    pub(super) fn remove_queues(
        &self,
        direction: Direction,
        position: Option<QueueIndex>,
    ) -> Result<u32, NetsimError> {
        let mut guard = self.lock();
        let queues = guard.inner().queues(direction);
        match position {
            None => {
                let count = queues.count;
                while queues.count != 0 {
                    // SAFETY: `0 < count`; the removed queue is owned here.
                    unsafe { free_queue(queues.remove(0)) };
                }
                Ok(count)
            }
            Some(QueueIndex(index)) if index < queues.count => {
                // SAFETY: `index < count`; the removed queue is owned here.
                unsafe { free_queue(queues.remove(index)) };
                Ok(1)
            }
            Some(_) => Err(NetsimError::Invalid),
        }
    }

    pub(super) fn queue_stats(
        &self,
        direction: Direction,
        index: QueueIndex,
    ) -> Result<QueueStats, NetsimError> {
        let mut guard = self.lock();
        let queue = guard
            .inner()
            .queues(direction)
            .get(index.0)
            .ok_or(NetsimError::Invalid)?;
        // SAFETY: members are live queues.
        Ok(unsafe { (*queue).stats })
    }

    pub(super) fn queue(
        &self,
        direction: Direction,
        index: QueueIndex,
    ) -> Result<QueueSnapshot, NetsimError> {
        let mut guard = self.lock();
        let queue = guard
            .inner()
            .queues(direction)
            .get(index.0)
            .ok_or(NetsimError::Invalid)?;
        // SAFETY: members are live queues.
        let queue = unsafe { &*queue };
        Ok(QueueSnapshot {
            kind: queue.kind,
            config: queue.config,
            program: StoredProgram::snapshot(&queue.program),
        })
    }

    /// 0x91f8d7c0 from the allocation (0x91f8cd50) on.
    pub(super) fn insert_redirect(
        &self,
        position: Option<RedirectIndex>,
        config: &RedirectConfig,
        program: Option<&Program>,
    ) -> Result<RedirectIndex, NetsimError> {
        let program = StoredProgram::store(program)?;
        let size = core::mem::size_of::<Redirect>()
            + usize::from(config.sessions) * core::mem::size_of::<Session>();
        let redirect = memory::allocate(size)
            .ok_or(NetsimError::OutOfMemory)?
            .cast::<Redirect>()
            .as_ptr();
        // SAFETY: the block holds the header and then the session slots.
        unsafe {
            redirect.write(Redirect {
                next: null_mut(),
                config: *config,
                program,
            });
            let slots = redirect.add(1).cast::<Session>();
            for index in 0..usize::from(config.sessions) {
                slots.add(index).write(Session {
                    next: null_mut(),
                    prev: null_mut(),
                    lookup: Direction::Inbound,
                    protocol: None,
                    last_used: 0,
                    new_address: [0; 4],
                    original_address: [0; 4],
                    new_port: 0,
                    original_port: 0,
                });
            }
        }
        // SAFETY: the redirect is live and unlinked; the chain owns it until
        // it is removed.
        let inserted = unsafe {
            self.lock()
                .inner()
                .redirects
                .insert(position.map(|RedirectIndex(index)| index), redirect)
        };
        inserted.map(RedirectIndex).ok_or_else(|| {
            // SAFETY: not inserted, so still owned here; its slots are in no
            // session list.
            unsafe { free_redirect(redirect) };
            NetsimError::Invalid
        })
    }

    /// 0x91f8d960.
    pub(super) fn remove_redirects(
        &self,
        position: Option<RedirectIndex>,
    ) -> Result<u32, NetsimError> {
        let mut guard = self.lock();
        let inner = guard.inner();
        let (first, count) = match position {
            None => (0, inner.redirects.count),
            Some(RedirectIndex(index)) if index < inner.redirects.count => (index, 1),
            Some(_) => return Err(NetsimError::Invalid),
        };
        for _ in 0..count {
            // SAFETY: each removal at `first` happens while `first < count`;
            // the removed redirect is owned here.
            unsafe {
                let redirect = inner.redirects.remove(first);
                unlink_sessions(inner, redirect);
                free_redirect(redirect);
            }
        }
        Ok(count)
    }

    pub(super) fn redirect(&self, index: RedirectIndex) -> Option<RedirectSnapshot> {
        let mut guard = self.lock();
        let redirect = guard.inner().redirects.get(index.0)?;
        // SAFETY: members are live redirects.
        let redirect = unsafe { &*redirect };
        Some(RedirectSnapshot {
            config: redirect.config,
            program: StoredProgram::snapshot(&redirect.program),
        })
    }
}

/// # Safety
/// `queue` is a live, unlinked queue that the caller owns.
unsafe fn free_queue(queue: *mut Queue) {
    // SAFETY: guaranteed by the caller; the block came from `memory::allocate`.
    unsafe {
        (*queue).pipeline.free_all();
        core::ptr::drop_in_place(queue);
        memory::free(queue.cast());
    }
}

/// # Safety
/// `redirect` is a live, unlinked redirect that the caller owns, with no
/// slot in a session list.
unsafe fn free_redirect(redirect: *mut Redirect) {
    // SAFETY: guaranteed by the caller; the block came from `memory::allocate`.
    unsafe {
        core::ptr::drop_in_place(redirect);
        memory::free(redirect.cast());
    }
}

/// Take the slots of `redirect` out of the session lists.
///
/// # Safety
/// `redirect` is a live redirect from `insert_redirect`.
unsafe fn unlink_sessions(inner: &mut Inner, redirect: *mut Redirect) {
    // SAFETY: guaranteed by the caller; a slot in use is a member of the
    // list its `lookup` names.
    unsafe {
        for slot in Redirect::sessions(redirect).iter_mut() {
            if slot.protocol.is_some() {
                let lookup = slot.lookup;
                inner.sessions(lookup).unlink(slot);
            }
        }
    }
}

/// A flow to remember: `lookup` is the direction of the frames that will
/// be rewritten back.
struct Flow {
    lookup: Direction,
    protocol: FrameFlags,
    new_address: [u8; 4],
    original_address: [u8; 4],
    new_port: u16,
    original_port: u16,
}

/// Claim a session slot of `redirect` (0x91f8ce98): the first free slot or
/// the slot already holding the flow, whichever the scan meets first, else
/// the last slot idle for two minutes. `false` drops the frame.
///
/// # Safety
/// `redirect` is a linked redirect.
unsafe fn claim_session(inner: &mut Inner, redirect: *mut Redirect, flow: &Flow) -> bool {
    let now = TickCount::now().milliseconds();
    let mut idle: Option<*mut Session> = None;
    // SAFETY: guaranteed by the caller.
    for slot in unsafe { Redirect::sessions(redirect) }.iter_mut() {
        let Some(protocol) = slot.protocol else {
            // SAFETY: a free slot is in no list.
            unsafe { fill_session(inner, slot, flow, now) };
            return true;
        };
        if protocol == flow.protocol
            && slot.new_address == flow.new_address
            && slot.original_address == flow.original_address
            && slot.new_port == flow.new_port
            && slot.original_port == flow.original_port
        {
            slot.last_used = now;
            return true;
        }
        if now.wrapping_sub(slot.last_used) >= SESSION_IDLE_MILLISECONDS {
            idle = Some(slot);
        }
    }
    let Some(session) = idle else {
        return false;
    };
    // SAFETY: slots of a live redirect stay valid; a slot in use is a member
    // of the list its `lookup` names, and leaves it before the refill.
    unsafe {
        let slot = &mut *session;
        let lookup = slot.lookup;
        inner.sessions(lookup).unlink(slot);
        fill_session(inner, slot, flow, now);
    }
    true
}

/// # Safety
/// `slot` is a slot of a linked redirect and in no list.
unsafe fn fill_session(inner: &mut Inner, slot: &mut Session, flow: &Flow, now: u32) {
    slot.lookup = flow.lookup;
    slot.protocol = Some(flow.protocol);
    slot.last_used = now;
    slot.new_address = flow.new_address;
    slot.original_address = flow.original_address;
    slot.new_port = flow.new_port;
    slot.original_port = flow.original_port;
    // SAFETY: guaranteed by the caller.
    unsafe { inner.sessions(flow.lookup).push_front(slot) };
}

/// Hand a frame to a chained callback; nonzero means it took the frame.
fn offer(chained: Option<(FrameCallback, usize)>, frame: &mut [u8]) -> bool {
    chained.is_some_and(|(callback, context)| {
        callback(context, frame.as_mut_ptr(), frame.len() as u32) != 0
    })
}

/// Send or indicate a released frame after the chained callback declined it
/// (0x91f8d1d8, 0x91f8d158), then free it.
fn emit(
    direction: Direction,
    mut packet: OwnedPacket,
    chained: Option<(FrameCallback, usize)>,
    transmit_unmodified: u32,
) {
    let redirected = packet.redirected();
    let frame = packet.frame();
    let length = frame.len() as u32;
    if !offer(chained, frame) {
        match direction {
            Direction::Outbound if redirected => {
                // SAFETY: XAM export 0x8e takes (caller, frame, length, flags).
                unsafe {
                    kernel::call_export(
                        transmit_unmodified,
                        XnCaller::SystemApp.raw(),
                        frame.as_mut_ptr() as u32,
                        length,
                        0,
                    );
                }
            }
            Direction::Outbound => {
                // SAFETY: `frame` is the live frame of an owned packet.
                unsafe {
                    NetDll_XnpEthernetInterceptXmit(XnCaller::SystemApp, frame.as_mut_ptr(), length)
                };
            }
            Direction::Inbound => {
                // SAFETY: `frame` is the live frame of an owned packet.
                unsafe {
                    NetDll_XnpEthernetInterceptRecv(XnCaller::SystemApp, frame.as_mut_ptr(), length)
                };
            }
        }
    }
    packet.free();
}

impl Instance {
    /// The frame processor (0x91f8e260); returns whether the frame was
    /// taken from the network stack.
    fn process(&self, direction: Direction, frame: &mut [u8]) -> bool {
        let length = frame.len() as u32;
        let parsed = frame::parse(frame);
        let classified = parsed.ipv4(frame);
        let mut guard = self.lock();
        let inner = guard.inner();
        let mut chained = inner.chained(direction);
        if inner.bypass {
            drop(guard);
            return offer(chained, frame);
        }
        let before = match direction {
            Direction::Inbound => inner.receive_first,
            Direction::Outbound => !inner.receive_first,
        };
        if before && chained.is_some() {
            drop(guard);
            if offer(chained, frame) {
                return true;
            }
            chained = None;
            guard = self.lock();
            if guard.inner().bypass {
                return false;
            }
        }
        let inner = guard.inner();
        let mut packet: Option<OwnedPacket> = None;
        if let Some(info) = classified {
            match redirect(inner, direction, frame, &parsed, info) {
                Redirection::None => {}
                Redirection::Drop => return true,
                Redirection::Pass => return false,
                Redirection::Rewritten(copy) => packet = Some(copy),
            }
        }
        let mut target = None;
        for queue in inner.queues(direction).iter() {
            // SAFETY: members are live queues; the lock is held.
            let accepted = accepts(unsafe { &(*queue).program }, frame, &parsed);
            match accepted {
                Ok(true) => {
                    target = Some(queue);
                    break;
                }
                Ok(false) => {}
                // Stock leaks a rewritten copy here.
                Err(_) => {
                    if let Some(packet) = packet {
                        packet.free();
                    }
                    return false;
                }
            }
        }
        let Some(target) = target else {
            let transmit_unmodified = inner.transmit_unmodified;
            drop(guard);
            return match packet {
                Some(packet) => {
                    emit(direction, packet, chained, transmit_unmodified);
                    true
                }
                None => offer(chained, frame),
            };
        };
        let packet = match packet {
            Some(packet) => packet,
            None => match OwnedPacket::allocate(frame) {
                Some(packet) => packet,
                None => return false,
            },
        };
        // SAFETY: members are live queues; the lock is held.
        let queue = unsafe { &mut *target };
        queue.stats.total_packets = queue.stats.total_packets.wrapping_add(1);
        queue.stats.total_bytes = queue.stats.total_bytes.wrapping_add(u64::from(length));
        let now = now();
        queue.pipeline.enqueue(packet, length, now);
        let next = queue.pipeline.next_time(now);
        inner.schedule(self, now, next);
        true
    }

    /// The release timer (0x91f8dec0): send what every queue releases,
    /// received frames first, and arm the timer for the earliest next
    /// release.
    fn release(&self) {
        let mut guard = self.lock();
        let inner = guard.inner();
        inner.due = None;
        let mut now = now();
        let mut batch = Batch::new();
        let mut next = inner.release(Direction::Inbound, now, &mut batch, None);
        if !batch.is_empty() {
            let chained = if inner.receive_first {
                None
            } else {
                inner.chained(Direction::Inbound)
            };
            let transmit_unmodified = inner.transmit_unmodified;
            drop(guard);
            batch.reverse();
            while let Some(packet) = batch.pop() {
                emit(Direction::Inbound, packet, chained, transmit_unmodified);
            }
            guard = self.lock();
            now = self::now();
        }
        let inner = guard.inner();
        next = inner.release(Direction::Outbound, now, &mut batch, next);
        inner.schedule(self, now, next);
        let chained = if inner.receive_first {
            inner.chained(Direction::Outbound)
        } else {
            None
        };
        let transmit_unmodified = inner.transmit_unmodified;
        drop(guard);
        batch.reverse();
        while let Some(packet) = batch.pop() {
            emit(Direction::Outbound, packet, chained, transmit_unmodified);
        }
    }
}

enum Redirection {
    None,
    /// No session slot is free: the frame is taken and dropped.
    Drop,
    /// A copy could not be made or a classifier failed: the frame passes.
    Pass,
    /// A rewritten copy of the frame.
    Rewritten(OwnedPacket),
}

/// Apply a remembered session, else the first matching redirect.
fn redirect(
    inner: &mut Inner,
    direction: Direction,
    frame: &[u8],
    parsed: &Parsed,
    info: Ipv4Frame,
) -> Redirection {
    let transmit = direction == Direction::Outbound;
    let address = frame::address(frame, transmit);
    let transport = !info.protocol.is_empty();
    let port = if transport {
        frame::port(frame, info, transmit)
    } else {
        0
    };
    let rewrite = |target_address: [u8; 4], target_port: u16| {
        let Some(mut packet) = OwnedPacket::allocate(frame) else {
            return Redirection::Pass;
        };
        packet.set_redirected();
        frame::rewrite(packet.frame(), info, transmit, target_address, target_port);
        Redirection::Rewritten(packet)
    };
    if transport && let Some(session) = inner.sessions(direction).find(info.protocol, address, port)
    {
        // SAFETY: members are live slots.
        let slot = unsafe { &mut *session };
        slot.last_used = TickCount::now().milliseconds();
        return rewrite(slot.original_address, slot.original_port);
    }
    let mut matched = None;
    for redirect in inner.redirects.iter() {
        // SAFETY: members are live redirects.
        let entry = unsafe { &*redirect };
        let config = entry.config;
        if (config.match_address != [0; 4] && config.match_address != address)
            || (config.match_port != 0 && config.match_port != port)
        {
            continue;
        }
        let accepted = accepts(&entry.program, frame, parsed);
        match accepted {
            Ok(true) => {
                matched = Some((redirect, config));
                break;
            }
            Ok(false) => {}
            Err(_) => return Redirection::Pass,
        }
    }
    let Some((redirect, config)) = matched else {
        return Redirection::None;
    };
    let target_address = if config.target_address == [0; 4] {
        address
    } else {
        config.target_address
    };
    let target_port = if config.target_port == 0 {
        port
    } else {
        config.target_port
    };
    if config.sessions > 0 {
        let flow = Flow {
            lookup: if transmit {
                Direction::Inbound
            } else {
                Direction::Outbound
            },
            protocol: info.protocol,
            new_address: target_address,
            original_address: address,
            new_port: target_port,
            original_port: port,
        };
        // SAFETY: `redirect` is a member of the chain.
        if !unsafe { claim_session(inner, redirect, &flow) } {
            return Redirection::Drop;
        }
    }
    rewrite(target_address, target_port)
}

/// Release timer DPC routine (0x91f8ea50).
extern "C" fn release_dpc(_dpc: usize, context: usize, _argument1: usize, _argument2: usize) {
    // SAFETY: the DPC context is the instance, which cancels the timer and
    // dequeues the DPC before it is freed.
    unsafe { &*(context as *const Instance) }.release();
}

/// Transmit intercept (0x91f36470).
pub(super) extern "C" fn transmit(context: usize, frame: *mut u8, length: u32) -> u32 {
    // SAFETY: the intercept context is the registered instance, and the
    // network stack passes a writable frame of `length` bytes.
    let (instance, frame) = unsafe {
        (
            &*(context as *const Instance),
            core::slice::from_raw_parts_mut(frame, length as usize),
        )
    };
    u32::from(instance.process(Direction::Outbound, frame))
}

/// Receive intercept (0x91f364b0).
pub(super) extern "C" fn receive(context: usize, frame: *mut u8, length: u32) -> u32 {
    // SAFETY: as for `transmit`.
    let (instance, frame) = unsafe {
        (
            &*(context as *const Instance),
            core::slice::from_raw_parts_mut(frame, length as usize),
        )
    };
    u32::from(instance.process(Direction::Inbound, frame))
}

crate::exports::bridged!(release_dpc_entry, release_dpc);
crate::exports::bridged!(pub(super) transmit_entry, transmit);
crate::exports::bridged!(pub(super) receive_entry, receive);
