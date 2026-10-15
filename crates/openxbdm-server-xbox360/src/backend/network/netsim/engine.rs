//! The simulator instance (stock 0xa8-byte object, vtable 0x91f0d240): queue
//! and redirect lists, the frame processor 0x91f8e260, and the release
//! timer 0x91f8dec0. Everything below the spin lock is shared with the
//! network stack's intercept callbacks and the timer DPC.

use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::ptr::null_mut;

use openxbdm_core::status::Hresult;
use openxbdm_server::commands::network::netsim::Direction;
use openxbdm_server::commands::network::netsim::Program;
use openxbdm_server::commands::network::netsim::QueueConfig;
use openxbdm_server::commands::network::netsim::QueueKind;
use openxbdm_server::commands::network::netsim::QueueSnapshot;
use openxbdm_server::commands::network::netsim::QueueStats;
use openxbdm_server::commands::network::netsim::RedirectConfig;
use openxbdm_server::commands::network::netsim::RedirectSnapshot;
use openxbdm_server::commands::network::netsim::status;

use super::KeCancelTimer;
use super::KeInitializeDpc;
use super::KeInitializeTimerEx;
use super::KeRemoveQueueDpc;
use super::NetDll_XnpEthernetInterceptRecv;
use super::NetDll_XnpEthernetInterceptXmit;
use super::XeCryptRandom;
use super::filter;
use super::frame;
use super::frame::Ipv4Frame;
use super::frame::Parsed;
use super::frame::Protocol;
use super::memory;
use super::pipeline::NEVER;
use super::pipeline::Packet;
use super::pipeline::Pipeline;
use super::pipeline::Random;
use super::set_timer;
use crate::backend::network::FrameCallback;
use crate::backend::network::FrameHook;
use crate::backend::network::XNCALLER_SYSAPP;
use crate::kernel;

/// Idle time after which a redirect session may be reused (120 s).
const SESSION_IDLE_MILLISECONDS: u32 = 120_000;
/// `KDPC` byte stock sets after initialization.
const DPC_IMPORTANCE_OFFSET: usize = 3;
const DPC_IMPORTANCE: u8 = 3;

/// Kernel object storage.
#[repr(C, align(8))]
struct KernelObject<const N: usize>(UnsafeCell<[u8; N]>);

impl<const N: usize> KernelObject<N> {
    fn as_ptr(&self) -> *mut u8 {
        self.0.get().cast()
    }
}

/// `XeCryptRandom`.
struct CryptRandom;

impl Random for CryptRandom {
    fn fill(&mut self, buffer: &mut [u8]) {
        XeCryptRandom(buffer.as_mut_ptr(), buffer.len() as u32);
    }
}

/// The time base, read again when its low word is zero as stock does.
fn now() -> u64 {
    let time = kernel::timebase();
    if time as u32 == 0 {
        kernel::timebase()
    } else {
        time
    }
}

/// A classifier copy in its own pool block, as stock keeps queue +0x08 and
/// the redirect classifier: queues and redirects without one stay small.
struct StoredProgram(NonNull<Program>);

impl StoredProgram {
    fn new(program: &Program) -> Result<Self, Hresult> {
        let block = memory::allocate(core::mem::size_of::<Program>())
            .ok_or(status::OUT_OF_MEMORY)?
            .cast::<Program>();
        // SAFETY: the block holds a `Program`; pool blocks are 8-aligned.
        unsafe {
            block.write(*program);
            Ok(Self(NonNull::new_unchecked(block)))
        }
    }

    fn store(program: Option<&Program>) -> Result<Option<Self>, Hresult> {
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
        memory::free(self.0.as_ptr().cast());
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
    /// `None` while free.
    protocol: Option<Protocol>,
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
    fn sessions<'a>(redirect: *mut Redirect) -> &'a mut [Session] {
        // SAFETY: `allocate_redirect` placed `sessions` slots after the
        // header.
        unsafe {
            let count = usize::from((*redirect).config.sessions);
            core::slice::from_raw_parts_mut(redirect.add(1).cast::<Session>(), count)
        }
    }
}

/// A singly linked list with positions.
trait Chained: Sized {
    fn next(node: *mut Self) -> *mut *mut Self;
}

impl Chained for Queue {
    fn next(node: *mut Self) -> *mut *mut Self {
        // SAFETY: callers pass live nodes.
        unsafe { &raw mut (*node).next }
    }
}

impl Chained for Redirect {
    fn next(node: *mut Self) -> *mut *mut Self {
        // SAFETY: callers pass live nodes.
        unsafe { &raw mut (*node).next }
    }
}

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
    fn link(&mut self, index: u32) -> *mut *mut T {
        let mut link = &raw mut self.head;
        for _ in 0..index {
            // SAFETY: `index` is at most `count`, so every link followed is
            // a live node.
            link = T::next(unsafe { *link });
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
    fn insert(&mut self, position: Option<u32>, node: *mut T) -> Option<u32> {
        let index = match position {
            None => self.count,
            Some(index) if index < self.count => index,
            Some(_) => return None,
        };
        let link = self.link(index);
        // SAFETY: `link` is a link of the chain and `node` is unlinked.
        unsafe {
            *T::next(node) = *link;
            *link = node;
        }
        self.count += 1;
        Some(index)
    }

    fn remove(&mut self, index: u32) -> *mut T {
        let link = self.link(index);
        // SAFETY: the caller checked `index < count`.
        unsafe {
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

/// Head of a session list.
struct SessionList(*mut Session);

impl SessionList {
    fn push_front(&mut self, session: *mut Session) {
        // SAFETY: `session` is a live slot not in any list.
        unsafe {
            (*session).prev = null_mut();
            (*session).next = self.0;
            if !self.0.is_null() {
                (*self.0).prev = session;
            }
        }
        self.0 = session;
    }

    fn unlink(&mut self, session: *mut Session) {
        // SAFETY: `session` is a member.
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

    fn find(&self, protocol: Protocol, address: [u8; 4], port: u16) -> Option<*mut Session> {
        let mut session = self.0;
        // SAFETY: members are live slots.
        unsafe {
            while !session.is_null() {
                let slot = &*session;
                if slot
                    .protocol
                    .is_some_and(|stored| stored.0 & protocol.0 != 0)
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
    /// Release time the timer is set for (+0x48).
    due: u64,
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
    fn schedule(&mut self, instance: &Instance, now: u64, next: u64) {
        if next >= self.due {
            return;
        }
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
        set_timer(
            instance.timer.as_ptr(),
            (due >> 32) as u32,
            due as u32,
            instance.dpc.as_ptr(),
        );
        self.due = next;
    }

    /// Take ready frames of every queue of `direction` (0x91f8d280); returns
    /// the earliest next release time.
    fn release(&mut self, direction: Direction, now: u64, batch: &mut Batch, mut next: u64) -> u64 {
        let mut random = CryptRandom;
        for queue in self.queues(direction).iter() {
            // SAFETY: members are live queues.
            let queue = unsafe { &mut *queue };
            while let Some(released) = queue.pipeline.dequeue(now, &mut random) {
                if released.dropped {
                    queue.stats.dropped_packets = queue.stats.dropped_packets.wrapping_add(1);
                    // SAFETY: released packets are live and unlinked.
                    let length = unsafe { (*released.packet).length };
                    queue.stats.dropped_bytes =
                        queue.stats.dropped_bytes.wrapping_add(u64::from(length));
                    // SAFETY: as above.
                    unsafe { Packet::free(released.packet) };
                } else {
                    batch.push(released.packet);
                }
            }
            next = next.min(queue.pipeline.next_time(now));
        }
        next
    }
}

/// Released frames waiting to leave once the lock is dropped.
struct Batch {
    packets: *mut Packet,
}

impl Batch {
    fn push(&mut self, packet: *mut Packet) {
        // Packets out of every stage are unlinked; the frame bytes stay
        // untouched, so the first word of the header carries the batch.
        // SAFETY: `packet` is a live, unlinked packet.
        unsafe { packet.cast::<*mut Packet>().write(self.packets) };
        self.packets = packet;
    }

    fn pop(&mut self) -> Option<*mut Packet> {
        (!self.packets.is_null()).then(|| {
            let packet = self.packets;
            // SAFETY: pushed packets keep the link in their first word.
            self.packets = unsafe { packet.cast::<*mut Packet>().read() };
            packet
        })
    }

    /// Frames leave in release order.
    fn reverse(&mut self) {
        let mut reversed = Batch {
            packets: null_mut(),
        };
        while let Some(packet) = self.pop() {
            reversed.push(packet);
        }
        *self = reversed;
    }
}

/// The instance; lives in pool memory at a fixed address because the timer,
/// the DPC, and the intercept context point into it.
pub(super) struct Instance {
    timer: KernelObject<0x28>,
    dpc: KernelObject<0x1c>,
    lock: UnsafeCell<u32>,
    inner: UnsafeCell<Inner>,
}

/// The locked state.
struct Guard<'a> {
    instance: &'a Instance,
    irql: u32,
}

impl Guard<'_> {
    fn inner(&mut self) -> &mut Inner {
        // SAFETY: the spin lock is held.
        unsafe { &mut *self.instance.inner.get() }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        kernel::KfReleaseSpinLock(self.instance.lock.get(), self.irql);
    }
}

// SAFETY: `inner` is only reached under the spin lock; the kernel objects
// are used through kernel calls.
unsafe impl Sync for Instance {}

impl Instance {
    /// Allocate and initialize (0x91f8ee60, 0x91f8ed88, 0x91f8c758).
    pub(super) fn create() -> Result<NonNull<Instance>, Hresult> {
        let instance = memory::allocate(core::mem::size_of::<Instance>())
            .ok_or(status::OUT_OF_MEMORY)?
            .cast::<Instance>();
        // SAFETY: the block is large enough and pool blocks are 8-aligned.
        unsafe {
            instance.write(Instance {
                timer: KernelObject(UnsafeCell::new([0; 0x28])),
                dpc: KernelObject(UnsafeCell::new([0; 0x1c])),
                lock: UnsafeCell::new(0),
                inner: UnsafeCell::new(Inner {
                    inbound: Chain::new(),
                    outbound: Chain::new(),
                    redirects: Chain::new(),
                    receive_sessions: SessionList(null_mut()),
                    transmit_sessions: SessionList(null_mut()),
                    due: NEVER,
                    chain: None,
                    receive_first: false,
                    bypass: false,
                    transmit_unmodified: 0,
                }),
            });
            let this = &*instance;
            KeInitializeTimerEx(this.timer.as_ptr(), 0);
            KeInitializeDpc(
                this.dpc.as_ptr(),
                release_dpc_entry as *const () as usize,
                instance as usize,
            );
            this.dpc
                .as_ptr()
                .add(DPC_IMPORTANCE_OFFSET)
                .write(DPC_IMPORTANCE);
        }
        // SAFETY: just initialized.
        let this = unsafe { &*instance };
        match super::super::xam_procedure(0x8e) {
            Some(address) => this.lock().inner().transmit_unmodified = address,
            None => {
                Instance::destroy(instance);
                return Err(Hresult::error(0xe));
            }
        }
        // SAFETY: allocation succeeded.
        Ok(unsafe { NonNull::new_unchecked(instance) })
    }

    /// Remove every queue and redirect, stop the timer, and free the
    /// instance (0x91f8e788). Stock leaves the redirects allocated.
    pub(super) fn destroy(instance: *mut Instance) {
        // SAFETY: the caller owns the instance and has detached it.
        let this = unsafe { &*instance };
        {
            let mut guard = this.lock();
            let inner = guard.inner();
            for direction in [Direction::Inbound, Direction::Outbound] {
                let queues = inner.queues(direction);
                while queues.count != 0 {
                    free_queue(queues.remove(0));
                }
            }
            while inner.redirects.count != 0 {
                let redirect = inner.redirects.remove(0);
                unlink_sessions(inner, redirect);
                free_redirect(redirect);
            }
        }
        KeCancelTimer(this.timer.as_ptr());
        KeRemoveQueueDpc(this.dpc.as_ptr());
        memory::free(instance.cast());
    }

    fn lock(&self) -> Guard<'_> {
        let irql = kernel::KfAcquireSpinLock(self.lock.get());
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
        position: Option<u32>,
        kind: QueueKind,
        update: &QueueConfig,
        program: Option<&Program>,
    ) -> Result<u32, Hresult> {
        let mut config = QueueConfig::default();
        config.merge(kind, update)?;
        let program = StoredProgram::store(program)?;
        let queue = memory::allocate(core::mem::size_of::<Queue>())
            .ok_or(status::OUT_OF_MEMORY)?
            .cast::<Queue>();
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
        let inserted = self
            .lock()
            .inner()
            .queues(direction)
            .insert(position, queue);
        inserted.ok_or_else(|| {
            free_queue(queue);
            status::INVALID
        })
    }

    /// 0x91f8ec80 after validation.
    pub(super) fn modify_queue(
        &self,
        direction: Direction,
        index: u32,
        update: &QueueConfig,
    ) -> Result<(), Hresult> {
        let mut guard = self.lock();
        let queue = guard
            .inner()
            .queues(direction)
            .get(index)
            .ok_or(status::INVALID)?;
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
        position: Option<u32>,
    ) -> Result<u32, Hresult> {
        let mut guard = self.lock();
        let queues = guard.inner().queues(direction);
        match position {
            None => {
                let count = queues.count;
                while queues.count != 0 {
                    free_queue(queues.remove(0));
                }
                Ok(count)
            }
            Some(index) if index < queues.count => {
                free_queue(queues.remove(index));
                Ok(1)
            }
            Some(_) => Err(status::INVALID),
        }
    }

    pub(super) fn queue_stats(
        &self,
        direction: Direction,
        index: u32,
    ) -> Result<QueueStats, Hresult> {
        let mut guard = self.lock();
        let queue = guard
            .inner()
            .queues(direction)
            .get(index)
            .ok_or(status::INVALID)?;
        // SAFETY: members are live queues.
        Ok(unsafe { (*queue).stats })
    }

    pub(super) fn queue(&self, direction: Direction, index: u32) -> Result<QueueSnapshot, Hresult> {
        let mut guard = self.lock();
        let queue = guard
            .inner()
            .queues(direction)
            .get(index)
            .ok_or(status::INVALID)?;
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
        position: Option<u32>,
        config: &RedirectConfig,
        program: Option<&Program>,
    ) -> Result<u32, Hresult> {
        let program = StoredProgram::store(program)?;
        let size = core::mem::size_of::<Redirect>()
            + usize::from(config.sessions) * core::mem::size_of::<Session>();
        let redirect = memory::allocate(size)
            .ok_or(status::OUT_OF_MEMORY)?
            .cast::<Redirect>();
        // SAFETY: the block holds the header and the session slots.
        unsafe {
            redirect.write(Redirect {
                next: null_mut(),
                config: *config,
                program,
            })
        };
        for slot in Redirect::sessions(redirect).iter_mut() {
            // SAFETY: the slot lies in the block.
            unsafe {
                (slot as *mut Session).write(Session {
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
        let inserted = self.lock().inner().redirects.insert(position, redirect);
        inserted.ok_or_else(|| {
            free_redirect(redirect);
            status::INVALID
        })
    }

    /// 0x91f8d960.
    pub(super) fn remove_redirects(&self, position: Option<u32>) -> Result<u32, Hresult> {
        let mut guard = self.lock();
        let inner = guard.inner();
        let (first, count) = match position {
            None => (0, inner.redirects.count),
            Some(index) if index < inner.redirects.count => (index, 1),
            Some(_) => return Err(status::INVALID),
        };
        for _ in 0..count {
            let redirect = inner.redirects.remove(first);
            unlink_sessions(inner, redirect);
            free_redirect(redirect);
        }
        Ok(count)
    }

    pub(super) fn redirect(&self, index: u32) -> Option<RedirectSnapshot> {
        let mut guard = self.lock();
        let redirect = guard.inner().redirects.get(index)?;
        // SAFETY: members are live redirects.
        let redirect = unsafe { &*redirect };
        Some(RedirectSnapshot {
            config: redirect.config,
            program: StoredProgram::snapshot(&redirect.program),
        })
    }
}

fn free_queue(queue: *mut Queue) {
    // SAFETY: the queue is unlinked and owned by the caller.
    unsafe {
        (*queue).pipeline.free_all();
        core::ptr::drop_in_place(queue);
    }
    memory::free(queue.cast());
}

fn free_redirect(redirect: *mut Redirect) {
    // SAFETY: the redirect is unlinked and owned by the caller.
    unsafe { core::ptr::drop_in_place(redirect) };
    memory::free(redirect.cast());
}

fn unlink_sessions(inner: &mut Inner, redirect: *mut Redirect) {
    for slot in Redirect::sessions(redirect).iter_mut() {
        if slot.protocol.is_some() {
            let lookup = slot.lookup;
            inner.sessions(lookup).unlink(slot);
        }
    }
}

/// A flow to remember: `lookup` is the direction of the frames that will
/// be rewritten back.
struct Flow {
    lookup: Direction,
    protocol: Protocol,
    new_address: [u8; 4],
    original_address: [u8; 4],
    new_port: u16,
    original_port: u16,
}

/// Claim a session slot of `redirect` (0x91f8ce98): the first free slot or
/// the slot already holding the flow, whichever the scan meets first, else
/// the last slot idle for two minutes. `false` drops the frame.
fn claim_session(inner: &mut Inner, redirect: *mut Redirect, flow: &Flow) -> bool {
    let now = kernel::tick_count();
    let mut idle: Option<*mut Session> = None;
    for slot in Redirect::sessions(redirect).iter_mut() {
        let Some(protocol) = slot.protocol else {
            fill_session(inner, slot, flow, now);
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
    // SAFETY: slots of a live redirect stay valid.
    let slot = unsafe { &mut *session };
    let lookup = slot.lookup;
    inner.sessions(lookup).unlink(slot);
    fill_session(inner, slot, flow, now);
    true
}

fn fill_session(inner: &mut Inner, slot: &mut Session, flow: &Flow, now: u32) {
    slot.lookup = flow.lookup;
    slot.protocol = Some(flow.protocol);
    slot.last_used = now;
    slot.new_address = flow.new_address;
    slot.original_address = flow.original_address;
    slot.new_port = flow.new_port;
    slot.original_port = flow.original_port;
    inner.sessions(flow.lookup).push_front(slot);
}

/// Hand a frame to a chained callback; nonzero means it took the frame.
fn offer(chained: Option<(FrameCallback, usize)>, frame: *mut u8, length: u32) -> bool {
    chained.is_some_and(|(callback, context)| callback(context, frame, length) != 0)
}

/// Send or indicate a released frame after the chained callback declined it
/// (0x91f8d1d8, 0x91f8d158), then free it.
fn emit(
    direction: Direction,
    packet: *mut Packet,
    chained: Option<(FrameCallback, usize)>,
    transmit_unmodified: u32,
) {
    // SAFETY: released packets are live and owned here.
    let (frame, redirected) = unsafe { (Packet::frame(packet), (*packet).redirected) };
    let length = frame.len() as u32;
    if !offer(chained, frame.as_mut_ptr(), length) {
        match direction {
            Direction::Outbound if redirected => {
                // SAFETY: XAM export 0x8e takes (caller, frame, length, flags).
                unsafe {
                    kernel::call_export(
                        transmit_unmodified,
                        XNCALLER_SYSAPP,
                        frame.as_mut_ptr() as u32,
                        length,
                        0,
                    );
                }
            }
            Direction::Outbound => {
                NetDll_XnpEthernetInterceptXmit(XNCALLER_SYSAPP, frame.as_mut_ptr(), length);
            }
            Direction::Inbound => {
                NetDll_XnpEthernetInterceptRecv(XNCALLER_SYSAPP, frame.as_mut_ptr(), length);
            }
        }
    }
    // SAFETY: as above.
    unsafe { Packet::free(packet) };
}

impl Instance {
    /// The frame processor (0x91f8e260); returns whether the frame was
    /// taken from the network stack.
    fn process(&self, direction: Direction, frame_pointer: *mut u8, length: u32) -> bool {
        // SAFETY: the network stack passes a frame of `length` bytes.
        let frame = unsafe { core::slice::from_raw_parts_mut(frame_pointer, length as usize) };
        let parsed = frame::parse(frame);
        let classified = parsed.ipv4(frame);
        let mut guard = self.lock();
        let inner = guard.inner();
        let mut chained = inner.chained(direction);
        if inner.bypass {
            drop(guard);
            return offer(chained, frame_pointer, length);
        }
        let before = match direction {
            Direction::Inbound => inner.receive_first,
            Direction::Outbound => !inner.receive_first,
        };
        if before && chained.is_some() {
            drop(guard);
            if offer(chained, frame_pointer, length) {
                return true;
            }
            chained = None;
            guard = self.lock();
            if guard.inner().bypass {
                return false;
            }
        }
        let inner = guard.inner();
        let mut packet: Option<*mut Packet> = None;
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
                        // SAFETY: the copy is owned here.
                        unsafe { Packet::free(packet) };
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
                None => offer(chained, frame_pointer, length),
            };
        };
        let packet = match packet {
            Some(packet) => packet,
            None => match Packet::allocate(frame) {
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
        inner.due = NEVER;
        let mut now = now();
        let mut batch = Batch {
            packets: null_mut(),
        };
        let mut next = inner.release(Direction::Inbound, now, &mut batch, NEVER);
        if !batch.packets.is_null() {
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
    Rewritten(*mut Packet),
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
    let port = if info.protocol.is_transport() {
        frame::port(frame, info, transmit)
    } else {
        0
    };
    let rewrite = |target_address: [u8; 4], target_port: u16| {
        let Some(packet) = Packet::allocate(frame) else {
            return Redirection::Pass;
        };
        // SAFETY: the packet was just allocated.
        unsafe {
            (*packet).redirected = true;
            frame::rewrite(
                Packet::frame(packet),
                info,
                transmit,
                target_address,
                target_port,
            );
        }
        Redirection::Rewritten(packet)
    };
    if info.protocol.is_transport()
        && let Some(session) = inner.sessions(direction).find(info.protocol, address, port)
    {
        // SAFETY: members are live slots.
        let slot = unsafe { &mut *session };
        slot.last_used = kernel::tick_count();
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
        if !claim_session(inner, redirect, &flow) {
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
    // SAFETY: the intercept context is the registered instance.
    u32::from(unsafe { &*(context as *const Instance) }.process(Direction::Outbound, frame, length))
}

/// Receive intercept (0x91f364b0).
pub(super) extern "C" fn receive(context: usize, frame: *mut u8, length: u32) -> u32 {
    // SAFETY: as for `transmit`.
    u32::from(unsafe { &*(context as *const Instance) }.process(Direction::Inbound, frame, length))
}

crate::exports::bridged!(release_dpc_entry, release_dpc);
crate::exports::bridged!(pub(super) transmit_entry, transmit);
crate::exports::bridged!(pub(super) receive_entry, receive);
