use core::ptr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use xbox360::atomic::Interlocked32;
use xbox360_sys::xboxkrnl::Handle;

use super::AllocatorRecord;
use super::Backoff;
use super::Error;
use super::ItemOrder;
use super::Layout;
use super::NodeAddress;
use super::SemaphoreKind;
use super::Supply;
use super::TaggedList;
use super::Wait;
use super::WaitObject;

/// The node supply of one container, for the routines every container
/// layout shares. The fields are private to this module, so a `Nodes`
/// always comes from [`Nodes::new`].
#[derive(Clone, Copy)]
pub(super) struct Nodes<'a> {
    /// Free nodes, at +0 of every container.
    free: &'a TaggedList,
    supply: &'a Supply,
    /// Allocator word of the container.
    allocator: &'a AtomicU32,
    layout: &'static Layout,
}

impl<'a> Nodes<'a> {
    /// # Safety
    ///
    /// `free`, `supply` and `allocator` are the free list, the supply
    /// fields and the allocator word of one container that creation set
    /// up, whose nodes have `layout`, and that stays allocated for `'a`.
    pub(super) const unsafe fn new(
        free: &'a TaggedList,
        supply: &'a Supply,
        allocator: &'a AtomicU32,
        layout: &'static Layout,
    ) -> Self {
        Self {
            free,
            supply,
            allocator,
            layout,
        }
    }

    pub(super) fn free(&self) -> &'a TaggedList {
        self.free
    }

    pub(super) fn supply(&self) -> &'a Supply {
        self.supply
    }

    pub(super) fn allocator(&self) -> &'a AllocatorRecord {
        // SAFETY: the allocator word of the container (`Nodes::new`).
        unsafe { AllocatorRecord::from_word(self.allocator) }
    }

    fn wait_object(&self, word: &'a AtomicU32) -> Option<WaitObject<'a>> {
        let raw = word.load(Relaxed);
        if raw == 0 {
            return None;
        }

        Some(match self.layout.semaphores {
            // SAFETY: an object-kind container stores the address of its
            // own initialized KSEMAPHORE in its semaphore words.
            SemaphoreKind::Object => {
                WaitObject::Object(unsafe { &*ptr::with_exposed_provenance(raw as usize) })
            }
            SemaphoreKind::Handle => WaitObject::Handle(Handle::from_raw(raw)),
            SemaphoreKind::GatedHandle => WaitObject::GatedHandle(Handle::from_raw(raw)),
        })
    }

    pub(super) fn item_words(&self) -> ItemWords<'a> {
        let [first, second] = &self.supply.items;
        match self.layout.items {
            ItemOrder::SemaphoreFirst => ItemWords {
                semaphore: first,
                count: second,
            },
            ItemOrder::CountFirst => ItemWords {
                semaphore: second,
                count: first,
            },
        }
    }

    pub(super) fn count(&self) -> &'a AtomicU32 {
        self.item_words().count
    }

    pub(super) fn count_added(&self) {
        self.count().fetch_add_relaxed(1);
    }

    pub(super) fn count_removed(&self) {
        self.count().fetch_add_relaxed(1_u32.wrapping_neg());
    }

    pub(super) fn free_semaphore(&self) -> Option<WaitObject<'a>> {
        self.wait_object(&self.supply.free_semaphore)
    }

    pub(super) fn item_semaphore(&self) -> Option<WaitObject<'a>> {
        self.wait_object(self.item_words().semaphore)
    }

    pub(super) fn pop_free(&self) -> Option<NodeAddress> {
        // SAFETY: the free list holds nodes of the container's blocks,
        // linked at the layout's link (module invariants).
        unsafe { self.free.pop(self.layout.link) }
    }

    /// # Safety
    ///
    /// `node` is a node of this container that no list holds.
    pub(super) unsafe fn push_free(&self, node: NodeAddress) {
        // SAFETY: the caller guarantees the node; nodes of the layout
        // hold its link word.
        unsafe { self.free.push(node, self.layout.link) };
    }

    /// Return a node to the free list and wake an insertion waiting for one.
    ///
    /// # Safety
    ///
    /// `node` is a node of this container that no list holds.
    pub(super) unsafe fn release_node(&self, node: NodeAddress) {
        // SAFETY: the caller guarantees the node.
        unsafe { self.push_free(node) };

        if let Some(semaphore) = self.free_semaphore()
            && (self.supply.credits.fetch_add_relaxed(1) as i32).wrapping_add(1) <= 0
        {
            semaphore.release(1);
        }
    }

    /// Wake a remover blocked on the item semaphore.
    pub(super) fn signal_item(&self) {
        if let Some(semaphore) = self.item_semaphore()
            && self.supply.waiters.load(Relaxed) as i32 > 0
        {
            semaphore.release(1);
        }
    }

    /// Allocate a block of `size` bytes for nodes.
    fn allocate_block(&self, size: u32) -> Option<NodeAddress> {
        // SAFETY: the block list of the container.
        unsafe {
            self.allocator()
                .allocate_block(&self.supply.blocks, size, &self.supply.memory)
        }
    }

    /// Take a block of nodes within the limit: all but the first go to the
    /// free list and the first is returned.
    pub(super) fn grow(&self) -> Option<NodeAddress> {
        let supply = self.supply;
        let nodes = supply.remaining.claim(supply.per_block.load(Relaxed))?;

        self.populate(nodes)
    }

    /// Allocate `nodes` nodes, free all but the first and pass the new
    /// credits to waiting insertions; a failed allocation ends growth.
    pub(super) fn populate(&self, nodes: u32) -> Option<NodeAddress> {
        let node_size = self.layout.node_size;
        let size = nodes.wrapping_mul(node_size);
        let Some(block) = self.allocate_block(size) else {
            self.supply.remaining.exhaust();
            return None;
        };

        self.supply.total.fetch_add_relaxed(nodes);

        let mut node = block.raw().wrapping_add(size);
        for _ in 1..nodes {
            node = node.wrapping_sub(node_size);
            // SAFETY: a node inside the new block, which holds `nodes` nodes.
            unsafe { self.push_free(NodeAddress::new_unchecked(node)) };
        }

        if let Some(semaphore) = self.free_semaphore() {
            let previous = self.supply.credits.fetch_add_relaxed(nodes) as i32;
            let spare = (nodes as i32).wrapping_sub(1);
            if previous < -1 && spare > 0 {
                semaphore.release((!previous).min(spare) as u32);
            }
        }

        Some(block)
    }

    /// Take a node for an insertion; with a node limit, wait per `wait`.
    pub(super) fn acquire_node(&self, wait: &Wait) -> Result<NodeAddress, Error> {
        let Some(semaphore) = self.free_semaphore() else {
            if let Some(node) = self.pop_free() {
                return Ok(node);
            }

            if self.supply.remaining.is_exhausted() {
                return Err(Error::Timeout);
            }

            return self.grow().ok_or(Error::Timeout);
        };

        let credits = &self.supply.credits;
        let reserved =
            (credits.fetch_add_relaxed(1_u32.wrapping_neg()) as i32).wrapping_sub(1) >= 0;
        let mut node = if reserved { self.pop_free() } else { None };
        if node.is_none() && !self.supply.remaining.is_exhausted() {
            node = self.grow();
        }

        let mut backoff = Backoff::new();
        if wait.spin {
            for _ in 0..Backoff::SPIN_ATTEMPTS {
                if node.is_some() {
                    break;
                }

                backoff.pause();
                node = self.pop_free();
            }
        }

        loop {
            if let Some(node) = node {
                return Ok(node);
            }

            if wait.spin {
                backoff.pause();
            }

            if let Err(error) = wait.block(semaphore) {
                credits.fetch_add_relaxed(1);
                return Err(error);
            }

            node = self.pop_free();
        }
    }

    /// Run `attempt` until it yields an item: at once, then spinning when
    /// asked, then counted among the waiters and blocking on `semaphore`
    /// between attempts.
    pub(super) fn remove_waiting<T>(
        &self,
        semaphore: WaitObject<'_>,
        wait: &Wait,
        mut attempt: impl FnMut() -> Option<T>,
    ) -> Result<T, Error> {
        if let Some(item) = attempt() {
            return Ok(item);
        }

        let mut backoff = Backoff::new();
        if wait.spin {
            for _ in 0..Backoff::SPIN_ATTEMPTS {
                backoff.pause();
                if let Some(item) = attempt() {
                    return Ok(item);
                }
            }
        }

        let waiters = &self.supply.waiters;
        waiters.fetch_add_relaxed(1);

        loop {
            if let Some(item) = attempt() {
                waiters.fetch_add_relaxed(1_u32.wrapping_neg());
                return Ok(item);
            }

            if wait.spin {
                backoff.pause();
            }

            if let Err(error) = wait.block(semaphore) {
                waiters.fetch_add_relaxed(1_u32.wrapping_neg());
                return Err(error);
            }
        }
    }
}

/// The item semaphore word and the item count of a [`Supply`], in the
/// order of the layout.
pub(super) struct ItemWords<'a> {
    pub(super) semaphore: &'a AtomicU32,
    count: &'a AtomicU32,
}
