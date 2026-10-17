//! Priority queue 'LFPQ' (exports 320-328): a sorted list in the queue
//! object layout, keyed by the low word of each item through the compare
//! routine. Hash table buckets use the same list routines.
//!
//! A list starts after the sentinel node whose address the object (+0x10)
//! or the bucket holds.

use core::ptr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_core::status::Hresult;
use xbox360::atomic::Interlocked32;

use super::Backoff;
use super::Creation;
use super::Error;
use super::ListNode;
use super::NodeAddress;
use super::NodeWord;
use super::Nodes;
use super::OptionFlags;
use super::OptionsRecord;
use super::OutputWord;
use super::Routine;
use super::Side;
use super::Signature;
use super::Tagged;
use super::Wait;
use super::insert_result;
use super::queue::Kept;
use super::queue::Queue;
use super::removed;
use super::report;
use super::success_result;
use super::walk;
use crate::exports::export;

/// Sort key of an item.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Key(pub(super) u32);

impl Key {
    /// Key stock stores in a node it unlinks.
    const RETIRED: Self = Self(u32::MAX);
}

/// An item as nodes hold it.
pub(super) struct Item {
    pub(super) value: u32,
    pub(super) key: Key,
}

/// Options of a sorted container (caller-visible, 0x24 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SortedOptions {
    /// `compare(key, key)`: below, equal to or above zero.
    compare: Routine,
    /// `hash(key, buckets)`: the bucket index.
    pub(super) hash: Routine,
    options: OptionsRecord,
}

const _: () = {
    assert!(core::mem::offset_of!(SortedOptions, options) == 0x8);
    assert!(size_of::<SortedOptions>() == 0x24);
};

/// Compare descriptor (caller record, 0xc bytes).
#[repr(C)]
struct CompareDescriptor {
    compare: Option<Routine>,
    hash: Option<Routine>,
    /// [`CompareDescriptor::SIZE`].
    size: u32,
}

impl CompareDescriptor {
    const SIZE: u32 = size_of::<Self>() as u32;
}

/// Unsigned order of two keys: -1, 0 or 1.
extern "C" fn default_compare(left: u32, right: u32) -> u32 {
    left.cmp(&right) as i32 as u32
}

/// Bucket of `key` among a power-of-two count of `buckets`.
extern "C" fn default_hash(key: u32, buckets: u32) -> u32 {
    let mixed = u64::from(key)
        .wrapping_mul(SortedOptions::HASH_MULTIPLIER)
        .wrapping_add(SortedOptions::HASH_INCREMENT);
    (mixed >> 32) as u32 & buckets.wrapping_sub(1)
}

/// Options of a sorted container and whether the compare descriptor
/// supplied a hash routine.
pub(super) struct Sorted {
    pub(super) options: SortedOptions,
    pub(super) custom_hash: bool,
}

impl SortedOptions {
    const HASH_MULTIPLIER: u64 = 0xfaf5_7cee_8543_3e40;
    const HASH_INCREMENT: u64 = 0xfc2d_7230_d92f_2eac;

    /// Options from a creation and the compare descriptor at `compare` (0
    /// for none): the routines default to unsigned order and
    /// multiplicative hashing.
    ///
    /// # Safety
    ///
    /// `compare` is 0 or the address of a compare descriptor (export
    /// contract), whose routine fields hold console routines.
    pub(super) unsafe fn read(creation: &Creation, compare: u32) -> Result<Sorted, Error> {
        let mut options = Self {
            compare: Routine::from(default_compare as extern "C" fn(u32, u32) -> u32),
            hash: Routine::from(default_hash as extern "C" fn(u32, u32) -> u32),
            options: creation.options(),
        };
        let mut custom_hash = false;
        // SAFETY: the caller guarantees the descriptor.
        let descriptor =
            unsafe { ptr::with_exposed_provenance::<CompareDescriptor>(compare as usize).as_ref() };
        if let Some(descriptor) = descriptor {
            if descriptor.size != CompareDescriptor::SIZE {
                return Err(Error::InvalidArgument);
            }
            if let Some(routine) = descriptor.compare {
                options.compare = routine;
            }
            if let Some(hash) = descriptor.hash {
                options.hash = hash;
                custom_hash = true;
            }
        }
        Ok(Sorted {
            options,
            custom_hash,
        })
    }

    /// Wait behavior and search of an insertion.
    pub(super) fn insert_wait(&self) -> (Wait, Search) {
        let flags = self.options.flags;
        let search = if flags.contains(OptionFlags::UNIQUE_KEYS) {
            Search::Exact
        } else {
            Search::After
        };
        (
            self.options
                .wait_with(flags, Side::Insert)
                .unwrap_or(Wait::NONE),
            search,
        )
    }

    pub(super) fn remove_wait(&self) -> Wait {
        self.options.wait(Side::Remove).unwrap_or(Wait::NONE)
    }
}

/// Search mode of a list walk.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Search {
    /// Stop before the first greater key, so equal keys stay in arrival
    /// order.
    After,
    /// Stop at the first node.
    First,
    /// Stop at the first key not less than the key; found when equal.
    Exact,
}

/// Result of a list walk.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The list was empty at the first look.
    Empty,
    Missing,
    Found,
}

/// Where a walk stopped: the node whose link points at `current`, that
/// link, and the link of `current`.
struct Position<'a> {
    outcome: Outcome,
    previous: &'a ListNode,
    link: Tagged,
    current: Option<NodeAddress>,
    next: Tagged,
}

/// What a woken remover does after its attempt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Handoff {
    /// Wake another remover when the list held only other keys.
    Missing,
    /// Wake another remover while the container counts items.
    Items,
}

/// Whether a remover blocks when it finds no item.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Blocking {
    Wait,
    Once,
}

/// A sorted list of a priority queue or hash table bucket. The fields are
/// private to this module, so a `SortedList` always comes from
/// [`SortedList::new`].
pub(super) struct SortedList<'a> {
    /// Word holding the address of the sentinel node.
    head: &'a AtomicU32,
    nodes: &'a Nodes<'a>,
    options: &'a SortedOptions,
}

impl<'a> SortedList<'a> {
    /// # Safety
    ///
    /// `head` is the sentinel word of a sorted list of the container that
    /// `nodes` and `options` belong to.
    pub(super) unsafe fn new(
        head: &'a AtomicU32,
        nodes: &'a Nodes<'a>,
        options: &'a SortedOptions,
    ) -> Self {
        Self {
            head,
            nodes,
            options,
        }
    }

    fn compare(&self, left: Key, right: Key) -> i32 {
        self.options.compare.call(left.0, right.0, 0, 0) as i32
    }

    fn node(&self, address: NodeAddress) -> &'a ListNode {
        // SAFETY: the links of a sorted list name nodes of its container
        // (module invariants).
        unsafe { address.get(self.nodes.free()) }
    }

    fn sentinel(&self) -> &'a ListNode {
        // SAFETY: the head of a sorted list always holds the address of its
        // sentinel node, which creation took from the container's blocks.
        self.node(unsafe { NodeAddress::new_unchecked(self.head.load(Relaxed)) })
    }

    /// Walk the list, unlinking and freeing deleted nodes on the way.
    fn find(&self, key: Key, search: Search) -> Position<'a> {
        let mut next = Tagged(0);
        let mut visited = false;
        'restart: loop {
            let mut previous = self.sentinel();
            let mut link = previous.next.load();
            loop {
                let Some(current) = link.address() else {
                    let outcome = if visited {
                        Outcome::Missing
                    } else {
                        Outcome::Empty
                    };
                    return Position {
                        outcome,
                        previous,
                        link,
                        current: None,
                        next,
                    };
                };
                let current_node = self.node(current);
                next = current_node.next.load();
                visited = true;
                let current_key = Key(current_node.item.low.load(Relaxed));
                if link.is_deleted() || previous.next.load() != link {
                    continue 'restart;
                }
                if next.is_deleted() {
                    if !previous
                        .next
                        .compare_exchange(link, link.successor(next.high()))
                    {
                        continue 'restart;
                    }
                    // SAFETY: the exchange unlinked the deleted node.
                    unsafe { self.nodes.release_node(current) };
                    // Stock keeps the deleted node's mark in the expected
                    // link, so the walk restarts unless the list ends here.
                    link = Tagged::new(
                        next.high(),
                        (next.low() & Tagged::DELETED)
                            | (link.low().wrapping_add(1) & !Tagged::DELETED),
                    );
                    next = link;
                    continue;
                }
                let outcome = match search {
                    Search::First => Outcome::Found,
                    Search::After if self.compare(key, current_key) >= 0 => {
                        previous = current_node;
                        link = next;
                        continue;
                    }
                    Search::After => Outcome::Missing,
                    Search::Exact => match self.compare(key, current_key) {
                        order if order > 0 => {
                            previous = current_node;
                            link = next;
                            continue;
                        }
                        0 => Outcome::Found,
                        _ => Outcome::Missing,
                    },
                };
                return Position {
                    outcome,
                    previous,
                    link,
                    current: Some(current),
                    next,
                };
            }
        }
    }

    /// Insert an item; with unique keys a present key fails.
    pub(super) fn insert(&self, item: Item, wait: &Wait, search: Search) -> Result<(), Error> {
        let address = self.nodes.acquire_node(wait)?;
        let node = self.node(address);
        node.next.high.store(0, Relaxed);
        node.next.low.store(
            (node.next.low.load(Relaxed) & !Tagged::DELETED).wrapping_add(1),
            Relaxed,
        );
        node.item.high.store(item.value, Relaxed);
        node.item.low.store(item.key.0, Relaxed);
        loop {
            let position = self.find(item.key, search);
            if position.outcome == Outcome::Found {
                // SAFETY: the node is on no list.
                unsafe { self.nodes.release_node(address) };
                return Err(Error::DuplicateKey);
            }
            node.next
                .high
                .store(position.current.map_or(0, NodeAddress::raw), Relaxed);
            node.next
                .low
                .store(node.next.low.load(Relaxed) & !Tagged::DELETED, Relaxed);
            if position
                .previous
                .next
                .compare_exchange(position.link, position.link.successor(address.raw()))
            {
                break;
            }
        }
        self.nodes.count_added();
        self.nodes.signal_item();
        Ok(())
    }

    /// Mark and unlink the node the search finds by `item`'s key, and store
    /// its item there.
    fn try_remove(&self, item: &mut Item, search: Search) -> Outcome {
        let mut position = self.find(item.key, search);
        loop {
            let (Outcome::Found, Some(current)) = (position.outcome, position.current) else {
                return position.outcome;
            };
            let node = self.node(current);
            let removed = node.item.load();
            let next = position.next;
            let marked = Tagged::new(next.high(), next.successor(0).low() | Tagged::DELETED);
            if node.next.compare_exchange(next, marked) {
                if position
                    .previous
                    .next
                    .compare_exchange(position.link, position.link.successor(next.high()))
                {
                    node.item.low.store(Key::RETIRED.0, Relaxed);
                    // SAFETY: the exchange unlinked the node.
                    unsafe { self.nodes.release_node(current) };
                } else {
                    self.find(item.key, search);
                }
                *item = Item {
                    value: removed.high(),
                    key: Key(removed.low()),
                };
                return Outcome::Found;
            }
            position = self.find(item.key, search);
        }
    }

    /// Remove an item, waiting for one when `blocking` and the item
    /// semaphore allow.
    pub(super) fn remove(
        &self,
        item: &mut Item,
        wait: &Wait,
        search: Search,
        blocking: Blocking,
        handoff: Handoff,
    ) -> Result<(), Error> {
        let nodes = self.nodes;
        let mut attempt = || self.try_remove(item, search);
        let found = 'found: {
            let Some(semaphore) = nodes.item_semaphore() else {
                break 'found attempt() == Outcome::Found;
            };
            if attempt() == Outcome::Found {
                break 'found true;
            }
            if blocking == Blocking::Once {
                break 'found false;
            }
            let mut backoff = Backoff::new();
            if wait.spin {
                for _ in 0..Backoff::SPIN_ATTEMPTS {
                    backoff.pause();
                    if attempt() == Outcome::Found {
                        break 'found true;
                    }
                }
            }
            let waiters = &nodes.supply().waiters;
            waiters.fetch_add_relaxed(1);
            let mut outcome = attempt();
            while outcome != Outcome::Found {
                if wait.spin {
                    backoff.pause();
                }
                if let Err(error) = wait.block(semaphore) {
                    waiters.fetch_add_relaxed(1_u32.wrapping_neg());
                    return Err(error);
                }
                outcome = attempt();
                let pass_on = match handoff {
                    Handoff::Missing => outcome == Outcome::Missing,
                    Handoff::Items => nodes.count().load(Relaxed) as i32 > 0,
                };
                if pass_on {
                    semaphore.release(1);
                }
            }
            waiters.fetch_add_relaxed(1_u32.wrapping_neg());
            true
        };
        if !found {
            return Err(Error::Timeout);
        }
        nodes.count_removed();
        Ok(())
    }

    /// Whether the list holds a node that is not deleted.
    pub(super) fn is_occupied(&self) -> bool {
        self.find(Key(0), Search::First).outcome == Outcome::Found
    }

    /// `callback(context, value, node)` in key order until one returns
    /// nonzero.
    pub(super) fn enumerate(&self, context: u32, callback: Routine) -> Result<(), Error> {
        let first = self.sentinel().next.high.load(Relaxed);
        // SAFETY: the nodes linked in this list (module invariants).
        unsafe { walk(first, NodeWord::Word2, context, callback) }
    }
}

/// Priority queue: a queue object whose head holds the sentinel of one
/// sorted list.
#[repr(transparent)]
struct PriorityQueue(Queue);

impl PriorityQueue {
    /// The priority queue at `handle`.
    ///
    /// # Safety
    ///
    /// `handle` is 0 or the address of a priority queue (export contract)
    /// that stays allocated for `'a`.
    unsafe fn from_handle<'a>(handle: u32) -> Option<&'a Self> {
        // SAFETY: the caller guarantees the object; `Self` is a transparent
        // `Queue`.
        unsafe {
            Queue::with_signature(handle, Signature::PRIORITY_QUEUE)
                .map(|queue| &*ptr::from_ref(queue).cast::<Self>())
        }
    }

    fn options(&self) -> &SortedOptions {
        // SAFETY: creation stores the address of the sorted options it wrote
        // after the allocator record.
        unsafe { &*ptr::with_exposed_provenance(self.0.options.load(Relaxed) as usize) }
    }

    fn list<'a>(&'a self, nodes: &'a Nodes<'a>) -> SortedList<'a> {
        // SAFETY: the head word of a priority queue names its sentinel;
        // `nodes` are the queue's.
        unsafe { SortedList::new(&self.0.head.high, nodes, self.options()) }
    }

    /// Remove an item (by key with [`Search::Exact`]).
    fn take(&self, key: Key, search: Search) -> Result<u32, Error> {
        let nodes = self.0.nodes();
        let list = self.list(&nodes);
        let wait = list.options.remove_wait();
        let mut item = Item { value: 0, key };
        list.remove(&mut item, &wait, search, Blocking::Wait, Handoff::Missing)?;
        Ok(item.value)
    }
}

extern "C" fn insert(queue: u32, key: u32, value: u32) -> Hresult {
    // SAFETY: export 320 contract: `queue` is 0 or a priority queue of
    // export 322.
    let Some(queue) = (unsafe { PriorityQueue::from_handle(queue) }) else {
        return Hresult::INVALID_ARGUMENT;
    };
    let nodes = queue.0.nodes();
    let list = queue.list(&nodes);
    let (wait, search) = list.options.insert_wait();
    insert_result(list.insert(
        Item {
            value,
            key: Key(key),
        },
        &wait,
        search,
    ))
}
export!(320, insert);

extern "C" fn memory(queue: u32, output_word: u32) -> Hresult {
    // SAFETY: export 321 contract: `queue` is 0 or a priority queue of
    // export 322; `output_word` is 0 or a writable word.
    let (queue, output_word) = unsafe {
        (
            PriorityQueue::from_handle(queue),
            OutputWord::new(output_word),
        )
    };
    report(
        queue.map(|queue| queue.0.supply.memory.load(Relaxed)),
        output_word,
    )
}
export!(321, memory);

/// `compare` is an optional compare descriptor.
extern "C" fn create(descriptor: u32, compare: u32, output_word: u32) -> Hresult {
    // SAFETY: export 322 contract: `output_word` is 0 or a writable word.
    let Some(output_word) = (unsafe { OutputWord::new(output_word) }) else {
        return Hresult::INVALID_ARGUMENT;
    };
    output_word.store(0);
    // SAFETY: export 322 contract: `descriptor` is 0 or a creation
    // descriptor and `compare` 0 or a compare descriptor.
    let created = unsafe { Creation::read(descriptor) }.and_then(|creation| {
        // SAFETY: as above.
        let sorted = unsafe { SortedOptions::read(&creation, compare) }?;
        Queue::create(
            &creation,
            Signature::PRIORITY_QUEUE,
            Kept::Sorted(&sorted.options),
        )
    });
    match created {
        Ok(queue) => {
            output_word.store(queue.handle());
            Hresult::SUCCESS
        }
        Err(error) => error.into(),
    }
}
export!(322, create);

/// Always 1, as stock.
extern "C" fn destroy(queue: u32) -> u32 {
    // SAFETY: export 323 contract: `queue` is 0 or a priority queue of
    // export 322 on which no other operation runs.
    unsafe { Queue::destroy_with(queue, Signature::PRIORITY_QUEUE) };
    1
}
export!(323, destroy);

extern "C" fn count(queue: u32, output_word: u32) -> Hresult {
    // SAFETY: export 324 contract: as for export 321.
    let (queue, output_word) = unsafe {
        (
            PriorityQueue::from_handle(queue),
            OutputWord::new(output_word),
        )
    };
    report(
        queue.map(|queue| queue.0.nodes().count().load(Relaxed)),
        output_word,
    )
}
export!(324, count);

/// 1 when the queue is empty or invalid.
extern "C" fn is_empty(queue: u32) -> u32 {
    // SAFETY: export 325 contract: `queue` is 0 or a priority queue of
    // export 322.
    unsafe { PriorityQueue::from_handle(queue) }.map_or(1, |queue| {
        let nodes = queue.0.nodes();
        u32::from(!queue.list(&nodes).is_occupied())
    })
}
export!(325, is_empty);

/// Exports 326 and 327: remove an item (by key with [`Search::Exact`]) and
/// store its value.
///
/// # Safety
///
/// Export contract: `queue` is 0 or a priority queue of export 322, and
/// `output_word` 0 or a writable word.
unsafe fn remove(queue: u32, key: Key, search: Search, output_word: u32) -> Hresult {
    // SAFETY: the caller guarantees both.
    let (queue, output_word) = unsafe {
        (
            PriorityQueue::from_handle(queue),
            OutputWord::new(output_word),
        )
    };
    let Some(queue) = queue else {
        return Hresult::INVALID_ARGUMENT;
    };
    removed(queue.take(key, search), output_word)
}

extern "C" fn remove_first(queue: u32, output_word: u32) -> Hresult {
    // SAFETY: export 326 contract.
    unsafe { remove(queue, Key(0), Search::First, output_word) }
}
export!(326, remove_first);

extern "C" fn remove_key(queue: u32, key: u32, output_word: u32) -> Hresult {
    // SAFETY: export 327 contract.
    unsafe { remove(queue, Key(key), Search::Exact, output_word) }
}
export!(327, remove_key);

/// `callback(context, value, node)` in key order until one returns nonzero;
/// positive results become HRESULTs.
extern "C" fn enumerate(queue: u32, context: u32, callback: u32) -> Hresult {
    // Stock checks the callback before the signature.
    // SAFETY: export 328 contract: `callback` is 0 or a console routine.
    let Some(callback) = (unsafe { Routine::new(callback) }) else {
        return success_result(Err(Error::InvalidArgument));
    };
    // SAFETY: export 328 contract: `queue` is 0 or a priority queue of
    // export 322.
    let Some(queue) = (unsafe { PriorityQueue::from_handle(queue) }) else {
        return success_result(Err(Error::InvalidArgument));
    };
    let nodes = queue.0.nodes();
    success_result(queue.list(&nodes).enumerate(context, callback))
}
export!(328, enumerate);
