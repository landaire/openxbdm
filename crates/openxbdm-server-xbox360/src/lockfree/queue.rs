//! Queue 'LfQu' (exports 302-309): a linked queue behind a sentinel node.
//! The priority queue shares the object layout and [`Queue::create`].

use core::mem::offset_of;
use core::num::NonZeroU32;
use core::ptr;
use core::slice;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_core::status::Hresult;
use xbox360_sys::processor::lwsync;
use xbox360_sys::xboxkrnl::KeInitializeSemaphore;
use xbox360_sys::xboxkrnl::Ksemaphore;

use super::AllocatorRecord;
use super::Creation;
use super::DoubleWord;
use super::Error;
use super::ItemOrder;
use super::Layout;
use super::ListNode;
use super::NodeAddress;
use super::NodeWord;
use super::Nodes;
use super::OptionsRecord;
use super::OutputWord;
use super::Routine;
use super::SemaphoreKind;
use super::Side;
use super::Signature;
use super::Supply;
use super::Tagged;
use super::TaggedList;
use super::Wait;
use super::WaitObject;
use super::claim;
use super::container;
use super::insert_result;
use super::priority::SortedOptions;
use super::removed;
use super::report;
use super::success_result;
use super::walk;
use crate::exports::export;

static LAYOUT: Layout = Layout {
    node_size: size_of::<ListNode>() as u32,
    link: NodeWord::Word2,
    semaphores: SemaphoreKind::Object,
    items: ItemOrder::SemaphoreFirst,
};

/// Queue object (caller-visible, 0x80 bytes, then the allocator record and
/// the options).
#[repr(C, align(8))]
pub(crate) struct Queue {
    /// Free nodes, linked through their value word.
    free: TaggedList,
    tail: DoubleWord,
    /// Link to the sentinel node before the first item. A priority queue
    /// keeps the address of its sentinel node in the high word.
    pub(super) head: DoubleWord,
    pub(super) supply: Supply,
    pub(super) signature: AtomicU32,

    item_object: Ksemaphore,
    free_object: Ksemaphore,

    /// Base of the allocation that holds the queue.
    allocation: AtomicU32,
    /// Address of the allocator record after the queue.
    allocator: AtomicU32,
    /// Address of the options after the allocator record, or 0.
    pub(super) options: AtomicU32,
}

const _: () = {
    assert!(offset_of!(Queue, tail) == 0x08);
    assert!(offset_of!(Queue, head) == 0x10);
    assert!(offset_of!(Queue, supply) == 0x18);
    assert!(offset_of!(Queue, signature) == 0x48);
    assert!(offset_of!(Queue, item_object) == 0x4c);
    assert!(offset_of!(Queue, free_object) == 0x60);
    assert!(offset_of!(Queue, allocation) == 0x74);
    assert!(offset_of!(Queue, allocator) == 0x78);
    assert!(offset_of!(Queue, options) == 0x7c);
    assert!(size_of::<Queue>() == 0x80);
};

impl Queue {
    /// The queue at `handle`.
    ///
    /// # Safety
    ///
    /// `handle` is 0 or the address of a queue-layout object (export
    /// contract) that stays allocated for `'a`.
    pub(crate) unsafe fn from_handle<'a>(handle: u32) -> Option<&'a Self> {
        // SAFETY: the caller guarantees the object.
        unsafe { Self::with_signature(handle, Signature::QUEUE) }
    }

    /// The queue-layout object at `handle` that carries `signature`.
    ///
    /// # Safety
    ///
    /// As for [`Queue::from_handle`].
    pub(super) unsafe fn with_signature<'a>(handle: u32, signature: Signature) -> Option<&'a Self> {
        // SAFETY: the caller guarantees the object.
        unsafe { container(handle, signature, offset_of!(Self, signature)) }
    }

    /// Create a queue that keeps the descriptor's options when any is set;
    /// its handle.
    pub(crate) fn create_with(creation: &Creation) -> Result<NonZeroU32, Error> {
        let kept = creation.kept_options().map_or(Kept::Nothing, Kept::Options);
        let queue = Self::create(creation, Signature::QUEUE, kept)?;

        // SAFETY: a reference is not null.
        Ok(unsafe { NonZeroU32::new_unchecked(queue.handle()) })
    }

    /// Create a queue-layout object with `signature`, its sentinel node and
    /// the `kept` options.
    pub(super) fn create(
        creation: &Creation,
        signature: Signature,
        kept: Kept<'_>,
    ) -> Result<&'static Self, Error> {
        const SIZE: u32 = size_of::<Queue>() as u32;

        let kept = kept.bytes();
        let memory = AtomicU32::new(0);
        let allocation = creation
            .allocator
            .allocate_aligned(SIZE + AllocatorRecord::SIZE + kept.len() as u32, &memory)
            .ok_or(Error::NotEnoughMemory)?;

        let object = ptr::with_exposed_provenance_mut::<Self>(allocation.aligned.get() as usize);
        // SAFETY: the new allocation holds the object, the allocator record
        // and the kept options, aligned to 128 bytes; zero bytes are a valid
        // queue.
        let queue = unsafe {
            object.write_bytes(0, 1);
            &*object
        };
        queue.allocation.store(allocation.base, Relaxed);
        queue.supply.memory.store(memory.load(Relaxed), Relaxed);

        let record = object.wrapping_add(1).cast::<AllocatorRecord>();
        queue
            .allocator
            .store(record.expose_provenance() as u32, Relaxed);
        let options = record.wrapping_add(1).cast::<u8>();
        // SAFETY: the record follows the object inside the allocation.
        unsafe { record.write(creation.allocator) };
        if !kept.is_empty() {
            queue
                .options
                .store(options.expose_provenance() as u32, Relaxed);
        }

        let counts = creation.counts(LAYOUT.node_size);
        queue.supply.per_block.store(counts.per_block, Relaxed);
        queue.supply.remaining.set(counts.limit);

        let nodes = queue.nodes();
        if creation.item_wait() {
            initialize_semaphore(&queue.item_object, nodes.item_words().semaphore);
        }

        if creation.free_wait() && counts.limit.is_some() {
            initialize_semaphore(&queue.free_object, &queue.supply.free_semaphore);
        }

        let Some(sentinel) = nodes.grow() else {
            creation.allocator.free(allocation.base);
            return Err(Error::NotEnoughMemory);
        };

        if nodes.free_semaphore().is_some() {
            let credits = &queue.supply.credits;
            credits.store(credits.load(Relaxed).wrapping_sub(1), Relaxed);
        }

        // SAFETY: the first node of the new block.
        let node = unsafe { sentinel.get::<ListNode, _>(queue) };
        node.next.high.store(0, Relaxed);
        node.next.low.store(0, Relaxed);

        for end in [&queue.head, &queue.tail] {
            end.high.store(sentinel.raw(), Relaxed);
            end.low.store(0, Relaxed);
        }

        queue.signature.store(signature.0, Relaxed);
        lwsync();

        // Stock copies the options after the barrier that publishes the
        // queue, before it returns the handle.
        // SAFETY: the kept bytes follow the record inside the allocation.
        unsafe { ptr::copy_nonoverlapping(kept.as_ptr(), options, kept.len()) };

        Ok(queue)
    }

    /// Clear the signature of the queue-layout object at `handle` and free
    /// it; whether it carried `signature`.
    ///
    /// # Safety
    ///
    /// `handle` is 0 or the address of a queue-layout object (export
    /// contract) on which no other operation runs, now or later.
    pub(super) unsafe fn destroy_with(handle: u32, signature: Signature) -> bool {
        // SAFETY: the caller guarantees the object. The reference is not
        // used once the object is freed.
        let Some(queue) =
            (unsafe { claim::<Self>(handle, signature, offset_of!(Self, signature)) })
        else {
            return false;
        };

        let allocation = queue.allocation.load(Relaxed);
        let allocator = *queue.nodes().allocator();
        // SAFETY: the block list of the queue, which no operation uses
        // anymore.
        unsafe { allocator.free_blocks(&queue.supply.blocks) };
        allocator.free(allocation);
        lwsync();

        true
    }

    /// Free the queue at `handle`.
    ///
    /// # Safety
    ///
    /// As for [`Queue::destroy_with`].
    pub(crate) unsafe fn destroy(handle: u32) {
        // SAFETY: the caller guarantees the queue.
        unsafe { Self::destroy_with(handle, Signature::QUEUE) };
    }

    /// The address callers know the queue by.
    pub(crate) fn handle(&self) -> u32 {
        ptr::from_ref(self).expose_provenance() as u32
    }

    pub(super) fn nodes(&self) -> Nodes<'_> {
        // SAFETY: the parts of this queue, which creation set up with the
        // queue node layout.
        unsafe { Nodes::new(&self.free, &self.supply, &self.allocator, &LAYOUT) }
    }

    /// The node at `address`.
    ///
    /// # Safety
    ///
    /// `address` was read from the head or tail of this queue, which always
    /// name one of its nodes: creation links the sentinel, and updates link
    /// only nodes of its blocks.
    unsafe fn end(&self, address: u32) -> &ListNode {
        // SAFETY: the caller guarantees the node.
        unsafe { NodeAddress::new_unchecked(address).get(self) }
    }

    fn options(&self) -> Option<&OptionsRecord> {
        let address = self.options.load(Relaxed);

        // SAFETY: a nonzero options word of a queue holds the address of the
        // options record creation wrote after the allocator record.
        unsafe { ptr::with_exposed_provenance::<OptionsRecord>(address as usize).as_ref() }
    }

    /// Link `value` behind the tail.
    fn append(&self, value: u32, wait: &Wait) -> Result<(), Error> {
        let nodes = self.nodes();
        let address = nodes.acquire_node(wait)?;

        // SAFETY: a node of this queue's supply.
        let node = unsafe { address.get::<ListNode, _>(self) };
        node.item.high.store(value, Relaxed);
        node.item.low.store(0, Relaxed);
        node.next.high.store(0, Relaxed);
        node.next.low.store(
            (node.next.low.load(Relaxed) & !Tagged::DELETED).wrapping_add(1),
            Relaxed,
        );

        loop {
            let last = self.tail.load();
            // SAFETY: read from the tail.
            let last_node = unsafe { self.end(last.high()) };
            let next = last_node.next.load();
            if self.tail.load() != last {
                continue;
            }

            if next.high() != 0 {
                self.tail
                    .compare_exchange(last, last.successor(next.high()));
                continue;
            }

            if last_node
                .next
                .compare_exchange(next, next.successor(address.raw()))
            {
                self.tail
                    .compare_exchange(last, last.successor(address.raw()));
                break;
            }
        }

        nodes.signal_item();
        nodes.count_added();

        Ok(())
    }

    /// Unlink the first item; its value, or nothing when the queue is empty.
    fn take(&self) -> Option<u32> {
        loop {
            let first = self.head.load();
            let last = self.tail.load();
            // SAFETY: read from the head.
            let next = unsafe { self.end(first.high()) }.next.high.load(Relaxed);
            if self.head.load() != first {
                continue;
            }

            if first.high() == last.high() {
                if next == 0 {
                    return None;
                }

                self.tail.compare_exchange(last, last.successor(next));
                continue;
            }

            let Some(next) = NodeAddress::new(next) else {
                continue;
            };

            // SAFETY: a node linked in this queue (module invariants).
            let value = unsafe { next.get::<ListNode, _>(self) }
                .item
                .high
                .load(Relaxed);
            if self
                .head
                .compare_exchange(first, first.successor(next.raw()))
            {
                // SAFETY: the old sentinel left the queue with the exchange.
                unsafe {
                    self.nodes()
                        .release_node(NodeAddress::new_unchecked(first.high()))
                };
                return Some(value);
            }
        }
    }

    /// Append `value` as export 302 does: with the insert wait of the
    /// options, or without waiting.
    pub(crate) fn enqueue(&self, value: u32) -> Result<(), Error> {
        // Without the wait option stock takes a path whose effects match a
        // wait that neither spins nor blocks.
        let wait = self
            .options()
            .and_then(|options| options.wait(Side::Insert))
            .unwrap_or(Wait::NONE);

        self.append(value, &wait)
    }

    /// Remove the first value as export 308 does: waiting per the options
    /// when the queue has an item semaphore.
    pub(crate) fn dequeue(&self) -> Result<u32, Error> {
        let wait = self
            .options()
            .and_then(|options| options.wait(Side::Remove));
        let nodes = self.nodes();
        let value = match (wait, nodes.item_semaphore()) {
            (Some(wait), Some(semaphore)) => {
                nodes.remove_waiting(semaphore, &wait, || self.take())?
            }
            _ => self.take().ok_or(Error::Timeout)?,
        };

        nodes.count_removed();

        Ok(value)
    }

    /// Whether the queue is empty; a lagging tail is advanced.
    pub(crate) fn is_empty(&self) -> bool {
        loop {
            let first = self.head.load();
            let last = self.tail.load();
            // SAFETY: read from the head.
            let next = unsafe { self.end(first.high()) }.next.high.load(Relaxed);
            if self.head.load() != first {
                continue;
            }

            if first.high() != last.high() {
                return false;
            }

            if next == 0 {
                return true;
            }

            self.tail.compare_exchange(last, last.successor(next));
        }
    }

    /// `callback(context, value, node)` for each item from the head until
    /// one returns nonzero.
    fn enumerate(&self, context: u32, callback: Routine) -> Result<(), Error> {
        // SAFETY: read from the head.
        let first = unsafe { self.end(self.head.high.load(Relaxed)) }
            .next
            .high
            .load(Relaxed);

        // SAFETY: the nodes linked in this queue (module invariants).
        unsafe { walk(first, NodeWord::Word2, context, callback) }
    }
}

/// Options a queue-layout object keeps after its allocator record.
pub(super) enum Kept<'a> {
    Nothing,
    Options(&'a OptionsRecord),
    Sorted(&'a SortedOptions),
}

impl Kept<'_> {
    /// The bytes of the kept record.
    fn bytes(&self) -> &[u8] {
        let (data, size) = match self {
            Self::Nothing => return &[],
            Self::Options(options) => (
                ptr::from_ref(*options).cast::<u8>(),
                size_of::<OptionsRecord>(),
            ),
            Self::Sorted(options) => (
                ptr::from_ref(*options).cast::<u8>(),
                size_of::<SortedOptions>(),
            ),
        };

        // SAFETY: both records are words without padding.
        unsafe { slice::from_raw_parts(data, size) }
    }
}

/// Initialize `object` at count 0 and store its address in `word`.
fn initialize_semaphore(object: &Ksemaphore, word: &AtomicU32) {
    // SAFETY: the storage lies in an unpublished queue, which no other
    // thread uses yet.
    unsafe { KeInitializeSemaphore(object.as_ptr(), 0, WaitObject::SEMAPHORE_LIMIT) };
    word.store(object.as_ptr().expose_provenance() as u32, Relaxed);
}

extern "C" fn enqueue(queue: u32, value: u32) -> Hresult {
    // SAFETY: export 302 contract: `queue` is 0 or a queue of export 304.
    let Some(queue) = (unsafe { Queue::from_handle(queue) }) else {
        return Hresult::INVALID_ARGUMENT;
    };

    insert_result(queue.enqueue(value))
}
export!(302, enqueue);

extern "C" fn memory(queue: u32, output_word: u32) -> Hresult {
    // SAFETY: export 303 contract: `queue` is 0 or a queue of export 304;
    // `output_word` is 0 or a writable word.
    let (queue, output_word) = unsafe { (Queue::from_handle(queue), OutputWord::new(output_word)) };

    report(
        queue.map(|queue| queue.supply.memory.load(Relaxed)),
        output_word,
    )
}
export!(303, memory);

extern "C" fn create(descriptor: u32, output_word: u32) -> Hresult {
    // SAFETY: export 304 contract: `output_word` is 0 or a writable word.
    let Some(output_word) = (unsafe { OutputWord::new(output_word) }) else {
        return Hresult::INVALID_ARGUMENT;
    };

    output_word.store(0);

    // SAFETY: export 304 contract: `descriptor` is 0 or a creation
    // descriptor.
    let created = unsafe { Creation::from_address(descriptor) }
        .and_then(|creation| Queue::create_with(&creation));
    match created {
        Ok(queue) => {
            output_word.store(queue.get());
            Hresult::SUCCESS
        }
        Err(error) => error.into(),
    }
}
export!(304, create);

/// Always 1, as stock.
extern "C" fn destroy(queue: u32) -> u32 {
    // SAFETY: export 305 contract: `queue` is 0 or a queue of export 304 on
    // which no other operation runs.
    unsafe { Queue::destroy(queue) };

    1
}
export!(305, destroy);

extern "C" fn count(queue: u32, output_word: u32) -> Hresult {
    // SAFETY: export 306 contract: as for export 303.
    let (queue, output_word) = unsafe { (Queue::from_handle(queue), OutputWord::new(output_word)) };

    report(
        queue.map(|queue| queue.nodes().count().load(Relaxed)),
        output_word,
    )
}
export!(306, count);

/// 1 when the queue is empty or invalid.
extern "C" fn is_empty(queue: u32) -> u32 {
    // SAFETY: export 307 contract: `queue` is 0 or a queue of export 304.
    unsafe { Queue::from_handle(queue) }.map_or(1, |queue| u32::from(queue.is_empty()))
}
export!(307, is_empty);

extern "C" fn dequeue(queue: u32, output_word: u32) -> Hresult {
    // SAFETY: export 308 contract: `queue` is 0 or a queue of export 304;
    // `output_word` is 0 or a writable word.
    let (queue, output_word) = unsafe { (Queue::from_handle(queue), OutputWord::new(output_word)) };
    let Some(queue) = queue else {
        return Hresult::INVALID_ARGUMENT;
    };

    removed(queue.dequeue(), output_word)
}
export!(308, dequeue);

/// `callback(context, value, node)` for each item from the head until one
/// returns nonzero; positive results become HRESULTs.
extern "C" fn enumerate(queue: u32, context: u32, callback: u32) -> Hresult {
    // Stock checks the callback before the signature.
    // SAFETY: export 309 contract: `callback` is 0 or a console routine.
    let Some(callback) = (unsafe { Routine::new(callback) }) else {
        return success_result(Err(Error::InvalidArgument));
    };

    // SAFETY: export 309 contract: `queue` is 0 or a queue of export 304.
    let Some(queue) = (unsafe { Queue::from_handle(queue) }) else {
        return success_result(Err(Error::InvalidArgument));
    };

    success_result(queue.enumerate(context, callback))
}
export!(309, enumerate);
