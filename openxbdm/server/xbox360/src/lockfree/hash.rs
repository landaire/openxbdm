//! Hash table 'LFHT' (exports 330-338): an array of sorted lists, each
//! headed by a sentinel node, selected by the hash routine. The nodes are
//! those of the priority queue. The semaphores are handles, which stock
//! never closes.

use core::mem::offset_of;
use core::ptr;
use core::slice;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_core::status::Hresult;
use xbox360::atomic::Interlocked32;
use xbox360_sys::processor::lwsync;
use xbox360_sys::xboxkrnl::Handle;

use super::AllocatorRecord;
use super::Creation;
use super::Error;
use super::ItemOrder;
use super::Layout;
use super::ListNode;
use super::NodeAddress;
use super::NodeWord;
use super::Nodes;
use super::OutputWord;
use super::Routine;
use super::SemaphoreKind;
use super::Signature;
use super::Supply;
use super::TaggedList;
use super::Wait;
use super::claim;
use super::close_semaphore;
use super::container;
use super::create_semaphore;
use super::insert_result;
use super::priority::Blocking;
use super::priority::Handoff;
use super::priority::Item;
use super::priority::Key;
use super::priority::Search;
use super::priority::Sorted;
use super::priority::SortedList;
use super::priority::SortedOptions;
use super::removed;
use super::report;
use super::success_result;
use crate::exports::export;

static LAYOUT: Layout = Layout {
    node_size: size_of::<ListNode>() as u32,
    link: NodeWord::Word2,
    semaphores: SemaphoreKind::GatedHandle,
    items: ItemOrder::CountFirst,
};

/// Hash table object (caller-visible, 0x80 bytes, then the allocator record
/// and the sorted options).
#[repr(C, align(8))]
struct HashTable {
    /// Free nodes, linked through their value word.
    free: TaggedList,
    /// Address of the bucket array.
    buckets: AtomicU32,
    bucket_count: AtomicU32,
    supply: Supply,
    signature: AtomicU32,
    _reserved_44: [AtomicU32; 10],

    /// Base of the allocation that holds the table.
    allocation: AtomicU32,
    /// Base of the allocation that holds the bucket array.
    bucket_allocation: AtomicU32,
    /// Address of the allocator record after the table.
    allocator: AtomicU32,
    /// Address of the sorted options after the allocator record.
    options: AtomicU32,
    _reserved_7c: AtomicU32,
}

const _: () = {
    assert!(offset_of!(HashTable, buckets) == 0x08);
    assert!(offset_of!(HashTable, bucket_count) == 0x0c);
    assert!(offset_of!(HashTable, supply) == 0x10);
    assert!(offset_of!(HashTable, signature) == 0x40);
    assert!(offset_of!(HashTable, allocation) == 0x6c);
    assert!(offset_of!(HashTable, bucket_allocation) == 0x70);
    assert!(offset_of!(HashTable, allocator) == 0x74);
    assert!(offset_of!(HashTable, options) == 0x78);
    assert!(size_of::<HashTable>() == 0x80);
};

impl HashTable {
    /// The table at `handle`.
    ///
    /// # Safety
    ///
    /// `handle` is 0 or the address of a hash table (export contract) that
    /// stays allocated for `'a`.
    unsafe fn from_handle<'a>(handle: u32) -> Option<&'a Self> {
        // SAFETY: the caller guarantees the table.
        unsafe { container(handle, Signature::HASH_TABLE, offset_of!(Self, signature)) }
    }

    fn create(
        buckets: u32,
        creation: &Creation,
        options: &SortedOptions,
    ) -> Result<&'static Self, Error> {
        /// Largest bucket count.
        const MAX_BUCKETS: u32 = 0x0fff_ffff;
        const SIZE: u32 = size_of::<HashTable>() as u32;

        if buckets as i32 <= 0 || buckets > MAX_BUCKETS {
            return Err(Error::NotEnoughMemory);
        }

        let memory = AtomicU32::new(0);
        let allocator = &creation.allocator;
        let size = SIZE + AllocatorRecord::SIZE + size_of::<SortedOptions>() as u32;
        let allocation = allocator
            .allocate_aligned(size, &memory)
            .ok_or(Error::NotEnoughMemory)?;

        let array_size = buckets * size_of::<Bucket>() as u32;
        let Some(array) = allocator.allocate_aligned(array_size, &memory) else {
            allocator.free(allocation.base);
            return Err(Error::NotEnoughMemory);
        };

        let array_object = ptr::with_exposed_provenance_mut::<Bucket>(array.aligned.get() as usize);
        let object = ptr::with_exposed_provenance_mut::<Self>(allocation.aligned.get() as usize);
        // SAFETY: the new allocations hold the bucket array, and the object
        // with the allocator record and the sorted options, aligned to at
        // least 8 bytes; zero bytes are valid buckets and a valid table.
        let table = unsafe {
            array_object.write_bytes(0, buckets as usize);
            object.write_bytes(0, 1);
            &*object
        };
        table.bucket_count.store(buckets, Relaxed);
        table.buckets.store(array.aligned.get(), Relaxed);
        table.allocation.store(allocation.base, Relaxed);
        table.bucket_allocation.store(array.base, Relaxed);
        table.supply.memory.store(memory.load(Relaxed), Relaxed);

        let record = object.wrapping_add(1).cast::<AllocatorRecord>();
        table
            .allocator
            .store(record.expose_provenance() as u32, Relaxed);
        let sorted = record.wrapping_add(1).cast::<SortedOptions>();
        // SAFETY: the record follows the object inside the allocation.
        unsafe { record.write(*allocator) };
        table
            .options
            .store(sorted.expose_provenance() as u32, Relaxed);

        let counts = creation.counts(LAYOUT.node_size);
        table.supply.per_block.store(counts.per_block, Relaxed);
        table.supply.remaining.set(counts.limit);

        let nodes = table.nodes();
        let item_semaphore = nodes.item_words().semaphore;
        'failed: {
            if creation.item_wait() {
                let handle = create_semaphore();
                item_semaphore.store(handle.map_or(0, Handle::raw), Relaxed);
                if handle.is_none() {
                    break 'failed;
                }
            }

            if creation.free_wait() && counts.limit.is_some() {
                let handle = create_semaphore();
                table
                    .supply
                    .free_semaphore
                    .store(handle.map_or(0, Handle::raw), Relaxed);
                if handle.is_none() {
                    table.close_semaphores();
                    break 'failed;
                }
            }

            let Some(sentinel) = table.grow_at_least(&nodes, buckets) else {
                table.close_semaphores();
                break 'failed;
            };

            let credits = &table.supply.credits;
            let free_wait = nodes.free_semaphore().is_some();
            for (index, bucket) in table.buckets().iter().enumerate() {
                let node = if index == 0 {
                    Some(sentinel)
                } else {
                    nodes.pop_free()
                };
                // The block holds a node for every bucket.
                let Some(node) = node else { unreachable!() };

                if free_wait {
                    credits.store(credits.load(Relaxed).wrapping_sub(1), Relaxed);
                }

                // SAFETY: a node of the new block.
                let sentinel = unsafe { node.get::<ListNode, _>(table) };
                sentinel.next.high.store(0, Relaxed);
                sentinel.next.low.store(0, Relaxed);
                bucket.sentinel.store(node.raw(), Relaxed);
                bucket.zero.store(0, Relaxed);
            }

            table.signature.store(Signature::HASH_TABLE.0, Relaxed);
            lwsync();

            // Stock copies the options after the barrier that publishes the
            // table, before it returns the handle.
            // SAFETY: the options follow the record inside the allocation.
            unsafe { sorted.write(*options) };

            return Ok(table);
        }

        allocator.free(array.base);
        allocator.free(allocation.base);

        Err(Error::NotEnoughMemory)
    }

    /// Clear the signature of the table at `handle` and free it; the
    /// semaphore handles stay open, as stock.
    ///
    /// # Safety
    ///
    /// `handle` is 0 or the address of a hash table (export contract) on
    /// which no other operation runs, now or later.
    unsafe fn destroy(handle: u32) {
        // SAFETY: the caller guarantees the table. The reference is not used
        // once the table is freed.
        let Some(table) =
            (unsafe { claim::<Self>(handle, Signature::HASH_TABLE, offset_of!(Self, signature)) })
        else {
            return;
        };

        let bucket_allocation = table.bucket_allocation.load(Relaxed);
        let allocation = table.allocation.load(Relaxed);
        let allocator = *table.nodes().allocator();
        // SAFETY: the block list of the table, which no operation uses
        // anymore.
        unsafe { allocator.free_blocks(&table.supply.blocks) };
        allocator.free(bucket_allocation);
        allocator.free(allocation);
        lwsync();
    }

    fn nodes(&self) -> Nodes<'_> {
        // SAFETY: the parts of this table, which creation set up with the
        // sorted node layout.
        unsafe { Nodes::new(&self.free, &self.supply, &self.allocator, &LAYOUT) }
    }

    fn options(&self) -> &SortedOptions {
        // SAFETY: creation stores the address of the sorted options it wrote
        // after the allocator record.
        unsafe { &*ptr::with_exposed_provenance(self.options.load(Relaxed) as usize) }
    }

    /// Whether the signature is still in place; stock checks it again
    /// inside each operation.
    fn is_live(&self) -> bool {
        Signature::HASH_TABLE.is_in(&self.signature)
    }

    fn buckets(&self) -> &[Bucket] {
        let address = self.buckets.load(Relaxed);
        let count = self.bucket_count.load(Relaxed);

        // SAFETY: creation stores the address and count of the bucket array
        // it allocated, which stays until destroy.
        unsafe {
            slice::from_raw_parts(
                ptr::with_exposed_provenance(address as usize),
                count as usize,
            )
        }
    }

    /// Bucket of `key` by the hash routine.
    fn bucket(&self, key: Key) -> &Bucket {
        let buckets = self.buckets();
        let index = self.options().hash.call(key.0, buckets.len() as u32, 0, 0);

        // SAFETY: a hash routine returns an index below the bucket count: the
        // default masks the key's hash with the power-of-two count less one,
        // and the export contract requires it of caller routines.
        unsafe { buckets.get_unchecked(index as usize) }
    }

    fn list<'a>(&'a self, nodes: &'a Nodes<'a>, bucket: &'a Bucket) -> SortedList<'a> {
        // SAFETY: a bucket of this table, whose sentinel word names a node
        // of the table; `nodes` are the table's.
        unsafe { SortedList::new(&bucket.sentinel, nodes, self.options()) }
    }

    /// Close the item semaphore, then the free node semaphore.
    fn close_semaphores(&self) {
        close_semaphore(self.nodes().item_words().semaphore);
        close_semaphore(&self.supply.free_semaphore);
    }

    /// Take a block of at least `minimum` nodes within the limit, in a
    /// multiple of the nodes per block.
    fn grow_at_least(&self, nodes: &Nodes<'_>, minimum: u32) -> Option<NodeAddress> {
        let step = self.supply.per_block.load(Relaxed);
        let mut wanted = step;
        while (wanted as i32) < minimum as i32 {
            wanted = wanted.wrapping_add(step);
        }

        let claimed = self.supply.remaining.claim_at_least(wanted, minimum)?;

        nodes.populate(claimed)
    }

    /// Remove from each bucket in turn without waiting; the error carries
    /// the failure of the last bucket, nothing when there is none.
    fn sweep(&self, nodes: &Nodes<'_>, item: &mut Item, wait: &Wait) -> Result<(), Option<Error>> {
        let mut last = None;
        for bucket in self.buckets() {
            let result = if self.is_live() {
                self.list(nodes, bucket).remove(
                    item,
                    wait,
                    Search::First,
                    Blocking::Once,
                    Handoff::Items,
                )
            } else {
                Err(Error::InvalidArgument)
            };
            match result {
                Ok(()) => return Ok(()),
                Err(error) => last = Some(error),
            }
        }

        Err(last)
    }

    /// Remove an item by key, or any item with [`Search::First`].
    fn remove(&self, item: &mut Item, wait: &Wait, search: Search) -> Result<(), Error> {
        if !self.is_live() {
            return Err(Error::InvalidArgument);
        }

        let nodes = self.nodes();
        if search != Search::First {
            let bucket = self.bucket(item.key);
            if !self.is_live() {
                return Err(Error::InvalidArgument);
            }

            return self.list(&nodes, bucket).remove(
                item,
                wait,
                search,
                Blocking::Wait,
                Handoff::Items,
            );
        }

        let Err(last) = self.sweep(&nodes, item, wait) else {
            return Ok(());
        };

        let Some(semaphore) = nodes.item_semaphore() else {
            // A table without buckets reports success, as stock.
            return last.map_or(Ok(()), Err);
        };

        let waiters = &self.supply.waiters;
        waiters.fetch_add_relaxed(1);
        if self.sweep(&nodes, item, wait).is_ok() {
            waiters.fetch_add_relaxed(1_u32.wrapping_neg());
            return Ok(());
        }

        // Stock reports success after the wait without removing an item and
        // leaves the remover counted as waiting.
        let result = wait.block(semaphore);
        if result.is_err() {
            waiters.fetch_add_relaxed(1_u32.wrapping_neg());
        }

        result
    }

    /// Remove an item (by key with [`Search::Exact`]); its value.
    fn take(&self, key: Key, search: Search) -> Result<u32, Error> {
        let wait = self.options().remove_wait();

        let mut item = Item { value: 0, key };
        self.remove(&mut item, &wait, search)?;

        Ok(item.value)
    }

    fn insert(&self, item: Item) -> Result<(), Error> {
        let (wait, search) = self.options().insert_wait();
        if !self.is_live() {
            return Err(Error::InvalidArgument);
        }

        let bucket = self.bucket(item.key);
        if !self.is_live() {
            return Err(Error::InvalidArgument);
        }

        let nodes = self.nodes();

        self.list(&nodes, bucket).insert(item, &wait, search)
    }

    /// Whether every bucket is empty; a bucket checked after the signature
    /// is gone counts as empty.
    fn is_empty(&self) -> bool {
        let nodes = self.nodes();

        !self
            .buckets()
            .iter()
            .any(|bucket| self.is_live() && self.list(&nodes, bucket).is_occupied())
    }

    /// `callback(context, value, node)` bucket by bucket in key order until
    /// one returns nonzero.
    fn enumerate(&self, context: u32, callback: Option<Routine>) -> Result<(), Error> {
        let nodes = self.nodes();
        for bucket in self.buckets() {
            let Some(callback) = callback.filter(|_| self.is_live()) else {
                return Err(Error::InvalidArgument);
            };

            self.list(&nodes, bucket).enumerate(context, callback)?;
        }

        Ok(())
    }
}

/// Bucket (8 bytes).
#[repr(C)]
struct Bucket {
    /// Address of the sentinel node of the bucket's list.
    sentinel: AtomicU32,
    zero: AtomicU32,
}

extern "C" fn insert(table: u32, key: u32, value: u32) -> Hresult {
    // SAFETY: export 330 contract: `table` is 0 or a hash table of export
    // 332.
    let Some(table) = (unsafe { HashTable::from_handle(table) }) else {
        return Hresult::INVALID_ARGUMENT;
    };

    insert_result(table.insert(Item {
        value,
        key: Key(key),
    }))
}
export!(330, insert);

extern "C" fn memory(table: u32, output_word: u32) -> Hresult {
    // SAFETY: export 331 contract: `table` is 0 or a hash table of export
    // 332; `output_word` is 0 or a writable word.
    let (table, output_word) =
        unsafe { (HashTable::from_handle(table), OutputWord::new(output_word)) };

    report(
        table.map(|table| table.supply.memory.load(Relaxed)),
        output_word,
    )
}
export!(331, memory);

/// `compare` is an optional compare descriptor. The bucket count rounds up
/// to a power of two unless it supplies a hash routine.
extern "C" fn create(descriptor: u32, compare: u32, buckets: u32, output_word: u32) -> Hresult {
    // SAFETY: export 332 contract: `output_word` is 0 or a writable word.
    let Some(output_word) = (unsafe { OutputWord::new(output_word) }) else {
        return Hresult::INVALID_ARGUMENT;
    };

    output_word.store(0);

    // Zero or above i32::MAX.
    if buckets as i32 <= 0 {
        return Hresult::INVALID_ARGUMENT;
    }

    // SAFETY: export 332 contract: `descriptor` is 0 or a creation
    // descriptor and `compare` 0 or a compare descriptor.
    let created = unsafe { Creation::from_address(descriptor) }.and_then(|creation| {
        // SAFETY: as above.
        let sorted = unsafe { Sorted::from_creation(&creation, compare) }?;
        let buckets = if sorted.custom_hash {
            buckets
        } else {
            buckets.next_power_of_two()
        };

        HashTable::create(buckets, &creation, &sorted.options)
    });
    match created {
        Ok(table) => {
            output_word.store(ptr::from_ref(table).expose_provenance() as u32);
            Hresult::SUCCESS
        }
        Err(error) => error.into(),
    }
}
export!(332, create);

/// Always 1, as stock.
extern "C" fn destroy(table: u32) -> u32 {
    // SAFETY: export 333 contract: `table` is 0 or a hash table of export
    // 332 on which no other operation runs.
    unsafe { HashTable::destroy(table) };

    1
}
export!(333, destroy);

extern "C" fn count(table: u32, output_word: u32) -> Hresult {
    // SAFETY: export 334 contract: as for export 331.
    let (table, output_word) =
        unsafe { (HashTable::from_handle(table), OutputWord::new(output_word)) };

    report(
        table.map(|table| table.nodes().count().load(Relaxed)),
        output_word,
    )
}
export!(334, count);

/// 1 when every bucket is empty or the table is invalid; 0 when the
/// signature changed meanwhile.
extern "C" fn is_empty(table: u32) -> u32 {
    // SAFETY: export 335 contract: `table` is 0 or a hash table of export
    // 332.
    let Some(table) = (unsafe { HashTable::from_handle(table) }) else {
        return 1;
    };

    u32::from(table.is_live() && table.is_empty())
}
export!(335, is_empty);

/// Exports 336 and 337: remove an item (by key with [`Search::Exact`]) and
/// store its value.
///
/// # Safety
///
/// Export contract: `table` is 0 or a hash table of export 332, and
/// `output_word` 0 or a writable word.
unsafe fn remove(table: u32, key: Key, search: Search, output_word: u32) -> Hresult {
    // SAFETY: the caller guarantees both.
    let (table, output_word) =
        unsafe { (HashTable::from_handle(table), OutputWord::new(output_word)) };
    let Some(table) = table else {
        return Hresult::INVALID_ARGUMENT;
    };

    removed(table.take(key, search), output_word)
}

extern "C" fn remove_any(table: u32, output_word: u32) -> Hresult {
    // SAFETY: export 336 contract.
    unsafe { remove(table, Key(0), Search::First, output_word) }
}
export!(336, remove_any);

extern "C" fn remove_key(table: u32, key: u32, output_word: u32) -> Hresult {
    // SAFETY: export 337 contract.
    unsafe { remove(table, Key(key), Search::Exact, output_word) }
}
export!(337, remove_key);

/// `callback(context, value, node)` bucket by bucket in key order until one
/// returns nonzero; positive results become HRESULTs.
extern "C" fn enumerate(table: u32, context: u32, callback: u32) -> Hresult {
    // SAFETY: export 338 contract: `table` is 0 or a hash table of export
    // 332 and `callback` 0 or a console routine.
    let (table, callback) = unsafe { (HashTable::from_handle(table), Routine::new(callback)) };
    let Some(table) = table else {
        return success_result(Err(Error::InvalidArgument));
    };

    success_result(table.enumerate(context, callback))
}
export!(338, enumerate);
