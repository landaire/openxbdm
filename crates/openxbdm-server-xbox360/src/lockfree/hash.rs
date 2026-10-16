//! Hash table 'LFHT' (exports 330-338): an array of sorted lists, each
//! headed by a sentinel node, selected by the hash routine.
//!
//! Object (0x80 bytes, then the allocator record and the sorted container
//! options): +0x00 free nodes (tagged), +0x08 bucket array, +0x0c bucket
//! count, +0x10 free node credits, +0x14 free node semaphore, +0x18
//! blocked removers, +0x1c item count, +0x20 item semaphore, +0x28 node
//! blocks (tagged), +0x30 nodes per block, +0x34 nodes the limit allows,
//! +0x38 node total, +0x3c bytes allocated, +0x40 signature, +0x6c
//! allocation base, +0x70 bucket array allocation base, +0x74 allocator
//! record, +0x78 options. A bucket is 8 bytes: +0 sentinel node, +4 zero.
//! Nodes are those of the priority queue. The semaphores are handles,
//! which stock never closes.

use openxbdm_core::status::Hresult;

use super::ALLOCATOR_SIZE;
use super::Allocator;
use super::CREATE_FAILED;
use super::Creation;
use super::Failure;
use super::Object;
use super::SUCCESS;
use super::SemaphoreKind;
use super::Shape;
use super::Side;
use super::UNLIMITED;
use super::Wait;
use super::call;
use super::close_handle;
use super::compare_exchange;
use super::copy;
use super::counts;
use super::create_semaphore;
use super::exchange;
use super::export_result;
use super::fetch_add;
use super::fetch_sub;
use super::insert_result;
use super::load;
use super::lwsync;
use super::options_wait;
use super::priority::Blocking;
use super::priority::Handoff;
use super::priority::Item;
use super::priority::Key;
use super::priority::RECORD;
use super::priority::SORTED_OPTIONS_SIZE;
use super::priority::Search;
use super::priority::VALUE;
use super::priority::first;
use super::priority::insert;
use super::priority::insert_options;
use super::priority::occupied;
use super::priority::remove;
use super::priority::sorted_options;
use super::read_field;
use super::remove_result;
use super::store;
use super::walk;
use super::zero;
use crate::exports::export;

const LFHT: u32 = u32::from_be_bytes(*b"LFHT");
const ARRAY: usize = 0x08;
const BUCKETS: usize = 0x0c;
const BASE: u8 = 0x6c;
const ARRAY_BASE: u8 = 0x70;
/// Bytes of the object before the allocator record.
const OBJECT_SIZE: u32 = 0x80;
const NODE_SIZE: u8 = 0x10;
/// Largest bucket count.
const BUCKET_LIMIT: u32 = 0x0fff_ffff;

static SHAPE: Shape = Shape {
    signature: LFHT,
    tag: 0x40,
    credits: 0x10,
    free_semaphore: 0x14,
    waiters: 0x18,
    item_semaphore: 0x20,
    count: 0x1c,
    blocks: 0x28,
    grow: 0x30,
    remaining: 0x34,
    total: 0x38,
    memory: 0x3c,
    allocator: 0x74,
    options: 0x78,
    node_size: NODE_SIZE,
    link: 8,
    semaphores: SemaphoreKind::GatedHandle,
};

/// Address of bucket `index`.
fn bucket_at(table: Object, index: u32) -> usize {
    load(table.base + ARRAY).wrapping_add(index.wrapping_mul(8)) as usize
}

fn bucket_count(table: Object) -> u32 {
    load(table.base + BUCKETS)
}

/// Bucket of `key` by the hash routine.
fn bucket(table: Object, key: Key) -> usize {
    let index = call(load(table.options() + 4), key.0, bucket_count(table), 0, 0);
    bucket_at(table, index)
}

/// Close the item semaphore, then the free node semaphore.
fn close_semaphores(table: Object) {
    for offset in [SHAPE.item_semaphore, SHAPE.free_semaphore] {
        let handle = load(table.field(offset));
        if handle != 0 {
            close_handle(handle);
        }
    }
}

/// Take a block of at least `minimum` nodes within the limit, in a
/// multiple of the nodes per block.
fn grow_at_least(table: Object, minimum: u32) -> Option<u32> {
    let step = load(table.field(SHAPE.grow));
    let mut nodes = step;
    while (nodes as i32) < minimum as i32 {
        nodes = nodes.wrapping_add(step);
    }
    let remaining = table.field(SHAPE.remaining);
    loop {
        let left = load(remaining);
        if (left as i32) < 0 {
            break;
        }
        if left == 0 {
            return None;
        }
        if nodes as i32 > left as i32 {
            nodes = left;
        }
        if (nodes as i32) < minimum as i32 {
            return None;
        }
        if compare_exchange(remaining, left, left.wrapping_sub(nodes)) == left {
            break;
        }
    }
    table.populate(nodes)
}

fn create(buckets: u32, creation: &Creation) -> Option<Object> {
    if buckets as i32 <= 0 || buckets > BUCKET_LIMIT {
        return None;
    }
    let mut memory = 0u32;
    let counter = &raw mut memory as usize;
    let allocator = Allocator::of(&creation.allocator);
    let (base, raw) =
        allocator.allocate_aligned(OBJECT_SIZE + ALLOCATOR_SIZE + SORTED_OPTIONS_SIZE, counter)?;
    let Some((array, array_raw)) = allocator.allocate_aligned(buckets * 8, counter) else {
        allocator.free(raw);
        return None;
    };
    let base = base as usize;
    let table = Object {
        base,
        shape: &SHAPE,
    };
    zero(array as usize, buckets as usize * 8);
    zero(base, OBJECT_SIZE as usize);
    store(base + BUCKETS, buckets);
    store(base + ARRAY, array);
    store(table.field(BASE), raw);
    store(table.field(ARRAY_BASE), array_raw);
    store(table.field(SHAPE.memory), load(counter));
    let record = base + OBJECT_SIZE as usize;
    store(table.field(SHAPE.allocator), record as u32);
    copy(
        record,
        creation.allocator.as_ptr() as usize,
        ALLOCATOR_SIZE as usize,
    );
    store(table.field(SHAPE.options), record as u32 + ALLOCATOR_SIZE);
    let (initial, limit) = counts(creation.initial, creation.limit, u32::from(NODE_SIZE));
    store(table.field(SHAPE.grow), initial);
    store(table.field(SHAPE.remaining), limit.unwrap_or(UNLIMITED));
    let mut created = true;
    if creation.item_wait() {
        let handle = create_semaphore();
        store(table.field(SHAPE.item_semaphore), handle);
        created = handle != 0;
    }
    if created && creation.free_wait() && limit.is_some() {
        let handle = create_semaphore();
        store(table.field(SHAPE.free_semaphore), handle);
        if handle == 0 {
            close_semaphores(table);
            created = false;
        }
    }
    if created {
        if let Some(sentinel) = grow_at_least(table, buckets) {
            let credits = table.field(SHAPE.credits);
            let free_wait = table.free_semaphore().is_some();
            for index in 0..buckets {
                // The block holds a node for every bucket.
                let Some(node) = (if index == 0 {
                    Some(sentinel)
                } else {
                    table.pop_node()
                }) else {
                    unreachable!()
                };
                if free_wait {
                    store(credits, load(credits).wrapping_sub(1));
                }
                store(node as usize, 0);
                store(node as usize + 4, 0);
                let bucket = bucket_at(table, index);
                store(bucket, node);
                store(bucket + 4, 0);
            }
            store(table.field(SHAPE.tag), LFHT);
            lwsync();
            return Some(table);
        }
        close_semaphores(table);
    }
    let allocator = table.allocator();
    allocator.free(array_raw);
    allocator.free(raw);
    None
}

/// Remove from each bucket in turn without waiting; the error carries the
/// failure of the last bucket, `None` when there is none.
fn sweep(table: Object, item: &mut Item, wait: &Wait) -> Result<(), Option<Failure>> {
    let mut last = None;
    let mut index = 0;
    while (index as i32) < bucket_count(table) as i32 {
        let result = if valid(table) {
            remove(
                table,
                bucket_at(table, index),
                item,
                wait,
                Search::First,
                Blocking::Once,
                Handoff::Items,
            )
        } else {
            Err(Failure::InvalidParameter)
        };
        match result {
            Ok(()) => return Ok(()),
            Err(failure) => last = Some(failure),
        }
        index += 1;
    }
    Err(last)
}

/// Whether the signature is still in place; stock checks it again inside
/// each operation.
fn valid(table: Object) -> bool {
    load(table.field(SHAPE.tag)) == LFHT
}

/// Remove an item by key, or any item with [`Search::First`].
fn remove_item(table: Object, item: &mut Item, wait: &Wait, search: Search) -> Result<(), Failure> {
    if !valid(table) {
        return Err(Failure::InvalidParameter);
    }
    if search != Search::First {
        let bucket = bucket(table, item.key);
        if !valid(table) {
            return Err(Failure::InvalidParameter);
        }
        return remove(
            table,
            bucket,
            item,
            wait,
            search,
            Blocking::Wait,
            Handoff::Items,
        );
    }
    let last = match sweep(table, item, wait) {
        Ok(()) => return Ok(()),
        Err(last) => last,
    };
    let Some(semaphore) = table.item_semaphore() else {
        // A table without buckets reports success, as stock.
        return match last {
            Some(failure) => Err(failure),
            None => Ok(()),
        };
    };
    let waiters = table.field(SHAPE.waiters);
    fetch_add(waiters, 1);
    if sweep(table, item, wait).is_ok() {
        fetch_sub(waiters, 1);
        return Ok(());
    }
    // Stock reports success after the wait without removing an item and
    // leaves the remover counted as waiting.
    let result = wait.block(semaphore);
    if result.is_err() {
        fetch_sub(waiters, 1);
    }
    result
}

extern "C" fn insert_export(table: u32, key: u32, value: u32) -> u32 {
    let Some(table) = Object::validate(table, &SHAPE) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let (wait, search) = insert_options(table.options() + RECORD);
    if !valid(table) {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let key = Key(key);
    let bucket = bucket(table, key);
    if !valid(table) {
        return Hresult::INVALID_ARGUMENT.0;
    }
    insert_result(insert(table, bucket, Item { value, key }, &wait, search))
}
export!(330, insert_export);

extern "C" fn memory(table: u32, output: u32) -> u32 {
    read_field(table, &SHAPE, SHAPE.memory, output)
}
export!(331, memory);

/// `compare` is an optional compare descriptor. The bucket count rounds up
/// to a power of two unless it supplies a hash routine.
extern "C" fn create_export(descriptor: u32, compare: u32, buckets: u32, output: u32) -> u32 {
    if output == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    store(output as usize, 0);
    if buckets == 0 || buckets & 0x8000_0000 != 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let creation = match Creation::read(descriptor) {
        Ok(creation) => creation,
        Err(error) => return Hresult::from(error).0,
    };
    let options = match sorted_options(&creation, compare) {
        Ok(options) => options,
        Err(error) => return Hresult::from(error).0,
    };
    let buckets = if options.custom_hash {
        buckets
    } else {
        buckets.next_power_of_two()
    };
    let Some(table) = create(buckets, &creation) else {
        return CREATE_FAILED.0;
    };
    copy(
        table.options(),
        options.words.as_ptr() as usize,
        SORTED_OPTIONS_SIZE as usize,
    );
    store(output as usize, table.base as u32);
    SUCCESS.0
}
export!(332, create_export);

/// Always 1, as stock; the semaphore handles stay open.
extern "C" fn destroy(table: u32) -> u32 {
    if table != 0 && exchange(table as usize + usize::from(SHAPE.tag), 0) == LFHT {
        Object {
            base: table as usize,
            shape: &SHAPE,
        }
        .free_storage(&[ARRAY_BASE, BASE]);
    }
    1
}
export!(333, destroy);

extern "C" fn count(table: u32, output: u32) -> u32 {
    read_field(table, &SHAPE, SHAPE.count, output)
}
export!(334, count);

/// 1 when every bucket is empty or the table is invalid; 0 when the
/// signature changed meanwhile.
extern "C" fn is_empty(table: u32) -> u32 {
    let Some(table) = Object::validate(table, &SHAPE) else {
        return 1;
    };
    if !valid(table) {
        return 0;
    }
    let mut index = 0;
    while (index as i32) < bucket_count(table) as i32 {
        // A bucket checked after the signature is gone counts as empty.
        if valid(table) && occupied(table, bucket_at(table, index)) {
            return 0;
        }
        index += 1;
    }
    1
}
export!(335, is_empty);

/// Remove an item (by key with [`Search::Exact`]) and store its value.
fn take(table: u32, key: u32, search: Search, output: u32) -> u32 {
    let Some(table) = Object::validate(table, &SHAPE) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let wait = options_wait(table.options() + RECORD, Side::Remove).unwrap_or(Wait::NONE);
    let mut item = Item {
        value: 0,
        key: Key(key),
    };
    if let Err(failure) = remove_item(table, &mut item, &wait, search) {
        return remove_result(failure);
    }
    if output != 0 {
        store(output as usize, item.value);
    }
    SUCCESS.0
}

extern "C" fn remove_any(table: u32, output: u32) -> u32 {
    take(table, 0, Search::First, output)
}
export!(336, remove_any);

extern "C" fn remove_key(table: u32, key: u32, output: u32) -> u32 {
    take(table, key, Search::Exact, output)
}
export!(337, remove_key);

/// `callback(context, value, node)` bucket by bucket in key order until one
/// returns nonzero; positive results become HRESULTs.
extern "C" fn enumerate(table: u32, context: u32, callback: u32) -> u32 {
    let Some(table) = Object::validate(table, &SHAPE) else {
        return export_result(Err(Failure::InvalidParameter));
    };
    let mut index = 0;
    while (index as i32) < bucket_count(table) as i32 {
        if callback == 0 || load(table.field(SHAPE.tag)) != LFHT {
            return export_result(Err(Failure::InvalidParameter));
        }
        let result = walk(first(bucket_at(table, index)), VALUE, context, callback);
        if result.is_err() {
            return export_result(result);
        }
        index += 1;
    }
    SUCCESS.0
}
export!(338, enumerate);
