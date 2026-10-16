//! Queue 'LfQu' (exports 302-309): a linked queue behind a sentinel node.
//! The priority queue shares the object layout and [`create`].
//!
//! Object (0x80 bytes, then the allocator record and the options): +0x00
//! free nodes (tagged), +0x08 tail (tagged), +0x10 head (tagged), +0x18
//! free node credits, +0x1c free node semaphore, +0x20 blocked removers,
//! +0x24 item semaphore, +0x28 item count, +0x30 node blocks (tagged),
//! +0x38 nodes per block, +0x3c nodes the limit allows, +0x40 node total,
//! +0x44 bytes allocated, +0x48 signature, +0x4c and +0x60 the item and
//! free node KSEMAPHOREs, +0x74 allocation base, +0x78 allocator record,
//! +0x7c options. Nodes are 0x10 bytes: +0 next (tagged), +8 item with the
//! value in the high word; the free list links through +8.

use openxbdm_core::status::Hresult;

use super::ALLOCATOR_SIZE;
use super::Allocator;
use super::CREATE_FAILED;
use super::Creation;
use super::Failure;
use super::KeInitializeSemaphore;
use super::MARK;
use super::OPTIONS_SIZE;
use super::Object;
use super::SEMAPHORE_LIMIT;
use super::SUCCESS;
use super::SemaphoreKind;
use super::Shape;
use super::Side;
use super::UNLIMITED;
use super::Wait;
use super::copy;
use super::counts;
use super::exchange;
use super::export_result;
use super::insert_result;
use super::load;
use super::load_tagged;
use super::lwsync;
use super::options_wait;
use super::read_field;
use super::remove_result;
use super::remove_waiting;
use super::store;
use super::swap_tagged;
use super::walk;
use super::zero;
use crate::exports::export;

const LFQU: u32 = u32::from_be_bytes(*b"LfQu");
const TAIL: usize = 0x08;
const HEAD: usize = 0x10;
const ITEM_SEMAPHORE: usize = 0x4c;
const FREE_SEMAPHORE: usize = 0x60;
const BASE: u8 = 0x74;
/// Bytes of the object before the allocator record.
const OBJECT_SIZE: u32 = 0x80;
const NODE_SIZE: u8 = 0x10;
/// Item of a node.
const ITEM: usize = 8;

/// Queue layout with `signature`.
pub(super) const fn shape(signature: u32) -> Shape {
    Shape {
        signature,
        tag: 0x48,
        credits: 0x18,
        free_semaphore: 0x1c,
        waiters: 0x20,
        item_semaphore: 0x24,
        count: 0x28,
        blocks: 0x30,
        grow: 0x38,
        remaining: 0x3c,
        total: 0x40,
        memory: 0x44,
        allocator: 0x78,
        options: 0x7c,
        node_size: NODE_SIZE,
        link: 8,
        semaphores: SemaphoreKind::Object,
    }
}

static SHAPE: Shape = shape(LFQU);

/// Create a queue-layout object with its sentinel node and `extra` bytes of
/// options after the allocator record.
pub(super) fn create(shape: &'static Shape, creation: &Creation, extra: u32) -> Option<Object> {
    let mut memory = 0u32;
    let counter = &raw mut memory as usize;
    let (base, raw) = Allocator::of(&creation.allocator)
        .allocate_aligned(OBJECT_SIZE + ALLOCATOR_SIZE + extra, counter)?;
    let base = base as usize;
    let object = Object { base, shape };
    zero(base, OBJECT_SIZE as usize);
    store(object.field(BASE), raw);
    store(object.field(shape.memory), load(counter));
    let record = base + OBJECT_SIZE as usize;
    store(object.field(shape.allocator), record as u32);
    copy(
        record,
        creation.allocator.as_ptr() as usize,
        ALLOCATOR_SIZE as usize,
    );
    if extra != 0 {
        store(object.field(shape.options), record as u32 + ALLOCATOR_SIZE);
    }
    let (initial, limit) = counts(creation.initial, creation.limit, u32::from(NODE_SIZE));
    store(object.field(shape.grow), initial);
    store(object.field(shape.remaining), limit.unwrap_or(UNLIMITED));
    if creation.item_wait() {
        KeInitializeSemaphore((base + ITEM_SEMAPHORE) as u32, 0, SEMAPHORE_LIMIT);
        store(
            object.field(shape.item_semaphore),
            (base + ITEM_SEMAPHORE) as u32,
        );
    }
    if creation.free_wait() && limit.is_some() {
        KeInitializeSemaphore((base + FREE_SEMAPHORE) as u32, 0, SEMAPHORE_LIMIT);
        store(
            object.field(shape.free_semaphore),
            (base + FREE_SEMAPHORE) as u32,
        );
    }
    let Some(sentinel) = object.grow() else {
        object.allocator().free(raw);
        return None;
    };
    if object.free_semaphore().is_some() {
        let credits = object.field(shape.credits);
        store(credits, load(credits).wrapping_sub(1));
    }
    store(sentinel as usize, 0);
    store(sentinel as usize + 4, 0);
    for end in [HEAD, TAIL] {
        store(base + end, sentinel);
        store(base + end + 4, 0);
    }
    store(object.field(shape.tag), shape.signature);
    lwsync();
    Some(object)
}

/// Link `value` behind the tail.
fn append(queue: Object, value: u32, wait: &Wait) -> Result<(), Failure> {
    let node = queue.acquire_node(wait)?;
    let address = node as usize;
    store(address + ITEM, value);
    store(address + ITEM + 4, 0);
    store(address, 0);
    store(address + 4, (load(address + 4) & !MARK).wrapping_add(1));
    let tail = queue.base + TAIL;
    loop {
        let last = load_tagged(tail);
        let next = load_tagged(last.address() as usize);
        if load_tagged(tail) != last {
            continue;
        }
        if next.address() != 0 {
            swap_tagged(tail, last, last.successor(next.address()));
            continue;
        }
        if swap_tagged(last.address() as usize, next, next.successor(node)) {
            swap_tagged(tail, last, last.successor(node));
            break;
        }
    }
    queue.signal_item();
    queue.count_added();
    Ok(())
}

/// Unlink the first item; its value, or nothing when the queue is empty.
fn take(queue: Object) -> Option<u32> {
    let head = queue.base + HEAD;
    let tail = queue.base + TAIL;
    loop {
        let first = load_tagged(head);
        let last = load_tagged(tail);
        let next = load(first.address() as usize);
        if load_tagged(head) != first {
            continue;
        }
        if first.address() == last.address() {
            if next == 0 {
                return None;
            }
            swap_tagged(tail, last, last.successor(next));
            continue;
        }
        if next == 0 {
            continue;
        }
        let value = load(next as usize + ITEM);
        if swap_tagged(head, first, first.successor(next)) {
            queue.release_node(first.address());
            return Some(value);
        }
    }
}

pub(crate) extern "C" fn enqueue(queue: u32, value: u32) -> u32 {
    let Some(queue) = Object::validate(queue, &SHAPE) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let options = queue.options();
    // Without the wait option stock takes a path whose effects match a wait
    // that neither spins nor blocks.
    let wait = if options == 0 {
        None
    } else {
        options_wait(options, Side::Insert)
    };
    insert_result(append(queue, value, &wait.unwrap_or(Wait::NONE)))
}
export!(302, enqueue);

extern "C" fn memory(queue: u32, output: u32) -> u32 {
    read_field(queue, &SHAPE, SHAPE.memory, output)
}
export!(303, memory);

pub(crate) extern "C" fn create_export(descriptor: u32, output: u32) -> u32 {
    if output == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    store(output as usize, 0);
    let creation = match Creation::read(descriptor) {
        Ok(creation) => creation,
        Err(error) => return Hresult::from(error).0,
    };
    let options = creation.keeps_options();
    let Some(queue) = create(&SHAPE, &creation, if options { OPTIONS_SIZE } else { 0 }) else {
        return CREATE_FAILED.0;
    };
    if options {
        copy(queue.options(), creation.descriptor, OPTIONS_SIZE as usize);
    }
    store(output as usize, queue.base as u32);
    SUCCESS.0
}
export!(304, create_export);

/// Always 1, as stock.
pub(crate) extern "C" fn destroy(queue: u32) -> u32 {
    if queue != 0 && exchange(queue as usize + usize::from(SHAPE.tag), 0) == LFQU {
        Object {
            base: queue as usize,
            shape: &SHAPE,
        }
        .free_storage(&[BASE]);
    }
    1
}
export!(305, destroy);

extern "C" fn count(queue: u32, output: u32) -> u32 {
    read_field(queue, &SHAPE, SHAPE.count, output)
}
export!(306, count);

/// 1 when the queue is empty or invalid; a lagging tail is advanced.
pub(crate) extern "C" fn is_empty(queue: u32) -> u32 {
    let Some(queue) = Object::validate(queue, &SHAPE) else {
        return 1;
    };
    let head = queue.base + HEAD;
    let tail = queue.base + TAIL;
    loop {
        let first = load_tagged(head);
        let last = load_tagged(tail);
        let next = load(first.address() as usize);
        if load_tagged(head) != first {
            continue;
        }
        if first.address() != last.address() {
            return 0;
        }
        if next == 0 {
            return 1;
        }
        swap_tagged(tail, last, last.successor(next));
    }
}
export!(307, is_empty);

pub(crate) extern "C" fn dequeue(queue: u32, output: u32) -> u32 {
    let Some(queue) = Object::validate(queue, &SHAPE) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let options = queue.options();
    let wait = if options == 0 {
        None
    } else {
        options_wait(options, Side::Remove)
    };
    let taken = match (wait, queue.item_semaphore()) {
        (Some(wait), Some(semaphore)) => remove_waiting(queue, semaphore, &wait, || take(queue)),
        _ => take(queue).ok_or(Failure::Timeout),
    };
    match taken {
        Ok(value) => {
            queue.count_removed();
            if output != 0 {
                store(output as usize, value);
            }
            SUCCESS.0
        }
        Err(failure) => remove_result(failure),
    }
}
export!(308, dequeue);

/// `callback(context, value, node)` for each item from the head until one
/// returns nonzero; positive results become HRESULTs.
extern "C" fn enumerate(queue: u32, context: u32, callback: u32) -> u32 {
    // Stock checks the callback before the signature.
    let result = match (callback != 0)
        .then(|| Object::validate(queue, &SHAPE))
        .flatten()
    {
        Some(queue) => walk(
            load(load(queue.base + HEAD) as usize),
            ITEM,
            context,
            callback,
        ),
        _ => Err(Failure::InvalidParameter),
    };
    export_result(result)
}
export!(309, enumerate);
