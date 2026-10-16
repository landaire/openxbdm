//! Stack 'LfSt' (exports 310-317): a linked stack whose semaphores are
//! handles.
//!
//! Object (0x50 bytes, then the allocator record and the options): +0x00
//! free nodes (tagged), +0x08 top (tagged), +0x10 free node credits,
//! +0x14 free node semaphore, +0x18 blocked removers, +0x1c item
//! semaphore, +0x20 item count, +0x28 node blocks (tagged), +0x30 nodes per
//! block, +0x34 nodes the limit allows, +0x38 node total, +0x3c bytes
//! allocated, +0x40 signature, +0x44 allocation base, +0x48 allocator
//! record, +0x4c options. Nodes are 8 bytes: +0 next, +4 value; the free
//! list links through +0.

use openxbdm_core::status::Hresult;

use super::ALLOCATOR_SIZE;
use super::Allocator;
use super::CREATE_FAILED;
use super::Creation;
use super::Failure;
use super::OPTIONS_SIZE;
use super::Object;
use super::REMOVE_TIMEOUT;
use super::SUCCESS;
use super::SemaphoreKind;
use super::Shape;
use super::Side;
use super::UNLIMITED;
use super::Wait;
use super::close_handle;
use super::copy;
use super::counts;
use super::create_semaphore;
use super::exchange;
use super::export_result;
use super::insert_result;
use super::load;
use super::lwsync;
use super::options_wait;
use super::pop;
use super::push;
use super::read_field;
use super::remove_result;
use super::remove_waiting;
use super::store;
use super::walk;
use super::zero;
use crate::exports::export;

const LFST: u32 = u32::from_be_bytes(*b"LfSt");
const TOP: usize = 0x08;
const BASE: u8 = 0x44;
/// Bytes of the object before the allocator record.
const OBJECT_SIZE: u32 = 0x50;
const NODE_SIZE: u8 = 8;
/// Value of a node.
const VALUE: usize = 4;

static SHAPE: Shape = Shape {
    signature: LFST,
    tag: 0x40,
    credits: 0x10,
    free_semaphore: 0x14,
    waiters: 0x18,
    item_semaphore: 0x1c,
    count: 0x20,
    blocks: 0x28,
    grow: 0x30,
    remaining: 0x34,
    total: 0x38,
    memory: 0x3c,
    allocator: 0x48,
    options: 0x4c,
    node_size: NODE_SIZE,
    link: 0,
    semaphores: SemaphoreKind::Handle,
};

/// Close the semaphores a stack holds: the item semaphore, then the free
/// node semaphore.
fn close_semaphores(stack: Object) {
    for offset in [SHAPE.item_semaphore, SHAPE.free_semaphore] {
        let handle = load(stack.field(offset));
        if handle != 0 {
            close_handle(handle);
        }
    }
}

fn create(creation: &Creation, extra: u32) -> Option<Object> {
    let mut memory = 0u32;
    let counter = &raw mut memory as usize;
    let (base, raw) = Allocator::of(&creation.allocator)
        .allocate_aligned(OBJECT_SIZE + ALLOCATOR_SIZE + extra, counter)?;
    let base = base as usize;
    let stack = Object {
        base,
        shape: &SHAPE,
    };
    zero(base, OBJECT_SIZE as usize);
    store(stack.field(BASE), raw);
    store(stack.field(SHAPE.memory), load(counter));
    let record = base + OBJECT_SIZE as usize;
    store(stack.field(SHAPE.allocator), record as u32);
    copy(
        record,
        creation.allocator.as_ptr() as usize,
        ALLOCATOR_SIZE as usize,
    );
    if extra != 0 {
        store(stack.field(SHAPE.options), record as u32 + ALLOCATOR_SIZE);
    }
    let (initial, limit) = counts(creation.initial, creation.limit, u32::from(NODE_SIZE));
    store(stack.field(SHAPE.grow), initial);
    store(stack.field(SHAPE.remaining), limit.unwrap_or(UNLIMITED));
    let mut created = true;
    if creation.item_wait() {
        let handle = create_semaphore();
        store(stack.field(SHAPE.item_semaphore), handle);
        created = handle != 0;
    }
    if created && creation.free_wait() && limit.is_some() {
        let handle = create_semaphore();
        store(stack.field(SHAPE.free_semaphore), handle);
        if handle == 0 {
            close_semaphores(stack);
            created = false;
        }
    }
    if created {
        store(stack.field(SHAPE.tag), LFST);
        if let Some(node) = stack.grow() {
            if stack.free_semaphore().is_some() {
                let credits = stack.field(SHAPE.credits);
                store(credits, load(credits).wrapping_sub(1));
            }
            stack.push_node(node);
            lwsync();
            return Some(stack);
        }
        close_semaphores(stack);
    }
    stack.allocator().free(raw);
    None
}

/// Return an unlinked top node to the free list; its value.
fn finish(stack: Object, node: u32) -> u32 {
    let value = load(node as usize + VALUE);
    stack.release_node(node);
    stack.count_removed();
    value
}

fn take(stack: Object) -> Option<u32> {
    pop(stack.base + TOP, 0).map(|node| finish(stack, node))
}

fn push_value(stack: Object, value: u32, wait: &Wait) -> Result<(), Failure> {
    let node = stack.acquire_node(wait)?;
    store(node as usize + VALUE, value);
    push(stack.base + TOP, node, 0);
    stack.signal_item();
    stack.count_added();
    Ok(())
}

/// Stock rechecks the signature and stores -1 when it changed meanwhile.
extern "C" fn memory(stack: u32, output: u32) -> u32 {
    let Some(stack) = Object::validate(stack, &SHAPE).filter(|_| output != 0) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let value = if load(stack.field(SHAPE.tag)) == LFST {
        load(stack.field(SHAPE.memory))
    } else {
        u32::MAX
    };
    store(output as usize, value);
    SUCCESS.0
}
export!(310, memory);

extern "C" fn create_export(descriptor: u32, output: u32) -> u32 {
    if output == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    store(output as usize, 0);
    let creation = match Creation::read(descriptor) {
        Ok(creation) => creation,
        Err(error) => return Hresult::from(error).0,
    };
    let options = creation.keeps_options();
    let Some(stack) = create(&creation, if options { OPTIONS_SIZE } else { 0 }) else {
        return CREATE_FAILED.0;
    };
    if options {
        copy(stack.options(), creation.descriptor, OPTIONS_SIZE as usize);
    }
    store(output as usize, stack.base as u32);
    SUCCESS.0
}
export!(311, create_export);

extern "C" fn destroy(stack: u32) {
    if stack != 0 && exchange(stack as usize + usize::from(SHAPE.tag), 0) == LFST {
        let stack = Object {
            base: stack as usize,
            shape: &SHAPE,
        };
        // Destroy closes the free node semaphore first, unlike a failed
        // creation.
        for offset in [SHAPE.free_semaphore, SHAPE.item_semaphore] {
            let handle = load(stack.field(offset));
            if handle != 0 {
                close_handle(handle);
            }
        }
        stack.free_storage(&[BASE]);
    }
}
export!(312, destroy);

extern "C" fn count(stack: u32, output: u32) -> u32 {
    read_field(stack, &SHAPE, SHAPE.count, output)
}
export!(313, count);

/// 1 when the stack is empty or invalid.
extern "C" fn is_empty(stack: u32) -> u32 {
    Object::validate(stack, &SHAPE).map_or(1, |stack| u32::from(load(stack.base + TOP) == 0))
}
export!(314, is_empty);

/// Without the wait option a popped value of 0 reads as an empty stack, as
/// in stock; the node is still removed.
extern "C" fn pop_export(stack: u32, output: u32) -> u32 {
    let Some(stack) = Object::validate(stack, &SHAPE) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let options = stack.options();
    let wait = if options == 0 {
        None
    } else {
        options_wait(options, Side::Remove)
    };
    let value = match wait {
        Some(wait) => {
            // A waiting remover leaves the waiter count before it frees the
            // node, as stock.
            let taken = match stack.item_semaphore() {
                Some(semaphore) => {
                    remove_waiting(stack, semaphore, &wait, || pop(stack.base + TOP, 0))
                        .map(|node| finish(stack, node))
                }
                None => take(stack).ok_or(Failure::Timeout),
            };
            match taken {
                Ok(value) => value,
                Err(failure) => return remove_result(failure),
            }
        }
        None => match take(stack) {
            Some(value) if value != 0 => value,
            _ => return REMOVE_TIMEOUT.0,
        },
    };
    if output != 0 {
        store(output as usize, value);
    }
    SUCCESS.0
}
export!(315, pop_export);

extern "C" fn push_export(stack: u32, value: u32) -> u32 {
    let Some(stack) = Object::validate(stack, &SHAPE) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let options = stack.options();
    // Without the wait option stock takes a path whose effects match a wait
    // that neither spins nor blocks.
    let wait = if options == 0 {
        None
    } else {
        options_wait(options, Side::Insert)
    };
    insert_result(push_value(stack, value, &wait.unwrap_or(Wait::NONE)))
}
export!(316, push_export);

/// `callback(context, value, node)` from the top until one returns
/// nonzero; positive results become HRESULTs.
extern "C" fn enumerate(stack: u32, context: u32, callback: u32) -> u32 {
    // Stock checks the callback before the signature.
    let result = match (callback != 0)
        .then(|| Object::validate(stack, &SHAPE))
        .flatten()
    {
        Some(stack) => walk(load(stack.base + TOP), VALUE, context, callback),
        _ => Err(Failure::InvalidParameter),
    };
    export_result(result)
}
export!(317, enumerate);
