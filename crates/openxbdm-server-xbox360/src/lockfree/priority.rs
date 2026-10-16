//! Priority queue 'LFPQ' (exports 320-328): a sorted list in the queue
//! object layout, keyed by the low word of each item through the compare
//! routine. Hash table buckets use the same list routines.
//!
//! Options (0x24 bytes): +0 compare(key, key) routine, +4 hash(key,
//! buckets) routine, +8 the options record. Nodes are 0x10 bytes: +0 next
//! (tagged, marked once deleted), +8 value, +0xc key; the free list links
//! through +8. The list starts after the sentinel node whose address the
//! object (+0x10) or the bucket holds.

use openxbdm_core::status::Hresult;

use super::Backoff;
use super::CREATE_FAILED;
use super::Creation;
use super::Failure;
use super::InvalidArgument;
use super::MARK;
use super::OPTIONS_SIZE;
use super::Object;
use super::SPIN_ATTEMPTS;
use super::SUCCESS;
use super::Shape;
use super::Side;
use super::Tagged;
use super::UNIQUE_FLAG;
use super::Wait;
use super::call;
use super::copy;
use super::exchange;
use super::export_result;
use super::fetch_add;
use super::fetch_sub;
use super::insert_result;
use super::load;
use super::load_quad;
use super::load_tagged;
use super::options_wait;
use super::options_wait_with;
use super::read_field;
use super::remove_result;
use super::store;
use super::swap_tagged;
use super::walk;
use crate::exports::export;

const LFPQ: u32 = u32::from_be_bytes(*b"LFPQ");
static SHAPE: Shape = super::queue::shape(LFPQ);
const HEAD: usize = 0x10;
const BASE: u8 = 0x74;
/// Fields of a node.
pub(super) const VALUE: usize = 8;
const KEY: usize = 0xc;
/// Key stock stores in a node it unlinks.
const RETIRED_KEY: Key = Key(u32::MAX);

/// Sort key of an item.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Key(pub(super) u32);

/// An item as nodes hold it.
pub(super) struct Item {
    pub(super) value: u32,
    pub(super) key: Key,
}

/// Bytes of the options of a sorted container.
pub(super) const SORTED_OPTIONS_SIZE: u32 = 0x24;
/// Options record within the options of a sorted container.
pub(super) const RECORD: usize = 8;
/// Size field value of a compare descriptor: +0 compare routine, +4 hash
/// routine, +8 size.
const COMPARE_DESCRIPTOR_SIZE: u32 = 0xc;

/// Unsigned order of two keys: -1, 0 or 1.
extern "C" fn default_compare(left: u32, right: u32) -> i32 {
    left.cmp(&right) as i32
}

/// Bucket of `key` among a power-of-two count of `buckets`.
extern "C" fn default_hash(key: u32, buckets: u32) -> u32 {
    let mixed = u64::from(key)
        .wrapping_mul(0xfaf5_7cee_8543_3e40)
        .wrapping_add(0xfc2d_7230_d92f_2eac);
    (mixed >> 32) as u32 & buckets.wrapping_sub(1)
}

/// Options of a sorted container.
pub(super) struct SortedOptions {
    pub(super) words: [u32; SORTED_OPTIONS_SIZE as usize / 4],
    /// The compare descriptor supplied a hash routine.
    pub(super) custom_hash: bool,
}

/// Options from a creation and a compare descriptor (optional): the
/// routines default to unsigned order and multiplicative hashing.
pub(super) fn sorted_options(
    creation: &Creation,
    compare: u32,
) -> Result<SortedOptions, InvalidArgument> {
    let mut words = [0; SORTED_OPTIONS_SIZE as usize / 4];
    words[0] = default_compare as extern "C" fn(u32, u32) -> i32 as usize as u32;
    words[1] = super::routine(default_hash);
    if creation.descriptor != 0 {
        copy(
            words[2..].as_mut_ptr() as usize,
            creation.descriptor,
            OPTIONS_SIZE as usize,
        );
    }
    let mut custom_hash = false;
    if compare != 0 {
        let compare = compare as usize;
        if load(compare + 8) != COMPARE_DESCRIPTOR_SIZE {
            return Err(InvalidArgument);
        }
        let routine = load(compare);
        if routine != 0 {
            words[0] = routine;
        }
        let hash = load(compare + 4);
        if hash != 0 {
            words[1] = hash;
            custom_hash = true;
        }
    }
    Ok(SortedOptions { words, custom_hash })
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

/// Wait behavior and search of an insertion, from one read of the option
/// flags.
pub(super) fn insert_options(record: usize) -> (Wait, Search) {
    let flags = load(record);
    let search = if flags & UNIQUE_FLAG != 0 {
        Search::Exact
    } else {
        Search::After
    };
    (
        options_wait_with(record, flags, Side::Insert).unwrap_or(Wait::NONE),
        search,
    )
}

/// Result of a list walk.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    /// The list was empty at the first look.
    Empty,
    Missing,
    Found,
}

/// Where a walk stopped: the link that points at `current` and its value,
/// and the value of the link of `current`.
struct Position {
    outcome: Outcome,
    previous: usize,
    link: Tagged,
    current: u32,
    next: Tagged,
}

fn compare(list: Object, left: Key, right: Key) -> i32 {
    call(load(list.options()), left.0, right.0, 0, 0) as i32
}

/// Walk the list after the sentinel at `*head`, unlinking and freeing
/// deleted nodes on the way.
fn find(list: Object, head: usize, key: Key, search: Search) -> Position {
    let mut next = Tagged(0);
    let mut visited = false;
    'restart: loop {
        let mut previous = load(head) as usize;
        let mut link = load_tagged(previous);
        loop {
            let current = link.address();
            if current == 0 {
                let outcome = if visited {
                    Outcome::Missing
                } else {
                    Outcome::Empty
                };
                return Position {
                    outcome,
                    previous,
                    link,
                    current,
                    next,
                };
            }
            next = load_tagged(current as usize);
            visited = true;
            let current_key = Key(load(current as usize + KEY));
            if link.low() & MARK != 0 || load_tagged(previous) != link {
                continue 'restart;
            }
            if next.low() & MARK != 0 {
                if !swap_tagged(previous, link, link.successor(next.address())) {
                    continue 'restart;
                }
                list.release_node(current);
                // Stock keeps the deleted node's mark in the expected link,
                // so the walk restarts unless the list ends here.
                link = Tagged::new(
                    next.address(),
                    (next.low() & MARK) | (link.low().wrapping_add(1) & !MARK),
                );
                next = link;
                continue;
            }
            let outcome = match search {
                Search::First => Outcome::Found,
                Search::After if compare(list, key, current_key) >= 0 => {
                    previous = current as usize;
                    link = next;
                    continue;
                }
                Search::After => Outcome::Missing,
                Search::Exact => match compare(list, key, current_key) {
                    order if order > 0 => {
                        previous = current as usize;
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
                current,
                next,
            };
        }
    }
}

/// Insert an item; a found key (unique keys only) fails like a timeout.
pub(super) fn insert(
    list: Object,
    head: usize,
    item: Item,
    wait: &Wait,
    search: Search,
) -> Result<(), Failure> {
    let node = list.acquire_node(wait)?;
    let address = node as usize;
    store(address, 0);
    store(address + 4, (load(address + 4) & !MARK).wrapping_add(1));
    store(address + VALUE, item.value);
    store(address + KEY, item.key.0);
    let key = item.key;
    loop {
        let position = find(list, head, key, search);
        if position.outcome == Outcome::Found {
            list.release_node(node);
            return Err(Failure::Timeout);
        }
        store(address, position.current);
        store(address + 4, load(address + 4) & !MARK);
        if swap_tagged(
            position.previous,
            position.link,
            position.link.successor(node),
        ) {
            break;
        }
    }
    list.count_added();
    list.signal_item();
    Ok(())
}

/// Mark and unlink the node the search finds by `item`'s key, and store its
/// item there.
fn try_remove(list: Object, head: usize, item: &mut Item, search: Search) -> Outcome {
    let mut position = find(list, head, item.key, search);
    loop {
        if position.outcome != Outcome::Found {
            return position.outcome;
        }
        let current = position.current as usize;
        let removed = load_quad(current + VALUE);
        let next = position.next;
        let marked = Tagged::new(next.address(), next.successor(0).low() | MARK);
        if swap_tagged(current, next, marked) {
            if swap_tagged(
                position.previous,
                position.link,
                position.link.successor(next.address()),
            ) {
                store(current + KEY, RETIRED_KEY.0);
                list.release_node(position.current);
            } else {
                find(list, head, item.key, search);
            }
            *item = Item {
                value: (removed >> 32) as u32,
                key: Key(removed as u32),
            };
            return Outcome::Found;
        }
        position = find(list, head, item.key, search);
    }
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

/// Remove an item, waiting for one when `blocking` and the item semaphore
/// allow.
pub(super) fn remove(
    list: Object,
    head: usize,
    item: &mut Item,
    wait: &Wait,
    search: Search,
    blocking: Blocking,
    handoff: Handoff,
) -> Result<(), Failure> {
    let mut attempt = || try_remove(list, head, item, search);
    let found = 'found: {
        let Some(semaphore) = list.item_semaphore() else {
            break 'found attempt() == Outcome::Found;
        };
        if attempt() == Outcome::Found {
            break 'found true;
        }
        if blocking == Blocking::Once {
            break 'found false;
        }
        let mut backoff = Backoff(0);
        if wait.spin {
            for _ in 0..SPIN_ATTEMPTS {
                backoff.pause();
                if attempt() == Outcome::Found {
                    break 'found true;
                }
            }
        }
        let waiters = list.field(list.shape.waiters);
        fetch_add(waiters, 1);
        let mut outcome = attempt();
        while outcome != Outcome::Found {
            if wait.spin {
                backoff.pause();
            }
            if let Err(failure) = wait.block(semaphore) {
                fetch_sub(waiters, 1);
                return Err(failure);
            }
            outcome = attempt();
            let pass_on = match handoff {
                Handoff::Missing => outcome == Outcome::Missing,
                Handoff::Items => load(list.field(list.shape.count)) as i32 > 0,
            };
            if pass_on {
                semaphore.release(1);
            }
        }
        fetch_sub(waiters, 1);
        true
    };
    if !found {
        return Err(Failure::Timeout);
    }
    list.count_removed();
    Ok(())
}

/// Whether the list holds a node that is not deleted.
pub(super) fn occupied(list: Object, head: usize) -> bool {
    find(list, head, Key(0), Search::First).outcome == Outcome::Found
}

/// First node after the sentinel at `*head`.
pub(super) fn first(head: usize) -> u32 {
    load(load(head) as usize)
}

extern "C" fn insert_export(queue: u32, key: u32, value: u32) -> u32 {
    let Some(queue) = Object::validate(queue, &SHAPE) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let (wait, search) = insert_options(queue.options() + RECORD);
    insert_result(insert(
        queue,
        queue.base + HEAD,
        Item {
            value,
            key: Key(key),
        },
        &wait,
        search,
    ))
}
export!(320, insert_export);

extern "C" fn memory(queue: u32, output: u32) -> u32 {
    read_field(queue, &SHAPE, SHAPE.memory, output)
}
export!(321, memory);

/// `compare` is an optional compare descriptor.
extern "C" fn create_export(descriptor: u32, compare: u32, output: u32) -> u32 {
    if output == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    store(output as usize, 0);
    let creation = match Creation::read(descriptor) {
        Ok(creation) => creation,
        Err(error) => return Hresult::from(error).0,
    };
    let options = match sorted_options(&creation, compare) {
        Ok(options) => options,
        Err(error) => return Hresult::from(error).0,
    };
    let Some(queue) = super::queue::create(&SHAPE, &creation, SORTED_OPTIONS_SIZE) else {
        return CREATE_FAILED.0;
    };
    copy(
        queue.options(),
        options.words.as_ptr() as usize,
        SORTED_OPTIONS_SIZE as usize,
    );
    store(output as usize, queue.base as u32);
    SUCCESS.0
}
export!(322, create_export);

/// Always 1, as stock.
extern "C" fn destroy(queue: u32) -> u32 {
    if queue != 0 && exchange(queue as usize + usize::from(SHAPE.tag), 0) == LFPQ {
        Object {
            base: queue as usize,
            shape: &SHAPE,
        }
        .free_storage(&[BASE]);
    }
    1
}
export!(323, destroy);

extern "C" fn count(queue: u32, output: u32) -> u32 {
    read_field(queue, &SHAPE, SHAPE.count, output)
}
export!(324, count);

/// 1 when the queue is empty or invalid.
extern "C" fn is_empty(queue: u32) -> u32 {
    Object::validate(queue, &SHAPE)
        .map_or(1, |queue| u32::from(!occupied(queue, queue.base + HEAD)))
}
export!(325, is_empty);

/// Remove an item (by key with [`Search::Exact`]) and store its value.
fn take(queue: u32, key: Key, search: Search, output: u32) -> u32 {
    let Some(queue) = Object::validate(queue, &SHAPE) else {
        return Hresult::INVALID_ARGUMENT.0;
    };
    let wait = options_wait(queue.options() + RECORD, Side::Remove).unwrap_or(Wait::NONE);
    let mut item = Item { value: 0, key };
    if let Err(failure) = remove(
        queue,
        queue.base + HEAD,
        &mut item,
        &wait,
        search,
        Blocking::Wait,
        Handoff::Missing,
    ) {
        return remove_result(failure);
    }
    if output != 0 {
        store(output as usize, item.value);
    }
    SUCCESS.0
}

extern "C" fn remove_first(queue: u32, output: u32) -> u32 {
    take(queue, Key(0), Search::First, output)
}
export!(326, remove_first);

extern "C" fn remove_key(queue: u32, key: u32, output: u32) -> u32 {
    take(queue, Key(key), Search::Exact, output)
}
export!(327, remove_key);

/// `callback(context, value, node)` in key order until one returns nonzero;
/// positive results become HRESULTs.
extern "C" fn enumerate(queue: u32, context: u32, callback: u32) -> u32 {
    // Stock checks the callback before the signature.
    let result = match (callback != 0)
        .then(|| Object::validate(queue, &SHAPE))
        .flatten()
    {
        Some(queue) => walk(first(queue.base + HEAD), VALUE, context, callback),
        _ => Err(Failure::InvalidParameter),
    };
    export_result(result)
}
export!(328, enumerate);
