//! Stack 'LfSt' (exports 310-317): a linked stack whose semaphores are
//! handles.

use core::mem::offset_of;
use core::ptr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_core::status::Hresult;
use xbox360_sys::processor::lwsync;
use xbox360_sys::xboxkrnl::Handle;

use super::AllocatorRecord;
use super::Creation;
use super::Error;
use super::ItemOrder;
use super::Layout;
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
use super::TaggedList;
use super::Wait;
use super::claim;
use super::close_semaphore;
use super::container;
use super::create_semaphore;
use super::insert_result;
use super::removed;
use super::report;
use super::success_result;
use super::walk;
use crate::exports::export;

static LAYOUT: Layout = Layout {
    node_size: size_of::<StackNode>() as u32,
    link: NodeWord::Word0,
    semaphores: SemaphoreKind::Handle,
    items: ItemOrder::SemaphoreFirst,
};

/// Stack object (caller-visible, 0x50 bytes, then the allocator record and
/// the options).
#[repr(C, align(8))]
struct Stack {
    /// Free nodes, linked through their next word.
    free: TaggedList,
    /// Nodes holding values, linked through their next word.
    top: TaggedList,
    supply: Supply,
    signature: AtomicU32,

    /// Base of the allocation that holds the stack.
    allocation: AtomicU32,
    /// Address of the allocator record after the stack.
    allocator: AtomicU32,
    /// Address of the options after the allocator record, or 0.
    options: AtomicU32,
}

const _: () = {
    assert!(offset_of!(Stack, top) == 0x08);
    assert!(offset_of!(Stack, supply) == 0x10);
    assert!(offset_of!(Stack, signature) == 0x40);
    assert!(offset_of!(Stack, allocation) == 0x44);
    assert!(offset_of!(Stack, allocator) == 0x48);
    assert!(offset_of!(Stack, options) == 0x4c);
    assert!(size_of::<Stack>() == 0x50);
};

impl Stack {
    /// The stack at `handle`.
    ///
    /// # Safety
    ///
    /// `handle` is 0 or the address of a stack (export contract) that stays
    /// allocated for `'a`.
    unsafe fn from_handle<'a>(handle: u32) -> Option<&'a Self> {
        // SAFETY: the caller guarantees the stack.
        unsafe { container(handle, Signature::STACK, offset_of!(Self, signature)) }
    }

    fn create(creation: &Creation) -> Result<&'static Self, Error> {
        const SIZE: u32 = size_of::<Stack>() as u32;

        let kept = creation.kept_options();
        let extra = kept.map_or(0, |_| size_of::<OptionsRecord>() as u32);
        let memory = AtomicU32::new(0);
        let allocation = creation
            .allocator
            .allocate_aligned(SIZE + AllocatorRecord::SIZE + extra, &memory)
            .ok_or(Error::NotEnoughMemory)?;

        let object = ptr::with_exposed_provenance_mut::<Self>(allocation.aligned.get() as usize);
        // SAFETY: the new allocation holds the object, the allocator record
        // and the kept options, aligned to 128 bytes; zero bytes are a valid
        // stack.
        let stack = unsafe {
            object.write_bytes(0, 1);
            &*object
        };
        stack.allocation.store(allocation.base, Relaxed);
        stack.supply.memory.store(memory.load(Relaxed), Relaxed);

        let record = object.wrapping_add(1).cast::<AllocatorRecord>();
        stack
            .allocator
            .store(record.expose_provenance() as u32, Relaxed);
        let options = record.wrapping_add(1).cast::<OptionsRecord>();
        // SAFETY: the record follows the object inside the allocation.
        unsafe { record.write(creation.allocator) };
        if kept.is_some() {
            stack
                .options
                .store(options.expose_provenance() as u32, Relaxed);
        }

        let counts = creation.counts(LAYOUT.node_size);
        stack.supply.per_block.store(counts.per_block, Relaxed);
        stack.supply.remaining.set(counts.limit);

        let nodes = stack.nodes();
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
                stack
                    .supply
                    .free_semaphore
                    .store(handle.map_or(0, Handle::raw), Relaxed);
                if handle.is_none() {
                    stack.close_semaphores();
                    break 'failed;
                }
            }

            stack.signature.store(Signature::STACK.0, Relaxed);
            let Some(node) = nodes.grow() else {
                stack.close_semaphores();
                break 'failed;
            };

            if nodes.free_semaphore().is_some() {
                let credits = &stack.supply.credits;
                credits.store(credits.load(Relaxed).wrapping_sub(1), Relaxed);
            }

            // SAFETY: the first node of the new block, on no list.
            unsafe { nodes.push_free(node) };
            lwsync();

            // Stock copies the options after the barrier that publishes the
            // stack, before it returns the handle.
            if let Some(kept) = kept {
                let options = stack.options.load(Relaxed);
                // SAFETY: the options word holds the address of the options
                // after the record, inside the allocation.
                unsafe {
                    ptr::with_exposed_provenance_mut::<OptionsRecord>(options as usize).write(*kept)
                };
            }

            return Ok(stack);
        }

        creation.allocator.free(allocation.base);

        Err(Error::NotEnoughMemory)
    }

    /// Clear the signature of the stack at `handle`, close its semaphores
    /// and free it.
    ///
    /// # Safety
    ///
    /// `handle` is 0 or the address of a stack (export contract) on which
    /// no other operation runs, now or later.
    unsafe fn destroy(handle: u32) {
        // SAFETY: the caller guarantees the stack. The reference is not used
        // once the stack is freed.
        let Some(stack) =
            (unsafe { claim::<Self>(handle, Signature::STACK, offset_of!(Self, signature)) })
        else {
            return;
        };

        // Destroy closes the free node semaphore first, unlike a failed
        // creation.
        close_semaphore(&stack.supply.free_semaphore);
        close_semaphore(stack.nodes().item_words().semaphore);

        let allocation = stack.allocation.load(Relaxed);
        let allocator = *stack.nodes().allocator();
        // SAFETY: the block list of the stack, which no operation uses
        // anymore.
        unsafe { allocator.free_blocks(&stack.supply.blocks) };
        allocator.free(allocation);
        lwsync();
    }

    fn nodes(&self) -> Nodes<'_> {
        // SAFETY: the parts of this stack, which creation set up with the
        // stack node layout.
        unsafe { Nodes::new(&self.free, &self.supply, &self.allocator, &LAYOUT) }
    }

    fn options(&self) -> Option<&OptionsRecord> {
        let address = self.options.load(Relaxed);

        // SAFETY: a nonzero options word of a stack holds the address of the
        // options record creation wrote after the allocator record.
        unsafe { ptr::with_exposed_provenance::<OptionsRecord>(address as usize).as_ref() }
    }

    /// Close the item semaphore, then the free node semaphore.
    fn close_semaphores(&self) {
        close_semaphore(self.nodes().item_words().semaphore);
        close_semaphore(&self.supply.free_semaphore);
    }

    fn pop_node(&self) -> Option<NodeAddress> {
        // SAFETY: the value list holds nodes of this stack (module
        // invariants).
        unsafe { self.top.pop(NodeWord::Word0) }
    }

    /// Return an unlinked node to the free list; its value.
    ///
    /// # Safety
    ///
    /// `node` is a node of this stack that no list holds.
    unsafe fn finish(&self, node: NodeAddress) -> u32 {
        // SAFETY: the caller guarantees the node.
        let value = unsafe { node.get::<StackNode, _>(self) }
            .value
            .load(Relaxed);

        let nodes = self.nodes();
        // SAFETY: as above.
        unsafe { nodes.release_node(node) };
        nodes.count_removed();

        value
    }

    fn take(&self) -> Option<u32> {
        // SAFETY: the popped node left the value list.
        self.pop_node().map(|node| unsafe { self.finish(node) })
    }

    fn push(&self, value: u32, wait: &Wait) -> Result<(), Error> {
        let nodes = self.nodes();
        let node = nodes.acquire_node(wait)?;

        // SAFETY: a node of this stack's supply, on no list.
        unsafe {
            node.get::<StackNode, _>(self).value.store(value, Relaxed);
            self.top.push(node, NodeWord::Word0);
        }

        nodes.signal_item();
        nodes.count_added();

        Ok(())
    }

    /// Without the wait option a popped value of 0 reads as an empty stack,
    /// as in stock; the node is still removed.
    fn pop(&self) -> Result<u32, Error> {
        let Some(wait) = self
            .options()
            .and_then(|options| options.wait(Side::Remove))
        else {
            return self
                .take()
                .filter(|&value| value != 0)
                .ok_or(Error::Timeout);
        };

        let nodes = self.nodes();
        match nodes.item_semaphore() {
            // A waiting remover leaves the waiter count before it frees the
            // node, as stock.
            Some(semaphore) => nodes
                .remove_waiting(semaphore, &wait, || self.pop_node())
                // SAFETY: the popped node left the value list.
                .map(|node| unsafe { self.finish(node) }),
            None => self.take().ok_or(Error::Timeout),
        }
    }

    /// `callback(context, value, node)` from the top until one returns
    /// nonzero.
    fn enumerate(&self, context: u32, callback: Routine) -> Result<(), Error> {
        // SAFETY: the nodes linked in this stack (module invariants).
        unsafe { walk(self.top.first(), NodeWord::Word1, context, callback) }
    }
}

/// Stack node (8 bytes).
#[repr(C)]
struct StackNode {
    /// Address of the next node; links the free list too.
    _next: AtomicU32,
    value: AtomicU32,
}

const _: () = assert!(offset_of!(StackNode, value) == NodeWord::Word1 as usize);

/// Stock rechecks the signature and stores -1 when it changed meanwhile.
extern "C" fn memory(stack: u32, output_word: u32) -> Hresult {
    // SAFETY: export 310 contract: `stack` is 0 or a stack of export 311;
    // `output_word` is 0 or a writable word.
    let (stack, output_word) = unsafe { (Stack::from_handle(stack), OutputWord::new(output_word)) };

    let value = stack.map(|stack| {
        if Signature::STACK.is_in(&stack.signature) {
            stack.supply.memory.load(Relaxed)
        } else {
            u32::MAX
        }
    });

    report(value, output_word)
}
export!(310, memory);

extern "C" fn create(descriptor: u32, output_word: u32) -> Hresult {
    // SAFETY: export 311 contract: `output_word` is 0 or a writable word.
    let Some(output_word) = (unsafe { OutputWord::new(output_word) }) else {
        return Hresult::INVALID_ARGUMENT;
    };

    output_word.store(0);

    // SAFETY: export 311 contract: `descriptor` is 0 or a creation
    // descriptor.
    let created =
        unsafe { Creation::from_address(descriptor) }.and_then(|creation| Stack::create(&creation));
    match created {
        Ok(stack) => {
            output_word.store(ptr::from_ref(stack).expose_provenance() as u32);
            Hresult::SUCCESS
        }
        Err(error) => error.into(),
    }
}
export!(311, create);

extern "C" fn destroy(stack: u32) {
    // SAFETY: export 312 contract: `stack` is 0 or a stack of export 311 on
    // which no other operation runs.
    unsafe { Stack::destroy(stack) }
}
export!(312, destroy);

extern "C" fn count(stack: u32, output_word: u32) -> Hresult {
    // SAFETY: export 313 contract: as for export 310.
    let (stack, output_word) = unsafe { (Stack::from_handle(stack), OutputWord::new(output_word)) };

    report(
        stack.map(|stack| stack.nodes().count().load(Relaxed)),
        output_word,
    )
}
export!(313, count);

/// 1 when the stack is empty or invalid.
extern "C" fn is_empty(stack: u32) -> u32 {
    // SAFETY: export 314 contract: `stack` is 0 or a stack of export 311.
    unsafe { Stack::from_handle(stack) }.map_or(1, |stack| u32::from(stack.top.first() == 0))
}
export!(314, is_empty);

extern "C" fn pop(stack: u32, output_word: u32) -> Hresult {
    // SAFETY: export 315 contract: `stack` is 0 or a stack of export 311;
    // `output_word` is 0 or a writable word.
    let (stack, output_word) = unsafe { (Stack::from_handle(stack), OutputWord::new(output_word)) };
    let Some(stack) = stack else {
        return Hresult::INVALID_ARGUMENT;
    };

    removed(stack.pop(), output_word)
}
export!(315, pop);

extern "C" fn push(stack: u32, value: u32) -> Hresult {
    // SAFETY: export 316 contract: `stack` is 0 or a stack of export 311.
    let Some(stack) = (unsafe { Stack::from_handle(stack) }) else {
        return Hresult::INVALID_ARGUMENT;
    };

    // Without the wait option stock takes a path whose effects match a wait
    // that neither spins nor blocks.
    let wait = stack
        .options()
        .and_then(|options| options.wait(Side::Insert))
        .unwrap_or(Wait::NONE);

    insert_result(stack.push(value, &wait))
}
export!(316, push);

/// `callback(context, value, node)` from the top until one returns
/// nonzero; positive results become HRESULTs.
extern "C" fn enumerate(stack: u32, context: u32, callback: u32) -> Hresult {
    // Stock checks the callback before the signature.
    // SAFETY: export 317 contract: `callback` is 0 or a console routine.
    let Some(callback) = (unsafe { Routine::new(callback) }) else {
        return success_result(Err(Error::InvalidArgument));
    };

    // SAFETY: export 317 contract: `stack` is 0 or a stack of export 311.
    let Some(stack) = (unsafe { Stack::from_handle(stack) }) else {
        return success_result(Err(Error::InvalidArgument));
    };

    success_result(stack.enumerate(context, callback))
}
export!(317, enumerate);
