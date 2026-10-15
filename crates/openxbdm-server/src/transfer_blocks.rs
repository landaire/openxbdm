//! Memory a transfer holds from its command to its last continuation call.
//! Stock allocates these blocks from pool memory; a static spare serves one
//! holder at a time so a single client does not depend on pool memory.

use crate::backend::Backend;
use crate::commands::filesystem::PoolBuffer;
use crate::network::SocketId;
use crate::server::MAX_CONNECTIONS;

/// Bytes of the spare: the largest block a transfer holds (the `getcontext`
/// copy).
pub const SPARE_SIZE: usize = 0xa50;

/// A held block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferBlock {
    Spare,
    Pool(PoolBuffer),
}

#[derive(Debug, Clone, Copy)]
struct Holder {
    socket: SocketId,
    block: TransferBlock,
    /// The transfer ended without its last call; the pool block is freed at
    /// the next event pass.
    abandoned: bool,
}

#[derive(Debug)]
pub struct TransferBlocks {
    spare: [u8; SPARE_SIZE],
    holders: [Option<Holder>; MAX_CONNECTIONS],
}

impl TransferBlocks {
    pub const fn new() -> Self {
        Self {
            spare: [0; SPARE_SIZE],
            holders: [None; MAX_CONNECTIONS],
        }
    }

    /// Hold `size` bytes for a transfer of `socket`: the spare when it is
    /// free and large enough, else pool memory. `None` when neither is
    /// available.
    pub fn acquire(
        &mut self,
        backend: &mut dyn Backend,
        socket: SocketId,
        size: u32,
    ) -> Option<TransferBlock> {
        self.release_abandoned(backend);
        let free = self.holders.iter().position(Option::is_none)?;
        let spare_held = self
            .holders
            .iter()
            .flatten()
            .any(|holder| holder.block == TransferBlock::Spare);
        let block = if size as usize <= SPARE_SIZE && !spare_held {
            TransferBlock::Spare
        } else {
            TransferBlock::Pool(backend.allocate_pool(size)?)
        };
        self.holders[free] = Some(Holder {
            socket,
            block,
            abandoned: false,
        });
        Some(block)
    }

    /// [`TransferBlocks::acquire`] a block holding a copy of `data`.
    pub fn hold(
        &mut self,
        backend: &mut dyn Backend,
        socket: SocketId,
        data: &[u8],
    ) -> Option<TransferBlock> {
        let block = self.acquire(backend, socket, data.len() as u32)?;
        self.bytes(backend, block)[..data.len()].copy_from_slice(data);
        Some(block)
    }

    /// The bytes of a held block; the spare is longer than requested.
    pub fn bytes<'a>(
        &'a mut self,
        backend: &'a mut dyn Backend,
        block: TransferBlock,
    ) -> &'a mut [u8] {
        match block {
            TransferBlock::Spare => &mut self.spare,
            TransferBlock::Pool(buffer) => backend.pool(buffer),
        }
    }

    /// The transfer ended.
    pub fn release(&mut self, backend: &mut dyn Backend, block: TransferBlock) {
        if let Some(slot) = self
            .holders
            .iter_mut()
            .find(|slot| slot.is_some_and(|holder| holder.block == block))
        {
            *slot = None;
        }
        if let TransferBlock::Pool(buffer) = block {
            backend.free_pool(buffer);
        }
    }

    /// The transfers of `socket` ended without their last call: the
    /// connection closed, or it runs a new command. The spare is free at
    /// once; pool blocks are freed at the next event pass.
    pub fn abandon(&mut self, socket: SocketId) {
        for slot in &mut self.holders {
            if let Some(holder) = slot
                && holder.socket == socket
            {
                match holder.block {
                    TransferBlock::Spare => *slot = None,
                    TransferBlock::Pool(_) => holder.abandoned = true,
                }
            }
        }
    }

    /// Free the abandoned pool blocks.
    pub fn release_abandoned(&mut self, backend: &mut dyn Backend) {
        for slot in &mut self.holders {
            if let Some(Holder {
                block: TransferBlock::Pool(buffer),
                ..
            }) = slot.take_if(|holder| holder.abandoned)
            {
                backend.free_pool(buffer);
            }
        }
    }
}
