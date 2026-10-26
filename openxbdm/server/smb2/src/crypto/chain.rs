//! Block chaining shared by CMAC, CBC-MAC, and GHASH: each 16-byte block is
//! XORed into the state, which a keyed function then transforms.

/// Keyed function applied to the state after each block.
pub(super) trait ChainStep {
    fn step(&self, state: &mut [u8; 16]);
}

impl ChainStep for super::aes::Aes128 {
    fn step(&self, state: &mut [u8; 16]) {
        self.encrypt_block(state);
    }
}

/// The step is taken through `dyn` so one copy of the buffering serves
/// every mode.
#[derive(Clone)]
pub(super) struct Chain {
    pub(super) state: [u8; 16],
    pending: [u8; 16],
    used: usize,
}

impl Chain {
    pub(super) const fn new() -> Self {
        Self {
            state: [0; 16],
            pending: [0; 16],
            used: 0,
        }
    }

    /// Append `data`. A full block stays pending until more data arrives,
    /// so CMAC can treat the final block specially.
    pub(super) fn update(&mut self, mut data: &[u8], step: &dyn ChainStep) {
        while !data.is_empty() {
            if self.used == 16 {
                self.fold();
                step.step(&mut self.state);
            }

            let take = data.len().min(16 - self.used);
            let (head, rest) = data.split_at(take);
            self.pending[self.used..self.used + take].copy_from_slice(head);
            self.used += take;
            data = rest;
        }
    }

    /// Process pending bytes as one block zero-padded to 16 bytes.
    pub(super) fn pad(&mut self, step: &dyn ChainStep) {
        if self.used > 0 {
            self.fold();
            step.step(&mut self.state);
        }
    }

    /// XOR pending bytes into the state without the step; returns how many
    /// there were.
    pub(super) fn fold(&mut self) -> usize {
        let used = self.used;

        for (byte, pending) in self.state.iter_mut().zip(&self.pending[..used]) {
            *byte ^= pending;
        }
        self.used = 0;

        used
    }
}
