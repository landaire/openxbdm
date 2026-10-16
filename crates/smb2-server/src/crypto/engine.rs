//! Merkle-Damgard block buffering shared by MD4, MD5, and SHA-256.

/// Compression function over a 64-byte block. MD4 and MD5 use the first
/// four state words.
pub(super) type Compress = fn(&mut [u32; 8], &[u8; 64]);

#[derive(Clone)]
pub(super) struct Engine {
    state: [u32; 8],
    block: [u8; 64],
    used: usize,
    length: u64,
    compress: Compress,
    big_endian: bool,
}

impl Engine {
    pub(super) const fn new(state: [u32; 8], compress: Compress, big_endian: bool) -> Self {
        Self {
            state,
            block: [0; 64],
            used: 0,
            length: 0,
            compress,
            big_endian,
        }
    }

    pub(super) fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.used > 0 {
            let take = data.len().min(64 - self.used);
            let (head, rest) = data.split_at(take);
            self.block[self.used..self.used + take].copy_from_slice(head);
            self.used += take;
            data = rest;
            if self.used < 64 {
                return;
            }
            (self.compress)(&mut self.state, &self.block);
            self.used = 0;
        }
        while let Some((block, rest)) = data.split_first_chunk::<64>() {
            (self.compress)(&mut self.state, block);
            data = rest;
        }
        self.block[..data.len()].copy_from_slice(data);
        self.used = data.len();
    }

    /// Pad the message and write the first `output.len() / 4` state words.
    pub(super) fn finish(&mut self, output: &mut [u8]) {
        let bits = self.length.wrapping_mul(8);
        self.block[self.used] = 0x80;
        self.block[self.used + 1..].fill(0);
        if self.used >= 56 {
            (self.compress)(&mut self.state, &self.block);
            self.block.fill(0);
        }
        let length = if self.big_endian {
            bits.to_be_bytes()
        } else {
            bits.to_le_bytes()
        };
        self.block[56..].copy_from_slice(&length);
        (self.compress)(&mut self.state, &self.block);
        for (word, bytes) in self.state.iter().zip(output.as_chunks_mut::<4>().0) {
            let encoded = if self.big_endian {
                word.to_be_bytes()
            } else {
                word.to_le_bytes()
            };
            *bytes = encoded;
        }
    }
}
