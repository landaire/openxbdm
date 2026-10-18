//! Notification texts queued for the server thread.

/// Longest notification text a posted slot holds.
pub const POSTED_TEXT_CAPACITY: usize = 0x200;
/// Posted texts that can wait for the server thread in slots.
pub const POSTED_TEXT_SLOTS: usize = 16;

/// Notification texts posted for the server thread, oldest first. The
/// monitor sends such texts in the posting thread; here the server thread
/// sends them on its next pass. Platforms keep the queue under their own
/// lock, together with the texts that did not fit it.
#[derive(Debug, Clone)]
pub struct PostedTexts {
    texts: [[u8; POSTED_TEXT_CAPACITY]; POSTED_TEXT_SLOTS],
    lengths: [u16; POSTED_TEXT_SLOTS],
    first: usize,
    count: usize,
}

impl PostedTexts {
    pub const fn new() -> Self {
        Self {
            texts: [[0; POSTED_TEXT_CAPACITY]; POSTED_TEXT_SLOTS],
            lengths: [0; POSTED_TEXT_SLOTS],
            first: 0,
            count: 0,
        }
    }

    pub const fn is_full(&self) -> bool {
        self.count == POSTED_TEXT_SLOTS
    }

    /// Queue `text`. `false` when the queue is full or `text` is longer
    /// than [`POSTED_TEXT_CAPACITY`].
    pub fn push(&mut self, text: &[u8]) -> bool {
        if self.is_full() || text.len() > POSTED_TEXT_CAPACITY {
            return false;
        }

        let slot = (self.first + self.count) % POSTED_TEXT_SLOTS;
        self.texts[slot][..text.len()].copy_from_slice(text);
        self.lengths[slot] = text.len() as u16;
        self.count += 1;

        true
    }

    /// Move the oldest text into `output`; returns its length.
    pub fn pop(&mut self, output: &mut [u8; POSTED_TEXT_CAPACITY]) -> Option<usize> {
        if self.count == 0 {
            return None;
        }

        let length = self.lengths[self.first] as usize;
        output[..length].copy_from_slice(&self.texts[self.first][..length]);
        self.first = (self.first + 1) % POSTED_TEXT_SLOTS;
        self.count -= 1;

        Some(length)
    }
}

impl Default for PostedTexts {
    fn default() -> Self {
        Self::new()
    }
}
