//! Simulated PIX engine.

use openxbdm_server::commands::performance::PixDogma;
use openxbdm_server::commands::performance::PixMessage;

/// Simulated PIX engine.
#[derive(Debug, Clone, Default)]
pub struct Pix {
    /// A PIX session exists; without one nothing can be posted.
    pub session: bool,
    pub queue: Vec<PixMessage>,

    pub status: [u32; 12],
    pub frame_statistics: Option<[u32; 3]>,
    pub frame_number: i32,
    pub events: Vec<u32>,

    pub trace: bool,
    pub bitmap: [u32; 2],
    pub group_calls: Vec<GroupCall>,

    pub capture_values: [u32; 2],
    pub capture_text: Vec<u8>,
    pub legacy: bool,
    pub gpu_capture: bool,
    pub dogma: Option<PixDogma>,
    pub boot_animation: bool,
    pub capture_ready: bool,

    /// Bytes queued in the trace ring.
    pub ring: Vec<u8>,
    /// Bytes of the snapshot not yet read.
    snapshot: Vec<u8>,
}

/// A call that enables or disables a PIX group other than the first.
#[derive(Debug, Clone, Copy)]
pub struct GroupCall {
    pub group: u32,
    pub id: u32,
    pub enabled: bool,
}

impl Pix {
    /// Queue `message`; a code 0xc message replaces a queued one.
    pub(super) fn post(&mut self, message: PixMessage) -> bool {
        const QUEUE_CAPACITY: usize = 8;

        if !self.session {
            return false;
        }

        if message.code == 0xc
            && let Some(queued) = self.queue.iter_mut().find(|queued| queued.code == 0xc)
        {
            *queued = message;
            return true;
        }

        if self.queue.len() >= QUEUE_CAPACITY {
            return false;
        }

        self.queue.push(message);

        true
    }

    /// Move the trace ring into the snapshot; returns its whole-word length.
    pub(super) fn take_snapshot(&mut self) -> u32 {
        self.snapshot = std::mem::take(&mut self.ring);

        self.snapshot.len() as u32 & !3
    }

    /// Move the whole-word part of the snapshot that fits into `output`.
    pub(super) fn read_snapshot(&mut self, output: &mut [u8]) -> usize {
        let count = (self.snapshot.len() & !3).min(output.len());
        output[..count].copy_from_slice(&self.snapshot[..count]);
        self.snapshot.drain(..count);

        count
    }
}
