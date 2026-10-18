//! XAM's media verification service (`civremote.cpp`, object 0x81d22368)
//! with a drive that holds no disc. Its worker runs passes against the
//! simulated millisecond clock.

use openxbdm_core::status::Win32Error;
use openxbdm_server::commands::services::CivProgress;

/// `ERROR_ACCESS_DENIED`: a verification session is already open.
const SESSION_OPEN: Win32Error = Win32Error::new(5).unwrap();
/// `ERROR_LOCK_VIOLATION`: no session is ready for a pass.
const SESSION_NOT_READY: Win32Error = Win32Error::new(0x21).unwrap();
/// `ERROR_FILE_CORRUPT`: the last startup failed a check.
const CHECK_FAILED: Win32Error = Win32Error::new(0x570).unwrap();
/// `ERROR_DISK_CORRUPT`: the session's startup failed.
const STARTUP_FAILED: Win32Error = Win32Error::new(0x571).unwrap();

/// Detection bit 12 marks a hash failure (0x81a15f50).
const HASH_FAILURE_DETECTED: u64 = 1 << 12;
/// Wait of a no-media read: verifier +0x100b0, set to 100 by 0x81a16c08 and
/// waited on the worker's own thread handle (0x81a16550).
const READ_MS: u64 = 100;
/// Wait of an unlimited pass between blocks (0x81a18148).
const THROTTLE_WAIT_MS: u64 = 200;
/// Interval between waits of a pass with the detection flag (0x81a18004);
/// other unlimited passes wait after every block.
const DETECTED_THROTTLE_INTERVAL_MS: u64 = 300;
/// Budget of `XamMediaVerificationVerify` that never ends a pass.
const UNLIMITED: u32 = u32::MAX;
/// Sectors per block (0x81a178b8).
const BLOCK_SECTORS: u32 = 16;
/// A hash index block covers 0x8000 sectors (0x81a17c54).
const INDEX_SHIFT: u32 = 15;
/// Total blocks of the no-media layout: (0x204d10 + 0x203d10) sectors
/// (0x81a17514) in blocks of 16 (0x81a180e0).
const NO_MEDIA_TOTAL_BLOCKS: u32 = (0x20_4d10 + 0x20_3d10) >> 4;

/// State word of the service (0x81d7e0cc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionState {
    /// 0: no session.
    #[default]
    Idle,
    /// 3: the worker waits for a pass request.
    Ready,
    /// 4: the worker runs a pass.
    Busy,
    /// 5: the worker's startup failed; only a close leaves this state.
    Failed,
}

/// The session's verifier (static 0x81d7e268).
#[derive(Debug, Clone, Copy)]
struct Verifier {
    /// +4.
    blocks_checked: u32,
    /// +0xc, in sectors.
    position: u32,
    /// +0x10084: hash index block last read and checked.
    index: Option<u32>,
    /// +0x10080.
    failed_reads: u32,
    /// +0x48.
    failed_hashes: u32,
    /// Flag 2: passes ignore their budget.
    unbounded: bool,
}

/// A pass the worker runs (0x81a17f28).
#[derive(Debug, Clone, Copy)]
struct Pass {
    /// Milliseconds after which the pass ends; `None` runs until a close.
    budget: Option<u64>,
    /// Interval between throttle waits of an unlimited pass.
    throttle_interval: u64,
    /// Start of the pass, moved to each throttle wait of an unlimited pass.
    mark: u64,
    /// Time at which the worker finishes its current block or wait.
    cursor: u64,
}

/// The service's state.
#[derive(Debug, Default)]
pub struct MediaVerification {
    pub state: SessionState,
    /// Object flag 0x10: the last startup failed an injected check.
    /// Cleared by a close.
    pub check_failed: bool,
    /// Object flags 0x1 and 0x2: detection bit 12 was set at a startup.
    /// Never cleared.
    pub hash_failure_detected: bool,
    /// Read failures still to inject (0x81d8e31c).
    pub pending_read_errors: u32,
    /// Hash failures still to inject (0x81d8e320).
    pub pending_hash_errors: u32,
    /// Progress record (object +0x1c).
    pub record: CivProgress,
    /// Failed reads a close keeps for the next verifier (object +0x38).
    kept_failed_reads: u32,
    /// Failed hashes a close keeps for the next verifier (object +0x3c).
    kept_failed_hashes: u32,
    verifier: Option<Verifier>,
    pass: Option<Pass>,
}

impl MediaVerification {
    /// `XamMediaVerificationCreate` (0x81a16110): start the worker and wait
    /// for its startup.
    pub(super) fn create(&mut self, now: u64, detected: u64) -> Result<(), Win32Error> {
        self.run_until(now);
        if self.state != SessionState::Idle {
            return Err(SESSION_OPEN);
        }

        if !self.hash_failure_detected && detected & HASH_FAILURE_DETECTED != 0 {
            self.hash_failure_detected = true;
        }

        // The startup (0x81a17698) consumes one pending error of each kind;
        // either fails it.
        let mut failed = false;
        for pending in [&mut self.pending_hash_errors, &mut self.pending_read_errors] {
            if *pending > 0 {
                *pending -= 1;
                failed = true;
            }
        }
        if failed {
            self.check_failed = true;
            self.state = SessionState::Failed;
            return Err(STARTUP_FAILED);
        }

        self.verifier = Some(Verifier {
            blocks_checked: 0,
            position: 0,
            index: None,
            failed_reads: self.kept_failed_reads,
            failed_hashes: self.kept_failed_hashes,
            unbounded: self.hash_failure_detected,
        });
        self.record.blocks_checked = 0;
        self.record.total_blocks = 0;
        self.record.completed = false;
        self.state = SessionState::Ready;

        Ok(())
    }

    /// `XamMediaVerificationClose` (0x81a15998): stop the worker and reset
    /// the object. A running pass ends after its current block. The
    /// failure counters and total of the record stay.
    pub(super) fn close(&mut self, now: u64) {
        self.run_until(now);
        if self.state == SessionState::Idle {
            return;
        }

        if self.pass.take().is_some() {
            self.check_block();
        }
        if let Some(verifier) = self.verifier.take() {
            self.kept_failed_reads = verifier.failed_reads;
            self.kept_failed_hashes = verifier.failed_hashes;
        }
        self.record.blocks_checked = 0;
        self.record.completed = false;
        self.check_failed = false;
        self.state = SessionState::Idle;
    }

    /// `XamMediaVerificationVerify` (0x81a15fd0): hand a pass with a budget
    /// of `milliseconds` to the worker and return at once.
    pub(super) fn verify(&mut self, now: u64, milliseconds: u32) -> Result<(), Win32Error> {
        self.run_until(now);
        let Some(verifier) = self.verifier.filter(|_| self.state == SessionState::Ready) else {
            return Err(SESSION_NOT_READY);
        };

        let (budget, throttle_interval) = if verifier.unbounded {
            (None, DETECTED_THROTTLE_INTERVAL_MS)
        } else if milliseconds == UNLIMITED {
            (None, 0)
        } else {
            (Some(u64::from(milliseconds)), 0)
        };
        self.pass = Some(Pass {
            budget,
            throttle_interval,
            mark: now,
            cursor: now,
        });
        self.state = SessionState::Busy;

        Ok(())
    }

    /// `XamMediaVerificationFailedBlocks` (0x81a15a48).
    pub(super) fn failed_blocks(&mut self, now: u64) -> Result<CivProgress, Win32Error> {
        self.run_until(now);
        if self.check_failed {
            return Err(CHECK_FAILED);
        }

        Ok(self.record)
    }

    /// `XamMediaVerificationInject` (0x8175ff68): two zero counts open a
    /// session on processor 5; a nonzero count is stored only when none of
    /// its kind is pending.
    pub(super) fn inject(&mut self, now: u64, detected: u64, hash_errors: u32, read_errors: u32) {
        if hash_errors == 0 && read_errors == 0 {
            // The continuous session that follows a successful open finds
            // the service busy (0x81a16200 returns `ERROR_NOT_READY`).
            // The result does not reach the caller.
            let _ = self.create(now, detected);
            return;
        }

        self.run_until(now);
        for (pending, count) in [
            (&mut self.pending_hash_errors, hash_errors),
            (&mut self.pending_read_errors, read_errors),
        ] {
            if count != 0 && *pending == 0 {
                *pending = count;
            }
        }
    }

    /// Run the worker's pass through every block that ends by `now`.
    fn run_until(&mut self, now: u64) {
        while let Some(mut pass) = self.pass {
            let end = pass.cursor + self.block_duration();
            if end > now {
                return;
            }

            self.check_block();
            if let Some(verifier) = &mut self.verifier {
                verifier.position += BLOCK_SECTORS;
            }
            pass.cursor = end;

            match pass.budget {
                // The budget is checked after each block (0x81a18194).
                Some(budget) => {
                    if end - pass.mark >= budget {
                        self.pass = None;
                        self.state = SessionState::Ready;
                        return;
                    }
                }
                None => {
                    // 0x81a18140 waits only when more time than the
                    // interval has passed.
                    if end - pass.mark > pass.throttle_interval {
                        pass.mark = end;
                        pass.cursor += THROTTLE_WAIT_MS;
                    }
                }
            }
            self.pass = Some(pass);
        }
    }

    /// Time the next block takes: one read, and one more for the hash index
    /// block unless it is the one last checked.
    fn block_duration(&self) -> u64 {
        let Some(verifier) = &self.verifier else {
            return READ_MS;
        };

        let index = verifier.position >> INDEX_SHIFT;
        if verifier.index == Some(index) {
            READ_MS
        } else if self.pending_read_errors > 0 || self.pending_hash_errors > 0 {
            // A failed index read or index hash check ends the block.
            READ_MS
        } else {
            2 * READ_MS
        }
    }

    /// 0x81a17c08 in the no-media mode: zero-filled reads whose hashes are
    /// not compared, so only injected errors fail a block.
    fn check_block(&mut self) {
        let Some(verifier) = &mut self.verifier else {
            return;
        };

        let index = verifier.position >> INDEX_SHIFT;
        let mut read = |failed: &mut u32| consume(&mut self.pending_read_errors, failed);
        let mut hash = |failed: &mut u32| consume(&mut self.pending_hash_errors, failed);
        'block: {
            if verifier.index != Some(index) {
                if !read(&mut verifier.failed_reads) || !hash(&mut verifier.failed_hashes) {
                    break 'block;
                }
                verifier.index = Some(index);
            }
            if read(&mut verifier.failed_reads) {
                hash(&mut verifier.failed_hashes);
            }
        }

        verifier.blocks_checked += 1;
        self.record = CivProgress {
            failed_reads: verifier.failed_reads,
            failed_hashes: verifier.failed_hashes,
            blocks_checked: verifier.blocks_checked,
            total_blocks: NO_MEDIA_TOTAL_BLOCKS,
            completed: false,
        };
    }
}

/// One read or hash check: a pending injected error fails it and counts.
fn consume(pending: &mut u32, failures: &mut u32) -> bool {
    if *pending == 0 {
        return true;
    }

    *pending -= 1;
    *failures += 1;

    false
}
