//! Simulated `dmtelllog` log engine.

use std::mem;
use std::ops::Range;

use openxbdm_server::commands::filesystem;
use openxbdm_server::commands::filesystem::FileData;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::session::LogEngineError;
use openxbdm_server::commands::session::TellLogAreas;
use openxbdm_server::commands::session::TellLogBackend;
use openxbdm_server::commands::session::TellLogConfig;
use openxbdm_server::commands::session::TellLogCounters;

use crate::backend::MockBackend;
use crate::backend::POOL_LIMIT;

/// The `dmtelllog` log engine.
#[derive(Debug)]
pub struct MockTellLog {
    pub file: FileHandle,
    pub area: TellLogAreas,

    ring: RecordRing,
    block: bool,
    storage: Vec<u8>,

    closing: bool,
    /// A failed write ended the worker.
    stopped: bool,

    pub counters: TellLogCounters,
}

/// Engine entries, taken and returned in order as through the engine's
/// free queue. An entry keeps the bytes of its previous record beyond a
/// shorter copy.
#[derive(Debug)]
struct RecordRing {
    entry_size: u32,
    entries: u32,
    /// Oldest queued entry.
    first: u32,
    /// Queued entries, including one being processed.
    used: u32,
}

impl RecordRing {
    fn new(config: TellLogConfig) -> Self {
        Self {
            entry_size: config.entry_size,
            entries: config.entries,
            first: 0,
            used: 0,
        }
    }

    fn range(&self, index: u32) -> Range<usize> {
        let start = (index * self.entry_size) as usize;

        start..start + self.entry_size as usize
    }

    /// Copy up to an entry of `record` into the next free entry. `false`
    /// when every entry is in use.
    fn push(&mut self, storage: &mut [u8], record: &[u8]) -> bool {
        if self.used == self.entries {
            return false;
        }

        let range = self.range((self.first + self.used) % self.entries);
        self.used += 1;

        let length = record.len().min(range.len());
        storage[range.start..range.start + length].copy_from_slice(&record[..length]);

        true
    }

    /// The oldest queued entry.
    fn front(&self) -> Option<Range<usize>> {
        (self.used != 0).then(|| self.range(self.first))
    }

    /// Release the oldest queued entry after it was processed.
    fn pop(&mut self) {
        if self.used != 0 {
            self.first = (self.first + 1) % self.entries;
            self.used -= 1;
        }
    }
}

impl MockBackend {
    /// A producer record (monitor control code 0x88): queued while a log
    /// is open and not closing.
    pub fn tell_log_record(&mut self, record: &[u8]) {
        let Some(log) = self.session.tell_log.as_ref() else {
            return;
        };

        if log.closing || record.is_empty() {
            return;
        }

        self.write_tell_log(record);

        if !self.session.tell_log_worker_paused {
            self.run_tell_log_worker(None);
        }
    }

    /// Engine write (export 363): a full log drops the record, or with
    /// `block` waits for the worker to free an entry.
    fn write_tell_log(&mut self, record: &[u8]) {
        let Some(log) = self.session.tell_log.as_mut() else {
            return;
        };

        if log.ring.push(&mut log.storage, record) {
            return;
        }

        if log.block {
            self.run_tell_log_worker(Some(1));
        }

        let Some(log) = self.session.tell_log.as_mut() else {
            return;
        };

        if !(log.block && log.ring.push(&mut log.storage, record)) {
            log.counters.dropped += 1;
        }
    }

    /// Process up to `limit` queued records, or all of them.
    pub fn run_tell_log_worker(&mut self, limit: Option<usize>) {
        let Some(mut log) = self.session.tell_log.take() else {
            return;
        };
        let mut writer = mem::take(&mut self.session.tell_log_writer);

        let mut processed = 0;

        while !log.stopped && limit.is_none_or(|limit| processed < limit) {
            let Some(range) = log.ring.front() else {
                break;
            };
            let file = log.file;
            let mut write = |bytes: &[u8]| {
                filesystem::Backend::write_file(self, file, None, FileData::Bytes(bytes))
            };
            if writer
                .process(&log.storage[range], log.closing, &mut write)
                .is_err()
            {
                log.stopped = true;
                break;
            }

            log.ring.pop();
            processed += 1;
        }

        self.session.tell_log_writer = writer;
        self.session.tell_log = Some(log);
    }
}

impl TellLogBackend for MockBackend {
    fn tell_log_area(&mut self) -> Option<TellLogAreas> {
        self.session.tell_log.as_ref().map(|log| log.area)
    }

    fn set_tell_log_area(&mut self, area: TellLogAreas) {
        if let Some(log) = self.session.tell_log.as_mut() {
            log.area = area;
        }
    }

    fn tell_log_start(
        &mut self,
        file: FileHandle,
        area: TellLogAreas,
        config: TellLogConfig,
    ) -> Result<(), LogEngineError> {
        /// Bytes of the log engine object beyond its entries.
        const ENGINE_HEADER: u32 = 0x160;

        let size = config
            .entry_size
            .checked_mul(config.entries)
            .and_then(|size| size.checked_add(ENGINE_HEADER));
        let Some(size) = size.filter(|&size| size <= POOL_LIMIT) else {
            return Err(LogEngineError::OutOfMemory);
        };

        self.session.tell_log = Some(MockTellLog {
            file,
            area,
            ring: RecordRing::new(config),
            block: config.block,
            storage: vec![0; (size - ENGINE_HEADER) as usize],
            closing: false,
            stopped: false,
            counters: TellLogCounters::default(),
        });

        Ok(())
    }

    fn tell_log_close(&mut self) -> Option<TellLogCounters> {
        self.session.tell_log.as_mut()?.closing = true;

        // The closing record makes the worker flush the writer.
        self.write_tell_log(&[0]);

        self.session.tell_log.as_ref().map(|log| log.counters)
    }

    fn tell_log_stop(&mut self) -> Option<FileHandle> {
        self.run_tell_log_worker(None);

        self.session.tell_log.take().map(|log| log.file)
    }
}
