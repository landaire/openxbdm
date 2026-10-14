//! Simulated session services.

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::filesystem;
use openxbdm_server::commands::filesystem::FileData;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::session;
use openxbdm_server::commands::session::DEBUG_CAPTURE_SIZE;
use openxbdm_server::commands::session::FastPipeBackend;
use openxbdm_server::commands::session::FileEventId;
use openxbdm_server::commands::session::ProcessorNumber;
use openxbdm_server::commands::session::RpcBackend;
use openxbdm_server::commands::session::RpcCall;
use openxbdm_server::commands::session::RpcContext;
use openxbdm_server::commands::session::RpcCreateError;
use openxbdm_server::commands::session::RpcThread;
use openxbdm_server::commands::session::TellLogBackend;
use openxbdm_server::commands::session::TellLogConfig;
use openxbdm_server::commands::session::TellLogCounters;
use openxbdm_server::commands::session::TellLogWriter;
use openxbdm_server::notify::POSTED_TEXT_CAPACITY;
use openxbdm_server::notify::PostedTexts;

use super::MockBackend;
use super::POOL_LIMIT;

/// Console address of the first call buffer; each call block gets its own
/// 1 MB window.
const RPC_BUFFER_BASE: u32 = 0x4a00_0068;
const RPC_BLOCK_STRIDE: u32 = 0x10_0000;
const MODULE_NOT_FOUND: u64 = 0xffff_ffff_8007_007e;
const PROCEDURE_NOT_FOUND: u64 = 0xffff_ffff_8007_007f;
/// The monitor waits this long for a call before sending a marker.
const RPC_WAIT: Duration = Duration::from_millis(100);
/// Bytes of the log engine object beyond its entries.
const ENGINE_HEADER: u32 = 0x160;

/// Drain requests of title threads (monitor control code 0xa8). Tests
/// send thread names without holding the host lock, as a title thread
/// runs beside the monitor; the simulation runs them before it checks a
/// call.
#[derive(Debug)]
pub struct RpcDrains {
    sender: mpsc::Sender<Vec<u8>>,
    receiver: mpsc::Receiver<Vec<u8>>,
}

impl Default for RpcDrains {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self { sender, receiver }
    }
}

impl RpcDrains {
    /// A sender for drain requests by thread name.
    pub fn sender(&self) -> mpsc::Sender<Vec<u8>> {
        self.sender.clone()
    }
}

/// The `dmtelllog` log engine.
#[derive(Debug)]
pub struct MockTellLog {
    pub file: FileHandle,
    pub area: u32,
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

    fn range(&self, index: u32) -> std::ops::Range<usize> {
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
    fn front(&self) -> Option<std::ops::Range<usize>> {
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

/// Arguments of a simulated call, as loaded into r3..r10 and f1..f8.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcArguments {
    pub integers: Vec<u64>,
    pub doubles: Vec<f64>,
}

/// Return registers of a simulated call.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RpcRegisters {
    pub r3: u64,
    pub f1: f64,
}

/// A console function callable through `rpc`.
pub type RpcFunction = Box<dyn FnMut(&RpcArguments) -> RpcRegisters + Send>;

/// Where a simulated call runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcRunner {
    OwnThread { context: RpcContext, processor: u32 },
    Named(Vec<u8>),
}

/// A call block.
#[derive(Debug)]
pub struct MockCall {
    pub runner: RpcRunner,
    pub buffer: Vec<u8>,
    pub started: bool,
    pub done: bool,
}

/// Simulated state of this domain.
#[derive(Default)]
pub struct Mock {
    pub debug_capture: Option<Box<[u8; DEBUG_CAPTURE_SIZE]>>,
    /// Makes the next debug capture allocation fail.
    pub exhausted: bool,
    /// Processor the server thread runs on.
    pub processor: u8,
    /// Functions by console address.
    pub rpc_functions: HashMap<u32, RpcFunction>,
    /// Export addresses by module name and ordinal.
    pub rpc_exports: HashMap<(Vec<u8>, u32), u32>,
    /// Last error of the calling thread.
    pub rpc_last_error: u32,
    /// Makes call block allocation fail.
    pub rpc_exhausted: bool,
    /// Live call blocks.
    pub rpc_calls: HashMap<u32, MockCall>,
    /// Calls queued for named threads, newest last.
    rpc_queue: Vec<u32>,
    next_call: u32,
    /// Drain requests of title threads.
    pub rpc_drains: RpcDrains,
    /// The open `dmtelllog` log.
    pub tell_log: Option<MockTellLog>,
    /// The log worker does not run; records stay queued.
    pub tell_log_worker_paused: bool,
    /// Collection buffer of the log writer; it outlives a log, as the
    /// monitor's static buffer does.
    tell_log_writer: Box<TellLogWriter>,
    /// File I/O event notifications are enabled.
    pub file_events: bool,
    /// Last file event identifier.
    pub file_event_id: FileEventId,
    /// Notification texts posted by other threads.
    pub posted: PostedTexts,
    /// Element count of file system cache 2.
    pub file_cache_elements: u32,
}

impl std::fmt::Debug for Mock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Mock")
            .field("processor", &self.processor)
            .field("rpc_calls", &self.rpc_calls)
            .field("file_cache_elements", &self.file_cache_elements)
            .finish_non_exhaustive()
    }
}

fn read_qword(buffer: &[u8], offset: usize) -> u64 {
    buffer.get(offset..offset + 8).map_or(0, |bytes| {
        u64::from_be_bytes(bytes.try_into().unwrap_or([0; 8]))
    })
}

fn write_qword(buffer: &mut [u8], offset: usize, value: u64) {
    if let Some(bytes) = buffer.get_mut(offset..offset + 8) {
        bytes.copy_from_slice(&value.to_be_bytes());
    }
}

impl Mock {
    fn buffer_address(id: u32) -> u32 {
        RPC_BUFFER_BASE + id * RPC_BLOCK_STRIDE
    }

    /// Run a call as its thread would. A call whose function address is not
    /// registered never finishes.
    fn execute(&mut self, id: u32) {
        let Some(call) = self.rpc_calls.get(&id) else {
            return;
        };
        let buffer = &call.buffer;
        let mut target = read_qword(buffer, 0x38) as u32;
        let module = read_qword(buffer, 0x30);
        if module != 0 {
            let start = (module as u32).wrapping_sub(Self::buffer_address(id)) as usize;
            let name = name_of(buffer, start);
            let failure = match self.rpc_exports.get(&(name.clone(), target)) {
                Some(&address) => {
                    target = address;
                    None
                }
                None if self.rpc_exports.keys().any(|(module, _)| *module == name) => {
                    Some(PROCEDURE_NOT_FOUND)
                }
                None => Some(MODULE_NOT_FOUND),
            };
            if let Some(failure) = failure {
                let call = self.rpc_calls.get_mut(&id).expect("call exists");
                write_qword(&mut call.buffer, 0, failure);
                call.done = true;
                return;
            }
        }
        let Some(function) = self.rpc_functions.get_mut(&target) else {
            return;
        };
        let flags = read_qword(buffer, 0x18);
        // Counts come from the client; arguments past the buffer are not simulated.
        let slots = buffer.len().saturating_sub(0x40) / 8;
        let integer_count = (read_qword(buffer, 0x20) as u32 as usize).min(slots);
        let double_count = (read_qword(buffer, 0x28) as u32 as usize).min(slots - integer_count);
        let integers = (0..integer_count)
            .map(|index| read_qword(buffer, 0x40 + 8 * index))
            .collect();
        let doubles = (0..double_count)
            .map(|index| f64::from_bits(read_qword(buffer, 0x40 + 8 * (integer_count + index))))
            .collect();
        let registers = function(&RpcArguments { integers, doubles });
        let last_error = self.rpc_last_error;
        let call = self.rpc_calls.get_mut(&id).expect("call exists");
        let value = if flags & 1 != 0 {
            registers.f1.to_bits()
        } else {
            registers.r3
        };
        write_qword(&mut call.buffer, 8, value);
        if read_qword(&call.buffer, 0x10) == 1 {
            write_qword(&mut call.buffer, 0x10, u64::from(last_error));
        }
        call.done = true;
        write_qword(&mut call.buffer, 0, 0);
    }
}

fn name_of(buffer: &[u8], start: usize) -> Vec<u8> {
    buffer.get(start..).map_or_else(Vec::new, |tail| {
        tail.split(|&byte| byte == 0)
            .next()
            .unwrap_or(tail)
            .to_vec()
    })
}

impl MockBackend {
    /// Post a notification text as a thread other than the server's does
    /// (monitor export 36). `false` when the queue is full.
    pub fn post_notification(&mut self, text: &[u8]) -> bool {
        self.session.posted.push(text)
    }

    /// Run the queued calls of the title thread named `name`, newest
    /// first, as the thread does when it drains the queue.
    pub fn drain_rpc(&mut self, name: &[u8]) {
        while let Some(position) = self.session.rpc_queue.iter().rposition(|id| {
            self.session
                .rpc_calls
                .get(id)
                .is_some_and(|call| call.runner == RpcRunner::Named(name.to_vec()))
        }) {
            let id = self.session.rpc_queue.remove(position);
            self.session.execute(id);
        }
    }

    fn run_rpc_drains(&mut self) {
        while let Ok(name) = self.session.rpc_drains.receiver.try_recv() {
            self.drain_rpc(&name);
        }
    }

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
        let mut writer = std::mem::take(&mut self.session.tell_log_writer);
        let mut processed = 0;
        while !log.stopped && limit.is_none_or(|limit| processed < limit) {
            let Some(range) = log.ring.front() else { break };
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

impl session::Backend for MockBackend {
    fn allocate_debug_capture(&mut self) -> bool {
        if self.session.exhausted {
            return false;
        }
        self.session.debug_capture = Some(Box::new([0; DEBUG_CAPTURE_SIZE]));
        true
    }

    fn free_debug_capture(&mut self) {
        self.session.debug_capture = None;
    }

    fn debug_capture(&mut self) -> Option<&mut [u8; DEBUG_CAPTURE_SIZE]> {
        self.session.debug_capture.as_deref_mut()
    }

    fn current_processor(&mut self) -> ProcessorNumber {
        ProcessorNumber(self.session.processor)
    }

    fn set_server_processor(&mut self, processor: ProcessorNumber) {
        self.session.processor = processor.0;
    }

    fn flush_file(&mut self, _handle: FileHandle) -> Result<(), NtStatus> {
        Ok(())
    }

    fn switch_file_events(&mut self, enable: bool) -> FileEventId {
        self.session.file_events = enable;
        self.session.file_event_id = self.session.file_event_id.next();
        self.session.file_event_id
    }

    fn next_posted_notification(&mut self, text: &mut [u8; POSTED_TEXT_CAPACITY]) -> Option<usize> {
        self.session.posted.pop(text)
    }

    /// The simulated console runs no in-process software, so no session
    /// has handlers.
    fn notify_sessions(&mut self, _event: &openxbdm_server::notify::Event<'_>) {}
}

impl TellLogBackend for MockBackend {
    fn tell_log_area(&mut self) -> Option<u32> {
        self.session.tell_log.as_ref().map(|log| log.area)
    }

    fn set_tell_log_area(&mut self, area: u32) {
        if let Some(log) = self.session.tell_log.as_mut() {
            log.area = area;
        }
    }

    fn tell_log_start(
        &mut self,
        file: FileHandle,
        area: u32,
        config: TellLogConfig,
    ) -> Result<Hresult, Hresult> {
        let size = config
            .entry_size
            .checked_mul(config.entries)
            .and_then(|size| size.checked_add(ENGINE_HEADER));
        let Some(size) = size.filter(|&size| size <= POOL_LIMIT) else {
            return Err(Hresult::OUT_OF_MEMORY);
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
        Ok(Hresult(0))
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

impl RpcBackend for MockBackend {
    fn rpc_create(
        &mut self,
        size: u32,
        context: RpcContext,
        thread: RpcThread<'_>,
    ) -> Result<RpcCall, RpcCreateError> {
        if self.session.rpc_exhausted || size > POOL_LIMIT {
            return Err(RpcCreateError::OutOfMemory);
        }
        let id = self.session.next_call;
        self.session.next_call += 1;
        let runner = match thread {
            RpcThread::Own { processor } => RpcRunner::OwnThread { context, processor },
            RpcThread::Named(name) => RpcRunner::Named(name.to_vec()),
        };
        self.session.rpc_calls.insert(
            id,
            MockCall {
                runner,
                buffer: vec![0; size as usize],
                started: false,
                done: false,
            },
        );
        Ok(RpcCall(id))
    }

    fn rpc_buffer_address(&mut self, call: RpcCall) -> u32 {
        Mock::buffer_address(call.0)
    }

    fn rpc_write(&mut self, call: RpcCall, offset: u32, data: &[u8]) {
        if let Some(call) = self.session.rpc_calls.get_mut(&call.0) {
            let start = offset as usize;
            call.buffer[start..start + data.len()].copy_from_slice(data);
        }
    }

    fn rpc_start(&mut self, call: RpcCall) {
        self.run_rpc_drains();
        let Some(entry) = self.session.rpc_calls.get_mut(&call.0) else {
            return;
        };
        entry.started = true;
        match entry.runner {
            RpcRunner::OwnThread { .. } => self.session.execute(call.0),
            RpcRunner::Named(_) => self.session.rpc_queue.push(call.0),
        }
    }

    fn rpc_abort(&mut self, call: RpcCall) {
        self.session.rpc_queue.retain(|&id| id != call.0);
        self.session.rpc_calls.remove(&call.0);
    }

    fn rpc_wait(&mut self, call: RpcCall) -> bool {
        self.run_rpc_drains();
        let done = self
            .session
            .rpc_calls
            .get(&call.0)
            .is_some_and(|call| call.done);
        if !done {
            std::thread::sleep(RPC_WAIT);
        }
        done
    }

    fn rpc_read(&mut self, call: RpcCall, offset: u32, output: &mut [u8]) {
        if let Some(call) = self.session.rpc_calls.get(&call.0) {
            let start = offset as usize;
            output.copy_from_slice(&call.buffer[start..start + output.len()]);
        }
    }

    fn rpc_release(&mut self, call: RpcCall) {
        self.session.rpc_queue.retain(|&id| id != call.0);
        self.session.rpc_calls.remove(&call.0);
    }
}

impl FastPipeBackend for MockBackend {
    fn file_cache_elements(&mut self) -> u32 {
        self.session.file_cache_elements
    }

    fn set_file_cache_elements(&mut self, count: u32) {
        self.session.file_cache_elements = count;
    }
}
