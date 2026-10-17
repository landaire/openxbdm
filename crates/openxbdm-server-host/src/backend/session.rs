//! Simulated session services.

mod rpc;
mod tell_log;

use std::collections::HashMap;
use std::fmt;

use openxbdm_core::status::KernelError;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::session;
use openxbdm_server::commands::session::DEBUG_CAPTURE_SIZE;
use openxbdm_server::commands::session::FastPipeBackend;
use openxbdm_server::commands::session::FileEventId;
use openxbdm_server::commands::session::ProcessorNumber;
use openxbdm_server::commands::session::TellLogWriter;
use openxbdm_server::notify::Event;
use openxbdm_server::notify::POSTED_TEXT_CAPACITY;
use openxbdm_server::notify::PostedTexts;

use super::MockBackend;

pub use self::rpc::MockCall;
pub use self::rpc::RpcArguments;
pub use self::rpc::RpcDrains;
pub use self::rpc::RpcFunction;
pub use self::rpc::RpcRegisters;
pub use self::rpc::RpcRunner;
pub use self::tell_log::MockTellLog;

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

impl fmt::Debug for Mock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Mock")
            .field("processor", &self.processor)
            .field("rpc_calls", &self.rpc_calls)
            .field("file_cache_elements", &self.file_cache_elements)
            .finish_non_exhaustive()
    }
}

impl MockBackend {
    /// Post a notification text as a thread other than the server's does
    /// (monitor export 36). `false` when the queue is full.
    pub fn post_notification(&mut self, text: &[u8]) -> bool {
        self.session.posted.push(text)
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

    fn flush_file(&mut self, _handle: FileHandle) -> Result<(), KernelError> {
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
    fn notify_sessions(&mut self, _event: &Event<'_>) {}
}

impl FastPipeBackend for MockBackend {
    fn file_cache_elements(&mut self) -> u32 {
        self.session.file_cache_elements
    }

    fn set_file_cache_elements(&mut self, count: u32) {
        self.session.file_cache_elements = count;
    }
}
