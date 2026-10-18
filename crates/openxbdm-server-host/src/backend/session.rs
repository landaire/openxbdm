//! Simulated session services.

mod rpc;
mod tell_log;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::backend::Platform as _;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::session;
use openxbdm_server::commands::session::DEBUG_CAPTURE_SIZE;
use openxbdm_server::commands::session::DebugCaptureRing;
use openxbdm_server::commands::session::EventPath;
use openxbdm_server::commands::session::FastPipeBackend;
use openxbdm_server::commands::session::FileEventBegin;
use openxbdm_server::commands::session::FileEventFlags;
use openxbdm_server::commands::session::FileEventId;
use openxbdm_server::commands::session::FileEventTitles;
use openxbdm_server::commands::session::FileOperationClass;
use openxbdm_server::commands::session::ProcessorNumber;
use openxbdm_server::commands::session::ReservationEvent;
use openxbdm_server::commands::session::TellLogWriter;
use openxbdm_server::commands::session::file_event_kind;
use openxbdm_server::commands::session::file_mode_flags;
use openxbdm_server::commands::session::format_file_event_begin;
use openxbdm_server::commands::session::format_file_event_end;
use openxbdm_server::notify::Event;
use openxbdm_server::notify::POSTED_TEXT_CAPACITY;
use openxbdm_server::notify::PostedTexts;
use xbox360_sys::xboxkrnl::CreateOptions;

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
    pub debug_capture: Option<Box<[AtomicU8; DEBUG_CAPTURE_SIZE]>>,
    /// Write offset of the debug capture ring.
    pub debug_capture_write: AtomicU32,
    /// Reservation failures the debug capture producer reported.
    pub debug_capture_events: Vec<ReservationEvent>,
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
    /// Titles whose file service events are reported.
    pub file_event_titles: FileEventTitles,
    /// Notification texts posted for the server thread.
    pub posted: PostedTexts,
    /// Posted texts that did not fit `posted`, newer than all of its texts.
    pub posted_kept: VecDeque<Vec<u8>>,
    /// Notification session handlers of in-process software, oldest first.
    pub session_handlers: Vec<SessionHandler>,
    /// Element count of file system cache 2.
    pub file_cache_elements: u32,
}

/// A notification session handler; it receives every event.
pub type SessionHandler = Box<dyn FnMut(&Event<'_>) + Send>;

/// A file service operation of the simulated kernel, which reports it with
/// monitor control code 0x64 before it runs and 0x65 after it ends.
#[derive(Debug, Clone, Copy)]
pub struct MockFileOperation<'a> {
    /// Title running at the time.
    pub title: u32,
    pub thread_id: u32,
    /// Operation number of the event record.
    pub operation: u32,
    pub handle: u32,
    /// Object name of an open.
    pub path: Option<&'a [u8]>,
    /// Requested byte offset of a transfer; 0 uses the file position.
    pub offset: u64,
    /// File position of the handle.
    pub position: u64,
    pub length: u32,
    /// Create options of an open; the file mode of a transfer.
    pub options: CreateOptions,
    /// I/O status of the operation.
    pub status: NtStatus,
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
    /// Post a notification text as the server thread or the log worker
    /// does (monitor export 36): a text that does not fit the queue, or
    /// arrives while earlier ones were kept, is kept until the next pass.
    pub fn post_notification(&mut self, text: &[u8]) {
        let session = &mut self.session;
        if !session.posted_kept.is_empty() || !session.posted.push(text) {
            session.posted_kept.push_back(text.to_vec());
        }
    }

    /// Run monitor control codes 0x64 and 0x65 (stock 0x91f2f5c8 and
    /// 0x91f2f930) around a file service operation.
    pub fn file_operation(&mut self, operation: &MockFileOperation<'_>) {
        if let Some(id) = self.file_event_begin(operation) {
            self.file_event_end(operation, id);
        }
    }

    /// Control code 0x64: the identifier assigned to the record, `None`
    /// when no event is reported. A wrapped identifier of 0 gets no end
    /// event.
    fn file_event_begin(&mut self, operation: &MockFileOperation<'_>) -> Option<FileEventId> {
        let session = &mut self.session;
        if !session.file_events || !session.file_event_titles.reports(operation.title) {
            return None;
        }

        session.file_event_id = session.file_event_id.next();
        let id = session.file_event_id;
        let class = FileOperationClass::of(operation.operation);
        let (offset, flags) = match class {
            FileOperationClass::Transfer { scatter_gather } => {
                let offset = match operation.offset {
                    0 => operation.position,
                    requested => requested,
                };
                let mut flags = file_mode_flags(operation.options);
                if scatter_gather {
                    flags |= FileEventFlags::SCATTER_GATHER;
                }

                (offset, flags)
            }
            FileOperationClass::Open => (0, file_mode_flags(operation.options)),
            FileOperationClass::Other => (0, FileEventFlags::empty()),
        };
        let path = match class {
            FileOperationClass::Open => operation.path.map(|text| EventPath {
                length: text.len() as u16,
                text,
            }),
            FileOperationClass::Transfer { .. } | FileOperationClass::Other => None,
        };

        let text = format_file_event_begin(&FileEventBegin {
            id,
            time_base: self.timebase(),
            kind: file_event_kind(operation.operation),
            thread_id: operation.thread_id,
            handle: operation.handle,
            offset,
            bytes: operation.length,
            flags,
            path,
        });
        self.post_notification(text.as_bytes());

        Some(id)
    }

    /// Control code 0x65 for a record that got identifier `id`.
    fn file_event_end(&mut self, operation: &MockFileOperation<'_>, id: FileEventId) {
        if id.0 == 0 || !self.session.file_events {
            return;
        }

        let time_base = self.timebase();
        if !self.session.file_event_titles.reports(operation.title) {
            return;
        }

        let text = format_file_event_end(id, time_base, operation.handle, operation.status);
        self.post_notification(text.as_bytes());
    }

    /// Append a message to the debug capture ring as the monitor's
    /// producers do; nothing while capture is off.
    pub fn debug_capture_print(&mut self, message: &[u8]) {
        let session = &mut self.session;
        if let Some(bytes) = session.debug_capture.as_deref() {
            let ring = DebugCaptureRing {
                bytes,
                write: &session.debug_capture_write,
            };
            ring.print(message, &mut |event| {
                session.debug_capture_events.push(event)
            });
        }
    }
}

impl session::Backend for MockBackend {
    fn allocate_debug_capture(&mut self) -> bool {
        if self.session.exhausted {
            return false;
        }

        let bytes = Box::new([const { AtomicU8::new(0) }; DEBUG_CAPTURE_SIZE]);
        self.session.debug_capture_write.store(0, Ordering::SeqCst);
        self.session.debug_capture = Some(bytes);

        true
    }

    fn free_debug_capture(&mut self) {
        self.session.debug_capture = None;
        self.session.debug_capture_write.store(0, Ordering::SeqCst);
    }

    fn debug_capture(&mut self) -> Option<DebugCaptureRing<'_>> {
        Some(DebugCaptureRing {
            bytes: self.session.debug_capture.as_deref()?,
            write: &self.session.debug_capture_write,
        })
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

    fn send_next_posted_notification(&mut self, send: &mut dyn FnMut(&[u8])) -> bool {
        let mut text = [0u8; POSTED_TEXT_CAPACITY];
        if let Some(length) = self.session.posted.pop(&mut text) {
            send(&text[..length]);
            return true;
        }

        match self.session.posted_kept.pop_front() {
            Some(kept) => {
                send(&kept);
                true
            }
            None => false,
        }
    }

    /// Handlers run newest first (stock 0x91f395c0).
    fn notify_sessions(&mut self, event: &Event<'_>) {
        for handler in self.session.session_handlers.iter_mut().rev() {
            handler(event);
        }
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
