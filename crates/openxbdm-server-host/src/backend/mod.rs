//! Deterministic console simulation for the host server.

pub mod console;
pub mod debugger;
pub mod filesystem;
pub mod hardware;
pub mod memory;
pub mod network;
pub mod performance;
pub mod security;
pub mod services;
pub mod session;
pub mod system;

use std::time::Instant;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::ConnectionIndex;
use openxbdm_server::Platform;
use openxbdm_server::notify::ExecutionState;
use openxbdm_server::processors::ExternalContinuation;
use openxbdm_server::processors::ExternalTransfer;
use openxbdm_server::processors::Processor;
use openxbdm_server::processors::ProcessorBackend;
use openxbdm_server::processors::ProcessorCall;
use openxbdm_server::processors::ProcessorFlags;
use openxbdm_server::processors::ProcessorHandle;
use openxbdm_server::processors::ProcessorProgress;
use openxbdm_server::processors::ProcessorThread;
use openxbdm_server::processors::Processors;
use openxbdm_server::processors::RegisterError;
use openxbdm_server::server::TRANSFER_CAPACITY;
use openxbdm_server::text::ResponseText;

/// FILETIME of 2024-01-01T00:00:00Z, the simulated boot time.
const BOOT_FILETIME: u64 = 133_485_408_000_000_000;
/// Time base ticks per microsecond.
const TIMEBASE_PER_MICROSECOND: u64 = 50;
/// Pool allocations larger than this stand in for exhausted pool memory.
pub(crate) const POOL_LIMIT: u32 = 0x100_0000;

/// A command processor registered by host code: receives the full line
/// and the reply text.
pub type ExternalProcessor = Box<dyn FnMut(&[u8], &mut ResponseText) -> Hresult + Send>;

/// Simulated console.
pub struct MockBackend {
    boot: Instant,
    random_state: u64,
    /// Lines written to the debug output.
    pub debug_output: Vec<Vec<u8>>,
    /// Handlers of processors registered with
    /// [`MockBackend::register_processor`], by handle.
    pub processor_handlers: Vec<ExternalProcessor>,
    pub processors: Processors,
    /// Calls of processors that run on another thread report
    /// [`ProcessorProgress::Running`] and keep their line here until the
    /// test completes them with `Server::complete_processor_call`.
    pub defer_processor_calls: bool,
    deferred_calls: Vec<(ConnectionIndex, Vec<u8>)>,
    pub test_kit: bool,
    pub execution_state: ExecutionState,
    pub session: session::Mock,
    pub security: security::Mock,
    pub console: console::Mock,
    pub system: system::Mock,
    pub filesystem: filesystem::Mock,
    pub memory: memory::Mock,
    pub debugger: debugger::Mock,
    pub network: network::Mock,
    pub performance: performance::Mock,
    pub hardware: hardware::Mock,
    pub services: services::Mock,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            boot: Instant::now(),
            random_state: 0x2545_f491_4f6c_dd1d,
            debug_output: Vec::new(),
            processor_handlers: Vec::new(),
            processors: Processors::new(),
            defer_processor_calls: false,
            deferred_calls: Vec::new(),
            test_kit: false,
            execution_state: ExecutionState::Started,
            session: Default::default(),
            security: Default::default(),
            console: Default::default(),
            system: Default::default(),
            filesystem: Default::default(),
            memory: Default::default(),
            debugger: Default::default(),
            network: Default::default(),
            performance: Default::default(),
            hardware: Default::default(),
            services: Default::default(),
        }
    }
}

impl MockBackend {
    /// Register `handler` under `name` as another module would, or
    /// unregister `name` when `handler` is `None`.
    pub fn register_processor(
        &mut self,
        name: &[u8],
        handler: Option<ExternalProcessor>,
        flags: ProcessorFlags,
    ) -> Result<(), RegisterError> {
        let handle = handler.map(|handler| {
            self.processor_handlers.push(handler);
            ProcessorHandle(self.processor_handlers.len() as u32 - 1)
        });
        self.processors.register(name, handle, flags)
    }

    fn elapsed_microseconds(&self) -> u64 {
        self.boot.elapsed().as_micros() as u64
    }

    /// Simulated clock before any `setsystime`.
    fn unadjusted_system_time(&self) -> u64 {
        BOOT_FILETIME + self.elapsed_microseconds() * 10
    }
}

impl Platform for MockBackend {
    fn system_time(&mut self) -> u64 {
        self.unadjusted_system_time()
            .wrapping_add(self.system.clock_adjustment)
    }

    fn timebase(&mut self) -> u64 {
        self.elapsed_microseconds() * TIMEBASE_PER_MICROSECOND
    }

    fn is_test_kit(&self) -> bool {
        self.test_kit || self.console.marked_test_kit
    }

    fn execution_state(&mut self) -> ExecutionState {
        self.execution_state
    }

    /// xorshift64; deterministic across runs.
    fn random_bytes(&mut self, output: &mut [u8]) {
        for byte in output {
            self.random_state ^= self.random_state << 13;
            self.random_state ^= self.random_state >> 7;
            self.random_state ^= self.random_state << 17;
            *byte = self.random_state as u8;
        }
    }

    fn debug_print(&mut self, text: &[u8]) {
        self.debug_output.push(text.to_vec());
    }
}

impl ProcessorBackend for MockBackend {
    fn find_processor(&mut self, name: &[u8]) -> Option<(u8, Processor)> {
        self.processors.find(name)
    }

    fn processor(&mut self, index: u8) -> Option<Processor> {
        self.processors.get(index)
    }

    fn remove_title_processors(&mut self) {
        self.processors.remove_title_processors();
    }

    fn call_processor(
        &mut self,
        call: ProcessorCall,
        line: &[u8],
        text: &mut ResponseText,
        _continuation: &mut Option<ExternalContinuation>,
        _receive_remaining: &mut Option<u32>,
    ) -> ProcessorProgress {
        let line = match self
            .deferred_calls
            .iter()
            .position(|(connection, _)| *connection == call.connection)
        {
            Some(position) => self.deferred_calls.remove(position).1,
            None if self.defer_processor_calls && call.thread != ProcessorThread::Server => {
                self.deferred_calls.push((call.connection, line.to_vec()));
                return ProcessorProgress::Running;
            }
            None => line.to_vec(),
        };
        ProcessorProgress::Complete(
            match self.processor_handlers.get_mut(call.handle.0 as usize) {
                Some(processor) => processor(&line, text),
                None => Hresult::FAIL,
            },
        )
    }

    /// Host processors reply with single lines and start no transfers.
    fn resume_processor(
        &mut self,
        _continuation: &mut ExternalContinuation,
        _transfer: ExternalTransfer<'_>,
    ) -> ProcessorProgress {
        ProcessorProgress::Complete(Hresult::END_OF_DATA)
    }

    fn processor_receive_limit(&mut self, _continuation: &ExternalContinuation) -> usize {
        TRANSFER_CAPACITY
    }
}
