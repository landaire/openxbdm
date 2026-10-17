//! Simulated detour engine: trampolines in simulated memory, a log writer
//! that writes each record as soon as it is queued, and a completion worker
//! that runs whenever a completion is queued or a test asks for a pass.
//! Title calls through a trampoline are simulated with
//! [`MockBackend::detour_call`].

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use openxbdm_core::status::KernelError;
use openxbdm_server::backend::Platform as _;
use openxbdm_server::commands::console::Backend as _;
use openxbdm_server::commands::filesystem::Backend as _;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::FileData;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::filesystem::PoolRange;
use openxbdm_server::commands::filesystem::ReadTarget;
use openxbdm_server::commands::memory::Backend as _;
use openxbdm_server::commands::memory::detour;
use openxbdm_server::commands::memory::detour::BLOCK_SIZE;
use openxbdm_server::commands::memory::detour::CallContext;
use openxbdm_server::commands::memory::detour::Engine;
use openxbdm_server::commands::memory::detour::RECORD_SIZE;
use openxbdm_server::commands::memory::detour::ReturnValue;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::Region;
use crate::backend::MockBackend;

/// Address of trampoline 0, as in the stock image.
pub const TRAMPOLINE_BASE: u32 = 0x91f1_3230;
/// Address of the entry stub the trampolines branch to.
pub const ENTRY_STUB: u32 = 0x91f1_3000;
/// Filler of the trampoline area (`and r0, r0, r0`).
const TRAMPOLINE_FILL: u32 = 0x7c00_0038;
/// `NtCreateFile` options of both log handles.
const LOG_OPTIONS: CreateOptions = CreateOptions::SYNCHRONOUS_IO_NONALERT;

/// The stub page and the trampoline area after module init: each
/// trampoline starts with `li r12, id` and `b ENTRY_STUB`. The stubs are
/// not simulated and read as zero, as does the rest of the last page.
pub fn trampoline_region() -> Region {
    let stubs = (TRAMPOLINE_BASE - ENTRY_STUB) as usize;
    let size = (detour::ENTRY_COUNT * detour::TRAMPOLINE_SIZE) as usize;
    let mut bytes = vec![0u8; stubs];
    bytes.extend(
        TRAMPOLINE_FILL
            .to_be_bytes()
            .iter()
            .copied()
            .cycle()
            .take(size),
    );
    for id in 0..detour::ENTRY_COUNT {
        let address = TRAMPOLINE_BASE + id * detour::TRAMPOLINE_SIZE;
        let branch = 0x4800_0000 | (ENTRY_STUB.wrapping_sub(address + 4) & 0x03ff_fffc);
        let offset = stubs + (id * detour::TRAMPOLINE_SIZE) as usize;
        bytes[offset..offset + 4].copy_from_slice(&(0x3980_0000 | id).to_be_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&branch.to_be_bytes());
    }
    bytes.resize(bytes.len().next_multiple_of(super::PAGE_SIZE), 0);
    Region {
        base: ENTRY_STUB,
        bytes,
    }
}

/// Simulated detour state.
#[derive(Default)]
pub struct Mock {
    pub engine: Arc<Engine>,
    write_handle: Option<FileHandle>,
    read_handle: Option<FileHandle>,
    /// Sleeps the logger requested, in milliseconds.
    pub sleeps: Vec<u32>,
    /// Event objects signaled by completed overlapped requests.
    pub signaled_events: Vec<u32>,
    /// Record pool storage, obtained at the first start and kept.
    records: Option<&'static [AtomicU32]>,
}

impl std::fmt::Debug for Mock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Mock")
            .field("state", &self.engine.state())
            .field("write_handle", &self.write_handle)
            .field("read_handle", &self.read_handle)
            .finish_non_exhaustive()
    }
}

/// A title call through a trampoline.
#[derive(Debug, Clone, Copy, Default)]
pub struct SimulatedCall {
    /// Address of the stub locals; register indexes past r10 read relative
    /// to it.
    pub context: u32,
    /// Entry stack pointer + 0x10.
    pub frame: u32,
    pub registers: [u64; 8],
    /// Saved f1-f13 (logged when the entry sets `FLOATING_POINT`).
    pub floating_point: u32,
    /// Vector save area (logged when the entry sets `VECTOR`).
    pub vector: u32,
    /// What the original function returns when it runs.
    pub original_result: ReturnValue,
}

/// What the stub returns to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallOutcome {
    /// The original function ran.
    pub called: bool,
    pub returned: ReturnValue,
}

/// Platform services over the simulated console.
struct HostPlatform<'a> {
    engine: &'a Engine,
    backend: RefCell<&'a mut MockBackend>,
}

impl HostPlatform<'_> {
    fn write_queued(&self) {
        self.engine
            .write_queued(self, &mut |record| self.write_record(record));
    }

    fn write_record(&self, record: &[u8; RECORD_SIZE]) -> bool {
        let mut backend = self.backend.borrow_mut();
        let Some(handle) = backend.memory.detour.write_handle else {
            return false;
        };
        backend
            .write_file(handle, None, FileData::Bytes(record))
            .is_ok()
    }

    fn read_byte(&self, address: u32) -> u8 {
        // An unmapped title address reads as zero; the console would fault.
        self.backend.borrow_mut().read_byte(address).unwrap_or(0)
    }
}

impl detour::Platform for HostPlatform<'_> {
    fn trampolines(&self) -> u32 {
        TRAMPOLINE_BASE
    }

    fn timebase(&self) -> u64 {
        self.backend.borrow_mut().timebase()
    }

    fn system_time(&self) -> u64 {
        self.backend.borrow_mut().system_time()
    }

    fn tick_count(&self) -> u32 {
        self.backend.borrow_mut().tick_milliseconds()
    }

    fn sleep(&self, milliseconds: u32) {
        self.backend
            .borrow_mut()
            .memory
            .detour
            .sleeps
            .push(milliseconds);
    }

    fn wait_for_record(&self) {
        self.write_queued();
    }

    fn record_queued(&self) {
        self.write_queued();
    }

    fn record_freed(&self) {}

    fn records(&self) -> Option<&'static [AtomicU32]> {
        self.backend.borrow().memory.detour.records
    }

    fn allocate_records(&self) -> bool {
        let mut backend = self.backend.borrow_mut();
        if backend.memory.detour.records.is_none() {
            if backend.filesystem.pool_exhausted {
                return false;
            }
            let storage = (0..detour::RECORD_STORAGE_WORDS)
                .map(|_| AtomicU32::new(0))
                .collect();
            backend.memory.detour.records = Some(Vec::leak(storage));
        }
        true
    }

    unsafe fn read_u32(&self, address: u32) -> u32 {
        u32::from_be_bytes(std::array::from_fn(|index| {
            self.read_byte(address.wrapping_add(index as u32))
        }))
    }

    unsafe fn read_u64(&self, address: u32) -> u64 {
        u64::from_be_bytes(std::array::from_fn(|index| {
            self.read_byte(address.wrapping_add(index as u32))
        }))
    }

    unsafe fn read_block(&self, address: u32, output: &mut [u8; BLOCK_SIZE]) {
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = self.read_byte(address.wrapping_add(index as u32));
        }
    }

    unsafe fn write_u32(&self, address: u32, value: u32) {
        let mut backend = self.backend.borrow_mut();
        for (index, byte) in value.to_be_bytes().into_iter().enumerate() {
            backend.write_byte(address.wrapping_add(index as u32), byte);
        }
    }

    /// The simulation has no object table: a handle stands for its object.
    fn reference_event(&self, handle: u32) -> Option<u32> {
        Some(handle)
    }

    unsafe fn signal_event(&self, event: u32) {
        self.backend
            .borrow_mut()
            .memory
            .detour
            .signaled_events
            .push(event);
    }

    fn lock_completions(&self) {}

    fn unlock_completions(&self) {}

    fn completion_queued(&self) {
        self.engine.service_completions(self);
    }

    fn completions_idle(&self) {}
}

impl MockBackend {
    fn with_detour<T>(&mut self, operation: impl FnOnce(&Engine, &HostPlatform<'_>) -> T) -> T {
        let engine = Arc::clone(&self.memory.detour.engine);
        let platform = HostPlatform {
            engine: &engine,
            backend: RefCell::new(self),
        };
        operation(&engine, &platform)
    }

    pub(super) fn detour_operation(
        &mut self,
        operation: &mut dyn FnMut(&Engine, &dyn detour::Platform),
    ) {
        self.with_detour(|engine, platform| operation(engine, platform));
    }

    /// The writer worker's start (0x91f2cb28): reset the pool, then create
    /// the log for writing and open it again for reading.
    pub(super) fn start_detour_writer(&mut self, log: Option<&[u8]>) -> Result<(), KernelError> {
        let engine = Arc::clone(&self.memory.detour.engine);
        if !self.with_detour(|engine, platform| engine.prepare_log(platform)) {
            engine.abort_start();
            return Ok(());
        }
        let opened = self.open_detour_log(log);
        engine.set_log_result(opened);
        if opened.is_ok() {
            engine.mark_running();
        } else {
            self.close_detour_log();
            engine.abort_start();
        }
        Ok(())
    }

    fn open_detour_log(&mut self, log: Option<&[u8]>) -> Result<(), KernelError> {
        let path = log.ok_or(KernelError::NoSuchFile)?;
        let write = CreateRequest {
            access: AccessMask::GENERIC_WRITE,
            allocation_size: None,
            attributes: FileAttributes::NORMAL,
            share: ShareAccess::all(),
            disposition: CreateDisposition::OverwriteIf,
            options: LOG_OPTIONS,
        };
        self.memory.detour.write_handle = Some(self.create_file(path, &write)?);
        let read = CreateRequest {
            access: AccessMask::GENERIC_READ.union(AccessMask::SYNCHRONIZE),
            disposition: CreateDisposition::Open,
            ..write
        };
        self.memory.detour.read_handle = Some(self.create_file(path, &read)?);
        Ok(())
    }

    fn close_detour_log(&mut self) {
        for handle in [
            self.memory.detour.write_handle.take(),
            self.memory.detour.read_handle.take(),
        ]
        .into_iter()
        .flatten()
        {
            self.close_file(handle);
        }
    }

    /// The rest of `stop` (0x91f2cd54): the writer drops queued records and
    /// closes the log, the log file is deleted, and pending completions are
    /// dropped.
    pub(super) fn stop_detour_writer(&mut self, log: Option<&[u8]>) {
        self.with_detour(|engine, platform| while engine.discard_queued(platform) {});
        self.close_detour_log();
        if let Some(path) = log {
            self.delete_detour_log(path);
        }
        self.with_detour(|engine, platform| engine.finish_stop(platform));
    }

    /// `NtDeleteFile`.
    fn delete_detour_log(&mut self, path: &[u8]) {
        let request = CreateRequest::open(
            AccessMask::DELETE.union(AccessMask::SYNCHRONIZE),
            ShareAccess::all(),
            CreateOptions::NON_DIRECTORY_FILE,
        );
        if let Ok(handle) = self.create_file(path, &request) {
            let _ = self.set_delete_disposition(handle, true);
            self.close_file(handle);
        }
    }

    /// One `log getentries` read (0x91f2bc90).
    pub(super) fn read_detour_log(&mut self, output: &mut [u8; RECORD_SIZE]) -> bool {
        let engine = Arc::clone(&self.memory.detour.engine);
        let Some(handle) = self
            .memory
            .detour
            .read_handle
            .filter(|_| engine.has_unread())
        else {
            return false;
        };
        let Some(buffer) = self.allocate_pool(RECORD_SIZE as u32) else {
            return false;
        };
        let read = self.read_file(
            handle,
            None,
            ReadTarget::Pool(PoolRange {
                buffer,
                offset: 0,
                length: RECORD_SIZE as u32,
            }),
        );
        output.copy_from_slice(&self.pool(buffer)[..RECORD_SIZE]);
        // SAFETY: the block is local to this read and not used after.
        unsafe { self.free_pool(buffer) };
        if read.is_err() {
            return false;
        }
        engine.note_read();
        true
    }

    /// Simulate a title call entering trampoline `hook`: the stub's
    /// notifications in order, with the original returning
    /// `call.original_result` when the logger lets it run.
    pub fn detour_call(&mut self, hook: detour::EntryId, call: SimulatedCall) -> CallOutcome {
        self.with_detour(|engine, platform| {
            let mut context = CallContext {
                address: call.context,
                hook: hook.0,
                registers: call.registers,
                ..CallContext::default()
            };
            // SAFETY: the host platform reads and writes simulated memory,
            // where every address is valid.
            unsafe { engine.enter(platform, &mut context, call.frame) };
            if context.flags.contains(detour::HookFlags::FLOATING_POINT) {
                // SAFETY: as above.
                unsafe { engine.floating_point(platform, &context, call.floating_point) };
            }
            if context.flags.contains(detour::HookFlags::VECTOR) {
                // SAFETY: as above.
                unsafe { engine.vector(platform, &context, call.vector) };
            }
            let called = context.function.is_some();
            if called {
                context.return_value = call.original_result;
            }
            // SAFETY: as above.
            unsafe { engine.exit(platform, &mut context) };
            CallOutcome {
                called,
                returned: context.return_value,
            }
        })
    }

    /// One pass of the completion worker, as after its poll interval.
    pub fn service_detour_completions(&mut self) -> bool {
        self.with_detour(|engine, platform| engine.service_completions(platform))
    }
}
