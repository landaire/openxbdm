//! Fast-cap and call-cap capture engine (stock dmcap, 0x91f27bb8 to
//! 0x91f2a03c): per-processor record buffers, the record hooks that
//! instrumented modules import (exports 65, 66, 70, 71), and the control
//! entries of `capctrl` and titles (exports 73, 74, 84, 90, 146, 162).
//! The control sequences are in `openxbdm_server::commands::performance::
//! capture`; this module supplies the buffers, hooks, and file writer.
//!
//! Hooks run on any thread at any IRQL with interrupts disabled around
//! each record, on the block of the current processor, as stock does.

mod file;

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::Win32Error;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::Server;
use openxbdm_server::commands::filesystem::DriveTable;
use openxbdm_server::commands::filesystem::ObjectPath;
use openxbdm_server::commands::memory::PAGE_SIZE;
use openxbdm_server::commands::performance::capture;
use openxbdm_server::commands::performance::capture::BufferRequest;
use openxbdm_server::commands::performance::capture::CHUNK_RESERVE_WORDS;
use openxbdm_server::commands::performance::capture::CaptureError;
use openxbdm_server::commands::performance::capture::CaptureFlags;
use openxbdm_server::commands::performance::capture::ControlRecord;
use openxbdm_server::commands::performance::capture::CounterSetup;
use openxbdm_server::commands::performance::capture::CounterSource;
use openxbdm_server::commands::performance::capture::DrivePaths;
use openxbdm_server::commands::performance::capture::Instrumentation;
use openxbdm_server::commands::performance::capture::MAX_PROCESSORS;
use openxbdm_server::commands::performance::capture::Paths;
use openxbdm_server::commands::performance::capture::RecordKind;
use openxbdm_server::commands::performance::capture::Started;
use openxbdm_server::reply;
use openxbdm_server::reply::CommandError;
use openxbdm_server::reply::Reply;
use xbox360::thread::ThreadObject;
use xbox360::time::FileTime;
use xbox360::time::TickCount;
use xbox360::time::Timebase;
use xbox360::time::sleep;
use xbox360_sys::export_raw;
use xbox360_sys::image::XexHeaderKey;
use xbox360_sys::mmio::MemoryCounters;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::KeIpiGenericCall;
use xbox360_sys::xboxkrnl::MemoryRegion;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::RtlImageXexHeaderField;

use self::file::create_file;
use self::file::delete_file;
use self::file::store_data_sizes;
use self::file::write_capture;
use self::file::write_failure;
use super::counters;
use super::load_pair;
use super::module_snapshot;
use super::pix;
use super::pmc;
use super::pmc::Owner;
use super::store_pair;
use crate::backend::Console;
use crate::backend::dispatcher;
use crate::exports::bridged;
use crate::exports::export;
use crate::kernel;
use crate::kernel::LoaderLock;
use crate::kernel::ModuleList;
use crate::kernel::RoutineVariable;
use crate::net::XamNetwork;

/// Capture file name buffer (stock 0x91fae820).
const NAME_CAPACITY: usize = 0x104;

static BLOCKS: [Block; MAX_PROCESSORS] = [const { Block::new() }; MAX_PROCESSORS];
/// Stock 0x91f96078.
static FLAGS: AtomicU32 = AtomicU32::new(CaptureFlags::IDLE.0);
/// Chunk size in bytes and words (0x91f9607c, 0x91f96080).
static CHUNK_BYTES: AtomicU32 = AtomicU32::new(0x4_0000);
static CHUNK_WORDS: AtomicU32 = AtomicU32::new(0x1_0000);
/// The performance counters were released or programmed (0x91f96084).
static COUNTERS_READY: AtomicBool = AtomicBool::new(true);
/// Counter number per processor of the processor counter setup
/// (0x91fae488).
static COUNTER_NUMBERS: [AtomicU8; MAX_PROCESSORS] = [const { AtomicU8::new(0) }; MAX_PROCESSORS];
/// Time base at start (0x91fae490).
static START_TIMEBASE: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
/// Lowest recording processor (0x91fae498).
static FIRST_PROCESSOR: AtomicU32 = AtomicU32::new(0);
/// Start/stop interlock (0x91fae49c).
static LOCK: AtomicU32 = AtomicU32::new(0);
/// Record buffer: base, next free chunk, end, size (0x91fae4a0..0x91fae4ac).
static BUFFER: AtomicU32 = AtomicU32::new(0);
static NEXT_CHUNK: AtomicU32 = AtomicU32::new(0);
static BUFFER_END: AtomicU32 = AtomicU32::new(0);
static BUFFER_SIZE: AtomicU32 = AtomicU32::new(0);
/// Chunk start and end arrays of every processor (0x91fae4b0).
static CHUNK_LIST: AtomicU32 = AtomicU32::new(0);
static CHUNKS_PER_PROCESSOR: AtomicU32 = AtomicU32::new(0);
/// A title terminated since the last start (0x91fae7e8).
static TITLE_TERMINATED: AtomicBool = AtomicBool::new(false);
/// Thread switch routine replaced while recording (0x91fae7ec).
static PREVIOUS_SWAP_ROUTINE: AtomicU32 = AtomicU32::new(0);
/// System time of the last start (0x91fae7f8).
static START_TIME: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
/// Flags before the last stop (0x91fae800).
static PREVIOUS_FLAGS: AtomicU32 = AtomicU32::new(0);
static FILE_NAME: FileName = FileName(UnsafeCell::new([0; NAME_CAPACITY]));

/// Like `bridged!`, passing the caller's return address as the argument.
macro_rules! bridged_with_return_address {
    ($entry:ident, $target:path) => {
        #[unsafe(naked)]
        extern "C" fn $entry() {
            core::arch::naked_asm!(
                "mflr 3",
                "lis 12, {target}@ha",
                "addi 12, 12, {target}@l",
                "b {bridge}",
                target = sym $target,
                bridge = sym crate::exports::export_bridge,
            )
        }
    };
}

xbox360_sys::flags! {
    /// Bits of [`Block::flags`] above the capture flags.
    pub struct ProcessorBlockFlags(u32) {
        /// The processor does not record.
        STOPPED = 0x8000_0000,
    }
}

/// Recording state of one processor (stock 0x20-byte blocks at
/// 0x91fae804).
struct Block {
    /// Address of the last word written.
    cursor: AtomicU32,
    /// A record starts only while the cursor is below this address.
    limit: AtomicU32,
    /// End of the records once stopped; 0 while recording.
    end: AtomicU32,
    /// Chunk start and end address arrays in the chunk list.
    chunk_starts: AtomicU32,
    chunk_ends: AtomicU32,
    chunk_count: AtomicU32,
    /// Capture flags at start, with [`ProcessorBlockFlags`].
    flags: AtomicU32,
    enabled: AtomicBool,
}

impl Block {
    const fn new() -> Self {
        Self {
            cursor: AtomicU32::new(0),
            limit: AtomicU32::new(0),
            end: AtomicU32::new(0),
            chunk_starts: AtomicU32::new(0),
            chunk_ends: AtomicU32::new(0),
            chunk_count: AtomicU32::new(0),
            flags: AtomicU32::new(ProcessorBlockFlags::STOPPED.bits()),
            enabled: AtomicBool::new(false),
        }
    }

    /// Disable and stop (stock 0x91f28048).
    fn reset(&self) {
        self.enabled.store(false, Ordering::Relaxed);
        self.end.store(0, Ordering::Relaxed);
        self.chunk_count.store(0, Ordering::Relaxed);
        self.flags
            .store(ProcessorBlockFlags::STOPPED.bits(), Ordering::Relaxed);
        self.limit.store(0, Ordering::Relaxed);
    }

    fn stopped(&self) -> bool {
        ProcessorBlockFlags::from_bits_retain(self.flags.load(Ordering::Relaxed))
            .contains(ProcessorBlockFlags::STOPPED)
    }

    /// Word `index` of the chunk start or end array `array` of the block.
    ///
    /// # Safety
    ///
    /// The block must be enabled with its arrays in the allocated chunk
    /// list, and `index` must be below its chunk count.
    unsafe fn chunk(&self, array: &AtomicU32, index: u32) -> u32 {
        // SAFETY: guaranteed by the caller.
        unsafe { word(array.load(Ordering::Relaxed) + index * 4) }.load(Ordering::Relaxed)
    }
}

/// Capture file name (0x91fae820); written and read under [`LOCK`].
struct FileName(UnsafeCell<[u8; NAME_CAPACITY]>);

// SAFETY: accessed only while `LOCK` is held.
unsafe impl Sync for FileName {}

/// Arguments of [`start_on_processor`]: first chunk per processor and the
/// chunk size in words.
#[repr(C)]
struct StartArguments {
    chunks: [u32; MAX_PROCESSORS],
    words: u32,
}

/// The capture engine over this module's state.
struct Engine;

impl capture::Engine for Engine {
    /// Stock 0x91f28ae0: the first loader list only, under the loader lock.
    fn instrumented(&mut self, kind: Instrumentation) -> bool {
        let lock = LoaderLock::acquire();

        lock.entries(ModuleList::Loaded).any(|entry| {
            let header = entry.xex_header_base;
            // SAFETY: `header` is the XEX header of a loaded module, mapped
            // while the loader lock is held.
            header != 0
                && unsafe { RtlImageXexHeaderField(header, XexHeaderKey(kind.header_field())) } != 0
        })
    }

    fn set_kernel_call_cap(&mut self, enable: bool) -> Result<(), KernelError> {
        // SAFETY: the service takes no pointers.
        let status = unsafe {
            xboxkrnl::ExDebugMonitorService(
                DebugMonitorService::KernelCallCapture,
                u32::from(enable),
                0,
                0,
            )
        };

        status.result()
    }

    fn set_title_terminated(&mut self, terminated: bool) {
        TITLE_TERMINATED.store(terminated, Ordering::Relaxed);
    }

    /// The title runs the capture: post the request in its control word
    /// and poll for its answer. The pointers are read again at every use,
    /// as stock does; a pointer the title cleared fails the request where
    /// stock dereferences null.
    fn request_title_capture(&mut self, megabytes: u8) -> Result<Started, CaptureError> {
        const POLL_MS: u32 = 60;
        const TIMEOUT_MS: u32 = 15_000;
        /// Control word bit that asks the title to start; the title clears
        /// the word once it has stored its result. The low byte holds the
        /// buffer size in megabytes.
        const START_REQUEST: u32 = 0x100;

        let request = counters::title_capture_request();
        let (Some(control), Some(_)) = (request.control, request.result) else {
            return Err(CaptureError::TitleCaptureFailed);
        };

        // SAFETY: the title published its control word in the title
        // interface and keeps it mapped while it runs.
        let control = unsafe { word(control) };
        control.store(
            control.load(Ordering::Relaxed) | u32::from(megabytes),
            Ordering::Relaxed,
        );

        let Some(control) = counters::title_capture_request().control else {
            return Err(CaptureError::TitleCaptureFailed);
        };

        // SAFETY: as above.
        let control = unsafe { word(control) };
        control.store(
            control.load(Ordering::Relaxed) | START_REQUEST,
            Ordering::Relaxed,
        );

        let start = TickCount::now().milliseconds();

        loop {
            sleep(Duration::from_millis(u64::from(POLL_MS)));
            if TickCount::now().milliseconds().wrapping_sub(start) > TIMEOUT_MS {
                return Err(CaptureError::TitleCaptureFailed);
            }

            let request = counters::title_capture_request();
            let Some(control) = request.control else {
                return Err(CaptureError::TitleCaptureFailed);
            };

            // SAFETY: as above.
            if unsafe { word(control) }.load(Ordering::Relaxed) == 0 {
                return counters::title_capture_request().result.map_or(
                    Err(CaptureError::TitleCaptureFailed),
                    |result| {
                        // SAFETY: the title published its result word with
                        // the control word.
                        capture::title_result(Hresult(
                            unsafe { word(result) }.load(Ordering::Relaxed),
                        ))
                    },
                );
            }
        }
    }

    /// Stock 0x91f29210.
    fn begin(
        &mut self,
        name: &[u8],
        buffer_size: u32,
        exclusive: bool,
    ) -> Result<Started, CaptureError> {
        /// The record buffer is written by every processor and read only
        /// by the file writer.
        const BUFFER_PROTECTION: PageProtection =
            PageProtection::READWRITE.union(PageProtection::WRITECOMBINE);

        if LOCK
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(CaptureError::Busy);
        }

        let flags = CaptureFlags(FLAGS.load(Ordering::Relaxed))
            .for_start(Kpcr::current().processor_number().get());
        FLAGS.store(flags.0, Ordering::Relaxed);

        let continued = recording();
        if continued && exclusive {
            LOCK.store(0, Ordering::Release);
            return Err(CaptureError::AlreadyRunning);
        }

        // SAFETY: `LOCK` is held.
        let file_name = unsafe { &mut *FILE_NAME.0.get() };
        let length = name.len().min(NAME_CAPACITY);
        file_name[..length].copy_from_slice(&name[..length]);
        file_name[length..].fill(0);
        file_name[NAME_CAPACITY - 1] = 0;

        let previous_size = BUFFER_SIZE.load(Ordering::Relaxed);
        let processors = processor_count();
        let recording_processors =
            (0..processors).filter(|&processor| flags.0 & 1 << processor != 0);
        let count = recording_processors.clone().count() as u32;
        if let Some(first) = recording_processors.clone().next() {
            FIRST_PROCESSOR.store(first as u32, Ordering::Relaxed);
        }

        let size = match capture::requested_buffer_size(buffer_size) {
            Some(size) => size,
            None if BUFFER.load(Ordering::Relaxed) != 0 => previous_size,
            None => match capture::probe_megabytes(&mut |megabytes| match allocate(
                megabytes << 20,
                BUFFER_PROTECTION,
            ) {
                0 => false,
                block => {
                    // SAFETY: the probe block was just allocated and is
                    // not used.
                    unsafe { free(block) };
                    true
                }
            }) {
                0 => {
                    BUFFER_SIZE.store(previous_size, Ordering::Relaxed);
                    LOCK.store(0, Ordering::Release);
                    return Err(CaptureError::NoBufferMemory);
                }
                megabytes => capture::default_buffer_size(megabytes),
            },
        };
        BUFFER_SIZE.store(size, Ordering::Relaxed);

        if flags.counters() && !pmc::acquire(Owner::CAPTURE) {
            BUFFER_SIZE.store(previous_size, Ordering::Relaxed);
            LOCK.store(0, Ordering::Release);
            return Err(CaptureError::CountersUnavailable);
        }

        let mut list = CHUNK_LIST.load(Ordering::Relaxed);
        if BUFFER.load(Ordering::Relaxed) != 0 {
            on_every_processor(reset_on_processor_entry, 0);
            let state = disable_interrupts();
            restore_swap_routine();
            restore_interrupts(state);

            if previous_size == size {
                NEXT_CHUNK.store(BUFFER.load(Ordering::Relaxed), Ordering::Relaxed);
            } else {
                // SAFETY: every processor was reset above, so no block
                // records into the buffers; the statics are cleared here.
                unsafe {
                    free(BUFFER.swap(0, Ordering::Relaxed));
                    free(list);
                }
                list = 0;
                CHUNK_LIST.store(0, Ordering::Relaxed);
                NEXT_CHUNK.store(0, Ordering::Relaxed);
            }
        }

        let chunk = capture::chunk_size(size, count);
        CHUNK_BYTES.store(chunk, Ordering::Relaxed);
        let words = chunk >> 2;
        CHUNK_WORDS.store(words, Ordering::Relaxed);

        // Stock traps on a zero chunk size, which no buffer size yields.
        let chunks = size.checked_div(chunk).unwrap_or(0);
        CHUNKS_PER_PROCESSOR.store(chunks, Ordering::Relaxed);

        let allocated = if BUFFER.load(Ordering::Relaxed) == 0 {
            let buffer = allocate(size, BUFFER_PROTECTION);
            BUFFER.store(buffer, Ordering::Relaxed);
            NEXT_CHUNK.store(buffer, Ordering::Relaxed);
            BUFFER_END.store(buffer.wrapping_add(size & !3), Ordering::Relaxed);
            list = allocate(
                chunks.wrapping_mul(processors as u32).wrapping_mul(8),
                PageProtection::READWRITE,
            );
            CHUNK_LIST.store(list, Ordering::Relaxed);

            buffer != 0
        } else {
            true
        };

        if !allocated || list == 0 {
            BUFFER_SIZE.store(previous_size, Ordering::Relaxed);
            if CaptureFlags(FLAGS.load(Ordering::Relaxed)).counters() {
                capture::Engine::release_counters(self);
            }

            LOCK.store(0, Ordering::Release);
            return Err(CaptureError::NoBufferMemory);
        }

        let state = disable_interrupts();
        if TITLE_TERMINATED.load(Ordering::Relaxed) {
            // Stock keeps the interlock until the next title terminates.
            restore_interrupts(state);
            return Err(CaptureError::TitleTerminated);
        }

        let mut arguments = StartArguments {
            chunks: [0; MAX_PROCESSORS],
            words,
        };
        let mut cursor = list;
        for (processor, block) in BLOCKS.iter().enumerate().take(processors) {
            let enabled = flags.0 & 1 << processor != 0;
            block.enabled.store(enabled, Ordering::Relaxed);
            block
                .flags
                .fetch_or(ProcessorBlockFlags::STOPPED.bits(), Ordering::Relaxed);

            if enabled {
                block.chunk_starts.store(cursor, Ordering::Relaxed);
                let ends = cursor + chunks * 4;
                block.chunk_ends.store(ends, Ordering::Relaxed);
                let next = NEXT_CHUNK.load(Ordering::Relaxed);
                arguments.chunks[processor] = next;
                NEXT_CHUNK.store(next.wrapping_add(words * 4), Ordering::Relaxed);
                cursor = ends + chunks * 4;
            } else {
                block.chunk_starts.store(0, Ordering::Relaxed);
                block.chunk_ends.store(0, Ordering::Relaxed);
                block.limit.store(0, Ordering::Relaxed);
            }
        }

        restore_interrupts(state);

        store_pair(&START_TIMEBASE, Timebase::now().ticks());
        on_every_processor(
            start_on_processor_entry,
            &raw const arguments as usize as u32,
        );

        if !continued && let Some(slot) = kernel::routine_variable(RoutineVariable::ContextSwap) {
            // A title terminate leaves the routine installed; saving it as
            // its own predecessor makes stock recurse on every thread
            // switch.
            let current = slot.load(Ordering::Relaxed);
            if current != thread_switch_entry as *const () as usize as u32 {
                PREVIOUS_SWAP_ROUTINE.store(current, Ordering::Relaxed);
            }

            // SAFETY: the kernel calls the routine with the previous and the
            // next thread on each thread switch, the form of
            // `thread_switch_entry`, which stays loaded until `shut_down`
            // restores the slot.
            unsafe {
                slot.store(
                    thread_switch_entry as *const () as usize as u32,
                    Ordering::Relaxed,
                )
            };
        }

        LOCK.store(0, Ordering::Release);

        if continued {
            Ok(Started::Continued)
        } else {
            Ok(Started::Recording)
        }
    }

    /// Stock 0x91f29830.
    fn end(&mut self) -> Result<(), CaptureError> {
        /// Longest capture that the 29-bit record timestamps cover.
        const TIMEBASE_LIMIT: u64 = 0x2000_0000;

        if LOCK
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(CaptureError::Busy);
        }

        if !recording() {
            LOCK.store(0, Ordering::Release);
            return Err(CaptureError::NoCapture);
        }

        if Timebase::now()
            .ticks()
            .wrapping_sub(load_pair(&START_TIMEBASE))
            > TIMEBASE_LIMIT
        {
            LOCK.store(0, Ordering::Release);
            return Err(CaptureError::TooLong);
        }

        let state = disable_interrupts();
        if let Some(slot) = kernel::routine_variable(RoutineVariable::ContextSwap) {
            // SAFETY: the kernel gets back the routine it called before
            // `begin` installed this module's, or none.
            unsafe {
                slot.store(
                    PREVIOUS_SWAP_ROUTINE.swap(0, Ordering::Relaxed),
                    Ordering::Relaxed,
                )
            };
        }

        let full = BLOCKS
            .iter()
            .take(processor_count())
            .any(|block| block.enabled.load(Ordering::Relaxed) && block.stopped());
        on_every_processor(stop_on_processor_entry, 0);
        restore_interrupts(state);
        LOCK.store(0, Ordering::Release);

        if full {
            Err(CaptureError::BufferFull)
        } else {
            Ok(())
        }
    }

    fn flags(&mut self) -> CaptureFlags {
        CaptureFlags(FLAGS.load(Ordering::Relaxed))
    }

    fn retire_flags(&mut self, previous: CaptureFlags) {
        FLAGS.store(CaptureFlags::IDLE.0, Ordering::Relaxed);
        PREVIOUS_FLAGS.store(previous.0, Ordering::Relaxed);
    }

    /// Stock 0x91f27db8.
    fn finish_counters(&mut self, flags: CaptureFlags) -> Result<(), CaptureError> {
        match flags.counter_source() {
            CounterSource::Processor(_) => {
                if pmc::stop(Owner::CAPTURE) {
                    Ok(())
                } else {
                    Err(CaptureError::CountersLost)
                }
            }
            _ => {
                // SAFETY: the memory controller counters count bus events
                // and write no memory.
                unsafe { MemoryCounters::get().control.write(MemoryCounters::STOP) };

                Ok(())
            }
        }
    }

    fn release_counters(&mut self) {
        pmc::release(Owner::CAPTURE);
        COUNTERS_READY.store(true, Ordering::Relaxed);
    }

    fn counters_ready(&mut self) -> bool {
        COUNTERS_READY.load(Ordering::Relaxed)
    }

    fn try_lock(&mut self) -> bool {
        LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    fn unlock(&mut self) {
        LOCK.store(0, Ordering::Release);
    }

    /// Stock 0x91f28540; an open failure keeps the buffers.
    fn write(&mut self, paths: &mut dyn Paths) -> Result<(), KernelError> {
        // SAFETY: the caller holds `LOCK`.
        let file_name = unsafe { &*FILE_NAME.0.get() };
        // A name without a terminator fills the buffer.
        let length = file_name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(NAME_CAPACITY);
        let path = paths
            .object_path(&file_name[..length])
            .ok_or(KernelError::NoSuchFile)?;
        let handle = create_file(path.as_bytes())?;

        let mut executable = [0u8; module_snapshot::PATH_LIMIT + 2];
        let executable_length = paths.executable_drive_path(&mut executable);
        // Each path closes the file itself, so no flag has to live across
        // the calls.
        let Some(mut snapshot) =
            module_snapshot::build(&executable[..executable_length], snapshot_fields())
        else {
            // SAFETY: `handle` was opened by `create_file` above and is
            // closed once.
            unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
            release_buffers();
            return Err(write_failure::NO_SNAPSHOT);
        };

        let written =
            store_data_sizes(snapshot.data_sizes()).and_then(|()| write_capture(handle, &snapshot));

        // SAFETY: as above.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
        module_snapshot::free(snapshot);
        release_buffers();

        written
    }

    fn dos_error(&mut self, error: KernelError) -> Option<Win32Error> {
        xbox360::status::dos_error(error)
    }

    /// Stock 0x91f28a10 after the flags: the buffers are forgotten, not
    /// freed.
    fn discard(&mut self) {
        on_every_processor(reset_on_processor_entry, 0);

        LOCK.store(0, Ordering::Relaxed);
        BUFFER.store(0, Ordering::Relaxed);
        NEXT_CHUNK.store(0, Ordering::Relaxed);
        BUFFER_END.store(0, Ordering::Relaxed);
        BUFFER_SIZE.store(0, Ordering::Relaxed);
        CHUNK_LIST.store(0, Ordering::Relaxed);
        CHUNKS_PER_PROCESSOR.store(0, Ordering::Relaxed);
    }
}

/// [`Paths`] where the server's drive table cannot be read: no name
/// translates, and the executable keeps its object path, as for a path
/// outside every drive.
struct NoDriveTable;

impl Paths for NoDriveTable {
    fn object_path(&mut self, _name: &[u8]) -> Option<ObjectPath> {
        None
    }

    fn executable_drive_path(&mut self, output: &mut [u8]) -> usize {
        let limit = output.len().saturating_sub(1);
        module_snapshot::copy_executable_object_path(&mut output[..limit])
    }
}

/// Export 73 request posted to the server thread.
struct TitleStart<'a> {
    name: &'a [u8],
    buffer: BufferRequest,
}

/// The word at `address` of the record buffer, the chunk list, or a
/// title's capture request. The record and chunk words are addressed by
/// the cursors of the blocks; a slice there would add a bounds check to
/// every record.
///
/// The chunk list is sized for the chunk count of the start that allocated
/// it. A later start with the same buffer size keeps both allocations even
/// when more processors record, which gives each processor fewer chunks,
/// so its start and end arrays can reach past the list. Stock does the
/// same; the chunk index is not checked here either.
///
/// # Safety
///
/// `address` must be an aligned word that stays mapped for `'a`: in the
/// record buffer or the chunk list while they are allocated, or published
/// by the running title.
unsafe fn word<'a>(address: u32) -> &'a AtomicU32 {
    // SAFETY: guaranteed by the caller.
    unsafe { kernel::object_at(address) }
}

fn current_thread_id() -> u32 {
    xbox360::thread::current_object().id().raw()
}

fn timebase_low() -> u32 {
    let value: u32;
    // SAFETY: reads the time base; no memory access.
    unsafe {
        core::arch::asm!("mftb {0}", out(reg) value, options(nomem, nostack, preserves_flags))
    };

    value
}

/// Clear the external interrupt enable bit and return the previous
/// machine state (stock 0x91f27b98).
fn disable_interrupts() -> u32 {
    let state: u32;
    // SAFETY: mtmsrd r13, 1 copies the interrupt enable bit of the PCR
    // address, which is clear.
    unsafe { core::arch::asm!("mfmsr {0}", ".long 0x7da10164", out(reg) state, options(nostack)) };

    state
}

/// Restore the interrupt enable bit (stock 0x91f27ba8).
fn restore_interrupts(state: u32) {
    // SAFETY: mtmsrd r11, 1 restores only the interrupt enable and
    // recoverable bits saved by `disable_interrupts`.
    unsafe { core::arch::asm!(".long 0x7d610164", in("r11") state, options(nostack)) };
}

fn processor_count() -> usize {
    (kernel::debug_monitor_data()
        .processor_count
        .load(Ordering::Relaxed) as usize)
        .min(MAX_PROCESSORS)
}

/// A chunk of the record buffer, or 0 when it is exhausted (stock
/// 0x91f27e20). A chunk is granted only while four chunks fit; with
/// discarded PIX output the buffer starts over at its base.
fn allocate_chunk() -> u32 {
    let size = CHUNK_BYTES.load(Ordering::Relaxed);
    let chunk = NEXT_CHUNK.fetch_add(size, Ordering::Relaxed);
    let reach = chunk.wrapping_add(size.wrapping_mul(4));
    let base = BUFFER.load(Ordering::Relaxed);

    if reach > base && reach <= BUFFER_END.load(Ordering::Relaxed) {
        return chunk;
    }

    if pix::discard_output() {
        NEXT_CHUNK.store(base, Ordering::Relaxed);
        return base;
    }

    0
}

/// Close the full chunk at `cursor` and continue in a new one; the new
/// cursor, or 0 when the processor stops recording (stock 0x91f28bd8).
fn next_chunk(cursor: u32, block: &Block) -> u32 {
    if block.stopped() {
        return 0;
    }

    let count = block.chunk_count.load(Ordering::Relaxed);
    // SAFETY: a block that has not stopped records into the chunk list
    // with at least one chunk; past the list only in the case that
    // [`word`] describes, as in stock.
    unsafe {
        word(
            block
                .chunk_ends
                .load(Ordering::Relaxed)
                .wrapping_add(count.wrapping_sub(1).wrapping_mul(4)),
        )
    }
    .store(cursor + 4, Ordering::Relaxed);

    let chunk = allocate_chunk();
    if chunk == 0 {
        block.cursor.store(cursor, Ordering::Relaxed);
        block.limit.store(0, Ordering::Relaxed);
        block
            .flags
            .fetch_or(ProcessorBlockFlags::STOPPED.bits(), Ordering::Relaxed);
        return 0;
    }

    if pix::discard_output() {
        block.chunk_count.store(0, Ordering::Relaxed);
    }

    let count = block.chunk_count.load(Ordering::Relaxed);
    // SAFETY: the start array of a recording block is in the chunk list
    // except in the case that [`word`] describes, as in stock.
    unsafe { word(block.chunk_starts.load(Ordering::Relaxed) + count * 4) }
        .store(chunk, Ordering::Relaxed);
    block.chunk_count.store(count + 1, Ordering::Relaxed);

    let words = CHUNK_WORDS.load(Ordering::Relaxed);
    block.limit.store(
        chunk.wrapping_add(words.wrapping_sub(CHUNK_RESERVE_WORDS) * 4),
        Ordering::Relaxed,
    );

    chunk - 4
}

/// Counter value appended to records (stock 0x91f28cb8).
fn read_counter(flags: CaptureFlags, processor: usize) -> u32 {
    match flags.counter_source() {
        CounterSource::Processor(_) => pmc::counter(u32::from(
            COUNTER_NUMBERS[processor].load(Ordering::Relaxed),
        )),
        source => {
            let counters = MemoryCounters::get();
            let second = match source {
                CounterSource::Memory(capture::MemoryCounter::Combined) => counters.value2.read(),
                _ => 0,
            };

            counters.value.read().wrapping_add(second)
        }
    }
}

/// Write one record into `processor`'s block. `checked` grows into a new
/// chunk at the limit (stock 0x91f28fa0 and the hooks); unchecked writes
/// rely on the chunk reserve (0x91f29048).
fn append(processor: usize, kind: RecordKind, first: u32, second: Option<u32>, checked: bool) {
    let Some(block) = BLOCKS.get(processor) else {
        return;
    };

    let state = disable_interrupts();
    let mut cursor = block.cursor.load(Ordering::Relaxed);
    let flags = CaptureFlags(block.flags.load(Ordering::Relaxed));
    if checked && cursor >= block.limit.load(Ordering::Relaxed) {
        cursor = next_chunk(cursor, block);
    }

    if cursor != 0 {
        // SAFETY: a nonzero cursor lies in a chunk granted to the block.
        // Checked records start below the limit and unchecked ones fit in
        // the chunk reserve above it, so every word is in the record
        // buffer.
        unsafe {
            cursor += 4;
            word(cursor).store(
                capture::record_header(kind, timebase_low()),
                Ordering::Relaxed,
            );
            cursor += 4;
            word(cursor).store(first, Ordering::Relaxed);
            if let Some(second) = second {
                cursor += 4;
                word(cursor).store(second, Ordering::Relaxed);
            }

            if flags.counters() {
                let counter = read_counter(flags, processor);
                cursor += 4;
                word(cursor).store(counter, Ordering::Relaxed);
            }
        }
        block.cursor.store(cursor, Ordering::Relaxed);
    }

    restore_interrupts(state);
}

/// Record of an enabled processor's control event.
fn append_control(processor: usize, record: ControlRecord, value: u32, checked: bool) {
    let enabled = BLOCKS
        .get(processor)
        .is_some_and(|block| block.enabled.load(Ordering::Relaxed));
    if !enabled {
        return;
    }

    append(
        processor,
        RecordKind::Control,
        record as u32,
        Some(value),
        checked,
    );
}

/// Export 65.
extern "C" fn record_pair(first: u32, second: u32) {
    append(
        usize::from(Kpcr::current().processor_number().get()),
        RecordKind::Pair,
        first,
        Some(second),
        true,
    );
}
export!(65, record_pair);

/// Export 66.
extern "C" fn record_single(value: u32) {
    append(
        usize::from(Kpcr::current().processor_number().get()),
        RecordKind::Single,
        value,
        None,
        true,
    );
}
export!(66, record_single);

extern "C" fn record_entry(return_address: u32) {
    append(
        usize::from(Kpcr::current().processor_number().get()),
        RecordKind::Entry,
        return_address,
        None,
        true,
    );
}
bridged_with_return_address!(entry_hook, record_entry);
export_raw!(70, entry_hook);

extern "C" fn record_exit(return_address: u32) {
    append(
        usize::from(Kpcr::current().processor_number().get()),
        RecordKind::Exit,
        return_address,
        None,
        true,
    );
}
bridged_with_return_address!(exit_hook, record_exit);
export_raw!(71, exit_hook);

/// Thread switch routine installed while recording (stock 0x91f290d0):
/// records the incoming thread, then runs the replaced routine.
extern "C" fn thread_switched(previous: u32, next: u32) {
    // SAFETY: the kernel passes the object of the thread it switches to,
    // which stays allocated while the thread runs.
    let next_thread = unsafe { ThreadObject::from_raw(next) };
    append_control(
        usize::from(Kpcr::current().processor_number().get()),
        ControlRecord::ThreadSwitch,
        next_thread.id().raw(),
        true,
    );

    let routine = PREVIOUS_SWAP_ROUTINE.load(Ordering::Relaxed);
    if routine != 0 {
        // SAFETY: the kernel's previous thread switch routine takes two
        // arguments.
        unsafe { crate::kernel::call_export(routine, previous, next, 0, 0) };
    }
}
bridged!(thread_switch_entry, thread_switched);

/// Program the counters of `flags` on this processor (stock 0x91f27ce8).
fn program_counters(flags: CaptureFlags) {
    match flags.counter_source() {
        CounterSource::Processor(setup) => program_processor_counters(setup),
        CounterSource::Memory(counter) => {
            let (event, second) = counter.events();
            let counters = MemoryCounters::get();
            // SAFETY: the memory controller counters count bus events and
            // write no memory.
            unsafe {
                counters.control.write(MemoryCounters::STOP);
                counters.event.write(event);
                counters.event2.write(second);
                counters.control.write(0);
                counters.control.write(MemoryCounters::START);
            }
        }
        // Stock prints the message and traps on every processor; the
        // capture records without programming instead.
        CounterSource::Unsupported(selector) => {
            pmc::print(c"Invalid counter ID %u\n", &[u64::from(selector)]);
        }
    }
}

/// Processor counter setup (stock 0x91f27bb8): every processor selects
/// the events; the lowest recording processor also takes the counter
/// numbers, configures, clears, and starts the counters.
fn program_processor_counters(setup: CounterSetup) {
    pmc::set_print_flags(u32::MAX);
    let counters = setup.setup();
    pmc::select_events(Owner::CAPTURE, &counters);

    let flags = FLAGS.load(Ordering::Relaxed);
    let first = (0..MAX_PROCESSORS).find(|&processor| flags & 1 << processor != 0);
    if first != Some(usize::from(Kpcr::current().processor_number().get())) {
        return;
    }

    for (number, &value) in COUNTER_NUMBERS.iter().zip(&setup.counter_numbers()) {
        number.store(value, Ordering::Relaxed);
    }

    let ready = pmc::configure(Owner::CAPTURE, &counters)
        && pmc::stop(Owner::CAPTURE)
        && pmc::clear(Owner::CAPTURE)
        && pmc::start(Owner::CAPTURE);
    COUNTERS_READY.store(ready, Ordering::Relaxed);
}

/// Start recording on this processor (stock 0x91f27eb8, IPI routine).
extern "C" fn start_on_processor(arguments: u32) -> u32 {
    // SAFETY: the initiator's arguments outlive the IPI.
    let arguments = unsafe { crate::kernel::object_at::<StartArguments>(arguments) };
    let processor = usize::from(Kpcr::current().processor_number().get());
    let flags = CaptureFlags(FLAGS.load(Ordering::Relaxed));
    let state = disable_interrupts();

    if let Some(block) = BLOCKS
        .get(processor)
        .filter(|block| block.enabled.load(Ordering::Relaxed))
    {
        let chunk = arguments.chunks[processor];
        let mut last = chunk + 8;
        // SAFETY: `begin` gave every enabled processor a chunk of the
        // allocated record buffer, larger than the start record, and its
        // block a start array whose first word is in the chunk list.
        unsafe {
            word(chunk).store(
                capture::record_header(RecordKind::Control, timebase_low()),
                Ordering::Relaxed,
            );
            word(chunk + 4).store(ControlRecord::Start as u32, Ordering::Relaxed);
            word(last).store(current_thread_id(), Ordering::Relaxed);
        }

        if flags.counters() {
            program_counters(flags);
            let counter = read_counter(flags, processor);
            last += 4;
            // SAFETY: as above.
            unsafe { word(last) }.store(counter, Ordering::Relaxed);
        }

        // SAFETY: as above.
        unsafe { word(block.chunk_starts.load(Ordering::Relaxed)) }.store(chunk, Ordering::Relaxed);
        block.cursor.store(last, Ordering::Relaxed);
        block.limit.store(
            chunk.wrapping_add(arguments.words.wrapping_sub(CHUNK_RESERVE_WORDS) * 4),
            Ordering::Relaxed,
        );
        block.chunk_count.store(1, Ordering::Relaxed);
        block.flags.store(flags.0, Ordering::Relaxed);
    }

    restore_interrupts(state);

    0
}
bridged!(start_on_processor_entry, start_on_processor);

/// Stop recording on this processor (stock 0x91f29160, IPI routine).
extern "C" fn stop_on_processor(_context: u32) -> u32 {
    let processor = usize::from(Kpcr::current().processor_number().get());
    let state = disable_interrupts();

    if let Some(block) = BLOCKS
        .get(processor)
        .filter(|block| block.enabled.load(Ordering::Relaxed))
    {
        append_control(processor, ControlRecord::Stop, current_thread_id(), false);
        let end = block.cursor.load(Ordering::Relaxed) + 4;
        block.end.store(end, Ordering::Relaxed);

        let count = block.chunk_count.load(Ordering::Relaxed);

        // SAFETY: an enabled block records into the chunk list with at
        // least one chunk.
        unsafe {
            word(
                block
                    .chunk_ends
                    .load(Ordering::Relaxed)
                    .wrapping_add(count.wrapping_sub(1).wrapping_mul(4)),
            )
        }
        .store(end, Ordering::Relaxed);
        block
            .flags
            .store(ProcessorBlockFlags::STOPPED.bits(), Ordering::Relaxed);
        block.limit.store(0, Ordering::Relaxed);
    }

    restore_interrupts(state);

    0
}
bridged!(stop_on_processor_entry, stop_on_processor);

/// Disable this processor's block (stock 0x91f28048, IPI routine).
extern "C" fn reset_on_processor(_context: u32) -> u32 {
    let state = disable_interrupts();

    if let Some(block) = BLOCKS
        .get(usize::from(Kpcr::current().processor_number().get()))
        .filter(|block| block.enabled.load(Ordering::Relaxed))
    {
        block.reset();
    }

    restore_interrupts(state);

    0
}
bridged!(reset_on_processor_entry, reset_on_processor);

fn on_every_processor(routine: unsafe extern "C" fn(), context: u32) {
    // SAFETY: `routine` is a bridged IPI entry of this image that reads only
    // static state; `context` is passed through.
    unsafe { KeIpiGenericCall(routine as *const () as usize as u32, context) };
}

/// Buffers exist and the lowest recording processor has not stopped.
fn recording() -> bool {
    BUFFER.load(Ordering::Relaxed) != 0
        && BLOCKS
            .get(FIRST_PROCESSOR.load(Ordering::Relaxed) as usize)
            .is_some_and(|block| block.end.load(Ordering::Relaxed) == 0)
}

fn allocate(size: u32, protection: PageProtection) -> u32 {
    // SAFETY: physical allocation of the requested size; callers check the result.
    unsafe {
        xboxkrnl::MmAllocatePhysicalMemoryEx(
            MemoryRegion::Title,
            size,
            protection,
            0,
            u32::MAX,
            PAGE_SIZE,
        )
    }
}

/// Free a buffer from [`allocate`] through the one shared copy.
///
/// # Safety
///
/// `address` must be 0 or a buffer from [`allocate`] that nothing uses any
/// more.
#[inline(always)]
unsafe fn free(address: u32) {
    // SAFETY: guaranteed by the caller.
    unsafe { module_snapshot::free_title_memory(address) };
}

/// Restore the thread switch routine replaced at start.
fn restore_swap_routine() {
    if let Some(slot) = kernel::routine_variable(RoutineVariable::ContextSwap) {
        // SAFETY: the kernel gets back the routine it called before `begin`
        // installed this module's, or none.
        unsafe {
            slot.store(
                PREVIOUS_SWAP_ROUTINE.load(Ordering::Relaxed),
                Ordering::Relaxed,
            )
        };
    }
}

/// Free the buffers and disable every processor (end of stock 0x91f28540).
fn release_buffers() {
    // SAFETY: the buffers are 0 or this module's allocations, and every
    // processor has stopped or been reset; the statics are cleared below.
    unsafe {
        free(BUFFER.load(Ordering::Relaxed));
        free(CHUNK_LIST.load(Ordering::Relaxed));
    }

    BUFFER.store(0, Ordering::Relaxed);
    CHUNK_LIST.store(0, Ordering::Relaxed);
    FIRST_PROCESSOR.store(0, Ordering::Relaxed);
    NEXT_CHUNK.store(0, Ordering::Relaxed);
    BUFFER_END.store(0, Ordering::Relaxed);
    BUFFER_SIZE.store(0, Ordering::Relaxed);
    CHUNKS_PER_PROCESSOR.store(0, Ordering::Relaxed);
    store_pair(&START_TIMEBASE, 0);

    for block in BLOCKS.iter().take(processor_count()) {
        if block.enabled.load(Ordering::Relaxed) {
            block
                .flags
                .store(ProcessorBlockFlags::STOPPED.bits(), Ordering::Relaxed);
            block.limit.store(0, Ordering::Relaxed);
            block.enabled.store(false, Ordering::Relaxed);
            block.end.store(0, Ordering::Relaxed);
            block.chunk_count.store(0, Ordering::Relaxed);
        }
    }
}

/// Capture values the module snapshot records.
pub(crate) fn snapshot_fields() -> module_snapshot::CaptureFields {
    module_snapshot::CaptureFields {
        start_time: load_pair(&START_TIME),
        previous_flags: PREVIOUS_FLAGS.load(Ordering::Relaxed),
    }
}

/// Capture buffers exist (stock 0x91f28bc0).
pub(crate) fn buffer_allocated() -> bool {
    BUFFER.load(Ordering::Relaxed) != 0
}

/// The result word of the capture exports.
fn reply_word(result: Result<Reply, CaptureError>) -> u32 {
    reply::hresult(result.map_err(CommandError::from)).0
}

/// `capctrl start` after the server validated the file (stock 0x91f29d08).
pub(super) fn start(
    name: &[u8],
    path: &[u8],
    buffer: BufferRequest,
) -> Result<Started, CaptureError> {
    delete_file(path);
    store_pair(&START_TIME, FileTime::now().intervals());

    capture::start(&mut Engine, name, buffer, true)
}

/// Export 73 with `paths` (stock 0x91f29c00): a running capture continues
/// under the new name without touching the file.
fn start_for_title(
    paths: &mut dyn Paths,
    name: &[u8],
    buffer: BufferRequest,
) -> Result<Started, CaptureError> {
    if !recording() {
        let path = paths.object_path(name).ok_or(CaptureError::FileFailed)?;
        let handle = create_file(path.as_bytes()).map_err(|_| CaptureError::FileFailed)?;
        // SAFETY: `handle` was just opened by `create_file` and is closed once.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
        delete_file(path.as_bytes());
    }

    store_pair(&START_TIME, FileTime::now().intervals());

    capture::start(&mut Engine, name, buffer, false)
}

fn start_on_server(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    request: &mut TitleStart<'_>,
) -> u32 {
    let mut paths = DrivePaths {
        drives: &server.state.filesystem.drives,
        backend: console,
    };

    reply_word(start_for_title(&mut paths, request.name, request.buffer).map(Reply::from))
}

/// Export 73: start a capture into the drive path `name`. The drive table
/// is read on the server thread; the title waits for it.
extern "C" fn title_start(name: *const u8, buffer_size: u32) -> u32 {
    /// Longest name read from the title.
    const NAME_LIMIT: usize = 0x140;

    // At most `NAME_LIMIT` bytes are read (stock copies the name unbounded
    // into a 0x141-byte stack buffer).
    // SAFETY: export 73 takes a NUL-terminated path, not 0 (stock reads it
    // without a check; here 0 breaks the export contract), that the title
    // keeps unchanged for the call.
    let name =
        unsafe { kernel::bounded_c_string(name as usize as u32, NAME_LIMIT).unwrap_unchecked() };
    let buffer = BufferRequest(buffer_size);
    let mut request = TitleStart { name, buffer };

    dispatcher::call_on_server_with(&mut request, start_on_server).unwrap_or_else(|| {
        reply_word(start_for_title(&mut NoDriveTable, name, buffer).map(Reply::from))
    })
}
bridged!(title_start_entry, title_start);
export_raw!(73, title_start_entry);

/// `capctrl stop` on the server thread.
pub(super) fn stop(console: &mut Console, drives: &DriveTable) -> Result<(), CaptureError> {
    capture::stop(
        &mut Engine,
        &mut DrivePaths {
            drives,
            backend: console,
        },
    )
}

fn stop_on_server(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    _request: &mut (),
) -> u32 {
    reply_word(stop(console, &server.state.filesystem.drives).map(|()| Reply::Ok))
}

/// Export 74: stop and write the capture file; the drive table is read on
/// the server thread.
extern "C" fn title_stop() -> u32 {
    dispatcher::call_on_server_with(&mut (), stop_on_server).unwrap_or_else(|| {
        reply_word(capture::stop(&mut Engine, &mut NoDriveTable).map(|()| Reply::Ok))
    })
}
bridged!(title_stop_entry, title_stop);
export_raw!(74, title_stop_entry);

pub(super) fn fast_cap_present() -> bool {
    capture::Engine::instrumented(&mut Engine, Instrumentation::FastCap)
}

pub(super) fn call_cap_present() -> bool {
    capture::Engine::instrumented(&mut Engine, Instrumentation::CallCap)
}

/// Export 84.
extern "C" fn fast_cap_result() -> u32 {
    reply_word(capture::fast_cap_state(fast_cap_present()).map(Reply::Capture))
}
export!(84, fast_cap_result);

pub(super) fn set_flags(flags: CaptureFlags) {
    FLAGS.store(flags.0, Ordering::Relaxed);
}

/// Export 90.
extern "C" fn set_flags_export(value: u32) -> u32 {
    set_flags(CaptureFlags::from_request(value));
    Hresult::OK.0
}
export!(90, set_flags_export);

/// `capctrl profilingstatus` (stock 0x91f28940).
pub(super) fn status() -> Result<(), CaptureError> {
    if TITLE_TERMINATED.load(Ordering::Relaxed) {
        return Err(CaptureError::TitleTerminated);
    }

    if !recording() {
        return Err(CaptureError::NoCapture);
    }

    let full = BLOCKS.iter().take(processor_count()).any(|block| {
        block.enabled.load(Ordering::Relaxed)
            && block.end.load(Ordering::Relaxed) == 0
            && block.stopped()
    });

    if full {
        Err(CaptureError::BufferFull)
    } else {
        Ok(())
    }
}

extern "C" fn status_export() -> u32 {
    reply_word(status().map(|()| Reply::Ok))
}
export!(146, status_export);

/// `capctrl abort` (export 162).
pub(super) fn abort() -> Result<(), CaptureError> {
    capture::abort(&mut Engine)
}

extern "C" fn abort_export() -> u32 {
    reply_word(abort().map(|()| Reply::Ok))
}
export!(162, abort_export);

/// Publish the title capture entries (stock 0x91f32628).
pub(super) fn initialize() {
    counters::set_capture_entries(
        title_start_entry as *const () as usize as u32,
        title_stop_entry as *const () as usize as u32,
    );
}

/// Stop a running capture (kernel call-cap, counters), restore the thread
/// switch routine, stop every processor, and free the buffers before the
/// image unloads; stock never unloads.
pub(super) fn shut_down() {
    if BUFFER.load(Ordering::Relaxed) != 0 {
        let _ = abort();
    }

    if let Some(slot) = kernel::routine_variable(RoutineVariable::ContextSwap)
        && slot.load(Ordering::Relaxed) == thread_switch_entry as *const () as usize as u32
    {
        // SAFETY: the kernel gets back the routine it called before `begin`
        // installed this module's, or none.
        unsafe {
            slot.store(
                PREVIOUS_SWAP_ROUTINE.swap(0, Ordering::Relaxed),
                Ordering::Relaxed,
            )
        };
    }

    on_every_processor(reset_on_processor_entry, 0);

    if BUFFER.load(Ordering::Relaxed) != 0 {
        release_buffers();
    }
}

/// Capture part of the title terminate routine (stock 0x91f28a10).
pub(super) fn title_terminated() {
    capture::title_terminated(&mut Engine);
}
