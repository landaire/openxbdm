use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::memory::PAGE_SIZE;
use openxbdm_server::commands::performance::profiler::ProfilerFlags;
use xbox360::status::dos_error;
use xbox360::time::FileTime;
use xbox360::time::Timebase;
use xbox360::time::sleep;
use xbox360_sys::image::ImageDirectory;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;
use xbox360_sys::status::Win32ErrorCode;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::Kevent;
use xbox360_sys::xboxkrnl::MemoryRegion;
use xbox360_sys::xboxkrnl::PageProtection;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::RtlImageDirectoryEntryToData;
use xbox360_sys::xboxkrnl::ShareAccess;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;

use super::super::module_snapshot;
use super::super::pmc::print;
use super::FLAGS;
use super::HEADER;
use super::ProfileHeader;
use super::RECORD_HEADER_WORDS;
use super::START_TIMEBASE;
use super::blocks::BLOCKS;
use super::blocks::ProfilerState;
use super::blocks::STAGING;
use super::blocks::THREADS;
use super::last_processor;
use super::sampled;
use super::word_bytes;
use crate::backend::filesystem;
use crate::kernel;
use crate::kernel::LoaderLock;

/// Function tables the file records at most.
const MODULE_CAPACITY: usize = 0x80;

static FILE: AtomicU32 = AtomicU32::new(0);
static WRITER_FAILED: AtomicBool = AtomicBool::new(false);
/// The writer opened the file (stock 0x91faaec4).
static WRITER_STARTED: NotificationEvent = NotificationEvent(UnsafeCell::new([0; 4]));
/// The writer closed the file (stock 0x91faaeb4).
static WRITER_FINISHED: NotificationEvent = NotificationEvent(UnsafeCell::new([0; 4]));
static WRITER_PATHS: WriterPaths = WriterPaths(UnsafeCell::new(WriterPathData {
    file: [0; 0x104],
    file_length: 0,
    executable: [0; module_snapshot::PATH_LIMIT + 2],
    executable_length: 0,
}));

/// A kernel notification event in static storage.
struct NotificationEvent(UnsafeCell<[u32; 4]>);

// SAFETY: the kernel synchronizes access to dispatcher objects.
unsafe impl Sync for NotificationEvent {}

impl NotificationEvent {
    fn pointer(&self) -> *mut Kevent {
        self.0.get().cast()
    }

    /// Unsignaled, with the wait list head pointing at itself.
    fn reset(&self) {
        let list = self.0.get().cast::<u32>().wrapping_add(2) as usize as u32;
        // SAFETY: called before the writer thread exists.
        unsafe { *self.0.get() = [0, 0, list, list] };
    }

    fn set(&self) {
        // SAFETY: the event lives in static storage initialized by `reset`.
        unsafe { xboxkrnl::KeSetEvent(self.pointer(), 1, false) };
    }

    fn wait(&self) -> bool {
        // SAFETY: the event lives in static storage initialized by `reset`.
        let status = unsafe {
            xboxkrnl::KeWaitForSingleObject(
                self.pointer().cast(),
                WaitReason::Executive,
                ProcessorMode::Kernel,
                false,
                core::ptr::null(),
            )
        };
        status.is_success()
    }
}

/// A module's exception directory copy (stock 0x91f32e90 entries).
#[derive(Clone, Copy, Default)]
struct FunctionTable {
    base: u32,
    image_size: u32,
    /// Bytes of `copy`; 0 without a directory.
    size: u32,
    /// Physical memory copy of the directory, owned by the table until
    /// freed; `None` without a directory.
    copy: Option<NonNull<u8>>,
}

/// Executable path the module snapshot records, prepared on the server
/// thread for the writer.
struct WriterPaths(UnsafeCell<WriterPathData>);

// SAFETY: written before the writer thread is created and read only by
// it while the starter waits.
unsafe impl Sync for WriterPaths {}

struct WriterPathData {
    file: [u8; 0x104],
    file_length: usize,

    executable: [u8; module_snapshot::PATH_LIMIT + 2],
    executable_length: usize,
}

/// Write `data`; true when all of it was written (stock 0x91f73af8).
/// `offset` is the file position, the current one when `None`.
#[inline(always)]
fn write(data: &[u8], offset: Option<u64>) -> bool {
    // SAFETY: `data` is a live slice.
    unsafe { write_raw(data.as_ptr(), data.len() as u32, offset) }
}

/// [`write`] of `length` bytes at `data`.
///
/// # Safety
///
/// `data` is readable for `length` bytes until the call returns.
pub(super) unsafe fn write_raw(data: *const u8, length: u32, offset: Option<u64>) -> bool {
    let mut io_status = IoStatusBlock {
        status: NtStatus::SUCCESS,
        information: 0,
    };
    let offset_pointer = offset
        .as_ref()
        .map_or(core::ptr::null(), |offset| offset as *const u64);

    // SAFETY: FILE is the writer's open file; `io_status` and the offset
    // are live for the synchronous call, and the caller guarantees `data`.
    let status = unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(FILE.load(Ordering::Relaxed)),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            data,
            length,
            offset_pointer,
        )
    };

    status.is_success() && io_status.information == length
}

/// Free a directory copy.
///
/// # Safety
///
/// `copy` must be a copy from `copy_function_tables` that is not used
/// afterwards.
#[inline(always)]
unsafe fn free_copy(copy: NonNull<u8>) {
    // SAFETY: a physical allocation in the region of
    // `copy_function_tables`, freed once by the contract.
    unsafe {
        xboxkrnl::MmFreePhysicalMemory(
            MemoryRegion::Title,
            copy.as_ptr().expose_provenance() as u32,
        )
    };
}

/// Copy the exception directories of the loaded modules into physical
/// memory (stock 0x91f32e90); `None` when a copy cannot be allocated.
fn copy_function_tables(tables: &mut [FunctionTable; MODULE_CAPACITY]) -> Option<usize> {
    // Copies may lie at any page aligned physical address.
    const LOWEST_ADDRESS: u32 = 0;
    const HIGHEST_ADDRESS: u32 = u32::MAX;
    const ALIGNMENT: u32 = PAGE_SIZE;

    let lock = LoaderLock::acquire();
    let mut count = 0;
    for record in lock.all_entries() {
        if count == MODULE_CAPACITY {
            break;
        }

        let base = record.dll_base;
        if base == 0 {
            continue;
        }

        let mut size = 0u32;
        // SAFETY: `base` is a loaded image on a list whose lock is held;
        // `size` is a live u32.
        let directory = unsafe {
            RtlImageDirectoryEntryToData(base, true, ImageDirectory::Exception, &mut size)
        };
        let mut table = FunctionTable {
            base,
            image_size: record.image_size,
            size: 0,
            copy: None,
        };

        if directory != 0 {
            // SAFETY: physical allocation of `size` bytes; the result is
            // checked below.
            let address = unsafe {
                xboxkrnl::MmAllocatePhysicalMemoryEx(
                    MemoryRegion::Title,
                    size,
                    PageProtection::READWRITE,
                    LOWEST_ADDRESS,
                    HIGHEST_ADDRESS,
                    ALIGNMENT,
                )
            };
            let Some(address) = NonNull::new(core::ptr::with_exposed_provenance_mut::<u8>(
                address as usize,
            )) else {
                // Stock also passes the null copies of modules without a
                // directory to MmFreePhysicalMemory.
                for table in &tables[..count] {
                    if let Some(copy) = table.copy {
                        // SAFETY: allocated above for an earlier table, and
                        // dropped with the tables.
                        unsafe { free_copy(copy) };
                    }
                }
                return None;
            };

            // SAFETY: the directory holds `size` bytes of an image on a list
            // whose lock is held; the new allocation holds `size` bytes that
            // nothing else uses.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::with_exposed_provenance::<u8>(directory as usize),
                    address.as_ptr(),
                    size as usize,
                )
            };
            table.size = size;
            table.copy = Some(address);
        }

        tables[count] = table;
        count += 1;
    }

    Some(count)
}

fn report_fatal(message: &core::ffi::CStr) {
    print(message, &[]);
    print(c"[LOP] Please try to free up disk space or memory\n", &[]);
    xboxkrnl::DbgBreakPoint();
}

/// Write the module snapshot, the header, and the function tables (stock
/// 0x91f8f5c0).
fn write_prologue() -> bool {
    for word in &HEADER.words()[ProfileHeader::CLEARED] {
        word.store(0, Ordering::Relaxed);
    }

    HEADER.unknown_004.store(0, Ordering::Relaxed);
    HEADER.write_errors.store(0, Ordering::Relaxed);
    HEADER
        .record_header_size
        .store((RECORD_HEADER_WORDS * 4) as u32, Ordering::Relaxed);
    HEADER.unknown_010.store(0, Ordering::Relaxed);

    for processor in 0..HARDWARE_THREAD_COUNT {
        HEADER.blocks[processor].store(BLOCKS.load(Ordering::Relaxed), Ordering::Relaxed);
        HEADER.smallest[processor].store(u32::MAX, Ordering::Relaxed);
    }

    // SAFETY: see `WriterPaths`.
    let paths = unsafe { &*WRITER_PATHS.0.get() };
    let time = FileTime::now().intervals();
    let capture = module_snapshot::CaptureFields {
        start_time: time,
        previous_flags: 0,
    };
    let Some(snapshot) =
        module_snapshot::build(&paths.executable[..paths.executable_length], capture)
    else {
        // Stock passes a stale register as the number.
        print(c"[LOP] Failed to create common header! %d\n", &[0]);
        return false;
    };

    let mut tables = [FunctionTable::default(); MODULE_CAPACITY];

    // Sampling has not started: `start` sets `SAMPLING_ACTIVE` after the
    // prologue, so no processor counts.
    if !write(word_bytes(snapshot.words()), None) || !HEADER.write(None) {
        module_snapshot::free(snapshot);
        report_fatal(c"[LOP] Fatal error. Error writing file header!\n");
        return false;
    }

    // Stock keeps the snapshot when the copies fail.
    if copy_function_tables(&mut tables).is_none() {
        report_fatal(c"[LOP] Fatal error. Could not allocate memory for function table data!\n");
        return false;
    }

    // Tables past the copied ones are zero and fail the base check.
    let complete = tables
        .iter()
        .zip(snapshot.module_bases())
        .all(|(table, base)| {
            let record = [
                table.base.to_be(),
                table.image_size.to_be(),
                table.size.to_be(),
            ];
            base == table.base
                && write(word_bytes(&record), None)
                && (table.size == 0 || {
                    // SAFETY: `copy_function_tables` sets a nonzero size only
                    // with a copy of that many bytes, freed only below.
                    let (copy, bytes) = unsafe {
                        let copy = table.copy.unwrap_unchecked();
                        (
                            copy,
                            core::slice::from_raw_parts(copy.as_ptr(), table.size as usize),
                        )
                    };
                    let written = write(bytes, None);
                    if written {
                        // SAFETY: the copy is from `copy_function_tables` and
                        // is not used after it was written.
                        unsafe { free_copy(copy) };
                    }
                    written
                })
        });
    module_snapshot::free(snapshot);
    if !complete {
        report_fatal(c"[LOP] Fatal error. Error writing file header!\n");
        return false;
    }

    true
}

/// Move the full blocks of every sampled processor to the file; while
/// stopping, also the partly filled ones (stock 0x91f8f8b8, 0x91f8f4c8).
fn write_blocks() {
    let staging = STAGING.load(Ordering::Relaxed);
    for (processor, blocks) in THREADS.iter().enumerate() {
        if !sampled(processor) {
            continue;
        }

        // SAFETY: the staging area holds `BLOCKS` blocks of the sample
        // buffer, which stays allocated while the writer runs, and only the
        // writer uses it. A processor's lists link its `BLOCKS` assigned
        // blocks, each popped once per drain, and a block the first drain
        // copies is zeroed, so the second one, run after sampling stopped,
        // skips it: both together copy at most `BLOCKS` blocks.
        let mut end = unsafe { blocks.drain(&blocks.full, &blocks.free, staging) };
        if blocks.state.load(Ordering::Acquire) != ProfilerState::Active {
            // SAFETY: as above.
            end = unsafe { blocks.drain(&blocks.free, &blocks.free, end) };
        }

        if end == staging {
            continue;
        }

        // SAFETY: `drain` filled the blocks from `staging` to `end`.
        let filled = unsafe {
            core::slice::from_raw_parts(staging.cast::<u8>(), end.addr() - staging.addr())
        };
        if !write(filled, None) {
            HEADER.write_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Writer thread (stock 0x91f8fa68). When the file cannot be opened or the
/// prologue fails, stock returns without signaling its starter, which then
/// waits forever; here the starter learns of the failure.
extern "C" fn writer_thread(_context: u32) -> u32 {
    const POLL_INTERVAL_MS: u32 = 250;

    /// System time intervals (100 ns) per second.
    const FILETIME_PER_SECOND: u64 = 10_000_000;

    // SAFETY: see `WriterPaths`.
    let paths = unsafe { &*WRITER_PATHS.0.get() };
    let request = CreateRequest {
        access: AccessMask::GENERIC_WRITE.union(AccessMask::SYNCHRONIZE),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::READ,
        disposition: CreateDisposition::OverwriteIf,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    };
    let handle = match filesystem::create_file(&paths.file[..paths.file_length], &request) {
        Ok(handle) => handle,
        Err(error) => {
            print(
                c"[LOP] Error! %d\n",
                &[u64::from(Win32ErrorCode::from(dos_error(error)).0)],
            );
            return fail_writer();
        }
    };

    FILE.store(handle.0, Ordering::Relaxed);
    if !write_prologue() {
        // Stock passes a stale register as the number.
        print(c"[LOP] Error! %d\n", &[0]);
        // SAFETY: `handle` was opened above and is closed once.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) };
        return fail_writer();
    }

    WRITER_STARTED.set();

    let last = &THREADS[last_processor()];
    while last.state.load(Ordering::Acquire) != ProfilerState::Stopping {
        sleep(Duration::from_millis(u64::from(POLL_INTERVAL_MS)));
        write_blocks();
    }

    while THREADS.iter().enumerate().any(|(processor, blocks)| {
        sampled(processor) && blocks.state.load(Ordering::Acquire) != ProfilerState::Stopping
    }) {}

    write_blocks();

    let seconds = Timebase::now().ticks().wrapping_sub(START_TIMEBASE.load())
        / kernel::performance_frequency();
    HEADER
        .end_time
        .store(seconds * FILETIME_PER_SECOND + HEADER.start_time.load());

    // `stop` clears `SAMPLING_ACTIVE` and disables the profile interrupt
    // before it stops the writer, so no processor counts.
    if !HEADER.write(Some(u64::from(module_snapshot::SIZE))) {
        report_fatal(c"[LOP] Fatal error. Error updating header file!\n");
    }

    // SAFETY: `handle` was opened above and is closed once.
    if !unsafe { xboxkrnl::NtClose(Handle::from_raw(handle.0)) }.is_success() {
        print(c"[LOP] Close handle failed!\n", &[]);
    }

    WRITER_FINISHED.set();
    0
}

// Kernel entry of `writer_thread`, preserving the full nonvolatile
// registers.
crate::exports::bridged!(writer_thread_entry, writer_thread);

fn fail_writer() -> u32 {
    WRITER_FAILED.store(true, Ordering::Release);
    WRITER_STARTED.set();
    WRITER_FINISHED.set();
    0
}

/// Start the writer and wait until it has written the prologue (stock
/// 0x91f8fcc0). The thread handle stays open, as in stock.
pub(super) fn start_writer() -> bool {
    const WRITER_STACK: u32 = 0x8000;
    /// `ExCreateThread` flags of the writer before its processor is added.
    const WRITER_FLAGS: ThreadCreationFlags = ThreadCreationFlags::SYSTEM_PROCESS
        .union(ThreadCreationFlags::PRIORITY_CLASS_13)
        .union(ThreadCreationFlags::RETURN_THREAD_OBJECT)
        .union(ThreadCreationFlags::NOT_DEBUGGABLE);

    for (processor, blocks) in THREADS.iter().enumerate() {
        if sampled(processor) {
            blocks.state.store(ProfilerState::Active, Ordering::Release);
        }
    }

    WRITER_STARTED.reset();
    WRITER_FINISHED.reset();
    WRITER_FAILED.store(false, Ordering::Relaxed);

    let writer_processor = ProfilerFlags(FLAGS.load(Ordering::Relaxed)).writer_processor();
    // Not `ThreadCreationFlags::processors`: the 3-bit field also selects
    // processors 6 and 7, whose bits stock passes on.
    let affinity = ThreadCreationFlags::from_bits_retain(
        ThreadCreationFlags::PROCESSOR0.bits() << writer_processor,
    );
    let mut handle = 0u32;
    // SAFETY: `handle` is a live u32; the writer takes no context and reads
    // only static state.
    let created = unsafe {
        xboxkrnl::ExCreateThread(
            &mut handle,
            WRITER_STACK,
            core::ptr::null_mut(),
            0,
            writer_thread_entry as *const () as usize as u32,
            0,
            WRITER_FLAGS.union(affinity),
        )
    };
    if !created.is_success() {
        return false;
    }

    if !WRITER_STARTED.wait() {
        print(c"[LOP] Wait for poll thread initialize failed\n", &[]);
    }

    !WRITER_FAILED.load(Ordering::Acquire)
}

/// Make the writer flush everything and wait for it (stock 0x91f8fc00).
pub(super) fn stop_writer() {
    for (processor, blocks) in THREADS.iter().enumerate() {
        if sampled(processor) {
            blocks
                .state
                .store(ProfilerState::Stopping, Ordering::Release);
        }
    }

    if !WRITER_FINISHED.wait() {
        print(c"[LOP] Wait for poll thread shutdown failed\n", &[]);
    }

    for (processor, blocks) in THREADS.iter().enumerate() {
        if sampled(processor) {
            // SAFETY: the writer has finished, and no processor samples:
            // `stop` disables the profile interrupt first, and a failed
            // `start` never sets `SAMPLING_ACTIVE`. A failed wait (only
            // possible on a kernel error, as in stock) leaves the writer
            // unsynchronized.
            unsafe { blocks.reset() };
        }
    }
}

/// Object path of the capture file, for the writer to open.
pub(super) fn store_file_path(path: &[u8]) {
    // SAFETY: see `WriterPaths`; no writer runs.
    let paths = unsafe { &mut *WRITER_PATHS.0.get() };
    let length = path.len().min(paths.file.len());
    paths.file[..length].copy_from_slice(&path[..length]);
    paths.file_length = length;
}

/// Executable drive path of the module snapshot (stock 0x91f33c38, which
/// export 131 runs on the writer thread; here the starter prepares it).
pub(super) fn store_executable_path(executable: &[u8]) {
    // SAFETY: see `WriterPaths`; no writer runs.
    let paths = unsafe { &mut *WRITER_PATHS.0.get() };
    let length = executable.len().min(paths.executable.len());
    paths.executable[..length].copy_from_slice(&executable[..length]);
    paths.executable_length = length;
}
