//! Counter objects in `\DmCounters`: the object type, registration (stock
//! export 33, 0x91f2a8b0), the built-in counters (0x91f2b110), and the
//! 100 ms sampler DPC (0x91f2af38).
//!
//! The sampler keeps ten buckets of objects, linked through the first two
//! words of each object; every tick samples the objects of one bucket and
//! moves each `period` buckets ahead.

use core::cell::UnsafeCell;
use core::ffi::CStr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands::performance::CounterEntry;
use openxbdm_server::commands::performance::CounterSample;
use openxbdm_server::commands::performance::counters;
use openxbdm_server::commands::performance::counters::CounterError;
use openxbdm_server::commands::performance::counters::CounterObject;
use openxbdm_server::commands::performance::counters::CounterQuery;
use openxbdm_server::commands::performance::counters::CounterRegistration;
use openxbdm_server::commands::performance::counters::Evaluation;
use openxbdm_server::reply::CommandError;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::time::TickCount;
use xbox360::time::sleep;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KeCancelTimer;
use xbox360_sys::xboxkrnl::KeInitializeDpc;
use xbox360_sys::xboxkrnl::KeInitializeTimerEx;
use xbox360_sys::xboxkrnl::KeRemoveQueueDpc;
use xbox360_sys::xboxkrnl::KeSetTimerEx;
use xbox360_sys::xboxkrnl::MmQueryStatistics;
use xbox360_sys::xboxkrnl::NtOpenDirectoryObject;
use xbox360_sys::xboxkrnl::ObCreateObject;
use xbox360_sys::xboxkrnl::ObInsertObject;
use xbox360_sys::xboxkrnl::ObMakeTemporaryObject;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::TimerType;

use crate::exports::bridged;
use crate::exports::export;
use crate::exports::export_result;
use crate::kernel;

const COUNTER_DIRECTORY: &[u8] = b"\\DmCounters";
/// IRQL that excludes the sampler and the clock.
const SAMPLER_IRQL: Irql = Irql::new(0x7c);
const BUCKETS: usize = counters::MAX_PERIOD as usize;
/// Registration flag: the source is a query routine.
const HAS_HANDLER: u32 = 0x10_0000;
const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001a;
/// Directory query buffer of the monitor.
const DIRECTORY_BUFFER: usize = 0x10c;
/// Kernel export ordinals of the pool routines the object type uses.
const EX_ALLOCATE_POOL_TYPE_WITH_TAG: Ordinal = Ordinal::new(11).unwrap();
const EX_FREE_POOL: Ordinal = Ordinal::new(15).unwrap();
/// Lengths of the debug-adjusted memory statistics of
/// `ExDebugMonitorService` 8 and of their reply.
const MEMORY_STATISTICS_LENGTH: u32 = 0x68;
const MEMORY_STATISTICS_REPLY_LENGTH: u32 = 0x90;
/// Length word of the monitor's memory statistics block.
pub(crate) const MONITOR_STATISTICS_LENGTH: u32 = 0x30;
/// Processor blocks the thread counters cover.
const PROCESSORS: usize = 6;

/// A failed counter registration (stock export 33).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegisterError {
    /// The process has no counter directory.
    NoDirectory,
    /// The sampling period exceeds [`counters::MAX_PERIOD`].
    PeriodTooLong,
    Kernel(KernelError),
}

impl From<RegisterError> for Hresult {
    fn from(error: RegisterError) -> Self {
        match error {
            RegisterError::NoDirectory => Hresult::OUT_OF_MEMORY,
            RegisterError::PeriodTooLong => CounterError::TypeInvalid.into(),
            RegisterError::Kernel(error) => {
                CommandError::from_kernel(error, CommandError::Fail).into()
            }
        }
    }
}

/// A failed memory statistics query (stock export 75).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatisticsError {
    /// The block's length word is not [`MONITOR_STATISTICS_LENGTH`].
    BadLength,
    Kernel(KernelError),
}

impl From<StatisticsError> for Hresult {
    fn from(error: StatisticsError) -> Self {
        match error {
            StatisticsError::BadLength => Hresult::INVALID_ARGUMENT,
            StatisticsError::Kernel(error) => error.into(),
        }
    }
}

/// Registration words of the built-in counters.
const FRAMES: u32 = 0x1_0011;
const FRAME_TICKS: u32 = 0x1_0001;
const PERCENT: u32 = 0x2_0021;
const PAGES: u32 = 0x2_0001;

fn failed(status: u32) -> bool {
    (status as i32) < 0
}

fn read(address: u32) -> u32 {
    // SAFETY: callers pass addresses of live kernel objects, list heads, or
    // processor blocks.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn write(address: u32, value: u32) {
    // SAFETY: as in `read`.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

/// Console object type descriptor.
#[repr(C)]
struct ObjectType {
    allocate: AtomicU32,
    free: AtomicU32,
    close: AtomicU32,
    delete: AtomicU32,
    parse: AtomicU32,
    default_object: AtomicU32,
    pool_tag: AtomicU32,
}

static COUNTER_TYPE: ObjectType = ObjectType {
    allocate: AtomicU32::new(0),
    free: AtomicU32::new(0),
    close: AtomicU32::new(0),
    delete: AtomicU32::new(0),
    parse: AtomicU32::new(0),
    default_object: AtomicU32::new(0),
    pool_tag: AtomicU32::new(u32::from_be_bytes(*b"cpmd")),
};

/// Wait target of counter objects (stock 0x91fadda0): a signaled
/// synchronization event (type byte 1), so the first wait on any counter
/// consumes the signal and later waits block.
static DEFAULT_OBJECT: [AtomicU32; 4] = [
    AtomicU32::new(0x0100_0000),
    AtomicU32::new(1),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

fn counter_type() -> u32 {
    core::ptr::from_ref(&COUNTER_TYPE) as u32
}

/// Directory handles per process type; a handle is never 0.
static SYSTEM_DIRECTORY: AtomicU32 = AtomicU32::new(0);
static TITLE_DIRECTORY: AtomicU32 = AtomicU32::new(0);
/// The module is unloading: no directory is created or opened again.
static CLOSED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The counter directory of the calling process (stock 0x91f2a7a8): the
/// system process creates it, a title opens it. Handles are kept.
pub(super) fn directory() -> Option<u32> {
    if CLOSED.load(Ordering::Acquire) {
        return None;
    }
    let (slot, system) = match xboxkrnl::KeGetCurrentProcessType() {
        ProcessType::SYSTEM => (&SYSTEM_DIRECTORY, true),
        ProcessType::TITLE => (&TITLE_DIRECTORY, false),
        _ => return None,
    };
    match slot.load(Ordering::Acquire) {
        0 => {}
        handle => return Some(handle),
    }
    let name = kernel::ansi_string(COUNTER_DIRECTORY);
    let attributes = ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: &name,
        attributes: ObjectAttributeFlags::PERMANENT,
    };
    let mut handle = 0u32;
    // SAFETY: `handle`, `attributes`, and the name it refers to are live
    // for the call.
    let status = unsafe {
        if system {
            xboxkrnl::NtCreateDirectoryObject((&raw mut handle).cast(), &attributes)
        } else {
            NtOpenDirectoryObject((&raw mut handle).cast(), &attributes)
        }
    };
    if failed(status.0) {
        kernel::debug_print(if system {
            c"Failed to create system counter object directory.\n"
        } else {
            c"Failed to create Title counter object directory.\n"
        });
        slot.store(0, Ordering::Release);
        return None;
    }
    slot.store(handle, Ordering::Release);
    Some(handle)
}

/// An open handle to a counter object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CounterHandle(u32);

impl CounterHandle {
    pub(super) fn close(self) {
        // SAFETY: the handle was opened by `open` and is closed once.
        unsafe { xboxkrnl::NtClose(Handle::from_raw(self.0)) };
    }
}

/// Open counter `name` (stock export 26, 0x91f2aa20).
pub(super) fn open(name: &[u8]) -> Result<CounterHandle, CounterError> {
    open_in(directory().ok_or(CounterError::NoDirectory)?, name)
}

fn open_in(directory: u32, name: &[u8]) -> Result<CounterHandle, CounterError> {
    let name = kernel::ansi_string(name);
    let attributes = ObjectAttributes {
        root_directory: Handle::from_raw(directory),
        object_name: &name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    let mut handle = 0u32;
    // SAFETY: `attributes`, the name it refers to, and `handle` are live;
    // the type is the registered counter object type.
    let status = unsafe {
        xboxkrnl::ObOpenObjectByName(&attributes, counter_type(), 0, (&raw mut handle).cast())
    };
    if failed(status.0) {
        return Err(CounterError::NotFound);
    }
    Ok(CounterHandle(handle))
}

/// Referenced counter object of an open handle.
pub(super) fn reference(handle: CounterHandle) -> Result<KernelCounter, KernelError> {
    let mut object = 0u32;
    // SAFETY: `object` is a live u32; the type is the registered counter
    // object type.
    let status = unsafe {
        xboxkrnl::ObReferenceObjectByHandle(Handle::from_raw(handle.0), counter_type(), &mut object)
    };
    status.result()?;
    Ok(KernelCounter::new(object))
}

/// Evaluate a referenced counter (stock export 27, 0x91f2aab0).
pub(super) fn query(
    counter: &mut KernelCounter,
    query: CounterQuery,
    out: &mut CounterSample,
) -> Result<Evaluation, CounterError> {
    counters::query(counter, query, out)
}

/// One directory entry after `context` (0 restarts), its name copied into
/// `name` (stock export 53, 0x91f2adf0).
pub(super) fn next(context: &mut u32, name: &mut [u8]) -> Result<CounterEntry, CounterError> {
    let directory = directory().ok_or(CounterError::End)?;
    let mut buffer = [0u32; DIRECTORY_BUFFER / 4];
    let restart = *context == 0;
    // SAFETY: `directory` is the open counter directory; `buffer` holds
    // DIRECTORY_BUFFER bytes and `context` is a live u32.
    let status = unsafe {
        xboxkrnl::NtQueryDirectoryObject(
            Handle::from_raw(directory),
            buffer.as_mut_ptr().cast(),
            DIRECTORY_BUFFER as u32,
            restart,
            context,
            core::ptr::null_mut(),
        )
    };
    status.result().map_err(|error| match error {
        KernelError::NoMoreEntries => CounterError::End,
        KernelError::BufferTooSmall => CounterError::NameTooLong,
        error => CounterError::Kernel(error),
    })?;
    // Stock copies the full entry name; the buffer holds at most 0x104
    // name bytes, which can run past the caller's name field.
    let length = ((buffer[0] >> 16) as usize).min(name.len() - 1);
    // SAFETY: the directory entry names a buffer of at least `length` bytes.
    let source = unsafe { core::slice::from_raw_parts(buffer[1] as usize as *const u8, length) };
    name[..length].copy_from_slice(source);
    name[length] = 0;
    let handle = open(&name[..length]).map_err(|_| CounterError::Unexpected)?;
    let entry = reference(handle).map(|counter| {
        let counter_type = counter.read_u32(8) as u16;
        counter.release();
        CounterEntry {
            name_len: length,
            counter_type,
        }
    });
    handle.close();
    entry.map_err(|_| CounterError::Unexpected)
}

/// A counter object in kernel memory, and the IRQL to return to while the
/// sampler is excluded.
pub(super) struct KernelCounter {
    object: u32,
    irql: Irql,
}

impl KernelCounter {
    fn new(object: u32) -> Self {
        Self {
            object,
            irql: Irql::PASSIVE,
        }
    }

    fn at<T>(&self, offset: i32) -> *mut T {
        (self.object as usize).wrapping_add_signed(offset as isize) as *mut T
    }

    fn source(&self) -> usize {
        // SAFETY: +0xc of a counter object holds its source pointer.
        unsafe { core::ptr::read_volatile(self.at::<u32>(0xc)) as usize }
    }

    /// Drop the reference taken by [`reference`].
    pub(super) fn release(self) {
        // SAFETY: `object` holds the reference taken by `reference`.
        unsafe { xboxkrnl::ObDereferenceObject(self.object) };
    }
}

impl CounterObject for KernelCounter {
    fn read_u32(&self, offset: i32) -> u32 {
        // SAFETY: offsets stay within the object and its header, as in the
        // monitor's own reads.
        unsafe { core::ptr::read_volatile(self.at(offset)) }
    }

    fn read_u64(&self, offset: i32) -> u64 {
        // SAFETY: as above.
        unsafe { core::ptr::read_volatile(self.at(offset)) }
    }

    fn write_u32(&mut self, offset: i32, value: u32) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(self.at(offset), value) }
    }

    fn write_u64(&mut self, offset: i32, value: u64) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(self.at(offset), value) }
    }

    fn source_u32(&self, offset: u32) -> u32 {
        // SAFETY: the registered source holds the counter's words.
        unsafe { core::ptr::read_volatile((self.source() + offset as usize) as *const u32) }
    }

    fn source_u64(&self, offset: u32) -> u64 {
        // SAFETY: as above.
        unsafe { core::ptr::read_volatile((self.source() + offset as usize) as *const u64) }
    }

    fn call_reader(&mut self, value: &mut u64, rate: Option<&mut u64>) -> Result<(), CounterError> {
        let rate = rate.map_or(0, |rate| rate as *mut u64 as usize as u32);
        // SAFETY: kind 1 counters register a reader taking (value, rate).
        let result = Hresult(unsafe {
            kernel::call_export(
                self.source() as u32,
                value as *mut u64 as usize as u32,
                rate,
                0,
                0,
            )
        });
        counters::routine_result(result).map(|_| ())
    }

    fn call_handler(
        &mut self,
        query: CounterQuery,
        out: &mut CounterSample,
    ) -> Result<Evaluation, CounterError> {
        let mut sample = [0u32; 6];
        sample[0] = (out.value >> 32) as u32;
        sample[1] = out.value as u32;
        sample[2] = (out.rate >> 32) as u32;
        sample[3] = out.rate as u32;
        sample[4] = out.sample_type;
        // SAFETY: handler counters register a routine taking (query,
        // object, sample).
        let result = Hresult(unsafe {
            kernel::call_export(
                self.source() as u32,
                query.0,
                self.object,
                sample.as_mut_ptr() as usize as u32,
                0,
            )
        });
        out.value = (u64::from(sample[0]) << 32) | u64::from(sample[1]);
        out.rate = (u64::from(sample[2]) << 32) | u64::from(sample[3]);
        out.sample_type = sample[4];
        counters::routine_result(result)
    }

    fn exclude_sampler(&mut self) {
        // SAFETY: `allow_sampler` restores the previous IRQL.
        self.irql = unsafe { xboxkrnl::KfRaiseIrql(SAMPLER_IRQL) };
    }

    fn allow_sampler(&mut self) {
        // SAFETY: returns to the IRQL saved by `exclude_sampler`.
        unsafe { xboxkrnl::KfLowerIrql(self.irql) };
    }
}

/// Block published at debug monitor data +0x20 (stock 0x91fade40): +0x00
/// size, +0x04 and +0x08 pointers to the title's capture control and
/// result dwords, +0x0c capture start and +0x10 capture stop entries for
/// titles, +0x18 and +0x1c pointers to the title's frame count and frame
/// ticks.
static TITLE_INTERFACE: [AtomicU32; 8] = [const { AtomicU32::new(0) }; 8];
const TITLE_INTERFACE_SIZE: u32 = 0x20;
const CAPTURE_CONTROL: usize = 1;
const CAPTURE_RESULT: usize = 2;
const CAPTURE_START: usize = 3;
const CAPTURE_STOP: usize = 4;
const FRAME_COUNT: usize = 6;
const FRAME_TICKS_COUNT: usize = 7;
/// Block published at debug monitor data +0x24 (stock 0x91fade30); the
/// monitor never reads or writes it.
static TITLE_RESERVED: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];

/// Store the capture entries titles call through the published block.
pub(super) fn set_capture_entries(start: u32, stop: u32) {
    TITLE_INTERFACE[CAPTURE_START].store(start, Ordering::Release);
    TITLE_INTERFACE[CAPTURE_STOP].store(stop, Ordering::Release);
}

/// Title capture dwords published through the block (stock 0x91fade44 and
/// 0x91fade48).
#[derive(Clone, Copy)]
pub(super) struct TitleCaptureRequest {
    pub(super) control: Option<u32>,
    pub(super) result: Option<u32>,
}

pub(super) fn title_capture_request() -> TitleCaptureRequest {
    let pointer = |index: usize| match TITLE_INTERFACE[index].load(Ordering::Acquire) {
        0 => None,
        address => Some(address),
    };
    TitleCaptureRequest {
        control: pointer(CAPTURE_CONTROL),
        result: pointer(CAPTURE_RESULT),
    }
}

/// The title's frame counter, when the title published one.
fn frame_number() -> u32 {
    match TITLE_INTERFACE[FRAME_COUNT].load(Ordering::Acquire) {
        0 => 0,
        pointer => read(pointer),
    }
}

/// Reader of `Frames` (stock 0x91f2a510).
extern "C" fn read_frames(value: *mut u32, _rate: *mut u32) -> u32 {
    let result = match TITLE_INTERFACE[FRAME_COUNT].load(Ordering::Acquire) {
        0 => Err(CounterError::DataNotAvailable),
        pointer => {
            write(value as usize as u32, 0);
            write(value as usize as u32 + 4, read(pointer));
            Ok(())
        }
    };
    export_result(result).0
}

/// Reader of `Frame Ticks` (stock 0x91f2a550).
extern "C" fn read_frame_ticks(value: *mut u32, _rate: *mut u32) -> u32 {
    let pointer = TITLE_INTERFACE[FRAME_TICKS_COUNT].load(Ordering::Acquire);
    if TITLE_INTERFACE[0].load(Ordering::Acquire) <= 0x1c || pointer == 0 {
        return export_result(Err(CounterError::DataNotAvailable)).0;
    }
    write(value as usize as u32, 0);
    write(value as usize as u32 + 4, read(pointer));
    Hresult::OK.0
}

/// Sources of the built-in counters (stock 0x91fae680): eight page
/// counts, then idle/DPC/ISR time and tick count pairs per processor.
#[repr(C)]
struct Sources {
    pages: [AtomicU32; 8],
    threads: [[AtomicU32; 6]; PROCESSORS],
}

static SOURCES: Sources = Sources {
    pages: [const { AtomicU32::new(0) }; 8],
    threads: [const { [const { AtomicU32::new(0) }; 6] }; PROCESSORS],
};

/// Sources of the GPU counters: value and rate words nothing updates.
static GPU_SOURCES: [[u32; 2]; 4] = [[0; 2]; 4];

const PAGE_COUNTERS: [&CStr; 8] = [
    c"Free Pages",
    c"Cache Pages",
    c"Image Pages",
    c"Pool Pages",
    c"Stack Pages",
    c"VM Pages",
    c"Contiguous Pages",
    c"Debugger Pages",
];
const THREAD_COUNTERS: [[&CStr; 3]; PROCESSORS] = [
    [c"%Thread0 Idle", c"%Thread0 DPC", c"%Thread0 ISR"],
    [c"%Thread1 Idle", c"%Thread1 DPC", c"%Thread1 ISR"],
    [c"%Thread2 Idle", c"%Thread2 DPC", c"%Thread2 ISR"],
    [c"%Thread3 Idle", c"%Thread3 DPC", c"%Thread3 ISR"],
    [c"%Thread4 Idle", c"%Thread4 DPC", c"%Thread4 ISR"],
    [c"%Thread5 Idle", c"%Thread5 DPC", c"%Thread5 ISR"],
];
const GPU_COUNTERS: [&CStr; 4] = [
    c"% GPU",
    c"% GPU Frontend",
    c"% GPU Backend",
    c"% GPU Swap Stall",
];

/// Output words of the monitor's memory statistics (stock export 75)
/// that feed the page counters, in counter order.
const PAGE_STATISTICS: [usize; 8] = [2, 9, 8, 6, 3, 7, 10, 11];

/// Kernel storage of the sampler.
#[repr(C, align(8))]
struct KernelObject<const N: usize>(UnsafeCell<[u8; N]>);

impl<const N: usize> KernelObject<N> {
    fn as_ptr(&self) -> *mut u8 {
        self.0.get().cast()
    }
}

/// Sampler state; modified at `SAMPLER_IRQL` or in the sampler DPC, as stock.
struct Sampler {
    dpc: KernelObject<0x20>,
    timer: KernelObject<0x28>,
    /// List heads `{flink, blink}` of the buckets.
    buckets: UnsafeCell<[[u32; 2]; BUCKETS]>,
    current: UnsafeCell<u32>,
    /// Address of the kernel's processor block array.
    processor_blocks: AtomicU32,
    /// DPC bodies in progress, waited for at unload.
    active: AtomicU32,
}

// SAFETY: the kernel objects are used through kernel calls; the buckets and
// the current index are only touched at raised IRQL or in the DPC, as in
// stock.
unsafe impl Sync for Sampler {}

static SAMPLER: Sampler = Sampler {
    dpc: KernelObject(UnsafeCell::new([0; 0x20])),
    timer: KernelObject(UnsafeCell::new([0; 0x28])),
    buckets: UnsafeCell::new([[0; 2]; BUCKETS]),
    current: UnsafeCell::new(0),
    processor_blocks: AtomicU32::new(0),
    active: AtomicU32::new(0),
};

fn bucket_head(index: u32) -> u32 {
    SAMPLER.buckets.get() as usize as u32 + index * 8
}

fn current_bucket() -> u32 {
    // SAFETY: see `Sampler`.
    unsafe { *SAMPLER.current.get() }
}

/// Append `object` to the bucket `period` ticks ahead of the current one.
fn schedule(object: u32, period: u32) {
    let mut index = current_bucket() + period;
    if index >= BUCKETS as u32 {
        index -= BUCKETS as u32;
    }
    let head = bucket_head(index);
    let tail = read(head + 4);
    write(object, head);
    write(object + 4, tail);
    write(tail, object);
    write(head + 4, object);
}

/// Register counter `name` (stock export 33): `word` is the registration
/// word, `source` the data or routine it reads.
fn register(name: &[u8], word: u32, source: u32) -> Result<(), RegisterError> {
    let directory = directory().ok_or(RegisterError::NoDirectory)?;
    let period = CounterRegistration(word).period();
    if period > counters::MAX_PERIOD {
        return Err(RegisterError::PeriodTooLong);
    }
    let name = kernel::ansi_string(name);
    let attributes = ObjectAttributes {
        root_directory: Handle::from_raw(directory),
        object_name: &name,
        attributes: ObjectAttributeFlags::PERMANENT | ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    let mut object = 0u32;
    // SAFETY: `attributes`, the name it refers to, and `object` are live;
    // the type is the registered counter object type.
    let status = unsafe {
        ObCreateObject(
            counter_type(),
            &attributes,
            counters::OBJECT_SIZE as u32,
            &mut object,
        )
    };
    status.result().map_err(RegisterError::Kernel)?;
    // SAFETY: the object body holds OBJECT_SIZE bytes.
    unsafe { core::ptr::write_bytes(object as usize as *mut u8, 0, counters::OBJECT_SIZE) };
    let mut handle = 0u32;
    // SAFETY: `object` was created above; `attributes` and `handle` are live.
    let status = unsafe { ObInsertObject(object, &attributes, 0, (&raw mut handle).cast()) };
    status.result().map_err(RegisterError::Kernel)?;
    let mut counter = KernelCounter::new(object);
    counter.write_u32(0xc, source);
    counters::initialize(&mut counter, CounterRegistration(word));
    if period != 0 {
        // SAFETY: the IRQL is restored below.
        let irql = unsafe { xboxkrnl::KfRaiseIrql(SAMPLER_IRQL) };
        schedule(object, period);
        // SAFETY: returns to the IRQL raised from above.
        unsafe { xboxkrnl::KfLowerIrql(irql) };
    }
    // SAFETY: `handle` was opened by `ObInsertObject` and is closed once.
    unsafe { xboxkrnl::NtClose(Handle::from_raw(handle)) };
    Ok(())
}

/// Stock export 33: `(name, word, source) -> HRESULT`.
extern "C" fn register_counter(name: *const u8, word: u32, source: u32) -> u32 {
    if name.is_null() {
        // Stock tests the directory before the name.
        return match directory() {
            Some(_) => Hresult::INVALID_ARGUMENT.0,
            None => Hresult::from(RegisterError::NoDirectory).0,
        };
    }
    // SAFETY: the caller passes a NUL-terminated name.
    let name = unsafe { CStr::from_ptr(name.cast()) };
    export_result(register(name.to_bytes(), word, source)).0
}
export!(33, register_counter);

/// Stock export 26: `(name, handle out) -> HRESULT`.
extern "C" fn open_counter(name: *const u8, handle: *mut u32) -> u32 {
    let Some(directory) = directory() else {
        return export_result(Err(CounterError::NoDirectory)).0;
    };
    if name.is_null() {
        return export_result(Err(CounterError::NoDirectory)).0;
    }
    // SAFETY: the caller passes a NUL-terminated name.
    let name = kernel::ansi_string(unsafe { CStr::from_ptr(name.cast()) }.to_bytes());
    let attributes = ObjectAttributes {
        root_directory: Handle::from_raw(directory),
        object_name: &name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    // The kernel stores the handle through the caller's pointer.
    // SAFETY: `attributes` and the name it refers to are live; the caller
    // passes a writable handle dword.
    let status =
        unsafe { xboxkrnl::ObOpenObjectByName(&attributes, counter_type(), 0, handle.cast()) };
    let result = match status {
        status if failed(status.0) => Err(CounterError::NotFound),
        _ => Ok(()),
    };
    export_result(result).0
}
export!(26, open_counter);

/// Stock export 27: `(handle, query, sample) -> HRESULT`; the sample is
/// `{u64 value, u64 rate, u32 type}` and keeps the fields the query does
/// not produce.
extern "C" fn query_counter(handle: u32, query_type: u32, sample: *mut u32) -> u32 {
    if sample.is_null() {
        return Hresult::INVALID_ARGUMENT.0;
    }
    let mut counter = match reference(CounterHandle(handle)) {
        Ok(counter) => counter,
        Err(error) => return export_result(Err(CounterError::Kernel(error))).0,
    };
    let address = sample as usize as u32;
    let mut out = CounterSample {
        value: (u64::from(read(address)) << 32) | u64::from(read(address + 4)),
        rate: (u64::from(read(address + 8)) << 32) | u64::from(read(address + 0xc)),
        sample_type: read(address + 0x10),
    };
    let result = query(&mut counter, CounterQuery(query_type), &mut out);
    counter.release();
    write(address, (out.value >> 32) as u32);
    write(address + 4, out.value as u32);
    write(address + 8, (out.rate >> 32) as u32);
    write(address + 0xc, out.rate as u32);
    write(address + 0x10, out.sample_type);
    match result {
        Ok(evaluation) => Hresult::from(evaluation).0,
        Err(error) => Hresult::from(error).0,
    }
}
export!(27, query_counter);

/// Name bytes of a stock export 53 entry; the counter type follows them.
const ENTRY_NAME: usize = 0x100;

/// Stock export 53: `(context in/out, entry) -> HRESULT`; the entry is
/// `{char name[0x100], u32 type}`.
extern "C" fn walk_counters(context: *mut u32, entry: *mut u8) -> u32 {
    let directory = directory();
    if context.is_null() || entry.is_null() {
        return Hresult::INVALID_ARGUMENT.0;
    }
    if directory.is_none() {
        return export_result(Err(CounterError::End)).0;
    }
    // SAFETY: the caller passes a context dword and an entry of
    // ENTRY_NAME + 4 bytes.
    let (context, name) = unsafe {
        (
            &mut *context,
            core::slice::from_raw_parts_mut(entry, ENTRY_NAME),
        )
    };
    let result = next(context, name).map(|counter| {
        write(
            entry as usize as u32 + ENTRY_NAME as u32,
            u32::from(counter.counter_type),
        );
    });
    export_result(result).0
}
export!(53, walk_counters);

/// Fill the monitor's memory statistics block (stock export 75,
/// 0x91f331c8): `out[0]` is the length word and must be 0x30.
pub(crate) fn memory_statistics(out: &mut [u32; 12]) -> Result<(), StatisticsError> {
    if out[0] != MONITOR_STATISTICS_LENGTH {
        return Err(StatisticsError::BadLength);
    }
    let mut reply = [0u32; MEMORY_STATISTICS_REPLY_LENGTH as usize / 4];
    reply[0] = MEMORY_STATISTICS_REPLY_LENGTH;
    reply[1] = MEMORY_STATISTICS_LENGTH;
    let mut statistics = [0u32; MEMORY_STATISTICS_LENGTH as usize / 4];
    // SAFETY: `reply` is a live block whose first words give its length.
    let mut status = unsafe {
        xboxkrnl::ExDebugMonitorService(
            DebugMonitorService::MemoryStatistics,
            reply.as_mut_ptr() as usize as u32,
            0,
            0,
        )
    };
    let s: &[u32] = if !failed(status.0) && reply[0] >= MEMORY_STATISTICS_REPLY_LENGTH {
        &reply[1..]
    } else {
        statistics[0] = MEMORY_STATISTICS_LENGTH;
        // SAFETY: `statistics` is a live block of the `MmStatistics` size
        // with its length word set.
        status = unsafe { MmQueryStatistics(statistics.as_mut_ptr().cast()) };
        &statistics
    };
    status.result().map_err(StatisticsError::Kernel)?;
    out[1] = s[1];
    out[2] = s[0xe].wrapping_add(s[3]);
    out[3] = s[0x13].wrapping_add(s[8]);
    out[4] = s[0x17].wrapping_add(s[0xc]);
    out[5] = 0;
    out[6] = s[0x12].wrapping_add(s[7]);
    out[7] = s[0x16]
        .wrapping_add(s[0x15])
        .wrapping_add(s[0xb])
        .wrapping_add(s[0xa]);
    out[8] = s[0x14].wrapping_add(s[9]);
    out[9] = s[0x18].wrapping_add(s[0xd]);
    out[10] = s[0x11].wrapping_add(s[6]).wrapping_add(s[2]);
    out[11] = 0;
    Ok(())
}

/// Update the idle/DPC/ISR sources from the processor blocks.
fn sample_processors() {
    let blocks = SAMPLER.processor_blocks.load(Ordering::Relaxed);
    if blocks == 0 {
        return;
    }
    for (index, words) in SOURCES.threads.iter().enumerate() {
        let block = read(blocks + index as u32 * 4);
        if block == 0 {
            continue;
        }
        // SAFETY: the IRQL is restored before the loop body ends.
        let irql = unsafe { xboxkrnl::KfRaiseIrql(SAMPLER_IRQL) };
        let interrupt = read(block + 0x18);
        let dpc = read(block + 0x14);
        let idle = read(read(block + 8) + 0x58);
        let tick = TickCount::now().milliseconds();
        // SAFETY: returns to the IRQL raised from above.
        unsafe { xboxkrnl::KfLowerIrql(irql) };
        for (word, value) in words.iter().zip(&[idle, tick, dpc, tick, interrupt, tick]) {
            word.store(*value, Ordering::Relaxed);
        }
    }
}

fn sample_pages() {
    let mut statistics = [0u32; 12];
    statistics[0] = MONITOR_STATISTICS_LENGTH;
    // Stock copies its uninitialized stack block when the query fails;
    // zeros are copied instead.
    let _ = memory_statistics(&mut statistics);
    for (word, &index) in SOURCES.pages.iter().zip(&PAGE_STATISTICS) {
        word.store(statistics[index], Ordering::Relaxed);
    }
}

/// Sample the objects of the current bucket and advance (stock 0x91f2af38).
extern "C" fn sampler_dpc(_dpc: usize, _context: usize, _argument1: usize, _argument2: usize) {
    SAMPLER.active.fetch_add(1, Ordering::AcqRel);
    sample_processors();
    sample_pages();
    let current = current_bucket();
    let head = bucket_head(current);
    let mut entry = read(head);
    if entry != head {
        write(read(head + 4), 0);
        write(head, head);
        write(head + 4, head);
        while entry != 0 {
            let next = read(entry);
            let word = read(entry + 8);
            if word & HAS_HANDLER == 0 {
                // SAFETY: the IRQL is restored after the sample.
                let irql = unsafe { xboxkrnl::KfRaiseIrql(SAMPLER_IRQL) };
                let tick = TickCount::now().milliseconds();
                let frame = frame_number();
                counters::sample(&mut KernelCounter::new(entry), tick, frame);
                // SAFETY: returns to the IRQL raised from above.
                unsafe { xboxkrnl::KfLowerIrql(irql) };
            } else {
                // SAFETY: handler counters register a routine taking
                // (query, object, sample).
                unsafe { kernel::call_export(read(entry + 0xc), 0, entry, 0, 0) };
            }
            schedule(entry, word & 0xf);
            entry = next;
        }
    }
    // SAFETY: see `Sampler`.
    unsafe {
        *SAMPLER.current.get() = if current + 1 == BUCKETS as u32 {
            0
        } else {
            current + 1
        }
    };
    SAMPLER.active.fetch_sub(1, Ordering::AcqRel);
}
bridged!(sampler_dpc_entry, sampler_dpc);

fn register_c(name: &CStr, word: u32, source: u32) {
    let _ = register(name.to_bytes(), word, source);
}

/// Create the object type, the sampler, and the built-in counters (stock
/// 0x91f2b110).
pub(super) fn initialize() {
    if let Ok(module) = SystemModule::Kernel.handle() {
        if let (Ok(allocate), Ok(free)) = (
            resolve_export(module, EX_ALLOCATE_POOL_TYPE_WITH_TAG),
            resolve_export(module, EX_FREE_POOL),
        ) {
            COUNTER_TYPE
                .allocate
                .store(allocate.raw(), Ordering::Relaxed);
            COUNTER_TYPE.free.store(free.raw(), Ordering::Relaxed);
        }
    }
    let wait_list = DEFAULT_OBJECT[2].as_ptr() as usize as u32;
    DEFAULT_OBJECT[2].store(wait_list, Ordering::Relaxed);
    DEFAULT_OBJECT[3].store(wait_list, Ordering::Relaxed);
    COUNTER_TYPE
        .default_object
        .store(DEFAULT_OBJECT.as_ptr() as usize as u32, Ordering::Relaxed);

    TITLE_INTERFACE[0].store(TITLE_INTERFACE_SIZE, Ordering::Relaxed);
    let data = kernel::debug_monitor_data();
    data.title_interface
        .store(TITLE_INTERFACE.as_ptr() as usize as u32, Ordering::Release);
    data.title_reserved
        .store(TITLE_RESERVED.as_ptr() as usize as u32, Ordering::Release);
    SAMPLER.processor_blocks.store(
        data.processor_blocks.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );

    let directory = directory();
    for index in 0..BUCKETS as u32 {
        let head = bucket_head(index);
        write(head, head);
        write(head + 4, head);
    }
    // SAFETY: the static sampler storage is zeroed, sized for a KDPC and a
    // KTIMER, and stays in place until `shut_down` cancels both.
    unsafe {
        KeInitializeDpc(
            SAMPLER.dpc.as_ptr().cast(),
            sampler_dpc_entry as *const () as usize,
            0,
        );
        KeInitializeTimerEx(
            SAMPLER.timer.as_ptr().cast(),
            TimerType::Notification,
            ProcessType::SYSTEM,
        );
        // Due time -1: the first expiry is immediate, then every 100 ms.
        KeSetTimerEx(
            SAMPLER.timer.as_ptr().cast(),
            -1,
            counters::SAMPLER_INTERVAL_MS,
            SAMPLER.dpc.as_ptr().cast(),
        );
    }

    if directory.is_none() {
        return;
    }
    register_c(c"Frames", FRAMES, read_frames as *const () as usize as u32);
    register_c(
        c"Frame Ticks",
        FRAME_TICKS,
        read_frame_ticks as *const () as usize as u32,
    );
    for (names, words) in THREAD_COUNTERS.iter().zip(&SOURCES.threads) {
        for (name, pair) in names.iter().zip(words.chunks(2)) {
            register_c(name, PERCENT, pair.as_ptr() as usize as u32);
        }
    }
    for (name, word) in PAGE_COUNTERS.iter().zip(&SOURCES.pages) {
        register_c(name, PAGES, word.as_ptr() as usize as u32);
    }
    for (name, source) in GPU_COUNTERS.iter().zip(&GPU_SOURCES) {
        register_c(name, PERCENT, source.as_ptr() as usize as u32);
    }
}

/// Stop the sampler and retire the counter objects, whose type descriptor
/// and sources live in this image; stock never unloads, so this has no
/// stock counterpart. Counters still open by other modules keep their
/// handles but leave the directory.
pub(super) fn shut_down() {
    CLOSED.store(true, Ordering::Release);
    // SAFETY: the sampler timer and DPC were initialized by `initialize`.
    unsafe {
        KeCancelTimer(SAMPLER.timer.as_ptr().cast());
        KeRemoveQueueDpc(SAMPLER.dpc.as_ptr().cast());
    }
    // A DPC the kernel dequeued just before the cancel may not have entered
    // the sampler yet; it runs at dispatch level, so it starts well within
    // one period.
    sleep(Duration::from_millis(u64::from(
        counters::SAMPLER_INTERVAL_MS,
    )));
    while SAMPLER.active.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
    let directory = SYSTEM_DIRECTORY.swap(0, Ordering::AcqRel);
    if directory == 0 {
        return;
    }
    // Objects leave the directory as their last handle closes, which moves
    // the enumeration; passes repeat until one finds no fewer entries.
    let mut previous = usize::MAX;
    loop {
        let remaining = retire_counters(directory);
        if remaining >= previous {
            break;
        }
        previous = remaining;
    }
    let mut object = 0u32;
    // SAFETY: `directory` is the owned system directory handle and `object`
    // a live u32.
    let status =
        unsafe { xboxkrnl::ObReferenceObjectByHandle(Handle::from_raw(directory), 0, &mut object) };
    if !failed(status.0) {
        // SAFETY: `object` holds the reference taken above, released here.
        unsafe {
            ObMakeTemporaryObject(object);
            xboxkrnl::ObDereferenceObject(object);
        }
    }
    // SAFETY: the directory handle was taken out of SYSTEM_DIRECTORY and is
    // closed once.
    unsafe { xboxkrnl::NtClose(Handle::from_raw(directory)) };
}

/// Make every counter object of `directory` temporary; returns the number
/// of entries the pass saw.
fn retire_counters(directory: u32) -> usize {
    let mut context = 0u32;
    let mut seen = 0usize;
    loop {
        let mut buffer = [0u32; DIRECTORY_BUFFER / 4];
        let restart = context == 0;
        // SAFETY: `directory` is the open system directory; `buffer` holds
        // DIRECTORY_BUFFER bytes and `context` is a live u32.
        let status = unsafe {
            xboxkrnl::NtQueryDirectoryObject(
                Handle::from_raw(directory),
                buffer.as_mut_ptr().cast(),
                DIRECTORY_BUFFER as u32,
                restart,
                &mut context,
                core::ptr::null_mut(),
            )
        };
        if failed(status.0) || status.0 == STATUS_NO_MORE_ENTRIES {
            return seen;
        }
        seen += 1;
        let length = (buffer[0] >> 16) as usize;
        // SAFETY: the directory entry names a buffer of `length` bytes.
        let name = unsafe { core::slice::from_raw_parts(buffer[1] as usize as *const u8, length) };
        let Ok(handle) = open_in(directory, name) else {
            continue;
        };
        if let Ok(counter) = reference(handle) {
            // SAFETY: `counter` holds a reference to the object.
            unsafe { ObMakeTemporaryObject(counter.object) };
            counter.release();
        }
        handle.close();
    }
}

/// Forget the title's frame counters (stock 0x91f32398).
pub(super) fn title_terminated() {
    // SAFETY: the IRQL is restored below.
    let irql = unsafe { xboxkrnl::KfRaiseIrql(SAMPLER_IRQL) };
    TITLE_INTERFACE[FRAME_COUNT].store(0, Ordering::Release);
    TITLE_INTERFACE[FRAME_TICKS_COUNT].store(0, Ordering::Release);
    // SAFETY: returns to the IRQL raised from above.
    unsafe { xboxkrnl::KfLowerIrql(irql) };
}

/// Forget the title's directory handle, which closed with the title
/// process (stock 0x91f32418).
pub(super) fn title_ended() {
    TITLE_DIRECTORY.store(0, Ordering::Release);
}
