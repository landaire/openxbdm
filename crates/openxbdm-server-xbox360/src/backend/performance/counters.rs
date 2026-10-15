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

use openxbdm_core::status::Hresult;
use openxbdm_server::commands::performance::CounterSample;
use openxbdm_server::commands::performance::counters;
use openxbdm_server::commands::performance::counters::CounterObject;
use openxbdm_server::commands::performance::counters::CounterRegistration;

use crate::exports::bridged;
use crate::exports::export;
use crate::kernel;
use crate::kernel::AnsiString;
use crate::kernel::KeCancelTimer;
use crate::kernel::KeInitializeDpc;
use crate::kernel::KeInitializeTimerEx;
use crate::kernel::KeRemoveQueueDpc;
use crate::kernel::KeSetTimerEx;
use crate::kernel::MmQueryStatistics;
use crate::kernel::NtOpenDirectoryObject;
use crate::kernel::ObCreateObject;
use crate::kernel::ObInsertObject;
use crate::kernel::ObMakeTemporaryObject;
use crate::kernel::ObjectAttributes;

const COUNTER_DIRECTORY: &[u8] = b"\\DmCounters";
const OBJ_PERMANENT: u32 = 0x10;
/// `KeGetCurrentProcessType` values.
const SYSTEM_PROCESS: u32 = 2;
const TITLE_PROCESS: u32 = 1;
/// IRQL that excludes the sampler and the clock.
const SAMPLER_IRQL: u32 = 0x7c;
const BUCKETS: usize = counters::MAX_PERIOD as usize;
/// Registration flag: the source is a query routine.
const HAS_HANDLER: u32 = 0x10_0000;
const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001a;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xc000_0023;
/// Directory query buffer of the monitor.
const DIRECTORY_BUFFER: usize = 0x10c;
/// Kernel export ordinals of the pool routines the object type uses.
const EX_ALLOCATE_POOL_TYPE_WITH_TAG: u32 = 11;
const EX_FREE_POOL: u32 = 15;
/// `ExDebugMonitorService` 8: debug-adjusted memory statistics.
const DEBUG_MONITOR_MEMORY_STATISTICS: u32 = 8;
const MEMORY_STATISTICS_LENGTH: u32 = 0x68;
const MEMORY_STATISTICS_REPLY_LENGTH: u32 = 0x90;
/// Length word of the monitor's memory statistics block.
pub(crate) const MONITOR_STATISTICS_LENGTH: u32 = 0x30;
/// Processor blocks the thread counters cover.
const PROCESSORS: usize = 6;

const SUCCESS: Hresult = Hresult::OK;
const OUT_OF_MEMORY: Hresult = Hresult(0x8007_000e);
const INVALID_ARGUMENT: Hresult = Hresult(0x8007_0057);
const OBJECT_NOT_FOUND: Hresult = Hresult::error(0x0e);
const NO_DIRECTORY: Hresult = Hresult::error(0x02);

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
    let (slot, system) = match kernel::KeGetCurrentProcessType() {
        SYSTEM_PROCESS => (&SYSTEM_DIRECTORY, true),
        TITLE_PROCESS => (&TITLE_DIRECTORY, false),
        _ => return None,
    };
    match slot.load(Ordering::Acquire) {
        0 => {}
        handle => return Some(handle),
    }
    let name = AnsiString::new(COUNTER_DIRECTORY);
    let attributes = ObjectAttributes {
        root_directory: 0,
        object_name: &name,
        attributes: OBJ_PERMANENT,
    };
    let mut handle = 0u32;
    let status = if system {
        kernel::NtCreateDirectoryObject(&mut handle, &attributes)
    } else {
        NtOpenDirectoryObject(&mut handle, &attributes)
    };
    if failed(status) {
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

/// Open counter `name` (stock export 26, 0x91f2aa20).
pub(super) fn open(name: &[u8]) -> Result<u32, Hresult> {
    open_in(directory().ok_or(NO_DIRECTORY)?, name)
}

fn open_in(directory: u32, name: &[u8]) -> Result<u32, Hresult> {
    let name = AnsiString::new(name);
    let attributes = ObjectAttributes {
        root_directory: directory,
        object_name: &name,
        attributes: kernel::OBJ_CASE_INSENSITIVE,
    };
    let mut handle = 0u32;
    if failed(kernel::ObOpenObjectByName(
        &attributes,
        counter_type(),
        0,
        &mut handle,
    )) {
        return Err(OBJECT_NOT_FOUND);
    }
    Ok(handle)
}

/// Referenced counter object of an open handle.
pub(super) fn reference(handle: u32) -> Result<KernelCounter, u32> {
    let mut object = 0u32;
    match kernel::ObReferenceObjectByHandle(handle, counter_type(), &mut object) {
        status if failed(status) => Err(status),
        _ => Ok(KernelCounter::new(object)),
    }
}

/// Evaluate a referenced counter (stock export 27, 0x91f2aab0).
pub(super) fn query(counter: &mut KernelCounter, query: u32, out: &mut CounterSample) -> Hresult {
    counters::query(counter, query, out)
}

/// One directory entry after `context` (0 restarts): the name length
/// copied into `name` and the counter type (stock export 53, 0x91f2adf0).
pub(super) fn next(context: &mut u32, name: &mut [u8]) -> Result<(usize, u16), Hresult> {
    let directory = directory().ok_or(Hresult::END_OF_DATA)?;
    let mut buffer = [0u32; DIRECTORY_BUFFER / 4];
    let restart = u32::from(*context == 0);
    let status = kernel::NtQueryDirectoryObject(
        directory,
        buffer.as_mut_ptr().cast(),
        DIRECTORY_BUFFER as u32,
        restart,
        context,
        core::ptr::null_mut(),
    );
    match status {
        STATUS_NO_MORE_ENTRIES => return Err(Hresult::END_OF_DATA),
        STATUS_BUFFER_TOO_SMALL => return Err(Hresult::error(0x105)),
        status if failed(status) => {
            return Err(Hresult::from_nt_status(
                openxbdm_core::status::NtStatus(status),
                Hresult::FAIL,
            ));
        }
        _ => {}
    }
    // Stock copies the full entry name; the buffer holds at most 0x104
    // name bytes, which can run past the caller's name field.
    let length = ((buffer[0] >> 16) as usize).min(name.len() - 1);
    // SAFETY: the directory entry names a buffer of at least `length` bytes.
    let source = unsafe { core::slice::from_raw_parts(buffer[1] as usize as *const u8, length) };
    name[..length].copy_from_slice(source);
    name[length] = 0;
    let handle = open(&name[..length]).map_err(|_| Hresult::UNEXPECTED)?;
    let entry = reference(handle).map(|counter| {
        let counter_type = counter.read_u32(8) as u16;
        counter.release();
        (length, counter_type)
    });
    kernel::NtClose(handle);
    entry.map_err(|_| Hresult::UNEXPECTED)
}

/// A counter object in kernel memory, and the IRQL to return to while the
/// sampler is excluded.
pub(super) struct KernelCounter {
    object: u32,
    irql: u32,
}

impl KernelCounter {
    fn new(object: u32) -> Self {
        Self { object, irql: 0 }
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
        kernel::ObDereferenceObject(self.object);
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

    fn call_reader(&mut self, value: &mut u64, rate: Option<&mut u64>) -> Hresult {
        let rate = rate.map_or(0, |rate| rate as *mut u64 as usize as u32);
        // SAFETY: kind 1 counters register a reader taking (value, rate).
        Hresult(unsafe {
            kernel::call_export(
                self.source() as u32,
                value as *mut u64 as usize as u32,
                rate,
                0,
                0,
            )
        })
    }

    fn call_handler(&mut self, query: u32, out: &mut CounterSample) -> Hresult {
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
                query,
                self.object,
                sample.as_mut_ptr() as usize as u32,
                0,
            )
        });
        out.value = (u64::from(sample[0]) << 32) | u64::from(sample[1]);
        out.rate = (u64::from(sample[2]) << 32) | u64::from(sample[3]);
        out.sample_type = sample[4];
        result
    }

    fn exclude_sampler(&mut self) {
        self.irql = kernel::KfRaiseIrql(SAMPLER_IRQL);
    }

    fn allow_sampler(&mut self) {
        kernel::KfLowerIrql(self.irql);
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
    match TITLE_INTERFACE[FRAME_COUNT].load(Ordering::Acquire) {
        0 => counters::DATA_NOT_AVAILABLE.0,
        pointer => {
            write(value as usize as u32, 0);
            write(value as usize as u32 + 4, read(pointer));
            SUCCESS.0
        }
    }
}

/// Reader of `Frame Ticks` (stock 0x91f2a550).
extern "C" fn read_frame_ticks(value: *mut u32, _rate: *mut u32) -> u32 {
    let pointer = TITLE_INTERFACE[FRAME_TICKS_COUNT].load(Ordering::Acquire);
    if TITLE_INTERFACE[0].load(Ordering::Acquire) <= 0x1c || pointer == 0 {
        return counters::DATA_NOT_AVAILABLE.0;
    }
    write(value as usize as u32, 0);
    write(value as usize as u32 + 4, read(pointer));
    SUCCESS.0
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

/// `KeSetTimerEx(timer, due, period, dpc)`: the console takes the due time
/// in one 64-bit register; this joins the two halves the 32-bit ABI passes.
#[unsafe(naked)]
pub(super) extern "C" fn set_timer(
    timer: *mut u8,
    due_high: u32,
    due_low: u32,
    period: u32,
    dpc: *mut u8,
) -> u32 {
    core::arch::naked_asm!(
        // rldimi 5, 4, 32, 0: the high half into the upper word of r5.
        ".long 0x7885000e",
        "mr 4, 5",
        "mr 5, 6",
        "mr 6, 7",
        "b {set}",
        set = sym KeSetTimerEx,
    )
}

/// Register counter `name` (stock export 33): `word` is the registration
/// word, `source` the data or routine it reads.
fn register(name: &[u8], word: u32, source: u32) -> Hresult {
    let Some(directory) = directory() else {
        return OUT_OF_MEMORY;
    };
    let period = CounterRegistration(word).period();
    if period > counters::MAX_PERIOD {
        return counters::TYPE_INVALID;
    }
    let name = AnsiString::new(name);
    let attributes = ObjectAttributes {
        root_directory: directory,
        object_name: &name,
        attributes: OBJ_PERMANENT | kernel::OBJ_CASE_INSENSITIVE,
    };
    let mut object = 0u32;
    let status = ObCreateObject(
        counter_type(),
        &attributes,
        counters::OBJECT_SIZE as u32,
        &mut object,
    );
    if failed(status) {
        return Hresult::from_nt_status(openxbdm_core::status::NtStatus(status), Hresult::FAIL);
    }
    // SAFETY: the object body holds OBJECT_SIZE bytes.
    unsafe { core::ptr::write_bytes(object as usize as *mut u8, 0, counters::OBJECT_SIZE) };
    let mut handle = 0u32;
    let status = ObInsertObject(object, &attributes, 0, &mut handle);
    if failed(status) {
        return Hresult::from_nt_status(openxbdm_core::status::NtStatus(status), Hresult::FAIL);
    }
    let mut counter = KernelCounter::new(object);
    counter.write_u32(0xc, source);
    counters::initialize(&mut counter, CounterRegistration(word));
    if period != 0 {
        let irql = kernel::KfRaiseIrql(SAMPLER_IRQL);
        schedule(object, period);
        kernel::KfLowerIrql(irql);
    }
    kernel::NtClose(handle);
    SUCCESS
}

/// Stock export 33: `(name, word, source) -> HRESULT`.
extern "C" fn register_counter(name: *const u8, word: u32, source: u32) -> u32 {
    if name.is_null() {
        // Stock tests the directory before the name.
        return match directory() {
            Some(_) => INVALID_ARGUMENT.0,
            None => OUT_OF_MEMORY.0,
        };
    }
    // SAFETY: the caller passes a NUL-terminated name.
    let name = unsafe { CStr::from_ptr(name.cast()) };
    register(name.to_bytes(), word, source).0
}
export!(33, register_counter);

/// Stock export 26: `(name, handle out) -> HRESULT`.
extern "C" fn open_counter(name: *const u8, handle: *mut u32) -> u32 {
    let Some(directory) = directory() else {
        return NO_DIRECTORY.0;
    };
    if name.is_null() {
        return NO_DIRECTORY.0;
    }
    // SAFETY: the caller passes a NUL-terminated name.
    let name = AnsiString::new(unsafe { CStr::from_ptr(name.cast()) }.to_bytes());
    let attributes = ObjectAttributes {
        root_directory: directory,
        object_name: &name,
        attributes: kernel::OBJ_CASE_INSENSITIVE,
    };
    // The kernel stores the handle through the caller's pointer.
    match kernel::ObOpenObjectByName(&attributes, counter_type(), 0, handle) {
        status if failed(status) => OBJECT_NOT_FOUND.0,
        _ => SUCCESS.0,
    }
}
export!(26, open_counter);

/// Stock export 27: `(handle, query, sample) -> HRESULT`; the sample is
/// `{u64 value, u64 rate, u32 type}` and keeps the fields the query does
/// not produce.
extern "C" fn query_counter(handle: u32, query_type: u32, sample: *mut u32) -> u32 {
    if sample.is_null() {
        return INVALID_ARGUMENT.0;
    }
    let mut counter = match reference(handle) {
        Ok(counter) => counter,
        Err(status) => {
            return Hresult::from_nt_status(openxbdm_core::status::NtStatus(status), Hresult::FAIL)
                .0;
        }
    };
    let address = sample as usize as u32;
    let mut out = CounterSample {
        value: (u64::from(read(address)) << 32) | u64::from(read(address + 4)),
        rate: (u64::from(read(address + 8)) << 32) | u64::from(read(address + 0xc)),
        sample_type: read(address + 0x10),
    };
    let result = query(&mut counter, query_type, &mut out);
    counter.release();
    write(address, (out.value >> 32) as u32);
    write(address + 4, out.value as u32);
    write(address + 8, (out.rate >> 32) as u32);
    write(address + 0xc, out.rate as u32);
    write(address + 0x10, out.sample_type);
    result.0
}
export!(27, query_counter);

/// Name bytes of a stock export 53 entry; the counter type follows them.
const ENTRY_NAME: usize = 0x100;

/// Stock export 53: `(context in/out, entry) -> HRESULT`; the entry is
/// `{char name[0x100], u32 type}`.
extern "C" fn walk_counters(context: *mut u32, entry: *mut u8) -> u32 {
    let directory = directory();
    if context.is_null() || entry.is_null() {
        return INVALID_ARGUMENT.0;
    }
    if directory.is_none() {
        return Hresult::END_OF_DATA.0;
    }
    // SAFETY: the caller passes a context dword and an entry of
    // ENTRY_NAME + 4 bytes.
    let (context, name) = unsafe {
        (
            &mut *context,
            core::slice::from_raw_parts_mut(entry, ENTRY_NAME),
        )
    };
    match next(context, name) {
        Ok((_, counter_type)) => {
            write(
                entry as usize as u32 + ENTRY_NAME as u32,
                u32::from(counter_type),
            );
            SUCCESS.0
        }
        Err(result) => result.0,
    }
}
export!(53, walk_counters);

/// Fill the monitor's memory statistics block (stock export 75,
/// 0x91f331c8): `out[0]` is the length word and must be 0x30.
pub(crate) fn memory_statistics(out: &mut [u32; 12]) -> Hresult {
    if out[0] != MONITOR_STATISTICS_LENGTH {
        return INVALID_ARGUMENT;
    }
    let mut reply = [0u32; MEMORY_STATISTICS_REPLY_LENGTH as usize / 4];
    reply[0] = MEMORY_STATISTICS_REPLY_LENGTH;
    reply[1] = MEMORY_STATISTICS_LENGTH;
    let mut statistics = [0u32; MEMORY_STATISTICS_LENGTH as usize / 4];
    let mut status = kernel::ExDebugMonitorService(
        DEBUG_MONITOR_MEMORY_STATISTICS,
        reply.as_mut_ptr() as usize as u32,
        0,
        0,
    );
    let s: &[u32] = if !failed(status) && reply[0] >= MEMORY_STATISTICS_REPLY_LENGTH {
        &reply[1..]
    } else {
        statistics[0] = MEMORY_STATISTICS_LENGTH;
        status = MmQueryStatistics(statistics.as_mut_ptr());
        &statistics
    };
    if failed(status) {
        return Hresult(status | 0x1000_0000);
    }
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
    SUCCESS
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
        let irql = kernel::KfRaiseIrql(SAMPLER_IRQL);
        let interrupt = read(block + 0x18);
        let dpc = read(block + 0x14);
        let idle = read(read(block + 8) + 0x58);
        let tick = kernel::tick_count();
        kernel::KfLowerIrql(irql);
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
                let irql = kernel::KfRaiseIrql(SAMPLER_IRQL);
                let tick = kernel::tick_count();
                let frame = frame_number();
                counters::sample(&mut KernelCounter::new(entry), tick, frame);
                kernel::KfLowerIrql(irql);
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
    if let Ok(module) = kernel::module_handle(c"xboxkrnl.exe") {
        if let (Ok(allocate), Ok(free)) = (
            kernel::resolve_export(module, EX_ALLOCATE_POOL_TYPE_WITH_TAG),
            kernel::resolve_export(module, EX_FREE_POOL),
        ) {
            COUNTER_TYPE.allocate.store(allocate, Ordering::Relaxed);
            COUNTER_TYPE.free.store(free, Ordering::Relaxed);
        }
    }
    let wait_list = DEFAULT_OBJECT[2].as_ptr() as usize as u32;
    DEFAULT_OBJECT[2].store(wait_list, Ordering::Relaxed);
    DEFAULT_OBJECT[3].store(wait_list, Ordering::Relaxed);
    COUNTER_TYPE
        .default_object
        .store(DEFAULT_OBJECT.as_ptr() as usize as u32, Ordering::Relaxed);

    TITLE_INTERFACE[0].store(TITLE_INTERFACE_SIZE, Ordering::Relaxed);
    kernel::set_debug_monitor_word(0x20, TITLE_INTERFACE.as_ptr() as usize as u32);
    kernel::set_debug_monitor_word(0x24, TITLE_RESERVED.as_ptr() as usize as u32);
    SAMPLER.processor_blocks.store(
        kernel::debug_monitor_data().words[0x5c / 4],
        Ordering::Relaxed,
    );

    let directory = directory();
    for index in 0..BUCKETS as u32 {
        let head = bucket_head(index);
        write(head, head);
        write(head + 4, head);
    }
    KeInitializeDpc(
        SAMPLER.dpc.as_ptr(),
        sampler_dpc_entry as *const () as usize,
        0,
    );
    KeInitializeTimerEx(SAMPLER.timer.as_ptr(), 0);
    // Due time -1: the first expiry is immediate, then every 100 ms.
    set_timer(
        SAMPLER.timer.as_ptr(),
        u32::MAX,
        u32::MAX,
        counters::SAMPLER_INTERVAL_MS,
        SAMPLER.dpc.as_ptr(),
    );

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
    KeCancelTimer(SAMPLER.timer.as_ptr());
    KeRemoveQueueDpc(SAMPLER.dpc.as_ptr());
    // A DPC the kernel dequeued just before the cancel may not have entered
    // the sampler yet; it runs at dispatch level, so it starts well within
    // one period.
    kernel::sleep_milliseconds(counters::SAMPLER_INTERVAL_MS);
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
    if !failed(kernel::ObReferenceObjectByHandle(directory, 0, &mut object)) {
        ObMakeTemporaryObject(object);
        kernel::ObDereferenceObject(object);
    }
    kernel::NtClose(directory);
}

/// Make every counter object of `directory` temporary; returns the number
/// of entries the pass saw.
fn retire_counters(directory: u32) -> usize {
    let mut context = 0u32;
    let mut seen = 0usize;
    loop {
        let mut buffer = [0u32; DIRECTORY_BUFFER / 4];
        let restart = u32::from(context == 0);
        let status = kernel::NtQueryDirectoryObject(
            directory,
            buffer.as_mut_ptr().cast(),
            DIRECTORY_BUFFER as u32,
            restart,
            &mut context,
            core::ptr::null_mut(),
        );
        if failed(status) || status == STATUS_NO_MORE_ENTRIES {
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
            ObMakeTemporaryObject(counter.object);
            counter.release();
        }
        kernel::NtClose(handle);
    }
}

/// Forget the title's frame counters (stock 0x91f32398).
pub(super) fn title_terminated() {
    let irql = kernel::KfRaiseIrql(SAMPLER_IRQL);
    TITLE_INTERFACE[FRAME_COUNT].store(0, Ordering::Release);
    TITLE_INTERFACE[FRAME_TICKS_COUNT].store(0, Ordering::Release);
    kernel::KfLowerIrql(irql);
}

/// Forget the title's directory handle, which closed with the title
/// process (stock 0x91f32418).
pub(super) fn title_ended() {
    TITLE_DIRECTORY.store(0, Ordering::Release);
}
