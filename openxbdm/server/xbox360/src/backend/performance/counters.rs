//! Counter objects in `\DmCounters`: the object type, registration (stock
//! export 33, 0x91f2a8b0), the built-in counters (0x91f2b110), and the
//! 100 ms sampler DPC (0x91f2af38).
//!
//! The sampler keeps ten buckets of objects, linked through the first two
//! words of each object; every tick samples the objects of one bucket and
//! moves each `period` buckets ahead.

use core::ffi::CStr;
use core::mem::offset_of;
use core::sync::atomic::AtomicBool;
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
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360::time::TickCount;
use xbox360::time::sleep;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;
use xbox360_sys::processor::Kprcb;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::DebugMemoryStatistics;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::EventType;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::Kdpc;
use xbox360_sys::xboxkrnl::KeCancelTimer;
use xbox360_sys::xboxkrnl::KeInitializeDpc;
use xbox360_sys::xboxkrnl::KeInitializeTimerEx;
use xbox360_sys::xboxkrnl::KeRemoveQueueDpc;
use xbox360_sys::xboxkrnl::KeSetTimerEx;
use xbox360_sys::xboxkrnl::KernelU32;
use xbox360_sys::xboxkrnl::Ktimer;
use xbox360_sys::xboxkrnl::MmQueryStatistics;
use xbox360_sys::xboxkrnl::MmStatistics;
use xbox360_sys::xboxkrnl::NtOpenDirectoryObject;
use xbox360_sys::xboxkrnl::ObCreateObject;
use xbox360_sys::xboxkrnl::ObInsertObject;
use xbox360_sys::xboxkrnl::ObMakeTemporaryObject;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::ProcessType;
use xbox360_sys::xboxkrnl::TimerType;

use super::error::RegisterError;
use super::error::StatisticsError;
use super::load_pair;
use super::store_pair;
use crate::exports::bridged;
use crate::exports::export;
use crate::exports::export_result;
use crate::kernel;

/// IRQL that excludes the sampler and the clock.
const SAMPLER_IRQL: Irql = Irql::new(0x7c);
const BUCKETS: usize = counters::MAX_PERIOD as usize;
const HISTORY: usize = counters::HISTORY_LENGTH as usize;
/// Length word of the monitor's memory statistics block.
pub(crate) const MONITOR_STATISTICS_LENGTH: u32 = 0x30;

/// Words of the monitor's memory statistics block (stock export 75).
mod monitor_statistics {
    pub(super) const LENGTH: usize = 0;
    pub(super) const TOTAL_PAGES: usize = 1;
    pub(super) const FREE_PAGES: usize = 2;
    pub(super) const STACK_PAGES: usize = 3;
    pub(super) const PAGE_TABLE_PAGES: usize = 4;
    /// Stock stores 0.
    pub(super) const RESERVED: usize = 5;
    pub(super) const POOL_PAGES: usize = 6;
    pub(super) const VM_PAGES: usize = 7;
    pub(super) const IMAGE_PAGES: usize = 8;
    pub(super) const CACHE_PAGES: usize = 9;
    pub(super) const CONTIGUOUS_PAGES: usize = 10;
    /// Stock stores 0.
    pub(super) const DEBUGGER_PAGES: usize = 11;
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

static DEFAULT_OBJECT: DefaultObject = DefaultObject {
    _object_type: AtomicU32::new(EventType::Synchronization.raw() << 24),
    _signal_state: AtomicU32::new(1),
    wait_list: Link::new(),
};

/// Directory handles per process type; a handle is never 0.
static SYSTEM_DIRECTORY: AtomicU32 = AtomicU32::new(0);
static TITLE_DIRECTORY: AtomicU32 = AtomicU32::new(0);
/// The module is unloading: no directory is created or opened again.
static CLOSED: AtomicBool = AtomicBool::new(false);

static TITLE_INTERFACE: TitleInterface = TitleInterface {
    size: AtomicU32::new(0),
    capture_control: AtomicU32::new(0),
    capture_result: AtomicU32::new(0),
    capture_start: AtomicU32::new(0),
    capture_stop: AtomicU32::new(0),
    _reserved_14: AtomicU32::new(0),
    frame_count: AtomicU32::new(0),
    frame_ticks: AtomicU32::new(0),
};

/// Block published at debug monitor data +0x24 (stock 0x91fade30); the
/// monitor never reads or writes it.
static TITLE_RESERVED: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];

static SOURCES: Sources = Sources {
    pages: [const { AtomicU32::new(0) }; 8],
    threads: [const { [const { SourcePair::new() }; 3] }; HARDWARE_THREAD_COUNT],
};

/// Sources of the GPU counters: value and rate words nothing updates.
static GPU_SOURCES: [[u32; 2]; 4] = [[0; 2]; 4];

static SAMPLER: Sampler = Sampler {
    dpc: Kdpc::new(),
    timer: Ktimer::new(),
    buckets: [const { Link::new() }; BUCKETS],
    current: AtomicU32::new(0),
    processor_blocks: AtomicU32::new(0),
    active: AtomicU32::new(0),
};

xbox360_sys::flags! {
    /// Flag bits of a registration word.
    pub struct RegistrationFlags(u32) {
        /// The source is a query routine.
        HAS_HANDLER = 0x10_0000,
    }
}

/// Source kind of a registration word, in its high half.
#[derive(Clone, Copy)]
#[repr(u32)]
enum SourceKind {
    /// A reader routine taking (value, rate).
    Reader = 1,
    /// A u32 value followed by a u32 rate.
    Words = 2,
}

impl SourceKind {
    /// Registration word of a built-in counter of `class`, sampled every
    /// tick.
    const fn registration(self, class: CounterClass) -> CounterRegistration {
        const EVERY_TICK: u32 = 1;
        CounterRegistration(((self as u32) << 16) | class as u32 | EVERY_TICK)
    }
}

/// Class bits of a counter type.
#[derive(Clone, Copy)]
#[repr(u32)]
enum CounterClass {
    Value = 0,
    Rate = 0x10,
    Ratio = 0x20,
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

/// `{flink, blink}` link of a list the monitor keeps: a sampler bucket
/// head, the first two words of a counter body, or the wait list of
/// [`DEFAULT_OBJECT`]. Links hold addresses of links.
#[repr(C)]
struct Link {
    flink: AtomicU32,
    blink: AtomicU32,
}

impl Link {
    const fn new() -> Self {
        Self {
            flink: AtomicU32::new(0),
            blink: AtomicU32::new(0),
        }
    }

    fn address(&self) -> u32 {
        core::ptr::from_ref(self) as usize as u32
    }

    /// The link at `address`.
    ///
    /// # Safety
    ///
    /// `address` is a sampler bucket head or the link of a counter body
    /// listed in a bucket. Listed counters are permanent objects.
    unsafe fn at<'a>(address: u32) -> &'a Self {
        // SAFETY: per the contract.
        unsafe { crate::kernel::object_at::<Self>(address) }
    }
}

/// Wait target of counter objects (stock 0x91fadda0): the dispatcher
/// header of a signaled synchronization event, so the first wait on any
/// counter consumes the signal and later waits block.
#[repr(C)]
struct DefaultObject {
    /// Dispatcher object type in the high byte.
    _object_type: AtomicU32,
    _signal_state: AtomicU32,
    wait_list: Link,
}

const _: () = assert!(size_of::<DefaultObject>() == size_of::<xboxkrnl::Kevent>());

/// Body of a counter object, laid out as [`counters`] describes it.
#[repr(C)]
struct CounterBody {
    /// Sampler bucket links.
    link: Link,
    registration: AtomicU32,
    /// Source data or routine address.
    source: AtomicU32,
    /// Sample values (u64, high word first), rates, frame numbers, the
    /// history index, which [`counters`] addresses by offset.
    _values: [[AtomicU32; 2]; HISTORY],
    _rates: [AtomicU32; HISTORY],
    _frames: [AtomicU32; HISTORY],
    _index: AtomicU32,
    _reserved_c4: AtomicU32,
}

const _: () = {
    assert!(offset_of!(CounterBody, link) == 0);
    assert!(offset_of!(CounterBody, registration) == 0x08);
    assert!(offset_of!(CounterBody, source) == 0x0c);
    assert!(offset_of!(CounterBody, _values) == 0x10);
    assert!(offset_of!(CounterBody, _rates) == 0x68);
    assert!(offset_of!(CounterBody, _frames) == 0x94);
    assert!(offset_of!(CounterBody, _index) == 0xc0);
    assert!(size_of::<CounterBody>() == counters::OBJECT_SIZE);
};

/// `NtQueryDirectoryObject` buffer of the monitor: the counted entry name,
/// the object type, then the name bytes.
#[repr(C)]
struct DirectoryEntry {
    name_length: u16,
    _name_maximum_length: u16,
    /// Address of the name bytes, which the kernel stores in `_data`.
    name: u32,
    _object_type: u32,
    _data: [u8; 0x100],
}

const _: () = {
    assert!(offset_of!(DirectoryEntry, name_length) == 0);
    assert!(offset_of!(DirectoryEntry, name) == 4);
    assert!(size_of::<DirectoryEntry>() == 0x10c);
};

impl DirectoryEntry {
    const fn new() -> Self {
        Self {
            name_length: 0,
            _name_maximum_length: 0,
            name: 0,
            _object_type: 0,
            _data: [0; 0x100],
        }
    }

    /// Query the entry after `context` (0 restarts) of `directory`; the
    /// entry's name on success.
    #[inline(always)]
    fn query(&mut self, directory: u32, context: &mut u32) -> Result<&[u8], KernelError> {
        let restart = *context == 0;
        // SAFETY: `directory` is an open directory handle; `self` holds the
        // buffer length passed and `context` is a live u32.
        let status = unsafe {
            xboxkrnl::NtQueryDirectoryObject(
                Handle::from_raw(directory),
                core::ptr::from_mut(self).cast(),
                size_of::<Self>() as u32,
                restart,
                context,
                core::ptr::null_mut(),
            )
        };
        status.result()?;

        // SAFETY: on success the kernel has stored the name bytes in this
        // buffer, after the 0xc-byte header, and pointed `name` at them. An
        // entry whose name does not fit the 0x100 bytes after the header
        // fails the query with a buffer-too-small status, so `name_length`
        // bytes are in the buffer. The borrow of `self` keeps them in place.
        Ok(unsafe {
            core::slice::from_raw_parts(
                self.name as usize as *const u8,
                usize::from(self.name_length),
            )
        })
    }
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

/// A referenced counter object (see [`reference`]). The evaluation runs on
/// the private [`CounterView`], so code outside this module cannot reach
/// its offset accessors.
pub(super) struct KernelCounter(CounterView);

impl KernelCounter {
    /// Drop the reference taken by [`reference`].
    pub(super) fn release(self) {
        // SAFETY: the counter holds the reference taken by `reference`,
        // dropped once here.
        unsafe { xboxkrnl::ObDereferenceObject(self.0.object) };
    }
}

/// A counter object in kernel memory, and the IRQL to return to while the
/// sampler is excluded.
///
/// Counter bodies are written only by this module, by [`counters`], and by
/// the routines export 33 trusts with the object. Under that trust the
/// registration word keeps the period `register` checked, and the history
/// index stays in -1..=10 (`counters` writes only 0 and -1 to it). The
/// offsets `counters` derives from the index then stay within the object
/// header (0x10 bytes below the body) and the body; only `counters` and
/// this module call the offset accessors.
struct CounterView {
    /// Address of the body.
    object: u32,
    irql: Irql,
}

impl CounterView {
    /// # Safety
    ///
    /// `object` is the body of an object of [`COUNTER_TYPE`] that
    /// [`register`] initialized, and it stays allocated while the view is
    /// used.
    unsafe fn new(object: u32) -> Self {
        Self {
            object,
            irql: Irql::PASSIVE,
        }
    }

    fn body(&self) -> &CounterBody {
        // SAFETY: per `new`.
        unsafe { kernel::object_at(self.object) }
    }

    fn registration(&self) -> CounterRegistration {
        CounterRegistration(self.body().registration.load(Ordering::Relaxed))
    }

    fn source(&self) -> u32 {
        self.body().source.load(Ordering::Relaxed)
    }

    /// Words at `offset` bytes from the body.
    ///
    /// # Safety
    ///
    /// The words are within the object header or the body.
    unsafe fn words<const N: usize>(&self, offset: i32) -> &[AtomicU32; N] {
        let address = self.object.wrapping_add_signed(offset);
        // SAFETY: per the contract; the object stays allocated per `new`.
        unsafe { kernel::object_at(address) }
    }

    /// Words at `offset` of the registered source.
    ///
    /// # Safety
    ///
    /// `offset + 4 * N` is within the source. Export 33 trusts its caller,
    /// as it trusts registered routines: the source holds the words its
    /// source kind is read through (value and rate, or a copied sample of
    /// 0x14 bytes) and stays readable while the counter is registered.
    /// Nothing checks this, and code that rewrites the registration word
    /// later must keep the source to the new kind.
    unsafe fn source_words<const N: usize>(&self, offset: u32) -> &[AtomicU32; N] {
        let address = self.source().wrapping_add(offset);
        // SAFETY: per the contract.
        unsafe { kernel::object_at(address) }
    }
}

impl CounterObject for CounterView {
    unsafe fn read_u32(&self, offset: i32) -> u32 {
        // SAFETY: the caller keeps `offset` within the object header and the
        // body.
        let [word] = unsafe { self.words::<1>(offset) };
        word.load(Ordering::Relaxed)
    }

    // One address computation and forced inlining keep the callers in
    // `counters` small enough to be inlined themselves.
    #[inline(always)]
    unsafe fn read_u64(&self, offset: i32) -> u64 {
        // SAFETY: as in `read_u32`.
        load_pair(unsafe { self.words::<2>(offset) })
    }

    unsafe fn write_u32(&mut self, offset: i32, value: u32) {
        // SAFETY: the caller keeps `offset` within the body.
        let [word] = unsafe { self.words::<1>(offset) };
        word.store(value, Ordering::Relaxed);
    }

    unsafe fn write_u64(&mut self, offset: i32, value: u64) {
        // SAFETY: as in `write_u32`.
        store_pair(unsafe { self.words::<2>(offset) }, value);
    }

    unsafe fn source_u32(&self, offset: u32) -> u32 {
        // SAFETY: the caller reads the words of the source kind of the
        // registration word (see `source_words`).
        let [word] = unsafe { self.source_words::<1>(offset) };
        word.load(Ordering::Relaxed)
    }

    #[inline(always)]
    unsafe fn source_u64(&self, offset: u32) -> u64 {
        // SAFETY: as in `source_u32`.
        load_pair(unsafe { self.source_words::<2>(offset) })
    }

    unsafe fn call_reader(
        &mut self,
        value: &mut u64,
        rate: Option<&mut u64>,
    ) -> Result<(), CounterError> {
        let rate = rate.map_or(0, |rate| rate as *mut u64 as usize as u32);
        // SAFETY: the caller checked kind 1, whose counters register a
        // reader taking (value, rate).
        let result = Hresult(unsafe {
            kernel::call_export(self.source(), value as *mut u64 as usize as u32, rate, 0, 0)
        });

        counters::routine_result(result).map(|_| ())
    }

    unsafe fn call_handler(
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

        // SAFETY: the caller checked the handler flag; handler counters
        // register a routine taking (query, object, sample).
        let result = Hresult(unsafe {
            kernel::call_export(
                self.source(),
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

/// Block published at debug monitor data +0x20 (stock 0x91fade40). Titles
/// store the addresses of their dwords in it and call the capture entries.
#[repr(C)]
struct TitleInterface {
    /// Size of the block in bytes.
    size: AtomicU32,
    /// Address of the title's capture control dword, or 0.
    capture_control: AtomicU32,
    /// Address of the title's capture result dword, or 0.
    capture_result: AtomicU32,
    /// Capture start entry for titles.
    capture_start: AtomicU32,
    /// Capture stop entry for titles.
    capture_stop: AtomicU32,
    _reserved_14: AtomicU32,
    /// Address of the title's frame count dword, or 0.
    frame_count: AtomicU32,
    /// Address of the title's frame ticks dword, or 0.
    frame_ticks: AtomicU32,
}

const _: () = {
    assert!(offset_of!(TitleInterface, capture_control) == 0x04);
    assert!(offset_of!(TitleInterface, capture_result) == 0x08);
    assert!(offset_of!(TitleInterface, capture_start) == 0x0c);
    assert!(offset_of!(TitleInterface, capture_stop) == 0x10);
    assert!(offset_of!(TitleInterface, frame_count) == 0x18);
    assert!(offset_of!(TitleInterface, frame_ticks) == 0x1c);
    assert!(size_of::<TitleInterface>() == 0x20);
};

/// Title capture dwords published through the block (stock 0x91fade44 and
/// 0x91fade48).
#[derive(Clone, Copy)]
pub(super) struct TitleCaptureRequest {
    pub(super) control: Option<u32>,
    pub(super) result: Option<u32>,
}

/// Value and rate words of a kind 2 counter source.
#[repr(C)]
struct SourcePair {
    value: AtomicU32,
    rate: AtomicU32,
}

impl SourcePair {
    const fn new() -> Self {
        Self {
            value: AtomicU32::new(0),
            rate: AtomicU32::new(0),
        }
    }
}

/// Sources of the built-in counters (stock 0x91fae680): eight page
/// counts, then idle, DPC and ISR time with tick count per processor.
#[repr(C)]
struct Sources {
    pages: [AtomicU32; 8],
    threads: [[SourcePair; 3]; HARDWARE_THREAD_COUNT],
}

/// Sampler state; modified at `SAMPLER_IRQL` or in the sampler DPC, as stock.
struct Sampler {
    dpc: Kdpc,
    timer: Ktimer,
    /// Bucket list heads.
    buckets: [Link; BUCKETS],
    /// Bucket the next tick samples; only the sampler DPC changes it, and
    /// it stays below `BUCKETS`.
    current: AtomicU32,
    /// Address of the kernel's processor block array.
    processor_blocks: AtomicU32,
    /// DPC bodies in progress, waited for at unload.
    active: AtomicU32,
}

/// Sample of stock export 27: `{u64 value, u64 rate, u32 type}`, high words
/// first.
#[repr(C)]
struct SampleRecord {
    value: [AtomicU32; 2],
    rate: [AtomicU32; 2],
    sample_type: AtomicU32,
}

const _: () = {
    assert!(offset_of!(SampleRecord, rate) == 8);
    assert!(offset_of!(SampleRecord, sample_type) == 0x10);
};

impl SampleRecord {
    fn load(&self) -> CounterSample {
        CounterSample {
            value: load_pair(&self.value),
            rate: load_pair(&self.rate),
            sample_type: self.sample_type.load(Ordering::Relaxed),
        }
    }

    fn store(&self, sample: &CounterSample) {
        store_pair(&self.value, sample.value);
        store_pair(&self.rate, sample.rate);
        self.sample_type
            .store(sample.sample_type, Ordering::Relaxed);
    }
}

/// Entry of stock export 53: `{char name[0x100], u32 type}`.
#[repr(C)]
struct WalkEntry {
    name: [u8; 0x100],
    counter_type: u32,
}

const _: () = assert!(offset_of!(WalkEntry, counter_type) == 0x100);

fn counter_type() -> u32 {
    core::ptr::from_ref(&COUNTER_TYPE) as u32
}

/// The counter directory of the calling process (stock 0x91f2a7a8): the
/// system process creates it, a title opens it. Handles are kept.
pub(super) fn directory() -> Option<u32> {
    const COUNTER_DIRECTORY: &[u8] = b"\\DmCounters";

    if CLOSED.load(Ordering::Acquire) {
        return None;
    }

    let (slot, system) = match xboxkrnl::KeGetCurrentProcessType() {
        ProcessType::SYSTEM => (&SYSTEM_DIRECTORY, true),
        ProcessType::TITLE => (&TITLE_DIRECTORY, false),
        _ => return None,
    };
    let cached = slot.load(Ordering::Acquire);
    if cached != 0 {
        return Some(cached);
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

    if !status.is_success() {
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

    if !status.is_success() {
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

    // SAFETY: the kernel referenced an object of the counter type, which
    // only `register` creates; the reference keeps it allocated until
    // `KernelCounter::release`.
    Ok(KernelCounter(unsafe { CounterView::new(object) }))
}

/// Evaluate a referenced counter (stock export 27, 0x91f2aab0).
pub(super) fn query(
    counter: &mut KernelCounter,
    query: CounterQuery,
    out: &mut CounterSample,
) -> Result<Evaluation, CounterError> {
    // SAFETY: only `register` creates counter objects, and it initializes
    // each; only the sampler writes the history index after that.
    unsafe { counters::query(&mut counter.0, query, out) }
}

/// One directory entry after `context` (0 restarts), its name copied into
/// `name` (stock export 53, 0x91f2adf0).
pub(super) fn next(context: &mut u32, name: &mut [u8]) -> Result<CounterEntry, CounterError> {
    let directory = directory().ok_or(CounterError::End)?;
    let mut record = DirectoryEntry::new();
    let source = record
        .query(directory, context)
        .map_err(|error| match error {
            KernelError::NoMoreEntries => CounterError::End,
            KernelError::BufferTooSmall => CounterError::NameTooLong,
            error => CounterError::Kernel(error),
        })?;

    // Stock copies the full entry name; the query buffer holds at most
    // 0x100 name bytes, which can run past the caller's name field.
    let length = source.len().min(name.len() - 1);
    name[..length].copy_from_slice(&source[..length]);
    name[length] = 0;

    let handle = open(&name[..length]).map_err(|_| CounterError::Unexpected)?;
    let entry = reference(handle).map(|counter| {
        let counter_type = counter.0.registration().counter_type();
        counter.release();
        CounterEntry {
            name_len: length,
            counter_type,
        }
    });

    handle.close();

    entry.map_err(|_| CounterError::Unexpected)
}

/// Store the capture entries titles call through the published block.
pub(super) fn set_capture_entries(start: u32, stop: u32) {
    TITLE_INTERFACE
        .capture_start
        .store(start, Ordering::Release);
    TITLE_INTERFACE.capture_stop.store(stop, Ordering::Release);
}

pub(super) fn title_capture_request() -> TitleCaptureRequest {
    let pointer = |field: &AtomicU32| match field.load(Ordering::Acquire) {
        0 => None,
        address => Some(address),
    };

    TitleCaptureRequest {
        control: pointer(&TITLE_INTERFACE.capture_control),
        result: pointer(&TITLE_INTERFACE.capture_result),
    }
}

/// The title's frame counter, when the title published one.
fn frame_number() -> u32 {
    match TITLE_INTERFACE.frame_count.load(Ordering::Acquire) {
        0 => 0,
        // SAFETY: a title publishes the address of its frame count dword
        // and keeps it until `title_terminated` withdraws it.
        address => unsafe { kernel::object_at::<AtomicU32>(address) }.load(Ordering::Relaxed),
    }
}

/// Reader of `Frames` (stock 0x91f2a510).
extern "C" fn read_frames(value: *mut [AtomicU32; 2], _rate: *mut u32) -> Hresult {
    let result = match TITLE_INTERFACE.frame_count.load(Ordering::Acquire) {
        0 => Err(CounterError::DataNotAvailable),
        address => {
            // SAFETY: readers are called with the address of a u64
            // (`CounterView::call_reader` passes its own).
            let value = unsafe { &*value };
            value[0].store(0, Ordering::Relaxed);
            // SAFETY: as in `frame_number`.
            let count = unsafe { kernel::object_at::<AtomicU32>(address) };
            value[1].store(count.load(Ordering::Relaxed), Ordering::Relaxed);

            Ok(())
        }
    };

    export_result(result)
}

/// Reader of `Frame Ticks` (stock 0x91f2a550).
extern "C" fn read_frame_ticks(value: *mut [AtomicU32; 2], _rate: *mut u32) -> Hresult {
    let address = TITLE_INTERFACE.frame_ticks.load(Ordering::Acquire);
    // A block that ends before the frame ticks field has none.
    let size = TITLE_INTERFACE.size.load(Ordering::Acquire);
    if size <= offset_of!(TitleInterface, frame_ticks) as u32 || address == 0 {
        return export_result(Err(CounterError::DataNotAvailable));
    }

    // SAFETY: as in `read_frames`.
    let value = unsafe { &*value };
    value[0].store(0, Ordering::Relaxed);
    // SAFETY: a title publishes the address of its frame ticks dword and
    // keeps it until `title_terminated` withdraws it.
    let ticks = unsafe { kernel::object_at::<AtomicU32>(address) };
    value[1].store(ticks.load(Ordering::Relaxed), Ordering::Relaxed);

    Hresult::OK
}

/// Append `object` to the bucket `period` ticks ahead of the current one.
///
/// # Safety
///
/// `period` is at most `counters::MAX_PERIOD`.
unsafe fn schedule(object: &Link, period: u32) {
    let mut index = SAMPLER.current.load(Ordering::Relaxed) + period;
    if index >= BUCKETS as u32 {
        index -= BUCKETS as u32;
    }

    // SAFETY: `current` is below BUCKETS and `period` at most BUCKETS, so
    // the index is below BUCKETS.
    let head = unsafe { SAMPLER.buckets.get_unchecked(index as usize) };
    let tail = head.blink.load(Ordering::Relaxed);
    object.flink.store(head.address(), Ordering::Relaxed);
    object.blink.store(tail, Ordering::Relaxed);

    // SAFETY: the tail of a bucket is its head or a listed counter.
    unsafe { Link::at(tail) }
        .flink
        .store(object.address(), Ordering::Relaxed);
    head.blink.store(object.address(), Ordering::Relaxed);
}

/// Register counter `name` (stock export 33) with the source it reads.
fn register(
    name: &[u8],
    registration: CounterRegistration,
    source: u32,
) -> Result<(), RegisterError> {
    let directory = directory().ok_or(RegisterError::NoDirectory)?;

    let period = registration.period();
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
            size_of::<CounterBody>() as u32,
            &mut object,
        )
    };
    status.result().map_err(RegisterError::Kernel)?;

    // SAFETY: `ObCreateObject` returned a fresh body of `CounterBody` size,
    // word aligned, that nothing else uses before `ObInsertObject`; zero is
    // a valid `CounterBody`.
    unsafe { core::ptr::write_bytes(object as usize as *mut CounterBody, 0, 1) };

    let mut handle = 0u32;
    // SAFETY: `object` was created above; `attributes` and `handle` are live.
    let status = unsafe { ObInsertObject(object, &attributes, 0, (&raw mut handle).cast()) };
    status.result().map_err(RegisterError::Kernel)?;

    // SAFETY: `object` is the counter body initialized above; its permanent
    // directory entry keeps it allocated.
    let mut counter = unsafe { CounterView::new(object) };
    counter.body().source.store(source, Ordering::Relaxed);
    counters::initialize(&mut counter, registration);

    if period != 0 {
        // SAFETY: the IRQL is restored below.
        let irql = unsafe { xboxkrnl::KfRaiseIrql(SAMPLER_IRQL) };
        // SAFETY: `period` was checked above.
        unsafe { schedule(&counter.body().link, period) };
        // SAFETY: returns to the IRQL raised from above.
        unsafe { xboxkrnl::KfLowerIrql(irql) };
    }

    // SAFETY: `handle` was opened by `ObInsertObject` and is closed once.
    unsafe { xboxkrnl::NtClose(Handle::from_raw(handle)) };

    Ok(())
}

/// Stock export 33: `(name, word, source) -> HRESULT`.
extern "C" fn register_counter(name: *const u8, word: u32, source: u32) -> Hresult {
    if name.is_null() {
        // Stock tests the directory before the name.
        return match directory() {
            Some(_) => Hresult::INVALID_ARGUMENT,
            None => RegisterError::NoDirectory.into(),
        };
    }

    // SAFETY: the caller passes a NUL-terminated name.
    let name = unsafe { CStr::from_ptr(name.cast()) };

    export_result(register(name.to_bytes(), CounterRegistration(word), source))
}
export!(33, register_counter);

/// Stock export 26: `(name, handle out) -> HRESULT`.
extern "C" fn open_counter(name: *const u8, handle: *mut u32) -> Hresult {
    let Some(directory) = directory() else {
        return export_result(Err(CounterError::NoDirectory));
    };

    if name.is_null() {
        return export_result(Err(CounterError::NoDirectory));
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
    let result = if status.is_success() {
        Ok(())
    } else {
        Err(CounterError::NotFound)
    };

    export_result(result)
}
export!(26, open_counter);

/// Stock export 27: `(handle, query, sample) -> HRESULT`; the sample keeps
/// the fields the query does not produce.
extern "C" fn query_counter(handle: u32, query_type: u32, sample: *const SampleRecord) -> Hresult {
    if sample.is_null() {
        return Hresult::INVALID_ARGUMENT;
    }

    let mut counter = match reference(CounterHandle(handle)) {
        Ok(counter) => counter,
        Err(error) => return export_result(Err(CounterError::Kernel(error))),
    };

    // SAFETY: the caller passes a writable sample, live for the call.
    let record = unsafe { &*sample };
    let mut out = record.load();
    let result = query(&mut counter, CounterQuery(query_type), &mut out);
    counter.release();
    record.store(&out);

    match result {
        Ok(evaluation) => evaluation.into(),
        Err(error) => error.into(),
    }
}
export!(27, query_counter);

/// Stock export 53: `(context in/out, entry) -> HRESULT`.
extern "C" fn walk_counters(context: *mut u32, entry: *mut WalkEntry) -> Hresult {
    let directory = directory();
    if context.is_null() || entry.is_null() {
        return Hresult::INVALID_ARGUMENT;
    }

    if directory.is_none() {
        return export_result(Err(CounterError::End));
    }

    // SAFETY: the caller passes a context dword and an entry, both
    // writable and unaliased for the call.
    let (context, entry) = unsafe { (&mut *context, &mut *entry) };
    let result = next(context, &mut entry.name).map(|counter| {
        entry.counter_type = u32::from(counter.counter_type);
    });

    export_result(result)
}
export!(53, walk_counters);

/// Fill the monitor's memory statistics block (stock export 75,
/// 0x91f331c8): `out[0]` is the length word and must be 0x30.
pub(crate) fn memory_statistics(
    out: &mut [u32; MONITOR_STATISTICS_LENGTH as usize / 4],
) -> Result<(), StatisticsError> {
    use monitor_statistics::CACHE_PAGES;
    use monitor_statistics::CONTIGUOUS_PAGES;
    use monitor_statistics::DEBUGGER_PAGES;
    use monitor_statistics::FREE_PAGES;
    use monitor_statistics::IMAGE_PAGES;
    use monitor_statistics::LENGTH;
    use monitor_statistics::PAGE_TABLE_PAGES;
    use monitor_statistics::POOL_PAGES;
    use monitor_statistics::RESERVED;
    use monitor_statistics::STACK_PAGES;
    use monitor_statistics::TOTAL_PAGES;
    use monitor_statistics::VM_PAGES;

    if out[LENGTH] != MONITOR_STATISTICS_LENGTH {
        return Err(StatisticsError::BadLength);
    }

    let mut reply = DebugMemoryStatistics::new();
    let mut statistics: MmStatistics;
    // SAFETY: `reply` is a live block whose first words give its length.
    let mut status = unsafe {
        xboxkrnl::ExDebugMonitorService(
            DebugMonitorService::MemoryStatistics,
            (&raw mut reply) as usize as u32,
            0,
            0,
        )
    };

    let block = if status.is_success() && reply.is_complete() {
        &reply.statistics
    } else {
        statistics = MmStatistics::new();
        // SAFETY: `statistics` is live with its length set.
        status = unsafe { MmQueryStatistics(&mut statistics) };
        &statistics
    };
    status.result().map_err(StatisticsError::Kernel)?;

    let (title, system) = (&block.title, &block.system);
    out[TOTAL_PAGES] = block.total_physical_pages;
    out[FREE_PAGES] = system.available_pages.wrapping_add(title.available_pages);
    out[STACK_PAGES] = system.stack_pages.wrapping_add(title.stack_pages);
    out[PAGE_TABLE_PAGES] = system.page_table_pages.wrapping_add(title.page_table_pages);
    out[RESERVED] = 0;
    out[POOL_PAGES] = system.pool_pages.wrapping_add(title.pool_pages);
    out[VM_PAGES] = system
        .virtual_pages
        .wrapping_add(system.heap_pages)
        .wrapping_add(title.virtual_pages)
        .wrapping_add(title.heap_pages);
    out[IMAGE_PAGES] = system.image_pages.wrapping_add(title.image_pages);
    out[CACHE_PAGES] = system.cache_pages.wrapping_add(title.cache_pages);
    out[CONTIGUOUS_PAGES] = system
        .physical_pages
        .wrapping_add(title.physical_pages)
        .wrapping_add(block.kernel_pages);
    out[DEBUGGER_PAGES] = 0;

    Ok(())
}

/// Update the idle/DPC/ISR sources from the processor blocks.
fn sample_processors() {
    let blocks = SAMPLER.processor_blocks.load(Ordering::Relaxed);
    if blocks == 0 {
        return;
    }

    // SAFETY: the debug monitor data gives the kernel's processor block
    // array, one entry per hardware thread, which the kernel never frees.
    let blocks = unsafe { crate::kernel::object_at::<[KernelU32; HARDWARE_THREAD_COUNT]>(blocks) };

    for (block, sources) in blocks.iter().zip(&SOURCES.threads) {
        let block = block.load(Ordering::Relaxed);
        if block == 0 {
            continue;
        }

        // SAFETY: a nonzero entry is the processor control block of a
        // started hardware thread, which stays mapped.
        let block = unsafe { crate::kernel::object_at::<Kprcb>(block) };

        // SAFETY: the IRQL is restored before the loop body ends.
        let irql = unsafe { xboxkrnl::KfRaiseIrql(SAMPLER_IRQL) };
        let interrupt = block.interrupt_time.load(Ordering::Relaxed);
        let dpc = block.dpc_time.load(Ordering::Relaxed);
        let idle_thread = block.idle_thread.load(Ordering::Relaxed);
        // SAFETY: the idle thread of a processor never ends.
        let idle = unsafe { crate::kernel::thread_at(idle_thread) }
            .run_time
            .load(Ordering::Relaxed);
        let tick = TickCount::now().milliseconds();
        // SAFETY: returns to the IRQL raised from above.
        unsafe { xboxkrnl::KfLowerIrql(irql) };

        let [idle_pair, dpc_pair, interrupt_pair] = sources;
        idle_pair.value.store(idle, Ordering::Relaxed);
        idle_pair.rate.store(tick, Ordering::Relaxed);
        dpc_pair.value.store(dpc, Ordering::Relaxed);
        dpc_pair.rate.store(tick, Ordering::Relaxed);
        interrupt_pair.value.store(interrupt, Ordering::Relaxed);
        interrupt_pair.rate.store(tick, Ordering::Relaxed);
    }
}

fn sample_pages() {
    /// Output words of the monitor's memory statistics that feed the page
    /// counters, in counter order.
    const PAGE_STATISTICS: [usize; 8] = [
        monitor_statistics::FREE_PAGES,
        monitor_statistics::CACHE_PAGES,
        monitor_statistics::IMAGE_PAGES,
        monitor_statistics::POOL_PAGES,
        monitor_statistics::STACK_PAGES,
        monitor_statistics::VM_PAGES,
        monitor_statistics::CONTIGUOUS_PAGES,
        monitor_statistics::DEBUGGER_PAGES,
    ];

    let mut statistics = [0u32; MONITOR_STATISTICS_LENGTH as usize / 4];
    statistics[monitor_statistics::LENGTH] = MONITOR_STATISTICS_LENGTH;
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

    let current = SAMPLER.current.load(Ordering::Relaxed);
    // SAFETY: `current` stays below BUCKETS (see `Sampler`).
    let head = unsafe { SAMPLER.buckets.get_unchecked(current as usize) };
    let mut entry = head.flink.load(Ordering::Relaxed);

    if entry != head.address() {
        // SAFETY: the bucket is not empty, so its tail is a listed counter.
        unsafe { Link::at(head.blink.load(Ordering::Relaxed)) }
            .flink
            .store(0, Ordering::Relaxed);
        head.flink.store(head.address(), Ordering::Relaxed);
        head.blink.store(head.address(), Ordering::Relaxed);

        while entry != 0 {
            // SAFETY: buckets list the bodies of permanent counter objects
            // that `register` initialized.
            let mut counter = unsafe { CounterView::new(entry) };
            let next = counter.body().link.flink.load(Ordering::Relaxed);
            let registration = counter.registration();
            if RegistrationFlags::from_bits_retain(registration.0)
                .contains(RegistrationFlags::HAS_HANDLER)
            {
                let routine = counter.source();
                // SAFETY: handler counters register a routine taking
                // (query, object, sample).
                unsafe { kernel::call_export(routine, 0, entry, 0, 0) };
            } else {
                // SAFETY: the IRQL is restored after the sample.
                let irql = unsafe { xboxkrnl::KfRaiseIrql(SAMPLER_IRQL) };
                let tick = TickCount::now().milliseconds();
                let frame = frame_number();
                // SAFETY: bucket entries are permanent counter objects that
                // `register` created, initialized, and scheduled; only the
                // sampler writes their history index.
                unsafe { counters::sample(&mut counter, tick, frame) };
                // SAFETY: returns to the IRQL raised from above.
                unsafe { xboxkrnl::KfLowerIrql(irql) };
            }

            // SAFETY: `register` checked the period, which the registration
            // word keeps (see `CounterView`).
            unsafe { schedule(&counter.body().link, registration.period()) };
            entry = next;
        }
    }

    let next = if current + 1 == BUCKETS as u32 {
        0
    } else {
        current + 1
    };

    SAMPLER.current.store(next, Ordering::Relaxed);
    SAMPLER.active.fetch_sub(1, Ordering::AcqRel);
}
bridged!(sampler_dpc_entry, sampler_dpc);

fn register_c(name: &CStr, registration: CounterRegistration, source: u32) {
    let _ = register(name.to_bytes(), registration, source);
}

/// Create the object type, the sampler, and the built-in counters (stock
/// 0x91f2b110).
pub(super) fn initialize() {
    /// Kernel export ordinals of the pool routines the object type uses.
    const EX_ALLOCATE_POOL_TYPE_WITH_TAG: Ordinal = Ordinal::new(11).unwrap();
    const EX_FREE_POOL: Ordinal = Ordinal::new(15).unwrap();
    const FRAMES: CounterRegistration = SourceKind::Reader.registration(CounterClass::Rate);
    const FRAME_TICKS: CounterRegistration = SourceKind::Reader.registration(CounterClass::Value);
    const PERCENT: CounterRegistration = SourceKind::Words.registration(CounterClass::Ratio);
    const PAGES: CounterRegistration = SourceKind::Words.registration(CounterClass::Value);
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
    const THREAD_COUNTERS: [[&CStr; 3]; HARDWARE_THREAD_COUNT] = [
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

    if let Ok(module) = SystemModule::Kernel.handle()
        && let (Ok(allocate), Ok(free)) = (
            resolve_export(module, EX_ALLOCATE_POOL_TYPE_WITH_TAG),
            resolve_export(module, EX_FREE_POOL),
        )
    {
        COUNTER_TYPE
            .allocate
            .store(allocate.raw(), Ordering::Relaxed);
        COUNTER_TYPE.free.store(free.raw(), Ordering::Relaxed);
    }

    let wait_list = &DEFAULT_OBJECT.wait_list;
    wait_list
        .flink
        .store(wait_list.address(), Ordering::Relaxed);
    wait_list
        .blink
        .store(wait_list.address(), Ordering::Relaxed);
    COUNTER_TYPE.default_object.store(
        core::ptr::from_ref(&DEFAULT_OBJECT) as usize as u32,
        Ordering::Relaxed,
    );

    TITLE_INTERFACE
        .size
        .store(size_of::<TitleInterface>() as u32, Ordering::Relaxed);

    let data = kernel::debug_monitor_data();
    data.title_interface
        .store(kernel::address_of(&TITLE_INTERFACE), Ordering::Release);
    data.title_reserved
        .store(TITLE_RESERVED.as_ptr() as usize as u32, Ordering::Release);
    SAMPLER.processor_blocks.store(
        data.processor_blocks.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );

    let directory = directory();

    for head in &SAMPLER.buckets {
        head.flink.store(head.address(), Ordering::Relaxed);
        head.blink.store(head.address(), Ordering::Relaxed);
    }

    // SAFETY: the static sampler storage is zeroed, sized for a KDPC and a
    // KTIMER, and stays in place until `shut_down` cancels both.
    unsafe {
        KeInitializeDpc(
            SAMPLER.dpc.as_ptr(),
            sampler_dpc_entry as *const () as usize,
            0,
        );
        KeInitializeTimerEx(
            SAMPLER.timer.as_ptr(),
            TimerType::Notification,
            ProcessType::SYSTEM,
        );
        // Due time -1: the first expiry is immediate, then every 100 ms.
        KeSetTimerEx(
            SAMPLER.timer.as_ptr(),
            -1,
            counters::SAMPLER_INTERVAL_MS,
            SAMPLER.dpc.as_ptr(),
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

    for (names, sources) in THREAD_COUNTERS.iter().zip(&SOURCES.threads) {
        for (name, pair) in names.iter().zip(sources) {
            register_c(name, PERCENT, core::ptr::from_ref(pair) as usize as u32);
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
        KeCancelTimer(SAMPLER.timer.as_ptr());
        KeRemoveQueueDpc(SAMPLER.dpc.as_ptr());
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
    if status.is_success() {
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
        let mut record = DirectoryEntry::new();
        // The pass ends with `KernelError::NoMoreEntries` or any failure.
        let Ok(name) = record.query(directory, &mut context) else {
            return seen;
        };
        seen += 1;

        let Ok(handle) = open_in(directory, name) else {
            continue;
        };

        if let Ok(counter) = reference(handle) {
            // SAFETY: `counter` holds a reference to the object.
            unsafe { ObMakeTemporaryObject(counter.0.object) };
            counter.release();
        }

        handle.close();
    }
}

/// Forget the title's frame counters (stock 0x91f32398).
pub(super) fn title_terminated() {
    // SAFETY: the IRQL is restored below.
    let irql = unsafe { xboxkrnl::KfRaiseIrql(SAMPLER_IRQL) };
    TITLE_INTERFACE.frame_count.store(0, Ordering::Release);
    TITLE_INTERFACE.frame_ticks.store(0, Ordering::Release);
    // SAFETY: returns to the IRQL raised from above.
    unsafe { xboxkrnl::KfLowerIrql(irql) };
}

/// Forget the title's directory handle, which closed with the title
/// process (stock 0x91f32418).
pub(super) fn title_ended() {
    TITLE_DIRECTORY.store(0, Ordering::Release);
}
