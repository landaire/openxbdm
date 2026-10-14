//! PGO instrumentation runtime (stock 0x91f6b900..0x91f71600): the
//! instrumented-module list, count blocks, the value probes instrumented
//! code calls (exports 181-193), profile files, and the controls behind
//! exports 106-115 and `pogoctrl`. Records, count blocks, and thread
//! records live in the title's memory and are reached by address, as the
//! title's code shares them. See `docs/re-notes/pgo.md`.

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::sync::atomic::fence;

use openxbdm_core::status::Hresult;
use openxbdm_server::Server;
use openxbdm_server::commands::filesystem::CreateDisposition;
use openxbdm_server::commands::filesystem::CreateOptions;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::FileAccess;
use openxbdm_server::commands::filesystem::FileAttributes;
use openxbdm_server::commands::filesystem::ShareAccess;
use openxbdm_server::commands::hardware::PgoError;
use openxbdm_server::commands::hardware::PgoModule;
use openxbdm_server::commands::hardware::pgo;
use openxbdm_server::commands::hardware::pgo::BlockFormat;
use openxbdm_server::commands::hardware::pgo::CountBlockHeader;
use openxbdm_server::commands::hardware::pgo::Fatal;
use openxbdm_server::commands::hardware::pgo::IniDirective;
use openxbdm_server::commands::hardware::pgo::ListHead;
use openxbdm_server::commands::hardware::pgo::ModuleShape;
use openxbdm_server::commands::hardware::pgo::PAGE_SIZE;
use openxbdm_server::commands::hardware::pgo::PATH_UNITS;
use openxbdm_server::commands::hardware::pgo::PgoOption;
use openxbdm_server::commands::hardware::pgo::ProfileName;
use openxbdm_server::commands::hardware::pgo::RangeTable;
use openxbdm_server::commands::hardware::pgo::SweepKind;
use openxbdm_server::commands::hardware::pgo::TreeDescriptor;
use openxbdm_server::commands::hardware::pgo::WidePath;
use openxbdm_server::commands::hardware::pgo::WriteWarning;
use openxbdm_server::commands::hardware::pgo::block;

use super::super::Console;
use super::super::debugger;
use super::super::dispatcher;
use super::super::filesystem;
use crate::exports::export;
use crate::exports::export_raw;
use crate::kernel;
use crate::kernel::CriticalSection;
use crate::kernel::IoStatusBlock;
use crate::kernel::LIB_KERNEL;
use crate::kernel::LIB_XAM;
use crate::kernel::import_thunk;
use crate::net::XamNetwork;

import_thunk!(
    KeBugCheck(code: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x52
);
import_thunk!(KeTlsAlloc() -> u32, lib = LIB_KERNEL, ordinal = 0x152);
import_thunk!(
    KeTlsGetValue(index: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x154
);
import_thunk!(
    KeTlsSetValue(index: u32, value: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x155
);
import_thunk!(
    XexPcToFileHeader(address: u32, entry: *mut u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x19c
);
import_thunk!(GetProcessHeap() -> u32, lib = LIB_XAM, ordinal = 0x7d2);
import_thunk!(
    RtlAllocateHeap(heap: u32, flags: u32, size: u32) -> u32,
    lib = LIB_XAM,
    ordinal = 0x3fc
);
import_thunk!(
    RtlFreeHeap(heap: u32, flags: u32, block: u32) -> u32,
    lib = LIB_XAM,
    ordinal = 0x3ff
);
import_thunk!(
    DuplicateHandle(
        source_process: u32,
        source: u32,
        target_process: u32,
        target: *mut u32,
        access: u32,
        inherit: u32,
        options: u32,
    ) -> u32,
    lib = LIB_XAM,
    ordinal = 0x45b
);
use crate::kernel::GetCurrentThreadId;
import_thunk!(
    ResetEvent(event: u32) -> u32,
    lib = LIB_XAM,
    ordinal = 0x42b
);

/// KMODE_EXCEPTION_NOT_HANDLED, the code of every runtime failure.
const BUG_CHECK_CODE: u32 = 0x1e;
const INFINITE: u32 = u32::MAX;
const HEAP_ZERO_MEMORY: u32 = 8;
const MEM_COMMIT: u32 = 0x1000;
const PAGE_READWRITE: u32 = 4;
const STATUS_PENDING: u32 = 0x103;
const FILE_POSITION_INFORMATION: u32 = 0xe;
const CURRENT_THREAD: u32 = 0xffff_fffe;
const DUPLICATE_SAME_ACCESS: u32 = 2;
/// FILE_READ_ATTRIBUTES, added to both profile opens.
const READ_ATTRIBUTES: u32 = 0x80;

/// Instrumented-module record (0x6d0 bytes from the title's heap).
mod node {
    pub const NEXT: u32 = 0x00;
    /// The module's 24-entry probe dispatch table.
    pub const TABLE: u32 = 0x04;
    /// Dispatch table contents while counting.
    pub const COUNTING: u32 = 0x08;
    pub const TABLE_ENTRIES: u32 = 24;
    /// Address inside the module, its identity.
    pub const MODULE: u32 = 0x68;
    pub const ALLOCATION_SCALE: u32 = 0x6c;
    pub const TITLE_MEMORY: u32 = 0x70;
    pub const MODULE_WORD: u32 = 0x74;
    pub const BLOCK: u32 = 0x7c;
    /// Byte: writing the dispatch table faulted; start and stop skip it.
    pub const DEAD: u32 = 0x80;
    /// Byte: counting requested.
    pub const ENABLED: u32 = 0x81;
    /// Dword: profile names carry the phase.
    pub const PHASE_SET: u32 = 0x84;
    pub const BASE_PATH: u32 = 0x88;
    pub const PHASE: u32 = 0x290;
    pub const MODULE_NAME: u32 = 0x498;
    pub const HAS_CALLERS: u32 = 0x6a0;
    pub const COUNT_SLOTS: u32 = 0x6a4;
    pub const TREE_COUNT: u32 = 0x6a8;
    pub const LIST_COUNT: u32 = 0x6ac;
    pub const WORD_COUNT: u32 = 0x6b0;
    pub const DESCRIPTORS: u32 = 0x6b4;
    /// Stub routines the dispatch table holds while stopped.
    pub const STUBS: u32 = 0x6b8;
    pub const SCRATCH: u32 = 0x6c4;
    pub const SCALE_BONUS: u32 = 0x6c8;
    pub const EXTENDED: u32 = 0x6c9;
    pub const FILL_COUNTERS: u32 = 0x6ca;
    pub const INTERFACE: u32 = 0x6cc;
    pub const SIZE: u32 = 0x6d0;
}

/// Per-thread record (0x10 bytes from the title's heap).
mod thread {
    /// The record's own address inside a probe, the processor region
    /// address outside one.
    pub const STATE: u32 = 0x0;
    pub const HANDLE: u32 = 0x4;
    pub const NEXT: u32 = 0x8;
    pub const ID: u32 = 0xc;
    pub const SIZE: u32 = 0x10;
}

/// Caller-owned probe context of exports 182, 185, 188, 191, and 193.
mod context {
    pub const KEY: u32 = 0x00;
    pub const THREAD: u32 = 0x04;
    pub const BLOCK: u32 = 0x08;
    pub const GENERATION: u32 = 0x0c;
    pub const PAYLOAD: u32 = 0x10;
    pub const DESCRIPTOR: u32 = 0x14;
}

/// Module interface of export 112's seventh argument.
mod interface {
    pub const BLOCK_SLOT: u32 = 0x34;
    pub const COUNTS_SLOT: u32 = 0x38;
    /// Slot pointers at +0x3c and +0x44..+0x58 for the probe exports.
    pub const PROBE_SLOTS: [u32; 7] = [0x3c, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x58];
}

/// Module header of export 113 (`'POGO'`, version 0x2b).
mod header {
    pub const MAGIC: u32 = 0x00;
    pub const MAGIC_VALUE: u32 = 0x4f47_4f50;
    pub const VERSION: u32 = 0x04;
    pub const VERSION_VALUE: u32 = 0x2b;
    pub const MODULE_WORD: u32 = 0x08;
    pub const FLAGS: u32 = 0x10;
    pub const SCALE_BONUS_FLAG: u32 = 0x0800_0000;
    pub const TREE_COUNT: u32 = 0x14;
    pub const COUNT_SLOTS: u32 = 0x18;
    pub const LIST_COUNT: u32 = 0x1c;
    pub const WORD_COUNT: u32 = 0x58;
    pub const DESCRIPTORS: u32 = 0x60;
}

// Memory of records, count blocks, module tables, and headers. The title
// registered every address; the image accesses them the same way.
fn read8(address: u32) -> u8 {
    // SAFETY: see above.
    unsafe { core::ptr::read_volatile(address as usize as *const u8) }
}

fn write8(address: u32, value: u8) {
    // SAFETY: see above.
    unsafe { core::ptr::write_volatile(address as usize as *mut u8, value) }
}

fn read16(address: u32) -> u16 {
    // SAFETY: see above.
    unsafe { core::ptr::read_volatile(address as usize as *const u16) }
}

fn write16(address: u32, value: u16) {
    // SAFETY: see above.
    unsafe { core::ptr::write_volatile(address as usize as *mut u16, value) }
}

fn read32(address: u32) -> u32 {
    // SAFETY: see above.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn write32(address: u32, value: u32) {
    // SAFETY: see above.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

fn read64(address: u32) -> u64 {
    u64::from(read32(address)) << 32 | u64::from(read32(address + 4))
}

fn write64(address: u32, value: u64) {
    write32(address, (value >> 32) as u32);
    write32(address + 4, value as u32);
}

fn word(address: u32) -> &'static AtomicU32 {
    // SAFETY: see above; the words are 4-byte aligned.
    unsafe { AtomicU32::from_ptr(address as usize as *mut u32) }
}

fn fetch_add(address: u32, value: u32) -> u32 {
    word(address).fetch_add(value, Ordering::AcqRel)
}

/// Compare and swap; returns the previous value.
fn exchange(address: u32, expected: u32, new: u32) -> u32 {
    match word(address).compare_exchange(expected, new, Ordering::AcqRel, Ordering::Acquire) {
        Ok(previous) | Err(previous) => previous,
    }
}

/// Atomic 64-bit increment; the console runs in 64-bit mode.
fn increment64(address: u32) {
    // SAFETY: an 8-byte aligned counter of a count block. ldarx 4,0,3 and
    // stdcx. 4,0,3 are encoded because the target CPU model lacks them.
    unsafe {
        core::arch::asm!(
            "2:",
            ".long 0x7c8018a8",
            "addi 4, 4, 1",
            ".long 0x7c8019ad",
            "bne- 2b",
            in("r3") address,
            out("r4") _,
            options(nostack),
        );
    }
}

/// Clear an 8-byte counter in one store (std 4,0(3)).
fn clear64(address: u32) {
    // SAFETY: an 8-byte aligned counter of a count block.
    unsafe {
        core::arch::asm!("li 4, 0", ".long 0xf8830000", in("r3") address, out("r4") _, options(nostack));
    }
}

fn fill(address: u32, value: u8, length: u32) {
    // SAFETY: a range inside a count block.
    unsafe { core::ptr::write_bytes(address as usize as *mut u8, value, length as usize) }
}

fn copy(target: u32, source: u32, length: u32) {
    // SAFETY: a count block range and a registered module table.
    unsafe {
        core::ptr::copy(
            source as usize as *const u8,
            target as usize as *mut u8,
            length as usize,
        )
    }
}

fn read_units(address: u32, units: &mut [u16]) {
    for (index, unit) in units.iter_mut().enumerate() {
        *unit = read16(address + 2 * index as u32);
    }
}

fn write_units(address: u32, units: &[u16]) {
    for (index, &unit) in units.iter().enumerate() {
        write16(address + 2 * index as u32, unit);
    }
}

/// Whether the calling thread belongs to the title process (stock
/// 0x91f713b8: current thread +0x72 is 1); other threads get no record.
fn title_thread() -> bool {
    read8(kernel::current_thread() + 0x72) == 1
}

/// Print a failure and stop the console (0x91f74280, then KeBugCheck).
fn fatal(failure: Fatal) -> ! {
    kernel::debug_print_bytes(failure.text().as_bytes());
    KeBugCheck(BUG_CHECK_CODE);
    loop {
        core::hint::spin_loop();
    }
}

fn warn(warning: WriteWarning) {
    kernel::debug_print_bytes(warning.text().as_bytes());
}

fn report_illegal(decoded: pgo::Decoded) {
    for _ in 0..decoded.illegal {
        kernel::debug_print_bytes(pgo::ILLEGAL_UTF8_WARNING.as_bytes());
    }
}

/// The registration lock (0x91fa3ac0).
static SECTION: CriticalSection = CriticalSection::new();

/// Base profile name from export 113 (0x91fa36a8).
struct BaseName(UnsafeCell<[u16; PATH_UNITS]>);

// SAFETY: export 113 writes the name before the module registers; stock
// shares the buffer the same way.
unsafe impl Sync for BaseName {}

static BASE_NAME: BaseName = BaseName(UnsafeCell::new([0; PATH_UNITS]));
/// 0x91fa3ae1: a full-buffer sweep runs; probes wait on [`SWEEP_EVENT`].
static SWEEPING: AtomicBool = AtomicBool::new(false);
/// 0x91fa38b4: newest record first.
static MODULES: AtomicU32 = AtomicU32::new(0);
/// 0x91fa3ae4.
static THREADS: AtomicU32 = AtomicU32::new(0);
/// 0x91fa3ae8: manual-reset event, signaled while no sweep runs.
static SWEEP_EVENT: AtomicU32 = AtomicU32::new(0);
/// 0x91f9904c.
static TLS_INDEX: AtomicU32 = AtomicU32::new(u32::MAX);
/// 0x91fa3adc and 0x91fa38b0 from export 113.
static HEADER: AtomicU32 = AtomicU32::new(0);
static WORDS: AtomicU32 = AtomicU32::new(0);
/// `ValidateVPLE`, `ValidateEPLH`, `ValidateVPLH` (0x91fa36a0..2).
static VALIDATE_VPLE: AtomicBool = AtomicBool::new(false);
static VALIDATE_EPLH: AtomicBool = AtomicBool::new(false);
static VALIDATE_VPLH: AtomicBool = AtomicBool::new(false);
/// `EnableSweepOnOverflow`, `EnableSweepFullBuffer` (0x91f99050, 0x91f99051).
static SWEEP_ON_OVERFLOW: AtomicBool = AtomicBool::new(true);
static SWEEP_FULL_BUFFER: AtomicBool = AtomicBool::new(true);

/// A registered module record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Node(u32);

impl Node {
    fn at(self, offset: u32) -> u32 {
        self.0 + offset
    }

    fn block(self) -> u32 {
        read32(self.at(node::BLOCK))
    }

    fn dead(self) -> bool {
        read8(self.at(node::DEAD)) != 0
    }

    fn base_path(self) -> WidePath {
        let mut path = WidePath::default();
        read_units(self.at(node::BASE_PATH), &mut path.0);
        path
    }

    fn set_base_path(self, path: &WidePath) {
        write_units(self.at(node::BASE_PATH), &path.0);
    }

    fn next(self) -> Option<Self> {
        Self::from_address(read32(self.at(node::NEXT)))
    }

    fn from_address(address: u32) -> Option<Self> {
        (address != 0).then_some(Self(address))
    }
}

fn modules() -> impl Iterator<Item = Node> {
    core::iter::successors(
        Node::from_address(MODULES.load(Ordering::Acquire)),
        |node| node.next(),
    )
}

fn find_node(address: u32) -> Option<Node> {
    modules().find(|node| node.0 == address)
}

fn node_of_block(block: u32) -> Option<Node> {
    modules().find(|node| node.block() == block)
}

/// Lookup under the registration lock (0x91f6bab0).
fn locked_node_of_block(block: u32) -> Node {
    SECTION.enter();
    let node = node_of_block(block);
    SECTION.leave();
    node.unwrap_or_else(|| fatal(Fatal::BlockLookup))
}

/// Store one dispatch table entry. Stock writes under an exception
/// handler that marks the record dead on a fault; an unmapped entry is
/// treated as that fault.
fn store_entry(record: u32, table: u32, index: u32, value: u32) -> bool {
    let address = table.wrapping_add(4 * index);
    if kernel::MmIsAddressValid(address) == 0 {
        write8(record + node::DEAD, 1);
        return false;
    }
    word(address).swap(value, Ordering::AcqRel);
    true
}

/// Point the dispatch table at the counting routines (0x91f6c090).
fn start_counting(record: u32) {
    let table = read32(record + node::TABLE);
    for index in 0..node::TABLE_ENTRIES {
        if !store_entry(
            record,
            table,
            index,
            read32(record + node::COUNTING + 4 * index),
        ) {
            return;
        }
    }
}

/// Point the dispatch table at the stubs (0x91f6c140): stub 0 for entries
/// 0-5 and 21-23, stub 1 for 6-8 and 12-17, stub 2 for 9-11; 18-20 keep
/// their routine.
fn stop_counting(record: u32) {
    let table = read32(record + node::TABLE);
    for index in 0..node::TABLE_ENTRIES {
        let stub = match index {
            0..=5 | 21..=23 => 0,
            6..=8 | 12..=17 => 1,
            9..=11 => 2,
            _ => continue,
        };
        if !store_entry(
            record,
            table,
            index,
            read32(record + node::STUBS + 4 * stub),
        ) {
            return;
        }
    }
}

fn format(block: u32) -> BlockFormat {
    BlockFormat::from_version(read32(block + block::VERSION))
}

fn lose(block: u32) {
    write8(block + block::LOST, 1);
}

fn sleep_zero() {
    let interval = 0i64;
    kernel::KeDelayExecutionThread(1, 0, &interval);
}

fn close_handle(handle: u32) -> bool {
    let status = kernel::NtClose(handle);
    if (status as i32) < 0 {
        kernel::set_last_error(status);
        return false;
    }
    true
}

/// Enter a probe (0x91f6c690): mark the thread inside, or count it
/// without a record, then wait out a sweep. A thread without a record
/// cannot wait and fails; its count stays raised, as in the image.
fn enter_probe(block: u32, record: Option<u32>) -> bool {
    match record {
        Some(record) => {
            write32(record + thread::STATE, record);
            fence(Ordering::Release);
        }
        None => {
            fetch_add(block + block::UNTRACKED, 1);
        }
    }
    while SWEEPING.load(Ordering::Acquire) {
        let Some(record) = record else {
            return false;
        };
        write32(record + thread::STATE, kernel::pcr());
        kernel::WaitForSingleObject(SWEEP_EVENT.load(Ordering::Acquire), INFINITE);
        write32(record + thread::STATE, record);
        fence(Ordering::Release);
    }
    true
}

fn leave_probe(block: u32, record: Option<u32>) {
    match record {
        Some(record) => write32(record + thread::STATE, kernel::pcr()),
        None => {
            fetch_add(block + block::UNTRACKED, u32::MAX);
        }
    }
}

/// The calling thread's record, created on first use (0x91f6c728).
fn thread_record(block: u32) -> Option<u32> {
    if !title_thread() {
        return None;
    }
    let index = TLS_INDEX.load(Ordering::Acquire);
    let existing = KeTlsGetValue(index);
    if existing != 0 {
        return Some(existing);
    }
    let record = RtlAllocateHeap(GetProcessHeap(), 0, thread::SIZE);
    if record == 0 {
        fatal(Fatal::ThreadListAllocation);
    }
    write32(record + thread::STATE, 0);
    write32(record + thread::ID, GetCurrentThreadId());
    let mut handle = 0u32;
    if DuplicateHandle(
        0,
        CURRENT_THREAD,
        0,
        &mut handle,
        0,
        0,
        DUPLICATE_SAME_ACCESS,
    ) == 0
    {
        fatal(Fatal::ThreadHandle);
    }
    write32(record + thread::HANDLE, handle);
    fetch_add(block + block::THREADS, 1);
    loop {
        let head = THREADS.load(Ordering::Acquire);
        write32(record + thread::NEXT, head);
        if THREADS
            .compare_exchange(head, record, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }
    KeTlsSetValue(index, record);
    Some(record)
}

fn acquire(block: u32) -> (Option<u32>, bool) {
    let record = thread_record(block);
    (record, enter_probe(block, record))
}

/// Leave the probe ahead of a sweep (0x91f6c618).
fn release_for_sweep(block: u32) -> Option<u32> {
    let record = if title_thread() {
        Some(KeTlsGetValue(TLS_INDEX.load(Ordering::Acquire))).filter(|&record| record != 0)
    } else {
        None
    };
    match record {
        Some(record) => write32(record + thread::STATE, kernel::pcr()),
        None => {
            fetch_add(block + block::UNTRACKED, u32::MAX);
        }
    }
    record
}

fn threads_head() -> u32 {
    THREADS.as_ptr() as usize as u32
}

/// Stop probes for a sweep (0x91f6c8d8, extended blocks only): optionally
/// start a new generation, then wait until no other thread is inside a
/// probe, freeing the records of threads that ended.
fn begin_sweep(block: u32, new_generation: bool) {
    if format(block) != BlockFormat::Extended {
        return;
    }
    ResetEvent(SWEEP_EVENT.load(Ordering::Acquire));
    fence(Ordering::Release);
    SWEEPING.store(true, Ordering::Release);
    if new_generation {
        fence(Ordering::Release);
        write32(
            block + block::GENERATION,
            read32(block + block::GENERATION).wrapping_add(1),
        );
    }
    fence(Ordering::SeqCst);
    let own = if title_thread() {
        KeTlsGetValue(TLS_INDEX.load(Ordering::Acquire))
    } else {
        0
    };
    loop {
        let mut link = threads_head();
        let mut busy = read32(block + block::UNTRACKED);
        let mut record = read32(link);
        while record != 0 {
            if record != own {
                if kernel::WaitForSingleObject(read32(record + thread::HANDLE), 0) == 0
                    && exchange(link, record, read32(record + thread::NEXT)) == record
                {
                    close_handle(read32(record + thread::HANDLE));
                    RtlFreeHeap(GetProcessHeap(), 0, record);
                    record = read32(link);
                    continue;
                }
                if read32(record + thread::STATE) == record {
                    busy = busy.wrapping_add(1);
                }
            }
            link = record + thread::NEXT;
            record = read32(link);
        }
        if busy == 0 {
            return;
        }
        sleep_zero();
    }
}

fn end_sweep() {
    fence(Ordering::SeqCst);
    SWEEPING.store(false, Ordering::Release);
    let status = kernel::NtSetEvent(SWEEP_EVENT.load(Ordering::Acquire), core::ptr::null_mut());
    if (status as i32) < 0 {
        kernel::set_last_error(status);
    }
}

/// Count block time: GetSystemTime through SystemTimeToFileTime keeps
/// whole milliseconds.
fn block_time() -> u64 {
    kernel::system_time() / 10_000 * 10_000
}

/// Raise the committed size to cover `offset` (0x91f6bc18); past the
/// reservation the console stops.
fn grow(block: u32, offset: u32) {
    let committed = pgo::align_up(offset.wrapping_add(PAGE_SIZE), PAGE_SIZE);
    if committed > read32(block + block::RESERVED) {
        locked_node_of_block(block);
        fatal(Fatal::ReservationExhausted);
    }
    word(block + block::COMMITTED).swap(committed, Ordering::AcqRel);
}

/// Allocate `size` bytes of a count block for an entry, sweeping a full
/// extended block when `EnableSweepFullBuffer` is set. `None` when the
/// thread cannot take part in the sweep.
fn allocate(block: u32, size: u32) -> Option<u32> {
    let used = block + block::USED;
    let mut offset = fetch_add(used, size);
    loop {
        let end = offset.wrapping_add(size);
        if end <= read32(block + block::COMMITTED) {
            return (offset != 0).then_some(offset);
        }
        if format(block) == BlockFormat::Extended
            && SWEEP_FULL_BUFFER.load(Ordering::Acquire)
            && end > read32(block + block::RESERVED)
        {
            // Without a record the image would use the offset past the
            // reservation; the entry is dropped instead.
            let node = node_of_block(block)?;
            let Some(record) = release_for_sweep(block) else {
                lose(block);
                return None;
            };
            SECTION.enter();
            if read32(used).wrapping_add(size) > read32(block + block::RESERVED) {
                full_buffer_sweep(node, block);
            }
            SECTION.leave();
            enter_probe(block, Some(record));
            offset = fetch_add(used, size);
            continue;
        }
        grow(block, offset);
        return (offset != 0).then_some(offset);
    }
}

fn full_buffer_sweep(node: Node, block: u32) {
    begin_sweep(block, true);
    stop_counting(node.0);
    write8(block + block::RESETTING, 1);
    write8(block + block::SWEEP_KIND, SweepKind::FullBuffer as u8);
    write8(block + block::FULL_BUFFER, 1);
    write8(block + block::FULL_BUFFER_OR_LIVE, 1);
    write_profile(node);
    write8(block + block::SWEEP_KIND, 0);
    write8(block + block::RESETTING, 0);
    write64(block + block::TIME, block_time());
    clear_block(block);
    write32(
        block + block::COMMITTED,
        pgo::align_up(read32(block + block::USED), PAGE_SIZE),
    );
    start_counting(node.0);
    end_sweep();
}

/// Clear every count and free every entry (0x91f70f88).
fn clear_block(block: u32) {
    let width = format(block).width();
    fill(
        block + read32(block + block::COUNTS),
        0,
        width.wrapping_mul(read32(block + block::COUNT_SLOTS)),
    );
    fill(
        block + read32(block + block::LISTS),
        0,
        read32(block + block::LIST_COUNT).wrapping_mul(4),
    );
    let trees = block + read32(block + block::TREES);
    for index in 1..read32(block + block::TREE_COUNT) {
        write32(trees + 8 * index + 4, 0);
    }
    let used = (read32(block + block::WORD_COUNT)
        .wrapping_mul(4)
        .wrapping_add(read32(block + block::WORDS))
        + 3)
        & !3;
    write32(block + block::USED, used);
    fill(
        block + used,
        0,
        read32(block + block::COMMITTED).wrapping_sub(used),
    );
}

/// Clear counts and keep entries (0x91f70e40).
fn reset_counts(block: u32) {
    let format = format(block);
    fill(
        block + read32(block + block::COUNTS),
        0,
        format
            .width()
            .wrapping_mul(read32(block + block::COUNT_SLOTS)),
    );
    let lists = block + read32(block + block::LISTS);
    for index in 0..read32(block + block::LIST_COUNT) {
        reset_list(
            block,
            format,
            match format {
                BlockFormat::Extended => lists + 4 * index,
                BlockFormat::Standard => lists + 8 * index,
            },
        );
    }
    let trees = block + read32(block + block::TREES);
    for index in 1..read32(block + block::TREE_COUNT) {
        let descriptor = trees + 8 * index;
        reset_tree(block, format, descriptor, read32(descriptor + 4));
    }
}

/// Clear the counts of one value list; `slot` is the descriptor (head at
/// +0 when extended, +4 when standard).
fn reset_list(block: u32, format: BlockFormat, slot: u32) {
    match format {
        BlockFormat::Extended => {
            let mut offset = ListHead(read32(slot)).offset();
            while offset != 0 {
                let entry = block + offset;
                offset = read32(entry + 8);
                write32(entry + 4, 0);
            }
        }
        BlockFormat::Standard => {
            let mut offset = read32(slot + 4);
            while offset != 0 {
                let entry = block + offset;
                offset = read32(entry + 0x10);
                clear64(entry + 8);
            }
        }
    }
}

/// Clear the counts of a call tree (0x91f70cf0).
fn reset_tree(block: u32, format: BlockFormat, descriptor: u32, mut offset: u32) {
    let width = format.width();
    while offset != 0 {
        let entry = block + offset;
        let counters = u32::from(read16(descriptor));
        let lists = u32::from(read16(descriptor + 2));
        fill(entry + 0x10, 0, width * counters);
        let heads = entry + 0x10 + width * counters;
        for index in 0..lists {
            reset_list(
                block,
                format,
                match format {
                    BlockFormat::Extended => heads + 4 * index,
                    BlockFormat::Standard => heads + 8 * index,
                },
            );
        }
        reset_tree(block, format, descriptor, read32(entry + 4));
        offset = read32(entry + 8);
    }
}

/// `ValidateEPLH` (0x91f6c278): a call tree descriptor of the block.
fn check_tree_descriptor(block: u32, descriptor: u32) {
    if !VALIDATE_EPLH.load(Ordering::Relaxed) {
        return;
    }
    let trees = block.wrapping_add(read32(block + block::TREES));
    if descriptor < trees
        || descriptor & 7 != 0
        || descriptor
            > (read32(block + block::TREE_COUNT).wrapping_mul(8))
                .wrapping_add(trees)
                .wrapping_sub(8)
    {
        fatal(Fatal::InvalidTreeHead);
    }
}

/// `ValidateVPLH` (0x91f6c3f8): a value list head of the block or of one
/// of its call tree entries.
fn check_list_head(block: u32, head: u32, alignment: u32) {
    if !VALIDATE_VPLH.load(Ordering::Relaxed) {
        return;
    }
    let lists = block.wrapping_add(read32(block + block::LISTS));
    if head < lists || head & (alignment - 1) != 0 {
        fatal(Fatal::InvalidValueListHead);
    }
    if head
        <= read32(block + block::LIST_COUNT)
            .wrapping_sub(1)
            .wrapping_mul(alignment)
            .wrapping_add(lists)
    {
        return;
    }
    let trees = block + read32(block + block::TREES);
    for index in 0..read32(block + block::TREE_COUNT) {
        let descriptor = trees + 8 * index;
        let root = read32(descriptor + 4);
        if read16(descriptor + 2) != 0
            && root != 0
            && head_in_tree(block, descriptor, root, head, alignment)
        {
            return;
        }
    }
    fatal(Fatal::InvalidValueListHead);
}

fn head_in_tree(block: u32, descriptor: u32, mut offset: u32, head: u32, alignment: u32) -> bool {
    while offset != 0 {
        let entry = block + offset;
        let start = format(block).width() * u32::from(read16(descriptor)) + entry + 0x10;
        let last = (u32::from(read16(descriptor + 2)).wrapping_sub(1))
            .wrapping_mul(alignment)
            .wrapping_add(start);
        if head >= start && head <= last {
            return true;
        }
        if head_in_tree(block, descriptor, read32(entry + 4), head, alignment) {
            return true;
        }
        offset = read32(entry + 8);
    }
    false
}

/// `ValidateVPLE` (0x91f6c520): every entry of a list lies in the
/// allocated area.
fn check_list_entries(block: u32, head: u32) {
    if !VALIDATE_VPLE.load(Ordering::Relaxed) {
        return;
    }
    let extended = format(block) == BlockFormat::Extended;
    let mut offset = if extended {
        ListHead(read32(head)).offset()
    } else {
        read32(head + 4)
    };
    while offset != 0 {
        let entry = block + offset;
        let first = read32(block + block::WORD_COUNT)
            .wrapping_mul(4)
            .wrapping_add(read32(block + block::WORDS))
            .wrapping_add(block);
        let last = block
            .wrapping_sub(if extended { 0xc } else { 0x18 })
            .wrapping_add(read32(block + block::USED));
        if entry < first || entry > last {
            fatal(Fatal::InvalidValueListEntry);
        }
        offset = if extended {
            read32(entry + 8)
        } else {
            read32(entry + 0x10)
        };
    }
}

fn descriptor(address: u32) -> TreeDescriptor {
    TreeDescriptor {
        counters: read16(address),
        lists: read16(address + 2),
    }
}

/// Whether a 64-bit argument is a zero- or sign-extended 32-bit value.
fn fits32(value: u64) -> bool {
    value == u64::from(value as u32) || value == value as u32 as i32 as i64 as u64
}

/// Export 181 (stock 0x91f6f7d0): find or insert `key` in a path tree
/// and count it in the first 8-byte slot; returns the entry's slots.
extern "C" fn probe_path(block: u32, tree: u32, key: u32) -> u32 {
    check_tree_descriptor(block, tree);
    let key = pgo::tree_key(key);
    let mut link = tree + 4;
    let mut allocated = None;
    let entry = loop {
        let offset = read32(link);
        if offset != 0 {
            let entry = block + offset;
            let existing = read32(entry);
            if existing == key {
                break Some(entry);
            }
            link = if existing > key { entry + 4 } else { entry + 8 };
            continue;
        }
        let offset = match allocated {
            Some(offset) => offset,
            None => match allocate(block, format(block).path_entry_size(descriptor(tree))) {
                Some(offset) => *allocated.insert(offset),
                None => break None,
            },
        };
        let entry = block + offset;
        write32(entry, key);
        write32(entry + 4, 0);
        write32(entry + 8, 0);
        if exchange(link, 0, offset) == 0 {
            fetch_add(block + block::PATH_ENTRIES, 1);
            break Some(entry);
        }
    };
    match entry {
        Some(entry) => {
            if read16(tree) != 0 {
                increment64(entry + 0x10);
            }
            entry + 0x10
        }
        // The image increments at address 0x10 when the tree has counters.
        None => 0x10,
    }
}

/// Find or insert `key` in a call tree: exports 182 and 193 share it.
/// `None` when no entry could be allocated.
fn tree_entry(block: u32, tree: u32, key: u32) -> Option<u32> {
    check_tree_descriptor(block, tree);
    let key = pgo::tree_key(key);
    let mut allocated: Option<u32> = None;
    'restart: loop {
        let mut link = tree + 4;
        loop {
            let offset = read32(link);
            if offset != 0 {
                let entry = block + offset;
                let existing = read32(entry);
                if existing == key {
                    return Some(entry);
                }
                link = if existing > key { entry + 4 } else { entry + 8 };
                continue;
            }
            let offset = match allocated {
                Some(offset) => offset,
                None => {
                    let generation = read32(block + block::GENERATION);
                    let offset = allocate(block, format(block).tree_entry_size(descriptor(tree)))?;
                    allocated = Some(offset);
                    if read32(block + block::GENERATION) != generation {
                        continue 'restart;
                    }
                    offset
                }
            };
            let entry = block + offset;
            write32(entry, key);
            write32(entry + 4, 0);
            write32(entry + 8, 0);
            if exchange(link, 0, offset) == 0 {
                return Some(entry);
            }
        }
    }
}

/// Export 182 (stock 0x91f6fb18): count `key` in a call tree and fill
/// the caller's context for the value probes of the entry.
extern "C" fn probe_call(block: u32, tree: u32, key: u32, frame: u32) {
    let (record, entered) = acquire(block);
    let fail = |frame: u32| {
        write32(frame + context::BLOCK, block);
        write32(frame + context::GENERATION, 0);
        write32(frame + context::THREAD, record.unwrap_or(0));
        write32(frame + context::PAYLOAD, read32(block + block::SCRATCH));
        write32(frame + context::DESCRIPTOR, tree);
    };
    if !entered {
        fail(frame);
        lose(block);
        return;
    }
    match tree_entry(block, tree, key) {
        Some(entry) => {
            let payload = entry + 0x10;
            if read16(tree) != 0 {
                // Stock's overflow test (`addic.` then `ble` toward 0x91f70920)
                // judges the 64-bit sum of a zero-extended word, which is
                // never <= 0, so the count wraps.
                loop {
                    let count = read32(payload);
                    if exchange(payload, count, count.wrapping_add(1)) == count {
                        break;
                    }
                }
            }
            write32(frame + context::BLOCK, block);
            write32(frame + context::THREAD, record.unwrap_or(0));
            write32(
                frame + context::GENERATION,
                read32(block + block::GENERATION),
            );
            write32(frame + context::PAYLOAD, payload);
            write32(frame + context::DESCRIPTOR, tree);
            if SWEEPING.load(Ordering::Acquire) {
                export_lookup(frame);
            }
        }
        None => fail(frame),
    }
    leave_probe(block, record);
}

/// Export 193 (stock 0x91f6d940): refresh a context after a sweep: wait
/// out the sweep, then find or insert its key again. 1 on success; on
/// failure the payload is the block's scratch word.
extern "C" fn export_lookup(frame: u32) -> u32 {
    loop {
        let block = read32(frame + context::BLOCK);
        if SWEEPING.load(Ordering::Acquire) {
            if read32(frame + context::THREAD) == 0 {
                lose(block);
                write32(frame + context::GENERATION, 0);
                write32(frame + context::PAYLOAD, read32(block + block::SCRATCH));
                return 0;
            }
            loop {
                let record = read32(frame + context::THREAD);
                leave_probe(block, (record != 0).then_some(record));
                kernel::WaitForSingleObject(SWEEP_EVENT.load(Ordering::Acquire), INFINITE);
                let record = read32(frame + context::THREAD);
                enter_probe(block, (record != 0).then_some(record));
                if !SWEEPING.load(Ordering::Acquire) {
                    break;
                }
            }
        }
        let tree = read32(frame + context::DESCRIPTOR);
        let Some(entry) = tree_entry(block, tree, read32(frame + context::KEY)) else {
            write32(frame + context::GENERATION, 0);
            write32(frame + context::PAYLOAD, read32(block + block::SCRATCH));
            return 0;
        };
        write32(frame + context::PAYLOAD, entry + 0x10);
        write32(
            frame + context::GENERATION,
            read32(block + block::GENERATION),
        );
        if !SWEEPING.load(Ordering::Acquire) {
            return 1;
        }
    }
}

/// Insert or count `value` in a sorted list of `{u64 value, u64 count,
/// next}` entries headed at `list` + 4 (exports 183 and 186). `limit`
/// redirects new values past [`pgo::LIST_LIMIT`] to the overflow entry
/// and counts entries at `list` + 0.
fn count_wide(block: u32, list: u32, mut value: u64, limit: bool) {
    let mut allocated: Option<u32> = None;
    'restart: loop {
        check_list_head(block, list, 8);
        check_list_entries(block, list);
        let mut link = list + 4;
        'search: loop {
            let mut current = read32(link);
            while current != 0 {
                let entry = block + current;
                let existing = read64(entry);
                if existing == value {
                    increment64(entry + 8);
                    return;
                }
                if existing > value {
                    break;
                }
                link = entry + 0x10;
                current = read32(link);
            }
            let offset = match allocated {
                Some(offset) => offset,
                None => {
                    if limit && read32(list) >= pgo::LIST_LIMIT && value != pgo::OVERFLOW_VALUE {
                        value = pgo::OVERFLOW_VALUE;
                        continue 'restart;
                    }
                    // The image increments at address 8 when allocation fails.
                    let Some(offset) = allocate(block, pgo::WIDE_ENTRY_SIZE) else {
                        return;
                    };
                    *allocated.insert(offset)
                }
            };
            let entry = block + offset;
            write64(entry, value);
            write32(entry + 0x10, read32(link));
            if exchange(link, current, offset) != current {
                continue 'search;
            }
            fetch_add(block + block::WIDE_ENTRIES, 1);
            if limit {
                write32(list, read32(list).wrapping_add(1));
            }
            increment64(entry + 8);
            return;
        }
    }
}

/// Insert or count `value` in a sorted list of `{value, count, next}`
/// entries with a [`ListHead`] at `list` (exports 184, 185, 187, 188).
/// `limit` applies [`pgo::LIST_LIMIT`] by the head's counter. `frame` is
/// the context of a probe that rebases `list` onto a refreshed call tree
/// entry after a sweep.
fn count_word(block: u32, mut list: u32, mut value: u64, limit: bool, frame: Option<u32>) {
    let mut allocated: Option<u32> = None;
    'restart: loop {
        check_list_head(block, list, 4);
        check_list_entries(block, list);
        let mut previous: Option<u32> = None;
        let mut head = read32(list);
        let mut current = ListHead(head).offset();
        loop {
            let mut found = None;
            while current != 0 {
                let entry = block + current;
                let existing = read32(entry);
                if existing == value as u32 {
                    found = Some(entry);
                    break;
                }
                if existing > value as u32 {
                    break;
                }
                previous = Some(entry + 8);
                current = read32(entry + 8);
            }
            if let Some(entry) = found {
                fetch_add(entry + 4, 1);
                return;
            }
            let offset = match allocated {
                Some(offset) => offset,
                None => {
                    if limit
                        && ListHead(read32(list)).counter() >= pgo::LIST_LIMIT
                        && value != pgo::OVERFLOW_VALUE
                    {
                        value = pgo::OVERFLOW_VALUE;
                        continue 'restart;
                    }
                    let generation = read32(block + block::GENERATION);
                    let Some(offset) = allocate(block, format(block).word_entry_size()) else {
                        return;
                    };
                    allocated = Some(offset);
                    if read32(block + block::GENERATION) != generation {
                        if let Some(frame) = frame {
                            let delta = list.wrapping_sub(read32(frame + context::PAYLOAD));
                            if export_lookup(frame) == 0 {
                                return;
                            }
                            list = read32(frame + context::PAYLOAD).wrapping_add(delta);
                        }
                        continue 'restart;
                    }
                    offset
                }
            };
            let entry = block + offset;
            write32(entry, value as u32);
            match previous {
                None => {
                    write32(entry + 8, ListHead(head).offset());
                    let replaced = exchange(list, head, ListHead(head).advanced(offset).0);
                    if replaced == head {
                        fetch_add(entry + 4, 1);
                        return;
                    }
                    // The search resumes at the entry it last compared.
                    if current == 0 {
                        current = ListHead(replaced).offset();
                        if current == 0 {
                            fatal(Fatal::InvalidValueListHead);
                        }
                    }
                    head = replaced;
                }
                Some(link) => {
                    write32(entry + 8, read32(link));
                    if exchange(link, current, offset) == current {
                        if limit {
                            let mut expected = head;
                            loop {
                                let replaced = exchange(
                                    list,
                                    expected,
                                    ListHead(expected).advanced(ListHead(expected).offset()).0,
                                );
                                if replaced == expected {
                                    break;
                                }
                                expected = replaced;
                            }
                        }
                        fetch_add(entry + 4, 1);
                        return;
                    }
                    current = read32(link);
                }
            }
        }
    }
}

/// Exports 184 and 187: count a 32-bit value on the calling thread.
fn word_probe(block: u32, list: u32, value: u64, limit: bool) {
    if !fits32(value) {
        lose(block);
        return;
    }
    let (record, entered) = acquire(block);
    if !entered {
        lose(block);
        return;
    }
    count_word(block, list, value, limit, None);
    leave_probe(block, record);
}

/// Exports 185 and 188: count a 32-bit value of the call tree entry the
/// context refers to, refreshing the context after a sweep.
fn tracked_word_probe(block: u32, list: u32, value: u64, frame: u32, limit: bool) {
    if !fits32(value) {
        lose(block);
        return;
    }
    let owner = read32(frame + context::BLOCK);
    let record = read32(frame + context::THREAD);
    let record = (record != 0).then_some(record);
    if !enter_probe(owner, record) {
        lose(owner);
        return;
    }
    if read32(frame + context::GENERATION) == read32(block + block::GENERATION)
        || export_lookup(frame) != 0
    {
        count_word(block, list, value, limit, Some(frame));
    }
    let record = read32(frame + context::THREAD);
    leave_probe(
        read32(frame + context::BLOCK),
        (record != 0).then_some(record),
    );
}

/// Export 183 (stock 0x91f6dd18): count a 64-bit value.
extern "C" fn probe_wide(block: u32, list: u32, value: u64) {
    count_wide(block, list, value, false);
}

/// Export 184 (stock 0x91f6e030).
extern "C" fn probe_word(block: u32, list: u32, value: u64) {
    word_probe(block, list, value, false);
}

/// Export 185 (stock 0x91f6e448).
extern "C" fn probe_tracked_word(block: u32, list: u32, value: u64, frame: u32) {
    tracked_word_probe(block, list, value, frame, false);
}

/// Export 186 (stock 0x91f6e8f8): count a 64-bit value, at most ten
/// distinct ones.
extern "C" fn probe_limited_wide(block: u32, list: u32, value: u64) {
    count_wide(block, list, value, true);
}

/// Export 187 (stock 0x91f6ec48).
extern "C" fn probe_limited_word(block: u32, list: u32, value: u64) {
    word_probe(block, list, value, true);
}

/// Export 188 (stock 0x91f6f148).
extern "C" fn probe_limited_tracked_word(block: u32, list: u32, value: u64, frame: u32) {
    tracked_word_probe(block, list, value, frame, true);
}

fn range_bucket(value: u64, table: u32) -> u64 {
    let range = RangeTable {
        count: read16(table + 4),
        flags: read16(table + 6),
    };
    let entries = table + 8;
    let bucket = range.bucket(value, |index| {
        if range.wide() {
            read64(entries + 8 * index)
        } else {
            u64::from(read32(entries + 4 * index))
        }
    });
    u64::from(bucket)
}

/// Export 189 (stock 0x91f6f6f0): count the range of a value as export 183.
extern "C" fn probe_wide_range(block: u32, list: u32, value: u64, table: u32) {
    probe_wide(block, list, range_bucket(value, table));
}

/// Export 190 (stock 0x91f6f740): as export 184.
extern "C" fn probe_word_range(block: u32, list: u32, value: u64, table: u32) {
    probe_word(block, list, range_bucket(value, table));
}

/// Export 191 (stock 0x91f6f790): as export 185.
extern "C" fn probe_tracked_word_range(block: u32, list: u32, value: u64, table: u32, frame: u32) {
    probe_tracked_word(block, list, range_bucket(value, table), frame);
}

/// Export 192 (stock 0x91f70920): a 31-bit call counter is about to
/// overflow: write a profile and reset, or stop the console.
extern "C" fn export_overflow(block: u32) {
    if !SWEEP_ON_OVERFLOW.load(Ordering::Acquire) {
        fatal(Fatal::CounterOverflow);
    }
    if let Some(node) = node_of_block(block) {
        snapshot(node, None, true, SweepKind::Overflow);
    }
}

/// Probe entries: the console passes a 64-bit value in one register; the
/// 32-bit routines take it as a register pair, so later arguments move up
/// one register (rldicl 5,5,32,32 puts the high word in r5).
macro_rules! probe_entry {
    ($entry:ident, $target:path, [$($adapt:literal),*]) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $entry() {
            core::arch::naked_asm!(
                $($adapt,)*
                "lis 12, {target}@ha",
                "addi 12, 12, {target}@l",
                "b {bridge}",
                target = sym $target,
                bridge = sym crate::exports::export_bridge,
            )
        }
    };
}

probe_entry!(entry_181, probe_path, []);
probe_entry!(entry_182, probe_call, []);
probe_entry!(entry_183, probe_wide, ["mr 6, 5", ".long 0x78a50022"]);
probe_entry!(entry_184, probe_word, ["mr 6, 5", ".long 0x78a50022"]);
probe_entry!(
    entry_185,
    probe_tracked_word,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_186,
    probe_limited_wide,
    ["mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_187,
    probe_limited_word,
    ["mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_188,
    probe_limited_tracked_word,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_189,
    probe_wide_range,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_190,
    probe_word_range,
    ["mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);
probe_entry!(
    entry_191,
    probe_tracked_word_range,
    ["mr 8, 7", "mr 7, 6", "mr 6, 5", ".long 0x78a50022"]
);

export_raw!(181, entry_181);
export_raw!(182, entry_182);
export_raw!(183, entry_183);
export_raw!(184, entry_184);
export_raw!(185, entry_185);
export_raw!(186, entry_186);
export_raw!(187, entry_187);
export_raw!(188, entry_188);
export_raw!(189, entry_189);
export_raw!(190, entry_190);
export_raw!(191, entry_191);
export!(192, export_overflow);
export!(193, export_lookup);

/// What the image stores in a probe slot: it loads 8 bytes at the export's
/// entry and stores the low word, the entry's second instruction.
fn probe_slot_word(entry: unsafe extern "C" fn()) -> u32 {
    read32(entry as usize as u32 + 4)
}

/// Publish the count block and probes to the module (0x91f6ff58) and
/// load the counting entries of the dispatch table from the interface.
fn connect_interface(node: Node, values: u32) {
    let module = read32(node.at(node::INTERFACE));
    let block = node.block();
    write32(read32(module + interface::BLOCK_SLOT), block);
    write32(
        read32(module + interface::COUNTS_SLOT),
        read32(block + block::COUNTS) + block,
    );
    let probes: [unsafe extern "C" fn(); 7] = if format(block) == BlockFormat::Extended {
        for index in [0, 1, 3, 4, 5, 6, 7, 8, 9] {
            write32(module + 4 * index, read32(values + 4 * index));
        }
        [
            entry_182, entry_184, entry_190, entry_187, entry_185, entry_191, entry_188,
        ]
    } else {
        [
            entry_181, entry_183, entry_189, entry_186, entry_183, entry_189, entry_186,
        ]
    };
    for (slot, entry) in interface::PROBE_SLOTS.iter().zip(probes) {
        write32(read32(module + slot), probe_slot_word(entry));
    }
    // Dispatch entries 0-13 take interface words 0-9 with every third
    // entry from 2 left empty; 14-23 are empty.
    const SOURCES: [Option<u32>; 14] = [
        Some(0),
        Some(1),
        None,
        Some(2),
        Some(3),
        None,
        Some(4),
        Some(5),
        None,
        Some(6),
        Some(7),
        None,
        Some(8),
        Some(9),
    ];
    for index in 0..node::TABLE_ENTRIES {
        let value = match SOURCES.get(index as usize).copied().flatten() {
            Some(source) => read32(module + 4 * source),
            None => 0,
        };
        write32(node.at(node::COUNTING + 4 * index), value);
    }
}

/// Copy the module header of export 113 into the record and build the
/// profile base path (0x91f6d8a0).
fn load_header(node: Node) {
    let header = HEADER.load(Ordering::Acquire);
    // A missing header would fault the image.
    if header == 0 || read32(header + header::MAGIC) != header::MAGIC_VALUE {
        fatal(Fatal::InvalidSignature);
    }
    if read32(header + header::VERSION) != header::VERSION_VALUE {
        fatal(Fatal::InvalidVersion);
    }
    write32(node.at(node::DESCRIPTORS), header + header::DESCRIPTORS);
    write32(node.at(node::HAS_CALLERS), 1);
    write32(
        node.at(node::MODULE_WORD),
        read32(header + header::MODULE_WORD),
    );
    write32(
        node.at(node::COUNT_SLOTS),
        read32(header + header::COUNT_SLOTS),
    );
    write32(
        node.at(node::TREE_COUNT),
        read32(header + header::TREE_COUNT),
    );
    write32(
        node.at(node::LIST_COUNT),
        read32(header + header::LIST_COUNT),
    );
    write32(
        node.at(node::WORD_COUNT),
        read32(header + header::WORD_COUNT),
    );
    write8(
        node.at(node::SCALE_BONUS),
        u8::from(read32(header + header::FLAGS) & header::SCALE_BONUS_FLAG != 0),
    );
    let module = module_file_name(read32(node.at(node::MODULE)));
    // SAFETY: export 113 completed before the module registered.
    let base_name = unsafe { &*BASE_NAME.0.get() };
    match pgo::base_path(base_name, module.units()) {
        Ok(path) => node.set_base_path(&path),
        Err(failure) => fatal(failure),
    }
}

/// The full name of the module containing `address` (GetModuleFileName,
/// 0x91f71128 and 0x91f71150).
struct ModuleFileName {
    units: [u16; PATH_UNITS + 1],
    length: usize,
}

impl ModuleFileName {
    fn units(&self) -> &[u16] {
        &self.units[..self.length]
    }

    /// The image also requires the copy to be terminated, which the copy
    /// guarantees below this length.
    fn fits(&self) -> bool {
        self.length < PATH_UNITS
    }
}

fn module_file_name(address: u32) -> ModuleFileName {
    let mut name = ModuleFileName {
        units: [0; PATH_UNITS + 1],
        length: 0,
    };
    let mut entry = 0u32;
    XexPcToFileHeader(address, &mut entry);
    // An address outside every module leaves the image with an unset
    // entry; the name is taken as empty.
    if entry == 0 {
        return name;
    }
    let bytes = usize::from(read16(entry + 0x24)).min(2 * PATH_UNITS);
    let buffer = read32(entry + 0x28);
    name.length = bytes / 2;
    read_units(buffer, &mut name.units[..name.length]);
    name
}

/// Lay out and allocate the count block (0x91f6cbd8).
fn create_block(node: Node) {
    let format = if read8(node.at(node::EXTENDED)) != 0 {
        BlockFormat::Extended
    } else {
        BlockFormat::Standard
    };
    let descriptors = read32(node.at(node::DESCRIPTORS));
    let tree_count = read32(node.at(node::TREE_COUNT));
    let shape = ModuleShape {
        format,
        module_word: read32(node.at(node::MODULE_WORD)),
        has_callers: read32(node.at(node::HAS_CALLERS)) != 0,
        count_slots: read32(node.at(node::COUNT_SLOTS)),
        list_count: read32(node.at(node::LIST_COUNT)),
        tree_count,
        word_count: read32(node.at(node::WORD_COUNT)),
        scratch: read32(node.at(node::SCRATCH)),
        title_memory: read32(node.at(node::TITLE_MEMORY)),
        scale_bonus: read8(node.at(node::SCALE_BONUS)) != 0,
        allocation_scale: read32(node.at(node::ALLOCATION_SCALE)),
        descriptors: (0..tree_count).map(move |index| descriptor(descriptors + 8 * index)),
    };
    let header = CountBlockHeader::new(&shape);
    let mut bytes = [0u8; 0x2a0];
    header.encode(block_time(), &mut bytes);
    let mut base = 0u32;
    let mut size = header.reserved;
    let status =
        kernel::NtAllocateVirtualMemory(&mut base, &mut size, MEM_COMMIT, PAGE_READWRITE, 0);
    if (status as i32) < 0 {
        kernel::set_last_error(status);
        base = 0;
    }
    write32(node.at(node::BLOCK), base);
    if base == 0 {
        fatal(Fatal::BlockAllocation);
    }
    let length = format.header_size() as usize;
    for (index, &byte) in bytes[..length].iter().enumerate() {
        write8(base + index as u32, byte);
    }
    if read8(node.at(node::FILL_COUNTERS)) != 0 {
        fill(
            base + header.counts.offset,
            0x7f,
            format
                .width()
                .wrapping_mul(read32(node.at(node::COUNT_SLOTS))),
        );
    }
    copy(
        base + header.trees.offset + 8,
        descriptors,
        tree_count.wrapping_mul(8),
    );
    copy(
        base + header.words.offset,
        WORDS.load(Ordering::Acquire),
        read32(node.at(node::WORD_COUNT)).wrapping_mul(4),
    );
}

/// A `pogo.ini` request for the server thread.
#[repr(C)]
struct IniRequest {
    path: u32,
    node: u32,
}

/// Export 107 (stock 0x91f3e038): apply `pogo.ini` to a record, then
/// raise `pogomodstartup` when `stopon pogomodstart` is set. The drive
/// table belongs to the server, so the file is read on its thread; when
/// the server cannot take the request the file is not read.
extern "C" fn export_load_ini(path: *const core::ffi::c_char, node: u32) -> u32 {
    // SAFETY: the caller passes a NUL-terminated module path.
    let bytes = unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes();
    if bytes.len() >= 0x140 {
        return pgo::BAD_MODULE_PATH.0;
    }
    let request = IniRequest {
        path: path as usize as u32,
        node,
    };
    let result = dispatcher::call_on_server(
        service_load_ini,
        &request as *const IniRequest as usize as u32,
    )
    .unwrap_or(pgo::SUCCESS.0);
    if result == pgo::SUCCESS.0 {
        debugger::report_pogo_module_start(path as usize as u32, node);
    }
    result
}

fn service_load_ini(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    argument: u32,
) -> u32 {
    // SAFETY: the poster waits with the request and its NUL-terminated
    // path in place.
    let request = unsafe { &*(argument as usize as *const IniRequest) };
    let node = Node(request.node);
    // SAFETY: as above.
    let path =
        unsafe { core::ffi::CStr::from_ptr(request.path as usize as *const core::ffi::c_char) }
            .to_bytes();
    let result = pgo::load_ini(
        &server.state,
        console,
        path,
        &mut |_, _, directive| match directive {
            IniDirective::AllocScale(scale) => {
                set_allocation_scale(node.0, scale);
            }
            IniDirective::OutputPath(directory) => {
                let mut path = node.base_path();
                report_illegal(pgo::output_path(&mut path, directory));
                node.set_base_path(&path);
            }
            IniDirective::DisableDataCollection => {
                stop_modules(node.0);
            }
            IniDirective::Option { option, value } => {
                set_option(node.0, option, value);
            }
        },
    );
    result.0
}

/// Set up a new record (0x91f70250).
fn initialize_module(node: Node, name: &ModuleFileName, values: u32) {
    load_header(node);
    if name.length >= PATH_UNITS {
        fatal(Fatal::BinaryPathTooLong);
    }
    write_units(node.at(node::MODULE_NAME), &name.units[..=name.length]);
    let mut path = [0u8; 0x104];
    let mut units = [0u16; PATH_UNITS + 1];
    units[..name.length].copy_from_slice(name.units());
    // A name longer than the buffer in UTF-8 keeps the bytes that fit.
    let _ = pgo::encode_utf8(&units[..=name.length], &mut path[..0x103]);
    write32(node.at(node::ALLOCATION_SCALE), 1);
    write32(node.at(node::BLOCK), 0);
    write8(node.at(node::EXTENDED), 1);
    write8(node.at(node::FILL_COUNTERS), 0);
    export_load_ini(path.as_ptr().cast(), node.0);
    create_block(node);
    connect_interface(node, values);
    if SWEEP_EVENT.load(Ordering::Acquire) == 0 {
        let event = kernel::CreateEventA(0, 1, 1, core::ptr::null());
        SWEEP_EVENT.store(event, Ordering::Release);
        if event == 0 {
            fatal(Fatal::EventCreation);
        }
    }
    let index = KeTlsAlloc();
    TLS_INDEX.store(index, Ordering::Release);
    if index == u32::MAX {
        close_handle(SWEEP_EVENT.swap(0, Ordering::AcqRel));
        fatal(Fatal::TlsAllocation);
    }
}

/// The record of `address` whose module has file name `name` (0x91f6bb40);
/// records at the address with another name are marked dead.
fn find_module(address: u32, name: Option<&[u16]>) -> Option<Node> {
    for node in modules() {
        if node.dead() || read32(node.at(node::MODULE)) != address {
            continue;
        }
        let Some(name) = name else {
            continue;
        };
        let mut existing = [0u16; PATH_UNITS];
        read_units(node.at(node::MODULE_NAME), &mut existing);
        if existing[..pgo::wide_len(&existing)] == name[..pgo::wide_len(name)] {
            return Some(node);
        }
        write8(node.at(node::DEAD), 1);
    }
    None
}

/// Export 112 (stock 0x91f703f8): register or re-register an instrumented
/// module and start or stop its counting.
extern "C" fn export_register(
    table: u32,
    address: u32,
    stub_a: u32,
    stub_b: u32,
    stub_c: u32,
    _reserved: u32,
    module_interface: u32,
    values: u32,
) {
    // The table starts out stopped through a stack record.
    let mut scratch = [0u32; (node::SIZE / 4) as usize];
    scratch[(node::TABLE / 4) as usize] = table;
    scratch[(node::STUBS / 4) as usize] = stub_a;
    scratch[(node::STUBS / 4) as usize + 1] = stub_b;
    scratch[(node::STUBS / 4) as usize + 2] = stub_c;
    stop_counting(scratch.as_mut_ptr() as usize as u32);
    let error = kernel::last_error();
    SECTION.enter();
    let name = module_file_name(address);
    let mut terminated = [0u16; PATH_UNITS + 1];
    terminated[..name.length].copy_from_slice(name.units());
    let node = match find_module(address, Some(&terminated[..])) {
        Some(node) => {
            write8(node.at(node::DEAD), 0);
            connect_interface(node, values);
            node
        }
        None => {
            if name.length == 0 {
                SECTION.leave();
                fatal(Fatal::ModuleNameFailed);
            }
            if !name.fits() {
                SECTION.leave();
                fatal(Fatal::ModuleNameTooLong);
            }
            let record = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, node::SIZE);
            if record == 0 {
                fatal(Fatal::NodeAllocation);
            }
            let node = Node(record);
            write32(node.at(node::TABLE), table);
            write32(node.at(node::MODULE), address);
            write32(node.at(node::NEXT), MODULES.load(Ordering::Acquire));
            MODULES.store(record, Ordering::Release);
            write32(node.at(node::STUBS), stub_a);
            write32(node.at(node::STUBS + 4), stub_b);
            write32(node.at(node::STUBS + 8), stub_c);
            write8(node.at(node::ENABLED), 1);
            write32(node.at(node::INTERFACE), module_interface);
            initialize_module(node, &name, values);
            write32(node.at(node::PHASE_SET), 0);
            write16(node.at(node::PHASE), 0);
            node
        }
    };
    if read8(node.at(node::ENABLED)) != 0 {
        start_counting(node.0);
    } else {
        stop_counting(node.0);
    }
    SECTION.leave();
    kernel::set_last_error_value(error);
}

/// Export 106 (stock 0x91f70628): look a module up without a name, which
/// never matches.
extern "C" fn export_find_module(address: u32) -> u32 {
    find_module(address, None).map_or(0, |node| node.0)
}

fn select(module: u32) -> impl Iterator<Item = Node> {
    modules().filter(move |node| module == 0 || node.0 == module)
}

fn module_result(module: u32, matched: bool) -> Hresult {
    if module != 0 && !matched {
        pgo::NO_SUCH_MODULE
    } else {
        pgo::SUCCESS
    }
}

/// Export 108 (stock 0x91f70630): request counting for one module or all.
fn start_modules(module: u32) -> Hresult {
    let mut matched = false;
    for node in select(module) {
        matched = true;
        write8(node.at(node::ENABLED), 1);
        if !node.dead() {
            start_counting(node.0);
        }
    }
    module_result(module, matched)
}

/// Export 109 (stock 0x91f706d0).
fn stop_modules(module: u32) -> Hresult {
    let mut matched = false;
    for node in select(module) {
        matched = true;
        write8(node.at(node::ENABLED), 0);
        if !node.dead() {
            stop_counting(node.0);
        }
    }
    module_result(module, matched)
}

/// Write a profile of one module and optionally reset its counts
/// (0x91f70770). Counting restarts afterwards even for a stopped module.
fn snapshot(node: Node, phase: Option<&[u8]>, reset: bool, kind: SweepKind) {
    stop_counting(node.0);
    match phase {
        Some(phase) => {
            let mut converted = [0u16; PATH_UNITS];
            report_illegal(pgo::decode_utf8(phase, &mut converted));
            write32(node.at(node::PHASE_SET), 1);
            write_units(node.at(node::PHASE), &WidePath::copy_from(&converted).0);
        }
        None => write16(node.at(node::PHASE), 0),
    }
    let block = node.block();
    let extended = format(block) == BlockFormat::Extended;
    if extended {
        write8(block + block::SWEEP_KIND, kind as u8);
        write8(block + block::RESETTING, u8::from(reset));
    }
    write_profile(node);
    if extended {
        write8(block + block::SWEEP_KIND, 0);
        write8(block + block::RESETTING, 0);
    }
    if reset {
        write64(block + block::TIME, block_time());
        reset_counts(block);
    }
    start_counting(node.0);
}

/// Export 110 and `pogoctrl snapshot` (0x91f70880).
fn snapshot_modules(phase: Option<&[u8]>, reset: bool, module: u32, kind: SweepKind) -> Hresult {
    let mut matched = false;
    for node in select(module) {
        matched = true;
        snapshot(node, phase, reset, kind);
    }
    module_result(module, matched)
}

/// `AllocScale` (0x91f70978).
fn set_allocation_scale(module: u32, scale: u32) -> Hresult {
    let Some(node) = (module != 0).then(|| find_node(module)).flatten() else {
        return pgo::NO_SUCH_MODULE;
    };
    if node.block() != 0 {
        return pgo::BLOCK_ALLOCATED;
    }
    write32(node.at(node::ALLOCATION_SCALE), scale);
    pgo::SUCCESS
}

/// `pogo.ini` options (0x91f709e0); the validation and sweep options are
/// global but still need a record without a count block.
fn set_option(module: u32, option: PgoOption, value: u32) -> Hresult {
    let Some(node) = (module != 0).then(|| find_node(module)).flatten() else {
        return pgo::NO_SUCH_MODULE;
    };
    if node.block() != 0 {
        return pgo::BLOCK_ALLOCATED;
    }
    let set = value != 0;
    match option {
        PgoOption::StandardPgc => write8(node.at(node::EXTENDED), u8::from(!set)),
        PgoOption::TestCounterOverflow => write8(node.at(node::FILL_COUNTERS), u8::from(set)),
        PgoOption::MaxTitleMemory => write32(node.at(node::TITLE_MEMORY), value),
        PgoOption::ValidateEplh => VALIDATE_EPLH.store(set, Ordering::Release),
        PgoOption::ValidateVplh => VALIDATE_VPLH.store(set, Ordering::Release),
        PgoOption::ValidateVple => VALIDATE_VPLE.store(set, Ordering::Release),
        PgoOption::EnableSweepOnOverflow => SWEEP_ON_OVERFLOW.store(set, Ordering::Release),
        PgoOption::EnableSweepFullBuffer => SWEEP_FULL_BUFFER.store(set, Ordering::Release),
    }
    pgo::SUCCESS
}

fn profile_request(access: u32, disposition: CreateDisposition) -> CreateRequest {
    CreateRequest {
        access: FileAccess(access | FileAccess::SYNCHRONIZE.0 | READ_ATTRIBUTES),
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess::NONE,
        disposition,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    }
}

/// Create the first free profile `<name>!<n>.pgc` from 1 (0x91f6d038).
/// The image also scans the directory for existing numbers but compares
/// the character after the name, which is always `!`, so the scan never
/// raises the start. `None` when a name can neither be created nor opened.
fn create_profile(name: &ProfileName) -> Option<u32> {
    let mut number = 1u32;
    loop {
        let mut bytes = [0u8; pgo::FILE_NAME_BYTES];
        let length = name.file_name(number, &mut bytes);
        let path = &bytes[..length];
        if let Ok(handle) = filesystem::create_file(
            path,
            &profile_request(FileAccess::GENERIC_WRITE.0, CreateDisposition::Create),
        ) {
            return Some(handle.0);
        }
        let handle = filesystem::create_file(
            path,
            &profile_request(FileAccess::GENERIC_READ.0, CreateDisposition::Open),
        )
        .ok()?;
        kernel::NtClose(handle.0);
        number = number.wrapping_add(1);
    }
}

fn write_file(handle: u32, buffer: u32, length: u32) -> bool {
    let mut io_status = IoStatusBlock::default();
    let mut status = kernel::NtWriteFile(
        handle,
        0,
        0,
        0,
        &mut io_status,
        buffer as usize as *const u8,
        length,
        core::ptr::null(),
    );
    if status == STATUS_PENDING {
        kernel::NtWaitForSingleObjectEx(handle, 1, 0, core::ptr::null());
        // SAFETY: the kernel completed the request and wrote the block.
        status = unsafe { core::ptr::read_volatile(&io_status.status) };
    }
    if (status as i32) < 0 {
        kernel::set_last_error(status);
        return false;
    }
    true
}

/// Write the count block to a new profile file (0x91f6d420), from the
/// module's directory or the devkit directory, then mark it complete.
fn write_profile(node: Node) {
    let base = node.base_path();
    let mut phase = [0u16; PATH_UNITS];
    let mut continuation = [0u16; PATH_UNITS];
    let phase_set = read32(node.at(node::PHASE_SET)) != 0;
    if phase_set {
        read_units(node.at(node::PHASE), &mut phase);
        read_units(node.at(node::MODULE_NAME), &mut continuation);
    }
    let phase = phase_set.then_some((&phase, &continuation[..]));
    let open = |path: &WidePath| {
        create_profile(&ProfileName::new(path, phase).unwrap_or_else(|failure| fatal(failure)))
    };
    let handle = open(&base)
        .or_else(|| open(&pgo::fallback_path(&base)))
        .unwrap_or_else(|| fatal(Fatal::WriteFailed));
    let block = node.block();
    let length = read32(block + block::USED).min(read32(block + block::COMMITTED));
    if !write_file(handle, block, length) {
        warn(WriteWarning::Write);
    }
    let mut io_status = IoStatusBlock::default();
    let status = kernel::NtFlushBuffersFile(handle, &mut io_status);
    if (status as i32) < 0 {
        kernel::set_last_error(status);
        warn(WriteWarning::Flush);
    }
    // The image reports a seek only when the new position is 0.
    let position = pgo::COMPLETION_OFFSET.to_be_bytes();
    let status = kernel::NtSetInformationFile(
        handle,
        &mut io_status,
        position.as_ptr(),
        8,
        FILE_POSITION_INFORMATION,
    );
    if (status as i32) < 0 {
        kernel::set_last_error(status);
    }
    let complete = 1u8;
    if !write_file(handle, &complete as *const u8 as usize as u32, 1) {
        warn(WriteWarning::Write);
    }
    if !close_handle(handle) {
        warn(WriteWarning::Close);
    }
}

/// The shutdown profile of one module (0x91f6d740).
fn shutdown_profile(node: Node) {
    stop_counting(node.0);
    write32(node.at(node::PHASE_SET), 0);
    let block = node.block();
    if format(block) == BlockFormat::Extended {
        write8(block + block::LIVE, 0);
        write8(block + block::SWEEP_KIND, SweepKind::Shutdown as u8);
    } else {
        write32(block + block::FULL_BUFFER_OR_LIVE, 0);
    }
    write_profile(node);
}

/// Title termination (0x91f6d7f8, last step of 0x91f32398): write a
/// profile of every module with a count block and forget the modules,
/// thread records, sweep event, and TLS slot.
pub(crate) fn title_terminated() {
    for node in modules() {
        if node.block() != 0 {
            shutdown_profile(node);
        }
    }
    MODULES.store(0, Ordering::Release);
    SWEEPING.store(false, Ordering::Release);
    THREADS.store(0, Ordering::Release);
    SWEEP_EVENT.store(0, Ordering::Release);
    TLS_INDEX.store(u32::MAX, Ordering::Release);
}

/// Prepare the registration lock; called once at module start, before
/// export 112 is reachable.
pub(super) fn initialize() {
    SECTION.initialize();
}

/// Export 108.
extern "C" fn export_start(module: u32) -> u32 {
    start_modules(module).0
}

/// Export 109.
extern "C" fn export_stop(module: u32) -> u32 {
    stop_modules(module).0
}

/// Export 110 (stock 0x91f70918): profile one module or all; `phase` may
/// be null.
extern "C" fn export_snapshot(phase: *const core::ffi::c_char, reset: u32, module: u32) -> u32 {
    let phase = (!phase.is_null()).then(|| {
        // SAFETY: the caller passes a NUL-terminated phase name.
        unsafe { core::ffi::CStr::from_ptr(phase) }.to_bytes_with_nul()
    });
    snapshot_modules(phase, reset != 0, module, SweepKind::Export).0
}

/// Export 111 (stock 0x91f6cba8).
extern "C" fn export_abort() {
    fatal(Fatal::ClientAbort);
}

/// Export 113 (stock 0x91f6b900): the base profile name (UTF-8), the
/// module header, and the module's word table for later registrations.
extern "C" fn export_set_module_info(
    name: *const core::ffi::c_char,
    module_header: u32,
    words: u32,
) {
    // A null name would fault the image; it is taken as unreadable.
    if name.is_null() {
        fatal(Fatal::BaseNameUnreadable);
    }
    // SAFETY: the caller passes a NUL-terminated name.
    let name = unsafe { core::ffi::CStr::from_ptr(name) }.to_bytes_with_nul();
    // SAFETY: registrations read the name after this call returns.
    let base_name = unsafe { &mut *BASE_NAME.0.get() };
    let decoded = pgo::decode_utf8(name, base_name);
    report_illegal(decoded);
    if !matches!(decoded.units, Ok(units) if units > 0) {
        fatal(Fatal::BaseNameUnreadable);
    }
    HEADER.store(module_header, Ordering::Release);
    WORDS.store(words, Ordering::Release);
}

/// Export 114 (stock 0x91f6d5d0): profile a module under a wide phase
/// name. The lookup runs without a name and never matches.
extern "C" fn export_phase_snapshot(address: u32, _phase: *const u16) {
    find_module(address, None);
}

/// Export 115 (stock 0x91f6d6c0): as export 114 with an ANSI phase,
/// which must convert into 0x104 units.
extern "C" fn export_ansi_phase_snapshot(address: u32, phase: *const core::ffi::c_char) {
    // A null phase would fault the image; it converts as empty.
    let length = if phase.is_null() {
        0
    } else {
        // SAFETY: the caller passes a NUL-terminated phase name.
        unsafe { core::ffi::CStr::from_ptr(phase) }.to_bytes().len()
    };
    if length + 1 > PATH_UNITS {
        fatal(Fatal::PhaseUnconvertible);
    }
    find_module(address, None);
}

export!(106, export_find_module);
export!(107, export_load_ini);
export!(108, export_start);
export!(109, export_stop);
export!(110, export_snapshot);
export!(111, export_abort);
export!(112, export_register);
export!(113, export_set_module_info);
export!(114, export_phase_snapshot);
export!(115, export_ansi_phase_snapshot);

fn control_result(result: Hresult) -> Result<(), PgoError> {
    match result {
        pgo::SUCCESS => Ok(()),
        pgo::BLOCK_ALLOCATED => Err(PgoError::Busy),
        _ => Err(PgoError::NoSuchModule),
    }
}

fn module_address(module: PgoModule) -> u32 {
    match module {
        PgoModule::All => 0,
        PgoModule::Record(address) => address,
    }
}

/// `pogoctrl start`.
pub(super) fn control_start(module: PgoModule) -> Result<(), PgoError> {
    control_result(start_modules(module_address(module)))
}

/// `pogoctrl stop`.
pub(super) fn control_stop(module: PgoModule) -> Result<(), PgoError> {
    control_result(stop_modules(module_address(module)))
}

/// `pogoctrl snapshot`: the phase is always set, empty when absent.
pub(super) fn control_snapshot(
    phase: &[u8],
    reset: bool,
    module: PgoModule,
) -> Result<(), PgoError> {
    control_result(snapshot_modules(
        Some(phase),
        reset,
        module_address(module),
        SweepKind::Control,
    ))
}

/// `pogoctrl allocscale`.
pub(super) fn control_allocation_scale(module: u32, scale: u32) -> Result<(), PgoError> {
    control_result(set_allocation_scale(module, scale))
}
