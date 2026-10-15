//! Hardware control services: virtual controllers, configuration hooks,
//! system service messages, the optical disc log, and NuiCam raw data
//! requests.

pub(crate) mod nuicam;
pub(super) mod pgo;

use core::cell::UnsafeCell;
use core::fmt::Write as _;
use core::num::NonZeroU32;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::NtStatus;
use openxbdm_server::ConnectionIndex;
use openxbdm_server::Server;
use openxbdm_server::commands;
use openxbdm_server::commands::filesystem::CreateDisposition;
use openxbdm_server::commands::filesystem::CreateOptions;
use openxbdm_server::commands::filesystem::CreateRequest;
use openxbdm_server::commands::filesystem::FileAccess;
use openxbdm_server::commands::filesystem::FileAttributes;
use openxbdm_server::commands::filesystem::FileHandle;
use openxbdm_server::commands::filesystem::ObjectPath;
use openxbdm_server::commands::filesystem::ShareAccess;
use openxbdm_server::commands::filesystem::nt;
use openxbdm_server::commands::hardware::AvatarError;
use openxbdm_server::commands::hardware::AvatarHook;
use openxbdm_server::commands::hardware::ExportMissing;
use openxbdm_server::commands::hardware::InputOwner;
use openxbdm_server::commands::hardware::OddLogNotRunning;
use openxbdm_server::commands::hardware::OddLogStartError;
use openxbdm_server::commands::hardware::PgoError;
use openxbdm_server::commands::hardware::PgoModule;
use openxbdm_server::commands::hardware::PlayToCommand;
use openxbdm_server::commands::hardware::PlayToState;
use openxbdm_server::commands::hardware::StackAddresses;
use openxbdm_server::commands::hardware::automation;
use openxbdm_server::commands::hardware::automation::Automation;
use openxbdm_server::commands::hardware::automation::AutomationError;
use openxbdm_server::commands::hardware::automation::Controllers;
use openxbdm_server::commands::hardware::automation::DebuggerMessage;
use openxbdm_server::commands::hardware::automation::Gamepad;
use openxbdm_server::commands::hardware::automation::InputPlatform;
use openxbdm_server::commands::hardware::automation::Poll;
use openxbdm_server::commands::hardware::automation::QueueEntry;
use openxbdm_server::commands::hardware::automation::QueueStatus;
use openxbdm_server::commands::hardware::automation::UploadLayout;
use openxbdm_server::text::Text;

use super::Console;
use super::dispatcher;
use super::network::xam_procedure;
use super::performance::pix;
use crate::exports::export;
use crate::kernel;
use crate::kernel::KernelEvent;
use crate::kernel::LIB_KERNEL;
use crate::kernel::LIB_XAM;
use crate::kernel::SpinLocked;
use crate::kernel::import_thunk;
use crate::net::XamNetwork;

import_thunk!(
    XAutomationpBindController(user: u32) -> u32,
    lib = LIB_XAM,
    ordinal = 0x3d5
);
import_thunk!(
    XAutomationpUnbindController(user: u32) -> u32,
    lib = LIB_XAM,
    ordinal = 0x3d6
);
import_thunk!(
    XAutomationpInputXenonButton(user: u32) -> u32,
    lib = LIB_XAM,
    ordinal = 0x3d7
);
import_thunk!(
    XInputdSetRFPowerMode(enable: u32) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x1ef
);

/// XAM ordinal: input focus query, nonzero when the system has focus.
const XAM_INPUT_FOCUS: u32 = 0x3dd;
/// XAM ordinal: avatar test hook lookup `(index, &function) -> HRESULT`.
const XAM_AVATAR_HOOKS: u32 = 0x5f2;
/// XAM ordinal: heap information `(id, class, buffer) -> HRESULT`.
const XAM_HEAP_INFO: u32 = 0x827;
/// XAM ordinal: heap counts `(buffer) -> HRESULT`.
const XAM_HEAP_COUNT: u32 = 0x828;
/// Kernel ordinal: USB port power `(controller, port, enable) -> NTSTATUS`.
const KERNEL_USB_PORT_POWER: u32 = 825;
/// Monitor service: devkit memory statistics.
const MONITOR_MEMORY_STATISTICS: u32 = 8;
/// Media service application and PlayTo message.
const MEDIA_APP: u32 = 0xf0;
const MEDIA_PLAY_TO: u32 = 0x900002;
/// Caller identifier passed to the network address queries.
const NETWORK_CALLER: u32 = 3;
const XNADDR_SIZE: usize = 0x24;
const STATUS_DEVICE_NOT_CONNECTED: u32 = 0xc000_009d;
const ERROR_DEVICE_NOT_CONNECTED: u32 = 0x48f;
const POOL_TAG_CONTROLLER: u32 = 0x646d_6175;
const POOL_TAG_UPLOAD: u32 = 0x444d_4155;
const POOL_TYPE: u32 = 2;
const MAX_CONNECTIONS: usize = 8;

/// Pool memory owned by a Rust value; freed on drop.
struct PoolBlock {
    address: NonZeroU32,
    len: usize,
}

impl PoolBlock {
    fn allocate(bytes: u64, tag: u32) -> Option<Self> {
        let size = u32::try_from(bytes).ok()?;
        let address = NonZeroU32::new(kernel::ExAllocatePoolTypeWithTag(size, tag, POOL_TYPE))?;
        let block = Self {
            address,
            len: size as usize,
        };
        // SAFETY: the pool returned `size` writable bytes at `address`.
        unsafe { core::ptr::write_bytes(block.base(), 0, block.len) };
        Some(block)
    }

    fn base(&self) -> *mut u8 {
        self.address.get() as usize as *mut u8
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: the block owns `len` bytes at `address` until dropped.
        unsafe { core::slice::from_raw_parts(self.base(), self.len) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `bytes`, with exclusive access through `&mut self`.
        unsafe { core::slice::from_raw_parts_mut(self.base(), self.len) }
    }
}

impl Drop for PoolBlock {
    fn drop(&mut self) {
        kernel::ExFreePool(self.address.get());
    }
}

/// Queue storage of a controller in pool memory.
pub struct PoolEntries {
    block: PoolBlock,
    count: usize,
}

impl AsRef<[QueueEntry]> for PoolEntries {
    fn as_ref(&self) -> &[QueueEntry] {
        // SAFETY: the block holds `count` zeroed entries, a valid bit
        // pattern, and pool memory is suitably aligned.
        unsafe { core::slice::from_raw_parts(self.block.base().cast::<QueueEntry>(), self.count) }
    }
}

impl AsMut<[QueueEntry]> for PoolEntries {
    fn as_mut(&mut self) -> &mut [QueueEntry] {
        // SAFETY: as `as_ref`, with exclusive access through `&mut self`.
        unsafe {
            core::slice::from_raw_parts_mut(self.block.base().cast::<QueueEntry>(), self.count)
        }
    }
}

/// The input system polls the controllers from other threads.
static AUTOMATION: SpinLocked<Automation<PoolEntries>> = SpinLocked::new(Automation::new());
/// Title decompression ignores GDF attributes (`tdecomp`).
static IGNORE_GDF_ATTRIBUTES: AtomicBool = AtomicBool::new(false);

struct Input;

impl InputPlatform for Input {
    fn tick(&mut self) -> u32 {
        kernel::tick_count()
    }

    fn press_guide(&mut self, user: u32) {
        XAutomationpInputXenonButton(user);
    }
}

struct XboxControllers;

impl Controllers for XboxControllers {
    type Storage = PoolEntries;

    fn locked<R>(
        &mut self,
        operation: impl FnOnce(&mut Automation<PoolEntries>, &mut dyn InputPlatform) -> R,
    ) -> R {
        AUTOMATION.with(|automation| operation(automation, &mut Input))
    }

    fn allocate(&mut self, queue_length: u32) -> Option<PoolEntries> {
        let block = PoolBlock::allocate(
            automation::allocation_size(queue_length),
            POOL_TAG_CONTROLLER,
        )?;
        let count = automation::storage_entries(queue_length);
        if count * core::mem::size_of::<QueueEntry>() > block.len {
            return None;
        }
        Some(PoolEntries { block, count })
    }

    fn bind_controller(&mut self, user: u32) -> bool {
        XAutomationpBindController(user) != 0
    }

    fn unbind_controller(&mut self, user: u32) -> bool {
        XAutomationpUnbindController(user) != 0
    }

    fn tell_debugger(&mut self, message: DebuggerMessage) {
        let (payload, _) = message.payload();
        let slot = kernel::KE_DEBUG_MONITOR_DATA.load(Ordering::Relaxed);
        // SAFETY: the loader stored the address of the kernel variable.
        let block = unsafe { core::ptr::read_volatile(slot as usize as *const u32) };
        if block == 0 {
            return;
        }
        // SAFETY: a published monitor data block holds the control routine at +0x18.
        let control = unsafe { core::ptr::read_volatile((block as usize + 0x18) as *const u32) };
        if control != 0 {
            // SAFETY: the control routine takes a code and a data pointer.
            unsafe {
                kernel::call_export(
                    control,
                    message.code(),
                    payload.as_ptr() as usize as u32,
                    0,
                    0,
                )
            };
        }
    }
}

/// Address of an export, resolved once and cached; absent exports are
/// looked up again on the next use, as the monitor does.
struct CachedExport(AtomicU32);

impl CachedExport {
    const fn new() -> Self {
        Self(AtomicU32::new(0))
    }

    /// XAM exports are resolved without the entry point check.
    fn xam(&self, ordinal: u32) -> Option<u32> {
        let cached = self.0.load(Ordering::Relaxed);
        if cached != 0 {
            return Some(cached);
        }
        let address = xam_procedure(ordinal).filter(|&address| address != 0)?;
        self.0.store(address, Ordering::Relaxed);
        Some(address)
    }

    fn kernel(&self, ordinal: u32) -> Option<u32> {
        let cached = self.0.load(Ordering::Relaxed);
        if cached != 0 {
            return Some(cached);
        }
        let module = kernel::module_handle(c"xboxkrnl.exe").ok()?;
        let address = kernel::resolve_export(module, ordinal).ok()?;
        self.0.store(address, Ordering::Relaxed);
        Some(address)
    }
}

/// XAM input focus query, resolved once at startup (stock 0x91f25288 into
/// 0x91f9e47c, without the entry point check).
static INPUT_FOCUS: AtomicU32 = AtomicU32::new(0);

fn input_focus() -> Option<u32> {
    Some(INPUT_FOCUS.load(Ordering::Relaxed)).filter(|&address| address != 0)
}

static HEAP_COUNT: CachedExport = CachedExport::new();
static HEAP_INFO: CachedExport = CachedExport::new();
static USB_PORT_POWER: CachedExport = CachedExport::new();

fn address_of<T: ?Sized>(value: &T) -> u32 {
    value as *const T as *const u8 as usize as u32
}

/// Address of a buffer a console service writes.
fn output_address<T: ?Sized>(value: &mut T) -> u32 {
    value as *mut T as *mut u8 as usize as u32
}

/// Platform state of this domain.
pub struct Data {
    uploads: [Option<PoolBlock>; MAX_CONNECTIONS],
}

impl Data {
    pub const fn new() -> Self {
        Self {
            uploads: [const { None }; MAX_CONNECTIONS],
        }
    }
}

fn read_word(address: u32) -> u32 {
    // SAFETY: callers pass addresses the input system supplied for output.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn write_word(address: u32, value: u32) {
    // SAFETY: as `read_word`.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

fn write_bytes(address: u32, bytes: &[u8]) {
    // SAFETY: as `read_word`; the destination holds `bytes.len()` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), address as usize as *mut u8, bytes.len())
    }
}

/// Monitor control 0x7a: current state of a virtual controller. `request`
/// is `{u32 user, u32 state, u32 status}`; `state` receives the packet
/// number and the gamepad. Returns 1 when the slot has a controller.
pub(crate) fn service_automation_get_state(request: u32) -> u32 {
    let user = read_word(request);
    let state = read_word(request + 4);
    let status = read_word(request + 8);
    match AUTOMATION.with(|automation| automation.poll(user, &mut Input)) {
        None => 0,
        Some(Poll::NotConnected) => {
            write_word(status, STATUS_DEVICE_NOT_CONNECTED);
            1
        }
        Some(Poll::State {
            packet_number,
            packet,
        }) => {
            write_word(status, 0);
            if state != 0 {
                write_word(state, packet_number);
                write_bytes(state + 4, &packet.to_console());
            }
            1
        }
    }
}

/// Monitor control 0x7b: connection status of a virtual controller.
/// `request` is `{u32 user, u32 unused, u32 status}`.
pub(crate) fn service_automation_get_status(request: u32) -> u32 {
    let user = read_word(request);
    let status = read_word(request + 8);
    match AUTOMATION.with(|automation| automation.is_connected(user)) {
        None => 0,
        Some(connected) => {
            write_word(
                status,
                if connected {
                    0
                } else {
                    ERROR_DEVICE_NOT_CONNECTED
                },
            );
            1
        }
    }
}

/// Capabilities reported for a connected virtual controller.
const CAPABILITIES: [u8; 20] = [
    1, 1, 0, 0xe, 0xff, 0xff, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0,
];

/// Monitor control 0x7c: capabilities of a virtual controller.
/// `request` is `{u32 user, u32 capabilities, u32 status}`.
pub(crate) fn service_automation_get_capabilities(request: u32) -> u32 {
    let user = read_word(request);
    let capabilities = read_word(request + 4);
    let status = read_word(request + 8);
    match AUTOMATION.with(|automation| automation.is_connected(user)) {
        None => 0,
        Some(true) => {
            write_word(status, 0);
            if capabilities != 0 {
                write_bytes(capabilities, &CAPABILITIES);
            }
            1
        }
        Some(false) => {
            write_word(status, ERROR_DEVICE_NOT_CONNECTED);
            1
        }
    }
}

/// Monitor control 0x21, first step: the input system restarted; bind
/// every installed controller again. Returns nothing meaningful; the
/// dispatcher continues with the title launch handling.
pub(crate) fn service_automation_rebind(_argument: u32) -> u32 {
    automation::rebind_all(&mut XboxControllers);
    0
}

/// Monitor control 0x7e without the DVD emulator check: whether title
/// decompression ignores GDF attributes. The dispatcher answers 1 instead
/// when the attached DVD emulator reports protocol 0002.
pub(crate) fn service_ignore_gdf_attributes(_argument: u32) -> u32 {
    u32::from(IGNORE_GDF_ATTRIBUTES.load(Ordering::Relaxed))
}

/// Record words of a slot, laid out per record kind; a timebase value
/// takes two words, high word first.
type OddWords = [u32; 7];

const ODD_RING: usize = 64;
/// Slot states; a ready slot's state is the kind of its record.
const SLOT_FREE: u32 = 0;
const SLOT_WRITING: u32 = 1;
/// `{start, count, requested, completed, status}`.
const SLOT_READ: u32 = 2;
/// `{sector, size, time}`.
const SLOT_MOUNT: u32 = 3;
/// `{current, target, status, time}`.
const SLOT_SPEED_CHANGE: u32 = 4;

struct OddSlot {
    state: AtomicU32,
    words: UnsafeCell<OddWords>,
}

/// Optical disc log: a ring filled by drive events and drained by the
/// writer thread.
struct OddLog {
    /// Nonzero when no log is being written; drive events are dropped.
    stopped: AtomicU32,
    /// A start owns the writer.
    busy: AtomicU32,
    allocate: AtomicU32,
    drops: AtomicU32,
    read: AtomicU32,
    slots: [OddSlot; ODD_RING],
    /// Read started by the drive and not yet completed.
    pending_start: AtomicU32,
    pending_count: AtomicU32,
    pending_time_high: AtomicU32,
    pending_time_low: AtomicU32,
    work: KernelEvent,
    /// Notification event: no writer runs.
    finished: KernelEvent,
    thread: AtomicU32,
}

// SAFETY: a slot's record is accessed only by the owner of its state.
unsafe impl Sync for OddLog {}

static ODD_LOG: OddLog = OddLog {
    stopped: AtomicU32::new(1),
    busy: AtomicU32::new(0),
    allocate: AtomicU32::new(ODD_RING as u32 - 1),
    drops: AtomicU32::new(0),
    read: AtomicU32::new(0),
    slots: [const {
        OddSlot {
            state: AtomicU32::new(SLOT_FREE),
            words: UnsafeCell::new([0; 7]),
        }
    }; ODD_RING],
    pending_start: AtomicU32::new(0),
    pending_count: AtomicU32::new(0),
    pending_time_high: AtomicU32::new(0),
    pending_time_low: AtomicU32::new(0),
    work: KernelEvent::new(),
    finished: KernelEvent::new(),
    thread: AtomicU32::new(0),
};

const ODD_LOG_HEADER: &[u8] = b"# Optical Disc Log Created on Console\r\n\
# Log Format Information:\r\n\
# READ,<StartSector>,<SectorCount>,<RequestTime_100ns>,<CompleteTime_100ns>,<NTSTATUS>,;for each read operation\r\n\
# GMNT,<RootDirStartSector>,<RootDirSize_bytes>,<Time_100ns>,;when GDFX filesystem is mounted\r\n\
# SSC ,<CurrentSpeed>,<TargetSpeed>,<NTSTATUS>,<Time_100ns>,;for each spindle speed change\r\n\
# DROP,<DropCount>,;indicates dropped log entries\r\n";

const ODD_WRITER_STACK: u32 = 0x8000;
const ODD_WRITER_FLAGS: u32 = 0x0400_02a6;

impl OddLog {
    /// Queue a record of `kind` (a `SLOT_*` ready state).
    fn publish(&self, kind: u32, words: OddWords) {
        if self.stopped.load(Ordering::Acquire) == 1 {
            return;
        }
        let mut index = self.allocate.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        if index >= ODD_RING as u32 {
            let wrapped = index % ODD_RING as u32;
            let _ =
                self.allocate
                    .compare_exchange(index, wrapped, Ordering::AcqRel, Ordering::Relaxed);
            index = wrapped;
        }
        let slot = &self.slots[index as usize];
        if slot
            .state
            .compare_exchange(SLOT_FREE, SLOT_WRITING, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            self.drops.fetch_add(1, Ordering::AcqRel);
            return;
        }
        // SAFETY: the slot is owned by this writer while its state is WRITING.
        unsafe { *slot.words.get() = words };
        slot.state.store(kind, Ordering::Release);
        self.work.set();
    }
}

/// Timebase ticks per 100 ns unit.
const TIMEBASE_PER_100NS: i64 = 5;

fn hundred_ns(high: u32, low: u32) -> u64 {
    let timebase = u64::from(high) << 32 | u64::from(low);
    (timebase as i64 / TIMEBASE_PER_100NS) as u64
}

fn speed_name(code: u32) -> &'static str {
    match code {
        1 => "2.4x",
        2 => "5x",
        3 => "8x",
        4 => "12x",
        _ => "Unknown",
    }
}

fn write_text(handle: u32, text: &[u8]) {
    let mut io_status = kernel::IoStatusBlock {
        status: 0,
        information: 0,
    };
    kernel::NtWriteFile(
        handle,
        0,
        0,
        0,
        &mut io_status,
        text.as_ptr(),
        text.len() as u32,
        core::ptr::null(),
    );
}

/// Trace stream record tag `ODD `.
const ODD_TRACE_TAG: u32 = 0x4f44_4420;
/// Bit 0 of the record's low time word: set on completion records.
const ODD_TRACE_COMPLETION: u32 = 1;

/// Trace record payload: the words in console memory order.
fn trace_payload<const WORDS: usize>(words: [u32; WORDS]) -> [[u8; 4]; WORDS] {
    words.map(u32::to_be_bytes)
}

/// Monitor control 0x46: the drive started a read; `request` is
/// `{u32 sector, u32 count}`.
pub(crate) fn service_odd_read_start(request: u32) -> u32 {
    let (start, count) = (read_word(request), read_word(request + 4));
    let time = kernel::timebase();
    if pix::stream_active() {
        let words = [
            (time >> 32) as u32,
            time as u32 & !ODD_TRACE_COMPLETION,
            start,
            count,
            ODD_AUTH_STATE.load(Ordering::Relaxed),
        ];
        pix::write_tagged_record(ODD_TRACE_TAG, trace_payload(words).as_flattened());
    }
    let log = &ODD_LOG;
    if log.stopped.load(Ordering::Acquire) != 1 {
        log.pending_start.store(start, Ordering::Relaxed);
        log.pending_count.store(count, Ordering::Relaxed);
        log.pending_time_high
            .store((time >> 32) as u32, Ordering::Relaxed);
        log.pending_time_low.store(time as u32, Ordering::Release);
    }
    0
}

/// Monitor control 0x47: the pending read completed; the argument is the
/// completion status itself.
pub(crate) fn service_odd_read_complete(status: u32) -> u32 {
    let completed = kernel::timebase();
    if pix::stream_active() {
        let words = [
            (completed >> 32) as u32,
            completed as u32 | ODD_TRACE_COMPLETION,
            status,
        ];
        pix::write_tagged_record(ODD_TRACE_TAG, trace_payload(words).as_flattened());
    }
    let log = &ODD_LOG;
    let low = log.pending_time_low.load(Ordering::Acquire);
    let high = log.pending_time_high.load(Ordering::Relaxed);
    if high != 0 || low != 0 {
        log.publish(
            SLOT_READ,
            [
                log.pending_start.load(Ordering::Relaxed),
                log.pending_count.load(Ordering::Relaxed),
                high,
                low,
                (completed >> 32) as u32,
                completed as u32,
                status,
            ],
        );
    }
    0
}

/// Monitor control 0x48: a GDFX volume was mounted; `request` holds the
/// volume descriptor's root directory sector and size first.
pub(crate) fn service_odd_mount(request: u32) -> u32 {
    let (sector, size) = (read_word(request), read_word(request + 4));
    let time = kernel::timebase();
    ODD_LOG.publish(
        SLOT_MOUNT,
        [sector, size, (time >> 32) as u32, time as u32, 0, 0, 0],
    );
    0
}

/// Monitor control 0x49: the spindle speed changed; `request` is
/// `{u32 current, u32 target, u32 status}`.
pub(crate) fn service_odd_speed_change(request: u32) -> u32 {
    let (current, target, status) = (
        read_word(request),
        read_word(request + 4),
        read_word(request + 8),
    );
    let time = kernel::timebase();
    ODD_LOG.publish(
        SLOT_SPEED_CHANGE,
        [
            current,
            target,
            status,
            (time >> 32) as u32,
            time as u32,
            0,
            0,
        ],
    );
    0
}

/// Drive authentication state kept for the optical disc trace stream.
static ODD_AUTH_STATE: AtomicU32 = AtomicU32::new(0);

/// States 1 to 4 are kept; anything else reads as 0.
fn odd_auth_state(state: u32) -> u32 {
    if (1..=4).contains(&state) { state } else { 0 }
}

/// Monitor control 0x4a: the drive authentication state changed.
pub(crate) fn service_odd_auth_state(state: u32) -> u32 {
    ODD_AUTH_STATE.store(odd_auth_state(state), Ordering::Relaxed);
    0
}

const OPTICAL_DRIVE: &[u8] = b"\\Device\\CdRom0";
const IOCTL_ODD_AUTH_STATE: u32 = 0x2_40cc;
/// Object attributes stock passes when opening the drive.
const OPTICAL_DRIVE_ATTRIBUTES: u32 = 0x50;

/// Startup steps of this domain, in stock's order (0x91f32628).
pub(crate) fn initialize() {
    pgo::initialize();
    odd_initialize();
    if let Some(address) = xam_procedure(XAM_INPUT_FOCUS) {
        INPUT_FOCUS.store(address, Ordering::Relaxed);
    }
    nuicam::initialize();
}

/// Startup (0x91f3d558): the log's events, then the drive's current
/// authentication state.
fn odd_initialize() {
    ODD_LOG.work.initialize();
    ODD_LOG.finished.initialize_notification(true);
    let name = kernel::AnsiString::new(OPTICAL_DRIVE);
    let attributes = kernel::ObjectAttributes {
        root_directory: 0,
        object_name: &name,
        attributes: OPTICAL_DRIVE_ATTRIBUTES,
    };
    let mut io_status = kernel::IoStatusBlock::default();
    let mut handle = 0u32;
    let opened = kernel::NtCreateFile(
        &mut handle,
        FileAccess::GENERIC_READ.0,
        &attributes,
        &mut io_status,
        core::ptr::null(),
        FileAttributes::NORMAL.0,
        0,
        CreateDisposition::Open as u32,
        CreateOptions::SYNCHRONOUS_IO_NONALERT.0,
    );
    if (opened as i32) < 0 {
        return;
    }
    // Stock reads the output even when the request fails (uninitialized
    // stack); a failed request leaves 0 here.
    let mut state = [0u8; 4];
    kernel::NtDeviceIoControlFile(
        handle,
        0,
        0,
        0,
        &mut io_status,
        IOCTL_ODD_AUTH_STATE,
        core::ptr::null(),
        0,
        state.as_mut_ptr(),
        4,
    );
    ODD_AUTH_STATE.store(odd_auth_state(u32::from_be_bytes(state)), Ordering::Relaxed);
    kernel::NtClose(handle);
}

fn odd_write_record(handle: u32, kind: u32, words: OddWords) {
    let mut line = Text::<0x100>::new();
    let _ = match kind {
        SLOT_MOUNT => {
            let [sector, size, high, low, ..] = words;
            write!(
                line,
                "GMNT,0x{sector:08x},0x{:016x},0x{:016x}\r\n",
                u64::from(size),
                hundred_ns(high, low)
            )
        }
        SLOT_READ => {
            let [
                start,
                count,
                requested_high,
                requested_low,
                high,
                low,
                status,
            ] = words;
            write!(
                line,
                "READ,0x{start:08x},0x{count:08x},0x{:016x},0x{:016x},0x{status:08x}\r\n",
                hundred_ns(requested_high, requested_low),
                hundred_ns(high, low)
            )
        }
        _ => {
            let [current, target, status, high, low, ..] = words;
            write!(
                line,
                "SSC ,{},{},0x{status:08X},0x{:016x}\r\n",
                speed_name(current),
                speed_name(target),
                hundred_ns(high, low)
            )
        }
    };
    write_text(handle, line.as_bytes());
}

fn odd_drain(handle: u32) {
    let log = &ODD_LOG;
    loop {
        let index = log.read.load(Ordering::Relaxed);
        let slot = &log.slots[index as usize];
        let kind = slot.state.load(Ordering::Acquire);
        if kind < SLOT_READ {
            break;
        }
        // SAFETY: a ready slot is owned by the writer thread.
        let words = unsafe { *slot.words.get() };
        odd_write_record(handle, kind, words);
        slot.state.store(SLOT_FREE, Ordering::Release);
        log.read
            .store((index + 1) % ODD_RING as u32, Ordering::Relaxed);
    }
    let drops = log.drops.swap(0, Ordering::AcqRel);
    if drops != 0 {
        let mut line = Text::<0x20>::new();
        let _ = write!(line, "DROP,0x{drops:08x}\r\n");
        write_text(handle, line.as_bytes());
    }
}

/// Writer thread; the context is the log file handle.
extern "C" fn odd_writer(handle: u32) -> u32 {
    let log = &ODD_LOG;
    while log.stopped.load(Ordering::Acquire) == 0 {
        log.work.wait();
        odd_drain(handle);
    }
    kernel::NtClose(handle);
    log.finished.set();
    0
}

fn failed(status: u32) -> bool {
    status & 0xc000_0000 == 0xc000_0000
}

/// Start the optical disc log (stock export 147 0x91f3dad0).
fn odd_log_start(path: Result<&[u8], NtStatus>) -> Result<(), OddLogStartError> {
    let log = &ODD_LOG;
    if log
        .busy
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return Err(OddLogStartError::Busy);
    }
    for slot in &log.slots {
        slot.state.store(SLOT_FREE, Ordering::Relaxed);
    }
    log.read.store(0, Ordering::Relaxed);
    log.drops.store(0, Ordering::Relaxed);
    log.allocate.store(ODD_RING as u32 - 1, Ordering::Relaxed);
    log.pending_time_low.store(0, Ordering::Relaxed);
    log.pending_time_high.store(0, Ordering::Relaxed);
    log.finished.reset();
    log.stopped.store(0, Ordering::Release);

    let request = CreateRequest {
        access: FileAccess::GENERIC_WRITE,
        allocation_size: None,
        attributes: FileAttributes::NORMAL,
        share: ShareAccess(5),
        disposition: CreateDisposition::OverwriteIf,
        options: CreateOptions::SYNCHRONOUS_IO_NONALERT,
    };
    let opened = path.and_then(|path| super::filesystem::create_file(path, &request));
    let status = match opened {
        Ok(FileHandle(handle)) => {
            let mut io_status = kernel::IoStatusBlock {
                status: 0,
                information: 0,
            };
            let status = kernel::NtWriteFile(
                handle,
                0,
                0,
                0,
                &mut io_status,
                ODD_LOG_HEADER.as_ptr(),
                ODD_LOG_HEADER.len() as u32,
                core::ptr::null(),
            );
            if failed(status) {
                kernel::NtClose(handle);
            } else {
                let mut thread = 0u32;
                let created = kernel::ExCreateThread(
                    &mut thread,
                    ODD_WRITER_STACK,
                    core::ptr::null_mut(),
                    0,
                    odd_writer as *const () as usize as u32,
                    handle,
                    ODD_WRITER_FLAGS,
                );
                if failed(created) {
                    // Stock leaves the finished event clear here, so its
                    // next stop waits forever; no writer runs, so mark it
                    // finished.
                    kernel::NtClose(handle);
                    log.finished.set();
                    log.busy.store(0, Ordering::Release);
                    return Err(OddLogStartError::Failed(NtStatus(created)));
                }
                // A stop that ran before this store left the previous
                // object behind.
                let previous = log.thread.swap(thread, Ordering::AcqRel);
                if previous != 0 {
                    kernel::ObDereferenceObject(previous);
                }
                return Ok(());
            }
            status
        }
        Err(status) => status.0,
    };
    // Stock's writer reports the open or header status and exits, setting
    // the finished event; only statuses with both severity bits set fail
    // the start. The stop flag stays clear, so a later stop succeeds.
    log.finished.set();
    if failed(status) {
        log.busy.store(0, Ordering::Release);
        return Err(OddLogStartError::Failed(NtStatus(status)));
    }
    Ok(())
}

/// Stop the optical disc log and wait for its writer (stock export 148
/// 0x91f3d140).
fn odd_log_stop() -> Result<(), OddLogNotRunning> {
    let log = &ODD_LOG;
    if log
        .stopped
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return Err(OddLogNotRunning);
    }
    log.work.set();
    log.finished.wait();
    // Creation flag 0x80 returns a referenced thread object rather than a
    // handle.
    let thread = log.thread.swap(0, Ordering::AcqRel);
    if thread != 0 {
        kernel::ObDereferenceObject(thread);
    }
    log.busy.store(0, Ordering::Release);
    Ok(())
}

/// The XAM input focus query for `user`; nonzero when the system has
/// focus.
fn query_input_focus(user: u32) -> Result<u32, ExportMissing> {
    let function = input_focus().ok_or(ExportMissing)?;
    // SAFETY: the query takes the user index.
    Ok(unsafe { kernel::call_export(function, user, 0, 0, 0) })
}

fn automation_hresult(result: Result<(), AutomationError>) -> u32 {
    result.map_or_else(|error| error.hresult().0, |()| Hresult::OK.0)
}

// Shared by the exports and the command backend.
#[inline(never)]
fn connect(user: u32) -> Result<(), AutomationError> {
    AUTOMATION.with(|automation| automation.connect(user))
}

#[inline(never)]
fn disconnect(user: u32) -> Result<(), AutomationError> {
    AUTOMATION.with(|automation| automation.disconnect(user))
}

#[inline(never)]
fn clear_queue(user: u32) -> Result<(), AutomationError> {
    AUTOMATION.with(|automation| automation.clear_queue(user))
}

#[inline(never)]
fn query_queue(user: u32) -> Result<QueueStatus, AutomationError> {
    AUTOMATION.with(|automation| automation.query(user, &mut Input))
}

/// Export 166 (stock 0x91f24468): input focus of `user` into `focus`;
/// 0 and `407` when the XAM query is absent.
extern "C" fn export_query_input_focus(user: u32, focus: *mut u32) -> u32 {
    let (value, result) = match query_input_focus(user) {
        Ok(value) => (value, Hresult::OK),
        Err(ExportMissing) => (0, Hresult::from_error_code(ErrorCode::UNKNOWN_COMMAND)),
    };
    // SAFETY: the caller passes a writable dword.
    unsafe { focus.write_volatile(value) };
    result.0
}

/// Export 167 (stock 0x91f24c08): `autoinput bind`.
extern "C" fn export_automation_bind(user: u32, queue_length: u32) -> u32 {
    automation_hresult(automation::bind(&mut XboxControllers, user, queue_length))
}

/// Export 168 (stock 0x91f24d60): `autoinput unbind`.
extern "C" fn export_automation_unbind(user: u32) -> u32 {
    automation_hresult(automation::unbind(&mut XboxControllers, user))
}

/// Export 169 (stock 0x91f244c8): `autoinput connect`.
extern "C" fn export_automation_connect(user: u32) -> u32 {
    automation_hresult(connect(user))
}

/// Export 170 (stock 0x91f24580): `autoinput disconnect`.
extern "C" fn export_automation_disconnect(user: u32) -> u32 {
    automation_hresult(disconnect(user))
}

/// Export 171 (stock 0x91f24e20): `autoinput setpacket` with a gamepad
/// state in console layout.
extern "C" fn export_automation_set_packet(
    user: u32,
    packet: *const [u8; Gamepad::WIRE_SIZE],
) -> u32 {
    if user >= automation::USERS {
        return AutomationError::BadParameter.hresult().0;
    }
    // SAFETY: the caller passes a gamepad state.
    let packet = unsafe { packet.read_unaligned() };
    let packet = Gamepad::from_console(&packet);
    automation_hresult(automation::set_packet(&mut XboxControllers, user, packet))
}

/// Export 172 (stock 0x91f24f90): queue `count` gamepad states in console
/// layout with optional time and poll-count arrays; `queued` receives the
/// number accepted.
extern "C" fn export_automation_queue(
    user: u32,
    packets: *const [u8; Gamepad::WIRE_SIZE],
    times: *const u32,
    counts: *const u32,
    count: u32,
    queued: *mut u32,
) -> u32 {
    if user >= automation::USERS
        || packets.is_null()
        || queued.is_null()
        || (times.is_null() && counts.is_null())
    {
        return AutomationError::BadParameter.hresult().0;
    }
    let layout = UploadLayout {
        count,
        times: !times.is_null(),
        counts: !counts.is_null(),
    };
    // SAFETY: the caller passes `count` states and, where present, `count`
    // times and counts.
    let entry = |item: usize| unsafe {
        QueueEntry {
            packet: Gamepad::from_console(&packets.add(item).read_unaligned()),
            time: if times.is_null() {
                0
            } else {
                times.add(item).read_unaligned()
            },
            count: if counts.is_null() {
                0
            } else {
                counts.add(item).read_unaligned()
            },
        }
    };
    match AUTOMATION.with(|automation| automation.queue_entries(user, layout, entry, &mut Input)) {
        Ok(accepted) => {
            // SAFETY: checked non-null above; the caller passes a writable dword.
            unsafe { queued.write_volatile(accepted) };
            Hresult::OK.0
        }
        Err(error) => error.hresult().0,
    }
}

/// Export 173 (stock 0x91f24630): `autoinput clearqueue`.
extern "C" fn export_automation_clear_queue(user: u32) -> u32 {
    automation_hresult(clear_queue(user))
}

/// Export 174 (stock 0x91f246c8): `autoinput queryqueue`; every present
/// output is cleared first.
extern "C" fn export_automation_query_queue(
    user: u32,
    queue_length: *mut u32,
    queued: *mut u32,
    remaining_ms: *mut u32,
    remaining_count: *mut u32,
) -> u32 {
    if user >= automation::USERS {
        return AutomationError::BadParameter.hresult().0;
    }
    let outputs = [queue_length, queued, remaining_ms, remaining_count];
    let store = |values: [u32; 4]| {
        for (output, value) in outputs.into_iter().zip(values) {
            if !output.is_null() {
                // SAFETY: the caller passes writable dwords or null.
                unsafe { output.write_volatile(value) };
            }
        }
    };
    store([0; 4]);
    match query_queue(user) {
        Ok(status) => {
            store([
                status.queue_length,
                status.queued,
                status.remaining_ms,
                status.remaining_count,
            ]);
            Hresult::OK.0
        }
        Err(error) => error.hresult().0,
    }
}

/// Request of [`translate_on_server`].
struct Translation<'a> {
    name: &'a [u8],
    path: Option<ObjectPath>,
}

fn translate_on_server(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    request: u32,
) -> u32 {
    // SAFETY: the poster waits in `call_on_server` while the request lives.
    let request = unsafe { &mut *(request as usize as *mut Translation<'_>) };
    request.path = server
        .state
        .filesystem
        .drives
        .translate(console, request.name);
    0
}

/// Export 147 (stock 0x91f3dad0): start the optical disc log at the drive
/// path `path`. Stock's writer translates it through the drive table
/// (0x91f2eb68); the table is server state, so it is translated on the
/// server thread, and a name that does not translate fails with
/// STATUS_NO_SUCH_FILE as stock's open does.
extern "C" fn export_odd_log_start(path: *const core::ffi::c_char) -> u32 {
    // SAFETY: the caller passes a NUL-terminated name.
    let name = unsafe { core::ffi::CStr::from_ptr(path) }.to_bytes();
    let mut translation = Translation { name, path: None };
    let translated =
        dispatcher::call_on_server(translate_on_server, &raw mut translation as usize as u32)
            .and(translation.path.as_ref())
            .map(ObjectPath::as_bytes)
            .ok_or(nt::NO_SUCH_FILE);
    odd_log_start(translated).map_or_else(|error| error.hresult().0, |()| Hresult::OK.0)
}

/// Export 148 (stock 0x91f3d140): stop the optical disc log.
extern "C" fn export_odd_log_stop() -> u32 {
    odd_log_stop().map_or(OddLogNotRunning::HRESULT.0, |()| Hresult::OK.0)
}

export!(147, export_odd_log_start);
export!(148, export_odd_log_stop);
export!(166, export_query_input_focus);
export!(167, export_automation_bind);
export!(168, export_automation_unbind);
export!(169, export_automation_connect);
export!(170, export_automation_disconnect);
export!(171, export_automation_set_packet);
export!(172, export_automation_queue);
export!(173, export_automation_clear_queue);
export!(174, export_automation_query_queue);

impl commands::hardware::Backend for Console {
    fn automation_connect(&mut self, user: u32) -> Result<(), AutomationError> {
        connect(user)
    }

    fn automation_disconnect(&mut self, user: u32) -> Result<(), AutomationError> {
        disconnect(user)
    }

    fn automation_bind(&mut self, user: u32, queue_length: u32) -> Result<(), AutomationError> {
        automation::bind(&mut XboxControllers, user, queue_length)
    }

    fn automation_unbind(&mut self, user: u32) -> Result<(), AutomationError> {
        automation::unbind(&mut XboxControllers, user)
    }

    fn automation_clear_queue(&mut self, user: u32) -> Result<(), AutomationError> {
        clear_queue(user)
    }

    fn automation_query_queue(&mut self, user: u32) -> Result<QueueStatus, AutomationError> {
        query_queue(user)
    }

    fn automation_set_packet(&mut self, user: u32, packet: Gamepad) -> Result<(), AutomationError> {
        automation::set_packet(&mut XboxControllers, user, packet)
    }

    fn automation_begin_upload(&mut self, connection: ConnectionIndex, size: u32) -> bool {
        let slot = &mut self.hardware.uploads[connection.0 as usize];
        *slot = None;
        *slot = PoolBlock::allocate(u64::from(size), POOL_TAG_UPLOAD);
        slot.is_some()
    }

    fn automation_upload(&mut self, connection: ConnectionIndex, offset: u32, bytes: &[u8]) {
        if let Some(block) = self.hardware.uploads[connection.0 as usize].as_mut() {
            let start = offset as usize;
            block.bytes_mut()[start..start + bytes.len()].copy_from_slice(bytes);
        }
    }

    fn automation_discard_upload(&mut self, connection: ConnectionIndex) {
        self.hardware.uploads[connection.0 as usize] = None;
    }

    fn automation_queue_upload(
        &mut self,
        connection: ConnectionIndex,
        user: u32,
        layout: UploadLayout,
    ) -> Result<u32, AutomationError> {
        let upload = self.hardware.uploads[connection.0 as usize].take();
        let bytes = upload.as_ref().map_or(&[][..], PoolBlock::bytes);
        AUTOMATION.with(|automation| automation.queue(user, layout, bytes, &mut Input))
    }

    fn automation_input_owner(&mut self, user: u32) -> Result<InputOwner, ExportMissing> {
        query_input_focus(user).map(|system| {
            if system != 0 {
                InputOwner::System
            } else {
                InputOwner::Title
            }
        })
    }

    fn avatar_hooks_available(&mut self) -> bool {
        avatar_lookup().is_some()
    }

    fn avatar_hook(&mut self, hook: AvatarHook) -> Result<(), AvatarError> {
        let lookup = avatar_lookup().ok_or(AvatarError::NoFunction)?;
        let mut function = 0u32;
        // SAFETY: the lookup takes an index and an output pointer.
        let result = unsafe {
            kernel::call_export(lookup, hook.index(), output_address(&mut function), 0, 0)
        };
        if (result as i32) < 0 {
            return Err(AvatarError::Lookup(Hresult(result)));
        }
        if function == 0 {
            return Err(AvatarError::NoFunction);
        }
        let (first, second) = match hook {
            AvatarHook::LoadAssetDelay(value)
            | AvatarHook::QueryMarketplaceDelay(value)
            | AvatarHook::ChangeMetadata(value) => (value, 0),
            AvatarHook::SimulateError { kind, value } => (kind, value),
        };
        // SAFETY: the hooks take at most two dword arguments.
        let result = unsafe { kernel::call_export(function, first, second, 0, 0) };
        if (result as i32) < 0 {
            Err(AvatarError::Hook(Hresult(result)))
        } else {
            Ok(())
        }
    }

    fn set_wireless_radio(&mut self, enabled: bool) -> NtStatus {
        NtStatus(XInputdSetRFPowerMode(u32::from(enabled)))
    }

    fn devkit_memory_statistics(&mut self, block: &mut [u8; 0x90]) -> NtStatus {
        NtStatus(kernel::ExDebugMonitorService(
            MONITOR_MEMORY_STATISTICS,
            output_address(&mut block[..]),
            0,
            0,
        ))
    }

    fn xam_heap_count_available(&mut self) -> bool {
        HEAP_COUNT.xam(XAM_HEAP_COUNT).is_some()
    }

    fn xam_heap_info_available(&mut self) -> bool {
        HEAP_INFO.xam(XAM_HEAP_INFO).is_some()
    }

    fn xam_heap_count(&mut self, block: &mut [u8; 12]) -> Hresult {
        let Some(function) = HEAP_COUNT.xam(XAM_HEAP_COUNT) else {
            return Hresult::FAIL;
        };
        // SAFETY: the export fills the sized block.
        Hresult(unsafe { kernel::call_export(function, output_address(&mut block[..]), 0, 0, 0) })
    }

    fn xam_heap_name(&mut self, id: u32, name: &mut [u8; 0x20]) -> Hresult {
        let Some(function) = HEAP_INFO.xam(XAM_HEAP_INFO) else {
            return Hresult::FAIL;
        };
        let mut length = name.len() as u32;
        let request = [output_address(&mut name[..]), output_address(&mut length)];
        // SAFETY: class 1 takes `{buffer, &length}`.
        Hresult(unsafe { kernel::call_export(function, id, 1, address_of(&request[..]), 0) })
    }

    fn xam_heap_info(&mut self, id: u32, class: u32, block: &mut [u8]) -> Hresult {
        let Some(function) = HEAP_INFO.xam(XAM_HEAP_INFO) else {
            return Hresult::FAIL;
        };
        // SAFETY: classes 2 and 3 fill the sized block.
        Hresult(unsafe { kernel::call_export(function, id, class, output_address(block), 0) })
    }

    fn system_message(&mut self, app: u32, message: u32, buffer: &mut [u8]) -> Hresult {
        Hresult(kernel::XMsgStartIORequest(
            app,
            message,
            0,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        ))
    }

    fn play_to(&mut self, command: PlayToCommand) -> Result<PlayToState, Hresult> {
        let mut output = [0u32; 2];
        let mut input = [command.code(), output_address(&mut output[..]), 8];
        let result =
            kernel::XMsgStartIORequest(MEDIA_APP, MEDIA_PLAY_TO, 0, input.as_mut_ptr().cast(), 12);
        if (result as i32) < 0 {
            return Err(Hresult(result));
        }
        Ok(PlayToState {
            xmp_heap: output[0],
            play_to: output[1],
        })
    }

    fn stack_addresses(&mut self) -> StackAddresses {
        let mut title = [0u8; XNADDR_SIZE];
        let mut debug = [0u8; XNADDR_SIZE];
        kernel::NetDll_XNetGetTitleXnAddr(NETWORK_CALLER, title.as_mut_ptr());
        kernel::NetDll_XNetGetDebugXnAddr(NETWORK_CALLER, debug.as_mut_ptr());
        StackAddresses {
            title: [title[0], title[1], title[2], title[3]],
            debug: [debug[0], debug[1], debug[2], debug[3]],
        }
    }

    fn odd_log_start(&mut self, path: Result<&[u8], NtStatus>) -> Result<(), OddLogStartError> {
        odd_log_start(path)
    }

    fn odd_log_stop(&mut self) -> Result<(), OddLogNotRunning> {
        odd_log_stop()
    }

    fn pgo_start(&mut self, module: PgoModule) -> Result<(), PgoError> {
        pgo::control_start(module)
    }

    fn pgo_stop(&mut self, module: PgoModule) -> Result<(), PgoError> {
        pgo::control_stop(module)
    }

    fn pgo_snapshot(
        &mut self,
        phase: &[u8],
        reset: bool,
        module: PgoModule,
    ) -> Result<(), PgoError> {
        pgo::control_snapshot(phase, reset, module)
    }

    fn pgo_set_allocation_scale(&mut self, module: u32, scale: u32) -> Result<(), PgoError> {
        pgo::control_allocation_scale(module, scale)
    }

    fn set_ignore_gdf_attributes(&mut self, ignore: bool) {
        IGNORE_GDF_ATTRIBUTES.store(ignore, Ordering::Relaxed);
    }

    fn ignore_gdf_attributes(&mut self) -> bool {
        IGNORE_GDF_ATTRIBUTES.load(Ordering::Relaxed)
    }

    fn usb_port_power_available(&mut self) -> bool {
        USB_PORT_POWER.kernel(KERNEL_USB_PORT_POWER).is_some()
    }

    fn set_usb_port_power(&mut self, controller: u32, port: u32, enable: bool) -> NtStatus {
        let Some(function) = USB_PORT_POWER.kernel(KERNEL_USB_PORT_POWER) else {
            return NtStatus(0xc000_0138);
        };
        // SAFETY: the export takes three dword arguments.
        NtStatus(unsafe { kernel::call_export(function, controller, port, u32::from(enable), 0) })
    }
}

/// The avatar hook lookup; resolved on every use, as the monitor does.
fn avatar_lookup() -> Option<u32> {
    xam_procedure(XAM_AVATAR_HOOKS)
}
