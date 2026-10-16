//! The PIX capture session (stock 0x91fab7cc): a 0x12380-byte pool block
//! created at initialization when XAM feature 0x22 is enabled (stock
//! 0x91f5c560). `pixcmd` and titles queue engine messages in it; the
//! capture engine (`super::capture`) processes them at frame boundaries.
//!
//! The block keeps the stock layout, which the capture engine shares;
//! offsets are named where this module uses them.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use xbox360::module::ExportAddress;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360_sys::processor;
use xbox360_sys::xam;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AccessMask;
use xbox360_sys::xboxkrnl::CreateDisposition;
use xbox360_sys::xboxkrnl::CreateOptions;
use xbox360_sys::xboxkrnl::FileAttributes;
use xbox360_sys::xboxkrnl::FsInformationClass;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;
use xbox360_sys::xboxkrnl::ShareAccess;

use super::events;
use crate::kernel;

/// Block size and pool tag `PSTR`.
pub(super) const BLOCK_SIZE: u32 = 0x1_2380;
pub(super) const BLOCK_TAG: PoolTag = PoolTag::new(*b"PSTR");
/// XAM feature that enables PIX streaming.
const STREAMING_FEATURE: u32 = 0x22;

/// Capture configuration words `+0..+0xc` (current) and `+0x28..+0x34`
/// (requested); 2 means off.
pub(super) const CONFIGURATION: u32 = 0x00;
pub(super) const REQUESTED_CONFIGURATION: u32 = 0x28;
pub(super) const CONFIGURATION_OFF: u32 = 2;
/// Engine flags: bit 31 engine running, bit 30 code 13, bits 5..28 frame
/// index.
pub(super) const FLAGS: u32 = 0x50;
/// Protocol revision reported by `pixcmd q`.
pub(super) const REVISION: u32 = 0x54;
/// Critical sections of the block and the engine.
pub(super) const LOCK: u32 = 0x58;
pub(super) const ENGINE_LOCK: u32 = 0x74;
/// Saved base priority increments of the two locks.
pub(super) const LOCK_PRIORITY: u32 = 0x90;
pub(super) const ENGINE_LOCK_PRIORITY: u32 = 0x94;
/// Message queue: 8 entries of `{code, 0, payload[0x50]}`, count and head.
const QUEUE: u32 = 0x2cc;
const QUEUE_ENTRY: u32 = 0x58;
const QUEUE_ENTRIES: u32 = 8;
const QUEUE_COUNT: u32 = 0x58c;
const QUEUE_HEAD: u32 = 0x590;
const MESSAGE_PAYLOAD: u32 = 8;
pub(super) const MESSAGE_PAYLOAD_SIZE: usize = 0x50;
/// Message being processed (its code; 0 when none).
pub(super) const CURRENT_MESSAGE: u32 = 0x594;
/// Frame record copy; `pixcmd q` reports three of its words.
const FRAME_RECORD: u32 = 0x5f4;
/// XAM export 0x1f0 (capture size routine) and the dump partition file.
pub(super) const CAPTURE_SIZE_ROUTINE: u32 = 0x634;
pub(super) const DUMP_FILE: u32 = 0x638;
pub(super) const DUMP_SIZE: u32 = 0x640;
/// Output sequence and byte that discarded output advances.
const OUTPUT_SEQUENCE: u32 = 0x648;
const OUTPUT_GENERATION: u32 = 0x46c8;
/// Frame start times, 32 slots indexed by the frame index.
pub(super) const FRAME_TIMES: u32 = 0xe188;
pub(super) const FRAME_TIME_SLOTS: u32 = 32;
/// Lock recursion override used while the engine calls out.
pub(super) const LOCK_OVERRIDE: u32 = 0xc834;
const STATUS_WORD_11: u32 = 0xc838;
const STATUS_WORD_10: u32 = 0x2b4;
/// Kernel export 0x2d4 used by the engine.
pub(super) const KERNEL_ROUTINE: u32 = 0x1_2294;

/// XAM export of the capture size routine.
const CAPTURE_SIZE_EXPORT: Ordinal = Ordinal::new(0x1f0).unwrap();
/// Kernel export of the engine's kernel routine.
const KERNEL_ROUTINE_EXPORT: Ordinal = Ordinal::new(0x2d4).unwrap();

/// Status words: version and field count, then the engine's values.
const STATUS_VERSION: u32 = 0x5308;
const MIN_STATUS_FLAGS: u32 = 3;

/// The session block, or 0.
static SESSION: AtomicU32 = AtomicU32::new(0);

/// Address of the session block.
#[derive(Clone, Copy)]
pub(super) struct Session(pub(super) u32);

impl Session {
    pub(super) fn word(self, offset: u32) -> u32 {
        super::read_u32(self.0 + offset)
    }

    pub(super) fn set_word(self, offset: u32, value: u32) {
        super::write_u32(self.0 + offset, value);
    }

    pub(super) fn quad(self, offset: u32) -> u64 {
        // SAFETY: an aligned quadword of the session block.
        unsafe { core::ptr::read_volatile((self.0 + offset) as usize as *const u64) }
    }

    pub(super) fn set_quad(self, offset: u32, value: u64) {
        // SAFETY: as `quad`.
        unsafe { core::ptr::write_volatile((self.0 + offset) as usize as *mut u64, value) };
    }

    pub(super) fn at(self, offset: u32) -> *mut u32 {
        (self.0 + offset) as usize as *mut u32
    }
}

/// The session, when one was created.
pub(super) fn session() -> Option<Session> {
    Some(SESSION.load(Ordering::Acquire))
        .filter(|&block| block != 0)
        .map(Session)
}

/// Whether XAM feature `feature` is enabled (stock 0x91f521a8). XAM builds
/// outside 0x2029dc00..=0x202af700 and older than 0x202ff100 have every
/// feature; others ask XAM export 0x200.
pub(super) fn xam_feature_enabled(feature: u32) -> bool {
    const FEATURE_QUERY: Ordinal = Ordinal::new(0x200).unwrap();
    static QUERY: AtomicU32 = AtomicU32::new(0);
    let version = xam::XamGetSystemVersion();
    if !(0x2029_dc00..0x202a_f701).contains(&version) && version < 0x202f_f100 {
        return true;
    }
    let mut query = QUERY.load(Ordering::Acquire);
    if query == 0 {
        let Ok(address) = SystemModule::Xam
            .handle()
            .and_then(|xam| resolve_export(xam, FEATURE_QUERY))
        else {
            return true;
        };
        query = address.raw();
        QUERY.store(query, Ordering::Release);
    }
    // SAFETY: XAM export 0x200 takes one argument, a feature number.
    (unsafe { kernel::call_export(query, feature, 0, 0, 0) }) != 0
}

/// Capture buffer size the title's D3D version calls for (stock
/// 0x91f5c4e0); `pixcmd q` reports it.
pub(super) fn capture_buffer_size() -> u32 {
    let version = (xam::XamGetSystemVersion() & 0x1fff_ff00) >> 8;
    // Stock queries the feature for these versions although every version
    // from 0x211f gets the same size.
    if version >= 0x2f7d {
        xam_feature_enabled(STREAMING_FEATURE);
    }
    if version >= 0x211f {
        0x6_0000
    } else if version >= 0x19fa {
        0x1c_0000
    } else if version >= 0x1676 {
        0x2c_0000
    } else {
        0
    }
}

const PIX_STREAM: &[u8] = b"\\Device\\Harddisk0\\PixStream";
const PIX_DUMP: &[u8] = b"\\Device\\Harddisk0\\PixDump";
/// Dump partitions are used in 128 KiB units.
const DUMP_UNIT: i64 = 0x2_0000;
/// Device flag set on the dump partition device.
const DEVICE_FLAG_DUMP: u32 = 1;

/// Create the session (stock 0x91f5c560); `false` when streaming is
/// disabled or the block cannot be allocated.
pub(super) fn create() -> bool {
    if !xam_feature_enabled(STREAMING_FEATURE) {
        return false;
    }
    // SAFETY: allocates from the system pool; no pointer arguments.
    let block =
        unsafe { xboxkrnl::ExAllocatePoolTypeWithTag(BLOCK_SIZE, BLOCK_TAG, PoolType::System) };
    if block == 0 {
        return false;
    }
    let session = Session(block);
    // SAFETY: a fresh pool block of `BLOCK_SIZE` bytes.
    unsafe { core::ptr::write_bytes(block as usize as *mut u8, 0, BLOCK_SIZE as usize) };
    // SAFETY: both sections lie in the fresh, zeroed block.
    unsafe {
        xboxkrnl::RtlInitializeCriticalSectionAndSpinCount(session.at(LOCK).cast(), 10);
        xboxkrnl::RtlInitializeCriticalSectionAndSpinCount(session.at(ENGINE_LOCK).cast(), 10);
    }
    let mut path = PIX_STREAM;
    let mut device = 0u32;
    let mut status = reference_device(path, &mut device);
    if (status as i32) < 0 {
        path = PIX_DUMP;
        status = reference_device(path, &mut device);
    }
    if (status as i32) >= 0 {
        // SAFETY: `device` is the device object referenced above; the lock
        // is released before the reference is dropped.
        unsafe {
            let irql = xboxkrnl::IoAcquireDeviceObjectLock();
            super::write_u32(
                device + 0x14,
                super::read_u32(device + 0x14) | DEVICE_FLAG_DUMP,
            );
            xboxkrnl::IoReleaseDeviceObjectLock(irql);
            xboxkrnl::ObDereferenceObject(device);
        }
    }
    let mut handle = 0u32;
    if open_device(path, &mut handle) {
        session.set_word(DUMP_FILE, handle);
        let mut io_status = IoStatusBlock::default();
        let mut size = [0u8; 0x18];
        // SAFETY: `handle` is the open partition; the output buffer is
        // 0x18 bytes, as passed.
        unsafe {
            xboxkrnl::NtQueryVolumeInformationFile(
                Handle::from_raw(handle),
                &mut io_status,
                size.as_mut_ptr(),
                0x18,
                FsInformationClass::Size,
            )
        };
        let units = u64::from_be_bytes(size[..8].try_into().unwrap_or_default());
        let sector = u32::from_be_bytes(size[0x14..0x18].try_into().unwrap_or_default());
        let bytes = units.wrapping_mul(u64::from(sector)) as i64;
        session.set_quad(DUMP_SIZE, (bytes / DUMP_UNIT * DUMP_UNIT) as u64);
    }
    session.set_word(CURRENT_MESSAGE, 0);
    session.set_word(0xc938, block + 0xc83c);
    session.set_word(0x0, CONFIGURATION_OFF);
    session.set_word(0x4, CONFIGURATION_OFF);
    session.set_word(0x8, CONFIGURATION_OFF);
    session.set_word(0xc, CONFIGURATION_OFF);
    session.set_word(0x28, CONFIGURATION_OFF);
    session.set_word(0x2c, CONFIGURATION_OFF);
    session.set_word(0x30, CONFIGURATION_OFF);
    session.set_word(0x34, CONFIGURATION_OFF);
    session.set_word(0xc83c, block);
    session.set_word(0xc934, block);
    for index in 0..0x800u32 {
        // SAFETY: fill bytes inside the block.
        unsafe { core::ptr::write_volatile((block + 0x68c + index * 8) as usize as *mut u8, 0xcc) };
    }
    if capture_buffer_size() != 0 {
        let routine = SystemModule::Xam
            .handle()
            .and_then(|xam| resolve_export(xam, CAPTURE_SIZE_EXPORT))
            .map_or(0, ExportAddress::raw);
        session.set_word(CAPTURE_SIZE_ROUTINE, routine);
    }
    let routine = SystemModule::Kernel
        .handle()
        .and_then(|kernel| resolve_export(kernel, KERNEL_ROUTINE_EXPORT))
        .map_or(0, ExportAddress::raw);
    session.set_word(KERNEL_ROUTINE, routine);
    session.set_word(REVISION, if routine != 0 { 0x5d } else { 0x55 });
    reset_budget(session);
    SESSION.store(block, Ordering::Release);
    true
}

/// Memory budget switches and overrides of code 0x56 at their defaults.
pub(super) fn reset_budget(session: Session) {
    session.set_word(0x87e4, 0);
    session.set_word(0x87dc, 1);
    session.set_word(0x87e0, 1);
    session.set_word(0x87e8, 0);
    session.set_word(0x87ec, 0);
    session.set_word(0x87f0, 0);
}

fn reference_device(path: &[u8], device: &mut u32) -> u32 {
    // SAFETY: the name string and `device` are live for the call.
    unsafe {
        xboxkrnl::ObReferenceObjectByName(
            &kernel::ansi_string(path),
            ObjectAttributeFlags::CASE_INSENSITIVE,
            xboxkrnl::IoDeviceObjectType.address(),
            0,
            device,
        )
    }
    .0
}

/// Open the partition device `path` for capture writes.
fn open_device(path: &[u8], handle: &mut u32) -> bool {
    let name = kernel::ansi_string(path);
    let attributes = ObjectAttributes {
        root_directory: Handle::NULL,
        object_name: &name,
        attributes: ObjectAttributeFlags::CASE_INSENSITIVE,
    };
    let mut io_status = IoStatusBlock::default();
    // SAFETY: all pointers refer to live locals or the caller's `handle`.
    (unsafe {
        xboxkrnl::NtCreateFile(
            (handle as *mut u32).cast(),
            AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE | AccessMask::SYNCHRONIZE,
            &attributes,
            &mut io_status,
            core::ptr::null(),
            FileAttributes::SYSTEM,
            ShareAccess::READ | ShareAccess::WRITE,
            CreateDisposition::Open,
            CreateOptions::NO_INTERMEDIATE_BUFFERING,
        )
    }
    .0 as i32)
        >= 0
}

/// Open a title handle to the dump partition (stock 0x91f5cb08):
/// `PixStream`, else `PixDump`.
pub(super) fn open_partition(handle: &mut u32) -> bool {
    open_device(PIX_STREAM, handle) || open_device(PIX_DUMP, handle)
}

/// `KTHREAD` fields the lock checks before raising the priority.
const THREAD_PRIORITY: u32 = 0x70;
const THREAD_BASE_PRIORITY: u32 = 0xb9;
const THREAD_SATURATION: u32 = 0xbb;
const THREAD_PRIORITY_BOOST: u32 = 0xb8;
const THREAD_BASE: u32 = 0xc9;
const THREAD_LIMIT: u32 = 0xca;
/// Priority increment while holding a session lock.
const LOCK_INCREMENT: u32 = 0xf;
/// Saved increment meaning the priority was not changed.
const PRIORITY_UNCHANGED: u32 = 0x8000_0000;

fn thread_byte(thread: u32, offset: u32) -> u32 {
    u32::from(super::read_u8(thread + offset))
}

/// Raise the caller's base priority unless it is already high, then
/// enter `section` (stock 0x91f5c2b0); returns the increment to restore.
pub(super) fn enter(section: *mut u32) -> u32 {
    let thread = processor::current_thread();
    let object = thread as usize as *mut xboxkrnl::Kthread;
    // SAFETY: `thread` is the current thread object; `section` is an
    // initialized critical section of the session block.
    unsafe { xboxkrnl::KeEnterCriticalRegion() };
    let saved = if thread_byte(thread, THREAD_PRIORITY) < 0x12
        && thread_byte(thread, THREAD_BASE_PRIORITY) < 0x11
        && thread_byte(thread, THREAD_SATURATION) == 0
    {
        // SAFETY: as above.
        unsafe { xboxkrnl::KeSetBasePriorityThread(object, LOCK_INCREMENT) }
    } else {
        PRIORITY_UNCHANGED
    };
    // SAFETY: as above.
    unsafe { xboxkrnl::RtlEnterCriticalSection(section.cast()) };
    saved
}

/// Leave `section` and restore the priority from [`enter`] (stock
/// 0x91f5c350); a priority changed meanwhile is put back.
pub(super) fn leave(section: *mut u32, saved: u32) {
    let thread = processor::current_thread();
    let object = thread as usize as *mut xboxkrnl::Kthread;
    // SAFETY: `section` is the session critical section [`enter`] took;
    // `thread` is the current thread object.
    unsafe { xboxkrnl::RtlLeaveCriticalSection(section.cast()) };
    if saved != PRIORITY_UNCHANGED {
        let expected = (thread_byte(thread, THREAD_BASE) + LOCK_INCREMENT)
            .min(thread_byte(thread, THREAD_LIMIT));
        if thread_byte(thread, THREAD_BASE_PRIORITY) == expected
            && thread_byte(thread, THREAD_PRIORITY_BOOST) == 0
        {
            // SAFETY: as above.
            let previous = unsafe { xboxkrnl::KeSetBasePriorityThread(object, saved) };
            if previous != expected - thread_byte(thread, THREAD_BASE) {
                kernel::debug_print(c"WRN[PIX]: Undoing thread base priority restore.\n");
                // SAFETY: as above.
                unsafe { xboxkrnl::KeSetBasePriorityThread(object, previous) };
            }
        }
    }
    // SAFETY: pairs with the `KeEnterCriticalRegion` of [`enter`].
    unsafe { xboxkrnl::KeLeaveCriticalRegion() };
}

/// The locked session (stock 0x91f5a7f0); unlocks on drop (0x91f5c350).
pub(super) struct Locked(pub(super) Session);

impl Drop for Locked {
    fn drop(&mut self) {
        leave(self.0.at(LOCK), self.0.word(LOCK_PRIORITY));
    }
}

pub(super) fn lock() -> Option<Locked> {
    let session = session()?;
    let saved = enter(session.at(LOCK));
    session.set_word(LOCK_PRIORITY, saved);
    Some(Locked(session))
}

/// Queue engine message `code` with `payload` (stock 0x91f5f000). A code
/// 0xc message replaces the payload of a queued one. `false` without a
/// session or with a full queue.
pub(super) fn post(code: u32, payload: &[u32]) -> bool {
    let Some(locked) = lock() else { return false };
    let session = locked.0;
    let count = session.word(QUEUE_COUNT);
    let head = session.word(QUEUE_HEAD);
    let entry = |index: u32| session.0 + QUEUE + ((head + index) % QUEUE_ENTRIES) * QUEUE_ENTRY;
    let write_payload = |entry: u32| {
        for (index, &word) in payload.iter().take(MESSAGE_PAYLOAD_SIZE / 4).enumerate() {
            super::write_u32(entry + MESSAGE_PAYLOAD + index as u32 * 4, word);
        }
    };
    if code == 0xc
        && let Some(queued) = (0..count)
            .map(entry)
            .find(|&queued| super::read_u32(queued) == 0xc)
    {
        write_payload(queued);
        return true;
    }
    if count >= QUEUE_ENTRIES {
        return false;
    }
    let free = entry(count);
    super::write_u32(free, code);
    super::write_u32(free + 4, 0);
    write_payload(free);
    session.set_word(QUEUE_COUNT, count + 1);
    true
}

/// Take the oldest queued message (stock 0x91f5d3f0); the address of its
/// entry.
pub(super) fn next_message(session: Session) -> Option<u32> {
    let count = session.word(QUEUE_COUNT);
    if count == 0 {
        return None;
    }
    let head = session.word(QUEUE_HEAD);
    session.set_word(QUEUE_COUNT, count - 1);
    session.set_word(
        QUEUE_HEAD,
        if head + 1 < QUEUE_ENTRIES {
            head + 1
        } else {
            0
        },
    );
    Some(session.0 + QUEUE + head * QUEUE_ENTRY)
}

/// Put the message [`next_message`] took back at the queue head (stock
/// 0x91f617b0 on resuming).
pub(super) fn requeue_message(session: Session) {
    session.set_word(QUEUE_COUNT, session.word(QUEUE_COUNT) + 1);
    let head = session.word(QUEUE_HEAD);
    session.set_word(
        QUEUE_HEAD,
        if head == 0 {
            QUEUE_ENTRIES - 1
        } else {
            head - 1
        },
    );
}

/// Engine status for `pixcmd q`/`p`/`u` (stock 0x91f5f130).
pub(super) fn status(version: u32, flags: u32) -> Option<[u32; 12]> {
    if version == 0 || flags & MIN_STATUS_FLAGS == 0 {
        return None;
    }
    let locked = lock()?;
    let session = locked.0;
    let dump = session.quad(DUMP_SIZE) as i64;
    Some([
        STATUS_VERSION,
        session.word(REVISION),
        session.word(FRAME_RECORD + 4),
        session.word(FRAME_RECORD + 0xc),
        session.word(FRAME_RECORD + 8),
        (xam::XamGetSystemVersion() & 0x1fff_ff00) >> 8,
        capture_buffer_size(),
        (dump / 0x10_0000) as u32,
        session.word(FLAGS) >> 31,
        session.word(0x5f0),
        session.word(STATUS_WORD_10),
        session.word(STATUS_WORD_11),
    ])
}

/// Frame rate statistics of `pixcmd m` (stock 0x91f5f230): the owner
/// callback reports two percentages and a count for `frame`, scaled by the
/// measured frame rate over the last 31 frames (at most 90).
pub(super) fn frame_statistics(frame: u32) -> Option<[u32; 3]> {
    const TICK_SECONDS: f32 = f32::from_bits(0x32ab_cc77);
    const MEASURED_FRAMES: f32 = 31.0;
    const MAX_RATE: f32 = 90.0;
    const RATE_SCALE: f32 = f32::from_bits(0x3c88_8889);
    const COUNT_SCALE: f32 = f32::from_bits(0x3655_5555);
    const PERCENT: f32 = 100.0;
    const STATISTICS_EVENT: u32 = 0xe3;
    let locked = lock()?;
    let session = locked.0;
    let index = session.word(FLAGS) >> 5;
    let slot = |index: u32| session.word(FRAME_TIMES + (index & (FRAME_TIME_SLOTS - 1)) * 4);
    let ticks = slot(index.wrapping_sub(1)).wrapping_sub(slot(index));
    let rate = (MEASURED_FRAMES / (ticks as f32 * TICK_SECONDS)).min(MAX_RATE);
    let mut query = [frame, 0, 0, 0];
    events::notify_owner(STATISTICS_EVENT, query.as_mut_ptr() as usize as u32);
    #[inline(never)]
    fn truncate(value: f32) -> u32 {
        value as i64 as u32
    }
    let mut out = [0u32; 3];
    if query[3] != 0 {
        let scale = rate * RATE_SCALE;
        out[0] = truncate(scale * f32::from_bits(query[1]) * PERCENT);
        out[1] = truncate(scale * f32::from_bits(query[2]) * PERCENT);
        out[2] = truncate(query[3] as f32 * scale * COUNT_SCALE * PERCENT);
    }
    Some(out)
}

/// Monitor control code 0x44 (stock 0x91f5f3b8): capture state bits.
pub(super) fn state_flags() -> u32 {
    let mut flags = 0;
    if let Some(locked) = lock() {
        let session = locked.0;
        if session.word(CONFIGURATION) != CONFIGURATION_OFF {
            flags |= 1;
        }
        if session.word(CONFIGURATION + 8) != CONFIGURATION_OFF {
            flags |= 0x40;
        }
        if session.word(CONFIGURATION + 0xc) != CONFIGURATION_OFF {
            flags |= 0x80;
        }
        match session.word(CURRENT_MESSAGE) {
            4 => flags |= 1,
            5 => flags |= 2,
            _ => {}
        }
    }
    if super::super::xtrace::is_recording() {
        flags |= 4;
    }
    if super::super::capture::buffer_allocated() {
        flags |= 8;
    }
    if super::super::profiler::running() {
        flags |= 0x10;
    }
    if super::stream_active() {
        flags |= 0x20;
    }
    flags
}

/// Monitor control code 0x3f (stock 0x91f5f4b0): clearing the discard flag
/// advances the session's output sequence by two.
pub(super) fn set_discard(discard: bool) {
    if super::discard_output()
        && !discard
        && let Some(locked) = lock()
    {
        let session = locked.0;
        session.set_quad(
            OUTPUT_SEQUENCE,
            session.quad(OUTPUT_SEQUENCE).wrapping_add(2),
        );
        let generation = session.0 + OUTPUT_GENERATION;
        super::write_u8(generation, super::read_u8(generation).wrapping_add(2));
    }
}
